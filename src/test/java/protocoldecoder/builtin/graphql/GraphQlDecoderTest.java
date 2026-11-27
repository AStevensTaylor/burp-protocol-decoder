package protocoldecoder.builtin.graphql;

import org.junit.jupiter.api.Test;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.util.TreeText;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class GraphQlDecoderTest {

    final GraphQlDecoder gql = new GraphQlDecoder();

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    static MessageContext.Builder post(String url, String ct, String body) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url(url).requestHeader("Content-Type", ct).requestBody(body);
    }

    static MessageContext.Builder postJson(String body) {
        return post("https://api.example.com/graphql", "application/json", body);
    }

    static MessageContext response(MessageContext.Builder req, String ct, String body) {
        return req.statusCode(200).responseHeader("Content-Type", ct).responseBody(body).build().withKind(MessageKind.RESPONSE);
    }

    static MessageContext ws(String payload, String protocol) {
        MessageContext.Builder b = MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("wss://api.example.com/subscriptions");
        if (protocol != null) b.requestHeader("Sec-WebSocket-Protocol", protocol);
        return b.webSocket("CLIENT_TO_SERVER", payload.getBytes(StandardCharsets.UTF_8)).build();
    }

    static String find(DecodedNode n, String name) {
        if (n.name().equals(name) && n.value() != null) return n.value();
        for (DecodedNode c : n.children()) {
            String v = find(c, name);
            if (v != null) return v;
        }
        return null;
    }

    static DecodedNode node(DecodedNode n, String name) {
        if (n.name().equals(name)) return n;
        for (DecodedNode c : n.children()) {
            DecodedNode v = node(c, name);
            if (v != null) return v;
        }
        return null;
    }

    // ------------------------------------------------------------ requests

    @Test
    void postJsonQuery() throws Exception {
        MessageContext m = postJson("{\"query\":\"query GetUser($id: ID!) { user(id: $id) { id name } settings { theme } }\","
                + "\"variables\":{\"id\":\"42\"},\"operationName\":\"GetUser\"}").build();
        assertEquals(95, gql.match(m).confidence());
        DecodeResult r = gql.decode(m);
        assertEquals("GraphQL query GetUser (2 root fields)", r.summary());
        assertEquals("query", find(r.root(), "Type"));
        assertEquals("GetUser", find(r.root(), "Name"));
        assertEquals("$id: ID!", node(r.root(), "Variable definitions").children().get(0).value());
        assertEquals("42", find(node(r.root(), "Variables"), "id"));
        assertTrue(r.text().startsWith("query GetUser($id: ID!) {\n  user(id: $id) {\n    id"), r.text());
        assertTrue(r.text().contains("# Variables\n{\n  \"id\": \"42\"\n}"), r.text());
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
    }

    @Test
    void mutationAndOperationNameSelection() throws Exception {
        MessageContext m = postJson("{\"query\":\"query A { a } mutation Login($p: String) { login(password: $p) { token } }\",\"operationName\":\"Login\"}").build();
        DecodeResult r = gql.decode(m);
        assertEquals("GraphQL mutation Login (1 root field)", r.summary());
        assertNotNull(node(r.root(), "Operations in document"));
    }

    @Test
    void missingOperationNameWarns() throws Exception {
        DecodeResult r = gql.decode(postJson("{\"query\":\"query A { a } query B { b }\",\"operationName\":\"C\"}").build());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("'C' is not defined")), r.warnings().toString());
    }

    @Test
    void introspectionRequestIsFlagged() throws Exception {
        MessageContext m = postJson("{\"query\":\"query IntrospectionQuery { __schema { queryType { name } types { name kind } } }\"}").build();
        DecodeResult r = gql.decode(m);
        assertEquals("GraphQL query IntrospectionQuery (1 root field) [introspection]", r.summary());
    }

    @Test
    void batchedOperations() throws Exception {
        MessageContext m = postJson("[{\"query\":\"query A { a }\"},{\"query\":\"mutation B { b }\",\"variables\":{\"x\":1}},"
                + "{\"operationName\":\"C\",\"extensions\":{\"persistedQuery\":{\"version\":1,\"sha256Hash\":\"abc123\"}}}]").build();
        assertEquals(95, gql.match(m).confidence());
        DecodeResult r = gql.decode(m);
        assertEquals("GraphQL batch: 3 operations (A, B, C) [includes mutation]", r.summary());
        DecodedNode batch = r.root().get("Batch");
        assertEquals(3, batch.children().size());
        assertEquals("mutation B (1 root field)", batch.children().get(1).value());
        assertTrue(r.text().contains("# [1] mutation B (1 root field)\nmutation B {\n  b\n}"), r.text());
    }

    @Test
    void automaticPersistedQueryHashOnly() throws Exception {
        String hash = "ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38";
        MessageContext m = postJson("{\"operationName\":\"GetUser\",\"variables\":{\"id\":1},\"extensions\":{\"persistedQuery\":{\"version\":1,\"sha256Hash\":\"" + hash + "\"}}}").build();
        assertEquals(90, gql.match(m).confidence());
        DecodeResult r = gql.decode(m);
        assertEquals("GraphQL persisted query GetUser (sha256 ecf4edb46db4…, query omitted)", r.summary());
        assertEquals(hash, find(r.root(), "sha256Hash"));
        assertTrue(TreeText.render(r.root()).contains("Query text omitted"));
    }

    @Test
    void persistedQueryRegistrationChecksHash() throws Exception {
        String q = "{ hello }";
        String hash = GraphQlOperations.sha256(q);
        DecodeResult r = gql.decode(postJson("{\"query\":\"" + q + "\",\"extensions\":{\"persistedQuery\":{\"version\":1,\"sha256Hash\":\"" + hash + "\"}}}").build());
        assertEquals("matches the query text", find(r.root(), "Hash check"));
        assertTrue(r.summary().contains("[APQ registration]"), r.summary());
        DecodeResult bad = gql.decode(postJson("{\"query\":\"" + q + "\",\"extensions\":{\"persistedQuery\":{\"sha256Hash\":\"00\"}}}").build());
        assertTrue(find(bad.root(), "Hash check").startsWith("does NOT match"));
    }

    @Test
    void getWithUrlParameters() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("GET")
                .url("https://api.example.com/graphql?query=" + enc("query Me { me { id } }") + "&variables=" + enc("{\"a\":true}") + "&operationName=Me")
                .build();
        assertEquals(95, gql.match(m).confidence());
        DecodeResult r = gql.decode(m);
        assertEquals("GraphQL query Me (1 root field)", r.summary());
        assertEquals("GET URL parameters", find(r.root(), "Transport"));
        assertEquals("true", find(node(r.root(), "Variables"), "a"));
    }

    @Test
    void getPersistedQueryInUrl() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("GET")
                .url("https://api.example.com/graphql?operationName=Feed&variables=" + enc("{}") + "&extensions="
                        + enc("{\"persistedQuery\":{\"version\":1,\"sha256Hash\":\"deadbeefdeadbeef\"}}"))
                .build();
        assertEquals(90, gql.match(m).confidence());
        assertEquals("GraphQL persisted query Feed (sha256 deadbeefdead…, query omitted)", gql.decode(m).summary());
    }

    @Test
    void applicationGraphqlBody() throws Exception {
        MessageContext m = post("https://x.example.com/api", "application/graphql", "subscription OnMsg { messageAdded { id } }").build();
        assertEquals(95, gql.match(m).confidence());
        DecodeResult r = gql.decode(m);
        assertEquals("GraphQL subscription OnMsg (1 root field)", r.summary());
        assertEquals("POST application/graphql body", find(r.root(), "Transport"));

        MessageContext broken = post("https://x.example.com/api", "application/graphql", "query { a(\"x) }").build();
        assertEquals(60, gql.match(broken).confidence());
        DecodeResult br = gql.decode(broken);
        assertEquals("query { a(\"x) }", br.text());
        assertFalse(br.warnings().isEmpty());
    }

    @Test
    void rawDocumentOnGraphqlPathWithoutContentType() {
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://x.example.com/graphql")
                .requestBody("{ me { id } }").build();
        assertEquals(80, gql.match(m).confidence());
    }

    @Test
    void multipartUpload() throws Exception {
        String b = "----X1";
        String body = "--" + b + "\r\nContent-Disposition: form-data; name=\"operations\"\r\n\r\n"
                + "{\"query\":\"mutation ($file: Upload!) { singleUpload(file: $file) { id } }\",\"variables\":{\"file\":null}}\r\n"
                + "--" + b + "\r\nContent-Disposition: form-data; name=\"map\"\r\n\r\n{\"0\":[\"variables.file\"]}\r\n"
                + "--" + b + "\r\nContent-Disposition: form-data; name=\"0\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nhello world\r\n"
                + "--" + b + "--\r\n";
        MessageContext m = post("https://x.example.com/graphql", "multipart/form-data; boundary=" + b, body).build();
        assertEquals(90, gql.match(m).confidence());
        DecodeResult r = gql.decode(m);
        assertEquals("GraphQL mutation (1 root field)", r.summary());
        DecodedNode up = r.root().get("Uploads").get("Field 0");
        assertEquals("variables.file", up.get("Variable paths").value());
        assertEquals("a.txt", up.get("Filename").value());
        assertEquals("11", up.get("Size (bytes)").value());
        assertEquals("hello world", up.get("Preview").value());
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
    }

    @Test
    void formEncodedQuery() throws Exception {
        MessageContext m = post("https://x.example.com/graphql", "application/x-www-form-urlencoded", "query=" + enc("{ a }")).build();
        assertEquals(90, gql.match(m).confidence());
        assertEquals("GraphQL query (1 root field)", gql.decode(m).summary());
    }

    @Test
    void variablesAsJsonString() throws Exception {
        DecodeResult r = gql.decode(postJson("{\"query\":\"{ a }\",\"variables\":\"{\\\"k\\\":5}\"}").build());
        assertEquals("5", find(node(r.root(), "Variables"), "k"));
    }

    // ------------------------------------------------------------ negatives / forced

    @Test
    void plainJsonApisDoNotMatch() {
        assertEquals(0, gql.match(postJson("{\"query\":\"john smith\",\"page\":1}").build()).confidence());
        assertEquals(0, gql.match(post("https://shop.example.com/search", "application/json", "{\"query\":\"select * from t\"}").build()).confidence());
        assertEquals(0, gql.match(post("https://es.example.com/_search", "application/json", "{\"query\":{\"match\":{\"title\":\"x\"}}}").build()).confidence());
        assertEquals(0, gql.match(post("https://x.example.com/api", "application/json", "[{\"query\":\"hello\"}]").build()).confidence());
        assertEquals(0, gql.match(post("https://x.example.com/api", "application/json", "{\"a\":1}").build()).confidence());
        MessageContext get = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://x.example.com/search?query=shoes").build();
        assertEquals(0, gql.match(get).confidence());
        MessageContext restResp = response(post("https://x.example.com/api/users", "application/json", "{\"a\":1}"), "application/json",
                "{\"data\":{\"id\":1}}");
        assertEquals(0, gql.match(restResp).confidence());
        assertEquals(0, gql.match(ws("{\"type\":\"message\",\"text\":\"hi\"}", null)).confidence());
        assertEquals(0, gql.match(ws("not json", null)).confidence());
    }

    @Test
    void forcedDecodeOnGarbageThrows() {
        DecodeException e = assertThrows(DecodeException.class, () -> gql.decode(post("https://x.example.com/", "application/octet-stream", "\u0001\u0002garbage").build()));
        assertTrue(e.getMessage().contains("Not a GraphQL request"), e.getMessage());
        assertThrows(DecodeException.class, () -> gql.decode(postJson("{\"query\":\"john\",\"page\":1}").build()));
        assertThrows(DecodeException.class, () -> gql.decode(response(postJson("{}"), "text/html", "<html></html>")));
        assertThrows(DecodeException.class, () -> gql.decode(response(postJson("{}"), "application/json", "{\"ok\":true}")));
        assertThrows(DecodeException.class, () -> gql.decode(response(postJson("{}"), "application/json", "")));
        assertThrows(DecodeException.class, () -> gql.decode(ws("garbage", null)));
        assertThrows(DecodeException.class, () -> gql.decode(ws("{\"type\":\"chat\"}", null)));
        assertThrows(DecodeException.class, () -> gql.decode(MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://x/").build()));
    }

    @Test
    void forcedDecodeOfJsonWithoutQueryWarns() throws Exception {
        DecodeResult r = gql.decode(postJson("{\"operationName\":\"X\",\"variables\":{}}").build());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("no query document")), r.warnings().toString());
    }

    // ------------------------------------------------------------ responses

    @Test
    void responseWithErrors() throws Exception {
        MessageContext m = response(postJson("{\"query\":\"query Me { me { id } }\"}"), "application/json",
                "{\"data\":{\"me\":null},\"errors\":[{\"message\":\"Not authorised\",\"locations\":[{\"line\":1,\"column\":12}],\"path\":[\"me\"],"
                        + "\"extensions\":{\"code\":\"UNAUTHENTICATED\"}}]}");
        assertEquals(90, gql.match(m).confidence());
        DecodeResult r = gql.decode(m);
        assertEquals("GraphQL response: 1 error — Not authorised", r.summary());
        DecodedNode err = r.root().get("Errors").children().get(0);
        assertEquals("me", err.get("Path").value());
        assertEquals("line 1, column 12", err.get("Locations").value());
        assertEquals("UNAUTHENTICATED", err.get("Code").value());
        assertEquals("Me", r.root().get("Operation").value());
    }

    @Test
    void successfulResponse() throws Exception {
        MessageContext m = response(postJson("{\"query\":\"{ a b }\"}"), "application/json", "{\"data\":{\"a\":1,\"b\":[1,2]}}");
        assertEquals("GraphQL response: data (2 root fields)", gql.decode(m).summary());
    }

    @Test
    void gzippedResponse() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
            gz.write("{\"errors\":[{\"message\":\"boom\"},{\"message\":\"two\"}]}".getBytes(StandardCharsets.UTF_8));
        }
        MessageContext m = postJson("{\"query\":\"{ a }\"}").statusCode(200).responseHeader("Content-Type", "application/json")
                .responseHeader("Content-Encoding", "gzip").responseBody(bos.toByteArray()).build().withKind(MessageKind.RESPONSE);
        assertEquals(90, gql.match(m).confidence());
        assertEquals("GraphQL response: 2 errors — boom", gql.decode(m).summary());
    }

    @Test
    void responseWithoutGraphqlRequest() {
        MessageContext onPath = response(MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://x.example.com/graphql"),
                "application/json", "{\"data\":{\"x\":1}}");
        assertEquals(75, gql.match(onPath).confidence());
        MessageContext errs = response(MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://x.example.com/api"),
                "application/json", "{\"errors\":[{\"message\":\"Syntax Error\",\"locations\":[{\"line\":1,\"column\":1}]}]}");
        assertEquals(60, gql.match(errs).confidence());
        MessageContext mediaType = response(MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://x.example.com/q"),
                "application/graphql-response+json; charset=utf-8", "{\"data\":{}}");
        assertEquals(95, gql.match(mediaType).confidence());
    }

    @Test
    void batchResponse() throws Exception {
        MessageContext m = response(postJson("[{\"query\":\"query A { a }\"},{\"query\":\"query B { b }\"}]"), "application/json",
                "[{\"data\":{\"a\":1}},{\"data\":null,\"errors\":[{\"message\":\"nope\"}]}]");
        DecodeResult r = gql.decode(m);
        assertEquals("GraphQL batch response: 2 results, 1 error — nope", r.summary());
        assertEquals("A: data (1 root field)", r.root().get("Batch results").children().get(0).value());
        assertEquals("B: 1 error — nope", r.root().get("Batch results").children().get(1).value());
    }

    @Test
    void introspectionResponseSummarisesSchema() throws Exception {
        String schema = "{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"},\"mutationType\":{\"name\":\"Mutation\"},\"subscriptionType\":null,"
                + "\"types\":["
                + "{\"kind\":\"OBJECT\",\"name\":\"Query\",\"fields\":[{\"name\":\"user\",\"args\":[{\"name\":\"id\",\"type\":{\"kind\":\"NON_NULL\",\"name\":null,\"ofType\":{\"kind\":\"SCALAR\",\"name\":\"ID\"}}}],"
                + "\"type\":{\"kind\":\"OBJECT\",\"name\":\"User\"}},{\"name\":\"users\",\"args\":[],\"type\":{\"kind\":\"NON_NULL\",\"ofType\":{\"kind\":\"LIST\",\"ofType\":{\"kind\":\"OBJECT\",\"name\":\"User\"}}}}]},"
                + "{\"kind\":\"OBJECT\",\"name\":\"Mutation\",\"fields\":[{\"name\":\"deleteUser\",\"args\":[],\"type\":{\"kind\":\"SCALAR\",\"name\":\"Boolean\"},\"isDeprecated\":true}]},"
                + "{\"kind\":\"OBJECT\",\"name\":\"User\",\"fields\":[]},"
                + "{\"kind\":\"OBJECT\",\"name\":\"__Schema\",\"fields\":[]}],"
                + "\"directives\":[]}}}";
        MessageContext m = response(MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://x.example.com/api"), "application/json", schema);
        assertEquals(85, gql.match(m).confidence());
        DecodeResult r = gql.decode(m);
        assertEquals("GraphQL introspection response: schema with 4 types (query: Query, mutation: Mutation)", r.summary());
        DecodedNode s = r.root().get("Schema (introspection)");
        assertEquals("Query", s.get("Query type").value());
        assertEquals("user(id: ID!): User", s.get("Query fields (Query)").children().get(0).value());
        assertEquals("users: [User]!", s.get("Query fields (Query)").children().get(1).value());
        assertEquals("deleteUser: Boolean  (deprecated)", s.get("Mutation fields (Mutation)").children().get(0).value());
        DecodedNode types = s.get("Types");
        assertEquals("Query — OBJECT", types.children().get(0).value());
        assertTrue(types.children().get(types.children().size() - 1).value().contains("1 introspection types"));
    }

    @Test
    void sseResponse() throws Exception {
        MessageContext m = response(postJson("{\"query\":\"subscription { tick }\"}"), "text/event-stream",
                "event: next\ndata: {\"data\":{\"tick\":1}}\n\nevent: next\ndata: {\"errors\":[{\"message\":\"x\"}]}\n\nevent: complete\ndata:\n\n");
        assertEquals(85, gql.match(m).confidence());
        DecodeResult r = gql.decode(m);
        assertEquals("GraphQL SSE stream: 2 events (2 results, 1 error — x)", r.summary());
    }

    @Test
    void incrementalMultipartResponse() throws Exception {
        String body = "\r\n---\r\nContent-Type: application/json; charset=utf-8\r\n\r\n{\"data\":{\"a\":1},\"hasNext\":true}\r\n---\r\n"
                + "Content-Type: application/json; charset=utf-8\r\n\r\n{\"incremental\":[{\"data\":{\"b\":2},\"path\":[]}],\"hasNext\":false}\r\n-----\r\n";
        MessageContext m = response(postJson("{\"query\":\"{ a ... @defer { b } }\"}"), "multipart/mixed; boundary=\"-\"; deferSpec=20220824", body);
        DecodeResult r = gql.decode(m);
        assertEquals("GraphQL incremental response: 2 events (2 results)", r.summary());
    }

    // ------------------------------------------------------------ WebSocket

    @Test
    void wsTransportSubscribe() throws Exception {
        MessageContext m = ws("{\"id\":\"1\",\"type\":\"subscribe\",\"payload\":{\"query\":\"subscription OnMessage { messageAdded { id text } }\",\"variables\":{}}}",
                "graphql-transport-ws");
        assertEquals(95, gql.match(m).confidence());
        DecodeResult r = gql.decode(m);
        assertEquals("GraphQL WS subscribe #1: subscription OnMessage (1 root field)", r.summary());
        assertEquals("graphql-transport-ws", find(r.root(), "Protocol"));
        assertTrue(r.text().startsWith("subscription OnMessage {"), r.text());
    }

    @Test
    void wsSubscribeWithoutHeader() throws Exception {
        MessageContext m = ws("{\"id\":\"1\",\"type\":\"subscribe\",\"payload\":{\"query\":\"subscription { a }\"}}", null);
        assertEquals(90, gql.match(m).confidence());
        assertEquals("graphql-transport-ws (inferred from message type)", find(gql.decode(m).root(), "Protocol"));
    }

    @Test
    void wsNextAndErrorAndComplete() throws Exception {
        MessageContext next = ws("{\"id\":\"1\",\"type\":\"next\",\"payload\":{\"data\":{\"messageAdded\":{\"id\":\"7\"}}}}", null);
        assertEquals(80, gql.match(next).confidence());
        assertEquals("GraphQL WS next #1: data (1 root field)", gql.decode(next).summary());

        MessageContext err = ws("{\"id\":\"1\",\"type\":\"error\",\"payload\":[{\"message\":\"Forbidden\"}]}", "graphql-transport-ws");
        assertEquals("GraphQL WS error #1: 1 error — Forbidden", gql.decode(err).summary());

        MessageContext complete = ws("{\"id\":\"1\",\"type\":\"complete\"}", null);
        assertEquals(30, gql.match(complete).confidence());
        assertEquals("GraphQL WS complete #1", gql.decode(complete).summary());

        MessageContext ping = ws("{\"type\":\"ping\"}", null);
        assertEquals(25, gql.match(ping).confidence());
        assertEquals(95, gql.match(ws("{\"type\":\"pong\"}", "graphql-transport-ws")).confidence());
    }

    @Test
    void wsConnectionInitShowsParams() throws Exception {
        MessageContext m = ws("{\"type\":\"connection_init\",\"payload\":{\"Authorization\":\"Bearer abc\"}}", null);
        assertEquals(60, gql.match(m).confidence());
        DecodeResult r = gql.decode(m);
        assertEquals("GraphQL WS connection_init (payload: Authorization)", r.summary());
        assertEquals("Bearer abc", find(r.root().get("Connection parameters"), "Authorization"));
        assertEquals(60, gql.match(ws("{\"type\":\"connection_ack\"}", null)).confidence());
    }

    @Test
    void wsLegacyProtocol() throws Exception {
        MessageContext start = ws("{\"id\":\"2\",\"type\":\"start\",\"payload\":{\"query\":\"subscription S { s }\",\"operationName\":\"S\"}}", "graphql-ws");
        assertEquals(95, gql.match(start).confidence());
        DecodeResult r = gql.decode(start);
        assertEquals("GraphQL WS start #2: subscription S (1 root field)", r.summary());
        assertEquals("subscriptions-transport-ws (graphql-ws)", find(r.root(), "Protocol"));

        MessageContext data = ws("{\"id\":\"2\",\"type\":\"data\",\"payload\":{\"data\":{\"s\":1}}}", null);
        assertEquals(80, gql.match(data).confidence());
        assertEquals("subscriptions-transport-ws (graphql-ws) (inferred from message type)", find(gql.decode(data).root(), "Protocol"));

        assertEquals(60, gql.match(ws("{\"type\":\"ka\"}", null)).confidence());
        assertEquals(95, gql.match(ws("{\"type\":\"ka\"}", "graphql-ws")).confidence());
        assertEquals(30, gql.match(ws("{\"id\":\"2\",\"type\":\"stop\"}", null)).confidence());
        assertEquals("GraphQL WS connection_terminate", gql.decode(ws("{\"type\":\"connection_terminate\"}", "graphql-ws")).summary());
        DecodeResult ce = gql.decode(ws("{\"type\":\"connection_error\",\"payload\":{\"message\":\"bad token\"}}", "graphql-ws"));
        assertEquals("GraphQL WS connection_error: bad token", ce.summary());
    }

    @Test
    void wsProtocolMismatchWarns() throws Exception {
        DecodeResult r = gql.decode(ws("{\"id\":\"1\",\"type\":\"start\",\"payload\":{\"query\":\"subscription { a }\"}}", "graphql-transport-ws"));
        assertFalse(r.warnings().isEmpty());
    }

    @Test
    void wsAppSyncStringData() throws Exception {
        MessageContext m = ws("{\"id\":\"9\",\"type\":\"data\",\"payload\":{\"data\":\"{\\\"onCreate\\\":{\\\"id\\\":\\\"x\\\"}}\"}}", null);
        assertEquals(80, gql.match(m).confidence());
        DecodeResult r = gql.decode(m);
        assertEquals("GraphQL WS data #9: data (1 root field)", r.summary());
        assertEquals("x", find(r.root(), "id"));
    }
}
