package protocoldecoder.builtin.graphql;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.scan.ActiveCheck;
import protocoldecoder.scan.Confidence;
import protocoldecoder.scan.Exchange;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.HttpSender;
import protocoldecoder.scan.InsertionPoint;
import protocoldecoder.scan.Severity;
import protocoldecoder.util.Codecs;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

class GraphQlScannerTest {

    static final String PAYLOAD = "x\"' OR \\1=1--\n<ü𝄞>";

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });
    final GraphQlDecoder gql = new GraphQlDecoder();

    @AfterEach
    void close() {
        app.close();
    }

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    static MessageContext.Builder postJson(String body) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://api.example.com/graphql")
                .requestHeader("Host", "api.example.com").requestHeader("Content-Type", "application/json")
                .requestHeader("Cookie", "sid=abc").requestHeader("Authorization", "Bearer t0k3n").requestHeader("apollo-require-preflight", "true")
                .requestBody(body);
    }

    static String op(String query, String vars, String name) {
        JsonObject o = new JsonObject();
        o.addProperty("query", query);
        if (name != null) o.addProperty("operationName", name);
        if (vars != null) o.add("variables", JsonParser.parseString(vars));
        return o.toString();
    }

    static MessageContext response(MessageContext.Builder req, String body) {
        return req.statusCode(200).responseHeader("Content-Type", "application/json").responseBody(body).build().withKind(MessageKind.RESPONSE);
    }

    static InsertionPoint ip(List<InsertionPoint> ips, String name) {
        return ips.stream().filter(i -> i.name().equals(name)).findFirst()
                .orElseThrow(() -> new AssertionError(name + " not in " + ips.stream().map(InsertionPoint::name).toList()));
    }

    static GraphQlLiterals.Literal literal(String query, String path) {
        return GraphQlLiterals.find(query, 500).stream().filter(l -> l.path().equals(path)).findFirst()
                .orElseThrow(() -> new AssertionError(path + " not in " + GraphQlLiterals.find(query, 500)));
    }

    List<InsertionPoint> points(MessageContext m) {
        return app.scanEngine().insertionPoints(m).stream().filter(i -> i.name().startsWith("GraphQL:")).toList();
    }

    List<Finding> passive(MessageContext m, String checkId) {
        return app.scanEngine().passive(m, false).stream().filter(f -> f.checkId().equals(checkId)).toList();
    }

    // ================================================================== insertion points

    static final String DOC = "query GetUser($id: ID = \"dflt\", $n: Int) {\n"
            + "  user(id: \"5\", filter: {name: \"x\\\"y\", tags: [\"a\", \"b\"], nested: {deep: 1.5}}, limit: 10, role: ADMIN, ref: $id, on: true) {\n"
            + "    id\n"
            + "    note(text: \"\"\"keep \"this\" \\n\"\"\")\n"
            + "    posts(first: 3) @include(if: true) { title }\n"
            + "    ...UserFields\n"
            + "    ... on Admin { level(scale: 2) }\n"
            + "  }\n"
            + "  alias: settings(key: \"theme\") { value }\n"
            + "}\n"
            + "fragment UserFields on User { avatar(size: 64) }";

    @Test
    void literalPathsInQueryDocument() {
        List<String> paths = GraphQlLiterals.find(DOC, 500).stream().map(l -> l.definition() + " " + l.path()).toList();
        assertEquals(List.of("GetUser user.id", "GetUser user.filter.name", "GetUser user.filter.tags[0]", "GetUser user.filter.tags[1]",
                "GetUser user.filter.nested.deep", "GetUser user.limit", "GetUser user.role", "GetUser user.note.text",
                "GetUser user.posts.first", "GetUser user.level.scale", "GetUser settings.key", "fragment UserFields avatar.size"), paths);
        assertEquals("x\"y", literal(DOC, "user.filter.name").baseValue());
        assertEquals("keep \"this\" \\n", literal(DOC, "user.note.text").baseValue());
    }

    @Test
    void inlineLiteralRoundTripInJsonBody() throws Exception {
        MessageContext m = postJson(op(DOC, "{\"n\":1}", "GetUser")).build();
        List<InsertionPoint> ips = points(m);
        // plain JSON variables in a single-op body are left to Burp
        assertTrue(ips.stream().noneMatch(i -> i.name().contains("$vars")), ips.toString());
        InsertionPoint p = ip(ips, "GraphQL: GetUser arg user.filter.name");
        assertEquals(InsertionPoint.Part.BODY, p.part());
        assertEquals("x\"y", p.baseValue());

        byte[] body = p.render().apply(PAYLOAD);
        MessageContext rendered = postJson(new String(body, StandardCharsets.UTF_8)).build();
        DecodeResult r = gql.decode(rendered);
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
        String q = JsonParser.parseString(new String(body, StandardCharsets.UTF_8)).getAsJsonObject().get("query").getAsString();
        assertEquals(PAYLOAD, literal(q, "user.filter.name").baseValue());
        assertTrue(q.contains("\"\"\"keep \"this\" \\n\"\"\""), "block string untouched: " + q);
        assertEquals("\"5\"", q.substring(literal(q, "user.id").start(), literal(q, "user.id").end()));
        assertEquals(GraphQlLiterals.find(DOC, 500).size(), GraphQlLiterals.find(q, 500).size());
        assertEquals("{\"n\":1}", JsonParser.parseString(new String(body, StandardCharsets.UTF_8)).getAsJsonObject().get("variables").toString());
    }

    @Test
    void numericAndEnumLiterals() {
        MessageContext m = postJson(op(DOC, null, null)).build();
        List<InsertionPoint> ips = points(m);
        InsertionPoint limit = ip(ips, "GraphQL: GetUser arg user.limit");
        assertEquals("10", limit.baseValue());
        String q1 = queryOf(limit.render().apply("42"));
        assertTrue(q1.contains("limit: 42,"), q1);
        String q2 = queryOf(limit.render().apply("10 OR 1=1"));
        assertTrue(q2.contains("limit: \"10 OR 1=1\","), q2);
        InsertionPoint role = ip(ips, "GraphQL: GetUser arg user.role");
        assertEquals("ADMIN", role.baseValue());
        assertTrue(queryOf(role.render().apply("x")).contains("role: \"x\""));
        // variable references, booleans and variable defaults are not insertion points
        assertTrue(ips.stream().noneMatch(i -> i.name().endsWith("user.ref") || i.name().endsWith("user.on") || i.baseValue().equals("dflt")));
    }

    static String queryOf(byte[] body) {
        return JsonParser.parseString(new String(body, StandardCharsets.UTF_8)).getAsJsonObject().get("query").getAsString();
    }

    @Test
    void quoteEscapesEverything() {
        String s = "a\"b\\c\nd\re\tf\u0001g\u00e9\uD834\uDD1E";
        String q = GraphQlLiterals.quote(s);
        assertEquals("\"a\\\"b\\\\c\\nd\\re\\tf\\u0001g\u00e9\uD834\uDD1E\"", q);
        assertEquals(s, GraphQlLiterals.unescape(q.substring(1, q.length() - 1)));
        GraphQlLexer.Result lex = GraphQlLexer.tokenize("{ a(x: " + q + ") }", 100);
        assertTrue(lex.errors.isEmpty());
    }

    @Test
    void getQueryAndVariablesRoundTrip() throws Exception {
        String query = "query Search($q: String!) { search(term: $q, kind: \"post\") { id } }";
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("GET")
                .url("https://api.example.com/graphql?operationName=Search&query=" + enc(query) + "&variables=" + enc("{\"q\":\"hello\",\"page\":{\"n\":2}}") + "&x=1")
                .build();
        List<InsertionPoint> ips = points(m);
        InsertionPoint v = ip(ips, "GraphQL: Search $vars.q");
        assertEquals(InsertionPoint.Part.QUERY, v.part());
        assertEquals("hello", v.baseValue());
        ip(ips, "GraphQL: Search $vars.page.n");
        String qs = new String(v.render().apply(PAYLOAD), StandardCharsets.ISO_8859_1);
        assertTrue(qs.chars().allMatch(c -> c < 128 && c != ' '), qs);
        Map<String, List<String>> p = Codecs.parseQuery(qs);
        assertEquals(PAYLOAD, JsonParser.parseString(Codecs.first(p, "variables")).getAsJsonObject().get("q").getAsString());
        assertEquals(query, Codecs.first(p, "query"));
        assertTrue(qs.startsWith("operationName=Search&query=") && qs.endsWith("&x=1"), qs);
        MessageContext again = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://api.example.com/graphql?" + qs).build();
        assertTrue(gql.decode(again).warnings().isEmpty());

        InsertionPoint kind = ip(ips, "GraphQL: Search arg search.kind");
        Map<String, List<String>> p2 = Codecs.parseQuery(new String(kind.render().apply(PAYLOAD), StandardCharsets.ISO_8859_1));
        assertEquals(PAYLOAD, literal(Codecs.first(p2, "query"), "search.kind").baseValue());
        assertEquals("{\"q\":\"hello\",\"page\":{\"n\":2}}", Codecs.first(p2, "variables"), "variables untouched");
    }

    @Test
    void formBodyTransport() {
        String query = "{ product(sku: \"A-1\") { name } }";
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://api.example.com/graphql")
                .requestHeader("Content-Type", "application/x-www-form-urlencoded")
                .requestBody("query=" + enc(query) + "&variables=" + enc("{\"a\":\"b\"}")).build();
        List<InsertionPoint> ips = points(m);
        InsertionPoint a = ip(ips, "GraphQL: query arg product.sku");
        assertEquals(InsertionPoint.Part.BODY, a.part());
        Map<String, List<String>> p = Codecs.parseQuery(new String(a.render().apply(PAYLOAD), StandardCharsets.ISO_8859_1));
        assertEquals(PAYLOAD, literal(Codecs.first(p, "query"), "product.sku").baseValue());
        ip(ips, "GraphQL: query $vars.a");
    }

    @Test
    void multipartOperationsRoundTrip() throws Exception {
        String b = "----X1";
        String ops = "{\"query\":\"mutation Upload($file: Upload!, $input: Meta!) { upload(file: $file, input: $input, folder: \\\"docs\\\") { id } }\","
                + "\"variables\":{\"file\":null,\"input\":{\"name\":\"a.txt\",\"tags\":[\"x\"]}}}";
        String tail = "--" + b + "\r\nContent-Disposition: form-data; name=\"map\"\r\n\r\n{\"0\":[\"variables.file\"]}\r\n"
                + "--" + b + "\r\nContent-Disposition: form-data; name=\"0\"; filename=\"a.txt\"\r\nContent-Type: application/octet-stream\r\n\r\n\u00ff\u00fe\u0000bin\r\n"
                + "--" + b + "--\r\n";
        byte[] body = Codecs.latin1Bytes("--" + b + "\r\nContent-Disposition: form-data; name=\"operations\"\r\n\r\n" + ops + "\r\n" + tail);
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://api.example.com/graphql")
                .requestHeader("Content-Type", "multipart/form-data; boundary=" + b).requestBody(body).build();
        List<InsertionPoint> ips = points(m);
        InsertionPoint name = ip(ips, "GraphQL: Upload $vars.input.name");
        ip(ips, "GraphQL: Upload $vars.input.tags[0]");
        ip(ips, "GraphQL: Upload arg upload.folder");
        byte[] out = name.render().apply(PAYLOAD);
        assertTrue(Codecs.latin1String(out).endsWith("\r\n" + tail), "rest of the multipart body is byte-identical");
        MessageContext rendered = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://api.example.com/graphql")
                .requestHeader("Content-Type", "multipart/form-data; boundary=" + b).requestBody(out).build();
        DecodeResult r = gql.decode(rendered);
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
        GraphQlHttpRequest parsed = GraphQlHttpRequest.parse(rendered);
        assertEquals(PAYLOAD, parsed.operations().get(0).getAsJsonObject("variables").getAsJsonObject("input").get("name").getAsString());

        byte[] out2 = ip(ips, "GraphQL: Upload arg upload.folder").render().apply(PAYLOAD);
        GraphQlHttpRequest p2 = GraphQlHttpRequest.parse(MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://api.example.com/graphql")
                .requestHeader("Content-Type", "multipart/form-data; boundary=" + b).requestBody(out2).build());
        assertEquals(PAYLOAD, literal(p2.operations().get(0).get("query").getAsString(), "upload.folder").baseValue());
    }

    @Test
    void batchVariablesPerOperation() throws Exception {
        String body = "[" + op("query A($id: ID!) { node(id: $id) { id } }", "{\"id\":\"1\"}", "A") + ","
                + op("query B($q: String) { search(q: $q, limit: 5) { id } }", "{\"q\":\"x\"}", "B") + "]";
        MessageContext m = postJson(body).build();
        List<InsertionPoint> ips = points(m);
        ip(ips, "GraphQL: [0] A $vars.id");
        ip(ips, "GraphQL: [1] B arg search.limit");
        InsertionPoint q = ip(ips, "GraphQL: [1] B $vars.q");
        String out = new String(q.render().apply(PAYLOAD), StandardCharsets.UTF_8);
        JsonArray a = JsonParser.parseString(out).getAsJsonArray();
        assertEquals("1", a.get(0).getAsJsonObject().getAsJsonObject("variables").get("id").getAsString());
        assertEquals(PAYLOAD, a.get(1).getAsJsonObject().getAsJsonObject("variables").get("q").getAsString());
        assertTrue(gql.decode(postJson(out).build()).warnings().isEmpty());
    }

    @Test
    void stringifiedVariablesInJsonBodyStayStrings() {
        JsonObject o = new JsonObject();
        o.addProperty("query", "query Q($id: ID!) { node(id: $id) { id } }");
        o.addProperty("variables", "{\"id\":\"7\"}");
        List<InsertionPoint> ips = points(postJson(o.toString()).build());
        InsertionPoint v = ip(ips, "GraphQL: Q $vars.id");
        JsonObject out = JsonParser.parseString(new String(v.render().apply(PAYLOAD), StandardCharsets.UTF_8)).getAsJsonObject();
        assertTrue(out.get("variables").getAsJsonPrimitive().isString());
        assertEquals(PAYLOAD, JsonParser.parseString(out.get("variables").getAsString()).getAsJsonObject().get("id").getAsString());
    }

    @Test
    void applicationGraphqlBody() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://api.example.com/graphql")
                .requestHeader("Content-Type", "application/graphql").requestBody("{ user(name: \"bob\") { id } }").build();
        InsertionPoint p = ip(points(m), "GraphQL: query arg user.name");
        String out = new String(p.render().apply(PAYLOAD), StandardCharsets.UTF_8);
        assertEquals("{ user(name: " + GraphQlLiterals.quote(PAYLOAD) + ") { id } }", out);
    }

    @Test
    void noPointsForMalformedOrNonGraphQl() {
        assertTrue(GraphQlLiterals.find("{ user(id: \"unterminated) { id } }", 10).isEmpty());
        assertTrue(new GraphQlScanner().insertionPoints(postJson("{\"a\":1}").build(), null).isEmpty());
    }

    // ================================================================== passive

    static final String SCHEMA = "{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"},\"mutationType\":{\"name\":\"Mutation\"},"
            + "\"types\":[{\"name\":\"Query\",\"kind\":\"OBJECT\"},{\"name\":\"User\",\"kind\":\"OBJECT\"},{\"name\":\"__Schema\",\"kind\":\"OBJECT\"}]}}}";

    @Test
    void introspectionPassive() {
        MessageContext pos = response(postJson(op("query IntrospectionQuery { __schema { queryType { name } types { name kind } } }", null, null)), SCHEMA);
        Finding f = passive(pos, "graphql.introspection-enabled").get(0);
        assertEquals(Severity.LOW, f.severity());
        assertEquals(Confidence.CERTAIN, f.confidence());
        assertEquals(Finding.Scope.HOST, f.scope());
        assertTrue(f.detail().contains("3 types"), f.detail());
        MessageContext neg = response(postJson(op("{ me { id } }", null, null)), "{\"data\":{\"me\":{\"id\":\"1\"}}}");
        assertTrue(passive(neg, "graphql.introspection-enabled").isEmpty());
    }

    @Test
    void suggestionsPassive() {
        MessageContext pos = response(postJson(op("{ usr { id } }", null, null)),
                "{\"errors\":[{\"message\":\"Cannot query field \\\"usr\\\" on type \\\"Query\\\". Did you mean \\\"user\\\" or \\\"users\\\"?\",\"locations\":[{\"line\":1,\"column\":3}]}]}");
        Finding f = passive(pos, "graphql.field-suggestions").get(0);
        assertEquals(GraphQlScanner.SUGGESTIONS_TITLE, f.title());
        MessageContext neg = response(postJson(op("{ usr { id } }", null, null)),
                "{\"errors\":[{\"message\":\"Cannot query field \\\"usr\\\" on type \\\"Query\\\".\"}]}");
        assertTrue(passive(neg, "graphql.field-suggestions").isEmpty());
    }

    @Test
    void verboseErrorsPassive() {
        MessageContext apollo = response(postJson(op("{ me { id } }", null, null)),
                "{\"errors\":[{\"message\":\"boom\",\"extensions\":{\"code\":\"INTERNAL_SERVER_ERROR\",\"exception\":{\"stacktrace\":"
                        + "[\"TypeError: Cannot read properties of undefined (reading 'id')\",\"    at Query.me (/app/src/resolvers.js:12:20)\"]}}}],\"data\":null}");
        Finding f = passive(apollo, "graphql.verbose-errors").get(0);
        assertTrue(f.detail().contains("extensions.exception.stacktrace"), f.detail());
        assertEquals(Severity.LOW, f.severity());
        MessageContext php = response(postJson(op("{ me { id } }", null, null)),
                "{\"errors\":[{\"message\":\"Internal server error\",\"extensions\":{\"debugMessage\":\"SQLSTATE[42S02]: Base table not found\"}}]}");
        assertFalse(passive(php, "graphql.verbose-errors").isEmpty());
        MessageContext neg = response(postJson(op("{ me { id } }", null, null)),
                "{\"errors\":[{\"message\":\"Not authorised\",\"path\":[\"me\"],\"extensions\":{\"code\":\"UNAUTHENTICATED\"}}],\"data\":{\"me\":null}}");
        assertTrue(passive(neg, "graphql.verbose-errors").isEmpty());
    }

    @Test
    void verboseErrorsOverWebSocket() {
        MessageContext ws = MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("wss://api.example.com/graphql")
                .requestHeader("Sec-WebSocket-Protocol", "graphql-transport-ws")
                .webSocket("SERVER_TO_CLIENT", ("{\"id\":\"1\",\"type\":\"error\",\"payload\":[{\"message\":\"x\",\"extensions\":{\"stacktrace\":"
                        + "[\"Error: x\",\"    at resolve (/srv/app.js:1:1)\"]}}]}").getBytes(StandardCharsets.UTF_8)).build();
        assertFalse(passive(ws, "graphql.verbose-errors").isEmpty());
    }

    @Test
    void batchingPassive() {
        String req = "[" + op("{ a }", null, null) + "," + op("{ b }", null, null) + "]";
        Finding f = passive(response(postJson(req), "[{\"data\":{\"a\":1}},{\"data\":{\"b\":2}}]"), "graphql.batching").get(0);
        assertEquals(Severity.INFORMATION, f.severity());
        assertTrue(passive(response(postJson(op("{ a }", null, null)), "{\"data\":{\"a\":1}}"), "graphql.batching").isEmpty());
    }

    @Test
    void persistedQueriesPassive() {
        MessageContext apq = MessageContext.builder(MessageKind.REQUEST).method("GET")
                .url("https://api.example.com/graphql?operationName=Feed&extensions=" + enc("{\"persistedQuery\":{\"version\":1,\"sha256Hash\":\"ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38\"}}"))
                .build();
        Finding f = passive(apq, "graphql.persisted-queries").get(0);
        assertTrue(f.detail().contains("without sending the query text"), f.detail());
        assertTrue(passive(postJson(op("{ a }", null, null)).build(), "graphql.persisted-queries").isEmpty());
    }

    @Test
    void mutationOverGetPassive() {
        String mutation = "mutation Del { deleteComment(id: \"9\") { ok } }";
        MessageContext.Builder get = MessageContext.builder(MessageKind.REQUEST).method("GET")
                .url("https://api.example.com/graphql?query=" + enc(mutation)).requestHeader("Cookie", "sid=1");
        Finding f = passive(response(get, "{\"data\":{\"deleteComment\":{\"ok\":true}}}"), "graphql.mutation-csrf").get(0);
        assertEquals(Severity.MEDIUM, f.severity());
        assertEquals("GraphQL mutation executed via GET", f.title());
        // rejected mutation, or a query over GET, is not reported
        assertTrue(passive(response(get, "{\"errors\":[{\"message\":\"Can only perform a mutation operation from a POST request.\"}]}"), "graphql.mutation-csrf").isEmpty());
        MessageContext.Builder q = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://api.example.com/graphql?query=" + enc("{ me { id } }"));
        assertTrue(passive(response(q, "{\"data\":{\"me\":{\"id\":\"1\"}}}"), "graphql.mutation-csrf").isEmpty());
    }

    @Test
    void sensitiveDataPassive() {
        String body = "{\"data\":{\"users\":[{\"email\":\"a@example.com\",\"passwordHash\":\"$2b$10$abcdefghijklmnopqrstuv\",\"passwordChangedAt\":\"2024-01-01\","
                + "\"session\":\"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl\"}],\"nextPageToken\":\"abcdefgh\"}}";
        Finding f = passive(response(postJson(op("{ users { email passwordHash passwordChangedAt session } }", null, null)), body), "graphql.sensitive-data").get(0);
        assertEquals(Confidence.TENTATIVE, f.confidence());
        assertTrue(f.detail().contains("passwordHash"), f.detail());
        assertTrue(f.detail().contains("JWT"), f.detail());
        assertFalse(f.detail().contains("a@example.com"), f.detail());
        assertFalse(f.detail().contains("passwordChangedAt"), f.detail());
        assertFalse(f.detail().contains("nextPageToken"), f.detail());
        String benign = "{\"data\":{\"me\":{\"email\":\"a@example.com\",\"passwordResetRequired\":false,\"pageToken\":\"abcdefgh12\",\"name\":\"Ann\"}}}";
        assertTrue(passive(response(postJson(op("{ me { email } }", null, null)), benign), "graphql.sensitive-data").isEmpty());
    }

    // ================================================================== active

    record Sent(String method, String path, List<Header> headers, String body) {
        String header(String name) {
            return headers.stream().filter(h -> h.name().equalsIgnoreCase(name)).map(Header::value).findFirst().orElse(null);
        }

        String param(String name) {
            int q = path.indexOf('?');
            return q < 0 ? null : Codecs.first(Codecs.parseQuery(path.substring(q + 1)), name);
        }

        String query() {
            if (param("query") != null) return param("query");
            String b = body.strip();
            if (b.startsWith("{")) return JsonParser.parseString(b).getAsJsonObject().get("query").getAsString();
            return Codecs.first(Codecs.parseQuery(body), "query");
        }
    }

    /** Fake server: handler returns {status, content-type, body}, or null for a 404. */
    static final class FakeServer implements HttpSender {
        final List<Sent> sent = new ArrayList<>();
        final Function<Sent, String[]> handler;

        FakeServer(Function<Sent, String[]> handler) {
            this.handler = handler;
        }

        @Override
        public Exchange send(String method, String pathAndQuery, List<Header> headers, byte[] body) {
            Sent s = new Sent(method, pathAndQuery, headers, new String(body, StandardCharsets.UTF_8));
            sent.add(s);
            String[] r = handler.apply(s);
            if (r == null) r = new String[]{"404", "text/plain", "not found"};
            MessageContext m = MessageContext.builder(MessageKind.REQUEST).method(method).url("https://api.example.com" + pathAndQuery)
                    .requestHeaders(headers).requestBody(body).statusCode(Integer.parseInt(r[0]))
                    .responseHeader("Content-Type", r[1]).responseBody(r[2]).build();
            return new Exchange(m, null);
        }

        @Override
        public Exchange send(InsertionPoint point, String payload) {
            throw new UnsupportedOperationException();
        }
    }

    static String[] json(String body) {
        return new String[]{"200", "application/json", body};
    }

    List<Finding> active(ActiveCheck.Scope scope, MessageContext base, FakeServer server, String checkId) {
        MessageContext req = base.isRequest() ? base : base.withKind(MessageKind.REQUEST);
        MessageContext resp = base.hasResponse() ? req.withKind(MessageKind.RESPONSE) : null;
        return app.scanEngine().active(scope, req, resp, null, null, null, server).stream().filter(f -> f.checkId().equals(checkId)).toList();
    }

    void only(String checkId) {
        for (var c : app.scanEngine().checks()) {
            if (c.kind() == protocoldecoder.scan.CheckInfo.Kind.ACTIVE && !c.id().equals(checkId)) app.scanEngine().setEnabled(c.id(), false);
        }
    }

    static final String ME = op("query Me { me { id name } }", null, "Me");
    static final String ME_DATA = "{\"data\":{\"me\":{\"id\":\"1\",\"name\":\"Ann\"}}}";

    @Test
    void introspectionProbe() {
        only("graphql.introspection-probe");
        FakeServer open = new FakeServer(s -> s.query().contains("types")
                ? json("{\"data\":{\"__schema\":{\"types\":[{\"name\":\"Query\"},{\"name\":\"User\"}]}}}")
                : json("{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"}}}}"));
        List<Finding> f = active(ActiveCheck.Scope.PER_HOST, response(postJson(ME), ME_DATA), open, "graphql.introspection-probe");
        assertEquals(2, open.sent.size());
        assertEquals("{__schema{queryType{name}}}", open.sent.get(0).query());
        assertEquals("application/json", open.sent.get(0).header("Content-Type"));
        assertEquals("sid=abc", open.sent.get(0).header("Cookie"));
        assertEquals(1, f.size());
        assertTrue(f.get(0).detail().contains("2 types"), f.get(0).detail());
        assertEquals(2, f.get(0).exchanges().size());

        FakeServer closed = new FakeServer(s -> json("{\"errors\":[{\"message\":\"GraphQL introspection is not allowed\"}]}"));
        assertTrue(active(ActiveCheck.Scope.PER_HOST, response(postJson(ME), ME_DATA), closed, "graphql.introspection-probe").isEmpty());
        assertEquals(1, closed.sent.size());

        // already observed in the base response: no request
        FakeServer unused = new FakeServer(s -> json(SCHEMA));
        active(ActiveCheck.Scope.PER_HOST, response(postJson(op("{ __schema { types { name } } }", null, null)), SCHEMA), unused, "graphql.introspection-probe");
        assertTrue(unused.sent.isEmpty());
    }

    @Test
    void suggestionsProbe() {
        only("graphql.suggestions-probe");
        FakeServer yes = new FakeServer(s -> json("{\"errors\":[{\"message\":\"Cannot query field \\\"mex\\\" on type \\\"Query\\\". Did you mean \\\"me\\\"?\"}]}"));
        List<Finding> f = active(ActiveCheck.Scope.PER_HOST, postJson(ME).build(), yes, "graphql.suggestions-probe");
        assertEquals(1, yes.sent.size());
        assertEquals("{ mex }", yes.sent.get(0).query());
        assertEquals(1, f.size());
        FakeServer no = new FakeServer(s -> json("{\"errors\":[{\"message\":\"Cannot query field \\\"mex\\\" on type \\\"Query\\\".\"}]}"));
        assertTrue(active(ActiveCheck.Scope.PER_HOST, postJson(ME).build(), no, "graphql.suggestions-probe").isEmpty());
        // a mutation base request is never used to build a probe
        FakeServer none = new FakeServer(s -> json("{}"));
        active(ActiveCheck.Scope.PER_HOST, postJson(op("mutation { logout { ok } }", null, null)).build(), none, "graphql.suggestions-probe");
        assertTrue(none.sent.isEmpty());
    }

    @Test
    void csrfProbeAcceptsGetAndForm() {
        only("graphql.csrf-probe");
        FakeServer lax = new FakeServer(s -> s.query().contains("me") ? json(ME_DATA) : null);
        String body = op("query Me($v: Int) { me { id name } }", "{\"v\":1}", "Me");
        List<Finding> f = active(ActiveCheck.Scope.PER_REQUEST, response(postJson(body), ME_DATA), lax, "graphql.csrf-probe");
        assertEquals(2, lax.sent.size());
        Sent get = lax.sent.get(0), form = lax.sent.get(1);
        assertEquals("GET", get.method());
        assertEquals("{\"v\":1}", get.param("variables"));
        assertEquals("Me", get.param("operationName"));
        assertNull(get.header("Authorization"));
        assertNull(get.header("apollo-require-preflight"));
        assertEquals("sid=abc", get.header("Cookie"));
        assertEquals("POST", form.method());
        assertEquals("application/x-www-form-urlencoded", form.header("Content-Type"));
        assertNotNull(form.header("Origin"));
        assertEquals("query Me($v: Int) { me { id name } }", Codecs.first(Codecs.parseQuery(form.body()), "query"));
        assertEquals(2, f.size());
        Finding fg = f.stream().filter(x -> x.title().contains("GET")).findFirst().orElseThrow();
        Finding fp = f.stream().filter(x -> x.title().contains("form POST")).findFirst().orElseThrow();
        assertEquals(Severity.LOW, fg.severity());
        assertEquals(Severity.MEDIUM, fp.severity());
        assertEquals(Confidence.FIRM, fp.confidence());
        assertTrue(fp.detail().contains("only sent a query"), fp.detail());
    }

    @Test
    void csrfProbeNegative() {
        only("graphql.csrf-probe");
        FakeServer strict = new FakeServer(s -> new String[]{"400", "application/json",
                "{\"errors\":[{\"message\":\"This operation has been blocked as a potential Cross-Site Request Forgery (CSRF).\"}]}"});
        assertTrue(active(ActiveCheck.Scope.PER_REQUEST, response(postJson(ME), ME_DATA), strict, "graphql.csrf-probe").isEmpty());
        assertEquals(2, strict.sent.size());
        // mutations are never re-sent
        FakeServer none = new FakeServer(s -> json(ME_DATA));
        active(ActiveCheck.Scope.PER_REQUEST, response(postJson(op("mutation M { like(id: 1) { ok } }", null, null)), "{\"data\":{\"like\":{\"ok\":true}}}"),
                none, "graphql.csrf-probe");
        assertTrue(none.sent.isEmpty());
    }

    @Test
    void batchingProbe() {
        only("graphql.batching-probe");
        FakeServer yes = new FakeServer(s -> s.body().startsWith("[") ? json("[" + ME_DATA + "," + ME_DATA + "]") : json(ME_DATA));
        List<Finding> f = active(ActiveCheck.Scope.PER_HOST, postJson(ME).build(), yes, "graphql.batching-probe");
        assertEquals(1, yes.sent.size());
        assertEquals(2, JsonParser.parseString(yes.sent.get(0).body()).getAsJsonArray().size());
        assertEquals(1, f.size());
        FakeServer no = new FakeServer(s -> new String[]{"400", "application/json", "{\"errors\":[{\"message\":\"Operation batching is disabled\"}]}"});
        assertTrue(active(ActiveCheck.Scope.PER_HOST, postJson(ME).build(), no, "graphql.batching-probe").isEmpty());
        FakeServer none = new FakeServer(s -> json("[]"));
        active(ActiveCheck.Scope.PER_HOST, postJson(op("mutation { a }", null, null)).build(), none, "graphql.batching-probe");
        assertTrue(none.sent.isEmpty());
    }

    @Test
    void ideProbe() {
        only("graphql.ide-exposed");
        FakeServer ide = new FakeServer(s -> new String[]{"200", "text/html",
                "<!DOCTYPE html><html><head><title>GraphiQL</title><script src=\"https://unpkg.com/graphiql/graphiql.min.js\"></script></head><body><div id=\"graphiql\"></div></body></html>"});
        List<Finding> f = active(ActiveCheck.Scope.PER_HOST, postJson(ME).build(), ide, "graphql.ide-exposed");
        assertEquals(1, ide.sent.size());
        assertEquals("GET", ide.sent.get(0).method());
        assertEquals("/graphql", ide.sent.get(0).path());
        assertEquals(1, f.size());
        assertTrue(f.get(0).detail().contains("GraphiQL"));
        FakeServer api = new FakeServer(s -> new String[]{"400", "application/json", "{\"errors\":[{\"message\":\"GET query missing.\"}]}"});
        assertTrue(active(ActiveCheck.Scope.PER_HOST, postJson(ME).build(), api, "graphql.ide-exposed").isEmpty());
    }

    @Test
    void checksAreListed() {
        List<String> ids = app.scanEngine().checks().stream().map(c -> c.id()).toList();
        for (String id : List.of("graphql.introspection-enabled", "graphql.field-suggestions", "graphql.verbose-errors", "graphql.batching",
                "graphql.persisted-queries", "graphql.mutation-csrf", "graphql.sensitive-data", "graphql.introspection-probe",
                "graphql.suggestions-probe", "graphql.csrf-probe", "graphql.batching-probe", "graphql.ide-exposed", "graphql.insertion-points")) {
            assertTrue(ids.contains(id), id);
        }
        app.scanEngine().checks().stream().filter(c -> c.decoderId().equals("graphql") && c.kind() != protocoldecoder.scan.CheckInfo.Kind.INSERTION_POINTS)
                .forEach(c -> assertFalse(c.description().isBlank(), c.id()));
    }
}
