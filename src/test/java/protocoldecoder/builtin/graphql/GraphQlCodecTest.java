package protocoldecoder.builtin.graphql;

import org.junit.jupiter.api.Test;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.edit.CodecTestSupport;
import protocoldecoder.edit.EditEngine;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.edit.JsonDocuments;
import protocoldecoder.util.Codecs;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class GraphQlCodecTest extends CodecTestSupport {

    static final String Q = "query GetUser($id: ID!) { user(id: $id) { name email } }";

    static MessageContext postJson(String body) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://api.example.com/graphql")
                .requestHeader("Content-Type", "application/json").requestBody(body).build();
    }

    /** All documents except the formatted query, which by design sends the re-formatted text. */
    List<EditEngine.Document> exact(MessageContext m) {
        return docs(m).stream().filter(d -> !d.document().title().contains("(formatted)")).toList();
    }

    static String quote(String s) {
        return JsonDocuments.quote(s, JsonDocuments.Style.PLAIN);
    }

    @Test
    void jsonRequestOffersQueryFormattedQueryAndVariables() throws Exception {
        String body = "{\"operationName\":\"GetUser\",\"query\":" + quote(Q) + ",\"variables\":{\"id\":\"42\",\"n\":1.0},\"extensions\":{\"x\":1}}";
        MessageContext m = postJson(body);
        assertEquals(List.of("GraphQL query", "GraphQL query (formatted)", "GraphQL variables"), titles(m));
        assertAllRoundTrip(exact(m), m);

        EditEngine.Document q = doc(m, "GraphQL query");
        assertEquals("graphql", q.document().syntax());
        assertEquals(Q, q.document().text());
        EditEngine.Document vars = doc(m, "GraphQL variables");
        assertEquals("{\n  \"id\": \"42\",\n  \"n\": 1.0\n}", vars.document().text());

        MessageContext edited = apply(vars, m, vars.document().text().replace("\"42\"", "\"1337\""));
        assertEquals(body.replace("\"42\"", "\"1337\""), edited.requestBodyText());
        assertTrue(decodedTree(edited).contains("1337"));

        // query edit with quotes and a newline is JSON-escaped; operationName/extensions untouched
        String newQ = "query GetUser($id: ID!) {\n  user(id: $id, note: \"a\\\"b\") { name } }";
        MessageContext eq = apply(q, m, newQ);
        assertEquals(body.replace(quote(Q), quote(newQ)), eq.requestBodyText());
        assertTrue(eq.requestBodyText().contains("\\n  user(id: $id, note: \\\"a\\\\\\\"b\\\")"));
        assertTrue(decodedTree(eq).contains("note"));

        // formatted document sends the formatted text
        EditEngine.Document f = doc(m, "GraphQL query (formatted)");
        MessageContext ef = apply(f, m, f.document().text());
        assertEquals(f.document().text(), JsonDocuments.parse(ef.requestBodyText()).get("query").string());

        assertThrows(EncodeException.class, () -> apply(vars, m, "{\"id\": }"));
    }

    @Test
    void batchAndStringVariables() throws Exception {
        String body = "[{\"query\":\"query A { a }\",\"variables\":\"{\\\"x\\\":1}\"},{\"operationName\":\"B\",\"query\":\"query B { b }\",\"variables\":{\"y\":\"é\"}}]";
        MessageContext m = postJson(body);
        assertEquals(List.of("GraphQL query #1 (A)", "GraphQL query (formatted) #1 (A)", "GraphQL variables #1 (A)",
                "GraphQL query #2 (B)", "GraphQL query (formatted) #2 (B)", "GraphQL variables #2 (B)"), titles(m));
        assertAllRoundTrip(exact(m), m);
        EditEngine.Document v1 = doc(m, "GraphQL variables #1 (A)");
        assertEquals("{\n  \"x\": 1\n}", v1.document().text());
        MessageContext e = apply(v1, m, "{\"x\": 2, \"s\": \"q\\\"uote\"}");
        // still a JSON string
        assertEquals(body.replace("\"{\\\"x\\\":1}\"", "\"{\\\"x\\\":2,\\\"s\\\":\\\"q\\\\\\\"uote\\\"}\""), e.requestBodyText());
        assertTrue(decodedTree(e).contains("s: \"q\\\"uote\""), decodedTree(e));
        MessageContext e2 = apply(doc(m, "GraphQL variables #2 (B)"), m, "{\"y\": \"ü ✓\"}");
        assertTrue(e2.requestBodyText().endsWith("\"variables\":{\"y\":\"ü ✓\"}}]"));
    }

    @Test
    void getParametersAreReEncodedLikeTheClient() throws Exception {
        String raw = "query=" + JsonDocuments.encodeURIComponent(Q) + "&operationName=GetUser&variables="
                + JsonDocuments.encodeURIComponent("{\"id\":\"42\"}") + "&extensions=%7B%7D";
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://api.example.com/graphql?" + raw).build();
        assertEquals(List.of("GraphQL query", "GraphQL query (formatted)", "GraphQL variables"), titles(m));
        assertAllRoundTrip(exact(m), m);
        MessageContext e = apply(doc(m, "GraphQL variables"), m, "{\"id\": \"a b&c\"}");
        assertEquals(raw.replace("%7B%22id%22%3A%2242%22%7D", "%7B%22id%22%3A%22a%20b%26c%22%7D"), e.query());
        assertTrue(decodedTree(e).contains("a b&c"));
        MessageContext eq = apply(doc(m, "GraphQL query"), m, "{ me { id } }");
        assertTrue(eq.query().startsWith("query=%7B%20me%20%7B%20id%20%7D%20%7D&operationName=GetUser"), eq.query());
    }

    @Test
    void formBodyUsesFormEncoding() throws Exception {
        String body = "query=" + JsonDocuments.formEncode("{ me { id } }") + "&variables=" + JsonDocuments.formEncode("{\"a\":\"x y\"}");
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://api.example.com/graphql")
                .requestHeader("Content-Type", "application/x-www-form-urlencoded").requestBody(body).build();
        assertAllRoundTrip(exact(m), m);
        MessageContext e = apply(doc(m, "GraphQL variables"), m, "{\"a\": \"p q\"}");
        assertEquals(body.replace("x+y", "p+q"), e.requestBodyText());
        assertTrue(decodedTree(e).contains("p q"));
    }

    @Test
    void multipartOperationsAndRawGraphQlBody() throws Exception {
        String ops = "{\"query\":\"mutation($f: Upload!) { upload(file: $f) }\",\"variables\":{\"f\":null,\"tag\":\"t1\"}}";
        String body = "------B7\r\nContent-Disposition: form-data; name=\"operations\"\r\n\r\n" + ops + "\r\n"
                + "------B7\r\nContent-Disposition: form-data; name=\"map\"\r\n\r\n{\"0\":[\"variables.f\"]}\r\n"
                + "------B7\r\nContent-Disposition: form-data; name=\"0\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nhi\r\n------B7--\r\n";
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://api.example.com/graphql")
                .requestHeader("Content-Type", "multipart/form-data; boundary=----B7").requestBody(body).build();
        assertTrue(titles(m).contains("GraphQL variables"), titles(m).toString());
        assertAllRoundTrip(exact(m), m);
        MessageContext e = apply(doc(m, "GraphQL variables"), m, "{\"f\": null, \"tag\": \"t2\"}");
        assertEquals(body.replace("\"tag\":\"t1\"", "\"tag\":\"t2\""), e.requestBodyText());
        assertTrue(decodedTree(e).contains("t2"));
        assertThrows(EncodeException.class, () -> apply(doc(m, "GraphQL variables"), m, "{\"tag\": \"------B7\"}"));

        MessageContext g = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://api.example.com/graphql")
                .requestHeader("Content-Type", "application/graphql").requestBody(Q).build();
        assertEquals(List.of("GraphQL query", "GraphQL query (formatted)"), titles(g));
        assertAllRoundTrip(exact(g), g);
        assertEquals("{ me }", apply(doc(g, "GraphQL query"), g, "{ me }").requestBodyText());
    }

    @Test
    void webSocketSubscribeAndResponses() throws Exception {
        String payload = "{\"id\":\"1\",\"type\":\"subscribe\",\"payload\":{\"query\":\"subscription { onMsg(room: \\\"r1\\\") { text } }\",\"variables\":{\"r\":1}}}";
        MessageContext ws = MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("wss://api.example.com/graphql")
                .requestHeader("Sec-WebSocket-Protocol", "graphql-transport-ws")
                .webSocket("CLIENT_TO_SERVER", payload.getBytes(StandardCharsets.UTF_8)).build();
        assertTrue(titles(ws).containsAll(List.of("GraphQL query", "GraphQL variables")), titles(ws).toString());
        assertAllRoundTrip(exact(ws), ws);
        MessageContext e = apply(doc(ws, "GraphQL query"), ws, "subscription { onMsg(room: \"r2\") { text } }");
        assertEquals(payload.replace("r1", "r2"), e.bodyText());
        assertTrue(decodedTree(e).contains("r2"));

        // gzip response
        String json = "{\"data\":{\"user\":{\"name\":\"Ann\",\"age\":30}}}";
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
            gz.write(json.getBytes(StandardCharsets.UTF_8));
        }
        MessageContext resp = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://api.example.com/graphql")
                .requestHeader("Content-Type", "application/json").requestBody("{\"query\":\"{ user { name age } }\"}")
                .statusCode(200).responseHeader("Content-Type", "application/json").responseHeader("Content-Encoding", "gzip")
                .responseBody(bos.toByteArray()).build().withKind(MessageKind.RESPONSE);
        assertEquals(List.of("GraphQL response"), titles(resp));
        assertAllRoundTrip(exact(resp), resp);
        EditEngine.Document r = doc(resp, "GraphQL response");
        MessageContext er = apply(r, resp, r.document().text().replace("\"Ann\"", "\"Bob\""));
        assertEquals(json.replace("Ann", "Bob"), Codecs.utf8(Codecs.gunzip(er.responseBody())));
        assertTrue(decodedTree(er).contains("Bob"));
        assertThrows(EncodeException.class, () -> apply(r, resp, "{\"data\": [}"));
    }
}
