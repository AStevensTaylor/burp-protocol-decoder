package protocoldecoder.builtin.graphql;

import org.junit.jupiter.api.Test;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.edit.CodecTestSupport;
import protocoldecoder.edit.EditEngine;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.edit.JsonDocuments;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TrpcCodecTest extends CodecTestSupport {

    static final String INPUT = "{\"0\":{\"json\":{\"id\":7,\"at\":\"2024-01-01T00:00:00.000Z\"},\"meta\":{\"values\":{\"at\":[\"Date\"]}}},\"1\":{\"json\":null}}";

    static MessageContext get(String input) {
        return MessageContext.builder(MessageKind.REQUEST).method("GET")
                .url("https://app.example.com/api/trpc/user.byId,post.list?batch=1&input=" + JsonDocuments.encodeURIComponent(input)).build();
    }

    @Test
    void getInputIsWholeBatchObjectReEncodedWithEncodeUriComponent() throws Exception {
        MessageContext m = get(INPUT);
        assertEquals(List.of("tRPC input (user.byId, post.list)"), titles(m));
        assertAllRoundTrip(docs(m), m);
        EditEngine.Document d = doc(m, "tRPC input (user.byId, post.list)");
        assertTrue(d.document().text().contains("\"meta\": {"), d.document().text());
        MessageContext e = apply(d, m, d.document().text().replace("\"id\": 7", "\"id\": \"7' OR 1=1 -- (x)\""));
        String expected = INPUT.replace("\"id\":7", "\"id\":\"7' OR 1=1 -- (x)\"");
        assertEquals("batch=1&input=" + JsonDocuments.encodeURIComponent(expected), e.query());
        assertTrue(e.query().contains("'%20OR%201%3D1%20--%20(x)"), e.query());
        assertTrue(decodedTree(e).contains("7' OR 1=1"));
        assertThrows(EncodeException.class, () -> apply(d, m, "{\"0\": {\"json\": }}"));
    }

    @Test
    void postBodyAndResponse() throws Exception {
        String body = "{\"0\":{\"json\":{\"title\":\"Hi ✓\"}}}";
        MessageContext.Builder b = MessageContext.builder(MessageKind.REQUEST).method("POST")
                .url("https://app.example.com/api/trpc/post.create?batch=1").requestHeader("Content-Type", "application/json").requestBody(body);
        MessageContext m = b.build();
        assertEquals(List.of("tRPC input body (post.create)"), titles(m));
        assertAllRoundTrip(docs(m), m);
        MessageContext e = apply(doc(m, "tRPC input body (post.create)"), m, "{\"0\": {\"json\": {\"title\": \"Bye\"}}}");
        assertEquals("{\"0\":{\"json\":{\"title\":\"Bye\"}}}", e.requestBodyText());
        assertTrue(decodedTree(e).contains("Bye"));

        MessageContext r = b.statusCode(200).responseHeader("Content-Type", "application/json")
                .responseBody("[{\"result\":{\"data\":{\"json\":{\"id\":1,\"ok\":true}}}}]").build().withKind(MessageKind.RESPONSE);
        assertEquals(List.of("tRPC response (post.create)"), titles(r));
        assertAllRoundTrip(docs(r), r);
        MessageContext er = apply(doc(r, "tRPC response (post.create)"), r, "[{\"result\": {\"data\": {\"json\": {\"id\": 2, \"ok\": false}}}}]");
        assertEquals("[{\"result\":{\"data\":{\"json\":{\"id\":2,\"ok\":false}}}}]", er.responseBodyText());
        assertTrue(decodedTree(er).contains("false"));
    }
}
