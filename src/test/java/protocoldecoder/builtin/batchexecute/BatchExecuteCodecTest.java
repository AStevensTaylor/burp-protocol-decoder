package protocoldecoder.builtin.batchexecute;

import org.junit.jupiter.api.Test;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.edit.CodecTestSupport;
import protocoldecoder.edit.EditEngine;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.edit.JsonDocuments;
import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BatchExecuteCodecTest extends CodecTestSupport {

    static final String URL = "https://docs.google.com/_/DocsApp/data/batchexecute?rpcids=AbC12%2CXyZ34&bl=boq_x&_reqid=1&rt=c";

    static String q(String s) {
        return JsonDocuments.quote(s, JsonDocuments.Style.PLAIN);
    }

    static MessageContext request(String body) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url(URL)
                .requestHeader("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8").requestBody(body).build();
    }

    static MessageContext response(String body) {
        return MessageContext.builder(MessageKind.RESPONSE).method("POST").url(URL).statusCode(200)
                .responseHeader("Content-Type", "application/json; charset=utf-8").responseBody(body.getBytes(StandardCharsets.UTF_8)).build();
    }

    @Test
    void requestArgumentsAreFullyUnwrappedAndRestringified() throws Exception {
        String nested = "{\"mode\":\"edit\",\"rev\":42}";
        String args2 = "[\"1x\"," + q(nested) + "]";
        String freq = "[[[\"AbC12\"," + q("[null,\"doc-1x\",[1,2,3],true]") + ",null,\"generic\"],[\"XyZ34\"," + q(args2) + ",null,\"generic\"]]]";
        String body = "f.req=" + JsonDocuments.formEncode(freq) + "&at=AJpMio2mLx%3A1714560000000&";
        MessageContext m = request(body);
        assertEquals(List.of("RPC AbC12 arguments", "RPC XyZ34 arguments"), titles(m));
        assertAllRoundTrip(docs(m), m);

        EditEngine.Document d = doc(m, "RPC XyZ34 arguments");
        assertEquals("""
                [
                  "1x",
                  {
                    "mode": "edit",
                    "rev": 42
                  }
                ]""", d.document().text());
        MessageContext e = apply(d, m, d.document().text().replace("\"edit\"", "\"admin \\\"x\\\" ✓\""));
        String newFreq = Codecs.first(Codecs.parseQuery(e.requestBodyText()), "f.req");
        String expected = freq.replace(q(args2), q("[\"1x\"," + q("{\"mode\":\"admin \\\"x\\\" ✓\",\"rev\":42}") + "]"));
        assertEquals(expected, newFreq);
        assertTrue(e.requestBodyText().startsWith("f.req=" + JsonDocuments.formEncode(expected) + "&at=AJpMio2mLx%3A1714560000000&"));
        assertTrue(decodedTree(e).contains("admin"), decodedTree(e));
        // the untouched first envelope is byte-identical
        assertTrue(newFreq.startsWith("[[[\"AbC12\"," + q("[null,\"doc-1x\",[1,2,3],true]")));
        assertThrows(EncodeException.class, () -> apply(d, m, "[\"1x\", {\"mode\": }]"));
    }

    @Test
    void chunkedResponseLengthsAreRecomputedInTheOriginalUnit() throws Exception {
        String a = "[[\"wrb.fr\",\"AbC12\"," + q("[\"héllo ✓\",[1,2]]") + ",null,null,null,\"generic\"]]";
        String b = "[[\"di\",42],[\"af.httprm\",41,\"-123\",7]]";
        int bytes = a.getBytes(StandardCharsets.UTF_8).length;
        // first chunk declared in bytes (excluding the newline), second in chars including the newline
        String body = ")]}'\n\n" + bytes + "\n" + a + "\n" + (b.length() + 1) + "\n" + b + "\n";
        MessageContext m = response(body);
        assertEquals(List.of("RPC AbC12 response"), titles(m));
        assertAllRoundTrip(docs(m), m);
        EditEngine.Document d = doc(m, "RPC AbC12 response");
        assertEquals("[\n  \"héllo ✓\",\n  [\n    1,\n    2\n  ]\n]", d.document().text());
        MessageContext e = apply(d, m, "[\"héllo wörld ✓\", [1, 2, 3]]");
        String a2 = "[[\"wrb.fr\",\"AbC12\"," + q("[\"héllo wörld ✓\",[1,2,3]]") + ",null,null,null,\"generic\"]]";
        assertEquals(")]}'\n\n" + a2.getBytes(StandardCharsets.UTF_8).length + "\n" + a2 + "\n" + (b.length() + 1) + "\n" + b + "\n", e.responseBodyText());
        String tree = decodedTree(e);
        assertTrue(tree.contains("wörld"), tree);
        assertThrows(EncodeException.class, () -> apply(d, m, "[\"x\""));
    }

    @Test
    void singleJsonResponse() throws Exception {
        String body = ")]}'\n\n[[\"wrb.fr\",\"XyZ34\"," + q("{\"ok\":true}") + ",null,null,null,\"generic\"],[\"di\",9]]";
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("POST")
                .url("https://docs.google.com/_/DocsApp/data/batchexecute?rpcids=XyZ34").statusCode(200)
                .responseBody(body).build();
        assertEquals(List.of("RPC XyZ34 response"), titles(m));
        assertAllRoundTrip(docs(m), m);
        MessageContext e = apply(doc(m, "RPC XyZ34 response"), m, "{\"ok\": false}");
        assertEquals(body.replace("{\\\"ok\\\":true}", "{\\\"ok\\\":false}"), e.responseBodyText());
        assertTrue(decodedTree(e).contains("false"));
    }
}
