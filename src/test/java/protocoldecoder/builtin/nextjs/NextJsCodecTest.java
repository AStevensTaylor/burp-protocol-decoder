package protocoldecoder.builtin.nextjs;

import org.junit.jupiter.api.Test;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.edit.CodecTestSupport;
import protocoldecoder.edit.EditEngine;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.edit.JsonDocuments;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class NextJsCodecTest extends CodecTestSupport {

    static final String ACTION_ID = "7f3a9c0e5b1d2f4a6c8e0b2d4f6a8c0e2b4d6f8a";
    static final String TREE = "[\"\",{\"children\":[\"cart\",{\"children\":[\"__PAGE__\",{}]}]},null,null,true]";

    @Test
    void serverActionJsonArgumentsAndRouterStateTree() throws Exception {
        String args = "[{\"id\":42,\"qty\":1.0},\"$undefined\"]";
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://shop.example.com/cart")
                .requestHeader("Next-Action", ACTION_ID).requestHeader("Content-Type", "text/plain;charset=UTF-8")
                .requestHeader("Next-Router-State-Tree", JsonDocuments.encodeURIComponent(TREE)).requestBody(args).build();
        assertEquals(List.of("Server Action arguments", "Next-Router-State-Tree"), titles(m));
        assertAllRoundTrip(docs(m), m);

        EditEngine.Document a = doc(m, "Server Action arguments");
        MessageContext e = apply(a, m, a.document().text().replace("\"id\": 42", "\"id\": 43"));
        assertEquals("[{\"id\":43,\"qty\":1.0},\"$undefined\"]", e.requestBodyText());
        assertTrue(decodedTree(e).contains("43"));
        assertThrows(EncodeException.class, () -> apply(a, m, "[1,"));

        EditEngine.Document t = doc(m, "Next-Router-State-Tree");
        String newTree = TREE.replace("\"cart\"", "\"admin panel\"");
        MessageContext et = apply(t, m, newTree);
        assertEquals(JsonDocuments.encodeURIComponent(newTree), et.requestHeader("Next-Router-State-Tree"));
        assertTrue(et.requestHeader("Next-Router-State-Tree").contains("admin%20panel"));
        assertTrue(decodedTree(et).contains("/admin panel"), decodedTree(et));
    }

    @Test
    void multipartActionFieldsKeepBoundaryAndFiles() throws Exception {
        String b = "----WebKitFormBoundaryX1";
        String body = "--" + b + "\r\nContent-Disposition: form-data; name=\"1_email\"\r\n\r\nbob@example.com\r\n"
                + "--" + b + "\r\nContent-Disposition: form-data; name=\"1_avatar\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nhi\r\n"
                + "--" + b + "\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n[\"$K1\"]\r\n"
                + "--" + b + "--\r\n";
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/signup")
                .requestHeader("Next-Action", ACTION_ID).requestHeader("Content-Type", "multipart/form-data; boundary=" + b)
                .requestBody(body).build();
        assertEquals(List.of("Server Action field \"1_email\"", "Server Action field \"0\""), titles(m));
        assertAllRoundTrip(docs(m), m);
        EditEngine.Document email = doc(m, "Server Action field \"1_email\"");
        assertEquals("text", email.document().syntax());
        MessageContext e = apply(email, m, "eve@example.com\" ünï");
        assertEquals(body.replace("bob@example.com", "eve@example.com\" ünï"), e.requestBodyText());
        assertTrue(decodedTree(e).contains("eve@example.com"));
        assertThrows(EncodeException.class, () -> apply(email, m, "x\r\n--" + b + "\r\n"));

        EditEngine.Document zero = doc(m, "Server Action field \"0\"");
        assertEquals("json", zero.document().syntax());
        MessageContext ez = apply(zero, m, "[\"$K1\", 5]");
        assertTrue(ez.requestBodyText().contains("\r\n\r\n[\"$K1\",5]\r\n--"));
        assertTrue(decodedTree(ez).contains("(2 args)"), decodedTree(ez));
    }

    @Test
    void nextDataIsReEmbeddedHtmlEscaped() throws Exception {
        String data = "{\"props\":{\"pageProps\":{\"bio\":\"\\u003cb\\u003ehi\\u003c/b\\u003e\",\"n\":7}},\"page\":\"/u/[id]\",\"buildId\":\"Zk3\"}";
        String html = "<!DOCTYPE html><html><body><div id=\"__next\"></div><script id=\"__NEXT_DATA__\" type=\"application/json\">"
                + data + "</script></body></html>";
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://www.example.com/u/1")
                .statusCode(200).responseHeader("Content-Type", "text/html; charset=utf-8").responseBody(html).build();
        assertEquals(List.of("__NEXT_DATA__"), titles(m));
        assertAllRoundTrip(docs(m), m);
        EditEngine.Document d = doc(m, "__NEXT_DATA__");
        String edited = d.document().text().replace("\"n\": 7", "\"n\": 8, \"x\": \"</script><img src=x> & \u2028\"");
        MessageContext e = apply(d, m, edited);
        String out = e.responseBodyText();
        assertTrue(out.contains("\"n\":8,\"x\":\"\\u003c/script\\u003e\\u003cimg src=x\\u003e \\u0026 \\u2028\"}"), out);
        assertEquals(1, out.split("</script>", -1).length - 1, "no early script end");
        assertTrue(decodedTree(e).contains("</script><img src=x>"), decodedTree(e));

        // /_next/data JSON
        MessageContext dj = MessageContext.builder(MessageKind.RESPONSE).method("GET")
                .url("https://shop.example.com/_next/data/abc123/blog/hello.json").statusCode(200)
                .responseHeader("Content-Type", "application/json")
                .responseBody("{\"pageProps\":{\"post\":{\"title\":\"Hello\"}},\"__N_SSP\":true}").build();
        assertEquals(List.of("Page data (/_next/data)"), titles(dj));
        assertAllRoundTrip(docs(dj), dj);
        MessageContext ed = apply(doc(dj, "Page data (/_next/data)"), dj, "{\"pageProps\": {\"post\": {\"title\": \"Bye\"}}, \"__N_SSP\": true}");
        assertEquals("{\"pageProps\":{\"post\":{\"title\":\"Bye\"}},\"__N_SSP\":true}", ed.responseBodyText());
        assertTrue(decodedTree(ed).contains("Bye"));
    }
}
