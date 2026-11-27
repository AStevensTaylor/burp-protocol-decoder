package protocoldecoder.builtin.serialized;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.edit.EditEngine;
import protocoldecoder.edit.EditableDocument;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.edit.MessagePatch;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.util.Codecs;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static protocoldecoder.builtin.serialized.Fixtures.*;

class SerializedObjectCodecTest {

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });

    @AfterEach
    void close() {
        app.close();
    }

    static final String PHP = "a:2:{s:4:\"user\";O:4:\"User\":2:{s:4:\"name\";s:5:\"alice\";s:4:\"role\";s:4:\"user\";}s:2:\"id\";i:7;}";

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    List<EditEngine.Document> docs(MessageContext m) {
        return app.editEngine().documents(m).stream().filter(d -> d.decoderId().equals(SerializedObjectDecoder.ID)).toList();
    }

    String decodedText(MessageContext m) {
        DecodeResult r = app.engine().decode(m).result();
        assertNotNull(r);
        return text(r.root());
    }

    @Test
    void cookieEndToEnd() throws Exception {
        String header = "theme=dark; session=" + enc(PHP) + "; x=1";
        MessageContext m = request("https://app.example.test/", null, "Cookie", header);
        List<EditEngine.Document> docs = docs(m);
        assertEquals(1, docs.size());
        EditEngine.Document d = docs.get(0);
        assertEquals("PHP serialized: cookie session (lengths auto-fixed)", d.document().title());
        assertEquals(PHP, d.document().text());
        assertEquals(header, EditEngine.encode(d, d.document().text()).applyTo(m).requestHeader("Cookie"));

        // correct lengths: used as written
        String edited = PHP.replace("s:4:\"user\";}", "s:5:\"admin\";}");
        MessageContext out = EditEngine.encode(d, edited).applyTo(m);
        String cookie = out.requestHeader("Cookie");
        assertTrue(cookie.startsWith("theme=dark; session=") && cookie.endsWith("; x=1"), cookie);
        assertEquals(edited, Sniffer.percentDecodeKeepPlus(cookie.substring(20, cookie.length() - 5)));
        assertTrue(decodedText(out).contains("admin"));
    }

    @Test
    void lengthsAreAutoFixed() throws Exception {
        MessageContext m = request("https://app.example.test/", null, "Cookie", "session=" + enc(PHP));
        EditableDocument d = docs(m).get(0).document();
        // change content without fixing s:N:, and add an array member without fixing a:N:
        String edited = PHP.replace("\"alice\"", "\"administrator é\";\"x\"").replace("i:7;}", "i:7;s:3:\"new\";b:1;}");
        MessageContext out = d.encode(edited).applyTo(m);
        String php = Sniffer.percentDecodeKeepPlus(out.requestHeader("Cookie").substring("session=".length()));
        assertEquals("a:3:{s:4:\"user\";O:4:\"User\":2:{s:4:\"name\";s:20:\"administrator é\";\"x\";s:4:\"role\";s:4:\"user\";}s:2:\"id\";i:7;s:3:\"new\";b:1;}", php);
        assertTrue(PhpParser.parse(php, new ParseOutput.Budget(1000)).complete);
        assertTrue(decodedText(out).contains("administrator é\\\";\\\"x"), decodedText(out));
        // shortened string and class name
        String shorter = PHP.replace("\"alice\"", "\"al\"").replace("O:4:\"User\"", "O:4:\"Admin\"");
        String fixed = new String(SerializedObjectCodec.toPayload(shorter), StandardCharsets.UTF_8);
        assertEquals(PHP.replace("s:5:\"alice\"", "s:2:\"al\"").replace("O:4:\"User\"", "O:5:\"Admin\""), fixed);
    }

    @Test
    void invalidEditsAreRejected() throws Exception {
        MessageContext m = request("https://app.example.test/", null, "Cookie", "session=" + enc(PHP));
        EditableDocument d = docs(m).get(0).document();
        EncodeException e = assertThrows(EncodeException.class, () -> d.encode("a:1:{s:1:\"a\";X:1;}"));
        assertTrue(e.getMessage().startsWith("PHP serialized data is invalid: "), e.getMessage());
        assertThrows(EncodeException.class, () -> d.encode("a:1:{s:1:\"a\";s:1:\"b\";"));
        assertThrows(EncodeException.class, () -> d.encode(PHP + "garbage"));
        assertThrows(EncodeException.class, () -> d.encode(""));
    }

    @Test
    void base64QueryParameterAndDelimiters() throws Exception {
        String b64 = Base64.getEncoder().encodeToString(PHP.getBytes(StandardCharsets.UTF_8));
        MessageContext m = request("https://app.example.test/x?a=1&data=" + enc(b64) + "&z=2", null);
        EditableDocument d = docs(m).get(0).document();
        assertEquals("PHP serialized: param data (lengths auto-fixed)", d.title());
        assertEquals(m.query(), d.encode(d.text()).query());
        MessagePatch p = d.encode(PHP.replace("\"alice\"", "\"a&b=c;d|\\\"e\""));
        MessageContext out = p.applyTo(m);
        assertTrue(out.query().startsWith("a=1&data=") && out.query().endsWith("&z=2"), out.query());
        String php = new String(Codecs.base64Decode(Codecs.first(out.queryParameters(), "data")), StandardCharsets.UTF_8);
        assertTrue(php.contains("s:11:\"a&b=c;d|\\\"e\""), php);
        assertTrue(decodedText(out).contains("a&b=c;d|\\\\\\\"e"), decodedText(out));
    }

    @Test
    void gzipBase64BodyAndRawBody() throws Exception {
        byte[] gz = gzip(PHP.getBytes(StandardCharsets.UTF_8));
        MessageContext m = request("https://app.example.test/x", b64(gz), "Content-Type", "text/plain");
        EditableDocument d = docs(m).get(0).document();
        assertArrayEquals(m.requestBody(), d.encode(d.text()).body());
        MessageContext out = d.encode(PHP.replace("alice", "bob")).applyTo(m);
        byte[] inner = Codecs.gunzip(Codecs.base64Decode(out.requestBodyText()));
        assertEquals(PHP.replace("s:5:\"alice\"", "s:3:\"bob\""), new String(inner, StandardCharsets.UTF_8));

        MessageContext raw = request("https://app.example.test/x", PHP, "Content-Type", "application/octet-stream");
        EditableDocument rd = docs(raw).get(0).document();
        assertEquals("PHP serialized: body (lengths auto-fixed)", rd.title());
        assertEquals(PHP.replace("i:7", "i:8"), rd.encode(PHP.replace("i:7", "i:8")).applyTo(raw).requestBodyText());
    }

    @Test
    void responseBodyWithUnicode() throws Exception {
        String php = "a:1:{s:4:\"name\";s:5:\"Jörg\";}";
        MessageContext m = response(php.getBytes(StandardCharsets.UTF_8), "Content-Type", "text/plain");
        EditableDocument d = docs(m).get(0).document();
        assertEquals(php, d.text());
        MessageContext out = d.encode(php.replace("Jörg", "☃☃")).applyTo(m);
        assertEquals("a:1:{s:4:\"name\";s:6:\"☃☃\";}", out.responseBodyText());
    }

    @Test
    void noDocumentsForBinaryOrSignedFormats() {
        MessageContext java = request("https://app.example.test/x", null, "Cookie", "s=" + b64(javaSerialize("hello")));
        assertTrue(docs(java).isEmpty());
        MessageContext signed = request("https://app.example.test/x", null, "Cookie",
                "_session=" + b64(PHP.getBytes(StandardCharsets.UTF_8)) + "--0123456789abcdef0123456789abcdef01234567");
        assertTrue(docs(signed).isEmpty());
        MessageContext broken = request("https://app.example.test/x", "a:2:{s:1:\"a\";i:1;", "Content-Type", "text/plain");
        assertTrue(docs(broken).isEmpty());
    }
}
