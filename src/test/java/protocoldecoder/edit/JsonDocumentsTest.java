package protocoldecoder.edit;

import org.junit.jupiter.api.Test;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.edit.JsonDocuments.JsonView;
import protocoldecoder.util.Codecs;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class JsonDocumentsTest {

    @Test
    void prettyKeepsTokensAndRoundTripsCompact() throws Exception {
        String json = "{\"b\":1.50,\"a\":[1e5,-0,12345678901234567890123],\"s\":\"\\u00e9\\/x\\n\",\"b\":null,\"e\":{},\"f\":[]}";
        JsonView v = JsonView.of(json);
        assertTrue(v.compact());
        assertEquals("""
                {
                  "b": 1.50,
                  "a": [
                    1e5,
                    -0,
                    12345678901234567890123
                  ],
                  "s": "\\u00e9\\/x\\n",
                  "b": null,
                  "e": {},
                  "f": []
                }""", v.text());
        assertEquals(json, v.encode(v.text()));
        // same content, different whitespace: minified back to the original bytes
        assertEquals(json, v.encode(v.text().replace("\n", "\r\n") + "\n"));
        assertEquals(json.replace("1.50", "2"), v.encode(v.text().replace("1.50", "2")));
    }

    @Test
    void formattedOriginalKeepsUserFormattingAndSurroundingWhitespace() throws Exception {
        String json = "\n{ \"a\" : 1 }\n";
        JsonView v = JsonView.of(json);
        assertFalse(v.compact());
        assertEquals(json, v.encode(v.text()));
        assertEquals("\n{\n  \"a\": 2\n}\n", v.encode("{\n  \"a\": 2\n}"));
    }

    @Test
    void escapingStyleOfTheOriginalIsReapplied() throws Exception {
        JsonView ascii = JsonView.of("{\"n\":\"Ren\\u00e9\"}");
        assertEquals("{\"n\":\"J\\u00fcrgen \\u2713\"}", ascii.encode("{\"n\": \"Jürgen ✓\"}"));
        JsonView raw = JsonView.of("{\"n\":\"René\"}");
        assertEquals("{\"n\":\"Jürgen\"}", raw.encode("{\"n\": \"Jürgen\"}"));
        JsonView slash = JsonView.of("{\"u\":\"a\\/b\"}");
        assertEquals("{\"u\":\"c\\/d\"}", slash.encode("{\"u\": \"c/d\"}"));
        JsonView html = JsonView.of("{\"h\":\"\\u003cb\\u003e\"}");
        assertEquals("{\"h\":\"\\u003ci\\u003e \\u0026\"}", html.encode("{\"h\": \"<i> &\"}"));
        JsonView upper = JsonView.of("{\"n\":\"\\u00E9\"}");
        assertEquals("{\"n\":\"\\u00FC\"}", upper.encode("{\"n\": \"ü\"}"));
    }

    @Test
    void errorsHaveLineAndColumn() {
        JsonView v = JsonView.of("{\"a\":1}");
        EncodeException e = assertThrows(EncodeException.class, () -> v.encode("{\n  \"a\": 1,\n  \"b\" 2\n}"));
        assertEquals("JSON error at line 3, column 7: expected ':' after key", e.getMessage());
        assertThrows(EncodeException.class, () -> v.encode("{\"a\": 01}"));
        assertThrows(EncodeException.class, () -> v.encode("{\"a\": [1,]}"));
        assertThrows(EncodeException.class, () -> v.encode("{\"a\": \"x\ny\"}"));
        assertThrows(EncodeException.class, () -> v.encode("{\"a\": 1} x"));
        assertThrows(EncodeException.class, () -> v.encode("{'a': 1}"));
        assertNull(JsonView.of("{nope"));
    }

    @Test
    void nestedJsonStringsAreUnwrappedAndRestringified() throws Exception {
        // root string → array with a JSON string inside → object
        String inner2 = "{\"q\":\"x\\\"y\",\"n\":1}";
        String inner1 = "[\"a\"," + JsonDocuments.quote(inner2, JsonDocuments.Style.PLAIN) + ",null]";
        String token = JsonDocuments.quote(inner1, JsonDocuments.Style.PLAIN);
        JsonView v = JsonView.ofStringToken(token, 3);
        assertNotNull(v);
        assertEquals("""
                [
                  "a",
                  {
                    "q": "x\\"y",
                    "n": 1
                  },
                  null
                ]""", v.text());
        assertEquals(token, v.encode(v.text()));
        String edited = v.encode(v.text().replace("\"n\": 1", "\"n\": 2"));
        String l1 = JsonDocuments.unquote(edited);
        assertEquals("[\"a\",\"{\\\"q\\\":\\\"x\\\\\\\"y\\\",\\\"n\\\":2}\",null]", l1);
        assertEquals("{\"q\":\"x\\\"y\",\"n\":2}", JsonDocuments.unquote(JsonDocuments.parse(l1).get(1).raw()));
        // depth 1: nested string stays a string
        JsonView shallow = JsonView.ofStringToken(token, 1);
        assertTrue(shallow.text().contains("\"{\\\"q\\\""), shallow.text());
        assertNull(JsonView.ofStringToken("\"plain text\"", 1));
    }

    @Test
    void urlEncodersAndParams() {
        assertEquals("%7B%22a%22%3A%22b%20c!'()*~%22%7D", JsonDocuments.encodeURIComponent("{\"a\":\"b c!'()*~\"}"));
        assertEquals("%7B%22a%22%3A%22b+c%21%27%28%29*%7E%22%7D", JsonDocuments.formEncode("{\"a\":\"b c!'()*~\"}"));
        String raw = "a=1&input=%7B%22x%22%3A%22a+b%22%7D&z";
        JsonDocuments.Param p = JsonDocuments.param(raw, "input");
        assertEquals("{\"x\":\"a b\"}", p.value());
        assertEquals(raw, JsonDocuments.replaceParam(raw, p, p.value(), JsonDocuments::encodeURIComponent));
        // original used + for spaces → the form encoder is reused
        assertEquals("a=1&input=%7B%22x%22%3A%22c+d%22%7D&z", JsonDocuments.replaceParam(raw, p, "{\"x\":\"c d\"}", JsonDocuments::encodeURIComponent));
    }

    @Test
    void gzipBodiesAreRecompressed() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
            gz.write("{\"a\":1}".getBytes(StandardCharsets.UTF_8));
        }
        byte[] gz = bos.toByteArray();
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).url("https://x.example/").statusCode(200)
                .responseHeader("Content-Encoding", "gzip").responseBody(gz).build();
        JsonDocuments.Body b = JsonDocuments.Body.of(m);
        assertEquals("{\"a\":1}", b.text());
        assertArrayEquals(gz, b.encode("{\"a\":1}"));
        assertEquals("{\"a\":2}", Codecs.utf8(Codecs.gunzip(b.encode("{\"a\":2}"))));
        MessageContext br = MessageContext.builder(MessageKind.RESPONSE).url("https://x.example/").statusCode(200)
                .responseHeader("Content-Encoding", "br").responseBody("x").build();
        assertNull(JsonDocuments.Body.of(br));
    }

    @Test
    void multipartPartsAreReplacedInPlace() throws Exception {
        String body = "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nhello\r\n"
                + "--XyZ\r\nContent-Disposition: form-data; name=\"f\"; filename=\"x.txt\"\r\nContent-Type: text/plain\r\n\r\nfile\r\n--XyZ--\r\n";
        byte[] raw = body.getBytes(StandardCharsets.UTF_8);
        List<JsonDocuments.Part> parts = JsonDocuments.multipart(raw, JsonDocuments.boundary("multipart/form-data; boundary=XyZ"));
        assertEquals(2, parts.size());
        assertEquals("hello", JsonDocuments.partText(raw, parts.get(0)));
        assertEquals("x.txt", parts.get(1).filename());
        assertEquals(body.replace("hello", "wörld"), Codecs.utf8(JsonDocuments.replacePart(raw, parts.get(0), "XyZ", "wörld")));
        EncodeException e = assertThrows(EncodeException.class, () -> JsonDocuments.replacePart(raw, parts.get(0), "XyZ", "a\r\n--XyZ\r\n"));
        assertTrue(e.getMessage().contains("boundary"));
    }
}
