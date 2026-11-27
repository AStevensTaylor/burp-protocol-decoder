package protocoldecoder.builtin.batchexecute;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
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

class BatchExecuteDecoderTest {

    final BatchExecuteDecoder be = new BatchExecuteDecoder();

    static final String URL = "https://docs.google.com/_/DocsApp/data/batchexecute?rpcids=AbC12%2CXyZ34&source-path=%2Fdocument%2Fd%2F1x"
            + "&f.sid=-123456789&bl=boq_docs_20240501.01_p0&hl=en&_reqid=123456&rt=c";

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    /** Builds an envelope the way the Closure client does: the inner arguments are a JSON-encoded string. */
    static JsonArray envelope(String rpc, String innerJson, String tag) {
        JsonArray a = new JsonArray();
        a.add(rpc);
        a.add(innerJson);
        a.add(JsonNull.INSTANCE);
        a.add(tag);
        return a;
    }

    static String freq(JsonArray... envs) {
        JsonArray list = new JsonArray();
        for (JsonArray e : envs) list.add(e);
        JsonArray outer = new JsonArray();
        outer.add(list);
        return outer.toString();
    }

    static JsonArray wrb(String rpc, String payloadJson) {
        JsonArray a = new JsonArray();
        a.add("wrb.fr");
        a.add(rpc);
        a.add(payloadJson);
        a.add(JsonNull.INSTANCE);
        a.add(JsonNull.INSTANCE);
        a.add(JsonNull.INSTANCE);
        a.add("generic");
        return a;
    }

    static String chunk(String json) {
        return json.length() + "\n" + json + "\n";
    }

    static String find(DecodedNode n, String nameContains) {
        if (n.name().contains(nameContains) && n.value() != null) return n.value();
        for (DecodedNode c : n.children()) {
            String v = find(c, nameContains);
            if (v != null) return v;
        }
        return null;
    }

    static MessageContext request(String url, String body) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url(url)
                .requestHeader("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8").requestBody(body).build();
    }

    static MessageContext response(String url, byte[] body, String... headers) {
        MessageContext.Builder b = MessageContext.builder(MessageKind.RESPONSE).method("POST").url(url).statusCode(200);
        for (int i = 0; i + 1 < headers.length; i += 2) b.responseHeader(headers[i], headers[i + 1]);
        return b.responseBody(body).build();
    }

    @Test
    void multiRpcRequest() throws Exception {
        // second envelope's arguments contain a further JSON-in-string level
        String inner2 = new JsonArray().toString();
        JsonArray args2 = new JsonArray();
        args2.add("1x");
        args2.add("{\"mode\":\"edit\",\"rev\":42}");
        inner2 = args2.toString();
        String f = freq(envelope("AbC12", "[null,\"doc-1x\",[1,2,3],true]", "generic"), envelope("XyZ34", inner2, "generic"));
        String body = "f.req=" + enc(f) + "&at=" + enc("AJpMio2mLx:1714560000000") + "&";
        MessageContext m = request(URL, body);
        assertEquals(95, be.match(m).confidence());
        DecodeResult r = be.decode(m);
        assertEquals("batchexecute → 2 RPCs: AbC12, XyZ34 [DocsApp]", r.summary());
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
        assertEquals("DocsApp", find(r.root(), "App"));
        assertEquals("/document/d/1x", find(r.root(), "source-path"));
        assertEquals("AJpMio2mLx:1714560000000", find(r.root(), "at (XSRF token)"));
        String text = TreeText.render(r.root());
        assertTrue(text.contains("doc-1x"), text);
        assertEquals("edit", find(r.root(), "mode"));   // nested JSON-in-string expanded
        assertEquals("42", find(r.root(), "rev"));
    }

    @Test
    void rpcidsMismatchWarnsAndNoXsrfToken() throws Exception {
        String f = freq(envelope("Qq9", "[]", "1"));
        DecodeResult r = be.decode(request("https://contacts.google.com/_/SocialPeopleHovercardUi/data/batchexecute?rpcids=Other", "f.req=" + enc(f)));
        assertEquals("batchexecute → 1 RPC: Qq9 [SocialPeopleHovercardUi]", r.summary());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("does not match")), r.warnings().toString());
        assertTrue(TreeText.render(r.root()).contains("No 'at' XSRF token"));
    }

    @Test
    void fReqOnOtherPathMatchesAt70() {
        String f = freq(envelope("AbC12", "[\"x\"]", "generic"));
        MessageContext m = request("https://www.google.com/some/other/rpc", "f.req=" + enc(f) + "&at=tok");
        assertEquals(70, be.match(m).confidence());
    }

    @Test
    void chunkedResponseWithAllEntryTypes() throws Exception {
        StringBuilder payload = new StringBuilder("[[\"doc-1x\",\"Quarterly report\",[\"alice@example.com\",\"bob@example.com\"]");
        for (int i = 0; i < 80; i++) payload.append(",[").append(i).append(",\"row ").append(i).append(" – détails\"]");
        payload.append("]]");
        JsonArray first = new JsonArray();
        first.add(wrb("AbC12", payload.toString()));
        JsonArray di = new JsonArray(); di.add("di"); di.add(123);
        JsonArray af = new JsonArray(); af.add("af.httprm"); af.add(122); af.add("-6087151398146938211"); af.add(31);
        JsonArray second = new JsonArray();
        second.add(di);
        second.add(af);
        JsonArray er = new JsonArray(); er.add("er"); er.add(JsonNull.INSTANCE); er.add(JsonNull.INSTANCE); er.add(JsonNull.INSTANCE);
        er.add(JsonNull.INSTANCE); er.add(400); er.add(JsonNull.INSTANCE); er.add(JsonNull.INSTANCE); er.add(JsonNull.INSTANCE); er.add(3);
        JsonArray third = new JsonArray(); third.add(er);
        JsonArray e = new JsonArray(); e.add("e"); e.add(4); e.add(JsonNull.INSTANCE); e.add(JsonNull.INSTANCE); e.add(1234);
        JsonArray fourth = new JsonArray(); fourth.add(e);
        String body = ")]}'\n\n" + chunk(first.toString()) + chunk(second.toString()) + chunk(third.toString()) + chunk(fourth.toString());
        MessageContext m = response(URL, body.getBytes(StandardCharsets.UTF_8), "Content-Type", "application/json; charset=utf-8");
        assertEquals(95, be.match(m).confidence());
        DecodeResult r = be.decode(m);
        String size = BatchExecuteDecoder.size(payload.length());
        assertEquals("batchexecute response: wrb.fr AbC12 (" + size + " payload), er (error 400)", r.summary());
        assertTrue(size.endsWith("KB"), size);
        assertFalse(r.warnings().stream().anyMatch(w -> w.contains("length")), r.warnings().toString());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("error entry")), r.warnings().toString());
        assertEquals("Quarterly report", find(r.root(), "[1]"));
        assertEquals("123", find(r.root(), "Value"));
        assertEquals("-6087151398146938211", find(r.root(), "Request id"));
        assertEquals("400", find(r.root(), "HTTP-like status"));
        assertTrue(TreeText.render(r.root()).contains("End of response"));
    }

    @Test
    void chunkLengthsInBytesOrOffByOneAreTolerated() throws Exception {
        JsonArray a = new JsonArray(); a.add(wrb("AbC12", "[\"héllo wörld ✓\"]"));
        JsonArray b = new JsonArray(); b.add(wrb("XyZ34", "[1]"));
        String ja = a.toString(), jb = b.toString();
        int bytes = ja.getBytes(StandardCharsets.UTF_8).length;
        String body = ")]}'\n" + bytes + "\n" + ja + "\n" + (jb.length() + 1) + "\n" + jb;
        DecodeResult r = be.decode(response(URL, body.getBytes(StandardCharsets.UTF_8)));
        assertEquals("batchexecute response: wrb.fr AbC12 (" + BatchExecuteDecoder.size(a.get(0).getAsJsonArray().get(2).getAsString().length())
                + " payload), wrb.fr XyZ34 (3 B payload)", r.summary());
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
    }

    @Test
    void resyncAfterGarbageAndWildLength() throws Exception {
        JsonArray a = new JsonArray(); a.add(wrb("AbC12", "[1]"));
        JsonArray b = new JsonArray(); b.add(wrb("XyZ34", "[2]"));
        String body = ")]}'\n999\n" + a + "\n%%corrupt%%\n" + b.toString().length() + "\n" + b;
        DecodeResult r = be.decode(response(URL, body.getBytes(StandardCharsets.UTF_8)));
        assertEquals("batchexecute response: wrb.fr AbC12 (3 B payload), wrb.fr XyZ34 (3 B payload)", r.summary());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("declared length 999")), r.warnings().toString());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("resynchronised")), r.warnings().toString());
    }

    @Test
    void truncatedChunkIsReported() throws Exception {
        JsonArray a = new JsonArray(); a.add(wrb("AbC12", "[1]"));
        String j = a.toString();
        String body = ")]}'\n" + j.length() + "\n" + j + "\n200\n[[\"wrb.fr\",\"XyZ34\",\"[1,2";
        DecodeResult r = be.decode(response(URL, body.getBytes(StandardCharsets.UTF_8)));
        assertTrue(r.summary().startsWith("batchexecute response: wrb.fr AbC12"), r.summary());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("incomplete")), r.warnings().toString());
    }

    @Test
    void nonChunkedGzipResponseAndRpcError() throws Exception {
        JsonArray all = new JsonArray();
        all.add(wrb("AbC12", "[[\"ok\"]]"));
        JsonArray err = new JsonArray(); err.add("wrb.fr"); err.add("XyZ34"); err.add(JsonNull.INSTANCE); err.add(JsonNull.INSTANCE);
        err.add(JsonNull.INSTANCE); JsonArray code = new JsonArray(); code.add(3); err.add(code); err.add("generic");
        all.add(err);
        JsonArray di = new JsonArray(); di.add("di"); di.add(45);
        all.add(di);
        String body = ")]}'\n\n" + all;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream g = new GZIPOutputStream(bos)) { g.write(body.getBytes(StandardCharsets.UTF_8)); }
        String url = "https://myaccount.google.com/_/AccountSettingsUi/data/batchexecute?rpcids=AbC12,XyZ34&hl=en";
        DecodeResult r = be.decode(response(url, bos.toByteArray(), "Content-Encoding", "gzip"));
        assertEquals("batchexecute response: wrb.fr AbC12 (8 B payload), wrb.fr XyZ34 error [3]", r.summary());
        assertEquals("single JSON body", find(r.root(), "Framing"));
        assertEquals("ok", find(r.root(), "[0]"));
    }

    @Test
    void xssiResponseOnOtherPathMatchesAt70() {
        JsonArray a = new JsonArray(); a.add(wrb("AbC12", "[1]"));
        String body = ")]}'\n" + chunk(a.toString());
        assertEquals(70, be.match(response("https://www.google.com/other", body.getBytes(StandardCharsets.UTF_8))).confidence());
        assertEquals(0, be.match(response("https://www.google.com/other", ")]}'\n{\"x\":1}".getBytes(StandardCharsets.UTF_8))).confidence());
    }

    @Test
    void negatives() {
        assertEquals(0, be.match(request("https://app.example.com/save", "f.req=hello&at=x")).confidence());
        assertEquals(0, be.match(request("https://app.example.com/save", "f.req=" + enc("[1,2,3]"))).confidence());
        assertEquals(0, be.match(request("https://app.example.com/save", "f.req=" + enc("[[\"a\",\"plain text\"]]"))).confidence());
        assertEquals(0, be.match(request("https://app.example.com/save", "user=bob&f.request=1")).confidence());
        MessageContext wsMsg = MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("wss://chat.example.com/ws")
                .webSocket("SERVER_TO_CLIENT", "{\"type\":\"message\",\"data\":[1,2]}".getBytes(StandardCharsets.UTF_8)).build();
        assertEquals(0, be.match(wsMsg).confidence());
    }

    @Test
    void forcedDecodeOnGarbageThrows() {
        assertThrows(DecodeException.class, () -> be.decode(request("https://app.example.com/save", "user=bob")));
        assertThrows(DecodeException.class, () -> be.decode(request("https://app.example.com/save", "f.req=" + enc("{not json"))));
        assertThrows(DecodeException.class, () -> be.decode(response("https://app.example.com/x",
                new byte[]{(byte) 0x89, 'P', 'N', 'G', 0, 1, 2, 3, 4, 5})));
        assertThrows(DecodeException.class, () -> be.decode(response(URL, ")]}'\n\n<html>error</html>".getBytes(StandardCharsets.UTF_8))));
    }
}
