package protocoldecoder.builtin.turbo;

import org.junit.jupiter.api.Test;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.util.TreeText;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.*;

public class TurboDecoderTest {

    final TurboDecoder turbo = new TurboDecoder();

    static final String DIGEST = "a".repeat(64);

    public static String signedJson(String json) {
        return Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8)) + "--" + DIGEST;
    }

    /** Marshal.dump("gid://app/Room/1:messages") */
    public static byte[] marshalString(String s) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        o.write(4); o.write(8); o.write('I'); o.write('"'); o.write(b.length + 5); o.writeBytes(b);
        o.write(6); o.write(':'); o.write(6); o.write('E'); o.write('T');
        return o.toByteArray();
    }

    static MessageContext.Builder response(String contentType, String body) {
        return MessageContext.builder(MessageKind.RESPONSE).method("POST").url("https://app.example.com/messages")
                .statusCode(200).responseHeader("Content-Type", contentType).responseBody(body);
    }

    static String find(DecodedNode n, String nameContains) {
        if (n.name().contains(nameContains) && n.value() != null) return n.value();
        for (DecodedNode c : n.children()) {
            String v = find(c, nameContains);
            if (v != null) return v;
        }
        return null;
    }

    static DecodedNode findNode(DecodedNode n, String nameContains) {
        if (n.name().contains(nameContains)) return n;
        for (DecodedNode c : n.children()) {
            DecodedNode v = findNode(c, nameContains);
            if (v != null) return v;
        }
        return null;
    }

    // ------------------------------------------------------------ Turbo Stream responses

    @Test
    void multiActionStream() throws Exception {
        String body = """
                <turbo-stream action="replace" target="message_42"><template><div id="message_42"><p>Edited</p></div></template></turbo-stream>
                <turbo-stream action="append" target="messages">
                  <template>
                    <div id="message_43">Hello <b>world</b></div>
                  </template>
                </turbo-stream>
                <turbo-stream action="remove" target="flash"></turbo-stream>
                """;
        MessageContext m = response("text/vnd.turbo-stream.html; charset=utf-8", body).build();
        assertEquals(95, turbo.match(m).confidence());
        DecodeResult r = turbo.decode(m);
        assertEquals("Turbo Stream: replace #message_42, append #messages, remove #flash", r.summary());
        DecodedNode actions = r.root().get("Actions");
        assertEquals(3, actions.children().size());
        DecodedNode first = actions.children().get(0);
        assertEquals(DecodedNode.Type.HTML, first.get("template").type());
        assertEquals("<div id=\"message_42\"><p>Edited</p></div>", first.get("template").value());
        assertTrue(actions.children().get(1).get("template").value().contains("<b>world</b>"));
        DecodedNode remove = actions.children().get(2);
        assertNull(remove.get("template"));
        assertNotNull(remove.get("note"));
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
    }

    @Test
    void targetsSelectorMorphRefreshAndSingleQuotes() throws Exception {
        String body = "<turbo-stream action='update' targets='.unread-count'><template>3</template></turbo-stream>"
                + "<turbo-stream action=\"replace\" method=\"morph\" target=\"card_1\"><template><div id='card_1'>x</div></template></turbo-stream>"
                + "<turbo-stream action=\"morph\" target=\"list\" children-only><template><li>a</li></template></turbo-stream>"
                + "<turbo-stream action=\"refresh\" request-id=\"abc-123\"></turbo-stream>";
        DecodeResult r = turbo.decode(response("text/vnd.turbo-stream.html", body).build());
        assertEquals("Turbo Stream: update .unread-count, replace (morph) #card_1, morph #list, refresh", r.summary());
        String text = TreeText.render(r.root());
        assertTrue(text.contains("targets (CSS selector)"), text);
        assertTrue(text.contains("abc-123"), text);
        assertTrue(text.contains("children-only"), text);
        assertEquals("<div id='card_1'>x</div>", r.root().get("Actions").children().get(1).get("template").value());
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
    }

    @Test
    void nestedTemplateAndClosingTagsInsideTemplate() throws Exception {
        String body = "<turbo-stream action=\"append\" target=\"forms\"><template>"
                + "<div class=\"x\" data-title=\"a > b\"></div></div>"
                + "<template id=\"inner\"><span>row</span></template>"
                + "<!-- </template></turbo-stream> -->"
                + "<script>if (a</template>b) {}</script>"
                + "</template></turbo-stream>"
                + "<turbo-stream action=\"before\" target=\"x\"><template><hr></template></turbo-stream>";
        DecodeResult r = turbo.decode(response("text/vnd.turbo-stream.html", body).build());
        DecodedNode actions = r.root().get("Actions");
        assertEquals(2, actions.children().size(), TreeText.render(r.root()));
        String tpl = actions.children().get(0).get("template").value();
        assertTrue(tpl.startsWith("<div class=\"x\""), tpl);
        assertTrue(tpl.contains("<template id=\"inner\"><span>row</span></template>"), tpl);
        assertTrue(tpl.endsWith("</script>"), tpl);
        assertEquals("Turbo Stream: append #forms, before #x", r.summary());
    }

    @Test
    void customActionAndMissingTargetWarn() throws Exception {
        String body = "<turbo-stream action=\"console_log\" message=\"hi\"></turbo-stream><turbo-stream action=\"append\"><template>x</template></turbo-stream>";
        DecodeResult r = turbo.decode(response("text/vnd.turbo-stream.html", body).build());
        assertEquals("Turbo Stream: console_log, append", r.summary());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("Custom stream action 'console_log'")), r.warnings().toString());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("no target")), r.warnings().toString());
        assertEquals("hi", find(r.root(), "message"));
    }

    @Test
    void unterminatedStreamTolerated() throws Exception {
        String body = "<turbo-stream action=\"append\" target=\"a\"><template><p>1</p></template>"
                + "<turbo-stream action=\"remove\" target=\"b\"></turbo-stream>";
        DecodeResult r = turbo.decode(response("text/vnd.turbo-stream.html", body).build());
        // the first stream swallows the second as nested content; the parser must not throw
        assertTrue(r.summary().startsWith("Turbo Stream: append #a"), r.summary());
    }

    @Test
    void gzipStream() throws Exception {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(bo)) {
            gz.write("<turbo-stream action=\"prepend\" target=\"feed\"><template><li>new</li></template></turbo-stream>".getBytes(StandardCharsets.UTF_8));
        }
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).url("https://app.example.com/feed").statusCode(200)
                .responseHeader("Content-Type", "text/vnd.turbo-stream.html").responseHeader("Content-Encoding", "gzip")
                .responseBody(bo.toByteArray()).build();
        assertEquals("Turbo Stream: prepend #feed", turbo.decode(m).summary());
    }

    @Test
    void streamOverWebSocketAndSse() throws Exception {
        MessageContext ws = MessageContext.builder(MessageKind.WEBSOCKET).url("wss://app.example.com/streams")
                .webSocket("SERVER_TO_CLIENT", "<turbo-stream action=\"append\" target=\"log\"><template>x</template></turbo-stream>".getBytes(StandardCharsets.UTF_8)).build();
        assertEquals(85, turbo.match(ws).confidence());
        assertEquals("Turbo Stream (WebSocket server → client): append #log", turbo.decode(ws).summary());

        String sse = "event: message\ndata: <turbo-stream action=\"replace\" target=\"t\">\ndata: <template>y</template></turbo-stream>\n\n";
        MessageContext m = response("text/event-stream", sse).build();
        assertEquals(80, turbo.match(m).confidence());
        assertEquals("Turbo Stream (Server-Sent Events): replace #t", turbo.decode(m).summary());
    }

    // ------------------------------------------------------------ requests / frames

    @Test
    void frameRequest() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://app.example.com/rooms/1/comments?page=2")
                .requestHeader("Turbo-Frame", "comments").requestHeader("Accept", "text/html, application/xhtml+xml")
                .requestHeader("X-Turbo-Request-Id", "9f1c2d3e-0000-4000-8000-000000000001").build();
        assertEquals(80, turbo.match(m).confidence());
        DecodeResult r = turbo.decode(m);
        assertEquals("Turbo Frame request → #comments (GET /rooms/1/comments) id 9f1c2d3e-0000-4000-8000-000000000001", r.summary());
        assertEquals("comments", find(r.root(), "Turbo-Frame"));
        assertEquals("false", find(r.root(), "Accepts Turbo Streams"));
    }

    @Test
    void streamAcceptingFormSubmission() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/messages/5")
                .requestHeader("Accept", "text/vnd.turbo-stream.html, text/html, application/xhtml+xml")
                .requestHeader("Content-Type", "application/x-www-form-urlencoded")
                .requestBody("_method=patch&authenticity_token=tok&message%5Bbody%5D=hi").build();
        assertEquals(50, turbo.match(m).confidence());
        DecodeResult r = turbo.decode(m);
        assertEquals("Turbo Stream-accepting request (PATCH (via _method) /messages/5)", r.summary());
        assertEquals("hi", find(r.root(), "message[body]"));
    }

    @Test
    void prefetchAndRequestIdOnly() throws Exception {
        MessageContext pf = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://app.example.com/about")
                .requestHeader("X-Sec-Purpose", "prefetch").requestHeader("X-Turbo-Request-Id", "r1").build();
        assertEquals(45, turbo.match(pf).confidence());
        assertEquals("Turbo prefetch (GET /about) id r1", turbo.decode(pf).summary());
        MessageContext only = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://app.example.com/x")
                .requestHeader("X-Sec-Purpose", "prefetch").build();
        assertEquals(40, turbo.match(only).confidence());
    }

    @Test
    void frameResponse() throws Exception {
        String html = "<!doctype html><html><head><meta name=\"turbo-cache-control\" content=\"no-cache\"></head><body>"
                + "<turbo-frame id=\"nav\"><a href=\"/\">home</a></turbo-frame>"
                + "<turbo-frame id=\"comments\" src=\"/rooms/1/comments\" loading=\"lazy\" target=\"_top\">"
                + "<turbo-frame id=\"comment_1\"><p>first</p></turbo-frame><div>after</div></turbo-frame>"
                + "</body></html>";
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://app.example.com/rooms/1/comments")
                .requestHeader("Turbo-Frame", "comments").statusCode(200)
                .responseHeader("Content-Type", "text/html; charset=utf-8").responseBody(html).build();
        assertEquals(85, turbo.match(m).confidence());
        DecodeResult r = turbo.decode(m);
        assertEquals("Turbo Frame response #comments (src=/rooms/1/comments, loading=lazy, target=_top)", r.summary());
        String inner = find(r.root(), "Inner HTML");
        assertEquals("<turbo-frame id=\"comment_1\"><p>first</p></turbo-frame><div>after</div>", inner);
        assertEquals(DecodedNode.Type.HTML, findNode(r.root(), "Inner HTML").type());
        assertNotNull(findNode(r.root(), "Page"));
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
    }

    @Test
    void frameResponseMissingFrame() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://app.example.com/login")
                .requestHeader("Turbo-Frame", "comments").statusCode(200)
                .responseHeader("Content-Type", "text/html").responseBody("<html><body>Please log in</body></html>").build();
        assertEquals(70, turbo.match(m).confidence());
        DecodeResult r = turbo.decode(m);
        assertEquals("Turbo Frame response #comments: matching frame missing", r.summary());
        assertFalse(r.warnings().isEmpty());
    }

    // ------------------------------------------------------------ page hints / signed stream names

    @Test
    void pageHintsWithJsonSignedStreamName() throws Exception {
        String token = signedJson("\"gid://app/Room/1:messages\"");
        String html = "<html><head><meta name=\"turbo-refresh-method\" content=\"morph\">"
                + "<meta name='turbo-visit-control' content='reload'><meta name=\"view-transition\" content=\"same-origin\">"
                + "<meta name=\"csrf-token\" content=\"x\"></head><body>"
                + "<turbo-cable-stream-source channel=\"Turbo::StreamsChannel\" signed-stream-name=\"" + token + "\"></turbo-cable-stream-source>"
                + "<turbo-frame id=\"messages\" src=\"/rooms/1/messages\" loading=\"lazy\"></turbo-frame>"
                + "</body></html>";
        MessageContext m = response("text/html; charset=utf-8", html).build();
        assertEquals(30, turbo.match(m).confidence());
        DecodeResult r = turbo.decode(m);
        assertEquals("Turbo page: turbo-refresh-method=morph, turbo-visit-control=reload, view-transition=same-origin, "
                + "1 stream source (gid://app/Room/1:messages), 1 frame", r.summary());
        String text = TreeText.render(r.root());
        assertTrue(text.contains("HMAC-SHA256"), text);
        assertTrue(text.contains("model Room, id 1"), text);
        assertTrue(text.contains("not encrypted"), text);
        assertFalse(text.contains("csrf-token"), text);
    }

    @Test
    void pageHintsWithMarshalSignedStreamName() throws Exception {
        String token = Base64.getEncoder().encodeToString(marshalString("gid://shop/Admin::Order/77:items")) + "--" + "b".repeat(40);
        String html = "<html><body><turbo-cable-stream-source channel=\"Turbo::StreamsChannel\" signed-stream-name=\"" + token + "\"></turbo-cable-stream-source></body></html>";
        DecodeResult r = turbo.decode(response("text/html", html).build());
        assertEquals("Turbo page: 1 stream source (gid://shop/Admin::Order/77:items)", r.summary());
        String text = TreeText.render(r.root());
        assertTrue(text.contains("Ruby Marshal"), text);
        assertTrue(text.contains("HMAC-SHA1"), text);
        assertTrue(text.contains("model Admin::Order, id 77"), text);
    }

    @Test
    void marshalArrayWithSymlinks() {
        // Marshal.dump(["gid://app/Room/1", "messages", 300, :sym, nil])
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.writeBytes(new byte[]{4, 8, '[', 10});
        o.writeBytes(new byte[]{'I', '"', 16 + 5}); o.writeBytes("gid://app/Room/1".getBytes(StandardCharsets.UTF_8));
        o.writeBytes(new byte[]{6, ':', 6, 'E', 'T'});
        o.writeBytes(new byte[]{'I', '"', 8 + 5}); o.writeBytes("messages".getBytes(StandardCharsets.UTF_8));
        o.writeBytes(new byte[]{6, ';', 0, 'T'});
        o.writeBytes(new byte[]{'i', 2, 0x2c, 0x01});
        o.writeBytes(new byte[]{':', 8, 's', 'y', 'm'});
        o.write('0');
        assertEquals("[\"gid://app/Room/1\", \"messages\", 300, :sym, nil]", RubyMarshal.inspect(o.toByteArray()));
        assertThrows(IllegalArgumentException.class, () -> RubyMarshal.inspect(new byte[]{4, 8, '[', 10, '0'}));
    }

    @Test
    void signedStreamNameEnvelopeAndGarbage() {
        String env = signedJson("{\"_rails\":{\"data\":\"gid://app/User/5\",\"pur\":\"turbo\"}}");
        SignedStreamName.Decoded d = SignedStreamName.decode("x", env);
        assertTrue(d.ok());
        assertEquals("gid://app/User/5", d.display());
        assertEquals(java.util.List.of("gid://app/User/5"), d.globalIds());
        assertTrue(TreeText.render(d.node()).contains("turbo"));

        SignedStreamName.Decoded bad = SignedStreamName.decode("x", "!!!not base64!!!--zz");
        assertFalse(bad.ok());
        assertFalse(SignedStreamName.looksSigned("plain"));
        assertTrue(SignedStreamName.looksSigned(env));
    }

    @Test
    void inlineStreamsAndFramesOnPage() throws Exception {
        String html = "<html><body><turbo-frame id=\"a\"></turbo-frame>"
                + "<turbo-stream action=\"update\" target=\"count\"><template>5</template></turbo-stream></body></html>";
        MessageContext m = response("text/html", html).build();
        assertEquals(25, turbo.match(m).confidence());
        assertEquals("Turbo page: 1 frame, inline streams: update #count", turbo.decode(m).summary());
    }

    // ------------------------------------------------------------ negatives / forced decodes

    @Test
    void ordinaryHtmlPageIsNotTurbo() {
        String html = "<html><head><meta name=\"description\" content=\"turbo charged\"><title>Turbo-stream fans</title></head>"
                + "<body><p>We love turbo-frame and <code>&lt;turbo-stream&gt;</code> talks</p></body></html>";
        MessageContext m = response("text/html", html).build();
        assertEquals(0, turbo.match(m).confidence());
        assertThrows(DecodeException.class, () -> turbo.decode(m));
        MessageContext req = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://example.com/")
                .requestHeader("Accept", "text/html").build();
        assertEquals(0, turbo.match(req).confidence());
        assertThrows(DecodeException.class, () -> turbo.decode(req));
    }

    @Test
    void forcedOnGarbage() {
        MessageContext bin = MessageContext.builder(MessageKind.RESPONSE).url("https://x/").statusCode(200)
                .responseHeader("Content-Type", "application/octet-stream").responseBody(new byte[]{0, 1, 2, (byte) 0xff, '<', 't'}).build();
        assertEquals(0, turbo.match(bin).confidence());
        assertThrows(DecodeException.class, () -> turbo.decode(bin));
        MessageContext ws = MessageContext.builder(MessageKind.WEBSOCKET).url("wss://x/cable")
                .webSocket("SERVER_TO_CLIENT", "{\"type\":\"ping\",\"message\":1}".getBytes(StandardCharsets.UTF_8)).build();
        assertEquals(0, turbo.match(ws).confidence());
        assertThrows(DecodeException.class, () -> turbo.decode(ws));
        // stream content type with no elements
        MessageContext empty = response("text/vnd.turbo-stream.html", "<div>nope</div>").build();
        assertThrows(DecodeException.class, () -> turbo.decode(empty));
        // malformed fragments never throw from the scanner
        for (String s : new String[]{"<", "<turbo-stream", "<turbo-stream action=\"x", "<turbo-stream action=a><template>", "<!-- <turbo-stream>", "<<<>>>"}) {
            assertDoesNotThrow(() -> TurboStream.parse(s), s);
            assertDoesNotThrow(() -> turbo.match(response("text/vnd.turbo-stream.html", s).build()), s);
        }
    }
}
