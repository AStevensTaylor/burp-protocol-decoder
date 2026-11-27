package protocoldecoder.builtin.phoenix;

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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class PhoenixDecoderTest {

    final PhoenixDecoder d = new PhoenixDecoder();

    static final String SOCKET = "wss://app.example.com/socket/websocket?vsn=2.0.0&token=abc";
    static final String LIVE = "wss://app.example.com/live/websocket?_csrf_token=xyz&vsn=2.0.0";

    static MessageContext ws(String url, String dir, byte[] p) {
        return MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url(url).webSocket(dir, p).build();
    }

    static MessageContext ws(String url, String dir, String text) {
        return ws(url, dir, text.getBytes(StandardCharsets.UTF_8));
    }

    static String find(DecodedNode n, String nameContains) {
        if (n.name().contains(nameContains) && n.value() != null) return n.value();
        for (DecodedNode c : n.children()) {
            String v = find(c, nameContains);
            if (v != null) return v;
        }
        return null;
    }

    static String text(DecodeResult r) {
        return TreeText.render(r.root());
    }

    // ------------------------------------------------------------ tiny ETF encoder + token signer for test data

    record A(String name) {
    }

    static void etf(ByteArrayOutputStream o, Object v) {
        if (v instanceof A a) {
            byte[] b = a.name().getBytes(StandardCharsets.UTF_8);
            o.write(119); o.write(b.length); o.writeBytes(b);
        } else if (v instanceof Integer i && i >= 0 && i < 256) {
            o.write(97); o.write(i);
        } else if (v instanceof Integer i) {
            o.write(98); o.write(i >>> 24); o.write(i >>> 16); o.write(i >>> 8); o.write(i);
        } else if (v instanceof Long l) {
            o.write(110); o.write(8); o.write(l < 0 ? 1 : 0);
            long x = Math.abs(l);
            for (int k = 0; k < 8; k++) o.write((int) (x >>> (8 * k)) & 0xff);
        } else if (v instanceof String s) {
            byte[] b = s.getBytes(StandardCharsets.UTF_8);
            o.write(109); int n = b.length; o.write(n >>> 24); o.write(n >>> 16); o.write(n >>> 8); o.write(n); o.writeBytes(b);
        } else if (v instanceof Object[] t) {
            o.write(104); o.write(t.length);
            for (Object x : t) etf(o, x);
        } else if (v instanceof List<?> l) {
            if (l.isEmpty()) { o.write(106); return; }
            o.write(108); int n = l.size(); o.write(n >>> 24); o.write(n >>> 16); o.write(n >>> 8); o.write(n);
            for (Object x : l) etf(o, x);
            o.write(106);
        } else if (v instanceof Map<?, ?> m) {
            o.write(116); int n = m.size(); o.write(n >>> 24); o.write(n >>> 16); o.write(n >>> 8); o.write(n);
            m.forEach((k, x) -> { etf(o, k); etf(o, x); });
        } else {
            throw new IllegalArgumentException(String.valueOf(v));
        }
    }

    static String signedToken(Object data, long signedAtMs, int maxAge) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(131);
        etf(o, new Object[]{data, signedAtMs, maxAge});
        Base64.Encoder e = Base64.getUrlEncoder().withoutPadding();
        return e.encodeToString("HS256".getBytes(StandardCharsets.US_ASCII)) + "." + e.encodeToString(o.toByteArray()) + "."
                + e.encodeToString(new byte[32]);
    }

    static Map<Object, Object> map(Object... kv) {
        Map<Object, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
        return m;
    }

    // ------------------------------------------------------------ channels

    @Test
    void v2JoinAndHeartbeat() throws Exception {
        MessageContext m = ws(SOCKET, "CLIENT_TO_SERVER", "[\"3\",\"3\",\"room:lobby\",\"phx_join\",{\"user\":\"bob\"}]");
        assertEquals(92, d.match(m).confidence());
        DecodeResult r = d.decode(m);
        assertEquals("Phoenix phx_join room:lobby (ref 3)", r.summary());
        assertEquals("v2 JSON array", find(r.root(), "Serializer"));
        assertEquals("bob", find(r.root(), "user"));
        assertEquals("2.0.0", find(r.root(), "vsn"));

        DecodeResult hb = d.decode(ws(SOCKET, "CLIENT_TO_SERVER", "[null,\"7\",\"phoenix\",\"heartbeat\",{}]"));
        assertEquals("Phoenix heartbeat (ref 7)", hb.summary());
        assertEquals("null", find(hb.root(), "join_ref"));

        DecodeResult hbr = d.decode(ws(SOCKET, "SERVER_TO_CLIENT", "[null,\"7\",\"phoenix\",\"phx_reply\",{\"status\":\"ok\",\"response\":{}}]"));
        assertEquals("Phoenix heartbeat reply ok (ref 7)", hbr.summary());
    }

    @Test
    void v1ObjectMessages() throws Exception {
        MessageContext m = ws("wss://app.example.com/socket/websocket?vsn=1.0.0", "CLIENT_TO_SERVER",
                "{\"topic\":\"room:lobby\",\"event\":\"new_msg\",\"payload\":{\"body\":\"hello\"},\"ref\":\"5\"}");
        assertEquals(92, d.match(m).confidence());
        DecodeResult r = d.decode(m);
        assertEquals("Phoenix new_msg on room:lobby (ref 5)", r.summary());
        assertEquals("v1 JSON object", find(r.root(), "Serializer"));
        assertEquals("hello", find(r.root(), "body"));

        DecodeResult close = d.decode(ws(SOCKET, "SERVER_TO_CLIENT", "{\"topic\":\"room:lobby\",\"event\":\"phx_close\",\"payload\":{},\"ref\":null,\"join_ref\":\"1\"}"));
        assertEquals("Phoenix phx_close on room:lobby", close.summary());
        assertTrue(text(close).contains("channel closed"));
    }

    @Test
    void replyOkAndError() throws Exception {
        DecodeResult ok = d.decode(ws(SOCKET, "SERVER_TO_CLIENT", "[\"3\",\"3\",\"room:lobby\",\"phx_reply\",{\"status\":\"ok\",\"response\":{\"id\":9}}]"));
        assertEquals("Phoenix phx_reply ok (ref 3) on room:lobby", ok.summary());
        assertEquals("9", find(ok.root(), "id"));

        DecodeResult err = d.decode(ws(SOCKET, "SERVER_TO_CLIENT", "[\"3\",\"3\",\"room:secret\",\"phx_reply\",{\"status\":\"error\",\"response\":{\"reason\":\"unauthorized\"}}]"));
        assertEquals("Phoenix phx_reply error (ref 3) on room:secret: unauthorized", err.summary());
        assertEquals("error", find(err.root(), "status"));

        assertEquals("Phoenix phx_leave on room:lobby (ref 4)",
                d.decode(ws(SOCKET, "CLIENT_TO_SERVER", "[\"3\",\"4\",\"room:lobby\",\"phx_leave\",{}]")).summary());
        assertEquals("Phoenix phx_error on room:lobby",
                d.decode(ws(SOCKET, "SERVER_TO_CLIENT", "[\"3\",null,\"room:lobby\",\"phx_error\",{}]")).summary());
    }

    // ------------------------------------------------------------ LiveView

    @Test
    void liveViewFormEvent() throws Exception {
        String f = "[\"4\",\"12\",\"lv:phx-F1a2\",\"event\",{\"type\":\"form\",\"event\":\"validate\",\"value\":\"user%5Bemail%5D=a%40b.com&user%5Bname%5D=Bob+Smith&_target=user%5Bemail%5D\",\"cid\":3}]";
        MessageContext m = ws(LIVE, "CLIENT_TO_SERVER", f);
        assertEquals(92, d.match(m).confidence());
        DecodeResult r = d.decode(m);
        assertEquals("LiveView event \"validate\" (form) on lv:phx-F1a2", r.summary());
        assertEquals("a@b.com", find(r.root(), "user[email]"));
        assertEquals("Bob Smith", find(r.root(), "user[name]"));
        assertEquals("user[email]", find(r.root(), "_target"));
        assertEquals("3", find(r.root(), "cid"));
        assertEquals("Phoenix LiveView", r.root().name());
    }

    @Test
    void liveViewClickEvent() throws Exception {
        DecodeResult r = d.decode(ws(LIVE, "CLIENT_TO_SERVER", "[\"4\",\"13\",\"lv:phx-F1a2\",\"event\",{\"type\":\"click\",\"event\":\"inc\",\"value\":{\"id\":\"7\"}}]"));
        assertEquals("LiveView event \"inc\" (click) on lv:phx-F1a2", r.summary());
        assertEquals("7", find(r.root(), "id"));
    }

    @Test
    void liveViewDiff() throws Exception {
        String diff = "[null,null,\"lv:phx-F1a2\",\"diff\",{\"0\":\"42\",\"1\":{\"0\":\"nested\"},\"2\":5,\"c\":{\"5\":{\"0\":\"comp\"}},\"e\":[[\"highlight\",{\"id\":\"row-1\"}]],\"t\":\"Dashboard\"}]";
        DecodeResult r = d.decode(ws(LIVE, "SERVER_TO_CLIENT", diff));
        assertEquals("LiveView diff on lv:phx-F1a2 (3 dynamics, 1 component, 1 event, title \"Dashboard\")", r.summary());
        String t = text(r);
        assertTrue(t.contains("0 — dynamic #0"), t);
        assertTrue(t.contains("c — components (1)"), t);
        assertTrue(t.contains("cid 5"), t);
        assertTrue(t.contains("e — pushed events (1)"), t);
        assertTrue(t.contains("t — page title"), t);
        assertEquals("row-1", find(r.root(), "id"));
    }

    @Test
    void liveViewJoinReplyRendersStatics() throws Exception {
        String reply = "[\"4\",\"4\",\"lv:phx-F1a2\",\"phx_reply\",{\"status\":\"ok\",\"response\":{\"rendered\":"
                + "{\"0\":\"7\",\"1\":{\"d\":[[\"a\"],[\"b\"]],\"s\":[\"<li>\",\"</li>\"]},\"2\":1,"
                + "\"c\":{\"1\":{\"0\":\"x\",\"s\":[\"<span>\",\"</span>\"]}},"
                + "\"s\":[\"<p>Count: \",\"</p><ul>\",\"</ul>\",\"\"],\"t\":\"Home\"}}}]";
        DecodeResult r = d.decode(ws(LIVE, "SERVER_TO_CLIENT", reply));
        assertEquals("LiveView phx_reply ok (ref 4) on lv:phx-F1a2 (rendered: statics, 3 dynamics, 1 component, title \"Home\")", r.summary());
        assertEquals("<p>Count: 7</p><ul><li>a</li><li>b</li></ul><span>x</span>", find(r.root(), "Rendered HTML"));
        assertTrue(text(r).contains("s — statics (4)"), text(r));
        assertTrue(text(r).contains("d — comprehension rows (2)"), text(r));
    }

    @Test
    void liveViewJoinWithSignedSession() throws Exception {
        String session = signedToken(map(new A("id"), "phx-F1a2", new A("session"), map("user_token", "s3cr3t"),
                new A("view"), new A("Elixir.MyAppWeb.PageLive"), new A("parent_pid"), new A("nil"), new A("assign_new"), List.of()),
                1_700_000_000_000L, 1209600);
        String join = "[\"4\",\"4\",\"lv:phx-F1a2\",\"phx_join\",{\"url\":\"https://app.example.com/dashboard\",\"params\":{\"_csrf_token\":\"xyz\",\"_mounts\":0},"
                + "\"session\":\"" + session + "\",\"static\":null}]";
        DecodeResult r = d.decode(ws(LIVE, "CLIENT_TO_SERVER", join));
        assertEquals("LiveView join lv:phx-F1a2 (https://app.example.com/dashboard)", r.summary());
        String t = text(r);
        assertEquals("HS256", find(r.root(), "Algorithm"));
        assertEquals("phx-F1a2", find(r.root(), "id"));
        assertEquals("s3cr3t", find(r.root(), "\"user_token\""));
        assertEquals("MyAppWeb.PageLive", find(r.root(), "view"));
        assertTrue(t.contains("2023-11-14T22:13:20Z"), t);
        assertTrue(t.contains("signed, not encrypted"), t);
    }

    @Test
    void navigationEvents() throws Exception {
        assertEquals("LiveView live_redirect → /users/1 on lv:phx-F1a2",
                d.decode(ws(LIVE, "SERVER_TO_CLIENT", "[\"4\",null,\"lv:phx-F1a2\",\"live_redirect\",{\"to\":\"/users/1\",\"kind\":\"push\"}]")).summary());
        assertEquals("LiveView live_patch → http://app.example.com/?page=2 on lv:phx-F1a2",
                d.decode(ws(LIVE, "CLIENT_TO_SERVER", "[\"4\",\"9\",\"lv:phx-F1a2\",\"live_patch\",{\"url\":\"http://app.example.com/?page=2\"}]")).summary());
        assertEquals("LiveView redirect → /login on lv:phx-F1a2",
                d.decode(ws(LIVE, "SERVER_TO_CLIENT", "[\"4\",null,\"lv:phx-F1a2\",\"redirect\",{\"to\":\"/login\"}]")).summary());
    }

    // ------------------------------------------------------------ binary serializer

    static byte[] binary(int kind, byte[] data, String... fields) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(kind);
        for (String f : fields) o.write(f.getBytes(StandardCharsets.UTF_8).length);
        for (String f : fields) o.writeBytes(f.getBytes(StandardCharsets.UTF_8));
        o.writeBytes(data);
        return o.toByteArray();
    }

    @Test
    void binaryPushReplyBroadcast() throws Exception {
        byte[] push = binary(0, new byte[]{1, 2, 3}, "1", "5", "room:files", "upload");
        MessageContext m = ws(SOCKET, "CLIENT_TO_SERVER", push);
        assertEquals(88, d.match(m).confidence());
        DecodeResult r = d.decode(m);
        assertEquals("Phoenix upload on room:files (binary, 3 bytes)", r.summary());
        assertEquals("5", r.root().get("ref").value());
        assertEquals("1", r.root().get("join_ref").value());
        assertEquals("01 02 03", find(r.root(), "hex"));

        byte[] serverPush = binary(0, "{\"answer\":1}".getBytes(StandardCharsets.UTF_8), "1", "room:files", "data");
        DecodeResult sp = d.decode(ws(SOCKET, "SERVER_TO_CLIENT", serverPush));
        assertEquals("Phoenix data on room:files (binary, 12 bytes)", sp.summary());
        assertEquals("1", find(sp.root(), "answer"));
        assertEquals("null", sp.root().get("ref").value());

        byte[] reply = binary(1, new byte[]{9}, "1", "5", "room:files", "ok");
        assertEquals("Phoenix phx_reply ok (ref 5) on room:files (binary, 1 bytes)", d.decode(ws(SOCKET, "SERVER_TO_CLIENT", reply)).summary());

        byte[] bc = binary(2, new byte[]{7, 7}, "room:files", "new_file");
        assertEquals("Phoenix new_file on room:files (binary, 2 bytes)", d.decode(ws(SOCKET, "SERVER_TO_CLIENT", bc)).summary());

        byte[] bad = {1, 50, 50, 50, 50, 1};
        assertEquals(40, d.match(ws(SOCKET, "SERVER_TO_CLIENT", bad)).confidence());
        assertThrows(DecodeException.class, () -> d.decode(ws(SOCKET, "SERVER_TO_CLIENT", bad)));
    }

    // ------------------------------------------------------------ long poll

    @Test
    void longPoll() throws Exception {
        MessageContext resp = MessageContext.builder(MessageKind.RESPONSE).method("GET")
                .url("https://app.example.com/socket/longpoll?vsn=2.0.0&token=t1")
                .statusCode(200).responseBody("{\"status\":200,\"token\":\"t2\",\"messages\":[\"[\\\"1\\\",\\\"1\\\",\\\"room:lobby\\\",\\\"phx_reply\\\",{\\\"status\\\":\\\"ok\\\",\\\"response\\\":{}}]\",\"[null,null,\\\"room:lobby\\\",\\\"new_msg\\\",{\\\"body\\\":\\\"hi\\\"}]\"]}")
                .build();
        assertEquals(85, d.match(resp).confidence());
        DecodeResult r = d.decode(resp);
        assertEquals("Phoenix long poll 200: 2 messages: phx_reply, new_msg", r.summary());
        assertEquals("hi", find(r.root(), "body"));

        MessageContext send = MessageContext.builder(MessageKind.REQUEST).method("POST")
                .url("https://app.example.com/socket/longpoll?vsn=2.0.0&token=t2")
                .requestHeader("Content-Type", "application/x-ndjson")
                .requestBody("[\"1\",\"2\",\"room:lobby\",\"new_msg\",{\"body\":\"a\"}]\n[null,\"3\",\"phoenix\",\"heartbeat\",{}]").build();
        assertEquals(85, d.match(send).confidence());
        assertEquals("Long poll send: 2 messages: new_msg, heartbeat", d.decode(send).summary());
    }

    // ------------------------------------------------------------ LiveView page

    @Test
    void liveViewPage() throws Exception {
        String session = signedToken(map(new A("id"), "phx-Fmain", new A("view"), new A("Elixir.AppWeb.HomeLive")), 1_700_000_000_000L, 1209600);
        String html = "<html><head><meta name=\"csrf-token\" content=\"Q1NSRi10b2tlbg\"></head><body>"
                + "<div id=\"phx-Fmain\" data-phx-main data-phx-session=\"" + session + "\" data-phx-static=\"\"><p>hi</p></div></body></html>";
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://app.example.com/")
                .statusCode(200).responseHeader("Content-Type", "text/html").responseBody(html).build();
        assertEquals(30, d.match(m).confidence());
        DecodeResult r = d.decode(m);
        assertEquals("LiveView page: 1 view (main phx-Fmain), CSRF token", r.summary());
        assertEquals("Q1NSRi10b2tlbg", find(r.root(), "CSRF"));
        assertEquals("AppWeb.HomeLive", find(r.root(), "view"));
        assertFalse(r.warnings().isEmpty());
    }

    @Test
    void encryptedTokenRecognised() {
        Base64.Encoder e = Base64.getUrlEncoder().withoutPadding();
        String tok = e.encodeToString("A256GCM".getBytes()) + ".aaaa.bbbb.cccc.dddd";
        assertTrue(PhoenixToken.looksLikeToken(tok));
        assertTrue(TreeText.render(PhoenixToken.node("t", tok)).contains("not readable"));
        assertFalse(PhoenixToken.looksLikeToken("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"));
    }

    // ------------------------------------------------------------ negatives and shapes

    @Test
    void shapeOnlyAndGenericJson() {
        String other = "wss://other.example/ws";
        assertEquals(60, d.match(ws(other, "CLIENT_TO_SERVER", "[\"1\",\"1\",\"room:lobby\",\"phx_join\",{}]")).confidence());
        assertEquals(60, d.match(ws(other, "SERVER_TO_CLIENT", "[null,null,\"lv:phx-1\",\"diff\",{\"0\":\"x\"}]")).confidence());
        assertEquals(40, d.match(ws(other, "SERVER_TO_CLIENT", "[\"1\",\"2\",\"room:lobby\",\"new_msg\",{}]")).confidence());
        assertEquals(0, d.match(ws(other, "SERVER_TO_CLIENT", "{\"type\":\"update\",\"id\":42}")).confidence());
        assertEquals(0, d.match(ws(other, "SERVER_TO_CLIENT", "[1,2,3,4,5]")).confidence());
        assertEquals(0, d.match(ws(other, "SERVER_TO_CLIENT", "{\"topic\":\"x\",\"event\":\"y\",\"payload\":{},\"extra\":1}")).confidence());
        assertEquals(0, d.match(ws(other, "SERVER_TO_CLIENT", "42[\"chat\",1]")).confidence());
        assertEquals(0, d.match(ws(other, "SERVER_TO_CLIENT", new byte[]{0, 1, 1, 1, 1, 'a', 'b', 'c', 'd'})).confidence());
        assertEquals(0, d.match(ws(SOCKET, "SERVER_TO_CLIENT", "{\"type\":\"update\"}")).confidence());
    }

    @Test
    void forcedDecodeOnGarbage() {
        assertThrows(DecodeException.class, () -> d.decode(ws(SOCKET, "SERVER_TO_CLIENT", "not json")));
        assertThrows(DecodeException.class, () -> d.decode(ws(SOCKET, "SERVER_TO_CLIENT", "{\"a\":1}")));
        assertThrows(DecodeException.class, () -> d.decode(ws(SOCKET, "SERVER_TO_CLIENT", new byte[0])));
        MessageContext html = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://x.example/")
                .statusCode(200).responseBody("<html>plain</html>").build();
        DecodeException e = assertThrows(DecodeException.class, () -> d.decode(html));
        assertTrue(e.getMessage().startsWith("Not a Phoenix channel message"), e.getMessage());
    }

    @Test
    void etfRejectsTruncatedInput() {
        assertThrows(Etf.EtfException.class, () -> Etf.decode(new byte[]{(byte) 131, 109, 0, 0, 0, 50, 1}));
        assertThrows(Etf.EtfException.class, () -> Etf.decode(new byte[]{(byte) 131, 108, 0x7f, 0, 0, 0}));
        assertThrows(Etf.EtfException.class, () -> Etf.decode(new byte[]{1, 2}));
    }
}
