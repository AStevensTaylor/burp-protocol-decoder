package protocoldecoder.builtin.socketio;

import org.junit.jupiter.api.Test;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.util.TreeText;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class SocketIoDecoderTest {

    final SocketIoDecoder d = new SocketIoDecoder();

    static final String WS_URL = "wss://chat.example.com/socket.io/?EIO=4&transport=websocket&sid=abc123";
    static final String WS3_URL = "wss://chat.example.com/socket.io/?EIO=3&transport=websocket";

    static MessageContext ws(String url, String dir, byte[] payload) {
        return MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url(url).webSocket(dir, payload).build();
    }

    static MessageContext ws(String dir, String text) {
        return ws(WS_URL, dir, text.getBytes(StandardCharsets.UTF_8));
    }

    static MessageContext pollResponse(String eio, String body) {
        return MessageContext.builder(MessageKind.RESPONSE).method("GET")
                .url("https://chat.example.com/socket.io/?EIO=" + eio + "&transport=polling&t=Nx1&sid=s1")
                .statusCode(200).responseHeader("Content-Type", "text/plain; charset=UTF-8").responseBody(body).build();
    }

    static MessageContext pollRequest(String eio, String body) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST")
                .url("https://chat.example.com/socket.io/?EIO=" + eio + "&transport=polling&sid=s1")
                .requestHeader("Content-Type", "text/plain;charset=UTF-8").requestBody(body).build();
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

    // ------------------------------------------------------------ Engine.IO packet types

    @Test
    void openHandshake() throws Exception {
        MessageContext m = ws("SERVER_TO_CLIENT", "0{\"sid\":\"lv9p-xG5\",\"upgrades\":[],\"pingInterval\":25000,\"pingTimeout\":20000,\"maxPayload\":1000000}");
        assertEquals(92, d.match(m).confidence());
        DecodeResult r = d.decode(m);
        assertEquals("Engine.IO open (sid lv9p-xG5, ping 25000ms)", r.summary());
        assertEquals("20000", find(r.root(), "pingTimeout"));
        assertEquals("1000000", find(r.root(), "maxPayload"));
        assertEquals("abc123", find(r.root(), "Session ID"));
        assertTrue(r.warnings().isEmpty());
    }

    @Test
    void closePingPongUpgradeNoop() throws Exception {
        assertEquals("Engine.IO close", d.decode(ws("CLIENT_TO_SERVER", "1")).summary());
        DecodeResult ping = d.decode(ws("SERVER_TO_CLIENT", "2"));
        assertEquals("Engine.IO ping", ping.summary());
        assertTrue(text(ping).contains("v4: sent by the server"), text(ping));
        assertEquals("Engine.IO pong", d.decode(ws("CLIENT_TO_SERVER", "3")).summary());
        assertEquals("Engine.IO ping probe", d.decode(ws("CLIENT_TO_SERVER", "2probe")).summary());
        assertEquals("Engine.IO pong probe", d.decode(ws("SERVER_TO_CLIENT", "3probe")).summary());
        assertEquals("Engine.IO upgrade", d.decode(ws("CLIENT_TO_SERVER", "5")).summary());
        assertEquals("Engine.IO noop", d.decode(ws("SERVER_TO_CLIENT", "6")).summary());
    }

    @Test
    void v3PingIsFromClient() throws Exception {
        DecodeResult r = d.decode(ws(WS3_URL, "CLIENT_TO_SERVER", "2".getBytes(StandardCharsets.UTF_8)));
        assertTrue(text(r).contains("v3: sent by the client"), text(r));
    }

    @Test
    void plainEngineIoMessage() throws Exception {
        DecodeResult r = d.decode(ws("CLIENT_TO_SERVER", "4hello world"));
        assertEquals("Engine.IO message", r.summary());
        assertEquals("hello world", find(r.root(), "Data"));
    }

    // ------------------------------------------------------------ Socket.IO packet types

    @Test
    void eventWithNamespaceAndAck() throws Exception {
        MessageContext m = ws("CLIENT_TO_SERVER", "42/admin,12[\"chat message\",{\"text\":\"hi\",\"room\":7}]");
        assertEquals(92, d.match(m).confidence());
        DecodeResult r = d.decode(m);
        assertEquals("Socket.IO EVENT \"chat message\" on /admin (ack 12)", r.summary());
        assertEquals("/admin", find(r.root(), "Namespace"));
        assertEquals("12", find(r.root(), "Ack ID"));
        assertEquals("chat message", find(r.root(), "Event"));
        assertEquals("hi", find(r.root(), "text"));
        assertEquals("7", find(r.root(), "room"));
    }

    @Test
    void eventOnDefaultNamespace() throws Exception {
        DecodeResult r = d.decode(ws("SERVER_TO_CLIENT", "42[\"news\",\"a\",1]"));
        assertEquals("Socket.IO EVENT \"news\"", r.summary());
        assertEquals("/", find(r.root(), "Namespace"));
        String t = text(r);
        assertTrue(t.contains("\"a\""), t);
    }

    @Test
    void connectDisconnectAckConnectError() throws Exception {
        DecodeResult c = d.decode(ws("CLIENT_TO_SERVER", "40/admin,{\"token\":\"secret\"}"));
        assertEquals("Socket.IO CONNECT on /admin", c.summary());
        assertEquals("secret", find(c.root(), "token"));
        assertTrue(text(c).contains("Payload (auth)"));

        DecodeResult cs = d.decode(ws("SERVER_TO_CLIENT", "40{\"sid\":\"wZX3oN0bSVIhsaknAAAI\"}"));
        assertEquals("Socket.IO CONNECT", cs.summary());
        assertTrue(text(cs).contains("Payload (server"));

        assertEquals("Socket.IO DISCONNECT on /admin", d.decode(ws("CLIENT_TO_SERVER", "41/admin,")).summary());

        DecodeResult ack = d.decode(ws("SERVER_TO_CLIENT", "43/admin,12[\"ok\",{\"saved\":true}]"));
        assertEquals("Socket.IO ACK on /admin (ack 12)", ack.summary());
        assertEquals("true", find(ack.root(), "saved"));

        DecodeResult err = d.decode(ws("SERVER_TO_CLIENT", "44/admin,{\"message\":\"Not authorized\"}"));
        assertEquals("Socket.IO CONNECT_ERROR \"Not authorized\" on /admin", err.summary());

        DecodeResult errV4 = d.decode(ws(WS3_URL, "SERVER_TO_CLIENT", "44\"Authentication error\"".getBytes(StandardCharsets.UTF_8)));
        assertEquals("Socket.IO CONNECT_ERROR \"Authentication error\"", errV4.summary());
    }

    @Test
    void binaryEventWithPlaceholders() throws Exception {
        DecodeResult r = d.decode(ws("CLIENT_TO_SERVER", "452-/uploads,[\"upload\",{\"name\":\"a.png\",\"file\":{\"_placeholder\":true,\"num\":0}},{\"_placeholder\":true,\"num\":1}]"));
        assertEquals("Socket.IO BINARY_EVENT \"upload\" on /uploads [2 attachments]", r.summary());
        assertEquals("2", find(r.root(), "Binary attachments"));
        String t = text(r);
        assertTrue(t.contains("args[0].file → attachment #0"), t);
        assertTrue(t.contains("args[1] → attachment #1"), t);

        DecodeResult ba = d.decode(ws("SERVER_TO_CLIENT", "461-3[{\"_placeholder\":true,\"num\":0}]"));
        assertEquals("Socket.IO BINARY_ACK (ack 3) [1 attachment]", ba.summary());
        assertTrue(text(ba).contains("data[0] → attachment #0"), text(ba));
    }

    @Test
    void binaryFramesV4AndV3() throws Exception {
        byte[] raw = {(byte) 0x89, 'P', 'N', 'G', 0, 1, 2, 3};
        MessageContext m = ws(WS_URL, "CLIENT_TO_SERVER", raw);
        assertEquals(80, d.match(m).confidence());
        DecodeResult r = d.decode(m);
        assertEquals("Engine.IO binary message (8 bytes)", r.summary());
        assertTrue(find(r.root(), "Hex").startsWith("89 50 4e 47"));

        byte[] v3 = {4, 1, 2, 3};
        DecodeResult r3 = d.decode(ws(WS3_URL, "CLIENT_TO_SERVER", v3));
        assertEquals("Engine.IO binary message (3 bytes)", r3.summary());
        assertEquals("01 02 03", find(r3.root(), "Hex"));
    }

    // ------------------------------------------------------------ long polling

    @Test
    void v4PollingPayload() throws Exception {
        String body = "42[\"chat message\",\"hi\"]\u001e42[\"typing\",true]\u001e2";
        MessageContext m = pollResponse("4", body);
        assertEquals(90, d.match(m).confidence());
        DecodeResult r = d.decode(m);
        assertEquals("Polling: 3 packets: EVENT ×2, PING", r.summary());
        assertTrue(find(r.root(), "Framing").startsWith("v4"));
        assertEquals("v4 (Socket.IO 3+/4)", find(r.root(), "Engine.IO protocol"));
    }

    @Test
    void v4PollingBase64Binary() throws Exception {
        String b64 = Base64.getEncoder().encodeToString(new byte[]{1, 2, 3, 4});
        DecodeResult r = d.decode(pollRequest("4", "451-[\"file\",{\"_placeholder\":true,\"num\":0}]\u001eb" + b64));
        assertEquals("Polling: 2 packets: BINARY_EVENT, BINARY", r.summary());
        assertEquals("01 02 03 04", find(r.root(), "Hex"));
    }

    @Test
    void v3PollingLengthFraming() throws Exception {
        String open = "0{\"sid\":\"Xa1\",\"upgrades\":[\"websocket\"],\"pingInterval\":25000,\"pingTimeout\":5000}";
        // UTF-16 lengths: "é" is one char, "😀" is two
        String ev = "42[\"msg\",\"café 😀\"]";
        String body = open.length() + ":" + open + "2:40" + ev.length() + ":" + ev;
        MessageContext m = pollResponse("3", body);
        assertEquals(90, d.match(m).confidence());
        DecodeResult r = d.decode(m);
        assertEquals("Polling: 3 packets: OPEN, CONNECT, EVENT", r.summary());
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
        assertTrue(text(r).contains("café 😀"), text(r));
        assertTrue(find(r.root(), "Framing").startsWith("v3"));
    }

    @Test
    void v3FramingSniffedWithoutEio() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://x.example/socket.io/?transport=polling")
                .statusCode(200).responseBody("1:22:40").build();
        DecodeResult r = d.decode(m);
        assertEquals("Polling: 2 packets: PING, CONNECT", r.summary());
    }

    @Test
    void v3BinaryBase64AndXhr2() throws Exception {
        String b64 = Base64.getEncoder().encodeToString(new byte[]{9, 8, 7});
        DecodeResult r = d.decode(pollResponse("3", "6:b4" + b64 + "2:40"));
        assertEquals("Polling: 2 packets: BINARY, CONNECT", r.summary());
        assertEquals("09 08 07", find(r.root(), "Hex"));

        // XHR2 binary framing: 0 <len digits> 0xFF "40", 1 <len digits> 0xFF <type 4><data>
        byte[] xhr2 = {0, 2, (byte) 0xff, '4', '0', 1, 3, (byte) 0xff, 4, 0x0a, 0x0b};
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://x.example/socket.io/?EIO=3&transport=polling&sid=q")
                .statusCode(200).responseHeader("Content-Type", "application/octet-stream").responseBody(xhr2).build();
        DecodeResult x = d.decode(m);
        assertEquals("Polling: 2 packets: CONNECT, BINARY", x.summary());
        assertEquals("0a 0b", find(x.root(), "Hex"));
    }

    @Test
    void jsonpPolling() throws Exception {
        DecodeResult r = d.decode(pollResponse("3", "___eio[0](\"2:40\");"));
        assertEquals("Polling: Socket.IO CONNECT", r.summary());
        MessageContext send = MessageContext.builder(MessageKind.REQUEST).method("POST")
                .url("https://x.example/socket.io/?EIO=3&transport=polling&j=0&sid=a")
                .requestHeader("Content-Type", "application/x-www-form-urlencoded").requestBody("d=" + java.net.URLEncoder.encode("7:42[\"a\"]", StandardCharsets.UTF_8)).build();
        assertEquals("Polling: Socket.IO EVENT \"a\"", d.decode(send).summary());
    }

    @Test
    void okAckErrorAndHandshakeRequest() throws Exception {
        MessageContext ok = pollResponse("4", "ok");
        assertEquals(90, d.match(ok).confidence());
        assertEquals("Polling: send acknowledged (ok)", d.decode(ok).summary());

        MessageContext err = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://x.example/socket.io/?EIO=4&transport=polling&sid=old")
                .statusCode(400).responseBody("{\"code\":1,\"message\":\"Session ID unknown\"}").build();
        assertEquals(85, d.match(err).confidence());
        DecodeResult er = d.decode(err);
        assertEquals("Engine.IO error 1: Session ID unknown", er.summary());

        MessageContext hs = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://x.example/socket.io/?EIO=4&transport=polling&t=OaB").build();
        assertEquals(40, d.match(hs).confidence());
        assertEquals("Engine.IO handshake request (EIO=4)", d.decode(hs).summary());
    }

    @Test
    void customPathMatchedByQuery() {
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://x.example/realtime/?EIO=4&transport=polling&sid=z")
                .statusCode(200).responseBody("40{\"sid\":\"y\"}").build();
        assertEquals(90, d.match(m).confidence());
    }

    @Test
    void partialPayloadWarns() throws Exception {
        DecodeResult r = d.decode(pollResponse("4", "2\u001ezzz"));
        assertEquals("Polling: 2 packets: PING, INVALID", r.summary());
        assertFalse(r.warnings().isEmpty());
        DecodeResult bad = d.decode(pollResponse("4", "42{\"not\":\"array\"}"));
        assertEquals("Polling: Engine.IO message", bad.summary());
        assertTrue(bad.warnings().get(0).contains("EVENT payload must be an array"), bad.warnings().toString());
    }

    // ------------------------------------------------------------ matching negatives / shapes

    @Test
    void shapeOnlyMatchesAreLow() {
        String url = "wss://other.example/ws";
        assertEquals(50, d.match(ws(url, "SERVER_TO_CLIENT", "42[\"x\",1]".getBytes(StandardCharsets.UTF_8))).confidence());
        assertEquals(45, d.match(ws(url, "CLIENT_TO_SERVER", "40".getBytes(StandardCharsets.UTF_8))).confidence());
        assertEquals(55, d.match(ws(url, "SERVER_TO_CLIENT", "0{\"sid\":\"a\",\"pingInterval\":1}".getBytes(StandardCharsets.UTF_8))).confidence());
        assertEquals(50, d.match(ws(url, "CLIENT_TO_SERVER", "2probe".getBytes(StandardCharsets.UTF_8))).confidence());
    }

    @Test
    void genericWebSocketDoesNotMatch() {
        String url = "wss://other.example/ws";
        assertEquals(0, d.match(ws(url, "SERVER_TO_CLIENT", "{\"type\":\"update\",\"id\":42}".getBytes(StandardCharsets.UTF_8))).confidence());
        assertEquals(0, d.match(ws(url, "SERVER_TO_CLIENT", "[\"1\",\"1\",\"room:lobby\",\"phx_join\",{}]".getBytes(StandardCharsets.UTF_8))).confidence());
        assertEquals(0, d.match(ws(url, "SERVER_TO_CLIENT", "42".getBytes(StandardCharsets.UTF_8))).confidence());
        assertEquals(0, d.match(ws(url, "SERVER_TO_CLIENT", "2".getBytes(StandardCharsets.UTF_8))).confidence());
        assertEquals(0, d.match(ws(url, "SERVER_TO_CLIENT", "12345".getBytes(StandardCharsets.UTF_8))).confidence());
        assertEquals(0, d.match(ws(url, "SERVER_TO_CLIENT", new byte[]{1, 2, 3})).confidence());
    }

    @Test
    void clientScriptAndUnrelatedHttpDoNotMatch() {
        MessageContext js = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://x.example/socket.io/socket.io.js")
                .statusCode(200).responseBody("!function(t,e){\"object\"==typeof exports}").build();
        assertEquals(0, d.match(js).confidence());
        MessageContext other = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://x.example/api/items")
                .statusCode(200).responseBody("42[\"x\"]").build();
        assertEquals(0, d.match(other).confidence());
    }

    // ------------------------------------------------------------ forced decode on garbage

    @Test
    void forcedDecodeOnGarbageThrows() {
        MessageContext html = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://x.example/")
                .statusCode(200).responseBody("<html><body>hello</body></html>").build();
        DecodeException e = assertThrows(DecodeException.class, () -> d.decode(html));
        assertTrue(e.getMessage().startsWith("Not an Engine.IO payload"), e.getMessage());
        assertThrows(DecodeException.class, () -> d.decode(ws("wss://x.example/ws", "SERVER_TO_CLIENT", "{\"a\":1}".getBytes(StandardCharsets.UTF_8))));
        assertThrows(DecodeException.class, () -> d.decode(ws("wss://x.example/ws", "SERVER_TO_CLIENT", new byte[0])));
        MessageContext empty = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://x.example/").statusCode(204).responseBody(new byte[0]).build();
        assertThrows(DecodeException.class, () -> d.decode(empty));
    }

    @Test
    void forcedBinaryOffPathWarns() throws Exception {
        DecodeResult r = d.decode(ws("wss://x.example/ws", "SERVER_TO_CLIENT", new byte[]{(byte) 0xde, (byte) 0xad}));
        assertFalse(r.warnings().isEmpty());
    }

    @Test
    void matchNeverThrows() {
        String[] samples = {"", "4", "45", "45-", "4512345678901-[]", "42/", "42/a", "b", "b!!!", "0", "0{", "3:abc", "99999999999:x"};
        for (String s : samples) {
            assertDoesNotThrow(() -> d.match(ws("SERVER_TO_CLIENT", s)), s);
            assertDoesNotThrow(() -> d.match(pollResponse("3", s)), s);
            assertDoesNotThrow(() -> d.match(pollResponse("4", s)), s);
        }
    }
}
