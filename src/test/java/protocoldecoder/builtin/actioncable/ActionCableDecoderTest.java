package protocoldecoder.builtin.actioncable;

import org.junit.jupiter.api.Test;
import protocoldecoder.builtin.turbo.TurboDecoderTest;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.util.TreeText;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class ActionCableDecoderTest {

    final ActionCableDecoder cable = new ActionCableDecoder();

    static MessageContext ws(String url, String dir, String payload) {
        return MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url(url)
                .requestHeader("Upgrade", "websocket")
                .requestHeader("Sec-WebSocket-Protocol", "actioncable-v1-json, actioncable-unsupported")
                .webSocket(dir, payload.getBytes(StandardCharsets.UTF_8)).build();
    }

    static MessageContext server(String payload) {
        return ws("wss://app.example.com/cable", "SERVER_TO_CLIENT", payload);
    }

    static MessageContext client(String payload) {
        return ws("wss://app.example.com/cable", "CLIENT_TO_SERVER", payload);
    }

    /** JSON-encodes a string (for identifier/data fields that hold JSON text). */
    static String q(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    static final String CHAT_ID = q("{\"channel\":\"ChatChannel\",\"room\":1}");

    static String find(DecodedNode n, String nameContains) {
        if (n.name().contains(nameContains) && n.value() != null) return n.value();
        for (DecodedNode c : n.children()) {
            String v = find(c, nameContains);
            if (v != null) return v;
        }
        return null;
    }

    @Test
    void welcome() throws Exception {
        MessageContext m = server("{\"type\":\"welcome\"}");
        assertEquals(95, cable.match(m).confidence());
        assertEquals("Action Cable welcome", cable.decode(m).summary());
        assertEquals("Action Cable welcome (sid abc)", cable.decode(server("{\"type\":\"welcome\",\"sid\":\"abc\"}")).summary());
    }

    @Test
    void ping() throws Exception {
        MessageContext m = server("{\"type\":\"ping\",\"message\":1795773600}");
        assertEquals(95, cable.match(m).confidence());
        DecodeResult r = cable.decode(m);
        assertEquals("Action Cable ping (2026-11-27T10:00:00Z)", r.summary());
        assertTrue(find(r.root(), "server time").contains("2026-11-27T10:00:00Z"));
    }

    @Test
    void subscribeConfirmRejectUnsubscribe() throws Exception {
        MessageContext sub = client("{\"command\":\"subscribe\",\"identifier\":" + CHAT_ID + "}");
        assertEquals(95, cable.match(sub).confidence());
        DecodeResult r = cable.decode(sub);
        assertEquals("Action Cable subscribe → ChatChannel {room: 1}", r.summary());
        assertEquals("ChatChannel", find(r.root(), "channel"));
        assertEquals("1", find(r.root(), "room"));

        assertEquals("Action Cable confirm_subscription → ChatChannel {room: 1}",
                cable.decode(server("{\"identifier\":" + CHAT_ID + ",\"type\":\"confirm_subscription\"}")).summary());
        assertEquals("Action Cable reject_subscription → ChatChannel {room: 1}",
                cable.decode(server("{\"identifier\":" + CHAT_ID + ",\"type\":\"reject_subscription\"}")).summary());
        assertEquals("Action Cable unsubscribe → ChatChannel {room: 1}",
                cable.decode(client("{\"command\":\"unsubscribe\",\"identifier\":" + CHAT_ID + "}")).summary());
    }

    @Test
    void messageCommandWithData() throws Exception {
        String data = q("{\"action\":\"speak\",\"message\":\"hello\",\"user_id\":7}");
        MessageContext m = client("{\"command\":\"message\",\"identifier\":" + CHAT_ID + ",\"data\":" + data + "}");
        DecodeResult r = cable.decode(m);
        assertEquals("Action Cable message → ChatChannel {room: 1}: speak", r.summary());
        assertEquals("speak", find(r.root(), "action (channel method"));
        assertEquals("hello", find(r.root(), "message"));
        assertEquals("7", find(r.root(), "user_id"));
    }

    @Test
    void disconnect() throws Exception {
        MessageContext m = server("{\"type\":\"disconnect\",\"reason\":\"unauthorized\",\"reconnect\":false}");
        assertEquals(95, cable.match(m).confidence());
        DecodeResult r = cable.decode(m);
        assertEquals("Action Cable disconnect (unauthorized, reconnect: false)", r.summary());
        assertEquals("false", find(r.root(), "reconnect"));
    }

    @Test
    void plainBroadcast() throws Exception {
        MessageContext m = server("{\"identifier\":" + CHAT_ID + ",\"message\":{\"body\":\"hi\",\"html\":\"<p>hi</p>\"}}");
        assertEquals(95, cable.match(m).confidence());
        DecodeResult r = cable.decode(m);
        assertEquals("Action Cable broadcast on ChatChannel {room: 1}", r.summary());
        assertEquals("hi", find(r.root(), "body"));
    }

    @Test
    void turboStreamsBroadcastWithSignedStreamName() throws Exception {
        String signed = TurboDecoderTest.signedJson("\"gid://app/Room/1:messages\"");
        String identifier = q("{\"channel\":\"Turbo::StreamsChannel\",\"signed_stream_name\":\"" + signed + "\"}");
        String stream = "<turbo-stream action=\"append\" target=\"messages\"><template><div id=\"message_9\">Hi</div></template></turbo-stream>";
        MessageContext m = server("{\"identifier\":" + identifier + ",\"message\":" + q(stream) + "}");
        assertEquals(95, cable.match(m).confidence());
        DecodeResult r = cable.decode(m);
        assertEquals("Action Cable broadcast on Turbo::StreamsChannel (gid://app/Room/1:messages): Turbo Stream append #messages", r.summary());
        String text = TreeText.render(r.root());
        assertTrue(text.contains("model Room, id 1"), text);
        assertTrue(text.contains("<div id=\\\"message_9\\\">Hi</div>") || text.contains("<div id=\"message_9\">Hi</div>"), text);

        MessageContext sub = client("{\"command\":\"subscribe\",\"identifier\":" + identifier + "}");
        assertEquals("Action Cable subscribe → Turbo::StreamsChannel (gid://app/Room/1:messages)", cable.decode(sub).summary());
    }

    @Test
    void marshalSignedStreamName() throws Exception {
        String signed = Base64.getEncoder().encodeToString(TurboDecoderTest.marshalString("gid://app/Room/2")) + "--" + "c".repeat(64);
        String identifier = q("{\"channel\":\"Turbo::StreamsChannel\",\"signed_stream_name\":\"" + signed + "\"}");
        DecodeResult r = cable.decode(client("{\"command\":\"subscribe\",\"identifier\":" + identifier + "}"));
        assertEquals("Action Cable subscribe → Turbo::StreamsChannel (gid://app/Room/2)", r.summary());
        assertTrue(TreeText.render(r.root()).contains("Ruby Marshal"));
    }

    @Test
    void anyCableExtendedFrames() throws Exception {
        MessageContext hist = client("{\"command\":\"history\",\"identifier\":" + CHAT_ID + ",\"history\":{\"since\":1795773600}}");
        assertEquals(95, cable.match(hist).confidence());
        assertEquals("Action Cable history → ChatChannel {room: 1}", cable.decode(hist).summary());
        MessageContext bc = server("{\"identifier\":" + CHAT_ID + ",\"message\":\"x\",\"stream_id\":\"s\",\"epoch\":\"e\",\"offset\":3}");
        assertEquals("Action Cable broadcast on ChatChannel {room: 1}", cable.decode(bc).summary());
    }

    @Test
    void frameShapeWithoutCablePath() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.WEBSOCKET).url("wss://app.example.com/ws")
                .webSocket("CLIENT_TO_SERVER", ("{\"command\":\"subscribe\",\"identifier\":" + CHAT_ID + "}").getBytes(StandardCharsets.UTF_8)).build();
        assertEquals(60, cable.match(m).confidence());
        assertEquals("Action Cable subscribe → ChatChannel {room: 1}", cable.decode(m).summary());
    }

    @Test
    void genericJsonWebSocketIsNotActionCable() {
        for (String p : new String[]{
                "{\"type\":\"ping\"}",                                   // graphql-transport-ws
                "{\"type\":\"connection_ack\"}",
                "{\"type\":\"welcome\",\"user\":\"bob\"}",
                "{\"event\":\"phx_join\",\"topic\":\"room:1\"}",
                "{\"command\":\"subscribe\",\"channel\":\"x\"}",          // no identifier
                "{\"identifier\":\"abc\",\"message\":1}",                 // identifier not JSON with channel
                "[1,2,3]", "hello"}) {
            MessageContext m = MessageContext.builder(MessageKind.WEBSOCKET).url("wss://other.example.com/socket")
                    .webSocket("SERVER_TO_CLIENT", p.getBytes(StandardCharsets.UTF_8)).build();
            assertEquals(0, cable.match(m).confidence(), p);
        }
        MessageContext http = MessageContext.builder(MessageKind.REQUEST).url("https://app.example.com/cable").build();
        assertEquals(0, cable.match(http).confidence());
    }

    @Test
    void forcedOnGarbage() throws Exception {
        assertThrows(DecodeException.class, () -> cable.decode(server("not json at all")));
        assertThrows(DecodeException.class, () -> cable.decode(server("")));
        assertThrows(DecodeException.class, () -> cable.decode(server("[1,2]")));
        MessageContext bin = MessageContext.builder(MessageKind.WEBSOCKET).url("wss://app.example.com/cable")
                .requestHeader("Sec-WebSocket-Protocol", "actioncable-v1-msgpack")
                .webSocket("SERVER_TO_CLIENT", new byte[]{(byte) 0x82, (byte) 0xa4, 't'}).build();
        assertEquals(40, cable.match(bin).confidence());
        DecodeException e = assertThrows(DecodeException.class, () -> cable.decode(bin));
        assertTrue(e.getMessage().contains("msgpack"), e.getMessage());
        // forced on an unrelated JSON object: decoded as JSON with a warning, never thrown
        DecodeResult r = cable.decode(server("{\"foo\":1}"));
        assertFalse(r.warnings().isEmpty());
        // bad identifier JSON
        DecodeResult bad = cable.decode(client("{\"command\":\"subscribe\",\"identifier\":\"{oops\"}"));
        assertTrue(bad.warnings().stream().anyMatch(w -> w.contains("identifier")), bad.warnings().toString());
    }
}
