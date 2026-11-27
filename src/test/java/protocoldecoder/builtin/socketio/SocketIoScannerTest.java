package protocoldecoder.builtin.socketio;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.scan.ActiveCheck;
import protocoldecoder.scan.Exchange;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.HttpSender;
import protocoldecoder.scan.InsertionPoint;
import protocoldecoder.scan.Severity;
import protocoldecoder.util.TreeText;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

class SocketIoScannerTest {

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });
    final SocketIoDecoder decoder = new SocketIoDecoder();

    @AfterEach
    void close() {
        app.close();
    }

    static final String JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

    List<Finding> passive(MessageContext m, String checkId) {
        return app.scanEngine().passive(m, false).stream().filter(f -> f.checkId().equals(checkId)).toList();
    }

    static MessageContext ws(String dir, String text) {
        return SocketIoDecoderTest.ws(dir, text);
    }


    static boolean hasValue(protocoldecoder.core.DecodedNode n, String v) {
        if (v.equals(n.value())) return true;
        for (protocoldecoder.core.DecodedNode c : n.children()) if (hasValue(c, v)) return true;
        return false;
    }

    // ------------------------------------------------------------ passive

    @Test
    void sensitiveDataInServerEvent() {
        List<Finding> f = passive(ws("SERVER_TO_CLIENT", "42[\"user\",{\"name\":\"bob\",\"apiKey\":\"sk_live_51Habc123\"}]"), "socketio.sensitive-data");
        assertEquals(1, f.size());
        assertEquals(Severity.LOW, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("sk_live_51Habc123"), f.get(0).detail());
        // client → server: a typed password is not reported, a JWT is (Information)
        assertTrue(passive(ws("CLIENT_TO_SERVER", "42[\"login\",{\"password\":\"hunter22\"}]"), "socketio.sensitive-data").isEmpty());
        List<Finding> c = passive(ws("CLIENT_TO_SERVER", "421[\"subscribe\",\"" + JWT + "\"]"), "socketio.sensitive-data");
        assertEquals(Severity.INFORMATION, c.get(0).severity());
    }

    @Test
    void benignEventsAndAuthHandshakeNotReported() {
        assertTrue(passive(ws("SERVER_TO_CLIENT", "42[\"chat message\",{\"from\":\"bob\",\"text\":\"hi\"}]"), "socketio.sensitive-data").isEmpty());
        // the CONNECT auth payload legitimately carries a token
        assertTrue(passive(ws("CLIENT_TO_SERVER", "40{\"token\":\"abcdefgh12345\"}"), "socketio.sensitive-data").isEmpty());
    }

    @Test
    void errorDisclosureInAckAndConnectError() {
        String ack = "431[{\"error\":\"TypeError: Cannot read properties of undefined (reading 'id')\\n    at Socket.<anonymous> (/srv/app/handlers/chat.js:42:17)\\n    at Socket.emit (node:events:517:28)\"}]";
        List<Finding> f = passive(ws("SERVER_TO_CLIENT", ack), "socketio.error-disclosure");
        assertEquals(1, f.size(), f.toString());
        assertTrue(f.get(0).detail().contains("/srv/app/handlers/chat.js:42:17"), f.get(0).detail());
        MessageContext poll = SocketIoDecoderTest.pollResponse("4", "44{\"message\":\"java.lang.IllegalStateException: no user\\n\\tat com.acme.Auth.check(Auth.java:10)\"}");
        assertEquals(1, passive(poll, "socketio.error-disclosure").size());
    }

    @Test
    void plainErrorsNotReported() {
        assertTrue(passive(ws("SERVER_TO_CLIENT", "44{\"message\":\"Authentication error\"}"), "socketio.error-disclosure").isEmpty());
        // exception text sent by the client is not a server disclosure
        assertTrue(passive(ws("CLIENT_TO_SERVER", "42[\"log\",\"at Object.<anonymous> (/srv/x.js:1:2)\"]"), "socketio.error-disclosure").isEmpty());
    }

    @Test
    void pollingTransportEnabled() {
        MessageContext hs = SocketIoDecoderTest.pollResponse("4", "0{\"sid\":\"lv9p-xG5\",\"upgrades\":[\"websocket\"],\"pingInterval\":25000,\"pingTimeout\":20000,\"maxPayload\":1000000}");
        List<Finding> f = passive(hs, "socketio.polling-enabled");
        assertEquals(1, f.size());
        assertEquals(Finding.Scope.HOST, f.get(0).scope());
        assertTrue(f.get(0).detail().contains("alongside WebSocket"));
        // handshake over WebSocket (no polling) does not count
        assertTrue(passive(ws("SERVER_TO_CLIENT", "0{\"sid\":\"x\",\"upgrades\":[],\"pingInterval\":25000,\"pingTimeout\":20000}"), "socketio.polling-enabled").isEmpty());
        // ordinary polling payloads are not handshakes
        assertTrue(passive(SocketIoDecoderTest.pollResponse("4", "42[\"a\",1]"), "socketio.polling-enabled").isEmpty());
    }

    @Test
    void legacyProtocol() {
        String open = "0{\"sid\":\"abc\",\"upgrades\":[\"websocket\"],\"pingInterval\":25000,\"pingTimeout\":5000}";
        MessageContext v3 = SocketIoDecoderTest.pollResponse("3", open.length() + ":" + open + "2:40");
        List<Finding> f = passive(v3, "socketio.legacy-protocol");
        assertEquals(1, f.size());
        assertEquals(Severity.INFORMATION, f.get(0).severity());
        assertTrue(passive(SocketIoDecoderTest.pollResponse("4", "2"), "socketio.legacy-protocol").isEmpty());
        // a v4-only server refusing EIO=3 is not reported
        assertTrue(passive(SocketIoDecoderTest.pollResponse("3", "{\"code\":5,\"message\":\"Unsupported protocol version\"}"), "socketio.legacy-protocol").isEmpty());
    }

    // ------------------------------------------------------------ active

    static HttpSender sender(List<MessageContext> sent, Function<MessageContext, MessageContext.Builder> respond) {
        return new HttpSender() {
            @Override
            public Exchange send(String method, String pathAndQuery, List<Header> headers, byte[] body) {
                MessageContext req = MessageContext.builder(MessageKind.REQUEST).method(method).url("https://chat.example.com" + pathAndQuery)
                        .requestHeaders(headers).requestBody(body).build();
                sent.add(req);
                return new Exchange(respond.apply(req).build(), null);
            }

            @Override
            public Exchange send(InsertionPoint point, String payload) {
                throw new UnsupportedOperationException();
            }
        };
    }

    static MessageContext.Builder response(MessageContext req, String body, String... headers) {
        MessageContext.Builder b = MessageContext.builder(MessageKind.REQUEST).method(req.method()).url(req.url()).requestHeaders(req.requestHeaders())
                .statusCode(200).responseHeader("Content-Type", "text/plain; charset=UTF-8").responseBody(body);
        for (int i = 0; i < headers.length; i += 2) b.responseHeader(headers[i], headers[i + 1]);
        return b;
    }

    static final String OPEN = "0{\"sid\":\"q1\",\"upgrades\":[\"websocket\"],\"pingInterval\":25000,\"pingTimeout\":20000,\"maxPayload\":1000000}";

    MessageContext base() {
        return MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://chat.example.com/app/socket.io/?EIO=4&transport=polling&t=abc")
                .requestHeader("Cookie", "connect.sid=s%3Aabc").requestHeader("Origin", "https://chat.example.com").build();
    }

    @Test
    void crossOriginHandshakeReflected() {
        List<MessageContext> sent = new ArrayList<>();
        HttpSender http = sender(sent, req -> response(req, OPEN, "Access-Control-Allow-Origin", req.requestHeader("Origin"),
                "Access-Control-Allow-Credentials", "true"));
        List<Finding> f = app.scanEngine().active(ActiveCheck.Scope.PER_HOST, base(), null, null, null, null, http);
        assertEquals(1, sent.size());
        assertEquals("/app/socket.io/", sent.get(0).path());
        assertTrue(sent.get(0).query().startsWith("EIO=4&transport=polling"), sent.get(0).query());
        assertEquals(SocketIoScanner.FOREIGN_ORIGIN, sent.get(0).requestHeader("Origin"));
        assertEquals("connect.sid=s%3Aabc", sent.get(0).requestHeader("Cookie"));
        assertEquals(1, f.size());
        assertEquals(Severity.MEDIUM, f.get(0).severity());
        assertEquals(1, f.get(0).exchanges().size());
    }

    @Test
    void crossOriginHandshakeRestricted() {
        List<MessageContext> sent = new ArrayList<>();
        // no CORS headers for the foreign origin
        assertTrue(app.scanEngine().active(ActiveCheck.Scope.PER_HOST, base(), null, null, null, null, sender(sent, req -> response(req, OPEN))).isEmpty());
        // reflected but without credentials: not reported
        assertTrue(app.scanEngine().active(ActiveCheck.Scope.PER_HOST, base(), null, null, null, null,
                sender(sent, req -> response(req, OPEN, "Access-Control-Allow-Origin", req.requestHeader("Origin")))).isEmpty());
        // credentials allowed, but the handshake failed
        assertTrue(app.scanEngine().active(ActiveCheck.Scope.PER_HOST, base(), null, null, null, null,
                sender(sent, req -> response(req, "{\"code\":3,\"message\":\"Bad request\"}", "Access-Control-Allow-Origin", req.requestHeader("Origin"),
                        "Access-Control-Allow-Credentials", "true"))).isEmpty());
        assertEquals(3, sent.size());
    }

    // ------------------------------------------------------------ insertion points

    static MessageContext post(String eio, String body) {
        return SocketIoDecoderTest.pollRequest(eio, body);
    }

    List<InsertionPoint> points(MessageContext m) {
        return app.scanEngine().insertionPoints(m).stream().filter(i -> i.name().startsWith("Socket.IO:")).toList();
    }

    static final String NASTY = "x\"'<>\u001e12:4é€😀\\";

    DecodeResult decodeRendered(String eio, InsertionPoint ip, String payload) throws Exception {
        MessageContext m = post(eio, new String(ip.render().apply(payload), StandardCharsets.UTF_8));
        return decoder.decode(m);
    }

    @Test
    void v4InsertionPointsRoundTrip() throws Exception {
        String body = "42/admin,17[\"chat\",{\"text\":\"hi\",\"n\":3}]\u001e3\u001e431[\"ok\",{\"id\":7}]";
        List<InsertionPoint> ips = points(post("4", body));
        List<String> names = ips.stream().map(InsertionPoint::name).toList();
        assertEquals(List.of("Socket.IO: EVENT \"chat\" on /admin args[0].text (packet 1)", "Socket.IO: EVENT \"chat\" on /admin args[0].n (packet 1)",
                "Socket.IO: ACK 1 args[0] (packet 3)", "Socket.IO: ACK 1 args[1].id (packet 3)"), names);
        InsertionPoint text = ips.get(0);
        assertEquals("hi", text.baseValue());
        String rendered = new String(text.render().apply(NASTY), StandardCharsets.UTF_8);
        assertTrue(rendered.startsWith("42/admin,17[\"chat\",{\"text\":\"x\\\"'<>\\u001e12:4"), rendered);
        assertTrue(rendered.endsWith("\u001e3\u001e431[\"ok\",{\"id\":7}]"), rendered);
        DecodeResult r = decodeRendered("4", text, NASTY);
        assertEquals("Polling: 3 packets: EVENT, PONG, ACK", r.summary());
        assertTrue(hasValue(r.root(), NASTY), TreeText.render(r.root()));
        assertEquals("/admin", SocketIoDecoderTest.find(r.root(), "Namespace"));
        assertEquals("17", SocketIoDecoderTest.find(r.root(), "Ack ID"));
    }

    @Test
    void v3InsertionPointsRecomputeLengths() throws Exception {
        String body = "17:42[\"msg\",\"hello\"]1:213:42[\"x\",\"abc\"]";
        List<InsertionPoint> ips = points(post("3", body));
        assertEquals(2, ips.size(), ips.stream().map(InsertionPoint::name).toList().toString());
        InsertionPoint first = ips.get(0);
        assertEquals("Socket.IO: EVENT \"msg\" args[0] (packet 1)", first.name());
        String rendered = new String(first.render().apply(NASTY), StandardCharsets.UTF_8);
        String pkt = "42[\"msg\",\"x\\\"'<>\\u001e12:4é€😀\\\\\"]";
        assertEquals(pkt.length() + ":" + pkt + "1:213:42[\"x\",\"abc\"]", rendered);
        DecodeResult r = decodeRendered("3", first, NASTY);
        assertEquals("Polling: 3 packets: EVENT ×2, PING", r.summary());
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
        assertTrue(hasValue(r.root(), NASTY), TreeText.render(r.root()));
    }

    @Test
    void binaryEventKeepsAttachmentPlaceholders() throws Exception {
        String body = "451-[\"upload\",{\"name\":\"a.png\",\"file\":{\"_placeholder\":true,\"num\":0}}]";
        List<InsertionPoint> ips = points(post("4", body));
        assertEquals(List.of("Socket.IO: EVENT \"upload\" args[0].name"), ips.stream().map(InsertionPoint::name).toList());
        String rendered = new String(ips.get(0).render().apply("p\"q"), StandardCharsets.UTF_8);
        assertEquals("451-[\"upload\",{\"name\":\"p\\\"q\",\"file\":{\"_placeholder\":true,\"num\":0}}]", rendered);
    }

    @Test
    void noInsertionPointsForHandshakesAndGets() {
        assertTrue(points(post("4", "40{\"token\":\"abc\"}")).isEmpty());
        MessageContext get = MessageContext.builder(MessageKind.REQUEST).method("GET")
                .url("https://chat.example.com/socket.io/?EIO=4&transport=polling&sid=s1").build();
        assertTrue(points(get).isEmpty());
    }
}
