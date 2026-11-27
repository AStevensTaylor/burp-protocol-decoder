package protocoldecoder.builtin.turbo;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.scan.ActiveCheck;
import protocoldecoder.scan.Confidence;
import protocoldecoder.scan.Exchange;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.HttpSender;
import protocoldecoder.scan.InsertionPoint;
import protocoldecoder.scan.Severity;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static protocoldecoder.builtin.turbo.TurboDecoderTest.marshalString;
import static protocoldecoder.builtin.turbo.TurboDecoderTest.signedJson;

class TurboScannerTest {

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });

    @AfterEach
    void close() {
        app.close();
    }

    List<Finding> passive(MessageContext m, String checkId) {
        return app.scanEngine().passive(m, false).stream().filter(f -> f.checkId().equals(checkId)).toList();
    }

    static String sourcePage(String token, String extraHead) {
        return "<html><head>" + extraHead + "<meta name=\"turbo-refresh-method\" content=\"morph\"></head><body>"
                + "<turbo-cable-stream-source channel=\"Turbo::StreamsChannel\" signed-stream-name=\"" + token + "\"></turbo-cable-stream-source>"
                + "<div id=\"messages\"></div></body></html>";
    }

    static MessageContext page(String html, String cookie) {
        MessageContext.Builder b = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://app.example.com/rooms/1")
                .requestHeader("Host", "app.example.com");
        if (cookie != null) b.requestHeader("Cookie", cookie);
        return b.statusCode(200).responseHeader("Content-Type", "text/html; charset=utf-8").responseBody(html).build();
    }

    static String marshalToken(String s) {
        return Base64.getEncoder().encodeToString(marshalString(s)) + "--" + "b".repeat(40);
    }

    // ------------------------------------------------------------ signed stream names

    @Test
    void globalIdsInSignedStreamNames() {
        List<Finding> f = passive(page(sourcePage(signedJson("\"gid://app/Room/1:messages\""), ""), null), "turbo.signed-stream-gid");
        assertEquals(1, f.size());
        assertEquals(Severity.INFORMATION, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("gid://app/Room/1"), f.get(0).detail());
        assertTrue(f.get(0).detail().contains("model Room, id 1"), f.get(0).detail());
        // a stream name without GlobalIDs
        assertTrue(passive(page(sourcePage(signedJson("\"notifications\""), ""), null), "turbo.signed-stream-gid").isEmpty());
    }

    @Test
    void marshalSignedStreamName() {
        List<Finding> f = passive(page(sourcePage(marshalToken("gid://shop/Admin::Order/77:items"), ""), null), "turbo.signed-stream-marshal");
        assertEquals(1, f.size());
        assertEquals(Severity.LOW, f.get(0).severity());
        assertEquals(Confidence.TENTATIVE, f.get(0).confidence());
        assertTrue(passive(page(sourcePage(signedJson("\"gid://app/Room/1\""), ""), null), "turbo.signed-stream-marshal").isEmpty());
    }

    // ------------------------------------------------------------ scripts in stream templates

    static MessageContext stream(String body) {
        return MessageContext.builder(MessageKind.RESPONSE).method("POST").url("https://app.example.com/messages")
                .statusCode(200).responseHeader("Content-Type", "text/vnd.turbo-stream.html").responseBody(body).build();
    }

    @Test
    void scriptInStreamTemplate() {
        List<Finding> f = passive(stream("<turbo-stream action=\"append\" target=\"messages\"><template><div>hi</div>"
                + "<script>track('x')</script></template></turbo-stream>"), "turbo.stream-script");
        assertEquals(1, f.size());
        assertTrue(f.get(0).detail().contains("append #messages"), f.get(0).detail());
        assertTrue(passive(stream("<turbo-stream action=\"replace\" target=\"m\"><template><p>no scripts here</p></template></turbo-stream>"),
                "turbo.stream-script").isEmpty());
    }

    // ------------------------------------------------------------ active: cross-origin cable

    static final class Fake implements HttpSender {
        final List<String> paths = new ArrayList<>();
        final List<List<Header>> headers = new ArrayList<>();
        final int status;

        Fake(int status) {
            this.status = status;
        }

        @Override
        public Exchange send(String method, String pathAndQuery, List<Header> h, byte[] body) {
            paths.add(pathAndQuery);
            headers.add(h);
            MessageContext.Builder b = MessageContext.builder(MessageKind.REQUEST).method(method).url("https://app.example.com" + pathAndQuery)
                    .requestHeaders(h).statusCode(status);
            if (status == 101) b.responseHeader("Upgrade", "websocket").responseHeader("Sec-WebSocket-Protocol", "actioncable-v1-json");
            return new Exchange(b.responseBody(status == 404 ? "Page not found" : "").build(), null);
        }

        @Override
        public Exchange send(InsertionPoint point, String payload) {
            throw new UnsupportedOperationException();
        }

        String header(int i, String name) {
            for (Header x : headers.get(i)) if (x.name().equalsIgnoreCase(name)) return x.value();
            return null;
        }
    }

    List<Finding> active(MessageContext resp, HttpSender http) {
        MessageContext req = resp.withKind(MessageKind.REQUEST);
        return app.scanEngine().active(ActiveCheck.Scope.PER_REQUEST, req, resp, null, null, null, http).stream()
                .filter(f -> f.checkId().equals("turbo.cable-cross-origin")).toList();
    }

    @Test
    void crossOriginCableAccepted() {
        Fake http = new Fake(101);
        MessageContext p = page(sourcePage(signedJson("\"gid://app/Room/1\""), ""), "_app_session=abc123");
        List<Finding> f = active(p, http);
        assertEquals(1, f.size());
        assertEquals(Severity.MEDIUM, f.get(0).severity());
        assertEquals(Confidence.TENTATIVE, f.get(0).confidence());
        assertEquals(Finding.Scope.HOST, f.get(0).scope());
        assertEquals(List.of("/cable"), http.paths);
        assertEquals("https://evil.example", http.header(0, "Origin"));
        assertEquals("_app_session=abc123", http.header(0, "Cookie"));
        assertEquals("websocket", http.header(0, "Upgrade"));
        assertNotNull(http.header(0, "Sec-WebSocket-Key"));
        // once per host
        assertTrue(active(p, http).isEmpty());
        assertEquals(1, http.paths.size());
    }

    @Test
    void crossOriginCableRejectedOrNotUsed() {
        Fake rejects = new Fake(404);
        assertTrue(active(page(sourcePage(signedJson("\"gid://app/Room/1\""), ""), "s=1"), rejects).isEmpty());
        assertEquals(1, rejects.paths.size());

        Fake unused = new Fake(101);
        assertTrue(active(page("<html><body><turbo-frame id=\"x\"></turbo-frame></body></html>", "s=1"), unused).isEmpty());
        assertTrue(unused.paths.isEmpty(), "no cable on the page: nothing sent");
    }

    @Test
    void cableUrlFromMetaTag() {
        Fake http = new Fake(404);
        active(page(sourcePage(signedJson("\"x\""), "<meta name=\"action-cable-url\" content=\"/ws/cable?v=2\">"), null), http);
        assertEquals(List.of("/ws/cable?v=2"), http.paths);

        Fake other = new Fake(101);
        App fresh = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });
        try {
            MessageContext p = page(sourcePage(signedJson("\"x\""), "<meta name=\"action-cable-url\" content=\"wss://cable.thirdparty.example/cable\">"), null);
            fresh.scanEngine().active(ActiveCheck.Scope.PER_REQUEST, p.withKind(MessageKind.REQUEST), p, null, null, null, other);
            assertTrue(other.paths.isEmpty(), "cable on another host is out of scope");
        } finally {
            fresh.close();
        }
    }

    @Test
    void noInsertionPoints() {
        MessageContext req = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/messages")
                .requestHeader("Accept", "text/vnd.turbo-stream.html, text/html").requestHeader("Content-Type", "application/x-www-form-urlencoded")
                .requestBody("message%5Bbody%5D=hi".getBytes(StandardCharsets.UTF_8)).build();
        assertTrue(app.scanEngine().insertionPoints(req).isEmpty());
    }
}
