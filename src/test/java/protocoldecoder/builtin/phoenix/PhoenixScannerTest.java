package protocoldecoder.builtin.phoenix;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.builtin.phoenix.PhoenixDecoderTest.A;
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
import protocoldecoder.util.Codecs;
import protocoldecoder.util.TreeText;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;
import static protocoldecoder.builtin.phoenix.PhoenixDecoderTest.map;
import static protocoldecoder.builtin.phoenix.PhoenixDecoderTest.signedToken;

class PhoenixScannerTest {

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });
    final PhoenixDecoder decoder = new PhoenixDecoder();

    @AfterEach
    void close() {
        app.close();
    }

    static final String SOCKET = PhoenixDecoderTest.SOCKET;
    static final String LIVE = PhoenixDecoderTest.LIVE;
    static final String LIVE_NO_CSRF = "wss://app.example.com/live/websocket?vsn=2.0.0";

    List<Finding> passive(MessageContext m, String checkId) {
        return app.scanEngine().passive(m, false).stream().filter(f -> f.checkId().equals(checkId)).toList();
    }

    static MessageContext ws(String url, String dir, String text) {
        return PhoenixDecoderTest.ws(url, dir, text);
    }

    static MessageContext page(String html) {
        return MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://app.example.com/")
                .statusCode(200).responseHeader("Content-Type", "text/html").responseBody(html).build();
    }


    static boolean hasValue(protocoldecoder.core.DecodedNode n, String v) {
        if (v.equals(n.value())) return true;
        for (protocoldecoder.core.DecodedNode c : n.children()) if (hasValue(c, v)) return true;
        return false;
    }

    // ------------------------------------------------------------ passive: tokens

    @Test
    void sensitiveDataInSignedSessionToken() {
        String session = signedToken(map(new A("id"), "phx-F1", new A("session"), map("api_key", "ak_9f8e7d6c5b4a"),
                new A("view"), new A("Elixir.AppWeb.HomeLive")), 1_700_000_000_000L, 1209600);
        String html = "<div id=\"phx-F1\" data-phx-main data-phx-session=\"" + session + "\" data-phx-static=\"\"></div>";
        List<Finding> f = passive(page(html), "phoenix.readable-token-data");
        assertEquals(1, f.size());
        assertEquals(Severity.LOW, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("ak_9f8e7d6c5b4a"), f.get(0).detail());
    }

    @Test
    void benignSignedTokensNotReported() {
        String session = signedToken(map(new A("id"), "phx-F1", new A("session"), map("_csrf_token", "Q1NSRi10b2tlbg", "locale", "en"),
                new A("view"), new A("Elixir.AppWeb.HomeLive")), 1_700_000_000_000L, 1209600);
        String html = "<div id=\"phx-F1\" data-phx-main data-phx-session=\"" + session + "\" data-phx-static=\"\"></div>";
        assertTrue(passive(page(html), "phoenix.readable-token-data").isEmpty());
    }

    // ------------------------------------------------------------ passive: error replies

    @Test
    void errorReplyWithElixirException() {
        String reply = "[\"3\",\"3\",\"room:lobby\",\"phx_reply\",{\"status\":\"error\",\"response\":{\"reason\":\"** (Ecto.NoResultsError) expected at least one result but got none in query:\\n\\n    (my_app 0.1.0) lib/my_app/rooms.ex:12: MyApp.Rooms.get!/1\"}}]";
        List<Finding> f = passive(ws(SOCKET, "SERVER_TO_CLIENT", reply), "phoenix.error-details");
        assertEquals(1, f.size(), f.toString());
        assertTrue(f.get(0).detail().contains("Ecto.NoResultsError"), f.get(0).detail());
    }

    @Test
    void plainErrorRepliesNotReported() {
        assertTrue(passive(ws(SOCKET, "SERVER_TO_CLIENT", "[\"3\",\"3\",\"room:lobby\",\"phx_reply\",{\"status\":\"error\",\"response\":{\"reason\":\"unauthorized\"}}]"),
                "phoenix.error-details").isEmpty());
        // exception-looking text in an ok reply is not an error disclosure
        assertTrue(passive(ws(SOCKET, "SERVER_TO_CLIENT", "[\"3\",\"4\",\"room:lobby\",\"phx_reply\",{\"status\":\"ok\",\"response\":{\"body\":\"** (RuntimeError) is a fun error\"}}]"),
                "phoenix.error-details").isEmpty());
    }

    // ------------------------------------------------------------ passive: payloads

    @Test
    void sensitivePayloadInBroadcast() {
        String msg = "[null,null,\"room:lobby\",\"user_joined\",{\"user\":{\"name\":\"bob\",\"password_hash\":\"$2b$12$abcdefghijklmnopqrstuv\"}}]";
        List<Finding> f = passive(ws(SOCKET, "SERVER_TO_CLIENT", msg), "phoenix.sensitive-payload");
        assertEquals(1, f.size());
        assertEquals(Severity.LOW, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("password_hash"), f.get(0).detail());
    }

    @Test
    void benignPayloadsNotReported() {
        assertTrue(passive(ws(SOCKET, "SERVER_TO_CLIENT", "[null,null,\"room:lobby\",\"new_msg\",{\"body\":\"hi\",\"user\":\"bob\"}]"), "phoenix.sensitive-payload").isEmpty());
        // a login form typed by the user (client → server) is not reported
        String form = "[\"4\",\"6\",\"lv:phx-F1\",\"event\",{\"type\":\"form\",\"event\":\"login\",\"value\":\"user%5Bemail%5D=a%40b.c&user%5Bpassword%5D=hunter22\"}]";
        assertTrue(passive(ws(LIVE, "CLIENT_TO_SERVER", form), "phoenix.sensitive-payload").isEmpty());
        // join auth params are expected
        assertTrue(passive(ws(SOCKET, "CLIENT_TO_SERVER", "[\"3\",\"3\",\"room:lobby\",\"phx_join\",{\"token\":\"abcdef123456\"}]"), "phoenix.sensitive-payload").isEmpty());
    }

    // ------------------------------------------------------------ passive: LiveView CSRF

    @Test
    void liveViewJoinWithoutCsrf() {
        String join = "[\"4\",\"4\",\"lv:phx-F1\",\"phx_join\",{\"url\":\"https://app.example.com/\",\"params\":{\"_mounts\":0},\"session\":\"x\",\"static\":null}]";
        List<Finding> f = passive(ws(LIVE_NO_CSRF, "CLIENT_TO_SERVER", join), "phoenix.liveview-no-csrf");
        assertEquals(1, f.size());
        assertEquals(Severity.INFORMATION, f.get(0).severity());
        // token in the socket URL, or in the join params: fine
        assertTrue(passive(ws(LIVE, "CLIENT_TO_SERVER", join), "phoenix.liveview-no-csrf").isEmpty());
        String withToken = join.replace("{\"_mounts\":0}", "{\"_csrf_token\":\"xyz\",\"_mounts\":0}");
        assertTrue(passive(ws(LIVE_NO_CSRF, "CLIENT_TO_SERVER", withToken), "phoenix.liveview-no-csrf").isEmpty());
        // plain channel joins are not LiveView
        assertTrue(passive(ws(LIVE_NO_CSRF, "CLIENT_TO_SERVER", "[\"3\",\"3\",\"room:lobby\",\"phx_join\",{\"params\":{}}]"), "phoenix.liveview-no-csrf").isEmpty());
    }

    // ------------------------------------------------------------ active

    static HttpSender sender(List<MessageContext> sent, Function<MessageContext, MessageContext.Builder> respond) {
        return new HttpSender() {
            @Override
            public Exchange send(String method, String pathAndQuery, List<Header> headers, byte[] body) {
                MessageContext req = MessageContext.builder(MessageKind.REQUEST).method(method).url("https://app.example.com" + pathAndQuery)
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

    static MessageContext.Builder response(MessageContext req, int status, String body) {
        return MessageContext.builder(MessageKind.REQUEST).method(req.method()).url(req.url()).requestHeaders(req.requestHeaders())
                .statusCode(status).responseHeader("Content-Type", "application/json").responseBody(body);
    }

    static MessageContext wsBase() {
        return MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://app.example.com/live/websocket?_csrf_token=secret&vsn=2.0.0")
                .requestHeader("Cookie", "_app_key=SFMyNTY.abc").requestHeader("Origin", "https://app.example.com")
                .requestHeader("Upgrade", "websocket").build();
    }

    List<Finding> active(MessageContext base, HttpSender http) {
        // the base request must be one the Phoenix decoder applies to
        app.overrides().set(base, PhoenixDecoder.ID);
        return app.scanEngine().active(ActiveCheck.Scope.PER_HOST, base, null, null, null, null, http);
    }

    @Test
    void crossOriginLongPollAcceptedFromLiveViewPage() {
        String session = signedToken(map(new A("id"), "phx-F1"), 1_700_000_000_000L, 1209600);
        MessageContext pageExchange = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://app.example.com/dashboard")
                .requestHeader("Cookie", "_app_key=SFMyNTY.abc").statusCode(200).responseHeader("Content-Type", "text/html")
                .responseBody("<div id=\"phx-F1\" data-phx-main data-phx-session=\"" + session + "\"></div>").build();
        List<MessageContext> sent = new ArrayList<>();
        List<Finding> f = app.scanEngine().active(ActiveCheck.Scope.PER_HOST, pageExchange, pageExchange.withKind(MessageKind.RESPONSE), null, null, null,
                sender(sent, req -> response(req, 200, "{\"status\":410,\"token\":\"SFMyNTY.lp\",\"messages\":[]}")));
        assertEquals(1, sent.size());
        MessageContext probe = sent.get(0);
        assertEquals("/live/longpoll", probe.path());
        assertEquals("vsn=2.0.0", probe.query());
        assertEquals(PhoenixScanner.FOREIGN_ORIGIN, probe.requestHeader("Origin"));
        assertNull(probe.requestHeader("Upgrade"));
        assertEquals(1, f.size());
        assertEquals(Severity.MEDIUM, f.get(0).severity());
    }

    @Test
    void probeDropsAuthParams() {
        List<MessageContext> sent = new ArrayList<>();
        List<Finding> f = active(wsBase(), sender(sent, req -> response(req, 200, "{\"status\":410,\"token\":\"SFMyNTY.lp\",\"messages\":[]}")));
        assertEquals("/live/longpoll", sent.get(0).path());
        assertEquals("vsn=2.0.0", sent.get(0).query()); // _csrf_token dropped
        assertEquals(1, f.size());
    }

    @Test
    void crossOriginWebSocketFallback() {
        List<MessageContext> sent = new ArrayList<>();
        List<Finding> f = active(wsBase(), sender(sent, req -> req.path().endsWith("/longpoll") ? response(req, 404, "Not Found")
                : response(req, 101, "")));
        assertEquals(2, sent.size());
        assertEquals("/live/websocket", sent.get(1).path());
        assertEquals("websocket", sent.get(1).requestHeader("Upgrade"));
        assertEquals(1, f.size());
    }

    @Test
    void crossOriginRejected() {
        List<MessageContext> sent = new ArrayList<>();
        assertTrue(active(wsBase(), sender(sent, req -> response(req, 200, "{\"status\":403}"))).isEmpty());
        assertEquals(1, sent.size()); // check_origin answered: no WebSocket attempt
        sent.clear();
        assertTrue(active(wsBase(), sender(sent, req -> req.path().endsWith("/longpoll") ? response(req, 404, "") : response(req, 403, ""))).isEmpty());
        assertEquals(2, sent.size());
    }

    // ------------------------------------------------------------ insertion points

    static MessageContext longPollPost(String body) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/socket/longpoll?vsn=2.0.0&token=t2")
                .requestHeader("Content-Type", "application/x-ndjson").requestBody(body).build();
    }

    List<InsertionPoint> points(MessageContext m) {
        return app.scanEngine().insertionPoints(m).stream().filter(i -> i.name().startsWith("Phoenix:")).toList();
    }

    static final String NASTY = "x\"'<>\n\\]},é😀";

    @Test
    void ndjsonLongPollRoundTrip() throws Exception {
        String body = "[\"1\",\"2\",\"room:lobby\",\"new_msg\",{\"body\":\"a\",\"meta\":{\"n\":1}}]\n[null,\"3\",\"phoenix\",\"heartbeat\",{}]";
        List<InsertionPoint> ips = points(longPollPost(body));
        assertEquals(List.of("Phoenix: room:lobby new_msg payload.body", "Phoenix: room:lobby new_msg payload.meta.n"),
                ips.stream().map(InsertionPoint::name).toList());
        String rendered = new String(ips.get(0).render().apply(NASTY), StandardCharsets.UTF_8);
        assertTrue(rendered.endsWith("\n[null,\"3\",\"phoenix\",\"heartbeat\",{}]"), rendered);
        DecodeResult r = decoder.decode(longPollPost(rendered));
        assertEquals("Long poll send: 2 messages: new_msg, heartbeat", r.summary());
        assertTrue(hasValue(r.root(), NASTY), TreeText.render(r.root()));
    }

    @Test
    void singleV1MessageAndLiveViewFormFields() throws Exception {
        String v1 = "{\"topic\":\"room:lobby\",\"event\":\"new_msg\",\"payload\":{\"body\":\"a\"},\"ref\":\"5\"}";
        List<InsertionPoint> ips = points(longPollPost(v1));
        assertEquals(List.of("Phoenix: room:lobby new_msg payload.body"), ips.stream().map(InsertionPoint::name).toList());
        String v1Rendered = new String(ips.get(0).render().apply(NASTY), StandardCharsets.UTF_8);
        assertEquals(NASTY, PhoenixDecoderTest.find(decoder.decode(longPollPost(v1Rendered)).root(), "body"));

        String form = "[\"4\",\"6\",\"lv:phx-F1\",\"event\",{\"type\":\"form\",\"event\":\"save\",\"value\":\"user%5Bname%5D=bob&tags=a&tags=b\"}]";
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/live/longpoll?vsn=2.0.0&token=t")
                .requestBody(form).build();
        ips = points(m);
        List<String> names = ips.stream().map(InsertionPoint::name).toList();
        assertTrue(names.contains("Phoenix: lv:phx-F1 event payload.value form field user[name]"), names.toString());
        assertFalse(names.contains("Phoenix: lv:phx-F1 event payload.value"), names.toString());
        InsertionPoint secondTag = ips.stream().filter(i -> i.name().endsWith("form field tags") && i.baseValue().equals("b")).findFirst().orElseThrow();
        String rendered = new String(secondTag.render().apply("x&y=\"z"), StandardCharsets.UTF_8);
        MessageContext again = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/live/longpoll?vsn=2.0.0&token=t")
                .requestBody(rendered).build();
        String value = PhoenixDecoderTest.find(decoder.decode(again).root(), "value (raw)");
        assertEquals(List.of("a", "x&y=\"z"), Codecs.parseQuery(value).get("tags"));
        assertEquals("bob", Codecs.first(Codecs.parseQuery(value), "user[name]"));
    }

    @Test
    void noInsertionPointsOutsideLongPollSends() {
        assertTrue(points(MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://app.example.com/socket/longpoll?vsn=2.0.0&token=t2").build()).isEmpty());
        assertTrue(points(MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/api/messages")
                .requestBody("[\"1\",\"2\",\"room:lobby\",\"new_msg\",{\"body\":\"a\"}]").build()).isEmpty());
    }
}
