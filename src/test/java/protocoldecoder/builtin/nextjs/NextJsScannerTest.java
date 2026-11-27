package protocoldecoder.builtin.nextjs;

import com.google.gson.JsonElement;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
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
import java.util.List;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;
import static protocoldecoder.builtin.nextjs.NextJsDecoderTest.ACTION_ID;
import static protocoldecoder.builtin.nextjs.NextJsDecoderTest.FLIGHT;
import static protocoldecoder.builtin.nextjs.NextJsDecoderTest.TREE;
import static protocoldecoder.builtin.nextjs.NextJsDecoderTest.enc;

class NextJsScannerTest {

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });

    /** Payload with quotes, JSON/URL/multipart delimiters, CRLF, a Flight-looking prefix and unicode. */
    static final String PAYLOAD = "a\"b'c\\d</x>&e=f%20;--g\r\n--h,[{}]:1 ü😀";

    @AfterEach
    void close() {
        app.close();
    }

    List<Finding> passive(MessageContext m, String checkId) {
        return app.scanEngine().passive(m, false).stream().filter(f -> f.checkId().equals(checkId)).toList();
    }

    static MessageContext rsc(String body) {
        return NextJsDecoderTest.rscResponse(body);
    }

    static MessageContext page(String html) {
        return MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://www.example.com/blog/hello")
                .statusCode(200).responseHeader("Content-Type", "text/html; charset=utf-8").responseBody(html).build();
    }

    static String nextDataPage(String data) {
        return "<!DOCTYPE html><html><body><div id=\"__next\"></div><script id=\"__NEXT_DATA__\" type=\"application/json\">" + data + "</script></body></html>";
    }

    // ------------------------------------------------------------------ sensitive data

    @Test
    void sensitiveDataInFlight() {
        String body = "0:{\"a\":\"$@1\",\"f\":\"\",\"b\":\"abc\"}\n"
                + "1:{\"ok\":true,\"sessionToken\":\"s3cr3tvalue\",\"user\":{\"email\":\"alice@example.com\"},\"db\":\"postgres://admin:pw@10.0.0.5/app\"}\n";
        List<Finding> f = passive(rsc(body), "nextjs.sensitive-data");
        assertEquals(1, f.size());
        assertEquals(Severity.LOW, f.get(0).severity());
        assertEquals(Confidence.TENTATIVE, f.get(0).confidence());
        String d = f.get(0).detail();
        assertTrue(d.contains("s3cr3tvalue") && d.contains("alice@example.com") && d.contains("postgres://admin:pw@10.0.0.5/app"), d);
    }

    @Test
    void benignFlightAndPageContentNotFlagged() {
        assertTrue(passive(rsc(FLIGHT), "nextjs.sensitive-data").isEmpty());
        String body = "0:[\"$\",\"p\",null,{\"children\":\"Contact support@example.com\",\"csrfToken\":\"abcdef123456\",\"role\":\"button\",\"token\":\"$undefined\"}]\n";
        assertTrue(passive(rsc(body), "nextjs.sensitive-data").isEmpty());
    }

    @Test
    void sensitiveDataInNextData() {
        String data = "{\"props\":{\"pageProps\":{\"user\":{\"id\":7,\"email\":\"alice@example.com\",\"password\":\"hunter22\"}}},\"page\":\"/u\",\"buildId\":\"b1\",\"gssp\":true}";
        List<Finding> f = passive(page(nextDataPage(data)), "nextjs.sensitive-data");
        assertEquals(1, f.size());
        assertEquals("Sensitive data in Next.js page data", f.get(0).title());
        assertTrue(f.get(0).detail().contains("hunter22"));
        // the URL query echoed into __NEXT_DATA__.query is not page data
        String echo = "{\"props\":{\"pageProps\":{}},\"page\":\"/r\",\"query\":{\"token\":\"abcdef123\"},\"buildId\":\"b1\"}";
        assertTrue(passive(page(nextDataPage(echo)), "nextjs.sensitive-data").isEmpty());
    }

    // ------------------------------------------------------------------ runtimeConfig

    @Test
    void runtimeConfig() {
        String secret = "{\"props\":{\"pageProps\":{}},\"page\":\"/\",\"buildId\":\"b1\",\"runtimeConfig\":{\"apiUrl\":\"https://api.example.com\",\"stripeSecretKey\":\"sk_test_123\"}}";
        List<Finding> f = passive(page(nextDataPage(secret)), "nextjs.public-runtime-config");
        assertEquals(1, f.size());
        assertEquals(Severity.LOW, f.get(0).severity());
        assertEquals(Finding.Scope.HOST, f.get(0).scope());
        assertTrue(f.get(0).detail().contains("stripeSecretKey = sk_test_123"));

        String pub = "{\"props\":{\"pageProps\":{}},\"page\":\"/\",\"buildId\":\"b1\",\"runtimeConfig\":{\"apiUrl\":\"https://api.example.com\",\"publicKey\":\"pk\"}}";
        f = passive(page(nextDataPage(pub)), "nextjs.public-runtime-config");
        assertEquals(Severity.INFORMATION, f.get(0).severity());

        String none = "{\"props\":{\"pageProps\":{}},\"page\":\"/\",\"buildId\":\"b1\",\"runtimeConfig\":{}}";
        assertTrue(passive(page(nextDataPage(none)), "nextjs.public-runtime-config").isEmpty());
    }

    // ------------------------------------------------------------------ server actions / errors

    @Test
    void serverActionIds() {
        List<Finding> f = passive(rsc(FLIGHT), "nextjs.server-actions");
        assertEquals(1, f.size());
        assertEquals(Finding.Scope.HOST, f.get(0).scope());
        assertTrue(f.get(0).detail().contains(ACTION_ID));
        assertTrue(passive(rsc("0:{\"b\":\"x\",\"p\":\"\"}\n"), "nextjs.server-actions").isEmpty());
    }

    @Test
    void rscErrors() {
        List<Finding> f = passive(rsc(FLIGHT), "nextjs.rsc-error");
        assertEquals(1, f.size());
        assertEquals(Severity.INFORMATION, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("2365098129"));

        String dev = "0:\"$L1\"\n1:E{\"digest\":\"\",\"message\":\"boom\",\"stack\":\"Error: boom\\n    at Page (webpack-internal:///./app/page.js:10:11)\"}\n";
        f = passive(rsc(dev), "nextjs.rsc-error");
        assertEquals(Severity.LOW, f.get(0).severity());
        assertEquals("Next.js server error with stack trace", f.get(0).title());

        assertTrue(passive(rsc("0:{\"b\":\"x\"}\n"), "nextjs.rsc-error").isEmpty());
    }

    @Test
    void nextDataErrWithStack() {
        String data = "{\"props\":{\"pageProps\":{}},\"page\":\"/_error\",\"buildId\":\"b1\",\"err\":{\"name\":\"TypeError\",\"message\":\"x is undefined\","
                + "\"stack\":\"TypeError: x is undefined\\n    at getServerSideProps (/app/.next/server/pages/index.js:1:200)\"}}";
        List<Finding> f = passive(page(nextDataPage(data)), "nextjs.rsc-error");
        assertEquals(1, f.size());
        assertEquals(Severity.LOW, f.get(0).severity());
    }

    // ------------------------------------------------------------------ subrequest header / dev server

    @Test
    void middlewareSubrequestHeaderSeen() {
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://app.example.com/admin")
                .requestHeader("x-middleware-subrequest", "middleware").build();
        assertEquals(1, passive(m, "nextjs.middleware-subrequest-header").size());
        MessageContext benign = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://app.example.com/admin")
                .requestHeader("RSC", "1").build();
        assertTrue(passive(benign, "nextjs.middleware-subrequest-header").isEmpty());
    }

    @Test
    void devServer() {
        MessageContext ws = MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("wss://app.example.com/_next/webpack-hmr")
                .webSocket("SERVER_TO_CLIENT", "{\"action\":\"built\",\"hash\":\"abc\"}".getBytes(StandardCharsets.UTF_8)).build();
        List<Finding> f = passive(ws, "nextjs.dev-server");
        assertEquals(1, f.size());
        assertEquals(Severity.MEDIUM, f.get(0).severity());

        String dev = "{\"props\":{\"pageProps\":{}},\"page\":\"/\",\"query\":{},\"buildId\":\"development\",\"nextExport\":true}";
        assertEquals(1, passive(page(nextDataPage(dev)), "nextjs.dev-server").size());

        String prod = "{\"props\":{\"pageProps\":{}},\"page\":\"/\",\"query\":{},\"buildId\":\"Zk3_9xq\"}";
        assertTrue(passive(page(nextDataPage(prod)), "nextjs.dev-server").isEmpty());
        assertTrue(passive(rsc(FLIGHT), "nextjs.dev-server").isEmpty());
    }

    // ------------------------------------------------------------------ active: CVE-2025-29927

    /** Records requests; answers with {@code responder(x-middleware-subrequest value)}. */
    static final class Fake implements HttpSender {
        final List<List<Header>> sent = new ArrayList<>();
        final Function<String, MessageContext.Builder> responder;

        Fake(Function<String, MessageContext.Builder> responder) {
            this.responder = responder;
        }

        @Override
        public Exchange send(String method, String pathAndQuery, List<Header> headers, byte[] body) {
            sent.add(headers);
            String v = null;
            for (Header h : headers) if (h.name().equalsIgnoreCase("x-middleware-subrequest")) v = h.value();
            MessageContext m = responder.apply(v).method(method).url("https://app.example.com" + pathAndQuery).requestHeaders(headers).build();
            return new Exchange(m, null);
        }

        @Override
        public Exchange send(InsertionPoint point, String payload) {
            throw new UnsupportedOperationException();
        }
    }

    static MessageContext.Builder redirectToLogin() {
        return MessageContext.builder(MessageKind.REQUEST).statusCode(307).responseHeader("Location", "/login?next=%2Fadmin").responseBody("");
    }

    static MessageContext.Builder adminPage() {
        return MessageContext.builder(MessageKind.REQUEST).statusCode(200).responseHeader("Content-Type", "text/html")
                .responseBody("<html><body><h1>Admin dashboard</h1><table>users…</table></body></html>");
    }

    static final MessageContext ADMIN_REQ = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://app.example.com/admin")
            .requestHeader("Host", "app.example.com").requestHeader("RSC", "1").build();
    static final MessageContext ADMIN_RESP = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://app.example.com/admin")
            .requestHeader("Host", "app.example.com").requestHeader("RSC", "1")
            .statusCode(307).responseHeader("Location", "/login?next=%2Fadmin").responseBody("").build();

    List<Finding> bypass(MessageContext resp, HttpSender http) {
        return app.scanEngine().active(ActiveCheck.Scope.PER_REQUEST, ADMIN_REQ, resp, null, null, null, http).stream()
                .filter(f -> f.checkId().equals("nextjs.middleware-bypass")).toList();
    }

    @Test
    void middlewareBypassDetectedAndConfirmed() {
        Fake http = new Fake(v -> NextJsScanner.BYPASS_VALUES[0].equals(v) ? adminPage() : redirectToLogin());
        List<Finding> f = bypass(ADMIN_RESP, http);
        assertEquals(1, f.size());
        assertEquals(Severity.HIGH, f.get(0).severity());
        assertEquals(Confidence.FIRM, f.get(0).confidence());
        assertEquals(2, http.sent.size(), "probe + control");
        assertEquals(2, f.get(0).exchanges().size());
    }

    @Test
    void middlewareBypassOnThirdValueIsTentative() {
        Fake http = new Fake(v -> "pages/_middleware".equals(v) ? adminPage() : redirectToLogin());
        List<Finding> f = bypass(ADMIN_RESP, http);
        assertEquals(1, f.size());
        assertEquals(Confidence.TENTATIVE, f.get(0).confidence());
        assertEquals(3, http.sent.size());
    }

    @Test
    void middlewareBypassNegatives() {
        Fake blocked = new Fake(v -> redirectToLogin());
        assertTrue(bypass(ADMIN_RESP, blocked).isEmpty());
        assertEquals(3, blocked.sent.size(), "bounded to 3 requests");

        Fake unstable = new Fake(v -> v == null ? redirectToLogin() : adminPage()); // control also flips
        assertTrue(bypass(ADMIN_RESP, unstable).isEmpty());

        Fake unused = new Fake(v -> adminPage());
        MessageContext ok = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://app.example.com/admin")
                .requestHeader("RSC", "1").statusCode(200).responseBody("<html>hi</html>").build();
        assertTrue(bypass(ok, unused).isEmpty());
        MessageContext otherRedirect = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://app.example.com/admin")
                .requestHeader("RSC", "1").statusCode(308).responseHeader("Location", "/admin/").responseBody("").build();
        assertTrue(bypass(otherRedirect, unused).isEmpty());
        assertTrue(unused.sent.isEmpty());
    }

    // ------------------------------------------------------------------ insertion points

    static DecodeResult decode(MessageContext m) throws Exception {
        return new NextJsDecoder().decode(m);
    }

    static MessageContext withBody(MessageContext m, byte[] body) {
        return MessageContext.builder(MessageKind.REQUEST).method(m.method()).url(m.url()).requestHeaders(m.requestHeaders()).requestBody(body).build();
    }

    static String find(DecodedNode n, String nameContains) {
        return NextJsDecoderTest.find(n, nameContains);
    }

    @Test
    void serverActionJsonArgsRoundTrip() throws Exception {
        String body = "[\"hello\",{\"qty\":2,\"note\":\"x\"},\"$undefined\"]";
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/cart")
                .requestHeader("Next-Action", ACTION_ID).requestHeader("Content-Type", "text/plain;charset=UTF-8").requestBody(body).build();
        List<InsertionPoint> ips = app.scanEngine().insertionPoints(m);
        List<String> names = ips.stream().map(InsertionPoint::name).toList();
        assertEquals(List.of("Next.js: Server Action 7f3a9c0e1d2b… args $[0]", "Next.js: Server Action 7f3a9c0e1d2b… args $[1].qty",
                "Next.js: Server Action 7f3a9c0e1d2b… args $[1].note"), names);
        InsertionPoint note = ips.get(2);
        assertEquals("x", note.baseValue());
        MessageContext mutated = withBody(m, note.render().apply(PAYLOAD));
        DecodeResult r = decode(mutated);
        assertEquals(PAYLOAD, r.root().get("Arguments (3)").get("arg 1").get("note").value());
        assertEquals("hello", r.root().get("Arguments (3)").get("arg 0").value());
        // '$'-prefixed payloads are escaped the way encodeReply does
        String dollar = new String(ips.get(0).render().apply("$1"), StandardCharsets.UTF_8);
        assertTrue(dollar.startsWith("[\"$$1\","), dollar);
    }

    @Test
    void noBodyPointsForApplicationJson() {
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/cart")
                .requestHeader("Next-Action", ACTION_ID).requestHeader("Content-Type", "application/json").requestBody("[\"a\"]").build();
        assertTrue(app.scanEngine().insertionPoints(m).stream().noneMatch(i -> i.part() == InsertionPoint.Part.BODY));
    }

    @Test
    void serverActionMultipartRoundTrip() throws Exception {
        String b = "----WebKitFormBoundaryX1";
        String body = "--" + b + "\r\nContent-Disposition: form-data; name=\"1_email\"\r\n\r\nbob@example.com\r\n"
                + "--" + b + "\r\nContent-Disposition: form-data; name=\"1_avatar\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nhi\r\n"
                + "--" + b + "\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n[\"$K1\",{\"coupon\":\"SAVE10\"}]\r\n"
                + "--" + b + "--\r\n";
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/signup")
                .requestHeader("Next-Action", ACTION_ID).requestHeader("Content-Type", "multipart/form-data; boundary=" + b)
                .requestBody(body).build();
        List<InsertionPoint> ips = app.scanEngine().insertionPoints(m);
        List<String> names = ips.stream().map(InsertionPoint::name).toList();
        assertEquals(List.of("Next.js: Server Action 7f3a9c0e1d2b… field 1_email", "Next.js: Server Action 7f3a9c0e1d2b… field 0 $[1].coupon"), names);

        MessageContext mutated = withBody(m, ips.get(0).render().apply(PAYLOAD));
        DecodedNode form = decode(mutated).root().get("Multipart fields (encodeReply / FormData)");
        assertEquals(PAYLOAD, form.get("1_email — FormData $K1 field \"email\"").value());
        assertEquals("a.txt", find(form, "Filename"));
        String raw = mutated.requestBodyText();
        assertTrue(raw.startsWith("--" + b + "\r\n") && raw.endsWith("--" + b + "--\r\n"), raw);
        assertTrue(raw.contains("[\"$K1\",{\"coupon\":\"SAVE10\"}]"), "other parts untouched");

        MessageContext mutated2 = withBody(m, ips.get(1).render().apply(PAYLOAD));
        List<Multipart.Part> parts = Multipart.parse(mutated2.requestBody(), m.requestHeader("Content-Type"));
        Multipart.Part zero = parts.stream().filter(p -> p.name().equals("0")).findFirst().orElseThrow();
        JsonElement j = com.google.gson.JsonParser.parseString(zero.text());
        assertEquals("$K1", j.getAsJsonArray().get(0).getAsString());
        assertEquals(PAYLOAD, j.getAsJsonArray().get(1).getAsJsonObject().get("coupon").getAsString());
        assertEquals("bob@example.com", parts.get(0).text());
    }

    @Test
    void progressiveEnhancementFormSkipsActionIdField() {
        String b = "XyZ";
        String body = "--" + b + "\r\nContent-Disposition: form-data; name=\"$ACTION_ID_" + ACTION_ID + "\"\r\n\r\n\r\n"
                + "--" + b + "\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--" + b + "--\r\n";
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/login")
                .requestHeader("Content-Type", "multipart/form-data; boundary=" + b).requestBody(body).build();
        List<String> names = app.scanEngine().insertionPoints(m).stream().map(InsertionPoint::name).toList();
        assertEquals(List.of("Next.js: Server Action field password"), names);
    }

    @Test
    void routerStateTreeHeaderRoundTrip() {
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://app.example.com/dashboard/42?_rsc=1x")
                .requestHeader("RSC", "1").requestHeader("Next-Router-State-Tree", enc(TREE)).build();
        List<InsertionPoint> ips = app.scanEngine().insertionPoints(m);
        assertTrue(ips.stream().allMatch(i -> i.part() == InsertionPoint.Part.HEADER && i.headerName().equals("Next-Router-State-Tree")));
        assertTrue(ips.stream().noneMatch(i -> i.baseValue().startsWith("__PAGE__")));
        InsertionPoint id = ips.stream().filter(i -> i.baseValue().equals("42")).findFirst().orElseThrow();
        assertEquals("Next.js: Next-Router-State-Tree $[1].children[1].children[0][1]", id.name());
        String header = new String(id.render().apply(PAYLOAD), StandardCharsets.UTF_8);
        assertFalse(header.contains("\r") || header.contains("\n") || header.contains("\""), "header-safe: " + header);
        JsonElement tree = RouterState.parse(header);
        assertNotNull(tree);
        assertEquals("/dashboard/[id=" + PAYLOAD + "]", RouterState.path(tree));
        // decoder still reads it as a Next.js request
        MessageContext mutated = MessageContext.builder(MessageKind.REQUEST).method("GET").url(m.url()).requestHeader("RSC", "1")
                .requestHeader("Next-Router-State-Tree", header).build();
        assertTrue(app.engine().decode(mutated).ok());
    }
}
