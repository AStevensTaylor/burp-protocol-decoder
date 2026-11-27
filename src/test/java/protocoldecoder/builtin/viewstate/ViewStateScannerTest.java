package protocoldecoder.builtin.viewstate;

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
import protocoldecoder.scan.Confidence;
import protocoldecoder.scan.Exchange;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.HttpSender;
import protocoldecoder.scan.InsertionPoint;
import protocoldecoder.scan.Severity;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.TreeText;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;
import static protocoldecoder.builtin.viewstate.ViewStateDecoderTest.Osf;
import static protocoldecoder.builtin.viewstate.ViewStateDecoderTest.b64;
import static protocoldecoder.builtin.viewstate.ViewStateDecoderTest.enc;
import static protocoldecoder.builtin.viewstate.ViewStateDecoderTest.eventValidation;
import static protocoldecoder.builtin.viewstate.ViewStateDecoderTest.page;
import static protocoldecoder.builtin.viewstate.ViewStateDecoderTest.post;

class ViewStateScannerTest {

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });
    final ViewStateDecoder decoder = new ViewStateDecoder();

    @AfterEach
    void close() {
        app.close();
    }

    List<Finding> passive(MessageContext m, String checkId) {
        return app.scanEngine().passive(m, false).stream().filter(f -> f.checkId().equals(checkId)).toList();
    }

    static MessageContext postVs(byte[] state, String extra) {
        return post("__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=" + enc(b64(state)) + "&__VIEWSTATEGENERATOR=CA0B0334" + extra + "&ctl00%24txtName=bob");
    }

    static byte[] withBlob() {
        ByteArrayOutputStream nrbf = new ByteArrayOutputStream();
        nrbf.writeBytes(new byte[]{0x00, 0x01, 0, 0, 0, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x01, 0, 0, 0, 0, 0, 0, 0});
        String cls = "System.Windows.Data.ObjectDataProvider";
        nrbf.write(cls.length());
        nrbf.writeBytes(cls.getBytes(StandardCharsets.US_ASCII));
        nrbf.write(0x0B);
        byte[] blob = nrbf.toByteArray();
        return new Osf().pair().str("x").tok(0x32).enc(blob.length).bytes(blob).build();
    }

    // ------------------------------------------------------------ passive

    @Test
    void noMacOnRequestAndResponse() {
        List<Finding> f = passive(postVs(page().build(), ""), "viewstate.no-mac");
        assertEquals(1, f.size());
        assertEquals(Severity.HIGH, f.get(0).severity());
        assertEquals(Confidence.FIRM, f.get(0).confidence());
        assertEquals(Finding.Scope.HOST, f.get(0).scope());
        assertTrue(f.get(0).detail().contains("not yet confirmed"), f.get(0).detail());

        String html = "<form><input type=\"hidden\" name=\"__VIEWSTATE\" id=\"__VIEWSTATE\" value=\"" + b64(page().build()) + "\" /></form>";
        MessageContext resp = ViewStateDecoderTest.response(html, "text/html");
        assertEquals(1, passive(resp, "viewstate.no-mac").size());
    }

    @Test
    void noMacNegatives() {
        assertTrue(passive(postVs(page().withMac(32), ""), "viewstate.no-mac").isEmpty());
        // Truncated (partial parse) is not "no MAC".
        byte[] full = page().build();
        assertTrue(passive(postVs(Arrays.copyOf(full, full.length - 3), ""), "viewstate.no-mac").isEmpty());
        byte[] random = new byte[160];
        new Random(1).nextBytes(random);
        random[0] = 0x3c;
        assertTrue(passive(postVs(random, "&__VIEWSTATEENCRYPTED="), "viewstate.no-mac").isEmpty());
    }

    @Test
    void weakMac() {
        List<Finding> f = passive(postVs(page().withMac(20), ""), "viewstate.weak-mac");
        assertEquals(1, f.size());
        assertEquals(Severity.LOW, f.get(0).severity());
        assertEquals(Confidence.TENTATIVE, f.get(0).confidence());
        assertTrue(f.get(0).detail().contains("HMACSHA1"));
        assertTrue(passive(postVs(page().withMac(16), ""), "viewstate.weak-mac").get(0).detail().contains("MD5"));
        assertTrue(passive(postVs(page().withMac(32), ""), "viewstate.weak-mac").isEmpty());
        assertTrue(passive(postVs(page().withMac(64), ""), "viewstate.weak-mac").isEmpty());
        assertTrue(passive(postVs(page().build(), ""), "viewstate.weak-mac").isEmpty());
    }

    @Test
    void eventValidationNoMac() {
        MessageContext m = postVs(page().withMac(32), "&__EVENTVALIDATION=" + enc(b64(eventValidation(2, 0))));
        List<Finding> f = passive(m, "viewstate.eventvalidation-no-mac");
        assertEquals(1, f.size());
        assertEquals(Severity.MEDIUM, f.get(0).severity());
        // With MAC: nothing.
        assertTrue(passive(postVs(page().withMac(32), "&__EVENTVALIDATION=" + enc(b64(eventValidation(2, 32)))),
                "viewstate.eventvalidation-no-mac").isEmpty());
        // ViewState also without MAC: only viewstate.no-mac is reported.
        MessageContext both = postVs(page().build(), "&__EVENTVALIDATION=" + enc(b64(eventValidation(2, 0))));
        assertTrue(passive(both, "viewstate.eventvalidation-no-mac").isEmpty());
        assertEquals(1, passive(both, "viewstate.no-mac").size());
    }

    @Test
    void binarySerialized() {
        List<Finding> f = passive(postVs(withBlob(), ""), "viewstate.binary-serialized");
        assertEquals(1, f.size());
        assertEquals(Severity.MEDIUM, f.get(0).severity());
        assertEquals(Confidence.TENTATIVE, f.get(0).confidence());
        assertTrue(f.get(0).detail().contains("ObjectDataProvider"), f.get(0).detail());
        // MAC-protected: still a sink but needs the key.
        byte[] withMac = Arrays.copyOf(withBlob(), withBlob().length + 32);
        assertEquals(Severity.LOW, passive(postVs(withMac, ""), "viewstate.binary-serialized").get(0).severity());
        assertTrue(passive(postVs(page().build(), ""), "viewstate.binary-serialized").isEmpty());
    }

    @Test
    void sensitiveData() {
        byte[] state = new Osf().pair().str("-1234567890").list(3).str("alice@example.com").str("4111 1111 1111 1111").str("plain").withMac(32);
        List<Finding> f = passive(postVs(state, ""), "viewstate.sensitive-data");
        assertEquals(1, f.size());
        assertEquals(Severity.LOW, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("alice@example.com") && f.get(0).detail().contains("payment card"), f.get(0).detail());
        assertTrue(passive(postVs(page().withMac(32), ""), "viewstate.sensitive-data").isEmpty());
    }

    @Test
    void queryString() {
        MessageContext get = MessageContext.builder(MessageKind.REQUEST).method("GET")
                .url("https://shop.example.com/Search.aspx?__VIEWSTATE=" + enc(b64(page().withMac(32))) + "&q=shoes").build();
        List<Finding> f = passive(get, "viewstate.in-query-string");
        assertEquals(1, f.size());
        assertEquals(Severity.LOW, f.get(0).severity());
        assertTrue(passive(postVs(page().withMac(32), ""), "viewstate.in-query-string").isEmpty());
    }

    @Test
    void largeViewState() {
        byte[] big = new Osf().pair().str("x".repeat(80_000)).nul().withMac(32);
        List<Finding> f = passive(postVs(big, ""), "viewstate.large");
        assertEquals(1, f.size());
        assertEquals(Severity.INFORMATION, f.get(0).severity());
        assertTrue(passive(postVs(page().withMac(32), ""), "viewstate.large").isEmpty());
    }

    // ------------------------------------------------------------ insertion points

    static final String PAYLOAD = "x'\"<script>&=|;%+/= 日本 😀 \\ \u0000" + "A".repeat(200);

    List<InsertionPoint> vsPoints(MessageContext m) {
        return app.scanEngine().insertionPoints(m).stream().filter(i -> i.name().startsWith("ViewState:")).toList();
    }

    @Test
    void insertionPointsRoundTrip() throws Exception {
        MessageContext m = postVs(page().build(), "");
        List<InsertionPoint> ips = vsPoints(m);
        List<String> names = ips.stream().map(InsertionPoint::name).toList();
        // Strings: "Text" (indexed add), "hello", "again", hybrid dictionary key; the page type hash is skipped.
        assertEquals(4, ips.size(), names.toString());
        assertTrue(names.contains("ViewState: __VIEWSTATE Root › First › Second › Second › [1] › First › First › [1]"), names.toString());
        assertTrue(names.stream().noneMatch(n -> n.endsWith("Root › First › First")), names.toString());
        InsertionPoint hello = ips.stream().filter(i -> i.baseValue().equals("hello")).findFirst().orElseThrow();
        assertEquals(InsertionPoint.Part.BODY, hello.part());

        String newBody = new String(hello.render().apply(PAYLOAD), StandardCharsets.ISO_8859_1);
        assertTrue(newBody.startsWith("__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE="), newBody);
        assertTrue(newBody.endsWith("&__VIEWSTATEGENERATOR=CA0B0334&ctl00%24txtName=bob"), newBody);
        String vs = Codecs.first(Codecs.parseQuery(newBody), "__VIEWSTATE");
        byte[] bytes = Codecs.base64Decode(vs);
        ObjectStateReader.Spans spans = ObjectStateReader.spans(bytes);
        assertTrue(spans.complete());
        assertEquals(bytes.length, spans.end(), "no trailing bytes after the re-serialised graph");
        assertTrue(spans.spans().stream().anyMatch(s -> s.value().equals(PAYLOAD)));
        assertEquals("again", spans.spans().stream().filter(s -> s.path().endsWith("[3]")).findFirst().orElseThrow().value());

        DecodeResult r = decoder.decode(post(newBody));
        assertTrue(r.summary().endsWith("no MAC ⚠"), r.summary() + r.warnings());
        assertTrue(r.warnings().stream().noneMatch(w -> w.contains("parse stopped")), r.warnings().toString());
        // The indexed string table entry ("Text") can be replaced too and its back-reference follows it.
        InsertionPoint text = ips.stream().filter(i -> i.baseValue().equals("Text")).findFirst().orElseThrow();
        DecodeResult r2 = decoder.decode(post(new String(text.render().apply("T\"|x"), StandardCharsets.ISO_8859_1)));
        String tree = TreeText.render(r2.root());
        assertTrue(tree.contains("T\\\"|x"), tree);
        assertTrue(r2.root().get("ViewState").get("String table (1)").children().get(0).value().equals("T\"|x"));
    }

    @Test
    void splitViewStateIsCollapsed() throws Exception {
        String full = b64(page().build());
        int a = full.length() / 3, b = 2 * full.length() / 3;
        String body = "__VIEWSTATEFIELDCOUNT=3&__VIEWSTATE=" + enc(full.substring(0, a)) + "&__VIEWSTATE1=" + enc(full.substring(a, b))
                + "&__VIEWSTATE2=" + enc(full.substring(b)) + "&btn=Go";
        List<InsertionPoint> ips = vsPoints(post(body));
        assertEquals(4, ips.size());
        String newBody = new String(ips.get(1).render().apply(PAYLOAD), StandardCharsets.ISO_8859_1);
        assertFalse(newBody.contains("__VIEWSTATE1") || newBody.contains("__VIEWSTATE2") || newBody.contains("__VIEWSTATEFIELDCOUNT"), newBody);
        assertTrue(newBody.endsWith("&btn=Go"));
        DecodeResult r = decoder.decode(post(newBody));
        assertTrue(TreeText.render(r.root()).contains("日本 😀"), TreeText.render(r.root()));
        assertTrue(r.summary().endsWith("no MAC ⚠"), r.summary());
    }

    @Test
    void queryStringInsertionPoint() throws Exception {
        MessageContext get = MessageContext.builder(MessageKind.REQUEST).method("GET")
                .url("https://shop.example.com/Search.aspx?q=shoes&__VIEWSTATE=" + enc(b64(page().build()))).build();
        InsertionPoint ip = vsPoints(get).get(0);
        assertEquals(InsertionPoint.Part.QUERY, ip.part());
        String q = new String(ip.render().apply(PAYLOAD), StandardCharsets.ISO_8859_1);
        assertTrue(q.startsWith("q=shoes&__VIEWSTATE="), q);
        byte[] bytes = Codecs.base64Decode(Codecs.first(Codecs.parseQuery(q), "__VIEWSTATE"));
        assertTrue(ObjectStateReader.spans(bytes).spans().stream().anyMatch(s -> s.value().equals(PAYLOAD)));
    }

    @Test
    void noInsertionPointsWhenMacOrEncrypted() {
        assertTrue(vsPoints(postVs(page().withMac(32), "")).isEmpty());
        assertTrue(vsPoints(postVs(page().withMac(20), "")).isEmpty());
        byte[] random = new byte[96];
        new Random(3).nextBytes(random);
        assertTrue(vsPoints(postVs(random, "")).isEmpty());
        assertTrue(vsPoints(post("__VIEWSTATE=%25%25")).isEmpty());
    }

    @Test
    void writerEncodesLongLengths() {
        byte[] orig = new Osf().pair().str("a").str("b").build();
        ObjectStateReader.Spans sp = ObjectStateReader.spans(orig);
        String big = "é".repeat(10_000); // 20,000 bytes → 3-byte 7-bit length
        byte[] out = ObjectStateWriter.replace(orig, sp.spans().get(0), big);
        ObjectStateReader.Spans again = ObjectStateReader.spans(out);
        assertTrue(again.complete());
        assertEquals(out.length, again.end());
        assertEquals(big, again.spans().get(0).value());
        assertEquals("b", again.spans().get(1).value());
    }

    // ------------------------------------------------------------ active

    static final class FakeSender implements HttpSender {
        final List<String> bodies = new ArrayList<>();
        final Function<String, MessageContext.Builder> reply;

        FakeSender(Function<String, MessageContext.Builder> reply) {
            this.reply = reply;
        }

        @Override
        public Exchange send(String method, String pathAndQuery, List<Header> headers, byte[] body) {
            String b = new String(body, StandardCharsets.ISO_8859_1);
            bodies.add(b);
            MessageContext m = reply.apply(b).method(method).url("https://shop.example.com" + pathAndQuery).requestBody(body).build();
            return new Exchange(m, null);
        }

        @Override
        public Exchange send(InsertionPoint point, String payload) {
            throw new UnsupportedOperationException();
        }
    }

    static MessageContext.Builder html(int status, String body) {
        return MessageContext.builder(MessageKind.REQUEST).statusCode(status).responseHeader("Content-Type", "text/html").responseBody(body);
    }

    static final String PAGE = "<html><body><form>" + "<p>Order list</p>".repeat(50) + "</form></body></html>";

    static MessageContext baseResponse(MessageContext req, int status, String body) {
        return MessageContext.builder(MessageKind.RESPONSE).method(req.method()).url(req.url()).requestHeaders(req.requestHeaders())
                .requestBody(req.requestBody()).statusCode(status).responseHeader("Content-Type", "text/html").responseBody(body).build();
    }

    List<Finding> active(MessageContext base, MessageContext resp, HttpSender http) {
        return app.scanEngine().active(ActiveCheck.Scope.PER_REQUEST, base, resp, null, null, null, http).stream()
                .filter(f -> f.checkId().equals("viewstate.mac-validation")).toList();
    }

    @Test
    void macNotEnforced() {
        byte[] state = page().withMac(32);
        MessageContext base = postVs(state, "");
        FakeSender http = new FakeSender(b -> html(200, PAGE));
        List<Finding> f = active(base, baseResponse(base, 200, PAGE), http);
        assertEquals(1, http.bodies.size());
        byte[] sent = Codecs.base64Decode(Codecs.first(Codecs.parseQuery(http.bodies.get(0)), "__VIEWSTATE"));
        assertEquals(state.length, sent.length);
        int diffs = 0, at = -1;
        for (int i = 0; i < sent.length; i++) if (sent[i] != state[i]) { diffs++; at = i; }
        assertEquals(1, diffs);
        assertEquals(state.length - 32, at, "only the first MAC byte is changed");
        assertEquals(1, f.size());
        assertEquals("ASP.NET ViewState MAC not enforced", f.get(0).title());
        assertEquals(Severity.HIGH, f.get(0).severity());
        assertEquals(Finding.Scope.HOST, f.get(0).scope());
        assertEquals(1, f.get(0).exchanges().size());
        // Once confirmed for a host, later pages are not probed again.
        active(base, baseResponse(base, 200, PAGE), http);
        assertEquals(1, http.bodies.size());
    }

    @Test
    void macEnforcedWithDetailedError() {
        MessageContext base = postVs(page().withMac(32), "");
        String err = "<h2><i>Validation of viewstate MAC failed.</i></h2><b>Exception Details: </b>System.Web.HttpException: Validation of viewstate MAC failed."
                + "<br>[HttpException]: at System.Web.UI.ViewStateException.ThrowError(Exception inner, String persistedState)";
        FakeSender http = new FakeSender(b -> html(500, err));
        List<Finding> f = active(base, baseResponse(base, 200, PAGE), http);
        assertEquals(1, f.size());
        assertEquals("ASP.NET ViewState error discloses exception details", f.get(0).title());
        assertEquals(Severity.LOW, f.get(0).severity());
    }

    @Test
    void macEnforcedGenericErrorAndRedirects() {
        MessageContext base = postVs(page().withMac(32), "");
        // Generic 200 error page mentioning invalid state.
        assertTrue(active(base, baseResponse(base, 200, PAGE), new FakeSender(b -> html(200, PAGE.replace("Order list", "The state information is invalid for this page"))))
                .isEmpty());
        // Redirect to an error page while the base redirected elsewhere.
        MessageContext redirectBase = MessageContext.builder(MessageKind.RESPONSE).method("POST").url(base.url()).requestBody(base.requestBody())
                .statusCode(302).responseHeader("Location", "/Done.aspx").responseBody("").build();
        assertTrue(active(base, redirectBase, new FakeSender(b -> html(302, "").responseHeader("Location", "/Error.aspx?aspxerrorpath=/Default.aspx"))).isEmpty());
        // Async postback delta error.
        assertTrue(active(base, baseResponse(base, 200, PAGE), new FakeSender(b -> html(200, "52|error|500|Validation of viewstate MAC failed. |"))).isEmpty());
    }

    @Test
    void noBaseResponseSendsBaseline() {
        MessageContext base = postVs(page().withMac(32), "");
        FakeSender http = new FakeSender(b -> html(200, PAGE));
        List<Finding> f = active(base, null, http);
        assertEquals(2, http.bodies.size());
        assertEquals(base.requestBodyText(), http.bodies.get(0));
        assertEquals(1, f.size());
        assertEquals(2, f.get(0).exchanges().size());
    }

    @Test
    void noMacTamperChangesAString() throws Exception {
        MessageContext base = postVs(page().build(), "");
        FakeSender http = new FakeSender(b -> html(200, PAGE));
        List<Finding> f = active(base, baseResponse(base, 200, PAGE), http);
        assertEquals(1, f.size());
        DecodeResult r = decoder.decode(post(http.bodies.get(0)));
        String tree = TreeText.render(r.root());
        assertTrue(tree.contains("Texx") || tree.contains("hellx"), tree);
        assertTrue(r.summary().endsWith("no MAC ⚠"));
    }

    @Test
    void activeSkipsCallbacksEncryptedAndGets() {
        app.scanEngine().setEnabled("devexpress.malformed-callback", false);
        FakeSender http = new FakeSender(b -> html(200, PAGE));
        MessageContext dx = post("__EVENTTARGET=&__VIEWSTATE=" + enc(b64(page().withMac(32))) + "&__CALLBACKID=" + enc("ctl00$Grid")
                + "&__CALLBACKPARAM=" + enc("c0:GB|3;1|a;"));
        active(dx, baseResponse(dx, 200, PAGE), http);
        byte[] random = new byte[96];
        new Random(5).nextBytes(random);
        random[0] = 0x3c;
        MessageContext enc = postVs(random, "&__VIEWSTATEENCRYPTED=");
        active(enc, baseResponse(enc, 200, PAGE), http);
        MessageContext get = MessageContext.builder(MessageKind.REQUEST).method("GET")
                .url("https://shop.example.com/a.aspx?__VIEWSTATE=" + enc(b64(page().withMac(32)))).build();
        active(get, null, http);
        assertTrue(http.bodies.isEmpty(), http.bodies.toString());
    }
}
