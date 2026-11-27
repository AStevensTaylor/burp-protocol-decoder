package protocoldecoder.builtin.serialized;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.scan.CheckInfo;
import protocoldecoder.scan.Confidence;
import protocoldecoder.scan.Evidence;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.InsertionPoint;
import protocoldecoder.scan.Severity;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.zip.DeflaterOutputStream;

import static org.junit.jupiter.api.Assertions.*;
import static protocoldecoder.builtin.serialized.Fixtures.*;

/** Passive checks and insertion points of the serialized-object scanner. Nothing here is ever deserialized. */
class SerializedObjectScannerTest {

    static final String NASTY = "x\"';:}{\\ ünï 日本 🎉 a:1:{s:1:\"q\";} --";
    /** pickle.dumps({'user': 'alice', 'role': 'admin~~??>>'}, protocol=4): has a FRAME and URL-safe base64 characters. */
    static final byte[] PICKLE_USER_P4 = hexBytes("80049529000000000000007d94288c0475736572948c05616c696365948c04726f6c65948c0b61646d696e7e7e3f3f3e3e94752e");

    final SerializedObjectScanner scanner = new SerializedObjectScanner();
    final App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });

    @AfterEach
    void close() {
        app.close();
    }

    // ------------------------------------------------------------------ helpers

    List<Finding> passive(MessageContext m) {
        List<Finding> out = new ArrayList<>();
        scanner.passiveChecks().forEach(c -> out.addAll(c.check(m, null)));
        return out;
    }

    static List<Finding> of(List<Finding> f, String checkId) {
        return f.stream().filter(x -> x.checkId().equals(checkId)).toList();
    }

    List<InsertionPoint> ips(MessageContext m) {
        return scanner.insertionPoints(m, null);
    }

    static InsertionPoint ip(List<InsertionPoint> ips, String name) {
        return ips.stream().filter(i -> i.name().equals(name)).findFirst()
                .orElseThrow(() -> new AssertionError("no insertion point " + name + " in " + ips.stream().map(InsertionPoint::name).toList()));
    }

    /** The request with the insertion point's part replaced by its rendering of {@code payload}. */
    static MessageContext apply(MessageContext m, InsertionPoint ip, String payload) {
        byte[] part = ip.render().apply(payload);
        MessageContext.Builder b = MessageContext.builder(MessageKind.REQUEST).method(m.method());
        String base = m.url().contains("?") ? m.url().substring(0, m.url().indexOf('?')) : m.url();
        b.url(ip.part() == InsertionPoint.Part.QUERY ? base + "?" + new String(part, StandardCharsets.UTF_8) : m.url());
        for (Header h : m.requestHeaders()) {
            boolean replace = ip.part() == InsertionPoint.Part.HEADER && h.name().equalsIgnoreCase(ip.headerName());
            b.requestHeader(h.name(), replace ? new String(part, StandardCharsets.UTF_8) : h.value());
        }
        b.requestBody(ip.part() == InsertionPoint.Part.BODY ? part : m.requestBody());
        return b.build();
    }

    /**
     * Renders the payload, then re-discovers the insertion points of the mutated request: the same point must exist
     * (structure fully parsed again, wrappers peeled) and hold exactly the payload.
     */
    InsertionPoint roundTrip(MessageContext m, InsertionPoint ip, String payload) {
        MessageContext mutated = apply(m, ip, payload);
        InsertionPoint again = ip(ips(mutated), ip.name());
        assertEquals(payload, again.baseValue(), "value after round trip of " + ip.name());
        assertTrue(new SerializedObjectDecoder().match(mutated).matched(), "mutated message still recognised");
        return again;
    }

    static String b64url(byte[] b) {
        return Base64.getUrlEncoder().encodeToString(b);
    }

    static byte[] zlib(byte[] b) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (DeflaterOutputStream d = new DeflaterOutputStream(bos)) {
            d.write(b);
        }
        return bos.toByteArray();
    }

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------ registration

    @Test
    void registeredWithTheEngine() {
        List<String> ids = app.scanEngine().checks().stream().map(CheckInfo::id).toList();
        assertTrue(ids.containsAll(List.of("serialized.client-supplied", "serialized.gadget-reference", "serialized.server-issued",
                "serialized.insertion-points")), ids.toString());
        String php = "a:1:{s:4:\"name\";s:5:\"alice\";}";
        MessageContext m = request("https://app.example.test/p", null, "Cookie", "prefs=" + enc(php));
        assertTrue(app.scanEngine().insertionPoints(m).stream().anyMatch(i -> i.name().equals("Serialized (PHP): cookie prefs › $.name")));
        assertTrue(app.scanEngine().passive(m, false).stream().anyMatch(f -> f.checkId().equals("serialized.client-supplied")));
    }

    // ------------------------------------------------------------------ PHP

    @Test
    void phpInsertionPointsNestedStringsAndIntegers() {
        String php = "a:3:{s:4:\"user\";a:2:{s:4:\"name\";s:5:\"alice\";s:4:\"tags\";a:1:{i:0;s:3:\"t;1\";}}s:2:\"id\";i:7;s:1:\"f\";d:1.5;}";
        MessageContext m = request("https://app.example.test/", null, "Cookie", "theme=dark; session=" + enc(php) + "; x=1");
        List<InsertionPoint> ips = ips(m);
        assertEquals(List.of("Serialized (PHP): cookie session › $.user.name", "Serialized (PHP): cookie session › $.user.tags[0]",
                "Serialized (PHP): cookie session › $.id"), ips.stream().map(InsertionPoint::name).toList());
        InsertionPoint name = ip(ips, "Serialized (PHP): cookie session › $.user.name");
        assertEquals("alice", name.baseValue());
        assertEquals("Cookie", name.headerName());

        roundTrip(m, name, NASTY);
        String header = new String(name.render().apply(NASTY), StandardCharsets.UTF_8);
        assertTrue(header.startsWith("theme=dark; session="), header);
        assertTrue(header.endsWith("; x=1"), header);
        String php2 = Sniffer.percentDecodeKeepPlus(header.substring("theme=dark; session=".length(), header.length() - "; x=1".length()));
        int bytes = NASTY.getBytes(StandardCharsets.UTF_8).length;
        assertEquals(php.replace("s:5:\"alice\"", "s:" + bytes + ":\"" + NASTY + "\""), php2, "everything else byte-for-byte");

        InsertionPoint id = ip(ips, "Serialized (PHP): cookie session › $.id");
        assertEquals("7", id.baseValue());
        roundTrip(m, id, "-123456");
        String numeric = Sniffer.percentDecodeKeepPlus(new String(id.render().apply("42"), StandardCharsets.UTF_8));
        assertTrue(numeric.contains("s:2:\"id\";i:42;"), numeric);
        // a non-numeric payload cannot be an integer: it is written as a string so the structure stays valid
        String text = Sniffer.percentDecodeKeepPlus(new String(id.render().apply("1' OR '1"), StandardCharsets.UTF_8));
        assertTrue(text.contains("s:2:\"id\";s:8:\"1' OR '1\";"), text);
        assertTrue(PhpParser.parse(text.substring(text.indexOf("a:3")), new ParseOutput.Budget(1000)).complete);
    }

    @Test
    void phpCookieDelimitersStayEncodedAndBase64Param() {
        String php = "O:4:\"User\":1:{s:4:\"name\";s:3:\"bob\";}";
        MessageContext raw = request("https://app.example.test/", null, "Cookie", "u=" + enc(php));
        InsertionPoint p = ip(ips(raw), "Serialized (PHP): cookie u › $.name");
        String header = new String(p.render().apply("a;b=c"), StandardCharsets.UTF_8);
        assertFalse(header.substring(2).contains(";"), "payload delimiters are percent-encoded: " + header);
        roundTrip(raw, p, NASTY);

        MessageContext q = request("https://app.example.test/x?a=1&data=" + enc(Base64.getEncoder().encodeToString(php.getBytes(StandardCharsets.UTF_8))) + "&z=2", null);
        InsertionPoint qp = ip(ips(q), "Serialized (PHP): param data › $.name");
        assertEquals(InsertionPoint.Part.QUERY, qp.part());
        String query = new String(qp.render().apply(NASTY), StandardCharsets.UTF_8);
        assertTrue(query.startsWith("a=1&data=") && query.endsWith("&z=2"), query);
        roundTrip(q, qp, NASTY);
    }

    @Test
    void phpPassiveSeverityDependsOnObjects() {
        MessageContext obj = request("https://app.example.test/", null, "Cookie", "u=" + enc("O:4:\"User\":1:{s:4:\"name\";s:3:\"bob\";}"));
        Finding f = of(passive(obj), SerializedObjectScanner.CLIENT_CHECK).get(0);
        assertEquals("PHP serialized object in request cookie u", f.title());
        assertEquals(Severity.MEDIUM, f.severity());
        assertEquals(Confidence.FIRM, f.confidence());
        assertTrue(f.detail().contains("User"), f.detail());
        assertEquals(List.of(Evidence.request(enc("O:4:\"User\":1:{s:4:\"name\";s:3:\"bob\";}"))), f.evidence());

        MessageContext arr = request("https://app.example.test/", null, "Cookie", "u=" + enc("a:1:{s:4:\"name\";s:3:\"bob\";}"));
        Finding low = of(passive(arr), SerializedObjectScanner.CLIENT_CHECK).get(0);
        assertEquals(Severity.LOW, low.severity());
        assertTrue(of(passive(arr), SerializedObjectScanner.GADGET_CHECK).isEmpty());
    }

    // ------------------------------------------------------------------ Java

    @Test
    void javaBase64GzipCookieAndLongStringSwitch() {
        byte[] ser = javaNamedObject("com.example.Prefs", "theme", "dark");
        MessageContext m = request("https://app.example.test/", null, "Cookie", "prefs=" + b64(gzip(ser)));
        InsertionPoint p = ip(ips(m), "Serialized (Java): cookie prefs › $.theme");
        assertEquals("dark", p.baseValue());
        roundTrip(m, p, NASTY);
        roundTrip(m, p, "\u0000nul");

        String big = "Aé".repeat(35_000); // 105,000 bytes of modified UTF-8: needs TC_LONGSTRING
        InsertionPoint again = roundTrip(m, p, big);
        assertEquals(big, again.baseValue());
        String cookie = new String(p.render().apply(big), StandardCharsets.UTF_8).substring("prefs=".length());
        byte[] stream = Sniffer.gunzip(Base64.getDecoder().decode(cookie), Sniffer.MAX_PAYLOAD).data();
        int at = stream.length - Reserializer.modifiedUtf8(big).length - 9;
        assertEquals(0x7C, stream[at] & 0xff, "TC_LONGSTRING");
        assertTrue(JavaSerialParser.parse(stream, new ParseOutput.Budget(1000)).complete);
    }

    @Test
    void javaBackReferencesKeepHandles() {
        java.util.ArrayList<String> list = new java.util.ArrayList<>();
        String same = new String("same");
        list.add(same);
        list.add(same);
        list.add("other");
        byte[] ser = javaSerialize(list);
        MessageContext m = requestBytes("https://app.example.test/rpc", ser, "Content-Type", "application/x-java-serialized-object");
        List<InsertionPoint> ips = ips(m);
        assertEquals(2, ips.size(), ips.stream().map(InsertionPoint::name).toList().toString()); // the second "same" is a reference
        for (InsertionPoint p : ips) {
            assertEquals(InsertionPoint.Part.BODY, p.part());
            roundTrip(m, p, NASTY);
            byte[] out = p.render().apply("changed");
            String tree = Fixtures.text(JavaSerialParser.parse(out, new ParseOutput.Budget(1000)).structure);
            assertEquals(1, tree.split("→ ", -1).length - 1, "the back-reference still resolves: " + tree);
        }
    }

    @Test
    void javaHexHeaderAndEmbeddedJsonToken() {
        byte[] ser = javaNamedObject("com.example.State", "step", "2");
        MessageContext h = request("https://app.example.test/", null, "X-State", hex(ser).toUpperCase());
        InsertionPoint hp = ip(ips(h), "Serialized (Java): header X-State › $.step");
        String rendered = new String(hp.render().apply("3"), StandardCharsets.UTF_8);
        assertTrue(rendered.matches("[0-9A-F]+"), "upper-case hex kept: " + rendered);
        roundTrip(h, hp, NASTY);

        String body = "{\"id\":5,\"state\":\"" + b64(ser) + "\",\"x\":true}";
        MessageContext j = request("https://app.example.test/api", body, "Content-Type", "application/json");
        InsertionPoint jp = ip(ips(j), "Serialized (Java): body field state › $.step");
        String newBody = new String(jp.render().apply(NASTY), StandardCharsets.ISO_8859_1);
        assertTrue(newBody.startsWith("{\"id\":5,\"state\":\"rO0AB") && newBody.endsWith("\",\"x\":true}"), newBody);
        roundTrip(j, jp, NASTY);
    }

    @Test
    void moreWrapperCombinations() {
        byte[] ser = javaNamedObject("com.example.State", "step", "2");
        // gzip-compressed request body (Content-Encoding: gzip)
        MessageContext gz = requestBytes("https://app.example.test/x", gzip(ser), "Content-Type", "application/octet-stream", "Content-Encoding", "gzip");
        InsertionPoint g = ip(ips(gz), "Serialized (Java): body › $.step");
        byte[] out = g.render().apply(NASTY);
        assertTrue(protocoldecoder.util.Codecs.isGzip(out));
        roundTrip(gz, g, NASTY);
        // hex of gzip in a query parameter
        MessageContext hx = request("https://app.example.test/x?s=" + hex(gzip(ser)), null);
        roundTrip(hx, ip(ips(hx), "Serialized (Java): param s › $.step"), NASTY);
        // base64 in a urlencoded form field, other fields untouched
        MessageContext form = request("https://app.example.test/x", "a=1&blob=" + enc(b64(ser)) + "&b=%20x", "Content-Type", "application/x-www-form-urlencoded");
        InsertionPoint f = ip(ips(form), "Serialized (Java): param blob › $.step");
        assertEquals(InsertionPoint.Part.BODY, f.part());
        String body = new String(f.render().apply(NASTY), StandardCharsets.UTF_8);
        assertTrue(body.startsWith("a=1&blob=rO0AB") && body.endsWith("&b=%20x"), body);
        roundTrip(form, f, NASTY);
        // percent-encoded base64 in a cookie
        MessageContext pc = request("https://app.example.test/x", null, "Cookie", "c=" + enc(b64(ser)));
        roundTrip(pc, ip(ips(pc), "Serialized (Java): cookie c › $.step"), NASTY);
    }

    @Test
    void javaPassiveAndGadgetReference() {
        byte[] benign = javaNamedObject("com.example.Prefs", "theme", "dark");
        String token = b64(benign);
        MessageContext m = request("https://app.example.test/?state=" + enc(token), null);
        List<Finding> f = passive(m);
        Finding c = of(f, SerializedObjectScanner.CLIENT_CHECK).get(0);
        assertEquals("Java serialized object in request parameter state", c.title());
        assertEquals(Severity.MEDIUM, c.severity());
        assertTrue(c.detail().contains("com.example.Prefs"), c.detail());
        assertEquals(enc(token), c.evidence().get(0).text());
        assertTrue(of(f, SerializedObjectScanner.GADGET_CHECK).isEmpty());

        byte[] gadget = javaNamedObject("org.apache.commons.collections.functors.InvokerTransformer", "iMethodName", "x");
        MessageContext g = request("https://app.example.test/", null, "Cookie", "s=" + b64(gadget));
        Finding gf = of(passive(g), SerializedObjectScanner.GADGET_CHECK).get(0);
        assertEquals(Severity.HIGH, gf.severity());
        assertEquals(Confidence.TENTATIVE, gf.confidence());
        assertTrue(gf.detail().contains("InvokerTransformer") && gf.detail().contains("cookie s"), gf.detail());
    }

    @Test
    void sameTokenTwiceIsReportedOnce() {
        String token = b64(javaNamedObject("com.example.Prefs", "theme", "dark"));
        MessageContext m = request("https://app.example.test/?a=" + enc(token), null, "Cookie", "b=" + token);
        List<Finding> f = of(passive(m), SerializedObjectScanner.CLIENT_CHECK);
        assertEquals(1, f.size(), f.toString());
        assertEquals(1, ips(m).size());
    }

    // ------------------------------------------------------------------ pickle

    @Test
    void pickleUrlSafeParamWithFrameResize() {
        String token = b64url(PICKLE_USER_P4);
        assertTrue(token.contains("-"), token);
        MessageContext m = request("https://app.example.test/load?p=" + token, null);
        List<InsertionPoint> ips = ips(m);
        assertEquals(List.of("Serialized (pickle): param p › $[0]", "Serialized (pickle): param p › $[1]",
                "Serialized (pickle): param p › $[2]", "Serialized (pickle): param p › $[3]"), ips.stream().map(InsertionPoint::name).toList());
        InsertionPoint user = ips.get(1);
        assertEquals("alice", user.baseValue());
        String big = "é".repeat(300); // 600 bytes: SHORT_BINUNICODE widened to BINUNICODE
        for (String payload : List.of(NASTY, big)) {
            roundTrip(m, user, payload);
            String q = new String(user.render().apply(payload), StandardCharsets.UTF_8);
            String v = protocoldecoder.util.Codecs.urlDecode(q.substring(2));
            assertFalse(v.contains("+") || v.contains("/"), "URL-safe alphabet kept: " + v);
            byte[] p = Base64.getUrlDecoder().decode(v);
            ParseOutput po = PickleParser.parse(p, new ParseOutput.Budget(1000));
            assertTrue(po.complete);
            ParseOutput.Frame frame = po.frames.get(0);
            assertEquals(p.length - frame.start(), frame.length(), "frame length recomputed");
        }
    }

    @Test
    void pickleStackGlobalOperandsAreNotInsertionPoints() {
        MessageContext m = requestBytes("https://app.example.test/x", PICKLE_ODICT_P4, "Content-Type", "application/octet-stream");
        List<InsertionPoint> ips = ips(m);
        assertEquals(List.of("a"), ips.stream().map(InsertionPoint::baseValue).toList());
        roundTrip(m, ips.get(0), NASTY);
    }

    @Test
    void pickleGadgetGlobalInRequestBody() {
        MessageContext m = requestBytes("https://app.example.test/x", PICKLE_GLOBAL_ONLY, "Content-Type", "application/octet-stream");
        List<Finding> f = passive(m);
        Finding g = of(f, SerializedObjectScanner.GADGET_CHECK).get(0);
        assertTrue(g.detail().contains("subprocess.Popen"), g.detail());
        assertEquals("Python pickle serialized object in request body", of(f, SerializedObjectScanner.CLIENT_CHECK).get(0).title());
    }

    @Test
    void djangoSignedPickleCookieIsLowAndNotFuzzed() throws Exception {
        String cookie = "." + b64url(zlib(PICKLE_USER_P4)).replace("=", "") + ":1qWxyz:" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-ab";
        MessageContext m = request("https://app.example.test/", null, "Cookie", "sessionid=" + cookie);
        assertTrue(new SerializedObjectDecoder().match(m).matched());
        Finding f = of(passive(m), SerializedObjectScanner.CLIENT_CHECK).get(0);
        assertEquals("Python pickle serialized object (signed) in request cookie sessionid", f.title());
        assertEquals(Severity.LOW, f.severity());
        assertEquals(Confidence.TENTATIVE, f.confidence());
        assertTrue(f.detail().contains("signing key"), f.detail());
        assertTrue(ips(m).isEmpty());
    }

    // ------------------------------------------------------------------ .NET

    @Test
    void nrbfBodyStringRoundTrip() {
        MessageContext m = requestBytes("https://app.example.test/svc", nrbfPerson(), "Content-Type", "application/octet-stream");
        InsertionPoint p = ip(ips(m), "Serialized (.NET): body › $.Name");
        assertEquals("alice", p.baseValue());
        roundTrip(m, p, NASTY);
        roundTrip(m, p, "z".repeat(20_000)); // 3-byte 7-bit length prefix
        Finding f = of(passive(m), SerializedObjectScanner.CLIENT_CHECK).get(0);
        assertEquals(".NET BinaryFormatter serialized object in request body", f.title());
        assertEquals(Severity.MEDIUM, f.severity());
        assertTrue(f.evidence().stream().anyMatch(e -> e.text().equals("Test.Person")), f.evidence().toString());
    }

    // ------------------------------------------------------------------ Ruby

    @Test
    void rubyHashCookieRoundTripAndSignedRailsCookie() {
        MessageContext m = request("https://app.example.test/", null, "Cookie", "data=" + b64(RUBY_HASH));
        List<InsertionPoint> ips = ips(m);
        InsertionPoint user = ip(ips, "Serialized (Ruby): cookie data › $.user");
        assertEquals("bob", user.baseValue());
        roundTrip(m, user, NASTY);
        roundTrip(m, user, "r".repeat(300)); // multi-byte Marshal length
        Finding f = of(passive(m), SerializedObjectScanner.CLIENT_CHECK).get(0);
        assertEquals("Ruby Marshal serialized object in request cookie data", f.title());
        assertEquals(Severity.MEDIUM, f.severity());

        String signed = b64(RUBY_OBJECT) + "--" + "0123456789abcdef0123456789abcdef01234567";
        MessageContext s = request("https://app.example.test/", null, "Cookie", "_app_session=" + signed);
        assertTrue(ips(s).isEmpty(), "signed values are not fuzzed");
        Finding sf = of(passive(s), SerializedObjectScanner.CLIENT_CHECK).get(0);
        assertEquals("Ruby Marshal serialized object (signed) in request cookie _app_session", sf.title());
        assertEquals(Severity.LOW, sf.severity());
        assertEquals(Confidence.TENTATIVE, sf.confidence());
        assertEquals(signed, sf.evidence().get(0).text());
    }

    // ------------------------------------------------------------------ Json.NET, responses, negatives

    @Test
    void jsonNetTypeHintInRequest() {
        String body = "{\"$type\":\"MyApp.Models.Order, MyApp\",\"Id\":5}";
        MessageContext m = request("https://app.example.test/api", body, "Content-Type", "application/json");
        Finding f = of(passive(m), SerializedObjectScanner.CLIENT_CHECK).get(0);
        assertEquals("Json.NET $type hints in request body", f.title());
        assertEquals(Severity.LOW, f.severity());
        assertEquals(Confidence.TENTATIVE, f.confidence());
        assertTrue(ips(m).isEmpty(), "plain JSON is left to Burp");

        String risky = "{\"$type\":\"System.Windows.Data.ObjectDataProvider, PresentationFramework\"}";
        MessageContext r = request("https://app.example.test/api", risky, "Content-Type", "application/json");
        assertEquals(Severity.HIGH, of(passive(r), SerializedObjectScanner.GADGET_CHECK).get(0).severity());
    }

    @Test
    void responseObjectsAreInformationOnly() {
        String token = b64(javaNamedObject("com.example.Prefs", "theme", "dark"));
        MessageContext set = response("ok".getBytes(StandardCharsets.UTF_8), "Set-Cookie", "prefs=" + token + "; Path=/; HttpOnly");
        List<Finding> f = passive(set);
        assertTrue(of(f, SerializedObjectScanner.CLIENT_CHECK).isEmpty());
        Finding s = of(f, SerializedObjectScanner.SERVER_CHECK).get(0);
        assertEquals("Java serialized object in response cookie prefs", s.title());
        assertEquals(Severity.INFORMATION, s.severity());
        assertTrue(s.detail().contains("client sends this value back"), s.detail());
        assertEquals(List.of(Evidence.response(token)), s.evidence());

        String html = "<html><body><form><input type=\"hidden\" name=\"javax.faces.ViewState\" id=\"j_id1\" value=\"" + token
                + "\"/></form></body></html>";
        MessageContext page = response(html.getBytes(StandardCharsets.UTF_8), "Content-Type", "text/html");
        Finding hf = of(passive(page), SerializedObjectScanner.SERVER_CHECK).get(0);
        assertEquals("Java serialized object in response body field javax.faces.ViewState", hf.title());

        byte[] gadget = javaNamedObject("org.apache.commons.collections.functors.InvokerTransformer", "x", "y");
        MessageContext rg = response(gadget, "Content-Type", "application/octet-stream");
        assertTrue(of(passive(rg), SerializedObjectScanner.GADGET_CHECK).isEmpty(), "gadget check is request-side only");
        assertEquals(1, of(passive(rg), SerializedObjectScanner.SERVER_CHECK).size());
    }

    @Test
    void webSocketDirectionDecidesSide() {
        byte[] ser = javaNamedObject("com.example.Msg", "text", "hi");
        MessageContext up = MessageContext.builder(MessageKind.WEBSOCKET).url("wss://app.example.test/ws").webSocket("CLIENT_TO_SERVER", ser).build();
        assertEquals("Java serialized object in request WebSocket message", of(passive(up), SerializedObjectScanner.CLIENT_CHECK).get(0).title());
        MessageContext down = MessageContext.builder(MessageKind.WEBSOCKET).url("wss://app.example.test/ws").webSocket("SERVER_TO_CLIENT", ser).build();
        assertTrue(of(passive(down), SerializedObjectScanner.CLIENT_CHECK).isEmpty());
        assertEquals(1, of(passive(down), SerializedObjectScanner.SERVER_CHECK).size());
    }

    @Test
    void benignTrafficProducesNothing() {
        MessageContext m = request("https://app.example.test/search?q=hello+world&page=2&token=" + b64("just some bytes here".getBytes(StandardCharsets.UTF_8)),
                "{\"name\":\"alice\",\"data\":\"" + b64("plain text".getBytes(StandardCharsets.UTF_8)) + "\"}",
                "Content-Type", "application/json", "Cookie", "sid=abcdef0123456789; theme=dark",
                "Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlc2lnbmF0dXJl");
        assertTrue(passive(m).isEmpty(), passive(m).toString());
        assertTrue(ips(m).isEmpty());
        MessageContext resp = response("<html><body>hello</body></html>".getBytes(StandardCharsets.UTF_8), "Set-Cookie", "sid=abc123456; Path=/");
        assertTrue(passive(resp).isEmpty());
        // a partially parsable Java stream gets no insertion points (positions would be unreliable)
        byte[] ser = javaNamedObject("com.example.Prefs", "theme", "dark");
        byte[] cut = java.util.Arrays.copyOf(ser, ser.length - 2);
        assertTrue(ips(requestBytes("https://app.example.test/x", cut, "Content-Type", "application/octet-stream")).isEmpty());
    }
}
