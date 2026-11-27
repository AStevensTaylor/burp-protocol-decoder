package protocoldecoder.builtin.saml;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
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
import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;
import static protocoldecoder.builtin.saml.SamlDecoderTest.*;

class SamlScannerTest {

    final SamlScanner scanner = new SamlScanner();
    final SamlDecoder decoder = new SamlDecoder();
    final App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });

    static final String PAYLOAD = "a\"b'<c>&d]]><!-- x --> é✓ 𝄞 %+=;";

    @AfterEach
    void close() {
        app.close();
    }

    static String signedResponse() {
        return response(sig("_resp1", RSA_SHA256, SHA256), SUCCESS, goodAssertion(sig("_a1", RSA_SHA256, SHA256)));
    }

    static InsertionPoint ip(List<InsertionPoint> ips, String name) {
        return ips.stream().filter(i -> i.name().equals(name)).findFirst()
                .orElseThrow(() -> new AssertionError(name + " not in " + ips.stream().map(InsertionPoint::name).toList()));
    }

    /** XML of the SAML message in a form body or query string. */
    static String xmlOf(String container, String param) throws Exception {
        String v = Codecs.first(Codecs.parseQuery(container), param);
        byte[] raw = SamlDecoder.base64(v);
        String s = new String(raw, StandardCharsets.UTF_8);
        if (!s.stripLeading().startsWith("<")) s = new String(Codecs.inflate(raw), StandardCharsets.UTF_8);
        return s;
    }

    List<Finding> passive(MessageContext m, String id) {
        return app.scanEngine().passive(m, false).stream().filter(f -> f.checkId().equals(id)).toList();
    }

    // ---------------------------------------------------------------- insertion points

    @Test
    void postBindingInsertionPointsRoundTrip() throws Exception {
        MessageContext m = postSamlResponse(signedResponse());
        List<InsertionPoint> ips = scanner.insertionPoints(m, null);
        List<String> names = ips.stream().map(InsertionPoint::name).toList();
        assertTrue(names.containsAll(List.of(
                "SAML: Response@Destination",
                "SAML: Issuer",
                "SAML: Assertion/Issuer",
                "SAML: Assertion/Subject/NameID",
                "SAML: Assertion/Subject/SubjectConfirmation/SubjectConfirmationData@Recipient",
                "SAML: Assertion/AttributeStatement/Attribute[email]/AttributeValue",
                "SAML: Assertion/AttributeStatement/Attribute[groups]/AttributeValue",
                "SAML: Assertion/AttributeStatement/Attribute[groups]/AttributeValue #2")), names.toString());
        InsertionPoint nameId = ip(ips, "SAML: Assertion/Subject/NameID");
        assertEquals("alice@example.com", nameId.baseValue());
        assertEquals(InsertionPoint.Part.BODY, nameId.part());

        String body = new String(nameId.render().apply(PAYLOAD), StandardCharsets.ISO_8859_1);
        assertTrue(body.endsWith("&RelayState=" + enc("https://sp.example.com/home")), "other params kept: " + body);
        String xml = xmlOf(body, "SAMLResponse");
        assertFalse(xml.contains("<!DOCTYPE"));
        Document d = SafeXml.parse(xml);
        assertEquals(PAYLOAD, d.getElementsByTagNameNS(SamlAnalyzer.SAML2, "NameID").item(0).getTextContent());
        // still a well-formed, decodable SAML Response; signatures are left in place
        DecodeResult r = decoder.decode(post(body));
        assertTrue(r.summary().contains(PAYLOAD), r.summary());
        assertEquals(2, d.getElementsByTagNameNS(SamlAnalyzer.DS, "Signature").getLength());

        // attribute insertion escapes quotes etc.
        String body2 = new String(ip(ips, "SAML: Response@Destination").render().apply(PAYLOAD), StandardCharsets.ISO_8859_1);
        assertEquals(PAYLOAD, SafeXml.parse(xmlOf(body2, "SAMLResponse")).getDocumentElement().getAttribute("Destination"));
        String body3 = new String(ip(ips, "SAML: Assertion/AttributeStatement/Attribute[groups]/AttributeValue #2").render().apply(PAYLOAD), StandardCharsets.ISO_8859_1);
        Document d3 = SafeXml.parse(xmlOf(body3, "SAMLResponse"));
        assertEquals("admins", d3.getElementsByTagNameNS(SamlAnalyzer.SAML2, "AttributeValue").item(1).getTextContent());
        assertEquals(PAYLOAD, d3.getElementsByTagNameNS(SamlAnalyzer.SAML2, "AttributeValue").item(2).getTextContent());
    }

    @Test
    void redirectBindingInsertionPointsReDeflate() throws Exception {
        String url = "https://idp.example.com/sso?SAMLRequest=" + enc(deflateB64(AUTHN_REQUEST)) + "&RelayState=abc&SigAlg=" + enc(RSA_SHA256)
                + "&Signature=c2ln";
        MessageContext m = get(url);
        List<InsertionPoint> ips = scanner.insertionPoints(m, null);
        InsertionPoint acs = ip(ips, "SAML: AuthnRequest@AssertionConsumerServiceURL");
        assertEquals("https://sp.example.com/acs", acs.baseValue());
        assertEquals(InsertionPoint.Part.QUERY, acs.part());
        assertNotNull(ip(ips, "SAML: Issuer"));
        String q = new String(acs.render().apply(PAYLOAD), StandardCharsets.ISO_8859_1);
        assertTrue(q.endsWith("&RelayState=abc&SigAlg=" + enc(RSA_SHA256) + "&Signature=c2ln"), q);
        // the value is raw DEFLATE again, not plain base64 XML
        byte[] raw = SamlDecoder.base64(Codecs.first(Codecs.parseQuery(q), "SAMLRequest"));
        assertNotEquals('<', raw[0]);
        assertEquals(PAYLOAD, SafeXml.parse(xmlOf(q, "SAMLRequest")).getDocumentElement().getAttribute("AssertionConsumerServiceURL"));
        DecodeResult r = decoder.decode(get("https://idp.example.com/sso?" + q));
        assertTrue(r.warnings().stream().noneMatch(w -> w.contains("not DEFLATE")), r.warnings().toString());
        assertEquals(PAYLOAD, find(r.root(), "AssertionConsumerServiceURL"));
    }

    @Test
    void noInsertionPointsForNonSaml() {
        assertTrue(scanner.insertionPoints(post("a=1&b=2"), null).isEmpty());
        assertTrue(scanner.insertionPoints(post("SAMLResponse=bm90IHhtbA%3D%3D"), null).isEmpty());
    }

    // ---------------------------------------------------------------- passive

    @Test
    void unsignedAssertion() {
        List<Finding> f = passive(postSamlResponse(response("", SUCCESS, goodAssertion(""))), "saml.unsigned-assertion");
        assertEquals(1, f.size());
        assertEquals(Severity.MEDIUM, f.get(0).severity());
        assertEquals(Finding.Scope.HOST, f.get(0).scope());
        assertTrue(f.get(0).detail().contains("https://idp.example.com"));
        // signed Response covers the assertion; signed assertion alone is fine too
        assertTrue(passive(postSamlResponse(response(sig("_resp1", RSA_SHA256, SHA256), SUCCESS, goodAssertion(""))), "saml.unsigned-assertion").isEmpty());
        assertTrue(passive(postSamlResponse(response("", SUCCESS, goodAssertion(sig("_a1", RSA_SHA256, SHA256)))), "saml.unsigned-assertion").isEmpty());
    }

    @Test
    void sha1Signature() {
        List<Finding> f = passive(postSamlResponse(response("", SUCCESS, goodAssertion(sig("_a1", RSA_SHA1, SHA1)))), "saml.sha1-signature");
        assertEquals(1, f.size());
        assertEquals(Severity.LOW, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("rsa-sha1"));
        assertTrue(passive(postSamlResponse(signedResponse()), "saml.sha1-signature").isEmpty());
        // redirect-binding SigAlg
        String url = "https://idp.example.com/sso?SAMLRequest=" + enc(deflateB64(AUTHN_REQUEST)) + "&SigAlg=" + enc(RSA_SHA1) + "&Signature=c2ln";
        assertEquals(1, passive(get(url), "saml.sha1-signature").size());
    }

    @Test
    void wrappingIndicators() {
        String evil = assertion("_evil", "", "admin@example.com", conditions("2026-01-01T09:59:05Z", "2026-01-01T10:05:05Z", true));
        String xml = response("", SUCCESS, evil + goodAssertion(sig("_a1", RSA_SHA256, SHA256)));
        List<Finding> f = passive(postSamlResponse(xml), "saml.xsw-indicators");
        assertEquals(1, f.size());
        assertTrue(f.get(0).detail().contains("2 assertions"), f.get(0).detail());
        // signature placed in the Response but referencing the assertion
        String moved = response(sig("_a1", RSA_SHA256, SHA256), SUCCESS, goodAssertion(""));
        assertTrue(passive(postSamlResponse(moved), "saml.xsw-indicators").get(0).detail().contains("references Assertion"));
        assertTrue(passive(postSamlResponse(signedResponse()), "saml.xsw-indicators").isEmpty());
    }

    @Test
    void weakConditions() {
        String longLived = assertion("_a1", sig("_a1", RSA_SHA256, SHA256), "alice@example.com", conditions("2026-01-01T09:59:05Z", "2026-01-08T10:05:05Z", false));
        List<Finding> f = passive(postSamlResponse(response("", SUCCESS, longLived)), "saml.weak-conditions");
        assertEquals(1, f.size());
        assertTrue(f.get(0).detail().contains("7 days"), f.get(0).detail());
        assertTrue(f.get(0).detail().contains("AudienceRestriction"));
        assertTrue(passive(postSamlResponse(signedResponse()), "saml.weak-conditions").isEmpty());
    }

    @Test
    void weakEncryption() {
        String enc = "<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">"
                + "<xenc:EncryptionMethod Algorithm=\"%s\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
                + "<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"%s\"/></xenc:EncryptedKey></ds:KeyInfo>"
                + "<xenc:CipherData><xenc:CipherValue>AAAA</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>";
        String weak = String.format(enc, "http://www.w3.org/2001/04/xmlenc#aes128-cbc", "http://www.w3.org/2001/04/xmlenc#rsa-1_5");
        List<Finding> f = passive(postSamlResponse(response(sig("_resp1", RSA_SHA256, SHA256), SUCCESS, weak)), "saml.weak-encryption");
        assertEquals(1, f.size());
        assertTrue(f.get(0).detail().contains("rsa-1_5") && f.get(0).detail().contains("aes128-cbc"), f.get(0).detail());
        String strong = String.format(enc, "http://www.w3.org/2009/xmlenc11#aes256-gcm", "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
        assertTrue(passive(postSamlResponse(response(sig("_resp1", RSA_SHA256, SHA256), SUCCESS, strong)), "saml.weak-encryption").isEmpty());
    }

    @Test
    void nameIdCommentAndRelayStateAndGet() {
        String commented = assertion("_a1", sig("_a1", RSA_SHA256, SHA256), "admin@example.com<!---->.evil.com",
                conditions("2026-01-01T09:59:05Z", "2026-01-01T10:05:05Z", true));
        List<Finding> c = passive(postSamlResponse(response("", SUCCESS, commented)), "saml.nameid-comment");
        assertEquals(1, c.size());
        assertEquals(Severity.INFORMATION, c.get(0).severity());
        assertTrue(passive(postSamlResponse(signedResponse()), "saml.nameid-comment").isEmpty());

        // postSamlResponse uses RelayState=https://sp.example.com/home
        assertEquals(1, passive(postSamlResponse(signedResponse()), "saml.relaystate-url").size());
        assertTrue(passive(post("SAMLResponse=" + enc(b64(signedResponse())) + "&RelayState=ss%3A123"), "saml.relaystate-url").isEmpty());

        assertTrue(passive(postSamlResponse(signedResponse()), "saml.response-via-get").isEmpty());
        List<Finding> g = passive(get("https://sp.example.com/acs?SAMLResponse=" + enc(deflateB64(signedResponse()))), "saml.response-via-get");
        assertEquals(1, g.size());
        assertEquals(Severity.LOW, g.get(0).severity());
        // LogoutResponse via redirect is normal
        String logout = "<samlp:LogoutResponse " + NS + " ID=\"_l\" Version=\"2.0\" IssueInstant=\"2026-01-01T10:00:00Z\"><samlp:Status>" + SUCCESS + "</samlp:Status></samlp:LogoutResponse>";
        assertTrue(passive(get("https://sp.example.com/slo?SAMLResponse=" + enc(deflateB64(logout))), "saml.response-via-get").isEmpty());
    }

    @Test
    void passiveChecksIgnoreResponses() {
        MessageContext html = response("https://idp.example.com/sso", 200, "text/html",
                "<form method=post action=\"https://sp.example.com/acs\"><input type=hidden name=SAMLResponse value=\"" + b64(response("", SUCCESS, goodAssertion(""))) + "\"></form>", null);
        assertTrue(app.scanEngine().passive(html, false).stream().noneMatch(f -> f.checkId().startsWith("saml.")));
    }

    // ---------------------------------------------------------------- active

    /** Fake SP: decides per received SAMLResponse XML. */
    static final class FakeSp implements HttpSender {
        final List<String> xmls = new ArrayList<>();
        final Function<String, Boolean> accepts;
        final boolean rejectAll;

        FakeSp(Function<String, Boolean> accepts, boolean rejectAll) {
            this.accepts = accepts;
            this.rejectAll = rejectAll;
        }

        @Override
        public Exchange send(String method, String pathAndQuery, List<Header> headers, byte[] body) {
            String xml;
            try {
                xml = xmlOf(new String(body, StandardCharsets.ISO_8859_1), "SAMLResponse");
            } catch (Exception e) {
                throw new AssertionError(e);
            }
            xmls.add(xml);
            boolean ok = !rejectAll && accepts.apply(xml);
            MessageContext.Builder b = MessageContext.builder(MessageKind.REQUEST).method(method).url("https://sp.example.com" + pathAndQuery)
                    .requestBody(body);
            if (ok) {
                b.statusCode(302).responseHeader("Location", "https://sp.example.com/home?t=" + xmls.size())
                        .responseHeader("Set-Cookie", "session=s" + xmls.size() + "; HttpOnly; Secure");
            } else {
                b.statusCode(302).responseHeader("Location", "https://sp.example.com/login?error=saml");
            }
            return new Exchange(b.responseBody("").build(), null);
        }

        @Override
        public Exchange send(InsertionPoint point, String payload) {
            throw new UnsupportedOperationException();
        }
    }

    /** Base request with the captured (successful) response attached. */
    static MessageContext baseWithResponse(String xml) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://sp.example.com/acs")
                .requestHeader("Content-Type", "application/x-www-form-urlencoded")
                .requestBody("SAMLResponse=" + enc(b64(xml)) + "&RelayState=" + enc("https://sp.example.com/home"))
                .statusCode(302).responseHeader("Location", "https://sp.example.com/home?t=0")
                .responseHeader("Set-Cookie", "session=s0; HttpOnly").responseBody("").build();
    }

    List<Finding> active(MessageContext base, HttpSender http) {
        return app.scanEngine().active(ActiveCheck.Scope.PER_REQUEST, base, base.withKind(MessageKind.RESPONSE), null, null, null, http);
    }

    static boolean hasAssertion(String xml) {
        return xml.contains("Assertion ID=");
    }

    @Test
    void signatureNotRequiredAndNotValidated() {
        String original = signedResponse();
        FakeSp sp = new FakeSp(SamlScannerTest::hasAssertion, false); // accepts anything with an assertion
        List<Finding> f = active(baseWithResponse(original), sp);
        assertEquals(4, sp.xmls.size());
        assertEquals(original, sp.xmls.get(0), "first request is the unmodified replay");
        assertFalse(sp.xmls.get(1).contains("Signature"), "signatures stripped");
        assertTrue(sp.xmls.get(2).contains("Signature") && sp.xmls.get(2).contains("IssueInstant=\"2026-01-01T10:00:04Z\""), sp.xmls.get(2));
        assertFalse(hasAssertion(sp.xmls.get(3)), "control without assertion");
        List<String> titles = f.stream().map(Finding::title).toList();
        assertEquals(List.of("SAML signature not required", "SAML signature not validated"), titles);
        assertEquals(Severity.HIGH, f.get(0).severity());
        assertEquals(3, f.get(0).exchanges().size());
    }

    @Test
    void onlyMissingSignatureAccepted() {
        String original = signedResponse();
        // validates signatures when present (any change to a signed message fails), but accepts unsigned ones
        FakeSp sp = new FakeSp(xml -> hasAssertion(xml) && (xml.equals(original) || !xml.contains("Signature")), false);
        List<Finding> f = active(baseWithResponse(original), sp);
        assertEquals(List.of("SAML signature not required"), f.stream().map(Finding::title).toList());
        assertEquals(4, sp.xmls.size());
    }

    @Test
    void secureSpProducesNothing() {
        String original = signedResponse();
        FakeSp sp = new FakeSp(original::equals, false);
        assertTrue(active(baseWithResponse(original), sp).isEmpty());
        assertEquals(3, sp.xmls.size(), "no control needed when nothing looked accepted");
    }

    @Test
    void rejectedReplaySkipsWithoutFinding() {
        FakeSp sp = new FakeSp(x -> true, true); // one-time use: even the unmodified replay fails now
        assertTrue(active(baseWithResponse(signedResponse()), sp).isEmpty());
        assertEquals(1, sp.xmls.size());
    }

    @Test
    void nonDiscriminatingSpProducesNothing() {
        FakeSp sp = new FakeSp(x -> true, false); // same answer for everything, including the control
        MessageContext base = baseWithResponse(signedResponse());
        assertTrue(active(base, sp).isEmpty());
        assertEquals(4, sp.xmls.size());
    }

    @Test
    void activeSkipsUnsuitableRequests() {
        FakeSp sp = new FakeSp(x -> true, false);
        // unsigned response: nothing to strip (passive check covers it)
        assertTrue(active(baseWithResponse(response("", SUCCESS, goodAssertion(""))), sp).isEmpty());
        // AuthnRequest via redirect: not an ACS POST
        MessageContext get = get("https://idp.example.com/sso?SAMLRequest=" + enc(deflateB64(AUTHN_REQUEST)));
        assertTrue(app.scanEngine().active(ActiveCheck.Scope.PER_REQUEST, get, null, null, null, null, sp).isEmpty());
        assertTrue(sp.xmls.isEmpty());
    }

    @Test
    void tamperFallsBackToNameId() throws Exception {
        String xml = signedResponse().replace("IssueInstant=\"2026-01-01T10:00:05Z\">", "IssueInstant=\"bad\">");
        Document d = SafeXml.parse(xml);
        String change = SamlScanner.SignatureEnforcement.tamper(d);
        assertNotNull(change);
        String out = SamlMessage.serialize(d);
        assertTrue(change.startsWith("NameID \"alice@example.com\" → \"Alice@example.com\""), change);
        assertTrue(out.contains(">Alice@example.com</saml:NameID>"), out);
        assertNotEquals(xml, out);
    }
}
