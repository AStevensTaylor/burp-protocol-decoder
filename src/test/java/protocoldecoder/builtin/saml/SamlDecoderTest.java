package protocoldecoder.builtin.saml;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.util.TreeText;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.zip.Deflater;

import static org.junit.jupiter.api.Assertions.*;

class SamlDecoderTest {

    final SamlDecoder saml = new SamlDecoder();

    // ---------------------------------------------------------------- fixtures

    static final String NS = "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"";
    static final String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    static final String RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    static final String SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
    static final String SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";

    static final String AUTHN_REQUEST = "<samlp:AuthnRequest " + NS + " ID=\"_req1\" Version=\"2.0\" IssueInstant=\"2026-01-01T10:00:00Z\""
            + " Destination=\"https://idp.example.com/sso\" AssertionConsumerServiceURL=\"https://sp.example.com/acs\""
            + " ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\">"
            + "<saml:Issuer>https://sp.example.com</saml:Issuer>"
            + "<samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\" AllowCreate=\"true\"/>"
            + "</samlp:AuthnRequest>";

    static String sig(String ref, String alg, String digest) {
        return "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo>"
                + "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
                + "<ds:SignatureMethod Algorithm=\"" + alg + "\"/>"
                + "<ds:Reference URI=\"#" + ref + "\"><ds:Transforms>"
                + "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></ds:Transforms>"
                + "<ds:DigestMethod Algorithm=\"" + digest + "\"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>"
                + "</ds:SignedInfo><ds:SignatureValue>c2lnbmF0dXJlIGJ5dGVz</ds:SignatureValue></ds:Signature>";
    }

    static String conditions(String notBefore, String notOnOrAfter, boolean audience) {
        return "<saml:Conditions NotBefore=\"" + notBefore + "\" NotOnOrAfter=\"" + notOnOrAfter + "\">"
                + (audience ? "<saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction>" : "")
                + "</saml:Conditions>";
    }

    static String assertion(String id, String signature, String nameId, String conditions) {
        return "<saml:Assertion ID=\"" + id + "\" Version=\"2.0\" IssueInstant=\"2026-01-01T10:00:05Z\">"
                + "<saml:Issuer>https://idp.example.com</saml:Issuer>" + signature
                + "<saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">" + nameId + "</saml:NameID>"
                + "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"
                + "<saml:SubjectConfirmationData Recipient=\"https://sp.example.com/acs\" NotOnOrAfter=\"2026-01-01T10:05:05Z\" InResponseTo=\"_req1\"/>"
                + "</saml:SubjectConfirmation></saml:Subject>" + conditions
                + "<saml:AuthnStatement AuthnInstant=\"2026-01-01T10:00:00Z\" SessionIndex=\"_sess1\"><saml:AuthnContext>"
                + "<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>"
                + "</saml:AuthnContext></saml:AuthnStatement>"
                + "<saml:AttributeStatement>"
                + "<saml:Attribute Name=\"email\"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute>"
                + "<saml:Attribute Name=\"groups\"><saml:AttributeValue>admins</saml:AttributeValue><saml:AttributeValue>users</saml:AttributeValue></saml:Attribute>"
                + "</saml:AttributeStatement></saml:Assertion>";
    }

    static String goodAssertion(String signature) {
        return assertion("_a1", signature, "alice@example.com", conditions("2026-01-01T09:59:05Z", "2026-01-01T10:05:05Z", true));
    }

    static String response(String signature, String status, String body) {
        return "<samlp:Response " + NS + " ID=\"_resp1\" Version=\"2.0\" IssueInstant=\"2026-01-01T10:00:05Z\""
                + " Destination=\"https://sp.example.com/acs\" InResponseTo=\"_req1\">"
                + "<saml:Issuer>https://idp.example.com</saml:Issuer>" + signature
                + "<samlp:Status>" + status + "</samlp:Status>" + body + "</samlp:Response>";
    }

    static final String SUCCESS = "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>";

    static String b64(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    static String deflateB64(String s) {
        Deflater d = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        d.setInput(s.getBytes(StandardCharsets.UTF_8));
        d.finish();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        while (!d.finished()) out.write(buf, 0, d.deflate(buf));
        d.end();
        return Base64.getEncoder().encodeToString(out.toByteArray());
    }

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    static MessageContext post(String body) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://sp.example.com/acs")
                .requestHeader("Content-Type", "application/x-www-form-urlencoded").requestBody(body).build();
    }

    static MessageContext postSamlResponse(String xml) {
        return post("SAMLResponse=" + enc(b64(xml)) + "&RelayState=" + enc("https://sp.example.com/home"));
    }

    static MessageContext get(String url) {
        return MessageContext.builder(MessageKind.REQUEST).method("GET").url(url).build();
    }

    static MessageContext response(String requestUrl, int status, String contentType, String body, String location) {
        MessageContext.Builder b = MessageContext.builder(MessageKind.RESPONSE).method("GET").url(requestUrl).statusCode(status);
        if (contentType != null) b.responseHeader("Content-Type", contentType);
        if (location != null) b.responseHeader("Location", location);
        return b.responseBody(body == null ? "" : body).build();
    }

    static String find(DecodedNode n, String nameContains) {
        if (n.name().contains(nameContains) && n.value() != null) return n.value();
        for (DecodedNode c : n.children()) {
            String v = find(c, nameContains);
            if (v != null) return v;
        }
        return null;
    }

    static DecodedNode findNode(DecodedNode n, String name) {
        if (n.name().equals(name)) return n;
        for (DecodedNode c : n.children()) {
            DecodedNode v = findNode(c, name);
            if (v != null) return v;
        }
        return null;
    }

    static boolean anyWarning(DecodeResult r, String contains) {
        return r.warnings().stream().anyMatch(w -> w.contains(contains));
    }

    // ---------------------------------------------------------------- HTTP-POST binding

    @Test
    void postResponseSignedResponseAndAssertion() throws Exception {
        String xml = response(sig("_resp1", RSA_SHA256, SHA256), SUCCESS, goodAssertion(sig("_a1", RSA_SHA256, SHA256)));
        MessageContext m = postSamlResponse(xml);
        MatchResult mr = saml.match(m);
        assertEquals(95, mr.confidence());

        DecodeResult r = saml.decode(m);
        assertEquals("SAML Response (Success) — alice@example.com, 1 assertion, signed: Response ✔ Assertion ✔", r.summary());
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
        String tree = TreeText.render(r.root());
        assertEquals("HTTP-POST", find(r.root(), "Binding"));
        assertEquals("_resp1", find(r.root(), "ID"));
        assertEquals("https://sp.example.com/acs", find(r.root(), "Recipient"));
        assertEquals("_req1", find(r.root(), "InResponseTo"));
        assertEquals("https://sp.example.com", find(r.root(), "Audience"));
        assertEquals("_sess1", find(r.root(), "SessionIndex"));
        assertTrue(find(r.root(), "AuthnContextClassRef").endsWith("PasswordProtectedTransport"));
        assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", find(r.root(), "Format"));
        DecodedNode groups = findNode(r.root(), "groups");
        assertNotNull(groups, tree);
        assertEquals(2, groups.children().size());
        assertEquals("https://sp.example.com/home", find(findNode(r.root(), "RelayState"), "Value"));
        assertTrue(tree.contains("Resolves to"), tree);
        // Pretty XML in the text view.
        assertNotNull(r.text());
        assertTrue(r.text().contains("\n  <saml:Issuer>https://idp.example.com</saml:Issuer>"), r.text());
        assertTrue(r.text().contains("<saml:NameID"), r.text());
    }

    @Test
    void responseSignedButAssertionNot() throws Exception {
        DecodeResult r = saml.decode(postSamlResponse(response(sig("_resp1", RSA_SHA256, SHA256), SUCCESS, goodAssertion(""))));
        assertEquals("SAML Response (Success) — alice@example.com, 1 assertion, signed: Response ✔ Assertion ✘", r.summary());
        assertTrue(anyWarning(r, "Signature present on Response but not on every Assertion"), r.warnings().toString());
        assertTrue(anyWarning(r, "Assertion #1 is not signed"), r.warnings().toString());
    }

    @Test
    void onlyAssertionSigned() throws Exception {
        DecodeResult r = saml.decode(postSamlResponse(response("", SUCCESS, goodAssertion(sig("_a1", RSA_SHA256, SHA256)))));
        assertTrue(r.summary().endsWith("signed: Response ✘ Assertion ✔"), r.summary());
        assertTrue(anyWarning(r, "Response is not signed (only the Assertion)"), r.warnings().toString());
    }

    @Test
    void completelyUnsignedResponse() throws Exception {
        DecodeResult r = saml.decode(postSamlResponse(response("", SUCCESS, goodAssertion(""))));
        assertTrue(r.summary().endsWith("signed: Response ✘ Assertion ✘"), r.summary());
        assertTrue(anyWarning(r, "Neither the Response nor any Assertion is signed"), r.warnings().toString());
    }

    @Test
    void sha1SignatureAndDigestFlagged() throws Exception {
        DecodeResult r = saml.decode(postSamlResponse(response("", SUCCESS, goodAssertion(sig("_a1", RSA_SHA1, SHA1)))));
        assertTrue(anyWarning(r, "SHA-1 signature algorithm"), r.warnings().toString());
        assertTrue(anyWarning(r, "SHA-1 digest"), r.warnings().toString());
    }

    @Test
    void postBindingThatIsDeflatedAnyway() throws Exception {
        String xml = response("", SUCCESS, goodAssertion(sig("_a1", RSA_SHA256, SHA256)));
        DecodeResult r = saml.decode(post("SAMLResponse=" + enc(deflateB64(xml))));
        assertEquals("base64 + DEFLATE", find(r.root(), "Encoding"));
        assertTrue(r.summary().startsWith("SAML Response (Success) — alice@example.com"), r.summary());
    }

    @Test
    void unencodedPlusInFormValueIsTolerated() throws Exception {
        // Some clients forget to percent-encode '+', which the form decoder turns into a space.
        String xml = response("", SUCCESS, goodAssertion("")) + "<!-- padding to force + and / in base64: ~~~~>>>>???? -->";
        String b = b64(xml);
        assertTrue(b.contains("+") || b.contains("/"));
        DecodeResult r = saml.decode(post("SAMLResponse=" + b.replace("=", "%3D")));
        assertTrue(r.summary().startsWith("SAML Response"), r.summary());
    }

    // ---------------------------------------------------------------- HTTP-Redirect binding

    @Test
    void redirectAuthnRequestWithQuerySignature() throws Exception {
        String url = "https://idp.example.com/sso?SAMLRequest=" + enc(deflateB64(AUTHN_REQUEST)) + "&RelayState=xyz"
                + "&SigAlg=" + enc(RSA_SHA1) + "&Signature=" + enc(Base64.getEncoder().encodeToString(new byte[256]));
        MessageContext m = get(url);
        assertEquals(95, saml.match(m).confidence());
        DecodeResult r = saml.decode(m);
        assertEquals("SAML AuthnRequest — from https://sp.example.com, signed: AuthnRequest ✔ (query)", r.summary());
        assertEquals("base64 + DEFLATE", find(r.root(), "Encoding"));
        assertEquals("https://sp.example.com/acs", find(r.root(), "AssertionConsumerServiceURL"));
        assertEquals("https://idp.example.com/sso", find(r.root(), "Destination"));
        assertEquals("true", find(findNode(r.root(), "NameIDPolicy"), "AllowCreate"));
        assertEquals("256", find(r.root(), "Signature bytes"));
        assertTrue(find(r.root(), "SigAlg").contains("RSA-SHA1"));
        assertTrue(anyWarning(r, "SigAlg uses SHA-1"), r.warnings().toString());
        assertFalse(anyWarning(r, "is not signed"), r.warnings().toString());
        assertTrue(r.text().contains("<samlp:AuthnRequest"), r.text());
    }

    @Test
    void unsignedRedirectAuthnRequest() throws Exception {
        DecodeResult r = saml.decode(get("https://idp.example.com/sso?SAMLRequest=" + enc(deflateB64(AUTHN_REQUEST))));
        assertTrue(r.summary().endsWith("signed: AuthnRequest ✘"), r.summary());
        assertTrue(anyWarning(r, "AuthnRequest is not signed"), r.warnings().toString());
    }

    @Test
    void redirectWithoutDeflateIsNotedButDecoded() throws Exception {
        DecodeResult r = saml.decode(get("https://idp.example.com/sso?SAMLRequest=" + enc(b64(AUTHN_REQUEST))));
        assertTrue(r.summary().startsWith("SAML AuthnRequest"), r.summary());
        assertTrue(anyWarning(r, "not DEFLATE-compressed"), r.warnings().toString());
    }

    @Test
    void locationHeaderRedirectInResponse() throws Exception {
        String loc = "https://idp.example.com/sso?SAMLRequest=" + enc(deflateB64(AUTHN_REQUEST)) + "&RelayState=abc";
        MessageContext m = response("https://sp.example.com/login", 302, "text/html", "", loc);
        assertEquals(90, saml.match(m).confidence());
        DecodeResult r = saml.decode(m);
        assertTrue(r.summary().startsWith("SAML AuthnRequest"), r.summary());
        assertEquals("https://idp.example.com/sso", find(r.root(), "Endpoint"));
    }

    @Test
    void logoutRequestUnsigned() throws Exception {
        String xml = "<samlp:LogoutRequest " + NS + " ID=\"_lo1\" Version=\"2.0\" IssueInstant=\"2026-01-01T11:00:00Z\">"
                + "<saml:Issuer>https://sp.example.com</saml:Issuer><saml:NameID>alice@example.com</saml:NameID>"
                + "<samlp:SessionIndex>_sess1</samlp:SessionIndex></samlp:LogoutRequest>";
        DecodeResult r = saml.decode(get("https://idp.example.com/slo?SAMLRequest=" + enc(deflateB64(xml))));
        assertEquals("SAML LogoutRequest — alice@example.com, signed: LogoutRequest ✘", r.summary());
        assertEquals("_sess1", find(r.root(), "SessionIndex"));
        assertTrue(anyWarning(r, "LogoutRequest is not signed"));
    }

    // ---------------------------------------------------------------- HTML auto-post form

    @Test
    void htmlAutoSubmitFormInResponse() throws Exception {
        String xml = response(sig("_resp1", RSA_SHA256, SHA256), SUCCESS, goodAssertion(sig("_a1", RSA_SHA256, SHA256)));
        String value = b64(xml).replace("+", "&#x2b;").replace("=", "&#61;");
        String html = "<html><body onload=\"document.forms[0].submit()\"><form method=\"post\" action=\"https://sp.example.com/acs\">"
                + "<input type=\"hidden\" name=\"SAMLResponse\" value=\"" + value + "\"/>"
                + "<input type='hidden' name='RelayState' value='token&amp;x'/>"
                + "<noscript><input type=\"submit\" value=\"Continue\"/></noscript></form></body></html>";
        MessageContext m = response("https://idp.example.com/sso", 200, "text/html; charset=utf-8", html, null);
        assertEquals(80, saml.match(m).confidence());
        DecodeResult r = saml.decode(m);
        assertEquals("SAML Response (Success) — alice@example.com, 1 assertion, signed: Response ✔ Assertion ✔", r.summary());
        assertEquals("https://sp.example.com/acs", find(r.root(), "Endpoint"));
        assertEquals("token&x", find(findNode(r.root(), "RelayState"), "Value"));
        assertEquals("HTTP-POST (auto-submit form)", find(r.root(), "Binding"));
    }

    // ---------------------------------------------------------------- Artifact binding

    @Test
    void artifactBinding() throws Exception {
        byte[] source = MessageDigest.getInstance("SHA-1").digest("https://idp.example.com".getBytes(StandardCharsets.UTF_8));
        byte[] art = new byte[44];
        art[1] = 4;
        art[3] = 2;
        System.arraycopy(source, 0, art, 4, 20);
        for (int i = 0; i < 20; i++) art[24 + i] = (byte) (i * 13 + 7);
        String a = Base64.getEncoder().encodeToString(art);
        MessageContext m = get("https://sp.example.com/acs?SAMLart=" + enc(a) + "&RelayState=r1");
        assertEquals(95, saml.match(m).confidence());
        DecodeResult r = saml.decode(m);
        assertTrue(r.summary().startsWith("SAML artifact — SAML 2.0 artifact, endpoint 2"), r.summary());
        assertEquals("0x0004", find(r.root(), "TypeCode"));
        assertEquals("2", find(r.root(), "EndpointIndex"));
        assertEquals(HexFormat.of().formatHex(source), find(r.root(), "SourceID"));
        assertEquals(HexFormat.of().formatHex(art, 24, 44), find(r.root(), "MessageHandle"));
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
    }

    @Test
    void artifactWithPredictableHandle() throws Exception {
        byte[] art = new byte[44];
        art[1] = 4;
        DecodeResult r = saml.decode(post("SAMLart=" + enc(Base64.getEncoder().encodeToString(art))));
        assertTrue(anyWarning(r, "low-entropy"), r.warnings().toString());
    }

    @Test
    void soapArtifactResolve() throws Exception {
        byte[] art = new byte[44];
        art[1] = 4;
        for (int i = 4; i < 44; i++) art[i] = (byte) (i * 31);
        String body = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body>"
                + "<samlp:ArtifactResolve " + NS + " ID=\"_ar1\" Version=\"2.0\" IssueInstant=\"2026-01-01T10:00:00Z\">"
                + "<saml:Issuer>https://sp.example.com</saml:Issuer>"
                + "<samlp:Artifact>" + Base64.getEncoder().encodeToString(art) + "</samlp:Artifact>"
                + "</samlp:ArtifactResolve></soap:Body></soap:Envelope>";
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://idp.example.com/ars")
                .requestHeader("Content-Type", "text/xml").requestBody(body).build();
        assertEquals(85, saml.match(m).confidence());
        DecodeResult r = saml.decode(m);
        assertTrue(r.summary().startsWith("SAML ArtifactResolve"), r.summary());
        assertEquals("0x0004", find(r.root(), "TypeCode"));
        assertTrue(find(r.root(), "Message type").contains("inside Envelope"));
    }

    // ---------------------------------------------------------------- WS-Federation

    static final String RSTR = "<t:RequestSecurityTokenResponse xmlns:t=\"http://schemas.xmlsoap.org/ws/2005/02/trust\">"
            + "<t:Lifetime><wsu:Created xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">2026-01-01T10:00:00Z</wsu:Created>"
            + "<wsu:Expires xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">2026-01-01T11:00:00Z</wsu:Expires></t:Lifetime>"
            + "<wsp:AppliesTo xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\"><wsa:EndpointReference xmlns:wsa=\"http://www.w3.org/2005/08/addressing\">"
            + "<wsa:Address>urn:app</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>"
            + "<t:RequestedSecurityToken>"
            + "<saml1:Assertion xmlns:saml1=\"urn:oasis:names:tc:SAML:1.0:assertion\" MajorVersion=\"1\" MinorVersion=\"1\" AssertionID=\"_s11\""
            + " Issuer=\"http://adfs.example.com/adfs/services/trust\" IssueInstant=\"2026-01-01T10:00:00Z\">"
            + "<saml1:Conditions NotBefore=\"2026-01-01T10:00:00Z\" NotOnOrAfter=\"2026-01-01T11:00:00Z\">"
            + "<saml1:AudienceRestrictionCondition><saml1:Audience>urn:app</saml1:Audience></saml1:AudienceRestrictionCondition></saml1:Conditions>"
            + "<saml1:AttributeStatement><saml1:Subject><saml1:NameIdentifier>bob</saml1:NameIdentifier></saml1:Subject>"
            + "<saml1:Attribute AttributeName=\"upn\" AttributeNamespace=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims\">"
            + "<saml1:AttributeValue>bob@example.com</saml1:AttributeValue></saml1:Attribute></saml1:AttributeStatement>"
            + "<saml1:AuthenticationStatement AuthenticationMethod=\"urn:oasis:names:tc:SAML:1.0:am:password\" AuthenticationInstant=\"2026-01-01T10:00:00Z\">"
            + "<saml1:Subject><saml1:NameIdentifier>bob</saml1:NameIdentifier></saml1:Subject></saml1:AuthenticationStatement>"
            + sig("_s11", RSA_SHA256, SHA256)
            + "</saml1:Assertion></t:RequestedSecurityToken></t:RequestSecurityTokenResponse>";

    @Test
    void wsFedSignInResponse() throws Exception {
        MessageContext m = post("wa=wsignin1.0&wresult=" + enc(RSTR) + "&wctx=" + enc("rm=0&id=passive&ru=/home"));
        assertEquals(90, saml.match(m).confidence());
        DecodeResult r = saml.decode(m);
        assertEquals("WS-Fed wsignin1.0 — bob, 1 SAML 1.1 assertion, signed: Assertion ✔", r.summary());
        assertEquals("SAML 1.1", find(r.root(), "SAML version"));
        assertEquals("urn:app", find(r.root(), "AppliesTo"));
        assertEquals("bob@example.com", find(r.root(), "upn"));
        assertEquals("urn:oasis:names:tc:SAML:1.0:am:password", find(r.root(), "AuthenticationMethod"));
        assertEquals("rm=0&id=passive&ru=/home", find(r.root(), "wctx"));
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
        assertTrue(r.text().contains("<saml1:Assertion"), r.text());
    }

    @Test
    void wsFedAutoPostFormFromAdfs() throws Exception {
        String html = "<html><body><form method=\"POST\" name=\"hiddenform\" action=\"https://app.example.com/\">"
                + "<input type=\"hidden\" name=\"wa\" value=\"wsignin1.0\" />"
                + "<input type=\"hidden\" name=\"wresult\" value=\"" + RSTR.replace("&", "&amp;").replace("<", "&lt;").replace("\"", "&quot;") + "\" />"
                + "</form></body></html>";
        MessageContext m = response("https://adfs.example.com/adfs/ls/", 200, "text/html", html, null);
        assertEquals(80, saml.match(m).confidence());
        DecodeResult r = saml.decode(m);
        assertTrue(r.summary().startsWith("WS-Fed wsignin1.0 — bob"), r.summary());
    }

    @Test
    void wsFedSignInRequest() throws Exception {
        MessageContext m = get("https://adfs.example.com/adfs/ls/?wa=wsignin1.0&wtrealm=" + enc("urn:app") + "&wctx=abc");
        assertEquals(75, saml.match(m).confidence());
        DecodeResult r = saml.decode(m);
        assertEquals("WS-Fed wsignin1.0 (sign-in) → realm urn:app", r.summary());
        assertEquals("urn:app", find(r.root(), "wtrealm"));
        assertNull(r.text());
    }

    // ---------------------------------------------------------------- status, encryption, wrapping, validity

    @Test
    void statusError() throws Exception {
        String status = "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Responder\">"
                + "<samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:AuthnFailed\"/></samlp:StatusCode>"
                + "<samlp:StatusMessage>Invalid credentials</samlp:StatusMessage>";
        DecodeResult r = saml.decode(postSamlResponse(response(sig("_resp1", RSA_SHA256, SHA256), status, "")));
        assertEquals("SAML Response (Responder/AuthnFailed) — 0 assertions, signed: Response ✔", r.summary());
        assertEquals("Invalid credentials", find(r.root(), "StatusMessage"));
        assertEquals("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed", find(r.root(), "Second-level StatusCode"));
    }

    @Test
    void encryptedAssertion() throws Exception {
        String enc = "<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\">"
                + "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/>"
                + "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><xenc:EncryptedKey>"
                + "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\"/>"
                + "<ds:KeyInfo><ds:KeyName>sp-encryption-key</ds:KeyName></ds:KeyInfo>"
                + "<xenc:CipherData><xenc:CipherValue>AAAA</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>"
                + "<xenc:CipherData><xenc:CipherValue>" + Base64.getEncoder().encodeToString(new byte[64]) + "</xenc:CipherValue></xenc:CipherData>"
                + "</xenc:EncryptedData></saml:EncryptedAssertion>";
        DecodeResult r = saml.decode(postSamlResponse(response(sig("_resp1", RSA_SHA256, SHA256), SUCCESS, enc)));
        assertEquals("SAML Response (Success) — 0 assertions, 1 encrypted, signed: Response ✔", r.summary());
        assertEquals("http://www.w3.org/2001/04/xmlenc#aes128-cbc", find(r.root(), "Data encryption"));
        assertEquals("http://www.w3.org/2001/04/xmlenc#rsa-1_5", find(r.root(), "Key transport"));
        assertEquals("sp-encryption-key", find(r.root(), "KeyName"));
        assertEquals("64", find(r.root(), "CipherValue bytes"));
        assertTrue(anyWarning(r, "EncryptedAssertion(s): contents cannot be decoded"), r.warnings().toString());
        assertTrue(anyWarning(r, "PKCS#1 v1.5"), r.warnings().toString());
        assertTrue(anyWarning(r, "CBC"), r.warnings().toString());
        assertFalse(anyWarning(r, "is not signed"), r.warnings().toString());
    }

    @Test
    void multipleAssertionsAndWrappingIndicators() throws Exception {
        // Classic XSW shape: an evil unsigned assertion plus the original signed one tucked inside Extensions,
        // and a Response signature that points at the inner element.
        String original = goodAssertion(sig("_a1", RSA_SHA256, SHA256));
        String evil = assertion("_a1", "", "admin@example.com", conditions("2026-01-01T09:59:05Z", "2026-01-01T10:05:05Z", true));
        String xml = response(sig("_a1", RSA_SHA256, SHA256), SUCCESS, "<samlp:Extensions>" + original + "</samlp:Extensions>" + evil);
        DecodeResult r = saml.decode(postSamlResponse(xml));
        assertTrue(anyWarning(r, "2 assertions"), r.warnings().toString());
        assertTrue(anyWarning(r, "is used by 2 elements"), r.warnings().toString());
        assertTrue(anyWarning(r, "unusual location (/Response/Extensions/Assertion)"), r.warnings().toString());
        assertTrue(anyWarning(r, "signed element is not the enveloping one"), r.warnings().toString());
    }

    @Test
    void danglingSignatureReference() throws Exception {
        DecodeResult r = saml.decode(postSamlResponse(response(sig("_nope", RSA_SHA256, SHA256), SUCCESS, goodAssertion(""))));
        assertTrue(anyWarning(r, "does not match any element ID"), r.warnings().toString());
        assertTrue(r.summary().contains("Response ✘"), r.summary());
    }

    @Test
    void commentInsideNameId() throws Exception {
        String a = assertion("_a1", sig("_a1", RSA_SHA256, SHA256), "alice@example.com<!---->.evil.com",
                conditions("2026-01-01T09:59:05Z", "2026-01-01T10:05:05Z", true));
        DecodeResult r = saml.decode(postSamlResponse(response("", SUCCESS, a)));
        assertTrue(anyWarning(r, "contains an XML comment"), r.warnings().toString());
        assertEquals("alice@example.com", find(r.root(), "NameID (first text node only)"));
        assertTrue(r.text().contains("alice@example.com\n") || r.text().contains("<!---->"), r.text());
        assertTrue(r.text().contains("<!---->"), "comment must survive pretty printing:\n" + r.text());
    }

    @Test
    void expiredConditionsAndMissingAudience() throws Exception {
        String a = assertion("_a1", sig("_a1", RSA_SHA256, SHA256), "alice@example.com",
                conditions("2025-12-01T00:00:00Z", "2025-12-31T00:00:00Z", false));
        DecodeResult r = saml.decode(postSamlResponse(response("", SUCCESS, a)));
        assertTrue(anyWarning(r, "expired when issued"), r.warnings().toString());
        assertTrue(anyWarning(r, "no AudienceRestriction"), r.warnings().toString());
        assertTrue(anyWarning(r, "validity window is long"), r.warnings().toString());
    }

    @Test
    void notYetValidConditions() throws Exception {
        String a = assertion("_a1", sig("_a1", RSA_SHA256, SHA256), "alice@example.com",
                conditions("2026-01-02T00:00:00Z", "2026-01-02T00:05:00Z", true));
        DecodeResult r = saml.decode(postSamlResponse(response("", SUCCESS, a)));
        assertTrue(anyWarning(r, "not yet valid when issued"), r.warnings().toString());
    }

    // ---------------------------------------------------------------- XML hardening

    @Test
    void xxePayloadIsNotResolved(@TempDir Path dir) throws Exception {
        Path secret = dir.resolve("secret.txt");
        Files.writeString(secret, "TOP-SECRET-MARKER-42");
        String xxe = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"" + secret.toUri() + "\">]>"
                + "<samlp:Response " + NS + " ID=\"_x\"><saml:Issuer>&xxe;</saml:Issuer></samlp:Response>";
        MessageContext m = postSamlResponse(xxe);
        assertEquals(95, saml.match(m).confidence());
        DecodeResult r = saml.decode(m);
        assertTrue(anyWarning(r, "DOCTYPE"), r.warnings().toString());
        assertTrue(anyWarning(r, "XXE"), r.warnings().toString());
        assertFalse(TreeText.render(r.root()).contains("TOP-SECRET-MARKER-42"));
        assertFalse(r.renderedText().contains("TOP-SECRET-MARKER-42"));

        SafeXml.XmlException ex = assertThrows(SafeXml.XmlException.class, () -> SafeXml.parse(xxe));
        assertTrue(ex.doctype);
    }

    @Test
    void billionLaughsAndExternalDtdRefused() {
        String lol = "<!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">"
                + "<!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">]><lolz>&lol3;</lolz>";
        assertTrue(assertThrows(SafeXml.XmlException.class, () -> SafeXml.parse(lol)).doctype);
        String extDtd = "<!DOCTYPE r SYSTEM \"http://127.0.0.1:1/evil.dtd\"><r/>";
        assertTrue(assertThrows(SafeXml.XmlException.class, () -> SafeXml.parse(extDtd)).doctype);
        // XInclude must not be processed either.
        String xi = "<r xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/passwd\" parse=\"text\"/></r>";
        assertDoesNotThrow(() -> {
            String pretty = SafeXml.pretty(SafeXml.parse(xi));
            assertTrue(pretty.contains("xi:include"), pretty);
            assertFalse(pretty.contains("root:"), pretty);
        });
    }

    @Test
    void malformedXmlReportedNotThrown() throws Exception {
        DecodeResult r = saml.decode(post("SAMLResponse=" + enc(b64("<samlp:Response><unclosed>"))));
        assertTrue(anyWarning(r, "malformed XML"), r.warnings().toString());
        assertTrue(r.renderedText().contains("<unclosed>"));
    }

    // ---------------------------------------------------------------- negative and forced cases

    @Test
    void doesNotMatchUnrelatedTraffic() {
        assertEquals(MatchResult.NONE, saml.match(get("https://example.com/search?q=SAMLResponse")));
        assertEquals(MatchResult.NONE, saml.match(get("https://example.com/x?xSAMLResponse=abc")));
        assertEquals(MatchResult.NONE, saml.match(post("username=alice&password=secret")));
        assertEquals(MatchResult.NONE, saml.match(MessageContext.builder(MessageKind.REQUEST).method("POST")
                .url("https://api.example.com/v1").requestHeader("Content-Type", "application/json")
                .requestBody("{\"note\":\"SAMLResponse is cool\"}").build()));
        assertEquals(MatchResult.NONE, saml.match(response("https://example.com/", 200, "text/html",
                "<html><body><p>We support SAML single sign-on.</p><input name=\"q\"></body></html>", null)));
        assertEquals(MatchResult.NONE, saml.match(MessageContext.builder(MessageKind.WEBSOCKET).url("wss://x/")
                .webSocket("CLIENT_TO_SERVER", "SAMLResponse=abc".getBytes(StandardCharsets.UTF_8)).build()));
        assertEquals(MatchResult.NONE, saml.match(response("https://example.com/", 302, null, "", "https://example.com/next?a=1")));
    }

    @Test
    void forcedDecodeOnGarbageThrows() {
        DecodeException e = assertThrows(DecodeException.class, () -> saml.decode(post("foo=bar&baz=1")));
        assertTrue(e.getMessage().contains("No SAML"), e.getMessage());
        assertThrows(DecodeException.class, () -> saml.decode(response("https://example.com/", 200, "text/html", "<html>hi</html>", null)));
        assertThrows(DecodeException.class, () -> saml.decode(MessageContext.builder(MessageKind.WEBSOCKET).url("wss://x/")
                .webSocket("CLIENT_TO_SERVER", new byte[]{1, 2, 3}).build()));
    }

    @Test
    void garbageSamlParameterGivesWarningsNotCrash() throws Exception {
        DecodeResult r = saml.decode(post("SAMLResponse=" + enc("!!!not base64!!!")));
        assertTrue(anyWarning(r, "not valid base64"), r.warnings().toString());
        DecodeResult r2 = saml.decode(post("SAMLResponse=" + enc(Base64.getEncoder().encodeToString(new byte[]{9, 8, 7, 6, 5, 4, 3}))));
        assertTrue(anyWarning(r2, "not XML"), r2.warnings().toString());
        DecodeResult r3 = saml.decode(post("SAMLart=" + enc("AAAA")));
        assertFalse(r3.warnings().isEmpty());
    }

    @Test
    void matchNeverThrowsOnOddInput() {
        List<MessageContext> odd = List.of(
                MessageContext.builder(MessageKind.REQUEST).build(),
                MessageContext.builder(MessageKind.RESPONSE).build(),
                get("https://x/?SAMLRequest"),
                response("https://x/", 200, "text/html", "<input name=SAMLResponse value=", null));
        for (MessageContext m : odd) assertDoesNotThrow(() -> saml.match(m));
        assertEquals(80, saml.match(odd.get(3)).confidence());
    }
}
