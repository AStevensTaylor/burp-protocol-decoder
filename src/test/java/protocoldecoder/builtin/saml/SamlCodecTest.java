package protocoldecoder.builtin.saml;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.edit.EditEngine;
import protocoldecoder.edit.EditableDocument;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.edit.MessagePatch;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.util.Codecs;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.*;
import static protocoldecoder.builtin.saml.SamlDecoderTest.*;

class SamlCodecTest {

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });
    final SamlDecoder decoder = new SamlDecoder();
    final SamlCodec codec = new SamlCodec();

    @AfterEach
    void close() {
        app.close();
    }

    List<EditableDocument> docs(MessageContext m) throws Exception {
        return codec.documents(m, decoder.decode(m));
    }

    static EditableDocument doc(List<EditableDocument> docs, String titlePart) {
        return docs.stream().filter(d -> d.title().contains(titlePart)).findFirst()
                .orElseThrow(() -> new AssertionError(docs.stream().map(EditableDocument::title).toList().toString()));
    }

    static final String UNSIGNED = response("", SUCCESS, goodAssertion(""));
    static final String SIGNED = response("", SUCCESS, goodAssertion(sig("_a1", RSA_SHA256, SHA256)));

    @Test
    void postBindingEndToEnd() throws Exception {
        MessageContext m = postSamlResponse(UNSIGNED);
        List<EditEngine.Document> all = app.editEngine().documents(m);
        assertEquals(List.of("SAMLResponse (XML)", "RelayState"), all.stream().map(d -> d.document().title()).toList());
        EditEngine.Document d = all.get(0);
        assertEquals("xml", d.document().syntax());
        assertFalse(d.document().text().contains("Protocol Decoder:"), "unsigned: no note");
        assertTrue(d.document().text().contains("\n  <saml:Issuer>"), "pretty-printed");

        // exact round trip
        MessageContext same = EditEngine.encode(d, d.document().text()).applyTo(m);
        assertArrayEquals(m.requestBody(), same.requestBody());

        // edit: the user's text is sent as written (base64, form-encoded), other params kept
        String edited = d.document().text().replace("alice@example.com</saml:NameID>", "mallory@example.com</saml:NameID>");
        MessageContext out = EditEngine.encode(d, edited).applyTo(m);
        String body = out.requestBodyText();
        assertTrue(body.endsWith("&RelayState=" + enc("https://sp.example.com/home")), body);
        String xml = new String(Codecs.base64Decode(Codecs.first(Codecs.parseQuery(body), "SAMLResponse")), StandardCharsets.UTF_8);
        assertEquals(edited, xml);
        DecodeResult r = app.engine().decode(out).result();
        assertTrue(r.text().contains("mallory@example.com"), r.text());
    }

    @Test
    void signedResponseGetsNoteAndPrefixAndNoteIsStripped() throws Exception {
        MessageContext m = postSamlResponse(SIGNED);
        EditableDocument d = doc(docs(m), "SAMLResponse");
        assertEquals("(signed) SAMLResponse (XML)", d.title());
        assertTrue(d.text().startsWith("<!-- Protocol Decoder: this SAMLResponse carries an XML signature."), d.text());
        String edited = d.text().replace("alice@example.com</saml:NameID>", "admin@example.com</saml:NameID>");
        MessagePatch p = d.encode(edited);
        String xml = new String(Codecs.base64Decode(Codecs.first(Codecs.parseQuery(new String(p.body(), StandardCharsets.UTF_8)), "SAMLResponse")), StandardCharsets.UTF_8);
        assertFalse(xml.contains("Protocol Decoder"), xml);
        assertTrue(xml.startsWith("<samlp:Response"), xml);
        assertTrue(xml.contains("admin@example.com"));
    }

    @Test
    void xmlDeclarationStaysFirst() throws Exception {
        MessageContext m = postSamlResponse("<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + SIGNED);
        EditableDocument d = doc(docs(m), "SAMLResponse");
        assertTrue(d.text().startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- Protocol Decoder:"), d.text());
        assertArrayEquals(m.requestBody(), d.encode(d.text()).body());
        MessagePatch p = d.encode(d.text().replace("_sess1", "_sess2"));
        String xml = new String(Codecs.base64Decode(Codecs.first(Codecs.parseQuery(new String(p.body(), StandardCharsets.UTF_8)), "SAMLResponse")), StandardCharsets.UTF_8);
        assertTrue(xml.startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<samlp:Response"), xml);
    }

    @Test
    void redirectBindingDeflatesAndWarnsAboutQuerySignature() throws Exception {
        String q = "SAMLRequest=" + enc(deflateB64(AUTHN_REQUEST)) + "&RelayState=abc&SigAlg=" + enc(RSA_SHA256) + "&Signature=" + enc("c2ln");
        MessageContext m = get("https://idp.example.com/sso?" + q);
        List<EditableDocument> docs = docs(m);
        EditableDocument d = doc(docs, "SAMLRequest");
        assertEquals("(signed) SAMLRequest (XML)", d.title());
        assertTrue(d.text().contains("HTTP-Redirect query string is signed"), d.text());
        assertEquals("(signed) RelayState", doc(docs, "RelayState").title());
        assertEquals(q, d.encode(d.text()).query());

        MessagePatch p = d.encode(d.text().replace("https://sp.example.com/acs", "https://evil.example/acs"));
        MessageContext out = p.applyTo(m);
        assertTrue(out.query().endsWith("&RelayState=abc&SigAlg=" + enc(RSA_SHA256) + "&Signature=c2ln"), out.query());
        byte[] raw = Codecs.base64Decode(Codecs.first(out.queryParameters(), "SAMLRequest"));
        assertFalse(Codecs.isZlib(raw), "raw DEFLATE like the original");
        String xml = new String(Codecs.inflate(raw), StandardCharsets.UTF_8);
        assertTrue(xml.contains("AssertionConsumerServiceURL=\"https://evil.example/acs\""), xml);
        assertTrue(app.engine().decode(out).result().text().contains("https://evil.example/acs"));
    }

    @Test
    void relayStateIsPlainText() throws Exception {
        MessageContext m = postSamlResponse(UNSIGNED);
        EditableDocument d = doc(docs(m), "RelayState");
        assertEquals("text", d.syntax());
        assertEquals("https://sp.example.com/home", d.text());
        assertArrayEquals(m.requestBody(), d.encode(d.text()).body());
        MessageContext out = d.encode("https://evil.example/?a=1&b=ü").applyTo(m);
        assertEquals("https://evil.example/?a=1&b=ü", Codecs.first(out.formParameters(), "RelayState"));
        assertNotNull(Codecs.first(out.formParameters(), "SAMLResponse"));
    }

    @Test
    void invalidXmlAndDoctypeAreRejected() throws Exception {
        EditableDocument d = doc(docs(postSamlResponse(UNSIGNED)), "SAMLResponse");
        EncodeException e = assertThrows(EncodeException.class, () -> d.encode("<samlp:Response><unclosed></samlp:Response>"));
        assertTrue(e.getMessage().contains("malformed XML"), e.getMessage());
        EncodeException x = assertThrows(EncodeException.class,
                () -> d.encode("<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>"));
        assertTrue(x.getMessage().contains("DOCTYPE"), x.getMessage());
        assertThrows(EncodeException.class, () -> d.encode("   "));
    }

    @Test
    void unicodeAndQuotesInXml() throws Exception {
        MessageContext m = postSamlResponse(UNSIGNED);
        EditableDocument d = doc(docs(m), "SAMLResponse");
        String edited = d.text().replace(">alice@example.com</saml:NameID>", ">jörg+\"q\" &amp; 'x' ☃@example.com</saml:NameID>");
        MessageContext out = d.encode(edited).applyTo(m);
        String xml = new String(Codecs.base64Decode(Codecs.first(out.formParameters(), "SAMLResponse")), StandardCharsets.UTF_8);
        assertTrue(xml.contains("jörg+\"q\" &amp; 'x' ☃@example.com"), xml);
        assertTrue(app.engine().decode(out).result().text().contains("jörg"));
    }

    @Test
    void wsFedWresultInRequestBody() throws Exception {
        MessageContext m = post("wa=wsignin1.0&wresult=" + enc(RSTR) + "&wctx=" + enc("rm=0&id=passive&ru=/home"));
        EditableDocument d = doc(docs(m), "wresult");
        assertEquals("(signed) wresult (XML)", d.title());
        assertArrayEquals(m.requestBody(), d.encode(d.text()).body());
        MessageContext out = d.encode(d.text().replace(">bob<", ">eve<")).applyTo(m);
        String wresult = Codecs.first(out.formParameters(), "wresult");
        assertTrue(wresult.startsWith("<t:RequestSecurityTokenResponse"), "raw XML, not base64");
        assertTrue(wresult.contains(">eve<"));
        assertEquals("rm=0&id=passive&ru=/home", Codecs.first(out.formParameters(), "wctx"));
        assertTrue(app.engine().decode(out).result().summary().contains("eve"), app.engine().decode(out).result().summary());
    }

    static String autoPost(String samlResponse, String relay) {
        return "<html><body onload=\"document.forms[0].submit()\"><form method=\"post\" action=\"https://sp.example.com/acs\">"
                + "<input type=\"hidden\" name=\"SAMLResponse\" value=\"" + samlResponse + "\"/>"
                + "<input type='hidden' name='RelayState' value='" + relay + "'/>"
                + "<noscript><input type=\"submit\" value=\"Continue\"/></noscript></form></body></html>";
    }

    @Test
    void htmlAutoSubmitFormInResponse() throws Exception {
        String html = autoPost(b64(UNSIGNED), "a&amp;b");
        MessageContext m = response("https://idp.example.com/sso", 200, "text/html", html, null);
        List<EditEngine.Document> all = app.editEngine().documents(m);
        EditableDocument d = all.stream().filter(x -> x.document().title().equals("SAMLResponse (XML)")).findFirst().orElseThrow().document();
        assertArrayEquals(m.responseBody(), d.encode(d.text()).body());
        MessageContext out = d.encode(d.text().replace("alice@example.com</saml:NameID>", "eve@example.com</saml:NameID>")).applyTo(m);
        String body = out.responseBodyText();
        assertTrue(body.startsWith("<html><body onload=\"document.forms[0].submit()\"><form method=\"post\""), body);
        assertTrue(body.contains("<input type='hidden' name='RelayState' value='a&amp;b'/>"));
        assertTrue(app.engine().decode(out).result().text().contains("eve@example.com"));

        EditableDocument relay = all.stream().filter(x -> x.document().title().equals("RelayState")).findFirst().orElseThrow().document();
        assertEquals("a&b", relay.text());
        String nb = relay.encode("x'<y>\"&").applyTo(m).responseBodyText();
        assertTrue(nb.contains("name='RelayState' value='x&#39;&lt;y&gt;&quot;&amp;'/>"), nb);
        assertEquals("x'<y>\"&", SamlDecoder.htmlInputs(nb).get("RelayState").get(0));
    }

    @Test
    void htmlWresultIsHtmlEscapedXmlAndGzipIsRestored() throws Exception {
        String html = "<form method=\"POST\" action=\"https://app.example.com/\"><input type=\"hidden\" name=\"wa\" value=\"wsignin1.0\" />"
                + "<input type=\"hidden\" name=\"wresult\" value=\"" + RSTR.replace("&", "&amp;").replace("<", "&lt;").replace("\"", "&quot;") + "\" /></form>";
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
            gz.write(html.getBytes(StandardCharsets.UTF_8));
        }
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://adfs.example.com/adfs/ls/").statusCode(200)
                .responseHeader("Content-Type", "text/html").responseHeader("Content-Encoding", "gzip").responseBody(bos.toByteArray()).build();
        EditableDocument d = doc(docs(m), "wresult");
        assertTrue(Arrays.equals(m.responseBody(), d.encode(d.text()).body()));
        MessageContext out = d.encode(d.text().replace(">bob<", ">eve \"x\" &amp; y<")).applyTo(m);
        assertTrue(Codecs.isGzip(out.responseBody()));
        String plain = new String(Codecs.gunzip(out.responseBody()), StandardCharsets.UTF_8);
        assertTrue(plain.contains("&gt;eve &quot;x&quot; &amp;amp; y&lt;"), plain);
        String wresult = SamlDecoder.htmlInputs(plain).get("wresult").get(0);
        assertTrue(wresult.contains(">eve \"x\" &amp; y<"), wresult);
        assertTrue(decoder.decode(out).summary().contains("eve"));
    }

    @Test
    void redirectLocationHeaderInResponse() throws Exception {
        String loc = "https://idp.example.com/sso?SAMLRequest=" + enc(deflateB64(AUTHN_REQUEST)) + "&RelayState=xyz#frag";
        MessageContext m = response("https://sp.example.com/login", 302, null, "", loc);
        EditableDocument d = doc(docs(m), "SAMLRequest");
        assertEquals(loc, d.encode(d.text()).headers().get("Location"));
        String nl = d.encode(d.text().replace("https://sp.example.com</saml:Issuer>", "https://other.example</saml:Issuer>")).headers().get("Location");
        assertTrue(nl.startsWith("https://idp.example.com/sso?SAMLRequest="), nl);
        assertTrue(nl.endsWith("&RelayState=xyz#frag"), nl);
        String q = nl.substring(nl.indexOf('?') + 1, nl.indexOf('#'));
        String xml = new String(Codecs.inflate(Codecs.base64Decode(Codecs.first(Codecs.parseQuery(q), "SAMLRequest"))), StandardCharsets.UTF_8);
        assertTrue(xml.contains("https://other.example"));
    }

    @Test
    void zlibWrappedPostIsReDeflatedTheSameWay() throws Exception {
        java.util.zip.Deflater def = new java.util.zip.Deflater(java.util.zip.Deflater.DEFAULT_COMPRESSION, false);
        def.setInput(UNSIGNED.getBytes(StandardCharsets.UTF_8));
        def.finish();
        byte[] buf = new byte[65536];
        int n = def.deflate(buf);
        def.end();
        MessageContext m = post("SAMLResponse=" + enc(Codecs.base64Encode(Arrays.copyOf(buf, n))));
        EditableDocument d = doc(docs(m), "SAMLResponse");
        MessageContext out = d.encode(d.text().replace("_sess1", "_sess9")).applyTo(m);
        byte[] raw = Codecs.base64Decode(Codecs.first(out.formParameters(), "SAMLResponse"));
        assertTrue(Codecs.isZlib(raw));
        assertTrue(new String(Codecs.inflate(raw), StandardCharsets.UTF_8).contains("_sess9"));
    }

    @Test
    void nothingForUnparseableXmlOrArtifacts() throws Exception {
        assertTrue(docs(post("SAMLResponse=" + enc(b64("<samlp:Response><broken>")))).stream().noneMatch(d -> d.title().contains("XML")));
        MessageContext art = get("https://sp.example.com/acs?SAMLart=" + enc("AAQAAMh48/1oXIM+sDo7Dh2qMp1HM4IF5DaRNmDj6RdUmllwn9jJHyEgIi8="));
        assertTrue(app.editEngine().documents(art).isEmpty());
    }
}
