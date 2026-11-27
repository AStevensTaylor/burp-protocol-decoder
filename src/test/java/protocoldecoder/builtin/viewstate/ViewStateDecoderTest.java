package protocoldecoder.builtin.viewstate;

import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.core.Resolution;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.util.TreeText;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class ViewStateDecoderTest {

    final ViewStateDecoder vs = new ViewStateDecoder();

    // ------------------------------------------------------------ tiny ObjectStateFormatter writer for fixtures

    static final class Osf {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();

        Osf() {
            out.write(0xFF);
            out.write(0x01);
        }

        Osf tok(int t) { out.write(t); return this; }
        Osf enc(int v) {
            while ((v & ~0x7f) != 0) { out.write((v & 0x7f) | 0x80); v >>>= 7; }
            out.write(v);
            return this;
        }
        Osf raw(String s) { byte[] b = s.getBytes(StandardCharsets.UTF_8); enc(b.length); out.writeBytes(b); return this; }
        Osf bytes(byte... b) { out.writeBytes(b); return this; }
        Osf le32(int v) { out.write(v); out.write(v >>> 8); out.write(v >>> 16); out.write(v >>> 24); return this; }
        Osf le64(long v) { for (int i = 0; i < 8; i++) out.write((int) (v >>> (8 * i))); return this; }

        Osf str(String s) { return tok(0x05).raw(s); }
        Osf istrAdd(String s) { return tok(0x1E).raw(s); }
        Osf istr(int i) { return tok(0x1F).tok(i); }
        Osf int32(int v) { return tok(0x02).enc(v); }
        Osf pair() { return tok(0x0F); }
        Osf triplet() { return tok(0x10); }
        Osf list(int n) { return tok(0x16).enc(n); }
        Osf hybrid(int n) { return tok(0x18).enc(n); }
        Osf nul() { return tok(0x64); }
        Osf t() { return tok(0x67); }
        Osf f() { return tok(0x68); }
        Osf zero() { return tok(0x66); }
        Osf typeAdd(String name) { return tok(0x29).raw(name); }
        Osf typeAddLocal(String name) { return tok(0x2A).raw(name); }
        Osf typeRef(int i) { return tok(0x2B).enc(i); }

        byte[] build() { return out.toByteArray(); }
        byte[] withMac(int n) {
            byte[] b = build();
            byte[] r = Arrays.copyOf(b, b.length + n);
            for (int i = b.length; i < r.length; i++) r[i] = (byte) (0xA0 + i);
            return r;
        }
    }

    static final String TEXTBOXMODE = "System.Web.UI.WebControls.TextBoxMode, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";

    /** A typical page: Pair(Pair(typeHash, controlTree), controlState). */
    static Osf page() {
        Osf o = new Osf();
        o.pair().pair().str("-1234567890")
                .pair().nul().list(4)
                    .int32(1).pair().pair().list(4).istrAdd("Text").str("hello").istr(0).str("again").nul().nul()
                    .int32(3).triplet().tok(0x0B).typeAdd(TEXTBOXMODE).enc(2)
                                       .tok(0x0B).typeRef(0).enc(1)
                                       .list(3).t().f().zero()
                .hybrid(1).str("ctl00$Main$chkAgree").t();
        return o;
    }

    static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    static MessageContext post(String body) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://shop.example.com/Default.aspx")
                .requestHeader("Content-Type", "application/x-www-form-urlencoded").requestBody(body).build();
    }

    static MessageContext response(String body, String ct) {
        return MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://shop.example.com/Default.aspx")
                .statusCode(200).responseHeader("Content-Type", ct).responseBody(body).build();
    }

    static String text(DecodeResult r) {
        return TreeText.render(r.root());
    }

    static boolean anyWarning(DecodeResult r, String s) {
        return r.warnings().stream().anyMatch(w -> w.contains(s));
    }

    static String find(DecodedNode n, String nameContains) {
        if (n.name().contains(nameContains) && n.value() != null) return n.value();
        for (DecodedNode c : n.children()) {
            String v = find(c, nameContains);
            if (v != null) return v;
        }
        return null;
    }

    static int eventValidationStoreLen(int hashes) {
        return 2 + 1 + 1 + 1 + hashes * 16;
    }

    static byte[] eventValidation(int hashes, int mac) {
        Osf o = new Osf().tok(0x1D).tok(0).enc(hashes);
        for (int i = 0; i < hashes * 16; i++) o.tok(i * 7);
        return o.withMac(mac);
    }

    // ------------------------------------------------------------ tests

    @Test
    void formPostWithSha256Mac() throws Exception {
        byte[] state = page().withMac(32);
        String body = "__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=" + enc(b64(state))
                + "&__VIEWSTATEGENERATOR=CA0B0334&__EVENTVALIDATION=" + enc(b64(eventValidation(3, 32)))
                + "&ctl00%24Main%24txtName=bob";
        MessageContext m = post(body);
        assertEquals(60, vs.match(m).confidence());
        DecodeResult r = vs.decode(m);
        assertTrue(r.summary().startsWith("ViewState (" + state.length + " bytes): "), r.summary());
        assertTrue(r.summary().contains("MAC present (HMACSHA256)"), r.summary());
        assertTrue(r.summary().contains("EventValidation (" + (eventValidationStoreLen(3) + 32) + " bytes): 3 hashes, MAC present (HMACSHA256)"), r.summary());
        String t = text(r);
        assertTrue(t.contains("hello") && t.contains("again"), t);
        // Indexed string back-reference resolved.
        assertEquals(3, t.split("\"Text\"", -1).length - 1, t);
        // Type ref resolved twice (TypeRefAdd then TypeRef).
        assertEquals(2, t.split("System.Web.UI.WebControls.TextBoxMode = ", -1).length - 1, t);
        assertTrue(t.contains("ctl00$Main$chkAgree"), t);
        assertEquals("-1234567890", find(r.root(), "Page type hash"));
        assertTrue(r.root().get("Generator").get("Value").value().startsWith("0xCA0B0334 = 3389719348"));
        assertEquals("MAC present (likely HMACSHA256, 32 bytes)", r.root().get("ViewState").get("MAC").get("Status").value());
        assertTrue(anyWarning(r, "ViewState: MAC present (likely HMACSHA256, 32 bytes)"), r.warnings().toString());
        assertNotNull(r.root().get("ViewState").get("String table (1)"));
        assertNotNull(r.root().get("ViewState").get("Type table (1)"));
        assertNotNull(r.root().get("Generator"));
        // Pair rendering: Root is a Pair with First/Second.
        DecodedNode root = r.root().get("ViewState").get("Root");
        assertEquals("Pair", root.value());
        assertNotNull(root.get("First"));
        assertNotNull(root.get("Second"));
        assertEquals("HybridDictionary(1)", root.get("Second").value());
    }

    @Test
    void sha1MacAndOtherLengths() throws Exception {
        for (int[] c : new int[][]{{20, 0}, {48, 1}, {64, 2}, {16, 3}}) {
            DecodeResult r = vs.decode(post("__VIEWSTATE=" + enc(b64(page().withMac(c[0])))));
            String expected = switch (c[1]) {
                case 0 -> "HMACSHA1";
                case 1 -> "HMACSHA384";
                case 2 -> "HMACSHA512";
                default -> "MD5 (legacy)";
            };
            assertTrue(r.summary().contains("MAC present (" + expected + ")"), r.summary());
        }
        DecodeResult odd = vs.decode(post("__VIEWSTATE=" + enc(b64(page().withMac(7)))));
        assertTrue(odd.summary().contains("unrecognised trailer (7 bytes)"), odd.summary());
    }

    @Test
    void noMacIsFlagged() throws Exception {
        DecodeResult r = vs.decode(post("__VIEWSTATE=" + enc(b64(page().build()))));
        assertTrue(r.summary().endsWith("no MAC ⚠"), r.summary());
        assertTrue(anyWarning(r, "No MAC — EnableViewStateMac appears disabled (possible deserialization RCE if exploitable)"), r.warnings().toString());
    }

    @Test
    void encryptedBlob() throws Exception {
        byte[] random = new byte[160];
        new Random(42).nextBytes(random);
        random[0] = 0x3c; // make sure it does not start with FF 01
        DecodeResult r = vs.decode(post("__VIEWSTATE=" + enc(b64(random)) + "&__VIEWSTATEENCRYPTED=&__VIEWSTATEGENERATOR=CA0B0334"));
        assertEquals("ViewState (160 bytes): encrypted", r.summary());
        assertTrue(anyWarning(r, "encrypted (ViewStateEncryptionMode / machineKey)"), r.warnings().toString());
        assertNotNull(r.root().get("Encryption"));
        // Without the flag, high entropy is still recognised.
        DecodeResult r2 = vs.decode(post("__VIEWSTATE=" + enc(b64(random))));
        assertEquals("ViewState (160 bytes): encrypted", r2.summary());
    }

    @Test
    void splitViewStateIsConcatenated() throws Exception {
        String full = b64(page().withMac(32));
        int a = full.length() / 3, b = 2 * full.length() / 3;
        String body = "__VIEWSTATEFIELDCOUNT=3&__VIEWSTATE=" + enc(full.substring(0, a)) + "&__VIEWSTATE1=" + enc(full.substring(a, b))
                + "&__VIEWSTATE2=" + enc(full.substring(b));
        DecodeResult r = vs.decode(post(body));
        assertTrue(r.summary().contains("MAC present (HMACSHA256)"), r.summary() + r.warnings());
        assertEquals("form field, split across 3 fields", r.root().get("ViewState").get("Source").value());
        assertTrue(r.warnings().stream().noneMatch(w -> w.contains("parse stopped")), r.warnings().toString());

        // A missing chunk is reported and the partial blob is parsed as far as possible.
        DecodeResult missing = vs.decode(post("__VIEWSTATEFIELDCOUNT=3&__VIEWSTATE=" + enc(full.substring(0, a)) + "&__VIEWSTATE1=" + enc(full.substring(a, b))));
        assertTrue(anyWarning(missing, "__VIEWSTATE2 missing"), missing.warnings().toString());
    }

    @Test
    void htmlHiddenInputs() throws Exception {
        String state = b64(page().withMac(20)).replace("+", "&#43;");
        String html = "<!DOCTYPE html><html><body><form method=\"post\" action=\"./Default.aspx\" id=\"form1\">\n"
                + "<div class=\"aspNetHidden\">\n"
                + "<input type=\"hidden\" name=\"__EVENTTARGET\" id=\"__EVENTTARGET\" value=\"\" />\n"
                + "<input type=\"hidden\" name=\"__VIEWSTATE\" id=\"__VIEWSTATE\" value=\"" + state + "\" />\n"
                + "</div><div class=\"aspNetHidden\">\n"
                + "<input value=\"CA0B0334\" id=\"__VIEWSTATEGENERATOR\" name=\"__VIEWSTATEGENERATOR\" type=\"hidden\" />\n"
                + "<input type='hidden' name='__EVENTVALIDATION' id='__EVENTVALIDATION' value='" + b64(eventValidation(2, 20)) + "' />\n"
                + "</div></form></body></html>";
        MessageContext m = response(html, "text/html; charset=utf-8");
        assertEquals(35, vs.match(m).confidence());
        DecodeResult r = vs.decode(m);
        assertTrue(r.summary().contains("ViewState") && r.summary().contains("MAC present (HMACSHA1)"), r.summary());
        assertTrue(r.summary().contains("2 hashes"), r.summary());
        assertEquals("hidden input", r.root().get("ViewState").get("Source").value());
        assertNotNull(r.root().get("Generator"));
    }

    @Test
    void ajaxDeltaHiddenField() throws Exception {
        String state = b64(page().withMac(32));
        String delta = "1|#||4|26|updatePanel|ctl00_up1|<span>updated</span>|" + state.length() + "|hiddenField|__VIEWSTATE|" + state
                + "|8|hiddenField|__VIEWSTATEGENERATOR|CA0B0334|0|asyncPostBackControlIDs|||";
        MessageContext m = response(delta, "text/plain; charset=utf-8");
        assertEquals(30, vs.match(m).confidence());
        DecodeResult r = vs.decode(m);
        assertTrue(r.summary().contains("MAC present (HMACSHA256)"), r.summary());
        assertEquals("AJAX delta hiddenField", r.root().get("ViewState").get("Source").value());
        assertEquals("CA0B0334", r.root().get("Generator").get("__VIEWSTATEGENERATOR").value());
    }

    @Test
    void legacyEventValidationArrayList() throws Exception {
        byte[] ev = new Osf().list(3).int32(123456).int32(987654321).int32(42).withMac(20);
        DecodeResult r = vs.decode(post("__EVENTVALIDATION=" + enc(b64(ev))));
        assertTrue(r.summary().startsWith("EventValidation (" + ev.length + " bytes)"), r.summary());
        assertTrue(r.summary().contains("MAC present (HMACSHA1)"), r.summary());
        assertTrue(text(r).contains("987654321"));
        assertEquals(40, vs.match(post("__EVENTVALIDATION=" + enc(b64(ev)))).confidence());

        DecodeResult noMac = vs.decode(post("__EVENTVALIDATION=" + enc(b64(eventValidation(1, 0)))));
        assertTrue(anyWarning(noMac, "EventValidation: No MAC"), noMac.warnings().toString());
    }

    @Test
    void binarySerializedBlobIsFlagged() throws Exception {
        ByteArrayOutputStream nrbf = new ByteArrayOutputStream();
        nrbf.writeBytes(new byte[]{0x00, 0x01, 0, 0, 0, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0x01, 0, 0, 0, 0, 0, 0, 0});
        nrbf.write(0x0C);
        nrbf.writeBytes(new byte[]{2, 0, 0, 0});
        String lib = "PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35";
        nrbf.write(lib.length());
        nrbf.writeBytes(lib.getBytes(StandardCharsets.US_ASCII));
        nrbf.write(0x05);
        nrbf.writeBytes(new byte[]{1, 0, 0, 0});
        String cls = "System.Windows.Data.ObjectDataProvider";
        nrbf.write(cls.length());
        nrbf.writeBytes(cls.getBytes(StandardCharsets.US_ASCII));
        nrbf.write(0x0B);
        byte[] blob = nrbf.toByteArray();
        Osf o = new Osf().pair().str("x").tok(0x32).enc(blob.length).bytes(blob);
        DecodeResult r = vs.decode(post("__VIEWSTATE=" + enc(b64(o.build()))));
        assertTrue(anyWarning(r, "BinaryFormatter"), r.warnings().toString());
        assertTrue(anyWarning(r, "ObjectDataProvider"), r.warnings().toString());
        assertTrue(r.summary().contains("BinaryFormatter blob ⚠"), r.summary());
        assertTrue(r.summary().contains("no MAC ⚠"), r.summary());
        String t = text(r);
        assertTrue(t.contains(cls) && t.contains(lib), t);
        assertTrue(t.contains("deserialization sink"), t);
    }

    @Test
    void truncatedStreamGivesPartialTree() throws Exception {
        byte[] full = page().build();
        byte[] cut = Arrays.copyOf(full, full.length / 2 + 3);
        DecodeResult r = vs.decode(post("__VIEWSTATE=" + enc(b64(cut))));
        assertTrue(r.summary().contains("partial parse ⚠"), r.summary());
        assertTrue(anyWarning(r, "parse stopped"), r.warnings().toString());
        assertTrue(text(r).contains("-1234567890"), text(r));
    }

    @Test
    void allPrimitiveTokens() throws Exception {
        Osf o = new Osf().list(22)
                .tok(0x01).bytes((byte) 0xFE, (byte) 0xFF)               // Int16 -2
                .tok(0x03).tok(200)                                      // Byte
                .tok(0x04).bytes((byte) 0xC3, (byte) 0xA9)               // Char é
                .tok(0x06).le64(0x4000000000000000L | 638_000_000_000_000_000L) // DateTime (Utc)
                .tok(0x07).le64(Double.doubleToLongBits(3.5))             // Double
                .tok(0x08).le32(Float.floatToIntBits(1.25f))             // Single
                .tok(0x09).le32(0xFF336699)                              // Color
                .tok(0x0A).enc(165)                                      // KnownColor
                .tok(0x0C)                                               // EmptyColor
                .tok(0x15).enc(2).raw("a").raw("bc")                     // string[]
                .tok(0x17).enc(1).str("k").int32(5)                      // Hashtable
                .tok(0x19).typeAddLocal("System.Web.UI.WebControls.Unit") // Type
                .tok(0x1B).le64(Double.doubleToLongBits(100)).le32(1)   // Unit 100px
                .tok(0x1C)                                               // EmptyUnit
                .tok(0x28).typeRef(0).raw("50%")                         // StringFormatted
                .tok(0x14).typeAdd("System.Int32, mscorlib").enc(2).int32(7).zero() // Array
                .tok(0x3C).typeRef(1).enc(10).enc(1).enc(4).str("sparse") // SparseArray
                .tok(0x65)                                               // EmptyString
                .nul().t().f().int32(300);
        DecodeResult r = vs.decode(post("__VIEWSTATE=" + enc(b64(o.withMac(32)))));
        assertTrue(r.warnings().stream().noneMatch(w -> w.contains("parse stopped")), r.warnings().toString());
        String t = text(r);
        for (String s : new String[]{"-2", "200", "'é'", "DateTime 2022-", "(Utc)", "3.5", "1.25", "Color #FF336699", "KnownColor 165",
                "Color.Empty", "string[2]", "Hashtable(1)", "typeof(System.Web.UI.WebControls.Unit [System.Web])", "Unit 100px",
                "Unit.Empty", "System.Web.UI.WebControls.Unit [System.Web] \\\"50%\\\"", "System.Int32[2]", "System.Int32[10] (sparse, 1 set)",
                "[4]", "sparse", "300"}) {
            assertTrue(t.contains(s), s + " missing in\n" + t);
        }
        assertTrue(r.summary().contains("MAC present (HMACSHA256)"), r.summary());
    }

    @Test
    void legacyLosFormatter() throws Exception {
        String los = "t<-1234567;t<;l<i<0>;>;l<t<p<l<Text;>;l<hello\\;world;>>;;>;>>;>";
        byte[] b = Arrays.copyOf(los.getBytes(StandardCharsets.US_ASCII), los.length() + 20);
        for (int i = los.length(); i < b.length; i++) b[i] = (byte) (0x80 + i);
        DecodeResult r = vs.decode(post("__VIEWSTATE=" + enc(b64(b))));
        assertTrue(r.summary().contains("legacy LosFormatter"), r.summary() + r.warnings());
        assertTrue(r.summary().contains("MAC present (HMACSHA1)"), r.summary());
        String t = text(r);
        assertTrue(t.contains("hello;world") && t.contains("-1234567"), t);
    }

    @Test
    void hostileInputsDoNotBlowUp() throws Exception {
        // Very deep nesting.
        Osf deep = new Osf();
        for (int i = 0; i < 5000; i++) deep.pair();
        DecodeResult r = vs.decode(post("__VIEWSTATE=" + enc(b64(deep.build()))));
        assertTrue(anyWarning(r, "nesting deeper"), r.warnings().toString());
        // Huge claimed counts / lengths.
        for (Osf o : new Osf[]{new Osf().list(Integer.MAX_VALUE), new Osf().tok(0x05).enc(Integer.MAX_VALUE), new Osf().tok(0x32).enc(1 << 30),
                new Osf().tok(0x1D).tok(0).enc(1 << 28), new Osf().istr(5), new Osf().tok(0x19).typeRef(3), new Osf().tok(0x99),
                new Osf().tok(0x02).bytes((byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF)}) {
            DecodeResult x = vs.decode(post("__VIEWSTATE=" + enc(b64(o.build()))));
            assertTrue(anyWarning(x, "parse stopped"), x.warnings().toString());
        }
        // Empty and invalid base64.
        assertTrue(vs.decode(post("__VIEWSTATE=")).summary().contains("empty"));
        assertTrue(vs.decode(post("__VIEWSTATE=%25%25%25")).summary().contains("invalid base64"));
    }

    @Test
    void multipartPost() throws Exception {
        String state = b64(page().withMac(32));
        String body = "--BOUND\r\nContent-Disposition: form-data; name=\"__VIEWSTATE\"\r\n\r\n" + state + "\r\n"
                + "--BOUND\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nhi\r\n--BOUND--\r\n";
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://shop.example.com/Upload.aspx")
                .requestHeader("Content-Type", "multipart/form-data; boundary=BOUND").requestBody(body).build();
        assertEquals(60, vs.match(m).confidence());
        assertTrue(vs.decode(m).summary().contains("MAC present (HMACSHA256)"));
    }

    @Test
    void negativeCases() {
        assertFalse(vs.match(post("user=bob&pass=x")).matched());
        assertFalse(vs.match(response("<html><body>hello</body></html>", "text/html")).matched());
        assertFalse(vs.match(response("{\"__VIEWSTATEX\":1}", "application/json")).matched());
        assertFalse(vs.match(MessageContext.builder(MessageKind.WEBSOCKET).url("wss://x/").webSocket("CLIENT_TO_SERVER",
                "__VIEWSTATE=abc".getBytes(StandardCharsets.UTF_8)).build()).matched());
        assertFalse(vs.match(MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://x/").build()).matched());
    }

    @Test
    void forcedDecodeOnGarbage() throws Exception {
        assertThrows(DecodeException.class, () -> vs.decode(post("user=bob&pass=x")));
        assertThrows(DecodeException.class, () -> vs.decode(response("\u0000\u0001garbage<<>>", "application/octet-stream")));
        assertThrows(DecodeException.class, () -> vs.decode(MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://x/").build()));
        // A bare blob (e.g. pasted into a WebSocket message) is decoded when forced.
        DecodeResult r = vs.decode(MessageContext.builder(MessageKind.WEBSOCKET).url("wss://x/")
                .webSocket("CLIENT_TO_SERVER", b64(page().withMac(32)).getBytes(StandardCharsets.UTF_8)).build());
        assertEquals("raw body", r.root().get("ViewState").get("Source").value());
    }

    @Test
    void devExpressAndAspNetCallbacksStillWin() {
        App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });
        try {
            assertTrue(app.registry().byId(ViewStateDecoder.ID).isPresent());
            String state = enc(b64(page().withMac(32)));
            MessageContext dx = post("__EVENTTARGET=&__VIEWSTATE=" + state + "&__CALLBACKID=" + enc("ctl00$Main$ASPxGridView1")
                    + "&__CALLBACKPARAM=" + enc("c0:KV|2;[];GB|20;12|PAGERONCLICK3|PN1;") + "&DXScript=" + enc("1_304,1_185"));
            Resolution r = app.engine().resolve(dx);
            assertEquals("devexpress", r.decoder().id());
            assertEquals(Resolution.Source.AUTO, r.source());
            // ViewState is still offered as a candidate for the picker.
            assertTrue(app.engine().candidates(dx).stream().anyMatch(c -> c.decoder().id().equals(ViewStateDecoder.ID) && c.match().matched()));

            Resolution plain = app.engine().resolve(post("__VIEWSTATE=" + state + "&__VIEWSTATEGENERATOR=CA0B0334&btnSave=Save"));
            assertEquals(ViewStateDecoder.ID, plain.decoder().id());
        } finally {
            app.close();
        }
    }
}
