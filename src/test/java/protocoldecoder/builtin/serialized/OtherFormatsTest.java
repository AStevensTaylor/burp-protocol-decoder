package protocoldecoder.builtin.serialized;

import org.junit.jupiter.api.Test;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static protocoldecoder.builtin.serialized.Fixtures.*;

/** .NET, PHP, pickle and Ruby Marshal detection and structural decoding. */
class OtherFormatsTest {

    final SerializedObjectDecoder decoder = new SerializedObjectDecoder();

    private DecodeResult decode(MessageContext m) throws Exception {
        assertTrue(decoder.match(m).matched(), "should match");
        return decoder.decode(m);
    }

    // ------------------------------------------------------------------ .NET

    @Test
    void nrbfRawBody() throws Exception {
        byte[] data = nrbfPerson();
        MessageContext m = requestBytes("https://app.example.test/svc", data, "Content-Type", "application/octet-stream");
        assertEquals(90, decoder.match(m).confidence());
        DecodeResult r = decoder.decode(m);
        String t = text(r.root());
        assertTrue(r.summary().startsWith(".NET BinaryFormatter object in body — 1 class (Test.Person)"), r.summary());
        assertTrue(t.contains("TestAssembly, Version=1.0.0.0"), t);
        assertTrue(t.contains("Name: \"alice"), t);
        assertTrue(t.contains("Age: 30"), t);
        assertTrue(t.contains("Next: null"), t);
        assertTrue(t.contains("MessageEnd"), t);
        assertFalse(r.summary().contains("[partial]"));
    }

    @Test
    void nrbfBase64CookieWithArraysAndRiskyName() throws Exception {
        byte[] data = nrbfSystemClass("System.Windows.Data.ObjectDataProvider");
        String b64 = b64(data);
        assertTrue(b64.startsWith("AAEAAAD/////"), b64);
        MessageContext m = request("https://app.example.test/", null, "Cookie", "state=" + b64);
        assertEquals(85, decoder.match(m).confidence());
        DecodeResult r = decoder.decode(m);
        String t = text(r.root());
        assertTrue(r.summary().contains("System.Windows.Data.ObjectDataProvider ⚠"), r.summary());
        assertTrue(t.contains("string[4]"), t);
        assertTrue(t.contains("one"), t);
        assertTrue(t.contains("→ #7"), t);
        assertTrue(t.contains("null ×2"), t);
        assertTrue(t.contains("ca fe 01"), t);
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("ObjectDataProvider")));
    }

    @Test
    void nrbfTruncatedIsPartial() throws Exception {
        byte[] data = nrbfPerson();
        DecodeResult r = decode(requestBytes("https://app.example.test/svc", Arrays.copyOf(data, data.length - 8)));
        assertTrue(r.summary().contains("[partial]"), r.summary());
        assertTrue(text(r.root()).contains("Test.Person"));
    }

    @Test
    void viewStateIsPointedAtViewStateDecoder() throws Exception {
        String vs = "/wEPDwUKLTEyMzQ1Njc4OQ9kFgICAw9kFgICAQ8PFgIeBFRleHQFBWhlbGxvZGRk";
        MessageContext webforms = request("https://app.example.test/Default.aspx",
                "__VIEWSTATE=" + URLEncoder.encode(vs, StandardCharsets.UTF_8) + "&btn=Go", "Content-Type", "application/x-www-form-urlencoded");
        assertEquals(15, decoder.match(webforms).confidence(), "plain WebForms posts stay low");
        DecodeResult r = decoder.decode(webforms);
        assertTrue(r.summary().startsWith("ASP.NET ViewState (ObjectStateFormatter) in param __VIEWSTATE"), r.summary());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("ASP.NET ViewState' decoder")), r.warnings().toString());

        MessageContext other = request("https://app.example.test/x?blob=" + URLEncoder.encode(vs, StandardCharsets.UTF_8), null);
        assertEquals(60, decoder.match(other).confidence());
    }

    @Test
    void jsonNetTypeHints() throws Exception {
        String json = "{\"$type\":\"System.Windows.Data.ObjectDataProvider, PresentationFramework\",\"MethodName\":\"ToString\","
                + "\"Inner\":{\"$type\":\"Shop.Models.Cart, Shop\"}}";
        MessageContext m = request("https://app.example.test/api", json, "Content-Type", "application/json");
        assertEquals(40, decoder.match(m).confidence());
        DecodeResult r = decoder.decode(m);
        assertTrue(r.summary().startsWith("Json.NET $type hints in body — 2 types"), r.summary());
        assertTrue(r.summary().contains("ObjectDataProvider, PresentationFramework ⚠"), r.summary());
        assertTrue(text(r.root()).contains("Shop.Models.Cart, Shop"));
    }

    @Test
    void xmlTypeHintsAreLowConfidence() throws Exception {
        String dc = "<Person xmlns=\"http://schemas.datacontract.org/2004/07/Shop.Models\" "
                + "xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\"><Name>bob</Name></Person>";
        MessageContext m = request("https://app.example.test/svc", dc, "Content-Type", "application/xml");
        assertEquals(20, decoder.match(m).confidence());
        assertTrue(decoder.decode(m).summary().contains("Shop.Models"));

        String ndc = "<Root z:Type=\"Shop.Models.Order\" z:Assembly=\"Shop, Version=1.0.0.0\" xmlns:z=\"http://schemas.microsoft.com/2003/10/Serialization/\"/>";
        assertEquals(30, decoder.match(request("https://app.example.test/svc", ndc)).confidence());
    }

    // ------------------------------------------------------------------ PHP

    static final String PHP = "a:2:{s:3:\"foo\";i:1;s:3:\"bar\";O:8:\"stdClass\":2:{s:1:\"x\";b:1;s:1:\"y\";d:0.5;}}";

    @Test
    void phpParameterIsParsedIntoATree() throws Exception {
        MessageContext m = request("https://app.example.test/p?data=" + URLEncoder.encode(PHP, StandardCharsets.UTF_8), null);
        assertEquals(80, decoder.match(m).confidence());
        DecodeResult r = decoder.decode(m);
        assertEquals("PHP serialized data in param data — 1 class (stdClass)", r.summary());
        String t = text(r.root());
        assertTrue(t.contains("foo: 1"), t);
        assertTrue(t.contains("object stdClass"), t);
        assertTrue(t.contains("x: true"), t);
        assertTrue(t.contains("y: 0.5"), t);
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("object injection")), r.warnings().toString());
    }

    @Test
    void phpUrlEncodedAndBase64Cookies() throws Exception {
        String enc = URLEncoder.encode(PHP, StandardCharsets.UTF_8).replace("+", "%20");
        DecodeResult r = decode(request("https://app.example.test/", null, "Cookie", "prefs=" + enc));
        assertTrue(r.summary().startsWith("PHP serialized data in cookie prefs"), r.summary());

        DecodeResult b = decode(request("https://app.example.test/", null, "Cookie", "prefs=" + b64(PHP.getBytes())));
        assertTrue(text(b.root()).contains("Encoding: \"base64\""), text(b.root()));
        assertTrue(b.summary().contains("stdClass"));
    }

    @Test
    void phpVisibilityCustomAndRiskyClasses() throws Exception {
        String user = "O:4:\"User\":3:{" + phpStr("\0User\0id") + "i:5;" + phpStr("\0*\0role") + "s:5:\"admin\";"
                + "s:3:\"log\";O:32:\"Monolog\\Handler\\SyslogUdpHandler\":0:{}}";
        String custom = "C:11:\"ArrayObject\":21:{x:i:0;a:0:{};m:a:0:{}}";
        String all = "a:2:{i:0;" + user + "i:1;" + custom + "}";
        DecodeResult r = decode(request("https://app.example.test/", all, "Content-Type", "text/plain"));
        String t = text(r.root());
        assertTrue(t.contains("id (private User): 5"), t);
        assertTrue(t.contains("role (protected): \"admin\""), t);
        assertTrue(t.contains("ArrayObject (custom Serializable)"), t);
        assertTrue(r.summary().contains("Monolog\\Handler\\SyslogUdpHandler ⚠"), r.summary());
        assertTrue(r.summary().startsWith("PHP serialized data in body — 3 classes"), r.summary());
    }

    @Test
    void phpTruncatedIsPartial() throws Exception {
        DecodeResult r = decode(request("https://app.example.test/p?data=" + URLEncoder.encode("a:2:{s:3:\"foo\";i:1;s:3:\"b", StandardCharsets.UTF_8), null));
        assertTrue(r.summary().contains("[partial]"), r.summary());
        assertTrue(text(r.root()).contains("foo: 1"));
    }

    // ------------------------------------------------------------------ pickle

    @Test
    void pickleProtocol4StackGlobalAndReduce() throws Exception {
        MessageContext m = requestBytes("https://app.example.test/ml", PICKLE_ODICT_P4, "Content-Type", "application/octet-stream");
        assertEquals(90, decoder.match(m).confidence());
        DecodeResult r = decoder.decode(m);
        assertEquals("Python pickle in body — 1 global (collections.OrderedDict)", r.summary());
        String t = text(r.root());
        assertTrue(t.contains("STACK_GLOBAL"), t);
        assertTrue(t.contains("REDUCE"), t);
        assertTrue(t.contains("FRAME 41"), t);
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("REDUCE")), r.warnings().toString());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("pickle imports collections.OrderedDict")), r.warnings().toString());
    }

    @Test
    void pickleProtocol2And5Base64() throws Exception {
        String p2 = b64(PICKLE_ODICT_P2);
        DecodeResult r = decode(request("https://app.example.test/", null, "Cookie", "session=" + p2));
        assertTrue(r.summary().startsWith("Python pickle in cookie session — 1 global (collections.OrderedDict)"), r.summary());
        assertTrue(text(r.root()).contains("GLOBAL collections.OrderedDict"));

        String d2 = b64(PICKLE_DICT_P2);
        assertTrue(d2.startsWith("gAJ"), d2);
        DecodeResult dict = decode(request("https://app.example.test/?p=" + URLEncoder.encode(d2, StandardCharsets.UTF_8), null));
        String t = text(dict.root());
        assertTrue(t.contains("BINUNICODE 'a'"), t);
        assertTrue(t.contains("STOP"), t);

        String p5 = b64(PICKLE_DICT_P5);
        DecodeResult five = decode(request("https://app.example.test/", null, "X-State", p5));
        assertTrue(five.summary().startsWith("Python pickle in header X-State"), five.summary());
        assertTrue(text(five.root()).contains("protocol: \"5\""));
    }

    @Test
    void pickleRiskyGlobalAndTruncation() throws Exception {
        DecodeResult r = decode(requestBytes("https://app.example.test/", PICKLE_GLOBAL_ONLY));
        assertTrue(r.summary().contains("subprocess.Popen ⚠"), r.summary());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("command execution")), r.warnings().toString());

        byte[] cut = Arrays.copyOf(PICKLE_DICT_P2, PICKLE_DICT_P2.length - 5);
        assertEquals(60, decoder.match(requestBytes("https://app.example.test/", cut)).confidence(), "no STOP at the end");
        DecodeResult p = decoder.decode(requestBytes("https://app.example.test/", cut));
        assertTrue(p.summary().contains("[partial]"), p.summary());
    }

    // ------------------------------------------------------------------ Ruby

    @Test
    void rubyMarshalRawAndBase64() throws Exception {
        MessageContext raw = requestBytes("https://app.example.test/", RUBY_HASH);
        assertEquals(70, decoder.match(raw).confidence());
        DecodeResult r = decoder.decode(raw);
        String t = text(r.root());
        assertTrue(t.contains("Hash(2)"), t);
        assertTrue(t.contains("user"), t);
        assertTrue(t.contains("bob"), t);
        assertTrue(t.contains(":id"), t);
        assertTrue(t.contains(":E"), "symbols listed: " + t);

        String cookie = b64(RUBY_OBJECT) + "--" + "0123456789abcdef0123456789abcdef01234567";
        assertTrue(cookie.startsWith("BAh"));
        MessageContext m = request("https://app.example.test/", null, "Cookie", "_app_session=" + URLEncoder.encode(cookie, StandardCharsets.UTF_8));
        assertEquals(85, decoder.match(m).confidence());
        DecodeResult c = decoder.decode(m);
        assertEquals("Ruby Marshal data in cookie _app_session — 1 class (Account)", c.summary());
        assertTrue(text(c.root()).contains("@name: \"bob\""), text(c.root()));
        assertTrue(text(c.root()).contains("signed value"));
    }

    @Test
    void rubyRiskyAndTruncated() throws Exception {
        DecodeResult r = decode(response(rubyObject("Gem::Requirement"), "Set-Cookie", "x=1"));
        assertTrue(r.summary().contains("Gem::Requirement ⚠"), r.summary());

        DecodeResult t = decode(requestBytes("https://app.example.test/", Arrays.copyOf(RUBY_HASH, 14)));
        assertTrue(t.summary().contains("[partial]"), t.summary());
    }
}
