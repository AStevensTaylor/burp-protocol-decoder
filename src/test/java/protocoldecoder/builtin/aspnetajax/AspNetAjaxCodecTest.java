package protocoldecoder.builtin.aspnetajax;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.edit.EditEngine;
import protocoldecoder.edit.EditableDocument;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.TreeText;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static protocoldecoder.builtin.aspnetajax.AspNetAjaxDecoderTest.*;

class AspNetAjaxCodecTest {

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });
    final AspNetAjaxDecoder dec = new AspNetAjaxDecoder();
    final AspNetAjaxCodec codec = new AspNetAjaxCodec();

    @AfterEach
    void close() {
        app.close();
    }

    List<EditableDocument> docs(MessageContext m) throws Exception {
        return codec.documents(m, dec.decode(m));
    }

    static final String PANEL = "<div id=\"p\">\n  <span>Total: 5 | x</span>\n### not a header\n</div>";
    static final String DELTA = rec("updatePanel", "UpdatePanel1", PANEL)
            + rec("hiddenField", "__VIEWSTATE", "/wEPDwUKLTk=")
            + rec("hiddenField", "__EVENTTARGET", "")
            + rec("scriptStartupBlock", "ScriptContentNoTags", "alert('a|b');\r\nvar s = \"\u00e9\uD83D\uDE00\";\n")
            + rec("asyncPostBackTimeout", "", "90")
            + rec("pageTitle", "", "Orders");

    @Test
    void deltaEndToEndRoundTripAndEdit() throws Exception {
        MessageContext m = deltaResponse(DELTA);
        List<EditEngine.Document> all = app.editEngine().documents(m);
        assertEquals(1, all.size(), all.toString());
        EditEngine.Document d = all.get(0);
        assertEquals("UpdatePanel delta (6 records)", d.document().title());
        String text = d.document().text();
        assertTrue(text.startsWith("### updatePanel | UpdatePanel1\n<div id=\"p\">\n"), text);
        assertTrue(text.contains("\n#### not a header\n"), "content line starting with ### is escaped");
        assertTrue(text.contains("### hiddenField | __EVENTTARGET\n\n### scriptStartupBlock"), text);

        assertArrayEquals(m.responseBody(), EditEngine.encode(d, text).applyTo(m).responseBody());
        // re-encoding the parsed text (not the shortcut) is also exact
        assertEquals(DELTA, AspNetAjaxCodec.encodeDelta(AspNetAjaxCodec.parseDeltaText(text)));

        String edited = text.replace("Total: 5", "Total: <b>\u20ac 5000</b>").replace("Orders", "Pwned \uD83D\uDE00");
        MessageContext out = EditEngine.encode(d, edited).applyTo(m);
        String body = out.responseBodyText();
        assertEquals(DELTA.replace(rec("updatePanel", "UpdatePanel1", PANEL), rec("updatePanel", "UpdatePanel1", PANEL.replace("Total: 5", "Total: <b>\u20ac 5000</b>")))
                .replace(rec("pageTitle", "", "Orders"), rec("pageTitle", "", "Pwned \uD83D\uDE00")), body);
        assertTrue(body.startsWith(PANEL.replace("Total: 5", "Total: <b>\u20ac 5000</b>").length() + "|updatePanel|"), body); // UTF-16 length
        DeltaParser.Result r = DeltaParser.parse(body, 100);
        assertTrue(r.clean());
        DecodeResult decoded = app.engine().decode(out).result();
        assertTrue(TreeText.render(decoded.root()).contains("Pwned"), TreeText.render(decoded.root()));
    }

    @Test
    void deltaAddRecordAndErrors() throws Exception {
        EditableDocument d = docs(deltaResponse(DELTA)).get(0);
        String added = d.text() + "### pageRedirect | \nhttps://evil.example/\n";
        String body = new String(d.encode(added).body(), StandardCharsets.UTF_8);
        assertTrue(body.endsWith("|21|pageRedirect||https://evil.example/|"), body);

        EncodeException e = assertThrows(EncodeException.class, () -> d.encode("junk\n" + d.text()));
        assertTrue(e.getMessage().contains("Line 1"), e.getMessage());
        assertThrows(EncodeException.class, () -> d.encode("### updatePanel\nx\n"));
        assertThrows(EncodeException.class, () -> d.encode("### a|b | c\nx\n"));
        assertThrows(EncodeException.class, () -> d.encode(""));
    }

    @Test
    void gzippedDeltaWithBomIsRestored() throws Exception {
        MessageContext m = asyncPost("__ASYNCPOST=true").statusCode(200).responseHeader("Content-Type", "text/plain")
                .responseHeader("Content-Encoding", "gzip").responseBody(gzip("\uFEFF" + DELTA)).build().withKind(MessageKind.RESPONSE);
        EditableDocument d = docs(m).get(0);
        assertArrayEquals(m.responseBody(), d.encode(d.text()).body());
        byte[] out = d.encode(d.text().replace("Orders", "X")).body();
        assertTrue(Codecs.isGzip(out));
        String plain = new String(Codecs.gunzip(out), StandardCharsets.UTF_8);
        assertEquals("\uFEFF" + DELTA.replace(rec("pageTitle", "", "Orders"), rec("pageTitle", "", "X")), plain);
    }

    static final String D_RESPONSE = "{\"d\":{\"__type\":\"Acme.Order\",\"Id\":42,\"Price\":1.50,\"Created\":\"\\/Date(1700000000000)\\/\","
            + "\"Name\":\"caf\u00e9 \\\"x\\\" <b>\",\"Tags\":[],\"Meta\":{},\"Ok\":true,\"Note\":null}}";

    @Test
    void serviceResponseJson() throws Exception {
        MessageContext m = jsonResponse("https://app.example.com/Services/Orders.asmx/GetOrder", "{\"id\":42}", D_RESPONSE);
        List<EditEngine.Document> all = app.editEngine().documents(m);
        assertEquals(1, all.size());
        EditableDocument d = all.get(0).document();
        assertEquals("Service response {\"d\"} (JSON)", d.title());
        assertEquals("json", d.syntax());
        assertTrue(d.text().startsWith("{\n  \"d\": {\n    \"__type\": \"Acme.Order\",\n    \"Id\": 42,\n    \"Price\": 1.50,"), d.text());
        assertTrue(d.text().contains("\"Created\": \"\\/Date(1700000000000)\\/\""), d.text());
        assertArrayEquals(m.responseBody(), d.encode(d.text()).body());
        // compact re-serialisation of the unedited tree is identical too
        assertEquals(D_RESPONSE, AspNetAjaxCodec.write(AspNetAjaxCodec.parseStrict(d.text()), false, true));

        String edited = d.text().replace("\"Id\": 42", "\"Id\": 43").replace("1700000000000", "1800000000000");
        String body = new String(d.encode(edited).body(), StandardCharsets.UTF_8);
        assertEquals(D_RESPONSE.replace("\"Id\":42", "\"Id\":43").replace("1700000000000", "1800000000000"), body);
        DecodeResult r = app.engine().decode(m.patched(body.getBytes(StandardCharsets.UTF_8), null, null)).result();
        assertTrue(TreeText.render(r.root()).contains("2027-01-15T08:00:00Z"), TreeText.render(r.root()));
    }

    @Test
    void serviceRequestJsonAndErrors() throws Exception {
        MessageContext m = jsonCall("https://app.example.com/Default.aspx/Search", "{\"q\":\"a\",\"page\":1}").build();
        EditableDocument d = docs(m).get(0);
        assertEquals("Service request (JSON)", d.title());
        assertArrayEquals(m.requestBody(), d.encode(d.text()).body());
        MessageContext out = d.encode("{\n  \"q\": \"' OR 1=1 --\",\n  \"page\": 1,\n  \"extra\": \"\\u2028\"\n}").applyTo(m);
        assertEquals("{\"q\":\"' OR 1=1 --\",\"page\":1,\"extra\":\"\\u2028\"}", out.requestBodyText());
        assertTrue(TreeText.render(app.engine().decode(out).result().root()).contains("OR 1=1"));

        EncodeException e = assertThrows(EncodeException.class, () -> d.encode("{\n  \"q\": 'single'\n}"));
        assertTrue(e.getMessage().startsWith("JSON error: ") && e.getMessage().contains("line 2"), e.getMessage());
        assertThrows(EncodeException.class, () -> d.encode("{\"q\":1} trailing"));
        assertThrows(EncodeException.class, () -> d.encode("{\"q\":"));
    }

    @Test
    void nothingForAsyncPostRequestsOrBrokenDeltas() throws Exception {
        assertTrue(app.editEngine().documents(asyncPost("ScriptManager1=UpdatePanel1%7CButton1&__ASYNCPOST=true").build()).stream()
                .noneMatch(x -> x.decoderId().equals(AspNetAjaxDecoder.ID)));
        MessageContext broken = deltaResponse(DELTA + "5|pageTitle||ab|");
        assertTrue(docs(broken).isEmpty());
        assertTrue(codec.documents(broken, null).isEmpty());
    }
}
