package protocoldecoder.builtin.devexpress;

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

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class DevExpressCodecTest {

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });
    final DevExpressDecoder dec = new DevExpressDecoder();
    final DevExpressCodec codec = new DevExpressCodec();

    @AfterEach
    void close() {
        app.close();
    }

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    static MessageContext dx(String param) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/Orders.aspx")
                .requestHeader("Content-Type", "application/x-www-form-urlencoded")
                .requestBody("__EVENTTARGET=&__CALLBACKID=ctl00%24grid&__CALLBACKPARAM=" + enc(param) + "&DXScript=1_42").build();
    }

    static String param(MessageContext m) {
        return Codecs.first(Codecs.parseQuery(m.requestBodyText()), "__CALLBACKPARAM");
    }

    List<EditableDocument> docs(MessageContext m) throws Exception {
        return codec.documents(m, dec.decode(m));
    }

    static final String PARAM = "c0:KV|2;[];GB|20;12|PAGERONCLICK3|PN1;";

    @Test
    void outlineEndToEnd() throws Exception {
        MessageContext m = dx(PARAM);
        List<EditEngine.Document> all = app.editEngine().documents(m);
        assertEquals(1, all.size());
        EditEngine.Document d = all.get(0);
        assertEquals("__CALLBACKPARAM (outline)", d.document().title());
        assertEquals(DevExpressCodec.COMMENT + "prefix: c0:\nKV: []\nGB:\n  - PAGERONCLICK\n  - PN1\n", d.document().text());
        assertArrayEquals(m.requestBody(), EditEngine.encode(d, d.document().text()).applyTo(m).requestBody());
        assertEquals(PARAM, DevExpressCodec.parseOutline(d.document().text()).serialize());

        String edited = d.document().text().replace("PAGERONCLICK", "CUSTOMCALLBACK").replace("- PN1", "- PN12");
        MessageContext out = EditEngine.encode(d, edited).applyTo(m);
        assertEquals("c0:KV|2;[];GB|23;14|CUSTOMCALLBACK4|PN12;", param(out));
        assertTrue(out.requestBodyText().startsWith("__EVENTTARGET=&__CALLBACKID=ctl00%24grid&__CALLBACKPARAM="));
        assertTrue(out.requestBodyText().endsWith("&DXScript=1_42"));
        DecodeResult r = app.engine().decode(out).result();
        assertEquals("Callback → grid (CUSTOMCALLBACK)", r.summary());
    }

    @Test
    void quotedValuesNestingAndTrailingSemicolon() throws Exception {
        String p = "c1:CB|28;8|ROWCLICK11|a|b;c\nd \"e\"2|  ;" + "CT|0;;";
        // positional value containing delimiters, newline, quotes, leading spaces; empty named value
        DxArgModel.Arg arg = DxArgModel.parse(p);
        String text = DevExpressCodec.outline(arg);
        assertTrue(text.contains("  - \"a|b;c\\nd \\\"e\\\"\"\n"), text);
        assertTrue(text.contains("  - \"  \"\n"), text);
        assertTrue(text.contains("CT: \"\"\n"), text);
        assertEquals(p, DevExpressCodec.parseOutline(text).serialize());

        String top = "12|PAGERONCLICK3|PN1;";
        String t2 = DevExpressCodec.outline(DxArgModel.parse(top));
        assertEquals(DevExpressCodec.COMMENT + "prefix: \"\"\n- PAGERONCLICK\n- PN1\n;\n", t2);
        assertEquals("12|PAGERONCLICK4|PN99;", DevExpressCodec.parseOutline(t2.replace("PN1", "PN99")).serialize());

        // unicode: lengths are UTF-16 units (as JavaScript counts)
        String u = DevExpressCodec.parseOutline("prefix: c0:\nGB:\n  - SORT\n  - é😀 x\n").serialize();
        assertEquals("c0:GB|13;4|SORT5|é😀 x;", u);
    }

    @Test
    void mvcArgumentAndUnicodeEdit() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/Home/GridPartial")
                .requestHeader("Content-Type", "application/x-www-form-urlencoded")
                .requestBody("DXCallbackName=grid&DXCallbackArgument=" + enc("c0:GB|8;6|FILTER;") ).build();
        EditableDocument d = docs(m).get(0);
        assertEquals("DXCallbackArgument (outline)", d.title());
        MessageContext out = d.encode(d.text().replace("- FILTER", "- \"x' OR '1'='1ü\"")).applyTo(m);
        assertEquals("c0:GB|16;13|x' OR '1'='1ü;", Codecs.first(Codecs.parseQuery(out.requestBodyText()), "DXCallbackArgument"));
    }

    @Test
    void outlineErrors() throws Exception {
        EditableDocument d = docs(dx(PARAM)).get(0);
        assertThrows(EncodeException.class, () -> d.encode("KV: []\n"));
        EncodeException e = assertThrows(EncodeException.class, () -> d.encode("prefix: c0:\nKV: []\n   GB: x\n"));
        assertTrue(e.getMessage().startsWith("Outline error at line 3"), e.getMessage());
        assertThrows(EncodeException.class, () -> d.encode("prefix: c0:\nKV: []\n- x\n"));
        assertThrows(EncodeException.class, () -> d.encode("prefix: c0:\nGB:\nKV: []\n"));
        assertThrows(EncodeException.class, () -> d.encode("prefix: c0:\n1A: x\n"));
        assertThrows(EncodeException.class, () -> d.encode("prefix: c0:\nKV: \"unterminated\n"));
        assertThrows(EncodeException.class, () -> d.encode("prefix: c0:\n- a\n;\n- b\n"));
    }

    static final String RESP = "s5|abcde/*DX*/({'id':1,'result':{'html':'<td>Order \\'1\\'</td>','keys':['1001','1002'],'pageIndex':0,'big':12345678901234567890}})";

    @Test
    void callbackResponseJson() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("POST").url("https://app.example.com/Orders.aspx")
                .statusCode(200).responseHeader("Content-Type", "text/html").responseBody(RESP).build();
        List<EditEngine.Document> all = app.editEngine().documents(m);
        assertEquals(1, all.size());
        EditableDocument d = all.get(0).document();
        assertEquals("/*DX*/ callback result (JSON)", d.title());
        assertEquals("json", d.syntax());
        assertTrue(d.text().contains("\"html\": \"<td>Order '1'</td>\""), d.text());
        assertArrayEquals(m.responseBody(), d.encode(d.text()).body());

        String body = new String(d.encode(d.text().replace("\"pageIndex\": 0", "\"pageIndex\": 7").replace("Order '1'", "<script>x</script>")).body(), StandardCharsets.UTF_8);
        assertEquals("s5|abcde/*DX*/({\"id\":1,\"result\":{\"html\":\"<td><script>x</script></td>\",\"keys\":[\"1001\",\"1002\"],\"pageIndex\":7,\"big\":12345678901234567890}})", body);
        DecodeResult r = dec.decode(m.patched(body.getBytes(StandardCharsets.UTF_8), null, null));
        assertTrue(TreeText.render(r.root()).contains("<script>x</script>"));
        assertTrue(TreeText.render(r.root()).contains("abcde"), "envelope kept");

        EncodeException e = assertThrows(EncodeException.class, () -> d.encode("{'id':1}"));
        assertTrue(e.getMessage().startsWith("JSON error: "), e.getMessage());
    }

    @Test
    void gzippedResponse() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
            gz.write("0|/*DX*/({'id':0,'result':'é'})".getBytes(StandardCharsets.UTF_8));
        }
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("POST").url("https://app.example.com/Orders.aspx")
                .statusCode(200).responseHeader("Content-Encoding", "gzip").responseBody(bos.toByteArray()).build();
        EditableDocument d = docs(m).get(0);
        byte[] out = d.encode(d.text().replace("é", "☃")).body();
        assertEquals("0|/*DX*/({\"id\":0,\"result\":\"☃\"})", new String(Codecs.gunzip(out), StandardCharsets.UTF_8));
    }

    @Test
    void nothingForUnstructuredOrUnparseable() throws Exception {
        assertTrue(docs(dx("plain text argument")).isEmpty());
        MessageContext js = MessageContext.builder(MessageKind.RESPONSE).method("POST").url("https://app.example.com/Orders.aspx")
                .statusCode(200).responseBody("0|/*DX*/({'id':0,'result':function(){return 1;}})").build();
        assertTrue(docs(js).isEmpty());
    }
}
