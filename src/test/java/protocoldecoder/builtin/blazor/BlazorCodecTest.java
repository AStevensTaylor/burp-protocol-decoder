package protocoldecoder.builtin.blazor;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.BlazorDecoderTest;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.edit.EditEngine;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.util.TreeText;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BlazorCodecTest {

    static final String RS = "\u001e";
    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });
    final BlazorDecoder blazor = new BlazorDecoder();

    @AfterEach
    void close() {
        app.close();
    }

    static MessageContext ws(byte[] payload) {
        return MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("https://app.example.com/_blazor?id=tok123")
                .webSocket("CLIENT_TO_SERVER", payload).build();
    }

    List<EditEngine.Document> docs(MessageContext m) {
        return app.editEngine().documents(m).stream().filter(d -> d.decoderId().equals(BlazorDecoder.ID)).toList();
    }

    String decoded(MessageContext m) throws Exception {
        return TreeText.render(blazor.decode(m).root());
    }

    static byte[] framed(byte[]... messages) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] m : messages) {
            o.writeBytes(MsgPackWriter.varInt(m.length));
            o.writeBytes(m);
        }
        return o.toByteArray();
    }

    /** [1, {}, "7", "Exotic", [map{1:"one", "k": nil}, bin, f32 1.5, f64 2.0, -100, uint64 max, ext(5, 0102), true, "é😀"]] */
    static byte[] exotic() {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        MsgPackWriter.arrayHeader(o, 5);
        MsgPackWriter.integer(o, BigInteger.ONE);
        MsgPackWriter.mapHeader(o, 0);
        o.writeBytes(MsgPackWriter.str("7"));
        o.writeBytes(MsgPackWriter.str("Exotic"));
        MsgPackWriter.arrayHeader(o, 9);
        MsgPackWriter.mapHeader(o, 2);
        MsgPackWriter.integer(o, BigInteger.ONE);
        o.writeBytes(MsgPackWriter.str("one"));
        o.writeBytes(MsgPackWriter.str("k"));
        MsgPackWriter.nil(o);
        MsgPackWriter.bin(o, new byte[]{0, 1, 2, (byte) 0xff});
        MsgPackWriter.float32(o, 1.5f);
        MsgPackWriter.float64(o, 2.0);
        MsgPackWriter.integer(o, BigInteger.valueOf(-100));
        MsgPackWriter.integer(o, BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE));
        MsgPackWriter.ext(o, 5, new byte[]{1, 2});
        MsgPackWriter.bool(o, true);
        o.writeBytes(MsgPackWriter.str("é😀"));
        return o.toByteArray();
    }

    // ------------------------------------------------------------------ MessagePack

    @Test
    void blazorpackRoundTripsExactlyAndShowsLosslessJson() throws Exception {
        byte[] hs = ("{\"protocol\":\"blazorpack\",\"version\":1}" + RS).getBytes(StandardCharsets.UTF_8);
        // test-writer messages use int32 / bin32 (non-minimal) encodings: unchanged messages must keep them
        byte[] invoke = BlazorDecoderTest.frames(BlazorDecoderTest.l(1, java.util.Map.of(), "1", "BeginInvokeDotNetFromJS",
                BlazorDecoderTest.l("2", "MyApp", "Transfer", 0, "[{\"amount\":1000}]")));
        byte[] payload = concat(hs, invoke, framed(exotic()));
        MessageContext m = ws(payload);
        List<EditEngine.Document> ds = docs(m);
        assertEquals(1, ds.size());
        EditEngine.Document d = ds.get(0);
        assertEquals("SignalR MessagePack messages (handshake kept)", d.document().title());
        assertEquals("json", d.document().syntax());
        String t = d.document().text();
        assertTrue(t.contains("\"BeginInvokeDotNetFromJS\""), t);
        assertTrue(t.contains("\"$map\": ["), t);
        assertTrue(t.contains("\"$bin\": \"AAEC/w==\""), t);
        assertTrue(t.contains("\"$f32\": 1.5"), t);
        assertTrue(t.contains("      2.0,"), t);
        assertTrue(t.contains("-100"), t);
        assertTrue(t.contains("18446744073709551615"), t);
        assertTrue(t.contains("\"$ext\": [\n          5,\n          \"AQI=\"\n        ]"), t);
        assertTrue(t.contains("\"é😀\""), t);
        assertArrayEquals(payload, EditEngine.encode(d, t).body());
        // re-encoding the exotic message from its JSON gives the same (minimal) bytes
        assertArrayEquals(exotic(), MsgPackJson.fromJson(MsgPackJson.toJson(exotic(), 0, exotic().length), "m"));
    }

    @Test
    void editReencodesOnlyTheChangedMessageWithNewLengthPrefix() throws Exception {
        byte[] hs = ("{\"protocol\":\"blazorpack\",\"version\":1}" + RS).getBytes(StandardCharsets.UTF_8);
        byte[] first = BlazorDecoderTest.frames(BlazorDecoderTest.l(1, java.util.Map.of(), "1", "BeginInvokeDotNetFromJS",
                BlazorDecoderTest.l("2", "MyApp", "Transfer", 0, "[{\"amount\":1000}]")));
        byte[] second = BlazorDecoderTest.frames(BlazorDecoderTest.l(6));
        MessageContext m = ws(concat(hs, first, second));
        EditEngine.Document d = docs(m).get(0);
        String longArg = "[{\\\"amount\\\":99999999,\\\"note\\\":\\\"" + "x".repeat(200) + "\\\"}]";
        String edited = d.document().text().replace("[{\\\"amount\\\":1000}]", longArg);
        assertNotEquals(d.document().text(), edited);
        MessageContext out = EditEngine.encode(d, edited).applyTo(m);
        byte[] p = out.body();
        assertArrayEquals(hs, Arrays.copyOfRange(p, 0, hs.length), "handshake kept");
        assertArrayEquals(second, Arrays.copyOfRange(p, p.length - second.length, p.length), "untouched message kept byte-for-byte");
        assertEquals(0x80, p[hs.length] & 0x80, "two-byte VarInt length for a >127-byte message");
        String tree = decoded(out);
        assertTrue(tree.contains("99999999"), tree);
        assertTrue(tree.contains("Transfer"), tree);
    }

    @Test
    void renderBatchesStayBinaryAndInvalidEditsFail() throws Exception {
        byte[] batch = BlazorDecoderTest.frames(BlazorDecoderTest.l(1, java.util.Map.of(), null, "JS.RenderBatch",
                BlazorDecoderTest.l(3, BlazorDecoderTest.renderBatch())));
        MessageContext m = MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("https://app.example.com/_blazor?id=tok123")
                .webSocket("SERVER_TO_CLIENT", batch).build();
        EditEngine.Document d = docs(m).get(0);
        assertEquals("SignalR MessagePack messages (render batches as $bin, not editable structurally)", d.document().title());
        assertTrue(d.document().text().contains("\"$bin\""));
        assertArrayEquals(batch, EditEngine.encode(d, d.document().text()).body());
        MessageContext out = EditEngine.encode(d, d.document().text().replace("\n      3,", "\n      4,")).applyTo(m);
        assertTrue(decoded(out).contains("Batch ID: 4"), decoded(out));

        EncodeException e = assertThrows(EncodeException.class, () -> EditEngine.encode(d, "[\n  [1, {}, \n]"));
        assertTrue(e.getMessage().startsWith("JSON error at line 3"), e.getMessage());
        e = assertThrows(EncodeException.class, () -> EditEngine.encode(d, "[[1, {\"$ext\": [500, \"AA==\"]}]]"));
        assertTrue(e.getMessage().contains("ext type"), e.getMessage());
        e = assertThrows(EncodeException.class, () -> EditEngine.encode(d, "[[1, 18446744073709551616]]"));
        assertTrue(e.getMessage().contains("out of the MessagePack range"), e.getMessage());
        e = assertThrows(EncodeException.class, () -> EditEngine.encode(d, "[[1, {\"$bin\": \"not base64!\"}]]"));
        assertTrue(e.getMessage().contains("base64"), e.getMessage());
        assertThrows(EncodeException.class, () -> EditEngine.encode(d, "{\"type\": 1}"));
    }

    @Test
    void tagLookalikeMapsAndInvalidUtf8AreLossless() throws Exception {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        MsgPackWriter.arrayHeader(o, 3);
        MsgPackWriter.mapHeader(o, 1); // a real map {"$bin": "x"} must not become a bin
        o.writeBytes(MsgPackWriter.str("$bin"));
        o.writeBytes(MsgPackWriter.str("x"));
        MsgPackWriter.strBytes(o, new byte[]{(byte) 0xc3, 0x28}); // invalid UTF-8 str
        MsgPackWriter.float64(o, Double.NaN);
        byte[] msg = o.toByteArray();
        var json = MsgPackJson.toJson(msg, 0, msg.length);
        assertEquals("[{\"$map\":[[\"$bin\",\"x\"]]},{\"$strbin\":\"wyg=\"},{\"$f64\":\"NaN\"}]", protocoldecoder.util.EditJson.compact(json));
        assertArrayEquals(msg, MsgPackJson.fromJson(json, "m"));
    }

    // ------------------------------------------------------------------ JSON hub protocol

    @Test
    void jsonHubProtocolRecords() throws Exception {
        // server-style escaping (<) must survive for unchanged records
        String recs = "{\"type\":1,\"target\":\"ReceiveMessage\",\"arguments\":[\"\\u003cb\\u003e\",1.0]}" + RS + "{\"type\":6}" + RS;
        MessageContext m = MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("https://chat.example.com/hub?id=abc")
                .webSocket("SERVER_TO_CLIENT", recs.getBytes(StandardCharsets.UTF_8)).build();
        EditEngine.Document d = docs(m).get(0);
        assertEquals("SignalR JSON messages", d.document().title());
        assertTrue(d.document().text().startsWith("[\n  {\n    \"type\": 1,"), d.document().text());
        assertEquals(recs, new String(EditEngine.encode(d, d.document().text()).body(), StandardCharsets.UTF_8));

        String edited = d.document().text().replace("\"<b>\"", "\"<img src=x onerror=alert(1)> \\\"quoted\\\"\"");
        String out = new String(EditEngine.encode(d, edited).body(), StandardCharsets.UTF_8);
        assertEquals("{\"type\":1,\"target\":\"ReceiveMessage\",\"arguments\":[\"<img src=x onerror=alert(1)> \\\"quoted\\\"\",1.0]}" + RS
                + "{\"type\":6}" + RS, out);
        MessageContext em = EditEngine.encode(d, edited).applyTo(m);
        assertTrue(decoded(em).contains("onerror=alert(1)"), decoded(em));

        assertThrows(EncodeException.class, () -> EditEngine.encode(d, "[1]"));
    }

    @Test
    void handshakeOnlyAndLongPolling() throws Exception {
        String hs = "{\"protocol\":\"json\",\"version\":1}" + RS;
        MessageContext m = ws(hs.getBytes(StandardCharsets.UTF_8));
        EditEngine.Document d = docs(m).get(0);
        assertEquals("SignalR handshake (JSON)", d.document().title());
        assertEquals(hs, new String(EditEngine.encode(d, d.document().text()).body(), StandardCharsets.UTF_8));
        assertEquals("{\"protocol\":\"messagepack\",\"version\":1}" + RS,
                new String(EditEngine.encode(d, d.document().text().replace("\"json\"", "\"messagepack\"")).body(), StandardCharsets.UTF_8));

        byte[] body = BlazorDecoderTest.frames(BlazorDecoderTest.l(1, java.util.Map.of(), "3", "OnLocationChanged",
                BlazorDecoderTest.l("https://app.example.com/a", null, false)));
        MessageContext poll = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/_blazor?id=tok123")
                .requestBody(body).build();
        EditEngine.Document pd = docs(poll).get(0);
        assertArrayEquals(body, EditEngine.encode(pd, pd.document().text()).body());
        MessageContext out = EditEngine.encode(pd, pd.document().text().replace("https://app.example.com/a", "https://app.example.com/admin")).applyTo(poll);
        assertTrue(decoded(out).contains("https://app.example.com/admin"), decoded(out));

        MessageContext negotiate = MessageContext.builder(MessageKind.RESPONSE).method("POST").url("https://app.example.com/_blazor/negotiate?negotiateVersion=1")
                .statusCode(200).responseBody("{\"connectionId\":\"x\"}").build();
        assertTrue(docs(negotiate).isEmpty());
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) o.writeBytes(p);
        return o.toByteArray();
    }
}
