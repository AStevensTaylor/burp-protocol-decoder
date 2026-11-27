package protocoldecoder;

import org.junit.jupiter.api.Test;
import protocoldecoder.builtin.blazor.BlazorDecoder;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.util.TreeText;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class BlazorDecoderTest {

    final BlazorDecoder blazor = new BlazorDecoder();

    // ------------------------------------------------------------ tiny MessagePack writer for test data

    static final class Pack {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();

        Pack value(Object v) {
            if (v == null) out.write(0xc0);
            else if (v instanceof Boolean b) out.write(b ? 0xc3 : 0xc2);
            else if (v instanceof Integer i) intVal(i);
            else if (v instanceof String s) str(s);
            else if (v instanceof byte[] b) { out.write(0xc6); int32be(b.length); out.writeBytes(b); }
            else if (v instanceof List<?> l) { arrayHeader(l.size()); l.forEach(this::value); }
            else if (v instanceof Map<?, ?> m) { out.write(0x80 | m.size()); m.forEach((k, x) -> { value(k); value(x); }); }
            else throw new IllegalArgumentException(v.getClass().toString());
            return this;
        }

        void intVal(int i) {
            if (i >= 0 && i < 128) out.write(i);
            else { out.write(0xd2); int32be(i); }
        }

        void str(String s) {
            byte[] b = s.getBytes(StandardCharsets.UTF_8);
            if (b.length < 32) out.write(0xa0 | b.length);
            else { out.write(0xda); out.write(b.length >> 8); out.write(b.length & 0xff); }
            out.writeBytes(b);
        }

        void arrayHeader(int n) {
            if (n < 16) out.write(0x90 | n);
            else { out.write(0xdc); out.write(n >> 8); out.write(n & 0xff); }
        }

        void int32be(int v) {
            out.write(v >>> 24); out.write(v >>> 16); out.write(v >>> 8); out.write(v);
        }
    }

    /** SignalR binary framing: VarInt length + MessagePack message. */
    public static List<Object> l(Object... items) {
        return java.util.Arrays.asList(items);
    }

    public static byte[] frames(List<?>... messages) {
        ByteArrayOutputStream all = new ByteArrayOutputStream();
        for (List<?> m : messages) {
            byte[] body = new Pack().value(m).out.toByteArray();
            int len = body.length;
            do {
                int b = len & 0x7f;
                len >>>= 7;
                all.write(len > 0 ? b | 0x80 : b);
            } while (len > 0);
            all.writeBytes(body);
        }
        return all.toByteArray();
    }

    /** Builds a render batch: component 5 prepends <div> containing "Hello"; disposes component 9. */
    public static byte[] renderBatch() {
        ByteBuffer b = ByteBuffer.allocate(512).order(ByteOrder.LITTLE_ENDIAN);
        int diff = b.position();
        b.putInt(5).putInt(2);                         // componentId, 2 edits
        b.putInt(1).putInt(0).putInt(0).putInt(-1);    // PrependFrame @0 → frame 0
        b.putInt(4).putInt(0).putInt(0).putInt(2);     // RemoveAttribute @0 → string 2
        int uc = b.position();
        b.putInt(1).putInt(diff);
        int rf = b.position();
        b.putInt(3);
        b.putInt(1).putInt(3).putInt(0).putInt(0).putInt(0);              // Element <div>, subtree 3
        b.putInt(3).putInt(2).putInt(3).putLong(7);                         // Attribute class="x" handler 7
        b.putInt(2).putInt(1).putInt(0).putInt(0).putInt(0);              // Text "Hello"
        int dc = b.position();
        b.putInt(1).putInt(9);
        int de = b.position();
        b.putInt(0);
        String[] strings = {"div", "Hello", "class", "x"};
        int[] pos = new int[strings.length];
        for (int i = 0; i < strings.length; i++) {
            pos[i] = b.position();
            byte[] s = strings[i].getBytes(StandardCharsets.UTF_8);
            b.put((byte) s.length).put(s);
        }
        int st = b.position();
        for (int p : pos) b.putInt(p);
        b.putInt(uc).putInt(rf).putInt(dc).putInt(de).putInt(st);
        byte[] out = new byte[b.position()];
        b.flip().get(out);
        return out;
    }

    static MessageContext ws(String direction, byte[] payload) {
        return MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("https://app.example.com/_blazor?id=tok123")
                .webSocket(direction, payload).build();
    }

    static String find(DecodedNode n, String nameContains) {
        if (n.name().contains(nameContains) && n.value() != null) return n.value();
        for (DecodedNode c : n.children()) {
            String v = find(c, nameContains);
            if (v != null) return v;
        }
        return null;
    }

    // ------------------------------------------------------------ tests

    @Test
    void handshakeThenBinaryInvocation() throws Exception {
        byte[] hs = "{\"protocol\":\"blazorpack\",\"version\":1}\u001e".getBytes(StandardCharsets.UTF_8);
        byte[] inv = frames(l(1, Map.of(), "0", "BeginInvokeDotNetFromJS",
                l("3", "MyApp", "SaveOrder", 0, "[{\"orderId\":42}]")));
        byte[] payload = new byte[hs.length + inv.length];
        System.arraycopy(hs, 0, payload, 0, hs.length);
        System.arraycopy(inv, 0, payload, hs.length, inv.length);
        MessageContext m = ws("CLIENT_TO_SERVER", payload);
        assertEquals(90, blazor.match(m).confidence());
        DecodeResult r = blazor.decode(m);
        assertEquals("WebSocket client → server: 2 messages: Handshake, BeginInvokeDotNetFromJS", r.summary());
        assertEquals("SaveOrder", find(r.root(), "methodIdentifier"));
        assertEquals("42", find(r.root(), "orderId"));
        assertEquals("tok123", find(r.root(), "Connection token"));
    }

    @Test
    void renderBatchIsDecoded() throws Exception {
        MessageContext m = ws("SERVER_TO_CLIENT", frames(l(1, Map.of(), null, "JS.RenderBatch", l(12, renderBatch()))));
        DecodeResult r = blazor.decode(m);
        assertEquals("WebSocket server → client: JS.RenderBatch #12 (1 component updated, 3 frames)", r.summary());
        String text = TreeText.render(r.root());
        assertTrue(text.contains("PrependFrame @0 → <div>  (subtree 3)"), text);
        assertTrue(text.contains("RemoveAttribute @0 → class"), text);
        assertTrue(text.contains("Attribute class=\\\"x\\\"  (event handler 7)"), text);
        assertTrue(text.contains("Text \\\"Hello\\\""), text);
        assertTrue(text.contains("Disposed component IDs"), text);
        assertTrue(r.warnings().isEmpty());
    }

    @Test
    void corruptRenderBatchFallsBack() throws Exception {
        byte[] junk = new byte[64];
        java.util.Arrays.fill(junk, (byte) 0x7f);
        DecodeResult r = blazor.decode(ws("SERVER_TO_CLIENT", frames(l(1, Map.of(), null, "JS.RenderBatch", l(1, junk)))));
        assertTrue(TreeText.render(r.root()).contains("not a recognised render batch"), TreeText.render(r.root()));
    }

    @Test
    void browserEventAndPingAndCompletion() throws Exception {
        byte[] p = frames(
                l(1, Map.of(), null, "DispatchBrowserEvent", l("{\"eventHandlerId\":7,\"eventName\":\"click\"}", "{\"type\":\"click\",\"detail\":1}")),
                l(6),
                l(3, Map.of(), "4", 1, "Boom"));
        DecodeResult r = blazor.decode(ws("CLIENT_TO_SERVER", p));
        assertEquals("WebSocket client → server: 3 messages: DispatchBrowserEvent, Ping, Completion", r.summary());
        assertEquals("click", find(r.root(), "eventName"));
        assertEquals("1 (error)", find(r.root(), "Result kind"));
        assertEquals("Boom", find(r.root(), "Error"));
    }

    @Test
    void jsonHubProtocol() throws Exception {
        String recs = "{\"type\":1,\"target\":\"JS.BeginInvokeJS\",\"arguments\":[1,\"localStorage.getItem\",\"[\\\"token\\\"]\",0,0]}\u001e{\"type\":6}\u001e";
        MessageContext m = MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("https://x.example/chathub")
                .webSocket("SERVER_TO_CLIENT", recs.getBytes(StandardCharsets.UTF_8)).build();
        assertEquals(60, blazor.match(m).confidence());
        DecodeResult r = blazor.decode(m);
        assertTrue(r.summary().contains("JS.BeginInvokeJS"), r.summary());
        assertEquals("localStorage.getItem", find(r.root(), "identifier"));
    }

    @Test
    void genericMessagePackHubMatchesLower() {
        MessageContext m = MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("https://x.example/hubs/chat")
                .webSocket("SERVER_TO_CLIENT", frames(l(1, Map.of(), null, "ReceiveMessage", l("bob", "hi")))).build();
        assertEquals(50, blazor.match(m).confidence());
        assertEquals(0, blazor.match(MessageContext.builder(MessageKind.WEBSOCKET).url("https://x.example/ws")
                .webSocket("SERVER_TO_CLIENT", "hello".getBytes()).build()).confidence());
    }

    @Test
    void negotiateResponse() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("POST").url("https://app.example.com/_blazor/negotiate?negotiateVersion=1")
                .statusCode(200).responseBody("{\"negotiateVersion\":1,\"connectionId\":\"abc\",\"connectionToken\":\"tok\",\"availableTransports\":[{\"transport\":\"WebSockets\",\"transferFormats\":[\"Text\",\"Binary\"]}]}")
                .build();
        assertEquals(90, blazor.match(m).confidence());
        DecodeResult r = blazor.decode(m);
        assertEquals("Negotiate response (connection abc)", r.summary());
        assertTrue(TreeText.render(r.root()).contains("WebSockets"));
    }

    @Test
    void longPollingBody() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/_blazor?id=tok")
                .requestBody(frames(l(1, Map.of(), null, "OnRenderCompleted", l(3, null)))).build();
        assertEquals(90, blazor.match(m).confidence());
        assertEquals("Long polling send: OnRenderCompleted", blazor.decode(m).summary());
    }

    @Test
    void prerenderedHtmlMarkers() throws Exception {
        String inner = Base64.getEncoder().encodeToString("{\"count\":3}".getBytes(StandardCharsets.UTF_8));
        String state = Base64.getEncoder().encodeToString(("{\"WeatherData\":\"" + inner + "\"}").getBytes(StandardCharsets.UTF_8));
        String html = "<html><body><!--Blazor:{\"type\":\"server\",\"sequence\":0,\"descriptor\":\"CfDJ8abc\"}--><p>hi</p><!--Blazor:{\"prerenderId\":\"x\"}-->"
                + "<!--Blazor-WebAssembly-Component-State:" + state + "--></body></html>";
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://app.example.com/")
                .statusCode(200).responseHeader("Content-Type", "text/html").responseBody(html).build();
        assertEquals(50, blazor.match(m).confidence());
        DecodeResult r = blazor.decode(m);
        assertEquals("Prerendered page: 2 component markers", r.summary());
        assertEquals("CfDJ8abc", find(r.root(), "descriptor"));
        assertEquals("3", find(r.root(), "count"));
        assertEquals(1, r.warnings().size());
    }

    @Test
    void bootManifest() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://app.example.com/_framework/blazor.boot.json")
                .statusCode(200).responseBody("{\"mainAssemblyName\":\"MyApp.Client\",\"debugBuild\":true,\"resources\":{\"assembly\":{\"A.dll\":\"sha\",\"B.dll\":\"sha\"}}}").build();
        assertEquals("WebAssembly boot manifest — MyApp.Client (debug build), 2 assemblies", blazor.decode(m).summary());
    }
}
