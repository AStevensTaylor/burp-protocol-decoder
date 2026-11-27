package protocoldecoder.builtin.blazor;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.scan.InsertionPoint;
import protocoldecoder.util.TreeText;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static protocoldecoder.BlazorDecoderTest.frames;
import static protocoldecoder.BlazorDecoderTest.l;

/** Insertion points added to {@link BlazorScanner} (its passive checks are covered in ScanEngineTest / BlazorDecoderTest). */
class BlazorScannerTest {

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });
    final BlazorDecoder decoder = new BlazorDecoder();

    @AfterEach
    void close() {
        app.close();
    }

    static final String RS = "\u001e";
    static final String NASTY = "x\"'<>\u001e\\]}é😀";

    static MessageContext send(byte[] body) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/_blazor?id=tok123")
                .requestHeader("Content-Type", "text/plain;charset=UTF-8").requestBody(body).build();
    }

    static MessageContext send(String body) {
        return send(body.getBytes(StandardCharsets.UTF_8));
    }

    List<InsertionPoint> points(MessageContext m) {
        return app.scanEngine().insertionPoints(m).stream().filter(i -> i.name().startsWith("Blazor:")).toList();
    }

    static InsertionPoint named(List<InsertionPoint> ips, String name) {
        return ips.stream().filter(i -> i.name().equals(name)).findFirst()
                .orElseThrow(() -> new AssertionError(name + " not in " + ips.stream().map(InsertionPoint::name).toList()));
    }

    static boolean hasValue(DecodedNode n, String v) {
        if (v.equals(n.value())) return true;
        for (DecodedNode c : n.children()) if (hasValue(c, v)) return true;
        return false;
    }

    DecodeResult decodeRendered(InsertionPoint ip, String payload) throws Exception {
        DecodeResult r = decoder.decode(send(ip.render().apply(payload)));
        assertTrue(r.warnings().isEmpty(), r.warnings() + "\n" + TreeText.render(r.root()));
        return r;
    }

    // ------------------------------------------------------------ JSON hub protocol

    static final String JSON_BODY = "{\"type\":1,\"target\":\"BeginInvokeDotNetFromJS\",\"arguments\":[\"3\",\"MyApp\",\"Save\",null,\"[\\\"bob\\\",{\\\"age\\\":3}]\"]}" + RS
            + "{\"type\":1,\"target\":\"DispatchBrowserEvent\",\"arguments\":[\"{\\\"eventHandlerId\\\":7,\\\"eventName\\\":\\\"change\\\",\\\"eventFieldInfo\\\":null}\",\"{\\\"value\\\":\\\"abc\\\"}\"]}" + RS
            + "{\"type\":6}" + RS;

    @Test
    void jsonProtocolPointsIncludeJsonInStringArguments() {
        List<String> names = points(send(JSON_BODY)).stream().map(InsertionPoint::name).toList();
        assertEquals(List.of(
                "Blazor: BeginInvokeDotNetFromJS callId", "Blazor: BeginInvokeDotNetFromJS assemblyName", "Blazor: BeginInvokeDotNetFromJS methodIdentifier",
                "Blazor: BeginInvokeDotNetFromJS argsJson $[0]", "Blazor: BeginInvokeDotNetFromJS argsJson $[1].age",
                "Blazor: DispatchBrowserEvent eventDescriptor $.eventHandlerId", "Blazor: DispatchBrowserEvent eventDescriptor $.eventName",
                "Blazor: DispatchBrowserEvent eventArgs $.value"), names);
    }

    @Test
    void jsonProtocolRoundTrip() throws Exception {
        List<InsertionPoint> ips = points(send(JSON_BODY));
        InsertionPoint value = named(ips, "Blazor: DispatchBrowserEvent eventArgs $.value");
        assertEquals("abc", value.baseValue());
        String rendered = new String(value.render().apply(NASTY), StandardCharsets.UTF_8);
        assertTrue(rendered.startsWith(JSON_BODY.substring(0, JSON_BODY.indexOf(RS) + 1)), "first record untouched: " + rendered);
        assertTrue(rendered.endsWith(RS + "{\"type\":6}" + RS), rendered);
        assertEquals(3, rendered.split(RS).length, "the payload's own 0x1E must be escaped inside the JSON");
        DecodeResult r = decodeRendered(value, NASTY);
        assertTrue(hasValue(r.root(), NASTY), TreeText.render(r.root()));

        InsertionPoint method = named(ips, "Blazor: BeginInvokeDotNetFromJS methodIdentifier");
        assertTrue(hasValue(decodeRendered(method, NASTY).root(), NASTY));
        InsertionPoint inner = named(ips, "Blazor: BeginInvokeDotNetFromJS argsJson $[0]");
        assertEquals("bob", inner.baseValue());
        DecodeResult ri = decodeRendered(inner, NASTY);
        assertTrue(hasValue(ri.root(), NASTY), TreeText.render(ri.root()));
        assertTrue(hasValue(ri.root(), "3"), "sibling inner value kept");
    }

    // ------------------------------------------------------------ MessagePack (blazorpack)

    static byte[] packBody(boolean handshake) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        if (handshake) o.writeBytes(("{\"protocol\":\"blazorpack\",\"version\":1}" + RS).getBytes(StandardCharsets.UTF_8));
        o.writeBytes(frames(
                l(1, Map.of(), null, "BeginInvokeDotNetFromJS", l("1", "MyApp", "Save", null, "[\"bob\",42]")),
                l(1, Map.of(), null, "OnRenderCompleted", l(3, null)),
                l(6)));
        return o.toByteArray();
    }

    @Test
    void messagePackPointsForStringArguments() {
        List<String> names = points(send(packBody(false))).stream().map(InsertionPoint::name).toList();
        assertEquals(List.of("Blazor: BeginInvokeDotNetFromJS callId", "Blazor: BeginInvokeDotNetFromJS assemblyName",
                "Blazor: BeginInvokeDotNetFromJS methodIdentifier", "Blazor: BeginInvokeDotNetFromJS argsJson $[0]",
                "Blazor: BeginInvokeDotNetFromJS argsJson $[1]"), names);
    }

    @Test
    void messagePackRoundTripRecomputesLengths() throws Exception {
        byte[] base = packBody(true);
        List<InsertionPoint> ips = points(send(base));
        // long payload: str8 → str16 header and a two-byte VarInt frame length
        String big = NASTY + "A".repeat(300) + NASTY;
        InsertionPoint asm = named(ips, "Blazor: BeginInvokeDotNetFromJS assemblyName");
        byte[] rendered = asm.render().apply(big);
        assertTrue(new String(rendered, StandardCharsets.UTF_8).startsWith("{\"protocol\":\"blazorpack\",\"version\":1}" + RS), "handshake kept");
        DecodeResult r = decodeRendered(asm, big);
        assertTrue(hasValue(r.root(), big), TreeText.render(r.root()));
        assertTrue(r.summary().contains("OnRenderCompleted"), r.summary());
        assertTrue(r.summary().contains("Ping"), r.summary());

        InsertionPoint inner = named(ips, "Blazor: BeginInvokeDotNetFromJS argsJson $[0]");
        DecodeResult ri = decodeRendered(inner, NASTY);
        assertTrue(hasValue(ri.root(), NASTY), TreeText.render(ri.root()));
        assertTrue(hasValue(ri.root(), "42"));
        // short payload keeps the message byte-identical apart from the replaced string and length prefix
        InsertionPoint call = named(ips, "Blazor: BeginInvokeDotNetFromJS callId");
        assertArrayEquals(base, call.render().apply("1"));
    }

    @Test
    void noPointsForPollsNonInvocationsOrOtherPaths() {
        assertTrue(points(send(frames(l(6), l(3, Map.of(), "1", 2)))).isEmpty());
        assertTrue(points(send("{\"protocol\":\"json\",\"version\":1}" + RS)).isEmpty());
        MessageContext ws = MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("https://app.example.com/_blazor?id=t")
                .webSocket("CLIENT_TO_SERVER", packBody(false)).build();
        assertTrue(app.scanEngine().insertionPoints(ws).isEmpty());
        MessageContext neg = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/_blazor/negotiate?negotiateVersion=1").build();
        assertTrue(points(neg).isEmpty());
    }

    // ------------------------------------------------------------ writer

    @Test
    void writerEncodingsDecode() throws Exception {
        for (int n : new int[]{0, 31, 32, 255, 256, 65535, 65536}) {
            String s = "é".repeat(n / 2) + "a".repeat(n % 2);
            byte[] enc = MsgPackWriter.str(s);
            assertEquals(s, MsgPackWriter.read(enc, 0, enc.length), "length " + n);
            assertEquals(enc.length, MsgPackWriter.skip(enc, 0, enc.length));
        }
        for (int n : new int[]{1, 127, 128, 16383, 16384, 2_000_000}) {
            byte[] frame = new byte[MsgPackWriter.varInt(n).length + n];
            System.arraycopy(MsgPackWriter.varInt(n), 0, frame, 0, MsgPackWriter.varInt(n).length);
            List<int[]> f = SignalR.binaryFrames(frame, 0);
            assertNotNull(f, "varint " + n);
            assertEquals(n, f.get(0)[1] - f.get(0)[0]);
        }
        assertArrayEquals(new int[]{3, 1}, MsgPackWriter.arrayHeader(new byte[]{(byte) 0x93}, 0, 1));
        assertNull(MsgPackWriter.arrayHeader(new byte[]{(byte) 0xa1}, 0, 1));
    }
}
