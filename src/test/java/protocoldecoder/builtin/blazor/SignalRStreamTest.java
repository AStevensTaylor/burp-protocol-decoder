package protocoldecoder.builtin.blazor;

import org.junit.jupiter.api.Test;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.core.WebSocketWindow;
import protocoldecoder.util.TreeText;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Hub messages split by the server across several WebSocket messages (4 KiB chunks). */
class SignalRStreamTest {

    final BlazorDecoder blazor = new BlazorDecoder();

    /** [1, {}, nil, "JS.BeginInvokeJS", [7, "app.render", argsJson, 0, 0]] with a large argsJson. */
    static byte[] bigInvoke(int size, char fill) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        MsgPackWriter.arrayHeader(o, 5);
        MsgPackWriter.integer(o, BigInteger.ONE);
        MsgPackWriter.mapHeader(o, 0);
        MsgPackWriter.nil(o);
        MsgPackWriter.strBytes(o, "JS.BeginInvokeJS".getBytes(StandardCharsets.UTF_8));
        MsgPackWriter.arrayHeader(o, 5);
        MsgPackWriter.integer(o, BigInteger.valueOf(7));
        MsgPackWriter.strBytes(o, "app.render".getBytes(StandardCharsets.UTF_8));
        String json = "[\"" + String.valueOf(fill).repeat(size) + "\",\"END-MARKER\"]";
        MsgPackWriter.strBytes(o, json.getBytes(StandardCharsets.UTF_8));
        MsgPackWriter.integer(o, BigInteger.ZERO);
        MsgPackWriter.integer(o, BigInteger.ZERO);
        return o.toByteArray();
    }

    static byte[] ping() {
        return new byte[]{(byte) 0x91, 6};
    }

    static List<byte[]> chunks(byte[] stream, int size) {
        List<byte[]> out = new ArrayList<>();
        for (int i = 0; i < stream.length; i += size) out.add(Arrays.copyOfRange(stream, i, Math.min(stream.length, i + size)));
        return out;
    }

    static MessageContext ws(List<byte[]> window, int current) {
        MessageContext.Builder b = MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("https://app.example.com/_blazor?id=tok")
                .webSocket("SERVER_TO_CLIENT", window.get(current));
        WebSocketWindow w = new WebSocketWindow(window, current);
        return b.webSocketWindow(() -> w).build();
    }

    String text(DecodeResult r) {
        return TreeText.render(r.root());
    }

    @Test
    void everyChunkOfASplitMessageDecodesTheWholeMessage() throws Exception {
        byte[] stream = BlazorCodecTest.framed(ping(), bigInvoke(10_000, 'a'));
        List<byte[]> parts = chunks(stream, 4096);
        assertEquals(3, parts.size());
        for (int i = 0; i < parts.size(); i++) {
            DecodeResult r = blazor.decode(ws(parts, i));
            String t = text(r);
            assertTrue(t.contains("END-MARKER"), "part " + i + ": " + t.substring(0, Math.min(400, t.length())));
            assertTrue(r.summary().contains(i == 0 ? "Ping, JS.BeginInvokeJS" : "JS.BeginInvokeJS (app.render)"), r.summary());
            assertTrue(r.summary().contains("reassembled from 3 WebSocket messages"), r.summary());
            assertTrue(t.contains("this one is part " + (i + 1)), t.substring(0, 300));
            assertTrue(r.warnings().isEmpty(), r.warnings().toString());
        }
        // The ping sharing the first chunk is shown too.
        assertTrue(blazor.decode(ws(parts, 0)).summary().startsWith("WebSocket server → client: 2 messages: Ping, JS.BeginInvokeJS"));
    }

    @Test
    void startIsFoundPastEarlierWholeMessages() throws Exception {
        List<byte[]> window = new ArrayList<>();
        for (int i = 0; i < 5; i++) window.add(BlazorCodecTest.framed(ping()));
        window.addAll(chunks(BlazorCodecTest.framed(bigInvoke(20_000, 'b')), 4096));
        window.add(BlazorCodecTest.framed(ping()));
        int middle = 7;
        DecodeResult r = blazor.decode(ws(window, middle));
        assertTrue(text(r).contains("END-MARKER"));
        assertTrue(r.summary().contains("reassembled from 5"), r.summary());
        // A whole message next to split ones decodes on its own.
        DecodeResult last = blazor.decode(ws(window, window.size() - 1));
        assertEquals("WebSocket server → client: Ping", last.summary());
    }

    @Test
    void unfinishedMessageWhenTheRestIsNotCaptured() throws Exception {
        List<byte[]> parts = chunks(BlazorCodecTest.framed(bigInvoke(10_000, 'c')), 4096);
        List<byte[]> seen = parts.subList(0, 2);
        DecodeResult r = blazor.decode(ws(seen, 1));
        assertTrue(r.summary().contains("part 2 of an unfinished hub message"), r.summary());
        assertTrue(r.summary().contains("8192 bytes of"), r.summary());
    }

    @Test
    void trailingStartOfAnotherSplitMessageIsNoted() throws Exception {
        byte[] stream = BlazorCodecTest.framed(bigInvoke(5_000, 'd'), bigInvoke(9_000, 'e'));
        List<byte[]> parts = chunks(stream, 4096);
        // Part 2 ends the first message and starts the second; only part 2 is captured after it.
        DecodeResult r = blazor.decode(ws(parts.subList(0, 2), 1));
        assertTrue(text(r).contains("runs past the captured ones"), text(r));
        assertTrue(r.summary().contains("JS.BeginInvokeJS"), r.summary());
        // With everything captured, part 2 shows both messages.
        DecodeResult all = blazor.decode(ws(parts, 1));
        assertTrue(all.summary().contains("2 messages: JS.BeginInvokeJS ×2"), all.summary());
    }

    @Test
    void jsonProtocolRecordsAreReassembled() throws Exception {
        String record = "{\"type\":1,\"target\":\"JS.BeginInvokeJS\",\"arguments\":[1,\"app.f\",\"[\\\"" + "x".repeat(9000) + "\\\",\\\"END-MARKER\\\"]\",0,0]}\u001e";
        List<byte[]> parts = chunks(record.getBytes(StandardCharsets.UTF_8), 4096);
        for (int i = 0; i < parts.size(); i++) {
            DecodeResult r = blazor.decode(ws(parts, i));
            assertTrue(text(r).contains("END-MARKER"), "part " + i);
            assertTrue(r.summary().contains("JS.BeginInvokeJS"), r.summary());
        }
    }

    @Test
    void withoutNeighboursAFragmentSaysWhereToLook() throws Exception {
        List<byte[]> parts = chunks(BlazorCodecTest.framed(bigInvoke(10_000, 'f')), 4096);
        MessageContext m = MessageContext.builder(MessageKind.WEBSOCKET).url("https://app.example.com/_blazor?id=tok")
                .webSocket("SERVER_TO_CLIENT", parts.get(0)).build();
        DecodeResult r = blazor.decode(m);
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("split across several WebSocket messages")), r.warnings().toString());
    }

    @Test
    void windowIsOnlyLoadedForFragments() throws Exception {
        int[] loads = {0};
        MessageContext m = MessageContext.builder(MessageKind.WEBSOCKET).url("https://app.example.com/_blazor?id=tok")
                .webSocket("SERVER_TO_CLIENT", BlazorCodecTest.framed(ping()))
                .webSocketWindow(() -> { loads[0]++; return null; }).build();
        assertEquals("WebSocket server → client: Ping", blazor.decode(m).summary());
        assertEquals(0, loads[0]);
    }
}
