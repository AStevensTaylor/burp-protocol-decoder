package protocoldecoder.builtin.grpc;

import org.junit.jupiter.api.Test;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.util.TreeText;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Random;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class GrpcDecoderTest {

    final GrpcDecoder grpc = new GrpcDecoder();
    static final String URL = "https://api.example.com/helloworld.Greeter/SayHello";

    // ------------------------------------------------------------ tiny protobuf writer for fixtures

    static final class Pb {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();

        Pb rawVarint(long v) {
            while ((v & ~0x7fL) != 0) {
                out.write((int) ((v & 0x7f) | 0x80));
                v >>>= 7;
            }
            out.write((int) v);
            return this;
        }

        Pb tag(int field, int wire) { return rawVarint(((long) field << 3) | wire); }
        Pb varint(int f, long v) { return tag(f, 0).rawVarint(v); }
        Pb sint(int f, long v) { return varint(f, (v << 1) ^ (v >> 63)); }
        Pb fixed64(int f, long v) { tag(f, 1); for (int i = 0; i < 8; i++) out.write((int) (v >>> (8 * i))); return this; }
        Pb fixed32(int f, int v) { tag(f, 5); for (int i = 0; i < 4; i++) out.write(v >>> (8 * i)); return this; }
        Pb bytes(int f, byte[] b) { tag(f, 2).rawVarint(b.length); out.writeBytes(b); return this; }
        Pb str(int f, String s) { return bytes(f, s.getBytes(StandardCharsets.UTF_8)); }
        Pb msg(int f, Pb m) { return bytes(f, m.build()); }
        byte[] build() { return out.toByteArray(); }
    }

    static Pb pb() { return new Pb(); }

    static byte[] frame(int flags, byte[] payload) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(flags);
        int n = payload.length;
        o.write(n >>> 24); o.write(n >>> 16); o.write(n >>> 8); o.write(n);
        o.writeBytes(payload);
        return o.toByteArray();
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) o.writeBytes(p);
        return o.toByteArray();
    }

    static byte[] gzip(byte[] b) throws IOException {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        try (OutputStream z = new GZIPOutputStream(o)) { z.write(b); }
        return o.toByteArray();
    }

    static byte[] deflate(byte[] b) throws IOException {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        try (OutputStream z = new DeflaterOutputStream(o)) { z.write(b); }
        return o.toByteArray();
    }

    static byte[] ascii(String s) { return s.getBytes(StandardCharsets.UTF_8); }

    static MessageContext.Builder req(String contentType, byte[] body) {
        MessageContext.Builder b = MessageContext.builder(MessageKind.REQUEST).method("POST").url(URL).requestBody(body);
        if (contentType != null) b.requestHeader("Content-Type", contentType);
        return b;
    }

    static MessageContext.Builder resp(String reqType, String respType, byte[] body) {
        MessageContext.Builder b = MessageContext.builder(MessageKind.RESPONSE).method("POST").url(URL)
                .requestHeader("Content-Type", reqType).requestBody(new byte[0]).statusCode(200);
        if (respType != null) b.responseHeader("Content-Type", respType);
        return b.responseBody(body);
    }

    static byte[] helloRequest() {
        return pb().str(1, "world").msg(2, pb().varint(1, 42).str(2, "nested text")).bytes(3, new byte[]{(byte) 0xff, 0x00, (byte) 0xfe}).build();
    }

    // ------------------------------------------------------------ schemaless protobuf

    @Test
    void nestedMessagesStringsAndBytes() throws Exception {
        DecodeResult r = grpc.decode(req("application/grpc-web+proto", frame(0, helloRequest())).build());
        assertEquals("gRPC-Web → helloworld.Greeter/SayHello (1 message, 3 fields)", r.summary());
        DecodedNode msg = r.root().get("message 1");
        assertEquals(DecodedNode.Type.STRING, msg.get("1").type());
        assertEquals("world", msg.get("1").value());
        DecodedNode nested = msg.get("2");
        assertEquals(DecodedNode.Type.OBJECT, nested.type());
        assertEquals("42", nested.get("1").value());
        assertEquals("nested text", nested.get("2").value());
        assertEquals(DecodedNode.Type.BINARY, msg.get("3").type());
        assertTrue(msg.get("3").value().startsWith("ff 00 fe"));
        DecodedNode call = r.root().get("call");
        assertEquals("helloworld", call.get("package").value());
        assertEquals("helloworld.Greeter", call.get("service").value());
        assertEquals("SayHello", call.get("method").value());
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
    }

    @Test
    void stringVersusBytesHeuristics() {
        byte[] b = pb().str(1, "héllo ✓ wörld").bytes(2, new byte[]{(byte) 0xc3, 0x28}) // invalid UTF-8
                .str(3, "").str(4, "line1\nline2").build();
        Protobuf.Parsed p = Protobuf.parse(b);
        assertTrue(p.complete());
        DecodedNode root = DecodedNode.object("m");
        Protobuf.render(p.fields, root);
        assertEquals("héllo ✓ wörld", root.get("1").value());
        assertEquals(DecodedNode.Type.BINARY, root.get("2").type());
        assertEquals("", root.get("3").value());
        assertEquals("line1\nline2", root.get("4").value());

        // Printable text that happens to parse as protobuf stays a string ("hi" = field 13 varint 105).
        Protobuf.Parsed p2 = Protobuf.parse(pb().str(1, "hi").build());
        assertEquals(Protobuf.LenKind.STRING, p2.fields.get(0).kind);

        // Printable bytes starting with 0x0a that parse as a message are treated as a message (field 1 = "helloworld").
        byte[] inner = pb().str(1, "helloworld").build(); // 0a 0a 'helloworld' — all "printable"
        Protobuf.Parsed p3 = Protobuf.parse(pb().bytes(5, inner).build());
        assertEquals(Protobuf.LenKind.MESSAGE, p3.fields.get(0).kind);
    }

    @Test
    void negativeAndZigzagVarints() {
        byte[] b = pb().varint(1, -1L).sint(2, -5).varint(3, 1).varint(4, 150).varint(5, -2147483648L).build();
        DecodedNode root = DecodedNode.object("m");
        Protobuf.render(Protobuf.parse(b).fields, root);
        assertEquals("18446744073709551615 (int64 -1)", root.get("1").value());
        assertEquals("9 (sint -5)", root.get("2").value());
        assertEquals("1", root.get("3").value());
        assertEquals("150", root.get("4").value());
        assertTrue(root.get("5").value().contains("int64 -2147483648"));
        assertEquals(DecodedNode.Type.NUMBER, root.get("2").type());
    }

    @Test
    void fixedWidthAsFloatingPoint() {
        byte[] b = pb().fixed64(1, Double.doubleToLongBits(3.5)).fixed32(2, Float.floatToIntBits(1.5f)).fixed32(3, 7).fixed64(4, -2L).build();
        DecodedNode root = DecodedNode.object("m");
        Protobuf.render(Protobuf.parse(b).fields, root);
        assertTrue(root.get("1").value().contains("double 3.5"), root.get("1").value());
        assertTrue(root.get("2").value().contains("float 1.5"), root.get("2").value());
        assertTrue(root.get("3").value().startsWith("7 ("), root.get("3").value());
        assertFalse(root.get("3").value().contains("float"), "denormal float should not be offered");
        assertTrue(root.get("4").value().contains("int64 -2"), root.get("4").value());
    }

    @Test
    void packedRepeatedShownAsBytesWithPackedReading() {
        Pb packed = pb();
        for (long v : new long[]{1, 2, 3, 300}) packed.rawVarint(v);
        DecodedNode root = DecodedNode.object("m");
        Protobuf.render(Protobuf.parse(pb().bytes(4, packed.build()).build()).fields, root);
        DecodedNode f = root.get("4");
        assertEquals(DecodedNode.Type.BINARY, f.type());
        assertTrue(f.value().endsWith("as packed varints: [1, 2, 3, 300]"), f.value());
    }

    @Test
    void repeatedFieldsKeepOrder() {
        byte[] b = pb().str(1, "a").str(1, "b").str(1, "c").build();
        DecodedNode root = DecodedNode.object("m");
        Protobuf.render(Protobuf.parse(b).fields, root);
        assertEquals(3, root.children().size());
        assertEquals("c", root.children().get(2).value());
    }

    @Test
    void groupsAndInvalidWireTypesRejected() {
        Protobuf.Parsed g = Protobuf.parse(pb().varint(1, 5).tag(2, 3).build());
        assertEquals(1, g.fields.size());
        assertTrue(g.error.contains("group"), g.error);
        Protobuf.Parsed w = Protobuf.parse(pb().tag(3, 6).build());
        assertTrue(w.error.contains("invalid wire type 6"), w.error);
        // A nested candidate containing a group is not taken as a message.
        Protobuf.Parsed n = Protobuf.parse(pb().bytes(1, pb().tag(1, 3).tag(1, 4).build()).build());
        assertEquals(Protobuf.LenKind.BYTES, n.fields.get(0).kind);
    }

    @Test
    void deepNestingIsBounded() {
        Pb m = pb().varint(1, 1);
        for (int i = 0; i < 200; i++) m = pb().msg(1, m);
        Protobuf.Parsed p = Protobuf.parse(m.build());
        assertTrue(p.complete());
        DecodedNode root = DecodedNode.object("m");
        Protobuf.render(p.fields, root);
        int depth = 0;
        DecodedNode n = root;
        while (n.get("1") != null && n.get("1").type() == DecodedNode.Type.OBJECT) { n = n.get("1"); depth++; }
        assertTrue(depth <= Protobuf.MAX_DEPTH, "depth " + depth);
        assertEquals(DecodedNode.Type.BINARY, n.get("1").type());
    }

    @Test
    void oversizedLengthsDoNotAllocate() {
        // LEN field claiming 2^62 bytes, and a frame claiming 4 GiB.
        Protobuf.Parsed p = Protobuf.parse(pb().tag(1, 2).rawVarint(1L << 62).build());
        assertTrue(p.error.contains("exceeds remaining"), p.error);
        byte[] body = {0, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, 0x08, 0x01};
        DecodeResult r = assertDoesNotThrow(() -> grpc.decode(req("application/grpc", body).build()));
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("declares 4294967295 bytes")), r.warnings().toString());
    }

    // ------------------------------------------------------------ gRPC-Web

    @Test
    void grpcWebDataAndTrailerFrames() throws Exception {
        byte[] reply = pb().str(1, "Hello world").build();
        byte[] trailers = ascii("grpc-status:0\r\ngrpc-message:\r\nx-custom: yes\r\n");
        MessageContext m = resp("application/grpc-web+proto", "application/grpc-web+proto",
                concat(frame(0, reply), frame(0x80, trailers))).build();
        assertEquals(95, grpc.match(m).confidence());
        DecodeResult r = grpc.decode(m);
        assertEquals("gRPC-Web response ← helloworld.Greeter/SayHello: status 0 OK (1 message, 1 field)", r.summary());
        assertEquals("Hello world", r.root().get("message 1").get("1").value());
        assertEquals("yes", r.root().get("trailers").get("x-custom").value());
        assertEquals("OK", r.root().get("status").get("name").value());
        assertEquals("trailer frame", r.root().get("status").get("source").value());
    }

    @Test
    void grpcWebTrailerErrorIsPercentDecoded() throws Exception {
        byte[] trailers = ascii("grpc-status: 7\r\ngrpc-message: caf%C3%A9 access denied%2E\r\n");
        DecodeResult r = grpc.decode(resp("application/grpc-web", "application/grpc-web", frame(0x80, trailers)).build());
        assertEquals("gRPC-Web response: status 7 PERMISSION_DENIED — café access denied.", r.summary());
    }

    @Test
    void grpcWebTextBase64WithSeparatelyPaddedChunks() throws Exception {
        byte[] data = frame(0, pb().str(1, "Hi").varint(2, 3).build()); // 11 bytes → padded base64
        byte[] trailer = frame(0x80, ascii("grpc-status:0\r\n"));
        String body = Base64.getEncoder().encodeToString(data) + Base64.getEncoder().encodeToString(trailer);
        assertTrue(body.indexOf('=') < body.length() - 2, "fixture should have padding mid-stream");
        MessageContext m = resp("application/grpc-web-text", "application/grpc-web-text+proto", ascii(body)).build();
        assertEquals(95, grpc.match(m).confidence());
        DecodeResult r = grpc.decode(m);
        assertEquals("gRPC-Web-Text response ← helloworld.Greeter/SayHello: status 0 OK (1 message, 2 fields)", r.summary());
        assertEquals("Hi", r.root().get("message 1").get("1").value());
    }

    @Test
    void compressedFrames() throws Exception {
        byte[] payload = pb().str(1, "compressed hello").varint(2, 99).build();
        MessageContext gz = req("application/grpc-web+proto", frame(1, gzip(payload))).requestHeader("grpc-encoding", "gzip").build();
        DecodeResult r = grpc.decode(gz);
        assertEquals("compressed hello", r.root().get("message 1").get("1").value());
        assertTrue(r.root().get("message 1").value().contains("gzip →"), r.root().get("message 1").value());

        MessageContext df = req("application/grpc", frame(1, deflate(payload))).requestHeader("grpc-encoding", "deflate").build();
        assertEquals("99 (sint -50)", grpc.decode(df).root().get("message 1").get("2").value());

        MessageContext snappy = req("application/grpc", frame(1, new byte[]{1, 2, 3})).requestHeader("grpc-encoding", "snappy").build();
        DecodeResult s = grpc.decode(snappy);
        assertTrue(s.warnings().stream().anyMatch(w -> w.contains("unsupported message encoding 'snappy'")), s.warnings().toString());
    }

    // ------------------------------------------------------------ native gRPC

    @Test
    void nativeGrpcErrorStatusFromHeaders() throws Exception {
        MessageContext m = resp("application/grpc", "application/grpc", new byte[0])
                .responseHeader("grpc-status", "16").responseHeader("grpc-message", "token%20expired").build();
        DecodeResult r = grpc.decode(m);
        assertEquals("gRPC response: status 16 UNAUTHENTICATED — token expired", r.summary());
        assertEquals("16", r.root().get("status").get("code").value());
    }

    @Test
    void trailersOnlyResponseWithoutContentTypeMatches() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("POST").url(URL)
                .requestHeader("Content-Type", "application/grpc").statusCode(200)
                .responseHeader("grpc-status", "5").responseBody(new byte[0]).build();
        assertTrue(grpc.match(m).confidence() >= 85);
        assertEquals("gRPC response: status 5 NOT_FOUND", grpc.decode(m).summary());
    }

    @Test
    void statusDetailsBinIsDecoded() throws Exception {
        byte[] status = pb().varint(1, 3).str(2, "bad email").msg(3, pb().str(1, "type.googleapis.com/google.rpc.BadRequest")
                .bytes(2, pb().msg(1, pb().str(1, "email").str(2, "invalid")).build())).build();
        MessageContext m = resp("application/grpc", "application/grpc", new byte[0])
                .responseHeader("grpc-status", "3").responseHeader("grpc-status-details-bin",
                        Base64.getEncoder().withoutPadding().encodeToString(status)).build();
        DecodeResult r = grpc.decode(m);
        DecodedNode details = r.root().get("status").get("details");
        assertEquals("bad email", details.get("2").value());
        assertEquals("type.googleapis.com/google.rpc.BadRequest", details.get("3").get("1").value());
        assertEquals("email", details.get("3").get("2").get("1").get("1").value());
    }

    @Test
    void multipleStreamedMessages() throws Exception {
        byte[] body = concat(frame(0, pb().varint(1, 1).build()), frame(0, pb().varint(1, 2).build()), frame(0, new byte[0]));
        DecodeResult r = grpc.decode(resp("application/grpc", "application/grpc+proto", body).build());
        assertEquals("gRPC response ← helloworld.Greeter/SayHello (3 messages)", r.summary());
        assertNotNull(r.root().get("message 3"));
    }

    // ------------------------------------------------------------ Connect

    @Test
    void connectUnaryProto() throws Exception {
        MessageContext m = req("application/proto", helloRequest()).requestHeader("Connect-Protocol-Version", "1").build();
        assertEquals(90, grpc.match(m).confidence());
        DecodeResult r = grpc.decode(m);
        assertEquals("Connect → helloworld.Greeter/SayHello (1 message, 3 fields)", r.summary());
        assertEquals("world", r.root().get("message").get("1").value());
    }

    @Test
    void connectUnaryJsonError() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("POST").url(URL)
                .requestHeader("Content-Type", "application/proto").requestHeader("Connect-Protocol-Version", "1")
                .statusCode(401).responseHeader("Content-Type", "application/json")
                .responseBody("{\"code\":\"unauthenticated\",\"message\":\"token expired\"}").build();
        assertEquals(85, grpc.match(m).confidence());
        assertEquals("Connect response: status 16 UNAUTHENTICATED — token expired", grpc.decode(m).summary());
    }

    @Test
    void connectStreamingWithEndStream() throws Exception {
        byte[] end = ascii("{\"error\":{\"code\":\"resource_exhausted\",\"message\":\"slow down\"},\"metadata\":{\"x\":[\"1\"]}}");
        byte[] body = concat(frame(0, pb().str(1, "chunk").build()), frame(2, end));
        MessageContext m = resp("application/connect+proto", "application/connect+proto", body).build();
        assertEquals(90, grpc.match(m).confidence());
        DecodeResult r = grpc.decode(m);
        assertEquals("Connect stream response: status 8 RESOURCE_EXHAUSTED — slow down", r.summary());
        assertEquals("chunk", r.root().get("message 1").get("1").value());
        assertNotNull(r.root().get("end of stream").get("metadata"));
    }

    @Test
    void connectJsonOnlyWithHeaderAndLowConfidence() throws Exception {
        byte[] json = ascii("{\"name\":\"world\"}");
        assertFalse(grpc.match(req("application/json", json).build()).matched());
        MessageContext m = req("application/json", json).requestHeader("Connect-Protocol-Version", "1").build();
        assertEquals(50, grpc.match(m).confidence());
        DecodeResult r = grpc.decode(m);
        assertEquals("world", r.root().get("message").get("name").value());
    }

    @Test
    void connectGetRequest() throws Exception {
        String msg = Base64.getUrlEncoder().withoutPadding().encodeToString(pb().str(1, "q").build());
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("GET")
                .url(URL + "?connect=v1&encoding=proto&base64=1&message=" + msg).build();
        assertEquals(85, grpc.match(m).confidence());
        DecodeResult r = grpc.decode(m);
        assertEquals("q", r.root().get("message").get("1").value());
        assertEquals("Connect GET → helloworld.Greeter/SayHello (1 message, 1 field)", r.summary());
    }

    @Test
    void plainProtobufContentTypes() throws Exception {
        for (String ct : new String[]{"application/x-protobuf", "application/protobuf", "application/vnd.google.protobuf; proto=foo.Bar"}) {
            MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://x.test/api/v1/items")
                    .requestHeader("Content-Type", ct).requestBody(helloRequest()).build();
            assertEquals(80, grpc.match(m).confidence(), ct);
            DecodeResult r = grpc.decode(m);
            assertEquals("Protobuf → /api/v1/items (1 message, 3 fields)", r.summary());
        }
    }

    // ------------------------------------------------------------ negative / forced

    @Test
    void doesNotMatchUnrelatedTraffic() {
        assertFalse(grpc.match(req("text/html", ascii("<html>")).build()).matched());
        assertFalse(grpc.match(req(null, helloRequest()).build()).matched());
        assertFalse(grpc.match(req("application/octet-stream", helloRequest()).build()).matched());
        assertFalse(grpc.match(MessageContext.builder(MessageKind.WEBSOCKET).url("wss://x/").webSocket("CLIENT_TO_SERVER", helloRequest()).build()).matched());
        // gRPC request, HTML error page from a proxy: response has its own content type → not ours.
        assertFalse(grpc.match(resp("application/grpc", "text/html", ascii("<h1>502</h1>")).build()).matched());
    }

    @Test
    void forcedDecodeOnUnknownBinaryBody() throws Exception {
        DecodeResult r = grpc.decode(req("application/octet-stream", helloRequest()).build());
        assertEquals("world", r.root().get("message").get("1").value());
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());

        DecodeResult framed = grpc.decode(req(null, frame(0, helloRequest())).build());
        assertEquals("world", framed.root().get("message 1").get("1").value());
        assertTrue(framed.warnings().get(0).contains("length-prefixed framing"));
    }

    @Test
    void forcedDecodeOnGarbage() {
        byte[] garbage = new byte[64];
        new Random(42).nextBytes(garbage);
        garbage[0] = (byte) 0xff; // tag varint with continuation bits ...
        garbage[1] = (byte) 0xff;
        garbage[2] = (byte) 0x07; // ... giving wire type 7 → invalid at offset 0
        DecodeException e = assertThrows(DecodeException.class, () -> grpc.decode(req("application/octet-stream", garbage).build()));
        assertTrue(e.getMessage().startsWith("Not a protobuf message"), e.getMessage());

        assertThrows(DecodeException.class, () -> grpc.decode(req("application/octet-stream", new byte[0]).build()));
    }

    @Test
    void forcedDecodeOnPartlyValidDataIsPartial() throws Exception {
        byte[] body = concat(pb().varint(1, 7).str(2, "ok").build(), new byte[]{(byte) 0x1f, 0x01, 0x02});
        DecodeResult r = grpc.decode(req("application/octet-stream", body).build());
        DecodedNode msg = r.root().get("message");
        assertEquals("7 (sint -4)", msg.get("1").value());
        assertEquals("1f 01 02", msg.get("unparsed").value());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("decoding stopped after 2 field(s)")), r.warnings().toString());
    }

    @Test
    void randomInputNeverThrowsUnchecked() {
        Random rnd = new Random(7);
        String[] types = {"application/grpc", "application/grpc-web", "application/grpc-web-text", "application/connect+proto",
                "application/proto", "application/x-protobuf", "application/octet-stream"};
        for (int i = 0; i < 2000; i++) {
            byte[] b = new byte[rnd.nextInt(80)];
            rnd.nextBytes(b);
            if (i % 3 == 0 && b.length > 5) { b[0] = (byte) (rnd.nextBoolean() ? 0 : 0x80); b[1] = b[2] = 0; }
            MessageContext m = req(types[i % types.length], b).requestHeader("grpc-encoding", "gzip").build();
            assertDoesNotThrow(() -> grpc.match(m));
            try {
                DecodeResult r = grpc.decode(m);
                assertNotNull(TreeText.render(r.root()));
            } catch (DecodeException expected) {
                // fine
            }
        }
    }

    @Test
    void callPathParsing() {
        assertEquals("helloworld.Greeter", GrpcDecoder.call("/helloworld.Greeter/SayHello").service());
        assertEquals("pkg.v1.Svc", GrpcDecoder.call("/api/grpc/pkg.v1.Svc/Get").service());
        assertNull(GrpcDecoder.call("/"));
        assertNull(GrpcDecoder.call("/onlyone"));
    }
}
