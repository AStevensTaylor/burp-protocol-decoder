package protocoldecoder.builtin.grpc;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.edit.EditEngine;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.edit.MessagePatch;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static protocoldecoder.builtin.grpc.GrpcDecoderTest.*;

class GrpcCodecTest {

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });
    final GrpcDecoder grpc = new GrpcDecoder();

    @AfterEach
    void close() {
        app.close();
    }

    List<EditEngine.Document> docs(MessageContext m) {
        return app.editEngine().documents(m).stream().filter(d -> d.decoderId().equals(GrpcDecoder.ID)).toList();
    }

    EditEngine.Document doc(MessageContext m, String title) {
        return docs(m).stream().filter(d -> d.document().title().equals(title)).findFirst()
                .orElseThrow(() -> new AssertionError(title + " not in " + docs(m).stream().map(d -> d.document().title()).toList()));
    }

    static byte[] packed(long... values) {
        Pb p = pb();
        for (long v : values) p.rawVarint(v);
        return p.build();
    }

    /** Every wire type: string, negative int64, nested message with a double, bytes, fixed32, packed, zero, fixed64 negative. */
    static byte[] everything() {
        return pb().str(1, "alice")
                .varint(2, -5)
                .msg(3, pb().fixed64(1, Double.doubleToLongBits(1.0)).str(2, "inner"))
                .bytes(4, new byte[]{0, 1, (byte) 0xff})
                .fixed32(5, 7)
                .bytes(6, packed(1, 2, 300))
                .varint(7, 0)
                .fixed64(8, -2)
                .str(9, "hi") // printable text that is also a valid message (field 13 varint): shown as a string
                .bytes(10, new byte[0])
                .build();
    }

    static MessageContext grpcWebRequest(byte[] body) {
        return req("application/grpc-web+proto", body).build();
    }

    DecodedNode firstMessage(MessageContext m) throws Exception {
        DecodeResult r = grpc.decode(m);
        DecodedNode msg = r.root().get("message 1");
        assertNotNull(msg, r.root().toString());
        return msg;
    }

    // ------------------------------------------------------------------ text format

    @Test
    void textShowsEveryWireTypeAndRoundTripsExactly() throws Exception {
        byte[] body = frame(0, everything());
        MessageContext m = grpcWebRequest(body);
        EditEngine.Document d = doc(m, "Protobuf message");
        assertEquals("protobuf-text", d.document().syntax());
        String t = d.document().text();
        assertTrue(t.startsWith("# Protobuf"), t);
        assertTrue(t.contains("\n1: \"alice\"\n"), t);
        assertTrue(t.contains("\n2: -5  # uint64 18446744073709551611\n"), t);
        assertTrue(t.contains("\n3 {\n  1: 0x3ff0000000000000  # fixed64 4607182418800017408, double 1.0\n  2: \"inner\"\n}\n"), t);
        assertTrue(t.contains("\n4: b\"\\x00\\x01\\xff\"\n"), t);
        assertTrue(t.contains("\n5: 0x00000007  # fixed32 7"), t);
        assertTrue(t.contains("\n6: b\"\\x01\\x02\\xac\\x02\"  # as packed varints: [1, 2, 300]\n"), t);
        assertTrue(t.contains("\n7: 0\n"), t);
        assertTrue(t.contains("\n8: 0xfffffffffffffffe  # fixed64 18446744073709551614, int64 -2"), t);
        assertTrue(t.contains("\n9: \"hi\"\n"), t);
        assertTrue(t.contains("\n10: \"\"\n"), t);

        MessagePatch p = EditEngine.encode(d, t);
        assertArrayEquals(body, p.body());
    }

    @Test
    void editChangesValuesAndAddsFieldsWithLengthsRecomputed() throws Exception {
        MessageContext m = grpcWebRequest(frame(0, everything()));
        EditEngine.Document d = doc(m, "Protobuf message");
        String edited = d.document().text()
                .replace("1: \"alice\"", "1: \"bob \\\"the\\\" \\u00e9😀\\n\"")
                .replace("2: -5", "2: -6")
                .replace("  2: \"inner\"", "  2: \"a much longer inner string than before\"\n  3: 1.5d\n  4: -1i32")
                .replace("6: b\"\\x01\\x02\\xac\\x02\"", "6: [7, 8, 9]")
                + "11: 2.5f\n12 {\n}\n13: 123i64 # trailing comment\n";
        MessageContext out = EditEngine.encode(d, edited).applyTo(m);
        DecodedNode msg = firstMessage(out);
        assertEquals("bob \"the\" é😀\n", msg.get("1").value());
        assertTrue(msg.get("2").value().contains("int64 -6"), msg.get("2").value());
        DecodedNode nested = msg.get("3");
        assertEquals("a much longer inner string than before", nested.get("2").value());
        assertTrue(nested.get("3").value().contains("double 1.5"), nested.get("3").value());
        assertTrue(nested.get("4").value().contains("int32 -1"), nested.get("4").value());
        assertTrue(msg.get("6").value().contains("packed varints: [7, 8, 9]"), msg.get("6").value());
        assertTrue(msg.get("11").value().contains("float 2.5"), msg.get("11").value());
        assertTrue(msg.get("13").value().startsWith("123"), msg.get("13").value());
        // the edited document re-opens and round-trips
        EditEngine.Document again = doc(out, "Protobuf message");
        assertArrayEquals(out.requestBody(), EditEngine.encode(again, again.document().text()).body());
    }

    @Test
    void stringThatLooksLikeAMessageStaysAString() throws Exception {
        // "hi" parses as field 13 varint 105, but is shown (and must be re-encoded) as a string
        MessageContext m = req("application/x-protobuf", pb().str(1, "hi").build()).build();
        EditEngine.Document d = doc(m, "Protobuf message");
        assertTrue(d.document().text().contains("1: \"hi\""));
        assertArrayEquals(m.requestBody(), EditEngine.encode(d, d.document().text()).body());
        // a nested message whose first byte is a tag stays a message
        byte[] nested = pb().msg(1, pb().str(1, "x")).build();
        MessageContext m2 = req("application/x-protobuf", nested).build();
        EditEngine.Document d2 = doc(m2, "Protobuf message");
        assertTrue(d2.document().text().contains("1 {\n  1: \"x\"\n}"), d2.document().text());
        assertArrayEquals(nested, EditEngine.encode(d2, d2.document().text()).body());
    }

    @Test
    void nonCanonicalVarintsStillRoundTripExactly() throws Exception {
        byte[] overlong = {0x08, (byte) 0x80, 0x00, 0x12, 0x01, 'a'}; // field 1 = 0 encoded in two bytes
        MessageContext m = req("application/x-protobuf", overlong).build();
        EditEngine.Document d = doc(m, "Protobuf message");
        assertTrue(d.document().text().startsWith("# note: the original uses non-canonical"), d.document().text());
        assertArrayEquals(overlong, EditEngine.encode(d, d.document().text()).body());
        byte[] edited = EditEngine.encode(d, d.document().text().replace("2: \"a\"", "2: \"b\"")).body();
        assertArrayEquals(new byte[]{0x08, 0x00, 0x12, 0x01, 'b'}, edited);
    }

    @Test
    void invalidTextGivesPreciseErrors() {
        MessageContext m = grpcWebRequest(frame(0, pb().str(1, "x").build()));
        EditEngine.Document d = doc(m, "Protobuf message");
        EncodeException e = assertThrows(EncodeException.class, () -> EditEngine.encode(d, "1: \"x\"\n2: \"unterminated\n"));
        assertEquals("Protobuf text error at line 2, column 4: unterminated string", e.getMessage());
        e = assertThrows(EncodeException.class, () -> EditEngine.encode(d, "1: 12abc"));
        assertTrue(e.getMessage().startsWith("Protobuf text error at line 1, column 4: '12abc' is not a number"), e.getMessage());
        e = assertThrows(EncodeException.class, () -> EditEngine.encode(d, "1 {\n  2: 3\n"));
        assertTrue(e.getMessage().contains("line 3") && e.getMessage().contains("missing '}'"), e.getMessage());
        e = assertThrows(EncodeException.class, () -> EditEngine.encode(d, "name: 1"));
        assertTrue(e.getMessage().contains("line 1, column 1: expected a field number"), e.getMessage());
        e = assertThrows(EncodeException.class, () -> EditEngine.encode(d, "0: 1"));
        assertTrue(e.getMessage().contains("out of range"), e.getMessage());
        e = assertThrows(EncodeException.class, () -> EditEngine.encode(d, "1: 5000000000i32"));
        assertTrue(e.getMessage().contains("does not fit in 32 bits"), e.getMessage());
        e = assertThrows(EncodeException.class, () -> EditEngine.encode(d, "1: [1, 2i32]"));
        assertTrue(e.getMessage().contains("mixes"), e.getMessage());
        e = assertThrows(EncodeException.class, () -> EditEngine.encode(d, "1: \"\\q\""));
        assertTrue(e.getMessage().contains("unknown escape"), e.getMessage());
    }

    // ------------------------------------------------------------------ framing

    @Test
    void compressedFramesKeepTheirBytesAndRecompressOnEdit() throws Exception {
        byte[] msg1 = pb().str(1, "first").build();
        byte[] msg2 = pb().str(1, "second").varint(2, 9).build();
        byte[] body = concat(frame(1, gzip(msg1)), frame(0, msg2));
        MessageContext m = req("application/grpc", body).requestHeader("grpc-encoding", "gzip").build();
        List<EditEngine.Document> ds = docs(m);
        assertEquals(List.of("Protobuf message 1 (gzip)", "Protobuf message 2"), ds.stream().map(x -> x.document().title()).toList());
        for (EditEngine.Document d : ds) assertArrayEquals(body, EditEngine.encode(d, d.document().text()).body());

        MessageContext out = EditEngine.encode(ds.get(0), ds.get(0).document().text().replace("first", "edited first")).applyTo(m);
        assertEquals(1, out.requestBody()[0], "still flagged compressed");
        assertTrue(Codecs.isGzip(java.util.Arrays.copyOfRange(out.requestBody(), 5, out.requestBody().length)));
        DecodeResult r = grpc.decode(out);
        assertEquals("edited first", r.root().get("message 1").get("1").value());
        assertEquals("second", r.root().get("message 2").get("1").value());
    }

    @Test
    void deflateAndContentEncodingAreReapplied() throws Exception {
        byte[] msg = pb().str(1, "deflated").build();
        MessageContext m = req("application/grpc", frame(1, deflate(msg))).requestHeader("grpc-encoding", "deflate").build();
        EditEngine.Document d = doc(m, "Protobuf message (deflate)");
        MessageContext out = EditEngine.encode(d, d.document().text().replace("deflated", "inflated?")).applyTo(m);
        assertEquals("inflated?", firstMessage(out).get("1").value());

        byte[] raw = gzip(pb().str(1, "http gzip").build());
        MessageContext ce = req("application/x-protobuf", raw).requestHeader("Content-Encoding", "gzip").build();
        EditEngine.Document d2 = doc(ce, "Protobuf message");
        assertArrayEquals(raw, EditEngine.encode(d2, d2.document().text()).body());
        MessageContext out2 = EditEngine.encode(d2, d2.document().text().replace("http gzip", "regzipped")).applyTo(ce);
        assertTrue(Codecs.isGzip(out2.requestBody()));
        assertEquals("regzipped", grpc.decode(out2).root().get("message").get("1").value());
    }

    @Test
    void grpcWebTextResponseWithTrailers() throws Exception {
        byte[] msg = pb().str(1, "reply").varint(2, 1).build();
        byte[] trailers = "grpc-status: 0\r\ngrpc-message: fine\r\n".getBytes(StandardCharsets.US_ASCII);
        // two base64 chunks, each padded, as servers flush them
        String body = Base64.getEncoder().encodeToString(frame(0, msg)) + Base64.getEncoder().encodeToString(frame(0x80, trailers));
        MessageContext m = resp("application/grpc-web-text", "application/grpc-web-text+proto", body.getBytes(StandardCharsets.US_ASCII)).build();
        List<EditEngine.Document> ds = docs(m);
        assertEquals(List.of("Protobuf message", "gRPC-Web trailers"), ds.stream().map(x -> x.document().title()).toList());
        for (EditEngine.Document d : ds) assertEquals(body, new String(EditEngine.encode(d, d.document().text()).body(), StandardCharsets.US_ASCII));
        assertEquals("grpc-status: 0\ngrpc-message: fine\n", ds.get(1).document().text());

        MessageContext out = EditEngine.encode(ds.get(0), ds.get(0).document().text().replace("\"reply\"", "\"changed reply\"")).applyTo(m);
        DecodeResult r = grpc.decode(out);
        assertEquals("changed reply", r.root().get("message 1").get("1").value());
        assertEquals("fine", r.root().get("trailers").get("grpc-message").value());

        MessageContext out2 = EditEngine.encode(ds.get(1), "grpc-status: 7\ngrpc-message: denied\n").applyTo(m);
        DecodeResult r2 = grpc.decode(out2);
        assertTrue(r2.summary().contains("status 7 PERMISSION_DENIED — denied"), r2.summary());
        byte[] bin = Base64.getDecoder().decode(out2.responseBody());
        assertTrue(new String(bin, StandardCharsets.US_ASCII).endsWith("grpc-status: 7\r\ngrpc-message: denied\r\n"), "CRLF kept");
        assertThrows(EncodeException.class, () -> EditEngine.encode(ds.get(1), "no colon here"));
    }

    @Test
    void connectGetMessageParameter() throws Exception {
        byte[] msg = pb().str(1, "query?&=").varint(2, 3).build();
        String b64 = Base64.getUrlEncoder().withoutPadding().encodeToString(msg);
        String url = "https://api.example.com/acme.v1.Svc/Get?connect=v1&encoding=proto&base64=1&message=" + b64 + "&x=1";
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("GET").url(url).build();
        EditEngine.Document d = doc(m, "Protobuf message (Connect GET)");
        assertEquals(m.query(), EditEngine.encode(d, d.document().text()).query());
        MessageContext out = EditEngine.encode(d, d.document().text().replace("2: 3", "2: 4\n3: \"" + "x".repeat(40) + "\"")).applyTo(m);
        assertTrue(out.query().endsWith("&x=1"), out.query());
        DecodedNode n = grpc.decode(out).root().get("message");
        assertEquals("query?&=", n.get("1").value());
        assertEquals("4", n.get("2").value());
        assertEquals("x".repeat(40), n.get("3").value());

        // percent-encoded (no base64) variant
        String url2 = "https://api.example.com/acme.v1.Svc/Get?connect=v1&encoding=proto&message=" + GrpcScanner.percentEncode(msg);
        MessageContext m2 = MessageContext.builder(MessageKind.REQUEST).method("GET").url(url2).build();
        EditEngine.Document d2 = doc(m2, "Protobuf message (Connect GET)");
        assertEquals(m2.query(), EditEngine.encode(d2, d2.document().text()).query());
        MessageContext out2 = EditEngine.encode(d2, d2.document().text().replace("2: 3", "2: 300")).applyTo(m2);
        assertEquals("300", grpc.decode(out2).root().get("message").get("2").value());
    }

    @Test
    void connectUnaryAndResponsesAndJsonSkipped() throws Exception {
        byte[] msg = pb().str(1, "unary").build();
        MessageContext r = resp("application/proto", "application/proto", msg).build();
        EditEngine.Document d = doc(r, "Protobuf message");
        MessageContext out = EditEngine.encode(d, "1: \"from response\"").applyTo(r);
        assertEquals("from response", grpc.decode(out).root().get("message").get("1").value());

        MessageContext json = req("application/connect+json", frame(0, "{\"a\":1}".getBytes(StandardCharsets.UTF_8))).build();
        assertTrue(docs(json).isEmpty());
        MessageContext notProto = req("application/x-protobuf", new byte[]{(byte) 0xff, (byte) 0xff}).build();
        assertTrue(docs(notProto).isEmpty());
    }

    @Test
    void emptyMessageAndManyFramesAreBounded() throws Exception {
        MessageContext empty = req("application/grpc", frame(0, new byte[0])).build();
        EditEngine.Document d = doc(empty, "Protobuf message");
        assertArrayEquals(empty.requestBody(), EditEngine.encode(d, d.document().text()).body());
        MessageContext out = EditEngine.encode(d, "1: 4").applyTo(empty);
        assertEquals("4", firstMessage(out).get("1").value());

        byte[][] frames = new byte[15][];
        for (int i = 0; i < frames.length; i++) frames[i] = frame(0, pb().varint(1, i).build());
        assertEquals(10, docs(req("application/grpc", concat(frames)).build()).size());
    }
}
