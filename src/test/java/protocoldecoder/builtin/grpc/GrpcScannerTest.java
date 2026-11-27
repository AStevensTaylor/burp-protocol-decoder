package protocoldecoder.builtin.grpc;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.scan.ActiveCheck;
import protocoldecoder.scan.Exchange;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.HttpSender;
import protocoldecoder.scan.InsertionPoint;
import protocoldecoder.scan.Severity;
import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;
import static protocoldecoder.builtin.grpc.GrpcDecoderTest.*;

class GrpcScannerTest {

    final GrpcDecoder grpc = new GrpcDecoder();
    final GrpcScanner scanner = new GrpcScanner();
    final App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });

    static final String PAYLOAD = "x'\"<a>;|&%\\ é✓ 𝄞\n]]>";

    @AfterEach
    void close() {
        app.close();
    }

    /** 1 "world", 2 {1 42, 2 "nested text", 3 {1 "deep", 2 fixed32 7}}, 3 bytes, 4 fixed64 9, 5 "tail" */
    static byte[] nested() {
        return pb().str(1, "world")
                .msg(2, pb().varint(1, 42).str(2, "nested text").msg(3, pb().str(1, "deep").fixed32(2, 7)))
                .bytes(3, new byte[]{(byte) 0xff, 0x00, (byte) 0xfe})
                .fixed64(4, 9)
                .str(5, "tail").build();
    }

    static InsertionPoint ip(List<InsertionPoint> ips, String name) {
        return ips.stream().filter(i -> i.name().equals(name)).findFirst()
                .orElseThrow(() -> new AssertionError(name + " not in " + ips.stream().map(InsertionPoint::name).toList()));
    }

    DecodeResult decodeBody(MessageContext original, byte[] newBody) throws Exception {
        MessageContext.Builder b = MessageContext.builder(MessageKind.REQUEST).method(original.method()).url(original.url()).requestBody(newBody);
        for (Header h : original.requestHeaders()) b.requestHeader(h.name(), h.value());
        return grpc.decode(b.build());
    }

    static DecodedNode at(DecodedNode n, String... path) {
        DecodedNode cur = n;
        for (String p : path) {
            cur = cur.get(p);
            assertNotNull(cur, "missing " + p);
        }
        return cur;
    }

    // ------------------------------------------------------------ insertion points

    @Test
    void nestedFieldsRoundTripWithLengthsRecomputed() throws Exception {
        MessageContext m = req("application/grpc-web+proto", frame(0, nested())).build();
        List<InsertionPoint> ips = scanner.insertionPoints(m, null);
        List<String> names = ips.stream().map(InsertionPoint::name).toList();
        assertTrue(names.containsAll(List.of(
                "gRPC: /helloworld.Greeter/SayHello 1 (string)",
                "gRPC: /helloworld.Greeter/SayHello 2.1 (varint)",
                "gRPC: /helloworld.Greeter/SayHello 2.2 (string)",
                "gRPC: /helloworld.Greeter/SayHello 2.3.1 (string)",
                "gRPC: /helloworld.Greeter/SayHello 2.3.2 (fixed32)",
                "gRPC: /helloworld.Greeter/SayHello 4 (fixed64)",
                "gRPC: /helloworld.Greeter/SayHello 5 (string)")), names.toString());
        assertFalse(names.stream().anyMatch(n -> n.contains(" 3 ")), "opaque bytes field not offered: " + names);
        assertEquals("deep", ip(ips, "gRPC: /helloworld.Greeter/SayHello 2.3.1 (string)").baseValue());
        assertEquals("42", ip(ips, "gRPC: /helloworld.Greeter/SayHello 2.1 (varint)").baseValue());

        // Deepest string: every enclosing length (2, 2.3) and the frame length must be recomputed.
        String big = PAYLOAD.repeat(20); // > 127 bytes: length varints grow to 2 bytes
        byte[] body = ip(ips, "gRPC: /helloworld.Greeter/SayHello 2.3.1 (string)").render().apply(big);
        DecodeResult r = decodeBody(m, body);
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
        DecodedNode msg = r.root().get("message 1");
        assertEquals(big, at(msg, "2", "3", "1").value());
        assertEquals("world", at(msg, "1").value());
        assertEquals("nested text", at(msg, "2", "2").value());
        assertTrue(at(msg, "2", "3", "2").value().startsWith("7"));
        assertTrue(at(msg, "3").value().startsWith("ff 00 fe"));
        assertTrue(at(msg, "4").value().startsWith("9"));
        assertEquals("tail", at(msg, "5").value());

        // Unchanged payload reproduces the original bytes exactly (only the edited path is rewritten).
        assertArrayEquals(frame(0, nested()), ip(ips, "gRPC: /helloworld.Greeter/SayHello 5 (string)").render().apply("tail"));
    }

    @Test
    void numericFieldsTakeNumbersOrFallBackToStrings() throws Exception {
        MessageContext m = req("application/grpc-web+proto", frame(0, nested())).build();
        List<InsertionPoint> ips = scanner.insertionPoints(m, null);
        InsertionPoint v = ip(ips, "gRPC: /helloworld.Greeter/SayHello 2.1 (varint)");

        DecodedNode msg = decodeBody(m, v.render().apply("1337")).root().get("message 1");
        assertTrue(at(msg, "2", "1").value().startsWith("1337 "), at(msg, "2", "1").value());
        msg = decodeBody(m, v.render().apply("-1")).root().get("message 1");
        assertTrue(at(msg, "2", "1").value().contains("int64 -1"), at(msg, "2", "1").value());
        // Type confusion: a non-numeric payload goes in as a length-delimited string with the same field number.
        msg = decodeBody(m, v.render().apply("1' OR '1'='1")).root().get("message 1");
        assertEquals("1' OR '1'='1", at(msg, "2", "1").value());
        assertEquals(DecodedNode.Type.STRING, at(msg, "2", "1").type());
        assertEquals("nested text", at(msg, "2", "2").value());

        InsertionPoint f64 = ip(ips, "gRPC: /helloworld.Greeter/SayHello 4 (fixed64)");
        msg = decodeBody(m, f64.render().apply("1.5")).root().get("message 1");
        assertTrue(at(msg, "4").value().contains("double 1.5"), at(msg, "4").value());
        msg = decodeBody(m, f64.render().apply("123")).root().get("message 1");
        assertTrue(at(msg, "4").value().startsWith("123 "), at(msg, "4").value());
    }

    @Test
    void compressedFrameIsRecompressed() throws Exception {
        byte[] body = frame(1, gzip(nested()));
        MessageContext m = req("application/grpc", body).requestHeader("grpc-encoding", "gzip").build();
        List<InsertionPoint> ips = scanner.insertionPoints(m, null);
        byte[] out = ip(ips, "gRPC: /helloworld.Greeter/SayHello 2.2 (string)").render().apply(PAYLOAD);
        assertEquals(1, out[0], "compressed flag kept");
        byte[] payload = java.util.Arrays.copyOfRange(out, 5, out.length);
        assertTrue(Codecs.isGzip(payload));
        DecodeResult r = decodeBody(m, out);
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
        assertEquals(PAYLOAD, at(r.root().get("message 1"), "2", "2").value());
        assertEquals("world", at(r.root().get("message 1"), "1").value());

        // deflate (zlib) with Connect streaming
        MessageContext c = req("application/connect+proto", frame(1, deflate(nested()))).requestHeader("Connect-Content-Encoding", "deflate").build();
        byte[] cout = ip(scanner.insertionPoints(c, null), "gRPC: /helloworld.Greeter/SayHello 1 (string)").render().apply(PAYLOAD);
        assertEquals(PAYLOAD, at(decodeBody(c, cout).root().get("message 1"), "1").value());
    }

    @Test
    void grpcWebTextIsReEncodedAsBase64() throws Exception {
        String text = Base64.getEncoder().encodeToString(frame(0, nested()));
        MessageContext m = req("application/grpc-web-text", ascii(text)).build();
        List<InsertionPoint> ips = scanner.insertionPoints(m, null);
        byte[] out = ip(ips, "gRPC: /helloworld.Greeter/SayHello 2.3.1 (string)").render().apply(PAYLOAD);
        assertTrue(new String(out, StandardCharsets.ISO_8859_1).matches("[A-Za-z0-9+/=]+"));
        DecodeResult r = decodeBody(m, out);
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
        assertEquals(PAYLOAD, at(r.root().get("message 1"), "2", "3", "1").value());
    }

    @Test
    void multipleFramesAreLabelledAndOthersKeptByteForByte() throws Exception {
        byte[] f1 = frame(0, pb().str(1, "first").build());
        byte[] f2 = frame(0, pb().str(1, "second").build());
        MessageContext m = req("application/grpc-web+proto", concat(f1, f2)).build();
        List<InsertionPoint> ips = scanner.insertionPoints(m, null);
        byte[] out = ip(ips, "gRPC: /helloworld.Greeter/SayHello msg2 1 (string)").render().apply(PAYLOAD);
        assertArrayEquals(f1, java.util.Arrays.copyOf(out, f1.length));
        DecodeResult r = decodeBody(m, out);
        assertEquals("first", r.root().get("message 1").get("1").value());
        assertEquals(PAYLOAD, r.root().get("message 2").get("1").value());
    }

    @Test
    void rawProtobufAndContentEncodedConnectUnary() throws Exception {
        MessageContext raw = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://api.example.com/v1/track")
                .requestHeader("Content-Type", "application/x-protobuf").requestBody(nested()).build();
        List<InsertionPoint> ips = scanner.insertionPoints(raw, null);
        byte[] out = ip(ips, "Protobuf: /v1/track 2.2 (string)").render().apply(PAYLOAD);
        assertEquals(PAYLOAD, at(decodeBody(raw, out).root().get("message"), "2", "2").value());

        MessageContext unary = req("application/proto", gzip(nested())).requestHeader("Content-Encoding", "gzip")
                .requestHeader("Connect-Protocol-Version", "1").build();
        byte[] uout = ip(scanner.insertionPoints(unary, null), "gRPC: /helloworld.Greeter/SayHello 1 (string)").render().apply(PAYLOAD);
        assertTrue(Codecs.isGzip(uout));
        assertEquals(PAYLOAD, at(decodeBody(unary, uout).root().get("message"), "1").value());
    }

    @Test
    void connectGetQueryMessage() throws Exception {
        String msg = Base64.getUrlEncoder().withoutPadding().encodeToString(nested());
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("GET")
                .url(URL + "?connect=v1&encoding=proto&base64=1&message=" + msg + "&x=keep%20me").build();
        List<InsertionPoint> ips = scanner.insertionPoints(m, null);
        InsertionPoint p = ip(ips, "gRPC: /helloworld.Greeter/SayHello (Connect GET) 2.3.1 (string)");
        assertEquals(InsertionPoint.Part.QUERY, p.part());
        String q = new String(p.render().apply(PAYLOAD), StandardCharsets.ISO_8859_1);
        assertTrue(q.startsWith("connect=v1&encoding=proto&base64=1&message=") && q.endsWith("&x=keep%20me"), q);
        DecodeResult r = grpc.decode(MessageContext.builder(MessageKind.REQUEST).method("GET").url(URL + "?" + q).build());
        assertEquals(PAYLOAD, at(r.root().get("message"), "2", "3", "1").value());

        // percent-encoded binary (no base64) with compression
        MessageContext m2 = MessageContext.builder(MessageKind.REQUEST).method("GET")
                .url(URL + "?connect=v1&encoding=proto&compression=gzip&message=" + GrpcScanner.percentEncode(gzip(nested()))).build();
        String q2 = new String(ip(scanner.insertionPoints(m2, null), "gRPC: /helloworld.Greeter/SayHello (Connect GET) 1 (string)")
                .render().apply(PAYLOAD), StandardCharsets.ISO_8859_1);
        DecodeResult r2 = grpc.decode(MessageContext.builder(MessageKind.REQUEST).method("GET").url(URL + "?" + q2).build());
        assertEquals(PAYLOAD, at(r2.root().get("message"), "1").value());
    }

    @Test
    void jsonFramesUseJsonLeaves() throws Exception {
        MessageContext m = req("application/grpc-web+json", frame(0, ascii("{\"name\":\"bob\",\"n\":1}"))).build();
        List<InsertionPoint> ips = scanner.insertionPoints(m, null);
        byte[] out = ip(ips, "gRPC: /helloworld.Greeter/SayHello $.name (json)").render().apply(PAYLOAD);
        assertEquals(PAYLOAD, decodeBody(m, out).root().get("message 1").get("name").value());
    }

    @Test
    void engineRegistersInsertionPointsAndTheyCanBeDisabled() {
        MessageContext m = req("application/grpc-web+proto", frame(0, nested())).build();
        assertTrue(app.scanEngine().insertionPoints(m).stream().anyMatch(i -> i.name().startsWith("gRPC: ")));
        app.scanEngine().setEnabled("grpc.insertion-points", false);
        assertTrue(app.scanEngine().insertionPoints(m).isEmpty());
        // Non-gRPC traffic gets nothing
        MessageContext form = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://x.example.com/a")
                .requestHeader("Content-Type", "application/x-www-form-urlencoded").requestBody("a=1").build();
        assertTrue(scanner.insertionPoints(form, null).isEmpty());
    }

    // ------------------------------------------------------------ passive

    List<Finding> passive(MessageContext m, String id) {
        return app.scanEngine().passive(m, false).stream().filter(f -> f.checkId().equals(id)).toList();
    }

    @Test
    void errorDetailsInGrpcMessage() {
        MessageContext bad = resp("application/grpc-web+proto", "application/grpc-web+proto", new byte[0])
                .responseHeader("grpc-status", "2")
                .responseHeader("grpc-message", "java.lang.NullPointerException: null%0A%09at com.acme.orders.OrderService.get(OrderService.java:42)")
                .build();
        List<Finding> f = passive(bad, "grpc.error-details");
        assertEquals(1, f.size());
        assertEquals(Severity.LOW, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("OrderService"), f.get(0).detail());

        MessageContext benign = resp("application/grpc-web+proto", "application/grpc-web+proto", new byte[0])
                .responseHeader("grpc-status", "5").responseHeader("grpc-message", "order not found").build();
        assertTrue(passive(benign, "grpc.error-details").isEmpty());
    }

    @Test
    void debugInfoInStatusDetails() {
        byte[] debugInfo = pb().str(1, "goroutine 1 [running]:").str(1, "main.(*server).Get(0xc000)\n\t/src/server.go:88").str(2, "db timeout").build();
        byte[] any = pb().str(1, "type.googleapis.com/google.rpc.DebugInfo").bytes(2, debugInfo).build();
        byte[] status = pb().varint(1, 13).str(2, "internal").bytes(3, any).build();
        byte[] trailer = frame(0x80, ascii("grpc-status: 13\r\ngrpc-message: internal\r\ngrpc-status-details-bin: "
                + Base64.getEncoder().withoutPadding().encodeToString(status) + "\r\n"));
        MessageContext m = resp("application/grpc-web+proto", "application/grpc-web+proto", trailer).build();
        List<Finding> f = passive(m, "grpc.debug-info");
        assertEquals(1, f.size(), app.scanEngine().passive(m, false).toString());
        assertTrue(f.get(0).detail().contains("server.go:88"), f.get(0).detail());
        assertTrue(f.get(0).detail().contains("db timeout"));

        // Status details without DebugInfo (e.g. BadRequest) are not reported
        byte[] other = pb().varint(1, 3).bytes(3, pb().str(1, "type.googleapis.com/google.rpc.BadRequest").bytes(2, pb().str(1, "x").build()).build()).build();
        MessageContext m2 = resp("application/grpc-web+proto", "application/grpc-web+proto", new byte[0])
                .responseHeader("grpc-status", "3").responseHeader("grpc-status-details-bin", Base64.getEncoder().encodeToString(other)).build();
        assertTrue(passive(m2, "grpc.debug-info").isEmpty());
    }

    @Test
    void reflectionTrafficSeen() {
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST")
                .url("https://api.example.com/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo")
                .requestHeader("Content-Type", "application/grpc-web+proto").requestBody(frame(0, pb().str(7, "*").build())).build();
        List<Finding> f = passive(m, "grpc.reflection-traffic");
        assertEquals(1, f.size());
        assertEquals(Finding.Scope.HOST, f.get(0).scope());
        assertTrue(passive(req("application/grpc-web+proto", frame(0, nested())).build(), "grpc.reflection-traffic").isEmpty());
    }

    @Test
    void sensitiveValuesInResponses() {
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSIsImFkbWluIjp0cnVlfQ.sig";
        byte[] reply = pb().str(1, "alice@example.com").msg(2, pb().str(1, jwt)).build();
        MessageContext m = resp("application/grpc-web+proto", "application/grpc-web+proto", frame(0, reply)).build();
        List<Finding> f = passive(m, "grpc.sensitive-data");
        assertEquals(1, f.size());
        assertTrue(f.get(0).detail().contains("JWT"), f.get(0).detail());
        assertFalse(f.get(0).detail().contains("email address"), "emails are not reported");

        MessageContext benign = resp("application/grpc-web+proto", "application/grpc-web+proto", frame(0, pb().str(1, "alice@example.com").varint(2, 5).build())).build();
        assertTrue(passive(benign, "grpc.sensitive-data").isEmpty());
    }

    // ------------------------------------------------------------ active

    static final class FakeSender implements HttpSender {
        final List<String> paths = new ArrayList<>();
        final List<byte[]> bodies = new ArrayList<>();
        final List<List<Header>> headers = new ArrayList<>();
        final Function<String, MessageContext.Builder> responder;

        FakeSender(Function<String, MessageContext.Builder> responder) {
            this.responder = responder;
        }

        @Override
        public Exchange send(String method, String pathAndQuery, List<Header> h, byte[] body) {
            paths.add(pathAndQuery);
            bodies.add(body);
            headers.add(h);
            MessageContext.Builder b = responder.apply(pathAndQuery);
            return new Exchange(b.method(method).url("https://api.example.com" + pathAndQuery).requestBody(body).build(), null);
        }

        @Override
        public Exchange send(InsertionPoint point, String payload) {
            throw new UnsupportedOperationException();
        }
    }

    static MessageContext.Builder grpcWebReply(byte[] body) {
        return MessageContext.builder(MessageKind.REQUEST).statusCode(200).responseHeader("Content-Type", "application/grpc-web+proto").responseBody(body);
    }

    @Test
    void reflectionProbeListsServices() {
        byte[] list = pb().msg(1, pb().str(1, "helloworld.Greeter")).msg(1, pb().str(1, "grpc.reflection.v1alpha.ServerReflection")).build();
        byte[] reply = pb().str(1, "").msg(2, pb().str(7, "*")).bytes(6, list).build();
        FakeSender http = new FakeSender(p -> p.contains("v1alpha")
                ? grpcWebReply(concat(frame(0, reply), frame(0x80, ascii("grpc-status:0\r\n"))))
                : grpcWebReply(frame(0x80, ascii("grpc-status:12\r\n"))));
        MessageContext base = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://api.example.com/rpc/helloworld.Greeter/SayHello")
                .requestHeader("Content-Type", "application/grpc-web+proto").requestHeader("Authorization", "Bearer abc")
                .requestHeader("grpc-encoding", "gzip").requestBody(frame(0, nested())).build();
        List<Finding> f = app.scanEngine().active(ActiveCheck.Scope.PER_HOST, base, null, null, null, null, http);
        assertEquals(1, http.paths.size());
        assertEquals("/rpc/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", http.paths.get(0));
        // body = frame(ServerReflectionRequest{host: "", list_services: "*"})
        assertArrayEquals(frame(0, pb().str(1, "").str(7, "*").build()), http.bodies.get(0));
        List<String> names = http.headers.get(0).stream().map(h -> h.name().toLowerCase()).toList();
        assertTrue(names.contains("authorization") && names.contains("x-grpc-web") && !names.contains("grpc-encoding"), names.toString());
        assertEquals(1, f.size());
        assertEquals("gRPC server reflection enabled", f.get(0).title());
        assertEquals(Severity.INFORMATION, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("helloworld.Greeter"));
        assertEquals(1, f.get(0).exchanges().size());
    }

    @Test
    void reflectionProbeNegativeAndNativeGrpcSkipped() {
        FakeSender http = new FakeSender(p -> grpcWebReply(new byte[0]).responseHeader("grpc-status", "12"));
        MessageContext web = req("application/grpc-web+proto", frame(0, nested())).build();
        assertTrue(app.scanEngine().active(ActiveCheck.Scope.PER_HOST, web, null, null, null, null, http).isEmpty());
        assertEquals(2, http.paths.size()); // v1alpha + v1
        assertEquals("/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", http.paths.get(1));

        FakeSender none = new FakeSender(p -> grpcWebReply(new byte[0]));
        MessageContext nativeGrpc = req("application/grpc", frame(0, nested())).build();
        assertTrue(app.scanEngine().active(ActiveCheck.Scope.PER_HOST, nativeGrpc, null, null, null, null, none).isEmpty());
        assertTrue(none.paths.isEmpty());
    }
}
