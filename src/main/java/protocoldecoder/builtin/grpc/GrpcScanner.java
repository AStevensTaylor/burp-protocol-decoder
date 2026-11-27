package protocoldecoder.builtin.grpc;

import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.scan.ActiveCheck;
import protocoldecoder.scan.ActiveContext;
import protocoldecoder.scan.Confidence;
import protocoldecoder.scan.Exchange;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.InsertionPoint;
import protocoldecoder.scan.InsertionPoints;
import protocoldecoder.scan.PassiveCheck;
import protocoldecoder.scan.ProtocolScanner;
import protocoldecoder.scan.ScanPatterns;
import protocoldecoder.scan.Severity;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;
import protocoldecoder.util.TreeText;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Function;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Scanner support for gRPC / gRPC-Web / Connect / raw protobuf: protobuf-aware insertion points (every scalar at any
 * nesting depth, lengths and framing recomputed), status/error disclosure checks and a server-reflection probe.
 */
public final class GrpcScanner implements ProtocolScanner {

    static final String REFLECTION_V1ALPHA = "grpc.reflection.v1alpha.ServerReflection";
    static final String REFLECTION_V1 = "grpc.reflection.v1.ServerReflection";

    @Override
    public String decoderId() {
        return GrpcDecoder.ID;
    }

    @Override
    public List<PassiveCheck> passiveChecks() {
        return List.of(new StatusErrorDisclosure(), new StatusDebugInfo(), new ReflectionTraffic(), new SensitiveResponseData());
    }

    @Override
    public List<ActiveCheck> activeChecks() {
        return List.of(new ReflectionProbe());
    }

    // ================================================================== insertion points

    /** A message embedded in the request and how to put a replacement back (whole new BODY or QUERY part). */
    record Carrier(String label, byte[] message, boolean json, InsertionPoint.Part part, Function<byte[], byte[]> render) {
    }

    @Override
    public List<InsertionPoint> insertionPoints(MessageContext request, DecodeResult decoded) {
        List<InsertionPoint> out = new ArrayList<>();
        if (request == null || !request.isRequest()) return out;
        List<Carrier> carriers;
        try {
            carriers = carriers(request);
        } catch (RuntimeException e) {
            return out;
        }
        String target = target(request);
        String protoName = protocolPrefix(request);
        for (Carrier c : carriers) {
            int room = InsertionPoints.MAX_POINTS - out.size();
            if (room <= 0) break;
            String lead = protoName + ": " + target + " " + c.label();
            if (c.json()) {
                var json = JsonTree.parseStrict(Codecs.utf8(c.message()));
                if (json == null) continue;
                for (InsertionPoints.JsonLeaf leaf : InsertionPoints.jsonLeaves(json)) {
                    if (out.size() >= InsertionPoints.MAX_POINTS) break;
                    Function<String, byte[]> render = payload -> c.render().apply(leaf.replace().apply(payload).getBytes(StandardCharsets.UTF_8));
                    out.add(point(c.part(), lead + leaf.path() + " (json)", InsertionPoints.text(leaf.value()), render));
                }
                continue;
            }
            for (ProtoEdit.Leaf leaf : ProtoEdit.leaves(c.message(), room)) {
                Function<String, byte[]> render = payload -> c.render().apply(leaf.rebuild().apply(payload));
                out.add(point(c.part(), lead + leaf.path() + " (" + leaf.kind() + ")", leaf.baseValue(), render));
            }
        }
        return out;
    }

    private static InsertionPoint point(InsertionPoint.Part part, String name, String base, Function<String, byte[]> render) {
        return part == InsertionPoint.Part.QUERY ? InsertionPoint.query(name, base, render) : InsertionPoint.body(name, base, render);
    }

    private static String protocolPrefix(MessageContext m) {
        GrpcDecoder.Detection d = GrpcDecoder.detect(m);
        return d != null && d.proto() == GrpcDecoder.Proto.PROTOBUF ? "Protobuf" : "gRPC";
    }

    /** "/pkg.Svc/Method" for RPC paths, else the request path. */
    static String target(MessageContext m) {
        GrpcDecoder.Call call = GrpcDecoder.call(m.path());
        return call == null ? m.path() : "/" + call.target();
    }

    static List<Carrier> carriers(MessageContext m) {
        List<Carrier> out = new ArrayList<>();
        GrpcDecoder.Detection d = GrpcDecoder.detect(m);
        if (d != null && d.proto() == GrpcDecoder.Proto.CONNECT_GET) {
            Carrier c = connectGet(m);
            if (c != null) out.add(c);
            return out;
        }
        byte[] raw = m.requestBody() == null ? new byte[0] : m.requestBody();
        if (raw.length == 0) return out;
        Function<byte[], byte[]> bodyEncoder = contentEncoder(m.requestHeader("Content-Encoding"));
        if (bodyEncoder == null) return out;
        byte[] body = Codecs.decodeContent(raw, m.requestHeader("Content-Encoding"));
        if (hasEncoding(m.requestHeader("Content-Encoding")) && Arrays.equals(body, raw)) return out; // could not decode it

        GrpcDecoder.Proto proto;
        boolean json;
        if (d != null) {
            proto = d.proto();
            json = d.json();
        } else if (GrpcFrames.looksFramed(body)) {
            proto = GrpcDecoder.Proto.GRPC;
            json = false;
        } else {
            proto = GrpcDecoder.Proto.PROTOBUF;
            json = false;
        }
        switch (proto) {
            case GRPC, GRPC_WEB, CONNECT_STREAM -> framed(m, proto, json, body, false, bodyEncoder, out);
            case GRPC_WEB_TEXT -> {
                byte[] bin = GrpcFrames.decodeBase64Chunks(new String(body, StandardCharsets.ISO_8859_1));
                if (bin != null) framed(m, proto, json, bin, true, bodyEncoder, out);
            }
            case CONNECT_UNARY, PROTOBUF -> {
                if (!looksJson(body)) out.add(new Carrier("", body, false, InsertionPoint.Part.BODY, bodyEncoder));
            }
            default -> {
                // Connect JSON: plain JSON body, Burp's own insertion points cover it
            }
        }
        return out;
    }

    private static void framed(MessageContext m, GrpcDecoder.Proto proto, boolean json, byte[] bin, boolean text,
                               Function<byte[], byte[]> bodyEncoder, List<Carrier> out) {
        GrpcFrames.Frames fr = GrpcFrames.parse(bin);
        boolean connect = proto == GrpcDecoder.Proto.CONNECT_STREAM;
        String encoding = m.requestHeader(connect ? "Connect-Content-Encoding" : "grpc-encoding");
        List<GrpcFrames.Frame> data = new ArrayList<>();
        for (GrpcFrames.Frame f : fr.frames()) {
            if (f.truncated()) continue;
            if (!connect && (f.flags() & GrpcFrames.FLAG_TRAILER) != 0) continue;
            if (connect && (f.flags() & GrpcFrames.FLAG_CONNECT_END) != 0) continue;
            data.add(f);
        }
        for (GrpcFrames.Frame f : data) {
            byte[] payload = f.payload();
            Function<byte[], byte[]> compress = b -> b;
            if (f.compressed()) {
                try {
                    payload = GrpcFrames.decompress(payload, encoding);
                } catch (IOException e) {
                    continue;
                }
                compress = messageCompressor(encoding, f.payload());
                if (compress == null) continue;
            }
            final Function<byte[], byte[]> comp = compress;
            final int start = f.offset();
            final int end = f.offset() + 5 + (int) f.declaredLength();
            final int flags = f.flags();
            Function<byte[], byte[]> render = newMsg -> {
                byte[] p = comp.apply(newMsg);
                byte[] frame = new byte[5 + p.length];
                frame[0] = (byte) flags;
                frame[1] = (byte) (p.length >>> 24);
                frame[2] = (byte) (p.length >>> 16);
                frame[3] = (byte) (p.length >>> 8);
                frame[4] = (byte) p.length;
                System.arraycopy(p, 0, frame, 5, p.length);
                byte[] newBin = ProtoEdit.concat(Arrays.copyOfRange(bin, 0, start), frame, Arrays.copyOfRange(bin, end, bin.length));
                byte[] body = text ? Base64.getEncoder().encode(newBin) : newBin;
                return bodyEncoder.apply(body);
            };
            String label = data.size() > 1 ? "msg" + (data.indexOf(f) + 1) + " " : "";
            out.add(new Carrier(label, payload, json, InsertionPoint.Part.BODY, render));
        }
    }

    /** Connect GET: {@code ?message=} (base64 when {@code base64=1}, else percent-encoded bytes), optionally compressed. */
    private static Carrier connectGet(MessageContext m) {
        String q = m.query();
        String[] pairs = q.split("&", -1);
        int idx = -1;
        boolean b64 = false;
        String compression = null;
        boolean json = false;
        for (int i = 0; i < pairs.length; i++) {
            String p = pairs[i];
            int eq = p.indexOf('=');
            String k = GrpcFrames.percentDecode(eq < 0 ? p : p.substring(0, eq));
            String v = eq < 0 ? "" : p.substring(eq + 1);
            switch (k) {
                case "message" -> { if (idx < 0) idx = i; }
                case "base64" -> b64 = "1".equals(v);
                case "compression" -> compression = GrpcFrames.percentDecode(v);
                case "encoding" -> json = "json".equalsIgnoreCase(GrpcFrames.percentDecode(v));
                default -> { }
            }
        }
        if (idx < 0) return null;
        String rawValue = pairs[idx].substring(pairs[idx].indexOf('=') + 1);
        byte[] msg = b64 ? Codecs.base64Decode(GrpcFrames.percentDecode(rawValue)) : GrpcFrames.percentDecodeBytes(rawValue);
        if (msg == null) return null;
        Function<byte[], byte[]> compress = b -> b;
        if (compression != null && !compression.isEmpty() && !compression.equalsIgnoreCase("identity")) {
            byte[] original = msg;
            try {
                msg = GrpcFrames.decompress(msg, compression);
            } catch (IOException e) {
                return null;
            }
            compress = messageCompressor(compression, original);
            if (compress == null) return null;
        }
        final Function<byte[], byte[]> comp = compress;
        final int at = idx;
        final boolean base64 = b64;
        Function<byte[], byte[]> render = newMsg -> {
            byte[] c = comp.apply(newMsg);
            String value = base64 ? Base64.getUrlEncoder().withoutPadding().encodeToString(c) : percentEncode(c);
            String[] copy = pairs.clone();
            String p = copy[at];
            copy[at] = p.substring(0, p.indexOf('=') + 1) + value;
            return String.join("&", copy).getBytes(StandardCharsets.ISO_8859_1);
        };
        return new Carrier("(Connect GET) ", msg, json, InsertionPoint.Part.QUERY, render);
    }

    static String percentEncode(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 3);
        for (byte x : b) {
            int c = x & 0xff;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
                sb.append((char) c);
            } else {
                sb.append('%').append(Character.toUpperCase(Character.forDigit(c >> 4, 16))).append(Character.toUpperCase(Character.forDigit(c & 15, 16)));
            }
        }
        return sb.toString();
    }

    private static boolean hasEncoding(String ce) {
        return ce != null && !ce.isBlank() && !ce.trim().equalsIgnoreCase("identity");
    }

    /** Re-applies an HTTP Content-Encoding; null if the encoding cannot be reproduced. */
    private static Function<byte[], byte[]> contentEncoder(String ce) {
        if (!hasEncoding(ce)) return b -> b;
        String e = ce.trim().toLowerCase(Locale.ROOT);
        if (e.equals("gzip") || e.equals("x-gzip")) return GrpcScanner::gzip;
        if (e.equals("deflate")) return GrpcScanner::zlib;
        return null;
    }

    /** Compressor matching the per-message encoding, mirroring {@link GrpcFrames#decompress}; null if unsupported. */
    private static Function<byte[], byte[]> messageCompressor(String encoding, byte[] original) {
        String enc = encoding == null ? "" : encoding.trim().toLowerCase(Locale.ROOT);
        if (enc.equals("gzip") || (enc.isEmpty() || enc.equals("identity")) && Codecs.isGzip(original)) return GrpcScanner::gzip;
        if (enc.equals("deflate") || (enc.isEmpty() && Codecs.isZlib(original))) return GrpcScanner::zlib;
        return null;
    }

    static byte[] gzip(byte[] b) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(b.length / 2 + 32);
        try (OutputStream z = new GZIPOutputStream(o)) {
            z.write(b);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return o.toByteArray();
    }

    static byte[] zlib(byte[] b) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(b.length / 2 + 32);
        try (OutputStream z = new DeflaterOutputStream(o)) {
            z.write(b);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return o.toByteArray();
    }

    private static boolean looksJson(byte[] b) {
        for (byte x : b) {
            if (x == ' ' || x == '\n' || x == '\r' || x == '\t') continue;
            return x == '{' || x == '[';
        }
        return false;
    }

    // ================================================================== protobuf helpers for checks

    /** Raw bytes of every LEN field {@code number} at the top level of {@code msg}. */
    static List<byte[]> lenFields(byte[] msg, int number) {
        List<byte[]> out = new ArrayList<>();
        if (msg == null) return out;
        for (Protobuf.Field f : Protobuf.parse(msg).fields) {
            if (f.number == number && f.wireType == Protobuf.LEN) out.add(Arrays.copyOfRange(f.src, f.start, f.start + f.length));
            if (out.size() > 1000) break;
        }
        return out;
    }

    static List<String> strings(byte[] msg, int number) {
        List<String> out = new ArrayList<>();
        for (byte[] b : lenFields(msg, number)) out.add(new String(b, StandardCharsets.UTF_8));
        return out;
    }

    /** The grpc-status-details-bin value from the response header or a gRPC-Web trailer frame. */
    static String detailsBin(MessageContext m, DecodeResult decoded) {
        String h = m.responseHeader("grpc-status-details-bin");
        if (h != null && !h.isBlank()) return h;
        if (decoded != null) {
            DecodedNode t = decoded.root().get("trailers");
            if (t != null && t.get("grpc-status-details-bin") != null) return t.get("grpc-status-details-bin").value();
        }
        return null;
    }

    /** Status message from the decoded tree (header, trailer frame or Connect error), falling back to the header. */
    static String statusMessage(MessageContext m, DecodeResult decoded) {
        if (decoded != null) {
            DecodedNode st = decoded.root().get("status");
            if (st != null && st.get("message") != null) return st.get("message").value();
        }
        return GrpcFrames.percentDecode(m.responseHeader("grpc-message"));
    }

    // ================================================================== passive checks

    /** grpc-message / Connect error message (or status details) revealing exceptions or stack traces. */
    static final class StatusErrorDisclosure implements PassiveCheck {
        @Override public String id() { return "grpc.error-details"; }
        @Override public String name() { return "Exception details in gRPC status"; }
        @Override public String description() { return "grpc-message, Connect error bodies or status details containing exception types or stack traces"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse()) return List.of();
            String message = statusMessage(m, decoded);
            StringBuilder text = new StringBuilder(message == null ? "" : message);
            if (decoded != null) {
                DecodedNode st = decoded.root().get("status");
                if (st != null && st.get("details") != null) text.append('\n').append(TreeText.render(st.get("details")));
                DecodedNode err = decoded.root().get("error");
                if (err != null) text.append('\n').append(TreeText.render(err));
            }
            String trace = ScanPatterns.exceptionEvidence(text.toString());
            if (trace == null) return List.of();
            Finding f = Finding.of(id(), "gRPC error discloses exception details")
                    .severity(Severity.LOW).confidence(Confidence.FIRM)
                    .detail("The gRPC status returned by <code>" + Finding.esc(target(m)) + "</code> contains exception details"
                            + (message == null || message.isEmpty() ? "" : ": <code>" + Finding.esc(Codecs.truncate(message, 500)) + "</code>")
                            + "<br>Evidence: <code>" + Finding.esc(trace) + "</code>")
                    .background("gRPC servers put the error text in the <code>grpc-message</code> header/trailer (or the Connect error body). "
                            + "Frameworks that copy exception messages or stack traces into it reveal internal types, code paths and data "
                            + "that help an attacker refine attacks.")
                    .remediation("Map internal exceptions to generic status messages in a server interceptor; log details server-side only.");
            f.responseEvidence(trace);
            return List.of(f);
        }
    }

    /** google.rpc.DebugInfo (stack entries) inside grpc-status-details-bin or a Connect error body. */
    static final class StatusDebugInfo implements PassiveCheck {
        static final String TYPE = "google.rpc.DebugInfo";

        @Override public String id() { return "grpc.debug-info"; }
        @Override public String name() { return "gRPC DebugInfo error details"; }
        @Override public String description() { return "Rich error details (google.rpc.DebugInfo) carrying server stack entries in grpc-status-details-bin"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse()) return List.of();
            List<String> entries = new ArrayList<>();
            String detailText = null;
            String bin = detailsBin(m, decoded);
            byte[] status = bin == null ? null : Codecs.base64Decode(bin.trim());
            if (status != null) {
                for (byte[] any : lenFields(status, 3)) {
                    List<String> type = strings(any, 1);
                    if (type.isEmpty() || !type.get(0).endsWith(TYPE)) continue;
                    for (byte[] value : lenFields(any, 2)) {
                        for (String s : strings(value, 1)) if (entries.size() < 30) entries.add(s);
                        List<String> d = strings(value, 2);
                        if (!d.isEmpty() && !d.get(0).isBlank()) detailText = d.get(0);
                    }
                }
            }
            // Connect: {"code":..., "details":[{"type":"google.rpc.DebugInfo","value":"...","debug":{...}}]}
            if (entries.isEmpty() && detailText == null && m.responseBodyText().contains(TYPE)) {
                var json = JsonTree.parseStrict(m.responseBodyText());
                if (json != null && json.isJsonObject() && json.getAsJsonObject().get("details") instanceof com.google.gson.JsonArray arr) {
                    for (var e : arr) {
                        if (!e.isJsonObject()) continue;
                        var o = e.getAsJsonObject();
                        if (!o.has("type") || !o.get("type").isJsonPrimitive() || !o.get("type").getAsString().endsWith(TYPE)) continue;
                        if (o.has("value") && o.get("value").isJsonPrimitive()) {
                            byte[] v = Codecs.base64Decode(o.get("value").getAsString());
                            if (v != null) {
                                for (String s : strings(v, 1)) if (entries.size() < 30) entries.add(s);
                                List<String> d = strings(v, 2);
                                if (!d.isEmpty() && !d.get(0).isBlank()) detailText = d.get(0);
                            }
                        }
                    }
                }
            }
            if (entries.isEmpty() && detailText == null) return List.of();
            StringBuilder html = new StringBuilder("The gRPC error returned by <code>" + Finding.esc(target(m))
                    + "</code> carries a <code>google.rpc.DebugInfo</code> detail");
            if (detailText != null) html.append(" with detail <code>").append(Finding.esc(Codecs.truncate(detailText, 500))).append("</code>");
            if (!entries.isEmpty()) {
                html.append(" and ").append(entries.size()).append(" stack entr").append(entries.size() == 1 ? "y" : "ies").append(":<ul>");
                for (String s : entries.subList(0, Math.min(entries.size(), 15))) html.append("<li><code>").append(Finding.esc(Codecs.truncate(s, 300))).append("</code></li>");
                html.append("</ul>");
            }
            return List.of(Finding.of(id(), "gRPC error details include debug information")
                    .severity(Severity.LOW).confidence(Confidence.FIRM)
                    .detail(html.toString())
                    .background("<code>google.rpc.DebugInfo</code> is meant for development: it carries the server's stack trace and "
                            + "internal detail. Returning it to clients discloses implementation details.")
                    .remediation("Strip DebugInfo from error details before they leave the service (e.g. in an interceptor) in production."));
        }
    }

    /** Traffic to the gRPC server reflection service. */
    static final class ReflectionTraffic implements PassiveCheck {
        @Override public String id() { return "grpc.reflection-traffic"; }
        @Override public String name() { return "gRPC server reflection in traffic"; }
        @Override public String description() { return "Requests to grpc.reflection.v1alpha/v1 ServerReflection were observed"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isRequest() || m.path() == null) return List.of();
            String p = m.path();
            String svc = p.contains(REFLECTION_V1ALPHA + "/") ? REFLECTION_V1ALPHA : p.contains(REFLECTION_V1 + "/") ? REFLECTION_V1 : null;
            if (svc == null) return List.of();
            return List.of(Finding.of(id(), "gRPC server reflection service in use")
                    .severity(Severity.INFORMATION).confidence(Confidence.CERTAIN).scope(Finding.Scope.HOST)
                    .detail("A request to the gRPC server reflection service <code>" + Finding.esc(svc) + "</code> was observed ("
                            + Finding.esc(p) + "). Check whether the service answers unauthenticated clients.")
                    .background("Server reflection lets any client list services and download their full protobuf schemas, which maps the "
                            + "complete API surface (including methods the front-end never calls).")
                    .remediation("Disable server reflection in production, or restrict it to authenticated internal clients.")
                    .requestEvidence(svc));
        }
    }

    /** Tokens, credentials or card numbers in decoded protobuf/JSON response messages. */
    static final class SensitiveResponseData implements PassiveCheck {
        @Override public String id() { return "grpc.sensitive-data"; }
        @Override public String name() { return "Sensitive values in gRPC responses"; }
        @Override public String description() { return "JWTs, bearer tokens, credential-like key=value pairs or card numbers in decoded response messages"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || decoded == null) return List.of();
            List<ScanPatterns.Sensitive> hits = new ArrayList<>();
            for (DecodedNode n : decoded.root().children()) {
                if (n.name().startsWith("message")) hits.addAll(ScanPatterns.sensitiveValues(n, 20));
            }
            // Schemaless field names are numbers, and e-mail addresses are routine API data; keep only secrets and cards.
            hits.removeIf(h -> h.kind().equals("email address"));
            if (hits.isEmpty()) return List.of();
            Finding f = Finding.of(id(), "Sensitive data in gRPC response")
                    .severity(Severity.LOW).confidence(Confidence.TENTATIVE)
                    .detail("Decoded response messages of <code>" + Finding.esc(target(m)) + "</code> contain values that look sensitive:"
                            + ScanPatterns.htmlList(hits))
                    .background("Binary protobuf responses are not inspected by most tooling, so secrets or payment data in them are easily overlooked.")
                    .remediation("Review whether the client needs these values; avoid returning secrets or full card numbers.");
            for (ScanPatterns.Sensitive h : hits) f.responseEvidence(h.value());
            return List.of(f);
        }
    }

    // ================================================================== active

    /**
     * Sends one gRPC-Web ServerReflectionInfo request with {@code list_services: "*"} (v1alpha, then v1 if needed).
     * ServerReflectionRequest: host = 1, list_services = 7. ServerReflectionResponse: list_services_response = 6
     * → ListServiceResponse.service = 1 → ServiceResponse.name = 1.
     */
    static final class ReflectionProbe implements ActiveCheck {
        @Override public String id() { return "grpc.reflection-enabled"; }
        @Override public String name() { return "gRPC server reflection enabled"; }
        @Override public String description() {
            return "Once per host with gRPC-Web/Connect traffic: asks the reflection service to list services over gRPC-Web (≤2 requests: v1alpha, v1)";
        }
        @Override public Scope scope() { return Scope.PER_HOST; }

        @Override
        public List<Finding> run(ActiveContext ctx) {
            MessageContext base = ctx.base();
            GrpcDecoder.Detection d = GrpcDecoder.detect(base);
            if (d == null) return List.of();
            switch (d.proto()) {
                case GRPC_WEB, GRPC_WEB_TEXT, CONNECT_STREAM, CONNECT_UNARY, CONNECT_GET, CONNECT_JSON -> { }
                default -> { return List.of(); } // native gRPC needs HTTP/2 trailers; raw protobuf is not RPC
            }
            String prefix = pathPrefix(base.path());
            byte[] request = ProtoEdit.concat(ProtoEdit.lenField(1, new byte[0]), ProtoEdit.lenField(7, "*".getBytes(StandardCharsets.UTF_8)));
            byte[] body = ProtoEdit.concat(new byte[]{0, 0, 0, 0, (byte) request.length}, request);
            List<Header> headers = new ArrayList<>();
            for (Header h : base.requestHeaders()) {
                String n = h.name().toLowerCase(Locale.ROOT);
                if (n.equals("content-type") || n.equals("content-length") || n.equals("content-encoding") || n.startsWith("grpc-")
                        || n.startsWith("connect-") || n.equals("x-grpc-web") || n.equals("accept") || n.equals("te")) continue;
                headers.add(h);
            }
            headers.add(new Header("Content-Type", "application/grpc-web+proto"));
            headers.add(new Header("Accept", "application/grpc-web+proto"));
            headers.add(new Header("X-Grpc-Web", "1"));
            for (String svc : new String[]{REFLECTION_V1ALPHA, REFLECTION_V1}) {
                Exchange x = ctx.http().send("POST", prefix + "/" + svc + "/ServerReflectionInfo", headers, body);
                if (x == null || !x.hasResponse()) continue;
                List<String> services = listedServices(x.message());
                if (services.isEmpty()) continue;
                StringBuilder html = new StringBuilder("The gRPC server reflection service <code>" + Finding.esc(svc)
                        + "</code> answered a <code>list_services</code> request and returned " + services.size() + " service(s):<ul>");
                for (String s : services) html.append("<li><code>").append(Finding.esc(s)).append("</code></li>");
                html.append("</ul>Use a reflection client (e.g. <code>grpcurl</code>) to download the schemas and enumerate every method.");
                Finding f = Finding.of(id(), "gRPC server reflection enabled")
                        .severity(Severity.INFORMATION).confidence(Confidence.FIRM).scope(Finding.Scope.HOST)
                        .detail(html.toString())
                        .background("Server reflection exposes the full protobuf schema of every registered service, including internal or "
                                + "administrative methods the client application never calls, which makes API discovery trivial.")
                        .remediation("Disable server reflection in production or restrict it to authenticated internal callers.")
                        .exchange(x);
                for (String s : services) f.responseEvidence(s);
                return List.of(f);
            }
            return List.of();
        }

        /** Part of the path before "/pkg.Service/Method" (gRPC-Web proxies are sometimes mounted under a prefix). */
        static String pathPrefix(String path) {
            if (path == null || GrpcDecoder.call(path) == null) return "";
            String p = path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
            int slash = p.lastIndexOf('/');
            int prev = p.lastIndexOf('/', slash - 1);
            return prev <= 0 ? "" : p.substring(0, prev);
        }

        static List<String> listedServices(MessageContext resp) {
            Set<String> out = new LinkedHashSet<>();
            byte[] body = Codecs.decodeContent(resp.responseBody(), resp.responseHeader("Content-Encoding"));
            if (body == null || body.length == 0) return List.of();
            String ct = resp.responseHeader("Content-Type");
            if (ct != null && ct.toLowerCase(Locale.ROOT).contains("grpc-web-text")) {
                body = GrpcFrames.decodeBase64Chunks(new String(body, StandardCharsets.ISO_8859_1));
                if (body == null) return List.of();
            }
            for (GrpcFrames.Frame f : GrpcFrames.parse(body).frames()) {
                if (f.truncated() || (f.flags() & GrpcFrames.FLAG_TRAILER) != 0) continue;
                byte[] p = f.payload();
                if (f.compressed()) {
                    try {
                        p = GrpcFrames.decompress(p, resp.responseHeader("grpc-encoding"));
                    } catch (IOException e) {
                        continue;
                    }
                }
                for (byte[] list : lenFields(p, 6)) {
                    for (byte[] svc : lenFields(list, 1)) {
                        for (String name : strings(svc, 1)) {
                            if (name.matches("[A-Za-z_][A-Za-z0-9_.]{0,200}") && out.size() < 200) out.add(name);
                        }
                    }
                }
            }
            return new ArrayList<>(out);
        }
    }
}
