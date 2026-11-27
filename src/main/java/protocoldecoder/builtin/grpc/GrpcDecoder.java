package protocoldecoder.builtin.grpc;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.Header;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.ProtocolDecoder;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * gRPC (as Burp shows HTTP/2 gRPC), gRPC-Web (binary and base64 text), Connect (unary, streaming, GET and JSON) and
 * plain protobuf bodies. Messages are decoded schemaless with {@link Protobuf}.
 */
public final class GrpcDecoder implements ProtocolDecoder {

    public static final String ID = "grpc";

    private static final Set<String> PROTOBUF_TYPES = Set.of(
            "application/x-protobuf", "application/protobuf", "application/vnd.google.protobuf",
            "application/x-google-protobuf", "application/x-protobuffer");

    enum Proto {
        GRPC("gRPC"), GRPC_WEB("gRPC-Web"), GRPC_WEB_TEXT("gRPC-Web-Text"), CONNECT_STREAM("Connect stream"),
        CONNECT_UNARY("Connect"), CONNECT_GET("Connect GET"), CONNECT_JSON("Connect JSON"), PROTOBUF("Protobuf");

        final String label;

        Proto(String label) { this.label = label; }

        boolean rpc() { return this != PROTOBUF; }
    }

    record Detection(Proto proto, boolean json, int confidence, String reason) {
    }

    record Status(int code, String message, String source, String detailsBin) {
    }

    /** Per-decode mutable state. */
    private static final class Ctx {
        final DecodedNode root;
        final List<String> warnings = new ArrayList<>();
        int messages;
        int firstFields = -1;
        Status status;

        Ctx(DecodedNode root) { this.root = root; }
    }

    @Override public String id() { return ID; }
    @Override public String name() { return "gRPC / Protobuf"; }
    @Override public String description() {
        return "gRPC, gRPC-Web (+text), Connect and raw protobuf bodies, decoded schemaless (like protoc --decode_raw)";
    }

    // ------------------------------------------------------------------ matching

    @Override
    public MatchResult match(MessageContext m) {
        try {
            Detection d = detect(m);
            return d == null ? MatchResult.NONE : MatchResult.of(d.confidence(), d.reason());
        } catch (RuntimeException e) {
            return MatchResult.NONE;
        }
    }

    static Detection detect(MessageContext m) {
        if (m.isWebSocket()) return null;
        boolean connectHeader = m.requestHeader("Connect-Protocol-Version") != null;
        String own = mime(m.contentType());
        String reqCt = mime(m.requestContentType());
        String ct = own.isEmpty() && m.isResponse() ? reqCt : own;

        if (m.isResponse() && own.equals("application/json") && reqCt.equals("application/proto")) {
            // Connect unary errors come back as JSON even for protobuf calls.
            return new Detection(Proto.CONNECT_UNARY, true, connectHeader ? 85 : 80, "JSON response to Connect application/proto request");
        }
        Detection d = byType(ct, connectHeader);
        if (d != null && m.isResponse() && own.isEmpty()) {
            d = new Detection(d.proto(), d.json(), Math.max(d.confidence() - 5, 40), d.reason() + " (request content type)");
        }
        if (d != null) return d;
        if (m.isResponse()) {
            if (m.responseHeader("grpc-status") != null) {
                return new Detection(Proto.GRPC, false, 90, "grpc-status response header");
            }
        }
        if (m.isRequest() && "GET".equalsIgnoreCase(m.method())) {
            String q = m.query();
            if (q.contains("connect=v1") && q.contains("message=")) {
                return new Detection(Proto.CONNECT_GET, q.contains("encoding=json"), 85, "Connect GET (connect=v1)");
            }
        }
        return null;
    }

    private static Detection byType(String ct, boolean connectHeader) {
        if (ct.isEmpty()) return null;
        boolean json = ct.endsWith("+json");
        if (ct.startsWith("application/grpc-web-text")) return new Detection(Proto.GRPC_WEB_TEXT, json, 95, "Content-Type " + ct);
        if (ct.startsWith("application/grpc-web")) return new Detection(Proto.GRPC_WEB, json, 95, "Content-Type " + ct);
        if (ct.equals("application/grpc") || ct.startsWith("application/grpc+")) return new Detection(Proto.GRPC, json, 95, "Content-Type " + ct);
        if (ct.startsWith("application/connect+")) return new Detection(Proto.CONNECT_STREAM, json, 90, "Content-Type " + ct);
        if (ct.equals("application/proto")) {
            return new Detection(Proto.CONNECT_UNARY, false, connectHeader ? 90 : 75, "Content-Type application/proto"
                    + (connectHeader ? " + Connect-Protocol-Version" : ""));
        }
        if (PROTOBUF_TYPES.contains(ct)) return new Detection(Proto.PROTOBUF, false, 80, "Content-Type " + ct);
        if (ct.equals("application/json") && connectHeader) {
            return new Detection(Proto.CONNECT_JSON, true, 50, "JSON with Connect-Protocol-Version header");
        }
        return null;
    }

    private static String mime(String contentType) {
        if (contentType == null) return "";
        int semi = contentType.indexOf(';');
        return (semi >= 0 ? contentType.substring(0, semi) : contentType).trim().toLowerCase(Locale.ROOT);
    }

    // ------------------------------------------------------------------ decoding

    @Override
    public DecodeResult decode(MessageContext m) throws DecodeException {
        if (m.isWebSocket()) {
            return decodeForced(m, m.body(), new Ctx(DecodedNode.object("WebSocket message")));
        }
        Detection d = detect(m);
        byte[] body = Codecs.decodeContent(m.body(), m.header("Content-Encoding"));
        if (body == null) body = new byte[0];
        String side = m.isResponse() ? " response" : " request";
        Ctx c = new Ctx(DecodedNode.object((d == null ? "Protobuf" : d.proto().label) + side));
        if (m.truncated()) c.warnings.add("The body was truncated by the size limit; the last message may be incomplete");
        if (d == null) return decodeForced(m, body, c);

        c.root.add(callNode(m, d.proto()));
        if (m.isResponse()) headerStatus(m, c);
        switch (d.proto()) {
            case GRPC, GRPC_WEB, CONNECT_STREAM -> decodeFramed(m, d.proto(), d.json(), body, c);
            case GRPC_WEB_TEXT -> {
                byte[] bin = GrpcFrames.decodeBase64Chunks(new String(body, StandardCharsets.ISO_8859_1));
                if (bin == null) {
                    c.warnings.add("Body is not valid base64 although the content type is grpc-web-text; decoding it as binary frames");
                    bin = body;
                }
                decodeFramed(m, d.proto(), d.json(), bin, c);
            }
            case CONNECT_UNARY -> {
                if (looksJson(body)) decodeConnectJson(m, body, c);
                else if (body.length > 0) addMessage(c, "message", body, false, body.length + " bytes");
            }
            case CONNECT_JSON -> decodeConnectJson(m, body, c);
            case CONNECT_GET -> decodeConnectGet(m, c);
            case PROTOBUF -> {
                if (body.length > 0) addMessage(c, "message", body, false, body.length + " bytes");
            }
        }
        if (c.status != null) c.root.add(statusNode(c.status, c));
        return new DecodeResult(summary(m, d.proto(), c), c.root, null, c.warnings);
    }

    /** No recognised content type (a user rule forced this decoder): sniff framing, base64, JSON, then raw protobuf. */
    private DecodeResult decodeForced(MessageContext m, byte[] body, Ctx c) throws DecodeException {
        String ct = m.isWebSocket() ? "" : m.contentType();
        String what = ct.isEmpty() ? "no Content-Type" : "Content-Type '" + ct + "'";
        if (body.length == 0) {
            if (!m.isWebSocket() && m.isResponse() && m.responseHeader("grpc-status") != null) {
                headerStatus(m, c);
                c.root.add(statusNode(c.status, c));
                return new DecodeResult(summary(m, Proto.GRPC, c), c.root, null, c.warnings);
            }
            throw new DecodeException("Empty body: nothing to decode as gRPC / Protobuf");
        }
        if (GrpcFrames.looksFramed(body)) {
            c.warnings.add(what + " is not a gRPC type, but the body has gRPC length-prefixed framing");
            if (!m.isWebSocket()) c.root.add(callNode(m, Proto.GRPC));
            decodeFramed(m, Proto.GRPC, false, body, c);
            if (c.status != null) c.root.add(statusNode(c.status, c));
            return new DecodeResult(summary(m, Proto.GRPC, c), c.root, null, c.warnings);
        }
        if (Codecs.isMostlyText(body)) {
            String text = new String(body, StandardCharsets.ISO_8859_1).strip();
            byte[] b64 = text.length() >= 8 ? GrpcFrames.decodeBase64Chunks(text) : null;
            if (b64 != null && GrpcFrames.looksFramed(b64)) {
                c.warnings.add(what + " is not a gRPC type, but the body is base64 of gRPC frames (grpc-web-text)");
                decodeFramed(m, Proto.GRPC_WEB_TEXT, false, b64, c);
                if (c.status != null) c.root.add(statusNode(c.status, c));
                return new DecodeResult(summary(m, Proto.GRPC_WEB_TEXT, c), c.root, null, c.warnings);
            }
            if (b64 != null && b64.length > 0 && Protobuf.parse(b64).complete()) {
                c.warnings.add("Body is base64; decoded it and parsed the bytes as protobuf");
                addMessage(c, "message", b64, false, b64.length + " bytes (base64-decoded)");
                return new DecodeResult(summary(m, Proto.PROTOBUF, c), c.root, null, c.warnings);
            }
            JsonElement json = JsonTree.parseStrict(Codecs.utf8(body));
            if (json != null && (json.isJsonObject() || json.isJsonArray())) {
                c.warnings.add("Body is JSON, not protobuf");
                c.root.add(JsonTree.toNode("json", json, true));
                return new DecodeResult("JSON body (" + body.length + " bytes)", c.root, null, c.warnings);
            }
        }
        Protobuf.Parsed p = Protobuf.parse(body);
        if (p.fields.isEmpty()) {
            throw new DecodeException("Not a protobuf message (" + what + "): " + p.error);
        }
        addMessage(c, "message", body, false, body.length + " bytes");
        return new DecodeResult(summary(m, Proto.PROTOBUF, c), c.root, null, c.warnings);
    }

    private void decodeFramed(MessageContext m, Proto proto, boolean json, byte[] data, Ctx c) {
        if (data.length == 0) return;
        GrpcFrames.Frames fr = GrpcFrames.parse(data);
        if (fr.frames().isEmpty()) {
            c.warnings.add("Body is not length-prefixed (" + fr.error() + "); decoding it as a bare message");
            addMessage(c, "message", data, json, data.length + " bytes");
            return;
        }
        if (fr.error() != null) c.warnings.add(fr.error());
        boolean connect = proto == Proto.CONNECT_STREAM;
        String encoding = m.isWebSocket() ? null : m.header(connect ? "Connect-Content-Encoding" : "grpc-encoding");
        for (GrpcFrames.Frame f : fr.frames()) {
            byte[] p = f.payload();
            StringBuilder info = new StringBuilder(String.format("flags 0x%02x, %d bytes", f.flags(), p.length));
            if (f.truncated()) {
                info.append(" of ").append(f.declaredLength()).append(" (truncated)");
                c.warnings.add("Frame " + (f.index() + 1) + " is incomplete; showing the bytes that are present");
            }
            if (f.compressed()) {
                if (f.truncated()) {
                    c.root.add(DecodedNode.leaf("frame " + (f.index() + 1), Protobuf.hex(p, 0, p.length), DecodedNode.Type.BINARY));
                    continue;
                }
                try {
                    byte[] out = GrpcFrames.decompress(p, encoding);
                    info.append(", ").append(encoding == null || encoding.isBlank() ? "compressed" : encoding.trim())
                            .append(" → ").append(out.length).append(" bytes");
                    p = out;
                } catch (IOException e) {
                    c.warnings.add("Frame " + (f.index() + 1) + " could not be decompressed: " + e.getMessage());
                    c.root.add(DecodedNode.leaf("frame " + (f.index() + 1) + " (compressed)", Protobuf.hex(p, 0, p.length), DecodedNode.Type.BINARY));
                    continue;
                }
            }
            if (!connect && (f.flags() & GrpcFrames.FLAG_TRAILER) != 0) {
                trailerFrame(p, info.toString(), c);
            } else if (connect && (f.flags() & GrpcFrames.FLAG_CONNECT_END) != 0) {
                connectEndStream(p, info.toString(), c);
            } else {
                addMessage(c, "message " + (c.messages + 1), p, json, info.toString());
            }
        }
    }

    private void trailerFrame(byte[] p, String info, Ctx c) {
        Map<String, String> t = GrpcFrames.parseTrailers(p);
        DecodedNode n = new DecodedNode("trailers", info, DecodedNode.Type.OBJECT);
        t.forEach(n::put);
        c.root.add(n);
        String code = t.get("grpc-status");
        if (code != null) {
            c.status = new Status(parseCode(code), GrpcFrames.percentDecode(t.get("grpc-message")), "trailer frame",
                    t.get("grpc-status-details-bin"));
        }
    }

    private void connectEndStream(byte[] p, String info, Ctx c) {
        String text = Codecs.utf8(p);
        JsonElement e = JsonTree.parseStrict(text);
        if (e == null) {
            c.warnings.add("Connect end-of-stream frame is not JSON");
            c.root.add(DecodedNode.leaf("end of stream", Codecs.truncate(text, 4000)));
            return;
        }
        DecodedNode holder = new DecodedNode("end of stream", info, DecodedNode.Type.OBJECT);
        JsonTree.toNode("end of stream", e, true).children().forEach(holder::add);
        c.root.add(holder);
        if (e.isJsonObject() && e.getAsJsonObject().get("error") instanceof JsonObject err) {
            c.status = connectError(err, "end-of-stream frame");
        } else {
            c.status = new Status(0, null, "end-of-stream frame", null);
        }
    }

    private void decodeConnectJson(MessageContext m, byte[] body, Ctx c) {
        if (body.length == 0) return;
        JsonElement e = JsonTree.parseStrict(Codecs.utf8(body));
        if (e == null) {
            c.warnings.add("Body is not valid JSON");
            c.root.add(DecodedNode.leaf("body", Codecs.truncate(Codecs.utf8(body), 8000)));
            return;
        }
        Integer http = m.statusCode();
        if (m.isResponse() && http != null && http >= 400 && e.isJsonObject() && e.getAsJsonObject().has("code")) {
            c.status = connectError(e.getAsJsonObject(), "Connect error body (HTTP " + http + ")");
            c.root.add(JsonTree.toNode("error", e, true));
            return;
        }
        addMessage(c, "message", body, true, body.length + " bytes");
    }

    private static Status connectError(JsonObject err, String source) {
        String codeName = err.has("code") && err.get("code").isJsonPrimitive() ? err.get("code").getAsString() : null;
        String msg = err.has("message") && err.get("message").isJsonPrimitive() ? err.get("message").getAsString() : null;
        int code = GrpcFrames.codeFromConnectName(codeName);
        return new Status(code < 0 ? 2 : code, msg, source, null);
    }

    private void decodeConnectGet(MessageContext m, Ctx c) {
        Map<String, String> q = new LinkedHashMap<>();
        for (String part : m.query().split("&")) {
            int eq = part.indexOf('=');
            String k = eq < 0 ? part : part.substring(0, eq);
            q.putIfAbsent(GrpcFrames.percentDecode(k), eq < 0 ? "" : part.substring(eq + 1));
        }
        DecodedNode params = c.root.child("query");
        for (String k : List.of("connect", "encoding", "base64", "compression")) {
            if (q.containsKey(k)) params.put(k, GrpcFrames.percentDecode(q.get(k)));
        }
        String raw = q.get("message");
        if (raw == null) return;
        byte[] msg = "1".equals(q.get("base64")) ? Codecs.base64Decode(GrpcFrames.percentDecode(raw)) : GrpcFrames.percentDecodeBytes(raw);
        if (msg == null) {
            c.warnings.add("message parameter is not valid base64");
            return;
        }
        String comp = q.get("compression");
        if (comp != null && !comp.isEmpty() && !comp.equals("identity")) {
            try {
                msg = GrpcFrames.decompress(msg, comp);
            } catch (IOException e) {
                c.warnings.add("message parameter could not be decompressed: " + e.getMessage());
            }
        }
        addMessage(c, "message", msg, "json".equals(q.get("encoding")), msg.length + " bytes");
    }

    // ------------------------------------------------------------------ messages

    /** Adds one decoded message (protobuf or JSON) to the tree and counts it. */
    private static void addMessage(Ctx c, String name, byte[] p, boolean json, String info) {
        c.messages++;
        if (json) {
            JsonElement e = JsonTree.parseStrict(Codecs.utf8(p));
            if (e == null) {
                c.warnings.add(name + " is not valid JSON");
                c.root.add(DecodedNode.leaf(name, Codecs.truncate(Codecs.utf8(p), 8000)));
                return;
            }
            DecodedNode n = JsonTree.toNode(name, e, true);
            DecodedNode holder = new DecodedNode(name, info, n.type() == DecodedNode.Type.ARRAY ? DecodedNode.Type.ARRAY : DecodedNode.Type.OBJECT);
            if (n.isContainer()) n.children().forEach(holder::add); else holder.add(n);
            c.root.add(holder);
            if (c.firstFields < 0) c.firstFields = n.children().size();
            return;
        }
        c.root.add(protoNode(c, name, p, Protobuf.parse(p), info));
    }

    private static DecodedNode protoNode(Ctx c, String name, byte[] p, Protobuf.Parsed parsed, String info) {
        if (parsed.limitReached) c.warnings.add(name + ": output limited to " + Protobuf.MAX_FIELDS + " fields");
        if (p.length == 0) {
            if (c.firstFields < 0) c.firstFields = 0;
            return new DecodedNode(name, info + ", empty message (all fields default)", DecodedNode.Type.OBJECT);
        }
        if (parsed.fields.isEmpty()) {
            c.warnings.add(name + " is not valid protobuf (" + parsed.error + "); shown as hex");
            return DecodedNode.leaf(name, Protobuf.hex(p, 0, p.length), DecodedNode.Type.BINARY);
        }
        DecodedNode n = new DecodedNode(name, info + ", " + parsed.fields.size() + Protobuf.plural(parsed.fields.size(), " field"),
                DecodedNode.Type.OBJECT);
        Protobuf.render(parsed.fields, n);
        if (!parsed.complete()) {
            c.warnings.add(name + ": decoding stopped after " + parsed.fields.size() + " field(s): " + parsed.error
                    + "; the rest is shown as hex");
            int rest = p.length - parsed.stoppedAt;
            n.add(DecodedNode.leaf("unparsed", Protobuf.hex(p, parsed.stoppedAt, rest), DecodedNode.Type.BINARY));
        }
        if (c.firstFields < 0) c.firstFields = parsed.fields.size();
        return n;
    }

    // ------------------------------------------------------------------ call, status, summary

    record Call(String service, String method) {
        String target() { return service + "/" + method; }
    }

    /** Service/method from a path ending in {@code /package.Service/Method} (gRPC-Web proxies may add a prefix). */
    static Call call(String path) {
        if (path == null) return null;
        String p = path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
        int slash = p.lastIndexOf('/');
        if (slash <= 0) return null;
        int prev = p.lastIndexOf('/', slash - 1);
        String service = p.substring(prev + 1, slash), method = p.substring(slash + 1);
        if (!service.matches("[A-Za-z_][A-Za-z0-9_.]*") || !method.matches("[A-Za-z_][A-Za-z0-9_]*")) return null;
        return new Call(service, method);
    }

    private static DecodedNode callNode(MessageContext m, Proto proto) {
        DecodedNode n = DecodedNode.object("call");
        n.put("protocol", proto.label);
        Call call = proto.rpc() ? call(m.path()) : null;
        if (call != null) {
            int dot = call.service().lastIndexOf('.');
            if (dot > 0) n.put("package", call.service().substring(0, dot));
            n.put("service", call.service());
            n.put("method", call.method());
        }
        n.put("path", m.path());
        if (!m.contentType().isEmpty()) n.put("content-type", m.contentType());
        DecodedNode meta = DecodedNode.object("metadata");
        for (Header h : m.headers()) {
            String ln = h.name().toLowerCase(Locale.ROOT);
            if (ln.equals("grpc-status") || ln.equals("grpc-message") || ln.equals("grpc-status-details-bin")) continue;
            if (ln.startsWith("grpc-") || ln.startsWith("connect-") || ln.equals("x-grpc-web") || ln.equals("x-user-agent") || ln.equals("te")) {
                meta.put(h.name(), h.value());
            }
        }
        if (!meta.isLeaf()) n.add(meta);
        return n;
    }

    private static void headerStatus(MessageContext m, Ctx c) {
        String code = m.responseHeader("grpc-status");
        if (code != null) {
            c.status = new Status(parseCode(code), GrpcFrames.percentDecode(m.responseHeader("grpc-message")), "grpc-status header",
                    m.responseHeader("grpc-status-details-bin"));
        }
    }

    private static int parseCode(String s) {
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return 2;
        }
    }

    private static DecodedNode statusNode(Status s, Ctx c) {
        DecodedNode n = DecodedNode.object("status");
        n.put("code", s.code());
        n.put("name", GrpcFrames.statusName(s.code()));
        if (s.message() != null && !s.message().isEmpty()) n.put("message", s.message());
        n.put("source", s.source());
        if (s.detailsBin() != null && !s.detailsBin().isBlank()) {
            byte[] d = Codecs.base64Decode(s.detailsBin());
            if (d == null) {
                c.warnings.add("grpc-status-details-bin is not valid base64");
            } else {
                Protobuf.Parsed p = Protobuf.parse(d);
                DecodedNode det = new DecodedNode("details", "google.rpc.Status (1=code, 2=message, 3=details Any)", DecodedNode.Type.OBJECT);
                Protobuf.render(p.fields, det);
                if (!p.complete()) c.warnings.add("grpc-status-details-bin: " + p.error);
                n.add(det);
            }
        }
        return n;
    }

    private static String summary(MessageContext m, Proto proto, Ctx c) {
        Call call = proto.rpc() && !m.isWebSocket() ? call(m.path()) : null;
        String target = call != null ? call.target() : (m.isWebSocket() ? "" : m.path());
        String counts = c.messages == 0 ? "no messages"
                : c.messages == 1 ? "1 message" + (c.firstFields >= 0 ? ", " + c.firstFields + Protobuf.plural(c.firstFields, " field") : "")
                : c.messages + " messages";
        if (m.isWebSocket()) return proto.label + " message (" + counts + ")";
        if (!m.isResponse()) return proto.label + " → " + target + " (" + counts + ")";
        Status s = c.status;
        if (s != null && s.code() != 0) {
            String msg = s.message() == null || s.message().isEmpty() ? "" : " — " + Codecs.truncate(s.message(), 200);
            return proto.label + " response: status " + s.code() + " " + GrpcFrames.statusName(s.code()) + msg;
        }
        return proto.label + " response ← " + target + (s != null ? ": status 0 OK" : "") + " (" + counts + ")";
    }

    private static boolean looksJson(byte[] b) {
        for (byte x : b) {
            if (x == ' ' || x == '\n' || x == '\r' || x == '\t') continue;
            return x == '{' || x == '[';
        }
        return false;
    }
}
