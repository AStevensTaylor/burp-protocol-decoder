package protocoldecoder.builtin.grpc;

import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.edit.EditableDocument;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.edit.MessageCodec;
import protocoldecoder.edit.MessagePatch;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.EditJson;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.function.Function;

/**
 * Documents for gRPC / gRPC-Web / Connect / raw protobuf messages (requests, responses, and framed WebSocket
 * payloads): one {@link ProtoText} document per protobuf message, re-framed on encode (5-byte header, per-message
 * compression, grpc-web-text base64, Content-Encoding, Connect GET {@code message=}). gRPC-Web trailer frames get a
 * "name: value" text document. JSON-encoded messages (Connect JSON, +json) are not offered.
 */
public final class GrpcCodec implements MessageCodec {

    @Override
    public String decoderId() {
        return GrpcDecoder.ID;
    }

    @Override
    public List<EditableDocument> documents(MessageContext m, DecodeResult decoded) {
        List<EditableDocument> out = new ArrayList<>();
        try {
            collect(m, out);
        } catch (RuntimeException e) {
            return List.of();
        }
        return out.size() > EditJson.MAX_DOCUMENTS ? out.subList(0, EditJson.MAX_DOCUMENTS) : out;
    }

    private static void collect(MessageContext m, List<EditableDocument> out) {
        GrpcDecoder.Detection d = m.isWebSocket() ? null : GrpcDecoder.detect(m);
        if (d != null && d.json()) return;
        if (d != null && d.proto() == GrpcDecoder.Proto.CONNECT_JSON) return;
        if (d != null && d.proto() == GrpcDecoder.Proto.CONNECT_GET) {
            if (m.isRequest()) connectGet(m, out);
            return;
        }
        byte[] raw = m.body();
        if (raw.length == 0) return;
        String ce = m.isWebSocket() ? null : m.header("Content-Encoding");
        if (!EditJson.reEncodable(raw, ce)) return;
        byte[] body = EditJson.hasEncoding(ce) ? Codecs.decodeContent(raw, ce) : raw;
        Function<byte[], MessagePatch> bodyPatch = newBody -> {
            try {
                return MessagePatch.body(EditJson.reEncode(newBody, body, raw, ce));
            } catch (EncodeException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
        };
        GrpcDecoder.Proto proto = d == null ? (GrpcFrames.looksFramed(body) ? GrpcDecoder.Proto.GRPC : GrpcDecoder.Proto.PROTOBUF) : d.proto();
        switch (proto) {
            case GRPC, GRPC_WEB, CONNECT_STREAM -> framed(m, proto, body, null, bodyPatch, out);
            case GRPC_WEB_TEXT -> {
                byte[] bin = GrpcFrames.decodeBase64Chunks(new String(body, StandardCharsets.ISO_8859_1));
                if (bin != null) framed(m, proto, bin, body, bodyPatch, out);
            }
            case CONNECT_UNARY, PROTOBUF -> {
                if (looksJson(body)) return;
                EditableDocument doc = messageDoc("Protobuf message", body, newMsg -> bodyPatch.apply(newMsg));
                if (doc != null) out.add(doc);
            }
            default -> {
            }
        }
    }

    // ------------------------------------------------------------------ framed bodies

    /**
     * @param textBody the grpc-web-text body (base64) when {@code bin} was decoded from it, else null
     */
    private static void framed(MessageContext m, GrpcDecoder.Proto proto, byte[] bin, byte[] textBody,
                               Function<byte[], MessagePatch> bodyPatch, List<EditableDocument> out) {
        GrpcFrames.Frames fr = GrpcFrames.parse(bin);
        if (fr.frames().isEmpty()) return;
        boolean connect = proto == GrpcDecoder.Proto.CONNECT_STREAM;
        String encoding = m.isWebSocket() ? null : m.header(connect ? "Connect-Content-Encoding" : "grpc-encoding");
        Function<byte[], MessagePatch> binPatch = newBin -> {
            if (textBody == null) return bodyPatch.apply(newBin);
            if (Arrays.equals(newBin, bin)) return bodyPatch.apply(textBody);
            return bodyPatch.apply(Base64.getEncoder().encode(newBin));
        };
        int dataFrames = 0;
        for (GrpcFrames.Frame f : fr.frames()) if (isData(f, connect)) dataFrames++;
        int n = 0;
        for (GrpcFrames.Frame f : fr.frames()) {
            if (out.size() >= EditJson.MAX_DOCUMENTS) break;
            if (f.truncated()) continue;
            int start = f.offset();
            int end = f.offset() + 5 + (int) f.declaredLength();
            if (!connect && (f.flags() & GrpcFrames.FLAG_TRAILER) != 0) {
                if (!f.compressed()) {
                    out.add(trailerDoc(f, newPayload -> binPatch.apply(splice(bin, start, end,
                            Arrays.equals(newPayload, f.payload()) ? Arrays.copyOfRange(bin, start, end) : frame(f.flags(), newPayload)))));
                }
                continue;
            }
            if (!isData(f, connect)) continue;
            n++;
            byte[] payload = f.payload();
            Function<byte[], byte[]> compress = b -> b;
            if (f.compressed()) {
                try {
                    payload = GrpcFrames.decompress(payload, encoding);
                } catch (IOException e) {
                    continue;
                }
                compress = GrpcScanner.messageCompressor(encoding, f.payload());
                if (compress == null) continue;
            }
            final byte[] plain = payload;
            final Function<byte[], byte[]> comp = compress;
            String title = dataFrames > 1 ? "Protobuf message " + n : "Protobuf message";
            if (f.compressed()) title += " (" + (encoding == null || encoding.isBlank() ? "compressed" : encoding.trim()) + ")";
            EditableDocument doc = messageDoc(title, plain, newMsg -> {
                byte[] newFrame = Arrays.equals(newMsg, plain)
                        ? Arrays.copyOfRange(bin, start, end)
                        : frame(f.flags(), comp.apply(newMsg));
                return binPatch.apply(splice(bin, start, end, newFrame));
            });
            if (doc != null) out.add(doc);
        }
    }

    private static boolean isData(GrpcFrames.Frame f, boolean connect) {
        if (!connect && (f.flags() & GrpcFrames.FLAG_TRAILER) != 0) return false;
        return !(connect && (f.flags() & GrpcFrames.FLAG_CONNECT_END) != 0);
    }

    static byte[] frame(int flags, byte[] p) {
        byte[] frame = new byte[5 + p.length];
        frame[0] = (byte) flags;
        frame[1] = (byte) (p.length >>> 24);
        frame[2] = (byte) (p.length >>> 16);
        frame[3] = (byte) (p.length >>> 8);
        frame[4] = (byte) p.length;
        System.arraycopy(p, 0, frame, 5, p.length);
        return frame;
    }

    private static byte[] splice(byte[] src, int start, int end, byte[] with) {
        return ProtoEdit.concat(Arrays.copyOfRange(src, 0, start), with, Arrays.copyOfRange(src, end, src.length));
    }

    // ------------------------------------------------------------------ documents

    private interface MessageEncoder {
        MessagePatch apply(byte[] newMessage);
    }

    /** A protobuf-text document for one message; null when the message is not complete protobuf or too large. */
    static EditableDocument messageDoc(String title, byte[] msg, MessageEncoder enc) {
        String printed = ProtoText.print(msg);
        if (printed == null) return null;
        String text = ProtoText.HEADER + printed;
        if (text.length() > EditJson.MAX_DOCUMENT_CHARS) return null;
        byte[] canonical;
        try {
            canonical = ProtoText.parse(text);
        } catch (EncodeException e) {
            return null;
        }
        if (!Arrays.equals(canonical, msg)) {
            // Non-canonical varints in the original: unchanged text still maps back to the original bytes.
            text = "# note: the original uses non-canonical varint encodings; edited messages are re-encoded canonically\n" + text;
        }
        return new EditJson.Doc(title, "protobuf-text", text, edited -> {
            byte[] newMsg = ProtoText.parse(edited);
            if (Arrays.equals(newMsg, canonical)) newMsg = msg;
            return call(enc, newMsg);
        });
    }

    private static MessagePatch call(MessageEncoder enc, byte[] b) throws EncodeException {
        try {
            return enc.apply(b);
        } catch (IllegalStateException e) {
            throw new EncodeException(e.getMessage(), e);
        }
    }

    /** gRPC-Web trailers frame: "name: value" lines, written back with the frame's original line separator. */
    private static EditableDocument trailerDoc(GrpcFrames.Frame f, MessageEncoder enc) {
        String original = new String(f.payload(), StandardCharsets.ISO_8859_1);
        String sep = original.contains("\r\n") ? "\r\n" : "\n";
        String text = original.replace("\r\n", "\n");
        return new EditJson.Doc("gRPC-Web trailers", "text", text, edited -> {
            if (edited.equals(text)) return call(enc, f.payload());
            StringBuilder sb = new StringBuilder();
            String[] lines = edited.replace("\r\n", "\n").split("\n", -1);
            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                if (!line.isEmpty()) {
                    int c = line.indexOf(':');
                    if (c <= 0) throw new EncodeException("Trailer line " + (i + 1) + " is not 'name: value'");
                    for (int k = 0; k < line.length(); k++) {
                        if (line.charAt(k) > 0xff) throw new EncodeException("Trailer line " + (i + 1) + " contains a non-Latin-1 character; percent-encode it");
                    }
                }
                sb.append(line);
                if (i < lines.length - 1) sb.append(sep);
            }
            return call(enc, sb.toString().getBytes(StandardCharsets.ISO_8859_1));
        });
    }

    // ------------------------------------------------------------------ Connect GET

    private static void connectGet(MessageContext m, List<EditableDocument> out) {
        String q = m.query();
        String[] pairs = q.split("&", -1);
        int idx = -1;
        boolean b64 = false, json = false;
        String compression = null;
        for (int i = 0; i < pairs.length; i++) {
            String p = pairs[i];
            int eq = p.indexOf('=');
            String k = GrpcFrames.percentDecode(eq < 0 ? p : p.substring(0, eq));
            String v = eq < 0 ? "" : p.substring(eq + 1);
            switch (k) {
                case "message" -> { if (idx < 0 && eq >= 0) idx = i; }
                case "base64" -> b64 = "1".equals(v);
                case "compression" -> compression = GrpcFrames.percentDecode(v);
                case "encoding" -> json = "json".equalsIgnoreCase(GrpcFrames.percentDecode(v));
                default -> { }
            }
        }
        if (idx < 0 || json) return;
        String rawValue = pairs[idx].substring(pairs[idx].indexOf('=') + 1);
        String b64Text = b64 ? GrpcFrames.percentDecode(rawValue) : null;
        byte[] wire = b64 ? Codecs.base64Decode(b64Text) : GrpcFrames.percentDecodeBytes(rawValue);
        if (wire == null) return;
        byte[] msg = wire;
        Function<byte[], byte[]> compress = b -> b;
        if (compression != null && !compression.isEmpty() && !compression.equalsIgnoreCase("identity")) {
            try {
                msg = GrpcFrames.decompress(wire, compression);
            } catch (IOException e) {
                return;
            }
            compress = GrpcScanner.messageCompressor(compression, wire);
            if (compress == null) return;
        }
        boolean urlSafe = b64 && (b64Text.indexOf('-') >= 0 || b64Text.indexOf('_') >= 0 || (b64Text.indexOf('+') < 0 && b64Text.indexOf('/') < 0));
        boolean padded = b64 && b64Text.endsWith("=");
        final byte[] plain = msg;
        final Function<byte[], byte[]> comp = compress;
        final int at = idx;
        final boolean base64 = b64;
        EditableDocument doc = messageDoc("Protobuf message (Connect GET)", plain, newMsg -> {
            if (Arrays.equals(newMsg, plain)) return MessagePatch.query(q);
            byte[] c = comp.apply(newMsg);
            String value;
            if (base64) {
                Base64.Encoder e = urlSafe ? Base64.getUrlEncoder() : Base64.getEncoder();
                if (!padded) e = e.withoutPadding();
                value = e.encodeToString(c);
                if (!urlSafe) value = value.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D");
                else value = value.replace("=", "%3D");
            } else {
                value = GrpcScanner.percentEncode(c);
            }
            String[] copy = pairs.clone();
            String p = copy[at];
            copy[at] = p.substring(0, p.indexOf('=') + 1) + value;
            return MessagePatch.query(String.join("&", copy));
        });
        if (doc != null) out.add(doc);
    }

    private static boolean looksJson(byte[] b) {
        for (byte x : b) {
            if (x == ' ' || x == '\n' || x == '\r' || x == '\t') continue;
            return x == '{' || x == '[';
        }
        return false;
    }
}
