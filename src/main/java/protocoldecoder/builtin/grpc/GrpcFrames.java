package protocoldecoder.builtin.grpc;

import protocoldecoder.util.Codecs;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Length-prefixed message framing shared by gRPC, gRPC-Web and Connect streaming (1 flag byte + 4-byte big-endian
 * length + payload), plus the small text formats around it: trailer blocks, percent-encoded grpc-message, status
 * names, and the concatenated base64 chunks of grpc-web-text.
 */
final class GrpcFrames {

    static final int FLAG_COMPRESSED = 0x01;
    static final int FLAG_CONNECT_END = 0x02;
    static final int FLAG_TRAILER = 0x80;
    static final int MAX_FRAMES = 10_000;

    static final String[] STATUS_NAMES = {
            "OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED", "NOT_FOUND", "ALREADY_EXISTS",
            "PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION", "ABORTED", "OUT_OF_RANGE",
            "UNIMPLEMENTED", "INTERNAL", "UNAVAILABLE", "DATA_LOSS", "UNAUTHENTICATED"};

    /** One frame. {@code truncated} is set when the declared length runs past the end of the body. */
    record Frame(int index, int offset, int flags, long declaredLength, byte[] payload, boolean truncated) {
        boolean compressed() { return (flags & FLAG_COMPRESSED) != 0; }
    }

    /** Frames parsed from a body; {@code error} describes trailing bytes that do not form a frame. */
    record Frames(List<Frame> frames, String error) {
    }

    private GrpcFrames() {
    }

    static Frames parse(byte[] b) {
        List<Frame> out = new ArrayList<>();
        int pos = 0;
        String error = null;
        while (pos < b.length) {
            if (out.size() >= MAX_FRAMES) {
                error = "frame limit (" + MAX_FRAMES + ") reached; " + (b.length - pos) + " bytes not shown";
                break;
            }
            int remaining = b.length - pos;
            if (remaining < 5) {
                error = remaining + " trailing byte(s) at offset " + pos + " do not form a frame header";
                break;
            }
            int flags = b[pos] & 0xff;
            long len = ((b[pos + 1] & 0xffL) << 24) | ((b[pos + 2] & 0xffL) << 16) | ((b[pos + 3] & 0xffL) << 8) | (b[pos + 4] & 0xffL);
            int avail = remaining - 5;
            if (len > avail) {
                byte[] partial = new byte[avail];
                System.arraycopy(b, pos + 5, partial, 0, avail);
                out.add(new Frame(out.size(), pos, flags, len, partial, true));
                error = "frame " + (out.size()) + " at offset " + pos + " declares " + len + " bytes but only " + avail + " remain";
                break;
            }
            byte[] payload = new byte[(int) len];
            System.arraycopy(b, pos + 5, payload, 0, (int) len);
            out.add(new Frame(out.size(), pos, flags, len, payload, false));
            pos += 5 + (int) len;
        }
        return new Frames(out, error);
    }

    /**
     * True if the bytes are exactly a sequence of complete frames with known flag values — a strong sign of gRPC
     * framing in a body whose content type says nothing.
     */
    static boolean looksFramed(byte[] b) {
        if (b == null || b.length < 5) return false;
        int pos = 0, n = 0;
        while (pos < b.length) {
            if (b.length - pos < 5 || ++n > MAX_FRAMES) return false;
            int flags = b[pos] & 0xff;
            if ((flags & ~(FLAG_COMPRESSED | FLAG_CONNECT_END | FLAG_TRAILER)) != 0) return false;
            long len = ((b[pos + 1] & 0xffL) << 24) | ((b[pos + 2] & 0xffL) << 16) | ((b[pos + 3] & 0xffL) << 8) | (b[pos + 4] & 0xffL);
            if (len > b.length - pos - 5) return false;
            pos += 5 + (int) len;
        }
        return true;
    }

    /** Parses an HTTP/1-style header block ("name: value" lines) as used by gRPC-Web trailer frames. */
    static Map<String, String> parseTrailers(byte[] payload) {
        Map<String, String> out = new LinkedHashMap<>();
        String text = new String(payload, StandardCharsets.UTF_8);
        for (String line : text.split("\r?\n")) {
            if (line.isBlank()) continue;
            int c = line.indexOf(':');
            String name = (c < 0 ? line : line.substring(0, c)).trim().toLowerCase(Locale.ROOT);
            String value = c < 0 ? "" : line.substring(c + 1).trim();
            out.merge(name, value, (a, x) -> a + ", " + x);
            if (out.size() > 1000) break;
        }
        return out;
    }

    static String statusName(int code) {
        return code >= 0 && code < STATUS_NAMES.length ? STATUS_NAMES[code] : "UNKNOWN_CODE";
    }

    /** Maps a Connect error code ("unauthenticated") to its gRPC number, or -1. */
    static int codeFromConnectName(String name) {
        if (name == null) return -1;
        String up = name.trim().toUpperCase(Locale.ROOT);
        if (up.equals("CANCELED")) return 1; // Connect spells it the American way
        for (int i = 0; i < STATUS_NAMES.length; i++) if (STATUS_NAMES[i].equals(up)) return i;
        return -1;
    }

    /** gRPC percent-decoding (no '+' → space), lenient about malformed escapes. */
    static String percentDecode(String s) {
        if (s == null || s.indexOf('%') < 0) return s;
        return new String(percentDecodeBytes(s), StandardCharsets.UTF_8);
    }

    static byte[] percentDecodeBytes(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%' && i + 2 < s.length() && hex(s.charAt(i + 1)) >= 0 && hex(s.charAt(i + 2)) >= 0) {
                out.write(hex(s.charAt(i + 1)) * 16 + hex(s.charAt(i + 2)));
                i += 2;
            } else {
                byte[] b = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
                out.write(b, 0, b.length);
            }
        }
        return out.toByteArray();
    }

    private static int hex(char c) {
        return Character.digit(c, 16);
    }

    /**
     * Decodes grpc-web-text: base64 where each chunk the server flushed may carry its own padding, so the body can be
     * several base64 strings back to back. Returns null if it is not base64.
     */
    static byte[] decodeBase64Chunks(String s) {
        String t = s.replaceAll("\\s+", "");
        if (t.isEmpty()) return new byte[0];
        ByteArrayOutputStream out = new ByteArrayOutputStream(t.length() * 3 / 4 + 4);
        int i = 0;
        while (i < t.length()) {
            int eq = t.indexOf('=', i);
            int end = eq < 0 ? t.length() : eq;
            while (end < t.length() && t.charAt(end) == '=') end++;
            String chunk = t.substring(i, end);
            for (int k = 0; k < chunk.length(); k++) {
                char c = chunk.charAt(k);
                boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                        || c == '+' || c == '/' || c == '-' || c == '_' || c == '=';
                if (!ok) return null;
            }
            byte[] d = Codecs.base64Decode(chunk);
            if (d == null) return null;
            out.writeBytes(d);
            i = end;
        }
        return out.toByteArray();
    }

    /** Undoes per-message compression. {@code encoding} is the grpc-encoding / connect-content-encoding value. */
    static byte[] decompress(byte[] payload, String encoding) throws IOException {
        String enc = encoding == null ? "" : encoding.trim().toLowerCase(Locale.ROOT);
        if (enc.equals("gzip") || (enc.isEmpty() || enc.equals("identity")) && Codecs.isGzip(payload)) return Codecs.gunzip(payload);
        if (enc.equals("deflate") || (enc.isEmpty() && Codecs.isZlib(payload))) return Codecs.inflate(payload);
        if (enc.isEmpty() || enc.equals("identity")) throw new IOException("message is flagged compressed but no grpc-encoding is declared");
        throw new IOException("unsupported message encoding '" + enc + "'");
    }
}
