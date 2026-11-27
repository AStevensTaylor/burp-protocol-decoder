package protocoldecoder.builtin.socketio;

import com.google.gson.JsonElement;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Engine.IO (v3 and v4) packet and polling-payload parsing. Stateless; every method is bounds-checked and reports
 * problems through {@link Packet#error()} or {@link Payload#warnings()} instead of throwing.
 */
final class EngineIo {

    static final String[] TYPES = {"open", "close", "ping", "pong", "message", "upgrade", "noop"};
    static final int OPEN = 0, MESSAGE = 4;
    /** Upper bound on packets taken from one polling payload. */
    static final int MAX_PACKETS = 2000;
    static final char RECORD_SEPARATOR = '\u001e';

    private EngineIo() {
    }

    /**
     * One Engine.IO packet. {@code type} is 0..6 or -1 when invalid; {@code text} holds the data of a text packet,
     * {@code binary} the data of a binary one.
     */
    record Packet(int type, String text, byte[] binary, String error) {
        static Packet invalid(String why, String raw) {
            return new Packet(-1, raw, null, why);
        }

        boolean valid() {
            return type >= 0;
        }

        boolean isBinary() {
            return binary != null;
        }

        String typeName() {
            return type >= 0 && type < TYPES.length ? TYPES[type] : "invalid";
        }
    }

    /** A polling payload split into packets. */
    record Payload(List<Packet> packets, String framing, List<String> warnings) {
    }

    /** Parses one text-encoded packet (a WebSocket text frame or one packet of a polling payload). */
    static Packet parseText(String s, int eio) {
        if (s == null || s.isEmpty()) return Packet.invalid("empty packet", "");
        char c = s.charAt(0);
        if (c == 'b') {
            // v4: "b<base64>" is always a message; v3: "b<type><base64>".
            String rest = s.substring(1);
            int type = MESSAGE;
            if (eio == 3 && !rest.isEmpty() && rest.charAt(0) >= '0' && rest.charAt(0) <= '6') {
                type = rest.charAt(0) - '0';
                rest = rest.substring(1);
            }
            byte[] b = Codecs.base64Decode(rest);
            if (b == null) return Packet.invalid("binary packet ('b' prefix) is not valid base64", s);
            return new Packet(type, null, b, null);
        }
        if (c < '0' || c > '6') return Packet.invalid("unknown packet type '" + printable(c) + "'", s);
        return new Packet(c - '0', s.substring(1), null, null);
    }

    /** Parses a binary WebSocket frame: raw message data in v4; type byte + data in v3. */
    static Packet parseBinaryFrame(byte[] b, int eio) {
        if (eio == 3 && b.length > 0 && b[0] >= 0 && b[0] <= 6) {
            byte[] data = new byte[b.length - 1];
            System.arraycopy(b, 1, data, 0, data.length);
            return new Packet(b[0], null, data, null);
        }
        return new Packet(MESSAGE, null, b, null);
    }

    /**
     * Splits a polling body into packets. {@code eio} is 3, 4 or 0 (unknown: sniff the framing).
     */
    static Payload parsePolling(byte[] body, int eio) {
        List<String> warnings = new ArrayList<>();
        if (body.length > 0 && (body[0] == 0 || body[0] == 1) && eio != 4) {
            Payload p = parseV3Binary(body, warnings);
            if (p != null) return p;
        }
        String text = new String(body, StandardCharsets.UTF_8);
        String jsonp = unwrapJsonp(text);
        if (jsonp != null) {
            text = jsonp;
            warnings.add("JSONP polling response (___eio callback) unwrapped");
        }
        if (eio == 4) return splitV4(text, warnings);
        if (eio == 3) {
            Payload p = splitV3(text, warnings);
            if (p != null) return p;
            warnings.add("EIO=3 but the body does not use <length>:<packet> framing; decoded as a single packet");
            return single(text, 3, warnings);
        }
        if (text.indexOf(RECORD_SEPARATOR) >= 0) return splitV4(text, warnings);
        if (startsWithLengthPrefix(text)) {
            Payload p = splitV3(text, new ArrayList<>(warnings));
            if (p != null) return p;
        }
        return single(text, 4, warnings);
    }

    private static Payload single(String text, int eio, List<String> warnings) {
        List<Packet> list = new ArrayList<>();
        list.add(parseText(text, eio));
        return new Payload(list, "single packet", warnings);
    }

    private static Payload splitV4(String text, List<String> warnings) {
        List<Packet> list = new ArrayList<>();
        int start = 0;
        while (start <= text.length()) {
            int end = text.indexOf(RECORD_SEPARATOR, start);
            if (end < 0) end = text.length();
            if (end == start && end == text.length() && !list.isEmpty()) break; // trailing separator
            if (list.size() >= MAX_PACKETS) {
                warnings.add("Stopped after " + MAX_PACKETS + " packets");
                break;
            }
            list.add(parseText(text.substring(start, end), 4));
            start = end + 1;
        }
        return new Payload(list, list.size() > 1 ? "v4 (record-separator \\x1e delimited)" : "v4 (single packet)", warnings);
    }

    static boolean startsWithLengthPrefix(String text) {
        int i = 0;
        while (i < text.length() && i < 11 && Character.isDigit(text.charAt(i))) i++;
        return i > 0 && i < text.length() && text.charAt(i) == ':';
    }

    /** v3 text framing: {@code <length>:<packet>} repeated; lengths count UTF-16 code units. Null if not framed. */
    private static Payload splitV3(String text, List<String> warnings) {
        List<Packet> list = new ArrayList<>();
        int i = 0;
        while (i < text.length()) {
            int colon = i;
            while (colon < text.length() && colon - i < 11 && Character.isDigit(text.charAt(colon))) colon++;
            if (colon == i || colon >= text.length() || text.charAt(colon) != ':') {
                if (list.isEmpty()) return null;
                warnings.add("Invalid v3 length prefix at offset " + i + "; remainder ignored");
                list.add(Packet.invalid("invalid length prefix", Codecs.truncate(text.substring(i), 200)));
                break;
            }
            long n = Long.parseLong(text.substring(i, colon));
            int start = colon + 1;
            if (start + n > text.length()) {
                warnings.add("v3 packet at offset " + i + " claims " + n + " chars but only " + (text.length() - start) + " remain");
                list.add(parseText(text.substring(start), 3));
                break;
            }
            if (list.size() >= MAX_PACKETS) {
                warnings.add("Stopped after " + MAX_PACKETS + " packets");
                break;
            }
            list.add(parseText(text.substring(start, start + (int) n), 3));
            i = start + (int) n;
        }
        if (list.isEmpty()) return null;
        return new Payload(list, "v3 (<length>:<packet> framing)", warnings);
    }

    /**
     * v3 binary (XHR2) payload: per packet a 0 (string) / 1 (binary) marker, the length as one byte per decimal
     * digit, 0xFF, then the packet bytes. Null if the body does not follow that layout.
     */
    private static Payload parseV3Binary(byte[] b, List<String> warnings) {
        List<Packet> list = new ArrayList<>();
        int i = 0;
        while (i < b.length) {
            int kind = b[i];
            if (kind != 0 && kind != 1) return list.isEmpty() ? null : withWarning(list, warnings, "Invalid binary framing at offset " + i);
            int j = i + 1;
            long len = 0;
            while (j < b.length && (b[j] & 0xff) != 0xff) {
                int d = b[j];
                if (d < 0 || d > 9 || j - i > 11) return list.isEmpty() ? null : withWarning(list, warnings, "Invalid binary length at offset " + i);
                len = len * 10 + d;
                j++;
            }
            if (j >= b.length || j == i + 1) return list.isEmpty() ? null : withWarning(list, warnings, "Truncated binary framing at offset " + i);
            int start = j + 1;
            if (start + len > b.length) return list.isEmpty() ? null : withWarning(list, warnings, "Binary packet at offset " + i + " runs past the end");
            byte[] data = new byte[(int) len];
            System.arraycopy(b, start, data, 0, data.length);
            if (list.size() >= MAX_PACKETS) {
                warnings.add("Stopped after " + MAX_PACKETS + " packets");
                break;
            }
            list.add(kind == 0 ? parseText(new String(data, StandardCharsets.UTF_8), 3) : parseBinaryFrame(data, 3));
            i = start + (int) len;
        }
        if (list.isEmpty()) return null;
        return new Payload(list, "v3 binary (XHR2) framing", warnings);
    }

    private static Payload withWarning(List<Packet> list, List<String> warnings, String w) {
        warnings.add(w + "; remainder ignored");
        return new Payload(list, "v3 binary (XHR2) framing", warnings);
    }

    /** {@code ___eio[0]("...");} → the string literal's content, or null. */
    static String unwrapJsonp(String text) {
        String t = text.strip();
        if (!t.startsWith("___eio[")) return null;
        int open = t.indexOf("(\"");
        int close = t.lastIndexOf("\")");
        if (open < 0 || close <= open) return null;
        JsonElement e = JsonTree.parseStrict(t.substring(open + 1, close + 1));
        return e != null && e.isJsonPrimitive() ? e.getAsString() : null;
    }

    private static String printable(char c) {
        return c >= 0x20 && c < 0x7f ? String.valueOf(c) : String.format("\\u%04x", (int) c);
    }
}
