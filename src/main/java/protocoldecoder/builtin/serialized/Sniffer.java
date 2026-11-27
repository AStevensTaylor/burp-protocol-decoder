package protocoldecoder.builtin.serialized;

import protocoldecoder.util.Codecs;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.zip.GZIPInputStream;

/**
 * Recognises serialized data in one value by magic bytes and prefixes, undoing base64 / hex / gzip / percent
 * encoding. In "sniff" mode (used by match) only a prefix of the value is decoded; in "full" mode the whole payload
 * is decoded (bounded) for the parsers.
 */
final class Sniffer {

    enum Format {
        JAVA("Java serialized object"),
        NRBF(".NET BinaryFormatter object"),
        VIEWSTATE("ASP.NET ViewState (ObjectStateFormatter)"),
        PHP("PHP serialized data"),
        PICKLE("Python pickle"),
        RUBY("Ruby Marshal data"),
        JSON_NET("Json.NET $type hints"),
        XML_HINT("XML serializer type hints"),
        /** Internal: gzip container, never reported. */
        GZIP("gzip");

        final String label;

        Format(String label) {
            this.label = label;
        }
    }

    /** Where a value came from; drives confidence. */
    enum Origin { BODY, PARAM, COOKIE, HEADER, EMBEDDED }

    /**
     * A recognised payload.
     *
     * @param payload decoded bytes (full mode; a prefix in sniff mode), null for text-only hints
     * @param text    the text for JSON/XML hints (full mode)
     * @param note    remark about the unwrapping (e.g. truncated gzip), or null
     */
    record Detection(Format format, String encoding, int confidence, byte[] payload, String text, String note) {
    }

    /** Cap on decompressed / decoded payload size handed to the parsers. */
    static final int MAX_PAYLOAD = 8 * 1024 * 1024;
    private static final int SNIFF_TEXT = 64 * 1024;
    private static final int SNIFF_B64_CHARS = 24;
    private static final int SNIFF_GZIP_B64_CHARS = 4096;
    private static final int SNIFF_GZIP_OUT = 64;

    private Sniffer() {
    }

    // ------------------------------------------------------------------ magic bytes

    /** Format identified by the leading bytes (which may be only a prefix of the payload), or null. */
    static Format magic(byte[] b) {
        if (b == null) return null;
        int n = b.length;
        if (n >= 4 && (b[0] & 0xff) == 0xAC && (b[1] & 0xff) == 0xED && b[2] == 0 && b[3] == 5) return Format.JAVA;
        if (NrbfParser.isHeader(b, 0)) return Format.NRBF;
        if (n >= 3 && (b[0] & 0xff) == 0x1f && (b[1] & 0xff) == 0x8b && b[2] == 8) return Format.GZIP;
        if (n >= 3 && (b[0] & 0xff) == 0x80 && b[1] >= 2 && b[1] <= 5 && PickleParser.isOpcode(b[2] & 0xff)) return Format.PICKLE;
        if (n >= 3 && b[0] == 4 && b[1] == 8 && RubyMarshalParser.isTypeByte(b[2] & 0xff)) return Format.RUBY;
        if (n >= 3 && (b[0] & 0xff) == 0xFF && b[1] == 1) return Format.VIEWSTATE;
        if (n >= 4 && phpStrength(new String(b, 0, Math.min(n, 32), StandardCharsets.ISO_8859_1)) > 0) return Format.PHP;
        return null;
    }

    /** 2 = array/object/enum, 1 = string scalar, 0 = not PHP serialize() output. */
    static int phpStrength(String s) {
        if (s.length() < 4) return 0;
        if (PhpParser.STRONG_START.matcher(s).lookingAt()) return 2;
        if (PhpParser.STRING_START.matcher(s).lookingAt() && s.stripTrailing().endsWith("\";")) return 1;
        return 0;
    }

    // ------------------------------------------------------------------ raw bytes (bodies)

    static Detection inspectBytes(byte[] body, Origin origin, String name, boolean full) {
        if (body == null || body.length < 3) return null;
        Format f = magic(Arrays.copyOf(body, Math.min(body.length, 32)));
        if (f == Format.GZIP) {
            Unzipped u = full ? gunzip(body, MAX_PAYLOAD) : gunzip(body, SNIFF_GZIP_OUT);
            if (u == null) return null;
            Format inner = magic(u.data);
            if (inner == null || inner == Format.GZIP) {
                // gzip of a base64/text value
                if (!full && u.data.length > 0) u = gunzip(body, 4096);
                if (u == null || !Codecs.isMostlyText(u.data)) return null;
                Detection d = inspect(new String(u.data, StandardCharsets.UTF_8), origin, name, full);
                return d == null ? null : new Detection(d.format, "gzip → " + d.encoding, d.confidence, d.payload, d.text, join(u.note, d.note));
            }
            return detection(inner, "gzip", confidence(inner, origin, name, true, u.data), u.data, u.note);
        }
        if (f != null) {
            if (f == Format.PHP && !Codecs.isMostlyText(Arrays.copyOf(body, Math.min(body.length, 512)))) return null;
            return detection(f, "raw", confidence(f, origin, name, false, body), body, null);
        }
        if (!Codecs.isMostlyText(body)) return null;
        int n = full ? body.length : Math.min(body.length, SNIFF_TEXT);
        return inspect(new String(body, 0, n, StandardCharsets.UTF_8), origin, name, full);
    }

    // ------------------------------------------------------------------ text values

    static Detection inspect(String value, Origin origin, String name, boolean full) {
        if (value == null) return null;
        String s = value.strip();
        if (s.length() >= 2 && s.charAt(0) == '"' && s.charAt(s.length() - 1) == '"') s = s.substring(1, s.length() - 1).strip();
        if (s.length() < 4) return null;
        if ((origin == Origin.COOKIE || origin == Origin.HEADER || origin == Origin.EMBEDDED) && s.indexOf('%') >= 0) {
            s = percentDecodeKeepPlus(s);
        }
        String head = full ? s : s.substring(0, Math.min(s.length(), SNIFF_TEXT));

        int php = phpStrength(head);
        if (php > 0) {
            byte[] bytes = full ? s.getBytes(StandardCharsets.UTF_8) : null;
            return new Detection(Format.PHP, "text", php == 2 ? (origin == Origin.HEADER ? 75 : 80) : 50, bytes, null, null);
        }
        if (origin != Origin.EMBEDDED && TypeHints.hasJsonType(head)) {
            return new Detection(Format.JSON_NET, "JSON", 40, null, full ? s : null, null);
        }
        int xml = origin == Origin.EMBEDDED ? 0 : TypeHints.xmlConfidence(head);
        if (xml > 0) return new Detection(Format.XML_HINT, "XML", xml, null, full ? s : null, null);

        Detection d = hex(s, origin, name, full);
        if (d != null) return d;
        d = base64(s, origin, name, full);
        if (d != null || origin == Origin.BODY) return d;
        return signedToken(s, origin, name);
    }

    /**
     * Django {@code signing} ({@code [.]payload:timestamp:signature}) and itsdangerous ({@code [.]payload.timestamp.signature})
     * tokens: URL-safe base64 payload, zlib-compressed when the token starts with '.'.
     */
    static final java.util.regex.Pattern SIGNED_TOKEN = java.util.regex.Pattern.compile(
            "(\\.?)([A-Za-z0-9_-]{8,})([.:])[A-Za-z0-9_-]{4,}(?:\\3[A-Za-z0-9_-]{16,})?");

    private static Detection signedToken(String s, Origin origin, String name) {
        if (s.length() > MAX_PAYLOAD) return null;
        java.util.regex.Matcher m = SIGNED_TOKEN.matcher(s);
        if (!m.matches()) return null;
        byte[] data = Codecs.base64Decode(m.group(2));
        if (data == null) return null;
        String encoding = "base64";
        if (!m.group(1).isEmpty()) {
            try {
                data = Codecs.inflate(data);
            } catch (IOException | RuntimeException e) {
                return null;
            }
            encoding = "base64 → zlib";
        }
        Format f = magic(Arrays.copyOf(data, Math.min(data.length, 32)));
        if (f == null || f == Format.GZIP || f == Format.VIEWSTATE) return null;
        return detection(f, encoding + " (signed value)", confidence(f, origin, name, true, null), data, null);
    }

    private static Detection hex(String s, Origin origin, String name, boolean full) {
        int run = 0;
        while (run < s.length() && Character.digit(s.charAt(run), 16) >= 0) run++;
        if (run < 8) return null;
        if (run != s.length() && origin != Origin.BODY) return null;
        run &= ~1;
        byte[] prefix = hexDecode(s, Math.min(run, 64));
        Format f = magic(prefix);
        if (f == null) return null;
        if (f == Format.GZIP) {
            byte[] gz = hexDecode(s, full ? Math.min(run, MAX_PAYLOAD * 2) : Math.min(run, SNIFF_GZIP_B64_CHARS));
            Unzipped u = gunzip(gz, full ? MAX_PAYLOAD : SNIFF_GZIP_OUT);
            Format inner = u == null ? null : magic(u.data);
            if (inner == null || inner == Format.GZIP) return null;
            return detection(inner, "hex → gzip", confidence(inner, origin, name, true, null), u.data, u.note);
        }
        byte[] data = full ? hexDecode(s, Math.min(run, MAX_PAYLOAD * 2)) : prefix;
        return detection(f, "hex", confidence(f, origin, name, true, null), data, null);
    }

    private static Detection base64(String value, Origin origin, String name, boolean full) {
        String s = value.indexOf(' ') >= 0 ? value.replace(' ', '+') : value; // '+' decoded to ' ' by form/query parsing
        String encoding = "base64";
        int sig = s.lastIndexOf("--");
        if (sig >= 8 && sig + 2 < s.length() && isSignature(s.substring(sig + 2))) {
            s = s.substring(0, sig);
            encoding = "base64 (signed value)";
        }
        int run = 0;
        while (run < s.length() && isB64(s.charAt(run))) run++;
        int data = run;
        while (run < s.length() && s.charAt(run) == '=' && run - data < 2) run++;
        if (data < 8) return null;
        if (run != s.length() && origin != Origin.BODY && origin != Origin.EMBEDDED) return null;
        String b64 = s.substring(0, data);

        byte[] prefix = Codecs.base64Decode(b64.substring(0, Math.min(data, SNIFF_B64_CHARS) & ~3));
        Format f = magic(prefix);
        if (f == null) return null;
        if (f == Format.GZIP) {
            byte[] gz = Codecs.base64Decode(full ? b64 : b64.substring(0, Math.min(data, SNIFF_GZIP_B64_CHARS) & ~3));
            Unzipped u = gz == null ? null : gunzip(gz, full ? MAX_PAYLOAD : SNIFF_GZIP_OUT);
            Format inner = u == null ? null : magic(u.data);
            if (inner == null || inner == Format.GZIP) return null;
            return detection(inner, encoding + " → gzip", confidence(inner, origin, name, true, null), u.data, u.note);
        }
        byte[] payload = prefix;
        if (full) {
            if (data > MAX_PAYLOAD / 3 * 4) b64 = b64.substring(0, MAX_PAYLOAD / 3 * 4);
            payload = Codecs.base64Decode(b64);
            if (payload == null) return null;
        }
        return detection(f, encoding, confidence(f, origin, name, true, null), payload, null);
    }

    private static Detection detection(Format f, String encoding, int confidence, byte[] payload, String note) {
        String text = null;
        if (f == Format.PHP && payload != null) text = new String(payload, StandardCharsets.UTF_8);
        return new Detection(f, encoding, confidence, payload, text, note);
    }

    /**
     * Confidence table: raw magic in a body 90; encoded magic in a param/cookie/header 85 (88 in a body); embedded
     * tokens 75; short-magic formats (Ruby, ViewState marker, unterminated pickle) lower.
     */
    static int confidence(Format f, Origin origin, String name, boolean encoded, byte[] data) {
        if (f == Format.VIEWSTATE) {
            if (name != null && name.startsWith("__VIEWSTATE")) return 15;
            return encoded ? 60 : 30;
        }
        if (f == Format.PHP) return origin == Origin.HEADER ? 75 : 80;
        if (origin == Origin.EMBEDDED) return 75;
        if (!encoded) {
            if (f == Format.RUBY) return 70;
            if (f == Format.PICKLE) return data != null && data.length > 0 && data[data.length - 1] == '.' ? 90 : 60;
            return 90;
        }
        return origin == Origin.BODY ? 88 : 85;
    }

    // ------------------------------------------------------------------ helpers

    private static boolean isB64(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '-' || c == '_';
    }

    private static boolean isSignature(String s) {
        if (s.length() < 16 || s.length() > 128) return false;
        for (int i = 0; i < s.length(); i++) if (!isB64(s.charAt(i)) && s.charAt(i) != '=') return false;
        return true;
    }

    private static byte[] hexDecode(String s, int chars) {
        int n = chars / 2;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) ((Character.digit(s.charAt(2 * i), 16) << 4) | Character.digit(s.charAt(2 * i + 1), 16));
        }
        return out;
    }

    /** Percent-decoding that leaves '+' alone (cookies and headers are not form-encoded). */
    static String percentDecodeKeepPlus(String s) {
        return Codecs.urlDecode(s.replace("+", "%2B"));
    }

    private static String join(String a, String b) {
        if (a == null) return b;
        if (b == null) return a;
        return a + "; " + b;
    }

    record Unzipped(byte[] data, String note) {
    }

    /** Bounded gunzip; returns what could be inflated from a truncated stream (with a note), or null. */
    static Unzipped gunzip(byte[] gz, int max) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        String note = null;
        try (InputStream in = new GZIPInputStream(new ByteArrayInputStream(gz), 4096)) {
            byte[] buf = new byte[4096];
            int n;
            while (out.size() < max && (n = in.read(buf, 0, Math.min(buf.length, max - out.size()))) > 0) {
                out.write(buf, 0, n);
            }
            if (out.size() >= max && in.read() >= 0) note = "decompressed data capped at " + max + " bytes";
        } catch (IOException e) {
            if (out.size() == 0) return null;
            note = "gzip stream is truncated or corrupt (" + e.getMessage() + ")";
        }
        byte[] data = out.toByteArray();
        return data.length == 0 ? null : new Unzipped(data, note);
    }
}
