package protocoldecoder.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.DataFormatException;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;

/** Small, dependency-free encoding helpers shared by built-in decoders and the script sandbox. */
public final class Codecs {

    /** Upper bound for anything we decompress, to stop zip bombs. */
    public static final int MAX_DECOMPRESSED = 32 * 1024 * 1024;

    private Codecs() {
    }

    public static String urlDecode(String s) {
        if (s == null) return null;
        try {
            return URLDecoder.decode(s, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            // Malformed % escape: decode what we can by hand.
            return lenientUrlDecode(s);
        }
    }

    private static String lenientUrlDecode(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '+') {
                out.write(' ');
            } else if (c == '%' && i + 2 < s.length() && isHex(s.charAt(i + 1)) && isHex(s.charAt(i + 2))) {
                out.write(Integer.parseInt(s.substring(i + 1, i + 3), 16));
                i += 2;
            } else {
                byte[] b = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
                out.write(b, 0, b.length);
            }
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    private static boolean isHex(char c) {
        return Character.digit(c, 16) >= 0;
    }

    /** Parses {@code a=1&b=2&a=3} into an ordered multimap with URL-decoded keys and values. */
    public static Map<String, List<String>> parseQuery(String query) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        if (query == null || query.isEmpty()) return out;
        String q = query.startsWith("?") ? query.substring(1) : query;
        for (String pair : q.split("&")) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            String k = urlDecode(eq < 0 ? pair : pair.substring(0, eq));
            String v = eq < 0 ? "" : urlDecode(pair.substring(eq + 1));
            out.computeIfAbsent(k, x -> new ArrayList<>()).add(v);
        }
        return out;
    }

    public static String first(Map<String, List<String>> params, String name) {
        List<String> v = params.get(name);
        return v == null || v.isEmpty() ? null : v.get(0);
    }

    /** Decodes standard or URL-safe base64, tolerating missing padding and whitespace. Returns null if invalid. */
    public static byte[] base64Decode(String s) {
        if (s == null) return null;
        String t = s.replaceAll("\\s+", "");
        if (t.isEmpty()) return new byte[0];
        boolean urlSafe = t.indexOf('-') >= 0 || t.indexOf('_') >= 0;
        t = t.replace("=", "");
        try {
            return (urlSafe ? Base64.getUrlDecoder() : Base64.getDecoder()).decode(pad(t));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static String pad(String t) {
        int rem = t.length() % 4;
        return rem == 0 ? t : t + "====".substring(rem);
    }

    public static String base64Encode(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    public static boolean isGzip(byte[] b) {
        return b != null && b.length > 2 && (b[0] & 0xff) == 0x1f && (b[1] & 0xff) == 0x8b;
    }

    /** True for a plausible zlib header (deflate with zlib wrapper). */
    public static boolean isZlib(byte[] b) {
        if (b == null || b.length < 2) return false;
        int cmf = b[0] & 0xff, flg = b[1] & 0xff;
        return (cmf & 0x0f) == 8 && ((cmf << 8) | flg) % 31 == 0;
    }

    public static byte[] gunzip(byte[] data) throws IOException {
        try (InputStream in = new GZIPInputStream(new ByteArrayInputStream(data))) {
            return readBounded(in);
        }
    }

    /** Inflates zlib-wrapped or raw deflate data. */
    public static byte[] inflate(byte[] data) throws IOException {
        try {
            return inflate(data, !isZlib(data));
        } catch (IOException e) {
            if (isZlib(data)) return inflate(data, true);
            throw e;
        }
    }

    private static byte[] inflate(byte[] data, boolean raw) throws IOException {
        Inflater inf = new Inflater(raw);
        try {
            inf.setInput(data);
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(64, data.length * 4));
            byte[] buf = new byte[8192];
            while (!inf.finished()) {
                int n = inf.inflate(buf);
                if (n == 0) {
                    if (inf.needsInput() || inf.needsDictionary()) break;
                }
                out.write(buf, 0, n);
                if (out.size() > MAX_DECOMPRESSED) throw new IOException("decompressed data exceeds " + MAX_DECOMPRESSED + " bytes");
            }
            if (out.size() == 0 && data.length > 0) throw new IOException("not deflate data");
            return out.toByteArray();
        } catch (DataFormatException e) {
            throw new IOException("invalid deflate data: " + e.getMessage(), e);
        } finally {
            inf.end();
        }
    }

    private static byte[] readBounded(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
            if (out.size() > MAX_DECOMPRESSED) throw new IOException("decompressed data exceeds " + MAX_DECOMPRESSED + " bytes");
        }
        return out.toByteArray();
    }

    /**
     * Undoes Content-Encoding (gzip/deflate) if declared, or if the body sniffs as gzip. Returns the input unchanged
     * when nothing applies. Brotli is not supported and is returned as-is.
     */
    public static byte[] decodeContent(byte[] body, String contentEncoding) {
        if (body == null || body.length == 0) return body;
        String ce = contentEncoding == null ? "" : contentEncoding.trim().toLowerCase();
        try {
            if (ce.contains("gzip") || isGzip(body)) return gunzip(body);
            if (ce.contains("deflate")) return inflate(body);
        } catch (IOException ignored) {
            // fall through: hand back the original bytes and let the decoder deal with it
        }
        return body;
    }

    /** True if the bytes look like human-readable UTF-8 text. */
    public static boolean isMostlyText(byte[] b) {
        if (b == null || b.length == 0) return true;
        int n = Math.min(b.length, 4096), bad = 0;
        for (int i = 0; i < n; i++) {
            int c = b[i] & 0xff;
            if (c < 0x09 || (c > 0x0d && c < 0x20) || c == 0x7f) bad++;
        }
        return bad * 20 < n;
    }

    public static String utf8(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }

    /** Converts a "binary string" (one char per byte, 0-255) to bytes. */
    public static byte[] latin1Bytes(String s) {
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }

    /** Converts bytes to a "binary string" (one char per byte, 0-255). */
    public static String latin1String(byte[] b) {
        return new String(b, StandardCharsets.ISO_8859_1);
    }

    /** Hex dump preview of the first bytes, for showing binary data in the tree. */
    public static String hexPreview(byte[] b, int max) {
        StringBuilder sb = new StringBuilder();
        int n = Math.min(b.length, max);
        for (int i = 0; i < n; i++) {
            if (i > 0) sb.append(' ');
            sb.append(String.format("%02x", b[i] & 0xff));
        }
        if (b.length > max) sb.append(" … (").append(b.length).append(" bytes)");
        return sb.toString();
    }

    public static String truncate(String s, int max) {
        if (s == null || s.length() <= max) return s;
        return s.substring(0, max) + "… (" + s.length() + " chars)";
    }
}
