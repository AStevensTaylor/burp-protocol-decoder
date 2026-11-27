package protocoldecoder.builtin.serialized;

import protocoldecoder.builtin.serialized.Sniffer.Format;
import protocoldecoder.util.Codecs;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.zip.GZIPOutputStream;

/**
 * Exact, reversible unwrapping of a serialized payload from the text or bytes it travels in (percent-encoding, standard
 * or URL-safe base64 with or without padding, hex, gzip, in any stacking), so a modified payload can be put back with
 * every wrapper restored. Only wrappings that can be reproduced are accepted: anything signed, line-wrapped or
 * otherwise ambiguous is rejected (returns null).
 */
final class Wrapping {

    enum Kind { PERCENT, BASE64, HEX, GZIP }

    /** One wrapper layer, outermost first in {@link Peeled#layers()}. */
    record Layer(Kind kind, boolean urlSafe, boolean padded, boolean upperHex) {
        static Layer of(Kind k) {
            return new Layer(k, false, false, false);
        }

        String label() {
            return switch (kind) {
                case PERCENT -> "percent-encoding";
                case BASE64 -> (urlSafe ? "URL-safe base64" : "base64") + (padded ? "" : " (unpadded)");
                case HEX -> "hex";
                case GZIP -> "gzip";
            };
        }
    }

    /** The innermost payload and how to get back to the original text/bytes. */
    record Peeled(byte[] payload, Format format, List<Layer> layers) {
        String encoding() {
            if (layers.isEmpty()) return "raw";
            List<String> l = new ArrayList<>();
            for (Layer x : layers) l.add(x.label());
            return String.join(" → ", l);
        }
    }

    private static final int MAX_DEPTH = 5;

    private Wrapping() {
    }

    /** Peels a text value (cookie, header, parameter after form-decoding, embedded token). */
    static Peeled peelText(String value, boolean allowPercent) {
        if (value == null || value.length() < 4 || value.length() > Sniffer.MAX_PAYLOAD * 2) return null;
        List<Layer> layers = new ArrayList<>();
        String s = value;
        if (allowPercent && hasPercentEscape(s)) {
            s = Sniffer.percentDecodeKeepPlus(s);
            layers.add(Layer.of(Kind.PERCENT));
        }
        return text(s, layers, 0);
    }

    /** Peels a raw body. */
    static Peeled peelBytes(byte[] data) {
        if (data == null || data.length < 3) return null;
        return bytes(data, new ArrayList<>(), 0);
    }

    private static Peeled bytes(byte[] data, List<Layer> layers, int depth) {
        if (depth > MAX_DEPTH) return null;
        Format f = Sniffer.magic(Arrays.copyOf(data, Math.min(data.length, 32)));
        if (f == Format.GZIP) {
            Sniffer.Unzipped u = Sniffer.gunzip(data, Sniffer.MAX_PAYLOAD);
            if (u == null || u.note() != null) return null; // truncated or capped: cannot be rebuilt exactly
            layers.add(Layer.of(Kind.GZIP));
            return bytes(u.data(), layers, depth + 1);
        }
        if (f == Format.PHP) {
            if (!Codecs.isMostlyText(Arrays.copyOf(data, Math.min(data.length, 512)))) return null;
            return new Peeled(data, f, List.copyOf(layers));
        }
        if (f != null) return f == Format.VIEWSTATE ? null : new Peeled(data, f, List.copyOf(layers));
        if (!Codecs.isMostlyText(data)) return null;
        return text(new String(data, StandardCharsets.ISO_8859_1), layers, depth + 1);
    }

    private static Peeled text(String s, List<Layer> layers, int depth) {
        if (depth > MAX_DEPTH || s.length() < 4) return null;
        if (Sniffer.phpStrength(s) > 0) {
            return new Peeled(s.getBytes(StandardCharsets.UTF_8), Format.PHP, List.copyOf(layers));
        }
        if (s.length() >= 8 && s.length() % 2 == 0 && isHex(s)) {
            boolean upper = s.chars().noneMatch(c -> c >= 'a' && c <= 'f');
            boolean lower = s.chars().noneMatch(c -> c >= 'A' && c <= 'F');
            if (upper || lower) {
                List<Layer> hl = new ArrayList<>(layers);
                hl.add(new Layer(Kind.HEX, false, false, upper && !lower));
                Peeled p = bytes(HexFormat.of().parseHex(s), hl, depth + 1);
                if (p != null) return p;
            }
        }
        // '+' turns into ' ' when a base64 value is form-decoded
        String b = s.indexOf(' ') >= 0 ? s.replace(' ', '+') : s;
        int data = 0;
        while (data < b.length() && isB64(b.charAt(data))) data++;
        int end = data;
        while (end < b.length() && b.charAt(end) == '=' && end - data < 2) end++;
        if (data < 8 || end != b.length()) return null;
        String body = b.substring(0, data);
        boolean std = body.indexOf('+') >= 0 || body.indexOf('/') >= 0;
        boolean url = body.indexOf('-') >= 0 || body.indexOf('_') >= 0;
        if (std && url) return null;
        if (data % 4 == 1) return null;
        boolean padded = end > data || data % 4 == 0;
        byte[] decoded = Codecs.base64Decode(body);
        if (decoded == null) return null;
        Layer layer = new Layer(Kind.BASE64, url, padded, false);
        // Only accept if re-encoding the decoded bytes reproduces the text (canonical base64).
        if (!new String(encode(decoded, layer), StandardCharsets.ISO_8859_1).equals(b)) return null;
        layers.add(layer);
        return bytes(decoded, layers, depth + 1);
    }

    /** Applies the layers (innermost last in the list) around a new payload; returns the outer bytes (text as ASCII). */
    static byte[] wrap(byte[] payload, List<Layer> layers) {
        byte[] cur = payload;
        for (int i = layers.size() - 1; i >= 0; i--) cur = encode(cur, layers.get(i));
        return cur;
    }

    private static byte[] encode(byte[] b, Layer l) {
        return switch (l.kind()) {
            case GZIP -> gzip(b);
            case HEX -> {
                String h = HexFormat.of().formatHex(b);
                yield (l.upperHex() ? h.toUpperCase(java.util.Locale.ROOT) : h).getBytes(StandardCharsets.US_ASCII);
            }
            case BASE64 -> {
                Base64.Encoder e = l.urlSafe() ? Base64.getUrlEncoder() : Base64.getEncoder();
                if (!l.padded()) e = e.withoutPadding();
                yield e.encode(b);
            }
            case PERCENT -> percentEncode(b).getBytes(StandardCharsets.US_ASCII);
        };
    }

    /** Percent-encodes everything except RFC 3986 unreserved characters. */
    static String percentEncode(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length + 16);
        for (byte x : b) {
            int c = x & 0xff;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~') {
                sb.append((char) c);
            } else {
                sb.append('%').append(Character.toUpperCase(Character.forDigit(c >> 4, 16))).append(Character.toUpperCase(Character.forDigit(c & 15, 16)));
            }
        }
        return sb.toString();
    }

    static byte[] gzip(byte[] b) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream(b.length / 2 + 32);
            try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
                gz.write(b);
            }
            return bos.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static boolean hasPercentEscape(String s) {
        for (int i = s.indexOf('%'); i >= 0 && i + 2 < s.length(); i = s.indexOf('%', i + 1)) {
            if (Character.digit(s.charAt(i + 1), 16) >= 0 && Character.digit(s.charAt(i + 2), 16) >= 0) return true;
        }
        return false;
    }

    private static boolean isHex(String s) {
        for (int i = 0; i < s.length(); i++) if (Character.digit(s.charAt(i), 16) < 0) return false;
        return true;
    }

    private static boolean isB64(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '-' || c == '_';
    }
}
