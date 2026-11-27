package protocoldecoder.builtin.serialized;

import protocoldecoder.builtin.serialized.ParseOutput.Frame;
import protocoldecoder.builtin.serialized.ParseOutput.Span;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Replaces one string value inside a serialized payload with another, re-encoding just that element (type tag and
 * length prefix recomputed) and keeping every other byte as it was. This only rewrites data the parser located
 * precisely; it never builds objects, adds classes or changes the structure of the stream.
 */
final class Reserializer {

    private static final int TC_STRING = 0x74;
    private static final int TC_LONGSTRING = 0x7C;
    private static final int SHORT_BINUNICODE = 0x8c;
    private static final int BINUNICODE = 'X';
    private static final int BINUNICODE8 = 0x8d;
    private static final Pattern PHP_INT = Pattern.compile("[+-]?\\d{1,19}");

    private Reserializer() {
    }

    /** {@code original} with {@code span} holding {@code value}; pickle frames are resized to match. */
    static byte[] replace(byte[] original, Span span, String value, List<Frame> frames) {
        byte[] element = encode(original, span, value);
        int delta = element.length - (span.end() - span.start());
        ByteArrayOutputStream out = new ByteArrayOutputStream(original.length + Math.max(0, delta));
        out.write(original, 0, span.start());
        out.writeBytes(element);
        out.write(original, span.end(), original.length - span.end());
        byte[] b = out.toByteArray();
        if (span.kind() == 'P' && delta != 0) {
            for (Frame f : frames) {
                if (span.start() >= f.start() && span.start() < f.start() + f.length() && f.lengthOffset() + 8 <= span.start()) {
                    putLongLe(b, f.lengthOffset(), f.length() + delta);
                    break;
                }
            }
        }
        return b;
    }

    static byte[] encode(byte[] original, Span span, String value) {
        return switch (span.kind()) {
            case 's' -> php(value);
            case 'i' -> PHP_INT.matcher(value).matches() ? ("i:" + value).getBytes(StandardCharsets.US_ASCII) : php(value);
            case 'J' -> java(value);
            case 'P' -> pickle(original[span.start()] & 0xff, value);
            case 'N' -> nrbf(value);
            case 'R' -> ruby(value);
            default -> throw new IllegalArgumentException("unknown span kind " + span.kind());
        };
    }

    /** {@code s:<byte length>:"<bytes>"} (the trailing ';' stays in place). */
    static byte[] php(String v) {
        byte[] b = v.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream o = new ByteArrayOutputStream(b.length + 16);
        o.writeBytes(("s:" + b.length + ":\"").getBytes(StandardCharsets.US_ASCII));
        o.writeBytes(b);
        o.write('"');
        return o.toByteArray();
    }

    /** TC_STRING with a 2-byte length, or TC_LONGSTRING with an 8-byte length beyond 65535 bytes of modified UTF-8. */
    static byte[] java(String v) {
        byte[] b = modifiedUtf8(v);
        ByteArrayOutputStream o = new ByteArrayOutputStream(b.length + 9);
        if (b.length <= 0xFFFF) {
            o.write(TC_STRING);
            o.write(b.length >>> 8);
            o.write(b.length & 0xff);
        } else {
            o.write(TC_LONGSTRING);
            long n = b.length;
            for (int i = 7; i >= 0; i--) o.write((int) (n >>> (8 * i)) & 0xff);
        }
        o.writeBytes(b);
        return o.toByteArray();
    }

    /** Keeps the original opcode where the new length fits, else widens SHORT_BINUNICODE to BINUNICODE. */
    static byte[] pickle(int opcode, String v) {
        byte[] b = v.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream o = new ByteArrayOutputStream(b.length + 9);
        if (opcode == SHORT_BINUNICODE && b.length <= 0xff) {
            o.write(SHORT_BINUNICODE);
            o.write(b.length);
        } else if (opcode == BINUNICODE8) {
            o.write(BINUNICODE8);
            for (int i = 0; i < 8; i++) o.write((int) ((long) b.length >>> (8 * i)) & 0xff);
        } else {
            o.write(BINUNICODE);
            for (int i = 0; i < 4; i++) o.write((b.length >>> (8 * i)) & 0xff);
        }
        o.writeBytes(b);
        return o.toByteArray();
    }

    /** [MS-NRBF] LengthPrefixedString: 7-bit encoded length then UTF-8. */
    static byte[] nrbf(String v) {
        byte[] b = v.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream o = new ByteArrayOutputStream(b.length + 5);
        int len = b.length;
        while (len >= 0x80) {
            o.write((len & 0x7f) | 0x80);
            len >>>= 7;
        }
        o.write(len);
        o.writeBytes(b);
        return o.toByteArray();
    }

    /** Marshal string body: packed length then bytes (the encoding ivar wrapper around it is unchanged). */
    static byte[] ruby(String v) {
        byte[] b = v.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream o = new ByteArrayOutputStream(b.length + 5);
        o.writeBytes(rubyLong(b.length));
        o.writeBytes(b);
        return o.toByteArray();
    }

    /** Marshal's packed integer for a non-negative value. */
    static byte[] rubyLong(long x) {
        if (x == 0) return new byte[]{0};
        if (x > 0 && x < 123) return new byte[]{(byte) (x + 5)};
        byte[] buf = new byte[9];
        int n = 0;
        long v = x;
        while (v != 0 && n < 8) {
            buf[++n] = (byte) (v & 0xff);
            v >>>= 8;
        }
        buf[0] = (byte) n;
        return Arrays.copyOf(buf, n + 1);
    }

    /** Java's modified UTF-8 (U+0000 as two bytes, supplementary characters as two 3-byte surrogates). */
    static byte[] modifiedUtf8(String s) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 1 && c <= 0x7f) {
                o.write(c);
            } else if (c <= 0x7ff) {
                o.write(0xc0 | (c >> 6));
                o.write(0x80 | (c & 0x3f));
            } else {
                o.write(0xe0 | (c >> 12));
                o.write(0x80 | ((c >> 6) & 0x3f));
                o.write(0x80 | (c & 0x3f));
            }
        }
        return o.toByteArray();
    }

    private static void putLongLe(byte[] b, int off, long v) {
        for (int i = 0; i < 8; i++) b[off + i] = (byte) (v >>> (8 * i));
    }
}
