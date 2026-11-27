package protocoldecoder.builtin.serialized;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Bounds-checked byte reader shared by the binary parsers. Every read checks the remaining length first, so a length
 * field taken from untrusted input can never cause an allocation larger than the input itself.
 */
final class Bin {

    /** Malformed or truncated input; carries the offset so partial output can say where parsing stopped. */
    static class FormatException extends Exception {
        FormatException(String message) {
            super(message);
        }
    }

    /** The output node cap was reached. */
    static final class LimitException extends FormatException {
        LimitException(String message) {
            super(message);
        }
    }

    private final byte[] b;
    private final int end;
    private int pos;

    Bin(byte[] b) {
        this(b, 0, b.length);
    }

    Bin(byte[] b, int offset, int end) {
        this.b = b;
        this.pos = offset;
        this.end = Math.min(end, b.length);
    }

    int pos() { return pos; }
    int end() { return end; }
    int remaining() { return end - pos; }
    boolean hasMore() { return pos < end; }

    void need(long n) throws FormatException {
        if (n < 0) throw new FormatException("negative length " + n + " at offset " + pos);
        if (n > end - pos) {
            throw new FormatException("truncated: need " + n + " bytes at offset " + pos + " but only " + (end - pos) + " remain");
        }
    }

    int peek() throws FormatException {
        need(1);
        return b[pos] & 0xff;
    }

    int u8() throws FormatException {
        need(1);
        return b[pos++] & 0xff;
    }

    int u16be() throws FormatException {
        need(2);
        int v = ((b[pos] & 0xff) << 8) | (b[pos + 1] & 0xff);
        pos += 2;
        return v;
    }

    int s32be() throws FormatException {
        need(4);
        int v = ((b[pos] & 0xff) << 24) | ((b[pos + 1] & 0xff) << 16) | ((b[pos + 2] & 0xff) << 8) | (b[pos + 3] & 0xff);
        pos += 4;
        return v;
    }

    long s64be() throws FormatException {
        long hi = s32be() & 0xffffffffL;
        long lo = s32be() & 0xffffffffL;
        return (hi << 32) | lo;
    }

    int u16le() throws FormatException {
        need(2);
        int v = (b[pos] & 0xff) | ((b[pos + 1] & 0xff) << 8);
        pos += 2;
        return v;
    }

    int s32le() throws FormatException {
        need(4);
        int v = (b[pos] & 0xff) | ((b[pos + 1] & 0xff) << 8) | ((b[pos + 2] & 0xff) << 16) | ((b[pos + 3] & 0xff) << 24);
        pos += 4;
        return v;
    }

    long u32le() throws FormatException {
        return s32le() & 0xffffffffL;
    }

    long s64le() throws FormatException {
        long lo = u32le();
        long hi = u32le();
        return (hi << 32) | lo;
    }

    byte[] bytes(long n) throws FormatException {
        need(n);
        byte[] out = Arrays.copyOfRange(b, pos, pos + (int) n);
        pos += (int) n;
        return out;
    }

    void skip(long n) throws FormatException {
        need(n);
        pos += (int) n;
    }

    String utf8(long n) throws FormatException {
        need(n);
        String s = new String(b, pos, (int) n, StandardCharsets.UTF_8);
        pos += (int) n;
        return s;
    }

    String latin1(long n) throws FormatException {
        need(n);
        String s = new String(b, pos, (int) n, StandardCharsets.ISO_8859_1);
        pos += (int) n;
        return s;
    }
}
