package protocoldecoder.builtin.blazor;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/**
 * Small MessagePack helpers for re-encoding hub messages: string encoding, SignalR VarInt length prefixes, array
 * header reading and value span measurement (via {@link MsgPack}). Re-encoding splices a new string over the old one
 * so every other byte of the message stays as the client sent it; array headers count elements, not bytes, so only
 * the frame's VarInt length prefix has to be recomputed.
 */
final class MsgPackWriter {

    private MsgPackWriter() {
    }

    /** Encodes a string with the smallest str header (fixstr / str8 / str16 / str32). */
    static byte[] str(String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream o = new ByteArrayOutputStream(b.length + 5);
        int n = b.length;
        if (n < 32) {
            o.write(0xa0 | n);
        } else if (n < 0x100) {
            o.write(0xd9);
            o.write(n);
        } else if (n < 0x10000) {
            o.write(0xda);
            o.write(n >>> 8);
            o.write(n);
        } else {
            o.write(0xdb);
            o.write(n >>> 24);
            o.write(n >>> 16);
            o.write(n >>> 8);
            o.write(n);
        }
        o.writeBytes(b);
        return o.toByteArray();
    }

    /** SignalR binary framing length prefix (7 bits per byte, little-endian, high bit = more). */
    static byte[] varInt(int len) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(5);
        int v = len;
        do {
            int b = v & 0x7f;
            v >>>= 7;
            o.write(v > 0 ? b | 0x80 : b);
        } while (v > 0);
        return o.toByteArray();
    }

    /** Array header at {@code pos}: {element count, header length}, or null if no array starts there. */
    static int[] arrayHeader(byte[] b, int pos, int end) {
        if (pos >= end) return null;
        int t = b[pos] & 0xff;
        if ((t & 0xf0) == 0x90) return new int[]{t & 0x0f, 1};
        if (t == 0xdc && pos + 3 <= end) return new int[]{((b[pos + 1] & 0xff) << 8) | (b[pos + 2] & 0xff), 3};
        if (t == 0xdd && pos + 5 <= end) {
            long n = ((long) (b[pos + 1] & 0xff) << 24) | ((b[pos + 2] & 0xff) << 16) | ((b[pos + 3] & 0xff) << 8) | (b[pos + 4] & 0xff);
            return n > end - pos ? null : new int[]{(int) n, 5};
        }
        return null;
    }

    /** End offset of the value starting at {@code pos}. */
    static int skip(byte[] b, int pos, int end) throws MsgPack.FormatException {
        MsgPack r = new MsgPack(b, pos, end);
        r.read();
        return r.position();
    }

    /** Decodes the value in {@code [pos, end)}. */
    static Object read(byte[] b, int pos, int end) throws MsgPack.FormatException {
        return new MsgPack(b, pos, end).read();
    }

    // ---------------------------------------------------------------- value writers (smallest encodings)

    static void nil(ByteArrayOutputStream o) {
        o.write(0xc0);
    }

    static void bool(ByteArrayOutputStream o, boolean v) {
        o.write(v ? 0xc3 : 0xc2);
    }

    /** Integer in the smallest format: fixint, uint8..uint64 for non-negatives, int8..int64 for negatives. */
    static void integer(ByteArrayOutputStream o, BigInteger v) {
        if (v.signum() >= 0) {
            if (v.bitLength() > 64) throw new IllegalArgumentException("integer " + v + " does not fit in uint64");
            long x = v.longValue();
            if (v.bitLength() <= 7) o.write((int) x);
            else if (v.bitLength() <= 8) { o.write(0xcc); be(o, x, 1); }
            else if (v.bitLength() <= 16) { o.write(0xcd); be(o, x, 2); }
            else if (v.bitLength() <= 32) { o.write(0xce); be(o, x, 4); }
            else { o.write(0xcf); be(o, x, 8); }
        } else {
            if (v.bitLength() > 63) throw new IllegalArgumentException("integer " + v + " does not fit in int64");
            long x = v.longValue();
            if (x >= -32) o.write((int) x & 0xff);
            else if (x >= Byte.MIN_VALUE) { o.write(0xd0); be(o, x, 1); }
            else if (x >= Short.MIN_VALUE) { o.write(0xd1); be(o, x, 2); }
            else if (x >= Integer.MIN_VALUE) { o.write(0xd2); be(o, x, 4); }
            else { o.write(0xd3); be(o, x, 8); }
        }
    }

    static void float64(ByteArrayOutputStream o, double d) {
        o.write(0xcb);
        be(o, Double.doubleToRawLongBits(d), 8);
    }

    static void float32(ByteArrayOutputStream o, float f) {
        o.write(0xca);
        be(o, Float.floatToRawIntBits(f) & 0xFFFFFFFFL, 4);
    }

    /** str header + raw UTF-8 bytes. */
    static void strBytes(ByteArrayOutputStream o, byte[] b) {
        int n = b.length;
        if (n < 32) o.write(0xa0 | n);
        else if (n < 0x100) { o.write(0xd9); be(o, n, 1); }
        else if (n < 0x10000) { o.write(0xda); be(o, n, 2); }
        else { o.write(0xdb); be(o, n, 4); }
        o.writeBytes(b);
    }

    static void bin(ByteArrayOutputStream o, byte[] b) {
        int n = b.length;
        if (n < 0x100) { o.write(0xc4); be(o, n, 1); }
        else if (n < 0x10000) { o.write(0xc5); be(o, n, 2); }
        else { o.write(0xc6); be(o, n, 4); }
        o.writeBytes(b);
    }

    static void ext(ByteArrayOutputStream o, int type, byte[] b) {
        int n = b.length;
        switch (n) {
            case 1 -> o.write(0xd4);
            case 2 -> o.write(0xd5);
            case 4 -> o.write(0xd6);
            case 8 -> o.write(0xd7);
            case 16 -> o.write(0xd8);
            default -> {
                if (n < 0x100) { o.write(0xc7); be(o, n, 1); }
                else if (n < 0x10000) { o.write(0xc8); be(o, n, 2); }
                else { o.write(0xc9); be(o, n, 4); }
            }
        }
        o.write(type);
        o.writeBytes(b);
    }

    static void arrayHeader(ByteArrayOutputStream o, int n) {
        if (n < 16) o.write(0x90 | n);
        else if (n < 0x10000) { o.write(0xdc); be(o, n, 2); }
        else { o.write(0xdd); be(o, n, 4); }
    }

    static void mapHeader(ByteArrayOutputStream o, int n) {
        if (n < 16) o.write(0x80 | n);
        else if (n < 0x10000) { o.write(0xde); be(o, n, 2); }
        else { o.write(0xdf); be(o, n, 4); }
    }

    private static void be(ByteArrayOutputStream o, long v, int bytes) {
        for (int i = bytes - 1; i >= 0; i--) o.write((int) (v >>> (8 * i)));
    }
}
