package protocoldecoder.builtin.blazor;

import java.io.ByteArrayOutputStream;
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
}
