package protocoldecoder.builtin.blazor;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal, bounds-checked MessagePack reader. Produces plain Java values: null, Boolean, Long, Double, String,
 * byte[] (bin), List, Map (insertion-ordered) and {@link Ext}.
 */
final class MsgPack {

    /** MessagePack extension value. */
    record Ext(int type, byte[] data) {
    }

    static final class FormatException extends Exception {
        FormatException(String m) {
            super(m);
        }
    }

    private static final int MAX_DEPTH = 64;

    private final byte[] b;
    private int pos;
    private final int end;

    MsgPack(byte[] b, int offset, int end) {
        this.b = b;
        this.pos = offset;
        this.end = end;
    }

    int position() {
        return pos;
    }

    boolean hasMore() {
        return pos < end;
    }

    Object read() throws FormatException {
        return read(0);
    }

    private Object read(int depth) throws FormatException {
        if (depth > MAX_DEPTH) throw new FormatException("nested too deep");
        int t = u8();
        if (t <= 0x7f) return (long) t;
        if (t >= 0xe0) return (long) (byte) t;
        if ((t & 0xf0) == 0x80) return map(t & 0x0f, depth);
        if ((t & 0xf0) == 0x90) return array(t & 0x0f, depth);
        if ((t & 0xe0) == 0xa0) return str(t & 0x1f);
        return switch (t) {
            case 0xc0 -> null;
            case 0xc2 -> Boolean.FALSE;
            case 0xc3 -> Boolean.TRUE;
            case 0xc4 -> bytes(u8());
            case 0xc5 -> bytes(u16());
            case 0xc6 -> bytes(len32());
            case 0xc7 -> ext(u8());
            case 0xc8 -> ext(u16());
            case 0xc9 -> ext(len32());
            case 0xca -> (double) Float.intBitsToFloat((int) u32());
            case 0xcb -> Double.longBitsToDouble(i64());
            case 0xcc -> (long) u8();
            case 0xcd -> (long) u16();
            case 0xce -> u32();
            case 0xcf -> i64(); // uint64 above Long.MAX_VALUE shows as negative; rare in practice
            case 0xd0 -> (long) (byte) u8();
            case 0xd1 -> (long) (short) u16();
            case 0xd2 -> (long) (int) u32();
            case 0xd3 -> i64();
            case 0xd4 -> ext(1);
            case 0xd5 -> ext(2);
            case 0xd6 -> ext(4);
            case 0xd7 -> ext(8);
            case 0xd8 -> ext(16);
            case 0xd9 -> str(u8());
            case 0xda -> str(u16());
            case 0xdb -> str(len32());
            case 0xdc -> array(u16(), depth);
            case 0xdd -> array(len32(), depth);
            case 0xde -> map(u16(), depth);
            case 0xdf -> map(len32(), depth);
            default -> throw new FormatException(String.format("invalid type byte 0x%02x at %d", t, pos - 1));
        };
    }

    private List<Object> array(int n, int depth) throws FormatException {
        if (n > end - pos) throw new FormatException("array length " + n + " exceeds data");
        List<Object> l = new ArrayList<>(n);
        for (int i = 0; i < n; i++) l.add(read(depth + 1));
        return l;
    }

    private Map<Object, Object> map(int n, int depth) throws FormatException {
        if (n > (end - pos) / 2) throw new FormatException("map length " + n + " exceeds data");
        Map<Object, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < n; i++) {
            Object k = read(depth + 1);
            m.put(k, read(depth + 1));
        }
        return m;
    }

    private String str(int n) throws FormatException {
        need(n);
        String s = new String(b, pos, n, StandardCharsets.UTF_8);
        pos += n;
        return s;
    }

    private byte[] bytes(int n) throws FormatException {
        need(n);
        byte[] out = new byte[n];
        System.arraycopy(b, pos, out, 0, n);
        pos += n;
        return out;
    }

    private Ext ext(int n) throws FormatException {
        int type = (byte) u8();
        return new Ext(type, bytes(n));
    }

    private void need(int n) throws FormatException {
        if (n < 0 || n > end - pos) throw new FormatException("unexpected end of data");
    }

    private int u8() throws FormatException {
        need(1);
        return b[pos++] & 0xff;
    }

    private int u16() throws FormatException {
        return (u8() << 8) | u8();
    }

    private long u32() throws FormatException {
        return ((long) u16() << 16) | u16();
    }

    private int len32() throws FormatException {
        long v = u32();
        if (v > Integer.MAX_VALUE) throw new FormatException("length too large");
        return (int) v;
    }

    private long i64() throws FormatException {
        return (u32() << 32) | u32();
    }
}
