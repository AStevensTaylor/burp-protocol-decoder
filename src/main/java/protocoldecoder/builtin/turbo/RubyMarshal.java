package protocoldecoder.builtin.turbo;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Minimal, read-only Ruby Marshal 4.8 reader that renders a value as Ruby {@code inspect}-style text. It never
 * instantiates anything; it only describes the structure (classes are shown by name). Bounded in depth and size.
 */
public final class RubyMarshal {

    private static final int MAX_DEPTH = 32;
    private static final int MAX_ITEMS = 10_000;
    private static final int MAX_OUT = 64 * 1024;

    private final byte[] b;
    private int pos;
    private int items;
    private final List<String> symbols = new ArrayList<>();
    private final StringBuilder out = new StringBuilder();

    private RubyMarshal(byte[] b) {
        this.b = b;
    }

    public static boolean isMarshal(byte[] b) {
        return b != null && b.length >= 3 && b[0] == 4 && b[1] == 8;
    }

    /** Renders the Marshal data as inspect-style text; throws IllegalArgumentException if it is malformed. */
    public static String inspect(byte[] data) {
        if (!isMarshal(data)) throw new IllegalArgumentException("not Ruby Marshal 4.8 data");
        RubyMarshal r = new RubyMarshal(data);
        r.pos = 2;
        r.value(0);
        if (r.pos != data.length) r.out.append(" /* ").append(data.length - r.pos).append(" trailing bytes */");
        return r.out.toString();
    }

    private int u8() {
        if (pos >= b.length) throw new IllegalArgumentException("truncated Marshal data at offset " + pos);
        return b[pos++] & 0xff;
    }

    /** Ruby's packed integer ("w_long"). */
    private long fixnum() {
        int c = (byte) u8();
        if (c == 0) return 0;
        if (c >= 5) return c - 5;
        if (c <= -5) return c + 5;
        if (c > 0) {
            long x = 0;
            for (int i = 0; i < c; i++) x |= (long) u8() << (8 * i);
            return x;
        }
        long x = -1;
        for (int i = 0; i < -c; i++) {
            x &= ~(0xffL << (8 * i));
            x |= (long) u8() << (8 * i);
        }
        return x;
    }

    private byte[] bytes() {
        long len = fixnum();
        if (len < 0 || len > b.length - pos) throw new IllegalArgumentException("bad length " + len + " at offset " + pos);
        byte[] r = new byte[(int) len];
        System.arraycopy(b, pos, r, 0, (int) len);
        pos += (int) len;
        return r;
    }

    private String symbolValue() {
        int t = u8();
        if (t == ':') {
            String s = new String(bytes(), StandardCharsets.UTF_8);
            symbols.add(s);
            return s;
        }
        if (t == ';') {
            long i = fixnum();
            if (i < 0 || i >= symbols.size()) throw new IllegalArgumentException("bad symbol link " + i);
            return symbols.get((int) i);
        }
        if (t == 'I') { // symbol with encoding ivars
            String s = symbolValue();
            long n = fixnum();
            for (long k = 0; k < n; k++) {
                symbolValue();
                skipValue();
            }
            return s;
        }
        throw new IllegalArgumentException("expected symbol at offset " + (pos - 1));
    }

    private void skipValue() {
        int len = out.length();
        value(MAX_DEPTH - 1);
        out.setLength(len);
    }

    private void emit(String s) {
        if (out.length() < MAX_OUT) out.append(s);
    }

    private void value(int depth) {
        if (depth > MAX_DEPTH) throw new IllegalArgumentException("nesting too deep");
        if (++items > MAX_ITEMS) throw new IllegalArgumentException("too many elements");
        int t = u8();
        switch (t) {
            case '0' -> emit("nil");
            case 'T' -> emit("true");
            case 'F' -> emit("false");
            case 'i' -> emit(Long.toString(fixnum()));
            case 'f' -> emit(new String(bytes(), StandardCharsets.UTF_8));
            case 'l' -> {
                int sign = u8();
                long words = fixnum();
                if (words < 0 || words * 2 > b.length - pos) throw new IllegalArgumentException("bad bignum");
                byte[] le = new byte[(int) words * 2];
                System.arraycopy(b, pos, le, 0, le.length);
                pos += le.length;
                byte[] be = new byte[le.length + 1];
                for (int i = 0; i < le.length; i++) be[be.length - 1 - i] = le[i];
                BigInteger v = new BigInteger(be);
                emit((sign == '-' ? v.negate() : v).toString());
            }
            case '"' -> emit(quote(new String(bytes(), StandardCharsets.UTF_8)));
            case ':' -> {
                pos--;
                emit(":" + symbolValue());
            }
            case ';' -> {
                pos--;
                emit(":" + symbolValue());
            }
            case 'I' -> {
                value(depth + 1);
                long n = fixnum();
                for (long k = 0; k < n; k++) {
                    symbolValue();
                    skipValue();
                }
            }
            case '[' -> {
                long n = fixnum();
                emit("[");
                for (long k = 0; k < n; k++) {
                    if (k > 0) emit(", ");
                    value(depth + 1);
                }
                emit("]");
            }
            case '{', '}' -> {
                long n = fixnum();
                emit("{");
                for (long k = 0; k < n; k++) {
                    if (k > 0) emit(", ");
                    value(depth + 1);
                    emit(" => ");
                    value(depth + 1);
                }
                emit("}");
                if (t == '}') {
                    emit(" /* default: ");
                    value(depth + 1);
                    emit(" */");
                }
            }
            case 'o' -> {
                String cls = symbolValue();
                long n = fixnum();
                emit("#<" + cls);
                for (long k = 0; k < n; k++) {
                    emit(k == 0 ? " " : ", ");
                    emit(symbolValue() + "=");
                    value(depth + 1);
                }
                emit(">");
            }
            case 'S' -> {
                String cls = symbolValue();
                long n = fixnum();
                emit("#<struct " + cls);
                for (long k = 0; k < n; k++) {
                    emit(k == 0 ? " " : ", ");
                    emit(symbolValue() + "=");
                    value(depth + 1);
                }
                emit(">");
            }
            case 'u' -> {
                String cls = symbolValue();
                byte[] data = bytes();
                emit("#<" + cls + " _dump(" + data.length + " bytes)>");
            }
            case 'U' -> {
                String cls = symbolValue();
                emit("#<" + cls + " marshal_load(");
                value(depth + 1);
                emit(")>");
            }
            case 'C' -> {
                String cls = symbolValue();
                emit("#<" + cls + " ");
                value(depth + 1);
                emit(">");
            }
            case 'e' -> {
                String mod = symbolValue();
                emit("/* extended " + mod + " */ ");
                value(depth + 1);
            }
            case 'c' -> emit(new String(bytes(), StandardCharsets.UTF_8));
            case 'm', 'M' -> emit("module " + new String(bytes(), StandardCharsets.UTF_8));
            case '/' -> {
                String src = new String(bytes(), StandardCharsets.UTF_8);
                u8(); // options
                emit("/" + src + "/");
            }
            case '@' -> emit("@object_ref(" + fixnum() + ")");
            case 'd' -> {
                String cls = symbolValue();
                emit("#<data " + cls + " ");
                value(depth + 1);
                emit(">");
            }
            default -> throw new IllegalArgumentException(String.format("unsupported Marshal type 0x%02x at offset %d", t, pos - 1));
        }
    }

    static String quote(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\x%02X", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.append('"').toString();
    }
}
