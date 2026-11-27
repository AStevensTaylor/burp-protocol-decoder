package protocoldecoder.builtin.grpc;

import protocoldecoder.edit.EncodeException;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Schemaless protobuf text format for editing, close to {@code protoc --decode_raw}:
 * <pre>
 * 1: "alice"                 # string (UTF-8)
 * 2: 42                      # varint; negatives are 64-bit two's complement (int32/int64)
 * 3 {                        # nested message
 *   1: 0x3ff0000000000000    # fixed64 (16 hex digits); also 7i64, 1.5d (double)
 * }
 * 4: b"\x00\x01\xff"         # bytes
 * 5: 0x00000007              # fixed32 (8 hex digits); also 7i32, 1.5f (float)
 * 6: [1, 2, 300]             # packed repeated varints (or i32/i64/f/d elements: packed fixed)
 * </pre>
 * The printer shows each length-delimited field the way {@link Protobuf}'s heuristic classified it (string, bytes or
 * nested message) and the parser encodes it back the same way, so unmodified text reproduces the original bytes
 * (as long as the original used canonical varints, which {@link #print} verifies).
 */
final class ProtoText {

    static final String HEADER = "# Protobuf (schemaless). 123 / -1 varint · 0x0000007b or 123i32 fixed32 · 0x…(16 hex) or 123i64 fixed64\n"
            + "# 1.5f float · 1.5d double · \"text\" string · b\"\\x00\" bytes · N { … } message · N: [1, 2] packed\n";

    private static final Pattern INT = Pattern.compile("([+-]?)(0[xX][0-9a-fA-F]+|[0-9]+)(i32|i64)?");
    private static final Pattern FLOAT = Pattern.compile("([+-]?(?:[0-9]+\\.?[0-9]*(?:[eE][+-]?[0-9]+)?|\\.[0-9]+(?:[eE][+-]?[0-9]+)?|nan|inf|infinity))([fd])",
            Pattern.CASE_INSENSITIVE);
    private static final BigInteger TWO_64 = BigInteger.ONE.shiftLeft(64);
    private static final BigInteger TWO_32 = BigInteger.ONE.shiftLeft(32);
    private static final int MAX_PACKED_COMMENT = 16;

    private ProtoText() {
    }

    // ================================================================== printing

    /** Text for a message, or null if it does not parse completely as protobuf. */
    static String print(byte[] msg) {
        Protobuf.Parsed p = Protobuf.parse(msg);
        if (!p.complete() || p.limitReached) return null;
        StringBuilder sb = new StringBuilder();
        print(p.fields, 0, sb);
        return sb.toString();
    }

    private static void print(List<Protobuf.Field> fields, int depth, StringBuilder sb) {
        String ind = "  ".repeat(depth);
        for (Protobuf.Field f : fields) {
            sb.append(ind).append(f.number);
            switch (f.wireType) {
                case Protobuf.VARINT -> {
                    sb.append(": ").append(f.value);
                    if (f.value < 0) sb.append("  # uint64 ").append(Long.toUnsignedString(f.value));
                }
                case Protobuf.I64 -> {
                    sb.append(": ").append(String.format("0x%016x", f.value)).append("  # fixed64 ").append(Long.toUnsignedString(f.value));
                    if (f.value < 0) sb.append(", int64 ").append(f.value);
                    double d = Double.longBitsToDouble(f.value);
                    if (plausible(d)) sb.append(", double ").append(d);
                }
                case Protobuf.I32 -> {
                    int v = (int) f.value;
                    sb.append(": ").append(String.format("0x%08x", v)).append("  # fixed32 ").append(Integer.toUnsignedString(v));
                    if (v < 0) sb.append(", int32 ").append(v);
                    float fl = Float.intBitsToFloat(v);
                    if (plausible(fl)) sb.append(", float ").append(fl);
                }
                default -> {
                    Protobuf.LenKind kind = f.kind == null ? Protobuf.LenKind.BYTES : f.kind;
                    switch (kind) {
                        case EMPTY -> sb.append(": \"\"");
                        case STRING -> sb.append(": ").append(quote(f.text));
                        case MESSAGE -> {
                            sb.append(" {\n");
                            print(f.nested, depth + 1, sb);
                            sb.append(ind).append('}');
                        }
                        default -> {
                            sb.append(": ").append(bytesLiteral(f.src, f.start, f.length));
                            List<Long> packed = Protobuf.packedVarints(f.src, f.start, f.length);
                            if (packed != null && packed.size() > 1) {
                                sb.append("  # as packed varints: [");
                                for (int i = 0; i < Math.min(packed.size(), MAX_PACKED_COMMENT); i++) {
                                    if (i > 0) sb.append(", ");
                                    sb.append(Long.toUnsignedString(packed.get(i)));
                                }
                                if (packed.size() > MAX_PACKED_COMMENT) sb.append(", …");
                                sb.append(']');
                            }
                        }
                    }
                }
            }
            sb.append('\n');
        }
    }

    private static boolean plausible(double d) {
        if (d == 0) return true;
        if (Double.isNaN(d) || Double.isInfinite(d)) return false;
        double a = Math.abs(d);
        return a >= 1e-9 && a <= 1e15;
    }

    static String quote(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20 || c == 0x7f) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.append('"').toString();
    }

    static String bytesLiteral(byte[] b, int off, int len) {
        StringBuilder sb = new StringBuilder(len * 2 + 3).append("b\"");
        for (int i = off; i < off + len; i++) {
            int c = b[i] & 0xff;
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c >= 0x20 && c < 0x7f) sb.append((char) c);
                    else sb.append("\\x").append(Character.forDigit(c >> 4, 16)).append(Character.forDigit(c & 15, 16));
                }
            }
        }
        return sb.append('"').toString();
    }

    // ================================================================== parsing

    /** Parses the text format into protobuf wire bytes. */
    static byte[] parse(String text) throws EncodeException {
        Parser p = new Parser(text);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        p.message(out, false);
        return out.toByteArray();
    }

    private enum T { NUMBER_FIELD, WORD, STRING, BYTES, LBRACE, RBRACE, COLON, LBRACKET, RBRACKET, COMMA, EOF }

    private record Tok(T type, String text, byte[] bytes, int line, int col) {
        String show() {
            return switch (type) {
                case EOF -> "end of text";
                case STRING, BYTES -> "a string";
                default -> "'" + text + "'";
            };
        }
    }

    private static final class Parser {
        final String s;
        int pos, line = 1, lineStart;
        Tok peeked;
        int depth;

        Parser(String s) {
            this.s = s == null ? "" : s;
        }

        EncodeException error(int l, int c, String msg) {
            return new EncodeException("Protobuf text error at line " + l + ", column " + c + ": " + msg);
        }

        EncodeException error(Tok t, String msg) {
            return error(t.line, t.col, msg);
        }

        // ---------------------------------------------------------- grammar

        void message(ByteArrayOutputStream out, boolean nested) throws EncodeException {
            if (++depth > 100) throw error(peek(), "messages nested too deeply");
            while (true) {
                Tok t = next();
                if (t.type == T.EOF) {
                    if (nested) throw error(t, "missing '}'");
                    break;
                }
                if (t.type == T.RBRACE) {
                    if (!nested) throw error(t, "unexpected '}'");
                    break;
                }
                if (t.type != T.WORD) throw error(t, "expected a field number, found " + t.show());
                int number = fieldNumber(t);
                Tok after = next();
                if (after.type == T.COLON) {
                    Tok v = peek();
                    if (v.type == T.LBRACE) {
                        next();
                        nestedMessage(number, out);
                    } else {
                        value(number, out);
                    }
                } else if (after.type == T.LBRACE) {
                    nestedMessage(number, out);
                } else {
                    throw error(after, "expected ':' or '{' after field number " + number + ", found " + after.show());
                }
            }
            depth--;
        }

        void nestedMessage(int number, ByteArrayOutputStream out) throws EncodeException {
            ByteArrayOutputStream inner = new ByteArrayOutputStream();
            message(inner, true);
            writeLen(out, number, inner.toByteArray());
        }

        int fieldNumber(Tok t) throws EncodeException {
            if (!t.text.matches("[0-9]{1,10}")) throw error(t, "expected a field number, found " + t.show());
            long n = Long.parseLong(t.text);
            if (n < 1 || n > Protobuf.MAX_FIELD_NUMBER) throw error(t, "field number " + t.text + " out of range (1.." + Protobuf.MAX_FIELD_NUMBER + ")");
            return (int) n;
        }

        void value(int number, ByteArrayOutputStream out) throws EncodeException {
            Tok v = next();
            switch (v.type) {
                case STRING, BYTES -> writeLen(out, number, v.bytes);
                case WORD -> {
                    Scalar sc = scalar(v);
                    writeVarint(out, ((long) number << 3) | sc.wire);
                    sc.write(out);
                }
                case LBRACKET -> {
                    ByteArrayOutputStream packed = new ByteArrayOutputStream();
                    int wire = -1;
                    Tok t = peek();
                    if (t.type == T.RBRACKET) {
                        next();
                    } else {
                        while (true) {
                            Tok e = next();
                            if (e.type != T.WORD) throw error(e, "expected a number in packed list, found " + e.show());
                            Scalar sc = scalar(e);
                            if (wire >= 0 && sc.wire != wire) throw error(e, "packed list mixes varint and fixed-width values");
                            wire = sc.wire;
                            sc.write(packed);
                            Tok sep = next();
                            if (sep.type == T.RBRACKET) break;
                            if (sep.type != T.COMMA) throw error(sep, "expected ',' or ']' in packed list, found " + sep.show());
                        }
                    }
                    writeLen(out, number, packed.toByteArray());
                }
                default -> throw error(v, "expected a value for field " + number + ", found " + v.show());
            }
        }

        record Scalar(int wire, long bits) {
            void write(ByteArrayOutputStream out) {
                if (wire == Protobuf.VARINT) writeVarint(out, bits);
                else {
                    int n = wire == Protobuf.I64 ? 8 : 4;
                    for (int i = 0; i < n; i++) out.write((int) (bits >>> (8 * i)));
                }
            }
        }

        Scalar scalar(Tok t) throws EncodeException {
            String w = t.text;
            if (w.equals("true")) return new Scalar(Protobuf.VARINT, 1);
            if (w.equals("false")) return new Scalar(Protobuf.VARINT, 0);
            Matcher m = INT.matcher(w);
            if (m.matches()) {
                boolean neg = m.group(1).equals("-");
                String digits = m.group(2);
                boolean hex = digits.length() > 1 && (digits.charAt(1) == 'x' || digits.charAt(1) == 'X');
                BigInteger v = hex ? new BigInteger(digits.substring(2), 16) : new BigInteger(digits);
                if (neg) v = v.negate();
                String suffix = m.group(3);
                int wire;
                if ("i32".equals(suffix)) wire = Protobuf.I32;
                else if ("i64".equals(suffix)) wire = Protobuf.I64;
                else if (hex && digits.length() - 2 == 8) wire = Protobuf.I32;
                else if (hex && digits.length() - 2 == 16) wire = Protobuf.I64;
                else wire = Protobuf.VARINT;
                BigInteger range = wire == Protobuf.I32 ? TWO_32 : TWO_64;
                if (v.compareTo(range) >= 0 || v.compareTo(range.shiftRight(1).negate()) < 0) {
                    throw error(t, w + " does not fit in " + (wire == Protobuf.I32 ? "32" : "64") + " bits");
                }
                return new Scalar(wire, v.longValue());
            }
            Matcher f = FLOAT.matcher(w);
            if (f.matches()) {
                String num = f.group(1).toLowerCase(java.util.Locale.ROOT);
                double d;
                if (num.endsWith("nan")) d = Double.NaN;
                else if (num.endsWith("inf") || num.endsWith("infinity")) d = num.startsWith("-") ? Double.NEGATIVE_INFINITY : Double.POSITIVE_INFINITY;
                else d = Double.parseDouble(num);
                if (f.group(2).equalsIgnoreCase("d")) return new Scalar(Protobuf.I64, Double.doubleToRawLongBits(d));
                return new Scalar(Protobuf.I32, Float.floatToRawIntBits((float) d) & 0xFFFFFFFFL);
            }
            throw error(t, "'" + w + "' is not a number (use 123, -1, 7i32, 7i64, 0x…, 1.5f, 1.5d, true/false) or a quoted string");
        }

        // ---------------------------------------------------------- lexer

        Tok peek() throws EncodeException {
            if (peeked == null) peeked = lex();
            return peeked;
        }

        Tok next() throws EncodeException {
            Tok t = peek();
            peeked = null;
            return t;
        }

        Tok lex() throws EncodeException {
            skipSpace();
            int l = line, c = pos - lineStart + 1;
            if (pos >= s.length()) return new Tok(T.EOF, "", null, l, c);
            char ch = s.charAt(pos);
            switch (ch) {
                case '{' -> { pos++; return new Tok(T.LBRACE, "{", null, l, c); }
                case '}' -> { pos++; return new Tok(T.RBRACE, "}", null, l, c); }
                case ':' -> { pos++; return new Tok(T.COLON, ":", null, l, c); }
                case '[' -> { pos++; return new Tok(T.LBRACKET, "[", null, l, c); }
                case ']' -> { pos++; return new Tok(T.RBRACKET, "]", null, l, c); }
                case ',' -> { pos++; return new Tok(T.COMMA, ",", null, l, c); }
                case '"', '\'' -> { return new Tok(T.STRING, "", string(false), l, c); }
                default -> { }
            }
            if (ch == 'b' && pos + 1 < s.length() && (s.charAt(pos + 1) == '"' || s.charAt(pos + 1) == '\'')) {
                pos++;
                return new Tok(T.BYTES, "", string(true), l, c);
            }
            int start = pos;
            while (pos < s.length()) {
                char x = s.charAt(pos);
                if (Character.isLetterOrDigit(x) || x == '-' || x == '+' || x == '.' || x == '_') pos++;
                else break;
            }
            if (pos == start) throw error(l, c, "unexpected character '" + ch + "'");
            return new Tok(T.WORD, s.substring(start, pos), null, l, c);
        }

        void skipSpace() {
            while (pos < s.length()) {
                char ch = s.charAt(pos);
                if (ch == '\n') {
                    pos++;
                    line++;
                    lineStart = pos;
                } else if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\f' || ch == ';') {
                    pos++;
                } else if (ch == '#') {
                    while (pos < s.length() && s.charAt(pos) != '\n') pos++;
                } else {
                    break;
                }
            }
        }

        /** Reads a quoted literal at pos. Escapes \xHH and octal give raw bytes; other characters are UTF-8. */
        byte[] string(boolean bytes) throws EncodeException {
            int l = line, c = pos - lineStart + 1;
            char quote = s.charAt(pos++);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            while (true) {
                if (pos >= s.length() || s.charAt(pos) == '\n') throw error(l, c, "unterminated string");
                char ch = s.charAt(pos);
                if (ch == quote) {
                    pos++;
                    break;
                }
                if (ch != '\\') {
                    int cp = s.codePointAt(pos);
                    pos += Character.charCount(cp);
                    out.writeBytes(new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8));
                    continue;
                }
                int ec = pos - lineStart + 1;
                pos++;
                if (pos >= s.length()) throw error(l, c, "unterminated string");
                char e = s.charAt(pos++);
                switch (e) {
                    case 'n' -> out.write('\n');
                    case 'r' -> out.write('\r');
                    case 't' -> out.write('\t');
                    case 'a' -> out.write(7);
                    case 'b' -> out.write('\b');
                    case 'f' -> out.write('\f');
                    case 'v' -> out.write(11);
                    case '\\', '"', '\'', '/', '?' -> out.write(e);
                    case 'x', 'X' -> {
                        int v = 0, n = 0;
                        while (n < 2 && pos < s.length() && Character.digit(s.charAt(pos), 16) >= 0) {
                            v = v * 16 + Character.digit(s.charAt(pos++), 16);
                            n++;
                        }
                        if (n == 0) throw error(line, ec, "\\x needs hex digits");
                        out.write(v);
                    }
                    case 'u', 'U' -> {
                        int len = e == 'u' ? 4 : 8;
                        if (pos + len > s.length()) throw error(line, ec, "\\" + e + " needs " + len + " hex digits");
                        int cp;
                        try {
                            cp = Integer.parseInt(s.substring(pos, pos + len), 16);
                        } catch (NumberFormatException ex) {
                            throw error(line, ec, "\\" + e + " needs " + len + " hex digits");
                        }
                        pos += len;
                        if (e == 'u' && Character.isHighSurrogate((char) cp) && pos + 6 <= s.length() && s.startsWith("\\u", pos)) {
                            try {
                                int lo = Integer.parseInt(s.substring(pos + 2, pos + 6), 16);
                                if (Character.isLowSurrogate((char) lo)) {
                                    cp = Character.toCodePoint((char) cp, (char) lo);
                                    pos += 6;
                                }
                            } catch (NumberFormatException ignored) {
                                // leave the high surrogate alone
                            }
                        }
                        if (cp > Character.MAX_CODE_POINT || (cp >= 0xd800 && cp <= 0xdfff)) throw error(line, ec, "invalid code point \\" + e + Integer.toHexString(cp));
                        out.writeBytes(new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8));
                    }
                    default -> {
                        if (e >= '0' && e <= '7') {
                            int v = e - '0', n = 1;
                            while (n < 3 && pos < s.length() && s.charAt(pos) >= '0' && s.charAt(pos) <= '7') {
                                v = v * 8 + (s.charAt(pos++) - '0');
                                n++;
                            }
                            if (v > 255) throw error(line, ec, "octal escape out of range");
                            out.write(v);
                        } else {
                            throw error(line, ec, "unknown escape '\\" + e + "'");
                        }
                    }
                }
            }
            // Adjacent literals concatenate, as in protoc's text format.
            int save = pos, saveLine = line, saveStart = lineStart;
            skipSpace();
            if (pos < s.length() && (s.charAt(pos) == '"' || s.charAt(pos) == '\'')) {
                out.writeBytes(string(bytes));
            } else if (bytes && pos + 1 < s.length() && s.charAt(pos) == 'b' && (s.charAt(pos + 1) == '"' || s.charAt(pos + 1) == '\'')) {
                pos++;
                out.writeBytes(string(true));
            } else {
                pos = save;
                line = saveLine;
                lineStart = saveStart;
            }
            return out.toByteArray();
        }
    }

    // ================================================================== wire helpers

    static void writeVarint(ByteArrayOutputStream o, long v) {
        while ((v & ~0x7fL) != 0) {
            o.write((int) ((v & 0x7f) | 0x80));
            v >>>= 7;
        }
        o.write((int) v);
    }

    static void writeLen(ByteArrayOutputStream o, int number, byte[] content) {
        writeVarint(o, ((long) number << 3) | Protobuf.LEN);
        writeVarint(o, content.length);
        o.writeBytes(content);
    }
}
