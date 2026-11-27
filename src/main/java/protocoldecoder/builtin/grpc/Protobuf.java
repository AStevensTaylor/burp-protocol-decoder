package protocoldecoder.builtin.grpc;

import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Schemaless Protocol Buffers wire-format decoder, in the spirit of {@code protoc --decode_raw}.
 *
 * <p>Wire types 0 (varint), 1 (64-bit), 2 (length-delimited) and 5 (32-bit) are decoded; the deprecated group wire
 * types 3/4 and the undefined types 6/7 are rejected. Length-delimited fields are classified heuristically:</p>
 * <ol>
 *   <li>printable UTF-8 text is a <b>string</b> — unless it starts with a control byte (e.g. {@code 0x0a}, the tag of
 *       field 1/LEN) and also parses as a message, in which case the message wins;</li>
 *   <li>otherwise, if the bytes parse as a complete message (every byte consumed, field numbers ≤
 *       {@link #MAX_NESTED_FIELD}, depth ≤ {@link #MAX_DEPTH}) it is a nested <b>message</b>;</li>
 *   <li>otherwise it is <b>bytes</b> (hex), annotated with a packed-varint reading when one exists, since packed
 *       repeated scalars are indistinguishable from bytes without a schema.</li>
 * </ol>
 *
 * <p>Parsing is bounded: recursion depth, total field count ({@link #MAX_FIELDS}) and rendered string/hex sizes are
 * capped. Nothing is allocated from an untrusted length without checking it against the remaining input.</p>
 */
final class Protobuf {

    static final int MAX_DEPTH = 32;
    static final int MAX_FIELDS = 50_000;
    static final int MAX_FIELD_NUMBER = (1 << 29) - 1;
    /** Nested-message guesses with larger field numbers are rejected (random bytes tend to produce huge ones). */
    static final int MAX_NESTED_FIELD = 1 << 16;
    static final int MAX_STRING_CHARS = 8192;
    static final int MAX_HEX_BYTES = 256;
    static final int MAX_PACKED_SHOWN = 64;

    static final int VARINT = 0, I64 = 1, LEN = 2, SGROUP = 3, EGROUP = 4, I32 = 5;

    enum LenKind { EMPTY, STRING, MESSAGE, BYTES }

    /** One decoded field. For LEN fields the payload is {@code src[start, start+length)}. */
    static final class Field {
        final int number;
        final int wireType;
        final int offset;
        final long value;
        final byte[] src;
        final int start;
        final int length;
        LenKind kind;
        String text;
        List<Field> nested;

        Field(int number, int wireType, int offset, long value, byte[] src, int start, int length) {
            this.number = number;
            this.wireType = wireType;
            this.offset = offset;
            this.value = value;
            this.src = src;
            this.start = start;
            this.length = length;
        }
    }

    /** Result of a top-level (lenient) parse. {@code error} is null when every byte was consumed. */
    static final class Parsed {
        final List<Field> fields;
        final int stoppedAt;
        final int end;
        final String error;
        final boolean limitReached;

        Parsed(List<Field> fields, int stoppedAt, int end, String error, boolean limitReached) {
            this.fields = fields;
            this.stoppedAt = stoppedAt;
            this.end = end;
            this.error = error;
            this.limitReached = limitReached;
        }

        boolean complete() { return error == null; }
    }

    private static final class ParseError extends Exception {
        final int offset;

        ParseError(int offset, String message) {
            super(message, null, false, false);
            this.offset = offset;
        }
    }

    private static final class Budget {
        int used;
        boolean exhausted;
    }

    private Protobuf() {
    }

    // ------------------------------------------------------------------ parsing

    static Parsed parse(byte[] b) {
        return parse(b, 0, b.length);
    }

    /**
     * Parses a message leniently: on the first malformed field it stops and reports the error, keeping every field
     * decoded so far.
     */
    static Parsed parse(byte[] b, int off, int len) {
        Budget budget = new Budget();
        List<Field> out = new ArrayList<>();
        int end = off + len;
        int pos = off;
        String error = null;
        while (pos < end) {
            if (budget.used >= MAX_FIELDS) {
                budget.exhausted = true;
                error = "field limit (" + MAX_FIELDS + ") reached";
                break;
            }
            try {
                int[] cursor = {pos};
                Field f = readField(b, cursor, end, MAX_FIELD_NUMBER);
                budget.used++;
                if (f.wireType == LEN) classify(f, 0, budget);
                out.add(f);
                pos = cursor[0];
            } catch (ParseError e) {
                error = e.getMessage() + " at offset " + (e.offset - off);
                break;
            }
        }
        return new Parsed(out, pos - off, len, error, budget.exhausted);
    }

    /** Strict parse used for nested-message guesses: null unless the whole range is a plausible message. */
    private static List<Field> tryNested(byte[] b, int off, int len, int depth, Budget budget) {
        int saved = budget.used;
        List<Field> out = new ArrayList<>();
        int end = off + len;
        int[] cursor = {off};
        try {
            while (cursor[0] < end) {
                if (budget.used >= MAX_FIELDS) {
                    budget.exhausted = true;
                    budget.used = saved;
                    return null;
                }
                Field f = readField(b, cursor, end, MAX_NESTED_FIELD);
                budget.used++;
                out.add(f);
            }
        } catch (ParseError e) {
            budget.used = saved;
            return null;
        }
        // Only classify children once the level as a whole is known to be valid (keeps the work linear per level).
        for (Field f : out) if (f.wireType == LEN) classify(f, depth, budget);
        return out;
    }

    private static Field readField(byte[] b, int[] cursor, int end, int maxField) throws ParseError {
        int fieldStart = cursor[0];
        long tag = readVarint(b, cursor, end);
        if (tag < 0 || tag > 0xFFFFFFFFL) throw new ParseError(fieldStart, "tag varint out of range");
        int wire = (int) (tag & 7);
        long number = tag >>> 3;
        if (number == 0) throw new ParseError(fieldStart, "invalid field number 0");
        if (number > maxField) throw new ParseError(fieldStart, "field number " + number + " out of range");
        int n = (int) number;
        switch (wire) {
            case VARINT -> {
                long v = readVarint(b, cursor, end);
                return new Field(n, wire, fieldStart, v, b, 0, 0);
            }
            case I64 -> {
                int p = cursor[0];
                if (end - p < 8) throw new ParseError(fieldStart, "truncated 64-bit field " + n);
                long v = 0;
                for (int i = 7; i >= 0; i--) v = (v << 8) | (b[p + i] & 0xffL);
                cursor[0] = p + 8;
                return new Field(n, wire, fieldStart, v, b, 0, 0);
            }
            case I32 -> {
                int p = cursor[0];
                if (end - p < 4) throw new ParseError(fieldStart, "truncated 32-bit field " + n);
                long v = 0;
                for (int i = 3; i >= 0; i--) v = (v << 8) | (b[p + i] & 0xffL);
                cursor[0] = p + 4;
                return new Field(n, wire, fieldStart, v, b, 0, 0);
            }
            case LEN -> {
                long l = readVarint(b, cursor, end);
                int p = cursor[0];
                if (l < 0 || l > end - p) {
                    throw new ParseError(fieldStart, "field " + n + " length " + Long.toUnsignedString(l)
                            + " exceeds remaining " + (end - p) + " bytes");
                }
                cursor[0] = p + (int) l;
                return new Field(n, wire, fieldStart, l, b, p, (int) l);
            }
            case SGROUP, EGROUP -> throw new ParseError(fieldStart, "deprecated group wire type " + wire + " (field " + n + ")");
            default -> throw new ParseError(fieldStart, "invalid wire type " + wire + " (field " + n + ")");
        }
    }

    private static long readVarint(byte[] b, int[] cursor, int end) throws ParseError {
        int p = cursor[0];
        long result = 0;
        for (int i = 0; i < 10; i++) {
            if (p >= end) throw new ParseError(cursor[0], "truncated varint");
            int c = b[p++] & 0xff;
            if (i == 9 && c > 1) throw new ParseError(cursor[0], "varint overflows 64 bits");
            result |= (long) (c & 0x7f) << (7 * i);
            if ((c & 0x80) == 0) {
                cursor[0] = p;
                return result;
            }
        }
        throw new ParseError(cursor[0], "varint longer than 10 bytes");
    }

    private static void classify(Field f, int depth, Budget budget) {
        if (f.length == 0) {
            f.kind = LenKind.EMPTY;
            return;
        }
        String text = printableUtf8(f.src, f.start, f.length);
        boolean leadingControl = (f.src[f.start] & 0xff) < 0x20;
        if (text != null && !leadingControl) {
            f.kind = LenKind.STRING;
            f.text = text;
            return;
        }
        List<Field> nested = depth + 1 < MAX_DEPTH ? tryNested(f.src, f.start, f.length, depth + 1, budget) : null;
        if (nested != null) {
            f.kind = LenKind.MESSAGE;
            f.nested = nested;
        } else if (text != null) {
            f.kind = LenKind.STRING;
            f.text = text;
        } else {
            f.kind = LenKind.BYTES;
        }
    }

    /** Decodes the range as UTF-8 and returns it if valid and free of control characters, else null. */
    static String printableUtf8(byte[] b, int off, int len) {
        CharsetDecoder dec = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        CharBuffer cb;
        try {
            cb = dec.decode(ByteBuffer.wrap(b, off, len));
        } catch (CharacterCodingException e) {
            return null;
        }
        for (int i = 0; i < cb.length(); i++) {
            char c = cb.charAt(i);
            if (c == '\t' || c == '\n' || c == '\r') continue;
            if (c < 0x20 || (c >= 0x7f && c < 0xa0) || c == '�' || c == '﻿') return null;
        }
        return cb.toString();
    }

    /** Reads the range as packed varints; null unless it decodes exactly. */
    static List<Long> packedVarints(byte[] b, int off, int len) {
        List<Long> out = new ArrayList<>();
        int end = off + len;
        int[] cursor = {off};
        try {
            while (cursor[0] < end) {
                out.add(readVarint(b, cursor, end));
                if (out.size() > 100_000) return null;
            }
        } catch (ParseError e) {
            return null;
        }
        return out.isEmpty() ? null : out;
    }

    // ------------------------------------------------------------------ rendering

    /** Adds one child per field to {@code parent}. */
    static void render(List<Field> fields, DecodedNode parent) {
        for (Field f : fields) parent.add(node(f));
    }

    static DecodedNode node(Field f) {
        String name = Integer.toString(f.number);
        return switch (f.wireType) {
            case VARINT -> DecodedNode.leaf(name, describeVarint(f.value), DecodedNode.Type.NUMBER);
            case I64 -> DecodedNode.leaf(name, describeFixed64(f.value), DecodedNode.Type.NUMBER);
            case I32 -> DecodedNode.leaf(name, describeFixed32((int) f.value), DecodedNode.Type.NUMBER);
            default -> lenNode(name, f);
        };
    }

    private static DecodedNode lenNode(String name, Field f) {
        LenKind kind = f.kind == null ? LenKind.BYTES : f.kind;
        switch (kind) {
            case EMPTY:
                return DecodedNode.leaf(name, "", DecodedNode.Type.STRING);
            case STRING:
                return DecodedNode.leaf(name, Codecs.truncate(f.text, MAX_STRING_CHARS), DecodedNode.Type.STRING);
            case MESSAGE: {
                DecodedNode n = new DecodedNode(name, "message, " + f.nested.size() + plural(f.nested.size(), " field"),
                        DecodedNode.Type.OBJECT);
                render(f.nested, n);
                return n;
            }
            default: {
                String v = hex(f.src, f.start, f.length);
                List<Long> packed = packedVarints(f.src, f.start, f.length);
                if (packed != null && packed.size() > 1) v += "  — as packed varints: " + formatPacked(packed);
                return DecodedNode.leaf(name, v, DecodedNode.Type.BINARY);
            }
        }
    }

    static String describeVarint(long v) {
        StringBuilder sb = new StringBuilder(Long.toUnsignedString(v));
        List<String> alt = new ArrayList<>();
        if (v < 0) alt.add("int64 " + v);
        // Zigzag (sint32/sint64): odd values encode negatives. Skipped for 1 (far more often true / enum 1) and for
        // values with the top bit set (those are sign-extended int32/int64 negatives, not zigzag).
        if ((v & 1) == 1 && v > 1) alt.add("sint " + ((v >>> 1) ^ -(v & 1)));
        if (!alt.isEmpty()) sb.append(" (").append(String.join(", ", alt)).append(')');
        return sb.toString();
    }

    static String describeFixed64(long v) {
        StringBuilder sb = new StringBuilder(Long.toUnsignedString(v));
        List<String> alt = new ArrayList<>();
        if (v < 0) alt.add("int64 " + v);
        double d = Double.longBitsToDouble(v);
        if (plausibleFloat(d)) alt.add("double " + d);
        alt.add(String.format("0x%016x", v));
        sb.append(" (").append(String.join(", ", alt)).append(')');
        return sb.toString();
    }

    static String describeFixed32(int v) {
        StringBuilder sb = new StringBuilder(Integer.toUnsignedString(v));
        List<String> alt = new ArrayList<>();
        if (v < 0) alt.add("int32 " + v);
        float fl = Float.intBitsToFloat(v);
        if (plausibleFloat(fl)) alt.add("float " + fl);
        alt.add(String.format("0x%08x", v));
        sb.append(" (").append(String.join(", ", alt)).append(')');
        return sb.toString();
    }

    /** Zero, or a finite value of "everyday" magnitude; denormals and astronomic values are probably integers. */
    private static boolean plausibleFloat(double d) {
        if (d == 0) return true;
        if (Double.isNaN(d) || Double.isInfinite(d)) return false;
        double a = Math.abs(d);
        return a >= 1e-9 && a <= 1e15;
    }

    private static String formatPacked(List<Long> values) {
        StringBuilder sb = new StringBuilder("[");
        int n = Math.min(values.size(), MAX_PACKED_SHOWN);
        for (int i = 0; i < n; i++) {
            if (i > 0) sb.append(", ");
            sb.append(Long.toUnsignedString(values.get(i)));
        }
        if (values.size() > n) sb.append(", … ").append(values.size()).append(" values");
        return sb.append(']').toString();
    }

    static String hex(byte[] b, int off, int len) {
        int n = Math.min(len, MAX_HEX_BYTES);
        StringBuilder sb = new StringBuilder(n * 3 + 24);
        for (int i = 0; i < n; i++) {
            if (i > 0) sb.append(' ');
            int c = b[off + i] & 0xff;
            sb.append(Character.forDigit(c >> 4, 16)).append(Character.forDigit(c & 15, 16));
        }
        if (len > n) sb.append(" … (").append(len).append(" bytes)");
        return sb.toString();
    }

    static String plural(int n, String word) {
        return n == 1 ? word : word + "s";
    }
}
