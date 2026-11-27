package protocoldecoder.builtin.grpc;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Minimal protobuf rewriter for scanner insertion points. It enumerates the scalar leaves of a schemaless parse
 * ({@link Protobuf}) at any depth and rebuilds the message with one leaf replaced: only the bytes on the path to that
 * leaf change (the leaf itself plus the length prefix of every enclosing length-delimited field); every other field,
 * including unknown/unparsed trailing bytes, is copied byte-for-byte.
 *
 * <p>Payload encoding per leaf kind:</p>
 * <ul>
 *   <li><b>string</b> (and empty length-delimited fields): the payload as UTF-8 in the same field number;</li>
 *   <li><b>varint</b>: if the payload parses as a (signed or unsigned) 64-bit integer it is written as a varint
 *       (negative numbers as 10-byte two's complement, like int64);</li>
 *   <li><b>fixed64 / fixed32</b>: an integer payload is written as little-endian fixed bytes, a decimal payload as a
 *       double / float;</li>
 *   <li>for any numeric leaf, a payload that is not a number is written as a <b>length-delimited string with the same
 *       field number</b>. This wire-type confusion is deliberate: it lets Burp's text payloads reach the server, and how
 *       the server reacts to a type mismatch (ignored, rejected, or a parser exception) is itself informative.</li>
 * </ul>
 * Bytes fields that are neither text nor a nested message are not offered (binary data rarely reaches injectable code).
 */
final class ProtoEdit {

    /** One replaceable scalar. {@code rebuild} maps a payload to the complete new top-level message. */
    record Leaf(String path, String kind, String baseValue, Function<String, byte[]> rebuild) {
    }

    private ProtoEdit() {
    }

    static List<Leaf> leaves(byte[] msg, int max) {
        List<Leaf> out = new ArrayList<>();
        if (msg == null || msg.length == 0 || max <= 0) return out;
        Protobuf.Parsed p = Protobuf.parse(msg);
        if (p.fields.isEmpty()) return out;
        walk(msg, p.fields, 0, p.stoppedAt, msg.length, "", content -> content, out, max);
        return out;
    }

    /**
     * @param cStart  start of the container's content in {@code src}
     * @param lastEnd end of the last parsed field (== cEnd except for a partially parsed top level)
     * @param cEnd    end of the container's content
     * @param wrap    new container content → whole top-level message
     */
    private static void walk(byte[] src, List<Protobuf.Field> fields, int cStart, int lastEnd, int cEnd, String prefix,
                             Function<byte[], byte[]> wrap, List<Leaf> out, int max) {
        Map<Integer, Integer> counts = new HashMap<>();
        for (Protobuf.Field f : fields) counts.merge(f.number, 1, Integer::sum);
        Map<Integer, Integer> seen = new HashMap<>();
        for (int i = 0; i < fields.size() && out.size() < max; i++) {
            Protobuf.Field f = fields.get(i);
            int fStart = f.offset;
            int fEnd = i + 1 < fields.size() ? fields.get(i + 1).offset : lastEnd;
            int occurrence = seen.merge(f.number, 1, Integer::sum) - 1;
            String name = f.number + (counts.get(f.number) > 1 ? "[" + occurrence + "]" : "");
            String path = prefix.isEmpty() ? name : prefix + "." + name;
            Function<byte[], byte[]> replaceField = newField -> wrap.apply(concat(src, cStart, fStart, newField, fEnd, cEnd));
            switch (f.wireType) {
                case Protobuf.VARINT -> out.add(new Leaf(path, "varint", Long.toUnsignedString(f.value),
                        payload -> replaceField.apply(numeric(f.number, Protobuf.VARINT, payload))));
                case Protobuf.I64 -> out.add(new Leaf(path, "fixed64", Long.toUnsignedString(f.value),
                        payload -> replaceField.apply(numeric(f.number, Protobuf.I64, payload))));
                case Protobuf.I32 -> out.add(new Leaf(path, "fixed32", Integer.toUnsignedString((int) f.value),
                        payload -> replaceField.apply(numeric(f.number, Protobuf.I32, payload))));
                case Protobuf.LEN -> {
                    Protobuf.LenKind kind = f.kind == null ? Protobuf.LenKind.BYTES : f.kind;
                    switch (kind) {
                        case STRING, EMPTY -> out.add(new Leaf(path, "string", kind == Protobuf.LenKind.EMPTY ? "" : f.text,
                                payload -> replaceField.apply(lenField(f.number, utf8(payload)))));
                        case MESSAGE -> walk(src, f.nested, f.start, f.start + f.length, f.start + f.length, path,
                                content -> replaceField.apply(lenField(f.number, content)), out, max);
                        default -> {
                            // opaque bytes: not offered
                        }
                    }
                }
                default -> {
                    // groups are rejected by the parser
                }
            }
        }
    }

    // ------------------------------------------------------------------ encoding

    static byte[] numeric(int number, int wire, String payload) {
        String p = payload == null ? "" : payload.strip();
        Long asLong = parseLong(p);
        if (asLong != null) {
            if (wire == Protobuf.VARINT) return concat(tag(number, Protobuf.VARINT), varint(asLong));
            if (wire == Protobuf.I64) return concat(tag(number, Protobuf.I64), fixed(asLong, 8));
            long v = asLong;
            if (v >= Integer.MIN_VALUE && v <= 0xFFFFFFFFL) return concat(tag(number, Protobuf.I32), fixed(v, 4));
        } else if (wire != Protobuf.VARINT && p.matches("[-+]?(\\d+\\.?\\d*|\\.\\d+)([eE][-+]?\\d+)?")) {
            double d = Double.parseDouble(p);
            if (wire == Protobuf.I64) return concat(tag(number, Protobuf.I64), fixed(Double.doubleToRawLongBits(d), 8));
            return concat(tag(number, Protobuf.I32), fixed(Float.floatToRawIntBits((float) d) & 0xFFFFFFFFL, 4));
        }
        return lenField(number, utf8(payload == null ? "" : payload));
    }

    private static Long parseLong(String s) {
        if (s.isEmpty() || s.length() > 20) return null;
        try {
            return Long.parseLong(s);
        } catch (NumberFormatException e) {
            try {
                return Long.parseUnsignedLong(s);
            } catch (NumberFormatException e2) {
                return null;
            }
        }
    }

    static byte[] lenField(int number, byte[] content) {
        return concat(tag(number, Protobuf.LEN), varint(content.length), content);
    }

    static byte[] tag(int number, int wire) {
        return varint(((long) number << 3) | wire);
    }

    static byte[] varint(long v) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(10);
        while ((v & ~0x7fL) != 0) {
            o.write((int) ((v & 0x7f) | 0x80));
            v >>>= 7;
        }
        o.write((int) v);
        return o.toByteArray();
    }

    private static byte[] fixed(long v, int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = (byte) (v >>> (8 * i));
        return b;
    }

    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int pos = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }

    /** src[cStart, fStart) + middle + src[fEnd, cEnd). */
    private static byte[] concat(byte[] src, int cStart, int fStart, byte[] middle, int fEnd, int cEnd) {
        byte[] out = new byte[(fStart - cStart) + middle.length + (cEnd - fEnd)];
        System.arraycopy(src, cStart, out, 0, fStart - cStart);
        System.arraycopy(middle, 0, out, fStart - cStart, middle.length);
        System.arraycopy(src, fEnd, out, fStart - cStart + middle.length, cEnd - fEnd);
        return out;
    }
}
