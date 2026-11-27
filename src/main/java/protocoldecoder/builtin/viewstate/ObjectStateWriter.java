package protocoldecoder.builtin.viewstate;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Minimal ObjectStateFormatter writer: replaces one string value of an existing stream (found with
 * {@link ObjectStateReader#spans(byte[])}) and re-encodes its 7-bit length prefix. Everything else is kept
 * byte-for-byte, so the rest of the graph (tokens, type and string tables, trailing bytes) stays valid.
 */
final class ObjectStateWriter {

    private ObjectStateWriter() {
    }

    /** BinaryWriter.Write7BitEncodedInt. */
    static void write7BitInt(ByteArrayOutputStream out, int v) {
        long u = v & 0xFFFF_FFFFL;
        while (u >= 0x80) {
            out.write((int) (u & 0x7f) | 0x80);
            u >>>= 7;
        }
        out.write((int) u);
    }

    /** BinaryWriter.Write(string) with UTF-8: 7-bit byte length, then the bytes. */
    static byte[] encodeString(String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream(b.length + 5);
        write7BitInt(out, b.length);
        out.writeBytes(b);
        return out.toByteArray();
    }

    /** Returns a copy of {@code data} with the string at {@code span} replaced by {@code value}. */
    static byte[] replace(byte[] data, ObjectStateReader.StringSpan span, String value) {
        byte[] enc = encodeString(value);
        ByteArrayOutputStream out = new ByteArrayOutputStream(data.length - (span.end() - span.start()) + enc.length);
        out.write(data, 0, span.start());
        out.writeBytes(enc);
        out.write(data, span.end(), data.length - span.end());
        return out.toByteArray();
    }
}
