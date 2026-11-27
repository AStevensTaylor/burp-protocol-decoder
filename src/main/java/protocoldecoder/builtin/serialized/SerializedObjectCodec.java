package protocoldecoder.builtin.serialized;

import protocoldecoder.builtin.serialized.SerializedObjectScanner.Loc;
import protocoldecoder.builtin.serialized.SerializedObjectScanner.Value;
import protocoldecoder.builtin.serialized.Sniffer.Format;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.edit.EditableDocument;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.edit.MessageCodec;
import protocoldecoder.edit.MessagePatch;

import java.io.ByteArrayOutputStream;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

/**
 * Document editing for PHP {@code serialize()} payloads: the raw serialized text, wherever the scanner can put a value
 * back (query / form parameter, cookie, header, body or a token embedded in the body), with every wrapper restored
 * (percent-encoding, base64 variant, hex, gzip; see {@link Wrapping}).
 *
 * <p>The text is the payload exactly; {@code encode(text())} returns the original part unchanged. On encode the text
 * must parse with {@link PhpParser}. If it does not, string lengths ({@code s:N:} / {@code E:N:} / class names) and
 * array / object member counts are recomputed by a lenient re-parse (the "lengths auto-fixed" in the title), so
 * changing a string's content without fixing its length just works. Nothing else is rewritten.</p>
 *
 * <p>Binary formats (Java, .NET BinaryFormatter, pickle, Ruby Marshal) get no document: their strings are already
 * editable as fields, and a whole-stream text form would not be meaningfully editable. Signed values (Rails, Django,
 * itsdangerous) are not offered because the signature cannot be recomputed.</p>
 */
public final class SerializedObjectCodec implements MessageCodec {

    private static final int MAX_DOCS = 10;
    private static final int MAX_TEXT = 4 * 1024 * 1024;

    @Override
    public String decoderId() {
        return SerializedObjectDecoder.ID;
    }

    @Override
    public List<EditableDocument> documents(MessageContext m, DecodeResult decoded) {
        if (decoded == null || m == null) return List.of();
        List<EditableDocument> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        try {
            for (Value v : SerializedObjectScanner.values(m)) {
                if (out.size() >= MAX_DOCS) break;
                if (v.loc() == Loc.SET_COOKIE) continue;
                Wrapping.Peeled p = switch (v.loc()) {
                    case BODY -> Wrapping.peelBytes(v.bytes());
                    case QUERY, FORM -> Wrapping.peelText(v.text(), false);
                    default -> Wrapping.peelText(v.raw(), true);
                };
                if (p == null || p.format() != Format.PHP || p.payload().length > MAX_TEXT) continue;
                if (signed(v)) continue;
                if (!seen.add(Arrays.hashCode(p.payload()) + ":" + p.payload().length)) continue;
                String text = strictUtf8(p.payload());
                if (text == null) continue;
                ParseOutput po = PhpParser.parse(p.payload(), new ParseOutput.Budget(200_000));
                if (!po.complete || trailing(po)) continue;
                List<Wrapping.Layer> layers = SerializedObjectScanner.layersFor(v, p);
                if (layers == null) continue;
                Function<byte[], byte[]> place = SerializedObjectScanner.placer(m, v);
                if (place == null) continue;
                MessagePatch original = originalPatch(m, v);
                if (original == null) continue;
                out.add(new PhpDoc("PHP serialized: " + v.shortWhere() + " (lengths auto-fixed)", text, v, layers, place, original));
            }
        } catch (RuntimeException e) {
            return out;
        }
        return out;
    }

    private static boolean signed(Value v) {
        Sniffer.Detection d = v.loc() == Loc.BODY
                ? Sniffer.inspectBytes(v.bytes(), Sniffer.Origin.BODY, null, false)
                : Sniffer.inspect(v.text(), v.origin(), v.name(), false);
        return d != null && d.encoding() != null && d.encoding().contains("signed");
    }

    private static boolean trailing(ParseOutput po) {
        for (String n : po.notes) if (n.contains("after the serialized value")) return true;
        return false;
    }

    private static String strictUtf8(byte[] b) {
        try {
            return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(b)).toString();
        } catch (CharacterCodingException e) {
            return null; // binary bytes in strings: not editable as text without corrupting them
        }
    }

    /** The part of the message holding the value, exactly as it is now. */
    private static MessagePatch originalPatch(MessageContext m, Value v) {
        return switch (v.loc()) {
            case QUERY -> MessagePatch.query(m.query() == null ? "" : m.query());
            case FORM, BODY, EMBEDDED -> MessagePatch.body(m.body());
            case HEADER -> {
                for (Header h : m.headers()) {
                    if (h.name().equalsIgnoreCase(v.name())) yield MessagePatch.header(v.name(), h.value());
                }
                yield null;
            }
            case COOKIE -> {
                for (Header h : m.requestHeaders()) {
                    if (!h.name().equalsIgnoreCase("Cookie")) continue;
                    String[] segs = h.value().split(";", -1);
                    if (v.index() < segs.length && segs[v.index()].contains("=")
                            && segs[v.index()].substring(segs[v.index()].indexOf('=') + 1).strip().equals(v.raw())) {
                        yield MessagePatch.header("Cookie", h.value());
                    }
                }
                yield null;
            }
            default -> null;
        };
    }

    private static MessagePatch patch(Value v, byte[] content) {
        return switch (v.loc()) {
            case QUERY -> MessagePatch.query(new String(content, StandardCharsets.ISO_8859_1));
            case COOKIE -> MessagePatch.header("Cookie", new String(content, StandardCharsets.UTF_8));
            case HEADER -> MessagePatch.header(v.name(), new String(content, StandardCharsets.UTF_8));
            default -> MessagePatch.body(content);
        };
    }

    private static final class PhpDoc implements EditableDocument {
        private final String title;
        private final String text;
        private final Value value;
        private final List<Wrapping.Layer> layers;
        private final Function<byte[], byte[]> place;
        private final MessagePatch original;

        PhpDoc(String title, String text, Value value, List<Wrapping.Layer> layers, Function<byte[], byte[]> place, MessagePatch original) {
            this.title = title;
            this.text = text;
            this.value = value;
            this.layers = layers;
            this.place = place;
            this.original = original;
        }

        @Override public String title() { return title; }
        @Override public String text() { return text; }

        @Override
        public MessagePatch encode(String editedText) throws EncodeException {
            if (editedText == null) throw new EncodeException("Nothing to encode");
            if (editedText.equals(text)) return original;
            byte[] payload = toPayload(editedText);
            try {
                return patch(value, place.apply(Wrapping.wrap(payload, layers)));
            } catch (RuntimeException e) {
                throw new EncodeException("Could not re-encode the PHP payload: " + e.getMessage(), e);
            }
        }
    }

    /** Validates the edited serialize() text, auto-fixing lengths and counts when it does not parse as written. */
    static byte[] toPayload(String edited) throws EncodeException {
        byte[] b = edited.getBytes(StandardCharsets.UTF_8);
        String error = strictError(b);
        if (error == null) return b;
        byte[] fixed;
        try {
            fixed = new LengthFixer(b).fix();
        } catch (Bin.FormatException e) {
            throw new EncodeException("PHP serialized data is invalid: " + error + " (automatic length fixing also failed: " + e.getMessage() + ")");
        }
        String again = strictError(fixed);
        if (again != null) throw new EncodeException("PHP serialized data is invalid: " + error);
        return fixed;
    }

    private static String strictError(byte[] b) {
        ParseOutput po = PhpParser.parse(b, new ParseOutput.Budget(Integer.MAX_VALUE));
        if (!po.complete) return po.stopReason;
        for (String n : po.notes) if (n.contains("after the serialized value")) return n;
        return null;
    }

    /**
     * Lenient re-parse of serialize() text that recomputes {@code s:}/{@code E:}/class-name byte lengths and
     * {@code a:}/{@code O:} member counts. A string ends at the first {@code ";} (or {@code ":} for class names) that
     * is followed by something that can continue the stream; the declared length is preferred when it lands on such
     * a terminator.
     */
    static final class LengthFixer {
        private final byte[] s;
        private final ByteArrayOutputStream out;
        private int pos;
        private static final int MAX_DEPTH = 64;

        LengthFixer(byte[] s) {
            this.s = s;
            this.out = new ByteArrayOutputStream(s.length + 16);
        }

        byte[] fix() throws Bin.FormatException {
            value(0);
            if (pos != s.length) throw err("unexpected data after the value");
            return out.toByteArray();
        }

        private void value(int depth) throws Bin.FormatException {
            if (depth > MAX_DEPTH) throw err("nesting too deep");
            if (pos >= s.length) throw err("truncated");
            char t = (char) s[pos];
            switch (t) {
                case 'N' -> {
                    expect("N;");
                    write("N;");
                }
                case 'b', 'i', 'd', 'r', 'R' -> {
                    int semi = indexOf(';', pos);
                    if (semi < 0 || s[pos + 1] != ':') throw err("bad scalar");
                    out.write(s, pos, semi + 1 - pos);
                    pos = semi + 1;
                }
                case 's', 'E' -> {
                    pos++;
                    byte[] str = string(';');
                    expectByte(';');
                    writeString(t, str);
                    write(";");
                }
                case 'a' -> {
                    pos++;
                    expectByte(':');
                    skipDigits();
                    expectByte(':');
                    expectByte('{');
                    ByteArrayOutputStream saved = swap();
                    int n = members(depth);
                    byte[] inner = restore(saved);
                    write("a:" + n + ":{");
                    out.writeBytes(inner);
                    write("}");
                }
                case 'O' -> {
                    pos++;
                    byte[] cls = string(':');
                    expectByte(':');
                    skipDigits();
                    expectByte(':');
                    expectByte('{');
                    ByteArrayOutputStream saved = swap();
                    int n = members(depth);
                    byte[] inner = restore(saved);
                    writeString('O', cls);
                    write(":" + n + ":{");
                    out.writeBytes(inner);
                    write("}");
                }
                case 'C' -> {
                    // Custom serialized data: length kept only when it is consistent (no safe way to guess it).
                    pos++;
                    byte[] cls = string(':');
                    expectByte(':');
                    int lenStart = pos;
                    skipDigits();
                    int len = Integer.parseInt(new String(s, lenStart, pos - lenStart, StandardCharsets.US_ASCII));
                    expectByte(':');
                    expectByte('{');
                    int end;
                    if (pos + len < s.length && s[pos + len] == '}') end = pos + len;
                    else throw err("custom (C:) data length does not match; fix it by hand");
                    writeString('C', cls);
                    write(":" + (end - pos) + ":{");
                    out.write(s, pos, end - pos);
                    write("}");
                    pos = end + 1;
                }
                default -> throw err("unknown type '" + (t >= 0x20 && t < 0x7f ? String.valueOf(t) : String.format("\\x%02x", (int) t)) + "'");
            }
        }

        private int members(int depth) throws Bin.FormatException {
            int n = 0;
            while (true) {
                if (pos >= s.length) throw err("truncated: expected '}'");
                if (s[pos] == '}') {
                    pos++;
                    return n;
                }
                char k = (char) s[pos];
                if (k != 'i' && k != 's') throw err("array key must be an int or string");
                value(depth + 1); // key
                value(depth + 1);
                n++;
            }
        }

        /** After the type letter: {@code :<len>:"<bytes>"}; returns the bytes, leaves pos after the closing quote. */
        private byte[] string(char terminator) throws Bin.FormatException {
            expectByte(':');
            int lenStart = pos;
            skipDigits();
            long declared = Long.parseLong(new String(s, lenStart, pos - lenStart, StandardCharsets.US_ASCII));
            expectByte(':');
            expectByte('"');
            int start = pos;
            int end = -1;
            if (declared <= s.length - start - 2) {
                int e = start + (int) declared;
                if (s[e] == '"' && s[e + 1] == terminator && continues(e + 2, terminator)) end = e;
            }
            if (end < 0) {
                for (int j = start; j + 1 < s.length; j++) {
                    if (s[j] == '"' && s[j + 1] == terminator && continues(j + 2, terminator)) {
                        end = j;
                        break;
                    }
                }
            }
            if (end < 0) throw err("unterminated string");
            pos = end + 1;
            return Arrays.copyOfRange(s, start, end);
        }

        /** Whether position {@code k} (after {@code ";} or {@code ":}) can continue a serialized stream. */
        private boolean continues(int k, char terminator) {
            if (terminator == ':') return k < s.length && Character.isDigit(s[k]);
            if (k == s.length) return true;
            char c = (char) s[k];
            if (c == '}') return true;
            if (k + 1 >= s.length) return false;
            char n = (char) s[k + 1];
            if (c == 'N') return n == ';';
            return "bidsSaOCErR".indexOf(c) >= 0 && n == ':';
        }

        private void writeString(char type, byte[] str) {
            write(type + ":" + str.length + ":\"");
            out.writeBytes(str);
            write("\"");
        }

        private ByteArrayOutputStream swap() {
            ByteArrayOutputStream saved = new ByteArrayOutputStream();
            saved.writeBytes(out.toByteArray());
            out.reset();
            return saved;
        }

        private byte[] restore(ByteArrayOutputStream saved) {
            byte[] inner = out.toByteArray();
            out.reset();
            out.writeBytes(saved.toByteArray());
            return inner;
        }

        private void skipDigits() throws Bin.FormatException {
            int start = pos;
            while (pos < s.length && pos - start < 10 && Character.isDigit(s[pos])) pos++;
            if (pos == start) throw err("expected a number");
        }

        private int indexOf(char c, int from) {
            for (int i = from; i < s.length && i - from < 64; i++) if (s[i] == c) return i;
            return -1;
        }

        private void expect(String lit) throws Bin.FormatException {
            for (int i = 0; i < lit.length(); i++) expectByte(lit.charAt(i));
        }

        private void expectByte(char c) throws Bin.FormatException {
            if (pos >= s.length || s[pos] != c) throw err("expected '" + c + "'");
            pos++;
        }

        private void write(String ascii) {
            out.writeBytes(ascii.getBytes(StandardCharsets.UTF_8));
        }

        private Bin.FormatException err(String m) {
            return new Bin.FormatException(m + " at offset " + pos);
        }
    }
}
