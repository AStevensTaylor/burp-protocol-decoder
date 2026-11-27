package protocoldecoder.builtin.serialized;

import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * Recursive parser for PHP {@code serialize()} output. Builds a tree of arrays, objects and scalars and records every
 * object class name ({@code O:}, {@code C:} and enum {@code E:}). Lengths are byte counts, so the input is handled
 * as bytes.
 */
final class PhpParser {

    /** Strong start of a serialized array/object/enum. */
    static final Pattern STRONG_START = Pattern.compile("^(?:a:\\d{1,9}:\\{|O:\\d{1,4}:\"|C:\\d{1,4}:\"|E:\\d{1,4}:\")");
    /** Serialized string scalar (weaker: harmless on its own, but still serialize() output). */
    static final Pattern STRING_START = Pattern.compile("^s:\\d{1,9}:\"");

    private static final int MAX_DEPTH = 64;
    private static final int MAX_STRING_SHOWN = 2000;

    private final byte[] s;
    private final ParseOutput.Budget budget;
    private final ParseOutput out;
    private int pos;
    /** Labels from the root to the current value, for insertion point paths. */
    private final java.util.List<String> trail = new java.util.ArrayList<>();

    private PhpParser(byte[] s, ParseOutput.Budget budget, ParseOutput out) {
        this.s = s;
        this.budget = budget;
        this.out = out;
    }

    static ParseOutput parse(String text, ParseOutput.Budget budget) {
        return parse(text.getBytes(StandardCharsets.UTF_8), budget);
    }

    static ParseOutput parse(byte[] data, ParseOutput.Budget budget) {
        ParseOutput out = new ParseOutput("Value");
        PhpParser p = new PhpParser(data, budget, out);
        try {
            p.value(out.structure, "value", 0);
            if (p.pos < data.length) {
                String rest = new String(data, p.pos, Math.min(80, data.length - p.pos), StandardCharsets.UTF_8);
                if (!rest.isBlank()) out.notes.add((data.length - p.pos) + " bytes after the serialized value: " + rest);
            }
        } catch (Bin.FormatException e) {
            out.stop(e.getMessage());
        }
        return out;
    }

    private void value(DecodedNode parent, String label, int depth) throws Bin.FormatException {
        if (depth > MAX_DEPTH) throw err("nesting deeper than " + MAX_DEPTH);
        trail.add(label);
        try {
            valueBody(parent, label, depth);
        } finally {
            trail.remove(trail.size() - 1);
        }
    }

    private void valueBody(DecodedNode parent, String label, int depth) throws Bin.FormatException {
        int at = pos;
        char t = (char) u8();
        switch (t) {
            case 'N' -> {
                expect(';');
                budget.add(parent, DecodedNode.leaf(label, "null", DecodedNode.Type.NULL));
            }
            case 'b' -> {
                expect(':');
                String v = until(';');
                if (!v.equals("0") && !v.equals("1")) throw err("bad boolean '" + v + "'");
                budget.add(parent, DecodedNode.leaf(label, v.equals("1") ? "true" : "false", DecodedNode.Type.BOOLEAN));
            }
            case 'i' -> {
                expect(':');
                String v = until(';');
                if (!v.matches("[+-]?\\d{1,20}")) throw err("bad integer '" + v + "'");
                out.span(at, pos - 1, v, trail, 'i');
                budget.add(parent, DecodedNode.leaf(label, v, DecodedNode.Type.NUMBER));
            }
            case 'd' -> {
                expect(':');
                String v = until(';');
                if (!v.matches("[+-]?(\\d+\\.?\\d*([eE][+-]?\\d+)?|\\.\\d+([eE][+-]?\\d+)?|INF|NAN)")) throw err("bad float '" + v + "'");
                budget.add(parent, DecodedNode.leaf(label, v, DecodedNode.Type.NUMBER));
            }
            case 's', 'S' -> {
                String v = t == 's' ? string() : escapedString();
                if (t == 's') out.span(at, pos, v, trail, 's');
                expect(';');
                budget.add(parent, DecodedNode.leaf(label, Codecs.truncate(v, MAX_STRING_SHOWN)));
            }
            case 'a' -> {
                expect(':');
                int n = count();
                expect(':');
                expect('{');
                DecodedNode node = budget.add(parent, new DecodedNode(label, "array(" + n + ")", DecodedNode.Type.OBJECT));
                members(node, n, null, depth);
                expect('}');
            }
            case 'O' -> {
                String cls = string();
                expect(':');
                int n = count();
                expect(':');
                expect('{');
                out.type(cls);
                DecodedNode node = budget.add(parent, new DecodedNode(label, "object " + cls, DecodedNode.Type.OBJECT));
                risk(node, cls);
                members(node, n, cls, depth);
                expect('}');
            }
            case 'C' -> {
                String cls = string();
                expect(':');
                int len = count();
                expect(':');
                expect('{');
                if (len > s.length - pos) throw err("custom data length " + len + " exceeds the remaining data");
                byte[] data = java.util.Arrays.copyOfRange(s, pos, pos + len);
                pos += len;
                expect('}');
                out.type(cls);
                DecodedNode node = budget.add(parent, new DecodedNode(label, "object " + cls + " (custom Serializable)", DecodedNode.Type.OBJECT));
                risk(node, cls);
                nested(node, data, depth);
            }
            case 'E' -> {
                String v = string();
                expect(';');
                int colon = v.indexOf(':');
                out.type(colon > 0 ? v.substring(0, colon) : v);
                budget.add(parent, DecodedNode.leaf(label, v + "  (enum)"));
            }
            case 'r', 'R' -> {
                expect(':');
                String v = until(';');
                if (!v.matches("\\d{1,9}")) throw err("bad reference '" + v + "'");
                budget.add(parent, DecodedNode.leaf(label, (t == 'R' ? "&ref #" : "→ #") + v));
            }
            default -> throw err("unknown type '" + printable(t) + "'");
        }
    }

    private void members(DecodedNode node, int n, String cls, int depth) throws Bin.FormatException {
        for (int i = 0; i < n; i++) {
            int at = pos;
            char kt = (char) u8();
            String key;
            if (kt == 'i') {
                expect(':');
                key = until(';');
                if (!key.matches("[+-]?\\d{1,20}")) throw err("bad integer key '" + key + "'");
                key = "[" + key + "]";
            } else if (kt == 's') {
                key = string();
                expect(';');
                if (cls != null) key = propertyName(key);
            } else {
                pos = at;
                throw err("array key must be an int or string, found '" + printable(kt) + "'");
            }
            value(node, key, depth + 1);
        }
    }

    /** Custom C: payloads are usually serialize() data themselves; show them parsed when that works. */
    private void nested(DecodedNode node, byte[] data, int depth) throws Bin.FormatException {
        if (data.length == 0) return;
        ParseOutput inner = new ParseOutput("data");
        PhpParser p = new PhpParser(data, budget, inner);
        try {
            DecodedNode holder = DecodedNode.object("data");
            p.value(holder, "data", depth + 1);
            if (p.pos == data.length) {
                for (DecodedNode c : holder.children()) node.add(c);
                inner.types.forEach(out::type);
                return;
            }
        } catch (Bin.LimitException e) {
            throw e;
        } catch (Bin.FormatException ignored) {
            // not nested serialize() data
        }
        budget.add(node, DecodedNode.leaf("data", Codecs.truncate(new String(data, StandardCharsets.UTF_8), MAX_STRING_SHOWN)));
    }

    /** PHP mangles non-public property names: "\0*\0name" (protected), "\0Class\0name" (private). */
    private static String propertyName(String k) {
        if (k.length() > 1 && k.charAt(0) == '\0') {
            int second = k.indexOf('\0', 1);
            if (second > 0) {
                String owner = k.substring(1, second);
                String name = k.substring(second + 1);
                return owner.equals("*") ? name + " (protected)" : name + " (private " + owner + ")";
            }
        }
        return k;
    }

    private void risk(DecodedNode node, String cls) throws Bin.LimitException {
        String r = RiskyTypes.reason(cls);
        if (r != null) budget.add(node, DecodedNode.leaf("⚠ risk", r));
    }

    /** {@code <len>:"<bytes>"} (after the type letter, the ':' is consumed here). */
    private String string() throws Bin.FormatException {
        expect(':');
        int len = count();
        expect(':');
        expect('"');
        if (len > s.length - pos) throw err("string length " + len + " exceeds the remaining data");
        String v = new String(s, pos, len, StandardCharsets.UTF_8);
        pos += len;
        expect('"');
        return v;
    }

    /** S:<len>:"..." where non-printable bytes are written as \xx hex escapes. */
    private String escapedString() throws Bin.FormatException {
        expect(':');
        int len = count();
        expect(':');
        expect('"');
        if (len > s.length - pos) throw err("string length " + len + " exceeds the remaining data");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            int c = u8();
            if (c == '\\') {
                if (pos + 2 > s.length) throw err("truncated escape");
                String hex = new String(s, pos, 2, StandardCharsets.ISO_8859_1);
                try {
                    c = Integer.parseInt(hex, 16);
                } catch (NumberFormatException e) {
                    throw err("bad escape \\" + hex);
                }
                pos += 2;
            }
            sb.append((char) c);
        }
        expect('"');
        return sb.toString();
    }

    private int count() throws Bin.FormatException {
        String v = until(':');
        if (!v.matches("\\d{1,9}")) throw err("bad length '" + v + "'");
        int n = Integer.parseInt(v);
        if (n > s.length) throw err("count " + n + " exceeds the input size");
        // The ':' is pushed back so callers can expect() it, keeping the grammar readable.
        pos--;
        return n;
    }

    /** Reads up to (not including) the terminator and consumes the terminator. */
    private String until(char term) throws Bin.FormatException {
        int start = pos;
        int limit = Math.min(s.length, pos + 64);
        while (pos < limit && s[pos] != term) pos++;
        if (pos >= limit) throw err("expected '" + term + "'");
        String v = new String(s, start, pos - start, StandardCharsets.ISO_8859_1);
        pos++;
        return v;
    }

    private void expect(char c) throws Bin.FormatException {
        if (pos >= s.length) throw err("truncated: expected '" + c + "'");
        if (s[pos] != c) throw err("expected '" + c + "' but found '" + printable((char) (s[pos] & 0xff)) + "'");
        pos++;
    }

    private int u8() throws Bin.FormatException {
        if (pos >= s.length) throw err("truncated");
        return s[pos++] & 0xff;
    }

    private Bin.FormatException err(String m) {
        return new Bin.FormatException(m + " at offset " + pos);
    }

    private static String printable(char c) {
        return c >= 0x20 && c < 0x7f ? String.valueOf(c) : String.format("\\x%02x", (int) c);
    }
}
