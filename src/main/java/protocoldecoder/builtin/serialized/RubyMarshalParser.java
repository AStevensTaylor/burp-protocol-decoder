package protocoldecoder.builtin.serialized;

import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Read-only parser for Ruby {@code Marshal.dump} format 4.8: lists class/module names and symbols, best-effort. */
final class RubyMarshalParser {

    private static final int MAX_DEPTH = 64;
    private static final int MAX_SYMBOLS = 10_000;
    private static final int MAX_STRING_SHOWN = 2000;

    /** Type bytes that may follow the 04 08 header (used by the sniffer). */
    static boolean isTypeByte(int c) {
        return "0TFi:;\"I[{}ouUeCcmMlfS/@d".indexOf(c) >= 0;
    }

    private final Bin in;
    private final ParseOutput.Budget budget;
    private final ParseOutput out = new ParseOutput("Value");
    private final List<String> symbols = new ArrayList<>();
    private final Set<String> symbolList = new LinkedHashSet<>();
    private int objects;
    /** Labels from the root to the current value, for insertion point paths. */
    private final List<String> trail = new ArrayList<>();

    private RubyMarshalParser(byte[] data, ParseOutput.Budget budget) {
        this.in = new Bin(data);
        this.budget = budget;
    }

    static ParseOutput parse(byte[] data, ParseOutput.Budget budget) {
        RubyMarshalParser p = new RubyMarshalParser(data, budget);
        p.run();
        return p.out;
    }

    private void run() {
        try {
            int major = in.u8();
            int minor = in.u8();
            if (major != 4 || minor != 8) throw new Bin.FormatException("unsupported Marshal version " + major + "." + minor);
            out.structure.put("version", "4.8");
            value(out.structure, "value", 0);
            if (in.hasMore()) out.notes.add(in.remaining() + " bytes after the marshalled value");
        } catch (Bin.FormatException e) {
            out.stop(e.getMessage());
        }
        if (!symbolList.isEmpty()) {
            DecodedNode s = DecodedNode.array("Symbols");
            for (String sym : symbolList) {
                if (s.children().size() >= 300) {
                    s.add(DecodedNode.note((symbolList.size() - 300) + " more"));
                    break;
                }
                s.add(DecodedNode.leaf("", ":" + sym));
            }
            out.extras.add(s);
        }
    }

    private void value(DecodedNode parent, String label, int depth) throws Bin.FormatException {
        value(parent, label, label, depth);
    }

    /** {@code pathLabel} names the value in insertion point paths (a hash value is named by its key). */
    private void value(DecodedNode parent, String label, String pathLabel, int depth) throws Bin.FormatException {
        if (depth > MAX_DEPTH) throw new Bin.FormatException("nesting deeper than " + MAX_DEPTH + " at offset " + in.pos());
        trail.add(pathLabel);
        try {
            valueBody(parent, label, depth);
        } finally {
            trail.remove(trail.size() - 1);
        }
    }

    private void valueBody(DecodedNode parent, String label, int depth) throws Bin.FormatException {
        int at = in.pos();
        int t = in.u8();
        switch (t) {
            case '0' -> leaf(parent, label, "nil", DecodedNode.Type.NULL);
            case 'T' -> leaf(parent, label, "true", DecodedNode.Type.BOOLEAN);
            case 'F' -> leaf(parent, label, "false", DecodedNode.Type.BOOLEAN);
            case 'i' -> leaf(parent, label, Long.toString(rLong()), DecodedNode.Type.NUMBER);
            case ':', ';' -> leaf(parent, label, ":" + symbolAfter(t), DecodedNode.Type.STRING);
            case '"' -> {
                objects++;
                int start = in.pos();
                String s = rString();
                out.span(start, in.pos(), s, trail, 'R');
                leaf(parent, label, Codecs.truncate(s, MAX_STRING_SHOWN), DecodedNode.Type.STRING);
            }
            case 'I' -> { // value with instance variables (usually a String with its encoding)
                DecodedNode holder = DecodedNode.object("holder");
                String self = trail.remove(trail.size() - 1); // the wrapped value takes this value's place in the path
                try {
                    value(holder, label, self, depth + 1);
                } finally {
                    trail.add(self);
                }
                DecodedNode inner = holder.children().isEmpty() ? null : holder.children().get(0);
                long n = count();
                DecodedNode target = inner;
                if (inner != null) parent.add(inner);
                for (long i = 0; i < n; i++) {
                    String ivar = symbol();
                    if (target != null && target.isContainer()) value(target, ivar, depth + 1);
                    else value(new DecodedNode("discard", null, DecodedNode.Type.OBJECT), ivar, depth + 1);
                }
            }
            case '[' -> {
                objects++;
                long n = count();
                DecodedNode a = budget.add(parent, new DecodedNode(label, "Array(" + n + ")", DecodedNode.Type.ARRAY));
                for (long i = 0; i < n; i++) value(a, "[" + i + "]", depth + 1);
            }
            case '{', '}' -> {
                objects++;
                long n = count();
                DecodedNode h = budget.add(parent, new DecodedNode(label, "Hash(" + n + ")", DecodedNode.Type.OBJECT));
                for (long i = 0; i < n; i++) {
                    DecodedNode pair = budget.add(h, DecodedNode.object("[" + i + "]"));
                    value(pair, "key", "[" + i + "].key", depth + 1);
                    value(pair, "value", keyName(pair, i), depth + 1);
                }
                if (t == '}') value(h, "default", depth + 1);
            }
            case 'o' -> {
                objects++;
                String cls = classSymbol();
                long n = count();
                DecodedNode o = objNode(parent, label, cls, "object");
                for (long i = 0; i < n; i++) {
                    String ivar = symbol();
                    value(o, ivar, depth + 1);
                }
            }
            case 'S' -> {
                objects++;
                String cls = classSymbol();
                long n = count();
                DecodedNode o = objNode(parent, label, cls, "Struct");
                for (long i = 0; i < n; i++) {
                    String member = symbol();
                    value(o, member, depth + 1);
                }
            }
            case 'u' -> { // _dump
                objects++;
                String cls = classSymbol();
                byte[] data = in.bytes(count());
                DecodedNode o = objNode(parent, label, cls, "_dump data");
                budget.add(o, DecodedNode.leaf("data", Codecs.hexPreview(data, 64), DecodedNode.Type.BINARY));
            }
            case 'U' -> { // marshal_load
                objects++;
                String cls = classSymbol();
                DecodedNode o = objNode(parent, label, cls, "marshal_dump data");
                value(o, "data", depth + 1);
            }
            case 'e' -> { // extended by module
                String mod = classSymbol();
                DecodedNode o = objNode(parent, label, mod, "extended with module");
                value(o, "value", depth + 1);
            }
            case 'C' -> { // subclass of String/Array/Hash/Regexp
                String cls = classSymbol();
                DecodedNode o = objNode(parent, label, cls, "user class");
                value(o, "value", depth + 1);
            }
            case 'c', 'm', 'M' -> {
                objects++;
                String name = rString();
                out.type(name);
                leaf(parent, label, (t == 'c' ? "class " : "module ") + name + risk(name), DecodedNode.Type.STRING);
            }
            case 'd' -> {
                objects++;
                String cls = classSymbol();
                DecodedNode o = objNode(parent, label, cls, "T_DATA");
                value(o, "data", depth + 1);
            }
            case 'l' -> {
                objects++;
                int sign = in.u8();
                long shorts = count();
                byte[] b = in.bytes(shorts * 2);
                leaf(parent, label, (sign == '-' ? "-" : "") + "bignum " + Codecs.hexPreview(b, 16), DecodedNode.Type.NUMBER);
            }
            case 'f' -> {
                objects++;
                leaf(parent, label, Codecs.truncate(rString(), 64), DecodedNode.Type.NUMBER);
            }
            case '/' -> {
                objects++;
                String src = rString();
                int opts = in.u8();
                leaf(parent, label, "/" + Codecs.truncate(src, MAX_STRING_SHOWN) + "/ (options " + opts + ")", DecodedNode.Type.STRING);
            }
            case '@' -> {
                long ref = rLong();
                if (ref < 0 || ref > objects) throw new Bin.FormatException("bad object link @" + ref + " at offset " + at);
                leaf(parent, label, "→ object @" + ref, DecodedNode.Type.STRING);
            }
            default -> throw new Bin.FormatException(String.format("unknown type byte 0x%02x at offset %d", t, at));
        }
    }

    /** Path label for a hash value: its key when that is a plain string or symbol. */
    private static String keyName(DecodedNode pair, long i) {
        if (!pair.children().isEmpty()) {
            DecodedNode k = pair.children().get(0);
            String v = k.value();
            if (k.isLeaf() && v != null && k.type() == DecodedNode.Type.STRING && !v.isEmpty() && v.length() <= 64 && !v.startsWith("→")) {
                return v.startsWith(":") ? v.substring(1) : v;
            }
        }
        return "[" + i + "]";
    }

    private DecodedNode objNode(DecodedNode parent, String label, String cls, String kind) throws Bin.LimitException {
        out.type(cls);
        return budget.add(parent, new DecodedNode(label, cls + " (" + kind + ")" + risk(cls), DecodedNode.Type.OBJECT));
    }

    private static String risk(String cls) {
        return RiskyTypes.reason(cls) != null ? "  ⚠" : "";
    }

    private void leaf(DecodedNode parent, String label, String v, DecodedNode.Type type) throws Bin.LimitException {
        budget.add(parent, DecodedNode.leaf(label, v, type));
    }

    /** A class/module name is a symbol (':' or ';' link). */
    private String classSymbol() throws Bin.FormatException {
        return symbol();
    }

    private String symbol() throws Bin.FormatException {
        int at = in.pos();
        int t = in.u8();
        if (t != ':' && t != ';') throw new Bin.FormatException(String.format("expected a symbol at offset %d, found 0x%02x", at, t));
        return symbolAfter(t);
    }

    private String symbolAfter(int t) throws Bin.FormatException {
        if (t == ':') {
            String s = new String(in.bytes(count()), StandardCharsets.UTF_8);
            if (symbols.size() < MAX_SYMBOLS) symbols.add(s);
            symbolList.add(s);
            return s;
        }
        long idx = rLong();
        if (idx < 0 || idx >= symbols.size()) throw new Bin.FormatException("bad symbol link ;" + idx);
        return symbols.get((int) idx);
    }

    private String rString() throws Bin.FormatException {
        return new String(in.bytes(count()), StandardCharsets.UTF_8);
    }

    private long count() throws Bin.FormatException {
        long n = rLong();
        if (n < 0 || n > in.remaining()) throw new Bin.FormatException("bad length " + n + " at offset " + in.pos());
        return n;
    }

    /** Marshal's packed integer ("w_long"). */
    private long rLong() throws Bin.FormatException {
        int c = (byte) in.u8();
        if (c == 0) return 0;
        if (c > 0) {
            if (c > 4) return c - 5;
            long x = 0;
            for (int i = 0; i < c; i++) x |= (long) in.u8() << (8 * i);
            return x;
        }
        if (c < -4) return c + 5;
        int n = -c;
        long x = -1;
        for (int i = 0; i < n; i++) {
            x &= ~(0xffL << (8 * i));
            x |= (long) in.u8() << (8 * i);
        }
        return x;
    }
}
