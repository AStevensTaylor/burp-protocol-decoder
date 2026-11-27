package protocoldecoder.builtin.viewstate;

import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;

/**
 * Best-effort reader for the ASP.NET 1.x {@code LosFormatter} text syntax, e.g.
 * {@code t<1234;t<;l<i<0>;>;l<t<p<l<Text;>;l<hello;>>;;>;>>;>}. Prefixes: {@code t} Triplet, {@code p} Pair,
 * {@code l} ArrayList, {@code h} Hashtable (alternating key;value), {@code i} Int32, {@code o} Boolean (t/f),
 * {@code @} array, {@code b} BinaryFormatter blob (base64); other letter prefixes are shown as typed values. Bare text
 * is a string; an empty item is null. Backslash escapes the next character.
 *
 * <p>The 1.x MAC (when enabled) is appended as raw bytes after the closing {@code >}.</p>
 */
final class LosTextReader {

    record Result(DecodedNode graph, int end, boolean complete, String error, int objects, boolean binarySerialized) {
    }

    private static final class FormatException extends Exception {
        FormatException(String m) {
            super(m);
        }
    }

    private final String s;
    private int pos;
    private int nodes;
    private boolean binary;

    private LosTextReader(String s) {
        this.s = s;
    }

    /** True if the decoded bytes look like LosFormatter text: a type letter followed by '<'. */
    static boolean looksLike(byte[] b) {
        if (b == null || b.length < 3 || b[1] != '<') return false;
        return "tplhio@b".indexOf((char) (b[0] & 0xff)) >= 0;
    }

    static Result parse(byte[] data) {
        LosTextReader r = new LosTextReader(Codecs.latin1String(data));
        DecodedNode holder = DecodedNode.object("holder");
        String error = null;
        try {
            r.value(holder, "Root", 0, true);
        } catch (FormatException e) {
            error = e.getMessage();
        } catch (RuntimeException e) {
            error = "parser error: " + e;
        }
        DecodedNode graph = holder.children().isEmpty() ? DecodedNode.leaf("Root", null) : holder.children().get(0);
        return new Result(graph, r.pos, error == null, error, r.nodes, r.binary);
    }

    private void add(DecodedNode parent, DecodedNode n) throws FormatException {
        if (++nodes > ObjectStateReader.MAX_NODES) throw new FormatException("node limit reached");
        parent.add(n);
    }

    private void value(DecodedNode parent, String name, int depth, boolean top) throws FormatException {
        if (depth > ObjectStateReader.MAX_DEPTH) throw new FormatException("nesting too deep at offset " + pos);
        if (pos + 1 < s.length() && s.charAt(pos + 1) == '<' && Character.isLetter(s.charAt(pos)) || pos + 1 < s.length() && s.charAt(pos) == '@' && s.charAt(pos + 1) == '<') {
            char type = s.charAt(pos);
            pos += 2;
            switch (type) {
                case 't', 'p', 'l', 'h', '@' -> {
                    String label = switch (type) {
                        case 't' -> "Triplet";
                        case 'p' -> "Pair";
                        case 'l' -> "ArrayList";
                        case 'h' -> "Hashtable";
                        default -> "Array";
                    };
                    DecodedNode n = new DecodedNode(name, label, type == 'l' || type == '@' ? DecodedNode.Type.ARRAY : DecodedNode.Type.OBJECT);
                    add(parent, n);
                    String[] slots = type == 't' ? new String[]{"First", "Second", "Third"} : type == 'p' ? new String[]{"First", "Second"} : null;
                    int i = 0;
                    while (true) {
                        if (pos >= s.length()) throw new FormatException("unterminated " + label + " at offset " + pos);
                        if (s.charAt(pos) == '>') { pos++; break; }
                        String slot = slots != null && i < slots.length ? slots[i]
                                : type == 'h' ? (i % 2 == 0 ? "Key" : "Value") : "[" + i + "]";
                        value(n, slot, depth + 1, false);
                        i++;
                        if (pos < s.length() && s.charAt(pos) == ';') pos++;
                    }
                }
                case 'i' -> {
                    add(parent, new DecodedNode(name, text(), DecodedNode.Type.NUMBER));
                    close();
                }
                case 'o' -> {
                    String v = text();
                    add(parent, new DecodedNode(name, "t".equals(v) ? "true" : "f".equals(v) ? "false" : v, DecodedNode.Type.BOOLEAN));
                    close();
                }
                case 'b' -> {
                    String v = text();
                    binary = true;
                    byte[] raw = Codecs.base64Decode(v);
                    add(parent, new DecodedNode(name, "BinarySerialized (" + (raw == null ? "?" : raw.length) + " bytes, BinaryFormatter) ⚠ deserialization sink", DecodedNode.Type.BINARY));
                    close();
                }
                default -> {
                    add(parent, new DecodedNode(name, "Typed '" + type + "': " + text(), DecodedNode.Type.STRING));
                    close();
                }
            }
        } else {
            String v = text();
            add(parent, v.isEmpty() ? DecodedNode.leaf(name, null) : DecodedNode.leaf(name, v));
        }
        if (top && pos < s.length() && s.charAt(pos) == ';') pos++;
    }

    private void close() throws FormatException {
        if (pos >= s.length() || s.charAt(pos) != '>') throw new FormatException("expected '>' at offset " + pos);
        pos++;
    }

    /** Reads text up to an unescaped ';' or '>'. */
    private String text() {
        StringBuilder sb = new StringBuilder();
        while (pos < s.length()) {
            char c = s.charAt(pos);
            if (c == '\\' && pos + 1 < s.length()) {
                sb.append(s.charAt(pos + 1));
                pos += 2;
                continue;
            }
            if (c == ';' || c == '>') break;
            if (c < 0x20 && c != '\t' && c != '\r' && c != '\n') break; // reached the binary MAC
            sb.append(c);
            pos++;
        }
        return sb.toString();
    }
}
