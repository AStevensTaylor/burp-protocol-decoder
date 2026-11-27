package protocoldecoder.builtin.phoenix;

import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal Erlang External Term Format reader (what {@code :erlang.term_to_binary/1} produces), enough for the terms
 * Phoenix/Plug put in signed tokens: atoms, integers, floats, binaries, lists, tuples, maps, pids and references.
 */
final class Etf {

    private static final int MAX_DEPTH = 64;
    private static final int MAX_ITEMS = 20_000;

    record Atom(String name) {
        @Override public String toString() {
            return name.startsWith("Elixir.") ? name.substring(7) : ":" + name;
        }
    }

    record Tuple(List<Object> items) {
    }

    /** A pid/reference/port/fun: kept as a description only. */
    record Opaque(String text) {
    }

    static final class EtfException extends Exception {
        EtfException(String m) {
            super(m);
        }
    }

    private final byte[] b;
    private int pos;
    private int items;

    private Etf(byte[] b, int pos) {
        this.b = b;
        this.pos = pos;
    }

    static boolean looksLikeEtf(byte[] b) {
        return b != null && b.length > 1 && (b[0] & 0xff) == 131;
    }

    /** Decodes a complete term (leading version byte 131 required). */
    static Object decode(byte[] data) throws EtfException {
        if (!looksLikeEtf(data)) throw new EtfException("not Erlang term format (missing version byte 131)");
        if ((data[1] & 0xff) == 80) {
            if (data.length < 6) throw new EtfException("truncated compressed term");
            byte[] z = new byte[data.length - 6];
            System.arraycopy(data, 6, z, 0, z.length);
            try {
                byte[] inflated = Codecs.inflate(z);
                Etf r = new Etf(inflated, 0);
                return r.term(0);
            } catch (IOException e) {
                throw new EtfException("compressed term: " + e.getMessage());
            }
        }
        Etf r = new Etf(data, 1);
        Object o = r.term(0);
        return o;
    }

    private int u8() throws EtfException {
        need(1);
        return b[pos++] & 0xff;
    }

    private int u16() throws EtfException {
        need(2);
        int v = ((b[pos] & 0xff) << 8) | (b[pos + 1] & 0xff);
        pos += 2;
        return v;
    }

    private long u32() throws EtfException {
        need(4);
        long v = ((long) (b[pos] & 0xff) << 24) | ((b[pos + 1] & 0xff) << 16) | ((b[pos + 2] & 0xff) << 8) | (b[pos + 3] & 0xff);
        pos += 4;
        return v;
    }

    private int len32() throws EtfException {
        long n = u32();
        if (n > b.length - pos && n > 0) {
            // lengths of lists/maps count elements, not bytes, but every element takes at least one byte
            throw new EtfException("length " + n + " exceeds the remaining " + (b.length - pos) + " bytes");
        }
        return (int) n;
    }

    private byte[] bytes(int n) throws EtfException {
        need(n);
        byte[] out = new byte[n];
        System.arraycopy(b, pos, out, 0, n);
        pos += n;
        return out;
    }

    private void need(int n) throws EtfException {
        if (n < 0 || pos + n > b.length) throw new EtfException("truncated term at offset " + pos);
    }

    private Object term(int depth) throws EtfException {
        if (depth > MAX_DEPTH) throw new EtfException("term nested too deeply");
        if (++items > MAX_ITEMS) throw new EtfException("term has too many elements");
        int tag = u8();
        switch (tag) {
            case 97: return (long) u8();
            case 98: return (long) (int) u32();
            case 70: {
                need(8);
                long bits = 0;
                for (int i = 0; i < 8; i++) bits = (bits << 8) | (b[pos + i] & 0xff);
                pos += 8;
                return Double.longBitsToDouble(bits);
            }
            case 99: return new String(bytes(31), StandardCharsets.ISO_8859_1).trim();
            case 100: return new Atom(new String(bytes(u16()), StandardCharsets.ISO_8859_1));
            case 115: return new Atom(new String(bytes(u8()), StandardCharsets.ISO_8859_1));
            case 118: return new Atom(new String(bytes(u16()), StandardCharsets.UTF_8));
            case 119: return new Atom(new String(bytes(u8()), StandardCharsets.UTF_8));
            case 104: return tuple(u8(), depth);
            case 105: return tuple(len32(), depth);
            case 106: return new ArrayList<>();
            case 107: {
                // STRING_EXT: a list of small integers (charlist)
                byte[] s = bytes(u16());
                List<Object> l = new ArrayList<>(s.length);
                for (byte x : s) l.add((long) (x & 0xff));
                return l;
            }
            case 108: {
                int n = len32();
                List<Object> l = new ArrayList<>(Math.min(n, 1024));
                for (int i = 0; i < n; i++) l.add(term(depth + 1));
                Object tail = term(depth + 1);
                if (!(tail instanceof List<?> t && t.isEmpty())) l.add(new Opaque("| " + tail)); // improper list
                return l;
            }
            case 109: return bytes(len32());
            case 77: {
                int n = len32();
                int bits = u8();
                byte[] data = bytes(n);
                return new Opaque("bitstring " + Codecs.hexPreview(data, 32) + " (" + bits + " bits in last byte)");
            }
            case 110: return big(u8());
            case 111: return big(len32());
            case 116: {
                int n = len32();
                Map<Object, Object> m = new LinkedHashMap<>();
                for (int i = 0; i < n; i++) {
                    Object k = term(depth + 1);
                    Object v = term(depth + 1);
                    m.put(k, v);
                }
                return m;
            }
            case 88: { // NEW_PID_EXT
                Object node = term(depth + 1);
                long id = u32(), serial = u32();
                u32();
                return new Opaque("#PID<" + node + "." + id + "." + serial + ">");
            }
            case 103: { // PID_EXT
                Object node = term(depth + 1);
                long id = u32(), serial = u32();
                u8();
                return new Opaque("#PID<" + node + "." + id + "." + serial + ">");
            }
            case 90: case 114: { // NEWER_REFERENCE_EXT / NEW_REFERENCE_EXT
                int n = u16();
                Object node = term(depth + 1);
                if (tag == 90) u32(); else u8();
                StringBuilder sb = new StringBuilder("#Reference<").append(node);
                for (int i = 0; i < n; i++) sb.append('.').append(u32());
                return new Opaque(sb.append('>').toString());
            }
            case 89: { // NEW_PORT_EXT
                Object node = term(depth + 1);
                long id = u32();
                u32();
                return new Opaque("#Port<" + node + "." + id + ">");
            }
            case 113: { // EXPORT_EXT
                Object mod = term(depth + 1), fun = term(depth + 1), arity = term(depth + 1);
                return new Opaque("&" + mod + "." + fun + "/" + arity);
            }
            default:
                throw new EtfException("unsupported term tag " + tag + " at offset " + (pos - 1));
        }
    }

    private Tuple tuple(int n, int depth) throws EtfException {
        List<Object> l = new ArrayList<>(Math.min(n, 1024));
        for (int i = 0; i < n; i++) l.add(term(depth + 1));
        return new Tuple(l);
    }

    /** Bignums that fit in a long (e.g. millisecond timestamps) come back as Long. */
    private Object big(int n) throws EtfException {
        int sign = u8();
        byte[] le = bytes(n);
        byte[] be = new byte[n];
        for (int i = 0; i < n; i++) be[i] = le[n - 1 - i];
        BigInteger v = new BigInteger(1, be);
        if (sign != 0) v = v.negate();
        return v.bitLength() < 64 ? (Object) v.longValue() : v;
    }

    // ------------------------------------------------------------------ presentation

    static DecodedNode toNode(String name, Object v) {
        return toNode(name, v, 0);
    }

    private static DecodedNode toNode(String name, Object v, int depth) {
        if (depth > MAX_DEPTH) return DecodedNode.note("…");
        if (v instanceof Atom a) {
            return switch (a.name()) {
                case "true", "false" -> DecodedNode.leaf(name, a.name(), DecodedNode.Type.BOOLEAN);
                case "nil" -> DecodedNode.leaf(name, "nil", DecodedNode.Type.NULL);
                default -> DecodedNode.leaf(name, a.toString());
            };
        }
        if (v instanceof Long || v instanceof BigInteger || v instanceof Double) return DecodedNode.leaf(name, v.toString(), DecodedNode.Type.NUMBER);
        if (v instanceof byte[] bin) {
            if (isUtf8Text(bin)) return DecodedNode.leaf(name, Codecs.truncate(new String(bin, StandardCharsets.UTF_8), 8000));
            return DecodedNode.leaf(name, "<<" + Codecs.hexPreview(bin, 128) + ">>", DecodedNode.Type.BINARY);
        }
        if (v instanceof Tuple t) {
            DecodedNode n = DecodedNode.array(name + " {tuple}");
            for (int i = 0; i < t.items().size(); i++) n.add(toNode("[" + i + "]", t.items().get(i), depth + 1));
            return n;
        }
        if (v instanceof List<?> l) {
            DecodedNode n = DecodedNode.array(name);
            for (int i = 0; i < l.size(); i++) n.add(toNode("[" + i + "]", l.get(i), depth + 1));
            return n;
        }
        if (v instanceof Map<?, ?> m) {
            DecodedNode n = DecodedNode.object(name);
            Object struct = m.get(new Atom("__struct__"));
            if (struct != null) n.put("struct", struct.toString());
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (e.getKey() instanceof Atom a && a.name().equals("__struct__")) continue;
                n.add(toNode(keyName(e.getKey()), e.getValue(), depth + 1));
            }
            return n;
        }
        if (v instanceof Opaque o) return DecodedNode.leaf(name, o.text());
        return DecodedNode.leaf(name, String.valueOf(v));
    }

    static String keyName(Object k) {
        if (k instanceof Atom a) return a.name().startsWith("Elixir.") ? a.name().substring(7) : a.name();
        if (k instanceof byte[] bin) return "\"" + new String(bin, StandardCharsets.UTF_8) + "\"";
        return String.valueOf(k);
    }

    static boolean isUtf8Text(byte[] b) {
        if (!Codecs.isMostlyText(b)) return false;
        try {
            StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(b));
            return true;
        } catch (java.nio.charset.CharacterCodingException e) {
            return false;
        }
    }
}
