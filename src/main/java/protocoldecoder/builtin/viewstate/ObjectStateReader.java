package protocoldecoder.builtin.viewstate;

import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;

import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Bounds-checked, read-only parser for the {@code System.Web.UI.ObjectStateFormatter} binary format (ViewState,
 * EventValidation, ControlState). It only builds a display tree: nothing is ever deserialized with .NET semantics, and
 * {@code BinarySerialized} (BinaryFormatter) blobs are only scanned for printable class/assembly names.
 *
 * <p>The tree is built while reading, so on corrupt or truncated input everything read so far is kept and the error is
 * reported in {@link Result#error()}.</p>
 */
final class ObjectStateReader {

    // Token values from System.Web.UI.ObjectStateFormatter (reference source).
    static final int T_INT16 = 0x01, T_INT32 = 0x02, T_BYTE = 0x03, T_CHAR = 0x04, T_STRING = 0x05,
            T_DATETIME = 0x06, T_DOUBLE = 0x07, T_SINGLE = 0x08, T_COLOR = 0x09, T_KNOWNCOLOR = 0x0A,
            T_INTENUM = 0x0B, T_EMPTYCOLOR = 0x0C, T_PAIR = 0x0F, T_TRIPLET = 0x10, T_ARRAY = 0x14,
            T_STRINGARRAY = 0x15, T_ARRAYLIST = 0x16, T_HASHTABLE = 0x17, T_HYBRIDDICT = 0x18, T_TYPE = 0x19,
            T_UNIT = 0x1B, T_EMPTYUNIT = 0x1C, T_EVENTVALIDATIONSTORE = 0x1D, T_INDEXEDSTRINGADD = 0x1E,
            T_INDEXEDSTRING = 0x1F, T_STRINGFORMATTED = 0x28, T_TYPEREFADD = 0x29, T_TYPEREFADDLOCAL = 0x2A,
            T_TYPEREF = 0x2B, T_BINARYSERIALIZED = 0x32, T_SPARSEARRAY = 0x3C, T_NULL = 0x64,
            T_EMPTYSTRING = 0x65, T_ZEROINT32 = 0x66, T_TRUE = 0x67, T_FALSE = 0x68;

    static final int MAX_DEPTH = 160;
    static final int MAX_NODES = 50_000;
    private static final int MAX_STRING_SHOWN = 64 * 1024;
    private static final int EVENT_VALIDATION_HASH = 16;

    /** Names that commonly show up in BinaryFormatter gadget chains (ysoserial.net and friends). */
    private static final String[] GADGET_MARKERS = {
            "TypeConfuseDelegate", "ObjectDataProvider", "TextFormattingRunProperties", "WindowsIdentity",
            "WindowsClaimsIdentity", "ClaimsIdentity", "ClaimsPrincipal", "SessionSecurityToken", "SessionViewStateHistoryItem",
            "ActivitySurrogateSelector", "ActivitySurrogateDisableTypeCheck", "ObjRef", "PSObject", "DataSet",
            "TypeConverter", "ComparisonComparer", "SortedSet", "XamlReader", "ResourceSet", "RolePrincipal",
            "AxHost", "ToolboxItemContainer", "GenericPrincipal", "System.Diagnostics.Process", "DelegateSerializationHolder",
    };

    /** A BinaryFormatter (NRBF) blob embedded through Token_BinarySerialized. */
    record BinaryBlob(int offset, int length, List<String> classes, List<String> libraries, List<String> gadgets) {
    }

    record Result(DecodedNode graph, int end, boolean complete, String error, List<String> strings, List<String> types,
                  int objects, List<BinaryBlob> blobs, int eventValidationHashes) {
    }

    /**
     * Where a plain string value sits in the stream: {@code start} is the offset of its 7-bit length prefix,
     * {@code dataStart}..{@code end} its UTF-8 bytes. {@code path} names it in the tree, e.g. "Root › First › [2]".
     */
    record StringSpan(int start, int dataStart, int end, String value, String path) {
    }

    /** String spans of a fully parsed stream; {@code complete} is false (and spans empty) if parsing stopped. */
    record Spans(boolean complete, int end, List<StringSpan> spans) {
    }

    static final class FormatException extends Exception {
        FormatException(String m) {
            super(m);
        }
    }

    private final byte[] b;
    private final int limit;
    private int pos;
    private int nodes;
    private int evHashes = -1;
    private final List<String> strings = new ArrayList<>();
    private final List<String> types = new ArrayList<>();
    private final List<BinaryBlob> blobs = new ArrayList<>();
    /** Non-null when string spans are recorded (see {@link #spans(byte[])}). */
    private List<StringSpan> spanList;
    private final java.util.ArrayDeque<String> path = new java.util.ArrayDeque<>();

    private ObjectStateReader(byte[] b, int offset, int limit) {
        this.b = b;
        this.pos = offset;
        this.limit = limit;
    }

    /** True if the bytes start with the ObjectStateFormatter marker {@code FF 01}. */
    static boolean hasMarker(byte[] b) {
        return b != null && b.length >= 2 && (b[0] & 0xff) == 0xFF && (b[1] & 0xff) == 0x01;
    }

    /** Parses one top-level value following the {@code FF 01} marker. Never throws. */
    static Result parse(byte[] data) {
        ObjectStateReader r = new ObjectStateReader(data, 2, data.length);
        DecodedNode holder = DecodedNode.object("holder");
        String error = null;
        try {
            if (!hasMarker(data)) throw new FormatException("missing FF 01 marker");
            r.value(holder, "Root", 0);
        } catch (FormatException e) {
            error = e.getMessage();
        } catch (RuntimeException e) { // defensive: never let a parser bug escape into Burp
            error = "parser error: " + e;
        }
        DecodedNode graph = holder.children().isEmpty() ? DecodedNode.leaf("Root", null) : holder.children().get(0);
        return new Result(graph, r.pos, error == null, error, List.copyOf(r.strings), List.copyOf(r.types), r.nodes,
                List.copyOf(r.blobs), r.evHashes);
    }

    /**
     * Parses like {@link #parse} and also records where each plain string value ({@code Token_String},
     * {@code Token_IndexedStringAdd}, {@code string[]} elements) is, so {@link ObjectStateWriter} can replace it.
     */
    static Spans spans(byte[] data) {
        ObjectStateReader r = new ObjectStateReader(data, 2, data.length);
        r.spanList = new ArrayList<>();
        try {
            if (!hasMarker(data)) return new Spans(false, 0, List.of());
            r.value(DecodedNode.object("holder"), "Root", 0);
        } catch (FormatException | RuntimeException e) {
            return new Spans(false, r.pos, List.of());
        }
        return new Spans(true, r.pos, List.copyOf(r.spanList));
    }

    /** Reads a string and, when recording, remembers its span under the current path (+ suffix). */
    private String spanString(String suffix) throws FormatException {
        int start = pos;
        String s = string();
        if (spanList != null) {
            int len = s.getBytes(StandardCharsets.UTF_8).length;
            List<String> parts = new ArrayList<>(path);
            java.util.Collections.reverse(parts);
            String p = String.join(" › ", parts) + (suffix == null ? "" : " › " + suffix);
            spanList.add(new StringSpan(start, pos - len, pos, s, p));
        }
        return s;
    }

    // ------------------------------------------------------------------ values

    private DecodedNode add(DecodedNode parent, DecodedNode n) throws FormatException {
        if (++nodes > MAX_NODES) throw new FormatException("node limit (" + MAX_NODES + ") reached");
        parent.add(n);
        return n;
    }

    private DecodedNode leaf(DecodedNode parent, String name, String value, DecodedNode.Type type) throws FormatException {
        return add(parent, DecodedNode.leaf(name, value, type));
    }

    private DecodedNode container(DecodedNode parent, String name, String label, DecodedNode.Type type) throws FormatException {
        return add(parent, new DecodedNode(name, label, type));
    }

    private void value(DecodedNode parent, String name, int depth) throws FormatException {
        if (depth > MAX_DEPTH) throw new FormatException("nesting deeper than " + MAX_DEPTH + " at offset " + pos);
        path.push(name);
        try {
            value0(parent, name, depth);
        } finally {
            path.pop();
        }
    }

    private void value0(DecodedNode parent, String name, int depth) throws FormatException {
        int at = pos;
        int t = u8();
        switch (t) {
            case T_INT16 -> leaf(parent, name, Short.toString((short) (u8() | (u8() << 8))), DecodedNode.Type.NUMBER);
            case T_INT32 -> leaf(parent, name, Integer.toString(encodedInt()), DecodedNode.Type.NUMBER);
            case T_BYTE -> leaf(parent, name, Integer.toString(u8()), DecodedNode.Type.NUMBER);
            case T_CHAR -> leaf(parent, name, "'" + readChar() + "'", DecodedNode.Type.STRING);
            case T_STRING -> leaf(parent, name, shown(spanString(null)), DecodedNode.Type.STRING);
            case T_DATETIME -> leaf(parent, name, dateTime(i64()), DecodedNode.Type.STRING);
            case T_DOUBLE -> leaf(parent, name, num(Double.longBitsToDouble(i64())), DecodedNode.Type.NUMBER);
            case T_SINGLE -> leaf(parent, name, num(Float.intBitsToFloat(i32())), DecodedNode.Type.NUMBER);
            case T_COLOR -> leaf(parent, name, String.format("Color #%08X", i32()), DecodedNode.Type.STRING);
            case T_KNOWNCOLOR -> leaf(parent, name, "KnownColor " + encodedInt(), DecodedNode.Type.STRING);
            case T_INTENUM -> {
                String type = typeRef();
                leaf(parent, name, shortType(type) + " = " + encodedInt(), DecodedNode.Type.NUMBER);
            }
            case T_EMPTYCOLOR -> leaf(parent, name, "Color.Empty", DecodedNode.Type.STRING);
            case T_PAIR -> {
                DecodedNode n = container(parent, name, "Pair", DecodedNode.Type.OBJECT);
                value(n, "First", depth + 1);
                value(n, "Second", depth + 1);
            }
            case T_TRIPLET -> {
                DecodedNode n = container(parent, name, "Triplet", DecodedNode.Type.OBJECT);
                value(n, "First", depth + 1);
                value(n, "Second", depth + 1);
                value(n, "Third", depth + 1);
            }
            case T_ARRAY -> {
                String type = typeRef();
                int count = count();
                DecodedNode n = container(parent, name, shortType(type) + "[" + count + "]", DecodedNode.Type.ARRAY);
                for (int i = 0; i < count; i++) value(n, "[" + i + "]", depth + 1);
            }
            case T_STRINGARRAY -> {
                int count = count();
                DecodedNode n = container(parent, name, "string[" + count + "]", DecodedNode.Type.ARRAY);
                // Elements are written with BinaryWriter.Write(string): plain length-prefixed strings, no tokens.
                for (int i = 0; i < count; i++) leaf(n, "[" + i + "]", shown(spanString("[" + i + "]")), DecodedNode.Type.STRING);
            }
            case T_ARRAYLIST -> {
                int count = count();
                DecodedNode n = container(parent, name, "ArrayList(" + count + ")", DecodedNode.Type.ARRAY);
                for (int i = 0; i < count; i++) value(n, "[" + i + "]", depth + 1);
            }
            case T_HASHTABLE, T_HYBRIDDICT -> {
                int count = count();
                String kind = t == T_HASHTABLE ? "Hashtable" : "HybridDictionary";
                DecodedNode n = container(parent, name, kind + "(" + count + ")", DecodedNode.Type.OBJECT);
                for (int i = 0; i < count; i++) {
                    DecodedNode entry = container(n, "[" + i + "]", "Entry", DecodedNode.Type.OBJECT);
                    path.push("[" + i + "]");
                    try {
                        value(entry, "Key", depth + 2);
                        value(entry, "Value", depth + 2);
                    } finally {
                        path.pop();
                    }
                }
            }
            case T_TYPE -> leaf(parent, name, "typeof(" + typeRef() + ")", DecodedNode.Type.STRING);
            case T_UNIT -> {
                double v = Double.longBitsToDouble(i64());
                int unitType = i32();
                leaf(parent, name, "Unit " + num(v) + unitSuffix(unitType), DecodedNode.Type.STRING);
            }
            case T_EMPTYUNIT -> leaf(parent, name, "Unit.Empty", DecodedNode.Type.STRING);
            case T_EVENTVALIDATIONSTORE -> eventValidationStore(parent, name);
            case T_INDEXEDSTRINGADD -> {
                String s = spanString(null);
                strings.add(s);
                leaf(parent, name, shown(s), DecodedNode.Type.STRING);
            }
            case T_INDEXEDSTRING -> {
                int idx = u8();
                if (idx >= strings.size()) throw new FormatException("indexed string #" + idx + " not in string table (size " + strings.size() + ") at offset " + at);
                leaf(parent, name, shown(strings.get(idx)), DecodedNode.Type.STRING);
            }
            case T_STRINGFORMATTED -> {
                String type = typeRef();
                String s = string();
                leaf(parent, name, shortType(type) + " \"" + shown(s) + "\"", DecodedNode.Type.STRING);
            }
            case T_BINARYSERIALIZED -> binarySerialized(parent, name, at);
            case T_SPARSEARRAY -> {
                String type = typeRef();
                int length = count();
                int items = encodedInt();
                if (items < 0 || items > length) throw new FormatException("sparse array item count " + items + " exceeds length " + length);
                DecodedNode n = container(parent, name, shortType(type) + "[" + length + "] (sparse, " + items + " set)", DecodedNode.Type.OBJECT);
                for (int i = 0; i < items; i++) {
                    int index = encodedInt();
                    if (index < 0 || index >= length) throw new FormatException("sparse array index " + index + " out of range");
                    value(n, "[" + index + "]", depth + 1);
                }
            }
            case T_NULL -> leaf(parent, name, null, DecodedNode.Type.NULL);
            case T_EMPTYSTRING -> leaf(parent, name, "", DecodedNode.Type.STRING);
            case T_ZEROINT32 -> leaf(parent, name, "0", DecodedNode.Type.NUMBER);
            case T_TRUE -> leaf(parent, name, "true", DecodedNode.Type.BOOLEAN);
            case T_FALSE -> leaf(parent, name, "false", DecodedNode.Type.BOOLEAN);
            default -> throw new FormatException(String.format("unknown token 0x%02X at offset %d", t, at));
        }
    }

    private void eventValidationStore(DecodedNode parent, String name) throws FormatException {
        // EventValidationStore.DeserializeFrom: version byte (0), 7-bit encoded hash count, then 16-byte hashes.
        int version = u8();
        if (version != 0) throw new FormatException("unsupported EventValidationStore version " + version);
        int count = count();
        if ((long) count * EVENT_VALIDATION_HASH > limit - pos) {
            throw new FormatException("EventValidationStore claims " + count + " hashes but only " + (limit - pos) + " bytes remain");
        }
        evHashes = count;
        DecodedNode n = container(parent, name, "EventValidationStore (" + count + " hashes)", DecodedNode.Type.ARRAY);
        for (int i = 0; i < count; i++) {
            leaf(n, "[" + i + "]", hex(pos, EVENT_VALIDATION_HASH), DecodedNode.Type.BINARY);
            pos += EVENT_VALIDATION_HASH;
        }
    }

    private void binarySerialized(DecodedNode parent, String name, int at) throws FormatException {
        int len = encodedInt();
        if (len < 0 || len > limit - pos) throw new FormatException("BinarySerialized blob of " + len + " bytes exceeds the " + (limit - pos) + " remaining");
        int start = pos;
        pos += len;
        List<String> classes = new ArrayList<>(), libraries = new ArrayList<>(), gadgets = new ArrayList<>();
        for (String s : printable(b, start, start + len, 4, 60)) {
            if (s.contains("Version=") || s.contains("PublicKeyToken") || s.contains("Culture=")) libraries.add(s);
            else if (s.indexOf('.') > 0 && s.indexOf(' ') < 0) classes.add(s);
            for (String g : GADGET_MARKERS) if (s.contains(g) && !gadgets.contains(g)) gadgets.add(g);
        }
        blobs.add(new BinaryBlob(at, len, classes, libraries, gadgets));
        DecodedNode n = container(parent, name, "BinarySerialized (" + len + " bytes, BinaryFormatter) ⚠ deserialization sink", DecodedNode.Type.OBJECT);
        add(n, DecodedNode.leaf("Size", Integer.toString(len), DecodedNode.Type.NUMBER));
        boolean nrbf = len >= 17 && (b[start] & 0xff) == 0x00 && (b[start + 1] & 0xff) == 0x01;
        add(n, DecodedNode.leaf("NRBF header", nrbf ? "yes (SerializationHeaderRecord)" : "not found"));
        if (!classes.isEmpty()) {
            DecodedNode c = container(n, "Class names (printable scan)", null, DecodedNode.Type.ARRAY);
            for (String s : classes) leaf(c, "", s, DecodedNode.Type.STRING);
        }
        if (!libraries.isEmpty()) {
            DecodedNode c = container(n, "Libraries (printable scan)", null, DecodedNode.Type.ARRAY);
            for (String s : libraries) leaf(c, "", s, DecodedNode.Type.STRING);
        }
        if (!gadgets.isEmpty()) leaf(n, "Known gadget markers", String.join(", ", gadgets), DecodedNode.Type.STRING);
        leaf(n, "Hex", hex(start, Math.min(len, 64)) + (len > 64 ? " … (" + len + " bytes)" : ""), DecodedNode.Type.BINARY);
    }

    // ------------------------------------------------------------------ types

    /** Reads a type reference (TypeRef / TypeRefAdd / TypeRefAddLocal) and returns the type name. */
    private String typeRef() throws FormatException {
        int at = pos;
        int t = u8();
        switch (t) {
            case T_TYPEREF -> {
                int idx = encodedInt();
                if (idx < 0 || idx >= types.size()) throw new FormatException("type reference #" + idx + " not in type table (size " + types.size() + ") at offset " + at);
                return types.get(idx);
            }
            case T_TYPEREFADD -> {
                String s = string();
                types.add(s);
                return s;
            }
            case T_TYPEREFADDLOCAL -> {
                String s = string() + " [System.Web]";
                types.add(s);
                return s;
            }
            default -> throw new FormatException(String.format("expected a type reference but found token 0x%02X at offset %d", t, at));
        }
    }

    /** Drops the assembly qualification for display: {@code System.Int32, mscorlib, ...} → {@code System.Int32}. */
    static String shortType(String t) {
        if (t == null) return "?";
        int depth = 0;
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if (c == '[') depth++;
            else if (c == ']') depth--;
            else if (c == ',' && depth == 0) return t.substring(0, i).trim();
        }
        return t;
    }

    // ------------------------------------------------------------------ primitives

    private int u8() throws FormatException {
        if (pos >= limit) throw new FormatException("unexpected end of data at offset " + pos);
        return b[pos++] & 0xff;
    }

    private int i32() throws FormatException {
        need(4);
        int v = (b[pos] & 0xff) | (b[pos + 1] & 0xff) << 8 | (b[pos + 2] & 0xff) << 16 | (b[pos + 3] & 0xff) << 24;
        pos += 4;
        return v;
    }

    private long i64() throws FormatException {
        need(8);
        long v = 0;
        for (int i = 7; i >= 0; i--) v = (v << 8) | (b[pos + i] & 0xff);
        pos += 8;
        return v;
    }

    private void need(int n) throws FormatException {
        if (n < 0 || n > limit - pos) throw new FormatException("unexpected end of data at offset " + pos + " (need " + n + " bytes)");
    }

    /** BinaryWriter 7-bit encoded Int32. */
    private int encodedInt() throws FormatException {
        int v = 0, shift = 0;
        while (true) {
            if (shift >= 35) throw new FormatException("bad 7-bit encoded integer at offset " + pos);
            int x = u8();
            v |= (x & 0x7f) << shift;
            if ((x & 0x80) == 0) return v;
            shift += 7;
        }
    }

    /** An element count; each element needs at least one byte, so larger counts are corrupt. */
    private int count() throws FormatException {
        int n = encodedInt();
        if (n < 0 || n > limit - pos) throw new FormatException("count " + n + " exceeds the " + (limit - pos) + " remaining bytes at offset " + pos);
        return n;
    }

    private String string() throws FormatException {
        int len = encodedInt();
        if (len < 0) throw new FormatException("negative string length at offset " + pos);
        need(len);
        String s = new String(b, pos, len, StandardCharsets.UTF_8);
        pos += len;
        return s;
    }

    /** BinaryReader.ReadChar with UTF-8: one UTF-8 encoded character. */
    private String readChar() throws FormatException {
        int lead = pos < limit ? b[pos] & 0xff : -1;
        int len = lead < 0 ? 1 : lead < 0x80 ? 1 : lead >= 0xF0 ? 4 : lead >= 0xE0 ? 3 : lead >= 0xC0 ? 2 : 1;
        need(len);
        try {
            String s = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(b, pos, len)).toString();
            pos += len;
            return s;
        } catch (CharacterCodingException e) {
            throw new FormatException("invalid UTF-8 character at offset " + pos);
        }
    }

    private static String shown(String s) {
        return Codecs.truncate(s, MAX_STRING_SHOWN);
    }

    private static String num(double d) {
        if (d == Math.rint(d) && !Double.isInfinite(d) && Math.abs(d) < 1e15) return Long.toString((long) d);
        return Double.toString(d);
    }

    private static String unitSuffix(int unitType) {
        return switch (unitType) {
            case 1 -> "px";
            case 2 -> "pt";
            case 3 -> "pc";
            case 4 -> "in";
            case 5 -> "mm";
            case 6 -> "cm";
            case 7 -> "%";
            case 8 -> "em";
            case 9 -> "ex";
            default -> " (unit type " + unitType + ")";
        };
    }

    /** DateTime.ToBinary(): kind in the top two bits, ticks (100ns since 0001-01-01) in the rest. */
    static String dateTime(long binary) {
        long ticks = binary & 0x3FFF_FFFF_FFFF_FFFFL;
        int kind = (int) (binary >>> 62);
        long epochTicks = 621_355_968_000_000_000L;
        String kindName = switch (kind) {
            case 0 -> "Unspecified";
            case 1 -> "Utc";
            default -> "Local";
        };
        if (ticks > 3_155_378_975_999_999_999L) return "DateTime(raw 0x" + Long.toHexString(binary) + ")";
        long rel = ticks - epochTicks;
        Instant i = Instant.ofEpochSecond(Math.floorDiv(rel, 10_000_000L), Math.floorMod(rel, 10_000_000L) * 100);
        return "DateTime " + i + " (" + kindName + ")";
    }

    private String hex(int from, int len) {
        StringBuilder sb = new StringBuilder(len * 3);
        for (int i = 0; i < len && from + i < b.length; i++) {
            if (i > 0) sb.append(' ');
            sb.append(String.format(Locale.ROOT, "%02x", b[from + i] & 0xff));
        }
        return sb.toString();
    }

    static List<String> printable(byte[] b, int from, int to, int min, int max) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        for (int i = from; i < to && out.size() < max; i++) {
            int c = b[i] & 0xff;
            if (c >= 0x20 && c < 0x7f) {
                if (cur.length() < 1024) cur.append((char) c);
            } else {
                if (cur.length() >= min) out.add(cur.toString());
                cur.setLength(0);
            }
        }
        if (cur.length() >= min && out.size() < max) out.add(cur.toString());
        return out;
    }
}
