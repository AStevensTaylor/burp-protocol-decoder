package protocoldecoder.builtin.serialized;

import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Read-only parser for the .NET Remoting Binary Format ([MS-NRBF]) written by {@code BinaryFormatter}. Lists
 * libraries (assemblies), class names, member names and simple values. Never resolves or loads a type.
 */
final class NrbfParser {

    private static final int MAX_DEPTH = 48;
    private static final int MAX_META = 20_000;
    private static final int MAX_ARRAY_SHOWN = 32;
    private static final int MAX_STRING_SHOWN = 2000;

    /** Member layout of a class record, kept so ClassWithId records can reuse it. */
    private record ClassMeta(String name, List<String> members, int[] binaryTypes, Object[] extra, Integer libraryId) {
    }

    private final Bin in;
    private final ParseOutput.Budget budget;
    private final ParseOutput out = new ParseOutput("Records");
    private final Map<Integer, String> libraries = new LinkedHashMap<>();
    private final Map<Integer, ClassMeta> metas = new HashMap<>();
    /** Labels from the top-level record to the current value, for insertion point paths. */
    private final List<String> trail = new ArrayList<>();

    private NrbfParser(byte[] data, int offset, ParseOutput.Budget budget) {
        this.in = new Bin(data, offset, data.length);
        this.budget = budget;
    }

    /** True if {@code b} at {@code off} starts with a SerializedStreamHeader record (version 1.0). */
    static boolean isHeader(byte[] b, int off) {
        if (b == null || off < 0 || b.length - off < 17) return false;
        if (b[off] != 0) return false;
        // HeaderId is -1 in practice; MajorVersion 1, MinorVersion 0.
        return le32(b, off + 9) == 1 && le32(b, off + 13) == 0 && le32(b, off + 5) == -1;
    }

    /** Index of the first NRBF header inside {@code b}, or -1. */
    static int find(byte[] b, int from) {
        for (int i = Math.max(0, from); i + 17 <= b.length; i++) {
            if (b[i] == 0 && isHeader(b, i)) return i;
        }
        return -1;
    }

    private static int le32(byte[] b, int i) {
        return (b[i] & 0xff) | ((b[i + 1] & 0xff) << 8) | ((b[i + 2] & 0xff) << 16) | ((b[i + 3] & 0xff) << 24);
    }

    static ParseOutput parse(byte[] data, ParseOutput.Budget budget) {
        return parse(data, 0, budget);
    }

    static ParseOutput parse(byte[] data, int offset, ParseOutput.Budget budget) {
        NrbfParser p = new NrbfParser(data, offset, budget);
        p.run();
        return p.out;
    }

    private void run() {
        DecodedNode root = out.structure;
        try {
            int rt = in.u8();
            if (rt != 0) throw new Bin.FormatException("stream does not start with a SerializedStreamHeader");
            DecodedNode h = budget.add(root, DecodedNode.object("SerializedStreamHeader"));
            h.put("RootId", in.s32le());
            h.put("HeaderId", in.s32le());
            h.put("Version", in.s32le() + "." + in.s32le());
            int i = 0;
            while (true) {
                int at = in.pos();
                rt = in.u8();
                if (rt == 11) {
                    budget.add(root, DecodedNode.leaf("MessageEnd", "offset " + at, DecodedNode.Type.NOTE));
                    if (in.hasMore()) out.notes.add(in.remaining() + " bytes after MessageEnd");
                    break;
                }
                if (rt == 12) {
                    readLibrary(root);
                    continue;
                }
                record(rt, root, "record[" + i++ + "]", 0);
            }
        } catch (Bin.FormatException e) {
            out.stop(e.getMessage());
        }
        if (!libraries.isEmpty()) {
            DecodedNode libs = DecodedNode.object("Libraries");
            libraries.forEach((id, name) -> libs.add(DecodedNode.leaf("#" + id, name)));
            out.extras.add(libs);
        }
    }

    private void readLibrary(DecodedNode parent) throws Bin.FormatException {
        int id = in.s32le();
        String name = lps();
        if (libraries.size() < MAX_META) libraries.put(id, name);
        budget.add(parent, DecodedNode.leaf("BinaryLibrary #" + id, name));
    }

    /** Reads a record used as a member/element value; returns how many slots it fills (ObjectNullMultiple > 1). */
    private int valueRecord(DecodedNode parent, String label, int depth) throws Bin.FormatException {
        int rt = in.u8();
        while (rt == 12) {
            readLibrary(parent);
            rt = in.u8();
        }
        if (rt == 11) throw new Bin.FormatException("MessageEnd inside an object at offset " + (in.pos() - 1));
        return record(rt, parent, label, depth);
    }

    private int record(int rt, DecodedNode parent, String label, int depth) throws Bin.FormatException {
        if (depth > MAX_DEPTH) throw new Bin.FormatException("nesting deeper than " + MAX_DEPTH + " at offset " + in.pos());
        trail.add(label);
        try {
            return recordBody(rt, parent, label, depth);
        } finally {
            trail.remove(trail.size() - 1);
        }
    }

    private int recordBody(int rt, DecodedNode parent, String label, int depth) throws Bin.FormatException {
        int at = in.pos() - 1;
        switch (rt) {
            case 1 -> { // ClassWithId
                int objectId = in.s32le();
                int metadataId = in.s32le();
                ClassMeta meta = metas.get(metadataId);
                if (meta == null) throw new Bin.FormatException("ClassWithId refers to unknown metadata #" + metadataId);
                DecodedNode n = classNode(parent, label, meta, objectId);
                values(n, meta, depth);
            }
            case 2, 3, 4, 5 -> {
                int objectId = in.s32le();
                String name = lps();
                int count = in.s32le();
                if (count < 0 || count > in.remaining()) throw new Bin.FormatException("bad member count " + count + " for " + name);
                List<String> members = new ArrayList<>(count);
                for (int i = 0; i < count; i++) members.add(lps());
                int[] types = null;
                Object[] extra = null;
                if (rt == 4 || rt == 5) {
                    types = new int[count];
                    extra = new Object[count];
                    for (int i = 0; i < count; i++) types[i] = in.u8();
                    for (int i = 0; i < count; i++) extra[i] = additionalInfo(types[i]);
                }
                Integer lib = (rt == 3 || rt == 5) ? in.s32le() : null;
                ClassMeta meta = new ClassMeta(name, members, types, extra, lib);
                if (metas.size() < MAX_META) metas.put(objectId, meta);
                DecodedNode n = classNode(parent, label, meta, objectId);
                n.put("record", recordName(rt));
                values(n, meta, depth);
            }
            case 6 -> { // BinaryObjectString
                int id = in.s32le();
                int start = in.pos();
                String s = lps();
                out.span(start, in.pos(), s, trail, 'N');
                budget.add(parent, DecodedNode.leaf(label, Codecs.truncate(s, MAX_STRING_SHOWN) + "  (#" + id + ")"));
            }
            case 7 -> binaryArray(parent, label, depth);
            case 8 -> { // MemberPrimitiveTyped
                int t = in.u8();
                primitive(parent, label, t);
            }
            case 9 -> budget.add(parent, DecodedNode.leaf(label, "→ #" + in.s32le()));
            case 10 -> budget.add(parent, DecodedNode.leaf(label, "null", DecodedNode.Type.NULL));
            case 13, 14 -> {
                int n = rt == 13 ? in.u8() : in.s32le();
                if (n < 1) throw new Bin.FormatException("bad null count " + n);
                budget.add(parent, DecodedNode.leaf(label, "null ×" + n, DecodedNode.Type.NULL));
                return n;
            }
            case 15 -> { // ArraySinglePrimitive
                int id = in.s32le();
                int len = in.s32le();
                int t = in.u8();
                primitiveArray(parent, label, id, len, t);
            }
            case 16, 17 -> { // ArraySingleObject / ArraySingleString
                int id = in.s32le();
                int len = in.s32le();
                if (len < 0 || len > in.remaining()) throw new Bin.FormatException("bad array length " + len);
                DecodedNode n = budget.add(parent, new DecodedNode(label,
                        (rt == 16 ? "object[" : "string[") + len + "]  (#" + id + ")", DecodedNode.Type.ARRAY));
                elements(n, len, depth);
            }
            case 21, 22 -> throw new Bin.FormatException((rt == 21 ? "BinaryMethodCall" : "BinaryMethodReturn")
                    + " record at offset " + at + " (remoting messages are not parsed)");
            default -> throw new Bin.FormatException("unknown record type " + rt + " at offset " + at);
        }
        return 1;
    }

    private DecodedNode classNode(DecodedNode parent, String label, ClassMeta meta, int objectId) throws Bin.LimitException {
        out.type(meta.name());
        String lib = meta.libraryId() == null ? null : libraries.get(meta.libraryId());
        DecodedNode n = budget.add(parent, new DecodedNode(label, meta.name() + "  (#" + objectId + ")", DecodedNode.Type.OBJECT));
        if (lib != null) n.put("library", lib);
        else if (meta.libraryId() == null) n.put("library", "mscorlib (system class)");
        String risky = RiskyTypes.reason(meta.name());
        if (risky != null) n.put("⚠ risk", risky);
        return n;
    }

    private void values(DecodedNode n, ClassMeta meta, int depth) throws Bin.FormatException {
        List<String> members = meta.members();
        int i = 0;
        while (i < members.size()) {
            String m = members.get(i);
            int bt = meta.binaryTypes() == null ? -1 : meta.binaryTypes()[i];
            if (bt == 0) {
                primitive(n, m, (Integer) meta.extra()[i]);
                i++;
            } else {
                i += valueRecord(n, m, depth + 1);
            }
        }
    }

    private void elements(DecodedNode n, long count, int depth) throws Bin.FormatException {
        long i = 0;
        while (i < count) {
            i += valueRecord(n, "[" + i + "]", depth + 1);
        }
    }

    private Object additionalInfo(int binaryType) throws Bin.FormatException {
        return switch (binaryType) {
            case 0, 7 -> in.u8(); // Primitive / PrimitiveArray: PrimitiveTypeEnum
            case 1, 2, 5, 6 -> null;
            case 3 -> lps(); // SystemClass
            case 4 -> { // Class: ClassTypeInfo
                String s = lps();
                in.s32le();
                yield s;
            }
            default -> throw new Bin.FormatException("unknown BinaryTypeEnum " + binaryType + " at offset " + (in.pos() - 1));
        };
    }

    private void binaryArray(DecodedNode parent, String label, int depth) throws Bin.FormatException {
        int id = in.s32le();
        int arrayType = in.u8();
        int rank = in.s32le();
        if (rank < 1 || rank > 32) throw new Bin.FormatException("bad array rank " + rank);
        long total = 1;
        StringBuilder dims = new StringBuilder();
        for (int i = 0; i < rank; i++) {
            int len = in.s32le();
            if (len < 0) throw new Bin.FormatException("negative array length");
            total *= len;
            if (total > Integer.MAX_VALUE) throw new Bin.FormatException("array too large");
            if (i > 0) dims.append(',');
            dims.append(len);
        }
        if (arrayType >= 3 && arrayType <= 5) for (int i = 0; i < rank; i++) in.s32le();
        int bt = in.u8();
        Object extra = additionalInfo(bt);
        String elemType = switch (bt) {
            case 0 -> primitiveName((Integer) extra);
            case 1 -> "string";
            case 2 -> "object";
            case 3, 4 -> String.valueOf(extra);
            case 5 -> "object[]";
            case 6 -> "string[]";
            default -> primitiveName((Integer) extra) + "[]";
        };
        if (bt == 3 || bt == 4) out.type(String.valueOf(extra));
        DecodedNode n = budget.add(parent, new DecodedNode(label, elemType + "[" + dims + "]  (#" + id + ")", DecodedNode.Type.ARRAY));
        if (bt == 0) {
            int t = (Integer) extra;
            int width = primitiveWidth(t);
            if (width > 0) in.need(total * width);
            long shown = Math.min(total, MAX_ARRAY_SHOWN);
            for (int i = 0; i < shown; i++) primitive(n, "[" + i + "]", t);
            for (long i = shown; i < total; i++) skipPrimitive(t);
            if (total > shown) budget.add(n, DecodedNode.note((total - shown) + " more elements not shown"));
        } else {
            if (total > in.remaining()) throw new Bin.FormatException("array size exceeds the remaining data");
            elements(n, total, depth);
        }
    }

    private void primitiveArray(DecodedNode parent, String label, int id, int len, int t) throws Bin.FormatException {
        if (len < 0) throw new Bin.FormatException("negative array length");
        int width = primitiveWidth(t);
        if (width > 0) in.need((long) len * width);
        else if (len > in.remaining()) throw new Bin.FormatException("array length exceeds the remaining data");
        DecodedNode n = budget.add(parent, new DecodedNode(label, primitiveName(t) + "[" + len + "]  (#" + id + ")", DecodedNode.Type.ARRAY));
        if (t == 2) { // Byte
            byte[] data = in.bytes(len);
            budget.add(n, DecodedNode.leaf("bytes", Codecs.hexPreview(data, 64), DecodedNode.Type.BINARY));
            if (isHeader(data, 0)) out.notes.add("byte array #" + id + " contains a nested BinaryFormatter stream");
            return;
        }
        int shown = Math.min(len, MAX_ARRAY_SHOWN);
        for (int i = 0; i < shown; i++) primitive(n, "[" + i + "]", t);
        for (int i = shown; i < len; i++) skipPrimitive(t);
        if (len > shown) budget.add(n, DecodedNode.note((len - shown) + " more elements not shown"));
    }

    private void primitive(DecodedNode parent, String label, int t) throws Bin.FormatException {
        String v;
        DecodedNode.Type type = DecodedNode.Type.NUMBER;
        switch (t) {
            case 1 -> { v = Boolean.toString(in.u8() != 0); type = DecodedNode.Type.BOOLEAN; }
            case 2 -> v = Integer.toString(in.u8());
            case 3 -> { v = "'" + utf8Char() + "'"; type = DecodedNode.Type.STRING; }
            case 5 -> v = lps();
            case 6 -> v = Double.toString(Double.longBitsToDouble(in.s64le()));
            case 7 -> v = Short.toString((short) in.u16le());
            case 8 -> v = Integer.toString(in.s32le());
            case 9 -> v = Long.toString(in.s64le());
            case 10 -> v = Byte.toString((byte) in.u8());
            case 11 -> v = Float.toString(Float.intBitsToFloat(in.s32le()));
            case 12 -> v = in.s64le() + " ticks (TimeSpan)";
            case 13 -> v = (in.s64le() & 0x3FFFFFFFFFFFFFFFL) + " ticks (DateTime)";
            case 14 -> v = Integer.toString(in.u16le());
            case 15 -> v = Long.toString(in.u32le());
            case 16 -> v = Long.toUnsignedString(in.s64le());
            case 17 -> { v = "null"; type = DecodedNode.Type.NULL; }
            case 18 -> { v = Codecs.truncate(lps(), MAX_STRING_SHOWN); type = DecodedNode.Type.STRING; }
            default -> throw new Bin.FormatException("unknown PrimitiveTypeEnum " + t + " at offset " + in.pos());
        }
        budget.add(parent, DecodedNode.leaf(label, v, type));
    }

    private void skipPrimitive(int t) throws Bin.FormatException {
        int w = primitiveWidth(t);
        if (w >= 0) {
            in.skip(w);
            return;
        }
        if (t == 3) utf8Char();
        else if (t == 5 || t == 18) lps();
        else throw new Bin.FormatException("unknown PrimitiveTypeEnum " + t);
    }

    private String utf8Char() throws Bin.FormatException {
        int c = in.peek();
        int n = c < 0x80 ? 1 : (c & 0xe0) == 0xc0 ? 2 : (c & 0xf0) == 0xe0 ? 3 : 4;
        return in.utf8(n);
    }

    /** LengthPrefixedString: 7-bit encoded length (at most 5 bytes) then UTF-8. */
    private String lps() throws Bin.FormatException {
        long len = 0;
        int shift = 0;
        for (int i = 0; i < 5; i++) {
            int b = in.u8();
            len |= (long) (b & 0x7f) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
            if (i == 4) throw new Bin.FormatException("bad string length prefix");
        }
        if (len > Integer.MAX_VALUE) throw new Bin.FormatException("string too long");
        return in.utf8(len);
    }

    private static int primitiveWidth(int t) {
        return switch (t) {
            case 1, 2, 10 -> 1;
            case 7, 14 -> 2;
            case 8, 11, 15 -> 4;
            case 6, 9, 12, 13, 16 -> 8;
            case 17 -> 0;
            default -> -1; // Char, Decimal, String: variable
        };
    }

    private static String primitiveName(int t) {
        return switch (t) {
            case 1 -> "Boolean";
            case 2 -> "Byte";
            case 3 -> "Char";
            case 5 -> "Decimal";
            case 6 -> "Double";
            case 7 -> "Int16";
            case 8 -> "Int32";
            case 9 -> "Int64";
            case 10 -> "SByte";
            case 11 -> "Single";
            case 12 -> "TimeSpan";
            case 13 -> "DateTime";
            case 14 -> "UInt16";
            case 15 -> "UInt32";
            case 16 -> "UInt64";
            case 17 -> "Null";
            case 18 -> "String";
            default -> "primitive(" + t + ")";
        };
    }

    private static String recordName(int rt) {
        return switch (rt) {
            case 2 -> "SystemClassWithMembers";
            case 3 -> "ClassWithMembers";
            case 4 -> "SystemClassWithMembersAndTypes";
            case 5 -> "ClassWithMembersAndTypes";
            default -> "record " + rt;
        };
    }
}
