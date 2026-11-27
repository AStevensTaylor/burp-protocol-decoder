package protocoldecoder.builtin.serialized;

import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Read-only structural parser for the Java Object Serialization Stream Protocol (version 5). It walks the grammar
 * (class descriptors, objects, arrays, strings, enums, references, block data) and reports class names, field
 * descriptors and primitive/string values. It never loads or instantiates a class.
 *
 * <p>Custom {@code writeObject}/{@code writeExternal} data is only understood when it is itself made of grammar
 * elements; when the stream cannot be followed precisely the parser stops, keeps what it has, and lists the class
 * names found by scanning the raw bytes for class descriptors.</p>
 */
final class JavaSerialParser {

    static final int MAGIC = 0xACED;
    static final int VERSION = 5;

    private static final int TC_NULL = 0x70;
    private static final int TC_REFERENCE = 0x71;
    private static final int TC_CLASSDESC = 0x72;
    private static final int TC_OBJECT = 0x73;
    private static final int TC_STRING = 0x74;
    private static final int TC_ARRAY = 0x75;
    private static final int TC_CLASS = 0x76;
    private static final int TC_BLOCKDATA = 0x77;
    private static final int TC_ENDBLOCKDATA = 0x78;
    private static final int TC_RESET = 0x79;
    private static final int TC_BLOCKDATALONG = 0x7A;
    private static final int TC_EXCEPTION = 0x7B;
    private static final int TC_LONGSTRING = 0x7C;
    private static final int TC_PROXYCLASSDESC = 0x7D;
    private static final int TC_ENUM = 0x7E;
    private static final int BASE_HANDLE = 0x7E0000;

    private static final int SC_WRITE_METHOD = 0x01;
    private static final int SC_SERIALIZABLE = 0x02;
    private static final int SC_EXTERNALIZABLE = 0x04;
    private static final int SC_BLOCK_DATA = 0x08;
    private static final int SC_ENUM = 0x10;

    private static final int MAX_DEPTH = 48;
    private static final int MAX_HANDLES = 200_000;
    private static final int MAX_ARRAY_SHOWN = 32;
    private static final int MAX_STRING_SHOWN = 2000;
    private static final int MAX_CLASSES_LISTED = 300;

    private static final class Field {
        final char type;
        final String name;
        final String className;

        Field(char type, String name, String className) {
            this.type = type;
            this.name = name;
            this.className = className;
        }
    }

    private static final class ClassDesc {
        String name;
        long suid;
        int flags;
        final List<Field> fields = new ArrayList<>();
        List<String> proxyInterfaces;
        ClassDesc superDesc;
    }

    private record ObjRef(String description) {
    }

    private final Bin in;
    private final ParseOutput.Budget budget;
    private final ParseOutput out = new ParseOutput("Stream");
    private final List<Object> handles = new ArrayList<>();
    private final Map<String, ClassDesc> classes = new LinkedHashMap<>();
    /** Labels from the top-level content to the current value, for insertion point paths. */
    private final List<String> trail = new ArrayList<>();

    private JavaSerialParser(byte[] data, ParseOutput.Budget budget) {
        this.in = new Bin(data);
        this.budget = budget;
    }

    static ParseOutput parse(byte[] data, ParseOutput.Budget budget) {
        JavaSerialParser p = new JavaSerialParser(data, budget);
        p.run(data);
        return p.out;
    }

    private void run(byte[] data) {
        DecodedNode root = out.structure;
        try {
            int magic = in.u16be();
            int version = in.u16be();
            if (magic != MAGIC) throw new Bin.FormatException("bad magic 0x" + Integer.toHexString(magic));
            root.put("Version", version);
            if (version != VERSION) out.notes.add("Unexpected stream version " + version + " (expected 5)");
            int i = 0;
            while (in.hasMore()) {
                readContent(root, "content[" + i++ + "]", 0, true);
            }
        } catch (Bin.FormatException e) {
            out.stop(e.getMessage());
        }
        if (!out.complete) {
            // Fall back to scanning for class descriptors anywhere in the stream.
            List<String> scanned = scanClassNames(data);
            if (!scanned.isEmpty()) {
                DecodedNode s = DecodedNode.array("Class names found by scanning");
                for (String n : scanned) {
                    s.add(DecodedNode.leaf("", n));
                    out.type(n);
                }
                out.extras.add(s);
            }
        }
        if (!classes.isEmpty()) out.extras.add(0, classTable());
    }

    // ------------------------------------------------------------------ grammar

    private void readContent(DecodedNode parent, String label, int depth, boolean allowBlockData) throws Bin.FormatException {
        if (depth > MAX_DEPTH) throw new Bin.FormatException("nesting deeper than " + MAX_DEPTH + " at offset " + in.pos());
        trail.add(label);
        try {
            readContentBody(parent, label, depth, allowBlockData);
        } finally {
            trail.remove(trail.size() - 1);
        }
    }

    private void readContentBody(DecodedNode parent, String label, int depth, boolean allowBlockData) throws Bin.FormatException {
        int at = in.pos();
        int tc = in.u8();
        switch (tc) {
            case TC_OBJECT -> readNewObject(parent, label, depth);
            case TC_CLASS -> {
                ClassDesc d = readClassDesc(depth + 1);
                int h = newHandle(new ObjRef("class " + nameOf(d)));
                budget.add(parent, DecodedNode.leaf(label, "class " + nameOf(d) + "  #" + h));
            }
            case TC_ARRAY -> readNewArray(parent, label, depth);
            case TC_STRING, TC_LONGSTRING -> {
                String s = readStringBody(tc);
                out.span(at, in.pos(), s, trail, 'J');
                budget.add(parent, DecodedNode.leaf(label, Codecs.truncate(s, MAX_STRING_SHOWN)));
            }
            case TC_ENUM -> {
                ClassDesc d = readClassDesc(depth + 1);
                int h = newHandle(null);
                String constant = readStringObject();
                handles.set(h, new ObjRef(nameOf(d) + "." + constant));
                budget.add(parent, DecodedNode.leaf(label, nameOf(d) + "." + constant + "  (enum)"));
            }
            case TC_CLASSDESC, TC_PROXYCLASSDESC -> {
                ClassDesc d = readClassDescBody(tc, depth + 1);
                budget.add(parent, DecodedNode.leaf(label, "class descriptor " + nameOf(d)));
            }
            case TC_REFERENCE -> budget.add(parent, DecodedNode.leaf(label, "→ " + describe(readHandle())));
            case TC_NULL -> budget.add(parent, DecodedNode.leaf(label, "null", DecodedNode.Type.NULL));
            case TC_EXCEPTION -> {
                handles.clear();
                DecodedNode n = budget.add(parent, new DecodedNode(label, "exception during serialization", DecodedNode.Type.OBJECT));
                readContent(n, "throwable", depth + 1, false);
                handles.clear();
            }
            case TC_RESET -> {
                handles.clear();
                budget.add(parent, DecodedNode.leaf(label, "reset (handle table cleared)", DecodedNode.Type.NOTE));
            }
            case TC_BLOCKDATA, TC_BLOCKDATALONG -> {
                if (!allowBlockData) {
                    throw new Bin.FormatException("block data where an object was expected at offset " + at
                            + " (custom writeObject data that does not match the declared fields)");
                }
                long len = tc == TC_BLOCKDATA ? in.u8() : in.s32be();
                byte[] data = in.bytes(len);
                budget.add(parent, DecodedNode.leaf(label, "blockdata (" + data.length + " bytes) " + Codecs.hexPreview(data, 32),
                        DecodedNode.Type.BINARY));
            }
            case TC_ENDBLOCKDATA -> {
                if (!allowBlockData) throw new Bin.FormatException("unexpected TC_ENDBLOCKDATA at offset " + at);
                budget.add(parent, DecodedNode.leaf(label, "end of block data (unexpected here)", DecodedNode.Type.NOTE));
            }
            default -> throw new Bin.FormatException(String.format("unknown type code 0x%02x at offset %d", tc, at));
        }
    }

    private void readNewObject(DecodedNode parent, String label, int depth) throws Bin.FormatException {
        ClassDesc desc = readClassDesc(depth + 1);
        if (desc == null) throw new Bin.FormatException("object with a null class descriptor at offset " + in.pos());
        int h = newHandle(new ObjRef(nameOf(desc) + " #" + (handles.size())));
        DecodedNode node = budget.add(parent, new DecodedNode(label, nameOf(desc) + "  #" + h, DecodedNode.Type.OBJECT));

        List<ClassDesc> chain = new ArrayList<>();
        for (ClassDesc d = desc; d != null && chain.size() < 64; d = d.superDesc) chain.add(0, d);
        boolean many = chain.size() > 1;
        for (ClassDesc cd : chain) {
            DecodedNode target = node;
            if (cd.proxyInterfaces != null) continue; // proxy classes carry no data of their own
            if (many && (!cd.fields.isEmpty() || (cd.flags & (SC_WRITE_METHOD | SC_EXTERNALIZABLE)) != 0)) {
                target = budget.add(node, new DecodedNode("‹" + cd.name + "›", null, DecodedNode.Type.OBJECT));
            }
            int flags = cd.flags;
            if ((flags & SC_EXTERNALIZABLE) != 0) {
                if ((flags & SC_BLOCK_DATA) == 0) {
                    throw new Bin.FormatException("externalizable class " + cd.name
                            + " uses protocol version 1 data, which cannot be parsed without the class");
                }
                readAnnotation(target, "writeExternal data", depth + 1);
            } else if ((flags & SC_SERIALIZABLE) != 0) {
                for (Field f : cd.fields) readFieldValue(target, f, depth + 1);
                if ((flags & SC_WRITE_METHOD) != 0) readAnnotation(target, "writeObject data", depth + 1);
            }
        }
    }

    private void readFieldValue(DecodedNode parent, Field f, int depth) throws Bin.FormatException {
        String label = f.name;
        switch (f.type) {
            case 'B' -> num(parent, label, (byte) in.u8());
            case 'C' -> budget.add(parent, DecodedNode.leaf(label, charLiteral((char) in.u16be())));
            case 'D' -> num(parent, label, Double.longBitsToDouble(in.s64be()));
            case 'F' -> num(parent, label, Float.intBitsToFloat(in.s32be()));
            case 'I' -> num(parent, label, in.s32be());
            case 'J' -> num(parent, label, in.s64be());
            case 'S' -> num(parent, label, (short) in.u16be());
            case 'Z' -> budget.add(parent, DecodedNode.leaf(label, Boolean.toString(in.u8() != 0), DecodedNode.Type.BOOLEAN));
            case 'L', '[' -> readContent(parent, label, depth, false);
            default -> throw new Bin.FormatException("unknown field type '" + f.type + "' for field " + f.name);
        }
    }

    private void num(DecodedNode parent, String label, Number n) throws Bin.LimitException {
        budget.add(parent, DecodedNode.leaf(label, n.toString(), DecodedNode.Type.NUMBER));
    }

    /** objectAnnotation / classAnnotation: contents up to TC_ENDBLOCKDATA. */
    private void readAnnotation(DecodedNode parent, String label, int depth) throws Bin.FormatException {
        if (depth > MAX_DEPTH) throw new Bin.FormatException("nesting deeper than " + MAX_DEPTH);
        if (in.peek() == TC_ENDBLOCKDATA) {
            in.u8();
            return;
        }
        DecodedNode n = budget.add(parent, DecodedNode.array(label));
        int i = 0;
        while (true) {
            if (in.peek() == TC_ENDBLOCKDATA) {
                in.u8();
                return;
            }
            readContent(n, "[" + i++ + "]", depth + 1, true);
        }
    }

    private void readNewArray(DecodedNode parent, String label, int depth) throws Bin.FormatException {
        ClassDesc desc = readClassDesc(depth + 1);
        if (desc == null) throw new Bin.FormatException("array with a null class descriptor at offset " + in.pos());
        String cls = desc.name;
        int h = newHandle(new ObjRef(readableType(cls)));
        int size = in.s32be();
        if (size < 0) throw new Bin.FormatException("negative array size " + size);
        char elem = cls.length() > 1 && cls.charAt(0) == '[' ? cls.charAt(1) : 'L';
        int width = primitiveWidth(elem);
        DecodedNode n = budget.add(parent, new DecodedNode(label, readableType(cls).replace("[]", "[" + size + "]") + "  #" + h,
                DecodedNode.Type.ARRAY));
        if (width > 0) {
            in.need((long) size * width);
            if (elem == 'B') {
                byte[] data = in.bytes(size);
                budget.add(n, DecodedNode.leaf("bytes", Codecs.hexPreview(data, 64), DecodedNode.Type.BINARY));
                if (data.length >= 4 && Codecs.isMostlyText(data)) {
                    budget.add(n, DecodedNode.leaf("as text", Codecs.truncate(new String(data, StandardCharsets.UTF_8), MAX_STRING_SHOWN)));
                }
                return;
            }
            int shown = Math.min(size, MAX_ARRAY_SHOWN);
            for (int i = 0; i < shown; i++) readFieldValue(n, new Field(elem, "[" + i + "]", null), depth + 1);
            if (size > shown) {
                in.skip((long) (size - shown) * width);
                budget.add(n, DecodedNode.note((size - shown) + " more elements not shown"));
            }
        } else {
            if (size > in.remaining()) throw new Bin.FormatException("array size " + size + " exceeds the remaining data");
            for (int i = 0; i < size; i++) readContent(n, "[" + i + "]", depth + 1, false);
        }
    }

    private ClassDesc readClassDesc(int depth) throws Bin.FormatException {
        if (depth > MAX_DEPTH) throw new Bin.FormatException("class descriptor nesting deeper than " + MAX_DEPTH);
        int at = in.pos();
        int tc = in.u8();
        return switch (tc) {
            case TC_NULL -> null;
            case TC_REFERENCE -> {
                Object o = readHandle();
                if (!(o instanceof ClassDesc d)) throw new Bin.FormatException("reference at offset " + at + " is not a class descriptor");
                yield d;
            }
            case TC_CLASSDESC, TC_PROXYCLASSDESC -> readClassDescBody(tc, depth);
            default -> throw new Bin.FormatException(String.format("expected a class descriptor at offset %d, found 0x%02x", at, tc));
        };
    }

    private ClassDesc readClassDescBody(int tc, int depth) throws Bin.FormatException {
        if (depth > MAX_DEPTH) throw new Bin.FormatException("class descriptor nesting deeper than " + MAX_DEPTH);
        ClassDesc d = new ClassDesc();
        if (tc == TC_CLASSDESC) {
            d.name = readUtf();
            d.suid = in.s64be();
            newHandle(d);
            d.flags = in.u8();
            int count = in.u16be();
            if (count * 3L > in.remaining()) throw new Bin.FormatException("field count " + count + " exceeds the remaining data");
            for (int i = 0; i < count; i++) {
                char type = (char) in.u8();
                String fname = readUtf();
                String cls = null;
                if (type == 'L' || type == '[') cls = readStringObject();
                else if (primitiveWidth(type) < 0) throw new Bin.FormatException("unknown field type code '" + type + "' in class " + d.name);
                d.fields.add(new Field(type, fname, cls));
            }
            remember(d);
        } else {
            newHandle(d);
            int count = in.s32be();
            if (count < 0 || count * 2L > in.remaining()) throw new Bin.FormatException("bad proxy interface count " + count);
            d.proxyInterfaces = new ArrayList<>();
            for (int i = 0; i < count; i++) {
                String iface = readUtf();
                d.proxyInterfaces.add(iface);
                out.type(iface);
            }
            d.name = "Proxy" + d.proxyInterfaces;
            d.flags = SC_SERIALIZABLE;
            remember(d);
        }
        DecodedNode annotation = DecodedNode.array("annotation");
        readAnnotation(annotation, "class annotation", depth + 1);
        d.superDesc = readClassDesc(depth + 1);
        return d;
    }

    private void remember(ClassDesc d) {
        // Primitive arrays ("[B", "[I") are noise in the type list; object arrays are shown readably.
        if (d.proxyInterfaces == null && !(d.name.length() == 2 && d.name.charAt(0) == '[')) out.type(readableType(d.name));
        if (classes.size() < MAX_CLASSES_LISTED) classes.putIfAbsent(d.name, d);
    }

    private String readStringObject() throws Bin.FormatException {
        int at = in.pos();
        int tc = in.u8();
        return switch (tc) {
            case TC_STRING, TC_LONGSTRING -> readStringBody(tc);
            case TC_REFERENCE -> {
                Object o = readHandle();
                if (!(o instanceof String s)) throw new Bin.FormatException("reference at offset " + at + " is not a string");
                yield s;
            }
            default -> throw new Bin.FormatException(String.format("expected a string at offset %d, found 0x%02x", at, tc));
        };
    }

    private String readStringBody(int tc) throws Bin.FormatException {
        String s;
        if (tc == TC_STRING) {
            s = readUtf();
        } else {
            long len = in.s64be();
            in.need(len);
            s = decodeModifiedUtf8(in.bytes(len));
        }
        newHandle(s);
        return s;
    }

    private String readUtf() throws Bin.FormatException {
        int len = in.u16be();
        return decodeModifiedUtf8(in.bytes(len));
    }

    private int newHandle(Object o) throws Bin.FormatException {
        if (handles.size() >= MAX_HANDLES) throw new Bin.FormatException("too many handles");
        handles.add(o);
        return handles.size() - 1;
    }

    private Object readHandle() throws Bin.FormatException {
        int raw = in.s32be();
        int h = raw - BASE_HANDLE;
        if (h < 0 || h >= handles.size()) {
            throw new Bin.FormatException("invalid back-reference 0x" + Integer.toHexString(raw) + " at offset " + (in.pos() - 4));
        }
        Object o = handles.get(h);
        return o == null ? new ObjRef("#" + h) : o;
    }

    private static String describe(Object o) {
        if (o instanceof String s) return "\"" + Codecs.truncate(s, 200) + "\"";
        if (o instanceof ClassDesc d) return "class descriptor " + nameOf(d);
        if (o instanceof ObjRef r) return r.description();
        return String.valueOf(o);
    }

    // ------------------------------------------------------------------ output helpers

    private DecodedNode classTable() {
        DecodedNode t = DecodedNode.object("Classes");
        for (ClassDesc d : classes.values()) {
            DecodedNode c = new DecodedNode(readableType(d.name), null, DecodedNode.Type.OBJECT);
            if (d.proxyInterfaces != null) {
                c.put("kind", "dynamic proxy");
            } else {
                c.put("serialVersionUID", String.format("0x%016x (%d)", d.suid, d.suid));
                c.put("flags", flagText(d.flags));
                if (!d.fields.isEmpty()) {
                    DecodedNode fs = DecodedNode.object("fields");
                    for (Field f : d.fields) {
                        String type = f.className != null ? readableType(f.className) : primitiveName(f.type);
                        fs.add(DecodedNode.leaf(f.name, type));
                    }
                    c.add(fs);
                }
            }
            if (d.superDesc != null) c.put("extends", nameOf(d.superDesc));
            String risky = RiskyTypes.reason(d.name);
            if (risky != null) c.put("⚠ risk", risky);
            t.add(c);
        }
        return t;
    }

    private static String flagText(int flags) {
        List<String> s = new ArrayList<>();
        if ((flags & SC_SERIALIZABLE) != 0) s.add("SERIALIZABLE");
        if ((flags & SC_WRITE_METHOD) != 0) s.add("WRITE_METHOD");
        if ((flags & SC_EXTERNALIZABLE) != 0) s.add("EXTERNALIZABLE");
        if ((flags & SC_BLOCK_DATA) != 0) s.add("BLOCK_DATA");
        if ((flags & SC_ENUM) != 0) s.add("ENUM");
        return String.format("0x%02x %s", flags, String.join("|", s));
    }

    private static String nameOf(ClassDesc d) {
        return d == null ? "null" : readableType(d.name);
    }

    /** "[Ljava.lang.String;" → "java.lang.String[]", "Ljava/util/Map;" → "java.util.Map", "[I" → "int[]". */
    static String readableType(String jvm) {
        if (jvm == null || jvm.isEmpty()) return String.valueOf(jvm);
        int dims = 0;
        while (dims < jvm.length() && jvm.charAt(dims) == '[') dims++;
        if (dims == 0 && !(jvm.startsWith("L") && jvm.endsWith(";"))) return jvm;
        String base = jvm.substring(dims);
        String name;
        if (base.startsWith("L") && base.endsWith(";")) name = base.substring(1, base.length() - 1).replace('/', '.');
        else if (base.length() == 1 && primitiveWidth(base.charAt(0)) > 0) name = primitiveName(base.charAt(0));
        else name = base;
        return name + "[]".repeat(dims);
    }

    private static String primitiveName(char t) {
        return switch (t) {
            case 'B' -> "byte";
            case 'C' -> "char";
            case 'D' -> "double";
            case 'F' -> "float";
            case 'I' -> "int";
            case 'J' -> "long";
            case 'S' -> "short";
            case 'Z' -> "boolean";
            default -> String.valueOf(t);
        };
    }

    private static int primitiveWidth(char t) {
        return switch (t) {
            case 'B', 'Z' -> 1;
            case 'C', 'S' -> 2;
            case 'I', 'F' -> 4;
            case 'J', 'D' -> 8;
            case 'L', '[' -> 0;
            default -> -1;
        };
    }

    private static String charLiteral(char c) {
        return c >= 0x20 && c < 0x7f ? "'" + c + "'" : String.format("'\\u%04x'", (int) c);
    }

    /** Java's modified UTF-8 (two-byte NUL, surrogate pairs encoded separately). Invalid bytes become U+FFFD. */
    static String decodeModifiedUtf8(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length);
        int i = 0;
        while (i < b.length) {
            int c = b[i] & 0xff;
            if (c < 0x80) {
                sb.append((char) c);
                i++;
            } else if ((c & 0xe0) == 0xc0 && i + 1 < b.length && (b[i + 1] & 0xc0) == 0x80) {
                sb.append((char) (((c & 0x1f) << 6) | (b[i + 1] & 0x3f)));
                i += 2;
            } else if ((c & 0xf0) == 0xe0 && i + 2 < b.length && (b[i + 1] & 0xc0) == 0x80 && (b[i + 2] & 0xc0) == 0x80) {
                sb.append((char) (((c & 0x0f) << 12) | ((b[i + 1] & 0x3f) << 6) | (b[i + 2] & 0x3f)));
                i += 3;
            } else {
                sb.append('�');
                i++;
            }
        }
        return sb.toString();
    }

    /** Finds TC_CLASSDESC records anywhere in the bytes and returns plausible class names (fallback). */
    static List<String> scanClassNames(byte[] b) {
        List<String> names = new ArrayList<>();
        for (int i = 0; i + 3 < b.length && names.size() < 200; i++) {
            if ((b[i] & 0xff) != TC_CLASSDESC) continue;
            int len = ((b[i + 1] & 0xff) << 8) | (b[i + 2] & 0xff);
            if (len < 2 || len > 512 || i + 3 + len + 8 > b.length) continue;
            String s = new String(b, i + 3, len, StandardCharsets.ISO_8859_1);
            if (isClassName(s) && !names.contains(s)) names.add(s);
        }
        return names;
    }

    private static boolean isClassName(String s) {
        if (!(Character.isJavaIdentifierStart(s.charAt(0)) || s.charAt(0) == '[')) return false;
        boolean dot = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '.') dot = true;
            else if (!(Character.isJavaIdentifierPart(c) || c == '[' || c == ';') || c < 0x20 || c > 0x7e) return false;
        }
        return dot || s.startsWith("[");
    }
}
