package protocoldecoder.builtin.blazor;

import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;

/**
 * Decoder for the binary render batch Blazor Server sends to the browser ({@code JS.RenderBatch}).
 *
 * <p>Layout (as read by Blazor's {@code OutOfProcessRenderBatch}): the batch ends with five little-endian int32
 * offsets: updated components, reference frames, disposed component ids, disposed event handler ids, string table.
 * Array ranges are {@code int32 count} followed by entries. Updated components are int32 pointers to diffs
 * ({@code componentId, editCount, edits[16 bytes]}); reference frames are 20 bytes; strings are LEB128-length-prefixed
 * UTF-8, addressed through an int32 position table.</p>
 */
final class RenderBatch {

    private static final int FRAME = 20;
    private static final int EDIT = 16;
    private static final int MAX_ITEMS = 5000;

    static final String[] EDIT_TYPES = {"?", "PrependFrame", "RemoveFrame", "SetAttribute", "RemoveAttribute", "UpdateText",
            "StepIn", "StepOut", "UpdateMarkup", "PermutationListEntry", "PermutationListEnd"};
    static final String[] FRAME_TYPES = {"?", "Element", "Text", "Attribute", "Component", "Region", "ElementReferenceCapture",
            "ComponentReferenceCapture", "Markup", "ComponentRenderMode", "NamedEvent"};

    /** Thrown when the bytes don't follow the expected layout. */
    static final class FormatException extends Exception {
        FormatException(String m) {
            super(m);
        }
    }

    private final byte[] b;
    private final int limit; // start of the 20-byte trailer
    private final int stringTable;
    private int stringCount = -1;

    private RenderBatch(byte[] b) throws FormatException {
        this.b = b;
        if (b.length < 20 + 4 * 4) throw new FormatException("too short for a render batch");
        this.limit = b.length - 20;
        this.stringTable = offset(b.length - 4);
    }

    /** Decodes a batch into a tree, or a fallback node listing printable strings if the layout doesn't fit. */
    static DecodedNode decode(String name, byte[] data, Long batchId) {
        try {
            return new RenderBatch(data).toNode(name, batchId);
        } catch (FormatException | RuntimeException e) {
            DecodedNode n = DecodedNode.object(name + " (unparsed)");
            n.add(DecodedNode.note("not a recognised render batch layout: " + e.getMessage()));
            n.put("Size", data.length);
            n.add(DecodedNode.leaf("Hex", Codecs.hexPreview(data, 96), DecodedNode.Type.BINARY));
            return n;
        }
    }

    /** Summary line, e.g. "2 components, 14 frames". Null if unparseable. */
    static String summarize(byte[] data) {
        try {
            RenderBatch rb = new RenderBatch(data);
            int uc = rb.count(rb.offset(data.length - 20));
            int rf = rb.count(rb.offset(data.length - 16));
            return uc + " component" + (uc == 1 ? "" : "s") + " updated, " + rf + " frames";
        } catch (FormatException | RuntimeException e) {
            return null;
        }
    }

    private DecodedNode toNode(String name, Long batchId) throws FormatException {
        int ucOff = offset(b.length - 20);
        int rfOff = offset(b.length - 16);
        int dcOff = offset(b.length - 12);
        int deOff = offset(b.length - 8);
        int rfCount = count(rfOff);
        checkRange(rfOff + 4, rfCount, FRAME);

        DecodedNode root = DecodedNode.object(name);
        if (batchId != null) root.put("Batch ID", batchId);
        root.put("Size", b.length);

        int ucCount = count(ucOff);
        checkRange(ucOff + 4, ucCount, 4);
        DecodedNode comps = DecodedNode.array("Updated components");
        for (int i = 0; i < Math.min(ucCount, MAX_ITEMS); i++) {
            int diff = offset(ucOff + 4 + i * 4);
            int componentId = i32(diff);
            int editCount = count(diff + 4);
            checkRange(diff + 8, editCount, EDIT);
            DecodedNode c = DecodedNode.object("Component #" + componentId);
            DecodedNode edits = DecodedNode.array("Edits");
            for (int j = 0; j < Math.min(editCount, MAX_ITEMS); j++) {
                int e = diff + 8 + j * EDIT;
                edits.add(edit(e, rfOff, rfCount));
            }
            c.add(edits);
            comps.add(c);
        }
        root.add(comps);

        DecodedNode frames = DecodedNode.array("Reference frames");
        for (int k = 0; k < Math.min(rfCount, MAX_ITEMS); k++) {
            frames.add(DecodedNode.leaf("[" + k + "]", frame(rfOff + 4 + k * FRAME)));
        }
        if (rfCount > MAX_ITEMS) frames.add(DecodedNode.note((rfCount - MAX_ITEMS) + " more frames not shown"));
        root.add(frames);

        int dc = count(dcOff);
        checkRange(dcOff + 4, dc, 4);
        if (dc > 0) {
            DecodedNode n = DecodedNode.array("Disposed component IDs");
            for (int i = 0; i < Math.min(dc, MAX_ITEMS); i++) n.add(DecodedNode.leaf("", Integer.toString(i32(dcOff + 4 + i * 4)), DecodedNode.Type.NUMBER));
            root.add(n);
        }
        int de = count(deOff);
        checkRange(deOff + 4, de, 8);
        if (de > 0) {
            DecodedNode n = DecodedNode.array("Disposed event handler IDs");
            for (int i = 0; i < Math.min(de, MAX_ITEMS); i++) n.add(DecodedNode.leaf("", Long.toUnsignedString(i64(deOff + 4 + i * 8)), DecodedNode.Type.NUMBER));
            root.add(n);
        }

        DecodedNode strings = DecodedNode.array("String table");
        int sc = stringCount();
        for (int i = 0; i < Math.min(sc, MAX_ITEMS); i++) strings.add(DecodedNode.leaf("[" + i + "]", string(i)));
        root.add(strings);
        return root;
    }

    private DecodedNode edit(int e, int rfOff, int rfCount) throws FormatException {
        int type = i32(e);
        int sibling = i32(e + 4);
        int frameIndex = i32(e + 8);
        String typeName = type > 0 && type < EDIT_TYPES.length ? EDIT_TYPES[type] : "Edit type " + type;
        StringBuilder sb = new StringBuilder(typeName).append(" @").append(sibling);
        switch (type) {
            case 1, 3, 5, 8 -> { // reference a frame
                if (frameIndex >= 0 && frameIndex < rfCount) sb.append(" → ").append(frame(rfOff + 4 + frameIndex * FRAME));
                else sb.append(" → frame ").append(frameIndex);
            }
            case 4 -> sb.append(" → ").append(string(i32(e + 12)));
            case 9 -> sb.append(" → move to ").append(frameIndex);
            default -> {
            }
        }
        return DecodedNode.leaf("", sb.toString());
    }

    private String frame(int f) throws FormatException {
        int type = i32(f);
        String t = type > 0 && type < FRAME_TYPES.length ? FRAME_TYPES[type] : "Frame type " + type;
        return switch (type) {
            case 1 -> "<" + string(i32(f + 8)) + ">  (subtree " + i32(f + 4) + ")";
            case 2 -> "Text \"" + string(i32(f + 4)) + "\"";
            case 3 -> {
                String v = string(i32(f + 8));
                long handler = i64(f + 12);
                yield "Attribute " + string(i32(f + 4)) + (v == null ? "" : "=\"" + v + "\"")
                        + (handler != 0 ? "  (event handler " + Long.toUnsignedString(handler) + ")" : "");
            }
            case 4 -> "Component #" + i32(f + 8) + "  (subtree " + i32(f + 4) + ")";
            case 5 -> "Region  (subtree " + i32(f + 4) + ")";
            case 6 -> "ElementReferenceCapture " + string(i32(f + 4));
            case 8 -> "Markup " + Codecs.truncate(string(i32(f + 4)), 500);
            default -> t + " [" + i32(f + 4) + ", " + i32(f + 8) + ", " + i32(f + 12) + ", " + i32(f + 16) + "]";
        };
    }

    private int stringCount() {
        if (stringCount < 0) stringCount = Math.max(0, (limit - stringTable) / 4);
        return stringCount;
    }

    private String string(int index) throws FormatException {
        if (index == -1) return null;
        if (index < 0 || index >= stringCount()) throw new FormatException("string index " + index + " out of range");
        int p = offset(stringTable + index * 4);
        int len = 0, shift = 0;
        while (true) {
            if (p >= limit || shift > 28) throw new FormatException("bad string length at " + p);
            int x = b[p++] & 0xff;
            len |= (x & 0x7f) << shift;
            if ((x & 0x80) == 0) break;
            shift += 7;
        }
        if (len < 0 || p + len > limit) throw new FormatException("string at " + p + " overruns batch");
        return new String(b, p, len, StandardCharsets.UTF_8);
    }

    private int count(int at) throws FormatException {
        int c = i32(at);
        if (c < 0) throw new FormatException("negative count at " + at);
        return c;
    }

    private void checkRange(int start, int count, int entry) throws FormatException {
        if ((long) start + (long) count * entry > limit) throw new FormatException("array at " + start + " overruns batch");
    }

    /** Reads an int32 that must point inside the batch body. */
    private int offset(int at) throws FormatException {
        int v = i32(at);
        if (v < 0 || v >= Math.max(1, b.length - 20 + 1)) throw new FormatException("offset " + v + " out of range");
        return v;
    }

    private int i32(int at) throws FormatException {
        if (at < 0 || at + 4 > b.length) throw new FormatException("read past end at " + at);
        return (b[at] & 0xff) | (b[at + 1] & 0xff) << 8 | (b[at + 2] & 0xff) << 16 | (b[at + 3] & 0xff) << 24;
    }

    private long i64(int at) throws FormatException {
        return (i32(at) & 0xffffffffL) | ((long) i32(at + 4) << 32);
    }
}
