package protocoldecoder.builtin.blazor;

import com.google.gson.JsonElement;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.util.List;
import java.util.Map;

/** Converts values produced by {@link MsgPack} into tree nodes, expanding strings that contain JSON. */
final class MsgPackTree {

    private MsgPackTree() {
    }

    static DecodedNode toNode(String name, Object v) {
        return toNode(name, v, 0);
    }

    private static DecodedNode toNode(String name, Object v, int depth) {
        if (v == null) return DecodedNode.leaf(name, "null", DecodedNode.Type.NULL);
        if (v instanceof Boolean b) return DecodedNode.leaf(name, b.toString(), DecodedNode.Type.BOOLEAN);
        if (v instanceof Long || v instanceof Integer) return DecodedNode.leaf(name, v.toString(), DecodedNode.Type.NUMBER);
        if (v instanceof Double d) return DecodedNode.leaf(name, d == Math.rint(d) && Math.abs(d) < 1e15 ? Long.toString(d.longValue()) : d.toString(), DecodedNode.Type.NUMBER);
        if (v instanceof String s) {
            if (JsonTree.looksLikeJson(s)) {
                JsonElement e = JsonTree.parseStrict(s);
                if (e != null) return JsonTree.toNode(name + " (JSON)", e, true);
            }
            return DecodedNode.leaf(name, s);
        }
        if (v instanceof byte[] b) {
            if (b.length > 0 && Codecs.isMostlyText(b)) {
                String s = Codecs.utf8(b);
                if (JsonTree.looksLikeJson(s)) {
                    JsonElement e = JsonTree.parseStrict(s);
                    if (e != null) return JsonTree.toNode(name + " (bytes, JSON)", e, true);
                }
                return DecodedNode.leaf(name + " (bytes, text)", s);
            }
            return DecodedNode.leaf(name + " (" + b.length + " bytes)", Codecs.hexPreview(b, 64), DecodedNode.Type.BINARY);
        }
        if (v instanceof MsgPack.Ext x) {
            return DecodedNode.leaf(name + " (ext " + x.type() + ")", Codecs.hexPreview(x.data(), 32), DecodedNode.Type.BINARY);
        }
        if (depth > 64) return DecodedNode.note("nested too deep");
        if (v instanceof List<?> l) {
            DecodedNode n = DecodedNode.array(name);
            for (int i = 0; i < l.size(); i++) n.add(toNode("[" + i + "]", l.get(i), depth + 1));
            return n;
        }
        if (v instanceof Map<?, ?> m) {
            DecodedNode n = DecodedNode.object(name);
            m.forEach((k, val) -> n.add(toNode(String.valueOf(k), val, depth + 1)));
            return n;
        }
        return DecodedNode.leaf(name, String.valueOf(v));
    }
}
