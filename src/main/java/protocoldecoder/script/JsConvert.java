package protocoldecoder.script;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.Function;
import org.mozilla.javascript.NativeArray;
import org.mozilla.javascript.NativeJSON;
import org.mozilla.javascript.ScriptRuntime;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.ScriptableObject;
import org.mozilla.javascript.Undefined;
import protocoldecoder.core.DecodedNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Conversions between JavaScript values and Java/tree values, with depth and size limits. */
final class JsConvert {

    static final int MAX_DEPTH = 100;
    static final int MAX_STRING = 1024 * 1024;

    private JsConvert() {
    }

    static Object fromJson(Context cx, Scriptable scope, JsonElement e, int depth) {
        if (e == null || e.isJsonNull() || depth > MAX_DEPTH) return null;
        if (e.isJsonObject()) {
            Scriptable o = cx.newObject(scope);
            for (Map.Entry<String, JsonElement> en : e.getAsJsonObject().entrySet()) {
                ScriptableObject.putProperty(o, en.getKey(), fromJson(cx, scope, en.getValue(), depth + 1));
            }
            return o;
        }
        if (e.isJsonArray()) {
            JsonArray a = e.getAsJsonArray();
            Object[] items = new Object[a.size()];
            for (int i = 0; i < items.length; i++) items[i] = fromJson(cx, scope, a.get(i), depth + 1);
            return cx.newArray(scope, items);
        }
        JsonPrimitive p = e.getAsJsonPrimitive();
        if (p.isBoolean()) return p.getAsBoolean();
        if (p.isNumber()) return p.getAsDouble();
        return p.getAsString();
    }

    static String stringify(Context cx, Scriptable scope, Scriptable value) {
        try {
            Object s = NativeJSON.stringify(cx, scope, value, null, null);
            return Context.toString(s);
        } catch (RuntimeException e) {
            return Context.toString(value);
        }
    }

    /** Thrown when a script result exceeds the output limits. */
    static final class TooLarge extends RuntimeException {
        TooLarge(String m) {
            super(m, null, false, false);
        }
    }

    /** Converts any JS value to a tree, counting nodes against a budget. */
    static DecodedNode toNode(String name, Object v, int[] budget, int depth) {
        if (--budget[0] < 0) throw new TooLarge("decode() result has too many nodes");
        if (v == null || Undefined.isUndefined(v)) return DecodedNode.leaf(name, "null", DecodedNode.Type.NULL);
        if (v instanceof Boolean b) return DecodedNode.leaf(name, b.toString(), DecodedNode.Type.BOOLEAN);
        if (v instanceof Number n) return DecodedNode.leaf(name, formatNumber(n.doubleValue()), DecodedNode.Type.NUMBER);
        if (v instanceof CharSequence cs) return stringLeaf(name, cs.toString());
        if (v instanceof Function) return DecodedNode.leaf(name, "[function]", DecodedNode.Type.NOTE);
        if (depth > MAX_DEPTH) return DecodedNode.leaf(name, "… (nested too deep)", DecodedNode.Type.NOTE);
        if (v instanceof NativeArray arr) {
            DecodedNode n = DecodedNode.array(name);
            long len = arr.getLength();
            for (int i = 0; i < len; i++) n.add(toNode("[" + i + "]", arr.get(i, arr), budget, depth + 1));
            return n;
        }
        if (v instanceof Scriptable s) {
            String cls = s.getClassName();
            if ("Date".equals(cls) || "RegExp".equals(cls) || "Error".equals(cls)) {
                return stringLeaf(name, Context.toString(v));
            }
            if (s instanceof ScriptableObject so && ScriptRuntime.isArrayObject(so)) {
                DecodedNode n = DecodedNode.array(name);
                Object lenObj = ScriptableObject.getProperty(so, "length");
                long len = lenObj instanceof Number num ? num.longValue() : 0;
                for (int i = 0; i < len; i++) n.add(toNode("[" + i + "]", ScriptableObject.getProperty(so, i), budget, depth + 1));
                return n;
            }
            DecodedNode n = DecodedNode.object(name);
            for (Object id : s.getIds()) {
                Object child = id instanceof Number num ? s.get(num.intValue(), s) : s.get(String.valueOf(id), s);
                if (child == Scriptable.NOT_FOUND) continue;
                n.add(toNode(String.valueOf(id), child, budget, depth + 1));
            }
            return n;
        }
        return stringLeaf(name, String.valueOf(v));
    }

    private static DecodedNode stringLeaf(String name, String s) {
        if (s.length() > MAX_STRING) s = s.substring(0, MAX_STRING) + "… (truncated)";
        String t = s.stripLeading();
        boolean html = t.startsWith("<") && (t.contains("</") || t.contains("/>"));
        return DecodedNode.leaf(name, s, html ? DecodedNode.Type.HTML : DecodedNode.Type.STRING);
    }

    static String formatNumber(double d) {
        if (d == Math.rint(d) && !Double.isInfinite(d) && Math.abs(d) < 1e15) return Long.toString((long) d);
        return Double.toString(d);
    }

    static String str(Object v) {
        if (v == null || Undefined.isUndefined(v) || v == Scriptable.NOT_FOUND) return null;
        return Context.toString(v);
    }

    static List<String> strings(Object v) {
        List<String> out = new ArrayList<>();
        if (v instanceof NativeArray arr) {
            for (int i = 0; i < arr.getLength() && i < 100; i++) {
                String s = str(arr.get(i, arr));
                if (s != null) out.add(s);
            }
        } else if (str(v) != null) {
            out.add(str(v));
        }
        return out;
    }

    /** Converts a JSON-like Java structure (for tests). */
    static JsonElement toJson(DecodedNode n) {
        if (n.type() == DecodedNode.Type.OBJECT) {
            JsonObject o = new JsonObject();
            n.children().forEach(c -> o.add(c.name(), toJson(c)));
            return o;
        }
        if (n.type() == DecodedNode.Type.ARRAY) {
            JsonArray a = new JsonArray();
            n.children().forEach(c -> a.add(toJson(c)));
            return a;
        }
        return new JsonPrimitive(n.value() == null ? "null" : n.value());
    }
}
