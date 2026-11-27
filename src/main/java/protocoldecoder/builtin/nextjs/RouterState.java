package protocoldecoder.builtin.nextjs;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The App Router's {@code Next-Router-State-Tree} header: URL-encoded JSON of the client's current route tree,
 * {@code [segment, {parallelRouteKey: subtree}, url?, refreshMarker?, isRootLayout?]}, where a dynamic segment is
 * {@code [paramName, value, type]}.
 */
final class RouterState {

    private static final int MAX_DEPTH = 40;

    private RouterState() {
    }

    static JsonElement parse(String headerValue) {
        if (headerValue == null || headerValue.isBlank()) return null;
        String v = headerValue.trim();
        JsonElement e = JsonTree.parseStrict(v);
        if (e == null && v.contains("%")) e = JsonTree.parseStrict(Codecs.urlDecode(v.replace("+", "%2B")));
        return e;
    }

    /** "/dashboard/[id=42]" style path following the "children" slots of the tree, or null. */
    static String path(JsonElement tree) {
        List<String> parts = new ArrayList<>();
        JsonElement cur = tree;
        for (int d = 0; d < MAX_DEPTH && cur != null && cur.isJsonArray(); d++) {
            JsonArray a = cur.getAsJsonArray();
            if (a.size() == 0) break;
            String seg = pathSegment(a.get(0));
            if (seg != null) parts.add(seg);
            if (a.size() < 2 || !a.get(1).isJsonObject()) break;
            JsonObject slots = a.get(1).getAsJsonObject();
            cur = slots.has("children") ? slots.get("children") : slots.entrySet().stream().findFirst().map(Map.Entry::getValue).orElse(null);
        }
        if (tree == null || !tree.isJsonArray()) return null;
        return "/" + String.join("/", parts);
    }

    private static String pathSegment(JsonElement seg) {
        if (seg == null) return null;
        if (seg.isJsonArray()) {
            JsonArray a = seg.getAsJsonArray();
            String name = a.size() > 0 ? Flight.str(a.get(0)) : "?";
            JsonElement val = a.size() > 1 ? a.get(1) : null;
            String v = val == null ? "" : val.isJsonPrimitive() ? val.getAsString() : val.toString();
            return "[" + name + "=" + v + "]";
        }
        String s = Flight.str(seg);
        if (s == null || s.isEmpty() || s.startsWith("__PAGE__") || s.startsWith("__DEFAULT__")) return null;
        if (s.startsWith("(") && s.endsWith(")")) return null; // route group: not part of the URL
        return s;
    }

    static DecodedNode node(String name, JsonElement tree) {
        return node(name, tree, 0);
    }

    private static DecodedNode node(String name, JsonElement tree, int depth) {
        if (tree == null || !tree.isJsonArray() || depth > MAX_DEPTH) return JsonTree.toNode(name, tree, false);
        JsonArray a = tree.getAsJsonArray();
        String seg = a.size() > 0 ? segmentLabel(a.get(0)) : "?";
        DecodedNode n = new DecodedNode(name + " " + seg, null, DecodedNode.Type.OBJECT);
        if (a.size() > 0 && a.get(0).isJsonArray()) {
            JsonArray d = a.get(0).getAsJsonArray();
            n.put("Dynamic param", d.size() > 0 ? Flight.str(d.get(0)) : null);
            if (d.size() > 1) n.add(JsonTree.toNode("Value", d.get(1), false));
            if (d.size() > 2) n.put("Param type", paramType(Flight.str(d.get(2))));
        }
        if (a.size() > 1 && a.get(1).isJsonObject()) {
            for (Map.Entry<String, JsonElement> en : a.get(1).getAsJsonObject().entrySet()) {
                n.add(node("@" + en.getKey(), en.getValue(), depth + 1));
            }
        }
        String[] extras = {"URL (to refetch)", "Refresh marker", "Is root layout", "Has loading boundary"};
        for (int i = 2; i < a.size(); i++) {
            if (a.get(i).isJsonNull()) continue;
            n.add(JsonTree.toNode(i - 2 < extras.length ? extras[i - 2] : "[" + i + "]", a.get(i), false));
        }
        return n;
    }

    private static String segmentLabel(JsonElement seg) {
        if (seg.isJsonArray()) {
            JsonArray d = seg.getAsJsonArray();
            String p = d.size() > 0 ? Flight.str(d.get(0)) : "?";
            String v = d.size() > 1 ? (d.get(1).isJsonPrimitive() ? d.get(1).getAsString() : d.get(1).toString()) : "";
            return "[" + p + "=" + v + "]";
        }
        String s = Flight.str(seg);
        if (s == null) return seg.toString();
        if (s.isEmpty()) return "(root layout)";
        if (s.startsWith("__PAGE__")) return "page" + (s.length() > 8 ? " " + s.substring(8) : "");
        if (s.equals("__DEFAULT__")) return "default";
        if (s.startsWith("(") && s.endsWith(")")) return "\"" + s + "\" (route group)";
        return "\"" + s + "\"";
    }

    private static String paramType(String t) {
        if (t == null) return null;
        return t + switch (t) {
            case "d" -> " (dynamic [param])";
            case "c" -> " (catch-all [...param])";
            case "oc" -> " (optional catch-all [[...param]])";
            case "di", "ci", "oci", "ic" -> " (intercepted)";
            default -> "";
        };
    }
}
