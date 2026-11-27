package protocoldecoder.builtin.phoenix;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Phoenix LiveView rendered trees and diffs: {@code "s"} statics, numeric keys for dynamics, {@code "c"} components,
 * {@code "e"} pushed events, {@code "t"} title, {@code "r"} root/reply, {@code "d"} comprehensions, {@code "p"} shared
 * templates, {@code "k"} keyed comprehensions, {@code "stream"} streams.
 */
final class LiveViewDiff {

    private static final int MAX_DEPTH = 48;
    private static final int MAX_HTML = 64 * 1024;

    private LiveViewDiff() {
    }

    /** True if the object has at least one LiveView diff key. */
    static boolean looksLikeDiff(JsonElement e) {
        if (e == null || !e.isJsonObject()) return false;
        JsonObject o = e.getAsJsonObject();
        if (o.isEmpty()) return false;
        for (String k : o.keySet()) {
            if (!(isDynamicKey(k) || k.equals("s") || k.equals("c") || k.equals("e") || k.equals("t") || k.equals("r")
                    || k.equals("d") || k.equals("p") || k.equals("k") || k.equals("stream") || k.equals("f"))) return false;
        }
        return true;
    }

    static boolean isDynamicKey(String k) {
        if (k.isEmpty() || k.length() > 6) return false;
        for (int i = 0; i < k.length(); i++) if (!Character.isDigit(k.charAt(i))) return false;
        return true;
    }

    /** "3 dynamics, 2 components, 1 event, title \"Dashboard\"". */
    static String describe(JsonObject o) {
        List<String> parts = new ArrayList<>();
        int dyn = 0;
        for (String k : o.keySet()) if (isDynamicKey(k)) dyn++;
        if (o.has("s")) parts.add("statics");
        if (dyn > 0) parts.add(dyn + (dyn == 1 ? " dynamic" : " dynamics"));
        if (o.get("c") instanceof JsonObject c && !c.isEmpty()) parts.add(c.size() + (c.size() == 1 ? " component" : " components"));
        if (o.get("e") instanceof JsonArray e && !e.isEmpty()) parts.add(e.size() + (e.size() == 1 ? " event" : " events"));
        if (o.get("t") instanceof JsonPrimitive t) parts.add("title \"" + Codecs.truncate(t.getAsString(), 60) + "\"");
        return parts.isEmpty() ? "empty" : String.join(", ", parts);
    }

    static DecodedNode node(String name, JsonElement e) {
        DecodedNode n = node(name, e, 0);
        if (e != null && e.isJsonObject()) {
            String html = render(e.getAsJsonObject());
            if (html != null) n.add(DecodedNode.leaf("Rendered HTML (preview)", html, DecodedNode.Type.HTML));
        }
        return n;
    }

    private static DecodedNode node(String name, JsonElement e, int depth) {
        if (depth > MAX_DEPTH || e == null || !e.isJsonObject()) return JsonTree.toNode(name, e, false);
        JsonObject o = e.getAsJsonObject();
        DecodedNode n = DecodedNode.object(name);
        for (Map.Entry<String, JsonElement> en : o.entrySet()) {
            String k = en.getKey();
            JsonElement v = en.getValue();
            if (isDynamicKey(k)) {
                if (v.isJsonObject()) n.add(node(k + " — dynamic #" + k, v, depth + 1));
                else if (v.isJsonPrimitive() && v.getAsJsonPrimitive().isNumber()) n.add(DecodedNode.leaf(k + " — dynamic #" + k + " (component)", "cid " + v.getAsString(), DecodedNode.Type.NUMBER));
                else n.add(JsonTree.toNode(k + " — dynamic #" + k, v, false));
                continue;
            }
            switch (k) {
                case "s" -> {
                    if (v.isJsonArray()) {
                        DecodedNode s = DecodedNode.array("s — statics (" + v.getAsJsonArray().size() + ")");
                        for (int i = 0; i < v.getAsJsonArray().size(); i++) s.add(JsonTree.toNode("[" + i + "]", v.getAsJsonArray().get(i), false));
                        n.add(s);
                    } else {
                        n.add(DecodedNode.leaf("s — statics", "shared from " + v + " (template / component)", DecodedNode.Type.NUMBER));
                    }
                }
                case "c" -> {
                    if (v.isJsonObject()) {
                        DecodedNode c = DecodedNode.object("c — components (" + v.getAsJsonObject().size() + ")");
                        for (Map.Entry<String, JsonElement> ce : v.getAsJsonObject().entrySet()) c.add(node("cid " + ce.getKey(), ce.getValue(), depth + 1));
                        n.add(c);
                    } else {
                        n.add(JsonTree.toNode("c — components", v, false));
                    }
                }
                case "e" -> n.add(events(v));
                case "t" -> n.add(JsonTree.toNode("t — page title", v, false));
                case "r" -> n.add(JsonTree.toNode("r — root flag / hook reply", v, true));
                case "d" -> {
                    if (v.isJsonArray()) {
                        DecodedNode d = DecodedNode.array("d — comprehension rows (" + v.getAsJsonArray().size() + ")");
                        JsonArray rows = v.getAsJsonArray();
                        for (int i = 0; i < rows.size() && i < 500; i++) {
                            JsonElement row = rows.get(i);
                            if (row.isJsonArray()) {
                                DecodedNode r = DecodedNode.array("row " + i);
                                for (int j = 0; j < row.getAsJsonArray().size(); j++) {
                                    JsonElement cell = row.getAsJsonArray().get(j);
                                    r.add(cell.isJsonObject() ? node("[" + j + "]", cell, depth + 2) : JsonTree.toNode("[" + j + "]", cell, false));
                                }
                                d.add(r);
                            } else {
                                d.add(JsonTree.toNode("row " + i, row, false));
                            }
                        }
                        n.add(d);
                    } else {
                        n.add(JsonTree.toNode("d — comprehension rows", v, false));
                    }
                }
                case "p" -> n.add(JsonTree.toNode("p — shared templates", v, false));
                case "k" -> {
                    if (v.isJsonObject()) {
                        DecodedNode kk = DecodedNode.object("k — keyed comprehension");
                        for (Map.Entry<String, JsonElement> ke : v.getAsJsonObject().entrySet()) {
                            if (ke.getKey().equals("kc")) kk.add(JsonTree.toNode("kc — entry count", ke.getValue(), false));
                            else kk.add(ke.getValue().isJsonObject() ? node("entry " + ke.getKey(), ke.getValue(), depth + 1) : JsonTree.toNode("entry " + ke.getKey(), ke.getValue(), false));
                        }
                        n.add(kk);
                    } else {
                        n.add(JsonTree.toNode("k — keyed comprehension", v, false));
                    }
                }
                case "stream" -> n.add(JsonTree.toNode("stream — stream inserts/deletes", v, false));
                default -> n.add(JsonTree.toNode(k, v, true));
            }
        }
        return n;
    }

    private static DecodedNode events(JsonElement v) {
        if (!v.isJsonArray()) return JsonTree.toNode("e — pushed events", v, true);
        DecodedNode e = DecodedNode.array("e — pushed events (" + v.getAsJsonArray().size() + ")");
        for (JsonElement ev : v.getAsJsonArray()) {
            if (ev.isJsonArray() && ev.getAsJsonArray().size() == 2 && ev.getAsJsonArray().get(0).isJsonPrimitive()) {
                e.add(JsonTree.toNode(ev.getAsJsonArray().get(0).getAsString(), ev.getAsJsonArray().get(1), true));
            } else {
                e.add(JsonTree.toNode("", ev, true));
            }
        }
        return e;
    }

    /** Best-effort HTML for a full render (one with string statics); null for partial diffs. */
    static String render(JsonObject root) {
        if (!(root.get("s") instanceof JsonArray)) return null;
        JsonObject components = root.get("c") instanceof JsonObject c ? c : new JsonObject();
        StringBuilder sb = new StringBuilder();
        render(root, components, sb, 0);
        if (sb.length() >= MAX_HTML) {
            sb.setLength(MAX_HTML);
            sb.append("\n<!-- … truncated -->");
        }
        String s = sb.toString().strip();
        return s.isEmpty() ? null : s;
    }

    private static void render(JsonObject o, JsonObject components, StringBuilder sb, int depth) {
        if (depth > MAX_DEPTH || sb.length() >= MAX_HTML) return;
        if (!(o.get("s") instanceof JsonArray statics)) {
            sb.append("<!-- shared template -->");
            return;
        }
        if (o.get("d") instanceof JsonArray rows) {
            for (JsonElement row : rows) {
                if (!row.isJsonArray()) continue;
                JsonArray cells = row.getAsJsonArray();
                for (int i = 0; i < statics.size(); i++) {
                    sb.append(str(statics.get(i)));
                    if (i < cells.size() && i < statics.size() - 1) dynamic(cells.get(i), components, sb, depth);
                }
                if (sb.length() >= MAX_HTML) return;
            }
            return;
        }
        for (int i = 0; i < statics.size(); i++) {
            sb.append(str(statics.get(i)));
            if (i < statics.size() - 1) dynamic(o.get(Integer.toString(i)), components, sb, depth);
            if (sb.length() >= MAX_HTML) return;
        }
    }

    private static void dynamic(JsonElement d, JsonObject components, StringBuilder sb, int depth) {
        if (d == null || d.isJsonNull()) return;
        if (d.isJsonPrimitive()) {
            JsonPrimitive p = d.getAsJsonPrimitive();
            if (p.isNumber()) {
                JsonElement comp = components.get(p.getAsString());
                if (comp instanceof JsonObject co && co.get("s") instanceof JsonArray) render(co, components, sb, depth + 1);
                else sb.append("<!-- component ").append(p.getAsString()).append(" -->");
            } else if (!p.isBoolean()) {
                sb.append(p.getAsString());
            }
        } else if (d.isJsonObject()) {
            render(d.getAsJsonObject(), components, sb, depth + 1);
        }
    }

    private static String str(JsonElement e) {
        return e != null && e.isJsonPrimitive() ? e.getAsString() : "";
    }
}
