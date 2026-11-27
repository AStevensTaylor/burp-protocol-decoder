package protocoldecoder.builtin.livewire;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Rendering of Livewire component data: v3 dehydrated synthesizer tuples ({@code [value, {"s": "mdl", ...}]}), v2
 * dataMeta, and the security observations collected along the way.
 */
final class LivewireData {

    private LivewireData() {
    }

    /** Livewire 3 synthesizer keys ({@code meta.s}) and what they mean. */
    static final Map<String, String> SYNTHS = Map.ofEntries(
            Map.entry("arr", "array"),
            Map.entry("clctn", "Collection"),
            Map.entry("mdl", "Eloquent model"),
            Map.entry("elcln", "Eloquent collection"),
            Map.entry("mdlclctn", "Eloquent model collection"),
            Map.entry("mdlcln", "Eloquent model collection"),
            Map.entry("fm", "Form object"),
            Map.entry("form", "Form object"),
            Map.entry("cbn", "Carbon / DateTime"),
            Map.entry("std", "stdClass"),
            Map.entry("stdClass", "stdClass"),
            Map.entry("enm", "Enum"),
            Map.entry("str", "Stringable"),
            Map.entry("wrbl", "Wireable object"),
            Map.entry("fil", "Temporary uploaded file"),
            Map.entry("int", "int"),
            Map.entry("float", "float"));

    private static final Pattern SYNTH_KEY = Pattern.compile("[A-Za-z]{1,16}");
    private static final Set<String> SENSITIVE = Set.of("password", "passwd", "pwd", "secret", "token", "apikey",
            "role", "roles", "admin", "superuser", "permission", "permissions", "privilege", "privileges", "ssn", "cvv",
            "otp", "mfa", "2fa", "salt", "hash", "credential", "credentials");

    static final int MAX_CHILDREN = 1000;
    static final int MAX_DEPTH = 40;

    // ---------------------------------------------------------------- findings

    /** Security observations, deduplicated and capped. */
    static final class Findings {
        private static final int MAX = 40;
        private final LinkedHashSet<String> warnings = new LinkedHashSet<>();
        private int dropped;
        String component = "";
        int models;

        void warn(String w) {
            if (warnings.contains(w)) return;
            if (warnings.size() < MAX) warnings.add(w);
            else dropped++;
        }

        List<String> list() {
            List<String> out = new ArrayList<>(warnings);
            if (dropped > 0) out.add(dropped + " further observation(s) not shown");
            return out;
        }

        private String of() {
            return component == null || component.isEmpty() ? "" : " of " + component;
        }

        void model(String path, String cls, String key, String connection) {
            models++;
            warn("Model " + cls + (key == null ? "" : " #" + key) + " exposed as property '" + path + "'" + of()
                    + (connection == null ? "" : " (connection " + connection + ")")
                    + " — key is visible client-side; the snapshot is checksum-protected, so test actions/updates for IDOR rather than raw tampering");
        }

        void modelCollection(String path, String cls, String keys) {
            models++;
            warn("Model collection " + cls + (keys == null ? "" : " " + keys) + " exposed as property '" + path + "'" + of()
                    + " — keys are visible client-side (checksum-protected snapshot); test for IDOR");
        }

        void sensitive(String path, String value) {
            warn("Property '" + path + "'" + of() + " looks sensitive and is sent to the client"
                    + (value == null ? "" : " (value: " + Codecs.truncate(value, 60) + ")"));
        }
    }

    // ---------------------------------------------------------------- helpers

    static boolean isSensitiveName(String name) {
        if (name == null || name.isEmpty() || name.startsWith("[")) return false;
        String snake = name.replaceAll("([a-z0-9])([A-Z])", "$1_$2").toLowerCase(Locale.ROOT);
        String compact = snake.replaceAll("[^a-z0-9]", "");
        if (compact.contains("password") || compact.contains("apikey") || compact.contains("privatekey") || compact.contains("isadmin")) return true;
        for (String t : snake.split("[^a-z0-9]+")) {
            if (SENSITIVE.contains(t)) return true;
        }
        return false;
    }

    static String str(JsonElement e) {
        if (e == null || e.isJsonNull()) return null;
        if (e.isJsonPrimitive()) return e.getAsString();
        return Codecs.truncate(e.toString(), 200);
    }

    static String str(JsonObject o, String key) {
        return o == null ? null : str(o.get(key));
    }

    static JsonObject obj(JsonObject o, String key) {
        if (o == null) return null;
        JsonElement e = o.get(key);
        return e != null && e.isJsonObject() ? e.getAsJsonObject() : null;
    }

    static JsonArray arr(JsonObject o, String key) {
        if (o == null) return null;
        JsonElement e = o.get(key);
        return e != null && e.isJsonArray() ? e.getAsJsonArray() : null;
    }

    /** Short scalar for display, or null if the value is a container. */
    static String scalar(JsonElement e) {
        if (e == null || e.isJsonNull()) return "null";
        if (e.isJsonPrimitive()) {
            JsonPrimitive p = e.getAsJsonPrimitive();
            return p.isString() ? "\"" + Codecs.truncate(p.getAsString(), 60) + "\"" : p.getAsString();
        }
        return null;
    }

    // ---------------------------------------------------------------- v3 synthesizer tuples

    /** True for {@code [value, {"s": "<key>", ...}]}. */
    static boolean isTuple(JsonElement e) {
        if (e == null || !e.isJsonArray()) return false;
        JsonArray a = e.getAsJsonArray();
        if (a.size() != 2 || !a.get(1).isJsonObject()) return false;
        JsonObject meta = a.get(1).getAsJsonObject();
        JsonElement s = meta.get("s");
        if (s == null || !s.isJsonPrimitive() || !s.getAsJsonPrimitive().isString()) return false;
        return meta.size() <= 10 && SYNTH_KEY.matcher(s.getAsString()).matches();
    }

    /**
     * Renders a (possibly dehydrated) value. Tuples become a node whose value names the synthesizer and, for models,
     * the class and key. Sensitive-looking property names and model bindings are recorded in {@code f}.
     */
    static DecodedNode render(String name, JsonElement e, String path, Findings f, int depth) {
        if (depth > MAX_DEPTH) return DecodedNode.leaf(name, Codecs.truncate(String.valueOf(e), 2000), DecodedNode.Type.NOTE);
        if (f != null && depth < 6 && isSensitiveName(name) && !isEmpty(e)) {
            f.sensitive(path, isTuple(e) ? null : scalar(e));
        }
        if (isTuple(e)) return tuple(name, e.getAsJsonArray(), path, f, depth);
        if (e != null && e.isJsonObject()) {
            DecodedNode n = DecodedNode.object(name);
            int i = 0;
            for (Map.Entry<String, JsonElement> en : e.getAsJsonObject().entrySet()) {
                if (i++ >= MAX_CHILDREN) {
                    n.add(DecodedNode.note((e.getAsJsonObject().size() - MAX_CHILDREN) + " more entries not shown"));
                    break;
                }
                n.add(render(en.getKey(), en.getValue(), path + "." + en.getKey(), f, depth + 1));
            }
            return n;
        }
        if (e != null && e.isJsonArray()) {
            JsonArray a = e.getAsJsonArray();
            DecodedNode n = DecodedNode.array(name);
            for (int i = 0; i < a.size(); i++) {
                if (i >= MAX_CHILDREN) {
                    n.add(DecodedNode.note((a.size() - MAX_CHILDREN) + " more items not shown"));
                    break;
                }
                n.add(render("[" + i + "]", a.get(i), path + "." + i, f, depth + 1));
            }
            return n;
        }
        return JsonTree.toNode(name, e, false);
    }

    private static boolean isEmpty(JsonElement e) {
        if (e == null || e.isJsonNull()) return true;
        if (e.isJsonPrimitive()) return e.getAsString().isEmpty();
        if (isTuple(e)) return false;
        if (e.isJsonArray()) return e.getAsJsonArray().isEmpty();
        return e.getAsJsonObject().isEmpty();
    }

    private static DecodedNode tuple(String name, JsonArray t, String path, Findings f, int depth) {
        JsonElement value = t.get(0);
        JsonObject meta = t.get(1).getAsJsonObject();
        String s = meta.get("s").getAsString();
        String label = SYNTHS.getOrDefault(s, "synthesizer '" + s + "'");
        String cls = str(meta, "class");
        String summary;
        switch (s) {
            case "mdl" -> {
                String key = str(meta, "key");
                summary = "Eloquent model " + (cls == null ? "?" : cls) + (key == null ? " (unsaved)" : " #" + key);
                if (f != null && cls != null) f.model(path, cls, key, str(meta, "connection"));
            }
            case "elcln", "mdlclctn", "mdlcln" -> {
                String modelClass = str(meta, "modelClass");
                String keys = str(meta, "keys");
                summary = label + " of " + (modelClass != null ? modelClass : cls == null ? "?" : cls) + (keys == null ? "" : " keys " + keys);
                if (f != null) f.modelCollection(path, modelClass != null ? modelClass : cls == null ? "?" : cls, keys);
            }
            case "arr", "int", "float" -> summary = label;
            case "cbn" -> summary = label + (scalar(value) != null ? " " + scalar(value) : "") + (str(meta, "type") == null ? "" : " (" + str(meta, "type") + ")");
            case "enm" -> summary = "Enum " + (cls == null ? "?" : cls) + (scalar(value) != null ? "::" + scalar(value) : "");
            default -> summary = label + (cls == null ? "" : " " + cls);
        }
        boolean container = value != null && (value.isJsonObject() || value.isJsonArray()) && !isTuple(value);
        DecodedNode n = new DecodedNode(name, summary, DecodedNode.Type.OBJECT);
        if (container) {
            // Children of the dehydrated value appear directly under the property, then the synthesizer metadata.
            DecodedNode inner = render(name, value, path, f, depth + 1);
            for (DecodedNode c : inner.children()) n.add(c);
        } else if (!(value == null || value.isJsonNull()) || !"mdl".equals(s)) {
            n.add(render("value", value, path, f, depth + 1));
        }
        DecodedNode m = DecodedNode.object("⟨synth⟩");
        m.put("s", s + " — " + label);
        for (Map.Entry<String, JsonElement> en : meta.entrySet()) {
            if (en.getKey().equals("s")) continue;
            m.add(JsonTree.toNode(en.getKey(), en.getValue(), false));
        }
        n.add(m);
        return n;
    }

    // ---------------------------------------------------------------- v2 dataMeta

    /** Renders v2 {@code serverMemo.dataMeta}, highlighting models / modelCollections. */
    static DecodedNode dataMeta(JsonObject meta, Findings f) {
        DecodedNode n = DecodedNode.object("Data meta (dataMeta)");
        for (Map.Entry<String, JsonElement> en : meta.entrySet()) {
            String k = en.getKey();
            JsonElement v = en.getValue();
            if ((k.equals("models") || k.equals("modelCollections")) && v.isJsonObject()) {
                boolean coll = k.equals("modelCollections");
                DecodedNode list = n.child(coll ? "Model collections" : "Models");
                for (Map.Entry<String, JsonElement> me : v.getAsJsonObject().entrySet()) {
                    if (!me.getValue().isJsonObject()) {
                        list.add(JsonTree.toNode(me.getKey(), me.getValue(), false));
                        continue;
                    }
                    JsonObject mo = me.getValue().getAsJsonObject();
                    String cls = str(mo, "class");
                    String id = str(mo, "id");
                    DecodedNode item = new DecodedNode(me.getKey(), (cls == null ? "?" : cls) + (id == null ? "" : " #" + id), DecodedNode.Type.OBJECT);
                    for (Map.Entry<String, JsonElement> fe : mo.entrySet()) item.add(JsonTree.toNode(fe.getKey(), fe.getValue(), false));
                    list.add(item);
                    if (f != null) {
                        if (coll) f.modelCollection(me.getKey(), cls == null ? "?" : cls, id);
                        else f.model(me.getKey(), cls == null ? "?" : cls, id, str(mo, "connection"));
                    }
                }
            } else {
                n.add(JsonTree.toNode(k, v, false));
            }
        }
        return n;
    }

    // ---------------------------------------------------------------- validation errors

    /** Renders memo/serverMemo errors ({@code {"field": ["message", ...]}}), returns null when there are none. */
    static DecodedNode errors(JsonElement errors, Findings f) {
        if (errors == null || !errors.isJsonObject() || errors.getAsJsonObject().isEmpty()) return null;
        DecodedNode n = DecodedNode.object("Validation errors");
        List<String> fields = new ArrayList<>();
        for (Map.Entry<String, JsonElement> en : errors.getAsJsonObject().entrySet()) {
            fields.add(en.getKey());
            JsonElement v = en.getValue();
            if (v.isJsonArray() && v.getAsJsonArray().size() == 1 && v.getAsJsonArray().get(0).isJsonPrimitive()) {
                n.put(en.getKey(), v.getAsJsonArray().get(0).getAsString());
            } else {
                n.add(JsonTree.toNode(en.getKey(), v, false));
            }
        }
        if (f != null) {
            f.warn("Validation errors returned" + f.of() + " for: " + Codecs.truncate(String.join(", ", fields), 200)
                    + " — messages can reveal rules, existing records or internal field names");
        }
        return n;
    }

    static int errorCount(JsonElement errors) {
        return errors != null && errors.isJsonObject() ? errors.getAsJsonObject().size() : 0;
    }
}
