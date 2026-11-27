package protocoldecoder.persistence;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import protocoldecoder.core.OverrideStore;
import protocoldecoder.rules.Rule;
import protocoldecoder.script.ScriptDefinition;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** JSON (de)serialisation of configuration, and the shareable export bundle. */
public final class ConfigCodec {

    public static final int BUNDLE_VERSION = 1;
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    private ConfigCodec() {
    }

    public static String rulesToJson(List<Rule> rules) {
        return GSON.toJson(rules);
    }

    public static List<Rule> rulesFromJson(String json) {
        if (json == null || json.isBlank()) return new ArrayList<>();
        List<Rule> r = GSON.fromJson(json, new TypeToken<List<Rule>>() { }.getType());
        return r == null ? new ArrayList<>() : new ArrayList<>(r);
    }

    public static String scriptsToJson(List<ScriptDefinition> scripts) {
        return GSON.toJson(scripts);
    }

    public static List<ScriptDefinition> scriptsFromJson(String json) {
        if (json == null || json.isBlank()) return new ArrayList<>();
        List<ScriptDefinition> s = GSON.fromJson(json, new TypeToken<List<ScriptDefinition>>() { }.getType());
        return s == null ? new ArrayList<>() : new ArrayList<>(s);
    }

    public static String settingsToJson(Settings s) {
        return GSON.toJson(s);
    }

    public static Settings settingsFromJson(String json) {
        if (json == null || json.isBlank()) return new Settings();
        Settings s = GSON.fromJson(json, Settings.class);
        return s == null ? new Settings() : s;
    }

    public static String idsToJson(Set<String> ids) {
        return GSON.toJson(ids);
    }

    public static Set<String> idsFromJson(String json) {
        if (json == null || json.isBlank()) return Set.of();
        Set<String> s = GSON.fromJson(json, new TypeToken<Set<String>>() { }.getType());
        return s == null ? Set.of() : s;
    }

    public static String overridesToJson(Map<String, OverrideStore.Entry> m) {
        JsonObject o = new JsonObject();
        m.forEach((k, v) -> {
            JsonObject e = new JsonObject();
            e.addProperty("decoder", v.decoderId());
            e.addProperty("description", v.description());
            o.add(k, e);
        });
        return GSON.toJson(o);
    }

    public static Map<String, OverrideStore.Entry> overridesFromJson(String json) {
        Map<String, OverrideStore.Entry> out = new LinkedHashMap<>();
        if (json == null || json.isBlank()) return out;
        JsonElement root = JsonParser.parseString(json);
        if (!root.isJsonObject()) return out;
        for (Map.Entry<String, JsonElement> e : root.getAsJsonObject().entrySet()) {
            if (!e.getValue().isJsonObject()) continue;
            JsonObject v = e.getValue().getAsJsonObject();
            out.put(e.getKey(), new OverrideStore.Entry(str(v, "decoder"), str(v, "description")));
        }
        return out;
    }

    private static String str(JsonObject o, String k) {
        JsonElement e = o.get(k);
        return e == null || e.isJsonNull() ? "" : e.getAsString();
    }

    /** A shareable file containing scripts and/or rules. */
    public record Bundle(List<ScriptDefinition> scripts, List<Rule> rules) {
    }

    public static String bundleToJson(Bundle b) {
        JsonObject o = new JsonObject();
        o.addProperty("format", "burp-protocol-decoder");
        o.addProperty("version", BUNDLE_VERSION);
        o.add("scripts", GSON.toJsonTree(b.scripts()));
        o.add("rules", GSON.toJsonTree(b.rules()));
        return GSON.toJson(o);
    }

    public static Bundle bundleFromJson(String json) {
        try {
            JsonElement root = JsonParser.parseString(json);
            if (!root.isJsonObject() || !"burp-protocol-decoder".equals(str(root.getAsJsonObject(), "format"))) {
                throw new IllegalArgumentException("not a Protocol Decoder export file");
            }
            JsonObject o = root.getAsJsonObject();
            JsonArray scripts = o.has("scripts") && o.get("scripts").isJsonArray() ? o.getAsJsonArray("scripts") : new JsonArray();
            JsonArray rules = o.has("rules") && o.get("rules").isJsonArray() ? o.getAsJsonArray("rules") : new JsonArray();
            return new Bundle(scriptsFromJson(GSON.toJson(scripts)), rulesFromJson(GSON.toJson(rules)));
        } catch (JsonParseException e) {
            throw new IllegalArgumentException("invalid JSON: " + e.getMessage(), e);
        }
    }
}
