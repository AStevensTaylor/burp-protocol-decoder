package protocoldecoder.scan;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/** Helpers for building protocol-aware insertion points. */
public final class InsertionPoints {

    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();
    /** Upper bound on insertion points one helper call produces. */
    public static final int MAX_POINTS = 200;

    private InsertionPoints() {
    }

    /**
     * Returns a urlencoded form body with the value of field {@code name} (the {@code occurrence}-th one, 0-based)
     * replaced by {@code newValue}; all other pairs are kept byte-for-byte.
     */
    public static String replaceFormField(String body, String name, int occurrence, String newValue) {
        String[] pairs = body.split("&", -1);
        int seen = 0;
        StringBuilder sb = new StringBuilder(body.length() + newValue.length());
        for (int i = 0; i < pairs.length; i++) {
            String pair = pairs[i];
            int eq = pair.indexOf('=');
            String rawKey = eq < 0 ? pair : pair.substring(0, eq);
            String key = protocoldecoder.util.Codecs.urlDecode(rawKey);
            if (i > 0) sb.append('&');
            if (key.equals(name) && seen++ == occurrence) {
                sb.append(rawKey).append('=').append(formEncode(newValue));
            } else {
                sb.append(pair);
            }
        }
        return sb.toString();
    }

    /** application/x-www-form-urlencoded encoding (spaces as '+'). */
    public static String formEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    /** One primitive leaf inside a JSON document. */
    public record JsonLeaf(String path, JsonElement value, Function<String, String> replace) {
    }

    /**
     * Enumerates primitive leaves (strings, numbers, booleans) of a JSON document. Each leaf's {@code replace}
     * returns the whole document re-serialised with that leaf set to the payload (as a JSON string).
     */
    public static List<JsonLeaf> jsonLeaves(JsonElement root) {
        List<JsonLeaf> out = new ArrayList<>();
        collect(root, "$", new ArrayList<>(), root, out);
        return out;
    }

    private static void collect(JsonElement e, String path, List<Object> steps, JsonElement root, List<JsonLeaf> out) {
        if (out.size() >= MAX_POINTS || e == null || e.isJsonNull()) return;
        if (e.isJsonObject()) {
            for (Map.Entry<String, JsonElement> en : e.getAsJsonObject().entrySet()) {
                List<Object> s = new ArrayList<>(steps);
                s.add(en.getKey());
                collect(en.getValue(), path + "." + en.getKey(), s, root, out);
            }
        } else if (e.isJsonArray()) {
            JsonArray a = e.getAsJsonArray();
            for (int i = 0; i < a.size(); i++) {
                List<Object> s = new ArrayList<>(steps);
                s.add(i);
                collect(a.get(i), path + "[" + i + "]", s, root, out);
            }
        } else {
            List<Object> fixed = List.copyOf(steps);
            out.add(new JsonLeaf(path, e, payload -> {
                JsonElement copy = root.deepCopy();
                set(copy, fixed, new JsonPrimitive(payload));
                return GSON.toJson(copy);
            }));
        }
    }

    private static void set(JsonElement root, List<Object> steps, JsonElement value) {
        JsonElement cur = root;
        for (int i = 0; i < steps.size() - 1; i++) {
            Object s = steps.get(i);
            cur = s instanceof Integer idx ? cur.getAsJsonArray().get(idx) : cur.getAsJsonObject().get((String) s);
        }
        Object last = steps.get(steps.size() - 1);
        if (last instanceof Integer idx) cur.getAsJsonArray().set(idx, value);
        else ((JsonObject) cur).add((String) last, value);
    }

    /** Base value of a JSON leaf as plain text. */
    public static String text(JsonElement leaf) {
        return leaf.isJsonPrimitive() ? leaf.getAsString() : leaf.toString();
    }
}
