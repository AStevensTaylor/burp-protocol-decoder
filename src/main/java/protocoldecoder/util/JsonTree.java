package protocoldecoder.util;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import protocoldecoder.core.DecodedNode;

import java.io.IOException;
import java.io.StringReader;
import java.util.Map;

/** JSON parsing (strict and JavaScript-literal-lenient) and conversion into {@link DecodedNode} trees. */
public final class JsonTree {

    private JsonTree() {
    }

    /** Parses strict JSON, or returns null. The whole input must be consumed. */
    public static JsonElement parseStrict(String s) {
        return parse(s, Strictness.STRICT);
    }

    /**
     * Parses JSON or a JavaScript object literal (single quotes, unquoted keys, comments), or returns null. The whole
     * input must be consumed.
     */
    public static JsonElement parseLenient(String s) {
        return parse(s, Strictness.LENIENT);
    }

    private static JsonElement parse(String s, Strictness strictness) {
        if (s == null) return null;
        String t = s.strip();
        if (t.isEmpty()) return null;
        char c = t.charAt(0);
        if (c != '{' && c != '[' && strictness == Strictness.STRICT && c != '"') {
            // allow bare primitives only in strict mode where they're unambiguous
            if (!(Character.isDigit(c) || c == '-' || t.equals("true") || t.equals("false") || t.equals("null"))) return null;
        }
        try (JsonReader reader = new JsonReader(new StringReader(t))) {
            reader.setStrictness(strictness);
            JsonElement e = JsonParser.parseReader(reader);
            if (reader.peek() != JsonToken.END_DOCUMENT) return null;
            return e;
        } catch (JsonParseException | IOException | IllegalStateException | NumberFormatException e) {
            return null;
        }
    }

    /** True if the string looks like a JSON object/array worth trying to parse. */
    public static boolean looksLikeJson(String s) {
        if (s == null) return false;
        String t = s.strip();
        if (t.length() < 2) return false;
        char a = t.charAt(0), z = t.charAt(t.length() - 1);
        return (a == '{' && z == '}') || (a == '[' && z == ']');
    }

    /** Converts a JSON element to a tree. String values that themselves contain JSON are expanded when expandNested. */
    public static DecodedNode toNode(String name, JsonElement e, boolean expandNested) {
        return toNode(name, e, expandNested, 0);
    }

    private static DecodedNode toNode(String name, JsonElement e, boolean expandNested, int depth) {
        if (e == null || e.isJsonNull()) return DecodedNode.leaf(name, "null", DecodedNode.Type.NULL);
        if (depth > 64) return DecodedNode.leaf(name, Codecs.truncate(e.toString(), 2000), DecodedNode.Type.NOTE);
        if (e.isJsonObject()) {
            DecodedNode n = DecodedNode.object(name);
            JsonObject o = e.getAsJsonObject();
            for (Map.Entry<String, JsonElement> en : o.entrySet()) {
                n.add(toNode(en.getKey(), en.getValue(), expandNested, depth + 1));
            }
            return n;
        }
        if (e.isJsonArray()) {
            DecodedNode n = DecodedNode.array(name);
            JsonArray a = e.getAsJsonArray();
            for (int i = 0; i < a.size(); i++) {
                n.add(toNode("[" + i + "]", a.get(i), expandNested, depth + 1));
            }
            return n;
        }
        JsonPrimitive p = e.getAsJsonPrimitive();
        if (p.isBoolean()) return DecodedNode.leaf(name, p.getAsString(), DecodedNode.Type.BOOLEAN);
        if (p.isNumber()) return DecodedNode.leaf(name, p.getAsString(), DecodedNode.Type.NUMBER);
        String s = p.getAsString();
        if (expandNested && looksLikeJson(s)) {
            JsonElement inner = parseLenient(s);
            if (inner != null) {
                DecodedNode n = toNode(name + " (JSON)", inner, true, depth + 1);
                return n;
            }
        }
        return DecodedNode.leaf(name, s, looksLikeHtml(s) ? DecodedNode.Type.HTML : DecodedNode.Type.STRING);
    }

    static boolean looksLikeHtml(String s) {
        String t = s.stripLeading();
        return t.length() > 3 && t.charAt(0) == '<' && t.indexOf('>') > 0 && (t.contains("</") || t.contains("/>"));
    }
}
