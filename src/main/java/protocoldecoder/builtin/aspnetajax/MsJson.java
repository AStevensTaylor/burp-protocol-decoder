package protocoldecoder.builtin.aspnetajax;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.time.DateTimeException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * JSON-to-tree conversion that understands the Microsoft AJAX JSON conventions: {@code "\/Date(ms[+-hhmm])\/"} dates,
 * {@code __type} hints ({@code Namespace.Class} from ASMX, {@code Class:#Namespace} from WCF) and ASP.NET error objects.
 */
final class MsJson {

    /** After JSON unescaping, {@code "\/Date(…)\/"} becomes {@code /Date(…)/}. */
    private static final Pattern DATE = Pattern.compile("^/Date\\((-?\\d{1,16})([+-])?(\\d{2})?(\\d{2})?\\)/$");
    private static final int MAX_DEPTH = 64;
    private static final int MAX_STRING = 256 * 1024;

    private MsJson() {
    }

    /** Converts a Microsoft JSON date string to ISO-8601, or returns null if it is not one. */
    static String isoDate(String s) {
        if (s == null || s.length() > 40 || !s.startsWith("/Date(")) return null;
        Matcher m = DATE.matcher(s);
        if (!m.matches()) return null;
        try {
            long ms = Long.parseLong(m.group(1));
            Instant t = Instant.ofEpochMilli(ms);
            if (m.group(2) != null) {
                if (m.group(3) == null || m.group(4) == null) return null;
                int sign = m.group(2).equals("-") ? -1 : 1;
                ZoneOffset off = ZoneOffset.ofHoursMinutes(sign * Integer.parseInt(m.group(3)), sign * Integer.parseInt(m.group(4)));
                return t.atOffset(off).toString();
            }
            return t.toString();
        } catch (NumberFormatException | DateTimeException | ArithmeticException e) {
            return null;
        }
    }

    /** Turns {@code Class:#Namespace} (WCF) into {@code Namespace.Class}; ASMX names are returned unchanged. */
    static String typeName(String hint) {
        if (hint == null) return null;
        int i = hint.indexOf(":#");
        if (i < 0) return hint;
        String cls = hint.substring(0, i);
        String ns = hint.substring(i + 2);
        return ns.isEmpty() ? cls : ns + "." + cls;
    }

    /** ASP.NET / WCF error object: {@code {Message, StackTrace, ExceptionType}} or WCF {@code ExceptionDetail}. */
    static boolean isErrorObject(JsonElement e) {
        if (e == null || !e.isJsonObject()) return false;
        JsonObject o = e.getAsJsonObject();
        if (o.has("ExceptionType") && (o.has("Message") || o.has("StackTrace"))) return true;
        return o.has("ExceptionDetail") && o.get("ExceptionDetail").isJsonObject();
    }

    /** True if any {@code StackTrace} member in the tree is a non-blank string. */
    static boolean hasStackTrace(JsonElement e) {
        return hasStackTrace(e, 0);
    }

    private static boolean hasStackTrace(JsonElement e, int depth) {
        if (e == null || depth > MAX_DEPTH) return false;
        if (e.isJsonObject()) {
            for (Map.Entry<String, JsonElement> en : e.getAsJsonObject().entrySet()) {
                JsonElement v = en.getValue();
                if (en.getKey().equals("StackTrace") && v.isJsonPrimitive() && !v.getAsString().isBlank()) return true;
                if (hasStackTrace(v, depth + 1)) return true;
            }
        } else if (e.isJsonArray()) {
            for (JsonElement v : e.getAsJsonArray()) if (hasStackTrace(v, depth + 1)) return true;
        }
        return false;
    }

    static String str(JsonObject o, String key) {
        JsonElement v = o.get(key);
        return v != null && v.isJsonPrimitive() ? v.getAsString() : null;
    }

    static DecodedNode toNode(String name, JsonElement e) {
        return toNode(name, e, 0);
    }

    private static DecodedNode toNode(String name, JsonElement e, int depth) {
        if (e == null || e.isJsonNull()) return DecodedNode.leaf(name, "null", DecodedNode.Type.NULL);
        if (depth > MAX_DEPTH) return DecodedNode.leaf(name, Codecs.truncate(e.toString(), 2000), DecodedNode.Type.NOTE);
        if (e.isJsonObject()) {
            JsonObject o = e.getAsJsonObject();
            String type = o.has("__type") && o.get("__type").isJsonPrimitive() ? typeName(o.get("__type").getAsString()) : null;
            DecodedNode n = new DecodedNode(name, type, DecodedNode.Type.OBJECT);
            for (Map.Entry<String, JsonElement> en : o.entrySet()) n.add(toNode(en.getKey(), en.getValue(), depth + 1));
            return n;
        }
        if (e.isJsonArray()) {
            JsonArray a = e.getAsJsonArray();
            DecodedNode n = DecodedNode.array(name);
            for (int i = 0; i < a.size(); i++) n.add(toNode("[" + i + "]", a.get(i), depth + 1));
            return n;
        }
        JsonPrimitive p = e.getAsJsonPrimitive();
        if (p.isBoolean()) return DecodedNode.leaf(name, p.getAsString(), DecodedNode.Type.BOOLEAN);
        if (p.isNumber()) return DecodedNode.leaf(name, p.getAsString(), DecodedNode.Type.NUMBER);
        String s = p.getAsString();
        String iso = isoDate(s);
        if (iso != null) return DecodedNode.leaf(name, iso + "  (" + s + ")");
        if (JsonTree.looksLikeJson(s)) {
            JsonElement inner = JsonTree.parseLenient(s);
            if (inner != null) return toNode(name + " (JSON)", inner, depth + 1);
        }
        return html(name, Codecs.truncate(s, MAX_STRING));
    }

    /** Leaf typed HTML when the text looks like markup, otherwise a plain string. */
    static DecodedNode html(String name, String s) {
        String t = s.stripLeading();
        boolean isHtml = t.length() > 3 && t.charAt(0) == '<' && t.indexOf('>') > 0 && (t.contains("</") || t.contains("/>"));
        return DecodedNode.leaf(name, s, isHtml ? DecodedNode.Type.HTML : DecodedNode.Type.STRING);
    }
}
