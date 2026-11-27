package protocoldecoder.builtin.firebase;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** Shared helpers for the Firebase decoders: per-decode output budget, safe JSON access, tree conversion, JWTs. */
final class Fb {

    private Fb() {
    }

    /** Per-decode state: warnings and a node budget so huge snapshots cannot blow up the UI. */
    static final class Out {
        static final int MAX_NODES = 50_000;
        final List<String> warnings = new ArrayList<>();
        private int nodes;
        private boolean capped;

        boolean budget() {
            if (++nodes <= MAX_NODES) return true;
            if (!capped) {
                capped = true;
                warnings.add("output truncated after " + MAX_NODES + " nodes");
            }
            return false;
        }

        void warn(String w) {
            if (!warnings.contains(w)) warnings.add(w);
        }
    }

    // ---------------------------------------------------------------- safe JSON access

    static JsonObject obj(JsonElement e) {
        return e != null && e.isJsonObject() ? e.getAsJsonObject() : null;
    }

    static JsonObject obj(JsonElement e, String key) {
        JsonObject o = obj(e);
        return o == null ? null : obj(o.get(key));
    }

    static JsonArray arr(JsonElement e, String key) {
        JsonObject o = obj(e);
        JsonElement v = o == null ? null : o.get(key);
        return v != null && v.isJsonArray() ? v.getAsJsonArray() : null;
    }

    static String str(JsonElement e, String key) {
        JsonObject o = obj(e);
        JsonElement v = o == null ? null : o.get(key);
        return prim(v);
    }

    /** String form of a primitive, or null for anything else. */
    static String prim(JsonElement v) {
        return v != null && v.isJsonPrimitive() ? v.getAsString() : null;
    }

    static boolean has(JsonElement e, String key) {
        JsonObject o = obj(e);
        return o != null && o.has(key);
    }

    static JsonElement parse(String s) {
        JsonElement e = JsonTree.parseStrict(s);
        return e != null || !JsonTree.looksLikeJson(s) ? e : JsonTree.parseLenient(s);
    }

    static String text(byte[] body, String contentEncoding) {
        byte[] b = Codecs.decodeContent(body, contentEncoding);
        return b == null ? "" : new String(b, StandardCharsets.UTF_8);
    }

    static String firstKey(JsonObject o) {
        for (String k : o.keySet()) return k;
        return null;
    }

    // ---------------------------------------------------------------- tree conversion

    /**
     * Converts JSON to a tree. When {@code typed}, Firestore {@code Value} objects ({"stringValue": …}) are rendered
     * as plain values with their type shown. JWT-shaped strings are always decoded.
     */
    static DecodedNode node(String name, JsonElement e, boolean typed, Out out, int depth) {
        if (!out.budget()) return null;
        if (e == null || e.isJsonNull()) return DecodedNode.leaf(name, "null", DecodedNode.Type.NULL);
        if (depth > 64) return DecodedNode.leaf(name, Codecs.truncate(e.toString(), 2000), DecodedNode.Type.NOTE);
        if (e.isJsonObject()) {
            JsonObject o = e.getAsJsonObject();
            if (typed && Firestore.isTypedValue(o)) return Firestore.typed(name, o, out, depth);
            DecodedNode n = DecodedNode.object(name);
            for (Map.Entry<String, JsonElement> en : o.entrySet()) n.add(node(en.getKey(), en.getValue(), typed, out, depth + 1));
            return n;
        }
        if (e.isJsonArray()) {
            DecodedNode n = DecodedNode.array(name);
            JsonArray a = e.getAsJsonArray();
            for (int i = 0; i < a.size(); i++) n.add(node("[" + i + "]", a.get(i), typed, out, depth + 1));
            return n;
        }
        JsonPrimitive p = e.getAsJsonPrimitive();
        if (p.isBoolean()) return DecodedNode.leaf(name, p.getAsString(), DecodedNode.Type.BOOLEAN);
        if (p.isNumber()) return DecodedNode.leaf(name, p.getAsString(), DecodedNode.Type.NUMBER);
        return stringNode(name, p.getAsString(), out);
    }

    static DecodedNode stringNode(String name, String s, Out out) {
        if (Jwt.looksLike(s)) {
            DecodedNode j = Jwt.node(name, s);
            if (j != null) return j;
        }
        return DecodedNode.leaf(name, s);
    }

    /** Leaf annotated with a time if the value looks like epoch seconds / millis. */
    static DecodedNode timeLeaf(String name, String v) {
        if (v != null && v.matches("\\d{10}")) return DecodedNode.leaf(name, v + "  (" + Instant.ofEpochSecond(Long.parseLong(v)) + ")");
        if (v != null && v.matches("\\d{13}")) return DecodedNode.leaf(name, v + "  (" + Instant.ofEpochMilli(Long.parseLong(v)) + ")");
        return DecodedNode.leaf(name, v);
    }

    // ---------------------------------------------------------------- JWT

    /** Unverified JWT decoding (Firebase ID tokens, App Check tokens, custom tokens). */
    static final class Jwt {
        private static final Pattern SHAPE = Pattern.compile("eyJ[A-Za-z0-9_-]{4,}\\.[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*");
        private static final Set<String> TIME_CLAIMS = Set.of("exp", "iat", "nbf", "auth_time");

        private Jwt() {
        }

        record Parsed(JsonObject header, JsonObject claims, int signatureBytes) {
        }

        static boolean looksLike(String s) {
            return s != null && s.length() >= 20 && s.length() <= 64 * 1024 && s.startsWith("eyJ") && SHAPE.matcher(s).matches();
        }

        static Parsed parse(String token) {
            if (!looksLike(token)) return null;
            String[] parts = token.split("\\.", -1);
            if (parts.length != 3) return null;
            JsonObject h = obj(decodePart(parts[0]));
            if (h == null || (!h.has("alg") && !h.has("typ"))) return null;
            JsonObject c = obj(decodePart(parts[1]));
            byte[] sig = Codecs.base64Decode(parts[2]);
            return new Parsed(h, c, sig == null ? 0 : sig.length);
        }

        private static JsonElement decodePart(String p) {
            byte[] b = Codecs.base64Decode(p);
            return b == null ? null : JsonTree.parseStrict(new String(b, StandardCharsets.UTF_8));
        }

        static DecodedNode node(String name, String token) {
            Parsed p = parse(token);
            if (p == null) return null;
            DecodedNode n = new DecodedNode(name + " (JWT)", describe(p), DecodedNode.Type.OBJECT);
            n.add(JsonTree.toNode("header", p.header(), false));
            if (p.claims() != null) {
                DecodedNode c = DecodedNode.object("claims");
                for (Map.Entry<String, JsonElement> en : p.claims().entrySet()) {
                    String v = prim(en.getValue());
                    if (TIME_CLAIMS.contains(en.getKey()) && v != null) c.add(timeLeaf(en.getKey(), v));
                    else c.add(JsonTree.toNode(en.getKey(), en.getValue(), false));
                }
                n.add(c);
            } else {
                n.add(DecodedNode.note("payload is not JSON (encrypted or opaque)"));
            }
            n.put("signature", p.signatureBytes() + " bytes (not verified)");
            n.put("token", token);
            return n;
        }

        /** One-line description: "uid X (email), provider password, project p, expires …". */
        static String describe(Parsed p) {
            JsonObject c = p.claims();
            if (c == null) return "alg " + str(p.header(), "alg");
            List<String> bits = new ArrayList<>();
            String uid = str(c, "user_id") != null ? str(c, "user_id") : str(c, "sub");
            String email = str(c, "email");
            if (uid != null) bits.add("uid " + uid + (email == null ? "" : " (" + email + ")"));
            else if (email != null) bits.add(email);
            String provider = str(obj(c, "firebase"), "sign_in_provider");
            if (provider != null) bits.add("provider " + provider);
            String aud = str(c, "aud");
            if (aud != null) bits.add("aud " + aud);
            String exp = str(c, "exp");
            if (exp != null && exp.matches("\\d{1,12}")) bits.add("expires " + Instant.ofEpochSecond(Long.parseLong(exp)));
            if (bits.isEmpty()) bits.add("alg " + str(p.header(), "alg"));
            return String.join(", ", bits);
        }
    }
}
