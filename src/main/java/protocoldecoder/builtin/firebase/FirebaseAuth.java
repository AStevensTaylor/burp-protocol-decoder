package protocoldecoder.builtin.firebase;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import protocoldecoder.builtin.firebase.Fb.Out;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MessageContext;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsLiteral;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static protocoldecoder.builtin.firebase.Fb.arr;
import static protocoldecoder.builtin.firebase.Fb.obj;
import static protocoldecoder.builtin.firebase.Fb.str;

/** Firebase Auth (Identity Toolkit, Secure Token) and Firebase web configuration found in pages and scripts. */
final class FirebaseAuth {

    private FirebaseAuth() {
    }

    private static final Pattern CONFIG_FIELD = Pattern.compile(
            "[\"']?\\b(apiKey|authDomain|databaseURL|projectId|storageBucket|messagingSenderId|appId|measurementId|locationId)\\b[\"']?\\s*:\\s*[\"'`]([^\"'`\\s]{1,300})[\"'`]");
    private static final int MAX_CONFIGS = 10;

    // ---------------------------------------------------------------- Identity Toolkit / Secure Token

    static String operation(MessageContext m, boolean secureToken) {
        String p = m.path();
        String last = p.substring(p.lastIndexOf('/') + 1);
        if (secureToken) return last.equals("token") ? "token exchange" : last;
        return last.isEmpty() ? p : last;
    }

    static DecodeResult decode(MessageContext m, boolean secureToken, Out out) throws DecodeException {
        String svc = secureToken ? "Secure Token" : "Identity Toolkit";
        String op = operation(m, secureToken);
        if (m.isResponse()) return response(m, svc, op, out);
        DecodedNode root = DecodedNode.object("Firebase Auth request");
        DecodedNode ep = root.child("Endpoint");
        ep.put("Service", svc + " (" + m.host() + ")");
        ep.put("Operation", op);
        FirebaseDecoder.queryParams(m, ep, out);
        FirebaseDecoder.authHeaders(m, root, out);
        String body = Fb.text(m.requestBody(), m.requestHeader("Content-Encoding"));
        JsonElement j = body.isBlank() ? null : Fb.parse(body);
        Map<String, String> fields = new LinkedHashMap<>();
        if (j != null) {
            root.add(Fb.node("Body", j, false, out, 0));
            JsonObject o = obj(j);
            if (o != null) for (String k : o.keySet()) if (Fb.prim(o.get(k)) != null) fields.put(k, Fb.prim(o.get(k)));
        } else if (!body.isBlank()) {
            DecodedNode b = root.child("Form body");
            for (Map.Entry<String, List<String>> e : Codecs.parseQuery(body.strip()).entrySet()) {
                for (String v : e.getValue()) b.add(Fb.stringNode(e.getKey(), v, out));
                fields.put(e.getKey(), e.getValue().get(0));
            }
        }
        List<String> bits = new ArrayList<>();
        for (String k : List.of("email", "phoneNumber", "providerId", "requestType", "grant_type", "tenantId")) {
            if (fields.containsKey(k)) bits.add(k.equals("email") ? fields.get(k) : k + " " + fields.get(k));
        }
        for (String k : List.of("idToken", "id_token", "refresh_token", "refreshToken", "token", "oobCode", "postBody")) {
            if (fields.containsKey(k)) bits.add(k);
        }
        String summary = svc + " " + op + (bits.isEmpty() ? "" : " (" + String.join(", ", bits) + ")");
        return new DecodeResult(summary, root, null, out.warnings);
    }

    private static DecodeResult response(MessageContext m, String svc, String op, Out out) throws DecodeException {
        String body = Fb.text(m.responseBody(), m.responseHeader("Content-Encoding"));
        DecodedNode root = DecodedNode.object("Firebase Auth response");
        if (body.isBlank()) return new DecodeResult(svc + " " + op + " response: empty", root, null, out.warnings);
        JsonElement j = Fb.parse(body);
        if (j == null) throw new DecodeException(svc + " response is not JSON");
        root.add(Fb.node("Body", j, false, out, 0));
        JsonObject o = obj(j);
        List<String> bits = new ArrayList<>();
        JsonObject err = obj(o, "error");
        if (err != null) {
            bits.add("error " + (str(err, "code") == null ? "" : str(err, "code") + " ") + str(err, "message"));
        } else if (o != null) {
            String tok = str(o, "idToken") != null ? str(o, "idToken") : str(o, "id_token");
            Fb.Jwt.Parsed p = tok == null ? null : Fb.Jwt.parse(tok);
            if (p != null) bits.add("idToken for " + Fb.Jwt.describe(p));
            else if (str(o, "localId") != null) bits.add("uid " + str(o, "localId") + (str(o, "email") == null ? "" : " (" + str(o, "email") + ")"));
            String exp = str(o, "expiresIn") != null ? str(o, "expiresIn") : str(o, "expires_in");
            if (exp != null) bits.add("expiresIn " + exp + "s");
            if (str(o, "refreshToken") != null || str(o, "refresh_token") != null) bits.add("refreshToken");
            JsonArray users = arr(o, "users");
            if (users != null) {
                JsonObject u = users.isEmpty() ? null : obj(users.get(0));
                bits.add(users.size() + (users.size() == 1 ? " user" : " users")
                        + (u == null ? "" : ": " + str(u, "localId") + (str(u, "email") == null ? "" : " (" + str(u, "email") + ")")));
            }
            if (Boolean.TRUE.toString().equals(str(o, "registered"))) bits.add("registered");
            if (o.has("mfaPendingCredential")) bits.add("MFA required");
        }
        String summary = svc + " " + op + " response" + (bits.isEmpty() ? "" : ": " + String.join(", ", bits));
        return new DecodeResult(summary, root, null, out.warnings);
    }

    // ---------------------------------------------------------------- web config

    /** Cheap check used by match(): does the text plausibly contain a Firebase web config? 0, 25 or 30. */
    static int configConfidence(String head) {
        if (!head.contains("apiKey")) return 0;
        if (!head.contains("authDomain") && !head.contains("projectId")) return 0;
        boolean marker = head.contains("firebaseConfig") || head.contains("initializeApp") || head.contains("firebaseapp.com")
                || head.contains("firebaseio.com") || head.contains("firebasedatabase.app") || head.contains("firebasestorage.app")
                || head.contains("appspot.com");
        if (!marker) return 0;
        return head.contains("AIza") ? 30 : 25;
    }

    static List<Map<String, String>> findConfigs(String s) {
        String t = s;
        if (t.contains("&quot;")) t = t.replace("&quot;", "\"");
        if (t.contains("\\\"")) t = t.replace("\\\"", "\"");
        List<Map<String, String>> out = new ArrayList<>();
        int idx = t.indexOf("apiKey");
        int anchors = 0;
        while (idx >= 0 && anchors++ < 100 && out.size() < MAX_CONFIGS) {
            String literal = enclosingLiteral(t, idx);
            if (literal == null) literal = t.substring(idx, Math.min(t.length(), idx + 2000));
            Map<String, String> cfg = new LinkedHashMap<>();
            Matcher fm = CONFIG_FIELD.matcher(literal);
            while (fm.find()) cfg.putIfAbsent(fm.group(1), fm.group(2));
            boolean useful = cfg.containsKey("apiKey") && (cfg.containsKey("projectId") || cfg.containsKey("authDomain")
                    || cfg.containsKey("appId") || cfg.containsKey("databaseURL"));
            if (useful && !out.contains(cfg)) out.add(cfg);
            idx = t.indexOf("apiKey", idx + 6);
        }
        return out;
    }

    private static String enclosingLiteral(String s, int anchor) {
        int floor = Math.max(0, anchor - 3000);
        for (int i = anchor; i >= floor; i--) {
            if (s.charAt(i) != '{') continue;
            int end = JsLiteral.matchBracket(s, i);
            if (end > anchor) return s.substring(i, Math.min(end, i + 20_000));
            if (end < 0) return null;
        }
        return null;
    }

    static DecodeResult decodeConfig(MessageContext m, Out out) throws DecodeException {
        String s = Fb.text(m.responseBody(), m.responseHeader("Content-Encoding"));
        if (s.length() > FirebaseDecoder.SNIFF * 8) {
            s = s.substring(0, FirebaseDecoder.SNIFF * 8);
            out.warn("only the first " + (FirebaseDecoder.SNIFF * 8 / 1024) + " KB were scanned");
        }
        List<Map<String, String>> configs = findConfigs(s);
        if (configs.isEmpty()) throw new DecodeException("No Firebase configuration (apiKey + projectId/authDomain) found");
        DecodedNode root = DecodedNode.object("Firebase web configuration");
        for (Map<String, String> cfg : configs) {
            String pid = cfg.get("projectId");
            DecodedNode n = new DecodedNode("Firebase config" + (pid == null ? "" : " — " + pid), null, DecodedNode.Type.OBJECT);
            cfg.forEach(n::put);
            DecodedNode derived = n.child("Derived endpoints");
            if (pid != null) {
                derived.put("Firestore REST", "https://firestore.googleapis.com/v1/projects/" + pid + "/databases/(default)/documents");
            }
            if (cfg.containsKey("databaseURL")) derived.put("Realtime Database REST", cfg.get("databaseURL") + "/.json");
            if (cfg.containsKey("storageBucket")) derived.put("Cloud Storage", "https://firebasestorage.googleapis.com/v0/b/" + cfg.get("storageBucket") + "/o");
            derived.put("Identity Toolkit", "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=" + cfg.get("apiKey"));
            n.add(DecodedNode.note("Firebase Web API keys are public identifiers by design; access control relies on Security Rules, App Check and API key restrictions"));
            root.add(n);
        }
        Map<String, String> c = configs.get(0);
        String summary = "Firebase config: " + (c.get("projectId") != null ? "project " + c.get("projectId") : c.get("authDomain"))
                + " (apiKey " + c.get("apiKey") + ")" + (configs.size() > 1 ? " +" + (configs.size() - 1) + " more" : "");
        return new DecodeResult(summary, root, null, out.warnings);
    }
}
