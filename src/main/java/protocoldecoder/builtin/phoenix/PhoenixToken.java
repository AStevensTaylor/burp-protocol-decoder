package protocoldecoder.builtin.phoenix;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Plug.Crypto / Phoenix.Token tokens: {@code base64url(alg).base64url(payload).base64url(signature)} for signed
 * tokens (MessageVerifier), five segments for encrypted ones (MessageEncryptor). The signed payload is
 * {@code term_to_binary({data, signed_at_ms, max_age_s})}.
 */
final class PhoenixToken {

    private static final Pattern SEGMENT = Pattern.compile("[A-Za-z0-9_-]+");
    private static final Pattern SIGN_ALG = Pattern.compile("HS(256|384|512)");
    private static final Pattern ENC_ALG = Pattern.compile("A(128|192|256)(GCM|CBC-HS\\d{3})");

    private PhoenixToken() {
    }

    /** Cheap check: "SFMy…" (HS256/384/512) or "QTEy…/QTI1…" (A128/A256…) followed by the right number of segments. */
    static boolean looksLikeToken(String s) {
        if (s == null || s.length() < 20 || s.length() > 64 * 1024) return false;
        String[] parts = s.split("\\.", -1);
        if (parts.length != 3 && parts.length != 5) return false;
        for (String p : parts) if (!p.isEmpty() && !SEGMENT.matcher(p).matches()) return false;
        String alg = algorithm(parts[0]);
        if (alg == null) return false;
        return parts.length == 3 ? SIGN_ALG.matcher(alg).matches() : ENC_ALG.matcher(alg).matches();
    }

    private static String algorithm(String seg) {
        if (seg.length() > 24) return null;
        byte[] b = Codecs.base64Decode(seg);
        if (b == null) return null;
        String a = new String(b, StandardCharsets.US_ASCII);
        return SIGN_ALG.matcher(a).matches() || ENC_ALG.matcher(a).matches() ? a : null;
    }

    static boolean isEncrypted(String token) {
        return token.split("\\.", -1).length == 5;
    }

    static DecodedNode node(String name, String token) {
        DecodedNode n = DecodedNode.object(name);
        String[] parts = token.split("\\.", -1);
        String alg = algorithm(parts[0]);
        n.put("Algorithm", alg);
        if (parts.length == 5) {
            n.put("Kind", "encrypted (Plug.Crypto.MessageEncryptor)");
            n.add(DecodedNode.note("encrypted with a key derived from secret_key_base; the contents are not readable"));
            return n;
        }
        n.put("Kind", "signed (Plug.Crypto.MessageVerifier / Phoenix.Token.sign)");
        byte[] payload = Codecs.base64Decode(parts[1]);
        byte[] sig = Codecs.base64Decode(parts[2]);
        if (sig != null) n.add(DecodedNode.leaf("Signature", Codecs.hexPreview(sig, 64), DecodedNode.Type.BINARY));
        if (payload == null) {
            n.add(DecodedNode.note("payload is not valid base64url"));
            return n;
        }
        if (!Etf.looksLikeEtf(payload)) {
            n.put("Payload", Etf.isUtf8Text(payload) ? Codecs.truncate(Codecs.utf8(payload), 8000) : Codecs.hexPreview(payload, 256));
        } else {
            try {
                Object term = Etf.decode(payload);
                if (term instanceof Etf.Tuple t && t.items().size() == 3 && t.items().get(1) instanceof Long signedAt
                        && t.items().get(2) instanceof Long maxAge) {
                    n.add(Etf.toNode("Data", t.items().get(0)));
                    n.put("Signed at", Instant.ofEpochMilli(signedAt).toString() + "  (" + signedAt + " ms)");
                    n.put("Max age", maxAge + " s" + (maxAge > 0 ? "  (expires " + Instant.ofEpochMilli(signedAt + maxAge * 1000).toString() + ")" : ""));
                } else {
                    n.add(Etf.toNode("Data", term));
                }
            } catch (Etf.EtfException e) {
                n.put("Payload (hex)", Codecs.hexPreview(payload, 256));
                n.add(DecodedNode.note("could not decode Erlang term: " + e.getMessage()));
            }
        }
        n.add(DecodedNode.note("signed, not encrypted: anyone holding the token can read this data, but cannot change it without the server's secret_key_base"));
        return n;
    }

    /** Collects every token-shaped string value in a JSON tree, as path → token. */
    static void collect(JsonElement e, String path, Map<String, String> out, int depth) {
        if (e == null || depth > 24 || out.size() >= 20) return;
        if (e.isJsonPrimitive() && e.getAsJsonPrimitive().isString()) {
            String s = e.getAsString();
            if (looksLikeToken(s)) out.put(path, s);
        } else if (e.isJsonObject()) {
            for (Map.Entry<String, JsonElement> en : e.getAsJsonObject().entrySet()) {
                collect(en.getValue(), path.isEmpty() ? en.getKey() : path + "." + en.getKey(), out, depth + 1);
            }
        } else if (e.isJsonArray()) {
            JsonArray a = e.getAsJsonArray();
            for (int i = 0; i < a.size() && i < 200; i++) collect(a.get(i), path + "[" + i + "]", out, depth + 1);
        }
    }

    static boolean anySigned(Map<String, String> tokens) {
        return tokens.values().stream().anyMatch(t -> !isEncrypted(t));
    }
}
