package protocoldecoder.builtin.turbo;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Decodes a Rails {@code ActiveSupport::MessageVerifier} token such as Turbo's {@code signed-stream-name}:
 * {@code base64(serialized data) + "--" + hex HMAC digest}. The data is JSON (Turbo's default) or Ruby Marshal (older
 * apps / custom verifiers); Rails 7.1+ may wrap it in a {@code {"_rails":{"data":…,"pur":…,"exp":…}}} envelope.
 * Signed, not encrypted: the content is readable but cannot be changed without the app's secret.
 */
public final class SignedStreamName {

    private static final Pattern GID = Pattern.compile(
            "gid://[A-Za-z0-9._-]+/[A-Z][A-Za-z0-9_]*(?:::[A-Z][A-Za-z0-9_]*)*/[^\\s\"':/?&<>]+(?:\\?[^\\s\"':<>]*)?");
    private static final Pattern HEX = Pattern.compile("[0-9a-fA-F]+");

    private SignedStreamName() {
    }

    /**
     * @param display    short rendering of the decoded value for summaries (stream name, JSON, or Marshal inspect)
     * @param format     "JSON", "Ruby Marshal", or "unknown"
     * @param globalIds  GlobalIDs (gid://app/Model/id) found in the decoded value
     */
    public record Decoded(boolean ok, String display, String format, String digest, String digestAlgorithm,
                          List<String> globalIds, DecodedNode node) {
    }

    /** True if the value has the {@code data--digest} shape. */
    public static boolean looksSigned(String token) {
        if (token == null) return false;
        int sep = token.lastIndexOf("--");
        return sep > 0 && sep + 2 < token.length() && HEX.matcher(token.substring(sep + 2)).matches();
    }

    public static Decoded decode(String name, String token) {
        DecodedNode n = DecodedNode.object(name);
        String t = token == null ? "" : token.strip();
        n.put("Raw", Codecs.truncate(t, 2000));
        int sep = t.lastIndexOf("--");
        String data = sep > 0 ? t.substring(0, sep) : t;
        String digest = sep > 0 ? t.substring(sep + 2) : null;
        String alg = null;
        if (digest != null) {
            alg = switch (digest.length()) {
                case 40 -> "HMAC-SHA1";
                case 64 -> "HMAC-SHA256";
                case 96 -> "HMAC-SHA384";
                case 128 -> "HMAC-SHA512";
                default -> HEX.matcher(digest).matches() ? "unknown (" + digest.length() / 2 + " bytes)" : "not hex";
            };
            n.put("Digest (" + alg + ")", digest);
        } else {
            n.add(DecodedNode.note("no '--digest' part: not a MessageVerifier token"));
        }
        byte[] raw = Codecs.base64Decode(data.contains("%") ? Codecs.urlDecode(data.replace("+", "%2B")) : data);
        if (raw == null || raw.length == 0) {
            n.add(DecodedNode.note("data part is not base64"));
            return new Decoded(false, Codecs.truncate(t, 80), "unknown", digest, alg, List.of(), n);
        }
        String display;
        String format;
        if (RubyMarshal.isMarshal(raw)) {
            format = "Ruby Marshal";
            String inspect;
            try {
                inspect = RubyMarshal.inspect(raw);
            } catch (IllegalArgumentException e) {
                inspect = null;
                n.add(DecodedNode.note("Marshal data could not be fully read: " + e.getMessage()));
                n.put("Data (hex)", Codecs.hexPreview(raw, 256));
            }
            if (inspect != null) n.put("Data (Ruby Marshal 4.8)", inspect);
            display = inspect != null ? stripQuotes(inspect) : "(Ruby Marshal, " + raw.length + " bytes)";
            n.add(DecodedNode.note("Ruby Marshal payload: the server deserialises this with Marshal.load after verifying the signature"));
        } else {
            String text = Codecs.utf8(raw);
            JsonElement e = JsonTree.parseStrict(text);
            if (e == null) e = JsonTree.parseLenient(text);
            if (e != null) {
                format = "JSON";
                JsonElement value = e;
                if (e.isJsonObject() && e.getAsJsonObject().has("_rails") && e.getAsJsonObject().get("_rails").isJsonObject()) {
                    JsonObject env = e.getAsJsonObject().getAsJsonObject("_rails");
                    DecodedNode meta = n.child("Rails 7.1+ metadata envelope");
                    if (env.has("pur")) meta.add(JsonTree.toNode("pur (purpose)", env.get("pur"), false));
                    if (env.has("exp")) meta.add(JsonTree.toNode("exp (expires)", env.get("exp"), false));
                    if (env.has("data")) value = env.get("data");
                }
                n.add(JsonTree.toNode("Data (JSON)", value, true));
                display = value.isJsonPrimitive() ? value.getAsString() : value.toString();
            } else if (Codecs.isMostlyText(raw)) {
                format = "text";
                n.put("Data (text)", Codecs.truncate(text, 4000));
                display = text;
            } else {
                format = "binary";
                n.put("Data (hex)", Codecs.hexPreview(raw, 256));
                display = "(" + raw.length + " bytes)";
            }
        }
        List<String> gids = globalIds(display);
        if (!gids.isEmpty()) {
            DecodedNode g = DecodedNode.array("GlobalIDs");
            for (String gid : gids) g.add(DecodedNode.leaf("", gid + describeGid(gid)));
            n.add(g);
            n.add(DecodedNode.note("GlobalIDs reveal model names and record ids; the stream is authorised only by this signature — check whether the channel also accepts unsigned or guessable names (IDOR)"));
        }
        n.add(DecodedNode.note("signed (" + (alg == null ? "HMAC" : alg) + "), not encrypted: readable by anyone, but cannot be altered without secret_key_base"));
        return new Decoded(true, Codecs.truncate(display, 200), format, digest, alg, gids, n);
    }

    private static String stripQuotes(String s) {
        return s.length() >= 2 && s.startsWith("\"") && s.endsWith("\"") && s.indexOf('"', 1) == s.length() - 1 ? s.substring(1, s.length() - 1) : s;
    }

    public static List<String> globalIds(String s) {
        Set<String> out = new LinkedHashSet<>();
        if (s == null) return List.of();
        Matcher m = GID.matcher(s);
        while (m.find() && out.size() < 50) out.add(m.group());
        return new ArrayList<>(out);
    }

    private static String describeGid(String gid) {
        String[] p = gid.substring("gid://".length()).split("/", 3);
        if (p.length < 3) return "";
        String id = p[2];
        int q = id.indexOf('?');
        if (q >= 0) id = id.substring(0, q);
        return "  (app " + p[0] + ", model " + p[1] + ", id " + Codecs.urlDecode(id) + ")";
    }
}
