package protocoldecoder.builtin.batchexecute;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonPrimitive;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MessageContext;
import protocoldecoder.scan.Confidence;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.InsertionPoint;
import protocoldecoder.scan.InsertionPoints;
import protocoldecoder.scan.PassiveCheck;
import protocoldecoder.scan.ProtocolScanner;
import protocoldecoder.scan.ScanPatterns;
import protocoldecoder.scan.Severity;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scanner support for Google batchexecute. The main value is insertion points: each RPC's arguments are a JSON string
 * inside the f.req JSON (often with further JSON strings nested inside), which Burp cannot edit itself. Every leaf is
 * exposed with all enclosing levels re-stringified and the form field re-URL-encoded.
 *
 * <p>No active checks: batchexecute is a generic transport, and the application-specific RPC handlers are reached
 * through the insertion points by Burp's own scan checks.</p>
 */
public final class BatchExecuteScanner implements ProtocolScanner {

    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();
    private static final Pattern APP = Pattern.compile("/_/([^/]+)/data/batchexecute$");
    /** Maximum depth of JSON-in-string nesting followed inside an RPC's arguments. */
    static final int MAX_NESTING = 4;

    @Override
    public String decoderId() {
        return BatchExecuteDecoder.ID;
    }

    @Override
    public List<PassiveCheck> passiveChecks() {
        return List.of(new ErrorDetails(), new RpcInventory(), new MissingXsrfToken());
    }

    // ================================================================ insertion points

    /** A payload position inside f.req: {@code render} returns the complete new f.req value. */
    record FreqLeaf(String rpcId, String path, String baseValue, Function<String, String> render) {
    }

    @Override
    public List<InsertionPoint> insertionPoints(MessageContext request, DecodeResult decoded) {
        List<InsertionPoint> out = new ArrayList<>();
        if (!request.isRequest() || request.requestHeader("Content-Encoding") != null) return out;
        String body = request.requestBodyText();
        Map<String, List<String>> form = Codecs.parseQuery(body);
        String freq = Codecs.first(form, "f.req");
        boolean inBody = freq != null;
        if (!inBody) freq = Codecs.first(request.queryParameters(), "f.req");
        if (freq == null) return out;
        String query = request.query();
        for (FreqLeaf leaf : leaves(freq)) {
            String name = "batchexecute: " + leaf.rpcId() + " " + leaf.path();
            if (inBody) {
                out.add(InsertionPoint.body(name, leaf.baseValue(),
                        p -> InsertionPoints.replaceFormField(body, "f.req", 0, leaf.render().apply(p)).getBytes(StandardCharsets.UTF_8)));
            } else {
                out.add(InsertionPoint.query(name, leaf.baseValue(),
                        p -> InsertionPoints.replaceFormField(query, "f.req", 0, leaf.render().apply(p)).getBytes(StandardCharsets.UTF_8)));
            }
        }
        return out;
    }

    /** Every primitive leaf of every RPC's (possibly multiply nested) arguments, bounded by {@link InsertionPoints#MAX_POINTS}. */
    static List<FreqLeaf> leaves(String freq) {
        List<FreqLeaf> out = new ArrayList<>();
        if (freq == null) return out;
        JsonElement root = JsonTree.parseStrict(freq.strip());
        if (root == null || !root.isJsonArray()) return out;
        List<List<Integer>> envs = new ArrayList<>();
        findEnvelopes(root.getAsJsonArray(), new ArrayList<>(), envs, 0);
        for (List<Integer> steps : envs) {
            JsonArray env = at(root, steps);
            String rpc = env.get(0).getAsString();
            String innerRaw = env.get(1).getAsString();
            JsonElement inner = JsonTree.parseStrict(innerRaw);
            if (inner == null || !(inner.isJsonArray() || inner.isJsonObject())) continue;
            Function<String, String> toFreq = s -> {
                JsonElement copy = root.deepCopy();
                at(copy, steps).set(1, new JsonPrimitive(s));
                return GSON.toJson(copy);
            };
            collect(rpc, inner, "", toFreq, out, 0);
        }
        return out;
    }

    private static void collect(String rpc, JsonElement level, String prefix, Function<String, String> wrap, List<FreqLeaf> out, int depth) {
        for (InsertionPoints.JsonLeaf leaf : InsertionPoints.jsonLeaves(level)) {
            if (out.size() >= InsertionPoints.MAX_POINTS) return;
            String path = prefix + leaf.path();
            JsonElement v = leaf.value();
            if (depth < MAX_NESTING && v.isJsonPrimitive() && v.getAsJsonPrimitive().isString()) {
                String s = v.getAsString().strip();
                if ((s.startsWith("[") || s.startsWith("{")) && s.length() >= 2) {
                    JsonElement nested = JsonTree.parseStrict(v.getAsString());
                    if (nested != null && (nested.isJsonArray() || nested.isJsonObject())) {
                        Function<String, String> replace = leaf.replace();
                        collect(rpc, nested, path + " › ", s2 -> wrap.apply(replace.apply(s2)), out, depth + 1);
                        continue;
                    }
                }
            }
            Function<String, String> replace = leaf.replace();
            out.add(new FreqLeaf(rpc, path, InsertionPoints.text(v), p -> wrap.apply(replace.apply(p))));
        }
    }

    private static JsonArray at(JsonElement root, List<Integer> steps) {
        JsonElement cur = root;
        for (int i : steps) cur = cur.getAsJsonArray().get(i);
        return cur.getAsJsonArray();
    }

    /** Same shape rules as the decoder: [rpcid, "&lt;json&gt;", null, tag], found up to 3 levels deep. */
    private static void findEnvelopes(JsonArray a, List<Integer> steps, List<List<Integer>> out, int depth) {
        if (depth > 3 || out.size() >= 200) return;
        if (isEnvelope(a)) {
            out.add(List.copyOf(steps));
            return;
        }
        for (int i = 0; i < a.size(); i++) {
            if (!a.get(i).isJsonArray()) continue;
            steps.add(i);
            findEnvelopes(a.get(i).getAsJsonArray(), steps, out, depth + 1);
            steps.remove(steps.size() - 1);
        }
    }

    private static boolean isEnvelope(JsonArray a) {
        if (a.size() < 2 || a.size() > 6) return false;
        JsonElement id = a.get(0), inner = a.get(1);
        if (!id.isJsonPrimitive() || !id.getAsJsonPrimitive().isString()) return false;
        String s = id.getAsString();
        if (s.isEmpty() || s.length() > 64 || !s.matches("[A-Za-z0-9_.$-]+")) return false;
        if (!inner.isJsonPrimitive() || !inner.getAsJsonPrimitive().isString()) return false;
        return JsonTree.looksLikeJson(inner.getAsString().strip());
    }

    // ================================================================ passive checks

    private static void walk(DecodedNode n, java.util.function.Consumer<DecodedNode> f, int[] budget) {
        if (n == null || budget[0]-- <= 0) return;
        f.accept(n);
        for (DecodedNode c : n.children()) walk(c, f, budget);
    }

    private static void leafText(DecodedNode n, StringBuilder sb, int[] budget) {
        if (n == null || budget[0]-- <= 0 || sb.length() > 200_000) return;
        if (n.value() != null) sb.append(n.value()).append('\n');
        for (DecodedNode c : n.children()) leafText(c, sb, budget);
    }

    /** er entries / wrb.fr error payloads containing exception or stack-trace details. */
    static final class ErrorDetails implements PassiveCheck {
        @Override public String id() { return "batchexecute.error-details"; }
        @Override public String name() { return "RPC error with stack trace"; }
        @Override public String description() { return "er entries or wrb.fr error payloads containing exception types or stack frames"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || decoded == null) return List.of();
            StringBuilder sb = new StringBuilder();
            int[] budget = {20_000};
            walk(decoded.root(), n -> {
                if (n.name().equals("er (error)") || n.name().equals("Error")) leafText(n, sb, new int[]{5_000});
            }, budget);
            if (sb.isEmpty()) return List.of();
            String trace = ScanPatterns.exceptionEvidence(sb.toString());
            if (trace == null) return List.of();
            return List.of(Finding.of(id(), "batchexecute error discloses exception details")
                    .severity(Severity.LOW).confidence(Confidence.FIRM)
                    .detail("A batchexecute error entry contains exception/stack-trace details: <code>" + Finding.esc(Codecs.truncate(trace, 500)) + "</code>")
                    .background("batchexecute returns per-RPC errors in <code>er</code> entries or the error slot of <code>wrb.fr</code>. "
                            + "Stack traces reveal server-side classes and code paths, and errors triggered by modified RPC arguments often point to missing validation.")
                    .remediation("Map server exceptions to generic RPC error codes before returning them to the client.")
                    .responseEvidence(trace));
        }
    }

    /** Inventory of RPC ids per host (Information). */
    static final class RpcInventory implements PassiveCheck {
        @Override public String id() { return "batchexecute.rpc-inventory"; }
        @Override public String name() { return "batchexecute RPC inventory"; }
        @Override public String description() { return "Lists the RPC ids and app name of batchexecute requests (Information, once per host)"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isRequest() || decoded == null) return List.of();
            DecodedNode rpcs = decoded.root().get("RPCs");
            if (rpcs == null || rpcs.isLeaf()) return List.of();
            Set<String> ids = new LinkedHashSet<>();
            for (DecodedNode n : rpcs.children()) if (ids.size() < 50) ids.add(n.name());
            Matcher am = APP.matcher(m.path());
            String app = am.find() ? am.group(1) : null;
            String source = Codecs.first(m.queryParameters(), "source-path");
            StringBuilder sb = new StringBuilder("The application uses Google batchexecute RPCs");
            if (app != null) sb.append(" (app <code>").append(Finding.esc(app)).append("</code>)");
            sb.append(" at <code>").append(Finding.esc(m.path())).append("</code>");
            if (source != null) sb.append(", called from page <code>").append(Finding.esc(Codecs.truncate(source, 300))).append("</code>");
            sb.append(". RPC ids in this request:<ul>");
            for (String id : ids) sb.append("<li><code>").append(Finding.esc(id)).append("</code></li>");
            sb.append("</ul>Other pages call other RPCs; the Protocol Decoder tab shows the arguments of each. "
                    + "Each RPC is an application endpoint — the protocol-aware insertion points let the scanner reach its arguments.");
            Finding f = Finding.of(id(), "batchexecute RPCs in use")
                    .severity(Severity.INFORMATION).confidence(Confidence.CERTAIN).scope(Finding.Scope.HOST)
                    .detail(sb.toString())
                    .background("batchexecute multiplexes RPC calls as <code>[[[\"rpcid\",\"&lt;JSON args&gt;\",null,\"generic\"]]]</code> in the "
                            + "<code>f.req</code> form field. RPC ids are opaque, so the endpoint list is only discoverable from traffic and client scripts.")
                    .remediation("No action required; this is an inventory finding.");
            for (String id : ids) {
                f.requestEvidence(id);
                if (f.evidence().size() >= 5) break;
            }
            return List.of(f);
        }
    }

    /** POST with session cookies but neither the {@code at} token nor X-Same-Domain, and the RPC still succeeded. */
    static final class MissingXsrfToken implements PassiveCheck {
        @Override public String id() { return "batchexecute.missing-xsrf"; }
        @Override public String name() { return "RPC accepted without XSRF token"; }
        @Override public String description() {
            return "Cookie-authenticated POST without the 'at' XSRF token or X-Same-Domain header whose RPC returned a payload (Information, tentative)";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || decoded == null || !"POST".equals(m.method())) return List.of();
            int st = m.statusCode() == null ? 0 : m.statusCode();
            if (st != 200) return List.of();
            if (m.requestHeader("Cookie") == null || m.requestHeader("X-Same-Domain") != null) return List.of();
            Map<String, List<String>> form = Codecs.parseQuery(Codecs.utf8(Codecs.decodeContent(m.requestBody(), m.requestHeader("Content-Encoding"))));
            if (form.get("f.req") == null) return List.of();
            if (form.containsKey("at") || m.queryParameters().containsKey("at")) return List.of();
            List<String> ok = new ArrayList<>();
            walk(decoded.root(), n -> {
                if (n.name().startsWith("wrb.fr ") && n.get("Payload size") != null && ok.size() < 10) ok.add(n.name().substring(7));
            }, new int[]{20_000});
            if (ok.isEmpty()) return List.of();
            return List.of(Finding.of(id(), "batchexecute RPC accepted without XSRF token")
                    .severity(Severity.INFORMATION).confidence(Confidence.TENTATIVE)
                    .detail("This cookie-authenticated POST has no <code>at</code> XSRF token and no <code>X-Same-Domain</code> header, yet RPC(s) "
                            + "<code>" + Finding.esc(String.join(", ", ok)) + "</code> returned a payload. If any of these RPCs change state, "
                            + "check whether they can be triggered cross-site (SameSite cookie attributes, Origin checks).")
                    .background("Google-style frameworks protect batchexecute with the <code>at</code> form field (an XSRF token bound to the session) "
                            + "and/or the <code>X-Same-Domain: 1</code> header. Read-only or anonymous RPCs legitimately omit them.")
                    .remediation("Require the XSRF token (or a custom header plus Origin check) for every state-changing RPC."));
        }
    }
}
