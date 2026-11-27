package protocoldecoder.builtin.batchexecute;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.ProtocolDecoder;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Google "batchexecute" RPC framework (Google web apps: /_/&lt;App&gt;/data/batchexecute): f.req request envelopes and
 * XSSI-protected, optionally length-chunked (rt=c) responses with wrb.fr / di / af.httprm / e / er entries.
 */
public final class BatchExecuteDecoder implements ProtocolDecoder {

    public static final String ID = "batchexecute";

    static final String XSSI = ")]}'";
    private static final int SNIFF = 64 * 1024;
    private static final int MAX_ENTRIES = 2000;
    private static final Pattern APP = Pattern.compile("/_/([^/]+)/data/batchexecute$");

    private static final Map<String, String> QUERY_LABELS = Map.ofEntries(
            Map.entry("rpcids", "RPC ids"),
            Map.entry("source-path", "Source path (page the RPC came from)"),
            Map.entry("f.sid", "Frontend session id"),
            Map.entry("bl", "Build label (server release)"),
            Map.entry("hl", "UI language"),
            Map.entry("soc-app", "Social app id"),
            Map.entry("soc-platform", "Social platform"),
            Map.entry("soc-device", "Social device"),
            Map.entry("_reqid", "Request sequence id"),
            Map.entry("rt", "Response type (c = chunked, b = binary-ish, absent = single JSON)"),
            Map.entry("authuser", "Signed-in account index"),
            Map.entry("pageId", "Page id"));

    @Override public String id() { return ID; }
    @Override public String name() { return "Google batchexecute"; }
    @Override public String description() {
        return "Google web-app batchexecute RPCs: f.req envelopes, chunked )]}' responses (wrb.fr, di, af.httprm, er)";
    }

    // ---------------------------------------------------------------- matching

    static boolean batchPath(MessageContext m) {
        return m.path().endsWith("/batchexecute");
    }

    @Override
    public MatchResult match(MessageContext m) {
        try {
            if (m.isWebSocket()) return MatchResult.NONE;
            if (m.isRequest()) {
                if (batchPath(m)) return MatchResult.of(95, "batchexecute endpoint");
                byte[] b = m.requestBody();
                if (b.length < 8 || b.length > 4 * 1024 * 1024) return MatchResult.NONE;
                String head = new String(b, 0, Math.min(b.length, 16), StandardCharsets.ISO_8859_1);
                String body = m.requestBodyText();
                if (!head.startsWith("f.req=") && !body.contains("&f.req=")) return MatchResult.NONE;
                String freq = Codecs.first(Codecs.parseQuery(body), "f.req");
                return envelopes(freq).isEmpty() ? MatchResult.NONE : MatchResult.of(70, "f.req batchexecute envelope in form body");
            }
            if (batchPath(m)) return MatchResult.of(95, "response from batchexecute endpoint");
            byte[] body = Codecs.decodeContent(m.responseBody(), m.responseHeader("Content-Encoding"));
            if (body == null || body.length < 8) return MatchResult.NONE;
            String head = new String(body, 0, Math.min(body.length, SNIFF), StandardCharsets.UTF_8);
            if (head.startsWith(XSSI) && head.contains("\"wrb.fr\"")) return MatchResult.of(70, ")]}' response with wrb.fr entries");
            return MatchResult.NONE;
        } catch (RuntimeException e) {
            return MatchResult.NONE;
        }
    }

    // ---------------------------------------------------------------- request

    /** An f.req envelope: [rpcid, inner JSON string, null, "generic" | index]. */
    record Envelope(String rpcId, JsonElement inner, String innerRaw, String tag) {
    }

    /** Extracts the envelopes from f.req, or an empty list if it does not have the batchexecute shape. */
    static List<Envelope> envelopes(String freq) {
        List<Envelope> out = new ArrayList<>();
        if (freq == null) return out;
        String t = freq.strip();
        if (!t.startsWith("[")) return out;
        JsonElement j = JsonTree.parseStrict(t);
        if (j == null) j = JsonTree.parseLenient(t);
        if (j == null || !j.isJsonArray()) return out;
        collect(j.getAsJsonArray(), out, 0);
        return out;
    }

    private static void collect(JsonArray a, List<Envelope> out, int depth) {
        if (depth > 3 || out.size() >= MAX_ENTRIES) return;
        if (isEnvelope(a)) {
            JsonElement inner = a.get(1);
            String raw = inner.isJsonNull() ? null : inner.getAsString();
            String tag = a.size() > 3 && a.get(3).isJsonPrimitive() ? a.get(3).getAsString() : null;
            out.add(new Envelope(a.get(0).getAsString(), raw == null ? null : parseAny(raw), raw, tag));
            return;
        }
        for (JsonElement e : a) {
            if (e.isJsonArray()) collect(e.getAsJsonArray(), out, depth + 1);
        }
    }

    private static boolean isEnvelope(JsonArray a) {
        if (a.size() < 2 || a.size() > 6) return false;
        JsonElement id = a.get(0), inner = a.get(1);
        if (!id.isJsonPrimitive() || !id.getAsJsonPrimitive().isString()) return false;
        String s = id.getAsString();
        if (s.isEmpty() || s.length() > 64 || !s.matches("[A-Za-z0-9_.$-]+")) return false;
        if (inner.isJsonNull()) return a.size() >= 3;
        if (!inner.isJsonPrimitive() || !inner.getAsJsonPrimitive().isString()) return false;
        String in = inner.getAsString().strip();
        return in.equals("null") || JsonTree.looksLikeJson(in);
    }

    private static JsonElement parseAny(String s) {
        JsonElement e = JsonTree.parseStrict(s);
        return e != null || !JsonTree.looksLikeJson(s) ? e : JsonTree.parseLenient(s);
    }

    @Override
    public DecodeResult decode(MessageContext m) throws DecodeException {
        try {
            return m.isResponse() ? decodeResponse(m) : decodeRequest(m);
        } catch (DecodeException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new DecodeException("batchexecute decode failed: " + e, e);
        }
    }

    private DecodeResult decodeRequest(MessageContext m) throws DecodeException {
        List<String> warnings = new ArrayList<>();
        Map<String, List<String>> q = m.queryParameters();
        String bodyText = Codecs.utf8(Codecs.decodeContent(m.requestBody(), m.requestHeader("Content-Encoding")));
        Map<String, List<String>> form = Codecs.parseQuery(bodyText);
        String freq = Codecs.first(form, "f.req");
        if (freq == null) freq = Codecs.first(q, "f.req");
        if (freq == null) throw new DecodeException("No f.req parameter found in this request");
        List<Envelope> envs = envelopes(freq);
        if (envs.isEmpty()) throw new DecodeException("f.req does not contain batchexecute envelopes ([[[\"rpcid\",\"<json>\",null,\"generic\"]]])");

        DecodedNode root = DecodedNode.object("batchexecute request");
        DecodedNode ep = root.child("Endpoint");
        Matcher am = APP.matcher(m.path());
        String app = am.find() ? am.group(1) : null;
        ep.put("App", app);
        ep.put("Host", m.host());
        ep.put("Path", m.path());
        if (!q.isEmpty()) {
            DecodedNode qp = ep.child("Query parameters");
            for (Map.Entry<String, List<String>> e : q.entrySet()) {
                String label = QUERY_LABELS.get(e.getKey());
                for (String v : e.getValue()) qp.put(label == null ? e.getKey() : e.getKey() + " — " + label, v);
            }
        }
        String at = Codecs.first(form, "at");
        if (at != null) {
            root.add(DecodedNode.leaf("at (XSRF token)", at));
        } else {
            root.add(DecodedNode.note("No 'at' XSRF token in the body (anonymous request, or token sent elsewhere)"));
        }

        DecodedNode rpcs = DecodedNode.array("RPCs");
        root.add(rpcs);
        Set<String> ids = new LinkedHashSet<>();
        for (Envelope e : envs) {
            ids.add(e.rpcId());
            DecodedNode n = new DecodedNode(e.rpcId(), e.tag() == null ? null : "tag " + e.tag(), DecodedNode.Type.OBJECT);
            n.put("RPC id", e.rpcId());
            if (e.tag() != null) n.put("Tag", e.tag());
            if (e.inner() != null) {
                n.add(JsonTree.toNode("Arguments", e.inner(), true));
            } else if (e.innerRaw() != null) {
                n.add(DecodedNode.leaf("Arguments (raw)", e.innerRaw()));
                warnings.add("arguments of " + e.rpcId() + " are not JSON");
            } else {
                n.add(DecodedNode.leaf("Arguments", "null", DecodedNode.Type.NULL));
            }
            rpcs.add(n);
        }
        for (Map.Entry<String, List<String>> e : form.entrySet()) {
            if (e.getKey().equals("f.req") || e.getKey().equals("at")) continue;
            DecodedNode other = root.get("Other form fields");
            if (other == null) other = root.child("Other form fields");
            for (String v : e.getValue()) other.put(e.getKey(), v);
        }
        String declared = Codecs.first(q, "rpcids");
        if (declared != null) {
            Set<String> decl = new LinkedHashSet<>(List.of(declared.split(",")));
            if (!decl.equals(ids)) warnings.add("rpcids query parameter (" + declared + ") does not match f.req envelopes (" + String.join(",", ids) + ")");
        }
        String summary = "batchexecute → " + envs.size() + (envs.size() == 1 ? " RPC: " : " RPCs: ") + String.join(", ", ids)
                + (app == null ? "" : " [" + app + "]");
        return new DecodeResult(summary, root, null, warnings);
    }

    // ---------------------------------------------------------------- response

    private DecodeResult decodeResponse(MessageContext m) throws DecodeException {
        byte[] raw = Codecs.decodeContent(m.responseBody(), m.responseHeader("Content-Encoding"));
        String s = Codecs.utf8(raw == null ? new byte[0] : raw);
        List<String> warnings = new ArrayList<>();
        int pos = 0;
        boolean xssi = s.startsWith(XSSI);
        if (xssi) pos = XSSI.length();
        else if (s.stripLeading().startsWith(XSSI)) { pos = s.indexOf(XSSI) + XSSI.length(); xssi = true; }

        DecodedNode root = DecodedNode.object("batchexecute response");
        root.put("XSSI prefix", xssi ? XSSI : "absent");
        List<JsonElement> batches = new ArrayList<>();
        boolean chunked = ChunkedJson.looksChunked(s, pos);
        if (chunked) {
            ChunkedJson.Result r = ChunkedJson.parse(s, pos);
            warnings.addAll(r.warnings());
            root.put("Framing", "length-prefixed chunks (rt=c), " + r.chunks().size() + " chunks");
            for (ChunkedJson.Chunk c : r.chunks()) {
                if (c.json() != null) batches.add(c.json());
                else root.add(DecodedNode.leaf("Unparsed chunk @" + c.offset(), Codecs.truncate(c.raw(), 4000)));
            }
        } else {
            String rest = s.substring(pos).strip();
            JsonElement j = rest.isEmpty() ? null : parseAny(rest);
            if (j == null) {
                // a single response may be followed by trailing data; take the first balanced array
                int open = rest.indexOf('[');
                int end = open < 0 ? -1 : protocoldecoder.util.JsLiteral.matchBracket(rest, open);
                if (end > 0) {
                    j = parseAny(rest.substring(open, end));
                    if (j != null) warnings.add("ignored " + (rest.length() - end) + " chars after the JSON body");
                }
            }
            if (j == null || !j.isJsonArray()) throw new DecodeException("Response is neither length-chunked nor a JSON array" + (xssi ? " after the )]}' prefix" : ""));
            root.put("Framing", "single JSON body");
            batches.add(j);
        }

        DecodedNode entries = DecodedNode.array("Entries");
        root.add(entries);
        List<String> parts = new ArrayList<>();
        int count = 0;
        for (JsonElement b : batches) {
            for (JsonArray entry : entryArrays(b)) {
                if (++count > MAX_ENTRIES) {
                    warnings.add("stopped after " + MAX_ENTRIES + " entries");
                    break;
                }
                entries.add(entryNode(entry, parts, warnings));
            }
        }
        if (count == 0 && !chunked && batches.size() == 1) {
            entries.add(JsonTree.toNode("body", batches.get(0), true));
        }
        String summary = "batchexecute response: " + (parts.isEmpty() ? count + " entries" : String.join(", ", dedupe(parts)));
        return new DecodeResult(summary, root, null, warnings);
    }

    /** A chunk is either an array of entries ([["wrb.fr",…],["di",…]]) or a single entry (["wrb.fr",…]). */
    private static List<JsonArray> entryArrays(JsonElement b) {
        List<JsonArray> out = new ArrayList<>();
        if (!b.isJsonArray()) return out;
        JsonArray a = b.getAsJsonArray();
        if (isTagged(a)) {
            out.add(a);
            return out;
        }
        for (JsonElement e : a) {
            if (e.isJsonArray()) out.add(e.getAsJsonArray());
        }
        return out;
    }

    private static boolean isTagged(JsonArray a) {
        return !a.isEmpty() && a.get(0).isJsonPrimitive() && a.get(0).getAsJsonPrimitive().isString();
    }

    private static String str(JsonArray a, int i) {
        if (i >= a.size()) return null;
        JsonElement e = a.get(i);
        return e.isJsonPrimitive() ? e.getAsString() : e.isJsonNull() ? null : e.toString();
    }

    private static DecodedNode entryNode(JsonArray a, List<String> parts, List<String> warnings) {
        String tag = isTagged(a) ? a.get(0).getAsString() : "?";
        switch (tag) {
            case "wrb.fr" -> {
                String rpc = str(a, 1);
                JsonElement payload = a.size() > 2 ? a.get(2) : null;
                DecodedNode n = new DecodedNode("wrb.fr " + rpc, null, DecodedNode.Type.OBJECT);
                n.put("RPC id", rpc);
                if (payload != null && payload.isJsonPrimitive()) {
                    String p = payload.getAsString();
                    JsonElement inner = parseAny(p);
                    n.put("Payload size", size(p.length()));
                    if (inner != null) n.add(JsonTree.toNode("Payload", inner, true));
                    else n.add(DecodedNode.leaf("Payload (raw)", Codecs.truncate(p, 100_000)));
                    parts.add("wrb.fr " + rpc + " (" + size(p.length()) + " payload)");
                } else {
                    JsonElement err = a.size() > 5 ? a.get(5) : null;
                    if (err != null && !err.isJsonNull()) {
                        n.add(JsonTree.toNode("Error", err, true));
                        parts.add("wrb.fr " + rpc + " error " + Codecs.truncate(err.toString(), 40));
                    } else {
                        n.add(DecodedNode.leaf("Payload", "null", DecodedNode.Type.NULL));
                        parts.add("wrb.fr " + rpc + " (no payload)");
                    }
                }
                for (int i = 3; i < Math.min(a.size(), 6); i++) {
                    if (!a.get(i).isJsonNull() && !(i == 5 && (payload == null || !payload.isJsonPrimitive()))) {
                        n.add(JsonTree.toNode("[" + i + "]", a.get(i), true));
                    }
                }
                String idx = str(a, 6);
                if (idx != null) n.put("Response tag / index", idx);
                return n;
            }
            case "di" -> {
                DecodedNode n = DecodedNode.object("di");
                n.put("Meaning", "Server processing time (ms)");
                n.put("Value", str(a, 1));
                return n;
            }
            case "af.httprm" -> {
                DecodedNode n = DecodedNode.object("af.httprm");
                n.put("Meaning", "HTTP response metadata (server time ms, request id, …)");
                n.put("Time (ms)", str(a, 1));
                n.put("Request id", str(a, 2));
                n.put("Flag", str(a, 3));
                return n;
            }
            case "e" -> {
                DecodedNode n = DecodedNode.object("e");
                n.put("Meaning", "End of response (entry count, …, byte count)");
                n.add(JsonTree.toNode("Values", a, false));
                return n;
            }
            case "er" -> {
                DecodedNode n = DecodedNode.object("er (error)");
                String code = null;
                for (int i = 1; i < a.size(); i++) {
                    JsonElement e = a.get(i);
                    if (e.isJsonPrimitive() && e.getAsJsonPrimitive().isNumber() && e.getAsDouble() >= 100 && e.getAsDouble() < 600) {
                        code = e.getAsString();
                        break;
                    }
                }
                if (code != null) n.put("HTTP-like status", code);
                n.add(JsonTree.toNode("Values", a, true));
                parts.add("er" + (code == null ? "" : " (error " + code + ")"));
                warnings.add("server returned an error entry (er)" + (code == null ? "" : " with status " + code));
                return n;
            }
            default -> {
                return JsonTree.toNode(tag, a, true);
            }
        }
    }

    private static List<String> dedupe(List<String> parts) {
        return new ArrayList<>(new LinkedHashSet<>(parts));
    }

    static String size(int chars) {
        if (chars < 1024) return chars + " B";
        if (chars < 1024 * 1024) return String.format(Locale.ROOT, "%.1f KB", chars / 1024.0);
        return String.format(Locale.ROOT, "%.1f MB", chars / (1024.0 * 1024));
    }
}
