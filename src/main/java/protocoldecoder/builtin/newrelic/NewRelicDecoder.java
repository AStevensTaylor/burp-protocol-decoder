package protocoldecoder.builtin.newrelic;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.Header;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.ProtocolDecoder;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsLiteral;
import protocoldecoder.util.JsonTree;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * New Relic telemetry: browser agent beacons (bam*.nr-data.net), mobile agent and APM collector traffic, distributed
 * tracing / cross-application headers on any request, and the browser agent configuration embedded in HTML pages.
 */
public final class NewRelicDecoder implements ProtocolDecoder {

    public static final String ID = "newrelic";

    private static final Pattern BEACON_PATH = Pattern.compile("^/(?:(events|jserrors|ins|resources|timing|pvt)/)?1/([^/?]+)");
    private static final Pattern LOADER = Pattern.compile("(?:js-agent\\.newrelic\\.com/)?(nr-(?:loader-)?(?:spa|full|rum|lite)?-?[\\d.]+(?:\\.min)?\\.js)");
    private static final int HTML_SNIFF = 256 * 1024;

    private static final Map<String, String> ENDPOINTS = Map.of(
            "", "Page view (RUM)",
            "events", "Browser interactions / SPA events",
            "jserrors", "JavaScript errors & AJAX metrics",
            "ins", "PageActions / custom events",
            "resources", "Session trace",
            "timing", "Page view timings",
            "pvt", "Page view timings");

    private static final Map<String, String> BROWSER_PARAMS = Map.ofEntries(
            Map.entry("a", "Application ID"),
            Map.entry("v", "Agent version"),
            Map.entry("t", "Transaction name"),
            Map.entry("rst", "Time since page origin (ms)"),
            Map.entry("ck", "Cookies enabled"),
            Map.entry("s", "Session ID"),
            Map.entry("ref", "Page URL"),
            Map.entry("ptid", "Page view trace ID"),
            Map.entry("af", "Enabled features"),
            Map.entry("be", "Back-end time (ms)"),
            Map.entry("fe", "Front-end time (ms)"),
            Map.entry("dc", "DOM content loaded (ms)"),
            Map.entry("perf", "Navigation timing"),
            Map.entry("ja", "Custom attributes"),
            Map.entry("at", "Attributes (obfuscated)"),
            Map.entry("ap", "Application time (ms)"),
            Map.entry("qt", "Queue time (ms)"),
            Map.entry("us", "User"),
            Map.entry("ac", "Account"),
            Map.entry("pr", "Product"),
            Map.entry("xx", "Transaction name (obfuscated)"),
            Map.entry("ua", "User attributes"),
            Map.entry("st", "Start time (epoch ms)"),
            Map.entry("tt", "Trace token"));

    private static final Map<String, String> TRACE_FIELDS = Map.of(
            "ty", "Parent type", "ac", "Account ID", "ap", "Application ID", "tx", "Transaction ID",
            "id", "Span ID", "tr", "Trace ID", "pr", "Priority", "sa", "Sampled", "ti", "Timestamp", "tk", "Trust key");

    private static final Map<String, String> RUM_FLAGS = Map.of(
            "err", "JS errors enabled", "ins", "PageActions enabled", "spa", "SPA interactions enabled",
            "stn", "Session traces enabled", "sts", "Session traces enabled", "sr", "Session replay enabled",
            "cap", "Capture enabled", "loaded", "Loaded", "app", "Application data");

    @Override public String id() { return ID; }
    @Override public String name() { return "New Relic"; }
    @Override public String description() {
        return "New Relic browser/mobile/APM telemetry, distributed-tracing headers and NREUM page configuration";
    }

    // ---------------------------------------------------------------- matching

    enum Channel { BROWSER, MOBILE, APM, OTHER }

    static Channel channel(MessageContext m) {
        String host = m.host().toLowerCase(Locale.ROOT);
        String path = m.path();
        if (host.contains("mobile-collector") || (host.endsWith("nr-data.net") && path.startsWith("/mobile"))) return Channel.MOBILE;
        if ((host.endsWith("newrelic.com") || host.endsWith("nr-data.net")) && path.contains("/agent_listener/")) return Channel.APM;
        if (host.endsWith("nr-data.net")) return Channel.BROWSER;
        return Channel.OTHER;
    }

    @Override
    public MatchResult match(MessageContext m) {
        if (m.isWebSocket()) return MatchResult.NONE;
        Channel ch = channel(m);
        if (m.isRequest()) {
            if (ch != Channel.OTHER) return MatchResult.of(95, "New Relic " + ch.name().toLowerCase(Locale.ROOT) + " endpoint");
            String th = traceHeaderPresent(m.requestHeaders());
            return th == null ? MatchResult.NONE : MatchResult.of(40, th + " header");
        }
        if (ch != Channel.OTHER) return MatchResult.of(85, "response from New Relic endpoint");
        if (m.responseHeader("X-NewRelic-App-Data") != null) return MatchResult.of(40, "X-NewRelic-App-Data header");
        String body = m.responseBodyText();
        String head = body.length() > HTML_SNIFF ? body.substring(0, HTML_SNIFF) : body;
        if (head.contains("NREUM")) return MatchResult.of(30, "NREUM browser agent configuration in page");
        return MatchResult.NONE;
    }

    private static String traceHeaderPresent(List<Header> headers) {
        for (Header h : headers) {
            String n = h.name().toLowerCase(Locale.ROOT);
            if (n.equals("newrelic")) return "newrelic";
            if (n.startsWith("x-newrelic-")) return h.name();
            if (n.equals("tracestate") && h.value().contains("@nr=")) return "tracestate (@nr)";
        }
        return null;
    }

    // ---------------------------------------------------------------- decoding

    @Override
    public DecodeResult decode(MessageContext m) throws DecodeException {
        return m.isResponse() ? decodeResponse(m) : decodeRequest(m);
    }

    private DecodeResult decodeRequest(MessageContext m) throws DecodeException {
        DecodedNode root = DecodedNode.object("New Relic request");
        List<String> warnings = new ArrayList<>();
        Channel ch = channel(m);
        String summary;
        switch (ch) {
            case BROWSER -> summary = decodeBrowserBeacon(m, root, warnings);
            case MOBILE -> summary = decodeMobile(m, root, warnings);
            case APM -> summary = decodeApm(m, root, warnings);
            default -> summary = "Distributed tracing headers";
        }
        DecodedNode trace = traceHeaders(m.requestHeaders());
        if (!trace.isLeaf()) root.add(trace);
        if (root.isLeaf()) throw new DecodeException("No New Relic data found in this request");
        return new DecodeResult(summary, root, null, warnings);
    }

    private String decodeBrowserBeacon(MessageContext m, DecodedNode root, List<String> warnings) {
        DecodedNode ep = root.child("Endpoint");
        Matcher pm = BEACON_PATH.matcher(m.path());
        String type;
        if (pm.find()) {
            String kind = pm.group(1) == null ? "" : pm.group(1);
            type = ENDPOINTS.getOrDefault(kind, kind);
            ep.put("Type", type);
            ep.put("Browser license key", pm.group(2));
        } else if (m.path().startsWith("/browser/blobs")) {
            type = "Session replay blob";
            ep.put("Type", type);
        } else if (m.path().startsWith("/browser/logs")) {
            type = "Browser logs";
            ep.put("Type", type);
        } else {
            type = "Browser beacon";
            ep.put("Type", type);
            ep.put("Path", m.path());
        }
        ep.put("Collector", m.host());

        Map<String, List<String>> q = m.queryParameters();
        if (!q.isEmpty()) {
            DecodedNode qp = root.child("Query parameters");
            for (Map.Entry<String, List<String>> e : q.entrySet()) {
                String label = BROWSER_PARAMS.get(e.getKey());
                for (String v : e.getValue()) {
                    String name = label == null ? e.getKey() : e.getKey() + " — " + label;
                    if (e.getKey().equals("st") && v.matches("\\d{12,14}")) {
                        qp.add(DecodedNode.leaf(name, v + "  (" + Instant.ofEpochMilli(Long.parseLong(v)) + ")"));
                    } else {
                        qp.add(valueNode(name, v));
                    }
                }
            }
        }
        DecodedNode payload = payload(m.requestBody(), m.requestHeader("Content-Encoding"), warnings);
        if (payload != null) root.add(payload);
        String app = Codecs.first(q, "a");
        return "Browser agent → " + type + (app == null ? "" : " (app " + app + ")");
    }

    private String decodeMobile(MessageContext m, DecodedNode root, List<String> warnings) {
        DecodedNode ep = root.child("Endpoint");
        String p = m.path();
        String type = p.contains("/connect") ? "Connect (handshake)" : p.contains("/data") ? "Harvest data"
                : p.endsWith("/f") || p.contains("crash") ? "Crash report" : p;
        ep.put("Type", type);
        ep.put("Collector", m.host());
        DecodedNode hdrs = DecodedNode.object("Agent headers");
        for (Header h : m.requestHeaders()) {
            String n = h.name().toLowerCase(Locale.ROOT);
            if (n.startsWith("x-app-") || n.startsWith("x-newrelic-")) hdrs.put(h.name(), h.value());
        }
        if (!hdrs.isLeaf()) root.add(hdrs);
        DecodedNode payload = payload(m.requestBody(), m.requestHeader("Content-Encoding"), warnings);
        if (payload != null) root.add(payload);
        return "Mobile agent → " + type;
    }

    private String decodeApm(MessageContext m, DecodedNode root, List<String> warnings) {
        Map<String, List<String>> q = m.queryParameters();
        String method = Codecs.first(q, "method");
        DecodedNode call = root.child("Collector call");
        call.put("Method", method);
        call.put("License key", Codecs.first(q, "license_key"));
        call.put("Protocol version", Codecs.first(q, "protocol_version"));
        call.put("Marshal format", Codecs.first(q, "marshal_format"));
        call.put("Run ID", Codecs.first(q, "run_id"));
        DecodedNode payload = payload(m.requestBody(), m.requestHeader("Content-Encoding"), warnings);
        if (payload != null) root.add(payload);
        return "APM agent → " + (method == null ? "collector" : method);
    }

    /** Decompresses (gzip/deflate) and parses a telemetry body (JSON, BEL, urlencoded or raw). */
    static DecodedNode payload(byte[] body, String contentEncoding, List<String> warnings) {
        if (body == null || body.length == 0) return null;
        byte[] data = Codecs.decodeContent(body, contentEncoding);
        DecodedNode n = DecodedNode.object("Payload");
        if (data != body) n.put("Compressed size", body.length).put("Decompressed size", data.length);
        if (!Codecs.isMostlyText(data)) {
            n.add(DecodedNode.leaf("Binary", Codecs.hexPreview(data, 256), DecodedNode.Type.BINARY));
            warnings.add("Payload is binary" + (contentEncoding == null ? "" : " (Content-Encoding: " + contentEncoding + ")"));
            return n;
        }
        String text = Codecs.utf8(data).strip();
        JsonElement json = JsonTree.parseStrict(text);
        if (json != null) {
            n.add(JsonTree.toNode("Body", json, true));
        } else if (text.startsWith("bel.")) {
            n.add(Bel.decode(text));
            warnings.add("BEL (browser event list) payload decoded structurally; field meanings are not documented");
        } else if (text.contains("=") && !text.contains(" ") && !text.contains("\n")) {
            DecodedNode form = n.child("Form parameters");
            Codecs.parseQuery(text).forEach((k, vs) -> vs.forEach(v -> form.add(valueNode(k, v))));
        } else {
            n.add(DecodedNode.leaf("Body", text));
        }
        return n;
    }

    // ---------------------------------------------------------------- trace headers

    static DecodedNode traceHeaders(List<Header> headers) {
        DecodedNode n = DecodedNode.object("Tracing headers");
        for (Header h : headers) {
            String name = h.name().toLowerCase(Locale.ROOT);
            switch (name) {
                case "newrelic" -> n.add(newrelicHeader(h.value()));
                case "traceparent" -> n.add(traceparent(h.value()));
                case "tracestate" -> n.add(tracestate(h.value()));
                default -> {
                    if (name.startsWith("x-newrelic-")) n.add(obfuscatedHeader(h.name(), h.value()));
                }
            }
        }
        return n;
    }

    static DecodedNode newrelicHeader(String value) {
        DecodedNode n = DecodedNode.object("newrelic (distributed trace payload)");
        n.put("Raw", value);
        byte[] raw = Codecs.base64Decode(value);
        JsonElement json = raw == null ? null : JsonTree.parseStrict(Codecs.utf8(raw));
        if (json == null || !json.isJsonObject()) {
            n.add(DecodedNode.note("not base64-encoded JSON"));
            return n;
        }
        JsonObject o = json.getAsJsonObject();
        if (o.has("v")) n.put("Version", o.get("v").toString());
        if (o.has("d") && o.get("d").isJsonObject()) {
            DecodedNode d = n.child("Data");
            for (Map.Entry<String, JsonElement> e : o.getAsJsonObject("d").entrySet()) {
                String label = TRACE_FIELDS.get(e.getKey());
                String v = e.getValue().isJsonPrimitive() ? e.getValue().getAsString() : e.getValue().toString();
                if (e.getKey().equals("ti") && v.matches("\\d{12,14}")) v += "  (" + Instant.ofEpochMilli(Long.parseLong(v)) + ")";
                d.add(DecodedNode.leaf(label == null ? e.getKey() : e.getKey() + " — " + label, v));
            }
        }
        return n;
    }

    static DecodedNode traceparent(String value) {
        DecodedNode n = DecodedNode.object("traceparent (W3C)");
        n.put("Raw", value);
        String[] p = value.trim().split("-");
        if (p.length >= 4) {
            n.put("Version", p[0]).put("Trace ID", p[1]).put("Parent span ID", p[2]);
            try {
                int flags = Integer.parseInt(p[3], 16);
                n.put("Flags", p[3] + ((flags & 1) == 1 ? " (sampled)" : " (not sampled)"));
            } catch (NumberFormatException e) {
                n.put("Flags", p[3]);
            }
        }
        return n;
    }

    static DecodedNode tracestate(String value) {
        DecodedNode n = DecodedNode.object("tracestate (W3C)");
        for (String member : value.split(",")) {
            String mbr = member.trim();
            int eq = mbr.indexOf('=');
            if (eq <= 0) continue;
            String key = mbr.substring(0, eq), v = mbr.substring(eq + 1);
            if (key.endsWith("@nr")) {
                DecodedNode nr = n.child(key + " (New Relic, trust key " + key.substring(0, key.length() - 3) + ")");
                String[] f = v.split("-", -1);
                String[] names = {"Version", "Parent type", "Account ID", "Application ID", "Span ID", "Transaction ID", "Sampled", "Priority", "Timestamp"};
                for (int i = 0; i < f.length && i < names.length; i++) {
                    String fv = f[i];
                    if (i == 1) fv = fv + switch (fv) { case "0" -> " (App)"; case "1" -> " (Browser)"; case "2" -> " (Mobile)"; default -> ""; };
                    if (i == 6) fv = fv + ("1".equals(f[i]) ? " (true)" : "0".equals(f[i]) ? " (false)" : "");
                    if (i == 8 && fv.matches("\\d{12,14}")) fv += "  (" + Instant.ofEpochMilli(Long.parseLong(fv)) + ")";
                    if (!f[i].isEmpty()) nr.put(names[i], fv);
                }
            } else {
                n.put(key, v);
            }
        }
        return n;
    }

    static DecodedNode obfuscatedHeader(String name, String value) {
        DecodedNode n = DecodedNode.object(name);
        n.put("Raw", value);
        byte[] raw = Codecs.base64Decode(value);
        if (raw == null) return n;
        String text = Codecs.utf8(raw);
        JsonElement json = JsonTree.parseStrict(text);
        if (json != null) {
            n.add(JsonTree.toNode("Decoded", json, true));
        } else if (Codecs.isMostlyText(raw) && text.chars().allMatch(c -> c >= 0x20 && c < 0x7f)) {
            n.put("Decoded", text);
        } else {
            n.add(DecodedNode.leaf("Base64-decoded", Codecs.hexPreview(raw, 64), DecodedNode.Type.BINARY));
            n.add(DecodedNode.note("XOR-obfuscated with the account's cross-process encoding key"));
        }
        return n;
    }

    // ---------------------------------------------------------------- responses

    private DecodeResult decodeResponse(MessageContext m) throws DecodeException {
        DecodedNode root = DecodedNode.object("New Relic response");
        List<String> warnings = new ArrayList<>();
        Channel ch = channel(m);
        String summary = null;

        String appData = m.responseHeader("X-NewRelic-App-Data");
        if (appData != null) root.add(obfuscatedHeader("X-NewRelic-App-Data", appData));

        if (ch != Channel.OTHER) {
            byte[] data = Codecs.decodeContent(m.responseBody(), m.responseHeader("Content-Encoding"));
            String text = Codecs.utf8(data).strip();
            JsonElement json = JsonTree.parseLenient(text);
            String jsonp = null;
            if (json == null) {
                int brace = text.indexOf('{');
                if (brace >= 0) {
                    int end = JsLiteral.matchBracket(text, brace);
                    if (end > 0) {
                        jsonp = text.substring(0, brace).replace("(", "").trim();
                        json = JsonTree.parseLenient(text.substring(brace, end));
                    }
                }
            }
            if (json != null) {
                DecodedNode body = JsonTree.toNode(jsonp == null || jsonp.isEmpty() ? "Body" : "Body (" + jsonp + ")", json, true);
                root.add(body);
                if (json.isJsonObject()) {
                    DecodedNode flags = DecodedNode.object("Feature flags");
                    for (Map.Entry<String, JsonElement> e : json.getAsJsonObject().entrySet()) {
                        String label = RUM_FLAGS.get(e.getKey());
                        if (label != null && e.getValue().isJsonPrimitive()) flags.put(label + " (" + e.getKey() + ")", e.getValue().getAsString());
                    }
                    if (!flags.isLeaf() && ch == Channel.BROWSER) root.add(flags);
                }
            } else if (!text.isEmpty()) {
                root.add(DecodedNode.leaf("Body", text));
            }
            summary = "Collector response (" + m.statusCode() + ")";
        } else {
            String body = m.responseBodyText();
            String head = body.length() > HTML_SNIFF ? body.substring(0, HTML_SNIFF) : body;
            DecodedNode cfg = nreumConfig(head);
            if (cfg != null) {
                root.add(cfg);
                summary = "Browser agent configuration";
                DecodedNode info = cfg.get("NREUM.info");
                if (info != null) {
                    DecodedNode app = info.get("applicationID");
                    if (app != null) summary += " (app " + app.value() + ")";
                }
            }
        }
        if (root.isLeaf()) throw new DecodeException("No New Relic data found in this response");
        if (summary == null) summary = "Cross-application tracing header";
        return new DecodeResult(summary, root, null, warnings);
    }

    /** Extracts NREUM.init / NREUM.loader_config / NREUM.info literals from page HTML or script. */
    static DecodedNode nreumConfig(String text) {
        DecodedNode n = DecodedNode.object("Browser agent (NREUM)");
        for (String name : new String[]{"NREUM.info", "NREUM.init", "NREUM.loader_config"}) {
            String lit = JsLiteral.findAssignedLiteral(text, name, 0);
            if (lit == null) continue;
            JsonElement e = JsonTree.parseLenient(lit);
            n.add(e == null ? DecodedNode.leaf(name, lit) : JsonTree.toNode(name, e, false));
        }
        Matcher lm = LOADER.matcher(text);
        if (lm.find()) n.put("Agent script", lm.group(1));
        return n.isLeaf() ? null : n;
    }

    /** Leaf, or parsed JSON subtree when the value is JSON. */
    static DecodedNode valueNode(String name, String v) {
        if (JsonTree.looksLikeJson(v)) {
            JsonElement e = JsonTree.parseLenient(v);
            if (e != null) return JsonTree.toNode(name, e, true);
        }
        return DecodedNode.leaf(name, v);
    }
}
