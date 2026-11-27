package protocoldecoder.builtin.blazor;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.ProtocolDecoder;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Blazor: Blazor Server / Blazor Web App circuits over SignalR (WebSocket frames, long polling, negotiate and
 * disconnect calls) in the MessagePack ("blazorpack") or JSON hub protocol, including render batches; plus Blazor
 * WebAssembly boot manifests and the Blazor markers/state embedded in prerendered HTML. Generic SignalR hubs are
 * recognised with lower confidence.
 */
public final class BlazorDecoder implements ProtocolDecoder {

    public static final String ID = "blazor";

    private static final Pattern HTML_MARKER = Pattern.compile("<!--(Blazor(?:-[A-Za-z]+)*):(.*?)-->", Pattern.DOTALL);
    private static final int HTML_SNIFF = 1024 * 1024;
    private static final Map<String, String> NEGOTIATE_FIELDS = Map.of(
            "connectionId", "Connection ID (public)",
            "connectionToken", "Connection token (the ?id= of later requests)",
            "negotiateVersion", "Negotiate protocol version",
            "availableTransports", "Transports the server offers",
            "url", "Redirect URL",
            "accessToken", "Access token (redirect)");

    @Override public String id() { return ID; }
    @Override public String name() { return "Blazor / SignalR"; }
    @Override public String description() {
        return "Blazor Server circuits over SignalR (blazorpack/JSON, render batches), negotiate/disconnect, WebAssembly boot manifest, prerendered HTML markers";
    }

    // ---------------------------------------------------------------- matching

    private static boolean blazorHub(MessageContext m) {
        String p = m.path().toLowerCase(Locale.ROOT);
        return p.endsWith("/_blazor") || p.contains("/_blazor/");
    }

    private static boolean longPolling(MessageContext m) {
        return m.path().toLowerCase(Locale.ROOT).endsWith("/_blazor") && m.query().contains("id=");
    }

    @Override
    public MatchResult match(MessageContext m) {
        String path = m.path().toLowerCase(Locale.ROOT);
        if (m.isWebSocket()) {
            if (blazorHub(m)) return MatchResult.of(90, "WebSocket on the Blazor hub (/_blazor)");
            byte[] p = m.body();
            if (SignalR.isTextRecords(p)) {
                String t = Codecs.utf8(p);
                if (t.contains("\"protocol\"") || t.contains("\"type\"")) return MatchResult.of(60, "SignalR JSON hub messages");
            }
            if (SignalR.looksLikeMessagePackHub(p)) return MatchResult.of(50, "SignalR MessagePack hub messages");
            return MatchResult.NONE;
        }
        if (path.endsWith("/_blazor/negotiate")) return MatchResult.of(90, "Blazor SignalR negotiate");
        if (path.endsWith("/_blazor/disconnect")) return MatchResult.of(90, "Blazor circuit disconnect");
        if (path.endsWith("/negotiate") && m.query().contains("negotiateVersion=")) return MatchResult.of(55, "SignalR negotiate");
        if (longPolling(m)) {
            boolean hasBody = m.isRequest() ? m.requestBody().length > 0 : m.responseBody().length > 0;
            return hasBody ? MatchResult.of(90, "Blazor SignalR long polling") : MatchResult.NONE;
        }
        if (m.isResponse()) {
            if (path.endsWith("/_framework/blazor.boot.json")) return MatchResult.of(85, "Blazor WebAssembly boot manifest");
            String body = m.responseBodyText();
            String head = body.length() > HTML_SNIFF ? body.substring(0, HTML_SNIFF) : body;
            if (head.contains("<!--Blazor")) return MatchResult.of(50, "Blazor markers in prerendered HTML");
        }
        return MatchResult.NONE;
    }

    // ---------------------------------------------------------------- decoding

    @Override
    public DecodeResult decode(MessageContext m) throws DecodeException {
        String path = m.path().toLowerCase(Locale.ROOT);
        if (m.isWebSocket()) return hubPayload(m, m.body(), "WebSocket " + direction(m));
        if (path.endsWith("/negotiate")) return negotiate(m);
        if (path.endsWith("/_blazor/disconnect") && m.isRequest()) return disconnect(m);
        if (longPolling(m) || blazorHub(m)) {
            return hubPayload(m, m.isRequest() ? m.requestBody() : Codecs.decodeContent(m.responseBody(), m.responseHeader("Content-Encoding")),
                    m.isRequest() ? "Long polling send" : "Long polling poll");
        }
        if (m.isResponse() && path.endsWith("/_framework/blazor.boot.json")) return bootManifest(m);
        if (m.isResponse()) {
            DecodeResult r = htmlMarkers(m);
            if (r != null) return r;
        }
        // Forced via a rule/override on something else: try it as hub messages.
        return hubPayload(m, m.body(), "Hub payload");
    }

    private static String direction(MessageContext m) {
        String d = m.webSocketDirection();
        if ("CLIENT_TO_SERVER".equals(d)) return "client → server";
        if ("SERVER_TO_CLIENT".equals(d)) return "server → client";
        return "message";
    }

    private DecodeResult hubPayload(MessageContext m, byte[] payload, String what) throws DecodeException {
        if (payload == null || payload.length == 0) throw new DecodeException("Empty payload");
        List<SignalR.Message> msgs = SignalR.decodePayload(payload);
        if (msgs.isEmpty()) throw new DecodeException("No SignalR messages found");
        DecodedNode root = DecodedNode.object("Blazor");
        String connection = Codecs.first(m.queryParameters(), "id");
        if (connection != null) root.put("Connection token (?id=)", connection);
        DecodedNode list = DecodedNode.array("Messages");
        List<String> labels = new ArrayList<>();
        boolean unknown = false;
        for (SignalR.Message x : msgs) {
            list.add(x.node());
            labels.add(x.label());
            unknown |= x.label().equals("unrecognised") || x.label().equals("invalid");
        }
        root.add(list);
        List<String> warnings = unknown ? List.of("Part of the payload is not valid SignalR framing") : List.of();
        return new DecodeResult(what + ": " + summarize(labels), root, null, warnings);
    }

    /** "JS.RenderBatch #3 (…)" or "4 messages: Ping, JS.RenderBatch ×2, Completion". */
    static String summarize(List<String> labels) {
        if (labels.size() == 1) return labels.get(0);
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String l : labels) {
            String key = l.replaceAll(" #\\d+.*| \\(.*", "");
            counts.merge(key, 1, Integer::sum);
        }
        StringBuilder sb = new StringBuilder(labels.size() + " messages: ");
        int i = 0;
        for (Map.Entry<String, Integer> e : counts.entrySet()) {
            if (i++ > 0) sb.append(", ");
            sb.append(e.getKey());
            if (e.getValue() > 1) sb.append(" ×").append(e.getValue());
        }
        return sb.toString();
    }

    private DecodeResult negotiate(MessageContext m) throws DecodeException {
        DecodedNode root = DecodedNode.object("SignalR negotiate");
        if (m.isRequest()) {
            DecodedNode q = root.child("Query");
            m.queryParameters().forEach((k, v) -> v.forEach(x -> q.put(k, x)));
            return DecodeResult.of("Negotiate request (version " + Codecs.first(m.queryParameters(), "negotiateVersion") + ")", root);
        }
        JsonElement e = JsonTree.parseStrict(Codecs.utf8(Codecs.decodeContent(m.responseBody(), m.responseHeader("Content-Encoding"))));
        if (e == null || !e.isJsonObject()) throw new DecodeException("Negotiate response is not JSON");
        JsonObject o = e.getAsJsonObject();
        for (Map.Entry<String, JsonElement> en : o.entrySet()) {
            String label = NEGOTIATE_FIELDS.get(en.getKey());
            if (en.getKey().equals("availableTransports") && en.getValue().isJsonArray()) {
                DecodedNode t = DecodedNode.array("availableTransports — " + label);
                for (JsonElement tr : en.getValue().getAsJsonArray()) {
                    if (tr.isJsonObject() && tr.getAsJsonObject().has("transport")) {
                        JsonObject to = tr.getAsJsonObject();
                        t.add(DecodedNode.leaf("", to.get("transport").getAsString() + (to.has("transferFormats") ? "  " + to.get("transferFormats") : "")));
                    } else {
                        t.add(JsonTree.toNode("", tr, false));
                    }
                }
                root.add(t);
            } else {
                root.add(JsonTree.toNode(label == null ? en.getKey() : en.getKey() + " — " + label, en.getValue(), false));
            }
        }
        String summary = "Negotiate response" + (o.has("connectionId") ? " (connection " + o.get("connectionId").getAsString() + ")" : "");
        if (o.has("error")) summary = "Negotiate error: " + o.get("error").getAsString();
        return DecodeResult.of(summary, root);
    }

    private DecodeResult disconnect(MessageContext m) {
        DecodedNode root = DecodedNode.object("Blazor disconnect");
        Map<String, List<String>> form = Codecs.parseQuery(m.requestBodyText());
        form.forEach((k, v) -> v.forEach(x -> root.put(k.equals("circuitId") ? "circuitId — Circuit ID (Data Protection–protected)" : k, x)));
        return DecodeResult.of("Circuit disconnect", root);
    }

    private DecodeResult bootManifest(MessageContext m) throws DecodeException {
        JsonElement e = JsonTree.parseStrict(Codecs.utf8(Codecs.decodeContent(m.responseBody(), m.responseHeader("Content-Encoding"))));
        if (e == null) throw new DecodeException("blazor.boot.json is not valid JSON");
        DecodedNode root = DecodedNode.object("Blazor WebAssembly boot manifest");
        root.add(JsonTree.toNode("Manifest", e, false));
        String summary = "WebAssembly boot manifest";
        if (e.isJsonObject()) {
            JsonObject o = e.getAsJsonObject();
            if (o.has("mainAssemblyName")) summary += " — " + o.get("mainAssemblyName").getAsString();
            else if (o.has("entryAssembly")) summary += " — " + o.get("entryAssembly").getAsString();
            if (o.has("debugBuild") && o.get("debugBuild").isJsonPrimitive() && o.get("debugBuild").getAsBoolean()) summary += " (debug build)";
            int assemblies = countAssemblies(o);
            if (assemblies > 0) summary += ", " + assemblies + " assemblies";
        }
        return DecodeResult.of(summary, root);
    }

    private static int countAssemblies(JsonObject o) {
        if (!o.has("resources") || !o.get("resources").isJsonObject()) return 0;
        JsonObject r = o.getAsJsonObject("resources");
        int n = 0;
        for (String k : new String[]{"assembly", "coreAssembly"}) {
            JsonElement a = r.get(k);
            if (a != null && a.isJsonObject()) n += a.getAsJsonObject().size();
            else if (a != null && a.isJsonArray()) n += a.getAsJsonArray().size();
        }
        return n;
    }

    private DecodeResult htmlMarkers(MessageContext m) {
        String body = m.responseBodyText();
        String head = body.length() > HTML_SNIFF ? body.substring(0, HTML_SNIFF) : body;
        Matcher mm = HTML_MARKER.matcher(head);
        DecodedNode root = DecodedNode.object("Blazor page markers");
        DecodedNode components = DecodedNode.array("Prerendered components");
        int count = 0;
        while (mm.find() && count < 500) {
            count++;
            String kind = mm.group(1);
            String value = mm.group(2).strip();
            switch (kind) {
                case "Blazor" -> {
                    JsonElement e = JsonTree.parseLenient(value);
                    DecodedNode c = e == null ? DecodedNode.leaf("[" + components.children().size() + "]", value)
                            : JsonTree.toNode("[" + components.children().size() + "]" + typeOf(e), e, true);
                    components.add(c);
                }
                case "Blazor-WebAssembly-Component-State", "Blazor-Web-Initializers", "Blazor-Web-Initializers-State" ->
                        root.add(base64Json(kind, value));
                case "Blazor-Server-Component-State" -> {
                    DecodedNode n = root.child(kind);
                    n.put("Raw", Codecs.truncate(value, 400));
                    n.add(DecodedNode.note("protected with ASP.NET Core Data Protection; not readable without the server's keys"));
                }
                default -> root.put(kind, Codecs.truncate(value, 2000));
            }
        }
        if (!components.isLeaf()) root.add(components);
        if (root.isLeaf()) return null;
        String summary = "Prerendered page: " + components.children().size() + " component marker" + (components.children().size() == 1 ? "" : "s");
        List<String> warnings = new ArrayList<>();
        if (root.get("Blazor-WebAssembly-Component-State") != null) {
            warnings.add("WebAssembly persisted component state is plain base64, readable by anyone who sees the page");
        }
        return new DecodeResult(summary, root, null, warnings);
    }

    private static String typeOf(JsonElement e) {
        if (e.isJsonObject() && e.getAsJsonObject().has("type")) return " " + e.getAsJsonObject().get("type").getAsString();
        return "";
    }

    /** Base64 → JSON; values that are themselves base64-encoded JSON (persisted state) are expanded too. */
    private static DecodedNode base64Json(String name, String value) {
        byte[] raw = Codecs.base64Decode(value);
        if (raw == null) return DecodedNode.leaf(name, value);
        JsonElement e = JsonTree.parseStrict(Codecs.utf8(raw));
        if (e == null) return DecodedNode.leaf(name + " (base64-decoded)", Codecs.utf8(raw));
        if (e.isJsonObject()) {
            DecodedNode n = DecodedNode.object(name);
            for (Map.Entry<String, JsonElement> en : e.getAsJsonObject().entrySet()) {
                JsonElement v = en.getValue();
                if (v.isJsonPrimitive() && v.getAsJsonPrimitive().isString()) {
                    byte[] inner = Codecs.base64Decode(v.getAsString());
                    JsonElement ij = inner == null ? null : JsonTree.parseStrict(Codecs.utf8(inner));
                    if (ij != null) {
                        n.add(JsonTree.toNode(en.getKey() + " (base64 JSON)", ij, true));
                        continue;
                    }
                }
                n.add(JsonTree.toNode(en.getKey(), v, true));
            }
            return n;
        }
        return JsonTree.toNode(name, e, true);
    }
}
