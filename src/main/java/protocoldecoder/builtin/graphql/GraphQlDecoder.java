package protocoldecoder.builtin.graphql;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import static protocoldecoder.builtin.graphql.GraphQlOperations.arr;
import static protocoldecoder.builtin.graphql.GraphQlOperations.obj;
import static protocoldecoder.builtin.graphql.GraphQlOperations.str;

/**
 * GraphQL over HTTP (POST JSON, batched arrays, GET parameters, application/graphql bodies, multipart uploads,
 * automatic persisted queries), its responses (including introspection schemas, SSE and incremental multipart
 * delivery) and GraphQL over WebSocket (graphql-transport-ws and the legacy subscriptions-transport-ws protocol).
 */
public final class GraphQlDecoder implements ProtocolDecoder {

    public static final String ID = "graphql";

    static final int SNIFF = 64 * 1024;
    static final int MAX_MATCH_PARSE = 4 * 1024 * 1024;
    static final int MAX_BATCH = 1000;
    static final int MAX_EVENTS = 2000;

    enum WsProtocol {
        TRANSPORT_WS("graphql-transport-ws"), LEGACY("subscriptions-transport-ws (graphql-ws)");
        final String label;
        WsProtocol(String label) { this.label = label; }
    }

    private static final Set<String> NEW_TYPES = Set.of("connection_init", "connection_ack", "ping", "pong", "subscribe", "next", "error", "complete");
    private static final Set<String> LEGACY_TYPES = Set.of("connection_init", "connection_ack", "connection_error", "ka", "connection_keep_alive",
            "connection_terminate", "start", "start_ack", "data", "error", "complete", "stop");
    private static final Map<String, String> WS_TYPES = new LinkedHashMap<>();

    static {
        WS_TYPES.put("connection_init", "Client opens the GraphQL session (payload = connection params, often auth)");
        WS_TYPES.put("connection_ack", "Server accepted the connection");
        WS_TYPES.put("connection_error", "Server rejected the connection");
        WS_TYPES.put("connection_terminate", "Client closes the session");
        WS_TYPES.put("ka", "Keep-alive");
        WS_TYPES.put("connection_keep_alive", "Keep-alive");
        WS_TYPES.put("ping", "Ping");
        WS_TYPES.put("pong", "Pong");
        WS_TYPES.put("subscribe", "Client starts an operation");
        WS_TYPES.put("start", "Client starts an operation");
        WS_TYPES.put("start_ack", "Server acknowledged the operation");
        WS_TYPES.put("next", "Operation result");
        WS_TYPES.put("data", "Operation result");
        WS_TYPES.put("error", "Operation failed");
        WS_TYPES.put("complete", "Operation finished");
        WS_TYPES.put("stop", "Client stops the operation");
    }

    @Override public String id() { return ID; }
    @Override public String name() { return "GraphQL"; }
    @Override public String description() {
        return "GraphQL over HTTP (JSON, batch, GET, application/graphql, multipart uploads, persisted queries), responses "
                + "incl. introspection, and GraphQL over WebSocket (graphql-transport-ws, subscriptions-transport-ws)";
    }

    // ================================================================== matching

    @Override
    public MatchResult match(MessageContext m) {
        try {
            return switch (m.kind()) {
                case REQUEST -> matchRequest(m);
                case RESPONSE -> matchResponse(m);
                case WEBSOCKET -> matchWebSocket(m);
            };
        } catch (RuntimeException e) {
            return MatchResult.NONE;
        }
    }

    /** Uses only the request side of the context, so it also serves response matching. */
    static MatchResult matchRequest(MessageContext m) {
        String q = m.query();
        if (q.contains("query=") || q.contains("extensions=")) {
            Map<String, List<String>> params = m.queryParameters();
            if (GraphQlDocument.isLikelyDocument(Codecs.first(params, "query"))) return MatchResult.of(95, "GraphQL query in URL parameters");
            String ext = Codecs.first(params, "extensions");
            if (ext != null && ext.contains("persistedQuery") && ext.contains("sha256Hash")) {
                return MatchResult.of(90, "GraphQL persisted query hash in URL parameters");
            }
        }
        byte[] body = m.requestBody();
        if (body.length == 0) return MatchResult.NONE;
        String ct = m.requestContentType().toLowerCase(Locale.ROOT);
        String head = head(body);
        if (ct.contains("multipart/form-data")) {
            return head.contains("name=\"operations\"") ? MatchResult.of(90, "GraphQL multipart upload (operations + map)") : MatchResult.NONE;
        }
        if (isGraphQlContentType(ct)) {
            return GraphQlDocument.isLikelyDocument(head) ? MatchResult.of(95, "application/graphql body")
                    : MatchResult.of(60, "application/graphql content type");
        }
        if (ct.contains("x-www-form-urlencoded")) {
            if (!head.contains("query=")) return MatchResult.NONE;
            String query = Codecs.first(Codecs.parseQuery(m.requestBodyText()), "query");
            return GraphQlDocument.isLikelyDocument(query) ? MatchResult.of(90, "GraphQL query in form body") : MatchResult.NONE;
        }
        String t = head.stripLeading();
        if ((t.startsWith("{") || t.startsWith("[")) && (head.contains("\"query\"") || head.contains("persistedQuery"))) {
            if (body.length > MAX_MATCH_PARSE) {
                return graphQlPath(m) ? MatchResult.of(60, "Large JSON body with a query field on a GraphQL endpoint (not verified)") : MatchResult.NONE;
            }
            JsonElement e = JsonTree.parseStrict(m.requestBodyText());
            if (e == null) return MatchResult.NONE;
            if (e.isJsonArray()) {
                JsonArray a = e.getAsJsonArray();
                if (a.isEmpty() || a.size() > MAX_BATCH) return MatchResult.NONE;
                for (JsonElement x : a) if (!GraphQlOperations.isOperation(x)) return MatchResult.NONE;
                return MatchResult.of(95, "GraphQL batch of " + a.size() + " operations");
            }
            if (GraphQlOperations.isOperation(e)) {
                return str(e.getAsJsonObject(), "query") != null ? MatchResult.of(95, "GraphQL JSON request")
                        : MatchResult.of(90, "GraphQL automatic persisted query (hash only)");
            }
            return MatchResult.NONE;
        }
        if (graphQlPath(m) && GraphQlDocument.isLikelyDocument(head)) return MatchResult.of(80, "GraphQL document body on a GraphQL endpoint");
        return MatchResult.NONE;
    }

    private MatchResult matchResponse(MessageContext m) {
        byte[] body = responseBody(m);
        if (body.length == 0) return MatchResult.NONE;
        String ct = lower(m.responseHeader("Content-Type"));
        String head = head(body);
        String t = head.stripLeading();
        boolean json = t.startsWith("{") || t.startsWith("[");
        boolean hasKeys = head.contains("\"data\"") || head.contains("\"errors\"");
        if (ct.contains("application/graphql-response+json") && json) return MatchResult.of(95, "application/graphql-response+json");
        boolean reqGql = matchRequest(m).confidence() >= 60;
        if (reqGql) {
            if (json && hasKeys) return MatchResult.of(90, "Response to a GraphQL request");
            if (ct.contains("text/event-stream") || ct.contains("multipart/mixed")) return MatchResult.of(85, "Streamed response to a GraphQL request");
            return MatchResult.NONE;
        }
        if (!json || !hasKeys || body.length > MAX_MATCH_PARSE) return MatchResult.NONE;
        JsonElement e = JsonTree.parseStrict(new String(body, StandardCharsets.UTF_8));
        if (e == null) return MatchResult.NONE;
        if (e.isJsonArray()) {
            JsonArray a = e.getAsJsonArray();
            if (a.isEmpty() || !graphQlPath(m)) return MatchResult.NONE;
            for (JsonElement x : a) if (!GraphQlOperations.isResult(x)) return MatchResult.NONE;
            return MatchResult.of(70, "Batch of GraphQL results on a GraphQL endpoint");
        }
        if (!GraphQlOperations.isResult(e)) return MatchResult.NONE;
        JsonObject o = e.getAsJsonObject();
        if (obj(obj(o, "data"), "__schema") != null) return MatchResult.of(85, "GraphQL introspection result");
        if (graphQlPath(m)) return MatchResult.of(75, "GraphQL result on a GraphQL endpoint");
        JsonArray errs = arr(o, "errors");
        if (errs != null && !errs.isEmpty() && errs.get(0).isJsonObject()) {
            JsonObject f = errs.get(0).getAsJsonObject();
            if (f.has("message") && (f.has("locations") || f.has("path"))) return MatchResult.of(60, "GraphQL-style errors (message + locations/path)");
        }
        return MatchResult.NONE;
    }

    private MatchResult matchWebSocket(MessageContext m) {
        byte[] p = m.body();
        if (p.length == 0) return MatchResult.NONE;
        String head = head(p);
        if (!head.stripLeading().startsWith("{") || !head.contains("\"type\"")) return MatchResult.NONE;
        WsProtocol proto = protocolFromHeaders(m);
        if (p.length > MAX_MATCH_PARSE) {
            return proto != null ? MatchResult.of(70, "Large message on a " + proto.label + " WebSocket") : MatchResult.NONE;
        }
        JsonElement e = JsonTree.parseStrict(m.bodyText());
        if (e == null || !e.isJsonObject()) return MatchResult.NONE;
        JsonObject o = e.getAsJsonObject();
        String type = str(o, "type");
        if (type == null || !WS_TYPES.containsKey(type)) return MatchResult.NONE;
        if (proto != null && typesOf(proto).contains(type)) return MatchResult.of(95, "GraphQL over WebSocket (" + proto.label + ")");
        JsonElement payload = o.get("payload");
        boolean hasId = o.has("id");
        return switch (type) {
            case "subscribe", "start" -> GraphQlOperations.isOperation(payload)
                    ? MatchResult.of(90, "GraphQL WebSocket " + type + " with a GraphQL document") : MatchResult.NONE;
            case "next", "data" -> hasId && payload != null && (GraphQlOperations.isResult(payload) || appSyncData(payload) != null)
                    ? MatchResult.of(80, "GraphQL WebSocket result message") : MatchResult.NONE;
            case "connection_init", "connection_ack", "connection_error", "ka", "connection_keep_alive", "connection_terminate", "start_ack" ->
                    onlyKeys(o, "type", "payload", "id") ? MatchResult.of(60, "GraphQL WebSocket " + type) : MatchResult.NONE;
            case "error" -> hasId && payload != null && payload.isJsonArray() && GraphQlOperations.isErrorList(payload.getAsJsonArray())
                    ? MatchResult.of(60, "GraphQL WebSocket error") : MatchResult.NONE;
            case "complete", "stop" -> hasId && onlyKeys(o, "type", "id", "payload") ? MatchResult.of(30, "GraphQL-style WebSocket " + type) : MatchResult.NONE;
            case "ping", "pong" -> onlyKeys(o, "type", "payload") ? MatchResult.of(25, "graphql-transport-ws-style " + type) : MatchResult.NONE;
            default -> MatchResult.NONE;
        };
    }

    // ================================================================== decoding

    @Override
    public DecodeResult decode(MessageContext m) throws DecodeException {
        try {
            return switch (m.kind()) {
                case REQUEST -> decodeRequest(m);
                case RESPONSE -> decodeResponse(m);
                case WEBSOCKET -> decodeWebSocket(m);
            };
        } catch (RuntimeException e) {
            throw new DecodeException("GraphQL decoding failed: " + e, e);
        }
    }

    // ------------------------------------------------------------------ requests

    private DecodeResult decodeRequest(MessageContext m) throws DecodeException {
        List<String> warnings = new ArrayList<>();
        DecodedNode root = DecodedNode.object("GraphQL request");
        String ct = m.requestContentType().toLowerCase(Locale.ROOT);
        byte[] body = m.requestBody();
        JsonElement ops = null;
        String transport = null;
        DecodedNode uploads = null;

        if (body.length > 0) {
            if (ct.contains("multipart/form-data")) {
                uploads = DecodedNode.array("Uploads");
                ops = multipartOperations(m, uploads, warnings);
                transport = "multipart upload (graphql-multipart-request-spec)";
            } else if (isGraphQlContentType(ct) || GraphQlDocument.isLikelyDocument(head(body))) {
                JsonObject o = new JsonObject();
                o.addProperty("query", m.requestBodyText());
                ops = o;
                transport = "POST " + (isGraphQlContentType(ct) ? "application/graphql" : "raw GraphQL") + " body";
            } else if (ct.contains("x-www-form-urlencoded")) {
                ops = fromParams(Codecs.parseQuery(m.requestBodyText()), warnings);
                transport = "form-encoded body";
            } else {
                JsonElement e = JsonTree.parseStrict(m.requestBodyText());
                if (e != null && (e.isJsonObject() || e.isJsonArray())) {
                    if (looksLikeOperations(e)) {
                        ops = e;
                        transport = m.method() + " JSON body";
                    } else if (!hasParamOperation(m)) {
                        throw new DecodeException("JSON body is not a GraphQL operation (no query document or persisted query hash)");
                    }
                }
            }
        }
        if (ops == null && hasParamOperation(m)) {
            ops = fromParams(m.queryParameters(), warnings);
            transport = m.method() + " URL parameters";
        }
        if (ops == null) {
            throw new DecodeException("Not a GraphQL request: no query document, persisted query or GraphQL JSON body found");
        }
        root.put("Transport", transport);

        String summary;
        String text;
        if (ops.isJsonArray()) {
            JsonArray a = ops.getAsJsonArray();
            if (a.isEmpty()) throw new DecodeException("Empty GraphQL batch");
            DecodedNode batch = DecodedNode.array("Batch");
            List<String> labels = new ArrayList<>();
            StringBuilder tb = new StringBuilder();
            boolean introspection = false, mutation = false, subscription = false;
            int n = Math.min(a.size(), MAX_BATCH);
            if (a.size() > n) warnings.add("Batch has " + a.size() + " operations; only the first " + n + " are shown");
            for (int i = 0; i < n; i++) {
                JsonElement x = a.get(i);
                if (!x.isJsonObject()) {
                    batch.add(JsonTree.toNode("[" + i + "]", x, true));
                    warnings.add("Batch element " + i + " is not an object");
                    continue;
                }
                DecodedNode tmp = DecodedNode.object("tmp");
                GraphQlOperations.OpInfo info = GraphQlOperations.decodeOperation(x.getAsJsonObject(), tmp, warnings, "[" + i + "] ");
                DecodedNode item = new DecodedNode("[" + i + "]", info.label() + info.flags(), DecodedNode.Type.OBJECT);
                for (DecodedNode c : tmp.children()) item.add(c);
                batch.add(item);
                labels.add(info.name != null ? info.name : info.type != null ? info.type : "operation");
                introspection |= info.introspection;
                mutation |= "mutation".equals(info.type);
                subscription |= "subscription".equals(info.type);
                if (tb.length() > 0) tb.append("\n\n");
                tb.append("# [").append(i).append("] ").append(info.label()).append('\n');
                String t = opText(info);
                tb.append(t == null ? "# (no query text)" : t);
            }
            root.add(batch);
            List<String> flags = new ArrayList<>();
            if (mutation) flags.add("includes mutation");
            if (subscription) flags.add("includes subscription");
            if (introspection) flags.add("introspection");
            summary = "GraphQL batch: " + a.size() + (a.size() == 1 ? " operation" : " operations")
                    + " (" + shortList(labels) + ")" + (flags.isEmpty() ? "" : " [" + String.join(", ", flags) + "]");
            text = tb.toString();
        } else {
            GraphQlOperations.OpInfo info = GraphQlOperations.decodeOperation(ops.getAsJsonObject(), root, warnings, "");
            summary = "GraphQL " + info.label() + info.flags();
            text = opText(info);
        }
        if (uploads != null && !uploads.isLeaf()) root.add(uploads);
        if (m.truncated()) warnings.add("Message was truncated; the decode may be incomplete");
        return new DecodeResult(summary, root, text, warnings);
    }

    private static String opText(GraphQlOperations.OpInfo info) {
        if (info.formatted == null) return info.variablesJson == null ? null : "# Variables\n" + info.variablesJson;
        return info.variablesJson == null ? info.formatted : info.formatted + "\n\n# Variables\n" + info.variablesJson;
    }

    private static boolean looksLikeOperations(JsonElement e) {
        if (e.isJsonArray()) {
            JsonArray a = e.getAsJsonArray();
            if (a.isEmpty()) return false;
            for (JsonElement x : a) if (!looksLikeOperation(x)) return false;
            return true;
        }
        return looksLikeOperation(e);
    }

    private static boolean looksLikeOperation(JsonElement e) {
        if (!e.isJsonObject()) return false;
        JsonObject o = e.getAsJsonObject();
        return GraphQlOperations.isOperation(o) || str(o, "query") != null && (o.has("variables") || o.has("operationName"))
                || (o.has("operationName") && (o.has("variables") || o.has("extensions")))
                || (str(o, "documentId") != null);
    }

    private static boolean hasParamOperation(MessageContext m) {
        Map<String, List<String>> p = m.queryParameters();
        String ext = Codecs.first(p, "extensions");
        return Codecs.first(p, "query") != null && GraphQlDocument.isLikelyDocument(Codecs.first(p, "query"))
                || ext != null && ext.contains("persistedQuery");
    }

    /** Builds an operation object from GET / form parameters (variables and extensions are JSON-encoded strings). */
    private static JsonObject fromParams(Map<String, List<String>> params, List<String> warnings) {
        JsonObject o = new JsonObject();
        String query = Codecs.first(params, "query");
        if (query != null) o.addProperty("query", query);
        String name = Codecs.first(params, "operationName");
        if (name != null && !name.isEmpty()) o.addProperty("operationName", name);
        for (String k : List.of("variables", "extensions")) {
            String v = Codecs.first(params, k);
            if (v == null || v.isBlank()) continue;
            JsonElement e = JsonTree.parseStrict(v);
            if (e == null) {
                warnings.add(k + " parameter is not valid JSON");
                o.addProperty(k, v);
            } else {
                o.add(k, e);
            }
        }
        for (Map.Entry<String, List<String>> en : params.entrySet()) {
            if (!o.has(en.getKey()) && !en.getKey().equals("operationName")) o.addProperty(en.getKey(), String.join(", ", en.getValue()));
        }
        return o;
    }

    private static JsonElement multipartOperations(MessageContext m, DecodedNode uploads, List<String> warnings) throws DecodeException {
        String boundary = Multipart.boundary(m.requestContentType());
        List<Multipart.Part> parts = Multipart.parse(m.requestBody(), boundary);
        if (parts.isEmpty()) throw new DecodeException("Multipart body has no parts" + (boundary == null ? " (no boundary in Content-Type)" : ""));
        Map<String, Multipart.Part> byName = new LinkedHashMap<>();
        for (Multipart.Part p : parts) if (p.name() != null) byName.putIfAbsent(p.name(), p);
        Multipart.Part opPart = byName.get("operations");
        if (opPart == null) throw new DecodeException("Multipart body has no 'operations' field (not a GraphQL multipart request)");
        JsonElement ops = JsonTree.parseStrict(opPart.text());
        if (ops == null || !(ops.isJsonObject() || ops.isJsonArray())) throw new DecodeException("'operations' field is not a JSON object or array");
        Multipart.Part mapPart = byName.get("map");
        if (mapPart == null) {
            warnings.add("Multipart request has no 'map' field");
        } else {
            JsonElement map = JsonTree.parseStrict(mapPart.text());
            if (map == null || !map.isJsonObject()) {
                warnings.add("'map' field is not a JSON object");
            } else {
                for (Map.Entry<String, JsonElement> en : map.getAsJsonObject().entrySet()) {
                    DecodedNode u = uploads.child("Field " + en.getKey());
                    List<String> paths = new ArrayList<>();
                    if (en.getValue().isJsonArray()) {
                        for (JsonElement x : en.getValue().getAsJsonArray()) paths.add(x.isJsonPrimitive() ? x.getAsString() : x.toString());
                    }
                    u.put("Variable paths", String.join(", ", paths));
                    Multipart.Part f = byName.get(en.getKey());
                    if (f == null) {
                        warnings.add("Upload field '" + en.getKey() + "' from map is missing from the body");
                        continue;
                    }
                    u.put("Filename", f.filename());
                    u.put("Content-Type", f.contentType());
                    u.put("Size (bytes)", f.body().length);
                    u.put("Preview", Codecs.isMostlyText(f.body()) ? Codecs.truncate(f.text(), 300) : Codecs.hexPreview(f.body(), 32));
                }
            }
        }
        for (Multipart.Part p : parts) {
            if (p.name() != null && !p.name().equals("operations") && !p.name().equals("map") && uploads.get("Field " + p.name()) == null) {
                warnings.add("Multipart field '" + p.name() + "' is not referenced by the map");
            }
        }
        return ops;
    }

    // ------------------------------------------------------------------ responses

    private DecodeResult decodeResponse(MessageContext m) throws DecodeException {
        byte[] body = responseBody(m);
        if (body.length == 0) throw new DecodeException("Empty response body");
        String ct = lower(m.responseHeader("Content-Type"));
        String text = new String(body, StandardCharsets.UTF_8);
        List<String> warnings = new ArrayList<>();
        if (m.truncated()) warnings.add("Message was truncated; the decode may be incomplete");
        DecodedNode root = DecodedNode.object("GraphQL response");

        if (ct.contains("text/event-stream")) return decodeEvents("GraphQL SSE stream", sseEvents(text, warnings), root, warnings);
        if (ct.contains("multipart/mixed")) {
            List<JsonElement> parts = new ArrayList<>();
            for (Multipart.Part p : Multipart.parse(body, Multipart.boundary(m.responseHeader("Content-Type")))) {
                String t = p.text().strip();
                if (t.isEmpty()) continue;
                JsonElement e = JsonTree.parseStrict(t);
                if (e == null) warnings.add("Multipart part is not JSON: " + Codecs.truncate(t, 80));
                else parts.add(e);
            }
            return decodeEvents("GraphQL incremental response", parts, root, warnings);
        }

        JsonElement e = JsonTree.parseStrict(text);
        if (e == null) throw new DecodeException("Response body is not JSON");
        if (e.isJsonArray()) {
            JsonArray a = e.getAsJsonArray();
            if (a.isEmpty() || !a.get(0).isJsonObject() || !isResultLoose(a.get(0))) throw new DecodeException("JSON array is not a batch of GraphQL results");
            List<String> names = requestOperationNames(m);
            DecodedNode batch = DecodedNode.array("Batch results");
            int errors = 0;
            String first = null;
            for (int i = 0; i < a.size() && i < MAX_BATCH; i++) {
                JsonElement x = a.get(i);
                if (!x.isJsonObject()) {
                    batch.add(JsonTree.toNode("[" + i + "]", x, true));
                    continue;
                }
                DecodedNode tmp = DecodedNode.object("tmp");
                GraphQlOperations.ResultInfo info = GraphQlOperations.decodeResult(x.getAsJsonObject(), tmp);
                String name = i < names.size() && names.get(i) != null ? names.get(i) + ": " : "";
                DecodedNode item = new DecodedNode("[" + i + "]", name + info.describe(), DecodedNode.Type.OBJECT);
                for (DecodedNode c : tmp.children()) item.add(c);
                batch.add(item);
                errors += info.errors;
                if (first == null) first = info.firstError;
            }
            root.add(batch);
            String summary = "GraphQL batch response: " + a.size() + (a.size() == 1 ? " result" : " results")
                    + (errors > 0 ? ", " + errors + (errors == 1 ? " error" : " errors") + (first == null ? "" : " — " + first) : "");
            return new DecodeResult(summary, root, null, warnings);
        }
        if (!isResultLoose(e)) throw new DecodeException("JSON is not a GraphQL result (no data or errors)");
        GraphQlOperations.ResultInfo info = GraphQlOperations.decodeResult(e.getAsJsonObject(), root);
        String summary = info.schemaSummary != null && info.errors == 0
                ? "GraphQL introspection response: " + info.schemaSummary
                : "GraphQL response: " + info.describe();
        List<String> names = requestOperationNames(m);
        if (names.size() == 1 && names.get(0) != null) root = withOperationName(root, names.get(0));
        return new DecodeResult(summary, root, null, warnings);
    }

    private static DecodedNode withOperationName(DecodedNode root, String name) {
        DecodedNode n = DecodedNode.object(root.name());
        n.put("Operation", name);
        for (DecodedNode c : root.children()) n.add(c);
        return n;
    }

    private DecodeResult decodeEvents(String what, List<JsonElement> events, DecodedNode root, List<String> warnings) throws DecodeException {
        if (events.isEmpty()) throw new DecodeException(what + ": no JSON events found");
        DecodedNode list = DecodedNode.array("Events");
        int errors = 0, results = 0;
        String first = null;
        for (int i = 0; i < events.size(); i++) {
            JsonElement e = events.get(i);
            JsonElement payload = e;
            if (e.isJsonObject() && e.getAsJsonObject().has("payload") && !isResultLoose(e)) payload = e.getAsJsonObject().get("payload");
            if (payload.isJsonObject() && isResultLoose(payload)) {
                DecodedNode tmp = DecodedNode.object("tmp");
                GraphQlOperations.ResultInfo info = GraphQlOperations.decodeResult(payload.getAsJsonObject(), tmp);
                DecodedNode item = new DecodedNode("[" + i + "]", info.describe(), DecodedNode.Type.OBJECT);
                if (payload != e && e.getAsJsonObject().has("id")) item.add(JsonTree.toNode("id", e.getAsJsonObject().get("id"), false));
                for (DecodedNode c : tmp.children()) item.add(c);
                list.add(item);
                results++;
                errors += info.errors;
                if (first == null) first = info.firstError;
            } else {
                list.add(JsonTree.toNode("[" + i + "]", e, true));
            }
        }
        root.add(list);
        String summary = what + ": " + events.size() + (events.size() == 1 ? " event" : " events") + " (" + results + " results"
                + (errors > 0 ? ", " + errors + (errors == 1 ? " error" : " errors") + (first == null ? "" : " — " + first) : "") + ")";
        return new DecodeResult(summary, root, null, warnings);
    }

    /** Parses text/event-stream data lines into JSON values (graphql-sse "next" events etc.). */
    static List<JsonElement> sseEvents(String text, List<String> warnings) {
        List<JsonElement> out = new ArrayList<>();
        StringBuilder data = new StringBuilder();
        String[] lines = text.split("\r?\n", -1);
        for (int i = 0; i <= lines.length && out.size() < MAX_EVENTS; i++) {
            String line = i < lines.length ? lines[i] : "";
            if (line.isEmpty()) {
                if (data.length() > 0) {
                    String d = data.toString();
                    JsonElement e = JsonTree.parseStrict(d);
                    if (e != null) out.add(e);
                    else if (!d.isBlank()) warnings.add("SSE event data is not JSON: " + Codecs.truncate(d, 80));
                    data.setLength(0);
                }
            } else if (line.startsWith("data:")) {
                if (data.length() > 0) data.append('\n');
                data.append(line.substring(5).startsWith(" ") ? line.substring(6) : line.substring(5));
            }
        }
        return out;
    }

    private static boolean isResultLoose(JsonElement e) {
        if (e == null || !e.isJsonObject()) return false;
        JsonObject o = e.getAsJsonObject();
        return o.has("data") || o.has("errors") || o.has("incremental") || o.has("hasNext");
    }

    /** Operation names of the request in this exchange (one entry per batch element); empty if unknown. */
    private static List<String> requestOperationNames(MessageContext m) {
        List<String> names = new ArrayList<>();
        try {
            if (m.requestBody().length == 0 || m.requestBody().length > MAX_MATCH_PARSE) return names;
            JsonElement e = JsonTree.parseStrict(m.requestBodyText());
            if (e == null) return names;
            List<JsonElement> ops = new ArrayList<>();
            if (e.isJsonArray()) e.getAsJsonArray().forEach(ops::add);
            else ops.add(e);
            for (JsonElement x : ops) {
                if (!x.isJsonObject()) {
                    names.add(null);
                    continue;
                }
                String n = str(x.getAsJsonObject(), "operationName");
                if (n == null && str(x.getAsJsonObject(), "query") != null) {
                    GraphQlDocument.Operation op = GraphQlDocument.parse(str(x.getAsJsonObject(), "query")).select(null);
                    if (op != null) n = op.name();
                }
                names.add(n);
            }
        } catch (RuntimeException ignored) {
            names.clear();
        }
        return names;
    }

    // ------------------------------------------------------------------ WebSocket

    private DecodeResult decodeWebSocket(MessageContext m) throws DecodeException {
        JsonElement e = JsonTree.parseStrict(m.bodyText());
        if (e == null || !e.isJsonObject()) throw new DecodeException("Not a GraphQL WebSocket message: payload is not a JSON object");
        JsonObject o = e.getAsJsonObject();
        String type = str(o, "type");
        if (type == null || !WS_TYPES.containsKey(type)) {
            throw new DecodeException("Not a GraphQL WebSocket message: " + (type == null ? "no \"type\" field" : "unknown type '" + type + "'"));
        }
        List<String> warnings = new ArrayList<>();
        WsProtocol proto = protocolFromHeaders(m);
        boolean fromHeader = proto != null;
        if (proto == null) proto = inferProtocol(type);
        else if (!typesOf(proto).contains(type)) warnings.add("Message type '" + type + "' is not defined by " + proto.label);

        DecodedNode root = DecodedNode.object("GraphQL WebSocket");
        root.put("Protocol", proto == null ? "graphql-transport-ws or subscriptions-transport-ws (undetermined)"
                : proto.label + (fromHeader ? "" : " (inferred from message type)"));
        String dir = m.webSocketDirection();
        if (dir != null) root.put("Direction", "CLIENT_TO_SERVER".equals(dir) ? "client → server" : "server → client");
        root.put("Type", type + " — " + WS_TYPES.get(type));
        String id = o.has("id") && o.get("id").isJsonPrimitive() ? o.get("id").getAsString() : null;
        root.put("ID", id);
        String idPart = id == null ? "" : " #" + id;
        JsonElement payload = o.get("payload");
        String summary;
        String text = null;

        switch (type) {
            case "subscribe", "start" -> {
                if (payload == null || !payload.isJsonObject()) throw new DecodeException("'" + type + "' message has no operation payload");
                DecodedNode op = root.child("Payload");
                GraphQlOperations.OpInfo info = GraphQlOperations.decodeOperation(payload.getAsJsonObject(), op, warnings, "");
                summary = "GraphQL WS " + type + idPart + ": " + info.label() + info.flags();
                text = opText(info);
            }
            case "next", "data" -> {
                JsonElement r = payload;
                JsonElement inner = appSyncData(payload);
                if (inner != null) {
                    r = inner;
                    root.put("Note", "AppSync-style payload: data was a JSON string");
                }
                if (r == null || !r.isJsonObject()) throw new DecodeException("'" + type + "' message has no result payload");
                DecodedNode res = root.child("Payload");
                GraphQlOperations.ResultInfo info = GraphQlOperations.decodeResult(r.getAsJsonObject(), res);
                summary = "GraphQL WS " + type + idPart + ": " + info.describe();
            }
            case "error", "connection_error" -> {
                String msg = null;
                if (payload != null && payload.isJsonArray()) {
                    JsonObject wrapper = new JsonObject();
                    wrapper.add("errors", payload);
                    GraphQlOperations.ResultInfo info = GraphQlOperations.decodeResult(wrapper, root);
                    msg = info.describe();
                } else if (payload != null) {
                    root.add(JsonTree.toNode("Payload", payload, true));
                    msg = GraphQlOperations.errorMessage(payload);
                    if (msg == null && payload.isJsonObject()) {
                        JsonArray errs = arr(payload.getAsJsonObject(), "errors");
                        if (errs != null && !errs.isEmpty()) msg = GraphQlOperations.errorMessage(errs.get(0));
                    }
                    if (msg != null) msg = Codecs.truncate(GraphQlOperations.oneLine(msg), 120);
                }
                summary = "GraphQL WS " + type + idPart + (msg == null ? "" : ": " + msg);
            }
            case "connection_init" -> {
                String keys = "";
                if (payload != null && !payload.isJsonNull()) {
                    root.add(JsonTree.toNode("Connection parameters", payload, true));
                    root.add(DecodedNode.note("Connection parameters often carry authentication tokens"));
                    if (payload.isJsonObject() && !payload.getAsJsonObject().isEmpty()) {
                        keys = " (payload: " + shortList(new ArrayList<>(payload.getAsJsonObject().keySet())) + ")";
                    }
                }
                summary = "GraphQL WS connection_init" + keys;
            }
            default -> {
                if (payload != null && !payload.isJsonNull()) root.add(JsonTree.toNode("Payload", payload, true));
                summary = "GraphQL WS " + type + idPart;
            }
        }
        DecodedNode other = DecodedNode.object("Other fields");
        for (Map.Entry<String, JsonElement> en : o.entrySet()) {
            if (!Set.of("type", "id", "payload").contains(en.getKey())) other.add(JsonTree.toNode(en.getKey(), en.getValue(), true));
        }
        if (!other.isLeaf()) root.add(other);
        return new DecodeResult(summary, root, text, warnings);
    }

    /** AppSync sends {"type":"data","payload":{"data":"<JSON string>"}}; returns the parsed inner result or null. */
    private static JsonElement appSyncData(JsonElement payload) {
        if (payload == null || !payload.isJsonObject()) return null;
        JsonElement d = payload.getAsJsonObject().get("data");
        if (d instanceof JsonPrimitive p && p.isString()) {
            JsonElement inner = JsonTree.parseStrict(p.getAsString());
            if (inner != null && inner.isJsonObject()) {
                JsonObject wrapped = new JsonObject();
                wrapped.add("data", inner);
                JsonElement errs = payload.getAsJsonObject().get("errors");
                if (errs != null) wrapped.add("errors", errs);
                return wrapped;
            }
        }
        return null;
    }

    static WsProtocol protocolFromHeaders(MessageContext m) {
        WsProtocol selected = protocolFrom(m.hasResponse() ? m.responseHeader("Sec-WebSocket-Protocol") : null);
        return selected != null ? selected : protocolFrom(m.requestHeader("Sec-WebSocket-Protocol"));
    }

    private static WsProtocol protocolFrom(String header) {
        if (header == null) return null;
        String h = header.toLowerCase(Locale.ROOT);
        boolean modern = h.contains("graphql-transport-ws");
        boolean legacy = false;
        for (String p : h.split(",")) if (p.trim().equals("graphql-ws")) legacy = true;
        if (modern == legacy) return null; // neither, or both offered
        return modern ? WsProtocol.TRANSPORT_WS : WsProtocol.LEGACY;
    }

    private static WsProtocol inferProtocol(String type) {
        boolean n = NEW_TYPES.contains(type), l = LEGACY_TYPES.contains(type);
        if (n && !l) return WsProtocol.TRANSPORT_WS;
        if (l && !n) return WsProtocol.LEGACY;
        return null;
    }

    private static Set<String> typesOf(WsProtocol p) {
        return p == WsProtocol.TRANSPORT_WS ? NEW_TYPES : LEGACY_TYPES;
    }

    // ------------------------------------------------------------------ helpers

    private static boolean onlyKeys(JsonObject o, String... allowed) {
        Set<String> a = Set.of(allowed);
        for (String k : o.keySet()) if (!a.contains(k)) return false;
        return true;
    }

    static boolean isGraphQlContentType(String ctLower) {
        return ctLower.startsWith("application/graphql") && !ctLower.contains("json");
    }

    static boolean graphQlPath(MessageContext m) {
        String p = m.path().toLowerCase(Locale.ROOT);
        return p.contains("graphql") || p.endsWith("/gql") || p.contains("/gql/");
    }

    static String head(byte[] b) {
        return new String(b, 0, Math.min(b.length, SNIFF), StandardCharsets.UTF_8);
    }

    private static String lower(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }

    private static byte[] responseBody(MessageContext m) {
        byte[] raw = m.responseBody();
        String ce = m.responseHeader("Content-Encoding");
        if ((ce != null && !ce.isBlank() && !ce.equalsIgnoreCase("identity")) || Codecs.isGzip(raw)) return Codecs.decodeContent(raw, ce);
        return raw;
    }

    static String shortList(List<String> items) {
        if (items.size() <= 4) return String.join(", ", items);
        return String.join(", ", items.subList(0, 3)) + ", … +" + (items.size() - 3);
    }
}
