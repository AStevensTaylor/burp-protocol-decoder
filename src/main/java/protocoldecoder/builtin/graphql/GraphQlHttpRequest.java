package protocoldecoder.builtin.graphql;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import protocoldecoder.core.MessageContext;
import protocoldecoder.scan.InsertionPoint;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A GraphQL HTTP request as a list of operation objects plus the transport it came in, so a modified copy of the
 * operations can be re-serialised exactly the same way (JSON body, GET parameters, form body, application/graphql
 * body, or the {@code operations} field of a multipart upload).
 */
final class GraphQlHttpRequest {

    static final Gson GSON = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();
    private static final int MAX_BODY = 4 * 1024 * 1024;
    private static final Pattern OPERATIONS_NAME = Pattern.compile("(?i)content-disposition:[^\\r\\n]*;\\s*name=(\"operations\"|operations)(?![\\w-])");

    enum Transport {
        JSON("JSON body"), GRAPHQL_BODY("application/graphql body"), QUERY_PARAMS("URL parameters"), FORM("form body"), MULTIPART("multipart operations field");
        final String label;
        Transport(String label) { this.label = label; }
    }

    final MessageContext message;
    final Transport transport;
    /** Operation object or array of them, with GET/form variables already parsed. */
    final JsonElement ops;
    // multipart splice points (latin-1 offsets into the raw body)
    private int partStart = -1, partEnd = -1;

    private GraphQlHttpRequest(MessageContext message, Transport transport, JsonElement ops) {
        this.message = message;
        this.transport = transport;
        this.ops = ops;
    }

    /** Parses a request, or returns null if it carries no GraphQL operation in a supported transport. */
    static GraphQlHttpRequest parse(MessageContext m) {
        try {
            return doParse(m);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static GraphQlHttpRequest doParse(MessageContext m) {
        byte[] body = m.requestBody();
        if (body.length > MAX_BODY) return null;
        String ct = m.requestContentType().toLowerCase(Locale.ROOT);
        if (body.length > 0) {
            if (ct.contains("multipart/form-data")) return multipart(m);
            if (GraphQlDecoder.isGraphQlContentType(ct)) {
                JsonObject o = new JsonObject();
                o.addProperty("query", m.requestBodyText());
                return new GraphQlHttpRequest(m, Transport.GRAPHQL_BODY, o);
            }
            if (ct.contains("x-www-form-urlencoded")) {
                JsonObject o = fromParams(Codecs.parseQuery(m.requestBodyText()));
                return o == null ? null : new GraphQlHttpRequest(m, Transport.FORM, o);
            }
            JsonElement e = JsonTree.parseStrict(m.requestBodyText());
            if (e != null && isOps(e)) return new GraphQlHttpRequest(m, Transport.JSON, e);
        }
        JsonObject o = fromParams(m.queryParameters());
        return o == null ? null : new GraphQlHttpRequest(m, Transport.QUERY_PARAMS, o);
    }

    private static boolean isOps(JsonElement e) {
        if (e.isJsonArray()) {
            JsonArray a = e.getAsJsonArray();
            if (a.isEmpty() || a.size() > GraphQlDecoder.MAX_BATCH) return false;
            for (JsonElement x : a) if (!isOp(x)) return false;
            return true;
        }
        return isOp(e);
    }

    private static boolean isOp(JsonElement e) {
        if (!e.isJsonObject()) return false;
        JsonObject o = e.getAsJsonObject();
        return GraphQlOperations.isOperation(o) || GraphQlOperations.str(o, "documentId") != null && (o.has("variables") || o.has("operationName"));
    }

    /** query / operationName / variables / extensions from GET or form parameters; null if there is no operation. */
    private static JsonObject fromParams(Map<String, List<String>> p) {
        String query = Codecs.first(p, "query");
        String ext = Codecs.first(p, "extensions");
        boolean persisted = ext != null && ext.contains("persistedQuery");
        if (!(query != null && GraphQlDocument.isLikelyDocument(query)) && !persisted) return null;
        JsonObject o = new JsonObject();
        if (query != null) o.addProperty("query", query);
        String name = Codecs.first(p, "operationName");
        if (name != null && !name.isEmpty()) o.addProperty("operationName", name);
        for (String k : List.of("variables", "extensions")) {
            String v = Codecs.first(p, k);
            if (v == null || v.isBlank()) continue;
            JsonElement e = JsonTree.parseStrict(v);
            if (e != null) o.add(k, e);
        }
        return o;
    }

    private static GraphQlHttpRequest multipart(MessageContext m) {
        String boundary = Multipart.boundary(m.requestContentType());
        if (boundary == null) return null;
        String s = Codecs.latin1String(m.requestBody());
        String delim = "--" + boundary;
        int i = s.indexOf(delim);
        while (i >= 0) {
            int lineEnd = s.indexOf('\n', i);
            if (lineEnd < 0) return null;
            int next = s.indexOf(delim, lineEnd);
            if (next < 0) return null;
            int sep = s.indexOf("\r\n\r\n", lineEnd);
            int sepLen = 4;
            int lf = s.indexOf("\n\n", lineEnd);
            if (sep < 0 || sep > next || (lf >= 0 && lf < sep)) {
                sep = lf;
                sepLen = 2;
            }
            if (sep >= 0 && sep < next) {
                String headers = s.substring(lineEnd + 1, sep);
                Matcher hm = OPERATIONS_NAME.matcher(headers);
                if (hm.find()) {
                    int start = sep + sepLen;
                    int end = next;
                    if (end >= 2 && s.startsWith("\r\n", end - 2) && end - 2 >= start) end -= 2;
                    else if (end >= 1 && s.charAt(end - 1) == '\n' && end - 1 >= start) end -= 1;
                    String json = new String(Codecs.latin1Bytes(s.substring(start, end)), StandardCharsets.UTF_8);
                    JsonElement e = JsonTree.parseStrict(json);
                    if (e == null || !(e.isJsonObject() || e.isJsonArray())) return null;
                    GraphQlHttpRequest r = new GraphQlHttpRequest(m, Transport.MULTIPART, e);
                    r.partStart = start;
                    r.partEnd = end;
                    return r;
                }
            }
            i = next;
        }
        return null;
    }

    // ------------------------------------------------------------------ access

    boolean batch() {
        return ops.isJsonArray();
    }

    List<JsonObject> operations() {
        List<JsonObject> out = new ArrayList<>();
        if (ops.isJsonArray()) {
            for (JsonElement e : ops.getAsJsonArray()) if (e.isJsonObject()) out.add(e.getAsJsonObject());
        } else if (ops.isJsonObject()) {
            out.add(ops.getAsJsonObject());
        }
        return out;
    }

    InsertionPoint.Part part() {
        return transport == Transport.QUERY_PARAMS ? InsertionPoint.Part.QUERY : InsertionPoint.Part.BODY;
    }

    /** Variables are carried inside a string for this transport (GET/form parameter, multipart field). */
    boolean variablesInString() {
        return transport == Transport.QUERY_PARAMS || transport == Transport.FORM || transport == Transport.MULTIPART;
    }

    /** Operation type (query/mutation/subscription) of an operation object, or null if unknown (persisted). */
    static String operationType(JsonObject op) {
        String q = GraphQlOperations.str(op, "query");
        if (q == null) return null;
        GraphQlDocument.Operation sel = GraphQlDocument.parse(q).select(GraphQlOperations.str(op, "operationName"));
        return sel == null ? null : sel.type();
    }

    static String operationLabel(JsonObject op) {
        String name = GraphQlOperations.str(op, "operationName");
        if (name != null && !name.isEmpty()) return name;
        String q = GraphQlOperations.str(op, "query");
        if (q != null) {
            GraphQlDocument.Operation sel = GraphQlDocument.parse(q).select(null);
            if (sel != null) return sel.name() != null ? sel.name() : sel.type();
        }
        return "operation";
    }

    // ------------------------------------------------------------------ rendering

    /** The new content of {@link #part()} for a modified copy of {@link #ops}. */
    byte[] render(JsonElement newOps) {
        return switch (transport) {
            case JSON -> GSON.toJson(newOps).getBytes(StandardCharsets.UTF_8);
            case GRAPHQL_BODY -> {
                String q = GraphQlOperations.str(newOps.getAsJsonObject(), "query");
                yield (q == null ? "" : q).getBytes(StandardCharsets.UTF_8);
            }
            case QUERY_PARAMS -> replaceParams(message.query(), newOps.getAsJsonObject(), true).getBytes(StandardCharsets.ISO_8859_1);
            case FORM -> replaceParams(message.requestBodyText(), newOps.getAsJsonObject(), false).getBytes(StandardCharsets.ISO_8859_1);
            case MULTIPART -> {
                byte[] raw = message.requestBody();
                byte[] json = GSON.toJson(newOps).getBytes(StandardCharsets.UTF_8);
                byte[] out = new byte[partStart + json.length + raw.length - partEnd];
                System.arraycopy(raw, 0, out, 0, partStart);
                System.arraycopy(json, 0, out, partStart, json.length);
                System.arraycopy(raw, partEnd, out, partStart + json.length, raw.length - partEnd);
                yield out;
            }
        };
    }

    /** Re-writes the query / variables parameters that differ from the original; other pairs are kept byte-for-byte. */
    private String replaceParams(String raw, JsonObject newOp, boolean url) {
        JsonObject old = ops.getAsJsonObject();
        String q = raw == null ? "" : raw;
        String newQuery = GraphQlOperations.str(newOp, "query");
        if (newQuery != null && !newQuery.equals(GraphQlOperations.str(old, "query"))) q = replaceParam(q, "query", newQuery, url);
        JsonElement nv = newOp.get("variables");
        if (nv != null && !nv.equals(old.get("variables"))) q = replaceParam(q, "variables", GSON.toJson(nv), url);
        return q;
    }

    static String replaceParam(String raw, String name, String value, boolean url) {
        String[] pairs = raw.split("&", -1);
        StringBuilder sb = new StringBuilder(raw.length() + value.length());
        boolean done = false;
        for (int i = 0; i < pairs.length; i++) {
            String pair = pairs[i];
            int eq = pair.indexOf('=');
            String rawKey = eq < 0 ? pair : pair.substring(0, eq);
            if (i > 0) sb.append('&');
            if (!done && Codecs.urlDecode(rawKey).equals(name)) {
                sb.append(rawKey).append('=').append(encode(value, url));
                done = true;
            } else {
                sb.append(pair);
            }
        }
        if (!done) sb.append(raw.isEmpty() ? "" : "&").append(name).append('=').append(encode(value, url));
        return sb.toString();
    }

    /** URL (%20 for spaces) or form (+ for spaces) encoding. */
    static String encode(String s, boolean url) {
        String e = URLEncoder.encode(s, StandardCharsets.UTF_8);
        return url ? e.replace("+", "%20") : e;
    }

    /** Sets op[index].variables (or the single op's) in a copy, keeping a JSON-string encoding if the original used it. */
    static void setVariables(JsonObject op, JsonElement vars) {
        JsonElement old = op.get("variables");
        if (old != null && old.isJsonPrimitive() && old.getAsJsonPrimitive().isString()) op.add("variables", new JsonPrimitive(GSON.toJson(vars)));
        else op.add("variables", vars);
    }

    /** Variables of an operation as JSON (parsing a JSON string if that is how they were sent), or null. */
    static JsonElement variables(JsonObject op) {
        JsonElement v = op.get("variables");
        if (v == null || v.isJsonNull()) return null;
        if (v.isJsonPrimitive() && v.getAsJsonPrimitive().isString()) {
            JsonElement p = JsonTree.parseStrict(v.getAsString());
            return p != null && (p.isJsonObject() || p.isJsonArray()) ? p : null;
        }
        return v.isJsonObject() || v.isJsonArray() ? v : null;
    }

    static boolean variablesAreString(JsonObject op) {
        JsonElement v = op.get("variables");
        return v != null && v.isJsonPrimitive() && v.getAsJsonPrimitive().isString();
    }
}
