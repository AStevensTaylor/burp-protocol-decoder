package protocoldecoder.builtin.graphql;

import com.google.gson.JsonArray;
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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import static protocoldecoder.builtin.graphql.GraphQlOperations.obj;
import static protocoldecoder.builtin.graphql.GraphQlOperations.str;

/**
 * tRPC over HTTP: {@code /trpc/<procedure>} and comma-separated batches ({@code ?batch=1&input=...} keyed by index),
 * POST mutation bodies, superjson {@code {json, meta}} envelopes, and the {@code result}/{@code error} response
 * envelopes of tRPC v9–v11.
 */
public final class TrpcDecoder implements ProtocolDecoder {

    public static final String ID = "trpc";

    private static final Pattern PROCEDURE = Pattern.compile("[A-Za-z0-9_$-]+(?:\\.[A-Za-z0-9_$-]+)*");
    private static final int MAX_PROCEDURES = 200;
    private static final int MAX_PARSE = 4 * 1024 * 1024;
    private static final int MAX_META = 500;
    private static final Map<Integer, String> RPC_CODES = Map.ofEntries(
            Map.entry(-32700, "PARSE_ERROR"), Map.entry(-32600, "BAD_REQUEST"), Map.entry(-32603, "INTERNAL_SERVER_ERROR"),
            Map.entry(-32001, "UNAUTHORIZED"), Map.entry(-32003, "FORBIDDEN"), Map.entry(-32004, "NOT_FOUND"),
            Map.entry(-32005, "METHOD_NOT_SUPPORTED"), Map.entry(-32008, "TIMEOUT"), Map.entry(-32009, "CONFLICT"),
            Map.entry(-32012, "PRECONDITION_FAILED"), Map.entry(-32013, "PAYLOAD_TOO_LARGE"), Map.entry(-32022, "UNPROCESSABLE_CONTENT"),
            Map.entry(-32029, "TOO_MANY_REQUESTS"), Map.entry(-32099, "CLIENT_CLOSED_REQUEST"));

    @Override public String id() { return ID; }
    @Override public String name() { return "tRPC"; }
    @Override public String description() {
        return "tRPC procedure calls (/trpc/<proc>, batched GET/POST, superjson) and their result/error envelopes";
    }

    // ================================================================== matching

    /** Procedure names from the path segment after /trpc/, or null if the path is not tRPC-shaped. */
    static List<String> procedures(String path) {
        if (path == null) return null;
        int idx = path.toLowerCase(Locale.ROOT).lastIndexOf("/trpc/");
        if (idx < 0) return null;
        String rest = path.substring(idx + 6);
        if (rest.endsWith("/")) rest = rest.substring(0, rest.length() - 1);
        if (rest.isEmpty() || rest.contains("/")) return null;
        String[] parts = Codecs.urlDecode(rest.replace("+", "%2B")).split(",", -1);
        if (parts.length > MAX_PROCEDURES) return null;
        List<String> out = new ArrayList<>();
        for (String p : parts) {
            if (!PROCEDURE.matcher(p).matches()) return null;
            out.add(p);
        }
        return out;
    }

    private static boolean batchFlag(Map<String, List<String>> params) {
        String b = Codecs.first(params, "batch");
        return "1".equals(b) || "true".equalsIgnoreCase(b);
    }

    @Override
    public MatchResult match(MessageContext m) {
        try {
            if (m.isWebSocket()) return MatchResult.NONE;
            List<String> procs = procedures(m.path());
            if (procs == null) return MatchResult.NONE;
            return m.isRequest() ? matchRequest(m, procs) : matchResponse(m);
        } catch (RuntimeException e) {
            return MatchResult.NONE;
        }
    }

    private static MatchResult matchRequest(MessageContext m, List<String> procs) {
        Map<String, List<String>> params = m.queryParameters();
        boolean batch = batchFlag(params);
        String input = Codecs.first(params, "input");
        if (input != null) {
            JsonElement e = input.length() > MAX_PARSE ? null : JsonTree.parseStrict(input);
            if (e == null) return MatchResult.of(40, "tRPC path with a non-JSON input parameter");
            if (batch) return indexKeyed(e) ? MatchResult.of(92, "tRPC batch call (" + procs.size() + " procedures)") : MatchResult.of(50, "tRPC path with batch=1");
            return MatchResult.of(85, "tRPC call with JSON input");
        }
        byte[] body = m.requestBody();
        if (body.length > 0 && body.length <= MAX_PARSE) {
            JsonElement e = JsonTree.parseStrict(m.requestBodyText());
            if (e == null) return MatchResult.NONE;
            if (batch) return indexKeyed(e) ? MatchResult.of(90, "tRPC batch mutation (" + procs.size() + " procedures)") : MatchResult.of(50, "tRPC path with batch=1");
            return MatchResult.of(75, "tRPC call with JSON body");
        }
        if (m.requestHeader("trpc-accept") != null || m.requestHeader("x-trpc-source") != null) return MatchResult.of(85, "tRPC client headers");
        if (batch) return MatchResult.of(70, "tRPC batch path");
        return body.length == 0 && procs.size() == 1 ? MatchResult.of(45, "tRPC-style path without input") : MatchResult.NONE;
    }

    private static MatchResult matchResponse(MessageContext m) {
        byte[] body = responseBody(m);
        if (body.length == 0 || body.length > MAX_PARSE) return MatchResult.NONE;
        String head = GraphQlDecoder.head(body);
        if (!head.contains("\"result\"") && !head.contains("\"error\"")) return MatchResult.NONE;
        JsonElement e = JsonTree.parseStrict(new String(body, StandardCharsets.UTF_8));
        if (e == null) return MatchResult.NONE;
        if (e.isJsonArray()) {
            JsonArray a = e.getAsJsonArray();
            if (a.isEmpty()) return MatchResult.NONE;
            for (JsonElement x : a) if (!isEnvelope(x)) return MatchResult.NONE;
            return MatchResult.of(92, "tRPC batch response (" + a.size() + " results)");
        }
        return isEnvelope(e) ? MatchResult.of(88, "tRPC response envelope") : MatchResult.NONE;
    }

    private static boolean indexKeyed(JsonElement e) {
        if (!e.isJsonObject()) return false;
        JsonObject o = e.getAsJsonObject();
        if (o.isEmpty()) return false;
        for (String k : o.keySet()) if (!k.matches("\\d{1,4}")) return false;
        return true;
    }

    static boolean isEnvelope(JsonElement e) {
        if (e == null || !e.isJsonObject()) return false;
        JsonObject o = e.getAsJsonObject();
        for (String k : o.keySet()) if (!Set.of("result", "error", "id", "jsonrpc").contains(k)) return false;
        JsonObject r = obj(o, "result");
        if (r != null) return r.has("data") || r.has("type");
        JsonObject err = obj(o, "error");
        if (err == null) return false;
        if (obj(err, "json") != null) return obj(err, "json").has("message");
        return err.has("message") && (err.has("code") || err.has("data"));
    }

    // ================================================================== decoding

    @Override
    public DecodeResult decode(MessageContext m) throws DecodeException {
        if (m.isWebSocket()) throw new DecodeException("tRPC decoding is only supported for HTTP requests and responses");
        try {
            return m.isRequest() ? decodeRequest(m) : decodeResponse(m);
        } catch (RuntimeException e) {
            throw new DecodeException("tRPC decoding failed: " + e, e);
        }
    }

    private DecodeResult decodeRequest(MessageContext m) throws DecodeException {
        List<String> procs = procedures(m.path());
        if (procs == null) throw new DecodeException("Not a tRPC request: the path has no /trpc/<procedure> segment");
        List<String> warnings = new ArrayList<>();
        Map<String, List<String>> params = m.queryParameters();
        boolean batch = batchFlag(params);
        String kind = "GET".equalsIgnoreCase(m.method()) ? "query" : "POST".equalsIgnoreCase(m.method()) ? "mutation" : m.method();

        DecodedNode root = DecodedNode.object("tRPC request");
        root.put("Type", kind + ("mutation".equals(kind) ? " (POST; queries can also be POSTed when methodOverride is enabled)" : ""));
        root.put("Batch", batch);
        root.add(GraphQlOperations.list("Procedures", procs));

        JsonElement input = null;
        String raw = Codecs.first(params, "input");
        String source = null;
        if (raw != null) {
            source = "input URL parameter";
        } else if (m.requestBody().length > 0) {
            raw = m.requestBodyText();
            source = "request body";
        }
        if (raw != null) {
            input = JsonTree.parseStrict(raw);
            if (input == null) {
                warnings.add("Input (" + source + ") is not valid JSON");
                root.put("Raw input", Codecs.truncate(raw, 100_000));
            } else {
                root.put("Input source", source);
            }
        }

        if (batch) {
            DecodedNode calls = DecodedNode.array("Calls");
            JsonObject byIndex = input != null && input.isJsonObject() ? input.getAsJsonObject() : null;
            if (input != null && byIndex == null) warnings.add("batch=1 but the input is not an object keyed by call index");
            for (int i = 0; i < procs.size(); i++) {
                DecodedNode call = new DecodedNode("[" + i + "]", procs.get(i), DecodedNode.Type.OBJECT);
                call.put("Procedure", procs.get(i));
                JsonElement v = byIndex == null ? null : byIndex.get(String.valueOf(i));
                if (v == null) call.add(DecodedNode.note("No input"));
                else call.add(valueNode("Input", v, warnings));
                calls.add(call);
            }
            if (byIndex != null) {
                for (String k : byIndex.keySet()) {
                    if (!k.matches("\\d+") || Integer.parseInt(k) >= procs.size()) {
                        warnings.add("Input key '" + k + "' has no matching procedure in the path");
                        calls.add(valueNode("Unmatched input " + k, byIndex.get(k), warnings));
                    }
                }
            }
            root.add(calls);
            return new DecodeResult("tRPC batch " + kind + ": " + procs.size() + (procs.size() == 1 ? " call (" : " calls (")
                    + GraphQlDecoder.shortList(procs) + ")", root, null, warnings);
        }
        if (procs.size() > 1) warnings.add("Several procedures in the path but no batch=1 parameter");
        if (input != null) root.add(valueNode("Input", input, warnings));
        else if (raw == null) root.add(DecodedNode.note("No input"));
        return new DecodeResult("tRPC " + kind + " " + String.join(",", procs), root, null, warnings);
    }

    private DecodeResult decodeResponse(MessageContext m) throws DecodeException {
        byte[] body = responseBody(m);
        if (body.length == 0) throw new DecodeException("Empty response body");
        JsonElement e = JsonTree.parseStrict(new String(body, StandardCharsets.UTF_8));
        if (e == null) throw new DecodeException("Response body is not JSON (streamed/JSONL tRPC responses are not supported)");
        List<String> procs = procedures(m.path());
        List<String> warnings = new ArrayList<>();
        DecodedNode root = DecodedNode.object("tRPC response");
        if (e.isJsonArray()) {
            JsonArray a = e.getAsJsonArray();
            if (a.isEmpty() || !isEnvelope(a.get(0))) throw new DecodeException("JSON array is not a batch of tRPC result/error envelopes");
            DecodedNode results = DecodedNode.array("Results");
            int errors = 0;
            String first = null;
            for (int i = 0; i < a.size(); i++) {
                String proc = procs != null && i < procs.size() ? procs.get(i) : null;
                DecodedNode tmp = DecodedNode.object("tmp");
                String err = envelope(a.get(i), tmp, warnings);
                DecodedNode item = new DecodedNode("[" + i + "]", (proc == null ? "" : proc + ": ") + (err == null ? "ok" : "error — " + err), DecodedNode.Type.OBJECT);
                if (proc != null) item.put("Procedure", proc);
                for (DecodedNode c : tmp.children()) item.add(c);
                results.add(item);
                if (err != null) {
                    errors++;
                    if (first == null) first = err;
                }
            }
            if (procs != null && procs.size() != a.size()) warnings.add("Path names " + procs.size() + " procedures but the response has " + a.size() + " results");
            root.add(results);
            String summary = "tRPC batch response: " + a.size() + (a.size() == 1 ? " result" : " results")
                    + (errors > 0 ? ", " + errors + (errors == 1 ? " error — " : " errors — ") + first : "");
            return new DecodeResult(summary, root, null, warnings);
        }
        if (!isEnvelope(e) && !(e.isJsonObject() && (e.getAsJsonObject().has("result") || e.getAsJsonObject().has("error")))) {
            throw new DecodeException("JSON is not a tRPC result/error envelope");
        }
        String proc = procs == null ? "" : " " + String.join(",", procs);
        if (procs != null) root.add(GraphQlOperations.list("Procedures", procs));
        String err = envelope(e, root, warnings);
        String summary = err == null ? "tRPC result" + proc : "tRPC error" + proc + " — " + err;
        return new DecodeResult(summary, root, null, warnings);
    }

    /** Decodes one {result} / {error} envelope into node; returns "CODE: message" for errors, null on success. */
    private static String envelope(JsonElement e, DecodedNode node, List<String> warnings) {
        if (!e.isJsonObject()) {
            node.add(JsonTree.toNode("Value", e, true));
            warnings.add("Batch element is not a tRPC envelope");
            return null;
        }
        JsonObject o = e.getAsJsonObject();
        if (o.has("id")) node.add(JsonTree.toNode("id", o.get("id"), false));
        JsonObject result = obj(o, "result");
        if (result != null) {
            if (str(result, "type") != null) node.put("Result type", str(result, "type"));
            JsonElement data = result.get("data");
            node.add(data == null ? DecodedNode.note("No data") : valueNode("Data", data, warnings));
            return null;
        }
        JsonObject error = obj(o, "error");
        if (error == null) {
            node.add(JsonTree.toNode("Value", e, true));
            warnings.add("Envelope has neither result nor error");
            return null;
        }
        boolean superjson = obj(error, "json") != null;
        JsonObject ej = superjson ? obj(error, "json") : error;
        DecodedNode en = node.child(superjson ? "Error (superjson)" : "Error");
        String message = str(ej, "message");
        en.put("Message", message);
        String code = null;
        JsonElement c = ej.get("code");
        if (c != null && c.isJsonPrimitive()) {
            String cs = c.getAsString();
            String name = null;
            if (c.getAsJsonPrimitive().isNumber()) {
                try {
                    name = RPC_CODES.get(c.getAsInt());
                } catch (NumberFormatException ignored) {
                    // not an int
                }
            }
            en.put("JSON-RPC code", name == null ? cs : cs + " (" + name + ")");
            code = name;
        }
        JsonObject data = obj(ej, "data");
        if (data != null) {
            if (str(data, "code") != null) {
                code = str(data, "code");
                en.put("Code", code);
            }
            if (data.has("httpStatus")) en.add(JsonTree.toNode("HTTP status", data.get("httpStatus"), false));
            if (str(data, "path") != null) en.put("Procedure path", str(data, "path"));
            if (str(data, "stack") != null) {
                en.put("Stack trace", str(data, "stack"));
                warnings.add("Server returned a stack trace in the error (development mode?)");
            }
            for (Map.Entry<String, JsonElement> x : data.entrySet()) {
                if (!Set.of("code", "httpStatus", "path", "stack").contains(x.getKey())) en.add(JsonTree.toNode(x.getKey(), x.getValue(), true));
            }
        }
        for (Map.Entry<String, JsonElement> x : ej.entrySet()) {
            if (!Set.of("message", "code", "data").contains(x.getKey())) en.add(JsonTree.toNode(x.getKey(), x.getValue(), true));
        }
        if (superjson && error.has("meta")) addMeta(en, error.get("meta"));
        String msg = message == null ? "(no message)" : Codecs.truncate(GraphQlOperations.oneLine(message), 120);
        return code == null ? msg : code + ": " + msg;
    }

    // ------------------------------------------------------------------ superjson

    static boolean isSuperjson(JsonElement e) {
        if (e == null || !e.isJsonObject()) return false;
        JsonObject o = e.getAsJsonObject();
        if (!o.has("json")) return false;
        for (String k : o.keySet()) if (!k.equals("json") && !k.equals("meta")) return false;
        return true;
    }

    private static DecodedNode valueNode(String name, JsonElement e, List<String> warnings) {
        if (!isSuperjson(e)) return JsonTree.toNode(name, e, true);
        JsonObject o = e.getAsJsonObject();
        DecodedNode n = DecodedNode.object(name + " (superjson)");
        n.add(JsonTree.toNode("json", o.get("json"), true));
        if (o.has("meta")) addMeta(n, o.get("meta"));
        return n;
    }

    private static void addMeta(DecodedNode n, JsonElement meta) {
        if (meta == null || !meta.isJsonObject()) return;
        JsonObject mo = meta.getAsJsonObject();
        JsonElement values = mo.get("values");
        if (values != null) {
            List<String> types = new ArrayList<>();
            flattenMeta("", values, types, 0);
            DecodedNode tn = DecodedNode.array("Meta: special types");
            for (int i = 0; i < types.size(); i++) tn.add(DecodedNode.leaf("[" + i + "]", types.get(i)));
            if (!types.isEmpty()) n.add(tn);
        }
        if (mo.has("referentialEqualities")) n.add(DecodedNode.note("superjson referentialEqualities present (shared object references)"));
        for (Map.Entry<String, JsonElement> x : mo.entrySet()) {
            if (!x.getKey().equals("values") && !x.getKey().equals("referentialEqualities")) n.add(JsonTree.toNode("meta." + x.getKey(), x.getValue(), false));
        }
    }

    /** superjson meta.values: a tree whose leaves are [typeName, ...] arrays. Produces "path: type" lines. */
    private static void flattenMeta(String path, JsonElement v, List<String> out, int depth) {
        if (out.size() >= MAX_META || depth > 32) return;
        if (v.isJsonArray()) {
            JsonArray a = v.getAsJsonArray();
            if (!a.isEmpty() && a.get(0).isJsonPrimitive()) {
                String type = a.get(0).getAsString();
                if (a.size() > 1) type += " " + a.get(1);
                out.add((path.isEmpty() ? "(root)" : path) + ": " + type);
            } else if (!a.isEmpty() && a.get(0).isJsonArray()) {
                // [typeOfSelf, childrenTree]
                flattenMeta(path, a.get(0), out, depth + 1);
                if (a.size() > 1) flattenMeta(path, a.get(1), out, depth + 1);
            }
        } else if (v.isJsonObject()) {
            for (Map.Entry<String, JsonElement> x : v.getAsJsonObject().entrySet()) {
                flattenMeta(path.isEmpty() ? x.getKey() : path + "." + x.getKey(), x.getValue(), out, depth + 1);
            }
        } else if (v.isJsonPrimitive()) {
            out.add((path.isEmpty() ? "(root)" : path) + ": " + v.getAsString());
        }
    }

    private static byte[] responseBody(MessageContext m) {
        byte[] raw = m.responseBody();
        String ce = m.responseHeader("Content-Encoding");
        if ((ce != null && !ce.isBlank() && !ce.equalsIgnoreCase("identity")) || Codecs.isGzip(raw)) return Codecs.decodeContent(raw, ce);
        return raw;
    }
}
