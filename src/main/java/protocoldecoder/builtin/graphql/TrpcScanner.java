package protocoldecoder.builtin.graphql;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import protocoldecoder.core.DecodeResult;
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
import java.util.List;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static protocoldecoder.builtin.graphql.GraphQlOperations.obj;
import static protocoldecoder.builtin.graphql.GraphQlOperations.str;

/**
 * Scanner support for tRPC: JSON-leaf insertion points inside the URL-encoded {@code input} parameter of GET calls
 * (batches keyed by index, superjson {@code {json, meta}} envelopes kept intact) and passive checks for development-mode
 * error details. POST bodies are plain JSON, which Burp handles itself. No active checks.
 */
public final class TrpcScanner implements ProtocolScanner {

    private static final int MAX_INPUT = 1024 * 1024;

    @Override
    public String decoderId() {
        return TrpcDecoder.ID;
    }

    @Override
    public List<PassiveCheck> passiveChecks() {
        return List.of(new StackTrace(), new InternalErrorDetails());
    }

    // ================================================================== insertion points

    @Override
    public List<InsertionPoint> insertionPoints(MessageContext request, DecodeResult decoded) {
        List<String> procs = TrpcDecoder.procedures(request.path());
        if (procs == null) return List.of();
        String raw = Codecs.first(request.queryParameters(), "input");
        if (raw == null || raw.length() > MAX_INPUT) return List.of();
        JsonElement input = JsonTree.parseStrict(raw);
        if (input == null) return List.of();
        String batchFlag = Codecs.first(request.queryParameters(), "batch");
        boolean batch = "1".equals(batchFlag) || "true".equalsIgnoreCase(batchFlag);
        String query = request.query();
        List<InsertionPoint> out = new ArrayList<>();
        if (batch && input.isJsonObject()) {
            for (String key : input.getAsJsonObject().keySet()) {
                if (!key.matches("\\d{1,4}")) continue;
                int i = Integer.parseInt(key);
                String proc = i < procs.size() ? procs.get(i) : "?";
                addPoints(out, "tRPC: [" + key + "] " + proc + " input", input, List.of(key), query);
            }
        } else {
            addPoints(out, "tRPC: " + String.join(",", procs) + " input", input, List.of(), query);
        }
        return out;
    }

    /** Points for the value at {@code steps} inside the input (descending into a superjson envelope's json). */
    private static void addPoints(List<InsertionPoint> out, String prefix, JsonElement input, List<String> steps, String query) {
        JsonElement value = at(input, steps);
        if (value == null) return;
        List<String> target = new ArrayList<>(steps);
        if (TrpcDecoder.isSuperjson(value)) {
            target.add("json");
            value = value.getAsJsonObject().get("json");
        }
        if (value == null || value.isJsonNull()) return;
        if (value.isJsonPrimitive()) {
            if (out.size() >= InsertionPoints.MAX_POINTS) return;
            out.add(InsertionPoint.query(prefix, InsertionPoints.text(value),
                    render(input, target, query, payload -> new JsonPrimitive(payload))));
            return;
        }
        for (InsertionPoints.JsonLeaf leaf : InsertionPoints.jsonLeaves(value)) {
            if (out.size() >= InsertionPoints.MAX_POINTS) return;
            out.add(InsertionPoint.query(prefix + leaf.path().substring(1), InsertionPoints.text(leaf.value()),
                    render(input, target, query, payload -> JsonParser.parseString(leaf.replace().apply(payload)))));
        }
    }

    private static Function<String, byte[]> render(JsonElement input, List<String> target, String query, Function<String, JsonElement> newValue) {
        return payload -> {
            JsonElement copy = input.deepCopy();
            JsonElement v = newValue.apply(payload);
            if (target.isEmpty()) {
                copy = v;
            } else {
                JsonObject parent = at(copy, target.subList(0, target.size() - 1)).getAsJsonObject();
                parent.add(target.get(target.size() - 1), v);
            }
            String json = GraphQlHttpRequest.GSON.toJson(copy);
            return GraphQlHttpRequest.replaceParam(query, "input", json, true).getBytes(StandardCharsets.ISO_8859_1);
        };
    }

    private static JsonElement at(JsonElement root, List<String> steps) {
        JsonElement cur = root;
        for (String s : steps) {
            if (cur == null || !cur.isJsonObject()) return null;
            cur = cur.getAsJsonObject().get(s);
        }
        return cur;
    }

    // ================================================================== passive

    /** Error objects (the inner json object for superjson errors) in a tRPC response. */
    static List<JsonObject> errors(MessageContext m) {
        List<JsonObject> out = new ArrayList<>();
        if (!m.isResponse()) return out;
        try {
            JsonElement e = GraphQlScanner.responseJson(m);
            if (e == null) return out;
            List<JsonElement> envs = new ArrayList<>();
            if (e.isJsonArray()) {
                JsonArray a = e.getAsJsonArray();
                for (int i = 0; i < a.size() && i < 500; i++) envs.add(a.get(i));
            } else {
                envs.add(e);
            }
            for (JsonElement env : envs) {
                if (!env.isJsonObject()) continue;
                JsonObject err = obj(env.getAsJsonObject(), "error");
                if (err == null) continue;
                JsonObject inner = obj(err, "json");
                out.add(inner != null ? inner : err);
            }
        } catch (RuntimeException ignored) {
            out.clear();
        }
        return out;
    }

    static String code(JsonObject err) {
        String c = str(obj(err, "data"), "code");
        if (c != null) return c;
        JsonElement n = err.get("code");
        if (n != null && n.isJsonPrimitive() && n.getAsJsonPrimitive().isNumber() && n.getAsString().equals("-32603")) return "INTERNAL_SERVER_ERROR";
        return n != null && n.isJsonPrimitive() ? n.getAsString() : null;
    }

    /** error.data.stack: the server runs with isDev / development error formatting. */
    static final class StackTrace implements PassiveCheck {
        @Override public String id() { return "trpc.stack-trace"; }
        @Override public String name() { return "Stack traces in errors"; }
        @Override public String description() { return "tRPC error responses with a stack trace in error.data.stack (development mode / isDev)"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            for (JsonObject err : errors(m)) {
                String stack = str(obj(err, "data"), "stack");
                if (stack == null || stack.isBlank()) continue;
                String first = stack.lines().limit(2).reduce((a, b) -> a + "\n" + b).orElse(stack);
                String ev = Codecs.truncate(stack.lines().findFirst().orElse(stack), 200);
                return List.of(Finding.of(id(), "tRPC errors include stack traces")
                        .severity(Severity.LOW).confidence(Confidence.FIRM).scope(Finding.Scope.HOST)
                        .detail("A tRPC error" + (str(obj(err, "data"), "path") == null ? "" : " from <code>" + Finding.esc(str(obj(err, "data"), "path")) + "</code>")
                                + " contains a server stack trace: <pre>" + Finding.esc(Codecs.truncate(first, 600)) + "</pre>")
                        .background("tRPC's default error formatter adds <code>data.stack</code> when the router is created with <code>isDev: true</code> "
                                + "(by default when NODE_ENV is not production). Stack traces disclose file paths, dependencies and code structure.")
                        .remediation("Run with NODE_ENV=production / <code>isDev: false</code>, or strip <code>stack</code> in a custom <code>errorFormatter</code>.")
                        .responseEvidence(ev));
            }
            return List.of();
        }
    }

    /** INTERNAL_SERVER_ERROR messages that pass through raw exception text. */
    static final class InternalErrorDetails implements PassiveCheck {
        private static final Pattern INTERNAL = Pattern.compile("(?i)(Invalid `prisma\\.|PrismaClient\\w*Error|\\bprisma\\.\\w+\\.\\w+\\(|ECONNREFUSED|ETIMEDOUT|ENOTFOUND|"
                + "relation \"[^\"]+\" does not exist|duplicate key value violates|violates (?:foreign key|unique|not-null) constraint|"
                + "syntax error at or near|SQLITE_\\w+|ER_\\w+:|MongoServerError|E11000 duplicate key|"
                + "Cannot read propert(?:y|ies) of (?:undefined|null)|is not a function|is not defined|"
                + "/(?:app|src|home|var|usr|opt)/[\\w./-]+\\.(?:ts|js|mjs|cjs)|node_modules/)");

        @Override public String id() { return "trpc.internal-error-details"; }
        @Override public String name() { return "Internal error details"; }
        @Override public String description() {
            return "INTERNAL_SERVER_ERROR responses whose message exposes database, ORM, runtime or file-path details (heuristic)";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            for (JsonObject err : errors(m)) {
                if (!"INTERNAL_SERVER_ERROR".equals(code(err))) continue;
                String msg = str(err, "message");
                if (msg == null) continue;
                Matcher mm = INTERNAL.matcher(msg);
                String ev = mm.find() ? mm.group() : ScanPatterns.exceptionEvidence(msg);
                if (ev == null) continue;
                return List.of(Finding.of(id(), "tRPC internal error details disclosed")
                        .severity(Severity.LOW).confidence(Confidence.TENTATIVE)
                        .detail("An <code>INTERNAL_SERVER_ERROR</code> from tRPC returns the underlying exception message: <code>"
                                + Finding.esc(Codecs.truncate(msg, 500)) + "</code>")
                        .background("tRPC passes the message of unexpected exceptions to the client unless an error formatter masks it. Database, "
                                + "ORM and runtime messages disclose schema, queries and code paths and often reveal injection points.")
                        .remediation("Mask unexpected errors in an <code>errorFormatter</code> (return a generic message for INTERNAL_SERVER_ERROR) and log details server-side.")
                        .responseEvidence(ev));
            }
            return List.of();
        }
    }
}
