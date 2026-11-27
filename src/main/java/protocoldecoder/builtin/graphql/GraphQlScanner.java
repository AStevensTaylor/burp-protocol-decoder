package protocoldecoder.builtin.graphql;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.scan.ActiveCheck;
import protocoldecoder.scan.ActiveContext;
import protocoldecoder.scan.Confidence;
import protocoldecoder.scan.Exchange;
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
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static protocoldecoder.builtin.graphql.GraphQlOperations.arr;
import static protocoldecoder.builtin.graphql.GraphQlOperations.obj;
import static protocoldecoder.builtin.graphql.GraphQlOperations.str;

/**
 * Scanner support for GraphQL: insertion points for inline argument literals and for variables carried inside strings
 * (GET/form parameters, multipart {@code operations}, batches), passive configuration/disclosure checks and a few
 * bounded, read-only active probes. Burp Suite Professional has its own GraphQL checks (introspection, suggestions);
 * the overlapping checks here say so in their description so they can be switched off.
 */
public final class GraphQlScanner implements ProtocolScanner {

    static final int MAX_RESPONSE = 8 * 1024 * 1024;
    static final String INTROSPECTION_TITLE = "GraphQL introspection enabled";
    static final String SUGGESTIONS_TITLE = "GraphQL field suggestions enabled";
    private static final Pattern DID_YOU_MEAN = Pattern.compile("Did you mean [\"'“`]?[_A-Za-z][_A-Za-z0-9]*");

    @Override
    public String decoderId() {
        return GraphQlDecoder.ID;
    }

    @Override
    public List<PassiveCheck> passiveChecks() {
        return List.of(new IntrospectionEnabled(), new FieldSuggestions(), new VerboseErrors(), new BatchingSupported(),
                new PersistedQueries(), new MutationCsrf(), new SensitiveData());
    }

    @Override
    public List<ActiveCheck> activeChecks() {
        return List.of(new IntrospectionProbe(), new SuggestionsProbe(), new CsrfProbe(), new BatchingProbe(), new IdeProbe());
    }

    // ================================================================== insertion points

    @Override
    public List<InsertionPoint> insertionPoints(MessageContext request, DecodeResult decoded) {
        GraphQlHttpRequest r = GraphQlHttpRequest.parse(request);
        if (r == null) return List.of();
        List<InsertionPoint> out = new ArrayList<>();
        Set<String> names = new HashSet<>();
        List<JsonObject> ops = r.operations();
        for (int idx = 0; idx < ops.size() && out.size() < InsertionPoints.MAX_POINTS; idx++) {
            JsonObject op = ops.get(idx);
            final int index = idx;
            String prefix = r.batch() ? "[" + idx + "] " : "";
            String label = GraphQlHttpRequest.operationLabel(op);
            String query = str(op, "query");
            if (query != null) {
                for (GraphQlLiterals.Literal lit : GraphQlLiterals.find(query, InsertionPoints.MAX_POINTS - out.size())) {
                    String name = unique(names, "GraphQL: " + prefix + lit.definition() + " arg " + lit.path());
                    out.add(point(r, name, lit.baseValue(), payload -> {
                        JsonElement copy = r.ops.deepCopy();
                        opAt(copy, index).addProperty("query", GraphQlLiterals.render(query, lit, payload));
                        return r.render(copy);
                    }));
                }
            }
            // Plain JSON variables in a single-operation JSON body are handled by Burp itself.
            boolean wantVars = r.variablesInString() || r.batch() || GraphQlHttpRequest.variablesAreString(op);
            JsonElement vars = GraphQlHttpRequest.variables(op);
            if (!wantVars || vars == null) continue;
            for (InsertionPoints.JsonLeaf leaf : InsertionPoints.jsonLeaves(vars)) {
                if (out.size() >= InsertionPoints.MAX_POINTS) break;
                String name = unique(names, "GraphQL: " + prefix + label + " $vars" + leaf.path().substring(1));
                out.add(point(r, name, InsertionPoints.text(leaf.value()), payload -> {
                    JsonElement nv = JsonParser.parseString(leaf.replace().apply(payload));
                    JsonElement copy = r.ops.deepCopy();
                    GraphQlHttpRequest.setVariables(opAt(copy, index), nv);
                    return r.render(copy);
                }));
            }
        }
        return out;
    }

    private static InsertionPoint point(GraphQlHttpRequest r, String name, String base, java.util.function.Function<String, byte[]> render) {
        return r.part() == InsertionPoint.Part.QUERY ? InsertionPoint.query(name, base, render) : InsertionPoint.body(name, base, render);
    }

    private static JsonObject opAt(JsonElement ops, int index) {
        return ops.isJsonArray() ? ops.getAsJsonArray().get(index).getAsJsonObject() : ops.getAsJsonObject();
    }

    private static String unique(Set<String> names, String name) {
        if (names.add(name)) return name;
        for (int i = 2; ; i++) if (names.add(name + " #" + i)) return name + " #" + i;
    }

    // ================================================================== shared helpers

    /** Response body as text, undoing gzip/deflate. */
    static String responseText(MessageContext m) {
        byte[] raw = m.responseBody();
        if (raw.length > MAX_RESPONSE) return "";
        String ce = m.responseHeader("Content-Encoding");
        if ((ce != null && !ce.isBlank() && !ce.equalsIgnoreCase("identity")) || Codecs.isGzip(raw)) raw = Codecs.decodeContent(raw, ce);
        return new String(raw, StandardCharsets.UTF_8);
    }

    static JsonElement responseJson(MessageContext m) {
        if (m == null || !m.hasResponse()) return null;
        String t = responseText(m);
        String s = t.stripLeading();
        if (!(s.startsWith("{") || s.startsWith("["))) return null;
        return JsonTree.parseStrict(t);
    }

    /** GraphQL result objects in a response (single or batch) or a server→client WebSocket result/error message. */
    static List<JsonObject> results(MessageContext m) {
        List<JsonObject> out = new ArrayList<>();
        try {
            if (m.isResponse()) {
                JsonElement e = responseJson(m);
                if (e == null) return out;
                if (e.isJsonArray()) {
                    for (JsonElement x : e.getAsJsonArray()) if (isResult(x)) out.add(x.getAsJsonObject());
                } else if (isResult(e)) {
                    out.add(e.getAsJsonObject());
                }
            } else if (m.isWebSocket() && m.body().length <= MAX_RESPONSE) {
                JsonElement e = JsonTree.parseStrict(m.bodyText());
                if (e == null || !e.isJsonObject()) return out;
                String type = str(e.getAsJsonObject(), "type");
                JsonElement p = e.getAsJsonObject().get("payload");
                if (("next".equals(type) || "data".equals(type)) && isResult(p)) out.add(p.getAsJsonObject());
                if ("error".equals(type) && p != null && p.isJsonArray()) {
                    JsonObject w = new JsonObject();
                    w.add("errors", p);
                    out.add(w);
                }
            }
        } catch (RuntimeException ignored) {
            out.clear();
        }
        return out;
    }

    private static boolean isResult(JsonElement e) {
        if (e == null || !e.isJsonObject()) return false;
        JsonObject o = e.getAsJsonObject();
        return o.has("data") || (o.has("errors") && o.get("errors").isJsonArray());
    }

    static List<JsonObject> errors(List<JsonObject> results) {
        List<JsonObject> out = new ArrayList<>();
        for (JsonObject r : results) {
            JsonArray a = arr(r, "errors");
            if (a == null) continue;
            for (JsonElement x : a) if (x.isJsonObject() && out.size() < 100) out.add(x.getAsJsonObject());
        }
        return out;
    }

    /** True if the result has a data object with at least one non-null root field. */
    static boolean hasData(JsonObject result) {
        JsonObject d = obj(result, "data");
        if (d == null) return false;
        for (Map.Entry<String, JsonElement> e : d.entrySet()) if (!e.getValue().isJsonNull()) return true;
        return false;
    }

    static JsonObject schema(List<JsonObject> results) {
        for (JsonObject r : results) {
            JsonObject s = obj(obj(r, "data"), "__schema");
            if (s != null && (obj(s, "queryType") != null || (arr(s, "types") != null && !arr(s, "types").isEmpty()))) return s;
        }
        return null;
    }

    private static String firstLine(String s) {
        int nl = s.indexOf('\n');
        return Codecs.truncate(nl < 0 ? s : s.substring(0, nl), 300);
    }

    // ================================================================== passive

    /** Introspection results in responses. */
    static final class IntrospectionEnabled implements PassiveCheck {
        @Override public String id() { return "graphql.introspection-enabled"; }
        @Override public String name() { return "Introspection enabled (observed)"; }
        @Override public String description() {
            return "A response contains an introspection result (__schema). Burp Suite Professional's own GraphQL checks may report this too; disable one of them to avoid duplicates";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse()) return List.of();
            JsonObject s = schema(results(m));
            if (s == null) return List.of();
            return List.of(introspectionFinding(id(), s, null, "A response to a request seen in traffic contains the server's schema (<code>__schema</code>)."));
        }
    }

    static Finding introspectionFinding(String id, JsonObject schema, Integer typeCount, String how) {
        JsonArray types = arr(schema, "types");
        int count = typeCount != null ? typeCount : types == null ? -1 : types.size();
        List<String> roots = new ArrayList<>();
        for (String k : new String[]{"queryType", "mutationType", "subscriptionType"}) {
            String n = str(obj(schema, k), "name");
            if (n != null) roots.add(k.replace("Type", "") + ": <code>" + Finding.esc(n) + "</code>");
        }
        return Finding.of(id, INTROSPECTION_TITLE)
                .severity(Severity.LOW).confidence(Confidence.CERTAIN).scope(Finding.Scope.HOST)
                .detail(how + (count >= 0 ? " The schema has " + count + " types." : "")
                        + (roots.isEmpty() ? "" : " Root types: " + String.join(", ", roots) + "."))
                .background("GraphQL introspection lets any client download the complete schema: every query, mutation, type, field and argument, "
                        + "including ones not used by the front end (admin or internal operations). It greatly speeds up finding authorization flaws.")
                .remediation("Disable introspection in production (e.g. <code>introspection: false</code> in Apollo Server, "
                        + "<code>NoSchemaIntrospectionCustomRule</code> in graphql-js) or restrict it to authenticated staff.")
                .responseEvidence("__schema");
    }

    /** "Did you mean …" in error messages. */
    static final class FieldSuggestions implements PassiveCheck {
        @Override public String id() { return "graphql.field-suggestions"; }
        @Override public String name() { return "Field suggestions enabled (observed)"; }
        @Override public String description() {
            return "Error messages suggest valid field/argument/type names (\"Did you mean …\"), which leaks the schema even with introspection off. Burp Suite Professional may report this too";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (m.isRequest()) return List.of();
            String hit = suggestion(errors(results(m)));
            if (hit == null) return List.of();
            return List.of(suggestionsFinding(id(), hit, "An error message in a response suggests schema names"));
        }
    }

    static String suggestion(List<JsonObject> errors) {
        for (JsonObject e : errors) {
            String msg = str(e, "message");
            if (msg != null && DID_YOU_MEAN.matcher(msg).find()) return msg;
        }
        return null;
    }

    static Finding suggestionsFinding(String id, String message, String how) {
        Matcher mm = DID_YOU_MEAN.matcher(message);
        String ev = mm.find() ? mm.group() : "Did you mean";
        return Finding.of(id, SUGGESTIONS_TITLE)
                .severity(Severity.LOW).confidence(Confidence.FIRM).scope(Finding.Scope.HOST)
                .detail(how + ": <code>" + Finding.esc(Codecs.truncate(message, 400)) + "</code>")
                .background("When a query names an unknown field, argument or type, graphql-js based servers (and others) answer with "
                        + "\"Did you mean …\" suggestions. Tools such as Clairvoyance use this to reconstruct most of the schema even when introspection is disabled.")
                .remediation("Disable suggestions in production, e.g. Apollo Server 4.9+ <code>hideSchemaDetailsFromClientErrors</code>, "
                        + "graphql-armor's block-field-suggestions, or mask validation error messages.")
                .responseEvidence(ev);
    }

    /** Stack traces / exception and debug details in GraphQL errors. */
    static final class VerboseErrors implements PassiveCheck {
        private static final Set<String> DEBUG_KEYS = Set.of("stacktrace", "stack", "trace", "debugmessage", "debuginfo", "innerexception");

        @Override public String id() { return "graphql.verbose-errors"; }
        @Override public String name() { return "Verbose errors / stack traces"; }
        @Override public String description() {
            return "GraphQL errors carrying stack traces or debug details (extensions.exception.stacktrace, extensions.stacktrace, debugMessage, trace)";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (m.isRequest()) return List.of();
            for (JsonObject err : errors(results(m))) {
                String[] hit = debugValue(err, 0);
                String trace = null;
                if (hit == null) {
                    trace = ScanPatterns.exceptionEvidence(err.toString().replace("\\n", "\n"));
                    if (trace == null) continue;
                }
                String evidence = hit != null ? firstLine(hit[1]) : trace;
                return List.of(Finding.of(id(), "GraphQL verbose error messages")
                        .severity(Severity.LOW).confidence(Confidence.FIRM).scope(Finding.Scope.HOST)
                        .detail("A GraphQL error contains "
                                + (hit != null ? "debug information in <code>" + Finding.esc(hit[0]) + "</code>" : "exception details")
                                + ": <code>" + Finding.esc(evidence) + "</code>"
                                + (str(err, "message") == null ? "" : "<br>Message: <code>" + Finding.esc(Codecs.truncate(str(err, "message"), 300)) + "</code>"))
                        .background("GraphQL servers in development/debug mode add stack traces and internal exception details to errors "
                                + "(Apollo <code>includeStacktraceInErrorResponses</code>/<code>debug</code>, graphql-php <code>DEBUG_INCLUDE_TRACE</code>, "
                                + "Hot Chocolate <code>IncludeExceptionDetails</code>). They disclose file paths, libraries, queries and code structure.")
                        .remediation("Run the server in production mode and mask unexpected errors; log details server-side.")
                        .responseEvidence(evidence));
            }
            return List.of();
        }

        /** [path, value] of the first non-empty debug field under the error's extensions (or the error itself). */
        private static String[] debugValue(JsonObject o, int depth) {
            if (depth > 4) return null;
            for (Map.Entry<String, JsonElement> e : o.entrySet()) {
                String k = e.getKey();
                JsonElement v = e.getValue();
                if (depth == 0 && (k.equals("message") || k.equals("locations") || k.equals("path"))) continue;
                if (DEBUG_KEYS.contains(k.toLowerCase(Locale.ROOT)) && nonEmpty(v)) {
                    return new String[]{k, v.isJsonPrimitive() ? v.getAsString() : v.isJsonArray() && !v.getAsJsonArray().isEmpty()
                            && v.getAsJsonArray().get(0).isJsonPrimitive() ? v.getAsJsonArray().get(0).getAsString() : v.toString()};
                }
                if (v.isJsonObject()) {
                    String[] r = debugValue(v.getAsJsonObject(), depth + 1);
                    if (r != null) return new String[]{k + "." + r[0], r[1]};
                }
            }
            return null;
        }

        private static boolean nonEmpty(JsonElement v) {
            if (v == null || v.isJsonNull()) return false;
            if (v.isJsonPrimitive()) return v.getAsString().strip().length() > 3;
            if (v.isJsonArray()) return !v.getAsJsonArray().isEmpty();
            return v.isJsonObject() && !v.getAsJsonObject().isEmpty();
        }
    }

    /** Batched request answered with a batch of results. */
    static final class BatchingSupported implements PassiveCheck {
        @Override public String id() { return "graphql.batching"; }
        @Override public String name() { return "Query batching supported (observed)"; }
        @Override public String description() { return "A JSON array of operations was answered with an array of results"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse()) return List.of();
            GraphQlHttpRequest r = GraphQlHttpRequest.parse(m);
            if (r == null || !r.batch()) return List.of();
            JsonElement e = responseJson(m);
            if (e == null || !e.isJsonArray() || e.getAsJsonArray().isEmpty() || !isResult(e.getAsJsonArray().get(0))) return List.of();
            return List.of(batchingFinding(id(), "A request with " + r.operations().size() + " operations in a JSON array was answered with "
                    + e.getAsJsonArray().size() + " results."));
        }
    }

    static Finding batchingFinding(String id, String how) {
        return Finding.of(id, "GraphQL query batching supported")
                .severity(Severity.INFORMATION).confidence(Confidence.CERTAIN).scope(Finding.Scope.HOST)
                .detail(how)
                .background("Array batching lets one HTTP request run many operations. Rate limits and lockouts that count HTTP requests "
                        + "can be bypassed this way (e.g. many login or OTP attempts in one request), and large batches can be used for denial of service.")
                .remediation("Disable batching if it is not needed, or limit batch size and apply rate limits per operation rather than per request.");
    }

    /** APQ hashes / persisted document ids. */
    static final class PersistedQueries implements PassiveCheck {
        @Override public String id() { return "graphql.persisted-queries"; }
        @Override public String name() { return "Persisted queries in use"; }
        @Override public String description() { return "Requests use automatic persisted queries (sha256Hash) or persisted document ids"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isRequest()) return List.of();
            GraphQlHttpRequest r = GraphQlHttpRequest.parse(m);
            if (r == null) return List.of();
            for (JsonObject op : r.operations()) {
                String hash = GraphQlOperations.persistedHash(op);
                String doc = str(op, "documentId");
                if (hash == null && doc == null) continue;
                boolean withQuery = str(op, "query") != null;
                return List.of(Finding.of(id(), "GraphQL persisted queries in use")
                        .severity(Severity.INFORMATION).confidence(Confidence.CERTAIN).scope(Finding.Scope.HOST)
                        .detail("The client identifies operations by " + (hash != null ? "an automatic persisted query hash (<code>"
                                + Finding.esc(hash) + "</code>)" : "a persisted document id (<code>" + Finding.esc(doc) + "</code>)")
                                + (withQuery ? ", sending the query text along with it (APQ registration)." : " without sending the query text."))
                        .background("Automatic persisted queries (APQ) are a caching feature, not an allow-list: unless the server rejects unknown "
                                + "documents, any client can register and run arbitrary queries by sending the text together with its hash. "
                                + "Trusted-document / persisted-operation allow-lists do restrict what can be run.")
                        .remediation("If persisted queries are meant to restrict the API surface, verify that arbitrary query text is rejected.")
                        .requestEvidence(hash != null ? hash : doc));
            }
            return List.of();
        }
    }

    /** Mutations executed over GET or a urlencoded form POST (CSRF-able transports). */
    static final class MutationCsrf implements PassiveCheck {
        @Override public String id() { return "graphql.mutation-csrf"; }
        @Override public String name() { return "Mutation over GET / form POST (CSRF)"; }
        @Override public String description() { return "A mutation sent as a GET request or form-encoded POST was executed (data returned)"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse()) return List.of();
            GraphQlHttpRequest r = GraphQlHttpRequest.parse(m);
            if (r == null) return List.of();
            boolean get = r.transport == GraphQlHttpRequest.Transport.QUERY_PARAMS && "GET".equalsIgnoreCase(m.method());
            if (!get && r.transport != GraphQlHttpRequest.Transport.FORM) return List.of();
            JsonObject op = r.operations().get(0);
            if (!"mutation".equals(GraphQlHttpRequest.operationType(op))) return List.of();
            List<JsonObject> res = results(m);
            if (res.isEmpty() || !hasData(res.get(0))) return List.of();
            boolean cookies = m.requestHeader("Cookie") != null;
            String how = get ? "a GET request" : "a <code>application/x-www-form-urlencoded</code> POST";
            return List.of(Finding.of(id(), "GraphQL mutation executed via " + (get ? "GET" : "form POST"))
                    .severity(cookies ? Severity.MEDIUM : Severity.LOW).confidence(Confidence.FIRM)
                    .detail("The mutation <code>" + Finding.esc(GraphQlHttpRequest.operationLabel(op)) + "</code> was sent as " + how
                            + " and the server executed it (the response contains data)."
                            + (cookies ? " The request carries cookies, so a cross-site page can make a victim's browser send it (CSRF)."
                            : " The request carries no cookies; if authentication only uses headers such as Authorization, CSRF is not possible."))
                    .background("Browsers send GET requests and simple form POSTs cross-site without a CORS preflight. A GraphQL server that "
                            + "executes mutations from such requests and authenticates with cookies is vulnerable to cross-site request forgery.")
                    .remediation("Only accept mutations in POST requests with <code>Content-Type: application/json</code> (GraphQL over HTTP spec), "
                            + "enable CSRF prevention (e.g. Apollo <code>csrfPrevention</code>), and use SameSite cookies or CSRF tokens.")
                    .requestEvidence("mutation"));
        }
    }

    /** Secrets / card numbers in response data (emails excluded: too common in GraphQL data). */
    static final class SensitiveData implements PassiveCheck {
        private static final Set<String> KINDS = Set.of("JWT", "bearer token", "credential-like key=value", "payment card number", "sensitive field name");
        private static final Pattern BORING_VALUE = Pattern.compile("(?i)true|false|null|-?\\d+(\\.\\d+)?|\\d{4}-\\d{2}-\\d{2}.*|bearer|basic|[A-Z_]+");
        private static final Pattern BORING_NAME = Pattern.compile("(?i).*(at|date|time|required|enabled|expires?|expiry|length|policy|count|type|hint|strength|"
                + "changed|updated|reset|valid|set|status|url|label|description|name)$|(?i)(is|has|can|should|must).*|(?i).*(next|page|continuation|cursor|sync|csrf|xsrf)_?token.*");

        @Override public String id() { return "graphql.sensitive-data"; }
        @Override public String name() { return "Sensitive data in responses"; }
        @Override public String description() {
            return "Tokens, credential-like fields and card numbers in GraphQL result data (heuristic; email addresses are not reported)";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (m.isRequest()) return List.of();
            List<ScanPatterns.Sensitive> hits = new ArrayList<>();
            for (JsonObject r : results(m)) {
                JsonObject data = obj(r, "data");
                if (data == null || data.has("__schema") || data.has("__type")) continue;
                for (ScanPatterns.Sensitive s : ScanPatterns.sensitiveValues(JsonTree.toNode("data", data, false), 30)) {
                    if (!KINDS.contains(s.kind())) continue;
                    if (s.kind().equals("sensitive field name")) {
                        String field = s.path().substring(s.path().lastIndexOf('›') + 1).strip();
                        if (BORING_VALUE.matcher(s.value()).matches() || BORING_NAME.matcher(field).matches() || s.value().length() < 6) continue;
                    }
                    if (hits.size() < 10) hits.add(s);
                }
            }
            if (hits.isEmpty()) return List.of();
            Finding f = Finding.of(id(), "Sensitive data in GraphQL response")
                    .severity(Severity.LOW).confidence(Confidence.TENTATIVE)
                    .detail("GraphQL result data contains values that look sensitive:" + ScanPatterns.htmlList(hits)
                            + "Check whether the client needs them and whether the caller is authorised to see them.")
                    .background("GraphQL lets clients select any field the schema exposes. Secrets, password hashes or tokens that are reachable "
                            + "through the schema can be retrieved by any user who can query the parent object.")
                    .remediation("Remove secrets from the schema or protect the fields with field-level authorization.");
            for (ScanPatterns.Sensitive h : hits) f.responseEvidence(h.value());
            return List.of(f);
        }
    }

    // ================================================================== active

    /** Headers of the base request minus body/encoding headers, plus the given extras. */
    static List<Header> headers(MessageContext base, boolean simpleOnly, Header... extra) {
        Set<String> drop = Set.of("content-type", "content-length", "transfer-encoding", "accept-encoding");
        Set<String> simple = Set.of("host", "cookie", "user-agent", "accept", "accept-language");
        List<Header> out = new ArrayList<>();
        Set<String> replaced = new HashSet<>();
        for (Header h : extra) replaced.add(h.name().toLowerCase(Locale.ROOT));
        for (Header h : base.requestHeaders()) {
            String n = h.name().toLowerCase(Locale.ROOT);
            if (drop.contains(n) || replaced.contains(n)) continue;
            if (simpleOnly && !simple.contains(n)) continue;
            out.add(h);
        }
        out.addAll(List.of(extra));
        return out;
    }

    /** Sends a read-only query document to the endpoint, by GET if the base request was a GET, else as POST JSON. */
    static Exchange sendQuery(ActiveContext ctx, String query) {
        MessageContext base = ctx.base();
        if ("GET".equalsIgnoreCase(base.method())) {
            return ctx.http().send("GET", base.path() + "?query=" + GraphQlHttpRequest.encode(query, true), headers(base, false), new byte[0]);
        }
        JsonObject o = new JsonObject();
        o.addProperty("query", query);
        return ctx.http().send("POST", base.path(), headers(base, false, new Header("Content-Type", "application/json")),
                GraphQlHttpRequest.GSON.toJson(o).getBytes(StandardCharsets.UTF_8));
    }

    static List<JsonObject> resultsOf(Exchange x) {
        if (x == null || !x.hasResponse()) return List.of();
        return results(x.message().withKind(protocoldecoder.core.MessageKind.RESPONSE));
    }

    private static boolean isGraphQl(ActiveContext ctx) {
        return ctx.base() != null && GraphQlHttpRequest.parse(ctx.base()) != null;
    }

    /** a) Minimal introspection query, then a type-name listing if it worked. */
    static final class IntrospectionProbe implements ActiveCheck {
        @Override public String id() { return "graphql.introspection-probe"; }
        @Override public String name() { return "Introspection probe"; }
        @Override public String description() {
            return "Once per host: sends {__schema{queryType{name}}} and, if answered, {__schema{types{name}}} to count types (≤2 requests). "
                    + "Skipped if the base response already is an introspection result. Burp Suite Professional's GraphQL checks may report this too";
        }
        @Override public Scope scope() { return Scope.PER_HOST; }

        @Override
        public List<Finding> run(ActiveContext ctx) {
            if (!isGraphQl(ctx)) return List.of();
            if (ctx.baseResponse() != null && schema(results(ctx.baseResponse())) != null) return List.of();
            Exchange x = sendQuery(ctx, "{__schema{queryType{name}}}");
            JsonObject s = schema(resultsOf(x));
            if (s == null) return List.of();
            Exchange y = sendQuery(ctx, "{__schema{types{name}}}");
            JsonObject s2 = schema(resultsOf(y));
            Integer count = s2 != null && arr(s2, "types") != null ? arr(s2, "types").size() : null;
            Finding f = introspectionFinding(id(), s, count, "The server answered an introspection query (<code>{__schema{queryType{name}}}</code>).");
            f.exchange(x);
            if (s2 != null) f.exchange(y);
            return List.of(f);
        }
    }

    /** b) Misspelled root field, looking for "Did you mean". */
    static final class SuggestionsProbe implements ActiveCheck {
        @Override public String id() { return "graphql.suggestions-probe"; }
        @Override public String name() { return "Field suggestions probe"; }
        @Override public String description() {
            return "Once per host: sends one query naming a misspelled version of a root query field from the scanned request and looks for \"Did you mean\" "
                    + "(1 request; skipped when the request has no query-type root field). Burp Suite Professional may report this too";
        }
        @Override public Scope scope() { return Scope.PER_HOST; }

        @Override
        public List<Finding> run(ActiveContext ctx) {
            GraphQlHttpRequest r = GraphQlHttpRequest.parse(ctx.base());
            if (r == null) return List.of();
            String field = null;
            for (JsonObject op : r.operations()) {
                String q = str(op, "query");
                if (q == null) continue;
                GraphQlDocument.Operation sel = GraphQlDocument.parse(q).select(str(op, "operationName"));
                if (sel == null || !"query".equals(sel.type())) continue;
                for (String rf : sel.rootFields()) {
                    String f = rf.contains(": ") ? rf.substring(rf.indexOf(": ") + 2) : rf;
                    if (f.matches("[A-Za-z][_A-Za-z0-9]{1,60}")) {
                        field = f;
                        break;
                    }
                }
                if (field != null) break;
            }
            if (field == null) return List.of();
            String typo = field + (field.endsWith("x") ? "q" : "x");
            Exchange x = sendQuery(ctx, "{ " + typo + " }");
            String hit = suggestion(errors(resultsOf(x)));
            if (hit == null) return List.of();
            return List.of(suggestionsFinding(id(), hit, "Querying the misspelled field <code>" + Finding.esc(typo) + "</code> returned").exchange(x));
        }
    }

    /** c) Re-sends a read-only query as GET and as a form POST to see if CSRF-able transports are accepted. */
    static final class CsrfProbe implements ActiveCheck {
        @Override public String id() { return "graphql.csrf-probe"; }
        @Override public String name() { return "Query over GET / form POST (CSRF)"; }
        @Override public String description() {
            return "For POST JSON query operations (never mutations): re-sends the same read-only query once as GET (query/variables/operationName "
                    + "parameters) and once as an application/x-www-form-urlencoded POST, with only simple headers (cookies kept). "
                    + "Reports if the server executes them like the original (≤2 requests)";
        }
        @Override public Scope scope() { return Scope.PER_REQUEST; }

        @Override
        public List<Finding> run(ActiveContext ctx) {
            MessageContext base = ctx.base();
            GraphQlHttpRequest r = GraphQlHttpRequest.parse(base);
            if (r == null || r.transport != GraphQlHttpRequest.Transport.JSON || r.batch() || !"POST".equalsIgnoreCase(base.method())) return List.of();
            JsonObject op = r.ops.getAsJsonObject();
            String query = str(op, "query");
            if (query == null || !"query".equals(GraphQlHttpRequest.operationType(op))) return List.of();
            JsonObject baseResult = null;
            if (ctx.baseResponse() != null) {
                List<JsonObject> br = results(ctx.baseResponse());
                if (br.isEmpty() || !hasData(br.get(0))) return List.of(); // nothing to compare with
                baseResult = br.get(0);
            }
            StringBuilder params = new StringBuilder("query=").append(GraphQlHttpRequest.encode(query, true));
            String name = str(op, "operationName");
            if (name != null) params.append("&operationName=").append(GraphQlHttpRequest.encode(name, true));
            JsonElement vars = GraphQlHttpRequest.variables(op);
            if (vars != null) params.append("&variables=").append(GraphQlHttpRequest.encode(GraphQlHttpRequest.GSON.toJson(vars), true));
            boolean cookies = base.requestHeader("Cookie") != null;
            List<Finding> out = new ArrayList<>();

            Exchange g = ctx.http().send("GET", base.path() + "?" + params, headers(base, true), new byte[0]);
            Confidence cg = executed(baseResult, g);
            if (cg != null) out.add(finding(op, "GET", cg, cookies, g));

            String form = params.toString().replace("%20", "+");
            Exchange p = ctx.http().send("POST", base.path(), headers(base, true,
                            new Header("Content-Type", "application/x-www-form-urlencoded"), new Header("Origin", "https://csrf-probe.invalid")),
                    form.getBytes(StandardCharsets.ISO_8859_1));
            Confidence cp = executed(baseResult, p);
            if (cp != null) out.add(finding(op, "form POST", cp, cookies, p));
            return out;
        }

        /** FIRM if the probe returned the same data as the base, TENTATIVE if it returned data for the same root fields. */
        private static Confidence executed(JsonObject baseResult, Exchange x) {
            List<JsonObject> res = resultsOf(x);
            if (res.isEmpty() || !hasData(res.get(0))) return null;
            JsonObject d = obj(res.get(0), "data");
            if (baseResult == null) return arr(res.get(0), "errors") == null ? Confidence.TENTATIVE : null;
            JsonObject bd = obj(baseResult, "data");
            if (d.equals(bd)) return Confidence.FIRM;
            return d.keySet().equals(bd.keySet()) && arr(res.get(0), "errors") == null ? Confidence.TENTATIVE : null;
        }

        private Finding finding(JsonObject op, String how, Confidence c, boolean cookies, Exchange x) {
            boolean form = how.equals("form POST");
            Severity sev = !cookies ? Severity.INFORMATION : form ? Severity.MEDIUM : Severity.LOW;
            return Finding.of(id(), "GraphQL operations accepted via " + how + " (CSRF)")
                    .severity(sev).confidence(c)
                    .detail("The read-only query <code>" + Finding.esc(GraphQlHttpRequest.operationLabel(op)) + "</code>, originally sent as a JSON POST, was "
                            + "executed when re-sent as " + (form ? "an <code>application/x-www-form-urlencoded</code> POST with a foreign Origin header"
                            : "a GET request with URL parameters") + " carrying only headers a cross-site page can cause a browser to send"
                            + (c == Confidence.FIRM ? " (identical data returned)." : " (data returned for the same fields).")
                            + " This check only sent a query; it did not try mutations."
                            + (form ? " Servers rarely treat mutations differently for form POSTs, so mutations are probably exposed to CSRF."
                            : " Many servers refuse mutations over GET even when they allow queries; verify with a harmless mutation.")
                            + (cookies ? "" : "<br>The request carries no cookies; if authentication relies on headers such as Authorization, CSRF is not possible."))
                    .background("Browsers send GET requests and simple form POSTs cross-site without a CORS preflight. If a cookie-authenticated "
                            + "GraphQL endpoint executes operations from such requests, an attacker's page can perform actions as the victim.")
                    .remediation("Only accept POST requests with <code>Content-Type: application/json</code> (and reject mutations over GET), "
                            + "enable CSRF prevention (e.g. Apollo <code>csrfPrevention</code>) and use SameSite cookies or CSRF tokens.")
                    .exchange(x);
        }
    }

    /** d) The captured query twice in a JSON array. */
    static final class BatchingProbe implements ActiveCheck {
        @Override public String id() { return "graphql.batching-probe"; }
        @Override public String name() { return "Query batching probe"; }
        @Override public String description() {
            return "Once per host: sends the captured query operation (never a mutation) as a 2-element JSON array and checks for an array of results (1 request)";
        }
        @Override public Scope scope() { return Scope.PER_HOST; }

        @Override
        public List<Finding> run(ActiveContext ctx) {
            MessageContext base = ctx.base();
            GraphQlHttpRequest r = GraphQlHttpRequest.parse(base);
            if (r == null || r.transport != GraphQlHttpRequest.Transport.JSON || r.batch()) return List.of();
            JsonObject op = r.ops.getAsJsonObject();
            if (!"query".equals(GraphQlHttpRequest.operationType(op))) return List.of();
            JsonArray a = new JsonArray();
            a.add(op.deepCopy());
            a.add(op.deepCopy());
            Exchange x = ctx.http().send("POST", base.path() + (base.query().isEmpty() ? "" : "?" + base.query()),
                    headers(base, false, new Header("Content-Type", "application/json")), GraphQlHttpRequest.GSON.toJson(a).getBytes(StandardCharsets.UTF_8));
            if (x == null || !x.hasResponse()) return List.of();
            JsonElement e = responseJson(x.message().withKind(protocoldecoder.core.MessageKind.RESPONSE));
            if (e == null || !e.isJsonArray() || e.getAsJsonArray().size() != 2 || !isResult(e.getAsJsonArray().get(0))) return List.of();
            return List.of(batchingFinding(id(), "Sending the query <code>" + Finding.esc(GraphQlHttpRequest.operationLabel(op))
                    + "</code> twice in a JSON array returned an array of 2 results.").exchange(x));
        }
    }

    /** GraphiQL / Playground / Apollo Sandbox served on GET of the endpoint. */
    static final class IdeProbe implements ActiveCheck {
        private static final String[][] MARKERS = {
                {"(?i)graphql-playground|GraphQLPlayground", "GraphQL Playground"},
                {"(?i)apollo-server-landing-page|embeddable-sandbox\\.cdn\\.apollographql\\.com|EmbeddedSandbox|studio\\.apollographql\\.com/sandbox", "Apollo Sandbox / landing page"},
                {"(?i)graphiql", "GraphiQL"},
                {"(?i)altair-graphql|AltairGraphQL", "Altair GraphQL client"},
                {"(?i)graphql-voyager", "GraphQL Voyager"},
                {"(?i)banana-cake-pop|bananacakepop", "Banana Cake Pop (Hot Chocolate)"},
        };

        @Override public String id() { return "graphql.ide-exposed"; }
        @Override public String name() { return "GraphQL IDE exposed"; }
        @Override public String description() {
            return "Once per host: GETs the GraphQL endpoint path with Accept: text/html and looks for GraphiQL, Playground, Apollo Sandbox, Altair, "
                    + "Voyager or Banana Cake Pop markers (1 request)";
        }
        @Override public Scope scope() { return Scope.PER_HOST; }

        @Override
        public List<Finding> run(ActiveContext ctx) {
            if (!isGraphQl(ctx)) return List.of();
            MessageContext base = ctx.base();
            Exchange x = ctx.http().send("GET", base.path(), headers(base, false, new Header("Accept", "text/html,application/xhtml+xml")), new byte[0]);
            if (x == null || !x.hasResponse() || x.status() != 200) return List.of();
            String text = responseText(x.message());
            String head = text.length() > 512 * 1024 ? text.substring(0, 512 * 1024) : text;
            if (!head.toLowerCase(Locale.ROOT).contains("<html") && !head.toLowerCase(Locale.ROOT).contains("<!doctype html")) return List.of();
            Set<String> found = new LinkedHashSet<>();
            String evidence = null;
            for (String[] mk : MARKERS) {
                Matcher mm = Pattern.compile(mk[0]).matcher(head);
                if (mm.find()) {
                    found.add(mk[1]);
                    if (evidence == null) evidence = mm.group();
                }
            }
            if (found.isEmpty()) return List.of();
            return List.of(Finding.of(id(), "GraphQL IDE exposed")
                    .severity(Severity.INFORMATION).confidence(Confidence.FIRM).scope(Finding.Scope.HOST)
                    .detail("A GET of <code>" + Finding.esc(base.path()) + "</code> serves an interactive GraphQL IDE: " + Finding.esc(String.join(", ", found)) + ".")
                    .background("GraphQL IDEs are development tools. Exposed in production they make exploring the API (often with introspection) trivial "
                            + "and indicate development settings may be enabled.")
                    .remediation("Disable the IDE / landing page in production builds.")
                    .responseEvidence(evidence)
                    .exchange(x));
        }
    }
}
