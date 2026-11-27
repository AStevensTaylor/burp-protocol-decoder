package protocoldecoder.builtin.graphql;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Decoding of GraphQL-over-HTTP operation objects ({@code {query, variables, operationName, extensions}}) and
 * execution results ({@code {data, errors, extensions}}), shared by the HTTP and WebSocket paths.
 */
final class GraphQlOperations {

    private static final int MAX_TYPES = 5000;
    private static final int MAX_FIELDS = 2000;
    private static final Set<String> OP_KEYS = Set.of("query", "operationName", "variables", "extensions");
    private static final Set<String> DOC_ID_KEYS = Set.of("documentId", "doc_id", "queryId", "id");

    private GraphQlOperations() {
    }

    /** What a decoded operation looked like, for summaries. */
    static final class OpInfo {
        String type;            // query / mutation / subscription, or null if unknown (persisted)
        String name;            // operation name (from document or operationName)
        int rootFields = -1;
        boolean introspection;
        boolean persisted;      // APQ hash or persisted document id
        boolean queryOmitted;
        String hash;
        String formatted;       // pretty-printed document, or null
        String variablesJson;   // pretty variables, or null

        String label() {
            StringBuilder sb = new StringBuilder();
            if (queryOmitted) {
                sb.append("persisted query");
                if (name != null) sb.append(' ').append(name);
                if (hash != null) sb.append(" (sha256 ").append(hash, 0, Math.min(12, hash.length())).append("…, query omitted)");
                else sb.append(" (query omitted)");
                return sb.toString();
            }
            sb.append(type == null ? "operation" : type);
            if (name != null) sb.append(' ').append(name);
            if (rootFields >= 0) sb.append(" (").append(rootFields).append(rootFields == 1 ? " root field)" : " root fields)");
            if (persisted && hash != null) sb.append(" [APQ registration]");
            return sb.toString();
        }

        String flags() {
            List<String> f = new ArrayList<>();
            if (introspection) f.add("introspection");
            return f.isEmpty() ? "" : " [" + String.join(", ", f) + "]";
        }
    }

    /** True if the JSON element is a GraphQL operation object (query document or persisted query). */
    static boolean isOperation(JsonElement e) {
        if (e == null || !e.isJsonObject()) return false;
        JsonObject o = e.getAsJsonObject();
        String q = str(o, "query");
        if (q != null && GraphQlDocument.isLikelyDocument(q)) return true;
        return persistedHash(o) != null;
    }

    static String persistedHash(JsonObject o) {
        JsonObject ext = obj(o, "extensions");
        if (ext == null && o.has("extensions") && o.get("extensions").isJsonPrimitive()) {
            JsonElement p = JsonTree.parseStrict(o.get("extensions").getAsString());
            if (p != null && p.isJsonObject()) ext = p.getAsJsonObject();
        }
        JsonObject pq = ext == null ? null : obj(ext, "persistedQuery");
        return pq == null ? null : str(pq, "sha256Hash");
    }

    /** Decodes one operation object into {@code node}. */
    static OpInfo decodeOperation(JsonObject op, DecodedNode node, List<String> warnings, String warnPrefix) {
        OpInfo info = new OpInfo();
        String query = str(op, "query");
        String operationName = str(op, "operationName");
        info.name = operationName;

        if (query != null) {
            GraphQlDocument doc = GraphQlDocument.parse(query);
            for (String w : doc.warnings) warnings.add(warnPrefix + w);
            GraphQlDocument.Operation sel = doc.select(operationName);
            if (operationName != null && !doc.operations.isEmpty() && !doc.hasOperation(operationName)) {
                warnings.add(warnPrefix + "operationName '" + operationName + "' is not defined in the document");
            }
            if (operationName == null && doc.operations.size() > 1) {
                warnings.add(warnPrefix + "Document defines " + doc.operations.size() + " operations but no operationName is given");
            }
            if (sel != null) {
                info.type = sel.type();
                if (sel.name() != null) info.name = sel.name();
                info.rootFields = sel.rootFields().size();
                DecodedNode o = node.child("Operation");
                o.put("Type", sel.type());
                o.put("Name", sel.name() == null ? "(anonymous)" : sel.name());
                if (operationName != null && !operationName.equals(sel.name())) o.put("Requested operationName", operationName);
                if (!sel.variables().isEmpty()) o.add(list("Variable definitions", sel.variables()));
                if (!sel.directives().isEmpty()) o.add(list("Directives", sel.directives()));
                o.add(list("Root fields", sel.rootFields()));
            }
            if (doc.operations.size() > 1) {
                List<String> all = new ArrayList<>();
                for (GraphQlDocument.Operation x : doc.operations) all.add(x.label() + " (" + x.rootFields().size() + " root fields)");
                node.add(list("Operations in document", all));
            }
            if (!doc.fragments.isEmpty()) {
                List<String> fr = new ArrayList<>();
                for (GraphQlDocument.Fragment f : doc.fragments) fr.add(f.name() + " on " + f.typeCondition());
                node.add(list("Fragments", fr));
            }
            if (!doc.otherDefinitions.isEmpty()) node.add(list("Other definitions", doc.otherDefinitions));
            if (doc.introspection) {
                info.introspection = true;
                node.add(DecodedNode.note("Introspection query (__schema / __type): asks the server for its schema"));
            }
            info.formatted = doc.formatted;
            node.add(DecodedNode.leaf("Document", doc.formatted));
        }

        String hash = persistedHash(op);
        if (hash != null) {
            info.persisted = true;
            info.hash = hash;
            DecodedNode pq = node.child("Persisted query (APQ)");
            pq.put("sha256Hash", hash);
            JsonObject pqo = obj(obj(op, "extensions"), "persistedQuery");
            if (pqo != null && pqo.has("version")) pq.put("Version", pqo.get("version").toString());
            if (query == null) {
                info.queryOmitted = true;
                pq.add(DecodedNode.note("Query text omitted: the server looks the document up by its hash "
                        + "(it answers PersistedQueryNotFound if it does not know it)"));
            } else {
                String actual = sha256(query);
                pq.put("Hash check", actual.equalsIgnoreCase(hash) ? "matches the query text" : "does NOT match the query text (sha256 " + actual + ")");
                pq.add(DecodedNode.note("Query sent with its hash: registers the persisted query"));
            }
        }
        if (query == null && hash == null) {
            for (String k : DOC_ID_KEYS) {
                String id = str(op, k);
                if (id != null) {
                    info.persisted = true;
                    info.queryOmitted = true;
                    node.child("Persisted document").put(k, id)
                            .add(DecodedNode.note("Query text omitted: the server resolves the document by ID"));
                    break;
                }
            }
            if (!info.persisted) warnings.add(warnPrefix + "Operation has no query document or persisted query hash");
        }

        JsonElement vars = op.get("variables");
        if (vars != null && vars.isJsonPrimitive() && vars.getAsJsonPrimitive().isString()) {
            JsonElement parsed = JsonTree.parseStrict(vars.getAsString());
            if (parsed != null) vars = parsed;
            else if (!vars.getAsString().isBlank()) warnings.add(warnPrefix + "variables is not valid JSON");
        }
        if (vars != null && !vars.isJsonNull()) {
            node.add(JsonTree.toNode("Variables", vars, false));
            info.variablesJson = pretty(vars);
        }
        JsonElement ext = op.get("extensions");
        if (ext != null && !ext.isJsonNull()) node.add(JsonTree.toNode("Extensions", ext, true));
        DecodedNode other = DecodedNode.object("Other fields");
        for (Map.Entry<String, JsonElement> en : op.entrySet()) {
            if (!OP_KEYS.contains(en.getKey()) && !(DOC_ID_KEYS.contains(en.getKey()) && info.persisted && query == null && hash == null)) {
                other.add(JsonTree.toNode(en.getKey(), en.getValue(), true));
            }
        }
        if (!other.isLeaf()) node.add(other);
        return info;
    }

    // ------------------------------------------------------------------ results

    static final class ResultInfo {
        int errors;
        String firstError;
        int dataFields = -1;     // root fields in data; -1 = no data / null
        boolean dataNull;
        String schemaSummary;    // set for introspection results
        boolean incremental;

        String describe() {
            if (schemaSummary != null && errors == 0) return schemaSummary;
            if (errors > 0) {
                return errors + (errors == 1 ? " error" : " errors") + (firstError == null ? "" : " — " + firstError);
            }
            if (dataFields >= 0) return "data (" + dataFields + (dataFields == 1 ? " root field)" : " root fields)");
            if (incremental) return "incremental payload";
            return dataNull ? "data null" : "no data";
        }
    }

    /** True if the object looks like a GraphQL execution result. */
    static boolean isResult(JsonElement e) {
        if (e == null || !e.isJsonObject()) return false;
        JsonObject o = e.getAsJsonObject();
        if (o.isEmpty()) return false;
        for (String k : o.keySet()) {
            if (!Set.of("data", "errors", "extensions", "hasNext", "incremental", "pending", "completed", "label", "path").contains(k)) return false;
        }
        JsonElement d = o.get("data");
        JsonElement er = o.get("errors");
        boolean dataOk = d != null && (d.isJsonObject() || d.isJsonNull());
        boolean errOk = er != null && er.isJsonArray() && isErrorList(er.getAsJsonArray());
        return dataOk || errOk || o.has("hasNext") || o.has("incremental");
    }

    static boolean isErrorList(JsonArray a) {
        if (a.isEmpty()) return true;
        JsonElement f = a.get(0);
        return f.isJsonObject() && f.getAsJsonObject().has("message");
    }

    static ResultInfo decodeResult(JsonObject res, DecodedNode node) {
        ResultInfo info = new ResultInfo();
        JsonElement errors = res.get("errors");
        if (errors != null && errors.isJsonArray()) {
            JsonArray a = errors.getAsJsonArray();
            info.errors = a.size();
            DecodedNode en = DecodedNode.array("Errors");
            for (int i = 0; i < a.size(); i++) en.add(errorNode("[" + i + "]", a.get(i)));
            if (!a.isEmpty()) {
                String m = errorMessage(a.get(0));
                if (m != null) info.firstError = Codecs.truncate(oneLine(m), 120);
            }
            node.add(en);
        } else if (errors != null && !errors.isJsonNull()) {
            node.add(JsonTree.toNode("Errors", errors, true));
        }

        JsonElement data = res.get("data");
        if (data != null) {
            if (data.isJsonObject()) {
                JsonObject d = data.getAsJsonObject();
                info.dataFields = d.size();
                JsonObject schema = obj(d, "__schema");
                if (schema != null) {
                    DecodedNode s = DecodedNode.object("Schema (introspection)");
                    info.schemaSummary = summarizeSchema(schema, s);
                    node.add(s);
                }
                node.add(JsonTree.toNode("Data", data, false));
            } else if (data.isJsonNull()) {
                info.dataNull = true;
                node.add(DecodedNode.leaf("Data", "null", DecodedNode.Type.NULL));
            } else {
                node.add(JsonTree.toNode("Data", data, true));
            }
        }
        if (res.has("incremental") || res.has("hasNext")) {
            info.incremental = true;
            if (res.has("hasNext")) node.add(JsonTree.toNode("hasNext", res.get("hasNext"), false));
            if (res.has("incremental")) node.add(JsonTree.toNode("Incremental", res.get("incremental"), false));
        }
        for (Map.Entry<String, JsonElement> e : res.entrySet()) {
            String k = e.getKey();
            if (k.equals("errors") || k.equals("data") || k.equals("incremental") || k.equals("hasNext")) continue;
            node.add(JsonTree.toNode(k.equals("extensions") ? "Extensions" : k, e.getValue(), true));
        }
        return info;
    }

    static String errorMessage(JsonElement e) {
        if (e != null && e.isJsonObject()) return str(e.getAsJsonObject(), "message");
        return e != null && e.isJsonPrimitive() ? e.getAsString() : null;
    }

    private static DecodedNode errorNode(String name, JsonElement e) {
        if (!e.isJsonObject()) return JsonTree.toNode(name, e, true);
        JsonObject o = e.getAsJsonObject();
        DecodedNode n = DecodedNode.object(name);
        String msg = str(o, "message");
        if (msg != null) n.put("Message", msg);
        JsonElement path = o.get("path");
        if (path != null && path.isJsonArray()) {
            List<String> parts = new ArrayList<>();
            for (JsonElement p : path.getAsJsonArray()) parts.add(p.isJsonPrimitive() ? p.getAsString() : p.toString());
            n.put("Path", String.join(".", parts));
        }
        JsonElement locs = o.get("locations");
        if (locs != null && locs.isJsonArray()) {
            List<String> l = new ArrayList<>();
            for (JsonElement x : locs.getAsJsonArray()) {
                if (x.isJsonObject() && x.getAsJsonObject().has("line")) {
                    JsonObject xo = x.getAsJsonObject();
                    l.add("line " + xo.get("line") + ", column " + xo.get("column"));
                }
            }
            if (!l.isEmpty()) n.put("Locations", String.join("; ", l));
        }
        JsonObject ext = obj(o, "extensions");
        if (ext != null && str(ext, "code") != null) n.put("Code", str(ext, "code"));
        for (Map.Entry<String, JsonElement> en : o.entrySet()) {
            String k = en.getKey();
            if (k.equals("message") || k.equals("path") || k.equals("locations")) continue;
            n.add(JsonTree.toNode(k.equals("extensions") ? "Extensions" : k, en.getValue(), true));
        }
        return n;
    }

    // ------------------------------------------------------------------ introspection schema

    static String summarizeSchema(JsonObject schema, DecodedNode node) {
        String q = typeName(schema, "queryType"), mu = typeName(schema, "mutationType"), su = typeName(schema, "subscriptionType");
        node.put("Query type", q);
        node.put("Mutation type", mu);
        node.put("Subscription type", su);
        JsonArray types = arr(schema, "types");
        int count = types == null ? 0 : types.size();
        node.put("Type count", count);
        if (types != null) {
            DecodedNode tl = DecodedNode.array("Types");
            int builtins = 0, shown = 0;
            for (JsonElement t : types) {
                if (!t.isJsonObject()) continue;
                String name = str(t.getAsJsonObject(), "name");
                if (name == null) continue;
                if (name.startsWith("__")) {
                    builtins++;
                    continue;
                }
                if (shown++ < MAX_TYPES) tl.add(DecodedNode.leaf("[" + (shown - 1) + "]", name + " — " + str(t.getAsJsonObject(), "kind")));
            }
            if (builtins > 0) tl.add(DecodedNode.note(builtins + " introspection types (__*) not listed"));
            node.add(tl);
            for (String[] root : new String[][]{{"Query", q}, {"Mutation", mu}, {"Subscription", su}}) {
                if (root[1] == null) continue;
                JsonObject rt = findType(types, root[1]);
                if (rt == null) continue;
                JsonArray fields = arr(rt, "fields");
                if (fields == null) continue;
                DecodedNode fn = DecodedNode.array(root[0] + " fields (" + root[1] + ")");
                int i = 0;
                for (JsonElement f : fields) {
                    if (i >= MAX_FIELDS) {
                        fn.add(DecodedNode.note((fields.size() - i) + " more fields"));
                        break;
                    }
                    if (f.isJsonObject()) fn.add(DecodedNode.leaf("[" + i++ + "]", fieldSignature(f.getAsJsonObject())));
                }
                node.add(fn);
            }
        }
        JsonArray dirs = arr(schema, "directives");
        if (dirs != null) node.put("Directive count", dirs.size());
        StringBuilder sb = new StringBuilder("schema with ").append(count).append(count == 1 ? " type" : " types");
        List<String> roots = new ArrayList<>();
        if (q != null) roots.add("query: " + q);
        if (mu != null) roots.add("mutation: " + mu);
        if (su != null) roots.add("subscription: " + su);
        if (!roots.isEmpty()) sb.append(" (").append(String.join(", ", roots)).append(')');
        return sb.toString();
    }

    private static String typeName(JsonObject schema, String key) {
        JsonObject t = obj(schema, key);
        return t == null ? null : str(t, "name");
    }

    private static JsonObject findType(JsonArray types, String name) {
        for (JsonElement t : types) {
            if (t.isJsonObject() && name.equals(str(t.getAsJsonObject(), "name"))) return t.getAsJsonObject();
        }
        return null;
    }

    private static String fieldSignature(JsonObject f) {
        StringBuilder sb = new StringBuilder(String.valueOf(str(f, "name")));
        JsonArray args = arr(f, "args");
        if (args != null && !args.isEmpty()) {
            sb.append('(');
            for (int i = 0; i < args.size() && i < 50; i++) {
                if (i > 0) sb.append(", ");
                JsonElement a = args.get(i);
                if (a.isJsonObject()) sb.append(str(a.getAsJsonObject(), "name")).append(": ").append(typeRef(obj(a.getAsJsonObject(), "type"), 0));
            }
            sb.append(')');
        }
        sb.append(": ").append(typeRef(obj(f, "type"), 0));
        if (f.has("isDeprecated") && f.get("isDeprecated").isJsonPrimitive() && f.get("isDeprecated").getAsBoolean()) sb.append("  (deprecated)");
        return sb.toString();
    }

    private static String typeRef(JsonObject t, int depth) {
        if (t == null || depth > 10) return "?";
        String kind = str(t, "kind");
        if ("NON_NULL".equals(kind)) return typeRef(obj(t, "ofType"), depth + 1) + "!";
        if ("LIST".equals(kind)) return "[" + typeRef(obj(t, "ofType"), depth + 1) + "]";
        String n = str(t, "name");
        return n == null ? "?" : n;
    }

    // ------------------------------------------------------------------ JSON helpers

    static String str(JsonObject o, String k) {
        if (o == null) return null;
        JsonElement e = o.get(k);
        return e != null && e.isJsonPrimitive() && e.getAsJsonPrimitive().isString() ? e.getAsString() : null;
    }

    static JsonObject obj(JsonObject o, String k) {
        if (o == null) return null;
        JsonElement e = o.get(k);
        return e != null && e.isJsonObject() ? e.getAsJsonObject() : null;
    }

    static JsonArray arr(JsonObject o, String k) {
        if (o == null) return null;
        JsonElement e = o.get(k);
        return e != null && e.isJsonArray() ? e.getAsJsonArray() : null;
    }

    static DecodedNode list(String name, List<String> values) {
        DecodedNode n = DecodedNode.array(name);
        for (int i = 0; i < values.size(); i++) n.add(DecodedNode.leaf("[" + i + "]", values.get(i)));
        return n;
    }

    static String pretty(JsonElement e) {
        return new com.google.gson.GsonBuilder().setPrettyPrinting().serializeNulls().disableHtmlEscaping().create().toJson(e);
    }

    static String oneLine(String s) {
        return s.replace('\n', ' ').replace('\r', ' ').strip();
    }

    static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
