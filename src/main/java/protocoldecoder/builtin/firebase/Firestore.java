package protocoldecoder.builtin.firebase;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import protocoldecoder.builtin.batchexecute.ChunkedJson;
import protocoldecoder.builtin.firebase.Fb.Out;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MessageContext;
import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static protocoldecoder.builtin.firebase.Fb.arr;
import static protocoldecoder.builtin.firebase.Fb.has;
import static protocoldecoder.builtin.firebase.Fb.obj;
import static protocoldecoder.builtin.firebase.Fb.prim;
import static protocoldecoder.builtin.firebase.Fb.str;

/** Cloud Firestore: typed values, WebChannel Listen/Write streams and the REST API. */
final class Firestore {

    private Firestore() {
    }

    static final Set<String> VALUE_KEYS = Set.of("nullValue", "booleanValue", "integerValue", "doubleValue",
            "timestampValue", "stringValue", "bytesValue", "referenceValue", "geoPointValue", "arrayValue", "mapValue");

    private static final int MAX_MESSAGES = 5000;
    private static final Pattern REQ_FIELD = Pattern.compile("^req(\\d{1,6})_(.*)$");

    private static final Map<String, String> CHANNEL_PARAMS = Map.ofEntries(
            Map.entry("VER", "WebChannel protocol version"),
            Map.entry("database", "Database"),
            Map.entry("RID", "Request id ('rpc' = backchannel)"),
            Map.entry("SID", "Session id"),
            Map.entry("AID", "Last acknowledged array id"),
            Map.entry("TYPE", "Request type (xmlhttp = backchannel poll, terminate = close session)"),
            Map.entry("CVER", "Client version"),
            Map.entry("CI", "Chunking disabled (1 = buffering proxy suspected)"),
            Map.entry("gsessionid", "Google session id"),
            Map.entry("X-HTTP-Session-Id", "Session id header name"),
            Map.entry("zx", "Cache buster"),
            Map.entry("t", "Attempt number"),
            Map.entry("$httpHeaders", "Headers tunnelled in the query"),
            Map.entry("$req", "Request payload in the query"));

    private static final Map<String, String> OPS = Map.ofEntries(
            Map.entry("EQUAL", "=="), Map.entry("NOT_EQUAL", "!="), Map.entry("LESS_THAN", "<"),
            Map.entry("LESS_THAN_OR_EQUAL", "<="), Map.entry("GREATER_THAN", ">"), Map.entry("GREATER_THAN_OR_EQUAL", ">="),
            Map.entry("ARRAY_CONTAINS", "array-contains"), Map.entry("IN", "in"),
            Map.entry("ARRAY_CONTAINS_ANY", "array-contains-any"), Map.entry("NOT_IN", "not-in"));

    // ---------------------------------------------------------------- typed values

    static boolean isTypedValue(JsonObject o) {
        if (o.size() != 1) return false;
        String k = Fb.firstKey(o);
        return k != null && VALUE_KEYS.contains(k);
    }

    static DecodedNode typed(String name, JsonObject o, Out out, int depth) {
        String k = Fb.firstKey(o);
        JsonElement v = o.get(k);
        switch (k) {
            case "nullValue" -> {
                return DecodedNode.leaf(name, "null  (null)", DecodedNode.Type.NULL);
            }
            case "booleanValue" -> {
                return DecodedNode.leaf(name, prim(v) + "  (boolean)", DecodedNode.Type.BOOLEAN);
            }
            case "integerValue" -> {
                return DecodedNode.leaf(name, prim(v) + "  (integer)", DecodedNode.Type.NUMBER);
            }
            case "doubleValue" -> {
                return DecodedNode.leaf(name, prim(v) + "  (double)", DecodedNode.Type.NUMBER);
            }
            case "timestampValue" -> {
                return DecodedNode.leaf(name, timestamp(v) + "  (timestamp)");
            }
            case "stringValue" -> {
                return DecodedNode.leaf(name, prim(v) + "  (string)");
            }
            case "referenceValue" -> {
                return DecodedNode.leaf(name, prim(v) + "  (reference)");
            }
            case "bytesValue" -> {
                return DecodedNode.leaf(name, bytes(prim(v)) + "  (bytes)", DecodedNode.Type.BINARY);
            }
            case "geoPointValue" -> {
                return DecodedNode.leaf(name, str(v, "latitude") + ", " + str(v, "longitude") + "  (geoPoint)");
            }
            case "arrayValue" -> {
                DecodedNode a = DecodedNode.array(name + " (array)");
                JsonArray values = arr(v, "values");
                if (values != null) {
                    for (int i = 0; i < values.size(); i++) a.add(Fb.node("[" + i + "]", values.get(i), true, out, depth + 1));
                }
                return a;
            }
            case "mapValue" -> {
                DecodedNode m = DecodedNode.object(name + " (map)");
                JsonObject fields = obj(v, "fields");
                if (fields != null) {
                    for (Map.Entry<String, JsonElement> en : fields.entrySet()) m.add(Fb.node(en.getKey(), en.getValue(), true, out, depth + 1));
                }
                return m;
            }
            default -> {
                return Fb.node(name, v, true, out, depth + 1);
            }
        }
    }

    private static String timestamp(JsonElement v) {
        String s = prim(v);
        if (s != null) return s;
        String sec = str(v, "seconds");
        if (sec != null && sec.matches("-?\\d{1,12}")) {
            String nanos = str(v, "nanos");
            long n = nanos != null && nanos.matches("\\d{1,9}") ? Long.parseLong(nanos) : 0;
            return Instant.ofEpochSecond(Long.parseLong(sec), n).toString();
        }
        return v == null ? "null" : v.toString();
    }

    private static String bytes(String b64) {
        if (b64 == null) return "null";
        byte[] b = Codecs.base64Decode(b64);
        if (b == null) return b64;
        String txt = Codecs.isMostlyText(b) && b.length > 0 ? " \"" + Codecs.truncate(new String(b, StandardCharsets.UTF_8), 200) + "\"" : "";
        return Codecs.truncate(b64, 400) + " [" + b.length + " bytes" + txt + "]";
    }

    /** Plain one-line rendering of a typed value for summaries. */
    static String plain(JsonElement e) {
        JsonObject o = obj(e);
        if (o == null || !isTypedValue(o)) return e == null ? "null" : Codecs.truncate(prim(e) != null ? prim(e) : e.toString(), 60);
        String k = Fb.firstKey(o);
        JsonElement v = o.get(k);
        String r = switch (k) {
            case "nullValue" -> "null";
            case "timestampValue" -> timestamp(v);
            case "referenceValue" -> docPath(prim(v));
            case "geoPointValue" -> "(" + str(v, "latitude") + ", " + str(v, "longitude") + ")";
            case "bytesValue" -> "bytes";
            case "arrayValue" -> {
                List<String> parts = new ArrayList<>();
                JsonArray values = arr(v, "values");
                if (values != null) for (JsonElement x : values) parts.add(plain(x));
                yield "[" + String.join(", ", parts) + "]";
            }
            case "mapValue" -> {
                JsonObject f = obj(v, "fields");
                yield f == null ? "{}" : "{" + String.join(", ", f.keySet()) + "}";
            }
            default -> prim(v) == null ? String.valueOf(v) : prim(v);
        };
        return Codecs.truncate(r, 60);
    }

    /** "projects/p/databases/d/documents/users/u1" → "users/u1". */
    static String docPath(String name) {
        if (name == null) return "";
        int i = name.indexOf("/documents/");
        if (i >= 0) return name.substring(i + "/documents/".length());
        if (name.endsWith("/documents")) return "";
        return name;
    }

    // ---------------------------------------------------------------- query description

    static String describeFilter(JsonElement f, boolean nested) {
        JsonObject ff = obj(f, "fieldFilter");
        if (ff != null) {
            String op = str(ff, "op");
            return fieldPath(ff) + " " + OPS.getOrDefault(op == null ? "" : op, op) + " " + plain(ff.get("value"));
        }
        JsonObject uf = obj(f, "unaryFilter");
        if (uf != null) {
            String op = str(uf, "op");
            String r = op == null ? "?" : switch (op) {
                case "IS_NULL" -> "== null";
                case "IS_NAN" -> "== NaN";
                case "IS_NOT_NULL" -> "!= null";
                case "IS_NOT_NAN" -> "!= NaN";
                default -> op;
            };
            return fieldPath(uf) + " " + r;
        }
        JsonObject cf = obj(f, "compositeFilter");
        if (cf != null) {
            JsonArray filters = arr(cf, "filters");
            List<String> parts = new ArrayList<>();
            if (filters != null) for (JsonElement x : filters) parts.add(describeFilter(x, true));
            String op = str(cf, "op");
            String joined = String.join(" " + (op == null ? "AND" : op) + " ", parts);
            return nested && parts.size() > 1 ? "(" + joined + ")" : joined;
        }
        return "?";
    }

    private static String fieldPath(JsonObject filter) {
        String p = str(obj(filter, "field"), "fieldPath");
        return p == null ? "?" : p;
    }

    static String describeQuery(JsonObject sq, String parentPath) {
        StringBuilder sb = new StringBuilder("query on ");
        JsonArray from = arr(sq, "from");
        List<String> colls = new ArrayList<>();
        if (from != null) {
            for (JsonElement f : from) {
                String c = str(f, "collectionId");
                boolean group = "true".equals(str(f, "allDescendants"));
                String full = (parentPath == null || parentPath.isEmpty() ? "" : parentPath + "/") + (c == null ? "?" : c);
                colls.add(group ? "collection group " + full : full);
            }
        }
        sb.append(colls.isEmpty() ? "?" : String.join(", ", colls));
        if (sq.has("where")) sb.append(" where ").append(describeFilter(sq.get("where"), false));
        JsonArray orderBy = arr(sq, "orderBy");
        if (orderBy != null) {
            List<String> ob = new ArrayList<>();
            for (JsonElement o : orderBy) {
                String p = str(obj(o, "field"), "fieldPath");
                if (p == null || p.equals("__name__")) continue;
                ob.add(p + ("DESCENDING".equals(str(o, "direction")) ? " desc" : ""));
            }
            if (!ob.isEmpty()) sb.append(" order by ").append(String.join(", ", ob));
        }
        JsonElement limit = sq.get("limit");
        if (limit != null) {
            String l = prim(limit) != null ? prim(limit) : str(limit, "value");
            if (l != null) sb.append(" limit ").append(l);
        }
        if (sq.has("startAt") || sq.has("endAt")) sb.append(" (cursor)");
        return sb.toString();
    }

    static String describeTarget(JsonObject t) {
        String d;
        JsonObject q = obj(t, "query");
        JsonObject docs = obj(t, "documents");
        if (q != null) {
            JsonObject sq = obj(q, "structuredQuery");
            d = sq == null ? "query" : describeQuery(sq, docPath(str(q, "parent")));
        } else if (docs != null) {
            JsonArray names = arr(docs, "documents");
            int n = names == null ? 0 : names.size();
            d = n == 0 ? "documents" : (n == 1 ? "document " : n + " documents ") + docPath(prim(names.get(0))) + (n > 1 ? " …" : "");
        } else {
            d = "target";
        }
        if (t.has("resumeToken")) d += " [resume]";
        if (t.has("expectedCount")) d += " [expectedCount " + str(t, "expectedCount") + "]";
        return "addTarget " + d;
    }

    static String describeWrite(JsonElement w) {
        if (has(w, "update")) {
            String s = "update " + docPath(str(obj(w, "update"), "name"));
            JsonArray mask = arr(obj(w, "updateMask"), "fieldPaths");
            if (mask != null) s += " (mask " + mask.size() + " fields)";
            return s;
        }
        if (has(w, "delete")) return "delete " + docPath(str(w, "delete"));
        if (has(w, "transform")) return "transform " + docPath(str(obj(w, "transform"), "document"));
        if (has(w, "verify")) return "verify " + docPath(str(w, "verify"));
        return "write";
    }

    static String describeWrites(JsonArray writes) {
        List<String> parts = new ArrayList<>();
        for (int i = 0; i < writes.size() && i < 3; i++) parts.add(describeWrite(writes.get(i)));
        if (writes.size() > 3) parts.add("…");
        return writes.size() + (writes.size() == 1 ? " write: " : " writes: ") + String.join(", ", parts);
    }

    // ---------------------------------------------------------------- WebChannel

    static String stream(MessageContext m) {
        String p = m.path();
        if (p.contains("/Listen/")) return "Listen";
        if (p.contains("/Write/")) return "Write";
        return "WebChannel";
    }

    static DecodeResult decodeChannel(MessageContext m, Out out) throws DecodeException {
        String stream = stream(m);
        if (m.isResponse()) return channelResponse(m, stream, out);
        DecodedNode root = DecodedNode.object("Firestore " + stream + " WebChannel request");
        Map<String, List<String>> q = m.queryParameters();
        root.add(channelParams(q, out));
        FirebaseDecoder.authHeaders(m, root, out);

        String body = Fb.text(m.requestBody(), m.requestHeader("Content-Encoding"));
        List<String> parts = new ArrayList<>();
        if (!body.isBlank()) {
            Map<String, List<String>> form = Codecs.parseQuery(body.strip());
            TreeMap<Integer, Map<String, String>> reqs = new TreeMap<>();
            DecodedNode framing = DecodedNode.object("Forward channel");
            for (Map.Entry<String, List<String>> e : form.entrySet()) {
                Matcher rm = REQ_FIELD.matcher(e.getKey());
                if (rm.matches()) {
                    reqs.computeIfAbsent(Integer.parseInt(rm.group(1)), x -> new LinkedHashMap<>()).put(rm.group(2), e.getValue().get(0));
                } else {
                    for (String v : e.getValue()) framing.put(e.getKey().equals("count") ? "count (maps in this POST)"
                            : e.getKey().equals("ofs") ? "ofs (index of first map)" : e.getKey(), v);
                }
            }
            if (!framing.isLeaf()) root.add(framing);
            if (reqs.isEmpty()) {
                JsonElement j = Fb.parse(body);
                if (j == null) {
                    root.add(DecodedNode.leaf("Body", Codecs.truncate(body, 20_000)));
                    out.warn("no reqN___data__ fields found in the forward-channel body");
                } else {
                    root.add(Fb.node("Body", j, true, out, 0));
                    parts.add(describeRequestJson(j, stream));
                }
            }
            DecodedNode msgs = DecodedNode.array("Messages");
            if (!reqs.isEmpty()) root.add(msgs);
            for (Map.Entry<Integer, Map<String, String>> r : reqs.entrySet()) {
                String data = r.getValue().get("__data__");
                if (data != null) {
                    JsonElement j = Fb.parse(data);
                    if (j == null) {
                        msgs.add(DecodedNode.leaf("req" + r.getKey(), Codecs.truncate(data, 20_000)));
                        out.warn("req" + r.getKey() + "___data__ is not JSON");
                        continue;
                    }
                    String d = describeRequestJson(j, stream);
                    DecodedNode n = Fb.node("req" + r.getKey() + " — " + d, j, true, out, 0);
                    msgs.add(n);
                    parts.add(d);
                } else {
                    DecodedNode n = DecodedNode.object("req" + r.getKey());
                    msgs.add(n);
                    for (Map.Entry<String, String> f : r.getValue().entrySet()) n.add(Fb.stringNode(f.getKey(), f.getValue(), out));
                    parts.add("map with " + r.getValue().size() + " fields");
                }
            }
        }
        String type = Codecs.first(q, "TYPE");
        String summary;
        if (!parts.isEmpty()) {
            summary = "Firestore " + stream + ": " + String.join("; ", dedupe(parts));
        } else if ("xmlhttp".equals(type) || "rpc".equals(Codecs.first(q, "RID"))) {
            summary = "Firestore " + stream + ": backchannel poll" + sid(q);
        } else if ("terminate".equals(type)) {
            summary = "Firestore " + stream + ": terminate session" + sid(q);
        } else {
            summary = "Firestore " + stream + " WebChannel request" + sid(q);
        }
        return new DecodeResult(summary, root, null, out.warnings);
    }

    private static List<String> dedupe(List<String> l) {
        return new ArrayList<>(new java.util.LinkedHashSet<>(l));
    }

    private static String sid(Map<String, List<String>> q) {
        String s = Codecs.first(q, "SID");
        return s == null ? "" : " (SID " + s + ")";
    }

    static String describeRequestJson(JsonElement j, String stream) {
        JsonObject o = obj(j);
        if (o == null) return "message";
        JsonObject add = obj(o, "addTarget");
        if (add != null) return describeTarget(add);
        if (o.has("removeTarget")) return "removeTarget " + str(o, "removeTarget");
        JsonArray writes = arr(o, "writes");
        if (writes != null) return describeWrites(writes);
        if (o.has("streamToken")) return "ack (streamToken)";
        if (o.has("database") && o.size() <= 2) return "handshake (" + str(o, "database") + ")";
        return Codecs.truncate(String.join(", ", o.keySet()), 80);
    }

    private static DecodedNode channelParams(Map<String, List<String>> q, Out out) {
        DecodedNode n = DecodedNode.object("Channel parameters");
        for (Map.Entry<String, List<String>> e : q.entrySet()) {
            String label = CHANNEL_PARAMS.get(e.getKey());
            String name = label == null ? e.getKey() : e.getKey() + " — " + label;
            for (String v : e.getValue()) {
                if (e.getKey().equals("$httpHeaders")) n.add(tunnelledHeaders(name, v, out));
                else n.add(Fb.stringNode(name, v, out));
            }
        }
        return n;
    }

    /** $httpHeaders carries "Name:Value\r\n" lines (or a JSON object); Authorization holds the Firebase ID token. */
    private static DecodedNode tunnelledHeaders(String name, String v, Out out) {
        DecodedNode n = DecodedNode.object(name);
        JsonElement j = v.strip().startsWith("{") ? Fb.parse(v) : null;
        if (j != null && j.isJsonObject()) {
            for (Map.Entry<String, JsonElement> en : j.getAsJsonObject().entrySet()) n.add(headerNode(en.getKey(), prim(en.getValue()), out));
            return n;
        }
        for (String line : v.split("\r?\n")) {
            int c = line.indexOf(':');
            if (c <= 0) continue;
            n.add(headerNode(line.substring(0, c).strip(), line.substring(c + 1).strip(), out));
        }
        return n;
    }

    static DecodedNode headerNode(String name, String value, Out out) {
        if (value == null) return DecodedNode.leaf(name, null);
        String v = value;
        if (v.regionMatches(true, 0, "Bearer ", 0, 7)) v = v.substring(7).strip();
        if (Fb.Jwt.looksLike(v)) {
            DecodedNode j = Fb.Jwt.node(name, v);
            if (j != null) return j;
        }
        return DecodedNode.leaf(name, value);
    }

    private static DecodeResult channelResponse(MessageContext m, String stream, Out out) throws DecodeException {
        String body = Fb.text(m.responseBody(), m.responseHeader("Content-Encoding"));
        DecodedNode root = DecodedNode.object("Firestore " + stream + " WebChannel response");
        List<JsonElement> batches = new ArrayList<>();
        if (ChunkedJson.looksChunked(body, 0)) {
            ChunkedJson.Result r = ChunkedJson.parse(body, 0);
            out.warnings.addAll(r.warnings());
            root.put("Framing", r.chunks().size() + " length-prefixed chunks");
            for (ChunkedJson.Chunk c : r.chunks()) {
                if (c.json() != null) batches.add(c.json());
                else root.add(DecodedNode.leaf("Unparsed chunk @" + c.offset(), Codecs.truncate(c.raw(), 4000)));
            }
        } else if (!body.isBlank()) {
            JsonElement j = Fb.parse(body);
            if (j == null) throw new DecodeException("Firestore WebChannel response is neither length-chunked nor JSON");
            root.put("Framing", "single JSON body");
            batches.add(j);
        } else {
            return new DecodeResult("Firestore " + stream + " response: empty", root, null, out.warnings);
        }

        DecodedNode msgs = DecodedNode.array("Messages");
        root.add(msgs);
        Map<String, Integer> counts = new LinkedHashMap<>();
        List<String> docs = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        int total = 0;
        for (JsonElement b : batches) {
            JsonArray a = b.isJsonArray() ? b.getAsJsonArray() : null;
            if (a != null && isAck(a)) {
                DecodedNode n = DecodedNode.object("Forward-channel ack");
                n.put("backchannel present", prim(a.get(0)));
                n.put("last array id", prim(a.get(1)));
                n.put("outstanding bytes", prim(a.get(2)));
                msgs.add(n);
                counts.merge("ack", 1, Integer::sum);
                continue;
            }
            if (a == null || !isArrayBatch(a)) {
                msgs.add(Fb.node("message", b, true, out, 0));
                continue;
            }
            for (JsonElement entry : a) {
                if (++total > MAX_MESSAGES) {
                    out.warn("stopped after " + MAX_MESSAGES + " messages");
                    break;
                }
                JsonArray e = entry.getAsJsonArray();
                String id = prim(e.get(0));
                payload(id, e.get(1), msgs, counts, docs, errors, out);
            }
        }
        List<String> cs = new ArrayList<>();
        for (Map.Entry<String, Integer> c : counts.entrySet()) cs.add(c.getValue() + " " + c.getKey());
        String summary = "Firestore " + stream + " response: " + (cs.isEmpty() ? "no messages" : String.join(", ", cs));
        if (!docs.isEmpty()) summary += " (" + commonName(docs) + ")";
        if (!errors.isEmpty()) summary += " — " + errors.get(0);
        return new DecodeResult(summary, root, null, out.warnings);
    }

    private static boolean isAck(JsonArray a) {
        if (a.size() != 3) return false;
        for (JsonElement e : a) if (!e.isJsonPrimitive() || !e.getAsJsonPrimitive().isNumber()) return false;
        return true;
    }

    private static boolean isArrayBatch(JsonArray a) {
        if (a.isEmpty()) return false;
        for (JsonElement e : a) {
            if (!e.isJsonArray() || e.getAsJsonArray().size() != 2) return false;
            JsonElement id = e.getAsJsonArray().get(0);
            if (!id.isJsonPrimitive() || !id.getAsJsonPrimitive().isNumber()) return false;
        }
        return true;
    }

    private static void payload(String id, JsonElement p, DecodedNode msgs, Map<String, Integer> counts,
                                List<String> docs, List<String> errors, Out out) {
        JsonArray a = p.isJsonArray() ? p.getAsJsonArray() : null;
        if (a != null && !a.isEmpty() && a.get(0).isJsonPrimitive() && a.get(0).getAsJsonPrimitive().isString()) {
            String cmd = a.get(0).getAsString();
            DecodedNode n;
            switch (cmd) {
                case "c" -> {
                    n = DecodedNode.object("#" + id + " create session");
                    String[] labels = {"command", "session id (SID)", "host prefix", "protocol version", "server version", "server keep-alive (ms)"};
                    for (int i = 1; i < a.size(); i++) n.add(Fb.node(i < labels.length ? labels[i] : "[" + i + "]", a.get(i), false, out, 1));
                    counts.merge("session created", 1, Integer::sum);
                }
                case "noop" -> {
                    n = DecodedNode.leaf("#" + id + " noop", "keep-alive");
                    counts.merge("noop", 1, Integer::sum);
                }
                case "close", "stop" -> {
                    n = DecodedNode.leaf("#" + id + " " + cmd, "server closed the channel");
                    counts.merge(cmd, 1, Integer::sum);
                }
                default -> {
                    n = Fb.node("#" + id + " " + cmd, a, true, out, 0);
                    counts.merge(cmd, 1, Integer::sum);
                }
            }
            msgs.add(n);
            return;
        }
        List<JsonElement> items = new ArrayList<>();
        if (a != null) a.forEach(items::add);
        else items.add(p);
        for (JsonElement item : items) {
            JsonObject o = obj(item);
            if (o == null) {
                msgs.add(Fb.node("#" + id, item, true, out, 0));
                continue;
            }
            String type = messageType(o);
            String label = type;
            JsonObject tc = obj(o, "targetChange");
            if (tc != null) label += " (" + (str(tc, "targetChangeType") == null ? "NO_CHANGE" : str(tc, "targetChangeType")) + ")";
            JsonObject dc = obj(o, "documentChange");
            if (dc != null) addDoc(docs, str(obj(dc, "document"), "name"));
            JsonObject dd = obj(o, "documentDelete");
            if (dd != null) addDoc(docs, str(dd, "document"));
            JsonObject dr = obj(o, "documentRemove");
            if (dr != null) addDoc(docs, str(dr, "document"));
            String err = error(o);
            if (err != null) errors.add(err);
            if (tc != null && obj(tc, "cause") != null) errors.add("targetChange cause: " + str(obj(tc, "cause"), "message"));
            counts.merge(type, 1, Integer::sum);
            msgs.add(Fb.node("#" + id + " " + label, o, true, out, 0));
        }
    }

    private static void addDoc(List<String> docs, String name) {
        if (name != null && docs.size() < 10_000) docs.add(name);
    }

    static String messageType(JsonObject o) {
        for (String k : List.of("targetChange", "documentChange", "documentDelete", "documentRemove", "filter")) {
            if (o.has(k)) return k;
        }
        if (o.has("writeResults") || o.has("streamToken") || o.has("streamId")) {
            JsonArray wr = arr(o, "writeResults");
            return wr == null ? "writeResponse" : "writeResponse (" + wr.size() + " results)";
        }
        if (o.has("error") || o.has("__sm__")) return "error";
        String k = Fb.firstKey(o);
        return k == null ? "{}" : k;
    }

    /** Google RPC status → "error 7 PERMISSION_DENIED: …", or null. */
    static String error(JsonObject o) {
        JsonObject e = obj(o, "error");
        if (e == null) {
            JsonObject sm = obj(o, "__sm__");
            JsonArray st = sm == null ? null : arr(sm, "status");
            if (st != null && !st.isEmpty()) e = obj(st.get(0));
        }
        if (e == null) return null;
        String code = str(e, "code"), status = str(e, "status"), msg = str(e, "message");
        return "error " + (code == null ? "" : code + " ") + (status == null ? "" : status + ": ") + (msg == null ? "" : msg);
    }

    /** One name, or the longest common prefix ending at '/' followed by "…". */
    static String commonName(List<String> names) {
        String first = names.get(0);
        boolean same = true;
        for (String n : names) if (!n.equals(first)) { same = false; break; }
        if (same) return first;
        String p = first;
        for (String n : names) {
            int i = 0;
            while (i < p.length() && i < n.length() && p.charAt(i) == n.charAt(i)) i++;
            p = p.substring(0, i);
        }
        int slash = p.lastIndexOf('/');
        return (slash >= 0 ? p.substring(0, slash + 1) : p) + "…";
    }

    // ---------------------------------------------------------------- REST

    static DecodeResult decodeRest(MessageContext m, Out out) throws DecodeException {
        String path = Codecs.urlDecode(m.path());
        int pi = path.indexOf("/projects/");
        String resource = pi >= 0 ? path.substring(pi + 1) : path;
        String rpc = null;
        int lastSlash = resource.lastIndexOf('/');
        int colon = resource.indexOf(':', Math.max(0, lastSlash));
        if (colon >= 0) {
            rpc = resource.substring(colon + 1);
            resource = resource.substring(0, colon);
        }
        String doc = docPath(resource);
        if (m.isResponse()) return restResponse(m, rpc, doc, out);

        DecodedNode root = DecodedNode.object("Firestore REST request");
        DecodedNode ep = root.child("Endpoint");
        ep.put("HTTP method", m.method());
        ep.put("Resource", resource);
        if (rpc != null) ep.put("RPC", rpc);
        int di = resource.indexOf("/documents");
        if (di > 0) ep.put("Database", resource.substring(0, di));
        if (!doc.isEmpty()) ep.put("Document / collection path", doc);
        FirebaseDecoder.queryParams(m, ep, out);
        FirebaseDecoder.authHeaders(m, root, out);
        String body = Fb.text(m.requestBody(), m.requestHeader("Content-Encoding"));
        JsonElement j = body.isBlank() ? null : Fb.parse(body);
        if (j != null) root.add(Fb.node("Body", j, true, out, 0));
        else if (!body.isBlank()) root.add(DecodedNode.leaf("Body", Codecs.truncate(body, 20_000)));

        String target = doc.isEmpty() ? "(root)" : doc;
        String summary;
        if (rpc == null) {
            String verb = switch (m.method()) {
                case "GET" -> "get";
                case "PATCH" -> "update";
                case "DELETE" -> "delete";
                case "POST" -> "create in";
                default -> m.method();
            };
            summary = "Firestore REST " + verb + " " + target;
        } else {
            JsonObject sq = obj(j, "structuredQuery");
            JsonObject saq = obj(j, "structuredAggregationQuery");
            if (sq == null && saq != null) sq = obj(saq, "structuredQuery");
            JsonArray writes = arr(j, "writes");
            JsonArray docs = arr(j, "documents");
            JsonObject add = obj(j, "addTarget");
            String detail;
            if (sq != null) detail = describeQuery(sq, doc);
            else if (writes != null) detail = describeWrites(writes);
            else if (docs != null) detail = docs.size() + " documents";
            else if (add != null) detail = describeTarget(add);
            else detail = target;
            summary = "Firestore REST " + rpc + ": " + detail;
        }
        return new DecodeResult(summary, root, null, out.warnings);
    }

    private static DecodeResult restResponse(MessageContext m, String rpc, String doc, Out out) throws DecodeException {
        String body = Fb.text(m.responseBody(), m.responseHeader("Content-Encoding"));
        DecodedNode root = DecodedNode.object("Firestore REST response");
        if (body.isBlank()) return new DecodeResult("Firestore REST response: empty", root, null, out.warnings);
        JsonElement j = Fb.parse(body);
        if (j == null) throw new DecodeException("Firestore REST response is not JSON");
        root.add(Fb.node("Body", j, true, out, 0));
        String what = rpc == null ? "" : rpc + " ";
        String summary;
        JsonObject o = obj(j);
        if (o != null && error(o) != null) {
            summary = "Firestore REST " + what + "response: " + error(o);
        } else if (j.isJsonArray()) {
            int docs = 0;
            List<String> names = new ArrayList<>();
            for (JsonElement e : j.getAsJsonArray()) {
                JsonObject d = obj(e, "document");
                if (d == null) d = obj(e, "found");
                if (d != null) { docs++; addDoc(names, str(d, "name")); }
                JsonObject eo = obj(e);
                if (eo != null && error(eo) != null) names.clear();
            }
            summary = "Firestore REST " + what + "response: " + docs + (docs == 1 ? " document" : " documents")
                    + (names.isEmpty() ? "" : " (" + commonName(names) + ")");
        } else if (o != null && arr(o, "documents") != null) {
            JsonArray docs = arr(o, "documents");
            summary = "Firestore REST " + what + "response: " + docs.size() + " documents" + (o.has("nextPageToken") ? " (more pages)" : "");
        } else if (o != null && o.has("name") && (o.has("fields") || o.has("createTime"))) {
            JsonObject f = obj(o, "fields");
            summary = "Firestore REST response: document " + docPath(str(o, "name")) + " (" + (f == null ? 0 : f.size()) + " fields)";
        } else if (o != null && arr(o, "writeResults") != null) {
            summary = "Firestore REST " + what + "response: " + arr(o, "writeResults").size() + " write results";
        } else {
            summary = "Firestore REST " + what + "response" + (doc.isEmpty() ? "" : " for " + doc);
        }
        return new DecodeResult(summary, root, null, out.warnings);
    }
}
