package protocoldecoder.builtin.nextjs;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * React Server Components "Flight" wire format (React 18/19 as used by the Next.js App Router): newline-separated rows
 * {@code <hex id>:<tag><payload>}, where text and typed-array rows are length-prefixed ({@code T<hex bytes>,<data>}) and
 * not newline-terminated. Parsing is lenient: unknown tags are kept, unparseable lines are counted and reported.
 */
final class Flight {

    static final int MAX_ROWS = 20_000;
    static final int MAX_NODES = 60_000;
    static final int MAX_STRING = 20_000;
    private static final int MAX_DEPTH = 80;

    /** Tags whose payload is {@code <hex length>,<bytes>} rather than a newline-terminated line. */
    private static final String LENGTH_TAGS = "TAOoUSsLlGgMmVB";

    enum Kind { MODEL, IMPORT, HINT, ERROR, TEXT, BINARY, DEBUG, CONSOLE, TIMESTAMP, POSTPONE, STREAM, SYMBOL, OTHER }

    record Row(String id, String tag, Kind kind, JsonElement json, String raw, boolean lengthPrefixed) {
        String tagLabel() {
            return Flight.tagLabel(tag, lengthPrefixed);
        }
    }

    static final class Parsed {
        final List<Row> rows = new ArrayList<>();
        final Map<String, Row> byId = new HashMap<>();
        final List<String> problems = new ArrayList<>();
        int badLines;
        boolean truncated;

        int count(Kind k) {
            int n = 0;
            for (Row r : rows) if (r.kind == k) n++;
            return n;
        }

        void problem(String p) {
            if (problems.size() < 20) problems.add(p);
        }
    }

    private Flight() {
    }

    // ---------------------------------------------------------------- sniffing

    /** Cheap check: does the text start like a Flight stream (first non-blank line is {@code <hex>:}...)? */
    static boolean looksLikeFlight(String s) {
        if (s == null) return false;
        int i = 0, n = Math.min(s.length(), 4096);
        while (i < n && (s.charAt(i) == '\n' || s.charAt(i) == '\r')) i++;
        int j = i;
        while (j < n && j - i < 8 && isHex(s.charAt(j))) j++;
        if (j == i || j >= n || s.charAt(j) != ':') return false;
        if (j + 1 >= n) return false;
        char c = s.charAt(j + 1);
        return c == '[' || c == '{' || c == '"' || Character.isLetter(c) || Character.isDigit(c) || c == '-';
    }

    // ---------------------------------------------------------------- parsing

    static Parsed parse(String s) {
        Parsed p = new Parsed();
        if (s == null) return p;
        int n = s.length();
        int i = 0;
        while (i < n) {
            if (p.rows.size() >= MAX_ROWS) {
                p.truncated = true;
                p.problem("Stopped after " + MAX_ROWS + " rows");
                break;
            }
            char c = s.charAt(i);
            if (c == '\n' || c == '\r') {
                i++;
                continue;
            }
            int j = i;
            while (j < n && j - i < 9 && isHex(s.charAt(j))) j++;
            if (j == i || j >= n || s.charAt(j) != ':') {
                p.badLines++;
                p.problem("Unparseable data at offset " + i + ": " + Codecs.truncate(lineAt(s, i), 80));
                i = nextLine(s, i);
                continue;
            }
            String id = s.substring(i, j);
            int pos = j + 1;
            String tag = "";
            if (pos < n && Character.isLetter(s.charAt(pos)) && !startsWithJsonLiteral(s, pos)) {
                char t = s.charAt(pos);
                if (t == 'H' && pos + 1 < n && Character.isLetter(s.charAt(pos + 1))) {
                    tag = "H" + s.charAt(pos + 1);
                    pos += 2;
                } else {
                    tag = String.valueOf(t);
                    pos++;
                }
            }
            if (tag.length() == 1 && LENGTH_TAGS.indexOf(tag.charAt(0)) >= 0) {
                int k = pos;
                while (k < n && k - pos < 12 && isHex(s.charAt(k))) k++;
                if (k > pos && k < n && s.charAt(k) == ',') {
                    long len = Long.parseLong(s.substring(pos, k), 16);
                    int start = k + 1;
                    int[] got = new int[1];
                    int end = advanceBytes(s, start, len, got);
                    if (got[0] < len) {
                        p.problem("Row " + id + " declares " + len + " bytes but only " + got[0] + " are present");
                    }
                    Kind kind = tag.equals("T") ? Kind.TEXT : Kind.BINARY;
                    add(p, new Row(id, tag, kind, null, s.substring(start, end), true));
                    i = end;
                    continue;
                }
            }
            int eol = s.indexOf('\n', pos);
            if (eol < 0) eol = n;
            String payload = s.substring(pos, eol);
            if (payload.endsWith("\r")) payload = payload.substring(0, payload.length() - 1);
            JsonElement json = payload.isEmpty() ? null : JsonTree.parseStrict(payload);
            if (json == null && !payload.isEmpty()) {
                p.problem("Row " + id + (tag.isEmpty() ? "" : " (" + tag + ")") + " is not valid JSON");
                if (tag.isEmpty()) p.badLines++;
            }
            add(p, new Row(id, tag, kindOf(tag), json, json == null ? payload : null, false));
            i = eol + 1;
        }
        return p;
    }

    private static void add(Parsed p, Row r) {
        p.rows.add(r);
        p.byId.putIfAbsent(r.id, r);
    }

    private static boolean startsWithJsonLiteral(String s, int pos) {
        return s.startsWith("true", pos) || s.startsWith("false", pos) || s.startsWith("null", pos);
    }

    private static String lineAt(String s, int i) {
        int e = s.indexOf('\n', i);
        return s.substring(i, e < 0 ? Math.min(s.length(), i + 200) : Math.min(e, i + 200));
    }

    private static int nextLine(String s, int i) {
        int e = s.indexOf('\n', i);
        return e < 0 ? s.length() : e + 1;
    }

    /** Advances over {@code bytes} UTF-8 bytes starting at {@code start}; returns the end index. */
    static int advanceBytes(String s, int start, long bytes, int[] consumed) {
        int i = start;
        long b = 0;
        while (i < s.length() && b < bytes) {
            char c = s.charAt(i);
            if (c < 0x80) b += 1;
            else if (c < 0x800) b += 2;
            else if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                b += 4;
                i++;
            } else b += 3;
            i++;
        }
        consumed[0] = (int) Math.min(Integer.MAX_VALUE, b);
        return i;
    }

    static boolean isHex(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    static Kind kindOf(String tag) {
        if (tag.isEmpty()) return Kind.MODEL;
        if (tag.startsWith("H")) return Kind.HINT;
        return switch (tag) {
            case "I" -> Kind.IMPORT;
            case "E" -> Kind.ERROR;
            case "T" -> Kind.TEXT;
            case "D", "J" -> Kind.DEBUG;
            case "W" -> Kind.CONSOLE;
            case "N" -> Kind.TIMESTAMP;
            case "P" -> Kind.POSTPONE;
            case "R", "r", "X", "x", "C" -> Kind.STREAM;
            case "S" -> Kind.SYMBOL;
            default -> Kind.OTHER;
        };
    }

    static String tagLabel(String tag, boolean lengthPrefixed) {
        if (tag.isEmpty()) return "model";
        if (tag.startsWith("H")) {
            return "hint: " + switch (tag) {
                case "HL" -> "preload";
                case "HD" -> "DNS prefetch";
                case "HC" -> "preconnect";
                case "Hm" -> "preload module";
                case "HS" -> "preinit stylesheet";
                case "HX" -> "preinit script";
                case "HM" -> "preinit module script";
                default -> tag.substring(1);
            };
        }
        if (lengthPrefixed) {
            return switch (tag) {
                case "T" -> "text chunk";
                case "A" -> "ArrayBuffer";
                case "O" -> "Int8Array";
                case "o" -> "Uint8Array";
                case "U" -> "Uint8ClampedArray";
                case "S" -> "Int16Array";
                case "s" -> "Uint16Array";
                case "L" -> "Int32Array";
                case "l" -> "Uint32Array";
                case "G" -> "Float32Array";
                case "g" -> "Float64Array";
                case "M" -> "BigInt64Array";
                case "m" -> "BigUint64Array";
                case "V" -> "DataView";
                default -> "binary (" + tag + ")";
            };
        }
        return switch (tag) {
            case "I" -> "client module reference";
            case "E" -> "error";
            case "T" -> "text";
            case "D" -> "debug info (dev)";
            case "J" -> "I/O info (dev)";
            case "W" -> "console replay (dev)";
            case "N" -> "time origin";
            case "P" -> "postponed (PPR)";
            case "R" -> "ReadableStream start";
            case "r" -> "byte ReadableStream start";
            case "X" -> "AsyncIterable start";
            case "x" -> "AsyncIterator start";
            case "C" -> "stream close";
            case "S" -> "symbol";
            default -> "tag " + tag;
        };
    }

    // ---------------------------------------------------------------- analysis

    record ClientModule(String rowId, String moduleId, String exportName, List<String> chunks, boolean async) {
        String label() {
            String n = exportName == null || exportName.isEmpty() ? "default" : exportName;
            return n + " @ " + moduleId + (async ? " (async)" : "");
        }
    }

    static ClientModule clientModule(Row r) {
        if (r.kind != Kind.IMPORT || r.json == null) return null;
        String id = null, name = null;
        boolean async = false;
        List<String> chunks = new ArrayList<>();
        JsonElement chunksEl = null;
        if (r.json.isJsonArray()) {
            JsonArray a = r.json.getAsJsonArray();
            if (a.size() > 0) id = str(a.get(0));
            if (a.size() > 1) chunksEl = a.get(1);
            if (a.size() > 2) name = str(a.get(2));
            if (a.size() > 3 && a.get(3).isJsonPrimitive() && a.get(3).getAsJsonPrimitive().isBoolean()) async = a.get(3).getAsBoolean();
        } else if (r.json.isJsonObject()) {
            JsonObject o = r.json.getAsJsonObject();
            id = str(o.get("id"));
            name = str(o.get("name"));
            chunksEl = o.get("chunks");
            if (o.has("async") && o.get("async").isJsonPrimitive() && o.get("async").getAsJsonPrimitive().isBoolean()) async = o.get("async").getAsBoolean();
        }
        if (chunksEl != null && chunksEl.isJsonArray()) {
            for (JsonElement c : chunksEl.getAsJsonArray()) {
                String cs = str(c);
                if (cs != null && chunks.size() < 200) chunks.add(cs);
            }
        }
        return new ClientModule(r.id, id == null ? "?" : id, name, chunks, async);
    }

    record FlightError(String rowId, String digest, String message) {
    }

    static FlightError error(Row r) {
        if (r.kind != Kind.ERROR) return null;
        if (r.json == null || !r.json.isJsonObject()) return new FlightError(r.id, null, r.raw);
        JsonObject o = r.json.getAsJsonObject();
        return new FlightError(r.id, str(o.get("digest")), str(o.get("message")));
    }

    /** Server references ({@code {"id":..., "bound":...}} model rows), i.e. Server Action IDs exposed to the client. */
    static List<String> serverReferences(Parsed p) {
        List<String> out = new ArrayList<>();
        for (Row r : p.rows) {
            if (r.kind == Kind.MODEL && r.json != null && r.json.isJsonObject()) {
                JsonObject o = r.json.getAsJsonObject();
                if (o.has("id") && o.has("bound") && o.get("id").isJsonPrimitive() && out.size() < 200) {
                    out.add(o.get("id").getAsString());
                }
            }
        }
        return out;
    }

    /** Next.js-specific fields of the root (row 0) payload. Lenient: the shape changed between Next 13, 14 and 15. */
    static Map<String, String> nextRoot(Parsed p) {
        Map<String, String> out = new LinkedHashMap<>();
        Row r = p.byId.get("0");
        if (r == null || r.kind != Kind.MODEL || r.json == null) return out;
        JsonElement j = r.json;
        if (j.isJsonObject()) {
            JsonObject o = j.getAsJsonObject();
            putStr(out, "Build ID", o.get("b"));
            putStr(out, "Server Action result", o.get("a"));
            putStr(out, "Asset prefix", o.get("p"));
            if (o.has("c") && o.get("c").isJsonArray()) out.put("Canonical URL", joinSegments(o.getAsJsonArray("c")));
            if (o.has("i")) out.put("Could be intercepted", o.get("i").toString());
            if (o.has("f")) out.put("Flight data (router)", o.get("f").isJsonArray() ? o.getAsJsonArray("f").size() + " entries" : o.get("f").toString());
        } else if (j.isJsonArray()) {
            JsonArray a = j.getAsJsonArray();
            if (a.size() >= 2) {
                String first = str(a.get(0));
                if (first != null && first.startsWith("$@")) {
                    out.put("Server Action result", first);
                    if (a.get(1).isJsonArray() && a.get(1).getAsJsonArray().size() > 0) {
                        String b = str(a.get(1).getAsJsonArray().get(0));
                        if (b != null && plausibleBuildId(b)) out.put("Build ID", b);
                    }
                } else if (first != null && plausibleBuildId(first) && a.get(1).isJsonArray()) {
                    out.put("Build ID", first);
                    out.put("Flight data (router)", a.get(1).getAsJsonArray().size() + " entries");
                }
            }
        }
        return out;
    }

    private static boolean plausibleBuildId(String s) {
        return !s.isEmpty() && s.length() <= 64 && !s.startsWith("$") && s.matches("[A-Za-z0-9_\\-.]+");
    }

    private static String joinSegments(JsonArray a) {
        List<String> parts = new ArrayList<>();
        for (JsonElement e : a) {
            String s = str(e);
            if (s != null) parts.add(s);
        }
        String j = String.join("/", parts);
        return j.startsWith("/") ? j : "/" + j;
    }

    private static void putStr(Map<String, String> out, String k, JsonElement e) {
        String s = str(e);
        if (s != null) out.put(k, s);
    }

    static String str(JsonElement e) {
        return e != null && e.isJsonPrimitive() ? e.getAsString() : null;
    }

    // ---------------------------------------------------------------- summary & tree

    static String summary(Parsed p) {
        StringBuilder sb = new StringBuilder();
        sb.append(p.rows.size()).append(p.rows.size() == 1 ? " row" : " rows");
        int modules = p.count(Kind.IMPORT), hints = p.count(Kind.HINT), texts = p.count(Kind.TEXT);
        if (modules > 0) sb.append(", ").append(modules).append(modules == 1 ? " client module" : " client modules");
        if (hints > 0) sb.append(", ").append(hints).append(hints == 1 ? " hint" : " hints");
        if (texts > 0) sb.append(", ").append(texts).append(texts == 1 ? " text chunk" : " text chunks");
        List<String> refs = serverReferences(p);
        if (!refs.isEmpty()) sb.append(", ").append(refs.size()).append(refs.size() == 1 ? " server reference" : " server references");
        List<FlightError> errors = new ArrayList<>();
        for (Row r : p.rows) {
            FlightError e = error(r);
            if (e != null) errors.add(e);
        }
        if (!errors.isEmpty()) {
            sb.append(", ").append(errors.size()).append(errors.size() == 1 ? " ERROR" : " ERRORS");
            FlightError e = errors.get(0);
            if (e.digest != null) sb.append(" (digest ").append(e.digest).append(')');
            else if (e.message != null) sb.append(" (").append(Codecs.truncate(e.message, 60)).append(')');
        }
        String build = nextRoot(p).get("Build ID");
        if (build != null) sb.append(", build ").append(build);
        return sb.toString();
    }

    /** Builds the decoded tree: overview, client modules, errors, server references, then every row. */
    static DecodedNode tree(String name, Parsed p) {
        Render render = new Render(p);
        DecodedNode root = DecodedNode.object(name);

        DecodedNode ov = root.child("Overview");
        ov.put("Rows", p.rows.size());
        Map<Kind, Integer> counts = new LinkedHashMap<>();
        for (Row r : p.rows) counts.merge(r.kind, 1, Integer::sum);
        counts.forEach((k, v) -> ov.put(k.name().toLowerCase().replace('_', ' ') + " rows", v));
        Map<String, String> next = nextRoot(p);
        if (!next.isEmpty()) {
            DecodedNode nx = ov.child("Next.js root payload (row 0)");
            next.forEach(nx::put);
        }

        List<ClientModule> mods = new ArrayList<>();
        for (Row r : p.rows) {
            ClientModule cm = clientModule(r);
            if (cm != null) mods.add(cm);
        }
        if (!mods.isEmpty()) {
            DecodedNode mn = DecodedNode.array("Client modules (I rows)");
            for (ClientModule cm : mods) {
                DecodedNode c = new DecodedNode("row " + cm.rowId, cm.label(), DecodedNode.Type.OBJECT);
                c.put("Module ID", cm.moduleId);
                c.put("Export", cm.exportName == null || cm.exportName.isEmpty() ? "default" : cm.exportName);
                if (!cm.chunks.isEmpty()) {
                    DecodedNode ch = DecodedNode.array("Chunks");
                    for (String s : cm.chunks) ch.add(DecodedNode.leaf("", s));
                    c.add(ch);
                }
                if (cm.async) c.put("Async", true);
                mn.add(c);
            }
            root.add(mn);
        }

        DecodedNode errs = DecodedNode.array("Errors (E rows)");
        for (Row r : p.rows) {
            FlightError e = error(r);
            if (e == null) continue;
            DecodedNode en = DecodedNode.object("row " + e.rowId);
            en.put("Digest — server error log correlation ID", e.digest);
            en.put("Message", e.message);
            if (r.json != null && r.json.isJsonObject()) {
                JsonObject o = r.json.getAsJsonObject();
                for (String k : o.keySet()) {
                    if (!k.equals("digest") && !k.equals("message")) en.add(JsonTree.toNode(k, o.get(k), false));
                }
            }
            errs.add(en);
        }
        if (!errs.isLeaf()) root.add(errs);

        List<String> refs = serverReferences(p);
        if (!refs.isEmpty()) {
            DecodedNode sr = DecodedNode.array("Server references (Server Action IDs)");
            for (String s : refs) sr.add(DecodedNode.leaf("", s));
            root.add(sr);
        }

        DecodedNode rows = DecodedNode.array("Rows");
        for (Row r : p.rows) {
            if (render.exhausted()) {
                rows.add(DecodedNode.note("… remaining rows omitted (output limit)"));
                break;
            }
            rows.add(render.row(r));
        }
        root.add(rows);
        return root;
    }

    /** Converts row payloads to nodes, annotating {@code $}-references and React element tuples. Bounded output. */
    static final class Render {
        private final Parsed p;
        private int budget = MAX_NODES;
        private boolean noted;

        Render(Parsed p) {
            this.p = p;
        }

        boolean exhausted() {
            return budget <= 0;
        }

        DecodedNode row(Row r) {
            String name = "row " + r.id + " (" + r.tagLabel() + ")";
            budget--;
            if (r.kind == Kind.TEXT) return DecodedNode.leaf(name, Codecs.truncate(r.raw, MAX_STRING));
            if (r.kind == Kind.BINARY) {
                byte[] b = r.raw.getBytes(StandardCharsets.UTF_8);
                return DecodedNode.leaf(name, b.length + " bytes: " + Codecs.hexPreview(b, 64), DecodedNode.Type.BINARY);
            }
            if (r.json == null) return DecodedNode.leaf(name, Codecs.truncate(r.raw, MAX_STRING));
            return value(name, r.json, 0);
        }

        DecodedNode value(String name, JsonElement e, int depth) {
            if (budget-- <= 0) {
                if (noted) return null;
                noted = true;
                return DecodedNode.note("… output truncated (node limit)");
            }
            if (e == null || e.isJsonNull()) return DecodedNode.leaf(name, "null", DecodedNode.Type.NULL);
            if (depth > MAX_DEPTH) return DecodedNode.leaf(name, Codecs.truncate(e.toString(), 2000), DecodedNode.Type.NOTE);
            if (e.isJsonArray()) {
                JsonArray a = e.getAsJsonArray();
                if (isElement(a)) return element(name, a, depth);
                DecodedNode n = DecodedNode.array(name);
                for (int i = 0; i < a.size() && !exhausted(); i++) n.add(value("[" + i + "]", a.get(i), depth + 1));
                if (exhausted()) n.add(value("", null, depth + 1));
                return n;
            }
            if (e.isJsonObject()) {
                DecodedNode n = DecodedNode.object(name);
                for (Map.Entry<String, JsonElement> en : e.getAsJsonObject().entrySet()) {
                    if (exhausted()) {
                        n.add(value("", null, depth + 1));
                        break;
                    }
                    n.add(value(en.getKey(), en.getValue(), depth + 1));
                }
                return n;
            }
            JsonPrimitive prim = e.getAsJsonPrimitive();
            if (prim.isBoolean()) return DecodedNode.leaf(name, prim.getAsString(), DecodedNode.Type.BOOLEAN);
            if (prim.isNumber()) return DecodedNode.leaf(name, prim.getAsString(), DecodedNode.Type.NUMBER);
            String s = prim.getAsString();
            String ref = describeRef(s);
            if (ref != null) return DecodedNode.leaf(name, s + "  (" + ref + ")");
            return DecodedNode.leaf(name, Codecs.truncate(s, MAX_STRING));
        }

        private static boolean isElement(JsonArray a) {
            return a.size() >= 4 && a.get(0).isJsonPrimitive() && "$".equals(a.get(0).getAsString());
        }

        private DecodedNode element(String name, JsonArray a, int depth) {
            String type = a.get(1).isJsonPrimitive() ? a.get(1).getAsString() : a.get(1).toString();
            String key = a.get(2).isJsonNull() ? null : str(a.get(2));
            String label = "<" + elementType(type) + (key != null ? " key=\"" + key + "\"" : "") + ">";
            DecodedNode n = new DecodedNode(name.isEmpty() ? label : name + " " + label, "React element " + label, DecodedNode.Type.OBJECT);
            if (type.startsWith("$")) n.put("type", type + "  (" + describeRef(type) + ")");
            JsonElement props = a.get(3);
            if (props.isJsonObject()) {
                for (Map.Entry<String, JsonElement> en : props.getAsJsonObject().entrySet()) {
                    if (exhausted()) break;
                    n.add(value(en.getKey(), en.getValue(), depth + 1));
                }
            } else {
                n.add(value("props", props, depth + 1));
            }
            for (int i = 4; i < a.size() && !exhausted(); i++) {
                n.add(value(i == 4 ? "owner (dev)" : i == 5 ? "stack (dev)" : "[" + i + "]", a.get(i), depth + 1));
            }
            return n;
        }

        String elementType(String type) {
            if (type.startsWith("$S")) return type.substring(2);
            if (type.startsWith("$L") || type.startsWith("$@") || (type.length() > 1 && type.charAt(0) == '$' && isHex(type.charAt(1)))) {
                String id = type.substring(type.charAt(1) == 'L' || type.charAt(1) == '@' ? 2 : 1);
                Row r = p.byId.get(rowPart(id));
                ClientModule cm = r == null ? null : clientModule(r);
                if (cm != null) return cm.exportName == null || cm.exportName.isEmpty() || cm.exportName.equals("*") ? "client:" + cm.moduleId : cm.exportName;
            }
            return type;
        }

        String describeRef(String s) {
            if (s.length() < 1 || s.charAt(0) != '$') return null;
            if (s.equals("$")) return "React element marker";
            char c = s.charAt(1);
            String rest = s.substring(2);
            return switch (c) {
                case '$' -> "escaped literal string \"" + s.substring(1) + "\"";
                case '@' -> "promise → " + rowRef(rest);
                case 'L' -> "lazy → " + rowRef(rest);
                case 'F' -> "server reference → " + rowRef(rest);
                case 'h' -> "server reference → " + rowRef(rest);
                case 'T' -> "temporary reference";
                case 'Q' -> "Map → " + rowRef(rest);
                case 'W' -> "Set → " + rowRef(rest);
                case 'K' -> "FormData → " + rowRef(rest);
                case 'B' -> "Blob → " + rowRef(rest);
                case 'i' -> "iterator → " + rowRef(rest);
                case 'R', 'r' -> "ReadableStream → " + rowRef(rest);
                case 'X', 'x' -> "async iterable → " + rowRef(rest);
                case 'Z' -> "error → " + rowRef(rest);
                case 'S' -> "symbol " + rest;
                case 'n' -> "BigInt " + rest;
                case 'D' -> "Date " + rest;
                case 'N' -> s.equals("$NaN") ? "NaN" : null;
                case 'I' -> s.equals("$Infinity") ? "Infinity" : null;
                case '-' -> s.equals("$-0") ? "-0" : s.equals("$-Infinity") ? "-Infinity" : null;
                case 'u' -> s.equals("$undefined") ? "undefined" : null;
                case 'E' -> "server function (dev, eval'd source)";
                case 'Y' -> "omitted (dev)";
                case 'P' -> "postponed";
                default -> isHex(c) ? "reference → " + rowRef(s.substring(1)) : null;
            };
        }

        private static String rowPart(String ref) {
            int colon = ref.indexOf(':');
            return colon < 0 ? ref : ref.substring(0, colon);
        }

        private String rowRef(String ref) {
            String id = rowPart(ref);
            String path = ref.length() > id.length() ? " path " + ref.substring(id.length() + 1).replace(':', '.') : "";
            Row r = p.byId.get(id);
            if (r == null) return "row " + id + path;
            ClientModule cm = clientModule(r);
            if (cm != null) return "row " + id + path + ", client module " + cm.label();
            return "row " + id + path + " (" + r.tagLabel() + ")";
        }
    }
}
