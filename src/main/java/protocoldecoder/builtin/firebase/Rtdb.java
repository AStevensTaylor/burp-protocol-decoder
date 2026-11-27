package protocoldecoder.builtin.firebase;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import protocoldecoder.builtin.firebase.Fb.Out;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MessageContext;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsLiteral;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static protocoldecoder.builtin.firebase.Fb.obj;
import static protocoldecoder.builtin.firebase.Fb.prim;
import static protocoldecoder.builtin.firebase.Fb.str;

/** Firebase Realtime Database wire protocol (WebSocket and long-poll) and REST API. */
final class Rtdb {

    private Rtdb() {
    }

    private static final int MAX_FRAMES = 2000;

    static final Map<String, String> CLIENT_ACTIONS = Map.ofEntries(
            Map.entry("q", "listen"), Map.entry("n", "unlisten"), Map.entry("p", "put"), Map.entry("m", "merge"),
            Map.entry("g", "get"), Map.entry("auth", "auth (ID token)"), Map.entry("gauth", "gauth (OAuth access token)"),
            Map.entry("unauth", "unauth"), Map.entry("appcheck", "App Check token"), Map.entry("unappcheck", "remove App Check token"),
            Map.entry("s", "stats"), Map.entry("o", "onDisconnect put"), Map.entry("om", "onDisconnect merge"),
            Map.entry("oc", "onDisconnect cancel"));

    static final Map<String, String> SERVER_ACTIONS = Map.of(
            "d", "data update", "m", "merge update", "c", "listen revoked", "ac", "auth revoked",
            "apc", "App Check revoked", "sd", "security debug");

    static final Map<String, String> CONTROL = Map.of(
            "h", "handshake", "r", "reset (reconnect to host)", "s", "server shutdown", "e", "error",
            "p", "ping", "o", "pong", "n", "end of transmission", "a", "ack");

    private static final Map<String, String> BODY_FIELDS = Map.ofEntries(
            Map.entry("p", "path"), Map.entry("h", "hash"), Map.entry("q", "query"), Map.entry("t", "tag"),
            Map.entry("d", "data"), Map.entry("s", "status"), Map.entry("c", "stats"), Map.entry("cred", "credential"),
            Map.entry("token", "token"), Map.entry("authvar", "auth variable override"), Map.entry("w", "warnings"));

    private static final Map<String, String> QUERY_FIELDS = Map.ofEntries(
            Map.entry("i", "orderBy index"), Map.entry("sp", "startAt value"), Map.entry("sn", "startAt key"),
            Map.entry("ep", "endAt value"), Map.entry("en", "endAt key"), Map.entry("l", "limit"),
            Map.entry("vf", "viewFrom (l = limitToFirst, r = limitToLast)"), Map.entry("sin", "start inclusive"),
            Map.entry("ein", "end inclusive"));

    private static final Map<String, String> LP_PARAMS = Map.ofEntries(
            Map.entry("start", "Start a new session"), Map.entry("ser", "Serial / cache buster"), Map.entry("cb", "Callback id"),
            Map.entry("v", "Protocol version"), Map.entry("ns", "Namespace (database)"), Map.entry("id", "Connection id"),
            Map.entry("pw", "Connection password"), Map.entry("dframe", "Disconnect frame"), Map.entry("ls", "Last session id"),
            Map.entry("p", "App id"), Map.entry("ac", "App Check token"), Map.entry("lp", "Long-poll marker"));

    private static final Map<String, String> REST_PARAMS = Map.ofEntries(
            Map.entry("auth", "Auth token (ID token or database secret)"), Map.entry("access_token", "OAuth2 access token"),
            Map.entry("orderBy", "Order by"), Map.entry("equalTo", "Equal to"), Map.entry("startAt", "Start at"),
            Map.entry("startAfter", "Start after"), Map.entry("endAt", "End at"), Map.entry("endBefore", "End before"),
            Map.entry("limitToFirst", "Limit to first"), Map.entry("limitToLast", "Limit to last"),
            Map.entry("shallow", "Shallow (keys only)"), Map.entry("print", "Output formatting"),
            Map.entry("format", "Format (export = include priorities)"), Map.entry("download", "Download as file"),
            Map.entry("timeout", "Read timeout"), Map.entry("writeSizeLimit", "Write size limit"),
            Map.entry("x-http-method", "Method override"), Map.entry("ns", "Namespace"));

    private static final Pattern LP_COMMAND = Pattern.compile("pLPCommand\\(\\s*['\"]([^'\"]*)['\"]((?:\\s*,\\s*['\"][^'\"]*['\"])*)\\s*\\)");
    private static final Pattern LP_ARG = Pattern.compile("['\"]([^'\"]*)['\"]");
    private static final Pattern SEG = Pattern.compile("^(seg|ts|d)(\\d{1,5})$");

    // ---------------------------------------------------------------- frames

    /** Decodes one protocol frame into {@code into}; returns a summary fragment. */
    static String frame(JsonElement f, Boolean fromClient, DecodedNode into, Out out) {
        JsonObject o = obj(f);
        String t = str(o, "t");
        JsonObject d = obj(o, "d");
        if ("c".equals(t) && d != null) {
            String ct = str(d, "t");
            String label = CONTROL.getOrDefault(ct == null ? "" : ct, "control '" + ct + "'");
            DecodedNode n = new DecodedNode("control: " + label, null, DecodedNode.Type.OBJECT);
            n.put("type", ct + " — " + label);
            JsonElement cd = d.get("d");
            String detail = "";
            if ("h".equals(ct)) {
                JsonObject h = obj(cd);
                if (h != null) {
                    n.add(Fb.timeLeaf("ts — server time", str(h, "ts")));
                    n.put("v — protocol version", str(h, "v"));
                    n.put("h — host", str(h, "h"));
                    n.put("s — session id", str(h, "s"));
                    detail = " (host " + str(h, "h") + ", session " + str(h, "s") + ")";
                }
            } else if (cd != null) {
                n.add(Fb.node("data", cd, false, out, 1));
                if (prim(cd) != null) detail = ": " + Codecs.truncate(prim(cd), 80);
            }
            into.add(n);
            return "control: " + label + detail;
        }
        if ("d".equals(t) && d != null) {
            String a = str(d, "a");
            String r = str(d, "r");
            JsonObject b = obj(d, "b");
            if (a == null && r != null) {
                String status = str(b, "s");
                DecodedNode n = new DecodedNode("response r=" + r, status, DecodedNode.Type.OBJECT);
                n.put("r — request number", r);
                body(b, n, out);
                into.add(n);
                String detail = status == null ? "" : ": " + status;
                if (status != null && !"ok".equals(status) && prim(b == null ? null : b.get("d")) != null) {
                    detail += " (" + Codecs.truncate(prim(b.get("d")), 80) + ")";
                }
                return "response r=" + r + detail;
            }
            boolean client = fromClient != null ? fromClient : r != null;
            String name = a == null ? "data" : (client ? CLIENT_ACTIONS : SERVER_ACTIONS).getOrDefault(a, "action '" + a + "'");
            DecodedNode n = new DecodedNode(name, null, DecodedNode.Type.OBJECT);
            n.put("a — action", a + " — " + name);
            if (r != null) n.put("r — request number", r);
            body(b, n, out);
            into.add(n);
            String path = str(b, "p");
            StringBuilder s = new StringBuilder(name);
            if (path != null) s.append(' ').append(path.startsWith("/") ? path : "/" + path);
            JsonObject q = obj(b, "q");
            if (q != null && !q.isEmpty()) s.append(" [").append(describeQuery(q)).append(']');
            String cred = str(b, "cred");
            if (cred != null) {
                Fb.Jwt.Parsed jp = Fb.Jwt.parse(cred);
                s.append(jp != null ? ": " + Fb.Jwt.describe(jp) : ": opaque credential");
            }
            if (r != null) s.append(" (r=").append(r).append(')');
            return s.toString();
        }
        into.add(Fb.node("frame", f, false, out, 0));
        return "frame";
    }

    private static void body(JsonObject b, DecodedNode n, Out out) {
        if (b == null) return;
        for (Map.Entry<String, JsonElement> en : b.entrySet()) {
            String label = BODY_FIELDS.get(en.getKey());
            String name = label == null ? en.getKey() : en.getKey() + " — " + label;
            if (en.getKey().equals("q") && en.getValue().isJsonObject()) {
                DecodedNode q = DecodedNode.object(name);
                for (Map.Entry<String, JsonElement> qe : en.getValue().getAsJsonObject().entrySet()) {
                    String ql = QUERY_FIELDS.get(qe.getKey());
                    q.add(Fb.node(ql == null ? qe.getKey() : qe.getKey() + " — " + ql, qe.getValue(), false, out, 2));
                }
                n.add(q);
            } else {
                n.add(Fb.node(name, en.getValue(), false, out, 1));
            }
        }
    }

    static String describeQuery(JsonObject q) {
        List<String> parts = new ArrayList<>();
        String i = str(q, "i");
        if (i != null) parts.add("orderBy " + i);
        String sp = q.has("sp") ? q.get("sp").toString() : null;
        String ep = q.has("ep") ? q.get("ep").toString() : null;
        if (sp != null && sp.equals(ep)) parts.add("equalTo " + sp);
        else {
            if (sp != null) parts.add("startAt " + sp);
            if (ep != null) parts.add("endAt " + ep);
        }
        String l = str(q, "l");
        if (l != null) parts.add(("r".equals(str(q, "vf")) ? "limitToLast " : "limitToFirst ") + l);
        if (parts.isEmpty()) parts.add(String.join(",", q.keySet()));
        return String.join(", ", parts);
    }

    private static Boolean fromClient(MessageContext m) {
        String d = m.webSocketDirection();
        if (d == null) return null;
        return d.toUpperCase(Locale.ROOT).startsWith("CLIENT");
    }

    // ---------------------------------------------------------------- WebSocket

    static DecodeResult decodeWs(MessageContext m, boolean rtdbHost, Out out) throws DecodeException {
        String s = m.bodyText().strip();
        DecodedNode root = DecodedNode.object("Firebase RTDB frame");
        if (rtdbHost) root.put("Namespace", ns(m));
        if (s.matches("\\d{1,6}")) {
            if (!rtdbHost) throw new DecodeException("Not a Firebase Realtime Database frame");
            root.put("Frame count", s);
            root.add(DecodedNode.note("The next " + s + " frames are fragments of one message (frames are limited to 16384 chars)"));
            return new DecodeResult("Firebase RTDB: multi-frame message header (" + s + " frames follow)", root, null, out.warnings);
        }
        JsonElement j = Fb.parse(s);
        if (j == null || !Fb.has(j, "t")) {
            if (!rtdbHost) throw new DecodeException("Not a Firebase Realtime Database frame (expected {\"t\":\"d\"|\"c\",\"d\":…})");
            root.add(DecodedNode.leaf("Fragment", Codecs.truncate(s, 100_000)));
            out.warn("frame is not a complete JSON message; probably a fragment of a multi-frame message");
            return new DecodeResult("Firebase RTDB: message fragment (" + s.length() + " chars)", root, null, out.warnings);
        }
        String summary = frame(j, fromClient(m), root, out);
        return new DecodeResult("Firebase RTDB " + summary, root, null, out.warnings);
    }

    static String ns(MessageContext m) {
        String ns = Codecs.first(m.queryParameters(), "ns");
        if (ns != null) return ns;
        String h = m.host();
        int dot = h.indexOf('.');
        return dot > 0 ? h.substring(0, dot) : h;
    }

    // ---------------------------------------------------------------- long polling

    static DecodeResult decodeLongPoll(MessageContext m, Out out) throws DecodeException {
        Boolean client = !m.isResponse();
        if (m.isResponse()) return longPollResponse(m, out);
        Map<String, List<String>> q = m.queryParameters();
        DecodedNode root = DecodedNode.object("Firebase RTDB long-poll request");
        DecodedNode params = root.child("Parameters");
        TreeMap<Integer, String[]> segs = new TreeMap<>();
        for (Map.Entry<String, List<String>> e : q.entrySet()) {
            Matcher sm = SEG.matcher(e.getKey());
            if (sm.matches()) {
                String[] seg = segs.computeIfAbsent(Integer.parseInt(sm.group(2)), x -> new String[3]);
                int idx = switch (sm.group(1)) { case "seg" -> 0; case "ts" -> 1; default -> 2; };
                seg[idx] = e.getValue().get(0);
                continue;
            }
            String label = LP_PARAMS.get(e.getKey());
            for (String v : e.getValue()) params.add(Fb.stringNode(label == null ? e.getKey() : e.getKey() + " — " + label, v, out));
        }
        String body = Fb.text(m.requestBody(), m.requestHeader("Content-Encoding"));
        if (segs.isEmpty() && !body.isBlank()) {
            // some transports POST the segments instead of putting them in the URL
            for (Map.Entry<String, List<String>> e : Codecs.parseQuery(body.strip()).entrySet()) {
                Matcher sm = SEG.matcher(e.getKey());
                if (!sm.matches()) continue;
                String[] seg = segs.computeIfAbsent(Integer.parseInt(sm.group(2)), x -> new String[3]);
                seg[switch (sm.group(1)) { case "seg" -> 0; case "ts" -> 1; default -> 2; }] = e.getValue().get(0);
            }
        }
        List<String> parts = new ArrayList<>();
        if (!segs.isEmpty()) {
            DecodedNode msgs = DecodedNode.array("Messages");
            root.add(msgs);
            StringBuilder buf = new StringBuilder();
            int have = 0;
            for (String[] seg : segs.values()) {
                buf.append(seg[2] == null ? "" : seg[2]);
                have++;
                int total = seg[1] != null && seg[1].matches("\\d{1,5}") ? Integer.parseInt(seg[1]) : 1;
                if (have >= total) {
                    decodeSegmentData(buf.toString(), client, msgs, parts, out);
                    buf.setLength(0);
                    have = 0;
                }
            }
            if (have > 0) {
                out.warn("long-poll message incomplete: " + have + " segment(s) of a multi-segment message");
                msgs.add(DecodedNode.leaf("incomplete message (base64)", Codecs.truncate(buf.toString(), 20_000)));
            }
        }
        String summary;
        if ("t".equals(Codecs.first(q, "start"))) summary = "long-poll: start session (ns " + ns(m) + ")";
        else if (q.containsKey("dframe")) summary = "long-poll: disconnect";
        else if (!parts.isEmpty()) summary = "long-poll → " + String.join("; ", parts);
        else summary = "long-poll: waiting for server data";
        return new DecodeResult("Firebase RTDB " + summary, root, null, out.warnings);
    }

    private static void decodeSegmentData(String data, Boolean client, DecodedNode msgs, List<String> parts, Out out) {
        // firebase util base64 is web-safe with '.' as padding
        byte[] b = Codecs.base64Decode(data.replace('.', '='));
        JsonElement j = b == null ? null : Fb.parse(new String(b, StandardCharsets.UTF_8));
        if (j == null) {
            out.warn("long-poll segment data is not base64-encoded JSON");
            msgs.add(DecodedNode.leaf("data", Codecs.truncate(data, 20_000)));
            return;
        }
        DecodedNode n = DecodedNode.object("message");
        parts.add(frame(j, client, n, out));
        msgs.add(n.children().size() == 1 ? n.children().get(0) : n);
    }

    private static DecodeResult longPollResponse(MessageContext m, Out out) throws DecodeException {
        String s = Fb.text(m.responseBody(), m.responseHeader("Content-Encoding"));
        DecodedNode root = DecodedNode.object("Firebase RTDB long-poll response");
        List<String> parts = new ArrayList<>();
        Matcher cm = LP_COMMAND.matcher(s);
        while (cm.find()) {
            DecodedNode c = DecodedNode.object("pLPCommand " + cm.group(1));
            Matcher am = LP_ARG.matcher(cm.group(2));
            List<String> args = new ArrayList<>();
            while (am.find()) args.add(am.group(1));
            if ("start".equals(cm.group(1)) && args.size() >= 2) {
                c.put("connection id", args.get(0));
                c.put("password", args.get(1));
                parts.add("session started (id " + args.get(0) + ")");
            } else {
                for (int i = 0; i < args.size(); i++) c.put("arg" + i, args.get(i));
                parts.add("command " + cm.group(1));
            }
            root.add(c);
        }
        DecodedNode msgs = DecodedNode.array("Messages");
        int idx = s.indexOf("pRTLPCB(");
        int frames = 0;
        while (idx >= 0 && frames < MAX_FRAMES) {
            int open = s.indexOf('[', idx);
            int close = s.indexOf(')', idx);
            if (open < 0 || (close >= 0 && close < open)) break;
            int end = JsLiteral.matchBracket(s, open);
            if (end < 0) {
                out.warn("pRTLPCB callback at offset " + idx + " is truncated");
                break;
            }
            JsonElement arr = Fb.parse(s.substring(open, end));
            if (arr != null && arr.isJsonArray()) {
                for (JsonElement f : (JsonArray) arr) {
                    frames++;
                    DecodedNode n = DecodedNode.object("message");
                    parts.add(frame(f, false, n, out));
                    msgs.add(n.children().size() == 1 ? n.children().get(0) : n);
                }
            } else {
                out.warn("pRTLPCB payload at offset " + idx + " is not JSON");
            }
            idx = s.indexOf("pRTLPCB(", end);
        }
        if (!msgs.isLeaf()) root.add(msgs);
        if (root.isLeaf()) {
            if (s.isBlank()) return new DecodeResult("Firebase RTDB long-poll response: empty", root, null, out.warnings);
            throw new DecodeException("No pLPCommand/pRTLPCB callbacks found in the long-poll response");
        }
        return new DecodeResult("Firebase RTDB long-poll ← " + (parts.isEmpty() ? "no messages" : String.join("; ", parts)), root, null, out.warnings);
    }

    // ---------------------------------------------------------------- REST

    static DecodeResult decodeRest(MessageContext m, Out out) throws DecodeException {
        String path = Codecs.urlDecode(m.path());
        String dbPath = path.endsWith(".json") ? path.substring(0, path.length() - 5) : path;
        if (dbPath.isEmpty()) dbPath = "/";
        if (m.isResponse()) return restResponse(m, dbPath, out);
        DecodedNode root = DecodedNode.object("Firebase RTDB REST request");
        DecodedNode ep = root.child("Endpoint");
        String method = m.method();
        String override = m.requestHeader("X-HTTP-Method-Override");
        if (override == null) override = Codecs.first(m.queryParameters(), "x-http-method");
        ep.put("Namespace", ns(m));
        ep.put("HTTP method", method + (override == null ? "" : " (override " + override + ")"));
        ep.put("Path", dbPath);
        String accept = m.requestHeader("Accept");
        boolean sse = accept != null && accept.contains("text/event-stream");
        if (sse) ep.put("Streaming", "Server-Sent Events (Accept: text/event-stream)");
        List<String> qparts = new ArrayList<>();
        Map<String, List<String>> q = m.queryParameters();
        if (!q.isEmpty()) {
            DecodedNode qp = ep.child("Query parameters");
            for (Map.Entry<String, List<String>> e : q.entrySet()) {
                String label = REST_PARAMS.get(e.getKey());
                for (String v : e.getValue()) {
                    String name = label == null ? e.getKey() : e.getKey() + " — " + label;
                    if (e.getKey().equals("auth") && !Fb.Jwt.looksLike(v)) {
                        qp.add(DecodedNode.leaf(name, v));
                        qp.add(DecodedNode.note("auth is not a JWT: likely a legacy database secret, which grants full admin access"));
                    } else {
                        qp.add(Fb.stringNode(name, v, out));
                    }
                    if (Map.of("orderBy", 1, "equalTo", 1, "startAt", 1, "endAt", 1, "limitToFirst", 1, "limitToLast", 1, "shallow", 1).containsKey(e.getKey())) {
                        qparts.add(e.getKey() + " " + v);
                    }
                }
            }
        }
        FirebaseDecoder.authHeaders(m, root, out);
        String body = Fb.text(m.requestBody(), m.requestHeader("Content-Encoding"));
        if (!body.isBlank()) {
            JsonElement j = Fb.parse(body);
            root.add(j != null ? Fb.node("Body", j, false, out, 0) : DecodedNode.leaf("Body", Codecs.truncate(body, 20_000)));
        }
        String verb = override != null ? override.toUpperCase(Locale.ROOT) : method;
        String summary = "Firebase RTDB REST " + verb + " " + dbPath + (qparts.isEmpty() ? "" : " (" + String.join(", ", qparts) + ")")
                + (sse ? " [stream]" : "") + (q.containsKey("auth") ? " [auth]" : "");
        return new DecodeResult(summary, root, null, out.warnings);
    }

    private static DecodeResult restResponse(MessageContext m, String dbPath, Out out) throws DecodeException {
        String s = Fb.text(m.responseBody(), m.responseHeader("Content-Encoding"));
        DecodedNode root = DecodedNode.object("Firebase RTDB REST response");
        String ct = m.responseHeader("Content-Type");
        String t = s.stripLeading();
        if ((ct != null && ct.contains("event-stream")) || t.startsWith("event:")) {
            DecodedNode events = DecodedNode.array("Events");
            root.add(events);
            List<String> types = new ArrayList<>();
            String event = null;
            StringBuilder data = new StringBuilder();
            for (String line : (s + "\n\n").split("\r?\n", -1)) {
                if (line.isEmpty()) {
                    if (event != null || data.length() > 0) {
                        String ev = event == null ? "message" : event;
                        if (types.size() < MAX_FRAMES) types.add(ev);
                        JsonElement j = Fb.parse(data.toString());
                        DecodedNode n = DecodedNode.object(ev);
                        if (j != null) {
                            n.put("path", str(j, "path"));
                            n.add(Fb.node("data", obj(j) != null && obj(j).has("data") ? obj(j).get("data") : j, false, out, 1));
                        } else if (data.length() > 0) {
                            n.put("data", data.toString());
                        }
                        events.add(n);
                    }
                    event = null;
                    data.setLength(0);
                } else if (line.startsWith("event:")) {
                    event = line.substring(6).strip();
                } else if (line.startsWith("data:")) {
                    if (data.length() > 0) data.append('\n');
                    data.append(line.substring(5).strip());
                }
            }
            return new DecodeResult("Firebase RTDB REST stream " + dbPath + ": " + types.size() + " events ("
                    + String.join(", ", new java.util.LinkedHashSet<>(types)) + ")", root, null, out.warnings);
        }
        if (s.isBlank()) return new DecodeResult("Firebase RTDB REST response: empty", root, null, out.warnings);
        JsonElement j = Fb.parse(s);
        if (j == null) throw new DecodeException("Realtime Database REST response is not JSON");
        root.add(Fb.node("Body", j, false, out, 0));
        String detail;
        JsonObject o = obj(j);
        if (o != null && o.size() == 1 && prim(o.get("error")) != null) {
            detail = "error: " + prim(o.get("error"));
        } else if (o != null && o.size() == 1 && prim(o.get("name")) != null && "POST".equals(m.method())) {
            detail = "pushed key " + prim(o.get("name"));
        } else if (o != null) {
            detail = o.size() + (o.size() == 1 ? " key" : " keys");
        } else if (j.isJsonArray()) {
            detail = j.getAsJsonArray().size() + " items";
        } else {
            detail = Codecs.truncate(j.isJsonNull() ? "null (no data)" : j.toString(), 60);
        }
        return new DecodeResult("Firebase RTDB REST response " + dbPath + ": " + detail, root, null, out.warnings);
    }
}
