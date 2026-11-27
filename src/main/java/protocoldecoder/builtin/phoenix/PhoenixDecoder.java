package protocoldecoder.builtin.phoenix;

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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Phoenix Channels (JSON v1/v2 and binary serializers, WebSocket and long-poll transports) and Phoenix LiveView
 * (joins, user events with form values, rendered diffs, navigation, signed session tokens in pages and joins).
 */
public final class PhoenixDecoder implements ProtocolDecoder {

    public static final String ID = "phoenix";

    private static final int MATCH_PARSE_LIMIT = 512 * 1024;
    private static final int HTML_SNIFF = 1024 * 1024;
    private static final int MAX_MESSAGES = 1000;

    private static final Set<String> LV_EVENTS = Set.of("event", "diff", "live_patch", "live_redirect", "redirect", "allow_upload", "progress", "cids_will_destroy", "cids_destroyed");
    private static final Map<String, String> EVENT_NOTES = Map.of(
            "phx_join", "join a channel (topic)",
            "phx_leave", "leave the channel",
            "phx_close", "channel closed",
            "phx_error", "channel crashed on the server",
            "phx_reply", "reply to the message with the same ref",
            "heartbeat", "keep-alive on the \"phoenix\" topic",
            "presence_state", "Phoenix.Presence full state",
            "presence_diff", "Phoenix.Presence joins/leaves");
    private static final Map<String, String> LONGPOLL_STATUS = Map.of(
            "200", "ok",
            "204", "no messages (poll timed out)",
            "410", "session gone: reconnect with the new token",
            "403", "forbidden",
            "500", "server error");

    private static final Pattern PHX_TAG = Pattern.compile("<[a-zA-Z][^<>]*?data-phx-session=\"[^\"]*\"[^<>]*>");
    private static final Pattern ATTR = Pattern.compile("([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:\\s*=\\s*\"([^\"]*)\")?");
    private static final Pattern META_CSRF = Pattern.compile("<meta[^<>]*name=\"csrf-token\"[^<>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern CONTENT_ATTR = Pattern.compile("content=\"([^\"]*)\"");

    @Override public String id() { return ID; }
    @Override public String name() { return "Phoenix Channels / LiveView"; }
    @Override public String description() {
        return "Phoenix channel messages (JSON v1/v2, binary serializer, WebSocket and long poll), LiveView events, diffs and signed session tokens";
    }

    // ---------------------------------------------------------------- matching

    static boolean phoenixWsPath(MessageContext m) {
        String p = m.path().toLowerCase(Locale.ROOT);
        if (!p.endsWith("/websocket")) return false;
        return m.query().contains("vsn=") || p.endsWith("/live/websocket") || p.endsWith("/socket/websocket");
    }

    static boolean longPollPath(MessageContext m) {
        String p = m.path().toLowerCase(Locale.ROOT);
        return p.endsWith("/longpoll") && (m.query().contains("vsn=") || p.endsWith("/live/longpoll") || p.endsWith("/socket/longpoll"));
    }

    private static Boolean fromClient(MessageContext m) {
        String d = m.webSocketDirection();
        if ("CLIENT_TO_SERVER".equals(d)) return true;
        if ("SERVER_TO_CLIENT".equals(d)) return false;
        return null;
    }

    @Override
    public MatchResult match(MessageContext m) {
        try {
            return doMatch(m);
        } catch (RuntimeException e) {
            return MatchResult.NONE;
        }
    }

    private MatchResult doMatch(MessageContext m) {
        if (m.isWebSocket()) {
            byte[] p = m.body();
            if (p.length == 0) return MatchResult.NONE;
            boolean onPath = phoenixWsPath(m);
            int c = p[0] & 0xff;
            if (c == '[' || c == '{' || c == ' ' || c == '\n') {
                if (p.length > MATCH_PARSE_LIMIT) return onPath ? MatchResult.of(85, "Large frame on a Phoenix socket") : MatchResult.NONE;
                PhoenixMessage msg = PhoenixMessage.parseText(Codecs.utf8(p));
                if (msg == null) return MatchResult.NONE;
                if (onPath) return MatchResult.of(92, "Phoenix channel message on a Phoenix socket");
                return shapeOnly(msg);
            }
            if (c <= 2 && onPath) {
                PhoenixMessage msg = PhoenixMessage.parseBinary(p, fromClient(m));
                return msg != null ? MatchResult.of(88, "Phoenix binary serializer frame") : MatchResult.of(40, "Binary frame on a Phoenix socket");
            }
            return MatchResult.NONE;
        }
        if (longPollPath(m)) {
            byte[] body = m.isRequest() ? m.requestBody() : Codecs.decodeContent(m.responseBody(), m.responseHeader("Content-Encoding"));
            if (body.length == 0 || body.length > MATCH_PARSE_LIMIT) return body.length == 0 ? MatchResult.NONE : MatchResult.of(80, "Phoenix long poll");
            String t = Codecs.utf8(body).strip();
            if (m.isResponse()) {
                JsonElement e = JsonTree.parseStrict(t);
                return e != null && e.isJsonObject() && e.getAsJsonObject().has("status") ? MatchResult.of(85, "Phoenix long-poll response") : MatchResult.NONE;
            }
            return !parseLines(t).isEmpty() ? MatchResult.of(85, "Phoenix long-poll send") : MatchResult.NONE;
        }
        if (m.isResponse()) {
            String body = m.responseBodyText();
            String head = body.length() > HTML_SNIFF ? body.substring(0, HTML_SNIFF) : body;
            if (head.contains("data-phx-session=\"")) return MatchResult.of(30, "LiveView session markers in HTML");
        }
        return MatchResult.NONE;
    }

    private static MatchResult shapeOnly(PhoenixMessage msg) {
        String ev = msg.event();
        if (ev.startsWith("phx_") || (ev.equals("heartbeat") && msg.topic().equals("phoenix"))) return MatchResult.of(60, "Phoenix channel message shape");
        if (msg.isLiveView() && LV_EVENTS.contains(ev)) return MatchResult.of(60, "LiveView message shape");
        if (msg.serializer().startsWith("v2") && msg.topic().contains(":")) return MatchResult.of(40, "Phoenix v2 array shape");
        return MatchResult.NONE;
    }

    // ---------------------------------------------------------------- decoding

    @Override
    public DecodeResult decode(MessageContext m) throws DecodeException {
        if (m.isWebSocket()) return webSocket(m);
        if (longPollPath(m)) return longPoll(m);
        if (m.isResponse()) {
            String body = m.responseBodyText();
            if (body.contains("data-phx-session=\"") || body.contains("data-phx-main")) return page(body);
        }
        // Forced on something else: try it as channel messages.
        String t = m.bodyText().strip();
        List<PhoenixMessage> msgs = parseLines(t);
        if (msgs.isEmpty()) throw new DecodeException("Not a Phoenix channel message (expected [join_ref, ref, topic, event, payload] or {topic, event, payload, ref})");
        return messages(msgs, "Messages", List.of());
    }

    private DecodeResult webSocket(MessageContext m) throws DecodeException {
        byte[] p = m.body();
        if (p.length == 0) throw new DecodeException("Empty frame");
        int c = p[0] & 0xff;
        PhoenixMessage msg;
        if (c <= 2) {
            msg = PhoenixMessage.parseBinary(p, fromClient(m));
            if (msg == null) throw new DecodeException("Not a Phoenix binary serializer frame (kind " + c + "; lengths do not fit the frame)");
        } else {
            msg = PhoenixMessage.parseText(Codecs.utf8(p));
            if (msg == null) throw new DecodeException("Not a Phoenix channel message (expected [join_ref, ref, topic, event, payload] or {topic, event, payload, ref})");
        }
        Built b = message(msg);
        DecodedNode root = DecodedNode.object(msg.isLiveView() ? "Phoenix LiveView" : "Phoenix");
        String vsn = Codecs.first(m.queryParameters(), "vsn");
        if (vsn != null) root.put("vsn (serializer version)", vsn);
        if (m.webSocketDirection() != null) root.put("Direction", Boolean.TRUE.equals(fromClient(m)) ? "client → server" : "server → client");
        for (DecodedNode ch : b.node.children()) root.add(ch);
        return new DecodeResult(b.label, root, null, b.warnings);
    }

    /** Text body as one JSON message, a JSON array of messages, or newline-delimited messages. */
    static List<PhoenixMessage> parseLines(String t) {
        List<PhoenixMessage> out = new ArrayList<>();
        if (t.isEmpty()) return out;
        PhoenixMessage single = PhoenixMessage.parseText(t);
        if (single != null) {
            out.add(single);
            return out;
        }
        JsonElement e = JsonTree.parseStrict(t);
        if (e != null && e.isJsonArray()) {
            for (JsonElement x : e.getAsJsonArray()) {
                PhoenixMessage pm = x.isJsonPrimitive() ? PhoenixMessage.parseText(x.getAsString()) : PhoenixMessage.fromJson(x);
                if (pm == null) return new ArrayList<>();
                out.add(pm);
                if (out.size() >= MAX_MESSAGES) break;
            }
            return out;
        }
        for (String line : t.split("\n")) {
            if (line.isBlank()) continue;
            PhoenixMessage pm = PhoenixMessage.parseText(line);
            if (pm == null) return new ArrayList<>();
            out.add(pm);
            if (out.size() >= MAX_MESSAGES) break;
        }
        return out;
    }

    private DecodeResult longPoll(MessageContext m) throws DecodeException {
        byte[] body = m.isRequest() ? m.requestBody() : Codecs.decodeContent(m.responseBody(), m.responseHeader("Content-Encoding"));
        String t = Codecs.utf8(body).strip();
        if (m.isRequest()) {
            if (t.isEmpty()) {
                DecodedNode root = DecodedNode.object("Phoenix long poll");
                String token = Codecs.first(m.queryParameters(), "token");
                if (token != null) root.add(tokenOrString("Session token (?token=)", token));
                return DecodeResult.of("Phoenix long poll " + (token == null ? "(new session)" : "poll"), root);
            }
            List<PhoenixMessage> msgs = parseLines(t);
            if (msgs.isEmpty()) throw new DecodeException("Long-poll body is not Phoenix channel messages");
            return messages(msgs, "Long poll send", List.of());
        }
        JsonElement e = JsonTree.parseStrict(t);
        if (e == null || !e.isJsonObject()) throw new DecodeException("Long-poll response is not a JSON object");
        JsonObject o = e.getAsJsonObject();
        DecodedNode root = DecodedNode.object("Phoenix long poll");
        String status = o.get("status") instanceof JsonPrimitive p ? p.getAsString() : null;
        if (status != null) root.put("Status", status + (LONGPOLL_STATUS.containsKey(status) ? " — " + LONGPOLL_STATUS.get(status) : ""));
        if (o.get("token") instanceof JsonPrimitive tok) root.add(tokenOrString("Session token", tok.getAsString()));
        List<String> warnings = new ArrayList<>();
        List<Built> built = new ArrayList<>();
        if (o.get("messages") instanceof JsonArray arr) {
            DecodedNode list = DecodedNode.array("Messages");
            for (JsonElement x : arr) {
                if (built.size() >= MAX_MESSAGES) {
                    warnings.add("Stopped after " + MAX_MESSAGES + " messages");
                    break;
                }
                PhoenixMessage pm = x.isJsonPrimitive() ? PhoenixMessage.parseText(x.getAsString()) : PhoenixMessage.fromJson(x);
                if (pm == null) {
                    list.add(JsonTree.toNode("unrecognised", x, true));
                    warnings.add("Some long-poll messages are not Phoenix channel messages");
                    continue;
                }
                Built b = message(pm);
                list.add(b.node);
                built.add(b);
                warnings.addAll(b.warnings);
            }
            root.add(list);
        }
        String summary = "Phoenix long poll" + (status != null ? " " + status : "");
        if (built.size() == 1) summary += ": " + built.get(0).label;
        else if (!built.isEmpty()) summary += ": " + summarize(built);
        return new DecodeResult(summary, root, null, warnings);
    }

    private DecodeResult messages(List<PhoenixMessage> msgs, String what, List<String> extra) {
        DecodedNode root = DecodedNode.object("Phoenix");
        List<String> warnings = new ArrayList<>(extra);
        if (msgs.size() == 1) {
            Built b = message(msgs.get(0));
            for (DecodedNode ch : b.node.children()) root.add(ch);
            return new DecodeResult(what + ": " + b.label, root, null, b.warnings);
        }
        DecodedNode list = DecodedNode.array("Messages");
        List<Built> built = new ArrayList<>();
        for (PhoenixMessage pm : msgs) {
            Built b = message(pm);
            built.add(b);
            list.add(b.node);
            warnings.addAll(b.warnings);
        }
        root.add(list);
        return new DecodeResult(what + ": " + summarize(built), root, null, warnings);
    }

    private static String summarize(List<Built> built) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (Built b : built) counts.merge(b.event, 1, Integer::sum);
        StringBuilder sb = new StringBuilder(built.size() + " messages: ");
        int i = 0;
        for (Map.Entry<String, Integer> e : counts.entrySet()) {
            if (i++ > 0) sb.append(", ");
            sb.append(e.getKey());
            if (e.getValue() > 1) sb.append(" ×").append(e.getValue());
        }
        return sb.toString();
    }

    private record Built(DecodedNode node, String label, String event, List<String> warnings) {
    }

    // ---------------------------------------------------------------- one message

    private Built message(PhoenixMessage msg) {
        DecodedNode n = DecodedNode.object(msg.event() + " on " + msg.topic());
        List<String> warnings = new ArrayList<>();
        n.put("Serializer", msg.serializer());
        n.put("join_ref", msg.joinRef() == null ? "null" : msg.joinRef());
        n.put("ref", msg.ref() == null ? "null" : msg.ref());
        n.put("topic", msg.topic());
        n.put("event", msg.event());
        String note = EVENT_NOTES.get(msg.event());
        if (note != null) n.add(DecodedNode.note(note));
        String refPart = msg.ref() != null ? " (ref " + msg.ref() + ")" : "";
        String label;

        if (msg.binary() != null) {
            n.add(binaryPayload(msg.replyStatus() != null ? "response" : "payload", msg.binary()));
            if (msg.replyStatus() != null) {
                n.put("status", msg.replyStatus());
                label = "Phoenix phx_reply " + msg.replyStatus() + refPart + " on " + msg.topic() + " (binary, " + msg.binary().length + " bytes)";
            } else {
                label = "Phoenix " + msg.event() + " on " + msg.topic() + " (binary, " + msg.binary().length + " bytes)";
            }
            return new Built(n, label, msg.event(), warnings);
        }

        JsonElement payload = msg.payload();
        JsonObject po = payload != null && payload.isJsonObject() ? payload.getAsJsonObject() : null;
        boolean lv = msg.isLiveView();
        switch (msg.event()) {
            case "phx_join" -> {
                if (lv && po != null) {
                    DecodedNode j = n.child("LiveView join");
                    putStr(j, po, "url");
                    putStr(j, po, "redirect");
                    if (po.has("params")) j.add(JsonTree.toNode("params", po.get("params"), true));
                    if (po.has("sticky")) j.add(JsonTree.toNode("sticky", po.get("sticky"), false));
                    String url = str(po, "url") != null ? str(po, "url") : str(po, "redirect");
                    label = "LiveView join " + msg.topic() + (url != null ? " (" + Codecs.truncate(url, 80) + ")" : "");
                } else {
                    label = "Phoenix phx_join " + msg.topic() + refPart;
                }
            }
            case "phx_reply" -> {
                String status = po != null ? str(po, "status") : null;
                JsonElement resp = po != null ? po.get("response") : null;
                DecodedNode r = n.child("Reply");
                if (status != null) r.put("status", status);
                String extra = "";
                if (resp != null && resp.isJsonObject()) {
                    JsonObject ro = resp.getAsJsonObject();
                    if (ro.has("rendered") && ro.get("rendered").isJsonObject()) {
                        r.add(LiveViewDiff.node("rendered — initial render", ro.get("rendered")));
                        extra = " (rendered: " + LiveViewDiff.describe(ro.getAsJsonObject("rendered")) + ")";
                    }
                    if (ro.has("diff") && ro.get("diff").isJsonObject()) {
                        r.add(LiveViewDiff.node("diff", ro.get("diff")));
                        extra = " (diff: " + LiveViewDiff.describe(ro.getAsJsonObject("diff")) + ")";
                    }
                    for (String k : ro.keySet()) {
                        if (k.equals("rendered") || k.equals("diff")) continue;
                        r.add(JsonTree.toNode(k, ro.get(k), true));
                    }
                    if ("error".equals(status)) {
                        String reason = str(ro, "reason");
                        if (reason != null) extra = ": " + reason;
                        else if (!ro.isEmpty()) extra = ": " + Codecs.truncate(ro.toString(), 80);
                    }
                } else if (resp != null) {
                    r.add(JsonTree.toNode("response", resp, true));
                }
                if (msg.topic().equals("phoenix")) label = "Phoenix heartbeat reply " + (status == null ? "?" : status) + refPart;
                else label = (lv ? "LiveView" : "Phoenix") + " phx_reply " + (status == null ? "?" : status) + refPart + " on " + msg.topic() + extra;
            }
            case "heartbeat" -> label = "Phoenix heartbeat" + refPart;
            case "event" -> {
                if (lv && po != null) {
                    label = liveViewEvent(n, po, msg.topic());
                } else {
                    label = "Phoenix event on " + msg.topic() + refPart;
                }
            }
            case "diff" -> {
                if (payload != null && payload.isJsonObject()) {
                    n.add(LiveViewDiff.node("Diff", payload));
                    label = "LiveView diff on " + msg.topic() + " (" + LiveViewDiff.describe(po) + ")";
                } else {
                    label = "Phoenix diff on " + msg.topic();
                }
            }
            case "live_patch", "live_redirect", "redirect" -> {
                String to = po == null ? null : str(po, "to") != null ? str(po, "to") : str(po, "url");
                if (po != null) {
                    DecodedNode nav = n.child("Navigation");
                    putStr(nav, po, "to");
                    putStr(nav, po, "url");
                    putStr(nav, po, "kind");
                }
                label = "LiveView " + msg.event() + (to != null ? " → " + Codecs.truncate(to, 100) : "") + " on " + msg.topic();
            }
            default -> label = (lv ? "LiveView " : "Phoenix ") + msg.event() + " on " + msg.topic() + refPart;
        }
        n.add(JsonTree.toNode("payload", payload, true));
        addTokens(n, payload);
        return new Built(n, label, msg.event(), warnings);
    }

    /** LiveView user event: {type, event, value, cid?, meta?, uploads?}. */
    private String liveViewEvent(DecodedNode n, JsonObject po, String topic) {
        DecodedNode ev = n.child("LiveView event");
        String type = str(po, "type");
        String name = str(po, "event");
        putStr(ev, po, "type");
        putStr(ev, po, "event");
        if (po.has("cid")) ev.add(JsonTree.toNode("cid (target component)", po.get("cid"), false));
        JsonElement value = po.get("value");
        if (value != null && value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) {
            String v = value.getAsString();
            boolean form = "form".equals(type) || v.contains("=");
            if (form) {
                DecodedNode f = ev.child("value — form fields (urlencoded)");
                Codecs.parseQuery(v).forEach((k, vals) -> vals.forEach(x -> f.put(k, x)));
                ev.put("value (raw)", Codecs.truncate(v, 8000));
            } else {
                ev.put("value", v);
            }
        } else if (value != null) {
            ev.add(JsonTree.toNode("value", value, true));
        }
        if (po.has("meta")) ev.add(JsonTree.toNode("meta", po.get("meta"), true));
        if (po.has("uploads")) ev.add(JsonTree.toNode("uploads", po.get("uploads"), true));
        return "LiveView event \"" + (name == null ? "?" : Codecs.truncate(name, 60)) + "\"" + (type != null ? " (" + type + ")" : "") + " on " + topic;
    }

    private static DecodedNode binaryPayload(String name, byte[] data) {
        DecodedNode n = DecodedNode.object(name + " (binary, " + data.length + " bytes)");
        if (data.length > 0 && Etf.isUtf8Text(data)) {
            String s = Codecs.utf8(data);
            JsonElement e = JsonTree.parseStrict(s);
            if (e != null) n.add(JsonTree.toNode("as JSON", e, true));
            else n.put("as text", Codecs.truncate(s, 8000));
        } else {
            n.add(DecodedNode.leaf("hex", Codecs.hexPreview(data, 512), DecodedNode.Type.BINARY));
        }
        return n;
    }

    private static void addTokens(DecodedNode n, JsonElement payload) {
        Map<String, String> tokens = new LinkedHashMap<>();
        PhoenixToken.collect(payload, "", tokens, 0);
        if (tokens.isEmpty()) return;
        DecodedNode t = n.child("Phoenix tokens");
        tokens.forEach((path, tok) -> t.add(PhoenixToken.node(path, tok)));
    }

    private static DecodedNode tokenOrString(String name, String v) {
        return PhoenixToken.looksLikeToken(v) ? PhoenixToken.node(name, v) : DecodedNode.leaf(name, v);
    }

    private static String str(JsonObject o, String k) {
        JsonElement e = o.get(k);
        return e != null && e.isJsonPrimitive() ? e.getAsString() : null;
    }

    private static void putStr(DecodedNode n, JsonObject o, String k) {
        String v = str(o, k);
        if (v != null) n.put(k, v);
    }

    // ---------------------------------------------------------------- LiveView page

    private DecodeResult page(String body) throws DecodeException {
        String head = body.length() > HTML_SNIFF ? body.substring(0, HTML_SNIFF) : body;
        DecodedNode root = DecodedNode.object("Phoenix LiveView page");
        List<String> warnings = new ArrayList<>();
        Matcher csrf = META_CSRF.matcher(head);
        boolean hasCsrf = false;
        if (csrf.find()) {
            Matcher c = CONTENT_ATTR.matcher(csrf.group());
            if (c.find()) {
                root.put("CSRF token (meta csrf-token)", c.group(1));
                root.add(DecodedNode.note("sent back as _csrf_token in the LiveView socket params"));
                hasCsrf = true;
            }
        }
        DecodedNode views = DecodedNode.array("LiveViews");
        Matcher tm = PHX_TAG.matcher(head);
        String mainId = null;
        int count = 0;
        boolean signed = false;
        while (tm.find() && count < 200) {
            count++;
            Map<String, String> attrs = attributes(tm.group());
            DecodedNode v = DecodedNode.object(attrs.getOrDefault("id", "view " + count));
            if (attrs.containsKey("data-phx-main")) {
                v.put("main", "true (root LiveView, data-phx-main)");
                if (mainId == null) mainId = attrs.get("id");
            }
            for (Map.Entry<String, String> a : attrs.entrySet()) {
                String k = a.getKey();
                if (k.equals("data-phx-session") || k.equals("data-phx-static")) {
                    String val = a.getValue() == null ? "" : unescapeHtml(a.getValue());
                    if (PhoenixToken.looksLikeToken(val)) {
                        v.add(PhoenixToken.node(k, val));
                        signed |= !PhoenixToken.isEncrypted(val);
                    } else {
                        v.put(k, val);
                    }
                } else if (k.startsWith("data-phx-") && !k.equals("data-phx-main")) {
                    v.put(k, a.getValue() == null ? "" : a.getValue());
                }
            }
            views.add(v);
        }
        if (count == 0 && !hasCsrf) throw new DecodeException("No LiveView markers (data-phx-session) found");
        root.add(views);
        if (signed) warnings.add("LiveView session tokens are signed, not encrypted: their contents are readable by anyone who sees the page");
        String summary = "LiveView page: " + count + (count == 1 ? " view" : " views") + (mainId != null ? " (main " + mainId + ")" : "")
                + (hasCsrf ? ", CSRF token" : "");
        return new DecodeResult(summary, root, null, warnings);
    }

    private static Map<String, String> attributes(String tag) {
        Map<String, String> out = new LinkedHashMap<>();
        int sp = tag.indexOf(' ');
        if (sp < 0) return out;
        Matcher am = ATTR.matcher(tag.substring(sp, tag.length() - 1));
        while (am.find()) {
            if (am.group(1).isEmpty()) continue;
            out.put(am.group(1), am.group(2));
        }
        return out;
    }

    private static String unescapeHtml(String s) {
        return s.replace("&quot;", "\"").replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&");
    }
}
