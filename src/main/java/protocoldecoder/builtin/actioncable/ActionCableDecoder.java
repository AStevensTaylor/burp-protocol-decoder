package protocoldecoder.builtin.actioncable;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import protocoldecoder.builtin.turbo.SignedStreamName;
import protocoldecoder.builtin.turbo.TurboStream;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.ProtocolDecoder;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Rails Action Cable (and AnyCable, which speaks the same protocol) WebSocket frames: welcome/ping/confirm/reject/
 * disconnect from the server, subscribe/unsubscribe/message commands from the client, and channel broadcasts. The
 * JSON-in-a-string {@code identifier} and {@code data} fields are expanded, Turbo signed stream names are decoded and
 * broadcasts carrying Turbo Stream HTML are parsed.
 */
public final class ActionCableDecoder implements ProtocolDecoder {

    public static final String ID = "actioncable";

    private static final int MAX_FRAME = 4 * 1024 * 1024;
    private static final Set<String> SERVER_TYPES = Set.of(
            "welcome", "ping", "confirm_subscription", "reject_subscription", "disconnect",
            "confirm_history", "reject_history"); // last two: AnyCable extended protocol
    private static final Set<String> COMMANDS = Set.of(
            "subscribe", "unsubscribe", "message", "history", "pong", "whisper"); // last three: AnyCable

    @Override public String id() { return ID; }
    @Override public String name() { return "Rails Action Cable"; }
    @Override public String description() {
        return "Rails Action Cable / AnyCable WebSocket frames: subscriptions, channel identifiers, actions, broadcasts (incl. Turbo Streams)";
    }

    // ---------------------------------------------------------------- matching

    static boolean cableEndpoint(MessageContext m) {
        String p = m.path().toLowerCase(Locale.ROOT);
        if (p.endsWith("/cable") || p.endsWith("/cable/")) return true;
        String proto = m.requestHeader("Sec-WebSocket-Protocol");
        return proto != null && proto.toLowerCase(Locale.ROOT).contains("actioncable-");
    }

    @Override
    public MatchResult match(MessageContext m) {
        if (!m.isWebSocket()) return MatchResult.NONE;
        try {
            byte[] b = m.body();
            boolean endpoint = cableEndpoint(m);
            if (b.length == 0 || b.length > MAX_FRAME || b[firstNonSpace(b)] != '{') {
                return endpoint && b.length > 0 ? MatchResult.of(40, "WebSocket on Action Cable endpoint (non-JSON frame)") : MatchResult.NONE;
            }
            JsonObject o = parseObject(Codecs.utf8(b));
            boolean valid = o != null && shape(o) != null;
            if (endpoint) return valid ? MatchResult.of(95, "Action Cable frame on " + m.path()) : MatchResult.of(40, "WebSocket on Action Cable endpoint");
            return valid ? MatchResult.of(60, "Action Cable frame shape") : MatchResult.NONE;
        } catch (RuntimeException e) {
            return MatchResult.NONE;
        }
    }

    private static int firstNonSpace(byte[] b) {
        int i = 0;
        while (i < b.length - 1 && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t')) i++;
        return i;
    }

    private static JsonObject parseObject(String s) {
        JsonElement e = JsonTree.parseStrict(s);
        return e != null && e.isJsonObject() ? e.getAsJsonObject() : null;
    }

    private static String str(JsonObject o, String k) {
        JsonElement e = o.get(k);
        return e != null && e.isJsonPrimitive() && e.getAsJsonPrimitive().isString() ? e.getAsString() : null;
    }

    /** Classifies a frame: "type:<t>", "command:<c>", "broadcast", or null when it is not Action Cable-shaped. */
    static String shape(JsonObject o) {
        String type = str(o, "type");
        if (type != null && SERVER_TYPES.contains(type)) {
            switch (type) {
                case "ping" -> {
                    JsonElement msg = o.get("message");
                    if (msg == null || !msg.isJsonPrimitive() || !msg.getAsJsonPrimitive().isNumber()) return null;
                }
                case "confirm_subscription", "reject_subscription", "confirm_history", "reject_history" -> {
                    if (str(o, "identifier") == null) return null;
                }
                case "welcome" -> {
                    for (String k : o.keySet()) if (!k.equals("type") && !k.equals("sid") && !k.equals("restored") && !k.equals("restored_ids")) return null;
                }
                case "disconnect" -> {
                    if (!o.has("reason") && !o.has("reconnect")) return null;
                }
                default -> {
                }
            }
            return "type:" + type;
        }
        String cmd = str(o, "command");
        if (cmd != null && COMMANDS.contains(cmd)) {
            if (!cmd.equals("pong") && str(o, "identifier") == null) return null;
            return "command:" + cmd;
        }
        if (type == null && str(o, "identifier") != null && o.has("message")) {
            String id = str(o, "identifier");
            JsonObject ido = parseObject(id);
            if (ido != null && ido.has("channel")) return "broadcast";
        }
        return null;
    }

    // ---------------------------------------------------------------- decoding

    @Override
    public DecodeResult decode(MessageContext m) throws DecodeException {
        byte[] b = m.body();
        if (b.length == 0) throw new DecodeException("Empty frame");
        if (b.length > MAX_FRAME) throw new DecodeException("Frame larger than " + MAX_FRAME + " bytes");
        String text = Codecs.utf8(b);
        JsonObject o = parseObject(text);
        if (o == null) {
            String proto = m.requestHeader("Sec-WebSocket-Protocol");
            if (proto != null && (proto.contains("msgpack") || proto.contains("protobuf"))) {
                throw new DecodeException("Binary AnyCable subprotocol (" + proto + ") is not supported; only actioncable-v1-json frames are decoded");
            }
            throw new DecodeException("Frame is not a JSON object, so not an Action Cable JSON frame");
        }
        String shape = shape(o);
        try {
            return decodeFrame(m, o, shape);
        } catch (RuntimeException e) {
            throw new DecodeException("Action Cable decoding failed: " + e, e);
        }
    }

    private DecodeResult decodeFrame(MessageContext m, JsonObject o, String shape) {
        List<String> warnings = new ArrayList<>();
        DecodedNode root = DecodedNode.object("Action Cable");
        String dir = m.webSocketDirection();
        if (dir != null) root.put("Direction", "CLIENT_TO_SERVER".equals(dir) ? "client → server" : "server → client");
        if (shape == null) warnings.add("Frame does not match a known Action Cable message shape; showing it as JSON");

        Channel ch = null;
        String identifier = str(o, "identifier");
        String summary;
        String type = str(o, "type");
        String cmd = str(o, "command");

        for (Map.Entry<String, JsonElement> en : o.entrySet()) {
            String k = en.getKey();
            JsonElement v = en.getValue();
            switch (k) {
                case "identifier" -> {
                    if (identifier != null) {
                        ch = channel(identifier);
                        root.add(ch.node);
                    } else {
                        root.add(JsonTree.toNode(k, v, true));
                    }
                }
                case "data" -> root.add(data(v));
                case "message" -> root.add(message(v, type));
                case "type" -> root.put("type", v.isJsonPrimitive() ? v.getAsString() + typeDescription(v.getAsString()) : v.toString());
                case "command" -> root.put("command", v.isJsonPrimitive() ? v.getAsString() : v.toString());
                case "reconnect" -> root.add(JsonTree.toNode("reconnect (client may retry)", v, false));
                case "reason" -> root.add(JsonTree.toNode("reason", v, false));
                case "sid" -> root.add(JsonTree.toNode("sid (AnyCable session id)", v, false));
                default -> root.add(JsonTree.toNode(k, v, true));
            }
        }

        String where = ch == null ? "" : ch.label;
        if (type != null && shape != null && shape.startsWith("type:")) {
            summary = switch (type) {
                case "welcome" -> "Action Cable welcome" + (str(o, "sid") != null ? " (sid " + str(o, "sid") + ")" : "");
                case "ping" -> "Action Cable ping (" + pingTime(o.get("message")) + ")";
                case "disconnect" -> "Action Cable disconnect" + disconnectInfo(o);
                default -> "Action Cable " + type + (where.isEmpty() ? "" : " → " + where);
            };
        } else if (cmd != null && shape != null) {
            summary = "Action Cable " + cmd + (where.isEmpty() ? "" : " → " + where);
            if (cmd.equals("message")) {
                String action = dataAction(o.get("data"));
                if (action != null) summary += ": " + action;
            }
        } else if ("broadcast".equals(shape)) {
            summary = "Action Cable broadcast on " + where;
            String turbo = turboSummary(o.get("message"));
            if (turbo != null) summary += ": " + turbo;
        } else {
            summary = "Action Cable frame (unrecognised)";
        }
        if (ch != null) warnings.addAll(ch.warnings);
        return new DecodeResult(summary, root, null, warnings);
    }

    private static String typeDescription(String t) {
        return switch (t) {
            case "welcome" -> " (connection accepted)";
            case "ping" -> " (server heartbeat, every 3 s)";
            case "confirm_subscription" -> " (channel subscribed)";
            case "reject_subscription" -> " (channel refused: subscribed callback called reject)";
            case "disconnect" -> " (server closing connection)";
            default -> "";
        };
    }

    private static String pingTime(JsonElement msg) {
        try {
            long epoch = msg.getAsLong();
            if (epoch > 100_000_000_000L) return Instant.ofEpochMilli(epoch).toString();
            return Instant.ofEpochSecond(epoch).toString();
        } catch (RuntimeException e) {
            return String.valueOf(msg);
        }
    }

    private static String disconnectInfo(JsonObject o) {
        List<String> bits = new ArrayList<>();
        String reason = str(o, "reason");
        if (reason != null) bits.add(reason);
        JsonElement rc = o.get("reconnect");
        if (rc != null && rc.isJsonPrimitive()) bits.add("reconnect: " + rc.getAsString());
        return bits.isEmpty() ? "" : " (" + String.join(", ", bits) + ")";
    }

    /** Parsed channel identifier. */
    record Channel(String label, DecodedNode node, List<String> warnings) {
    }

    static Channel channel(String identifier) {
        DecodedNode n = DecodedNode.object("identifier");
        n.put("Raw", Codecs.truncate(identifier, 4000));
        List<String> warnings = new ArrayList<>();
        JsonObject id = parseObject(identifier);
        if (id == null) {
            JsonElement lenient = JsonTree.parseLenient(identifier);
            id = lenient != null && lenient.isJsonObject() ? lenient.getAsJsonObject() : null;
        }
        if (id == null) {
            warnings.add("identifier is not a JSON object");
            return new Channel(Codecs.truncate(identifier, 80), n, warnings);
        }
        String channel = str(id, "channel");
        if (channel != null) n.put("channel", channel);
        StringBuilder params = new StringBuilder();
        String streamName = null;
        for (Map.Entry<String, JsonElement> en : id.entrySet()) {
            String k = en.getKey();
            if (k.equals("channel")) continue;
            JsonElement v = en.getValue();
            if (k.equals("signed_stream_name") && v.isJsonPrimitive()) {
                SignedStreamName.Decoded d = SignedStreamName.decode("signed_stream_name", v.getAsString());
                n.add(d.node());
                if (d.ok()) streamName = d.display();
                continue;
            }
            n.add(JsonTree.toNode(k, v, true));
            if (params.length() > 0) params.append(", ");
            params.append(k).append(": ").append(Codecs.truncate(v.toString(), 60));
        }
        String label = channel == null ? "(no channel)" : channel;
        if (streamName != null) label += " (" + streamName + ")";
        if (params.length() > 0) label += " {" + params + "}";
        return new Channel(label, n, warnings);
    }

    private static DecodedNode data(JsonElement v) {
        if (v.isJsonPrimitive() && v.getAsJsonPrimitive().isString()) {
            JsonElement inner = JsonTree.parseLenient(v.getAsString());
            if (inner != null && inner.isJsonObject()) {
                JsonObject d = inner.getAsJsonObject();
                DecodedNode n = DecodedNode.object("data (JSON)");
                String action = str(d, "action");
                if (action != null) n.put("action (channel method called)", action);
                for (Map.Entry<String, JsonElement> en : d.entrySet()) {
                    if (en.getKey().equals("action") && action != null) continue;
                    n.add(JsonTree.toNode(en.getKey(), en.getValue(), true));
                }
                return n;
            }
        }
        return JsonTree.toNode("data", v, true);
    }

    private static String dataAction(JsonElement v) {
        if (v == null) return null;
        JsonElement inner = v.isJsonPrimitive() && v.getAsJsonPrimitive().isString() ? JsonTree.parseLenient(v.getAsString()) : v;
        return inner != null && inner.isJsonObject() ? str(inner.getAsJsonObject(), "action") : null;
    }

    private static DecodedNode message(JsonElement v, String type) {
        if ("ping".equals(type) && v.isJsonPrimitive() && v.getAsJsonPrimitive().isNumber()) {
            return DecodedNode.leaf("message (server time)", v.getAsString() + "  (" + pingTime(v) + ")", DecodedNode.Type.NUMBER);
        }
        if (v.isJsonPrimitive() && v.getAsJsonPrimitive().isString() && TurboStream.contains(v.getAsString())) {
            TurboStream.Result r = TurboStream.parse(v.getAsString());
            DecodedNode n = DecodedNode.object("message (Turbo Stream)");
            n.add(TurboStream.toNode("Actions", r));
            for (String w : r.warnings()) n.add(DecodedNode.note(w));
            return n;
        }
        return JsonTree.toNode("message", v, true);
    }

    private static String turboSummary(JsonElement v) {
        if (v == null || !(v instanceof JsonPrimitive p) || !p.isString() || !TurboStream.contains(p.getAsString())) return null;
        TurboStream.Result r = TurboStream.parse(p.getAsString());
        return r.isEmpty() ? null : "Turbo Stream " + r.summaryList();
    }
}
