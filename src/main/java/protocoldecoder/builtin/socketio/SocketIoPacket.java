package protocoldecoder.builtin.socketio;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * A Socket.IO packet carried in the data of an Engine.IO message packet:
 * {@code <type>[<attachments>-][/<namespace>,][<ack id>][<JSON payload>]}.
 */
record SocketIoPacket(int type, int attachments, String namespace, String namespaceQuery, Long ackId,
                      JsonElement data, String rawData, String error) {

    static final String[] TYPES = {"CONNECT", "DISCONNECT", "EVENT", "ACK", "CONNECT_ERROR", "BINARY_EVENT", "BINARY_ACK"};
    static final int CONNECT = 0, DISCONNECT = 1, EVENT = 2, ACK = 3, CONNECT_ERROR = 4, BINARY_EVENT = 5, BINARY_ACK = 6;

    boolean valid() {
        return error == null;
    }

    String typeName() {
        return type >= 0 && type < TYPES.length ? TYPES[type] : "invalid";
    }

    String nsp() {
        return namespace == null ? "/" : namespace;
    }

    /** Event name for (BINARY_)EVENT packets, else null. */
    String eventName() {
        if ((type == EVENT || type == BINARY_EVENT) && data != null && data.isJsonArray() && !data.getAsJsonArray().isEmpty()) {
            JsonElement first = data.getAsJsonArray().get(0);
            if (first.isJsonPrimitive()) return first.getAsString();
        }
        return null;
    }

    static SocketIoPacket parse(String s) {
        if (s == null || s.isEmpty()) return fail(-1, "empty Socket.IO packet", s);
        char c = s.charAt(0);
        if (c < '0' || c > '6') return fail(-1, "unknown Socket.IO packet type '" + c + "'", s);
        int type = c - '0';
        int i = 1;
        int attachments = 0;
        if (type == BINARY_EVENT || type == BINARY_ACK) {
            int dash = s.indexOf('-', i);
            if (dash < 0 || dash == i || dash - i > 9 || !digits(s, i, dash)) return fail(type, "binary packet without a valid attachment count", s);
            attachments = Integer.parseInt(s.substring(i, dash));
            i = dash + 1;
        }
        String nsp = null, nspQuery = null;
        if (i < s.length() && s.charAt(i) == '/') {
            int comma = s.indexOf(',', i);
            int end = comma < 0 ? s.length() : comma;
            nsp = s.substring(i, end);
            int q = nsp.indexOf('?');
            if (q >= 0) {
                nspQuery = nsp.substring(q + 1);
                nsp = nsp.substring(0, q);
            }
            i = comma < 0 ? s.length() : comma + 1;
        }
        Long ack = null;
        int ackStart = i;
        while (i < s.length() && Character.isDigit(s.charAt(i)) && i - ackStart < 18) i++;
        if (i > ackStart) ack = Long.parseLong(s.substring(ackStart, i));
        String raw = s.substring(i);
        JsonElement data = null;
        String error = null;
        if (!raw.isEmpty()) {
            data = JsonTree.parseStrict(raw);
            if (data == null) error = "payload is not valid JSON";
        }
        if (error == null) error = validate(type, data);
        return new SocketIoPacket(type, attachments, nsp, nspQuery, ack, data, raw, error);
    }

    /** Mirrors socket.io-parser's isPayloadValid checks. */
    private static String validate(int type, JsonElement data) {
        return switch (type) {
            case CONNECT -> data == null || data.isJsonObject() ? null : "CONNECT payload must be an object";
            case DISCONNECT -> data == null ? null : "DISCONNECT must not carry a payload";
            case CONNECT_ERROR -> data == null || data.isJsonObject() || (data.isJsonPrimitive() && data.getAsJsonPrimitive().isString())
                    ? null : "CONNECT_ERROR payload must be a string or an object";
            case EVENT, BINARY_EVENT -> data != null && data.isJsonArray() && !data.getAsJsonArray().isEmpty()
                    && data.getAsJsonArray().get(0).isJsonPrimitive() ? null : "EVENT payload must be an array starting with the event name";
            case ACK, BINARY_ACK -> data != null && data.isJsonArray() ? null : "ACK payload must be an array";
            default -> "unknown type";
        };
    }

    private static boolean digits(String s, int from, int to) {
        for (int k = from; k < to; k++) if (!Character.isDigit(s.charAt(k))) return false;
        return true;
    }

    private static SocketIoPacket fail(int type, String why, String raw) {
        return new SocketIoPacket(type, 0, null, null, null, null, raw, why);
    }

    // ------------------------------------------------------------------ presentation

    /** {@code EVENT "chat message" on /admin (ack 12)}. */
    String label() {
        StringBuilder sb = new StringBuilder(typeName());
        String ev = eventName();
        if (ev != null) sb.append(" \"").append(Codecs.truncate(ev, 60)).append('"');
        if (type == CONNECT_ERROR) {
            String msg = errorMessage();
            if (msg != null) sb.append(" \"").append(Codecs.truncate(msg, 60)).append('"');
        }
        if (namespace != null && !namespace.equals("/")) sb.append(" on ").append(namespace);
        if (ackId != null) sb.append(" (ack ").append(ackId).append(')');
        if (attachments > 0) sb.append(" [").append(attachments).append(attachments == 1 ? " attachment]" : " attachments]");
        return sb.toString();
    }

    private String errorMessage() {
        if (data == null) return null;
        if (data.isJsonPrimitive()) return data.getAsString();
        if (data.isJsonObject() && data.getAsJsonObject().get("message") instanceof JsonPrimitive p) return p.getAsString();
        return null;
    }

    DecodedNode node() {
        DecodedNode n = DecodedNode.object("Socket.IO packet");
        n.put("Type", type < 0 ? "invalid" : type + " " + typeName());
        if (!valid()) {
            n.put("Error", error);
            if (rawData != null && !rawData.isEmpty()) n.put("Raw", Codecs.truncate(rawData, 4000));
            if (data != null) n.add(JsonTree.toNode("Payload", data, true));
            return n;
        }
        n.put("Namespace", nsp());
        if (namespaceQuery != null) {
            DecodedNode q = n.child("Namespace query (v2 protocol)");
            Codecs.parseQuery(namespaceQuery).forEach((k, v) -> v.forEach(x -> q.put(k, x)));
        }
        if (ackId != null) n.put("Ack ID", ackId);
        if (type == BINARY_EVENT || type == BINARY_ACK) n.put("Binary attachments", attachments);
        switch (type) {
            case EVENT, BINARY_EVENT -> {
                JsonArray a = data.getAsJsonArray();
                n.put("Event", a.get(0).getAsString());
                DecodedNode args = DecodedNode.array("Arguments");
                for (int k = 1; k < a.size(); k++) args.add(JsonTree.toNode("[" + (k - 1) + "]", a.get(k), true));
                n.add(args);
                if (ackId != null) n.add(DecodedNode.note("the sender expects an ACK with id " + ackId));
            }
            case ACK, BINARY_ACK -> {
                n.add(JsonTree.toNode("Arguments", data, true));
                n.add(DecodedNode.note("reply to the EVENT sent with ack id " + ackId));
            }
            case CONNECT -> {
                if (data != null) {
                    JsonObject o = data.getAsJsonObject();
                    n.add(JsonTree.toNode(o.has("sid") ? "Payload (server: Socket.IO session)" : "Payload (auth)", o, true));
                }
            }
            case CONNECT_ERROR -> n.add(JsonTree.toNode("Error", data, true));
            default -> {
            }
        }
        List<String> placeholders = new ArrayList<>();
        if (data != null) findPlaceholders(data, type == EVENT || type == BINARY_EVENT ? "args" : "data", placeholders, 0);
        if (!placeholders.isEmpty()) {
            DecodedNode p = DecodedNode.array("Binary placeholders");
            for (String s : placeholders) p.add(DecodedNode.leaf("", s));
            p.add(DecodedNode.note("the binary data follows as " + attachments + " separate Engine.IO binary packet(s)"));
            n.add(p);
        }
        return n;
    }

    /** Collects {"_placeholder":true,"num":n} locations as "path → attachment #n". */
    static void findPlaceholders(JsonElement e, String path, List<String> out, int depth) {
        if (e == null || depth > 32 || out.size() > 100) return;
        if (e.isJsonObject()) {
            JsonObject o = e.getAsJsonObject();
            if (o.has("_placeholder") && o.get("_placeholder").isJsonPrimitive() && o.get("_placeholder").getAsJsonPrimitive().isBoolean()
                    && o.get("_placeholder").getAsBoolean() && o.get("num") instanceof JsonPrimitive num && num.isNumber()) {
                out.add(path + " → attachment #" + num.getAsString());
                return;
            }
            for (Map.Entry<String, JsonElement> en : o.entrySet()) findPlaceholders(en.getValue(), path + "." + en.getKey(), out, depth + 1);
        } else if (e.isJsonArray()) {
            JsonArray a = e.getAsJsonArray();
            for (int k = 0; k < a.size(); k++) {
                // args path: element 0 of an EVENT is the name, so args[0] is array index 1
                String p = path.equals("args") ? (k == 0 ? "event" : "args[" + (k - 1) + "]") : path + "[" + k + "]";
                findPlaceholders(a.get(k), p, out, depth + 1);
            }
        }
    }
}
