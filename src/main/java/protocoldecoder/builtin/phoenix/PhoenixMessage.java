package protocoldecoder.builtin.phoenix;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import protocoldecoder.util.JsonTree;

import java.nio.charset.StandardCharsets;

/**
 * One Phoenix channel message in any serializer: v2 JSON array {@code [join_ref, ref, topic, event, payload]}, v1 JSON
 * object {@code {topic, event, payload, ref[, join_ref]}}, or the v2 binary serializer (push/reply/broadcast).
 *
 * @param serializer   human-readable serializer name
 * @param payload      JSON payload, or null for binary payloads
 * @param binary       payload bytes of a binary frame, else null
 * @param replyStatus  status of a binary reply (whose payload is then {@code {status, response: <binary>}})
 */
record PhoenixMessage(String serializer, String joinRef, String ref, String topic, String event,
                      JsonElement payload, byte[] binary, String replyStatus) {

    static final int KIND_PUSH = 0, KIND_REPLY = 1, KIND_BROADCAST = 2;

    boolean isLiveView() {
        return topic.startsWith("lv:");
    }

    static PhoenixMessage parseText(String s) {
        if (s == null) return null;
        String t = s.strip();
        if (t.isEmpty() || (t.charAt(0) != '[' && t.charAt(0) != '{')) return null;
        return fromJson(JsonTree.parseStrict(t));
    }

    static PhoenixMessage fromJson(JsonElement e) {
        if (e == null) return null;
        if (e.isJsonArray()) {
            JsonArray a = e.getAsJsonArray();
            if (a.size() != 5) return null;
            if (!isRef(a.get(0)) || !isRef(a.get(1)) || !isString(a.get(2)) || !isString(a.get(3))) return null;
            return new PhoenixMessage("v2 JSON array", ref(a.get(0)), ref(a.get(1)), a.get(2).getAsString(), a.get(3).getAsString(),
                    a.get(4), null, null);
        }
        if (e.isJsonObject()) {
            JsonObject o = e.getAsJsonObject();
            if (!isString(o.get("topic")) || !isString(o.get("event"))) return null;
            if (!o.has("payload") && !o.has("ref")) return null;
            for (String k : o.keySet()) {
                if (!(k.equals("topic") || k.equals("event") || k.equals("payload") || k.equals("ref") || k.equals("join_ref"))) return null;
            }
            if (o.has("ref") && !isRef(o.get("ref"))) return null;
            if (o.has("join_ref") && !isRef(o.get("join_ref"))) return null;
            return new PhoenixMessage("v1 JSON object", ref(o.get("join_ref")), ref(o.get("ref")), o.get("topic").getAsString(),
                    o.get("event").getAsString(), o.get("payload"), null, null);
        }
        return null;
    }

    private static boolean isString(JsonElement e) {
        return e != null && e.isJsonPrimitive() && e.getAsJsonPrimitive().isString();
    }

    private static boolean isRef(JsonElement e) {
        return e == null || e.isJsonNull() || (e.isJsonPrimitive() && !e.getAsJsonPrimitive().isBoolean());
    }

    private static String ref(JsonElement e) {
        return e == null || e.isJsonNull() ? null : e.getAsString();
    }

    /**
     * Parses a binary-serializer frame. {@code fromClient} selects the push layout: client pushes carry a ref (four
     * size bytes), server pushes do not (three); null tries the client layout first.
     */
    static PhoenixMessage parseBinary(byte[] b, Boolean fromClient) {
        if (b == null || b.length < 3) return null;
        int kind = b[0] & 0xff;
        switch (kind) {
            case KIND_PUSH -> {
                if (fromClient == null || fromClient) {
                    PhoenixMessage m = fields(b, 4, true, "binary push (client → server)");
                    if (m != null || fromClient != null) return m;
                }
                return fields(b, 3, false, "binary push (server → client)");
            }
            case KIND_REPLY -> {
                return fields(b, 4, true, "binary reply");
            }
            case KIND_BROADCAST -> {
                return fields(b, 2, false, "binary broadcast");
            }
            default -> {
                return null;
            }
        }
    }

    /** Reads {@code sizes} length bytes then the strings, in the order the serializer writes them. */
    private static PhoenixMessage fields(byte[] b, int sizes, boolean hasRef, String serializer) {
        int kind = b[0] & 0xff;
        if (b.length < 1 + sizes) return null;
        int[] len = new int[sizes];
        for (int i = 0; i < sizes; i++) len[i] = b[1 + i] & 0xff;
        int off = 1 + sizes;
        String[] s = new String[sizes];
        for (int i = 0; i < sizes; i++) {
            if (off + len[i] > b.length) return null;
            s[i] = new String(b, off, len[i], StandardCharsets.UTF_8);
            if (!printable(s[i])) return null;
            off += len[i];
        }
        byte[] data = new byte[b.length - off];
        System.arraycopy(b, off, data, 0, data.length);
        String joinRef, ref, topic, event;
        if (kind == KIND_BROADCAST) {
            joinRef = null; ref = null; topic = s[0]; event = s[1];
        } else if (hasRef) {
            joinRef = s[0]; ref = s[1]; topic = s[2]; event = s[3];
        } else {
            joinRef = s[0]; ref = null; topic = s[1]; event = s[2];
        }
        if (topic.isEmpty() || event.isEmpty()) return null;
        if (kind == KIND_REPLY) return new PhoenixMessage(serializer, empty(joinRef), empty(ref), topic, "phx_reply", null, data, event);
        return new PhoenixMessage(serializer, empty(joinRef), empty(ref), topic, event, null, data, null);
    }

    private static String empty(String s) {
        return s == null || s.isEmpty() ? null : s;
    }

    private static boolean printable(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c == 0x7f || c == '�') return false;
        }
        return true;
    }
}
