package protocoldecoder.builtin.blazor;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * SignalR hub protocol framing (JSON records terminated by 0x1E, or MessagePack messages with a VarInt length prefix),
 * with Blazor-specific naming of hub methods and their arguments.
 */
final class SignalR {

    static final char RS = '\u001e';

    static final String[] TYPES = {"?", "Invocation", "StreamItem", "Completion", "StreamInvocation", "CancelInvocation",
            "Ping", "Close", "Ack", "Sequence"};

    /** Argument names of Blazor hub methods, both directions. */
    static final Map<String, String[]> BLAZOR_ARGS = Map.ofEntries(
            Map.entry("StartCircuit", new String[]{"baseUri", "uri", "serializedComponentRecords", "applicationState"}),
            Map.entry("ConnectCircuit", new String[]{"circuitId"}),
            Map.entry("ResumeCircuit", new String[]{"circuitId", "baseUri", "uri", "rootComponents", "applicationState"}),
            Map.entry("UpdateRootComponents", new String[]{"serializedComponentOperations", "applicationState"}),
            Map.entry("BeginInvokeDotNetFromJS", new String[]{"callId", "assemblyName", "methodIdentifier", "dotNetObjectId", "argsJson"}),
            Map.entry("EndInvokeJSFromDotNet", new String[]{"asyncHandle", "succeeded", "argsJson"}),
            Map.entry("DispatchBrowserEvent", new String[]{"eventDescriptor", "eventArgs"}),
            Map.entry("OnRenderCompleted", new String[]{"batchId", "errorMessage"}),
            Map.entry("OnLocationChanged", new String[]{"uri", "state", "intercepted"}),
            Map.entry("OnLocationChanging", new String[]{"callId", "uri", "state", "intercepted"}),
            Map.entry("ReceiveByteArray", new String[]{"id", "data"}),
            Map.entry("ReceiveJSDataChunk", new String[]{"streamId", "chunkId", "chunk", "error"}),
            Map.entry("SendDotNetStreamToJS", new String[]{"streamId"}),
            Map.entry("JS.AttachComponent", new String[]{"componentId", "selector"}),
            Map.entry("JS.BeginInvokeJS", new String[]{"asyncHandle", "identifier", "argsJson", "resultType", "targetInstanceId"}),
            Map.entry("JS.EndInvokeDotNet", new String[]{"argsJson"}),
            Map.entry("JS.RenderBatch", new String[]{"batchId", "renderBatch"}),
            Map.entry("JS.Error", new String[]{"error"}),
            Map.entry("JS.EndLocationChanging", new String[]{"callId", "shouldContinue"}),
            Map.entry("JS.ReceiveByteArray", new String[]{"id", "data"}),
            Map.entry("JS.BeginTransmitStream", new String[]{"streamId"}),
            Map.entry("JS.EndUpdateRootComponents", new String[]{"batchId"}));

    /** One decoded hub message plus a one-line label for summaries. */
    record Message(DecodedNode node, String label) {
    }

    private SignalR() {
    }

    // ---------------------------------------------------------------- framing

    /** True if the payload looks like JSON-protocol records (or a handshake). */
    static boolean isTextRecords(byte[] p) {
        return p.length > 1 && p[0] == '{' && p[p.length - 1] == RS;
    }

    /** Splits binary payload into VarInt-length-prefixed messages; null if the framing doesn't fit exactly. */
    static List<int[]> binaryFrames(byte[] p, int start) {
        List<int[]> out = new ArrayList<>();
        int pos = start;
        while (pos < p.length) {
            int len = 0, shift = 0, x;
            do {
                if (pos >= p.length || shift > 28) return null;
                x = p[pos++] & 0xff;
                len |= (x & 0x7f) << shift;
                shift += 7;
            } while ((x & 0x80) != 0);
            if (len <= 0 || pos + len > p.length) return null;
            out.add(new int[]{pos, pos + len});
            pos += len;
        }
        return out.isEmpty() ? null : out;
    }

    /** Cheap check used by the matcher: first binary frame is a MessagePack array starting with a hub message type. */
    static boolean looksLikeMessagePackHub(byte[] p) {
        List<int[]> frames = binaryFrames(p, 0);
        if (frames == null) return false;
        int[] f = frames.get(0);
        int first = p[f[0]] & 0xff;
        if ((first & 0xf0) != 0x90 && first != 0xdc) return false;
        if (f[1] - f[0] < 2) return false;
        int type = p[f[0] + 1] & 0xff;
        return type >= 1 && type <= 9;
    }

    // ---------------------------------------------------------------- MessagePack messages

    static Message fromMessagePack(byte[] p, int start, int end, int index) {
        String name = "[" + index + "]";
        try {
            MsgPack r = new MsgPack(p, start, end);
            Object v = r.read();
            if (!(v instanceof List<?> l) || l.isEmpty() || !(l.get(0) instanceof Long type)) {
                return new Message(MsgPackTree.toNode(name + " (not a hub message)", v), "?");
            }
            int t = type.intValue();
            String typeName = t > 0 && t < TYPES.length ? TYPES[t] : "Type " + t;
            DecodedNode n = DecodedNode.object(name + " " + typeName);
            String label = typeName;
            switch (t) {
                case 1, 4 -> { // [type, headers, invocationId, target, arguments, streamIds?]
                    headers(n, at(l, 1));
                    putScalar(n, "Invocation ID", at(l, 2));
                    String target = String.valueOf(at(l, 3));
                    n.put("Target", target);
                    List<?> args = at(l, 4) instanceof List<?> a ? a : List.of();
                    n.add(arguments(target, args));
                    if (at(l, 5) instanceof List<?> s && !s.isEmpty()) n.add(MsgPackTree.toNode("Stream IDs", s));
                    label = target + detail(target, args);
                    n = rename(n, name + " " + typeName + " → " + label);
                }
                case 2 -> {
                    headers(n, at(l, 1));
                    putScalar(n, "Invocation ID", at(l, 2));
                    n.add(MsgPackTree.toNode("Item", at(l, 3)));
                }
                case 3 -> { // [3, headers, invocationId, resultKind, result?]
                    headers(n, at(l, 1));
                    putScalar(n, "Invocation ID", at(l, 2));
                    long kind = at(l, 3) instanceof Long k ? k : 0;
                    n.put("Result kind", kind == 1 ? "1 (error)" : kind == 2 ? "2 (void)" : kind == 3 ? "3 (result)" : Long.toString(kind));
                    if (l.size() > 4) n.add(MsgPackTree.toNode(kind == 1 ? "Error" : "Result", at(l, 4)));
                    label = "Completion" + (kind == 1 ? " (error)" : "");
                }
                case 5 -> {
                    headers(n, at(l, 1));
                    putScalar(n, "Invocation ID", at(l, 2));
                }
                case 7 -> { // [7, error, allowReconnect]
                    putScalar(n, "Error", at(l, 1));
                    putScalar(n, "Allow reconnect", at(l, 2));
                    label = "Close" + (at(l, 1) != null ? " (" + at(l, 1) + ")" : "");
                }
                case 8, 9 -> putScalar(n, "Sequence ID", at(l, 1));
                default -> {
                }
            }
            if (r.position() != end) n.add(DecodedNode.note((end - r.position()) + " trailing bytes in frame"));
            return new Message(n, label);
        } catch (MsgPack.FormatException e) {
            DecodedNode n = DecodedNode.object(name + " (invalid MessagePack)");
            n.add(DecodedNode.note(e.getMessage()));
            byte[] slice = java.util.Arrays.copyOfRange(p, start, end);
            n.add(DecodedNode.leaf("Hex", Codecs.hexPreview(slice, 96), DecodedNode.Type.BINARY));
            return new Message(n, "invalid");
        }
    }

    private static DecodedNode arguments(String target, List<?> args) {
        String[] names = BLAZOR_ARGS.get(target);
        DecodedNode n = DecodedNode.array("Arguments");
        for (int i = 0; i < args.size(); i++) {
            String argName = names != null && i < names.length ? names[i] : "[" + i + "]";
            Object v = args.get(i);
            if ("JS.RenderBatch".equals(target) && i == 1) {
                byte[] batch = v instanceof byte[] bytes ? bytes : v instanceof String s ? Codecs.base64Decode(s) : null;
                if (batch != null) {
                    n.add(RenderBatch.decode(argName, batch, at(args, 0) instanceof Long id ? id : null));
                    continue;
                }
            }
            n.add(MsgPackTree.toNode(argName, v));
        }
        return n;
    }

    /** Extra summary detail for well-known Blazor calls. */
    static String detail(String target, List<?> args) {
        try {
            switch (target) {
                case "DispatchBrowserEvent" -> {
                    JsonElement d = JsonTree.parseStrict(String.valueOf(at(args, 0)));
                    if (d != null && d.isJsonObject() && d.getAsJsonObject().has("eventName")) {
                        return " (" + d.getAsJsonObject().get("eventName").getAsString() + ")";
                    }
                }
                case "BeginInvokeDotNetFromJS" -> {
                    return " (" + at(args, 2) + (at(args, 1) != null ? " in " + at(args, 1) : "") + ")";
                }
                case "JS.BeginInvokeJS" -> {
                    return " (" + at(args, 1) + ")";
                }
                case "JS.RenderBatch" -> {
                    Object b = at(args, 1);
                    byte[] bytes = b instanceof byte[] x ? x : b instanceof String s ? Codecs.base64Decode(s) : null;
                    String s = bytes == null ? null : RenderBatch.summarize(bytes);
                    return " #" + at(args, 0) + (s == null ? "" : " (" + s + ")");
                }
                case "OnLocationChanged", "OnLocationChanging" -> {
                    return " (" + at(args, target.equals("OnLocationChanged") ? 0 : 1) + ")";
                }
                default -> {
                }
            }
        } catch (RuntimeException ignored) {
            // summary detail is best effort
        }
        return "";
    }

    private static void headers(DecodedNode n, Object h) {
        if (h instanceof Map<?, ?> m && !m.isEmpty()) n.add(MsgPackTree.toNode("Headers", m));
    }

    private static void putScalar(DecodedNode n, String name, Object v) {
        if (v != null) n.add(MsgPackTree.toNode(name, v));
    }

    static Object at(List<?> l, int i) {
        return i < l.size() ? l.get(i) : null;
    }

    private static DecodedNode rename(DecodedNode n, String newName) {
        DecodedNode r = DecodedNode.object(newName);
        n.children().forEach(r::add);
        return r;
    }

    // ---------------------------------------------------------------- JSON messages

    static Message fromJson(String record, int index) {
        String name = "[" + index + "]";
        JsonElement e = JsonTree.parseStrict(record);
        if (e == null || !e.isJsonObject()) return new Message(DecodedNode.leaf(name + " (unparsed)", record), "?");
        JsonObject o = e.getAsJsonObject();
        if (!o.has("type")) {
            // handshake request {"protocol":"blazorpack","version":1} or response {} / {"error":...}
            String label = o.has("protocol") ? "Handshake (" + o.get("protocol").getAsString() + " v" + (o.has("version") ? o.get("version").getAsString() : "?") + ")"
                    : o.has("error") ? "Handshake error: " + o.get("error").getAsString() : "Handshake response";
            return new Message(JsonTree.toNode(name + " " + label, o, true), label);
        }
        int t = o.get("type").getAsInt();
        String typeName = t > 0 && t < TYPES.length ? TYPES[t] : "Type " + t;
        String label = typeName;
        DecodedNode n;
        if ((t == 1 || t == 4) && o.has("target")) {
            String target = o.get("target").getAsString();
            List<Object> args = new ArrayList<>();
            if (o.has("arguments") && o.get("arguments").isJsonArray()) {
                for (JsonElement a : o.getAsJsonArray("arguments")) args.add(jsonToJava(a));
            }
            label = target + detail(target, args);
            n = DecodedNode.object(name + " " + typeName + " → " + label);
            if (o.has("invocationId")) n.put("Invocation ID", o.get("invocationId").getAsString());
            n.put("Target", target);
            n.add(arguments(target, args));
            for (Map.Entry<String, JsonElement> en : o.entrySet()) {
                if (!List.of("type", "target", "arguments", "invocationId").contains(en.getKey())) n.add(JsonTree.toNode(en.getKey(), en.getValue(), true));
            }
        } else {
            n = JsonTree.toNode(name + " " + typeName, o, true);
            if (t == 3 && o.has("error")) label = "Completion (error)";
            if (t == 7 && o.has("error")) label = "Close (" + o.get("error").getAsString() + ")";
        }
        return new Message(n, label);
    }

    private static Object jsonToJava(JsonElement e) {
        if (e == null || e.isJsonNull()) return null;
        if (e.isJsonArray()) {
            List<Object> l = new ArrayList<>();
            for (JsonElement x : e.getAsJsonArray()) l.add(jsonToJava(x));
            return l;
        }
        if (e.isJsonObject()) {
            Map<Object, Object> m = new java.util.LinkedHashMap<>();
            e.getAsJsonObject().entrySet().forEach(en -> m.put(en.getKey(), jsonToJava(en.getValue())));
            return m;
        }
        var p = e.getAsJsonPrimitive();
        if (p.isBoolean()) return p.getAsBoolean();
        if (p.isNumber()) {
            double d = p.getAsDouble();
            return d == Math.rint(d) && Math.abs(d) < 1e15 ? (Object) (long) d : (Object) d;
        }
        return p.getAsString();
    }

    // ---------------------------------------------------------------- whole payloads

    /**
     * Decodes a WebSocket frame or long-polling body: optional handshake record(s), then JSON records or binary
     * MessagePack messages.
     */
    static List<Message> decodePayload(byte[] p) {
        return decodePayload(p, true);
    }

    /** As {@link #decodePayload(byte[])}; with {@code allowJson} false the payload is binary messages only. */
    static List<Message> decodePayload(byte[] p, boolean allowJson) {
        List<Message> out = new ArrayList<>();
        int pos = 0;
        // Leading JSON records (handshake, or the whole payload for the JSON protocol).
        while (allowJson && pos < p.length && p[pos] == '{') {
            int rs = indexOf(p, (byte) RS, pos);
            if (rs < 0) break;
            out.add(fromJson(new String(p, pos, rs - pos, StandardCharsets.UTF_8), out.size()));
            pos = rs + 1;
        }
        if (pos >= p.length) return out;
        List<int[]> frames = binaryFrames(p, pos);
        if (frames == null) {
            DecodedNode n = DecodedNode.object("[" + out.size() + "] Unrecognised data");
            byte[] rest = java.util.Arrays.copyOfRange(p, pos, p.length);
            n.add(Codecs.isMostlyText(rest) ? DecodedNode.leaf("Text", Codecs.utf8(rest)) : DecodedNode.leaf("Hex", Codecs.hexPreview(rest, 128), DecodedNode.Type.BINARY));
            out.add(new Message(n, "unrecognised"));
            return out;
        }
        for (int[] f : frames) out.add(fromMessagePack(p, f[0], f[1], out.size()));
        return out;
    }

    /**
     * True if the payload holds only whole hub messages; false if it looks like part of a message split across
     * several WebSocket messages (or isn't SignalR at all).
     */
    static boolean selfContained(byte[] p) {
        int pos = 0;
        while (pos < p.length && p[pos] == '{') {
            int rs = indexOf(p, (byte) RS, pos);
            if (rs < 0) return false;
            pos = rs + 1;
        }
        return pos >= p.length || binaryFrames(p, pos) != null;
    }

    private static int indexOf(byte[] p, byte v, int from) {
        for (int i = from; i < p.length; i++) if (p[i] == v) return i;
        return -1;
    }

    /** Base64 helper exposed for tests and the HTML state decoder. */
    static byte[] b64(String s) {
        try {
            return Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            return Codecs.base64Decode(s);
        }
    }

}
