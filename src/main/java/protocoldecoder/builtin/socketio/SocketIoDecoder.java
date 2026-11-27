package protocoldecoder.builtin.socketio;

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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Socket.IO over Engine.IO (v3 and v4): WebSocket frames, HTTP long-polling payloads (v4 record-separator framing,
 * v3 length-prefixed and XHR2 binary framing, JSONP), handshakes and Socket.IO packets with namespaces, ack ids and
 * binary attachment placeholders.
 */
public final class SocketIoDecoder implements ProtocolDecoder {

    public static final String ID = "socketio";

    /** Most we parse during match(); larger bodies are only sniffed by their first bytes. */
    private static final int MATCH_PARSE_LIMIT = 256 * 1024;

    private static final Map<Integer, String> ERROR_CODES = Map.of(
            0, "Transport unknown",
            1, "Session ID unknown",
            2, "Bad handshake method",
            3, "Bad request",
            4, "Forbidden",
            5, "Unsupported protocol version");

    @Override public String id() { return ID; }
    @Override public String name() { return "Socket.IO / Engine.IO"; }
    @Override public String description() {
        return "Socket.IO events/acks/namespaces over Engine.IO v3/v4: WebSocket frames, long-polling payloads, handshakes, binary attachments";
    }

    // ---------------------------------------------------------------- matching

    private static boolean socketIoPath(MessageContext m) {
        return m.path().toLowerCase(Locale.ROOT).contains("/socket.io/");
    }

    private static boolean engineIoQuery(MessageContext m) {
        String q = m.query();
        return (q.startsWith("EIO=") || q.contains("&EIO=")) && q.contains("transport=");
    }

    private static boolean isScript(MessageContext m) {
        String p = m.path().toLowerCase(Locale.ROOT);
        return p.endsWith(".js") || p.endsWith(".map") || p.endsWith(".mjs");
    }

    /** EIO query parameter: 3 (also for older 1/2), 4, or 0 when unknown. */
    static int eioVersion(MessageContext m) {
        String v = Codecs.first(m.queryParameters(), "EIO");
        if (v == null) return 0;
        try {
            int n = Integer.parseInt(v.strip());
            return n >= 4 ? 4 : n >= 1 ? 3 : 0;
        } catch (NumberFormatException e) {
            return 0;
        }
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
        boolean onPath = (socketIoPath(m) || engineIoQuery(m)) && !isScript(m);
        int eio = eioVersion(m);
        if (m.isWebSocket()) {
            byte[] p = m.body();
            if (p.length == 0) return MatchResult.NONE;
            if (onPath) {
                if (!looksLikeTextFrame(p)) return MatchResult.of(80, "Binary frame on a Socket.IO WebSocket");
                if (p.length > MATCH_PARSE_LIMIT) return MatchResult.of(85, "Socket.IO WebSocket");
                EngineIo.Packet pk = EngineIo.parseText(Codecs.utf8(p), eio);
                return pk.valid() ? MatchResult.of(92, "Engine.IO packet on a Socket.IO WebSocket") : MatchResult.NONE;
            }
            return shapeOnly(p);
        }
        if (!onPath) return MatchResult.NONE;
        byte[] body = m.isRequest() ? m.requestBody() : Codecs.decodeContent(m.responseBody(), m.responseHeader("Content-Encoding"));
        if (body == null || body.length == 0) {
            return m.isRequest() && eio > 0 ? MatchResult.of(40, "Engine.IO request (no body)") : MatchResult.NONE;
        }
        if (body.length > MATCH_PARSE_LIMIT) {
            char c = (char) (body[0] & 0xff);
            return (c >= '0' && c <= '9') || c == 'b' ? MatchResult.of(85, "Large Engine.IO polling payload") : MatchResult.NONE;
        }
        String text = Codecs.utf8(body).strip();
        if (text.equals("ok")) return MatchResult.of(90, "Engine.IO polling acknowledgement");
        if (errorObject(text) != null) return MatchResult.of(85, "Engine.IO error response");
        EngineIo.Payload pl = EngineIo.parsePolling(body, eio);
        if (pl.packets().stream().anyMatch(EngineIo.Packet::valid)) return MatchResult.of(90, "Engine.IO long-polling payload");
        return MatchResult.NONE;
    }

    /** WebSocket frame on an unknown path: only distinctive Engine.IO/Socket.IO shapes, at low confidence. */
    private static MatchResult shapeOnly(byte[] p) {
        if (p.length < 1 || p.length > MATCH_PARSE_LIMIT || !looksLikeTextFrame(p)) return MatchResult.NONE;
        String t = Codecs.utf8(p);
        if (t.equals("2probe") || t.equals("3probe")) return MatchResult.of(50, "Engine.IO probe");
        if (t.startsWith("0{\"sid\"")) {
            JsonElement e = JsonTree.parseStrict(t.substring(1));
            if (e != null && e.isJsonObject() && e.getAsJsonObject().has("pingInterval")) return MatchResult.of(55, "Engine.IO open handshake shape");
            return MatchResult.NONE;
        }
        if (t.length() >= 2 && t.charAt(0) == '4' && t.charAt(1) >= '0' && t.charAt(1) <= '6') {
            SocketIoPacket s = SocketIoPacket.parse(t.substring(1));
            if (!s.valid()) return MatchResult.NONE;
            if (s.type() == SocketIoPacket.EVENT || s.type() == SocketIoPacket.BINARY_EVENT) return MatchResult.of(50, "Socket.IO event shape");
            if (s.type() == SocketIoPacket.CONNECT && (t.equals("40") || t.startsWith("40{") || t.startsWith("40/"))) return MatchResult.of(45, "Socket.IO connect shape");
            return MatchResult.of(35, "Socket.IO packet shape");
        }
        return MatchResult.NONE;
    }

    /** Text frames start with a packet type digit or 'b' and are valid UTF-8 text. */
    static boolean looksLikeTextFrame(byte[] p) {
        if (p.length == 0) return false;
        int c = p[0] & 0xff;
        if (!((c >= '0' && c <= '6') || c == 'b')) return false;
        return Codecs.isMostlyText(p);
    }

    private static JsonObject errorObject(String text) {
        if (!text.startsWith("{")) return null;
        JsonElement e = JsonTree.parseStrict(text);
        if (e == null || !e.isJsonObject()) return null;
        JsonObject o = e.getAsJsonObject();
        return o.has("code") && o.has("message") && o.size() <= 3 ? o : null;
    }

    // ---------------------------------------------------------------- decoding

    @Override
    public DecodeResult decode(MessageContext m) throws DecodeException {
        int eio = eioVersion(m);
        if (m.isWebSocket()) return webSocket(m, eio);
        byte[] body = m.isRequest() ? m.requestBody() : Codecs.decodeContent(m.responseBody(), m.responseHeader("Content-Encoding"));
        if (body == null) body = new byte[0];
        if (m.isRequest()) {
            String form = Codecs.first(m.formParameters(), "d");
            if (form != null) body = form.getBytes(StandardCharsets.UTF_8); // v3 JSONP send: d=<payload>
        }
        DecodedNode root = DecodedNode.object("Socket.IO");
        addTransportInfo(m, root, eio);
        String text = new String(body, StandardCharsets.UTF_8).strip();
        if (body.length == 0) {
            if (!m.isRequest()) throw new DecodeException("Empty body");
            String transport = Codecs.first(m.queryParameters(), "transport");
            String sid = Codecs.first(m.queryParameters(), "sid");
            String what = "websocket".equals(transport) ? "WebSocket upgrade request" : sid == null ? "handshake request" : "poll request";
            return DecodeResult.of("Engine.IO " + what + (eio > 0 ? " (EIO=" + eio + (sid != null ? ", sid " + sid : "") + ")" : ""), root);
        }
        if (text.equals("ok")) {
            root.add(DecodedNode.note("the server accepted the packets POSTed by the client"));
            return DecodeResult.of("Polling: send acknowledged (ok)", root);
        }
        JsonObject err = errorObject(text);
        if (err != null) {
            root.add(JsonTree.toNode("Error", err, false));
            int code = err.get("code") instanceof JsonPrimitive p && p.isNumber() ? p.getAsInt() : -1;
            String meaning = ERROR_CODES.get(code);
            if (meaning != null) root.put("Meaning", meaning);
            return DecodeResult.of("Engine.IO error " + err.get("code").getAsString() + ": " + err.get("message").getAsString(), root);
        }
        EngineIo.Payload pl = EngineIo.parsePolling(body, eio);
        long valid = pl.packets().stream().filter(EngineIo.Packet::valid).count();
        if (valid == 0) throw new DecodeException("Not an Engine.IO payload: " + pl.packets().get(0).error());
        root.put("Framing", pl.framing());
        DecodedNode list = DecodedNode.array("Packets");
        List<String> labels = new ArrayList<>();
        List<String> warnings = new ArrayList<>(pl.warnings());
        for (EngineIo.Packet p : pl.packets()) {
            Decoded d = packet(p, eio, m);
            list.add(d.node);
            labels.add(d.label);
            if (d.warning != null) warnings.add(d.warning);
        }
        root.add(list);
        String summary = labels.size() == 1 ? "Polling: " + labels.get(0) : "Polling: " + summarize(labels);
        return new DecodeResult(summary, root, null, dedupe(warnings));
    }

    private DecodeResult webSocket(MessageContext m, int eio) throws DecodeException {
        byte[] p = m.body();
        if (p.length == 0) throw new DecodeException("Empty frame");
        DecodedNode root = DecodedNode.object("Socket.IO");
        addTransportInfo(m, root, eio);
        EngineIo.Packet pk;
        if (looksLikeTextFrame(p)) {
            pk = EngineIo.parseText(Codecs.utf8(p), eio);
        } else if ((p[0] & 0xff) >= 0x20 && (p[0] & 0xff) < 0x7f && Codecs.isMostlyText(p)) {
            // ASCII text that is not a packet (e.g. JSON from another protocol): refuse rather than call it binary
            pk = EngineIo.parseText(Codecs.utf8(p), eio);
            if (!pk.valid()) throw new DecodeException("Not an Engine.IO packet: " + pk.error());
        } else {
            pk = EngineIo.parseBinaryFrame(p, eio);
        }
        if (!pk.valid()) throw new DecodeException("Not an Engine.IO packet: " + pk.error());
        Decoded d = packet(pk, eio, m);
        root.add(d.node);
        List<String> warnings = new ArrayList<>();
        if (d.warning != null) warnings.add(d.warning);
        if (pk.isBinary() && !socketIoPath(m) && !engineIoQuery(m)) {
            warnings.add("Binary frame outside a recognised Socket.IO connection: shown as a raw Engine.IO binary message");
        }
        return new DecodeResult(d.label, root, null, warnings);
    }

    private static void addTransportInfo(MessageContext m, DecodedNode root, int eio) {
        Map<String, List<String>> q = m.queryParameters();
        if (eio > 0) root.put("Engine.IO protocol", "v" + eio + (eio == 4 ? " (Socket.IO 3+/4)" : " (Socket.IO 2)"));
        String transport = Codecs.first(q, "transport");
        if (transport != null) root.put("Transport", transport);
        String sid = Codecs.first(q, "sid");
        if (sid != null) root.put("Session ID (sid)", sid);
        if (m.isWebSocket() && m.webSocketDirection() != null) {
            root.put("Direction", "CLIENT_TO_SERVER".equals(m.webSocketDirection()) ? "client → server" : "server → client");
        }
    }

    private record Decoded(DecodedNode node, String label, String warning) {
    }

    /** Builds the node for one Engine.IO packet. Labels: "Socket.IO EVENT \"x\"" / "Engine.IO ping" etc. */
    private Decoded packet(EngineIo.Packet p, int eio, MessageContext m) {
        DecodedNode n = DecodedNode.object("Engine.IO packet");
        if (!p.valid()) {
            n.put("Error", p.error());
            if (p.text() != null) n.put("Raw", Codecs.truncate(p.text(), 2000));
            return new Decoded(n, "invalid", "Invalid Engine.IO packet: " + p.error());
        }
        n.put("Type", p.type() + " " + p.typeName());
        if (p.isBinary()) {
            byte[] b = p.binary();
            n.put("Binary data", b.length + " bytes");
            n.add(DecodedNode.leaf("Hex", Codecs.hexPreview(b, 256), DecodedNode.Type.BINARY));
            if (b.length > 0 && Codecs.isMostlyText(b)) n.put("As text", Codecs.truncate(Codecs.utf8(b), 4000));
            n.add(DecodedNode.note("binary message: usually an attachment of the preceding BINARY_EVENT/BINARY_ACK"));
            return new Decoded(n, "Engine.IO binary message (" + b.length + " bytes)", null);
        }
        String data = p.text();
        switch (p.type()) {
            case EngineIo.OPEN -> {
                JsonElement e = JsonTree.parseStrict(data);
                if (e == null || !e.isJsonObject()) {
                    n.put("Data", Codecs.truncate(data, 2000));
                    return new Decoded(n, "Engine.IO open", "open packet does not carry a JSON handshake");
                }
                JsonObject o = e.getAsJsonObject();
                DecodedNode hs = JsonTree.toNode("Handshake", o, false);
                n.add(hs);
                if (o.has("upgrades") && o.get("upgrades").isJsonArray() && o.getAsJsonArray("upgrades").isEmpty()) {
                    n.add(DecodedNode.note("no transport upgrades offered (polling only)"));
                }
                StringBuilder lbl = new StringBuilder("Engine.IO open (");
                lbl.append("sid ").append(str(o, "sid"));
                if (o.has("pingInterval")) lbl.append(", ping ").append(str(o, "pingInterval")).append("ms");
                lbl.append(')');
                return new Decoded(n, lbl.toString(), null);
            }
            case 2, 3 -> {
                boolean probe = data.equals("probe");
                if (!data.isEmpty()) n.put("Data", Codecs.truncate(data, 2000));
                if (probe) n.add(DecodedNode.note("WebSocket upgrade probe"));
                else n.add(DecodedNode.note(pingNote(p.type(), eio)));
                return new Decoded(n, "Engine.IO " + p.typeName() + (probe ? " probe" : ""), null);
            }
            case EngineIo.MESSAGE -> {
                SocketIoPacket s = SocketIoPacket.parse(data);
                if (s.valid()) {
                    n.add(s.node());
                    return new Decoded(n, "Socket.IO " + s.label(), null);
                }
                // Plain Engine.IO message (not Socket.IO) or a malformed Socket.IO packet.
                n.put("Data", Codecs.truncate(data, 8000));
                JsonElement e = JsonTree.parseStrict(data);
                if (e != null) n.add(JsonTree.toNode("Data (JSON)", e, true));
                if (s.type() >= 0) {
                    n.add(DecodedNode.note("not a valid Socket.IO packet: " + s.error()));
                    return new Decoded(n, "Engine.IO message", "Socket.IO " + s.typeName() + " packet: " + s.error());
                }
                return new Decoded(n, "Engine.IO message", null);
            }
            default -> {
                if (!data.isEmpty()) n.put("Data", Codecs.truncate(data, 2000));
                String note = switch (p.type()) {
                    case 1 -> "transport closed";
                    case 5 -> "transport upgrade completed (switching to WebSocket)";
                    case 6 -> "no-op (used to end a pending poll during upgrade)";
                    default -> null;
                };
                if (note != null) n.add(DecodedNode.note(note));
                return new Decoded(n, "Engine.IO " + p.typeName(), null);
            }
        }
    }

    private static String pingNote(int type, int eio) {
        if (eio == 3) return type == 2 ? "heartbeat (v3: sent by the client)" : "heartbeat reply (v3: sent by the server)";
        if (eio == 4) return type == 2 ? "heartbeat (v4: sent by the server)" : "heartbeat reply (v4: sent by the client)";
        return type == 2 ? "heartbeat" : "heartbeat reply";
    }

    private static String str(JsonObject o, String k) {
        JsonElement e = o.get(k);
        return e == null || e.isJsonNull() ? "?" : e.isJsonPrimitive() ? e.getAsString() : e.toString();
    }

    /** "3 packets: EVENT ×2, PING" from per-packet labels. */
    static String summarize(List<String> labels) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String l : labels) counts.merge(shortLabel(l), 1, Integer::sum);
        StringBuilder sb = new StringBuilder(labels.size() + " packets: ");
        int i = 0;
        for (Map.Entry<String, Integer> e : counts.entrySet()) {
            if (i++ > 0) sb.append(", ");
            sb.append(e.getKey());
            if (e.getValue() > 1) sb.append(" ×").append(e.getValue());
        }
        return sb.toString();
    }

    private static String shortLabel(String l) {
        if (l.startsWith("Socket.IO ")) {
            String rest = l.substring("Socket.IO ".length());
            int sp = rest.indexOf(' ');
            return sp < 0 ? rest : rest.substring(0, sp);
        }
        if (l.startsWith("Engine.IO ")) {
            String rest = l.substring("Engine.IO ".length());
            if (rest.startsWith("binary")) return "BINARY";
            int sp = rest.indexOf(' ');
            String w = sp < 0 ? rest : rest.substring(0, sp);
            return rest.endsWith(" probe") ? w.toUpperCase(Locale.ROOT) + " probe" : w.toUpperCase(Locale.ROOT);
        }
        return l.toUpperCase(Locale.ROOT);
    }

    private static List<String> dedupe(List<String> w) {
        return new ArrayList<>(new java.util.LinkedHashSet<>(w));
    }
}
