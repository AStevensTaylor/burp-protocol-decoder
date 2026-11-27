package protocoldecoder.builtin.socketio;

import com.google.gson.JsonElement;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.edit.EditableDocument;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.edit.MessageCodec;
import protocoldecoder.edit.MessagePatch;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.EditJson;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * One text document per Socket.IO WebSocket text frame or long-polling body, one block per Engine.IO packet:
 * <pre>
 * ### 42/admin,12
 * [
 *   "chat message",
 *   {"text": "hi"}
 * ]
 * </pre>
 * The header line is the packet up to its payload (Engine.IO type, Socket.IO type, attachment count, namespace, ack
 * id) and is written back verbatim; a JSON payload is pretty-printed and re-compacted, other payloads ({@code probe},
 * {@code b<base64>} binary packets) are kept as raw text. Packets are re-framed like the original: v4 {@code \x1e}
 * separators or v3 {@code <length>:} prefixes (UTF-16 lengths). Unchanged packets are written back byte-for-byte.
 * Not offered for binary frames, v3 XHR2 binary payloads, JSONP and {@code d=} form sends.
 */
public final class SocketIoCodec implements MessageCodec {

    static final String HEADER = "# Engine.IO / Socket.IO packets: \"### <packet header>\" then the payload (JSON is re-compacted; other text is sent as is)\n";

    private enum Framing { SINGLE, V4, V3 }

    /** {@code payload} is the text shown (pretty JSON, or the stripped raw payload); {@code raw} the original packet. */
    private record Block(String header, String payload, boolean json, String raw) {
        String display() {
            return payload;
        }
    }

    @Override
    public String decoderId() {
        return SocketIoDecoder.ID;
    }

    @Override
    public List<EditableDocument> documents(MessageContext m, DecodeResult decoded) {
        try {
            EditableDocument d = document(m);
            return d == null ? List.of() : List.of(d);
        } catch (RuntimeException e) {
            return List.of();
        }
    }

    private static EditableDocument document(MessageContext m) {
        int eio = SocketIoDecoder.eioVersion(m);
        byte[] raw = m.body();
        if (raw.length == 0) return null;
        String ce = m.isResponse() ? m.header("Content-Encoding") : null;
        if (!EditJson.reEncodable(raw, ce)) return null;
        byte[] body = EditJson.hasEncoding(ce) ? Codecs.decodeContent(raw, ce) : raw;
        if (body.length > EditJson.MAX_DOCUMENT_CHARS || !textPackets(body)) return null;
        String text = new String(body, StandardCharsets.UTF_8);
        if (!java.util.Arrays.equals(text.getBytes(StandardCharsets.UTF_8), body)) return null; // not valid UTF-8

        List<String> packets;
        Framing framing;
        boolean trailingSep = false;
        if (m.isWebSocket()) {
            framing = Framing.SINGLE;
            packets = List.of(text);
        } else {
            if (m.isRequest() && Codecs.first(m.formParameters(), "d") != null) return null;
            String strip = text.strip();
            if (strip.equals("ok")) return null;
            String f = EngineIo.parsePolling(body, eio).framing();
            if (f.startsWith("v4")) {
                framing = Framing.V4;
                packets = new ArrayList<>(List.of(text.split(String.valueOf(EngineIo.RECORD_SEPARATOR), -1)));
                if (packets.size() > 1 && packets.get(packets.size() - 1).isEmpty()) {
                    packets.remove(packets.size() - 1);
                    trailingSep = true;
                }
            } else if (f.startsWith("v3 (")) {
                framing = Framing.V3;
                packets = splitV3(text);
                if (packets == null) return null;
            } else if (f.equals("single packet")) {
                framing = Framing.SINGLE;
                packets = List.of(text);
            } else {
                return null;
            }
        }
        if (packets.isEmpty() || packets.size() > EngineIo.MAX_PACKETS) return null;
        List<Block> blocks = new ArrayList<>();
        for (String p : packets) {
            Block b = block(p);
            if (b == null) return null;
            blocks.add(b);
        }
        StringBuilder sb = new StringBuilder(HEADER);
        for (Block b : blocks) {
            sb.append('\n').append("### ").append(b.header()).append('\n');
            if (!b.payload().isEmpty()) sb.append(b.payload()).append('\n');
        }
        String docText = sb.toString();
        String title = (m.isWebSocket() ? "Engine.IO packet" : "Engine.IO packets") + (blocks.size() > 1 ? " (" + blocks.size() + ")" : "");
        final Framing fr = framing;
        final boolean trailing = trailingSep;
        final int version = eio;
        return new EditJson.Doc(title, "text", docText, edited -> {
            List<String> out = encodeBlocks(edited, blocks, version);
            if (fr == Framing.SINGLE && out.size() != 1) {
                if (m.isWebSocket()) throw new EncodeException("A WebSocket frame carries exactly one Engine.IO packet; found " + out.size());
            }
            String joined = join(out, fr == Framing.SINGLE && out.size() > 1 ? (version == 3 ? Framing.V3 : Framing.V4) : fr, trailing);
            return MessagePatch.body(EditJson.reEncode(joined.getBytes(StandardCharsets.UTF_8), body, raw, ce));
        });
    }

    /** Starts like a text packet (type digit, v3 length digit or 'b') and has no control bytes but tab/CR/LF/RS. */
    private static boolean textPackets(byte[] b) {
        int c = b[0] & 0xff;
        if (!((c >= '0' && c <= '9') || c == 'b')) return false;
        for (byte x : b) {
            int v = x & 0xff;
            if (v < 0x20 && v != '\t' && v != '\n' && v != '\r' && v != 0x1e) return false;
        }
        return true;
    }

    /** v3 {@code <len>:<packet>} framing; null unless it consumes the whole text exactly. */
    static List<String> splitV3(String text) {
        List<String> out = new ArrayList<>();
        int i = 0;
        while (i < text.length()) {
            int colon = i;
            while (colon < text.length() && colon - i < 11 && Character.isDigit(text.charAt(colon))) colon++;
            if (colon == i || colon >= text.length() || text.charAt(colon) != ':') return null;
            long n = Long.parseLong(text.substring(i, colon));
            int start = colon + 1;
            if (start + n > text.length()) return null;
            out.add(text.substring(start, start + (int) n));
            i = start + (int) n;
            if (out.size() > EngineIo.MAX_PACKETS) return null;
        }
        return out.isEmpty() ? null : out;
    }

    private static String join(List<String> packets, Framing f, boolean trailingSep) {
        StringBuilder sb = new StringBuilder();
        switch (f) {
            case SINGLE -> sb.append(packets.get(0));
            case V4 -> {
                sb.append(String.join(String.valueOf(EngineIo.RECORD_SEPARATOR), packets));
                if (trailingSep) sb.append(EngineIo.RECORD_SEPARATOR);
            }
            case V3 -> {
                for (String p : packets) sb.append(p.length()).append(':').append(p);
            }
        }
        return sb.toString();
    }

    /** Splits a packet into header and payload; JSON payloads are pretty-printed. */
    static Block block(String raw) {
        if (raw.isEmpty()) return null;
        char c = raw.charAt(0);
        String header, payload;
        if (c == 'b') {
            return new Block("b", raw.substring(1), false, raw);
        }
        if (c == '4' && raw.length() > 1) {
            SocketIoPacket s = SocketIoPacket.parse(raw.substring(1));
            if (s.valid() && s.rawData() != null) {
                header = raw.substring(0, raw.length() - s.rawData().length());
                payload = s.rawData();
            } else {
                header = "4";
                payload = raw.substring(1);
            }
        } else {
            header = raw.substring(0, 1);
            payload = raw.substring(1);
        }
        if (header.indexOf('\n') >= 0 || header.indexOf('\r') >= 0) return null;
        JsonElement e = payload.isEmpty() ? null : EditJson.tryParse(payload);
        boolean json = e != null && (e.isJsonObject() || e.isJsonArray() || payload.startsWith("\""));
        String shown = json ? EditJson.pretty(e) : payload.strip();
        if (!json && (shown.contains("\n### ") || shown.startsWith("### ") || shown.equals("###") || shown.contains("\n###\n"))) return null; // would not survive the block format
        return new Block(header, shown, json, raw);
    }

    private static List<String> encodeBlocks(String edited, List<Block> original, int eio) throws EncodeException {
        String[] lines = edited.replace("\r\n", "\n").split("\n", -1);
        List<String> out = new ArrayList<>();
        String header = null;
        int headerLine = 0;
        StringBuilder payload = new StringBuilder();
        for (int i = 0; i <= lines.length; i++) {
            boolean end = i == lines.length;
            String line = end ? null : lines[i];
            if (end || line.startsWith("### ") || line.equals("###")) {
                if (header != null) out.add(packet(header, payload.toString().strip(), headerLine, out.size(), original, eio));
                if (end) break;
                header = line.length() > 4 ? line.substring(4).stripTrailing() : "";
                headerLine = i + 1;
                payload.setLength(0);
                continue;
            }
            if (header == null) {
                if (line.isBlank() || line.startsWith("#")) continue;
                throw new EncodeException("Line " + (i + 1) + ": text before the first \"### <packet header>\" line");
            }
            if (!payload.isEmpty()) payload.append('\n');
            payload.append(line);
        }
        if (out.isEmpty()) throw new EncodeException("No packets: add at least one \"### <packet header>\" line");
        return out;
    }

    private static String packet(String header, String payload, int line, int index, List<Block> original, int eio) throws EncodeException {
        String where = "Packet " + (index + 1) + " (line " + line + ")";
        if (index < original.size()) {
            Block o = original.get(index);
            if (o.header().equals(header) && o.display().equals(payload)) return o.raw();
        }
        if (header.isEmpty()) throw new EncodeException(where + ": empty packet header");
        char c = header.charAt(0);
        if (!(c == 'b' || (c >= '0' && c <= '6'))) throw new EncodeException(where + ": the header must start with an Engine.IO packet type 0-6 (or b for base64 binary)");
        if (c == 'b') {
            String b64 = header.substring(1) + payload;
            if (Codecs.base64Decode(eio == 3 && !b64.isEmpty() && Character.isDigit(b64.charAt(0)) ? b64.substring(1) : b64) == null) {
                throw new EncodeException(where + ": binary packet data is not valid base64");
            }
            return header + payload;
        }
        boolean wasRaw = index < original.size() && !original.get(index).json() && original.get(index).display().equals(payload);
        String data = payload;
        if (!payload.isEmpty() && !wasRaw) {
            char first = payload.charAt(0);
            boolean jsonish = first == '[' || first == '{' || first == '"';
            JsonElement e = jsonish ? null : EditJson.tryParse(payload);
            if (jsonish) e = parseOrFail(payload, where);
            if (e != null) data = EditJson.compact(e);
        }
        String packet = header + data;
        if (c == '4' && header.length() > 1) {
            SocketIoPacket s = SocketIoPacket.parse(packet.substring(1));
            if (!s.valid()) throw new EncodeException(where + ": invalid Socket.IO packet: " + s.error());
        }
        return packet;
    }

    private static JsonElement parseOrFail(String payload, String where) throws EncodeException {
        try {
            return EditJson.parse(payload, "JSON");
        } catch (EncodeException e) {
            throw new EncodeException(where + ": " + e.getMessage() + " (lines counted from the line after the header)", e);
        }
    }
}
