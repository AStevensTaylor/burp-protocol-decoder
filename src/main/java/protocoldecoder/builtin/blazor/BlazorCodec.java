package protocoldecoder.builtin.blazor;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.edit.EditableDocument;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.edit.MessageCodec;
import protocoldecoder.edit.MessagePatch;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.EditJson;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Documents for SignalR hub payloads (WebSocket frames and long-polling bodies, both directions):
 * <ul>
 *   <li>JSON hub protocol: the records (handshake included) as a pretty JSON array; each element is written back
 *       compactly followed by {@code \x1e};</li>
 *   <li>MessagePack (blazorpack): the hub messages as a JSON array in the {@link MsgPackJson} mapping, re-encoded to
 *       MessagePack with VarInt length prefixes; a leading JSON handshake record is kept as is.</li>
 * </ul>
 * Elements the user did not change are written back byte-for-byte (so the server's own JSON escaping and the
 * client's MessagePack integer widths survive); changed elements are re-serialised canonically.
 */
public final class BlazorCodec implements MessageCodec {

    @Override
    public String decoderId() {
        return BlazorDecoder.ID;
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
        if (!m.isWebSocket()) {
            String p = m.path().toLowerCase(Locale.ROOT);
            if (p.endsWith("/negotiate") || p.endsWith("/disconnect") || p.endsWith(".json")) return null;
        }
        byte[] raw = m.body();
        if (raw.length == 0) return null;
        String ce = m.isWebSocket() || m.isRequest() ? null : m.header("Content-Encoding");
        if (!EditJson.reEncodable(raw, ce)) return null;
        byte[] payload = EditJson.hasEncoding(ce) ? Codecs.decodeContent(raw, ce) : raw;
        if (payload.length > EditJson.MAX_DOCUMENT_CHARS) return null;

        // Leading JSON records (handshake, or every record of the JSON protocol).
        List<String> records = new ArrayList<>();
        int pos = 0;
        while (pos < payload.length && payload[pos] == '{') {
            int rs = indexOf(payload, (byte) SignalR.RS, pos);
            if (rs < 0) break;
            records.add(new String(payload, pos, rs - pos, StandardCharsets.UTF_8));
            pos = rs + 1;
        }
        Encoder toPatch = newPayload -> MessagePatch.body(EditJson.reEncode(newPayload, payload, raw, ce));
        if (pos >= payload.length) return records.isEmpty() ? null : jsonDocument(records, toPatch);
        List<int[]> frames = SignalR.binaryFrames(payload, pos);
        if (frames == null || frames.size() > 1000) return null;
        return packDocument(payload, pos, frames, toPatch);
    }

    private interface Encoder {
        MessagePatch apply(byte[] payload) throws EncodeException;
    }

    // ---------------------------------------------------------------- JSON hub protocol

    private static EditableDocument jsonDocument(List<String> records, Encoder toPatch) {
        JsonArray all = new JsonArray();
        List<String> canonical = new ArrayList<>();
        boolean handshakeOnly = true;
        for (String r : records) {
            JsonElement e = EditJson.tryParse(r);
            if (e == null || !e.isJsonObject()) return null;
            if (e.getAsJsonObject().has("type")) handshakeOnly = false;
            all.add(e);
            canonical.add(EditJson.compact(e));
        }
        String text = EditJson.pretty(all);
        String title = handshakeOnly ? "SignalR handshake (JSON)" : "SignalR JSON messages";
        return new EditJson.Doc(title, "json", text, edited -> {
            JsonElement e = EditJson.parse(edited, "JSON");
            if (!e.isJsonArray()) throw new EncodeException("The document must be a JSON array with one element per hub message");
            StringBuilder sb = new StringBuilder();
            JsonArray a = e.getAsJsonArray();
            for (int i = 0; i < a.size(); i++) {
                JsonElement x = a.get(i);
                if (!x.isJsonObject()) throw new EncodeException("Message " + (i + 1) + " must be a JSON object (SignalR JSON records are objects)");
                String c = EditJson.compact(x);
                sb.append(i < canonical.size() && canonical.get(i).equals(c) ? records.get(i) : c).append(SignalR.RS);
            }
            return toPatch.apply(sb.toString().getBytes(StandardCharsets.UTF_8));
        });
    }

    // ---------------------------------------------------------------- MessagePack hub protocol

    private static EditableDocument packDocument(byte[] p, int prefixEnd, List<int[]> frames, Encoder toPatch) {
        JsonArray all = new JsonArray();
        List<String> canonical = new ArrayList<>();
        List<byte[]> originals = new ArrayList<>();
        boolean renderBatch = false;
        int prev = prefixEnd;
        for (int[] f : frames) {
            JsonElement e;
            try {
                e = MsgPackJson.toJson(p, f[0], f[1]);
            } catch (MsgPack.FormatException ex) {
                return null;
            }
            all.add(e);
            canonical.add(EditJson.compact(e));
            originals.add(Arrays.copyOfRange(p, prev, f[1])); // VarInt prefix + message
            prev = f[1];
            if (e.isJsonArray() && e.getAsJsonArray().size() > 3 && e.getAsJsonArray().get(3).isJsonPrimitive()
                    && "JS.RenderBatch".equals(e.getAsJsonArray().get(3).getAsString())) renderBatch = true;
        }
        String text = EditJson.pretty(all);
        if (text.length() > EditJson.MAX_DOCUMENT_CHARS) return null;
        byte[] prefix = Arrays.copyOfRange(p, 0, prefixEnd);
        String title = "SignalR MessagePack messages" + (prefixEnd > 0 ? " (handshake kept)" : "")
                + (renderBatch ? " (render batches as $bin, not editable structurally)" : "");
        return new EditJson.Doc(title, "json", text, edited -> {
            JsonElement e = EditJson.parse(edited, "JSON");
            if (!e.isJsonArray()) throw new EncodeException("The document must be a JSON array with one element per hub message");
            JsonArray a = e.getAsJsonArray();
            if (a.isEmpty()) throw new EncodeException("At least one hub message is required");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.writeBytes(prefix);
            for (int i = 0; i < a.size(); i++) {
                JsonElement x = a.get(i);
                if (i < canonical.size() && canonical.get(i).equals(EditJson.compact(x))) {
                    out.writeBytes(originals.get(i));
                    continue;
                }
                byte[] msg = MsgPackJson.fromJson(x, "message " + (i + 1));
                out.writeBytes(MsgPackWriter.varInt(msg.length));
                out.writeBytes(msg);
            }
            return toPatch.apply(out.toByteArray());
        });
    }

    private static int indexOf(byte[] p, byte v, int from) {
        for (int i = from; i < p.length; i++) if (p[i] == v) return i;
        return -1;
    }
}
