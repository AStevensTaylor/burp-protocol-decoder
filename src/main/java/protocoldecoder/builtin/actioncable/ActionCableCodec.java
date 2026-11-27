package protocoldecoder.builtin.actioncable;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.edit.EditableDocument;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.edit.MessageCodec;
import protocoldecoder.edit.MessagePatch;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.EditJson;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * One JSON document per Action Cable frame. The JSON-in-a-string fields {@code identifier} and {@code data} are
 * unfolded into nested JSON for editing and re-stringified compactly on encode (as the Rails client's
 * {@code JSON.stringify} does); leave them as strings to send them verbatim. Unchanged nested values and unchanged
 * frames are written back byte-for-byte.
 */
public final class ActionCableCodec implements MessageCodec {

    static final List<String> NESTED = List.of("identifier", "data");

    @Override
    public String decoderId() {
        return ActionCableDecoder.ID;
    }

    @Override
    public List<EditableDocument> documents(MessageContext m, DecodeResult decoded) {
        try {
            if (!m.isWebSocket()) return List.of();
            byte[] b = m.body();
            if (b.length == 0 || b.length > EditJson.MAX_DOCUMENT_CHARS) return List.of();
            String text = Codecs.utf8(b);
            JsonElement e = EditJson.tryParse(text);
            if (e == null || !e.isJsonObject()) return List.of();
            JsonObject frame = e.getAsJsonObject();
            JsonObject unfolded = frame.deepCopy();
            for (String k : NESTED) {
                String inner = str(frame, k);
                if (inner == null) continue;
                JsonElement x = EditJson.tryParse(inner);
                if (x != null && (x.isJsonObject() || x.isJsonArray())) unfolded.add(k, x);
            }
            String canonical = EditJson.compact(unfolded);
            String title = "Action Cable frame" + describe(frame);
            return List.of(new EditJson.Doc(title, "json", EditJson.pretty(unfolded), edited -> {
                JsonElement p = EditJson.parse(edited, "JSON");
                if (!p.isJsonObject()) throw new EncodeException("An Action Cable frame must be a JSON object");
                if (EditJson.compact(p).equals(canonical)) return MessagePatch.body(b);
                JsonObject out = new JsonObject();
                for (Map.Entry<String, JsonElement> en : p.getAsJsonObject().entrySet()) {
                    JsonElement v = en.getValue();
                    if (NESTED.contains(en.getKey()) && (v.isJsonObject() || v.isJsonArray())) {
                        String originalInner = str(frame, en.getKey());
                        JsonElement before = unfolded.get(en.getKey());
                        String inner = originalInner != null && before != null && EditJson.compact(before).equals(EditJson.compact(v))
                                ? originalInner : EditJson.compact(v);
                        out.addProperty(en.getKey(), inner);
                    } else {
                        out.add(en.getKey(), v);
                    }
                }
                return MessagePatch.body(EditJson.compact(out).getBytes(StandardCharsets.UTF_8));
            }));
        } catch (RuntimeException ex) {
            return List.of();
        }
    }

    private static String describe(JsonObject o) {
        String cmd = str(o, "command"), type = str(o, "type");
        String what = cmd != null ? cmd : type;
        return what == null ? "" : " (" + what + ")";
    }

    private static String str(JsonObject o, String k) {
        JsonElement e = o.get(k);
        return e != null && e.isJsonPrimitive() && e.getAsJsonPrimitive().isString() ? e.getAsString() : null;
    }
}
