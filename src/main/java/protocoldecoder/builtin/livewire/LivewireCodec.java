package protocoldecoder.builtin.livewire;

import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.edit.EditableDocument;
import protocoldecoder.edit.JsonDocuments;
import protocoldecoder.edit.JsonDocuments.Body;
import protocoldecoder.edit.JsonDocuments.JsonView;
import protocoldecoder.edit.JsonDocuments.Node;
import protocoldecoder.edit.MessageCodec;

import java.util.ArrayList;
import java.util.List;

/**
 * Livewire documents: the whole JSON body of update/message requests ("Livewire request") and responses ("Livewire
 * response"), and for each v3 component whose {@code snapshot} is a JSON string, the decoded snapshot ("(signed)
 * Snapshot data …"), re-stringified into the {@code snapshot} field on encode. The snapshot checksum is an HMAC over
 * the snapshot with the app key, so an edited snapshot will be rejected unless the server skips verification — which
 * is exactly what the scanner's checksum-enforcement check probes.
 */
public final class LivewireCodec implements MessageCodec {

    @Override
    public String decoderId() {
        return LivewireDecoder.ID;
    }

    @Override
    public List<EditableDocument> documents(MessageContext m, DecodeResult decoded) {
        List<EditableDocument> out = new ArrayList<>();
        if (m.isWebSocket()) return out;
        Body body = Body.of(m);
        if (body == null) return out;
        String text = body.text();
        if (!JsonDocuments.looksLikeContainer(text)) return out;
        JsonView view = JsonView.of(text);
        if (view == null) return out;
        JsonDocuments.add(out, JsonDocuments.json(m.isRequest() ? "Livewire request" : "Livewire response", view, body::patch));
        if (!m.isRequest()) return out;
        Node root = JsonDocuments.tryParse(text);
        Node comps = root == null || !root.isObject() ? null : root.get("components");
        if (comps == null || !comps.isArray()) return out;
        for (int i = 0; i < comps.size() && out.size() < JsonDocuments.MAX_DOCS; i++) {
            Node c = comps.get(i);
            Node snap = c.isObject() ? c.get("snapshot") : null;
            if (snap == null || !snap.isString()) continue;
            JsonView sv = JsonView.ofStringToken(snap.raw(), 1);
            if (sv == null) continue;
            JsonDocuments.add(out, JsonDocuments.json("(signed) Snapshot data: " + name(snap, i) + " (checksum will break)", sv,
                    s -> body.patch(JsonDocuments.splice(text, snap.start(), snap.end(), s))));
        }
        return out;
    }

    private static String name(Node snap, int index) {
        Node inner = JsonDocuments.tryParse(snap.string());
        Node memo = inner == null || !inner.isObject() ? null : inner.get("memo");
        Node name = memo == null || !memo.isObject() ? null : memo.get("name");
        return name != null && name.isString() ? name.string() : "component " + (index + 1);
    }
}
