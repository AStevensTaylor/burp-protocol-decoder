package protocoldecoder.builtin.firebase;

import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.edit.EditableDocument;
import protocoldecoder.edit.JsonDocuments;
import protocoldecoder.edit.JsonDocuments.Body;
import protocoldecoder.edit.JsonDocuments.JsonView;
import protocoldecoder.edit.JsonDocuments.Node;
import protocoldecoder.edit.JsonDocuments.Param;
import protocoldecoder.edit.MessageCodec;
import protocoldecoder.edit.MessagePatch;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Firebase documents: one per Firestore WebChannel {@code reqN___data__} map (re-URL-encoded into the form like the
 * original, {@code count}/{@code ofs} and all other fields kept), JSON bodies of Firestore REST, Realtime Database
 * REST ({@code .json}), Identity Toolkit and Secure Token requests/responses, and complete Realtime Database
 * WebSocket frames ({@code {"t":"d","d":…}}). Multi-frame count prefixes and fragments are not editable.
 */
public final class FirebaseCodec implements MessageCodec {

    private static final Pattern REQ_DATA = Pattern.compile("^req(\\d{1,6})___data__$");

    @Override
    public String decoderId() {
        return FirebaseDecoder.ID;
    }

    @Override
    public List<EditableDocument> documents(MessageContext m, DecodeResult decoded) {
        List<EditableDocument> out = new ArrayList<>();
        FirebaseDecoder.Variant v = FirebaseDecoder.variant(m);
        if (m.isWebSocket()) {
            webSocket(m, out);
            return out;
        }
        switch (v) {
            case FIRESTORE_CHANNEL -> {
                if (m.isRequest()) channel(m, out);
            }
            case FIRESTORE_REST -> body(m, out, m.isRequest() ? "Firestore request" : "Firestore response");
            case RTDB_REST -> body(m, out, m.isRequest() ? "RTDB data (request)" : "RTDB data (response)");
            case IDENTITY_TOOLKIT, SECURE_TOKEN -> body(m, out, m.isRequest() ? "Firebase Auth request" : "Firebase Auth response");
            default -> {
            }
        }
        return out;
    }

    private static void channel(MessageContext m, List<EditableDocument> out) {
        Body body = Body.of(m);
        if (body == null || body.text().isBlank()) return;
        String raw = body.text();
        String stream = Firestore.stream(m);
        boolean any = false;
        for (Param p : JsonDocuments.params(raw)) {
            Matcher rm = REQ_DATA.matcher(p.name());
            if (!rm.matches()) continue;
            any = true;
            JsonView view = JsonView.of(p.value());
            if (view == null) continue;
            JsonDocuments.add(out, JsonDocuments.json("Firestore " + stream + " req" + rm.group(1), view,
                    s -> body.patch(JsonDocuments.replaceParam(raw, p, s, JsonDocuments::encodeURIComponent))));
        }
        if (!any) body(m, out, "Firestore " + stream + " request");
    }

    private static void body(MessageContext m, List<EditableDocument> out, String title) {
        String ct = m.contentType().toLowerCase(java.util.Locale.ROOT);
        if (ct.contains("event-stream")) return;
        Body body = Body.of(m);
        if (body == null || body.text().isBlank()) return;
        JsonView view = JsonView.of(body.text());
        if (view != null) JsonDocuments.add(out, JsonDocuments.json(title, view, body::patch));
    }

    private static void webSocket(MessageContext m, List<EditableDocument> out) {
        String text = m.bodyText();
        if (text.length() > JsonDocuments.MAX_TEXT) return;
        Node root = JsonDocuments.tryParse(text);
        if (root == null || !root.isObject() || root.get("t") == null) return; // count prefix or fragment
        JsonView view = JsonView.of(text);
        if (view != null) JsonDocuments.add(out, JsonDocuments.json("RTDB frame", view, s -> MessagePatch.body(s)));
    }
}
