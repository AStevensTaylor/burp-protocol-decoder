package protocoldecoder.builtin.graphql;

import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.edit.EditableDocument;
import protocoldecoder.edit.JsonDocuments;
import protocoldecoder.edit.JsonDocuments.Body;
import protocoldecoder.edit.JsonDocuments.JsonView;
import protocoldecoder.edit.JsonDocuments.Param;
import protocoldecoder.edit.MessageCodec;
import protocoldecoder.edit.MessagePatch;

import java.util.ArrayList;
import java.util.List;

/**
 * tRPC documents: the whole {@code input} query parameter of GET calls (batch index keys and superjson
 * {@code {json, meta}} envelopes included) as pretty JSON, re-encoded into the query with {@code encodeURIComponent}
 * like the tRPC client (or like the original value, if it was encoded differently); POST bodies and responses as
 * pretty JSON.
 */
public final class TrpcCodec implements MessageCodec {

    @Override
    public String decoderId() {
        return TrpcDecoder.ID;
    }

    @Override
    public List<EditableDocument> documents(MessageContext m, DecodeResult decoded) {
        List<EditableDocument> out = new ArrayList<>();
        if (m.isWebSocket()) return out;
        List<String> procs = TrpcDecoder.procedures(m.path());
        String what = procs == null || procs.isEmpty() ? "" : " (" + String.join(", ", procs) + ")";
        if (m.isRequest()) {
            String q = m.query();
            Param input = q == null ? null : JsonDocuments.param(q, "input");
            if (input != null) {
                JsonView view = JsonView.of(input.value());
                if (view != null) {
                    JsonDocuments.add(out, JsonDocuments.json("tRPC input" + what, view,
                            s -> MessagePatch.query(JsonDocuments.replaceParam(q, input, s, JsonDocuments::encodeURIComponent))));
                }
            }
            if (m.requestBody().length > 0) body(out, m, "tRPC input body" + what);
        } else {
            body(out, m, "tRPC response" + what);
        }
        return out;
    }

    private static void body(List<EditableDocument> out, MessageContext m, String title) {
        Body body = Body.of(m);
        if (body == null) return;
        JsonView view = JsonView.of(body.text());
        if (view != null) JsonDocuments.add(out, JsonDocuments.json(title, view, body::patch));
    }
}
