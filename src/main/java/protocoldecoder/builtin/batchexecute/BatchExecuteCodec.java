package protocoldecoder.builtin.batchexecute;

import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.edit.EditableDocument;
import protocoldecoder.edit.JsonDocuments;
import protocoldecoder.edit.JsonDocuments.Body;
import protocoldecoder.edit.JsonDocuments.JsonView;
import protocoldecoder.edit.JsonDocuments.Node;
import protocoldecoder.edit.JsonDocuments.Param;
import protocoldecoder.edit.JsonDocuments.Rebuild;
import protocoldecoder.edit.MessageCodec;
import protocoldecoder.edit.MessagePatch;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Google batchexecute documents. Requests: one "RPC &lt;id&gt; arguments" document per f.req envelope, showing the
 * arguments with every JSON-in-string level unwrapped (up to {@link BatchExecuteScanner#MAX_NESTING} levels below the
 * arguments string, like the scanner); on encode each level is re-stringified (unchanged levels keep their exact
 * original string) and f.req is re-URL-encoded like the original. Responses: one "RPC &lt;id&gt; response" document per
 * {@code wrb.fr} payload; the {@code )]}'} prefix and all other bytes are kept, and for {@code rt=c} the edited chunk's
 * length header is recomputed in the unit (UTF-16 chars, bytes or code points, with the same offset) the original used.
 */
public final class BatchExecuteCodec implements MessageCodec {

    private static final Pattern RPC_ID = Pattern.compile("[A-Za-z0-9_.$-]+");
    private static final int UNWRAP = 1 + BatchExecuteScanner.MAX_NESTING;

    @Override
    public String decoderId() {
        return BatchExecuteDecoder.ID;
    }

    @Override
    public List<EditableDocument> documents(MessageContext m, DecodeResult decoded) {
        List<EditableDocument> out = new ArrayList<>();
        if (m.isRequest()) request(m, out);
        else if (m.isResponse()) response(m, out);
        return out;
    }

    // ------------------------------------------------------------------ requests

    private static void request(MessageContext m, List<EditableDocument> out) {
        Body body = Body.of(m);
        Param p = body == null ? null : JsonDocuments.param(body.text(), "f.req");
        if (p != null) {
            String raw = body.text();
            freqDocs(out, p.value(), freq -> body.patch(JsonDocuments.replaceParam(raw, p, freq, JsonDocuments::formEncode)));
            return;
        }
        String q = m.query();
        Param qp = q == null ? null : JsonDocuments.param(q, "f.req");
        if (qp != null) freqDocs(out, qp.value(), freq -> MessagePatch.query(JsonDocuments.replaceParam(q, qp, freq, JsonDocuments::formEncode)));
    }

    private static void freqDocs(List<EditableDocument> out, String freq, Rebuild outer) {
        if (freq.length() > JsonDocuments.MAX_TEXT) return;
        Node root = JsonDocuments.tryParse(freq);
        if (root == null || !root.isArray()) return;
        List<Node> envs = new ArrayList<>();
        envelopes(root, envs, 0);
        for (Node env : envs) {
            Node inner = env.get(1);
            JsonView view = JsonView.ofStringToken(inner.raw(), UNWRAP);
            if (view == null) continue;
            JsonDocuments.add(out, JsonDocuments.json("RPC " + env.get(0).string() + " arguments", view,
                    s -> outer.apply(JsonDocuments.splice(freq, inner.start(), inner.end(), s))));
        }
    }

    /** [rpcid, "&lt;json&gt;", null, tag] arrays up to 3 levels deep (same shape rules as the decoder). */
    private static void envelopes(Node a, List<Node> out, int depth) {
        if (depth > 3 || out.size() >= JsonDocuments.MAX_DOCS) return;
        if (isEnvelope(a)) {
            out.add(a);
            return;
        }
        for (Node e : a.items()) if (e.isArray()) envelopes(e, out, depth + 1);
    }

    private static boolean isEnvelope(Node a) {
        if (a.size() < 2 || a.size() > 6) return false;
        Node id = a.get(0), inner = a.get(1);
        if (!id.isString() || !inner.isString()) return false;
        String s = id.string();
        return !s.isEmpty() && s.length() <= 64 && RPC_ID.matcher(s).matches() && JsonDocuments.looksLikeContainer(inner.string());
    }

    // ------------------------------------------------------------------ responses

    private static void response(MessageContext m, List<EditableDocument> out) {
        Body body = Body.of(m);
        if (body == null) return;
        String s = body.text();
        int pos = 0;
        int x = s.indexOf(BatchExecuteDecoder.XSSI);
        if (x >= 0 && s.substring(0, x).isBlank()) pos = x + BatchExecuteDecoder.XSSI.length();
        if (ChunkedJson.looksChunked(s, pos)) {
            List<ChunkedJson.Chunk> chunks = ChunkedJson.parse(s, pos).chunks();
            for (int i = 0; i < chunks.size() && out.size() < JsonDocuments.MAX_DOCS; i++) {
                ChunkedJson.Chunk c = chunks.get(i);
                int nl = s.indexOf('\n', c.offset());
                if (nl < 0) continue;
                int bodyStart = nl + 1;
                int js = s.indexOf(c.raw(), bodyStart);
                if (js < 0 || !s.substring(bodyStart, js).isBlank()) continue;
                int spanEnd = i + 1 < chunks.size() ? chunks.get(i + 1).offset() : s.length();
                if (js + c.raw().length() > spanEnd) continue;
                int digitsEnd = c.offset();
                while (digitsEnd < s.length() && Character.isDigit(s.charAt(digitsEnd))) digitsEnd++;
                Unit unit = Unit.of(c.declaredLength(), s.substring(bodyStart, spanEnd));
                int de = digitsEnd;
                entries(out, c.raw(), newChunk -> {
                    String span = s.substring(bodyStart, js) + newChunk + s.substring(js + c.raw().length(), spanEnd);
                    String rebuilt = s.substring(0, c.offset()) + unit.length(span) + s.substring(de, bodyStart) + span + s.substring(spanEnd);
                    return body.patch(rebuilt);
                });
            }
        } else {
            String rest = s.substring(pos);
            int open = rest.indexOf('[');
            if (open < 0 || !rest.substring(0, open).isBlank()) return;
            int start = pos + open;
            String json = s.substring(start).stripTrailing();
            entries(out, json, newJson -> body.patch(s.substring(0, start) + newJson + s.substring(start + json.length())));
        }
    }

    /** Documents for the wrb.fr entries of one chunk ([[entry…]] or a single tagged entry). */
    private static void entries(List<EditableDocument> out, String chunk, Rebuild outer) {
        Node root = JsonDocuments.tryParse(chunk);
        if (root == null || !root.isArray()) return;
        List<Node> list = root.size() > 0 && root.get(0).isString() ? List.of(root) : root.items();
        for (Node e : list) {
            if (!e.isArray() || e.size() < 3 || !e.get(0).isString() || !"wrb.fr".equals(e.get(0).string())) continue;
            Node payload = e.get(2);
            if (!payload.isString()) continue;
            JsonView view = JsonView.ofStringToken(payload.raw(), UNWRAP);
            if (view == null) continue;
            String rpc = e.get(1).isString() ? e.get(1).string() : "?";
            JsonDocuments.add(out, JsonDocuments.json("RPC " + rpc + " response", view,
                    p -> outer.apply(JsonDocuments.splice(chunk, payload.start(), payload.end(), p))));
        }
    }

    /** How a chunk's declared length relates to its text: unit plus constant offset (e.g. a counted newline). */
    record Unit(int kind, int delta) {
        static Unit of(int declared, String span) {
            int best = 0, bestDiff = Integer.MAX_VALUE;
            for (int k = 0; k < 3; k++) {
                int d = declared - measure(k, span);
                if (Math.abs(d) < Math.abs(bestDiff)) {
                    best = k;
                    bestDiff = d;
                }
            }
            return new Unit(best, bestDiff);
        }

        static int measure(int kind, String s) {
            return switch (kind) {
                case 0 -> s.length();
                case 1 -> s.getBytes(StandardCharsets.UTF_8).length;
                default -> s.codePointCount(0, s.length());
            };
        }

        int length(String span) {
            return Math.max(0, measure(kind, span) + delta);
        }
    }
}
