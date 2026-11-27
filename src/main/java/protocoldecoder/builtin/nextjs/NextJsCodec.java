package protocoldecoder.builtin.nextjs;

import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.edit.EditableDocument;
import protocoldecoder.edit.JsonDocuments;
import protocoldecoder.edit.JsonDocuments.Body;
import protocoldecoder.edit.JsonDocuments.JsonView;
import protocoldecoder.edit.MessageCodec;
import protocoldecoder.edit.MessagePatch;
import protocoldecoder.util.Codecs;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Next.js documents:
 * <ul>
 * <li>Server Action requests: JSON arguments ("Server Action arguments"), or one document per non-file multipart
 * field (the body is re-assembled with the original boundary; edits containing the boundary are rejected);</li>
 * <li>the {@code Next-Router-State-Tree} header as JSON, re-encoded with {@code encodeURIComponent} like the
 * browser;</li>
 * <li>responses: {@code __NEXT_DATA__} in HTML pages, re-embedded with {@code <>&} U+2028 U+2029 escaped as
 * {@code \\u003c}… (Next.js {@code htmlEscapeJsonString}), and {@code /_next/data/…json} bodies.</li>
 * </ul>
 */
public final class NextJsCodec implements MessageCodec {

    private static final Pattern DATA_PATH = Pattern.compile("/_next/data/([^/]+)/(.+)\\.json$");
    private static final Pattern NEXT_DATA_TAG = Pattern.compile("<script\\b[^>]*\\bid=[\"']?__NEXT_DATA__[\"']?[^>]*>", Pattern.CASE_INSENSITIVE);

    @Override
    public String decoderId() {
        return NextJsDecoder.ID;
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
        String ct = m.requestContentType().toLowerCase(Locale.ROOT);
        boolean action = m.requestHeader("Next-Action") != null;
        byte[] raw = m.requestBody();
        if (raw.length > 0 && ct.contains("multipart/form-data")) {
            String head = Codecs.latin1String(java.util.Arrays.copyOf(raw, Math.min(raw.length, 64 * 1024)));
            if (action || head.contains("$ACTION_ID_") || head.contains("$ACTION_REF_")) multipart(m, out);
        } else if (raw.length > 0 && action && !ct.contains("x-www-form-urlencoded")) {
            Body body = Body.of(m);
            JsonView view = body == null ? null : JsonView.of(body.text());
            if (view != null) JsonDocuments.add(out, JsonDocuments.json("Server Action arguments", view, body::patch));
        }
        stateTree(m, out);
    }

    private static void multipart(MessageContext m, List<EditableDocument> out) {
        if (m.requestHeader("Content-Encoding") != null) return;
        byte[] raw = m.requestBody();
        String boundary = JsonDocuments.boundary(m.requestContentType());
        List<JsonDocuments.Part> parts = JsonDocuments.multipart(raw, boundary);
        if (parts == null) return;
        for (JsonDocuments.Part p : parts) {
            if (out.size() >= JsonDocuments.MAX_DOCS - 1) break; // keep room for the router state tree
            if (p.filename() != null || p.name() == null) continue;
            if (p.contentEnd() - p.contentStart() > JsonDocuments.MAX_TEXT) continue;
            String text = JsonDocuments.partText(raw, p);
            String title = "Server Action field \"" + p.name() + "\"";
            JsonView view = JsonDocuments.looksLikeContainer(text) ? JsonView.of(text) : null;
            if (view != null) {
                JsonDocuments.add(out, JsonDocuments.json(title, view, s -> MessagePatch.body(JsonDocuments.replacePart(raw, p, boundary, s))));
            } else {
                JsonDocuments.add(out, JsonDocuments.document(title, "text", text,
                        s -> MessagePatch.body(JsonDocuments.replacePart(raw, p, boundary, s))));
            }
        }
    }

    private static void stateTree(MessageContext m, List<EditableDocument> out) {
        String header = null;
        for (var h : m.requestHeaders()) if (h.name().equalsIgnoreCase(NextJsScanner.STATE_TREE)) header = h.value();
        if (header == null || header.isBlank()) return;
        String value = header;
        String json;
        UnaryOperator<String> enc;
        if (JsonDocuments.tryParse(value) != null) {
            json = value; // sent unencoded
            enc = UnaryOperator.identity();
        } else {
            json = Codecs.urlDecode(value.replace("+", "%2B"));
            enc = JsonDocuments.urlEncoderLike(value, json, JsonDocuments::encodeURIComponent);
        }
        JsonView view = JsonView.of(json);
        if (view == null) return;
        String decodedOriginal = json;
        JsonDocuments.add(out, JsonDocuments.json("Next-Router-State-Tree", view,
                s -> MessagePatch.header(NextJsScanner.STATE_TREE, s.equals(decodedOriginal) ? value : enc.apply(s))));
    }

    // ------------------------------------------------------------------ responses

    private static void response(MessageContext m, List<EditableDocument> out) {
        Body body = Body.of(m);
        if (body == null || body.text().isEmpty()) return;
        String text = body.text();
        if (DATA_PATH.matcher(m.path()).find()) {
            JsonView view = JsonView.of(text);
            if (view != null) JsonDocuments.add(out, JsonDocuments.json("Page data (/_next/data)", view, body::patch));
            return;
        }
        Matcher tm = NEXT_DATA_TAG.matcher(text);
        if (!tm.find()) return;
        int start = tm.end();
        int end = text.indexOf("</script", start);
        if (end < 0) return;
        String content = text.substring(start, end);
        JsonView view = JsonView.of(content);
        if (view == null) return;
        JsonDocuments.add(out, JsonDocuments.json("__NEXT_DATA__", view, s -> {
            String embedded = s.equals(content) ? s : JsonDocuments.restyle(s, JsonDocuments.Style.HTML_SAFE);
            return body.patch(JsonDocuments.splice(text, start, end, embedded));
        }));
    }
}
