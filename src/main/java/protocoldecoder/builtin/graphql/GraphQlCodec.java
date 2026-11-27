package protocoldecoder.builtin.graphql;

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

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.UnaryOperator;

/**
 * GraphQL documents: per operation the query text exactly as sent ("GraphQL query"), a re-formatted copy whose encode
 * sends the formatted text ("GraphQL query (formatted)"), and the variables as pretty JSON ("GraphQL variables"), in
 * every request transport (JSON body or batch, GET/form parameters, multipart {@code operations}, application/graphql)
 * and in GraphQL-over-WebSocket subscribe/start messages. JSON responses are offered as "GraphQL response".
 *
 * <p>Edits are spliced into the original text: operationName, extensions and every other byte are untouched, a JSON
 * string is re-escaped in the original's style, a string-encoded variables value stays a string, and GET/form
 * parameters are re-URL-encoded like the original value.</p>
 */
public final class GraphQlCodec implements MessageCodec {

    @Override
    public String decoderId() {
        return GraphQlDecoder.ID;
    }

    @Override
    public List<EditableDocument> documents(MessageContext m, DecodeResult decoded) {
        List<EditableDocument> out = new ArrayList<>();
        switch (m.kind()) {
            case REQUEST -> request(m, out);
            case RESPONSE -> response(m, out);
            case WEBSOCKET -> webSocket(m, out);
        }
        return out;
    }

    // ------------------------------------------------------------------ requests

    private static void request(MessageContext m, List<EditableDocument> out) {
        String ct = m.requestContentType().toLowerCase(Locale.ROOT);
        byte[] raw = m.requestBody();
        if (raw.length > 0) {
            if (ct.contains("multipart/form-data")) {
                multipart(m, out);
                return;
            }
            Body body = Body.of(m);
            if (body == null) return;
            if (GraphQlDecoder.isGraphQlContentType(ct) || GraphQlDocument.isLikelyDocument(GraphQlDecoder.head(body.decoded()))) {
                queryDocs(out, "", body.text(), body::patch);
                return;
            }
            if (ct.contains("x-www-form-urlencoded")) {
                params(out, body.text(), JsonDocuments::formEncode, body::patch);
                return;
            }
            Node root = JsonDocuments.tryParse(body.text());
            if (root != null && (root.isObject() || root.isArray())) {
                operations(out, body.text(), root, body::patch);
                if (!out.isEmpty()) return;
            }
        }
        String q = m.query();
        if (q != null && !q.isEmpty()) params(out, q, JsonDocuments::encodeURIComponent, s -> MessagePatch.query(s));
    }

    private static void multipart(MessageContext m, List<EditableDocument> out) {
        String boundary = JsonDocuments.boundary(m.requestContentType());
        byte[] raw = m.requestBody();
        List<JsonDocuments.Part> parts = JsonDocuments.multipart(raw, boundary);
        if (parts == null) return;
        for (JsonDocuments.Part p : parts) {
            if (!"operations".equals(p.name()) || p.filename() != null) continue;
            String json = JsonDocuments.partText(raw, p);
            Node root = JsonDocuments.tryParse(json);
            if (root == null) return;
            operations(out, json, root, s -> MessagePatch.body(JsonDocuments.replacePart(raw, p, boundary, s)));
            return;
        }
    }

    /** Documents for an operation object or a batch array inside {@code json}; {@code outer} re-encodes new JSON. */
    static void operations(List<EditableDocument> out, String json, Node root, Rebuild outer) {
        if (root.isObject()) {
            operation(out, json, root, "", outer);
        } else if (root.isArray()) {
            int n = root.size();
            for (int i = 0; i < n && out.size() < JsonDocuments.MAX_DOCS; i++) {
                Node op = root.get(i);
                if (op.isObject()) operation(out, json, op, n == 1 ? "" : " #" + (i + 1) + label(op), outer);
            }
        }
    }

    private static String label(Node op) {
        Node name = op.get("operationName");
        if (name != null && name.isString() && !name.string().isEmpty()) return " (" + name.string() + ")";
        Node q = op.get("query");
        if (q != null && q.isString()) {
            GraphQlDocument.Operation sel = GraphQlDocument.parse(q.string()).select(null);
            if (sel != null) return " (" + (sel.name() != null ? sel.name() : sel.type()) + ")";
        }
        return "";
    }

    private static void operation(List<EditableDocument> out, String json, Node op, String suffix, Rebuild outer) {
        Node q = op.get("query");
        Node vars = op.get("variables");
        if (!(q != null && q.isString()) && vars == null && op.get("extensions") == null && op.get("documentId") == null) return;
        JsonDocuments.Style style = JsonDocuments.Style.detect(json);
        if (q != null && q.isString()) {
            String orig = q.string();
            queryDocs(out, suffix, orig, edited -> outer.apply(JsonDocuments.splice(json, q.start(), q.end(),
                    edited.equals(orig) ? q.raw() : JsonDocuments.quote(edited, style))));
        }
        if (vars != null) {
            JsonView view = vars.isString() ? JsonView.ofStringToken(vars.raw(), 1)
                    : vars.isObject() || vars.isArray() ? JsonView.of(vars.raw()) : null;
            if (view != null) {
                JsonDocuments.add(out, JsonDocuments.json("GraphQL variables" + suffix, view,
                        s -> outer.apply(JsonDocuments.splice(json, vars.start(), vars.end(), s))));
            }
        }
    }

    /** "GraphQL query" (exact) and, when it differs, "GraphQL query (formatted)". */
    private static void queryDocs(List<EditableDocument> out, String suffix, String query, Rebuild setQuery) {
        if (query.length() > JsonDocuments.MAX_TEXT) return;
        JsonDocuments.add(out, JsonDocuments.document("GraphQL query" + suffix, "graphql", query, setQuery));
        String formatted = query.length() > GraphQlDocument.MAX_FORMAT_CHARS ? null : GraphQlDocument.parse(query).formatted;
        if (formatted != null && !formatted.equals(query)) {
            // Sends the formatted (or edited) text: semantically the same document, different bytes.
            JsonDocuments.add(out, JsonDocuments.document("GraphQL query (formatted)" + suffix, "graphql", formatted, setQuery));
        }
    }

    /** query / variables of a GET query string or form body. */
    private static void params(List<EditableDocument> out, String raw, UnaryOperator<String> fallback, Rebuild outer) {
        Param query = JsonDocuments.param(raw, "query");
        Param vars = JsonDocuments.param(raw, "variables");
        Param ext = JsonDocuments.param(raw, "extensions");
        boolean persisted = ext != null && ext.value().contains("persistedQuery");
        if (!(query != null && GraphQlDocument.isLikelyDocument(query.value())) && !persisted) return;
        if (query != null) queryDocs(out, "", query.value(), s -> outer.apply(JsonDocuments.replaceParam(raw, query, s, fallback)));
        if (vars != null) {
            JsonView view = JsonView.of(vars.value());
            if (view != null) {
                JsonDocuments.add(out, JsonDocuments.json("GraphQL variables", view,
                        s -> outer.apply(JsonDocuments.replaceParam(raw, vars, s, fallback))));
            }
        }
    }

    // ------------------------------------------------------------------ responses / WebSocket

    private static void response(MessageContext m, List<EditableDocument> out) {
        String ct = m.contentType().toLowerCase(Locale.ROOT);
        if (ct.contains("event-stream") || ct.contains("multipart")) return;
        Body body = Body.of(m);
        if (body == null) return;
        JsonView view = JsonView.of(body.text());
        if (view == null) return;
        JsonDocuments.add(out, JsonDocuments.json("GraphQL response", view, body::patch));
    }

    private static void webSocket(MessageContext m, List<EditableDocument> out) {
        String text = m.bodyText();
        if (text.length() > JsonDocuments.MAX_TEXT) return;
        Node root = JsonDocuments.tryParse(text);
        if (root == null || !root.isObject()) return;
        Node type = root.get("type");
        Node payload = root.get("payload");
        if (type == null || !type.isString() || payload == null || !payload.isObject()) return;
        String t = type.string();
        if (!t.equals("subscribe") && !t.equals("start")) return;
        operation(out, text, payload, "", s -> MessagePatch.body(s));
    }
}
