package protocoldecoder.edit;

import protocoldecoder.core.MessageContext;
import protocoldecoder.scan.InsertionPoint;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A change to the displayed message: new body, new raw query string (requests only, without '?') and/or headers to
 * set. Null means "unchanged". Patches are absolute, so combining them is "later wins".
 */
public record MessagePatch(byte[] body, String query, Map<String, String> headers) {

    public static final MessagePatch NONE = new MessagePatch(null, null, Map.of());

    public MessagePatch {
        headers = headers == null ? Map.of() : Map.copyOf(new LinkedHashMap<>(headers));
    }

    public static MessagePatch body(byte[] body) {
        return new MessagePatch(body, null, Map.of());
    }

    public static MessagePatch body(String utf8) {
        return body(utf8.getBytes(StandardCharsets.UTF_8));
    }

    public static MessagePatch query(String rawQuery) {
        return new MessagePatch(null, rawQuery, Map.of());
    }

    public static MessagePatch header(String name, String value) {
        return new MessagePatch(null, null, Map.of(name, value));
    }

    /** The patch an insertion point produces for a payload. */
    public static MessagePatch of(InsertionPoint ip, String payload) {
        byte[] content = ip.render().apply(payload);
        return switch (ip.part()) {
            case BODY -> body(content);
            case QUERY -> query(new String(content, StandardCharsets.ISO_8859_1));
            case HEADER -> header(ip.headerName(), new String(content, StandardCharsets.UTF_8));
        };
    }

    public boolean isEmpty() {
        return body == null && query == null && headers.isEmpty();
    }

    /** This patch followed by {@code next} (next wins where both set something). */
    public MessagePatch then(MessagePatch next) {
        if (next == null || next.isEmpty()) return this;
        Map<String, String> h = new LinkedHashMap<>(headers);
        next.headers.forEach((k, v) -> {
            h.keySet().removeIf(x -> x.equalsIgnoreCase(k));
            h.put(k, v);
        });
        return new MessagePatch(next.body != null ? next.body : body, next.query != null ? next.query : query, h);
    }

    public MessageContext applyTo(MessageContext m) {
        return isEmpty() ? m : m.patched(body, query, headers.isEmpty() ? null : headers);
    }
}
