package protocoldecoder.core;

import protocoldecoder.util.Codecs;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Immutable, Burp-independent view of a message that decoders, matchers and rules work against.
 *
 * <p>It always carries the request side (method, URL, headers, body). When the exchange has a response it carries that
 * too, so that response decoders can look at the URL and request decoders/rules can look at the response. {@link #kind()}
 * says which part the user is actually looking at; {@link #body()} and {@link #headers()} return that part.</p>
 */
public final class MessageContext {

    private final MessageKind kind;
    private final String method;
    private final String url;
    private final String host;
    private final String path;
    private final String query;
    private final List<Header> requestHeaders;
    private final byte[] requestBody;
    private final Integer statusCode;
    private final List<Header> responseHeaders;
    private final byte[] responseBody;
    private final String webSocketDirection;
    private final byte[] webSocketPayload;
    private final boolean truncated;

    private volatile String exchangeKey;
    private volatile String contentFingerprint;

    private MessageContext(Builder b) {
        this.kind = b.kind;
        this.method = b.method == null ? "" : b.method;
        this.url = b.url == null ? "" : b.url;
        String h = b.host;
        String p = b.path;
        String q = b.query;
        if ((h == null || p == null) && !this.url.isEmpty()) {
            try {
                URI uri = URI.create(this.url);
                if (h == null) h = uri.getHost();
                if (p == null) p = uri.getRawPath();
                if (q == null) q = uri.getRawQuery();
            } catch (IllegalArgumentException ignored) {
                // leave whatever we have
            }
        }
        this.host = h == null ? "" : h;
        String rawPath = p == null ? "" : p;
        int qi = rawPath.indexOf('?');
        if (qi >= 0) {
            if (q == null) q = rawPath.substring(qi + 1);
            rawPath = rawPath.substring(0, qi);
        }
        this.path = rawPath;
        this.query = q == null ? "" : q;
        this.requestHeaders = List.copyOf(b.requestHeaders);
        this.requestBody = b.requestBody == null ? new byte[0] : b.requestBody;
        this.statusCode = b.statusCode;
        this.responseHeaders = b.responseHeaders == null ? null : List.copyOf(b.responseHeaders);
        this.responseBody = b.responseBody;
        this.webSocketDirection = b.webSocketDirection;
        this.webSocketPayload = b.webSocketPayload;
        this.truncated = b.truncated;
    }

    public static Builder builder(MessageKind kind) {
        return new Builder(kind);
    }

    public MessageKind kind() { return kind; }
    public boolean isRequest() { return kind == MessageKind.REQUEST; }
    public boolean isResponse() { return kind == MessageKind.RESPONSE; }
    public boolean isWebSocket() { return kind == MessageKind.WEBSOCKET; }
    public String method() { return method; }
    public String url() { return url; }
    public String host() { return host; }
    /** Path without the query string. */
    public String path() { return path; }
    /** Raw (still URL-encoded) query string, without the leading '?'. Empty if none. */
    public String query() { return query; }
    public List<Header> requestHeaders() { return requestHeaders; }
    public byte[] requestBody() { return requestBody; }
    public boolean hasResponse() { return responseHeaders != null; }
    public Integer statusCode() { return statusCode; }
    public List<Header> responseHeaders() { return responseHeaders == null ? List.of() : responseHeaders; }
    public byte[] responseBody() { return responseBody == null ? new byte[0] : responseBody; }
    /** "CLIENT_TO_SERVER" / "SERVER_TO_CLIENT" for WebSocket messages, otherwise null. */
    public String webSocketDirection() { return webSocketDirection; }
    /** True if a body was cut short because it exceeded the configured size limit. */
    public boolean truncated() { return truncated; }

    /** Headers of the displayed message (the upgrade request's headers for WebSocket messages). */
    public List<Header> headers() {
        return kind == MessageKind.RESPONSE ? responseHeaders() : requestHeaders;
    }

    /** Body bytes of the displayed message. */
    public byte[] body() {
        return switch (kind) {
            case REQUEST -> requestBody;
            case RESPONSE -> responseBody();
            case WEBSOCKET -> webSocketPayload == null ? new byte[0] : webSocketPayload;
        };
    }

    /** Body of the displayed message decoded as UTF-8. */
    public String bodyText() {
        return new String(body(), StandardCharsets.UTF_8);
    }

    public String requestBodyText() {
        return new String(requestBody, StandardCharsets.UTF_8);
    }

    public String responseBodyText() {
        return new String(responseBody(), StandardCharsets.UTF_8);
    }

    /** First header value of the displayed message, case-insensitive, or null. */
    public String header(String name) {
        return find(headers(), name);
    }

    public String requestHeader(String name) {
        return find(requestHeaders, name);
    }

    public String responseHeader(String name) {
        return find(responseHeaders(), name);
    }

    public String contentType() {
        String ct = header("Content-Type");
        return ct == null ? "" : ct;
    }

    public String requestContentType() {
        String ct = requestHeader("Content-Type");
        return ct == null ? "" : ct;
    }

    /** Parsed (URL-decoded) query parameters; later duplicates are kept as separate entries in the list values. */
    public Map<String, List<String>> queryParameters() {
        return Codecs.parseQuery(query);
    }

    /** Parsed form parameters from a urlencoded request body, or an empty map. */
    public Map<String, List<String>> formParameters() {
        String ct = requestContentType().toLowerCase(Locale.ROOT);
        if (!ct.contains("x-www-form-urlencoded")) {
            return Collections.emptyMap();
        }
        return Codecs.parseQuery(requestBodyText());
    }

    /**
     * Stable identifier for the exchange (method, URL and request body), used to key manual overrides so they survive
     * Burp re-creating the message objects.
     */
    public String exchangeKey() {
        String k = exchangeKey;
        if (k == null) {
            k = sha256(method + " " + url + "\n", requestBody, webSocketPayload);
            exchangeKey = k;
        }
        return k;
    }

    /** Key for an override that applies to this specific part of the exchange. */
    public String overrideKey() {
        return exchangeKey() + "|" + kind.name();
    }

    /** Fingerprint of everything a matcher could look at; used for caching match results. */
    public String contentFingerprint() {
        String f = contentFingerprint;
        if (f == null) {
            StringBuilder sb = new StringBuilder(kind.name()).append('\n').append(method).append(' ').append(url).append('\n');
            for (Header h : requestHeaders) sb.append(h.name()).append(':').append(h.value()).append('\n');
            sb.append(statusCode).append('\n');
            if (responseHeaders != null) for (Header h : responseHeaders) sb.append(h.name()).append(':').append(h.value()).append('\n');
            sb.append(webSocketDirection);
            f = sha256(sb.toString(), requestBody, responseBody, webSocketPayload);
            contentFingerprint = f;
        }
        return f;
    }

    private static String find(List<Header> headers, String name) {
        if (headers == null || name == null) return null;
        for (Header h : headers) {
            if (h.name().equalsIgnoreCase(name)) return h.value();
        }
        return null;
    }

    private static String sha256(String prefix, byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(prefix.getBytes(StandardCharsets.UTF_8));
            for (byte[] p : parts) {
                if (p != null) {
                    md.update(Integer.toString(p.length).getBytes(StandardCharsets.UTF_8));
                    md.update((byte) 0);
                    md.update(p);
                }
                md.update((byte) 1);
            }
            return HexFormat.of().formatHex(md.digest(), 0, 16);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Returns a copy of this context presenting a different part of the same exchange. */
    public MessageContext withKind(MessageKind newKind) {
        Builder b = new Builder(newKind);
        b.method = method;
        b.url = url;
        b.host = host;
        b.path = path;
        b.query = query;
        b.requestHeaders.addAll(requestHeaders);
        b.requestBody = requestBody;
        b.statusCode = statusCode;
        b.responseHeaders = responseHeaders == null ? null : new ArrayList<>(responseHeaders);
        b.responseBody = responseBody;
        b.webSocketDirection = webSocketDirection;
        b.webSocketPayload = webSocketPayload;
        b.truncated = truncated;
        return b.build();
    }

    public static final class Builder {
        private final MessageKind kind;
        private String method;
        private String url;
        private String host;
        private String path;
        private String query;
        private final List<Header> requestHeaders = new ArrayList<>();
        private byte[] requestBody;
        private Integer statusCode;
        private List<Header> responseHeaders;
        private byte[] responseBody;
        private String webSocketDirection;
        private byte[] webSocketPayload;
        private boolean truncated;

        private Builder(MessageKind kind) {
            this.kind = kind;
        }

        public Builder method(String v) { this.method = v; return this; }
        public Builder url(String v) { this.url = v; return this; }
        public Builder host(String v) { this.host = v; return this; }
        public Builder path(String v) { this.path = v; return this; }
        public Builder query(String v) { this.query = v; return this; }
        public Builder requestHeader(String name, String value) { requestHeaders.add(new Header(name, value)); return this; }
        public Builder requestHeaders(List<Header> v) { requestHeaders.addAll(v); return this; }
        public Builder requestBody(byte[] v) { this.requestBody = v; return this; }
        public Builder requestBody(String v) { this.requestBody = v.getBytes(StandardCharsets.UTF_8); return this; }
        public Builder statusCode(Integer v) { this.statusCode = v; return this; }
        public Builder responseHeader(String name, String value) {
            if (responseHeaders == null) responseHeaders = new ArrayList<>();
            responseHeaders.add(new Header(name, value));
            return this;
        }
        public Builder responseHeaders(List<Header> v) {
            if (responseHeaders == null) responseHeaders = new ArrayList<>();
            responseHeaders.addAll(v);
            return this;
        }
        public Builder responseBody(byte[] v) {
            if (responseHeaders == null) responseHeaders = new ArrayList<>();
            this.responseBody = v;
            return this;
        }
        public Builder responseBody(String v) { return responseBody(v.getBytes(StandardCharsets.UTF_8)); }
        public Builder webSocket(String direction, byte[] payload) {
            this.webSocketDirection = direction;
            this.webSocketPayload = payload;
            return this;
        }

        public Builder truncated(boolean v) { this.truncated = v; return this; }

        public MessageContext build() {
            return new MessageContext(this);
        }
    }

    @Override
    public String toString() {
        return kind + " " + method + " " + url;
    }

    /** Convenience for decoders: query + form parameters merged, query first. */
    public Map<String, List<String>> allRequestParameters() {
        Map<String, List<String>> all = new LinkedHashMap<>(queryParameters());
        formParameters().forEach((k, v) -> all.computeIfAbsent(k, x -> new ArrayList<>()).addAll(v));
        return all;
    }
}
