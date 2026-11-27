package protocoldecoder.burp;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Converts Montoya API objects into Burp-independent {@link MessageContext}s. */
public final class Montoya {

    private Montoya() {
    }

    /** Returns null if the needed part of the message is missing. */
    public static MessageContext fromHttp(HttpRequestResponse rr, MessageKind kind, int maxBytes) {
        if (rr == null) return null;
        HttpRequest req = rr.request();
        if (req == null) return null;
        HttpResponse resp = rr.response();
        if (kind == MessageKind.RESPONSE && resp == null) return null;
        MessageContext.Builder b = MessageContext.builder(kind);
        boolean[] truncated = {false};
        fillRequest(b, req, maxBytes, truncated);
        if (resp != null) {
            b.statusCode((int) resp.statusCode());
            b.responseHeaders(headers(resp.headers()));
            b.responseBody(cap(resp.body() == null ? new byte[0] : resp.body().getBytes(), maxBytes, truncated));
        }
        return b.truncated(truncated[0]).build();
    }

    public static MessageContext fromWebSocket(WebSocketMessage msg, int maxBytes) {
        if (msg == null) return null;
        MessageContext.Builder b = MessageContext.builder(MessageKind.WEBSOCKET);
        boolean[] truncated = {false};
        if (msg.upgradeRequest() != null) fillRequest(b, msg.upgradeRequest(), maxBytes, truncated);
        byte[] payload = msg.payload() == null ? new byte[0] : msg.payload().getBytes();
        b.webSocket(msg.direction() == null ? null : msg.direction().name(), cap(payload, maxBytes, truncated));
        return b.truncated(truncated[0]).build();
    }

    private static void fillRequest(MessageContext.Builder b, HttpRequest req, int maxBytes, boolean[] truncated) {
        b.method(safe(req::method));
        String url = safe(req::url);
        b.url(url);
        HttpService svc = req.httpService();
        if (svc != null) b.host(svc.host());
        String path = safe(req::pathWithoutQuery);
        if (path != null && !path.isEmpty()) b.path(path);
        String query = safe(req::query);
        if (query != null) b.query(query);
        b.requestHeaders(headers(req.headers()));
        b.requestBody(cap(req.body() == null ? new byte[0] : req.body().getBytes(), maxBytes, truncated));
    }

    private static List<Header> headers(List<HttpHeader> hs) {
        List<Header> out = new ArrayList<>(hs == null ? 0 : hs.size());
        if (hs != null) for (HttpHeader h : hs) out.add(new Header(h.name(), h.value()));
        return out;
    }

    private static byte[] cap(byte[] b, int max, boolean[] truncated) {
        if (b.length <= max) return b;
        truncated[0] = true;
        return Arrays.copyOf(b, max);
    }

    private static String safe(java.util.function.Supplier<String> s) {
        try {
            return s.get();
        } catch (RuntimeException e) {
            return null;
        }
    }
}
