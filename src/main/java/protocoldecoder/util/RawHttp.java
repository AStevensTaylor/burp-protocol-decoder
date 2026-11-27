package protocoldecoder.util;

import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Parses pasted raw HTTP messages into a {@link MessageContext}, for the script tester. */
public final class RawHttp {

    private RawHttp() {
    }

    private record Parsed(String startLine, List<Header> headers, byte[] body) {
    }

    private static Parsed split(String raw) {
        String text = raw.replace("\r\n", "\n");
        int sep = text.indexOf("\n\n");
        String head = sep < 0 ? text : text.substring(0, sep);
        String body = sep < 0 ? "" : text.substring(sep + 2);
        String[] lines = head.split("\n");
        List<Header> headers = new ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            int c = lines[i].indexOf(':');
            if (c > 0) headers.add(new Header(lines[i].substring(0, c).trim(), lines[i].substring(c + 1).trim()));
        }
        return new Parsed(lines.length > 0 ? lines[0].trim() : "", headers, body.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Builds a message from a raw request and optional raw response. The URL scheme defaults to https unless the
     * request line holds an absolute URL.
     */
    public static MessageContext parse(String rawRequest, String rawResponse, MessageKind kind) {
        Parsed req = split(rawRequest == null ? "" : rawRequest.stripLeading());
        String[] parts = req.startLine().split(" ");
        String method = parts.length > 0 ? parts[0] : "GET";
        String target = parts.length > 1 ? parts[1] : "/";
        String host = "";
        for (Header h : req.headers()) if (h.name().equalsIgnoreCase("Host")) host = h.value();
        String url = target.startsWith("http://") || target.startsWith("https://") ? target : "https://" + (host.isEmpty() ? "localhost" : host) + target;
        MessageContext.Builder b = MessageContext.builder(kind).method(method).url(url).requestHeaders(req.headers()).requestBody(req.body());
        if (rawResponse != null && !rawResponse.isBlank()) {
            Parsed resp = split(rawResponse.stripLeading());
            String[] sp = resp.startLine().split(" ");
            Integer status = null;
            if (sp.length > 1) {
                try {
                    status = Integer.parseInt(sp[1]);
                } catch (NumberFormatException ignored) {
                    // leave null
                }
            }
            b.statusCode(status).responseHeaders(resp.headers()).responseBody(resp.body());
        }
        return b.build();
    }
}
