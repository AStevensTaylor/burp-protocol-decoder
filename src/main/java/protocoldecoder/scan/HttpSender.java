package protocoldecoder.scan;

import protocoldecoder.core.Header;

import java.util.List;

/** Sends requests for active checks, to the same host/port/scheme as the base request. */
public interface HttpSender {

    /**
     * @param pathAndQuery request target, e.g. "/_blazor/negotiate?negotiateVersion=1"
     * @param headers      complete header list (Host and Content-Length are fixed up by the host)
     */
    Exchange send(String method, String pathAndQuery, List<Header> headers, byte[] body);

    /** Re-sends the base request with this insertion point's part replaced by the payload. */
    Exchange send(InsertionPoint point, String payload);
}
