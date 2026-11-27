package protocoldecoder.scan;

import protocoldecoder.core.MessageContext;

/**
 * A request/response sent by an active check. {@code message} is the Burp-independent view (kind REQUEST, with the
 * response attached if one came back); {@code handle} is the host's native object (Burp's HttpRequestResponse), used to
 * attach the exchange to an issue.
 */
public record Exchange(MessageContext message, Object handle) {
    public boolean hasResponse() {
        return message.hasResponse();
    }

    public int status() {
        return message.statusCode() == null ? 0 : message.statusCode();
    }

    public String responseText() {
        return message.responseBodyText();
    }
}
