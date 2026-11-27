package protocoldecoder.scan;

import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;

/**
 * Everything an active check gets.
 *
 * @param base               the scanned request (kind REQUEST, response attached when known)
 * @param baseResponse       the same exchange viewed as RESPONSE, or null when there is no response
 * @param decoded            the owning decoder's result for the request side, or null if it didn't decode
 * @param insertionPointName name of the current insertion point (PER_INSERTION_POINT only, else null)
 * @param insertionPointBase base value of the current insertion point (PER_INSERTION_POINT only, else null)
 * @param http               sender; for PER_INSERTION_POINT, {@link #sendPayload(String)} uses the current point
 */
public record ActiveContext(MessageContext base, MessageContext baseResponse, DecodeResult decoded,
                            String insertionPointName, String insertionPointBase, PayloadSender payloads, HttpSender http) {

    /** Sends the base request with a payload in the current insertion point. */
    @FunctionalInterface
    public interface PayloadSender {
        Exchange send(String payload);
    }

    public boolean hasInsertionPoint() {
        return payloads != null;
    }

    /** Alias for checks that just need the name. */
    public String insertionPoint() {
        return insertionPointName;
    }

    public Exchange sendPayload(String payload) {
        if (payloads == null) throw new IllegalStateException("no insertion point for this check scope");
        return payloads.send(payload);
    }
}
