package protocoldecoder.scan;

import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;

import java.util.List;

/**
 * A check that inspects traffic without sending anything. Runs for HTTP requests/responses seen by Burp's passive
 * scanner and for WebSocket messages passing through the proxy, whenever the owning protocol's decoder applies.
 */
public interface PassiveCheck {

    /** Stable id, e.g. "devexpress.callback-error". Used to enable/disable the check. */
    String id();

    /** Short name for the checks list. */
    String name();

    default String description() {
        return "";
    }

    /**
     * @param message the message (kind REQUEST, RESPONSE or WEBSOCKET)
     * @param decoded the owning decoder's output for this message, or null if decoding failed
     */
    List<Finding> check(MessageContext message, DecodeResult decoded);
}
