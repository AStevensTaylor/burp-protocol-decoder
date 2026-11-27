package protocoldecoder.scan;

import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;

import java.util.List;

/**
 * Scanner support for one protocol, tied to a decoder by id. Every method is optional. Implementations must be
 * thread-safe and must never throw for unexpected input (return empty lists).
 */
public interface ProtocolScanner {

    /** Id of the decoder this scanner belongs to; its checks run when that decoder applies to a message. */
    String decoderId();

    default List<PassiveCheck> passiveChecks() {
        return List.of();
    }

    default List<ActiveCheck> activeChecks() {
        return List.of();
    }

    /**
     * Protocol-aware insertion points for a request the decoder applies to.
     *
     * @param request kind REQUEST
     * @param decoded the decoder's result for it, or null
     */
    default List<InsertionPoint> insertionPoints(MessageContext request, DecodeResult decoded) {
        return List.of();
    }
}
