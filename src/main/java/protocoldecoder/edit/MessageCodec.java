package protocoldecoder.edit;

import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;

import java.util.List;

/**
 * Whole-document editing support for one protocol, tied to a decoder by id. Field-level editing needs no codec: it
 * comes from the protocol scanner's insertion points.
 */
public interface MessageCodec {

    /** Id of the decoder this codec belongs to. */
    String decoderId();

    /**
     * Documents that can be edited in this message (any kind: request, response or WebSocket). Return an empty list
     * when the message can't be edited (e.g. it is signed and editing would be pointless, or it didn't parse).
     */
    List<EditableDocument> documents(MessageContext message, DecodeResult decoded);
}
