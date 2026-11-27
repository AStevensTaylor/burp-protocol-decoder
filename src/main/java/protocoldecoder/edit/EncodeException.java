package protocoldecoder.edit;

/** The edited value or document can't be encoded back into the protocol. Message is shown to the user. */
public class EncodeException extends Exception {
    public EncodeException(String message) {
        super(message);
    }

    public EncodeException(String message, Throwable cause) {
        super(message, cause);
    }
}
