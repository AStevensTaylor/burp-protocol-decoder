package protocoldecoder.core;

/** Thrown by a decoder when the message cannot be decoded. The message is shown to the user. */
public class DecodeException extends Exception {
    public DecodeException(String message) {
        super(message);
    }

    public DecodeException(String message, Throwable cause) {
        super(message, cause);
    }
}
