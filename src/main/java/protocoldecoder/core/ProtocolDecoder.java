package protocoldecoder.core;

/**
 * A protocol decoder: a matcher that recognises messages of a protocol plus a decoder that turns them into a
 * {@link DecodeResult} for display.
 *
 * <p>Implementations must be thread-safe and must not keep per-message state: Burp calls editors from several
 * threads and the same decoder instance serves every editor.</p>
 */
public interface ProtocolDecoder {

    /** Stable identifier, used in rules, overrides and persisted settings. Lower-case, no spaces. */
    String id();

    /** Human-readable name shown in the UI. */
    String name();

    /** One-line description shown in the decoder list. */
    default String description() {
        return "";
    }

    /** Whether this decoder ships with the extension (as opposed to a user script). */
    default boolean isBuiltIn() {
        return true;
    }

    /**
     * Decide whether this decoder understands the message. Must be fast (it runs for every message Burp shows) and
     * must not throw for messages it does not recognise.
     */
    MatchResult match(MessageContext message);

    /**
     * Decode the message. Called when this decoder matched, or when a rule or manual override forces it, so it must
     * cope with input it would not have matched itself (throw {@link DecodeException} with a useful message).
     */
    DecodeResult decode(MessageContext message) throws DecodeException;
}
