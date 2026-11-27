package protocoldecoder.core;

/**
 * Which decoder will handle a message, and why.
 *
 * @param decoder decoder to use, or null when the message should not be decoded
 * @param source  how it was chosen
 * @param match   the matcher result (for AUTO; for other sources the decoder's own opinion if computed, may be NONE)
 * @param detail  human-readable explanation, e.g. the rule name
 */
public record Resolution(ProtocolDecoder decoder, Source source, MatchResult match, String detail) {

    public enum Source {
        /** User picked a decoder for this specific message. */
        OVERRIDE,
        /** A user rule matched. */
        RULE,
        /** Highest-confidence matcher. */
        AUTO,
        /** Nothing applies. */
        NONE
    }

    public static final Resolution NOTHING = new Resolution(null, Source.NONE, MatchResult.NONE, "No decoder matched");

    public boolean hasDecoder() {
        return decoder != null;
    }

    public String describe() {
        return switch (source) {
            case OVERRIDE -> decoder == null ? "Decoding disabled for this message (manual override)" : "Manual override → " + decoder.name();
            case RULE -> (decoder == null ? "Not decoded" : decoder.name()) + " — rule \"" + detail + "\"";
            case AUTO -> decoder.name() + " — auto-detected (" + match.confidence() + "%" + (match.reason().isEmpty() ? "" : ": " + match.reason()) + ")";
            case NONE -> detail;
        };
    }
}
