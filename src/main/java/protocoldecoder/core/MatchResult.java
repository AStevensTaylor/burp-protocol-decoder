package protocoldecoder.core;

/**
 * Outcome of a matcher. Confidence is 0..100; 0 means "not mine". When several decoders match, the highest confidence
 * wins (ties go to the decoder listed first).
 */
public record MatchResult(int confidence, String reason) {

    public static final MatchResult NONE = new MatchResult(0, "");

    public MatchResult {
        confidence = Math.max(0, Math.min(100, confidence));
        reason = reason == null ? "" : reason;
    }

    public static MatchResult of(int confidence, String reason) {
        return confidence <= 0 ? NONE : new MatchResult(confidence, reason);
    }

    public boolean matched() {
        return confidence > 0;
    }

    /** Returns whichever result has the higher confidence. */
    public MatchResult max(MatchResult other) {
        return other != null && other.confidence > confidence ? other : this;
    }
}
