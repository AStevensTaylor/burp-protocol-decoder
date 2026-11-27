package protocoldecoder.rules;

/** What happens when a rule matches. */
public enum RuleAction {
    /** Decode with the rule's decoder, regardless of what auto-detection would pick. */
    DECODE_AS("Decode as"),
    /** Do not decode (hides the tab unless "always show" is on). */
    DO_NOT_DECODE("Don't decode");

    private final String label;

    RuleAction(String label) {
        this.label = label;
    }

    @Override
    public String toString() {
        return label;
    }
}
