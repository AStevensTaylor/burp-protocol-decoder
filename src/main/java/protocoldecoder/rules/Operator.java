package protocoldecoder.rules;

/** Comparison applied by a rule condition. */
public enum Operator {
    CONTAINS("contains"),
    NOT_CONTAINS("does not contain"),
    EQUALS("equals"),
    NOT_EQUALS("does not equal"),
    STARTS_WITH("starts with"),
    ENDS_WITH("ends with"),
    MATCHES_REGEX("matches regex"),
    NOT_MATCHES_REGEX("does not match regex"),
    EXISTS("exists"),
    NOT_EXISTS("does not exist");

    private final String label;

    Operator(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    /** Whether the operator ignores the value field. */
    public boolean unary() {
        return this == EXISTS || this == NOT_EXISTS;
    }

    @Override
    public String toString() {
        return label;
    }
}
