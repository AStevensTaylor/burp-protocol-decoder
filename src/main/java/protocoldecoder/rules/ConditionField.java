package protocoldecoder.rules;

/** What part of the exchange a rule condition looks at. */
public enum ConditionField {
    URL("URL", false),
    HOST("Host", false),
    PATH("Path", false),
    QUERY("Query string", false),
    METHOD("Method", false),
    REQUEST_HEADER("Request header", true),
    RESPONSE_HEADER("Response header", true),
    REQUEST_BODY("Request body", false),
    RESPONSE_BODY("Response body", false),
    MESSAGE_BODY("Displayed message body", false),
    CONTENT_TYPE("Displayed Content-Type", false),
    STATUS_CODE("Status code", false),
    WEBSOCKET_DIRECTION("WebSocket direction", false);

    private final String label;
    private final boolean needsName;

    ConditionField(String label, boolean needsName) {
        this.label = label;
        this.needsName = needsName;
    }

    public String label() {
        return label;
    }

    /** Whether the condition needs a header name in addition to a value. */
    public boolean needsName() {
        return needsName;
    }

    @Override
    public String toString() {
        return label;
    }
}
