package protocoldecoder.core;

/** Which part of an exchange is currently being displayed / decoded. */
public enum MessageKind {
    REQUEST("Request"),
    RESPONSE("Response"),
    WEBSOCKET("WebSocket");

    private final String label;

    MessageKind(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
