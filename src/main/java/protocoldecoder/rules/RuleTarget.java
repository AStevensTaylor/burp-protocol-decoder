package protocoldecoder.rules;

import protocoldecoder.core.MessageKind;

/** Which kind of displayed message a rule applies to. */
public enum RuleTarget {
    ANY("Any message"),
    REQUEST("Requests"),
    RESPONSE("Responses"),
    HTTP("Requests and responses"),
    WEBSOCKET("WebSocket messages");

    private final String label;

    RuleTarget(String label) {
        this.label = label;
    }

    public boolean applies(MessageKind kind) {
        return switch (this) {
            case ANY -> true;
            case REQUEST -> kind == MessageKind.REQUEST;
            case RESPONSE -> kind == MessageKind.RESPONSE;
            case HTTP -> kind != MessageKind.WEBSOCKET;
            case WEBSOCKET -> kind == MessageKind.WEBSOCKET;
        };
    }

    @Override
    public String toString() {
        return label;
    }
}
