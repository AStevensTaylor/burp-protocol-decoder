package protocoldecoder.scan;

import protocoldecoder.core.MessageKind;

/** Text to highlight in the request or response of an issue. */
public record Evidence(MessageKind where, String text) {
    public static Evidence request(String text) {
        return new Evidence(MessageKind.REQUEST, text);
    }

    public static Evidence response(String text) {
        return new Evidence(MessageKind.RESPONSE, text);
    }
}
