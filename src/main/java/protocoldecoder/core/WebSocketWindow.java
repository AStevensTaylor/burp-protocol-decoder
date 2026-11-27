package protocoldecoder.core;

import java.util.List;

/**
 * The payloads of neighbouring messages on the same WebSocket connection, all in the same direction as the displayed
 * one, oldest first. Lets a decoder reassemble protocol messages that the server split across several WebSocket
 * frames (for example SignalR hub messages larger than the server's 4 KiB send buffer).
 *
 * @param payloads payloads in order; {@code payloads.get(current)} is the displayed message
 * @param current  index of the displayed message
 */
public record WebSocketWindow(List<byte[]> payloads, int current) {

    public WebSocketWindow {
        payloads = List.copyOf(payloads);
        if (current < 0 || current >= payloads.size()) throw new IllegalArgumentException("current out of range");
    }

    public int size() {
        return payloads.size();
    }

    public byte[] get(int i) {
        return payloads.get(i);
    }
}
