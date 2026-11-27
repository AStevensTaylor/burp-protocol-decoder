package protocoldecoder.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.proxy.ProxyWebSocketMessage;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import burp.api.montoya.websocket.Direction;
import protocoldecoder.core.WebSocketWindow;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Deque;
import java.util.List;
import java.util.function.Supplier;

/**
 * Supplies the neighbouring messages of a WebSocket message, so decoders can reassemble protocol messages split across
 * several WebSocket messages. Editors look the message up in Proxy WebSocket history; the live proxy handler keeps a
 * small per-connection buffer instead ({@link Recent}).
 */
final class WebSocketWindows {

    /** Neighbours taken on each side of the displayed message. */
    static final int MAX_MESSAGES = 1024;
    static final long MAX_BYTES = 8L * 1024 * 1024;

    private final MontoyaApi api;

    WebSocketWindows(MontoyaApi api) {
        this.api = api;
    }

    /** Lazy lookup for the message an editor shows; {@code payload} is the (possibly capped) payload it decodes. */
    Supplier<WebSocketWindow> forMessage(WebSocketMessage msg, byte[] payload, boolean truncated) {
        if (msg == null || truncated) return null;
        return () -> lookup(msg, payload);
    }

    private WebSocketWindow lookup(WebSocketMessage msg, byte[] payload) {
        Direction dir = msg.direction();
        int wsId;
        int id;
        if (msg instanceof ProxyWebSocketMessage pm) {
            wsId = pm.webSocketId();
            id = pm.id();
        } else {
            List<ProxyWebSocketMessage> hits = api.proxy().webSocketHistory(h -> h.direction() == dir && samePayload(h, payload));
            if (hits.isEmpty()) return null;
            String url = msg.upgradeRequest() == null ? null : msg.upgradeRequest().url();
            ProxyWebSocketMessage best = null;
            for (ProxyWebSocketMessage h : hits) {
                boolean sameUrl = url == null || (h.upgradeRequest() != null && url.equals(h.upgradeRequest().url()));
                if (sameUrl && (best == null || h.id() > best.id())) best = h;
            }
            if (best == null) return null;
            wsId = best.webSocketId();
            id = best.id();
        }
        List<ProxyWebSocketMessage> conn = new ArrayList<>(api.proxy().webSocketHistory(h -> h.webSocketId() == wsId && h.direction() == dir));
        conn.sort(Comparator.comparingInt(ProxyWebSocketMessage::id));
        int at = -1;
        for (int i = 0; i < conn.size(); i++) if (conn.get(i).id() == id) at = i;
        if (at < 0) return null;
        Deque<byte[]> before = new ArrayDeque<>();
        long bytes = 0;
        for (int i = at - 1; i >= 0 && before.size() < MAX_MESSAGES && bytes < MAX_BYTES; i--) {
            byte[] p = sent(conn.get(i));
            before.addFirst(p);
            bytes += p.length;
        }
        List<byte[]> all = new ArrayList<>(before);
        int current = all.size();
        all.add(payload);
        bytes = 0;
        for (int i = at + 1, n = 0; i < conn.size() && n < MAX_MESSAGES && bytes < MAX_BYTES; i++, n++) {
            byte[] p = sent(conn.get(i));
            all.add(p);
            bytes += p.length;
        }
        return new WebSocketWindow(all, current);
    }

    private static boolean samePayload(ProxyWebSocketMessage h, byte[] payload) {
        return equal(h.payload(), payload) || equal(h.editedPayload(), payload);
    }

    private static boolean equal(ByteArray a, byte[] b) {
        return a != null && a.length() == b.length && Arrays.equals(a.getBytes(), b);
    }

    /** What was actually forwarded: the edited payload if the message was changed in the proxy. */
    private static byte[] sent(ProxyWebSocketMessage h) {
        ByteArray e = h.editedPayload();
        ByteArray p = e != null && e.length() > 0 ? e : h.payload();
        return p == null ? new byte[0] : p.getBytes();
    }

    /** Recent same-direction payloads of one live connection, for passive scanning as messages pass through. */
    static final class Recent {
        static final int MAX_MESSAGES = 256;
        static final long MAX_BYTES = 1024 * 1024;

        private final Deque<byte[]> messages = new ArrayDeque<>();
        private long bytes;

        /** Returns a window ending with {@code payload}, then remembers it. */
        synchronized WebSocketWindow add(byte[] payload) {
            List<byte[]> all = new ArrayList<>(messages);
            all.add(payload);
            messages.addLast(payload);
            bytes += payload.length;
            while (messages.size() > MAX_MESSAGES || (bytes > MAX_BYTES && messages.size() > 1)) bytes -= messages.removeFirst().length;
            return new WebSocketWindow(all, all.size() - 1);
        }

        synchronized void clear() {
            messages.clear();
            bytes = 0;
        }
    }
}
