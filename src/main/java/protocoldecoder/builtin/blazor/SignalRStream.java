package protocoldecoder.builtin.blazor;

import protocoldecoder.core.WebSocketWindow;

import java.util.ArrayList;
import java.util.List;

/**
 * Reassembles SignalR hub messages that span several WebSocket messages.
 *
 * <p>ASP.NET Core sends hub output in chunks of its pipe buffer (4 KiB segments), so a large render batch or JS interop
 * call arrives as several WebSocket frames, and Burp lists each frame on its own. Only the first carries the VarInt
 * length prefix. This class treats the messages of one direction as the byte stream they really are: it finds the
 * closest earlier message that begins a hub message, parses forward from there, and returns the hub messages that
 * overlap the displayed WebSocket message.</p>
 */
final class SignalRStream {

    /** How far back to look for the start of a message. */
    static final int MAX_BACK = 1024;

    /**
     * What to decode for the displayed message.
     *
     * @param payload   the complete hub messages overlapping the displayed message, framing included; empty when the
     *                  displayed message lies inside a hub message that runs past the captured messages
     * @param jsonFirst true if {@code payload} starts with a JSON record (handshake or JSON hub protocol)
     * @param first     window index of the WebSocket message where the first of those hub messages starts
     * @param last      window index of the WebSocket message where the last of them ends
     * @param part      position (1-based) of the displayed message among messages {@code first..last}
     * @param missing   bytes still missing from a hub message that runs past the captured messages: 0 if none, -1 if
     *                  unknown (JSON records carry no length)
     * @param pending   bytes of that unfinished hub message seen so far
     */
    record Assembled(byte[] payload, boolean jsonFirst, int first, int last, int part, long missing, long pending) {
        /** Window index of the displayed message. */
        int current() {
            return first + part - 1;
        }

        int frames() {
            return last - first + 1;
        }

        boolean reassembled() {
            return first != last || missing != 0;
        }
    }

    private SignalRStream() {
    }

    /** Returns the reassembled view of the displayed message, or null if no consistent start could be found. */
    static Assembled assemble(WebSocketWindow w) {
        int c = w.current();
        long[] off = new long[w.size() + 1];
        for (int i = 0; i < w.size(); i++) off[i + 1] = off[i] + w.get(i).length;
        Bytes s = new Bytes(w, off);
        for (int j = c; j >= Math.max(0, c - MAX_BACK); j--) {
            byte[] p = w.get(j);
            if (p.length == 0 || !startsLikeHub(p)) continue;
            Assembled a = parseFrom(s, off, j, c);
            if (a != null) return a;
        }
        return null;
    }

    /** First bytes look like the start of a JSON record or a MessagePack hub message. */
    static boolean startsLikeHub(byte[] p) {
        if (p[0] == '{') return true;
        Bytes one = new Bytes(p);
        return validBinaryHeader(one, 0) != null;
    }

    private static Assembled parseFrom(Bytes s, long[] off, int j, int c) {
        long pos = off[j];
        long curStart = off[c], curEnd = off[c + 1], end = s.length();
        boolean binary = false;
        long firstStart = -1, lastEnd = -1;
        boolean jsonFirst = false;
        while (pos < curEnd) {
            boolean json = !binary && s.at(pos) == '{';
            long frameEnd;
            long missing;
            if (json) {
                long rs = s.indexOf((byte) SignalR.RS, pos);
                frameEnd = rs < 0 ? -1 : rs + 1;
                missing = -1;
            } else {
                binary = true;
                long[] h = validBinaryHeader(s, pos);
                if (h == null) return null;
                frameEnd = h[0] + h[1];
                missing = frameEnd - end;
                if (frameEnd > end) frameEnd = -1;
            }
            if (frameEnd < 0) {
                // This hub message runs past the captured messages.
                if (firstStart < 0) {
                    if (pos < curStart) {
                        // The displayed message lies entirely inside it.
                        int first = indexOf(off, pos);
                        return new Assembled(new byte[0], json, first, c, c - first + 1, missing, end - pos);
                    }
                    return null;
                }
                return result(s, off, c, firstStart, lastEnd, jsonFirst, missing, end - pos);
            }
            if (frameEnd > curStart && firstStart < 0) {
                firstStart = pos;
                jsonFirst = json;
            }
            if (frameEnd > curStart) lastEnd = frameEnd;
            pos = frameEnd;
        }
        if (firstStart < 0) return null;
        return result(s, off, c, firstStart, lastEnd, jsonFirst, 0, 0);
    }

    private static Assembled result(Bytes s, long[] off, int c, long firstStart, long lastEnd, boolean jsonFirst, long missing, long pending) {
        int first = indexOf(off, firstStart);
        int last = Math.max(c, indexOf(off, lastEnd - 1));
        return new Assembled(s.slice(firstStart, lastEnd), jsonFirst, first, last, c - first + 1, missing, pending);
    }

    /** Window index of the message containing stream offset {@code pos}. */
    private static int indexOf(long[] off, long pos) {
        int lo = 0, hi = off.length - 2;
        while (lo < hi) {
            int mid = (lo + hi + 1) >>> 1;
            if (off[mid] <= pos) lo = mid;
            else hi = mid - 1;
        }
        return lo;
    }

    /**
     * Reads a VarInt length at {@code pos} and checks what follows looks like a hub message (a MessagePack array whose
     * first element is a message type 1–9). Returns {bodyStart, length} or null. Bytes past the end count as unknown,
     * not invalid, so a header split across two WebSocket messages still validates once both are present.
     */
    static long[] validBinaryHeader(Bytes s, long pos) {
        long len = 0;
        int shift = 0, x;
        long p = pos;
        do {
            if (p >= s.length() || shift > 28) return null;
            x = s.at(p++) & 0xff;
            len |= (long) (x & 0x7f) << shift;
            shift += 7;
        } while ((x & 0x80) != 0);
        if (len < 2) return null;
        if (p < s.length()) {
            int first = s.at(p) & 0xff;
            if ((first & 0xf0) != 0x90 && first != 0xdc) return null;
            int typeAt = first == 0xdc ? 3 : 1;
            if (p + typeAt < s.length()) {
                int type = s.at(p + typeAt) & 0xff;
                if (type < 1 || type > 9) return null;
            }
        }
        return new long[]{p, len};
    }

    /** Random access over the concatenated payloads without copying them. */
    static final class Bytes {
        private final List<byte[]> parts;
        private final long[] off;

        Bytes(WebSocketWindow w, long[] off) {
            this.parts = w.payloads();
            this.off = off;
        }

        Bytes(byte[] single) {
            this.parts = List.of(single);
            this.off = new long[]{0, single.length};
        }

        long length() {
            return off[off.length - 1];
        }

        byte at(long pos) {
            int i = SignalRStream.indexOf(off, pos);
            return parts.get(i)[(int) (pos - off[i])];
        }

        long indexOf(byte v, long from) {
            if (from >= length()) return -1;
            for (int i = SignalRStream.indexOf(off, from); i < parts.size(); i++) {
                byte[] p = parts.get(i);
                for (int k = (int) Math.max(0, from - off[i]); k < p.length; k++) if (p[k] == v) return off[i] + k;
            }
            return -1;
        }

        byte[] slice(long from, long to) {
            List<byte[]> chunks = new ArrayList<>();
            int total = 0;
            for (int i = SignalRStream.indexOf(off, from); i < parts.size() && off[i] < to; i++) {
                int a = (int) Math.max(0, from - off[i]);
                int b = (int) Math.min(parts.get(i).length, to - off[i]);
                if (b <= a) continue;
                byte[] c = java.util.Arrays.copyOfRange(parts.get(i), a, b);
                chunks.add(c);
                total += c.length;
            }
            byte[] out = new byte[total];
            int k = 0;
            for (byte[] c : chunks) {
                System.arraycopy(c, 0, out, k, c.length);
                k += c.length;
            }
            return out;
        }
    }
}
