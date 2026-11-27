package protocoldecoder.builtin.socketio;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.scan.ActiveCheck;
import protocoldecoder.scan.ActiveContext;
import protocoldecoder.scan.Confidence;
import protocoldecoder.scan.Evidence;
import protocoldecoder.scan.Exchange;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.InsertionPoint;
import protocoldecoder.scan.InsertionPoints;
import protocoldecoder.scan.PassiveCheck;
import protocoldecoder.scan.ProtocolScanner;
import protocoldecoder.scan.ScanPatterns;
import protocoldecoder.scan.Severity;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scanner support for Socket.IO / Engine.IO. Most coverage is passive (WebSocket frames pass through the proxy);
 * HTTP long-polling sends get insertion points inside the Socket.IO packets so Burp's payloads reach event arguments
 * with the Engine.IO framing kept valid.
 */
public final class SocketIoScanner implements ProtocolScanner {

    static final String FOREIGN_ORIGIN = "https://evil.example";

    @Override
    public String decoderId() {
        return SocketIoDecoder.ID;
    }

    @Override
    public List<PassiveCheck> passiveChecks() {
        return List.of(new SensitiveEventData(), new ErrorDisclosure(), new PollingTransport(), new LegacyProtocol());
    }

    @Override
    public List<ActiveCheck> activeChecks() {
        return List.of(new CrossOriginHandshake());
    }

    // ---------------------------------------------------------------- shared parsing

    /** One Engine.IO packet of a message and, for message packets, its Socket.IO packet (else null). */
    record Pkt(EngineIo.Packet eio, SocketIoPacket sio) {
    }

    static boolean fromServer(MessageContext m) {
        return m.isResponse() || (m.isWebSocket() && "SERVER_TO_CLIENT".equals(m.webSocketDirection()));
    }

    /** Packets of a WebSocket frame or polling body (bounded by the Engine.IO parser). */
    static List<Pkt> packets(MessageContext m) {
        int eio = SocketIoDecoder.eioVersion(m);
        List<EngineIo.Packet> raw = new ArrayList<>();
        if (m.isWebSocket()) {
            byte[] p = m.body();
            if (p.length == 0 || !SocketIoDecoder.looksLikeTextFrame(p)) return List.of();
            raw.add(EngineIo.parseText(Codecs.utf8(p), eio));
        } else {
            byte[] body = m.isRequest() ? m.requestBody() : Codecs.decodeContent(m.responseBody(), m.responseHeader("Content-Encoding"));
            if (body == null || body.length == 0) return List.of();
            if (m.isRequest()) {
                String form = Codecs.first(m.formParameters(), "d");
                if (form != null) body = form.getBytes(StandardCharsets.UTF_8);
            }
            String t = Codecs.utf8(body).strip();
            if (t.equals("ok") || t.startsWith("{")) return List.of();
            raw.addAll(EngineIo.parsePolling(body, eio).packets());
        }
        List<Pkt> out = new ArrayList<>();
        for (EngineIo.Packet p : raw) {
            if (!p.valid()) continue;
            SocketIoPacket s = null;
            if (p.type() == EngineIo.MESSAGE && !p.isBinary()) {
                SocketIoPacket x = SocketIoPacket.parse(p.text());
                if (x.valid()) s = x;
            }
            out.add(new Pkt(p, s));
        }
        return out;
    }

    private static boolean carriesArguments(SocketIoPacket s) {
        return s != null && (s.type() == SocketIoPacket.EVENT || s.type() == SocketIoPacket.BINARY_EVENT
                || s.type() == SocketIoPacket.ACK || s.type() == SocketIoPacket.BINARY_ACK);
    }

    private static String where(MessageContext m) {
        return m.isWebSocket() ? "a WebSocket message (" + (fromServer(m) ? "server → client" : "client → server") + ")"
                : m.isResponse() ? "a long-polling response" : "a long-polling request";
    }

    // ---------------------------------------------------------------- passive checks

    /** Credentials/secrets in event or ack arguments. */
    static final class SensitiveEventData implements PassiveCheck {
        /** Kinds reported for client → server data (anything else there is usually just what the user typed). */
        private static final Set<String> CLIENT_KINDS = Set.of("JWT", "bearer token");

        @Override public String id() { return "socketio.sensitive-data"; }
        @Override public String name() { return "Sensitive data in events"; }
        @Override public String description() {
            return "Tokens, credentials or card numbers in Socket.IO event/ack arguments (server → client: Low; client → server: only JWT/bearer tokens, Information)";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            boolean server = fromServer(m);
            List<ScanPatterns.Sensitive> hits = new ArrayList<>();
            List<String> events = new ArrayList<>();
            for (Pkt p : packets(m)) {
                if (!carriesArguments(p.sio()) || hits.size() >= 20) continue;
                DecodedNode args = p.sio().node().get("Arguments");
                if (args == null) continue;
                List<ScanPatterns.Sensitive> h = new ArrayList<>(ScanPatterns.sensitiveValues(args, 20));
                h.removeIf(x -> x.kind().equals("email address") || (!server && !CLIENT_KINDS.contains(x.kind())));
                if (h.isEmpty()) continue;
                hits.addAll(h);
                events.add(p.sio().label());
            }
            if (hits.isEmpty()) return List.of();
            Finding f = Finding.of(id(), server ? "Sensitive data in Socket.IO events" : "Token sent in Socket.IO event arguments")
                    .severity(server ? Severity.LOW : Severity.INFORMATION).confidence(Confidence.TENTATIVE)
                    .detail("Socket.IO " + Finding.esc(String.join(", ", events)) + " in " + where(m) + " on <code>" + Finding.esc(m.path())
                            + "</code> carries sensitive-looking values:" + ScanPatterns.htmlList(hits))
                    .background(server
                            ? "Socket.IO events are often broadcast to rooms or namespaces. Secrets or credentials in server events may reach "
                            + "clients that should not see them, and are visible to any script in the page."
                            : "Tokens passed as event arguments (rather than in the connection handshake <code>auth</code> payload) tend to be "
                            + "logged by servers and middleware, and are exposed to any script in the page.")
                    .remediation(server
                            ? "Only emit data the receiving clients are entitled to; never include secrets in broadcasts."
                            : "Authenticate the connection once (handshake <code>auth</code> or an HttpOnly cookie) instead of sending tokens with events.");
            for (ScanPatterns.Sensitive h : hits) f.evidence(new Evidence(m.isRequest() ? MessageKind.REQUEST : MessageKind.RESPONSE, h.value()));
            return List.of(f);
        }
    }

    /** Exception types / stack traces in server events, acks or CONNECT_ERROR. */
    static final class ErrorDisclosure implements PassiveCheck {
        @Override public String id() { return "socketio.error-disclosure"; }
        @Override public String name() { return "Server error details"; }
        @Override public String description() { return "Exception text or stack traces in server-sent Socket.IO events, acks or CONNECT_ERROR packets"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!fromServer(m)) return List.of();
            for (Pkt p : packets(m)) {
                SocketIoPacket s = p.sio();
                if (s == null || !(carriesArguments(s) || s.type() == SocketIoPacket.CONNECT_ERROR) || s.rawData() == null) continue;
                String text = s.rawData().replace("\\n", "\n").replace("\\t", "\t");
                String trace = exceptionEvidence(text);
                if (trace == null) continue;
                return List.of(Finding.of(id(), "Socket.IO server error details disclosed")
                        .severity(Severity.LOW).confidence(Confidence.FIRM)
                        .detail("Socket.IO " + Finding.esc(s.label()) + " in " + where(m) + " on <code>" + Finding.esc(m.path())
                                + "</code> contains exception details: <code>" + Finding.esc(Codecs.truncate(trace, 400)) + "</code>")
                        .background("Socket.IO handlers that pass caught errors to acks, emit them as events or reject connections with "
                                + "<code>next(err)</code> send the error text to the client. Stack traces reveal file paths, libraries and code structure.")
                        .remediation("Send generic error messages to clients and log details server-side.")
                        .responseEvidence(trace.split("\n", 2)[0]));
            }
            return List.of();
        }
    }

    /** Engine.IO handshake answered over HTTP long-polling. */
    static final class PollingTransport implements PassiveCheck {
        @Override public String id() { return "socketio.polling-enabled"; }
        @Override public String name() { return "Long-polling transport enabled"; }
        @Override public String description() { return "Engine.IO handshake served over HTTP long-polling (scannable over HTTP; may bypass WebSocket-only controls)"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || !"polling".equals(Codecs.first(m.queryParameters(), "transport"))) return List.of();
            for (Pkt p : packets(m)) {
                if (p.eio().type() != EngineIo.OPEN || p.eio().isBinary()) continue;
                JsonElement e = JsonTree.parseStrict(p.eio().text());
                if (e == null || !e.isJsonObject() || !e.getAsJsonObject().has("sid")) continue;
                JsonObject o = e.getAsJsonObject();
                boolean ws = o.get("upgrades") instanceof JsonArray a && a.toString().contains("\"websocket\"");
                return List.of(Finding.of(id(), "Socket.IO long-polling transport enabled")
                        .severity(Severity.INFORMATION).confidence(Confidence.CERTAIN).scope(Finding.Scope.HOST)
                        .detail("The Engine.IO server at <code>" + Finding.esc(m.path()) + "</code> accepts the HTTP long-polling transport"
                                + (ws ? " alongside WebSocket (handshake offers <code>upgrades: [\"websocket\"]</code>)." : " (no WebSocket upgrade offered)."))
                        .background("Long-polling carries the same Socket.IO events as plain HTTP requests (<code>POST ?transport=polling&amp;sid=…</code>). "
                                + "Burp can actively scan those requests (this extension adds insertion points inside the packets), and protections "
                                + "implemented only for WebSocket upgrades (origin checks, WAF rules, auth on the upgrade request) may not apply to them.")
                        .remediation("If clients only use WebSocket, restrict the server to <code>transports: [\"websocket\"]</code>; otherwise apply the "
                                + "same authentication and origin checks to both transports (e.g. in <code>allowRequest</code> / middleware).")
                        .responseEvidence(p.eio().text().length() > 200 ? "\"sid\"" : p.eio().text()));
            }
            return List.of();
        }
    }

    /** Engine.IO v3 (Socket.IO 2.x and older) accepted by the server. */
    static final class LegacyProtocol implements PassiveCheck {
        @Override public String id() { return "socketio.legacy-protocol"; }
        @Override public String name() { return "Legacy Socket.IO protocol (EIO=3)"; }
        @Override public String description() { return "Server answers Engine.IO v3 clients (Socket.IO 2.x protocol, or v3/v4 with allowEIO3)"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (m.isRequest() || SocketIoDecoder.eioVersion(m) != 3) return List.of();
            if (m.isResponse() && (m.statusCode() == null || m.statusCode() != 200)) return List.of();
            if (packets(m).isEmpty()) return List.of(); // errors like "Unsupported protocol version" don't count
            String eio = Codecs.first(m.queryParameters(), "EIO");
            return List.of(Finding.of(id(), "Legacy Socket.IO protocol in use (Engine.IO v3)")
                    .severity(Severity.INFORMATION).confidence(Confidence.FIRM).scope(Finding.Scope.HOST)
                    .detail("The server exchanges Engine.IO protocol v3 packets (<code>EIO=" + Finding.esc(eio) + "</code>) on <code>" + Finding.esc(m.path())
                            + "</code>, i.e. it runs Socket.IO 2.x (or a newer server with <code>allowEIO3</code> enabled for old clients).")
                    .background("Socket.IO 2.x is no longer maintained. Older 2.x releases had insecure defaults, notably accepting "
                            + "cross-origin connections from any origin (restricted from 2.4.0), and they miss later fixes in engine.io and "
                            + "socket.io-parser. Review the server and client library versions.")
                    .remediation("Upgrade server and clients to a maintained Socket.IO release and disable <code>allowEIO3</code> once old clients are gone.")
                    .requestEvidence("EIO=" + eio));
        }
    }

    // ---------------------------------------------------------------- active

    /** Polling handshake with a foreign Origin, looking for a reflected ACAO with credentials. */
    static final class CrossOriginHandshake implements ActiveCheck {
        @Override public String id() { return "socketio.cross-origin-handshake"; }
        @Override public String name() { return "Socket.IO cross-origin handshake"; }
        @Override public String description() {
            return "1 request per host: Engine.IO polling handshake with Origin " + FOREIGN_ORIGIN
                    + "; reports a reflected Access-Control-Allow-Origin with credentials (cross-origin reading of the session)";
        }
        @Override public Scope scope() { return Scope.PER_HOST; }

        @Override
        public List<Finding> run(ActiveContext ctx) {
            MessageContext base = ctx.base();
            String path = handshakePath(base);
            if (path == null) return List.of();
            int eio = SocketIoDecoder.eioVersion(base) == 3 ? 3 : 4;
            String target = path + "?EIO=" + eio + "&transport=polling&t=pdscan1";
            List<Header> headers = new ArrayList<>();
            for (Header h : base.requestHeaders()) {
                String n = h.name().toLowerCase(Locale.ROOT);
                if (n.equals("origin") || n.equals("content-type") || n.equals("content-length") || n.equals("upgrade")
                        || n.equals("connection") || n.startsWith("sec-websocket-")) continue;
                headers.add(h);
            }
            headers.add(new Header("Origin", FOREIGN_ORIGIN));
            Exchange x = ctx.http().send("GET", target, headers, new byte[0]);
            if (x == null || !x.hasResponse() || x.status() != 200) return List.of();
            MessageContext r = x.message();
            String acao = r.responseHeader("Access-Control-Allow-Origin");
            String acac = r.responseHeader("Access-Control-Allow-Credentials");
            if (acao == null || !acao.strip().equalsIgnoreCase(FOREIGN_ORIGIN) || acac == null || !acac.strip().equalsIgnoreCase("true")) return List.of();
            byte[] body = Codecs.decodeContent(r.responseBody(), r.responseHeader("Content-Encoding"));
            boolean open = EngineIo.parsePolling(body, eio).packets().stream().anyMatch(p -> p.valid() && p.type() == EngineIo.OPEN);
            if (!open) return List.of();
            boolean cookies = base.requestHeader("Cookie") != null;
            return List.of(Finding.of(id(), "Socket.IO accepts cross-origin requests with credentials")
                    .severity(Severity.MEDIUM).confidence(Confidence.TENTATIVE)
                    .detail("An Engine.IO polling handshake to <code>" + Finding.esc(target) + "</code> sent with <code>Origin: " + FOREIGN_ORIGIN
                            + "</code> succeeded, and the response reflected that origin in <code>Access-Control-Allow-Origin</code> with "
                            + "<code>Access-Control-Allow-Credentials: true</code>."
                            + (cookies ? " The scanned request carries cookies, so a cross-site page could use the victim's session." : ""))
                    .background("A server configured with <code>cors: {origin: true, credentials: true}</code> (or a reflecting origin callback) lets "
                            + "any website open a Socket.IO session in the victim's browser over long-polling, with their cookies, and read the "
                            + "server's events (cross-site WebSocket/long-polling hijacking). WebSocket upgrades are not covered by CORS at all, so "
                            + "origin checks must be enforced separately.")
                    .remediation("Configure <code>cors.origin</code> with an explicit list of trusted origins and verify the Origin header for both "
                            + "transports (e.g. <code>allowRequest</code>); prefer handshake <code>auth</code> tokens over cookies for socket authentication.")
                    .responseEvidence("Access-Control-Allow-Origin: " + acao.strip())
                    .exchange(x));
        }

        /** "/prefix/socket.io/" of the scanned request, or the request path when it carries an EIO query. */
        static String handshakePath(MessageContext m) {
            String p = m.path();
            int i = p.toLowerCase(Locale.ROOT).indexOf("/socket.io/");
            if (i >= 0) return p.substring(0, i + "/socket.io/".length());
            return Codecs.first(m.queryParameters(), "EIO") != null && !m.path().isEmpty() ? m.path() : null;
        }
    }

    // ---------------------------------------------------------------- insertion points

    @Override
    public List<InsertionPoint> insertionPoints(MessageContext request, DecodeResult decoded) {
        if (!"POST".equalsIgnoreCase(request.method()) || !"polling".equals(Codecs.first(request.queryParameters(), "transport"))) return List.of();
        byte[] body = request.requestBody();
        if (body.length == 0 || body[0] == 0 || body[0] == 1) return List.of(); // empty, or v3 binary (XHR2) framing
        String text = new String(body, StandardCharsets.UTF_8);
        if (text.startsWith("d=")) return List.of(); // JSONP form send
        Framed framed = Framed.split(text, SocketIoDecoder.eioVersion(request));
        if (framed == null) return List.of();
        List<InsertionPoint> out = new ArrayList<>();
        for (int i = 0; i < framed.packets().size() && out.size() < InsertionPoints.MAX_POINTS; i++) {
            String pkt = framed.packets().get(i);
            if (pkt.isEmpty() || pkt.charAt(0) != '4') continue;
            SocketIoPacket s = SocketIoPacket.parse(pkt.substring(1));
            if (!s.valid() || !carriesArguments(s) || s.data() == null || !s.data().isJsonArray()) continue;
            String prefix = pkt.substring(0, pkt.length() - s.rawData().length());
            boolean event = s.type() == SocketIoPacket.EVENT || s.type() == SocketIoPacket.BINARY_EVENT;
            List<String> placeholders = new ArrayList<>();
            placeholderPaths(s.data(), "$", placeholders, 0);
            String what = event ? "EVENT \"" + Codecs.truncate(s.eventName(), 60) + "\"" : s.typeName() + (s.ackId() != null ? " " + s.ackId() : "");
            String nsp = s.namespace() != null && !s.namespace().equals("/") ? " on " + s.namespace() : "";
            String idx = framed.packets().size() > 1 ? " (packet " + (i + 1) + ")" : "";
            final int index = i;
            for (InsertionPoints.JsonLeaf leaf : InsertionPoints.jsonLeaves(s.data())) {
                if (out.size() >= InsertionPoints.MAX_POINTS) break;
                if (event && leaf.path().equals("$[0]")) continue; // event name
                if (placeholders.stream().anyMatch(ph -> under(leaf.path(), ph))) continue;
                out.add(InsertionPoint.body("Socket.IO: " + what + nsp + " " + argPath(leaf.path(), event) + idx, InsertionPoints.text(leaf.value()),
                        payload -> framed.with(index, prefix + leaf.replace().apply(payload)).getBytes(StandardCharsets.UTF_8)));
            }
        }
        return out;
    }

    /** "$[2].name" → "args[1].name" for events (element 0 is the event name), "args[2].name" for acks. */
    static String argPath(String leafPath, boolean event) {
        if (!leafPath.startsWith("$[")) return leafPath;
        int close = leafPath.indexOf(']');
        try {
            int k = Integer.parseInt(leafPath.substring(2, close));
            return "args[" + (event ? k - 1 : k) + "]" + leafPath.substring(close + 1);
        } catch (NumberFormatException e) {
            return leafPath;
        }
    }

    private static boolean under(String path, String prefix) {
        if (!path.startsWith(prefix)) return false;
        return path.length() == prefix.length() || path.charAt(prefix.length()) == '.' || path.charAt(prefix.length()) == '[';
    }

    /** Paths (in jsonLeaves syntax) of binary attachment placeholder objects, which must stay intact. */
    private static void placeholderPaths(JsonElement e, String path, List<String> out, int depth) {
        if (e == null || depth > 32 || out.size() > 100) return;
        if (e.isJsonObject()) {
            JsonObject o = e.getAsJsonObject();
            if (o.has("_placeholder") && o.has("num")) {
                out.add(path);
                return;
            }
            for (Map.Entry<String, JsonElement> en : o.entrySet()) placeholderPaths(en.getValue(), path + "." + en.getKey(), out, depth + 1);
        } else if (e.isJsonArray()) {
            JsonArray a = e.getAsJsonArray();
            for (int k = 0; k < a.size(); k++) placeholderPaths(a.get(k), path + "[" + k + "]", out, depth + 1);
        }
    }

    /**
     * A polling payload split into raw packet strings, re-joinable with one packet replaced: v4 joins with the 0x1E
     * record separator, v3 re-computes each {@code <length>:} prefix (in UTF-16 code units, as Engine.IO counts).
     */
    record Framed(List<String> packets, boolean v3) {

        static Framed split(String text, int eio) {
            boolean v3 = eio == 3 || (eio == 0 && text.indexOf(EngineIo.RECORD_SEPARATOR) < 0 && EngineIo.startsWithLengthPrefix(text));
            if (!v3) return new Framed(List.of(text.split(String.valueOf(EngineIo.RECORD_SEPARATOR), -1)), false);
            List<String> list = new ArrayList<>();
            int i = 0;
            while (i < text.length()) {
                int colon = i;
                while (colon < text.length() && colon - i < 10 && Character.isDigit(text.charAt(colon))) colon++;
                if (colon == i || colon >= text.length() || text.charAt(colon) != ':') return null;
                long n = Long.parseLong(text.substring(i, colon));
                int start = colon + 1;
                if (start + n > text.length() || list.size() >= EngineIo.MAX_PACKETS) return null;
                list.add(text.substring(start, start + (int) n));
                i = start + (int) n;
            }
            return list.isEmpty() ? null : new Framed(List.copyOf(list), true);
        }

        String with(int index, String packet) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < packets.size(); i++) {
                String p = i == index ? packet : packets.get(i);
                if (v3) sb.append(p.length()).append(':').append(p);
                else {
                    if (i > 0) sb.append(EngineIo.RECORD_SEPARATOR);
                    sb.append(p);
                }
            }
            return sb.toString();
        }
    }

    // ---------------------------------------------------------------- helpers

    private static final Pattern NODE_ERROR = Pattern.compile(
            "(?m)^\\s*at (?:[\\w.$<>\\[\\] ]+ \\()?(?:file://)?(?:/|[A-Za-z]:\\\\|node:)[^()\\n]{1,300}:\\d+:\\d+\\)?");

    /** Generic exception evidence plus Node.js stack frames ("at fn (/app/x.js:1:2)"). */
    static String exceptionEvidence(String text) {
        Matcher m = NODE_ERROR.matcher(text);
        if (m.find()) return m.group().strip();
        return ScanPatterns.exceptionEvidence(text);
    }
}
