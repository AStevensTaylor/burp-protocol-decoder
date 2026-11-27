package protocoldecoder.builtin.phoenix;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.scan.ActiveCheck;
import protocoldecoder.scan.ActiveContext;
import protocoldecoder.scan.Confidence;
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
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scanner support for Phoenix Channels / LiveView. Channel traffic is mostly WebSocket (passive only); long-poll sends
 * get insertion points inside the channel message payloads (and inside LiveView form-event values).
 */
public final class PhoenixScanner implements ProtocolScanner {

    static final String FOREIGN_ORIGIN = "https://evil.example";
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();

    @Override
    public String decoderId() {
        return PhoenixDecoder.ID;
    }

    @Override
    public List<PassiveCheck> passiveChecks() {
        return List.of(new ReadableTokens(), new ErrorReplies(), new SensitivePayloads(), new LiveViewJoinWithoutCsrf());
    }

    @Override
    public List<ActiveCheck> activeChecks() {
        return List.of(new CrossOriginSocket());
    }

    // ---------------------------------------------------------------- shared parsing

    static boolean fromServer(MessageContext m) {
        return m.isResponse() || (m.isWebSocket() && "SERVER_TO_CLIENT".equals(m.webSocketDirection()));
    }

    /** JSON channel messages in a WebSocket frame or long-poll body (binary-serializer frames are skipped). */
    static List<PhoenixMessage> messages(MessageContext m) {
        if (m.isWebSocket()) {
            byte[] p = m.body();
            if (p.length == 0 || (p[0] & 0xff) <= 2) return List.of();
            PhoenixMessage msg = PhoenixMessage.parseText(Codecs.utf8(p));
            return msg == null ? List.of() : List.of(msg);
        }
        if (!PhoenixDecoder.longPollPath(m)) return List.of();
        byte[] body = m.isRequest() ? m.requestBody() : Codecs.decodeContent(m.responseBody(), m.responseHeader("Content-Encoding"));
        String t = Codecs.utf8(body).strip();
        if (m.isRequest()) return PhoenixDecoder.parseLines(t);
        JsonElement e = JsonTree.parseStrict(t);
        if (e == null || !e.isJsonObject() || !(e.getAsJsonObject().get("messages") instanceof JsonArray arr)) return List.of();
        List<PhoenixMessage> out = new ArrayList<>();
        for (JsonElement x : arr) {
            if (out.size() >= 1000) break;
            PhoenixMessage pm = x.isJsonPrimitive() ? PhoenixMessage.parseText(x.getAsString()) : PhoenixMessage.fromJson(x);
            if (pm != null) out.add(pm);
        }
        return out;
    }

    private static String where(MessageContext m) {
        return m.isWebSocket() ? "a WebSocket message (" + (fromServer(m) ? "server → client" : "client → server") + ")"
                : m.isResponse() ? "a long-poll response" : m.path().toLowerCase(Locale.ROOT).endsWith("/longpoll") ? "a long-poll request" : "the page";
    }

    private static String str(JsonObject o, String k) {
        JsonElement e = o == null ? null : o.get(k);
        return e != null && e.isJsonPrimitive() ? e.getAsString() : null;
    }

    private static boolean csrfPath(String path) {
        return path.toLowerCase(Locale.ROOT).contains("csrf");
    }

    // ---------------------------------------------------------------- passive checks

    /** Signed (not encrypted) Plug/Phoenix tokens whose readable contents look sensitive. */
    static final class ReadableTokens implements PassiveCheck {
        @Override public String id() { return "phoenix.readable-token-data"; }
        @Override public String name() { return "Sensitive data in signed tokens"; }
        @Override public String description() {
            return "LiveView session/static tokens or Phoenix.Token values (signed, not encrypted) whose decoded contents hold secrets or credentials";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (decoded == null) return List.of();
            List<ScanPatterns.Sensitive> hits = new ArrayList<>();
            collect(decoded.root(), hits, 0);
            hits.removeIf(h -> csrfPath(h.path()) || h.kind().equals("email address"));
            if (hits.isEmpty()) return List.of();
            return List.of(Finding.of(id(), "Sensitive data readable in Phoenix signed token")
                    .severity(Severity.LOW).confidence(Confidence.TENTATIVE)
                    .detail("A signed Phoenix token in " + where(m) + " on <code>" + Finding.esc(m.path())
                            + "</code> carries sensitive-looking data that anyone holding the token can read:" + ScanPatterns.htmlList(hits))
                    .background("<code>Phoenix.Token.sign</code> and LiveView's <code>data-phx-session</code> / <code>data-phx-static</code> tokens are "
                            + "signed with <code>Plug.Crypto.MessageVerifier</code>: they cannot be forged, but their payload is only base64url-encoded "
                            + "Erlang terms and is readable by the browser, browser extensions, logs and anyone the page is cached for.")
                    .remediation("Keep secrets out of LiveView session data and signed tokens; store a reference (e.g. an id) and look the value up "
                            + "server-side, or use <code>Phoenix.Token.encrypt</code> / <code>Plug.Crypto.encrypt</code>."));
        }

        private static void collect(DecodedNode n, List<ScanPatterns.Sensitive> out, int depth) {
            if (depth > 40 || out.size() >= 20) return;
            DecodedNode kind = n.get("Kind");
            DecodedNode data = n.get("Data");
            if (kind != null && kind.value() != null && kind.value().startsWith("signed") && data != null) {
                for (ScanPatterns.Sensitive s : ScanPatterns.sensitiveValues(data, 20)) {
                    out.add(new ScanPatterns.Sensitive(s.kind(), n.name() + " › " + s.path(), s.value()));
                }
                return;
            }
            for (DecodedNode c : n.children()) collect(c, out, depth + 1);
        }
    }

    /** phx_reply {status: "error"} / phx_error carrying exception or stack trace text. */
    static final class ErrorReplies implements PassiveCheck {
        @Override public String id() { return "phoenix.error-details"; }
        @Override public String name() { return "Error replies with exception details"; }
        @Override public String description() { return "phx_reply with status \"error\" (or phx_error) whose payload contains Elixir/other exception text or stack traces"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!fromServer(m)) return List.of();
            for (PhoenixMessage msg : messages(m)) {
                if (msg.payload() == null) continue;
                JsonObject po = msg.payload().isJsonObject() ? msg.payload().getAsJsonObject() : null;
                boolean error = ("phx_reply".equals(msg.event()) && "error".equals(str(po, "status"))) || "phx_error".equals(msg.event());
                if (!error) continue;
                String text = msg.payload().toString().replace("\\n", "\n").replace("\\t", "\t").replace("\\\"", "\"");
                String trace = exceptionEvidence(text);
                if (trace == null) continue;
                return List.of(Finding.of(id(), "Phoenix channel error discloses exception details")
                        .severity(Severity.LOW).confidence(Confidence.FIRM)
                        .detail("An error reply on topic <code>" + Finding.esc(msg.topic()) + "</code> in " + where(m) + " contains exception details: <code>"
                                + Finding.esc(Codecs.truncate(trace, 400)) + "</code>")
                        .background("Channel <code>join</code>/<code>handle_in</code> callbacks that reply with <code>{:error, %{reason: inspect(e)}}</code> "
                                + "or similar send exception structs, messages and stack traces to the client, revealing modules, file paths and dependencies.")
                        .remediation("Reply with generic error reasons and log exception details server-side.")
                        .responseEvidence(trace.split("\n", 2)[0]));
            }
            return List.of();
        }
    }

    /** Secrets in channel payloads / LiveView diffs. */
    static final class SensitivePayloads implements PassiveCheck {
        private static final Set<String> CLIENT_KINDS = Set.of("JWT", "bearer token");
        private static final Set<String> SKIP_EVENTS = Set.of("phx_join", "heartbeat", "phx_leave", "phx_close");

        @Override public String id() { return "phoenix.sensitive-payload"; }
        @Override public String name() { return "Sensitive data in channel payloads"; }
        @Override public String description() {
            return "Tokens, credentials or card numbers in channel payloads and LiveView diffs (server → client: Low; client → server: only JWT/bearer tokens, Information)";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            boolean server = fromServer(m);
            List<ScanPatterns.Sensitive> hits = new ArrayList<>();
            List<String> where = new ArrayList<>();
            for (PhoenixMessage msg : messages(m)) {
                if (msg.payload() == null || SKIP_EVENTS.contains(msg.event()) || hits.size() >= 20) continue;
                if (msg.topic().equals("phoenix")) continue;
                List<ScanPatterns.Sensitive> h = new ArrayList<>(ScanPatterns.sensitiveValues(JsonTree.toNode("payload", msg.payload(), true), 20));
                h.removeIf(x -> x.kind().equals("email address") || csrfPath(x.path()) || PhoenixToken.looksLikeToken(x.value())
                        || (!server && !CLIENT_KINDS.contains(x.kind())));
                if (h.isEmpty()) continue;
                hits.addAll(h);
                where.add(msg.event() + " on " + msg.topic());
            }
            if (hits.isEmpty()) return List.of();
            return List.of(Finding.of(id(), server ? "Sensitive data in Phoenix channel messages" : "Token sent in Phoenix channel payload")
                    .severity(server ? Severity.LOW : Severity.INFORMATION).confidence(Confidence.TENTATIVE)
                    .detail("Phoenix " + Finding.esc(String.join(", ", where)) + " in " + where(m) + " carries sensitive-looking values:" + ScanPatterns.htmlList(hits))
                    .background(server
                            ? "Channel broadcasts go to every subscriber of a topic, and LiveView diffs/assigns end up in the browser. Secrets in "
                            + "them can reach users who should not see them and are visible to any script in the page."
                            : "Tokens sent in channel payloads (rather than socket connect params) are easily logged and exposed to scripts in the page.")
                    .remediation(server
                            ? "Only push data the subscribers are entitled to; keep secrets out of assigns that are rendered or pushed."
                            : "Authenticate once in <code>UserSocket.connect/3</code> and keep tokens out of message payloads."));
        }
    }

    /** LiveView joins whose params carry no _csrf_token (session not shared with the socket). */
    static final class LiveViewJoinWithoutCsrf implements PassiveCheck {
        @Override public String id() { return "phoenix.liveview-no-csrf"; }
        @Override public String name() { return "LiveView join without _csrf_token"; }
        @Override public String description() { return "Client LiveView phx_join whose params (and socket URL) carry no _csrf_token"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isWebSocket() || fromServer(m)) return List.of();
            if (Codecs.first(m.queryParameters(), "_csrf_token") != null) return List.of();
            for (PhoenixMessage msg : messages(m)) {
                if (!msg.isLiveView() || !"phx_join".equals(msg.event()) || msg.payload() == null || !msg.payload().isJsonObject()) continue;
                JsonObject po = msg.payload().getAsJsonObject();
                if (!(po.get("params") instanceof JsonObject params) || params.has("_csrf_token")) continue;
                return List.of(Finding.of(id(), "LiveView socket connects without a CSRF token")
                        .severity(Severity.INFORMATION).confidence(Confidence.TENTATIVE).scope(Finding.Scope.HOST)
                        .detail("The LiveView join for <code>" + Finding.esc(msg.topic()) + "</code> on <code>" + Finding.esc(m.path())
                                + "</code> sends params without <code>_csrf_token</code>, and the socket URL has none either.")
                        .background("Phoenix LiveView clients normally pass the page's CSRF token (<code>params: {_csrf_token: …}</code>), which the "
                                + "server requires before it hands the Plug session (<code>connect_info: [session: …]</code>) to the socket. Without it the "
                                + "LiveView runs without the user's session, or the application authenticates the socket some other way. Review how "
                                + "the socket is authenticated and that <code>check_origin</code> is enabled.")
                        .remediation("Pass <code>_csrf_token</code> in the LiveSocket params and configure <code>connect_info: [session: @session_options]</code> "
                                + "if the LiveView relies on the session.")
                        .requestEvidence("\"params\":" + Codecs.truncate(params.toString(), 200)));
            }
            return List.of();
        }
    }

    // ---------------------------------------------------------------- active

    /** Opens a socket (long poll, else WebSocket upgrade) with a foreign Origin and without auth params. */
    static final class CrossOriginSocket implements ActiveCheck {
        /** Query parameters a cross-site attacker would not know; dropped from the probe. */
        private static final Set<String> AUTH_PARAMS = Set.of("token", "_csrf_token", "csrf_token", "auth", "access_token", "jwt",
                "user_token", "session", "api_key", "key");

        @Override public String id() { return "phoenix.cross-origin-socket"; }
        @Override public String name() { return "Phoenix socket cross-origin check"; }
        @Override public String description() {
            return "Up to 2 requests per host: long-poll connect (falling back to a WebSocket upgrade) with Origin " + FOREIGN_ORIGIN
                    + " and without token/CSRF params; reports when the socket is accepted (check_origin disabled)";
        }
        @Override public Scope scope() { return Scope.PER_HOST; }

        @Override
        public List<Finding> run(ActiveContext ctx) {
            MessageContext base = ctx.base();
            String prefix = socketPrefix(base);
            if (prefix == null) return List.of();
            String query = probeQuery(base);
            List<Header> headers = new ArrayList<>();
            for (Header h : base.requestHeaders()) {
                String n = h.name().toLowerCase(Locale.ROOT);
                if (n.equals("origin") || n.equals("content-type") || n.equals("content-length") || n.equals("upgrade")
                        || n.equals("connection") || n.startsWith("sec-websocket-")) continue;
                headers.add(h);
            }
            headers.add(new Header("Origin", FOREIGN_ORIGIN));

            Exchange lp = ctx.http().send("GET", prefix + "/longpoll?" + query, headers, new byte[0]);
            Exchange accepted = null;
            String how = null;
            if (lp != null && lp.hasResponse()) {
                Integer status = lp.status() == 200 ? longPollStatus(lp) : null;
                if (status != null && (status == 410 || status == 200)) {
                    accepted = lp;
                    how = "a long-poll connect (<code>GET " + Finding.esc(prefix) + "/longpoll</code>) returned <code>{\"status\":" + status + ", \"token\":…}</code>";
                } else if (status != null) {
                    return List.of(); // {"status":403}: origin rejected (or connect refused)
                }
            }
            if (accepted == null) {
                List<Header> ws = new ArrayList<>(headers);
                ws.add(new Header("Upgrade", "websocket"));
                ws.add(new Header("Connection", "Upgrade"));
                ws.add(new Header("Sec-WebSocket-Version", "13"));
                ws.add(new Header("Sec-WebSocket-Key", Base64.getEncoder().encodeToString("protocol-decoder".getBytes(StandardCharsets.US_ASCII))));
                Exchange up = ctx.http().send("GET", prefix + "/websocket?" + query, ws, new byte[0]);
                if (up == null || !up.hasResponse() || up.status() != 101) return List.of();
                accepted = up;
                how = "a WebSocket upgrade (<code>GET " + Finding.esc(prefix) + "/websocket</code>) was answered with <code>101 Switching Protocols</code>";
            }
            boolean cookies = base.requestHeader("Cookie") != null;
            return List.of(Finding.of(id(), "Phoenix socket accepts cross-origin connections")
                    .severity(cookies ? Severity.MEDIUM : Severity.LOW).confidence(Confidence.TENTATIVE)
                    .detail("With <code>Origin: " + FOREIGN_ORIGIN + "</code> and without token/CSRF parameters, " + how + ". "
                            + (cookies ? "The request carried the session cookies, as a cross-site page's connection would."
                            : "No cookies were sent, so impact depends on whether the socket uses cookie/session data at all."))
                    .background("Phoenix rejects WebSocket and long-poll connections from origins other than the endpoint's host unless "
                            + "<code>check_origin</code> is disabled (or set too broadly). Without it, any website can open the socket in a "
                            + "victim's browser (cross-site WebSocket hijacking); if <code>connect/3</code> trusts the session cookie, the "
                            + "attacker's page then acts as the victim on every channel.")
                    .remediation("Enable <code>check_origin</code> (the default outside development) with an explicit list of allowed origins, and "
                            + "authenticate sockets with a signed token or the LiveView <code>_csrf_token</code> rather than cookies alone.")
                    .exchange(accepted));
        }

        /** "/live" for "/live/websocket" etc.; "/live" for LiveView pages; else null. */
        static String socketPrefix(MessageContext m) {
            String p = m.path();
            String lower = p.toLowerCase(Locale.ROOT);
            if (lower.endsWith("/websocket")) return p.substring(0, p.length() - "/websocket".length());
            if (lower.endsWith("/longpoll")) return p.substring(0, p.length() - "/longpoll".length());
            if (m.hasResponse() && m.responseBodyText().contains("data-phx-session=\"")) return "/live";
            return null;
        }

        static String probeQuery(MessageContext m) {
            StringBuilder q = new StringBuilder();
            boolean vsn = false;
            for (Map.Entry<String, List<String>> e : Codecs.parseQuery(m.query()).entrySet()) {
                if (AUTH_PARAMS.contains(e.getKey().toLowerCase(Locale.ROOT))) continue;
                if (e.getKey().equals("vsn")) vsn = true;
                for (String v : e.getValue()) {
                    if (q.length() > 0) q.append('&');
                    q.append(InsertionPoints.formEncode(e.getKey())).append('=').append(InsertionPoints.formEncode(v));
                }
            }
            if (!vsn) q.append(q.length() > 0 ? "&" : "").append("vsn=2.0.0");
            return q.toString();
        }

        private static Integer longPollStatus(Exchange x) {
            JsonElement e = JsonTree.parseStrict(Codecs.utf8(Codecs.decodeContent(x.message().responseBody(), x.message().responseHeader("Content-Encoding"))).strip());
            if (e == null || !e.isJsonObject() || !(e.getAsJsonObject().get("status") instanceof JsonPrimitive p) || !p.isNumber()) return null;
            if (p.getAsInt() != 403 && !e.getAsJsonObject().has("token")) return null;
            return p.getAsInt();
        }
    }

    // ---------------------------------------------------------------- insertion points

    @Override
    public List<InsertionPoint> insertionPoints(MessageContext request, DecodeResult decoded) {
        if (!"POST".equalsIgnoreCase(request.method()) || !PhoenixDecoder.longPollPath(request)) return List.of();
        String body = new String(request.requestBody(), StandardCharsets.UTF_8);
        if (body.isBlank()) return List.of();
        List<InsertionPoint> out = new ArrayList<>();
        if (PhoenixMessage.parseText(body) != null) {
            addMessage(out, JsonTree.parseStrict(body.strip()), "$", json -> json);
            return out;
        }
        JsonElement all = JsonTree.parseStrict(body);
        if (all != null && all.isJsonArray()) {
            JsonArray arr = all.getAsJsonArray();
            for (int i = 0; i < arr.size() && out.size() < InsertionPoints.MAX_POINTS; i++) {
                if (!arr.get(i).isJsonArray() && !arr.get(i).isJsonObject()) continue;
                final int idx = i;
                addMessage(out, arr.get(i), "$", json -> {
                    JsonArray copy = arr.deepCopy();
                    copy.set(idx, JsonTree.parseStrict(json));
                    return GSON.toJson(copy);
                });
            }
            return out;
        }
        String[] lines = body.split("\n", -1);
        for (int i = 0; i < lines.length && out.size() < InsertionPoints.MAX_POINTS; i++) {
            if (lines[i].isBlank()) continue;
            final int idx = i;
            addMessage(out, JsonTree.parseStrict(lines[i].strip()), "$", json -> {
                String[] copy = lines.clone();
                copy[idx] = json;
                return String.join("\n", copy);
            });
        }
        return out;
    }

    /**
     * Adds points for the payload leaves of one message; {@code wrap} turns the re-serialised message into the whole body.
     */
    private static void addMessage(List<InsertionPoint> out, JsonElement msgJson, String root, java.util.function.UnaryOperator<String> wrap) {
        PhoenixMessage pm = PhoenixMessage.fromJson(msgJson);
        if (pm == null || pm.payload() == null) return;
        String payloadPath = msgJson.isJsonArray() ? root + "[4]" : root + ".payload";
        String label = "Phoenix: " + Codecs.truncate(pm.topic(), 60) + " " + Codecs.truncate(pm.event(), 40) + " ";
        // LiveView form events: one point per urlencoded field of payload.value.
        String formValue = null;
        JsonObject po = pm.payload().isJsonObject() ? pm.payload().getAsJsonObject() : null;
        if (pm.isLiveView() && "event".equals(pm.event()) && "form".equals(str(po, "type")) && po.get("value") instanceof JsonPrimitive v && v.isString()) {
            formValue = v.getAsString();
            Map<String, Integer> seen = new java.util.HashMap<>();
            for (Map.Entry<String, List<String>> f : Codecs.parseQuery(formValue).entrySet()) {
                for (String val : f.getValue()) {
                    if (out.size() >= InsertionPoints.MAX_POINTS) return;
                    String field = f.getKey();
                    int occ = seen.merge(field, 1, Integer::sum) - 1;
                    String fv = formValue;
                    out.add(InsertionPoint.body(label + "payload.value form field " + field, val, payload -> {
                        JsonElement copy = msgJson.deepCopy();
                        JsonObject cp = copy.isJsonArray() ? copy.getAsJsonArray().get(4).getAsJsonObject() : copy.getAsJsonObject().getAsJsonObject("payload");
                        cp.addProperty("value", InsertionPoints.replaceFormField(fv, field, occ, payload));
                        return wrap.apply(GSON.toJson(copy)).getBytes(StandardCharsets.UTF_8);
                    }));
                }
            }
        }
        for (InsertionPoints.JsonLeaf leaf : InsertionPoints.jsonLeaves(msgJson)) {
            if (out.size() >= InsertionPoints.MAX_POINTS) return;
            String p = leaf.path();
            if (!(p.equals(payloadPath) || p.startsWith(payloadPath + ".") || p.startsWith(payloadPath + "["))) continue;
            String rel = "payload" + p.substring(payloadPath.length());
            if (formValue != null && rel.equals("payload.value")) continue;
            out.add(InsertionPoint.body(label + rel, InsertionPoints.text(leaf.value()),
                    payload -> wrap.apply(leaf.replace().apply(payload)).getBytes(StandardCharsets.UTF_8)));
        }
    }

    // ---------------------------------------------------------------- helpers

    /** "** (RuntimeError) boom", "%Ecto.Query.CastError{", "(my_app 0.1.0) lib/x.ex:12:". */
    private static final Pattern ELIXIR_RAISE = Pattern.compile("\\*\\* \\([A-Z][\\w.]*\\)[^\\n\"]{0,200}");
    private static final Pattern ELIXIR_STRUCT = Pattern.compile("%[A-Z][\\w.]*(?:Error|Exception)\\{");
    private static final Pattern ELIXIR_FRAME = Pattern.compile("\\([a-z_][a-z0-9_]* [0-9][^()\\s]{0,30}\\) [\\w/.-]+\\.exs?:\\d+:[^\\n\"]{0,200}");

    static String exceptionEvidence(String text) {
        for (Pattern p : new Pattern[]{ELIXIR_RAISE, ELIXIR_FRAME, ELIXIR_STRUCT}) {
            Matcher m = p.matcher(text);
            if (m.find()) return m.group().strip();
        }
        return ScanPatterns.exceptionEvidence(text);
    }
}
