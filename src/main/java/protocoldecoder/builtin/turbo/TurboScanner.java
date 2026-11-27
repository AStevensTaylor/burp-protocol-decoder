package protocoldecoder.builtin.turbo;

import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.scan.ActiveCheck;
import protocoldecoder.scan.ActiveContext;
import protocoldecoder.scan.Confidence;
import protocoldecoder.scan.Exchange;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.PassiveCheck;
import protocoldecoder.scan.ProtocolScanner;
import protocoldecoder.scan.Severity;
import protocoldecoder.util.Codecs;

import java.net.URI;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Scanner support for Hotwire Turbo: signed stream names in pages (GlobalIDs, Ruby Marshal), {@code <script>} in
 * Turbo Stream templates, and the Action Cable cross-origin WebSocket check (run from Turbo pages because the Action
 * Cable decoder only sees WebSocket frames, which Burp's active scanner never hands to extensions).
 *
 * <p>No insertion points: Turbo Drive/Frame requests are ordinary HTML form posts and links, which Burp handles.</p>
 */
public final class TurboScanner implements ProtocolScanner {

    /** One instance: it remembers which hosts were already tested. */
    private final CableCrossOrigin cableCheck = new CableCrossOrigin();

    @Override
    public String decoderId() {
        return TurboDecoder.ID;
    }

    @Override
    public List<PassiveCheck> passiveChecks() {
        return List.of(new StreamGlobalIds(), new StreamMarshal(), new StreamScript());
    }

    @Override
    public List<ActiveCheck> activeChecks() {
        return List.of(cableCheck);
    }

    static void findNodes(DecodedNode n, java.util.function.Predicate<DecodedNode> pred, List<DecodedNode> out, int depth) {
        if (n == null || depth > 60 || out.size() >= 200) return;
        if (pred.test(n)) out.add(n);
        for (DecodedNode c : n.children()) findNodes(c, pred, out, depth + 1);
    }

    /** Signed stream names of {@code <turbo-cable-stream-source>} elements in a decoded page / frame. */
    static List<SignedStreamFindings.Token> tokens(DecodeResult decoded) {
        List<DecodedNode> nodes = new ArrayList<>();
        findNodes(decoded.root(), x -> x.name().equals("signed-stream-name") && x.get("Raw") != null, nodes, 0);
        List<SignedStreamFindings.Token> out = new ArrayList<>();
        for (DecodedNode n : nodes) {
            String raw = n.get("Raw").value();
            if (raw != null && !raw.isEmpty() && out.size() < 50) out.add(SignedStreamFindings.Token.of(raw));
        }
        return out;
    }

    static final class StreamGlobalIds implements PassiveCheck {
        @Override public String id() { return "turbo.signed-stream-gid"; }
        @Override public String name() { return "GlobalIDs in signed stream names"; }
        @Override public String description() { return "turbo-cable-stream-source signed-stream-name values that decode to gid://app/Model/ID (IDOR hints)"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || decoded == null) return List.of();
            Finding f = SignedStreamFindings.globalIds(id(), tokens(decoded), "in <code>&lt;turbo-cable-stream-source&gt;</code> elements of this page");
            return f == null ? List.of() : List.of(f);
        }
    }

    static final class StreamMarshal implements PassiveCheck {
        @Override public String id() { return "turbo.signed-stream-marshal"; }
        @Override public String name() { return "Ruby Marshal in signed stream names"; }
        @Override public String description() { return "Signed stream names whose data is Ruby Marshal (deserialised server-side; RCE if secret_key_base leaks)"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || decoded == null) return List.of();
            Finding f = SignedStreamFindings.marshal(id(), tokens(decoded), "in <code>&lt;turbo-cable-stream-source&gt;</code> elements of this page");
            return f == null ? List.of() : List.of(f);
        }
    }

    static final class StreamScript implements PassiveCheck {
        @Override public String id() { return "turbo.stream-script"; }
        @Override public String name() { return "Script in Turbo Stream template"; }
        @Override public String description() { return "Turbo Stream actions whose template contains <script> elements (executed by Turbo when rendered)"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (m.isRequest() || decoded == null) return List.of();
            List<DecodedNode> nodes = new ArrayList<>();
            findNodes(decoded.root(), x -> (x.name().equals("template") || x.name().equals("content (no <template>)")) && x.value() != null
                    && x.value().toLowerCase(Locale.ROOT).contains("<script"), nodes, 0);
            if (nodes.isEmpty()) return List.of();
            List<String> actions = new ArrayList<>();
            List<DecodedNode> all = new ArrayList<>();
            findNodes(decoded.root(), x -> x.name().matches("\\[\\d+\\] .*") && x.get("action") != null, all, 0);
            for (DecodedNode a : all) {
                for (DecodedNode c : a.children()) {
                    if (nodes.contains(c) && actions.size() < 20) actions.add(a.name().replaceFirst("^\\[\\d+\\] ", ""));
                }
            }
            String snippet = nodes.get(0).value();
            int i = snippet.toLowerCase(Locale.ROOT).indexOf("<script");
            String around = snippet.substring(i, Math.min(snippet.length(), i + 200));
            return List.of(Finding.of(id(), "Turbo Stream template contains script")
                    .severity(Severity.INFORMATION).confidence(Confidence.FIRM)
                    .detail("Turbo Stream action(s) " + (actions.isEmpty() ? "" : "<code>" + Finding.esc(String.join(", ", actions)) + "</code> ")
                            + (m.isWebSocket() ? "received over a WebSocket stream source " : "")
                            + "carry a <code>&lt;script&gt;</code> element in their template: <code>" + Finding.esc(around) + "</code>")
                    .background("Turbo activates <code>&lt;script&gt;</code> elements in rendered stream templates, so stream responses and broadcasts "
                            + "are a script execution channel. That is sometimes intentional, but any user-controlled HTML that reaches a stream "
                            + "template unescaped is directly exploitable XSS, including for every subscriber of a broadcast stream.")
                    .remediation("Avoid scripts in stream templates (use Stimulus controllers or custom stream actions instead) and make sure all "
                            + "user content in partials is HTML-escaped.")
                    .responseEvidence("<script"));
        }
    }

    // ================================================================ active: Action Cable cross-origin upgrade

    static final String EVIL_ORIGIN = "https://evil.example";

    static final class CableCrossOrigin implements ActiveCheck {
        private final Set<String> tested = ConcurrentHashMap.newKeySet();
        private final SecureRandom random = new SecureRandom();

        @Override public String id() { return "turbo.cable-cross-origin"; }
        @Override public String name() { return "Action Cable cross-site WebSocket hijacking"; }
        @Override public String description() {
            return "On pages that use Action Cable (turbo-cable-stream-source or action-cable-url meta), sends one WebSocket upgrade to the "
                    + "cable endpoint with Origin: " + EVIL_ORIGIN + " and the page's cookies; reports a 101 response. 1 request, at most once per host";
        }
        @Override public Scope scope() { return Scope.PER_REQUEST; }

        /** Same-origin cable path for this page, or null when the page doesn't use Action Cable (or the cable is on another host). */
        static String cablePath(MessageContext base, String html) {
            boolean source = html.contains("<turbo-cable-stream-source");
            String url = null;
            int i = html.indexOf("action-cable-url");
            if (i >= 0) {
                int tagStart = html.lastIndexOf('<', i);
                int tagEnd = html.indexOf('>', i);
                if (tagStart >= 0 && tagEnd > i) {
                    HtmlScan.Tag t = HtmlScan.next(html, tagStart);
                    if (t != null && "meta".equals(t.name())) url = t.attr("content");
                }
            }
            if (url == null || url.isBlank()) return source || i >= 0 ? "/cable" : null;
            url = url.strip();
            if (url.startsWith("/") && !url.startsWith("//")) return url;
            try {
                URI u = URI.create(url.startsWith("//") ? "wss:" + url : url);
                if (u.getHost() == null || !u.getHost().equalsIgnoreCase(base.host())) return null; // other host: out of scope
                String p = u.getRawPath() == null || u.getRawPath().isEmpty() ? "/" : u.getRawPath();
                return p + (u.getRawQuery() == null ? "" : "?" + u.getRawQuery());
            } catch (IllegalArgumentException e) {
                return null;
            }
        }

        private static String origin(MessageContext m) {
            try {
                URI u = URI.create(m.url());
                return (u.getScheme() + "://" + u.getHost() + ":" + u.getPort()).toLowerCase(Locale.ROOT);
            } catch (IllegalArgumentException e) {
                return m.host().toLowerCase(Locale.ROOT);
            }
        }

        @Override
        public List<Finding> run(ActiveContext ctx) {
            MessageContext base = ctx.base();
            MessageContext resp = ctx.baseResponse();
            if (resp == null) return List.of();
            String ct = resp.responseHeader("Content-Type");
            if (ct != null && !ct.toLowerCase(Locale.ROOT).contains("html")) return List.of();
            byte[] body = Codecs.decodeContent(resp.responseBody(), resp.responseHeader("Content-Encoding"));
            String html = new String(body, 0, Math.min(body.length, 1024 * 1024), java.nio.charset.StandardCharsets.UTF_8);
            String path = cablePath(base, html);
            if (path == null) return List.of();
            String key = origin(base);
            if (tested.size() > 10_000 || !tested.add(key)) return List.of();

            String cookie = base.requestHeader("Cookie");
            List<Header> headers = new ArrayList<>();
            String host = base.requestHeader("Host");
            if (host != null) headers.add(new Header("Host", host));
            String ua = base.requestHeader("User-Agent");
            if (ua != null) headers.add(new Header("User-Agent", ua));
            byte[] nonce = new byte[16];
            random.nextBytes(nonce);
            headers.add(new Header("Upgrade", "websocket"));
            headers.add(new Header("Connection", "Upgrade"));
            headers.add(new Header("Sec-WebSocket-Version", "13"));
            headers.add(new Header("Sec-WebSocket-Key", Base64.getEncoder().encodeToString(nonce)));
            headers.add(new Header("Sec-WebSocket-Protocol", "actioncable-v1-json, actioncable-unsupported"));
            headers.add(new Header("Origin", EVIL_ORIGIN));
            if (cookie != null) headers.add(new Header("Cookie", cookie));
            Exchange x = ctx.http().send("GET", path, headers, new byte[0]);
            if (x == null || !x.hasResponse() || x.status() != 101) return List.of();
            boolean withCookies = cookie != null && !cookie.isBlank();
            return List.of(Finding.of(id(), "Action Cable accepts cross-origin WebSocket connections")
                    .severity(withCookies ? Severity.MEDIUM : Severity.LOW).confidence(Confidence.TENTATIVE).scope(Finding.Scope.HOST)
                    .detail("A WebSocket upgrade to <code>" + Finding.esc(path) + "</code> with <code>Origin: " + EVIL_ORIGIN + "</code>"
                            + (withCookies ? " and the session cookies of the scanned request" : " (no cookies were available)")
                            + " was accepted with <b>HTTP 101 Switching Protocols</b>. A malicious site can open the cable in a victim's browser, "
                            + "which sends the victim's cookies, subscribe to their channels and read broadcasts or call channel actions "
                            + "(cross-site WebSocket hijacking). Confirm by subscribing over the hijacked connection: if the connection is "
                            + "authenticated by cookies, the welcome message is followed by data for the victim.")
                    .background("Action Cable relies on the Origin check (<code>config.action_cable.allowed_request_origins</code>, by default the "
                            + "application's own host) because browsers attach cookies to cross-site WebSocket handshakes. "
                            + "<code>disable_request_forgery_protection = true</code> or an over-broad allow list removes it.")
                    .remediation("Restrict <code>config.action_cable.allowed_request_origins</code> to the application's origins and keep "
                            + "request forgery protection enabled; authenticate connections in <code>ApplicationCable::Connection#connect</code>.")
                    .requestEvidence("Origin: " + EVIL_ORIGIN)
                    .exchange(x));
        }
    }
}
