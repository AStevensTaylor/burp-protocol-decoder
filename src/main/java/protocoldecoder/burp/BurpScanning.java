package protocoldecoder.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.websocket.BinaryMessageReceivedAction;
import burp.api.montoya.proxy.websocket.BinaryMessageToBeSentAction;
import burp.api.montoya.proxy.websocket.InterceptedBinaryMessage;
import burp.api.montoya.proxy.websocket.InterceptedTextMessage;
import burp.api.montoya.proxy.websocket.ProxyMessageHandler;
import burp.api.montoya.proxy.websocket.TextMessageReceivedAction;
import burp.api.montoya.proxy.websocket.TextMessageToBeSentAction;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import burp.api.montoya.websocket.Direction;
import protocoldecoder.App;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.scan.ActiveCheck;
import protocoldecoder.scan.Evidence;
import protocoldecoder.scan.Exchange;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.HttpSender;
import protocoldecoder.scan.InsertionPoint;
import protocoldecoder.util.Codecs;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/** Connects the Burp-independent {@link protocoldecoder.scan.ScanEngine} to Burp's scanner and proxy. */
final class BurpScanning {

    private static final int MAX_MARKERS = 20;
    private static final int MAX_WS_ISSUE_KEYS = 20_000;

    private final MontoyaApi api;
    private final App app;
    private final Set<String> reportedWebSocketIssues = ConcurrentHashMap.newKeySet();
    private final ThreadPoolExecutor wsExecutor = new ThreadPoolExecutor(1, 1, 30, TimeUnit.SECONDS, new ArrayBlockingQueue<>(2000), r -> {
        Thread t = new Thread(r, "protocol-decoder-ws-scan");
        t.setDaemon(true);
        t.setContextClassLoader(BurpScanning.class.getClassLoader());
        return t;
    }, new ThreadPoolExecutor.DiscardPolicy());

    BurpScanning(MontoyaApi api, App app) {
        this.api = api;
        this.app = app;
    }

    void register() {
        api.scanner().registerPassiveScanCheck(new Passive(), ScanCheckType.PER_REQUEST);
        api.scanner().registerActiveScanCheck(new Active(ActiveCheck.Scope.PER_HOST), ScanCheckType.PER_HOST);
        api.scanner().registerActiveScanCheck(new Active(ActiveCheck.Scope.PER_REQUEST), ScanCheckType.PER_REQUEST);
        api.scanner().registerActiveScanCheck(new Active(ActiveCheck.Scope.PER_INSERTION_POINT), ScanCheckType.PER_INSERTION_POINT);
        api.scanner().registerInsertionPointProvider(this::insertionPoints);
        api.proxy().registerWebSocketCreationHandler(creation -> {
            HttpRequest upgrade = creation.upgradeRequest();
            creation.proxyWebSocket().registerProxyMessageHandler(new WebSocketScanner(upgrade));
        });
    }

    void close() {
        wsExecutor.shutdownNow();
    }

    private int maxBytes() {
        return app.settings().maxMatchBytes;
    }

    // ---------------------------------------------------------------- passive

    private final class Passive implements PassiveScanCheck {
        @Override
        public String checkName() {
            return "Protocol Decoder passive checks";
        }

        @Override
        public AuditResult doCheck(HttpRequestResponse rr) {
            if (!app.settings().scanPassive) return AuditResult.auditResult(List.of());
            try {
                List<AuditIssue> issues = new ArrayList<>();
                MessageContext req = Montoya.fromHttp(rr, MessageKind.REQUEST, maxBytes());
                if (req != null) for (Finding f : app.scanEngine().passive(req, true)) issues.add(toIssue(f, rr, null));
                MessageContext resp = Montoya.fromHttp(rr, MessageKind.RESPONSE, maxBytes());
                if (resp != null) for (Finding f : app.scanEngine().passive(resp, true)) issues.add(toIssue(f, rr, null));
                return AuditResult.auditResult(dedupe(issues));
            } catch (RuntimeException e) {
                app.logError("Passive scan failed for " + rr.request().url() + ": " + e);
                return AuditResult.auditResult(List.of());
            }
        }

        @Override
        public ConsolidationAction consolidateIssues(AuditIssue existing, AuditIssue newIssue) {
            return consolidate(existing, newIssue);
        }
    }

    static ConsolidationAction consolidate(AuditIssue existing, AuditIssue newIssue) {
        return existing.name().equals(newIssue.name()) && existing.baseUrl().equals(newIssue.baseUrl())
                ? ConsolidationAction.KEEP_EXISTING : ConsolidationAction.KEEP_BOTH;
    }

    private static List<AuditIssue> dedupe(List<AuditIssue> issues) {
        List<AuditIssue> out = new ArrayList<>();
        Set<String> seen = new java.util.HashSet<>();
        for (AuditIssue i : issues) if (seen.add(i.name() + "\u0000" + i.baseUrl())) out.add(i);
        return out;
    }

    // ---------------------------------------------------------------- active

    private final class Active implements ActiveScanCheck {
        private final ActiveCheck.Scope scope;

        Active(ActiveCheck.Scope scope) {
            this.scope = scope;
        }

        @Override
        public String checkName() {
            return "Protocol Decoder active checks (" + scope.name().toLowerCase().replace('_', ' ') + ")";
        }

        @Override
        public AuditResult doCheck(HttpRequestResponse base, AuditInsertionPoint point, Http http) {
            if (!app.settings().scanActive) return AuditResult.auditResult(List.of());
            try {
                MessageContext req = Montoya.fromHttp(base, MessageKind.REQUEST, maxBytes());
                if (req == null) return AuditResult.auditResult(List.of());
                MessageContext resp = Montoya.fromHttp(base, MessageKind.RESPONSE, maxBytes());
                Sender sender = new Sender(base.request(), http);
                String ipName = null, ipBase = null;
                protocoldecoder.scan.ActiveContext.PayloadSender payloads = null;
                if (scope == ActiveCheck.Scope.PER_INSERTION_POINT && point != null) {
                    ipName = point.name();
                    ipBase = point.baseValue();
                    payloads = payload -> sender.sendRaw(point.buildHttpRequestWithPayload(ByteArray.byteArray(payload.getBytes(StandardCharsets.UTF_8))));
                }
                List<AuditIssue> issues = new ArrayList<>();
                for (Finding f : app.scanEngine().active(scope, req, resp, ipName, ipBase, payloads, sender)) issues.add(toIssue(f, base, null));
                return AuditResult.auditResult(issues);
            } catch (RuntimeException e) {
                app.logError("Active check failed for " + base.request().url() + ": " + e);
                return AuditResult.auditResult(List.of());
            }
        }

        @Override
        public ConsolidationAction consolidateIssues(AuditIssue existing, AuditIssue newIssue) {
            return consolidate(existing, newIssue);
        }
    }

    /** HttpSender backed by Burp's Http, targeting the base request's service. */
    private final class Sender implements HttpSender {
        private final HttpRequest base;
        private final Http http;

        Sender(HttpRequest base, Http http) {
            this.base = base;
            this.http = http;
        }

        @Override
        public Exchange send(String method, String pathAndQuery, List<Header> headers, byte[] body) {
            ByteArrayOutputStream raw = new ByteArrayOutputStream();
            raw.writeBytes((method + " " + pathAndQuery + " HTTP/1.1\r\n").getBytes(StandardCharsets.ISO_8859_1));
            boolean host = false;
            for (Header h : headers) {
                if (h.name().equalsIgnoreCase("Content-Length")) continue;
                if (h.name().equalsIgnoreCase("Host")) host = true;
                raw.writeBytes((h.name() + ": " + h.value() + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
            }
            if (!host) raw.writeBytes(("Host: " + hostHeader(base.httpService()) + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
            raw.writeBytes("\r\n".getBytes(StandardCharsets.ISO_8859_1));
            HttpRequest req = HttpRequest.httpRequest(base.httpService(), ByteArray.byteArray(raw.toByteArray()))
                    .withBody(ByteArray.byteArray(body == null ? new byte[0] : body));
            return sendRaw(req);
        }

        @Override
        public Exchange send(InsertionPoint point, String payload) {
            return sendRaw(apply(base, point, payload));
        }

        Exchange sendRaw(HttpRequest req) {
            HttpRequestResponse rr = http.sendRequest(req);
            MessageContext m = Montoya.fromHttp(rr, MessageKind.REQUEST, maxBytes());
            return m == null ? null : new Exchange(m, rr);
        }
    }

    private static String hostHeader(HttpService s) {
        boolean dflt = (s.secure() && s.port() == 443) || (!s.secure() && s.port() == 80);
        return dflt ? s.host() : s.host() + ":" + s.port();
    }

    /** Applies an insertion point edit to a request. */
    static HttpRequest apply(HttpRequest base, InsertionPoint ip, String payload) {
        byte[] content = ip.render().apply(payload);
        return switch (ip.part()) {
            case BODY -> base.withBody(ByteArray.byteArray(content));
            case QUERY -> {
                String q = new String(content, StandardCharsets.ISO_8859_1);
                yield base.withPath(base.pathWithoutQuery() + (q.isEmpty() ? "" : "?" + q));
            }
            case HEADER -> {
                String v = new String(content, StandardCharsets.UTF_8);
                yield base.hasHeader(ip.headerName()) ? base.withUpdatedHeader(ip.headerName(), v) : base.withAddedHeader(ip.headerName(), v);
            }
        };
    }

    // ---------------------------------------------------------------- insertion points

    private List<AuditInsertionPoint> insertionPoints(HttpRequestResponse rr) {
        if (!app.settings().scanInsertionPoints) return List.of();
        try {
            MessageContext req = Montoya.fromHttp(rr, MessageKind.REQUEST, maxBytes());
            if (req == null || req.truncated()) return List.of();
            List<AuditInsertionPoint> out = new ArrayList<>();
            HttpRequest base = rr.request();
            for (InsertionPoint ip : app.scanEngine().insertionPoints(req)) {
                out.add(new AuditInsertionPoint() {
                    @Override public String name() { return ip.name(); }
                    @Override public String baseValue() { return ip.baseValue(); }
                    @Override public HttpRequest buildHttpRequestWithPayload(ByteArray payload) {
                        return apply(base, ip, new String(payload.getBytes(), StandardCharsets.UTF_8));
                    }
                    @Override public List<Range> issueHighlights(ByteArray payload) { return List.of(); }
                    @Override public AuditInsertionPointType type() { return AuditInsertionPointType.EXTENSION_PROVIDED; }
                });
            }
            return out;
        } catch (RuntimeException e) {
            app.logError("Insertion point provider failed for " + rr.request().url() + ": " + e);
            return List.of();
        }
    }

    // ---------------------------------------------------------------- WebSockets

    /** Runs passive checks on proxied WebSocket messages (off the proxy thread) and adds issues to the site map. */
    private final class WebSocketScanner implements ProxyMessageHandler {
        private final HttpRequest upgrade;

        WebSocketScanner(HttpRequest upgrade) {
            this.upgrade = upgrade;
        }

        private void submit(byte[] payload, Direction direction) {
            if (!app.settings().scanWebSockets || !app.settings().scanPassive) return;
            wsExecutor.execute(() -> {
                try {
                    MessageContext m = Montoya.fromWebSocket(upgrade, direction == null ? null : direction.name(), payload, maxBytes());
                    for (Finding f : app.scanEngine().passive(m, true)) {
                        String key = f.title() + "\u0000" + issueBaseUrl(f, upgrade);
                        if (reportedWebSocketIssues.size() > MAX_WS_ISSUE_KEYS || !reportedWebSocketIssues.add(key)) continue;
                        HttpRequestResponse rr = HttpRequestResponse.httpRequestResponse(upgrade, null);
                        String excerpt = Codecs.isMostlyText(payload) ? Codecs.truncate(Codecs.utf8(payload), 2000) : Codecs.hexPreview(payload, 256);
                        api.siteMap().add(toIssue(f, rr, "<br><br>WebSocket message (" + (direction == null ? "?" : direction.name()) + "):<br><pre>"
                                + Finding.esc(excerpt) + "</pre>"));
                    }
                } catch (RuntimeException e) {
                    app.logError("WebSocket passive scan failed: " + e);
                }
            });
        }

        @Override
        public TextMessageReceivedAction handleTextMessageReceived(InterceptedTextMessage message) {
            submit(message.payload().getBytes(StandardCharsets.UTF_8), message.direction());
            return TextMessageReceivedAction.continueWith(message);
        }

        @Override
        public TextMessageToBeSentAction handleTextMessageToBeSent(InterceptedTextMessage message) {
            return TextMessageToBeSentAction.continueWith(message);
        }

        @Override
        public BinaryMessageReceivedAction handleBinaryMessageReceived(InterceptedBinaryMessage message) {
            submit(message.payload().getBytes(), message.direction());
            return BinaryMessageReceivedAction.continueWith(message);
        }

        @Override
        public BinaryMessageToBeSentAction handleBinaryMessageToBeSent(InterceptedBinaryMessage message) {
            return BinaryMessageToBeSentAction.continueWith(message);
        }
    }

    // ---------------------------------------------------------------- Finding → AuditIssue

    private static String issueBaseUrl(Finding f, HttpRequest req) {
        HttpService s = req.httpService();
        String origin = (s.secure() ? "https://" : "http://") + hostHeader(s);
        if (f.scope() == Finding.Scope.HOST) return origin + "/";
        String path = req.pathWithoutQuery();
        return origin + (path == null || path.isEmpty() ? "/" : path);
    }

    private AuditIssue toIssue(Finding f, HttpRequestResponse base, String extraDetail) {
        List<HttpRequestResponse> evidence = new ArrayList<>();
        if (f.exchanges().isEmpty()) {
            evidence.add(withMarkers(base, f.evidence()));
        } else {
            for (Exchange x : f.exchanges()) {
                if (x.handle() instanceof HttpRequestResponse rr) evidence.add(withMarkers(rr, f.evidence()));
            }
            if (evidence.isEmpty()) evidence.add(base);
        }
        String detail = f.detail() + (extraDetail == null ? "" : extraDetail);
        return AuditIssue.auditIssue(f.title(), detail, f.remediation(), issueBaseUrl(f, base.request()),
                severity(f), confidence(f), f.background(), null, severity(f), evidence);
    }

    private static AuditIssueSeverity severity(Finding f) {
        return switch (f.severity()) {
            case HIGH -> AuditIssueSeverity.HIGH;
            case MEDIUM -> AuditIssueSeverity.MEDIUM;
            case LOW -> AuditIssueSeverity.LOW;
            case INFORMATION -> AuditIssueSeverity.INFORMATION;
        };
    }

    private static AuditIssueConfidence confidence(Finding f) {
        return switch (f.confidence()) {
            case CERTAIN -> AuditIssueConfidence.CERTAIN;
            case FIRM -> AuditIssueConfidence.FIRM;
            case TENTATIVE -> AuditIssueConfidence.TENTATIVE;
        };
    }

    private static HttpRequestResponse withMarkers(HttpRequestResponse rr, List<Evidence> evidence) {
        if (evidence.isEmpty() || rr == null) return rr;
        List<Marker> reqMarkers = new ArrayList<>();
        List<Marker> respMarkers = new ArrayList<>();
        byte[] req = rr.request() == null ? new byte[0] : rr.request().toByteArray().getBytes();
        byte[] resp = rr.response() == null ? new byte[0] : rr.response().toByteArray().getBytes();
        for (Evidence e : evidence) {
            boolean inResponse = e.where() == MessageKind.RESPONSE;
            mark(inResponse ? resp : req, e.text(), inResponse ? respMarkers : reqMarkers);
        }
        HttpRequestResponse out = rr;
        if (!reqMarkers.isEmpty()) out = out.withRequestMarkers(sorted(reqMarkers));
        if (!respMarkers.isEmpty()) out = out.withResponseMarkers(sorted(respMarkers));
        return out;
    }

    private static List<Marker> sorted(List<Marker> m) {
        m.sort((a, b) -> Integer.compare(a.range().startIndexInclusive(), b.range().startIndexInclusive()));
        List<Marker> out = new ArrayList<>();
        int lastEnd = -1;
        for (Marker x : m) {
            if (x.range().startIndexInclusive() >= lastEnd) {
                out.add(x);
                lastEnd = x.range().endIndexExclusive();
            }
        }
        return out;
    }

    /** Marks occurrences of the text (as UTF-8, then URL-encoded form) in the raw message. */
    private static void mark(byte[] hay, String text, List<Marker> out) {
        for (String variant : new String[]{text, java.net.URLEncoder.encode(text, StandardCharsets.UTF_8)}) {
            byte[] needle = variant.getBytes(StandardCharsets.UTF_8);
            if (needle.length == 0) continue;
            int from = 0, found = 0;
            while (out.size() < MAX_MARKERS && (from = indexOf(hay, needle, from)) >= 0) {
                out.add(Marker.marker(from, from + needle.length));
                from += needle.length;
                found++;
            }
            if (found > 0) return;
        }
    }

    static int indexOf(byte[] hay, byte[] needle, int from) {
        outer:
        for (int i = Math.max(0, from); i <= hay.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) if (hay[i + j] != needle[j]) continue outer;
            return i;
        }
        return -1;
    }
}
