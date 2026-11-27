package protocoldecoder.builtin.nextjs;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
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

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scanner support for Next.js: data-exposure checks on page data / RSC payloads, dev-server and error disclosure,
 * the CVE-2025-29927 middleware bypass probe, and insertion points inside Server Action bodies (text/plain JSON and
 * multipart encodeReply fields) and the URL-encoded {@code Next-Router-State-Tree} header.
 */
public final class NextJsScanner implements ProtocolScanner {

    static final String STATE_TREE = "Next-Router-State-Tree";
    private static final int MAX_ITEMS = 25;

    @Override
    public String decoderId() {
        return NextJsDecoder.ID;
    }

    @Override
    public List<PassiveCheck> passiveChecks() {
        return List.of(new SensitiveData(), new RuntimeConfig(), new ServerActions(), new RscErrors(), new MiddlewareSubrequestSeen(), new DevServer());
    }

    @Override
    public List<ActiveCheck> activeChecks() {
        return List.of(new MiddlewareBypass());
    }

    // ================================================================ helpers

    /** Depth-first search for nodes whose name satisfies {@code pred} (bounded). */
    static void findNodes(DecodedNode n, java.util.function.Predicate<DecodedNode> pred, List<DecodedNode> out, int depth) {
        if (n == null || depth > 60 || out.size() >= 200) return;
        if (pred.test(n)) out.add(n);
        for (DecodedNode c : n.children()) findNodes(c, pred, out, depth + 1);
    }

    static List<DecodedNode> findNodes(DecodedNode root, java.util.function.Predicate<DecodedNode> pred) {
        List<DecodedNode> out = new ArrayList<>();
        findNodes(root, pred, out, 0);
        return out;
    }

    private static String lower(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }

    private static String htmlItems(Iterable<String> items) {
        StringBuilder sb = new StringBuilder("<ul>");
        for (String s : items) sb.append("<li><code>").append(Finding.esc(s)).append("</code></li>");
        return sb.append("</ul>").toString();
    }

    private static String responseText(MessageContext m, int cap) {
        byte[] b = Codecs.decodeContent(m.responseBody(), m.responseHeader("Content-Encoding"));
        return new String(b, 0, Math.min(b.length, cap), StandardCharsets.UTF_8);
    }

    // ================================================================ passive: sensitive data

    /** Well-known secret formats and internal URLs, on top of {@link ScanPatterns}. */
    static final Pattern[] EXTRA = {
            Pattern.compile("\\bsk_live_[0-9A-Za-z]{10,}"),
            Pattern.compile("\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b"),
            Pattern.compile("-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
            Pattern.compile("\\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\\+srv)?|redis|amqp)://[^\\s:@/\"']+:[^\\s@/\"']+@[^\\s\"']+"),
            Pattern.compile("\\bxox[baprs]-[0-9A-Za-z-]{10,}"),
            Pattern.compile("\\bgh[pousr]_[0-9A-Za-z]{36}\\b"),
            Pattern.compile("(?i)\\bhttps?://(?:localhost|127\\.\\d+\\.\\d+\\.\\d+|10\\.\\d+\\.\\d+\\.\\d+|192\\.168\\.\\d+\\.\\d+|172\\.(?:1[6-9]|2\\d|3[01])\\.\\d+\\.\\d+|[a-z0-9.-]+\\.(?:internal|local|corp|lan|intranet))(?::\\d+)?(?:/[^\\s\"'<>]*)?")};
    static final String[] EXTRA_KINDS = {"Stripe secret key", "AWS access key id", "private key", "database connection string with credentials",
            "Slack token", "GitHub token", "internal URL"};

    /** Field names that ScanPatterns flags but are routinely sent to the browser on purpose. */
    private static final Pattern BENIGN_NAME = Pattern.compile("(?i)(csrf|xsrf|nonce|tokenizer|token_?type|tokens?_?(count|length|limit)|expires|expiry|placeholder|label)");
    private static final Set<String> SKIP_SUBTREES = Set.of("Overview", "Client modules (I rows)", "Server references (Server Action IDs)",
            "Next.js request headers", "Next.js response headers", "Interesting keys (possible secrets / PII / authz data)", "Errors (E rows)",
            // URL query echoed back, and runtimeConfig (reported by nextjs.public-runtime-config)
            "query — route params / query string", "runtimeConfig — publicRuntimeConfig (exposed to every visitor)");

    /** Sensitive-looking values in a Next.js data tree (page data, Flight rows), with noise filtered out. */
    static List<ScanPatterns.Sensitive> sensitive(DecodedNode root) {
        List<ScanPatterns.Sensitive> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        scanTree(root, "", out, seen, 0);
        return out;
    }

    private static void scanTree(DecodedNode n, String path, List<ScanPatterns.Sensitive> out, Set<String> seen, int depth) {
        if (out.size() >= MAX_ITEMS || depth > 60) return;
        if (SKIP_SUBTREES.contains(n.name())) return;
        String p = path.isEmpty() ? n.name() : path + " › " + n.name();
        if (n.isLeaf()) {
            // ScanPatterns on a single leaf (wrap so it reports this node's own path)
            for (ScanPatterns.Sensitive s : ScanPatterns.sensitiveValues(n, 5)) keep(out, seen, s.kind(), p, s.value(), n.name());
            String v = n.value();
            if (v != null && n.type() != DecodedNode.Type.NOTE) {
                String val = v.length() > 100_000 ? v.substring(0, 100_000) : v;
                for (int i = 0; i < EXTRA.length; i++) {
                    Matcher m = EXTRA[i].matcher(val);
                    if (m.find()) keep(out, seen, EXTRA_KINDS[i], p, m.group(), n.name());
                }
            }
            return;
        }
        for (DecodedNode c : n.children()) scanTree(c, p, out, seen, depth + 1);
    }

    private static void keep(List<ScanPatterns.Sensitive> out, Set<String> seen, String kind, String path, String value, String name) {
        if (out.size() >= MAX_ITEMS) return;
        if (kind.equals("sensitive field name")) {
            if (BENIGN_NAME.matcher(name).find()) return;
            String v = value.strip();
            if (v.startsWith("$") || v.equals("true") || v.equals("false") || v.equals("undefined")) return; // Flight references / flags
        }
        // e-mail addresses inside rendered prose (React children, text rows) are normally intended page content
        if (kind.equals("email address") && !lower(name).contains("mail")) return;
        String v = value.length() > 200 ? value.substring(0, 200) + "…" : value;
        if (seen.add(kind + "\u0000" + v)) out.add(new ScanPatterns.Sensitive(kind, path, v));
    }

    /** Sensitive values in __NEXT_DATA__ props, /_next/data JSON and RSC Flight payloads. */
    static final class SensitiveData implements PassiveCheck {
        @Override public String id() { return "nextjs.sensitive-data"; }
        @Override public String name() { return "Sensitive data in page data / RSC payloads"; }
        @Override public String description() {
            return "Secrets, tokens, credentials, e-mail fields and internal URLs in __NEXT_DATA__, /_next/data JSON or RSC Flight payloads sent to the browser";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || decoded == null) return List.of();
            List<ScanPatterns.Sensitive> hits = sensitive(decoded.root());
            if (hits.isEmpty()) return List.of();
            String where = decoded.root().name();
            boolean page = where.contains("page") || where.contains("data");
            Finding f = Finding.of(id(), "Sensitive data in Next.js " + (page ? "page data" : "RSC payload"))
                    .severity(Severity.LOW).confidence(Confidence.TENTATIVE)
                    .detail("The " + Finding.esc(where) + " sent to the browser contains sensitive-looking values:" + ScanPatterns.htmlList(hits)
                            + "Review whether these need to reach the client.")
                    .background("Next.js serialises everything returned from getServerSideProps/getStaticProps (into <code>__NEXT_DATA__</code> or "
                            + "<code>/_next/data/…json</code>) and every prop passed from a Server Component to a Client Component (into the RSC Flight "
                            + "payload) into the response, whether or not the page displays it. Over-fetched objects (whole user records, config objects, "
                            + "API responses) commonly leak secrets, tokens and personal data this way.")
                    .remediation("Return only the fields the page needs from data-fetching functions and Server Components; keep secrets in server-only "
                            + "modules (<code>import 'server-only'</code>) and use React's taint APIs (<code>experimental_taintObjectReference</code>) for sensitive objects.");
            for (ScanPatterns.Sensitive s : hits) f.responseEvidence(s.value());
            return List.of(f);
        }
    }

    // ================================================================ passive: runtimeConfig

    private static final Pattern SECRETISH_KEY = Pattern.compile("(?i)(secret|token|passw(or)?d|pwd|private|api[_-]?key|access[_-]?key|credential|"
            + "database|db[_-]?(url|uri|host|user|pass)|dsn|connection[_-]?string|auth[_-]?key|client[_-]?secret|signing|webhook)");

    static final class RuntimeConfig implements PassiveCheck {
        @Override public String id() { return "nextjs.public-runtime-config"; }
        @Override public String name() { return "publicRuntimeConfig exposed"; }
        @Override public String description() {
            return "__NEXT_DATA__.runtimeConfig (publicRuntimeConfig) sent to every visitor; Low when it holds secret-looking keys, else Information";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || decoded == null || decoded.root().get("__NEXT_DATA__ (Pages Router)") == null) return List.of();
            JsonElement data = NextJsDecoder.findNextData(responseText(m, 8 * 1024 * 1024), new ArrayList<>());
            if (data == null || !data.isJsonObject()) return List.of();
            JsonElement rc = data.getAsJsonObject().get("runtimeConfig");
            if (rc == null || !rc.isJsonObject() || rc.getAsJsonObject().isEmpty()) return List.of();
            List<String> keys = new ArrayList<>();
            List<String> secret = new ArrayList<>();
            flatten(rc.getAsJsonObject(), "", keys, secret, 0);
            if (keys.isEmpty()) return List.of();
            boolean bad = !secret.isEmpty();
            Finding f = Finding.of(id(), bad ? "Next.js publicRuntimeConfig exposes secret-looking values" : "Next.js publicRuntimeConfig exposed")
                    .severity(bad ? Severity.LOW : Severity.INFORMATION).confidence(bad ? Confidence.TENTATIVE : Confidence.CERTAIN)
                    .scope(Finding.Scope.HOST)
                    .detail("<code>__NEXT_DATA__.runtimeConfig</code> sends these configuration keys to every visitor:" + htmlItems(keys)
                            + (bad ? "Keys that look like secrets:" + htmlItems(secret) : ""))
                    .background("<code>publicRuntimeConfig</code> in next.config.js is embedded into every Pages Router page. It is meant for public "
                            + "values only; secrets placed there (or copied from <code>serverRuntimeConfig</code>/environment variables by mistake) are disclosed.")
                    .remediation("Move secrets to <code>serverRuntimeConfig</code> or server-only environment variables and rotate any exposed credentials.");
            for (String s : secret) f.responseEvidence(s.substring(0, s.indexOf(" = ")));
            return List.of(f);
        }

        private static void flatten(JsonObject o, String prefix, List<String> keys, List<String> secret, int depth) {
            if (depth > 10) return;
            for (Map.Entry<String, JsonElement> en : o.entrySet()) {
                if (keys.size() >= 100) return;
                String k = prefix.isEmpty() ? en.getKey() : prefix + "." + en.getKey();
                JsonElement v = en.getValue();
                if (v.isJsonObject()) {
                    flatten(v.getAsJsonObject(), k, keys, secret, depth + 1);
                    continue;
                }
                String shown = v.isJsonPrimitive() ? v.getAsString() : v.toString();
                String line = k + " = " + Codecs.truncate(shown, 120);
                keys.add(line);
                boolean empty = v.isJsonNull() || shown.isEmpty() || (v.isJsonPrimitive() && v.getAsJsonPrimitive().isBoolean());
                if (!empty && SECRETISH_KEY.matcher(en.getKey()).find() && !lower(en.getKey()).contains("public")) secret.add(line);
            }
        }
    }

    // ================================================================ passive: Server Action IDs

    static final class ServerActions implements PassiveCheck {
        @Override public String id() { return "nextjs.server-actions"; }
        @Override public String name() { return "Server Action IDs exposed"; }
        @Override public String description() {
            return "Server Action IDs found in RSC Flight payloads: each is a directly callable POST endpoint (attack surface inventory)";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || decoded == null) return List.of();
            Set<String> ids = new LinkedHashSet<>();
            for (DecodedNode n : findNodes(decoded.root(), x -> x.name().equals("Server references (Server Action IDs)"))) {
                for (DecodedNode c : n.children()) if (c.value() != null && ids.size() < 100) ids.add(c.value());
            }
            if (ids.isEmpty()) return List.of();
            Finding f = Finding.of(id(), "Next.js Server Action IDs exposed")
                    .severity(Severity.INFORMATION).confidence(Confidence.CERTAIN).scope(Finding.Scope.HOST)
                    .detail("The RSC payload references " + ids.size() + " Server Action" + (ids.size() == 1 ? "" : "s") + ":" + htmlItems(ids)
                            + "Each can be invoked with <code>POST</code> to any page path and the header <code>Next-Action: &lt;id&gt;</code>; "
                            + "arguments are a JSON array (text/plain) or multipart form data.")
                    .background("Server Actions are public HTTP endpoints. Next.js only checks the Origin header; it does not authenticate or "
                            + "authorise calls, so every action must check the session and validate its arguments itself. Actions bound to a form "
                            + "can be called with arguments the UI would never send.")
                    .remediation("Verify authentication/authorisation and validate all arguments inside every Server Action (e.g. with zod); "
                            + "do not rely on the UI hiding an action.");
            for (String id : ids) f.responseEvidence(id);
            return List.of(f);
        }
    }

    // ================================================================ passive: RSC errors

    static final class RscErrors implements PassiveCheck {
        @Override public String id() { return "nextjs.rsc-error"; }
        @Override public String name() { return "Server render errors"; }
        @Override public String description() {
            return "RSC Flight error rows (digest/message/stack) and __NEXT_DATA__.err objects; Low when a stack trace or exception detail is included";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || decoded == null) return List.of();
            List<String> items = new ArrayList<>();
            String stack = null;
            for (DecodedNode errs : findNodes(decoded.root(), x -> x.name().equals("Errors (E rows)") || x.name().equals("err — server render error"))) {
                List<DecodedNode> entries = errs.name().startsWith("err") ? List.of(errs) : errs.children();
                for (DecodedNode e : entries) {
                    if (items.size() >= MAX_ITEMS) break;
                    StringBuilder sb = new StringBuilder();
                    for (DecodedNode c : e.children()) {
                        if (c.value() == null) continue;
                        if (sb.length() > 0) sb.append(", ");
                        sb.append(c.name().replace(" — server error log correlation ID", "")).append(": ").append(Codecs.truncate(c.value(), 300));
                        if (stack != null || lower(c.name()).startsWith("digest")) continue;
                        if (lower(c.name()).startsWith("stack") && !c.value().isBlank()) stack = Codecs.truncate(c.value(), 300);
                        else stack = ScanPatterns.exceptionEvidence(c.value().replace("\\n", "\n"));
                    }
                    if (sb.length() > 0) items.add(sb.toString());
                }
            }
            if (items.isEmpty()) return List.of();
            boolean low = stack != null;
            Finding f = Finding.of(id(), low ? "Next.js server error with stack trace" : "Next.js server render error")
                    .severity(low ? Severity.LOW : Severity.INFORMATION).confidence(Confidence.FIRM)
                    .detail("The response carries server-side error information:" + htmlItems(items)
                            + (low ? "It includes stack/exception details: <code>" + Finding.esc(stack) + "</code>" : ""))
                    .background("In production Next.js replaces Server Component errors with a generic message and a <code>digest</code> that "
                            + "correlates with server logs. Full messages and stack traces are only sent by the development server or when errors "
                            + "are serialised by application code, and reveal file paths, code structure and data. Errors triggered by tampered "
                            + "input also point at missing validation.")
                    .remediation("Run production builds (<code>next build &amp;&amp; next start</code>), handle errors in Server Components and "
                            + "don't return raw error objects from getServerSideProps / Server Actions.");
            if (stack != null) f.responseEvidence(stack);
            return List.of(f);
        }
    }

    // ================================================================ passive: x-middleware-subrequest in a request

    static final class MiddlewareSubrequestSeen implements PassiveCheck {
        @Override public String id() { return "nextjs.middleware-subrequest-header"; }
        @Override public String name() { return "x-middleware-subrequest sent by a client"; }
        @Override public String description() {
            return "A request carries the internal x-middleware-subrequest header (CVE-2025-29927 bypass marker)";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isRequest()) return List.of();
            String v = m.requestHeader("x-middleware-subrequest");
            if (v == null) return List.of();
            return List.of(Finding.of(id(), "Next.js x-middleware-subrequest header in request")
                    .severity(Severity.INFORMATION).confidence(Confidence.CERTAIN)
                    .detail("The request sends <code>x-middleware-subrequest: " + Finding.esc(Codecs.truncate(v, 300)) + "</code>. "
                            + (m.hasResponse() && m.statusCode() != null ? "The server answered HTTP " + m.statusCode() + ". " : "")
                            + "Browsers never send this header; it is internal to Next.js.")
                    .background("Next.js used <code>x-middleware-subrequest</code> to stop middleware recursing. On versions before 12.3.5, 13.5.9, "
                            + "14.2.25 and 15.2.3 a client-supplied value makes the server skip middleware entirely (CVE-2025-29927), bypassing "
                            + "authentication or rewrites implemented there. Compare the response with the same request without the header.")
                    .remediation("Upgrade Next.js, and strip <code>x-middleware-subrequest</code> at the reverse proxy / CDN.")
                    .requestEvidence("x-middleware-subrequest"));
        }
    }

    // ================================================================ passive: dev server

    private static final Pattern DEV_BUILD = Pattern.compile("/_next/static/development/_(?:buildManifest|ssgManifest)\\.js|\"buildId\"\\s*:\\s*\"development\"");

    static final class DevServer implements PassiveCheck {
        @Override public String id() { return "nextjs.dev-server"; }
        @Override public String name() { return "Development server exposed"; }
        @Override public String description() {
            return "next dev markers: HMR WebSocket (/_next/webpack-hmr, turbopack-hmr), buildId \"development\", RSC debug rows";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            String evidence = null;
            String what = null;
            if (m.isWebSocket()) {
                String p = m.path();
                if (p.contains("/_next/webpack-hmr") || p.contains("/_next/turbopack-hmr")) {
                    evidence = p.contains("webpack") ? "/_next/webpack-hmr" : "/_next/turbopack-hmr";
                    what = "a hot-module-reload WebSocket at <code>" + Finding.esc(p) + "</code>";
                }
            } else if (m.isResponse()) {
                if (decoded != null) {
                    if (!findNodes(decoded.root(), x -> x.name().startsWith("Build ID") && "development".equals(x.value())).isEmpty()) {
                        evidence = "development";
                        what = "build ID <code>development</code> (pages served by <code>next dev</code>)";
                    } else {
                        List<DecodedNode> dbg = findNodes(decoded.root(), x -> x.name().equals("debug rows") && x.value() != null && !x.value().equals("0"));
                        if (!dbg.isEmpty()) what = dbg.get(0).value() + " React debug (D) rows in the RSC payload, which only the development server emits";
                    }
                }
                if (what == null && lower(m.responseHeader("Content-Type")).contains("html")) {
                    Matcher dm = DEV_BUILD.matcher(responseText(m, 2 * 1024 * 1024));
                    if (dm.find()) {
                        evidence = dm.group();
                        what = "development build assets (<code>" + Finding.esc(dm.group()) + "</code>)";
                    }
                }
            }
            if (what == null) return List.of();
            Finding f = Finding.of(id(), "Next.js development server exposed")
                    .severity(Severity.MEDIUM).confidence(Confidence.FIRM).scope(Finding.Scope.HOST)
                    .detail("The application appears to be served by the Next.js development server: " + what + ".")
                    .background("<code>next dev</code> is not meant to be exposed: it returns full error overlays with source code and stack traces, "
                            + "serves source maps and unminified code, exposes the HMR channel and internal development endpoints "
                            + "(e.g. <code>/__nextjs_original-stack-frame</code>), and has had its own vulnerabilities (cross-origin access to dev "
                            + "resources, CVE-2025-48068). It is also far less robust under load.")
                    .remediation("Deploy production builds (<code>next build</code> + <code>next start</code> or a platform adapter); never expose "
                            + "<code>next dev</code> to untrusted networks.");
            if (evidence != null) f.responseEvidence(evidence);
            return List.of(f);
        }
    }

    // ================================================================ active: CVE-2025-29927

    /** Values per the public advisory: Next ≥ 13.2 (recursion depth 5, root and src/ middleware), ≤ 12.1 (pages/_middleware). */
    static final String[] BYPASS_VALUES = {
            "middleware:middleware:middleware:middleware:middleware",
            "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware",
            "pages/_middleware"};
    static final String CONTROL_VALUE = "protocol-decoder-control";
    private static final Pattern LOGIN_LIKE = Pattern.compile("(?i)(log-?in|sign-?in|signon|auth|sso|oauth|session|account|unauthori[sz]ed|forbidden|denied|/40[13]\\b)");

    static final class MiddlewareBypass implements ActiveCheck {
        @Override public String id() { return "nextjs.middleware-bypass"; }
        @Override public String name() { return "Middleware authorization bypass (CVE-2025-29927)"; }
        @Override public String description() {
            return "For 401/403 responses or redirects to a login-like path, resends the request with x-middleware-subrequest "
                    + "(middleware x5, src/middleware x5, pages/_middleware) and reports if it flips to 2xx with different content. "
                    + "At most 3 requests (a control request with a non-matching value confirms a hit when budget remains)";
        }
        @Override public Scope scope() { return Scope.PER_REQUEST; }

        @Override
        public List<Finding> run(ActiveContext ctx) {
            MessageContext base = ctx.base();
            MessageContext resp = ctx.baseResponse();
            if (resp == null || resp.statusCode() == null || base.requestHeader("x-middleware-subrequest") != null) return List.of();
            int status = resp.statusCode();
            String location = resp.responseHeader("Location");
            boolean redirect = status >= 301 && status <= 308 && status != 304 && location != null && LOGIN_LIKE.matcher(location).find();
            if (!(redirect || status == 401 || status == 403)) return List.of();
            String baseBody = responseText(resp, 1024 * 1024);
            String target = base.path() + (base.query().isEmpty() ? "" : "?" + base.query());
            int budget = 3;
            for (String value : BYPASS_VALUES) {
                if (budget <= 0) break;
                Exchange x = send(ctx, base, target, value);
                budget--;
                if (!flipped(x, baseBody)) continue;
                boolean confirmed = false;
                Exchange control = null;
                if (budget > 0) {
                    control = send(ctx, base, target, CONTROL_VALUE);
                    budget--;
                    if (flipped(control, baseBody)) return List.of(); // the page isn't protected (or state changed): not a bypass
                    confirmed = true;
                }
                Finding f = Finding.of(id(), "Next.js middleware bypass via x-middleware-subrequest (CVE-2025-29927)")
                        .severity(Severity.HIGH).confidence(confirmed ? Confidence.FIRM : Confidence.TENTATIVE)
                        .detail("The original request returned <b>HTTP " + status + "</b>" + (redirect ? " redirecting to <code>" + Finding.esc(location) + "</code>" : "")
                                + ". Re-sending it with <code>x-middleware-subrequest: " + Finding.esc(value) + "</code> returned <b>HTTP " + x.status()
                                + "</b> with different content (" + x.responseText().length() + " characters vs " + baseBody.length() + ")."
                                + (confirmed ? " A control request with a non-matching header value was still blocked (HTTP " + control.status() + ")." : "")
                                + " The middleware that enforces access control was skipped.")
                        .background("Next.js versions before 12.3.5, 13.5.9, 14.2.25 and 15.2.3 trust the internal <code>x-middleware-subrequest</code> "
                                + "header: when it names the middleware module (repeated up to the recursion limit on 13.2+), the server skips "
                                + "middleware and serves the route directly. Applications that implement authentication or authorisation only in "
                                + "middleware are fully bypassed.")
                        .remediation("Upgrade Next.js to a patched release. Until then, strip <code>x-middleware-subrequest</code> from incoming "
                                + "requests at the proxy/CDN, and enforce authorisation in the route/page or data layer, not only in middleware.")
                        .requestEvidence("x-middleware-subrequest: " + value)
                        .exchange(x);
                if (control != null) f.exchange(control);
                return List.of(f);
            }
            return List.of();
        }

        private static Exchange send(ActiveContext ctx, MessageContext base, String target, String value) {
            List<Header> headers = new ArrayList<>();
            for (Header h : base.requestHeaders()) if (!h.name().equalsIgnoreCase("x-middleware-subrequest")) headers.add(h);
            headers.add(new Header("x-middleware-subrequest", value));
            return ctx.http().send(base.method(), target, headers, base.requestBody());
        }

        static boolean flipped(Exchange x, String baseBody) {
            if (x == null || !x.hasResponse()) return false;
            int s = x.status();
            if (s < 200 || s >= 300) return false;
            if (x.message().responseHeader("Location") != null) return false;
            String body = x.responseText();
            if (body.isBlank()) return false;
            return different(body, baseBody);
        }

        /** True unless the two bodies are near-identical (same start, length within 5%). */
        static boolean different(String a, String b) {
            if (b == null || b.isBlank()) return true;
            if (a.equals(b)) return false;
            int la = a.length(), lb = b.length();
            boolean similarLength = Math.abs(la - lb) <= Math.max(la, lb) * 0.05;
            boolean sameStart = a.regionMatches(0, b, 0, Math.min(200, Math.min(la, lb)));
            return !(similarLength && sameStart);
        }
    }

    // ================================================================ insertion points

    @Override
    public List<InsertionPoint> insertionPoints(MessageContext request, DecodeResult decoded) {
        List<InsertionPoint> out = new ArrayList<>();
        String enc = request.requestHeader("Content-Encoding");
        boolean identity = enc == null || enc.isBlank() || lower(enc).contains("identity");
        String actionId = request.requestHeader("Next-Action");
        String ct = lower(request.requestHeader("Content-Type"));
        String label = actionId == null ? "Server Action" : "Server Action " + shortId(actionId.strip());
        if (identity && "POST".equalsIgnoreCase(request.method()) && request.requestBody().length > 0) {
            if (ct.contains("multipart/form-data")) {
                multipartPoints(request, label, out);
            } else if (actionId != null && !ct.contains("json") && !ct.contains("x-www-form-urlencoded")) {
                JsonElement json = JsonTree.parseStrict(request.requestBodyText());
                if (json != null && (json.isJsonArray() || json.isJsonObject())) {
                    for (InsertionPoints.JsonLeaf leaf : InsertionPoints.jsonLeaves(json)) {
                        if (skipLeaf(leaf)) continue;
                        out.add(InsertionPoint.body("Next.js: " + label + " args " + leaf.path(), InsertionPoints.text(leaf.value()),
                                payload -> leaf.replace().apply(replyString(payload)).getBytes(StandardCharsets.UTF_8)));
                    }
                }
            }
        }
        String tree = request.requestHeader(STATE_TREE);
        JsonElement t = RouterState.parse(tree);
        if (t != null && (t.isJsonArray() || t.isJsonObject())) {
            for (InsertionPoints.JsonLeaf leaf : InsertionPoints.jsonLeaves(t)) {
                if (out.size() >= InsertionPoints.MAX_POINTS) break;
                JsonElement v = leaf.value();
                if (!v.isJsonPrimitive() || !v.getAsJsonPrimitive().isString()) continue; // booleans/refresh markers: structural
                String s = v.getAsString();
                if (s.isEmpty() || s.startsWith("__PAGE__") || s.startsWith("__DEFAULT__") || s.equals("children") || s.equals("refetch")) continue;
                out.add(InsertionPoint.header("Next.js: " + STATE_TREE + " " + leaf.path(), STATE_TREE, s,
                        payload -> encodeUriComponent(leaf.replace().apply(payload)).getBytes(StandardCharsets.UTF_8)));
            }
        }
        return out;
    }

    private static String shortId(String id) {
        return id.length() > 12 ? id.substring(0, 12) + "…" : id;
    }

    /** React's encodeReply escapes strings that begin with '$' as "$$…" so they aren't read as references. */
    static String replyString(String payload) {
        return payload.startsWith("$") ? "$" + payload : payload;
    }

    /** Leaves that are Flight references ($K1, $@2, $undefined, $D…, $T…) are structural, not data. */
    private static boolean skipLeaf(InsertionPoints.JsonLeaf leaf) {
        JsonElement v = leaf.value();
        if (!v.isJsonPrimitive() || !v.getAsJsonPrimitive().isString()) return false;
        String s = v.getAsString();
        return s.startsWith("$") && !s.startsWith("$$");
    }

    /** JavaScript encodeURIComponent, which the App Router uses for Next-Router-State-Tree. */
    static String encodeUriComponent(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20").replace("%21", "!").replace("%27", "'")
                .replace("%28", "(").replace("%29", ")").replace("%7E", "~");
    }

    // ---- multipart

    /** A multipart part with the byte offsets of its value inside the body. */
    record PartSpan(String name, String filename, int valueStart, int valueEnd) {
    }

    /** Splits a multipart body (latin-1 view) into parts with value offsets; null if it isn't multipart. */
    static List<PartSpan> spans(byte[] body, String contentType) {
        String b = Multipart.boundary(contentType, body);
        if (b == null || b.isEmpty()) return null;
        String s = Codecs.latin1String(body);
        String delim = "--" + b;
        int i = s.indexOf(delim);
        if (i < 0) return null;
        List<PartSpan> out = new ArrayList<>();
        Pattern name = Pattern.compile("(?i)\\bname=\"([^\"]*)\"");
        Pattern filename = Pattern.compile("(?i)\\bfilename=\"([^\"]*)\"");
        while (i >= 0 && out.size() < Multipart.MAX_PARTS) {
            int p = i + delim.length();
            if (s.startsWith("--", p)) break;
            if (s.startsWith("\r\n", p)) p += 2;
            else if (s.startsWith("\n", p)) p += 1;
            int hdrEnd = s.indexOf("\r\n\r\n", p);
            int bodyStart;
            if (hdrEnd >= 0) {
                bodyStart = hdrEnd + 4;
            } else {
                hdrEnd = s.indexOf("\n\n", p);
                if (hdrEnd < 0) break;
                bodyStart = hdrEnd + 2;
            }
            String headers = s.substring(p, hdrEnd);
            int next = s.indexOf(delim, bodyStart);
            if (next < 0) break; // unterminated: don't guess
            int dataEnd = next;
            if (dataEnd >= 2 && s.startsWith("\r\n", dataEnd - 2) && dataEnd - 2 >= bodyStart) dataEnd -= 2;
            else if (dataEnd >= 1 && s.charAt(dataEnd - 1) == '\n' && dataEnd - 1 >= bodyStart) dataEnd -= 1;
            String n = null, fn = null;
            for (String line : headers.split("\r?\n")) {
                if (!line.toLowerCase(Locale.ROOT).startsWith("content-disposition:")) continue;
                Matcher nm = name.matcher(line);
                if (nm.find()) n = new String(Codecs.latin1Bytes(nm.group(1)), StandardCharsets.UTF_8);
                Matcher fm = filename.matcher(line);
                if (fm.find()) fn = fm.group(1);
            }
            out.add(new PartSpan(n == null ? "" : n, fn, bodyStart, dataEnd));
            i = next;
        }
        return out;
    }

    /** Body with the value of one part replaced (boundary and all other bytes kept). */
    static byte[] replacePart(byte[] body, PartSpan span, String newValue) {
        ByteArrayOutputStream o = new ByteArrayOutputStream(body.length + newValue.length() * 3);
        o.write(body, 0, span.valueStart());
        o.writeBytes(newValue.getBytes(StandardCharsets.UTF_8));
        o.write(body, span.valueEnd(), body.length - span.valueEnd());
        return o.toByteArray();
    }

    private static final Pattern BOUND_ARG = Pattern.compile("\\$ACTION_\\d+:[1-9]\\d*");

    private static void multipartPoints(MessageContext request, String label, List<InsertionPoint> out) {
        byte[] body = request.requestBody();
        List<PartSpan> spans = spans(body, request.requestHeader("Content-Type"));
        if (spans == null) return;
        for (PartSpan sp : spans) {
            if (out.size() >= InsertionPoints.MAX_POINTS) return;
            if (sp.filename() != null || sp.name().isEmpty()) continue;
            if (sp.name().startsWith("$ACTION_") && !BOUND_ARG.matcher(sp.name()).matches()) continue; // action id / ref / key: structural
            String value = new String(body, sp.valueStart(), sp.valueEnd() - sp.valueStart(), StandardCharsets.UTF_8);
            JsonElement json = JsonTree.looksLikeJson(value) ? JsonTree.parseStrict(value) : null;
            if (json != null && (json.isJsonArray() || json.isJsonObject())) {
                for (InsertionPoints.JsonLeaf leaf : InsertionPoints.jsonLeaves(json)) {
                    if (out.size() >= InsertionPoints.MAX_POINTS) return;
                    if (skipLeaf(leaf)) continue;
                    out.add(InsertionPoint.body("Next.js: " + label + " field " + sp.name() + " " + leaf.path(), InsertionPoints.text(leaf.value()),
                            payload -> replacePart(body, sp, leaf.replace().apply(replyString(payload)))));
                }
            } else {
                // FormData entries are plain strings ("$K1"-prefixed field names); values are never reference-decoded.
                out.add(InsertionPoint.body("Next.js: " + label + " field " + sp.name(), value, payload -> replacePart(body, sp, payload)));
            }
        }
    }
}
