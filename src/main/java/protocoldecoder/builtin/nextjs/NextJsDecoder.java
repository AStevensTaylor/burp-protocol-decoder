package protocoldecoder.builtin.nextjs;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.Header;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.ProtocolDecoder;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsLiteral;
import protocoldecoder.util.JsonTree;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Next.js: React Server Components (Flight) responses of App Router navigations, Server Action calls and their
 * results, router headers ({@code RSC}, {@code Next-Router-State-Tree}, {@code Next-Url}, {@code x-nextjs-*},
 * {@code x-middleware-*}), Pages Router {@code __NEXT_DATA__} and {@code /_next/data/<buildId>/…json} props, the App
 * Router's inline {@code self.__next_f.push(...)} Flight chunks, and the dev-server HMR WebSocket.
 */
public final class NextJsDecoder implements ProtocolDecoder {

    public static final String ID = "nextjs";

    private static final int HTML_SNIFF = 1024 * 1024;
    private static final int HTML_DECODE = 8 * 1024 * 1024;
    private static final int FLIGHT_DECODE = 16 * 1024 * 1024;
    private static final int MULTIPART_SNIFF = 64 * 1024;
    private static final int MAX_NEXT_F_CHUNKS = 10_000;
    private static final int MAX_INTERESTING = 50;

    private static final Pattern DATA_PATH = Pattern.compile("/_next/data/([^/]+)/(.+)\\.json$");
    private static final Pattern STATIC_BUILD = Pattern.compile("/_next/static/([A-Za-z0-9_\\-]{5,64})/_(?:buildManifest|ssgManifest)\\.js");
    private static final Pattern SENSITIVE = Pattern.compile(
            "(?i)(secret|token|passw(or)?d|pwd|api[_-]?key|apikey|private[_-]?key|credential|auth(?!or)|session|jwt|bearer|cookie|"
                    + "access[_-]?key|signature|ssn|email|phone|aws|stripe|database|db[_-]?(url|uri|host)|connection[_-]?string|"
                    + "internal|is[_-]?admin|admin|debug|role|permission)");

    /** React/HTML prop names that match {@link #SENSITIVE} but are almost always harmless (ARIA role, input autocomplete...). */
    private static final java.util.Set<String> NOISY_PROPS = java.util.Set.of("role", "autoComplete", "aria-roledescription");

    private static final Map<String, String> REQUEST_HEADERS = Map.ofEntries(
            Map.entry("rsc", "RSC — React Server Components request (App Router navigation)"),
            Map.entry("next-action", "Next-Action — Server Action ID"),
            Map.entry("next-router-prefetch", "Next-Router-Prefetch — prefetch request"),
            Map.entry("next-router-segment-prefetch", "Next-Router-Segment-Prefetch — segment prefetch"),
            Map.entry("next-url", "Next-Url — current URL (intercepting routes)"),
            Map.entry("next-hmr-refresh", "Next-HMR-Refresh — dev server refresh"),
            Map.entry("next-test-fetch-priority", "Next-Test-Fetch-Priority"),
            Map.entry("x-nextjs-data", "x-nextjs-data — Pages Router client-side data request"),
            Map.entry("x-middleware-prefetch", "x-middleware-prefetch — prefetch hint for middleware"),
            Map.entry("x-middleware-subrequest", "x-middleware-subrequest — internal middleware recursion marker"),
            Map.entry("x-deployment-id", "x-deployment-id — skew-protection deployment ID"),
            Map.entry("purpose", "Purpose"));

    private static final Map<String, String> RESPONSE_HEADERS = Map.ofEntries(
            Map.entry("x-nextjs-cache", "x-nextjs-cache — ISR/full-route cache status"),
            Map.entry("x-nextjs-prerender", "x-nextjs-prerender — served from prerender"),
            Map.entry("x-nextjs-postponed", "x-nextjs-postponed — partial prerendering"),
            Map.entry("x-nextjs-matched-path", "x-nextjs-matched-path — internal route that served the request"),
            Map.entry("x-nextjs-page", "x-nextjs-page — page file"),
            Map.entry("x-nextjs-redirect", "x-nextjs-redirect — middleware redirect"),
            Map.entry("x-nextjs-rewrite", "x-nextjs-rewrite — middleware rewrite target"),
            Map.entry("x-nextjs-stale-time", "x-nextjs-stale-time — client router cache stale time (s)"),
            Map.entry("x-nextjs-deployment-id", "x-nextjs-deployment-id"),
            Map.entry("x-middleware-rewrite", "x-middleware-rewrite — middleware rewrite target"),
            Map.entry("x-middleware-redirect", "x-middleware-redirect — middleware redirect target"),
            Map.entry("x-middleware-next", "x-middleware-next — middleware passed through"),
            Map.entry("x-middleware-set-cookie", "x-middleware-set-cookie"),
            Map.entry("x-middleware-override-headers", "x-middleware-override-headers — request headers overridden by middleware"),
            Map.entry("x-middleware-skip", "x-middleware-skip"),
            Map.entry("x-action-revalidated", "x-action-revalidated — [tags, paths revalidated, cookies changed]"),
            Map.entry("x-action-redirect", "x-action-redirect — Server Action redirect (path;type)"),
            Map.entry("x-powered-by", "x-powered-by"),
            Map.entry("vary", "Vary"));

    @Override public String id() { return ID; }
    @Override public String name() { return "Next.js"; }
    @Override public String description() {
        return "Next.js RSC Flight payloads, Server Actions, router headers, __NEXT_DATA__ / __next_f page data and /_next/data JSON";
    }

    // ---------------------------------------------------------------- matching

    @Override
    public MatchResult match(MessageContext m) {
        try {
            return switch (m.kind()) {
                case REQUEST -> matchRequest(m);
                case RESPONSE -> matchResponse(m);
                case WEBSOCKET -> m.path().contains("/_next/webpack-hmr") || m.path().contains("/_next/turbopack-hmr")
                        ? MatchResult.of(85, "Next.js dev server HMR WebSocket") : MatchResult.NONE;
            };
        } catch (RuntimeException e) {
            return MatchResult.NONE;
        }
    }

    private static MatchResult matchRequest(MessageContext m) {
        if (m.requestHeader("Next-Action") != null) return MatchResult.of(95, "Next-Action header (Server Action call)");
        if (isActionMultipart(m)) return MatchResult.of(85, "Server Action form fields ($ACTION_…)");
        if (DATA_PATH.matcher(m.path()).find()) return MatchResult.of(85, "/_next/data/<buildId>/ request");
        if ("1".equals(trim(m.requestHeader("RSC")))) return MatchResult.of(90, "RSC: 1 header (App Router request)");
        if (m.requestHeader("Next-Router-State-Tree") != null) return MatchResult.of(90, "Next-Router-State-Tree header");
        if (hasRscQuery(m)) return MatchResult.of(70, "_rsc cache-busting query parameter");
        if (m.requestHeader("x-middleware-subrequest") != null) return MatchResult.of(60, "x-middleware-subrequest header");
        if (m.requestHeader("Next-Router-Prefetch") != null || m.requestHeader("Next-Url") != null || m.requestHeader("x-nextjs-data") != null) {
            return MatchResult.of(60, "Next.js router headers");
        }
        return MatchResult.NONE;
    }

    private static MatchResult matchResponse(MessageContext m) {
        String ct = lower(m.responseHeader("Content-Type"));
        if (ct.contains("text/x-component")) return MatchResult.of(95, "Content-Type: text/x-component (RSC Flight)");
        boolean hasBody = m.responseBody().length > 0;
        if (hasBody && m.requestHeader("Next-Action") != null) return MatchResult.of(90, "response to a Server Action");
        if (hasBody && "1".equals(trim(m.requestHeader("RSC")))) return MatchResult.of(90, "response to an RSC request");
        if (hasBody && DATA_PATH.matcher(m.path()).find()) return MatchResult.of(90, "/_next/data/<buildId>/ JSON");
        if (hasBody && hasRscQuery(m)) return MatchResult.of(75, "response to an _rsc request");
        if (hasBody && (ct.isEmpty() || ct.contains("html"))) {
            String head = head(m.responseBody(), HTML_SNIFF);
            if (head.contains("__NEXT_DATA__") && head.contains("<script")) return MatchResult.of(50, "__NEXT_DATA__ in page");
            if (head.contains("self.__next_f")) return MatchResult.of(50, "self.__next_f Flight chunks in page");
        }
        if (hasNextResponseHeaders(m)) return MatchResult.of(40, "x-nextjs-* / x-middleware-* response headers");
        if (lower(m.responseHeader("X-Powered-By")).contains("next.js")) return MatchResult.of(30, "X-Powered-By: Next.js");
        if (hasBody && ct.contains("html") && head(m.responseBody(), HTML_SNIFF).contains("/_next/static/")) {
            return MatchResult.of(20, "/_next/static/ assets referenced");
        }
        return MatchResult.NONE;
    }

    private static boolean hasRscQuery(MessageContext m) {
        String q = m.query();
        return q.startsWith("_rsc=") || q.contains("&_rsc=");
    }

    private static boolean isActionMultipart(MessageContext m) {
        if (!"POST".equalsIgnoreCase(m.method())) return false;
        if (!lower(m.requestHeader("Content-Type")).contains("multipart/form-data")) return false;
        String head = Codecs.latin1String(java.util.Arrays.copyOf(m.requestBody(), Math.min(m.requestBody().length, MULTIPART_SNIFF)));
        return head.contains("$ACTION_ID_") || head.contains("$ACTION_REF_");
    }

    private static boolean hasNextResponseHeaders(MessageContext m) {
        for (Header h : m.responseHeaders()) {
            String n = h.name().toLowerCase(Locale.ROOT);
            if (n.startsWith("x-nextjs-") || n.startsWith("x-middleware-") || n.equals("x-action-revalidated") || n.equals("x-action-redirect")) return true;
        }
        return false;
    }

    private static String head(byte[] b, int cap) {
        return new String(b, 0, Math.min(b.length, cap), StandardCharsets.UTF_8);
    }

    private static String lower(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }

    private static String trim(String s) {
        return s == null ? null : s.trim();
    }

    // ---------------------------------------------------------------- decoding

    @Override
    public DecodeResult decode(MessageContext m) throws DecodeException {
        try {
            return switch (m.kind()) {
                case REQUEST -> decodeRequest(m);
                case RESPONSE -> decodeResponse(m);
                case WEBSOCKET -> decodeWebSocket(m);
            };
        } catch (RuntimeException e) {
            throw new DecodeException("Next.js decode failed: " + e, e);
        }
    }

    // ---- requests

    private DecodeResult decodeRequest(MessageContext m) throws DecodeException {
        List<String> warnings = new ArrayList<>();
        String actionId = trim(m.requestHeader("Next-Action"));
        if (actionId != null || isActionMultipart(m)) return serverAction(m, actionId, warnings);

        DecodedNode root = DecodedNode.object("Next.js request");
        Matcher dm = DATA_PATH.matcher(m.path());
        String summary;
        if (dm.find()) {
            DecodedNode d = root.child("Pages Router data request");
            d.put("Build ID", dm.group(1));
            d.put("Page", pageFromData(dm.group(2)));
            if (!m.queryParameters().isEmpty()) {
                DecodedNode q = d.child("Query / dynamic route params");
                m.queryParameters().forEach((k, v) -> v.forEach(x -> q.put(k, x)));
            }
            summary = "Pages Router data request → " + pageFromData(dm.group(2)) + " (build " + dm.group(1) + ")";
        } else {
            boolean rsc = "1".equals(trim(m.requestHeader("RSC"))) || m.requestHeader("Next-Router-State-Tree") != null || hasRscQuery(m);
            boolean prefetch = m.requestHeader("Next-Router-Prefetch") != null;
            summary = rsc ? (prefetch ? "RSC prefetch → " : "RSC navigation → ") + (m.path().isEmpty() ? "/" : m.path()) : "Next.js request headers";
            String rscQ = Codecs.first(m.queryParameters(), "_rsc");
            if (rscQ != null) root.put("_rsc — cache-busting hash of router headers", rscQ);
        }
        DecodedNode headers = nextHeaders(m.requestHeaders(), true, warnings);
        String route = routeOf(m);
        if (route != null && !summary.startsWith("Pages")) summary += " (client at " + route + ")";
        if (!headers.isLeaf()) root.add(headers);

        if (root.isLeaf()) {
            // forced onto something else: maybe the body is Flight / action args
            byte[] body = Codecs.decodeContent(m.requestBody(), m.requestHeader("Content-Encoding"));
            String text = Codecs.utf8(body);
            if (Flight.looksLikeFlight(text)) return flightResult(text, "RSC payload", "Next.js request body", warnings, null);
            JsonElement json = JsonTree.parseStrict(text);
            if (json != null && json.isJsonArray()) {
                Flight.Render render = new Flight.Render(Flight.parse(""));
                root.add(render.value("Arguments (encodeReply)", json, 0));
                return new DecodeResult("Server Action-style arguments (no Next-Action header)", root, null, warnings);
            }
            throw new DecodeException("No Next.js headers, Server Action or RSC data found in this request");
        }
        return new DecodeResult(summary, root, null, warnings);
    }

    private static String routeOf(MessageContext m) {
        JsonElement tree = RouterState.parse(m.requestHeader("Next-Router-State-Tree"));
        return tree == null ? null : RouterState.path(tree);
    }

    private DecodeResult serverAction(MessageContext m, String actionId, List<String> warnings) {
        DecodedNode root = DecodedNode.object("Next.js Server Action");
        DecodedNode call = root.child("Server Action");
        call.put("Next-Action — Server Action ID", actionId);
        call.put("Endpoint", m.method() + " " + (m.path().isEmpty() ? "/" : m.path()));
        String route = routeOf(m);
        if (route != null) call.put("Client route", route);

        byte[] body = Codecs.decodeContent(m.requestBody(), m.requestHeader("Content-Encoding"));
        String ct = lower(m.requestHeader("Content-Type"));
        Flight.Render render = new Flight.Render(Flight.parse(""));
        int argCount = -1, formFields = -1;
        List<String> interesting = new ArrayList<>();

        List<Multipart.Part> parts = ct.contains("multipart") ? Multipart.parse(body, m.requestHeader("Content-Type")) : null;
        if (parts != null) {
            DecodedNode form = DecodedNode.array("Multipart fields (encodeReply / FormData)");
            for (Multipart.Part p : parts) {
                String name = p.name();
                String label = fieldLabel(name);
                if (name.contains("$ACTION_ID_") && actionId == null) {
                    actionId = name.substring(name.indexOf("$ACTION_ID_") + 11);
                    call.put("Action ID (from $ACTION_ID_ field, progressive enhancement)", actionId);
                }
                if (p.filename() != null) {
                    DecodedNode f = form.child(label);
                    f.put("Filename", p.filename()).put("Content-Type", p.contentType()).put("Size", p.data().length);
                    if (Codecs.isMostlyText(p.data())) f.put("Content", Codecs.truncate(p.text(), 4000));
                    else f.add(DecodedNode.leaf("Content", Codecs.hexPreview(p.data(), 64), DecodedNode.Type.BINARY));
                    continue;
                }
                String v = p.text();
                JsonElement json = JsonTree.looksLikeJson(v) ? JsonTree.parseStrict(v) : null;
                if (json != null) {
                    if (name.equals("0") && json.isJsonArray()) argCount = json.getAsJsonArray().size();
                    if (name.matches("\\$ACTION_\\d+:0") && json.isJsonObject() && json.getAsJsonObject().has("id") && actionId == null) {
                        actionId = Flight.str(json.getAsJsonObject().get("id"));
                        call.put("Action ID (from bound action reference)", actionId);
                    }
                    form.add(render.value(label, json, 0));
                    scanInteresting(json, name, interesting);
                } else {
                    DecodedNode leaf = render.value(label, new com.google.gson.JsonPrimitive(Codecs.truncate(v, 20_000)), 0);
                    form.add(leaf);
                    if (SENSITIVE.matcher(name).find() && interesting.size() < MAX_INTERESTING) interesting.add(name + " = " + Codecs.truncate(v, 80));
                }
            }
            root.add(form);
            if (argCount < 0) {
                int fields = 0;
                for (Multipart.Part part : parts) if (!part.name().startsWith("$ACTION_") && !part.name().contains("$ACTION_ID_")) fields++;
                formFields = fields;
            }
        } else if (body.length > 0) {
            String text = Codecs.utf8(body);
            JsonElement json = JsonTree.parseStrict(text);
            if (json == null && ct.contains("x-www-form-urlencoded")) {
                DecodedNode form = root.child("Form fields");
                Codecs.parseQuery(text).forEach((k, vs) -> vs.forEach(v -> form.put(k, v)));
            } else if (json == null) {
                root.put("Body", Codecs.truncate(text, 20_000));
                warnings.add("Server Action body is not JSON");
            } else {
                if (json.isJsonArray()) {
                    argCount = json.getAsJsonArray().size();
                    DecodedNode args = DecodedNode.array("Arguments (" + argCount + ")");
                    JsonArray a = json.getAsJsonArray();
                    for (int i = 0; i < a.size() && !render.exhausted(); i++) args.add(render.value("arg " + i, a.get(i), 0));
                    root.add(args);
                } else {
                    root.add(render.value("Argument", json, 0));
                    argCount = 1;
                }
                scanInteresting(json, "args", interesting);
            }
        } else {
            argCount = 0;
        }
        addInteresting(root, interesting);
        DecodedNode headers = nextHeaders(m.requestHeaders(), true, warnings);
        if (!headers.isLeaf()) root.add(headers);
        String summary = "Server Action " + (actionId == null ? "(unknown id)" : actionId)
                + (argCount >= 0 ? " (" + argCount + (argCount == 1 ? " arg)" : " args)")
                : formFields >= 0 ? " (" + formFields + (formFields == 1 ? " form field)" : " form fields)") : "")
                + " → " + (m.path().isEmpty() ? "/" : m.path());
        return new DecodeResult(summary, root, null, warnings);
    }

    private static String fieldLabel(String name) {
        if (name.equals("0")) return "0 — arguments (encodeReply root)";
        if (name.contains("$ACTION_ID_")) return name + " — Server Action ID (no-JS form)";
        if (name.startsWith("$ACTION_REF_")) return name + " — bound action reference";
        if (name.equals("$ACTION_KEY")) return name + " — useActionState key";
        if (name.matches("\\$ACTION_\\d+:\\d+")) return name + " — bound action data";
        Matcher pm = Pattern.compile("^(\\d+)_(.+)$").matcher(name);
        if (pm.matches()) return name + " — FormData $K" + pm.group(1) + " field \"" + pm.group(2) + "\"";
        return name;
    }

    private static String pageFromData(String p) {
        if (p.equals("index")) return "/";
        if (p.endsWith("/index")) p = p.substring(0, p.length() - 6);
        return "/" + p;
    }

    // ---- responses

    private DecodeResult decodeResponse(MessageContext m) throws DecodeException {
        List<String> warnings = new ArrayList<>();
        byte[] raw = m.responseBody();
        byte[] body = Codecs.decodeContent(raw, m.responseHeader("Content-Encoding"));
        String ct = lower(m.responseHeader("Content-Type"));
        if (m.truncated()) warnings.add("Response body was truncated by the size limit; decode is partial");
        if (lower(m.responseHeader("Content-Encoding")).contains("br")) warnings.add("Brotli Content-Encoding is not supported; body left as-is");
        DecodedNode headers = nextHeaders(m.responseHeaders(), false, warnings);
        boolean action = m.requestHeader("Next-Action") != null;
        boolean rsc = "1".equals(trim(m.requestHeader("RSC"))) || hasRscQuery(m);

        if (body.length > 0 && (ct.contains("text/x-component") || ((action || rsc) && !ct.contains("html")))) {
            String text = Codecs.utf8(body.length > FLIGHT_DECODE ? java.util.Arrays.copyOf(body, FLIGHT_DECODE) : body);
            if (body.length > FLIGHT_DECODE) warnings.add("Flight payload is larger than " + (FLIGHT_DECODE >> 20) + " MB; only the start was decoded");
            String prefix = action ? "Server Action response" : "RSC payload";
            return flightResult(text, prefix, action ? "Next.js Server Action response" : "Next.js RSC response", warnings, headers);
        }
        Matcher dm = DATA_PATH.matcher(m.path());
        if (body.length > 0 && dm.find()) return dataResponse(m, body, dm, warnings, headers);

        if (body.length > 0) {
            String html = Codecs.utf8(body.length > HTML_DECODE ? java.util.Arrays.copyOf(body, HTML_DECODE) : body);
            if (body.length > HTML_DECODE) warnings.add("Page is larger than " + (HTML_DECODE >> 20) + " MB; only the start was scanned");
            DecodeResult r = htmlPage(html, warnings, headers);
            if (r != null) return r;
            if (Flight.looksLikeFlight(html)) return flightResult(html, "RSC payload", "Next.js RSC response", warnings, headers);
            if (!(ct.contains("html"))) {
                JsonElement json = JsonTree.parseStrict(html);
                if (json != null && json.isJsonObject() && json.getAsJsonObject().has("pageProps")) {
                    return dataResponse(m, body, null, warnings, headers);
                }
            }
        }
        if (!headers.isLeaf()) {
            DecodedNode root = DecodedNode.object("Next.js response");
            root.add(headers);
            return new DecodeResult(headerSummary(m), root, null, warnings);
        }
        throw new DecodeException("No Next.js data found in this response (not RSC Flight, __NEXT_DATA__, __next_f or /_next/data JSON)");
    }

    private static String headerSummary(MessageContext m) {
        StringBuilder sb = new StringBuilder("Next.js response");
        List<String> bits = new ArrayList<>();
        String cache = m.responseHeader("x-nextjs-cache");
        if (cache != null) bits.add("cache " + cache.trim());
        String matched = m.responseHeader("x-nextjs-matched-path");
        if (matched != null) bits.add("matched " + matched.trim());
        String rw = m.responseHeader("x-middleware-rewrite");
        if (rw != null) bits.add("rewrite → " + rw.trim());
        String rd = m.responseHeader("x-middleware-redirect");
        if (rd == null) rd = m.responseHeader("x-nextjs-redirect");
        if (rd != null) bits.add("redirect → " + rd.trim());
        if (!bits.isEmpty()) sb.append(" (").append(String.join(", ", bits)).append(')');
        return sb.toString();
    }

    private DecodeResult flightResult(String text, String prefix, String rootName, List<String> warnings, DecodedNode headers) throws DecodeException {
        Flight.Parsed p = Flight.parse(text);
        if (p.rows.isEmpty() || (p.badLines > 0 && p.badLines >= p.rows.size())) {
            throw new DecodeException("Not a React Server Components (Flight) payload: "
                    + (p.problems.isEmpty() ? "no rows found" : p.problems.get(0)));
        }
        addFlightWarnings(p, warnings);
        DecodedNode root = Flight.tree(rootName, p);
        addFlightInteresting(p, root);
        if (headers != null && !headers.isLeaf()) root.add(headers);
        return new DecodeResult(prefix + ": " + Flight.summary(p), root, null, warnings);
    }

    private static void addFlightWarnings(Flight.Parsed p, List<String> warnings) {
        if (p.badLines > 0) warnings.add(p.badLines + " line(s) could not be parsed as Flight rows");
        for (String s : p.problems) if (warnings.size() < 15) warnings.add(s);
        int errors = p.count(Flight.Kind.ERROR);
        if (errors > 0) warnings.add(errors + " server error row(s) in the payload (look up the digest in server logs)");
        if (p.count(Flight.Kind.DEBUG) > 0 || p.count(Flight.Kind.CONSOLE) > 0) warnings.add("Development-mode debug rows present (dev server or debug build)");
    }

    private static void addFlightInteresting(Flight.Parsed p, DecodedNode root) {
        List<String> hits = new ArrayList<>();
        for (Flight.Row r : p.rows) {
            if (r.json() != null && (r.kind() == Flight.Kind.MODEL)) scanInteresting(r.json(), "row " + r.id(), hits);
            if (hits.size() >= MAX_INTERESTING) break;
        }
        addInteresting(root, hits);
    }

    private DecodeResult dataResponse(MessageContext m, byte[] body, Matcher dm, List<String> warnings, DecodedNode headers) throws DecodeException {
        JsonElement json = JsonTree.parseStrict(Codecs.utf8(body));
        if (json == null) throw new DecodeException("/_next/data response is not JSON");
        DecodedNode root = DecodedNode.object("Next.js data (Pages Router)");
        DecodedNode ov = root.child("Overview");
        String build = dm == null ? null : dm.group(1);
        String page = dm == null ? null : pageFromData(dm.group(2));
        ov.put("Build ID", build);
        ov.put("Page", page);
        String mode = null;
        if (json.isJsonObject()) {
            JsonObject o = json.getAsJsonObject();
            if (o.has("__N_SSP")) mode = "getServerSideProps";
            else if (o.has("__N_SSG")) mode = "getStaticProps";
            ov.put("Data fetching", mode);
            JsonObject pp = o.has("pageProps") && o.get("pageProps").isJsonObject() ? o.getAsJsonObject("pageProps") : null;
            if (pp != null && pp.has("__N_REDIRECT")) {
                ov.put("Redirect (__N_REDIRECT)", Flight.str(pp.get("__N_REDIRECT")));
                ov.put("Redirect status", Flight.str(pp.get("__N_REDIRECT_STATUS")));
            }
            if (o.has("notFound")) ov.put("notFound", o.get("notFound").toString());
        }
        root.add(JsonTree.toNode("Body", json, true));
        List<String> hits = new ArrayList<>();
        scanInteresting(json, "", hits);
        addInteresting(root, hits);
        if (headers != null && !headers.isLeaf()) root.add(headers);
        String summary = "Next.js data" + (mode == null ? "" : " (" + mode + ")") + (page == null ? "" : " → " + page)
                + (build == null ? "" : " (build " + build + ")") + (hits.isEmpty() ? "" : ", " + hits.size() + " interesting key(s)");
        return new DecodeResult(summary, root, null, warnings);
    }

    // ---- HTML pages

    /** Decodes __NEXT_DATA__ and/or self.__next_f chunks; null if the page has neither (and no Next.js assets). */
    DecodeResult htmlPage(String html, List<String> warnings, DecodedNode headers) {
        DecodedNode root = DecodedNode.object("Next.js page");
        List<String> summaryParts = new ArrayList<>();

        JsonElement nextData = findNextData(html, warnings);
        if (nextData != null) {
            summaryParts.add(nextDataNode(nextData, root, warnings));
        }

        StringBuilder flight = new StringBuilder();
        int[] counts = new int[4];
        int chunks = collectNextF(html, flight, counts, warnings);
        if (chunks > 0) {
            DecodedNode fn = root.child("self.__next_f (App Router inline RSC payload)");
            fn.put("push() calls", chunks);
            fn.put("Bootstrap [0]", counts[0]);
            fn.put("Flight data [1]", counts[1]);
            if (counts[2] > 0) fn.put("Form state [2]", counts[2]);
            if (counts[3] > 0) fn.put("Binary (base64) [3]", counts[3]);
            fn.put("Flight bytes", flight.length());
            Flight.Parsed p = Flight.parse(flight.toString());
            if (!p.rows.isEmpty()) {
                addFlightWarnings(p, warnings);
                DecodedNode t = Flight.tree("Flight payload", p);
                fn.add(t);
                addFlightInteresting(p, root);
                summaryParts.add("App Router page, inline RSC: " + Flight.summary(p));
            } else if (flight.length() > 0) {
                warnings.add("self.__next_f chunks did not parse as Flight rows");
                fn.put("Concatenated data", Codecs.truncate(flight.toString(), 20_000));
                summaryParts.add("App Router page");
            } else {
                summaryParts.add("App Router page (no inline RSC data)");
            }
        }

        Matcher bm = STATIC_BUILD.matcher(html);
        if (bm.find()) {
            root.put("Build ID (from /_next/static/<id>/_buildManifest.js)", bm.group(1));
            if (summaryParts.isEmpty()) summaryParts.add("Next.js page (build " + bm.group(1) + ")");
        }
        if (summaryParts.isEmpty()) {
            if (!html.contains("/_next/static/")) return null;
            int scripts = 0;
            for (int i = html.indexOf("/_next/static/chunks/"); i >= 0 && scripts < 10_000; i = html.indexOf("/_next/static/chunks/", i + 1)) scripts++;
            root.put("/_next/static/chunks/ references", scripts);
            summaryParts.add("Next.js page (assets only, no embedded data)");
        }
        if (headers != null && !headers.isLeaf()) root.add(headers);
        return new DecodeResult(String.join("; ", summaryParts), root, null, warnings);
    }

    static JsonElement findNextData(String html, List<String> warnings) {
        int from = 0;
        for (int attempt = 0; attempt < 5; attempt++) {
            int idx = html.indexOf("__NEXT_DATA__", from);
            if (idx < 0) return null;
            from = idx + 13;
            int tagStart = html.lastIndexOf("<script", idx);
            int lastGt = html.lastIndexOf('>', idx);
            if (tagStart < 0 || lastGt > tagStart) continue; // not inside a <script ...> start tag
            int gt = html.indexOf('>', idx);
            if (gt < 0) return null;
            int end = html.indexOf("</script>", gt);
            if (end < 0) end = html.length();
            String body = html.substring(gt + 1, end).trim();
            JsonElement e = JsonTree.parseStrict(body);
            if (e == null) e = JsonTree.parseLenient(body);
            if (e != null) return e;
            warnings.add("__NEXT_DATA__ script is not valid JSON");
        }
        return null;
    }

    private static String nextDataNode(JsonElement data, DecodedNode root, List<String> warnings) {
        DecodedNode nd = root.child("__NEXT_DATA__ (Pages Router)");
        String page = null, build = null, mode = "static";
        List<String> hits = new ArrayList<>();
        if (data.isJsonObject()) {
            JsonObject o = data.getAsJsonObject();
            page = Flight.str(o.get("page"));
            build = Flight.str(o.get("buildId"));
            if (isTrue(o.get("gssp"))) mode = "getServerSideProps";
            else if (isTrue(o.get("gsp"))) mode = "getStaticProps";
            else if (isTrue(o.get("gip")) || isTrue(o.get("appGip"))) mode = "getInitialProps";
            else if (isTrue(o.get("autoExport"))) mode = "automatic static optimisation";
            DecodedNode ov = nd.child("Overview");
            ov.put("Page (route)", page);
            ov.put("Build ID", build);
            ov.put("Data fetching", mode);
            String[][] fields = {
                    {"assetPrefix", "Asset prefix"}, {"isFallback", "isFallback — fallback page"},
                    {"nextExport", "nextExport — static export"}, {"autoExport", "autoExport"},
                    {"customServer", "customServer — custom server in use"}, {"isPreview", "isPreview — Preview/Draft mode"},
                    {"locale", "Locale"}, {"defaultLocale", "Default locale"}, {"locales", "Locales"},
                    {"dynamicIds", "dynamicIds"}, {"scriptLoader", "scriptLoader"}, {"notFound", "notFound"}};
            for (String[] f : fields) if (o.has(f[0])) ov.add(JsonTree.toNode(f[1], o.get(f[0]), false));
            if (o.has("query")) nd.add(JsonTree.toNode("query — route params / query string", o.get("query"), true));
            if (o.has("runtimeConfig")) {
                JsonElement rc = o.get("runtimeConfig");
                nd.add(JsonTree.toNode("runtimeConfig — publicRuntimeConfig (exposed to every visitor)", rc, true));
                if (rc.isJsonObject() && !rc.getAsJsonObject().isEmpty()) {
                    warnings.add("publicRuntimeConfig exposes " + rc.getAsJsonObject().size() + " key(s) to the client");
                }
                scanInteresting(rc, "runtimeConfig", hits);
            }
            if (o.has("err")) {
                nd.add(JsonTree.toNode("err — server render error", o.get("err"), true));
                warnings.add("__NEXT_DATA__ contains a server-side error object" + (o.get("err").toString().contains("stack") ? " with a stack trace" : ""));
            }
            if (isTrue(o.get("isPreview"))) warnings.add("Page rendered in Preview/Draft mode");
            if (o.has("props")) {
                nd.add(JsonTree.toNode("props", o.get("props"), true));
                scanInteresting(o.get("props"), "props", hits);
            }
            for (Map.Entry<String, JsonElement> en : o.entrySet()) {
                String k = en.getKey();
                if (!List.of("props", "page", "buildId", "query", "runtimeConfig", "err", "assetPrefix", "isFallback", "nextExport",
                        "autoExport", "customServer", "isPreview", "locale", "defaultLocale", "locales", "dynamicIds", "scriptLoader",
                        "notFound", "gssp", "gsp", "gip", "appGip").contains(k)) {
                    nd.add(JsonTree.toNode(k, en.getValue(), false));
                }
            }
        } else {
            nd.add(JsonTree.toNode("data", data, true));
        }
        addInteresting(root, hits);
        return "Pages Router page " + (page == null ? "" : page + " ") + "(" + mode + (build == null ? "" : ", build " + build) + ")"
                + (hits.isEmpty() ? "" : ", " + hits.size() + " interesting key(s)");
    }

    /**
     * Concatenates the string pieces of {@code self.__next_f.push([1,"..."])} calls (and base64 [3, "..."] binary
     * chunks). Returns the number of push() calls found; counts[type] tallies per chunk type.
     */
    static int collectNextF(String html, StringBuilder out, int[] counts, List<String> warnings) {
        int calls = 0, from = 0;
        while (calls < MAX_NEXT_F_CHUNKS) {
            int idx = html.indexOf("__next_f", from);
            if (idx < 0) break;
            int push = html.indexOf(".push(", idx);
            if (push < 0) break;
            from = idx + 8;
            if (push - idx > 40) continue;
            int open = push + 6;
            while (open < html.length() && Character.isWhitespace(html.charAt(open))) open++;
            if (open >= html.length() || html.charAt(open) != '[') continue;
            int end = JsLiteral.matchBracket(html, open);
            if (end < 0) {
                warnings.add("Unterminated self.__next_f.push() call");
                break;
            }
            from = end;
            JsonElement e = JsonTree.parseLenient(html.substring(open, end));
            calls++;
            if (e == null || !e.isJsonArray() || e.getAsJsonArray().isEmpty()) continue;
            JsonArray a = e.getAsJsonArray();
            int type = a.get(0).isJsonPrimitive() && a.get(0).getAsJsonPrimitive().isNumber() ? a.get(0).getAsInt() : -1;
            if (type >= 0 && type < counts.length) counts[type]++;
            if (a.size() < 2 || out.length() > HTML_DECODE) continue;
            String s = Flight.str(a.get(1));
            if (type == 1 && s != null) out.append(s);
            else if (type == 3 && s != null) {
                byte[] b = Codecs.base64Decode(s);
                if (b != null) out.append(new String(b, StandardCharsets.UTF_8));
            }
        }
        return calls;
    }

    // ---- WebSocket (dev HMR)

    private DecodeResult decodeWebSocket(MessageContext m) throws DecodeException {
        String text = Codecs.utf8(m.body()).trim();
        JsonElement json = JsonTree.parseStrict(text);
        if (json == null) {
            if (Flight.looksLikeFlight(text)) return flightResult(text, "RSC payload", "Next.js RSC (WebSocket)", new ArrayList<>(), null);
            throw new DecodeException("WebSocket message is not Next.js HMR JSON");
        }
        DecodedNode root = DecodedNode.object("Next.js HMR");
        root.add(JsonTree.toNode("Message", json, true));
        String action = null;
        if (json.isJsonObject()) {
            JsonObject o = json.getAsJsonObject();
            action = Flight.str(o.has("action") ? o.get("action") : o.get("type"));
        }
        return DecodeResult.of("Next.js dev HMR" + (action == null ? " message" : ": " + action), root);
    }

    // ---------------------------------------------------------------- headers & helpers

    static DecodedNode nextHeaders(List<Header> headers, boolean request, List<String> warnings) {
        DecodedNode n = DecodedNode.object(request ? "Next.js request headers" : "Next.js response headers");
        Map<String, String> labels = request ? REQUEST_HEADERS : RESPONSE_HEADERS;
        for (Header h : headers) {
            String name = h.name().toLowerCase(Locale.ROOT);
            String v = h.value();
            if (request && name.equals("next-router-state-tree")) {
                JsonElement tree = RouterState.parse(v);
                if (tree == null) {
                    n.put("Next-Router-State-Tree — client router state (unparsed)", v);
                    warnings.add("Next-Router-State-Tree is not valid URL-encoded JSON");
                } else {
                    DecodedNode t = n.child("Next-Router-State-Tree — client router state");
                    t.put("Current route", RouterState.path(tree));
                    t.add(RouterState.node("Tree", tree));
                }
                continue;
            }
            if (name.equals("x-powered-by") && !lower(v).contains("next")) continue;
            if (name.equals("vary") && !lower(v).contains("rsc")) continue;
            if (name.equals("purpose") && !lower(v).contains("prefetch")) continue;
            String label = labels.get(name);
            if (label == null && (name.startsWith("x-nextjs-") || name.startsWith("x-middleware-"))) label = h.name();
            if (label == null) continue;
            if (name.equals("x-action-revalidated")) {
                JsonElement e = JsonTree.parseStrict(v);
                n.add(e == null ? DecodedNode.leaf(label, v) : JsonTree.toNode(label, e, false));
                continue;
            }
            if (name.equals("x-middleware-subrequest")) {
                warnings.add("x-middleware-subrequest request header present: can bypass Next.js middleware (auth) on vulnerable versions (CVE-2025-29927)");
            }
            n.put(label, v);
        }
        return n;
    }

    private static boolean isTrue(JsonElement e) {
        return e != null && e.isJsonPrimitive() && e.getAsJsonPrimitive().isBoolean() && e.getAsBoolean();
    }

    /** Records "path = value" for keys that look security-relevant (secrets, tokens, PII, roles...). Bounded. */
    static void scanInteresting(JsonElement e, String path, List<String> out) {
        int[] visits = {0};
        scan(e, path, out, 0, visits);
    }

    private static void scan(JsonElement e, String path, List<String> out, int depth, int[] visits) {
        if (e == null || out.size() >= MAX_INTERESTING || depth > 40 || ++visits[0] > 200_000) return;
        if (e.isJsonObject()) {
            for (Map.Entry<String, JsonElement> en : e.getAsJsonObject().entrySet()) {
                String p = path.isEmpty() ? en.getKey() : path + "." + en.getKey();
                JsonElement v = en.getValue();
                if (SENSITIVE.matcher(en.getKey()).find() && !NOISY_PROPS.contains(en.getKey()) && !v.isJsonNull() && !(v.isJsonPrimitive() && v.getAsString().isEmpty())) {
                    if (out.size() >= MAX_INTERESTING) return;
                    String shown = v.isJsonPrimitive() ? v.getAsString() : v.toString();
                    out.add(p + " = " + Codecs.truncate(shown, 120));
                }
                scan(v, p, out, depth + 1, visits);
            }
        } else if (e.isJsonArray()) {
            JsonArray a = e.getAsJsonArray();
            for (int i = 0; i < a.size() && out.size() < MAX_INTERESTING; i++) scan(a.get(i), path + "[" + i + "]", out, depth + 1, visits);
        }
    }

    private static void addInteresting(DecodedNode root, List<String> hits) {
        if (hits.isEmpty()) return;
        DecodedNode n = DecodedNode.array("Interesting keys (possible secrets / PII / authz data)");
        for (String h : hits) n.add(DecodedNode.leaf("", h));
        if (hits.size() >= MAX_INTERESTING) n.add(DecodedNode.note("limit of " + MAX_INTERESTING + " reached"));
        root.add(n);
    }
}
