package protocoldecoder.builtin.aspnetajax;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
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

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scanner support for ASP.NET AJAX: service error disclosure (ASMX/WCF/PageMethods and UpdatePanel delta errors),
 * proxy script inventory, verbose-error and proxy-exposure probes, and insertion points for the panel / trigger parts
 * of the ScriptManager field in async postbacks.
 */
public final class AspNetAjaxScanner implements ProtocolScanner {

    private static final Pattern SERVICE = Pattern.compile("(?i)^(.*\\.(?:asmx|svc))/([A-Za-z_][A-Za-z0-9_]*)$");
    private static final Pattern SERVICE_METHOD = Pattern.compile("(?i)\\.(?:asmx|svc|aspx)/[A-Za-z_][A-Za-z0-9_]*$");
    private static final Pattern PROXY = Pattern.compile("(?i)\\.(?:asmx|svc)/(js|jsdebug)$");
    private static final Pattern DEBUG_ANNOTATION = Pattern.compile("///\\s*<param\\s+name=");
    /** Generic texts ASP.NET sends when details are hidden. */
    private static final Pattern GENERIC_ERROR = Pattern.compile("(?i)^(there was an error processing the request\\.?|an unknown error occurred.*|)$");

    @Override
    public String decoderId() {
        return AspNetAjaxDecoder.ID;
    }

    private final List<PassiveCheck> passive = List.of(new ServiceErrorDetails(), new DeltaErrorDetails(), new ProxyMethods(),
            new JsDebugProxy(), new RedirectFromInput());
    /** Kept as one instance: the proxy probe remembers which services it already requested. */
    private final List<ActiveCheck> active = List.of(new VerboseServiceErrors(), new ProxyScriptExposure());

    @Override
    public List<PassiveCheck> passiveChecks() {
        return passive;
    }

    @Override
    public List<ActiveCheck> activeChecks() {
        return active;
    }

    // ================================================================ helpers

    private static String val(DecodedNode n, String child) {
        DecodedNode c = n == null ? null : n.get(child);
        return c == null ? null : c.value();
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank() || s.equals("null");
    }

    /** Exception type / stack trace from a decoded service error object (handles WCF ExceptionDetail). */
    record ErrorInfo(String type, String message, String stackTrace) {
        boolean detailed() {
            return !blank(type) || !blank(stackTrace);
        }
    }

    static ErrorInfo errorInfo(DecodedNode error) {
        if (error == null) return null;
        DecodedNode detail = error.get("ExceptionDetail");
        String type = val(error, "ExceptionType");
        if (blank(type)) type = val(detail, "Type");
        String trace = val(error, "StackTrace");
        if (blank(trace)) trace = val(detail, "StackTrace");
        String msg = val(error, "Message");
        if (blank(msg)) msg = val(detail, "Message");
        return new ErrorInfo(type, msg, trace);
    }

    /** Same, from a raw JSON response body (active checks). */
    static ErrorInfo errorInfo(String json) {
        JsonElement e = JsonTree.parseLenient(json == null ? "" : json.strip());
        if (!MsJson.isErrorObject(e)) return null;
        return errorInfo(MsJson.toNode("Error", e));
    }

    private static String firstLine(String s) {
        if (s == null) return null;
        String t = s.strip();
        int nl = t.indexOf('\n');
        return Codecs.truncate(nl > 0 ? t.substring(0, nl).strip() : t, 300);
    }

    private static Finding errorFinding(String id, ErrorInfo info, String context) {
        String evidence = !blank(info.type()) ? info.type() : firstLine(info.stackTrace());
        Finding f = Finding.of(id, "ASP.NET AJAX service discloses exception details")
                .severity(Severity.LOW).confidence(Confidence.FIRM)
                .detail(context + " returned a JSON error object with exception details:<ul>"
                        + (blank(info.type()) ? "" : "<li>ExceptionType: <code>" + Finding.esc(info.type()) + "</code></li>")
                        + (blank(info.message()) ? "" : "<li>Message: <code>" + Finding.esc(Codecs.truncate(info.message(), 500)) + "</code></li>")
                        + (blank(info.stackTrace()) ? "" : "<li>StackTrace: <code>" + Finding.esc(Codecs.truncate(info.stackTrace(), 1000)) + "</code></li>")
                        + "</ul>")
                .background("ASMX, WCF (AJAX-enabled) and PageMethod endpoints serialize unhandled exceptions to the client. With customErrors off "
                        + "(or WCF includeExceptionDetailInFaults=true) the exception type and stack trace are included, revealing internal "
                        + "class names, code paths and sometimes data.")
                .remediation("Enable <code>&lt;customErrors mode=\"On\"&gt;</code> (ASMX/PageMethods) and set <code>includeExceptionDetailInFaults=\"false\"</code> "
                        + "(WCF); catch exceptions in service methods and return generic errors.");
        if (evidence != null) f.responseEvidence(evidence);
        return f;
    }

    // ================================================================ passive

    /** ASMX / WCF / PageMethod error objects with ExceptionType or StackTrace. */
    static final class ServiceErrorDetails implements PassiveCheck {
        @Override public String id() { return "aspnet-ajax.service-error-details"; }
        @Override public String name() { return "Service exception details"; }
        @Override public String description() { return "ASMX/WCF/PageMethod JSON error objects exposing ExceptionType or StackTrace"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || decoded == null) return List.of();
            ErrorInfo info = errorInfo(decoded.root().get("Error"));
            if (info == null || !info.detailed()) return List.of();
            if (!"ASP.NET AJAX service response".equals(decoded.root().name())) return List.of();
            return List.of(errorFinding(id(), info, "The service"));
        }
    }

    /** UpdatePanel delta {@code error} records that carry exception text. */
    static final class DeltaErrorDetails implements PassiveCheck {
        @Override public String id() { return "aspnet-ajax.delta-error"; }
        @Override public String name() { return "Async postback error details"; }
        @Override public String description() { return "UpdatePanel delta 'error' records returning server exception messages or stack traces"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || decoded == null || !"ASP.NET AJAX delta".equals(decoded.root().name())) return List.of();
            DecodedNode err = decoded.root().get("Error");
            String msg = val(err, "Message");
            if (err == null || msg == null || GENERIC_ERROR.matcher(msg.strip()).matches()) return List.of();
            String status = val(err, "HTTP status (id)");
            String trace = ScanPatterns.exceptionEvidence(msg);
            Finding f = Finding.of(id(), trace != null ? "ASP.NET AJAX async postback discloses exception details"
                            : "ASP.NET AJAX async postback returns server error message")
                    .severity(trace != null ? Severity.LOW : Severity.INFORMATION).confidence(Confidence.FIRM)
                    .detail("The UpdatePanel delta response contains an <code>error</code> record (status " + Finding.esc(status) + "): <code>"
                            + Finding.esc(Codecs.truncate(msg, 500)) + "</code>"
                            + (trace != null ? "<br>It includes exception/stack trace details: <code>" + Finding.esc(trace) + "</code>" : ""))
                    .background("ScriptManager sends the message of an unhandled exception during an async postback to the browser unless "
                            + "AsyncPostBackErrorMessage / custom errors replace it. Raw exception messages reveal implementation details and "
                            + "often indicate input that reaches code without validation.")
                    .remediation("Handle <code>ScriptManager.AsyncPostBackError</code> and set a generic <code>AsyncPostBackErrorMessage</code>; enable custom errors.")
                    .responseEvidence(Codecs.truncate(msg, 200));
            if (trace != null) f.responseEvidence(trace);
            return List.of(f);
        }
    }

    /** Lists methods exposed by a generated proxy script. */
    static final class ProxyMethods implements PassiveCheck {
        @Override public String id() { return "aspnet-ajax.proxy-methods"; }
        @Override public String name() { return "Service proxy method inventory"; }
        @Override public String description() { return "Lists the methods a /js or /jsdebug service proxy script exposes (attack surface)"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || decoded == null || !"ASP.NET AJAX service proxy".equals(decoded.root().name())) return List.of();
            return proxyFinding(id(), decoded, null);
        }
    }

    static List<Finding> proxyFinding(String id, DecodeResult decoded, Exchange x) {
        DecodedNode methods = decoded.root().get("Methods");
        if (methods == null || methods.children().isEmpty()) return List.of();
        String servicePath = val(decoded.root(), "Service path");
        StringBuilder list = new StringBuilder("<ul>");
        int shown = 0;
        for (DecodedNode mth : methods.children()) {
            if (++shown > 200) {
                list.append("<li>… ").append(methods.children().size() - 200).append(" more</li>");
                break;
            }
            DecodedNode params = mth.get("Parameters");
            List<String> names = params == null ? List.of() : params.children().stream().map(DecodedNode::value).toList();
            list.append("<li><code>").append(Finding.esc(val(mth, "HTTP"))).append(' ').append(Finding.esc(mth.name())).append('(')
                    .append(Finding.esc(String.join(", ", names))).append(")</code></li>");
        }
        list.append("</ul>");
        Finding f = Finding.of(id, "ASP.NET AJAX service proxy exposes methods")
                .severity(Severity.INFORMATION).confidence(Confidence.CERTAIN)
                .detail("The generated JavaScript proxy for <code>" + Finding.esc(servicePath == null ? val(decoded.root(), "Proxy class") : servicePath)
                        + "</code> lists " + methods.children().size() + " callable method(s):" + list
                        + "Each can be invoked directly with a JSON POST to <code>&lt;service&gt;/&lt;Method&gt;</code> — including methods the UI never calls.")
                .background("ASP.NET AJAX generates client proxies for every [ScriptService]/[WebMethod] or AJAX-enabled WCF operation. The proxy "
                        + "is a complete inventory of server-side methods and parameter names.")
                .remediation("Review every exposed method for authentication and authorization; remove unused methods. Proxy generation can't be "
                        + "fully disabled for script services, so don't rely on obscurity.");
        if (x != null) f.exchange(x);
        return List.of(f);
    }

    /** Debug proxies with parameter type annotations. */
    static final class JsDebugProxy implements PassiveCheck {
        @Override public String id() { return "aspnet-ajax.jsdebug"; }
        @Override public String name() { return "Debug service proxy (jsdebug)"; }
        @Override public String description() { return "A /jsdebug proxy script served with parameter type annotations"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || decoded == null || !"ASP.NET AJAX service proxy".equals(decoded.root().name())) return List.of();
            Matcher p = PROXY.matcher(m.path() == null ? "" : m.path());
            if (!p.find() || !p.group(1).equalsIgnoreCase("jsdebug")) return List.of();
            String text = m.responseBodyText();
            Matcher a = DEBUG_ANNOTATION.matcher(text);
            if (!a.find()) return List.of();
            return List.of(Finding.of(id(), "ASP.NET AJAX debug service proxy available")
                    .severity(Severity.LOW).confidence(Confidence.FIRM).scope(Finding.Scope.HOST)
                    .detail("<code>" + Finding.esc(m.path()) + "</code> returns the debug proxy script, which documents each method's parameters "
                            + "and their .NET types in <code>/// &lt;param&gt;</code> comments.")
                    .background("The /jsdebug variant of an ASP.NET AJAX proxy adds XML documentation comments with parameter names and types and "
                            + "data contract details, making it easier to craft valid calls against every exposed method.")
                    .remediation("Review exposed service methods; set <code>&lt;compilation debug=\"false\"&gt;</code> and use the release /js proxy.")
                    .responseEvidence(a.group()));
        }
    }

    /** Off-site pageRedirect whose target appears in the request. */
    static final class RedirectFromInput implements PassiveCheck {
        @Override public String id() { return "aspnet-ajax.redirect-from-input"; }
        @Override public String name() { return "Off-site async postback redirect from input"; }
        @Override public String description() { return "Delta pageRedirect to another host whose target URL appears in the request (open redirect hint)"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || decoded == null || !"ASP.NET AJAX delta".equals(decoded.root().name())) return List.of();
            DecodedNode r = decoded.root().get("Redirect");
            String raw = val(r, "URL");
            if (raw == null) return List.of();
            String url = val(r, "URL (decoded)") != null ? val(r, "URL (decoded)") : raw;
            String host = offSiteHost(url, m.host());
            if (host == null) return List.of();
            String req = Codecs.urlDecode(m.query() == null ? "" : m.query()) + "\n" + Codecs.urlDecode(Codecs.latin1String(m.requestBody()));
            String lower = req.toLowerCase(Locale.ROOT);
            String target = url.strip();
            if (!lower.contains(target.toLowerCase(Locale.ROOT)) && !lower.contains("//" + host)) return List.of();
            return List.of(Finding.of(id(), "ASP.NET AJAX async postback redirects off-site to a requested URL")
                    .severity(Severity.INFORMATION).confidence(Confidence.TENTATIVE)
                    .detail("The delta response tells the browser to navigate to <code>" + Finding.esc(Codecs.truncate(url, 500)) + "</code> (host <code>"
                            + Finding.esc(host) + "</code>), and that target appears in the request. If the redirect target is taken from user input "
                            + "this is an open redirect.")
                    .background("<code>pageRedirect</code> delta records are how Response.Redirect works during UpdatePanel postbacks.")
                    .remediation("Only redirect to relative URLs or an allow-list of hosts.")
                    .responseEvidence(raw));
        }
    }

    /** Host of an absolute or protocol-relative URL if it differs from {@code ownHost}, else null. */
    static String offSiteHost(String url, String ownHost) {
        String u = url.strip();
        String lower = u.toLowerCase(Locale.ROOT);
        if (!(lower.startsWith("http://") || lower.startsWith("https://") || u.startsWith("//") || u.startsWith("\\\\") || u.startsWith("/\\"))) return null;
        String host;
        try {
            String norm = u.replace('\\', '/');
            host = URI.create(norm.startsWith("//") ? "http:" + norm : norm).getHost();
        } catch (IllegalArgumentException e) {
            host = null;
        }
        if (host == null) {
            Matcher h = Pattern.compile("^(?:[a-zA-Z]+:)?[/\\\\]{2}([^/\\\\?#:]+)").matcher(u);
            host = h.find() ? h.group(1) : null;
        }
        if (host == null) return null;
        String own = ownHost == null ? "" : ownHost.toLowerCase(Locale.ROOT);
        int colon = own.indexOf(':');
        if (colon > 0) own = own.substring(0, colon);
        return host.equalsIgnoreCase(own) ? null : host;
    }

    // ================================================================ insertion points

    /**
     * For async postbacks: the update panel and triggering control IDs inside the ScriptManager field
     * ({@code ScriptManager1=Panel|Trigger}). Burp only sees the whole field; replacing it breaks the {@code |}
     * structure, so the page fails before it processes the trigger. JSON service bodies and ordinary form fields are
     * left to Burp.
     */
    @Override
    public List<InsertionPoint> insertionPoints(MessageContext request, DecodeResult decoded) {
        if (decoded == null || !"ASP.NET AJAX async postback".equals(decoded.root().name())) return List.of();
        DecodedNode post = decoded.root().get("Async postback");
        DecodedNode sm = post == null ? null : post.get("ScriptManager field");
        String field = val(sm, "Name");
        String rawValue = val(sm, "Raw value");
        if (field == null || rawValue == null) return List.of();
        String body = Codecs.latin1String(request.requestBody());
        String current = Codecs.first(Codecs.parseQuery(body), field);
        if (current == null || !current.equals(rawValue)) return List.of();
        int bar = current.indexOf('|');
        String panel = current.substring(0, bar), trigger = current.substring(bar + 1);
        return List.of(
                InsertionPoint.body("ASP.NET AJAX: " + field + " update panel", panel,
                        p -> Codecs.latin1Bytes(InsertionPoints.replaceFormField(body, field, 0, p + "|" + trigger))),
                InsertionPoint.body("ASP.NET AJAX: " + field + " trigger", trigger,
                        p -> Codecs.latin1Bytes(InsertionPoints.replaceFormField(body, field, 0, panel + "|" + p))));
    }

    // ================================================================ active

    /** Type-mismatched JSON argument to a service method; reports exception details in the error. */
    static final class VerboseServiceErrors implements ActiveCheck {
        @Override public String id() { return "aspnet-ajax.verbose-service-errors"; }
        @Override public String name() { return "ASMX/WCF verbose errors"; }
        @Override public String description() {
            return "JSON calls to .asmx/.svc/PageMethods: resends once with a type-mismatched argument and checks for ExceptionType/StackTrace (1 request)";
        }
        @Override public Scope scope() { return Scope.PER_REQUEST; }

        @Override
        public List<Finding> run(ActiveContext ctx) {
            MessageContext base = ctx.base();
            if (!"POST".equalsIgnoreCase(base.method()) || base.path() == null || !SERVICE_METHOD.matcher(base.path()).find()) return List.of();
            if (!base.requestContentType().toLowerCase(Locale.ROOT).contains("json")) return List.of();
            if (ctx.baseResponse() != null) {
                ErrorInfo already = errorInfo(ctx.baseResponse().responseBodyText());
                if (already != null && already.detailed()) return List.of(); // the passive check reports it
            }
            String body = Codecs.utf8(Codecs.decodeContent(base.requestBody(), base.requestHeader("Content-Encoding"))).strip();
            JsonElement json = body.isEmpty() ? new JsonObject() : JsonTree.parseStrict(body);
            String probe;
            if (json != null && json.isJsonObject() && !json.getAsJsonObject().isEmpty()) {
                JsonObject o = json.getAsJsonObject().deepCopy();
                String first = o.keySet().iterator().next();
                JsonArray nested = new JsonArray();
                nested.add(new JsonArray());
                o.add(first, nested); // [[]] converts to no scalar or simple object type
                probe = o.toString();
            } else {
                probe = "{\"pdProbe\":"; // truncated JSON
            }
            List<Header> headers = new ArrayList<>();
            for (Header h : base.requestHeaders()) if (!h.name().equalsIgnoreCase("Content-Encoding")) headers.add(h);
            String target = base.path() + (base.query() == null || base.query().isEmpty() ? "" : "?" + base.query());
            Exchange x = ctx.http().send(base.method(), target, headers, probe.getBytes(StandardCharsets.UTF_8));
            if (x == null || !x.hasResponse()) return List.of();
            ErrorInfo info = errorInfo(x.responseText());
            if (info == null || !info.detailed()) return List.of();
            Finding f = errorFinding(id(), info, "Sending a type-mismatched argument (<code>" + Finding.esc(Codecs.truncate(probe, 200)) + "</code>) to the service");
            return List.of(f.exchange(x));
        }
    }

    /** Requests the /js and /jsdebug proxies of a JSON service seen in scanned traffic. */
    static final class ProxyScriptExposure implements ActiveCheck {
        private static final int MAX_SERVICES = 5_000;
        private final Set<String> probed = ConcurrentHashMap.newKeySet();

        @Override public String id() { return "aspnet-ajax.proxy-script-exposure"; }
        @Override public String name() { return "Proxy script exposure"; }
        @Override public String description() {
            return "For each .asmx/.svc service seen in a JSON call, requests <service>/js and <service>/jsdebug once (≤2 requests per service) and lists exposed methods";
        }
        // Per request + per-service memo rather than PER_HOST: Burp's per-host base request is rarely a service call.
        @Override public Scope scope() { return Scope.PER_REQUEST; }

        @Override
        public List<Finding> run(ActiveContext ctx) {
            MessageContext base = ctx.base();
            Matcher s = SERVICE.matcher(base.path() == null ? "" : base.path());
            if (!s.find() || PROXY.matcher(base.path()).find()) return List.of();
            String key = (base.host() == null ? "" : base.host().toLowerCase(Locale.ROOT)) + s.group(1).toLowerCase(Locale.ROOT);
            if (probed.size() >= MAX_SERVICES || !probed.add(key)) return List.of();
            List<Header> headers = new ArrayList<>();
            for (Header h : base.requestHeaders()) {
                String n = h.name().toLowerCase(Locale.ROOT);
                if (!n.equals("content-type") && !n.equals("content-length") && !n.equals("content-encoding") && !n.equals("x-microsoftajax")) headers.add(h);
            }
            AspNetAjaxDecoder dec = new AspNetAjaxDecoder();
            List<Finding> out = new ArrayList<>();
            for (String variant : new String[]{"js", "jsdebug"}) {
                Exchange x = ctx.http().send("GET", s.group(1) + "/" + variant, headers, new byte[0]);
                if (x == null || !x.hasResponse() || x.status() != 200) continue;
                DecodeResult r;
                try {
                    MessageContext resp = x.message().withKind(MessageKind.RESPONSE);
                    r = dec.decode(resp);
                } catch (DecodeException | RuntimeException e) {
                    continue;
                }
                if (!"ASP.NET AJAX service proxy".equals(r.root().name())) continue;
                if (out.isEmpty()) out.addAll(proxyFinding(id(), r, x));
                else out.get(0).exchange(x);
            }
            return out;
        }
    }
}
