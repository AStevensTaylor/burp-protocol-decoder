package protocoldecoder.builtin.aspnetajax;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.ProtocolDecoder;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ASP.NET AJAX (System.Web.Extensions): WebForms UpdatePanel partial rendering, ASMX / WCF "AJAX-enabled" JSON services,
 * PageMethods, their generated JavaScript proxies, and ScriptResource.axd / WebResource.axd references.
 *
 * <p>Async postback requests carry {@code X-MicrosoftAjax: Delta=true} and {@code __ASYNCPOST=true}; their responses
 * are in the length-prefixed "delta" format parsed by {@link DeltaParser}. JSON service responses wrap the result in
 * {@code {"d": …}} and use {@code "\/Date(ms)\/"} dates and {@code __type} hints (see {@link MsJson}).</p>
 *
 * <p>Client callbacks ({@code __CALLBACKID}) are left to the DevExpress decoder.</p>
 */
public final class AspNetAjaxDecoder implements ProtocolDecoder {

    public static final String ID = "aspnet-ajax";

    private static final Pattern SERVICE_PATH = Pattern.compile("(?i)([^/]*\\.(asmx|svc))/([A-Za-z_][A-Za-z0-9_]*)$");
    private static final Pattern PAGE_METHOD_PATH = Pattern.compile("(?i)([^/]*\\.aspx)/([A-Za-z_][A-Za-z0-9_]*)$");
    private static final Pattern PROXY_PATH = Pattern.compile("(?i)([^/]*\\.(asmx|svc))/(js|jsdebug)$");
    private static final Pattern AXD_PATH = Pattern.compile("(?i)/(ScriptResource|WebResource)\\.axd$");
    private static final Pattern D_WRAPPER = Pattern.compile("^\\{\\s*\"d\"\\s*:");
    private static final Pattern ERROR_START = Pattern.compile("^\\{\\s*\"(Message|ExceptionDetail)\"\\s*:");
    private static final Pattern ASPNET_STATE = Pattern.compile("^__(VIEWSTATE.*|EVENTVALIDATION|PREVIOUSPAGE|LASTFOCUS|SCROLLPOSITION[XY]|VIEWSTATEGENERATOR|VIEWSTATEENCRYPTED|REQUESTDIGEST)$");

    private static final Pattern PROXY_METHOD = Pattern.compile(
            "_invoke\\(\\s*this\\._get_path\\(\\)\\s*,\\s*'([^']+)'\\s*,\\s*(true|false)\\s*,\\s*\\{([^}]*)\\}");
    private static final Pattern PROXY_SET_PATH = Pattern.compile("set_path\\(\\s*[\"']([^\"']+)[\"']\\s*\\)");
    private static final Pattern PROXY_CLASS = Pattern.compile("registerClass\\(\\s*'([^']+)'\\s*,\\s*Sys\\.Net\\.WebServiceProxy");
    private static final Pattern PROXY_TYPE = Pattern.compile("registerClass\\(\\s*'([^']+)'\\s*\\)");
    private static final Pattern PROXY_ENUM = Pattern.compile("registerEnum\\(\\s*'([^']+)'");

    private static final int SNIFF = 64 * 1024;
    private static final int MAX_RECORDS = 20_000;
    private static final int MAX_CONTENT = 256 * 1024;
    private static final int MAX_LIST = 2_000;
    /** .NET ticks at the Unix epoch. */
    private static final long EPOCH_TICKS = 621_355_968_000_000_000L;

    @Override public String id() { return ID; }
    @Override public String name() { return "ASP.NET AJAX"; }
    @Override public String description() {
        return "ASP.NET AJAX: UpdatePanel async postbacks and delta responses, ASMX/WCF/PageMethod JSON services, ScriptResource.axd";
    }

    // ================================================================ matching

    @Override
    public MatchResult match(MessageContext m) {
        try {
            if (m.isWebSocket()) return MatchResult.NONE;
            return m.isRequest() ? matchRequest(m) : matchResponse(m);
        } catch (RuntimeException e) {
            return MatchResult.NONE;
        }
    }

    private static boolean deltaHeader(MessageContext m) {
        String h = m.requestHeader("X-MicrosoftAjax");
        return h != null && h.toLowerCase(Locale.ROOT).contains("delta=true");
    }

    private static boolean asyncPostField(MessageContext m) {
        byte[] b = m.requestBody();
        if (b.length == 0) return false;
        String body = m.requestBodyText();
        return body.contains("__ASYNCPOST=true") && !body.contains("__CALLBACKID=");
    }

    private static boolean jsonContentType(String ct) {
        return ct != null && ct.toLowerCase(Locale.ROOT).contains("json");
    }

    private MatchResult matchRequest(MessageContext m) {
        if (deltaHeader(m)) return MatchResult.of(95, "X-MicrosoftAjax: Delta=true async postback");
        if (asyncPostField(m)) return MatchResult.of(85, "__ASYNCPOST=true form post");
        String path = m.path();
        if (PROXY_PATH.matcher(path).find()) return MatchResult.of(40, "ASP.NET AJAX service proxy script request");
        boolean json = jsonContentType(m.requestContentType());
        if (json && SERVICE_PATH.matcher(path).find()) return MatchResult.of(80, "JSON call to an ASMX/WCF service method");
        if (json && PAGE_METHOD_PATH.matcher(path).find()) return MatchResult.of(75, "JSON call to an ASP.NET PageMethod");
        if (AXD_PATH.matcher(path).find() && m.queryParameters().containsKey("d")) {
            return MatchResult.of(40, "ScriptResource/WebResource.axd reference");
        }
        return MatchResult.NONE;
    }

    private MatchResult matchResponse(MessageContext m) {
        byte[] raw = m.responseBody();
        if (raw.length == 0) return MatchResult.NONE;
        boolean digit = startsWithLengthPrefix(raw);
        boolean compressed = Codecs.isGzip(raw) || m.responseHeader("Content-Encoding") != null;
        String text = null;
        if (digit || (compressed && deltaHeader(m))) {
            text = Codecs.utf8(Codecs.decodeContent(raw, m.responseHeader("Content-Encoding")));
            if (DeltaParser.looksLikeDelta(text, 3)) return MatchResult.of(95, "ASP.NET AJAX delta response");
        }
        if (deltaHeader(m)) return MatchResult.NONE;

        String path = m.path();
        boolean servicePath = SERVICE_PATH.matcher(path).find() && !PROXY_PATH.matcher(path).find();
        boolean pageMethod = PAGE_METHOD_PATH.matcher(path).find()
                && (jsonContentType(m.requestContentType()) || jsonContentType(m.responseHeader("Content-Type")));
        boolean proxy = PROXY_PATH.matcher(path).find();
        if (!servicePath && !pageMethod && !proxy) {
            // Error objects and __type-hinted d wrappers are recognisable on their own; skip everything else cheaply.
            byte first = firstNonSpace(raw);
            if (first != '{' && !compressed) return MatchResult.NONE;
        }
        if (text == null) text = Codecs.utf8(Codecs.decodeContent(raw, m.responseHeader("Content-Encoding")));
        String head = (text.length() > SNIFF ? text.substring(0, SNIFF) : text).strip();
        if (head.isEmpty()) return MatchResult.NONE;

        if (proxy) {
            if (head.contains("Sys.Net.WebServiceProxy") || head.contains("_invoke(this._get_path()")) {
                return MatchResult.of(80, "ASP.NET AJAX generated service proxy");
            }
            return MatchResult.NONE;
        }
        boolean object = head.startsWith("{");
        if (object && (servicePath || pageMethod) && D_WRAPPER.matcher(head).find()) {
            return MatchResult.of(80, "{\"d\": …} response from an ASP.NET AJAX service method");
        }
        if (object && ("true".equalsIgnoreCase(trim(m.responseHeader("jsonerror")))
                || (ERROR_START.matcher(head).find() && head.contains("\"ExceptionType\"")))) {
            return MatchResult.of(80, "ASP.NET service error object");
        }
        if (object && D_WRAPPER.matcher(head).find() && head.contains("\"__type\"")) {
            return MatchResult.of(60, "{\"d\": …} response with __type hints");
        }
        if ((servicePath || pageMethod) && (object || head.startsWith("["))) {
            return MatchResult.of(60, "JSON response from an ASP.NET AJAX service method");
        }
        return MatchResult.NONE;
    }

    /** {@code \d{1,9}|} at the start of the body. */
    private static boolean startsWithLengthPrefix(byte[] b) {
        for (int i = 0; i < Math.min(b.length, 10); i++) {
            if (b[i] == '|') return i > 0;
            if (b[i] < '0' || b[i] > '9') return false;
        }
        return false;
    }

    private static byte firstNonSpace(byte[] b) {
        for (int i = 0; i < Math.min(b.length, 64); i++) {
            if (b[i] != ' ' && b[i] != '\t' && b[i] != '\r' && b[i] != '\n' && (b[i] & 0xff) != 0xef && (b[i] & 0xff) != 0xbb
                    && (b[i] & 0xff) != 0xbf) {
                return b[i];
            }
        }
        return 0;
    }

    private static String trim(String s) {
        return s == null ? null : s.trim();
    }

    // ================================================================ decoding

    @Override
    public DecodeResult decode(MessageContext m) throws DecodeException {
        if (m.isWebSocket()) throw new DecodeException("ASP.NET AJAX does not use WebSockets");
        return m.isResponse() ? decodeResponse(m) : decodeRequest(m);
    }

    // ---------------------------------------------------------------- requests

    private DecodeResult decodeRequest(MessageContext m) throws DecodeException {
        String path = m.path();
        if (deltaHeader(m) || asyncPostField(m)) return decodeAsyncPostback(m, true);
        if (PROXY_PATH.matcher(path).find()) return decodeProxyRequest(m);
        if (SERVICE_PATH.matcher(path).find() || PAGE_METHOD_PATH.matcher(path).find()) return decodeServiceRequest(m);
        if (AXD_PATH.matcher(path).find()) return decodeAxd(m);
        Map<String, List<String>> form = formParams(m);
        if (form.containsKey("__VIEWSTATE") || form.containsKey("__EVENTTARGET")) return decodeAsyncPostback(m, false);
        throw new DecodeException("Not an ASP.NET AJAX request: no X-MicrosoftAjax header or __ASYNCPOST field, and the path is "
                + "not an .asmx/.svc/.aspx method, proxy script or ScriptResource/WebResource.axd");
    }

    private static Map<String, List<String>> formParams(MessageContext m) {
        Map<String, List<String>> params = m.formParameters();
        if (params.isEmpty() && m.requestBody().length > 0) {
            String body = Codecs.utf8(Codecs.decodeContent(m.requestBody(), m.requestHeader("Content-Encoding")));
            if (body.contains("=") && !body.strip().startsWith("{") && !body.strip().startsWith("<")) params = Codecs.parseQuery(body);
        }
        return params;
    }

    private DecodeResult decodeAsyncPostback(MessageContext m, boolean async) throws DecodeException {
        Map<String, List<String>> params = formParams(m);
        if (params.isEmpty()) throw new DecodeException("No form fields in the request body");
        List<String> warnings = new ArrayList<>();
        if (!async) warnings.add("Not an async postback (no X-MicrosoftAjax header or __ASYNCPOST field); showing it as a regular WebForms postback");

        DecodedNode root = DecodedNode.object(async ? "ASP.NET AJAX async postback" : "ASP.NET WebForms postback");
        DecodedNode post = root.child(async ? "Async postback" : "Postback");

        String smKey = null, smValue = null;
        for (Map.Entry<String, List<String>> e : params.entrySet()) {
            if (e.getKey().startsWith("__") || e.getValue().isEmpty()) continue;
            if (e.getValue().get(0).contains("|")) {
                smKey = e.getKey();
                smValue = e.getValue().get(0);
                break;
            }
        }
        String panels = null, trigger = null;
        if (smKey != null) {
            int bar = smValue.indexOf('|');
            panels = smValue.substring(0, bar);
            trigger = smValue.substring(bar + 1);
            DecodedNode sm = post.child("ScriptManager field");
            sm.put("Name", smKey);
            sm.put("Raw value", smValue);
            if (panels.contains(",")) {
                DecodedNode arr = DecodedNode.array("Update panels");
                for (String p : panels.split(",")) arr.add(DecodedNode.leaf("", p));
                sm.add(arr);
            } else {
                sm.put("Update panel", panels);
            }
            sm.put("Triggering control", trigger);
        } else if (async) {
            warnings.add("No ScriptManager field (name=Panel|Control) found");
        }
        String target = Codecs.first(params, "__EVENTTARGET");
        String argument = Codecs.first(params, "__EVENTARGUMENT");
        post.put("Event target (__EVENTTARGET)", target);
        post.put("Event argument (__EVENTARGUMENT)", argument);
        post.put("__ASYNCPOST", Codecs.first(params, "__ASYNCPOST"));
        post.put("X-MicrosoftAjax", m.requestHeader("X-MicrosoftAjax"));

        DecodedNode state = DecodedNode.object("ASP.NET state");
        DecodedNode other = DecodedNode.object("Form fields");
        for (Map.Entry<String, List<String>> e : params.entrySet()) {
            String k = e.getKey();
            if (k.equals(smKey) || k.equals("__EVENTTARGET") || k.equals("__EVENTARGUMENT") || k.equals("__ASYNCPOST")) continue;
            for (String v : e.getValue()) {
                if (ASPNET_STATE.matcher(k).matches()) state.add(stateField(k, v));
                else other.add(smartValue(k, v));
            }
        }
        if (!state.isLeaf()) root.add(state);
        if (!other.isLeaf()) root.add(other);

        StringBuilder summary = new StringBuilder(async ? "Async postback" : "Postback");
        if (panels != null) {
            summary.append(" → ").append(shortIds(panels));
            if (!trigger.isEmpty()) summary.append(" via ").append(shortId(trigger));
        } else if (target != null && !target.isEmpty()) {
            summary.append(" → ").append(shortId(target));
        }
        if (argument != null && !argument.isEmpty()) summary.append(" [arg: ").append(Codecs.truncate(argument, 40)).append(']');
        return new DecodeResult(summary.toString(), root, null, warnings);
    }

    private static DecodedNode stateField(String k, String v) {
        if (k.startsWith("__VIEWSTATE") && v.length() > 200) {
            return DecodedNode.leaf(k, Codecs.truncate(v, 200) + "  (use Burp's ViewState tab to decode)");
        }
        return DecodedNode.leaf(k, v);
    }

    private static DecodedNode smartValue(String name, String v) {
        if (JsonTree.looksLikeJson(v)) {
            JsonElement e = JsonTree.parseLenient(v);
            if (e != null) return MsJson.toNode(name, e);
        }
        return MsJson.html(name, Codecs.truncate(v, MAX_CONTENT));
    }

    private static String shortId(String id) {
        int i = id.lastIndexOf('$');
        return i >= 0 && i < id.length() - 1 ? id.substring(i + 1) : id;
    }

    private static String shortIds(String ids) {
        List<String> out = new ArrayList<>();
        for (String s : ids.split(",")) out.add(shortId(s));
        return String.join(", ", out);
    }

    // ---------------------------------------------------------------- JSON services

    private record ServiceInfo(String kind, String file, String method) {
    }

    private static ServiceInfo serviceInfo(String path) {
        Matcher s = SERVICE_PATH.matcher(path);
        if (s.find() && !PROXY_PATH.matcher(path).find()) {
            return new ServiceInfo(s.group(2).equalsIgnoreCase("svc") ? "WCF" : "ASMX", s.group(1), s.group(3));
        }
        Matcher p = PAGE_METHOD_PATH.matcher(path);
        if (p.find()) return new ServiceInfo("PageMethod", p.group(1), p.group(2));
        return null;
    }

    private DecodeResult decodeServiceRequest(MessageContext m) throws DecodeException {
        ServiceInfo info = serviceInfo(m.path());
        if (info == null) throw new DecodeException("Path is not an ASP.NET AJAX service method");
        List<String> warnings = new ArrayList<>();
        DecodedNode root = DecodedNode.object("ASP.NET AJAX service call");
        DecodedNode call = root.child("Call");
        call.put("Kind", info.kind());
        call.put("Service", info.file());
        call.put("Method", info.method());
        call.put("HTTP method", m.method());

        List<String> argNames = new ArrayList<>();
        String body = Codecs.utf8(Codecs.decodeContent(m.requestBody(), m.requestHeader("Content-Encoding")));
        if (!body.isBlank()) {
            JsonElement json = JsonTree.parseStrict(body);
            if (json == null) json = JsonTree.parseLenient(body);
            if (json == null) {
                warnings.add("Request body is not JSON");
                root.add(DecodedNode.leaf("Body", Codecs.truncate(body, MAX_CONTENT)));
            } else {
                root.add(MsJson.toNode("Arguments", json));
                if (json.isJsonObject()) argNames.addAll(json.getAsJsonObject().keySet());
            }
        }
        Map<String, List<String>> query = m.queryParameters();
        if (!query.isEmpty()) {
            // ScriptMethod(UseHttpGet = true): each argument is a JSON-encoded query parameter.
            DecodedNode q = root.child("Query arguments");
            for (Map.Entry<String, List<String>> e : query.entrySet()) {
                for (String v : e.getValue()) {
                    JsonElement j = JsonTree.parseStrict(v);
                    q.add(j != null ? MsJson.toNode(e.getKey(), j) : DecodedNode.leaf(e.getKey(), v));
                }
                argNames.add(e.getKey());
            }
        }
        if (!jsonContentType(m.requestContentType()) && m.requestBody().length > 0) {
            warnings.add("Request Content-Type is not JSON; ASP.NET AJAX services require application/json");
        }
        String summary = info.kind() + " call → " + info.file() + "/" + info.method() + "(" + String.join(", ", argNames) + ")";
        return new DecodeResult(summary, root, null, warnings);
    }

    private DecodeResult decodeServiceResponse(MessageContext m, String text) throws DecodeException {
        JsonElement json = JsonTree.parseStrict(text);
        if (json == null) json = JsonTree.parseLenient(text);
        if (json == null) throw new DecodeException("Response body is not valid JSON");
        ServiceInfo info = serviceInfo(m.path());
        List<String> warnings = new ArrayList<>();
        DecodedNode root = DecodedNode.object("ASP.NET AJAX service response");
        String label = info == null ? "Service" : info.kind() + " " + info.method();
        String summary;

        if (MsJson.isErrorObject(json)) {
            JsonObject o = json.getAsJsonObject();
            root.add(MsJson.toNode("Error", o));
            String type = MsJson.str(o, "ExceptionType");
            String msg = MsJson.str(o, "Message");
            StringBuilder sb = new StringBuilder(label).append(" error");
            if (type != null && !type.isBlank()) sb.append(": ").append(type);
            if (msg != null && !msg.isBlank()) sb.append(": ").append(Codecs.truncate(oneLine(msg), 120));
            summary = sb.toString();
            if (MsJson.hasStackTrace(o)) {
                warnings.add("Response discloses a server stack trace (customErrors off / includeExceptionDetailInFaults on)");
            }
        } else if (json.isJsonObject() && json.getAsJsonObject().has("d")) {
            JsonObject o = json.getAsJsonObject();
            root.add(MsJson.toNode("d (result)", o.get("d")));
            for (Map.Entry<String, JsonElement> e : o.entrySet()) {
                if (!e.getKey().equals("d")) root.add(MsJson.toNode(e.getKey(), e.getValue()));
            }
            summary = label + " → " + describe(o.get("d"));
        } else {
            root.add(MsJson.toNode("Body", json));
            summary = label + " response (no \"d\" wrapper) → " + describe(json);
        }
        if ("true".equalsIgnoreCase(trim(m.responseHeader("jsonerror")))) root.put("jsonerror header", "true");
        return new DecodeResult(summary, root, null, warnings);
    }

    private static String describe(JsonElement e) {
        if (e == null || e.isJsonNull()) return "null";
        if (e.isJsonObject()) {
            JsonObject o = e.getAsJsonObject();
            String t = MsJson.str(o, "__type");
            if (t != null) return simpleType(MsJson.typeName(t));
            List<String> keys = new ArrayList<>(o.keySet());
            return "{" + String.join(", ", keys.subList(0, Math.min(4, keys.size()))) + (keys.size() > 4 ? ", …" : "") + "}";
        }
        if (e.isJsonArray()) {
            JsonArray a = e.getAsJsonArray();
            String of = "";
            if (!a.isEmpty() && a.get(0).isJsonObject()) {
                String t = MsJson.str(a.get(0).getAsJsonObject(), "__type");
                if (t != null) of = " of " + simpleType(MsJson.typeName(t));
            }
            return "array[" + a.size() + "]" + of;
        }
        String s = e.getAsString();
        if (e.getAsJsonPrimitive().isString()) {
            String iso = MsJson.isoDate(s);
            return iso != null ? iso : "\"" + Codecs.truncate(oneLine(s), 60) + "\"";
        }
        return s;
    }

    private static String simpleType(String full) {
        int i = full.lastIndexOf('.');
        return i >= 0 && i < full.length() - 1 ? full.substring(i + 1) : full;
    }

    private static String oneLine(String s) {
        return s.replaceAll("\\s+", " ").strip();
    }

    // ---------------------------------------------------------------- proxy scripts

    private DecodeResult decodeProxyRequest(MessageContext m) {
        Matcher p = PROXY_PATH.matcher(m.path());
        p.find();
        DecodedNode root = DecodedNode.object("ASP.NET AJAX proxy script request");
        root.put("Service", p.group(1));
        root.put("Variant", p.group(3));
        root.add(DecodedNode.note("Requests the JavaScript proxy ASP.NET generates for this service; the response lists every "
                + "exposed method and its parameters (useful for attack surface enumeration)."));
        return DecodeResult.of((p.group(2).equalsIgnoreCase("svc") ? "WCF" : "ASMX") + " proxy script request → " + p.group(1), root);
    }

    private DecodeResult decodeProxyScript(String text) throws DecodeException {
        DecodedNode root = DecodedNode.object("ASP.NET AJAX service proxy");
        Matcher cls = PROXY_CLASS.matcher(text);
        String service = cls.find() ? cls.group(1) : null;
        Matcher path = PROXY_SET_PATH.matcher(text);
        String servicePath = path.find() ? path.group(1) : null;
        root.put("Proxy class", service);
        root.put("Service path", servicePath);

        DecodedNode methods = DecodedNode.array("Methods");
        Set<String> seen = new LinkedHashSet<>();
        Matcher mm = PROXY_METHOD.matcher(text);
        while (mm.find() && seen.size() < MAX_LIST) {
            if (!seen.add(mm.group(1))) continue;
            DecodedNode n = DecodedNode.object(mm.group(1));
            n.put("HTTP", mm.group(2).equals("true") ? "GET" : "POST");
            DecodedNode params = DecodedNode.array("Parameters");
            for (String part : mm.group(3).split(",")) {
                String name = part.contains(":") ? part.substring(0, part.indexOf(':')).trim() : part.trim();
                if (!name.isEmpty()) params.add(DecodedNode.leaf("", name));
            }
            n.add(params);
            methods.add(n);
        }
        if (service == null && seen.isEmpty()) throw new DecodeException("Not an ASP.NET AJAX proxy script (no Sys.Net.WebServiceProxy class or _invoke calls)");
        root.add(methods);

        DecodedNode types = DecodedNode.array("Data contract types");
        Set<String> typeNames = new LinkedHashSet<>();
        Matcher t = PROXY_TYPE.matcher(text);
        while (t.find() && typeNames.size() < MAX_LIST) typeNames.add(t.group(1));
        Matcher en = PROXY_ENUM.matcher(text);
        while (en.find() && typeNames.size() < MAX_LIST) typeNames.add(en.group(1) + " (enum)");
        for (String s : typeNames) types.add(DecodedNode.leaf("", s));
        if (!types.isLeaf()) root.add(types);

        String summary = "Service proxy" + (service == null ? "" : ": " + service) + (servicePath == null ? "" : " at " + servicePath)
                + ", " + seen.size() + (seen.size() == 1 ? " method" : " methods");
        return DecodeResult.of(summary, root);
    }

    // ---------------------------------------------------------------- axd

    private DecodeResult decodeAxd(MessageContext m) throws DecodeException {
        Matcher h = AXD_PATH.matcher(m.path());
        if (!h.find()) throw new DecodeException("Not a ScriptResource.axd / WebResource.axd request");
        Map<String, List<String>> q = m.queryParameters();
        String d = Codecs.first(q, "d");
        if (d == null) throw new DecodeException(h.group(1) + ".axd request without a d parameter");
        String handler = h.group(1) + ".axd";
        DecodedNode root = DecodedNode.object(handler + " request");
        DecodedNode dn = root.child("d (resource reference)");
        dn.put("Raw", d);
        byte[] bytes = urlTokenDecode(d);
        if (bytes != null) {
            dn.put("Encrypted bytes", bytes.length);
            dn.add(DecodedNode.leaf("Hex", Codecs.hexPreview(bytes, 48), DecodedNode.Type.BINARY));
        } else {
            dn.add(DecodedNode.note("Not valid URL-token (base64url + padding digit) encoding"));
        }
        dn.add(DecodedNode.note("Encrypted and signed with the application's machine key (identifies the assembly and "
                + "resource / script path); it cannot be decoded without the key. Pre-MS10-070 servers were vulnerable to "
                + "a padding oracle through this parameter."));

        String t = Codecs.first(q, "t");
        if (t != null) {
            DecodedNode tn = root.child("t (cache-busting timestamp)");
            tn.put("Raw", t);
            String date = ticksToDate(t);
            if (date != null) tn.put("As .NET ticks", date);
            else tn.add(DecodedNode.note("Not a plausible .NET ticks value (often a hashed or truncated assembly timestamp); left raw"));
        }
        DecodedNode other = DecodedNode.object("Other parameters");
        for (Map.Entry<String, List<String>> e : q.entrySet()) {
            if (e.getKey().equals("d") || e.getKey().equals("t")) continue;
            for (String v : e.getValue()) other.put(e.getKey(), v);
        }
        if (!other.isLeaf()) root.add(other);
        String summary = handler + " resource request (encrypted d" + (bytes == null ? "" : ", " + bytes.length + " bytes") + ")";
        return DecodeResult.of(summary, root);
    }

    /** HttpServerUtility.UrlTokenDecode: base64url without '=' padding, followed by a digit giving the pad count. */
    static byte[] urlTokenDecode(String s) {
        if (s == null || s.length() < 2) return null;
        char pad = s.charAt(s.length() - 1);
        if (pad < '0' || pad > '2') return null;
        String body = s.substring(0, s.length() - 1);
        if (!body.chars().allMatch(c -> Character.isLetterOrDigit(c) && c < 128 || c == '-' || c == '_')) return null;
        if ((body.length() + (pad - '0')) % 4 != 0) return null;
        try {
            return java.util.Base64.getUrlDecoder().decode(body + "==".substring(0, pad - '0'));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Interprets a decimal or hex value as .NET DateTime ticks, accepting only dates between 2000 and 2100. */
    static String ticksToDate(String t) {
        long ticks;
        try {
            if (t.matches("\\d{17,19}")) ticks = Long.parseLong(t);
            else if (t.matches("(?i)[0-9a-f]{15,16}")) ticks = Long.parseUnsignedLong(t, 16);
            else return null;
        } catch (NumberFormatException e) {
            return null;
        }
        if (ticks < 630_822_816_000_000_000L || ticks > 662_380_416_000_000_000L) return null; // 2000-01-01 .. 2100-01-01
        long ms = (ticks - EPOCH_TICKS) / 10_000;
        return Instant.ofEpochMilli(ms).toString();
    }

    // ---------------------------------------------------------------- responses

    private DecodeResult decodeResponse(MessageContext m) throws DecodeException {
        byte[] bytes = Codecs.decodeContent(m.responseBody(), m.responseHeader("Content-Encoding"));
        String text = Codecs.utf8(bytes);
        if (!text.isEmpty() && text.charAt(0) == '﻿') text = text.substring(1);
        if (text.isBlank()) throw new DecodeException("Empty response body");

        String deltaError = null;
        if (Character.isDigit(text.charAt(0))) {
            DeltaParser.Result r = DeltaParser.parse(text, MAX_RECORDS);
            if (!r.records().isEmpty()) return decodeDelta(m, text, r);
            deltaError = r.error();
        }
        String stripped = text.strip();
        if (stripped.startsWith("{") || stripped.startsWith("[")) return decodeServiceResponse(m, stripped);
        if (PROXY_PATH.matcher(m.path()).find() || text.contains("Sys.Net.WebServiceProxy")) return decodeProxyScript(text);
        throw new DecodeException(deltaError != null
                ? "Not a valid ASP.NET AJAX delta response: " + deltaError
                : "Response is not an ASP.NET AJAX delta, JSON service response or service proxy script");
    }

    private DecodeResult decodeDelta(MessageContext m, String text, DeltaParser.Result r) {
        List<String> warnings = new ArrayList<>();
        DecodedNode root = DecodedNode.object("ASP.NET AJAX delta");
        DecodedNode error = DecodedNode.object("Error");
        DecodedNode redirect = DecodedNode.object("Redirect");
        DecodedNode panels = DecodedNode.object("Updated panels");
        DecodedNode hidden = DecodedNode.object("Hidden fields");
        DecodedNode page = DecodedNode.object("Page");
        DecodedNode ids = DecodedNode.object("Control ID lists");
        DecodedNode scripts = DecodedNode.array("Scripts");
        DecodedNode data = DecodedNode.object("Data items");
        DecodedNode other = DecodedNode.array("Other records");
        DecodedNode index = DecodedNode.array("Record index");

        int panelCount = 0, hiddenCount = 0, dataCount = 0, scriptCount = 0;
        String redirectUrl = null, errorText = null;
        Set<String> unknown = new LinkedHashSet<>();
        int i = 0;
        for (DeltaParser.Record rec : r.records()) {
            String type = rec.type();
            String id = rec.id();
            String content = rec.content();
            index.add(DecodedNode.leaf("[" + i++ + "]", type + (id.isEmpty() ? "" : " #" + id) + " (" + rec.length() + " chars)"));
            switch (type) {
                case "updatePanel" -> {
                    panelCount++;
                    panels.add(DecodedNode.leaf(id, Codecs.truncate(content, MAX_CONTENT), DecodedNode.Type.HTML));
                }
                case "hiddenField" -> {
                    hiddenCount++;
                    hidden.add(stateField(id, content));
                }
                case "asyncPostBackControlIDs", "postBackControlIDs", "updatePanelIDs", "childUpdatePanelIDs", "panelsToRefreshIDs" ->
                        ids.add(idList(type, content));
                case "asyncPostBackTimeout" -> page.add(DecodedNode.leaf("asyncPostBackTimeout (s)", content,
                        content.matches("\\d+") ? DecodedNode.Type.NUMBER : DecodedNode.Type.STRING));
                case "formAction" -> page.put("formAction", content);
                case "pageTitle" -> page.put("pageTitle", content);
                case "focus" -> page.put("focus", content.isEmpty() ? id : content);
                case "scriptBlock", "scriptStartupBlock", "fallbackScript", "scriptDispose", "onSubmit", "arrayDeclaration", "expando" -> {
                    scriptCount++;
                    scripts.add(scriptNode(type, id, content));
                }
                case "dataItem" -> {
                    dataCount++;
                    data.add(smartValue(id, content));
                }
                case "dataItemJson" -> {
                    dataCount++;
                    JsonElement j = JsonTree.parseLenient(content);
                    if (j != null) {
                        data.add(MsJson.toNode(id + " (JSON)", j));
                    } else {
                        data.add(DecodedNode.leaf(id, Codecs.truncate(content, MAX_CONTENT)));
                        warnings.add("dataItemJson '" + id + "' is not valid JSON");
                    }
                }
                case "pageRedirect" -> {
                    String decoded = content.contains("%") ? Codecs.urlDecode(content) : content;
                    redirect.put("URL", content);
                    if (!decoded.equals(content)) redirect.put("URL (decoded)", decoded);
                    if (redirectUrl == null) redirectUrl = decoded;
                }
                case "error" -> {
                    error.put("HTTP status (id)", id);
                    error.add(MsJson.html("Message", Codecs.truncate(content, MAX_CONTENT)));
                    if (errorText == null) errorText = "error " + id + ": " + Codecs.truncate(oneLine(content), 120);
                }
                default -> {
                    unknown.add(type);
                    DecodedNode n = DecodedNode.object(type);
                    n.put("id", id);
                    n.add(MsJson.html("content", Codecs.truncate(content, MAX_CONTENT)));
                    other.add(n);
                }
            }
        }
        if (!unknown.isEmpty()) warnings.add("Unknown delta record type(s): " + String.join(", ", unknown));
        if (r.capped()) warnings.add("Stopped after " + MAX_RECORDS + " records; the rest is not shown");
        if (r.error() != null) {
            String tail = text.substring(r.errorOffset());
            warnings.add("Malformed delta at character " + r.errorOffset() + ": " + r.error() + "; " + tail.length()
                    + " characters not decoded" + (m.truncated() ? " (the body was truncated by the size limit)" : ""));
            other.add(DecodedNode.leaf("Undecoded tail", Codecs.truncate(tail, 2000)));
        }

        for (DecodedNode n : List.of(error, redirect, panels, hidden, page, ids, scripts, data, other, index)) {
            if (!n.isLeaf()) root.add(n);
        }

        List<String> parts = new ArrayList<>();
        if (errorText != null) parts.add(errorText);
        if (panelCount > 0) parts.add(plural(panelCount, "panel") + " updated");
        if (hiddenCount > 0) parts.add(plural(hiddenCount, "hidden field"));
        if (dataCount > 0) parts.add(plural(dataCount, "data item"));
        if (scriptCount > 0 && parts.isEmpty()) parts.add(plural(scriptCount, "script"));
        if (redirectUrl != null) parts.add("redirect to " + Codecs.truncate(redirectUrl, 120));
        if (parts.isEmpty()) parts.add(plural(r.records().size(), "record"));
        return new DecodeResult("Async postback delta: " + String.join(", ", parts), root, null, warnings);
    }

    private static String plural(int n, String word) {
        return n + " " + word + (n == 1 ? "" : "s");
    }

    private static DecodedNode idList(String type, String content) {
        DecodedNode arr = DecodedNode.array(type);
        if (content.isEmpty()) return arr;
        List<String> items = new ArrayList<>();
        for (String s : content.split(",")) if (!s.isEmpty() && items.size() < MAX_LIST) items.add(s);
        if (type.equals("updatePanelIDs")) {
            // Each panel ID is prefixed with 't'/'f' (ChildrenAsTriggers). ASP.NET 4 also interleaves the client ID.
            boolean allPrefixed = items.stream().allMatch(AspNetAjaxDecoder::tfPrefixed);
            boolean pairs = !allPrefixed && items.size() % 2 == 0;
            for (int k = 0; pairs && k < items.size(); k += 2) pairs = tfPrefixed(items.get(k));
            if (allPrefixed || pairs) {
                int step = pairs ? 2 : 1;
                for (int k = 0; k < items.size(); k += step) {
                    String p = items.get(k);
                    DecodedNode n = DecodedNode.object(p.substring(1));
                    n.put("childrenAsTriggers", p.charAt(0) == 't');
                    if (pairs) n.put("clientID", items.get(k + 1));
                    arr.add(n);
                }
                return arr;
            }
        }
        for (String s : items) arr.add(DecodedNode.leaf("", s));
        return arr;
    }

    private static boolean tfPrefixed(String s) {
        return s.length() > 1 && (s.charAt(0) == 't' || s.charAt(0) == 'f');
    }

    private static DecodedNode scriptNode(String type, String id, String content) {
        DecodedNode n = new DecodedNode(type, id.isEmpty() ? null : id, DecodedNode.Type.OBJECT);
        n.put("id", id);
        if ("ScriptContentWithTags".equals(id) && JsonTree.looksLikeJson(content)) {
            JsonElement j = JsonTree.parseLenient(content);
            if (j != null) {
                n.add(MsJson.toNode("attributes", j));
                return n;
            }
        }
        String label = "ScriptPath".equals(id) || type.equals("fallbackScript") ? "path" : "content";
        n.put(label, Codecs.truncate(content, MAX_CONTENT));
        return n;
    }

    @Override
    public String toString() {
        return ID;
    }
}
