package protocoldecoder.builtin.livewire;

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

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static protocoldecoder.builtin.livewire.LivewireData.arr;
import static protocoldecoder.builtin.livewire.LivewireData.obj;
import static protocoldecoder.builtin.livewire.LivewireData.str;

/**
 * Laravel Livewire: v3 {@code /livewire/update} requests/responses (snapshots with synthesizer tuples, updates, calls,
 * effects), v2 {@code /livewire/message/<name>} (fingerprint, serverMemo, dataMeta, updates), temporary file upload and
 * preview endpoints, and component state embedded in rendered pages ({@code wire:snapshot}, {@code wire:initial-data}).
 */
public final class LivewireDecoder implements ProtocolDecoder {

    public static final String ID = "livewire";

    private static final Pattern UPDATE_PATH = Pattern.compile("/livewire[^/]*/update$");
    private static final Pattern MESSAGE_PATH = Pattern.compile("/livewire/message/([^/]+)$");
    private static final Pattern UPLOAD_PATH = Pattern.compile("/livewire[^/]*/upload-file$");
    private static final Pattern PREVIEW_PATH = Pattern.compile("/livewire[^/]*/preview-file/([^/]+)$");
    private static final Pattern MULTIPART_FILE = Pattern.compile("name=\"([^\"]*)\"; filename=\"([^\"]*)\"(?:\\r?\\nContent-Type: *([^\\r\\n]+))?", Pattern.CASE_INSENSITIVE);

    private static final int HTML_SNIFF = 1024 * 1024;
    private static final int JSON_SNIFF = 8 * 1024 * 1024;
    private static final int HTML_DECODE = 4 * 1024 * 1024;
    private static final int MAX_COMPONENTS = 200;
    private static final int MAX_HTML = 512 * 1024;

    /** Built-in methods the Livewire JS client calls by itself. */
    private static final Map<String, String> MAGIC = Map.ofEntries(
            Map.entry("$refresh", "re-render the component"),
            Map.entry("$set", "set a property (name, value)"),
            Map.entry("$sync", "sync a property"),
            Map.entry("$commit", "commit pending updates"),
            Map.entry("$toggle", "toggle a boolean property"),
            Map.entry("__dispatch", "event dispatched to this component (name, params)"),
            Map.entry("__lazyLoad", "lazy-load the component (encoded snapshot)"),
            Map.entry("_startUpload", "begin temporary upload → server answers with a signed upload URL"),
            Map.entry("_finishUpload", "attach uploaded temporary files to the property"),
            Map.entry("_uploadErrored", "report a failed upload"),
            Map.entry("_removeUpload", "remove a temporary uploaded file"),
            Map.entry("startUpload", "begin temporary upload (v2)"),
            Map.entry("finishUpload", "attach uploaded temporary files (v2)"),
            Map.entry("uploadErrored", "report a failed upload (v2)"),
            Map.entry("removeUpload", "remove a temporary uploaded file (v2)"));

    @Override public String id() { return ID; }
    @Override public String name() { return "Laravel Livewire"; }
    @Override public String description() {
        return "Livewire v3 /livewire/update snapshots, updates, calls and effects; v2 /livewire/message; uploads; wire:snapshot page state";
    }

    // ---------------------------------------------------------------- matching

    enum Endpoint { UPDATE, MESSAGE, UPLOAD, PREVIEW, ASSET, NONE }

    static Endpoint endpoint(String rawPath) {
        String p = rawPath.toLowerCase(Locale.ROOT);
        if (!p.contains("/livewire")) return Endpoint.NONE;
        if (UPDATE_PATH.matcher(p).find()) return Endpoint.UPDATE;
        if (p.contains("/livewire/message/")) return Endpoint.MESSAGE;
        if (UPLOAD_PATH.matcher(p).find()) return Endpoint.UPLOAD;
        if (p.contains("/preview-file/")) return Endpoint.PREVIEW;
        if (p.endsWith(".js") || p.endsWith(".js.map") || p.endsWith(".css")) return Endpoint.ASSET;
        return Endpoint.NONE;
    }

    @Override
    public MatchResult match(MessageContext m) {
        try {
            return doMatch(m);
        } catch (RuntimeException e) {
            return MatchResult.NONE;
        }
    }

    private MatchResult doMatch(MessageContext m) {
        if (m.isWebSocket()) return MatchResult.NONE;
        Endpoint ep = endpoint(m.path());
        switch (ep) {
            case ASSET:
                return MatchResult.NONE;
            case UPDATE: {
                String b = displayedText(m, JSON_SNIFF);
                if (m.isRequest() ? b.contains("\"components\"") && b.contains("snapshot")
                        : b.contains("\"components\"") && (b.contains("snapshot") || b.contains("effects"))) {
                    return MatchResult.of(95, "Livewire v3 update " + (m.isRequest() ? "request" : "response"));
                }
                return "POST".equalsIgnoreCase(m.method()) ? MatchResult.of(55, "Livewire v3 update endpoint") : MatchResult.NONE;
            }
            case MESSAGE: {
                String b = displayedText(m, JSON_SNIFF);
                if (m.isRequest() ? b.contains("\"fingerprint\"") || b.contains("\"serverMemo\"")
                        : b.contains("\"effects\"") || b.contains("\"serverMemo\"")) {
                    return MatchResult.of(95, "Livewire v2 message " + (m.isRequest() ? "request" : "response"));
                }
                return "POST".equalsIgnoreCase(m.method()) ? MatchResult.of(55, "Livewire v2 message endpoint") : MatchResult.NONE;
            }
            case UPLOAD:
                return MatchResult.of(70, "Livewire temporary file upload");
            case PREVIEW:
                return MatchResult.of(60, "Livewire temporary file preview");
            default:
        }
        // Customised endpoints: recognise the JSON shape.
        byte[] raw = m.body();
        if (raw.length > 0 && raw.length <= JSON_SNIFF) {
            String ct = m.contentType().toLowerCase(Locale.ROOT);
            String b = ct.contains("json") ? Codecs.utf8(Codecs.decodeContent(raw, m.header("Content-Encoding"))) : Codecs.utf8(raw);
            String t = b.stripLeading();
            if (t.startsWith("{") && b.contains("\"components\"") && b.contains("snapshot") && b.contains("checksum") && b.contains("memo")) {
                JsonElement e = JsonTree.parseStrict(b);
                if (e != null && e.isJsonObject() && v3Shape(e.getAsJsonObject())) {
                    return MatchResult.of(75, "Livewire v3 component snapshot payload");
                }
            }
            if (t.startsWith("{") && b.contains("\"serverMemo\"") && b.contains("checksum")
                    && (b.contains("\"fingerprint\"") || b.contains("\"effects\""))) {
                JsonElement e = JsonTree.parseStrict(b);
                if (e != null && e.isJsonObject() && v2Shape(e.getAsJsonObject())) {
                    return MatchResult.of(75, "Livewire v2 message payload");
                }
            }
        }
        if (m.isResponse()) {
            String body = m.responseBodyText();
            String head = body.length() > HTML_SNIFF ? body.substring(0, HTML_SNIFF) : body;
            if (head.contains("wire:snapshot=") || head.contains("wire:initial-data=")) {
                return MatchResult.of(30, "Livewire component state in page");
            }
            if (head.contains("data-update-uri=") || head.contains("/livewire/livewire.js") || head.contains("livewire.min.js")) {
                return MatchResult.of(20, "Livewire script in page");
            }
        }
        return MatchResult.NONE;
    }

    private static String displayedText(MessageContext m, int cap) {
        byte[] b = m.body();
        if (b.length > cap) b = java.util.Arrays.copyOf(b, cap);
        return Codecs.utf8(Codecs.decodeContent(b, m.header("Content-Encoding")));
    }

    /** {@code components[]} whose first entry carries a snapshot (string or object) with memo + checksum/data. */
    static boolean v3Shape(JsonObject o) {
        JsonArray comps = arr(o, "components");
        if (comps == null || comps.isEmpty() || !comps.get(0).isJsonObject()) return false;
        JsonObject snap = snapshotOf(comps.get(0).getAsJsonObject());
        return snap != null && snap.has("memo") && (snap.has("checksum") || snap.has("data"));
    }

    static boolean v2Shape(JsonObject o) {
        JsonObject memo = obj(o, "serverMemo");
        if (memo == null) return false;
        return (obj(o, "fingerprint") != null || obj(o, "effects") != null) && (memo.has("checksum") || memo.has("data"));
    }

    private static JsonObject snapshotOf(JsonObject comp) {
        JsonElement s = comp.get("snapshot");
        if (s == null) return null;
        if (s.isJsonObject()) return s.getAsJsonObject();
        if (s.isJsonPrimitive() && s.getAsJsonPrimitive().isString()) {
            JsonElement e = JsonTree.parseStrict(s.getAsString());
            return e != null && e.isJsonObject() ? e.getAsJsonObject() : null;
        }
        return null;
    }

    // ---------------------------------------------------------------- decoding

    @Override
    public DecodeResult decode(MessageContext m) throws DecodeException {
        if (m.isWebSocket()) throw new DecodeException("Livewire does not use WebSockets");
        Endpoint ep = endpoint(m.path());
        if (ep == Endpoint.UPLOAD) return upload(m);
        if (ep == Endpoint.PREVIEW) return preview(m);

        String text = Codecs.utf8(Codecs.decodeContent(m.body(), m.header("Content-Encoding")));
        JsonElement json = JsonTree.looksLikeJson(text) ? JsonTree.parseStrict(text) : null;
        if (json != null && json.isJsonObject()) {
            JsonObject o = json.getAsJsonObject();
            if (arr(o, "components") != null && hasLivewireComponent(o)) return v3(m, o);
            if (obj(o, "fingerprint") != null || obj(o, "serverMemo") != null
                    || (ep == Endpoint.MESSAGE && (o.has("updates") || o.has("effects")))) {
                return v2(m, o);
            }
        }
        if (m.isResponse() && (text.contains("wire:snapshot") || text.contains("wire:initial-data") || text.contains("livewire"))) {
            DecodeResult r = page(m, text);
            if (r != null) return r;
        }
        if (ep == Endpoint.UPDATE || ep == Endpoint.MESSAGE) return endpointWithoutPayload(m, ep, text);
        throw new DecodeException("Not a Livewire message: expected a /livewire/update components payload, a v2 "
                + "fingerprint/serverMemo message, or a page with wire:snapshot / wire:initial-data");
    }

    private static boolean hasLivewireComponent(JsonObject o) {
        for (JsonElement c : arr(o, "components")) {
            if (c.isJsonObject() && (c.getAsJsonObject().has("snapshot") || c.getAsJsonObject().has("effects"))) return true;
        }
        return false;
    }

    // ---------------------------------------------------------------- v3

    private DecodeResult v3(MessageContext m, JsonObject o) {
        boolean request = m.isRequest();
        LivewireData.Findings f = new LivewireData.Findings();
        DecodedNode root = DecodedNode.object(request ? "Livewire v3 update request" : "Livewire v3 update response");
        if (o.has("_token")) root.put("_token — CSRF token", str(o, "_token"));
        JsonArray comps = arr(o, "components");
        DecodedNode list = DecodedNode.array("Components");
        List<String> parts = new ArrayList<>();
        int i = 0;
        for (JsonElement ce : comps) {
            if (i >= MAX_COMPONENTS) {
                list.add(DecodedNode.note((comps.size() - MAX_COMPONENTS) + " more components not shown"));
                break;
            }
            if (!ce.isJsonObject()) {
                list.add(JsonTree.toNode("[" + i++ + "]", ce, false));
                continue;
            }
            StringBuilder part = new StringBuilder();
            list.add(v3Component(ce.getAsJsonObject(), i++, request, f, part, false));
            parts.add(part.toString());
        }
        root.add(list);
        for (Map.Entry<String, JsonElement> en : o.entrySet()) {
            if (en.getKey().equals("_token") || en.getKey().equals("components")) continue;
            root.add(JsonTree.toNode(en.getKey(), en.getValue(), true));
        }
        if (request && !o.has("_token")) f.warn("Request carries no _token (CSRF token)");
        String head = request ? "Livewire update" : "Livewire response";
        if (comps.size() > 1) head += " (" + comps.size() + " components)";
        String summary = head + ": " + String.join("; ", parts);
        return new DecodeResult(Codecs.truncate(summary, 400), root, null, f.list());
    }

    /**
     * Renders one v3 component (from an update request/response or a page). Appends a summary fragment such as
     * {@code edit-post → save(…), 2 property updates} to {@code part}.
     */
    static DecodedNode v3Component(JsonObject comp, int index, boolean request, LivewireData.Findings f, StringBuilder part, boolean page) {
        JsonObject snap = snapshotOf(comp);
        JsonObject memo = snap == null ? null : obj(snap, "memo");
        String name = memo == null ? null : str(memo, "name");
        String id = memo == null ? null : str(memo, "id");
        f.component = name == null ? "" : name;
        DecodedNode n = new DecodedNode("[" + index + "] " + (name == null ? "component" : name), id == null ? null : "wire:id " + id, DecodedNode.Type.OBJECT);
        part.append(name == null ? "component" : name);

        if (comp.has("snapshot") && snap == null) {
            n.add(DecodedNode.note("snapshot is not valid JSON"));
            n.put("snapshot (raw)", Codecs.truncate(str(comp, "snapshot"), 4000));
        }
        if (memo != null) {
            DecodedNode c = n.child("Component");
            c.put("name", name).put("id", id).put("path", str(memo, "path")).put("method", str(memo, "method")).put("locale", str(memo, "locale"));
            if (memo.has("release")) c.put("release", str(memo, "release"));
        }

        List<String> actions = new ArrayList<>();
        // Updates (request): property path → new value.
        JsonObject updates = obj(comp, "updates");
        if (updates != null && !updates.isEmpty()) {
            DecodedNode u = n.child("Updates");
            for (Map.Entry<String, JsonElement> en : updates.entrySet()) {
                u.add(LivewireData.render(en.getKey(), en.getValue(), en.getKey(), null, 0));
                String last = en.getKey().substring(en.getKey().lastIndexOf('.') + 1);
                if (LivewireData.isSensitiveName(last) || LivewireData.isSensitiveName(en.getKey())) {
                    f.warn("Client update sets sensitive-looking property '" + en.getKey() + "'" + (name == null ? "" : " of " + name)
                            + " — check it is #[Locked] or authorised server-side");
                }
            }
        }
        // Calls (request): method + params.
        JsonArray calls = arr(comp, "calls");
        List<String> callLabels = new ArrayList<>();
        if (calls != null && !calls.isEmpty()) {
            DecodedNode cs = DecodedNode.array("Calls");
            for (JsonElement ce : calls) {
                if (!ce.isJsonObject()) {
                    cs.add(JsonTree.toNode("call", ce, false));
                    continue;
                }
                JsonObject call = ce.getAsJsonObject();
                String method = str(call, "method");
                JsonArray params = arr(call, "params");
                cs.add(callNode(method, str(call, "path"), params, call));
                callLabels.add(callLabel(method, params));
                callWarnings(method, params, name, f);
            }
            n.add(cs);
        }
        if (!callLabels.isEmpty()) actions.add(String.join(", ", callLabels));
        if (updates != null && !updates.isEmpty()) actions.add(updates.size() + " property update" + (updates.size() == 1 ? "" : "s"));

        // Effects (response / page).
        JsonObject effects = obj(comp, "effects");
        if (effects != null) actions.addAll(effects(effects, n, f));

        if (snap != null) {
            JsonObject data = obj(snap, "data");
            if (data != null) {
                DecodedNode props = DecodedNode.object("Properties");
                int k = 0;
                for (Map.Entry<String, JsonElement> en : data.entrySet()) {
                    if (k++ >= LivewireData.MAX_CHILDREN) {
                        props.add(DecodedNode.note((data.size() - LivewireData.MAX_CHILDREN) + " more properties not shown"));
                        break;
                    }
                    props.add(LivewireData.render(en.getKey(), en.getValue(), en.getKey(), f, 0));
                }
                n.add(props);
            }
            if (memo != null) {
                DecodedNode errs = LivewireData.errors(memo.get("errors"), f);
                if (errs != null) {
                    n.add(errs);
                    int ec = LivewireData.errorCount(memo.get("errors"));
                    actions.add(ec + " validation error" + (ec == 1 ? "" : "s"));
                }
                DecodedNode mn = DecodedNode.object("Memo");
                for (Map.Entry<String, JsonElement> en : memo.entrySet()) mn.add(JsonTree.toNode(en.getKey(), en.getValue(), true));
                n.add(mn);
            }
            String checksum = str(snap, "checksum");
            if (checksum != null) n.put("Checksum (HMAC of snapshot, APP_KEY)", checksum);
            else f.warn("Snapshot" + (name == null ? "" : " of " + name) + " has no checksum");
            for (Map.Entry<String, JsonElement> en : snap.entrySet()) {
                String k2 = en.getKey();
                if (!k2.equals("data") && !k2.equals("memo") && !k2.equals("checksum")) n.add(JsonTree.toNode(k2, en.getValue(), true));
            }
        }
        for (Map.Entry<String, JsonElement> en : comp.entrySet()) {
            String k2 = en.getKey();
            if (!List.of("snapshot", "updates", "calls", "effects").contains(k2)) n.add(JsonTree.toNode(k2, en.getValue(), true));
        }

        if (!page) {
            if (request) {
                if (actions.isEmpty()) actions.add("no updates or calls");
            } else if (actions.isEmpty()) {
                actions.add("no effects");
            }
        }
        if (!actions.isEmpty()) part.append(request ? " → " : " — ").append(String.join(", ", actions));
        return n;
    }

    private static DecodedNode callNode(String method, String path, JsonArray params, JsonObject call) {
        String magic = method == null ? null : MAGIC.get(method);
        DecodedNode c = new DecodedNode(callLabel(method, params), magic, DecodedNode.Type.OBJECT);
        c.put("method", method);
        if (path != null && !path.isEmpty()) c.put("path", path);
        if (params != null) c.add(LivewireData.render("params", params, "params", null, 0));
        if (call != null) {
            for (Map.Entry<String, JsonElement> en : call.entrySet()) {
                if (!List.of("method", "path", "params").contains(en.getKey())) c.add(JsonTree.toNode(en.getKey(), en.getValue(), false));
            }
        }
        return c;
    }

    static String callLabel(String method, JsonArray params) {
        String mth = method == null ? "?" : method;
        if (("__dispatch".equals(mth) || "$set".equals(mth)) && params != null && !params.isEmpty() && params.get(0).isJsonPrimitive()) {
            return mth + "(" + Codecs.truncate(params.get(0).getAsString(), 40) + (params.size() > 1 ? ", …)" : ")");
        }
        return mth + (params == null || params.isEmpty() ? "()" : "(…)");
    }

    private static void callWarnings(String method, JsonArray params, String component, LivewireData.Findings f) {
        if (method == null) return;
        String of = component == null ? "" : " on " + component;
        if (method.startsWith("_startUpload") || method.equals("startUpload")) {
            f.warn("File upload started" + of + " — test the signed /livewire/upload-file flow (type/size validation, preview-file serving)");
        } else if (method.equals("$set") && params != null && !params.isEmpty() && params.get(0).isJsonPrimitive()
                && LivewireData.isSensitiveName(params.get(0).getAsString())) {
            f.warn("$set targets sensitive-looking property '" + params.get(0).getAsString() + "'" + of);
        } else if (!MAGIC.containsKey(method) && params != null && !params.isEmpty()) {
            f.warn("Client calls " + method + "() " + of.strip() + " with " + params.size() + " client-controlled parameter"
                    + (params.size() == 1 ? "" : "s") + " — any public method is callable; check authorisation and validation of the arguments");
        }
    }

    /** Renders v3 effects onto {@code n}; returns summary fragments. */
    private static List<String> effects(JsonObject fx, DecodedNode n, LivewireData.Findings f) {
        List<String> parts = new ArrayList<>();
        DecodedNode e = n.child("Effects");
        for (Map.Entry<String, JsonElement> en : fx.entrySet()) {
            String k = en.getKey();
            JsonElement v = en.getValue();
            switch (k) {
                case "html" -> {
                    String h = str(v);
                    if (h != null) {
                        e.add(DecodedNode.leaf("html", Codecs.truncate(h, MAX_HTML), DecodedNode.Type.HTML));
                        parts.add("html");
                    }
                }
                case "redirect" -> {
                    String r = str(v);
                    if (r != null) {
                        e.put("redirect", r);
                        parts.add("redirect → " + Codecs.truncate(r, 80));
                        f.warn("Response redirects to " + Codecs.truncate(r, 200) + " — check whether the target is influenced by input (open redirect)");
                    }
                }
                case "dispatches" -> {
                    if (v.isJsonArray()) {
                        DecodedNode d = DecodedNode.array("dispatches");
                        for (JsonElement de : v.getAsJsonArray()) {
                            if (de.isJsonObject()) {
                                JsonObject dob = de.getAsJsonObject();
                                String nm = str(dob, "name");
                                DecodedNode dn = new DecodedNode(nm == null ? "event" : nm, dispatchTarget(dob), DecodedNode.Type.OBJECT);
                                for (Map.Entry<String, JsonElement> x : dob.entrySet()) dn.add(JsonTree.toNode(x.getKey(), x.getValue(), true));
                                d.add(dn);
                            } else {
                                d.add(JsonTree.toNode("event", de, true));
                            }
                        }
                        e.add(d);
                        int c = v.getAsJsonArray().size();
                        if (c > 0) parts.add(c + " dispatch" + (c == 1 ? "" : "es"));
                    } else {
                        e.add(JsonTree.toNode(k, v, true));
                    }
                }
                case "returns" -> {
                    e.add(LivewireData.render("returns", v, "returns", null, 0));
                    if (v.isJsonArray() && !v.getAsJsonArray().isEmpty()) {
                        parts.add(v.getAsJsonArray().size() + " return value" + (v.getAsJsonArray().size() == 1 ? "" : "s"));
                    }
                }
                case "xjs" -> {
                    e.add(JsonTree.toNode("xjs — JavaScript evaluated in the browser", v, false));
                    if (v.isJsonArray() && !v.getAsJsonArray().isEmpty()) {
                        parts.add("xjs");
                        f.warn("Response carries xjs (JavaScript executed client-side) — check it never embeds user input (XSS)");
                    }
                }
                case "download" -> {
                    if (v.isJsonObject()) {
                        JsonObject d = v.getAsJsonObject();
                        DecodedNode dn = e.child("download");
                        dn.put("name", str(d, "name")).put("contentType", str(d, "contentType"));
                        String content = str(d, "content");
                        byte[] raw = content == null ? null : Codecs.base64Decode(content);
                        if (raw != null) {
                            dn.put("size (bytes)", raw.length);
                            dn.put("preview", Codecs.isMostlyText(raw) ? Codecs.truncate(Codecs.utf8(raw), 2000) : Codecs.hexPreview(raw, 64));
                        }
                        parts.add("download " + str(d, "name"));
                        f.warn("Response delivers a file download (" + str(d, "name") + ") — check access control on the generating action");
                    } else if (!v.isJsonNull()) {
                        e.add(JsonTree.toNode(k, v, false));
                    }
                }
                default -> e.add(JsonTree.toNode(k, v, true));
            }
        }
        return parts;
    }

    private static String dispatchTarget(JsonObject d) {
        if (d.has("to")) return "to " + str(d, "to");
        if (d.has("component")) return "to " + str(d, "component");
        if (d.has("self") && d.get("self").isJsonPrimitive() && d.get("self").getAsBoolean()) return "self";
        return null;
    }

    // ---------------------------------------------------------------- v2

    private DecodeResult v2(MessageContext m, JsonObject o) {
        boolean request = m.isRequest();
        LivewireData.Findings f = new LivewireData.Findings();
        JsonObject fp = obj(o, "fingerprint");
        String name = fp != null ? str(fp, "name") : null;
        if (name == null) name = nameFromPath(m.path());
        if (name == null && !request) {
            JsonElement req = JsonTree.parseStrict(Codecs.utf8(Codecs.decodeContent(m.requestBody(), m.requestHeader("Content-Encoding"))));
            if (req != null && req.isJsonObject() && obj(req.getAsJsonObject(), "fingerprint") != null) {
                name = str(obj(req.getAsJsonObject(), "fingerprint"), "name");
            }
        }
        f.component = name == null ? "" : name;
        DecodedNode root = DecodedNode.object(request ? "Livewire v2 message request" : "Livewire v2 message response");
        if (fp != null) {
            DecodedNode c = root.child("Component (fingerprint)");
            for (Map.Entry<String, JsonElement> en : fp.entrySet()) c.add(JsonTree.toNode(en.getKey(), en.getValue(), false));
        } else if (name != null) {
            root.put("Component", name);
        }

        List<String> actions = new ArrayList<>();
        JsonArray updates = arr(o, "updates");
        if (updates != null) {
            DecodedNode un = DecodedNode.array("Updates");
            int syncs = 0, events = 0;
            List<String> calls = new ArrayList<>();
            for (JsonElement ue : updates) {
                if (!ue.isJsonObject()) {
                    un.add(JsonTree.toNode("update", ue, false));
                    continue;
                }
                JsonObject u = ue.getAsJsonObject();
                String type = str(u, "type");
                JsonObject payload = obj(u, "payload");
                if ("syncInput".equals(type) && payload != null) {
                    syncs++;
                    String prop = str(payload, "name");
                    DecodedNode x = new DecodedNode("syncInput " + prop, LivewireData.scalar(payload.get("value")), DecodedNode.Type.OBJECT);
                    for (Map.Entry<String, JsonElement> en : payload.entrySet()) x.add(JsonTree.toNode(en.getKey(), en.getValue(), false));
                    un.add(x);
                    if (prop != null && LivewireData.isSensitiveName(prop.substring(prop.lastIndexOf('.') + 1))) {
                        f.warn("Client update sets sensitive-looking property '" + prop + "'" + (name == null ? "" : " of " + name)
                                + " — check it is protected/authorised server-side");
                    }
                } else if ("callMethod".equals(type) && payload != null) {
                    String method = str(payload, "method");
                    JsonArray params = arr(payload, "params");
                    calls.add(callLabel(method, params));
                    DecodedNode c = callNode(method, null, params, null);
                    if (payload.has("id")) c.put("id", str(payload, "id"));
                    un.add(c);
                    callWarnings(method, params, name, f);
                } else if ("fireEvent".equals(type) && payload != null) {
                    events++;
                    DecodedNode x = new DecodedNode("fireEvent " + str(payload, "event"), null, DecodedNode.Type.OBJECT);
                    for (Map.Entry<String, JsonElement> en : payload.entrySet()) x.add(JsonTree.toNode(en.getKey(), en.getValue(), false));
                    un.add(x);
                } else {
                    un.add(JsonTree.toNode(type == null ? "update" : type, ue, false));
                }
            }
            root.add(un);
            if (!calls.isEmpty()) actions.add(String.join(", ", calls));
            if (syncs > 0) actions.add(syncs + " input sync" + (syncs == 1 ? "" : "s"));
            if (events > 0) actions.add(events + " event" + (events == 1 ? "" : "s"));
        }

        JsonObject effects = obj(o, "effects");
        if (effects != null) actions.addAll(v2Effects(effects, root, f));

        JsonObject memo = obj(o, "serverMemo");
        if (memo != null) {
            JsonObject data = obj(memo, "data");
            if (data != null) {
                DecodedNode props = DecodedNode.object("Properties (serverMemo.data)");
                for (Map.Entry<String, JsonElement> en : data.entrySet()) props.add(LivewireData.render(en.getKey(), en.getValue(), en.getKey(), f, 0));
                root.add(props);
            }
            JsonObject meta = obj(memo, "dataMeta");
            if (meta != null && !meta.isEmpty()) root.add(LivewireData.dataMeta(meta, f));
            DecodedNode errs = LivewireData.errors(memo.get("errors"), f);
            if (errs != null) {
                root.add(errs);
                int ec = LivewireData.errorCount(memo.get("errors"));
                actions.add(ec + " validation error" + (ec == 1 ? "" : "s"));
            }
            DecodedNode mn = root.child("Server memo");
            for (Map.Entry<String, JsonElement> en : memo.entrySet()) {
                String k = en.getKey();
                if (k.equals("data") || k.equals("dataMeta") || k.equals("errors") || k.equals("checksum")) continue;
                mn.add(JsonTree.toNode(k, en.getValue(), true));
            }
            String checksum = str(memo, "checksum");
            if (checksum != null) root.put("Checksum (HMAC of fingerprint + serverMemo, APP_KEY)", checksum);
            else if (request) f.warn("serverMemo has no checksum");
        }
        for (Map.Entry<String, JsonElement> en : o.entrySet()) {
            if (!List.of("fingerprint", "serverMemo", "updates", "effects").contains(en.getKey())) root.add(JsonTree.toNode(en.getKey(), en.getValue(), true));
        }
        if (actions.isEmpty()) actions.add(request ? "no updates" : "no effects");
        String summary = (request ? "Livewire v2 message: " : "Livewire v2 response: ") + (name == null ? "component" : name)
                + (request ? " → " : " — ") + String.join(", ", actions);
        return new DecodeResult(Codecs.truncate(summary, 400), root, null, f.list());
    }

    private static String nameFromPath(String path) {
        Matcher mm = MESSAGE_PATH.matcher(path);
        return mm.find() ? Codecs.urlDecode(mm.group(1)) : null;
    }

    private static List<String> v2Effects(JsonObject fx, DecodedNode root, LivewireData.Findings f) {
        List<String> parts = new ArrayList<>();
        DecodedNode e = root.child("Effects");
        for (Map.Entry<String, JsonElement> en : fx.entrySet()) {
            String k = en.getKey();
            JsonElement v = en.getValue();
            switch (k) {
                case "html" -> {
                    String h = str(v);
                    if (h != null) {
                        e.add(DecodedNode.leaf("html", Codecs.truncate(h, MAX_HTML), DecodedNode.Type.HTML));
                        parts.add("html");
                    }
                }
                case "redirect" -> {
                    String r = str(v);
                    if (r != null) {
                        e.put("redirect", r);
                        parts.add("redirect → " + Codecs.truncate(r, 80));
                        f.warn("Response redirects to " + Codecs.truncate(r, 200) + " — check whether the target is influenced by input (open redirect)");
                    }
                }
                case "dirty" -> {
                    e.add(JsonTree.toNode("dirty — properties changed server-side", v, false));
                    if (v.isJsonArray() && !v.getAsJsonArray().isEmpty()) parts.add(v.getAsJsonArray().size() + " dirty");
                }
                case "emits", "dispatches" -> {
                    if (v.isJsonArray()) {
                        DecodedNode d = DecodedNode.array(k);
                        for (JsonElement de : v.getAsJsonArray()) {
                            String ev = de.isJsonObject() ? str(de.getAsJsonObject(), "event") : null;
                            DecodedNode dn = JsonTree.toNode(ev == null ? "event" : ev, de, true);
                            d.add(dn);
                        }
                        e.add(d);
                        int c = v.getAsJsonArray().size();
                        if (c > 0) parts.add(c + " " + (k.equals("emits") ? "emit" : "dispatch") + (c == 1 ? "" : k.equals("emits") ? "s" : "es"));
                    } else {
                        e.add(JsonTree.toNode(k, v, true));
                    }
                }
                case "download" -> {
                    e.add(JsonTree.toNode(k, v, false));
                    if (v.isJsonObject()) {
                        parts.add("download");
                        f.warn("Response delivers a file download — check access control on the generating action");
                    }
                }
                default -> e.add(JsonTree.toNode(k, v, true));
            }
        }
        return parts;
    }

    // ---------------------------------------------------------------- uploads

    private DecodeResult upload(MessageContext m) {
        DecodedNode root = DecodedNode.object("Livewire temporary file upload");
        List<String> warnings = new ArrayList<>();
        Map<String, List<String>> q = m.queryParameters();
        DecodedNode signed = root.child("Signed URL");
        signed.put("expires", Codecs.first(q, "expires"));
        String exp = Codecs.first(q, "expires");
        if (exp != null && exp.matches("\\d{9,11}")) signed.put("expires (UTC)", java.time.Instant.ofEpochSecond(Long.parseLong(exp)).toString());
        signed.put("signature", Codecs.first(q, "signature"));
        if (Codecs.first(q, "signature") == null) warnings.add("Upload URL has no signature parameter");
        String summary;
        if (m.isRequest()) {
            String body = Codecs.latin1String(m.requestBody().length > HTML_SNIFF ? java.util.Arrays.copyOf(m.requestBody(), HTML_SNIFF) : m.requestBody());
            Matcher mm = MULTIPART_FILE.matcher(body);
            DecodedNode files = DecodedNode.array("Files");
            int n = 0;
            while (mm.find() && n < 100) {
                n++;
                DecodedNode fl = new DecodedNode(mm.group(2), mm.group(3), DecodedNode.Type.OBJECT);
                fl.put("field", mm.group(1)).put("filename", mm.group(2)).put("Content-Type", mm.group(3));
                files.add(fl);
            }
            root.add(files);
            summary = "Livewire upload: " + n + " file" + (n == 1 ? "" : "s");
            warnings.add("Temporary upload endpoint — test file type/size validation, filename handling and whether preview-file serves active content (SVG/HTML XSS)");
        } else {
            String text = Codecs.utf8(Codecs.decodeContent(m.responseBody(), m.responseHeader("Content-Encoding")));
            JsonElement e = JsonTree.parseStrict(text);
            summary = "Livewire upload response (HTTP " + m.statusCode() + ")";
            if (e != null) {
                root.add(JsonTree.toNode("Body", e, true));
                JsonArray paths = e.isJsonObject() ? arr(e.getAsJsonObject(), "paths") : e.isJsonArray() ? e.getAsJsonArray() : null;
                if (paths != null) summary = "Livewire upload response: " + paths.size() + " temporary file" + (paths.size() == 1 ? "" : "s");
                if (e.isJsonObject() && obj(e.getAsJsonObject(), "errors") != null) {
                    warnings.add("Upload rejected with validation errors");
                }
            } else {
                root.put("Body", Codecs.truncate(text, 4000));
            }
        }
        return new DecodeResult(summary, root, null, warnings);
    }

    private DecodeResult preview(MessageContext m) {
        DecodedNode root = DecodedNode.object("Livewire temporary file preview");
        Matcher mm = PREVIEW_PATH.matcher(m.path());
        String file = mm.find() ? Codecs.urlDecode(mm.group(1)) : null;
        root.put("Temporary filename", file);
        Map<String, List<String>> q = m.queryParameters();
        root.put("expires", Codecs.first(q, "expires")).put("signature", Codecs.first(q, "signature"));
        List<String> warnings = new ArrayList<>();
        String summary = "Livewire file preview: " + (file == null ? "?" : file);
        if (m.isResponse()) {
            String ct = m.responseHeader("Content-Type");
            root.put("Status", m.statusCode() == null ? null : m.statusCode().toString());
            root.put("Content-Type", ct);
            root.put("Size (bytes)", m.responseBody().length);
            summary += " (" + (ct == null ? "no content type" : ct) + ")";
            String lct = ct == null ? "" : ct.toLowerCase(Locale.ROOT);
            if (lct.contains("svg") || lct.contains("html") || lct.contains("xml") || lct.contains("javascript")) {
                warnings.add("Preview serves active content (" + ct + ") from the application origin — possible stored XSS");
            }
        }
        return new DecodeResult(summary, root, null, warnings);
    }

    // ---------------------------------------------------------------- pages

    private DecodeResult page(MessageContext m, String text) {
        String html = text.length() > HTML_DECODE ? text.substring(0, HTML_DECODE) : text;
        List<LivewireHtml.Element> elements = LivewireHtml.elements(html);
        List<String[]> script = LivewireHtml.scriptAttributes(html);
        String csrf = LivewireHtml.csrfMeta(html);
        if (elements.isEmpty() && script.isEmpty()) return null;

        LivewireData.Findings f = new LivewireData.Findings();
        DecodedNode root = DecodedNode.object("Livewire page");
        if (!script.isEmpty() || csrf != null) {
            DecodedNode cfg = root.child("Configuration");
            if (csrf != null) cfg.put("meta csrf-token", csrf);
            for (String[] a : script) {
                cfg.put(a[0], a[1]);
                if (a[0].equals("data-update-uri") && !a[1].endsWith("/livewire/update")) {
                    cfg.add(DecodedNode.note("customised update endpoint: " + a[1]));
                }
            }
        }
        DecodedNode list = DecodedNode.array("Components");
        List<String> names = new ArrayList<>();
        int v2 = 0, v3 = 0, i = 0;
        for (LivewireHtml.Element el : elements) {
            JsonElement state = JsonTree.parseStrict(el.state());
            if (state == null || !state.isJsonObject()) {
                list.add(DecodedNode.leaf("[" + i++ + "] wire:id " + el.id(), Codecs.truncate(el.state(), 2000)));
                continue;
            }
            if (el.version() == 3) {
                v3++;
                JsonObject comp = new JsonObject();
                comp.add("snapshot", state);
                if (el.effects() != null) {
                    JsonElement fx = JsonTree.parseStrict(el.effects());
                    if (fx != null && fx.isJsonObject()) comp.add("effects", fx);
                }
                StringBuilder part = new StringBuilder();
                list.add(v3Component(comp, i++, false, f, part, true));
                names.add(str(obj(state.getAsJsonObject(), "memo"), "name"));
            } else {
                v2++;
                list.add(v2Initial(state.getAsJsonObject(), el.id(), i++, f));
                names.add(str(obj(state.getAsJsonObject(), "fingerprint"), "name"));
            }
        }
        if (!list.isLeaf()) root.add(list);
        names.removeIf(x -> x == null);
        String ver = v3 > 0 && v2 > 0 ? "" : v3 > 0 ? "v3 " : v2 > 0 ? "v2 " : "";
        String summary = "Livewire page: " + elements.size() + " " + ver + "component" + (elements.size() == 1 ? "" : "s")
                + (names.isEmpty() ? "" : " (" + Codecs.truncate(String.join(", ", names.stream().distinct().toList()), 200) + ")");
        if (elements.size() >= LivewireHtml.MAX_COMPONENTS) f.warn("Only the first " + LivewireHtml.MAX_COMPONENTS + " components are shown");
        return new DecodeResult(summary, root, null, f.list());
    }

    private static DecodedNode v2Initial(JsonObject o, String wireId, int index, LivewireData.Findings f) {
        JsonObject fp = obj(o, "fingerprint");
        String name = fp == null ? null : str(fp, "name");
        f.component = name == null ? "" : name;
        DecodedNode n = new DecodedNode("[" + index + "] " + (name == null ? "component" : name), "wire:id " + (wireId != null ? wireId : fp == null ? "?" : str(fp, "id")) + " (v2)", DecodedNode.Type.OBJECT);
        if (fp != null) n.add(JsonTree.toNode("Component (fingerprint)", fp, false));
        JsonObject memo = obj(o, "serverMemo");
        if (memo != null) {
            JsonObject data = obj(memo, "data");
            if (data != null) {
                DecodedNode props = DecodedNode.object("Properties");
                for (Map.Entry<String, JsonElement> en : data.entrySet()) props.add(LivewireData.render(en.getKey(), en.getValue(), en.getKey(), f, 0));
                n.add(props);
            }
            JsonObject meta = obj(memo, "dataMeta");
            if (meta != null && !meta.isEmpty()) n.add(LivewireData.dataMeta(meta, f));
            DecodedNode errs = LivewireData.errors(memo.get("errors"), f);
            if (errs != null) n.add(errs);
            n.put("Checksum", str(memo, "checksum"));
        }
        JsonObject fx = obj(o, "effects");
        if (fx != null) n.add(JsonTree.toNode("Effects", fx, true));
        return n;
    }

    // ---------------------------------------------------------------- endpoint without a JSON payload

    private DecodeResult endpointWithoutPayload(MessageContext m, Endpoint ep, String text) throws DecodeException {
        if (m.isRequest()) {
            throw new DecodeException("Livewire " + (ep == Endpoint.UPDATE ? "update" : "message") + " endpoint, but the body is not a Livewire JSON payload");
        }
        Integer status = m.statusCode();
        DecodedNode root = DecodedNode.object("Livewire endpoint response");
        root.put("Status", status == null ? null : status.toString());
        String meaning = status == null ? null : switch (status) {
            case 419 -> "page expired — CSRF token missing/invalid or session expired";
            case 404 -> "component or route not found (or checksum/snapshot rejected in some versions)";
            case 403 -> "forbidden — authorisation or corrupt/tampered snapshot (CorruptComponentPayloadException)";
            case 500 -> "server error — a tampered snapshot/checksum or invalid method often surfaces here";
            default -> null;
        };
        if (meaning != null) root.put("Meaning", meaning);
        root.add(DecodedNode.leaf("Body", Codecs.truncate(text, 20000), JsonTree.looksLikeJson(text) ? DecodedNode.Type.STRING : DecodedNode.Type.HTML));
        List<String> warnings = new ArrayList<>();
        if (text.contains("CorruptComponentPayloadException") || text.contains("ChecksumException") || text.toLowerCase(Locale.ROOT).contains("checksum")) {
            warnings.add("Response mentions a checksum/corrupt payload error — the server rejected a modified snapshot");
        }
        if (text.contains("Whoops") || text.contains("ignition") || text.contains("vendor/laravel")) {
            warnings.add("Response looks like a Laravel debug page (APP_DEBUG enabled?)");
        }
        return new DecodeResult("Livewire endpoint response: HTTP " + status + (meaning == null ? "" : " (" + meaning + ")"), root, null, warnings);
    }
}
