package protocoldecoder.builtin.livewire;

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
import protocoldecoder.scan.PassiveCheck;
import protocoldecoder.scan.ProtocolScanner;
import protocoldecoder.scan.ScanPatterns;
import protocoldecoder.scan.Severity;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.net.URI;
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
 * Scanner support for Laravel Livewire: model/property exposure in snapshots, debug pages on Livewire endpoints,
 * CSRF and redirect observations, and an active check that the snapshot checksum is enforced.
 *
 * <p>No insertion points: v3 {@code updates} values and {@code calls[].params} (and v2 {@code updates[].payload})
 * are plain JSON in an {@code application/json} body, which Burp's own JSON insertion points already reach. The only
 * nested encoding is the JSON-in-string {@code snapshot}, which is HMAC-protected — payloads there are rejected by
 * the checksum, which {@link ChecksumEnforcement} tests directly.</p>
 */
public final class LivewireScanner implements ProtocolScanner {

    private static final int MAX_ITEMS = 30;
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();

    @Override
    public String decoderId() {
        return LivewireDecoder.ID;
    }

    @Override
    public List<PassiveCheck> passiveChecks() {
        return List.of(new ModelExposure(), new SensitiveProperties(), new DebugPage(), new MissingCsrfToken(), new ExternalRedirect());
    }

    @Override
    public List<ActiveCheck> activeChecks() {
        return List.of(new ChecksumEnforcement());
    }

    // ================================================================ helpers

    private static String htmlItems(Iterable<String> items) {
        StringBuilder sb = new StringBuilder("<ul>");
        for (String s : items) sb.append("<li><code>").append(Finding.esc(s)).append("</code></li>");
        return sb.append("</ul>").toString();
    }

    private static String text(MessageContext m) {
        byte[] b = m.body();
        if (b.length > 8 * 1024 * 1024) b = java.util.Arrays.copyOf(b, 8 * 1024 * 1024);
        return Codecs.utf8(Codecs.decodeContent(b, m.header("Content-Encoding")));
    }

    private static JsonObject jsonObject(String text) {
        if (!JsonTree.looksLikeJson(text)) return null;
        JsonElement e = JsonTree.parseStrict(text);
        return e != null && e.isJsonObject() ? e.getAsJsonObject() : null;
    }

    /** Component display name of a v3 component node ("[0] edit-post") or v2 root. */
    private static String component(String nodeName) {
        return nodeName.replaceFirst("^\\[\\d+\\] ", "");
    }

    // ================================================================ passive: Eloquent models

    private static final Set<String> MODEL_SYNTHS = Set.of("mdl", "elcln", "mdlclctn", "mdlcln");

    static final class ModelExposure implements PassiveCheck {
        @Override public String id() { return "livewire.model-exposure"; }
        @Override public String name() { return "Eloquent models in component state"; }
        @Override public String description() {
            return "Model classes and primary keys exposed in Livewire snapshots (v3 mdl/elcln synthesizers, v2 dataMeta) — IDOR attack surface";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || decoded == null) return List.of();
            Set<String> items = new LinkedHashSet<>();
            collect(decoded.root(), "", "", false, items, 0);
            if (items.isEmpty()) return List.of();
            Finding f = Finding.of(id(), "Livewire component exposes Eloquent model identifiers")
                    .severity(Severity.INFORMATION).confidence(Confidence.FIRM)
                    .detail("Livewire component state sent to the browser identifies these Eloquent models:" + htmlItems(items)
                            + "Model class names and primary keys are visible client-side.")
                    .background("Livewire dehydrates public model properties to their class and key and re-loads them from the database on every "
                            + "request. The snapshot is protected by an HMAC checksum, so the key cannot simply be edited, but the exposed keys "
                            + "reveal record ids and table structure, and component actions that take ids as parameters, or properties that are "
                            + "not <code>#[Locked]</code>, often allow other records to be addressed (IDOR).")
                    .remediation("Authorise every action and property update against the current user (policies / <code>$this->authorize()</code>), "
                            + "mark id properties <code>#[Locked]</code>, and avoid exposing models that the user may not access.");
            return List.of(f);
        }

        private static void collect(DecodedNode n, String comp, String path, boolean inProps, Set<String> out, int depth) {
            if (depth > 60 || out.size() >= MAX_ITEMS) return;
            comp = componentOf(n, comp);
            String prefix = comp.isEmpty() ? "" : comp + " → ";
            if (inProps) {
                DecodedNode synth = n.get("⟨synth⟩");
                String s = synth == null || synth.get("s") == null ? null : synth.get("s").value();
                String key = s == null ? null : s.contains(" ") ? s.substring(0, s.indexOf(' ')) : s;
                if (key != null && MODEL_SYNTHS.contains(key) && n.value() != null) out.add(prefix + path + ": " + n.value());
            }
            if (!inProps && (n.name().equals("Models") || n.name().equals("Model collections"))) {
                for (DecodedNode c : n.children()) {
                    if (out.size() >= MAX_ITEMS) break;
                    if (c.value() != null) out.add(prefix + c.name() + ": " + (n.name().equals("Models") ? "" : "collection ") + c.value());
                }
                return;
            }
            boolean props = n.name().startsWith("Properties");
            for (DecodedNode c : n.children()) {
                if (c.name().equals("⟨synth⟩")) continue;
                collect(c, comp, props ? c.name() : inProps ? path + "." + c.name() : "", props || inProps, out, depth + 1);
            }
        }
    }

    /** Component name for a v3 component node ("[0] edit-post"), a v2 node with a fingerprint, else the inherited one. */
    static String componentOf(DecodedNode n, String inherited) {
        DecodedNode fp = n.get("Component (fingerprint)");
        if (fp != null && fp.get("name") != null && fp.get("name").value() != null) return fp.get("name").value();
        if (n.name().matches("\\[\\d+\\] .*") && (n.get("Component") != null || n.get("Properties") != null)) return component(n.name());
        DecodedNode c = n.get("Component");
        if (c != null && c.isLeaf() && c.value() != null) return c.value();
        return inherited;
    }

    // ================================================================ passive: sensitive properties

    private static final Pattern BCRYPT = Pattern.compile("\\$2[aby]\\$\\d{2}\\$[./A-Za-z0-9]{53}");
    private static final Pattern BENIGN_NAME = Pattern.compile("(?i)(csrf|xsrf|_token$|nonce|token_?type|placeholder|label|^confirm)");

    static final class SensitiveProperties implements PassiveCheck {
        @Override public String id() { return "livewire.sensitive-properties"; }
        @Override public String name() { return "Sensitive public properties"; }
        @Override public String description() {
            return "Public component properties with sensitive names or values (passwords, tokens, secrets, hashes) sent to the browser";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || decoded == null) return List.of();
            List<ScanPatterns.Sensitive> hits = new ArrayList<>();
            Set<String> seen = new LinkedHashSet<>();
            walk(decoded.root(), "", "", false, hits, seen, 0);
            if (hits.isEmpty()) return List.of();
            Finding f = Finding.of(id(), "Livewire component state contains sensitive-looking data")
                    .severity(Severity.LOW).confidence(Confidence.TENTATIVE)
                    .detail("Public Livewire properties sent to the browser contain sensitive-looking values:" + ScanPatterns.htmlList(hits))
                    .background("Every public property of a Livewire component is serialised into the snapshot embedded in the page "
                            + "(<code>wire:snapshot</code>) and returned by every update. Secrets, tokens, password hashes or other users' data held "
                            + "in public properties are therefore disclosed, even when the Blade view never displays them.")
                    .remediation("Keep sensitive values in protected/private properties, computed properties or the session, and expose only "
                            + "what the view needs.");
            for (ScanPatterns.Sensitive s : hits) f.responseEvidence(s.value());
            return List.of(f);
        }

        private static void walk(DecodedNode n, String comp, String path, boolean inProps, List<ScanPatterns.Sensitive> out, Set<String> seen, int depth) {
            if (depth > 60 || out.size() >= MAX_ITEMS) return;
            comp = componentOf(n, comp);
            if (inProps && n.isLeaf() && n.type() != DecodedNode.Type.NOTE && n.value() != null) {
                String last = path.substring(path.lastIndexOf('.') + 1);
                if (BENIGN_NAME.matcher(last).find()) return;
                String where = (comp.isEmpty() ? "" : comp + " → ") + path;
                // ScanPatterns looks at the node's own name, so give it the property name (leaf "value" nodes sit under tuples)
                DecodedNode probe = DecodedNode.leaf(n.name().equals("value") ? last : n.name(), n.value(), n.type());
                for (ScanPatterns.Sensitive s : ScanPatterns.sensitiveValues(probe, 5)) {
                    String v = s.value().strip();
                    if (s.kind().equals("sensitive field name") && (v.equals("true") || v.equals("false") || v.equals("0") || v.equals("1"))) continue;
                    if (seen.add(s.kind() + "\u0000" + v)) out.add(new ScanPatterns.Sensitive(s.kind(), where, s.value()));
                }
                Matcher bm = BCRYPT.matcher(n.value());
                if (bm.find() && seen.add("hash\u0000" + bm.group())) out.add(new ScanPatterns.Sensitive("bcrypt password hash", where, bm.group()));
                return;
            }
            boolean props = n.name().startsWith("Properties");
            for (DecodedNode c : n.children()) {
                if (c.name().equals("⟨synth⟩")) continue;
                String cp = props ? c.name() : inProps ? (c.name().equals("value") ? path : path + "." + c.name()) : "";
                walk(c, comp, cp, props || inProps, out, seen, depth + 1);
            }
        }
    }

    // ================================================================ passive: Laravel debug page

    private static final String[] DEBUG_MARKERS = {"vendor/laravel/framework", "Illuminate\\Foundation", "spatie/laravel-ignition",
            "window.ignite", "ignition-", "Whoops! There was an error", "laravel-exceptions-renderer", "Illuminate\\\\Foundation"};

    /** Evidence of a Laravel debug page / JSON debug exception in {@code body}, or null. */
    static String debugEvidence(String body) {
        if (body == null || body.isEmpty()) return null;
        JsonObject o = jsonObject(body.strip());
        if (o != null) {
            JsonElement ex = o.get("exception");
            JsonElement trace = o.get("trace");
            if (ex != null && ex.isJsonPrimitive() && trace != null && trace.isJsonArray() && o.has("file")) return ex.getAsString();
            return null;
        }
        boolean laravel = body.contains("Illuminate\\") || body.contains("Illuminate\\\\") || body.contains("Symfony\\Component") || body.contains("Livewire\\");
        if (!laravel) return null;
        for (String mk : DEBUG_MARKERS) if (body.contains(mk)) return mk;
        return null;
    }

    static final class DebugPage implements PassiveCheck {
        @Override public String id() { return "livewire.debug-page"; }
        @Override public String name() { return "Laravel debug mode on Livewire endpoint"; }
        @Override public String description() {
            return "Livewire endpoint responses that are Laravel/Ignition debug pages or JSON debug exceptions (APP_DEBUG=true)";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse()) return List.of();
            LivewireDecoder.Endpoint ep = LivewireDecoder.endpoint(m.path());
            if (ep == LivewireDecoder.Endpoint.NONE || ep == LivewireDecoder.Endpoint.ASSET) return List.of();
            String ev = debugEvidence(text(m));
            if (ev == null) return List.of();
            return List.of(Finding.of(id(), "Laravel debug mode enabled (Livewire endpoint)")
                    .severity(Severity.MEDIUM).confidence(Confidence.FIRM).scope(Finding.Scope.HOST)
                    .detail("A Livewire endpoint (<code>" + Finding.esc(m.path()) + "</code>, HTTP " + m.statusCode()
                            + ") returned a Laravel debug error page / exception with stack trace (<code>" + Finding.esc(Codecs.truncate(ev, 200)) + "</code>).")
                    .background("With <code>APP_DEBUG=true</code> Laravel renders exceptions with full stack traces, source snippets, request data "
                            + "and often environment/config values (Ignition). Livewire endpoints are easy to make throw (malformed snapshots, unknown "
                            + "methods), so debug mode there discloses internals and sometimes secrets such as APP_KEY or database credentials; older "
                            + "Ignition versions were also remotely exploitable (CVE-2021-3129).")
                    .remediation("Set <code>APP_DEBUG=false</code> in production and rotate any secrets that may have been disclosed.")
                    .responseEvidence(ev));
        }
    }

    // ================================================================ passive: missing _token

    static final class MissingCsrfToken implements PassiveCheck {
        @Override public String id() { return "livewire.missing-csrf-token"; }
        @Override public String name() { return "Update request without CSRF token"; }
        @Override public String description() {
            return "Livewire v3 update requests with no _token in the body and no X-CSRF-TOKEN / X-XSRF-TOKEN header";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isRequest() || decoded == null || !decoded.root().name().equals("Livewire v3 update request")) return List.of();
            if (m.requestHeader("X-CSRF-TOKEN") != null || m.requestHeader("X-XSRF-TOKEN") != null) return List.of();
            JsonObject o = jsonObject(text(m));
            if (o == null) return List.of();
            JsonElement t = o.get("_token");
            if (t != null && t.isJsonPrimitive() && !t.getAsString().isBlank()) return List.of();
            String status = m.hasResponse() && m.statusCode() != null ? " The server answered HTTP " + m.statusCode() + "." : "";
            return List.of(Finding.of(id(), "Livewire update request without CSRF token")
                    .severity(Severity.INFORMATION).confidence(Confidence.TENTATIVE).scope(Finding.Scope.HOST)
                    .detail("The Livewire update request to <code>" + Finding.esc(m.path()) + "</code> carries no <code>_token</code> and no "
                            + "CSRF header." + status + " If such requests succeed, the update route is excluded from CSRF verification.")
                    .background("Livewire sends the session's CSRF token as <code>_token</code> in every update request and Laravel's "
                            + "VerifyCsrfToken middleware checks it. An update endpoint without that protection lets other sites trigger component "
                            + "actions in a victim's session (CSRF), limited only by the need for a valid snapshot — which is embedded in pages "
                            + "and may be reusable.")
                    .remediation("Keep the Livewire update route under the <code>web</code> middleware group with CSRF verification enabled; don't "
                            + "add it to the CSRF exception list.")
                    .requestEvidence("\"components\""));
        }
    }

    // ================================================================ passive: external redirect

    static boolean external(String target, String host) {
        if (target == null || host == null || host.isEmpty()) return false;
        String t = target.strip();
        if (t.startsWith("//")) t = "https:" + t;
        if (!t.regionMatches(true, 0, "http://", 0, 7) && !t.regionMatches(true, 0, "https://", 0, 8)) return false;
        try {
            String h = URI.create(t).getHost();
            if (h == null) return false;
            h = h.toLowerCase(Locale.ROOT);
            String b = host.toLowerCase(Locale.ROOT);
            return !(h.equals(b) || h.endsWith("." + b) || b.endsWith("." + h));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    static final class ExternalRedirect implements PassiveCheck {
        @Override public String id() { return "livewire.external-redirect"; }
        @Override public String name() { return "Redirect effect to another domain"; }
        @Override public String description() { return "Livewire responses whose effects.redirect points to a different host"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || decoded == null) return List.of();
            JsonObject o = jsonObject(text(m));
            if (o == null) return List.of();
            List<String> targets = new ArrayList<>();
            JsonArray comps = LivewireData.arr(o, "components");
            if (comps != null) {
                for (JsonElement c : comps) {
                    if (c.isJsonObject()) addRedirect(LivewireData.obj(c.getAsJsonObject(), "effects"), targets);
                }
            }
            addRedirect(LivewireData.obj(o, "effects"), targets);
            targets.removeIf(t -> !external(t, m.host()));
            if (targets.isEmpty()) return List.of();
            Finding f = Finding.of(id(), "Livewire redirect to external domain")
                    .severity(Severity.INFORMATION).confidence(Confidence.FIRM)
                    .detail("The Livewire response instructs the browser to navigate to another domain:" + htmlItems(targets)
                            + "Check whether the target can be influenced by request data (open redirect).")
                    .background("Components redirect with <code>$this->redirect($url)</code>; the URL is returned as <code>effects.redirect</code> "
                            + "and followed by the Livewire JavaScript. If it is built from a property or action parameter, it can be abused for "
                            + "phishing or OAuth token theft.")
                    .remediation("Redirect only to allow-listed or relative URLs (e.g. <code>redirect()->intended()</code> with validated paths).");
            for (String t : targets) f.responseEvidence(t);
            return List.of(f);
        }

        private static void addRedirect(JsonObject fx, List<String> out) {
            String r = fx == null ? null : LivewireData.str(fx, "redirect");
            if (r != null && out.size() < MAX_ITEMS) out.add(r);
        }
    }

    // ================================================================ active: checksum enforcement

    static final class ChecksumEnforcement implements ActiveCheck {
        @Override public String id() { return "livewire.checksum-enforcement"; }
        @Override public String name() { return "Snapshot checksum enforcement"; }
        @Override public String description() {
            return "Re-sends a v3 update with one snapshot data value changed (checksum kept, no updates/calls, so only a re-render) and "
                    + "reports if the server accepts it. 1 request";
        }
        @Override public Scope scope() { return Scope.PER_REQUEST; }

        /** The tampered request: the first component only, one scalar data property changed. */
        record Tampered(String body, String property, JsonElement original, JsonElement modified) {
        }

        static Tampered tamper(String requestBody) {
            JsonObject o = jsonObject(requestBody);
            if (o == null) return null;
            JsonArray comps = LivewireData.arr(o, "components");
            if (comps == null) return null;
            for (JsonElement ce : comps) {
                if (!ce.isJsonObject()) continue;
                JsonElement s = ce.getAsJsonObject().get("snapshot");
                if (s == null || !s.isJsonPrimitive() || !s.getAsJsonPrimitive().isString()) continue;
                JsonObject snap = jsonObject(s.getAsString());
                if (snap == null || !snap.has("checksum")) continue;
                JsonObject data = LivewireData.obj(snap, "data");
                if (data == null) continue;
                for (Map.Entry<String, JsonElement> en : data.entrySet()) {
                    JsonElement v = en.getValue();
                    if (!v.isJsonPrimitive()) continue;
                    JsonPrimitive p = v.getAsJsonPrimitive();
                    JsonPrimitive changed;
                    if (p.isBoolean()) changed = new JsonPrimitive(!p.getAsBoolean());
                    else if (p.isNumber()) {
                        try {
                            changed = new JsonPrimitive(Long.parseLong(p.getAsString()) + 1);
                        } catch (NumberFormatException e) {
                            continue;
                        }
                    } else changed = new JsonPrimitive(p.getAsString() + "pd7x");
                    data.add(en.getKey(), changed);
                    JsonObject comp = new JsonObject();
                    comp.addProperty("snapshot", GSON.toJson(snap));
                    comp.add("updates", new JsonObject());
                    comp.add("calls", new JsonArray());
                    JsonObject req = new JsonObject();
                    for (Map.Entry<String, JsonElement> top : o.entrySet()) {
                        if (!top.getKey().equals("components")) req.add(top.getKey(), top.getValue());
                    }
                    JsonArray one = new JsonArray();
                    one.add(comp);
                    req.add("components", one);
                    return new Tampered(GSON.toJson(req), en.getKey(), v, changed);
                }
            }
            return null;
        }

        /** True if the response carries a component snapshot whose data still holds the modified value. */
        static boolean accepted(Exchange x, Tampered t) {
            if (x == null || !x.hasResponse() || x.status() < 200 || x.status() >= 300) return false;
            JsonObject o = jsonObject(x.responseText());
            JsonArray comps = o == null ? null : LivewireData.arr(o, "components");
            if (comps == null) return false;
            for (JsonElement ce : comps) {
                if (!ce.isJsonObject()) continue;
                JsonElement s = ce.getAsJsonObject().get("snapshot");
                JsonObject snap = s != null && s.isJsonPrimitive() ? jsonObject(s.getAsString()) : s != null && s.isJsonObject() ? s.getAsJsonObject() : null;
                JsonObject data = snap == null ? null : LivewireData.obj(snap, "data");
                if (data != null && t.modified().equals(data.get(t.property()))) return true;
            }
            return false;
        }

        @Override
        public List<Finding> run(ActiveContext ctx) {
            MessageContext base = ctx.base();
            if (!"POST".equalsIgnoreCase(base.method()) || LivewireDecoder.endpoint(base.path()) != LivewireDecoder.Endpoint.UPDATE
                    && (ctx.decoded() == null || !ctx.decoded().root().name().equals("Livewire v3 update request"))) return List.of();
            MessageContext resp = ctx.baseResponse();
            if (resp != null && resp.statusCode() != null && (resp.statusCode() < 200 || resp.statusCode() >= 300)) return List.of();
            String enc = base.requestHeader("Content-Encoding");
            if (enc != null && !enc.isBlank()) return List.of();
            Tampered t = tamper(base.requestBodyText());
            if (t == null) return List.of();
            Exchange x = ctx.http().send(base.method(), base.path() + (base.query().isEmpty() ? "" : "?" + base.query()),
                    new ArrayList<Header>(base.requestHeaders()), t.body().getBytes(StandardCharsets.UTF_8));
            if (!accepted(x, t)) return List.of();
            return List.of(Finding.of(id(), "Livewire snapshot checksum not enforced")
                    .severity(Severity.MEDIUM).confidence(Confidence.FIRM)
                    .detail("The update request was re-sent with snapshot property <code>" + Finding.esc(t.property()) + "</code> changed from <code>"
                            + Finding.esc(Codecs.truncate(t.original().toString(), 100)) + "</code> to <code>" + Finding.esc(Codecs.truncate(t.modified().toString(), 100))
                            + "</code> while keeping the original checksum. The server accepted it (HTTP " + x.status()
                            + ") and returned a snapshot containing the modified value instead of rejecting the payload.")
                    .background("Livewire signs each component snapshot with an HMAC (APP_KEY) and must reject modified snapshots "
                            + "(CorruptComponentPayloadException). Without that check, clients can set any property — including <code>#[Locked]</code> "
                            + "ones, model keys and authorisation state — by editing the snapshot.")
                    .remediation("Upgrade Livewire and don't disable or override checksum verification; ensure APP_KEY is set and secret.")
                    .requestEvidence(t.property())
                    .exchange(x));
        }
    }
}
