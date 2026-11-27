package protocoldecoder.builtin.viewstate;

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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Scanner support for ASP.NET page state: MAC / deserialization analysis of {@code __VIEWSTATE} and
 * {@code __EVENTVALIDATION}, an active MAC-enforcement probe, and insertion points for string values inside an
 * unprotected (no MAC) ViewState graph.
 *
 * <p>MAC findings are host-scoped (machineKey / EnableViewStateMac are configuration), so ViewState seen on many
 * pages — including DevExpress callbacks, which also carry {@code __VIEWSTATE} — is reported once per host.</p>
 */
public final class ViewStateScanner implements ProtocolScanner {

    /** ViewState larger than this (base64 characters) is reported as informational. */
    static final int LARGE_VIEWSTATE = 100_000;
    private static final Pattern SPLIT_FIELD = Pattern.compile("__VIEWSTATE\\d+|__VIEWSTATEFIELDCOUNT");
    private static final Pattern TYPE_HASH = Pattern.compile("-?\\d{1,11}");
    private static final String TYPE_HASH_PATH = "Root › First › First";

    private static final String MAC_BACKGROUND = "ASP.NET WebForms round-trips page state in <code>__VIEWSTATE</code> (and <code>__EVENTVALIDATION</code>), "
            + "serialized with <code>ObjectStateFormatter</code>. The server normally appends a keyed MAC (machineKey validation key) and rejects "
            + "state whose MAC does not verify. Without a MAC the server deserializes whatever the client sends; because ObjectStateFormatter "
            + "can embed <code>BinaryFormatter</code> data, a crafted value can lead to remote code execution (e.g. ysoserial.net gadget chains).";
    private static final String MAC_REMEDIATION = "Never set <code>EnableViewStateMac=\"false\"</code> (page directive or <code>&lt;pages&gt;</code> in web.config) "
            + "and remove <code>aspnet:AllowInsecureDeserialization</code>; run .NET Framework 4.5.2 or later, which always enforces the MAC. "
            + "Use a strong, unique, secret <code>machineKey</code> (HMACSHA256 or better) and consider <code>ViewStateEncryptionMode=\"Always\"</code>.";

    @Override
    public String decoderId() {
        return ViewStateDecoder.ID;
    }

    private final List<PassiveCheck> passive = List.of(new NoMac(), new WeakMac(), new EventValidationNoMac(), new BinarySerialized(),
            new SensitiveData(), new InQueryString(), new LargeViewState());
    /** Kept as one instance: the MAC probe remembers confirmed hosts. */
    private final List<ActiveCheck> active = List.of(new MacValidation());

    @Override
    public List<PassiveCheck> passiveChecks() {
        return passive;
    }

    @Override
    public List<ActiveCheck> activeChecks() {
        return active;
    }

    // ================================================================ helpers

    static DecodedNode section(DecodeResult d, String label) {
        return d == null || d.root() == null ? null : d.root().get(label);
    }

    /** "No MAC", "MAC present (likely …)", … or null when the stream was not fully parsed / is encrypted. */
    static String macStatus(DecodedNode sec) {
        if (sec == null) return null;
        DecodedNode mac = sec.get("MAC");
        DecodedNode st = mac == null ? null : mac.get("Status");
        return st == null ? null : st.value();
    }

    static int trailing(DecodedNode sec) {
        DecodedNode mac = sec == null ? null : sec.get("MAC");
        DecodedNode t = mac == null ? null : mac.get("Trailing bytes");
        try {
            return t == null || t.value() == null ? -1 : Integer.parseInt(t.value());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    static String value(DecodedNode sec, String child) {
        DecodedNode c = sec == null ? null : sec.get(child);
        return c == null ? null : c.value();
    }

    private static Finding evidence(Finding f, MessageContext m, String text) {
        return m.isResponse() ? f.responseEvidence(text) : f.requestEvidence(text);
    }

    private static String where(MessageContext m) {
        return m.isResponse() ? "the response" : m.isRequest() ? "the request" : "the message";
    }

    private static String describe(DecodedNode sec) {
        return "Format: <code>" + Finding.esc(value(sec, "Format")) + "</code>, " + Finding.esc(value(sec, "Decoded bytes"))
                + " bytes, source: " + Finding.esc(value(sec, "Source")) + ".";
    }

    // ================================================================ passive checks

    /** ViewState that fully parses with nothing after the serialized graph. */
    static final class NoMac implements PassiveCheck {
        @Override public String id() { return "viewstate.no-mac"; }
        @Override public String name() { return "ViewState without MAC"; }
        @Override public String description() {
            return "Unencrypted __VIEWSTATE that parses completely with no MAC after it (EnableViewStateMac disabled → deserialization RCE risk)";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            DecodedNode vs = section(decoded, "ViewState");
            if (!"No MAC".equals(macStatus(vs)) || trailing(vs) != 0) return List.of();
            Finding f = Finding.of(id(), "ASP.NET ViewState MAC disabled")
                    .severity(Severity.HIGH).confidence(Confidence.FIRM).scope(Finding.Scope.HOST)
                    .detail("The <code>__VIEWSTATE</code> in " + where(m) + " is an unencrypted ObjectStateFormatter stream that parses completely and "
                            + "has <b>no MAC</b> after the serialized data, so <code>EnableViewStateMac</code> appears to be disabled. " + describe(vs)
                            + "<br><br>This is <b>not yet confirmed</b>: verify that the server accepts a modified ViewState (the active check "
                            + "\"ViewState MAC validation\" does this safely), then assess deserialization impact with an approved, non-destructive payload.")
                    .background(MAC_BACKGROUND)
                    .remediation(MAC_REMEDIATION);
            return List.of(evidence(f, m, "__VIEWSTATE"));
        }
    }

    /** MAC length matching MD5 (16) or SHA1 (20). */
    static final class WeakMac implements PassiveCheck {
        @Override public String id() { return "viewstate.weak-mac"; }
        @Override public String name() { return "ViewState MAC uses MD5/SHA1"; }
        @Override public String description() { return "ViewState MAC whose length suggests MD5 or HMACSHA1 (legacy machineKey validation)"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            DecodedNode vs = section(decoded, "ViewState");
            String st = macStatus(vs);
            int t = trailing(vs);
            if (st == null || !st.startsWith("MAC present") || (t != 16 && t != 20)) return List.of();
            String alg = t == 16 ? "MD5" : "HMACSHA1";
            Finding f = Finding.of(id(), "ASP.NET ViewState MAC uses a legacy algorithm")
                    .severity(Severity.LOW).confidence(Confidence.TENTATIVE).scope(Finding.Scope.HOST)
                    .detail("The ViewState MAC is " + t + " bytes long, which matches <b>" + alg + "</b> (inferred from the length only). "
                            + "This indicates <code>machineKey validation=\"" + (t == 16 ? "MD5" : "SHA1") + "\"</code> and usually a pre-4.5 / legacy "
                            + "cryptography mode. " + describe(vs))
                    .background("The ViewState MAC protects the page state against tampering and, with it, against ObjectStateFormatter "
                            + "deserialization attacks. Legacy algorithms and legacy (non-purpose-derived) keys are weaker, and applications still "
                            + "on them often use default, shared or published machineKeys, which make the MAC forgeable.")
                    .remediation("Configure <code>machineKey validation=\"HMACSHA256\"</code> (or stronger) with a unique random key, and target "
                            + ".NET 4.5+ cryptography (<code>&lt;httpRuntime targetFramework=\"4.5\"/&gt;</code> or later). Verify the key is not a known/published one.");
            return List.of(evidence(f, m, "__VIEWSTATE"));
        }
    }

    /** EventValidation without MAC; skipped when the ViewState in the same message is already reported. */
    static final class EventValidationNoMac implements PassiveCheck {
        @Override public String id() { return "viewstate.eventvalidation-no-mac"; }
        @Override public String name() { return "EventValidation without MAC"; }
        @Override public String description() { return "__EVENTVALIDATION that parses completely with no MAC (reported when the ViewState check did not fire)"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            DecodedNode ev = section(decoded, "EventValidation");
            if (!"No MAC".equals(macStatus(ev)) || trailing(ev) != 0) return List.of();
            if ("No MAC".equals(macStatus(section(decoded, "ViewState")))) return List.of(); // viewstate.no-mac covers it
            Finding f = Finding.of(id(), "ASP.NET EventValidation MAC disabled")
                    .severity(Severity.MEDIUM).confidence(Confidence.FIRM).scope(Finding.Scope.HOST)
                    .detail("The <code>__EVENTVALIDATION</code> field in " + where(m) + " is an unencrypted ObjectStateFormatter stream with "
                            + "<b>no MAC</b>. " + describe(ev) + " Event validation data can therefore be forged (allowing postback events and "
                            + "values the page never rendered), and the field is deserialized with ObjectStateFormatter like ViewState. "
                            + "Not confirmed until a modified value is shown to be accepted.")
                    .background(MAC_BACKGROUND)
                    .remediation(MAC_REMEDIATION);
            return List.of(evidence(f, m, "__EVENTVALIDATION"));
        }
    }

    /** Token_BinarySerialized inside the ViewState graph. */
    static final class BinarySerialized implements PassiveCheck {
        @Override public String id() { return "viewstate.binary-serialized"; }
        @Override public String name() { return "BinaryFormatter data in ViewState"; }
        @Override public String description() { return "ViewState containing BinarySerialized (BinaryFormatter) blobs — a deserialization sink"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            DecodedNode vs = section(decoded, "ViewState");
            if (vs == null) return List.of();
            List<DecodedNode> blobs = new ArrayList<>();
            collectBlobs(vs, blobs, 0);
            if (blobs.isEmpty()) return List.of();
            String st = macStatus(vs);
            boolean protectedByMac = st != null && st.startsWith("MAC present");
            StringBuilder list = new StringBuilder("<ul>");
            for (DecodedNode b : blobs.subList(0, Math.min(blobs.size(), 10))) {
                list.append("<li><code>").append(Finding.esc(b.value())).append("</code>");
                DecodedNode classes = b.get("Class names (printable scan)");
                if (classes != null && !classes.children().isEmpty()) {
                    List<String> names = classes.children().stream().limit(5).map(DecodedNode::value).toList();
                    list.append(" — classes: <code>").append(Finding.esc(String.join(", ", names))).append("</code>");
                }
                DecodedNode g = b.get("Known gadget markers");
                if (g != null) list.append(" — <b>known gadget markers: ").append(Finding.esc(g.value())).append("</b>");
                list.append("</li>");
            }
            list.append("</ul>");
            Finding f = Finding.of(id(), "ASP.NET ViewState contains BinaryFormatter data")
                    .severity(protectedByMac ? Severity.LOW : Severity.MEDIUM).confidence(Confidence.TENTATIVE)
                    .detail("The ViewState in " + where(m) + " contains " + blobs.size() + " <code>BinarySerialized</code> value(s), which the server "
                            + "deserializes with <code>BinaryFormatter</code>:" + list
                            + (protectedByMac
                            ? "The ViewState carries a MAC, so exploiting this requires the machineKey."
                            : "The ViewState has no recognised MAC (" + Finding.esc(st == null ? "MAC status unknown" : st) + "), so this sink may be reachable "
                            + "with attacker-controlled data."))
                    .background("BinaryFormatter is inherently unsafe for untrusted input: known gadget chains turn deserialization into code "
                            + "execution. Objects that are not natively supported by ObjectStateFormatter (custom serializable classes stored in "
                            + "ViewState) are written this way.")
                    .remediation("Avoid storing custom serializable objects in ViewState (store primitives or keep the data server-side); ensure the "
                            + "ViewState MAC is enforced with a secret machineKey.");
            return List.of(evidence(f, m, "__VIEWSTATE"));
        }

        private static void collectBlobs(DecodedNode n, List<DecodedNode> out, int depth) {
            if (depth > ObjectStateReader.MAX_DEPTH + 5 || out.size() >= 50) return;
            if (n.value() != null && n.value().startsWith("BinarySerialized (")) {
                out.add(n);
                return;
            }
            for (DecodedNode c : n.children()) collectBlobs(c, out, depth + 1);
        }
    }

    /** Sensitive-looking values in the readable (unencrypted) ViewState / ControlState graph. */
    static final class SensitiveData implements PassiveCheck {
        @Override public String id() { return "viewstate.sensitive-data"; }
        @Override public String name() { return "Sensitive data in unencrypted ViewState"; }
        @Override public String description() { return "Emails, tokens, credentials or card numbers stored in readable (unencrypted) ViewState"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            List<ScanPatterns.Sensitive> found = new ArrayList<>();
            for (String label : new String[]{"ViewState", "ControlState"}) {
                DecodedNode sec = section(decoded, label);
                DecodedNode graph = sec == null ? null : sec.get("Root");
                if (graph != null) found.addAll(ScanPatterns.sensitiveValues(graph, 10));
            }
            if (found.isEmpty()) return List.of();
            Finding f = Finding.of(id(), "Sensitive data in unencrypted ASP.NET ViewState")
                    .severity(Severity.LOW).confidence(Confidence.TENTATIVE)
                    .detail("The ViewState in " + where(m) + " is not encrypted and contains sensitive-looking values:"
                            + ScanPatterns.htmlList(found.subList(0, Math.min(found.size(), 10))))
                    .background("ViewState is only base64-encoded unless ViewStateEncryptionMode is enabled: anyone who can see the page (browser "
                            + "history, caches, proxies, shoulder-surfing tools) can read everything stored in it.")
                    .remediation("Don't keep secrets or personal data in ViewState; store them server-side, or enable "
                            + "<code>ViewStateEncryptionMode=\"Always\"</code>.");
            return List.of(evidence(f, m, "__VIEWSTATE"));
        }
    }

    /** __VIEWSTATE sent in a URL. */
    static final class InQueryString implements PassiveCheck {
        @Override public String id() { return "viewstate.in-query-string"; }
        @Override public String name() { return "ViewState in query string"; }
        @Override public String description() { return "__VIEWSTATE sent as a URL parameter (leaks via logs, history and Referer)"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isRequest()) return List.of();
            String v = Codecs.first(m.queryParameters(), "__VIEWSTATE");
            if (v == null || v.isEmpty()) return List.of();
            return List.of(Finding.of(id(), "ASP.NET ViewState sent in query string")
                    .severity(Severity.LOW).confidence(Confidence.FIRM)
                    .detail("The request URL carries <code>__VIEWSTATE</code> (" + v.length() + " characters), typically from a form with "
                            + "<code>method=\"get\"</code>.")
                    .background("Page state in the URL ends up in web server and proxy logs, browser history and Referer headers sent to other sites. "
                            + "It also makes cross-site request forgery and ViewState tampering easier to deliver via links.")
                    .remediation("Use <code>method=\"post\"</code> for WebForms forms, or disable ViewState for pages that must use GET.")
                    .requestEvidence("__VIEWSTATE="));
        }
    }

    static final class LargeViewState implements PassiveCheck {
        @Override public String id() { return "viewstate.large"; }
        @Override public String name() { return "Very large ViewState"; }
        @Override public String description() { return "__VIEWSTATE over " + LARGE_VIEWSTATE + " base64 characters"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            DecodedNode vs = section(decoded, "ViewState");
            String len = value(vs, "Base64 length");
            int n;
            try {
                n = len == null ? 0 : Integer.parseInt(len);
            } catch (NumberFormatException e) {
                return List.of();
            }
            if (n < LARGE_VIEWSTATE) return List.of();
            Finding f = Finding.of(id(), "Very large ASP.NET ViewState")
                    .severity(Severity.INFORMATION).confidence(Confidence.CERTAIN)
                    .detail("The ViewState in " + where(m) + " is " + n + " base64 characters (" + Finding.esc(value(vs, "Decoded bytes")) + " bytes decoded).")
                    .background("Large ViewState often means data-bound controls persist whole data sets client-side — worth reviewing for "
                            + "data that should not be exposed or trusted — and it slows every postback.")
                    .remediation("Disable ViewState on controls that don't need it (<code>EnableViewState=\"false\"</code>) and keep data server-side.");
            return List.of(evidence(f, m, "__VIEWSTATE"));
        }
    }

    // ================================================================ form handling

    /** The urlencoded part (body or query) that carries __VIEWSTATE, with the page-state fields it contains. */
    record StatePart(boolean inQuery, String raw, Map<String, String> fields, String viewState) {
    }

    static StatePart statePart(MessageContext request) {
        String ct = request.requestContentType().toLowerCase(Locale.ROOT);
        if (!ct.contains("multipart/")) {
            String body = Codecs.latin1String(request.requestBody());
            StatePart p = statePart(false, body);
            if (p != null) return p;
        }
        return statePart(true, request.query());
    }

    private static StatePart statePart(boolean inQuery, String raw) {
        if (raw == null || raw.isEmpty() || !raw.contains("__VIEWSTATE")) return null;
        Map<String, String> fields = StateFields.newMap();
        StateFields.fromParams(Codecs.parseQuery(raw), fields);
        if (!fields.containsKey("__VIEWSTATE")) return null;
        String vs = ViewStateDecoder.joinSplit(fields, new ArrayList<>());
        return vs == null ? null : new StatePart(inQuery, raw, fields, vs);
    }

    /**
     * Returns {@code raw} with {@code __VIEWSTATE} set to {@code newValue}; split chunks ({@code __VIEWSTATE1..N}) and
     * {@code __VIEWSTATEFIELDCOUNT} are removed so the whole state travels in the one field. Other pairs are kept as is.
     */
    static String replaceViewState(String raw, String newValue) {
        String[] pairs = raw.split("&", -1);
        List<String> out = new ArrayList<>(pairs.length);
        boolean done = false;
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            String rawKey = eq < 0 ? pair : pair.substring(0, eq);
            String key = Codecs.urlDecode(rawKey);
            if (SPLIT_FIELD.matcher(key).matches()) continue;
            if (key.equals("__VIEWSTATE")) {
                if (done) continue;
                done = true;
                out.add(rawKey + "=" + InsertionPoints.formEncode(newValue));
            } else {
                out.add(pair);
            }
        }
        return String.join("&", out);
    }

    static boolean isTypeHash(ObjectStateReader.StringSpan s) {
        return s.path().equals(TYPE_HASH_PATH) && TYPE_HASH.matcher(s.value()).matches();
    }

    // ================================================================ insertion points

    /**
     * One insertion point per string value inside an <b>unprotected</b> (no MAC, unencrypted) ViewState graph. With a
     * MAC the server rejects any change, so no points are offered. The rendered field holds the re-serialized,
     * re-base64'd state (split ViewState is collapsed into the single {@code __VIEWSTATE} field).
     */
    @Override
    public List<InsertionPoint> insertionPoints(MessageContext request, DecodeResult decoded) {
        StatePart part = statePart(request);
        if (part == null || part.fields().containsKey("__VIEWSTATEENCRYPTED")) return List.of();
        byte[] bytes = Codecs.base64Decode(part.viewState().replace(' ', '+'));
        if (bytes == null || !ObjectStateReader.hasMarker(bytes)) return List.of();
        ObjectStateReader.Spans spans = ObjectStateReader.spans(bytes);
        if (!spans.complete() || spans.end() != bytes.length) return List.of(); // MAC present (or junk): payloads would be rejected
        List<InsertionPoint> out = new ArrayList<>();
        for (ObjectStateReader.StringSpan s : spans.spans()) {
            if (out.size() >= InsertionPoints.MAX_POINTS) break;
            if (isTypeHash(s)) continue; // changing the page type hash just invalidates the state
            String name = "ViewState: __VIEWSTATE " + s.path();
            java.util.function.Function<String, byte[]> render = payload -> Codecs.latin1Bytes(
                    replaceViewState(part.raw(), Codecs.base64Encode(ObjectStateWriter.replace(bytes, s, payload))));
            out.add(part.inQuery() ? InsertionPoint.query(name, s.value(), render) : InsertionPoint.body(name, s.value(), render));
        }
        return out;
    }

    // ================================================================ active

    /** Resends the page with a tampered ViewState and compares the result with the base response. */
    static final class MacValidation implements ActiveCheck {
        private static final Pattern REJECTED = Pattern.compile(
                "(?i)validation of viewstate mac failed|viewstateexception|httpexception|the state information is invalid|invalid viewstate"
                        + "|failed to load viewstate|invalid postback or callback argument|\\|error\\|\\d{3}\\||server error in '|runtime error");
        private static final int MAX_HOSTS = 10_000;
        /** Hosts where MAC enforcement was already shown to be missing (don't keep probing every page). */
        private final Set<String> confirmed = ConcurrentHashMap.newKeySet();

        @Override public String id() { return "viewstate.mac-validation"; }
        @Override public String name() { return "ViewState MAC validation"; }
        @Override public String description() {
            return "POSTs with __VIEWSTATE: resends once with a tampered ViewState (one MAC byte flipped, or one string value changed when there is "
                    + "no MAC) and compares with the base response; 1 request, 2 if no base response is available. No payloads are sent.";
        }
        @Override public Scope scope() { return Scope.PER_REQUEST; }

        @Override
        public List<Finding> run(ActiveContext ctx) {
            MessageContext base = ctx.base();
            if (!"POST".equalsIgnoreCase(base.method())) return List.of();
            String host = base.host() == null ? "" : base.host();
            if (confirmed.contains(host)) return List.of();
            String body = Codecs.latin1String(base.requestBody());
            if (body.contains("__CALLBACKID=")) return List.of(); // DevExpress / client callbacks: response isn't a reliable signal
            StatePart part = statePart(base);
            if (part == null || part.inQuery() || part.fields().containsKey("__VIEWSTATEENCRYPTED")) return List.of();
            byte[] bytes = Codecs.base64Decode(part.viewState().replace(' ', '+'));
            if (bytes == null || !ObjectStateReader.hasMarker(bytes)) return List.of();
            ObjectStateReader.Spans spans = ObjectStateReader.spans(bytes);
            if (!spans.complete()) return List.of();
            boolean mac = spans.end() < bytes.length;
            byte[] tampered;
            String how;
            if (mac) {
                tampered = Arrays.copyOf(bytes, bytes.length);
                tampered[spans.end()] ^= 0x01;
                how = "flipped one bit in the first MAC byte (offset " + spans.end() + ")";
            } else {
                ObjectStateReader.StringSpan target = spans.spans().stream().filter(s -> !s.value().isEmpty() && !isTypeHash(s)).findFirst().orElse(null);
                if (target == null) return List.of();
                String v = target.value();
                String changed = v.substring(0, v.length() - 1) + (v.charAt(v.length() - 1) == 'x' ? 'y' : 'x');
                tampered = ObjectStateWriter.replace(bytes, target, changed);
                how = "changed the string value at <code>" + Finding.esc(target.path()) + "</code> (no MAC present)";
            }
            String newBody = replaceViewState(part.raw(), Codecs.base64Encode(tampered));
            String target = base.path() + (base.query() == null || base.query().isEmpty() ? "" : "?" + base.query());
            List<Header> headers = new ArrayList<>(base.requestHeaders());

            MessageContext baseline = ctx.baseResponse();
            Exchange baselineX = null;
            if (baseline == null || !baseline.hasResponse()) {
                baselineX = ctx.http().send(base.method(), target, headers, base.requestBody());
                if (baselineX == null || !baselineX.hasResponse()) return List.of();
                baseline = baselineX.message();
            }
            Exchange x = ctx.http().send(base.method(), target, headers, Codecs.latin1Bytes(newBody));
            if (x == null || !x.hasResponse()) return List.of();

            int baseStatus = baseline.statusCode() == null ? 0 : baseline.statusCode();
            String baseText = baseline.responseBodyText();
            String text = x.responseText();
            boolean newMarker = REJECTED.matcher(text).find() && !REJECTED.matcher(baseText).find();
            if (accepted(baseStatus, baseline.responseHeader("Location"), baseText, x, newMarker)) {
                if (confirmed.size() < MAX_HOSTS) confirmed.add(host);
                Finding f = Finding.of(id(), "ASP.NET ViewState MAC not enforced")
                        .severity(Severity.HIGH).confidence(Confidence.FIRM).scope(Finding.Scope.HOST)
                        .detail("The page was re-submitted with a tampered <code>__VIEWSTATE</code> (" + how + ") and the server answered like "
                                + "the original request (HTTP " + x.status() + ", no ViewState/MAC validation error, similar response). "
                                + (mac ? "The ViewState carries a MAC, but the server does not verify it."
                                       : "The ViewState has no MAC and modified state is accepted.")
                                + " An attacker can therefore supply arbitrary ObjectStateFormatter data, which can lead to remote code execution "
                                + "through deserialization gadgets. Confirm manually with an approved, non-destructive test.")
                        .background(MAC_BACKGROUND)
                        .remediation(MAC_REMEDIATION)
                        .requestEvidence("__VIEWSTATE");
                if (baselineX != null) f.exchange(baselineX);
                return List.of(f.exchange(x));
            }
            String trace = ScanPatterns.exceptionEvidence(text);
            if (trace != null && ScanPatterns.exceptionEvidence(baseText) == null) {
                Finding f = Finding.of(id(), "ASP.NET ViewState error discloses exception details")
                        .severity(Severity.LOW).confidence(Confidence.FIRM)
                        .detail("Submitting a tampered <code>__VIEWSTATE</code> (" + how + ") produced an error page with exception details: <code>"
                                + Finding.esc(trace) + "</code>")
                        .background("Detailed ASP.NET error pages (customErrors off) disclose framework versions, code paths and types.")
                        .remediation("Set <code>&lt;customErrors mode=\"On\"&gt;</code> (or RemoteOnly) and handle ViewState errors with a generic page.")
                        .responseEvidence(trace)
                        .exchange(x);
                return List.of(f);
            }
            return List.of();
        }

        /** True when the tampered request looks like the successful base request. */
        static boolean accepted(int baseStatus, String baseLocation, String baseText, Exchange x, boolean newMarker) {
            int st = x.status();
            if (baseStatus == 0 || baseStatus >= 400 || st != baseStatus || newMarker) return false;
            if (st >= 300 && st < 400) {
                String loc = x.message().responseHeader("Location");
                return loc != null && loc.equals(baseLocation);
            }
            int a = baseText.length(), b = x.responseText().length();
            return Math.abs(a - b) <= 2000 || (b >= a * 0.6 && b <= a * 1.6);
        }
    }
}
