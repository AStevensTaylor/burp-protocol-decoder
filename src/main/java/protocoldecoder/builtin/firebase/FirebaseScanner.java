package protocoldecoder.builtin.firebase;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import protocoldecoder.builtin.firebase.FirebaseDecoder.Variant;
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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static protocoldecoder.builtin.firebase.Fb.arr;
import static protocoldecoder.builtin.firebase.Fb.obj;
import static protocoldecoder.builtin.firebase.Fb.prim;
import static protocoldecoder.builtin.firebase.Fb.str;

/**
 * Scanner support for Firebase: configuration / token / rules-related passive checks, read-only unauthenticated
 * access probes against the target project's Realtime Database and Firestore, and insertion points inside Firestore
 * WebChannel {@code reqN___data__} JSON.
 *
 * <p>All active probes are single, read-only GET/query requests sent to the base request's own host (the target
 * project's database endpoint); nothing writes, deletes or creates accounts.</p>
 */
public final class FirebaseScanner implements ProtocolScanner {

    private static final Pattern REQ_DATA = Pattern.compile("^req(\\d{1,6})___data__$");
    private static final Pattern DOC_NAME = Pattern.compile("\"name\"\\s*:\\s*\"(projects/[^\"/]+/databases/[^\"/]+/documents/[^\"]+)\"");
    private static final Pattern FS_REST_PATH = Pattern.compile("^/v1(?:beta\\d)?/(projects/[^/]+/databases/[^/]+)/documents(?:/([^:]*))?(?::([A-Za-z]+))?$");
    private static final Set<String> READ_RPCS = Set.of("runQuery", "batchGet", "runAggregationQuery");
    /** Typed-value keys whose values are app data worth fuzzing (not Firestore framing). */
    private static final Set<String> FUZZ_VALUE_KEYS = Set.of("stringValue", "integerValue", "doubleValue", "timestampValue", "referenceValue");
    private static final Set<String> AUTH_HEADERS = Set.of("authorization", "cookie", "proxy-authorization", "x-firebase-auth-token",
            "x-goog-firebase-installations-auth", "content-length");
    private static final Set<String> BODY_HEADERS = Set.of("content-type", "content-encoding");
    private static final Set<String> AUTH_PARAMS = Set.of("auth", "access_token");
    private static final Set<String> STANDARD_CLAIMS = Set.of("iss", "aud", "auth_time", "user_id", "sub", "iat", "exp", "nbf",
            "email", "email_verified", "firebase", "name", "picture", "phone_number", "provider_id", "uid", "jti", "azp", "at_hash");
    private static final Pattern PRIVILEGED_CLAIM = Pattern.compile("(?i)admin|role|perm|group|staff|super|owner|tenant|org|scope|level|tier|plan|access");
    private static final int MAX_LISTED = 20;

    @Override
    public String decoderId() {
        return FirebaseDecoder.ID;
    }

    /** Created once so per-scanner state (the list probe's deduplication) survives across scans. */
    private final List<ActiveCheck> active = List.of(new RtdbUnauthRead(), new FirestoreUnauthRead(), new FirestoreUnauthList());

    @Override
    public List<PassiveCheck> passiveChecks() {
        return List.of(new WebConfig(), new TokenCustomClaims(), new TokenLifetime(), new SensitiveData(), new PermissionDenied(),
                new SelfRegistration(), new AccountEnumeration());
    }

    @Override
    public List<ActiveCheck> activeChecks() {
        return active;
    }

    // ================================================================ insertion points

    /**
     * Firestore WebChannel forward-channel bodies carry each message as JSON in a {@code reqN___data__} form field. One
     * insertion point per Firestore value leaf (filter values, document field values) inside those messages; the other
     * form fields ({@code count}, {@code ofs}, other maps) are kept byte-for-byte, so the framing stays consistent.
     */
    @Override
    public List<InsertionPoint> insertionPoints(MessageContext request, DecodeResult decoded) {
        List<InsertionPoint> out = new ArrayList<>();
        if (FirebaseDecoder.variant(request) != Variant.FIRESTORE_CHANNEL) return out;
        if (request.requestHeader("Content-Encoding") != null) return out;
        String body = request.requestBodyText();
        if (body.isBlank()) return out;
        Map<String, List<String>> form = Codecs.parseQuery(body);
        for (Map.Entry<String, List<String>> e : form.entrySet()) {
            if (!REQ_DATA.matcher(e.getKey()).matches() || e.getValue().isEmpty()) continue;
            String field = e.getKey();
            JsonElement j = JsonTree.parseStrict(e.getValue().get(0));
            if (j == null || !(j.isJsonObject() || j.isJsonArray())) continue;
            for (InsertionPoints.JsonLeaf leaf : InsertionPoints.jsonLeaves(j)) {
                if (out.size() >= InsertionPoints.MAX_POINTS) return out;
                String path = leaf.path();
                String last = path.substring(path.lastIndexOf('.') + 1);
                if (!FUZZ_VALUE_KEYS.contains(last)) continue;
                out.add(InsertionPoint.body("Firestore: " + field + " " + path, InsertionPoints.text(leaf.value()),
                        payload -> InsertionPoints.replaceFormField(body, field, 0, leaf.replace().apply(payload)).getBytes(StandardCharsets.UTF_8)));
            }
        }
        return out;
    }

    // ================================================================ helpers

    private static String responseText(MessageContext m) {
        return Fb.text(m.responseBody(), m.responseHeader("Content-Encoding"));
    }

    private static int status(MessageContext m) {
        return m.statusCode() == null ? 0 : m.statusCode();
    }

    private static void walk(DecodedNode n, java.util.function.Consumer<DecodedNode> f, int[] budget) {
        if (n == null || budget[0]-- <= 0) return;
        f.accept(n);
        for (DecodedNode c : n.children()) walk(c, f, budget);
    }

    /** Firebase-auth-like JWTs found anywhere in the decoded tree (headers, query, RTDB cred, Auth responses). */
    static List<Fb.Jwt.Parsed> tokens(DecodeResult decoded) {
        List<Fb.Jwt.Parsed> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        if (decoded == null) return out;
        walk(decoded.root(), n -> {
            if (out.size() >= 5 || !n.name().endsWith("(JWT)")) return;
            DecodedNode t = n.get("token");
            if (t == null || t.value() == null || !seen.add(t.value())) return;
            Fb.Jwt.Parsed p = Fb.Jwt.parse(t.value());
            if (p == null || p.claims() == null) return;
            String iss = str(p.claims(), "iss");
            if (iss != null && iss.contains("firebaseappcheck")) return; // App Check token, not user auth
            out.add(p);
        }, new int[]{20_000});
        return out;
    }

    static boolean isFirebaseIdToken(Fb.Jwt.Parsed p) {
        String iss = str(p.claims(), "iss");
        return iss != null && iss.startsWith("https://securetoken.google.com/");
    }

    static long claimLong(JsonObject c, String k) {
        String v = str(c, k);
        if (v == null || !v.matches("\\d{1,12}")) return -1;
        return Long.parseLong(v);
    }

    /** Headers without user credentials (Authorization, cookies, Firebase auth tokens); body headers dropped when {@code noBody}. */
    static List<Header> unauthHeaders(List<Header> headers, boolean noBody) {
        List<Header> out = new ArrayList<>();
        for (Header h : headers) {
            String n = h.name().toLowerCase(Locale.ROOT);
            if (AUTH_HEADERS.contains(n)) continue;
            if (noBody && BODY_HEADERS.contains(n)) continue;
            out.add(h);
        }
        return out;
    }

    static boolean hasAuth(MessageContext m) {
        String a = m.requestHeader("Authorization");
        if (a != null && !a.isBlank()) return true;
        Map<String, List<String>> q = m.queryParameters();
        for (String p : AUTH_PARAMS) if (q.containsKey(p)) return true;
        return false;
    }

    /** Raw query string with credential parameters ({@code auth}, {@code access_token}) removed, other pairs kept as-is. */
    static String stripAuthParams(String query) {
        if (query == null || query.isEmpty()) return "";
        List<String> keep = new ArrayList<>();
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            String k = Codecs.urlDecode(eq < 0 ? pair : pair.substring(0, eq));
            if (!AUTH_PARAMS.contains(k)) keep.add(pair);
        }
        return String.join("&", keep);
    }

    /** Percent-encodes one path segment (spaces as %20). */
    static String seg(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20").replace("%28", "(").replace("%29", ")");
    }

    static Set<String> docNames(String json) {
        Set<String> out = new LinkedHashSet<>();
        if (json == null) return out;
        Matcher m = DOC_NAME.matcher(json.length() > 4_000_000 ? json.substring(0, 4_000_000) : json);
        while (m.find() && out.size() < 10_000) out.add(m.group(1));
        return out;
    }

    static String keysList(JsonObject o) {
        StringBuilder sb = new StringBuilder("<ul>");
        int i = 0;
        for (String k : o.keySet()) {
            if (i++ >= MAX_LISTED) {
                sb.append("<li>… ").append(o.size() - MAX_LISTED).append(" more</li>");
                break;
            }
            sb.append("<li><code>").append(Finding.esc(Codecs.truncate(k, 200))).append("</code></li>");
        }
        return sb.append("</ul>").toString();
    }

    private static String rulesBackground() {
        return "Firebase clients talk directly to Google-hosted databases; the only access control is the project's Security Rules "
                + "(plus optional App Check). Rules that allow reads without <code>request.auth</code> checks, or that only check "
                + "<code>request.auth != null</code>, expose data to anyone holding the public web config (and anyone who can self-register).";
    }

    // ================================================================ passive checks

    /** Firebase web configuration in pages / scripts / Hosting init.json. */
    static final class WebConfig implements PassiveCheck {
        @Override public String id() { return "firebase.web-config"; }
        @Override public String name() { return "Firebase web configuration exposed"; }
        @Override public String description() {
            return "Firebase config (apiKey, projectId, databaseURL, storageBucket, appId) in a page or script — once per host; lists the project's endpoints to test Security Rules against";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || decoded == null || !"Firebase web configuration".equals(decoded.root().name())) return List.of();
            StringBuilder sb = new StringBuilder("The response contains Firebase web configuration:");
            List<String> evidence = new ArrayList<>();
            int configs = 0;
            for (DecodedNode cfg : decoded.root().children()) {
                if (!cfg.name().startsWith("Firebase config") || configs++ >= 5) continue;
                sb.append("<ul>");
                for (DecodedNode leaf : cfg.children()) {
                    if (!leaf.isLeaf() || leaf.value() == null || leaf.type() == DecodedNode.Type.NOTE) continue;
                    sb.append("<li><code>").append(Finding.esc(leaf.name())).append("</code>: <code>")
                            .append(Finding.esc(Codecs.truncate(leaf.value(), 300))).append("</code></li>");
                    if (leaf.name().equals("apiKey") || leaf.name().equals("projectId") || leaf.name().equals("databaseURL")) evidence.add(leaf.value());
                }
                DecodedNode derived = cfg.get("Derived endpoints");
                if (derived != null && !derived.isLeaf()) {
                    sb.append("<li>Endpoints to test: <ul>");
                    for (DecodedNode d : derived.children()) {
                        sb.append("<li>").append(Finding.esc(d.name())).append(": <code>").append(Finding.esc(d.value())).append("</code></li>");
                    }
                    sb.append("</ul></li>");
                }
                sb.append("</ul>");
            }
            if (configs == 0) return List.of();
            Finding f = Finding.of(id(), "Firebase web configuration exposed")
                    .severity(Severity.INFORMATION).confidence(Confidence.CERTAIN).scope(Finding.Scope.HOST)
                    .detail(sb + "Firebase Web API keys are <b>public by design</b> (they identify the project, they are not secrets). "
                            + "The risk lies in the project's Security Rules: use these values to test whether Firestore, the Realtime Database "
                            + "and Cloud Storage can be read or written without authentication or by any signed-in user.")
                    .background(rulesBackground())
                    .remediation("No change is needed to hide the config. Review Security Rules for every Firebase product (deny by default, "
                            + "check ownership/roles, not just <code>request.auth != null</code>), enable App Check, and restrict the API key to "
                            + "the required APIs and HTTP referrers in Google Cloud console.");
            evidence.forEach(f::responseEvidence);
            return List.of(f);
        }
    }

    /** Custom claims (admin, role, …) in Firebase ID tokens. */
    static final class TokenCustomClaims implements PassiveCheck {
        @Override public String id() { return "firebase.token-custom-claims"; }
        @Override public String name() { return "Firebase ID token custom claims"; }
        @Override public String description() {
            return "Firebase ID tokens carrying custom claims (e.g. admin, role) — reveals the authorization model the Security Rules rely on; once per host";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            for (Fb.Jwt.Parsed p : tokens(decoded)) {
                if (!isFirebaseIdToken(p)) continue;
                List<String> custom = new ArrayList<>();
                boolean privileged = false;
                for (Map.Entry<String, JsonElement> e : p.claims().entrySet()) {
                    if (STANDARD_CLAIMS.contains(e.getKey())) continue;
                    custom.add("<li><code>" + Finding.esc(e.getKey()) + "</code> = <code>" + Finding.esc(Codecs.truncate(e.getValue().toString(), 200)) + "</code></li>");
                    if (PRIVILEGED_CLAIM.matcher(e.getKey()).find()) privileged = true;
                    if (custom.size() >= MAX_LISTED) break;
                }
                if (custom.isEmpty()) continue;
                Finding f = Finding.of(id(), "Firebase ID token carries custom claims")
                        .severity(Severity.INFORMATION).confidence(Confidence.FIRM).scope(Finding.Scope.HOST)
                        .detail("A Firebase ID token (" + Finding.esc(Fb.Jwt.describe(p)) + ") contains custom claims:<ul>" + String.join("", custom) + "</ul>"
                                + (privileged ? "Some claims look authorization-related. Security Rules and backend code probably grant access based on them: "
                                + "test whether the code paths that <i>set</i> these claims (admin endpoints, Cloud Functions) can be reached by ordinary users, "
                                + "and whether rules also trust user-writable document fields for the same decisions." : ""))
                        .background("Custom claims are set server-side with the Admin SDK and are signed into every ID token; Security Rules read them as "
                                + "<code>request.auth.token.&lt;claim&gt;</code>. They are not secret, but they document the roles the application enforces.")
                        .remediation("No change required if claims are only set by trusted server code. Ensure rules check claims rather than "
                                + "client-writable profile fields, and that tokens are refreshed after claims are revoked.");
                return List.of(f);
            }
            return List.of();
        }
    }

    /** Tokens used for Firebase auth with a lifetime well beyond the 1-hour Firebase ID token. */
    static final class TokenLifetime implements PassiveCheck {
        static final long LIMIT = 2 * 3600;

        @Override public String id() { return "firebase.token-lifetime"; }
        @Override public String name() { return "Long-lived Firebase auth token"; }
        @Override public String description() {
            return "JWTs used with Firebase (Authorization header, RTDB auth, Identity Toolkit responses) valid for more than 2 hours (Firebase ID tokens last 1 hour); once per host";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            for (Fb.Jwt.Parsed p : tokens(decoded)) {
                long iat = claimLong(p.claims(), "iat"), exp = claimLong(p.claims(), "exp");
                if (iat < 0 || exp < 0 || exp - iat <= LIMIT) continue;
                long hours = (exp - iat) / 3600;
                Finding f = Finding.of(id(), "Long-lived Firebase authentication token")
                        .severity(Severity.LOW).confidence(Confidence.FIRM).scope(Finding.Scope.HOST)
                        .detail("A JWT used for Firebase authentication (" + Finding.esc(Fb.Jwt.describe(p)) + ") is valid for <b>" + hours
                                + " hours</b> (iat " + iat + ", exp " + exp + ")." + (isFirebaseIdToken(p) ? "" : " Its issuer is not "
                                + "<code>securetoken.google.com</code>, so it is minted by the application or another identity provider."))
                        .background("Firebase ID tokens are short-lived (1 hour) and refreshed with a refresh token, which limits the impact of a leaked token. "
                                + "Tokens with long lifetimes stay usable after logout or account changes.")
                        .remediation("Use standard Firebase ID tokens (1 hour) with refresh tokens, or reduce the lifetime of custom tokens; "
                                + "revoke refresh tokens on logout and password change.");
                return List.of(f);
            }
            return List.of();
        }
    }

    /** Sensitive-looking values in Firestore / RTDB data returned to the client. */
    static final class SensitiveData implements PassiveCheck {
        @Override public String id() { return "firebase.sensitive-data"; }
        @Override public String name() { return "Sensitive data in Firestore / Realtime Database responses"; }
        @Override public String description() {
            return "Credentials, tokens, card numbers or several email addresses inside database documents returned to the client (top hits per response)";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (decoded == null) return List.of();
            Variant v = FirebaseDecoder.variant(m);
            boolean data = switch (v) {
                case FIRESTORE_CHANNEL, FIRESTORE_REST, RTDB_REST, RTDB_LONGPOLL -> m.isResponse();
                case RTDB_WS -> m.isWebSocket() && !"CLIENT_TO_SERVER".equals(m.webSocketDirection());
                default -> false;
            };
            if (!data) return List.of();
            List<ScanPatterns.Sensitive> hits = new ArrayList<>(ScanPatterns.sensitiveValues(decoded.root(), 40));
            // Firebase plumbing that matches the generic patterns
            hits.removeIf(h -> h.path().contains("Firebase headers") || h.path().contains("resumeToken") || h.path().contains("streamToken")
                    || h.path().contains("Channel parameters"));
            long emails = hits.stream().filter(h -> h.kind().equals("email address")).map(ScanPatterns.Sensitive::value).distinct().count();
            // one email is usually the signed-in user's own profile; several suggest other users' data
            if (emails < 3) hits.removeIf(h -> h.kind().equals("email address"));
            if (hits.isEmpty()) return List.of();
            List<ScanPatterns.Sensitive> top = hits.subList(0, Math.min(10, hits.size()));
            Finding f = Finding.of(id(), "Sensitive data in Firebase database response")
                    .severity(Severity.LOW).confidence(Confidence.TENTATIVE)
                    .detail("Data read from the Firebase database contains values that look sensitive"
                            + (hits.size() > top.size() ? " (" + top.size() + " of " + hits.size() + " shown)" : "") + ":" + ScanPatterns.htmlList(top)
                            + "Check whether the current user should be able to read these documents/paths and whether the same data is "
                            + "readable by other users or without authentication.")
                    .background(rulesBackground() + " Data the client can read is often broader than what the UI displays.")
                    .remediation("Store secrets server-side only; restrict reads in Security Rules to the owning user/role; move sensitive "
                            + "fields to separate documents/paths with stricter rules.");
            for (ScanPatterns.Sensitive h : top) f.responseEvidence(h.value());
            return List.of(f);
        }
    }

    /** Security Rules denials that name the protected path. */
    static final class PermissionDenied implements PassiveCheck {
        @Override public String id() { return "firebase.permission-denied"; }
        @Override public String name() { return "Security Rules permission denied (path)"; }
        @Override public String description() {
            return "Firestore / Realtime Database permission-denied errors for a known path — maps which paths rules protect (useful targets for rules testing)";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            Variant v = FirebaseDecoder.variant(m);
            String path = null, product = null, evidence = null;
            if (m.isResponse() && v == Variant.RTDB_REST) {
                JsonObject o = obj(Fb.parse(responseText(m)));
                String err = str(o, "error");
                if (err != null && err.toLowerCase(Locale.ROOT).contains("permission denied")) {
                    String p = Codecs.urlDecode(m.path());
                    path = p.endsWith(".json") ? p.substring(0, p.length() - 5) : p;
                    if (path.isEmpty()) path = "/";
                    product = "Realtime Database";
                    evidence = err;
                }
            } else if (m.isResponse() && v == Variant.FIRESTORE_REST) {
                JsonElement j = Fb.parse(responseText(m));
                JsonObject e = obj(j, "error");
                if (e == null && j != null && j.isJsonArray() && !j.getAsJsonArray().isEmpty()) e = obj(j.getAsJsonArray().get(0), "error");
                if (e != null && "PERMISSION_DENIED".equals(str(e, "status"))) {
                    String p = Codecs.urlDecode(m.path());
                    int i = p.indexOf("/documents");
                    path = i >= 0 ? p.substring(i + "/documents".length()) : p;
                    if (path.isEmpty() || path.startsWith(":")) path = "/" + path;
                    product = "Firestore";
                    evidence = "PERMISSION_DENIED";
                }
            } else if (m.isWebSocket() && v == Variant.RTDB_WS && !"CLIENT_TO_SERVER".equals(m.webSocketDirection())) {
                JsonObject d = obj(Fb.parse(m.bodyText()), "d");
                JsonObject b = obj(d, "b");
                if ("c".equals(str(d, "a")) && b != null && str(b, "p") != null && "permission_denied".equals(str(b, "msg"))) {
                    path = str(b, "p").startsWith("/") ? str(b, "p") : "/" + str(b, "p");
                    product = "Realtime Database";
                    evidence = "permission_denied";
                }
            }
            if (path == null) return List.of();
            return List.of(Finding.of(id(), "Firebase " + product + " Security Rules denied access")
                    .severity(Severity.INFORMATION).confidence(Confidence.FIRM)
                    .detail("The " + product + " rejected access to <code>" + Finding.esc(Codecs.truncate(path, 500)) + "</code> with a permission-denied error. "
                            + "This path exists in the application's data model and is protected by Security Rules: test it with other users' "
                            + "accounts, sibling paths and parent paths (rules do not cascade the same way for reads and writes).")
                    .background(rulesBackground())
                    .remediation("No action required; this is an inventory finding for rules testing.")
                    .responseEvidence(evidence));
        }
    }

    /** Successful Identity Toolkit sign-up by the app (self-registration / anonymous auth enabled). */
    static final class SelfRegistration implements PassiveCheck {
        @Override public String id() { return "firebase.self-registration"; }
        @Override public String name() { return "Firebase Auth self-registration enabled"; }
        @Override public String description() {
            return "accounts:signUp succeeding — anyone can obtain a Firebase ID token, so rules that only check request.auth != null are effectively public; once per host";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || FirebaseDecoder.variant(m) != Variant.IDENTITY_TOOLKIT) return List.of();
            String p = m.path();
            if (!p.endsWith("accounts:signUp") && !p.endsWith("/signupNewUser")) return List.of();
            int st = status(m);
            if (st < 200 || st >= 300) return List.of();
            JsonObject o = obj(Fb.parse(responseText(m)));
            if (o == null || (str(o, "idToken") == null && str(o, "localId") == null)) return List.of();
            JsonObject req = obj(Fb.parse(Fb.text(m.requestBody(), m.requestHeader("Content-Encoding"))));
            boolean anonymous = req == null || (str(req, "email") == null && str(req, "phoneNumber") == null);
            boolean linking = req != null && str(req, "idToken") != null;
            String title = anonymous && !linking ? "Firebase anonymous sign-in enabled" : "Firebase Auth self-registration enabled";
            return List.of(Finding.of(id(), title)
                    .severity(Severity.INFORMATION).confidence(Confidence.CERTAIN).scope(Finding.Scope.HOST)
                    .detail((anonymous && !linking
                            ? "The application created an <b>anonymous</b> Firebase account via <code>" + Finding.esc(p) + "</code>."
                            : "The application registered a new email/password account via <code>" + Finding.esc(p) + "</code>.")
                            + " Anyone with the public API key can call this endpoint directly and obtain a valid ID token"
                            + (str(o, "localId") != null ? " (new uid <code>" + Finding.esc(str(o, "localId")) + "</code>)" : "") + ". "
                            + "Security Rules that only require <code>request.auth != null</code> therefore grant access to anyone.")
                    .background(rulesBackground())
                    .remediation("If self-registration is not intended, disable the provider (or enable Identity Platform blocking functions). "
                            + "Write rules that check ownership (<code>request.auth.uid == userId</code>), custom claims or "
                            + "<code>email_verified</code> rather than mere sign-in.")
                    .responseEvidence(str(o, "localId")));
        }
    }

    /** Identity Toolkit answers that distinguish existing from unknown accounts. */
    static final class AccountEnumeration implements PassiveCheck {
        @Override public String id() { return "firebase.account-enumeration"; }
        @Override public String name() { return "Firebase Auth account enumeration"; }
        @Override public String description() {
            return "createAuthUri 'registered'/sign-in methods, or EMAIL_NOT_FOUND / INVALID_PASSWORD errors — email enumeration protection is off; once per host";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || FirebaseDecoder.variant(m) != Variant.IDENTITY_TOOLKIT) return List.of();
            String p = m.path();
            JsonObject o = obj(Fb.parse(responseText(m)));
            if (o == null) return List.of();
            String how = null, evidence = null;
            if (p.endsWith("createAuthUri")) {
                JsonArray methods = arr(o, "signinMethods");
                JsonArray providers = arr(o, "allProviders");
                if (o.has("registered")) {
                    how = "<code>createAuthUri</code> returned <code>\"registered\": " + Finding.esc(str(o, "registered")) + "</code> for the submitted email";
                    evidence = "\"registered\"";
                } else if ((methods != null && !methods.isEmpty()) || (providers != null && !providers.isEmpty())) {
                    how = "<code>createAuthUri</code> returned the sign-in methods registered for the submitted email";
                    evidence = methods != null ? "signinMethods" : "allProviders";
                }
            } else {
                String msg = str(obj(o, "error"), "message");
                if (msg != null) {
                    String code = msg.split("[ :]", 2)[0];
                    if (code.equals("EMAIL_NOT_FOUND") || code.equals("INVALID_PASSWORD") || code.equals("USER_NOT_FOUND")) {
                        how = "<code>" + Finding.esc(p.substring(p.lastIndexOf('/') + 1)) + "</code> returned <code>" + Finding.esc(code)
                                + "</code>; with enumeration protection the error would be the generic <code>INVALID_LOGIN_CREDENTIALS</code>";
                        evidence = code;
                    }
                }
            }
            if (how == null) return List.of();
            return List.of(Finding.of(id(), "Firebase Auth allows account enumeration")
                    .severity(Severity.LOW).confidence(Confidence.FIRM).scope(Finding.Scope.HOST)
                    .detail(how + ". The Identity Toolkit API can be called directly with the public API key, so registered email "
                            + "addresses can be enumerated.")
                    .background("Firebase Authentication distinguishes unknown accounts from wrong passwords unless <i>email enumeration "
                            + "protection</i> is enabled (default for projects created since September 2023).")
                    .remediation("Enable email enumeration protection in Firebase console → Authentication → Settings (or Identity Platform "
                            + "settings) and handle the generic INVALID_LOGIN_CREDENTIALS error in the client.")
                    .responseEvidence(evidence));
        }
    }

    // ================================================================ active checks

    /**
     * {@code GET /.json?shallow=true} without credentials against the Realtime Database host. Only runs when the base
     * request itself targets the RTDB host: the sender can only reach the base request's host, so a databaseURL seen
     * only in a page config is not probed (open {@code <databaseURL>/.json?shallow=true} manually).
     */
    static final class RtdbUnauthRead implements ActiveCheck {
        @Override public String id() { return "firebase.rtdb-unauth-read"; }
        @Override public String name() { return "Realtime Database readable without auth"; }
        @Override public String description() {
            return "1 request per host: GET /.json?shallow=true without credentials (top-level keys only, read-only). Runs only for scanned requests to "
                    + "the *.firebaseio.com / *.firebasedatabase.app host itself";
        }
        @Override public Scope scope() { return Scope.PER_HOST; }

        @Override
        public List<Finding> run(ActiveContext ctx) {
            MessageContext base = ctx.base();
            if (!FirebaseDecoder.isRtdbHost(base.host().toLowerCase(Locale.ROOT))) return List.of();
            String ns = Codecs.first(base.queryParameters(), "ns");
            String target = "/.json?shallow=true" + (ns != null && ns.matches("[A-Za-z0-9-]{1,100}") ? "&ns=" + ns : "");
            Exchange x = ctx.http().send("GET", target, unauthHeaders(base.requestHeaders(), true), new byte[0]);
            if (x == null || !x.hasResponse() || x.status() != 200) return List.of();
            JsonElement j = Fb.parse(x.responseText());
            if (j == null || j.isJsonNull()) return List.of();
            JsonObject o = obj(j);
            if (o != null && (o.isEmpty() || (o.size() == 1 && o.has("error")))) return List.of();
            String detail = o != null ? "Top-level keys:" + keysList(o) : "Root value: <code>" + Finding.esc(Codecs.truncate(j.toString(), 200)) + "</code>";
            Finding f = Finding.of(id(), "Firebase Realtime Database readable without authentication")
                    .severity(Severity.MEDIUM).confidence(Confidence.FIRM).scope(Finding.Scope.HOST)
                    .detail("An unauthenticated <code>GET " + Finding.esc(target) + "</code> to <code>" + Finding.esc(base.host())
                            + "</code> returned database content. " + detail
                            + "Only keys were requested (<code>shallow=true</code>); fetch individual paths to assess what data is exposed.")
                    .background(rulesBackground() + " A root rule such as <code>\".read\": true</code> exposes the entire database.")
                    .remediation("Set <code>\".read\": false</code> at the root and grant reads per path with conditions on <code>auth.uid</code> / custom claims.")
                    .exchange(x);
            if (o != null) {
                int i = 0;
                for (String k : o.keySet()) {
                    if (i++ >= 5) break;
                    f.responseEvidence("\"" + k + "\"");
                }
            }
            return List.of(f);
        }
    }

    /** Resends an authenticated Firestore REST read (GET / runQuery / batchGet) without credentials. */
    static final class FirestoreUnauthRead implements ActiveCheck {
        @Override public String id() { return "firebase.firestore-unauth-read"; }
        @Override public String name() { return "Firestore document readable without auth"; }
        @Override public String description() {
            return "1 request per authenticated Firestore REST read (GET, runQuery, batchGet): resends it without Authorization/cookies/auth params "
                    + "and compares the returned document names";
        }
        @Override public Scope scope() { return Scope.PER_REQUEST; }

        @Override
        public List<Finding> run(ActiveContext ctx) {
            MessageContext base = ctx.base();
            if (FirebaseDecoder.variant(base) != Variant.FIRESTORE_REST || !hasAuth(base)) return List.of();
            Matcher pm = FS_REST_PATH.matcher(Codecs.urlDecode(base.path()));
            if (!pm.matches()) return List.of();
            String rpc = pm.group(3);
            boolean read = rpc == null ? base.method().equals("GET") : base.method().equals("POST") && READ_RPCS.contains(rpc);
            if (!read) return List.of();
            MessageContext resp = ctx.baseResponse();
            if (resp == null || status(resp) != 200) return List.of();
            Set<String> baseDocs = docNames(responseText(resp));
            if (baseDocs.isEmpty()) return List.of();
            String q = stripAuthParams(base.query());
            String target = base.path() + (q.isEmpty() ? "" : "?" + q);
            byte[] body = base.method().equals("GET") ? new byte[0] : base.requestBody();
            Exchange x = ctx.http().send(base.method(), target, unauthHeaders(base.requestHeaders(), body.length == 0), body);
            if (x == null || !x.hasResponse()) return List.of();
            String text = x.responseText();
            if (x.status() == 200) {
                Set<String> got = docNames(text);
                got.retainAll(baseDocs);
                if (got.isEmpty()) return List.of();
                StringBuilder list = new StringBuilder("<ul>");
                int i = 0;
                for (String d : got) {
                    if (i++ >= MAX_LISTED) break;
                    list.append("<li><code>").append(Finding.esc(Firestore.docPath(d))).append("</code></li>");
                }
                list.append("</ul>");
                Finding f = Finding.of(id(), "Firestore data readable without authentication")
                        .severity(Severity.HIGH).confidence(Confidence.FIRM)
                        .detail("The application's authenticated Firestore request <code>" + Finding.esc(base.method() + " " + Codecs.urlDecode(base.path()))
                                + "</code> was resent without the <code>Authorization</code> header, cookies or auth parameters and returned "
                                + got.size() + " of the same documents:" + list)
                        .background(rulesBackground())
                        .remediation("Require authentication and ownership in the rules for this collection, e.g. "
                                + "<code>allow read: if request.auth != null &amp;&amp; request.auth.uid == resource.data.owner;</code>")
                        .exchange(x);
                f.responseEvidence(baseDocs.iterator().next());
                return List.of(f);
            }
            if (x.status() == 401 || x.status() == 403 || text.contains("PERMISSION_DENIED")) {
                return List.of(Finding.of(id(), "Firestore read requires authentication")
                        .severity(Severity.INFORMATION).confidence(Confidence.FIRM)
                        .detail("Resending <code>" + Finding.esc(base.method() + " " + Codecs.urlDecode(base.path()))
                                + "</code> without credentials was denied by Security Rules (HTTP " + x.status() + "). "
                                + "Rules still need testing with <i>other</i> signed-in users (horizontal access) and self-registered accounts.")
                        .background(rulesBackground())
                        .remediation("No action required.")
                        .exchange(x));
            }
            return List.of();
        }
    }

    /**
     * Lists the collection behind an observed Firestore document/query ({@code GET …/documents/<collection>?pageSize=1})
     * without credentials. Collections come from Firestore REST paths/queries and from WebChannel Listen/Write targets
     * (the probe itself is a plain REST GET to the same firestore.googleapis.com host). Each collection is probed once.
     */
    static final class FirestoreUnauthList implements ActiveCheck {
        private final Set<String> probed = ConcurrentHashMap.newKeySet();

        @Override public String id() { return "firebase.firestore-unauth-list"; }
        @Override public String name() { return "Firestore collection listable without auth"; }
        @Override public String description() {
            return "1 request per observed collection (deduplicated): GET /v1/<db>/documents/<collection>?pageSize=1 without credentials, derived "
                    + "from Firestore REST paths/queries and WebChannel targets";
        }
        @Override public Scope scope() { return Scope.PER_REQUEST; }

        @Override
        public List<Finding> run(ActiveContext ctx) {
            MessageContext base = ctx.base();
            String[] coll = collection(base);
            if (coll == null) return List.of();
            String db = coll[0], collection = coll[1];
            if (!db.matches("projects/[A-Za-z0-9._:-]{1,100}/databases/[A-Za-z0-9()._-]{1,100}") || collection.isEmpty()) return List.of();
            if (probed.size() > 5000 || !probed.add(base.host() + "|" + db + "|" + collection)) return List.of();
            StringBuilder path = new StringBuilder("/v1/").append(db).append("/documents");
            for (String s : collection.split("/")) path.append('/').append(seg(s));
            String key = Codecs.first(base.queryParameters(), "key");
            String target = path + "?pageSize=1" + (key != null && key.matches("[A-Za-z0-9_-]{10,100}") ? "&key=" + key : "");
            Exchange x = ctx.http().send("GET", target, unauthHeaders(base.requestHeaders(), true), new byte[0]);
            if (x == null || !x.hasResponse() || x.status() != 200) return List.of();
            JsonObject o = obj(Fb.parse(x.responseText()));
            JsonArray docs = arr(o, "documents");
            if (docs == null || docs.isEmpty()) return List.of();
            String first = str(docs.get(0), "name");
            Finding f = Finding.of(id(), "Firestore collection listable without authentication")
                    .severity(Severity.MEDIUM).confidence(Confidence.FIRM)
                    .detail("An unauthenticated <code>GET " + Finding.esc(target) + "</code> listed documents of collection <code>"
                            + Finding.esc(collection) + "</code>" + (first == null ? "" : " (first: <code>" + Finding.esc(Firestore.docPath(first)) + "</code>)")
                            + (o.has("nextPageToken") ? "; more pages are available" : "") + ". Only one document was requested "
                            + "(<code>pageSize=1</code>); page through the collection to assess the exposure.")
                    .background(rulesBackground() + " <code>allow read</code> covers both <code>get</code> and <code>list</code>; "
                            + "rules that intend per-document access often allow listing the whole collection.")
                    .remediation("Split <code>read</code> into <code>get</code> and <code>list</code> rules, require authentication and constrain "
                            + "list queries (e.g. <code>resource.data.owner == request.auth.uid</code>).")
                    .exchange(x);
            if (first != null) f.responseEvidence(first);
            return List.of(f);
        }

        /** [database, collection path] for the base request, or null. */
        static String[] collection(MessageContext m) {
            Variant v = FirebaseDecoder.variant(m);
            if (v == Variant.FIRESTORE_REST) {
                Matcher pm = FS_REST_PATH.matcher(Codecs.urlDecode(m.path()));
                if (!pm.matches()) return null;
                String db = pm.group(1), rest = pm.group(2) == null ? "" : pm.group(2), rpc = pm.group(3);
                if (rpc != null) {
                    if (!rpc.equals("runQuery") && !rpc.equals("runAggregationQuery")) return null;
                    JsonElement j = Fb.parse(Fb.text(m.requestBody(), m.requestHeader("Content-Encoding")));
                    JsonObject sq = obj(j, "structuredQuery");
                    if (sq == null) sq = obj(obj(j, "structuredAggregationQuery"), "structuredQuery");
                    String c = fromCollection(sq);
                    return c == null ? null : new String[]{db, join(rest, c)};
                }
                return new String[]{db, collectionOf(rest)};
            }
            if (v == Variant.FIRESTORE_CHANNEL && m.isRequest()) {
                Map<String, List<String>> form = Codecs.parseQuery(Fb.text(m.requestBody(), m.requestHeader("Content-Encoding")));
                for (Map.Entry<String, List<String>> e : form.entrySet()) {
                    if (!REQ_DATA.matcher(e.getKey()).matches()) continue;
                    JsonObject o = obj(Fb.parse(e.getValue().get(0)));
                    String[] r = channelCollection(o);
                    if (r != null) return r;
                }
            }
            return null;
        }

        private static String[] channelCollection(JsonObject o) {
            JsonObject add = obj(o, "addTarget");
            JsonObject q = obj(add, "query");
            if (q != null) {
                String parent = str(q, "parent");
                String c = fromCollection(obj(q, "structuredQuery"));
                String[] dp = split(parent);
                if (c != null && dp != null) return new String[]{dp[0], join(dp[1], c)};
            }
            JsonArray names = arr(obj(add, "documents"), "documents");
            if (names != null && !names.isEmpty()) {
                String[] dp = split(prim(names.get(0)));
                if (dp != null) return new String[]{dp[0], collectionOf(dp[1])};
            }
            JsonArray writes = arr(o, "writes");
            if (writes != null && !writes.isEmpty()) {
                String[] dp = split(str(obj(writes.get(0), "update"), "name"));
                if (dp != null) return new String[]{dp[0], collectionOf(dp[1])};
            }
            return null;
        }

        /** "projects/p/databases/d/documents/a/b" → [projects/p/databases/d, a/b]. */
        private static String[] split(String name) {
            if (name == null) return null;
            int i = name.indexOf("/documents");
            if (i <= 0 || !name.startsWith("projects/")) return null;
            String rest = name.substring(i + "/documents".length());
            return new String[]{name.substring(0, i), rest.startsWith("/") ? rest.substring(1) : rest};
        }

        private static String fromCollection(JsonObject sq) {
            JsonArray from = arr(sq, "from");
            if (from == null || from.isEmpty()) return null;
            if ("true".equals(str(from.get(0), "allDescendants"))) return null; // collection group: no single REST list path
            String c = str(from.get(0), "collectionId");
            return c == null || c.isEmpty() || c.contains("/") ? null : c;
        }

        private static String join(String parent, String c) {
            return parent == null || parent.isEmpty() ? c : parent.replaceAll("/+$", "") + "/" + c;
        }

        /** Document path → its collection; a collection path (odd number of segments) is returned as is. */
        static String collectionOf(String rest) {
            String r = rest.replaceAll("^/+|/+$", "");
            if (r.isEmpty()) return "";
            String[] segs = r.split("/");
            if (segs.length % 2 == 1) return r;
            return r.substring(0, r.lastIndexOf('/'));
        }
    }
}
