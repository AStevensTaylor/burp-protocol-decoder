package protocoldecoder.builtin.firebase;

import com.google.gson.JsonElement;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.scan.ActiveCheck;
import protocoldecoder.scan.Confidence;
import protocoldecoder.scan.Exchange;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.HttpSender;
import protocoldecoder.scan.InsertionPoint;
import protocoldecoder.scan.Severity;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static protocoldecoder.builtin.firebase.FirebaseDecoderTest.DB;
import static protocoldecoder.builtin.firebase.FirebaseDecoderTest.ID_TOKEN;
import static protocoldecoder.builtin.firebase.FirebaseDecoderTest.LISTEN;
import static protocoldecoder.builtin.firebase.FirebaseDecoderTest.WRITE;
import static protocoldecoder.builtin.firebase.FirebaseDecoderTest.b64url;
import static protocoldecoder.builtin.firebase.FirebaseDecoderTest.enc;
import static protocoldecoder.builtin.firebase.FirebaseDecoderTest.response;
import static protocoldecoder.builtin.firebase.FirebaseDecoderTest.ws;

class FirebaseScannerTest {

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });

    @AfterEach
    void close() {
        app.close();
    }

    static final String DOC_URL = "https://firestore.googleapis.com/v1/" + DB + "/documents/users/uid42";
    static final String DOC = "{\"name\":\"" + DB + "/documents/users/uid42\",\"fields\":{\"nick\":{\"stringValue\":\"al\"}},"
            + "\"createTime\":\"2024-01-01T00:00:00Z\",\"updateTime\":\"2024-01-01T00:00:00Z\"}";
    static final String DENIED = "{\"error\":{\"code\":403,\"message\":\"Missing or insufficient permissions.\",\"status\":\"PERMISSION_DENIED\"}}";

    static String jwt(String claims) {
        return b64url("{\"alg\":\"RS256\",\"kid\":\"k\",\"typ\":\"JWT\"}") + "." + b64url(claims) + "." + b64url("sig-bytes");
    }

    List<Finding> passive(MessageContext m, String checkId) {
        return app.scanEngine().passive(m, false).stream().filter(f -> f.checkId().equals(checkId)).toList();
    }

    static MessageContext restGet(String url, String auth, int status, String respBody) {
        MessageContext.Builder b = MessageContext.builder(MessageKind.REQUEST).method("GET").url(url).requestHeader("Accept", "*/*");
        if (auth != null) b.requestHeader("Authorization", "Bearer " + auth);
        if (respBody != null) b.statusCode(status).responseHeader("Content-Type", "application/json").responseBody(respBody);
        return b.build();
    }

    /** Fake sender answering every request with one canned response, recording what was sent. */
    static final class Fake implements HttpSender {
        final List<String> targets = new ArrayList<>();
        final List<List<Header>> headers = new ArrayList<>();
        final List<String> bodies = new ArrayList<>();
        final int status;
        final String body;

        Fake(int status, String body) {
            this.status = status;
            this.body = body;
        }

        @Override
        public Exchange send(String method, String pathAndQuery, List<Header> h, byte[] b) {
            targets.add(method + " " + pathAndQuery);
            headers.add(h);
            bodies.add(new String(b, StandardCharsets.UTF_8));
            MessageContext m = MessageContext.builder(MessageKind.REQUEST).method(method).url("https://probe.invalid" + pathAndQuery)
                    .requestHeaders(h).requestBody(b).statusCode(status).responseBody(body).build();
            return new Exchange(m, null);
        }

        @Override
        public Exchange send(InsertionPoint point, String payload) {
            throw new UnsupportedOperationException();
        }

        boolean sentAuth() {
            for (List<Header> l : headers) {
                for (Header h : l) if (h.name().equalsIgnoreCase("Authorization") || h.name().equalsIgnoreCase("Cookie")) return true;
            }
            return targets.stream().anyMatch(t -> t.contains("auth=") || t.contains("access_token="));
        }
    }

    List<Finding> active(ActiveCheck.Scope scope, MessageContext base, HttpSender http) {
        MessageContext resp = base.hasResponse() ? base.withKind(MessageKind.RESPONSE) : null;
        return app.scanEngine().active(scope, base, resp, null, null, null, http);
    }

    // ================================================================ passive

    @Test
    void webConfigOncePerHost() {
        String html = "<script>const firebaseConfig = {apiKey: \"AIzaSyFAKEKEY123\", authDomain: \"acme-prod.firebaseapp.com\","
                + " databaseURL: \"https://acme-prod-default-rtdb.firebaseio.com\", projectId: \"acme-prod\", appId: \"1:1:web:a\"};"
                + " initializeApp(firebaseConfig);</script>";
        List<Finding> f = passive(response("GET", "https://www.acme.example/", html, "Content-Type", "text/html"), "firebase.web-config");
        assertEquals(1, f.size());
        assertEquals(Finding.Scope.HOST, f.get(0).scope());
        assertEquals(Severity.INFORMATION, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("acme-prod-default-rtdb.firebaseio.com/.json"), f.get(0).detail());
        assertTrue(f.get(0).detail().contains("public by design"));
        // negative: ordinary page
        assertTrue(passive(response("GET", "https://www.acme.example/", "<html>apiKey docs</html>", "Content-Type", "text/html"),
                "firebase.web-config").isEmpty());
    }

    @Test
    void customClaimsInIdToken() {
        String admin = jwt("{\"iss\":\"https://securetoken.google.com/acme-prod\",\"aud\":\"acme-prod\",\"user_id\":\"u1\",\"sub\":\"u1\","
                + "\"iat\":1700000000,\"exp\":1700003600,\"admin\":true,\"role\":\"support\",\"firebase\":{\"sign_in_provider\":\"password\"}}");
        List<Finding> f = passive(restGet(DOC_URL, admin, 0, null), "firebase.token-custom-claims");
        assertEquals(1, f.size(), f.toString());
        assertTrue(f.get(0).detail().contains("<code>admin</code>"), f.get(0).detail());
        assertTrue(f.get(0).detail().contains("<code>role</code> = <code>&quot;support&quot;</code>"), f.get(0).detail());
        assertEquals(Finding.Scope.HOST, f.get(0).scope());
        // standard Firebase token: no custom claims, normal lifetime
        assertTrue(passive(restGet(DOC_URL, ID_TOKEN, 0, null), "firebase.token-custom-claims").isEmpty());
        assertTrue(passive(restGet(DOC_URL, ID_TOKEN, 0, null), "firebase.token-lifetime").isEmpty());
    }

    @Test
    void longLivedTokenOverRtdbWebSocket() {
        String longTok = jwt("{\"iss\":\"https://auth.acme.example\",\"sub\":\"u1\",\"iat\":1700000000,\"exp\":1702592000}");
        MessageContext m = ws(FirebaseDecoderTest.RTDB_WS, "CLIENT_TO_SERVER", "{\"t\":\"d\",\"d\":{\"r\":1,\"a\":\"auth\",\"b\":{\"cred\":\"" + longTok + "\"}}}");
        List<Finding> f = passive(m, "firebase.token-lifetime");
        assertEquals(1, f.size(), f.toString());
        assertEquals(Severity.LOW, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("720 hours"), f.get(0).detail());
        // App Check tokens are not user auth
        String appCheck = jwt("{\"iss\":\"https://firebaseappcheck.googleapis.com/123\",\"sub\":\"1:1:web:a\",\"iat\":1700000000,\"exp\":1702592000}");
        MessageContext ac = MessageContext.builder(MessageKind.REQUEST).method("GET").url(DOC_URL).requestHeader("X-Firebase-AppCheck", appCheck).build();
        assertTrue(passive(ac, "firebase.token-lifetime").isEmpty());
    }

    @Test
    void sensitiveDataInFirestoreResponse() {
        String url = "https://firestore.googleapis.com/v1/" + DB + "/documents:runQuery";
        String resp = "[{\"document\":{\"name\":\"" + DB + "/documents/users/a\",\"fields\":{\"password\":{\"stringValue\":\"hunter22\"},"
                + "\"card\":{\"stringValue\":\"4111 1111 1111 1111\"}}}}]";
        List<Finding> f = passive(response("POST", url, resp), "firebase.sensitive-data");
        assertEquals(1, f.size(), f.toString());
        assertEquals(Confidence.TENTATIVE, f.get(0).confidence());
        assertTrue(f.get(0).detail().contains("hunter22"), f.get(0).detail());
        assertTrue(f.get(0).detail().contains("payment card number"), f.get(0).detail());
        // benign: a single (own) email address is not reported
        String benign = "[{\"document\":{\"name\":\"" + DB + "/documents/users/a\",\"fields\":{\"email\":{\"stringValue\":\"alice@example.com\"},"
                + "\"nick\":{\"stringValue\":\"al\"}}}}]";
        assertTrue(passive(response("POST", url, benign), "firebase.sensitive-data").isEmpty());
        // several users' emails are
        String many = "{\"u1\":{\"e\":\"a@example.com\"},\"u2\":{\"e\":\"b@example.com\"},\"u3\":{\"e\":\"c@example.com\"}}";
        assertEquals(1, passive(response("GET", "https://acme-default-rtdb.firebaseio.com/users.json", many), "firebase.sensitive-data").size());
    }

    @Test
    void permissionDeniedRevealsPath() {
        List<Finding> rtdb = passive(response("GET", "https://acme-default-rtdb.firebaseio.com/admin/config.json",
                "{\"error\" : \"Permission denied\"}"), "firebase.permission-denied");
        assertEquals(1, rtdb.size());
        assertTrue(rtdb.get(0).detail().contains("<code>/admin/config</code>"), rtdb.get(0).detail());
        List<Finding> fs = passive(response("GET", DOC_URL, DENIED), "firebase.permission-denied");
        assertEquals(1, fs.size());
        assertTrue(fs.get(0).title().contains("Firestore"));
        assertTrue(fs.get(0).detail().contains("/users/uid42"), fs.get(0).detail());
        MessageContext revoked = ws(FirebaseDecoderTest.RTDB_WS, "SERVER_TO_CLIENT",
                "{\"t\":\"d\",\"d\":{\"a\":\"c\",\"b\":{\"p\":\"private/u2\",\"msg\":\"permission_denied\"}}}");
        assertEquals(1, passive(revoked, "firebase.permission-denied").size());
        // negative: data returned
        assertTrue(passive(response("GET", DOC_URL, DOC), "firebase.permission-denied").isEmpty());
    }

    @Test
    void selfRegistrationAndAnonymousSignIn() {
        String url = "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=AIzaSyFAKEKEY123";
        String ok = "{\"kind\":\"identitytoolkit#SignupNewUserResponse\",\"idToken\":\"" + ID_TOKEN + "\",\"email\":\"eve@example.com\","
                + "\"refreshToken\":\"AMf\",\"expiresIn\":\"3600\",\"localId\":\"newUid\"}";
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("POST").url(url)
                .requestBody("{\"email\":\"eve@example.com\",\"password\":\"x\",\"returnSecureToken\":true}").statusCode(200).responseBody(ok).build();
        List<Finding> f = passive(m, "firebase.self-registration");
        assertEquals(1, f.size());
        assertEquals("Firebase Auth self-registration enabled", f.get(0).title());
        MessageContext anon = MessageContext.builder(MessageKind.RESPONSE).method("POST").url(url)
                .requestBody("{\"returnSecureToken\":true}").statusCode(200).responseBody("{\"idToken\":\"" + ID_TOKEN + "\",\"localId\":\"a1\"}").build();
        assertEquals("Firebase anonymous sign-in enabled", passive(anon, "firebase.self-registration").get(0).title());
        // negatives: sign-up disabled, and a sign-in
        MessageContext disabled = MessageContext.builder(MessageKind.RESPONSE).method("POST").url(url).requestBody("{}")
                .statusCode(400).responseBody("{\"error\":{\"code\":400,\"message\":\"ADMIN_ONLY_OPERATION\"}}").build();
        assertTrue(passive(disabled, "firebase.self-registration").isEmpty());
        MessageContext signIn = MessageContext.builder(MessageKind.RESPONSE).method("POST")
                .url("https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=k").requestBody("{}").statusCode(200).responseBody(ok).build();
        assertTrue(passive(signIn, "firebase.self-registration").isEmpty());
    }

    @Test
    void accountEnumeration() {
        String signIn = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=k";
        List<Finding> f = passive(response("POST", signIn, "{\"error\":{\"code\":400,\"message\":\"EMAIL_NOT_FOUND\",\"errors\":[]}}"),
                "firebase.account-enumeration");
        assertEquals(1, f.size());
        assertEquals(Severity.LOW, f.get(0).severity());
        assertEquals(Finding.Scope.HOST, f.get(0).scope());
        assertEquals(1, passive(response("POST", "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=k",
                "{\"kind\":\"identitytoolkit#CreateAuthUriResponse\",\"registered\":false,\"sessionId\":\"s\"}"), "firebase.account-enumeration").size());
        // with enumeration protection
        assertTrue(passive(response("POST", signIn, "{\"error\":{\"code\":400,\"message\":\"INVALID_LOGIN_CREDENTIALS\"}}"),
                "firebase.account-enumeration").isEmpty());
        assertTrue(passive(response("POST", "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=k",
                "{\"kind\":\"identitytoolkit#CreateAuthUriResponse\",\"sessionId\":\"s\"}"), "firebase.account-enumeration").isEmpty());
    }

    // ================================================================ insertion points

    @Test
    void webChannelDataInsertionPointsRoundTrip() throws Exception {
        String add = "{\"database\":\"" + DB + "\",\"addTarget\":{\"query\":{\"structuredQuery\":{\"from\":[{\"collectionId\":\"users\"}],"
                + "\"where\":{\"fieldFilter\":{\"field\":{\"fieldPath\":\"role\"},\"op\":\"EQUAL\",\"value\":{\"stringValue\":\"admin\"}}}},"
                + "\"parent\":\"" + DB + "/documents\"},\"targetId\":2}}";
        String remove = "{\"database\":\"" + DB + "\",\"removeTarget\":4}";
        String body = "count=2&ofs=7&req0___data__=" + enc(add) + "&req1___data__=" + enc(remove);
        MessageContext m = FirebaseDecoderTest.post(LISTEN + "?VER=8&database=" + enc(DB) + "&SID=s1&RID=5&AID=1&zx=z&t=1", body).build();
        List<InsertionPoint> ips = app.scanEngine().insertionPoints(m).stream().filter(i -> i.name().startsWith("Firestore:")).toList();
        assertEquals(List.of("Firestore: req0___data__ $.addTarget.query.structuredQuery.where.fieldFilter.value.stringValue"),
                ips.stream().map(InsertionPoint::name).toList());
        InsertionPoint ip = ips.get(0);
        assertEquals("admin", ip.baseValue());
        String payload = "x\"' OR \\\"1\\\"=\"1 & a=b%26+c\n ünïcödé 日本   ]}";
        String newBody = new String(ip.render().apply(payload), StandardCharsets.UTF_8);
        assertTrue(newBody.startsWith("count=2&ofs=7&req0___data__="), newBody);
        assertTrue(newBody.endsWith("&req1___data__=" + enc(remove)), newBody);
        var form = Codecs.parseQuery(newBody);
        JsonElement j = JsonTree.parseStrict(Codecs.first(form, "req0___data__"));
        assertEquals(payload, j.getAsJsonObject().getAsJsonObject("addTarget").getAsJsonObject("query").getAsJsonObject("structuredQuery")
                .getAsJsonObject("where").getAsJsonObject("fieldFilter").getAsJsonObject("value").get("stringValue").getAsString());
        // still decodes as a Listen message
        MessageContext mutated = FirebaseDecoderTest.post(m.url(), newBody).build();
        DecodeResult r = new FirebaseDecoder().decode(mutated);
        assertTrue(r.summary().startsWith("Firestore Listen: addTarget query on users where role == "), r.summary());
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
    }

    @Test
    void writeStreamDocumentFieldsAreInsertionPoints() {
        String w = "{\"streamToken\":\"EAEZ\",\"writes\":[{\"update\":{\"name\":\"" + DB + "/documents/posts/p1\",\"fields\":{"
                + "\"title\":{\"stringValue\":\"Hi\"},\"likes\":{\"integerValue\":\"3\"},\"pub\":{\"booleanValue\":true}}}}]}";
        MessageContext m = FirebaseDecoderTest.post(WRITE + "?VER=8&database=" + enc(DB) + "&SID=s&RID=9", "count=1&ofs=3&req0___data__=" + enc(w)).build();
        List<String> names = app.scanEngine().insertionPoints(m).stream().map(InsertionPoint::name).toList();
        assertTrue(names.contains("Firestore: req0___data__ $.writes[0].update.fields.title.stringValue"), names.toString());
        assertTrue(names.contains("Firestore: req0___data__ $.writes[0].update.fields.likes.integerValue"), names.toString());
        assertFalse(names.stream().anyMatch(n -> n.contains("streamToken") || n.contains(".name") || n.contains("booleanValue")), names.toString());
        // non-channel Firestore REST: Burp handles plain JSON itself
        MessageContext rest = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://firestore.googleapis.com/v1/" + DB + "/documents:runQuery")
                .requestBody("{\"structuredQuery\":{}}").build();
        assertTrue(app.scanEngine().insertionPoints(rest).isEmpty());
    }

    // ================================================================ active

    @Test
    void rtdbReadableWithoutAuth() {
        MessageContext base = restGet("https://acme-default-rtdb.firebaseio.com/users/u1.json?auth=" + ID_TOKEN, null, 200, "{\"name\":\"a\"}");
        Fake fake = new Fake(200, "{\"users\":true,\"secrets\":true}");
        List<Finding> f = active(ActiveCheck.Scope.PER_HOST, base, fake);
        assertEquals(List.of("GET /.json?shallow=true"), fake.targets);
        assertFalse(fake.sentAuth());
        assertEquals(1, f.size());
        assertEquals(Severity.MEDIUM, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("<code>secrets</code>"), f.get(0).detail());
        assertEquals(1, f.get(0).exchanges().size());
        // negative: rules deny
        Fake denied = new Fake(401, "{\"error\" : \"Permission denied\"}");
        assertTrue(active(ActiveCheck.Scope.PER_HOST, base, denied).isEmpty());
        assertEquals(1, denied.targets.size());
        // negative: empty database
        assertTrue(active(ActiveCheck.Scope.PER_HOST, base, new Fake(200, "null")).isEmpty());
    }

    @Test
    void rtdbProbeSkipsOtherHosts() {
        // the sender can only reach the base host: an RTDB URL seen in a page config on another host is not probed
        String html = "<script>firebaseConfig={apiKey:\"AIzaSyFAKEKEY123\",projectId:\"acme\",databaseURL:\"https://acme.firebaseio.com\"};initializeApp(firebaseConfig)</script>";
        MessageContext page = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://www.acme.example/")
                .statusCode(200).responseHeader("Content-Type", "text/html").responseBody(html).build();
        Fake fake = new Fake(200, "{\"users\":true}");
        assertTrue(active(ActiveCheck.Scope.PER_HOST, page, fake).isEmpty());
        assertTrue(fake.targets.isEmpty());
        MessageContext fs = restGet(DOC_URL, ID_TOKEN, 200, DOC);
        assertTrue(active(ActiveCheck.Scope.PER_HOST, fs, fake).isEmpty());
        assertTrue(fake.targets.isEmpty());
    }

    @Test
    void firestoreDocumentReadableWithoutAuth() {
        MessageContext base = restGet(DOC_URL + "?key=AIzaSyFAKEKEY123&access_token=ya29.x", ID_TOKEN, 200, DOC);
        Fake fake = new Fake(200, DOC);
        List<Finding> f = active(ActiveCheck.Scope.PER_REQUEST, base, fake).stream()
                .filter(x -> x.checkId().equals("firebase.firestore-unauth-read")).toList();
        assertEquals(1, f.size());
        assertEquals(Severity.HIGH, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("users/uid42"), f.get(0).detail());
        assertTrue(fake.targets.contains("GET /v1/" + DB + "/documents/users/uid42?key=AIzaSyFAKEKEY123"), fake.targets.toString());
        assertFalse(fake.sentAuth());
    }

    @Test
    void firestoreDeniedWithoutAuthIsInformation() {
        String url = "https://firestore.googleapis.com/v1/" + DB + "/documents:runQuery";
        String q = "{\"structuredQuery\":{\"from\":[{\"collectionId\":\"orders\"}],\"limit\":5}}";
        String docs = "[{\"document\":{\"name\":\"" + DB + "/documents/orders/o1\",\"fields\":{}},\"readTime\":\"2024-01-01T00:00:00Z\"}]";
        MessageContext base = MessageContext.builder(MessageKind.REQUEST).method("POST").url(url).requestHeader("Authorization", "Bearer " + ID_TOKEN)
                .requestHeader("Content-Type", "application/json").requestBody(q).statusCode(200).responseBody(docs).build();
        Fake fake = new Fake(403, DENIED);
        List<Finding> f = active(ActiveCheck.Scope.PER_REQUEST, base, fake);
        Finding read = f.stream().filter(x -> x.checkId().equals("firebase.firestore-unauth-read")).findFirst().orElseThrow();
        assertEquals(Severity.INFORMATION, read.severity());
        assertTrue(fake.bodies.contains(q), "query resent unchanged");
        assertTrue(fake.targets.contains("POST /v1/" + DB + "/documents:runQuery"), fake.targets.toString());
        // list probe derived from the runQuery collection, denied → no finding
        assertTrue(fake.targets.contains("GET /v1/" + DB + "/documents/orders?pageSize=1"), fake.targets.toString());
        assertTrue(f.stream().noneMatch(x -> x.checkId().equals("firebase.firestore-unauth-list")));
        assertFalse(fake.sentAuth());
        assertEquals(2, fake.targets.size());
    }

    @Test
    void firestoreReadProbeSkipsUnauthenticatedAndWrites() {
        Fake fake = new Fake(200, DOC);
        app.scanEngine().setEnabled("firebase.firestore-unauth-list", false);
        // already unauthenticated
        assertTrue(active(ActiveCheck.Scope.PER_REQUEST, restGet(DOC_URL, null, 200, DOC), fake).isEmpty());
        // write
        MessageContext patch = MessageContext.builder(MessageKind.REQUEST).method("PATCH").url(DOC_URL).requestHeader("Authorization", "Bearer " + ID_TOKEN)
                .requestBody(DOC).statusCode(200).responseBody(DOC).build();
        assertTrue(active(ActiveCheck.Scope.PER_REQUEST, patch, fake).isEmpty());
        // commit RPC
        MessageContext commit = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://firestore.googleapis.com/v1/" + DB + "/documents:commit")
                .requestHeader("Authorization", "Bearer " + ID_TOKEN).requestBody("{\"writes\":[]}").statusCode(200).responseBody(DOC).build();
        assertTrue(active(ActiveCheck.Scope.PER_REQUEST, commit, fake).isEmpty());
        // different documents back (e.g. a public placeholder) → not the same data
        Fake other = new Fake(200, DOC.replace("uid42", "public"));
        assertTrue(active(ActiveCheck.Scope.PER_REQUEST, restGet(DOC_URL, ID_TOKEN, 200, DOC), other).isEmpty());
        assertTrue(fake.targets.isEmpty(), fake.targets.toString());
    }

    @Test
    void firestoreCollectionListableFromWebChannelTarget() {
        String add = "{\"database\":\"" + DB + "\",\"addTarget\":{\"documents\":{\"documents\":[\"" + DB + "/documents/teams/t 1/members/m1\"]},\"targetId\":6}}";
        MessageContext m = FirebaseDecoderTest.post(LISTEN + "?VER=8&database=" + enc(DB) + "&SID=s&RID=3", "count=1&ofs=0&req0___data__=" + enc(add))
                .requestHeader("Authorization", "Bearer " + ID_TOKEN).build();
        String listing = "{\"documents\":[{\"name\":\"" + DB + "/documents/teams/t 1/members/m1\",\"fields\":{}}],\"nextPageToken\":\"abc\"}";
        Fake fake = new Fake(200, listing);
        List<Finding> f = active(ActiveCheck.Scope.PER_REQUEST, m, fake);
        assertEquals(List.of("GET /v1/" + DB + "/documents/teams/t%201/members?pageSize=1"), fake.targets);
        assertFalse(fake.sentAuth());
        assertEquals(1, f.size());
        assertEquals("firebase.firestore-unauth-list", f.get(0).checkId());
        assertEquals(Severity.MEDIUM, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("more pages"), f.get(0).detail());
        // each collection is probed once
        assertTrue(active(ActiveCheck.Scope.PER_REQUEST, m, fake).isEmpty());
        assertEquals(1, fake.targets.size());
        // negative: empty listing
        MessageContext other = restGet("https://firestore.googleapis.com/v1/" + DB + "/documents/invoices/i9", ID_TOKEN, 200, null);
        Fake empty = new Fake(200, "{}");
        assertTrue(active(ActiveCheck.Scope.PER_REQUEST, other, empty).isEmpty());
        assertEquals(List.of("GET /v1/" + DB + "/documents/invoices?pageSize=1"), empty.targets);
    }

    @Test
    void collectionDerivation() {
        assertEquals("users", FirebaseScanner.FirestoreUnauthList.collectionOf("users/u1"));
        assertEquals("users/u1/posts", FirebaseScanner.FirestoreUnauthList.collectionOf("users/u1/posts"));
        assertEquals("", FirebaseScanner.FirestoreUnauthList.collectionOf(""));
        assertEquals("a=1&key=k", FirebaseScanner.stripAuthParams("a=1&auth=tok&access_token=x&key=k"));
    }
}
