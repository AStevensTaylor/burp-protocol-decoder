package protocoldecoder.builtin.firebase;

import org.junit.jupiter.api.Test;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.util.TreeText;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class FirebaseDecoderTest {

    final FirebaseDecoder fb = new FirebaseDecoder();

    static final String DB = "projects/acme-prod/databases/(default)";
    static final String LISTEN = "https://firestore.googleapis.com/google.firestore.v1.Firestore/Listen/channel";
    static final String WRITE = "https://firestore.googleapis.com/google.firestore.v1.Firestore/Write/channel";

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    static String b64url(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    static final String ID_TOKEN = b64url("{\"alg\":\"RS256\",\"kid\":\"abc123\",\"typ\":\"JWT\"}") + "."
            + b64url("{\"iss\":\"https://securetoken.google.com/acme-prod\",\"aud\":\"acme-prod\",\"auth_time\":1700000000,"
            + "\"user_id\":\"uid42\",\"sub\":\"uid42\",\"iat\":1700000000,\"exp\":1700003600,\"email\":\"alice@example.com\","
            + "\"firebase\":{\"identities\":{\"email\":[\"alice@example.com\"]},\"sign_in_provider\":\"password\"}}")
            + "." + b64url("signature-bytes-here");

    /** WebChannel chunk: length (in chars) + newline + JSON. */
    static String chunk(String json) {
        return json.length() + "\n" + json;
    }

    static String find(DecodedNode n, String nameContains) {
        if (n.name().contains(nameContains) && n.value() != null) return n.value();
        for (DecodedNode c : n.children()) {
            String v = find(c, nameContains);
            if (v != null) return v;
        }
        return null;
    }

    static DecodedNode findNode(DecodedNode n, String nameContains) {
        if (n.name().contains(nameContains)) return n;
        for (DecodedNode c : n.children()) {
            DecodedNode v = findNode(c, nameContains);
            if (v != null) return v;
        }
        return null;
    }

    static MessageContext.Builder post(String url, String body) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url(url)
                .requestHeader("Content-Type", "application/x-www-form-urlencoded").requestBody(body);
    }

    static MessageContext response(String method, String url, String body, String... headers) {
        MessageContext.Builder b = MessageContext.builder(MessageKind.RESPONSE).method(method).url(url).statusCode(200);
        for (int i = 0; i + 1 < headers.length; i += 2) b.responseHeader(headers[i], headers[i + 1]);
        return b.responseBody(body).build();
    }

    static MessageContext ws(String url, String direction, String frame) {
        return MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url(url)
                .webSocket(direction, frame.getBytes(StandardCharsets.UTF_8)).build();
    }

    // ------------------------------------------------------------ Firestore WebChannel

    @Test
    void listenAddTargetWithStructuredQuery() throws Exception {
        String add = "{\"database\":\"" + DB + "\",\"addTarget\":{\"query\":{\"structuredQuery\":{\"from\":[{\"collectionId\":\"users\"}],"
                + "\"where\":{\"fieldFilter\":{\"field\":{\"fieldPath\":\"role\"},\"op\":\"EQUAL\",\"value\":{\"stringValue\":\"admin\"}}},"
                + "\"orderBy\":[{\"field\":{\"fieldPath\":\"__name__\"},\"direction\":\"ASCENDING\"}]},"
                + "\"parent\":\"" + DB + "/documents\"},\"targetId\":2}}";
        String headers = "X-Goog-Api-Client:gl-js/ fire/10.7.0\r\nContent-Type:text/plain\r\nX-Firebase-GMPID:1:123:web:abc\r\nAuthorization:Bearer " + ID_TOKEN + "\r\n";
        String url = LISTEN + "?VER=8&database=" + enc(DB) + "&RID=12345&CVER=22&X-HTTP-Session-Id=gsessionid&%24httpHeaders="
                + enc(headers) + "&zx=abc123&t=1";
        MessageContext m = post(url, "count=1&ofs=0&req0___data__=" + enc(add)).build();
        assertEquals(95, fb.match(m).confidence());
        DecodeResult r = fb.decode(m);
        assertEquals("Firestore Listen: addTarget query on users where role == admin", r.summary());
        assertEquals("admin  (string)", find(r.root(), "value"));
        assertEquals("8", find(r.root(), "VER"));
        DecodedNode auth = findNode(r.root(), "Authorization (JWT)");
        assertNotNull(auth, TreeText.render(r.root()));
        assertTrue(auth.value().contains("uid uid42 (alice@example.com)"), auth.value());
        assertTrue(find(auth, "exp").contains("2023-11-14T23:13:20Z"));
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
    }

    @Test
    void listenCompositeFilterDocumentsAndRemoveTarget() throws Exception {
        String q = "{\"database\":\"" + DB + "\",\"addTarget\":{\"query\":{\"structuredQuery\":{\"from\":[{\"collectionId\":\"orders\",\"allDescendants\":true}],"
                + "\"where\":{\"compositeFilter\":{\"op\":\"AND\",\"filters\":[{\"fieldFilter\":{\"field\":{\"fieldPath\":\"total\"},\"op\":\"GREATER_THAN\",\"value\":{\"integerValue\":\"100\"}}},"
                + "{\"unaryFilter\":{\"field\":{\"fieldPath\":\"deletedAt\"},\"op\":\"IS_NULL\"}}]}},"
                + "\"orderBy\":[{\"field\":{\"fieldPath\":\"total\"},\"direction\":\"DESCENDING\"}],\"limit\":{\"value\":10}},\"parent\":\"" + DB + "/documents\"},"
                + "\"targetId\":4,\"resumeToken\":\"CgkI2Nf1\"}}";
        String docs = "{\"database\":\"" + DB + "\",\"addTarget\":{\"documents\":{\"documents\":[\"" + DB + "/documents/users/uid42\"]},\"targetId\":6}}";
        String remove = "{\"database\":\"" + DB + "\",\"removeTarget\":2}";
        MessageContext m = post(LISTEN + "?VER=8&database=" + enc(DB) + "&gsessionid=gs1&SID=sid1&RID=12346&AID=3&zx=x&t=1",
                "count=3&ofs=1&req0___data__=" + enc(q) + "&req1___data__=" + enc(docs) + "&req2___data__=" + enc(remove)).build();
        DecodeResult r = fb.decode(m);
        assertEquals("Firestore Listen: addTarget query on collection group orders where total > 100 AND deletedAt == null"
                + " order by total desc limit 10 [resume]; addTarget document users/uid42; removeTarget 2", r.summary());
        assertEquals("100  (integer)", find(r.root(), "value"));
    }

    @Test
    void writeRequestWithUpdateDeleteTransform() throws Exception {
        String w = "{\"streamToken\":\"EAEZ\",\"writes\":[{\"update\":{\"name\":\"" + DB + "/documents/users/uid42\",\"fields\":{"
                + "\"name\":{\"stringValue\":\"Alice\"},\"age\":{\"integerValue\":\"31\"},\"score\":{\"doubleValue\":9.5},\"admin\":{\"booleanValue\":true},"
                + "\"tags\":{\"arrayValue\":{\"values\":[{\"stringValue\":\"a\"},{\"stringValue\":\"b\"}]}},"
                + "\"address\":{\"mapValue\":{\"fields\":{\"city\":{\"stringValue\":\"Paris\"}}}},"
                + "\"loc\":{\"geoPointValue\":{\"latitude\":48.85,\"longitude\":2.35}},\"avatar\":{\"bytesValue\":\"aGVsbG8=\"},"
                + "\"manager\":{\"referenceValue\":\"" + DB + "/documents/users/uid1\"},\"gone\":{\"nullValue\":null}}},"
                + "\"updateMask\":{\"fieldPaths\":[\"name\",\"age\"]},\"currentDocument\":{\"exists\":true}},"
                + "{\"delete\":\"" + DB + "/documents/sessions/s1\"},"
                + "{\"transform\":{\"document\":\"" + DB + "/documents/users/uid42\",\"fieldTransforms\":[{\"fieldPath\":\"updated\",\"setToServerValue\":\"REQUEST_TIME\"}]}}]}";
        MessageContext m = post(WRITE + "?VER=8&database=" + enc(DB) + "&SID=s&RID=5&AID=1&zx=z&t=1",
                "count=1&ofs=4&req0___data__=" + enc(w)).build();
        assertEquals(95, fb.match(m).confidence());
        DecodeResult r = fb.decode(m);
        assertEquals("Firestore Write: 3 writes: update users/uid42 (mask 2 fields), delete sessions/s1, transform users/uid42", r.summary());
        String text = TreeText.render(r.root());
        assertEquals("Alice  (string)", findExact(r.root(), "fields").get("name").value());
        assertEquals("31  (integer)", find(r.root(), "age"));
        assertEquals("true  (boolean)", find(r.root(), "admin"));
        assertEquals("48.85, 2.35  (geoPoint)", find(r.root(), "loc"));
        assertTrue(find(r.root(), "avatar").contains("\"hello\""), text);
        assertEquals("Paris  (string)", find(findNode(r.root(), "address (map)"), "city"));
        assertEquals(2, findNode(r.root(), "tags (array)").children().size());
        assertEquals("null  (null)", find(r.root(), "gone"));
        assertTrue(find(r.root(), "manager").endsWith("(reference)"));
    }

    @Test
    void writeHandshake() throws Exception {
        MessageContext m = post(WRITE + "?VER=8&database=" + enc(DB) + "&RID=1&zx=z&t=1",
                "count=1&ofs=0&req0___data__=" + enc("{\"database\":\"" + DB + "\"}")).build();
        assertEquals("Firestore Write: handshake (" + DB + ")", fb.decode(m).summary());
    }

    @Test
    void chunkedListenResponseWithDocumentChanges() throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append(chunk("[[0,[\"c\",\"SID_abc\",\"\",8,12,30000]]]\n"));
        sb.append(chunk("[[1,[{\n  \"targetChange\": {\n    \"targetChangeType\": \"ADD\",\n    \"targetIds\": [\n      2\n    ]\n  }\n}\n]]]"));
        StringBuilder docs = new StringBuilder("[");
        for (int i = 0; i < 3; i++) {
            if (i > 0) docs.append(',');
            docs.append("[").append(2 + i).append(",[{\"documentChange\":{\"document\":{\"name\":\"").append(DB).append("/documents/users/u").append(i)
                    .append("\",\"fields\":{\"role\":{\"stringValue\":\"admin\"},\"created\":{\"timestampValue\":\"2024-05-01T10:00:00.123Z\"},")
                    .append("\"n\":{\"integerValue\":\"").append(i).append("\"},\"name\":{\"stringValue\":\"Zoë ").append(i).append("\"}},")
                    .append("\"createTime\":\"2024-05-01T10:00:00Z\",\"updateTime\":\"2024-05-02T10:00:00Z\"},\"targetIds\":[2]}}]]");
        }
        docs.append("]");
        sb.append(chunk(docs.toString()));
        sb.append(chunk("[[5,[\"noop\"]]]"));
        MessageContext m = response("GET", LISTEN + "?VER=8&database=" + enc(DB) + "&RID=rpc&SID=SID_abc&AID=0&CI=0&TYPE=xmlhttp&zx=z&t=1", sb.toString());
        assertEquals(95, fb.match(m).confidence());
        DecodeResult r = fb.decode(m);
        assertEquals("Firestore Listen response: 1 session created, 1 targetChange, 3 documentChange, 1 noop ("
                + DB + "/documents/users/…)", r.summary());
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
        assertEquals("2024-05-01T10:00:00.123Z  (timestamp)", find(r.root(), "created"));
        assertEquals("SID_abc", find(r.root(), "session id"));
        assertNotNull(findNode(r.root(), "#1 targetChange (ADD)"));
        assertEquals("Zoë 2  (string)", findName(findNode(r.root(), "#4 documentChange")));
    }

    static DecodedNode findExact(DecodedNode n, String name) {
        if (n.name().equals(name)) return n;
        for (DecodedNode c : n.children()) {
            DecodedNode v = findExact(c, name);
            if (v != null) return v;
        }
        return null;
    }

    private static String findName(DecodedNode n) {
        DecodedNode f = findExact(n, "fields");
        return f == null ? null : f.get("name").value();
    }

    @Test
    void chunkedResponseToleratesWrongLengthsAndGarbage() throws Exception {
        String c1 = "[[1,[{\"documentDelete\":{\"document\":\"" + DB + "/documents/users/u9\",\"removedTargetIds\":[2]}}]]]";
        String c2 = "[[2,[{\"filter\":{\"targetId\":2,\"count\":5}}]]]";
        String body = (c1.length() + 7) + "\n" + c1 + "\nGARBAGE!!\n" + c2.length() + "\n" + c2;
        DecodeResult r = fb.decode(response("GET", LISTEN + "?TYPE=xmlhttp", body));
        assertTrue(r.summary().startsWith("Firestore Listen response: 1 documentDelete, 1 filter"), r.summary());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("declared length")), r.warnings().toString());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("resynchronised")), r.warnings().toString());
    }

    @Test
    void writeResponseAndErrorStatus() throws Exception {
        String wr = "[[3,[{\"streamId\":\"s1\",\"streamToken\":\"EAIZ\",\"writeResults\":[{\"updateTime\":\"2024-05-01T10:00:00Z\"}],\"commitTime\":\"2024-05-01T10:00:00Z\"}]]]";
        DecodeResult r = fb.decode(response("POST", WRITE + "?SID=s", chunk(wr)));
        assertEquals("Firestore Write response: 1 writeResponse (1 results)", r.summary());
        String err = "[[4,[{\"error\":{\"code\":7,\"message\":\"Missing or insufficient permissions.\",\"status\":\"PERMISSION_DENIED\"}}]]]";
        DecodeResult e = fb.decode(response("GET", LISTEN + "?TYPE=xmlhttp", chunk(err)));
        assertTrue(e.summary().contains("error 7 PERMISSION_DENIED: Missing or insufficient permissions."), e.summary());
    }

    @Test
    void gzipChunkedResponse() throws Exception {
        String c = chunk("[[0,[\"noop\"]]]");
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream g = new GZIPOutputStream(bos)) { g.write(c.getBytes(StandardCharsets.UTF_8)); }
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("GET").url(LISTEN + "?TYPE=xmlhttp").statusCode(200)
                .responseHeader("Content-Encoding", "gzip").responseBody(bos.toByteArray()).build();
        assertEquals("Firestore Listen response: 1 noop", fb.decode(m).summary());
    }

    @Test
    void backchannelPollAndTerminate() throws Exception {
        MessageContext poll = MessageContext.builder(MessageKind.REQUEST).method("GET")
                .url(LISTEN + "?VER=8&database=" + enc(DB) + "&RID=rpc&SID=abc&AID=0&CI=0&TYPE=xmlhttp&zx=z&t=1").build();
        assertEquals("Firestore Listen: backchannel poll (SID abc)", fb.decode(poll).summary());
        MessageContext term = MessageContext.builder(MessageKind.REQUEST).method("GET")
                .url(LISTEN + "?VER=8&database=" + enc(DB) + "&SID=abc&RID=9&TYPE=terminate&zx=z&t=1").build();
        assertEquals("Firestore Listen: terminate session (SID abc)", fb.decode(term).summary());
    }

    // ------------------------------------------------------------ Firestore REST

    @Test
    void firestoreRestRunQueryAndResponse() throws Exception {
        String url = "https://firestore.googleapis.com/v1/" + DB + "/documents:runQuery?key=AIzaSyFAKEKEY123";
        String body = "{\"structuredQuery\":{\"from\":[{\"collectionId\":\"users\"}],\"where\":{\"fieldFilter\":{\"field\":{\"fieldPath\":\"tier\"},"
                + "\"op\":\"IN\",\"value\":{\"arrayValue\":{\"values\":[{\"stringValue\":\"gold\"},{\"stringValue\":\"plat\"}]}}}},\"limit\":5}}";
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url(url)
                .requestHeader("Content-Type", "application/json").requestHeader("Authorization", "Bearer " + ID_TOKEN).requestBody(body).build();
        assertEquals(90, fb.match(m).confidence());
        DecodeResult r = fb.decode(m);
        assertEquals("Firestore REST runQuery: query on users where tier in [gold, plat] limit 5", r.summary());
        assertNotNull(findNode(r.root(), "Authorization (JWT)"));
        assertTrue(TreeText.render(r.root()).contains("public by design"));

        String resp = "[{\"document\":{\"name\":\"" + DB + "/documents/users/a\",\"fields\":{\"tier\":{\"stringValue\":\"gold\"}}},\"readTime\":\"2024-01-01T00:00:00Z\"},"
                + "{\"document\":{\"name\":\"" + DB + "/documents/users/b\",\"fields\":{\"tier\":{\"stringValue\":\"plat\"}}},\"readTime\":\"2024-01-01T00:00:00Z\"}]";
        DecodeResult rr = fb.decode(response("POST", url, resp));
        assertEquals("Firestore REST runQuery response: 2 documents (" + DB + "/documents/users/…)", rr.summary());
        assertEquals("gold  (string)", find(rr.root(), "tier"));
    }

    @Test
    void firestoreRestGetDocument() throws Exception {
        String url = "https://firestore.googleapis.com/v1/" + DB + "/documents/users/uid42";
        MessageContext req = MessageContext.builder(MessageKind.REQUEST).method("GET").url(url).build();
        assertEquals("Firestore REST get users/uid42", fb.decode(req).summary());
        String doc = "{\"name\":\"" + DB + "/documents/users/uid42\",\"fields\":{\"email\":{\"stringValue\":\"a@b.c\"},\"n\":{\"integerValue\":\"1\"}},"
                + "\"createTime\":\"2024-01-01T00:00:00Z\",\"updateTime\":\"2024-01-01T00:00:00Z\"}";
        assertEquals("Firestore REST response: document users/uid42 (2 fields)", fb.decode(response("GET", url, doc)).summary());
        String err = "{\"error\":{\"code\":403,\"message\":\"Missing or insufficient permissions.\",\"status\":\"PERMISSION_DENIED\"}}";
        assertEquals("Firestore REST response: error 403 PERMISSION_DENIED: Missing or insufficient permissions.",
                fb.decode(response("GET", url, err)).summary());
    }

    // ------------------------------------------------------------ Realtime Database

    static final String RTDB_WS = "wss://acme-default-rtdb.firebaseio.com/.ws?v=5&ns=acme-default-rtdb";

    @Test
    void rtdbWebSocketDataFrames() throws Exception {
        MessageContext listen = ws(RTDB_WS, "CLIENT_TO_SERVER",
                "{\"t\":\"d\",\"d\":{\"r\":3,\"a\":\"q\",\"b\":{\"p\":\"/users\",\"q\":{\"i\":\"role\",\"sp\":\"admin\",\"ep\":\"admin\",\"l\":10,\"vf\":\"l\"},\"t\":1,\"h\":\"\"}}}");
        assertEquals(95, fb.match(listen).confidence());
        assertEquals("Firebase RTDB listen /users [orderBy role, equalTo \"admin\", limitToFirst 10] (r=3)", fb.decode(listen).summary());

        MessageContext put = ws(RTDB_WS, "CLIENT_TO_SERVER", "{\"t\":\"d\",\"d\":{\"r\":4,\"a\":\"p\",\"b\":{\"p\":\"/users/u1/role\",\"d\":\"admin\"}}}");
        assertEquals("Firebase RTDB put /users/u1/role (r=4)", fb.decode(put).summary());

        MessageContext auth = ws(RTDB_WS, "CLIENT_TO_SERVER", "{\"t\":\"d\",\"d\":{\"r\":1,\"a\":\"auth\",\"b\":{\"cred\":\"" + ID_TOKEN + "\"}}}");
        DecodeResult ar = fb.decode(auth);
        assertTrue(ar.summary().startsWith("Firebase RTDB auth (ID token): uid uid42 (alice@example.com), provider password"), ar.summary());
        assertNotNull(findNode(ar.root(), "credential (JWT)"));

        MessageContext resp = ws(RTDB_WS, "SERVER_TO_CLIENT", "{\"t\":\"d\",\"d\":{\"r\":4,\"b\":{\"s\":\"permission_denied\",\"d\":\"Permission denied\"}}}");
        assertEquals("Firebase RTDB response r=4: permission_denied (Permission denied)", fb.decode(resp).summary());

        MessageContext push = ws(RTDB_WS, "SERVER_TO_CLIENT", "{\"t\":\"d\",\"d\":{\"a\":\"d\",\"b\":{\"p\":\"users\",\"d\":{\"u1\":{\"role\":\"admin\"}},\"t\":1}}}");
        DecodeResult pr = fb.decode(push);
        assertEquals("Firebase RTDB data update /users", pr.summary());
        assertEquals("admin", find(pr.root(), "role"));

        MessageContext od = ws(RTDB_WS, "CLIENT_TO_SERVER", "{\"t\":\"d\",\"d\":{\"r\":7,\"a\":\"o\",\"b\":{\"p\":\"/presence/u1\",\"d\":false}}}");
        assertEquals("Firebase RTDB onDisconnect put /presence/u1 (r=7)", fb.decode(od).summary());
    }

    @Test
    void rtdbWebSocketControlFramesAndFragments() throws Exception {
        MessageContext hs = ws(RTDB_WS, "SERVER_TO_CLIENT",
                "{\"t\":\"c\",\"d\":{\"t\":\"h\",\"d\":{\"ts\":1700000000000,\"v\":\"5\",\"h\":\"s-usc1b-nss-2100.firebaseio.com\",\"s\":\"sessXYZ\"}}}");
        assertEquals("Firebase RTDB control: handshake (host s-usc1b-nss-2100.firebaseio.com, session sessXYZ)", fb.decode(hs).summary());
        MessageContext reset = ws(RTDB_WS, "SERVER_TO_CLIENT", "{\"t\":\"c\",\"d\":{\"t\":\"r\",\"d\":\"s-usc1a-nss-2.firebaseio.com\"}}");
        assertEquals("Firebase RTDB control: reset (reconnect to host): s-usc1a-nss-2.firebaseio.com", fb.decode(reset).summary());

        assertEquals("Firebase RTDB: multi-frame message header (3 frames follow)", fb.decode(ws(RTDB_WS, "SERVER_TO_CLIENT", "3")).summary());
        DecodeResult frag = fb.decode(ws(RTDB_WS, "SERVER_TO_CLIENT", "{\"t\":\"d\",\"d\":{\"a\":\"d\",\"b\":{\"p\":\"big\",\"d\":\"xxxx"));
        assertTrue(frag.summary().startsWith("Firebase RTDB: message fragment"));
        assertFalse(frag.warnings().isEmpty());
    }

    @Test
    void rtdbFrameShapeOnOtherHostIsWeakAndGenericJsonIsNot() {
        MessageContext m = ws("wss://proxy.example.com/socket", "CLIENT_TO_SERVER", "{\"t\":\"d\",\"d\":{\"r\":1,\"a\":\"q\",\"b\":{\"p\":\"/x\",\"h\":\"\"}}}");
        assertEquals(55, fb.match(m).confidence());
        MessageContext generic = ws("wss://chat.example.com/ws", "SERVER_TO_CLIENT", "{\"type\":\"message\",\"data\":{\"text\":\"hello there\"}}");
        assertEquals(0, fb.match(generic).confidence());
        assertThrows(DecodeException.class, () -> fb.decode(generic));
    }

    @Test
    void rtdbLongPoll() throws Exception {
        String msg = "{\"t\":\"d\",\"d\":{\"r\":2,\"a\":\"m\",\"b\":{\"p\":\"/users/u1\",\"d\":{\"role\":\"admin\",\"active\":true}}}}";
        // firebase web-safe base64 with '.' padding, split over two segments
        String b64 = Base64.getUrlEncoder().encodeToString(msg.getBytes(StandardCharsets.UTF_8)).replace('=', '.');
        String a = b64.substring(0, 40), b = b64.substring(40);
        String url = "https://acme-default-rtdb.firebaseio.com/.lp?id=7&pw=secretpw&ser=123&ns=acme-default-rtdb&seg0=5&ts0=2&d0=" + enc(a)
                + "&seg1=6&ts1=2&d1=" + enc(b);
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("GET").url(url).build();
        assertEquals(95, fb.match(m).confidence());
        DecodeResult r = fb.decode(m);
        assertEquals("Firebase RTDB long-poll → merge /users/u1 (r=2)", r.summary());
        assertEquals("admin", find(r.root(), "role"));

        MessageContext start = MessageContext.builder(MessageKind.REQUEST).method("GET")
                .url("https://acme-default-rtdb.firebaseio.com/.lp?start=t&ser=9&cb=1&v=5&ns=acme-default-rtdb").build();
        assertEquals("Firebase RTDB long-poll: start session (ns acme-default-rtdb)", fb.decode(start).summary());

        String script = "<script>pLPCommand('start','7','secretpw');pRTLPCB(0,[{\"t\":\"c\",\"d\":{\"t\":\"h\",\"d\":{\"ts\":1700000000000,\"v\":\"5\",\"h\":\"h1\",\"s\":\"s1\"}}}]);</script>";
        DecodeResult sr = fb.decode(response("GET", "https://acme-default-rtdb.firebaseio.com/.lp?start=t&ser=9&cb=1&v=5&ns=acme-default-rtdb", script));
        assertEquals("Firebase RTDB long-poll ← session started (id 7); control: handshake (host h1, session s1)", sr.summary());
    }

    @Test
    void rtdbRest() throws Exception {
        String url = "https://acme-default-rtdb.europe-west1.firebasedatabase.app/users.json?orderBy=%22role%22&equalTo=%22admin%22&auth=" + ID_TOKEN;
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("GET").url(url).build();
        assertEquals(90, fb.match(m).confidence());
        DecodeResult r = fb.decode(m);
        assertEquals("Firebase RTDB REST GET /users (orderBy \"role\", equalTo \"admin\") [auth]", r.summary());
        assertNotNull(findNode(r.root(), "(JWT)"));
        DecodeResult resp = fb.decode(response("GET", url, "{\"u1\":{\"role\":\"admin\"},\"u2\":{\"role\":\"admin\"}}"));
        assertEquals("Firebase RTDB REST response /users: 2 keys", resp.summary());
        assertEquals("Firebase RTDB REST response /users: error: Permission denied",
                fb.decode(response("GET", url, "{\"error\" : \"Permission denied\"}")).summary());
        String sse = "event: put\ndata: {\"path\":\"/\",\"data\":{\"a\":1}}\n\nevent: keep-alive\ndata: null\n\n";
        assertEquals("Firebase RTDB REST stream /users: 2 events (put, keep-alive)",
                fb.decode(response("GET", url, sse, "Content-Type", "text/event-stream")).summary());
    }

    // ------------------------------------------------------------ Firebase Auth

    @Test
    void identityToolkitSignInWithPassword() throws Exception {
        String url = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=AIzaSyFAKEKEY123";
        MessageContext req = MessageContext.builder(MessageKind.REQUEST).method("POST").url(url)
                .requestHeader("Content-Type", "application/json").requestHeader("X-Client-Version", "Chrome/JsCore/10.7.0/FirebaseCore-web")
                .requestBody("{\"returnSecureToken\":true,\"email\":\"alice@example.com\",\"password\":\"hunter2\",\"clientType\":\"CLIENT_TYPE_WEB\"}").build();
        assertEquals(95, fb.match(req).confidence());
        DecodeResult r = fb.decode(req);
        assertEquals("Identity Toolkit accounts:signInWithPassword (alice@example.com)", r.summary());
        assertEquals("AIzaSyFAKEKEY123", find(r.root(), "Web API key"));
        assertTrue(TreeText.render(r.root()).contains("public by design"));

        String body = "{\"kind\":\"identitytoolkit#VerifyPasswordResponse\",\"localId\":\"uid42\",\"email\":\"alice@example.com\",\"displayName\":\"\","
                + "\"idToken\":\"" + ID_TOKEN + "\",\"registered\":true,\"refreshToken\":\"AMf-vBx\",\"expiresIn\":\"3600\"}";
        MessageContext resp = response("POST", url, body, "Content-Type", "application/json; charset=UTF-8");
        assertEquals(90, fb.match(resp).confidence());
        DecodeResult rr = fb.decode(resp);
        assertTrue(rr.summary().startsWith("Identity Toolkit accounts:signInWithPassword response: idToken for uid uid42 (alice@example.com)"), rr.summary());
        assertTrue(rr.summary().contains("expiresIn 3600s"), rr.summary());
        DecodedNode jwt = findNode(rr.root(), "idToken (JWT)");
        assertNotNull(jwt);
        assertEquals("RS256", find(jwt, "alg"));
        assertEquals("password", find(jwt, "sign_in_provider"));
        assertTrue(find(jwt, "signature").contains("not verified"));

        String err = "{\"error\":{\"code\":400,\"message\":\"INVALID_LOGIN_CREDENTIALS\",\"errors\":[]}}";
        assertEquals("Identity Toolkit accounts:signInWithPassword response: error 400 INVALID_LOGIN_CREDENTIALS",
                fb.decode(response("POST", url, err)).summary());
    }

    @Test
    void secureTokenRefresh() throws Exception {
        String url = "https://securetoken.googleapis.com/v1/token?key=AIzaSyFAKEKEY123";
        MessageContext req = MessageContext.builder(MessageKind.REQUEST).method("POST").url(url)
                .requestHeader("Content-Type", "application/x-www-form-urlencoded").requestBody("grant_type=refresh_token&refresh_token=AMf-vBx").build();
        assertEquals("Secure Token token exchange (grant_type refresh_token, refresh_token)", fb.decode(req).summary());
        String body = "{\"access_token\":\"" + ID_TOKEN + "\",\"expires_in\":\"3600\",\"token_type\":\"Bearer\",\"refresh_token\":\"AMf-vBy\","
                + "\"id_token\":\"" + ID_TOKEN + "\",\"user_id\":\"uid42\",\"project_id\":\"123\"}";
        DecodeResult r = fb.decode(response("POST", url, body));
        assertTrue(r.summary().startsWith("Secure Token token exchange response: idToken for uid uid42"), r.summary());
        assertNotNull(findNode(r.root(), "access_token (JWT)"));
    }

    // ------------------------------------------------------------ web config

    @Test
    void htmlFirebaseConfig() throws Exception {
        String html = "<!doctype html><html><head><script type=\"module\">\n"
                + "import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.7.0/firebase-app.js';\n"
                + "const firebaseConfig = {\n  apiKey: \"AIzaSyFAKEKEY123\",\n  authDomain: \"acme-prod.firebaseapp.com\",\n"
                + "  databaseURL: \"https://acme-prod-default-rtdb.firebaseio.com\",\n  projectId: \"acme-prod\",\n"
                + "  storageBucket: \"acme-prod.appspot.com\",\n  messagingSenderId: \"1234567890\",\n  appId: \"1:1234567890:web:abcdef\"\n};\n"
                + "const app = initializeApp(firebaseConfig);\n</script></head><body></body></html>";
        MessageContext m = response("GET", "https://www.acme.example/", html, "Content-Type", "text/html; charset=utf-8");
        assertEquals(30, fb.match(m).confidence());
        DecodeResult r = fb.decode(m);
        assertEquals("Firebase config: project acme-prod (apiKey AIzaSyFAKEKEY123)", r.summary());
        assertEquals("acme-prod.firebaseapp.com", find(r.root(), "authDomain"));
        assertEquals("https://acme-prod-default-rtdb.firebaseio.com/.json", find(r.root(), "Realtime Database REST"));
    }

    @Test
    void minifiedJsConfigAndHostingInit() throws Exception {
        String js = "var a=1;Object(o.initializeApp)({apiKey:\"AIzaSyMINIFIED\",authDomain:\"shop-1.firebaseapp.com\",projectId:\"shop-1\",appId:\"1:9:web:f\"});";
        MessageContext m = response("GET", "https://cdn.acme.example/main.3f2a.js", js, "Content-Type", "application/javascript");
        assertEquals(30, fb.match(m).confidence());
        assertEquals("Firebase config: project shop-1 (apiKey AIzaSyMINIFIED)", fb.decode(m).summary());

        String init = "{\n  \"apiKey\": \"AIzaSyINIT\",\n  \"appId\": \"1:2:web:3\",\n  \"authDomain\": \"site.firebaseapp.com\",\n  \"projectId\": \"site\"\n}";
        MessageContext h = response("GET", "https://site.web.app/__/firebase/init.json", init, "Content-Type", "application/json");
        assertEquals(85, fb.match(h).confidence());
        assertEquals("Firebase config: project site (apiKey AIzaSyINIT)", fb.decode(h).summary());
    }

    @Test
    void negativesAndForcedGarbage() {
        MessageContext page = response("GET", "https://www.acme.example/", "<html><body>apiKey docs page</body></html>", "Content-Type", "text/html");
        assertEquals(0, fb.match(page).confidence());
        MessageContext plain = post("https://www.acme.example/login", "user=a&pass=b").build();
        assertEquals(0, fb.match(plain).confidence());
        assertThrows(DecodeException.class, () -> fb.decode(plain));
        assertThrows(DecodeException.class, () -> fb.decode(page));
        MessageContext garbageChannel = response("GET", LISTEN + "?TYPE=xmlhttp", "\u0001\u0002 not json at all");
        assertThrows(DecodeException.class, () -> fb.decode(garbageChannel));
        MessageContext garbageWs = ws("wss://x.example/ws", "SERVER_TO_CLIENT", "\u0000\u0001\u0002garbage");
        assertEquals(0, fb.match(garbageWs).confidence());
        assertThrows(DecodeException.class, () -> fb.decode(garbageWs));
        MessageContext img = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://x.example/a.png").statusCode(200)
                .responseHeader("Content-Type", "image/png").responseBody(new byte[]{(byte) 0x89, 'P', 'N', 'G'}).build();
        assertEquals(0, fb.match(img).confidence());
    }
}
