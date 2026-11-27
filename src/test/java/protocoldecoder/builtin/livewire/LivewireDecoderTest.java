package protocoldecoder.builtin.livewire;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.util.TreeText;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class LivewireDecoderTest {

    final LivewireDecoder lw = new LivewireDecoder();

    // ------------------------------------------------------------ fixtures

    static JsonObject json(String s) {
        return JsonParser.parseString(s.replace('\'', '"')).getAsJsonObject();
    }

    static final String EDIT_POST_DATA = """
            {'title':'Hello world',
             'post':[null,{'key':5,'class':'App\\\\Models\\\\Post','connection':'mysql','s':'mdl'}],
             'tags':[['php','laravel'],{'s':'arr'}],
             'form':[{'body':'text','author':[null,{'key':9,'class':'App\\\\Models\\\\User','s':'mdl'}]},{'class':'App\\\\Livewire\\\\Forms\\\\PostForm','s':'form'}],
             'published_at':['2024-05-01T10:00:00+00:00',{'type':'carbon','s':'cbn'}],
             'comments':[[],{'keys':[1,2,3],'class':'Illuminate\\\\Database\\\\Eloquent\\\\Collection','modelClass':'App\\\\Models\\\\Comment','s':'elcln'}],
             'status':['draft',{'class':'App\\\\Enums\\\\Status','s':'enm'}],
             'isAdmin':false,
             'apiToken':'tok_live_123'}""";

    static String snapshot(String name, String id, String data, String errors) {
        JsonObject snap = new JsonObject();
        snap.add("data", json(data));
        snap.add("memo", json("{'id':'" + id + "','name':'" + name + "','path':'posts/5/edit','method':'GET','children':[],"
                + "'scripts':[],'assets':[],'errors':" + errors + ",'locale':'en'}"));
        snap.addProperty("checksum", "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90");
        return snap.toString();
    }

    static JsonObject component(String snapshot, String updates, String calls) {
        JsonObject c = new JsonObject();
        c.addProperty("snapshot", snapshot);
        c.add("updates", json(updates));
        c.add("calls", JsonParser.parseString(calls.replace('\'', '"')));
        return c;
    }

    static String updateRequest(JsonObject... comps) {
        JsonObject o = new JsonObject();
        o.addProperty("_token", "csrfTok3n");
        JsonArray a = new JsonArray();
        for (JsonObject c : comps) a.add(c);
        o.add("components", a);
        return o.toString();
    }

    static MessageContext request(String path, String body) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com" + path)
                .requestHeader("Content-Type", "application/json").requestHeader("X-Livewire", "").requestBody(body).build();
    }

    static MessageContext.Builder response(String path, String reqBody, int status, String contentType) {
        return MessageContext.builder(MessageKind.RESPONSE).method("POST").url("https://app.example.com" + path)
                .requestHeader("Content-Type", "application/json").requestBody(reqBody)
                .statusCode(status).responseHeader("Content-Type", contentType);
    }

    static String find(DecodedNode n, String nameContains) {
        if (n.name().contains(nameContains) && n.value() != null) return n.value();
        for (DecodedNode c : n.children()) {
            String v = find(c, nameContains);
            if (v != null) return v;
        }
        return null;
    }

    static DecodedNode node(DecodedNode n, String nameContains) {
        if (n.name().contains(nameContains)) return n;
        for (DecodedNode c : n.children()) {
            DecodedNode v = node(c, nameContains);
            if (v != null) return v;
        }
        return null;
    }

    /** Property {@code name} of the first Properties node under {@code n}. */
    static DecodedNode prop(DecodedNode n, String name) {
        DecodedNode props = node(n, "Properties");
        return props == null ? null : props.get(name);
    }

    static boolean anyWarning(DecodeResult r, String... parts) {
        outer:
        for (String w : r.warnings()) {
            for (String p : parts) if (!w.contains(p)) continue outer;
            return true;
        }
        return false;
    }

    static byte[] gzip(String s) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
            gz.write(s.getBytes(StandardCharsets.UTF_8));
        }
        return bos.toByteArray();
    }

    // ------------------------------------------------------------ v3 requests

    @Test
    void v3UpdateRequestWithCallsUpdatesAndModels() throws Exception {
        String body = updateRequest(component(snapshot("edit-post", "Xk2pLm9QaR", EDIT_POST_DATA, "[]"),
                "{'title':'New title','form.body':'changed'}",
                "[{'path':'','method':'save','params':[5,'draft']}]"));
        MessageContext m = request("/livewire/update", body);
        assertEquals(95, lw.match(m).confidence());

        DecodeResult r = lw.decode(m);
        assertEquals("Livewire update: edit-post → save(…), 2 property updates", r.summary());
        DecodedNode root = r.root();
        assertEquals("csrfTok3n", find(root, "_token"));
        assertEquals("wire:id Xk2pLm9QaR", node(root, "[0] edit-post").value());
        assertEquals("Eloquent model App\\Models\\Post #5", prop(root, "post").value());
        assertEquals("Eloquent model App\\Models\\User #9", prop(root, "form").get("author").value());
        assertEquals("Form object App\\Livewire\\Forms\\PostForm", prop(root, "form").value());
        assertEquals("Eloquent collection of App\\Models\\Comment keys [1,2,3]", prop(root, "comments").value());
        assertTrue(prop(root, "published_at").value().startsWith("Carbon / DateTime \"2024-05-01"));
        assertEquals("Enum App\\Enums\\Status::\"draft\"", prop(root, "status").value());
        assertEquals("New title", find(node(root, "Updates"), "title"));
        DecodedNode calls = node(root, "Calls");
        assertEquals("save(…)", calls.children().get(0).name());
        assertTrue(TreeText.render(calls).contains("draft"));
        assertNotNull(find(root, "Checksum"));
        assertEquals("en", find(node(root, "Memo"), "locale"));

        assertTrue(anyWarning(r, "App\\Models\\Post #5", "'post'", "edit-post", "mysql", "checksum"), r.warnings().toString());
        assertTrue(anyWarning(r, "App\\Models\\User #9", "form.author"), r.warnings().toString());
        assertTrue(anyWarning(r, "Model collection App\\Models\\Comment"), r.warnings().toString());
        assertTrue(anyWarning(r, "'apiToken'", "tok_live_123"), r.warnings().toString());
        assertTrue(anyWarning(r, "'isAdmin'"), r.warnings().toString());
        assertTrue(anyWarning(r, "save()", "2 client-controlled parameters"), r.warnings().toString());
    }

    @Test
    void sensitiveUpdatesAndMagicCalls() throws Exception {
        String body = updateRequest(component(snapshot("user-settings", "abc", "{'name':'Bob','role':'user'}", "[]"),
                "{'role':'admin'}",
                "[{'path':'','method':'$set','params':['is_admin',true]},{'path':'','method':'__dispatch','params':['refresh-list',{}]},"
                        + "{'path':'','method':'_startUpload','params':['photo',[{'name':'a.svg','size':12,'type':'image/svg+xml'}],false]}]"));
        DecodeResult r = lw.decode(request("/livewire/update", body));
        assertEquals("Livewire update: user-settings → $set(is_admin, …), __dispatch(refresh-list, …), _startUpload(…), 1 property update", r.summary());
        assertTrue(anyWarning(r, "Client update sets sensitive-looking property 'role'"), r.warnings().toString());
        assertTrue(anyWarning(r, "$set targets", "is_admin"), r.warnings().toString());
        assertTrue(anyWarning(r, "File upload started"), r.warnings().toString());
        assertFalse(anyWarning(r, "__dispatch()"), r.warnings().toString());
        assertEquals("event dispatched to this component (name, params)", node(r.root(), "__dispatch").value());
    }

    @Test
    void multipleComponentsInOneRequest() throws Exception {
        String body = updateRequest(
                component(snapshot("edit-post", "id1", "{'title':'x'}", "[]"), "{'title':'y'}", "[{'path':'','method':'save','params':[]}]"),
                component(snapshot("counter", "id2", "{'count':3}", "[]"), "{}", "[{'path':'','method':'increment','params':[]}]"),
                component(snapshot("search", "id3", "{'q':''}", "[]"), "{}", "[]"));
        DecodeResult r = lw.decode(request("/livewire/update", body));
        assertEquals("Livewire update (3 components): edit-post → save(), 1 property update; counter → increment(); search → no updates or calls", r.summary());
        assertEquals(3, node(r.root(), "Components").children().size());
        assertEquals("3", prop(node(r.root(), "[1] counter"), "count").value());
    }

    @Test
    void customUpdatePathMatchedByShape() throws Exception {
        String body = updateRequest(component(snapshot("edit-post", "id1", "{'title':'x'}", "[]"), "{}", "[]"));
        assertEquals(75, lw.match(request("/api/internal/lw", body)).confidence());
        // Livewire 3.5+ hashes the prefix, e.g. /livewire-4f2a9c1b/update
        assertEquals(95, lw.match(request("/livewire-4f2a9c1b/update", body)).confidence());
        assertEquals(95, lw.match(request("/admin/livewire/update", body)).confidence());
    }

    // ------------------------------------------------------------ v3 responses

    @Test
    void v3ResponseWithEffectsAndValidationErrors() throws Exception {
        String reqBody = updateRequest(component(snapshot("edit-post", "id1", "{'title':''}", "[]"), "{'title':''}", "[{'path':'','method':'save','params':[]}]"));
        JsonObject fx = json("""
                {'html':'<div wire:id=\\"id1\\"><span class=\\"error\\">The title field is required.</span></div>',
                 'returns':[null],
                 'dispatches':[{'name':'post-saved','params':{'id':5}},{'name':'notify','params':{'msg':'ok'},'to':'toaster'}],
                 'redirect':'/posts?saved=1','redirectUsingNavigate':true,
                 'xjs':[{'expression':'alert(1)','params':[]}],
                 'download':{'name':'report.csv','content':'aWQsbmFtZQoxLEJvYgo=','contentType':'text/csv'}}""");
        JsonObject comp = new JsonObject();
        comp.addProperty("snapshot", snapshot("edit-post", "id1", "{'title':'','post':[null,{'key':5,'class':'App\\\\Models\\\\Post','s':'mdl'}]}",
                "{'title':['The title field is required.'],'body':['The body must be at least 10 characters.']}"));
        comp.add("effects", fx);
        JsonObject o = new JsonObject();
        JsonArray a = new JsonArray();
        a.add(comp);
        o.add("components", a);
        o.add("assets", new JsonArray());

        MessageContext m = response("/livewire/update", reqBody, 200, "application/json").responseBody(o.toString()).build();
        assertEquals(95, lw.match(m).confidence());
        DecodeResult r = lw.decode(m);
        assertEquals("Livewire response: edit-post — html, 1 return value, 2 dispatches, redirect → /posts?saved=1, xjs, download report.csv, 2 validation errors",
                r.summary());
        DecodedNode effects = node(r.root(), "Effects");
        assertEquals(DecodedNode.Type.HTML, effects.get("html").type());
        assertEquals("to toaster", node(effects, "notify").value());
        assertEquals("14", find(node(effects, "download"), "size"));
        assertTrue(find(node(effects, "download"), "preview").startsWith("id,name"));
        assertEquals("The title field is required.", find(node(r.root(), "Validation errors"), "title"));
        assertTrue(anyWarning(r, "Validation errors", "title, body"), r.warnings().toString());
        assertTrue(anyWarning(r, "redirects to /posts?saved=1"), r.warnings().toString());
        assertTrue(anyWarning(r, "xjs"), r.warnings().toString());
        assertTrue(anyWarning(r, "download", "report.csv"), r.warnings().toString());
        assertTrue(anyWarning(r, "App\\Models\\Post #5"), r.warnings().toString());
    }

    @Test
    void gzippedResponse() throws Exception {
        JsonObject comp = new JsonObject();
        comp.addProperty("snapshot", snapshot("counter", "c1", "{'count':4}", "[]"));
        comp.add("effects", json("{'html':'<div>4</div>','returns':[]}"));
        JsonObject o = new JsonObject();
        JsonArray a = new JsonArray();
        a.add(comp);
        o.add("components", a);
        MessageContext m = response("/livewire/update", "{}", 200, "application/json").responseHeader("Content-Encoding", "gzip")
                .responseBody(gzip(o.toString())).build();
        assertEquals(95, lw.match(m).confidence());
        assertEquals("Livewire response: counter — html", lw.decode(m).summary());
    }

    @Test
    void updateEndpointErrorResponse() throws Exception {
        MessageContext m = response("/livewire/update", "{}", 419, "text/html")
                .responseBody("<!DOCTYPE html><html><title>Page Expired</title></html>").build();
        assertEquals(55, lw.match(m).confidence());
        DecodeResult r = lw.decode(m);
        assertTrue(r.summary().startsWith("Livewire endpoint response: HTTP 419 (page expired"), r.summary());
    }

    // ------------------------------------------------------------ v2

    static final String V2_REQUEST = """
            {'fingerprint':{'id':'XyZ123abc','name':'edit-post','locale':'en','path':'posts/5/edit','method':'GET','v':'acj'},
             'serverMemo':{'children':[],'errors':[],'htmlHash':'5d1b3e0f',
               'data':{'post':[],'title':'Hello','password':'hunter2','comments':[]},
               'dataMeta':{'models':{'post':{'class':'App\\\\Models\\\\Post','id':5,'relations':['author'],'connection':'mysql'}},
                           'modelCollections':{'comments':{'class':'App\\\\Models\\\\Comment','id':[11,12],'relations':[],'connection':'mysql'}}},
               'checksum':'9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'},
             'updates':[
               {'type':'syncInput','payload':{'id':'k1','name':'title','value':'Changed'}},
               {'type':'syncInput','payload':{'id':'k2','name':'post.user_id','value':'2'}},
               {'type':'callMethod','payload':{'id':'k3','method':'update','params':[5]}},
               {'type':'fireEvent','payload':{'id':'k4','event':'refreshPosts','params':[]}}]}""";

    @Test
    void v2MessageRequestWithDataMeta() throws Exception {
        String body = json(V2_REQUEST).toString();
        MessageContext m = request("/livewire/message/edit-post", body);
        assertEquals(95, lw.match(m).confidence());
        DecodeResult r = lw.decode(m);
        assertEquals("Livewire v2 message: edit-post → update(…), 2 input syncs, 1 event", r.summary());
        DecodedNode models = node(r.root(), "Models");
        assertEquals("App\\Models\\Post #5", models.get("post").value());
        assertEquals("App\\Models\\Comment #[11,12]", node(r.root(), "Model collections").get("comments").value());
        assertEquals("\"Changed\"", node(r.root(), "syncInput title").value());
        assertNotNull(find(r.root(), "Checksum (HMAC of fingerprint"));
        assertEquals("acj", find(node(r.root(), "fingerprint"), "v"));
        assertTrue(anyWarning(r, "Model App\\Models\\Post #5", "'post'", "mysql"), r.warnings().toString());
        assertTrue(anyWarning(r, "Model collection App\\Models\\Comment [11,12]"), r.warnings().toString());
        assertTrue(anyWarning(r, "'password'", "hunter2"), r.warnings().toString());
        assertTrue(anyWarning(r, "update()", "1 client-controlled parameter "), r.warnings().toString());
        // also matched by shape on a different path
        assertEquals(75, lw.match(request("/custom/lw-endpoint", body)).confidence());
    }

    @Test
    void v2MessageResponse() throws Exception {
        String resp = json("""
                {'effects':{'html':'<div wire:id=\\"XyZ123abc\\">Saved</div>','dirty':['title'],
                   'emits':[{'event':'postSaved','params':[5],'selfOnly':false}],
                   'dispatches':[{'event':'browser-notify','data':{'msg':'Saved'}}],
                   'redirect':'https://evil.example/'},
                 'serverMemo':{'htmlHash':'77aa','data':{'title':'Changed'},'dataMeta':{'models':{'post':{'class':'App\\\\Models\\\\Post','id':5,'relations':[],'connection':'mysql'}}},
                   'errors':{'title':['The title has already been taken.']},'checksum':'abcd'}}""").toString();
        MessageContext m = response("/livewire/message/edit-post", json(V2_REQUEST).toString(), 200, "application/json").responseBody(resp).build();
        assertEquals(95, lw.match(m).confidence());
        DecodeResult r = lw.decode(m);
        assertEquals("Livewire v2 response: edit-post — html, 1 dirty, 1 emit, 1 dispatch, redirect → https://evil.example/, 1 validation error", r.summary());
        assertEquals(DecodedNode.Type.HTML, node(r.root(), "Effects").get("html").type());
        assertNotNull(node(node(r.root(), "emits"), "postSaved"));
        assertTrue(anyWarning(r, "redirects to https://evil.example/"), r.warnings().toString());
        assertTrue(anyWarning(r, "Validation errors", "title"), r.warnings().toString());
        assertTrue(anyWarning(r, "App\\Models\\Post #5"), r.warnings().toString());
    }

    // ------------------------------------------------------------ pages

    static String escape(String s) {
        return s.replace("&", "&amp;").replace("\"", "&quot;").replace("'", "&#039;").replace("<", "&lt;").replace(">", "&gt;");
    }

    @Test
    void htmlPageWithV3SnapshotsAndV2InitialData() throws Exception {
        String v3snap = snapshot("edit-post", "Xk2pLm9QaR", "{'title':'Tom & Jerry <3','post':[null,{'key':5,'class':'App\\\\Models\\\\Post','s':'mdl'}],'secretNote':'shh'}", "[]");
        String v3fx = "{\"listeners\":[\"post-updated\"],\"url\":{\"q\":{\"as\":\"q\"}}}";
        String v2data = json("""
                {'fingerprint':{'id':'legacy1','name':'legacy-widget','locale':'en','path':'/','method':'GET','v':'acj'},
                 'effects':{'listeners':[]},
                 'serverMemo':{'children':[],'errors':[],'htmlHash':'aa','data':{'count':1},
                   'dataMeta':{'models':{'user':{'class':'App\\\\Models\\\\User','id':42,'relations':[],'connection':'pgsql'}}},'checksum':'ff'}}""").toString();
        String html = "<!DOCTYPE html><html><head><meta name=\"csrf-token\" content=\"pageCsrf123\"></head><body>\n"
                + "<div wire:snapshot=\"" + escape(v3snap) + "\" wire:effects=\"" + escape(v3fx) + "\" wire:id=\"Xk2pLm9QaR\">\n"
                + "  <input wire:model=\"title\"></div>\n"
                + "<div wire:id=\"legacy1\" wire:initial-data=\"" + escape(v2data) + "\">1</div>\n"
                + "<script src=\"/livewire/livewire.js?id=cc800bf4\" data-csrf=\"pageCsrf123\" data-update-uri=\"/app/livewire-x/update\" data-navigate-once=\"true\"></script>\n"
                + "</body></html>";
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://app.example.com/posts/5/edit")
                .statusCode(200).responseHeader("Content-Type", "text/html; charset=UTF-8").responseBody(html).build();
        assertEquals(30, lw.match(m).confidence());
        DecodeResult r = lw.decode(m);
        assertEquals("Livewire page: 2 components (edit-post, legacy-widget)", r.summary());
        DecodedNode root = r.root();
        assertEquals("Tom & Jerry <3", prop(root, "title").value());
        assertEquals("Eloquent model App\\Models\\Post #5", prop(root, "post").value());
        assertEquals("wire:id Xk2pLm9QaR", node(root, "[0] edit-post").value());
        assertNotNull(node(node(root, "[0] edit-post"), "Effects"));
        assertEquals("App\\Models\\User #42", node(node(root, "[1] legacy-widget"), "Models").get("user").value());
        DecodedNode cfg = node(root, "Configuration");
        assertEquals("pageCsrf123", cfg.get("meta csrf-token").value());
        assertEquals("pageCsrf123", cfg.get("data-csrf").value());
        assertEquals("/app/livewire-x/update", cfg.get("data-update-uri").value());
        assertTrue(TreeText.render(cfg).contains("customised update endpoint"));
        assertTrue(anyWarning(r, "'secretNote'"), r.warnings().toString());
        assertTrue(anyWarning(r, "App\\Models\\User #42", "pgsql"), r.warnings().toString());
        assertFalse(r.summary().contains("no effects"));
    }

    @Test
    void pageWithOnlyLivewireScriptIsLowConfidence() {
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://app.example.com/")
                .statusCode(200).responseHeader("Content-Type", "text/html")
                .responseBody("<html><script src=\"/livewire/livewire.js?id=1\" data-csrf=\"t\" data-update-uri=\"/livewire/update\"></script></html>").build();
        assertEquals(20, lw.match(m).confidence());
    }

    // ------------------------------------------------------------ uploads

    @Test
    void uploadAndPreview() throws Exception {
        String multipart = "--b\r\nContent-Disposition: form-data; name=\"files[]\"; filename=\"evil.svg\"\r\nContent-Type: image/svg+xml\r\n\r\n<svg/>\r\n--b--\r\n";
        MessageContext up = MessageContext.builder(MessageKind.REQUEST).method("POST")
                .url("https://app.example.com/livewire/upload-file?expires=1717000000&signature=deadbeef")
                .requestHeader("Content-Type", "multipart/form-data; boundary=b").requestBody(multipart).build();
        assertEquals(70, lw.match(up).confidence());
        DecodeResult r = lw.decode(up);
        assertEquals("Livewire upload: 1 file", r.summary());
        assertEquals("image/svg+xml", node(r.root(), "Files").children().get(0).value());
        assertEquals("deadbeef", find(r.root(), "signature"));
        assertNotNull(find(r.root(), "expires (UTC)"));

        MessageContext upResp = MessageContext.builder(MessageKind.RESPONSE).method("POST")
                .url("https://app.example.com/livewire/upload-file?expires=1717000000&signature=deadbeef")
                .statusCode(200).responseHeader("Content-Type", "application/json")
                .responseBody("{\"paths\":[\"Qm9vbXRtcA-meta-ZXZpbC5zdmc=-.svg\"]}").build();
        assertEquals("Livewire upload response: 1 temporary file", lw.decode(upResp).summary());

        MessageContext prev = MessageContext.builder(MessageKind.RESPONSE).method("GET")
                .url("https://app.example.com/livewire/preview-file/Qm9vbXRtcA-meta-ZXZpbC5zdmc=-.svg?expires=1717000000&signature=cafe")
                .statusCode(200).responseHeader("Content-Type", "image/svg+xml").responseBody("<svg onload=alert(1)/>").build();
        assertEquals(60, lw.match(prev).confidence());
        DecodeResult p = lw.decode(prev);
        assertTrue(p.summary().startsWith("Livewire file preview: Qm9vbXRtcA-meta-ZXZpbC5zdmc=-.svg"), p.summary());
        assertTrue(anyWarning(p, "stored XSS"), p.warnings().toString());
    }

    // ------------------------------------------------------------ negatives

    @Test
    void genericComponentsApiDoesNotMatch() {
        String body = "{\"components\":[{\"name\":\"button\",\"snapshot\":\"abc\",\"memo\":\"x\",\"checksum\":\"y\"}],\"version\":2}";
        MessageContext m = response("/api/design-system/components", "", 200, "application/json").responseBody(body).build();
        assertEquals(0, lw.match(m).confidence());
        MessageContext req = request("/api/design-system/components", body);
        assertEquals(0, lw.match(req).confidence());
        MessageContext asset = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://app.example.com/livewire/livewire.js?id=abc")
                .statusCode(200).responseHeader("Content-Type", "application/javascript").responseBody("window.Livewire={snapshot:1,components:[]}").build();
        assertEquals(0, lw.match(asset).confidence());
        MessageContext ws = MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("https://app.example.com/livewire/update")
                .webSocket("CLIENT_TO_SERVER", body.getBytes(StandardCharsets.UTF_8)).build();
        assertEquals(0, lw.match(ws).confidence());
    }

    @Test
    void forcedDecodeOnGarbageThrows() {
        MessageContext garbage = request("/api/other", "\u0000\u0001not json at all {");
        DecodeException e = assertThrows(DecodeException.class, () -> lw.decode(garbage));
        assertTrue(e.getMessage().startsWith("Not a Livewire message"), e.getMessage());
        assertThrows(DecodeException.class, () -> lw.decode(request("/api/other", "{\"components\":[1,2]}")));
        assertThrows(DecodeException.class, () -> lw.decode(request("/livewire/update", "garbage")));
        assertEquals(0, lw.match(request("/api/other", "{\"components\":[{\"snapshot\":\"{memo checksum\"}]}")).confidence());
    }

    @Test
    void brokenSnapshotStillDecodes() throws Exception {
        JsonObject c = new JsonObject();
        c.addProperty("snapshot", "{not-json");
        c.add("updates", new JsonObject());
        c.add("calls", new JsonArray());
        DecodeResult r = lw.decode(request("/livewire/update", updateRequest(c)));
        assertTrue(TreeText.render(r.root()).contains("snapshot is not valid JSON"));
        assertTrue(r.summary().startsWith("Livewire update: component"), r.summary());
    }
}
