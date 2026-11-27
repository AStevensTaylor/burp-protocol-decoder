package protocoldecoder.builtin.livewire;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.scan.ActiveCheck;
import protocoldecoder.scan.Exchange;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.HttpSender;
import protocoldecoder.scan.InsertionPoint;
import protocoldecoder.scan.Severity;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;
import static protocoldecoder.builtin.livewire.LivewireDecoderTest.EDIT_POST_DATA;
import static protocoldecoder.builtin.livewire.LivewireDecoderTest.component;
import static protocoldecoder.builtin.livewire.LivewireDecoderTest.request;
import static protocoldecoder.builtin.livewire.LivewireDecoderTest.response;
import static protocoldecoder.builtin.livewire.LivewireDecoderTest.snapshot;
import static protocoldecoder.builtin.livewire.LivewireDecoderTest.updateRequest;

class LivewireScannerTest {

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });

    @AfterEach
    void close() {
        app.close();
    }

    static final String UPDATE = "/livewire/update";
    static final String PLAIN_DATA = "{'title':'Hello world','count':3}";

    List<Finding> passive(MessageContext m, String checkId) {
        return app.scanEngine().passive(m, false).stream().filter(f -> f.checkId().equals(checkId)).toList();
    }

    static String reqBody(String data) {
        return updateRequest(component(snapshot("edit-post", "abc123", data, "[]"), "{'title':'New'}", "[{'path':'','method':'save','params':[]}]"));
    }

    static String respBody(String data, String effects) {
        JsonObject c = new JsonObject();
        c.addProperty("snapshot", snapshot("edit-post", "abc123", data, "[]"));
        c.add("effects", JsonParser.parseString(effects.replace('\'', '"')));
        JsonArray a = new JsonArray();
        a.add(c);
        JsonObject o = new JsonObject();
        o.add("components", a);
        o.add("assets", new JsonArray());
        return o.toString();
    }

    static MessageContext v3Response(String data, String effects) {
        return response(UPDATE, reqBody(data), 200, "application/json").responseBody(respBody(data, effects)).build();
    }

    // ------------------------------------------------------------ models / properties

    @Test
    void modelExposure() {
        List<Finding> f = passive(v3Response(EDIT_POST_DATA, "{'html':'<div></div>'}"), "livewire.model-exposure");
        assertEquals(1, f.size());
        assertEquals(Severity.INFORMATION, f.get(0).severity());
        String d = f.get(0).detail();
        assertTrue(d.contains("edit-post → post: Eloquent model App\\Models\\Post #5"), d);
        assertTrue(d.contains("form.author: Eloquent model App\\Models\\User #9"), d);
        assertTrue(d.contains("App\\Models\\Comment"), d);
        assertTrue(passive(v3Response(PLAIN_DATA, "{'html':'<div></div>'}"), "livewire.model-exposure").isEmpty());
        // requests echo the snapshot: not reported again
        assertTrue(passive(request(UPDATE, reqBody(EDIT_POST_DATA)), "livewire.model-exposure").isEmpty());
    }

    @Test
    void v2DataMetaModels() {
        String body = "{'effects':{'html':'<div></div>','dirty':[]},'serverMemo':{'data':{'post':[]},'dataMeta':{'models':{'post':{'class':'App\\\\Models\\\\Post','id':12,'relations':[],'connection':'mysql'}}},'checksum':'abc'}}";
        MessageContext m = response("/livewire/message/edit-post", "{'fingerprint':{'id':'x','name':'edit-post'},'serverMemo':{'checksum':'abc'},'updates':[]}".replace('\'', '"'),
                200, "application/json").responseBody(body.replace('\'', '"')).build();
        List<Finding> f = passive(m, "livewire.model-exposure");
        assertEquals(1, f.size());
        assertTrue(f.get(0).detail().contains("post: App\\Models\\Post #12"), f.get(0).detail());
    }

    @Test
    void sensitiveProperties() {
        List<Finding> f = passive(v3Response(EDIT_POST_DATA, "{'html':'<div></div>'}"), "livewire.sensitive-properties");
        assertEquals(1, f.size());
        assertEquals(Severity.LOW, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("tok_live_123"), f.get(0).detail());
        assertFalse(f.get(0).detail().contains("isAdmin"), "boolean flags are not secrets");

        String hash = "{'title':'x','user':{'name':'bob','pw':'$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234'}}";
        f = passive(v3Response(hash, "{}"), "livewire.sensitive-properties");
        assertEquals(1, f.size());
        assertTrue(f.get(0).detail().contains("bcrypt password hash"), f.get(0).detail());

        assertTrue(passive(v3Response(PLAIN_DATA, "{}"), "livewire.sensitive-properties").isEmpty());
    }

    // ------------------------------------------------------------ debug page / csrf / redirect

    @Test
    void debugPage() {
        String html = "<!doctype html><html><head><title>Illuminate\\Database\\QueryException</title></head><body>"
                + "<script>window.ignite = {}</script><div>/var/www/vendor/laravel/framework/src/Illuminate/Database/Connection.php:822</div></body></html>";
        MessageContext m = response(UPDATE, reqBody(PLAIN_DATA), 500, "text/html; charset=UTF-8").responseBody(html).build();
        List<Finding> f = passive(m, "livewire.debug-page");
        assertEquals(1, f.size());
        assertEquals(Severity.MEDIUM, f.get(0).severity());
        assertEquals(Finding.Scope.HOST, f.get(0).scope());

        String json = "{\"message\":\"Undefined variable\",\"exception\":\"ErrorException\",\"file\":\"/var/www/app/Livewire/EditPost.php\",\"line\":12,\"trace\":[{\"file\":\"x\"}]}";
        m = response(UPDATE, reqBody(PLAIN_DATA), 500, "application/json").responseBody(json).build();
        assertEquals(1, passive(m, "livewire.debug-page").size());

        MessageContext prod = response(UPDATE, reqBody(PLAIN_DATA), 500, "text/html").responseBody("<html><body>Server Error</body></html>").build();
        assertTrue(passive(prod, "livewire.debug-page").isEmpty());
        MessageContext prodJson = response(UPDATE, reqBody(PLAIN_DATA), 500, "application/json").responseBody("{\"message\":\"Server Error\"}").build();
        assertTrue(passive(prodJson, "livewire.debug-page").isEmpty());
    }

    @Test
    void missingCsrfToken() {
        JsonObject o = JsonParser.parseString(reqBody(PLAIN_DATA)).getAsJsonObject();
        o.remove("_token");
        List<Finding> f = passive(request(UPDATE, o.toString()), "livewire.missing-csrf-token");
        assertEquals(1, f.size());
        assertEquals(Severity.INFORMATION, f.get(0).severity());

        assertTrue(passive(request(UPDATE, reqBody(PLAIN_DATA)), "livewire.missing-csrf-token").isEmpty());
        MessageContext header = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com" + UPDATE)
                .requestHeader("Content-Type", "application/json").requestHeader("X-CSRF-TOKEN", "t0k").requestBody(o.toString()).build();
        assertTrue(passive(header, "livewire.missing-csrf-token").isEmpty());
    }

    @Test
    void externalRedirect() {
        List<Finding> f = passive(v3Response(PLAIN_DATA, "{'redirect':'https://evil.example/phish','html':''}"), "livewire.external-redirect");
        assertEquals(1, f.size());
        assertTrue(f.get(0).detail().contains("https://evil.example/phish"));
        assertTrue(passive(v3Response(PLAIN_DATA, "{'redirect':'/dashboard'}"), "livewire.external-redirect").isEmpty());
        assertTrue(passive(v3Response(PLAIN_DATA, "{'redirect':'https://app.example.com/x'}"), "livewire.external-redirect").isEmpty());
        assertTrue(passive(v3Response(PLAIN_DATA, "{'redirect':'https://auth.app.example.com/x'}"), "livewire.external-redirect").isEmpty());
    }

    // ------------------------------------------------------------ active

    static final class Fake implements HttpSender {
        final List<String> bodies = new ArrayList<>();
        final Function<String, MessageContext.Builder> responder;

        Fake(Function<String, MessageContext.Builder> responder) {
            this.responder = responder;
        }

        @Override
        public Exchange send(String method, String pathAndQuery, List<Header> headers, byte[] body) {
            String b = new String(body, StandardCharsets.UTF_8);
            bodies.add(b);
            return new Exchange(responder.apply(b).method(method).url("https://app.example.com" + pathAndQuery).requestBody(body).build(), null);
        }

        @Override
        public Exchange send(InsertionPoint point, String payload) {
            throw new UnsupportedOperationException();
        }
    }

    /** A server that skips checksum verification: echoes the received snapshot back. */
    static MessageContext.Builder echo(String requestBody) {
        JsonObject req = JsonParser.parseString(requestBody).getAsJsonObject();
        String snap = req.getAsJsonArray("components").get(0).getAsJsonObject().get("snapshot").getAsString();
        JsonObject c = new JsonObject();
        c.addProperty("snapshot", snap);
        c.add("effects", JsonParser.parseString("{\"html\":\"<div></div>\"}"));
        JsonArray a = new JsonArray();
        a.add(c);
        JsonObject o = new JsonObject();
        o.add("components", a);
        return MessageContext.builder(MessageKind.REQUEST).statusCode(200).responseHeader("Content-Type", "application/json").responseBody(o.toString());
    }

    List<Finding> active(HttpSender http) {
        return app.scanEngine().active(ActiveCheck.Scope.PER_REQUEST, request(UPDATE, reqBody(EDIT_POST_DATA)), null, null, null, null, http)
                .stream().filter(f -> f.checkId().equals("livewire.checksum-enforcement")).toList();
    }

    @Test
    void checksumNotEnforced() {
        Fake http = new Fake(LivewireScannerTest::echo);
        List<Finding> f = active(http);
        assertEquals(1, http.bodies.size());
        JsonObject sent = JsonParser.parseString(http.bodies.get(0)).getAsJsonObject();
        assertEquals("csrfTok3n", sent.get("_token").getAsString());
        JsonObject comp = sent.getAsJsonArray("components").get(0).getAsJsonObject();
        assertEquals(0, comp.getAsJsonObject("updates").size(), "no property updates");
        assertEquals(0, comp.getAsJsonArray("calls").size(), "no method calls");
        JsonObject snap = JsonParser.parseString(comp.get("snapshot").getAsString()).getAsJsonObject();
        assertEquals("Hello worldpd7x", snap.getAsJsonObject("data").get("title").getAsString());
        assertEquals("a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90", snap.get("checksum").getAsString());
        assertEquals(1, f.size());
        assertEquals(Severity.MEDIUM, f.get(0).severity());
    }

    @Test
    void checksumEnforced() {
        Fake rejects = new Fake(b -> MessageContext.builder(MessageKind.REQUEST).statusCode(500).responseHeader("Content-Type", "text/html")
                .responseBody("Livewire\\Mechanisms\\HandleComponents\\CorruptComponentPayloadException"));
        assertTrue(active(rejects).isEmpty());
        assertEquals(1, rejects.bodies.size());
        // a 200 that doesn't carry the modified value isn't proof
        Fake unrelated = new Fake(b -> MessageContext.builder(MessageKind.REQUEST).statusCode(200).responseHeader("Content-Type", "application/json")
                .responseBody(respBody(PLAIN_DATA, "{}")));
        assertTrue(active(unrelated).isEmpty());
    }

    @Test
    void noInsertionPoints() {
        assertTrue(app.scanEngine().insertionPoints(request(UPDATE, reqBody(EDIT_POST_DATA))).isEmpty());
    }
}
