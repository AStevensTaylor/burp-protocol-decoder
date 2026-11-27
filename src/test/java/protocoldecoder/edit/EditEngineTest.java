package protocoldecoder.edit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.util.Codecs;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class EditEngineTest {

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });

    @AfterEach
    void close() {
        app.close();
    }

    static MessageContext dx(String param) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/Orders.aspx")
                .requestHeader("Content-Type", "application/x-www-form-urlencoded")
                .requestBody("__CALLBACKID=grid&__CALLBACKPARAM=" + URLEncoder.encode(param, StandardCharsets.UTF_8)).build();
    }

    static EditEngine.Field field(List<EditEngine.Field> fs, String suffix) {
        return fs.stream().filter(f -> f.name().endsWith(suffix)).findFirst().orElseThrow(() -> new AssertionError(fs.toString()));
    }

    @Test
    void successiveFieldEditsCompose() throws Exception {
        MessageContext original = dx("c0:KV|2;[];GB|20;12|PAGERONCLICK3|PN1;");
        EditEngine e = app.editEngine();
        List<EditEngine.Field> fs = e.fields(original);
        EditEngine.Field page = field(fs, "GB[1]");
        assertEquals("PN1", page.value());

        MessagePatch p1 = e.setField(original, page, "PN12");
        MessageContext m1 = p1.applyTo(original);
        EditEngine.Field cmd = field(e.fields(m1), "GB[0]");
        MessagePatch total = p1.then(e.setField(m1, cmd, "CUSTOMCALLBACK"));
        MessageContext m2 = total.applyTo(original);

        String param = Codecs.first(Codecs.parseQuery(m2.requestBodyText()), "__CALLBACKPARAM");
        assertEquals("c0:KV|2;[];GB|23;14|CUSTOMCALLBACK4|PN12;", param);
        DecodeResult r = app.engine().decode(m2).result();
        assertEquals("Callback → grid (CUSTOMCALLBACK)", r.summary());
        // original untouched
        assertTrue(original.requestBodyText().contains("PAGERONCLICK"));
    }

    @Test
    void missingFieldIsAnEncodeError() {
        MessageContext m = dx("c0:GB|3;1|a;");
        EditEngine.Field ghost = new EditEngine.Field("DevExpress: __CALLBACKPARAM nope", 0, "", protocoldecoder.scan.InsertionPoint.Part.BODY);
        assertThrows(EncodeException.class, () -> app.editEngine().setField(m, ghost, "x"));
    }

    @Test
    void noFieldsForResponsesTruncatedOrUnknown() {
        MessageContext resp = dx("c0:GB|3;1|a;").withKind(MessageKind.RESPONSE);
        assertTrue(app.editEngine().fields(resp).isEmpty());
        MessageContext plain = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://x.example/").build();
        assertTrue(app.editEngine().fields(plain).isEmpty());
        MessageContext truncated = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/a")
                .requestBody(dx("c0:GB|3;1|a;").requestBody()).truncated(true).build();
        assertTrue(app.editEngine().fields(truncated).isEmpty());
    }

    @Test
    void fieldsIgnoreScanInsertionPointToggle() {
        app.scanEngine().setEnabled("devexpress.insertion-points", false);
        assertFalse(app.editEngine().fields(dx("c0:GB|3;1|a;")).isEmpty());
    }

    @Test
    void documentsFromRegisteredCodec() throws Exception {
        app.editEngine().register(new MessageCodec() {
            @Override public String decoderId() { return "devexpress"; }
            @Override
            public List<EditableDocument> documents(MessageContext m, DecodeResult decoded) {
                if (!m.isRequest()) return List.of();
                String param = Codecs.first(Codecs.parseQuery(m.requestBodyText()), "__CALLBACKPARAM");
                return List.of(new EditableDocument() {
                    @Override public String title() { return "__CALLBACKPARAM (raw)"; }
                    @Override public String text() { return param; }
                    @Override public MessagePatch encode(String edited) {
                        return MessagePatch.body(protocoldecoder.scan.InsertionPoints.replaceFormField(m.requestBodyText(), "__CALLBACKPARAM", 0, edited));
                    }
                });
            }
        });
        MessageContext m = dx("c0:GB|3;1|a;");
        // the built-in DevExpressCodec contributes its own document too; keep only the test codec's
        List<EditEngine.Document> docs = app.editEngine().documents(m).stream()
                .filter(d -> d.document().title().equals("__CALLBACKPARAM (raw)")).toList();
        assertEquals(1, docs.size());
        assertEquals("c0:GB|3;1|a;", docs.get(0).document().text());
        MessageContext edited = EditEngine.encode(docs.get(0), "c0:GB|3;1|b;").applyTo(m);
        assertTrue(edited.requestBodyText().endsWith("c0%3AGB%7C3%3B1%7Cb%3B"));
    }

    @Test
    void patchesMergeAndApplyToEachKind() {
        MessagePatch p = MessagePatch.query("a=1").then(MessagePatch.header("X-Test", "1")).then(MessagePatch.query("b=2"))
                .then(MessagePatch.header("x-test", "2"));
        assertEquals("b=2", p.query());
        assertEquals(Map.of("x-test", "2"), p.headers());
        MessageContext req = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://h.example/p?a=0")
                .requestHeader("X-Test", "0").requestHeader("X-Test", "dup").build();
        MessageContext out = p.applyTo(req);
        assertEquals("https://h.example/p?b=2", out.url());
        assertEquals("b=2", out.query());
        assertEquals(1, out.requestHeaders().stream().filter(h -> h.name().equalsIgnoreCase("x-test")).count());
        assertEquals("2", out.requestHeader("X-Test"));

        MessageContext ws = MessageContext.builder(MessageKind.WEBSOCKET).url("https://h.example/ws").webSocket("CLIENT_TO_SERVER", "a".getBytes()).build();
        assertEquals("b", MessagePatch.body("b").applyTo(ws).bodyText());
        MessageContext resp = MessageContext.builder(MessageKind.RESPONSE).url("https://h.example/").statusCode(200).responseBody("x").build();
        assertEquals("y", MessagePatch.body("y").applyTo(resp).bodyText());
    }
}
