package protocoldecoder.builtin.phoenix;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.edit.EditEngine;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.util.TreeText;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PhoenixCodecTest {

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });
    final PhoenixDecoder phoenix = new PhoenixDecoder();

    @AfterEach
    void close() {
        app.close();
    }

    static MessageContext ws(String path, String frame) {
        return MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("https://app.example.com" + path + "?vsn=2.0.0")
                .webSocket("CLIENT_TO_SERVER", frame.getBytes(StandardCharsets.UTF_8)).build();
    }

    List<EditEngine.Document> docs(MessageContext m) {
        return app.editEngine().documents(m).stream().filter(d -> d.decoderId().equals(PhoenixDecoder.ID)).toList();
    }

    static String encode(EditEngine.Document d, String text) throws EncodeException {
        return new String(EditEngine.encode(d, text).body(), StandardCharsets.UTF_8);
    }

    String decoded(MessageContext m) throws Exception {
        return TreeText.render(phoenix.decode(m).root());
    }

    @Test
    void v2ArrayMessage() throws Exception {
        String frame = "[\"3\",\"4\",\"room:lobby\",\"new_msg\",{\"body\":\"hi <b>\",\"n\":1.50}]";
        MessageContext m = ws("/socket/websocket", frame);
        List<EditEngine.Document> ds = docs(m);
        assertEquals(1, ds.size());
        EditEngine.Document d = ds.get(0);
        assertEquals("Phoenix message (new_msg on room:lobby)", d.document().title());
        assertEquals("json", d.document().syntax());
        assertTrue(d.document().text().startsWith("[\n  \"3\",\n  \"4\",\n  \"room:lobby\""), d.document().text());
        assertEquals(frame, encode(d, d.document().text()));
        String edited = d.document().text().replace("\"hi <b>\"", "\"bye \\\"é\\\" 😀\"");
        assertEquals("[\"3\",\"4\",\"room:lobby\",\"new_msg\",{\"body\":\"bye \\\"é\\\" 😀\",\"n\":1.50}]", encode(d, edited));
        assertTrue(decoded(EditEngine.encode(d, edited).applyTo(m)).contains("bye \\\"é\\\" 😀"));
        EncodeException e = assertThrows(EncodeException.class, () -> EditEngine.encode(d, "[\"3\", \"4\",\n  ]"));
        assertTrue(e.getMessage().startsWith("JSON error at line 2"), e.getMessage());
    }

    @Test
    void v1ObjectMessageKeepsItsShape() throws Exception {
        String frame = "{\"topic\":\"room:lobby\",\"event\":\"phx_join\",\"payload\":{\"token\":\"abc\"},\"ref\":\"1\"}";
        MessageContext m = ws("/socket/websocket", frame);
        EditEngine.Document d = docs(m).get(0);
        assertEquals(frame, encode(d, d.document().text()));
        String out = encode(d, d.document().text().replace("room:lobby", "room:admin"));
        assertEquals("{\"topic\":\"room:admin\",\"event\":\"phx_join\",\"payload\":{\"token\":\"abc\"},\"ref\":\"1\"}", out);
        assertTrue(decoded(EditEngine.encode(d, d.document().text().replace("room:lobby", "room:admin")).applyTo(m)).contains("room:admin"));
    }

    @Test
    void liveViewFormValueDocument() throws Exception {
        String value = "user%5Bname%5D=alice+b&user%5Bbio%5D=line1%0D%0Aline2%5C&_target=user%5Bname%5D&flag";
        String frame = "[\"4\",\"5\",\"lv:phx-F1\",\"event\",{\"type\":\"form\",\"event\":\"save\",\"value\":\"" + value + "\"}]";
        MessageContext m = ws("/live/websocket", frame);
        List<EditEngine.Document> ds = docs(m);
        assertEquals(2, ds.size());
        EditEngine.Document form = ds.get(1);
        assertEquals("LiveView form value (save)", form.document().title());
        String t = form.document().text();
        assertTrue(t.endsWith("user[name]=alice b\nuser[bio]=line1\\r\\nline2\\\\\n_target=user[name]\nflag\n"), t);
        assertEquals(frame, encode(form, t));

        String edited = t.replace("user[name]=alice b", "user[name]=eve & co=1").replace("flag\n", "flag\nuser[role]=admin\n");
        String out = encode(form, edited);
        assertEquals("[\"4\",\"5\",\"lv:phx-F1\",\"event\",{\"type\":\"form\",\"event\":\"save\",\"value\":\""
                + "user%5Bname%5D=eve+%26+co%3D1&user%5Bbio%5D=line1%0D%0Aline2%5C&_target=user%5Bname%5D&flag&user%5Brole%5D=admin\"}]", out);
        String tree = decoded(EditEngine.encode(form, edited).applyTo(m));
        assertTrue(tree.contains("admin"), tree);

        assertThrows(EncodeException.class, () -> EditEngine.encode(form, "a=\\q"));
        // the whole message is still editable as JSON too
        assertEquals(frame, encode(ds.get(0), ds.get(0).document().text()));
    }

    @Test
    void longPollBodies() throws Exception {
        String lines = "[null,\"1\",\"phoenix\",\"heartbeat\",{}]\n[\"2\",\"3\",\"room:1\",\"msg\",{\"a\":1}]\n";
        MessageContext req = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/socket/longpoll?vsn=2.0.0&token=t")
                .requestHeader("Content-Type", "application/x-ndjson").requestBody(lines).build();
        EditEngine.Document d = docs(req).get(0);
        assertEquals("Phoenix long-poll messages (one per line)", d.document().title());
        assertEquals(lines, encode(d, d.document().text()));
        String out = encode(d, d.document().text().replace("\"a\": 1", "\"a\": 2"));
        assertEquals("[null,\"1\",\"phoenix\",\"heartbeat\",{}]\n[\"2\",\"3\",\"room:1\",\"msg\",{\"a\":2}]\n", out);

        String resp = "{\"status\":200,\"token\":\"tok\",\"messages\":[\"[null,null,\\\"room:1\\\",\\\"msg\\\",{}]\"]}";
        MessageContext r = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://app.example.com/socket/longpoll?vsn=2.0.0&token=t")
                .statusCode(200).responseHeader("Content-Type", "application/json").responseBody(resp).build();
        EditEngine.Document rd = docs(r).get(0);
        assertEquals(resp, encode(rd, rd.document().text()));
        assertTrue(decoded(EditEngine.encode(rd, rd.document().text().replace("\"status\": 200", "\"status\": 410")).applyTo(r)).contains("410"));
    }

    @Test
    void binaryFramesAreSkipped() {
        byte[] bin = {0, 1, 1, 4, 5, '1', '2', 'r', 'o', 'o', 'm', ':', '1', 'e', 'v', 'e', 'n', 't', 9};
        MessageContext m = MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("https://app.example.com/socket/websocket?vsn=2.0.0")
                .webSocket("CLIENT_TO_SERVER", bin).build();
        assertTrue(docs(m).isEmpty());
    }
}
