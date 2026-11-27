package protocoldecoder.builtin.actioncable;

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

class ActionCableCodecTest {

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });

    @AfterEach
    void close() {
        app.close();
    }

    static MessageContext ws(String dir, String frame) {
        return MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("https://app.example.com/cable")
                .webSocket(dir, frame.getBytes(StandardCharsets.UTF_8)).build();
    }

    EditEngine.Document doc(MessageContext m) {
        List<EditEngine.Document> ds = app.editEngine().documents(m).stream().filter(d -> d.decoderId().equals(ActionCableDecoder.ID)).toList();
        assertEquals(1, ds.size());
        return ds.get(0);
    }

    static String encode(EditEngine.Document d, String text) throws EncodeException {
        return new String(EditEngine.encode(d, text).body(), StandardCharsets.UTF_8);
    }

    @Test
    void messageCommandUnfoldsIdentifierAndData() throws Exception {
        String frame = "{\"command\":\"message\",\"identifier\":\"{\\\"channel\\\":\\\"ChatChannel\\\",\\\"room\\\":\\\"1\\\"}\","
                + "\"data\":\"{\\\"message\\\":\\\"hi \\\\\\\"there\\\\\\\"\\\",\\\"action\\\":\\\"speak\\\"}\"}";
        MessageContext m = ws("CLIENT_TO_SERVER", frame);
        EditEngine.Document d = doc(m);
        assertEquals("Action Cable frame (message)", d.document().title());
        String t = d.document().text();
        assertTrue(t.contains("\"identifier\": {\n    \"channel\": \"ChatChannel\",\n    \"room\": \"1\"\n  }"), t);
        assertTrue(t.contains("\"message\": \"hi \\\"there\\\"\""), t);
        assertEquals(frame, encode(d, t));

        String edited = t.replace("\"hi \\\"there\\\"\"", "\"<script>é😀\"").replace("\"room\": \"1\"", "\"room\": \"2\"");
        String out = encode(d, edited);
        assertEquals("{\"command\":\"message\",\"identifier\":\"{\\\"channel\\\":\\\"ChatChannel\\\",\\\"room\\\":\\\"2\\\"}\","
                + "\"data\":\"{\\\"message\\\":\\\"<script>é😀\\\",\\\"action\\\":\\\"speak\\\"}\"}", out);
        String tree = TreeText.render(new ActionCableDecoder().decode(EditEngine.encode(d, edited).applyTo(m)).root());
        assertTrue(tree.contains("<script>é😀") && tree.contains("ChatChannel"), tree);

        EncodeException e = assertThrows(EncodeException.class, () -> EditEngine.encode(d, "{\"command\": \"message\",\n  \"identifier\": {,}}"));
        assertTrue(e.getMessage().startsWith("JSON error at line 2"), e.getMessage());
        assertThrows(EncodeException.class, () -> EditEngine.encode(d, "[1]"));
    }

    @Test
    void unchangedNestedStringsKeepTheirOriginalFormatting() throws Exception {
        // identifier with spaces (not JSON.stringify formatting): kept verbatim when only data changes
        String frame = "{\"command\":\"message\",\"identifier\":\"{\\\"channel\\\": \\\"X\\\"}\",\"data\":\"{\\\"n\\\":1}\"}";
        EditEngine.Document d = doc(ws("CLIENT_TO_SERVER", frame));
        assertEquals(frame, encode(d, d.document().text()));
        assertEquals("{\"command\":\"message\",\"identifier\":\"{\\\"channel\\\": \\\"X\\\"}\",\"data\":\"{\\\"n\\\":2}\"}",
                encode(d, d.document().text().replace("\"n\": 1", "\"n\": 2")));
        // leaving a nested value as a string sends it verbatim
        assertEquals("{\"command\":\"message\",\"identifier\":\"raw\",\"data\":\"{\\\"n\\\":1}\"}",
                encode(d, d.document().text().replaceFirst("\"identifier\": \\{[^}]*\\}", "\"identifier\": \"raw\"")));
    }

    @Test
    void serverFrames() throws Exception {
        String broadcast = "{\"identifier\":\"{\\\"channel\\\":\\\"Turbo::StreamsChannel\\\",\\\"signed_stream_name\\\":\\\"abc--def\\\"}\","
                + "\"message\":\"<turbo-stream action=\\\"append\\\" target=\\\"m\\\"><template>x</template></turbo-stream>\"}";
        EditEngine.Document d = doc(ws("SERVER_TO_CLIENT", broadcast));
        assertEquals(broadcast, encode(d, d.document().text()));
        assertTrue(encode(d, d.document().text().replace("<template>x", "<template>y")).contains("<template>y"));
        EditEngine.Document ping = doc(ws("SERVER_TO_CLIENT", "{\"type\":\"ping\",\"message\":1700000000}"));
        assertEquals("Action Cable frame (ping)", ping.document().title());
        assertEquals("{\"type\":\"ping\",\"message\":1700000000}", encode(ping, ping.document().text()));
    }
}
