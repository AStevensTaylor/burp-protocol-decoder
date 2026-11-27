package protocoldecoder.builtin.actioncable;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.builtin.turbo.TurboDecoderTest;
import protocoldecoder.core.MessageContext;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.Severity;

import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static protocoldecoder.builtin.actioncable.ActionCableDecoderTest.CHAT_ID;
import static protocoldecoder.builtin.actioncable.ActionCableDecoderTest.client;
import static protocoldecoder.builtin.actioncable.ActionCableDecoderTest.q;
import static protocoldecoder.builtin.actioncable.ActionCableDecoderTest.server;

class ActionCableScannerTest {

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });

    @AfterEach
    void close() {
        app.close();
    }

    List<Finding> passive(MessageContext m, String checkId) {
        return app.scanEngine().passive(m, false).stream().filter(f -> f.checkId().equals(checkId)).toList();
    }

    static String subscribe(String signed) {
        String identifier = q("{\"channel\":\"Turbo::StreamsChannel\",\"signed_stream_name\":\"" + signed + "\"}");
        return "{\"command\":\"subscribe\",\"identifier\":" + identifier + "}";
    }

    @Test
    void globalIdsInSubscription() {
        List<Finding> f = passive(client(subscribe(TurboDecoderTest.signedJson("\"gid://app/Room/1:messages\""))), "actioncable.signed-stream-gid");
        assertEquals(1, f.size());
        assertEquals(Severity.INFORMATION, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("gid://app/Room/1"), f.get(0).detail());
        // confirmations carry the same identifier
        String confirm = "{\"identifier\":" + q("{\"channel\":\"Turbo::StreamsChannel\",\"signed_stream_name\":\""
                + TurboDecoderTest.signedJson("\"gid://app/User/5\"") + "\"}") + ",\"type\":\"confirm_subscription\"}";
        assertEquals(1, passive(server(confirm), "actioncable.signed-stream-gid").size());
        // plain channel params / non-gid stream names
        assertTrue(passive(client("{\"command\":\"subscribe\",\"identifier\":" + CHAT_ID + "}"), "actioncable.signed-stream-gid").isEmpty());
        assertTrue(passive(client(subscribe(TurboDecoderTest.signedJson("\"lobby\""))), "actioncable.signed-stream-gid").isEmpty());
    }

    @Test
    void marshalSignedStreamName() {
        String signed = Base64.getEncoder().encodeToString(TurboDecoderTest.marshalString("gid://app/Room/2")) + "--" + "c".repeat(64);
        List<Finding> f = passive(client(subscribe(signed)), "actioncable.signed-stream-marshal");
        assertEquals(1, f.size());
        assertEquals(Severity.LOW, f.get(0).severity());
        assertTrue(passive(client(subscribe(TurboDecoderTest.signedJson("\"gid://app/Room/2\""))), "actioncable.signed-stream-marshal").isEmpty());
    }

    @Test
    void sensitiveBroadcast() {
        String msg = "{\"identifier\":" + CHAT_ID + ",\"message\":{\"body\":\"hi\",\"author\":{\"email\":\"carol@example.com\",\"api_key\":\"ak_9f8e7d6c5b\"}}}";
        List<Finding> f = passive(server(msg), "actioncable.sensitive-broadcast");
        assertEquals(1, f.size());
        assertEquals(Severity.LOW, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("carol@example.com") && f.get(0).detail().contains("ak_9f8e7d6c5b"), f.get(0).detail());
        assertTrue(f.get(0).detail().contains("ChatChannel"), f.get(0).detail());

        assertTrue(passive(server("{\"identifier\":" + CHAT_ID + ",\"message\":{\"body\":\"hello there\",\"id\":5}}"), "actioncable.sensitive-broadcast").isEmpty());
        assertTrue(passive(server("{\"type\":\"ping\",\"message\":1700000000}"), "actioncable.sensitive-broadcast").isEmpty());
        // client → server action messages are the user's own input, not broadcasts
        String data = q("{\"action\":\"speak\",\"password\":\"hunter22\"}");
        assertTrue(passive(client("{\"command\":\"message\",\"identifier\":" + CHAT_ID + ",\"data\":" + data + "}"), "actioncable.sensitive-broadcast").isEmpty());
    }

    @Test
    void noActiveChecksOrInsertionPoints() {
        ActionCableScanner s = new ActionCableScanner();
        assertTrue(s.activeChecks().isEmpty());
        assertTrue(s.insertionPoints(client(subscribe("x--aa")), null).isEmpty());
    }
}
