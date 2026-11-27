package protocoldecoder.builtin.socketio;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.edit.EditEngine;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.EditJson;
import protocoldecoder.util.TreeText;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class SocketIoCodecTest {

    static final String RS = "\u001e";
    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });
    final SocketIoDecoder sio = new SocketIoDecoder();

    @AfterEach
    void close() {
        app.close();
    }

    static MessageContext ws(String frame) {
        return MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("https://chat.example.com/socket.io/?EIO=4&transport=websocket&sid=abc")
                .webSocket("CLIENT_TO_SERVER", frame.getBytes(StandardCharsets.UTF_8)).build();
    }

    static MessageContext pollResponse(int eio, String body) {
        return MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://chat.example.com/socket.io/?EIO=" + eio + "&transport=polling&sid=abc")
                .statusCode(200).responseHeader("Content-Type", "text/plain; charset=UTF-8").responseBody(body).build();
    }

    EditEngine.Document doc(MessageContext m) {
        List<EditEngine.Document> ds = app.editEngine().documents(m).stream().filter(d -> d.decoderId().equals(SocketIoDecoder.ID)).toList();
        assertEquals(1, ds.size(), ds.toString());
        return ds.get(0);
    }

    String encode(EditEngine.Document d, String text) throws EncodeException {
        return new String(EditEngine.encode(d, text).body(), StandardCharsets.UTF_8);
    }

    String decoded(MessageContext m) throws Exception {
        return TreeText.render(sio.decode(m).root());
    }

    @Test
    void webSocketEventWithNamespaceAndAck() throws Exception {
        String frame = "42/admin,12[\"chat message\",{\"text\":\"hi\"}]";
        MessageContext m = ws(frame);
        EditEngine.Document d = doc(m);
        assertEquals("Engine.IO packet", d.document().title());
        String t = d.document().text();
        assertTrue(t.contains("\n### 42/admin,12\n[\n  \"chat message\",\n  {\n    \"text\": \"hi\"\n  }\n]\n"), t);
        assertEquals(frame, encode(d, t));

        String edited = t.replace("\"hi\"", "\"bye \\\"q\\\" é😀 \\u001e\"");
        assertEquals("42/admin,12[\"chat message\",{\"text\":\"bye \\\"q\\\" é😀 \\u001e\"}]", encode(d, edited));
        MessageContext out = EditEngine.encode(d, edited).applyTo(m);
        String tree = decoded(out);
        assertTrue(tree.contains("/admin") && tree.contains("bye \\\"q\\\" é😀"), tree);

        // header edits: different namespace and ack id
        assertEquals("42/other,99[\"chat message\",{\"text\":\"hi\"}]", encode(d, t.replace("### 42/admin,12", "### 42/other,99")));
    }

    @Test
    void invalidEditsAreRejected() {
        EditEngine.Document d = doc(ws("42[\"ev\",1]"));
        EncodeException e = assertThrows(EncodeException.class, () -> EditEngine.encode(d, "### 42\n[\"ev\",\n"));
        assertTrue(e.getMessage().startsWith("Packet 1 (line 1): JSON error at line 1, column 7"), e.getMessage());
        e = assertThrows(EncodeException.class, () -> EditEngine.encode(d, "### 9\n[1]"));
        assertTrue(e.getMessage().contains("Engine.IO packet type"), e.getMessage());
        e = assertThrows(EncodeException.class, () -> EditEngine.encode(d, "### 42\n{\"not\":\"an array\"}"));
        assertTrue(e.getMessage().contains("EVENT payload must be an array"), e.getMessage());
        e = assertThrows(EncodeException.class, () -> EditEngine.encode(d, "### 42\n[\"a\"]\n### 2\n"));
        assertTrue(e.getMessage().contains("exactly one"), e.getMessage());
        e = assertThrows(EncodeException.class, () -> EditEngine.encode(d, "stray text\n### 2"));
        assertTrue(e.getMessage().contains("Line 1"), e.getMessage());
    }

    @Test
    void rawEngineIoPackets() throws Exception {
        EditEngine.Document probe = doc(ws("3probe"));
        assertTrue(probe.document().text().endsWith("### 3\nprobe\n"), probe.document().text());
        assertEquals("3probe", encode(probe, probe.document().text()));
        assertEquals("2probe", encode(probe, probe.document().text().replace("### 3", "### 2")));
        EditEngine.Document ping = doc(ws("2"));
        assertEquals("2", encode(ping, ping.document().text()));

        MessageContext bin = MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("https://chat.example.com/socket.io/?EIO=4&transport=websocket")
                .webSocket("CLIENT_TO_SERVER", new byte[]{1, 2, 3}).build();
        assertTrue(app.editEngine().documents(bin).stream().noneMatch(x -> x.decoderId().equals(SocketIoDecoder.ID)));
    }

    @Test
    void v4PollingKeepsSeparatorsAndBinaryPackets() throws Exception {
        String body = "0{\"sid\":\"abc\",\"upgrades\":[\"websocket\"],\"pingInterval\":25000,\"pingTimeout\":20000}" + RS
                + "451-[\"upload\",{\"_placeholder\":true,\"num\":0}]" + RS + "bAQID" + RS + "2";
        MessageContext m = pollResponse(4, body);
        EditEngine.Document d = doc(m);
        assertEquals("Engine.IO packets (4)", d.document().title());
        String t = d.document().text();
        assertTrue(t.contains("### 451-\n[\n  \"upload\","), t);
        assertTrue(t.contains("### b\nAQID\n"), t);
        assertEquals(body, encode(d, t));

        String edited = t.replace("\"upload\"", "\"upload2\"") + "\n### 42/admin,\n[\"added\", 1]\n";
        String out = encode(d, edited);
        assertEquals("0{\"sid\":\"abc\",\"upgrades\":[\"websocket\"],\"pingInterval\":25000,\"pingTimeout\":20000}" + RS
                + "451-[\"upload2\",{\"_placeholder\":true,\"num\":0}]" + RS + "bAQID" + RS + "2" + RS + "42/admin,[\"added\",1]", out);
        String tree = decoded(EditEngine.encode(d, edited).applyTo(m));
        assertTrue(tree.contains("upload2") && tree.contains("added"), tree);

        assertThrows(EncodeException.class, () -> EditEngine.encode(d, t.replace("### b\nAQID", "### b\n!!not base64")));
    }

    @Test
    void v3PollingRecomputesUtf16Lengths() throws Exception {
        String p1 = "42[\"é😀\",1]";
        String body = p1.length() + ":" + p1 + "6:3probe";
        MessageContext m = pollResponse(3, body);
        EditEngine.Document d = doc(m);
        assertEquals(body, encode(d, d.document().text()));
        String out = encode(d, d.document().text().replace("\"é😀\"", "\"é😀😀 longer\""));
        String np = "42[\"é😀😀 longer\",1]";
        assertEquals(np.length() + ":" + np + "6:3probe", out);
        assertEquals(20, np.length(), "UTF-16 code units: each emoji counts twice");
        String tree = decoded(EditEngine.encode(d, d.document().text().replace("\"é😀\"", "\"é😀😀 longer\"")).applyTo(m));
        assertTrue(tree.contains("é😀😀 longer"), tree);
    }

    @Test
    void pollingRequestsAndCompressedResponses() throws Exception {
        String body = "42[\"msg\",\"a\"]";
        MessageContext req = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://chat.example.com/socket.io/?EIO=4&transport=polling&sid=abc")
                .requestHeader("Content-Type", "text/plain;charset=UTF-8").requestBody(body).build();
        EditEngine.Document d = doc(req);
        assertEquals(body, encode(d, d.document().text()));
        assertEquals("42[\"msg\",\"b\"]", encode(d, d.document().text().replace("\"a\"", "\"b\"")));

        byte[] gz = EditJson.gzip(("40" + RS + "42[\"x\",1]").getBytes(StandardCharsets.UTF_8));
        MessageContext resp = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://chat.example.com/socket.io/?EIO=4&transport=polling&sid=abc")
                .statusCode(200).responseHeader("Content-Encoding", "gzip").responseBody(gz).build();
        EditEngine.Document rd = doc(resp);
        assertArrayEquals(gz, EditEngine.encode(rd, rd.document().text()).body());
        byte[] out = EditEngine.encode(rd, rd.document().text().replace("\"x\"", "\"y\"")).body();
        assertEquals("40" + RS + "42[\"y\",1]", new String(Codecs.gunzip(out), StandardCharsets.UTF_8));

        MessageContext ok = MessageContext.builder(MessageKind.RESPONSE).method("POST").url("https://chat.example.com/socket.io/?EIO=4&transport=polling&sid=abc")
                .statusCode(200).responseBody("ok").build();
        assertTrue(app.editEngine().documents(ok).stream().noneMatch(x -> x.decoderId().equals(SocketIoDecoder.ID)));
    }
}
