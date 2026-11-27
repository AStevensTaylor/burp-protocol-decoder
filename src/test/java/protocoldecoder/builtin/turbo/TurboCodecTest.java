package protocoldecoder.builtin.turbo;

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

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TurboCodecTest {

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });

    @AfterEach
    void close() {
        app.close();
    }

    static final String STREAM = "<turbo-stream action=\"replace\" target=\"message_1\"><template><p>Hi é</p></template></turbo-stream>\n"
            + "<turbo-stream action=\"remove\" target=\"flash\"></turbo-stream>\n";

    static MessageContext resp(byte[] body, String ce) {
        MessageContext.Builder b = MessageContext.builder(MessageKind.RESPONSE).method("POST").url("https://app.example.com/messages")
                .requestHeader("Accept", "text/vnd.turbo-stream.html, text/html").statusCode(200)
                .responseHeader("Content-Type", "text/vnd.turbo-stream.html; charset=utf-8");
        if (ce != null) b.responseHeader("Content-Encoding", ce);
        return b.responseBody(body).build();
    }

    List<EditEngine.Document> docs(MessageContext m) {
        return app.editEngine().documents(m).stream().filter(d -> d.decoderId().equals(TurboDecoder.ID)).toList();
    }

    @Test
    void streamResponseAsHtml() throws Exception {
        MessageContext m = resp(STREAM.getBytes(StandardCharsets.UTF_8), null);
        EditEngine.Document d = docs(m).get(0);
        assertEquals("Turbo Stream (HTML)", d.document().title());
        assertEquals("html", d.document().syntax());
        assertEquals(STREAM, d.document().text());
        assertArrayEquals(m.responseBody(), EditEngine.encode(d, d.document().text()).body());
        String edited = STREAM.replace("<p>Hi é</p>", "<img src=x onerror=alert(1)>");
        MessageContext out = EditEngine.encode(d, edited).applyTo(m);
        String summary = new TurboDecoder().decode(out).summary();
        assertTrue(summary.contains("replace #message_1"), summary);
        assertEquals(edited, out.responseBodyText());

        EncodeException e = assertThrows(EncodeException.class, () -> EditEngine.encode(d, "<div>no stream</div>"));
        assertTrue(e.getMessage().contains("No <turbo-stream>"), e.getMessage());
        e = assertThrows(EncodeException.class, () -> EditEngine.encode(d, "<turbo-stream action=\"append\" target=\"x\"><template>open"));
        assertTrue(e.getMessage().contains("not closed"), e.getMessage());
        assertThrows(EncodeException.class, () -> EditEngine.encode(d, "<turbo-stream target=\"x\"></turbo-stream>"));
    }

    @Test
    void gzipResponseIsRecompressedAndPagesAreSkipped() throws Exception {
        byte[] gz = EditJson.gzip(STREAM.getBytes(StandardCharsets.UTF_8));
        MessageContext m = resp(gz, "gzip");
        EditEngine.Document d = docs(m).get(0);
        assertArrayEquals(gz, EditEngine.encode(d, d.document().text()).body());
        byte[] out = EditEngine.encode(d, STREAM.replace("flash", "notice")).body();
        assertEquals(STREAM.replace("flash", "notice"), new String(Codecs.gunzip(out), StandardCharsets.UTF_8));

        MessageContext page = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://app.example.com/")
                .statusCode(200).responseHeader("Content-Type", "text/html").responseBody("<html><turbo-frame id=\"a\"></turbo-frame></html>").build();
        assertTrue(docs(page).isEmpty());
    }
}
