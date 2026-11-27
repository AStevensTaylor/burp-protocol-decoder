package protocoldecoder.edit;

import org.junit.jupiter.api.AfterEach;
import protocoldecoder.App;
import protocoldecoder.core.DecoderEngine;
import protocoldecoder.core.MessageContext;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.util.TreeText;

import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/** End-to-end helpers for codec tests: documents via the real {@link EditEngine}, edits applied, re-decoded. */
public abstract class CodecTestSupport {

    protected final App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });

    @AfterEach
    void closeApp() {
        app.close();
    }

    protected List<EditEngine.Document> docs(MessageContext m) {
        return app.editEngine().documents(m);
    }

    protected List<String> titles(MessageContext m) {
        return docs(m).stream().map(d -> d.document().title()).collect(Collectors.toList());
    }

    /** The document with exactly this title. */
    protected EditEngine.Document doc(MessageContext m, String title) {
        return docs(m).stream().filter(d -> d.document().title().equals(title)).findFirst()
                .orElseThrow(() -> new AssertionError("no document \"" + title + "\" in " + titles(m)));
    }

    protected static MessageContext apply(EditEngine.Document d, MessageContext m, String text) throws EncodeException {
        return EditEngine.encode(d, text).applyTo(m);
    }

    /** encode(text()) reproduces the message byte-for-byte (body, URL, headers). */
    protected static void assertRoundTrip(EditEngine.Document d, MessageContext m) throws EncodeException {
        MessageContext r = apply(d, m, d.document().text());
        assertArrayEquals(m.body(), r.body(), d.document().title() + ": body changed by an unedited round trip");
        assertEquals(m.url(), r.url(), d.document().title());
        assertEquals(m.headers(), r.headers(), d.document().title());
    }

    protected static void assertAllRoundTrip(List<EditEngine.Document> docs, MessageContext m) throws EncodeException {
        assertFalse(docs.isEmpty(), "no documents");
        for (EditEngine.Document d : docs) assertRoundTrip(d, m);
    }

    /** Text of the decoded tree of {@code m} with its resolved decoder; fails if decoding fails. */
    protected String decodedTree(MessageContext m) {
        DecoderEngine.Outcome o = app.engine().decode(m);
        assertTrue(o.ok(), "decode failed: " + o.error());
        return TreeText.render(o.result().root()) + "\n" + o.result().summary();
    }

    protected static String replaceOnce(String s, String from, String to) {
        int i = s.indexOf(from);
        assertTrue(i >= 0, "\"" + from + "\" not in:\n" + s);
        return s.substring(0, i) + to + s.substring(i + from.length());
    }
}
