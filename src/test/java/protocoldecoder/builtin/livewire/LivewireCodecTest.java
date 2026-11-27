package protocoldecoder.builtin.livewire;

import org.junit.jupiter.api.Test;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.edit.CodecTestSupport;
import protocoldecoder.edit.EditEngine;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.edit.JsonDocuments;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class LivewireCodecTest extends CodecTestSupport {

    static final String SNAP = "{\"data\":{\"title\":\"Hello\",\"isAdmin\":false,\"post\":[null,{\"key\":5,\"class\":\"App\\\\Models\\\\Post\",\"s\":\"mdl\"}]},"
            + "\"memo\":{\"id\":\"Xk2\",\"name\":\"edit-post\",\"path\":\"posts/5/edit\",\"method\":\"GET\",\"children\":[],\"errors\":[],\"locale\":\"en\"},"
            + "\"checksum\":\"a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90\"}";

    static String body(String snapshot) {
        return "{\"_token\":\"csrfTok3n\",\"components\":[{\"snapshot\":" + JsonDocuments.quote(snapshot, JsonDocuments.Style.PLAIN)
                + ",\"updates\":{\"title\":\"x\"},\"calls\":[{\"path\":\"\",\"method\":\"save\",\"params\":[]}]}]}";
    }

    static MessageContext.Builder update(String body) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/livewire/update")
                .requestHeader("Content-Type", "application/json").requestHeader("X-Livewire", "").requestBody(body);
    }

    @Test
    void wholeRequestAndSignedSnapshot() throws Exception {
        String body = body(SNAP);
        MessageContext m = update(body).build();
        assertEquals(List.of("Livewire request", "(signed) Snapshot data: edit-post (checksum will break)"), titles(m));
        assertAllRoundTrip(docs(m), m);

        EditEngine.Document s = doc(m, "(signed) Snapshot data: edit-post (checksum will break)");
        assertTrue(s.document().text().startsWith("{\n  \"data\": {\n    \"title\": \"Hello\","), s.document().text());
        MessageContext e = apply(s, m, s.document().text().replace("\"isAdmin\": false", "\"isAdmin\": true"));
        assertEquals(body(SNAP.replace("\"isAdmin\":false", "\"isAdmin\":true")), e.requestBodyText());
        assertTrue(decodedTree(e).contains("true"));
        // checksum is kept verbatim (it will no longer match)
        assertTrue(e.requestBodyText().contains("a1b2c3d4e5f6"));
        assertThrows(EncodeException.class, () -> apply(s, m, "{\"data\": {,}}"));

        EditEngine.Document whole = doc(m, "Livewire request");
        MessageContext ew = apply(whole, m, whole.document().text().replace("\"title\": \"x\"", "\"title\": \"<script>\""));
        assertTrue(ew.requestBodyText().contains("\"updates\":{\"title\":\"<script>\"}"), ew.requestBodyText());
        assertTrue(decodedTree(ew).contains("<script>"));
    }

    @Test
    void responseIsPrettyJson() throws Exception {
        String resp = "{\"components\":[{\"snapshot\":" + JsonDocuments.quote(SNAP, JsonDocuments.Style.PLAIN)
                + ",\"effects\":{\"html\":\"<div wire:id=\\\"Xk2\\\">Hello<\\/div>\",\"dirty\":[\"title\"]}}],\"assets\":[]}";
        MessageContext m = update(body(SNAP)).statusCode(200).responseHeader("Content-Type", "application/json")
                .responseBody(resp).build().withKind(MessageKind.RESPONSE);
        assertEquals(List.of("Livewire response"), titles(m));
        assertAllRoundTrip(docs(m), m);
        EditEngine.Document d = doc(m, "Livewire response");
        MessageContext e = apply(d, m, d.document().text().replace("Hello<\\/div>", "Bye</div>"));
        // the original escaped '/', so the edited string is escaped the same way
        assertTrue(e.responseBodyText().contains("Bye<\\/div>"), e.responseBodyText());
        assertTrue(decodedTree(e).contains("Bye"));
    }
}
