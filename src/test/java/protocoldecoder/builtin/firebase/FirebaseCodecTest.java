package protocoldecoder.builtin.firebase;

import org.junit.jupiter.api.Test;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.edit.CodecTestSupport;
import protocoldecoder.edit.EditEngine;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.edit.JsonDocuments;
import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class FirebaseCodecTest extends CodecTestSupport {

    static final String DB = "projects/acme-prod/databases/(default)";
    static final String LISTEN = "https://firestore.googleapis.com/google.firestore.v1.Firestore/Listen/channel?VER=8&database="
            + JsonDocuments.encodeURIComponent(DB) + "&RID=1&CVER=22&X-HTTP-Session-Id=gsessionid&zx=abc&t=1";

    static MessageContext post(String url, String ct, String body) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url(url).requestHeader("Content-Type", ct).requestBody(body).build();
    }

    @Test
    void webChannelMapsAreEditedInPlace() throws Exception {
        String add = "{\"database\":\"" + DB + "\",\"addTarget\":{\"query\":{\"structuredQuery\":{\"from\":[{\"collectionId\":\"users\"}],"
                + "\"where\":{\"fieldFilter\":{\"field\":{\"fieldPath\":\"role\"},\"op\":\"EQUAL\",\"value\":{\"stringValue\":\"user\"}}}},"
                + "\"parent\":\"" + DB + "/documents\"},\"targetId\":2}}";
        String remove = "{\"removeTarget\":2}";
        String body = "count=2&ofs=5&req0___data__=" + JsonDocuments.encodeURIComponent(add) + "&req1___data__=" + JsonDocuments.encodeURIComponent(remove);
        MessageContext m = post(LISTEN, "application/x-www-form-urlencoded", body);
        assertEquals(List.of("Firestore Listen req0", "Firestore Listen req1"), titles(m));
        assertAllRoundTrip(docs(m), m);
        EditEngine.Document d = doc(m, "Firestore Listen req0");
        MessageContext e = apply(d, m, d.document().text().replace("\"user\"", "\"admin (x)\""));
        assertEquals("count=2&ofs=5&req0___data__=" + JsonDocuments.encodeURIComponent(add.replace("\"user\"", "\"admin (x)\""))
                + "&req1___data__=" + JsonDocuments.encodeURIComponent(remove), e.requestBodyText());
        assertTrue(decodedTree(e).contains("role == admin (x)"), decodedTree(e));
        assertThrows(EncodeException.class, () -> apply(d, m, "{\"addTarget\": nope}"));
    }

    @Test
    void restBodiesAndAuth() throws Exception {
        String write = "{\"fields\":{\"name\":{\"stringValue\":\"Ann\"},\"age\":{\"integerValue\":\"30\"}}}";
        MessageContext rest = MessageContext.builder(MessageKind.REQUEST).method("PATCH")
                .url("https://firestore.googleapis.com/v1/" + DB + "/documents/users/u1?updateMask.fieldPaths=name")
                .requestHeader("Content-Type", "application/json").requestBody(write).build();
        assertEquals(List.of("Firestore request"), titles(rest));
        assertAllRoundTrip(docs(rest), rest);
        MessageContext er = apply(doc(rest, "Firestore request"), rest, write.replace("Ann", "Zoë"));
        assertEquals(write.replace("Ann", "Zoë"), er.requestBodyText());
        assertTrue(decodedTree(er).contains("Zoë"));

        MessageContext rtdb = MessageContext.builder(MessageKind.REQUEST).method("PUT")
                .url("https://acme-default-rtdb.firebaseio.com/users/u1.json?auth=x").requestHeader("Content-Type", "application/json")
                .requestBody("{\"admin\":false}").statusCode(200).responseHeader("Content-Type", "application/json; charset=utf-8")
                .responseBody("{\"admin\":false}").build();
        assertEquals(List.of("RTDB data (request)"), titles(rtdb));
        MessageContext ed = apply(doc(rtdb, "RTDB data (request)"), rtdb, "{\"admin\": true}");
        assertEquals("{\"admin\":true}", ed.requestBodyText());
        assertTrue(decodedTree(ed).contains("true"));
        MessageContext resp = rtdb.withKind(MessageKind.RESPONSE);
        assertEquals(List.of("RTDB data (response)"), titles(resp));
        assertAllRoundTrip(docs(resp), resp);

        MessageContext auth = post("https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=AIzaSyX",
                "application/json", "{\"email\":\"a@b.c\",\"password\":\"p\",\"returnSecureToken\":true}");
        assertEquals(List.of("Firebase Auth request"), titles(auth));
        assertAllRoundTrip(docs(auth), auth);
        MessageContext ea = apply(doc(auth, "Firebase Auth request"), auth, "{\"email\": \"admin@b.c\", \"password\": \"p\", \"returnSecureToken\": true}");
        assertTrue(decodedTree(ea).contains("admin@b.c"));
    }

    @Test
    void rtdbWebSocketFramesButNotCountPrefixes() throws Exception {
        String url = "wss://acme-default-rtdb.firebaseio.com/.ws?v=5&ns=acme-default-rtdb";
        String frame = "{\"t\":\"d\",\"d\":{\"r\":3,\"a\":\"p\",\"b\":{\"p\":\"/users/u1\",\"d\":{\"name\":\"Ann\",\"n\":1.5e3}}}}";
        MessageContext ws = MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url(url)
                .webSocket("CLIENT_TO_SERVER", frame.getBytes(StandardCharsets.UTF_8)).build();
        assertEquals(List.of("RTDB frame"), titles(ws));
        assertAllRoundTrip(docs(ws), ws);
        EditEngine.Document d = doc(ws, "RTDB frame");
        MessageContext e = apply(d, ws, d.document().text().replace("/users/u1", "/users/u2"));
        assertEquals(frame.replace("u1", "u2"), Codecs.utf8(e.body()));
        assertTrue(decodedTree(e).contains("/users/u2"));

        MessageContext count = MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url(url)
                .webSocket("SERVER_TO_CLIENT", "3".getBytes(StandardCharsets.UTF_8)).build();
        assertTrue(titles(count).isEmpty());
        MessageContext fragment = MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url(url)
                .webSocket("SERVER_TO_CLIENT", "{\"t\":\"d\",\"d\":{\"b\":".getBytes(StandardCharsets.UTF_8)).build();
        assertTrue(titles(fragment).isEmpty());
    }
}
