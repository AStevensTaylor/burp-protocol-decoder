package protocoldecoder.builtin.serialized;

import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;

import java.nio.charset.StandardCharsets;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;
import static protocoldecoder.builtin.serialized.Fixtures.*;

/** Locations, multiple findings, negatives, forced decodes and registration. */
class DetectionTest {

    final SerializedObjectDecoder decoder = new SerializedObjectDecoder();

    @Test
    void registeredInApp() {
        try (App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { })) {
            assertTrue(app.registry().byId("serialized").isPresent());
            assertEquals("Serialized objects", app.registry().byId("serialized").get().name());
        }
    }

    @Test
    void setCookieAndMultipleFindings() throws Exception {
        byte[] ser = javaNamedObject("com.example.Prefs", "theme", "dark");
        MessageContext m = response("ok".getBytes(),
                "Set-Cookie", "prefs=" + b64(ser) + "; Path=/; HttpOnly",
                "Set-Cookie", "cart=" + b64(PICKLE_DICT_P2) + "; Path=/",
                "Set-Cookie", "plain=hello-world");
        assertEquals(85, decoder.match(m).confidence());
        DecodeResult r = decoder.decode(m);
        assertTrue(r.summary().startsWith("2 serialized payloads: Java serialized object in set-cookie prefs"), r.summary());
        assertTrue(r.summary().contains("Python pickle in set-cookie cart"), r.summary());
        assertEquals(2, r.root().children().size());
        assertNotNull(r.root().get("set-cookie: prefs — Java serialized object"));
    }

    @Test
    void bearerTokenHeaderAndFormParam() throws Exception {
        byte[] ser = javaNamedObject("com.example.Token", "user", "bob");
        MessageContext m = request("https://app.example.test/api", "x=1&payload=" + java.net.URLEncoder.encode(b64(ser), StandardCharsets.UTF_8),
                "Content-Type", "application/x-www-form-urlencoded",
                "Authorization", "Bearer " + b64(ser));
        DecodeResult r = decoder.decode(m);
        // Same payload in a header and a form value: reported once, at the first location.
        assertEquals(1, r.root().children().size(), r.summary());
        assertTrue(r.summary().contains("param payload"), r.summary());

        MessageContext hdr = request("https://app.example.test/api", null, "Authorization", "Bearer " + b64(ser));
        assertTrue(decoder.decode(hdr).summary().contains("header Authorization"));
        MessageContext basic = request("https://app.example.test/api", null, "Authorization", "Basic " + b64(ser));
        assertFalse(decoder.match(basic).matched(), "Basic credentials are not scanned");
    }

    @Test
    void plusSignsSurviveQueryDecoding() throws Exception {
        // Raw (unencoded) '+' in a query value becomes ' ' after URL decoding; the sniffer puts it back.
        byte[] data = javaSerialize(new java.util.ArrayList<>(java.util.List.of("a".repeat(40), "ÿþý~~~")));
        String b64 = b64(data);
        MessageContext m = request("https://app.example.test/?v=" + b64.replace("/", "%2F").replace("=", "%3D"), null);
        DecodeResult r = decoder.decode(m);
        assertFalse(r.summary().contains("[partial]"), r.summary() + " " + b64);
    }

    @Test
    void negativesDoNotMatch() {
        Random rnd = new Random(1234);
        for (int i = 0; i < 200; i++) {
            byte[] junk = new byte[16 + rnd.nextInt(200)];
            rnd.nextBytes(junk);
            String v = b64(junk);
            MessageContext c = request("https://app.example.test/?id=" + java.net.URLEncoder.encode(v, StandardCharsets.UTF_8), null,
                    "Cookie", "sid=" + v);
            assertFalse(decoder.match(c).matched(), "random base64 must not match: " + v);
        }
        String json = "{\"user\":\"bob\",\"items\":[1,2,3],\"type\":\"basic\"}";
        assertFalse(decoder.match(response(json.getBytes(), "Content-Type", "application/json")).matched());
        assertFalse(decoder.match(request("https://app.example.test/api", json, "Content-Type", "application/json")).matched());
        String html = "<!DOCTYPE html><html><head><title>x</title></head><body><p type=\"System.String\">hi</p></body></html>";
        assertFalse(decoder.match(response(html.getBytes(), "Content-Type", "text/html")).matched());
        assertFalse(decoder.match(request("https://app.example.test/login", "user=bob&pass=secret123&remember=on",
                "Content-Type", "application/x-www-form-urlencoded")).matched());
        String jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assertFalse(decoder.match(request("https://app.example.test/", null, "Authorization", "Bearer " + jwt,
                "Cookie", "token=" + jwt)).matched());
        assertFalse(decoder.match(request("https://app.example.test/?hash=deadbeefcafebabe0011223344556677", null)).matched());
        byte[] png = {(byte) 0x89, 'P', 'N', 'G', 13, 10, 26, 10, 0, 0, 0, 13};
        assertFalse(decoder.match(response(png, "Content-Type", "image/png")).matched());
        assertFalse(decoder.match(response(new byte[0])).matched());
    }

    @Test
    void forcedDecodeOnGarbageThrows() {
        DecodeException e = assertThrows(DecodeException.class,
                () -> decoder.decode(request("https://app.example.test/?q=hello", "just some text", "Cookie", "a=b")));
        assertTrue(e.getMessage().startsWith("No serialized object found"), e.getMessage());
        assertTrue(e.getMessage().contains("body"), e.getMessage());

        byte[] junk = new byte[4096];
        new Random(5).nextBytes(junk);
        junk[0] = 0x13;
        assertThrows(DecodeException.class, () -> decoder.decode(response(junk)));
        assertThrows(DecodeException.class, () -> decoder.decode(response(new byte[0])));
    }

    @Test
    void magicPrefixesOnTheirOwnAreHandled() throws Exception {
        // Just the header bytes of each format: detected, decoded as partial, never thrown.
        byte[][] stubs = {
                {(byte) 0xAC, (byte) 0xED, 0, 5},
                {(byte) 0xAC, (byte) 0xED, 0, 5, 0x73},
                {(byte) 0x80, 4, (byte) 0x95},
                {4, 8, '['},
        };
        for (byte[] s : stubs) {
            MessageContext m = requestBytes("https://app.example.test/", s);
            if (decoder.match(m).matched()) assertDoesNotThrow(() -> decoder.decode(m));
        }
        DecodeResult r = decoder.decode(requestBytes("https://app.example.test/", new byte[]{(byte) 0xAC, (byte) 0xED, 0, 5, 0x73}));
        assertTrue(r.summary().contains("[partial]"), r.summary());
    }

    @Test
    void manyParametersAreCapped() throws Exception {
        StringBuilder q = new StringBuilder();
        for (int i = 0; i < 200; i++) q.append("p").append(i).append("=value").append(i).append('&');
        q.append("late=").append(java.net.URLEncoder.encode(b64(PICKLE_DICT_P2), StandardCharsets.UTF_8));
        MessageContext m = request("https://app.example.test/?" + q, null);
        assertFalse(decoder.match(m).matched(), "values beyond the cap are not examined");
        DecodeException e = assertThrows(DecodeException.class, () -> decoder.decode(m));
        assertTrue(e.getMessage().contains("skipped by limits"), e.getMessage());
    }
}
