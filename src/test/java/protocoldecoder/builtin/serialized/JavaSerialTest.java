package protocoldecoder.builtin.serialized;

import org.junit.jupiter.api.Test;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static protocoldecoder.builtin.serialized.Fixtures.*;

/** Java serialization: fixtures are produced with ObjectOutputStream over benign test classes; nothing is deserialized. */
class JavaSerialTest {

    final SerializedObjectDecoder decoder = new SerializedObjectDecoder();

    enum Color { RED, GREEN }

    static class Person implements Serializable {
        private static final long serialVersionUID = 42L;
        String name = "alice";
        int age = 30;
        boolean admin = true;
        double score = 1.5;
        char initial = 'A';
        long id = 1234567890123L;
        List<String> tags = new ArrayList<>(List.of("x", "y"));
        Map<String, Object> attrs = new HashMap<>(Map.of("k", "v"));
        Color favourite = Color.GREEN;
        int[] numbers = {1, 2, 3};
        byte[] blob = "hello".getBytes();
    }

    record Point(int x, int y) implements Serializable {
    }

    static class Inner implements Serializable {
        int v = 7;
    }

    /** writeObject that skips defaultWriteObject: its data does not match the declared fields. */
    static class Odd implements Serializable {
        String s = "x";

        private void writeObject(ObjectOutputStream o) throws IOException {
            o.writeInt(42);
            o.writeObject(new Inner());
        }
    }

    public static class Ext implements Externalizable {
        public Ext() {
        }

        @Override
        public void writeExternal(ObjectOutput out) throws IOException {
            out.writeUTF("hello");
            out.writeInt(3);
        }

        @Override
        public void readExternal(ObjectInput in) {
            throw new UnsupportedOperationException("tests never deserialize");
        }
    }

    static class Handler implements InvocationHandler, Serializable {
        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            return null;
        }
    }

    static class Nest implements Serializable {
        Nest next;
    }

    private DecodeResult decode(MessageContext m) throws Exception {
        assertTrue(decoder.match(m).matched(), "should match");
        return decoder.decode(m);
    }

    @Test
    void rawBodyIsParsedWithFieldsAndValues() throws Exception {
        byte[] data = javaSerialize(new Person());
        MessageContext m = response(data, "Content-Type", "application/x-java-serialized-object");
        MatchResult mr = decoder.match(m);
        assertEquals(90, mr.confidence());
        DecodeResult r = decoder.decode(m);
        String t = text(r.root());
        assertTrue(r.summary().startsWith("Java serialized object in body"), r.summary());
        assertTrue(t.contains(Person.class.getName()), t);
        assertTrue(t.contains("alice"));
        assertTrue(t.contains("age: 30"));
        assertTrue(t.contains("admin: true"));
        assertTrue(t.contains("'A'"));
        assertTrue(t.contains("1234567890123"));
        assertTrue(t.contains("java.util.ArrayList"));
        assertTrue(t.contains("java.util.HashMap"));
        assertTrue(t.contains(Color.class.getName() + ".GREEN"));
        assertTrue(t.contains("int[3]"));
        assertTrue(t.contains("68 65 6c 6c 6f"), "byte[] shown as hex");
        assertTrue(t.contains("serialVersionUID: \"0x000000000000002a"), t);
        assertTrue(t.contains("WRITE_METHOD"), "ArrayList/HashMap use writeObject");
        assertTrue(t.contains("tags: \"java.util.List\""), "field descriptors are named: " + t);
        assertFalse(r.summary().contains("[partial]"), r.summary());
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
    }

    @Test
    void recordsReferencesAndResets() throws Exception {
        String shared = "shared-string";
        byte[] data = javaSerialize(new Point(3, 4), new ArrayList<>(Arrays.asList(shared, shared)));
        DecodeResult r = decode(response(data));
        String t = text(r.root());
        assertTrue(t.contains(Point.class.getName()));
        assertTrue(t.contains("x: 3") && t.contains("y: 4"), t);
        assertTrue(t.contains("→ \\\"shared-string\\\""), "second occurrence is a TC_REFERENCE: " + t);
    }

    @Test
    void externalizableProxyAndReset() throws Exception {
        Object proxy = Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{Runnable.class}, new Handler());
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(new Ext());
            oos.reset();
            oos.writeObject(proxy);
        }
        DecodeResult r = decode(response(bos.toByteArray()));
        String t = text(r.root());
        assertTrue(t.contains("writeExternal data"), t);
        assertTrue(t.contains("reset"), t);
        assertTrue(t.contains("java.lang.Runnable"), t);
        assertTrue(t.contains("java.lang.reflect.Proxy"), t);
        assertTrue(t.contains(Handler.class.getName()), t);
        assertFalse(r.summary().contains("[partial]"), r.summary());
    }

    @Test
    void base64CookieWithRiskyClassIsFlagged() throws Exception {
        byte[] data = javaNamedObject("org.apache.commons.collections.functors.InvokerTransformer", "iMethodName", "toString");
        MessageContext m = request("https://app.example.test/home", null, "Cookie", "theme=dark; JSESSIONDATA=" + b64(data));
        assertEquals(85, decoder.match(m).confidence());
        DecodeResult r = decoder.decode(m);
        assertEquals("Java serialized object in cookie JSESSIONDATA — 1 class "
                + "(org.apache.commons.collections.functors.InvokerTransformer ⚠)", r.summary());
        assertTrue(r.warnings().stream().anyMatch(w -> w.startsWith("⚠ cookie: JSESSIONDATA") && w.contains("commons-collections")),
                r.warnings().toString());
        String t = text(r.root());
        assertTrue(t.contains("iMethodName: \"toString\""), t);
        assertTrue(t.contains("Location: \"cookie: JSESSIONDATA\""));
    }

    @Test
    void queryParameterAndHexAndGzip() throws Exception {
        byte[] data = javaSerialize(new Point(1, 2));
        String enc = java.net.URLEncoder.encode(b64(data), java.nio.charset.StandardCharsets.UTF_8);
        DecodeResult r = decode(request("https://app.example.test/view?viewData=" + enc, null));
        assertTrue(r.summary().startsWith("Java serialized object in param viewData"), r.summary());

        DecodeResult h = decode(request("https://app.example.test/x?state=" + hex(data), null));
        assertTrue(text(h.root()).contains("Encoding: \"hex\""));

        String gz = b64(gzip(data));
        assertTrue(gz.startsWith("H4sI"));
        MessageContext form = request("https://app.example.test/submit", "a=1&blob=" + java.net.URLEncoder.encode(gz, java.nio.charset.StandardCharsets.UTF_8),
                "Content-Type", "application/x-www-form-urlencoded");
        assertEquals(85, decoder.match(form).confidence());
        DecodeResult g = decoder.decode(form);
        String t = text(g.root());
        assertTrue(t.contains("Encoding: \"base64 → gzip\""), t);
        assertTrue(t.contains(Point.class.getName()));
        assertEquals(1, g.root().children().size(), "embedded-token duplicate of the form value is dropped");
    }

    @Test
    void rawGzipBodyAndContentEncoding() throws Exception {
        byte[] data = javaSerialize(new Point(5, 6));
        DecodeResult r = decode(response(gzip(data)));
        assertTrue(text(r.root()).contains("Encoding: \"gzip\""), text(r.root()));
        DecodeResult ce = decode(response(gzip(data), "Content-Encoding", "gzip"));
        assertTrue(text(ce.root()).contains("Encoding: \"raw\""), "Content-Encoding is undone before sniffing");
    }

    @Test
    void embeddedTokenInHtml() throws Exception {
        String html = "<html><body><form><input type=\"hidden\" name=\"javax.faces.ViewState\" value=\""
                + b64(gzip(javaSerialize(new Point(7, 8)))) + "\"/></form></body></html>";
        MessageContext m = response(html.getBytes(), "Content-Type", "text/html");
        assertEquals(75, decoder.match(m).confidence());
        DecodeResult r = decoder.decode(m);
        assertTrue(r.summary().startsWith("Java serialized object in body @"), r.summary());
    }

    @Test
    void truncatedStreamGivesPartialOutputAndScannedNames() throws Exception {
        byte[] data = javaSerialize(new Person());
        byte[] cut = Arrays.copyOf(data, data.length * 2 / 3);
        DecodeResult r = decode(response(cut));
        assertTrue(r.summary().endsWith("[partial]"), r.summary());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("Parsing stopped")), r.warnings().toString());
        String t = text(r.root());
        assertTrue(t.contains("Class names found by scanning"), t);
        assertTrue(t.contains(Person.class.getName()));
    }

    @Test
    void customWriteObjectStopsGracefully() throws Exception {
        DecodeResult r = decode(response(javaSerialize(new Odd())));
        String t = text(r.root());
        assertTrue(r.summary().contains("[partial]"), r.summary());
        assertTrue(t.contains("custom writeObject data"), t);
        assertTrue(t.contains(Inner.class.getName()), "fallback scan finds the class inside the custom data: " + t);
    }

    @Test
    void handBuiltExceptionRecord() throws Exception {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        java.io.DataOutputStream o = new java.io.DataOutputStream(bos);
        o.writeShort(0xACED);
        o.writeShort(5);
        o.write(0x7B); // TC_EXCEPTION
        o.write(0x73);
        o.write(0x72);
        o.writeUTF("java.lang.IllegalStateException");
        o.writeLong(1L);
        o.write(0x02);
        o.writeShort(0);
        o.write(0x78);
        o.write(0x70);
        DecodeResult r = decode(response(bos.toByteArray()));
        String t = text(r.root());
        assertTrue(t.contains("exception during serialization"), t);
        assertTrue(t.contains("java.lang.IllegalStateException"));
    }

    @Test
    void bigAndDeepStreamsAreBounded() throws Exception {
        List<Integer> many = new ArrayList<>();
        for (int i = 0; i < 30_000; i++) many.add(i);
        DecodeResult r = decode(response(javaSerialize(many)));
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("output limit")), r.warnings().toString());
        assertTrue(r.root().size() < 25_000);

        Nest head = new Nest();
        Nest cur = head;
        for (int i = 0; i < 300; i++) {
            cur.next = new Nest();
            cur = cur.next;
        }
        DecodeResult d = decode(response(javaSerialize(head)));
        assertTrue(d.warnings().stream().anyMatch(w -> w.contains("nesting deeper")), d.warnings().toString());
    }

    @Test
    void corruptStreamsNeverThrow() {
        byte[] data = javaSerialize(new Person(), new LinkedHashMap<>(Map.of("a", 1)));
        java.util.Random rnd = new java.util.Random(7);
        for (int i = 0; i < 300; i++) {
            byte[] copy = data.clone();
            for (int j = 0; j < 3; j++) copy[4 + rnd.nextInt(copy.length - 4)] = (byte) rnd.nextInt(256);
            MessageContext m = response(Arrays.copyOf(copy, 4 + rnd.nextInt(copy.length - 4)));
            assertDoesNotThrow(() -> decoder.match(m));
            assertDoesNotThrow(() -> decoder.decode(m));
        }
    }
}
