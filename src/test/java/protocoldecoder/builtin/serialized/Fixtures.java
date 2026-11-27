package protocoldecoder.builtin.serialized;

import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.util.TreeText;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;
import java.util.zip.GZIPOutputStream;

/** Message builders and benign fixtures for the serialized-object tests. Nothing here is ever deserialized. */
final class Fixtures {

    private Fixtures() {
    }

    static MessageContext request(String url, String body, String... headers) {
        MessageContext.Builder b = MessageContext.builder(MessageKind.REQUEST).method(body == null ? "GET" : "POST").url(url);
        for (int i = 0; i + 1 < headers.length; i += 2) b.requestHeader(headers[i], headers[i + 1]);
        if (body != null) b.requestBody(body);
        return b.build();
    }

    static MessageContext requestBytes(String url, byte[] body, String... headers) {
        MessageContext.Builder b = MessageContext.builder(MessageKind.REQUEST).method("POST").url(url);
        for (int i = 0; i + 1 < headers.length; i += 2) b.requestHeader(headers[i], headers[i + 1]);
        b.requestBody(body);
        return b.build();
    }

    static MessageContext response(byte[] body, String... headers) {
        MessageContext.Builder b = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://app.example.test/data")
                .statusCode(200);
        for (int i = 0; i + 1 < headers.length; i += 2) b.responseHeader(headers[i], headers[i + 1]);
        b.responseBody(body);
        return b.build();
    }

    static String text(DecodedNode n) {
        return TreeText.render(n);
    }

    static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }

    static byte[] hexBytes(String s) {
        return HexFormat.of().parseHex(s);
    }

    static byte[] gzip(byte[] b) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
                gz.write(b);
            }
            return bos.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Serializes benign test data with the JDK (serialization only; the tests never deserialize). */
    static byte[] javaSerialize(Object... objects) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
                for (Object o : objects) oos.writeObject(o);
            }
            return bos.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * Hand-built stream: one object of {@code className} with a single String field. Used to check name-based
     * flagging without needing the (absent) class.
     */
    static byte[] javaNamedObject(String className, String field, String value) {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            DataOutputStream o = new DataOutputStream(bos);
            o.writeShort(0xACED);
            o.writeShort(5);
            o.write(0x73); // TC_OBJECT
            o.write(0x72); // TC_CLASSDESC
            o.writeUTF(className);
            o.writeLong(0x1234L);
            o.write(0x02); // SC_SERIALIZABLE
            o.writeShort(1);
            o.write('L');
            o.writeUTF(field);
            o.write(0x74);
            o.writeUTF("Ljava/lang/String;");
            o.write(0x78); // end of class annotation
            o.write(0x70); // no superclass
            o.write(0x74);
            o.writeUTF(value);
            return bos.toByteArray();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // ------------------------------------------------------------------ .NET NRBF writer

    static final class Nrbf {
        final ByteBuffer buf = ByteBuffer.allocate(4096).order(ByteOrder.LITTLE_ENDIAN);

        Nrbf header() {
            buf.put((byte) 0).putInt(1).putInt(-1).putInt(1).putInt(0);
            return this;
        }

        Nrbf u8(int v) {
            buf.put((byte) v);
            return this;
        }

        Nrbf i32(int v) {
            buf.putInt(v);
            return this;
        }

        Nrbf lps(String s) {
            byte[] b = s.getBytes(StandardCharsets.UTF_8);
            int len = b.length;
            while (len >= 0x80) {
                buf.put((byte) ((len & 0x7f) | 0x80));
                len >>>= 7;
            }
            buf.put((byte) len);
            buf.put(b);
            return this;
        }

        Nrbf library(int id, String name) {
            return u8(12).i32(id).lps(name);
        }

        Nrbf string(int id, String s) {
            return u8(6).i32(id).lps(s);
        }

        Nrbf end() {
            return u8(11);
        }

        byte[] bytes() {
            byte[] out = new byte[buf.position()];
            buf.duplicate().flip().get(out);
            return out;
        }
    }

    /** A Test.Person (Name: string, Age: int, Next: Test.Person) instance followed by a string array. */
    static byte[] nrbfPerson() {
        Nrbf n = new Nrbf().header().library(2, "TestAssembly, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null");
        n.u8(5).i32(1).lps("Test.Person").i32(3).lps("Name").lps("Age").lps("Next")
                .u8(1).u8(0).u8(4) // String, Primitive, Class
                .u8(8)             // Age: Int32
                .lps("Test.Person").i32(2)
                .i32(2);           // library id
        n.string(3, "alice");
        n.i32(30);
        n.u8(10); // Next = null
        n.end();
        return n.bytes();
    }

    /** System class record with a string array, a member reference, nulls and a byte array. */
    static byte[] nrbfSystemClass(String className) {
        Nrbf n = new Nrbf().header();
        n.u8(4).i32(1).lps(className).i32(3).lps("Items").lps("Blob").lps("Count")
                .u8(6).u8(7).u8(0) // StringArray, PrimitiveArray, Primitive
                .u8(2)             // Blob: byte[]
                .u8(8);            // Count: Int32
        n.u8(9).i32(5); // Items → #5
        n.u8(9).i32(6); // Blob → #6
        n.i32(3);       // Count
        n.u8(17).i32(5).i32(4); // ArraySingleString #5 length 4
        n.string(7, "one");
        n.u8(9).i32(7);         // reference to "one"
        n.u8(13).u8(2);         // two nulls
        n.u8(15).i32(6).i32(3).u8(2).u8(0xCA).u8(0xFE).u8(0x01); // ArraySinglePrimitive bytes
        n.end();
        return n.bytes();
    }

    // ------------------------------------------------------------------ pickles (generated with CPython's pickle.dumps)

    /** pickle.dumps({'a': [1, 2], 'b': 'x'}, protocol=2) */
    static final byte[] PICKLE_DICT_P2 = hexBytes("80027d71002858010000006171015d7102284b014b026558010000006271035801000000787104752e");
    /** pickle.dumps(collections.OrderedDict(a=1), protocol=4) */
    static final byte[] PICKLE_ODICT_P4 = hexBytes("80049529000000000000008c0b636f6c6c656374696f6e73948c0b4f726465726564446963749493942952948c0161944b01732e");
    /** pickle.dumps(collections.OrderedDict(a=1), protocol=2) */
    static final byte[] PICKLE_ODICT_P2 = hexBytes("800263636f6c6c656374696f6e730a4f726465726564446963740a71002952710158010000006171024b01732e");
    /** pickle.dumps({'k': 'v'}, protocol=5) */
    static final byte[] PICKLE_DICT_P5 = hexBytes("8005950c000000000000007d948c016b948c017694732e");
    /** Protocol 2 pickle that only references the subprocess.Popen class (GLOBAL then STOP, no call). */
    static final byte[] PICKLE_GLOBAL_ONLY = ("\u0080\u0002csubprocess\nPopen\n.").getBytes(StandardCharsets.ISO_8859_1);

    // ------------------------------------------------------------------ Ruby Marshal (hand-built, format 4.8)

    /** Marshal.dump({"user" => "bob", :id => 5}) */
    static final byte[] RUBY_HASH = hexBytes("04087b074922097573657206" + "3a064554" + "492208626f62063b0054" + "3a076964690a");
    /** Marshal.dump(Account.new with @name = "bob") */
    static final byte[] RUBY_OBJECT = hexBytes("04086f3a0c4163636f756e74063a0a406e616d6522" + "08626f62");

    static byte[] rubyObject(String cls) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.write(4);
        b.write(8);
        b.write('o');
        b.write(':');
        byte[] name = cls.getBytes(StandardCharsets.UTF_8);
        b.write(name.length + 5);
        b.writeBytes(name);
        b.write(0); // no ivars
        return b.toByteArray();
    }

    // ------------------------------------------------------------------ PHP

    /** s:<len>:"..." with the byte length computed (handles the NUL-mangled property names). */
    static String phpStr(String s) {
        return "s:" + s.getBytes(StandardCharsets.UTF_8).length + ":\"" + s + "\";";
    }
}
