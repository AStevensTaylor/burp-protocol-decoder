package protocoldecoder;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.script.SandboxLimits;
import protocoldecoder.script.ScriptDecoder;
import protocoldecoder.script.ScriptDefinition;
import protocoldecoder.script.ScriptSandbox;
import protocoldecoder.script.ScriptTemplates;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class SandboxTest {

    static ScriptSandbox sandbox;
    static final SandboxLimits LIMITS = new SandboxLimits(200, 500, 1024 * 1024, 1000);

    @BeforeAll
    static void setUp() {
        sandbox = new ScriptSandbox();
    }

    @AfterAll
    static void tearDown() {
        sandbox.close();
    }

    static ScriptDecoder decoder(String src) {
        return new ScriptDecoder(new ScriptDefinition("t", "Test", "", src), sandbox, () -> LIMITS);
    }

    static MessageContext request(String body) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://example.com/api/rpc?x=1&y=two")
                .requestHeader("Content-Type", "application/json").requestBody(body).build();
    }

    @Test
    void templateWorks() {
        ScriptDecoder d = decoder(ScriptTemplates.DEFAULT);
        assertNull(d.compileError());
        MessageContext m = request("{\"method\":\"getUser\",\"params\":{\"id\":7}}");
        assertEquals(80, d.match(m).confidence());
        ScriptDecoder.Trace<DecodeResult> t = d.traceDecode(m);
        assertNull(t.error(), t.error());
        assertEquals("RPC call: getUser", t.value().summary());
        assertEquals("7", t.value().root().get("params").get("id").value());
        assertEquals(1, t.logs().size());
    }

    @Test
    void messageApi() {
        ScriptDecoder d = decoder("""
                function decode(msg) {
                  return { data: { kind: msg.kind, host: msg.host, path: msg.path, q: msg.queryParams.y,
                    ct: msg.header('content-type'), n: msg.headers.length, sc: msg.statusCode,
                    keys: Object.keys(msg).length } };
                }""");
        ScriptDecoder.Trace<DecodeResult> t = d.traceDecode(request("{}"));
        assertNull(t.error(), t.error());
        DecodeResult r = t.value();
        assertEquals("request", r.root().get("kind").value());
        assertEquals("example.com", r.root().get("host").value());
        assertEquals("/api/rpc", r.root().get("path").value());
        assertEquals("two", r.root().get("q").value());
        assertEquals("application/json", r.root().get("ct").value());
        assertEquals("null", r.root().get("sc").value());
    }

    @Test
    void codecHelpers() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
            gz.write("{\"hello\":\"wörld\"}".getBytes(StandardCharsets.UTF_8));
        }
        String b64 = Base64.getEncoder().encodeToString(bos.toByteArray());
        ScriptDecoder d = decoder("""
                function decode(msg) {
                  var o = JSON.parse(codec.utf8Decode(codec.gunzip(codec.base64Decode(msg.bodyText))));
                  var lj = codec.parseLenientJson("{a:'x', b:[1,2]}");
                  return { summary: o.hello, data: { lj: lj, hex: codec.hexEncode('AB'), q: codec.parseQuery('a=1&a=2') } };
                }""");
        ScriptDecoder.Trace<DecodeResult> t = d.traceDecode(request(b64));
        assertNull(t.error(), t.error());
        assertEquals("wörld", t.value().summary());
        assertEquals("x", t.value().root().get("lj").get("a").value());
        assertEquals("4142", t.value().root().get("hex").value());
        assertEquals(2, t.value().root().get("q").get("a").children().size());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "java.lang.System.exit(1)",
            "Packages.java.lang.Runtime.getRuntime()",
            "new JavaImporter(java.io)",
            "importPackage(java.io)",
            "msg.getClass().forName('java.lang.Runtime')",
            "''.getClass()",
            "codec.base64Decode.getClass()",
            "(function(){ return this })().java.lang.System",
            "this.constructor.constructor('return java')().lang",
            "Object.getPrototypeOf(codec).constructor.constructor('return Packages')().java",
            "codec.__proto__.__proto__.getClass()",
            "msg.headers.getClass()",
            "Java.type('java.lang.Runtime')",
    })
    void noJavaAccess(String expr) {
        ScriptDecoder d = decoder("function decode(msg) { var r = " + expr + "; return { data: { r: String(r) } }; }");
        ScriptDecoder.Trace<DecodeResult> t = d.traceDecode(request("{}"));
        // Either it throws, or it evaluates to something harmless (undefined) — never a Java object.
        if (t.error() == null) {
            String v = t.value().root().get("r").value();
            assertFalse(v.contains("java.") || v.contains("Runtime") || v.contains("class "), "leaked: " + v);
        }
    }

    @Test
    void infiniteLoopTimesOutEvenWithCatch() {
        ScriptDecoder d = decoder("function decode(msg) { try { while(true) {} } catch (e) {} finally { while(true){} } }");
        long start = System.currentTimeMillis();
        ScriptDecoder.Trace<DecodeResult> t = d.traceDecode(request("{}"));
        assertNotNull(t.error());
        assertTrue(t.error().contains("timed out"), t.error());
        assertTrue(System.currentTimeMillis() - start < 3000);
    }

    @Test
    void recursionIsBounded() {
        ScriptDecoder d = decoder("function f(n){ return f(n+1) + 1; } function decode(msg) { return f(0); }");
        ScriptDecoder.Trace<DecodeResult> t = d.traceDecode(request("{}"));
        assertNotNull(t.error());
    }

    @Test
    void outputSizeIsBounded() {
        ScriptDecoder d = decoder("function decode(msg) { var a = []; for (var i = 0; i < 5000; i++) a.push(i); return a; }");
        ScriptDecoder.Trace<DecodeResult> t = d.traceDecode(request("{}"));
        assertNotNull(t.error());
        assertTrue(t.error().contains("too many nodes"), t.error());
    }

    @Test
    void builtInsAreFrozenAcrossScripts() {
        ScriptDecoder evil = decoder("function decode(msg) { JSON.parse = function(){ return 'pwned' }; Array.prototype.x = 1; return 1; }");
        evil.traceDecode(request("{}"));
        ScriptDecoder good = decoder("function decode(msg) { return { data: { v: JSON.parse('{\"a\":1}').a, x: String([].x) } }; }");
        DecodeResult r = good.traceDecode(request("{}")).value();
        assertEquals("1", r.root().get("v").value());
        assertEquals("undefined", r.root().get("x").value());
    }

    @Test
    void globalsDoNotLeakBetweenCalls() {
        ScriptDecoder d = decoder("var counter = (typeof counter === 'undefined') ? 0 : counter; function decode(msg) { counter++; return counter; }");
        assertEquals("1", d.traceDecode(request("{}")).value().root().children().get(0).value());
        assertEquals("1", d.traceDecode(request("{}")).value().root().children().get(0).value());
    }

    @Test
    void matcherSuspendsAfterRepeatedFailures() {
        ScriptDecoder d = decoder("function match(msg) { throw new Error('boom'); } function decode(msg) { return 1; }");
        for (int i = 0; i < 5; i++) assertEquals(MatchResult.NONE, d.match(request("{}")));
        assertTrue(d.matcherSuspended());
        assertTrue(d.status().contains("boom"));
    }

    @Test
    void compileErrorsReportLine() {
        ScriptDecoder d = decoder("function decode(msg) {\n  return {;\n}");
        assertNotNull(d.compileError());
        assertTrue(d.compileError().matches(".*line [23].*"), d.compileError());
    }

    @Test
    void missingDecodeIsAnError() {
        assertNotNull(decoder("function match(m){return 1}").compileError());
    }

    @Test
    void thrownErrorMessageIsReported() {
        ScriptDecoder d = decoder("function decode(msg) { throw new Error('not my format'); }");
        assertTrue(d.traceDecode(request("{}")).error().contains("not my format"));
    }

    @Test
    void msgIsReadOnly() {
        ScriptDecoder d = decoder("function decode(msg) { msg.host = 'x'; return msg.host; }");
        assertEquals("example.com", d.traceDecode(request("{}")).value().root().children().get(0).value());
    }
}
