package protocoldecoder.builtin.batchexecute;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.InsertionPoint;
import protocoldecoder.scan.Severity;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static protocoldecoder.builtin.batchexecute.BatchExecuteDecoderTest.URL;
import static protocoldecoder.builtin.batchexecute.BatchExecuteDecoderTest.chunk;
import static protocoldecoder.builtin.batchexecute.BatchExecuteDecoderTest.enc;
import static protocoldecoder.builtin.batchexecute.BatchExecuteDecoderTest.envelope;
import static protocoldecoder.builtin.batchexecute.BatchExecuteDecoderTest.freq;
import static protocoldecoder.builtin.batchexecute.BatchExecuteDecoderTest.wrb;

class BatchExecuteScannerTest {

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });

    @AfterEach
    void close() {
        app.close();
    }

    static final String PAYLOAD = "x\"'] \\\" \\\\ }{ [\"]\" ünï 日本   & = + % \n end";

    /** Inner args: ["query", 5, "<json string: [\"nested\",[1,\"<json string: {\\\"deep\\\":\\\"v\\\"}>\"]]>", {"k":"v"}]. */
    static String innerArgs() {
        JsonObject deep = new JsonObject();
        deep.addProperty("deep", "v");
        JsonArray mid = new JsonArray();
        mid.add("nested");
        JsonArray pair = new JsonArray();
        pair.add(1);
        pair.add(deep.toString());
        mid.add(pair);
        JsonArray inner = new JsonArray();
        inner.add("query");
        inner.add(5);
        inner.add(mid.toString());
        JsonObject k = new JsonObject();
        k.addProperty("k", "v");
        inner.add(k);
        inner.add(JsonNull.INSTANCE);
        return inner.toString();
    }

    static String freqValue() {
        return freq(envelope("AbC12", innerArgs(), "generic"), envelope("XyZ34", "[\"other\"]", "generic"));
    }

    static MessageContext post(String body) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url(URL)
                .requestHeader("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8").requestHeader("Cookie", "SID=abc")
                .requestBody(body).build();
    }

    List<Finding> passive(MessageContext m, String id) {
        return app.scanEngine().passive(m, false).stream().filter(f -> f.checkId().equals(id)).toList();
    }

    static JsonArray innerOf(String freq, String rpc) {
        for (BatchExecuteDecoder.Envelope e : BatchExecuteDecoder.envelopes(freq)) {
            if (e.rpcId().equals(rpc)) return JsonTree.parseStrict(e.innerRaw()).getAsJsonArray();
        }
        throw new AssertionError("no envelope " + rpc);
    }

    // ================================================================ insertion points

    @Test
    void insertionPointsForEveryNestedLeaf() {
        String body = "f.req=" + enc(freqValue()) + "&at=" + enc("AJpMio2:1714560000000") + "&";
        List<InsertionPoint> ips = app.scanEngine().insertionPoints(post(body));
        List<String> names = ips.stream().map(InsertionPoint::name).toList();
        assertEquals(List.of(
                "batchexecute: AbC12 $[0]",
                "batchexecute: AbC12 $[1]",
                "batchexecute: AbC12 $[2] › $[0]",
                "batchexecute: AbC12 $[2] › $[1][0]",
                "batchexecute: AbC12 $[2] › $[1][1] › $.deep",
                "batchexecute: AbC12 $[3].k",
                "batchexecute: XyZ34 $[0]"), names);
        assertEquals("v", ips.get(4).baseValue());
        assertEquals("5", ips.get(1).baseValue());
    }

    @Test
    void deepLeafRoundTripsThroughThreeStringLevels() throws Exception {
        String at = "AJpMio2:1714560000000";
        String body = "f.req=" + enc(freqValue()) + "&at=" + enc(at) + "&";
        InsertionPoint ip = app.scanEngine().insertionPoints(post(body)).stream()
                .filter(i -> i.name().endsWith("› $.deep")).findFirst().orElseThrow();
        String newBody = new String(ip.render().apply(PAYLOAD), StandardCharsets.UTF_8);
        assertTrue(newBody.endsWith("&at=" + enc(at) + "&"), newBody);
        String f = Codecs.first(Codecs.parseQuery(newBody), "f.req");
        JsonArray inner = innerOf(f, "AbC12");
        JsonArray mid = JsonTree.parseStrict(inner.get(2).getAsString()).getAsJsonArray();
        JsonObject deep = JsonTree.parseStrict(mid.get(1).getAsJsonArray().get(1).getAsString()).getAsJsonObject();
        assertEquals(PAYLOAD, deep.get("deep").getAsString());
        // everything else unchanged, envelope shape preserved
        assertEquals("query", inner.get(0).getAsString());
        assertEquals(5, inner.get(1).getAsInt());
        assertEquals("nested", mid.get(0).getAsString());
        assertTrue(inner.get(4).isJsonNull());
        assertEquals("[\"other\"]", BatchExecuteDecoder.envelopes(f).get(1).innerRaw());
        JsonArray env = JsonTree.parseStrict(f).getAsJsonArray().get(0).getAsJsonArray().get(0).getAsJsonArray();
        assertTrue(env.get(2).isJsonNull());
        assertEquals("generic", env.get(3).getAsString());
        // the mutated request still decodes cleanly
        var r = new BatchExecuteDecoder().decode(post(newBody));
        assertEquals("batchexecute → 2 RPCs: AbC12, XyZ34 [DocsApp]", r.summary());
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
    }

    @Test
    void untouchedLeafRendersOriginalFreq() {
        String fv = freqValue();
        InsertionPoint ip = app.scanEngine().insertionPoints(post("f.req=" + enc(fv))).get(0);
        String f = Codecs.first(Codecs.parseQuery(new String(ip.render().apply("query"), StandardCharsets.UTF_8)), "f.req");
        assertEquals(fv, f);
    }

    @Test
    void fReqInQueryString() {
        String q = "rpcids=AbC12&f.req=" + enc(freq(envelope("AbC12", "[\"a\",\"[\\\"b\\\"]\"]", "1"))) + "&hl=en";
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://app.example.com/_/Svc/data/batchexecute?" + q).build();
        List<InsertionPoint> ips = app.scanEngine().insertionPoints(m);
        assertEquals(List.of("batchexecute: AbC12 $[0]", "batchexecute: AbC12 $[1] › $[0]"), ips.stream().map(InsertionPoint::name).toList());
        InsertionPoint ip = ips.get(1);
        assertEquals(InsertionPoint.Part.QUERY, ip.part());
        String newQ = new String(ip.render().apply(PAYLOAD), StandardCharsets.UTF_8);
        assertTrue(newQ.startsWith("rpcids=AbC12&f.req=") && newQ.endsWith("&hl=en"), newQ);
        JsonArray inner = innerOf(Codecs.first(Codecs.parseQuery(newQ), "f.req"), "AbC12");
        assertEquals(PAYLOAD, JsonTree.parseStrict(inner.get(1).getAsString()).getAsJsonArray().get(0).getAsString());
    }

    @Test
    void noInsertionPointsWithoutEnvelopes() {
        assertTrue(app.scanEngine().insertionPoints(post("f.req=" + enc("[[\"not an envelope\"]]"))).isEmpty());
        assertTrue(BatchExecuteScanner.leaves("garbage").isEmpty());
    }

    // ================================================================ passive

    static MessageContext resp(String reqBody, String respBody, String... reqHeaders) {
        MessageContext.Builder b = MessageContext.builder(MessageKind.RESPONSE).method("POST").url(URL)
                .requestHeader("Content-Type", "application/x-www-form-urlencoded");
        for (int i = 0; i + 1 < reqHeaders.length; i += 2) b.requestHeader(reqHeaders[i], reqHeaders[i + 1]);
        return b.requestBody(reqBody).statusCode(200).responseHeader("Content-Type", "application/json").responseBody(respBody).build();
    }

    static String errResponse(String detail) {
        JsonArray er = new JsonArray();
        er.add("er");
        er.add(JsonNull.INSTANCE);
        er.add(JsonNull.INSTANCE);
        er.add(detail);
        er.add(500);
        JsonArray b = new JsonArray();
        b.add(er);
        return ")]}'\n\n" + chunk(b.toString());
    }

    @Test
    void errorEntryWithStackTrace() {
        String body = "f.req=" + enc(freqValue());
        List<Finding> f = passive(resp(body, errResponse("java.lang.IllegalStateException: bad arg\n\tat com.acme.rpc.DocHandler.handle(DocHandler.java:42)")),
                "batchexecute.error-details");
        assertEquals(1, f.size());
        assertEquals(Severity.LOW, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("DocHandler"), f.get(0).detail());
        // plain error code: nothing
        assertTrue(passive(resp(body, errResponse("INVALID_ARGUMENT")), "batchexecute.error-details").isEmpty());
        // stack-trace-like text inside a successful payload is not an error entry
        JsonArray ok = new JsonArray();
        ok.add(wrb("AbC12", "[\"at com.acme.Foo.bar(Foo.java:1)\"]"));
        assertTrue(passive(resp(body, ")]}'\n\n" + chunk(ok.toString())), "batchexecute.error-details").isEmpty());
    }

    @Test
    void rpcInventoryPerHost() {
        List<Finding> f = passive(post("f.req=" + enc(freqValue())), "batchexecute.rpc-inventory");
        assertEquals(1, f.size());
        assertEquals(Finding.Scope.HOST, f.get(0).scope());
        assertEquals(Severity.INFORMATION, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("<code>AbC12</code>") && f.get(0).detail().contains("<code>XyZ34</code>"), f.get(0).detail());
        assertTrue(f.get(0).detail().contains("DocsApp"), f.get(0).detail());
        // ordinary form post: not batchexecute at all
        MessageContext other = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/login").requestBody("user=a&pass=b").build();
        assertTrue(passive(other, "batchexecute.rpc-inventory").isEmpty());
    }

    @Test
    void missingXsrfTokenOnSuccessfulCookiePost() {
        JsonArray ok = new JsonArray();
        ok.add(wrb("AbC12", "[[\"saved\"]]"));
        String okResp = ")]}'\n\n" + chunk(ok.toString());
        String noAt = "f.req=" + enc(freqValue());
        List<Finding> f = passive(resp(noAt, okResp, "Cookie", "SID=abc"), "batchexecute.missing-xsrf");
        assertEquals(1, f.size(), f.toString());
        assertEquals(Severity.INFORMATION, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("AbC12"), f.get(0).detail());
        // negatives: token present, X-Same-Domain present, no cookies, RPC failed
        assertTrue(passive(resp(noAt + "&at=tok", okResp, "Cookie", "SID=abc"), "batchexecute.missing-xsrf").isEmpty());
        assertTrue(passive(resp(noAt, okResp, "Cookie", "SID=abc", "X-Same-Domain", "1"), "batchexecute.missing-xsrf").isEmpty());
        assertTrue(passive(resp(noAt, okResp), "batchexecute.missing-xsrf").isEmpty());
        assertTrue(passive(resp(noAt, errResponse("PERMISSION_DENIED"), "Cookie", "SID=abc"), "batchexecute.missing-xsrf").isEmpty());
    }

    @Test
    void checksAreListed() {
        var ids = app.scanEngine().checks().stream().map(c -> c.id()).toList();
        for (String id : List.of("batchexecute.error-details", "batchexecute.rpc-inventory", "batchexecute.missing-xsrf", "batchexecute.insertion-points",
                "firebase.web-config", "firebase.rtdb-unauth-read", "firebase.firestore-unauth-read", "firebase.firestore-unauth-list",
                "firebase.insertion-points")) {
            assertTrue(ids.contains(id), id);
        }
        app.scanEngine().checks().stream().filter(c -> c.decoderId().equals("firebase") || c.decoderId().equals("batchexecute"))
                .forEach(c -> assertFalse(c.description().isBlank(), c.id()));
    }
}
