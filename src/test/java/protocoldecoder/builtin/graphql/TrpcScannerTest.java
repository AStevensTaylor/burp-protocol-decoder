package protocoldecoder.builtin.graphql;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.scan.Confidence;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.InsertionPoint;
import protocoldecoder.scan.Severity;
import protocoldecoder.util.Codecs;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TrpcScannerTest {

    static final String PAYLOAD = "x\"' OR \\1=1--\n<ü𝄞>&input=%00";

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });
    final TrpcDecoder trpc = new TrpcDecoder();

    @AfterEach
    void close() {
        app.close();
    }

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    static MessageContext get(String url) {
        return MessageContext.builder(MessageKind.REQUEST).method("GET").url(url).build();
    }

    static MessageContext response(String url, String body) {
        return MessageContext.builder(MessageKind.REQUEST).method("GET").url(url).statusCode(500)
                .responseHeader("Content-Type", "application/json").responseBody(body).build().withKind(MessageKind.RESPONSE);
    }

    List<InsertionPoint> points(MessageContext m) {
        return app.scanEngine().insertionPoints(m).stream().filter(i -> i.name().startsWith("tRPC:")).toList();
    }

    static InsertionPoint ip(List<InsertionPoint> ips, String name) {
        return ips.stream().filter(i -> i.name().equals(name)).findFirst()
                .orElseThrow(() -> new AssertionError(name + " not in " + ips.stream().map(InsertionPoint::name).toList()));
    }

    List<Finding> passive(MessageContext m, String checkId) {
        return app.scanEngine().passive(m, false).stream().filter(f -> f.checkId().equals(checkId)).toList();
    }

    static final String BATCH_INPUT = "{\"0\":{\"json\":{\"id\":\"42\",\"since\":\"2024-01-01T00:00:00.000Z\"},\"meta\":{\"values\":{\"since\":[\"Date\"]}}},"
            + "\"1\":{\"json\":{\"cursor\":null,\"tags\":[\"a\",\"b\"],\"limit\":10}}}";

    @Test
    void batchGetWithSuperjsonRoundTrip() throws Exception {
        MessageContext m = get("https://app.example.com/api/trpc/user.byId,post.list?batch=1&input=" + enc(BATCH_INPUT));
        List<InsertionPoint> ips = points(m);
        assertEquals(List.of("tRPC: [0] user.byId input.id", "tRPC: [0] user.byId input.since", "tRPC: [1] post.list input.tags[0]",
                "tRPC: [1] post.list input.tags[1]", "tRPC: [1] post.list input.limit"), ips.stream().map(InsertionPoint::name).toList());
        InsertionPoint id = ip(ips, "tRPC: [0] user.byId input.id");
        assertEquals(InsertionPoint.Part.QUERY, id.part());
        assertEquals("42", id.baseValue());

        String qs = new String(id.render().apply(PAYLOAD), StandardCharsets.ISO_8859_1);
        assertTrue(qs.chars().allMatch(c -> c < 128 && c != ' '), qs);
        assertTrue(qs.startsWith("batch=1&input="), qs);
        JsonObject input = JsonParser.parseString(Codecs.first(Codecs.parseQuery(qs), "input")).getAsJsonObject();
        assertEquals(PAYLOAD, input.getAsJsonObject("0").getAsJsonObject("json").get("id").getAsString());
        assertEquals("{\"values\":{\"since\":[\"Date\"]}}", input.getAsJsonObject("0").get("meta").toString(), "superjson meta untouched");
        assertEquals(JsonParser.parseString(BATCH_INPUT).getAsJsonObject().get("1"), input.get("1"), "other calls untouched");

        DecodeResult r = trpc.decode(get("https://app.example.com/api/trpc/user.byId,post.list?" + qs));
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
        assertEquals(PAYLOAD, r.root().get("Calls").children().get(0).get("Input (superjson)").get("json").get("id").value());
    }

    @Test
    void singleCallPlainAndPrimitiveInput() {
        List<InsertionPoint> plain = points(get("https://app.example.com/trpc/greeting?input=" + enc("{\"name\":\"bob\",\"opts\":{\"loud\":true}}")));
        InsertionPoint name = ip(plain, "tRPC: greeting input.name");
        ip(plain, "tRPC: greeting input.opts.loud");
        String input = Codecs.first(Codecs.parseQuery(new String(name.render().apply(PAYLOAD), StandardCharsets.ISO_8859_1)), "input");
        assertEquals(PAYLOAD, JsonParser.parseString(input).getAsJsonObject().get("name").getAsString());

        List<InsertionPoint> prim = points(get("https://app.example.com/trpc/post.bySlug?input=" + enc("{\"json\":\"hello-world\"}")));
        InsertionPoint slug = ip(prim, "tRPC: post.bySlug input");
        assertEquals("hello-world", slug.baseValue());
        String in2 = Codecs.first(Codecs.parseQuery(new String(slug.render().apply(PAYLOAD), StandardCharsets.ISO_8859_1)), "input");
        assertEquals(PAYLOAD, JsonParser.parseString(in2).getAsJsonObject().get("json").getAsString());
    }

    @Test
    void noPointsForPostBodiesOrNonTrpc() {
        MessageContext post = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/trpc/user.update")
                .requestHeader("Content-Type", "application/json").requestBody("{\"id\":1,\"name\":\"x\"}").build();
        assertTrue(points(post).isEmpty());
        assertTrue(new TrpcScanner().insertionPoints(get("https://app.example.com/api/users?input=%7B%22a%22%3A1%7D"), null).isEmpty());
    }

    @Test
    void stackTracePassive() {
        String body = "[{\"error\":{\"json\":{\"message\":\"boom\",\"code\":-32603,\"data\":{\"code\":\"INTERNAL_SERVER_ERROR\",\"httpStatus\":500,"
                + "\"stack\":\"TRPCError: boom\\n    at resolver (/app/src/server/routers/user.ts:14:11)\",\"path\":\"user.byId\"}}}}]";
        Finding f = passive(response("https://app.example.com/api/trpc/user.byId?batch=1&input=%7B%7D", body), "trpc.stack-trace").get(0);
        assertEquals(Severity.LOW, f.severity());
        assertEquals(Finding.Scope.HOST, f.scope());
        assertTrue(f.detail().contains("user.byId"), f.detail());
        String clean = "{\"error\":{\"message\":\"Not found\",\"code\":-32004,\"data\":{\"code\":\"NOT_FOUND\",\"httpStatus\":404,\"path\":\"user.byId\"}}}";
        assertTrue(passive(response("https://app.example.com/trpc/user.byId?input=%7B%7D", clean), "trpc.stack-trace").isEmpty());
    }

    @Test
    void internalErrorDetailsPassive() {
        String prisma = "{\"error\":{\"message\":\"\\nInvalid `prisma.user.findUnique()` invocation:\\n\\nThe column `User.email2` does not exist in the current database.\","
                + "\"code\":-32603,\"data\":{\"code\":\"INTERNAL_SERVER_ERROR\",\"httpStatus\":500,\"path\":\"user.byId\"}}}";
        Finding f = passive(response("https://app.example.com/trpc/user.byId?input=%7B%7D", prisma), "trpc.internal-error-details").get(0);
        assertEquals(Confidence.TENTATIVE, f.confidence());
        assertTrue(f.detail().contains("prisma.user.findUnique"), f.detail());
        String generic = "{\"error\":{\"message\":\"Internal server error\",\"code\":-32603,\"data\":{\"code\":\"INTERNAL_SERVER_ERROR\",\"httpStatus\":500}}}";
        assertTrue(passive(response("https://app.example.com/trpc/user.byId?input=%7B%7D", generic), "trpc.internal-error-details").isEmpty());
        String validation = "{\"error\":{\"message\":\"[{\\\"code\\\":\\\"too_small\\\",\\\"path\\\":[\\\"name\\\"]}]\",\"code\":-32600,"
                + "\"data\":{\"code\":\"BAD_REQUEST\",\"httpStatus\":400}}}";
        assertTrue(passive(response("https://app.example.com/trpc/user.byId?input=%7B%7D", validation), "trpc.internal-error-details").isEmpty());
    }

    @Test
    void checksAreListed() {
        List<String> ids = app.scanEngine().checks().stream().map(c -> c.id()).toList();
        assertTrue(ids.containsAll(List.of("trpc.stack-trace", "trpc.internal-error-details", "trpc.insertion-points")), ids.toString());
    }
}
