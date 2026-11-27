package protocoldecoder.builtin.graphql;

import org.junit.jupiter.api.Test;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.util.TreeText;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TrpcDecoderTest {

    final TrpcDecoder trpc = new TrpcDecoder();
    final GraphQlDecoder gql = new GraphQlDecoder();

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    static MessageContext.Builder get(String url) {
        return MessageContext.builder(MessageKind.REQUEST).method("GET").url(url);
    }

    static MessageContext.Builder post(String url, String body) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url(url).requestHeader("Content-Type", "application/json").requestBody(body);
    }

    static MessageContext response(MessageContext.Builder req, String body) {
        return req.statusCode(200).responseHeader("Content-Type", "application/json").responseBody(body).build().withKind(MessageKind.RESPONSE);
    }

    @Test
    void procedureParsing() {
        assertEquals(List.of("user.byId", "post.list"), TrpcDecoder.procedures("/api/trpc/user.byId,post.list"));
        assertEquals(List.of("greeting"), TrpcDecoder.procedures("/trpc/greeting"));
        assertEquals(List.of("a", "b"), TrpcDecoder.procedures("/trpc/a%2Cb"));
        assertNull(TrpcDecoder.procedures("/api/users/1"));
        assertNull(TrpcDecoder.procedures("/trpc/"));
        assertNull(TrpcDecoder.procedures("/trpc/a/b"));
        assertNull(TrpcDecoder.procedures("/trpc/a b"));
    }

    @Test
    void batchGet() throws Exception {
        String input = "{\"0\":{\"json\":{\"id\":42}},\"1\":{\"json\":{\"limit\":10,\"since\":\"2024-01-01T00:00:00.000Z\"},\"meta\":{\"values\":{\"since\":[\"Date\"]}}}}";
        MessageContext m = get("https://app.example.com/api/trpc/user.byId,post.list?batch=1&input=" + enc(input)).build();
        assertEquals(92, trpc.match(m).confidence());
        DecodeResult r = trpc.decode(m);
        assertEquals("tRPC batch query: 2 calls (user.byId, post.list)", r.summary());
        DecodedNode calls = r.root().get("Calls");
        assertEquals("user.byId", calls.children().get(0).value());
        DecodedNode in0 = calls.children().get(0).get("Input (superjson)");
        assertEquals("42", in0.get("json").get("id").value());
        DecodedNode in1 = calls.children().get(1).get("Input (superjson)");
        assertEquals("since: Date", in1.get("Meta: special types").children().get(0).value());
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
        assertEquals(0, gql.match(m).confidence());
    }

    @Test
    void singleGetWithPlainInput() throws Exception {
        MessageContext m = get("https://app.example.com/trpc/greeting?input=" + enc("{\"name\":\"bob\"}")).build();
        assertEquals(85, trpc.match(m).confidence());
        DecodeResult r = trpc.decode(m);
        assertEquals("tRPC query greeting", r.summary());
        assertEquals("bob", r.root().get("Input").get("name").value());
    }

    @Test
    void batchPostMutation() throws Exception {
        MessageContext m = post("https://app.example.com/api/trpc/post.create,post.like?batch=1",
                "{\"0\":{\"json\":{\"title\":\"hi\"}},\"1\":{\"json\":{\"postId\":3}}}").build();
        assertEquals(90, trpc.match(m).confidence());
        DecodeResult r = trpc.decode(m);
        assertEquals("tRPC batch mutation: 2 calls (post.create, post.like)", r.summary());
    }

    @Test
    void singlePost() throws Exception {
        MessageContext m = post("https://app.example.com/api/trpc/auth.login", "{\"email\":\"a@b.c\"}").build();
        assertEquals(75, trpc.match(m).confidence());
        assertEquals("tRPC mutation auth.login", trpc.decode(m).summary());
    }

    @Test
    void batchResponseWithError() throws Exception {
        MessageContext.Builder req = get("https://app.example.com/api/trpc/user.byId,post.list?batch=1&input=" + enc("{\"0\":{},\"1\":{}}"));
        MessageContext m = response(req, "[{\"result\":{\"data\":{\"json\":{\"id\":42,\"name\":\"Ann\"}}}},"
                + "{\"error\":{\"json\":{\"message\":\"Not signed in\",\"code\":-32001,\"data\":{\"code\":\"UNAUTHORIZED\",\"httpStatus\":401,"
                + "\"path\":\"post.list\",\"stack\":\"Error: Not signed in\\n    at ...\"}}}}]");
        assertEquals(92, trpc.match(m).confidence());
        DecodeResult r = trpc.decode(m);
        assertEquals("tRPC batch response: 2 results, 1 error — UNAUTHORIZED: Not signed in", r.summary());
        DecodedNode results = r.root().get("Results");
        assertEquals("user.byId: ok", results.children().get(0).value());
        assertEquals("Ann", results.children().get(0).get("Data (superjson)").get("json").get("name").value());
        DecodedNode err = results.children().get(1).get("Error (superjson)");
        assertEquals("-32001 (UNAUTHORIZED)", err.get("JSON-RPC code").value());
        assertEquals("401", err.get("HTTP status").value());
        assertEquals("post.list", err.get("Procedure path").value());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("stack trace")), r.warnings().toString());
        assertEquals(0, gql.match(m).confidence());
    }

    @Test
    void singleResponses() throws Exception {
        MessageContext.Builder req = get("https://app.example.com/trpc/greeting?input=" + enc("{}"));
        MessageContext ok = response(req, "{\"result\":{\"data\":\"hello\"}}");
        assertEquals(88, trpc.match(ok).confidence());
        assertEquals("tRPC result greeting", trpc.decode(ok).summary());

        MessageContext.Builder req2 = get("https://app.example.com/trpc/greeting");
        MessageContext err = response(req2, "{\"error\":{\"message\":\"Input invalid\",\"code\":-32600,\"data\":{\"code\":\"BAD_REQUEST\",\"httpStatus\":400}}}");
        assertEquals(88, trpc.match(err).confidence());
        assertEquals("tRPC error greeting — BAD_REQUEST: Input invalid", trpc.decode(err).summary());

        MessageContext v9 = response(get("https://app.example.com/trpc/x"), "{\"id\":null,\"result\":{\"type\":\"data\",\"data\":{\"a\":1}}}");
        DecodeResult r9 = trpc.decode(v9);
        assertEquals("tRPC result x", r9.summary());
        assertEquals("data", r9.root().get("Result type").value());
    }

    @Test
    void superjsonMetaNested() throws Exception {
        String input = "{\"json\":{\"tags\":[\"a\"],\"user\":{\"born\":\"2000-01-01\"},\"big\":\"1\"},\"meta\":{\"values\":{\"tags\":[\"set\"],"
                + "\"user.born\":[\"Date\"],\"big\":[\"bigint\"]},\"referentialEqualities\":{}}}";
        DecodeResult r = trpc.decode(get("https://app.example.com/trpc/u.save?input=" + enc(input)).build());
        String text = TreeText.render(r.root());
        assertTrue(text.contains("tags: set"), text);
        assertTrue(text.contains("user.born: Date"), text);
        assertTrue(text.contains("big: bigint"), text);
        assertTrue(text.contains("referentialEqualities"), text);
    }

    @Test
    void negatives() {
        assertEquals(0, trpc.match(get("https://x.example.com/api/users?input=" + enc("{}")).build()).confidence());
        assertEquals(0, trpc.match(response(get("https://x.example.com/api/users"), "[{\"result\":{\"data\":1}}]")).confidence());
        assertEquals(0, trpc.match(response(get("https://x.example.com/trpc/a"), "{\"items\":[]}")).confidence());
        assertEquals(0, trpc.match(post("https://x.example.com/trpc/a", "not json").build()).confidence());
        assertEquals(45, trpc.match(get("https://x.example.com/trpc/a").build()).confidence());
        MessageContext wsMsg = MessageContext.builder(MessageKind.WEBSOCKET).url("wss://x.example.com/trpc/a")
                .webSocket("CLIENT_TO_SERVER", "{}".getBytes(StandardCharsets.UTF_8)).build();
        assertEquals(0, trpc.match(wsMsg).confidence());
    }

    @Test
    void forcedDecodeOnGarbage() {
        assertThrows(DecodeException.class, () -> trpc.decode(post("https://x.example.com/api", "{}").build()));
        assertThrows(DecodeException.class, () -> trpc.decode(response(get("https://x.example.com/trpc/a"), "<html>")));
        assertThrows(DecodeException.class, () -> trpc.decode(response(get("https://x.example.com/trpc/a"), "{\"items\":[]}")));
        assertThrows(DecodeException.class, () -> trpc.decode(response(get("https://x.example.com/trpc/a"), "")));
        assertThrows(DecodeException.class, () -> trpc.decode(MessageContext.builder(MessageKind.WEBSOCKET).url("wss://x/trpc/a")
                .webSocket("CLIENT_TO_SERVER", new byte[]{1}).build()));
    }

    @Test
    void invalidInputWarnsButDecodes() throws Exception {
        DecodeResult r = trpc.decode(get("https://x.example.com/trpc/a?input=%7Bbroken").build());
        assertFalse(r.warnings().isEmpty());
        assertEquals("{broken", r.root().get("Raw input").value());
    }
}
