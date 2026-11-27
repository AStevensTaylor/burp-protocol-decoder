package protocoldecoder.builtin.nextjs;

import org.junit.jupiter.api.Test;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.util.TreeText;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class NextJsDecoderTest {

    final NextJsDecoder next = new NextJsDecoder();

    static final String ACTION_ID = "7f3a9c0e1d2b4a5f6e7d8c9b0a1f2e3d4c5b6a79";
    static final String TREE = "[\"\",{\"children\":[\"dashboard\",{\"children\":[[\"id\",\"42\",\"d\"],{\"children\":[\"__PAGE__\",{}]}]}]},null,null,true]";

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }

    static String find(DecodedNode n, String nameContains) {
        if (n.name().contains(nameContains) && n.value() != null) return n.value();
        for (DecodedNode c : n.children()) {
            String v = find(c, nameContains);
            if (v != null) return v;
        }
        return null;
    }

    static DecodedNode findNode(DecodedNode n, String nameContains) {
        if (n.name().contains(nameContains)) return n;
        for (DecodedNode c : n.children()) {
            DecodedNode v = findNode(c, nameContains);
            if (v != null) return v;
        }
        return null;
    }

    static String textRow(String id, String text) {
        return id + ":T" + Integer.toHexString(text.getBytes(StandardCharsets.UTF_8).length) + "," + text;
    }

    static final String FLIGHT = "1:HL[\"/_next/static/css/app/layout.css?v=1\",\"style\"]\n"
            + "2:I[\"7600\",[\"7600\",\"static/chunks/app/page-abc.js\"],\"Counter\"]\n"
            + "0:[\"dev-build-1\",[[\"children\",\"__PAGE__\",[\"__PAGE__\",{}],[\"__PAGE__\",{},[[\"$L3\",[\"$\",\"div\",null,{\"children\":[\"$\",\"$L2\",null,{\"initial\":5}]}]]],null],null]]]\n"
            + "3:[[\"$\",\"meta\",\"0\",{\"name\":\"viewport\",\"content\":\"width=device-width\"}],\"$4\"]\n"
            + textRow("4", "<p>Grüße – ünïcode 😀</p>")
            + "5:E{\"digest\":\"2365098129\",\"message\":\"An error occurred in the Server Components render.\"}\n"
            + "6:{\"id\":\"" + ACTION_ID + "\",\"bound\":null}\n";

    static MessageContext rscResponse(String body) {
        return MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://app.example.com/dashboard/42?_rsc=1x2y3")
                .requestHeader("RSC", "1").requestHeader("Next-Router-State-Tree", enc(TREE))
                .statusCode(200).responseHeader("Content-Type", "text/x-component").responseBody(body).build();
    }

    // ------------------------------------------------------------------ Flight responses

    @Test
    void flightResponseParsesRowsAndSummarises() throws Exception {
        MessageContext m = rscResponse(FLIGHT);
        assertEquals(95, next.match(m).confidence());
        DecodeResult r = next.decode(m);
        assertEquals("RSC payload: 7 rows, 1 client module, 1 hint, 1 text chunk, 1 server reference, 1 ERROR (digest 2365098129), build dev-build-1",
                r.summary());
        DecodedNode root = r.root();
        assertEquals("Counter @ 7600", root.get("Client modules (I rows)").children().get(0).value());
        assertEquals("2365098129", find(root.get("Errors (E rows)"), "Digest"));
        assertEquals(ACTION_ID, root.get("Server references (Server Action IDs)").children().get(0).value());
        assertEquals("<p>Grüße – ünïcode 😀</p>", find(root.get("Rows"), "row 4 (text chunk)"));
        // the row after the length-prefixed text (no newline) still parses
        assertNotNull(findNode(root.get("Rows"), "row 5 (error)"));
        // client component element resolved through the I row
        assertNotNull(findNode(root, "<Counter>"), TreeText.render(root));
        String text = TreeText.render(root);
        assertTrue(text.contains("$L3  (lazy → row 3"), text);
        assertTrue(text.contains("$4  (reference → row 4 (text chunk))"), text);
        assertEquals("dev-build-1", find(root.get("Overview"), "Build ID"));
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("server error row")), r.warnings().toString());
        assertTrue(r.root().get("Next.js response headers") == null || r.root().get("Next.js response headers").isLeaf());
    }

    @Test
    void flightResponseWithoutContentTypeButRscRequest() throws Exception {
        String body = "0:{\"P\":null,\"b\":\"Xb1_buildid\",\"p\":\"\",\"c\":[\"\",\"about\"],\"i\":false,\"f\":[[[\"\",{}],null]],\"m\":\"$undefined\"}\n";
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://app.example.com/about")
                .requestHeader("RSC", "1").statusCode(200).responseBody(body).build();
        assertEquals(90, next.match(m).confidence());
        DecodeResult r = next.decode(m);
        assertEquals("RSC payload: 1 row, build Xb1_buildid", r.summary());
        assertEquals("/about", find(r.root(), "Canonical URL"));
        assertTrue(TreeText.render(r.root()).contains("$undefined  (undefined)"));
    }

    @Test
    void gzippedFlightResponse() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
            gz.write(FLIGHT.getBytes(StandardCharsets.UTF_8));
        }
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://app.example.com/x")
                .statusCode(200).responseHeader("Content-Type", "text/x-component").responseHeader("Content-Encoding", "gzip")
                .responseBody(bos.toByteArray()).build();
        assertTrue(next.decode(m).summary().startsWith("RSC payload: 7 rows"));
    }

    @Test
    void truncatedTextRowIsReportedNotThrown() throws Exception {
        MessageContext m = rscResponse("0:\"$1\"\n1:Tffff,short");
        DecodeResult r = next.decode(m);
        assertTrue(r.summary().startsWith("RSC payload: 2 rows"), r.summary());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("declares 65535 bytes")), r.warnings().toString());
    }

    @Test
    void serverActionResponse() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("POST").url("https://app.example.com/cart")
                .requestHeader("Next-Action", ACTION_ID).requestHeader("Content-Type", "text/plain;charset=UTF-8").requestBody("[]")
                .statusCode(200).responseHeader("Content-Type", "text/x-component")
                .responseHeader("x-action-revalidated", "[[],1,0]")
                .responseBody("0:{\"a\":\"$@1\",\"f\":\"\",\"b\":\"abc\"}\n1:{\"ok\":true,\"sessionToken\":\"s3cr3t\"}\n").build();
        DecodeResult r = next.decode(m);
        assertEquals("Server Action response: 2 rows, build abc", r.summary());
        assertEquals("$@1", find(r.root(), "Server Action result"));
        assertNotNull(r.root().get("Next.js response headers").get("x-action-revalidated — [tags, paths revalidated, cookies changed]"));
        assertTrue(TreeText.render(r.root()).contains("row 1.sessionToken = s3cr3t"));
    }

    // ------------------------------------------------------------------ requests

    @Test
    void rscNavigationRequestWithRouterStateTree() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://app.example.com/settings?_rsc=abc12")
                .requestHeader("RSC", "1").requestHeader("Next-Router-State-Tree", enc(TREE))
                .requestHeader("Next-Url", "/dashboard/42").build();
        assertEquals(90, next.match(m).confidence());
        DecodeResult r = next.decode(m);
        assertEquals("RSC navigation → /settings (client at /dashboard/[id=42])", r.summary());
        DecodedNode tree = r.root().get("Next.js request headers").get("Next-Router-State-Tree — client router state");
        assertEquals("/dashboard/[id=42]", tree.get("Current route").value());
        assertEquals("d (dynamic [param])", find(tree, "Param type"));
        assertEquals("true", find(tree, "Is root layout"));
        assertEquals("abc12", find(r.root(), "_rsc"));
        assertEquals("/dashboard/42", find(r.root(), "Next-Url"));
    }

    @Test
    void prefetchViaRscQueryOnly() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://app.example.com/blog?_rsc=zz9")
                .requestHeader("Next-Router-Prefetch", "1").build();
        assertEquals(70, next.match(m).confidence());
        assertEquals("RSC prefetch → /blog", next.decode(m).summary());
    }

    @Test
    void serverActionJsonArgs() throws Exception {
        String body = "[\"hello\",{\"qty\":2,\"apiToken\":\"abc\"},\"$undefined\",\"$D2024-01-01T00:00:00.000Z\"]";
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/cart")
                .requestHeader("Next-Action", ACTION_ID).requestHeader("Content-Type", "text/plain;charset=UTF-8")
                .requestHeader("Next-Router-State-Tree", enc("[\"\",{\"children\":[\"cart\",{\"children\":[\"__PAGE__\",{}]}]},null,null,true]"))
                .requestBody(body).build();
        assertEquals(95, next.match(m).confidence());
        DecodeResult r = next.decode(m);
        assertEquals("Server Action " + ACTION_ID + " (4 args) → /cart", r.summary());
        assertEquals(ACTION_ID, find(r.root(), "Next-Action — Server Action ID"));
        assertEquals("/cart", find(r.root(), "Client route"));
        DecodedNode args = r.root().get("Arguments (4)");
        assertEquals("hello", args.get("arg 0").value());
        assertEquals("$D2024-01-01T00:00:00.000Z  (Date 2024-01-01T00:00:00.000Z)", args.get("arg 3").value());
        assertTrue(TreeText.render(r.root()).contains("args[1].apiToken = abc"));
    }

    @Test
    void serverActionMultipartFormData() throws Exception {
        String b = "----WebKitFormBoundaryX1";
        String body = "--" + b + "\r\nContent-Disposition: form-data; name=\"1_email\"\r\n\r\nbob@example.com\r\n"
                + "--" + b + "\r\nContent-Disposition: form-data; name=\"1_avatar\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nhi\r\n"
                + "--" + b + "\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n[\"$K1\"]\r\n"
                + "--" + b + "--\r\n";
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/signup")
                .requestHeader("Next-Action", ACTION_ID).requestHeader("Content-Type", "multipart/form-data; boundary=" + b)
                .requestBody(body).build();
        DecodeResult r = next.decode(m);
        assertEquals("Server Action " + ACTION_ID + " (1 arg) → /signup", r.summary());
        DecodedNode form = r.root().get("Multipart fields (encodeReply / FormData)");
        assertEquals("bob@example.com", form.get("1_email — FormData $K1 field \"email\"").value());
        assertEquals("a.txt", find(form, "Filename"));
        assertTrue(TreeText.render(form).contains("$K1  (FormData → row 1)"), TreeText.render(form));
    }

    @Test
    void progressiveEnhancementActionWithoutHeader() throws Exception {
        String b = "XyZ";
        String body = "--" + b + "\r\nContent-Disposition: form-data; name=\"$ACTION_ID_" + ACTION_ID + "\"\r\n\r\n\r\n"
                + "--" + b + "\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nhunter2\r\n--" + b + "--\r\n";
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/login")
                .requestHeader("Content-Type", "multipart/form-data; boundary=" + b).requestBody(body).build();
        assertEquals(85, next.match(m).confidence());
        DecodeResult r = next.decode(m);
        assertEquals("Server Action " + ACTION_ID + " (1 form field) → /login", r.summary());
        assertTrue(TreeText.render(r.root()).contains("password = hunter2"));
    }

    @Test
    void middlewareSubrequestIsFlagged() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://app.example.com/admin")
                .requestHeader("x-middleware-subrequest", "middleware:middleware:middleware:middleware:middleware").build();
        assertEquals(60, next.match(m).confidence());
        DecodeResult r = next.decode(m);
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("CVE-2025-29927")), r.warnings().toString());
    }

    @Test
    void nextDataRequestFromPath() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("GET")
                .url("https://shop.example.com/_next/data/abc123/products/index.json?slug=shoes").requestHeader("x-nextjs-data", "1").build();
        assertEquals(85, next.match(m).confidence());
        DecodeResult r = next.decode(m);
        assertEquals("Pages Router data request → /products (build abc123)", r.summary());
        assertEquals("shoes", find(r.root(), "slug"));
    }

    // ------------------------------------------------------------------ Pages Router data / HTML

    @Test
    void nextDataJsonResponse() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("GET")
                .url("https://shop.example.com/_next/data/abc123/blog/hello.json").statusCode(200)
                .responseHeader("Content-Type", "application/json")
                .responseBody("{\"pageProps\":{\"post\":{\"title\":\"Hello\",\"authorEmail\":\"a@b.c\"}},\"__N_SSP\":true}").build();
        assertEquals(90, next.match(m).confidence());
        DecodeResult r = next.decode(m);
        assertEquals("Next.js data (getServerSideProps) → /blog/hello (build abc123), 1 interesting key(s)", r.summary());
        assertEquals("Hello", find(r.root(), "title"));
    }

    @Test
    void pagesRouterNextDataInHtml() throws Exception {
        String data = "{\"props\":{\"pageProps\":{\"user\":{\"id\":7,\"email\":\"alice@example.com\",\"isAdmin\":true},\"author\":\"x\"},\"__N_SSP\":true},"
                + "\"page\":\"/blog/[slug]\",\"query\":{\"slug\":\"hello\"},\"buildId\":\"Zk3_9xq\",\"runtimeConfig\":{\"stripeKey\":\"pk_live_1\"},"
                + "\"isFallback\":false,\"gssp\":true,\"scriptLoader\":[]}";
        String html = "<!DOCTYPE html><html><head><script src=\"/_next/static/chunks/main.js\"></script></head><body><div id=\"__next\"></div>"
                + "<script id=\"__NEXT_DATA__\" type=\"application/json\">" + data + "</script></body></html>";
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://www.example.com/blog/hello")
                .statusCode(200).responseHeader("Content-Type", "text/html; charset=utf-8").responseHeader("X-Powered-By", "Next.js")
                .responseBody(html).build();
        assertEquals(50, next.match(m).confidence());
        DecodeResult r = next.decode(m);
        assertEquals("Pages Router page /blog/[slug] (getServerSideProps, build Zk3_9xq), 3 interesting key(s)", r.summary());
        DecodedNode nd = r.root().get("__NEXT_DATA__ (Pages Router)");
        assertEquals("hello", find(nd, "slug"));
        String interesting = TreeText.render(r.root().get("Interesting keys (possible secrets / PII / authz data)"));
        assertTrue(interesting.contains("props.pageProps.user.email = alice@example.com"), interesting);
        assertTrue(interesting.contains("runtimeConfig.stripeKey = pk_live_1"), interesting);
        assertFalse(interesting.contains("author"), interesting);
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("publicRuntimeConfig exposes 1")), r.warnings().toString());
        assertEquals("Next.js", find(r.root(), "x-powered-by"));
    }

    @Test
    void appRouterInlineNextF() throws Exception {
        String html = "<html><body><script>(self.__next_f=self.__next_f||[]).push([0])</script>"
                + "<script>self.__next_f.push([1,\"1:I[\\\"123\\\",[\\\"static/chunks/nav.js\\\"],\\\"Nav\\\"]\\n\"])</script>"
                + "<script>self.__next_f.push([1,\"0:[\\\"$\\\",\\\"$L1\\\",null,{\\\"title\\\":\\\"\\u003cb\\u003eHi\\\"}]\\n\"])</script>"
                + "</body></html>";
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://www.example.com/")
                .statusCode(200).responseHeader("Content-Type", "text/html").responseBody(html).build();
        assertEquals(50, next.match(m).confidence());
        DecodeResult r = next.decode(m);
        assertEquals("App Router page, inline RSC: 2 rows, 1 client module", r.summary());
        DecodedNode fn = r.root().get("self.__next_f (App Router inline RSC payload)");
        assertEquals("3", fn.get("push() calls").value());
        assertNotNull(findNode(fn, "<Nav>"), TreeText.render(fn));
        assertEquals("<b>Hi", find(fn, "title"));
        assertNull(r.root().get("Interesting keys (possible secrets / PII / authz data)"), "ARIA role prop is not flagged");
    }

    @Test
    void responseHeadersOnly() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://www.example.com/api/x")
                .statusCode(200).responseHeader("Content-Type", "application/json").responseHeader("x-nextjs-cache", "HIT")
                .responseHeader("x-nextjs-matched-path", "/blog/[slug]").responseBody("{\"a\":1}").build();
        assertEquals(40, next.match(m).confidence());
        DecodeResult r = next.decode(m);
        assertEquals("Next.js response (cache HIT, matched /blog/[slug])", r.summary());
    }

    @Test
    void hmrWebSocket() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("wss://localhost:3000/_next/webpack-hmr")
                .webSocket("SERVER_TO_CLIENT", "{\"action\":\"built\",\"hash\":\"abc\"}".getBytes(StandardCharsets.UTF_8)).build();
        assertEquals(85, next.match(m).confidence());
        assertEquals("Next.js dev HMR: built", next.decode(m).summary());
    }

    // ------------------------------------------------------------------ negatives & forced decodes

    @Test
    void doesNotMatchOrdinaryTraffic() {
        MessageContext req = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://api.example.com/v1/orders")
                .requestHeader("Content-Type", "application/json").requestBody("[1,2,3]").build();
        assertEquals(0, next.match(req).confidence());
        MessageContext html = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://www.example.com/")
                .statusCode(200).responseHeader("Content-Type", "text/html").responseBody("<html><script>var x = {a:1};</script></html>").build();
        assertEquals(0, next.match(html).confidence());
        MessageContext json = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://www.example.com/api")
                .statusCode(200).responseHeader("Content-Type", "application/json").responseBody("{\"pageProps\":1}").build();
        assertEquals(0, next.match(json).confidence());
        MessageContext ws = MessageContext.builder(MessageKind.WEBSOCKET).url("wss://x.example.com/socket")
                .webSocket("CLIENT_TO_SERVER", new byte[]{1, 2}).build();
        assertEquals(0, next.match(ws).confidence());
    }

    @Test
    void forcedDecodeOnGarbageThrows() {
        byte[] junk = new byte[512];
        new java.util.Random(7).nextBytes(junk);
        MessageContext req = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://x.example.com/upload").requestBody(junk).build();
        assertThrows(DecodeException.class, () -> next.decode(req));
        MessageContext resp = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://x.example.com/")
                .statusCode(200).responseBody(junk).build();
        assertThrows(DecodeException.class, () -> next.decode(resp));
        MessageContext fakeFlight = rscResponse("hello world\nthis is not flight\n");
        DecodeException e = assertThrows(DecodeException.class, () -> next.decode(fakeFlight));
        assertTrue(e.getMessage().contains("Flight"), e.getMessage());
        MessageContext ws = MessageContext.builder(MessageKind.WEBSOCKET).url("wss://x.example.com/").webSocket("CLIENT_TO_SERVER", junk).build();
        assertThrows(DecodeException.class, () -> next.decode(ws));
        assertDoesNotThrow(() -> next.match(fakeFlight));
    }

    @Test
    void largeAndHostileInputsStayBounded() throws Exception {
        StringBuilder sb = new StringBuilder("fffff:" + "[".repeat(5000) + "]".repeat(5000) + "\n");
        for (int i = 0; i < 30_000; i++) sb.append(Integer.toHexString(i)).append(":[\"$\",\"div\",null,{\"children\":\"$L").append(Integer.toHexString(i + 1)).append("\"}]\n");
        MessageContext m = rscResponse(sb.toString());
        DecodeResult r = next.decode(m);
        assertTrue(r.summary().startsWith("RSC payload: " + Flight.MAX_ROWS + " rows"), r.summary());
        assertTrue(r.root().size() < Flight.MAX_NODES + 5_000, "nodes: " + r.root().size());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("Stopped after")));
    }

    @Test
    void flightRowParserHandlesTagsAndLiterals() {
        Flight.Parsed p = Flight.parse("0:null\n1:true\na:N1712345678.5\nb:HC[\"https://fonts.example.com\",\"\"]\nc:S\"react.suspense\"\nd:o3,abc\ne:D{\"name\":\"Page\"}\n");
        assertEquals(7, p.rows.size());
        assertEquals(Flight.Kind.MODEL, p.rows.get(0).kind());
        assertEquals(Flight.Kind.MODEL, p.rows.get(1).kind());
        assertEquals(Flight.Kind.TIMESTAMP, p.rows.get(2).kind());
        assertEquals("hint: preconnect", p.rows.get(3).tagLabel());
        assertEquals("symbol", p.rows.get(4).tagLabel());
        assertEquals("Uint8Array", p.rows.get(5).tagLabel());
        assertEquals(Flight.Kind.DEBUG, p.rows.get(6).kind());
        assertEquals(0, p.badLines);
    }
}
