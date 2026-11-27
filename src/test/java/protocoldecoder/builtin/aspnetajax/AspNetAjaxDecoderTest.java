package protocoldecoder.builtin.aspnetajax;

import org.junit.jupiter.api.Test;
import protocoldecoder.builtin.devexpress.DevExpressDecoder;
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

class AspNetAjaxDecoderTest {

    final AspNetAjaxDecoder dec = new AspNetAjaxDecoder();

    // ------------------------------------------------------------ helpers

    /** Builds one delta record with the length JavaScript would compute (UTF-16 code units). */
    static String rec(String type, String id, String content) {
        return content.length() + "|" + type + "|" + id + "|" + content + "|";
    }

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    static MessageContext.Builder asyncPost(String body) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/Orders.aspx")
                .requestHeader("X-MicrosoftAjax", "Delta=true")
                .requestHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8").requestBody(body);
    }

    static MessageContext deltaResponse(String delta) {
        return asyncPost("ScriptManager1=UpdatePanel1%7CButton1&__ASYNCPOST=true").statusCode(200)
                .responseHeader("Content-Type", "text/plain; charset=utf-8").responseBody(delta).build()
                .withKind(MessageKind.RESPONSE);
    }

    static MessageContext.Builder jsonCall(String url, String body) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url(url)
                .requestHeader("Content-Type", "application/json; charset=utf-8").requestBody(body);
    }

    static MessageContext jsonResponse(String url, String reqBody, String respBody) {
        return jsonCall(url, reqBody).statusCode(200).responseHeader("Content-Type", "application/json; charset=utf-8")
                .responseBody(respBody).build().withKind(MessageKind.RESPONSE);
    }

    static DecodedNode node(DecodedNode n, String... path) {
        DecodedNode cur = n;
        for (String p : path) {
            assertNotNull(cur, "missing parent of " + p);
            cur = cur.get(p);
        }
        assertNotNull(cur, "missing " + String.join("/", path));
        return cur;
    }

    static String find(DecodedNode n, String nameContains) {
        if (n.name().contains(nameContains) && n.value() != null) return n.value();
        for (DecodedNode c : n.children()) {
            String v = find(c, nameContains);
            if (v != null) return v;
        }
        return null;
    }

    static byte[] gzip(String s) throws Exception {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try (GZIPOutputStream g = new GZIPOutputStream(bo)) {
            g.write(s.getBytes(StandardCharsets.UTF_8));
        }
        return bo.toByteArray();
    }

    // ------------------------------------------------------------ delta parser

    @Test
    void parserHandlesPipesAndMultiByteContent() {
        String html = "<td>a|b||c</td><td>café ☕ 😀 日本</td>";
        String delta = rec("updatePanel", "UpdatePanel1", html) + rec("hiddenField", "__EVENTTARGET", "") + rec("pageTitle", "", "x|y");
        DeltaParser.Result r = DeltaParser.parse(delta, 100);
        assertTrue(r.clean(), r.error());
        assertEquals(3, r.records().size());
        assertEquals(html, r.records().get(0).content());
        assertEquals(html.length(), r.records().get(0).length());
        assertEquals("", r.records().get(1).content());
        assertEquals("x|y", r.records().get(2).content());
        assertTrue(DeltaParser.looksLikeDelta(delta, 3));
    }

    @Test
    void parserReportsBadLengthsAndTails() {
        DeltaParser.Result tooLong = DeltaParser.parse("50|updatePanel|P|short|", 100);
        assertTrue(tooLong.records().isEmpty());
        assertTrue(tooLong.error().contains("declares 50"), tooLong.error());

        DeltaParser.Result mismatch = DeltaParser.parse("3|updatePanel|P|short|", 100);
        assertTrue(mismatch.error().contains("length mismatch"), mismatch.error());

        DeltaParser.Result tail = DeltaParser.parse(rec("pageTitle", "", "Hi") + "12|hiddenField|__VIEW", 100);
        assertEquals(1, tail.records().size());
        assertNotNull(tail.error());
        assertEquals(rec("pageTitle", "", "Hi").length(), tail.errorOffset());

        assertNotNull(DeltaParser.parse("abc|x|y|z|", 100).error());
        assertFalse(DeltaParser.looksLikeDelta("12|foo|bar|", 3));
        assertFalse(DeltaParser.looksLikeDelta("0|/*DX*/({'id':0})", 3));
        assertFalse(DeltaParser.looksLikeDelta("5|unknownType||hello|", 3)); // first type must be known
        assertTrue(DeltaParser.parse(rec("a", "b", "c") + rec("d", "e", "f"), 1).capped());
    }

    // ------------------------------------------------------------ async postback requests

    @Test
    void asyncPostbackRequest() throws Exception {
        String vs = "/wEPDwUKMTY1NDU2MTA1MmRk" + "A".repeat(400);
        String body = "ctl00%24ScriptManager1=" + enc("ctl00$Main$UpdatePanel1|ctl00$Main$btnSave")
                + "&__EVENTTARGET=&__EVENTARGUMENT=&__VIEWSTATE=" + enc(vs) + "&__VIEWSTATEGENERATOR=CA0B0334"
                + "&__EVENTVALIDATION=%2FwEdAAJ&ctl00%24Main%24txtName=bob&ctl00%24Main%24hdnData=" + enc("{\"a\":1}")
                + "&__ASYNCPOST=true&ctl00%24Main%24btnSave=Save";
        MessageContext m = asyncPost(body).build();
        assertEquals(95, dec.match(m).confidence());
        DecodeResult r = dec.decode(m);
        assertEquals("Async postback → UpdatePanel1 via btnSave", r.summary());
        DecodedNode sm = node(r.root(), "Async postback", "ScriptManager field");
        assertEquals("ctl00$ScriptManager1", sm.get("Name").value());
        assertEquals("ctl00$Main$UpdatePanel1", sm.get("Update panel").value());
        assertEquals("ctl00$Main$btnSave", sm.get("Triggering control").value());
        assertEquals("true", node(r.root(), "Async postback", "__ASYNCPOST").value());
        String viewState = node(r.root(), "ASP.NET state", "__VIEWSTATE").value();
        assertTrue(viewState.contains("ViewState tab"), viewState);
        assertTrue(viewState.length() < 300);
        assertEquals("CA0B0334", node(r.root(), "ASP.NET state", "__VIEWSTATEGENERATOR").value());
        assertEquals("bob", node(r.root(), "Form fields", "ctl00$Main$txtName").value());
        assertEquals("1", node(r.root(), "Form fields", "ctl00$Main$hdnData", "a").value());
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
    }

    @Test
    void asyncPostbackViaDoPostBackWithoutHeader() throws Exception {
        String body = "ScriptManager1=" + enc("UpdatePanel1|GridView1") + "&__EVENTTARGET=GridView1&__EVENTARGUMENT=" + enc("Page$2")
                + "&__VIEWSTATE=abc&__ASYNCPOST=true&";
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://x.test/a.aspx")
                .requestHeader("Content-Type", "application/x-www-form-urlencoded").requestBody(body).build();
        assertEquals(85, dec.match(m).confidence());
        DecodeResult r = dec.decode(m);
        assertEquals("Async postback → UpdatePanel1 via GridView1 [arg: Page$2]", r.summary());
        assertEquals("GridView1", find(r.root(), "__EVENTTARGET"));
    }

    // ------------------------------------------------------------ delta responses

    @Test
    void deltaResponseFullDecode() throws Exception {
        String panelHtml = "<table><tr><td>Total | 42 €</td></tr></table>";
        String vs = "/wEPDwUK" + "B".repeat(500);
        String delta = rec("updatePanel", "ctl00_Main_UpdatePanel1", panelHtml)
                + rec("updatePanel", "ctl00_Main_UpdatePanel2", "<span>😀 ok</span>")
                + rec("hiddenField", "__EVENTTARGET", "")
                + rec("hiddenField", "__VIEWSTATE", vs)
                + rec("hiddenField", "__EVENTVALIDATION", "/wEdAAKx")
                + rec("asyncPostBackControlIDs", "", "ctl00$Main$btnSave,ctl00$Main$GridView1")
                + rec("postBackControlIDs", "", "")
                + rec("updatePanelIDs", "", "tctl00$Main$UpdatePanel1,fctl00$Main$UpdatePanel2")
                + rec("childUpdatePanelIDs", "", "")
                + rec("panelsToRefreshIDs", "", "ctl00$Main$UpdatePanel1")
                + rec("asyncPostBackTimeout", "", "90")
                + rec("formAction", "", "Orders.aspx?id=5")
                + rec("pageTitle", "", "Orders | Admin")
                + rec("focus", "", "ctl00_Main_txtName")
                + rec("scriptBlock", "ScriptPath", "/ScriptResource.axd?d=abc1&t=ffffffffb2a7d8a8")
                + rec("scriptBlock", "ScriptContentNoTags", "var x = 'a|b';")
                + rec("scriptBlock", "ScriptContentWithTags", "{\"text\":\"alert(1)\",\"type\":\"text/javascript\"}")
                + rec("scriptStartupBlock", "ScriptContentNoTags", "Sys.Application.add_init(function(){});")
                + rec("arrayDeclaration", "Page_Validators", "document.getElementById(\"rfv1\")")
                + rec("expando", "document.getElementById('rfv1')['controltovalidate']", "\"txtName\"")
                + rec("onSubmit", "", "return WebForm_OnSubmit();")
                + rec("scriptDispose", "ctl00_Main_UpdatePanel1", "dispose();")
                + rec("dataItem", "ctl00_Main_Label1", "plain text")
                + rec("dataItemJson", "ctl00_Main_Grid", "{\"rows\":3,\"when\":\"\\/Date(1700000000000)\\/\"}");
        MessageContext m = deltaResponse(delta);
        assertEquals(95, dec.match(m).confidence());
        DecodeResult r = dec.decode(m);
        assertEquals("Async postback delta: 2 panels updated, 3 hidden fields, 2 data items", r.summary());
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());

        DecodedNode p1 = node(r.root(), "Updated panels", "ctl00_Main_UpdatePanel1");
        assertEquals(DecodedNode.Type.HTML, p1.type());
        assertEquals(panelHtml, p1.value());
        assertEquals("<span>😀 ok</span>", node(r.root(), "Updated panels", "ctl00_Main_UpdatePanel2").value());
        assertTrue(node(r.root(), "Hidden fields", "__VIEWSTATE").value().contains("ViewState tab"));
        assertEquals("/wEdAAKx", node(r.root(), "Hidden fields", "__EVENTVALIDATION").value());

        DecodedNode async = node(r.root(), "Control ID lists", "asyncPostBackControlIDs");
        assertEquals(2, async.children().size());
        assertEquals("ctl00$Main$GridView1", async.children().get(1).value());
        assertEquals("true", node(r.root(), "Control ID lists", "updatePanelIDs", "ctl00$Main$UpdatePanel1", "childrenAsTriggers").value());
        assertEquals("false", node(r.root(), "Control ID lists", "updatePanelIDs", "ctl00$Main$UpdatePanel2", "childrenAsTriggers").value());

        assertEquals("90", node(r.root(), "Page", "asyncPostBackTimeout (s)").value());
        assertEquals("Orders.aspx?id=5", node(r.root(), "Page", "formAction").value());
        assertEquals("Orders | Admin", node(r.root(), "Page", "pageTitle").value());
        assertEquals("ctl00_Main_txtName", node(r.root(), "Page", "focus").value());

        DecodedNode scripts = node(r.root(), "Scripts");
        assertEquals(8, scripts.children().size());
        assertEquals("/ScriptResource.axd?d=abc1&t=ffffffffb2a7d8a8", scripts.children().get(0).get("path").value());
        assertEquals("var x = 'a|b';", scripts.children().get(1).get("content").value());
        assertEquals("alert(1)", scripts.children().get(2).get("attributes").get("text").value());

        assertEquals("plain text", node(r.root(), "Data items", "ctl00_Main_Label1").value());
        DecodedNode grid = node(r.root(), "Data items", "ctl00_Main_Grid (JSON)");
        assertEquals("3", grid.get("rows").value());
        assertTrue(grid.get("when").value().startsWith("2023-11-14T22:13:20Z"), grid.get("when").value());

        assertEquals(24, node(r.root(), "Record index").children().size());
        assertFalse(TreeText.render(r.root()).isEmpty());
    }

    @Test
    void deltaUpdatePanelIdsNet4Pairs() throws Exception {
        String delta = rec("updatePanelIDs", "", "tctl00$UP1,ctl00_UP1,fctl00$UP2,ctl00_UP2") + rec("pageTitle", "", "x");
        DecodeResult r = dec.decode(deltaResponse(delta));
        DecodedNode up2 = node(r.root(), "Control ID lists", "updatePanelIDs", "ctl00$UP2");
        assertEquals("false", up2.get("childrenAsTriggers").value());
        assertEquals("ctl00_UP2", up2.get("clientID").value());
    }

    @Test
    void deltaErrorRecord() throws Exception {
        String msg = "Object reference not set to an instance of an object.";
        String delta = rec("error", "500", msg);
        MessageContext m = deltaResponse(delta);
        assertEquals(95, dec.match(m).confidence());
        DecodeResult r = dec.decode(m);
        assertEquals("Async postback delta: error 500: " + msg, r.summary());
        assertEquals("500", node(r.root(), "Error", "HTTP status (id)").value());
        assertEquals(msg, node(r.root(), "Error", "Message").value());
    }

    @Test
    void deltaPageRedirect() throws Exception {
        String delta = rec("pageRedirect", "", "%2fLogin.aspx%3fReturnUrl%3d%252fOrders.aspx");
        DecodeResult r = dec.decode(deltaResponse(delta));
        assertEquals("Async postback delta: redirect to /Login.aspx?ReturnUrl=%2fOrders.aspx", r.summary());
        assertEquals("%2fLogin.aspx%3fReturnUrl%3d%252fOrders.aspx", node(r.root(), "Redirect", "URL").value());

        DecodeResult plain = dec.decode(deltaResponse(rec("pageRedirect", "", "/Login.aspx")));
        assertEquals("Async postback delta: redirect to /Login.aspx", plain.summary());
    }

    @Test
    void deltaMalformedTailAndUnknownType() throws Exception {
        String good = rec("updatePanel", "UP1", "<b>hi</b>") + rec("newFancyType", "x", "y");
        DecodeResult r = dec.decode(deltaResponse(good + "999|hiddenField|__VIEWSTATE|/wEPD"));
        assertEquals("Async postback delta: 1 panel updated", r.summary());
        assertTrue(r.warnings().stream().anyMatch(w -> w.startsWith("Malformed delta at character " + good.length())), r.warnings().toString());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("newFancyType")), r.warnings().toString());
        assertNotNull(find(r.root(), "Undecoded tail"));
    }

    @Test
    void gzippedDeltaResponse() throws Exception {
        String delta = rec("updatePanel", "UP1", "<p>zipped</p>");
        MessageContext m = asyncPost("a=1").statusCode(200).responseHeader("Content-Encoding", "gzip")
                .responseBody(gzip(delta)).build().withKind(MessageKind.RESPONSE);
        assertEquals(95, dec.match(m).confidence());
        assertEquals("<p>zipped</p>", node(dec.decode(m).root(), "Updated panels", "UP1").value());
    }

    @Test
    void deltaMatchesWithoutRequestHeader() {
        String delta = rec("updatePanel", "UP1", "<p>x</p>") + rec("hiddenField", "__VIEWSTATE", "abc");
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("POST").url("https://x.test/a.aspx").statusCode(200)
                .responseHeader("Content-Type", "text/plain").responseBody(delta).build();
        assertEquals(95, dec.match(m).confidence());
    }

    // ------------------------------------------------------------ JSON services

    @Test
    void asmxRequestAndResponse() throws Exception {
        String url = "https://app.example.com/Services/CustomerService.asmx/GetCustomer";
        String req = "{\"id\":42,\"since\":\"\\/Date(1700000000000+0100)\\/\"}";
        MessageContext rq = jsonCall(url, req).build();
        assertEquals(80, dec.match(rq).confidence());
        DecodeResult r = dec.decode(rq);
        assertEquals("ASMX call → CustomerService.asmx/GetCustomer(id, since)", r.summary());
        assertEquals("42", node(r.root(), "Arguments", "id").value());
        assertTrue(node(r.root(), "Arguments", "since").value().startsWith("2023-11-14T23:13:20+01:00"),
                node(r.root(), "Arguments", "since").value());

        String resp = "{\"d\":{\"__type\":\"Acme.Model.Customer\",\"Name\":\"Bob\",\"Created\":\"\\/Date(-62135596800000)\\/\",\"Orders\":[1,2]}}";
        MessageContext rs = jsonResponse(url, req, resp);
        assertEquals(80, dec.match(rs).confidence());
        DecodeResult out = dec.decode(rs);
        assertEquals("ASMX GetCustomer → Customer", out.summary());
        DecodedNode d = node(out.root(), "d (result)");
        assertEquals("Acme.Model.Customer", d.value());
        assertEquals("Bob", d.get("Name").value());
        assertTrue(d.get("Created").value().startsWith("0001-01-01T00:00:00Z"), d.get("Created").value());
        assertTrue(out.warnings().isEmpty());
    }

    @Test
    void wcfTypeHintsAndArrays() throws Exception {
        String url = "https://app.example.com/OrderService.svc/ListOrders";
        String resp = "{\"d\":[{\"__type\":\"Order:#Acme.Contracts\",\"Id\":1,\"Placed\":\"\\/Date(1700000000000-0500)\\/\"},"
                + "{\"__type\":\"Order:#Acme.Contracts\",\"Id\":2,\"Placed\":null}]}";
        MessageContext rs = jsonResponse(url, "{}", resp);
        assertEquals(80, dec.match(rs).confidence());
        DecodeResult out = dec.decode(rs);
        assertEquals("WCF ListOrders → array[2] of Order", out.summary());
        DecodedNode first = node(out.root(), "d (result)", "[0]");
        assertEquals("Acme.Contracts.Order", first.value());
        assertTrue(first.get("Placed").value().startsWith("2023-11-14T17:13:20-05:00"), first.get("Placed").value());
        assertEquals("WCF call → OrderService.svc/ListOrders()", dec.decode(jsonCall(url, "{}").build()).summary());
    }

    @Test
    void primitiveDResults() throws Exception {
        String url = "https://x.test/Svc.asmx/Hello";
        assertEquals("ASMX Hello → \"Hello World\"", dec.decode(jsonResponse(url, "{}", "{\"d\":\"Hello World\"}")).summary());
        assertEquals("ASMX Hello → null", dec.decode(jsonResponse(url, "{}", "{\"d\":null}")).summary());
        assertEquals("ASMX Hello → 2023-11-14T22:13:20Z",
                dec.decode(jsonResponse(url, "{}", "{\"d\":\"\\/Date(1700000000000)\\/\"}")).summary());
    }

    @Test
    void pageMethod() throws Exception {
        String url = "https://app.example.com/Default.aspx/GetTime";
        MessageContext rq = jsonCall(url, "{\"zone\":\"UTC\"}").build();
        assertEquals(75, dec.match(rq).confidence());
        assertEquals("PageMethod call → Default.aspx/GetTime(zone)", dec.decode(rq).summary());
        MessageContext rs = jsonResponse(url, "{\"zone\":\"UTC\"}", "{\"d\":\"12:00\"}");
        assertEquals(80, dec.match(rs).confidence());
        assertEquals("PageMethod GetTime → \"12:00\"", dec.decode(rs).summary());
    }

    @Test
    void errorObjectWithStackTrace() throws Exception {
        String url = "https://app.example.com/Services/CustomerService.asmx/GetCustomer";
        String resp = "{\"Message\":\"Invalid web service call, missing value for parameter: 'id'.\","
                + "\"StackTrace\":\"   at System.Web.Script.Services.WebServiceMethodData.CallMethod(Object target)\\r\\n   at ...\","
                + "\"ExceptionType\":\"System.InvalidOperationException\"}";
        MessageContext rs = jsonCall(url, "{}").statusCode(500).responseHeader("Content-Type", "application/json; charset=utf-8")
                .responseHeader("jsonerror", "true").responseBody(resp).build().withKind(MessageKind.RESPONSE);
        assertEquals(80, dec.match(rs).confidence());
        DecodeResult r = dec.decode(rs);
        assertEquals("ASMX GetCustomer error: System.InvalidOperationException: Invalid web service call, missing value for parameter: 'id'.",
                r.summary());
        assertTrue(r.warnings().stream().anyMatch(w -> w.contains("stack trace")), r.warnings().toString());
        assertEquals("System.InvalidOperationException", node(r.root(), "Error", "ExceptionType").value());

        // An error object recognised on any path, even without the jsonerror header.
        MessageContext bare = MessageContext.builder(MessageKind.RESPONSE).method("POST").url("https://x.test/api/thing").statusCode(500)
                .responseHeader("Content-Type", "application/json").responseBody(resp).build();
        assertEquals(80, dec.match(bare).confidence());
    }

    @Test
    void genericErrorHasNoStackTraceWarning() throws Exception {
        String resp = "{\"Message\":\"There was an error processing the request.\",\"StackTrace\":\"\",\"ExceptionType\":\"\"}";
        DecodeResult r = dec.decode(jsonResponse("https://x.test/S.asmx/M", "{}", resp));
        assertEquals("ASMX M error: There was an error processing the request.", r.summary());
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
    }

    @Test
    void wcfExceptionDetail() throws Exception {
        String resp = "{\"ExceptionDetail\":{\"HelpLink\":null,\"InnerException\":null,\"Message\":\"boom\","
                + "\"StackTrace\":\"at Acme.Svc.Do()\",\"Type\":\"System.ApplicationException\"},"
                + "\"ExceptionType\":\"System.ApplicationException\",\"Message\":\"boom\",\"StackTrace\":\"at Acme.Svc.Do()\"}";
        MessageContext rs = jsonResponse("https://x.test/Svc.svc/Do", "{}", resp);
        assertEquals(80, dec.match(rs).confidence());
        DecodeResult r = dec.decode(rs);
        assertEquals("WCF Do error: System.ApplicationException: boom", r.summary());
        assertFalse(r.warnings().isEmpty());
    }

    @Test
    void dateConversion() {
        assertEquals("2023-11-14T22:13:20Z", MsJson.isoDate("/Date(1700000000000)/"));
        assertEquals("2023-11-14T23:13:20+01:00", MsJson.isoDate("/Date(1700000000000+0100)/"));
        assertEquals("2023-11-14T16:43:20-05:30", MsJson.isoDate("/Date(1700000000000-0530)/"));
        assertNull(MsJson.isoDate("/Date(abc)/"));
        assertNull(MsJson.isoDate("Date(1700000000000)"));
        assertNull(MsJson.isoDate("/Date(1700000000000+01)/"));
        assertEquals("Acme.Order", MsJson.typeName("Order:#Acme"));
        assertEquals("Acme.Order", MsJson.typeName("Acme.Order"));
    }

    // ------------------------------------------------------------ proxy scripts

    @Test
    void proxyScript() throws Exception {
        String js = "Type.registerNamespace('Acme');\n"
                + "Acme.CustomerService=function() {\nAcme.CustomerService.initializeBase(this);\nthis._timeout = 0;}\n"
                + "Acme.CustomerService.prototype={_get_path:function() {\n var p = this.get_path();\n return Acme.CustomerService._staticInstance.get_path();},\n"
                + "GetCustomer:function(id,since,succeededCallback, failedCallback, userContext) {\n"
                + "return this._invoke(this._get_path(), 'GetCustomer',false,{id:id,since:since},succeededCallback,failedCallback,userContext); },\n"
                + "Ping:function(succeededCallback, failedCallback, userContext) {\n"
                + "return this._invoke(this._get_path(), 'Ping',true,{},succeededCallback,failedCallback,userContext); }}\n"
                + "Acme.CustomerService.registerClass('Acme.CustomerService',Sys.Net.WebServiceProxy);\n"
                + "Acme.CustomerService._staticInstance = new Acme.CustomerService();\n"
                + "Acme.CustomerService.set_path(\"/Services/CustomerService.asmx\");\n"
                + "if (typeof(Acme.Customer) === 'undefined') {\nAcme.Customer=gtc(\"Acme.Customer\");\nAcme.Customer.registerClass('Acme.Customer');\n}";
        String url = "https://app.example.com/Services/CustomerService.asmx/js";
        MessageContext rq = MessageContext.builder(MessageKind.REQUEST).method("GET").url(url).build();
        assertEquals(40, dec.match(rq).confidence());
        assertEquals("ASMX proxy script request → CustomerService.asmx", dec.decode(rq).summary());

        MessageContext rs = MessageContext.builder(MessageKind.REQUEST).method("GET").url(url).statusCode(200)
                .responseHeader("Content-Type", "application/x-javascript").responseBody(js).build().withKind(MessageKind.RESPONSE);
        assertEquals(80, dec.match(rs).confidence());
        DecodeResult r = dec.decode(rs);
        assertEquals("Service proxy: Acme.CustomerService at /Services/CustomerService.asmx, 2 methods", r.summary());
        DecodedNode get = node(r.root(), "Methods").children().get(0);
        assertEquals("GetCustomer", get.name());
        assertEquals("POST", get.get("HTTP").value());
        assertEquals("since", get.get("Parameters").children().get(1).value());
        assertEquals("GET", node(r.root(), "Methods").children().get(1).get("HTTP").value());
        assertEquals("Acme.Customer", node(r.root(), "Data contract types").children().get(0).value());
    }

    // ------------------------------------------------------------ axd

    @Test
    void scriptResourceAxd() throws Exception {
        // 32 bytes -> 43 base64url chars + pad digit "1"
        String d = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]) + "1";
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("GET")
                .url("https://app.example.com/ScriptResource.axd?d=" + d + "&t=ffffffffb2a7d8a8").build();
        assertEquals(40, dec.match(m).confidence());
        DecodeResult r = dec.decode(m);
        assertEquals("ScriptResource.axd resource request (encrypted d, 32 bytes)", r.summary());
        assertEquals("32", node(r.root(), "d (resource reference)", "Encrypted bytes").value());
        assertTrue(TreeText.render(r.root()).contains("machine key"));
        assertNull(node(r.root(), "t (cache-busting timestamp)").get("As .NET ticks"));
        assertEquals("ffffffffb2a7d8a8", node(r.root(), "t (cache-busting timestamp)", "Raw").value());
    }

    @Test
    void webResourceAxdDecimalTicks() throws Exception {
        // 2014-01-01T00:00:00Z in ticks
        long ticks = 621_355_968_000_000_000L + 1_388_534_400_000L * 10_000;
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("GET")
                .url("https://app.example.com/WebResource.axd?d=AAAA0&t=" + ticks).build();
        assertEquals(40, dec.match(m).confidence());
        DecodeResult r = dec.decode(m);
        assertEquals("2014-01-01T00:00:00Z", node(r.root(), "t (cache-busting timestamp)", "As .NET ticks").value());
        assertEquals("2014-01-01T00:00:00Z", AspNetAjaxDecoder.ticksToDate(Long.toHexString(ticks)));
        assertNull(AspNetAjaxDecoder.urlTokenDecode("AAAA5"));
    }

    // ------------------------------------------------------------ negatives

    @Test
    void devExpressCallbackIsNotClaimed() {
        DevExpressDecoder dx = new DevExpressDecoder();
        String body = "__EVENTTARGET=&__VIEWSTATE=%2FwEPDwUK&__CALLBACKID=" + enc("ctl00$Main$ASPxGridView1")
                + "&__CALLBACKPARAM=" + enc("c0:KV|2;[];GB|20;12|PAGERONCLICK3|PN1;") + "&DXScript=1_304";
        MessageContext rq = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/Orders.aspx")
                .requestHeader("Content-Type", "application/x-www-form-urlencoded").requestBody(body).build();
        assertEquals(0, dec.match(rq).confidence());
        assertTrue(dx.match(rq).confidence() > dec.match(rq).confidence());

        String resp = "0|/*DX*/({'id':0,'result':{'html':'<table></table>'}})";
        MessageContext rs = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/Orders.aspx")
                .requestHeader("Content-Type", "application/x-www-form-urlencoded").requestBody(body).statusCode(200)
                .responseHeader("Content-Type", "text/plain").responseBody(resp).build().withKind(MessageKind.RESPONSE);
        assertEquals(0, dec.match(rs).confidence());
    }

    @Test
    void plainJsonApiIsNotClaimed() {
        MessageContext rq = jsonCall("https://api.example.com/v1/users/42", "{\"name\":\"bob\"}").build();
        assertEquals(0, dec.match(rq).confidence());
        MessageContext rs = jsonResponse("https://api.example.com/v1/users/42", "{}", "{\"id\":42,\"name\":\"bob\"}");
        assertEquals(0, dec.match(rs).confidence());
        // OData-v2-style {"d": …} without __type on a non-ASMX path stays unclaimed.
        MessageContext odata = jsonResponse("https://api.example.com/odata/Users", "{}", "{\"d\":{\"results\":[]}}");
        assertEquals(0, dec.match(odata).confidence());
        // Plain numeric / text responses.
        MessageContext num = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://x.test/count").statusCode(200)
                .responseBody("12345").build();
        assertEquals(0, dec.match(num).confidence());
        MessageContext html = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://x.test/a.aspx").statusCode(200)
                .responseBody("<html><body>hi</body></html>").build();
        assertEquals(0, dec.match(html).confidence());
        MessageContext get = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://x.test/a.aspx").build();
        assertEquals(0, dec.match(get).confidence());
        MessageContext ws = MessageContext.builder(MessageKind.WEBSOCKET).url("wss://x.test/ws")
                .webSocket("CLIENT_TO_SERVER", "1|updatePanel|x|y|".getBytes(StandardCharsets.UTF_8)).build();
        assertEquals(0, dec.match(ws).confidence());
    }

    @Test
    void typeHintedDWrapperOnUnknownPathIsWeak() {
        MessageContext rs = jsonResponse("https://x.test/api/svc", "{}", "{\"d\":{\"__type\":\"Acme.Foo\",\"a\":1}}");
        assertEquals(60, dec.match(rs).confidence());
    }

    @Test
    void forcedDecodeOnGarbageThrows() {
        MessageContext rq = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://x.test/upload")
                .requestHeader("Content-Type", "application/octet-stream").requestBody(new byte[]{1, 2, 3}).build();
        DecodeException e = assertThrows(DecodeException.class, () -> dec.decode(rq));
        assertTrue(e.getMessage().contains("Not an ASP.NET AJAX request"), e.getMessage());

        MessageContext rs = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://x.test/").statusCode(200)
                .responseBody("hello world, this is not a delta").build();
        assertThrows(DecodeException.class, () -> dec.decode(rs));

        MessageContext badDelta = deltaResponse("99|updatePanel|UP1|short|");
        DecodeException e2 = assertThrows(DecodeException.class, () -> dec.decode(badDelta));
        assertTrue(e2.getMessage().contains("delta"), e2.getMessage());

        MessageContext empty = deltaResponse("");
        assertThrows(DecodeException.class, () -> dec.decode(empty));

        MessageContext ws = MessageContext.builder(MessageKind.WEBSOCKET).url("wss://x.test/ws").webSocket("CLIENT_TO_SERVER", new byte[]{1}).build();
        assertThrows(DecodeException.class, () -> dec.decode(ws));

        MessageContext axdNoD = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://x.test/WebResource.axd?x=1").build();
        assertThrows(DecodeException.class, () -> dec.decode(axdNoD));
    }

    @Test
    void forcedDecodeOnRegularPostback() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://x.test/a.aspx")
                .requestHeader("Content-Type", "application/x-www-form-urlencoded")
                .requestBody("__EVENTTARGET=btn&__EVENTARGUMENT=&__VIEWSTATE=abc&txt=1").build();
        assertEquals(0, dec.match(m).confidence());
        DecodeResult r = dec.decode(m);
        assertEquals("Postback → btn", r.summary());
        assertFalse(r.warnings().isEmpty());
    }
}
