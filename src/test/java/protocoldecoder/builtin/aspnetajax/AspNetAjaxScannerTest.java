package protocoldecoder.builtin.aspnetajax;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.scan.ActiveCheck;
import protocoldecoder.scan.Confidence;
import protocoldecoder.scan.Exchange;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.HttpSender;
import protocoldecoder.scan.InsertionPoint;
import protocoldecoder.scan.Severity;
import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiFunction;

import static org.junit.jupiter.api.Assertions.*;
import static protocoldecoder.builtin.aspnetajax.AspNetAjaxDecoderTest.asyncPost;
import static protocoldecoder.builtin.aspnetajax.AspNetAjaxDecoderTest.deltaResponse;
import static protocoldecoder.builtin.aspnetajax.AspNetAjaxDecoderTest.enc;
import static protocoldecoder.builtin.aspnetajax.AspNetAjaxDecoderTest.jsonCall;
import static protocoldecoder.builtin.aspnetajax.AspNetAjaxDecoderTest.jsonResponse;
import static protocoldecoder.builtin.aspnetajax.AspNetAjaxDecoderTest.rec;

class AspNetAjaxScannerTest {

    App app = new App(new ConfigStore(KeyValueStore.inMemory(), KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });

    @AfterEach
    void close() {
        app.close();
    }

    List<Finding> passive(MessageContext m, String checkId) {
        return app.scanEngine().passive(m, false).stream().filter(f -> f.checkId().equals(checkId)).toList();
    }

    static final String SVC = "https://app.example.com/Services/CustomerService.asmx/GetCustomer";
    static final String STACK_ERROR = "{\"Message\":\"Invalid web service call, missing value for parameter: 'id'.\","
            + "\"StackTrace\":\"   at System.Web.Script.Services.WebServiceMethodData.CallMethod(Object target)\\r\\n   at ...\","
            + "\"ExceptionType\":\"System.InvalidOperationException\"}";
    static final String GENERIC_ERROR = "{\"Message\":\"There was an error processing the request.\",\"StackTrace\":\"\",\"ExceptionType\":\"\"}";

    static final String PROXY_JS = "Type.registerNamespace('Acme');\n"
            + "Acme.CustomerService=function() {\nAcme.CustomerService.initializeBase(this);}\n"
            + "Acme.CustomerService.prototype={\n"
            + "GetCustomer:function(id,since,succeededCallback, failedCallback, userContext) {\n"
            + "/// <param name=\"id\" type=\"Number\">System.Int32</param>\n"
            + "return this._invoke(this._get_path(), 'GetCustomer',false,{id:id,since:since},succeededCallback,failedCallback,userContext); },\n"
            + "DeleteAll:function(succeededCallback, failedCallback, userContext) {\n"
            + "return this._invoke(this._get_path(), 'DeleteAll',false,{},succeededCallback,failedCallback,userContext); }}\n"
            + "Acme.CustomerService.registerClass('Acme.CustomerService',Sys.Net.WebServiceProxy);\n"
            + "Acme.CustomerService.set_path(\"/Services/CustomerService.asmx\");\n";

    static MessageContext proxyResponse(String path, String js) {
        return MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://app.example.com" + path).statusCode(200)
                .responseHeader("Content-Type", "application/x-javascript").responseBody(js).build();
    }

    // ------------------------------------------------------------ passive

    @Test
    void serviceErrorDetails() {
        MessageContext rs = jsonCall(SVC, "{}").statusCode(500).responseHeader("Content-Type", "application/json; charset=utf-8")
                .responseHeader("jsonerror", "true").responseBody(STACK_ERROR).build().withKind(MessageKind.RESPONSE);
        List<Finding> f = passive(rs, "aspnet-ajax.service-error-details");
        assertEquals(1, f.size());
        assertEquals(Severity.LOW, f.get(0).severity());
        assertEquals(Confidence.FIRM, f.get(0).confidence());
        assertEquals("System.InvalidOperationException", f.get(0).evidence().get(0).text());
        // WCF ExceptionDetail
        String wcf = "{\"ExceptionDetail\":{\"HelpLink\":null,\"InnerException\":null,\"Message\":\"boom\",\"StackTrace\":\"at Acme.Svc.Do()\","
                + "\"Type\":\"System.ApplicationException\"},\"ExceptionType\":\"System.ApplicationException\",\"Message\":\"boom\"}";
        assertEquals(1, passive(jsonResponse("https://x.test/Svc.svc/Do", "{}", wcf), "aspnet-ajax.service-error-details").size());
        // Negatives: generic error, normal result.
        assertTrue(passive(jsonResponse(SVC, "{}", GENERIC_ERROR), "aspnet-ajax.service-error-details").isEmpty());
        assertTrue(passive(jsonResponse(SVC, "{}", "{\"d\":{\"Name\":\"Bob\"}}"), "aspnet-ajax.service-error-details").isEmpty());
    }

    @Test
    void deltaErrorDetails() {
        String stack = "System.NullReferenceException: Object reference not set to an instance of an object.\n   at Shop.Orders.Save_Click(Object sender, EventArgs e)";
        List<Finding> f = passive(deltaResponse(rec("error", "500", stack)), "aspnet-ajax.delta-error");
        assertEquals(1, f.size());
        assertEquals(Severity.LOW, f.get(0).severity());
        List<Finding> plain = passive(deltaResponse(rec("error", "500", "Object reference not set to an instance of an object.")), "aspnet-ajax.delta-error");
        assertEquals(1, plain.size());
        assertEquals(Severity.INFORMATION, plain.get(0).severity());
        assertTrue(passive(deltaResponse(rec("error", "500", "An unknown error occurred while processing the request on the server.")),
                "aspnet-ajax.delta-error").isEmpty());
        assertTrue(passive(deltaResponse(rec("updatePanel", "UP1", "<b>ok</b>")), "aspnet-ajax.delta-error").isEmpty());
    }

    @Test
    void proxyMethodsAndJsDebug() {
        List<Finding> f = passive(proxyResponse("/Services/CustomerService.asmx/js", PROXY_JS), "aspnet-ajax.proxy-methods");
        assertEquals(1, f.size());
        assertEquals(Severity.INFORMATION, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("POST GetCustomer(id, since)") && f.get(0).detail().contains("DeleteAll()"), f.get(0).detail());
        assertTrue(f.get(0).detail().contains("/Services/CustomerService.asmx"));
        assertTrue(passive(proxyResponse("/Services/CustomerService.asmx/js", PROXY_JS), "aspnet-ajax.jsdebug").isEmpty());

        List<Finding> dbg = passive(proxyResponse("/Services/CustomerService.asmx/jsdebug", PROXY_JS), "aspnet-ajax.jsdebug");
        assertEquals(1, dbg.size());
        assertEquals(Severity.LOW, dbg.get(0).severity());
        assertEquals(Finding.Scope.HOST, dbg.get(0).scope());
        // jsdebug without annotations: only the inventory.
        assertTrue(passive(proxyResponse("/Services/CustomerService.asmx/jsdebug", PROXY_JS.replace("/// <param name=\"id\" type=\"Number\">System.Int32</param>\n", "")),
                "aspnet-ajax.jsdebug").isEmpty());
        assertTrue(passive(jsonResponse(SVC, "{}", "{\"d\":1}"), "aspnet-ajax.proxy-methods").isEmpty());
    }

    @Test
    void redirectFromInput() {
        String body = "ScriptManager1=UpdatePanel1%7CbtnGo&__ASYNCPOST=true&returnUrl=" + enc("https://evil.example.net/landing");
        MessageContext m = asyncPost(body).statusCode(200).responseHeader("Content-Type", "text/plain")
                .responseBody(rec("pageRedirect", "", "https%3a%2f%2fevil.example.net%2flanding")).build().withKind(MessageKind.RESPONSE);
        List<Finding> f = passive(m, "aspnet-ajax.redirect-from-input");
        assertEquals(1, f.size());
        assertEquals(Severity.INFORMATION, f.get(0).severity());
        assertEquals(Confidence.TENTATIVE, f.get(0).confidence());
        // Off-site, but not from the request.
        MessageContext notInput = asyncPost("ScriptManager1=UpdatePanel1%7CbtnGo&__ASYNCPOST=true").statusCode(200)
                .responseBody(rec("pageRedirect", "", "https://sso.example.net/login")).build().withKind(MessageKind.RESPONSE);
        assertTrue(passive(notInput, "aspnet-ajax.redirect-from-input").isEmpty());
        // Same host / relative.
        MessageContext local = asyncPost("returnUrl=" + enc("/Orders.aspx") + "&__ASYNCPOST=true").statusCode(200)
                .responseBody(rec("pageRedirect", "", "/Orders.aspx")).build().withKind(MessageKind.RESPONSE);
        assertTrue(passive(local, "aspnet-ajax.redirect-from-input").isEmpty());
        assertNull(AspNetAjaxScanner.offSiteHost("https://app.example.com/x", "app.example.com"));
        assertEquals("evil.test", AspNetAjaxScanner.offSiteHost("//evil.test/x", "app.example.com"));
        assertEquals("evil.test", AspNetAjaxScanner.offSiteHost("/\\evil.test/x", "app.example.com"));
    }

    // ------------------------------------------------------------ insertion points

    @Test
    void scriptManagerInsertionPoints() throws Exception {
        String body = "ctl00%24ScriptManager1=" + enc("ctl00$Main$UpdatePanel1|ctl00$Main$btnSave") + "&__EVENTTARGET=&__ASYNCPOST=true&ctl00%24Main%24txt=hi";
        MessageContext m = asyncPost(body).build();
        List<InsertionPoint> ips = app.scanEngine().insertionPoints(m).stream().filter(i -> i.name().startsWith("ASP.NET AJAX:")).toList();
        assertEquals(List.of("ASP.NET AJAX: ctl00$ScriptManager1 update panel", "ASP.NET AJAX: ctl00$ScriptManager1 trigger"),
                ips.stream().map(InsertionPoint::name).toList());
        assertEquals("ctl00$Main$btnSave", ips.get(1).baseValue());
        String payload = "x'\"<>&=|;%+ 日本 😀";
        String trig = new String(ips.get(1).render().apply(payload), StandardCharsets.ISO_8859_1);
        assertEquals("ctl00$Main$UpdatePanel1|" + payload, Codecs.first(Codecs.parseQuery(new String(trig.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8)), "ctl00$ScriptManager1"));
        assertTrue(trig.endsWith("&__EVENTTARGET=&__ASYNCPOST=true&ctl00%24Main%24txt=hi"), trig);
        DecodeResult r = new AspNetAjaxDecoder().decode(asyncPost(new String(trig.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8)).build());
        assertEquals(payload, r.root().get("Async postback").get("ScriptManager field").get("Triggering control").value());
        String panel = new String(ips.get(0).render().apply("P'\"&日本"), StandardCharsets.UTF_8);
        assertEquals("P'\"&日本|ctl00$Main$btnSave", Codecs.first(Codecs.parseQuery(panel), "ctl00$ScriptManager1"));

        // Not for JSON service calls or non-async posts.
        assertTrue(app.scanEngine().insertionPoints(jsonCall(SVC, "{\"id\":1}").build()).stream().noneMatch(i -> i.name().startsWith("ASP.NET AJAX:")));
    }

    // ------------------------------------------------------------ active

    static final class FakeSender implements HttpSender {
        final List<String> sent = new ArrayList<>();
        final BiFunction<String, String, MessageContext.Builder> reply;

        FakeSender(BiFunction<String, String, MessageContext.Builder> reply) {
            this.reply = reply;
        }

        @Override
        public Exchange send(String method, String pathAndQuery, List<Header> headers, byte[] body) {
            String b = new String(body, StandardCharsets.UTF_8);
            sent.add(method + " " + pathAndQuery + " " + b);
            MessageContext m = reply.apply(pathAndQuery, b).method(method).url("https://app.example.com" + pathAndQuery).requestHeaders(headers)
                    .requestBody(body).build();
            return new Exchange(m, null);
        }

        @Override
        public Exchange send(InsertionPoint point, String payload) {
            throw new UnsupportedOperationException();
        }
    }

    static MessageContext.Builder resp(int status, String ct, String body) {
        return MessageContext.builder(MessageKind.REQUEST).statusCode(status).responseHeader("Content-Type", ct).responseBody(body);
    }

    List<Finding> active(MessageContext base, MessageContext response, HttpSender http, String id) {
        return app.scanEngine().active(ActiveCheck.Scope.PER_REQUEST, base, response, null, null, null, http).stream()
                .filter(f -> f.checkId().equals(id)).toList();
    }

    @Test
    void verboseServiceErrors() {
        app.scanEngine().setEnabled("aspnet-ajax.proxy-script-exposure", false);
        MessageContext base = jsonCall(SVC, "{\"id\":42,\"name\":\"x\"}").build();
        FakeSender http = new FakeSender((p, b) -> resp(500, "application/json", STACK_ERROR).responseHeader("jsonerror", "true"));
        List<Finding> f = active(base, jsonResponse(SVC, "{}", "{\"d\":null}"), http, "aspnet-ajax.verbose-service-errors");
        assertEquals(1, http.sent.size());
        assertEquals("POST /Services/CustomerService.asmx/GetCustomer {\"id\":[[]],\"name\":\"x\"}", http.sent.get(0));
        assertEquals(1, f.size());
        assertEquals(Severity.LOW, f.get(0).severity());
        assertEquals(1, f.get(0).exchanges().size());

        // Generic error → nothing.
        FakeSender generic = new FakeSender((p, b) -> resp(500, "application/json", GENERIC_ERROR));
        assertTrue(active(base, null, generic, "aspnet-ajax.verbose-service-errors").isEmpty());
        assertEquals(1, generic.sent.size());
        // Empty body → truncated JSON probe.
        FakeSender empty = new FakeSender((p, b) -> resp(500, "application/json", STACK_ERROR));
        assertEquals(1, active(jsonCall("https://app.example.com/Default.aspx/GetTime", "").build(), null, empty, "aspnet-ajax.verbose-service-errors").size());
        assertTrue(empty.sent.get(0).endsWith("{\"pdProbe\":"));
        // Async postbacks aren't probed.
        FakeSender none = new FakeSender((p, b) -> resp(500, "application/json", STACK_ERROR));
        active(asyncPost("ScriptManager1=UP1%7CBtn&__ASYNCPOST=true").build(), null, none, "aspnet-ajax.verbose-service-errors");
        assertTrue(none.sent.isEmpty());
    }

    @Test
    void proxyScriptExposure() {
        app.scanEngine().setEnabled("aspnet-ajax.verbose-service-errors", false);
        FakeSender http = new FakeSender((p, b) -> p.endsWith("/js") ? resp(200, "application/x-javascript", PROXY_JS) : resp(404, "text/html", "Not found"));
        MessageContext base = jsonCall(SVC, "{\"id\":1}").build();
        List<Finding> f = active(base, null, http, "aspnet-ajax.proxy-script-exposure");
        assertEquals(List.of("GET /Services/CustomerService.asmx/js ", "GET /Services/CustomerService.asmx/jsdebug "), http.sent);
        assertEquals(1, f.size());
        assertEquals(Severity.INFORMATION, f.get(0).severity());
        assertTrue(f.get(0).detail().contains("DeleteAll()"), f.get(0).detail());
        assertEquals(1, f.get(0).exchanges().size());
        // Another method on the same service: not requested again.
        active(jsonCall("https://app.example.com/Services/CustomerService.asmx/Other", "{}").build(), null, http, "aspnet-ajax.proxy-script-exposure");
        assertEquals(2, http.sent.size());

        // Proxy disabled (error page) → no finding.
        FakeSender off = new FakeSender((p, b) -> resp(500, "text/html", "<html>Server Error</html>"));
        assertTrue(active(jsonCall("https://app.example.com/Other.svc/Do", "{}").build(), null, off, "aspnet-ajax.proxy-script-exposure").isEmpty());
        assertEquals(2, off.sent.size());
        // PageMethods have no proxy endpoint.
        FakeSender pm = new FakeSender((p, b) -> resp(200, "application/x-javascript", PROXY_JS));
        active(jsonCall("https://app.example.com/Default.aspx/GetTime", "{}").build(), null, pm, "aspnet-ajax.proxy-script-exposure");
        assertTrue(pm.sent.isEmpty());
    }
}
