package protocoldecoder;

import org.junit.jupiter.api.Test;
import protocoldecoder.builtin.devexpress.DevExpressDecoder;
import protocoldecoder.builtin.newrelic.NewRelicDecoder;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.util.TreeText;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.zip.GZIPOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class DecodersTest {

    final DevExpressDecoder dx = new DevExpressDecoder();
    final NewRelicDecoder nr = new NewRelicDecoder();

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    static MessageContext.Builder dxPost(String body) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/Orders.aspx")
                .requestHeader("Content-Type", "application/x-www-form-urlencoded").requestBody(body);
    }

    static String find(DecodedNode n, String nameContains) {
        if (n.name().contains(nameContains) && n.value() != null) return n.value();
        for (DecodedNode c : n.children()) {
            String v = find(c, nameContains);
            if (v != null) return v;
        }
        return null;
    }

    @Test
    void devexpressGridCallbackRequest() throws Exception {
        String body = "__EVENTTARGET=&__VIEWSTATE=%2FwEPDwUK&__CALLBACKID=" + enc("ctl00$Main$ASPxGridView1")
                + "&__CALLBACKPARAM=" + enc("c0:KV|2;[];GB|20;12|PAGERONCLICK3|PN1;")
                + "&DXScript=" + enc("1_304,1_185,1_298") + "&ctl00$Main$txtName=bob";
        MessageContext m = dxPost(body).build();
        assertTrue(dx.match(m).confidence() >= 90);
        DecodeResult r = dx.decode(m);
        assertEquals("Callback → ASPxGridView1 (PAGERONCLICK)", r.summary());
        String text = TreeText.render(r.root());
        assertTrue(text.contains("PAGERONCLICK"), text);
        assertTrue(text.contains("PN1"), text);
        assertEquals("0", find(r.root(), "Callback index"));
        assertNotNull(r.root().get("ASP.NET state"));
        assertEquals("bob", find(r.root(), "txtName"));
        assertTrue(r.warnings().isEmpty(), r.warnings().toString());
    }

    @Test
    void devexpressCustomCallbackWithPlainValue() throws Exception {
        MessageContext m = dxPost("__CALLBACKID=cbPanel&__CALLBACKPARAM=" + enc("c0:refresh:42")).build();
        DecodeResult r = dx.decode(m);
        assertEquals("refresh:42", find(r.root(), "Value"));
    }

    @Test
    void devexpressCallbackResponse() throws Exception {
        String resp = "0|/*DX*/({'id':0,'result':{'html':'<table><tr><td>1</td></tr></table>','stateObject':{'keys':['1','2']}}})";
        MessageContext m = dxPost("__CALLBACKID=x&__CALLBACKPARAM=c0%3Ax").statusCode(200)
                .responseHeader("Content-Type", "text/plain").responseBody(resp).build().withKind(MessageKind.RESPONSE);
        assertEquals(95, dx.match(m).confidence());
        DecodeResult r = dx.decode(m);
        assertTrue(r.summary().startsWith("Callback result #0"), r.summary());
        DecodedNode result = r.root().get("Result").get("result");
        assertEquals(DecodedNode.Type.HTML, result.get("html").type());
        assertEquals("2", result.get("stateObject").get("keys").children().get(1).value());
    }

    @Test
    void devexpressErrorResponseWithValidationEnvelope() throws Exception {
        String resp = "s5|abcde/*DX*/({'id':1,'error':{'message':'Object reference not set','data':null}})";
        MessageContext m = dxPost("x=1").statusCode(200).responseBody(resp).build().withKind(MessageKind.RESPONSE);
        DecodeResult r = dx.decode(m);
        assertTrue(r.summary().contains("ERROR: Object reference not set"), r.summary());
        assertEquals("abcde", r.root().get("ASP.NET callback envelope").get("__EVENTVALIDATION").value());
    }

    @Test
    void devexpressDoesNotMatchOrdinaryForm() {
        assertEquals(0, dx.match(dxPost("user=a&pass=b").build()).confidence());
    }

    @Test
    void devexpressMvcCallback() throws Exception {
        MessageContext m = dxPost("DXCallbackName=GridView&DXCallbackArgument=" + enc("c0:KV|5;['7'];GB|20;14|CUSTOMCALLBACK1|x;")
                + "&DXMVCEditorsValues=" + enc("{\"txt\":\"a\"}")).build();
        DecodeResult r = dx.decode(m);
        assertEquals("MVC callback → GridView (CUSTOMCALLBACK)", r.summary());
        assertEquals("a", find(r.root(), "txt"));
    }

    @Test
    void newRelicBrowserBeaconGzipped() throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
            gz.write("{\"err\":[{\"params\":{\"message\":\"x is undefined\"}}]}".getBytes(StandardCharsets.UTF_8));
        }
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST")
                .url("https://bam.nr-data.net/jserrors/1/NRJS-0123456789abcdef?a=1234567&v=1.250.0&t=Unnamed%20Transaction&st=1732700000000")
                .requestBody(bos.toByteArray()).build();
        assertEquals(95, nr.match(m).confidence());
        DecodeResult r = nr.decode(m);
        assertTrue(r.summary().contains("JavaScript errors"), r.summary());
        assertEquals("NRJS-0123456789abcdef", find(r.root(), "Browser license key"));
        assertEquals("x is undefined", find(r.root(), "message"));
        assertEquals("1234567", find(r.root(), "Application ID"));
    }

    @Test
    void newRelicTraceHeaders() throws Exception {
        String payload = "{\"v\":[0,1],\"d\":{\"ty\":\"Browser\",\"ac\":\"111\",\"ap\":\"222\",\"id\":\"abc\",\"tr\":\"def\",\"ti\":1732700000000}}";
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("GET").url("https://api.example.com/x")
                .requestHeader("newrelic", Base64.getEncoder().encodeToString(payload.getBytes(StandardCharsets.UTF_8)))
                .requestHeader("traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
                .requestHeader("tracestate", "33@nr=0-1-111-222-b7ad6b7169203331--1-1.2-1732700000000")
                .build();
        assertEquals(40, nr.match(m).confidence());
        DecodeResult r = nr.decode(m);
        assertEquals("111", find(r.root(), "Account ID"));
        assertEquals("01 (sampled)", find(r.root(), "Flags"));
        assertEquals("1 (Browser)", find(r.root().get("Tracing headers").get("tracestate (W3C)"), "Parent type"));
    }

    @Test
    void newRelicPageConfig() throws Exception {
        String html = "<html><head><script>;window.NREUM||(NREUM={});NREUM.init={distributed_tracing:{enabled:true}};"
                + "NREUM.loader_config={accountID:\"111\",trustKey:\"33\",agentID:\"444\",licenseKey:\"NRJS-abc\",applicationID:\"444\"};"
                + "NREUM.info={beacon:\"bam.nr-data.net\",errorBeacon:\"bam.nr-data.net\",licenseKey:\"NRJS-abc\",applicationID:\"444\",sa:1}</script></head></html>";
        MessageContext m = MessageContext.builder(MessageKind.RESPONSE).method("GET").url("https://www.example.com/")
                .statusCode(200).responseHeader("Content-Type", "text/html").responseBody(html).build();
        assertEquals(30, nr.match(m).confidence());
        DecodeResult r = nr.decode(m);
        assertEquals("Browser agent configuration (app 444)", r.summary());
        assertEquals("NRJS-abc", find(r.root().get("Browser agent (NREUM)").get("NREUM.loader_config"), "licenseKey"));
    }

    @Test
    void newRelicApmCollector() throws Exception {
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST")
                .url("https://collector.newrelic.com/agent_listener/invoke_raw_method?method=preconnect&license_key=abc&protocol_version=17&marshal_format=json")
                .requestBody("[]").build();
        DecodeResult r = nr.decode(m);
        assertEquals("APM agent → preconnect", r.summary());
    }
}
