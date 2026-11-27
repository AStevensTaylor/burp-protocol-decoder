package protocoldecoder.scan;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import protocoldecoder.App;
import protocoldecoder.BlazorDecoderTest;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.core.OverrideStore;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.rules.Condition;
import protocoldecoder.rules.ConditionField;
import protocoldecoder.rules.Operator;
import protocoldecoder.rules.Rule;
import protocoldecoder.rules.RuleAction;
import protocoldecoder.script.ScriptDefinition;
import protocoldecoder.util.Codecs;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ScanEngineTest {

    KeyValueStore global = KeyValueStore.inMemory();
    App app = new App(new ConfigStore(global, KeyValueStore.inMemory(), s -> { }), s -> { }, s -> { });

    @AfterEach
    void close() {
        app.close();
    }

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    static MessageContext dxRequest(String param) {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/Orders.aspx")
                .requestHeader("Content-Type", "application/x-www-form-urlencoded")
                .requestBody("__EVENTTARGET=&__CALLBACKID=" + enc("ctl00$Main$Grid") + "&__CALLBACKPARAM=" + enc(param) + "&DXScript=1_1")
                .build();
    }

    static List<String> titles(List<Finding> f) {
        return f.stream().map(Finding::title).toList();
    }

    @Test
    void devexpressInsertionPointsKeepLengthsValid() {
        MessageContext m = dxRequest("c0:KV|2;[];GB|20;12|PAGERONCLICK3|PN1;");
        List<InsertionPoint> ips = app.scanEngine().insertionPoints(m);
        List<String> names = ips.stream().map(InsertionPoint::name).toList();
        assertTrue(names.contains("DevExpress: __CALLBACKPARAM GB[1]"), names.toString());
        InsertionPoint pn = ips.stream().filter(i -> i.name().endsWith("GB[1]")).findFirst().orElseThrow();
        assertEquals("PN1", pn.baseValue());
        String newBody = new String(pn.render().apply("x' OR 1=1--"), StandardCharsets.ISO_8859_1);
        String param = Codecs.first(Codecs.parseQuery(newBody), "__CALLBACKPARAM");
        // 12|PAGERONCLICK + 11|x' OR 1=1-- = 15 + 14 = 29 chars inside GB
        assertEquals("c0:KV|2;[];GB|29;12|PAGERONCLICK11|x' OR 1=1--;", param);
        assertTrue(newBody.startsWith("__EVENTTARGET=&__CALLBACKID=ctl00%24Main%24Grid&"), "other fields untouched: " + newBody);
        // the mutated message still decodes structurally
        assertTrue(app.engine().decode(dxRequest(param)).ok());
    }

    @Test
    void insertionPointsCanBeDisabledPerProtocol() {
        app.scanEngine().setEnabled("devexpress.insertion-points", false);
        assertTrue(app.scanEngine().insertionPoints(dxRequest("c0:GB|3;1|a;")).isEmpty());
        assertTrue(global.get("protocoldecoder.disabledChecks").contains("devexpress.insertion-points"));
    }

    @Test
    void jsonLeavesReplaceIndividually() {
        var leaves = InsertionPoints.jsonLeaves(com.google.gson.JsonParser.parseString("{\"a\":1,\"b\":[\"x\",{\"c\":true}]}"));
        assertEquals(List.of("$.a", "$.b[0]", "$.b[1].c"), leaves.stream().map(InsertionPoints.JsonLeaf::path).toList());
        assertEquals("{\"a\":1,\"b\":[\"PAY\\\"LOAD\",{\"c\":true}]}", leaves.get(1).replace().apply("PAY\"LOAD"));
    }

    @Test
    void protocolDetectedAndCallbackErrorPassive() {
        MessageContext resp = dxRequest("c0:GB|3;1|a;").withKind(MessageKind.RESPONSE);
        resp = MessageContext.builder(MessageKind.RESPONSE).method("POST").url("https://app.example.com/Orders.aspx")
                .requestHeader("Content-Type", "application/x-www-form-urlencoded").requestBody(dxRequest("c0:GB|3;1|a;").requestBody())
                .statusCode(200)
                .responseBody("0|/*DX*/({'id':1,'error':{'message':'System.NullReferenceException: Object reference not set\\r\\n   at Shop.Orders.Grid_CustomCallback(Object sender) in C:\\\\src\\\\Orders.aspx.cs:line 42'}})")
                .build();
        List<Finding> f = app.scanEngine().passive(resp, true);
        assertTrue(titles(f).contains("Protocol detected: DevExpress"), titles(f).toString());
        Finding err = f.stream().filter(x -> x.checkId().equals("devexpress.callback-error")).findFirst().orElseThrow();
        assertEquals("DevExpress callback discloses exception details", err.title());
        assertEquals(Severity.LOW, err.severity());
        assertFalse(err.evidence().isEmpty());
        // protocol-detected can be switched off
        app.scanEngine().setEnabled(ScanEngine.DETECTED_CHECK, false);
        assertFalse(titles(app.scanEngine().passive(resp, true)).contains("Protocol detected: DevExpress"));
    }

    @Test
    void newRelicSensitiveTelemetry() {
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST")
                .url("https://bam.nr-data.net/ins/1/NRJS-abc?a=1&ja=" + enc("{\"userEmail\":\"alice@example.com\"}"))
                .requestBody("{\"ins\":[{\"actionName\":\"login\",\"password\":\"hunter22\"}]}").build();
        List<Finding> f = app.scanEngine().passive(m, false);
        Finding s = f.stream().filter(x -> x.checkId().equals("newrelic.sensitive-telemetry")).findFirst().orElseThrow();
        assertTrue(s.detail().contains("alice@example.com"), s.detail());
        assertTrue(s.detail().contains("hunter22"), s.detail());
    }

    @Test
    void blazorDetailedErrorsOverWebSocket() {
        byte[] frame = BlazorDecoderTest.frames(BlazorDecoderTest.l(1, Map.of(), null, "JS.Error",
                BlazorDecoderTest.l("System.InvalidOperationException: boom\n   at MyApp.Pages.Index.OnClick() in /src/Index.razor:line 12")));
        MessageContext m = MessageContext.builder(MessageKind.WEBSOCKET).method("GET").url("https://app.example.com/_blazor?id=t")
                .webSocket("SERVER_TO_CLIENT", frame).build();
        List<Finding> f = app.scanEngine().passive(m, false);
        assertTrue(titles(f).contains("Blazor Server detailed errors enabled"), titles(f).toString());
    }

    @Test
    void dontDecodeRuleSilencesScanning() {
        MessageContext m = dxRequest("c0:GB|3;1|a;");
        app.rules().add(new Rule().name("quiet").action(RuleAction.DO_NOT_DECODE)
                .addCondition(new Condition(ConditionField.HOST, Operator.EQUALS, "app.example.com")));
        assertTrue(app.scanEngine().passive(m, true).isEmpty());
        assertTrue(app.scanEngine().insertionPoints(m).isEmpty());
    }

    @Test
    void manualOverrideAddsForcedProtocol() {
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://x.example.com/api")
                .requestBody("__CALLBACKPARAM=" + enc("c0:GB|3;1|a;")).build();
        assertTrue(app.scanEngine().insertionPoints(m).stream().anyMatch(i -> i.name().startsWith("DevExpress")) == false
                || app.engine().resolve(m).hasDecoder());
        app.overrides().set(m, "devexpress");
        assertFalse(app.scanEngine().insertionPoints(m).isEmpty());
        app.overrides().set(m, OverrideStore.NONE);
        assertTrue(app.scanEngine().insertionPoints(m).isEmpty());
    }

    @Test
    void scriptPassiveCheck() {
        String src = """
                function match(msg) { return msg.path === '/api/rpc' ? 80 : 0; }
                function decode(msg) { return { data: JSON.parse(msg.bodyText) }; }
                function passive(msg) {
                  var o = JSON.parse(msg.bodyText);
                  if (o.debug) return [{ title: 'RPC debug flag set', severity: 'medium', confidence: 'firm',
                                         detail: 'debug=<true>', evidence: ['"debug":true'] }];
                  return [];
                }""";
        assertNull(app.saveScript(null, new ScriptDefinition("rpc", "RPC", "", src)));
        MessageContext m = MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://x.example.com/api/rpc")
                .requestBody("{\"debug\":true}").build();
        List<Finding> f = app.scanEngine().passive(m, false);
        assertEquals(1, f.size());
        assertEquals(Severity.MEDIUM, f.get(0).severity());
        assertEquals("debug=&lt;true&gt;", f.get(0).detail()); // escaped
        assertTrue(app.scanEngine().checks().stream().anyMatch(c -> c.id().equals("script.rpc.passive")));
    }

    @Test
    void activeMalformedCallbackProbe() {
        List<String> sentBodies = new ArrayList<>();
        HttpSender fake = new HttpSender() {
            @Override
            public Exchange send(String method, String pathAndQuery, List<Header> headers, byte[] body) {
                sentBodies.add(new String(body, StandardCharsets.ISO_8859_1));
                MessageContext m = MessageContext.builder(MessageKind.REQUEST).method(method).url("https://app.example.com" + pathAndQuery)
                        .requestBody(body).statusCode(500)
                        .responseBody("<b>Exception Details: </b>System.FormatException: Input string was not in a correct format.<br>   at DevExpress.Web.Internal.CallbackArgumentsReader.ReadLength()")
                        .build();
                return new Exchange(m, null);
            }

            @Override
            public Exchange send(InsertionPoint point, String payload) {
                throw new UnsupportedOperationException();
            }
        };
        MessageContext base = dxRequest("c0:KV|2;[];GB|20;12|PAGERONCLICK3|PN1;");
        List<Finding> f = app.scanEngine().active(ActiveCheck.Scope.PER_REQUEST, base, null, null, null, null, fake);
        assertEquals(1, sentBodies.size());
        assertTrue(Codecs.first(Codecs.parseQuery(sentBodies.get(0)), "__CALLBACKPARAM").contains("|99999;"));
        assertEquals(1, f.size());
        assertEquals(1, f.get(0).exchanges().size());
        // disabled active check does nothing
        app.scanEngine().setEnabled("devexpress.malformed-callback", false);
        assertTrue(app.scanEngine().active(ActiveCheck.Scope.PER_REQUEST, base, null, null, null, null, fake).isEmpty());
    }

    @Test
    void sensitivePatterns() {
        assertTrue(ScanPatterns.luhn("4111111111111111"));
        assertFalse(ScanPatterns.luhn("4111111111111112"));
        assertNotNull(ScanPatterns.exceptionEvidence("java.lang.IllegalStateException: x\n\tat com.acme.Foo.bar(Foo.java:10)"));
        assertNull(ScanPatterns.exceptionEvidence("everything is fine"));
    }
}
