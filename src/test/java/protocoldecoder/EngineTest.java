package protocoldecoder;

import org.junit.jupiter.api.Test;
import protocoldecoder.builtin.devexpress.DevExpressDecoder;
import protocoldecoder.builtin.newrelic.NewRelicDecoder;
import protocoldecoder.core.DecoderEngine;
import protocoldecoder.core.DecoderRegistry;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.core.OverrideStore;
import protocoldecoder.core.Resolution;
import protocoldecoder.persistence.ConfigCodec;
import protocoldecoder.rules.Condition;
import protocoldecoder.rules.ConditionField;
import protocoldecoder.rules.Operator;
import protocoldecoder.rules.Rule;
import protocoldecoder.rules.RuleAction;
import protocoldecoder.rules.RuleSet;
import protocoldecoder.rules.RuleTarget;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class EngineTest {

    DecoderRegistry registry = new DecoderRegistry();
    RuleSet rules = new RuleSet();
    OverrideStore overrides = new OverrideStore();
    DecoderEngine engine = new DecoderEngine(registry, rules, overrides);

    {
        registry.register(new DevExpressDecoder());
        registry.register(new NewRelicDecoder());
    }

    MessageContext dxWithNrHeader() {
        return MessageContext.builder(MessageKind.REQUEST).method("POST").url("https://app.example.com/a.aspx")
                .requestHeader("Content-Type", "application/x-www-form-urlencoded")
                .requestHeader("newrelic", "eyJ2IjpbMCwxXX0=")
                .requestBody("__CALLBACKID=g&__CALLBACKPARAM=c0%3AKV%7C2%3B%5B%5D%3B").build();
    }

    @Test
    void highestConfidenceWins() {
        Resolution r = engine.resolve(dxWithNrHeader());
        assertEquals(Resolution.Source.AUTO, r.source());
        assertEquals("devexpress", r.decoder().id());
        List<DecoderEngine.Candidate> c = engine.candidates(dxWithNrHeader());
        assertEquals("devexpress", c.get(0).decoder().id());
        assertEquals("newrelic", c.get(1).decoder().id());
        assertTrue(c.get(1).match().matched());
    }

    @Test
    void ruleOverridesAutoDetection() {
        rules.add(new Rule().name("force NR").target(RuleTarget.REQUEST).decoderId("newrelic")
                .addCondition(new Condition(ConditionField.HOST, Operator.ENDS_WITH, "EXAMPLE.com"))
                .addCondition(new Condition(ConditionField.REQUEST_HEADER, "NewRelic", Operator.EXISTS, "")));
        Resolution r = engine.resolve(dxWithNrHeader());
        assertEquals(Resolution.Source.RULE, r.source());
        assertEquals("newrelic", r.decoder().id());
        assertEquals("force NR", r.detail());
    }

    @Test
    void ruleCanDisableDecoding() {
        rules.add(new Rule().name("off").action(RuleAction.DO_NOT_DECODE)
                .addCondition(new Condition(ConditionField.REQUEST_BODY, Operator.MATCHES_REGEX, "__CALLBACKPARAM=c\\d")));
        assertFalse(engine.resolve(dxWithNrHeader()).hasDecoder());
    }

    @Test
    void ruleTargetRespected() {
        rules.add(new Rule().name("resp only").target(RuleTarget.RESPONSE).decoderId("newrelic"));
        assertEquals(Resolution.Source.AUTO, engine.resolve(dxWithNrHeader()).source());
    }

    @Test
    void disabledRulesAndDecodersIgnored() {
        rules.add(new Rule().name("x").enabled(false).decoderId("newrelic"));
        registry.setEnabled("devexpress", false);
        Resolution r = engine.resolve(dxWithNrHeader());
        assertEquals("newrelic", r.decoder().id());
        assertEquals(Resolution.Source.AUTO, r.source());
    }

    @Test
    void overrideBeatsRules() {
        rules.add(new Rule().name("off").action(RuleAction.DO_NOT_DECODE));
        MessageContext m = dxWithNrHeader();
        overrides.set(m, "newrelic");
        Resolution r = engine.resolve(m);
        assertEquals(Resolution.Source.OVERRIDE, r.source());
        assertEquals("newrelic", r.decoder().id());
        // keyed per exchange: rebuilt message object still hits the override; the response side doesn't
        assertEquals(Resolution.Source.OVERRIDE, engine.resolve(dxWithNrHeader()).source());
        assertNotEquals(Resolution.Source.OVERRIDE, engine.resolve(m.withKind(MessageKind.RESPONSE)).source());
        overrides.set(m, OverrideStore.NONE);
        assertFalse(engine.resolve(m).hasDecoder());
    }

    @Test
    void negativeOperatorsOnMissingValues() {
        MessageContext m = dxWithNrHeader();
        assertTrue(new Condition(ConditionField.RESPONSE_HEADER, "X", Operator.NOT_CONTAINS, "a").test(m));
        assertFalse(new Condition(ConditionField.RESPONSE_HEADER, "X", Operator.CONTAINS, "a").test(m));
        assertTrue(new Condition(ConditionField.REQUEST_HEADER, "x-missing", Operator.NOT_EXISTS, "").test(m));
    }

    @Test
    void rulesRoundTripThroughJson() {
        Rule r = new Rule().name("n").target(RuleTarget.HTTP).mode(Rule.MatchMode.ANY).decoderId("devexpress")
                .addCondition(new Condition(ConditionField.REQUEST_HEADER, "X-Test", Operator.MATCHES_REGEX, "^a+$").caseSensitive(true));
        String json = ConfigCodec.rulesToJson(List.of(r));
        List<Rule> back = ConfigCodec.rulesFromJson(json);
        assertEquals(1, back.size());
        assertEquals(r.describeConditions(), back.get(0).describeConditions());
        assertEquals(RuleTarget.HTTP, back.get(0).target());
        assertTrue(back.get(0).conditions().get(0).caseSensitive());
    }
}
