package protocoldecoder.rules;

import protocoldecoder.core.MessageContext;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * A user-defined rule that overrides auto-detection: when it matches a message, the message is decoded with a chosen
 * decoder (or not decoded at all). Rules are evaluated top to bottom and the first match wins.
 */
public final class Rule {

    public enum MatchMode { ALL, ANY }

    private String id = UUID.randomUUID().toString();
    private String name = "New rule";
    private boolean enabled = true;
    private RuleTarget target = RuleTarget.ANY;
    private MatchMode mode = MatchMode.ALL;
    private List<Condition> conditions = new ArrayList<>();
    private RuleAction action = RuleAction.DECODE_AS;
    private String decoderId = "";

    public String id() { return id; }
    public String name() { return name == null ? "" : name; }
    public boolean enabled() { return enabled; }
    public RuleTarget target() { return target == null ? RuleTarget.ANY : target; }
    public MatchMode mode() { return mode == null ? MatchMode.ALL : mode; }
    public List<Condition> conditions() {
        if (conditions == null) conditions = new ArrayList<>();
        return conditions;
    }
    public RuleAction action() { return action == null ? RuleAction.DECODE_AS : action; }
    public String decoderId() { return decoderId == null ? "" : decoderId; }

    public Rule name(String v) { this.name = v; return this; }
    public Rule enabled(boolean v) { this.enabled = v; return this; }
    public Rule target(RuleTarget v) { this.target = v; return this; }
    public Rule mode(MatchMode v) { this.mode = v; return this; }
    public Rule action(RuleAction v) { this.action = v; return this; }
    public Rule decoderId(String v) { this.decoderId = v; return this; }
    public Rule conditions(List<Condition> v) { this.conditions = new ArrayList<>(v); return this; }
    public Rule addCondition(Condition c) { conditions().add(c); return this; }

    /** True when the rule is enabled, applies to this kind of message and its conditions hold. */
    public boolean matches(MessageContext m) {
        if (!enabled || !target().applies(m.kind())) return false;
        List<Condition> cs = conditions();
        if (cs.isEmpty()) return true;
        if (mode() == MatchMode.ALL) {
            for (Condition c : cs) if (!c.test(m)) return false;
            return true;
        }
        for (Condition c : cs) if (c.test(m)) return true;
        return false;
    }

    /** Returns null if valid, else a description of the first problem. */
    public String validate() {
        if (name().isBlank()) return "rule name is required";
        if (action() == RuleAction.DECODE_AS && decoderId().isBlank()) return "choose a decoder";
        for (Condition c : conditions()) {
            String err = c.validate();
            if (err != null) return err;
        }
        return null;
    }

    public String describeConditions() {
        if (conditions().isEmpty()) return "(always)";
        String joiner = mode() == MatchMode.ALL ? " AND " : " OR ";
        return conditions().stream().map(Condition::describe).collect(Collectors.joining(joiner));
    }

    public Rule copy() {
        Rule r = new Rule();
        r.id = id;
        r.name = name;
        r.enabled = enabled;
        r.target = target;
        r.mode = mode;
        r.conditions = conditions().stream().map(Condition::copy).collect(Collectors.toCollection(ArrayList::new));
        r.action = action;
        r.decoderId = decoderId;
        return r;
    }

    /** Copy with a fresh id (for "duplicate"). */
    public Rule duplicate() {
        Rule r = copy();
        r.id = UUID.randomUUID().toString();
        r.name = name() + " (copy)";
        return r;
    }
}
