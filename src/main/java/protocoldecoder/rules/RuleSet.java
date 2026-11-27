package protocoldecoder.rules;

import protocoldecoder.core.MessageContext;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/** Ordered, thread-safe list of rules. Readers see an immutable snapshot; edits replace the list. */
public final class RuleSet {

    private volatile List<Rule> rules = List.of();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    public List<Rule> rules() {
        return rules;
    }

    /** Replaces all rules (copies them so later edits to the passed objects don't leak in). */
    public void setRules(List<Rule> newRules) {
        List<Rule> copy = new ArrayList<>();
        for (Rule r : newRules) copy.add(r.copy());
        this.rules = List.copyOf(copy);
        listeners.forEach(Runnable::run);
    }

    public void add(Rule r) {
        List<Rule> copy = new ArrayList<>(rules);
        copy.add(r);
        setRules(copy);
    }

    /** First enabled rule that matches, or null. */
    public Rule firstMatch(MessageContext m) {
        for (Rule r : rules) {
            if (r.matches(m)) return r;
        }
        return null;
    }

    public void addListener(Runnable l) {
        listeners.add(l);
    }
}
