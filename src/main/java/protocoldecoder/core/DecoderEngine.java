package protocoldecoder.core;

import protocoldecoder.rules.Rule;
import protocoldecoder.rules.RuleAction;
import protocoldecoder.rules.RuleSet;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Decides which decoder handles a message (manual override → first matching rule → best auto-match) and runs it.
 * Resolution results are cached per message content; any change to decoders, rules or overrides invalidates the cache.
 */
public final class DecoderEngine {

    /** Outcome of running a decoder. Exactly one of result / error is non-null. */
    public record Outcome(Resolution resolution, DecodeResult result, String error, long millis) {
        public boolean ok() {
            return result != null;
        }
    }

    /** A decoder and how well it matches a message, for "decode as" pickers. */
    public record Candidate(ProtocolDecoder decoder, MatchResult match) {
    }

    private static final int CACHE_SIZE = 2048;

    private final DecoderRegistry registry;
    private final RuleSet rules;
    private final OverrideStore overrides;
    private final AtomicLong generation = new AtomicLong();
    private final Map<String, Resolution> cache = new LinkedHashMap<>(256, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Resolution> eldest) {
            return size() > CACHE_SIZE;
        }
    };
    private volatile Consumer<String> errorLog = s -> { };

    public DecoderEngine(DecoderRegistry registry, RuleSet rules, OverrideStore overrides) {
        this.registry = registry;
        this.rules = rules;
        this.overrides = overrides;
        registry.addListener(this::invalidate);
        rules.addListener(this::invalidate);
        overrides.addListener(this::invalidate);
    }

    public DecoderRegistry registry() { return registry; }
    public RuleSet rules() { return rules; }
    public OverrideStore overrides() { return overrides; }

    public void setErrorLog(Consumer<String> log) {
        this.errorLog = log == null ? s -> { } : log;
    }

    /** Monotonic counter bumped whenever configuration changes; views use it to know when to refresh. */
    public long generation() {
        return generation.get();
    }

    public void invalidate() {
        synchronized (cache) {
            cache.clear();
        }
        generation.incrementAndGet();
    }

    public Resolution resolve(MessageContext m) {
        String key = m.contentFingerprint();
        synchronized (cache) {
            Resolution r = cache.get(key);
            if (r != null) return r;
        }
        long gen = generation.get();
        Resolution r = computeResolution(m);
        synchronized (cache) {
            // Don't cache a result computed against configuration that changed meanwhile.
            if (gen == generation.get()) cache.put(key, r);
        }
        return r;
    }

    private Resolution computeResolution(MessageContext m) {
        OverrideStore.Entry o = overrides.get(m.overrideKey());
        if (o != null) {
            if (OverrideStore.NONE.equals(o.decoderId())) {
                return new Resolution(null, Resolution.Source.OVERRIDE, MatchResult.NONE, "");
            }
            ProtocolDecoder d = registry.byId(o.decoderId()).orElse(null);
            if (d != null) return new Resolution(d, Resolution.Source.OVERRIDE, MatchResult.NONE, "");
            // decoder was deleted: fall through to rules/auto
        }

        Rule rule = rules.firstMatch(m);
        if (rule != null) {
            if (rule.action() == RuleAction.DO_NOT_DECODE) {
                return new Resolution(null, Resolution.Source.RULE, MatchResult.NONE, rule.name());
            }
            ProtocolDecoder d = registry.byId(rule.decoderId()).orElse(null);
            if (d != null) return new Resolution(d, Resolution.Source.RULE, MatchResult.NONE, rule.name());
            errorLog.accept("Rule \"" + rule.name() + "\" refers to unknown decoder '" + rule.decoderId() + "'; ignoring it");
        }

        ProtocolDecoder best = null;
        MatchResult bestMatch = MatchResult.NONE;
        for (ProtocolDecoder d : registry.enabled()) {
            MatchResult mr = safeMatch(d, m);
            if (mr.confidence() > bestMatch.confidence()) {
                best = d;
                bestMatch = mr;
            }
        }
        return best == null ? Resolution.NOTHING : new Resolution(best, Resolution.Source.AUTO, bestMatch, "");
    }

    /** All decoders (enabled or not) with their match confidence, best first, for "decode as" pickers. */
    public List<Candidate> candidates(MessageContext m) {
        List<Candidate> out = new ArrayList<>();
        for (ProtocolDecoder d : registry.all()) {
            out.add(new Candidate(d, registry.isEnabled(d.id()) ? safeMatch(d, m) : MatchResult.NONE));
        }
        out.sort(Comparator.comparingInt((Candidate c) -> -c.match().confidence()));
        return out;
    }

    private MatchResult safeMatch(ProtocolDecoder d, MessageContext m) {
        try {
            MatchResult r = d.match(m);
            return r == null ? MatchResult.NONE : r;
        } catch (RuntimeException | StackOverflowError e) {
            errorLog.accept("Matcher of decoder '" + d.id() + "' failed: " + e);
            return MatchResult.NONE;
        }
    }

    /** Resolves and decodes. */
    public Outcome decode(MessageContext m) {
        return decode(m, resolve(m));
    }

    public Outcome decode(MessageContext m, Resolution r) {
        if (!r.hasDecoder()) return new Outcome(r, null, r.describe(), 0);
        return decodeWith(m, r.decoder(), r);
    }

    /** Decodes with a specific decoder, regardless of matching. */
    public Outcome decodeWith(MessageContext m, ProtocolDecoder d, Resolution r) {
        long start = System.nanoTime();
        try {
            DecodeResult res = d.decode(m);
            long ms = (System.nanoTime() - start) / 1_000_000;
            if (res == null) return new Outcome(r, null, d.name() + " returned no result", ms);
            return new Outcome(r, res, null, ms);
        } catch (DecodeException e) {
            return new Outcome(r, null, e.getMessage(), (System.nanoTime() - start) / 1_000_000);
        } catch (RuntimeException | StackOverflowError e) {
            errorLog.accept("Decoder '" + d.id() + "' crashed on " + m + ": " + e);
            return new Outcome(r, null, d.name() + " failed: " + e, (System.nanoTime() - start) / 1_000_000);
        }
    }
}
