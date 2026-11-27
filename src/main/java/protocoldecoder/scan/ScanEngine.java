package protocoldecoder.scan;

import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecoderEngine;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.ProtocolDecoder;
import protocoldecoder.core.Resolution;
import protocoldecoder.script.ScriptDecoder;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Runs protocol scanner checks. For each message it works out which protocols apply — every enabled decoder whose
 * matcher recognises the message, plus a decoder forced by a rule or manual choice — decodes the message with each,
 * and runs that protocol's checks. A rule or manual choice of "don't decode" also excludes the message from scanning.
 */
public final class ScanEngine {

    /** Id of the built-in "protocol detected" informational check. */
    public static final String DETECTED_CHECK = "core.protocol-detected";
    /** Minimum auto-detect confidence for the "protocol detected" issue. */
    static final int DETECTED_MIN_CONFIDENCE = 70;

    /** A decoder that applies to a message, with its decode result (null if decoding failed). */
    public record Applicable(ProtocolDecoder decoder, MatchResult match, boolean forced, DecodeResult decoded) {
    }

    private final DecoderEngine engine;
    private final List<ProtocolScanner> scanners = new CopyOnWriteArrayList<>();
    /** Check instances fetched once per scanner, so checks may keep state (e.g. "already probed this host"). */
    private final Map<ProtocolScanner, List<PassiveCheck>> passiveByScanner = new ConcurrentHashMap<>();
    private final Map<ProtocolScanner, List<ActiveCheck>> activeByScanner = new ConcurrentHashMap<>();
    private final Set<String> disabledChecks = ConcurrentHashMap.newKeySet();
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();
    private volatile Consumer<String> errorLog = s -> { };

    public ScanEngine(DecoderEngine engine) {
        this.engine = engine;
    }

    public void setErrorLog(Consumer<String> log) {
        this.errorLog = log == null ? s -> { } : log;
    }

    public void register(ProtocolScanner s) {
        for (ProtocolScanner old : scanners) {
            if (old.getClass().equals(s.getClass()) && old.decoderId().equals(s.decoderId())) {
                scanners.remove(old);
                passiveByScanner.remove(old);
                activeByScanner.remove(old);
            }
        }
        passiveByScanner.put(s, List.copyOf(s.passiveChecks()));
        activeByScanner.put(s, List.copyOf(s.activeChecks()));
        scanners.add(s);
        fire();
    }

    private List<PassiveCheck> passiveOf(ProtocolScanner s) {
        return passiveByScanner.getOrDefault(s, List.of());
    }

    private List<ActiveCheck> activeOf(ProtocolScanner s) {
        return activeByScanner.getOrDefault(s, List.of());
    }

    public List<ProtocolScanner> scanners() {
        return List.copyOf(scanners);
    }

    // ---------------------------------------------------------------- check catalogue / enablement

    /** Every check, for the UI. Script passive checks are included for scripts that define passive(). */
    public List<CheckInfo> checks() {
        List<CheckInfo> out = new ArrayList<>();
        out.add(new CheckInfo(DETECTED_CHECK, "Protocol detected", "Informational issue (once per host) naming each protocol found", "", CheckInfo.Kind.PASSIVE, null));
        for (ProtocolScanner s : scanners) {
            for (PassiveCheck c : passiveOf(s)) out.add(new CheckInfo(c.id(), c.name(), c.description(), s.decoderId(), CheckInfo.Kind.PASSIVE, null));
            for (ActiveCheck c : activeOf(s)) out.add(new CheckInfo(c.id(), c.name(), c.description(), s.decoderId(), CheckInfo.Kind.ACTIVE, c.scope()));
            out.add(new CheckInfo(insertionPointsId(s.decoderId()), "Protocol-aware insertion points",
                    "Lets Burp's scanner put payloads inside " + s.decoderId() + " encodings", s.decoderId(), CheckInfo.Kind.INSERTION_POINTS, null));
        }
        for (ProtocolDecoder d : engine.registry().all()) {
            if (d instanceof ScriptDecoder sd && sd.hasPassive()) {
                out.add(new CheckInfo(scriptCheckId(sd.id()), sd.name() + " — passive()", "User script passive check", sd.id(), CheckInfo.Kind.PASSIVE, null));
            }
        }
        // Insertion point entries only for scanners that actually provide them is unknowable statically; keep them all.
        return out;
    }

    static String insertionPointsId(String decoderId) {
        return decoderId + ".insertion-points";
    }

    static String scriptCheckId(String scriptId) {
        return "script." + scriptId + ".passive";
    }

    public boolean isEnabled(String checkId) {
        return !disabledChecks.contains(checkId);
    }

    public void setEnabled(String checkId, boolean enabled) {
        boolean changed = enabled ? disabledChecks.remove(checkId) : disabledChecks.add(checkId);
        if (changed) fire();
    }

    public Set<String> disabledIds() {
        return Set.copyOf(disabledChecks);
    }

    public void setDisabledIds(Set<String> ids) {
        disabledChecks.clear();
        disabledChecks.addAll(ids);
        fire();
    }

    public void addListener(Runnable r) {
        listeners.add(r);
    }

    private void fire() {
        listeners.forEach(Runnable::run);
    }

    // ---------------------------------------------------------------- applicability

    /** Decoders that apply to this message (in this kind), each decoded once. */
    public List<Applicable> applicable(MessageContext m) {
        Resolution r = engine.resolve(m);
        if (!r.hasDecoder() && (r.source() == Resolution.Source.RULE || r.source() == Resolution.Source.OVERRIDE)) {
            return List.of(); // user said "don't decode" this message
        }
        Map<String, Applicable> out = new LinkedHashMap<>();
        if (r.hasDecoder() && r.source() != Resolution.Source.AUTO) {
            out.put(r.decoder().id(), new Applicable(r.decoder(), MatchResult.NONE, true, decode(m, r.decoder())));
        }
        for (ProtocolDecoder d : engine.registry().enabled()) {
            if (out.containsKey(d.id())) continue;
            MatchResult mr = safeMatch(d, m);
            if (mr.matched()) out.put(d.id(), new Applicable(d, mr, false, decode(m, d)));
        }
        return new ArrayList<>(out.values());
    }

    private MatchResult safeMatch(ProtocolDecoder d, MessageContext m) {
        try {
            MatchResult r = d.match(m);
            return r == null ? MatchResult.NONE : r;
        } catch (RuntimeException e) {
            return MatchResult.NONE;
        }
    }

    private DecodeResult decode(MessageContext m, ProtocolDecoder d) {
        DecoderEngine.Outcome o = engine.decodeWith(m, d, Resolution.NOTHING);
        return o.ok() ? o.result() : null;
    }

    private List<ProtocolScanner> scannersFor(String decoderId) {
        List<ProtocolScanner> out = new ArrayList<>();
        for (ProtocolScanner s : scanners) if (s.decoderId().equals(decoderId)) out.add(s);
        return out;
    }

    // ---------------------------------------------------------------- passive

    /** Runs passive checks on one message (REQUEST, RESPONSE or WEBSOCKET). */
    public List<Finding> passive(MessageContext m, boolean reportDetected) {
        List<Finding> out = new ArrayList<>();
        for (Applicable a : applicable(m)) {
            ProtocolDecoder d = a.decoder();
            if (reportDetected && isEnabled(DETECTED_CHECK) && !a.forced() && a.match().confidence() >= DETECTED_MIN_CONFIDENCE) {
                out.add(Finding.of(DETECTED_CHECK, "Protocol detected: " + d.name())
                        .severity(Severity.INFORMATION).confidence(a.match().confidence() >= 90 ? Confidence.CERTAIN : Confidence.FIRM)
                        .scope(Finding.Scope.HOST)
                        .detail("The application uses <b>" + Finding.esc(d.name()) + "</b> (" + Finding.esc(a.match().reason())
                                + "). The Protocol Decoder tab shows decoded messages; protocol-specific checks run when this protocol is seen.")
                        .background(Finding.esc(d.description())));
            }
            for (ProtocolScanner s : scannersFor(d.id())) {
                for (PassiveCheck c : passiveOf(s)) {
                    if (!isEnabled(c.id())) continue;
                    try {
                        List<Finding> f = c.check(m, a.decoded());
                        if (f != null) out.addAll(f);
                    } catch (RuntimeException | StackOverflowError e) {
                        errorLog.accept("Passive check " + c.id() + " failed on " + m + ": " + e);
                    }
                }
            }
            if (d instanceof ScriptDecoder sd && sd.hasPassive() && isEnabled(scriptCheckId(sd.id()))) {
                out.addAll(sd.passive(m));
            }
        }
        return out;
    }

    // ---------------------------------------------------------------- insertion points

    /** Protocol-aware insertion points for a request (kind REQUEST). */
    public List<InsertionPoint> insertionPoints(MessageContext request) {
        return insertionPoints(request, true);
    }

    /**
     * Protocol-aware insertion points for a request.
     *
     * @param respectToggles false to ignore the per-protocol "insertion points" switches (used by editing)
     */
    public List<InsertionPoint> insertionPoints(MessageContext request, boolean respectToggles) {
        List<InsertionPoint> out = new ArrayList<>();
        for (Applicable a : applicable(request)) {
            if (respectToggles && !isEnabled(insertionPointsId(a.decoder().id()))) continue;
            for (ProtocolScanner s : scannersFor(a.decoder().id())) {
                try {
                    List<InsertionPoint> ips = s.insertionPoints(request, a.decoded());
                    if (ips != null) out.addAll(ips);
                } catch (RuntimeException e) {
                    errorLog.accept("Insertion points for " + a.decoder().id() + " failed: " + e);
                }
            }
        }
        return out;
    }

    // ---------------------------------------------------------------- active

    /**
     * Runs active checks of the given scope for protocols that apply to the base exchange (request or response side).
     */
    public List<Finding> active(ActiveCheck.Scope scope, MessageContext request, MessageContext response,
                                String ipName, String ipBase, ActiveContext.PayloadSender payloads, HttpSender http) {
        Map<String, DecodeResult> decoders = new LinkedHashMap<>();
        for (Applicable a : applicable(request)) decoders.put(a.decoder().id(), a.decoded());
        if (response != null) for (Applicable a : applicable(response)) decoders.putIfAbsent(a.decoder().id(), null);
        List<Finding> out = new ArrayList<>();
        for (Map.Entry<String, DecodeResult> e : decoders.entrySet()) {
            ActiveContext ctx = new ActiveContext(request, response, e.getValue(), ipName, ipBase, payloads, http);
            for (ProtocolScanner s : scannersFor(e.getKey())) {
                for (ActiveCheck c : activeOf(s)) {
                    if (c.scope() != scope || !isEnabled(c.id())) continue;
                    try {
                        List<Finding> f = c.run(ctx);
                        if (f != null) out.addAll(f);
                    } catch (RuntimeException e2) {
                        errorLog.accept("Active check " + c.id() + " failed: " + e2);
                    }
                }
            }
        }
        return out;
    }
}
