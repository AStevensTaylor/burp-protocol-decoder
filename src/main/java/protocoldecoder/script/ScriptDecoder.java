package protocoldecoder.script;

import org.mozilla.javascript.NativeArray;
import org.mozilla.javascript.Script;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.ScriptableObject;
import org.mozilla.javascript.Undefined;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.ProtocolDecoder;
import protocoldecoder.scan.ScanIds;
import protocoldecoder.util.Codecs;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

/** A {@link ProtocolDecoder} backed by a sandboxed user script. */
public final class ScriptDecoder implements ProtocolDecoder {

    /** After this many consecutive match() failures the matcher is suspended until the script is replaced. */
    static final int MAX_MATCH_FAILURES = 3;
    private static final Set<String> RESULT_KEYS = Set.of("summary", "data", "text", "warnings");

    /** A match/decode run, with whatever the script logged, for the script tester. */
    public record Trace<T>(T value, String error, List<String> logs, long millis) {
    }

    private final ScriptDefinition definition;
    private final ScriptSandbox sandbox;
    private final Supplier<SandboxLimits> limits;
    private final Script compiled;
    private final String compileError;
    private final boolean hasMatch;
    private final boolean hasPassive;
    private final AtomicInteger consecutiveMatchFailures = new AtomicInteger();
    private volatile String lastError;

    public ScriptDecoder(ScriptDefinition definition, ScriptSandbox sandbox, Supplier<SandboxLimits> limits) {
        this.definition = definition.copy();
        this.sandbox = sandbox;
        this.limits = limits;
        Script s = null;
        String err = null;
        boolean m = false;
        boolean p = false;
        try {
            s = sandbox.compile(definition.source(), definition.id() + ".js");
            m = sandbox.defines(s, "match");
            p = sandbox.defines(s, "passive");
            if (!sandbox.defines(s, "decode")) err = "script does not define a decode(msg) function";
        } catch (ScriptException e) {
            err = e.getMessage();
        }
        this.compiled = err == null ? s : null;
        this.compileError = err;
        this.hasMatch = m;
        this.hasPassive = p && err == null;
    }

    public ScriptDefinition definition() { return definition.copy(); }
    @Override public String id() { return definition.id(); }
    @Override public String name() { return definition.name(); }
    @Override public String description() { return definition.description(); }
    @Override public boolean isBuiltIn() { return false; }

    /** Compile error, or null if the script compiled. */
    public String compileError() { return compileError; }

    public boolean hasMatcher() { return hasMatch; }

    /** Whether the script defines passive(msg) for scanner issues. */
    public boolean hasPassive() { return hasPassive; }

    public boolean matcherSuspended() { return consecutiveMatchFailures.get() >= MAX_MATCH_FAILURES; }

    public void resetMatcher() { consecutiveMatchFailures.set(0); }

    /** Most recent runtime error (match or decode), for the decoder list. */
    public String lastError() { return lastError; }

    /** One-word status for the UI. */
    public String status() {
        if (compileError != null) return "Error: " + compileError;
        if (matcherSuspended()) return "Matcher suspended: " + lastError;
        if (!hasMatch) return "OK (no match(); rules/overrides only)";
        return "OK";
    }

    @Override
    public MatchResult match(MessageContext m) {
        if (compiled == null || !hasMatch || matcherSuspended()) return MatchResult.NONE;
        Trace<MatchResult> t = traceMatch(m);
        if (t.error() != null) {
            lastError = "match(): " + t.error();
            consecutiveMatchFailures.incrementAndGet();
            return MatchResult.NONE;
        }
        consecutiveMatchFailures.set(0);
        return t.value();
    }

    public Trace<MatchResult> traceMatch(MessageContext m) {
        List<String> logs = new ArrayList<>();
        long start = System.nanoTime();
        if (compiled == null) return new Trace<>(MatchResult.NONE, compileError, logs, 0);
        SandboxLimits l = limits.get();
        try {
            MatchResult r = sandbox.invoke(compiled, "match", l.matchTimeoutMs(), new JsMessage.Data(m, l.maxBodyBytes()), logs,
                    (cx, scope, v) -> toMatch(v));
            return new Trace<>(r == null ? MatchResult.NONE : r, null, logs, ms(start));
        } catch (ScriptException e) {
            return new Trace<>(MatchResult.NONE, e.getMessage(), logs, ms(start));
        }
    }

    private static MatchResult toMatch(Object v) {
        if (v instanceof Boolean b) return b ? MatchResult.of(50, "script") : MatchResult.NONE;
        if (v instanceof Number n) return MatchResult.of((int) Math.round(n.doubleValue()), "script");
        if (v instanceof Scriptable s && !(v instanceof NativeArray)) {
            Object c = ScriptableObject.getProperty(s, "confidence");
            Object r = ScriptableObject.getProperty(s, "reason");
            int conf = c instanceof Number n ? (int) Math.round(n.doubleValue()) : (Boolean.TRUE.equals(c) ? 50 : 0);
            String reason = JsConvert.str(r);
            return MatchResult.of(conf, reason == null ? "script" : reason);
        }
        return MatchResult.NONE;
    }

    @Override
    public DecodeResult decode(MessageContext m) throws DecodeException {
        Trace<DecodeResult> t = traceDecode(m);
        if (t.error() != null) {
            lastError = "decode(): " + t.error();
            throw new DecodeException(definition.name() + ": " + t.error());
        }
        return t.value();
    }

    public Trace<DecodeResult> traceDecode(MessageContext m) {
        List<String> logs = new ArrayList<>();
        long start = System.nanoTime();
        if (compiled == null) return new Trace<>(null, compileError, logs, 0);
        SandboxLimits l = limits.get();
        try {
            DecodeResult r = sandbox.invoke(compiled, "decode", l.decodeTimeoutMs(), new JsMessage.Data(m, l.maxBodyBytes()), logs,
                    (cx, scope, v) -> toResult(v, l.maxOutputNodes()));
            if (r == null) return new Trace<>(null, "decode() returned nothing", logs, ms(start));
            return new Trace<>(r, null, logs, ms(start));
        } catch (ScriptException e) {
            return new Trace<>(null, e.getMessage(), logs, ms(start));
        } catch (JsConvert.TooLarge e) {
            return new Trace<>(null, e.getMessage() + " (limit " + l.maxOutputNodes() + ")", logs, ms(start));
        }
    }

    private static DecodeResult toResult(Object v, int maxNodes) throws ScriptException {
        if (v == null || Undefined.isUndefined(v)) return null;
        int[] budget = {maxNodes};
        try {
            if (v instanceof Scriptable s && !(v instanceof NativeArray) && isResultObject(s)) {
                String summary = JsConvert.str(ScriptableObject.getProperty(s, "summary"));
                Object data = ScriptableObject.getProperty(s, "data");
                String text = JsConvert.str(ScriptableObject.getProperty(s, "text"));
                List<String> warnings = JsConvert.strings(ScriptableObject.getProperty(s, "warnings"));
                DecodedNode root = data == Scriptable.NOT_FOUND
                        ? DecodedNode.object("root")
                        : JsConvert.toNode("root", data, budget, 0);
                if (!root.isContainer()) root = DecodedNode.object("root").add(root);
                return new DecodeResult(summary, root, text, warnings);
            }
            DecodedNode node = JsConvert.toNode("root", v, budget, 0);
            if (!node.isContainer()) {
                return new DecodeResult("", DecodedNode.object("root").add(node), v instanceof CharSequence cs ? cs.toString() : null, List.of());
            }
            return new DecodeResult("", node, null, List.of());
        } catch (JsConvert.TooLarge e) {
            throw new ScriptException(e.getMessage() + " (limit " + maxNodes + ")");
        }
    }

    /** Runs the script's passive(msg) check; errors are recorded in lastError and yield no findings. */
    public List<protocoldecoder.scan.Finding> passive(MessageContext m) {
        Trace<List<protocoldecoder.scan.Finding>> t = tracePassive(m);
        if (t.error() != null) {
            lastError = "passive(): " + t.error();
            return List.of();
        }
        return t.value();
    }

    public Trace<List<protocoldecoder.scan.Finding>> tracePassive(MessageContext m) {
        List<String> logs = new ArrayList<>();
        long start = System.nanoTime();
        if (compiled == null || !hasPassive) return new Trace<>(List.of(), compileError, logs, 0);
        SandboxLimits l = limits.get();
        try {
            List<protocoldecoder.scan.Finding> r = sandbox.invoke(compiled, "passive", l.decodeTimeoutMs(), new JsMessage.Data(m, l.maxBodyBytes()), logs,
                    (cx, scope, v) -> toFindings(v, m));
            return new Trace<>(r == null ? List.of() : r, null, logs, ms(start));
        } catch (ScriptException e) {
            return new Trace<>(List.of(), e.getMessage(), logs, ms(start));
        }
    }

    private List<protocoldecoder.scan.Finding> toFindings(Object v, MessageContext m) {
        List<protocoldecoder.scan.Finding> out = new ArrayList<>();
        if (v == null || Undefined.isUndefined(v)) return out;
        List<Object> items = new ArrayList<>();
        if (v instanceof NativeArray arr) {
            for (int i = 0; i < arr.getLength() && i < 50; i++) items.add(arr.get(i, arr));
        } else {
            items.add(v);
        }
        for (Object item : items) {
            if (!(item instanceof Scriptable s)) continue;
            String title = JsConvert.str(ScriptableObject.getProperty(s, "title"));
            if (title == null || title.isBlank()) continue;
            protocoldecoder.scan.Finding f = protocoldecoder.scan.Finding.of(ScanIds.scriptCheck(definition.id()), Codecs.truncate(title, 200))
                    .severity(enumOr(protocoldecoder.scan.Severity.class, JsConvert.str(ScriptableObject.getProperty(s, "severity")), protocoldecoder.scan.Severity.INFORMATION))
                    .confidence(enumOr(protocoldecoder.scan.Confidence.class, JsConvert.str(ScriptableObject.getProperty(s, "confidence")), protocoldecoder.scan.Confidence.TENTATIVE))
                    .detail(htmlText(JsConvert.str(ScriptableObject.getProperty(s, "detail"))))
                    .remediation(htmlText(JsConvert.str(ScriptableObject.getProperty(s, "remediation"))))
                    .background("Reported by the custom decoder script \"" + protocoldecoder.scan.Finding.esc(definition.name()) + "\".");
            boolean inResponse = "response".equalsIgnoreCase(String.valueOf(JsConvert.str(ScriptableObject.getProperty(s, "evidenceIn"))));
            for (String e : JsConvert.strings(ScriptableObject.getProperty(s, "evidence"))) {
                f.evidence(new protocoldecoder.scan.Evidence(inResponse ? protocoldecoder.core.MessageKind.RESPONSE : m.kind() == protocoldecoder.core.MessageKind.RESPONSE
                        ? protocoldecoder.core.MessageKind.RESPONSE : protocoldecoder.core.MessageKind.REQUEST, e));
            }
            out.add(f);
        }
        return out;
    }

    private static <E extends Enum<E>> E enumOr(Class<E> type, String name, E dflt) {
        if (name == null) return dflt;
        try {
            return Enum.valueOf(type, name.trim().toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return dflt;
        }
    }

    private static String htmlText(String s) {
        return s == null ? "" : protocoldecoder.scan.Finding.esc(Codecs.truncate(s, 20_000)).replace("\n", "<br>");
    }

    private static boolean isResultObject(Scriptable s) {
        Object[] ids = s.getIds();
        if (ids.length == 0) return false;
        for (Object id : ids) if (!RESULT_KEYS.contains(String.valueOf(id))) return false;
        return true;
    }

    private static long ms(long start) {
        return (System.nanoTime() - start) / 1_000_000;
    }
}
