package protocoldecoder.script;

import org.mozilla.javascript.ClassShutter;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.ContextFactory;
import org.mozilla.javascript.EcmaError;
import org.mozilla.javascript.EvaluatorException;
import org.mozilla.javascript.Function;
import org.mozilla.javascript.JavaScriptException;
import org.mozilla.javascript.RhinoException;
import org.mozilla.javascript.Script;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.ScriptableObject;
import org.mozilla.javascript.WrappedException;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * Runs untrusted decoder scripts in Mozilla Rhino with:
 * <ul>
 *   <li>no Java interop: the global scope is built with {@code initSafeStandardObjects} (no {@code Packages},
 *       {@code java}, {@code JavaImporter}…), a {@link ClassShutter} that hides every Java class, and only
 *       JavaScript-native values are passed in;</li>
 *   <li>a CPU deadline enforced by the interpreter's instruction observer (an uncatchable error), backed by a
 *       wall-clock timeout on a separate worker thread;</li>
 *   <li>a frozen, shared standard library so one script can't tamper with built-ins used by another;</li>
 *   <li>a bounded interpreter stack depth.</li>
 * </ul>
 * <p>The JVM gives no way to cap a single thread's memory, so a script can still allocate a lot before hitting a
 * timeout; bodies handed in are size-limited and helper outputs are bounded to limit the damage.</p>
 */
public final class ScriptSandbox implements AutoCloseable {

    /** Per-invocation state hung off the Rhino context. */
    static final class SandboxContext extends Context {
        long deadlineNanos = Long.MAX_VALUE;
        List<String> logs = new ArrayList<>();

        SandboxContext(ContextFactory f) {
            super(f);
        }
    }

    static final int MAX_LOG_LINES = 200;
    private static final int GRACE_MS = 1000;

    private final ContextFactory factory = new ContextFactory() {
        @Override
        protected Context makeContext() {
            SandboxContext cx = new SandboxContext(this);
            cx.setInterpretedMode(true);                // instruction counting only works when interpreted
            cx.setLanguageVersion(Context.VERSION_ECMASCRIPT);
            cx.setInstructionObserverThreshold(2_000);
            cx.setMaximumInterpreterStackDepth(1_000);
            cx.setClassShutter(DENY_ALL);
            return cx;
        }

        @Override
        protected boolean hasFeature(Context cx, int featureIndex) {
            if (featureIndex == Context.FEATURE_ENHANCED_JAVA_ACCESS) return false;
            return super.hasFeature(cx, featureIndex);
        }

        @Override
        protected void observeInstructionCount(Context cx, int instructionCount) {
            SandboxContext sc = (SandboxContext) cx;
            if (System.nanoTime() > sc.deadlineNanos || Thread.currentThread().isInterrupted()) {
                throw new ScriptTimeoutError("script exceeded its time limit");
            }
        }
    };

    private static final ClassShutter DENY_ALL = className -> false;

    private final ExecutorService executor;
    private final ScriptableObject sharedScope;
    private volatile Consumer<String> logSink = s -> { };

    public ScriptSandbox() {
        ClassLoader loader = ScriptSandbox.class.getClassLoader();
        AtomicInteger n = new AtomicInteger();
        ThreadFactory tf = r -> {
            Thread t = new Thread(r, "protocol-decoder-script-" + n.incrementAndGet());
            t.setDaemon(true);
            // Burp loads extensions in their own class loader; Rhino uses the context loader for ServiceLoader.
            t.setContextClassLoader(loader);
            return t;
        };
        this.executor = Executors.newCachedThreadPool(tf);
        this.sharedScope = buildSharedScope();
    }

    private ScriptableObject buildSharedScope() {
        Thread t = Thread.currentThread();
        ClassLoader old = t.getContextClassLoader();
        t.setContextClassLoader(ScriptSandbox.class.getClassLoader());
        Context cx = factory.enterContext();
        try {
            ScriptableObject scope = cx.initSafeStandardObjects(null, true);
            JsHelpers.install(cx, scope);
            scope.sealObject();
            return scope;
        } finally {
            Context.exit();
            t.setContextClassLoader(old);
        }
    }

    public void setLogSink(Consumer<String> sink) {
        this.logSink = sink == null ? s -> { } : sink;
    }

    /** Compiles a script; throws with line information on syntax errors. Compiled scripts are reusable. */
    public Script compile(String source, String name) throws ScriptException {
        return run(500, cx -> {
            try {
                return cx.compileString(source, name, 1, null);
            } catch (EvaluatorException e) {
                throw new ScriptException(describe(e));
            }
        }, new ArrayList<>());
    }

    /** Body of a sandboxed call: runs on a worker thread inside an entered context. */
    @FunctionalInterface
    interface SandboxedCall<T> {
        T run(SandboxContext cx) throws ScriptException;
    }

    /** Executes the script's top level in a fresh scope, then invokes {@code fn}. Returns null if fn is undefined. */
    <T> T invoke(Script script, String fn, int timeoutMs, JsMessage.Data message, List<String> logs,
                 ResultConverter<T> converter) throws ScriptException {
        return run(timeoutMs, cx -> {
            Scriptable scope = cx.newObject(sharedScope);
            scope.setPrototype(sharedScope);
            scope.setParentScope(null);
            script.exec(cx, scope, scope);
            Object f = ScriptableObject.getProperty(scope, fn);
            if (!(f instanceof Function func)) return null;
            Object arg = new JsMessage(message, scope);
            Object result = func.call(cx, scope, scope, new Object[]{arg});
            return converter.convert(cx, scope, result);
        }, logs);
    }

    /** Converts a JS return value while still inside the context (and the time budget). */
    @FunctionalInterface
    interface ResultConverter<T> {
        T convert(Context cx, Scriptable scope, Object value) throws ScriptException;
    }

    /** Returns true if the script defines a top-level function with this name. */
    boolean defines(Script script, String fn) throws ScriptException {
        Boolean b = run(500, cx -> {
            Scriptable scope = cx.newObject(sharedScope);
            scope.setPrototype(sharedScope);
            scope.setParentScope(null);
            script.exec(cx, scope, scope);
            return ScriptableObject.getProperty(scope, fn) instanceof Function;
        }, new ArrayList<>());
        return Boolean.TRUE.equals(b);
    }

    private <T> T run(int timeoutMs, SandboxedCall<T> call, List<String> logs) throws ScriptException {
        Future<T> future;
        try {
            future = executor.submit(() -> {
                SandboxContext cx = (SandboxContext) factory.enterContext();
                try {
                    cx.deadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs);
                    cx.logs = logs;
                    return call.run(cx);
                } finally {
                    Context.exit();
                }
            });
        } catch (java.util.concurrent.RejectedExecutionException e) {
            throw new ScriptException("script engine is shut down");
        }
        try {
            return future.get(timeoutMs + GRACE_MS, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            future.cancel(true);
            logSink.accept("Script still running after " + (timeoutMs + GRACE_MS) + " ms (stuck in a native call such as a regex); abandoned");
            throw new ScriptException("timed out after " + timeoutMs + " ms", true);
        } catch (InterruptedException e) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            throw new ScriptException("interrupted");
        } catch (ExecutionException e) {
            throw translate(e.getCause());
        }
    }

    private static ScriptException translate(Throwable t) {
        if (t instanceof ScriptException se) return se;
        if (t instanceof ScriptTimeoutError) return new ScriptException("timed out (CPU limit reached)", true);
        if (t instanceof JavaScriptException jse) {
            Object v = jse.getValue();
            String msg = v instanceof Scriptable s ? String.valueOf(ScriptableObject.getProperty(s, "message")) : Context.toString(v);
            if ("undefined".equals(msg) || "org.mozilla.javascript.UniqueTag@NOT_FOUND".equals(msg) || msg.contains("NOT_FOUND")) {
                msg = Context.toString(v);
            }
            return new ScriptException(msg + location(jse));
        }
        if (t instanceof EcmaError ee) return new ScriptException(ee.getName() + ": " + ee.getErrorMessage() + location(ee));
        if (t instanceof EvaluatorException ev) return new ScriptException(describe(ev));
        if (t instanceof WrappedException we) return translate(we.getWrappedException());
        if (t instanceof StackOverflowError) return new ScriptException("stack overflow (too much recursion)");
        if (t instanceof OutOfMemoryError) return new ScriptException("out of memory");
        if (t instanceof RhinoException re) return new ScriptException(re.details() + location(re));
        StackTraceElement[] st = t.getStackTrace();
        String where = st.length > 0 ? " at " + st[0] : "";
        return new ScriptException("internal error: " + t.getClass().getSimpleName() + (t.getMessage() == null ? "" : ": " + t.getMessage()) + where);
    }

    private static String describe(EvaluatorException e) {
        return e.details() + location(e);
    }

    private static String location(RhinoException e) {
        return e.lineNumber() > 0 ? " (line " + e.lineNumber() + (e.columnNumber() > 0 ? ", col " + e.columnNumber() : "") + ")" : "";
    }

    /** Appends a log line from a script (bounded). */
    static void log(Context cx, String line) {
        if (cx instanceof SandboxContext sc && sc.logs.size() < MAX_LOG_LINES) {
            sc.logs.add(line.length() > 2000 ? line.substring(0, 2000) + "…" : line);
        }
    }

    @Override
    public void close() {
        executor.shutdownNow();
    }
}
