package protocoldecoder;

import protocoldecoder.builtin.actioncable.ActionCableDecoder;
import protocoldecoder.builtin.aspnetajax.AspNetAjaxDecoder;
import protocoldecoder.builtin.aspnetajax.AspNetAjaxScanner;
import protocoldecoder.builtin.graphql.GraphQlDecoder;
import protocoldecoder.builtin.graphql.GraphQlScanner;
import protocoldecoder.builtin.graphql.TrpcDecoder;
import protocoldecoder.builtin.graphql.TrpcScanner;
import protocoldecoder.builtin.grpc.GrpcDecoder;
import protocoldecoder.builtin.grpc.GrpcScanner;
import protocoldecoder.builtin.livewire.LivewireDecoder;
import protocoldecoder.builtin.nextjs.NextJsDecoder;
import protocoldecoder.builtin.saml.SamlDecoder;
import protocoldecoder.builtin.saml.SamlScanner;
import protocoldecoder.builtin.serialized.SerializedObjectDecoder;
import protocoldecoder.builtin.serialized.SerializedObjectScanner;
import protocoldecoder.builtin.turbo.TurboDecoder;
import protocoldecoder.builtin.viewstate.ViewStateDecoder;
import protocoldecoder.builtin.viewstate.ViewStateScanner;
import protocoldecoder.builtin.batchexecute.BatchExecuteDecoder;
import protocoldecoder.builtin.firebase.FirebaseScanner;
import protocoldecoder.builtin.batchexecute.BatchExecuteScanner;
import protocoldecoder.builtin.nextjs.NextJsScanner;
import protocoldecoder.builtin.livewire.LivewireScanner;
import protocoldecoder.builtin.turbo.TurboScanner;
import protocoldecoder.builtin.actioncable.ActionCableScanner;
import protocoldecoder.builtin.blazor.BlazorDecoder;
import protocoldecoder.builtin.firebase.FirebaseDecoder;
import protocoldecoder.builtin.phoenix.PhoenixDecoder;
import protocoldecoder.builtin.phoenix.PhoenixScanner;
import protocoldecoder.builtin.socketio.SocketIoDecoder;
import protocoldecoder.builtin.socketio.SocketIoScanner;
import protocoldecoder.builtin.blazor.BlazorScanner;
import protocoldecoder.builtin.devexpress.DevExpressDecoder;
import protocoldecoder.builtin.devexpress.DevExpressScanner;
import protocoldecoder.builtin.newrelic.NewRelicScanner;
import protocoldecoder.builtin.newrelic.NewRelicDecoder;
import protocoldecoder.core.DecoderEngine;
import protocoldecoder.core.DecoderRegistry;
import protocoldecoder.core.OverrideStore;
import protocoldecoder.core.ProtocolDecoder;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.Settings;
import protocoldecoder.rules.Rule;
import protocoldecoder.rules.RuleSet;
import protocoldecoder.scan.ScanEngine;
import protocoldecoder.script.ScriptDecoder;
import protocoldecoder.script.ScriptDefinition;
import protocoldecoder.script.ScriptSandbox;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Wires the extension together: registry (built-ins + scripts), rules, overrides, engine, sandbox and persistence.
 * Independent of the Montoya API so it can be exercised in tests.
 */
public final class App implements AutoCloseable {

    private final DecoderRegistry registry = new DecoderRegistry();
    private final RuleSet rules = new RuleSet();
    private final OverrideStore overrides = new OverrideStore();
    private final DecoderEngine engine = new DecoderEngine(registry, rules, overrides);
    private final ScriptSandbox sandbox = new ScriptSandbox();
    private final ScanEngine scanEngine = new ScanEngine(engine);
    private final ConfigStore config;
    private final Consumer<String> output;
    private final Consumer<String> errors;
    private final List<ScriptDefinition> scripts = new CopyOnWriteArrayList<>();
    private final List<Runnable> sampleListeners = new CopyOnWriteArrayList<>();
    private volatile Settings settings;
    private volatile TestSample testSample;

    /** Raw message text the user sent to the script tester. */
    public record TestSample(String request, String response, protocoldecoder.core.MessageKind kind) {
    }

    public App(ConfigStore config, Consumer<String> output, Consumer<String> errors) {
        this.config = config;
        this.output = output;
        this.errors = errors;
        this.settings = config.loadSettings();
        engine.setErrorLog(errors);
        scanEngine.setErrorLog(errors);
        sandbox.setLogSink(errors);

        // Registration order breaks confidence ties (earlier wins).
        registry.register(new DevExpressDecoder());
        registry.register(new AspNetAjaxDecoder());
        registry.register(new ViewStateDecoder());
        registry.register(new NewRelicDecoder());
        registry.register(new BlazorDecoder());
        registry.register(new NextJsDecoder());
        registry.register(new LivewireDecoder());
        registry.register(new TurboDecoder());
        registry.register(new ActionCableDecoder());
        registry.register(new SocketIoDecoder());
        registry.register(new PhoenixDecoder());
        registry.register(new GraphQlDecoder());
        registry.register(new TrpcDecoder());
        registry.register(new GrpcDecoder());
        registry.register(new SamlDecoder());
        registry.register(new FirebaseDecoder());
        registry.register(new BatchExecuteDecoder());
        registry.register(new SerializedObjectDecoder());
        for (ScriptDefinition d : config.loadScripts()) {
            if (d.validate() != null || registry.byId(d.id()).isPresent()) {
                errors.accept("Skipping saved script '" + d.id() + "': " + (d.validate() != null ? d.validate() : "duplicate id"));
                continue;
            }
            scripts.add(d);
            ScriptDecoder sd = newScriptDecoder(d);
            if (sd.compileError() != null) errors.accept("Script '" + d.id() + "' has errors: " + sd.compileError());
            registry.register(sd);
        }
        scanEngine.register(new DevExpressScanner());
        scanEngine.register(new NewRelicScanner());
        scanEngine.register(new BlazorScanner());
        scanEngine.register(new ViewStateScanner());
        scanEngine.register(new AspNetAjaxScanner());
        scanEngine.register(new SocketIoScanner());
        scanEngine.register(new PhoenixScanner());
        scanEngine.register(new GrpcScanner());
        scanEngine.register(new SamlScanner());
        scanEngine.register(new GraphQlScanner());
        scanEngine.register(new TrpcScanner());
        scanEngine.register(new NextJsScanner());
        scanEngine.register(new LivewireScanner());
        scanEngine.register(new TurboScanner());
        scanEngine.register(new ActionCableScanner());
        scanEngine.register(new FirebaseScanner());
        scanEngine.register(new BatchExecuteScanner());
        scanEngine.register(new SerializedObjectScanner());
        scanEngine.setDisabledIds(config.loadDisabledChecks());

        config.loadDisabled(registry);
        rules.setRules(config.loadRules());
        config.loadOverrides(overrides);

        registry.addListener(() -> config.saveDisabled(registry));
        rules.addListener(() -> config.saveRules(rules));
        overrides.addListener(() -> config.saveOverrides(overrides, settings.persistOverrides));
        scanEngine.addListener(() -> config.saveDisabledChecks(scanEngine.disabledIds()));
    }

    public DecoderRegistry registry() { return registry; }
    public RuleSet rules() { return rules; }
    public OverrideStore overrides() { return overrides; }
    public DecoderEngine engine() { return engine; }
    public ScriptSandbox sandbox() { return sandbox; }
    public ScanEngine scanEngine() { return scanEngine; }
    public Settings settings() { return settings; }

    public void log(String s) { output.accept(s); }
    public void logError(String s) { errors.accept(s); }

    public void updateSettings(Settings s) {
        this.settings = s.copy();
        config.saveSettings(this.settings);
        config.saveOverrides(overrides, this.settings.persistOverrides);
        engine.invalidate();
    }

    public ScriptDecoder newScriptDecoder(ScriptDefinition d) {
        return new ScriptDecoder(d, sandbox, () -> settings.limits());
    }

    public List<ScriptDefinition> scripts() {
        return List.copyOf(scripts);
    }

    /**
     * Adds or replaces a script (matched by {@code previousId}, or by its own id when new). Returns an error message
     * or null on success.
     */
    public synchronized String saveScript(String previousId, ScriptDefinition d) {
        String err = d.validate();
        if (err != null) return err;
        boolean renamed = previousId != null && !previousId.equals(d.id());
        if ((previousId == null || renamed) && registry.byId(d.id()).isPresent()) return "a decoder with id '" + d.id() + "' already exists";
        if (previousId != null && registry.byId(previousId).map(ProtocolDecoder::isBuiltIn).orElse(false)) return "cannot replace a built-in decoder";

        ScriptDecoder sd = newScriptDecoder(d);
        int idx = -1;
        for (int i = 0; i < scripts.size(); i++) if (scripts.get(i).id().equals(previousId == null ? d.id() : previousId)) idx = i;
        if (idx >= 0) scripts.set(idx, d.copy()); else scripts.add(d.copy());
        if (renamed) {
            boolean wasEnabled = registry.isEnabled(previousId);
            registry.unregister(previousId);
            registry.register(sd);
            registry.setEnabled(d.id(), wasEnabled);
            retargetRules(previousId, d.id());
        } else {
            registry.replace(sd);
        }
        config.saveScripts(scripts());
        return null;
    }

    public synchronized void deleteScript(String id) {
        scripts.removeIf(s -> s.id().equals(id));
        registry.unregister(id);
        config.saveScripts(scripts());
    }

    private void retargetRules(String from, String to) {
        List<Rule> updated = new ArrayList<>();
        for (Rule r : rules.rules()) {
            Rule c = r.copy();
            if (from.equals(c.decoderId())) c.decoderId(to);
            updated.add(c);
        }
        rules.setRules(updated);
    }

    /** The most recent message the user sent to the script tester, or null. */
    public TestSample testSample() {
        return testSample;
    }

    public void setTestSample(TestSample m) {
        this.testSample = m;
        sampleListeners.forEach(Runnable::run);
    }

    public void addSampleListener(Runnable r) {
        sampleListeners.add(r);
    }

    public void removeSampleListener(Runnable r) {
        sampleListeners.remove(r);
    }

    @Override
    public void close() {
        sandbox.close();
    }
}
