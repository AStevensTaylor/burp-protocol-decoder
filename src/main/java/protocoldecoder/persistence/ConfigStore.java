package protocoldecoder.persistence;

import protocoldecoder.core.DecoderRegistry;
import protocoldecoder.core.OverrideStore;
import protocoldecoder.rules.Rule;
import protocoldecoder.rules.RuleSet;
import protocoldecoder.script.ScriptDefinition;

import java.util.List;
import java.util.function.Consumer;

/**
 * Loads and saves configuration. Scripts, rules, enabled state and settings are global (Burp preferences, shared by
 * all projects); manual overrides are per project (they refer to specific messages).
 */
public final class ConfigStore {

    static final String KEY_SCRIPTS = "protocoldecoder.scripts";
    static final String KEY_RULES = "protocoldecoder.rules";
    static final String KEY_DISABLED = "protocoldecoder.disabled";
    static final String KEY_SETTINGS = "protocoldecoder.settings";
    static final String KEY_OVERRIDES = "protocoldecoder.overrides";
    static final String KEY_DISABLED_CHECKS = "protocoldecoder.disabledChecks";

    private final KeyValueStore global;
    private final KeyValueStore project;
    private final Consumer<String> errorLog;

    public ConfigStore(KeyValueStore global, KeyValueStore project, Consumer<String> errorLog) {
        this.global = global;
        this.project = project;
        this.errorLog = errorLog;
    }

    public List<ScriptDefinition> loadScripts() {
        try {
            return ConfigCodec.scriptsFromJson(global.get(KEY_SCRIPTS));
        } catch (RuntimeException e) {
            errorLog.accept("Could not load saved scripts: " + e);
            return new java.util.ArrayList<>();
        }
    }

    public void saveScripts(List<ScriptDefinition> scripts) {
        global.set(KEY_SCRIPTS, ConfigCodec.scriptsToJson(scripts));
    }

    public List<Rule> loadRules() {
        try {
            return ConfigCodec.rulesFromJson(global.get(KEY_RULES));
        } catch (RuntimeException e) {
            errorLog.accept("Could not load saved rules: " + e);
            return new java.util.ArrayList<>();
        }
    }

    public void saveRules(RuleSet rules) {
        global.set(KEY_RULES, ConfigCodec.rulesToJson(rules.rules()));
    }

    public void loadDisabled(DecoderRegistry registry) {
        try {
            registry.setDisabledIds(ConfigCodec.idsFromJson(global.get(KEY_DISABLED)));
        } catch (RuntimeException e) {
            errorLog.accept("Could not load enabled/disabled decoders: " + e);
        }
    }

    public void saveDisabled(DecoderRegistry registry) {
        global.set(KEY_DISABLED, ConfigCodec.idsToJson(registry.disabledIds()));
    }

    public java.util.Set<String> loadDisabledChecks() {
        try {
            return ConfigCodec.idsFromJson(global.get(KEY_DISABLED_CHECKS));
        } catch (RuntimeException e) {
            errorLog.accept("Could not load disabled scan checks: " + e);
            return java.util.Set.of();
        }
    }

    public void saveDisabledChecks(java.util.Set<String> ids) {
        global.set(KEY_DISABLED_CHECKS, ConfigCodec.idsToJson(ids));
    }

    public Settings loadSettings() {
        try {
            return ConfigCodec.settingsFromJson(global.get(KEY_SETTINGS));
        } catch (RuntimeException e) {
            errorLog.accept("Could not load settings: " + e);
            return new Settings();
        }
    }

    public void saveSettings(Settings s) {
        global.set(KEY_SETTINGS, ConfigCodec.settingsToJson(s));
    }

    public void loadOverrides(OverrideStore store) {
        try {
            store.load(ConfigCodec.overridesFromJson(project.get(KEY_OVERRIDES)));
        } catch (RuntimeException e) {
            errorLog.accept("Could not load overrides: " + e);
        }
    }

    public void saveOverrides(OverrideStore store, boolean persist) {
        project.set(KEY_OVERRIDES, persist ? ConfigCodec.overridesToJson(store.snapshot()) : null);
    }
}
