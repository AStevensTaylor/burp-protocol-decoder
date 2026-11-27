package protocoldecoder.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.ui.Theme;
import protocoldecoder.App;
import protocoldecoder.core.MessageKind;
import protocoldecoder.persistence.ConfigStore;
import protocoldecoder.persistence.KeyValueStore;
import protocoldecoder.ui.MainTab;
import protocoldecoder.ui.UiEnv;

import java.awt.Font;

/** Burp Suite entry point (Montoya API). */
public final class ProtocolDecoderExtension implements BurpExtension {

    public static final String NAME = "Protocol Decoder";

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName(NAME);

        Preferences prefs = api.persistence().preferences();
        PersistedObject project = api.persistence().extensionData();
        KeyValueStore global = new KeyValueStore() {
            @Override
            public String get(String key) {
                return prefs.getString(key);
            }

            @Override
            public void set(String key, String value) {
                if (value == null) prefs.deleteString(key);
                else prefs.setString(key, value);
            }
        };
        KeyValueStore projectStore = new KeyValueStore() {
            @Override
            public String get(String key) {
                return project.getString(key);
            }

            @Override
            public void set(String key, String value) {
                if (value == null) project.deleteString(key);
                else project.setString(key, value);
            }
        };

        App app = new App(new ConfigStore(global, projectStore, api.logging()::logToError),
                api.logging()::logToOutput, api.logging()::logToError);

        UiEnv env = new UiEnv(isDark(api), editorFont(api), c -> api.userInterface().applyThemeToComponent(c));
        MainTab tab = new MainTab(app, env);
        api.userInterface().applyThemeToComponent(tab);

        api.userInterface().registerSuiteTab(NAME, tab);
        api.userInterface().registerHttpRequestEditorProvider(ctx -> new DecodedHttpEditor(app, env, MessageKind.REQUEST));
        api.userInterface().registerHttpResponseEditorProvider(ctx -> new DecodedHttpEditor(app, env, MessageKind.RESPONSE));
        api.userInterface().registerWebSocketMessageEditorProvider(ctx -> new DecodedWebSocketEditor(app, env));
        api.userInterface().registerContextMenuItemsProvider(new ContextMenu(app, env, tab));
        api.extension().registerUnloadingHandler(app::close);

        api.logging().logToOutput(NAME + " loaded: " + app.registry().all().size() + " decoders ("
                + app.scripts().size() + " custom), " + app.rules().rules().size() + " rules.");
    }

    private static boolean isDark(MontoyaApi api) {
        try {
            return api.userInterface().currentTheme() == Theme.DARK;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static Font editorFont(MontoyaApi api) {
        try {
            Font f = api.userInterface().currentEditorFont();
            return f != null ? f : new Font(Font.MONOSPACED, Font.PLAIN, 12);
        } catch (RuntimeException e) {
            return new Font(Font.MONOSPACED, Font.PLAIN, 12);
        }
    }
}
