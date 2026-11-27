package protocoldecoder.burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedWebSocketMessageEditor;
import protocoldecoder.App;
import protocoldecoder.core.MessageContext;
import protocoldecoder.ui.MessageDecodePanel;
import protocoldecoder.ui.UiEnv;

import java.awt.Component;

/** Read-only "Decoded" tab for WebSocket message editors. */
final class DecodedWebSocketEditor implements ExtensionProvidedWebSocketMessageEditor {

    private final App app;
    private final MessageDecodePanel panel;
    private WebSocketMessage current;

    DecodedWebSocketEditor(App app, UiEnv env, boolean editable) {
        this.app = app;
        this.panel = new MessageDecodePanel(app, env, editable);
        env.theme(panel);
    }

    @Override
    public ByteArray getMessage() {
        if (current == null) return ByteArray.byteArray(new byte[0]);
        byte[] edited = panel.edits().body();
        return edited != null ? ByteArray.byteArray(edited) : current.payload();
    }

    @Override
    public void setMessage(WebSocketMessage message) {
        this.current = message;
        panel.setMessage(Montoya.fromWebSocket(message, app.settings().maxMatchBytes));
    }

    @Override
    public boolean isEnabledFor(WebSocketMessage message) {
        try {
            MessageContext m = Montoya.fromWebSocket(message, app.settings().maxMatchBytes);
            return m != null && (app.settings().alwaysShowTab || app.engine().resolve(m).hasDecoder());
        } catch (RuntimeException e) {
            app.logError("isEnabledFor (WebSocket) failed: " + e);
            return false;
        }
    }

    @Override
    public String caption() {
        return DecodedHttpEditor.CAPTION;
    }

    @Override
    public Component uiComponent() {
        return panel;
    }

    @Override
    public Selection selectedData() {
        String v = panel.selectedValue();
        return v == null || v.isEmpty() ? null : Selection.selection(ByteArray.byteArray(v));
    }

    @Override
    public boolean isModified() {
        return panel.hasEdits();
    }
}
