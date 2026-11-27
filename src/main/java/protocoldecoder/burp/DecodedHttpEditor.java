package protocoldecoder.burp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import protocoldecoder.App;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.ui.MessageDecodePanel;
import protocoldecoder.ui.UiEnv;

import java.awt.Component;

/** Read-only "Decoded" tab for HTTP request and response editors. */
final class DecodedHttpEditor implements ExtensionProvidedHttpRequestEditor, ExtensionProvidedHttpResponseEditor {

    static final String CAPTION = "Decoded";

    private final App app;
    private final MessageKind kind;
    private final MessageDecodePanel panel;
    private HttpRequestResponse current;

    DecodedHttpEditor(App app, UiEnv env, MessageKind kind, boolean editable) {
        this.app = app;
        this.kind = kind;
        this.panel = new MessageDecodePanel(app, env, editable);
        env.theme(panel);
    }

    @Override
    public HttpRequest getRequest() {
        if (current == null) return null;
        return kind == MessageKind.REQUEST ? Montoya.apply(current.request(), panel.edits()) : current.request();
    }

    @Override
    public HttpResponse getResponse() {
        if (current == null) return null;
        return kind == MessageKind.RESPONSE ? Montoya.apply(current.response(), panel.edits()) : current.response();
    }

    @Override
    public void setRequestResponse(HttpRequestResponse rr) {
        this.current = rr;
        panel.setMessage(Montoya.fromHttp(rr, kind, app.settings().maxMatchBytes));
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse rr) {
        try {
            MessageContext m = Montoya.fromHttp(rr, kind, app.settings().maxMatchBytes);
            if (m == null) return false;
            return app.settings().alwaysShowTab || app.engine().resolve(m).hasDecoder();
        } catch (RuntimeException e) {
            app.logError("isEnabledFor failed: " + e);
            return false;
        }
    }

    @Override
    public String caption() {
        return CAPTION;
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
