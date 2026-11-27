package protocoldecoder.burp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.contextmenu.WebSocketContextMenuEvent;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import protocoldecoder.App;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.core.OverrideStore;
import protocoldecoder.core.ProtocolDecoder;
import protocoldecoder.ui.RuleEditorDialog;
import protocoldecoder.ui.UiEnv;

import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import javax.swing.JMenu;
import javax.swing.JMenuItem;

/** Right-click → Protocol Decoder → Decode as / Create rule / Send to script tester. */
final class ContextMenu implements ContextMenuItemsProvider {

    private final App app;
    private final UiEnv env;
    private final Component parent;

    ContextMenu(App app, UiEnv env, Component parent) {
        this.app = app;
        this.env = env;
        this.parent = parent;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        int max = app.settings().maxMatchBytes;
        List<MessageContext> targets = new ArrayList<>();
        MessageContext primary = null;
        HttpRequestResponse primaryRaw = null;
        MessageKind primaryKind = MessageKind.REQUEST;
        if (event.messageEditorRequestResponse().isPresent()) {
            MessageEditorHttpRequestResponse ed = event.messageEditorRequestResponse().get();
            primaryKind = ed.selectionContext() == MessageEditorHttpRequestResponse.SelectionContext.RESPONSE ? MessageKind.RESPONSE : MessageKind.REQUEST;
            primaryRaw = ed.requestResponse();
            primary = Montoya.fromHttp(primaryRaw, primaryKind, max);
            if (primary != null) targets.add(primary);
        } else {
            for (HttpRequestResponse rr : event.selectedRequestResponses()) {
                MessageContext req = Montoya.fromHttp(rr, MessageKind.REQUEST, max);
                if (req != null) targets.add(req);
                MessageContext resp = Montoya.fromHttp(rr, MessageKind.RESPONSE, max);
                if (resp != null) targets.add(resp);
                if (primary == null && req != null) {
                    primary = resp != null ? resp : req;
                    primaryRaw = rr;
                    primaryKind = resp != null ? MessageKind.RESPONSE : MessageKind.REQUEST;
                }
            }
        }
        if (targets.isEmpty()) return List.of();

        JMenu root = new JMenu("Protocol Decoder");
        String scope = event.messageEditorRequestResponse().isPresent() ? "this " + primaryKind.label().toLowerCase()
                : targets.size() > 2 ? "selected messages" : "this request and response";
        root.add(decodeAsMenu("Decode " + scope + " as", targets));

        MessageContext p = primary;
        if (event.selectedRequestResponses().size() <= 1) {
            JMenuItem rule = new JMenuItem("Create rule from this message…");
            rule.addActionListener(e -> {
                var r = app.engine().resolve(p);
                RuleEditorDialog.createFromMessage(parent, app, env, p, r.hasDecoder() ? r.decoder().id() : null);
            });
            root.add(rule);
        }
        HttpRequestResponse raw = primaryRaw;
        MessageKind k = primaryKind;
        JMenuItem tester = new JMenuItem("Send to script tester");
        tester.addActionListener(e -> app.setTestSample(new App.TestSample(
                raw.request().toString(), raw.response() == null ? "" : raw.response().toString(), k)));
        root.add(tester);
        return List.of(root);
    }

    @Override
    public List<Component> provideMenuItems(WebSocketContextMenuEvent event) {
        int max = app.settings().maxMatchBytes;
        List<MessageContext> targets = new ArrayList<>();
        if (event.messageEditorWebSocket().isPresent()) {
            MessageContext m = Montoya.fromWebSocket(event.messageEditorWebSocket().get().webSocketMessage(), max);
            if (m != null) targets.add(m);
        } else {
            for (WebSocketMessage w : event.selectedWebSocketMessages()) {
                MessageContext m = Montoya.fromWebSocket(w, max);
                if (m != null) targets.add(m);
            }
        }
        if (targets.isEmpty()) return List.of();
        JMenu root = new JMenu("Protocol Decoder");
        root.add(decodeAsMenu("Decode message" + (targets.size() > 1 ? "s" : "") + " as", targets));
        if (targets.size() == 1) {
            MessageContext m = targets.get(0);
            JMenuItem rule = new JMenuItem("Create rule from this message…");
            rule.addActionListener(e -> {
                var r = app.engine().resolve(m);
                RuleEditorDialog.createFromMessage(parent, app, env, m, r.hasDecoder() ? r.decoder().id() : null);
            });
            root.add(rule);
        }
        return List.of(root);
    }

    private JMenu decodeAsMenu(String title, List<MessageContext> targets) {
        JMenu m = new JMenu(title);
        m.add(item("Automatic (clear manual choice)", ignored -> targets.forEach(t -> app.overrides().clear(t))));
        m.addSeparator();
        for (ProtocolDecoder d : app.registry().all()) {
            String label = d.name() + (app.registry().isEnabled(d.id()) ? "" : " (disabled)");
            m.add(item(label, ignored -> targets.forEach(t -> app.overrides().set(t, d.id()))));
        }
        m.addSeparator();
        m.add(item("Don't decode", ignored -> targets.forEach(t -> app.overrides().set(t, OverrideStore.NONE))));
        return m;
    }

    private static JMenuItem item(String label, Consumer<Object> action) {
        JMenuItem i = new JMenuItem(label);
        i.addActionListener(e -> action.accept(null));
        return i;
    }
}
