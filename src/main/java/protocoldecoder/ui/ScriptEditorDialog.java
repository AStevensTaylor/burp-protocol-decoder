package protocoldecoder.ui;

import protocoldecoder.App;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.script.ScriptDecoder;
import protocoldecoder.script.ScriptDefinition;
import protocoldecoder.script.ScriptTemplates;
import protocoldecoder.util.RawHttp;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.text.BadLocationException;

/**
 * Editor for a custom decoder script with a built-in tester: paste (or send from Burp) a request/response, run the
 * script's match() and decode() in the sandbox and see the tree, logs and timing — without saving.
 */
public final class ScriptEditorDialog extends JFrame {

    private final App app;
    private final UiEnv env;
    private final String originalId;
    private final JTextField id = new JTextField(18);
    private final JTextField name = new JTextField(22);
    private final JTextField description = new JTextField(40);
    private final JTextArea source = new JTextArea();
    private final JLabel caret = new JLabel(" ");
    private final JTextArea rawRequest = new JTextArea();
    private final JTextArea rawResponse = new JTextArea();
    private final JComboBox<MessageKind> kind = new JComboBox<>(new MessageKind[]{MessageKind.REQUEST, MessageKind.RESPONSE});
    private final DecodedView result;
    private final JTextArea logs = new JTextArea();
    private final JLabel status = new JLabel(" ");
    private final JTabbedPane right = new JTabbedPane();
    private final Runnable sampleListener;
    private boolean dirty;

    private ScriptEditorDialog(Component parent, App app, UiEnv env, ScriptDefinition def, boolean isNew) {
        super(isNew ? "New decoder script" : "Edit decoder script — " + def.name());
        this.app = app;
        this.env = env;
        this.originalId = isNew ? null : def.id();
        this.result = new DecodedView(env);
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);

        id.setText(def.id());
        name.setText(def.name());
        description.setText(def.description());
        source.setText(def.source());
        source.setFont(env.editorFont());
        source.setTabSize(2);
        source.setCaretPosition(0);
        source.addCaretListener(e -> updateCaret());
        source.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { dirty = true; }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { dirty = true; }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { }
        });
        for (JTextArea a : new JTextArea[]{rawRequest, rawResponse, logs}) {
            a.setFont(env.editorFont());
        }
        logs.setEditable(false);

        JPanel meta = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(2, 4, 2, 4);
        g.anchor = GridBagConstraints.WEST;
        meta.add(new JLabel("ID:"), g);
        meta.add(id, g);
        meta.add(new JLabel("Name:"), g);
        meta.add(name, g);
        meta.add(new JLabel("Description:"), g);
        g.weightx = 1;
        g.fill = GridBagConstraints.HORIZONTAL;
        meta.add(description, g);
        id.setToolTipText("Stable identifier used by rules and overrides (lower-case, digits, . _ -)");

        JPanel editor = new JPanel(new BorderLayout());
        editor.add(new JScrollPane(source), BorderLayout.CENTER);
        caret.setForeground(env.noteColor());
        editor.add(caret, BorderLayout.SOUTH);

        // Tester
        JPanel sample = new JPanel(new BorderLayout());
        JSplitPane rr = new JSplitPane(JSplitPane.VERTICAL_SPLIT, titled(new JScrollPane(rawRequest), "Raw request"),
                titled(new JScrollPane(rawResponse), "Raw response (optional)"));
        rr.setResizeWeight(0.5);
        sample.add(rr, BorderLayout.CENTER);
        JPanel sampleBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        sampleBar.add(new JLabel("Decode the:"));
        sampleBar.add(kind);
        JButton fromBurp = new JButton("Load sample sent from Burp");
        fromBurp.setToolTipText("Right-click a message in Burp → Protocol Decoder → Send to script tester");
        fromBurp.addActionListener(e -> loadSample());
        sampleBar.add(fromBurp);
        sample.add(sampleBar, BorderLayout.NORTH);

        JPanel output = new JPanel(new BorderLayout());
        JSplitPane out = new JSplitPane(JSplitPane.VERTICAL_SPLIT, result, titled(new JScrollPane(logs), "log() output"));
        out.setResizeWeight(0.8);
        output.add(out, BorderLayout.CENTER);

        JTextArea api = new JTextArea(ScriptTemplates.API_REFERENCE);
        api.setEditable(false);
        api.setFont(env.editorFont());
        api.setCaretPosition(0);

        right.addTab("Sample message", sample);
        right.addTab("Result", output);
        right.addTab("Script API", new JScrollPane(api));

        JSplitPane main = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, editor, right);
        main.setResizeWeight(0.55);

        JPanel buttons = new JPanel(new BorderLayout());
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton run = new JButton("Run test (Ctrl+Enter)");
        run.addActionListener(e -> runTest());
        left.add(run);
        left.add(status);
        JPanel rightButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton save = new JButton("Save");
        save.addActionListener(e -> save(false));
        JButton saveClose = new JButton("Save & close");
        saveClose.addActionListener(e -> save(true));
        JButton close = new JButton("Close");
        close.addActionListener(e -> closeWindow());
        rightButtons.add(save);
        rightButtons.add(saveClose);
        rightButtons.add(close);
        buttons.add(left, BorderLayout.WEST);
        buttons.add(rightButtons, BorderLayout.EAST);

        JPanel content = new JPanel(new BorderLayout(4, 4));
        content.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
        content.add(meta, BorderLayout.NORTH);
        content.add(main, BorderLayout.CENTER);
        content.add(buttons, BorderLayout.SOUTH);
        setContentPane(content);

        content.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, KeyEvent.CTRL_DOWN_MASK), "run");
        content.getActionMap().put("run", new javax.swing.AbstractAction() {
            public void actionPerformed(java.awt.event.ActionEvent e) { runTest(); }
        });
        content.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(KeyStroke.getKeyStroke(KeyEvent.VK_S, KeyEvent.CTRL_DOWN_MASK), "save");
        content.getActionMap().put("save", new javax.swing.AbstractAction() {
            public void actionPerformed(java.awt.event.ActionEvent e) { save(false); }
        });

        sampleListener = () -> DecodedView.onEdt(() -> status.setText("New sample available from Burp — click \"Load sample sent from Burp\""));
        app.addSampleListener(sampleListener);
        if (app.testSample() != null) loadSample();

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                closeWindow();
            }
        });

        dirty = isNew;
        env.theme(this);
        setSize(new Dimension(1300, 800));
        setLocationRelativeTo(parent);
        updateCaret();
    }

    private static JComponent titled(JComponent c, String title) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createTitledBorder(title));
        p.add(c, BorderLayout.CENTER);
        return p;
    }

    private void updateCaret() {
        try {
            int pos = source.getCaretPosition();
            int line = source.getLineOfOffset(pos);
            caret.setText(" Line " + (line + 1) + ", col " + (pos - source.getLineStartOffset(line) + 1));
        } catch (BadLocationException e) {
            caret.setText(" ");
        }
    }

    private void loadSample() {
        App.TestSample s = app.testSample();
        if (s == null) {
            status.setText("No sample sent yet: right-click a message → Protocol Decoder → Send to script tester");
            return;
        }
        rawRequest.setText(s.request());
        rawRequest.setCaretPosition(0);
        rawResponse.setText(s.response() == null ? "" : s.response());
        rawResponse.setCaretPosition(0);
        kind.setSelectedItem(s.kind() == MessageKind.RESPONSE ? MessageKind.RESPONSE : MessageKind.REQUEST);
        status.setText("Loaded sample from Burp");
    }

    private ScriptDefinition current() {
        return new ScriptDefinition(id.getText().trim(), name.getText().trim(), description.getText().trim(), source.getText());
    }

    private void runTest() {
        ScriptDefinition def = current();
        if (rawRequest.getText().isBlank()) {
            status.setText("Paste a raw request (and optionally a response) in the Sample tab first");
            right.setSelectedIndex(0);
            return;
        }
        MessageKind k = (MessageKind) kind.getSelectedItem();
        if (k == MessageKind.RESPONSE && rawResponse.getText().isBlank()) {
            status.setText("Paste a raw response to test response decoding");
            return;
        }
        MessageContext m = RawHttp.parse(rawRequest.getText(), rawResponse.getText(), k);
        status.setText("Running…");
        result.showMessage("Running…");
        right.setSelectedIndex(1);
        MessageDecodePanel.WORKERS.submit(() -> {
            ScriptDecoder sd = app.newScriptDecoder(def);
            String compileError = sd.compileError();
            ScriptDecoder.Trace<MatchResult> mt = compileError == null && sd.hasMatcher() ? sd.traceMatch(m) : null;
            ScriptDecoder.Trace<DecodeResult> dt = compileError == null ? sd.traceDecode(m) : null;
            DecodedView.onEdt(() -> {
                StringBuilder log = new StringBuilder();
                if (compileError != null) {
                    status.setText("Compile error: " + compileError);
                    result.showError(compileError);
                    jumpToLine(compileError);
                    logs.setText("");
                    return;
                }
                String matchText;
                if (mt == null) matchText = "match(): not defined";
                else if (mt.error() != null) matchText = "match() error: " + mt.error();
                else matchText = "match(): " + mt.value().confidence() + (mt.value().matched() ? "% (" + mt.value().reason() + ")" : " (no match)") + " in " + mt.millis() + " ms";
                if (mt != null) mt.logs().forEach(l -> log.append("[match] ").append(l).append('\n'));
                dt.logs().forEach(l -> log.append("[decode] ").append(l).append('\n'));
                logs.setText(log.toString());
                if (dt.error() != null) {
                    result.showError(dt.error());
                    status.setText(matchText + "   ·   decode() error");
                    jumpToLine(dt.error());
                } else {
                    result.show(dt.value());
                    status.setText(matchText + "   ·   decode(): " + dt.value().root().size() + " nodes in " + dt.millis() + " ms");
                }
            });
        });
    }

    private void jumpToLine(String error) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("line (\\d+)").matcher(error);
        if (!m.find()) return;
        try {
            int line = Integer.parseInt(m.group(1)) - 1;
            if (line >= 0 && line < source.getLineCount()) {
                source.setCaretPosition(source.getLineStartOffset(line));
                source.requestFocusInWindow();
            }
        } catch (BadLocationException | NumberFormatException ignored) {
            // best effort
        }
    }

    private boolean save(boolean close) {
        ScriptDefinition def = current();
        ScriptDecoder probe = app.newScriptDecoder(def);
        if (probe.compileError() != null) {
            int c = JOptionPane.showConfirmDialog(this, "The script has an error:\n" + probe.compileError() + "\n\nSave anyway? (It won't decode until fixed.)",
                    "Script error", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (c != JOptionPane.YES_OPTION) return false;
        }
        String err = app.saveScript(savedId, def);
        if (err != null) {
            JOptionPane.showMessageDialog(this, err, "Cannot save", JOptionPane.WARNING_MESSAGE);
            return false;
        }
        savedId = def.id();
        dirty = false;
        setTitle("Edit decoder script — " + def.name());
        status.setText("Saved");
        if (close) dispose();
        return true;
    }

    private String savedId;

    private void closeWindow() {
        if (dirty) {
            int c = JOptionPane.showConfirmDialog(this, "Save changes to this script?", "Unsaved changes", JOptionPane.YES_NO_CANCEL_OPTION);
            if (c == JOptionPane.CANCEL_OPTION || c == JOptionPane.CLOSED_OPTION) return;
            if (c == JOptionPane.YES_OPTION && !save(false)) return;
        }
        dispose();
    }

    @Override
    public void dispose() {
        app.removeSampleListener(sampleListener);
        super.dispose();
    }

    public static void open(Component parent, App app, UiEnv env, ScriptDefinition def, boolean isNew) {
        ScriptEditorDialog d = new ScriptEditorDialog(parent, app, env, def, isNew);
        d.savedId = d.originalId;
        d.setVisible(true);
    }
}
