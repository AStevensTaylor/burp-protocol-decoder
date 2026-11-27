package protocoldecoder.ui;

import protocoldecoder.App;
import protocoldecoder.persistence.Settings;
import protocoldecoder.script.ScriptTemplates;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.SpinnerNumberModel;

/** Settings plus the script API reference. */
final class SettingsPanel extends JPanel {

    SettingsPanel(App app, UiEnv env) {
        super(new BorderLayout(8, 8));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        Settings s = app.settings();

        JCheckBox alwaysShow = new JCheckBox("Show the Decoded tab on every message (lets you pick a decoder for unrecognised messages)", s.alwaysShowTab);
        JCheckBox persist = new JCheckBox("Save manual decoder choices in the Burp project", s.persistOverrides);
        JSpinner matchMs = spinner(s.matchTimeoutMs, 10, 10_000, 10);
        JSpinner decodeMs = spinner(s.decodeTimeoutMs, 50, 60_000, 100);
        JSpinner bodyKb = spinner(s.maxScriptBodyBytes / 1024, 1, 65_536, 256);
        JSpinner nodes = spinner(s.maxOutputNodes, 100, 1_000_000, 1000);
        JSpinner matchKb = spinner(s.maxMatchBytes / 1024, 64, 262_144, 1024);

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createTitledBorder("Settings"));
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(3, 6, 3, 6);
        g.anchor = GridBagConstraints.WEST;
        int row = 0;
        g.gridx = 0;
        g.gridwidth = 2;
        g.gridy = row++;
        form.add(alwaysShow, g);
        g.gridy = row++;
        form.add(persist, g);
        g.gridwidth = 1;
        row = addRow(form, g, row, "Script match() time limit (ms):", matchMs);
        row = addRow(form, g, row, "Script decode() time limit (ms):", decodeMs);
        row = addRow(form, g, row, "Max body passed to scripts (KB):", bodyKb);
        row = addRow(form, g, row, "Max tree nodes from a script:", nodes);
        row = addRow(form, g, row, "Max message size inspected (KB, larger bodies are truncated):", matchKb);

        JLabel saved = new JLabel(" ");
        JButton save = new JButton("Apply");
        save.addActionListener(e -> {
            Settings n = app.settings().copy();
            n.alwaysShowTab = alwaysShow.isSelected();
            n.persistOverrides = persist.isSelected();
            n.matchTimeoutMs = (Integer) matchMs.getValue();
            n.decodeTimeoutMs = (Integer) decodeMs.getValue();
            n.maxScriptBodyBytes = (Integer) bodyKb.getValue() * 1024;
            n.maxOutputNodes = (Integer) nodes.getValue();
            n.maxMatchBytes = (Integer) matchKb.getValue() * 1024;
            app.updateSettings(n);
            saved.setText("Saved.");
        });
        JPanel bp = new JPanel(new FlowLayout(FlowLayout.LEFT));
        bp.add(save);
        bp.add(saved);
        g.gridx = 0;
        g.gridy = row;
        g.gridwidth = 2;
        form.add(bp, g);

        JTextArea api = new JTextArea(HELP + "\n\n" + ScriptTemplates.API_REFERENCE);
        api.setEditable(false);
        api.setFont(env.editorFont());
        api.setCaretPosition(0);
        JComponent help = new JScrollPane(api);
        help.setBorder(BorderFactory.createTitledBorder("How it works"));

        JPanel top = new JPanel(new BorderLayout());
        top.add(form, BorderLayout.WEST);
        add(top, BorderLayout.NORTH);
        add(help, BorderLayout.CENTER);
    }

    private static JSpinner spinner(int value, int min, int max, int step) {
        return new JSpinner(new SpinnerNumberModel(Math.max(min, Math.min(max, value)), min, max, step));
    }

    private static int addRow(JPanel p, GridBagConstraints g, int row, String label, JComponent field) {
        g.gridx = 0;
        g.gridy = row;
        p.add(new JLabel(label), g);
        g.gridx = 1;
        p.add(field, g);
        return row + 1;
    }

    static final String HELP = """
            CHOOSING A DECODER (first that applies wins)
              1. Manual choice for this message  — the Decoder picker in the "Decoded" tab, or right-click → Protocol Decoder → Decode as
              2. Rules                           — Rules tab, top to bottom; match on URL, host, path, headers, bodies, status…
              3. Auto-detection                  — every enabled decoder's match(); highest confidence wins

            WHERE DECODED MESSAGES APPEAR
              A "Decoded" tab is added to HTTP request/response and WebSocket message editors everywhere in Burp
              (Proxy, Repeater, Intruder results, Logger, Site map, Organizer…), whenever a decoder applies.

            CUSTOM DECODERS
              Decoders tab → New script…  Scripts are JavaScript, run in a sandbox with no access to Java, files or the
              network, and with CPU-time limits. Use the built-in tester (paste a message, or right-click a message →
              Protocol Decoder → Send to script tester) before saving. Share scripts and rules with Export/Import.
              Note: the sandbox can't cap memory use; a hostile script could still allocate heavily before its time limit.""";
}
