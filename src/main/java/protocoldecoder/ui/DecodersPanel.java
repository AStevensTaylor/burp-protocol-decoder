package protocoldecoder.ui;

import protocoldecoder.App;
import protocoldecoder.core.ProtocolDecoder;
import protocoldecoder.persistence.ConfigCodec;
import protocoldecoder.rules.Rule;
import protocoldecoder.script.ScriptDecoder;
import protocoldecoder.script.ScriptDefinition;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.AbstractTableModel;

/** Lists built-in and script decoders; enable/disable, create/edit/delete scripts, import/export. */
final class DecodersPanel extends JPanel {

    private final App app;
    private final UiEnv env;
    private final Model model = new Model();
    private final JTable table = new JTable(model);

    DecodersPanel(App app, UiEnv env) {
        super(new BorderLayout(4, 4));
        this.app = app;
        this.env = env;
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        var intro = DecodedView.note("Decoders are tried on every message; the highest-confidence match is used unless a rule or a "
                + "manual choice says otherwise. Built-in decoders can be disabled; custom decoders are sandboxed JavaScript.");
        add(intro, BorderLayout.NORTH);

        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(false);
        table.getColumnModel().getColumn(0).setMaxWidth(70);
        table.getColumnModel().getColumn(1).setPreferredWidth(160);
        table.getColumnModel().getColumn(2).setPreferredWidth(110);
        table.getColumnModel().getColumn(3).setPreferredWidth(70);
        table.getColumnModel().getColumn(4).setPreferredWidth(220);
        table.getColumnModel().getColumn(5).setPreferredWidth(420);
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && table.columnAtPoint(e.getPoint()) != 0) edit();
            }
        });
        add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttons.add(button("New script…", this::create));
        buttons.add(button("Edit…", this::edit));
        buttons.add(button("Duplicate", this::duplicate));
        buttons.add(button("Delete", this::delete));
        buttons.add(button("Resume matcher", this::resume));
        buttons.add(new JLabel("   "));
        buttons.add(button("Import…", this::importBundle));
        buttons.add(button("Export…", this::exportBundle));
        add(buttons, BorderLayout.SOUTH);

        app.registry().addListener(() -> DecodedView.onEdt(model::reload));
        model.reload();
    }

    private static JButton button(String label, Runnable r) {
        JButton b = new JButton(label);
        b.addActionListener(e -> r.run());
        return b;
    }

    private ProtocolDecoder selected() {
        int r = table.getSelectedRow();
        return r < 0 ? null : model.rows.get(r);
    }

    private void create() {
        ScriptEditorDialog.open(this, app, env, ScriptDefinition.newFromTemplate(), true);
    }

    private void edit() {
        ProtocolDecoder d = selected();
        if (d == null) return;
        if (d instanceof ScriptDecoder sd) {
            ScriptEditorDialog.open(this, app, env, sd.definition(), false);
        } else {
            JOptionPane.showMessageDialog(this, d.name() + " is built in.\n\nYou can disable it, force or suppress it with rules, "
                    + "or write a script decoder to replace it.", "Built-in decoder", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void duplicate() {
        if (!(selected() instanceof ScriptDecoder sd)) {
            JOptionPane.showMessageDialog(this, "Select a script decoder to duplicate.");
            return;
        }
        ScriptDefinition copy = sd.definition();
        copy.id(copy.id() + "-copy-" + UUID.randomUUID().toString().substring(0, 4)).name(copy.name() + " (copy)");
        ScriptEditorDialog.open(this, app, env, copy, true);
    }

    private void delete() {
        ProtocolDecoder d = selected();
        if (!(d instanceof ScriptDecoder)) {
            if (d != null) JOptionPane.showMessageDialog(this, "Built-in decoders can't be deleted; untick Enabled instead.");
            return;
        }
        long refs = app.rules().rules().stream().filter(r -> r.decoderId().equals(d.id())).count();
        String msg = "Delete script decoder \"" + d.name() + "\"?" + (refs > 0 ? "\n" + refs + " rule(s) refer to it and will stop working." : "");
        if (JOptionPane.showConfirmDialog(this, msg, "Delete decoder", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
            app.deleteScript(d.id());
        }
    }

    private void resume() {
        if (selected() instanceof ScriptDecoder sd) {
            sd.resetMatcher();
            app.engine().invalidate();
            model.reload();
        }
    }

    private void exportBundle() {
        JFileChooser fc = new JFileChooser();
        fc.setSelectedFile(new File("protocol-decoders.json"));
        fc.setFileFilter(new FileNameExtensionFilter("Protocol Decoder export (*.json)", "json"));
        if (fc.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        Object[] options = {"Scripts and rules", "Scripts only", "Cancel"};
        int choice = JOptionPane.showOptionDialog(this, "What should be exported?", "Export", JOptionPane.DEFAULT_OPTION,
                JOptionPane.QUESTION_MESSAGE, null, options, options[0]);
        if (choice != 0 && choice != 1) return;
        List<Rule> rules = choice == 0 ? app.rules().rules() : List.of();
        try {
            Files.writeString(fc.getSelectedFile().toPath(), ConfigCodec.bundleToJson(new ConfigCodec.Bundle(app.scripts(), rules)), StandardCharsets.UTF_8);
        } catch (IOException e) {
            JOptionPane.showMessageDialog(this, "Export failed: " + e.getMessage(), "Export", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void importBundle() {
        JFileChooser fc = new JFileChooser();
        fc.setFileFilter(new FileNameExtensionFilter("Protocol Decoder export (*.json) or script (*.js)", "json", "js"));
        if (fc.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        File f = fc.getSelectedFile();
        try {
            String text = Files.readString(f.toPath(), StandardCharsets.UTF_8);
            if (f.getName().toLowerCase().endsWith(".js")) {
                String base = f.getName().replaceFirst("\\.js$", "").toLowerCase().replaceAll("[^a-z0-9._-]", "-");
                ScriptDefinition d = new ScriptDefinition(base.isEmpty() ? "imported" : base, f.getName(), "Imported from " + f.getName(), text);
                ScriptEditorDialog.open(this, app, env, d, true);
                return;
            }
            ConfigCodec.Bundle b = ConfigCodec.bundleFromJson(text);
            List<String> problems = new ArrayList<>();
            int imported = 0;
            for (ScriptDefinition d : b.scripts()) {
                boolean exists = app.registry().byId(d.id()).isPresent();
                if (exists) {
                    boolean builtIn = app.registry().byId(d.id()).get().isBuiltIn();
                    if (builtIn || JOptionPane.showConfirmDialog(this, "Replace existing decoder '" + d.id() + "'?", "Import",
                            JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) {
                        problems.add(d.id() + ": skipped (already exists)");
                        continue;
                    }
                }
                String err = app.saveScript(exists ? d.id() : null, d);
                if (err != null) problems.add(d.id() + ": " + err); else imported++;
            }
            if (!b.rules().isEmpty() && JOptionPane.showConfirmDialog(this, "Also import " + b.rules().size() + " rule(s)? They'll be added after your existing rules.",
                    "Import rules", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
                List<Rule> all = new ArrayList<>(app.rules().rules());
                for (Rule r : b.rules()) all.add(r.duplicate().name(r.name()));
                app.rules().setRules(all);
            }
            JOptionPane.showMessageDialog(this, "Imported " + imported + " script(s)." + (problems.isEmpty() ? "" : "\n\n" + String.join("\n", problems))
                    + "\n\nImported scripts run in the sandbox, but review them before relying on their output.");
        } catch (IOException | IllegalArgumentException e) {
            JOptionPane.showMessageDialog(this, "Import failed: " + e.getMessage(), "Import", JOptionPane.ERROR_MESSAGE);
        }
    }

    private final class Model extends AbstractTableModel {
        private static final String[] COLS = {"Enabled", "Name", "ID", "Type", "Status", "Description"};
        List<ProtocolDecoder> rows = new ArrayList<>();

        void reload() {
            int sel = table.getSelectedRow();
            String selId = sel >= 0 && sel < rows.size() ? rows.get(sel).id() : null;
            rows = new ArrayList<>(app.registry().all());
            fireTableDataChanged();
            for (int i = 0; i < rows.size(); i++) if (rows.get(i).id().equals(selId)) table.setRowSelectionInterval(i, i);
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) { return c == 0 ? Boolean.class : String.class; }
        @Override public boolean isCellEditable(int r, int c) { return c == 0; }

        @Override
        public Object getValueAt(int r, int c) {
            ProtocolDecoder d = rows.get(r);
            return switch (c) {
                case 0 -> app.registry().isEnabled(d.id());
                case 1 -> d.name();
                case 2 -> d.id();
                case 3 -> d.isBuiltIn() ? "Built-in" : "Script";
                case 4 -> d instanceof ScriptDecoder sd ? sd.status() : "OK";
                default -> d.description();
            };
        }

        @Override
        public void setValueAt(Object v, int r, int c) {
            if (c == 0) app.registry().setEnabled(rows.get(r).id(), Boolean.TRUE.equals(v));
        }
    }
}
