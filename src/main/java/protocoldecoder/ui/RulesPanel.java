package protocoldecoder.ui;

import protocoldecoder.App;
import protocoldecoder.rules.Rule;
import protocoldecoder.rules.RuleAction;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.table.AbstractTableModel;

/** Ordered list of override rules. First match wins. */
final class RulesPanel extends JPanel {

    private final App app;
    private final UiEnv env;
    private final Model model = new Model();
    private final JTable table = new JTable(model);

    RulesPanel(App app, UiEnv env) {
        super(new BorderLayout(4, 4));
        this.app = app;
        this.env = env;
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        add(DecodedView.note("Rules override auto-detection. They're checked top to bottom and the first enabled rule that "
                + "matches decides the decoder (or turns decoding off). A manual choice in the message tab beats rules."), BorderLayout.NORTH);

        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getColumnModel().getColumn(0).setMaxWidth(70);
        table.getColumnModel().getColumn(1).setPreferredWidth(180);
        table.getColumnModel().getColumn(2).setPreferredWidth(130);
        table.getColumnModel().getColumn(3).setPreferredWidth(480);
        table.getColumnModel().getColumn(4).setPreferredWidth(180);
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && table.columnAtPoint(e.getPoint()) != 0) edit();
            }
        });
        add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttons.add(button("Add…", this::add));
        buttons.add(button("Edit…", this::edit));
        buttons.add(button("Duplicate", this::duplicate));
        buttons.add(button("Remove", this::remove));
        buttons.add(button("Move up", () -> move(-1)));
        buttons.add(button("Move down", () -> move(1)));
        add(buttons, BorderLayout.SOUTH);

        app.rules().addListener(() -> DecodedView.onEdt(model::fireTableDataChanged));
        app.registry().addListener(() -> DecodedView.onEdt(model::fireTableDataChanged));
    }

    private static JButton button(String label, Runnable r) {
        JButton b = new JButton(label);
        b.addActionListener(e -> r.run());
        return b;
    }

    private List<Rule> rules() {
        return new ArrayList<>(app.rules().rules());
    }

    private void add() {
        Rule r = RuleEditorDialog.edit(this, app, env, new Rule(), null);
        if (r != null) {
            List<Rule> all = rules();
            all.add(r);
            app.rules().setRules(all);
            select(all.size() - 1);
        }
    }

    private void edit() {
        int i = table.getSelectedRow();
        if (i < 0) return;
        List<Rule> all = rules();
        Rule r = RuleEditorDialog.edit(this, app, env, all.get(i), null);
        if (r != null) {
            all.set(i, r);
            app.rules().setRules(all);
            select(i);
        }
    }

    private void duplicate() {
        int i = table.getSelectedRow();
        if (i < 0) return;
        List<Rule> all = rules();
        all.add(i + 1, all.get(i).duplicate());
        app.rules().setRules(all);
        select(i + 1);
    }

    private void remove() {
        int i = table.getSelectedRow();
        if (i < 0) return;
        List<Rule> all = rules();
        if (JOptionPane.showConfirmDialog(this, "Remove rule \"" + all.get(i).name() + "\"?", "Remove rule", JOptionPane.OK_CANCEL_OPTION) != JOptionPane.OK_OPTION) return;
        all.remove(i);
        app.rules().setRules(all);
    }

    private void move(int delta) {
        int i = table.getSelectedRow();
        List<Rule> all = rules();
        int j = i + delta;
        if (i < 0 || j < 0 || j >= all.size()) return;
        Rule r = all.remove(i);
        all.add(j, r);
        app.rules().setRules(all);
        select(j);
    }

    private void select(int i) {
        DecodedView.onEdt(() -> {
            if (i >= 0 && i < table.getRowCount()) table.setRowSelectionInterval(i, i);
        });
    }

    private final class Model extends AbstractTableModel {
        private static final String[] COLS = {"Enabled", "Name", "Applies to", "Conditions", "Action"};

        @Override public int getRowCount() { return app.rules().rules().size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) { return c == 0 ? Boolean.class : String.class; }
        @Override public boolean isCellEditable(int r, int c) { return c == 0; }

        @Override
        public Object getValueAt(int r, int c) {
            List<Rule> all = app.rules().rules();
            if (r >= all.size()) return null;
            Rule x = all.get(r);
            return switch (c) {
                case 0 -> x.enabled();
                case 1 -> x.name();
                case 2 -> x.target().toString();
                case 3 -> x.describeConditions();
                default -> x.action() == RuleAction.DO_NOT_DECODE ? "Don't decode"
                        : "Decode as " + app.registry().byId(x.decoderId()).map(d -> d.name()).orElse(x.decoderId() + " (missing!)");
            };
        }

        @Override
        public void setValueAt(Object v, int r, int c) {
            if (c != 0) return;
            List<Rule> all = rules();
            all.set(r, all.get(r).copy().enabled(Boolean.TRUE.equals(v)));
            app.rules().setRules(all);
        }
    }
}
