package protocoldecoder.ui;

import protocoldecoder.App;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.ProtocolDecoder;
import protocoldecoder.rules.Condition;
import protocoldecoder.rules.ConditionField;
import protocoldecoder.rules.Operator;
import protocoldecoder.rules.Rule;
import protocoldecoder.rules.RuleAction;
import protocoldecoder.rules.RuleTarget;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Window;
import java.util.ArrayList;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;

/** Modal editor for a single {@link Rule}. */
public final class RuleEditorDialog extends JDialog {

    record DecoderItem(String id, String label) {
        @Override
        public String toString() {
            return label;
        }
    }

    private final JTextField name = new JTextField(30);
    private final JCheckBox enabled = new JCheckBox("Enabled", true);
    private final JComboBox<RuleTarget> target = new JComboBox<>(RuleTarget.values());
    private final JComboBox<String> mode = new JComboBox<>(new String[]{"all conditions match", "any condition matches"});
    private final JComboBox<RuleAction> action = new JComboBox<>(RuleAction.values());
    private final JComboBox<DecoderItem> decoder = new JComboBox<>();
    private final ConditionsModel conditions = new ConditionsModel();
    private final JTable table = new JTable(conditions);
    private final JLabel testResult = new JLabel(" ");
    private final MessageContext sample;
    private Rule result;

    private RuleEditorDialog(Component parent, App app, UiEnv env, Rule rule, MessageContext sample) {
        super(SwingUtilities.getWindowAncestor(parent), "Protocol Decoder rule", ModalityType.APPLICATION_MODAL);
        this.sample = sample;

        for (ProtocolDecoder d : app.registry().all()) decoder.addItem(new DecoderItem(d.id(), d.name() + "  (" + d.id() + ")"));
        if (!rule.decoderId().isEmpty() && app.registry().byId(rule.decoderId()).isEmpty()) {
            decoder.addItem(new DecoderItem(rule.decoderId(), rule.decoderId() + "  (missing)"));
        }

        name.setText(rule.name());
        enabled.setSelected(rule.enabled());
        target.setSelectedItem(rule.target());
        mode.setSelectedIndex(rule.mode() == Rule.MatchMode.ALL ? 0 : 1);
        action.setSelectedItem(rule.action());
        for (int i = 0; i < decoder.getItemCount(); i++) {
            if (decoder.getItemAt(i).id().equals(rule.decoderId())) decoder.setSelectedIndex(i);
        }
        for (Condition c : rule.conditions()) conditions.rows.add(c.copy());

        table.setRowHeight(Math.max(table.getRowHeight(), 22));
        table.getColumnModel().getColumn(0).setCellEditor(new DefaultCellEditor(new JComboBox<>(ConditionField.values())));
        table.getColumnModel().getColumn(2).setCellEditor(new DefaultCellEditor(new JComboBox<>(Operator.values())));
        table.getColumnModel().getColumn(0).setPreferredWidth(170);
        table.getColumnModel().getColumn(1).setPreferredWidth(110);
        table.getColumnModel().getColumn(2).setPreferredWidth(150);
        table.getColumnModel().getColumn(3).setPreferredWidth(300);
        table.getColumnModel().getColumn(4).setPreferredWidth(60);
        table.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(3, 4, 3, 4);
        g.anchor = GridBagConstraints.WEST;
        int row = 0;
        addRow(form, g, row++, "Name:", name, enabled);
        addRow(form, g, row++, "Applies to:", target, null);
        addRow(form, g, row++, "When:", mode, null);

        JPanel condPanel = new JPanel(new BorderLayout());
        condPanel.setBorder(BorderFactory.createTitledBorder("Conditions (none = always)"));
        JScrollPane sp = new JScrollPane(table);
        sp.setPreferredSize(new Dimension(820, 170));
        condPanel.add(sp, BorderLayout.CENTER);
        JPanel condButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton add = new JButton("Add condition");
        add.addActionListener(e -> {
            stopEditing();
            conditions.rows.add(new Condition(ConditionField.HOST, Operator.ENDS_WITH, ""));
            conditions.fireTableDataChanged();
            updateTest();
        });
        JButton remove = new JButton("Remove");
        remove.addActionListener(e -> {
            stopEditing();
            int r = table.getSelectedRow();
            if (r >= 0) {
                conditions.rows.remove(r);
                conditions.fireTableDataChanged();
                updateTest();
            }
        });
        condButtons.add(add);
        condButtons.add(remove);
        if (sample != null) condButtons.add(testResult);
        condPanel.add(condButtons, BorderLayout.SOUTH);

        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        actionRow.add(new JLabel("Then:"));
        actionRow.add(action);
        actionRow.add(decoder);
        action.addActionListener(e -> decoder.setEnabled(action.getSelectedItem() == RuleAction.DECODE_AS));
        decoder.setEnabled(rule.action() == RuleAction.DECODE_AS);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton ok = new JButton("Save");
        JButton cancel = new JButton("Cancel");
        ok.addActionListener(e -> save(rule));
        cancel.addActionListener(e -> dispose());
        buttons.add(ok);
        buttons.add(cancel);
        getRootPane().setDefaultButton(ok);

        JPanel center = new JPanel(new BorderLayout());
        center.add(condPanel, BorderLayout.CENTER);
        center.add(actionRow, BorderLayout.SOUTH);

        JPanel content = new JPanel(new BorderLayout(4, 4));
        content.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        content.add(form, BorderLayout.NORTH);
        content.add(center, BorderLayout.CENTER);
        content.add(buttons, BorderLayout.SOUTH);
        setContentPane(content);

        conditions.addTableModelListener(e -> updateTest());
        target.addActionListener(e -> updateTest());
        mode.addActionListener(e -> updateTest());
        updateTest();

        env.theme(this);
        pack();
        setLocationRelativeTo(parent);
    }

    private static void addRow(JPanel p, GridBagConstraints g, int row, String label, Component field, Component extra) {
        g.gridx = 0;
        g.gridy = row;
        g.weightx = 0;
        g.fill = GridBagConstraints.NONE;
        p.add(new JLabel(label), g);
        g.gridx = 1;
        g.weightx = 1;
        g.fill = GridBagConstraints.HORIZONTAL;
        p.add(field, g);
        if (extra != null) {
            g.gridx = 2;
            g.weightx = 0;
            g.fill = GridBagConstraints.NONE;
            p.add(extra, g);
        }
    }

    private void stopEditing() {
        if (table.isEditing()) table.getCellEditor().stopCellEditing();
    }

    private Rule build(Rule base) {
        Rule r = base.copy();
        r.name(name.getText().trim()).enabled(enabled.isSelected())
                .target((RuleTarget) target.getSelectedItem())
                .mode(mode.getSelectedIndex() == 0 ? Rule.MatchMode.ALL : Rule.MatchMode.ANY)
                .action((RuleAction) action.getSelectedItem())
                .conditions(conditions.rows);
        DecoderItem d = (DecoderItem) decoder.getSelectedItem();
        r.decoderId(d == null ? "" : d.id());
        return r;
    }

    private void updateTest() {
        if (sample == null) return;
        Rule r = build(new Rule()).enabled(true);
        if (r.validate() != null && !r.validate().equals("choose a decoder")) {
            testResult.setText("  " + r.validate());
            return;
        }
        testResult.setText(r.matches(sample) ? "  ✔ matches this message" : "  ✘ does not match this message");
    }

    private void save(Rule base) {
        stopEditing();
        Rule r = build(base);
        String err = r.validate();
        if (err != null) {
            JOptionPane.showMessageDialog(this, err, "Invalid rule", JOptionPane.WARNING_MESSAGE);
            return;
        }
        result = r;
        dispose();
    }

    /** Shows the editor; returns the edited rule or null if cancelled. */
    public static Rule edit(Component parent, App app, UiEnv env, Rule rule, MessageContext sample) {
        RuleEditorDialog d = new RuleEditorDialog(parent, app, env, rule, sample);
        d.setVisible(true);
        return d.result;
    }

    /** Opens a new rule prefilled from a message (host + path), and adds it if saved. */
    public static void createFromMessage(Component parent, App app, UiEnv env, MessageContext m, String decoderId) {
        Rule r = new Rule().name(m.host() + m.path())
                .target(m.isWebSocket() ? RuleTarget.WEBSOCKET : m.isRequest() ? RuleTarget.REQUEST : RuleTarget.RESPONSE)
                .decoderId(decoderId == null ? "" : decoderId);
        if (!m.host().isEmpty()) r.addCondition(new Condition(ConditionField.HOST, Operator.EQUALS, m.host()));
        if (!m.path().isEmpty()) r.addCondition(new Condition(ConditionField.PATH, Operator.STARTS_WITH, m.path()));
        Rule saved = edit(parent, app, env, r, m);
        if (saved != null) {
            List<Rule> all = new ArrayList<>();
            all.add(saved); // new rules go first so they win over older, broader ones
            all.addAll(app.rules().rules());
            app.rules().setRules(all);
        }
    }

    static Window window(Component c) {
        return c instanceof Window w ? w : SwingUtilities.getWindowAncestor(c);
    }

    private static final class ConditionsModel extends AbstractTableModel {
        final List<Condition> rows = new ArrayList<>();
        private static final String[] COLS = {"Field", "Header name", "Operator", "Value", "Case"};

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) { return c == 4 ? Boolean.class : Object.class; }
        @Override public boolean isCellEditable(int r, int c) {
            Condition x = rows.get(r);
            if (c == 1) return x.field().needsName();
            if (c == 3) return !x.operator().unary();
            return true;
        }

        @Override
        public Object getValueAt(int r, int c) {
            Condition x = rows.get(r);
            return switch (c) {
                case 0 -> x.field();
                case 1 -> x.field().needsName() ? x.name() : "";
                case 2 -> x.operator();
                case 3 -> x.operator().unary() ? "" : x.value();
                default -> x.caseSensitive();
            };
        }

        @Override
        public void setValueAt(Object v, int r, int c) {
            Condition x = rows.get(r);
            switch (c) {
                case 0 -> x.field((ConditionField) v);
                case 1 -> x.name(String.valueOf(v));
                case 2 -> x.operator((Operator) v);
                case 3 -> x.value(String.valueOf(v));
                default -> x.caseSensitive(Boolean.TRUE.equals(v));
            }
            fireTableRowsUpdated(r, r);
        }
    }
}
