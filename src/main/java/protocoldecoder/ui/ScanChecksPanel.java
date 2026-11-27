package protocoldecoder.ui;

import protocoldecoder.App;
import protocoldecoder.persistence.Settings;
import protocoldecoder.scan.CheckInfo;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;

/** Scanner integration: global switches and per-check enablement. */
final class ScanChecksPanel extends JPanel {

    private final App app;
    private final Model model = new Model();

    ScanChecksPanel(App app) {
        super(new BorderLayout(4, 4));
        this.app = app;
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel top = new JPanel(new BorderLayout());
        top.add(DecodedView.note("Protocol checks run inside Burp's scanner. Passive checks run on proxied traffic and passive scans "
                + "(and on proxied WebSocket messages, reported to the site map). Active checks and protocol-aware insertion points run only "
                + "in active scans you start; insertion points let Burp's own payloads reach values inside protocol encodings "
                + "(lengths and escaping are recomputed). Checks for a protocol only run when its decoder is enabled and applies to the message; "
                + "a \"Don't decode\" rule or manual choice also excludes the message from scanning. Custom scripts can add passive checks "
                + "by defining passive(msg)."), BorderLayout.NORTH);
        Settings s = app.settings();
        JCheckBox passive = toggle("Passive checks", s.scanPassive, (n, v) -> n.scanPassive = v);
        JCheckBox ws = toggle("WebSocket passive checks (proxy)", s.scanWebSockets, (n, v) -> n.scanWebSockets = v);
        JCheckBox active = toggle("Active checks", s.scanActive, (n, v) -> n.scanActive = v);
        JCheckBox ips = toggle("Protocol-aware insertion points", s.scanInsertionPoints, (n, v) -> n.scanInsertionPoints = v);
        JPanel switches = new JPanel(new FlowLayout(FlowLayout.LEFT));
        switches.add(passive);
        switches.add(ws);
        switches.add(active);
        switches.add(ips);
        top.add(switches, BorderLayout.SOUTH);
        add(top, BorderLayout.NORTH);

        JTable table = new JTable(model);
        table.getColumnModel().getColumn(0).setMaxWidth(70);
        table.getColumnModel().getColumn(1).setPreferredWidth(260);
        table.getColumnModel().getColumn(2).setPreferredWidth(110);
        table.getColumnModel().getColumn(3).setPreferredWidth(150);
        table.getColumnModel().getColumn(4).setPreferredWidth(480);
        add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton all = new JButton("Enable all");
        all.addActionListener(e -> model.rows.forEach(c -> app.scanEngine().setEnabled(c.id(), true)));
        JButton none = new JButton("Disable all");
        none.addActionListener(e -> model.rows.forEach(c -> app.scanEngine().setEnabled(c.id(), false)));
        buttons.add(all);
        buttons.add(none);
        add(buttons, BorderLayout.SOUTH);

        app.scanEngine().addListener(() -> DecodedView.onEdt(model::reload));
        app.registry().addListener(() -> DecodedView.onEdt(model::reload));
        model.reload();
    }

    @FunctionalInterface
    private interface Setter {
        void set(Settings s, boolean v);
    }

    private JCheckBox toggle(String label, boolean value, Setter setter) {
        JCheckBox c = new JCheckBox(label, value);
        c.addActionListener(e -> {
            Settings n = app.settings().copy();
            setter.set(n, c.isSelected());
            app.updateSettings(n);
        });
        return c;
    }

    private final class Model extends AbstractTableModel {
        private static final String[] COLS = {"Enabled", "Check", "Protocol", "Type", "Description"};
        List<CheckInfo> rows = new ArrayList<>();

        void reload() {
            rows = new ArrayList<>(app.scanEngine().checks());
            rows.sort(Comparator.comparing((CheckInfo c) -> c.decoderId()).thenComparing(c -> c.kind()).thenComparing(CheckInfo::name));
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }
        @Override public Class<?> getColumnClass(int c) { return c == 0 ? Boolean.class : String.class; }
        @Override public boolean isCellEditable(int r, int c) { return c == 0; }

        @Override
        public Object getValueAt(int r, int c) {
            CheckInfo x = rows.get(r);
            return switch (c) {
                case 0 -> app.scanEngine().isEnabled(x.id());
                case 1 -> x.name();
                case 2 -> x.decoderId().isEmpty() ? "(all)" : app.registry().byId(x.decoderId()).map(d -> d.name()).orElse(x.decoderId());
                case 3 -> x.kind() + (x.scope() == null ? "" : " · " + x.scope().name().toLowerCase().replace('_', ' '));
                default -> x.description();
            };
        }

        @Override
        public void setValueAt(Object v, int r, int c) {
            if (c == 0) app.scanEngine().setEnabled(rows.get(r).id(), Boolean.TRUE.equals(v));
        }
    }
}
