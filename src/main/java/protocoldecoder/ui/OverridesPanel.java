package protocoldecoder.ui;

import protocoldecoder.App;
import protocoldecoder.core.OverrideStore;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.AbstractTableModel;

/** Manual per-message decoder choices. */
final class OverridesPanel extends JPanel {

    private final App app;
    private final Model model = new Model();
    private final JTable table = new JTable(model);

    OverridesPanel(App app) {
        super(new BorderLayout(4, 4));
        this.app = app;
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        add(DecodedView.note("Messages you've told to decode with a specific decoder (from the message tab's Decoder picker "
                + "or the context menu). These win over rules and auto-detection."), BorderLayout.NORTH);
        table.getColumnModel().getColumn(0).setPreferredWidth(700);
        table.getColumnModel().getColumn(1).setPreferredWidth(200);
        add(new JScrollPane(table), BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton remove = new JButton("Remove selected");
        remove.addActionListener(e -> {
            int[] rows = table.getSelectedRows();
            List<String> keys = new ArrayList<>();
            for (int r : rows) keys.add(model.rows.get(r).getKey());
            keys.forEach(k -> app.overrides().remove(k));
        });
        JButton clear = new JButton("Clear all");
        clear.addActionListener(e -> {
            if (JOptionPane.showConfirmDialog(this, "Remove all manual decoder choices?", "Clear", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
                app.overrides().clearAll();
            }
        });
        buttons.add(remove);
        buttons.add(clear);
        add(buttons, BorderLayout.SOUTH);

        app.overrides().addListener(() -> DecodedView.onEdt(model::reload));
        model.reload();
    }

    private final class Model extends AbstractTableModel {
        List<Map.Entry<String, OverrideStore.Entry>> rows = new ArrayList<>();

        void reload() {
            rows = new ArrayList<>(app.overrides().snapshot().entrySet());
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return 2; }
        @Override public String getColumnName(int c) { return c == 0 ? "Message" : "Decoder"; }

        @Override
        public Object getValueAt(int r, int c) {
            OverrideStore.Entry e = rows.get(r).getValue();
            if (c == 0) return e.description();
            if (OverrideStore.NONE.equals(e.decoderId())) return "Don't decode";
            return app.registry().byId(e.decoderId()).map(d -> d.name()).orElse(e.decoderId() + " (missing)");
        }
    }
}
