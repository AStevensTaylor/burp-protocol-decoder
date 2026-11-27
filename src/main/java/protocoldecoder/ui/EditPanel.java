package protocoldecoder.ui;

import protocoldecoder.edit.EditEngine;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import javax.swing.BorderFactory;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.table.AbstractTableModel;

/**
 * The "Edit" tab: editable fields (protocol insertion points) and editable documents (protocol codecs). Every change
 * is handed to the owner, which re-encodes it into the message.
 */
final class EditPanel extends JPanel {

    /** Picker entry for a document. */
    private record DocItem(EditEngine.Document doc) {
        @Override
        public String toString() {
            return doc.decoderName() + ": " + doc.document().title();
        }
    }

    private final FieldsModel fields = new FieldsModel();
    private final JTable table = new JTable(fields);
    private final JComboBox<DocItem> docPicker = new JComboBox<>();
    private final JTextArea docText = new JTextArea();
    private final JLabel status = new JLabel(" ");
    private final JLabel fieldsEmpty = new JLabel("  No editable fields for this message.");
    private final JPanel docPanel = new JPanel(new BorderLayout());
    private final UiEnv env;
    private BiConsumer<EditEngine.Field, String> onField = (f, v) -> { };
    private BiConsumer<EditEngine.Document, String> onDocument = (d, t) -> { };
    private Runnable onRevert = () -> { };
    private boolean loading;

    EditPanel(UiEnv env) {
        super(new BorderLayout());
        this.env = env;

        table.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);
        table.getColumnModel().getColumn(0).setPreferredWidth(380);
        table.getColumnModel().getColumn(1).setPreferredWidth(420);
        table.setToolTipText("Double-click a value to edit it; the message is re-encoded when you press Enter");
        JPanel fieldsPanel = new JPanel(new BorderLayout());
        fieldsPanel.setBorder(BorderFactory.createTitledBorder("Fields"));
        fieldsPanel.add(new JScrollPane(table), BorderLayout.CENTER);
        fieldsPanel.add(fieldsEmpty, BorderLayout.NORTH);

        docText.setFont(env.editorFont());
        docText.setTabSize(2);
        JPanel docBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        docBar.add(new JLabel("Document:"));
        docBar.add(docPicker);
        JButton apply = new JButton("Apply document");
        apply.addActionListener(e -> {
            DocItem d = (DocItem) docPicker.getSelectedItem();
            if (d != null) onDocument.accept(d.doc(), docText.getText());
        });
        JButton reset = new JButton("Reset text");
        reset.addActionListener(e -> showSelectedDoc());
        docBar.add(apply);
        docBar.add(reset);
        docPicker.addActionListener(e -> {
            if (!loading) showSelectedDoc();
        });
        docPanel.setBorder(BorderFactory.createTitledBorder("Edit as document"));
        docPanel.add(docBar, BorderLayout.NORTH);
        docPanel.add(new JScrollPane(docText), BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, fieldsPanel, docPanel);
        split.setResizeWeight(0.45);
        split.setBorder(null);

        JPanel footer = new JPanel(new BorderLayout());
        JButton revert = new JButton("Revert all edits");
        revert.addActionListener(e -> onRevert.run());
        footer.add(status, BorderLayout.CENTER);
        footer.add(revert, BorderLayout.EAST);
        status.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));

        add(DecodedView.note("Edit decoded values and the extension re-encodes them into the message (lengths, compression, "
                + "base64, nested JSON…). Changes reach Burp when you switch back to the Raw/Pretty tab or send the request."),
                BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);
        add(footer, BorderLayout.SOUTH);
    }

    void onFieldEdit(BiConsumer<EditEngine.Field, String> l) { this.onField = l; }
    void onDocumentApply(BiConsumer<EditEngine.Document, String> l) { this.onDocument = l; }
    void onRevert(Runnable r) { this.onRevert = r; }

    /** Replaces the fields and documents shown, keeping the selected document when it still exists. */
    void load(List<EditEngine.Field> newFields, List<EditEngine.Document> docs) {
        loading = true;
        try {
            if (table.isEditing()) table.getCellEditor().cancelCellEditing();
            fields.rows = new ArrayList<>(newFields);
            fields.fireTableDataChanged();
            fieldsEmpty.setVisible(newFields.isEmpty());
            String selected = docPicker.getSelectedItem() == null ? null : docPicker.getSelectedItem().toString();
            DefaultComboBoxModel<DocItem> model = new DefaultComboBoxModel<>();
            for (EditEngine.Document d : docs) model.addElement(new DocItem(d));
            docPicker.setModel(model);
            for (int i = 0; i < model.getSize(); i++) if (model.getElementAt(i).toString().equals(selected)) docPicker.setSelectedIndex(i);
            docPanel.setVisible(!docs.isEmpty());
            showSelectedDoc();
        } finally {
            loading = false;
        }
        revalidate();
    }

    private void showSelectedDoc() {
        DocItem d = (DocItem) docPicker.getSelectedItem();
        docText.setText(d == null ? "" : d.doc().document().text());
        docText.setCaretPosition(0);
    }

    void status(String text, boolean error) {
        status.setForeground(error ? env.errorColor() : env.foreground());
        status.setText(text == null || text.isEmpty() ? " " : text);
    }

    int fieldCount() { return fields.rows.size(); }
    int documentCount() { return docPicker.getItemCount(); }
    EditEngine.Field field(int i) { return fields.rows.get(i); }

    /** For tests: press "Revert all edits". */
    void onRevertForTest() { onRevert.run(); }

    /** For tests: edit a field as if typed. */
    void editField(int row, String value) { fields.setValueAt(value, row, 1); }

    /** For tests: select a document, replace its text and apply. */
    void applyDocument(int index, Consumer<JTextArea> edit) {
        docPicker.setSelectedIndex(index);
        edit.accept(docText);
        DocItem d = (DocItem) docPicker.getSelectedItem();
        onDocument.accept(d.doc(), docText.getText());
    }

    private final class FieldsModel extends AbstractTableModel {
        List<EditEngine.Field> rows = new ArrayList<>();

        @Override public int getRowCount() { return rows.size(); }
        @Override public int getColumnCount() { return 2; }
        @Override public String getColumnName(int c) { return c == 0 ? "Field" : "Value"; }
        @Override public boolean isCellEditable(int r, int c) { return c == 1; }

        @Override
        public Object getValueAt(int r, int c) {
            EditEngine.Field f = rows.get(r);
            return c == 0 ? f.label() : f.value();
        }

        @Override
        public void setValueAt(Object v, int r, int c) {
            if (c != 1 || loading) return;
            EditEngine.Field f = rows.get(r);
            String value = v == null ? "" : v.toString();
            if (value.equals(f.value())) return;
            onField.accept(f, value);
        }
    }
}
