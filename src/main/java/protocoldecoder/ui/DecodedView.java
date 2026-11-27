package protocoldecoder.ui;

import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

/**
 * Renders a {@link DecodeResult}: summary and warnings on top, a "Tree" tab (tree plus full value of the selected node)
 * and a "Text" tab. Used by the message editor tabs and by the script tester.
 */
public final class DecodedView extends JPanel {

    private static final int AUTO_EXPAND_NODES = 400;
    private static final int MAX_LABEL = 300;

    private final UiEnv env;
    private final JLabel summary = new JLabel(" ");
    private final JTextArea warnings = new JTextArea();
    private final JTree tree = new JTree(new DefaultTreeModel(new DefaultMutableTreeNode()));
    private final JTextArea detail = new JTextArea();
    private final JTextArea text = new JTextArea();
    private final JTextField find = new JTextField(16);
    private final JTabbedPane tabs = new JTabbedPane();
    private DecodeResult current;

    public DecodedView(UiEnv env) {
        super(new BorderLayout());
        this.env = env;

        summary.setFont(summary.getFont().deriveFont(Font.BOLD));
        summary.setBorder(BorderFactory.createEmptyBorder(4, 6, 2, 6));
        warnings.setEditable(false);
        warnings.setLineWrap(true);
        warnings.setWrapStyleWord(true);
        warnings.setBackground(env.warningBackground());
        warnings.setBorder(BorderFactory.createEmptyBorder(3, 6, 3, 6));
        warnings.setVisible(false);

        JPanel top = new JPanel(new BorderLayout());
        top.add(summary, BorderLayout.NORTH);
        top.add(warnings, BorderLayout.CENTER);

        tree.setRootVisible(false);
        tree.setShowsRootHandles(true);
        tree.setCellRenderer(new Renderer());
        tree.setLargeModel(true);
        tree.addTreeSelectionListener(e -> showDetail());
        tree.setComponentPopupMenu(treeMenu());

        for (JTextArea a : new JTextArea[]{detail, text}) {
            a.setEditable(false);
            a.setFont(env.editorFont());
            a.setTabSize(2);
        }
        detail.setLineWrap(true);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(tree), new JScrollPane(detail));
        split.setResizeWeight(0.8);
        split.setBorder(null);

        JPanel treeTab = new JPanel(new BorderLayout());
        treeTab.add(split, BorderLayout.CENTER);
        JPanel findBar = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 2));
        findBar.add(new JLabel("Find:"));
        findBar.add(find);
        JButton next = new JButton("Next");
        next.addActionListener(e -> findNext());
        find.addActionListener(e -> findNext());
        findBar.add(next);
        JButton expand = new JButton("Expand all");
        expand.addActionListener(e -> expandAll(Integer.MAX_VALUE));
        JButton collapse = new JButton("Collapse");
        collapse.addActionListener(e -> {
            for (int i = tree.getRowCount() - 1; i >= 0; i--) tree.collapseRow(i);
        });
        findBar.add(expand);
        findBar.add(collapse);
        treeTab.add(findBar, BorderLayout.SOUTH);

        tabs.addTab("Tree", treeTab);
        tabs.addTab("Text", new JScrollPane(text));

        add(top, BorderLayout.NORTH);
        add(tabs, BorderLayout.CENTER);
    }

    /** Shows a successful result. */
    public void show(DecodeResult r) {
        current = r;
        summary.setForeground(env.foreground());
        summary.setText(r.summary().isEmpty() ? " " : r.summary());
        setWarnings(r.warnings());
        DefaultMutableTreeNode root = toTree(r.root());
        tree.setModel(new DefaultTreeModel(root));
        expandAll(AUTO_EXPAND_NODES);
        text.setText(r.renderedText());
        text.setCaretPosition(0);
        detail.setText("");
    }

    /** Shows an error message instead of a result. */
    public void showError(String message) {
        current = null;
        summary.setForeground(env.errorColor());
        summary.setText("Could not decode");
        setWarnings(List.of(message == null ? "unknown error" : message));
        tree.setModel(new DefaultTreeModel(new DefaultMutableTreeNode()));
        text.setText(message == null ? "" : message);
        detail.setText("");
    }

    /** Shows a neutral status message (e.g. "Decoding…", "No decoder"). */
    public void showMessage(String message) {
        current = null;
        summary.setForeground(env.foreground());
        summary.setText(message);
        setWarnings(List.of());
        tree.setModel(new DefaultTreeModel(new DefaultMutableTreeNode()));
        text.setText("");
        detail.setText("");
    }

    public DecodeResult current() {
        return current;
    }

    /** Value of the selected tree node, or the selected text in the Text tab, or null. */
    public String selectedValue() {
        if (tabs.getSelectedIndex() == 1) return text.getSelectedText();
        DecodedNode n = selectedNode();
        return n == null ? null : n.value() != null ? n.value() : protocoldecoder.util.TreeText.render(n);
    }

    private DecodedNode selectedNode() {
        TreePath p = tree.getSelectionPath();
        if (p == null) return null;
        Object u = ((DefaultMutableTreeNode) p.getLastPathComponent()).getUserObject();
        return u instanceof DecodedNode dn ? dn : null;
    }

    public String fullText() {
        return text.getText();
    }

    private void setWarnings(List<String> w) {
        warnings.setText(String.join("\n", w.stream().map(s -> "⚠ " + s).toList()));
        warnings.setVisible(!w.isEmpty());
        revalidate();
    }

    private static DefaultMutableTreeNode toTree(DecodedNode n) {
        DefaultMutableTreeNode t = new DefaultMutableTreeNode(n);
        for (DecodedNode c : n.children()) t.add(toTree(c));
        return t;
    }

    private void expandAll(int budget) {
        int expanded = 0;
        for (int row = 0; row < tree.getRowCount() && expanded < budget; row++) {
            TreePath p = tree.getPathForRow(row);
            DefaultMutableTreeNode n = (DefaultMutableTreeNode) p.getLastPathComponent();
            if (!n.isLeaf()) {
                expanded += n.getChildCount();
                if (expanded <= budget || budget == Integer.MAX_VALUE) tree.expandRow(row);
            }
        }
    }

    private void showDetail() {
        DecodedNode n = selectedNode();
        if (n == null) {
            detail.setText("");
        } else if (n.value() != null && n.isLeaf()) {
            detail.setText(n.value());
        } else {
            detail.setText(protocoldecoder.util.TreeText.render(n));
        }
        detail.setCaretPosition(0);
    }

    private void findNext() {
        String q = find.getText().trim().toLowerCase(Locale.ROOT);
        if (q.isEmpty()) return;
        DefaultMutableTreeNode root = (DefaultMutableTreeNode) tree.getModel().getRoot();
        List<DefaultMutableTreeNode> all = new ArrayList<>();
        Enumeration<?> e = root.preorderEnumeration();
        while (e.hasMoreElements()) all.add((DefaultMutableTreeNode) e.nextElement());
        int start = 0;
        TreePath sel = tree.getSelectionPath();
        if (sel != null) start = all.indexOf((DefaultMutableTreeNode) sel.getLastPathComponent()) + 1;
        for (int i = 0; i < all.size(); i++) {
            DefaultMutableTreeNode t = all.get((start + i) % all.size());
            if (t.getUserObject() instanceof DecodedNode dn) {
                String hay = (dn.name() + " " + (dn.value() == null ? "" : dn.value())).toLowerCase(Locale.ROOT);
                if (hay.contains(q)) {
                    TreePath p = new TreePath(t.getPath());
                    tree.setSelectionPath(p);
                    tree.scrollPathToVisible(p);
                    return;
                }
            }
        }
        Toolkit.getDefaultToolkit().beep();
    }

    private JPopupMenu treeMenu() {
        JPopupMenu m = new JPopupMenu();
        JMenuItem copyValue = new JMenuItem("Copy value");
        copyValue.addActionListener(e -> copy(selectedValue()));
        JMenuItem copyName = new JMenuItem("Copy name");
        copyName.addActionListener(e -> {
            DecodedNode n = selectedNode();
            if (n != null) copy(n.name());
        });
        JMenuItem copyAll = new JMenuItem("Copy all as text");
        copyAll.addActionListener(e -> copy(text.getText()));
        m.add(copyValue);
        m.add(copyName);
        m.add(copyAll);
        return m;
    }

    static void copy(String s) {
        if (s != null) Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(s), null);
    }

    /** Colours values by type and keeps long values to one line. */
    private final class Renderer extends DefaultTreeCellRenderer {
        @Override
        public Component getTreeCellRendererComponent(JTree t, Object value, boolean sel, boolean expanded, boolean leaf, int row, boolean focus) {
            super.getTreeCellRendererComponent(t, value, sel, expanded, leaf, row, focus);
            setIcon(null);
            Object u = ((DefaultMutableTreeNode) value).getUserObject();
            if (!(u instanceof DecodedNode n)) return this;
            String name = esc(n.name());
            String label;
            if (n.isContainer() || !n.isLeaf()) {
                String count = n.type() == DecodedNode.Type.ARRAY ? " [" + n.children().size() + "]" : n.children().isEmpty() ? " {}" : "";
                label = "<b>" + name + "</b>" + count + (n.value() != null ? "  " + span(env.noteColor(), oneLine(n.value())) : "");
            } else {
                java.awt.Color c = switch (n.type()) {
                    case NUMBER -> env.numberColor();
                    case BOOLEAN, NULL -> env.keywordColor();
                    case NOTE, BINARY -> env.noteColor();
                    case HTML -> env.htmlColor();
                    default -> env.stringColor();
                };
                String v = n.value() == null ? "null" : oneLine(n.value());
                if (n.type() == DecodedNode.Type.NOTE) v = "(" + v + ")";
                label = (name.isEmpty() ? "" : name + ": ") + (sel ? esc(v) : span(c, v));
            }
            setText("<html><nobr>" + label + "</nobr></html>");
            return this;
        }

        private String oneLine(String s) {
            String t = s.replace('\n', ' ').replace('\r', ' ');
            return t.length() > MAX_LABEL ? t.substring(0, MAX_LABEL) + " …" : t;
        }

        private String span(java.awt.Color c, String s) {
            return String.format("<span style='color:#%06x'>%s</span>", c.getRGB() & 0xffffff, esc(s));
        }
    }

    /** Read-only text that wraps to the available width (an HTML JLabel doesn't). */
    static JTextArea note(String text) {
        JTextArea a = new JTextArea(text);
        a.setEditable(false);
        a.setFocusable(false);
        a.setLineWrap(true);
        a.setWrapStyleWord(true);
        a.setOpaque(false);
        a.setFont(javax.swing.UIManager.getFont("Label.font"));
        a.setBorder(BorderFactory.createEmptyBorder(0, 2, 4, 2));
        return a;
    }

    static String esc(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    /** Runs on the EDT, now if already there. */
    static void onEdt(Runnable r) {
        if (SwingUtilities.isEventDispatchThread()) r.run();
        else SwingUtilities.invokeLater(r);
    }
}
