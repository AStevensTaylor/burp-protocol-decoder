package protocoldecoder.util;

import protocoldecoder.core.DecodedNode;

/** Renders a {@link DecodedNode} tree as indented, JSON-like text for the "Text" view and for copying. */
public final class TreeText {

    private static final int MAX_CHARS = 4 * 1024 * 1024;

    private TreeText() {
    }

    public static String render(DecodedNode root) {
        StringBuilder sb = new StringBuilder();
        if (root.isLeaf() && !root.isContainer()) {
            appendValue(sb, root, 0);
        } else {
            renderChildren(sb, root, 0);
        }
        if (sb.length() > MAX_CHARS) {
            sb.setLength(MAX_CHARS);
            sb.append("\n… truncated");
        }
        return sb.toString();
    }

    private static void renderChildren(StringBuilder sb, DecodedNode node, int indent) {
        boolean array = node.type() == DecodedNode.Type.ARRAY;
        sb.append(array ? "[" : "{");
        if (node.value() != null) sb.append("  // ").append(oneLine(node.value()));
        if (node.children().isEmpty()) {
            sb.append(array ? "]" : "}");
            return;
        }
        sb.append('\n');
        int i = 0;
        for (DecodedNode c : node.children()) {
            if (sb.length() > MAX_CHARS) return;
            indent(sb, indent + 1);
            if (!array) sb.append(c.name()).append(": ");
            if (c.isContainer() || !c.isLeaf()) {
                renderChildren(sb, c, indent + 1);
            } else {
                appendValue(sb, c, indent + 1);
            }
            if (++i < node.children().size()) sb.append(',');
            sb.append('\n');
        }
        indent(sb, indent);
        sb.append(array ? "]" : "}");
    }

    private static void appendValue(StringBuilder sb, DecodedNode n, int indent) {
        String v = n.value();
        switch (n.type()) {
            case NUMBER, BOOLEAN, NULL -> sb.append(v);
            case NOTE -> sb.append("/* ").append(v).append(" */");
            default -> {
                if (v == null) {
                    sb.append("null");
                } else if (v.indexOf('\n') >= 0 && n.type() == DecodedNode.Type.HTML) {
                    sb.append("\"\"\"\n").append(v).append("\n");
                    indent(sb, indent);
                    sb.append("\"\"\"");
                } else {
                    sb.append('"').append(escape(v)).append('"');
                }
            }
        }
    }

    private static String escape(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.toString();
    }

    private static String oneLine(String s) {
        return s.replace('\n', ' ').replace('\r', ' ');
    }

    private static void indent(StringBuilder sb, int n) {
        sb.append("  ".repeat(n));
    }
}
