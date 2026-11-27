package protocoldecoder.builtin.devexpress;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

/**
 * Re-serialisable model of a DevExpress callback argument (see {@link DxCallbackArgs} for the format). Used to put
 * scanner payloads inside segments while keeping every enclosing length prefix correct.
 */
final class DxArgModel {

    /** A value: either a leaf string, named segments, or positional segments. */
    sealed interface Node permits Leaf, Named, Positional {
        String serialize();
    }

    record Leaf(String value) implements Node {
        public String serialize() {
            return value;
        }
    }

    record Named(List<String> names, List<Node> values) implements Node {
        public String serialize() {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < names.size(); i++) {
                String v = values.get(i).serialize();
                sb.append(names.get(i)).append('|').append(v.length()).append(';').append(v).append(';');
            }
            return sb.toString();
        }
    }

    record Positional(List<Node> values, boolean trailingSemicolon) implements Node {
        public String serialize() {
            StringBuilder sb = new StringBuilder();
            for (Node n : values) {
                String v = n.serialize();
                sb.append(v.length()).append('|').append(v);
            }
            if (trailingSemicolon) sb.append(';');
            return sb.toString();
        }
    }

    /** The whole parameter: optional "cN:" prefix plus the body. */
    record Arg(String prefix, Node body) {
        String serialize() {
            return prefix + body.serialize();
        }
    }

    private static final int MAX_DEPTH = 8;

    private DxArgModel() {
    }

    static Arg parse(String param) {
        String prefix = "";
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("^c\\d+:").matcher(param);
        if (m.find()) prefix = m.group();
        return new Arg(prefix, parseNode(param.substring(prefix.length()), 0));
    }

    private static Node parseNode(String s, int depth) {
        if (depth >= MAX_DEPTH) return new Leaf(s);
        List<String[]> named = DxCallbackArgs.parseNamed(s);
        if (named != null && !named.isEmpty() && new Named(names(named), leaves(named)).serialize().equals(s)) {
            List<Node> vals = new ArrayList<>();
            for (String[] seg : named) vals.add(parseNode(seg[1], depth + 1));
            return new Named(names(named), vals);
        }
        List<String> pos = DxCallbackArgs.parsePositional(s);
        if (pos != null && !(pos.size() == 1 && pos.get(0).equals(s))) {
            boolean semi = s.endsWith(";");
            List<Node> vals = new ArrayList<>();
            for (String p : pos) vals.add(new Leaf(p));
            if (new Positional(vals, semi).serialize().equals(s)) {
                List<Node> parsed = new ArrayList<>();
                for (String p : pos) parsed.add(parseNode(p, depth + 1));
                return new Positional(parsed, semi);
            }
        }
        return new Leaf(s);
    }

    private static List<String> names(List<String[]> named) {
        List<String> n = new ArrayList<>();
        for (String[] seg : named) n.add(seg[0]);
        return n;
    }

    private static List<Node> leaves(List<String[]> named) {
        List<Node> n = new ArrayList<>();
        for (String[] seg : named) n.add(new Leaf(seg[1]));
        return n;
    }

    /**
     * Visits every leaf with a path and a function rebuilding the whole argument with that leaf replaced.
     */
    static void leaves(Arg arg, BiConsumer<String, LeafSlot> visitor) {
        walk(arg.body(), "", replacement -> arg.prefix() + replacement.serialize(), visitor);
    }

    /** A leaf's current value and a way to rebuild the whole argument around a new value. */
    record LeafSlot(String value, java.util.function.Function<String, String> rebuild) {
    }

    private static void walk(Node n, String path, java.util.function.Function<Node, String> rebuildParent, BiConsumer<String, LeafSlot> visitor) {
        switch (n) {
            case Leaf l -> visitor.accept(path.isEmpty() ? "value" : path, new LeafSlot(l.value(), v -> rebuildParent.apply(new Leaf(v))));
            case Named nm -> {
                for (int i = 0; i < nm.names().size(); i++) {
                    final int idx = i;
                    walk(nm.values().get(i), path + (path.isEmpty() ? "" : ".") + nm.names().get(i), child -> {
                        List<Node> vals = new ArrayList<>(nm.values());
                        vals.set(idx, child);
                        return rebuildParent.apply(new Named(nm.names(), vals));
                    }, visitor);
                }
            }
            case Positional p -> {
                for (int i = 0; i < p.values().size(); i++) {
                    final int idx = i;
                    walk(p.values().get(i), path + "[" + i + "]", child -> {
                        List<Node> vals = new ArrayList<>(p.values());
                        vals.set(idx, child);
                        return rebuildParent.apply(new Positional(vals, p.trailingSemicolon()));
                    }, visitor);
                }
            }
        }
    }
}
