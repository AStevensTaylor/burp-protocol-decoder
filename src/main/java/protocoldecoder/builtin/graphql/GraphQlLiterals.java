package protocoldecoder.builtin.graphql;

import protocoldecoder.builtin.graphql.GraphQlLexer.Kind;
import protocoldecoder.builtin.graphql.GraphQlLexer.Token;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Finds inline argument literals (strings, block strings, numbers, enum values) in an executable GraphQL document and
 * replaces one of them with a payload, re-escaped as a GraphQL string literal. Only lexically valid documents are
 * handled; variable definitions (types and default values) are skipped.
 */
final class GraphQlLiterals {

    static final int MAX_DOC_CHARS = 1024 * 1024;
    private static final int MAX_TOKENS = 200_000;
    private static final Pattern NUMBER = Pattern.compile("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?");
    private static final Set<String> OP_TYPES = Set.of("query", "mutation", "subscription");
    private static final Set<String> NOT_ENUMS = Set.of("true", "false", "null");

    /** One literal: its token span in the document, a label for the definition it is in, and its argument path. */
    record Literal(int start, int end, Kind kind, String definition, String path, String baseValue) {
        boolean numeric() {
            return kind == Kind.NUMBER;
        }
    }

    private enum Ctx { SELECTION, ARGS, OBJECT, LIST, SKIP }

    private static final class Frame {
        final Ctx ctx;
        final String path;     // argument path of this container ("user.id", "filter.tags")
        final boolean pushedField;
        String key;            // ARGS/OBJECT: key whose value comes next
        int index;             // LIST: next element index

        Frame(Ctx ctx, String path, boolean pushedField) {
            this.ctx = ctx;
            this.path = path;
            this.pushedField = pushedField;
        }
    }

    private GraphQlLiterals() {
    }

    static List<Literal> find(String src, int max) {
        List<Literal> out = new ArrayList<>();
        if (src == null || src.isEmpty() || src.length() > MAX_DOC_CHARS || max <= 0) return out;
        GraphQlLexer.Result lex = GraphQlLexer.tokenize(src, MAX_TOKENS);
        if (!lex.errors.isEmpty() || lex.truncated) return out;
        List<Token> sig = new ArrayList<>();
        for (Token t : lex.tokens) if (t.significant()) sig.add(t);

        Deque<Frame> stack = new ArrayDeque<>();
        Deque<String> fields = new ArrayDeque<>(); // selection path (field names), innermost last
        String definition = null;     // label of the current top-level definition
        boolean header = false;       // inside a definition header (before its selection set)
        String lastField = null;
        boolean inlineFragment = false;

        for (int i = 0; i < sig.size() && out.size() < max; i++) {
            Token t = sig.get(i);
            Token prev = i > 0 ? sig.get(i - 1) : null;
            Token prev2 = i > 1 ? sig.get(i - 2) : null;
            Token next = i + 1 < sig.size() ? sig.get(i + 1) : null;
            Frame top = stack.peek();

            if (top != null && top.ctx == Ctx.SKIP) {
                if (t.is("(") || t.is("[") || t.is("{")) stack.push(new Frame(Ctx.SKIP, "", false));
                else if (t.is(")") || t.is("]") || t.is("}")) stack.pop();
                continue;
            }

            if (top == null) {
                // ---- top level: definition headers
                if (t.kind() == Kind.NAME && !header && OP_TYPES.contains(t.text())) {
                    header = true;
                    definition = t.text();
                    if (next != null && next.kind() == Kind.NAME) {
                        definition = next.text();
                        i++;
                    }
                } else if (t.isName("fragment") && !header) {
                    header = true;
                    definition = next != null && next.kind() == Kind.NAME ? "fragment " + next.text() : "fragment";
                } else if (t.is("(")) {
                    boolean directive = prev != null && prev.kind() == Kind.NAME && prev2 != null && prev2.is("@");
                    stack.push(directive ? new Frame(Ctx.ARGS, "@" + prev.text(), false) : new Frame(Ctx.SKIP, "", false));
                } else if (t.is("{")) {
                    if (!header) definition = "query";
                    header = false;
                    lastField = null;
                    inlineFragment = false;
                    stack.push(new Frame(Ctx.SELECTION, "", false));
                }
                continue;
            }

            switch (top.ctx) {
                case SELECTION -> {
                    if (t.is("{")) {
                        boolean push = !inlineFragment && lastField != null;
                        if (push) fields.addLast(lastField);
                        stack.push(new Frame(Ctx.SELECTION, "", push));
                        lastField = null;
                        inlineFragment = false;
                    } else if (t.is("}")) {
                        Frame f = stack.pop();
                        if (f.pushedField && !fields.isEmpty()) fields.removeLast();
                        lastField = null;
                    } else if (t.is("(")) {
                        boolean directive = prev != null && prev.kind() == Kind.NAME && prev2 != null && prev2.is("@");
                        String owner = join(fields, lastField) + (directive ? "@" + prev.text() : "");
                        stack.push(new Frame(Ctx.ARGS, owner, false));
                    } else if (t.kind() == Kind.SPREAD) {
                        inlineFragment = !(next != null && next.kind() == Kind.NAME && !next.text().equals("on"));
                        if (!inlineFragment) i++; // named fragment spread: skip its name
                    } else if (t.kind() == Kind.NAME) {
                        if (prev != null && prev.is("@")) {
                            // directive name
                        } else if (prev != null && prev.kind() == Kind.SPREAD && t.text().equals("on")) {
                            if (next != null && next.kind() == Kind.NAME) i++; // type condition
                        } else {
                            lastField = t.text(); // after "alias:" this replaces the alias with the real field
                        }
                    }
                }
                case ARGS, OBJECT -> {
                    if (t.is(")") || t.is("}")) {
                        stack.pop();
                    } else if (prev != null && prev.is(":") && top.key != null) {
                        String path = child(top.path, top.key);
                        top.key = null;
                        if (!value(t, next, path, definition, out, stack)) {
                            if (t.is("$")) i++;
                        }
                    } else if (t.kind() == Kind.NAME && next != null && next.is(":")) {
                        top.key = t.text();
                    }
                }
                case LIST -> {
                    if (t.is("]")) {
                        stack.pop();
                    } else {
                        String path = top.path + "[" + top.index++ + "]";
                        if (!value(t, next, path, definition, out, stack)) {
                            if (t.is("$")) i++;
                        }
                    }
                }
                default -> {
                }
            }
        }
        return out;
    }

    /** Handles a token in value position; returns true if it was consumed as a literal or container. */
    private static boolean value(Token t, Token next, String path, String definition, List<Literal> out, Deque<Frame> stack) {
        if (t.is("{")) {
            stack.push(new Frame(Ctx.OBJECT, path, false));
            return true;
        }
        if (t.is("[")) {
            stack.push(new Frame(Ctx.LIST, path, false));
            return true;
        }
        Kind k = t.kind();
        if (k == Kind.STRING || k == Kind.BLOCK_STRING || k == Kind.NUMBER || (k == Kind.NAME && !NOT_ENUMS.contains(t.text()))) {
            out.add(new Literal(t.pos(), t.pos() + t.text().length(), k, definition, path, baseValue(t)));
            return true;
        }
        return false;
    }

    private static String join(Deque<String> fields, String last) {
        StringBuilder sb = new StringBuilder();
        for (String f : fields) {
            if (sb.length() > 0) sb.append('.');
            sb.append(f);
        }
        if (last != null) {
            if (sb.length() > 0) sb.append('.');
            sb.append(last);
        }
        return sb.toString();
    }

    private static String child(String path, String key) {
        return path.isEmpty() ? key : path + "." + key;
    }

    /** The document with one literal replaced by the payload. */
    static String render(String src, Literal lit, String payload) {
        String p = payload == null ? "" : payload;
        String text = lit.numeric() && NUMBER.matcher(p).matches() ? p : quote(p);
        return src.substring(0, lit.start()) + text + src.substring(lit.end());
    }

    /** A GraphQL string literal for any text. */
    static String quote(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2).append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20 || c == 0x7f || Character.isSurrogate(c) && !validSurrogate(s, i)) {
                        sb.append(String.format("\\u%04X", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.append('"').toString();
    }

    private static boolean validSurrogate(String s, int i) {
        char c = s.charAt(i);
        if (Character.isHighSurrogate(c)) return i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1));
        return i > 0 && Character.isHighSurrogate(s.charAt(i - 1));
    }

    /** The value a literal token denotes (strings unescaped). */
    static String baseValue(Token t) {
        String s = t.text();
        if (t.kind() == Kind.BLOCK_STRING) return s.length() >= 6 ? s.substring(3, s.length() - 3).replace("\\\"\"\"", "\"\"\"") : s;
        if (t.kind() != Kind.STRING) return s;
        return unescape(s.length() >= 2 ? s.substring(1, s.length() - 1) : s);
    }

    private static final Map<Character, Character> ESCAPES = new HashMap<>(Map.of('"', '"', '\\', '\\', '/', '/',
            'b', '\b', 'f', '\f', 'n', '\n', 'r', '\r', 't', '\t'));

    static String unescape(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c != '\\' || i + 1 >= s.length()) {
                sb.append(c);
                continue;
            }
            char e = s.charAt(++i);
            if (e == 'u') {
                String hex = i + 5 <= s.length() ? s.substring(i + 1, i + 5) : "";
                if (hex.length() == 4 && hex.chars().allMatch(ch -> Character.digit(ch, 16) >= 0)) {
                    sb.append((char) Integer.parseInt(hex, 16));
                    i += 4;
                    continue;
                }
                sb.append('\\').append(e);
            } else if (ESCAPES.containsKey(e)) {
                sb.append(ESCAPES.get(e));
            } else {
                sb.append('\\').append(e);
            }
        }
        return sb.toString();
    }
}
