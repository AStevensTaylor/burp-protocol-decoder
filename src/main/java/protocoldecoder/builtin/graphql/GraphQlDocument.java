package protocoldecoder.builtin.graphql;

import protocoldecoder.builtin.graphql.GraphQlLexer.Kind;
import protocoldecoder.builtin.graphql.GraphQlLexer.Token;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Set;

/**
 * A GraphQL document as far as a proxy viewer cares: a re-indented rendering plus the operations (type, name,
 * variable definitions, root fields), fragments and an introspection flag. Works on the token stream with a bracket
 * stack rather than a full parser, so malformed documents still produce something useful; problems become warnings.
 */
final class GraphQlDocument {

    /** Documents larger than this are not re-formatted. */
    static final int MAX_FORMAT_CHARS = 2 * 1024 * 1024;
    static final int MAX_TOKENS = 400_000;
    private static final int MAX_LIST = 500;

    private static final Set<String> OPERATION_TYPES = Set.of("query", "mutation", "subscription");

    record Operation(String type, String name, List<String> variables, List<String> directives, List<String> rootFields) {
        String label() {
            return name == null ? type + " (anonymous)" : type + " " + name;
        }
    }

    record Fragment(String name, String typeCondition) {
    }

    private enum Ctx { SELECTION, PARENS, LIST, OBJECT }

    /** Structural information about one token, computed in a single pass. */
    private static final class Ann {
        Ctx ctx;        // innermost bracket context before the token
        int depth;      // bracket depth before the token
        boolean selStart;
        Ctx opens;
        Ctx closes;
    }

    final String source;
    final List<Operation> operations = new ArrayList<>();
    final List<Fragment> fragments = new ArrayList<>();
    final List<String> otherDefinitions = new ArrayList<>();
    final List<String> warnings = new ArrayList<>();
    boolean introspection;
    /** Pretty-printed document, or the raw source when formatting was not possible. */
    String formatted;
    /** False if the lexer reported errors. */
    boolean lexicallyValid = true;

    private GraphQlDocument(String source) {
        this.source = source;
    }

    static GraphQlDocument parse(String source) {
        GraphQlDocument d = new GraphQlDocument(source == null ? "" : source);
        try {
            d.run();
        } catch (RuntimeException e) {
            d.formatted = d.source;
            d.warnings.add("Could not analyse GraphQL document (" + e + "); showing raw text");
        }
        return d;
    }

    /** Operation selected by operationName (or the only/first operation), or null if the document has none. */
    Operation select(String operationName) {
        if (operationName != null) {
            for (Operation o : operations) if (operationName.equals(o.name)) return o;
        }
        return operations.isEmpty() ? null : operations.get(0);
    }

    boolean hasOperation(String name) {
        for (Operation o : operations) if (name != null && name.equals(o.name)) return true;
        return false;
    }

    // ------------------------------------------------------------------ detection

    /**
     * Cheap check used by matchers: does this string start like an executable GraphQL document, with no lexical
     * errors in (a bounded prefix of) it?
     */
    static boolean isLikelyDocument(String s) {
        if (s == null) return false;
        int limit = 16 * 1024;
        boolean cut = s.length() > limit;
        String head = cut ? s.substring(0, limit) : s;
        if (head.indexOf('{') < 0) return false;
        GraphQlLexer.Result r = GraphQlLexer.tokenize(head, 4000);
        List<Token> sig = new ArrayList<>();
        for (Token t : r.tokens) {
            if (t.kind() == Kind.ERROR && (!cut || t.pos() < head.length() - 1024)) return false;
            if (t.significant()) sig.add(t);
        }
        if (sig.size() < 3) return false;
        Token a = sig.get(0), b = sig.get(1), c = sig.get(2);
        if (a.is("{")) return b.kind() == Kind.NAME || b.kind() == Kind.SPREAD;
        if (a.kind() == Kind.NAME && OPERATION_TYPES.contains(a.text())) {
            Token next = b.kind() == Kind.NAME ? c : b;
            return next.is("(") || next.is("@") || next.is("{");
        }
        if (a.isName("fragment") && sig.size() >= 5) {
            return b.kind() == Kind.NAME && c.isName("on") && sig.get(3).kind() == Kind.NAME
                    && (sig.get(4).is("{") || sig.get(4).is("@"));
        }
        return false;
    }

    // ------------------------------------------------------------------ analysis

    private void run() {
        if (source.length() > MAX_FORMAT_CHARS) {
            formatted = source;
            warnings.add("GraphQL document is " + source.length() + " characters; not re-formatted or analysed");
            return;
        }
        GraphQlLexer.Result lex = GraphQlLexer.tokenize(source, MAX_TOKENS);
        List<Token> toks = lex.tokens;
        if (!lex.errors.isEmpty()) {
            lexicallyValid = false;
            warnings.add("GraphQL syntax error: " + String.join("; ", lex.errors));
        }
        if (lex.truncated) warnings.add("GraphQL document has more than " + MAX_TOKENS + " tokens; analysis is partial");

        Ann[] ann = annotate(toks);
        analyse(toks, ann);
        if (lexicallyValid && !lex.truncated) {
            formatted = format(toks, ann);
        } else {
            formatted = source;
            warnings.add("Showing the GraphQL document as sent (not re-formatted)");
        }
        if (operations.isEmpty() && fragments.isEmpty() && otherDefinitions.isEmpty()) {
            warnings.add("No GraphQL operations found in the document");
        }
    }

    private Ann[] annotate(List<Token> toks) {
        Ann[] ann = new Ann[toks.size()];
        Deque<Ctx> stack = new ArrayDeque<>();
        Token prev = null, prev2 = null;
        int strays = 0;
        for (int k = 0; k < toks.size(); k++) {
            Token t = toks.get(k);
            Ann a = new Ann();
            a.ctx = stack.peek();
            a.depth = stack.size();
            ann[k] = a;
            if (!t.significant()) continue;
            if (t.is("{")) {
                Ctx c = a.ctx == Ctx.PARENS || a.ctx == Ctx.LIST || a.ctx == Ctx.OBJECT ? Ctx.OBJECT : Ctx.SELECTION;
                stack.push(c);
                a.opens = c;
            } else if (t.is("(")) {
                stack.push(Ctx.PARENS);
                a.opens = Ctx.PARENS;
            } else if (t.is("[")) {
                stack.push(Ctx.LIST);
                a.opens = Ctx.LIST;
            } else if (t.is("}") || t.is(")") || t.is("]")) {
                Set<Ctx> want = t.is("}") ? Set.of(Ctx.SELECTION, Ctx.OBJECT) : t.is(")") ? Set.of(Ctx.PARENS) : Set.of(Ctx.LIST);
                if (!stack.isEmpty() && want.contains(stack.peek())) {
                    a.closes = stack.pop();
                } else if (stack.stream().anyMatch(want::contains)) {
                    while (!want.contains(stack.peek())) stack.pop();
                    a.closes = stack.pop();
                    strays++;
                } else {
                    strays++;
                }
            } else if ((t.kind() == Kind.NAME || t.kind() == Kind.SPREAD) && a.ctx == Ctx.SELECTION) {
                a.selStart = startsSelection(prev, prev2);
                if (t.kind() == Kind.NAME && (t.text().equals("__schema") || t.text().equals("__type"))
                        && (a.selStart || (prev != null && prev.is(":")))) {
                    introspection = true;
                }
            }
            prev2 = prev;
            prev = t;
        }
        if (strays > 0) warnings.add("GraphQL document has " + strays + " mismatched closing bracket(s)");
        if (!stack.isEmpty()) warnings.add("GraphQL document has " + stack.size() + " unclosed bracket(s)");
        return ann;
    }

    /** In a selection set, does this name/spread begin a new selection (rather than continue the previous one)? */
    private static boolean startsSelection(Token prev, Token prev2) {
        if (prev == null) return true;
        if (prev.is(":") || prev.is("...") || prev.is("@")) return false;
        return !(prev.isName("on") && prev2 != null && prev2.is("..."));
    }

    private void analyse(List<Token> toks, Ann[] ann) {
        List<Integer> sig = new ArrayList<>();
        for (int k = 0; k < toks.size(); k++) if (toks.get(k).significant()) sig.add(k);

        String opType = null, opName = null;
        List<String> vars = null, dirs = null, fields = null;
        boolean inHeader = false, inVarDefs = false, inBody = false;
        StringBuilder var = null;
        Token varPrev = null;

        for (int j = 0; j < sig.size(); j++) {
            int k = sig.get(j);
            Token t = toks.get(k);
            Ann a = ann[k];

            if (inVarDefs) {
                if (t.is(")") && a.depth == 1) {
                    if (var != null) vars.add(var.toString());
                    var = null;
                    inVarDefs = false;
                } else {
                    if (t.is("$") && a.depth == 1) {
                        if (var != null) vars.add(var.toString());
                        var = new StringBuilder();
                        varPrev = null;
                    }
                    if (var != null && var.length() < 1000) {
                        if (varPrev != null && space(varPrev, t)) var.append(' ');
                        var.append(t.text());
                        varPrev = t;
                    }
                }
                continue;
            }

            if (a.depth == 0) {
                if (t.is("{")) {
                    if (!inHeader) {
                        opType = "query";
                        opName = null;
                        vars = new ArrayList<>();
                        dirs = new ArrayList<>();
                    }
                    inHeader = false;
                    if (opType != null) {
                        fields = new ArrayList<>();
                        operations.add(new Operation(opType, opName, vars, dirs, fields));
                        inBody = true;
                    } else {
                        inBody = false;
                    }
                    opType = null;
                } else if (t.kind() == Kind.NAME && !inHeader && OPERATION_TYPES.contains(t.text())) {
                    inHeader = true;
                    opType = t.text();
                    opName = null;
                    vars = new ArrayList<>();
                    dirs = new ArrayList<>();
                    Token nx = sigTok(toks, sig, j + 1);
                    if (nx != null && nx.kind() == Kind.NAME) {
                        opName = nx.text();
                        j++;
                    }
                } else if (t.isName("fragment") && !inHeader) {
                    inHeader = true;
                    opType = null;
                    Token name = sigTok(toks, sig, j + 1);
                    Token on = sigTok(toks, sig, j + 2);
                    Token type = sigTok(toks, sig, j + 3);
                    if (name != null && name.kind() == Kind.NAME && on != null && on.isName("on") && type != null && type.kind() == Kind.NAME) {
                        if (fragments.size() < MAX_LIST) fragments.add(new Fragment(name.text(), type.text()));
                        j += 3;
                    } else {
                        warnings.add("Malformed fragment definition at " + GraphQlLexer.lineCol(source, t.pos()));
                    }
                } else if (t.is("(") && inHeader && opType != null) {
                    inVarDefs = true;
                    var = null;
                } else if (t.is("@") && inHeader && opType != null) {
                    Token nx = sigTok(toks, sig, j + 1);
                    if (nx != null && nx.kind() == Kind.NAME) dirs.add("@" + nx.text());
                } else if (t.kind() == Kind.NAME && !inHeader) {
                    inHeader = true;
                    opType = null;
                    Token nx = sigTok(toks, sig, j + 1);
                    if (otherDefinitions.size() < MAX_LIST) {
                        otherDefinitions.add(nx != null && nx.kind() == Kind.NAME ? t.text() + " " + nx.text() : t.text());
                    }
                }
                continue;
            }

            if (inBody && a.depth == 1 && a.ctx == Ctx.SELECTION && a.selStart && fields.size() < MAX_LIST) {
                Token n1 = sigTok(toks, sig, j + 1), n2 = sigTok(toks, sig, j + 2);
                if (t.kind() == Kind.NAME) {
                    if (n1 != null && n1.is(":") && n2 != null && n2.kind() == Kind.NAME) fields.add(t.text() + ": " + n2.text());
                    else fields.add(t.text());
                } else if (n1 != null && n1.isName("on") && n2 != null && n2.kind() == Kind.NAME) {
                    fields.add("... on " + n2.text());
                } else if (n1 != null && n1.kind() == Kind.NAME) {
                    fields.add("..." + n1.text());
                } else {
                    fields.add("... (inline fragment)");
                }
            }
        }
        if (inVarDefs && var != null) vars.add(var.toString());

        if (!sig.isEmpty()) {
            Token first = toks.get(sig.get(0));
            boolean ok = first.is("{") || (first.kind() == Kind.NAME && (OPERATION_TYPES.contains(first.text()) || first.text().equals("fragment")));
            if (!ok) warnings.add("Document does not start with an operation or fragment ('" + first.text() + "')");
        }
    }

    private static Token sigTok(List<Token> toks, List<Integer> sig, int j) {
        return j < sig.size() ? toks.get(sig.get(j)) : null;
    }

    // ------------------------------------------------------------------ formatting

    private static final class Out {
        final StringBuilder sb = new StringBuilder();
        boolean lineStart = true;
        int indent;

        void newline() {
            if (!lineStart) {
                int e = sb.length();
                while (e > 0 && sb.charAt(e - 1) == ' ') e--;
                sb.setLength(e);
                sb.append('\n');
                lineStart = true;
            }
        }

        void blankLine() {
            newline();
            if (sb.length() > 0 && !(sb.length() >= 2 && sb.charAt(sb.length() - 2) == '\n')) sb.append('\n');
        }

        void token(String text, boolean space) {
            if (lineStart) {
                sb.append("  ".repeat(Math.max(0, indent)));
                lineStart = false;
            } else if (space) {
                sb.append(' ');
            }
            sb.append(text);
        }

        void raw(String text) {
            sb.append(text);
            lineStart = false;
        }

        void comment(String text) {
            if (lineStart) token(text, false);
            else sb.append(' ').append(text);
            lineStart = false;
            newline();
        }
    }

    private static String format(List<Token> toks, Ann[] ann) {
        Out out = new Out();
        Token prev = null;
        boolean comma = false;
        for (int k = 0; k < toks.size(); k++) {
            Token t = toks.get(k);
            Ann a = ann[k];
            if (t.kind() == Kind.COMMENT) {
                out.comment(t.text());
                continue;
            }
            if (t.kind() == Kind.COMMA) {
                if (a.ctx == Ctx.PARENS || a.ctx == Ctx.LIST || a.ctx == Ctx.OBJECT) {
                    if (out.lineStart) out.token("", false);
                    out.raw(",");
                    comma = true;
                }
                continue;
            }
            boolean sp = comma ? !isCloser(t) : prev != null && space(prev, t);
            if (t.is("{") && a.opens == Ctx.SELECTION) {
                if (a.depth == 0 && prev != null && prev.is("}")) out.blankLine();
                out.token("{", !out.lineStart);
                out.indent++; // the next selection (or the closing brace) starts the new line, so trailing comments stay put
            } else if (t.is("}") && a.closes == Ctx.SELECTION) {
                out.indent--;
                out.newline();
                out.token("}", false);
            } else {
                if (a.selStart) {
                    out.newline();
                } else if (a.depth == 0 && prev != null && prev.is("}")) {
                    out.blankLine();
                }
                out.token(t.text(), sp);
            }
            comma = false;
            prev = t;
        }
        out.newline();
        return out.sb.toString().stripTrailing();
    }

    private static boolean isCloser(Token t) {
        return t.is(")") || t.is("]") || t.is("}");
    }

    /** Whether a space goes between two adjacent significant tokens on the same line. */
    static boolean space(Token prev, Token t) {
        if (t.is(")") || t.is("]") || t.is(":") || t.is("!") || t.is("(")) return false;
        if (prev.is("(") || prev.is("[") || prev.is("$") || prev.is("@")) return false;
        if (prev.is("...")) return t.isName("on") || t.is("@") || t.is("{");
        if (prev.is("{") && t.is("}")) return false;
        return true;
    }
}
