package protocoldecoder.builtin.graphql;

import java.util.ArrayList;
import java.util.List;

/**
 * Tolerant GraphQL tokenizer (GraphQL spec, section 2.1). Never throws: characters it cannot lex become
 * {@link Kind#ERROR} tokens and are reported in {@link Result#errors}. Comments and commas are kept as tokens so the
 * formatter can preserve comments.
 */
final class GraphQlLexer {

    enum Kind { PUNCT, SPREAD, NAME, NUMBER, STRING, BLOCK_STRING, COMMENT, COMMA, ERROR }

    record Token(Kind kind, String text, int pos) {
        boolean is(String s) {
            return (kind == Kind.PUNCT || kind == Kind.SPREAD) && text.equals(s);
        }

        boolean isName(String s) {
            return kind == Kind.NAME && text.equals(s);
        }

        boolean significant() {
            return kind != Kind.COMMENT && kind != Kind.COMMA;
        }
    }

    static final class Result {
        final List<Token> tokens = new ArrayList<>();
        final List<String> errors = new ArrayList<>();
        /** True if lexing stopped early because the token limit was reached. */
        boolean truncated;
    }

    private static final String PUNCTUATORS = "!$&()[]{}:=@|";

    private GraphQlLexer() {
    }

    static Result tokenize(String src, int maxTokens) {
        Result r = new Result();
        int n = src.length();
        int i = 0;
        while (i < n) {
            if (r.tokens.size() >= maxTokens) {
                r.truncated = true;
                break;
            }
            char c = src.charAt(i);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '﻿') {
                i++;
            } else if (c == ',') {
                r.tokens.add(new Token(Kind.COMMA, ",", i));
                i++;
            } else if (c == '#') {
                int e = i;
                while (e < n && src.charAt(e) != '\n' && src.charAt(e) != '\r') e++;
                r.tokens.add(new Token(Kind.COMMENT, src.substring(i, e).stripTrailing(), i));
                i = e;
            } else if (c == '.') {
                if (src.startsWith("...", i)) {
                    r.tokens.add(new Token(Kind.SPREAD, "...", i));
                    i += 3;
                } else {
                    error(r, src, i, i + 1, "Unexpected '.'");
                    i++;
                }
            } else if (PUNCTUATORS.indexOf(c) >= 0) {
                r.tokens.add(new Token(Kind.PUNCT, String.valueOf(c), i));
                i++;
            } else if (isNameStart(c)) {
                int e = i + 1;
                while (e < n && isNameContinue(src.charAt(e))) e++;
                r.tokens.add(new Token(Kind.NAME, src.substring(i, e), i));
                i = e;
            } else if (c == '-' || isDigit(c)) {
                i = number(r, src, i);
            } else if (c == '"') {
                i = src.startsWith("\"\"\"", i) ? blockString(r, src, i) : string(r, src, i);
            } else {
                int cp = src.codePointAt(i);
                int e = i + Character.charCount(cp);
                error(r, src, i, e, "Unexpected character '" + new String(Character.toChars(cp)) + "'");
                i = e;
            }
        }
        return r;
    }

    private static int number(Result r, String src, int start) {
        int n = src.length();
        int i = start;
        if (src.charAt(i) == '-') i++;
        int digits = i;
        while (i < n && isDigit(src.charAt(i))) i++;
        boolean ok = i > digits;
        if (ok && i < n && src.charAt(i) == '.') {
            int f = ++i;
            while (i < n && isDigit(src.charAt(i))) i++;
            ok = i > f;
        }
        if (ok && i < n && (src.charAt(i) == 'e' || src.charAt(i) == 'E')) {
            i++;
            if (i < n && (src.charAt(i) == '+' || src.charAt(i) == '-')) i++;
            int f = i;
            while (i < n && isDigit(src.charAt(i))) i++;
            ok = i > f;
        }
        if (ok && i < n && (isNameStart(src.charAt(i)) || src.charAt(i) == '.')) ok = false;
        if (!ok) {
            int e = Math.max(i, start + 1);
            while (e < n && (isNameContinue(src.charAt(e)) || src.charAt(e) == '.')) e++;
            error(r, src, start, e, "Invalid number");
            return e;
        }
        r.tokens.add(new Token(Kind.NUMBER, src.substring(start, i), start));
        return i;
    }

    private static int string(Result r, String src, int start) {
        int n = src.length();
        int i = start + 1;
        while (i < n) {
            char c = src.charAt(i);
            if (c == '\\') {
                i += 2;
            } else if (c == '"') {
                r.tokens.add(new Token(Kind.STRING, src.substring(start, i + 1), start));
                return i + 1;
            } else if (c == '\n' || c == '\r') {
                break;
            } else {
                i++;
            }
        }
        int e = Math.min(i, n);
        error(r, src, start, e, "Unterminated string");
        return e;
    }

    private static int blockString(Result r, String src, int start) {
        int n = src.length();
        int i = start + 3;
        while (i < n) {
            if (src.startsWith("\\\"\"\"", i)) {
                i += 4;
            } else if (src.startsWith("\"\"\"", i)) {
                r.tokens.add(new Token(Kind.BLOCK_STRING, src.substring(start, i + 3), start));
                return i + 3;
            } else {
                i++;
            }
        }
        error(r, src, start, n, "Unterminated block string");
        return n;
    }

    private static void error(Result r, String src, int start, int end, String what) {
        r.tokens.add(new Token(Kind.ERROR, src.substring(start, Math.min(end, src.length())), start));
        if (r.errors.size() < 20) r.errors.add(what + " at " + lineCol(src, start));
    }

    static String lineCol(String src, int pos) {
        int line = 1, col = 1;
        for (int i = 0; i < pos && i < src.length(); i++) {
            if (src.charAt(i) == '\n') {
                line++;
                col = 1;
            } else {
                col++;
            }
        }
        return "line " + line + ", column " + col;
    }

    static boolean isNameStart(char c) {
        return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    }

    static boolean isNameContinue(char c) {
        return isNameStart(c) || isDigit(c);
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }
}
