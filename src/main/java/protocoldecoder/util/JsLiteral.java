package protocoldecoder.util;

/** Helpers for pulling JavaScript object literals out of surrounding script/HTML text. */
public final class JsLiteral {

    private JsLiteral() {
    }

    /**
     * Given the index of an opening '{' or '[', returns the index just past its matching closer, honouring string
     * literals and escapes; -1 if unbalanced.
     */
    public static int matchBracket(String s, int open) {
        if (open < 0 || open >= s.length()) return -1;
        char o = s.charAt(open);
        if (o != '{' && o != '[') return -1;
        int depth = 0;
        char quote = 0;
        for (int i = open; i < s.length(); i++) {
            char c = s.charAt(i);
            if (quote != 0) {
                if (c == '\\') {
                    i++;
                } else if (c == quote) {
                    quote = 0;
                }
                continue;
            }
            switch (c) {
                case '"', '\'', '`' -> quote = c;
                case '{', '[' -> depth++;
                case '}', ']' -> {
                    depth--;
                    if (depth == 0) return i + 1;
                }
                default -> {
                }
            }
        }
        return -1;
    }

    /**
     * Finds {@code <name> = {...}} (or {@code name:{...}}) after {@code from} and returns the literal text, or null.
     */
    public static String findAssignedLiteral(String s, String name, int from) {
        int idx = s.indexOf(name, from);
        while (idx >= 0) {
            int i = idx + name.length();
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
            if (i < s.length() && (s.charAt(i) == '=' || s.charAt(i) == ':')) {
                i++;
                while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
                if (i < s.length() && (s.charAt(i) == '{' || s.charAt(i) == '[')) {
                    int end = matchBracket(s, i);
                    if (end > 0) return s.substring(i, end);
                }
            }
            idx = s.indexOf(name, idx + 1);
        }
        return null;
    }
}
