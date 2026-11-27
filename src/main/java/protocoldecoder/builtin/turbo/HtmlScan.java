package protocoldecoder.builtin.turbo;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * A small, tolerant HTML tag scanner: finds start/end tags, parses their attributes (double, single or unquoted
 * values, HTML entities) and locates matching close tags with nesting. Comments, and the content of
 * {@code <script>}/{@code <style>} elements, are skipped. Not an HTML parser; it never throws on malformed input.
 */
public final class HtmlScan {

    private HtmlScan() {
    }

    /**
     * A tag. {@code start} is the index of '<', {@code end} the index just past '>' (or the end of input for an
     * unterminated tag). Names are lower-cased.
     */
    public record Tag(String name, Map<String, String> attrs, int start, int end, boolean closing, boolean selfClosing) {
        public String attr(String n) {
            return attrs.get(n);
        }
    }

    /** Returns the next start or end tag at or after {@code from}, or null. */
    public static Tag next(String s, int from) {
        int n = s.length();
        int i = Math.max(0, from);
        while (i < n) {
            int lt = s.indexOf('<', i);
            if (lt < 0 || lt + 1 >= n) return null;
            if (s.startsWith("<!--", lt)) {
                int e = s.indexOf("-->", lt + 4);
                if (e < 0) return null;
                i = e + 3;
                continue;
            }
            char c = s.charAt(lt + 1);
            boolean closing = c == '/';
            int nameStart = closing ? lt + 2 : lt + 1;
            if (nameStart >= n || !isAsciiLetter(s.charAt(nameStart))) {
                i = lt + 1;
                continue;
            }
            int j = nameStart;
            while (j < n && isNameChar(s.charAt(j))) j++;
            String name = s.substring(nameStart, j).toLowerCase(Locale.ROOT);
            Map<String, String> attrs = new LinkedHashMap<>();
            boolean selfClosing = false;
            // attributes
            while (j < n) {
                char d = s.charAt(j);
                if (d == '>') {
                    j++;
                    break;
                }
                if (d == '/' && j + 1 < n && s.charAt(j + 1) == '>') {
                    selfClosing = true;
                    j += 2;
                    break;
                }
                if (Character.isWhitespace(d) || d == '/') {
                    j++;
                    continue;
                }
                int an = j;
                while (j < n && !Character.isWhitespace(s.charAt(j)) && s.charAt(j) != '=' && s.charAt(j) != '>'
                        && !(s.charAt(j) == '/' && j + 1 < n && s.charAt(j + 1) == '>')) j++;
                String attrName = s.substring(an, j).toLowerCase(Locale.ROOT);
                int k = j;
                while (k < n && Character.isWhitespace(s.charAt(k))) k++;
                String value = "";
                if (k < n && s.charAt(k) == '=') {
                    k++;
                    while (k < n && Character.isWhitespace(s.charAt(k))) k++;
                    if (k < n && (s.charAt(k) == '"' || s.charAt(k) == '\'')) {
                        char q = s.charAt(k);
                        int close = s.indexOf(q, k + 1);
                        if (close < 0) close = n;
                        value = s.substring(k + 1, close);
                        j = Math.min(n, close + 1);
                    } else {
                        int vs = k;
                        while (k < n && !Character.isWhitespace(s.charAt(k)) && s.charAt(k) != '>') k++;
                        value = s.substring(vs, k);
                        j = k;
                    }
                }
                if (!attrName.isEmpty() && !attrs.containsKey(attrName)) attrs.put(attrName, decodeEntities(value));
                if (j == an) j++; // safety: always make progress
            }
            return new Tag(name, Collections.unmodifiableMap(attrs), lt, Math.min(j, n), closing, selfClosing);
        }
        return null;
    }

    /** Index just past a raw-text element's content (the position of its close tag), for script/style. */
    private static int skipRaw(String s, Tag t) {
        if (t.closing || t.selfClosing || !(t.name.equals("script") || t.name.equals("style"))) return t.end;
        int e = indexOfIgnoreCase(s, "</" + t.name, t.end);
        return e < 0 ? s.length() : e;
    }

    /** Finds the next start tag named {@code name} (case-insensitive) at or after {@code from}, or null. */
    public static Tag find(String s, String name, int from) {
        String want = name.toLowerCase(Locale.ROOT);
        int i = from;
        while (true) {
            Tag t = next(s, i);
            if (t == null) return null;
            if (!t.closing && t.name.equals(want)) return t;
            i = Math.max(skipRaw(s, t), t.start + 1);
        }
    }

    /**
     * Given the end of a start tag named {@code name}, returns the index of the '<' of its matching end tag, honouring
     * nested elements of the same name; -1 if unterminated.
     */
    public static int findClose(String s, String name, int contentStart) {
        String want = name.toLowerCase(Locale.ROOT);
        int depth = 1;
        int i = contentStart;
        while (true) {
            Tag t = next(s, i);
            if (t == null) return -1;
            if (t.name.equals(want)) {
                if (t.closing) {
                    if (--depth == 0) return t.start;
                } else if (!t.selfClosing) {
                    depth++;
                }
            }
            i = Math.max(skipRaw(s, t), t.start + 1);
        }
    }

    /** Index just past the '>' of the end tag starting at {@code closeStart}. */
    public static int afterClose(String s, int closeStart) {
        int gt = s.indexOf('>', closeStart);
        return gt < 0 ? s.length() : gt + 1;
    }

    static int indexOfIgnoreCase(String s, String needle, int from) {
        int n = needle.length();
        for (int i = Math.max(0, from); i + n <= s.length(); i++) {
            if (s.regionMatches(true, i, needle, 0, n)) return i;
        }
        return -1;
    }

    private static boolean isAsciiLetter(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    }

    private static boolean isNameChar(char c) {
        return isAsciiLetter(c) || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == ':' || c == '.';
    }

    /** Decodes the common named entities and numeric character references. */
    public static String decodeEntities(String v) {
        if (v.indexOf('&') < 0) return v;
        StringBuilder sb = new StringBuilder(v.length());
        int i = 0;
        while (i < v.length()) {
            char c = v.charAt(i);
            if (c == '&') {
                int semi = v.indexOf(';', i + 1);
                if (semi > i + 1 && semi - i <= 10) {
                    String ent = v.substring(i + 1, semi);
                    String rep = entity(ent);
                    if (rep != null) {
                        sb.append(rep);
                        i = semi + 1;
                        continue;
                    }
                }
            }
            sb.append(c);
            i++;
        }
        return sb.toString();
    }

    private static String entity(String e) {
        switch (e) {
            case "amp": return "&";
            case "quot": return "\"";
            case "apos": return "'";
            case "lt": return "<";
            case "gt": return ">";
            case "nbsp": return " ";
            default:
        }
        try {
            int cp;
            if (e.startsWith("#x") || e.startsWith("#X")) cp = Integer.parseInt(e.substring(2), 16);
            else if (e.startsWith("#")) cp = Integer.parseInt(e.substring(1));
            else return null;
            return Character.isValidCodePoint(cp) ? new String(Character.toChars(cp)) : null;
        } catch (NumberFormatException ex) {
            return null;
        }
    }
}
