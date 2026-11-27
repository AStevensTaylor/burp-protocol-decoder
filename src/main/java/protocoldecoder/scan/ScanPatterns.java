package protocoldecoder.scan;

import protocoldecoder.core.DecodedNode;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Reusable detectors for checks: exception/stack-trace disclosure and sensitive values in decoded data. */
public final class ScanPatterns {

    private static final Pattern DOTNET_EXCEPTION = Pattern.compile("\\b(?:System|Microsoft)\\.[A-Za-z0-9_.]*Exception\\b");
    private static final Pattern JAVA_EXCEPTION = Pattern.compile("\\b(?:java|javax|jakarta|org|com)\\.[a-z0-9_.]+\\.[A-Z][A-Za-z0-9_]*(?:Exception|Error)\\b");
    private static final Pattern STACK_FRAME = Pattern.compile("(?m)(?:^|\\\\n|\\n)\\s*at [A-Za-z_][\\w.$<>`]*\\.[\\w$<>`]+\\(");
    private static final Pattern DOTNET_LINE = Pattern.compile(" in [^\\n]{1,300}:line \\d+");

    private static final Pattern EMAIL = Pattern.compile("\\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\\.[A-Za-z]{2,24}\\b");
    private static final Pattern JWT = Pattern.compile("\\beyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]*");
    private static final Pattern BEARER = Pattern.compile("(?i)\\bbearer\\s+[A-Za-z0-9._~+/=-]{16,}");
    private static final Pattern SECRET_KV = Pattern.compile("(?i)\\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?id)\\b\\s*[=:]\\s*[\"']?([^\\s\"'&,;]{4,})");
    private static final Pattern CARD = Pattern.compile("\\b(?:\\d[ -]?){13,19}\\b");

    private ScanPatterns() {
    }

    /** Returns the first piece of text showing an exception type or stack trace, or null. */
    public static String exceptionEvidence(String text) {
        if (text == null || text.isEmpty()) return null;
        String t = text.length() > 2_000_000 ? text.substring(0, 2_000_000) : text;
        for (Pattern p : new Pattern[]{STACK_FRAME, DOTNET_LINE, DOTNET_EXCEPTION, JAVA_EXCEPTION}) {
            Matcher m = p.matcher(t);
            if (m.find()) return m.group().strip();
        }
        return null;
    }

    /** A sensitive-looking value found in decoded data. */
    public record Sensitive(String kind, String path, String value) {
    }

    /** Scans every name/value of a decoded tree for sensitive-looking data (bounded). */
    public static List<Sensitive> sensitiveValues(DecodedNode root, int max) {
        List<Sensitive> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        walk(root, "", out, seen, max);
        return out;
    }

    private static final Pattern SENSITIVE_NAME = Pattern.compile("(?i)(password|passwd|secret|token|api[_-]?key|authorization|ssn|credit.?card|card.?number|cvv)");

    private static void walk(DecodedNode n, String path, List<Sensitive> out, Set<String> seen, int max) {
        if (out.size() >= max) return;
        String p = path.isEmpty() ? n.name() : path + " › " + n.name();
        String v = n.value();
        if (v != null && !v.isEmpty() && n.isLeaf() && n.type() != DecodedNode.Type.NOTE) {
            String val = v.length() > 100_000 ? v.substring(0, 100_000) : v;
            if (SENSITIVE_NAME.matcher(n.name()).find() && !val.equals("null") && val.length() >= 4) add(out, seen, "sensitive field name", p, val);
            find(EMAIL, "email address", p, val, out, seen);
            find(JWT, "JWT", p, val, out, seen);
            find(BEARER, "bearer token", p, val, out, seen);
            Matcher kv = SECRET_KV.matcher(val);
            if (kv.find()) add(out, seen, "credential-like key=value", p, kv.group());
            Matcher card = CARD.matcher(val);
            while (card.find()) {
                String digits = card.group().replaceAll("[ -]", "");
                if (digits.length() >= 13 && digits.length() <= 19 && luhn(digits)) {
                    add(out, seen, "payment card number", p, card.group());
                    break;
                }
            }
        }
        for (DecodedNode c : n.children()) walk(c, p, out, seen, max);
    }

    private static void find(Pattern pat, String kind, String path, String val, List<Sensitive> out, Set<String> seen) {
        Matcher m = pat.matcher(val);
        if (m.find()) add(out, seen, kind, path, m.group());
    }

    private static void add(List<Sensitive> out, Set<String> seen, String kind, String path, String value) {
        String v = value.length() > 200 ? value.substring(0, 200) + "…" : value;
        if (seen.add(kind + "\u0000" + v)) out.add(new Sensitive(kind, path, v));
    }

    static boolean luhn(String digits) {
        int sum = 0;
        boolean dbl = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int d = digits.charAt(i) - '0';
            if (dbl) {
                d *= 2;
                if (d > 9) d -= 9;
            }
            sum += d;
            dbl = !dbl;
        }
        return sum % 10 == 0 && !digits.chars().allMatch(c -> c == digits.charAt(0));
    }

    /** Renders sensitive findings as an HTML list for issue details. */
    public static String htmlList(List<Sensitive> items) {
        StringBuilder sb = new StringBuilder("<ul>");
        for (Sensitive s : items) {
            sb.append("<li><b>").append(Finding.esc(s.kind())).append("</b> in <code>").append(Finding.esc(s.path()))
                    .append("</code>: <code>").append(Finding.esc(s.value())).append("</code></li>");
        }
        return sb.append("</ul>").toString();
    }
}
