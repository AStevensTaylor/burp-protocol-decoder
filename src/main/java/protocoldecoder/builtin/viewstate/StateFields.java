package protocoldecoder.builtin.viewstate;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds the ASP.NET page-state fields ({@code __VIEWSTATE*}, {@code __EVENTVALIDATION}, ...) in form parameters,
 * multipart bodies, HTML hidden inputs and ASP.NET AJAX delta ({@code |hiddenField|…|}) responses.
 */
final class StateFields {

    static final Pattern NAME = Pattern.compile(
            "__(?:VIEWSTATE\\d*|VIEWSTATEFIELDCOUNT|VIEWSTATEGENERATOR|VIEWSTATEENCRYPTED|EVENTVALIDATION|PREVIOUSPAGE|CONTROLSTATE)");

    private static final Pattern HTML_NAME = Pattern.compile(
            "\\bname\\s*=\\s*[\"']?(" + NAME.pattern() + ")(?=[\"'\\s/>])", Pattern.CASE_INSENSITIVE);
    private static final Pattern HTML_VALUE = Pattern.compile("\\bvalue\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))", Pattern.CASE_INSENSITIVE);
    private static final Pattern DELTA = Pattern.compile("(?:^|\\|)(\\d{1,9})\\|hiddenField\\|(" + NAME.pattern() + ")\\|");
    private static final Pattern MULTIPART_NAME = Pattern.compile("(?i)content-disposition:[^\\r\\n]*\\bname=\"(" + NAME.pattern() + ")\"");

    private StateFields() {
    }

    static boolean isStateField(String name) {
        return NAME.matcher(name).matches();
    }

    /** Fields from already parsed parameters (first value wins). */
    static void fromParams(Map<String, List<String>> params, Map<String, String> out) {
        for (Map.Entry<String, List<String>> e : params.entrySet()) {
            if (isStateField(e.getKey()) && !e.getValue().isEmpty()) out.putIfAbsent(e.getKey(), e.getValue().get(0));
        }
    }

    static void fromMultipart(String body, Map<String, String> out) {
        Matcher m = MULTIPART_NAME.matcher(body);
        while (m.find()) {
            int headersEnd = body.indexOf("\r\n\r\n", m.end());
            int sep = 4;
            if (headersEnd < 0) {
                headersEnd = body.indexOf("\n\n", m.end());
                sep = 2;
            }
            if (headersEnd < 0) continue;
            int start = headersEnd + sep;
            int end = body.indexOf("\n--", start);
            if (end < 0) end = body.length();
            else if (end > start && body.charAt(end - 1) == '\r') end--;
            out.putIfAbsent(m.group(1), body.substring(start, Math.max(start, end)));
        }
    }

    /** {@code <input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="…" />}, attributes in any order. */
    static void fromHtml(String html, Map<String, String> out) {
        Matcher m = HTML_NAME.matcher(html);
        while (m.find()) {
            int tagStart = html.lastIndexOf('<', m.start());
            int tagEnd = html.indexOf('>', m.end());
            if (tagStart < 0 || tagEnd < 0) continue;
            String tag = html.substring(tagStart, tagEnd + 1);
            if (!tag.regionMatches(true, 0, "<input", 0, 6)) continue;
            Matcher v = HTML_VALUE.matcher(tag);
            String value = v.find() ? (v.group(1) != null ? v.group(1) : v.group(2) != null ? v.group(2) : v.group(3)) : "";
            out.putIfAbsent(m.group(1).toUpperCase(java.util.Locale.ROOT), unescapeHtml(value));
        }
    }

    /** ASP.NET AJAX UpdatePanel delta: {@code length|hiddenField|__VIEWSTATE|value|}. */
    static void fromDelta(String body, Map<String, String> out) {
        Matcher m = DELTA.matcher(body);
        while (m.find()) {
            int len;
            try {
                len = Integer.parseInt(m.group(1));
            } catch (NumberFormatException e) {
                continue;
            }
            int start = m.end();
            String value;
            if (len >= 0 && start + len <= body.length()) {
                value = body.substring(start, start + len);
            } else {
                int bar = body.indexOf('|', start);
                value = body.substring(start, bar < 0 ? body.length() : bar);
            }
            out.putIfAbsent(m.group(2), value);
        }
    }

    static String unescapeHtml(String s) {
        if (s.indexOf('&') < 0) return s;
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int semi = c == '&' ? s.indexOf(';', i) : -1;
            if (semi > i && semi - i <= 10) {
                String ent = s.substring(i + 1, semi);
                String rep = switch (ent) {
                    case "amp" -> "&";
                    case "quot" -> "\"";
                    case "apos" -> "'";
                    case "lt" -> "<";
                    case "gt" -> ">";
                    default -> numericEntity(ent);
                };
                if (rep != null) {
                    sb.append(rep);
                    i = semi;
                    continue;
                }
            }
            sb.append(c);
        }
        return sb.toString();
    }

    private static String numericEntity(String ent) {
        try {
            if (ent.startsWith("#x") || ent.startsWith("#X")) return new String(Character.toChars(Integer.parseInt(ent.substring(2), 16)));
            if (ent.startsWith("#")) return new String(Character.toChars(Integer.parseInt(ent.substring(1))));
        } catch (IllegalArgumentException e) {
            return null;
        }
        return null;
    }

    /** Ordered copy helper. */
    static Map<String, String> newMap() {
        return new LinkedHashMap<>();
    }
}
