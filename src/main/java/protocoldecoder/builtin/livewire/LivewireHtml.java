package protocoldecoder.builtin.livewire;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Pulls Livewire component state and configuration out of rendered HTML pages. */
final class LivewireHtml {

    private LivewireHtml() {
    }

    static final int MAX_COMPONENTS = 200;

    /** One component root element found in the page. */
    record Element(int version, String id, String state, String effects) {
    }

    private static final Pattern STATE_ATTR = Pattern.compile("\\bwire:(snapshot|initial-data)\\s*=\\s*(\"([^\"]*)\"|'([^']*)')");
    private static final Pattern ID_ATTR = Pattern.compile("\\bwire:id\\s*=\\s*[\"']([^\"']*)[\"']");
    private static final Pattern EFFECTS_ATTR = Pattern.compile("\\bwire:effects\\s*=\\s*(\"([^\"]*)\"|'([^']*)')");
    private static final Pattern CSRF_META = Pattern.compile("<meta\\s[^>]*name\\s*=\\s*[\"']csrf-token[\"'][^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern CONTENT_ATTR = Pattern.compile("\\bcontent\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern SCRIPT_TAG = Pattern.compile("<script\\b[^>]*(?:livewire|data-update-uri|data-csrf)[^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern DATA_ATTR = Pattern.compile("\\b(src|data-csrf|data-update-uri|data-uri|data-navigate-once)\\s*=\\s*[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE);
    private static final Pattern V2_GLOBALS = Pattern.compile("window\\.(livewire_token|livewire_app_url)\\s*=\\s*(['\"])([^'\"]*)\\2");

    static List<Element> elements(String html) {
        List<Element> out = new ArrayList<>();
        Matcher m = STATE_ATTR.matcher(html);
        while (m.find() && out.size() < MAX_COMPONENTS) {
            String raw = m.group(3) != null ? m.group(3) : m.group(4);
            int start = html.lastIndexOf('<', m.start());
            int end = html.indexOf('>', m.end());
            String tag = html.substring(Math.max(0, start), end < 0 ? html.length() : end);
            Matcher id = ID_ATTR.matcher(tag);
            Matcher fx = EFFECTS_ATTR.matcher(tag);
            String effects = null;
            if (fx.find()) effects = unescape(fx.group(2) != null ? fx.group(2) : fx.group(3));
            out.add(new Element(m.group(1).equals("snapshot") ? 3 : 2, id.find() ? id.group(1) : null, unescape(raw), effects));
        }
        return out;
    }

    /** CSRF token from {@code <meta name="csrf-token">}, or null. */
    static String csrfMeta(String html) {
        Matcher m = CSRF_META.matcher(html);
        if (!m.find()) return null;
        Matcher c = CONTENT_ATTR.matcher(m.group());
        return c.find() ? unescape(c.group(1)) : null;
    }

    /** Attributes of the Livewire script tag(s): src, data-csrf, data-update-uri, ... in document order. */
    static List<String[]> scriptAttributes(String html) {
        List<String[]> out = new ArrayList<>();
        Matcher m = SCRIPT_TAG.matcher(html);
        while (m.find() && out.size() < 20) {
            String tag = m.group();
            if (!tag.toLowerCase().contains("livewire") && !tag.contains("data-update-uri") && !tag.contains("data-csrf")) continue;
            Matcher a = DATA_ATTR.matcher(tag);
            while (a.find()) {
                String name = a.group(1).toLowerCase();
                if (name.equals("src") && !a.group(2).toLowerCase().contains("livewire")) continue;
                out.add(new String[]{name, unescape(a.group(2))});
            }
        }
        Matcher g = V2_GLOBALS.matcher(html);
        while (g.find() && out.size() < 40) out.add(new String[]{"window." + g.group(1), g.group(3)});
        return out;
    }

    /** Decodes the HTML entities Blade's {@code e()} / htmlspecialchars produce, plus numeric references. */
    static String unescape(String s) {
        if (s == null || s.indexOf('&') < 0) return s;
        StringBuilder sb = new StringBuilder(s.length());
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == '&') {
                int semi = s.indexOf(';', i);
                if (semi > i && semi - i <= 10) {
                    String ent = s.substring(i + 1, semi);
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
            case "quot": return "\"";
            case "amp": return "&";
            case "lt": return "<";
            case "gt": return ">";
            case "apos": return "'";
            case "nbsp": return "\u00a0";
            default:
        }
        if (e.length() > 1 && e.charAt(0) == '#') {
            try {
                int cp = e.charAt(1) == 'x' || e.charAt(1) == 'X' ? Integer.parseInt(e.substring(2), 16) : Integer.parseInt(e.substring(1));
                if (Character.isValidCodePoint(cp)) return new String(Character.toChars(cp));
            } catch (NumberFormatException ignored) {
                // not a numeric reference
            }
        }
        return null;
    }
}
