package protocoldecoder.builtin.aspnetajax;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Parser for the ASP.NET AJAX partial-rendering "delta" response format ({@code PageRequestManager._parseDelta}).
 *
 * <p>The body is a sequence of {@code length|type|id|content|} records, where {@code length} is the number of
 * characters (UTF-16 code units, as JavaScript counts them) of {@code content}. {@code type} and {@code id} cannot
 * contain {@code |}; {@code content} can, which is why the length prefix exists.</p>
 */
final class DeltaParser {

    /** One delta record. {@code offset} is the character offset of the record start in the body. */
    record Record(int offset, int length, String type, String id, String content) {
    }

    /**
     * Parse outcome. {@code error} is null when the whole input was consumed; otherwise it describes why parsing
     * stopped at {@code errorOffset}. {@code capped} is true when {@code maxRecords} stopped parsing early.
     */
    record Result(List<Record> records, String error, int errorOffset, boolean capped) {
        boolean clean() {
            return error == null && !capped;
        }
    }

    /** Known record types and what they mean. */
    static final Map<String, String> TYPES = Map.ofEntries(
            Map.entry("updatePanel", "Re-rendered UpdatePanel HTML (id = panel client ID)"),
            Map.entry("hiddenField", "Hidden form field value (id = field name)"),
            Map.entry("asyncPostBackControlIDs", "Controls that trigger async postbacks"),
            Map.entry("postBackControlIDs", "Controls that trigger full postbacks"),
            Map.entry("updatePanelIDs", "UpdatePanels on the page"),
            Map.entry("childUpdatePanelIDs", "Child UpdatePanels being updated"),
            Map.entry("panelsToRefreshIDs", "UpdatePanels refreshed by this postback"),
            Map.entry("asyncPostBackTimeout", "Async postback timeout (seconds)"),
            Map.entry("formAction", "Form action URL"),
            Map.entry("pageTitle", "New page title"),
            Map.entry("focus", "Control to focus"),
            Map.entry("scriptBlock", "Registered script (id: ScriptContentNoTags / ScriptContentWithTags / ScriptPath)"),
            Map.entry("fallbackScript", "Fallback script path"),
            Map.entry("scriptStartupBlock", "Startup script (id: ScriptContentNoTags / ScriptContentWithTags / ScriptPath)"),
            Map.entry("scriptDispose", "Dispose script (id = panel ID)"),
            Map.entry("onSubmit", "OnSubmit statement"),
            Map.entry("arrayDeclaration", "RegisterArrayDeclaration (id = array name)"),
            Map.entry("expando", "Expando attribute (id = target expression)"),
            Map.entry("dataItem", "Data item (id = control ID)"),
            Map.entry("dataItemJson", "JSON data item (id = control ID)"),
            Map.entry("pageRedirect", "Redirect the browser to the URL in content"),
            Map.entry("error", "Server error (id = HTTP status code)"));

    /** Longest type or id we accept while sniffing (the real parser has no limit). */
    private static final int SNIFF_FIELD_MAX = 1024;

    private DeltaParser() {
    }

    static Result parse(String s, int maxRecords) {
        List<Record> out = new ArrayList<>();
        int i = 0;
        int n = s.length();
        while (i < n) {
            if (out.size() >= maxRecords) return new Result(out, null, i, true);
            int start = i;
            int bar = s.indexOf('|', i);
            if (bar < 0) return new Result(out, "missing '|' after record length", start, false);
            String lenText = s.substring(i, bar);
            if (lenText.isEmpty() || lenText.length() > 9 || !lenText.chars().allMatch(c -> c >= '0' && c <= '9')) {
                return new Result(out, "record length is not a number: '" + abbreviate(lenText) + "'", start, false);
            }
            int len = Integer.parseInt(lenText);
            i = bar + 1;
            bar = s.indexOf('|', i);
            if (bar < 0) return new Result(out, "missing '|' after record type", start, false);
            String type = s.substring(i, bar);
            i = bar + 1;
            bar = s.indexOf('|', i);
            if (bar < 0) return new Result(out, "missing '|' after record id", start, false);
            String id = s.substring(i, bar);
            i = bar + 1;
            if ((long) i + len >= n) {
                return new Result(out, "record '" + abbreviate(type) + "' declares " + len + " characters but only "
                        + Math.max(0, n - i) + " remain", start, false);
            }
            String content = s.substring(i, i + len);
            i += len;
            if (s.charAt(i) != '|') {
                return new Result(out, "record '" + abbreviate(type) + "' content is not followed by '|' (length mismatch)", start, false);
            }
            i++;
            out.add(new Record(start, len, type, id, content));
        }
        return new Result(out, null, n, false);
    }

    /**
     * Cheap check used by the matcher: the body starts with well-framed records whose first type is a known delta
     * type. Validates up to {@code records} records (all of them if there are fewer).
     */
    static boolean looksLikeDelta(String s, int records) {
        if (s.isEmpty() || s.charAt(0) < '0' || s.charAt(0) > '9') return false;
        int i = 0;
        int n = s.length();
        for (int r = 0; r < records && i < n; r++) {
            int bar = indexOfBar(s, i, 10);
            if (bar <= i) return false;
            for (int k = i; k < bar; k++) if (s.charAt(k) < '0' || s.charAt(k) > '9') return false;
            int len = Integer.parseInt(s.substring(i, bar));
            int typeStart = bar + 1;
            int typeEnd = indexOfBar(s, typeStart, SNIFF_FIELD_MAX);
            if (typeEnd < 0) return false;
            String type = s.substring(typeStart, typeEnd);
            if (r == 0 && !TYPES.containsKey(type)) return false;
            if (!type.chars().allMatch(Character::isLetter)) return false;
            int idEnd = indexOfBar(s, typeEnd + 1, SNIFF_FIELD_MAX);
            if (idEnd < 0) return false;
            i = idEnd + 1;
            if ((long) i + len >= n || s.charAt(i + len) != '|') return false;
            i += len + 1;
        }
        return true;
    }

    private static int indexOfBar(String s, int from, int max) {
        int end = (int) Math.min(s.length(), (long) from + max + 1);
        for (int k = from; k < end; k++) if (s.charAt(k) == '|') return k;
        return -1;
    }

    private static String abbreviate(String s) {
        return s.length() > 40 ? s.substring(0, 40) + "…" : s;
    }
}
