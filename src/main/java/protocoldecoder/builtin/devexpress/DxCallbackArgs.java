package protocoldecoder.builtin.devexpress;

import com.google.gson.JsonElement;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.JsonTree;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser for the length-prefixed serialisation DevExpress ASP.NET controls use in callback arguments.
 *
 * <p>Two shapes occur, and they nest:</p>
 * <ul>
 *   <li>named segments, produced by {@code ASPx.FormatCallbackArg(prefix, arg)}: {@code PREFIX|LEN;VALUE;} repeated,
 *       e.g. {@code KV|2;[];GB|20;12|PAGERONCLICK3|PN1;}</li>
 *   <li>positional segments used for command arguments: {@code LEN|VALUE} repeated, optionally ending with
 *       {@code ;}, e.g. {@code 12|PAGERONCLICK3|PN1;}</li>
 * </ul>
 * <p>The whole parameter is usually prefixed with a callback marker such as {@code c0:}.</p>
 */
public final class DxCallbackArgs {

    private static final Pattern CALLBACK_PREFIX = Pattern.compile("^c(\\d+):");
    private static final int MAX_DEPTH = 8;

    /** Well-known segment prefixes (best effort; DevExpress does not document these). */
    static final Map<String, String> PREFIX_NAMES = Map.ofEntries(
            Map.entry("KV", "Row keys (visible rows)"),
            Map.entry("GB", "Grid command"),
            Map.entry("CT", "Client state / custom tag"),
            Map.entry("CR", "Client-side column resizing state"),
            Map.entry("GLP", "Grid lookup popup"),
            Map.entry("CB", "Custom callback"),
            Map.entry("FB", "Filter builder"),
            Map.entry("CL", "Column layout"),
            Map.entry("EV", "Editor values"),
            Map.entry("CPC", "Callback panel"),
            Map.entry("TV", "Tree view"),
            Map.entry("FR", "Focused row"),
            Map.entry("SR", "Selected rows"),
            Map.entry("PS", "Page size"));

    /** Known grid command names, mapped to a description. */
    static final Map<String, String> COMMANDS = Map.ofEntries(
            Map.entry("PAGERONCLICK", "Pager click"),
            Map.entry("CUSTOMCALLBACK", "Custom callback (PerformCallback)"),
            Map.entry("SORT", "Sort column"),
            Map.entry("GROUP", "Group by column"),
            Map.entry("UNGROUP", "Ungroup column"),
            Map.entry("APPLYFILTER", "Apply filter expression"),
            Map.entry("APPLYCOLUMNFILTER", "Apply column filter"),
            Map.entry("APPLYMULTICOLUMNFILTER", "Apply multi-column filter"),
            Map.entry("APPLYHEADERCOLUMNFILTER", "Apply header filter"),
            Map.entry("FILTERROWMENU", "Filter row menu"),
            Map.entry("STARTEDIT", "Start editing row"),
            Map.entry("UPDATEEDIT", "Save edited row"),
            Map.entry("CANCELEDIT", "Cancel editing"),
            Map.entry("ADDNEWROW", "Add new row"),
            Map.entry("DELETEROW", "Delete row"),
            Map.entry("SELECTROWS", "Select rows"),
            Map.entry("SELECTROWSKEY", "Select rows by key"),
            Map.entry("FOCUSEDROW", "Focus row"),
            Map.entry("EXPANDROW", "Expand group row"),
            Map.entry("COLLAPSEROW", "Collapse group row"),
            Map.entry("SHOWDETAILROW", "Show detail row"),
            Map.entry("HIDEDETAILROW", "Hide detail row"),
            Map.entry("SHOWFILTERCONTROL", "Show filter control"),
            Map.entry("CUSTOMBUTTONCALLBACK", "Custom button callback"),
            Map.entry("CUSTOMVALUES", "Get custom values"),
            Map.entry("FILTERPOPUP", "Header filter popup"),
            Map.entry("COLUMNMOVE", "Move column"),
            Map.entry("REFRESH", "Refresh"),
            Map.entry("BATCHUPDATEEDIT", "Batch edit save"));

    private DxCallbackArgs() {
    }

    /** Result of parsing a callback parameter. */
    public record Parsed(String callbackIndex, String body, DecodedNode tree, String command, boolean structured) {
    }

    public static Parsed parse(String param) {
        String body = param == null ? "" : param;
        String index = null;
        Matcher m = CALLBACK_PREFIX.matcher(body);
        if (m.find()) {
            index = m.group(1);
            body = body.substring(m.end());
        }
        DecodedNode root = DecodedNode.object("Callback argument");
        if (index != null) root.put("Callback index", index);
        String[] command = new String[1];
        List<String[]> named = parseNamed(body);
        boolean structured = false;
        if (named != null && !named.isEmpty()) {
            structured = true;
            DecodedNode segs = root.child("Segments");
            for (String[] seg : named) {
                segs.add(valueNode(seg[0], seg[1], 0, command, PREFIX_NAMES.get(seg[0])));
            }
        } else {
            List<String> positional = parsePositional(body);
            if (positional != null && positional.size() > 1) {
                structured = true;
                root.add(positionalNode("Arguments", positional, 0, command));
            } else {
                root.add(valueNode("Value", body, 0, command, null));
            }
        }
        return new Parsed(index, body, root, command[0], structured);
    }

    private static DecodedNode valueNode(String name, String value, int depth, String[] command, String description) {
        String label = description == null ? name : name + " — " + description;
        if (depth < MAX_DEPTH) {
            if (JsonTree.looksLikeJson(value)) {
                JsonElement e = JsonTree.parseLenient(value);
                if (e != null) return JsonTree.toNode(label, e, true);
            }
            List<String[]> named = parseNamed(value);
            if (named != null && !named.isEmpty()) {
                DecodedNode n = DecodedNode.object(label);
                for (String[] seg : named) n.add(valueNode(seg[0], seg[1], depth + 1, command, PREFIX_NAMES.get(seg[0])));
                return n;
            }
            List<String> positional = parsePositional(value);
            if (positional != null && !positional.isEmpty() && !(positional.size() == 1 && positional.get(0).equals(value))) {
                return positionalNode(label, positional, depth + 1, command);
            }
        }
        if (command[0] == null && COMMANDS.containsKey(value)) command[0] = value;
        String desc = COMMANDS.get(value);
        return DecodedNode.leaf(desc == null ? label : label + " (" + desc + ")", value);
    }

    private static DecodedNode positionalNode(String label, List<String> values, int depth, String[] command) {
        DecodedNode n = DecodedNode.array(label);
        for (int i = 0; i < values.size(); i++) {
            String v = values.get(i);
            if (i == 0 && command[0] == null && v.matches("[A-Z][A-Z0-9_]+")) command[0] = v;
            n.add(valueNode("[" + i + "]", v, depth, command, null));
        }
        return n;
    }

    /** Parses {@code NAME|LEN;VALUE;...}; returns null unless the entire string is consumed. */
    static List<String[]> parseNamed(String s) {
        List<String[]> out = new ArrayList<>();
        int i = 0, n = s.length();
        while (i < n) {
            int bar = s.indexOf('|', i);
            if (bar <= i) return null;
            String name = s.substring(i, bar);
            if (!name.matches("[A-Za-z][A-Za-z0-9_]*")) return null;
            int semi = s.indexOf(';', bar + 1);
            if (semi < 0) return null;
            int len = parseLen(s.substring(bar + 1, semi));
            if (len < 0 || semi + 1 + len > n) return null;
            String value = s.substring(semi + 1, semi + 1 + len);
            i = semi + 1 + len;
            if (i < n && s.charAt(i) == ';') i++;
            out.add(new String[]{name, value});
        }
        return out;
    }

    /** Parses {@code LEN|VALUE...} with optional trailing {@code ;}; returns null unless fully consumed. */
    static List<String> parsePositional(String s) {
        List<String> out = new ArrayList<>();
        int i = 0, n = s.length();
        while (i < n) {
            if (s.charAt(i) == ';' && i == n - 1) break;
            int bar = s.indexOf('|', i);
            if (bar <= i) return null;
            int len = parseLen(s.substring(i, bar));
            if (len < 0 || bar + 1 + len > n) return null;
            out.add(s.substring(bar + 1, bar + 1 + len));
            i = bar + 1 + len;
        }
        return out.isEmpty() ? null : out;
    }

    private static int parseLen(String s) {
        if (s.isEmpty() || s.length() > 9) return -1;
        for (int k = 0; k < s.length(); k++) if (!Character.isDigit(s.charAt(k))) return -1;
        return Integer.parseInt(s);
    }
}
