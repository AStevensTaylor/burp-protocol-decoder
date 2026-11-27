package protocoldecoder.builtin.turbo;

import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Parser for Turbo Stream messages: one or more {@code <turbo-stream action="…" target="…"><template>…</template></turbo-stream>}
 * elements, as sent with {@code Content-Type: text/vnd.turbo-stream.html}, over a stream source, or inside an Action
 * Cable broadcast. Shared by the Turbo and Action Cable decoders.
 */
public final class TurboStream {

    public static final String CONTENT_TYPE = "text/vnd.turbo-stream.html";
    public static final Set<String> KNOWN_ACTIONS = Set.of(
            "append", "prepend", "replace", "update", "remove", "before", "after", "morph", "refresh");

    static final int MAX_ACTIONS = 1000;
    static final int MAX_TEMPLATE_CHARS = 256 * 1024;
    private static final int SUMMARY_ITEMS = 6;

    private TurboStream() {
    }

    /** One {@code <turbo-stream>} element. {@code template} is null when there is no {@code <template>} child. */
    public record Action(String action, String target, String targets, Map<String, String> attrs, String template,
                         String content, boolean terminated) {

        /** "replace #message_42", "append .messages", "refresh", "replace (morph) #card". */
        public String label() {
            StringBuilder sb = new StringBuilder(action.isEmpty() ? "(no action)" : action);
            if ("morph".equalsIgnoreCase(attrs.get("method")) && !action.equals("morph")) sb.append(" (morph)");
            if (target != null && !target.isEmpty()) sb.append(" #").append(target);
            else if (targets != null && !targets.isEmpty()) sb.append(' ').append(targets);
            return sb.toString();
        }
    }

    /** Parsed stream plus non-fatal problems. */
    public record Result(List<Action> actions, List<String> warnings) {
        public boolean isEmpty() {
            return actions.isEmpty();
        }

        /** "replace #message_42, append #messages, remove #flash" (capped). */
        public String summaryList() {
            StringBuilder sb = new StringBuilder();
            int n = Math.min(actions.size(), SUMMARY_ITEMS);
            for (int i = 0; i < n; i++) {
                if (i > 0) sb.append(", ");
                sb.append(actions.get(i).label());
            }
            if (actions.size() > n) sb.append(", +").append(actions.size() - n).append(" more");
            return sb.toString();
        }

        public String summary() {
            return "Turbo Stream: " + summaryList();
        }
    }

    /** Cheap check: does the text contain a turbo-stream start tag? */
    public static boolean contains(String s) {
        return s != null && hasStreamTag(s);
    }

    private static boolean hasStreamTag(String s) {
        int i = HtmlScan.indexOfIgnoreCase(s, "<turbo-stream", 0);
        while (i >= 0) {
            int after = i + "<turbo-stream".length();
            if (after >= s.length()) return false;
            char c = s.charAt(after);
            if (c == '>' || c == '/' || Character.isWhitespace(c)) return true;
            i = HtmlScan.indexOfIgnoreCase(s, "<turbo-stream", after);
        }
        return false;
    }

    /** Parses every {@code <turbo-stream>} element in {@code s} (top level; nested ones stay inside templates). */
    public static Result parse(String s) {
        List<Action> out = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        int i = 0;
        boolean unknownWarned = false;
        while (out.size() < MAX_ACTIONS) {
            HtmlScan.Tag t = HtmlScan.find(s, "turbo-stream", i);
            if (t == null) break;
            String action = t.attrs().getOrDefault("action", "");
            String target = t.attr("target");
            String targets = t.attr("targets");
            int contentStart = t.end();
            int close = t.selfClosing() ? contentStart : HtmlScan.findClose(s, "turbo-stream", contentStart);
            boolean terminated = close >= 0;
            int contentEnd;
            if (terminated) {
                contentEnd = close;
                i = t.selfClosing() ? contentStart : HtmlScan.afterClose(s, close);
            } else {
                // Unterminated: content runs to the next top-level turbo-stream or the end.
                HtmlScan.Tag nx = HtmlScan.find(s, "turbo-stream", contentStart);
                contentEnd = nx == null ? s.length() : nx.start();
                i = contentEnd;
                warnings.add("<turbo-stream action=\"" + action + "\"> is not closed");
            }
            String content = s.substring(contentStart, Math.max(contentStart, contentEnd));
            String template = null;
            HtmlScan.Tag tpl = HtmlScan.find(content, "template", 0);
            if (tpl != null) {
                int tclose = tpl.selfClosing() ? tpl.end() : HtmlScan.findClose(content, "template", tpl.end());
                if (tclose < 0) {
                    warnings.add("<template> in <turbo-stream action=\"" + action + "\"> is not closed");
                    tclose = content.length();
                }
                template = content.substring(tpl.end(), Math.max(tpl.end(), tclose));
            }
            if (action.isEmpty()) warnings.add("<turbo-stream> without an action attribute");
            else if (!KNOWN_ACTIONS.contains(action) && !unknownWarned) {
                warnings.add("Custom stream action '" + action + "' (not a built-in Turbo action; handled by app JavaScript)");
                unknownWarned = true;
            }
            boolean needsTarget = !action.equals("refresh") && !action.isEmpty();
            if (needsTarget && (target == null || target.isEmpty()) && (targets == null || targets.isEmpty())) {
                warnings.add("<turbo-stream action=\"" + action + "\"> has no target or targets");
            }
            out.add(new Action(action, target, targets, t.attrs(), template, content, terminated));
            if (i <= t.start()) i = t.end();
        }
        if (out.size() >= MAX_ACTIONS) warnings.add("Stopped after " + MAX_ACTIONS + " stream actions");
        return new Result(out, warnings);
    }

    /** Tree for a parsed stream: an array of actions with their attributes and template HTML. */
    public static DecodedNode toNode(String name, Result r) {
        DecodedNode list = DecodedNode.array(name);
        int idx = 0;
        for (Action a : r.actions()) {
            DecodedNode n = new DecodedNode("[" + idx++ + "] " + a.label(), null, DecodedNode.Type.OBJECT);
            n.put("action", a.action());
            if (a.target() != null) n.put("target (element id)", a.target());
            if (a.targets() != null) n.put("targets (CSS selector)", a.targets());
            for (Map.Entry<String, String> e : a.attrs().entrySet()) {
                String k = e.getKey();
                if (k.equals("action") || k.equals("target") || k.equals("targets")) continue;
                String label = switch (k) {
                    case "method" -> "method" + ("morph".equals(e.getValue()) ? " (morph instead of replace)" : "");
                    case "request-id" -> "request-id (X-Turbo-Request-Id of the originating request)";
                    case "children-only" -> "children-only (morph children only)";
                    default -> k;
                };
                n.put(label, e.getValue());
            }
            if (a.template() != null) {
                String tpl = a.template().strip();
                n.add(DecodedNode.leaf("template", Codecs.truncate(tpl, MAX_TEMPLATE_CHARS), DecodedNode.Type.HTML));
            } else if (!a.content().isBlank()) {
                n.add(DecodedNode.leaf("content (no <template>)", Codecs.truncate(a.content().strip(), MAX_TEMPLATE_CHARS), DecodedNode.Type.HTML));
            } else if (a.action().equals("remove") || a.action().equals("refresh")) {
                n.add(DecodedNode.note(a.action().equals("remove") ? "removes the target element(s); no template" : "page refresh; no template"));
            }
            list.add(n);
        }
        return list;
    }
}
