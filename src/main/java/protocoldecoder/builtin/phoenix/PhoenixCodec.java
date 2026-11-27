package protocoldecoder.builtin.phoenix;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.edit.EditableDocument;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.edit.MessageCodec;
import protocoldecoder.edit.MessagePatch;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.EditJson;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Documents for Phoenix channel messages in the JSON serializers (v1 objects, v2 arrays) on WebSocket frames and
 * long-poll bodies: the message as pretty JSON, written back compactly in whatever shape the edited JSON has (as
 * {@code JSON.stringify} / Jason would). LiveView {@code event} pushes whose {@code payload.value} is a urlencoded
 * form string also get a "Form value" document of {@code name=value} lines. Binary-serializer frames are not offered.
 * Unchanged messages (and unchanged form fields) are written back byte-for-byte.
 */
public final class PhoenixCodec implements MessageCodec {

    static final String FORM_HEADER = "# LiveView form value (payload.value): one field per line as name=value, decoded.\n"
            + "# Escapes: \\n newline, \\r carriage return, \\\\ backslash, \\= '=' in a name, \\# leading '#'.\n";

    @Override
    public String decoderId() {
        return PhoenixDecoder.ID;
    }

    @Override
    public List<EditableDocument> documents(MessageContext m, DecodeResult decoded) {
        List<EditableDocument> out = new ArrayList<>();
        try {
            collect(m, out);
        } catch (RuntimeException e) {
            return List.of();
        }
        return out;
    }

    private interface Encoder {
        MessagePatch apply(byte[] body) throws EncodeException;
    }

    private static void collect(MessageContext m, List<EditableDocument> out) {
        byte[] raw = m.body();
        if (raw.length == 0 || raw.length > EditJson.MAX_DOCUMENT_CHARS) return;
        if (m.isWebSocket()) {
            if ((raw[0] & 0xff) <= 2) return; // binary serializer
            String text = Codecs.utf8(raw);
            if (PhoenixMessage.parseText(text) == null) return;
            single(text, b -> MessagePatch.body(b), "Phoenix message", out);
            return;
        }
        if (!PhoenixDecoder.longPollPath(m)) return;
        String ce = m.isResponse() ? m.header("Content-Encoding") : null;
        if (!EditJson.reEncodable(raw, ce)) return;
        byte[] body = EditJson.hasEncoding(ce) ? Codecs.decodeContent(raw, ce) : raw;
        String text = Codecs.utf8(body);
        Encoder enc = b -> MessagePatch.body(EditJson.reEncode(b, body, raw, ce));
        if (m.isResponse()) {
            JsonElement e = EditJson.tryParse(text);
            if (e == null || !e.isJsonObject()) return;
            out.add(jsonDoc("Phoenix long-poll response", text, e, enc));
            return;
        }
        String t = text.strip();
        if (PhoenixMessage.parseText(t) != null) {
            single(text, enc, "Phoenix message", out);
            return;
        }
        JsonElement whole = EditJson.tryParse(t);
        if (whole != null && whole.isJsonArray()) {
            if (PhoenixDecoder.parseLines(t).isEmpty()) return;
            out.add(jsonDoc("Phoenix long-poll messages", text, whole, enc));
            return;
        }
        if (!PhoenixDecoder.parseLines(t).isEmpty()) out.add(ndjsonDoc(text, enc));
    }

    // ---------------------------------------------------------------- message documents

    private static void single(String text, Encoder enc, String title, List<EditableDocument> out) {
        JsonElement e = EditJson.tryParse(text);
        if (e == null) return;
        PhoenixMessage pm = PhoenixMessage.fromJson(e);
        String label = pm == null ? title : title + " (" + pm.event() + " on " + pm.topic() + ")";
        out.add(jsonDoc(label, text, e, enc));
        EditableDocument form = formDoc(text, e, enc);
        if (form != null) out.add(form);
    }

    /** Pretty JSON; written back compactly, or as the original text when unchanged. */
    private static EditableDocument jsonDoc(String title, String original, JsonElement parsed, Encoder enc) {
        String canonical = EditJson.compact(parsed);
        return new EditJson.Doc(title, "json", EditJson.pretty(parsed), edited -> {
            String c = EditJson.compact(EditJson.parse(edited, "JSON"));
            return enc.apply((c.equals(canonical) ? original : c).getBytes(StandardCharsets.UTF_8));
        });
    }

    /** Newline-delimited messages: a JSON array, one element per line. */
    private static EditableDocument ndjsonDoc(String original, Encoder enc) {
        List<String> lines = new ArrayList<>();
        JsonArray all = new JsonArray();
        List<String> canonical = new ArrayList<>();
        for (String line : original.split("\n", -1)) {
            if (line.isBlank()) continue;
            JsonElement e = EditJson.tryParse(line);
            if (e == null) return null;
            lines.add(line);
            all.add(e);
            canonical.add(EditJson.compact(e));
        }
        boolean trailingNewline = original.endsWith("\n");
        return new EditJson.Doc("Phoenix long-poll messages (one per line)", "json", EditJson.pretty(all), edited -> {
            JsonElement e = EditJson.parse(edited, "JSON");
            if (!e.isJsonArray()) throw new EncodeException("The document must be a JSON array with one element per message line");
            StringBuilder sb = new StringBuilder();
            JsonArray a = e.getAsJsonArray();
            boolean same = a.size() == canonical.size();
            for (int i = 0; i < a.size(); i++) {
                String c = EditJson.compact(a.get(i));
                if (i > 0) sb.append('\n');
                boolean keep = i < canonical.size() && canonical.get(i).equals(c);
                same &= keep;
                sb.append(keep ? lines.get(i) : c);
            }
            if (trailingNewline) sb.append('\n');
            if (same) return enc.apply(original.getBytes(StandardCharsets.UTF_8));
            return enc.apply(sb.toString().getBytes(StandardCharsets.UTF_8));
        });
    }

    // ---------------------------------------------------------------- LiveView form value

    private static EditableDocument formDoc(String original, JsonElement msg, Encoder enc) {
        PhoenixMessage pm = PhoenixMessage.fromJson(msg);
        if (pm == null || !pm.isLiveView() || !"event".equals(pm.event())) return null;
        if (!(pm.payload() instanceof JsonObject po) || !(po.get("value") instanceof JsonPrimitive v) || !v.isString()) return null;
        String type = po.get("type") instanceof JsonPrimitive t && t.isString() ? t.getAsString() : "";
        String value = v.getAsString();
        if (!type.equals("form") && !(value.contains("=") && !value.contains(" ") && !value.startsWith("{"))) return null;
        String[] pairs = value.isEmpty() ? new String[0] : value.split("&", -1);
        List<String[]> decodedPairs = new ArrayList<>();
        StringBuilder sb = new StringBuilder(FORM_HEADER);
        for (String p : pairs) {
            int eq = p.indexOf('=');
            String k = Codecs.urlDecode(eq < 0 ? p : p.substring(0, eq));
            String val = eq < 0 ? null : Codecs.urlDecode(p.substring(eq + 1));
            decodedPairs.add(new String[]{k, val});
            sb.append(escapeName(k));
            if (val != null) sb.append('=').append(escapeValue(val));
            sb.append('\n');
        }
        String event = po.get("event") instanceof JsonPrimitive ev ? " " + ev.getAsString() : "";
        String canonicalMsg = EditJson.compact(msg);
        return new EditJson.Doc("LiveView form value" + (event.isEmpty() ? "" : " (" + event.strip() + ")"), "text", sb.toString(), edited -> {
            List<String> rebuilt = new ArrayList<>();
            String[] lines = edited.replace("\r\n", "\n").split("\n", -1);
            int n = 0;
            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] kv = unescapeLine(line, i + 1);
                int idx = n++;
                if (idx < decodedPairs.size() && eq(decodedPairs.get(idx), kv) && idx < pairs.length) {
                    rebuilt.add(pairs[idx]);
                } else {
                    rebuilt.add(enc(kv[0]) + (kv[1] == null ? "" : "=" + enc(kv[1])));
                }
            }
            String newValue = String.join("&", rebuilt);
            JsonElement copy = msg.deepCopy();
            JsonObject payload = copy.isJsonArray() ? copy.getAsJsonArray().get(4).getAsJsonObject() : copy.getAsJsonObject().getAsJsonObject("payload");
            payload.addProperty("value", newValue);
            String c = EditJson.compact(copy);
            return enc.apply((c.equals(canonicalMsg) ? original : c).getBytes(StandardCharsets.UTF_8));
        });
    }

    private static boolean eq(String[] a, String[] b) {
        return a[0].equals(b[0]) && (a[1] == null ? b[1] == null : a[1].equals(b[1]));
    }

    /** URLSearchParams-style encoding (space as '+'), as the LiveView client serialises forms. */
    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    static String escapeName(String s) {
        String e = escapeValue(s).replace("=", "\\=");
        return e.startsWith("#") ? "\\" + e : e;
    }

    static String escapeValue(String s) {
        return s.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r");
    }

    /** {name, value-or-null}: splits at the first unescaped '='. */
    static String[] unescapeLine(String line, int lineNo) throws EncodeException {
        StringBuilder name = new StringBuilder();
        StringBuilder value = null;
        StringBuilder cur = name;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '\\') {
                if (i + 1 >= line.length()) throw new EncodeException("Line " + lineNo + ": trailing backslash (write \\\\ for a backslash)");
                char e = line.charAt(++i);
                switch (e) {
                    case 'n' -> cur.append('\n');
                    case 'r' -> cur.append('\r');
                    case '\\', '=', '#' -> cur.append(e);
                    default -> throw new EncodeException("Line " + lineNo + ", column " + i + ": unknown escape '\\" + e + "' (use \\\\ for a backslash)");
                }
            } else if (c == '=' && value == null) {
                value = new StringBuilder();
                cur = value;
            } else {
                cur.append(c);
            }
        }
        return new String[]{name.toString(), value == null ? null : value.toString()};
    }
}
