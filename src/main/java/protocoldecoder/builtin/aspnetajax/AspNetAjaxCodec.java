package protocoldecoder.builtin.aspnetajax;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.edit.EditableDocument;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.edit.MessageCodec;
import protocoldecoder.edit.MessagePatch;
import protocoldecoder.util.Codecs;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.zip.Deflater;
import java.util.zip.GZIPOutputStream;

/**
 * Document editing for ASP.NET AJAX.
 *
 * <ul>
 *   <li><b>UpdatePanel delta responses</b> as an editable record list (syntax "text"). Each record is a header line
 *       {@code ### <type> | <id>} followed by its content lines; content lines that start with {@code ###} are written
 *       with one extra {@code #} (removed again on encode), so headers are unambiguous. Encoding rebuilds
 *       {@code length|type|id|content|} with lengths recomputed in UTF-16 code units, as {@link DeltaParser} and the
 *       browser count them. Lossless: {@code encode(text())} gives the original bytes.</li>
 *   <li><b>ASMX / WCF / PageMethod JSON</b> request bodies and responses ({@code {"d": …}}) as pretty JSON. Encoding
 *       re-serialises compactly with key order kept and {@code "\/Date(…)\/"} strings written with the escaped
 *       slashes ASP.NET needs (when the original used them). Unedited text returns the original bytes; an edited
 *       document is semantically identical apart from the edit (whitespace and string escapes are normalised).</li>
 * </ul>
 * Content-Encoding (gzip / deflate) and a leading BOM are restored.
 */
public final class AspNetAjaxCodec implements MessageCodec {

    private static final int MAX_TEXT = 4 * 1024 * 1024;
    private static final int MAX_RECORDS = 20_000;
    private static final Pattern DATE = Pattern.compile("^/Date\\(-?\\d{1,16}([+-]\\d{4})?\\)/$");
    private static final Gson GSON = new Gson();

    @Override
    public String decoderId() {
        return AspNetAjaxDecoder.ID;
    }

    @Override
    public List<EditableDocument> documents(MessageContext m, DecodeResult decoded) {
        if (decoded == null || decoded.root() == null || m == null || m.isWebSocket()) return List.of();
        try {
            String kind = decoded.root().name();
            Body body = Body.of(m);
            if (body == null) return List.of();
            if (m.isResponse() && "ASP.NET AJAX delta".equals(kind)) {
                DeltaParser.Result r = DeltaParser.parse(body.text, MAX_RECORDS);
                if (!r.clean() || r.records().isEmpty()) return List.of();
                return List.of(new DeltaDoc(body, r.records()));
            }
            if ((m.isResponse() && "ASP.NET AJAX service response".equals(kind))
                    || (m.isRequest() && "ASP.NET AJAX service call".equals(kind))) {
                if (body.text.isBlank()) return List.of();
                JsonElement e;
                try {
                    e = parseStrict(body.text);
                } catch (EncodeException ex) {
                    return List.of(); // not strict JSON: nothing safe to offer
                }
                boolean dates = body.text.contains("\\/Date(");
                String title = m.isRequest() ? "Service request (JSON)"
                        : e.isJsonObject() && e.getAsJsonObject().has("d") ? "Service response {\"d\"} (JSON)" : "Service response (JSON)";
                return List.of(new JsonDoc(title, body, write(e, true, dates), dates));
            }
        } catch (RuntimeException e) {
            return List.of();
        }
        return List.of();
    }

    // ---------------------------------------------------------------- body handling

    /** Decoded body text plus what is needed to put new text back (BOM, Content-Encoding). */
    private record Body(MessageContext m, String text, boolean bom, boolean compressed, byte[] raw, String ce) {
        static Body of(MessageContext m) {
            byte[] raw = m.body();
            if (raw == null || raw.length == 0) return new Body(m, "", false, false, raw == null ? new byte[0] : raw, null);
            String ce = m.header("Content-Encoding");
            byte[] dec = Codecs.decodeContent(raw, ce);
            if (dec.length > MAX_TEXT) return null;
            String text = new String(dec, StandardCharsets.UTF_8);
            if (!java.util.Arrays.equals(text.getBytes(StandardCharsets.UTF_8), dec)) return null; // not clean UTF-8
            boolean bom = !text.isEmpty() && text.charAt(0) == '﻿';
            if (bom) text = text.substring(1);
            return new Body(m, text, bom, dec != raw, raw, ce);
        }

        MessagePatch original() {
            return MessagePatch.body(raw);
        }

        MessagePatch with(String newText) {
            byte[] b = ((bom ? "﻿" : "") + newText).getBytes(StandardCharsets.UTF_8);
            return MessagePatch.body(compressed ? recompress(b, raw, ce) : b);
        }
    }

    private static byte[] recompress(byte[] data, byte[] original, String ce) {
        try {
            if (Codecs.isGzip(original) || (ce != null && ce.toLowerCase(Locale.ROOT).contains("gzip"))) {
                ByteArrayOutputStream bos = new ByteArrayOutputStream(data.length / 2 + 32);
                try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
                    gz.write(data);
                }
                return bos.toByteArray();
            }
            Deflater d = new Deflater(Deflater.DEFAULT_COMPRESSION, !Codecs.isZlib(original));
            try {
                d.setInput(data);
                d.finish();
                ByteArrayOutputStream out = new ByteArrayOutputStream(data.length / 2 + 64);
                byte[] buf = new byte[8192];
                while (!d.finished()) out.write(buf, 0, d.deflate(buf));
                return out.toByteArray();
            } finally {
                d.end();
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // ---------------------------------------------------------------- delta

    static final String HEADER = "### ";

    /** Text form of delta records. */
    static String deltaText(List<DeltaParser.Record> records) {
        StringBuilder sb = new StringBuilder();
        for (DeltaParser.Record r : records) {
            sb.append(HEADER).append(r.type()).append(" | ").append(r.id()).append('\n');
            String[] lines = r.content().split("\n", -1);
            for (int i = 0; i < lines.length; i++) {
                if (i > 0) sb.append('\n');
                if (lines[i].startsWith("###")) sb.append('#');
                sb.append(lines[i]);
            }
            sb.append('\n');
        }
        return sb.toString();
    }

    /** One parsed record of the text form. */
    record TextRecord(String type, String id, String content) {
    }

    /** Parses the text form back into records. */
    static List<TextRecord> parseDeltaText(String text) throws EncodeException {
        List<TextRecord> out = new ArrayList<>();
        String[] lines = text.split("\n", -1);
        String type = null, id = null;
        StringBuilder content = null;
        int contentLines = 0;
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (line.startsWith(HEADER)) {
                if (type != null) out.add(new TextRecord(type, id, content.toString()));
                String h = line.endsWith("\r") ? line.substring(0, line.length() - 1) : line;
                h = h.substring(HEADER.length());
                int sep = h.indexOf(" | ");
                if (sep < 0) throw new EncodeException("Line " + (i + 1) + ": record header must be '### <type> | <id>'");
                type = h.substring(0, sep);
                id = h.substring(sep + 3);
                if (type.isEmpty()) throw new EncodeException("Line " + (i + 1) + ": record type is empty");
                if (type.indexOf('|') >= 0 || id.indexOf('|') >= 0) {
                    throw new EncodeException("Line " + (i + 1) + ": record type and id cannot contain '|'");
                }
                content = new StringBuilder();
                contentLines = 0;
                continue;
            }
            if (type == null) {
                if (line.isBlank()) continue;
                throw new EncodeException("Line " + (i + 1) + ": text before the first '### <type> | <id>' record header");
            }
            if (contentLines++ > 0) content.append('\n');
            content.append(line.startsWith("####") ? line.substring(1) : line);
        }
        if (type == null) throw new EncodeException("No records: expected at least one '### <type> | <id>' header");
        // The newline after the last record's content is a separator, not content.
        String last = content.toString();
        out.add(new TextRecord(type, id, last.endsWith("\n") ? last.substring(0, last.length() - 1) : last));
        return out;
    }

    /** {@code length|type|id|content|} for each record, length in UTF-16 code units. */
    static String encodeDelta(List<TextRecord> records) {
        StringBuilder sb = new StringBuilder();
        for (TextRecord r : records) {
            sb.append(r.content().length()).append('|').append(r.type()).append('|').append(r.id()).append('|')
                    .append(r.content()).append('|');
        }
        return sb.toString();
    }

    private static final class DeltaDoc implements EditableDocument {
        private final Body body;
        private final String text;
        private final int count;

        DeltaDoc(Body body, List<DeltaParser.Record> records) {
            this.body = body;
            this.text = deltaText(records);
            this.count = records.size();
        }

        @Override public String title() { return "UpdatePanel delta (" + count + (count == 1 ? " record)" : " records)"); }
        @Override public String text() { return text; }

        @Override
        public MessagePatch encode(String editedText) throws EncodeException {
            if (editedText == null) throw new EncodeException("Nothing to encode");
            if (editedText.equals(text)) return body.original();
            String delta = encodeDelta(parseDeltaText(editedText));
            return body.with(delta);
        }
    }

    // ---------------------------------------------------------------- JSON

    private static final class JsonDoc implements EditableDocument {
        private final String title;
        private final Body body;
        private final String text;
        private final boolean dates;

        JsonDoc(String title, Body body, String text, boolean dates) {
            this.title = title;
            this.body = body;
            this.text = text;
            this.dates = dates;
        }

        @Override public String title() { return title; }
        @Override public String syntax() { return "json"; }
        @Override public String text() { return text; }

        @Override
        public MessagePatch encode(String editedText) throws EncodeException {
            if (editedText == null) throw new EncodeException("Nothing to encode");
            if (editedText.equals(text)) return body.original();
            JsonElement e = parseStrict(editedText);
            return body.with(write(e, false, dates));
        }
    }

    /** Strict JSON parse with a user-facing error message. */
    static JsonElement parseStrict(String s) throws EncodeException {
        try (JsonReader r = new JsonReader(new StringReader(s))) {
            r.setStrictness(Strictness.STRICT);
            JsonElement e = GSON.getAdapter(JsonElement.class).read(r);
            if (r.peek() != JsonToken.END_DOCUMENT) throw new EncodeException("JSON error: unexpected data after the JSON value");
            return e;
        } catch (JsonParseException | IOException | IllegalStateException | NumberFormatException e) {
            String msg = e.getMessage() == null ? e.toString() : e.getMessage();
            int see = msg.indexOf("\nSee ");
            if (see >= 0) msg = msg.substring(0, see);
            throw new EncodeException("JSON error: " + msg.replace(" column ", ", column "), e);
        }
    }

    /** JSON writer: pretty (2-space indent) or compact; keeps key order and number text; optional {@code \/Date} escaping. */
    static String write(JsonElement e, boolean pretty, boolean escapeDates) {
        StringBuilder sb = new StringBuilder();
        write(sb, e, pretty, escapeDates, 0);
        return sb.toString();
    }

    private static void write(StringBuilder sb, JsonElement e, boolean pretty, boolean dates, int depth) {
        if (e == null || e.isJsonNull()) {
            sb.append("null");
        } else if (e.isJsonObject()) {
            JsonObject o = e.getAsJsonObject();
            if (o.size() == 0) {
                sb.append("{}");
                return;
            }
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, JsonElement> en : o.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                newline(sb, pretty, depth + 1);
                string(sb, en.getKey(), false);
                sb.append(pretty ? ": " : ":");
                write(sb, en.getValue(), pretty, dates, depth + 1);
            }
            newline(sb, pretty, depth);
            sb.append('}');
        } else if (e.isJsonArray()) {
            JsonArray a = e.getAsJsonArray();
            if (a.isEmpty()) {
                sb.append("[]");
                return;
            }
            sb.append('[');
            for (int i = 0; i < a.size(); i++) {
                if (i > 0) sb.append(',');
                newline(sb, pretty, depth + 1);
                write(sb, a.get(i), pretty, dates, depth + 1);
            }
            newline(sb, pretty, depth);
            sb.append(']');
        } else {
            JsonPrimitive p = e.getAsJsonPrimitive();
            if (p.isBoolean()) sb.append(p.getAsBoolean());
            else if (p.isNumber()) sb.append(p.getAsNumber().toString());
            else string(sb, p.getAsString(), dates && DATE.matcher(p.getAsString()).matches());
        }
    }

    private static void newline(StringBuilder sb, boolean pretty, int depth) {
        if (!pretty) return;
        sb.append('\n');
        for (int i = 0; i < depth; i++) sb.append("  ");
    }

    private static void string(StringBuilder sb, String s, boolean escapeSlash) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '/' -> sb.append(escapeSlash ? "\\/" : "/");
                default -> {
                    if (c < 0x20 || c == ' ' || c == ' ') sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        sb.append('"');
    }
}
