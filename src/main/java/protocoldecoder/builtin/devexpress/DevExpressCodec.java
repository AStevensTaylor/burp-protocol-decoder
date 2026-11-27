package protocoldecoder.builtin.devexpress;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.edit.EditableDocument;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.edit.MessageCodec;
import protocoldecoder.edit.MessagePatch;
import protocoldecoder.scan.InsertionPoints;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.Deflater;
import java.util.zip.GZIPOutputStream;

/**
 * Document editing for DevExpress callbacks.
 *
 * <p><b>Callback argument</b> ({@code __CALLBACKPARAM} / {@code DXCallbackArgument}) as an outline of its segment
 * structure ({@link DxArgModel}), syntax "text":</p>
 * <pre>
 * prefix: c0:
 * KV: []
 * GB:
 *   - PAGERONCLICK
 *   - PN1
 * </pre>
 * <ul>
 *   <li>{@code NAME: value} is a named segment ({@code NAME|LEN;value;}); {@code NAME:} alone opens a nested block.</li>
 *   <li>{@code - value} is a positional segment ({@code LEN|value}); {@code -} alone opens a nested block; a line
 *       {@code ;} at the end of a positional block is its trailing semicolon.</li>
 *   <li>{@code = value} is an unstructured top-level value. Nested blocks are indented by two spaces.</li>
 *   <li>Values are bare text, or a JSON string ({@code "…"}, JSON escapes) when empty, containing control characters
 *       or newlines, starting with {@code "} or having leading/trailing spaces. Lines starting with {@code #} are
 *       comments.</li>
 * </ul>
 * All {@code NAME|LEN;} and {@code LEN|} prefixes (UTF-16 lengths, as the browser computes them) are recomputed. The
 * outline is lossless: {@code encode(text())} reproduces the parameter exactly.
 *
 * <p><b>{@code /*DX*&#47;(…)} responses</b>: the inner JavaScript literal as pretty JSON. The envelope
 * ({@code 0|} / {@code s<len>|<validation>}), the {@code /*DX*&#47;(} wrapper and anything after {@code )} are kept
 * byte-for-byte. DevExpress writes single-quoted JavaScript; an edited result is emitted as standard (compact) JSON,
 * which the client {@code eval}s just the same. Unedited text returns the original bytes.</p>
 */
public final class DevExpressCodec implements MessageCodec {

    private static final Pattern DX_MARKER = Pattern.compile("/\\*DX\\*/\\s*\\(");
    private static final int MAX_TEXT = 4 * 1024 * 1024;
    private static final Gson PRETTY = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().serializeNulls().create();
    private static final Gson COMPACT = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();
    static final String COMMENT = "# DevExpress callback argument: NAME|LEN; and LEN| prefixes are recomputed on encode.\n";

    @Override
    public String decoderId() {
        return DevExpressDecoder.ID;
    }

    @Override
    public List<EditableDocument> documents(MessageContext m, DecodeResult decoded) {
        if (decoded == null || m == null || m.isWebSocket()) return List.of();
        try {
            return m.isRequest() ? requestDocs(m) : responseDocs(m);
        } catch (RuntimeException e) {
            return List.of();
        }
    }

    // ---------------------------------------------------------------- requests

    private static List<EditableDocument> requestDocs(MessageContext m) {
        byte[] raw = m.requestBody();
        if (raw == null || raw.length == 0 || raw.length > MAX_TEXT) return List.of();
        String container = new String(raw, StandardCharsets.ISO_8859_1);
        var form = Codecs.parseQuery(m.requestBodyText());
        List<EditableDocument> out = new ArrayList<>();
        for (String field : DevExpressScanner.CALLBACK_FIELDS) {
            String value = Codecs.first(form, field);
            if (value == null || value.isEmpty()) continue;
            DxArgModel.Arg arg = DxArgModel.parse(value);
            if (arg.body() instanceof DxArgModel.Leaf || !arg.serialize().equals(value)) continue;
            out.add(new ArgDoc(field, value, outline(arg), container, raw));
        }
        return out;
    }

    private static final class ArgDoc implements EditableDocument {
        private final String field;
        private final String value;
        private final String text;
        private final String container;
        private final byte[] raw;

        ArgDoc(String field, String value, String text, String container, byte[] raw) {
            this.field = field;
            this.value = value;
            this.text = text;
            this.container = container;
            this.raw = raw;
        }

        @Override public String title() { return field + " (outline)"; }
        @Override public String text() { return text; }

        @Override
        public MessagePatch encode(String editedText) throws EncodeException {
            if (editedText == null) throw new EncodeException("Nothing to encode");
            if (editedText.equals(text)) return MessagePatch.body(raw);
            String param = parseOutline(editedText).serialize();
            if (param.equals(value)) return MessagePatch.body(raw);
            return MessagePatch.body(InsertionPoints.replaceFormField(container, field, 0, param).getBytes(StandardCharsets.ISO_8859_1));
        }
    }

    // ---------------------------------------------------------------- outline writer

    static String outline(DxArgModel.Arg arg) {
        StringBuilder sb = new StringBuilder(COMMENT);
        sb.append("prefix: ").append(scalar(arg.prefix())).append('\n');
        if (arg.body() instanceof DxArgModel.Leaf l) sb.append("= ").append(scalar(l.value())).append('\n');
        else block(sb, arg.body(), 0);
        return sb.toString();
    }

    private static void block(StringBuilder sb, DxArgModel.Node n, int depth) {
        String ind = "  ".repeat(depth);
        switch (n) {
            case DxArgModel.Named nm -> {
                for (int i = 0; i < nm.names().size(); i++) {
                    DxArgModel.Node v = nm.values().get(i);
                    sb.append(ind).append(nm.names().get(i)).append(':');
                    if (v instanceof DxArgModel.Leaf l) {
                        sb.append(' ').append(scalar(l.value())).append('\n');
                    } else {
                        sb.append('\n');
                        block(sb, v, depth + 1);
                    }
                }
            }
            case DxArgModel.Positional p -> {
                for (DxArgModel.Node v : p.values()) {
                    sb.append(ind).append('-');
                    if (v instanceof DxArgModel.Leaf l) {
                        sb.append(' ').append(scalar(l.value())).append('\n');
                    } else {
                        sb.append('\n');
                        block(sb, v, depth + 1);
                    }
                }
                if (p.trailingSemicolon()) sb.append(ind).append(";\n");
            }
            case DxArgModel.Leaf l -> sb.append(ind).append("= ").append(scalar(l.value())).append('\n');
        }
    }

    /** Bare text when unambiguous, otherwise a JSON string. */
    static String scalar(String v) {
        boolean bare = !v.isEmpty() && v.charAt(0) != '"' && v.equals(v.strip());
        for (int i = 0; bare && i < v.length(); i++) {
            char c = v.charAt(i);
            if (c < 0x20 || c == 0x7f || c == ' ' || c == ' ' || c == '\u0085') bare = false;
        }
        return bare ? v : COMPACT.toJson(v);
    }

    // ---------------------------------------------------------------- outline parser

    private record Line(int no, int indent, String body) {
    }

    static DxArgModel.Arg parseOutline(String text) throws EncodeException {
        List<Line> lines = new ArrayList<>();
        String[] raw = text.split("\n", -1);
        for (int i = 0; i < raw.length; i++) {
            String l = raw[i].endsWith("\r") ? raw[i].substring(0, raw[i].length() - 1) : raw[i];
            String t = l.strip();
            if (t.isEmpty() || t.startsWith("#")) continue;
            int ind = 0;
            while (ind < l.length() && l.charAt(ind) == ' ') ind++;
            if (ind < l.length() && l.charAt(ind) == '\t') throw err(i + 1, "use spaces, not tabs, for indentation");
            if (ind % 2 != 0) throw err(i + 1, "indentation must be a multiple of two spaces");
            lines.add(new Line(i + 1, ind / 2, l.substring(ind)));
        }
        if (lines.isEmpty() || !lines.get(0).body().startsWith("prefix:") || lines.get(0).indent() != 0) {
            throw err(lines.isEmpty() ? 1 : lines.get(0).no(), "the outline must start with 'prefix: <callback prefix>' (use prefix: \"\" for none)");
        }
        Line first = lines.get(0);
        String prefix = value(first, first.body().substring("prefix:".length()), true);
        if (lines.size() < 2) throw err(first.no(), "no segments after the prefix");
        int[] at = {1};
        DxArgModel.Node body;
        Line l1 = lines.get(1);
        if (l1.indent() != 0) throw err(l1.no(), "unexpected indentation");
        if (l1.body().startsWith("=")) {
            body = new DxArgModel.Leaf(value(l1, l1.body().substring(1), false));
            at[0] = 2;
        } else {
            body = parseBlock(lines, at, 0);
        }
        if (at[0] < lines.size()) throw err(lines.get(at[0]).no(), "unexpected line (wrong indentation?)");
        return new DxArgModel.Arg(prefix, body);
    }

    private static DxArgModel.Node parseBlock(List<Line> lines, int[] at, int depth) throws EncodeException {
        Line head = lines.get(at[0]);
        boolean positional = head.body().startsWith("-") || head.body().equals(";");
        List<String> names = new ArrayList<>();
        List<DxArgModel.Node> values = new ArrayList<>();
        boolean semi = false;
        while (at[0] < lines.size()) {
            Line l = lines.get(at[0]);
            if (l.indent() < depth) break;
            if (l.indent() > depth) throw err(l.no(), "unexpected indentation");
            if (semi) throw err(l.no(), "';' must be the last line of a positional block");
            String b = l.body();
            at[0]++;
            if (positional) {
                if (b.equals(";")) {
                    semi = true;
                    continue;
                }
                if (!b.startsWith("-")) throw err(l.no(), "expected '- value' (this block is positional)");
                String rest = b.substring(1);
                if (rest.isBlank()) values.add(child(lines, at, depth, l));
                else values.add(new DxArgModel.Leaf(value(l, rest, false)));
            } else {
                int colon = b.indexOf(':');
                if (b.startsWith("-") || b.equals(";")) throw err(l.no(), "expected 'NAME: value' (this block is named)");
                if (colon <= 0) throw err(l.no(), "expected 'NAME: value' or 'NAME:' followed by an indented block");
                String name = b.substring(0, colon);
                if (!name.matches("[A-Za-z][A-Za-z0-9_]*")) throw err(l.no(), "invalid segment name '" + name + "'");
                String rest = b.substring(colon + 1);
                names.add(name);
                if (rest.isBlank()) values.add(child(lines, at, depth, l));
                else values.add(new DxArgModel.Leaf(value(l, rest, false)));
            }
        }
        if (values.isEmpty()) throw err(head.no(), "empty block");
        return positional ? new DxArgModel.Positional(values, semi) : new DxArgModel.Named(names, values);
    }

    private static DxArgModel.Node child(List<Line> lines, int[] at, int depth, Line owner) throws EncodeException {
        if (at[0] >= lines.size() || lines.get(at[0]).indent() != depth + 1) {
            throw err(owner.no(), "a nested block (indented two more spaces) must follow; use \"\" for an empty value");
        }
        return parseBlock(lines, at, depth + 1);
    }

    /** The value after "NAME:", "-" or "=": optional spaces, then a JSON string or bare text (trailing spaces dropped). */
    private static String value(Line l, String rest, boolean allowEmpty) throws EncodeException {
        String v = rest.strip();
        if (v.isEmpty()) {
            if (allowEmpty) return "";
            throw err(l.no(), "missing value");
        }
        if (v.charAt(0) != '"') return v;
        try (JsonReader r = new JsonReader(new StringReader(v))) {
            r.setStrictness(Strictness.STRICT);
            if (r.peek() != JsonToken.STRING) throw err(l.no(), "bad quoted value");
            String s = r.nextString();
            if (r.peek() != JsonToken.END_DOCUMENT) throw err(l.no(), "text after the closing quote");
            return s;
        } catch (IOException | IllegalStateException | NumberFormatException e) {
            throw err(l.no(), "bad quoted value (" + e.getMessage().replaceFirst("\nSee .*", "") + ")");
        }
    }

    private static EncodeException err(int line, String msg) {
        return new EncodeException("Outline error at line " + line + ": " + msg);
    }

    // ---------------------------------------------------------------- responses

    private static List<EditableDocument> responseDocs(MessageContext m) {
        byte[] raw = m.responseBody();
        if (raw.length == 0) return List.of();
        String ce = m.responseHeader("Content-Encoding");
        byte[] dec = Codecs.decodeContent(raw, ce);
        if (dec.length > MAX_TEXT) return List.of();
        String text = new String(dec, StandardCharsets.UTF_8);
        if (!java.util.Arrays.equals(text.getBytes(StandardCharsets.UTF_8), dec)) return List.of();
        Matcher dx = DX_MARKER.matcher(text);
        if (!dx.find()) return List.of();
        int open = dx.end() - 1;
        int close = text.lastIndexOf(')');
        if (close <= open) return List.of();
        String literal = text.substring(open + 1, close);
        JsonElement e = JsonTree.parseLenient(literal);
        if (e == null) return List.of();
        String pretty;
        try {
            pretty = PRETTY.toJson(e);
        } catch (RuntimeException ex) {
            return List.of();
        }
        String before = text.substring(0, open + 1);
        String after = text.substring(close);
        boolean compressed = dec != raw;
        return List.of(new ResultDoc(pretty, before, after, raw, compressed, ce));
    }

    private static final class ResultDoc implements EditableDocument {
        private final String text;
        private final String before;
        private final String after;
        private final byte[] raw;
        private final boolean compressed;
        private final String ce;

        ResultDoc(String text, String before, String after, byte[] raw, boolean compressed, String ce) {
            this.text = text;
            this.before = before;
            this.after = after;
            this.raw = raw;
            this.compressed = compressed;
            this.ce = ce;
        }

        @Override public String title() { return "/*DX*/ callback result (JSON)"; }
        @Override public String syntax() { return "json"; }
        @Override public String text() { return text; }

        @Override
        public MessagePatch encode(String editedText) throws EncodeException {
            if (editedText == null) throw new EncodeException("Nothing to encode");
            if (editedText.equals(text)) return MessagePatch.body(raw);
            JsonElement e = parseStrict(editedText);
            byte[] b = (before + COMPACT.toJson(e) + after).getBytes(StandardCharsets.UTF_8);
            return MessagePatch.body(compressed ? recompress(b, raw, ce) : b);
        }
    }

    static JsonElement parseStrict(String s) throws EncodeException {
        try (JsonReader r = new JsonReader(new StringReader(s))) {
            r.setStrictness(Strictness.STRICT);
            JsonElement e = COMPACT.getAdapter(JsonElement.class).read(r);
            if (r.peek() != JsonToken.END_DOCUMENT) throw new EncodeException("JSON error: unexpected data after the JSON value");
            return e;
        } catch (JsonParseException | IOException | IllegalStateException | NumberFormatException e) {
            String msg = e.getMessage() == null ? e.toString() : e.getMessage();
            int see = msg.indexOf("\nSee ");
            if (see >= 0) msg = msg.substring(0, see);
            throw new EncodeException("JSON error: " + msg.replace(" column ", ", column "), e);
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
}
