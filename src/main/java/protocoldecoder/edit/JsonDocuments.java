package protocoldecoder.edit;

import protocoldecoder.core.MessageContext;
import protocoldecoder.util.Codecs;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Shared machinery for codecs that present JSON (or JSON nested in JSON strings) as editable documents.
 *
 * <p>JSON is handled at the token level rather than through a tree model: strings, numbers and keys are kept in their
 * original lexical form (escapes, exponent notation, trailing zeros, duplicate keys and key order survive), and only
 * whitespace is changed for display. Re-encoding follows the original's style: a compact original is re-minified, a
 * formatted one is sent as the user typed it, and escaping conventions the original used ({@code \\uXXXX} for
 * non-ASCII, {@code \/}, HTML-safe {@code \\u003c}…) are re-applied to edited strings. An unedited document always
 * re-encodes to the original bytes.</p>
 */
public final class JsonDocuments {

    /** Documents whose text would be larger than this are not offered. */
    public static final int MAX_TEXT = 4 * 1024 * 1024;
    /** At most this many documents per message and codec. */
    public static final int MAX_DOCS = 10;
    private static final int MAX_DEPTH = 500;

    private JsonDocuments() {
    }

    // =================================================================== documents

    /** Re-encodes a validated, re-styled JSON text into the message. */
    @FunctionalInterface
    public interface Rebuild {
        MessagePatch apply(String newText) throws EncodeException;
    }

    /** A document with fixed text whose encoder is {@code rebuild}. */
    public static EditableDocument document(String title, String syntax, String text, Rebuild rebuild) {
        return new EditableDocument() {
            @Override public String title() { return title; }
            @Override public String syntax() { return syntax; }
            @Override public String text() { return text; }
            @Override public MessagePatch encode(String editedText) throws EncodeException {
                if (editedText == null) throw new EncodeException("No text");
                return rebuild.apply(editedText);
            }
        };
    }

    /** A pretty-printed JSON document over {@code view}; {@code rebuild} receives the re-encoded JSON (or string token). */
    public static EditableDocument json(String title, JsonView view, Rebuild rebuild) {
        return document(title, "json", view.text(), edited -> rebuild.apply(view.encode(edited)));
    }

    /** Adds {@code d} unless the list is full or {@code d} is null. */
    public static void add(List<EditableDocument> out, EditableDocument d) {
        if (d != null && out.size() < MAX_DOCS) out.add(d);
    }

    // =================================================================== JSON view

    /**
     * Editable view of one JSON text. With {@code unwrapDepth > 0}, string values holding a JSON object/array (the root
     * itself, if it is such a string, counts as the first level) are shown parsed and re-stringified on encode.
     */
    public static final class JsonView {
        private final String original;
        private final Node root;
        private final Style style;
        private final boolean compact;
        private final Map<List<Object>, Wrap> wraps = new HashMap<>();
        private final String text;

        private record Wrap(String rawToken, String inner, Node innerNode, Style innerStyle, Style outerStyle) {
        }

        private JsonView(String original, Node root, int unwrapDepth) {
            this.original = original;
            this.root = root;
            this.style = Style.detect(original);
            String trimmed = original.strip();
            this.compact = minify(root).equals(trimmed);
            collectWraps(root, new ArrayList<>(), unwrapDepth, style);
            StringBuilder sb = new StringBuilder();
            pretty(root, new ArrayList<>(), 0, sb);
            this.text = sb.toString();
        }

        /** View of a JSON text, or null if it is not valid JSON or too large. */
        public static JsonView of(String json) {
            return of(json, 0);
        }

        public static JsonView of(String json, int unwrapDepth) {
            if (json == null || json.length() > MAX_TEXT) return null;
            Node n = tryParse(json);
            if (n == null) return null;
            JsonView v = new JsonView(json, n, unwrapDepth);
            return v.text.length() > MAX_TEXT ? null : v;
        }

        /** View of a JSON string token (with quotes) whose content is a JSON object/array; null otherwise. */
        public static JsonView ofStringToken(String rawToken, int unwrapDepth) {
            JsonView v = of(rawToken, Math.max(1, unwrapDepth));
            return v == null || !v.wraps.containsKey(List.of()) ? null : v;
        }

        public String text() {
            return text;
        }

        public String original() {
            return original;
        }

        /** True if the original was minified (no insignificant whitespace). */
        public boolean compact() {
            return compact;
        }

        /** Validates the edited text and re-encodes it in the original's style. */
        public String encode(String edited) throws EncodeException {
            if (edited.equals(text)) return original;
            Node n = parse(edited);
            if (wraps.isEmpty() && !compact) {
                int lead = 0, trail = original.length();
                while (lead < trail && isWs(original.charAt(lead))) lead++;
                while (trail > lead && isWs(original.charAt(trail - 1))) trail--;
                return original.substring(0, lead) + restyle(edited.strip(), style) + original.substring(trail);
            }
            StringBuilder sb = new StringBuilder();
            emit(n, new ArrayList<>(), style, sb);
            String out = sb.toString();
            if (compact) {
                int lead = 0, trail = original.length();
                while (lead < trail && isWs(original.charAt(lead))) lead++;
                while (trail > lead && isWs(original.charAt(trail - 1))) trail--;
                out = original.substring(0, lead) + out + original.substring(trail);
            }
            return out;
        }

        // ------------------------------------------------------------- internals

        private void collectWraps(Node n, List<Object> path, int depth, Style levelStyle) {
            if (wraps.size() > 10_000) return;
            switch (n.type) {
                case OBJECT -> {
                    for (int i = 0; i < n.values.size(); i++) {
                        path.add(n.keys.get(i).string());
                        collectWraps(n.values.get(i), path, depth, levelStyle);
                        path.remove(path.size() - 1);
                    }
                }
                case ARRAY -> {
                    for (int i = 0; i < n.values.size(); i++) {
                        path.add(i);
                        collectWraps(n.values.get(i), path, depth, levelStyle);
                        path.remove(path.size() - 1);
                    }
                }
                case STRING -> {
                    if (depth <= 0) return;
                    String s = n.string();
                    String t = s.strip();
                    if (t.length() < 2 || !((t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]")))) return;
                    Node inner = tryParse(s);
                    if (inner == null) return;
                    Style innerStyle = Style.detect(s);
                    wraps.put(List.copyOf(path), new Wrap(n.raw(), s, inner, innerStyle, levelStyle));
                    collectWraps(inner, path, depth - 1, innerStyle);
                }
                default -> {
                }
            }
        }

        private void pretty(Node n, List<Object> path, int indent, StringBuilder sb) {
            if (n.type == Type.STRING) {
                Wrap w = wraps.get(path);
                if (w != null) {
                    pretty(w.innerNode, path, indent, sb);
                    return;
                }
            }
            switch (n.type) {
                case OBJECT, ARRAY -> {
                    boolean obj = n.type == Type.OBJECT;
                    if (n.values.isEmpty()) {
                        sb.append(obj ? "{}" : "[]");
                        return;
                    }
                    sb.append(obj ? '{' : '[').append('\n');
                    for (int i = 0; i < n.values.size(); i++) {
                        indent(sb, indent + 1);
                        if (obj) {
                            sb.append(n.keys.get(i).raw()).append(": ");
                            path.add(n.keys.get(i).string());
                        } else {
                            path.add(i);
                        }
                        pretty(n.values.get(i), path, indent + 1, sb);
                        path.remove(path.size() - 1);
                        if (i < n.values.size() - 1) sb.append(',');
                        sb.append('\n');
                    }
                    indent(sb, indent);
                    sb.append(obj ? '}' : ']');
                }
                default -> sb.append(n.raw());
            }
        }

        private void emit(Node n, List<Object> path, Style levelStyle, StringBuilder sb) {
            Wrap w = wraps.get(path);
            if (w != null && (n.type == Type.OBJECT || n.type == Type.ARRAY)) {
                StringBuilder inner = new StringBuilder();
                emitNode(n, path, w.innerStyle, inner);
                String s = inner.toString();
                sb.append(s.equals(w.inner) || s.equals(w.inner.strip()) ? w.rawToken : quote(s, w.outerStyle));
                return;
            }
            emitNode(n, path, levelStyle, sb);
        }

        /** Emits {@code n} itself (no wrap at its own path), children via {@link #emit}. */
        private void emitNode(Node n, List<Object> path, Style levelStyle, StringBuilder sb) {
            switch (n.type) {
                case OBJECT, ARRAY -> {
                    boolean obj = n.type == Type.OBJECT;
                    sb.append(obj ? '{' : '[');
                    for (int i = 0; i < n.values.size(); i++) {
                        if (i > 0) sb.append(',');
                        if (obj) {
                            sb.append(restyle(n.keys.get(i).raw(), levelStyle)).append(':');
                            path.add(n.keys.get(i).string());
                        } else {
                            path.add(i);
                        }
                        emit(n.values.get(i), path, levelStyle, sb);
                        path.remove(path.size() - 1);
                    }
                    sb.append(obj ? '}' : ']');
                }
                case STRING -> sb.append(restyle(n.raw(), levelStyle));
                default -> sb.append(n.raw());
            }
        }

        private static void indent(StringBuilder sb, int n) {
            for (int i = 0; i < n; i++) sb.append("  ");
        }
    }

    // =================================================================== token-level JSON

    enum Type { OBJECT, ARRAY, STRING, NUMBER, LITERAL }

    /** A parsed JSON value with its source span. */
    public static final class Node {
        final Type type;
        final String src;
        final int start;
        int end;
        final List<Node> keys;
        final List<Node> values;

        Node(Type type, String src, int start) {
            this.type = type;
            this.src = src;
            this.start = start;
            boolean container = type == Type.OBJECT || type == Type.ARRAY;
            this.values = container ? new ArrayList<>() : List.of();
            this.keys = type == Type.OBJECT ? new ArrayList<>() : List.of();
        }

        public int start() { return start; }
        public int end() { return end; }
        public String raw() { return src.substring(start, end); }
        public boolean isObject() { return type == Type.OBJECT; }
        public boolean isArray() { return type == Type.ARRAY; }
        public boolean isString() { return type == Type.STRING; }
        public int size() { return values.size(); }
        public Node get(int i) { return i >= 0 && i < values.size() ? values.get(i) : null; }
        public List<Node> items() { return values; }

        /** First member with this key, or null. */
        public Node get(String key) {
            for (int i = 0; i < keys.size(); i++) if (keys.get(i).string().equals(key)) return values.get(i);
            return null;
        }

        public List<String> keyNames() {
            List<String> out = new ArrayList<>();
            for (Node k : keys) out.add(k.string());
            return out;
        }

        /** Decoded string value (strings only), else null. */
        public String string() {
            return type == Type.STRING ? unquote(raw()) : null;
        }
    }

    /** True if the text (trimmed) starts and ends like a JSON object or array. */
    public static boolean looksLikeContainer(String s) {
        if (s == null) return false;
        String t = s.strip();
        return t.length() >= 2 && ((t.charAt(0) == '{' && t.charAt(t.length() - 1) == '}') || (t.charAt(0) == '[' && t.charAt(t.length() - 1) == ']'));
    }

    /** Parses strict JSON, or returns null. */
    public static Node tryParse(String s) {
        try {
            return parse(s);
        } catch (EncodeException e) {
            return null;
        }
    }

    /** Parses strict JSON (surrounding whitespace allowed), with a line/column message on error. */
    public static Node parse(String s) throws EncodeException {
        Parser p = new Parser(s);
        p.ws();
        Node n = p.value(0);
        p.ws();
        if (p.i < s.length()) throw p.error("unexpected '" + printable(s.charAt(p.i)) + "' after the end of the JSON value");
        return n;
    }

    private static final class Parser {
        final String s;
        int i;

        Parser(String s) {
            this.s = s;
        }

        void ws() {
            while (i < s.length() && isWs(s.charAt(i))) i++;
        }

        EncodeException error(String msg) {
            int line = 1, col = 1;
            for (int k = 0; k < Math.min(i, s.length()); k++) {
                if (s.charAt(k) == '\n') {
                    line++;
                    col = 1;
                } else {
                    col++;
                }
            }
            return new EncodeException("JSON error at line " + line + ", column " + col + ": " + msg);
        }

        Node value(int depth) throws EncodeException {
            if (depth > MAX_DEPTH) throw error("nesting deeper than " + MAX_DEPTH + " levels");
            if (i >= s.length()) throw error("unexpected end of input, expected a value");
            char c = s.charAt(i);
            return switch (c) {
                case '{' -> container(Type.OBJECT, depth);
                case '[' -> container(Type.ARRAY, depth);
                case '"' -> string();
                case 't' -> literal("true");
                case 'f' -> literal("false");
                case 'n' -> literal("null");
                default -> {
                    if (c == '-' || (c >= '0' && c <= '9')) yield number();
                    throw error("unexpected '" + printable(c) + "', expected a value");
                }
            };
        }

        Node container(Type t, int depth) throws EncodeException {
            boolean obj = t == Type.OBJECT;
            char close = obj ? '}' : ']';
            Node n = new Node(t, s, i);
            i++;
            ws();
            if (i < s.length() && s.charAt(i) == close) {
                i++;
                n.end = i;
                return n;
            }
            while (true) {
                ws();
                if (obj) {
                    if (i >= s.length() || s.charAt(i) != '"') throw error(i >= s.length() ? "unexpected end of input, expected a key" : "expected a quoted key, found '" + printable(s.charAt(i)) + "'");
                    n.keys.add(string());
                    ws();
                    if (i >= s.length() || s.charAt(i) != ':') throw error("expected ':' after key");
                    i++;
                    ws();
                }
                n.values.add(value(depth + 1));
                ws();
                if (i >= s.length()) throw error("unexpected end of input, expected ',' or '" + close + "'");
                char c = s.charAt(i);
                if (c == ',') {
                    i++;
                    ws();
                    if (i < s.length() && s.charAt(i) == close) throw error("trailing comma before '" + close + "'");
                    continue;
                }
                if (c == close) {
                    i++;
                    n.end = i;
                    return n;
                }
                throw error("expected ',' or '" + close + "', found '" + printable(c) + "'");
            }
        }

        Node string() throws EncodeException {
            Node n = new Node(Type.STRING, s, i);
            i++;
            while (true) {
                if (i >= s.length()) throw error("unterminated string");
                char c = s.charAt(i);
                if (c == '"') {
                    i++;
                    n.end = i;
                    return n;
                }
                if (c == '\\') {
                    if (i + 1 >= s.length()) throw error("unterminated string");
                    char e = s.charAt(i + 1);
                    if (e == 'u') {
                        for (int k = 2; k < 6; k++) {
                            if (i + k >= s.length() || Character.digit(s.charAt(i + k), 16) < 0) throw error("invalid \\u escape");
                        }
                        i += 6;
                    } else if ("\"\\/bfnrt".indexOf(e) >= 0) {
                        i += 2;
                    } else {
                        throw error("invalid escape '\\" + printable(e) + "'");
                    }
                    continue;
                }
                if (c < 0x20) throw error(c == '\n' ? "line break inside a string (use \\n)" : "control character inside a string");
                i++;
            }
        }

        Node literal(String word) throws EncodeException {
            if (!s.startsWith(word, i)) throw error("unexpected '" + printable(s.charAt(i)) + "', expected a value");
            Node n = new Node(Type.LITERAL, s, i);
            i += word.length();
            n.end = i;
            return n;
        }

        Node number() throws EncodeException {
            Node n = new Node(Type.NUMBER, s, i);
            if (s.charAt(i) == '-') i++;
            if (i >= s.length() || !isDigit(s.charAt(i))) throw error("invalid number");
            if (s.charAt(i) == '0') {
                i++;
                if (i < s.length() && isDigit(s.charAt(i))) throw error("invalid number (leading zero)");
            } else {
                while (i < s.length() && isDigit(s.charAt(i))) i++;
            }
            if (i < s.length() && s.charAt(i) == '.') {
                i++;
                if (i >= s.length() || !isDigit(s.charAt(i))) throw error("invalid number (digit expected after '.')");
                while (i < s.length() && isDigit(s.charAt(i))) i++;
            }
            if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                i++;
                if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) i++;
                if (i >= s.length() || !isDigit(s.charAt(i))) throw error("invalid number (digit expected in exponent)");
                while (i < s.length() && isDigit(s.charAt(i))) i++;
            }
            n.end = i;
            return n;
        }
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    private static boolean isWs(char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    }

    private static String printable(char c) {
        if (c == '\n') return "\\n";
        if (c == '\t') return "\\t";
        if (c < 0x20) return String.format("\\u%04x", (int) c);
        return String.valueOf(c);
    }

    /** Minified form of a parsed value (tokens verbatim). */
    public static String minify(Node n) {
        StringBuilder sb = new StringBuilder();
        minify(n, sb);
        return sb.toString();
    }

    private static void minify(Node n, StringBuilder sb) {
        switch (n.type) {
            case OBJECT, ARRAY -> {
                boolean obj = n.type == Type.OBJECT;
                sb.append(obj ? '{' : '[');
                for (int i = 0; i < n.values.size(); i++) {
                    if (i > 0) sb.append(',');
                    if (obj) sb.append(n.keys.get(i).raw()).append(':');
                    minify(n.values.get(i), sb);
                }
                sb.append(obj ? '}' : ']');
            }
            default -> sb.append(n.raw());
        }
    }

    /** Minifies JSON text, validating it. */
    public static String minify(String json) throws EncodeException {
        return minify(parse(json));
    }

    // =================================================================== strings and escaping

    /** Decodes a JSON string token (with quotes). The token must be valid. */
    public static String unquote(String raw) {
        StringBuilder sb = new StringBuilder(raw.length());
        int end = raw.length() - 1;
        for (int i = 1; i < end; i++) {
            char c = raw.charAt(i);
            if (c != '\\') {
                sb.append(c);
                continue;
            }
            char e = raw.charAt(++i);
            switch (e) {
                case 'b' -> sb.append('\b');
                case 'f' -> sb.append('\f');
                case 'n' -> sb.append('\n');
                case 'r' -> sb.append('\r');
                case 't' -> sb.append('\t');
                case 'u' -> {
                    sb.append((char) Integer.parseInt(raw.substring(i + 1, i + 5), 16));
                    i += 4;
                }
                default -> sb.append(e);
            }
        }
        return sb.toString();
    }

    /** Escaping conventions of a JSON text. */
    public record Style(boolean asciiOnly, boolean escapeSlash, String htmlChars, boolean upperHex) {
        public static final Style PLAIN = new Style(false, false, "", false);
        /** Next.js / React {@code htmlEscapeJsonString}: &lt; &gt; &amp; U+2028 U+2029. */
        public static final Style HTML_SAFE = new Style(false, false, "<>&", false);

        /** Detects the conventions from escapes present in {@code json} (default: plain JSON.stringify style). */
        public static Style detect(String json) {
            boolean rawNonAscii = false, escNonAscii = false, slash = false, upper = false, lower = false;
            StringBuilder html = new StringBuilder();
            for (int i = 0; i < json.length(); i++) {
                char c = json.charAt(i);
                if (c >= 0x80) rawNonAscii = true;
                if (c != '\\' || i + 1 >= json.length()) continue;
                char e = json.charAt(++i);
                if (e == '/') slash = true;
                if (e == 'u' && i + 4 < json.length()) {
                    String hex = json.substring(i + 1, i + 5);
                    int v;
                    try {
                        v = Integer.parseInt(hex, 16);
                    } catch (NumberFormatException x) {
                        continue;
                    }
                    if (!hex.equals(hex.toLowerCase(Locale.ROOT))) upper = true;
                    if (!hex.equals(hex.toUpperCase(Locale.ROOT))) lower = true;
                    if (v >= 0x80) escNonAscii = true;
                    if ((v == '<' || v == '>' || v == '&') && html.indexOf("<") < 0) html.append("<>&");
                    if ((v == '=' || v == '\'') && html.indexOf(String.valueOf((char) v)) < 0) html.append((char) v);
                    i += 4;
                }
            }
            return new Style(escNonAscii && !rawNonAscii, slash, html.toString(), upper && !lower);
        }

        boolean escapes(char c) {
            return (asciiOnly && c >= 0x80) || (!htmlChars.isEmpty() && (c == 0x2028 || c == 0x2029)) || (c < 0x80 && htmlChars.indexOf(c) >= 0);
        }

        String hex(char c) {
            String h = String.format("%04x", (int) c);
            return "\\u" + (upperHex ? h.toUpperCase(Locale.ROOT) : h);
        }
    }

    /** JSON string token for {@code value} (JSON.stringify escaping plus the style's extra escapes). */
    public static String quote(String value, Style style) {
        StringBuilder sb = new StringBuilder(value.length() + 16).append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c == '/' && style.escapeSlash()) sb.append("\\/");
                    else if (c < 0x20 || style.escapes(c)) sb.append(style.hex(c));
                    else sb.append(c);
                }
            }
        }
        return sb.append('"').toString();
    }

    /** Applies the style's extra escapes to the string tokens of valid JSON text (existing escapes kept). */
    public static String restyle(String json, Style style) {
        if (!style.asciiOnly() && !style.escapeSlash() && style.htmlChars().isEmpty()) return json;
        StringBuilder sb = new StringBuilder(json.length() + 16);
        boolean in = false;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (!in) {
                if (c == '"') in = true;
                sb.append(c);
                continue;
            }
            if (c == '\\') {
                sb.append(c).append(json.charAt(++i));
                continue;
            }
            if (c == '"') {
                in = false;
                sb.append(c);
            } else if (c == '/' && style.escapeSlash()) {
                sb.append("\\/");
            } else if (style.escapes(c)) {
                sb.append(style.hex(c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    public static String splice(String s, int start, int end, String replacement) {
        return s.substring(0, start) + replacement + s.substring(end);
    }

    // =================================================================== URL encoding

    /** JavaScript {@code encodeURIComponent} (UTF-8; leaves {@code A-Za-z0-9-_.!~*'()}). */
    public static String encodeURIComponent(String s) {
        return percentEncode(s, "-_.!~*'()", false);
    }

    /** {@code application/x-www-form-urlencoded} encoding as browsers / URLSearchParams do (space as +). */
    public static String formEncode(String s) {
        return percentEncode(s, "-_.*", true);
    }

    private static String percentEncode(String s, String safe, boolean plus) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder(b.length + 16);
        for (byte x : b) {
            int c = x & 0xff;
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || (c < 0x80 && safe.indexOf(c) >= 0)) {
                sb.append((char) c);
            } else if (c == ' ' && plus) {
                sb.append('+');
            } else {
                sb.append('%').append(Character.toUpperCase(Character.forDigit(c >> 4, 16))).append(Character.toUpperCase(Character.forDigit(c & 15, 16)));
            }
        }
        return sb.toString();
    }

    /**
     * The URL encoder that reproduces {@code originalRaw} from {@code originalDecoded} (encodeURIComponent, form or
     * Java-style encoding), preferring and defaulting to {@code fallback}.
     */
    public static UnaryOperator<String> urlEncoderLike(String originalRaw, String originalDecoded, UnaryOperator<String> fallback) {
        List<UnaryOperator<String>> candidates = List.of(JsonDocuments::encodeURIComponent, JsonDocuments::formEncode,
                s -> formEncode(s).replace("+", "%20"), s -> java.net.URLEncoder.encode(s, StandardCharsets.UTF_8));
        if (originalRaw != null && originalDecoded != null) {
            if (fallback.apply(originalDecoded).equals(originalRaw)) return fallback;
            for (UnaryOperator<String> c : candidates) if (c.apply(originalDecoded).equals(originalRaw)) return c;
            // lowercase hex escapes
            for (UnaryOperator<String> c : candidates) {
                if (lowerHex(c.apply(originalDecoded)).equals(originalRaw)) return s -> lowerHex(c.apply(s));
            }
        }
        return fallback;
    }

    private static String lowerHex(String s) {
        Matcher m = Pattern.compile("%[0-9A-F]{2}").matcher(s);
        StringBuilder sb = new StringBuilder();
        while (m.find()) m.appendReplacement(sb, m.group().toLowerCase(Locale.ROOT));
        m.appendTail(sb);
        return sb.toString();
    }

    /** One {@code name=value} pair of a raw query/form string. */
    public record Param(int index, String rawName, String name, String rawValue, String value) {
    }

    public static List<Param> params(String raw) {
        List<Param> out = new ArrayList<>();
        if (raw == null || raw.isEmpty()) return out;
        String[] pairs = raw.split("&", -1);
        for (int i = 0; i < pairs.length; i++) {
            String p = pairs[i];
            int eq = p.indexOf('=');
            String rn = eq < 0 ? p : p.substring(0, eq);
            String rv = eq < 0 ? "" : p.substring(eq + 1);
            out.add(new Param(i, rn, Codecs.urlDecode(rn), rv, Codecs.urlDecode(rv)));
        }
        return out;
    }

    /** First parameter with this (decoded) name, or null. */
    public static Param param(String raw, String name) {
        for (Param p : params(raw)) if (p.name().equals(name)) return p;
        return null;
    }

    /**
     * Replaces the value of parameter {@code p} (as returned by {@link #params}) with {@code newValue}, encoded like
     * the original value (or with {@code fallback}). Everything else is kept byte-for-byte; an unchanged value keeps its
     * original encoding.
     */
    public static String replaceParam(String raw, Param p, String newValue, UnaryOperator<String> fallback) {
        String[] pairs = raw.split("&", -1);
        String enc = newValue.equals(p.value()) ? p.rawValue() : urlEncoderLike(p.rawValue(), p.value(), fallback).apply(newValue);
        pairs[p.index()] = p.rawName() + "=" + enc;
        return String.join("&", pairs);
    }

    // =================================================================== bodies

    /**
     * The displayed message's body with Content-Encoding (gzip/deflate) undone, and re-encoded the same way on
     * {@link #encode}. Null from {@link #of} when the coding is unsupported or the body is not UTF-8 text.
     */
    public record Body(byte[] raw, byte[] decoded, String coding, String text) {

        public static Body of(MessageContext m) {
            byte[] raw = m.body();
            if (raw == null) raw = new byte[0];
            String ce = m.isWebSocket() ? null : m.header("Content-Encoding");
            String coding = ce == null ? "" : ce.trim().toLowerCase(Locale.ROOT);
            byte[] decoded = raw;
            if (!coding.isEmpty() && !coding.equals("identity")) {
                if (!coding.equals("gzip") && !coding.equals("x-gzip") && !coding.equals("deflate")) return null;
                decoded = Codecs.decodeContent(raw, coding);
                if (decoded == raw && raw.length > 0) return null; // failed to decompress
            } else {
                coding = "";
            }
            if (decoded.length > MAX_TEXT) return null;
            String text = new String(decoded, StandardCharsets.UTF_8);
            if (!Arrays.equals(text.getBytes(StandardCharsets.UTF_8), decoded)) return null;
            return new Body(raw, decoded, coding, text);
        }

        /** Body bytes for new text, compressed like the original (the original bytes when the text is unchanged). */
        public byte[] encode(String newText) throws EncodeException {
            byte[] b = newText.getBytes(StandardCharsets.UTF_8);
            if (Arrays.equals(b, decoded)) return raw;
            if (coding.isEmpty()) return b;
            try {
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                if (coding.contains("gzip")) {
                    try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
                        gz.write(b);
                    }
                } else if (Codecs.isZlib(raw)) {
                    try (DeflaterOutputStream d = new DeflaterOutputStream(bos)) {
                        d.write(b);
                    }
                } else {
                    java.util.zip.Deflater def = new java.util.zip.Deflater(java.util.zip.Deflater.DEFAULT_COMPRESSION, true);
                    try (DeflaterOutputStream d = new DeflaterOutputStream(bos, def)) {
                        d.write(b);
                    } finally {
                        def.end();
                    }
                }
                return bos.toByteArray();
            } catch (IOException e) {
                throw new EncodeException("Could not re-compress the body (" + coding + "): " + e.getMessage(), e);
            }
        }

        public MessagePatch patch(String newText) throws EncodeException {
            return MessagePatch.body(encode(newText));
        }
    }

    // =================================================================== multipart

    /** A multipart/form-data part with its content span (latin-1 offsets into the raw body). */
    public record Part(String name, String filename, String contentType, int contentStart, int contentEnd) {
    }

    private static final Pattern BOUNDARY = Pattern.compile("(?i)boundary=(?:\"([^\"]+)\"|([^;\\s]+))");
    private static final Pattern NAME = Pattern.compile("(?i);\\s*name=(?:\"((?:[^\"\\\\]|\\\\.)*)\"|([^;\\s]+))");
    private static final Pattern FILENAME = Pattern.compile("(?i);\\s*filename=(?:\"((?:[^\"\\\\]|\\\\.)*)\"|([^;\\s]+))");

    public static String boundary(String contentType) {
        if (contentType == null) return null;
        Matcher m = BOUNDARY.matcher(contentType);
        if (!m.find()) return null;
        String b = m.group(1) != null ? m.group(1) : m.group(2);
        return b.isEmpty() ? null : b;
    }

    /** Parts of a multipart body, or null if it doesn't parse. At most 1000 parts. */
    public static List<Part> multipart(byte[] body, String boundary) {
        if (boundary == null || body == null) return null;
        String s = Codecs.latin1String(body);
        String delim = "--" + boundary;
        int i = s.indexOf(delim);
        if (i < 0) return null;
        List<Part> parts = new ArrayList<>();
        while (i >= 0 && parts.size() < 1000) {
            int p = i + delim.length();
            if (s.startsWith("--", p)) return parts;
            int nl = s.indexOf('\n', p);
            if (nl < 0) return null;
            int hdrStart = nl + 1;
            int crlf = s.indexOf("\r\n\r\n", hdrStart);
            int lf = s.indexOf("\n\n", hdrStart);
            int hdrEnd, contentStart;
            if (crlf >= 0 && (lf < 0 || crlf < lf)) {
                hdrEnd = crlf;
                contentStart = crlf + 4;
            } else if (lf >= 0) {
                hdrEnd = lf;
                contentStart = lf + 2;
            } else {
                return null;
            }
            int next = s.indexOf(delim, contentStart);
            if (next < 0) return null;
            int contentEnd = next;
            if (contentEnd >= 2 && s.startsWith("\r\n", contentEnd - 2) && contentEnd - 2 >= contentStart) contentEnd -= 2;
            else if (contentEnd >= 1 && s.charAt(contentEnd - 1) == '\n' && contentEnd - 1 >= contentStart) contentEnd -= 1;
            String name = null, filename = null, ct = null;
            for (String line : s.substring(hdrStart, hdrEnd).split("\r?\n")) {
                String l = line.toLowerCase(Locale.ROOT);
                if (l.startsWith("content-disposition:")) {
                    Matcher nm = NAME.matcher(line);
                    if (nm.find()) name = utf8(nm.group(1) != null ? nm.group(1) : nm.group(2));
                    Matcher fm = FILENAME.matcher(line);
                    if (fm.find()) filename = utf8(fm.group(1) != null ? fm.group(1) : fm.group(2));
                } else if (l.startsWith("content-type:")) {
                    ct = line.substring(13).trim();
                }
            }
            parts.add(new Part(name, filename, ct, contentStart, contentEnd));
            i = next;
        }
        return parts;
    }

    private static String utf8(String latin1) {
        return new String(Codecs.latin1Bytes(latin1), StandardCharsets.UTF_8);
    }

    /** UTF-8 text of a part. */
    public static String partText(byte[] body, Part p) {
        return new String(body, p.contentStart(), p.contentEnd() - p.contentStart(), StandardCharsets.UTF_8);
    }

    /** The body with one part's content replaced; rejects content containing the boundary delimiter. */
    public static byte[] replacePart(byte[] body, Part p, String boundary, String newContent) throws EncodeException {
        byte[] c = newContent.getBytes(StandardCharsets.UTF_8);
        if (Codecs.latin1String(c).contains("--" + boundary)) {
            throw new EncodeException("The edited field contains the multipart boundary \"--" + boundary + "\"; remove it");
        }
        byte[] out = new byte[body.length - (p.contentEnd() - p.contentStart()) + c.length];
        System.arraycopy(body, 0, out, 0, p.contentStart());
        System.arraycopy(c, 0, out, p.contentStart(), c.length);
        System.arraycopy(body, p.contentEnd(), out, p.contentStart() + c.length, body.length - p.contentEnd());
        return out;
    }
}
