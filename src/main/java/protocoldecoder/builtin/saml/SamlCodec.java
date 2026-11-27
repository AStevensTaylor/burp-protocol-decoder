package protocoldecoder.builtin.saml;

import org.w3c.dom.Document;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.edit.EditableDocument;
import protocoldecoder.edit.EncodeException;
import protocoldecoder.edit.MessageCodec;
import protocoldecoder.edit.MessagePatch;
import protocoldecoder.scan.InsertionPoints;
import protocoldecoder.util.Codecs;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.Deflater;
import java.util.zip.GZIPOutputStream;

/**
 * Document editing for SAML / WS-Federation: the XML of SAMLRequest / SAMLResponse (HTTP-Redirect query parameter,
 * HTTP-POST form field, redirect {@code Location} header or an IdP's HTML auto-submit form) and of a WS-Fed
 * {@code wresult}, plus RelayState as plain text.
 *
 * <p>The XML is shown pretty-printed by {@link SafeXml#pretty}. When the text is left as shown, encoding returns the
 * original message unchanged (byte-exact). Otherwise the edited text is checked with {@link SafeXml} (well-formed, no
 * DOCTYPE) and sent <em>exactly as written</em> (not re-serialised), then deflated (raw or zlib, as the original),
 * base64-encoded and form/URL- or HTML-encoded back into the same place. Pretty-printing drops insignificant
 * whitespace and the XML declaration's position is kept, so an edit that changes nothing semantic is still a
 * semantically identical message. A leading "Protocol Decoder:" note comment (signature warning) is removed before
 * encoding.</p>
 */
public final class SamlCodec implements MessageCodec {

    private static final List<String> MESSAGES = List.of("SAMLResponse", "SAMLRequest");
    private static final int MAX_DOCS = 10;
    private static final int MAX_VALUE = 8 * 1024 * 1024;
    static final String NOTE_MARK = "Protocol Decoder:";
    private static final Pattern LEADING_NOTE = Pattern.compile(
            "^(\\s*<\\?xml[^>]*\\?>)?\\s*<!--\\s*" + Pattern.quote(NOTE_MARK) + ".*?-->[ \\t]*\\r?\\n?", Pattern.DOTALL);
    private static final Pattern XML_DECL = Pattern.compile("^\\s*(<\\?xml[^>]*\\?>)");
    private static final Pattern INPUT = Pattern.compile("<input\\b(?:[^>\"']++|\"[^\"]*+\"|'[^']*+')*+>", Pattern.CASE_INSENSITIVE);
    private static final Pattern TAG_ATTR = Pattern.compile(
            "\\b(name|value)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>\"']+))", Pattern.CASE_INSENSITIVE);

    @Override
    public String decoderId() {
        return SamlDecoder.ID;
    }

    /** A parameter value found in the message, and how to put a new raw value back. */
    private record Slot(String name, String value, String where, boolean querySigned, Function<String, MessagePatch> place,
                        MessagePatch original) {
    }

    @Override
    public List<EditableDocument> documents(MessageContext m, DecodeResult decoded) {
        if (decoded == null || m == null || m.isWebSocket()) return List.of();
        List<Slot> slots = new ArrayList<>();
        try {
            if (m.isRequest()) requestSlots(m, slots);
            else responseSlots(m, slots);
        } catch (RuntimeException e) {
            return List.of();
        }
        List<EditableDocument> out = new ArrayList<>();
        Map<String, Integer> titles = new HashMap<>();
        for (Slot s : slots) {
            if (out.size() >= MAX_DOCS) break;
            EditableDocument d = s.name().equals("RelayState") ? new RelayDoc(s) : xmlDoc(s);
            if (d == null) continue;
            int n = titles.merge(d.title(), 1, Integer::sum);
            out.add(n == 1 ? d : renamed(d, d.title() + " #" + n));
        }
        return out;
    }

    // ---------------------------------------------------------------- locating values

    private static final List<String> NAMES = List.of("SAMLResponse", "SAMLRequest", "wresult", "RelayState");

    private static void requestSlots(MessageContext m, List<Slot> out) {
        String q = m.query();
        if (q != null && !q.isEmpty()) {
            boolean signed = SamlDecoder.hasParam(q, "Signature");
            formSlots(q, "query", signed, out, newQuery -> MessagePatch.query(newQuery), MessagePatch.query(q));
        }
        byte[] body = m.requestBody();
        if (body != null && body.length > 0 && body.length <= MAX_VALUE * 2) {
            String b = new String(body, StandardCharsets.ISO_8859_1);
            boolean any = false;
            for (String n : NAMES) any |= SamlDecoder.hasParam(b, n);
            if (any) {
                boolean signed = SamlDecoder.hasParam(b, "Signature");
                formSlots(b, "body", signed, out, nb -> MessagePatch.body(nb.getBytes(StandardCharsets.ISO_8859_1)), MessagePatch.body(body));
            }
        }
    }

    /** Slots for the first occurrence of each interesting parameter in a urlencoded string. */
    private static void formSlots(String container, String where, boolean querySigned, List<Slot> out,
                                  Function<String, MessagePatch> setContainer, MessagePatch original) {
        Map<String, List<String>> params = Codecs.parseQuery(container);
        for (String n : NAMES) {
            String v = Codecs.first(params, n);
            if (v == null || v.length() > MAX_VALUE) continue;
            out.add(new Slot(n, v, where, querySigned && !n.equals("wresult"),
                    nv -> setContainer.apply(InsertionPoints.replaceFormField(container, n, 0, nv)), original));
        }
    }

    private static void responseSlots(MessageContext m, List<Slot> out) {
        String loc = m.responseHeader("Location");
        if (loc != null) {
            int qi = loc.indexOf('?');
            if (qi >= 0) {
                String rest = loc.substring(qi + 1);
                int hash = rest.indexOf('#');
                String query = hash >= 0 ? rest.substring(0, hash) : rest;
                String fragment = hash >= 0 ? rest.substring(hash) : "";
                String base = loc.substring(0, qi + 1);
                formSlots(query, "Location", SamlDecoder.hasParam(query, "Signature"), out,
                        nq -> MessagePatch.header("Location", base + nq + fragment), MessagePatch.header("Location", loc));
                if (!out.isEmpty()) return;
            }
        }
        byte[] raw = m.responseBody();
        if (raw.length == 0) return;
        String ce = m.responseHeader("Content-Encoding");
        byte[] body = Codecs.decodeContent(raw, ce);
        if (body.length > MAX_VALUE * 2) return;
        boolean compressed = body != raw;
        String html = new String(body, StandardCharsets.ISO_8859_1);
        Matcher im = INPUT.matcher(html);
        int count = 0;
        java.util.Set<String> seen = new java.util.HashSet<>();
        while (im.find() && count++ < 500) {
            String tag = im.group();
            String name = null;
            int vStart = -1, vEnd = -1;
            boolean quoted = true;
            char quote = '"';
            String value = "";
            Matcher am = TAG_ATTR.matcher(tag);
            while (am.find()) {
                int g = am.group(2) != null ? 2 : am.group(3) != null ? 3 : 4;
                String v = am.group(g);
                if (am.group(1).equalsIgnoreCase("name")) {
                    name = SamlDecoder.unescapeHtml(latin1ToUtf8(v));
                } else {
                    value = SamlDecoder.unescapeHtml(latin1ToUtf8(v));
                    vStart = am.start(g);
                    vEnd = am.end(g);
                    quoted = g != 4;
                    quote = g == 3 ? '\'' : '"';
                }
            }
            if (name == null || !NAMES.contains(name) || !seen.add(name) || value.length() > MAX_VALUE) continue;
            final int absStart, absEnd;
            final boolean wasQuoted = quoted;
            final char q = quote;
            if (vStart >= 0) {
                absStart = im.start() + vStart;
                absEnd = im.start() + vEnd;
            } else {
                // no value attribute: add one before the closing '>' (or '/>')
                int close = tag.endsWith("/>") ? tag.length() - 2 : tag.length() - 1;
                absStart = absEnd = im.start() + close;
            }
            final boolean addAttr = vStart < 0;
            byte[] original = raw;
            out.add(new Slot(name, value, "HTML form", false, nv -> {
                String escaped = htmlEscape(nv, q);
                String insert = addAttr ? " value=\"" + escaped + "\"" : (wasQuoted ? escaped : "\"" + escaped + "\"");
                byte[] ins = insert.getBytes(StandardCharsets.UTF_8);
                byte[] nb = new byte[body.length - (absEnd - absStart) + ins.length];
                System.arraycopy(body, 0, nb, 0, absStart);
                System.arraycopy(ins, 0, nb, absStart, ins.length);
                System.arraycopy(body, absEnd, nb, absStart + ins.length, body.length - absEnd);
                return MessagePatch.body(compressed ? recompress(nb, raw, ce) : nb);
            }, MessagePatch.body(original)));
        }
    }

    private static String latin1ToUtf8(String s) {
        return new String(s.getBytes(StandardCharsets.ISO_8859_1), StandardCharsets.UTF_8);
    }

    /** HTML attribute escaping ({@code &}, {@code <}, {@code >} and both quote characters). */
    static String htmlEscape(String s, char quote) {
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '&' -> sb.append("&amp;");
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append(quote == '\'' ? "&#39;" : "'");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Re-applies the response's Content-Encoding (gzip, or deflate zlib/raw as the original). */
    private static byte[] recompress(byte[] data, byte[] original, String ce) {
        try {
            if (Codecs.isGzip(original) || (ce != null && ce.toLowerCase(Locale.ROOT).contains("gzip"))) {
                ByteArrayOutputStream bos = new ByteArrayOutputStream(data.length / 2 + 32);
                try (GZIPOutputStream gz = new GZIPOutputStream(bos)) {
                    gz.write(data);
                }
                return bos.toByteArray();
            }
            return deflate(data, !Codecs.isZlib(original));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static byte[] deflate(byte[] in, boolean raw) {
        Deflater d = new Deflater(Deflater.DEFAULT_COMPRESSION, raw);
        try {
            d.setInput(in);
            d.finish();
            ByteArrayOutputStream out = new ByteArrayOutputStream(in.length / 2 + 64);
            byte[] buf = new byte[8192];
            while (!d.finished()) out.write(buf, 0, d.deflate(buf));
            return out.toByteArray();
        } finally {
            d.end();
        }
    }

    // ---------------------------------------------------------------- XML documents

    /** How the XML sits inside the parameter value. */
    private enum Wrap { RAW, BASE64, BASE64_RAW_DEFLATE, BASE64_ZLIB }

    private static EditableDocument xmlDoc(Slot s) {
        String v = s.value();
        Wrap wrap;
        String xml;
        boolean wresult = s.name().equals("wresult");
        if (wresult && v.stripLeading().startsWith("<")) {
            wrap = Wrap.RAW;
            xml = v;
        } else {
            byte[] raw = SamlDecoder.base64(v);
            if (raw == null || raw.length == 0) return null;
            if (looksLikeXml(raw)) {
                wrap = Wrap.BASE64;
                xml = new String(raw, StandardCharsets.UTF_8);
            } else {
                if (wresult) return null;
                try {
                    byte[] inflated = Codecs.inflate(raw);
                    if (!looksLikeXml(inflated)) return null;
                    wrap = Codecs.isZlib(raw) ? Wrap.BASE64_ZLIB : Wrap.BASE64_RAW_DEFLATE;
                    xml = new String(inflated, StandardCharsets.UTF_8);
                } catch (IOException e) {
                    return null;
                }
            }
        }
        if (xml.length() > SafeXml.MAX_XML_CHARS) return null;
        Document doc;
        try {
            doc = SafeXml.parse(xml);
        } catch (SafeXml.XmlException e) {
            return null; // not parsed: nothing to offer
        }
        int sigs = SafeXml.descendants(doc.getDocumentElement(), SamlAnalyzer.DS, "Signature").size();
        Matcher decl = XML_DECL.matcher(xml);
        String body = (decl.find() ? decl.group(1) + "\n" : "") + SafeXml.pretty(doc);
        String note = note(s, sigs);
        String text = note == null ? body : insertNote(body, note);
        String title = (sigs > 0 || s.querySigned() ? "(signed) " : "") + s.name() + " (XML)";
        return new XmlDoc(title, text, body, s, wrap);
    }

    private static String note(Slot s, int sigs) {
        List<String> parts = new ArrayList<>();
        if (sigs > 0) {
            parts.add("this " + s.name() + " carries " + (sigs == 1 ? "an XML signature" : sigs + " XML signatures")
                    + ". Any edit invalidates " + (sigs == 1 ? "it" : "them") + ": the receiver will reject the message unless it"
                    + " does not verify signatures (which is what you are testing).");
        }
        if (s.querySigned()) {
            parts.add("the HTTP-Redirect query string is signed (Signature / SigAlg parameters). Editing breaks that"
                    + " signature; it is not recomputed.");
        }
        if (parts.isEmpty()) return null;
        return "<!-- " + NOTE_MARK + " " + String.join(" Also, ", parts).replace("--", "- -")
                + " This comment is removed when the message is encoded. -->";
    }

    private static String insertNote(String body, String note) {
        if (body.startsWith("<?xml")) {
            int nl = body.indexOf('\n');
            return body.substring(0, nl + 1) + note + "\n" + body.substring(nl + 1);
        }
        return note + "\n" + body;
    }

    /** Removes the leading note comment (keeping an XML declaration in front of it). */
    static String stripNote(String text) {
        Matcher m = LEADING_NOTE.matcher(text);
        if (!m.find()) return text;
        String decl = m.group(1) == null ? "" : m.group(1).strip() + "\n";
        return decl + text.substring(m.end());
    }

    private static boolean looksLikeXml(byte[] b) {
        int i = 0;
        if (b.length >= 3 && (b[0] & 0xff) == 0xEF && (b[1] & 0xff) == 0xBB && (b[2] & 0xff) == 0xBF) i = 3;
        while (i < b.length && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t')) i++;
        return i < b.length && b[i] == '<';
    }

    private static final class XmlDoc implements EditableDocument {
        private final String title;
        private final String text;
        private final String body;
        private final Slot slot;
        private final Wrap wrap;

        XmlDoc(String title, String text, String body, Slot slot, Wrap wrap) {
            this.title = title;
            this.text = text;
            this.body = body;
            this.slot = slot;
            this.wrap = wrap;
        }

        @Override public String title() { return title; }
        @Override public String syntax() { return "xml"; }
        @Override public String text() { return text; }

        @Override
        public MessagePatch encode(String editedText) throws EncodeException {
            if (editedText == null) throw new EncodeException("No XML to encode");
            String xml = stripNote(editedText).strip();
            if (xml.equals(body.strip())) return slot.original();
            if (xml.isEmpty()) throw new EncodeException(slot.name() + ": the XML document is empty");
            try {
                SafeXml.parse(xml);
            } catch (SafeXml.XmlException e) {
                throw new EncodeException(slot.name() + ": " + (e.doctype
                        ? "DOCTYPE declarations are not allowed (the editor refuses to build XXE / entity-expansion payloads from this view)"
                        : e.getMessage()));
            }
            byte[] b = xml.getBytes(StandardCharsets.UTF_8);
            String value = switch (wrap) {
                case RAW -> xml;
                case BASE64 -> Codecs.base64Encode(b);
                case BASE64_RAW_DEFLATE -> Codecs.base64Encode(deflate(b, true));
                case BASE64_ZLIB -> Codecs.base64Encode(deflate(b, false));
            };
            try {
                return slot.place().apply(value);
            } catch (RuntimeException e) {
                throw new EncodeException(slot.name() + ": could not rebuild the message: " + e.getMessage(), e);
            }
        }
    }

    private static final class RelayDoc implements EditableDocument {
        private final Slot slot;

        RelayDoc(Slot slot) {
            this.slot = slot;
        }

        @Override public String title() { return (slot.querySigned() ? "(signed) " : "") + "RelayState"; }
        @Override public String text() { return slot.value(); }

        @Override
        public MessagePatch encode(String editedText) throws EncodeException {
            if (editedText == null) throw new EncodeException("No RelayState to encode");
            if (editedText.equals(slot.value())) return slot.original();
            try {
                return slot.place().apply(editedText);
            } catch (RuntimeException e) {
                throw new EncodeException("RelayState: could not rebuild the message: " + e.getMessage(), e);
            }
        }
    }

    private static EditableDocument renamed(EditableDocument d, String title) {
        return new EditableDocument() {
            @Override public String title() { return title; }
            @Override public String syntax() { return d.syntax(); }
            @Override public String text() { return d.text(); }
            @Override public MessagePatch encode(String editedText) throws EncodeException { return d.encode(editedText); }
        };
    }
}
