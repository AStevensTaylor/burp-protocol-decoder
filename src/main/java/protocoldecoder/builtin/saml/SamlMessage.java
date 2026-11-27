package protocoldecoder.builtin.saml;

import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import protocoldecoder.core.MessageContext;
import protocoldecoder.scan.InsertionPoints;
import protocoldecoder.util.Codecs;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.zip.Deflater;

/**
 * A SAMLRequest / SAMLResponse carried by a request (HTTP-POST form field or HTTP-Redirect query parameter), with what
 * is needed to put a modified XML document back in exactly the same encoding: base64, optional DEFLATE (raw or
 * zlib-wrapped, as the original), then form/URL encoding into the same parameter. Other parameters are kept verbatim.
 *
 * <p>The XML is always parsed with {@link SafeXml} (no DOCTYPE accepted) and written back with
 * {@link #serialize(Node)}, which never emits a DOCTYPE or entity declarations.</p>
 */
final class SamlMessage {

    enum Location { BODY, QUERY }

    final String param;
    final Location location;
    /** 0 = not compressed, 1 = raw DEFLATE, 2 = zlib-wrapped DEFLATE. */
    final int deflate;
    final String xml;
    private final String container;

    private SamlMessage(String param, Location location, int deflate, String xml, String container) {
        this.param = param;
        this.location = location;
        this.deflate = deflate;
        this.xml = xml;
        this.container = container;
    }

    /** Finds the first SAMLResponse / SAMLRequest in the query string or urlencoded body; null if none decodes to XML. */
    static SamlMessage extract(MessageContext req) {
        if (req == null || !req.isRequest()) return null;
        for (String name : List.of("SAMLResponse", "SAMLRequest")) {
            SamlMessage m = from(name, Location.QUERY, req.query());
            if (m != null) return m;
            String body = req.requestBody() == null ? "" : new String(req.requestBody(), StandardCharsets.ISO_8859_1);
            if (SamlDecoder.hasParam(body, name)) {
                m = from(name, Location.BODY, body);
                if (m != null) return m;
            }
        }
        return null;
    }

    private static SamlMessage from(String name, Location loc, String container) {
        if (container == null || container.isEmpty() || !SamlDecoder.hasParam(container, name)) return null;
        Map<String, List<String>> params = Codecs.parseQuery(container);
        String value = Codecs.first(params, name);
        if (value == null || value.length() > 8 * 1024 * 1024) return null;
        byte[] raw = SamlDecoder.base64(value);
        if (raw == null || raw.length == 0) return null;
        if (looksLikeXml(raw)) return new SamlMessage(name, loc, 0, new String(raw, StandardCharsets.UTF_8), container);
        try {
            byte[] inflated = Codecs.inflate(raw);
            if (looksLikeXml(inflated)) {
                return new SamlMessage(name, loc, Codecs.isZlib(raw) ? 2 : 1, new String(inflated, StandardCharsets.UTF_8), container);
            }
        } catch (IOException ignored) {
            // not deflate
        }
        return null;
    }

    private static boolean looksLikeXml(byte[] b) {
        int i = 0;
        if (b.length >= 3 && (b[0] & 0xff) == 0xEF && (b[1] & 0xff) == 0xBB && (b[2] & 0xff) == 0xBF) i = 3;
        while (i < b.length && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t')) i++;
        return i < b.length && b[i] == '<';
    }

    boolean redirectBinding() {
        return location == Location.QUERY;
    }

    Document parse() throws SafeXml.XmlException {
        return SafeXml.parse(xml);
    }

    /** base64( [deflate]( UTF-8 xml ) ), as the original. */
    String encode(String newXml) {
        byte[] b = newXml.getBytes(StandardCharsets.UTF_8);
        if (deflate != 0) b = deflate(b, deflate == 1);
        return Codecs.base64Encode(b);
    }

    /** The whole new query string or body (same part as the original) carrying {@code newXml}. */
    String rebuild(String newXml) {
        return InsertionPoints.replaceFormField(container, param, 0, encode(newXml));
    }

    byte[] rebuildBytes(String newXml) {
        return rebuild(newXml).getBytes(StandardCharsets.ISO_8859_1);
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

    // ---------------------------------------------------------------- serialisation

    /** Compact XML serialisation of a parsed document or element: no XML declaration, no DOCTYPE, comments kept. */
    static String serialize(Node n) {
        StringBuilder sb = new StringBuilder();
        if (n instanceof Document d) {
            for (Node c = d.getFirstChild(); c != null; c = c.getNextSibling()) write(sb, c);
        } else {
            write(sb, n);
        }
        return sb.toString();
    }

    private static void write(StringBuilder sb, Node n) {
        switch (n.getNodeType()) {
            case Node.ELEMENT_NODE -> {
                sb.append('<').append(n.getNodeName());
                NamedNodeMap attrs = n.getAttributes();
                for (int i = 0; i < attrs.getLength(); i++) {
                    Node a = attrs.item(i);
                    sb.append(' ').append(a.getNodeName()).append("=\"");
                    escape(sb, a.getNodeValue(), true);
                    sb.append('"');
                }
                if (!n.hasChildNodes()) {
                    sb.append("/>");
                    return;
                }
                sb.append('>');
                for (Node c = n.getFirstChild(); c != null; c = c.getNextSibling()) write(sb, c);
                sb.append("</").append(n.getNodeName()).append('>');
            }
            case Node.TEXT_NODE -> escape(sb, n.getNodeValue(), false);
            case Node.CDATA_SECTION_NODE -> {
                // Split "]]>" so arbitrary content stays well-formed.
                sb.append("<![CDATA[").append(n.getNodeValue().replace("]]>", "]]]]><![CDATA[>")).append("]]>");
            }
            case Node.COMMENT_NODE -> sb.append("<!--").append(n.getNodeValue()).append("-->");
            case Node.PROCESSING_INSTRUCTION_NODE -> sb.append("<?").append(n.getNodeName()).append(' ').append(n.getNodeValue()).append("?>");
            default -> {
                // DocumentType / entity nodes cannot occur (SafeXml refuses DOCTYPE) and are never written.
            }
        }
    }

    static void escape(StringBuilder sb, String s, boolean attr) {
        if (s == null) return;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '&' -> sb.append("&amp;");
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '"' -> sb.append(attr ? "&quot;" : "\"");
                case '\r' -> sb.append("&#13;");
                case '\t' -> sb.append(attr ? "&#9;" : "\t");
                case '\n' -> sb.append(attr ? "&#10;" : "\n");
                default -> sb.append(c);
            }
        }
    }
}
