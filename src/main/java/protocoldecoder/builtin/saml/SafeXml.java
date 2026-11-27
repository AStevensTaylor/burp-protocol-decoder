package protocoldecoder.builtin.saml;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

/**
 * Hardened DOM parsing plus small DOM helpers and a comment-preserving pretty printer.
 *
 * <p>The parser refuses any DOCTYPE (which rules out XXE and entity-expansion bombs outright), never loads external
 * DTDs, schemas or entities, has XInclude off and runs with secure processing on. It never touches the network or
 * the file system.</p>
 */
final class SafeXml {

    /** Largest XML document we are willing to parse (characters). */
    static final int MAX_XML_CHARS = 4 * 1024 * 1024;
    /** Largest number of elements in a parsed document. */
    static final int MAX_ELEMENTS = 20_000;

    private SafeXml() {
    }

    /** Thrown when the XML is refused or malformed. The message is user-facing. */
    static final class XmlException extends Exception {
        final boolean doctype;

        XmlException(String message, boolean doctype, Throwable cause) {
            super(message, cause);
            this.doctype = doctype;
        }
    }

    static DocumentBuilderFactory hardenedFactory() {
        // newDefaultInstance: always the JDK's built-in implementation, whatever else is on Burp's classpath.
        DocumentBuilderFactory f = DocumentBuilderFactory.newDefaultInstance();
        try {
            f.setNamespaceAware(true);
            f.setValidating(false);
            f.setXIncludeAware(false);
            f.setExpandEntityReferences(false);
            f.setIgnoringComments(false);
            f.setCoalescing(false);
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setFeature("http://xml.org/sax/features/external-general-entities", false);
            f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (ParserConfigurationException | IllegalArgumentException e) {
            // Fail closed: never parse with a parser we could not harden.
            throw new IllegalStateException("cannot configure a hardened XML parser", e);
        }
        return f;
    }

    static Document parse(String xml) throws XmlException {
        if (xml == null || xml.isBlank()) throw new XmlException("empty XML", false, null);
        if (xml.length() > MAX_XML_CHARS) throw new XmlException("XML too large (" + xml.length() + " chars, limit " + MAX_XML_CHARS + ")", false, null);
        String s = xml.charAt(0) == '﻿' ? xml.substring(1) : xml;
        try {
            DocumentBuilder b = hardenedFactory().newDocumentBuilder();
            b.setEntityResolver((publicId, systemId) -> {
                throw new SAXException("external entity resolution is disabled (" + systemId + ")");
            });
            b.setErrorHandler(new ErrorHandler() {
                @Override public void warning(SAXParseException e) { }
                @Override public void error(SAXParseException e) throws SAXException { throw e; }
                @Override public void fatalError(SAXParseException e) throws SAXException { throw e; }
            });
            Document d = b.parse(new InputSource(new StringReader(s.strip())));
            int n = d.getElementsByTagName("*").getLength();
            if (n > MAX_ELEMENTS) throw new XmlException("XML has too many elements (" + n + ", limit " + MAX_ELEMENTS + ")", false, null);
            return d;
        } catch (SAXException e) {
            String msg = e.getMessage() == null ? e.toString() : e.getMessage();
            boolean doctype = msg.toUpperCase().contains("DOCTYPE");
            if (doctype) {
                throw new XmlException("XML contains a DOCTYPE declaration, refused (XXE / entity expansion protection)", true, e);
            }
            throw new XmlException("malformed XML: " + msg, false, e);
        } catch (IOException | ParserConfigurationException e) {
            throw new XmlException("cannot parse XML: " + e.getMessage(), false, e);
        }
    }

    // ---------------------------------------------------------------- DOM helpers

    static List<Element> children(Element e, String local) {
        List<Element> out = new ArrayList<>();
        if (e == null) return out;
        for (Node c = e.getFirstChild(); c != null; c = c.getNextSibling()) {
            if (c instanceof Element ce && (local == null || local.equals(ce.getLocalName()))) out.add(ce);
        }
        return out;
    }

    static Element child(Element e, String local) {
        if (e == null) return null;
        for (Node c = e.getFirstChild(); c != null; c = c.getNextSibling()) {
            if (c instanceof Element ce && local.equals(ce.getLocalName())) return ce;
        }
        return null;
    }

    /** Follows a path of local names through first-match children. */
    static Element path(Element e, String... locals) {
        Element cur = e;
        for (String l : locals) {
            cur = child(cur, l);
            if (cur == null) return null;
        }
        return cur;
    }

    static List<Element> descendants(Element e, String local) {
        List<Element> out = new ArrayList<>();
        if (e == null) return out;
        NodeList nl = e.getElementsByTagNameNS("*", local);
        for (int i = 0; i < nl.getLength(); i++) out.add((Element) nl.item(i));
        return out;
    }

    static List<Element> descendants(Element e, String ns, String local) {
        List<Element> out = new ArrayList<>();
        if (e == null) return out;
        NodeList nl = e.getElementsByTagNameNS(ns, local);
        for (int i = 0; i < nl.getLength(); i++) out.add((Element) nl.item(i));
        return out;
    }

    static Element firstDescendant(Element e, String local) {
        if (e == null) return null;
        NodeList nl = e.getElementsByTagNameNS("*", local);
        return nl.getLength() == 0 ? null : (Element) nl.item(0);
    }

    static String text(Element e) {
        if (e == null) return null;
        String t = e.getTextContent();
        return t == null ? null : t.strip();
    }

    /** Attribute value, or null when the attribute is absent. */
    static String attr(Element e, String name) {
        if (e == null) return null;
        Attr a = e.getAttributeNode(name);
        return a == null ? null : a.getValue();
    }

    /** "/Response/Assertion" style path of local names. */
    static String locate(Element e) {
        StringBuilder sb = new StringBuilder();
        for (Node n = e; n instanceof Element el; n = n.getParentNode()) {
            sb.insert(0, "/" + el.getLocalName());
        }
        return sb.toString();
    }

    // ---------------------------------------------------------------- pretty printing

    /** Pretty-prints a document, keeping comments (they matter for NameID comment-truncation attacks). */
    static String pretty(Document d) {
        StringBuilder sb = new StringBuilder();
        int[] budget = {MAX_ELEMENTS};
        for (Node c = d.getFirstChild(); c != null; c = c.getNextSibling()) write(sb, c, 0, budget);
        return sb.toString().stripTrailing();
    }

    private static void write(StringBuilder sb, Node n, int depth, int[] budget) {
        switch (n.getNodeType()) {
            case Node.ELEMENT_NODE -> {
                if (budget[0]-- <= 0) {
                    if (budget[0] == -1) indent(sb, depth).append("<!-- … output truncated … -->\n");
                    return;
                }
                indent(sb, depth).append('<').append(n.getNodeName());
                NamedNodeMap attrs = n.getAttributes();
                for (int i = 0; i < attrs.getLength(); i++) {
                    Node a = attrs.item(i);
                    sb.append(' ').append(a.getNodeName()).append("=\"").append(escape(a.getNodeValue(), true)).append('"');
                }
                if (!n.hasChildNodes()) {
                    sb.append("/>\n");
                    return;
                }
                boolean simple = true;
                for (Node c = n.getFirstChild(); c != null; c = c.getNextSibling()) {
                    short t = c.getNodeType();
                    if (t != Node.TEXT_NODE && t != Node.CDATA_SECTION_NODE) {
                        simple = false;
                        break;
                    }
                }
                if (simple) {
                    sb.append('>');
                    for (Node c = n.getFirstChild(); c != null; c = c.getNextSibling()) inline(sb, c);
                    sb.append("</").append(n.getNodeName()).append(">\n");
                    return;
                }
                sb.append(">\n");
                for (Node c = n.getFirstChild(); c != null; c = c.getNextSibling()) write(sb, c, depth + 1, budget);
                indent(sb, depth).append("</").append(n.getNodeName()).append(">\n");
            }
            case Node.TEXT_NODE -> {
                String t = n.getNodeValue().strip();
                if (!t.isEmpty()) indent(sb, depth).append(escape(t, false)).append('\n');
            }
            case Node.CDATA_SECTION_NODE -> indent(sb, depth).append("<![CDATA[").append(n.getNodeValue()).append("]]>\n");
            case Node.COMMENT_NODE -> indent(sb, depth).append("<!--").append(n.getNodeValue()).append("-->\n");
            case Node.PROCESSING_INSTRUCTION_NODE -> indent(sb, depth).append("<?").append(n.getNodeName()).append(' ')
                    .append(n.getNodeValue()).append("?>\n");
            default -> {
                // entity references etc. cannot occur (no DOCTYPE)
            }
        }
    }

    private static void inline(StringBuilder sb, Node c) {
        if (c.getNodeType() == Node.CDATA_SECTION_NODE) sb.append("<![CDATA[").append(c.getNodeValue()).append("]]>");
        else sb.append(escape(c.getNodeValue().strip(), false));
    }

    private static StringBuilder indent(StringBuilder sb, int depth) {
        for (int i = 0; i < depth; i++) sb.append("  ");
        return sb;
    }

    static String escape(String s, boolean attr) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '&' -> sb.append("&amp;");
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '"' -> sb.append(attr ? "&quot;" : "\"");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }
}
