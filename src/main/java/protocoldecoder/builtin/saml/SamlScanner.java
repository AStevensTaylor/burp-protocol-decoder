package protocoldecoder.builtin.saml;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.scan.ActiveCheck;
import protocoldecoder.scan.ActiveContext;
import protocoldecoder.scan.Confidence;
import protocoldecoder.scan.Exchange;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.InsertionPoint;
import protocoldecoder.scan.InsertionPoints;
import protocoldecoder.scan.PassiveCheck;
import protocoldecoder.scan.ProtocolScanner;
import protocoldecoder.scan.Severity;
import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static protocoldecoder.builtin.saml.SafeXml.attr;
import static protocoldecoder.builtin.saml.SafeXml.child;
import static protocoldecoder.builtin.saml.SafeXml.descendants;
import static protocoldecoder.builtin.saml.SafeXml.text;

/**
 * Scanner support for SAML (HTTP-POST / HTTP-Redirect bindings): passive posture checks on captured messages,
 * insertion points inside the XML (re-serialised, re-deflated, re-base64'd), and a bounded differential test of
 * signature enforcement at the assertion consumer service.
 *
 * <p>Not done (too invasive for a default check, left for future work): XML Signature Wrapping permutations, XXE /
 * XSLT-transform injection, comment-truncation NameID probes.</p>
 */
public final class SamlScanner implements ProtocolScanner {

    @Override
    public String decoderId() {
        return SamlDecoder.ID;
    }

    @Override
    public List<PassiveCheck> passiveChecks() {
        return List.of(new UnsignedAssertion(), new Sha1Signature(), new WrappingIndicators(), new WeakConditions(),
                new WeakEncryption(), new NameIdComment(), new RelayStateUrl(), new ResponseViaGet());
    }

    @Override
    public List<ActiveCheck> activeChecks() {
        return List.of(new SignatureEnforcement());
    }

    // ================================================================== analysis

    static final String[] ID_ATTRS = {"ID", "Id", "AssertionID", "ResponseID", "RequestID"};

    /** Parsed message plus signature coverage. */
    static final class Analysis {
        final SamlMessage message;
        final Document doc;
        final Element root;
        final Element msg;
        final String local;
        final List<Element> assertions = new ArrayList<>();
        final List<Element> encrypted;
        final List<Element> signatures;
        final Map<String, List<Element>> ids = new LinkedHashMap<>();
        final Set<Element> signed = Collections.newSetFromMap(new IdentityHashMap<>());
        final List<String> wrapping = new ArrayList<>();
        final String querySigAlg;
        final boolean querySigned;
        final String issuer;

        private Analysis(SamlMessage message, Document doc, String querySigAlg, boolean querySigned) {
            this.message = message;
            this.doc = doc;
            this.root = doc.getDocumentElement();
            this.msg = SamlAnalyzer.unwrap(root);
            this.local = msg.getLocalName() == null ? msg.getNodeName() : msg.getLocalName();
            this.querySigAlg = querySigAlg;
            this.querySigned = querySigned;
            assertions.addAll(descendants(root, SamlAnalyzer.SAML2, "Assertion"));
            assertions.addAll(descendants(root, SamlAnalyzer.SAML1, "Assertion"));
            if (assertions.isEmpty() && "Assertion".equals(root.getLocalName())) assertions.add(root);
            encrypted = descendants(root, "EncryptedAssertion");
            signatures = descendants(root, SamlAnalyzer.DS, "Signature");
            indexIds();
            resolveSignatures();
            String iss = text(child(msg, "Issuer"));
            if (iss == null && !assertions.isEmpty()) {
                Element a = assertions.get(0);
                iss = SamlAnalyzer.SAML1.equals(a.getNamespaceURI()) ? attr(a, "Issuer") : text(child(a, "Issuer"));
            }
            this.issuer = iss;
            if (assertions.size() > 1) wrapping.add(assertions.size() + " assertions in one message");
            for (Element a : assertions) {
                Node p = a.getParentNode();
                String pn = p instanceof Element pe ? pe.getLocalName() : null;
                if (p instanceof Element && !"Response".equals(pn) && !"RequestedSecurityToken".equals(pn)) {
                    wrapping.add("Assertion at unusual location " + SafeXml.locate(a));
                }
            }
        }

        static Analysis of(MessageContext req) {
            SamlMessage m = SamlMessage.extract(req);
            if (m == null) return null;
            try {
                Document d = m.parse();
                String sigAlg = null;
                boolean qs = false;
                if (m.redirectBinding()) {
                    Map<String, List<String>> q = Codecs.parseQuery(req.query());
                    sigAlg = Codecs.first(q, "SigAlg");
                    String s = Codecs.first(q, "Signature");
                    qs = s != null && !s.isBlank();
                }
                return new Analysis(m, d, sigAlg, qs);
            } catch (SafeXml.XmlException | RuntimeException e) {
                return null;
            }
        }

        private void indexIds() {
            NodeList all = doc.getElementsByTagName("*");
            for (int i = 0; i < all.getLength(); i++) {
                Element e = (Element) all.item(i);
                NamedNodeMap attrs = e.getAttributes();
                for (int j = 0; j < attrs.getLength(); j++) {
                    Attr a = (Attr) attrs.item(j);
                    String l = a.getLocalName() == null ? a.getName() : a.getLocalName();
                    for (String id : ID_ATTRS) {
                        if (l.equals(id) && (a.getNamespaceURI() == null || l.equals("Id"))) {
                            ids.computeIfAbsent(a.getValue(), x -> new ArrayList<>()).add(e);
                            break;
                        }
                    }
                }
            }
            for (Map.Entry<String, List<Element>> en : ids.entrySet()) {
                if (en.getValue().size() > 1) wrapping.add("ID \"" + en.getKey() + "\" is used by " + en.getValue().size() + " elements");
            }
        }

        private void resolveSignatures() {
            int i = 0;
            for (Element sig : signatures) {
                i++;
                Element parent = sig.getParentNode() instanceof Element pe ? pe : null;
                for (Element ref : SafeXml.children(child(sig, "SignedInfo"), "Reference")) {
                    String uri = attr(ref, "URI");
                    Element target = null;
                    if (uri == null || uri.isEmpty()) target = root;
                    else if (uri.startsWith("#")) {
                        List<Element> hits = ids.get(uri.substring(1));
                        if (hits != null && !hits.isEmpty()) target = hits.get(0);
                    }
                    if (target == null) {
                        wrapping.add("Signature #" + i + " reference " + uri + " does not resolve to any element");
                    } else {
                        signed.add(target);
                        if (parent != null && target != parent && target != root) {
                            wrapping.add("Signature #" + i + " sits in " + parent.getLocalName() + " but references " + target.getLocalName()
                                    + " (" + uri + ")");
                        }
                    }
                }
            }
        }

        /** True if the element or one of its ancestors is referenced by a ds:Signature (or the redirect query is signed). */
        boolean covered(Element e) {
            if (querySigned) return true;
            for (Node n = e; n instanceof Element el; n = n.getParentNode()) if (signed.contains(el)) return true;
            return false;
        }

        boolean isResponse() {
            String ns = msg.getNamespaceURI() == null ? "" : msg.getNamespaceURI();
            return "Response".equals(local) && (ns.equals(SamlAnalyzer.SAML2P) || ns.equals(SamlAnalyzer.SAML1P));
        }

        String who() {
            return issuer == null ? "" : " issued by <code>" + Finding.esc(issuer) + "</code>";
        }
    }

    private static Finding issue(String id, String title, Severity s, Confidence c) {
        return Finding.of(id, title).severity(s).confidence(c);
    }

    private static String list(List<String> items) {
        StringBuilder sb = new StringBuilder("<ul>");
        for (String s : items.subList(0, Math.min(items.size(), 20))) sb.append("<li>").append(Finding.esc(s)).append("</li>");
        return sb.append("</ul>").toString();
    }

    // ================================================================== passive checks

    /** Assertion not covered by any signature (neither its own, the Response's, nor a signed redirect query). */
    static final class UnsignedAssertion implements PassiveCheck {
        @Override public String id() { return "saml.unsigned-assertion"; }
        @Override public String name() { return "Unsigned SAML assertion"; }
        @Override public String description() { return "SAML Response carrying an assertion that no XML signature covers"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            Analysis a = m.isRequest() ? Analysis.of(m) : null;
            if (a == null || !a.isResponse() || a.assertions.isEmpty()) return List.of();
            int unsigned = 0;
            for (Element as : a.assertions) if (!a.covered(as)) unsigned++;
            if (unsigned == 0) return List.of();
            return List.of(issue(id(), "Unsigned SAML assertion", Severity.MEDIUM, Confidence.TENTATIVE).scope(Finding.Scope.HOST)
                    .detail("The SAML Response" + a.who() + " sent to <code>" + Finding.esc(m.path()) + "</code> contains " + unsigned
                            + " assertion(s) not covered by any XML signature: neither the Assertion nor the enclosing Response is signed.<br>"
                            + "Whether this is exploitable depends on the service provider: if it does not require a signature, anyone can "
                            + "forge an assertion for any user. The active check <i>SAML signature enforcement</i> confirms it.")
                    .background("SAML assertions are bearer tokens. Their integrity relies entirely on the IdP's XML signature over the "
                            + "Assertion or the Response; an SP that accepts unsigned assertions accepts forged identities.")
                    .remediation("Configure the IdP to sign assertions (and preferably responses), and configure the SP to reject "
                            + "assertions that are not covered by a valid signature from the expected IdP key."));
        }
    }

    /** SHA-1 signature or digest algorithms. */
    static final class Sha1Signature implements PassiveCheck {
        @Override public String id() { return "saml.sha1-signature"; }
        @Override public String name() { return "SAML signature uses SHA-1"; }
        @Override public String description() { return "ds:SignatureMethod / DigestMethod or redirect-binding SigAlg using SHA-1"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            Analysis a = m.isRequest() ? Analysis.of(m) : null;
            if (a == null) return List.of();
            Set<String> algs = new TreeSet<>();
            for (Element sig : a.signatures) {
                Element si = child(sig, "SignedInfo");
                String sm = attr(child(si, "SignatureMethod"), "Algorithm");
                if (SamlAnalyzer.isSha1(sm)) algs.add(sm);
                for (Element ref : SafeXml.children(si, "Reference")) {
                    String dm = attr(child(ref, "DigestMethod"), "Algorithm");
                    if (SamlAnalyzer.isSha1(dm)) algs.add(dm);
                }
            }
            if (a.querySigned && SamlAnalyzer.isSha1(a.querySigAlg)) algs.add(a.querySigAlg);
            if (algs.isEmpty()) return List.of();
            Finding f = issue(id(), "SAML signature uses SHA-1", Severity.LOW, Confidence.CERTAIN).scope(Finding.Scope.HOST)
                    .detail("The SAML " + Finding.esc(a.local) + a.who() + " is signed with SHA-1 based algorithms:" + list(new ArrayList<>(algs)))
                    .background("SHA-1 is deprecated for digital signatures because practical collision attacks exist. Federation "
                            + "profiles and most IdPs default to RSA-SHA256.")
                    .remediation("Configure the IdP (and SP metadata) to use RSA-SHA256 or stronger for signatures and SHA-256 digests, "
                            + "and have the SP reject SHA-1 signatures.");
            if (a.querySigned && SamlAnalyzer.isSha1(a.querySigAlg)) f.requestEvidence("SigAlg=");
            return List.of(f);
        }
    }

    /** Structures typical of XML Signature Wrapping attacks. */
    static final class WrappingIndicators implements PassiveCheck {
        @Override public String id() { return "saml.xsw-indicators"; }
        @Override public String name() { return "SAML signature wrapping indicators"; }
        @Override public String description() { return "Multiple assertions, duplicate IDs, misplaced assertions or signatures referencing a non-enveloping element"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            Analysis a = m.isRequest() ? Analysis.of(m) : null;
            if (a == null || a.wrapping.isEmpty()) return List.of();
            return List.of(issue(id(), "SAML message structure indicates signature wrapping", Severity.MEDIUM, Confidence.TENTATIVE)
                    .detail("The SAML " + Finding.esc(a.local) + a.who() + " sent to <code>" + Finding.esc(m.path())
                            + "</code> has structural anomalies associated with XML Signature Wrapping (XSW):" + list(a.wrapping)
                            + "If this message was not crafted by the tester, the SP may be under attack or the IdP produces unusual messages; "
                            + "if the SP accepts such a message, check which assertion it actually uses.")
                    .background("In XSW attacks a validly signed element is moved or duplicated so that signature verification succeeds on "
                            + "one element while the application logic reads another, attacker-controlled one.")
                    .remediation("Process only the element that the verified signature references (by node identity, not by re-lookup of "
                            + "the ID), reject documents with duplicate IDs or more than one assertion, and use schema-validated parsing."));
        }
    }

    /** Validity window over 24h, no Conditions, or no AudienceRestriction. */
    static final class WeakConditions implements PassiveCheck {
        static final Duration LONG = Duration.ofHours(24);

        @Override public String id() { return "saml.weak-conditions"; }
        @Override public String name() { return "Weak SAML assertion conditions"; }
        @Override public String description() { return "Assertion validity window over 24 hours, no Conditions, or no AudienceRestriction"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            Analysis a = m.isRequest() ? Analysis.of(m) : null;
            if (a == null || a.assertions.isEmpty()) return List.of();
            List<String> problems = new ArrayList<>();
            int i = 0;
            for (Element as : a.assertions) {
                i++;
                String label = a.assertions.size() > 1 ? "Assertion #" + i + ": " : "";
                Element cond = child(as, "Conditions");
                if (cond == null) {
                    problems.add(label + "no Conditions element (no validity window, not bound to an audience)");
                    continue;
                }
                if (descendants(cond, "Audience").isEmpty()) problems.add(label + "no AudienceRestriction: the assertion is not bound to this SP");
                Instant nb = SamlAnalyzer.time(attr(cond, "NotBefore"));
                Instant noa = SamlAnalyzer.time(attr(cond, "NotOnOrAfter"));
                if (nb != null && noa != null && Duration.between(nb, noa).compareTo(LONG) > 0) {
                    long h = Duration.between(nb, noa).toHours();
                    problems.add(label + "validity window is " + (h >= 48 ? h / 24 + " days" : h + " hours")
                            + " (NotBefore " + attr(cond, "NotBefore") + ", NotOnOrAfter " + attr(cond, "NotOnOrAfter") + ")");
                }
            }
            if (problems.isEmpty()) return List.of();
            return List.of(issue(id(), "Weak SAML assertion conditions", Severity.LOW, Confidence.FIRM).scope(Finding.Scope.HOST)
                    .detail("Assertions" + a.who() + " have weak conditions:" + list(problems))
                    .background("A long validity window extends how long a stolen or logged assertion can be replayed. Without an "
                            + "AudienceRestriction an assertion issued for one service provider can be presented to another one that "
                            + "trusts the same IdP.")
                    .remediation("Issue assertions with a short validity (minutes) and an AudienceRestriction naming the SP entity ID; "
                            + "make the SP enforce both and track assertion IDs to prevent replay."));
        }
    }

    /** EncryptedAssertion using RSA PKCS#1 v1.5 key transport or CBC block mode. */
    static final class WeakEncryption implements PassiveCheck {
        @Override public String id() { return "saml.weak-encryption"; }
        @Override public String name() { return "Weak SAML assertion encryption"; }
        @Override public String description() { return "EncryptedAssertion using RSA PKCS#1 v1.5 key transport or a CBC-mode cipher"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            Analysis a = m.isRequest() ? Analysis.of(m) : null;
            if (a == null || a.encrypted.isEmpty()) return List.of();
            Set<String> weak = new TreeSet<>();
            for (Element ea : a.encrypted) {
                for (Element em : descendants(ea, "EncryptionMethod")) {
                    String alg = attr(em, "Algorithm");
                    if (alg == null) continue;
                    String l = alg.toLowerCase(Locale.ROOT);
                    if (l.endsWith("rsa-1_5")) weak.add(alg + " (RSA PKCS#1 v1.5 key transport)");
                    else if (l.contains("-cbc")) weak.add(alg + " (CBC mode)");
                }
            }
            if (weak.isEmpty()) return List.of();
            return List.of(issue(id(), "Weak SAML assertion encryption", Severity.LOW, Confidence.FIRM).scope(Finding.Scope.HOST)
                    .detail("Encrypted assertions" + a.who() + " use weak algorithms:" + list(new ArrayList<>(weak)))
                    .background("XML Encryption with CBC mode is vulnerable to padding-oracle style attacks (Jager &amp; Somorovsky, 2011) and "
                            + "RSA PKCS#1 v1.5 key transport to Bleichenbacher attacks, when the SP reveals decryption errors.")
                    .remediation("Use AES-GCM (xmlenc11#aes128-gcm / aes256-gcm) for data and RSA-OAEP for key transport."));
        }
    }

    /** XML comments inside a NameID (comment-truncation attack family). */
    static final class NameIdComment implements PassiveCheck {
        @Override public String id() { return "saml.nameid-comment"; }
        @Override public String name() { return "Comment inside SAML NameID"; }
        @Override public String description() { return "NameID containing an XML comment (CVE-2017-11427 comment-truncation family)"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            Analysis a = m.isRequest() ? Analysis.of(m) : null;
            if (a == null) return List.of();
            List<String> hits = new ArrayList<>();
            List<Element> ids = new ArrayList<>(descendants(a.root, "NameID"));
            ids.addAll(descendants(a.root, "NameIdentifier"));
            for (Element nid : ids) {
                String first = null;
                boolean comment = false;
                for (Node c = nid.getFirstChild(); c != null; c = c.getNextSibling()) {
                    if (c.getNodeType() == Node.COMMENT_NODE) comment = true;
                    else if (first == null && (c.getNodeType() == Node.TEXT_NODE || c.getNodeType() == Node.CDATA_SECTION_NODE)) first = c.getNodeValue();
                }
                if (comment) hits.add("full text \"" + nid.getTextContent() + "\", first text node \"" + (first == null ? "" : first) + "\"");
            }
            if (hits.isEmpty()) return List.of();
            return List.of(issue(id(), "XML comment inside SAML NameID", Severity.INFORMATION, Confidence.CERTAIN)
                    .detail("A NameID in the SAML " + Finding.esc(a.local) + " contains an XML comment:" + list(hits)
                            + "If this was not crafted by the tester, check how the SP extracts the NameID.")
                    .background("Comments do not change a canonicalised signature, so an attacker who controls part of a NameID (e.g. "
                            + "registers <code>admin@example.com<!---->.evil.com</code>) gets a validly signed assertion. SAML libraries that "
                            + "read only the first text node then authenticate the attacker as <code>admin@example.com</code> (CVE-2017-11427 and related).")
                    .remediation("Use a SAML library version that reads the full text content of NameID, and reject identities containing comments."));
        }
    }

    private static final Pattern ABSOLUTE_URL = Pattern.compile("(?i)^\\s*(?:https?:)?//[^/\\s]");

    /** RelayState that is an absolute URL (open-redirect candidate after login). */
    static final class RelayStateUrl implements PassiveCheck {
        @Override public String id() { return "saml.relaystate-url"; }
        @Override public String name() { return "SAML RelayState is a URL"; }
        @Override public String description() { return "RelayState carrying an absolute URL: test for open redirect after SSO"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isRequest()) return List.of();
            String relay = Codecs.first(m.queryParameters(), "RelayState");
            if (relay == null) {
                String body = m.requestBody() == null ? "" : new String(m.requestBody(), StandardCharsets.ISO_8859_1);
                if (SamlDecoder.hasParam(body, "RelayState")) relay = Codecs.first(Codecs.parseQuery(body), "RelayState");
            }
            if (relay == null || !ABSOLUTE_URL.matcher(relay).find()) return List.of();
            if (SamlMessage.extract(m) == null) return List.of();
            return List.of(issue(id(), "SAML RelayState contains a URL", Severity.INFORMATION, Confidence.FIRM)
                    .detail("The SAML message to <code>" + Finding.esc(m.path()) + "</code> carries RelayState <code>"
                            + Finding.esc(Codecs.truncate(relay, 300)) + "</code>. If the SP redirects there after login, test whether "
                            + "an external URL is accepted (open redirect, possibly leaking tokens in the URL).")
                    .background("RelayState is opaque state the SP gets back from the IdP. Many SPs use it as the post-login return URL; "
                            + "it is not covered by the assertion signature (and not at all in the POST binding).")
                    .remediation("Store the return URL server-side and put an opaque reference in RelayState, or validate it against an "
                            + "allow-list of same-site paths."));
        }
    }

    /** SAML Response (with assertions) sent in the query string. */
    static final class ResponseViaGet implements PassiveCheck {
        @Override public String id() { return "saml.response-via-get"; }
        @Override public String name() { return "SAML Response in URL"; }
        @Override public String description() { return "Authentication Response (not LogoutResponse) delivered via the HTTP-Redirect binding / query string"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            Analysis a = m.isRequest() ? Analysis.of(m) : null;
            if (a == null || !a.message.redirectBinding() || !"SAMLResponse".equals(a.message.param) || !a.isResponse()) return List.of();
            return List.of(issue(id(), "SAML Response sent in URL", Severity.LOW, Confidence.FIRM)
                    .detail("The SAML authentication Response" + a.who() + " is delivered in the query string of <code>"
                            + Finding.esc(m.path()) + "</code>.")
                    .background("Assertions in URLs end up in browser history, proxy and server logs and Referer headers, where they can be "
                            + "replayed while still valid. SAML profiles require the POST or Artifact binding for authentication responses.")
                    .remediation("Use the HTTP-POST (or Artifact) binding for authentication responses.")
                    .requestEvidence("SAMLResponse="));
        }
    }

    // ================================================================== insertion points

    /** NameID, AttributeValue, Issuer, Destination / ACS URL / Recipient values inside the XML. */
    @Override
    public List<InsertionPoint> insertionPoints(MessageContext request, DecodeResult decoded) {
        List<InsertionPoint> out = new ArrayList<>();
        SamlMessage sm = SamlMessage.extract(request);
        if (sm == null) return out;
        Document doc;
        try {
            doc = sm.parse();
        } catch (SafeXml.XmlException | RuntimeException e) {
            return out;
        }
        Element root = doc.getDocumentElement();
        Element msgElement = SamlAnalyzer.unwrap(root);
        NodeList all = doc.getElementsByTagName("*");
        Map<String, Integer> names = new HashMap<>();
        InsertionPoint.Part part = sm.location == SamlMessage.Location.QUERY ? InsertionPoint.Part.QUERY : InsertionPoint.Part.BODY;
        for (int i = 0; i < all.getLength() && out.size() < InsertionPoints.MAX_POINTS; i++) {
            Element e = (Element) all.item(i);
            String l = e.getLocalName() == null ? e.getNodeName() : e.getLocalName();
            List<String> attrs = new ArrayList<>();
            boolean textTarget = false;
            switch (l) {
                case "NameID", "NameIdentifier", "Issuer", "AttributeValue" -> textTarget = child(e, "EncryptedData") == null && SafeXml.children(e, null).isEmpty();
                case "SubjectConfirmationData" -> attrs.add("Recipient");
                default -> { }
            }
            if (e == msgElement) {
                attrs.add("Destination");
                attrs.add("AssertionConsumerServiceURL");
            }
            if (textTarget) {
                add(out, names, part, sm, i, null, pathName(e, root), text(e) == null ? "" : e.getTextContent());
            }
            for (String at : attrs) {
                if (!e.hasAttribute(at)) continue;
                add(out, names, part, sm, i, at, pathName(e, root) + "@" + at, e.getAttribute(at));
            }
        }
        return out;
    }

    private static void add(List<InsertionPoint> out, Map<String, Integer> names, InsertionPoint.Part part, SamlMessage sm,
                            int index, String attr, String path, String baseValue) {
        int n = names.merge(path, 1, Integer::sum);
        String name = "SAML: " + path + (n > 1 ? " #" + n : "");
        Function<String, byte[]> render = payload -> sm.rebuildBytes(withValue(sm.xml, index, attr, payload == null ? "" : payload));
        out.add(part == InsertionPoint.Part.QUERY ? InsertionPoint.query(name, baseValue, render) : InsertionPoint.body(name, baseValue, render));
    }

    /** Re-parses the original XML (DOM is not thread-safe), sets one element's text or attribute, re-serialises. */
    static String withValue(String xml, int elementIndex, String attr, String value) {
        try {
            Document d = SafeXml.parse(xml);
            Element e = (Element) d.getElementsByTagName("*").item(elementIndex);
            if (e == null) return xml;
            if (attr != null) {
                e.setAttribute(attr, value);
            } else {
                while (e.getFirstChild() != null) e.removeChild(e.getFirstChild());
                e.appendChild(d.createTextNode(value));
            }
            return SamlMessage.serialize(d);
        } catch (SafeXml.XmlException e) {
            return xml;
        }
    }

    /** "Assertion/Subject/NameID", "Assertion/AttributeStatement/Attribute[email]/AttributeValue", or the root name. */
    static String pathName(Element e, Element root) {
        if (e == root) return root.getLocalName();
        List<String> parts = new ArrayList<>();
        for (Node n = e; n instanceof Element el && el != root; n = n.getParentNode()) {
            String l = el.getLocalName();
            if ("Attribute".equals(l)) {
                String an = attr(el, "Name") != null ? attr(el, "Name") : attr(el, "AttributeName");
                if (an != null) l += "[" + an + "]";
            }
            parts.add(0, l);
        }
        return String.join("/", parts);
    }

    // ================================================================== active

    /** How a response looks for the differential comparison. */
    record Outcome(int status, String location, Set<String> cookies, String title, int length) {
        static final Pattern TITLE = Pattern.compile("(?is)<title[^>]*>(.*?)</title>");

        static Outcome of(MessageContext m) {
            int status = m.statusCode() == null ? 0 : m.statusCode();
            String loc = null;
            Set<String> cookies = new TreeSet<>();
            for (Header h : m.responseHeaders()) {
                if (h.name().equalsIgnoreCase("Location")) loc = normalizeLocation(h.value());
                if (h.name().equalsIgnoreCase("Set-Cookie")) {
                    String v = h.value();
                    int eq = v.indexOf('=');
                    if (eq <= 0) continue;
                    String name = v.substring(0, eq).trim();
                    int semi = v.indexOf(';', eq);
                    String val = (semi < 0 ? v.substring(eq + 1) : v.substring(eq + 1, semi)).trim();
                    String lv = v.toLowerCase(Locale.ROOT);
                    boolean deleted = val.isEmpty() || val.equals("\"\"") || lv.contains("max-age=0") || lv.contains("expires=thu, 01 jan 1970")
                            || lv.contains("expires=thu, 01-jan-1970");
                    if (!deleted) cookies.add(name);
                }
            }
            String body = m.responseBodyText();
            Matcher t = TITLE.matcher(body.length() > 200_000 ? body.substring(0, 200_000) : body);
            String title = t.find() ? t.group(1).strip() : null;
            return new Outcome(status, loc, cookies, title, m.responseBody().length);
        }

        /** Keeps scheme/host/path and parameter names; drops parameter values and fragments (state tokens vary). */
        static String normalizeLocation(String loc) {
            if (loc == null) return null;
            String l = loc.strip();
            int hash = l.indexOf('#');
            if (hash >= 0) l = l.substring(0, hash);
            int q = l.indexOf('?');
            if (q < 0) return l;
            StringBuilder sb = new StringBuilder(l.substring(0, q)).append('?');
            for (String p : l.substring(q + 1).split("&")) {
                int eq = p.indexOf('=');
                sb.append(eq < 0 ? p : p.substring(0, eq)).append('&');
            }
            return sb.toString();
        }

        boolean same(Outcome o) {
            if (o == null || status != o.status || !java.util.Objects.equals(location, o.location) || !cookies.equals(o.cookies)) return false;
            if (status >= 200 && status < 300) {
                if (!java.util.Objects.equals(title, o.title)) return false;
                int max = Math.max(length, o.length);
                return Math.abs(length - o.length) <= Math.max(64, max / 10);
            }
            return true;
        }

        String describe() {
            return "HTTP " + status + (location == null ? "" : ", Location " + location) + (cookies.isEmpty() ? "" : ", sets " + String.join(", ", cookies))
                    + (title == null ? "" : ", title \"" + title + "\"");
        }
    }

    /**
     * Differential test of signature enforcement at the ACS, on a request POSTing a signed SAMLResponse:
     * <ol>
     *   <li>replay the unmodified request — if its outcome differs from the captured response the SP rejects replays
     *       (InResponseTo / one-time use / expiry) and nothing can be concluded: stop;</li>
     *   <li>send the Response with every ds:Signature removed;</li>
     *   <li>send it with signatures kept but a signed value changed (assertion IssueInstant minus one second, else the
     *       NameID's first letter case-flipped);</li>
     *   <li>only if 2 or 3 looked accepted: a control with the assertion removed, which every SP must reject. A finding
     *       is reported only when the modified message's outcome matches the replay and differs from the control.</li>
     * </ol>
     * At most 4 requests.
     */
    static final class SignatureEnforcement implements ActiveCheck {
        @Override public String id() { return "saml.signature-enforcement"; }
        @Override public String name() { return "SAML signature enforcement"; }
        @Override public String description() {
            return "For a POSTed, signed SAMLResponse: replays it, then sends it with signatures removed and with a signed value changed, "
                    + "comparing with a control that has no assertion (≤4 requests; skipped if the SP rejects the plain replay)";
        }
        @Override public Scope scope() { return Scope.PER_REQUEST; }

        @Override
        public List<Finding> run(ActiveContext ctx) {
            MessageContext base = ctx.base();
            if (!"POST".equalsIgnoreCase(base.method())) return List.of();
            Analysis a = Analysis.of(base);
            if (a == null || a.message.location != SamlMessage.Location.BODY || !"SAMLResponse".equals(a.message.param)) return List.of();
            if (!a.isResponse() || a.assertions.isEmpty() || a.signatures.isEmpty()) return List.of();

            String pathAndQuery = base.path() + (base.query() == null || base.query().isEmpty() ? "" : "?" + base.query());
            List<Header> headers = base.requestHeaders();
            Function<byte[], Exchange> send = body -> ctx.http().send(base.method(), pathAndQuery, headers, body);

            // 1. unmodified replay
            Exchange replay = send.apply(base.requestBody());
            if (replay == null || !replay.hasResponse()) return List.of();
            Outcome ok = Outcome.of(replay.message());
            MessageContext captured = ctx.baseResponse() != null ? ctx.baseResponse() : base.hasResponse() ? base : null;
            if (captured != null && captured.hasResponse() && !ok.same(Outcome.of(captured))) return List.of();

            // 2. signatures removed
            Document stripped = copy(a);
            if (stripped == null) return List.of();
            for (Element s : descendants(stripped.getDocumentElement(), SamlAnalyzer.DS, "Signature")) s.getParentNode().removeChild(s);
            Exchange noSig = send.apply(a.message.rebuildBytes(SamlMessage.serialize(stripped)));

            // 3. signed value modified, signatures kept
            Document tampered = copy(a);
            String change = tampered == null ? null : tamper(tampered);
            Exchange modified = change == null ? null : send.apply(a.message.rebuildBytes(SamlMessage.serialize(tampered)));

            boolean noSigAccepted = noSig != null && noSig.hasResponse() && ok.same(Outcome.of(noSig.message()));
            boolean modAccepted = modified != null && modified.hasResponse() && ok.same(Outcome.of(modified.message()));
            if (!noSigAccepted && !modAccepted) return List.of();

            // 4. control: assertion removed
            Document control = copy(a);
            if (control == null) return List.of();
            List<Element> as = new ArrayList<>(descendants(control.getDocumentElement(), SamlAnalyzer.SAML2, "Assertion"));
            as.addAll(descendants(control.getDocumentElement(), SamlAnalyzer.SAML1, "Assertion"));
            for (Element e : as) if (e.getParentNode() != null) e.getParentNode().removeChild(e);
            Exchange ctl = send.apply(a.message.rebuildBytes(SamlMessage.serialize(control)));
            if (ctl == null || !ctl.hasResponse()) return List.of();
            Outcome rejected = Outcome.of(ctl.message());
            if (ok.same(rejected)) return List.of(); // the SP's response does not tell acceptance from rejection

            List<Finding> out = new ArrayList<>();
            String compare = "<ul><li>Unmodified replay: " + Finding.esc(ok.describe()) + "</li>"
                    + "<li>Control without assertion: " + Finding.esc(rejected.describe()) + "</li>";
            if (noSigAccepted) {
                out.add(issue(id(), "SAML signature not required", Severity.HIGH, Confidence.FIRM)
                        .detail("The assertion consumer service <code>" + Finding.esc(base.path()) + "</code> accepted the SAML Response"
                                + a.who() + " after all " + a.signatures.size() + " ds:Signature element(s) were removed: it responded exactly like "
                                + "it did to the original message and differently from a control message without an assertion." + compare
                                + "<li>Signatures removed: " + Finding.esc(Outcome.of(noSig.message()).describe()) + "</li></ul>"
                                + "An attacker can forge assertions for any user. Confirm by changing the NameID in the unsigned message.")
                        .background("Service providers must verify that the assertion is covered by a valid signature from the IdP's key. "
                                + "SPs that only verify signatures when present accept completely unsigned, forged assertions.")
                        .remediation("Require a valid signature (on the Response or the Assertion) from the configured IdP certificate and "
                                + "reject unsigned messages.")
                        .exchange(replay).exchange(noSig).exchange(ctl));
            }
            if (modAccepted) {
                out.add(issue(id(), "SAML signature not validated", Severity.HIGH, Confidence.FIRM)
                        .detail("The assertion consumer service <code>" + Finding.esc(base.path()) + "</code> accepted the SAML Response"
                                + a.who() + " after a signed value was changed (" + Finding.esc(change) + ") while the original signature was kept, "
                                + "so the signature cannot have been verified." + compare
                                + "<li>Signed value modified: " + Finding.esc(Outcome.of(modified.message()).describe()) + "</li></ul>"
                                + "An attacker can alter identities and attributes in captured assertions.")
                        .background("A signature only protects the message if the SP recomputes the digests and verifies the signature value "
                                + "against the IdP's trusted key; checking that a ds:Signature element exists is not enough.")
                        .remediation("Use a maintained SAML library, verify signatures against the IdP certificate from metadata (never the "
                                + "KeyInfo in the message), and process only the signed elements.")
                        .exchange(replay).exchange(modified).exchange(ctl));
            }
            return out;
        }

        private static Document copy(Analysis a) {
            try {
                return a.message.parse();
            } catch (SafeXml.XmlException e) {
                return null;
            }
        }

        /** Changes a value inside the signed content; returns a description, or null if nothing suitable exists. */
        static String tamper(Document d) {
            List<Element> as = new ArrayList<>(descendants(d.getDocumentElement(), SamlAnalyzer.SAML2, "Assertion"));
            as.addAll(descendants(d.getDocumentElement(), SamlAnalyzer.SAML1, "Assertion"));
            if (as.isEmpty()) return null;
            Element a = as.get(0);
            String ii = attr(a, "IssueInstant");
            Instant t = SamlAnalyzer.time(ii);
            if (t != null) {
                String nv = t.minusSeconds(1).toString();
                a.setAttribute("IssueInstant", nv);
                return "Assertion IssueInstant " + ii + " → " + nv;
            }
            Element nid = SafeXml.firstDescendant(a, "NameID");
            if (nid == null) nid = SafeXml.firstDescendant(a, "NameIdentifier");
            String v = nid == null ? null : nid.getTextContent();
            if (v == null) return null;
            for (int i = 0; i < v.length(); i++) {
                char c = v.charAt(i);
                if (Character.isLetter(c) && Character.toUpperCase(c) != Character.toLowerCase(c)) {
                    char f = Character.isUpperCase(c) ? Character.toLowerCase(c) : Character.toUpperCase(c);
                    String nv = v.substring(0, i) + f + v.substring(i + 1);
                    while (nid.getFirstChild() != null) nid.removeChild(nid.getFirstChild());
                    nid.appendChild(d.createTextNode(nv));
                    return "NameID \"" + v.strip() + "\" → \"" + nv.strip() + "\"";
                }
            }
            return null;
        }
    }

}
