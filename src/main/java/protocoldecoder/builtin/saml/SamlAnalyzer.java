package protocoldecoder.builtin.saml;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static protocoldecoder.builtin.saml.SafeXml.attr;
import static protocoldecoder.builtin.saml.SafeXml.child;
import static protocoldecoder.builtin.saml.SafeXml.children;
import static protocoldecoder.builtin.saml.SafeXml.descendants;
import static protocoldecoder.builtin.saml.SafeXml.firstDescendant;
import static protocoldecoder.builtin.saml.SafeXml.locate;
import static protocoldecoder.builtin.saml.SafeXml.path;
import static protocoldecoder.builtin.saml.SafeXml.text;

/**
 * Turns a parsed SAML 2.0 / SAML 1.1 / WS-Trust document into summary nodes and security observations. Does not verify
 * signatures cryptographically; it reports which elements carry ds:Signature and what those signatures reference.
 */
final class SamlAnalyzer {

    static final String SAML2P = "urn:oasis:names:tc:SAML:2.0:protocol";
    static final String SAML2 = "urn:oasis:names:tc:SAML:2.0:assertion";
    static final String SAML1P = "urn:oasis:names:tc:SAML:1.0:protocol";
    static final String SAML1 = "urn:oasis:names:tc:SAML:1.0:assertion";
    static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    static final String XENC = "http://www.w3.org/2001/04/xmlenc#";

    private static final int MAX_ASSERTIONS = 20;
    private static final int MAX_SIGNATURES = 20;
    private static final int MAX_ATTRIBUTES = 300;
    private static final int MAX_VALUES = 50;
    private static final Duration LONG_VALIDITY = Duration.ofHours(24);

    private static final String[] ID_ATTRS = {"ID", "Id", "AssertionID", "ResponseID", "RequestID"};

    /** Analysis output: tree node and one-line summary. */
    record Result(DecodedNode node, String summary, String subject) {
    }

    private final Document doc;
    private final List<String> warnings;
    private final String querySigAlg;
    private final Map<String, List<Element>> ids = new LinkedHashMap<>();
    private final Map<Element, List<Integer>> signedBy = new IdentityHashMap<>();

    private SamlAnalyzer(Document doc, String querySigAlg, List<String> warnings) {
        this.doc = doc;
        this.querySigAlg = querySigAlg;
        this.warnings = warnings;
    }

    /**
     * @param querySigAlg SigAlg of an HTTP-Redirect binding signature, or null when the message was not signed that way
     */
    static Result analyze(Document doc, String label, String querySigAlg, List<String> warnings) {
        return new SamlAnalyzer(doc, querySigAlg, warnings).run(label);
    }

    private Result run(String label) {
        Element root = doc.getDocumentElement();
        indexIds(root);
        DecodedNode node = DecodedNode.object(label);
        DecodedNode sigNode = signatures(root);

        Element msg = unwrap(root);
        String local = msg.getLocalName() == null ? msg.getNodeName() : msg.getLocalName();
        String ns = msg.getNamespaceURI() == null ? "" : msg.getNamespaceURI();
        boolean saml1 = ns.equals(SAML1P) || ns.equals(SAML1);
        boolean wsTrust = local.startsWith("RequestSecurityTokenResponse");
        boolean known = ns.equals(SAML2P) || ns.equals(SAML2) || saml1 || wsTrust;
        if (!known) warnings.add("Root element <" + msg.getNodeName() + "> is not a SAML protocol message or assertion");

        String typeLabel = (wsTrust ? "WS-Trust " : saml1 ? "SAML 1.1 " : "SAML ") + local;
        node.put("Message type", typeLabel + (msg != root ? "  (inside " + root.getLocalName() + ")" : ""));

        String[] summaryParts = message(msg, node);
        String status = summaryParts[0];
        String subject = summaryParts[1];

        // Assertions anywhere in the document.
        List<Element> assertions = new ArrayList<>(descendants(root, SAML2, "Assertion"));
        assertions.addAll(descendants(root, SAML1, "Assertion"));
        if (assertions.isEmpty() && "Assertion".equals(root.getLocalName())) assertions.add(root);
        List<Boolean> assertionSigned = new ArrayList<>();
        if (!assertions.isEmpty()) {
            DecodedNode arr = node.add(DecodedNode.array("Assertions")).get("Assertions");
            int i = 0;
            for (Element a : assertions) {
                i++;
                if (i > MAX_ASSERTIONS) {
                    arr.add(DecodedNode.note("… " + (assertions.size() - MAX_ASSERTIONS) + " more assertions not shown"));
                    break;
                }
                String nid = assertion(a, i, arr, msg);
                if (subject == null) subject = nid;
                assertionSigned.add(signedBy.containsKey(a));
            }
            if (assertions.size() > 1) {
                warnings.add("Message contains " + assertions.size() + " assertions: unusual, check for XML Signature Wrapping (XSW)");
            }
        }

        List<Element> encrypted = descendants(root, "EncryptedAssertion");
        if (!encrypted.isEmpty()) {
            DecodedNode arr = DecodedNode.array("Encrypted assertions");
            node.add(arr);
            int i = 0;
            for (Element e : encrypted) arr.add(encryptedAssertion(e, ++i));
            warnings.add(encrypted.size() + " EncryptedAssertion(s): contents cannot be decoded without the SP's private key");
        }
        if (!descendants(root, "EncryptedID").isEmpty()) node.add(DecodedNode.note("Contains EncryptedID (encrypted NameID)"));
        if (!descendants(root, "EncryptedAttribute").isEmpty()) node.add(DecodedNode.note("Contains EncryptedAttribute(s)"));

        if (!sigNode.isLeaf()) node.add(sigNode);
        else node.put("Signatures", "none (no ds:Signature elements)");

        // Signing posture.
        boolean msgIsAssertion = msg == root && "Assertion".equals(local);
        boolean msgSigned = signedBy.containsKey(msg);
        boolean viaQuery = querySigAlg != null;
        boolean carriesAssertions = !assertions.isEmpty();
        if (!msgIsAssertion && !wsTrust) {
            if (carriesAssertions) {
                boolean anyAssertionSigned = assertionSigned.contains(Boolean.TRUE);
                if (!msgSigned && !viaQuery && !anyAssertionSigned) {
                    warnings.add("Neither the " + local + " nor any Assertion is signed");
                } else if (!msgSigned && !viaQuery) {
                    warnings.add(local + " is not signed (only the Assertion): Destination, InResponseTo and Status are unprotected");
                }
                if ((msgSigned || viaQuery) && assertionSigned.contains(Boolean.FALSE)) {
                    warnings.add("Signature present on " + local + " but not on every Assertion: an SP that validates assertions independently may accept a tampered one");
                }
            } else if (encrypted.isEmpty() && !msgSigned && !viaQuery) {
                warnings.add(local + " is not signed");
            }
        }
        for (int i = 0; i < assertionSigned.size(); i++) {
            if (!assertionSigned.get(i)) warnings.add("Assertion #" + (i + 1) + " is not signed");
        }
        if (viaQuery && isSha1(querySigAlg)) warnings.add("Redirect-binding SigAlg uses SHA-1: " + querySigAlg);

        // Summary.
        StringBuilder s = new StringBuilder(wsTrust ? "WS-Fed RSTR" : typeLabel);
        if (status != null) s.append(" (").append(status).append(')');
        List<String> bits = new ArrayList<>();
        if (subject != null) bits.add(subject);
        if (carriesAssertions || !encrypted.isEmpty() || local.endsWith("Response")) {
            if (saml1 && carriesAssertions || wsTrust && carriesAssertions) {
                bits.add(assertions.size() + (isSaml1(assertions.get(0)) ? " SAML 1.1" : " SAML 2.0") + " assertion" + (assertions.size() == 1 ? "" : "s"));
            } else {
                bits.add(assertions.size() + " assertion" + (assertions.size() == 1 ? "" : "s"));
            }
            if (!encrypted.isEmpty()) bits.add(encrypted.size() + " encrypted");
        }
        StringBuilder signed = new StringBuilder("signed: ");
        if (!msgIsAssertion && !wsTrust) {
            signed.append(local).append(msgSigned ? " ✔" : viaQuery ? " ✔ (query)" : " ✘");
        }
        if (!assertionSigned.isEmpty()) {
            if (signed.length() > 8) signed.append(' ');
            signed.append("Assertion ");
            for (Boolean b : assertionSigned) signed.append(b ? '✔' : '✘');
        }
        if (signed.length() > 8) bits.add(signed.toString());
        if (!bits.isEmpty()) s.append(" — ").append(String.join(", ", bits));
        return new Result(node, s.toString(), subject);
    }

    // ---------------------------------------------------------------- message level

    static Element unwrap(Element root) {
        Element cur = root;
        if ("Envelope".equals(cur.getLocalName())) {
            Element body = child(cur, "Body");
            List<Element> kids = children(body, null);
            if (!kids.isEmpty()) cur = kids.get(0);
        }
        if ("RequestSecurityTokenResponseCollection".equals(cur.getLocalName())) {
            Element rstr = child(cur, "RequestSecurityTokenResponse");
            if (rstr != null) cur = rstr;
        }
        return cur;
    }

    /** Fills message-level fields; returns {status, subject}. */
    private String[] message(Element msg, DecodedNode node) {
        String local = msg.getLocalName();
        String status = null;
        String subject = null;
        putAttributes(node, msg);
        Element issuer = child(msg, "Issuer");
        if (issuer != null) node.put("Issuer", text(issuer));
        node.put("Signed", signedLabel(msg));

        Element st = child(msg, "Status");
        if (st != null) {
            DecodedNode sn = node.child("Status");
            Element code = child(st, "StatusCode");
            List<String> shorts = new ArrayList<>();
            int level = 0;
            while (code != null && level < 5) {
                String v = attr(code, "Value");
                sn.put(level == 0 ? "StatusCode" : "Second-level StatusCode", v);
                if (v != null) shorts.add(v.substring(v.lastIndexOf(':') + 1));
                code = child(code, "StatusCode");
                level++;
            }
            sn.put("StatusMessage", text(child(st, "StatusMessage")));
            Element detail = child(st, "StatusDetail");
            if (detail != null) sn.put("StatusDetail", Codecs.truncate(text(detail), 500));
            if (!shorts.isEmpty()) status = String.join("/", shorts);
        }

        switch (local == null ? "" : local) {
            case "AuthnRequest" -> {
                Element p = child(msg, "NameIDPolicy");
                if (p != null) {
                    DecodedNode pn = node.child("NameIDPolicy");
                    putAttributes(pn, p);
                }
                Element rac = child(msg, "RequestedAuthnContext");
                if (rac != null) {
                    DecodedNode rn = node.child("RequestedAuthnContext");
                    rn.put("Comparison", attr(rac, "Comparison"));
                    for (Element c : children(rac, null)) rn.put(c.getLocalName(), text(c));
                }
                Element subj = child(msg, "Subject");
                if (subj != null) node.put("Subject NameID", text(firstDescendant(subj, "NameID")));
                Element scoping = child(msg, "Scoping");
                if (scoping != null) {
                    DecodedNode sc = node.child("Scoping");
                    putAttributes(sc, scoping);
                    for (Element e : descendants(scoping, "IDPEntry")) sc.put("IDPEntry", attr(e, "ProviderID"));
                    for (Element e : children(scoping, "RequesterID")) sc.put("RequesterID", text(e));
                }
                if (child(msg, "Extensions") != null) node.add(DecodedNode.note("Has <Extensions>"));
                if (issuer != null) subject = "from " + text(issuer);
            }
            case "LogoutRequest" -> {
                Element nid = child(msg, "NameID");
                if (nid != null) {
                    DecodedNode nn = node.child("NameID");
                    nn.put("Value", text(nid));
                    putAttributes(nn, nid);
                    checkNameIdComments(nid, "LogoutRequest NameID");
                    subject = text(nid);
                }
                if (child(msg, "EncryptedID") != null) node.put("NameID", "(EncryptedID)");
                for (Element si : children(msg, "SessionIndex")) node.put("SessionIndex", text(si));
            }
            case "ArtifactResolve" -> {
                Element art = child(msg, "Artifact");
                if (art != null) {
                    SamlArtifact.Parsed p = SamlArtifact.parse("Artifact", text(art), warnings);
                    node.add(p.node());
                    subject = p.brief();
                }
            }
            case "ArtifactResponse" -> {
                for (Element inner : children(msg, null)) {
                    String l = inner.getLocalName();
                    if (l.equals("Issuer") || l.equals("Signature") || l.equals("Status") || l.equals("Extensions")) continue;
                    DecodedNode in = node.child("Wrapped message: " + l);
                    String[] r = message(inner, in);
                    if (r[0] != null) status = (status == null ? "" : status + ", inner ") + r[0];
                    if (r[1] != null) subject = r[1];
                    break;
                }
            }
            case "AttributeQuery", "AuthnQuery", "AuthzDecisionQuery" -> {
                Element subj = child(msg, "Subject");
                if (subj != null) {
                    subject = text(firstDescendant(subj, "NameID"));
                    node.put("Subject NameID", subject);
                }
                for (Element a : children(msg, "Attribute")) node.put("Requested attribute", attr(a, "Name"));
            }
            case "RequestSecurityTokenResponse" -> {
                node.put("TokenType", text(child(msg, "TokenType")));
                node.put("RequestType", text(child(msg, "RequestType")));
                node.put("KeyType", text(child(msg, "KeyType")));
                Element life = child(msg, "Lifetime");
                if (life != null) {
                    DecodedNode ln = node.child("Lifetime");
                    ln.put("Created", text(child(life, "Created")));
                    ln.put("Expires", text(child(life, "Expires")));
                }
                Element applies = child(msg, "AppliesTo");
                if (applies != null) node.put("AppliesTo", text(firstDescendant(applies, "Address")));
                if (child(msg, "RequestedSecurityToken") == null) warnings.add("RequestSecurityTokenResponse has no RequestedSecurityToken");
            }
            default -> {
                // Response / LogoutResponse / bare Assertion etc.: generic fields above are enough.
            }
        }
        return new String[]{status, subject};
    }

    // ---------------------------------------------------------------- assertions

    private static boolean isSaml1(Element a) {
        return SAML1.equals(a.getNamespaceURI());
    }

    /** Analyses one assertion; returns its subject NameID (or null). */
    private String assertion(Element a, int index, DecodedNode arr, Element msg) {
        boolean v1 = isSaml1(a);
        String label = "Assertion #" + index;
        DecodedNode n = DecodedNode.object(label);
        arr.add(n);
        n.put("SAML version", v1 ? "SAML 1." + (attr(a, "MinorVersion") == null ? "x" : attr(a, "MinorVersion")) : "SAML 2.0");
        putAttributes(n, a);
        String issuer = v1 ? attr(a, "Issuer") : text(child(a, "Issuer"));
        if (!v1) n.put("Issuer", issuer);
        n.put("Signed", signedLabel(a));

        Node parent = a.getParentNode();
        String parentName = parent instanceof Element pe ? pe.getLocalName() : null;
        if (parent instanceof Element && !"Response".equals(parentName) && !"RequestedSecurityToken".equals(parentName)) {
            String where = locate(a);
            n.put("Location", where);
            warnings.add(label + " is at an unusual location (" + where + "): possible signature wrapping");
        }

        Instant issued = time(attr(a, "IssueInstant"));
        if (issued == null) issued = time(attr(msg, "IssueInstant"));

        // Subject
        String nameId = null;
        Element subj = v1 ? firstDescendant(a, "Subject") : child(a, "Subject");
        if (subj != null) {
            DecodedNode sn = n.child("Subject");
            Element nid = child(subj, v1 ? "NameIdentifier" : "NameID");
            if (nid != null) {
                nameId = text(nid);
                sn.put("NameID", nameId);
                sn.put("Format", attr(nid, "Format"));
                sn.put("NameQualifier", attr(nid, "NameQualifier"));
                sn.put("SPNameQualifier", attr(nid, "SPNameQualifier"));
                String first = checkNameIdComments(nid, label + " NameID");
                if (first != null) sn.put("NameID (first text node only)", first);
            } else if (child(subj, "EncryptedID") != null) {
                sn.put("NameID", "(EncryptedID)");
            }
            int c = 0;
            for (Element sc : children(subj, "SubjectConfirmation")) {
                DecodedNode cn = sn.child("SubjectConfirmation" + (++c > 1 ? " #" + c : ""));
                String method = v1 ? text(child(sc, "ConfirmationMethod")) : attr(sc, "Method");
                cn.put("Method", method);
                Element data = child(sc, "SubjectConfirmationData");
                if (data != null) {
                    for (String at : new String[]{"Recipient", "NotOnOrAfter", "NotBefore", "InResponseTo", "Address"}) {
                        cn.put(at, attr(data, at));
                    }
                    Instant noa = time(attr(data, "NotOnOrAfter"));
                    if (noa != null && issued != null && !noa.isAfter(issued)) {
                        warnings.add(label + " SubjectConfirmationData NotOnOrAfter (" + attr(data, "NotOnOrAfter") + ") is not after IssueInstant: already expired when issued");
                    }
                    if (!v1 && method != null && method.endsWith(":bearer")) {
                        if (attr(data, "Recipient") == null) warnings.add(label + " bearer SubjectConfirmation has no Recipient");
                        if (attr(data, "NotOnOrAfter") == null) warnings.add(label + " bearer SubjectConfirmation has no NotOnOrAfter");
                    }
                } else if (!v1 && method != null && method.endsWith(":bearer")) {
                    warnings.add(label + " bearer SubjectConfirmation has no SubjectConfirmationData (no Recipient/NotOnOrAfter)");
                }
            }
        }

        // Conditions
        Element cond = child(a, "Conditions");
        if (cond != null) {
            DecodedNode cn = n.child("Conditions");
            cn.put("NotBefore", attr(cond, "NotBefore"));
            cn.put("NotOnOrAfter", attr(cond, "NotOnOrAfter"));
            List<Element> audiences = descendants(cond, "Audience");
            for (Element au : audiences) cn.put("Audience", text(au));
            if (child(cond, "OneTimeUse") != null || child(cond, "DoNotCacheCondition") != null) cn.put("OneTimeUse", Boolean.TRUE);
            Element proxy = child(cond, "ProxyRestriction");
            if (proxy != null) cn.put("ProxyRestriction Count", attr(proxy, "Count"));
            if (audiences.isEmpty()) warnings.add(label + " has no AudienceRestriction: it is not bound to a specific SP");

            Instant nb = time(attr(cond, "NotBefore"));
            Instant noa = time(attr(cond, "NotOnOrAfter"));
            if (issued != null && noa != null && !noa.isAfter(issued)) {
                warnings.add(label + " Conditions NotOnOrAfter (" + attr(cond, "NotOnOrAfter") + ") is not after IssueInstant: expired when issued");
            }
            if (issued != null && nb != null && nb.isAfter(issued.plus(Duration.ofMinutes(5)))) {
                warnings.add(label + " Conditions NotBefore (" + attr(cond, "NotBefore") + ") is later than IssueInstant: not yet valid when issued");
            }
            if (nb != null && noa != null && Duration.between(nb, noa).compareTo(LONG_VALIDITY) > 0) {
                warnings.add(label + " validity window is long (" + human(Duration.between(nb, noa)) + "): replay window");
            }
            if (noa == null) warnings.add(label + " Conditions has no NotOnOrAfter: no expiry");
        } else {
            warnings.add(label + " has no Conditions (no validity window, no AudienceRestriction)");
        }

        // Authentication statements
        int k = 0;
        for (Element as : children(a, v1 ? "AuthenticationStatement" : "AuthnStatement")) {
            DecodedNode an = n.child((v1 ? "AuthenticationStatement" : "AuthnStatement") + (++k > 1 ? " #" + k : ""));
            if (v1) {
                an.put("AuthenticationMethod", attr(as, "AuthenticationMethod"));
                an.put("AuthenticationInstant", attr(as, "AuthenticationInstant"));
            } else {
                an.put("AuthnInstant", attr(as, "AuthnInstant"));
                an.put("SessionIndex", attr(as, "SessionIndex"));
                an.put("SessionNotOnOrAfter", attr(as, "SessionNotOnOrAfter"));
                Element ctx = child(as, "AuthnContext");
                if (ctx != null) {
                    an.put("AuthnContextClassRef", text(child(ctx, "AuthnContextClassRef")));
                    an.put("AuthnContextDeclRef", text(child(ctx, "AuthnContextDeclRef")));
                    for (Element aa : children(ctx, "AuthenticatingAuthority")) an.put("AuthenticatingAuthority", text(aa));
                }
                Element loc = child(as, "SubjectLocality");
                if (loc != null) an.put("SubjectLocality", attr(loc, "Address"));
            }
        }

        // Attributes
        List<Element> attrs = new ArrayList<>();
        for (Element st : children(a, "AttributeStatement")) attrs.addAll(children(st, "Attribute"));
        if (!attrs.isEmpty()) {
            DecodedNode an = n.child("Attributes");
            int count = 0;
            for (Element at : attrs) {
                if (++count > MAX_ATTRIBUTES) {
                    an.add(DecodedNode.note("… " + (attrs.size() - MAX_ATTRIBUTES) + " more attributes not shown"));
                    break;
                }
                String name = v1 ? attr(at, "AttributeName") : attr(at, "Name");
                String friendly = attr(at, "FriendlyName");
                String key = (name == null ? "(unnamed)" : name) + (friendly != null && !friendly.equals(name) ? " (" + friendly + ")" : "");
                List<Element> values = children(at, "AttributeValue");
                if (values.size() == 1) {
                    an.put(key, valueText(values.get(0)));
                } else {
                    DecodedNode va = DecodedNode.array(key);
                    an.add(va);
                    int vi = 0;
                    for (Element v : values) {
                        if (++vi > MAX_VALUES) {
                            va.add(DecodedNode.note("… " + (values.size() - MAX_VALUES) + " more values"));
                            break;
                        }
                        va.put("[" + (vi - 1) + "]", valueText(v));
                    }
                }
            }
        }
        if (child(a, "AuthzDecisionStatement") != null || child(a, "AuthorizationDecisionStatement") != null) {
            n.add(DecodedNode.note("Has an authorization decision statement"));
        }
        return nameId;
    }

    private static String valueText(Element v) {
        if ("true".equals(v.getAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "nil"))) return "(nil)";
        String t = text(v);
        return Codecs.truncate(t == null ? "" : t, 4000);
    }

    /**
     * Reports comments / split text inside a NameID (the comment-truncation attack family, e.g. CVE-2017-11427).
     * Returns the first text node's value when it differs from the full text, else null.
     */
    private String checkNameIdComments(Element nid, String label) {
        boolean comment = false;
        int texts = 0;
        String first = null;
        for (Node c = nid.getFirstChild(); c != null; c = c.getNextSibling()) {
            if (c.getNodeType() == Node.COMMENT_NODE) comment = true;
            else if (c.getNodeType() == Node.TEXT_NODE || c.getNodeType() == Node.CDATA_SECTION_NODE) {
                if (texts++ == 0) first = c.getNodeValue().strip();
            } else if (c.getNodeType() == Node.ELEMENT_NODE) {
                warnings.add(label + " contains child elements");
            }
        }
        if (comment) {
            warnings.add(label + " contains an XML comment: comment-truncation attack (CVE-2017-11427 family); full text \""
                    + text(nid) + "\" vs first text node \"" + first + "\"");
            return first;
        }
        return null;
    }

    // ---------------------------------------------------------------- encrypted assertions

    private DecodedNode encryptedAssertion(Element e, int index) {
        DecodedNode n = DecodedNode.object("EncryptedAssertion #" + index);
        Element data = child(e, "EncryptedData");
        if (data != null) {
            n.put("Type", attr(data, "Type"));
            Element m = child(data, "EncryptionMethod");
            String alg = attr(m, "Algorithm");
            n.put("Data encryption", alg);
            if (alg != null && alg.toLowerCase(Locale.ROOT).contains("-cbc")) {
                warnings.add("EncryptedAssertion #" + index + " uses CBC mode (" + alg + "): padding-oracle risk, GCM preferred");
            }
            Element cipher = path(data, "CipherData", "CipherValue");
            if (cipher != null) {
                byte[] c = Codecs.base64Decode(text(cipher));
                n.put("CipherValue bytes", c == null ? null : c.length);
            }
        }
        List<Element> keys = descendants(e, "EncryptedKey");
        int k = 0;
        for (Element key : keys) {
            DecodedNode kn = n.child("EncryptedKey" + (++k > 1 ? " #" + k : ""));
            Element m = child(key, "EncryptionMethod");
            String alg = attr(m, "Algorithm");
            kn.put("Key transport", alg);
            Element dm = child(m, "DigestMethod");
            if (dm != null) kn.put("OAEP digest", attr(dm, "Algorithm"));
            kn.put("Recipient", attr(key, "Recipient"));
            keyInfo(child(key, "KeyInfo"), kn);
            if (alg != null && alg.endsWith("rsa-1_5")) {
                warnings.add("EncryptedAssertion #" + index + " key transport is RSA PKCS#1 v1.5 (" + alg + "): Bleichenbacher-style oracle risk");
            }
        }
        Element ki = data == null ? null : child(data, "KeyInfo");
        if (ki != null) {
            for (Element rm : children(ki, "RetrievalMethod")) n.put("KeyInfo RetrievalMethod", attr(rm, "URI"));
            Element kn = child(ki, "KeyName");
            if (kn != null) n.put("KeyName", text(kn));
        }
        return n;
    }

    // ---------------------------------------------------------------- signatures

    private void indexIds(Element root) {
        NodeList all = root.getOwnerDocument().getElementsByTagName("*");
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
            if (en.getValue().size() > 1) {
                warnings.add("ID \"" + en.getKey() + "\" is used by " + en.getValue().size() + " elements: signature wrapping indicator");
            }
        }
    }

    private static String idOf(Element e) {
        for (String id : ID_ATTRS) {
            String v = attr(e, id);
            if (v != null) return v;
        }
        String wsu = e.getAttributeNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Id");
        return wsu == null || wsu.isEmpty() ? null : wsu;
    }

    private static String describe(Element e) {
        String id = idOf(e);
        return e.getLocalName() + (id == null ? "" : " (ID=" + id + ")");
    }

    private String signedLabel(Element e) {
        List<Integer> by = signedBy.get(e);
        if (by == null) return "no";
        StringBuilder sb = new StringBuilder("yes (Signature #");
        for (int i = 0; i < by.size(); i++) sb.append(i == 0 ? "" : ", #").append(by.get(i));
        return sb.append(')').toString();
    }

    private DecodedNode signatures(Element root) {
        DecodedNode arr = DecodedNode.array("Signatures");
        List<Element> all = descendants(root, DS, "Signature");
        if (DS.equals(root.getNamespaceURI()) && "Signature".equals(root.getLocalName())) all.add(0, root);
        int i = 0;
        for (Element sig : all) {
            i++;
            if (i > MAX_SIGNATURES) {
                arr.add(DecodedNode.note("… " + (all.size() - MAX_SIGNATURES) + " more signatures not shown"));
                break;
            }
            DecodedNode n = DecodedNode.object("Signature #" + i);
            arr.add(n);
            Element parent = sig.getParentNode() instanceof Element pe ? pe : null;
            n.put("Location", locate(sig));
            if (parent != null) n.put("Enveloping element", describe(parent));
            Element si = child(sig, "SignedInfo");
            String c14n = attr(child(si, "CanonicalizationMethod"), "Algorithm");
            String sm = attr(child(si, "SignatureMethod"), "Algorithm");
            n.put("CanonicalizationMethod", c14n);
            n.put("SignatureMethod", sm);
            if (isSha1(sm)) warnings.add("Signature #" + i + " (on " + (parent == null ? "?" : parent.getLocalName()) + ") uses SHA-1 signature algorithm: " + sm);
            Element sv = child(sig, "SignatureValue");
            if (sv != null) {
                byte[] b = Codecs.base64Decode(text(sv));
                n.put("SignatureValue bytes", b == null ? null : b.length);
                if (b == null || b.length == 0) warnings.add("Signature #" + i + " has an empty or invalid SignatureValue");
            }
            List<Element> refs = children(si, "Reference");
            if (refs.isEmpty()) warnings.add("Signature #" + i + " has no Reference");
            int r = 0;
            for (Element ref : refs) {
                DecodedNode rn = n.child("Reference" + (refs.size() > 1 ? " #" + (++r) : ""));
                String uri = attr(ref, "URI");
                rn.put("URI", uri == null ? "(absent)" : uri.isEmpty() ? "\"\" (whole document)" : uri);
                String dm = attr(child(ref, "DigestMethod"), "Algorithm");
                rn.put("DigestMethod", dm);
                if (isSha1(dm)) warnings.add("Signature #" + i + " uses SHA-1 digest: " + dm);
                for (Element t : descendants(child(ref, "Transforms"), "Transform")) rn.put("Transform", attr(t, "Algorithm"));
                Element target = null;
                if (uri == null || uri.isEmpty()) {
                    target = root.getOwnerDocument().getDocumentElement();
                } else if (uri.startsWith("#")) {
                    List<Element> hits = ids.get(uri.substring(1));
                    if (hits != null && !hits.isEmpty()) target = hits.get(0);
                }
                if (target == null) {
                    rn.put("Resolves to", "nothing");
                    warnings.add("Signature #" + i + " reference " + uri + " does not match any element ID");
                } else {
                    rn.put("Resolves to", describe(target) + " at " + locate(target));
                    signedBy.computeIfAbsent(target, x -> new ArrayList<>()).add(i);
                    if (parent != null && target != parent && target != root.getOwnerDocument().getDocumentElement()) {
                        warnings.add("Signature #" + i + " sits in " + describe(parent) + " but references " + describe(target)
                                + ": signed element is not the enveloping one (signature wrapping indicator)");
                    }
                }
            }
            keyInfo(child(sig, "KeyInfo"), n);
        }
        return arr;
    }

    private void keyInfo(Element ki, DecodedNode n) {
        if (ki == null) return;
        DecodedNode kn = n.child("KeyInfo");
        Element name = child(ki, "KeyName");
        if (name != null) kn.put("KeyName", text(name));
        if (child(ki, "KeyValue") != null) kn.put("KeyValue", "present (raw public key)");
        int c = 0;
        for (Element x : descendants(ki, "X509Certificate")) {
            if (++c > 3) break;
            DecodedNode cn = kn.child("X509Certificate" + (c > 1 ? " #" + c : ""));
            byte[] der = Codecs.base64Decode(text(x));
            if (der == null) {
                cn.put("Error", "invalid base64");
                continue;
            }
            try {
                X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
                cn.put("Subject", cert.getSubjectX500Principal().getName());
                cn.put("Issuer", cert.getIssuerX500Principal().getName());
                cn.put("Serial", cert.getSerialNumber().toString(16));
                cn.put("NotBefore", cert.getNotBefore().toInstant().toString());
                cn.put("NotAfter", cert.getNotAfter().toInstant().toString());
                cn.put("Signature algorithm", cert.getSigAlgName());
            } catch (Exception e) {
                cn.put("Bytes", der.length);
                cn.put("Error", "not a parseable X.509 certificate");
            }
        }
        if (child(ki, "EncryptedKey") != null && n.get("EncryptedKey") == null) kn.put("EncryptedKey", "present");
        for (Element rm : children(ki, "RetrievalMethod")) kn.put("RetrievalMethod", attr(rm, "URI"));
    }

    // ---------------------------------------------------------------- utilities

    private static void putAttributes(DecodedNode n, Element e) {
        NamedNodeMap attrs = e.getAttributes();
        List<Attr> list = new ArrayList<>();
        for (int i = 0; i < attrs.getLength(); i++) list.add((Attr) attrs.item(i));
        for (Attr a : list) {
            String name = a.getName();
            if (name.equals("xmlns") || name.startsWith("xmlns:")) continue;
            n.put(name, a.getValue());
        }
    }

    static boolean isSha1(String alg) {
        if (alg == null) return false;
        String a = alg.toLowerCase(Locale.ROOT);
        return a.endsWith("sha1") || a.contains("-sha1") || a.contains("#sha1");
    }

    static Instant time(String s) {
        if (s == null || s.isBlank()) return null;
        try {
            return Instant.parse(s.strip());
        } catch (RuntimeException e) {
            try {
                return OffsetDateTime.parse(s.strip()).toInstant();
            } catch (RuntimeException e2) {
                return null;
            }
        }
    }

    private static String human(Duration d) {
        long h = d.toHours();
        return h >= 48 ? (h / 24) + " days" : h + " hours";
    }
}
