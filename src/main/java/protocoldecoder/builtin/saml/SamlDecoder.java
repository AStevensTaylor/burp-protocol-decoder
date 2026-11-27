package protocoldecoder.builtin.saml;

import org.w3c.dom.Document;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.ProtocolDecoder;
import protocoldecoder.util.Codecs;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SAML 2.0 (HTTP-Redirect, HTTP-POST, Artifact and SOAP bindings, SAML 1.1 assertions) and WS-Federation passive
 * sign-in messages. XML is parsed with a hardened parser (no DOCTYPE, no external entities, nothing fetched).
 */
public final class SamlDecoder implements ProtocolDecoder {

    public static final String ID = "saml";

    /** How much of a body {@link #match} looks at. */
    private static final int SCAN = 1024 * 1024;
    /** Largest base64 parameter we decode. */
    private static final int MAX_PARAM_CHARS = 8 * 1024 * 1024;
    /** Largest raw XML shown when it could not be parsed. */
    private static final int MAX_RAW_TEXT = 256 * 1024;

    private static final List<String> SAML_MESSAGES = List.of("SAMLRequest", "SAMLResponse");
    private static final Set<String> SAML_PARAMS = Set.of("SAMLRequest", "SAMLResponse", "SAMLart", "RelayState", "SigAlg", "Signature");
    private static final Map<String, String> WSFED_PARAMS = new LinkedHashMap<>();

    static {
        WSFED_PARAMS.put("wa", "Action");
        WSFED_PARAMS.put("wtrealm", "Realm (relying party)");
        WSFED_PARAMS.put("wreply", "Reply URL");
        WSFED_PARAMS.put("wctx", "Context (opaque RP state)");
        WSFED_PARAMS.put("wct", "Current time at RP");
        WSFED_PARAMS.put("whr", "Home realm");
        WSFED_PARAMS.put("wfresh", "Freshness (minutes)");
        WSFED_PARAMS.put("wauth", "Requested authentication");
        WSFED_PARAMS.put("wreq", "Token request");
        WSFED_PARAMS.put("wreqptr", "Token request pointer");
        WSFED_PARAMS.put("wresultptr", "Result pointer");
        WSFED_PARAMS.put("wp", "Policy");
        WSFED_PARAMS.put("wattr", "Requested attributes");
        WSFED_PARAMS.put("wresult", "Result (RSTR)");
    }

    private static final Map<String, String> WA = Map.of(
            "wsignin1.0", "Sign-in", "wsignout1.0", "Sign-out", "wsignoutcleanup1.0", "Sign-out cleanup",
            "wattr1.0", "Attribute request");

    private static final Map<String, String> SIG_ALGS = Map.of(
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1", "RSA-SHA1",
            "http://www.w3.org/2000/09/xmldsig#dsa-sha1", "DSA-SHA1",
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "RSA-SHA256",
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "RSA-SHA384",
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "RSA-SHA512",
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", "ECDSA-SHA256",
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1", "ECDSA-SHA1");

    private static final Pattern HTML_SAML_INPUT = Pattern.compile(
            "<input\\b(?:[^>\"']|\"[^\"]*+\"|'[^']*+')*?\\bname\\s*=\\s*[\"']?(SAMLResponse|SAMLRequest|SAMLart|wresult)\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern INPUT = Pattern.compile("<input\\b(?:[^>\"']++|\"[^\"]*+\"|'[^']*+')*+>", Pattern.CASE_INSENSITIVE);
    private static final Pattern TAG_ATTR = Pattern.compile(
            "\\b(name|value)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>\"']+))", Pattern.CASE_INSENSITIVE);
    private static final Pattern FORM_ACTION = Pattern.compile(
            "<form\\b[^>]*\\baction\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>\"']+))", Pattern.CASE_INSENSITIVE);
    private static final Pattern ENTITY = Pattern.compile("&(#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[a-zA-Z]{2,6});");

    @Override public String id() { return ID; }
    @Override public String name() { return "SAML / WS-Fed"; }
    @Override public String description() {
        return "SAML 2.0 / 1.1 messages (Redirect, POST, Artifact, SOAP bindings) and WS-Federation sign-in, with signature and validity checks";
    }

    // ---------------------------------------------------------------- matching

    @Override
    public MatchResult match(MessageContext m) {
        try {
            return doMatch(m);
        } catch (RuntimeException e) {
            return MatchResult.NONE;
        }
    }

    private MatchResult doMatch(MessageContext m) {
        if (m.isWebSocket()) return MatchResult.NONE;
        if (m.isRequest()) {
            String q = m.query();
            if (hasAnyParam(q, "SAMLRequest", "SAMLResponse")) return MatchResult.of(95, "SAML message in query string (HTTP-Redirect binding)");
            if (hasParam(q, "SAMLart")) return MatchResult.of(95, "SAMLart query parameter (Artifact binding)");
            String body = head(m.requestBody());
            if (hasAnyParam(body, "SAMLRequest", "SAMLResponse")) return MatchResult.of(95, "SAML message in form body (HTTP-POST binding)");
            if (hasParam(body, "SAMLart")) return MatchResult.of(95, "SAMLart form parameter (Artifact binding)");
            String wa = paramPrefix(q, body, "wa");
            if (wa != null && wa.startsWith("wsignin1.0")) {
                if (hasParam(body, "wresult") || hasParam(q, "wresult")) return MatchResult.of(90, "WS-Federation sign-in response (wresult)");
                return MatchResult.of(75, "WS-Federation sign-in request (wa=wsignin1.0)");
            }
            if (wa != null && (wa.startsWith("wsignout1.0") || wa.startsWith("wsignoutcleanup1.0"))) {
                return MatchResult.of(60, "WS-Federation sign-out (wa=" + wa + ")");
            }
            if (looksLikeSamlXml(body)) return MatchResult.of(85, "SAML protocol XML in request body (SOAP binding)");
            return MatchResult.NONE;
        }
        String loc = m.responseHeader("Location");
        if (loc != null && (hasAnyParam(loc, "SAMLRequest", "SAMLResponse") || hasParam(loc, "SAMLart"))) {
            return MatchResult.of(90, "Redirect carrying a SAML message (HTTP-Redirect binding)");
        }
        String body = head(m.responseBody());
        if ((body.contains("SAML") || body.contains("wresult") || body.contains("saml")) && HTML_SAML_INPUT.matcher(body).find()) {
            return MatchResult.of(80, "HTML auto-submit form with a SAML / WS-Fed field");
        }
        if (looksLikeSamlXml(body)) return MatchResult.of(85, "SAML protocol XML in response body (SOAP binding)");
        return MatchResult.NONE;
    }

    private static String head(byte[] b) {
        return new String(b, 0, Math.min(b.length, SCAN), StandardCharsets.ISO_8859_1);
    }

    /** True if {@code s} contains {@code name=} at a parameter boundary. */
    static boolean hasParam(String s, String name) {
        if (s == null || s.isEmpty()) return false;
        String needle = name + "=";
        int i = s.indexOf(needle);
        while (i >= 0) {
            if (i == 0 || s.charAt(i - 1) == '&' || s.charAt(i - 1) == '?') return true;
            i = s.indexOf(needle, i + 1);
        }
        return false;
    }

    private static boolean hasAnyParam(String s, String... names) {
        for (String n : names) if (hasParam(s, n)) return true;
        return false;
    }

    /** First few characters of a parameter's raw value in either string, or null. */
    private static String paramPrefix(String q, String body, String name) {
        for (String s : new String[]{q, body}) {
            if (s == null) continue;
            String needle = name + "=";
            int i = s.indexOf(needle);
            while (i >= 0) {
                if (i == 0 || s.charAt(i - 1) == '&' || s.charAt(i - 1) == '?') {
                    int start = i + needle.length();
                    int end = s.indexOf('&', start);
                    return s.substring(start, end < 0 ? Math.min(s.length(), start + 40) : Math.min(end, start + 40));
                }
                i = s.indexOf(needle, i + 1);
            }
        }
        return null;
    }

    private static boolean looksLikeSamlXml(String body) {
        String t = body.stripLeading();
        if (t.isEmpty() || t.charAt(0) != '<') return false;
        return t.contains(SamlAnalyzer.SAML2P) || t.contains(SamlAnalyzer.SAML1P)
                || (t.contains(SamlAnalyzer.SAML2) && t.contains("Assertion"))
                || t.contains("RequestSecurityTokenResponse");
    }

    // ---------------------------------------------------------------- decoding

    /** A parameter found in the message and where it came from. */
    record Param(String name, String value, String binding) {
    }

    @Override
    public DecodeResult decode(MessageContext m) throws DecodeException {
        if (m.isWebSocket()) throw new DecodeException("SAML / WS-Federation messages are not carried over WebSocket");
        List<String> warnings = new ArrayList<>();
        List<Param> params = new ArrayList<>();
        String endpoint = m.url();
        String rawXml = null;
        String xmlBinding = null;

        if (m.isRequest()) {
            collect(params, m.queryParameters(), "HTTP-Redirect");
            Map<String, List<String>> form = m.formParameters();
            String bodyText = m.requestBodyText();
            if (form.isEmpty() && bodyText.length() <= MAX_PARAM_CHARS && (hasAnyParam(bodyText, SAML_PARAMS.toArray(String[]::new)) || hasParam(bodyText, "wa"))) {
                form = Codecs.parseQuery(bodyText.strip());
            }
            collect(params, form, "HTTP-POST");
            if (params.isEmpty() && looksLikeSamlXml(head(m.requestBody()))) {
                rawXml = bodyText;
                xmlBinding = "SOAP / XML body";
            }
        } else {
            String loc = m.responseHeader("Location");
            if (loc != null) {
                int qi = loc.indexOf('?');
                if (qi >= 0) {
                    String lq = loc.substring(qi + 1);
                    int hash = lq.indexOf('#');
                    if (hash >= 0) lq = lq.substring(0, hash);
                    collect(params, Codecs.parseQuery(lq), "HTTP-Redirect");
                    if (!params.isEmpty()) endpoint = loc.substring(0, qi);
                }
            }
            byte[] body = Codecs.decodeContent(m.responseBody(), m.responseHeader("Content-Encoding"));
            String bodyText = new String(body, 0, Math.min(body.length, MAX_PARAM_CHARS), StandardCharsets.UTF_8);
            if (params.isEmpty() && HTML_SAML_INPUT.matcher(bodyText).find()) {
                collect(params, htmlInputs(bodyText), "HTTP-POST (auto-submit form)");
                String action = formAction(bodyText);
                if (action != null) endpoint = action;
            }
            if (params.isEmpty() && looksLikeSamlXml(bodyText)) {
                rawXml = bodyText;
                xmlBinding = "SOAP / XML body";
            }
        }

        Map<String, Param> byName = new LinkedHashMap<>();
        for (Param p : params) byName.putIfAbsent(p.name(), p);
        boolean hasSaml = byName.containsKey("SAMLRequest") || byName.containsKey("SAMLResponse") || byName.containsKey("SAMLart");
        boolean hasWsFed = byName.containsKey("wa") || byName.containsKey("wresult");
        if (!hasSaml && !hasWsFed && rawXml == null) {
            throw new DecodeException("No SAML or WS-Federation data found (expected SAMLRequest / SAMLResponse / SAMLart, "
                    + "a WS-Fed wa / wresult parameter, an auto-submit form or a SAML XML body)");
        }

        DecodedNode root = DecodedNode.object("SAML");
        List<String> texts = new ArrayList<>();
        List<String> summaries = new ArrayList<>();
        DecodedNode transport = root.child("Transport");
        Set<String> bindings = new LinkedHashSet<>();
        for (Param p : byName.values()) if (SAML_PARAMS.contains(p.name()) || WSFED_PARAMS.containsKey(p.name())) bindings.add(p.binding());
        if (xmlBinding != null) bindings.add(xmlBinding);
        transport.put("Binding", String.join(", ", bindings));
        transport.put("Endpoint", endpoint);

        // Redirect-binding signature (signature over the query string, not the XML).
        Param sigAlg = byName.get("SigAlg");
        Param sig = byName.get("Signature");
        String querySigAlg = null;
        if (sigAlg != null || sig != null) {
            DecodedNode sn = root.child("Redirect-binding signature");
            if (sigAlg != null) {
                sn.put("SigAlg", sigAlg.value() + (SIG_ALGS.containsKey(sigAlg.value()) ? "  (" + SIG_ALGS.get(sigAlg.value()) + ")" : ""));
                querySigAlg = sigAlg.value();
            }
            if (sig != null) {
                byte[] sb = base64(sig.value());
                sn.put("Signature bytes", sb == null ? null : sb.length);
                if (sb == null || sb.length == 0) warnings.add("Redirect-binding Signature parameter is empty or not valid base64");
                if (querySigAlg == null) querySigAlg = "(SigAlg missing)";
            } else {
                warnings.add("SigAlg present but no Signature parameter: the redirect message is not actually signed");
                querySigAlg = null;
            }
            sn.add(DecodedNode.note("Covers SAMLRequest/SAMLResponse, RelayState and SigAlg in the query string (not verified)"));
        }

        for (String name : SAML_MESSAGES) {
            Param p = byName.get(name);
            if (p == null) continue;
            String qs = p.binding().startsWith("HTTP-Redirect") ? querySigAlg : null;
            String s = decodeMessage(p.name() + " (" + p.binding() + ")", p.value(), p.binding().startsWith("HTTP-Redirect"),
                    qs, root, texts, warnings);
            if (s != null) summaries.add(s);
        }

        Param art = byName.get("SAMLart");
        if (art != null) {
            SamlArtifact.Parsed parsed = SamlArtifact.parse("SAMLart (Artifact binding)", art.value(), warnings);
            root.add(parsed.node());
            summaries.add("SAML artifact — " + parsed.brief());
        }

        Param relay = byName.get("RelayState");
        if (relay != null) {
            DecodedNode rn = root.child("RelayState");
            rn.put("Value", Codecs.truncate(relay.value(), 4000));
            if (relay.value().length() > 80) warnings.add("RelayState is " + relay.value().length() + " bytes (spec limit 80)");
            if (relay.value().matches("(?i)^(https?:)?//.*")) rn.add(DecodedNode.note("RelayState is a URL: check for open redirect after login"));
            byte[] b = base64(relay.value());
            if (b != null && b.length >= 8 && Codecs.isMostlyText(b) && relay.value().length() >= 12 && !relay.value().contains("/")) {
                rn.put("Base64-decoded", Codecs.truncate(Codecs.utf8(b), 2000));
            }
        }

        if (hasWsFed) summaries.addAll(wsFed(byName, root, texts, warnings));

        if (rawXml != null) {
            String s = decodeXml(xmlBinding, rawXml, null, root, texts, warnings, "XML body");
            if (s != null) summaries.add(s);
        }

        String summary = summaries.isEmpty() ? "SAML" : summaries.get(0) + (summaries.size() > 1 ? "  (+" + (summaries.size() - 1) + " more)" : "");
        String text = texts.isEmpty() ? null : String.join("\n\n", texts);
        return new DecodeResult(summary, root, text, new ArrayList<>(new LinkedHashSet<>(warnings)));
    }

    private static void collect(List<Param> out, Map<String, List<String>> params, String binding) {
        for (Map.Entry<String, List<String>> e : params.entrySet()) {
            if (!SAML_PARAMS.contains(e.getKey()) && !WSFED_PARAMS.containsKey(e.getKey())) continue;
            for (String v : e.getValue()) out.add(new Param(e.getKey(), v, binding));
        }
    }

    // ---------------------------------------------------------------- SAML messages

    /** Decodes a base64 (optionally deflated) SAML message parameter; returns its summary or null. */
    private String decodeMessage(String label, String value, boolean redirect, String querySigAlg, DecodedNode root,
                                 List<String> texts, List<String> warnings) {
        if (value.length() > MAX_PARAM_CHARS) {
            root.child(label).put("Error", "parameter too large (" + value.length() + " chars)");
            warnings.add(label + " is too large to decode");
            return null;
        }
        byte[] raw = base64(value);
        if (raw == null || raw.length == 0) {
            DecodedNode n = root.child(label);
            n.put("Error", "not valid base64");
            n.put("Raw", Codecs.truncate(value, 500));
            warnings.add(label + " is not valid base64");
            return null;
        }
        String encoding;
        byte[] xmlBytes;
        if (looksLikeXml(raw)) {
            xmlBytes = raw;
            encoding = "base64";
            if (redirect) warnings.add(label + " is not DEFLATE-compressed (the Redirect binding requires DEFLATE)");
        } else {
            byte[] inflated = null;
            try {
                inflated = Codecs.inflate(raw);
            } catch (IOException ignored) {
                // handled below
            }
            if (inflated != null && looksLikeXml(inflated)) {
                xmlBytes = inflated;
                encoding = "base64 + DEFLATE";
            } else {
                DecodedNode n = root.child(label);
                n.put("Error", "decoded bytes are neither XML nor DEFLATE-compressed XML");
                n.put("Bytes", Codecs.hexPreview(raw, 64));
                warnings.add(label + ": decoded value is not XML");
                return null;
            }
        }
        if (xmlBytes.length > SafeXml.MAX_XML_CHARS) {
            root.child(label).put("Error", "decoded XML too large (" + xmlBytes.length + " bytes)");
            warnings.add(label + ": decoded XML exceeds " + SafeXml.MAX_XML_CHARS + " bytes, not parsed");
            return null;
        }
        return decodeXml(label, new String(xmlBytes, StandardCharsets.UTF_8), querySigAlg, root, texts, warnings, encoding);
    }

    /** Parses and analyses one XML document, appending a node and its pretty text. Returns its summary or null. */
    private String decodeXml(String label, String xml, String querySigAlg, DecodedNode root, List<String> texts,
                             List<String> warnings, String encoding) {
        DecodedNode n = DecodedNode.object(label);
        root.add(n);
        n.put("Encoding", encoding);
        n.put("XML size", xml.length());
        Document doc;
        try {
            doc = SafeXml.parse(xml);
        } catch (SafeXml.XmlException e) {
            n.put("Error", e.getMessage());
            warnings.add(label + ": " + e.getMessage() + (e.doctype ? " — possible XXE / entity-expansion payload" : ""));
            texts.add("<!-- " + label + ": not parsed (" + e.getMessage() + ") -->\n" + Codecs.truncate(xml, MAX_RAW_TEXT));
            return null;
        }
        SamlAnalyzer.Result r = SamlAnalyzer.analyze(doc, label, querySigAlg, warnings);
        for (DecodedNode c : r.node().children()) n.add(c);
        texts.add("<!-- " + label + ", " + encoding + " -->\n" + SafeXml.pretty(doc));
        return r.summary();
    }

    // ---------------------------------------------------------------- WS-Federation

    private List<String> wsFed(Map<String, Param> byName, DecodedNode root, List<String> texts, List<String> warnings) {
        DecodedNode n = root.child("WS-Federation");
        List<String> summaries = new ArrayList<>();
        Param wa = byName.get("wa");
        String action = wa == null ? null : wa.value();
        for (Map.Entry<String, String> e : WSFED_PARAMS.entrySet()) {
            Param p = byName.get(e.getKey());
            if (p == null || e.getKey().equals("wresult")) continue;
            String v = p.value();
            if (e.getKey().equals("wa") && WA.containsKey(v)) v = v + "  (" + WA.get(v) + ")";
            n.put(e.getKey() + " — " + e.getValue(), Codecs.truncate(v, 4000));
        }
        Param wreply = byName.get("wreply");
        if (wreply != null) n.add(DecodedNode.note("wreply is where the token is posted: check it is validated against the realm"));
        Param wresult = byName.get("wresult");
        String head = "WS-Fed " + (action == null ? "message" : action);
        if (wresult != null) {
            String xml = wresult.value();
            if (!xml.stripLeading().startsWith("<")) {
                byte[] b = base64(xml);
                if (b != null && looksLikeXml(b)) xml = new String(b, StandardCharsets.UTF_8);
            }
            String s = decodeXml("wresult (" + wresult.binding() + ")", xml, null, root, texts, warnings, "XML");
            summaries.add(head + " — " + (s == null ? "unparseable wresult" : s.replaceFirst("^WS-Fed RSTR( — )?", "")));
        } else {
            Param realm = byName.get("wtrealm");
            summaries.add(head + (wa != null && WA.containsKey(action) ? " (" + WA.get(action).toLowerCase() + ")" : "")
                    + (realm == null ? "" : " → realm " + realm.value()));
        }
        return summaries;
    }

    // ---------------------------------------------------------------- HTML forms

    static Map<String, List<String>> htmlInputs(String html) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        Matcher im = INPUT.matcher(html);
        int count = 0;
        while (im.find() && count++ < 500) {
            String name = null, value = "";
            Matcher am = TAG_ATTR.matcher(im.group());
            while (am.find()) {
                String v = am.group(2) != null ? am.group(2) : am.group(3) != null ? am.group(3) : am.group(4);
                if (am.group(1).equalsIgnoreCase("name")) name = v;
                else value = v;
            }
            if (name != null) out.computeIfAbsent(unescapeHtml(name), k -> new ArrayList<>()).add(unescapeHtml(value));
        }
        return out;
    }

    private static String formAction(String html) {
        Matcher m = FORM_ACTION.matcher(html);
        if (!m.find()) return null;
        String v = m.group(1) != null ? m.group(1) : m.group(2) != null ? m.group(2) : m.group(3);
        return unescapeHtml(v);
    }

    static String unescapeHtml(String s) {
        if (s.indexOf('&') < 0) return s;
        Matcher m = ENTITY.matcher(s);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String e = m.group(1);
            String rep;
            try {
                if (e.startsWith("#x") || e.startsWith("#X")) rep = new String(Character.toChars(Integer.parseInt(e.substring(2), 16)));
                else if (e.startsWith("#")) rep = new String(Character.toChars(Integer.parseInt(e.substring(1))));
                else rep = switch (e) {
                    case "lt" -> "<";
                    case "gt" -> ">";
                    case "amp" -> "&";
                    case "quot" -> "\"";
                    case "apos" -> "'";
                    case "nbsp" -> "\u00a0";
                    default -> m.group();
                };
            } catch (IllegalArgumentException ex) {
                rep = m.group();
            }
            m.appendReplacement(sb, Matcher.quoteReplacement(rep));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    // ---------------------------------------------------------------- utilities

    /** Base64 decode tolerant of '+' turned into ' ' by a form/query decoder. Returns null if invalid. */
    static byte[] base64(String s) {
        if (s == null) return null;
        return Codecs.base64Decode(s.strip().replace(' ', '+'));
    }

    private static boolean looksLikeXml(byte[] b) {
        int i = 0;
        if (b.length >= 3 && (b[0] & 0xff) == 0xEF && (b[1] & 0xff) == 0xBB && (b[2] & 0xff) == 0xBF) i = 3;
        while (i < b.length && (b[i] == ' ' || b[i] == '\n' || b[i] == '\r' || b[i] == '\t')) i++;
        return i < b.length && b[i] == '<';
    }
}
