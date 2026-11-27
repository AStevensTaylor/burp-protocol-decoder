package protocoldecoder.builtin.serialized;

import protocoldecoder.builtin.serialized.ParseOutput.Span;
import protocoldecoder.builtin.serialized.Sniffer.Detection;
import protocoldecoder.builtin.serialized.Sniffer.Format;
import protocoldecoder.builtin.serialized.Sniffer.Origin;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.scan.Confidence;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.InsertionPoint;
import protocoldecoder.scan.InsertionPoints;
import protocoldecoder.scan.PassiveCheck;
import protocoldecoder.scan.ProtocolScanner;
import protocoldecoder.scan.Severity;
import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scanner support for native serialization (Java, .NET BinaryFormatter, PHP, pickle, Ruby Marshal, Json.NET / XML type
 * hints). Passive checks report where serialized objects are accepted from the client, gadget class names inside
 * client-supplied data and serialized objects issued by the server. Insertion points expose the string values inside
 * serialized structures (lengths recomputed, base64 / hex / gzip / percent-encoding restored) to Burp's own scanner.
 *
 * <p>Detection and payload placement only: nothing is deserialized, no gadget chain or object is generated, and no
 * active check tries to trigger deserialization. A "does tampering change the response" active probe is deliberately
 * not provided: it cannot tell deserialization apart from ordinary input handling, and Burp's payloads sent through
 * the insertion points already exercise the values.</p>
 */
public final class SerializedObjectScanner implements ProtocolScanner {

    static final String CLIENT_CHECK = "serialized.client-supplied";
    static final String GADGET_CHECK = "serialized.gadget-reference";
    static final String SERVER_CHECK = "serialized.server-issued";

    private static final int MAX_VALUES = 64;
    private static final int MAX_EMBEDDED = 16;
    private static final int MAX_VALUE_CHARS = 4 * 1024 * 1024;
    private static final int MAX_BODY = 8 * 1024 * 1024;
    private static final int EMBED_SCAN = 2 * 1024 * 1024;
    private static final int PARSE_BUDGET = 20_000;
    private static final int IP_PARSE_BUDGET = 200_000;
    private static final int MAX_POINTS_PER_PAYLOAD = 100;
    private static final int MAX_POINTS = 200;
    private static final Pattern PHP_OBJECT = Pattern.compile("(?:^|[;{}])[OC]:\\d{1,4}:\"");
    private static final Pattern FIELD_NAME = Pattern.compile("(?:name|id)\\s*=\\s*[\"']([^\"'<>]{1,100})[\"'][^<>]{0,300}$|\"([^\"\\\\]{1,100})\"\\s*:\\s*\"?$");

    @Override
    public String decoderId() {
        return SerializedObjectDecoder.ID;
    }

    @Override
    public List<PassiveCheck> passiveChecks() {
        return List.of(new ClientSupplied(), new GadgetReference(), new ServerIssued());
    }

    // ================================================================== locations

    enum Loc { QUERY, FORM, COOKIE, HEADER, BODY, EMBEDDED, SET_COOKIE }

    /**
     * One value that may hold serialized data.
     *
     * @param raw    the value exactly as it appears in the message (null for a binary body)
     * @param text   the value as handed to the sniffer (form-decoded for parameters, without "Bearer " for headers)
     * @param index  pair index (query/form), segment index in the Cookie header, or -1
     * @param start  token offsets in the body (EMBEDDED)
     * @param prefix text kept in front of the value (header auth scheme)
     */
    record Value(Loc loc, String name, String raw, String text, byte[] bytes, int index, int start, int end, String prefix) {
        String where() {
            return switch (loc) {
                case QUERY, FORM -> "parameter " + name;
                case COOKIE, SET_COOKIE -> "cookie " + name;
                case HEADER -> "header " + name;
                case BODY -> name == null ? "body" : name;
                case EMBEDDED -> name == null ? "body token" : "body field " + name;
            };
        }

        /** Short form for insertion point names. */
        String shortWhere() {
            return switch (loc) {
                case QUERY, FORM -> "param " + name;
                case COOKIE, SET_COOKIE -> "cookie " + name;
                case HEADER -> "header " + name;
                case BODY -> "body";
                case EMBEDDED -> name == null ? "body @" + start : "body field " + name;
            };
        }

        Origin origin() {
            return switch (loc) {
                case QUERY, FORM -> Origin.PARAM;
                case COOKIE, SET_COOKIE -> Origin.COOKIE;
                case HEADER -> Origin.HEADER;
                case BODY -> Origin.BODY;
                case EMBEDDED -> Origin.EMBEDDED;
            };
        }
    }

    /** Values of the message that are examined (requests: params, cookies, headers, body; responses: Set-Cookie, headers, body). */
    static List<Value> values(MessageContext m) {
        List<Value> out = new ArrayList<>();
        if (!m.isWebSocket()) {
            if (m.isRequest()) {
                pairs(m.query(), Loc.QUERY, out);
                if (isForm(m)) pairs(m.requestBodyText(), Loc.FORM, out);
                for (Header h : m.requestHeaders()) {
                    if (!h.name().equalsIgnoreCase("Cookie")) continue;
                    String[] segs = h.value().split(";", -1);
                    for (int i = 0; i < segs.length && out.size() < MAX_VALUES; i++) {
                        int eq = segs[i].indexOf('=');
                        if (eq <= 0) continue;
                        String name = segs[i].substring(0, eq).strip();
                        String v = segs[i].substring(eq + 1).strip();
                        if (v.length() >= 4 && v.length() <= MAX_VALUE_CHARS) out.add(new Value(Loc.COOKIE, name, v, v, null, i, -1, -1, ""));
                    }
                }
            } else {
                for (Header h : m.responseHeaders()) {
                    if (!h.name().equalsIgnoreCase("Set-Cookie") || out.size() >= MAX_VALUES) continue;
                    String v = h.value();
                    int semi = v.indexOf(';');
                    String pair = semi >= 0 ? v.substring(0, semi) : v;
                    int eq = pair.indexOf('=');
                    if (eq <= 0) continue;
                    String val = pair.substring(eq + 1).strip();
                    if (val.length() >= 4 && val.length() <= MAX_VALUE_CHARS) out.add(new Value(Loc.SET_COOKIE, pair.substring(0, eq).strip(), val, val, null, -1, -1, -1, ""));
                }
            }
            for (Header h : m.headers()) {
                if (out.size() >= MAX_VALUES) break;
                String name = h.name().toLowerCase(Locale.ROOT);
                if (Scanner.SKIP_HEADERS.contains(name) || name.startsWith("sec-") || name.startsWith("access-control-")) continue;
                String v = h.value();
                String prefix = "";
                if (name.equals("authorization") || name.equals("proxy-authorization")) {
                    String lower = v.toLowerCase(Locale.ROOT);
                    if (!(lower.startsWith("bearer ") || lower.startsWith("token "))) continue;
                    int sp = v.indexOf(' ') + 1;
                    prefix = v.substring(0, sp);
                    v = v.substring(sp);
                }
                if (v.length() >= 4 && v.length() <= MAX_VALUE_CHARS) out.add(new Value(Loc.HEADER, h.name(), v, v, null, -1, -1, -1, prefix));
            }
        }
        if (!(m.isRequest() && isForm(m))) body(m, out);
        return out;
    }

    private static boolean isForm(MessageContext m) {
        return m.requestContentType().toLowerCase(Locale.ROOT).contains("x-www-form-urlencoded");
    }

    private static void pairs(String q, Loc loc, List<Value> out) {
        if (q == null || q.isEmpty()) return;
        String s = q.startsWith("?") && loc == Loc.QUERY ? q.substring(1) : q;
        String[] pairs = s.split("&", -1);
        for (int i = 0; i < pairs.length && out.size() < MAX_VALUES; i++) {
            int eq = pairs[i].indexOf('=');
            if (eq <= 0) continue;
            String raw = pairs[i].substring(eq + 1);
            if (raw.length() < 4 || raw.length() > MAX_VALUE_CHARS) continue;
            out.add(new Value(loc, Codecs.urlDecode(pairs[i].substring(0, eq)), raw, Codecs.urlDecode(raw), null, i, -1, -1, ""));
        }
    }

    private static void body(MessageContext m, List<Value> out) {
        byte[] body = m.body();
        if (body == null || body.length < 3 || body.length > MAX_BODY) return;
        String label = m.isWebSocket() ? "WebSocket message" : null;
        out.add(new Value(Loc.BODY, label, null, null, body, -1, -1, -1, ""));
        if (m.isWebSocket() || (m.header("Content-Encoding") != null && !m.header("Content-Encoding").isBlank())) return;
        if (Codecs.isGzip(body) || Sniffer.magic(Arrays.copyOf(body, Math.min(32, body.length))) != null) return;
        String text = new String(body, 0, Math.min(body.length, EMBED_SCAN), StandardCharsets.ISO_8859_1);
        Matcher mt = Scanner.EMBEDDED.matcher(text);
        int found = 0;
        while (mt.find() && found < MAX_EMBEDDED && out.size() < MAX_VALUES + MAX_EMBEDDED) {
            String token = mt.group();
            if (token.length() < 12 || token.length() == text.strip().length()) continue;
            found++;
            out.add(new Value(Loc.EMBEDDED, fieldName(text, mt.start()), token, token, null, -1, mt.start(), mt.end(), ""));
        }
    }

    /** Name of the HTML input / JSON key a token is the value of, when it is right before it. */
    private static String fieldName(String text, int at) {
        String before = text.substring(Math.max(0, at - 400), at);
        Matcher m = FIELD_NAME.matcher(before);
        if (!m.find()) return null;
        String n = m.group(1) != null ? m.group(1) : m.group(2);
        return n == null || n.isBlank() ? null : n;
    }

    // ================================================================== detection

    /** A recognised serialized payload at one location. */
    record Item(Value value, Detection detection, ParseOutput parsed) {
        Format format() {
            return detection.format();
        }

        boolean signed() {
            return detection.encoding() != null && detection.encoding().contains("signed");
        }

        List<String> risky() {
            List<String> r = new ArrayList<>();
            if (parsed != null) for (String t : parsed.types) if (RiskyTypes.reason(t) != null) r.add(t);
            return r;
        }
    }

    private record Cached(MessageContext message, List<Item> items) {
    }

    /** The passive checks run one after another on the same message and thread: parse it once. */
    private static final ThreadLocal<Cached> LAST = new ThreadLocal<>();

    /** Recognised payloads of a message, one per distinct payload (first location wins). */
    static List<Item> items(MessageContext m) {
        Cached c = LAST.get();
        if (c != null && c.message() == m) return c.items();
        List<Item> items = List.copyOf(scanItems(m));
        LAST.set(new Cached(m, items));
        return items;
    }

    private static List<Item> scanItems(MessageContext m) {
        List<Item> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (Value v : values(m)) {
            Detection d = v.loc() == Loc.BODY
                    ? Sniffer.inspectBytes(v.bytes(), Origin.BODY, null, true)
                    : Sniffer.inspect(v.text(), v.origin(), v.name(), true);
            if (d == null || d.confidence() <= 0 || d.format() == Format.GZIP || d.format() == Format.VIEWSTATE) continue;
            String key = d.format() + ":" + (d.payload() != null ? d.payload().length + ":" + Arrays.hashCode(d.payload())
                    : String.valueOf(d.text() == null ? v.where() : d.text().hashCode()));
            if (!seen.add(key)) continue;
            out.add(new Item(v, d, parse(d, new ParseOutput.Budget(PARSE_BUDGET))));
        }
        return out;
    }

    static ParseOutput parse(Detection d, ParseOutput.Budget budget) {
        try {
            return switch (d.format()) {
                case JAVA -> JavaSerialParser.parse(d.payload(), budget);
                case NRBF -> NrbfParser.parse(d.payload(), budget);
                case PHP -> PhpParser.parse(d.payload(), budget);
                case PICKLE -> PickleParser.parse(d.payload(), budget);
                case RUBY -> RubyMarshalParser.parse(d.payload(), budget);
                case JSON_NET -> d.text() == null ? null : TypeHints.jsonNet(d.text());
                case XML_HINT -> d.text() == null ? null : TypeHints.xml(d.text());
                default -> null;
            };
        } catch (RuntimeException e) {
            return null;
        }
    }

    static ParseOutput parse(Format f, byte[] payload, ParseOutput.Budget budget) {
        return parse(new Detection(f, "", 1, payload, null, null), budget);
    }

    private static boolean clientSide(MessageContext m) {
        return m.isRequest() || (m.isWebSocket() && "CLIENT_TO_SERVER".equals(m.webSocketDirection()));
    }

    static String formatName(Format f) {
        return switch (f) {
            case JAVA -> "Java";
            case NRBF -> ".NET BinaryFormatter";
            case PHP -> "PHP";
            case PICKLE -> "Python pickle";
            case RUBY -> "Ruby Marshal";
            case JSON_NET -> "Json.NET";
            case XML_HINT -> "XML serializer";
            case VIEWSTATE -> "ViewState";
            case GZIP -> "gzip";
        };
    }

    /** "PHP", "Java", ".NET", "pickle", "Ruby" for insertion point names. */
    static String shortName(Format f) {
        return switch (f) {
            case NRBF -> ".NET";
            case PICKLE -> "pickle";
            case RUBY -> "Ruby";
            default -> formatName(f);
        };
    }

    private static String title(Item it, String side) {
        Format f = it.format();
        String what = switch (f) {
            case JSON_NET -> "Json.NET $type hints";
            case XML_HINT -> "XML serializer type hints";
            default -> formatName(f) + " serialized object" + (it.signed() ? " (signed)" : "");
        };
        return what + " in " + side + " " + it.value().where();
    }

    /** Text to highlight: the token as it appears, or for raw bodies a prefix / class names that occur verbatim. */
    private static List<String> evidence(Item it) {
        Value v = it.value();
        if (v.raw() != null) return List.of(v.raw());
        byte[] body = v.bytes();
        if (body == null) return List.of();
        if (Codecs.isMostlyText(Arrays.copyOf(body, Math.min(body.length, 512)))) {
            String t = new String(body, StandardCharsets.UTF_8);
            return List.of(t.substring(0, Math.min(t.length(), 120)));
        }
        List<String> out = new ArrayList<>();
        String latin = new String(body, 0, Math.min(body.length, EMBED_SCAN), StandardCharsets.ISO_8859_1);
        if (it.parsed() != null) {
            for (String t : it.parsed().types) {
                if (out.size() >= 5) break;
                if (t.length() >= 4 && latin.contains(t)) out.add(t);
            }
        }
        return out;
    }

    private static String typesHtml(ParseOutput po, int max) {
        if (po == null || po.types.isEmpty()) return "";
        StringBuilder sb = new StringBuilder("<br>").append(Finding.esc(capitalise(po.typeNoun))).append(":<ul>");
        int n = 0;
        for (String t : po.types) {
            if (n++ >= max) {
                sb.append("<li>… ").append(po.types.size() - max).append(" more</li>");
                break;
            }
            String r = RiskyTypes.reason(t);
            sb.append("<li><code>").append(Finding.esc(t)).append("</code>");
            if (r != null) sb.append(" — <b>").append(Finding.esc(r)).append("</b>");
            sb.append("</li>");
        }
        return sb.append("</ul>").toString();
    }

    private static String describe(Item it) {
        Detection d = it.detection();
        StringBuilder sb = new StringBuilder("Format: <b>").append(Finding.esc(d.format().label)).append("</b><br>")
                .append("Location: <b>").append(Finding.esc(it.value().where())).append("</b><br>")
                .append("Encoding: ").append(Finding.esc(d.encoding()));
        if (d.payload() != null) sb.append("<br>Size: ").append(d.payload().length).append(" bytes");
        if (it.parsed() != null && !it.parsed().complete) {
            sb.append("<br>Structure parse stopped early (").append(Finding.esc(Codecs.truncate(it.parsed().stopReason, 200))).append(").");
        }
        sb.append(typesHtml(it.parsed(), 25));
        return sb.toString();
    }

    private static String capitalise(String s) {
        return s == null || s.isEmpty() ? "" : s.substring(0, 1).toUpperCase(Locale.ROOT) + s.substring(1);
    }

    private static final String SIGNED_NOTE = "The value carries a signature (Rails <code>--digest</code>, Django signing or "
            + "itsdangerous style), so modifying it should be rejected unless the signing key is known or the signature is "
            + "not verified. Check for a weak/default/leaked secret (e.g. <code>secret_key_base</code>, <code>SECRET_KEY</code>) "
            + "and whether the application still accepts the value with the signature removed or altered.";

    // ================================================================== passive checks

    /** Native serialized objects (or type-hinted JSON/XML) in data the client sends. */
    static final class ClientSupplied implements PassiveCheck {
        @Override public String id() { return CLIENT_CHECK; }
        @Override public String name() { return "Serialized object in client-supplied data"; }
        @Override public String description() {
            return "Java / .NET BinaryFormatter / pickle / Ruby Marshal / PHP serialize() data (and Json.NET $type / XML type hints) "
                    + "in request parameters, cookies, headers or body — one issue per format and location, with format, encoding and class names";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!clientSide(m)) return List.of();
            List<Finding> out = new ArrayList<>();
            for (Item it : items(m)) {
                Finding f = finding(it);
                if (f != null) out.add(f);
            }
            return out;
        }

        private Finding finding(Item it) {
            Format f = it.format();
            Severity sev;
            Confidence conf;
            String background;
            switch (f) {
                case JAVA, NRBF, PICKLE, RUBY -> {
                    sev = Severity.MEDIUM;
                    conf = Confidence.FIRM;
                    background = "The client sends a native " + formatName(f) + " serialized object. If the server deserializes it "
                            + "(" + api(f) + "), an attacker who can modify it may be able to instantiate arbitrary classes available to the "
                            + "application and chain their side effects (\"gadget chains\") into remote code execution, file access or "
                            + "denial of service. This is an indicator, not confirmation: whether the value is deserialized, and with which "
                            + "type restrictions, has to be verified.";
                }
                case PHP -> {
                    byte[] php = it.detection().payload() == null ? new byte[0] : it.detection().payload();
                    boolean objects = PHP_OBJECT.matcher(new String(php, StandardCharsets.ISO_8859_1)).find();
                    sev = objects ? Severity.MEDIUM : Severity.LOW;
                    conf = Confidence.FIRM;
                    background = objects
                            ? "The client sends PHP serialize() data containing objects. If the server passes it to unserialize() without "
                            + "<code>allowed_classes</code>, an attacker can inject objects of any loaded class and trigger magic methods "
                            + "(<code>__wakeup</code>, <code>__destruct</code>, <code>__toString</code>) — PHP object injection, often leading "
                            + "to code execution through framework gadget chains. Unconfirmed until the use of unserialize() is verified."
                            : "The client sends PHP serialize() data (scalars/arrays only). If the server passes it to unserialize(), an "
                            + "attacker can add objects to it (PHP object injection); the current value contains no objects, so this is "
                            + "a weaker indicator.";
                }
                case JSON_NET -> {
                    sev = Severity.LOW;
                    conf = Confidence.TENTATIVE;
                    background = "The request JSON carries Json.NET <code>$type</code> hints. When the server uses TypeNameHandling other "
                            + "than None without a restrictive SerializationBinder, a client-chosen <code>$type</code> makes Json.NET "
                            + "instantiate arbitrary .NET types (known gadget types lead to code execution).";
                }
                case XML_HINT -> {
                    if (it.detection().confidence() < 30) return null; // xsi:type / DataContract namespaces are everyday SOAP
                    sev = Severity.LOW;
                    conf = Confidence.TENTATIVE;
                    background = "The request XML carries serializer type information (NetDataContractSerializer, SoapFormatter, XAML or "
                            + "XMLDecoder). Serializers that take the type from the document can be made to instantiate arbitrary types.";
                }
                default -> {
                    return null;
                }
            }
            if (it.signed()) {
                sev = Severity.LOW;
                conf = Confidence.TENTATIVE;
            }
            String detail = "A serialized object was found in client-supplied data.<br>" + describe(it)
                    + (it.signed() ? "<br><br>" + SIGNED_NOTE : "")
                    + "<br><br>The scanner adds insertion points for string values inside this structure (named "
                    + "<code>Serialized (" + Finding.esc(shortName(f)) + "): …</code>) so Burp's payloads reach them with lengths and "
                    + "encodings kept valid.";
            Finding fd = Finding.of(CLIENT_CHECK, title(it, "request"))
                    .severity(sev).confidence(conf)
                    .detail(detail)
                    .background(background)
                    .remediation("Do not deserialize native objects from untrusted input; exchange plain data (JSON without type "
                            + "information) instead. If native serialization cannot be removed, protect the value with a MAC verified "
                            + "before deserialization and restrict deserialization to an allow-list of types (Java ObjectInputFilter / "
                            + "look-ahead, .NET: avoid BinaryFormatter, Json.NET TypeNameHandling.None, PHP "
                            + "<code>unserialize($v, ['allowed_classes' =&gt; false])</code>, never pickle/Marshal untrusted data).");
            evidence(it).forEach(fd::requestEvidence);
            return fd;
        }

        private static String api(Format f) {
            return switch (f) {
                case JAVA -> "ObjectInputStream.readObject()";
                case NRBF -> "BinaryFormatter / SoapFormatter / ObjectStateFormatter";
                case PICKLE -> "pickle.loads() and anything built on it";
                case RUBY -> "Marshal.load";
                default -> "unserialize";
            };
        }
    }

    /** Well-known gadget class / dangerous global names inside client-supplied serialized data. */
    static final class GadgetReference implements PassiveCheck {
        @Override public String id() { return GADGET_CHECK; }
        @Override public String name() { return "Gadget class reference in client-supplied serialized data"; }
        @Override public String description() {
            return "Known gadget-chain classes or dangerous callables (e.g. commons-collections functors, ObjectDataProvider, "
                    + "os.system, subprocess.Popen, Gem::Requirement) inside serialized data sent by the client";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!clientSide(m)) return List.of();
            Map<String, List<String>> byLocation = new LinkedHashMap<>();
            List<String> evidence = new ArrayList<>();
            for (Item it : items(m)) {
                List<String> risky = it.risky();
                if (risky.isEmpty()) continue;
                byLocation.put(it.value().where() + " (" + formatName(it.format()) + (it.signed() ? ", signed" : "") + ")", risky);
                evidence.addAll(evidence(it));
                for (String r : risky) if (evidence.size() < 12) evidence.add(r);
            }
            if (byLocation.isEmpty()) return List.of();
            StringBuilder sb = new StringBuilder("Client-supplied serialized data references classes / callables known as "
                    + "deserialization gadget-chain building blocks:<ul>");
            for (Map.Entry<String, List<String>> e : byLocation.entrySet()) {
                sb.append("<li>").append(Finding.esc(e.getKey())).append(":<ul>");
                for (String t : e.getValue()) {
                    sb.append("<li><code>").append(Finding.esc(t)).append("</code> — ").append(Finding.esc(RiskyTypes.reason(t))).append("</li>");
                }
                sb.append("</ul></li>");
            }
            sb.append("</ul>This may be an exploitation attempt already in progress (from another tester, a scanner or an attacker), "
                    + "or the application may round-trip these types through the client. Either way the server is likely to deserialize "
                    + "this value with these classes on its class path; confirm by reviewing how the value is processed.");
            Finding f = Finding.of(GADGET_CHECK, "Gadget class reference in client-supplied serialized data")
                    .severity(Severity.HIGH).confidence(Confidence.TENTATIVE)
                    .detail(sb.toString())
                    .background("Deserialization exploits are built from classes already present on the server (gadgets) whose "
                            + "methods run during deserialization. Seeing such classes in client-controlled data means the endpoint very "
                            + "likely deserializes client input and the gadget library is available.")
                    .remediation("Stop deserializing untrusted data; if that is not possible enforce a strict type allow-list before "
                            + "objects are created and remove unused gadget libraries. Investigate where this request came from.");
            new java.util.LinkedHashSet<>(evidence).forEach(f::requestEvidence);
            return List.of(f);
        }
    }

    /** Serialized objects the server hands to the client (cookies, hidden fields, bodies). */
    static final class ServerIssued implements PassiveCheck {
        @Override public String id() { return SERVER_CHECK; }
        @Override public String name() { return "Serialized object issued to the client"; }
        @Override public String description() {
            return "Native serialized objects in responses (Set-Cookie, headers, hidden fields / JSON values, bodies) — "
                    + "informational: check whether the client sends them back";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (m.isRequest() || clientSide(m)) return List.of();
            List<Finding> out = new ArrayList<>();
            for (Item it : items(m)) {
                Format f = it.format();
                if (f == Format.JSON_NET || f == Format.XML_HINT) continue;
                Finding fd = Finding.of(SERVER_CHECK, title(it, "response"))
                        .severity(Severity.INFORMATION).confidence(Confidence.FIRM)
                        .detail("The server sends a serialized object to the client.<br>" + describe(it)
                                + (it.signed() ? "<br><br>" + SIGNED_NOTE : "")
                                + "<br><br>Check whether the client sends this value back (cookie, form field, parameter): if so the "
                                + "server deserializes data the client controls, and the request-side issue "
                                + "\"serialized object in request\" applies.")
                        .background("Native serialized objects stored on the client (session cookies, view state, hidden form "
                                + "fields) are usually deserialized again when they come back, which exposes the server to "
                                + "deserialization attacks unless the value is integrity-protected. They can also disclose internal "
                                + "class names and data.")
                        .remediation("Keep serialized state on the server, or protect it with a MAC that is verified before "
                                + "deserialization; prefer plain data formats.");
                evidence(it).forEach(fd::responseEvidence);
                out.add(fd);
            }
            return out;
        }
    }

    // ================================================================== insertion points

    @Override
    public List<InsertionPoint> insertionPoints(MessageContext request, DecodeResult decoded) {
        if (request == null || !request.isRequest()) return List.of();
        List<InsertionPoint> out = new ArrayList<>();
        Set<String> seenPayloads = new HashSet<>();
        Map<String, Integer> names = new HashMap<>();
        for (Value v : values(request)) {
            if (out.size() >= MAX_POINTS) break;
            Wrapping.Peeled p = switch (v.loc()) {
                case BODY -> Wrapping.peelBytes(v.bytes());
                case QUERY, FORM -> Wrapping.peelText(v.text(), false);
                default -> Wrapping.peelText(v.raw(), true);
            };
            if (p == null || !rewritable(p.format())) continue;
            if (!seenPayloads.add(p.format() + ":" + Arrays.hashCode(p.payload()))) continue;
            List<Wrapping.Layer> layers = layersFor(v, p);
            if (layers == null) continue;
            ParseOutput po = parse(p.format(), p.payload(), new ParseOutput.Budget(IP_PARSE_BUDGET));
            if (po == null || !po.complete || po.spans.isEmpty()) continue;
            Function<byte[], byte[]> place = placer(request, v);
            if (place == null) continue;
            int n = 0;
            for (Span span : po.spans) {
                if (n++ >= MAX_POINTS_PER_PAYLOAD || out.size() >= MAX_POINTS) break;
                String base = "Serialized (" + shortName(p.format()) + "): " + v.shortWhere() + " › " + span.path();
                int dup = names.merge(base, 1, Integer::sum);
                String name = dup == 1 ? base : base + " #" + dup;
                byte[] payload = p.payload();
                List<ParseOutput.Frame> frames = List.copyOf(po.frames);
                Function<String, byte[]> render = s -> place.apply(Wrapping.wrap(Reserializer.replace(payload, span, s == null ? "" : s, frames), layers));
                out.add(switch (v.loc()) {
                    case QUERY -> InsertionPoint.query(name, span.value(), render);
                    case COOKIE -> InsertionPoint.header(name, "Cookie", span.value(), render);
                    case HEADER -> InsertionPoint.header(name, v.name(), span.value(), render);
                    default -> InsertionPoint.body(name, span.value(), render);
                });
            }
        }
        return out;
    }

    private static boolean rewritable(Format f) {
        return f == Format.JAVA || f == Format.NRBF || f == Format.PHP || f == Format.PICKLE || f == Format.RUBY;
    }

    /**
     * Layers to restore for this location. Raw PHP text in a cookie is percent-encoded (as PHP's setcookie does) so
     * that ';' and quotes in payloads cannot break the header; raw text in other headers is not supported.
     */
    private static List<Wrapping.Layer> layersFor(Value v, Wrapping.Peeled p) {
        List<Wrapping.Layer> layers = p.layers();
        boolean textSafe = !layers.isEmpty() && layers.get(0).kind() != Wrapping.Kind.GZIP;
        if (textSafe || v.loc() == Loc.BODY || v.loc() == Loc.QUERY || v.loc() == Loc.FORM) return layers;
        if (v.loc() == Loc.COOKIE) {
            List<Wrapping.Layer> l = new ArrayList<>();
            l.add(Wrapping.Layer.of(Wrapping.Kind.PERCENT));
            l.addAll(layers);
            return l;
        }
        return null;
    }

    /** Function from the new encoded value to the complete new content of the request part. */
    private static Function<byte[], byte[]> placer(MessageContext m, Value v) {
        switch (v.loc()) {
            case QUERY, FORM -> {
                String all = v.loc() == Loc.QUERY ? m.query() : m.requestBodyText();
                if (all == null) return null;
                String s = v.loc() == Loc.QUERY && all.startsWith("?") ? all.substring(1) : all;
                String[] pairs = s.split("&", -1);
                int idx = v.index();
                if (idx < 0 || idx >= pairs.length) return null;
                String key = pairs[idx].substring(0, pairs[idx].indexOf('='));
                return enc -> {
                    StringBuilder sb = new StringBuilder(s.length() + enc.length * 3);
                    for (int i = 0; i < pairs.length; i++) {
                        if (i > 0) sb.append('&');
                        if (i == idx) sb.append(key).append('=').append(InsertionPoints.formEncode(new String(enc, StandardCharsets.UTF_8)));
                        else sb.append(pairs[i]);
                    }
                    return sb.toString().getBytes(StandardCharsets.UTF_8);
                };
            }
            case COOKIE -> {
                String header = null;
                for (Header h : m.requestHeaders()) {
                    if (!h.name().equalsIgnoreCase("Cookie")) continue;
                    String[] segs = h.value().split(";", -1);
                    if (v.index() < segs.length && segs[v.index()].contains("=") && segs[v.index()].substring(segs[v.index()].indexOf('=') + 1).strip().equals(v.raw())) {
                        header = h.value();
                        break;
                    }
                }
                if (header == null) return null;
                String[] segs = header.split(";", -1);
                int idx = v.index();
                String seg = segs[idx];
                String head = seg.substring(0, seg.indexOf('=') + 1);
                return enc -> {
                    StringBuilder sb = new StringBuilder(enc.length + 64);
                    for (int i = 0; i < segs.length; i++) {
                        if (i > 0) sb.append(';');
                        if (i == idx) sb.append(head).append(new String(enc, StandardCharsets.ISO_8859_1));
                        else sb.append(segs[i]);
                    }
                    return sb.toString().getBytes(StandardCharsets.UTF_8);
                };
            }
            case HEADER -> {
                String prefix = v.prefix();
                return enc -> (prefix + new String(enc, StandardCharsets.ISO_8859_1)).getBytes(StandardCharsets.UTF_8);
            }
            case BODY -> {
                return enc -> enc;
            }
            case EMBEDDED -> {
                byte[] body = m.body();
                int start = v.start();
                int end = v.end();
                return enc -> {
                    byte[] out = new byte[body.length - (end - start) + enc.length];
                    System.arraycopy(body, 0, out, 0, start);
                    System.arraycopy(enc, 0, out, start, enc.length);
                    System.arraycopy(body, end, out, start + enc.length, body.length - end);
                    return out;
                };
            }
            default -> {
                return null;
            }
        }
    }
}
