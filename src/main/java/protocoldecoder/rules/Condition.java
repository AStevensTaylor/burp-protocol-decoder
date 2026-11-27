package protocoldecoder.rules;

import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/** A single test against a message. Mutable bean so it can be edited in the UI and serialised with Gson. */
public final class Condition {

    /** Bodies are only scanned up to this many characters, to keep matching cheap on large responses. */
    static final int MAX_BODY_SCAN = 2 * 1024 * 1024;

    private ConditionField field = ConditionField.URL;
    private Operator operator = Operator.CONTAINS;
    /** Header name, for header fields. */
    private String name = "";
    private String value = "";
    private boolean caseSensitive = false;

    private transient Pattern compiled;
    private transient String compiledFrom;

    public Condition() {
    }

    public Condition(ConditionField field, Operator operator, String value) {
        this.field = field;
        this.operator = operator;
        this.value = value;
    }

    public Condition(ConditionField field, String name, Operator operator, String value) {
        this(field, operator, value);
        this.name = name;
    }

    public ConditionField field() { return field == null ? ConditionField.URL : field; }
    public Operator operator() { return operator == null ? Operator.CONTAINS : operator; }
    public String name() { return name == null ? "" : name; }
    public String value() { return value == null ? "" : value; }
    public boolean caseSensitive() { return caseSensitive; }

    public Condition field(ConditionField f) { this.field = f; return this; }
    public Condition operator(Operator o) { this.operator = o; return this; }
    public Condition name(String n) { this.name = n; return this; }
    public Condition value(String v) { this.value = v; compiled = null; return this; }
    public Condition caseSensitive(boolean c) { this.caseSensitive = c; compiled = null; return this; }

    /** Returns null if valid, else a description of the problem. */
    public String validate() {
        if (field().needsName() && name().isBlank()) return "header name is required for " + field().label();
        if (operator() == Operator.MATCHES_REGEX || operator() == Operator.NOT_MATCHES_REGEX) {
            try {
                Pattern.compile(value());
            } catch (PatternSyntaxException e) {
                return "invalid regex: " + e.getDescription();
            }
        }
        return null;
    }

    public boolean test(MessageContext m) {
        List<String> candidates = values(m);
        Operator op = operator();
        if (op == Operator.EXISTS) return !candidates.isEmpty();
        if (op == Operator.NOT_EXISTS) return candidates.isEmpty();
        boolean negative = op == Operator.NOT_CONTAINS || op == Operator.NOT_EQUALS || op == Operator.NOT_MATCHES_REGEX;
        if (candidates.isEmpty()) {
            // A missing value can't "contain" anything, but it does "not contain" it.
            return negative;
        }
        for (String c : candidates) {
            boolean hit = testOne(c);
            if (negative && !hit) return false;
            if (!negative && hit) return true;
        }
        return negative;
    }

    private boolean testOne(String actual) {
        String v = value();
        boolean cs = caseSensitive;
        String a = cs ? actual : actual.toLowerCase(Locale.ROOT);
        String e = cs ? v : v.toLowerCase(Locale.ROOT);
        return switch (operator()) {
            case CONTAINS, NOT_CONTAINS -> a.contains(e);
            case EQUALS, NOT_EQUALS -> a.equals(e);
            case STARTS_WITH -> a.startsWith(e);
            case ENDS_WITH -> a.endsWith(e);
            case MATCHES_REGEX, NOT_MATCHES_REGEX -> pattern().matcher(actual).find();
            case EXISTS, NOT_EXISTS -> true;
        };
    }

    private Pattern pattern() {
        String v = value();
        Pattern p = compiled;
        if (p == null || !v.equals(compiledFrom)) {
            try {
                p = Pattern.compile(v, caseSensitive ? 0 : Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
            } catch (PatternSyntaxException ex) {
                p = Pattern.compile("(?!)"); // never matches
            }
            compiled = p;
            compiledFrom = v;
        }
        return p;
    }

    /** The value(s) of the field for this message; empty list if the field is absent. */
    private List<String> values(MessageContext m) {
        List<String> out = new ArrayList<>(1);
        switch (field()) {
            case URL -> out.add(m.url());
            case HOST -> out.add(m.host());
            case PATH -> out.add(m.path());
            case QUERY -> { if (!m.query().isEmpty()) out.add(m.query()); }
            case METHOD -> out.add(m.method());
            case REQUEST_HEADER -> headerValues(m.requestHeaders(), out);
            case RESPONSE_HEADER -> headerValues(m.responseHeaders(), out);
            case REQUEST_BODY -> addBody(out, m.requestBody());
            case RESPONSE_BODY -> { if (m.hasResponse()) addBody(out, m.responseBody()); }
            case MESSAGE_BODY -> addBody(out, m.body());
            case CONTENT_TYPE -> { String ct = m.contentType(); if (!ct.isEmpty()) out.add(ct); }
            case STATUS_CODE -> { if (m.statusCode() != null) out.add(m.statusCode().toString()); }
            case WEBSOCKET_DIRECTION -> { if (m.webSocketDirection() != null) out.add(m.webSocketDirection()); }
        }
        return out;
    }

    private void headerValues(List<Header> headers, List<String> out) {
        for (Header h : headers) if (h.name().equalsIgnoreCase(name().trim())) out.add(h.value());
    }

    private static void addBody(List<String> out, byte[] body) {
        if (body == null || body.length == 0) return;
        int n = Math.min(body.length, MAX_BODY_SCAN);
        out.add(new String(body, 0, n, java.nio.charset.StandardCharsets.UTF_8));
    }

    /** Short human-readable description, e.g. {@code Host ends with "example.com"}. */
    public String describe() {
        String f = field().needsName() ? field().label() + " '" + name() + "'" : field().label();
        return operator().unary() ? f + " " + operator().label() : f + " " + operator().label() + " \"" + value() + "\"";
    }

    public Condition copy() {
        Condition c = new Condition(field, name, operator, value);
        c.caseSensitive = caseSensitive;
        return c;
    }
}
