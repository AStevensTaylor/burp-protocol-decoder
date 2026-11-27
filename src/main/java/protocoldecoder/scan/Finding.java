package protocoldecoder.scan;

import java.util.ArrayList;
import java.util.List;

/**
 * A scanner issue produced by a check, independent of Burp. Detail/background/remediation may contain simple HTML
 * (Burp renders it); use {@link #esc(String)} for untrusted text.
 */
public final class Finding {

    /** Where the issue applies; HOST findings are reported once per host (e.g. "protocol in use"). */
    public enum Scope { URL, HOST }

    private final String checkId;
    private final String title;
    private Severity severity = Severity.INFORMATION;
    private Confidence confidence = Confidence.FIRM;
    private String detail = "";
    private String background = "";
    private String remediation = "";
    private Scope scope = Scope.URL;
    private final List<Evidence> evidence = new ArrayList<>();
    private final List<Exchange> exchanges = new ArrayList<>();

    public Finding(String checkId, String title) {
        this.checkId = checkId;
        this.title = title;
    }

    public static Finding of(String checkId, String title) {
        return new Finding(checkId, title);
    }

    public Finding severity(Severity s) { this.severity = s; return this; }
    public Finding confidence(Confidence c) { this.confidence = c; return this; }
    public Finding detail(String d) { this.detail = d == null ? "" : d; return this; }
    public Finding background(String b) { this.background = b == null ? "" : b; return this; }
    public Finding remediation(String r) { this.remediation = r == null ? "" : r; return this; }
    public Finding scope(Scope s) { this.scope = s; return this; }
    public Finding evidence(Evidence e) { if (e != null && e.text() != null && !e.text().isEmpty()) evidence.add(e); return this; }
    public Finding requestEvidence(String text) { return evidence(Evidence.request(text)); }
    public Finding responseEvidence(String text) { return evidence(Evidence.response(text)); }
    public Finding exchange(Exchange x) { if (x != null) exchanges.add(x); return this; }

    public String checkId() { return checkId; }
    public String title() { return title; }
    public Severity severity() { return severity; }
    public Confidence confidence() { return confidence; }
    public String detail() { return detail; }
    public String background() { return background; }
    public String remediation() { return remediation; }
    public Scope scope() { return scope; }
    public List<Evidence> evidence() { return List.copyOf(evidence); }
    public List<Exchange> exchanges() { return List.copyOf(exchanges); }

    /** HTML-escapes untrusted text for detail fields. */
    public static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    @Override
    public String toString() {
        return severity + "/" + confidence + " " + title + " [" + checkId + "]";
    }
}
