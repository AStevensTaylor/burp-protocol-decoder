package protocoldecoder.builtin.turbo;

import protocoldecoder.scan.Confidence;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.Severity;
import protocoldecoder.util.Codecs;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Findings about Rails signed stream names (Turbo stream sources, Action Cable identifiers); shared by both scanners. */
public final class SignedStreamFindings {

    private SignedStreamFindings() {
    }

    /** A signed token and its decoding. */
    public record Token(String raw, SignedStreamName.Decoded decoded) {
        public static Token of(String raw) {
            return new Token(raw, SignedStreamName.decode("signed stream name", raw));
        }
    }

    /** "GlobalIDs in signed stream names" (Information), or null when no token decodes to a GlobalID. */
    public static Finding globalIds(String checkId, List<Token> tokens, String where) {
        Set<String> gids = new LinkedHashSet<>();
        Set<String> streams = new LinkedHashSet<>();
        for (Token t : tokens) {
            if (!t.decoded().ok() || t.decoded().globalIds().isEmpty()) continue;
            gids.addAll(t.decoded().globalIds());
            streams.add(t.decoded().display());
        }
        if (gids.isEmpty()) return null;
        StringBuilder list = new StringBuilder("<ul>");
        int n = 0;
        for (String g : gids) {
            if (n++ >= 30) break;
            list.append("<li><code>").append(Finding.esc(g)).append("</code>").append(Finding.esc(describe(g))).append("</li>");
        }
        list.append("</ul>");
        Finding f = Finding.of(checkId, "Signed stream names reveal GlobalIDs")
                .severity(Severity.INFORMATION).confidence(Confidence.FIRM)
                .detail("Signed stream names " + where + " decode to Rails GlobalIDs:" + list
                        + "Streams: <code>" + Finding.esc(Codecs.truncate(String.join(", ", streams), 500)) + "</code>")
                .background("Turbo's <code>turbo_stream_from</code> and Action Cable channels identify broadcast streams by signed names "
                        + "(<code>ActiveSupport::MessageVerifier</code>: base64 data + HMAC). They are signed, not encrypted: anyone can read the model "
                        + "names and record ids. The signature stops tampering (a different id needs <code>secret_key_base</code>), but the ids map out "
                        + "records for IDOR testing elsewhere, and custom channels that accept unsigned stream or record parameters may let "
                        + "subscribers listen to other users' streams.")
                .remediation("Treat stream names as public. Authorise subscriptions in the channel's <code>subscribed</code> callback (not only via "
                        + "the signature) and avoid streaming per-user data on guessable or unsigned names.");
        for (Token t : tokens) if (t.decoded().ok() && !t.decoded().globalIds().isEmpty()) f.responseEvidence(t.raw());
        return f;
    }

    /** "Ruby Marshal in signed data" (Low/Tentative), or null when no token is Marshal-serialised. */
    public static Finding marshal(String checkId, List<Token> tokens, String where) {
        Set<String> shown = new LinkedHashSet<>();
        for (Token t : tokens) if ("Ruby Marshal".equals(t.decoded().format()) && shown.size() < 10) shown.add(t.decoded().display());
        if (shown.isEmpty()) return null;
        StringBuilder list = new StringBuilder("<ul>");
        for (String s : shown) list.append("<li><code>").append(Finding.esc(Codecs.truncate(s, 300))).append("</code></li>");
        list.append("</ul>");
        Finding f = Finding.of(checkId, "Signed data uses Ruby Marshal serialisation")
                .severity(Severity.LOW).confidence(Confidence.TENTATIVE)
                .detail("Signed values " + where + " carry Ruby <code>Marshal</code> data (format 4.8):" + list)
                .background("The server deserialises this data with <code>Marshal.load</code> after checking the HMAC. Marshal deserialisation of "
                        + "attacker-controlled data leads to remote code execution through gadget chains, so the only protection is "
                        + "<code>secret_key_base</code>: if it ever leaks (repository, logs, debug pages, default/shared keys), any signed value becomes "
                        + "an RCE vector. JSON serialisation removes that risk.")
                .remediation("Configure message verifiers/cookies to use JSON (<code>config.active_support.message_serializer = :json</code>, "
                        + "<code>Rails.application.message_verifier</code> with <code>serializer: JSON</code>) and keep <code>secret_key_base</code> secret.");
        for (Token t : tokens) if ("Ruby Marshal".equals(t.decoded().format())) f.responseEvidence(t.raw());
        return f;
    }

    private static String describe(String gid) {
        String[] p = gid.substring("gid://".length()).split("/", 3);
        if (p.length < 3) return "";
        String id = p[2];
        int q = id.indexOf('?');
        if (q >= 0) id = id.substring(0, q);
        return " — model " + p[1] + ", id " + Codecs.urlDecode(id);
    }
}
