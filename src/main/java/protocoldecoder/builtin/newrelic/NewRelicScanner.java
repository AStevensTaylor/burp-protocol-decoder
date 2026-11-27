package protocoldecoder.builtin.newrelic;

import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MessageContext;
import protocoldecoder.scan.Confidence;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.PassiveCheck;
import protocoldecoder.scan.ProtocolScanner;
import protocoldecoder.scan.ScanPatterns;
import protocoldecoder.scan.Severity;
import protocoldecoder.util.Codecs;

import java.util.ArrayList;
import java.util.List;

/**
 * Passive checks for New Relic. No active checks or insertion points: New Relic collectors are third-party
 * infrastructure and out of scope for a test of the application.
 */
public final class NewRelicScanner implements ProtocolScanner {

    @Override
    public String decoderId() {
        return NewRelicDecoder.ID;
    }

    @Override
    public List<PassiveCheck> passiveChecks() {
        return List.of(new SensitiveTelemetry(), new AgentConfiguration(), new IngestKeyInTraffic());
    }

    /** Personal data / secrets sent to New Relic in beacons (custom attributes, error messages, URLs). */
    static final class SensitiveTelemetry implements PassiveCheck {
        @Override public String id() { return "newrelic.sensitive-telemetry"; }
        @Override public String name() { return "Sensitive data sent to New Relic"; }
        @Override public String description() { return "Emails, tokens, credentials or card numbers inside browser/mobile telemetry payloads"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isRequest() || decoded == null || NewRelicDecoder.channel(m) == NewRelicDecoder.Channel.OTHER) return List.of();
            List<DecodedNode> scope = new ArrayList<>();
            for (String part : new String[]{"Query parameters", "Payload"}) {
                DecodedNode n = decoded.root().get(part);
                if (n != null) scope.add(n);
            }
            List<ScanPatterns.Sensitive> hits = new ArrayList<>();
            for (DecodedNode n : scope) hits.addAll(ScanPatterns.sensitiveValues(n, 20));
            // License keys are expected in beacons; don't report them as secrets.
            hits.removeIf(h -> h.path().contains("license"));
            if (hits.isEmpty()) return List.of();
            Finding f = Finding.of(id(), "Sensitive data sent to New Relic")
                    .severity(Severity.LOW).confidence(Confidence.TENTATIVE)
                    .detail("New Relic telemetry sent from the client contains data that looks sensitive:" + ScanPatterns.htmlList(hits))
                    .background("Browser and mobile agents send page URLs, custom attributes, error messages and AJAX details to New Relic. "
                            + "Personal data or secrets in these fields are disclosed to a third party and retained in its data store.")
                    .remediation("Avoid putting personal data or secrets in URLs, custom attributes and error messages; configure New Relic "
                            + "obfuscation / attribute exclusion rules.");
            for (ScanPatterns.Sensitive h : hits) f.requestEvidence(h.value());
            return List.of(f);
        }
    }

    /** NREUM configuration (license key, account/app ids) embedded in pages. */
    static final class AgentConfiguration implements PassiveCheck {
        @Override public String id() { return "newrelic.agent-config"; }
        @Override public String name() { return "Browser agent configuration in page"; }
        @Override public String description() { return "Account ID, application ID and browser license key exposed in NREUM config"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || decoded == null) return List.of();
            DecodedNode cfg = decoded.root().get("Browser agent (NREUM)");
            if (cfg == null) return List.of();
            List<String> items = new ArrayList<>();
            List<String> evidence = new ArrayList<>();
            for (String key : new String[]{"licenseKey", "applicationID", "accountID", "trustKey", "agentID", "xpid"}) {
                String v = findValue(cfg, key);
                if (v != null) {
                    items.add("<li><code>" + key + "</code>: <code>" + Finding.esc(v) + "</code></li>");
                    evidence.add(v);
                }
            }
            if (items.isEmpty()) return List.of();
            Finding f = Finding.of(id(), "New Relic browser agent configuration disclosed")
                    .severity(Severity.INFORMATION).confidence(Confidence.CERTAIN).scope(Finding.Scope.HOST)
                    .detail("The page embeds New Relic browser agent configuration:<ul>" + String.join("", items) + "</ul>")
                    .background("The browser license key is an ingest-only key that is public by design, but together with the account and "
                            + "application IDs it allows anyone to send fabricated telemetry to this account (data pollution, cost).")
                    .remediation("No action is usually required. Consider New Relic's browser key restrictions/allow-lists if telemetry abuse is a concern.");
            evidence.forEach(f::responseEvidence);
            return List.of(f);
        }
    }

    /** APM/mobile ingest keys seen in client traffic (e.g. from thick clients or mobile apps). */
    static final class IngestKeyInTraffic implements PassiveCheck {
        @Override public String id() { return "newrelic.ingest-key"; }
        @Override public String name() { return "APM license / mobile app token in client traffic"; }
        @Override public String description() { return "license_key on collector calls or X-App-License-Key headers seen through the proxy"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isRequest()) return List.of();
            NewRelicDecoder.Channel ch = NewRelicDecoder.channel(m);
            if (ch == NewRelicDecoder.Channel.APM) {
                String key = Codecs.first(m.queryParameters(), "license_key");
                if (key == null) return List.of();
                return List.of(Finding.of(id(), "New Relic APM license key exposed in client traffic")
                        .severity(Severity.LOW).confidence(Confidence.FIRM).scope(Finding.Scope.HOST)
                        .detail("A New Relic APM agent call passed through the proxy with license key <code>" + Finding.esc(mask(key)) + "</code>.")
                        .background("APM license keys are meant to stay on servers. Seeing one in intercepted traffic means it is shipped in a client "
                                + "(desktop/mobile app or device) where users can extract it and send data to — or exhaust ingest limits of — the account.")
                        .remediation("Rotate the key and keep APM agents server-side; use a browser/mobile application token for client telemetry.")
                        .requestEvidence(key));
            }
            if (ch == NewRelicDecoder.Channel.MOBILE) {
                String token = m.requestHeader("X-App-License-Key");
                if (token == null) return List.of();
                return List.of(Finding.of(id(), "New Relic mobile application token in traffic")
                        .severity(Severity.INFORMATION).confidence(Confidence.CERTAIN).scope(Finding.Scope.HOST)
                        .detail("The mobile agent sends application token <code>" + Finding.esc(mask(token)) + "</code>.")
                        .background("Mobile application tokens are embedded in apps by design; anyone extracting it can submit fabricated telemetry.")
                        .remediation("No action is usually required.")
                        .requestEvidence(token));
            }
            return List.of();
        }

        private static String mask(String k) {
            return k.length() <= 8 ? k : k.substring(0, 4) + "…" + k.substring(k.length() - 4);
        }
    }

    static String findValue(DecodedNode n, String key) {
        if (n.name().equals(key) && n.value() != null) return n.value();
        for (DecodedNode c : n.children()) {
            String v = findValue(c, key);
            if (v != null) return v;
        }
        return null;
    }
}
