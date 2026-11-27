package protocoldecoder.builtin.devexpress;

import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
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
import protocoldecoder.scan.ScanPatterns;
import protocoldecoder.scan.Severity;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Scanner support for DevExpress: segment-aware insertion points, error disclosure checks. */
public final class DevExpressScanner implements ProtocolScanner {

    static final String[] CALLBACK_FIELDS = {"__CALLBACKPARAM", "DXCallbackArgument"};

    @Override
    public String decoderId() {
        return DevExpressDecoder.ID;
    }

    @Override
    public List<PassiveCheck> passiveChecks() {
        return List.of(new CallbackErrorDisclosure());
    }

    @Override
    public List<ActiveCheck> activeChecks() {
        return List.of(new MalformedCallbackProbe());
    }

    /**
     * One insertion point per leaf inside the callback argument segments (lengths recomputed), plus each JSON leaf of
     * a Reporting {@code arg} parameter.
     */
    @Override
    public List<InsertionPoint> insertionPoints(MessageContext request, DecodeResult decoded) {
        List<InsertionPoint> out = new ArrayList<>();
        String body = request.requestBodyText();
        Map<String, List<String>> form = Codecs.parseQuery(body);
        for (String field : CALLBACK_FIELDS) {
            String value = Codecs.first(form, field);
            if (value == null) continue;
            DxArgModel.Arg arg = DxArgModel.parse(value);
            DxArgModel.leaves(arg, (path, slot) -> {
                if (out.size() >= InsertionPoints.MAX_POINTS) return;
                out.add(InsertionPoint.body("DevExpress: " + field + " " + path, slot.value(),
                        payload -> InsertionPoints.replaceFormField(body, field, 0, slot.rebuild().apply(payload)).getBytes(StandardCharsets.ISO_8859_1)));
            });
        }
        String reportArg = Codecs.first(form, "arg");
        if (reportArg != null && Codecs.first(form, "actionKey") != null) {
            var json = JsonTree.parseLenient(reportArg);
            if (json != null) {
                for (InsertionPoints.JsonLeaf leaf : InsertionPoints.jsonLeaves(json)) {
                    out.add(InsertionPoint.body("DevExpress Reporting: arg " + leaf.path(), InsertionPoints.text(leaf.value()),
                            payload -> InsertionPoints.replaceFormField(body, "arg", 0, leaf.replace().apply(payload)).getBytes(StandardCharsets.ISO_8859_1)));
                }
            }
        }
        return out;
    }

    /** Callback responses whose error object discloses exception details. */
    static final class CallbackErrorDisclosure implements PassiveCheck {
        @Override public String id() { return "devexpress.callback-error"; }
        @Override public String name() { return "Callback error details"; }
        @Override public String description() { return "Callback results containing server error messages or stack traces"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (!m.isResponse() || decoded == null) return List.of();
            DecodedNode result = decoded.root().get("Result");
            DecodedNode error = result == null ? null : result.get("error");
            if (error == null) return List.of();
            String message = error.get("message") != null ? error.get("message").value() : error.value();
            String text = m.responseBodyText();
            String trace = ScanPatterns.exceptionEvidence(text);
            Finding f = Finding.of(id(), trace != null ? "DevExpress callback discloses exception details" : "DevExpress callback returns a server error")
                    .severity(trace != null ? Severity.LOW : Severity.INFORMATION)
                    .confidence(Confidence.FIRM)
                    .detail("The DevExpress callback response contains an error"
                            + (message == null ? "" : ": <code>" + Finding.esc(Codecs.truncate(message, 500)) + "</code>")
                            + (trace != null ? "<br>It includes exception/stack trace details: <code>" + Finding.esc(trace) + "</code>" : ""))
                    .background("DevExpress controls return server-side exceptions to the client in the callback result. Detailed messages can reveal code paths, "
                            + "types and data useful to an attacker, and errors triggered by modified callback arguments often indicate missing input validation.")
                    .remediation("Handle exceptions in callback handlers and return generic messages; disable detailed errors in production "
                            + "(customErrors mode=\"On\"/\"RemoteOnly\").");
            if (message != null) f.responseEvidence(Codecs.truncate(message, 200));
            if (trace != null) f.responseEvidence(trace);
            return List.of(f);
        }
    }

    /** Sends a callback with corrupted segment lengths and looks for exception details in the reply. */
    static final class MalformedCallbackProbe implements ActiveCheck {
        @Override public String id() { return "devexpress.malformed-callback"; }
        @Override public String name() { return "Malformed callback error handling"; }
        @Override public String description() { return "Sends callback arguments with invalid segment lengths and checks for verbose exceptions"; }
        @Override public Scope scope() { return Scope.PER_REQUEST; }

        @Override
        public List<Finding> run(ActiveContext ctx) {
            MessageContext base = ctx.base();
            String body = base.requestBodyText();
            Map<String, List<String>> form = Codecs.parseQuery(body);
            for (String field : CALLBACK_FIELDS) {
                String value = Codecs.first(form, field);
                if (value == null) continue;
                // Bump the first declared length so the server's parser reads past the segment.
                String broken = value.replaceFirst("\\|(\\d+);", "|99999;");
                if (broken.equals(value)) broken = value + "|9;";
                String newBody = InsertionPoints.replaceFormField(body, field, 0, broken);
                List<Header> headers = new ArrayList<>(base.requestHeaders());
                Exchange x = ctx.http().send(base.method(), base.path() + (base.query().isEmpty() ? "" : "?" + base.query()), headers,
                        newBody.getBytes(StandardCharsets.ISO_8859_1));
                if (x == null || !x.hasResponse()) return List.of();
                String trace = ScanPatterns.exceptionEvidence(x.responseText());
                if (trace == null) return List.of();
                return List.of(Finding.of(id(), "DevExpress callback discloses exception details")
                        .severity(Severity.LOW).confidence(Confidence.FIRM)
                        .detail("Sending a <code>" + field + "</code> value with an invalid segment length caused the server to return exception details: <code>"
                                + Finding.esc(trace) + "</code>")
                        .background("Unhandled exceptions in DevExpress callback processing are returned to the client.")
                        .remediation("Disable detailed errors in production and handle callback parsing errors generically.")
                        .responseEvidence(trace)
                        .exchange(x));
            }
            return List.of();
        }
    }
}
