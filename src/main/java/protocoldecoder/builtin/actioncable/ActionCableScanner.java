package protocoldecoder.builtin.actioncable;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import protocoldecoder.builtin.turbo.SignedStreamFindings;
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
import protocoldecoder.util.JsonTree;

import java.util.ArrayList;
import java.util.List;

/**
 * Passive checks for Rails Action Cable frames (seen as proxied WebSocket messages). No active checks or insertion
 * points: Burp's scanner can't send WebSocket frames; the cross-origin handshake check lives in the Turbo scanner
 * ({@code turbo.cable-cross-origin}) because it needs an HTTP base request.
 */
public final class ActionCableScanner implements ProtocolScanner {

    @Override
    public String decoderId() {
        return ActionCableDecoder.ID;
    }

    @Override
    public List<PassiveCheck> passiveChecks() {
        return List.of(new StreamGlobalIds(), new StreamMarshal(), new SensitiveBroadcast());
    }

    private static JsonObject frame(MessageContext m) {
        if (!m.isWebSocket() || m.body().length == 0 || m.body().length > 4 * 1024 * 1024) return null;
        JsonElement e = JsonTree.parseStrict(Codecs.utf8(m.body()));
        return e != null && e.isJsonObject() ? e.getAsJsonObject() : null;
    }

    /** The signed_stream_name of the frame's channel identifier, if any. */
    static List<SignedStreamFindings.Token> tokens(MessageContext m) {
        JsonObject o = frame(m);
        if (o == null) return List.of();
        JsonElement id = o.get("identifier");
        if (id == null || !id.isJsonPrimitive() || !id.getAsJsonPrimitive().isString()) return List.of();
        JsonElement ide = JsonTree.parseLenient(id.getAsString());
        if (ide == null || !ide.isJsonObject()) return List.of();
        JsonElement ssn = ide.getAsJsonObject().get("signed_stream_name");
        if (ssn == null || !ssn.isJsonPrimitive() || ssn.getAsString().isEmpty()) return List.of();
        return List.of(SignedStreamFindings.Token.of(ssn.getAsString()));
    }

    private static String where(MessageContext m) {
        return "in Action Cable channel identifiers on <code>" + Finding.esc(m.path()) + "</code>";
    }

    static final class StreamGlobalIds implements PassiveCheck {
        @Override public String id() { return "actioncable.signed-stream-gid"; }
        @Override public String name() { return "GlobalIDs in signed stream names"; }
        @Override public String description() { return "Channel identifiers whose signed_stream_name decodes to gid://app/Model/ID (IDOR hints)"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            Finding f = SignedStreamFindings.globalIds(id(), tokens(m), where(m));
            return f == null ? List.of() : List.of(f);
        }
    }

    static final class StreamMarshal implements PassiveCheck {
        @Override public String id() { return "actioncable.signed-stream-marshal"; }
        @Override public String name() { return "Ruby Marshal in signed stream names"; }
        @Override public String description() { return "Channel identifiers whose signed_stream_name carries Ruby Marshal data"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            Finding f = SignedStreamFindings.marshal(id(), tokens(m), where(m));
            return f == null ? List.of() : List.of(f);
        }
    }

    static final class SensitiveBroadcast implements PassiveCheck {
        @Override public String id() { return "actioncable.sensitive-broadcast"; }
        @Override public String name() { return "Sensitive data in broadcasts"; }
        @Override public String description() {
            return "Server broadcasts whose JSON message carries secrets, tokens, credentials, card numbers or e-mail addresses";
        }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (decoded == null || !"SERVER_TO_CLIENT".equals(m.webSocketDirection())) return List.of();
            JsonObject o = frame(m);
            if (o == null || !"broadcast".equals(ActionCableDecoder.shape(o))) return List.of();
            DecodedNode msg = decoded.root().get("message");
            if (msg == null) return List.of(); // Turbo Stream HTML broadcasts are rendered page content
            List<ScanPatterns.Sensitive> hits = ScanPatterns.sensitiveValues(msg, 20);
            hits = new ArrayList<>(hits);
            hits.removeIf(s -> s.kind().equals("sensitive field name") && s.path().toLowerCase(java.util.Locale.ROOT).matches(".*(csrf|xsrf|nonce)[^›]*$"));
            if (hits.isEmpty()) return List.of();
            JsonElement id = o.get("identifier");
            String channel = id != null && id.isJsonPrimitive() ? ActionCableDecoder.channel(id.getAsString()).label() : "?";
            return List.of(Finding.of(id(), "Sensitive data in Action Cable broadcast")
                    .severity(Severity.LOW).confidence(Confidence.TENTATIVE)
                    .detail("A broadcast on <code>" + Finding.esc(Codecs.truncate(channel, 300)) + "</code> (WebSocket <code>" + Finding.esc(m.path())
                            + "</code>) contains sensitive-looking values:" + ScanPatterns.htmlList(hits)
                            + "Every subscriber of this stream receives them.")
                    .background("Broadcasts go to every connection subscribed to the stream. Data intended for one user (tokens, personal data) "
                            + "broadcast on a shared or guessable stream, or serialised from whole model objects, leaks to other subscribers.")
                    .remediation("Broadcast only the fields the client needs, on per-user streams that the channel authorises in "
                            + "<code>subscribed</code>."));
        }
    }
}
