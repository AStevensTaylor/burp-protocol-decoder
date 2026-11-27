package protocoldecoder.builtin.firebase;

import protocoldecoder.builtin.firebase.Fb.Out;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.Header;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.ProtocolDecoder;
import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Firebase / Google Cloud client protocols: Firestore (WebChannel Listen/Write streams and REST), Realtime Database
 * (WebSocket, long-poll, REST), Firebase Auth (Identity Toolkit, Secure Token) and Firebase web configuration
 * embedded in pages and scripts.
 */
public final class FirebaseDecoder implements ProtocolDecoder {

    public static final String ID = "firebase";
    static final int SNIFF = 512 * 1024;
    private static final int WS_SNIFF = 256;

    private static final Set<String> FIREBASE_HEADERS = Set.of("authorization", "x-firebase-appcheck", "x-firebase-gmpid",
            "x-client-version", "x-firebase-client", "x-goog-api-key", "x-goog-api-client", "x-firebase-locale",
            "x-goog-firebase-installations-auth", "x-firebase-auth-token");

    enum Variant { FIRESTORE_CHANNEL, FIRESTORE_REST, RTDB_WS, RTDB_LONGPOLL, RTDB_REST, IDENTITY_TOOLKIT, SECURE_TOKEN, HOSTING_INIT, NONE }

    @Override public String id() { return ID; }
    @Override public String name() { return "Firebase"; }
    @Override public String description() {
        return "Firestore WebChannel/REST, Realtime Database WebSocket/long-poll/REST, Firebase Auth tokens and web config";
    }

    static boolean isRtdbHost(String h) {
        return h.endsWith(".firebaseio.com") || h.endsWith(".firebasedatabase.app");
    }

    static Variant variant(MessageContext m) {
        String host = m.host().toLowerCase(Locale.ROOT);
        String path = m.path();
        if (host.equals("firestore.googleapis.com")) {
            if (path.startsWith("/google.firestore.") && path.endsWith("/channel")) return Variant.FIRESTORE_CHANNEL;
            if (path.matches("/v1(?:beta\\d)?/projects/.*")) return Variant.FIRESTORE_REST;
            return Variant.NONE;
        }
        if (isRtdbHost(host)) {
            if (path.equals("/.ws")) return Variant.RTDB_WS;
            if (path.equals("/.lp")) return Variant.RTDB_LONGPOLL;
            if (m.isWebSocket()) return Variant.RTDB_WS;
            if (path.endsWith(".json")) return Variant.RTDB_REST;
            return Variant.NONE;
        }
        if (host.equals("identitytoolkit.googleapis.com") || (host.equals("www.googleapis.com") && path.startsWith("/identitytoolkit/"))) {
            return Variant.IDENTITY_TOOLKIT;
        }
        if (host.equals("securetoken.googleapis.com")) return Variant.SECURE_TOKEN;
        if (path.equals("/__/firebase/init.json") || path.equals("/__/firebase/init.js")) return Variant.HOSTING_INIT;
        return Variant.NONE;
    }

    // ---------------------------------------------------------------- matching

    @Override
    public MatchResult match(MessageContext m) {
        try {
            Variant v = variant(m);
            if (m.isWebSocket()) {
                if (v == Variant.RTDB_WS) return MatchResult.of(95, "Firebase Realtime Database WebSocket");
                byte[] b = m.body();
                if (b.length < 16) return MatchResult.NONE;
                String head = new String(b, 0, Math.min(b.length, WS_SNIFF), StandardCharsets.UTF_8);
                if ((head.startsWith("{\"t\":\"d\",\"d\":{") || head.startsWith("{\"t\":\"c\",\"d\":{\"t\":\""))
                        && (head.contains("\"a\":\"") || head.contains("\"r\":") || head.startsWith("{\"t\":\"c\""))) {
                    return MatchResult.of(55, "Realtime Database frame shape on a non-Firebase host");
                }
                return MatchResult.NONE;
            }
            boolean req = m.isRequest();
            switch (v) {
                case FIRESTORE_CHANNEL -> { return MatchResult.of(95, "Firestore WebChannel " + Firestore.stream(m)); }
                case FIRESTORE_REST -> { return MatchResult.of(90, "Firestore REST API"); }
                case RTDB_LONGPOLL -> { return MatchResult.of(95, "Realtime Database long-poll"); }
                case RTDB_REST -> { return MatchResult.of(req ? 90 : 85, "Realtime Database REST (.json)"); }
                case IDENTITY_TOOLKIT -> { return MatchResult.of(req ? 95 : 90, "Firebase Auth (Identity Toolkit)"); }
                case SECURE_TOKEN -> { return MatchResult.of(req ? 95 : 90, "Firebase Auth (Secure Token)"); }
                case HOSTING_INIT -> {
                    if (req) return MatchResult.NONE;
                    return responseHead(m).contains("apiKey") ? MatchResult.of(85, "Firebase Hosting init config") : MatchResult.NONE;
                }
                case RTDB_WS -> { return MatchResult.NONE; }
                default -> {
                }
            }
            if (req) return MatchResult.NONE;
            String ct = m.contentType().toLowerCase(Locale.ROOT);
            if (!ct.isEmpty() && !ct.contains("html") && !ct.contains("javascript") && !ct.contains("json") && !ct.contains("text/plain")) {
                return MatchResult.NONE;
            }
            int c = FirebaseAuth.configConfidence(responseHead(m));
            return c == 0 ? MatchResult.NONE : MatchResult.of(c, "Firebase web config (apiKey/authDomain) in page or script");
        } catch (RuntimeException e) {
            return MatchResult.NONE;
        }
    }

    private static String responseHead(MessageContext m) {
        byte[] b = Codecs.decodeContent(m.responseBody(), m.responseHeader("Content-Encoding"));
        if (b == null) return "";
        return new String(b, 0, Math.min(b.length, SNIFF), StandardCharsets.UTF_8);
    }

    // ---------------------------------------------------------------- decoding

    @Override
    public DecodeResult decode(MessageContext m) throws DecodeException {
        Out out = new Out();
        try {
            Variant v = variant(m);
            return switch (v) {
                case FIRESTORE_CHANNEL -> Firestore.decodeChannel(m, out);
                case FIRESTORE_REST -> Firestore.decodeRest(m, out);
                case RTDB_WS -> Rtdb.decodeWs(m, true, out);
                case RTDB_LONGPOLL -> Rtdb.decodeLongPoll(m, out);
                case RTDB_REST -> Rtdb.decodeRest(m, out);
                case IDENTITY_TOOLKIT -> FirebaseAuth.decode(m, false, out);
                case SECURE_TOKEN -> FirebaseAuth.decode(m, true, out);
                case HOSTING_INIT -> m.isResponse() ? FirebaseAuth.decodeConfig(m, out) : notFirebase();
                case NONE -> {
                    if (m.isWebSocket()) yield Rtdb.decodeWs(m, false, out);
                    if (m.isResponse()) yield FirebaseAuth.decodeConfig(m, out);
                    yield notFirebase();
                }
            };
        } catch (DecodeException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new DecodeException("Firebase decode failed: " + e, e);
        }
    }

    private static DecodeResult notFirebase() throws DecodeException {
        throw new DecodeException("Not a recognised Firebase request (expected a Firestore, Realtime Database or Firebase Auth endpoint)");
    }

    // ---------------------------------------------------------------- shared rendering

    /** Adds Firebase-relevant request headers (ID token, App Check token, SDK version, API key) to {@code root}. */
    static void authHeaders(MessageContext m, DecodedNode root, Out out) {
        DecodedNode n = null;
        for (Header h : m.requestHeaders()) {
            if (!FIREBASE_HEADERS.contains(h.name().toLowerCase(Locale.ROOT))) continue;
            if (n == null) n = root.child("Firebase headers");
            n.add(Firestore.headerNode(h.name(), h.value(), out));
            if (h.name().equalsIgnoreCase("x-goog-api-key")) n.add(apiKeyNote());
        }
    }

    /** Adds query parameters to {@code ep}, decoding JWTs and flagging the (public) API key. */
    static void queryParams(MessageContext m, DecodedNode ep, Out out) {
        Map<String, List<String>> q = m.queryParameters();
        if (q.isEmpty()) return;
        DecodedNode qp = ep.child("Query parameters");
        for (Map.Entry<String, List<String>> e : q.entrySet()) {
            for (String v : e.getValue()) {
                if (e.getKey().equals("key")) {
                    qp.put("key — Web API key", v);
                    qp.add(apiKeyNote());
                } else {
                    qp.add(Fb.stringNode(e.getKey(), v, out));
                }
            }
        }
    }

    static DecodedNode apiKeyNote() {
        return DecodedNode.note("Firebase Web API keys are public by design (they identify the project); check key restrictions, Security Rules and App Check instead");
    }
}
