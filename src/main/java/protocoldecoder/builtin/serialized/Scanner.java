package protocoldecoder.builtin.serialized;

import protocoldecoder.builtin.serialized.Sniffer.Detection;
import protocoldecoder.builtin.serialized.Sniffer.Origin;
import protocoldecoder.core.Header;
import protocoldecoder.core.MessageContext;
import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Walks the places serialized data hides in a message (parameters, cookies, headers, body, base64 tokens embedded in
 * the body) and runs the {@link Sniffer} on each, with caps on how many and how large the values are.
 */
final class Scanner {

    /** One recognised payload and where it was found. */
    record Hit(String location, Detection detection) {
    }

    /** What was examined, for the "nothing found" message. */
    static final class Stats {
        int params;
        int cookies;
        int headers;
        boolean body;
        int skipped;

        @Override
        public String toString() {
            List<String> parts = new ArrayList<>();
            if (body) parts.add("body");
            parts.add(params + " parameter" + (params == 1 ? "" : "s"));
            parts.add(cookies + " cookie" + (cookies == 1 ? "" : "s"));
            parts.add(headers + " header" + (headers == 1 ? "" : "s"));
            String s = String.join(", ", parts);
            return skipped > 0 ? s + "; " + skipped + " values skipped by limits" : s;
        }
    }

    static final int MAX_VALUES = 64;
    static final int MAX_HITS = 32;
    private static final int MAX_EMBEDDED = 16;
    private static final int MAX_VALUE_CHARS = 4 * 1024 * 1024;
    private static final int MAX_BODY = 16 * 1024 * 1024;
    private static final int SNIFF_BODY = 256 * 1024;
    private static final int MIN_VALUE = 4;

    static final Set<String> SKIP_HEADERS = Set.of(
            "host", "content-length", "content-type", "accept", "accept-encoding", "accept-language", "accept-charset",
            "user-agent", "connection", "cookie", "set-cookie", "referer", "origin", "date", "cache-control", "pragma",
            "expires", "last-modified", "etag", "if-none-match", "if-modified-since", "server", "vary", "transfer-encoding",
            "content-encoding", "upgrade-insecure-requests", "te", "priority", "keep-alive", "location",
            "content-security-policy", "content-security-policy-report-only", "strict-transport-security",
            "x-content-type-options", "x-frame-options", "x-xss-protection", "alt-svc", "age", "via", "dnt",
            "content-disposition", "content-language", "permissions-policy", "referrer-policy", "report-to", "nel",
            "upgrade", "range", "content-range", "accept-ranges", "link", "x-powered-by", "x-aspnet-version",
            "x-requested-with", "access-control-request-method", "access-control-request-headers");

    /** Base64 tokens with a serialization prefix, at a token boundary. */
    static final Pattern EMBEDDED = Pattern.compile(
            "(?<![A-Za-z0-9+/_%-])(?:rO0AB|H4sIA|AAEAAAD/////|gASV|gAJ|gAN|gAR|gAW|BAh[7\\[IoTFiu\"])[A-Za-z0-9+/_%-]{7,}={0,2}");
    private static final byte[] JAVA_MAGIC = {(byte) 0xAC, (byte) 0xED, 0x00, 0x05};

    private Scanner() {
    }

    static List<Hit> scan(MessageContext m, boolean full, Stats stats) {
        List<Hit> hits = new ArrayList<>();
        int[] budget = {MAX_VALUES};
        Set<String> seen = new HashSet<>();

        if (!m.isWebSocket()) {
            if (m.isRequest()) {
                Map<String, List<String>> query = m.queryParameters();
                params(query, "param", full, hits, stats, budget);
                params(m.formParameters(), "param", full, hits, stats, budget);
                for (Header h : m.requestHeaders()) {
                    if (!h.name().equalsIgnoreCase("Cookie")) continue;
                    for (String part : h.value().split(";")) cookie(part, "cookie", full, hits, stats, budget);
                }
            } else {
                for (Header h : m.responseHeaders()) {
                    if (!h.name().equalsIgnoreCase("Set-Cookie")) continue;
                    String v = h.value();
                    int semi = v.indexOf(';');
                    cookie(semi >= 0 ? v.substring(0, semi) : v, "set-cookie", full, hits, stats, budget);
                }
            }
            for (Header h : m.headers()) {
                String name = h.name().toLowerCase(Locale.ROOT);
                if (SKIP_HEADERS.contains(name) || name.startsWith("sec-") || name.startsWith("access-control-")) continue;
                String v = h.value();
                if (name.equals("authorization") || name.equals("proxy-authorization")) {
                    String lower = v.toLowerCase(Locale.ROOT);
                    if (lower.startsWith("bearer ") || lower.startsWith("token ")) v = v.substring(v.indexOf(' ') + 1);
                    else continue;
                }
                if (v.length() < MIN_VALUE) continue;
                if (!take(budget, stats)) break;
                stats.headers++;
                add(hits, "header: " + h.name(), Sniffer.inspect(cap(v, full), Origin.HEADER, h.name(), full));
            }
        }
        body(m, full, hits, stats);
        // Drop duplicates (the same payload reached through two routes, e.g. a form param and an embedded token).
        List<Hit> unique = new ArrayList<>();
        for (Hit h : hits) {
            Detection d = h.detection();
            String key = d.format() + ":" + (d.payload() != null ? d.payload().length + ":" + Arrays.hashCode(d.payload())
                    : String.valueOf(d.text() == null ? h.location() : d.text().hashCode()));
            if (!full || seen.add(key)) unique.add(h);
            if (unique.size() >= MAX_HITS) break;
        }
        return unique;
    }

    private static void params(Map<String, List<String>> params, String kind, boolean full, List<Hit> hits, Stats stats, int[] budget) {
        for (Map.Entry<String, List<String>> e : params.entrySet()) {
            for (String v : e.getValue()) {
                if (v == null || v.length() < MIN_VALUE) continue;
                if (!take(budget, stats)) return;
                stats.params++;
                add(hits, kind + ": " + e.getKey(), Sniffer.inspect(cap(v, full), Origin.PARAM, e.getKey(), full));
            }
        }
    }

    private static void cookie(String pair, String kind, boolean full, List<Hit> hits, Stats stats, int[] budget) {
        int eq = pair.indexOf('=');
        if (eq <= 0) return;
        String name = pair.substring(0, eq).strip();
        String v = pair.substring(eq + 1).strip();
        if (v.length() < MIN_VALUE) return;
        if (!take(budget, stats)) return;
        stats.cookies++;
        add(hits, kind + ": " + name, Sniffer.inspect(cap(v, full), Origin.COOKIE, name, full));
    }

    private static void body(MessageContext m, boolean full, List<Hit> hits, Stats stats) {
        byte[] raw = m.body();
        if (raw == null || raw.length < 3) return;
        stats.body = true;
        byte[] body = raw;
        String ce = m.isWebSocket() ? null : m.header("Content-Encoding");
        boolean gz = Codecs.isGzip(raw) || (ce != null && ce.toLowerCase(Locale.ROOT).contains("gzip"));
        boolean declaredGzip = gz && ce != null && ce.toLowerCase(Locale.ROOT).contains("gzip");
        if (declaredGzip) {
            // Content-Encoding is transport, not part of the payload: unwrap it first.
            Sniffer.Unzipped u = Sniffer.gunzip(raw, full ? MAX_BODY : SNIFF_BODY);
            if (u != null) body = u.data();
        } else if (!full && body.length > SNIFF_BODY && !Codecs.isGzip(body)) {
            // match: the head is enough for magic checks; keep the last byte for the pickle STOP check
            byte[] head = Arrays.copyOf(body, SNIFF_BODY);
            head[head.length - 1] = body[body.length - 1];
            body = head;
        } else if (body.length > MAX_BODY) {
            body = Arrays.copyOf(body, MAX_BODY);
            stats.skipped++;
        }
        boolean form = m.isRequest() && m.requestContentType().toLowerCase(Locale.ROOT).contains("x-www-form-urlencoded");
        Detection whole = form ? null : Sniffer.inspectBytes(body, Origin.BODY, null, full);
        add(hits, "body", whole);
        if (whole != null && whole.format() != Sniffer.Format.JSON_NET && whole.format() != Sniffer.Format.XML_HINT) return;

        // Tokens embedded in a larger text body (JSF ViewState in HTML, base64 in JSON, multipart parts, ...).
        int limit = Math.min(body.length, full ? MAX_BODY : SNIFF_BODY);
        String text = new String(body, 0, limit, StandardCharsets.ISO_8859_1);
        Matcher mt = EMBEDDED.matcher(text);
        int found = 0;
        while (mt.find() && found < MAX_EMBEDDED) {
            String token = mt.group();
            if (token.length() < 12 || token.length() == text.strip().length()) continue;
            Detection d = Sniffer.inspect(cap(token, full), Origin.EMBEDDED, null, full);
            if (d != null) {
                found++;
                add(hits, "body @" + mt.start(), d);
            }
        }
        // Raw Java stream inside a binary body (e.g. a multipart part).
        int idx = indexOf(body, JAVA_MAGIC, 1, limit);
        if (idx > 0) {
            byte[] payload = full ? Arrays.copyOfRange(body, idx, body.length) : Arrays.copyOfRange(body, idx, Math.min(body.length, idx + 32));
            add(hits, "body @" + idx, new Detection(Sniffer.Format.JAVA, "raw (embedded)", 75, payload, null,
                    "stream starts inside the body; trailing bytes after it may show up as a parse error"));
        }
    }

    private static boolean take(int[] budget, Stats stats) {
        if (budget[0] <= 0) {
            stats.skipped++;
            return false;
        }
        budget[0]--;
        return true;
    }

    private static String cap(String v, boolean full) {
        int max = full ? MAX_VALUE_CHARS : 8192;
        return v.length() > max ? v.substring(0, max) : v;
    }

    private static void add(List<Hit> hits, String location, Detection d) {
        if (d != null && d.confidence() > 0) hits.add(new Hit(location, d));
    }

    private static int indexOf(byte[] b, byte[] needle, int from, int limit) {
        int end = Math.min(b.length, limit) - needle.length;
        outer:
        for (int i = Math.max(0, from); i <= end; i++) {
            for (int j = 0; j < needle.length; j++) if (b[i + j] != needle[j]) continue outer;
            return i;
        }
        return -1;
    }
}
