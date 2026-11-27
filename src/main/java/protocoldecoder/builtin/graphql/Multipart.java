package protocoldecoder.builtin.graphql;

import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Minimal multipart (form-data / mixed) splitter for GraphQL uploads and incremental-delivery responses. */
final class Multipart {

    static final int MAX_PARTS = 1000;
    private static final Pattern BOUNDARY = Pattern.compile("(?i)boundary=(\"([^\"]*)\"|[^;\\s]+)");
    private static final Pattern DISPOSITION_PARAM = Pattern.compile("(?i);\\s*(name|filename)=(\"((?:[^\"\\\\]|\\\\.)*)\"|[^;\\s]+)");

    record Part(String name, String filename, String contentType, byte[] body) {
        String text() {
            return new String(body, StandardCharsets.UTF_8);
        }
    }

    private Multipart() {
    }

    static String boundary(String contentType) {
        if (contentType == null) return null;
        Matcher m = BOUNDARY.matcher(contentType);
        if (!m.find()) return null;
        String b = m.group(2) != null ? m.group(2) : m.group(1);
        return b.isEmpty() ? null : b;
    }

    /** Splits the body into parts. Returns an empty list if the boundary never occurs. */
    static List<Part> parse(byte[] body, String boundary) {
        List<Part> parts = new ArrayList<>();
        if (boundary == null || body == null) return parts;
        String s = Codecs.latin1String(body);
        String delim = "--" + boundary;
        int i = s.indexOf(delim);
        while (i >= 0 && parts.size() < MAX_PARTS) {
            int start = i + delim.length();
            if (s.startsWith("--", start)) break; // closing delimiter
            int next = s.indexOf(delim, start);
            int end = next < 0 ? s.length() : next;
            String raw = s.substring(start, end);
            raw = stripLeadingNewline(raw);
            if (raw.endsWith("\r\n")) raw = raw.substring(0, raw.length() - 2);
            else if (raw.endsWith("\n")) raw = raw.substring(0, raw.length() - 1);
            int sep = raw.indexOf("\r\n\r\n");
            int sepLen = 4;
            int lf = raw.indexOf("\n\n");
            if (sep < 0 || (lf >= 0 && lf < sep)) {
                sep = lf;
                sepLen = 2;
            }
            String headers = sep < 0 ? "" : raw.substring(0, sep);
            String content = sep < 0 ? raw : raw.substring(sep + sepLen);
            String name = null, filename = null, ct = null;
            for (String h : headers.split("\r?\n")) {
                int c = h.indexOf(':');
                if (c < 0) continue;
                String hn = h.substring(0, c).trim().toLowerCase(Locale.ROOT);
                String hv = h.substring(c + 1).trim();
                if (hn.equals("content-type")) ct = hv;
                if (hn.equals("content-disposition")) {
                    Matcher m = DISPOSITION_PARAM.matcher(hv);
                    while (m.find()) {
                        String v = m.group(3) != null ? m.group(3) : m.group(2);
                        v = new String(Codecs.latin1Bytes(v), StandardCharsets.UTF_8);
                        if (m.group(1).equalsIgnoreCase("name")) name = v;
                        else filename = v;
                    }
                }
            }
            parts.add(new Part(name, filename, ct, Codecs.latin1Bytes(content)));
            if (next < 0) break;
            i = next;
        }
        return parts;
    }

    private static String stripLeadingNewline(String s) {
        // Skip transport padding up to the end of the delimiter line.
        int nl = s.indexOf('\n');
        if (nl >= 0 && s.substring(0, nl).isBlank()) return s.substring(nl + 1);
        return s;
    }
}
