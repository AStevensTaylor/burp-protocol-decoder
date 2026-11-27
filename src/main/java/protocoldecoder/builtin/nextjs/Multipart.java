package protocoldecoder.builtin.nextjs;

import protocoldecoder.util.Codecs;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Minimal, bounded multipart/form-data parser for Server Action bodies. */
final class Multipart {

    static final int MAX_PARTS = 500;
    private static final Pattern BOUNDARY = Pattern.compile("(?i)boundary=(?:\"([^\"]+)\"|([^;\\s]+))");
    private static final Pattern NAME = Pattern.compile("(?i)\\bname=\"([^\"]*)\"");
    private static final Pattern FILENAME = Pattern.compile("(?i)\\bfilename=\"([^\"]*)\"");

    record Part(String name, String filename, String contentType, byte[] data) {
        String text() {
            return Codecs.utf8(data);
        }
    }

    private Multipart() {
    }

    static String boundary(String contentType, byte[] body) {
        if (contentType != null) {
            Matcher m = BOUNDARY.matcher(contentType);
            if (m.find()) return m.group(1) != null ? m.group(1) : m.group(2);
        }
        // sniff: first line "--boundary"
        String head = Codecs.latin1String(java.util.Arrays.copyOf(body, Math.min(body.length, 256)));
        if (head.startsWith("--")) {
            int e = head.indexOf('\n');
            if (e > 2) return head.substring(2, e).trim();
        }
        return null;
    }

    /** Parses the parts; returns null if this is not multipart data. */
    static List<Part> parse(byte[] body, String contentType) {
        String b = boundary(contentType, body);
        if (b == null || b.isEmpty()) return null;
        String s = Codecs.latin1String(body);
        String delim = "--" + b;
        int i = s.indexOf(delim);
        if (i < 0) return null;
        List<Part> parts = new ArrayList<>();
        while (i >= 0 && parts.size() < MAX_PARTS) {
            int p = i + delim.length();
            if (s.startsWith("--", p)) break;
            if (s.startsWith("\r\n", p)) p += 2;
            else if (s.startsWith("\n", p)) p += 1;
            int hdrEnd = s.indexOf("\r\n\r\n", p);
            int bodyStart;
            if (hdrEnd >= 0) {
                bodyStart = hdrEnd + 4;
            } else {
                hdrEnd = s.indexOf("\n\n", p);
                if (hdrEnd < 0) break;
                bodyStart = hdrEnd + 2;
            }
            String headers = s.substring(p, hdrEnd);
            int next = s.indexOf(delim, bodyStart);
            int dataEnd = next < 0 ? s.length() : next;
            if (dataEnd >= 2 && s.startsWith("\r\n", dataEnd - 2) && dataEnd - 2 >= bodyStart) dataEnd -= 2;
            else if (dataEnd >= 1 && s.charAt(dataEnd - 1) == '\n' && dataEnd - 1 >= bodyStart) dataEnd -= 1;
            String name = null, filename = null, ct = null;
            for (String line : headers.split("\r?\n")) {
                String l = line.toLowerCase(Locale.ROOT);
                if (l.startsWith("content-disposition:")) {
                    Matcher nm = NAME.matcher(line);
                    if (nm.find()) name = new String(Codecs.latin1Bytes(nm.group(1)), java.nio.charset.StandardCharsets.UTF_8);
                    Matcher fm = FILENAME.matcher(line);
                    if (fm.find()) filename = new String(Codecs.latin1Bytes(fm.group(1)), java.nio.charset.StandardCharsets.UTF_8);
                } else if (l.startsWith("content-type:")) {
                    ct = line.substring(13).trim();
                }
            }
            parts.add(new Part(name == null ? "" : name, filename, ct, Codecs.latin1Bytes(s.substring(bodyStart, dataEnd))));
            i = next;
        }
        return parts;
    }
}
