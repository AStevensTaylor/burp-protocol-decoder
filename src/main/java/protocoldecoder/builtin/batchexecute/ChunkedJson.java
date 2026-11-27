package protocoldecoder.builtin.batchexecute;

import com.google.gson.JsonElement;
import protocoldecoder.util.JsLiteral;
import protocoldecoder.util.JsonTree;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser for Google's length-prefixed JSON streams ({@code <length>\n<json><length>\n<json>…}), used by batchexecute
 * ({@code rt=c}) and by the Closure WebChannel backchannel (Firestore).
 *
 * <p>The declared length is only a hint: servers count UTF-16 code units, proxies re-encode, and some streams include
 * or exclude the trailing newline. Each chunk is therefore delimited by bracket matching from its first '[' / '{',
 * and the declared length is only checked (with a warning on a real mismatch). When the input stops looking like
 * {@code digits\n}, the parser resynchronises on the next {@code \n<digits>\n[} it can find.</p>
 */
public final class ChunkedJson {

    public static final int MAX_CHUNKS = 2000;
    private static final Pattern RESYNC = Pattern.compile("\n(\\d{1,9})\r?\n\\s*[\\[{]");

    private ChunkedJson() {
    }

    /** One chunk. {@code json} is null when the chunk text did not parse. */
    public record Chunk(int offset, int declaredLength, String raw, JsonElement json) {
    }

    /** Parsed chunks plus non-fatal problems (resyncs, length mismatches, incomplete chunks). */
    public record Result(List<Chunk> chunks, List<String> warnings) {
    }

    /** True if, after whitespace, {@code s} at {@code pos} starts with {@code <digits>\n}. */
    public static boolean looksChunked(String s, int pos) {
        int i = skipWs(s, pos);
        int d = i;
        while (d < s.length() && d - i < 10 && isDigit(s.charAt(d))) d++;
        if (d == i || d - i >= 10) return false;
        if (d < s.length() && s.charAt(d) == '\r') d++;
        return d < s.length() && s.charAt(d) == '\n';
    }

    public static Result parse(String s, int start) {
        List<Chunk> chunks = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        int n = s.length();
        int pos = start;
        while (true) {
            pos = skipWs(s, pos);
            if (pos >= n) break;
            if (chunks.size() >= MAX_CHUNKS) {
                warnings.add("stopped after " + MAX_CHUNKS + " chunks; " + (n - pos) + " chars not shown");
                break;
            }
            int d = pos;
            while (d < n && d - pos < 10 && isDigit(s.charAt(d))) d++;
            int nl = d;
            if (nl < n && s.charAt(nl) == '\r') nl++;
            if (d == pos || d - pos >= 10 || nl >= n || s.charAt(nl) != '\n') {
                int next = resync(s, pos);
                if (next < 0) {
                    warnings.add("unparseable data at offset " + pos + " (" + (n - pos) + " chars); no further length-prefixed chunk found");
                    break;
                }
                warnings.add("resynchronised: skipped " + (next - pos) + " chars at offset " + pos);
                pos = next;
                continue;
            }
            int declared = Integer.parseInt(s.substring(pos, d));
            int bodyStart = nl + 1;
            int js = skipWs(s, bodyStart);
            int end;
            String raw;
            if (js < n && (s.charAt(js) == '[' || s.charAt(js) == '{')) {
                end = JsLiteral.matchBracket(s, js);
                if (end < 0) {
                    raw = s.substring(js);
                    warnings.add("chunk at offset " + pos + " is incomplete (declared " + declared + " chars, "
                            + (n - bodyStart) + " available)");
                    chunks.add(new Chunk(pos, declared, raw, null));
                    break;
                }
                raw = s.substring(js, end);
                if (!lengthPlausible(declared, s, bodyStart, end)) {
                    warnings.add("chunk at offset " + pos + ": declared length " + declared + " but JSON spans "
                            + (end - bodyStart) + " chars");
                }
            } else {
                end = (int) Math.min(n, (long) bodyStart + declared);
                raw = s.substring(bodyStart, end);
                if ((long) bodyStart + declared > n) {
                    warnings.add("chunk at offset " + pos + " is incomplete (declared " + declared + " chars, "
                            + (n - bodyStart) + " available)");
                }
            }
            JsonElement j = JsonTree.parseStrict(raw);
            if (j == null) j = JsonTree.parseLenient(raw);
            if (j == null) warnings.add("chunk at offset " + pos + " is not valid JSON");
            chunks.add(new Chunk(pos, declared, raw, j));
            pos = Math.max(end, pos + 1);
        }
        return new Result(chunks, warnings);
    }

    private static boolean lengthPlausible(int declared, String s, int bodyStart, int end) {
        int chars = end - bodyStart;
        // allow for a trailing newline being counted or not, and for CRLF line ends
        if (Math.abs(declared - chars) <= 2) return true;
        int bytes = s.substring(bodyStart, end).getBytes(StandardCharsets.UTF_8).length;
        if (Math.abs(declared - bytes) <= 2) return true;
        int cps = s.codePointCount(bodyStart, end);
        return Math.abs(declared - cps) <= 2;
    }

    private static int resync(String s, int from) {
        Matcher m = RESYNC.matcher(s);
        int f = Math.max(0, from);
        return m.find(f) ? m.start(1) : -1;
    }

    static int skipWs(String s, int i) {
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        return i;
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }
}
