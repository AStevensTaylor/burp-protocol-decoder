package protocoldecoder.builtin.newrelic;

import protocoldecoder.core.DecodedNode;

import java.util.ArrayList;
import java.util.List;

/**
 * Structural decoder for the New Relic browser agent's compact "BEL" serialisation ({@code bel.<version>;...}). Records
 * are separated by {@code ;} and fields by {@code ,}. Strings are prefixed with {@code '}; numbers are base-36. The
 * agent does not document field meanings, so this shows structure and decodes the token types only.
 */
final class Bel {

    private static final int MAX_RECORDS = 5000;

    private Bel() {
    }

    static DecodedNode decode(String text) {
        DecodedNode n = DecodedNode.object("BEL payload");
        List<String> records = split(text, ';');
        if (!records.isEmpty()) n.put("Format", records.get(0));
        DecodedNode recs = DecodedNode.array("Records");
        for (int i = 1; i < records.size() && i <= MAX_RECORDS; i++) {
            String rec = records.get(i);
            if (rec.isEmpty()) continue;
            DecodedNode r = DecodedNode.array("[" + (i - 1) + "]");
            for (String field : split(rec, ',')) r.add(token(field));
            recs.add(r);
        }
        n.add(recs);
        return n;
    }

    private static DecodedNode token(String f) {
        if (f.startsWith("'")) return DecodedNode.leaf("string", f.substring(1));
        if (f.equals("!")) return DecodedNode.leaf("bool", "true", DecodedNode.Type.BOOLEAN);
        if (f.isEmpty()) return DecodedNode.leaf("empty", "", DecodedNode.Type.NULL);
        if (f.matches("-?[0-9a-z]{1,12}")) {
            try {
                return DecodedNode.leaf("b36 " + f, Long.toString(Long.parseLong(f, 36)), DecodedNode.Type.NUMBER);
            } catch (NumberFormatException ignored) {
                // fall through
            }
        }
        return DecodedNode.leaf("raw", f);
    }

    /** Splits on sep, honouring backslash escapes. */
    private static List<String> split(String s, char sep) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                cur.append(s.charAt(++i));
            } else if (c == sep) {
                out.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        out.add(cur.toString());
        return out;
    }
}
