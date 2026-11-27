package protocoldecoder.builtin.serialized;

import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Low-confidence detectors for type-carrying text formats (Json.NET {@code $type}, DataContract / NetDataContract /
 * XmlSerializer / SoapFormatter / XMLDecoder type hints) and an informational view of ASP.NET ViewState
 * (ObjectStateFormatter / LosFormatter) data.
 */
final class TypeHints {

    private static final int MAX_HITS = 50;
    private static final int SCAN_LIMIT = 2 * 1024 * 1024;

    static final Pattern JSON_TYPE = Pattern.compile("\"\\$type\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.){1,1000})\"");

    /** XML hint kinds with their match pattern (group 1 = type name when present) and confidence. */
    private record XmlHint(String label, Pattern pattern, int confidence) {
    }

    private static final List<XmlHint> XML_HINTS = List.of(
            new XmlHint("NetDataContractSerializer z:Type", Pattern.compile("\\bz:Type=\"([^\"]{1,500})\""), 30),
            new XmlHint("NetDataContractSerializer z:Assembly", Pattern.compile("\\bz:Assembly=\"([^\"]{1,500})\""), 30),
            new XmlHint("SoapFormatter CLR namespace", Pattern.compile("xmlns:\\w+=\"http://schemas\\.microsoft\\.com/clr/(?:nsassem|ns|assem)/([^\"]{1,500})\""), 30),
            new XmlHint("XAML ObjectDataProvider", Pattern.compile("<(?:\\w+:)?(ObjectDataProvider)\\b"), 30),
            new XmlHint("ExpandedWrapper type", Pattern.compile("(ExpandedWrapperOf\\w{1,200})"), 30),
            new XmlHint("Java XMLDecoder", Pattern.compile("<java\\b[^>]{0,200}class=\"(java\\.beans\\.XMLDecoder)\""), 30),
            new XmlHint("XmlSerializer type attribute", Pattern.compile("\\btype=\"((?:System|Microsoft)\\.[^\"]{1,500})\""), 25),
            new XmlHint("DataContract namespace", Pattern.compile("xmlns(?::\\w+)?=\"http://schemas\\.datacontract\\.org/2004/07/([^\"]{0,500})\""), 20),
            new XmlHint("xsi/i:type", Pattern.compile("\\b(?:xsi|i):type=\"([^\"]{1,500})\""), 20)
    );

    private TypeHints() {
    }

    /** Cheap check for Json.NET type hints in JSON text. */
    static boolean hasJsonType(String s) {
        if (s.isEmpty()) return false;
        char c = s.charAt(0);
        return (c == '{' || c == '[') && s.contains("\"$type\"");
    }

    static ParseOutput jsonNet(String text) {
        ParseOutput out = new ParseOutput("Json.NET type hints");
        out.typeNoun = "types";
        Matcher m = JSON_TYPE.matcher(cap(text));
        int hits = 0;
        while (m.find() && hits++ < MAX_HITS) {
            String type = m.group(1).replace("\\\\", "\\").replace("\\\"", "\"");
            out.type(type);
            String r = RiskyTypes.reason(type);
            out.structure.add(DecodedNode.leaf("$type @" + m.start(), type + (r != null ? "  ⚠ " + r : "")));
        }
        out.notes.add("Json.NET honours $type only when TypeNameHandling is not None; check the server configuration");
        return out;
    }

    /** Highest XML hint confidence for the text, or 0. */
    static int xmlConfidence(String s) {
        if (s.isEmpty() || s.charAt(0) != '<' || isHtml(s)) return 0;
        String t = s.length() > 64 * 1024 ? s.substring(0, 64 * 1024) : s;
        int best = 0;
        for (XmlHint h : XML_HINTS) {
            if (h.confidence > best && h.pattern.matcher(t).find()) best = h.confidence;
        }
        return best;
    }

    static boolean isHtml(String s) {
        String head = s.substring(0, Math.min(s.length(), 200)).toLowerCase(java.util.Locale.ROOT);
        return head.startsWith("<!doctype html") || head.startsWith("<html") || head.contains("<head") || head.contains("<body");
    }

    static ParseOutput xml(String text) {
        ParseOutput out = new ParseOutput("XML type hints");
        out.typeNoun = "types";
        String t = cap(text);
        int hits = 0;
        for (XmlHint h : XML_HINTS) {
            Matcher m = h.pattern.matcher(t);
            while (m.find() && hits++ < MAX_HITS) {
                String type = m.groupCount() >= 1 && m.group(1) != null ? m.group(1) : m.group();
                out.type(type);
                String r = RiskyTypes.reason(type);
                out.structure.add(DecodedNode.leaf(h.label + " @" + m.start(), type + (r != null ? "  ⚠ " + r : "")));
            }
        }
        return out;
    }

    /** ObjectStateFormatter / LosFormatter: informational only, nested BinaryFormatter payloads are parsed. */
    static ParseOutput viewState(byte[] data, ParseOutput.Budget budget) {
        ParseOutput out = new ParseOutput("ViewState");
        out.typeNoun = "types";
        out.structure.put("format", "ObjectStateFormatter (marker FF 01)");
        out.structure.put("size", data.length + " bytes");
        out.structure.add(DecodedNode.note("Pick the 'ASP.NET ViewState' decoder in the Decoder picker (or Burp's ViewState tab) to view this data in full; "
                + "check whether MAC validation (EnableViewStateMac) is enforced."));
        List<String> strings = printableStrings(data, 4, 40);
        if (!strings.isEmpty()) {
            DecodedNode s = DecodedNode.array("Embedded strings");
            for (String str : strings) s.add(DecodedNode.leaf("", str));
            out.structure.add(s);
        }
        int nested = NrbfParser.find(data, 0);
        if (nested >= 0) {
            out.notes.add("contains a BinaryFormatter (NRBF) payload at offset " + nested);
            ParseOutput inner = NrbfParser.parse(data, nested, budget);
            DecodedNode n = DecodedNode.object("Nested BinaryFormatter @" + nested);
            n.add(inner.structure);
            inner.extras.forEach(n::add);
            out.structure.add(n);
            inner.types.forEach(out::type);
            if (!inner.complete) out.notes.add("nested BinaryFormatter parse stopped: " + inner.stopReason);
        }
        return out;
    }

    static List<String> printableStrings(byte[] b, int min, int max) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        for (byte x : b) {
            int c = x & 0xff;
            if (c >= 0x20 && c < 0x7f) {
                cur.append((char) c);
            } else {
                if (cur.length() >= min) out.add(Codecs.truncate(cur.toString(), 200));
                cur.setLength(0);
                if (out.size() >= max) return out;
            }
        }
        if (cur.length() >= min && out.size() < max) out.add(Codecs.truncate(cur.toString(), 200));
        return out;
    }

    private static String cap(String s) {
        return s.length() > SCAN_LIMIT ? s.substring(0, SCAN_LIMIT) : s;
    }

    static String utf8(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }
}
