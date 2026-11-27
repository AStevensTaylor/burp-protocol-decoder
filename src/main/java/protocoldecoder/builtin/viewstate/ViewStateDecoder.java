package protocoldecoder.builtin.viewstate;

import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.ProtocolDecoder;
import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * ASP.NET WebForms page state: {@code __VIEWSTATE} (including split {@code __VIEWSTATE1..N}),
 * {@code __EVENTVALIDATION}, {@code __VIEWSTATEGENERATOR} and friends, in form posts, HTML hidden inputs and ASP.NET
 * AJAX delta responses.
 *
 * <p>The ObjectStateFormatter stream is parsed structurally (never deserialized). The main pentest value is the MAC /
 * encryption analysis: whether a MAC follows the serialized graph (and its likely algorithm from its length), or
 * whether the blob is encrypted. No key guessing or brute force is attempted.</p>
 */
public final class ViewStateDecoder implements ProtocolDecoder {

    public static final String ID = "viewstate";

    /** Request bodies / response bodies scanned by {@link #match}. */
    private static final int REQUEST_SCAN = 2 * 1024 * 1024;
    private static final int RESPONSE_SCAN = 1024 * 1024;
    private static final int MAX_FIELDS = 1000;

    private static final byte[] VS = ascii("__VIEWSTATE");
    private static final byte[] VS_FORM = ascii("__VIEWSTATE=");
    private static final byte[] VS_MULTIPART = ascii("name=\"__VIEWSTATE\"");
    private static final byte[] EV_FORM = ascii("__EVENTVALIDATION=");
    private static final byte[] VS_DELTA = ascii("|hiddenField|__VIEWSTATE|");
    private static final byte[] VS_QUOTED = ascii("\"__VIEWSTATE\"");

    @Override public String id() { return ID; }
    @Override public String name() { return "ASP.NET ViewState"; }
    @Override public String description() {
        return "ASP.NET __VIEWSTATE / __EVENTVALIDATION (ObjectStateFormatter, legacy LosFormatter) with MAC and encryption analysis";
    }

    // ---------------------------------------------------------------- matching

    @Override
    public MatchResult match(MessageContext m) {
        try {
            if (m.isWebSocket()) return MatchResult.NONE;
            if (m.isRequest()) {
                byte[] body = m.requestBody();
                int n = Math.min(body.length, REQUEST_SCAN);
                if (indexOf(body, n, VS) >= 0) {
                    if (indexOf(body, n, VS_FORM) >= 0) return MatchResult.of(60, "POST with __VIEWSTATE form field");
                    if (indexOf(body, n, VS_MULTIPART) >= 0) return MatchResult.of(60, "multipart POST with __VIEWSTATE field");
                }
                if (m.query().contains("__VIEWSTATE=")) return MatchResult.of(50, "__VIEWSTATE query parameter");
                if (indexOf(body, n, EV_FORM) >= 0) return MatchResult.of(40, "POST with __EVENTVALIDATION form field");
                return MatchResult.NONE;
            }
            byte[] body = m.responseBody();
            int n = Math.min(body.length, RESPONSE_SCAN);
            int at = indexOf(body, n, VS);
            if (at < 0) return MatchResult.NONE;
            if (indexOf(body, n, VS_DELTA) >= 0) return MatchResult.of(30, "__VIEWSTATE in ASP.NET AJAX delta response");
            if (indexOf(body, n, VS_QUOTED) >= 0) return MatchResult.of(35, "__VIEWSTATE hidden input in page");
            return MatchResult.NONE;
        } catch (RuntimeException e) {
            return MatchResult.NONE;
        }
    }

    private static int indexOf(byte[] hay, int limit, byte[] needle) {
        outer:
        for (int i = 0, last = limit - needle.length; i <= last; i++) {
            if (hay[i] != needle[0]) continue;
            for (int j = 1; j < needle.length; j++) if (hay[i + j] != needle[j]) continue outer;
            return i;
        }
        return -1;
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    // ---------------------------------------------------------------- decoding

    @Override
    public DecodeResult decode(MessageContext m) throws DecodeException {
        String source;
        Map<String, String> fields = StateFields.newMap();
        if (m.isRequest()) {
            source = "form field";
            String body = m.requestBodyText();
            StateFields.fromParams(m.queryParameters(), fields);
            String ct = m.requestContentType().toLowerCase(Locale.ROOT);
            if (ct.contains("multipart/")) {
                StateFields.fromMultipart(body, fields);
            } else if (!body.isEmpty() && body.indexOf('=') > 0) {
                StateFields.fromParams(Codecs.parseQuery(body), fields); // also when Content-Type is missing/wrong
            }
            if (fields.isEmpty() && body.contains("Content-Disposition")) StateFields.fromMultipart(body, fields);
        } else {
            source = "hidden input";
            byte[] raw = m.isResponse() ? Codecs.decodeContent(m.responseBody(), m.responseHeader("Content-Encoding")) : m.body();
            String body = Codecs.utf8(raw);
            if (body.contains("|hiddenField|")) {
                StateFields.fromDelta(body, fields);
                if (!fields.isEmpty()) source = "AJAX delta hiddenField";
            }
            StateFields.fromHtml(body, fields);
        }
        if (!fields.containsKey("__VIEWSTATE") && !fields.containsKey("__EVENTVALIDATION")) {
            // Forced on a bare blob (e.g. a value pasted into a request body or a WebSocket message).
            String t = (m.isResponse() ? m.responseBodyText() : m.bodyText()).strip();
            byte[] b = t.length() <= 16 * 1024 * 1024 && t.length() >= 4 ? Codecs.base64Decode(t.replace(' ', '+')) : null;
            if (b != null && (ObjectStateReader.hasMarker(b) || LosTextReader.looksLike(b))) {
                fields.put("__VIEWSTATE", t);
                source = "raw body";
            }
        }
        if (!fields.containsKey("__VIEWSTATE") && !fields.containsKey("__EVENTVALIDATION")) {
            throw new DecodeException("No __VIEWSTATE or __EVENTVALIDATION found in this message");
        }

        List<String> warnings = new ArrayList<>();
        DecodedNode root = DecodedNode.object("ASP.NET page state");
        DecodedNode fieldsNode = root.child("Fields");
        int shown = 0;
        for (Map.Entry<String, String> e : fields.entrySet()) {
            if (++shown > MAX_FIELDS) break;
            String v = e.getValue();
            fieldsNode.add(DecodedNode.leaf(e.getKey(), v.length() > 120 ? Codecs.truncate(v, 120) : v));
        }

        List<String> summary = new ArrayList<>();
        boolean encryptedFlag = fields.containsKey("__VIEWSTATEENCRYPTED");

        String vs = joinSplit(fields, warnings);
        if (vs != null) {
            String src = source + (fields.containsKey("__VIEWSTATEFIELDCOUNT") ? ", split across " + fields.get("__VIEWSTATEFIELDCOUNT") + " fields" : "");
            summary.add(analyse(root, "ViewState", vs, src, encryptedFlag, warnings));
        }
        String ev = fields.get("__EVENTVALIDATION");
        if (ev != null) summary.add(analyse(root, "EventValidation", ev, source, encryptedFlag, warnings));

        String gen = fields.get("__VIEWSTATEGENERATOR");
        if (gen != null) {
            DecodedNode g = root.child("Generator");
            g.put("__VIEWSTATEGENERATOR", gen);
            String hex = gen.strip();
            if (hex.matches("[0-9A-Fa-f]{1,8}")) {
                long v = Long.parseLong(hex, 16);
                g.put("Value", "0x" + hex.toUpperCase(Locale.ROOT) + " = " + v + " (signed " + (int) v + ")");
                g.put("Meaning", "Page type hash (from the page class and application path). ASP.NET uses it as the "
                        + "modifier when computing/validating the ViewState MAC in legacy (pre-4.5) mode.");
            } else {
                g.put("Meaning", "Unexpected format (normally 8 hex digits)");
            }
        }
        if (encryptedFlag) {
            root.child("Encryption").put("__VIEWSTATEENCRYPTED", "present: page state is encrypted (ViewStateEncryptionMode / machineKey)");
        }
        String prev = fields.get("__PREVIOUSPAGE");
        if (prev != null) {
            DecodedNode p = root.child("PreviousPage");
            p.put("Value", Codecs.truncate(prev, 200));
            p.put("Length", prev.length());
            p.put("Meaning", "Cross-page postback source path, encrypted with the machineKey (not decodable without it)");
        }
        String cs = fields.get("__CONTROLSTATE");
        if (cs != null) summary.add(analyse(root, "ControlState", cs, source, encryptedFlag, warnings));

        return new DecodeResult(String.join("; ", summary), root, null, warnings);
    }

    /** {@code __VIEWSTATE} + {@code __VIEWSTATE1} … {@code __VIEWSTATE(N-1)} when {@code __VIEWSTATEFIELDCOUNT=N}. */
    static String joinSplit(Map<String, String> fields, List<String> warnings) {
        String first = fields.get("__VIEWSTATE");
        String countStr = fields.get("__VIEWSTATEFIELDCOUNT");
        if (countStr == null) {
            if (first == null || !fields.containsKey("__VIEWSTATE1")) return first;
            countStr = "";
        }
        int count;
        try {
            count = Integer.parseInt(countStr.strip());
        } catch (NumberFormatException e) {
            count = -1;
        }
        StringBuilder sb = new StringBuilder(first == null ? "" : first);
        if (first == null) warnings.add("__VIEWSTATEFIELDCOUNT present but __VIEWSTATE (first chunk) is missing");
        int max = count > 0 ? Math.min(count, MAX_FIELDS) : MAX_FIELDS;
        for (int i = 1; i < max; i++) {
            String part = fields.get("__VIEWSTATE" + i);
            if (part == null) {
                if (count > 0) warnings.add("Split ViewState: __VIEWSTATE" + i + " missing (expected " + count + " chunks); result is incomplete");
                break;
            }
            sb.append(part);
        }
        if (count <= 0 && countStr.length() > 0) warnings.add("Invalid __VIEWSTATEFIELDCOUNT '" + countStr + "'");
        return sb.toString();
    }

    // ---------------------------------------------------------------- analysis

    /** Decodes one state blob into a child of {@code root}; returns its summary fragment. */
    private String analyse(DecodedNode root, String label, String b64, String source, boolean encryptedFlag, List<String> warnings) {
        DecodedNode n = root.child(label);
        n.put("Source", source);
        n.put("Base64 length", b64.length());
        if (b64.isBlank()) {
            n.put("Status", "empty");
            return label + ": empty";
        }
        byte[] bytes = Codecs.base64Decode(b64.replace(' ', '+'));
        if (bytes == null) {
            n.put("Status", "not valid base64");
            warnings.add(label + " is not valid base64");
            return label + ": invalid base64";
        }
        n.put("Decoded bytes", bytes.length);
        String head = label + " (" + bytes.length + " bytes)";

        if (ObjectStateReader.hasMarker(bytes)) {
            n.put("Format", "ObjectStateFormatter v1 (FF 01)");
            ObjectStateReader.Result r = ObjectStateReader.parse(bytes);
            n.add(r.graph());
            if (label.equals("ViewState")) describePage(n, r.graph());
            if (!r.strings().isEmpty()) {
                DecodedNode st = DecodedNode.array("String table (" + r.strings().size() + ")");
                for (int i = 0; i < r.strings().size(); i++) st.add(DecodedNode.leaf("[" + i + "]", Codecs.truncate(r.strings().get(i), 500)));
                n.add(st);
            }
            if (!r.types().isEmpty()) {
                DecodedNode tt = DecodedNode.array("Type table (" + r.types().size() + ")");
                for (int i = 0; i < r.types().size(); i++) tt.add(DecodedNode.leaf("[" + i + "]", r.types().get(i)));
                n.add(tt);
            }
            for (ObjectStateReader.BinaryBlob blob : r.blobs()) {
                warnings.add(label + " contains a BinarySerialized (BinaryFormatter) blob of " + blob.length() + " bytes at offset "
                        + blob.offset() + " — server-side BinaryFormatter deserialization sink"
                        + (blob.gadgets().isEmpty() ? "" : " (gadget markers: " + String.join(", ", blob.gadgets()) + ")"));
            }
            StringBuilder s = new StringBuilder(head).append(": ");
            if (r.eventValidationHashes() >= 0) s.append(r.eventValidationHashes()).append(" hashes, ");
            else s.append(r.objects()).append(" objects, ");
            if (!r.complete()) {
                warnings.add(label + " parse stopped: " + r.error() + "; showing partial tree");
                n.add(DecodedNode.leaf("MAC", "unknown (stream could not be fully parsed)"));
                s.append("partial parse ⚠");
                return s.toString();
            }
            s.append(mac(n, label, bytes, r.end(), warnings, true));
            if (!r.blobs().isEmpty()) s.append(", BinaryFormatter blob ⚠");
            return s.toString();
        }

        if (LosTextReader.looksLike(bytes)) {
            n.put("Format", "Legacy LosFormatter text (ASP.NET 1.x)");
            LosTextReader.Result r = LosTextReader.parse(bytes);
            n.add(r.graph());
            if (r.binarySerialized()) warnings.add(label + " (legacy) contains a BinaryFormatter blob — deserialization sink");
            if (!r.complete()) {
                warnings.add(label + " (legacy LosFormatter) parse stopped: " + r.error() + "; showing partial tree");
                return head + ": legacy LosFormatter, partial parse ⚠";
            }
            return head + ": legacy LosFormatter, " + r.objects() + " objects, " + mac(n, label, bytes, r.end(), warnings, false);
        }

        // Not a known plain-text format.
        double entropy = entropy(bytes);
        DecodedNode enc = n.child("Encryption analysis");
        enc.put("First bytes", Codecs.hexPreview(bytes, 16));
        enc.put("Entropy (bits/byte)", String.format(Locale.ROOT, "%.2f", entropy));
        enc.put("Block-aligned (16)", bytes.length % 16 == 0);
        enc.put("__VIEWSTATEENCRYPTED", encryptedFlag ? "present" : "absent");
        // Random data approaches log2(min(n, 256)) bits per byte.
        boolean random = entropy > 0.8 * (Math.log(Math.min(bytes.length, 256)) / Math.log(2));
        if (random || encryptedFlag) {
            n.put("Format", "encrypted (ViewStateEncryptionMode / machineKey)");
            enc.put("Assessment", "Looks encrypted (and, on .NET 4.5+, signed). Contents and MAC cannot be inspected without the machineKey.");
            warnings.add(label + " is encrypted (ViewStateEncryptionMode / machineKey), " + bytes.length + " bytes; not decodable without the key");
            return head + ": encrypted";
        }
        n.put("Format", "unrecognised (no FF 01 marker)");
        n.add(DecodedNode.leaf("Hex", Codecs.hexPreview(bytes, 64), DecodedNode.Type.BINARY));
        warnings.add(label + " does not start with the ObjectStateFormatter marker FF 01 and does not look encrypted");
        return head + ": unrecognised format";
    }

    /** MAC heuristics on the bytes left after the serialized graph. */
    private static String mac(DecodedNode n, String label, byte[] bytes, int end, List<String> warnings, boolean modern) {
        int trailing = bytes.length - end;
        DecodedNode mac = n.child("MAC");
        mac.put("Serialized data ends at", end);
        mac.put("Trailing bytes", trailing);
        if (trailing == 0) {
            mac.put("Status", "No MAC");
            if (label.equals("EventValidation")) {
                warnings.add("EventValidation: No MAC — EnableViewStateMac appears disabled (event validation data can be forged)");
            } else {
                warnings.add(label + ": No MAC — EnableViewStateMac appears disabled (possible deserialization RCE if exploitable)");
            }
            return "no MAC ⚠";
        }
        String alg = switch (trailing) {
            case 16 -> "MD5 (legacy)";
            case 20 -> "HMACSHA1";
            case 32 -> "HMACSHA256";
            case 48 -> "HMACSHA384";
            case 64 -> "HMACSHA512";
            default -> null;
        };
        mac.add(DecodedNode.leaf("Bytes", Codecs.hexPreview(java.util.Arrays.copyOfRange(bytes, end, bytes.length), 64), DecodedNode.Type.BINARY));
        if (alg == null) {
            mac.put("Status", "Unrecognised trailing data (" + trailing + " bytes)");
            warnings.add(label + ": " + trailing + " unexpected trailing bytes after the serialized data (not a standard MAC length)");
            return "unrecognised trailer (" + trailing + " bytes) ⚠";
        }
        mac.put("Status", "MAC present (likely " + alg + ", " + trailing + " bytes)");
        if (modern && trailing == 32) {
            mac.put("Note", "HMACSHA256 is the default validation algorithm on .NET 4.x; on 4.5+ (non-legacy) the key is derived with purposes");
        }
        warnings.add(label + ": MAC present (likely " + alg + ", " + trailing + " bytes)");
        return "MAC present (" + alg + ")";
    }

    /** Points out the conventional Page layout: Pair(Pair(typeHash, controlTree), controlState). */
    private static void describePage(DecodedNode n, DecodedNode graph) {
        if (!"Pair".equals(graph.value())) return;
        DecodedNode first = graph.get("First");
        if (first == null || !"Pair".equals(first.value())) return;
        DecodedNode hash = first.get("First");
        DecodedNode page = n.child("Page structure");
        if (hash != null && hash.value() != null && hash.value().matches("-?\\d{1,11}")) {
            page.put("Page type hash (GetTypeHashCode)", hash.value());
        }
        DecodedNode tree = first.get("Second");
        if (tree != null) page.put("Control tree", "Root → First → Second (" + countControls(tree, 0) + " control state entries)");
        DecodedNode cs = graph.get("Second");
        if (cs != null) page.put("Control state", cs.value() == null ? "none" : "Root → Second (" + cs.value() + ")");
    }

    /** Counts Pair/Triplet nodes, which is how controls persist their view state and child-state lists. */
    private static int countControls(DecodedNode node, int depth) {
        if (depth > ObjectStateReader.MAX_DEPTH) return 0;
        int c = "Pair".equals(node.value()) || "Triplet".equals(node.value()) ? 1 : 0;
        for (DecodedNode ch : node.children()) c += countControls(ch, depth + 1);
        return c;
    }

    static double entropy(byte[] b) {
        if (b.length == 0) return 0;
        int[] freq = new int[256];
        for (byte x : b) freq[x & 0xff]++;
        double e = 0;
        for (int f : freq) {
            if (f == 0) continue;
            double p = (double) f / b.length;
            e -= p * (Math.log(p) / Math.log(2));
        }
        return e;
    }

    @Override
    public String toString() {
        return ID;
    }
}
