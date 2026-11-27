package protocoldecoder.builtin.saml;

import protocoldecoder.core.DecodedNode;
import protocoldecoder.util.Codecs;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;

/**
 * SAML artifacts (SAML 2.0 type 0x0004 and the SAML 1.x types 0x0001 / 0x0002): fixed binary structures, base64
 * encoded. The artifact itself carries no assertion data; the SP resolves it over the back channel.
 */
final class SamlArtifact {

    private SamlArtifact() {
    }

    /** Short description for summaries, e.g. "type 0x0004, endpoint 0, SourceID 1a2b3c…". */
    record Parsed(DecodedNode node, String brief) {
    }

    static Parsed parse(String name, String value, List<String> warnings) {
        DecodedNode n = DecodedNode.object(name);
        n.put("Raw", Codecs.truncate(value, 200));
        byte[] b = SamlDecoder.base64(value);
        if (b == null || b.length < 4) {
            n.add(DecodedNode.note("Not a valid base64 SAML artifact"));
            warnings.add(name + " is not a valid base64 SAML artifact");
            return new Parsed(n, "invalid artifact");
        }
        HexFormat hex = HexFormat.of();
        int type = ((b[0] & 0xff) << 8) | (b[1] & 0xff);
        n.put("Length", b.length);
        n.put("TypeCode", String.format("0x%04X", type));
        switch (type) {
            case 0x0004 -> {
                n.put("Format", "SAML 2.0 artifact");
                if (b.length != 44) warnings.add("SAML 2.0 artifact should be 44 bytes, got " + b.length);
                if (b.length < 44) {
                    n.put("Remainder", hex.formatHex(b, 2, b.length));
                    return new Parsed(n, "SAML 2.0 artifact (truncated)");
                }
                int index = ((b[2] & 0xff) << 8) | (b[3] & 0xff);
                String source = hex.formatHex(b, 4, 24);
                String handle = hex.formatHex(b, 24, 44);
                n.put("EndpointIndex", index);
                n.put("SourceID", source);
                n.add(DecodedNode.note("SourceID is normally SHA-1(IdP entityID); it selects the ArtifactResolutionService endpoint"));
                n.put("MessageHandle", handle);
                checkHandle(b, 24, 44, warnings);
                return new Parsed(n, "SAML 2.0 artifact, endpoint " + index + ", SourceID " + source.substring(0, 8) + "…");
            }
            case 0x0001 -> {
                n.put("Format", "SAML 1.x artifact (type 1)");
                if (b.length < 42) return new Parsed(n, "SAML 1.x artifact (truncated)");
                String source = hex.formatHex(b, 2, 22);
                n.put("SourceID", source);
                n.put("AssertionHandle", hex.formatHex(b, 22, 42));
                checkHandle(b, 22, 42, warnings);
                return new Parsed(n, "SAML 1.x artifact, SourceID " + source.substring(0, 8) + "…");
            }
            case 0x0002 -> {
                n.put("Format", "SAML 1.x artifact (type 2)");
                if (b.length < 22) return new Parsed(n, "SAML 1.x artifact (truncated)");
                n.put("AssertionHandle", hex.formatHex(b, 2, 22));
                n.put("SourceLocation", new String(b, 22, b.length - 22, StandardCharsets.UTF_8));
                return new Parsed(n, "SAML 1.x artifact (type 2)");
            }
            default -> {
                n.put("Format", "unknown artifact type");
                n.put("Bytes", Codecs.hexPreview(b, 64));
                warnings.add("Unknown SAML artifact type code " + String.format("0x%04X", type));
                return new Parsed(n, "unknown artifact type " + String.format("0x%04X", type));
            }
        }
    }

    private static void checkHandle(byte[] b, int from, int to, List<String> warnings) {
        boolean[] seen = new boolean[256];
        int distinct = 0;
        for (int i = from; i < to; i++) {
            if (!seen[b[i] & 0xff]) {
                seen[b[i] & 0xff] = true;
                distinct++;
            }
        }
        // 20 random bytes almost always contain 17+ distinct values.
        if (distinct < 10) warnings.add("Artifact message handle looks low-entropy (" + distinct + " distinct bytes of 20): possibly predictable");
    }
}
