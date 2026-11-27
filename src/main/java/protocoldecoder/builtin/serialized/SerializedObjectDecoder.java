package protocoldecoder.builtin.serialized;

import protocoldecoder.builtin.serialized.Scanner.Hit;
import protocoldecoder.builtin.serialized.Sniffer.Detection;
import protocoldecoder.builtin.serialized.Sniffer.Format;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.ProtocolDecoder;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Spots native serialization in HTTP traffic (Java, .NET BinaryFormatter / ViewState / Json.NET / XML type hints,
 * PHP, Python pickle, Ruby Marshal) and shows its structure. It is a pure parser: nothing is deserialized, no class is
 * loaded or instantiated, and nothing is generated. Well-known gadget classes are flagged by name.
 */
public final class SerializedObjectDecoder implements ProtocolDecoder {

    public static final String ID = "serialized";

    /** Total tree nodes produced for one message. */
    private static final int NODE_BUDGET = 20_000;

    @Override public String id() { return ID; }
    @Override public String name() { return "Serialized objects"; }
    @Override public String description() {
        return "Detects and structurally decodes Java, .NET (BinaryFormatter, ViewState, Json.NET $type), PHP, pickle and "
                + "Ruby Marshal serialization in bodies, parameters, cookies and headers; flags known gadget classes";
    }

    @Override
    public MatchResult match(MessageContext m) {
        try {
            Scanner.Stats stats = new Scanner.Stats();
            List<Hit> hits = Scanner.scan(m, false, stats);
            Hit best = null;
            for (Hit h : hits) if (best == null || h.detection().confidence() > best.detection().confidence()) best = h;
            if (best == null) return MatchResult.NONE;
            return MatchResult.of(best.detection().confidence(), best.detection().format().label + " in " + where(best.location()));
        } catch (RuntimeException e) {
            return MatchResult.NONE;
        }
    }

    @Override
    public DecodeResult decode(MessageContext m) throws DecodeException {
        Scanner.Stats stats = new Scanner.Stats();
        List<Hit> hits;
        try {
            hits = Scanner.scan(m, true, stats);
        } catch (RuntimeException e) {
            throw new DecodeException("Could not scan the message: " + e, e);
        }
        if (hits.isEmpty()) {
            throw new DecodeException("No serialized object found (checked " + stats + ")");
        }

        ParseOutput.Budget budget = new ParseOutput.Budget(NODE_BUDGET);
        DecodedNode root = DecodedNode.object("Serialized objects");
        List<String> warnings = new ArrayList<>();
        List<String> summaries = new ArrayList<>();
        boolean anyRisk = false;

        for (Hit hit : hits) {
            Detection d = hit.detection();
            ParseOutput po = parse(d, budget);
            DecodedNode finding = root.child(hit.location() + " — " + d.format().label);
            finding.put("Location", hit.location());
            finding.put("Format", d.format().label);
            finding.put("Encoding", d.encoding());
            if (d.payload() != null) finding.put("Size", d.payload().length + " bytes");
            finding.put("Confidence", d.confidence());

            List<String> risky = new ArrayList<>();
            if (!po.types.isEmpty()) {
                DecodedNode types = DecodedNode.array(capitalise(po.typeNoun) + " (" + po.types.size() + ")");
                for (String t : po.types) {
                    String r = RiskyTypes.reason(t);
                    types.add(DecodedNode.leaf("", r == null ? t : t + "  ⚠ " + r));
                    if (r != null) {
                        risky.add(t);
                        warnings.add("⚠ " + hit.location() + ": " + t + " — " + r);
                    }
                }
                finding.add(types);
            }
            if (!po.structure.isLeaf()) finding.add(po.structure);
            po.extras.forEach(finding::add);

            List<String> notes = new ArrayList<>();
            if (d.note() != null) notes.add(d.note());
            notes.addAll(po.notes);
            if (!po.complete) {
                notes.add(0, "Parsing stopped: " + po.stopReason + " — partial output shown"
                        + (d.format() == Format.JAVA ? "; class names found by scanning are listed" : ""));
            }
            for (String n : notes) {
                finding.add(DecodedNode.note(n));
                warnings.add(hit.location() + ": " + n);
            }
            if (d.format() == Format.PHP) {
                List<String> objs = new ArrayList<>(po.types);
                if (!objs.isEmpty()) {
                    warnings.add(hit.location() + ": PHP object" + (objs.size() == 1 ? "" : "s") + " " + String.join(", ", head(objs, 5))
                            + " — object injection risk if this reaches unserialize()");
                }
            }
            if (d.format() == Format.PICKLE && !po.types.isEmpty()) {
                List<String> globals = new ArrayList<>(po.types);
                warnings.add(hit.location() + ": pickle imports " + String.join(", ", head(globals, 10))
                        + (globals.size() > 10 ? ", …" : "") + " on load");
            }
            if (d.format() == Format.VIEWSTATE) {
                warnings.add(hit.location() + ": ASP.NET ViewState — pick the 'ASP.NET ViewState' decoder for the full decode (MAC/encryption analysis)");
            }
            anyRisk |= !risky.isEmpty();
            summaries.add(summaryFor(hit, po, risky));
        }

        String summary;
        if (summaries.size() == 1) {
            summary = summaries.get(0);
        } else {
            summary = summaries.size() + " serialized payloads" + (anyRisk ? " ⚠" : "") + ": " + String.join("; ", head(summaries, 3))
                    + (summaries.size() > 3 ? "; …" : "");
        }
        if (budget.exhausted()) warnings.add("Output limit of " + NODE_BUDGET + " nodes reached; later content is not shown");
        return new DecodeResult(summary, root, null, warnings);
    }

    private static ParseOutput parse(Detection d, ParseOutput.Budget budget) {
        try {
            return switch (d.format()) {
                case JAVA -> JavaSerialParser.parse(d.payload(), budget);
                case NRBF -> NrbfParser.parse(d.payload(), budget);
                case VIEWSTATE -> TypeHints.viewState(d.payload(), budget);
                case PHP -> PhpParser.parse(d.payload(), budget);
                case PICKLE -> PickleParser.parse(d.payload(), budget);
                case RUBY -> RubyMarshalParser.parse(d.payload(), budget);
                case JSON_NET -> TypeHints.jsonNet(d.text());
                case XML_HINT -> TypeHints.xml(d.text());
                case GZIP -> {
                    ParseOutput o = new ParseOutput("gzip");
                    o.stop("gzip data without a recognised payload");
                    yield o;
                }
            };
        } catch (RuntimeException e) {
            // Parsers handle malformed input themselves; this is a last line of defence.
            ParseOutput o = new ParseOutput("Structure");
            o.stop("internal parser error: " + e);
            return o;
        }
    }

    private static String summaryFor(Hit hit, ParseOutput po, List<String> risky) {
        StringBuilder sb = new StringBuilder(hit.detection().format().label).append(" in ").append(where(hit.location()));
        int n = po.types.size();
        if (n > 0) {
            String noun = n == 1 ? singular(po.typeNoun) : po.typeNoun;
            sb.append(" — ").append(n).append(' ').append(noun).append(" (");
            if (!risky.isEmpty()) {
                List<String> shown = new ArrayList<>();
                for (String r : head(risky, 2)) shown.add(r + " ⚠");
                sb.append(String.join(", ", shown));
                if (risky.size() > 2) sb.append(", …");
            } else {
                List<String> all = new ArrayList<>(po.types);
                sb.append(String.join(", ", head(all, 2)));
                if (all.size() > 2) sb.append(", …");
            }
            sb.append(')');
        }
        if (!po.complete) sb.append(" [partial]");
        return sb.toString();
    }

    /** "cookie: session" → "cookie session". */
    private static String where(String location) {
        return location.replaceFirst(": ", " ");
    }

    private static String singular(String noun) {
        return switch (noun) {
            case "classes" -> "class";
            case "globals" -> "global";
            case "types" -> "type";
            default -> noun;
        };
    }

    private static String capitalise(String s) {
        return s.isEmpty() ? s : s.substring(0, 1).toUpperCase(Locale.ROOT) + s.substring(1);
    }

    private static <T> List<T> head(List<T> l, int n) {
        return l.size() <= n ? l : l.subList(0, n);
    }

    @Override
    public String toString() {
        return ID;
    }
}
