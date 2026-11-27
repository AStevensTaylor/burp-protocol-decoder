package protocoldecoder.edit;

import protocoldecoder.core.MessageContext;
import protocoldecoder.core.MessageKind;
import protocoldecoder.scan.InsertionPoint;
import protocoldecoder.scan.ScanEngine;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Editing of decoded messages. Fields come from the protocol scanners' insertion points (each is "set this nested
 * value and re-encode everything around it"); documents come from registered {@link MessageCodec}s.
 */
public final class EditEngine {

    /** An editable value. {@code occurrence} disambiguates fields that share a name. */
    public record Field(String name, int occurrence, String value, InsertionPoint.Part part) {
        public String label() {
            return occurrence == 0 ? name : name + " #" + (occurrence + 1);
        }
    }

    /** A document offered for editing, with the protocol it came from. */
    public record Document(String decoderId, String decoderName, EditableDocument document) {
    }

    private final ScanEngine scanEngine;
    private final List<MessageCodec> codecs = new CopyOnWriteArrayList<>();
    private volatile Consumer<String> errorLog = s -> { };

    public EditEngine(ScanEngine scanEngine) {
        this.scanEngine = scanEngine;
    }

    public void setErrorLog(Consumer<String> log) {
        this.errorLog = log == null ? s -> { } : log;
    }

    public void register(MessageCodec codec) {
        codecs.removeIf(c -> c.getClass().equals(codec.getClass()) && c.decoderId().equals(codec.decoderId()));
        codecs.add(codec);
    }

    public List<MessageCodec> codecs() {
        return List.copyOf(codecs);
    }

    /** Whether a message can be edited at all (complete, not truncated). */
    public static boolean editable(MessageContext m) {
        return m != null && !m.truncated();
    }

    // ---------------------------------------------------------------- fields

    /** Editable fields of a request (from insertion points, regardless of the scan toggles). Empty for other kinds. */
    public List<Field> fields(MessageContext m) {
        if (!editable(m) || m.kind() != MessageKind.REQUEST) return List.of();
        List<Field> out = new ArrayList<>();
        List<InsertionPoint> ips = points(m);
        for (int i = 0; i < ips.size(); i++) {
            InsertionPoint ip = ips.get(i);
            out.add(new Field(ip.name(), occurrence(ips, i), ip.baseValue() == null ? "" : ip.baseValue(), ip.part()));
        }
        return out;
    }

    private List<InsertionPoint> points(MessageContext m) {
        try {
            return scanEngine.insertionPoints(m, false);
        } catch (RuntimeException e) {
            errorLog.accept("Listing editable fields failed: " + e);
            return List.of();
        }
    }

    private static int occurrence(List<InsertionPoint> ips, int index) {
        int n = 0;
        for (int i = 0; i < index; i++) if (ips.get(i).name().equals(ips.get(index).name())) n++;
        return n;
    }

    /**
     * Sets one field. Insertion points are recomputed on {@code current} (so successive edits compose) and the field
     * is found by name and occurrence.
     */
    public MessagePatch setField(MessageContext current, Field field, String value) throws EncodeException {
        List<InsertionPoint> ips = points(current);
        for (int i = 0; i < ips.size(); i++) {
            InsertionPoint ip = ips.get(i);
            if (ip.name().equals(field.name()) && occurrence(ips, i) == field.occurrence()) {
                try {
                    return MessagePatch.of(ip, value);
                } catch (RuntimeException e) {
                    throw new EncodeException("Could not re-encode " + field.label() + ": " + e.getMessage(), e);
                }
            }
        }
        throw new EncodeException("Field " + field.label() + " no longer exists in the edited message");
    }

    // ---------------------------------------------------------------- documents

    public List<Document> documents(MessageContext m) {
        if (!editable(m) || codecs.isEmpty()) return List.of();
        List<Document> out = new ArrayList<>();
        for (ScanEngine.Applicable a : scanEngine.applicable(m)) {
            for (MessageCodec c : codecs) {
                if (!c.decoderId().equals(a.decoder().id())) continue;
                try {
                    List<EditableDocument> docs = c.documents(m, a.decoded());
                    if (docs != null) for (EditableDocument d : docs) out.add(new Document(a.decoder().id(), a.decoder().name(), d));
                } catch (RuntimeException e) {
                    errorLog.accept("Codec for " + c.decoderId() + " failed to open " + m + ": " + e);
                }
            }
        }
        return out;
    }

    public static MessagePatch encode(Document d, String text) throws EncodeException {
        try {
            MessagePatch p = d.document().encode(text);
            if (p == null) throw new EncodeException("Encoder returned nothing");
            return p;
        } catch (RuntimeException e) {
            throw new EncodeException(d.document().title() + ": " + e, e);
        }
    }
}
