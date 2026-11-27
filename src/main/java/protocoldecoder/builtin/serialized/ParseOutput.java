package protocoldecoder.builtin.serialized;

import protocoldecoder.core.DecodedNode;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** What one structural parser produced for one serialized payload. Always usable, even after a parse error. */
final class ParseOutput {

    /** Shared cap on the number of tree nodes produced across all payloads of one message. */
    static final class Budget {
        private int left;

        Budget(int max) {
            this.left = max;
        }

        /** Creates a node and attaches it to {@code parent}; throws once the cap is reached. */
        DecodedNode add(DecodedNode parent, DecodedNode child) throws Bin.LimitException {
            if (left <= 0) throw new Bin.LimitException("output limit reached");
            left--;
            parent.add(child);
            return child;
        }

        boolean exhausted() {
            return left <= 0;
        }
    }

    static final int MAX_TYPES = 500;

    /** Structure tree (children are added by the parser). */
    final DecodedNode structure;
    /** Class / type / global names in order of first appearance. */
    final Set<String> types = new LinkedHashSet<>();
    /** Non-fatal remarks shown under the finding and as warnings. */
    final List<String> notes = new ArrayList<>();
    /** Extra nodes (class tables, symbol lists, ...) shown after the structure. */
    final List<DecodedNode> extras = new ArrayList<>();
    /** Noun for {@link #types} in summaries ("classes", "globals", "types"). */
    String typeNoun = "classes";
    /** False when parsing stopped before the end of the payload. */
    boolean complete = true;
    /** Why parsing stopped, when {@link #complete} is false. */
    String stopReason;

    /**
     * A rewritable value inside the payload (used for scanner insertion points): bytes {@code [start, end)} hold the
     * whole encoded element (type tag / length prefix and content), which {@code Reserializer} regenerates for a new
     * value. {@code kind}: 's' PHP string, 'i' PHP integer, 'J' Java TC_STRING/TC_LONGSTRING, 'P' pickle unicode
     * opcode, 'N' NRBF length-prefixed string, 'R' Ruby string (length + bytes).
     */
    record Span(int start, int end, String value, String path, char kind) {
    }

    /** A pickle FRAME: offset of its 8-byte length field, first byte of the frame, frame length. */
    record Frame(int lengthOffset, int start, long length) {
    }

    static final int MAX_SPANS = 500;

    /** Rewritable string values, in stream order. */
    final List<Span> spans = new ArrayList<>();
    /** Pickle frames (protocol 4+). */
    final List<Frame> frames = new ArrayList<>();

    ParseOutput(String structureName) {
        this.structure = DecodedNode.object(structureName);
    }

    void type(String name) {
        if (name != null && !name.isEmpty() && types.size() < MAX_TYPES) types.add(name);
    }

    void span(int start, int end, String value, List<String> trail, char kind) {
        if (spans.size() < MAX_SPANS && start >= 0 && end > start) spans.add(new Span(start, end, value, path(trail), kind));
    }

    /** "$.user.name", "$.items[0]" from a stack of labels (the first, root label is skipped). */
    static String path(List<String> trail) {
        StringBuilder sb = new StringBuilder("$");
        for (int i = 1; i < trail.size(); i++) {
            String t = trail.get(i);
            if (t.startsWith("[")) sb.append(t);
            else sb.append('.').append(t);
        }
        return sb.toString();
    }

    void stop(String reason) {
        if (complete) {
            complete = false;
            stopReason = reason;
        }
    }
}
