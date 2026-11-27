package protocoldecoder.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A node of the decoded tree. Leaves carry a value; branches carry children (and optionally a value as a summary).
 * Decoders build these; views render them. Not thread-safe while being built; treat as immutable afterwards.
 */
public final class DecodedNode {

    /** Rendering hint; views use it for colouring and for the text rendering. */
    public enum Type { OBJECT, ARRAY, STRING, NUMBER, BOOLEAN, NULL, BINARY, HTML, NOTE }

    private final String name;
    private final String value;
    private final Type type;
    private final List<DecodedNode> children = new ArrayList<>();

    public DecodedNode(String name, String value, Type type) {
        this.name = name == null ? "" : name;
        this.value = value;
        this.type = type == null ? Type.STRING : type;
    }

    public static DecodedNode object(String name) {
        return new DecodedNode(name, null, Type.OBJECT);
    }

    public static DecodedNode array(String name) {
        return new DecodedNode(name, null, Type.ARRAY);
    }

    public static DecodedNode leaf(String name, String value) {
        return new DecodedNode(name, value, value == null ? Type.NULL : Type.STRING);
    }

    public static DecodedNode leaf(String name, String value, Type type) {
        return new DecodedNode(name, value, type);
    }

    public static DecodedNode note(String text) {
        return new DecodedNode("note", text, Type.NOTE);
    }

    /** Adds a child and returns this node (for chaining). */
    public DecodedNode add(DecodedNode child) {
        if (child != null) children.add(child);
        return this;
    }

    /** Adds a string leaf if value is non-null; returns this node. */
    public DecodedNode put(String name, String value) {
        if (value != null) children.add(leaf(name, value));
        return this;
    }

    public DecodedNode put(String name, Number value) {
        if (value != null) children.add(new DecodedNode(name, value.toString(), Type.NUMBER));
        return this;
    }

    public DecodedNode put(String name, Boolean value) {
        if (value != null) children.add(new DecodedNode(name, value.toString(), Type.BOOLEAN));
        return this;
    }

    /** Adds and returns a new object child. */
    public DecodedNode child(String name) {
        DecodedNode n = object(name);
        children.add(n);
        return n;
    }

    public String name() { return name; }
    public String value() { return value; }
    public Type type() { return type; }
    public List<DecodedNode> children() { return Collections.unmodifiableList(children); }
    public boolean isLeaf() { return children.isEmpty(); }
    public boolean isContainer() { return type == Type.OBJECT || type == Type.ARRAY; }

    /** Finds a direct child by name, or null. */
    public DecodedNode get(String childName) {
        for (DecodedNode c : children) if (c.name.equals(childName)) return c;
        return null;
    }

    /** Total number of nodes in this subtree. */
    public int size() {
        int n = 1;
        for (DecodedNode c : children) n += c.size();
        return n;
    }

    @Override
    public String toString() {
        return value == null ? name : name + ": " + value;
    }
}
