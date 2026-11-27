package protocoldecoder.script;

import java.util.UUID;

/** A user-authored decoder script as persisted. Mutable bean for Gson and the editor. */
public final class ScriptDefinition {

    private String id;
    private String name;
    private String description;
    private String source;

    public ScriptDefinition() {
    }

    public ScriptDefinition(String id, String name, String description, String source) {
        this.id = id;
        this.name = name;
        this.description = description;
        this.source = source;
    }

    public static ScriptDefinition newFromTemplate() {
        String id = "script-" + UUID.randomUUID().toString().substring(0, 8);
        return new ScriptDefinition(id, "My protocol", "", ScriptTemplates.DEFAULT);
    }

    public String id() { return id == null ? "" : id; }
    public String name() { return name == null || name.isBlank() ? id() : name; }
    public String description() { return description == null ? "" : description; }
    public String source() { return source == null ? "" : source; }

    public ScriptDefinition id(String v) { this.id = v; return this; }
    public ScriptDefinition name(String v) { this.name = v; return this; }
    public ScriptDefinition description(String v) { this.description = v; return this; }
    public ScriptDefinition source(String v) { this.source = v; return this; }

    public ScriptDefinition copy() {
        return new ScriptDefinition(id, name, description, source);
    }

    /** Returns null when valid. */
    public String validate() {
        if (id().isBlank()) return "id is required";
        if (!id().matches("[a-z0-9][a-z0-9._-]{0,63}")) return "id must be lower-case letters, digits, '.', '_' or '-' (max 64)";
        if (source().isBlank()) return "script is empty";
        return null;
    }
}
