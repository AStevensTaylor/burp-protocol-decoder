package protocoldecoder.script;

/** A script failed to compile or run. Message is user-facing. */
public class ScriptException extends Exception {
    private final boolean timeout;

    public ScriptException(String message) {
        this(message, false);
    }

    public ScriptException(String message, boolean timeout) {
        super(message);
        this.timeout = timeout;
    }

    public boolean isTimeout() {
        return timeout;
    }
}
