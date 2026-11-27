package protocoldecoder.script;

/**
 * Thrown from the instruction observer when a script exceeds its time budget. Extends {@link Error} so script
 * {@code try/catch} blocks cannot swallow it.
 */
final class ScriptTimeoutError extends Error {
    ScriptTimeoutError(String message) {
        super(message, null, false, false);
    }
}
