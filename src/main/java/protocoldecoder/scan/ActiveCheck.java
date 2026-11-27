package protocoldecoder.scan;

import java.util.List;

/**
 * A check that sends requests. Only runs during an active scan the user started, for base requests the owning
 * protocol's decoder applies to (request or response side).
 */
public interface ActiveCheck {

    /** How often Burp invokes the check. */
    enum Scope {
        /** Once per host. */
        PER_HOST,
        /** Once per scanned base request. */
        PER_REQUEST,
        /** Once per insertion point (including Burp's own); see {@link ActiveContext#insertionPoint()}. */
        PER_INSERTION_POINT
    }

    String id();

    String name();

    default String description() {
        return "";
    }

    Scope scope();

    List<Finding> run(ActiveContext ctx);
}
