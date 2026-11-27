package protocoldecoder.scan;

/** Check id conventions shared with code outside this package. */
public final class ScanIds {
    private ScanIds() {
    }

    public static String scriptCheck(String scriptId) {
        return ScanEngine.scriptCheckId(scriptId);
    }
}
