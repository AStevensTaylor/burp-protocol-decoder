package protocoldecoder.script;

/**
 * Resource limits for script execution.
 *
 * @param matchTimeoutMs  CPU budget for match()
 * @param decodeTimeoutMs CPU budget for decode()
 * @param maxBodyBytes    bodies larger than this are truncated before being handed to scripts
 * @param maxOutputNodes  maximum number of tree nodes a decode() result may produce
 */
public record SandboxLimits(int matchTimeoutMs, int decodeTimeoutMs, int maxBodyBytes, int maxOutputNodes) {

    public static final SandboxLimits DEFAULT = new SandboxLimits(250, 3000, 5 * 1024 * 1024, 50_000);

    public SandboxLimits {
        matchTimeoutMs = clamp(matchTimeoutMs, 10, 10_000);
        decodeTimeoutMs = clamp(decodeTimeoutMs, 50, 60_000);
        maxBodyBytes = clamp(maxBodyBytes, 1024, 64 * 1024 * 1024);
        maxOutputNodes = clamp(maxOutputNodes, 100, 1_000_000);
    }

    private static int clamp(int v, int lo, int hi) {
        return Math.max(lo, Math.min(hi, v));
    }
}
