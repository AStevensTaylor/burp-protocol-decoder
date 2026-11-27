package protocoldecoder.persistence;

import protocoldecoder.script.SandboxLimits;

/** User-tunable settings. Mutable bean for Gson. */
public final class Settings {

    /** Show the "Decoded" tab even when no decoder matches (so you can pick one manually). */
    public boolean alwaysShowTab = false;
    public int matchTimeoutMs = SandboxLimits.DEFAULT.matchTimeoutMs();
    public int decodeTimeoutMs = SandboxLimits.DEFAULT.decodeTimeoutMs();
    public int maxScriptBodyBytes = SandboxLimits.DEFAULT.maxBodyBytes();
    public int maxOutputNodes = SandboxLimits.DEFAULT.maxOutputNodes();
    /** Messages bigger than this are not matched at all (keeps the UI responsive on huge downloads). */
    public int maxMatchBytes = 16 * 1024 * 1024;
    /** Remember manual overrides in the Burp project file. */
    public boolean persistOverrides = true;
    /** Run protocol passive checks from Burp's passive scanner. */
    public boolean scanPassive = true;
    /** Run protocol active checks during active scans. */
    public boolean scanActive = true;
    /** Offer protocol-aware insertion points to Burp's scanner. */
    public boolean scanInsertionPoints = true;
    /** Run passive checks on WebSocket messages passing through the proxy. */
    public boolean scanWebSockets = true;

    public SandboxLimits limits() {
        return new SandboxLimits(matchTimeoutMs, decodeTimeoutMs, maxScriptBodyBytes, maxOutputNodes);
    }

    public Settings copy() {
        Settings s = new Settings();
        s.alwaysShowTab = alwaysShowTab;
        s.matchTimeoutMs = matchTimeoutMs;
        s.decodeTimeoutMs = decodeTimeoutMs;
        s.maxScriptBodyBytes = maxScriptBodyBytes;
        s.maxOutputNodes = maxOutputNodes;
        s.maxMatchBytes = maxMatchBytes;
        s.persistOverrides = persistOverrides;
        s.scanPassive = scanPassive;
        s.scanActive = scanActive;
        s.scanInsertionPoints = scanInsertionPoints;
        s.scanWebSockets = scanWebSockets;
        return s;
    }
}
