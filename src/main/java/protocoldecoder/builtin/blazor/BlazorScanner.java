package protocoldecoder.builtin.blazor;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MessageContext;
import protocoldecoder.scan.Confidence;
import protocoldecoder.scan.Finding;
import protocoldecoder.scan.InsertionPoint;
import protocoldecoder.scan.InsertionPoints;
import protocoldecoder.scan.PassiveCheck;
import protocoldecoder.scan.ProtocolScanner;
import protocoldecoder.scan.ScanPatterns;
import protocoldecoder.scan.Severity;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;
import protocoldecoder.util.TreeText;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Passive checks for Blazor (circuit messages are checked as they pass through the proxy WebSocket), plus insertion
 * points inside hub invocations sent over long polling.
 */
public final class BlazorScanner implements ProtocolScanner {

    @Override
    public String decoderId() {
        return BlazorDecoder.ID;
    }

    @Override
    public List<PassiveCheck> passiveChecks() {
        return List.of(new DetailedErrors(), new WasmDebugBuild(), new WasmAssemblies(), new PersistedState(), new SensitiveCircuitData());
    }

    // ---------------------------------------------------------------- insertion points (long polling sends)

    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();

    /**
     * Points inside hub invocations POSTed over long polling ({@code /_blazor?id=…}): JSON-protocol records
     * (0x1E-terminated; argument leaves, with JSON-in-string arguments such as {@code argsJson} or
     * {@code eventArgs} expanded and re-stringified) and blazorpack MessagePack messages (string arguments, spliced in
     * with the VarInt length prefix recomputed).
     */
    @Override
    public List<InsertionPoint> insertionPoints(MessageContext request, DecodeResult decoded) {
        if (!"POST".equalsIgnoreCase(request.method()) || !request.path().toLowerCase(Locale.ROOT).endsWith("/_blazor")
                || !request.query().contains("id=")) return List.of();
        byte[] p = request.requestBody();
        if (p.length == 0) return List.of();
        List<InsertionPoint> out = new ArrayList<>();
        int pos = 0;
        while (pos < p.length && p[pos] == '{' && out.size() < InsertionPoints.MAX_POINTS) {
            int rs = indexOf(p, (byte) SignalR.RS, pos);
            if (rs < 0) return out;
            jsonRecord(out, p, pos, rs);
            pos = rs + 1;
        }
        if (pos >= p.length) return out;
        List<int[]> frames = SignalR.binaryFrames(p, pos);
        if (frames == null) return out;
        int headerStart = pos;
        for (int[] f : frames) {
            if (out.size() >= InsertionPoints.MAX_POINTS) break;
            try {
                packRecord(out, p, headerStart, f[0], f[1]);
            } catch (MsgPack.FormatException | RuntimeException e) {
                // not an invocation we can re-encode; skip this frame
            }
            headerStart = f[1];
        }
        return out;
    }

    private static void jsonRecord(List<InsertionPoint> out, byte[] p, int start, int end) {
        JsonElement e = JsonTree.parseStrict(new String(p, start, end - start, StandardCharsets.UTF_8));
        if (e == null || !e.isJsonObject()) return;
        JsonObject o = e.getAsJsonObject();
        if (!(o.get("type") instanceof JsonPrimitive t) || !t.isNumber() || (t.getAsInt() != 1 && t.getAsInt() != 4)) return;
        if (!(o.get("target") instanceof JsonPrimitive tp) || !(o.get("arguments") instanceof JsonArray args)) return;
        String target = tp.getAsString();
        String[] names = SignalR.BLAZOR_ARGS.get(target);
        for (int i = 0; i < args.size() && out.size() < InsertionPoints.MAX_POINTS; i++) {
            JsonElement arg = args.get(i);
            String argName = names != null && i < names.length ? names[i] : "[" + i + "]";
            String label = "Blazor: " + Codecs.truncate(target, 60) + " " + argName;
            final int idx = i;
            java.util.function.Function<JsonElement, byte[]> withArg = v -> {
                JsonObject copy = o.deepCopy();
                copy.getAsJsonArray("arguments").set(idx, v);
                return splice(p, start, end, GSON.toJson(copy).getBytes(StandardCharsets.UTF_8));
            };
            JsonElement inner = arg.isJsonPrimitive() && arg.getAsJsonPrimitive().isString() && JsonTree.looksLikeJson(arg.getAsString())
                    ? JsonTree.parseStrict(arg.getAsString()) : null;
            if (inner != null) {
                for (InsertionPoints.JsonLeaf leaf : InsertionPoints.jsonLeaves(inner)) {
                    if (out.size() >= InsertionPoints.MAX_POINTS) return;
                    out.add(InsertionPoint.body(label + " " + leaf.path(), InsertionPoints.text(leaf.value()),
                            payload -> withArg.apply(new JsonPrimitive(leaf.replace().apply(payload)))));
                }
            } else if (arg.isJsonPrimitive()) {
                out.add(InsertionPoint.body(label, arg.getAsString(), payload -> withArg.apply(new JsonPrimitive(payload))));
            } else if (arg.isJsonObject() || arg.isJsonArray()) {
                for (InsertionPoints.JsonLeaf leaf : InsertionPoints.jsonLeaves(arg)) {
                    if (out.size() >= InsertionPoints.MAX_POINTS) return;
                    out.add(InsertionPoint.body(label + " " + leaf.path(), InsertionPoints.text(leaf.value()),
                            payload -> withArg.apply(JsonTree.parseStrict(leaf.replace().apply(payload)))));
                }
            }
        }
    }

    /** One blazorpack frame: [type, headers, invocationId, target, arguments, streamIds?]. */
    private static void packRecord(List<InsertionPoint> out, byte[] p, int headerStart, int start, int end) throws MsgPack.FormatException {
        int[] top = MsgPackWriter.arrayHeader(p, start, end);
        if (top == null || top[0] < 5) return;
        int off = start + top[1];
        if (!(MsgPackWriter.read(p, off, end) instanceof Long type) || (type != 1 && type != 4)) return;
        for (int k = 0; k < 3; k++) off = MsgPackWriter.skip(p, off, end); // type, headers, invocationId
        int targetEnd = MsgPackWriter.skip(p, off, end);
        if (!(MsgPackWriter.read(p, off, targetEnd) instanceof String target)) return;
        off = targetEnd;
        int[] argsHeader = MsgPackWriter.arrayHeader(p, off, end);
        if (argsHeader == null) return;
        off += argsHeader[1];
        String[] names = SignalR.BLAZOR_ARGS.get(target);
        for (int i = 0; i < argsHeader[0] && out.size() < InsertionPoints.MAX_POINTS; i++) {
            int argStart = off;
            int argEnd = MsgPackWriter.skip(p, argStart, end);
            off = argEnd;
            if (!(MsgPackWriter.read(p, argStart, argEnd) instanceof String s)) continue;
            String argName = names != null && i < names.length ? names[i] : "[" + i + "]";
            String label = "Blazor: " + Codecs.truncate(target, 60) + " " + argName;
            java.util.function.Function<String, byte[]> withArg = v -> {
                byte[] enc = MsgPackWriter.str(v);
                byte[] msg = new byte[(argStart - start) + enc.length + (end - argEnd)];
                System.arraycopy(p, start, msg, 0, argStart - start);
                System.arraycopy(enc, 0, msg, argStart - start, enc.length);
                System.arraycopy(p, argEnd, msg, argStart - start + enc.length, end - argEnd);
                byte[] len = MsgPackWriter.varInt(msg.length);
                byte[] frame = new byte[len.length + msg.length];
                System.arraycopy(len, 0, frame, 0, len.length);
                System.arraycopy(msg, 0, frame, len.length, msg.length);
                return splice(p, headerStart, end, frame);
            };
            JsonElement inner = JsonTree.looksLikeJson(s) ? JsonTree.parseStrict(s) : null;
            if (inner != null) {
                for (InsertionPoints.JsonLeaf leaf : InsertionPoints.jsonLeaves(inner)) {
                    if (out.size() >= InsertionPoints.MAX_POINTS) return;
                    out.add(InsertionPoint.body(label + " " + leaf.path(), InsertionPoints.text(leaf.value()),
                            payload -> withArg.apply(leaf.replace().apply(payload))));
                }
            } else {
                out.add(InsertionPoint.body(label, s, withArg::apply));
            }
        }
    }

    /** {@code p} with {@code [start, end)} replaced. */
    private static byte[] splice(byte[] p, int start, int end, byte[] with) {
        byte[] r = new byte[start + with.length + (p.length - end)];
        System.arraycopy(p, 0, r, 0, start);
        System.arraycopy(with, 0, r, start, with.length);
        System.arraycopy(p, end, r, start + with.length, p.length - end);
        return r;
    }

    private static int indexOf(byte[] p, byte v, int from) {
        for (int i = from; i < p.length; i++) if (p[i] == v) return i;
        return -1;
    }

    /** Circuit errors (JS.Error, completion errors, close reasons) carrying exception details. */
    static final class DetailedErrors implements PassiveCheck {
        @Override public String id() { return "blazor.detailed-errors"; }
        @Override public String name() { return "Detailed circuit errors"; }
        @Override public String description() { return "Exception types / stack traces in Blazor Server circuit messages (DetailedErrors enabled)"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (decoded == null || m.isRequest()) return List.of();
            String text = TreeText.render(decoded.root());
            boolean errorMessage = text.contains("JS.Error") || text.contains("Completion (error)") || text.contains("Close (")
                    || text.contains("Result kind: \"1 (error)\"") || text.contains("1 (error)");
            String trace = ScanPatterns.exceptionEvidence(text.replace("\\n", "\n"));
            if (!errorMessage || trace == null) return List.of();
            return List.of(Finding.of(id(), "Blazor Server detailed errors enabled")
                    .severity(Severity.LOW).confidence(Confidence.FIRM).scope(Finding.Scope.HOST)
                    .detail("A Blazor circuit message from the server contains exception details: <code>" + Finding.esc(Codecs.truncate(trace, 400)) + "</code>"
                            + (m.isWebSocket() ? "<br>(Seen in a WebSocket message on " + Finding.esc(m.path()) + ".)" : ""))
                    .background("With <code>CircuitOptions.DetailedErrors</code> (or the DetailedErrors configuration key) enabled, Blazor Server "
                            + "sends full exception messages and stack traces to the browser, disclosing internals.")
                    .remediation("Disable DetailedErrors outside development and log exceptions server-side.")
                    .responseEvidence(trace));
        }
    }

    static final class WasmDebugBuild implements PassiveCheck {
        @Override public String id() { return "blazor.wasm-debug"; }
        @Override public String name() { return "WebAssembly debug build"; }
        @Override public String description() { return "blazor.boot.json reports debugBuild: true"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (decoded == null || !m.isResponse() || !m.path().endsWith("/blazor.boot.json")) return List.of();
            if (!decoded.summary().contains("(debug build)")) return List.of();
            return List.of(Finding.of(id(), "Blazor WebAssembly debug build deployed")
                    .severity(Severity.LOW).confidence(Confidence.CERTAIN).scope(Finding.Scope.HOST)
                    .detail("<code>blazor.boot.json</code> declares <code>\"debugBuild\": true</code>.")
                    .background("Debug builds ship unoptimised assemblies (and often PDBs), easing decompilation and exposing debugging features.")
                    .remediation("Publish in Release configuration.")
                    .responseEvidence("\"debugBuild\":true"));
        }
    }

    static final class WasmAssemblies implements PassiveCheck {
        @Override public String id() { return "blazor.wasm-assemblies"; }
        @Override public String name() { return "WebAssembly assemblies listed"; }
        @Override public String description() { return "Application assemblies downloadable to the client (review for secrets/logic)"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (decoded == null || !m.isResponse() || !m.path().endsWith("/blazor.boot.json")) return List.of();
            List<String> app = new ArrayList<>();
            collectAssemblies(decoded.root(), app);
            app.removeIf(a -> a.startsWith("System.") || a.startsWith("Microsoft.") || a.startsWith("netstandard") || a.startsWith("mscorlib"));
            if (app.isEmpty()) return List.of();
            StringBuilder list = new StringBuilder("<ul>");
            app.stream().limit(50).forEach(a -> list.append("<li><code>").append(Finding.esc(a)).append("</code></li>"));
            list.append("</ul>");
            return List.of(Finding.of(id(), "Blazor WebAssembly application assemblies exposed")
                    .severity(Severity.INFORMATION).confidence(Confidence.CERTAIN).scope(Finding.Scope.HOST)
                    .detail("The boot manifest lists application assemblies that every client downloads:" + list)
                    .background("Blazor WebAssembly runs .NET assemblies in the browser. They can be downloaded from <code>_framework/</code> and "
                            + "decompiled, revealing client logic, API endpoints and any embedded secrets.")
                    .remediation("Keep secrets and authorisation logic on the server; treat client assemblies as public."));
        }

        private static void collectAssemblies(DecodedNode n, List<String> out) {
            String name = n.name();
            if ((name.endsWith(".dll") || name.endsWith(".wasm")) && !out.contains(name) && out.size() < 500) out.add(name);
            for (DecodedNode c : n.children()) collectAssemblies(c, out);
        }
    }

    static final class PersistedState implements PassiveCheck {
        @Override public String id() { return "blazor.persisted-state"; }
        @Override public String name() { return "Readable persisted component state"; }
        @Override public String description() { return "Blazor-WebAssembly-Component-State in pages (plain base64), reported when it holds sensitive-looking data"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (decoded == null || !m.isResponse()) return List.of();
            DecodedNode state = decoded.root().get("Blazor-WebAssembly-Component-State");
            if (state == null) return List.of();
            List<ScanPatterns.Sensitive> hits = ScanPatterns.sensitiveValues(state, 20);
            Finding f = Finding.of(id(), hits.isEmpty() ? "Blazor persisted component state in page" : "Sensitive data in Blazor persisted component state")
                    .severity(hits.isEmpty() ? Severity.INFORMATION : Severity.LOW)
                    .confidence(hits.isEmpty() ? Confidence.CERTAIN : Confidence.TENTATIVE)
                    .detail("The page carries WebAssembly persisted component state, which is only base64-encoded (not protected)."
                            + (hits.isEmpty() ? "" : " It contains:" + ScanPatterns.htmlList(hits)))
                    .background("<code>PersistentComponentState</code> transfers prerendered state to the WebAssembly client in an HTML comment. "
                            + "Anyone who can see the page can read it.")
                    .remediation("Only persist data the user is allowed to see; never persist secrets.");
            hits.forEach(h -> f.responseEvidence(h.value()));
            return List.of(f);
        }
    }

    /** Sensitive-looking values in circuit traffic (both directions). */
    static final class SensitiveCircuitData implements PassiveCheck {
        @Override public String id() { return "blazor.sensitive-circuit-data"; }
        @Override public String name() { return "Secrets in JS interop"; }
        @Override public String description() { return "Tokens/credentials passed through JS interop (e.g. localStorage reads, BeginInvokeJS arguments)"; }

        @Override
        public List<Finding> check(MessageContext m, DecodeResult decoded) {
            if (decoded == null || !m.isWebSocket()) return List.of();
            String summary = decoded.summary().toLowerCase(Locale.ROOT);
            if (!summary.contains("invoke") && !summary.contains("endinvoke")) return List.of();
            List<ScanPatterns.Sensitive> hits = ScanPatterns.sensitiveValues(decoded.root(), 10);
            hits.removeIf(h -> h.kind().equals("email address"));
            if (hits.isEmpty()) return List.of();
            return List.of(Finding.of(id(), "Secrets passed through Blazor JS interop")
                    .severity(Severity.INFORMATION).confidence(Confidence.TENTATIVE)
                    .detail("Blazor JS interop messages on <code>" + Finding.esc(m.path()) + "</code> carry sensitive-looking values:" + ScanPatterns.htmlList(hits))
                    .background("Values read from browser storage or passed to JavaScript are exposed to any script running in the page (XSS impact).")
                    .remediation("Keep tokens server-side (e.g. in the circuit or HttpOnly cookies) where possible."));
        }
    }
}
