package protocoldecoder.builtin.turbo;

import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.Header;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.ProtocolDecoder;
import protocoldecoder.util.Codecs;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Hotwire Turbo: Turbo Stream responses ({@code text/vnd.turbo-stream.html}, also over WebSocket/SSE stream sources),
 * Turbo Drive/Frame requests (Turbo-Frame, stream Accept, X-Turbo-Request-Id, prefetch) and the matching
 * {@code <turbo-frame>} in frame responses, plus page hints ({@code <meta name="turbo-*">}, frames and
 * {@code <turbo-cable-stream-source>} with its signed stream name decoded).
 */
public final class TurboDecoder implements ProtocolDecoder {

    public static final String ID = "turbo";

    private static final int SNIFF = 1024 * 1024;
    private static final int MAX_TEXT = 8 * 1024 * 1024;
    private static final int MAX_INNER = 256 * 1024;
    private static final int MAX_LIST = 200;

    private static final Map<String, String> META = Map.of(
            "turbo-visit-control", "reload = Turbo always does a full page load",
            "turbo-cache-control", "no-cache / no-preview: snapshot cache behaviour",
            "turbo-refresh-method", "morph / replace: how page refreshes are applied",
            "turbo-refresh-scroll", "preserve / reset: scroll on page refresh",
            "turbo-prefetch", "false disables hover prefetching",
            "turbo-root", "Turbo Drive only handles URLs under this path",
            "view-transition", "same-origin enables View Transitions",
            "turbo-cache-control-preview", "snapshot preview control");

    @Override public String id() { return ID; }
    @Override public String name() { return "Hotwire Turbo"; }
    @Override public String description() {
        return "Hotwire Turbo Streams, Turbo Frame requests/responses, Turbo page metadata and signed cable stream names";
    }

    // ---------------------------------------------------------------- matching

    @Override
    public MatchResult match(MessageContext m) {
        try {
            return doMatch(m);
        } catch (RuntimeException e) {
            return MatchResult.NONE;
        }
    }

    private MatchResult doMatch(MessageContext m) {
        if (m.isWebSocket()) {
            String head = head(m.body());
            return startsWithStream(head) ? MatchResult.of(85, "Turbo Stream over a WebSocket stream source") : MatchResult.NONE;
        }
        if (m.isRequest()) {
            if (notBlank(m.requestHeader("Turbo-Frame"))) return MatchResult.of(80, "Turbo-Frame request header");
            if (acceptsStream(m)) return MatchResult.of(50, "Accept: " + TurboStream.CONTENT_TYPE);
            if (notBlank(m.requestHeader("X-Turbo-Request-Id"))) return MatchResult.of(45, "X-Turbo-Request-Id header");
            String purpose = m.requestHeader("X-Sec-Purpose");
            if (purpose != null && purpose.toLowerCase(Locale.ROOT).contains("prefetch")) return MatchResult.of(40, "Turbo prefetch (X-Sec-Purpose)");
            return MatchResult.NONE;
        }
        String ct = m.contentType().toLowerCase(Locale.ROOT);
        if (ct.contains(TurboStream.CONTENT_TYPE)) return MatchResult.of(95, "Content-Type " + TurboStream.CONTENT_TYPE);
        boolean textual = ct.isEmpty() || ct.contains("html") || ct.contains("text/") || ct.contains("xml");
        if (!textual) return MatchResult.NONE;
        String head = head(Codecs.decodeContent(m.responseBody(), m.responseHeader("Content-Encoding")));
        if (ct.contains("text/event-stream")) {
            return TurboStream.contains(head) ? MatchResult.of(80, "Turbo Streams over Server-Sent Events") : MatchResult.NONE;
        }
        String frame = m.requestHeader("Turbo-Frame");
        if (notBlank(frame)) {
            if (findFrame(head, frame.strip()) != null) return MatchResult.of(85, "response with the requested <turbo-frame id=\"" + frame.strip() + "\">");
            return MatchResult.of(70, "response to a Turbo-Frame request");
        }
        if (startsWithStream(head)) return MatchResult.of(70, "body is Turbo Stream elements");
        if (head.contains("<turbo-cable-stream-source") || head.contains("<turbo-stream-source")) return MatchResult.of(30, "Turbo stream source in page");
        if (hasTurboMeta(head)) return MatchResult.of(25, "<meta name=\"turbo-*\"> in page");
        if (head.contains("<turbo-frame")) return MatchResult.of(25, "<turbo-frame> in page");
        return MatchResult.NONE;
    }

    private static String head(byte[] b) {
        if (b == null || b.length == 0) return "";
        int n = Math.min(b.length, SNIFF);
        return new String(b, 0, n, java.nio.charset.StandardCharsets.UTF_8);
    }

    private static boolean startsWithStream(String s) {
        String t = s.stripLeading();
        return t.regionMatches(true, 0, "<turbo-stream", 0, 13) && TurboStream.contains(t.substring(0, Math.min(t.length(), 200)));
    }

    private static boolean hasTurboMeta(String s) {
        return s.contains("name=\"turbo-") || s.contains("name='turbo-") || s.contains("name=\"view-transition\"") || s.contains("name=turbo-");
    }

    private static boolean acceptsStream(MessageContext m) {
        String a = m.requestHeader("Accept");
        return a != null && a.toLowerCase(Locale.ROOT).contains(TurboStream.CONTENT_TYPE);
    }

    private static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }

    private static boolean hasTurboRequestHeaders(MessageContext m) {
        if (notBlank(m.requestHeader("Turbo-Frame")) || acceptsStream(m) || notBlank(m.requestHeader("X-Turbo-Request-Id"))) return true;
        String purpose = m.requestHeader("X-Sec-Purpose");
        return purpose != null && purpose.toLowerCase(Locale.ROOT).contains("prefetch");
    }

    // ---------------------------------------------------------------- decoding

    @Override
    public DecodeResult decode(MessageContext m) throws DecodeException {
        try {
            return doDecode(m);
        } catch (DecodeException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new DecodeException("Turbo decoding failed: " + e, e);
        }
    }

    private DecodeResult doDecode(MessageContext m) throws DecodeException {
        if (m.isWebSocket()) {
            String t = Codecs.utf8(m.body());
            if (!TurboStream.contains(t)) throw new DecodeException("WebSocket message contains no <turbo-stream> elements");
            return streams("Turbo Stream (WebSocket " + direction(m) + ")", t, List.of());
        }
        if (m.isRequest()) {
            if (TurboStream.contains(m.requestBodyText())) return streams("Turbo Stream (request body)", m.requestBodyText(), List.of());
            if (hasTurboRequestHeaders(m)) return request(m);
            throw new DecodeException("No Turbo request headers (Turbo-Frame, Accept: " + TurboStream.CONTENT_TYPE + ", X-Turbo-Request-Id, X-Sec-Purpose) found");
        }
        List<String> warnings = new ArrayList<>();
        byte[] body = Codecs.decodeContent(m.responseBody(), m.responseHeader("Content-Encoding"));
        String text = Codecs.utf8(body.length > MAX_TEXT ? java.util.Arrays.copyOf(body, MAX_TEXT) : body);
        if (body.length > MAX_TEXT) warnings.add("Body larger than " + MAX_TEXT + " bytes; only the start was scanned");
        if (m.truncated()) warnings.add("Message body was truncated by the size limit");
        String ct = m.contentType().toLowerCase(Locale.ROOT);
        if (ct.contains("text/event-stream")) {
            String data = sseData(text);
            if (TurboStream.contains(data)) return streams("Turbo Stream (Server-Sent Events)", data, warnings);
        }
        if (ct.contains(TurboStream.CONTENT_TYPE) || startsWithStream(text)) {
            if (!TurboStream.contains(text)) throw new DecodeException("Turbo Stream response contains no <turbo-stream> elements");
            return streams(null, text, warnings);
        }
        String frame = m.requestHeader("Turbo-Frame");
        if (notBlank(frame)) return frameResponse(m, text, frame.strip(), warnings);
        DecodeResult page = page(text, warnings);
        if (page != null) return page;
        throw new DecodeException("No Turbo Stream elements, Turbo Frame or Turbo page markers found");
    }

    private static String direction(MessageContext m) {
        String d = m.webSocketDirection();
        if ("CLIENT_TO_SERVER".equals(d)) return "client → server";
        if ("SERVER_TO_CLIENT".equals(d)) return "server → client";
        return "message";
    }

    /** Joins the data: lines of an SSE body, one event per line block. */
    static String sseData(String body) {
        StringBuilder sb = new StringBuilder();
        for (String line : body.split("\r?\n", -1)) {
            if (line.startsWith("data:")) {
                String v = line.substring(5);
                if (v.startsWith(" ")) v = v.substring(1);
                sb.append(v).append('\n');
            }
        }
        return sb.toString();
    }

    private DecodeResult streams(String title, String text, List<String> prior) {
        TurboStream.Result r = TurboStream.parse(text);
        DecodedNode root = DecodedNode.object("Turbo Stream");
        root.add(TurboStream.toNode("Actions", r));
        List<String> w = new ArrayList<>(prior);
        w.addAll(r.warnings());
        String summary = (title == null ? "Turbo Stream" : title) + ": " + r.summaryList();
        return new DecodeResult(summary, root, null, w);
    }

    private DecodeResult request(MessageContext m) {
        DecodedNode root = DecodedNode.object("Turbo request");
        List<String> parts = new ArrayList<>();
        String frame = m.requestHeader("Turbo-Frame");
        if (notBlank(frame)) {
            root.put("Turbo-Frame (target frame id)", frame.strip());
            root.add(DecodedNode.note("frame navigation: the server should answer with HTML containing <turbo-frame id=\"" + frame.strip() + "\">"));
            parts.add("Turbo Frame request → #" + frame.strip());
        }
        boolean streams = acceptsStream(m);
        root.put("Accepts Turbo Streams", streams);
        if (streams) {
            root.put("Accept", m.requestHeader("Accept"));
            if (parts.isEmpty()) parts.add("Turbo Stream-accepting request");
        }
        String rid = m.requestHeader("X-Turbo-Request-Id");
        if (notBlank(rid)) {
            root.put("X-Turbo-Request-Id", rid.strip());
            root.add(DecodedNode.note("echoed as request-id on broadcast streams so the originating tab can ignore its own refresh"));
        }
        String purpose = m.requestHeader("X-Sec-Purpose");
        boolean prefetch = purpose != null && purpose.toLowerCase(Locale.ROOT).contains("prefetch");
        if (purpose != null) root.put("X-Sec-Purpose", purpose);
        if (prefetch) parts.add(parts.isEmpty() ? "Turbo prefetch" : "prefetch");
        DecodedNode other = DecodedNode.object("Other Turbo headers");
        for (Header h : m.requestHeaders()) {
            String n = h.name().toLowerCase(Locale.ROOT);
            if ((n.startsWith("turbo-") || n.startsWith("x-turbo-")) && !n.equals("turbo-frame") && !n.equals("x-turbo-request-id")) other.put(h.name(), h.value());
        }
        if (!other.isLeaf()) root.add(other);
        Map<String, List<String>> form = m.formParameters();
        if (!form.isEmpty()) {
            DecodedNode f = root.child("Form");
            form.forEach((k, v) -> v.forEach(x -> f.put(k.equals("_method") ? "_method (Rails method override)" : k, Codecs.truncate(x, 4000))));
        }
        if (parts.isEmpty()) parts.add("Turbo request");
        String method = Codecs.first(form, "_method");
        String verb = method != null ? method.toUpperCase(Locale.ROOT) + " (via _method)" : m.method();
        String summary = String.join(", ", parts) + " (" + verb + " " + m.path() + ")" + (notBlank(rid) ? " id " + rid.strip() : "");
        return DecodeResult.of(summary, root);
    }

    /** First {@code <turbo-frame id="…">} with the given id, or null. */
    static HtmlScan.Tag findFrame(String html, String id) {
        int i = 0;
        for (int guard = 0; guard < 10_000; guard++) {
            HtmlScan.Tag t = HtmlScan.find(html, "turbo-frame", i);
            if (t == null) return null;
            if (id.equals(t.attr("id"))) return t;
            i = t.end();
        }
        return null;
    }

    private DecodeResult frameResponse(MessageContext m, String html, String id, List<String> warnings) {
        DecodedNode root = DecodedNode.object("Turbo Frame response");
        root.put("Requested frame (Turbo-Frame header)", id);
        HtmlScan.Tag t = findFrame(html, id);
        String summary;
        if (t == null) {
            warnings.add("Response has no <turbo-frame id=\"" + id + "\">; Turbo will show \"Content missing\" (or visit the page if the frame has target=_top)");
            summary = "Turbo Frame response #" + id + ": matching frame missing";
        } else {
            DecodedNode f = root.child("<turbo-frame id=\"" + id + "\">");
            for (Map.Entry<String, String> e : t.attrs().entrySet()) f.put(frameAttrLabel(e.getKey()), e.getValue());
            int close = t.selfClosing() ? t.end() : HtmlScan.findClose(html, "turbo-frame", t.end());
            if (close < 0) {
                warnings.add("<turbo-frame id=\"" + id + "\"> is not closed");
                close = html.length();
            }
            String inner = html.substring(t.end(), Math.max(t.end(), close)).strip();
            f.add(DecodedNode.leaf("Inner HTML", Codecs.truncate(inner, MAX_INNER), DecodedNode.Type.HTML));
            List<String> bits = new ArrayList<>();
            for (String a : new String[]{"src", "loading", "target"}) if (t.attr(a) != null) bits.add(a + "=" + t.attr(a));
            summary = "Turbo Frame response #" + id + (bits.isEmpty() ? "" : " (" + String.join(", ", bits) + ")");
        }
        DecodeResult page = page(html, new ArrayList<>());
        if (page != null) root.add(renamed(page.root(), "Page"));
        return new DecodeResult(summary, root, null, warnings);
    }

    private static DecodedNode renamed(DecodedNode n, String name) {
        DecodedNode r = new DecodedNode(name, n.value(), n.type());
        n.children().forEach(r::add);
        return r;
    }

    private static String frameAttrLabel(String k) {
        return switch (k) {
            case "src" -> "src (lazy/eager load URL)";
            case "loading" -> "loading (eager|lazy)";
            case "target" -> "target (_top = navigate whole page)";
            case "disabled" -> "disabled (navigation off)";
            case "refresh" -> "refresh (morph = reload on page refresh)";
            case "autoscroll" -> "autoscroll";
            default -> k;
        };
    }

    /** Page hints: turbo meta tags, stream sources, frames and inline streams; null when the page has none. */
    private DecodeResult page(String html, List<String> warnings) {
        DecodedNode root = DecodedNode.object("Turbo page");
        DecodedNode metas = DecodedNode.object("Meta");
        DecodedNode sources = DecodedNode.array("Stream sources");
        DecodedNode frames = DecodedNode.array("Frames");
        List<String> streamNames = new ArrayList<>();
        List<String> metaSummary = new ArrayList<>();
        int frameCount = 0, sourceCount = 0;
        boolean inlineStreams = false;
        int i = 0;
        for (int guard = 0; guard < 2_000_000; guard++) {
            HtmlScan.Tag t = HtmlScan.next(html, i);
            if (t == null) break;
            i = Math.max(t.end(), t.start() + 1);
            if (t.closing()) continue;
            switch (t.name()) {
                case "script", "style" -> {
                    int e = HtmlScan.indexOfIgnoreCase(html, "</" + t.name(), t.end());
                    i = e < 0 ? html.length() : e;
                }
                case "meta" -> {
                    String n = t.attr("name");
                    if (n == null) break;
                    String ln = n.toLowerCase(Locale.ROOT);
                    if (!ln.startsWith("turbo-") && !ln.equals("view-transition")) break;
                    String c = t.attrs().getOrDefault("content", "");
                    String desc = META.get(ln);
                    if (metas.children().size() < MAX_LIST) metas.put(desc == null ? n : n + " — " + desc, c);
                    if (metaSummary.size() < 4) metaSummary.add(n + "=" + c);
                }
                case "turbo-cable-stream-source" -> {
                    sourceCount++;
                    if (sources.children().size() >= MAX_LIST) break;
                    DecodedNode s = DecodedNode.object("[" + sources.children().size() + "] " + t.attrs().getOrDefault("channel", "turbo-cable-stream-source"));
                    for (Map.Entry<String, String> e : t.attrs().entrySet()) {
                        if (e.getKey().equals("signed-stream-name")) {
                            SignedStreamName.Decoded d = SignedStreamName.decode("signed-stream-name", e.getValue());
                            s.add(d.node());
                            if (d.ok()) streamNames.add(d.display());
                        } else {
                            s.put(e.getKey(), e.getValue());
                        }
                    }
                    sources.add(s);
                }
                case "turbo-stream-source" -> {
                    sourceCount++;
                    if (sources.children().size() >= MAX_LIST) break;
                    DecodedNode s = DecodedNode.object("[" + sources.children().size() + "] turbo-stream-source");
                    t.attrs().forEach(s::put);
                    s.add(DecodedNode.note("WebSocket/EventSource endpoint that pushes raw Turbo Stream HTML"));
                    sources.add(s);
                }
                case "turbo-frame" -> {
                    frameCount++;
                    if (frames.children().size() >= MAX_LIST) break;
                    DecodedNode f = DecodedNode.object("#" + t.attrs().getOrDefault("id", "(no id)"));
                    for (Map.Entry<String, String> e : t.attrs().entrySet()) if (!e.getKey().equals("id")) f.put(frameAttrLabel(e.getKey()), e.getValue());
                    frames.add(f);
                }
                case "turbo-stream" -> inlineStreams = true;
                default -> {
                }
            }
        }
        if (!metas.isLeaf()) root.add(metas);
        if (!sources.isLeaf()) root.add(sources);
        if (!frames.isLeaf()) root.add(frames);
        TurboStream.Result inline = null;
        if (inlineStreams) {
            inline = TurboStream.parse(html);
            if (!inline.isEmpty()) {
                root.add(TurboStream.toNode("Inline Turbo Streams", inline));
                warnings.addAll(inline.warnings());
            }
        }
        if (root.isLeaf()) return null;
        List<String> parts = new ArrayList<>(metaSummary);
        if (sourceCount > 0) {
            String names = streamNames.isEmpty() ? "" : " (" + String.join(", ", streamNames.subList(0, Math.min(3, streamNames.size()))) + (streamNames.size() > 3 ? ", …" : "") + ")";
            parts.add(sourceCount + " stream source" + (sourceCount == 1 ? "" : "s") + names);
        }
        if (frameCount > 0) parts.add(frameCount + " frame" + (frameCount == 1 ? "" : "s"));
        if (inline != null && !inline.isEmpty()) parts.add("inline streams: " + inline.summaryList());
        return new DecodeResult("Turbo page: " + String.join(", ", parts), root, null, warnings);
    }
}
