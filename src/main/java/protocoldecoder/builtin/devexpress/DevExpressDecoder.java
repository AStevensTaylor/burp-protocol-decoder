package protocoldecoder.builtin.devexpress;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import protocoldecoder.core.DecodeException;
import protocoldecoder.core.DecodeResult;
import protocoldecoder.core.DecodedNode;
import protocoldecoder.core.MatchResult;
import protocoldecoder.core.MessageContext;
import protocoldecoder.core.ProtocolDecoder;
import protocoldecoder.util.Codecs;
import protocoldecoder.util.JsonTree;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * DevExpress ASP.NET (WebForms and MVC) callbacks and DevExpress Reporting/Query Builder service calls.
 *
 * <p>Requests: {@code __CALLBACKID}/{@code __CALLBACKPARAM} (WebForms) or {@code DXCallbackName}/
 * {@code DXCallbackArgument} (MVC) form posts, with the DevExpress length-prefixed argument format; and
 * {@code actionKey}/{@code arg} posts to {@code DXXRDV}/{@code DXXRD}/{@code DXXQB} handlers.</p>
 *
 * <p>Responses: ASP.NET callback envelope ({@code [s|e]<validationLength>|<validation><result>}) wrapping a
 * {@code /*DX*&#47;(&#123;...&#125;)} JavaScript literal; or JSON from the reporting handlers.</p>
 */
public final class DevExpressDecoder implements ProtocolDecoder {

    public static final String ID = "devexpress";

    private static final Pattern DX_MARKER = Pattern.compile("/\\*DX\\*/\\s*\\(");
    private static final Pattern REPORTING_PATH = Pattern.compile("(?i)/(DXXRDV|DXXRD|DXXQB|DXQB|DXXRDVAJ|DXDD)(\\.axd)?(/|$)");
    private static final Pattern ASPNET_STATE = Pattern.compile("^__(VIEWSTATE.*|EVENTVALIDATION|EVENTTARGET|EVENTARGUMENT|PREVIOUSPAGE|LASTFOCUS|SCROLLPOSITION[XY]|VIEWSTATEGENERATOR|VIEWSTATEENCRYPTED|REQUESTDIGEST)$");
    private static final int SNIFF = 512;

    @Override public String id() { return ID; }
    @Override public String name() { return "DevExpress"; }
    @Override public String description() {
        return "DevExpress ASP.NET WebForms/MVC callbacks (__CALLBACKPARAM, /*DX*/ responses) and Reporting service calls";
    }

    @Override
    public MatchResult match(MessageContext m) {
        if (m.isWebSocket()) return MatchResult.NONE;
        if (m.isRequest()) return matchRequest(m);
        MatchResult r = MatchResult.NONE;
        String head = head(m.responseBodyText()).strip();
        if (DX_MARKER.matcher(head).find()) r = MatchResult.of(95, "/*DX*/ callback response");
        else if (isReportingPath(m) && (head.startsWith("{") || head.startsWith("["))) r = MatchResult.of(75, "DevExpress reporting service response");
        else if (matchRequest(m).confidence() >= 80 && !m.responseBodyText().isBlank()) {
            r = MatchResult.of(70, "response to a DevExpress callback");
        }
        return r;
    }

    private MatchResult matchRequest(MessageContext m) {
        String body = m.requestBodyText();
        if (body.isEmpty() && m.query().isEmpty()) return MatchResult.NONE;
        // Cheap substring checks before parsing parameters.
        boolean aspCallback = body.contains("__CALLBACKID=") && body.contains("__CALLBACKPARAM=");
        boolean mvcCallback = body.contains("DXCallbackName=") || body.contains("DXCallbackArgument=");
        if (aspCallback) {
            boolean dx = body.contains("DXScript=") || body.contains("__CALLBACKPARAM=c0%3A") || body.contains("__CALLBACKPARAM=c0:")
                    || body.contains("%24DX") || body.contains("$DX");
            return MatchResult.of(dx ? 95 : 70, dx ? "ASP.NET callback with DevExpress markers" : "ASP.NET client callback");
        }
        if (mvcCallback) return MatchResult.of(95, "DevExpress MVC callback");
        if (isReportingPath(m) && (body.contains("actionKey=") || m.query().contains("actionKey="))) {
            return MatchResult.of(90, "DevExpress reporting service call");
        }
        return MatchResult.NONE;
    }

    private static boolean isReportingPath(MessageContext m) {
        return REPORTING_PATH.matcher(m.path()).find();
    }

    private static String head(String s) {
        return s.length() > SNIFF ? s.substring(0, SNIFF) : s;
    }

    @Override
    public DecodeResult decode(MessageContext m) throws DecodeException {
        return m.isResponse() ? decodeResponse(m) : decodeRequest(m);
    }

    // ---------------------------------------------------------------- requests

    private DecodeResult decodeRequest(MessageContext m) throws DecodeException {
        Map<String, List<String>> params = m.allRequestParameters();
        if (params.isEmpty() && !m.requestBodyText().isEmpty()) {
            params = Codecs.parseQuery(m.requestBodyText()); // content-type missing or wrong
        }
        if (params.isEmpty()) throw new DecodeException("No form or query parameters to decode");

        DecodedNode root = DecodedNode.object("DevExpress request");
        List<String> warnings = new ArrayList<>();
        String summary;

        String callbackId = Codecs.first(params, "__CALLBACKID");
        String callbackParam = Codecs.first(params, "__CALLBACKPARAM");
        String mvcName = Codecs.first(params, "DXCallbackName");
        String mvcArg = Codecs.first(params, "DXCallbackArgument");
        String actionKey = Codecs.first(params, "actionKey");

        if (callbackId != null || callbackParam != null) {
            DecodedNode cb = root.child("Callback");
            cb.put("Control (__CALLBACKID)", callbackId);
            cb.put("Raw __CALLBACKPARAM", callbackParam);
            DxCallbackArgs.Parsed parsed = DxCallbackArgs.parse(callbackParam == null ? "" : callbackParam);
            cb.add(parsed.tree());
            if (!parsed.structured()) warnings.add("Callback argument is not in DevExpress segment format; shown as-is");
            summary = "Callback → " + shortControl(callbackId) + (parsed.command() == null ? "" : " (" + parsed.command() + ")");
        } else if (mvcName != null || mvcArg != null) {
            DecodedNode cb = root.child("MVC callback");
            cb.put("Extension (DXCallbackName)", mvcName);
            cb.put("Raw DXCallbackArgument", mvcArg);
            DxCallbackArgs.Parsed parsed = DxCallbackArgs.parse(mvcArg == null ? "" : mvcArg);
            cb.add(parsed.tree());
            summary = "MVC callback → " + mvcName + (parsed.command() == null ? "" : " (" + parsed.command() + ")");
        } else if (actionKey != null) {
            DecodedNode call = root.child("Reporting service call");
            call.put("Action", actionKey);
            String arg = Codecs.first(params, "arg");
            if (arg != null) call.add(smartValue("Argument", arg));
            summary = "Reporting → " + actionKey;
        } else {
            summary = "DevExpress form post";
            warnings.add("No __CALLBACKPARAM, DXCallbackArgument or actionKey found");
        }

        DecodedNode dxFields = DecodedNode.object("DevExpress fields");
        DecodedNode aspnet = DecodedNode.object("ASP.NET state");
        DecodedNode other = DecodedNode.object("Other parameters");
        for (Map.Entry<String, List<String>> e : params.entrySet()) {
            String k = e.getKey();
            if (k.equals("__CALLBACKID") || k.equals("__CALLBACKPARAM") || k.equals("DXCallbackName")
                    || k.equals("DXCallbackArgument") || k.equals("actionKey") || k.equals("arg")) {
                continue;
            }
            for (String v : e.getValue()) {
                if (ASPNET_STATE.matcher(k).matches()) {
                    aspnet.add(k.startsWith("__VIEWSTATE") && v.length() > 200
                            ? DecodedNode.leaf(k, Codecs.truncate(v, 200) + "  (use Burp's ViewState tab to decode)")
                            : DecodedNode.leaf(k, v));
                } else if (isDxField(k)) {
                    dxFields.add(dxField(k, v));
                } else {
                    other.add(smartValue(k, v));
                }
            }
        }
        if (!dxFields.isLeaf()) root.add(dxFields);
        if (!aspnet.isLeaf()) root.add(aspnet);
        if (!other.isLeaf()) root.add(other);
        return new DecodeResult(summary, root, null, warnings);
    }

    private static boolean isDxField(String k) {
        return k.startsWith("DX") || k.contains("$DX") || k.endsWith("CallbackState") || k.endsWith("$State")
                || k.endsWith("_DXKVInput") || k.endsWith("_DXSelInput") || k.endsWith("_DXFocusedRowInput");
    }

    private static DecodedNode dxField(String k, String v) {
        if (k.equals("DXScript") || k.equals("DXCss")) {
            DecodedNode n = DecodedNode.array(k + " (loaded resources)");
            for (String part : v.split(",")) n.add(DecodedNode.leaf("", part.trim()));
            return n;
        }
        if (k.endsWith("CallbackState")) {
            byte[] raw = Codecs.base64Decode(v);
            DecodedNode n = DecodedNode.object(k);
            n.put("Raw", v);
            if (raw != null) {
                n.put("Decoded bytes", raw.length);
                n.add(DecodedNode.leaf("Hex", Codecs.hexPreview(raw, 64), DecodedNode.Type.BINARY));
                List<String> strings = printableStrings(raw, 4);
                if (!strings.isEmpty()) {
                    DecodedNode s = DecodedNode.array("Embedded strings");
                    for (String str : strings) s.add(DecodedNode.leaf("", str));
                    n.add(s);
                }
            }
            return n;
        }
        return smartValue(k, v);
    }

    /** Renders a value, parsing it as JSON or DX segment format where that works. */
    private static DecodedNode smartValue(String name, String v) {
        if (JsonTree.looksLikeJson(v)) {
            JsonElement e = JsonTree.parseLenient(v);
            if (e != null) return JsonTree.toNode(name, e, true);
        }
        return DecodedNode.leaf(name, v);
    }

    private static List<String> printableStrings(byte[] b, int min) {
        List<String> out = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        for (byte x : b) {
            int c = x & 0xff;
            if (c >= 0x20 && c < 0x7f) {
                cur.append((char) c);
            } else {
                if (cur.length() >= min) out.add(cur.toString());
                cur.setLength(0);
            }
            if (out.size() >= 50) break;
        }
        if (cur.length() >= min) out.add(cur.toString());
        return out;
    }

    private static String shortControl(String id) {
        if (id == null) return "(unknown control)";
        int i = Math.max(id.lastIndexOf('$'), id.lastIndexOf('_'));
        return i >= 0 && i < id.length() - 1 ? id.substring(i + 1) : id;
    }

    // ---------------------------------------------------------------- responses

    private DecodeResult decodeResponse(MessageContext m) throws DecodeException {
        byte[] bytes = Codecs.decodeContent(m.responseBody(), m.responseHeader("Content-Encoding"));
        String text = Codecs.utf8(bytes).strip();
        if (text.isEmpty()) throw new DecodeException("Empty response body");
        List<String> warnings = new ArrayList<>();
        DecodedNode root = DecodedNode.object("DevExpress response");

        Matcher dx = DX_MARKER.matcher(text);
        if (!dx.find()) {
            JsonElement json = JsonTree.parseLenient(text);
            if (json == null) throw new DecodeException("Response is neither a /*DX*/ callback result nor JSON");
            root.add(JsonTree.toNode("Body", json, true));
            String summary = "Reporting response";
            if (json.isJsonObject() && json.getAsJsonObject().has("success")) {
                summary += " (success=" + json.getAsJsonObject().get("success") + ")";
            }
            return new DecodeResult(summary, root, null, warnings);
        }

        // ASP.NET callback envelope before the DX literal.
        String envelope = text.substring(0, dx.start());
        DecodedNode env = describeEnvelope(envelope);
        if (env != null) root.add(env);

        int open = dx.end() - 1; // the '('
        int close = text.lastIndexOf(')');
        if (close <= open) throw new DecodeException("Unterminated /*DX*/( … ) literal");
        String literal = text.substring(open + 1, close).strip();
        String trailing = text.substring(close + 1).strip();
        if (!trailing.isEmpty() && !trailing.equals(";")) warnings.add("Unexpected text after the DX literal: " + Codecs.truncate(trailing, 80));

        JsonElement e = JsonTree.parseLenient(literal);
        if (e == null) {
            warnings.add("Could not parse the DX literal as a JavaScript object; showing raw text");
            root.add(DecodedNode.leaf("Literal", literal));
            return new DecodeResult("DevExpress callback result (unparsed)", root, null, warnings);
        }
        root.add(JsonTree.toNode("Result", e, true));

        String summary = "Callback result";
        if (e.isJsonObject()) {
            JsonObject o = e.getAsJsonObject();
            if (o.has("id")) summary += " #" + o.get("id").getAsString();
            if (o.has("error")) {
                summary += " — ERROR";
                JsonElement err = o.get("error");
                if (err.isJsonObject() && err.getAsJsonObject().has("message")) {
                    summary += ": " + err.getAsJsonObject().get("message").getAsString();
                }
            } else if (o.has("redirect")) {
                summary += " — redirect to " + o.get("redirect").getAsString();
            } else if (o.has("result")) {
                JsonElement r = o.get("result");
                if (r.isJsonObject()) summary += " — keys: " + String.join(", ", r.getAsJsonObject().keySet());
            }
        }
        return new DecodeResult(summary, root, null, warnings);
    }

    /** Explains the {@code [s|e]<len>|<eventValidation>} prefix ASP.NET puts before callback results. */
    static DecodedNode describeEnvelope(String envelope) {
        if (envelope.isEmpty()) return null;
        DecodedNode n = DecodedNode.object("ASP.NET callback envelope");
        String rest = envelope;
        if (rest.startsWith("s") || rest.startsWith("e")) {
            n.put("Status", rest.startsWith("s") ? "s (success)" : "e (error)");
            rest = rest.substring(1);
        }
        int bar = rest.indexOf('|');
        if (bar > 0 && rest.substring(0, bar).chars().allMatch(Character::isDigit)) {
            int len = Integer.parseInt(rest.substring(0, bar));
            n.put("Event validation length", len);
            String val = rest.substring(bar + 1, Math.min(rest.length(), bar + 1 + len));
            if (!val.isEmpty()) n.put("__EVENTVALIDATION", val);
            rest = rest.substring(Math.min(rest.length(), bar + 1 + len));
        }
        if (!rest.isEmpty()) n.put("Other prefix", rest);
        return n;
    }

    @Override
    public String toString() {
        return name().toLowerCase(Locale.ROOT);
    }
}
