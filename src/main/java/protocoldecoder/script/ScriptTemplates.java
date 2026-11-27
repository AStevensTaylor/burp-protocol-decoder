package protocoldecoder.script;

/** Starter script and API reference shown in the script editor. */
public final class ScriptTemplates {

    private ScriptTemplates() {
    }

    public static final String DEFAULT = """
            // Custom protocol decoder. Runs in a sandbox: no Java, file or network access,
            // and each call has a CPU-time limit. See the "Script API" tab for the full reference.

            // Return a confidence 0-100 (or true/false). 0 means "not my protocol".
            // Keep this fast: it runs for every message Burp displays.
            function match(msg) {
              if (msg.isRequest && msg.path.indexOf('/api/rpc') === 0
                  && msg.contentType.indexOf('json') >= 0) {
                return 80;
              }
              return 0;
            }

            // Return { summary, data, text, warnings }. `data` can be any JSON-like value and is
            // shown as a tree. Throw an Error to report that the message can't be decoded.
            function decode(msg) {
              var payload = JSON.parse(msg.bodyText);
              var data = {
                method: payload.method,
                params: payload.params
              };
              // e.g. a base64 + gzip blob inside the JSON:
              // data.blob = JSON.parse(codec.utf8Decode(codec.gunzip(codec.base64Decode(payload.blob))));
              log('decoded ' + Object.keys(payload).length + ' top-level keys');
              return { summary: 'RPC call: ' + payload.method, data: data };
            }
            """;

    public static final String API_REFERENCE = """
            SCRIPT CONTRACT
              function match(msg)   -> number 0..100 | boolean | {confidence, reason}
              function decode(msg)  -> {summary?, data?, text?, warnings?[]} | any value (shown as data)
              function passive(msg) -> [{title, severity?, confidence?, detail?, remediation?, evidence?[], evidenceIn?}]
              Both match() and passive() are optional; a script without match() only runs via rules/overrides.
              passive() runs in Burp's passive scanner (and on proxied WebSocket messages) when this decoder applies;
              severity: HIGH|MEDIUM|LOW|INFORMATION, confidence: CERTAIN|FIRM|TENTATIVE, evidence: strings to highlight,
              evidenceIn: "request"|"response" (default: the message being checked).
              throw new Error("reason") from decode() to show a decode error.

            THE msg OBJECT (read-only)
              kind               "request" | "response" | "websocket"
              isRequest / isResponse / isWebSocket
              method, url, host, path (no query), query (raw, without '?')
              statusCode         number, or null when there is no response
              contentType        Content-Type of the displayed message ("" if none)
              headers            [{name, value}] of the displayed message
              requestHeaders, responseHeaders
              header(name) / requestHeader(name) / responseHeader(name)   case-insensitive, null if absent
              body               displayed body as a binary string (one char per byte, 0-255)
              bodyText           displayed body decoded as UTF-8
              requestBody / requestBodyText, responseBody / responseBodyText
              queryParams        {name: firstValue}   (URL-decoded)
              formParams         {name: firstValue}   (urlencoded request bodies only)
              websocketDirection "CLIENT_TO_SERVER" | "SERVER_TO_CLIENT" | null
              truncated          true if bodies were cut at the configured size limit

            HELPERS (global `codec`)
              Binary data is passed around as binary strings (one char per byte).
              codec.base64Decode(s) -> bin        codec.base64Encode(bin) -> s   (std or URL-safe input)
              codec.hexDecode(s) -> bin           codec.hexEncode(bin) -> s
              codec.utf8Decode(bin) -> string     codec.utf8Encode(string) -> bin
              codec.urlDecode(s)                  codec.urlEncode(s)
              codec.parseQuery(s) -> {name: [values]}
              codec.gunzip(bin) -> bin            codec.inflate(bin) -> bin   (zlib or raw deflate)
              codec.decodeContent(bin, contentEncoding) -> bin   (gzip/deflate or sniffed gzip)
              codec.parseLenientJson(s) -> value  (JS object literals: single quotes, unquoted keys)
              log(...)                            message shown in the script tester / extension output

            JS ENGINE
              Mozilla Rhino (ES2015+ subset: let/const, arrow functions, template literals, Map/Set, JSON).
              No require/import, no Java interop, no timers, no network or file system.

            LIMITS (Settings tab)
              CPU time per call (match and decode separately), output tree size, body size passed in.
              Matchers that time out or throw 3 times in a row are suspended until the script is saved again.
            """;
}
