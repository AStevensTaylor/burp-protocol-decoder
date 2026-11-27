<img src="assets/icon.svg" width="64" height="64" alt="">

# Protocol Decoder for Burp Suite

A Burp Suite extension (Montoya API) that recognises application protocols inside HTTP and WebSocket traffic and adds a
**Decoded** tab, showing the decoded message as a tree and as text, wherever Burp shows a message (Proxy, Repeater,
Intruder, Logger, Site map, Organizer…).

It is a general framework: each protocol is a **decoder**, made of a matcher and a decoder. It ships with:

| Decoder | Recognises |
|---|---|
| **DevExpress** | ASP.NET WebForms callbacks (`__CALLBACKID` / `__CALLBACKPARAM` with DevExpress `NAME\|LEN;VALUE;` segments), MVC callbacks (`DXCallbackName` / `DXCallbackArgument`), `/*DX*/({...})` callback responses including the ASP.NET `s<len>\|<validation>` envelope, and Reporting / Query Builder service calls (`DXXRDV`, `DXXRD`, `DXXQB`). |
| **Blazor / SignalR** | Blazor Server / Web App circuits on `/_blazor`: WebSocket frames and long-polling bodies in the MessagePack (`blazorpack`) or JSON hub protocol, with Blazor hub methods and their arguments named (`StartCircuit`, `BeginInvokeDotNetFromJS`, `DispatchBrowserEvent`, `JS.BeginInvokeJS`…) and `JS.RenderBatch` binaries decoded into component edits, frames and the string table. Also negotiate and disconnect calls, `blazor.boot.json` (WebAssembly), and the `<!--Blazor…-->` markers and persisted state in prerendered HTML. Other SignalR hubs are recognised at lower confidence. |
| **New Relic** | Browser agent beacons (`bam*.nr-data.net`: RUM, events, jserrors, ins, resources, logs, blobs; gzip and BEL payloads), mobile agent and APM collector traffic, `newrelic` / `traceparent` / `tracestate@nr` / `X-NewRelic-*` headers on any request, and the `NREUM.info` / `NREUM.init` / `NREUM.loader_config` configuration embedded in HTML pages. |

You can add your own decoders as sandboxed JavaScript from inside Burp, and use rules or manual choices to override
which decoder handles a message.

## Build and install

Requirements: JDK 21 or newer.

```sh
./gradlew build
```

In Burp, go to **Extensions → Installed → Add**, pick type *Java*, and choose
`build/libs/burp-protocol-decoder-0.1.0.jar`. Rhino and Gson are bundled into that jar.

## How a decoder is chosen

The first of these that applies wins:

1. **Manual choice for this message.** Use the *Decoder* picker in the Decoded tab, or right-click → *Protocol Decoder → Decode as*. The choice is stored per exchange (method + URL + request body) and per side (request, response or WebSocket message). It is saved in the Burp project unless you turn that off.
2. **Rules** (*Protocol Decoder → Rules*). Rules are checked from top to bottom and the first enabled match wins. A rule's conditions can test the URL, host, path, query, method, a request or response header, the request, response or displayed body, the Content-Type, the status code or the WebSocket direction. The operators are contains, equals, starts/ends with, regex, exists, and their negations. A rule either forces a decoder or turns decoding off. *Create rule…* in the Decoded tab, or in the context menu, prefills a rule from the current message and shows whether the rule matches it.
3. **Auto-detection.** Every enabled decoder's matcher returns a confidence from 0 to 100, and the highest wins. For example, a DevExpress callback that also carries a New Relic `newrelic` header is decoded as DevExpress (95), while the New Relic decoder (40) is still listed in the picker.

By default, the Decoded tab only appears when a decoder applies. To pick a decoder for any message, turn on
*Settings & help → Show the Decoded tab on every message*.

## Writing a custom decoder

Go to **Protocol Decoder → Decoders → New script…**. The editor opens with a working template, a tester and the API
reference. To load a real message into the tester, right-click it in Burp → *Protocol Decoder → Send to script tester*,
then click *Load sample sent from Burp* and run the test with **Ctrl+Enter**. The tester shows the `match()` result,
the decoded tree, the `log()` output and the timings.

```js
// 0..100, boolean, or {confidence, reason}. Runs for every message, so keep it cheap.
function match(msg) {
  return msg.isRequest && msg.path.startsWith('/api/rpc') ? 80 : 0;
}

// Return {summary, data, text, warnings}; `data` is any JSON-like value and is shown as a tree.
function decode(msg) {
  var body = JSON.parse(codec.utf8Decode(codec.gunzip(codec.base64Decode(msg.bodyText))));
  return { summary: 'RPC ' + body.method, data: body };
}
```

- `msg` exposes `kind`, `isRequest`, `isResponse`, `isWebSocket`, `method`, `url`, `host`, `path`, `query`, `statusCode`, `contentType`, `headers` / `requestHeaders` / `responseHeaders`, `header(name)`, `body` (a binary string), `bodyText`, the request and response bodies, `queryParams`, `formParams` and `websocketDirection`.
- `codec` provides base64 (standard and URL-safe), hex, UTF-8, URL encoding, `parseQuery`, `gunzip`, `inflate`, `decodeContent` and `parseLenientJson`, which accepts JavaScript object literals. Binary data is passed around as binary strings, one character per byte.
- A script without `match()` only runs when a rule or a manual choice selects it.
- [`examples/jwt-bearer.js`](examples/jwt-bearer.js) is a complete example. Import it with *Decoders → Import…*.
- *Export…* and *Import…* share scripts and rules as a single JSON file.

Scripts, rules, enabled state and settings are stored in Burp's global preferences, so they are shared across projects.
Manual choices are stored in the project.

### Sandbox

Scripts run in Mozilla Rhino, configured as follows:

- **No Java interop.** The global scope is built with `initSafeStandardObjects`, so there is no `Packages`, `java` or `JavaImporter`. A `ClassShutter` hides every Java class, and only JavaScript-native values are passed in. The tests try the usual escape routes (`getClass()`, constructor chains, `Packages`, `Java.type`…).
- **No I/O.** Scripts have no file, network, timer or module access.
- **CPU limits.** `match()` gets 250 ms per call by default and `decode()` gets 3 s. The limits are enforced inside the interpreter loop, and a script can't catch the timeout with `try/catch/finally`. A wall-clock timeout backs this up.
- **Shared built-ins are frozen.** One script can't change `JSON`, `Array.prototype` and so on for others. Each call runs in a fresh scope.
- **Bounded size.** Recursion depth, the size of bodies passed in, the number of tree nodes returned, and decompression output (32 MB) are all capped.
- **Automatic suspension.** A matcher that throws or times out 3 times in a row is suspended until the script is saved again, or until you click *Resume matcher*. This keeps a broken script from slowing down every message.

**Limitation:** the JVM can't cap the memory of a single thread, so a hostile script could allocate a lot of memory
before its time limit. A pathological regex that is stuck inside the native regex engine also isn't interrupted. It is
abandoned after the timeout, and its matcher gets suspended. Review scripts from others before you import them.

## Adding a built-in decoder

To add a decoder in Java, implement `protocoldecoder.core.ProtocolDecoder`:

```java
public interface ProtocolDecoder {
    String id();
    String name();
    MatchResult match(MessageContext message);                         // fast, never throws
    DecodeResult decode(MessageContext message) throws DecodeException; // may be forced by rules/overrides
}
```

Then register it in `protocoldecoder.App`. `MessageContext` doesn't depend on Burp: it always carries the request,
plus the response when there is one, and `kind()` says which side is displayed. This makes decoders unit-testable
without Burp. Build the output with `DecodedNode`, or `JsonTree.toNode(...)` for JSON. See `builtin/devexpress`, `builtin/blazor` and
`builtin/newrelic`.

## Project layout

```
src/main/java/protocoldecoder/
  core/        MessageContext, ProtocolDecoder, DecoderRegistry, DecoderEngine (override → rule → auto), OverrideStore
  rules/       Rule, Condition, operators/fields, RuleSet
  builtin/     devexpress/, newrelic/, blazor/ (SignalR framing, MessagePack reader, RenderBatch)
  script/      ScriptSandbox (Rhino), JsMessage/JsHelpers/JsConvert, ScriptDecoder, templates & API reference
  persistence/ Settings, ConfigStore, JSON codec, export bundles
  ui/          Decoded tab (MessageDecodePanel/DecodedView), suite tab panels, rule and script editors
  burp/        Montoya entry point, editor providers, context menu, Montoya → MessageContext adapter
```

Run the tests with `./gradlew test`. They cover the decoders, the rule engine, the sandbox security tests, the example
script and a headless smoke test of the Swing UI.
