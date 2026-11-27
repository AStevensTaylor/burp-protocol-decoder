<img src="assets/icon.svg" width="96" height="96" alt="Protocol Decoder logo">

# Protocol Decoder for Burp Suite

A Burp Suite extension (Montoya API) for application protocols carried inside HTTP and WebSocket traffic.
For each protocol it:

- **decodes** messages in a **Decoded** tab, as a tree and as text, wherever Burp shows a message (Proxy, Repeater,
  Intruder, Logger, Site map, Organizer…);
- lets you **edit** decoded values in Repeater and Intercept, and **re-encodes** them automatically;
- **scans** them, through passive checks, active checks and protocol-aware insertion points in Burp's scanner.

Each protocol is a pluggable **decoder** (matcher + decoder) with an optional **scanner**. You can add your own
decoders, and passive checks, as sandboxed JavaScript from inside Burp, and use rules or manual choices to override
which decoder handles a message.

## Built-in protocols

| Protocol | Decodes | Scanner highlights |
|---|---|---|
| **DevExpress** | WebForms/MVC callbacks (`NAME\|LEN;VALUE;` segments), `/*DX*/` responses, Reporting calls | Insertion points inside callback segments; callback error disclosure; malformed-callback probe |
| **ASP.NET AJAX** | UpdatePanel async postbacks and delta responses, ASMX/WCF/PageMethods JSON (`d`, `__type`, `/Date()/`), proxy scripts, `.axd` | Service stack traces; proxy script method lists; `jsdebug`; verbose-error probe |
| **ASP.NET ViewState** | ObjectStateFormatter graph, split fields, EventValidation, MAC/encryption analysis | No-MAC / weak-MAC; embedded BinaryFormatter; **active MAC-enforcement test**; insertion points inside unprotected ViewState |
| **Blazor / SignalR** | `/_blazor` circuits (blazorpack and JSON), `JS.RenderBatch`, hub messages split across WebSocket frames (reassembled from Proxy history), negotiate, WebAssembly boot manifest, prerender markers | Detailed circuit errors; WASM debug build/assemblies; persisted state; insertion points in long-poll hub messages |
| **Next.js** | RSC Flight payloads, Server Actions, router-state headers, `__NEXT_DATA__`, `/_next/data` | Secrets in page data; Server Action inventory; dev server; **CVE-2025-29927 middleware bypass probe**; insertion points in action args |
| **Laravel Livewire** | v3 `/livewire/update` and v2 `/livewire/message` (snapshots, synthesizers, effects), page markers | Model class/key exposure; debug pages; **snapshot checksum enforcement test** |
| **Hotwire Turbo** / **Action Cable** | Turbo Streams, Turbo Frames, signed stream names (GlobalID / Marshal); Action Cable frames | GlobalID / Marshal stream names; sensitive broadcasts; cross-origin cable handshake |
| **Socket.IO / Engine.IO** | v3/v4 WebSocket and polling payloads, events, acks, namespaces, binary attachments | Error/sensitive data in events; polling enabled; cross-origin handshake; insertion points in polling events |
| **Phoenix Channels / LiveView** | v1/v2/binary serializers, LiveView events and diffs, signed tokens | Readable token data; error replies; cross-origin socket; insertion points in long-poll messages |
| **GraphQL** / **tRPC** | Queries (formatted), batches, persisted queries, uploads, responses, GraphQL over WebSocket; tRPC batches/superjson | Introspection, suggestions, verbose errors, batching, query-over-GET CSRF; insertion points in **inline literals** and string-encoded variables; tRPC `input` |
| **gRPC / Protobuf** | Schemaless protobuf, gRPC, gRPC-Web(-text), Connect, `x-protobuf`; status names and details | Insertion points in **every protobuf field** (lengths, framing, compression rebuilt); error/debug-info disclosure; reflection probe |
| **SAML / WS-Fed** | Redirect/POST/artifact bindings, assertions, signatures, encryption (hardened XML parser) | Unsigned assertions, SHA-1, XSW indicators, weak conditions; **active signature-required / signature-validated tests**; insertion points in NameID/attributes |
| **Firebase** | Firestore WebChannel and REST (typed values), Realtime Database WS/long-poll/REST, Auth (JWTs), web config | Unauthenticated RTDB read / Firestore read & list (read-only); token claims; account enumeration; insertion points in WebChannel requests |
| **Google batchexecute** | `f.req` RPC envelopes and chunked `)]}'` responses, JSON-in-JSON unpacked | Insertion points through nested JSON-in-string; RPC inventory; error details |
| **New Relic** | Browser/mobile/APM telemetry, tracing headers, `NREUM` page config | Sensitive data sent to New Relic; exposed agent config; APM license key in client traffic |
| **Serialized objects** | Java, .NET BinaryFormatter, PHP, Python pickle, Ruby Marshal, Json.NET `$type` in params/cookies/headers/bodies (any base64/gzip/hex wrapping) | Client-supplied native serialization by format; gadget class names; insertion points in serialized strings (lengths and wrappers rebuilt) |

Decoders are pure parsers: nothing is deserialized, and no exploit payloads are generated.

## Build and install

Requirements: JDK 21 or newer.

```sh
./gradlew build
```

In Burp, go to **Extensions → Installed → Add**, pick type *Java*, and choose
`build/libs/burp-protocol-decoder-<version>.jar`. Rhino and Gson are bundled into that jar.
Prebuilt jars are attached to each GitHub release; every merge that changes the jar
publishes one.

## CI and releases

`.github/workflows/build.yml` builds and tests every push and pull request, uploads the
jar as a build artifact (and the test report when something fails), and publishes a
release when `main` moves. `.github/workflows/release-label.yml` is the status check
that makes the release decision possible.

Every pull request carries exactly one release label; the **release label** check fails
until it does:

| Label | Effect on the newest `vX.Y.Z` tag |
|---|---|
| `release:major` | `X+1.0.0`: incompatible change to how the extension is used or configured |
| `release:minor` | `X.Y+1.0`: new capability, backwards compatible |
| `release:patch` | `X.Y.Z+1`: fix or internal change, no new capability |
| `release:none` | No release. Docs, CI, and anything that does not change the jar |

On a push to `main` the release job reads the label off the merged pull request, works
out the next version from the newest `v*` tag (starting from `0.0.0` when there is
none), rebuilds and retests the jar with `-Pversion=<next>`, then creates the tag and a
release with generated notes and attaches `burp-protocol-decoder-<version>.jar`. A
commit pushed straight to `main` has no pull request and releases nothing; run the
workflow manually with a `bump` input if it should have.

The tags are the source of truth for the version. `version` in `gradle.properties` is
only the fallback for local builds. The jar manifest records `Implementation-Version`
and `Implementation-Commit`.

- Every action is pinned to a commit SHA, with its tag in a trailing comment.
  Dependabot (`.github/dependabot.yml`) proposes Gradle and Actions updates weekly.
- The Gradle wrapper jar is checked against the checksum Gradle publishes for the
  distribution `gradle-wrapper.properties` names, before anything else runs.
- Pull requests cannot reach a write token. The workflow defaults to `contents: read`;
  only the release job widens that (`contents: write`, `pull-requests: read`), and it
  runs only on a push to `main` or a manual run. The label check runs with
  `permissions: {}` and never checks out the branch.

## How a decoder is chosen

The first of these that applies wins:

1. **Manual choice for this message.** Use the *Decoder* picker in the Decoded tab, or right-click → *Protocol Decoder → Decode as*. The choice is stored per exchange (method + URL + request body) and per side (request, response or WebSocket message). It is saved in the Burp project unless you turn that off.
2. **Rules** (*Protocol Decoder → Rules*). Rules are checked from top to bottom and the first enabled match wins. A rule's conditions can test the URL, host, path, query, method, a request or response header, the request, response or displayed body, the Content-Type, the status code or the WebSocket direction. The operators are contains, equals, starts/ends with, regex, exists, and their negations. A rule either forces a decoder or turns decoding off. *Create rule…* in the Decoded tab, or in the context menu, prefills a rule from the current message and shows whether the rule matches it.
3. **Auto-detection.** Every enabled decoder's matcher returns a confidence from 0 to 100, and the highest wins. For example, a DevExpress callback that also carries a New Relic `newrelic` header is decoded as DevExpress (95), while the New Relic decoder (40) is still listed in the picker.

By default, the Decoded tab only appears when a decoder applies. To pick a decoder for any message, turn on
*Settings & help → Show the Decoded tab on every message*.

## Editing decoded messages

In editable Burp editors (Repeater, Intercept) the Decoded tab gets an **Edit** tab. Changes are re-encoded into the
message automatically: lengths, framing, compression, base64 and URL-encoding, JSON inside strings and so on. They
reach Burp when you switch back to Raw/Pretty or send the request. Edits stack on top of each other, the decoded view
refreshes after each one, and *Revert all edits* restores the original.

- **Fields** list every editable value in a request, for all protocols. They come from the scanners' insertion
  points, so a protobuf field, a DevExpress segment value, a GraphQL literal or a string inside a serialized object
  can each be edited in place.
- **Documents** edit a whole decoded structure as text, for requests, intercepted responses and WebSocket messages.
  Each protocol offers its own:
  - SAML XML (all bindings, including the IdP's auto-post form); PHP `serialize()` text, with string lengths
    auto-fixed
  - ASP.NET UpdatePanel deltas; ASMX/WCF JSON; the DevExpress callback outline and `/*DX*/` results
  - GraphQL query and variables; tRPC input; Next.js Server Action arguments, router state and `__NEXT_DATA__`
  - batchexecute RPC payloads; Firestore and Realtime Database JSON; Livewire requests and snapshots
  - protobuf as editable text (`1: "alice"`, `2 { 3: 42 }`, `4: b"\x00"`) for gRPC, gRPC-Web, Connect and raw
    protobuf; Blazor MessagePack as lossless JSON; Socket.IO packets; Phoenix, Action Cable and Turbo Stream messages
- **Exact round trips.** Applying an unedited document reproduces the original bytes. Parts you don't touch keep
  their original encoding.
- **Signed data.** Documents whose signature or checksum an edit would break (SAML, Livewire snapshots) are marked
  "(signed)", so you can test whether the server enforces it.
- Truncated messages, those over the size limit, can't be edited.

To support editing in your own Java decoder, implement `protocoldecoder.edit.MessageCodec` and register it with
`editEngine.register(...)`.

## Scanner integration

Protocol checks plug into Burp's scanner. The **Scan checks** tab has switches for each feature and a checkbox for
every check.

- **Passive checks** run on proxied traffic and passive scans. Proxied **WebSocket** messages are checked as well,
  which Burp's scanner doesn't do itself; those issues are added to the site map.
- **Active checks** run only in active scans you start. They are read-only and send a small, fixed number of requests
  (each check's description says how many). Most are differential, comparing against the base response or a control.
- **Protocol-aware insertion points** let Burp's own payloads (SQLi, XSS, …) reach values nested inside encodings Burp
  can't edit: length prefixes, protobuf, base64/gzip wrappers, JSON inside strings, GraphQL literals, serialized
  objects. The surrounding structure is rebuilt for every payload.
- **Which checks run.** A protocol's checks run whenever its decoder matches a message, or a rule or manual choice
  forces it. A "Don't decode" rule or manual choice also excludes the message from scanning.
- **Protocol detected.** An informational issue, raised once per host, names each protocol in use.

Custom scripts can add passive checks by defining `passive(msg)`, returning
`[{title, severity, confidence, detail, remediation, evidence: [...]}]`. Scripts can't send requests.

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

Then register it in `protocoldecoder.App`. To add scanning, implement `protocoldecoder.scan.ProtocolScanner`
(passive checks, active checks, insertion points) and register it with `scanEngine.register(...)`. `InsertionPoints`
and `ScanPatterns` have helpers for re-encoding and for spotting stack traces or sensitive values. `MessageContext` doesn't depend on Burp: it always carries the request,
plus the response when there is one, and `kind()` says which side is displayed. This makes decoders unit-testable
without Burp. Build the output with `DecodedNode`, or `JsonTree.toNode(...)` for JSON. See `builtin/devexpress` for a small, complete example of both.

## Project layout

```
src/main/java/protocoldecoder/
  core/        MessageContext, ProtocolDecoder, DecoderRegistry, DecoderEngine (override → rule → auto), OverrideStore
  rules/       Rule, Condition, operators/fields, RuleSet
  builtin/     one package per protocol: <Name>Decoder + <Name>Scanner (+ parsers/writers)
  edit/        EditEngine, MessageCodec/EditableDocument, MessagePatch, JSON document helpers
  scan/        ScanEngine, PassiveCheck/ActiveCheck/InsertionPoint, Finding, InsertionPoints, ScanPatterns
  script/      ScriptSandbox (Rhino), JsMessage/JsHelpers/JsConvert, ScriptDecoder, templates & API reference
  persistence/ Settings, ConfigStore, JSON codec, export bundles
  ui/          Decoded tab (MessageDecodePanel/DecodedView), suite tab panels, rule and script editors
  burp/        Montoya entry point, editor providers, context menu, scanner/proxy adapter (BurpScanning)
```

Run the tests with `./gradlew test` (about 700). They cover every decoder and scanner, including insertion-point
round trips and active checks against a fake HTTP sender, plus the rule engine, the sandbox security tests, the
example script and a headless smoke test of the Swing UI.
