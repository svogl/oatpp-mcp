# Security findings — oatpp-mcp

Durable record of the vulnerabilities reported against this module, what was verified on this
tree, and where the fix landed. **Update the status column as the fix PRs merge** — this file is
the thread that runs through them.

Verified against `main` @ `fee4651` with oatpp 1.4.0. Everything marked *verified* was reproduced
by running the code, not by reading it.

## Status

| ID | Finding | Severity | Status | Test |
|----|---------|----------|--------|------|
| [F1](#f1--request-smuggling-via-tool-arguments) | Request smuggling via tool arguments | High | **fixed** | `HttpSanitizeTest`, `ToolHttpFramingTest` |
| [F2](#f2--session-identifiers-are-heap-addresses) | Session identifiers are heap addresses | High | **fixed** | `UuidTest`, `SessionIdTest` |
| [F3](#f3--remote-denial-of-service-on-malformed-messages) | Remote DoS on malformed messages | High | **fixed** | `ListenerMessageTest` |
| [F4](#f4--no-origin-host-or-peer-validation-on-the-sse-endpoints) | No Origin/Host/peer validation on the SSE endpoints | Medium | open | — |
| [F5](#f5--two-blocked-threads-per-sse-connection) | Two blocked threads per SSE connection | Medium | open | — |
| [F6](#f6--attacker-controlled-text-in-info-level-logs) | Attacker-controlled text in info-level logs | Medium | **fixed** | `LogSafeTest`, `ToolLoggingTest` |
| [F7](#f7--apibridge-cannot-be-stopped) | `ApiBridge` cannot be stopped | Medium | open | — |
| [F8](#f8--dropped-events-are-silent) | Dropped events are silent | Low | open | — |
| [F9](#f9--capability-registries-are-not-thread-safe) | Capability registries are not thread safe | Low | open | — |
| [F10](#f10--no-body-size-limit-and-no-rate-limiting) | No body size limit, no rate limiting | Low | open | — |
| [F11](#f11--a-notification-with-a-known-method-is-answered) | A notification with a known method is answered | Low | open | `ListenerMessageTest` pins the unknown-method case |

F1, F2 and F3 were reported by an external disclosure. F4–F10 were found while verifying them.

**Consequence of F1's fix that upstream should know about:** oatpp never percent-decodes a URL.
`Url::Parser::parseQueryParams()` and the router's path-variable labels hand the endpoint the raw
bytes, and `oatpp::encoding::Url::decode()` is not called from anywhere in the library. An endpoint
therefore receives `hello%20world` where the tool caller meant `hello world`. Nothing that worked
before regresses — a value containing a space used to produce a malformed request line — but the
correct end state needs the server side to decode as well. Tracked as **B6** below.

## Running the tests

```
cmake -S . -B build && cmake --build build
ctest --test-dir build                 # each test in its own process
build/test/module-tests --list         # what is registered
build/test/module-tests --test=SessionIdTest
```

`mcp-server-demo` (formerly also called `module-tests`) is the manual playground on port 3001 and
is not a test. See [test/CMakeLists.txt](test/CMakeLists.txt) for how tests are registered.

To check that the tests still *protect* the fixes rather than merely passing over them:

```
python3 tools_mutation_check.py            # revert one decision at a time; require a failure
python3 tools_mutation_check.py --list
python3 tools_mutation_check.py --only 7
```

It edits the working tree and rebuilds, so do not `git commit` while it runs. It currently covers
F3 and F6 (23 mutations, all caught); extending it to the F1 and F2 decisions is task **T6.1**.

---

## F1 — request smuggling via tool arguments

**Where:** `src/oatpp-mcp/capabilities/Tool.cpp` — `prepareEndpointPath()`,
`prepareEndpointHeaders()`.

A tool call is turned into an HTTP request and executed by an oatpp `HttpRequestExecutor`. The
arguments end up in the request verbatim:

| value | path | encoded? |
|---|---|---|
| path variable | `Pattern::reconstruct()` writes `params.at(name)` straight into the path | **no** |
| query parameter | `ss << param.name << "=" << it->second` | **no** |
| header parameter | `Headers::put(name, value)` | **no** |
| body | serialized by a content mapper | yes (JSON escaping) |

Nothing downstream rejects CR or LF either: `outgoing::Request::send()` writes
`method + " " + "/" + path + " " + "HTTP/1.1\r\n"` and `http::Utils::writeHeaders()` writes
`name: value\r\n` without looking at what they are given. An argument containing `\r\n` therefore
ends the request line or the header block and starts a new request, which the upstream executes as
though the MCP client had sent it.

**Verified.** Against the demo server, one `tools/call` of `getUsers` executed both `getUsers` and
a smuggled `GET /users/42`:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"getUsers",
 "arguments":{"offset":"1","limit":"1",
              "searchPhrase":"x HTTP/1.1\r\nX-Injected: 1\r\n\r\nGET /users/42 HTTP/1.1\r\nX-Second: 2\r\n\r\n"}}}
```

```
D UserController:getUsers
D UserController:getUserById     <- never requested
```

`ToolHttpFramingTest` reproduces this in-process (query parameter, path variable and header
injection) and asserts on what the *upstream endpoint observed*, because the caller always gets a
normal-looking answer.

**Note on the disclosed payload.** It injects `\r\n\r\n` directly after a path variable, which
produces a request line with no HTTP version; oatpp 1.4.0's `Parser::parseRequestStartingLine()`
requires one and answers 400, so that exact payload does not split a request here. That is an
accident of this upstream parser, not a defence: the payload above needs no parser bug and works
today, and a deployment whose tool upstream is a real HTTP server or a proxy has no such luck.

**Fix — landed.** `src/oatpp-mcp/utils/HttpSanitize.{hpp,cpp}`, used from `EndpointTool`:

| value | rule | why |
|---|---|---|
| path variable | percent-encoded (`encodePathSegment`) | encoding is lossless; the upstream gets what the caller meant |
| query name and value | percent-encoded (`encodeQueryComponent`) | same |
| header name, header value | **rejected** if not RFC 9110 `tchar` / `field-value` | there is no encoding for a header; stripping CR/LF would silently send a different header |
| assembled request target | final CR/LF/NUL guard (`validateRequestTarget`) | cheap insurance; fires only on a malformed endpoint pattern |
| body | unchanged | already serialized by a mapper; `ToolHttpFramingTest` pins this |

- The encoded set is RFC 3986 unreserved plus `!'()*`; everything else — including `%`, `/`, `?`,
  `#`, `&`, `=`, `+` and every control character — becomes `%XX`.
- **Input is always treated as raw**: `a%20b` becomes `a%2520b`. There is no sound way to tell a
  pre-encoded value from a literal one, so the distinction is not offered.
- Path variables are encoded before `Pattern::reconstruct()` is called, so the module does not
  depend on a base-project change; `reconstructEncoded()` (B3) is still worth having upstream.
- A rejected header throws `std::invalid_argument`, which `Listener::toolsCall` already turns into
  an MCP tool error.

Verified end-to-end against the demo server: the payload above now sends
`?searchPhrase=x%20HTTP%2F1.1%0D%0A…` and only `UserController:getUsers` runs. Legitimate calls are
unaffected — `getUserById(42)` still returns the user, and a search phrase containing spaces, `&`,
`=` and `%` now produces a well-formed request where it previously produced a truncated one.

Defence in depth belongs in oatpp itself (reject CR/LF when serializing a request target and
headers; add `Pattern::reconstructEncoded()`; decode what was encoded — B6); see below.

---

## F2 — session identifiers are heap addresses

**Where:** `src/oatpp-mcp/event/Session.cpp` — `Session::getId()` returns
`reinterpret_cast<v_uint64>(this)` formatted as decimal.

**Verified.** `SessionIdTest` reports the identifier and the object address side by side:

```
FAILED: identifier is not the address of the Session object | id=192059764978560, &Session=192059764978560
FAILED: no identifier is reissued across create/close cycles | unique=1 of 200
```

`unique=1 of 200`: create and close a session in a loop and the allocator hands back *the same
address every time*. An attacker who opens a session, notes the identifier and closes it has
predicted the identifier of the next client, and can then POST messages to it — `POST
/mcp/sessions/{sessionId}` authenticates nothing (F4), so those messages are delivered to the
victim's SSE stream.

**Fix — landed.** `src/oatpp-mcp/utils/Uuid.{hpp,cpp}`, used from the `Session` constructor:
`m_id` is generated once and `getId()` returns it, so the identifier is stable for the lifetime of
the session and outlives nothing that could have been derived from the object.

| decision | what was chosen | why |
|---|---|---|
| format | UUID v4, canonical 8-4-4-4-12 lowercase, 122 random bits | a standard shape clients already handle, and a length that makes "is this an address?" a category error |
| entropy | `std::random_device` directly | **not** `oatpp::utils::Random` — that is `std::mt19937`, whose state is recoverable from its output; fine for shuffling, wrong for a capability |
| lifetime of the source | one process-wide source, allocated once, never destroyed | sessions run on detached threads that can call this during shutdown, after function-local statics are gone; a mutex destroyed under a waiting thread is worse than bytes the loader never reclaims |
| thread safety | mutex around `operator()` | the standard does not require `std::random_device::operator()` to be thread-safe on one object, and sessions are created on whichever thread served the request |
| entropy source unavailable | the exception propagates; no fallback | an identifier that is not random is the vulnerability itself. Failing to open a session is recoverable; failing silently is not |
| `random_device::entropy()` | deliberately **not** consulted | libc++ documents it as always returning 0, so a warning keyed on it is noise on exactly the platforms that are fine. It informs nothing; the source either works or throws |

Two supporting changes in `event/Server.cpp`, both about the same invariant:

- `startNewSession()` logs an error if an identifier is already in the registry. With 122 random
  bits this is not a race to be handled — it is the generator having stopped being random, and it
  must not be papered over by overwriting the session that got there first.
- the session's cleanup erases its registry entry **only if it is still its own**, so that if two
  sessions ever did share an identifier, the first to finish could not retire the second.

**Verified after the fix.** `UuidTest` 11/11 (format, lowercase, no repeats in 20 000 draws, no
long common prefix, every hex digit seen in the leading position, 10 000 draws from 4 threads all
distinct) and `SessionIdTest` 7/7 (identifier is not the object address, no reissue across 200
create/close cycles, longest common prefix ≤ 8). End-to-end against the demo server, the churn that
used to produce `unique=1 of 200` now produces 15 distinct identifiers out of 15 sequential SSE
connections, all canonical v4, longest common prefix 2:

```
56afe4ae-f74f-450f-922d-9ec6f4fc06b6   cfb8ba8b-d856-4a9a-bc8a-eac4d5aa99bc
63d097af-22b2-4a25-9e34-38a896ffc228   a635945e-661b-4a16-9ba0-305320814123
```

The SSE round-trip is unaffected: `tools/list` and `tools/call` still complete on a session
addressed by its UUID, and the F1 smuggling payload still produces one encoded request and one
controller call.

**What this does not fix.** The identifier is now unguessable, but the endpoints still authenticate
nothing else: no Origin/Host check, no peer binding, and an unknown identifier is still answered
`200 OK` rather than `404` — see F4. A random identifier raises the cost of hijacking a session from
"open a session and wait" to "guess 122 bits"; it does not make the session *authorized*.

---

## F3 — remote denial of service on malformed messages

**Where:** `src/oatpp-mcp/Listener.cpp` — `onEvent()` and every per-method handler.

`m_mapper.readFromString<Tree>(...)` throws `MappingError` on input that is not valid JSON, and
each handler calls `m_remapper.remap<Object<...>>(call->params)` *outside* its own `try` block. The
session runs on a detached thread with no handler, so any of this reaches `std::terminate` and the
process aborts. One unauthenticated POST is enough.

**Verified.** `ListenerMessageTest` drives `Listener::onEvent()` with a corpus; 7 of its rows threw
(where nothing should escape at all), including the disclosed empty body:

```
FAILED: no exception escapes onEvent(): empty POST body (the disclosed PoC) | thrown: [json]: Unknown character.
FAILED: no exception escapes onEvent(): truncated garbage | thrown: ... 'null' expected
FAILED: no exception escapes onEvent(): params is a number | thrown: ... TreeChildrenOperator(): Node type is NOT suppoerted
FAILED: no exception escapes onEvent(): params is an array | thrown: ... getPair(): Node type doesn't support pairs
FAILED: no exception escapes onEvent(): params is a string | thrown: ...
FAILED: no exception escapes onEvent(): params.name is a number | thrown: ... mapString(): Node is NOT a STRING
FAILED: no exception escapes onEvent(): method is a number | thrown: ...
```

The reported "empty body" case is one instance of a missing error path, not the whole of it. The
same test also pins two things the fix must not break (`tools/list`, `ping`, unknown tool) and one
that is wrong today: a request with an `id` and an unknown method is currently **ignored**, where
JSON-RPC requires a `-32601` reply.

**Fix — landed.** Three layers, as planned, in `Listener.cpp` and `event/Session.cpp`.

1. **Envelope validation** (`Listener::handleCall`, split out of `onEvent`) — parseable, a JSON
   object, `id` a string or number, `method` a string, `params` absent or an object — each failure
   answered with the code that describes it. An absent `params` is normalised to an empty object:
   remapping a *missing* node into a params DTO is one of the things that aborted the process, and
   every params field of every method is optional at the DTO level, so the handler — not the
   remapper — is what should report a missing required field.
2. **Every handler wraps its own parameter remap** and answers `-32602`; the tool/prompt/resource
   invocation `catch` blocks gained a `catch (...)` they did not have.
3. **`Session::listen()` wraps the listener call.** A listener is extension code, so "it cannot
   throw" is not a property of this library; an exception that reaches the top of that detached
   thread is `std::terminate`, and short of that the session is never removed from its server's
   registry. Log, drop the message, keep the session.

`onEvent()` keeps an outer `catch` as the last line, and it deliberately **does not reply**: by then
there is no way to know whether a response already went out for the id, and a second response to the
same id is a worse protocol violation than silence.

The error taxonomy, now visible to clients:

| situation | code | example |
|---|---|---|
| not JSON at all | `-32700` | the disclosed empty POST body, `"not json at all"`, binary junk |
| JSON, not a request object | `-32600` | `null`, `[1,2,3]` |
| `id` not a string/number | `-32600` | `"id":{…}` — and it is not reflected back |
| `method` missing or not a string | `-32600` | `"method":123` |
| `params` present and not an object | `-32600` | `"params":123`, `"params":[1]` |
| method exists, parameters do not fit | `-32602` | `"params":{"name":123}`, `"arguments":5`, `"cursor":123` |
| required field missing | `-32602` | `tools/call` with no `name` |
| unknown method **with an id** | `-32601` | previously a black hole: the client waited forever |
| unknown method **with no id** | *no reply* | a notification must not be answered (JSON-RPC §4.1) |
| a handler threw | `-32603` / `isError` result | detail logged, not sent |

**`e.what()` no longer goes to the client.** It was being placed straight into error messages and
into tool results; it now goes to the log, and the client gets `Invalid params` / `Internal error` /
`Tool handler thrown an exception`. A tool that wants the model to see its own failure text should
say so in an `isError` result it builds itself — that is a different channel from an exception that
happened to carry library internals.

**Verified.** `ListenerMessageTest` — 117 checks, all green — drives `onEvent()` with the corpus
above plus controls, asserts the **specific error code** (not merely that an error came back), that
control rows get a *result* rather than an error, that the registered tool ran or did not run, and —
for layer 3 — that a listener which throws three times leaves the session thread alive and reading.

The fix was then mutation-checked: **13 of 13 reverted decisions are caught by the suite** (swallow
the parse error, drop each of the four envelope checks, answer notifications anyway, drop the params
normalisation, unwrap each handler's remap, remove the `Session::listen` guard). Two of them were
*not* caught by the first version of the test — the parse-error reply and the params normalisation —
which is why the corpus now pins codes and why a control row has to be a result, not just "a reply".

End to end against the demo server: 19 malformed payloads (including the disclosed empty body and
binary junk) leave the process alive, and normal operation is unaffected — `tools/list`, `tools/call`
and `ping` still round-trip, `-32601` reaches the client for an unknown method, and a notification
for an unknown method gets no reply.

**Not fixed here:** see [F11](#f11--a-notification-with-a-known-method-is-answered).

---

## F4 — no Origin, Host or peer validation on the SSE endpoints

**Where:** `src/oatpp-mcp/sse/Controller.hpp`.

`GET /sse` and `POST /sessions/{id}` accept any `Origin`, any `Host`, and any peer address; there is
no authentication of any kind. Unknown session identifiers are answered `200 OK` rather than `404`,
so guessing cannot even be distinguished from a live session, and a browser page can drive a
localhost MCP server through DNS rebinding (the MCP specification requires the Host/Origin check
for exactly this reason).

This is what turns F2 from a weakness into an attack. **Fix:** reject cross-origin `Origin` and
unexpected `Host` (configurable allow-list), answer `404` for unknown sessions, optionally bind a
session to the peer address that opened it.

## F5 — two blocked threads per SSE connection

**Where:** `src/oatpp-mcp/event/Server.cpp` (`startNewSession` detaches a thread per session) and
`src/oatpp-mcp/sse/ReadCallback.cpp` (the connection thread blocks in `EventStream::read` for the
lifetime of the connection). `HttpConnectionHandler` is itself thread-per-connection with no cap.

N idle SSE clients cost 2N threads and nothing limits N. **Fix:** cap sessions, add an idle TTL, and
document the thread cost; ideally drive the SSE body with oatpp's async/streaming facilities instead
of a blocked worker.

## F6 — attacker-controlled text in info-level logs

**Where:** `src/oatpp-mcp/capabilities/Tool.cpp` — `OATPP_LOGi` printed the resolved request path and
every header value, and the request body went out at debug. The same habit was still in
`Listener::onEvent()` and `sse::ReadCallback::waitEvent()`, which log whole messages.

Two problems, and they do not pull the same way:

- **a log is where secrets go to leak.** `Authorization` was just another header name among the ones
  an endpoint declares, and info is the level that is on by default and shipped somewhere else;
- **a log is a line-oriented sink.** A `\n` in anything written to it begins a new record — carrying
  this server's own timestamp and tag, which is exactly what makes it worth forging.

**Verified.** Forging a record did not need the F1 payload, and does not need the request to be
valid — a message is logged before the parser rejects it:

```
POST /mcp/sessions/<id>     body: "GARBAGE\n2026-10-11 00:00:00 FORGED RECORD from a tool client\n"

 D |...| Event:[<session>] --> : GARBAGE
 2026-10-11 00:00:00 FORGED RECORD from a tool client     <- not a record; a grep for a date says it is
```

(The F1 payload forged records through the resolved path too; encoding the arguments for F1 closed
that route and left this one.)

**Fix — landed.** `src/oatpp-mcp/utils/LogSafe.{hpp,cpp}`, used from `EndpointTool::call`,
`Listener` and `sse::ReadCallback`.

| decision | what was chosen | why |
|---|---|---|
| level | one info line per tool call naming the endpoint, its method and its **path pattern**; the resolved target, the headers and the body at debug | "which tool ran" is the operator's question — with a proxy blocking tools it is also the security question — so it survives the default level; what the caller sent does not need to |
| control characters | `\r`, `\n` and `\t` keep a readable two-character form; every other C0 control and DEL becomes `\xNN`; bytes >= 0x80 pass through | one record per input line, and the record still says what was in it — including text that is not ASCII |
| length | 1 KiB per value, 2 KiB per message, then `...[+N bytes]` | the budget is measured in *rendered* bytes, because that is what a log line has to stay inside; what was dropped is reported rather than hidden, and the cut never lands inside a multi-byte character |
| credentials | header values, and query-parameter values, whose name matches a known credential name become `<redacted>` | an escaped password is still a password; the name stays, because "which credential" is a fair question and "what was it" is not |
| scope | every value that reaches a log statement goes through this, including the developer-supplied endpoint name and path pattern | "nothing unrendered reaches the log" is then a property of the code, not of a list of call sites somebody decided were dangerous |

Redaction is best effort — it knows the common names, not this deployment's — and it is deliberately
not applied to bodies: a body is what somebody turned on debug logging to look at, and debug-only is
the control that was missing.

**Verified after the fix.** `LogSafeTest` 81/81 and `ToolLoggingTest` 26/26. The same POST is now one
record, and a tool call says what it ran without saying what it was sent:

```
 D |...| Event:[<session>] --> : GARBAGE\n2026-10-11 00:00:00 FORGED RECORD from a tool client\n...

 I |...| EndpointTool::call:tool 'getUsers': GET users/offset/{offset}/limit/{limit}/*
 D |...| EndpointTool::call:request target: '/users/offset/1/limit/1/?searchPhrase=x%20HTTP%2F1.1%0D%0A…'
```

Ten F6 decisions are in `tools_mutation_check.py` — log a value at info, stop escaping, stop
redacting a header or a query parameter, stop truncating, cut inside a multi-byte character — all
caught.

## F7 — `ApiBridge` cannot be stopped

**Where:** `src/oatpp-mcp/utils/ApiBridge.cpp`.

`run()` creates two `oatpp::network::Server`s on the stack and joins them; the threads capture
`this`, so the object can neither be destroyed nor shut down.

**Destroying an `ApiBridge` aborts the process.** Its constructor creates an
`oatpp::async::Executor`, and `Executor::~Executor() = default` (`oatpp/async/Executor.hpp`) while
its workers still own joinable `std::thread`s — so `~ApiBridge` destroys a joinable thread:

```
terminate called without an active exception
```

This is what `ToolHttpFramingTest` hit first; the fixture is now deliberately leaked, with the
reason in the code, and the object-leak check for that test is disabled in the runner
(`test/oatpp-mcp/tests.cpp`). Embedding an MCP server in an application that wants a clean shutdown
is not possible either. The async half is also dead: `m_asyncConnectionHandler` is built with
`m_router` instead of `m_asyncRouter`, and the second thread body in `run()` never calls
`server.run()`, so `getAsyncHttpExecutor()` returns an executor with no server behind it.

**Fix:** hold the servers as members, add `stop()` (stopping the executor and the interface too),
and either wire the async router properly or remove the async accessors until they work.

## F8 — dropped events are silent

**Where:** `src/oatpp-mcp/event/EventStream.cpp` — `post()` returns void and drops the event when
the queue is full (100) or the stream is closed. A slow SSE reader therefore makes the server
silently ignore valid RPC calls. **Fix:** return whether the event was queued and log/count drops.

## F9 — capability registries are not thread safe

**Where:** `src/oatpp-mcp/Listener.cpp` — `addTool()`, `addPrompt()` and `addResource()` mutate maps
and vectors that every session thread reads, with no synchronization. Registering a capability while
sessions are running is a data race. **Fix:** guard the registries, or document that capabilities
must be added before the server starts.

## F10 — no body size limit and no rate limiting

**Where:** `src/oatpp-mcp/sse/Controller.hpp` — `BODY_STRING(String, body)` reads the whole POST
body into memory. **Fix:** configure a maximum message size.

---

## F11 — a notification with a known method is answered

**Where:** `src/oatpp-mcp/Listener.cpp` — every handler ends in `sendRpcResult()`.

JSON-RPC 2.0 §4.1: a Notification is a request without an `id`, and the server **must not** reply to
it. Since the F3 fix, unknown-method notifications are correctly ignored — but a notification naming
a *known* method still gets a full response, addressed to `id: null`:

```
--> {"jsonrpc":"2.0","method":"tools/list"}
<-- {"jsonrpc":"2.0","result":{"tools":[…]}      <- no id came in, so none goes out either
```

Found while fixing F3, and deliberately left alone: the handlers do not currently know whether the
message had an `id`, threading that through every handler is a behaviour change for anyone whose
client omits ids and waits for replies, and MCP's own notifications (`notifications/initialized`,
`notifications/cancelled`) are unknown methods here and are already handled correctly — so nothing
in the disclosed attack surface depends on it.

**Fix:** pass the presence of an `id` down (or hand the handlers a small `Reply` object that knows
whether it may send), and suppress the response for notifications. `ListenerMessageTest` has the
`NoResponse` expectation ready for the rows this needs.

---

## Base project (oatpp)

Changes that belong upstream rather than here; the module fixes are sufficient on their own, these
are the second line of defence.

| ID | Change | File |
|----|--------|------|
| B1 | reject CR/LF/NUL in header names and values when serializing | `web/protocol/http/Http.cpp` (`Utils::writeHeaders`) |
| B2 | reject CR/LF/NUL in the request target before writing the request line | `web/protocol/http/outgoing/Request.cpp` |
| B3 | add `Pattern::reconstructEncoded()`; leave `reconstruct()` alone so existing callers do not double-encode | `web/url/mapping/Pattern.{hpp,cpp}` |
| B4 | `RequestHeadersReader::readHeadersSectionIterative()` sets the buffer position to the end of the peeked chunk instead of to the section end, so the header parse is handed bytes past `\r\n\r\n`. Benign today because `Parser::parseHeaders()` stops at the blank line | `web/protocol/http/incoming/RequestHeadersReader.cpp` |
| B5 | a CSPRNG-backed UUID helper, so modules stop hand-rolling identifiers from `std::mt19937`. `oatpp::utils::Random` is `std::mt19937` and is not a candidate for identifiers; `oatpp-mcp` grew its own (`utils/Uuid.{hpp,cpp}`, see F2) which is a suitable starting point if upstream wants one | new `utils/Uuid.hpp` |
| B6 | **percent-decode what was encoded.** `Url::Parser::parseQueryParams()` splits on `&`/`=` and hands out raw labels; path-variable labels are raw too; `encoding::Url::decode()` is never called anywhere in the library. A correctly-encoded request therefore delivers `%20` to the endpoint | `network/Url.cpp`, `web/protocol/http/incoming/Request.cpp` |
| B7 | `Executor::~Executor() = default` while workers own joinable threads — destroying a stopped-but-not-joined executor is `std::terminate` | `async/Executor.hpp` |

## Conventions for the fix PRs

- One finding per PR where possible; a PR that adds a failing test and the fix that turns it green
  is easier to review than either alone.
- Tests are table-driven and report every failed row (`test/oatpp-mcp/tests/TestChecks.hpp`) rather
  than aborting on the first `OATPP_ASSERT`.
- Security properties are asserted on what the *upstream endpoint observed*, not on what the tool
  returned — the attack returns a normal answer.
- Every test is listed once, in `MCP_TESTS` in `test/CMakeLists.txt` and in the registry in
  `test/oatpp-mcp/tests.cpp`.
