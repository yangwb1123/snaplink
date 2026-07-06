# Pluggable WASM authorization engine

`platform/lifecycle/wasmauthz` is an opt-in, pluggable authorization-decision
engine hosted on [wazero](https://github.com/tetratelabs/wazero), a pure-Go
(no cgo, no external process) WebAssembly runtime. An operator supplies the
bytes of a COMPILED `.wasm` module implementing a small, fixed ABI; the
engine calls into it once per decision.

This is the same shape as this SDK's other pluggable primitives —
`platform/lifecycle/rebac` (Zanzibar-style ReBAC) is the closest sibling:

- A `New`/`NewEngine`-constructed `Engine` type, no framework magic.
- ONE opt-in admin debug endpoint, mounted only when wired, gated
  `admin:read`, and otherwise absent (404) — never a live authorization
  decision path.
- Zero wiring into `/auth/login` or any other built-in gate. An operator who
  wants a WASM-hosted authorization decision calls `Engine.Authorize` from
  their OWN integration code (a custom HTTP handler, a gRPC interceptor, a
  business-logic layer).

wasmauthz is a FOURTH, independent authorization model alongside
`domains/permissions` (RBAC), `domains/conditionalaccess` (attribute-based),
and `platform/lifecycle/rebac` (relationship-based) — none of the four
consult each other.

## What this is NOT (see `docs/deferred-backlog.md`)

This is the authorization-**engine** half of the "Edge MQTT + WASM" backlog
entry. The other pieces:

- A **WASM authenticator** — done. `domains/authenticators/wasmauth`
  verifies a credential (a custom MFA factor, a passwordless scheme, a
  legacy on-prem auth system being bridged in) hosted in WASM, mirroring
  this package's own alloc/call/dealloc interop pattern and fail-closed
  doctrine but with an authentication-shaped ABI (`authenticate` instead
  of `authorize`) and result (`{authenticated, subject_id, claims,
  reason}` instead of `{allowed, reason}`). It implements
  `core.Authenticator` directly, so it wires through the existing generic
  `sso.WithAuthenticator(a)` — no new SDK option was needed. See that
  package's doc.go for the full ABI contract.
- An MQTT `cluster.Bus` backend — done. `infrastructure/mqtt`
  (`github.com/snaplink/sso/mqtt`), a nested module built on
  `github.com/eclipse/paho.golang`. Wires through the existing
  `sso.WithInvalidationBus(bus)` (fork-only — no config.yaml-driven
  backend selection yet, since `cluster.Bus` has no factory-registration
  extension point the way `infrastructure/kafka`'s audit sink does; see
  that package's doc.go).
- An MQTT CAEP/SSF channel — done. `protocols/caep`'s `Transmitter`
  gained a local `MQTTPublisher` interface + `WithMQTTPublisher` option
  (mirroring `Logger`'s "kept local so caep depends only on core + audit"
  pattern — caep imports no MQTT client library). A receiver opts in by
  registering `AttrReceiverMQTTTopic` instead of (or alongside)
  `AttrReceiverEndpoint`; `infrastructure/mqtt`'s `TopicPublisher`
  satisfies the seam. Without `WithMQTTPublisher` wired, behavior is
  byte-identical to before this channel existed.

## Quickstart

```go
wasmBytes, _ := os.ReadFile("policy.wasm")
engine, err := wasmauthz.New(ctx, wasmBytes)
if err != nil {
    log.Fatal(err) // module doesn't satisfy the ABI — fail fast at startup
}
defer engine.Close(ctx)

srv := sso.NewServer(
    sso.WithWASMAuthzEngine(engine),
    // ... every other option
)
```

With `WithWASMAuthzEngine` wired, `POST /api/v1/admin/wasmauthz/check`
becomes reachable (admin:read bearer required) for operational debugging —
"what would this policy module decide for this request":

```
POST /api/v1/admin/wasmauthz/check
Authorization: Bearer <admin token with admin:read>
Content-Type: application/json

{"subject": "alice", "action": "read", "resource": "doc:1"}
```

```json
{"allowed": true, "reason": "alice may read"}
```

Nothing else changes: omitting `WithWASMAuthzEngine` (the default) leaves the
route unmounted — byte-identical to a build without the feature.

## The ABI contract (what a WASM module author must implement)

The guest module MUST export:

| Export | Signature | Meaning |
|---|---|---|
| `memory` | (linear memory) | The module's own linear memory, exported under this exact name — the default wasm-ld and TinyGo both already produce. |
| `alloc` | `(size: i32) -> i32` | Allocate `size` bytes in the guest's OWN linear memory; return a pointer to the block, or `0` on failure. |
| `authorize` | `(reqPtr: i32, reqLen: i32) -> i64` | Decode the JSON [`Request`](#request-json-shape) written at `reqPtr`/`reqLen`, evaluate the policy, JSON-encode a [`Decision`](#decision-json-shape), and return it packed into a single `i64`: **high 32 bits = response pointer, low 32 bits = response length**. |
| `dealloc` | `(ptr: i32, size: i32)` | Release a block previously returned by `alloc`. Called best-effort by the host for both the request and response buffers; a trap or missing export here does not fail the surrounding call. |

This is the standard "allocate a buffer in guest memory, write JSON into it,
call the exported function with a pointer+length, read the returned
pointer+length" interop pattern used broadly across the wazero ecosystem —
not something invented for this package. The host-side call sequence per
`Authorize` invocation:

1. Marshal the [`Request`](#request-json-shape) to JSON.
2. Call `alloc(len(json))` to get a guest pointer `reqPtr`.
3. Write the JSON bytes into guest memory at `reqPtr`.
4. Call `authorize(reqPtr, len(json))`; unpack the returned `i64` into
   `respPtr`/`respLen`.
5. Read `respLen` bytes from guest memory at `respPtr`, and copy them out
   (the guest may reuse that memory once `dealloc` is called).
6. Call `dealloc(reqPtr, len(json))` and `dealloc(respPtr, respLen)`
   (best-effort).
7. Unmarshal the copied JSON bytes into a [`Decision`](#decision-json-shape).

### Request JSON shape

```json
{
  "subject": "alice",
  "action": "read",
  "resource": "doc:1",
  "context": { "role": "admin", "tenant_id": "acme", "ip": "203.0.113.9" }
}
```

`subject`, `action`, `resource` are free-form strings — this package does not
interpret them, the guest policy does. `context` is an extensible
`map[string]string` for anything else a policy needs (subject roles, tenant
id, source IP, device posture, ...) without requiring an ABI change for every
new attribute.

### Decision JSON shape

```json
{ "allowed": true, "reason": "alice may read" }
```

`reason` is for audit/debugging only. A `Decision` with `allowed: false` is
an ordinary, successfully-evaluated denial — NOT the same thing as an
`Authorize` error (see "Fail-closed" below).

### A minimal alloc/dealloc implementation

The reference test fixture (`platform/lifecycle/wasmauthz/testdata/policy.c`)
implements `alloc` as a trivial bump allocator over a static arena and
`dealloc` as a no-op — fine for a handful of calls, but memory then grows
monotonically over the module instance's lifetime. A REAL policy module
should use a real allocator that actually reclaims freed blocks — e.g.
TinyGo's built-in GC-backed `malloc`/`free` (TinyGo programs get a working
`alloc`/`dealloc` pair almost for free via `//export` directives over
`unsafe.Pointer` arithmetic against Go's own allocator).

One easy-to-hit pitfall: a pointer of `0` returned from `alloc` is the
host-side "allocation failed" sentinel (see the table above), so a module's
allocator must never legitimately hand out address `0` for a real
allocation — reserve a small dummy region first if your linker would
otherwise place your arena/heap at absolute address 0.

## Fail-closed guarantee

Any non-nil error from `Engine.Authorize` — a guest trap (e.g. an assertion
or out-of-bounds access), a malformed/non-JSON response, an out-of-bounds
pointer, or the per-call timeout firing because the guest looped or blocked
— means the decision could **not** be evaluated. **The caller MUST treat any
such error as a denial**, never as "inconclusive, so allow". This mirrors
this SDK's other security-critical fail-closed doctrine (the CAEP receiver,
federation trust-chain validation — see `AGENTS.md`): a WASM policy module is
untrusted, arbitrary, operator-supplied code, so an engine that failed open
on a broken or malicious module would turn every ABI bug into a bypass.

The admin debug endpoint reflects this at the wire level too: an `Authorize`
error surfaces as `500 internal_error` (with the raw error message, for
operator debugging), never as a fabricated `{"allowed": false}` — see
`docs/error-codes.md`'s wasmauthz section.

## Construction-time validation

`wasmauthz.New` compiles the module once (the expensive step) and then
inspects its EXPORT TABLE — without instantiating it — to confirm
`alloc`/`authorize`/`dealloc` exist with the right arity and `memory` is
exported. A module that doesn't satisfy the ABI fails at `New`, not on the
first `Authorize` call.

## Concurrency and timeouts

`Engine.Authorize` is safe for unlimited concurrent use. Rather than sharing
one long-lived wazero module instance behind a mutex, the engine
instantiates a fresh, anonymous module instance from the one compiled module
for EVERY `Authorize` call, and closes it again once the call returns. Two
reasons this is safer than a shared instance, not just simpler:

1. wazero's `api.Function.Call` is documented as not goroutine-safe per
   instance — concurrent callers need independent instances regardless.
2. The engine enables `RuntimeConfig.WithCloseOnContextDone` so a per-call
   timeout can actually interrupt a looping/blocked guest — but that setting
   PERMANENTLY closes whichever module instance was running when the
   deadline fired. A single shared instance would therefore be wedged
   forever after just one slow or malicious call. Per-call instantiation
   means a timeout only destroys that one call's own throwaway instance.

Measured overhead for a minimal module is tens of microseconds per call —
acceptable for an operator-debugging/authorization-decision primitive that,
by design, is never wired into the hot `/auth/login` path.

## Memory limit

Each guest instance's linear memory is capped at `wasmauthz.DefaultMemoryLimitPages`
(256 wazero pages, 16 MiB). Without this, a module whose memory section omits
an explicit max — the ordinary output of a plain `wasm-ld`/TinyGo build, not a
contrived case — would be allowed by wazero to grow to its own 4 GiB default
ceiling. Since a fresh instance is created per `Authorize` call and the guest
is untrusted, operator-supplied code (see "Fail-closed" above), an unbounded
ceiling would let one malicious or buggy module exhaust host memory well
within `DefaultCallTimeout`. 16 MiB is far beyond what a JSON authorization
request/response needs; a module that legitimately needs more must be split
or redesigned, not accommodated by raising this ceiling process-wide.
