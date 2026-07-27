// Package wasmauthz is a pluggable, WebAssembly-hosted authorization-decision
// engine: an operator supplies the bytes of a COMPILED WASM module implementing
// a small, fixed ABI (see "ABI contract" below), and [Engine.Authorize] calls
// into it once per decision — marshaling a [Request] to JSON, handing it to
// the guest module, and unmarshaling the JSON [Decision] the guest returns.
// The policy logic itself (which subjects may do what to which resources)
// lives entirely inside the guest module; this package only implements the
// host side of the calling convention plus one admin debug endpoint.
//
// # Relationship to the other authorization layers
//
// This is a FOURTH, independent authorization model, additive alongside:
//
//   - domains/permissions: RBAC — a user holds named ROLES per client, each
//     role bundling PERMISSION codes ("user:read"). Coarse-grained,
//     app-scoped, good for "can this user use this feature at all".
//   - domains/conditionalaccess: attribute-based policy (ABAC-ish) — a
//     request's trust score/device posture/geo/time decides allow/deny/
//     step-up. Good for "is this REQUEST risky enough to challenge or block".
//   - platform/lifecycle/rebac: relationship-based (Zanzibar-style) — a
//     subject's access to a specific object instance is derived from a graph
//     of who-relates-to-what tuples.
//   - wasmauthz (this package): policy-as-WASM — an operator ships arbitrary
//     decision logic, compiled to WebAssembly from whatever language they
//     prefer, and this package hosts it. Good for "the authorization rule is
//     too bespoke/dynamic/proprietary to express in this SDK's Go code, but
//     the operator can compile it".
//
// None of the four consult each other. wasmauthz has zero dependency on
// domains/permissions, domains/conditionalaccess, or platform/lifecycle/rebac
// (and none of those depend on it). An operator who needs a WASM-hosted
// authorization decision consults [Engine.Authorize] from their OWN
// integration code (a custom HTTP handler, a gRPC interceptor, a
// business-logic layer) the same way they'd consult a Provider or a
// rebac.Engine — this package does not wire itself into /auth/login or any
// built-in gate. The one exception is a single, explicitly opt-in, read-only
// admin endpoint (POST /api/v1/admin/wasmauthz/check, mounted only when
// [github.com/yangwb1123/snaplink/interfaces/sso.WithWASMAuthzEngine] is wired) for
// operational debugging — "what would this policy module decide for this
// request" — never a live authorization decision path.
//
// # ABI contract
//
// The guest module MUST export:
//
//   - A linear memory named "memory" (the default export name wasm-ld and
//     TinyGo both produce; this is also how a module built with
//     `--export-memory` or TinyGo's default settings already behaves).
//
//   - alloc(size uint32) uint32 — allocate size bytes in the guest's OWN
//     linear memory and return a pointer to the start of the block, or 0 if
//     the allocation failed (e.g. out of memory). The host calls this ONCE
//     per Authorize call, with size == the length of the JSON-encoded
//     [Request], BEFORE writing anything into guest memory.
//
//   - authorize(reqPtr uint32, reqLen uint32) uint64 — reqPtr/reqLen locate
//     the JSON-encoded [Request] the host already wrote into guest memory
//     (at the address alloc returned). The guest decodes it, evaluates its
//     policy, JSON-encodes a [Decision], and returns a SINGLE packed uint64:
//     the high 32 bits are a pointer to the response bytes (which MUST
//     remain valid in guest memory until the host finishes reading them —
//     either a fresh alloc'd block, or a static/rodata address, both work),
//     and the low 32 bits are the response's byte length. This
//     "pack (ptr<<32)|len into one i64 return value" shape is the same
//     ptr+length interop convention used throughout the wazero ecosystem
//     (e.g. wazero's own allocation examples) for returning a
//     variable-length buffer from a guest function without a second export.
//
//   - dealloc(ptr uint32, size uint32) — release a block previously returned
//     by alloc, so a long-lived guest instance does not leak memory across
//     calls. The host calls this on a BEST-EFFORT basis for both the request
//     buffer and the response buffer once it has copied the response bytes
//     out; a dealloc trap or missing export does not fail the surrounding
//     Authorize call. (This package's own test fixture uses a trivial bump
//     allocator with a no-op dealloc — fine for a few test calls, but a REAL
//     policy module should use a real allocator, e.g. TinyGo's built-in
//     GC-backed malloc/free, so memory does not grow unbounded over the
//     module's lifetime.)
//
// See [Request] and [Decision] for the exact JSON wire shape crossing the
// host/guest boundary in each direction. [New] fails at CONSTRUCTION time
// (compiles the module, then inspects its export table) when alloc/authorize/
// dealloc are missing or have the wrong arity, or "memory" is not exported —
// never silently at first use.
//
// # Fail-closed
//
// [Engine.Authorize] returning a non-nil error means the decision could NOT
// be evaluated — a guest trap, a malformed/oversized JSON response, an
// out-of-bounds pointer, or the per-call timeout firing because the guest
// looped or blocked. This is EXACTLY the same failure category as a CAEP
// receiver's signature-verification failure or a federation trust-chain
// error elsewhere in this SDK: the caller MUST treat any Authorize error as
// a DENIAL, never as "inconclusive, so allow". A WASM policy module is
// UNTRUSTED, arbitrary, operator-supplied code; an engine that let a broken
// or slow module fail open would turn every ABI bug or malicious module into
// a bypass.
//
// # Concurrency
//
// Engine.Authorize is safe for unlimited concurrent use, but NOT by sharing
// one long-lived wazero module instance across goroutines: wazero's
// api.Function.Call is documented as not goroutine-safe per instance
// ("recommended to create another Function if you want to invoke the same
// function concurrently"), and this package additionally enables
// RuntimeConfig.WithCloseOnContextDone so a timed-out call's execution is
// actually interrupted — but that setting closes the WHOLE module instance
// it was running in, permanently, the moment the deadline fires. A single
// shared instance guarded by a mutex would therefore be wedged FOREVER after
// just one slow or malicious call — precisely the "must not let a single bad
// WASM module wedge the whole engine" failure this package must avoid.
//
// Instead, [Engine] compiles the module exactly ONCE at construction (the
// genuinely expensive step — parsing, validating, and machine-code
// generation), then instantiates a fresh, anonymous module instance from
// that one CompiledModule for every single Authorize call, and closes it
// again once the call returns. This is the same "concurrent instantiation"
// pattern wazero's own documentation recommends for concurrent use of one
// compiled module, and it means a trap or timeout in one call only destroys
// that call's own throwaway instance — the shared Runtime and CompiledModule,
// and therefore every OTHER in-flight or future call, are unaffected.
// Measured overhead for a minimal module is tens of microseconds per call;
// this is an operator-debugging/authorization-decision primitive, not
// something wired into the hot /auth/login path (see above), so this
// trades a small constant cost for an engine that cannot be permanently
// wedged by one bad call.
package wasmauthz
