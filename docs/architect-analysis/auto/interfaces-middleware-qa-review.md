# QA Review: interfaces/middleware — Typed named-slot pipeline (`middleware.Chain`)

Review target: `docs/auto/interfaces-middleware-design.md` (design stage; the
`interfaces/middleware/chain` subpackage does not exist yet — every "after"
claim below is a proposal until implemented). Baseline gates were run on the
current tree (commit `cde984d6`). Findings are advisory.

## 1. Test inventory and commands actually run for this revision

| Command | Result | Evidence |
|---|---|---|
| `go build ./... && go vet ./...` | PASS | clean output, both stages |
| `go test -run 'TestMaintainability_|TestArchitecture_' .` | PASS | `ok ... 0.130s` |
| `go test -race -count=1 ./interfaces/middleware/... ./interfaces/sso/...` | PASS | middleware 1.0s, sso 65.5s, servercache 1.1s |
| `go test -count=1 ./test/ -run 'Middleware|Tracing|Probe'` | PASS | 16 selected tests incl. `TestAuthMiddleware_*`, geo/probe E2E |
| Static verification of every design line reference | see matrix | 20+ claims checked against source |

No `make ci` run in this review (design stage; no code changed). The design's
proposed test commands (`-run 'Chain|Idempotency|Probe|RateLimit|Degradation'`)
reference tests that do not exist yet — they are acceptance criteria, not
evidence.

## 2. Design-claim verification and requirement-to-test matrix

### Factual claims in the design — all re-verified

| Claim | Verdict | Evidence |
|---|---|---|
| `interfaces/middleware` at 10-file ceiling | **Verified** | 10 non-test files; `directory_fanout_test.go:34` `maxGoFilesPerDir = 10` |
| Subdir cap 16 (spec says 15) | **Verified (design), spec error** | `directory_fanout_test.go:35` `maxSubdirsPerDir = 16` |
| `interfaces/sso` at 60-file ceiling | **Verified** | 60 non-test files |
| `server_routes.go` 488 / `sso_wiring.go` 446 / `server_health.go` 443 / `middleware.go` 166 lines | **Verified** | `wc -l` |
| Current canonical order (probe mux → Recover → OTel → Metrics → TrustedProxies → RateLimit → Degradation → AcceptVersion → BodyLimit → Compress → CORS → SecurityHeaders → RequestLog → Router) | **Verified** | `server_routes.go:364-399`, `:432-470`, `sso_wiring.go:389-421` |
| `Deprecation` wraps outside `AcceptVersion` | **Verified** | `sso_wiring.go:407-420` |
| `degradationGate` single call site, seeds gauge | **Verified** | `server_health.go:347-360`, one call in `buildMiddlewareChain` |
| `s.rateLimitStore` recreated per `Handler()` call; `SetRateLimitPolicy` no-ops when nil | **Verified** | `server_routes.go:379-381`, `:405-431`; `rate_limit_hotreload_test.go` exists |
| `middleware.Idempotency` has zero production call sites | **Verified** | grep returns nothing outside definition; `idempotency.go:142-153` is the invariant comment |
| `router.Use` middlewares run only on matched routes | **Verified** | `router.go:234-238` copies `r.middlewares` per route; unmatched → `http.NotFound` (`:284`) |
| Abort loop at `router.go:270-277` | **Verified** | loop at `router.go:273-277` (`mw(ctx); if ctx.Aborted() { break }`) |
| `health_test.go:121` direct `middleware.Tracing()(ctx)` | **Verified** | line 121, `core.HandlerContext` |
| `aliases.go:43-44` = `AuthMiddleware`/`CORS` | **Verified** | lines 43-44; zero non-test consumers |
| Tracing sets response headers at entry (not via writer wrapper) | **Verified** | `middleware.go:126-143` |
| `ratelimit.KeyByClientIP` → `middleware.RealClientIP`, RemoteAddr fallback without TrustedProxies | **Verified** | `ratelimit/middleware.go:76-100` |
| `NewTrustedProxies(cidrs, hops)` fixture exists | **Verified** | `trusted_proxy.go:39` |

### Requirement-to-test matrix

| Spec requirement | Test asset | Status / evidence |
|---|---|---|
| §1 `Chain` typed slots, canonical order | `TestChain_CanonicalSlotOrder` | **Proposed** (new). Acceptance: `SlotOrder()` equals exact 12-slot list; probes not listed. Note: pins the constant, not `Wrap`'s if-chain — invariants (a)-(c) carry the real proof |
| §1 probes outside every slot | (c) probe-bypass test | **Proposed** (new). Existing partial: `degradation_test.go` (modes only, no position), no livez-under-rate-limit test found |
| §1 one construction site | grep acceptance + `rate_limit_hotreload_test.go` | **Proposed** + existing green |
| §2 single signature, `FromCore` | grep acceptance | **Proposed**. Gap: no `FromCore` unit test specified (abort vs pass-through) |
| §2 migrate Tracing/Logger/Idempotency | rewrite `middleware_extra_test.go` (Tracing ×4, Logger ×1), `test/middleware_test.go` (Tracing ×5, Logger ×1, RequestID ×1), `health_test.go:121` | **Proposed**; blast radius wider than the design's risk register (see finding H1) |
| §2 remove Auth/CORS | delete 8 tests in `test/middleware_test.go` + 9 in `middleware_extra_test.go`; `interfaces/cors` untouched | **Proposed** |
| §3 (a) forged-XFF/rate-limit | chain test with recording `Key` | **Proposed**; negative control feasible (RemoteAddr fallback verified) |
| §3 (b) degradation position | chain test (429 outside gate, 503 before body read) | **Proposed**; no existing coverage |
| §3 (c) probe byte-identity | chain test vs today's mux construction | **Proposed** |
| §3 (d) idempotency-after-auth | sso composition-site test | **Proposed**; must also assert zero `idempotency_capture_missing` events |
| Existing regression anchors | `rate_limit_hotreload_test.go`, `forwarded_trust_test.go`, `trusted_proxy_gate_test.go`, `degradation_test.go`, `security_headers_test.go` | **Existing, green** in baseline run |

## 3. Findings

### HIGH-1 — `feature_gate_hotreload_test.go` breaks; the design's delta list misses the 404 case

**Evidence.** `interfaces/sso/feature_gate_hotreload_test.go` wires
`WithTracingMiddleware` 8 times and asserts the **absence** of `X-Request-Id`
on gated-off and never-mounted paths at 7 sites (lines 175-176, 183-184,
212-213, 256-257, 294-295, 347-348, 396-397), plus the byte-identity oracle
`TestSetAdminAPIGateEnabled_ByteIdenticalWithGlobalTracingMiddleware`
(lines 155-184) whose doc comment says the gated-off response must be
"byte-identical to the baseline EVEN WITH Tracing wired". Today that works
because `router.Use` copies middlewares per route (`router.go:234-238`), so
unmatched paths never run request-ID. Moving request-ID into the chain's
Tracing slot makes **every unmatched-route 404 carry `X-Request-Id`/
`traceparent`/`X-Trace-Id`** — the sanity check at line 175-176 fails with
`Fatalf`, and all 7 absence assertions fail.

**Impact.** The migration as designed fails CI at ~7 assertion sites. Worse,
the design's "documented delta" covers only 429/503/413; the 404 case is a
second, undocumented delta, and it destroys the file's core oracle ("absent
X-Request-Id ⇒ route never matched") for all future feature-gate work.

**Regression risk.** A reader implementing the design without auditing this
file ships a red suite; or "fixes" the tests by dropping
`WithTracingMiddleware`, silently deleting the leak-detection scenario the
feature exists for.

**Exact test change.** In `feature_gate_hotreload_test.go`, replace the
absence oracle with a route-matched marker: register a counting
`core.MiddlewareFunc` via `s.router`'s `Use` (or a response-header canary set
only by matched handlers) and assert (1) gated-off response still byte-identical
to the never-mounted baseline (both 404 — this property survives the
migration because both paths now run chain-level Tracing identically), and
(2) the marker count proves the gated route's own middleware list never ran.
**Acceptance assertion:** gated-off and baseline responses equal under
`fghrAssertIdentical` with the marker at zero; a matched route with the gate
on increments the marker.

### MED-2 — The intentional header delta (429/503/413) has no pinning test

**Evidence.** The design documents "429/503/413 now carry X-Request-Id/
traceparent/X-Trace-Id" as release-noted, but none of the four proposed tests
asserts it. Today these rejections provably lack the headers (Tracing sets
headers at entry, `middleware.go:126-143`, and runs inside the router, after
the rejecting slots). A future reordering (or someone re-installing Tracing
via `router.Use`) would silently revert the fix with no CI failure.

**Exact test to add** (chain package, extends invariant (b)): with a fully
populated chain, (1) over-limit request → 429 with `X-Request-Id`,
`traceparent`, `X-Trace-Id` present; (2) shedding-gate request → 503 with the
same; (3) oversized body → 413 with the same; (4) unmatched path → 404 with
the same. **Acceptance assertion:** all four responses carry the three
headers; and a negative control with request-ID composed inside the router
(i.e., slot omitted, `FromCore`-adaptered at route level) fails the header
assertion.

### MED-3 — Migration blast radius under-scoped in the risk register

**Evidence.** Risk item 2 names only `health_test.go:121` and
`test/middleware_test.go`. `interfaces/middleware/middleware_extra_test.go`
holds 14 direct `core.HandlerContext` invocations of the migrated/deleted
surfaces: `Auth` ×4 (lines 78-131), `CORS` ×5 (151-217), `Logger` ×1 (232),
`Tracing` ×4 (257-354). Nine of these tests are deleted with the surfaces,
five must be rewritten to `httptest.NewRecorder()` + `ServeHTTP` — in the
package being migrated, so the compiler forces the work, but the risk
register should enumerate it. Related planning slip: the design says the
fake-context harness in `test/middleware_test.go` "shrinks to the remaining
route-level middlewares" — after the migration there are **no** remaining
`core.MiddlewareFunc` users in that file, so the harness (30+ lines) becomes
dead code and should be deleted, not shrunk.

**Exact test change.** Add `middleware_extra_test.go` to the design's rewrite
list; delete `fakeContext` and its helpers from `test/middleware_test.go` in
the same change. **Acceptance assertion:** `grep -rn "HandlerContext"`
`test/middleware_test.go` returns nothing; the package compiles without the
harness.

### LOW-4 — "Panic responses remain header-less" is factually wrong

**Evidence.** `Tracing()` sets `X-Request-Id`/`traceparent`/`X-Trace-Id` on
the response writer at entry (`middleware.go:126-143`); `Recover` writes the
500 on the same writer without clearing headers (`middleware.go:31-45`). So
**today** a recovered panic response carries the tracing headers whenever
`WithTracingMiddleware` is wired. The invariance claim (unchanged after
migration) holds — Recover stays outermost — but the "header-less" wording
is wrong in both states.

**Exact test to add** (chain package): a slot (and separately, the wrapped
router) that panics → `Wrap` output is a 500 with Recover's exact JSON body
and, with tracing wired, the three headers present. **Acceptance assertion:**
status 500, body `{"error":"internal_error"}`, `X-Request-Id` non-empty;
without the tracing slot, headers absent — proving Recover outermost and the
header behavior pinned both ways.

### LOW-5 — `server_health.go` line estimate unexplained

The design's budget table claims `server_health.go` 443 → ~425 (net −18),
but nothing in the migration removes code from that file (`degradationGate`
and `bodyLimitMiddleware` stay with one call site each, per the design's own
storage model). Either the estimate is wrong (file stays ~443) or a removal
is unspecified. `server_routes.go` −70 and `sso_wiring.go` −56 are plausible
(≈95 lines of `buildMiddlewareChain`/`wrapInnerMiddlewares`/`buildProbeMux`/
three `wrap*` removed, ~45-line `buildChain` added). Correct the table before
implementation so the line-budget check has a real target.

### INFO-6 — Spec/design subdir-budget discrepancy resolved in design's favor

Spec §0 says "subdir budget 15"; the enforced gate is `maxSubdirsPerDir = 16`
(`directory_fanout_test.go:35`). The design uses 16. 0 → 1 subdir is safe
under either reading; no action beyond noting the spec typo.

### INFO-7 — Small unit tests missing from the design's test set

The design pins order and invariants but not the Chain's own contract:
(1) zero-value `Chain{}.Wrap(router)` returns `router` unchanged; (2) every
`With*(nil)` is a no-op (no nil deref, slot skipped); (3) `WithProbes` copies
the map (mutating the caller's map after wiring must not affect serving);
(4) empty probe map → no mux, `Wrap` returns the chained handler. Each is a
5-line test; (3) is the only one touching concurrency-relevant behavior.

## 4. Prioritized scenario list

Happy path:
1. Fully-populated chain on a matched request — every slot fires in canonical
   order (observable via RequestLogger output and a marker slot).
2. Zero slots + probes — router served unchanged; `/livez` `/readyz` green.
3. `Handler()` called twice — chain and `rateLimitStore` rebuilt; second call
   still serves and `SetRateLimitPolicy` still swaps live (existing
   `rate_limit_hotreload_test.go`).

Boundary:
4. Each `With*(nil)` — slot skipped, no panic (12 cases, table-driven).
5. `WithProbes(nil)` and empty map — no mux built; `Wrap(router)` identity.
6. Single-option chains — e.g., only `WithRateLimit`, only `WithCORS` —
   behavior matches today's conditional assembly.

Error paths (each pinned with headers, see MED-2):
7. Forged `X-Forwarded-For` + TrustedProxies + RateLimit — bucket keyed on
   validated real IP, not the header (invariant (a)); swapped order keys on
   RemoteAddr fallback (negative control).
8. Over-limit request with Degradation shedding — 429, not 503 (invariant (b)).
9. Huge body to shedding gate — 503 before the body limit reads the body
   (invariant (b)).
10. Unmatched path (404) and method-mismatch path — chain-level Tracing runs;
    headers present (new behavior, HIGH-1 companion).
11. Panic in router handler and in a slot — 500 with Recover body; headers
    present iff tracing wired (LOW-4).
12. `FromCore` with an aborting `MiddlewareFunc` — downstream chain not run;
    non-aborting — passes through; double-write documented, not "fixed".

Race/recovery:
13. Chain wired once, served under `-race` with concurrent requests (probe map
    copy protects serving; document "wire, then Wrap, then serve").
14. Degradation gauge seeding — one call site; `DegradationMode` gauge seeded
    at build (existing `degradation_test.go` modes coverage stays green).
15. Idempotency-after-auth (invariant (d)): cached success seeded through an
    authenticated path never replayed to an unauthenticated same-key request;
    swapped composition replays (negative control); zero
    `idempotency_capture_missing` audit events.

## 5. CI/manual-suite gaps, flake risks, fixtures, exit criteria

Gaps:
- No test pins the new 429/503/413/404 header behavior (MED-2) and no test
  pins Recover-outermost through the Chain (LOW-4).
- No `FromCore` unit test (abort semantics) is specified anywhere.
- The design's §1 acceptance `grep -rn "core.MiddlewareFunc"
  interfaces/middleware` hits only `FromCore` — achievable only because
  Auth/CORS/Logger/Tracing/RequestID all leave the package; the grep must be
  part of implementation verification, and `aliases.go` must drop exactly
  `AuthMiddleware`/`CORS` while keeping the other four aliases.
- `make ci` (nested modules, examples, config validation) is the handoff gate;
  nothing in this design touches nested modules (`interfaces/cors`,
  `ratelimit`, `platform/tracing`, `platform/audit` are untouched by design).

Flake risks:
- Invariant (a) depends on `ratelimit` clock/limiter internals — reuse the
  existing `ratelimit` test policy fixtures rather than inventing new ones.
- `feature_gate_hotreload_test.go` rewrite must keep `fghrAssertIdentical`
  semantics; the new marker must be deterministic (counter, not timing).
- The 65s `interfaces/sso` race run shows that package is slow; new chain
  tests are pure handler composition and should stay in the `chain` package
  (fast) with only (d) in `interfaces/sso`.

Fixtures needed: none new beyond `NewTrustedProxies(cidrs, hops)` (exists,
`trusted_proxy.go:39`), a `ratelimit.Policy` with a recording `Key`, and a
`spi.Logger` no-op for `Recover`/`RequestLogger` (existing test loggers).

Exit criteria for implementation:
1. `chain` subpackage lands with `TestChain_CanonicalSlotOrder`, (a)-(d), and
   the INFO-7/LOW-4/MED-2 unit tests green, each with its documented negative
   control verified once.
2. `feature_gate_hotreload_test.go` green with the marker oracle (HIGH-1).
3. `middleware_extra_test.go` migrated/deleted; `fakeContext` harness removed
   from `test/middleware_test.go` (MED-3).
4. `go build ./... && go vet ./...`; `TestMaintainability_|TestArchitecture_`
   green (chain classifies as `interfaces`, no `layerName()` change);
   `go test -race ./interfaces/middleware/... ./interfaces/sso/...` green.
5. Grep acceptances: no `wrap*`/`buildProbeMux` outside the construction
   site; `core.MiddlewareFunc` only in `FromCore`; no new `interfaces/sso`
   file; `interfaces/middleware` non-test count ≤ 10; `chain.go` < 500 lines.
6. `make ci` green; release notes carry the `sso.CORS`/`sso.AuthMiddleware`
   removal and the header delta (429/503/413/404 now carry correlation IDs).
