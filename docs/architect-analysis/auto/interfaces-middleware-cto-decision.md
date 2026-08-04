# CTO Decision: `interfaces/middleware` typed Chain (subsystem `adversarial_review`)

**Role:** CTO advisory decision. Repository maintainers and accountable
business owners retain approval authority.

**Revision reviewed:** `cde984d6` (design stage). Inputs: the design
(`docs/auto/interfaces-middleware-design.md`) plus four independent
adversarial reviews (protocol, security, QA, architecture). All material
claims below were re-verified against the tree by the CTO reviewer, including
the disputed ones.

**Checks actually run by the CTO reviewer:** `shared/core/router.go:230-287`
(ServeHTTP + gated-off comment), `interfaces/sso/feature_gate_hotreload_test.go`
(header-absence assertions, sanity check, byte-identity helper),
`interfaces/middleware/middleware.go` (Tracing header stamping),
`interfaces/middleware/idempotency.go` (position invariant, handler-side
commit), `interfaces/sso/server_routes.go:108-121` (mountMiddleware),
`interfaces/sso/aliases.go:40-50` (re-exports), `interfaces/cors/cors.go:5`
(stale reference), `docs/observability.md:94-103` (stack diagram), budget
gates (`directory_fanout_test.go:35`, file counts, line counts), treewide
grep for production call sites of `middleware.Idempotency`/`sso.AuthMiddleware`
and for `core.MiddlewareFunc` in `interfaces/middleware`.

---

## 1. Executive summary and advisory decision

**Decision: PROCEED WITH CONDITIONS.**

This is an internal maintainability refactor of the request admission
pipeline — the highest-security surface in an SSO product (every OAuth/OIDC/
CAEP/SAML request passes through it). It delivers no user-visible feature;
its value is (a) compile-time order safety for a 12-slot chain whose wrong
ordering is a security failure, (b) collapse of seven hand-written assembly
functions into one construction site, (c) relief of real budget pressure
(`interfaces/middleware` at its 10-file ceiling, `server_routes.go` at
488/500), and (d) a typed `Chain` surface for SDK embedders.

The design is exceptionally well-verified on structure: every budget, line
citation, signature, and ordering claim checked against the tree holds
(confirmed independently by CTO re-verification). But all four adversarial
reviews independently converged on the same HIGH flaw — **F1: the Tracing
relocation breaks a deliberate, adversarial-review-hardened
anti-enumeration invariant with 7+ committed regression tests, and the
design's risk register misses it while mischaracterizing the delta as "a
fix"**. The design is not implementable as written: it ships a red suite at
`feature_gate_hotreload_test.go`.

The resolution is cheap and lossless: **keep request-ID stamping on
`Router.Use` (route-level); the chain's Tracing slot hosts OTel only**
(architect Option A / security Option a). This preserves every invariant,
every committed test, and all of the spec's §1 goals. The only thing given
up is the side-effect "correlation headers on early rejections" delta, which
was never a stated requirement of the refactor — if product wants
rejection-path correlation IDs, that is a separate, deliberate change with
its own tests, not something to smuggle through a refactor.

**Conditions (all resolvable before/at M0–M1, none are code-blocking after
the M0 decision):**

1. F1 resolved as Option A (or, if owners override, as an explicit
   Option B with the 9-test rewrite + `router.go` comment + release notes in
   the *same* change and a replacement invariant — never as "audit the
   tests").
2. Spec §2 grep acceptance amended: "chain slots accept only
   `middleware.Middleware`"; route-level middlewares remain
   `core.MiddlewareFunc` by router design. Tracing/Logger/Idempotency
   migrations are then optional cleanup, not acceptance requirements —
   **Idempotency migration should be deferred** (zero call sites; it is a
   protocol migration, not a signature change, per security F3).
3. `FromCore` spec amended per security F2: pass-through must call
   `next.ServeHTTP(ctx.ResponseWriter(), ctx.Request())`, with a
   writer-identity regression test.
4. SDK break (`sso.AuthMiddleware`/`sso.CORS` removal): explicit product
   approval; zero in-tree consumers verified, but it is a public API break
   of an embeddable SDK — separable into its own release.
5. Same-change contract updates per AGENTS.md §5.6: `docs/observability.md`
   stack diagram (already drifted today — fix it in this change),
   `interfaces/cors/cors.go:5` stale reference, release notes.

---

## 2. Evidence-backed rationale and the strongest contrary case

### Rationale for proceeding

- **Verified structural soundness.** Every budget claim in the design holds:
  `interfaces/middleware` at exactly 10 non-test files (cap 10,
  `directory_fanout_test.go`), `interfaces/sso` at 60 (cap 60), line counts
  166/488/446/443/500, `maxSubdirsPerDir = 16`, depth-3 `chain` subpackage,
  first-segment layer rule → no `layerName()` change, `chain` imports only
  `net/http` + `shared/core` (no cycle). All 11 slot-filling constructors
  are `func(http.Handler) http.Handler`-shaped (alias = zero conversions;
  verified for `Recover`, `Compress`, `AcceptVersion`, `Degradation`,
  `RequestLogger`, `cors.Middleware`, `ratelimit.DynamicMiddleware`).
- **The core deliverable is low-risk and separable.** M1 (the `chain`
  subpackage + 4 invariant tests + slot-order pin) is purely additive — not
  wired into `Server`. M2 (the collapse) is behavior-identical under
  Option A. Value is banked early; the change can be stopped after M1 with
  most of the value retained.
- **Four independent reviewers converged on F1.** Security, protocol, QA,
  and architecture reviews each independently found the same HIGH issue —
  and my own re-verification confirms it: `router.go:244-253` documents the
  deliberate design intent ("That distinction is exactly what would
  otherwise let a global middleware … stamp response headers a
  genuinely-unmatched request never gets"), and
  `feature_gate_hotreload_test.go` encodes it with a `t.Fatalf` baseline
  sanity check, 7 `X-Request-Id`-absence assertions, and byte-identity
  comparisons. A finding that survives four independent adversarial passes
  and a CTO re-check is the highest-confidence signal available in this
  process.
- **The underlying security property survives relocation** (gated-off and
  never-mounted paths are stamped identically — no enumeration oracle is
  reintroduced), so F1 is an invariant/regression break, not a new exploit.
  But the *strongest form* of the invariant (byte-identity) becomes
  mechanically unreachable once random per-request IDs are stamped
  pre-router: the committed suite would have to be weakened permanently.
  Weakening a suite that was hardened after an adversarial review, to
  purchase a side-effect header delta that was never a requirement, fails
  the cost/benefit test. Option A avoids the trade entirely.
- **Storage/state model is sound.** No durable state; chain rebuilt per
  `Handler()` call; the one side-effectful assignment (`s.rateLimitStore`)
  is preserved adjacent to `WithRateLimit` (hot-reload covered by
  `rate_limit_hotreload_test.go`); the per-call reset quirk is correctly
  preserved, not "fixed", in this change.

### The strongest contrary case

1. **No user-visible value; touches the security admission pipeline.**
   Every line of this change edits code in front of the product's
   authentication surface. For an SSO vendor, that is the worst possible
   place for a churn-heavy refactor with zero feature payoff.
2. **The "dual-signature tax" is largely inherent, not removable.** Route-
   level middlewares are `core.MiddlewareFunc` by the router's design
   (`shared/core` is explicitly untouched by the spec). Only three
   ctx-shaped middlewares remain in `interfaces/middleware` — `Tracing`,
   `Logger`, `Idempotency` — and two of them have zero production call
   sites. The spec's grep acceptance ("`core.MiddlewareFunc` only in
   `FromCore`") fights the architecture; the marginal value of satisfying it
   (M3) is near zero, and the Idempotency migration in particular is a
   protocol re-wiring (handler-side commit moves, fail-open canary path
   re-wired) with zero consumers.
3. **The F1 miss is a process signal.** The design claims "every budget and
   signature claim was re-verified" — and it was, but only for structure.
   The committed test surface's behavioral invariants were not scanned; the
   design's own risk register item 1 ("audit tests; the delta is a fix")
   actively inverts the invariant's intent. This argues for a
   "committed-test impact scan" gate before implementation, and for
   skepticism about the design's delta claims in general (verified: the
   delta list also omits 404s and AcceptVersion 400s, and the "panic
   responses remain header-less" claim is factually wrong in both states —
   `Tracing()` stamps at entry, so matched-route panic 500s carry headers
   today; invariance still holds, but the design's delta description is
   inaccurate in the direction that matters).

**Why proceed anyway:** the contrary case argues for trimming scope, not
stopping. The budget pressure is real (10-file ceiling, 488/500 lines), the
order-safety value is real and compounding, and the marginal cost after
Option A + trimmed M3 is small: one new ~300-line file, collapse of seven
functions, four invariant tests, and a bounded, enumerable test rewrite
(`middleware_extra_test.go` ~16 ctx call sites, `test/middleware_test.go`,
`health_test.go:121`). The sunk investment (spec → design → four
adversarial reviews) is substantial; the remaining decision is cheap.

---

## 3. Option table

| Option | Value | Cost drivers | Key risks | Reversibility | Dependencies |
|---|---|---|---|---|---|
| **A. Proceed as designed (Option A for F1, trimmed M3)** — *recommended* | Compile-time order safety; single construction site; −70 lines in `server_routes.go`; typed `Chain` SDK surface; budget headroom restored | ~1 new file (~300 lines); collapse edits in 3 sso files; test rewrites in 4 files (~1.3k lines touched); docs | F2 adapter gap; Idempotency re-wiring if not deferred; Wrap cyclo headroom (~13–14/15); budget re-check in M2 | High: M1 purely additive; M2 behavior-identical and revertible by grep; chain not yet wired | M0 owner decisions (F1, SDK break, §2 amendment, test-(d) stub, canonical doc copy) |
| **B. Build-lean (M1+M2 only; defer M3 and SDK break)** | Order safety + collapse without touching any public API or the Idempotency protocol | Smallest: no signature migrations, no alias churn, no test rewrites beyond chain tests | None material; leaves `Auth`/`CORS`/`Logger`/`Tracing`/`Idempotency` ctx-shaped (fine — route-level by design) | Very high | F1 decision only; §2 acceptance re-scoped |
| **C. Defer (no code now)** | Zero near-term risk | None | Budget pressure compounds (10-file ceiling blocks any future root file in `middleware`; 488/500 lines blocks `server_routes.go` growth); dual-signature tax persists; sunk design/review investment idles | n/a | n/a |
| **D. Redesign around Option B relocation (uniform request-ID everywhere)** | Operational nicety: correlation IDs on every response incl. 404/429/503/413 | Rewrite 9 committed tests; weaken byte-identity oracle permanently; invert `router.go`'s documented intent; release-note a wide header delta | Weakens the strongest security regression guard for a side-effect benefit; contradicts the design's own "smallest cohesive change" discipline | Low once committed (suite weakened) | Product owner acceptance of a permanent invariant change; not justified by any stated requirement |

Build over buy/reuse: no external product addresses this; the design
correctly reuses all 11 existing constructors and the router's own Abort
semantics in `FromCore`. There is no stop case except owner refusal of the
SDK break — which is separable, not blocking.

**Recommended: Option A** (per the table: proceed with conditions, trimmed
M3). If maintainers prefer minimal blast radius above all, **Option B is
the fallback** — M1+M2 deliver most of the value with the smallest
footprint; the SDK break and signature migrations can be re-scoped into a
later, separately approved change.

---

## 4. Required conditions, exit criteria, non-goals, owner decisions

### Required conditions (before M2)

1. **F1 resolution recorded** (Option A recommended; Option B requires the
   9-test rewrite + `router.go` comment update + full 400/404/413/429/503
   header-delta release note in the same change).
2. **Spec §2 amendment** approved: chain slots accept only
   `middleware.Middleware`; route-level middlewares remain
   `core.MiddlewareFunc`.
3. **`FromCore` spec amended** (F2): `next.ServeHTTP(ctx.ResponseWriter(),
   ctx.Request())`; abort-after-write double-write hazard documented;
   writer-identity regression test.
4. **Test-(d) stub mechanism specified** (architect finding 3): inline
   handler-shaped auth stub; the design's "swapped composition" negative
   control cannot use `middleware.Auth` (deleted in the same change).
5. **SDK break approved** by product owner, or M3 split into a later
   release (feature matrix + release notes updated in the same change).
6. **Idempotency migration deferred** (security F3): keep it
   `core.MiddlewareFunc`, keep the handler-side commit and the
   `idempotency_capture_missing` fail-open canary untouched; test (d) stays
   a route-level contract pin.
7. **Canonical doc copy decided** (`docs/auto/` vs
   `docs/architect-analysis/auto/` — currently identical, cross-references
   stale in both).

### Measurable exit criteria (adapted from the reviews)

- `go build ./... && go vet ./...`; `go test -run
  'TestMaintainability_|TestArchitecture_' .` green.
- `go test ./interfaces/sso/ -run 'FeatureGate|ByteIdentical' -count=1`
  green **with the committed tests unchanged** (under Option A; this is the
  F1 regression gate).
- `TestChain_CanonicalSlotOrder` green; invariant tests (a)–(d) green with
  each negative control verified to fail on slot swap.
- New pinning test for the intended rejection-path header behavior
  (QA MED-2), with the request-ID-inside-router negative control.
- Grep acceptance: `wrapPanicRecovery\|wrapCompression\|wrapAPIVersioning\|
  buildProbeMux` absent from `interfaces/sso` except `buildChain` (or
  absence); `interfaces/middleware` non-test count stays ≤ 10; `interfaces/
  sso` file count stays 60; `server_routes.go` ≤ 500 (realistic landing
  ≈ 440–465, not the optimistic ~420 — architect finding 9).
- `rate_limit_hotreload_test.go`, `degradation_test.go`, probe-bypass tests
  green and unchanged in behavior.
- `go test ./interfaces/middleware/... ./interfaces/sso/... -run
  'Chain|Idempotency|Probe|RateLimit|Degradation' -race`; `go test ./...`
  `-race`; `go test ./test/ -run TestE2E -v`; `make ci` at handoff.
- Same-change docs: `docs/observability.md` stack diagram corrected (it is
  already drifted today), `interfaces/cors/cors.go:5` stale `sso.CORS`
  reference removed, release notes cover the SDK break and (under B) the
  header delta.

### Non-goals (explicit)

- No caching of the chain on `Server`; no "fixing" the per-`Handler()`
  `rateLimitStore` reset semantics.
- No changes to `shared/core/router.go`, `interfaces/ratelimit`,
  `platform/tracing`, `platform/audit`, the idempotency replay cache, or
  the `idempotency_capture_missing` canary.
- No new config, endpoint, `Err*`, or durable state; probes stay outside
  all slots; no OIDF certification claims; no browser/frontend scope.
- Not in scope: rejection-path correlation IDs unless separately specified
  and tested (see Option D — not recommended).

### Owner decisions required (unresolved unknowns)

| # | Decision | Owner | Recommended |
|---|---|---|---|
| 1 | F1: preserve "unmatched ⇒ no tracing headers" (A) or accept uniform stamping (B) | Security/product owner | Option A |
| 2 | SDK break `sso.AuthMiddleware`/`sso.CORS` in current release or split | Product owner | Split to later release if any doubt |
| 3 | Spec §2 acceptance re-scoping | Spec owner | Accept route-level exception |
| 4 | Test-(d) auth stub mechanism | Design owner | Inline fixed-token bearer stub |
| 5 | Canonical doc location | Maintainers | `docs/auto/` (working set), architect-analysis copy as snapshot |
| 6 | Idempotency migration deferral | Design owner + security | Defer |

---

## 5. Top risks, mitigation, validation, residual-risk owner

| # | Risk | Severity | Mitigation | Validation | Residual owner |
|---|---|---|---|---|---|
| 1 | F1 mis-resolution: implementer weakens the feature-gate suite instead of preserving the invariant | High | M0 decision recorded before M2; negative control test must fail on any header/body/status divergence from the never-mounted baseline | `-run 'FeatureGate|ByteIdentical'` green with committed tests unchanged | Security engineer + maintainers |
| 2 | FromCore writer-propagation bug silently degrades replay control (F2) | Medium | Spec amendment; writer-identity regression test (`FromCore(Idempotency(...))`: handler-visible writer is the `CaptureWriter`; replay short-circuits) | New test in M1 | Design owner |
| 3 | Idempotency protocol re-wiring loses the oracle-safe position (F3) | Medium | Defer the migration (condition 6); if ever migrated: before/after contract table + `idempotency_capture_missing` audit assertion | Test (d) + capture-missing assertion | Security engineer |
| 4 | Budget regressions: `Wrap` cyclo ~13–14/15; `chain.go` ~300/500; `server_routes.go` landing over 500 | Low | Document growth path (fixed-order literal array of slot closures, cyclo ≈ 2; future slots = new files in `chain/`, never depth-4 subpackages); re-run arithmetic in M2 | Budget gates in `make ci` | Implementer |
| 5 | Test-churn inventory undershoot (F3/QA MED-3): `middleware_extra_test.go` (~16 ctx call sites) unnamed in the design | Low | Enumerate all sites in M3 scope before editing; delete the `fakeContext` harness (zero remaining users) rather than shrinking it | Grep count vs. plan | Implementer |
| 6 | Docs drift ships as-is (observability.md already wrong; cors.go stale) | Low | Same-change contract updates per AGENTS.md §5.6 | Review diff for docs/observability.md | Implementer |
| 7 | `WithProbes` ServeMux pattern panic for SDK callers (invalid patterns panic at registration) | Low | Document the constraint; sso-server passes only `PathLivez`/`PathReadyz`/`PathMetrics` (no production exposure) | Doc note + existing probe tests | SDK owner |

**Residual risks accepted as-is (pre-existing, preserved by design):**
per-`Handler()` `rateLimitStore` reset; probe bypass of rate limiting;
chain concurrency documented but unenforced; `Chain` mutable until `Wrap`.

**Validation sequence (prioritized):** (1) M0 decision gate → (2) F2 spec
amendment + writer-identity test → (3) M1 additive chain + invariant tests
with negative controls → (4) M2 collapse with feature-gate suite green
unchanged → (5) M3 (trimmed) with enumerated test rewrites → (6) full gates:
`go test ./... -race`, `go test ./test/ -run TestE2E -v`, `make ci`.

---

*Advisory only. Maintainers and accountable business owners retain approval
authority. No code was modified by this review.*
