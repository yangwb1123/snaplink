# QA Review: interfaces/cors execution observability design

Reviewer: QA lead. Input: `docs/auto/interfaces-cors-observability-design.md` +
`docs/auto/interfaces-cors-observability-spec.md` (direction 三), against
current source at this revision. Docs-only revision — no Go edits exist yet,
so every test below is **Proposed** unless marked otherwise. All citations in
the design were re-checked against source; discrepancies are findings F5.

## 1. Test inventory and commands actually run for this revision

All run on the current working tree (design doc present, no CORS-observability
code). **Verified** unless noted.

| Command | Result |
|---|---|
| `go build ./... && go vet ./...` | PASS |
| `go test -run 'TestMaintainability_\|TestArchitecture_' .` | PASS (includes `TestMaintainability_FileSizeBudget`, the 500-line gate) |
| `go test ./interfaces/cors/ ./platform/metrics/ ./interfaces/sso/` | PASS |
| `go test ./platform/audit/...` (8 packages) | PASS |
| `go test ./test/` (full ssotest suite) | PASS (20.7s) |
| `go test ./test/ -run TestCORS -v` | PASS (5 tests: 2 unit-ish + 3 e2e) |
| `go test -race ./interfaces/cors/ ./platform/metrics/ ./platform/audit/...` | PASS |
| `go test -race ./interfaces/sso/` | PASS (64.3s) |
| `go test ./platform/audit/auditreport/ -run 'TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized\|TestBuildSOC2Report_'` | PASS (drift guard + SOC2 buckets) |
| `go test ./...` | PASS |
| Coverage (baseline, current): `interfaces/cors` 84.1%, `platform/metrics` 68.6%, `test/` no statements | measured |
| Empirical probe (temp test in `test/`, deleted after run): disallowed-origin preflight (`OPTIONS /auth/login` + `Access-Control-Request-Method`) | **404**, no `Access-Control-Allow-Origin` header |
| Budget simulation (python/awk on `/tmp` copy of `platform/metrics/metrics.go`): insert design's `CORSBlockedTotal` field block beside `CIBAPingTotal` | **502 lines > 500 → gate fails** |

Suite taxonomy (Verified): default CI = `go test ./...` + root gates + `make ci`
(nested modules, config, module validation). `bench`/`bench-gate` (opt-in
baseline compare), `load-test` (k6, `/token` happy path), and `chaos-test` are
manual/opt-in targets — none exercises the CORS reject path today; no
`Benchmark*` exists in `interfaces/cors`, `platform/metrics`, `interfaces/sso`,
or `test/`.

## 2. Requirement-to-test matrix

Status: all **Proposed** (this revision ships no code/tests). Evidence column
cites the source anchor the test must pin.

| Requirement (spec §) | Test to add | Status | Evidence / acceptance assertion |
|---|---|---|---|
| Shared: observer fires exactly once per rejected request, before forward; correct `preflight` flag | `interfaces/cors/cors_test.go` (205 lines, headroom): new `TestMiddleware_BlockObserver*` | Proposed | Reject branch `cors.go:185-188`; assert call count == 1, `preflight` true for OPTIONS+ACRM, false for GET. Allowed-origin, no-Origin, and empty-policy (identity, `cors.go:173-176`) fire **zero** times |
| Shared: option is source-compatible; identity fast-path intact | existing 10 call sites compile unchanged (9 in `cors_test.go`, 1 at `server_routes.go:452`) | Verified (count) | Variadic `opts ...Option` with private type + `WithBlockObserver` constructor; `test/cors_e2e_test.go` uses `sso.WithCORS`, not `cors.Middleware` (design's parenthetical is imprecise — see F5) |
| §1: blocked request increments `CORSBlockedTotal{reason="disallowed_origin",preflight="false"}` by exactly 1 | E2E case 1 (`test/cors_observability_test.go`) | Proposed | Counter via `testutil.ToFloat64` or `/metrics` scrape — design must pick (F4) |
| §1: chain order — blocked request also counted by `sso_http_requests_total` | E2E case 1 assertion "both move together" | Proposed | `metrics.Middleware` wraps CORS (`server_routes.go:390` vs `:452`); catches chain-order regression |
| §1: `/metrics` shows series with `WithMetrics`; no series / no panic without | E2E cases 1, 5 | Proposed | Probe mux registers `/metrics` only when `s.metrics != nil` (`server_routes.go:481-483`); case 5 must assert 404 + no panic, not "zero series" (F7) |
| §2: recorder helper mirrors `RecordCIBAPingFailed` (nil-recorder no-op, `SetMeta` only, trace via ctx) | `platform/audit/recorder_events_test.go` additions beside `:154` | Proposed | Mirror `TestRecordCIBAPingFailed_BackgroundContext`; assert type `cors_origin_blocked`, `OutcomeFailure`, 4 metadata keys, empty-trace tolerated, nil rec no-op |
| §2: login gate keeps 403 + `iss`, drops log; exactly one event per rejected `/auth/login` | E2E case 2 + `interfaces/sso/origin_validation_test.go` | Proposed | Gate at `server_login.go:30,166-181`; `TestLogin_OriginBlocked_CarriesNoStoreAndIssuer` (`login_early_gate_headers_test.go:51`) pins 403+no-store+iss and is unaffected by log removal (no test asserts the `origin_blocked` log — Verified). `audit.New(MemorySink)` is synchronous (Verified: `recorder.go:88` no async wrap), so "ONE event total" is deterministic — the gate aborts before any other event |
| §2: `corsPolicy == nil` → zero events | E2E case 5 / unit | Proposed | `isOriginAllowed` returns true when nil (`origin_validation.go:107-109`); middleware not mounted (`server_routes.go:449-451`) |
| §2: classification in CC6.1, drift guard green | `platform/audit/auditreport` edit; drift test stays green | Proposed | CC6.1 block `control_areas.go:50-66`; guard `TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized` (`drift_test.go:103`) passes today — Verified |
| §3: `docs/observability.md` rows + middleware-order sentence; grep acceptance | contract rows in `observability.md` | Proposed | Table `:32`-area, audit section, chain line `:100`; greps `sso_cors_blocked_total` / `cors_origin_blocked` must hit |
| §3: PathOverrides-resolved decision not counted | E2E case 4 | Proposed | Use in-chain `/.well-known/openid-configuration` (`server_discovery.go:27`) with a `"/.well-known/"` override; assert headers present, counter unchanged, zero events |
| Cross-cutting: `-race`, full suite, `make ci`, budget/architecture gates | run at handoff | Proposed | Budget tripwires: F1 (missed) and `metrics_ctor.go` 497→498 (Verified correct) |

## 3. Findings

Sorted by severity. Evidence labels per the evidence standard.

### F1 — Medium (blocks the change as designed): `metrics.go` line-budget tripwire missed; design's own field block pushes the file over 500
**Verified.** The design budgets `metrics_ctor.go` (497→498, correct — Verified)
but not `metrics.go`, which is at 494/500 (gate counting = newline count,
`maintainability_budget_test.go:117-129`). Inserting the design's exact
`CORSBlockedTotal` block (7 comment lines + field = 8 lines) beside
`CIBAPingTotal` (`metrics.go:191`) yields **502 lines > 500** — the committed
`TestMaintainability_FileSizeBudget` fails at implementation time. The
"budget-shaped answer" framing is incomplete: the register call was split into
a new file, but the struct field cannot leave `metrics.go`.
**Recommendation:** trim the field comment to ≤5 lines (494+6 = 500 = at the
limit, allowed) or relocate the doc detail into the new
`platform/metrics/cors.go` registration Help text.
**Validation:** after implementation, `go test -run TestMaintainability_FileSizeBudget .`
must pass; repeat the /tmp insertion simulation.

### F2 — Medium: shared reason const implies a new `platform/audit → platform/metrics` import that the design leaves unpinned
**Partial.** Decision 1 puts `CORSBlockReasonDisallowedOrigin` in
`platform/metrics/consts.go`; Decision 2's helper (`platform/audit`) hard-codes
it. `platform/audit` has **zero** cross-platform imports today (Verified —
grep of non-test files). The same-layer import would pass the architecture gate
(no upward edge), but it is a new coupling in a security-sensitive package and
the "single source of truth via a shared string" claim never says where the
string lives or how audit obtains it.
**Recommendation:** parameterize the helper —
`RecordCORSOriginBlocked(rec, ctx, origin, method, path string, preflight bool, reason string)` —
and have the `interfaces/sso` observer pass the metrics const (sso already
imports both; single source of truth lives at the wiring layer, no new
dependency). If the design prefers the direct import, state it explicitly.
**Validation:** `go vet ./...` + architecture gate after implementation; no
cycle (`platform/metrics` must not import `platform/audit`).

### F3 — Low (factual error in narrative): "a disallowed preflight is counted as a 2xx" is false — it is a 404
**Verified (empirically).** `StdRouter` (`shared/core/router.go:250-279`) is a
linear method-matching router with no OPTIONS handling; an unmatched OPTIONS
falls through to `http.NotFound` → 404. gin/echo adapters normalize unmatched
OPTIONS to 404 as well (`interfaces/adapters/gin/adapter.go:63-72`). Probe:
disallowed-origin preflight on `/auth/login` returned **404**, no ACAO header.
Impact: the motivation narrative overstates invisibility (disallowed
preflights already surface as 4xx); the counter design itself is unaffected.
**Recommendation:** correct the sentence; strengthen E2E case 1 to assert the
disallowed preflight status (404) and `preflight="true"` label — this also pins
the router interaction so a future OPTIONS auto-handler (Go ServeMux-style 200)
cannot silently change the status_class.
**Validation:** E2E case 1 asserts `resp.StatusCode == 404` for the disallowed
preflight and `sso_http_requests_total{...,status_class="4xx"}` increments.

### F4 — Low: E2E counter-read mechanism is underspecified and contradicts the sibling precedent
**Partial.** The design says the E2E "reads the in-memory `*metrics.Metrics`
registry directly (not the `/metrics` scrape)". Reading a CounterVec value
requires `prometheus/testutil.ToFloat64`, but `test/` deliberately contains no
testutil import — `ciba_ping_test.go:192-193` documents the scrape pattern as
the reason (the comment's claim that testutil "pulls a new indirect module" is
itself inaccurate — testutil is a package of the already-present
`client_golang` — but the pattern is established and consistent).
**Recommendation:** adopt the `cibaPingMetricValue` scrape pattern for
`sso_cors_blocked_total` (probe mux already serves `/metrics` from
`buildProbeMux` when metrics are wired); or explicitly accept the testutil
import and drop the sibling's rationale.
**Validation:** one of the two mechanisms appears verbatim in the E2E; no new
go.mod entry.

### F5 — Low: citation drift in a doc that claims "every citation re-verified"
**Verified.** None change the design's substance:
- `sanitizeMethod` is at `middleware.go:38`, not `:29`;
- bounded-cardinality sentence is `observability.md:9`, not `:7`;
- `AdoptionReason*` consts are `consts.go:201-202`; `:142` is `LabelReason`;
- `test/cors_e2e_test.go` is not a `cors.Middleware` call site (it uses
  `sso.WithCORS`); the "~10" count is still right (9 + 1);
- "CORS sits innermost" — `wrapCompression`, `bodyLimitMiddleware`, and
  `wrapAPIVersioning` sit inside CORS (`server_routes.go:453-465`); CORS is
  just outside the router, which is what the observer actually needs
  (every in-chain path passes it; probes excluded).

### F6 — Info: log-volume amplification at the observer
Previously one `origin_blocked` log per disallowed `/auth/login`; after the
change, one structured log + one audit event + one counter increment per
rejected-origin request on every in-chain path. Bounded upstream by the rate
limiter (which wraps CORS, `server_routes.go:383-388`), so volume is
rate-limit × path-scan. The design addresses audit volume (async drop
counters) but not log volume; a noisy-peer log destination is the only
unbounded sink. No action required beyond noting it in the operator docs.

### F7 — Info: E2E case 5 "zero series" cannot be asserted as written
With `WithMetrics` absent, `buildProbeMux` registers no `/metrics` route at
all (`server_routes.go:481-483`) — a scrape gets 404, not an empty series.
Assert: no panic, request forwarded, `/metrics` returns 404 (or skip the
scrape entirely).

### F8 — Info: PathOverrides × login-gate asymmetry — verified, correctly handled, one cheap pin missing
**Verified.** `isOriginAllowed` (`origin_validation.go:103-119`) checks only
`AllowedOrigins`/wildcard; the middleware resolves `PathOverrides`. The
design's handling (document as known limitation, exclude `/auth/login`
overrides from E2E, defer unification to direction 二) is sound — and E2E case
2 would pass today because the gate's 403 is independent of the observer.
Recommend one regression pin: a unit test in `origin_validation_test.go`
asserting the gate ignores `PathOverrides` (current behavior), so the
direction-二 unification is a deliberate, test-visible change. The E2E must NOT
add an `/auth/login` PathOverrides case (it would encode the silent-enforcement
hole).

## 4. Prioritized scenario list

Happy path:
1. Allowed-origin GET `/health` → ACAO echoed, counter/event/log unchanged.
2. Allowed-origin preflight → 204 + Allow-Methods/Headers, metrics 2xx,
   observer silent (pins the `isPreflight` short-circuit interaction).

Boundary:
3. No-Origin request → forwarded untouched, observer silent (same-origin
   browsers/native clients must not flood).
4. `Origin: "null"` (sandboxed iframe) → treated as disallowed today:
   counter `preflight="false"` +1; documents the direction-一 `null_origin`
   seam.
5. Empty policy + observer wired → identity, zero fires (pins the
   observer-before-identity bug, design's breakage risk 2).
6. Wildcard `"*"` with/without credentials → allowed, silent.
7. PathOverrides longest-prefix match; override-allowed origin on
   `/.well-known/openid-configuration` → headers present, zero telemetry
   (E2E case 4).
8. `corsPolicy == nil` → middleware absent, gate permissive, zero events.

Error path:
9. Disallowed GET on public path → no ACAO, forwarded, counter+event+log
   exactly once, `sso_http_requests_total` also moves (E2E case 1 + F3 status
   pin).
10. Disallowed POST `/auth/login` → 403 + `iss` + no-store headers, exactly
    one event (E2E case 2; existing
    `TestLogin_OriginBlocked_CarriesNoStoreAndIssuer` stays green).
11. Disallowed preflight → 404 + `preflight="true"` label (F3).
12. Server without `WithMetrics`/`WithAuditRecorder` → no panic, no series,
    `/metrics` 404 (E2E case 5 + F7).
13. Partial ctor (`CORSBlockedTotal == nil`) → second nil-guard no-op
    (unit, mirror `ObserveConditionalAccessDecision`, `metrics.go:462-467`).

Race:
14. Concurrent disallowed requests → counter exact (prometheus atomic);
    run the E2E/unit additions under `-race -count=10`.
15. Concurrent observer + async-sink drop → counter fires, event may drop
    (unit-level with a failing sink; E2E uses the synchronous MemorySink, so
    divergence is by design and must not be asserted as equality).

Recovery/failure:
16. Sink error → fail-open: response unaffected, error routed to
    `Recorder`'s `onError` (`recorder.go:176-178`, Verified).
17. No trace middleware → empty TraceID tolerated, event still recorded.
18. Login-gate 403 with policy disagreement (PathOverrides on `/auth/login`)
    → documented limitation; gate still 403s; NOT an E2E case (F8).

## 5. CI/manual-suite gaps, flake risks, fixtures, exit criteria

CI/manual gaps:
- Default CI (`make ci`, root gates, `-race` runs) covers the new tests once
  written; nothing new is needed there.
- **Gap:** `load-test` (k6, `/token`) has no disallowed-origin scenario; the
  observer adds a synchronous interface call + nil-checks + counter Inc on the
  reject path (coldest path — low risk). Optional: one k6 scenario with
  disallowed origins to confirm no per-request cost cliff; not a gate.
- **Gap:** no benchmark for the CORS middleware; the reject path is coldest —
  skip (state explicitly; do not add to `bench-gate`).
- `chaos-test` has no CORS scenario — appropriate: the observer holds no state,
  nothing to chaos-test beyond the fail-open paths already unit-covered.
- **Docs check:** the spec's grep acceptance (`sso_cors_blocked_total` /
  `cors_origin_blocked` in `observability.md`) must be folded into the
  change's verification, not a one-off.

Flake risks: none identified. The E2E uses a per-test server/registry
(`minServer` pattern, `ops_test.go:30`), the synchronous `MemorySink`
(`audit.New` wraps nothing, `recorder.go:88`), no timers, and exact counter
values on a per-test registry — no cross-test pollution. The only risk is the
F4 mechanism ambiguity (testutil vs scrape); pick one and the tests are
deterministic.

Fixtures needed: none new. Reuse `minServer`, `cibaPingMetricValue`-style
scrape (or testutil — F4), `MemorySink`, and the `recCtx`/`only` helpers
(`recorder_events_test.go`). The PathOverrides policy for E2E case 4 is inline
fixture data.

Exit criteria (all must pass):
1. `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .`
2. New unit tests in `interfaces/cors`, `platform/audit`, `interfaces/sso`;
   new `test/cors_observability_test.go` with the five pinned cases (plus F3's
   404/preflight status pin).
3. `go test ./... -race`; `go test ./test/ -run TestE2E -v`; `make ci`.
4. Greps hit in `docs/observability.md`; drift test green with the CC6.1
   classification; `TestLogin_OriginBlocked_CarriesNoStoreAndIssuer` unchanged.
5. Budget simulation: `metrics.go` ≤ 500 after the field addition (F1);
   `metrics_ctor.go` at 498; `interfaces/sso` file count unchanged at 60;
   `interfaces/cors` stays 242+headroom (< 500).
6. No new `Err*`/endpoint/config knob — `error-codes.md`, `openapi.yaml`,
   `config-reference.md` untouched.

## Verdict

The design is sound in its core mechanism (single observer, single emission
point, three fail-open sinks, budget-aware placement) and its risk analysis of
the CORS boundary is accurate. Two defects must be fixed before
implementation: **F1** (metrics.go 502 > 500 — committed gate failure) and
**F2** (unpinned cross-platform const dependency). **F3** is a factual
narrative error with a cheap test-side fix. The remaining findings are
precision/consistency items. No security or oracle-safety invariants are
affected by this direction: the login-gate 403 response is byte-identical, no
new error surfaces, and no headers change.
