# domains/tokenanomaly — 方向 1 设计 QA 评审（risk-based test review）

Review of `docs/auto/domains-tokenanomaly-direction1-design.md` at revision
`c8ab9768` ("Stage: design"). The implementation has **not** landed
(Verified: no `CountryCodeFromContext`, no `offerUsage`, no `RefreshToken.JTI`
anywhere in non-test Go); this review therefore validates the design's
evidence, maps every spec acceptance check to an existing or required test,
and measures the baseline the change will build on. All commands below ran
for this revision; no result is inherited from documentation.

## 1. Test inventory and commands actually run

| Command | Result | Notes |
|---|---|---|
| `go build ./... && go vet ./...` | PASS | full module |
| `go test -run 'TestMaintainability_|TestArchitecture_' .` | PASS | budget/architecture gates |
| `go test ./domains/tokenanomaly/ ./domains/threataction/ ./domains/metering/ ./platform/geo/ ./cmd/sso-server/serverbuildplatform/` | PASS | 5 touchpoint packages |
| `go test ./protocols/oauth/ ./infrastructure/defaultimpl/memorystoreoauth/ ./infrastructure/defaultimpl/sqlite/ ./infrastructure/redis/ ./internal/handler/tokengrant/` | PASS | redis suite 28.7s (miniredis) |
| `go test -race` on tokenanomaly, threataction, geo, oauth, memorystoreoauth, sqlite | PASS | — |
| `go test ./... -race` | PASS | full repo, zero failures |
| `go test ./test/ -run 'TestE2E' -v` | PASS | 4 `TestE2E_*` tests |
| `make ci` | **FAIL (pre-existing)** | fmt gate: untracked `test/region_token_contract_test.go` unformatted; unrelated in-progress work, not touched |
| `make config-validate-all` | PASS | — |
| `make route-contract` | PASS | 241 runtime routes / 322 documented ops |
| `make capabilities-check` | PASS | 28 capabilities |
| `make sdk-surface-check` | PASS | 13 groups / 316 ops |
| `make modules-check` / `modules-smoke` | PASS | profiles build |
| `go test -cover` touchpoints | tokenanomaly 87.1%, threataction 74.1%, metering 64.2%, platform/geo 98.3%, protocols/oauth 89.1%, sqlite 80.2% | line coverage only; behavioral adequacy argued in §3 |

Existing tests at the touchpoints (all green, all cited from grep of the
current tree):

- **platform/geo**: `context_test.go`, `geo_test.go`, `middleware_test.go` —
  middleware stash/read pair is well covered (98.3%), so the new
  `CountryCodeFromContext` test slots into an established pattern.
- **domains/tokenanomaly**: `detector_test.go` (MultiGeo, Velocity,
  SingleGeoNoFinding, StaleObservationNotReported, RateSpike,
  ThreatExecutorReceivesFindings, NilThreatExecutorIsNoop,
  ThreatExecutorErrorIsLogged, ThreatExecutorPanicIsRecovered,
  ConcurrentRecordAndAnalyze, …), `detector_adversarial_test.go`,
  `admin_test.go`, `tokenanomaly_test.go`.
- **domains/threataction**: `actions_test.go`
  (`RevokeFamilyExecutor_FamilyIDPresent_UsesFamilyPath`,
  `_SubjectFallback_WhenFamilyIDEmpty`, `_NoCapabilityWired_NoOp`),
  `registry_test.go` (`PolicyMatchRoutesToHandler`, `NilPolicyStore`,
  `RateLimit`, `AuditEventRecordedOnNonNoop`, Evidence-bounds tests),
  `policy_test.go` (`ThreatConditions_Match` incl. numeric gt/lt fail-closed),
  `admin_test.go` (policy CRUD), `executor_test.go`.
- **protocols/oauth**: `handle_introspect_test.go` — refresh-token-via-
  inspector body tests ("refresh token via inspector with hint" at :254,
  DPoP-bound refresh at :774), oracle-safety, no-store/credential-header
  tests. **No test asserts Offer Event contents anywhere in the package**
  (the harness's `usageRecorder` field is never read).
- **infrastructure**: memorystoreoauth expiry/generation tests; sqlite
  `migration_test.go` (`TestMigration_RefreshTokensBackfillsLegacyColumns`
  **pins `version == 7`**, see F1), generation/family-created-at/expiry/
  grace/purge tests; redis rotation/reuse/grace tests on miniredis.
- **cmd/sso-server/serverbuildplatform**: `build_governance_test.go`
  (`TestBuildTokenAnomaly_EnabledCoWiresRecorderAndDetector`,
  `TestBuildThreatAction_EnabledSeedsPoliciesAndDispatches` — exercises
  `impossible_travel`, **no geo type**).
- **test/** (package ssotest): `geo_login_test.go` — E2E geo middleware +
  audit enrichment with stub providers (the pattern a geo E2E would reuse);
  4 `TestE2E_*` wire tests. **No test wires `WithTokenAnomalyDetector`**
  (grep across `*_test.go` is empty) and none wires token_anomaly +
  threat_action together.

## 2. Requirement-to-test matrix

Status labels: **Exists** (green today), **Extend** (existing test must gain
an assertion), **Add** (net-new test required by the design), **Blocked**
(cannot be tested in-repo).

| Spec acceptance check | Status | Evidence / required test |
|---|---|---|
| Imp 1 — extractor unit: country code from stubbed context, `""` without | **Add** | `platform/geo` new test beside `middleware_test.go`; both branches |
| Imp 1 — five seam tests: stubbed geo ⇒ `GeoCountry` == stubbed code; no geo ⇒ byte-identical Event | **Add** | **No Offer-content assertion exists in the repo today** (Verified: `usageRecorder` in `handle_introspect_test.go:34/64` never asserted; tokengrant tests assert nothing on usage). Three `interfaces/sso` seams need a recorder harness; two `protocols/oauth` seams need `introspectDeps`-level assertion. Both branches required (F3) |
| Imp 1 — pipeline: two Events, one thumbprint, two countries ⇒ `multi_geo` warn / `velocity` critical via `Findings().List` | **Exists** | `TestDetector_MultiGeo` (detector_test.go:54), `TestDetector_Velocity` (:294) — feed the detector via `Record` exactly as the seams will, `At`-stamped |
| Imp 1 — zero-value byte-identity (no provider / lookup miss / bad IP ⇒ `""`) | **Add** | negative branch of the five seam tests; middleware no-op path already covered by `platform/geo/middleware_test.go` |
| Imp 2 — store round-trip JTI via Issue→Inspect on memory/redis/sqlite | **Add** | no conformance suite exists; extend `memory_refresh_token_expiry_test.go` / `redis/refresh_token_test.go` / `sqlite/refresh_tokens_generation_test.go` patterns. (Design's "postgres peer" does not exist — F4) |
| Imp 2 — rotation propagates JTI unchanged | **Add** | extend `refresh_token_rotation_test.go` (redis) / sqlite rotation test: Issue → Consume → Inspect new leaf, assert `JTI` equal; pin thumbprint continuity across the chain |
| Imp 2 — seam: refresh introspect ⇒ `Thumbprint == metering.Thumbprint(jti)` + geo | **Add** | in `handle_introspect_test.go` with `introspectDeps.usageRecorder` wired; `memRefreshStore` harness already implements `RefreshTokenInspector` (handler_harness_test.go:258) |
| Imp 2 — pipeline: two introspect Events, same refresh token, two countries ⇒ `velocity` | **Add** | detector-level: `presentAt` already uses `EndpointIntrospect`; add a variant carrying `Thumbprint(metering.Thumbprint(jti))`-style continuity assertion or reuse `TestDetector_Velocity` shape with EndpointIntrospect |
| Imp 2 — oracle-safety regression: unknown/expired ⇒ `{"active":false}`, no-store | **Exists** | `TestHandleIntrospect` refresh subtests + credential-endpoint header tests; must stay green — the Offer is fire-and-forget and must not change bodies |
| Imp 2 — migration v8: fresh DB skips add, pre-v8 backfills, legacy row `''` | **Extend** | `TestMigration_RefreshTokensBackfillsLegacyColumns` — **must bump the `want 7` pin (F1)** and add `jti` to the backfill SELECT + a legacy-row `jti == ''` assert |
| Imp 3 — dispatch Evidence carries `geos`/`count` for both geo types | **Extend** | `TestDetector_ThreatExecutorReceivesFindings` (detector_test.go:113) currently asserts only `token_thumbprint`; add `Evidence["geos"] == "AU,US"`-style sorted-join assert + `count` |
| Imp 3 — nil executor stays no-op | **Exists** | `TestDetector_NilThreatExecutorIsNoop` |
| Imp 3 — policy conditional `geos exists` matches only when present | **Extend** | `TestThreatConditions_Match` (policy_test.go:428) covers operators incl. numeric fail-closed; add the `exists`-on-`geos` case + empty-Evidence no-match case |
| Imp 3 — composition: policy `type: velocity` → `ActionRevoke` executes, audit `threat.type=velocity` | **Extend** | `TestBuildThreatAction_EnabledSeedsPoliciesAndDispatches` (build_governance_test.go:491) — currently `impossible_travel`/`notify`; new case needs `velocity`/`revoke` **with a wired SubjectRevoker** (fixture exists: `MemoryRefreshTokenStore.DeleteAllForSubject`, memory_refresh_token.go:307; nil deps ⇒ `OK:false`, so the "OK:true via subject fallback" assertion requires the fixture) |
| Imp 3 — cross-server E2E (spec offers "or an E2E test") | **Gap — recommended** | contract tests satisfy the letter of the spec; see F2 |

## 3. Findings

### F1 — Medium — v8 migration breaks a pinned test the design's change map omits

`infrastructure/defaultimpl/sqlite/migration_test.go:74-78`
(`TestMigration_RefreshTokensBackfillsLegacyColumns`) asserts
`v != 7 → "version = %d, want 7"`, and its comment enumerates "the v3 …
v7" columns. The design verified `maxversions_test.go` (correctly: it pins
only positivity) but **missed this exact pin**, and the file-change map
does not list `migration_test.go`. The v8 `addRefreshTokenJTI` lands on the
same precedent the v7 migration used, and v7's own commit
(`d3c0f4be`) bumped this very pin.

- **Impact**: the same commit that adds v8 fails `go test
  ./infrastructure/defaultimpl/sqlite/` until the pin moves — self-catching,
  so not High; but the incomplete change map means the failure is discovered
  at gate time, not planned.
- **Exact test update**: in the same commit, `want 7` → `want 8`, extend the
  backfill `SELECT` with `jti`, add `SELECT jti FROM refresh_tokens WHERE
  token='old'` → `''` (legacy-row degradation asserted, not just compiles).
- **Acceptance assertion**: `TestMigration_RefreshTokensBackfillsLegacyColumns`
  green with `version == 8`; fresh-DB path (`ensureRefreshTokenSchema`
  baseline DDL carries `jti`) covered by the store's own round-trip test.

### F2 — Medium — no composition or E2E coverage of the flagship chain

No test in the repo wires `WithTokenAnomalyDetector` on a `Server` (grep of
`*_test.go` empty), and none wires token_anomaly + threat_action together.
`TestBuildThreatAction_EnabledSeedsPoliciesAndDispatches` exercises
`impossible_travel` (the `anomaly` domain), not a geo type; the detector and
executor are each unit-covered in isolation. The spec's Improvement 3
acceptance says "or an E2E test", so Decision 8's contract tests satisfy the
letter — but the direction's flagship promise (two-country token usage on a
real server → `velocity` finding → `revoke` action) has zero proof at the
composition layer, and the design adds none.

- **Exact test to add**: `test/token_anomaly_geo_test.go` (package ssotest),
  reusing the stub-provider fixture pattern of `test/geo_login_test.go`
  (IP→country mapping): build `sso.NewServer` with `WithGeoProvider`,
  `WithTokenAnomalyDetector`, `WithThreatExecutor` (recording executor or a
  `BuildThreatAction`-built one with a `velocity` policy + memory subject
  revoker); present the same refresh token from two countries within
  `velocity_gap` via `/token/introspect`; run the sweep.
- **Acceptance assertion**: `GET /api/v1/admin/tokens/suspicious` returns
  exactly one `velocity` finding with `Geos == ["CN","US"]` and
  `Count == 2`; the recording executor received
  `Threat{Type: "velocity", Evidence["geos"] == "CN,US", Evidence["count"] == "2"}`.
- **Constraint**: single-server harness only — cross-replica observation
  tables never combine (design risk 9); a two-replica variant would be a
  guaranteed flake and must not be written.

### F3 — Medium — the fail-open `ctx` drift guard depends on seam tests that do not exist yet

Design risk 3 ("a future caller forgets `ctx` … silently emits `GeoCountry
== ""`") is mitigated by "the seam test in Improvement 1 pins both branches".
But **no Offer-content assertion exists anywhere today** (Verified: the
`usageRecorder` field in `handle_introspect_test.go:34` is never read; no
tokengrant test asserts usage; `metering` tests assert recorder internals,
not seam output). The mitigation is entirely net-new, so the design must be
explicit that both branches are asserted per seam.

- **Exact tests to add** (five, one per seam; two packages):
  - `interfaces/sso`: recorder-harness test for `recordTokenIssued` /
    `recordRefreshTokenIssued` / `recordIDTokenIssued` — context with
    stashed `*geo.GeoInfo{CountryCode: "US"}` ⇒ Event equality on the full
    struct (not just one field) with `GeoCountry == "US"`; bare context ⇒
    full-struct equality with `GeoCountry == ""` (byte-identical to today).
  - `protocols/oauth`: same two branches for `recordIntrospectionUsage` and
    `introspectRefresh`, plus `Thumbprint == metering.Thumbprint(jti)`.
- **Acceptance assertion**: full `metering.Event` equality, not field-spot-
  checks — that is what "byte-identical" means and what prevents the two
  layers from drifting apart (Decision 1's load-bearing property).
- **Read-back path**: `metering.Recorder.UsageStore()` (token_recorder.go:130)
  plus a real `Memory*` store, per repo convention (no mocks).

### F4 — Low — "postgres peers" in the design's Verification does not exist

Verified: `infrastructure/postgres/` contains no `RefreshTokenStore`
(grep empty); refresh stores are memory / redis / sqlite only. The
Verification line "round-trips JTI on memory/redis/postgres peers" and the
word "conformance" (there is no refresh-store conformance suite; round-trips
live in per-store test files) overstate the surface. Correction: three peers,
sqlite is the only columnar one and the migration carrier. No code impact.

### F5 — Low — pre-existing CI blocker in this worktree (not caused by the design)

`make ci` fails at the fmt gate: untracked, unformatted
`test/region_token_contract_test.go` (unrelated in-progress work; git status
`??`). Per AGENTS.md I did not modify it. Any handoff commit from this
worktree hits this until that file is gofmt'd; report it separately from the
design work.

### F6 — Info — JTI-stamping failure path is not failure-injectable

`GenerateAuthCodeBytes` is a package function with no injection seam, so the
"JTI stamp fails ⇒ issue fails loud" row of the failure-mode table is not
directly testable — but the identical `FamilyID` branch (auth_code_handler.go
:238-244) has the same property today and its error wrap is exercised by
`TestGenerateAuthCodeBytes` (auth_code_handler_test.go:113) at the generator
level. Acceptable; do not add DI machinery for it.

### F7 — Info — `json:"jti,omitempty"` is the only tagged field on `RefreshToken`

Sibling fields marshal under Go default names (`FamilyID`), so the blob key
`jti` is stylistically inconsistent. Wire analysis holds either way
(Verified against `encoding/json` semantics: unknown keys ignored on read by
old binaries, missing key → `""` for new binaries). Cosmetic; keep the tag
for the `omitempty` intent or drop it — do not mix.

### F8 — Info — `Finding.Count` semantics are type-dependent (design risk 5, confirmed)

`Finding.Count` is `o.count` (sightings) for geo findings but latest-minute
count for `rate_spike` (Verified: tokenanomaly.go:94-97, detect.go
`geoFinding`). Existing `TestThreatConditions_Match` already pins the
numeric fail-closed behavior; new conditional tests must scope to
`velocity|multi_geo` only, and the config-reference wording must say so
(Decision 9 covers this — keep it).

### F9 — Info — evidence-pin hygiene

The design's dispatch contract test asserts `Evidence["geos"] == "CN,US"`,
which pins the sorted comma-join (design risk 6). Good. Add the same
assertion to the existing `TestDetector_ThreatExecutorReceivesFindings` via
a second velocity case so the pin lives with the test that already guards
Finding→Threat mirroring, rather than only in a new test.

## 4. Prioritized scenario list

Priority P0 = acceptance-blocking for the three improvements; P1 = guards
the invariants in AGENTS.md §3; P2 = nice-to-have.

**Happy path (P0)**
1. Extractor: stashed `*GeoInfo` → `"US"`; none → `""` (both branches).
2. Five seams: stubbed geo → full-Event equality with `GeoCountry`; bare
   context → full-Event equality with `""` (F3).
3. Refresh-introspect Offer: `Thumbprint == metering.Thumbprint(jti)` + geo.
4. JTI round-trip Issue→Inspect on memory/redis/sqlite; rotation keeps JTI
   (chain thumbprint continuity).
5. Dispatch Evidence `geos`/`count` for `multi_geo` and `velocity`.
6. Composition: `velocity` policy → `ActionRevoke` OK:true via subject
   fallback, audit `threat.type=velocity` (F2 fixture: memory subject
   revoker).
7. Existing pipeline tests stay green (TestDetector_MultiGeo/Velocity) —
   they are the Imp-1 pipeline acceptance and prove no detection drift.

**Boundary (P0/P1)**
8. Migration v8: fresh DB (skip add) + pre-v8 DB (backfill `''`) + legacy
   row reads `jti == ''` (F1).
9. Zero-value byte-identity matrix: no provider, nil provider, lookup miss,
   unknown IP — all `""` at all five seams.
10. Old redis blob (no `jti`) → `""`; old-binary-reads-new-blob is
    untestable in-repo (single binary) — assert the one-way case.
11. Sorted `geos` comma-join stable for `eq`; `count gt` numeric; `geos`
    with `gt` → fail-closed no-match (extends TestThreatConditions_Match).
12. Empty Evidence + `exists` condition → default/noop.
13. Single-geo and stale observations produce nothing (exists; keep).

**Error (P1)**
14. Introspection oracle safety on the refresh path: unknown/expired ⇒
    `{"active":false}`, no-store headers (exists; must stay green).
15. Executor error logged, panic recovered, policy-store outage →
    defaultPolicy/noop (exists: TestDetector_* + TestThreatExecutors_*).
16. Recorder drop-on-full (exists in metering) — new seams must not add
    request-path latency; no new test beyond seam-level Offer.
17. JTI-stamp generator failure → issue fails loud (F6: not injectable;
    covered at generator level; document).

**Race (P1)**
18. `go test -race` on all touched packages; `TestDetector_
    ConcurrentRecordAndAnalyze` stays green.
19. Seam tests run with `-race`: Offer is async (drain goroutine); assert
    via `UsageStore()` polling (pattern: `waitFor` in token_recorder_test).
20. Rotation + introspect concurrency: JTI is immutable once stamped —
    assert no new shared state in the rotation path; existing redis/sqlite
    rotation tests with `-race` are the guard.

**Recovery (P1/P2)**
21. Mid-rollout rotation on pre-JTI binary: leaf `JTI == ""` ⇒
    `Thumbprint == ""` ⇒ no observation — assert via store round-trip with
    empty JTI (behavioral, in-repo testable).
22. Migration failure boots loud via `migrate.CheckSchema` (existing
    contract; v8 follows it — no new test beyond the migration test).
23. Cross-replica: **do not test in-repo** (per-replica observation tables);
    E2E must be single-server (F2 constraint).

## 5. CI/manual-suite gaps, flake risks, fixtures, exit criteria

**CI gaps**
- `make ci` blocked at fmt by untracked `test/region_token_contract_test.go`
  (F5, pre-existing). Design handoff requires it gofmt'd first or reported
  separately.
- No `TestE2E` for the token-anomaly chain (F2). Spec-compliant without it
  ("or an E2E test"), but the composition layer is otherwise unproven for
  geo types; recommend adding the single-server E2E in the Imp-3 commit.
- No Offer-content assertions anywhere (F3) — the design's own drift
  mitigation depends on them; treat the five seam tests as P0, not optional.

**Flake risks**
- Redis suite takes ~29s and is miniredis-backed — the new JTI round-trip
  must not add timers or sleeps; follow existing `waitFor`/`FastForward`
  patterns.
- The sqlite migration test is `t.Parallel()` with per-test temp DBs —
  extend the existing test rather than adding a second one that touches the
  same `refresh_tokens` table namespace.
- Any E2E that crosses replicas or relies on wall-clock velocity gaps is a
  guaranteed flake; single server, stub provider, `At`-controlled (the
  detector pipeline tests use `At`-stamped Events — mirror that, don't sleep).

**Fixtures needed (all exist in-repo, none need mocks)**
- `platform/geo`: stashed `*GeoInfo` via `HandlerContext.Set` (pattern in
  `middleware_test.go`).
- `protocols/oauth`: `introspectDeps.usageRecorder` + `memRefreshStore`
  (handler_harness_test.go:258 implements `RefreshTokenInspector`).
- `domains/tokenanomaly`: `presentAt`/`newDetector` helpers + recording
  executor (detector_test.go).
- `cmd/sso-server/serverbuildplatform`: `BuildThreatAction` + real
  `MemoryRefreshTokenStore` as SubjectRevoker (memory_refresh_token.go:307)
  for the OK:true revoke assertion.
- `test/`: stub geo provider from `test/geo_login_test.go`.

**Exit criteria for the design's landing**
1. All five seam tests green with full-Event equality on both geo branches
   (F3) — `go test ./protocols/oauth/ ./interfaces/sso/...`.
2. `TestMigration_RefreshTokensBackfillsLegacyColumns` green with
   `version == 8` + legacy `jti == ''` (F1).
3. JTI round-trip + rotation-continuity green on memory/redis/sqlite with
   `-race`.
4. Decision-8 contract tests green: Evidence `geos`/`count`; `exists`
   conditional; `velocity`→revoke with audit meta; nil-executor no-op
   unchanged.
5. Optional-but-recommended: single-server token-anomaly geo E2E (F2).
6. Docs landed in the same commit (feature-matrix + config-reference,
   including the `count`-is-per-type warning — F8).
7. `go build ./... && go vet ./...`; `go test -run
   'TestMaintainability_|TestArchitecture_' .`; `go test ./... -race`;
   `go test ./test/ -run TestE2E -v`; `make ci` — the last green only after
   the pre-existing fmt blocker (F5) is resolved or excluded with
   authorization.

**Verdict**: design is sound against the source (all nine evidence claims
re-verified; two corrections: F1 migration-test pin and F4 postgres-peer
wording). No High/Critical findings. The three Mediums (F1–F3) are all
test-plan completeness issues the design can absorb without changing any
API decision — no design rework required. Landing order per spec
(single commit per improvement) holds; the seam tests (F3) must land in the
Imp-1 commit, not deferred, because Decision 8's contract tests depend on
the same harness patterns.
