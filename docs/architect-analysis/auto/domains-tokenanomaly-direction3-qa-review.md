# domains/tokenanomaly — 方向 3 设计 QA 评审（risk-based test review）

Review of `docs/auto/domains-tokenanomaly-direction3-design.md` at worktree
HEAD `35dee544` ("Stage: design"). The design is **Stage: design** — no
implementation landed (Verified: no `FamilyID` on `metering.Event`, no
`familyID` parameter on the seam, no `observation.familyID`, no windowed
`spikeForClient`; the design doc itself is untracked under `docs/auto/`).
This review therefore re-verifies every evidence claim against the code,
maps the six decisions and the spec's acceptance checks to existing/required
tests, and measures the baseline the change will build on. All commands
below ran for this revision; no result is inherited from documentation or
from the direction-1 review.

## 0. Design-evidence re-verification (all claims checked against source)

| Design claim | Verified |
|---|---|
| `Event` struct (:45-77) has no `FamilyID`; stores never read it (`memory/token_store.go` `Record` keys only minute/client/kind/endpoint) | Verified |
| Seam declared in six interfaces: `serverdeps.go:157`, `token_refresh.go:30`, `token_authcode.go:38`, `token_ciba.go:29`, `token_device.go:29`, `token_exchange.go:67`; five production calls (`token_refresh.go:206`, `token_authcode.go:232`, `token_ciba.go:252`, `token_device.go:169`, `token_exchange_stages.go:491`) + fake at `token_ciba_test.go:70` | Verified |
| Spec's modify list omits `token_device.go`, `token_exchange.go`, `token_ciba_test.go` → `go build`/`go vet` break without them | Verified (the design's Decision-1 gap claim is correct) |
| `info.FamilyID` in scope at `token_refresh.go:206` (threaded into `IssueRefreshToken` two statements later via `refreshRotateFamily` :224-232) | Verified |
| `recordObservation` runs only when `ev.Thumbprint != ""` (`detector.go:259`) ⇒ issuance events (no thumbprint) never enter the observation table | Verified — Decision 2's gap is real |
| `handle_introspect.go:358` Offer; `info` is the full `*RefreshToken` (`Inspect`), `info.FamilyID` in scope; `:363` `Thumbprint: metering.Thumbprint(info.JTI)` | Verified |
| JTI/FamilyID share the lineage discipline (`oauthspi/refresh_token.go` JTI doc: "propagated UNCHANGED through rotation — the same lineage discipline as FamilyID") | Verified |
| `Finding` (:50-72) has no `FamilyID`; `DedupKey` = type+thumbprint else type+client ⇒ subject-scoped spike would collide with client-scoped key `rate_spike\x00<client>` | Verified — Decision 5's collision is real and its one-per-client resolution is load-bearing |
| `dispatchThreat` (detector.go:138-155) leaves `Threat.FamilyID` unset; `evidenceFor` (:157-175) emits thumbprint/detail/geos/count, no family | Verified |
| `Threat.FamilyID` exists (`threataction.go:31-47`) with no production writer; `RevokeFamilyExecutor.Execute` = `families != nil && FamilyID != ""` → `DeleteFamily`, else subject fallback; no-op Detail `"no family tracker or empty family ID"` | Verified |
| `publishRevoked` keys the bus event by FamilyID on the family path | Verified |
| `mergeFinding` (`memory/store.go:76-90`) starts from `next` (freshest sweep) ⇒ FamilyID rides with the fresher finding like Detail/Count/Geos | Verified |
| `ThreatConditions` is generic over `Evidence` keys (Key/Operator/Value, missing key fails closed) ⇒ `family_id` conditions need no engine change | Verified (`domains/threataction/policy.go:91-104`) |
| Budgets: `server_helpers.go` = 493 lines (edge), `detector.go` = 442, `detect.go` = 155; `defaultMaxThumbprints` = 4096 | Verified |
| Audit event unchanged: `platform/audit/recorder_events.go:35` five-arg `RecordRefreshTokenIssued` | Verified |
| `config.TokenAnomalyConfig` maps every detector knob (`MaxThumbprints/Window/VelocityGap/SpikeFactor/SpikeMinCount`) via `detectorOptions` (`build_governance.go:412-437`) | Verified — see F3 |
| E2E fixtures exist: `MemoryRefreshTokenStore` implements `DeleteFamily` (:197), `Inspect` (:269), `DeleteAllForSubject` (:308); `sso.WithGeoProvider` installs `GeoMiddleware` ahead of all routes; `sso.WithTokenAnomalyDetector` exists | Verified |
| No test wires `WithTokenAnomalyDetector` anywhere; no rate_spike `Detail` assertion exists; no Offer-content assertion exists in `protocols/oauth` tests | Verified — direction-1 F2/F3 gaps persist, see F2/F8 |
| `sso_usage_geo_test.go` calls `s.recordRefreshTokenIssued(...)` twice | Verified — **not in the design's change map**, see F1 |

## 1. Test inventory and commands actually run for this revision

| Command | Result | Notes |
|---|---|---|
| `go build ./... && go vet ./...` | PASS | full module |
| `go test -run 'TestMaintainability_|TestArchitecture_' .` | PASS | budget/architecture gates |
| `go test ./domains/tokenanomaly/... ./domains/threataction/... ./domains/metering/... -race` | PASS | 8 packages |
| `go test ./protocols/oauth/ ./interfaces/sso/... ./infrastructure/defaultimpl/memorystoreoauth/ ./cmd/sso-server/serverbuildplatform/` | PASS | the four packages the design edits around |
| `go test ./internal/handler/tokengrant/ -run 'Refresh' -v` | PASS | **only `refresh_grace` + CIBA tests exist — no `HandleRefreshGrant` unit test anywhere** (see F4) |
| `go test ./test/ -run TestE2E -v` | PASS | 4 `TestE2E_*` tests |
| `make ci` | **FAIL (pre-existing)** | fmt gate: unformatted `infrastructure/defaultimpl/sqlite/refresh_tokens_schema.go` (modified, unrelated in-progress work) and `test/region_token_contract_test.go` (untracked; same file direction-1 F5 flagged, still unfixed). Design changed no `.go` |
| `make config-validate-all modules-check` | PASS | run directly (after the fmt gate blocks the ci chain) |
| `go test -cover` touchpoints | tokenanomaly 87.4%, threataction 74.4%, metering 64.2% | line coverage only; behavioral adequacy argued in §3 |

Worktree note: HEAD `35dee544` is a batch commit touching only
`docs/proposals/design.md`; the direction-3 design doc and its sibling
`docs/auto/` artifacts are untracked. The tree carries many unrelated
uncommitted modifications; all measured results include them.

## 2. Requirement-to-test matrix

Status: **Exists** (green today), **Extend** (existing test must gain an
arg/assert), **Add** (net-new test required), **Blocked** (not testable
in-repo).

| Design decision / spec acceptance | Status | Evidence / required test |
|---|---|---|
| D1 — `Event.FamilyID` field, source-compatible | **Add** | asserted only through seam tests (below); no test constructs `Event` positionally (Verified) |
| D1 — seam signature: 6 decls + 5 calls + CIBA fake | **Extend** | `token_ciba_test.go:70` fake gains `string` param; compile-gated by `go build`/`go vet` |
| D1 — rotation passes `info.FamilyID` | **Add** | **new `token_refresh_test.go`** — no `HandleRefreshGrant` unit test exists today (F4). Assert the Deps ARG `familyID == info.FamilyID` of the consumed token |
| D1 — first-issue `""` (authcode/CIBA/device/exchange) | **Add** | same new file(s); zero-value byte-identity branch |
| D1 — `interfaces/sso` seam (`recordRefreshTokenIssued` +1 param) | **Extend** | `sso_usage_geo_test.go` two call sites gain `""` arg (F1); extend `TestRecordIssuedSeams_*` to assert drained `Event.FamilyID` (geoRecordingStore pattern already exists) |
| D1 — audit event unchanged | **Exists** | `recorder_events_test.go` (5-arg) |
| D2 — introspect Offer gains `FamilyID: info.FamilyID` | **Add** | **no Offer-content assertion exists in `protocols/oauth` today** (Verified) — new test in `handle_introspect_test.go` (F2) |
| D2 — thumbprint↔family 1:1 on the observation row | **Add** | same test asserts `Thumbprint == metering.Thumbprint(jti)` AND `FamilyID == info.FamilyID` |
| D2 — `recordObservation` family guard (non-empty overwrite) | **Add** | detector unit: family-bearing rotation event stamps `o.familyID`; `""` sighting later must not erase it; foreign-family overwrite = last writer (documented best-effort) |
| D3 — `Finding.FamilyID` `omitempty` wire shape | **Extend** | `tokenanomaly_test.go` `TestFindingFields` + a marshal round-trip asserting `family_id` absent when empty |
| D3 — `DedupKey` unchanged | **Exists** | `TestFindingDedupKey`; **Add** the regression pin: subject-scoped spike key == client-scoped key, resolved by one-per-client (F7) |
| D3 — `dispatchThreat` fills `Threat.FamilyID` | **Add** | extend `TestDetector_ThreatExecutorReceivesFindings`-style spy test (family-bearing velocity case) |
| D3 — `evidenceFor` gains `family_id` | **Add** | assert `Evidence["family_id"] == f.FamilyID` and absence for family-less findings (fail-closed condition) — F6 |
| D3 — executor family path reachable, fallback byte-identical | **Exists** | `TestRevokeFamilyExecutor_FamilyIDPresent_UsesFamilyPath` / `_SubjectFallback_WhenFamilyIDEmpty` / `_NoCapabilityWired_NoOp` — unchanged by design |
| D3 — E2E: family revoke precision + bus event keyed by FamilyID | **Add** | `test/` `TestE2E_*` (must match the design's verification command), §4 S1 |
| D4 — no `Bucket` dimension, no migration | **Exists** | store conformance suites + `memory` Record unchanged; optional cheap pin: `Event{FamilyID: "x"}` produces identical bucket keys |
| D4 — subject-table feed from `Record` (`SubjectID != ""`) | **Add** | detector unit: issuance burst (no thumbprint, has subject) lands in the table |
| D4 — `WithMaxTrackedSubjects` cap + oldest-minute eviction + deterministic order | **Add** | unit incl. the empty-subject guard (F5) |
| D4 — sweep-time window pruning | **Add** | unit: minutes older than `now-window` dropped; rows left empty dropped |
| D4 — subject table concurrency | **Extend** | `TestDetector_ConcurrentRecordAndAnalyze` already feeds `SubjectID` via `presentAt` — becomes the race guard once the fold lands; run `-race` |
| D5 — burst at T−2 (subsided before sweep) yields finding | **Add** | windowed-spike unit (the direction's core fix) |
| D5 — flat→spike→flat: exactly one finding, strongest candidate | **Add** | includes the "earliest minute on tie" determinism |
| D5 — brand-new client can't self-trip (≥2 earlier minutes per candidate) | **Add** | design breakage #5 pin |
| D5 — one finding per client per sweep | **Add** | regression pin for the DedupKey collision (F7) |
| D5 — subject spike with flat client baseline | **Add** | `SubjectID` set, `Thumbprint` zero value, `Detail` names the burst minute |
| D5 — latest-minute behavior byte-identical | **Exists** | `TestDetector_RateSpike` (Count==12), `TestDetector_NoSpikeBelowFloor` stay green unchanged |
| D5 — `Detail` wording change | **Exists/Add** | **no test asserts the generated rate_spike Detail** (Verified) — breakage #3's "tests must be updated" is moot; add a fresh assertion on the new wording |
| D6 — zero-value byte-identity (no family ⇒ `""` everywhere, executor fallback) | **Add** | negative branches of the seam tests + executor fallback tests (exist) + `family_id` absent from Evidence/JSON |
| D6 — fail-open untouched | **Exists** | nil-executor no-op, executor-error logged, executor/store panic recovered, recorder drop-on-full — all covered today |
| D6 — import direction | **Exists** | `TestArchitecture_` gate |
| Docs — config-reference threat_action guidance + openapi `family_id` | **Add** | docs-only; config knob gap F3 |

## 3. Findings

### F1 — Medium — change map misses a compile-breaking test site (same gap class as the spec's)

`interfaces/sso/sso_usage_geo_test.go` calls `s.recordRefreshTokenIssued(...)`
twice (`TestRecordIssuedSeams_CarryGeo`, `TestRecordIssuedSeams_NoGeoByteIdentical`).
The seam gains `familyID string` ⇒ the test binary fails `go vet`/`go test`.
The design's Decision-1 table enumerates six interfaces and six handler-layer
sites but not this file. Self-catching at gate time, not a release blocker —
but the design's whole premise is that the spec's file list was incomplete,
and its own list is incomplete in the same way.

- **Exact test update**: add `""` to both call sites; extend both tests to
  assert the drained `Event.FamilyID` (`""` in the byte-identical leg,
  `"fam-x"` in a new family leg) via the existing `geoRecordingStore`.
- **Acceptance assertion**: `TestRecordIssuedSeams_*` green with
  `Event.FamilyID` equality on both branches.

### F2 — Medium — Decision 2's load-bearing edit has no planned test at the protocols/oauth layer

The introspect Offer is the ONLY production path that makes Improvement 2
reachable (Design Decision 2's own argument). The design's test list covers
tokengrant seam args, detector units, and the E2E — but nothing asserts the
`FamilyID` field on the Offer at `handle_introspect.go:358`. Today there is
**no Offer-content assertion anywhere in `protocols/oauth`** (direction-1 F3
gap, still open; `introspectDeps.usageRecorder` is never read). A future
"cleanup" that drops `FamilyID: info.FamilyID` from the Offer would silently
reinstate the permanent no-op with every other test green.

- **Exact test to add** (`handle_introspect_test.go`): wire
  `introspectDeps.usageRecorder` over a `geoRecordingStore`-style capture,
  seed `memRefreshStore` with a `RefreshToken{FamilyID: "fam-x", JTI: "j1"}`
  (`memRefreshStore` already implements `RefreshTokenInspector`), call the
  refresh-introspect path, drain the recorder.
- **Acceptance assertion**: drained
  `Event{Kind: KindRefresh, Endpoint: EndpointIntrospect, Thumbprint: metering.Thumbprint("j1"), FamilyID: "fam-x", SubjectID, ClientID}` —
  full-field equality, not spot checks.

### F3 — Medium — `WithMaxTrackedSubjects` has no config surface

Every other detector knob maps from `config.TokenAnomalyConfig` →
`detectorOptions` (`build_governance.go:412-437`) and is documented at
`config-reference.md:660`. The new cap is code-only: a stock-binary operator
cannot tune it, and the design's docs section omits the row. The spec's
Improvement 3 promised the option, not a key — so this is a decision the
design must make explicitly, not an omission to discover at config-validate
time.

- **Exact change**: either add `token_anomaly.max_tracked_subjects` to
  `TokenAnomalyConfig` + `detectorOptions` + `config-reference.md` (consistent
  with siblings), or state in the design that the cap is default-only.
- **Acceptance assertion**: `make config-validate-all` green with the new key;
  a build-level test (`TestBuildTokenAnomaly_*`) asserting the option reaches
  the detector when set.

### F4 — Medium — the tokengrant seam test is net-new with no precedent, and its named assertion is mislocated

The design says: "unit (`internal/handler/tokengrant`): rotation Event family
== consumed `info.FamilyID`". The `metering.Event` is built two layers up in
`interfaces/sso` (`recordRefreshTokenIssued` → `offerUsage`); the tokengrant
layer can only observe the Deps **argument**. Also, `HandleRefreshGrant` has
zero direct unit coverage today — the package holds only `refresh_grace_test.go`
and `token_ciba_test.go` (Verified), so the design's test is entirely net-new
and must build a fake `RefreshGrantDeps` whose `Consume` returns a known
family.

- **Exact tests to add**:
  1. `internal/handler/tokengrant/token_refresh_test.go` — rotation:
     `fakeDeps.recordedFamily == info.FamilyID`; first-issue paths
     (`authcode`, `device`, `exchange_stages`, `ciba`) record `""`.
  2. `interfaces/sso` (extends F1's update): the drained `Event.FamilyID`
     equals the seam argument — the actual "Event family" assertion.
- **Acceptance assertion**: both layers green; `Event.FamilyID == "fam-x"`
  only at the interfaces/sso assertion, seam arg equality at tokengrant.

### F5 — Low — subject-table feed guard is a named failure mode but not a named test

Design breakage #6: "a bug [in the empty-SubjectID guard] would churn the cap
with junk rows and evict real ones. Cheap to pin in a unit test." The test
list says "cap eviction + deterministic order" — fold the guard into that
test rather than leaving it implicit.

- **Exact test to add**: `WithMaxTrackedSubjects(1)`; record one
  subject-bearing event, then flood `Record` with N events carrying
  `SubjectID == ""`; assert the subject row survives and table size stays 1.
- **Acceptance assertion**: cap eviction touches only subject-bearing rows;
  `TrackedBuckets`-style determinism holds.

### F6 — Low — `evidenceFor`'s `family_id` key unpinned

The design's spy-executor test asserts `Threat.FamilyID` but not the
`Evidence["family_id"]` key that conditional policies match on (the design's
own "policy can scope `revoke` to the lineage" claim). Direction-1 F9 set the
precedent of pinning evidence keys in the mirroring test.

- **Exact test to add**: extend the family-bearing spy test — assert
  `Evidence["family_id"] == f.FamilyID`; extend the family-less spike test
  (exists: `TestDetector_ThreatEvidenceOmitsGeosForSpikes`) with a
  `family_id`-absent assertion, and a `policy_test.go` case:
  `ThreatConditions{Key: "family_id", Operator: "eq", Value: "fam-x"}`
  matches with the key present and fails closed without it.
- **Acceptance assertion**: conditional `revoke` fires only for the named
  lineage.

### F7 — Low — DedupKey collision: the one-per-client rule needs a store-level pin

The design resolves the collision by construction (one finding per client per
sweep), and breakage #4 says "a regression test pins it". The test list's
"one finding per client per sweep" covers the sweep; add the store-level
assertion that a subject-scoped and a client-scoped spike for the same client
across sweeps upsert ONE row (earliest FirstSeen / latest LastSeen preserved
by `mergeFinding`), so a future relaxation cannot silently overwrite.

- **Acceptance assertion**: `Findings().List` returns exactly one
  `rate_spike` row for the client after two sweeps whose winners differ by
  dimension.

### F8 — Info — repeated dispatch within the window is accepted, but the E2E must not assert dispatch counts

With defaults (window 15m / sweep 1m) a burst re-dispatches up to ~15 times
until it leaves the window (design's own arithmetic). The E2E must assert
**idempotent final state** (one finding row, family deleted once, bus event
received) and never "executor called exactly once".

### F9 — Info — pre-existing `make ci` blockers are unrelated to the design

fmt gate fails on `infrastructure/defaultimpl/sqlite/refresh_tokens_schema.go`
(modified, uncommitted) and `test/region_token_contract_test.go` (untracked;
flagged in direction-1 F5, still unfixed). The design changed no `.go`, so
handoff is unaffected, but the ci chain cannot reach vet/race/examples/
proto-lint/route-contract/etc. until those are formatted. Per AGENTS.md I did
not touch them. Also: the new family-revoke E2E must be named `TestE2E_*` or
the design's own verification line (`go test ./test/ -run TestE2E -v`) will
not execute it.

## 4. Prioritized scenario list

P0 = acceptance-blocking for the three improvements; P1 = invariant guards;
P2 = hardening.

**Happy path (P0)**
1. E2E family-revoke precision (`test/`, `TestE2E_*`): two auth-code grants for
   one subject+client mint two families; introspect family-A's refresh token
   from two geos within the velocity gap (stub geo provider, pattern from
   `test/geo_login_test.go`); run the sweep (`go srv.RunTokenAnomalyDetection`
   with a short interval + deadline poll of the admin API); assert one
   `velocity` finding with `FamilyID == A`, `RevokeFamilyExecutor` called
   `DeleteFamily(A)` and **never** `DeleteAllForSubject`, family B's token
   still introspects active, `KindTokenRevoked` bus event keyed by A (F8:
   idempotent-final-state assertions only).
2. Tokengrant seam: rotation arg `familyID == info.FamilyID`; four first-issue
   paths record `""` (F4).
3. `interfaces/sso` seam: drained `Event.FamilyID` == seam arg; both branches
   (F1).
4. `protocols/oauth` introspect Offer: full-Event equality incl.
   `FamilyID == info.FamilyID` and `Thumbprint == metering.Thumbprint(jti)`
   (F2).
5. Detector: family-bearing observation → `geoFinding` carries family →
   `dispatchThreat` sets `Threat.FamilyID` → spy executor records it;
   `Evidence["family_id"]` present (F6).
6. Executor: family path (`DeleteFamily`, no subject call) — exists; fallback
   byte-identical — exists; keep green unchanged.
7. Windowed spike: burst at T−2 (subsided) yields a finding; flat→spike→flat
   yields exactly one (strongest, earliest-minute tie-break); subject spike
   with flat client baseline yields subject-scoped finding (zero-value
   `Thumbprint`); latest-minute case byte-identical to today
   (`TestDetector_RateSpike` unchanged).
8. `Finding.FamilyID` marshal: `family_id` omitted when empty, present
   otherwise (extend `TestFindingFields`).

**Boundary (P0/P1)**
9. One finding per client per sweep + store-level single-row upsert across
   dimension-changing sweeps (F7).
10. Brand-new client cannot self-trip (≥2 earlier minutes per candidate
    minute); below-floor jumps still no-op (`TestDetector_NoSpikeBelowFloor`).
11. Subject-table cap: `WithMaxTrackedSubjects` eviction, deterministic order,
    empty-SubjectID flood does not churn the cap (F5); sweep pruning drops
    out-of-window minutes and empty rows.
12. Zero-value byte-identity matrix: family-less store / legacy rows (empty
    JTI ⇒ no observation ⇒ no family), first-issue findings, client-scoped
    spikes, login-side `anomaly` — all `""` end-to-end, executor falls back.
13. `family_id` conditional policy: `eq` matches with the key, fails closed
    without it (F6).

**Error (P1)**
14. Fail-open unchanged: nil executor, executor error logged, executor/store
    panic recovered, store `Query` error ⇒ no spike findings, recorder
    drop-on-full — all existing tests stay green.
15. Observation mislabeled with a foreign family: read-side last-writer
    behavior pinned by the guard test (documented, never a grant decision).

**Race (P1)**
16. `-race` on all touched packages; `TestDetector_ConcurrentRecordAndAnalyze`
    now exercises the subject fold + prune concurrently (events carry
    `SubjectID`); the fold/prune must share `d.mu` with the observation table.
17. Seam tests with `-race` (recorder drain goroutine): assert via
    `Close()`-drain + `geoRecordingStore.taken()` (existing pattern), never
    sleeps.

**Recovery (P1/P2)**
18. Repeated dispatch while the burst minute is in-window: idempotent
    final-state assertion (F8).
19. Rotation burst (issuance, no thumbprint) composes with the subject
    dimension: subject-scoped finding → subject fallback revoke — assert
    scope is subject-wide by construction (documented, correct).
20. Cross-replica: **do not test in-repo** (per-replica observation tables);
    E2E must stay single-server (direction-1 F2 constraint).

## 5. CI/manual-suite gaps, flake risks, fixtures needed, exit criteria

**CI gaps**
- `make ci` fmt gate blocked by two pre-existing unformatted files (F9).
- No test anywhere wires `WithTokenAnomalyDetector` (direction-1 F2 gap still
  open) — the direction-3 E2E (S1) is the first composition-level proof of
  the whole detection→response chain; it is P0, not optional.
- No Offer-content assertion in `protocols/oauth` (direction-1 F3 gap still
  open) — Decision 2's edit must not land without it (F2).
- No direct `HandleRefreshGrant` unit test exists (F4) — the seam change is
  the first.

**Flake risks**
- The E2E is timing-based (sweep interval + poll). Mitigate: short interval
  (50-100ms), deadline-bounded polling of the admin API (existing `waitFor`
  pattern), assertions on final state only; the velocity gap is real-time
  (ms apart ≪ 5m) so no sleeping. Never assert intermediate sweep counts.
- The subject table's sorted iteration and eviction tie-break must be
  deterministic for tests; pin with sorted-input fixtures.
- Redis/sqlite suites are untouched by this design (no migration, no store
  change) — no new flake surface there.

**Fixtures needed (all exist in-repo; no mocks)**
- `geoRecordingStore` + `newUsageSeamServer` (`interfaces/sso/sso_usage_geo_test.go`) — seam tests.
- `memRefreshStore` + `introspectDeps.usageRecorder` (`protocols/oauth/handler_harness_test.go`) — F2.
- `MemoryRefreshTokenStore` (DeleteFamily/Inspect/DeleteAllForSubject) — executor + E2E.
- `presentAt`/`newDetector`/`recordingThreatExecutor`/`countingLogger` (`domains/tokenanomaly/detector_test.go`) — extend with a `family` param.
- Stub geo provider (`test/geo_login_test.go`) + `clustermemory` bus — E2E.
- A new fake `RefreshGrantDeps` with a family-carrying `Consume` — F4.

**Exit criteria for the design's landing**
1. F1 green: `sso_usage_geo_test.go` updated, both branches assert
   `Event.FamilyID`.
2. F2 green: `handle_introspect_test.go` Offer-assertion test (full-Event
   equality with FamilyID + Thumbprint).
3. F4 green: `token_refresh_test.go` seam-arg assertions (rotation family,
   first-issue `""`); interfaces/sso Event-level assertion.
4. Detector units green: family-bearing observation → finding → threat
   (incl. `Evidence["family_id"]`, F6); windowed-spike matrix; subject table
   (feed, cap, guard F5, pruning, one-per-client F7).
5. E2E green: family revoke precision + survivor token + bus key (S1).
6. Docs landed in the same commit: config-reference threat_action guidance +
   openapi `family_id` + **F3 decision** (config key or documented
   default-only).
7. Gates: `go build ./... && go vet ./...`; `go test -run
   'TestMaintainability_|TestArchitecture_' .`; `-race` on all touched
   packages; `go test ./test/ -run TestE2E -v` (including the new
   `TestE2E_*`, F9); `make ci` green after the pre-existing fmt blockers are
   resolved (F9, with authorization).

**Verdict**: design is sound against the source — all evidence claims
re-verified, including the two gap claims the design itself makes (spec's
incomplete file list; the permanent-no-op without the introspect edit). No
Critical or High findings. The four Mediums (F1–F4) are test-plan and
change-map completeness issues plus one explicit design decision the doc must
make (F3 config key); none requires reworking an API decision. The direction-1
review's two open gaps (no composition test, no protocols/oauth Offer-content
assertion) are exactly where the direction-3 test plan must invest first —
the E2E and the Decision-2 seam test are the two tests that prove the
direction's flagship claim.
