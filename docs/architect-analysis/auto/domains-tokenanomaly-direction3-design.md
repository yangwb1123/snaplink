# domains/tokenanomaly — Direction 3 design: FamilyID through the detection→response chain; windowed rate_spike

Scope: implementation design for `domains-tokenanomaly-direction3-spec.md` (three
improvements: FamilyID into token telemetry, FamilyID through Finding→Threat→revoke,
windowed + subject-dimensioned rate_spike). This document fixes the API surface,
storage model, and failure modes, and — critically — closes two gaps found while
verifying the spec against the code:

1. The spec's modify list omits `internal/handler/tokengrant/token_device.go`,
   `token_exchange.go` (interface declarations) and `token_ciba_test.go` (fake).
   The seam signature change breaks `go build` / `go vet` without them.
2. The spec's modify list omits `protocols/oauth/handle_introspect.go` — and
   without a one-line telemetry addition there, **Improvement 2 is unreachable in
   production** (the exact permanent-no-op the spec claims to fix). See
   [Decision 2](#decision-2-production-reachability-the-refresh-introspect-offer-must-carry-familyid).

Every decision below preserves the spec's non-negotiables: opaque non-PII family
id, zero-value byte-identity, fail-open hot paths, no new `Bucket` dimension, no
upward import, and the file budgets.

## Decision 1: API surface — `metering.Event.FamilyID` and the full `RecordRefreshTokenIssued` seam change

**Surface.** `metering.Event` gains one field (`domains/metering/token_usage.go`,
Event struct at :45-77):

```go
// FamilyID is the opaque refresh-token lineage id (see oauthspi.RefreshToken).
// Empty = unknown (first issue, or a store that does not track families).
// Not PII; the per-token thumbprint is 1:1 with the lineage because both JTI
// and FamilyID propagate unchanged through rotation.
FamilyID string
```

Source-compatible: `Event` is never marshaled to a wire format (only
`Bucket`/`Finding` are), stores never read the field, and no test constructs it
positionally. No proto, no store change, no migration.

**Seam signature.** `RecordRefreshTokenIssued` gains one parameter,
`familyID string`, in **every** declaration and call site — the spec names only
`serverdeps.go:157`, but the method is declared in six interfaces and called at
six sites:

| Location | Kind | Change |
|---|---|---|
| `internal/handler/serverdeps.go:157` | Deps interface decl | +`familyID string` |
| `internal/handler/tokengrant/token_refresh.go:30` | `RefreshGrantDeps` decl | +`familyID string` |
| `internal/handler/tokengrant/token_authcode.go:38` | `AuthCodeGrantDeps` decl | +`familyID string` |
| `internal/handler/tokengrant/token_ciba.go:29` | `CIBAGrantDeps` decl | +`familyID string` |
| `internal/handler/tokengrant/token_device.go:29` | `DeviceGrantDeps` decl | +`familyID string` — **missing from spec** |
| `internal/handler/tokengrant/token_exchange.go:67` | `ExchangeGrantDeps` decl | +`familyID string` — **missing from spec** |
| `internal/handler/tokengrant/token_refresh.go:206` | rotation call | `info.FamilyID` |
| `internal/handler/tokengrant/token_authcode.go:232` | first issue | `""` |
| `internal/handler/tokengrant/token_ciba.go:252` | first issue | `""` |
| `internal/handler/tokengrant/token_device.go:169` | first issue (device flow) | `""` — **missing from spec** |
| `internal/handler/tokengrant/token_exchange_stages.go:491` | first issue | `""` |
| `internal/handler/tokengrant/token_ciba_test.go:70` | fake Deps impl | +`string` param — **missing from spec** |
| `interfaces/sso/accessors_handlers.go:336,457` | adapter (`Server.RecordRefreshTokenIssued`) | thread param |
| `interfaces/sso/server_helpers.go:439` | `recordRefreshTokenIssued` impl | thread param |

The rotation call passes `info.FamilyID` (in scope at :206, two statements before
`refreshRotateFamily` threads it into `IssueRefreshToken` at :232). All first-issue
paths pass `""` — a new family is minted inside the store during issuance, so there
is nothing to pass and behavior is byte-identical.

**Audit event unchanged.** `audit.RecordRefreshTokenIssued` (`platform/audit/recorder_events.go:35`)
keeps its five-argument signature — the SIEM-facing `refresh_token_issued` event
does not grow a family. Family already reaches audit through
`RecordRefreshTokenReuse` and `RecordRefreshRotationVelocityExceeded`
(`server_helpers.go:477-487`), which are unchanged. Only the metering `Event`
gains the field.

**Budget.** `server_helpers.go` is at 493 lines; the change is one parameter plus
a doc line, staying under 500. If the edit drifts over, move
`recordRefreshTokenIssued` to a new `interfaces/sso/server_usage_family.go` first
(the spec's escape hatch).

## Decision 2: Production reachability — the refresh-introspect Offer must carry FamilyID

**The problem the spec leaves implicit.** The detector's `observation` table is
keyed by thumbprint, and `recordObservation` runs only when `ev.Thumbprint != ""`
(`detector.go:254-260`). Issuance events — the only events the new seam
parameter feeds — carry **no thumbprint**: the jti is minted inside the
`TokenIssuer` and the handler only holds the opaque token string, so
`recordRefreshTokenIssued`'s `Event` (no `Thumbprint`) can never enter the
observation table. Without a thumbprint-bearing event that also carries a
family, `Finding.FamilyID` (Improvement 2) would stay `""` for every production
finding, and the family-scoped revoke would remain a permanent no-op — the exact
bug the direction claims to fix.

**The seam that closes it.** `protocols/oauth/handle_introspect.go:358` offers a
refresh-token introspection event with `Thumbprint: metering.Thumbprint(info.JTI)`
where `info` is the full `oauthspi.RefreshToken` record — **`info.FamilyID` is in
scope at that line**. `RefreshToken.JTI` and `FamilyID` share the same lineage
discipline (both propagate unchanged through rotation; see
`oauthspi/refresh_token.go` JTI doc: "giving a rotation chain one stable
thumbprint"), so the refresh-introspect event is thumbprint↔family 1:1 — the
observation row for a lineage learns the lineage's family the first time a
refresh token of that family is introspected.

**Decision.** Add one field to that Offer:

```go
d.TokenUsageRecorder().Offer(metering.Event{
    Kind:       metering.KindRefresh,
    Endpoint:   metering.EndpointIntrospect,
    ClientID:   info.ClientID,
    SubjectID:  info.UserID,
    Thumbprint: metering.Thumbprint(info.JTI),
    FamilyID:   info.FamilyID, // NEW — telemetry only
    GeoCountry: geo.CountryCodeFromContext(ctx),
})
```

This is a **telemetry-only** edit inside `protocols/oauth`: no grant decision,
no introspection response byte, no store API changes — consistent with the
spec's do-not-modify rationale ("no grant/introspect wire behavior changes"),
which governs wire contracts, not an `Offer` payload. The spec's import-direction
invariant still holds: the family reaches the detector through the recorder, and
`domains/tokenanomaly` / `domains/threataction` never import `protocols/oauth`.

**Consequence for the signal chain.** In production, family-bearing observations
arise from refresh-token introspection (a stolen refresh token being probed or
replayed is exactly when an operator wants the family-scoped revoke). The
rotation-burst path (attacker rotates a stolen token at `/token`) produces
issuance events — no thumbprint — and is caught by the subject dimension of
Improvement 3 instead (issuance events do carry `SubjectID`), which composes
with the family path: per-token geo/velocity finding → family revoke;
per-subject rotation burst → subject-scoped finding → subject fallback revoke
(see Decision 5 for why the fallback is the *correct* scope there).

**Alternative considered and rejected.** Stamping a thumbprint on issuance
events would require the issuance seams to learn the minted jti — a change to
`oauthspi` issuer/store contracts and a new token-return shape; disproportionate
for a telemetry field, and it would duplicate what `RefreshToken.JTI` already
exists for.

## Decision 3: API surface — `Finding.FamilyID` → `Threat.FamilyID` → reachable `revoke_family`

**Finding.** `Finding` gains `FamilyID string \`json:"family_id,omitempty"\``
(`tokenanomaly.go:50-72`). It is governance data only (opaque lineage id, not
PII; `SubjectID` remains the single PII field) and marshal-omits when empty, so
the admin wire shape is unchanged for every family-less finding. `DedupKey` is
unchanged: per-token findings key on type+thumbprint, and thumbprint is 1:1 with
the lineage (Decision 2), so the family can never vary under one key.

**Writers.** `geoFinding` (`detect.go:38-66`) copies `o.familyID` when non-empty
(never overwrites with `""`). `spikeForClient` leaves it `""` — rate spikes are
client/subject-scoped, never token-scoped, and the subject table has no family
dimension (bounded cardinality, see Decision 4). The memory `FindingStore`
merge (`memory/store.go` `mergeFinding`) needs no change: `FamilyID` rides with
the fresher finding exactly like `Detail`/`Count`/`Geos`.

**Threat.** `threataction.Threat.FamilyID` already exists (`threataction.go:31-47`)
with no production writer; `dispatchThreat` (`detector.go:138-155`) sets
`threat.FamilyID = f.FamilyID`. `evidenceFor` (`detector.go:157-175`) adds
`"family_id"` to the evidence map when non-empty, so a conditional policy
(`conditions` on `family_id`) can scope `revoke` to the lineage; absent key =
condition fails closed, byte-identical to today.

**Executor.** `RevokeFamilyExecutor.Execute` (`domains/threataction/actions.go`)
is **not modified**. Its existing branch — `families != nil && threat.FamilyID != ""`
→ `DeleteFamily`; else `DeleteAllForSubject` — becomes reachable from the
tokenanomaly source. Family-less threats (`rate_spike`, first-issue findings,
login-side `anomaly` signals) keep the subject fallback byte-identical, and the
`KindTokenRevoked` bus event is keyed by FamilyID on the family path (already
implemented in `publishRevoked`).

**Docs.** `docs/config-reference.md` threat_action section gains the statement
that token findings with a known family revoke only that family, with the
subject-scoped fallback reserved for family-less threats. `docs/openapi.yaml`
`/api/v1/admin/tokens/suspicious` finding schema gains
`family_id: { type: string }` (optional).

## Decision 4: Storage model — no new bucket dimension; detector-local capped subject table

**Bucket stays untouched.** `metering.Bucket` gains no subject/token/family
dimension — the bounded-store and privacy stance of `token_usage.go`. `Event.FamilyID`
is simply never read by the memory or sqlite stores; the memory store's
`Record` (`domains/metering/memory/token_store.go:69`) keys buckets on
(minute, client, kind, endpoint) and ignores the new field. Store conformance
suites and `TrackedBuckets` are unchanged, and there is no migration.

**Subject-rate table lives in the Detector.** New detector-owned state in
`domains/tokenanomaly/detect.go` (155 lines today; ~345 of headroom — the
spec's placement constraint, keeping `detector.go` at 442 away from the 500-line
budget):

```go
// subjectMinuteRates is the detector's own per-(subject, client) per-minute
// issuance/usage counts, folded from raw Record events (which carry
// SubjectID even though Bucket does not). Bounded: cap on tracked
// (subject, client) rows, minutes pruned outside the analysis window.
type subjectMinuteRates map[subjectClientKey]map[int64]int64
```

- **Feed**: `Detector.Record` (`detector.go`) folds every event with
  `SubjectID != ""` into the table — thumbprint irrelevant, so the
  refresh-rotation issuance burst (no thumbprint, has subject) is captured.
  The fold mirrors `foldClientMinuteRates`'s semantics: all kinds/endpoints
  summed per minute (uniform signal definition; the adaptive per-row baseline
  absorbs volume, exactly as it does for the client table today). The fold is
  in-memory and can never fail `Record`.
- **Cap**: `WithMaxTrackedSubjects(n)` option, default
  `defaultMaxThumbprints` (4096), mirroring the observation-table discipline.
  At cap, evict the row whose most-recent minute is oldest (deterministic
  tie-break: insertion order).
- **Pruning**: at each `Analyze` sweep, drop minutes older than
  `now - window` and drop rows left empty — per-row memory is bounded by the
  window (≤ 16 minutes at defaults), total by cap × window. Without pruning a
  long-lived (subject, client) pair would accumulate unbounded minute history.
- **Iteration**: sorted (subject, client) key order for deterministic sweep
  output, mirroring `detectRateSpike`'s sorted client order.

`FindingStore` is unchanged: bounded, dedup-by-key, upsert merge.

## Decision 5: rate_spike — windowed scan, strongest-candidate-per-client, subject dimension

**Windowed test.** Replace the latest-minute-only test (`spikeForClient`,
`detect.go:100-136`) with a scan over every minute `m` in the query window:

- candidate iff `count[m] ≥ spikeMinCount` **and** `count[m] > spikeFactor ×
  mean(counts of minutes strictly before m within the window)` **and** there
  are ≥ 2 minutes strictly before `m` in the window.
- The prefix baseline means the latest minute's test is **exactly** today's
  test (mean of all earlier minutes, ≥ 2 required ⇒ `len ≥ 3`), so the
  per-client family-less behavior is byte-identical when the latest minute is
  the strongest candidate.
- A burst at minute T−2 that already subsided is now evaluated — the fix for
  "burst before the current partial minute / before the sweep".

**One finding per client per sweep.** Candidate pool = the client-wide winner
plus every subject-scoped winner for that client; emit the single strongest
(highest `count/baseline` ratio; earliest minute on tie). This keeps the
finding store bounded and — decisively — **preserves `DedupKey` semantics**:
a subject-scoped finding has `Thumbprint == ""`, so its base id would be
`ClientID`, colliding with the client-scoped key
(`"rate_spike\x00<client>"`). The one-per-client rule resolves the collision by
construction: the winning candidate's `SubjectID`/`Count`/`Detail` define the
row; a later sweep in which the other dimension wins simply upserts the same
key (the store's `mergeFinding` keeps earliest `FirstSeen`, latest `LastSeen`,
escalating severity — no code change). Two subjects spiking in one client in
one sweep: only the strongest emits; the other surfaces on a later sweep.

**Finding shape.** Subject-scoped winner: `SubjectID` set, `Thumbprint` zero
value (unchanged wire shape), `Detail` names the subject-scoped burst minute,
`FirstSeen`/`LastSeen` bound the burst minute. `Detail` wording changes for
**all** rate_spike findings (names the burst minute rather than "latest-minute")
— a deliberate, documented surface change; nothing matches on `Detail`.

## Decision 6: Zero-value byte-identity, fail-open, import direction

- No family anywhere (first issue, family-less store, client-scoped spike,
  login-side `anomaly`) ⇒ `Event.FamilyID`/`Finding.FamilyID`/`Threat.FamilyID`
  all `""`, `family_id` omitted from JSON and absent from `Evidence`, executor
  falls back to `DeleteAllForSubject` — byte-identical to today.
- Fail-open untouched: `Offer` stays drop-on-full; `Record`'s subject fold
  cannot fail; `detectRateSpike` still returns no findings on store error;
  `dispatchThreat` still logs executor errors without blocking the sweep;
  no change alters a grant/introspect decision or wire response.
- Import direction: the family reaches the detector through the existing
  `internal/handler` Deps → `interfaces/sso` seam and the recorder;
  `domains/tokenanomaly` / `domains/threataction` still import only
  metering/threataction/spi. The one `protocols/oauth` edit (Decision 2) is
  within the package, telemetry-only, and adds no imports.

## Failure modes

- **Observation mislabeled with a foreign family.** If a store ever minted a
  new FamilyID per rotation while propagating JTI unchanged (violating the
  documented lineage discipline), one thumbprint would see two families and
  `recordObservation`'s non-empty overwrite would keep the last writer. This
  cannot happen with the shipped stores (family and JTI propagate together);
  the guard mirrors the existing `SubjectID` guard and is a read-side best
  effort, never a grant decision.
- **Repeated threat dispatch while a burst minute is in-window.** The windowed
  scan re-detects the same burst on every sweep until the burst minute leaves
  the window (up to `window`/`sweep_interval` dispatches, e.g. 15 with defaults).
  Safe: `DeleteFamily`/`DeleteAllForSubject` are idempotent, the finding store
  upserts one row, and the bus event is best-effort with receiver-side dedup —
  the same re-dispatch-on-persistent-signal semantics `anomaly.Runner` already
  has. Accepted, documented behavior; not a new failure mode.
- **Consecutive bursts dampen each other's baseline.** A burst at m−1 inflates
  the prefix baseline for m, so a client spiking every minute may never trip.
  Same spirit as today (the burst inflated the next latest-minute baseline);
  the adaptive-baseline trade-off is unchanged.
- **Subject-table memory.** Bounded by cap × window via sweep pruning; the
  `TrackedBuckets` gauge does not cover the subject table (detector-local
  state) — operators watch `max_tracked_subjects` behavior via the finding
  output only. Worst case at defaults: 4096 rows × 16 minutes ≈ 65k entries,
  well under the observation table's equivalent footprint.
- **Partial-minute understatement persists** for the in-progress minute
  (systematic by construction); the fix's value is completed-minute bursts.
  No clock change; `ev.At` buckets as today, so a skewed replica clock shifts
  the window exactly as it does today.
- **Subject-spike revoke scope is subject-wide.** A per-subject rotation burst
  finding has no thumbprint/family by construction (issuance events, no
  family aggregation — bounded cardinality), so its `revoke` uses the subject
  fallback. This is the *correct* scope: the signal is subject-wide (many
  tokens for one subject), not one lineage — the fallback's own doc contract.
- **Legacy refresh rows** (empty JTI) produce no observation and no family —
  pre-feature behavior preserved (documented on `RefreshToken.JTI`).

## What could break the design

1. **Spec file list is incomplete and would not compile.** `token_device.go`
   (interface decl :29, call :169) and `token_exchange.go:67` declare/call the
   seam; `token_ciba_test.go:70` implements it. All three must change or
   `go build ./...` / `go vet ./...` fail. The spec's modify list names only
   `serverdeps.go`; the design (Decision 1) makes the full set explicit.
2. **Improvement 2 silently no-ops without the `handle_introspect.go` edit.**
   This is the highest-risk drift: the spec's do-not-modify list says
   "protocols/oauth — no grant/introspect wire behavior changes", which a
   reviewer could read as "no protocols/oauth edits at all". Decision 2
   narrows it to its actual intent (wire contracts) and requires the one
   telemetry-only `FamilyID: info.FamilyID` addition. If that edit is refused,
   Improvement 2 must be descoped or the family routed via the subject table
   (which would change `Finding`/`DedupKey` — a bigger surface).
3. **`Detail` wording change for rate_spike.** The "byte-identical for
   family-less paths" claim covers family/revoke/evidence behavior, not the
   spike `Detail` string, which names the burst minute. Existing tests
   asserting exact wording must be updated; anything downstream that matches
   on `Detail` (none found) would break.
4. **DedupKey collision if the one-per-client rule is ever relaxed.** If a
   future change emits client-scoped and subject-scoped findings for the same
   client in one sweep, they silently overwrite each other in the store
   (same key). The rule is load-bearing; a regression test pins it.
5. **Baseline definition drift.** The "≥ 2 minutes strictly before m" rule
   must apply per candidate minute; a naive "≥ 2 minutes before the burst"
   re-uses today's `len ≥ 3` shape and would let a brand-new client's first
   burst self-trip. The unit tests in the verification plan pin the
   flat-then-spike-then-flat and brand-new-client cases.
6. **Subject-table growth from client-credentials/unknown-subject events.**
   Events with empty `SubjectID` are excluded by the feed guard; a bug there
   would churn the cap with junk rows and evict real ones. Cheap to pin in a
   unit test.
7. **`server_helpers.go` budget drift.** 493 lines today; the seam change is
   small, but if the edit plus doc lines cross 500, the maintainability gate
   fails and the spec's escape hatch (move to
   `interfaces/sso/server_usage_family.go`) must be taken before handoff.
8. **`mergeFinding` family staleness.** If a lineage's observation somehow
   carried two families (Failure mode 1), the upsert keeps whichever family
   the freshest sweep wrote — bounded, logged nowhere. Accepted as a read-side
   best effort; the family is never used for a grant decision.

## File change map

Modify (spec list, completed):

```text
domains/metering/token_usage.go                 Event.FamilyID field (+ doc)
internal/handler/serverdeps.go                  seam param :157
internal/handler/tokengrant/token_refresh.go    decl :30 + rotation passes info.FamilyID :206
internal/handler/tokengrant/token_authcode.go   decl :38 + first-issue "" :232
internal/handler/tokengrant/token_ciba.go       decl :29 + first-issue "" :252
internal/handler/tokengrant/token_device.go     decl :29 + first-issue "" :169   (spec gap)
internal/handler/tokengrant/token_exchange.go   decl :67                        (spec gap)
internal/handler/tokengrant/token_exchange_stages.go  first-issue "" :491
internal/handler/tokengrant/token_ciba_test.go  fake Deps signature              (spec gap)
interfaces/sso/accessors_handlers.go            adapter :336, :457
interfaces/sso/server_helpers.go                impl :439
protocols/oauth/handle_introspect.go            Offer gains FamilyID :358        (spec gap, Decision 2)
domains/tokenanomaly/tokenanomaly.go            Finding.FamilyID
domains/tokenanomaly/detector.go                observation.familyID, recordObservation,
                                                dispatchThreat, evidenceFor, WithMaxTrackedSubjects,
                                                Record subject-fold hook
domains/tokenanomaly/detect.go                  windowed spikeForClient, subjectMinuteRates table
docs/config-reference.md                        threat_action family-scoped revoke guidance
docs/openapi.yaml                               suspicious finding schema family_id
```

Do not modify (unchanged, per spec):

```text
domains/threataction/actions.go     RevokeFamilyExecutor semantics; only reachability changes
domains/metering Bucket aggregation no new dimension, no migration
grant/introspect wire behavior      no response/decision byte changes (telemetry-only Offer edit)
```

Tests added beside the change: `domains/tokenanomaly` (family-bearing
observation → finding → threat via spy executor; windowed-spike series;
subject-spike with flat client baseline; cap eviction + deterministic order;
one-finding-per-client-per-sweep), `internal/handler/tokengrant` (rotation
Event family == consumed `info.FamilyID`; first-issue `""`),
`domains/threataction` (family path invokes `DeleteFamily` and never
`DeleteAllForSubject`; empty-family fallback byte-identical), and `test/`
(`package ssotest`): with `default_action: revoke`, a velocity finding for one
family revokes that family while a second refresh token of the same
subject+client survives, with the `KindTokenRevoked` bus event keyed by
FamilyID.

## Verification

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./domains/tokenanomaly/... ./domains/threataction/... ./domains/metering/... -race
go test ./internal/handler/tokengrant/ -run 'Refresh' -v
go test ./test/ -run TestE2E -v
make ci
```

Success criteria: family-bearing observation produces a family-carrying
Finding and Threat; `RevokeFamilyExecutor` family path executes with a
`DeleteFamily` spy and the fallback path is byte-identical to today's tests;
burst-at-T−2 and subject-scoped series yield findings; one finding per client
per sweep; all gates green.
