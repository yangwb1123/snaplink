# domains/tokenanomaly — 方向 3 需求规格：响应精度（FamilyID 贯穿检测→响应链；rate_spike 窗口化）

Scope: expansion direction 3 from `docs/auto/domains-tokenanomaly-analysis.md` —
「响应精度不足：FamilyID 未贯穿检测→响应链，revoke 退化为整用户兜底；rate_spike
只盯"最后一分钟"」.

Today the response chain cannot distinguish "one stolen credential" from "the
whole user": `velocity` / `multi_geo` findings are per-token signals, but the
refresh-family lineage (`FamilyID`) is dropped at every hop — `metering.Event`
has no family field, `observation` does not record it, `Finding` does not carry
it, and `dispatchThreat` builds a `threataction.Threat` with an empty
`FamilyID`. `RevokeFamilyExecutor` therefore always degrades to
`SubjectRevoker.DeleteAllForSubject` — revoking EVERY refresh token the user
holds for the client for what is usually a single stolen token (self-inflicted
DoS on the legitimate user). Separately, `rate_spike` compares only the
newest bucket in the query window against the trailing mean, so any burst that
began before the current minute — or already subsided — is never evaluated,
and the aggregation is per-client only, so a burst of many tokens for one
subject inside a high-volume client is invisible.

This spec contains exactly three evidence-backed improvements:

1. Carry `FamilyID` into token telemetry: new `metering.Event.FamilyID` field,
   filled at the refresh-rotation seam (the one place the family is known
   before issuance), captured by the detector's observation table.
2. Thread `FamilyID` through the response chain: `Finding` → `Threat` →
   family-scoped `revoke_family` execution, with the subject-scoped fallback
   retained (and byte-identical) for family-less findings.
3. Generalize `rate_spike` from "latest minute only" to any burst inside the
   window, and add a bounded subject dimension so per-user token-rotation
   bursts inside a high-volume client are detectable.

## Preserved invariants (non-negotiable)

- `FamilyID` is an opaque refresh-lineage identifier, not PII. It already
  flows through audit events today (`RecordRefreshTokenReuse`,
  `RecordRefreshRotationVelocityExceeded`, `interfaces/sso/server_helpers.go:477-487`);
  `Finding.SubjectID` remains the single PII field.
- Refresh-family semantics unchanged (AGENTS.md OAuth invariants): rotation
  propagates `FamilyID` unchanged; reuse deletes the family; per-family
  rotation-velocity kill stays in the grant path. This spec only *reads* the
  family for detection/response; it never changes grant decisions.
- Zero-value byte-identity: no family known (first-issue auth-code/CIBA/token-
  exchange, `rate_spike` at client granularity, login-side `anomaly` signals)
  ⇒ `Event.FamilyID` / `Finding.FamilyID` / `Threat.FamilyID` stay `""` and
  every behavior is byte-identical to today — the `SubjectRevoker` fallback
  remains exactly as it is for those paths.
- Fail-open and hot-path contracts untouched: Offer points stay off-path
  best-effort (drop-on-full queue), detection stays off the request path,
  `dispatchThreat` stays fail-open with logged executor errors, and no change
  alters a grant/introspect decision or wire response.
- Bounded cardinality: `metering.Bucket` gets NO new dimension (subject/token
  would explode the bucket key space — the privacy and bounded-store stance of
  `token_usage.go`). Subject-level rates live only in the detector's own
  capped table.
- Import direction: `domains/tokenanomaly` and `domains/threataction` do not
  import `protocols/oauth`; the family reaches the detector through the
  existing `internal/handler` Deps → `interfaces/sso` seam, exactly like
  `RecordRefreshTokenIssued` flows today.
- Budgets: no new top-level packages. `domains/tokenanomaly` root stays at 5
  non-test files — the windowed-spike and subject-rate logic lands in
  `detect.go` (155 lines, owns spike analysis) rather than `detector.go`
  (442 lines, near the 500-line budget). `interfaces/sso/server_helpers.go`
  (493 lines) only gains one parameter on an existing helper; if the edit
  pushes it past budget, the helper moves to a new small
  `interfaces/sso/server_usage_family.go` first.

## Improvement 1: FamilyID 进入 token 遥测（Event 字段 + 旋转握手点填充 + observation 捕获）

**Problem**: the detection side cannot name which refresh family a finding
concerns. `metering.Event` carries thumbprint/kind/client/subject/geo but no
family, and the one production seam where the family is known before issuance
— the refresh-rotation grant — calls `RecordRefreshTokenIssued` without it,
even though `info.FamilyID` is in scope at that exact line (it is threaded
into `IssueRefreshToken` two statements' worth of code later). The detector's
per-thumbprint `observation` then records client/subject/geos only, so
`Finding` can never learn the family.

**Evidence**:
- `domains/metering/token_usage.go:45-77` — `Event` struct: `Thumbprint`,
  `Kind`, `Endpoint`, `ClientID`, `SubjectID`, `TenantID`, `At`,
  `GeoCountry`; no `FamilyID`.
- `internal/handler/tokengrant/token_refresh.go:206` —
  `d.RecordRefreshTokenIssued(ctx, client.ID, info.UserID, true)`; `:232`
  (via `refreshRotateFamily`) — `d.IssueRefreshToken(..., info.FamilyID, ...)`
  proves `info.FamilyID` is in scope at the same call site.
- `internal/handler/serverdeps.go:157` — `RecordRefreshTokenIssued func(ctx
  HandlerContext, clientID, subjectID string, rotation bool)`; mirror
  declarations in `token_authcode.go:38`, `token_ciba.go:30`,
  `token_exchange_stages.go` — none accept a family.
- `interfaces/sso/server_helpers.go:439-447` — `recordRefreshTokenIssued`
  builds the usage `Event` without a family.
- `domains/tokenanomaly/detector.go:59-68` — `observation` struct:
  `clientID`, `subjectID`, `geos`, `first`, `last`, `count`, `lastGeo`,
  `lastGeoAt`, `minSwitch`; no `familyID`. `recordObservation`
  (detector.go:200-221) copies client/subject only.

**Proposed behavior**:
- Add `FamilyID string` to `metering.Event`, documented as the opaque
  refresh-token family lineage id; empty = unknown. The field is
  source-compatible (no wire/proto), and the memory/sqlite stores ignore it
  for `Bucket` aggregation — no store change, no migration.
- Extend the handler seam by one parameter: `serverdeps.go:157`,
  `accessors_handlers.go:457`, `server_helpers.go:439` gain `familyID
  string`. The rotation path (`token_refresh.go:206`) passes `info.FamilyID`;
  the first-issue paths (`token_authcode.go:232`, `token_ciba.go:252`,
  `token_exchange_stages.go:491`) pass `""` — a new family is minted inside
  the store during issuance, so there is nothing to pass and behavior stays
  byte-identical.
- `observation` gains `familyID string`; `recordObservation` copies
  `ev.FamilyID` when non-empty (mirroring the `SubjectID` guard), so a
  per-thumbprint observation that saw a family-bearing rotation event carries
  the lineage even if earlier sightings predated the field.

**Acceptance check**:
- Unit (`domains/tokenanomaly`): `Detector.Record` with an Event carrying
  `FamilyID: "fam-x"` yields an observation whose family is `fam-x`, and a
  subsequent `Analyze` geo/velocity finding built from it carries it.
- Unit (`internal/handler/tokengrant`): `HandleRefreshGrant` rotation test
  asserts the offered usage Event's `FamilyID` equals the consumed token's
  `info.FamilyID`; auth-code/CIBA/token-exchange first-issue tests assert
  `""` (zero-value byte-identity).
- `go build ./... && go vet ./... && go test -run
  'TestMaintainability_|TestArchitecture_' .` — metering store conformance and
  memory-store tests pass unchanged.

## Improvement 2: FamilyID 贯穿 Finding→Threat→revoke，精确到 refresh family（SubjectRevoker 仅作兜底）

**Problem**: even with telemetry carrying the family, the response chain drops
it at every hop. `Finding` has no `FamilyID`; `dispatchThreat` constructs the
`threataction.Threat` with `FamilyID` empty; `RevokeFamilyExecutor.Execute`
therefore always takes the `revokeSubject` fallback —
`DeleteAllForSubject(subjectID, clientID)` — which kills EVERY refresh token
the user holds for the client, a user-wide hammer for what is usually one
stolen credential. The `SubjectRevoker` doc comment itself admits the
family-scoped path is "a permanent no-op in production". `evidenceFor` also
omits the family, so a conditional threat policy cannot scope `revoke` to the
affected lineage either.

**Evidence**:
- `domains/tokenanomaly/tokenanomaly.go:50-72` — `Finding` struct fields:
  `Type`, `Severity`, `Thumbprint`, `ClientID`, `SubjectID`, `Geos`,
  `Detail`, `Count`, `FirstSeen`, `LastSeen`; no `FamilyID`.
- `domains/tokenanomaly/detector.go:138-155` — `dispatchThreat`: `threat :=
  threataction.Threat{Type, Severity, SubjectID, ClientID, Evidence}` —
  `FamilyID` left at its zero value.
- `domains/threataction/actions.go` — `RevokeFamilyExecutor.Execute`:
  `if e.families != nil && threat.FamilyID != "" { return e.revokeFamily(...)
  }` else `revokeSubject` → `subjects.DeleteAllForSubject(ctx,
  threat.SubjectID, threat.ClientID)`; `SubjectRevoker` interface doc: "the
  fallback RevokeFamilyExecutor uses when a threat carries no FamilyID.
  Neither anomaly.Runner ... nor tokenanomaly.Detector ... ever populate
  Threat.FamilyID today, so without this fallback revoke_family is a
  permanent no-op in production."
- `domains/threataction/threataction.go:31-47` — `Threat.FamilyID` exists
  ("the refresh token family, when the threat is token-scoped") but has no
  production writer.
- `domains/tokenanomaly/detector.go:157-175` — `evidenceFor` emits
  `token_thumbprint`, `detail`, `geos`, `count`; no family key for policy
  conditions.

**Proposed behavior**:
- `Finding` gains `FamilyID string \`json:"family_id,omitempty"\``. `DedupKey`
  unchanged (per-token findings already key on type+thumbprint, which is
  unique per token; per-client `rate_spike` has no family by construction).
- `geoFinding` (detect.go:38-66) copies `o.familyID` into the Finding when
  non-empty; `spikeForClient` leaves it empty (client-scoped).
- `dispatchThreat` sets `threat.FamilyID = f.FamilyID`.
- `evidenceFor` adds `"family_id"` when non-empty, so a conditional policy
  (`conditions` on `family_id`, per config-reference.md threat_action
  guidance) can scope `revoke` to the lineage.
- `RevokeFamilyExecutor` code is unchanged but its family path becomes
  reachable: a token finding with a family executes `families.DeleteFamily`
  (kills only the stolen lineage), and the `DeleteAllForSubject` fallback
  remains byte-identical for family-less threats (`rate_spike` at client
  granularity, first-issue findings, login-side `anomaly` signals).
- Documentation: `docs/config-reference.md` threat_action section updated to
  state that token findings with a known family revoke the family only, and
  the subject-scoped fallback applies only when the family is unknown.

**Acceptance check**:
- Unit (`domains/tokenanomaly`): a family-bearing observation produces a
  Finding whose `FamilyID` survives into the `Threat` `dispatchThreat`
  constructs (executor recorded via a spy `ThreatExecutor`).
- Unit (`domains/threataction`): `RevokeFamilyExecutor.Execute` with
  non-empty `FamilyID` invokes `families.DeleteFamily` and never
  `subjects.DeleteAllForSubject`; with empty `FamilyID` the fallback path and
  its result string are byte-identical to today's tests.
- Integration (`test/`, package `ssotest`): with `default_action: revoke`, a
  velocity finding for one family revokes that family while a second refresh
  token of the same subject+client survives; the `KindTokenRevoked` bus event
  is keyed by the FamilyID.
- `go build ./... && go vet ./...` and the committed architecture +
  maintainability gates.

## Improvement 3: rate_spike 窗口化——任意窗口内突发 + 有界 subject 维度

**Problem**: `spikeForClient` evaluates ONLY the newest bucket in the query
window: `latest := minutes[len(minutes)-1]`, baseline = mean of
`minutes[:len(minutes)-1]`. Because `detectRateSpike` queries
`Since = now - window` and the newest bucket is the in-progress (partial)
minute, any burst that began before the current minute — or already subsided
before the sweep — is never tested; it merely inflates the baseline for the
next minute. A burst shorter than the sweep cadence that ends before the sweep
is invisible. Separately, `foldClientMinuteRates` keys only on `ClientID`
(`Bucket` has no subject/token dimension), so an attacker rotating many tokens
for ONE subject inside a high-volume client produces no per-client spike.

**Evidence**:
- `domains/tokenanomaly/detect.go:100-136` — `spikeForClient`:
  `latest := minutes[len(minutes)-1]`; `latestCount := byMin[latest]`;
  baseline over `minutes[:len(minutes)-1]`; returns a finding only when the
  latest minute clears `spikeMinCount` and `spikeFactor × baseline`. No other
  minute is ever tested.
- `domains/tokenanomaly/detect.go:88-98` — `foldClientMinuteRates`:
  `rates[b.ClientID]` — subject discarded; `domains/metering/token_usage.go`
  `Bucket` struct has `Minute/ClientID/Kind/Endpoint/Count` and no subject.
- `domains/tokenanomaly/detect.go:73-86` — `detectRateSpike`: window is
  `now.Add(-d.window)`; the sweep runs on `token_anomaly.sweep_interval`
  (`docs/config-reference.md:656`), so "latest minute" is a partially elapsed
  bucket whose count is systematically understated.

**Proposed behavior**:
- Generalize the spike test to scan every minute in the window: minute `m` is
  a candidate when its count clears `spikeMinCount` AND exceeds
  `spikeFactor ×` the mean of the minutes strictly before `m` inside the
  window (still requiring ≥ 2 earlier baseline minutes, so a brand-new client
  cannot self-trip). Emit at most ONE `rate_spike` finding per client per
  sweep — the strongest candidate (highest count/baseline ratio, earliest
  minute tie-break) — keeping the finding store bounded and the
  type+client `DedupKey` semantics unchanged. `Detail` names the burst
  minute, not just "latest-minute".
- Add a bounded subject dimension: the Detector folds its own
  per-(subject, client) per-minute counts from `Record` events (raw events
  carry `SubjectID` even though `Bucket` does not), stored in a new capped
  table with `WithMaxTrackedSubjects` (default mirrors
  `defaultMaxThumbprints`; oldest-minute eviction), and applies the same
  windowed test per subject. `Finding` already carries `SubjectID`/`ClientID`,
  so no new Finding fields are needed; the finding's `Detail` names the
  subject-scoped burst.
- Zero-config default: per-client behavior for the family-less case stays
  byte-identical; the subject table simply extends detection when events
  carry subjects.

**Acceptance check**:
- Unit: minute series with the burst at minute T-2 (latest minute back to
  baseline) now yields a finding; a flat-then-spike-then-flat series yields
  exactly one finding (strongest candidate), never a duplicate per client per
  sweep.
- Unit: a subject whose per-minute issuance spikes while the client-wide
  baseline stays flat yields a subject-scoped `rate_spike` finding with
  `SubjectID` set and a zero-value `Thumbprint` (unchanged wire shape).
- Unit: subject table respects `WithMaxTrackedSubjects` eviction; sweep order
  stays deterministic (sorted iteration).
- Gates: `go build ./... && go vet ./...`, architecture + maintainability
  gates, existing `memory` store and `detector_test` suites unchanged.

## Files

### Modify

```text
domains/metering/token_usage.go — Event.FamilyID field (+ doc)
internal/handler/serverdeps.go — RecordRefreshTokenIssued gains familyID param
internal/handler/tokengrant/token_refresh.go — pass info.FamilyID at :206
internal/handler/tokengrant/token_authcode.go, token_ciba.go,
  token_exchange_stages.go — pass "" (first-issue, byte-identical)
interfaces/sso/accessors_handlers.go, server_helpers.go — seam plumbing
domains/tokenanomaly/tokenanomaly.go — Finding.FamilyID
domains/tokenanomaly/detector.go — observation.familyID, recordObservation,
  dispatchThreat, evidenceFor
domains/tokenanomaly/detect.go — windowed spikeForClient, subject-rate table
docs/config-reference.md — threat_action family-scoped revoke guidance
docs/openapi.yaml — /api/v1/admin/tokens/suspicious finding schema (family_id)
```

### Do not modify

```text
domains/threataction/actions.go — RevokeFamilyExecutor semantics stay; only
  its reachability changes via Threat.FamilyID writers
domains/metering Bucket aggregation — no new bucket dimension (cardinality)
protocols/oauth — no grant/introspect wire behavior changes
```

## Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./domains/tokenanomaly/... ./domains/threataction/... ./domains/metering/... -race
go test ./internal/handler/tokengrant/ -run 'Refresh' -v
go test ./test/ -run TestE2E -v   # integration: family-scoped revoke precision
make ci
```
