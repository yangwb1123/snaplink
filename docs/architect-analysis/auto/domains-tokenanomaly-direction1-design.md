# domains/tokenanomaly — 方向 1 设计：打通 Geo 信号链路（multi_geo / velocity）

Design companion to `docs/auto/domains-tokenanomaly-direction1-spec.md`. All
evidence re-verified against source before writing:

- `GeoCountry:` is assigned **only** in `_test.go` files (grep over non-test
  Go is empty); `domains/metering/token_usage.go:73-76` defines the field and
  the privacy boundary.
- The five Offer seams are exactly: `recordTokenIssued`,
  `recordRefreshTokenIssued`, `recordIDTokenIssued`
  (`interfaces/sso/server_helpers.go:428/441/453`), `recordIntrospectionUsage`
  (`protocols/oauth/introspect_body.go:16-29`), `introspectRefresh`
  (`protocols/oauth/handle_introspect.go:335-365`). All five have a
  `core.HandlerContext` in scope except `recordIntrospectionUsage`, whose
  sole call site (`handle_introspect.go:306`) does.
- `Detector.Record` gates observations on `ev.Thumbprint != ""`
  (`domains/tokenanomaly/detector.go:257`); `refreshTokenMigrations` is at v7
  (`infrastructure/defaultimpl/sqlite/refresh_tokens_schema.go:78-115`);
  `ThreatExecutors.Execute` ignores the caller-passed `ThreatPolicy` and
  matches from the store (`domains/threataction/registry.go:91-104`);
  `RevokeFamilyExecutor` falls back to subject-scoped revocation when
  `Threat.FamilyID == ""` (`domains/threataction/actions.go:142-148`) —
  and no detector populates `FamilyID` today (actions.go:23-26).

This document fixes the API surface, storage model, failure modes, and the
things that could break the design. No detection logic changes; the detector's
per-thumbprint observation table, sweep, and finding store are untouched.

## Decision 1: one canonical extractor, `geo.CountryCodeFromContext`, in `platform/geo`

**API surface.** Add one function (and its test) to `platform/geo`:

```go
// CountryCodeFromContext returns the coarse ISO-3166-1 alpha-2 country code
// GeoMiddleware stashed for this request, or "" when no provider is wired,
// the lookup failed, or the IP was unknown. The single canonical geo→Event
// read: both interfaces/sso and protocols/oauth route their Offer seams
// through it so a missing geo source degrades to the zero value everywhere.
func CountryCodeFromContext(hctx core.HandlerContext) string {
    info, ok := FromHandlerContext(hctx)
    if !ok {
        return ""
    }
    return info.CountryCode
}
```

`platform/geo` already owns the stash/read pair (`HandlerContextKey`,
`FromHandlerContext`, `middleware.go:99`) and already imports `shared/core`;
this is a 10-line addition to the same package — no new package, no new
import edge.

**Why `platform/geo` and not a `protocols/oauth`-local helper.** The
extractor is consumed by two layers that cannot import each other
(`protocols/oauth` must not import `interfaces/sso`). Both can import
`platform/geo`: layer numbers are shared=0, platform=1, protocols=3,
interfaces=5 and imports flow high→low (`architecture_layer_test.go:41`).
`interfaces/sso` already imports `platform/geo` in six files
(`options_misc.go`, `sso_wiring.go`, `server_invalidation.go`,
`accessors.go`, `aliases.go`, `server_login_client.go`); `protocols/oauth`
currently does not, but the edge `protocols/oauth -> platform/geo` is legal
downward. A single canonical reader is the load-bearing property: the two
layers must produce byte-identical `GeoCountry` values for the same request,
or the per-token observation table would silently split a token's sightings
by seam.

**Alternative rejected.** A helper on the `protocols/oauth` side plus a
separate one on the sso side (two copies) — rejected: duplicated extraction
logic is exactly the drift class this design must not introduce, and the
spec's precedent (`introspect_body.go` calling `metering.Thumbprint` from
`domains/metering`) shows the shared-kernel-read pattern is established.

## Decision 2: `s.offerUsage` choke point in `interfaces/sso`

**API surface** (new small method on `*Server`, in `server_helpers.go` or a
new `server_usage_geo.go` — see "What could break", budget):

```go
// offerUsage stamps the request's coarse geo onto a token-usage Event and
// hands it to the recorder. Nil recorder = no-op (unchanged). No geo in
// context => GeoCountry stays "" => the Event is byte-identical to today.
func (s *Server) offerUsage(ctx HandlerContext, ev metering.Event) {
    ev.GeoCountry = geo.CountryCodeFromContext(ctx)
    s.tokenUsageRecorder.Offer(ev)
}
```

The three `record*Issued` helpers build their `metering.Event` literal as
today and replace the direct `s.tokenUsageRecorder.Offer(...)` call with
`s.offerUsage(ctx, ev)`. `s.tokenUsageRecorder` is a `*metering.Recorder`
whose `Offer` is nil-safe (`server_helpers.go:428` calls it without a nil
check today; `accessors.go:187` documents the field).

**Zero-value byte-identity.** `CountryCodeFromContext` returns `""` when no
`*GeoInfo` is stashed — no `WithGeoProvider`, a lookup miss, an unknown IP,
or `ErrNotFound` all produce the same `""` the seams emit today. The geo
middleware is installed ahead of all routes (`options_misc.go:55-62`), so on
a geo-enabled server every grant handler's `ctx` already carries the info;
the login-side precedent (`recordLoginAttempt`, `server_helpers.go:313`) is
unchanged and proves the read pattern on the same context type.

**Contract notes.** `Event.GeoCountry` is the ONLY new field; the three
helpers keep their signatures and call sites
(`internal/handler/tokengrant/*`, which funnel through the Deps interface —
zero hot-file changes). Offer remains off the request path: the recorder's
drop-on-full queue, not this helper, absorbs load.

## Decision 3: the two `protocols/oauth` seams — thread `ctx` into `recordIntrospectionUsage`

**API surface.** `recordIntrospectionUsage` gains a `ctx core.HandlerContext`
parameter (package-private; sole caller `introspectAccess` already holds
`ctx`):

```go
func recordIntrospectionUsage(d IntrospectDeps, ctx core.HandlerContext, claims *core.TokenClaims) {
    // ...existing client-id fallback unchanged...
    d.TokenUsageRecorder().Offer(metering.Event{
        Thumbprint: metering.Thumbprint(claims.JTI),
        Kind:       metering.KindAccess,
        Endpoint:   metering.EndpointIntrospect,
        ClientID:   clientID,
        SubjectID:  claims.Subject,
        GeoCountry: geo.CountryCodeFromContext(ctx),
    })
}
```

`introspectRefresh` (already has `ctx core.HandlerContext`) stamps
`GeoCountry: geo.CountryCodeFromContext(ctx)` and, per Decision 6,
`Thumbprint: metering.Thumbprint(info.JTI)`.

**Signature-change blast radius.** Grep-verified: `recordIntrospectionUsage`
has exactly one caller. `IntrospectDeps` is unchanged. `/token/introspect`
response bodies are untouched — the Offer is fire-and-forget and cannot
alter `{active:true/false}` or the no-store headers.

## Decision 4: `RefreshToken.JTI` — field, stamping, rotation propagation

**API surface.** Three additive members, all zero-value-safe:

```go
// oauthspi/refresh_token.go
type RefreshToken struct {
    // ...existing fields...
    // JTI is the refresh record's correlation id, stamped once at first
    // issue (the new-family branch) and propagated UNCHANGED through
    // rotation, the same lineage discipline as FamilyID. It is never a
    // JWT claim — refresh tokens are opaque — it exists so the
    // refresh-introspect Offer can feed the per-token observation table
    // via metering.Thumbprint(JTI). Empty on legacy rows (or a rotation
    // that predates the field) => Thumbprint "" => pre-feature behavior.
    JTI string `json:"jti,omitempty"`
}

// oauthspi/refresh_token.go — the propagate-unchanged context bucket
type RefreshAuthContext struct {
    // ...existing fields...
    JTI string // propagated from the parent at rotation; empty at first issue
}

// oauthwire/auth_code_handler.go
type IssueRefreshTokenParams struct {
    // ...existing fields...
    JTI string
}
```

**Stamping discipline** (mirrors `FamilyID` exactly,
`auth_code_handler.go:238-244`):

```go
freshFamily := p.FamilyID == ""
if freshFamily {
    fid, err := GenerateAuthCodeBytes()  // existing
    ...
    p.FamilyID = fid
    if p.JTI == "" {                     // new: stamp once per family
        jti, err := GenerateAuthCodeBytes()
        ...
        p.JTI = jti
    }
}
```

`buildRefreshTokenEntry` copies `JTI: p.JTI` onto the record. `GenerateAuthCodeBytes`
is the same randomness source the token and family id already use — a JTI
needs only uniqueness, and sharing the generator adds no new entropy
dependency.

**Propagation through rotation.** The rotation site
(`internal/handler/tokengrant/token_refresh.go:228-239`,
`refreshRotateFamily`) already threads every "propagate unchanged" lineage
field (`AMR/ACR/AuthTime/Generation/FamilyCreatedAt`) through
`oauth.RefreshAuthContext` — the structured bucket whose doc says it exists
so "the already-long issue signature does not gain one positional parameter
per field". Add `JTI: info.JTI` to that literal. **This is why JTI goes on
`RefreshAuthContext`, not as a positional parameter:** the `IssueRefreshToken`
Deps interface is 14 positional args implemented at
`interfaces/sso/accessors_handlers.go:427` and invoked by six tokengrant
handlers; a positional `jti` would touch every one. The bucket is the
existing mechanism, and the first-issue call sites
(`token_authcode.go:225`, `token_ciba.go:245`, `token_device.go:162`,
`token_exchange_stages.go:480`) construct an empty `RefreshAuthContext` —
JTI stays `""` there, so the fresh-family branch stamps it. A rotation that
runs on a pre-field binary mid-rollout leaves `JTI == ""` on the new leaf →
`Thumbprint == ""` → today's byte-identical behavior (fail-open, no signal).

## Decision 5: storage model for JTI

| Store | Mechanism | Change | Legacy rows |
|---|---|---|---|
| Memory (`infrastructure/defaultimpl/memorystoreoauth/memory_refresh_token.go:133-152`) | field-by-field rebuild on Issue | add `JTI: info.JTI` to the literal | N/A (memory is per-process) |
| Redis (`infrastructure/redis/refresh_token.go:133`) | whole-struct `json.Marshal` blob | field tag `json:"jti,omitempty"` is automatic; zero code beyond the struct tag | old blobs unmarshal to `""` |
| SQLite (`infrastructure/defaultimpl/sqlite/refresh_tokens_*.go`) | columnar | baseline DDL gains `jti TEXT NOT NULL DEFAULT ''`; new **v8** migration `addRefreshTokenJTI` (`ALTER TABLE ... ADD COLUMN jti TEXT NOT NULL DEFAULT ''`, idempotent via the existing `refreshTokenColumnExists` PRAGMA pattern); INSERT (line ~99) and the SELECT/scan paths gain the column | `''` → `Thumbprint == ""` → pre-feature behavior |

**Migration mechanics.** v8 follows the v3-v7 precedent exactly
(`refresh_tokens_schema.go:96-115`): one `migrate.Migration` entry with a
`Func` that adds the column only when missing, so fresh DBs (whose baseline
DDL already has it) skip the add and pre-v8 DBs get it backfilled.
`RefreshTokensMaxVersion()` derives from the slice
(`maxversions.go:30`), so the boot-time `migrate.CheckSchema` canary for
old-binary/new-DB rollbacks updates itself; `maxversions_test.go` asserts
only positivity, not exact pins. No index needed (JTI is written and read
with the row, never queried by).

**JSON forward/backward compatibility.** Redis stores opaque JSON read only
by this binary. New blob + old binary: `encoding/json` ignores the unknown
`jti` key → JTI lost until that token rotates again (benign). Old blob + new
binary: `omitempty` + missing key → `""`. Both directions degrade to
today's behavior, never to an error.

## Decision 6: Thumbprint at the refresh-introspect Offer (privacy contract)

`introspectRefresh` stamps `Thumbprint: metering.Thumbprint(info.JTI)` —
the exact pattern `recordIntrospectionUsage` already uses for access tokens
(`introspect_body.go:21-29`). Privacy properties:

- `Thumbprint` is SHA-256(jti) (`metering/token_usage.go:122-131`), never the
  refresh-token value, never the raw JTI. The usage store gains no new PII;
  the subject id remains the single PII field.
- The JTI itself is a random 256-bit opaque id, not a claim and not derived
  from user data.
- Oracle safety untouched: introspection response bodies, `{"active":false}`
  collapsing, and no-store headers are unchanged; the Offer fires after the
  response is decided.

**Why this closes the hole.** `Detector.Record` only captures observations
when `ev.Thumbprint != ""` (`detector.go:257`). Without JTI, every
refresh-token presentation via `/token/introspect` is invisible to the
per-token geo table, so a stolen refresh token used from a second country
could never produce `multi_geo`/`velocity`. Because JTI propagates through
rotation (Decision 4), the entire rotation chain of one family presents
under one stable thumbprint — the same continuity `FamilyID` gives reuse
detection.

## Decision 7: `Threat.Evidence` carries the geo set and count

**API surface.** `dispatchThreat` (`domains/tokenanomaly/detector.go:405-426`)
extends the Evidence map:

```go
evidence := map[string]string{
    "token_thumbprint": f.Thumbprint,
    "detail":           f.Detail,
}
if len(f.Geos) > 0 {
    evidence["geos"] = strings.Join(f.Geos, ",") // already sorted (detect.go geoFinding)
    evidence["count"] = strconv.FormatInt(f.Count, 10)
}
```

The 1:1 type mapping already holds and is preserved:
`FindingMultiGeo == "multi_geo" == ThreatMultiGeo`, `FindingVelocity ==
"velocity" == ThreatVelocity` (`threataction.go:109-110`), so no new wire
strings exist — the policy store can already match them; this change makes
them reachable and evidence-bearing. `f.Geos` is sorted in `geoFinding`
(`detect.go`), so the joined string is canonical and `eq`-matchable.

**Policy contract (documented in config-reference, Decision 9).** With
`geos` and `count` in Evidence, `ThreatConditions` (`policy.go:91-120`)
gains two usable levers:

- `conditions: {key: "geos", operator: "exists"}` — matches only when a geo
  set is present (the "keyed on geos presence" conditional).
- `conditions: {key: "count", operator: "gt", value: "2"}` — numeric
  cardinality gate (conditions' `gt`/`lt` parse both sides as float64 and
  fail-closed on parse errors, per `policy.go:96-101`).

Comma-joined `geos` is a string; `gt`/`lt` on it would fail-close, so
cardinality comparisons MUST use `count`. This is the documented contract,
not an accident.

**Audit.** The composite's `recordAudit` emits `threat_action_executed`
with `threat.type`/`threat.action`/`threat.subject` meta
(`threataction.go:118-127`); the executor stores the policy's conditions but
Evidence is carried on the Threat the handler receives, so `revoke`-family
detail lines can now name the geo set — the geo context the spec's problem
statement calls out as missing.

## Decision 8: dispatch contract tests and the revoke-subject nuance

Three new contract tests, per spec acceptance:

1. `domains/tokenanomaly`: a recording `ThreatExecutor` (via
   `WithThreatExecutor`, `detector.go:172-178`) receives
   `Threat{Type: "velocity", Severity: "critical", SubjectID, ClientID,
   Evidence["geos"] == "CN,US", Evidence["count"] == "2"}` from a
   `velocity` finding; `threatExec == nil` stays a no-op (existing guard,
   `detector.go:406`).
2. `cmd/sso-server/serverbuildplatform` (or `domains/threataction`):
   `BuildThreatAction` (build_governance.go:338 `WithDefaultAction`) +
   `NewThreatExecutors` + a policy matching `type: velocity` →
   `ActionRevoke` executes and the audit event carries `threat.type=velocity`.
3. Policy conditional: `conditions: {key: "geos", operator: "exists"}`
   matches only when the geo set is present (empty Evidence ⇒ no match ⇒
   `default_action`/`noop`).

**Design note — what "revoke executes" means for geo findings.** Neither
detector populates `Threat.FamilyID` today (`actions.go:23-26` documents
this for both `anomaly.Runner` and `tokenanomaly.Detector`). The
`RevokeFamilyExecutor` therefore takes its subject-scoped fallback for a
`velocity` finding (`actions.go:142-148`: `FamilyID == ""` ⇒
`revokeSubject`, which kills the subject's refresh tokens for the threat's
ClientID). The contract test asserts `ActionRevoke` with `OK: true` via
that fallback — geo findings always carry `SubjectID`. Carrying the actual
`FamilyID` onto `Finding`/`Threat` would require plumbing the family id out
of the refresh stores into the metering Event — a store/interface change
explicitly out of scope; documented here so the test's expectation is
deliberate, not accidental. (`revokeSubject` with empty ClientID mirrors
`DeleteAllForSubject`'s own "every client" semantics, so the fallback is
safe if a finding lacks ClientID.)

## Decision 9: documentation surface

- `docs/feature-matrix.md` and the `docs/config-reference.md:649` Token
  Anomaly block: state that `multi_geo`/`velocity` require `geo.*` +
  `WithGeoProvider` wiring (the static backend, config-reference:381, is
  wired unconditionally and no-ops on nil — so an operator enabling
  `token_anomaly` without geo sees zero geo findings, which is correct
  fail-open behavior, now documented rather than surprising).
- `docs/config-reference.md` threat_action block: document the geo threat
  type wire strings (`multi_geo`, `velocity`) and the two conditions levers
  from Decision 7, so operators can seed policies without guessing.
- `docs/error-codes.md`: no change (no new `Err*`; the only new error
  surface is `GenerateAuthCodeBytes` failing at JTI stamping, which wraps
  through the existing issue path).

## Failure modes

| Failure | Behavior | Why safe |
|---|---|---|
| No `WithGeoProvider` / nil provider | `CountryCodeFromContext` → `""` at all five seams; Events byte-identical to today | zero-value fail-open; middleware no-ops on nil provider (`middleware.go`) |
| Geo lookup timeout / `ErrNotFound` / bad IP | middleware stashes nothing; same `""` | `DefaultLookupTimeout` 200ms caps hot-path cost; failure is silent by design |
| Recorder queue full | Offer drops the Event (drop-on-full) | unchanged; telemetry loss never adds `/token` latency |
| `GenerateAuthCodeBytes` fails at JTI stamp | issue fails loud through existing error wrap | token issuance is allowed to fail; a failed *telemetry id* must not be silently empty on a fresh grant — actually it would be `""` if we swallowed; we do not swallow: the wrap is the existing issue-path contract |
| Rotation on a pre-JTI binary (mid-rollout) | new leaf has `JTI == ""` | `Thumbprint == ""` ⇒ observation not recorded ⇒ pre-feature behavior, byte-identical |
| Legacy sqlite rows / old redis blobs | `jti` reads `""` | additive migration default; no backfill needed (a JTI is only useful from issue onward) |
| SQLite v8 migration failure | boot fails loud via `migrate.CheckSchema` | same contract as v3-v7; column add is idempotent |
| Policy store outage at dispatch | composite logs, falls back to `defaultPolicy` (or noop) | existing fail-open (`registry.go:93-101`) |
| Executor panic during dispatch | `processFindingSafe` recover() confines it | existing (`detector.go:383-397`) |
| `rate_limit` on a geo policy | action fires at most `max`/`per_window` per (subject,type,action) | existing composite behavior; test seeds no rate limit |
| Clock skew on `At` | observation uses recorder-stamped `At` or detector clock | `updateGeoLocked` abs()s the gap; velocity gap is a minimum, skew only delays/advances the finding |
| Cross-replica token usage | observations are per-replica (Detector is in-process) | pre-existing wave-1 limitation, unchanged; a token split across two replicas in two countries is not combined — see "What could break" |

## What could break the design

1. **Import-direction regression.** `protocols/oauth -> platform/geo` is the
   only new edge. If a future change makes `platform/geo` import `protocols`
   or `domains/tokenanomaly`, the cycle breaks the build. The extractor must
   stay dependency-free (only `shared/core`). The architecture gate
   (`TestArchitecture_*`) catches violations.
2. **File budgets.** `interfaces/sso/server_helpers.go` is 493 lines
   (ceiling 500). `offerUsage` + the three literal rework push it over.
   Mitigation already in the spec: land the helper in a new small
   `interfaces/sso/server_usage_geo.go`. `domains/tokenanomaly` root is at 5
   non-test files (ceiling 10) — no new file needed there; `dispatchThreat`
   edit stays within `detector.go` (function is ~20 lines, well under 50).
3. **`recordIntrospectionUsage` signature change.** Package-private with one
   caller — but if a future caller forgets `ctx`, the seam silently emits
   `GeoCountry == ""` (fail-open, compiles fine). The seam test in
   Improvement 1 pins both branches, so a regression is caught.
4. **`RefreshAuthContext.JTI` vs positional `jti`.** If a rotation caller
   builds `RefreshAuthContext` from a non-`info` source (e.g. token-exchange
   minting a *new* family with a caller-supplied context), JTI is empty and
   the fresh-family branch stamps a new one — correct. The failure mode to
   watch is the opposite: a *rotation* that accidentally constructs an empty
   context, silently breaking thumbprint continuity across the family chain
   (token looks like a different token after rotation). The store
   conformance test (Issue → Inspect round-trip) plus the seam test on
   `introspectRefresh` pin the propagation.
5. **`count` semantics drift.** `Finding.Count` is sightings for geo
   findings (per-token) but latest-minute count for `rate_spike`. A policy
   using `count gt N` must be scoped by `type: velocity|multi_geo` or it
   silently means something different for spikes. Documented in
   config-reference; the conditional test uses the geo types only.
6. **The `geos` string contract.** `eq` matching depends on the sorted
   comma-join being stable. `geoFinding` sorts (`detect.go`); a future
   refactor that changes ordering breaks `eq` policies silently. The
   dispatch contract test asserting `"CN,US"` pins it.
7. **Mixed-version fleet semantics.** New binary issuing refresh tokens
   with JTI while old replicas introspect them: old `introspectRefresh`
   doesn't stamp Thumbprint — no observation, pre-feature behavior. Safe
   but invisible; no cross-version break.
8. **`ActionRevoke` for geo findings revokes subject-scoped, not
   family-scoped.** If an operator's mental model is "revoke this token's
   family", the subject fallback is broader (every refresh token the user
   holds for the client). This is the existing, documented behavior of the
   executor (`actions.go:23-26`); the design does not change it, but the
   policy-routing test must assert the fallback path so the contract is
   explicit.
9. **Per-replica observation tables.** `multi_geo`/`velocity` only fire
   when both geo sightings reach the SAME replica's Detector within
   `window`. A load-balanced fleet where replica A sees country X and
   replica B sees country Y never combines the evidence. This is a
   pre-existing wave-1 architecture limit (in-process observation table,
   no shared store), not a regression — but the feature's flagship promise
   is bounded by it, and the spec's E2E must use a single-server harness.
   Flagged here because an operator could reasonably expect cross-replica
   detection after this change.
10. **Docs contract drift.** `docs/config-reference.md` and
    `docs/feature-matrix.md` must be updated in the same change as the code
    (AGENTS.md §5). `make ci` validates config-reference against
    `config.ThreatActionConfig`; the `multi_geo`/`velocity` wire strings
    are constants in `threataction`/`tokenanomaly`, so docs can cite them
    without duplication.

## File change map

```text
platform/geo/middleware.go (or geo.go)      + CountryCodeFromContext + test
interfaces/sso/server_usage_geo.go (new)    offerUsage helper (if budget requires)
interfaces/sso/server_helpers.go            three record*Issued delegate to offerUsage
protocols/oauth/introspect_body.go          recordIntrospectionUsage(ctx, ...) + GeoCountry
protocols/oauth/handle_introspect.go        introspectRefresh: GeoCountry + Thumbprint(info.JTI)
protocols/oauth/oauthspi/refresh_token.go   RefreshToken.JTI + RefreshAuthContext.JTI
protocols/oauth/oauthwire/auth_code_handler.go  IssueRefreshTokenParams.JTI + fresh-branch stamp
internal/handler/tokengrant/token_refresh.go    refreshRotateFamily threads JTI: info.JTI
interfaces/sso/server_oauth.go              issueRefreshToken maps authCtx.JTI
interfaces/sso/accessors_handlers.go        no change (bucket already a param)
infrastructure/defaultimpl/memorystoreoauth/memory_refresh_token.go   JTI copy
infrastructure/redis/refresh_token.go       struct tag only (automatic)
infrastructure/defaultimpl/sqlite/refresh_tokens_schema.go  v8 migration + baseline DDL
infrastructure/defaultimpl/sqlite/refresh_tokens.go        INSERT/SELECT/scan columns
domains/tokenanomaly/detector.go            dispatchThreat Evidence geos/count
domains/tokenanomaly/ + build_governance tests          3 contract tests
docs/feature-matrix.md, docs/config-reference.md        geo prerequisite + threat wire strings
```

## Verification

Per spec: `go build ./... && go vet ./...`; `go test -run
'TestMaintainability_|TestArchitecture_' .` after every `.go` edit;
`go test ./... -race`; `go test ./test/ -run TestE2E -v`; `make ci`.
Store conformance: `IssueRefreshToken` → `Inspect` round-trips JTI on
memory/redis/postgres peers. The single commit per improvement rule and the
AI co-author trailer apply.
