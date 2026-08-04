# domains/tokenanomaly — 方向 1 需求规格：打通 Geo 信号链路（multi_geo / velocity 从死代码到生产可用）

Scope: expansion direction 1 from `docs/auto/domains-tokenanomaly-analysis.md` —
「打通 Geo 信号链路：multi_geo / velocity 两个旗舰信号在生产路径上是死代码」.

Today the module's two flagship signals can never fire in production: no
production `metering.Event` ever carries a `GeoCountry`, so
`Detector.detectGeoVelocity`'s `len(o.geos) >= 2` gate is unreachable — only
per-client `rate_spike` works. The geo context needed to fix this already
exists on the request path (`WithGeoProvider` + `GeoFromHandlerContext`), and
the login-side `anomaly` subsystem already consumes it; the token-usage Offer
seams simply never read it. Downstream, `ThreatMultiGeo`/`ThreatVelocity`
are defined and `dispatchThreat` forwards them, but production never
receives such a Threat.

This spec contains exactly three evidence-backed improvements:

1. Fill `GeoCountry` at all five token-usage Offer seams (the data-source
   wiring — the root fix).
2. Close the refresh-introspection hole: that seam's Event carries no
   Thumbprint, so even geo-enriched refresh presentations never reach the
   per-token observation table.
3. Activate and verify the response chain: carry the geo set into
   `Threat.Evidence` and prove geo findings route through policies to
   actions.

## Preserved invariants (non-negotiable)

- Coarse-geo privacy boundary: only ISO-3166-1 alpha-2 `CountryCode` may
  flow into `metering.Event.GeoCountry`. Never an IP, city, region,
  latitude/longitude, or time zone. `Finding.Geos` stays the only
  aggregation surface; no new PII is introduced (subject id remains the
  single PII field).
- Zero-value byte-identity: no `WithGeoProvider` / no geo in context ⇒
  `GeoCountry` stays `""` and every Offer emits byte-identical Events to
  today (fail-open — detection never escalates a missing geo source).
- Oracle-safe and hot-path contracts are untouched: Offer points stay
  off-path best-effort (drop-on-full queue), `/token/introspect` response
  bodies are unchanged, and no change may alter a grant/introspect
  decision.
- Detection remains REPORTING/ACTION off the request path: findings never
  feed an auth decision; `dispatchThreat` stays fail-open with logged
  executor errors.
- Import direction: `protocols/oauth` must not import `interfaces/sso`;
  the geo extractor lives where both layers can reach it (`platform/geo`
  or the `protocols/oauth` package itself), mirroring how
  `introspect_body.go` already calls `metering.Thumbprint`.
- Budgets: no new top-level packages; additions land in existing files
  (`interfaces/sso/server_helpers.go` is large — prefer a new small
  `interfaces/sso/server_usage_geo.go` if the helper pushes a file past
  budget); `domains/tokenanomaly` root stays at 5 non-test files.
- No `layerExemptions`, no new nested modules, no `go.mod` changes.

## Improvement 1: 五个 Offer 握手点写入粗粒度 GeoCountry（数据源打通）

**Problem**: `multi_geo` / `velocity` — the module's flagship per-token
signals — are dead code in production. All five `metering.Event` Offer
sites omit `GeoCountry`, so `updateGeoLocked` no-ops on `""` and
`detectGeoVelocity`'s `len(o.geos) < 2` gate can never pass. The only
`GeoCountry:` assignments in the repository are in test files. The geo
source already exists on the same request path: `WithGeoProvider` installs
GeoMiddleware ahead of all routes, handlers read it via
`GeoFromHandlerContext`, and the login-side `recordLoginAttempt` already
consumes it — the token-usage seams simply never do.

**Evidence**:
- `interfaces/sso/server_helpers.go:428-453` — `recordTokenIssued`,
  `recordRefreshTokenIssued`, `recordIDTokenIssued` Offer `metering.Event`
  literals with no `GeoCountry`.
- `protocols/oauth/handle_introspect.go:357` and
  `protocols/oauth/introspect_body.go:21` — the two introspect Offers, same
  omission.
- `domains/tokenanomaly/detect.go` `detectGeoVelocity` — `if len(o.geos) < 2
  || o.last.Before(cutoff) { continue }`; `domains/tokenanomaly/detector.go:308`
  `updateGeoLocked` — `if geo == "" { return }`.
- `interfaces/sso/options_misc.go:55-58` — `WithGeoProvider` installs
  GeoMiddleware ahead of all routes; `platform/geo/middleware.go:99`
  `FromHandlerContext`; precedent consumer:
  `interfaces/sso/server_helpers.go:313` (`recordLoginAttempt` fills
  `event.Geo` from `GeoFromHandlerContext`).

**Proposed behavior**:
- Add one canonical coarse-geo extractor, e.g.
  `geo.CountryCodeFromContext(ctx core.HandlerContext) string` in
  `platform/geo` (importable by both `interfaces/sso` and
  `protocols/oauth`), returning `*GeoInfo.CountryCode` when the middleware
  stashed a `*GeoInfo`, else `""`.
- Route all five Offer sites through it:
  - `interfaces/sso`: a single `s.offerUsage(ctx, ev metering.Event)`
    helper that stamps `ev.GeoCountry = geo.CountryCodeFromContext(ctx)`
    and calls `s.tokenUsageRecorder.Offer(ev)`; the three
    `record*Issued` helpers build the Event and delegate.
  - `protocols/oauth`: `recordIntrospectionUsage` and the
    `introspectRefresh` Offer call the same extractor.
- No geo provider wired / lookup failed ⇒ `""` ⇒ byte-identical behavior
  (fail-open, no signal).
- Update `docs/feature-matrix.md` (or `docs/config-reference.md` line 649
  block) to state that `multi_geo`/`velocity` require `WithGeoProvider`.

**Acceptance check**:
- Unit: extractor returns the country code from a stubbed
  `core.HandlerContext` with a `*GeoInfo` and `""` without one.
- Seam tests: each of the five Offer sites, run with a stubbed geo
  context, produces an Event whose `GeoCountry` equals the stubbed
  `CountryCode`; without geo context the Event is byte-identical to today
  (`GeoCountry == ""`).
- Pipeline test: two `Offer`ed Events for one thumbprint from two
  countries — gap > `VelocityGap` yields a `warn` `multi_geo` finding;
  gap <= `VelocityGap` yields a `critical` `velocity` finding, visible via
  `Detector.Findings().List` after `Analyze`.
- Gates: `go build ./... && go vet ./...`,
  `go test -run 'TestMaintainability_|TestArchitecture_' .`,
  `go test ./... -race`, `make ci` all green.

## Improvement 2: refresh-introspect 展示链路补齐 Thumbprint，让 EndpointIntrospect 事件进入逐 token 观测表

**Problem**: Even after improvement 1, one geo-carrying seam cannot feed
the per-token signals: the refresh-token introspection Offer
(`handle_introspect.go:357`) sets no `Thumbprint`, and
`Detector.Record` only captures observations when
`ev.Thumbprint != ""` — so a stolen refresh token presented via
`/token/introspect` from a second country is invisible to
`multi_geo`/`velocity`. Root cause: the `RefreshToken` record has no JTI
(fields: `UserID`, `ClientID`, `Provider`, `Scopes`, `Attributes`,
`IssuedAt`, `ExpiresAt`, `FamilyID`, `Resources`,
`AuthorizationDetails`), unlike access tokens whose jti is a first-class
claim (`introspect_body.go:90-91`). The access-token introspect seam
already stamps `Thumbprint: metering.Thumbprint(claims.JTI)` —
proving the intended pattern and the asymmetry.

**Evidence**:
- `protocols/oauth/handle_introspect.go:357-362` — Event with
  `Kind: KindRefresh, Endpoint: EndpointIntrospect` and no `Thumbprint`.
- `protocols/oauth/oauthspi/refresh_token.go:25-43` — `RefreshToken` struct
  without a JTI field; `RefreshTokenInspector.Inspect` (line 194-197)
  returns `*RefreshToken`, so a stamped JTI surfaces to the seam with no
  interface change.
- `domains/tokenanomaly/detector.go:257` — `if ev.Thumbprint != "" {
  d.recordObservation(ev) }`.
- `protocols/oauth/introspect_body.go:21-29` — the working pattern:
  `Thumbprint: metering.Thumbprint(claims.JTI)`.

**Proposed behavior**:
- Add `JTI string` to `RefreshToken`; stamp it at issue (the "new family"
  branch of `IssueRefreshToken`, cf.
  `protocols/oauth/oauthwire/auth_code_handler.go:238-244`) and propagate
  it unchanged through rotation (same discipline as `FamilyID`).
- `introspectRefresh` sets `Thumbprint: metering.Thumbprint(info.JTI)` on
  the Offer (plus `GeoCountry` from improvement 1's extractor).
- Update every `RefreshTokenStore` implementation (memory, redis, postgres)
  with the additive field; empty JTI for legacy rows ⇒ `Thumbprint == ""`
  ⇒ today's behavior.
- Privacy unchanged: `Thumbprint` remains SHA-256(jti), never the token
  value; JTI is not PII.

**Acceptance check**:
- Store conformance: memory/redis/postgres refresh stores round-trip JTI
  through `IssueRefreshToken` → `Inspect`.
- Seam test: introspection of an active refresh token yields an Event with
  `Thumbprint == metering.Thumbprint(jti)` and the geo from context.
- Pipeline test: two introspect Events for the same refresh token from two
  countries within `VelocityGap` produce a `critical` `velocity` finding.
- Regression: existing introspection oracle-safety tests (unknown/expired
  → `{"active":false}`, no-store headers) unchanged and green.
- Gates: `go test ./... -race`, `make ci`.

## Improvement 3: 响应链激活：Geos 进入 Threat.Evidence，端到端契约测试证明 geo finding 可路由、可执行、可观测

**Problem**: The response end of the geo chain is unverified and
underspecified. `ThreatMultiGeo`/`ThreatVelocity` exist and
`dispatchThreat` forwards, but (a) `dispatchThreat`'s `Evidence` map
carries only `token_thumbprint` and `detail` — the geo set, the entire
evidentiary basis of the finding, is dropped before policy evaluation and
audit, so a conditional policy (e.g. "revoke only when >= 3 geos") is
impossible and the `threat_action_executed` audit event lacks geo context;
(b) no test anywhere proves a geo finding dispatches with the correct
`Threat.Type` or that a policy-matched action actually executes — the
Finding → `ThreatExecutors` → policy → `ActionRevoke` chain is verified
only by code reading; (c) because of improvement 1's root cause,
production has never delivered a `multi_geo`/`velocity` Threat, so the
`BuildThreatAction` `default_action` wiring
(`cmd/sso-server/serverbuildplatform/build_governance.go:338`) has never
been exercised for geo types.

**Evidence**:
- `domains/threataction/threataction.go:109-110` — `ThreatMultiGeo`,
  `ThreatVelocity` constants (wire strings identical to `Finding*`).
- `domains/tokenanomaly/detector.go:405-426` — `dispatchThreat` builds
  `Evidence{"token_thumbprint": …, "detail": …}`; `f.Geos` never leaves
  the finding, and `threatExec.Execute(ctx, threat,
  threataction.ThreatPolicy{})` passes an empty policy — routing depends on
  the registry's policy store, which has no geo-type coverage test.
- `cmd/sso-server/serverbuildplatform/build_governance.go:338` —
  `WithDefaultAction(threataction.Action(cfg.DefaultAction))` wiring whose
  behavior for `multi_geo`/`velocity` threats is untested.

**Proposed behavior**:
- `dispatchThreat` adds `"geos"` (comma-joined sorted set) and `"count"`
  to `Threat.Evidence`; keep the 1:1 type mapping
  (`FindingMultiGeo` → `ThreatMultiGeo`, `FindingVelocity` →
  `ThreatVelocity` — the wire strings already match).
- Add contract tests:
  - `domains/tokenanomaly`: with a recording `ThreatExecutor` (via
    `WithThreatExecutor`), a `velocity` finding dispatches
    `Threat{Type: "velocity", Severity: "critical", SubjectID, ClientID,
    Evidence["geos"] == "CN,US"}`; a nil executor stays byte-identical
    (no dispatch).
  - `cmd/sso-server/serverbuildplatform` (or `domains/threataction`):
    end-to-end — `ThreatExecutors` with a policy matching `velocity` →
    `ActionRevoke` executes (family revoker invoked) and
    `threat_action_executed` audit event carries `threat.type=velocity`.
  - Policy conditional: a policy keyed on
    `evidence.geos` cardinality matches only when the geo set is present.
- Document the geo threat types in the `threat_action` config guidance
  (`docs/config-reference.md`), so operators can seed policies for
  `multi_geo`/`velocity` without guessing wire strings.

**Acceptance check**:
- The three contract tests above pass; `dispatchThreat` with
  `threatExec == nil` remains a no-op (existing behavior preserved).
- `Finding.Geos` and `Finding.Count` round-trip into
  `Threat.Evidence` for both geo finding types.
- Cross-server: `go test ./test/ -run TestE2E -v` green (or an E2E test
  exercising token_anomaly + threat_action with a geo provider and two
  countries asserts one `velocity` finding and one `revoke` action).
- Gates: `go build ./... && go vet ./...`, `make ci`.

## Deliverable shape

- `platform/geo`: `CountryCodeFromContext` (or equivalent) — one small
  file.
- `interfaces/sso`: `offerUsage` helper + wiring in the three
  `record*Issued` helpers; tests.
- `protocols/oauth`: extractor calls in `recordIntrospectionUsage` and
  `introspectRefresh`; JTI field on `RefreshToken` + stamping at issue;
  Thumbprint on the refresh-introspect Offer; store impl updates (memory /
  redis / postgres); tests.
- `domains/tokenanomaly`: `dispatchThreat` Evidence extension; contract
  tests; no detection logic changes.
- Docs: `docs/feature-matrix.md`, `docs/config-reference.md` threat_action
  guidance.
- Single commit per improvement; conventional, imperative, AI co-author
  trailer; contracts updated in the same change.
