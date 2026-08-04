# Requirements Specification — domains/region, Direction 1: Observability for the fail-open residency control

Source analysis: `docs/architect-analysis/auto/domains-region-analysis.md` §1. Scope: decision metrics and
failure alerting for the data-residency governance layer. The three improvements below are
independent, additive, and never change wire behavior, the oracle-safe tables, or the
fail-open decision order in `interfaces/sso/server_tenant_residency.go`.

Design constraints honored throughout:

- `domains/region` must not import `platform/metrics` (imports flow downward; domains is
  above platform). Metrics observe sites live in `interfaces/sso`; the resolver-failure hook
  is wired at `cmd/sso-server` through the existing `MiddlewareOptions.OnError` seam.
- `interfaces/sso` is at its 60-file ceiling (AGENTS.md §2). All sso-side changes extend
  existing files (`server_tenant_residency.go`, `accessors.go`); no new file there.
- `platform/metrics/metrics_ctor.go` is at 497/500 lines. New metric registration goes in a
  new file `platform/metrics/residency.go`, following the `conditional_access.go` split
  precedent.
- Every counter is nil-safe at the observe site (`m == nil || vec == nil` → no-op), so a
  build without `WithMetrics` stays byte-identical.
- Label cardinality stays bounded (§5 of `platform/metrics/metrics.go`): `code`, `reason`,
  `outcome`, `surface` are closed sets; `region` is operator-config-bounded (the same
  justification as the existing `provider` label).

## 1. Residency decision and cache counters: make every enforcement verdict countable

**Name**: `sso_residency_decisions_total{code,region,surface}` + `sso_residency_cache_total{outcome}`.

**Problem**: the residency engine is the only enforcement layer in the server with zero
metrics. An operator cannot quantify how many mints or reads were denied per region or per
surface, cannot compute an enforcement rate for compliance evidence, cannot see whether the
60s policy cache is actually absorbing tenant-store load, and cannot distinguish "control
silently off" from "control active and allowing". The mesh read-gate DENY
(`interfaces/sso/mesh_authz.go:197`) is deliberately binary on the wire, which makes a
server-side counter the ONLY way to see residency-driven mesh denials at all.

**Evidence**:
- `interfaces/sso/server_tenant_residency.go` — `checkTenantResidency` (decision ladder,
  early returns at steps 1–7) and `resolveResidencyPolicy` (cache `get`/`put`); neither
  touches `s.metrics`.
- `interfaces/sso/server_helpers.go:280` — `recordLoginFailure` is the existing precedent
  for a nil-safe metrics bump beside an audit event.
- `platform/metrics/conditional_access.go` — `registerConditionalAccessMetrics` +
  `ObserveConditionalAccessDecision` (CounterVec + nil-safe observe pattern to copy);
  registration call at `platform/metrics/metrics_ctor.go:54`.
- `platform/metrics/metrics.go:383-387` — `DegradedRejectionsTotal` CounterVec precedent
  (labels: mode, method — bounded).
- Gate call sites that must be labeled: `server_login_client.go:50` (interactive login),
  `server_login_resolve.go:163` (prompt=none), `server_mfa.go:382` +
  `server_mfa_trust.go:341` (MFA legs), `server_tenant.go:412` (token grant),
  `accessors.go:246/340` (read gates), `mesh_authz.go:197` (mesh).

**Proposed behavior**:
- New file `platform/metrics/residency.go` with `registerResidencyMetrics(factory, m)`,
  called from `NewWithRegistry` in `metrics_ctor.go`, registering:
  - `ResidencyDecisionsTotal *prometheus.CounterVec` — `sso_residency_decisions_total`,
    labels `{code, region, surface}`. `code ∈ {allow, region_not_allowed,
    residency_violation}` (closed set — the two wire codes plus the allow verdict);
    `region` = serving-region ID (operator-config-bounded, empty-string label for
    unconstrained); `surface ∈ {login, token_grant, userinfo, mesh, me}` (closed set, one
    value per gate call site).
  - `ResidencyCacheTotal *prometheus.CounterVec` — `sso_residency_cache_total`, labels
    `{outcome ∈ {hit, miss}}` (mirrors the `ClientStoreCacheTotal` shape). Cache hit rate
    is `sum(rate(...{outcome="hit"})) / sum(rate(...))`.
  - Nil-safe observers `ObserveResidencyDecision(code, region, surface string)` and
    `ObserveResidencyCache(outcome string)` on `*Metrics`, matching the
    `ObserveConditionalAccessDecision` idiom.
- Extend the unexported `checkTenantResidency(ctx, tenantID, servingRegion, isWrite)` with
  a `surface string` parameter (4 internal call sites: `residencyGateLogin`,
  `residencyDeniedForAccess`, `server_tenant.go:412`, `ResidencyDecision`). Observe the
  verdict in the single choke point: `evaluateResidency` result → `allow` or the mapped
  wire code, with the serving region and surface. This guarantees every gate labels
  identically (no copy-paste drift, matching the design rationale already documented on
  `residencyGateLogin`).
- Observe cache hit/miss inside `resolveResidencyPolicy` (both the `get` hit branch and
  the store-read + `put` path).
- Add `ResidencyDecisionsTotal`, `ResidencyCacheTotal`, and the two observers to
  `platform/metrics/metrics.go` struct with doc comments stating zero-traffic-when-unwired,
  and the two name constants to `platform/metrics/consts.go` (wire contract — `sso_`
  prefix).

**Acceptance check**:
- New unit test `platform/metrics/residency_test.go`: register via `NewWithRegistry`,
  fire the observers, scrape the registry, assert label sets and values; assert the
  observers are nil-safe on a bare `&Metrics{}`.
- New server test in `interfaces/sso` (extend an existing residency test file):
  `WithTenantResidencyCheck` + `WithMetrics` → a denied mint increments
  `sso_residency_decisions_total{code="region_not_allowed", surface="login"}` by 1 and an
  allowed mint increments `code="allow"`; with the engine unwired the series stays absent
  (byte-identical off).
- Existing residency e2e in `test/` stays green; add one scrape assertion on a
  mesh-DENY case (`surface="mesh"`) to the mesh e2e.
- `go build ./... && go vet ./...` and `go test -run 'TestMaintainability_|TestArchitecture_' .`
  pass (no new package in `interfaces/sso`, no `domains/region` change, no upward import).

## 2. Fail-open and resolver-failure alerting: a safety net for the silent-degrade default

**Name**: `sso_residency_failopen_total{reason}` + `sso_residency_enabled` +
`sso_region_resolution_errors_total`, plus alert rules in `ops/deploy/grafana/alerts.yaml`.

**Problem**: residency is an explicit fail-open control — a tenant-store partition must not
4xx the fleet — but the ONLY trace of a fail-open episode is one `logger.Error` line in
`resolveResidencyPolicy`. There is no counter, no gauge, and no alert rule; a store outage
silently turns the control off for the whole window. Every other fail-open subsystem in the
codebase has a metric-and-alert safety net (risk scorer: `SSORiskScorerSilent`; signing-key
aggregation: `SSOSigningKeyAggregationDegraded`; signing backend: `SigningBackendUp`
gauge). Region resolution failures are likewise only logged, because
`MiddlewareOptions.OnError` is wired to a logger alone.

**Evidence**:
- `interfaces/sso/server_tenant_residency.go` — the fail-open branch of
  `resolveResidencyPolicy` (`if err != nil && s.logger != nil { s.logger.Error("tenant
  residency check: tenant store lookup failed; failing open", ...) }`); also the
  `s.tenantStore == nil` early return (engine enabled without a store — a second,
  misconfiguration-shaped fail-open).
- `domains/region/middleware.go:14-19` — `MiddlewareOptions.OnError` is the only
  resolution-failure hook ("Optional — resolution failures stay non-fatal").
- `cmd/sso-server/build_app_selfservice.go:256-262` — the OnError wiring maps to
  `b.logger.Error("region resolution failed", ...)` and nothing else.
- `ops/deploy/grafana/alerts.yaml:89-108` — `SSORiskScorerSilent`: "errors are
  intentionally fail-open per the SPI contract — alert is the safety net"; and
  `:210-228` — `SSOSigningKeyAggregationDegraded` gauge-alert precedent.
- `platform/metrics/metrics.go` — `SigningBackendUp` gauge precedent ("a directly
  alertable gauge that fires BEFORE /readyz drains"); `FeatureGateEnabled` is the
  boot-time set-once gauge precedent for `sso_residency_enabled`.

**Proposed behavior**:
- In `platform/metrics/residency.go` (same new file as improvement 1), register:
  - `ResidencyFailOpenTotal *prometheus.CounterVec` — `sso_residency_failopen_total`,
    labels `{reason ∈ {store_error, store_unwired}}` (closed set). `store_error` = a
    tenant-store lookup failed; `store_unwired` = `WithTenantResidencyCheck` was called
    but no `tenantStore` is wired (config mistake worth surfacing).
  - `ResidencyEnabled prometheus.Gauge` — `sso_residency_enabled`, set to 1 in
    `WithTenantResidencyCheck` (boot-time, matches `FeatureGateEnabled` semantics; never
    set when the option is not used, so `sso_residency_enabled == 1` keys all residency
    alert expressions).
  - `RegionResolutionErrorsTotal prometheus.Counter` — `sso_region_resolution_errors_total`
    (no labels; bounded).
  - Nil-safe observers `ObserveResidencyFailOpen(reason string)` and
    `ObserveRegionResolutionError()`.
- Increment `ObserveResidencyFailOpen("store_error")` in the `resolveResidencyPolicy`
  error branch (beside the existing log line — the log stays, the counter makes it
  alertable) and `"store_unwired"` in the `s.tenantStore == nil` branch; set
  `ResidencyEnabled` to 1 in `WithTenantResidencyCheck` (via a nil-safe setter).
- Wire `ObserveRegionResolutionError` into `cmd/sso-server/build_app_selfservice.go`
  (`b.metricsRegistry` is already a field on `appBuilder`, see `build_app.go:69`): the
  `OnError` callback keeps the log line and additionally bumps the counter.
- Add two rules to `ops/deploy/grafana/alerts.yaml`, following the `SSORiskScorerSilent`
  annotation style:
  - `SSOResidencyFailOpen`: `sso_residency_enabled == 1 and
    sum(increase(sso_residency_failopen_total[5m])) > 0` for 10m, severity `warning` —
    "tenant-store outage window; residency control is failing open". Description must
    state the design intent (availability over strictness, mirroring the fail-open
    rationale comment on `checkTenantResidency`) and point at the `region_not_allowed`
    audit trail for the window.
  - `SSORegionResolutionDegraded`: `increase(sso_region_resolution_errors_total[10m]) > 0`
    for 15m, severity `warning` — malformed/absent region source; requests are being
    served unconstrained.

**Acceptance check**:
- Server test with an injected failing `tenant.Store` (error-returning fake) + `WithMetrics`:
  a gated request increments `sso_residency_failopen_total{reason="store_error"}` and the
  request is still allowed (fail-open semantics byte-identical); `sso_residency_enabled`
  reads 1 after `WithTenantResidencyCheck` and is absent without it.
- Test for the cmd wiring: the `OnError` closure in `wireRegion` bumps
  `sso_region_resolution_errors_total` (cmd test or covered by an existing
  build_app_coverage test path).
- `promtool check rules ops/deploy/grafana/alerts.yaml` passes (or manual review of the two
  new expressions if promtool is unavailable).
- `go build ./... && go vet ./...`; targeted `go test ./interfaces/sso/ ./platform/metrics/`
  green; `go test ./test/ -run TestE2E -v` green (no wire change).

## 3. Read-gate denial audit trail and the observability contract document

**Name**: server-side audit event for read-gate residency denials + a Residency section in
`docs/observability.md`.

**Problem**: the write gates emit `login_failure` audit events with the wire reason
(`recordLoginFailure` → `audit.RecordLoginFailure`), so a denied mint is provable. The
read gates (`/userinfo`, mesh ext_authz, `/me`) emit NOTHING on a residency denial — no
audit event, and the mesh DENY is binary by oracle-safe design
(`mesh_authz.go:197` → `meshDenyInvalidToken`, "Access denied"). For compliance evidence
("the read side was actually enforced in region X during incident window W") the record
does not exist. Separately, `docs/observability.md` has zero residency content (0 matches
for region/residency), so neither the existing `region.serving` audit enrichment nor the
fail-open contract is discoverable, and the new counters from improvements 1–2 would ship
undocumented — a contract drift risk the repo's own discipline forbids (AGENTS.md §5:
update contracts in the same change).

**Evidence**:
- `interfaces/sso/mesh_authz.go:197` — `if _, denied := s.residencyDeniedForAccess(hctx,
  claims); denied { return s.meshDenyInvalidToken(hctx, res, "Access denied") }`: the
  denial collapses to a body-less binary DENY with no server-side record.
- `interfaces/sso/accessors.go:246-247, 339-341` — `ResidencyGateAccess` /
  `ResidencyDeniedForAccess` (exported read gates, no observation, no audit).
- `interfaces/sso/server_tenant_residency.go:300-307` — `residencyDeniedForAccess`
  returns `(code, true)` and leaves all recording to the caller, which none of the three
  callers does today.
- `platform/audit/handler_helpers.go:19-25, 91-99` — `metaKeyRegionServing = "region.serving"`
  enrichment already exists (server-side only, safe against the wire oracle tables) and is
  undocumented.
- `docs/observability.md` — Metrics table (lines 7-66) and Audit section; grep for
  region/residency: 0 hits.
- `platform/audit/auditreport/drift_test.go` — every new `EventType` must be classified in
  `auditreport` (AGENTS.md §4).

**Proposed behavior**:
- Emit a new audit event `region_denied` from `residencyDeniedForAccess` when it returns
  `(code, true)`, carrying metadata via `audit.SetMeta`: `region.serving` (already the
  canonical key), the tenant ID, the surface (`userinfo` / `mesh` / `me`), and the wire
  code. The event is server-side only — it never changes the 403 body or the binary mesh
  DENY, so the oracle-safe table in AGENTS.md §3 is untouched. Classify the new event type
  in `platform/audit/auditreport` (SOC2/bucketing), per the drift test.
- Write-gate parity stays as-is (`login_failure` with `region_not_allowed` /
  `residency_violation` reasons already covers mints; no change).
- Add a `### Residency` subsection to `docs/observability.md` documenting: the three
  counters from improvements 1–2 with exact names/labels/zero-traffic conditions;
  `sso_residency_enabled`; the fail-open contract and the two alert rules; the audit
  events (`login_failure` with residency reasons, `region_denied`, `region.serving`
  metadata enrichment). Add the counters to the Metrics table so the table and the code
  constants cannot drift silently (same review path as every other metric row).
- `docs/error-codes.md` `region_not_allowed` row: add a one-line pointer to the
  observability section (no semantic change to the documented disposition).

**Acceptance check**:
- New audit test: a region-denied read (`residencyDeniedForAccess` denial path) yields one
  `region_denied` event carrying `region.serving`, tenant, surface, and code; a mesh DENY
  still renders the byte-identical binary 401 (asserted by the existing mesh e2e).
- `platform/audit/auditreport` drift test passes with the new event type classified
  (`go test ./platform/audit/...`).
- `docs/observability.md` Metrics table rows match `platform/metrics/consts.go` names
  exactly (manual cross-check in review; no automated doc-lint exists for this table).
- `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .`
  green; full `make ci` green before handoff.
