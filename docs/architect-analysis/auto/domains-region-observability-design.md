# Design: `domains/region` observability — countable enforcement, fail-open alerting, read-gate audit trail

Design counterpart to `docs/architect-analysis/auto/domains-region-observability-spec.md`. Covers
the API surface, storage model, failure modes, and breakage risks for the
three improvements. Every decision below was checked against current code,
the AGENTS.md budgets, and the compile-enforced contract tests that a new
audit event type must satisfy; where the spec left an ambiguity (cache
hit/miss semantics, exported-seam threading, closed-set label mapping), this
document pins the exact behavior.

Layer map used throughout:

```text
composition (cmd/sso-server)                     ← wires RegionResolutionErrorsTotal
  → interfaces/sso (server_tenant_residency.go)  ← observes decisions/cache/fail-open, emits audit
  → protocols (oidc/userinfo, selfservice /me)   ← consume exported read gates (unchanged)
  → domains (region, tenant)                     ← UNCHANGED — never imports platform/metrics
  → platform (metrics, audit, auditreport)       ← new file residency.go, new event type
```

Non-negotiable constraints re-verified against source:

- `interfaces/sso` is at its 60-file ceiling: every sso-side edit extends
  `server_tenant_residency.go` or `accessors.go`; no new file there.
- `platform/metrics/metrics_ctor.go` is at 497/500 lines: the registration
  call is one added line (→ 498); the register function body lives in the new
  `platform/metrics/residency.go`, following the `conditional_access.go`
  precedent.
- `domains/region` and `domains/tenant` change nothing. The resolver-failure
  counter is bumped in `cmd/sso-server/build_app_selfservice.go`
  (`wireRegion`, line 242), which already holds `b.metricsRegistry`
  (`build_app.go:69`).
- Every observe site is nil-safe (`m == nil || vec == nil` → no-op), so a
  build without `WithMetrics` stays byte-identical, including the wire.

## Decision: one observation choke point for residency verdicts — thread `surface` through `checkTenantResidency`

### Problem restated

`checkTenantResidency` (`interfaces/sso/server_tenant_residency.go`) is the
single enforcement ladder every gate funnels through, and it has zero
`s.metrics` contact. The mesh read-gate DENY (`mesh_authz.go:197`) is
deliberately binary on the wire, so a server-side counter is the only
observable of residency-driven mesh denials. The fix is one observation
point, not eight.

### API surface

**1. `checkTenantResidency(ctx, tenantID, servingRegion, isWrite, surface)`**
gains a `surface string` parameter. The four internal call sites supply one
closed-set value each:

| Call site | surface | Wire shape it backs |
|---|---|---|
| `residencyGateLogin` (`server_tenant_residency.go`) | `login` | `/auth/login` direct/code mint, prompt=none silent renewal (`server_login_client.go:50`, `server_login_resolve.go:163`), MFA legs (`server_mfa.go:382`, `server_mfa_trust.go:341`) — all four funnel here, one label value |
| `residencyDeniedForAccess` | its own `surface` param (below) | `/userinfo`, mesh, `/me` reads |
| `server_tenant.go:412` | `token_grant` | `/token` grants post-client-auth (authz-code exchange, refresh, token-exchange, CIBA, device, client_credentials) |
| `ResidencyDecision` | its own `surface` param (below) | raw-handler mints (WebAuthn) + `/me` writes |

The observation happens at exactly one place — the `evaluateResidency` call
site — so every gate labels identically and there is no copy-paste drift.
Verdict mapping is an explicit `errors.Is` ladder onto the closed set
`{allow, region_not_allowed, residency_violation}` — NEVER
`s.mapResidencyError`'s `access_denied` default, which would inject an
unclosed label value. (`evaluateResidency` can only return the two sentinels
or nil today, but the observe site must not inherit a future default's label.)

**2. `residencyDeniedForAccess(hctx, claims, surface)`** gains a `surface`
param; its three callers pass their own value. `mesh_authz.go:197` passes
`mesh`; the two exported wrappers hard-code their known surface internally so
the cross-package protocol interfaces stay untouched:

- `ResidencyDeniedForAccess` (`accessors.go:341`) → `userinfo` (consumed by
  `protocols/oidc/handle_userinfo.go:57` only — verified).
- `ResidencyGateAccess` (`accessors.go:246`) → `me` (consumed by
  `protocols/selfservice` for GET `/me`, `/me/data-export` only — verified).

**3. `ResidencyDecision(ctx, tenantID, servingRegion, isWrite, surface)`**
gains a `surface` param. Its two in-repo consumers pass `login`
(`cmd/sso-server/serverwebauthn/webauthn.go:243`) and `me`
(`accessors.go:265`, `ResidencyGateWrite`). This is a breaking change to an
exported `*sso.Server` method — see the risk register; every consumer is
in-repo and compile-checked in the same change.

**4. Cache accounting** — `sso_residency_cache_total{outcome ∈ {hit, miss}}`
is observed inside `resolveResidencyPolicy` with exactly one observation per
call, never both:

- `hit` — the `cache.get` success branch.
- `miss` — the fall-through to the tenant-store read, covering every
  non-hit outcome (store unwired, store error, tenant not found, success).
  This makes the miss count literally "checks the cache did not absorb",
  which is the load the 60s TTL exists to shed; hit rate =
  `sum(rate(...{outcome="hit"})) / sum(rate(...))` over both series.

Fail-open cases are deliberately NOT counted as `allow` on
`sso_residency_decisions_total`: steps 1–2 of the ladder (engine off, no
region/tenant, store outage, store unwired) return before `evaluateResidency`
runs and emit nothing. This is what makes "engine unwired ⇒ series absent"
true (the acceptance's byte-identical-off property) and keeps the three
controls orthogonal: `decisions_total` counts resolved-policy verdicts,
`failopen_total` counts the silent-degrade windows, `cache_total` counts
store-round-trip avoidance. A constrained tenant with an empty `HomeRegion`
(resolved + cached, `evaluateResidency` returns nil) DOES observe `allow` —
that is "control active and allowing", which the spec wants visible.

**5. New file `platform/metrics/residency.go`** (well under budget, ~110
lines, mirroring `conditional_access.go`):

- `registerResidencyMetrics(factory promauto.Factory, m *Metrics)` — registers
  `ResidencyDecisionsTotal` (CounterVec, labels `{code, region, surface}`),
  `ResidencyCacheTotal` (CounterVec, labels `{outcome}`),
  `ResidencyFailOpenTotal` (CounterVec, labels `{reason}`),
  `ResidencyEnabled` (Gauge), `RegionResolutionErrorsTotal` (Counter).
- Nil-safe observers on `*Metrics`: `ObserveResidencyDecision(code, region,
  surface string)`, `ObserveResidencyCache(outcome string)`,
  `ObserveResidencyFailOpen(reason string)`,
  `ObserveRegionResolutionError()`, and a setter
  `SetResidencyEnabled()` (mirrors `SetFeatureGateEnabled`,
  `metrics.go:437-449`).
- Name constants in `platform/metrics/consts.go`:
  `NameResidencyDecisionsTotal = "sso_residency_decisions_total"`,
  `NameResidencyCacheTotal = "sso_residency_cache_total"`,
  `NameResidencyFailOpenTotal = "sso_residency_failopen_total"`,
  `NameResidencyEnabled = "sso_residency_enabled"`,
  `NameRegionResolutionErrorsTotal = "sso_region_resolution_errors_total"`
  (wire contract — `sso_` prefix, documented as renames are a major-version
  break). Struct fields with doc comments land in `metrics.go` next to
  `DegradedRejectionsTotal`/`ClientStoreCacheTotal`; label constants
  (`code`/`region`/`surface`/`reason`/`outcome`) reuse existing
  `LabelOutcome`/`LabelReason` where the semantic matches and add
  `LabelCode`, `LabelRegion`, `LabelSurface` in `consts.go`.
- Registration: one line `registerResidencyMetrics(factory, m)` appended to
  the `NewWithRegistry` block (`metrics_ctor.go:54` area) → 498/500 lines.

### Storage model

None. Counters and gauges live in the in-memory Prometheus registry held on
`*Metrics` (`metrics.go:36` `Registry`), scraped by the operator's collector;
there is no durable storage and no cross-replica state. The only pre-existing
state touched is the 60s TTL `residencyCache` (`server_tenant_residency.go`),
whose allocation/eviction semantics are unchanged. `sso_residency_enabled`
is set once at boot by `WithTenantResidencyCheck` (the option allocates the
cache, so gauge-set and cache-alloc are the same event) and never written
again.

### Failure modes

- Metrics registry nil or unwired: every observer no-ops before touching
  labels; decision order and wire bytes are identical to today.
- Label cardinality: `region` is bounded by the serving-region domain, which
  the region middleware already gates — `AllowedRegions` allowlist drops
  unlisted values (`domains/region/middleware.go`), and the observation only
  runs when `servingRegion != ""`. An attacker who can influence the region
  label can already influence the policy itself, so no new trust boundary.
  `code`/`surface`/`outcome`/`reason` are closed sets enforced by the
  explicit ladder + the single choke point.
- A future edit that adds an `evaluateResidency`-style branch but forgets the
  observe ladder: the counter silently misses that verdict. Mitigated by the
  unit test asserting the full `{code,region,surface}` tuple matrix fires
  exactly once per `checkTenantResidency` verdict.

### What could break this

- **Exporting the seam**: `ResidencyDecision`'s signature change is an SDK Go
  API break for external embedders (compile-time, not wire). All in-repo
  consumers (`cmd/sso-server/serverwebauthn/webauthn.go:243`, `accessors.go:
  265`, `rootcov2_cluster_test.go:473`) are updated in the same change, so CI
  cannot go green with a stale caller. Fallback if SDK stability is demanded:
  keep `ResidencyDecision(ctx, tenantID, servingRegion, isWrite)` and route
  `ResidencyGateWrite` through a new unexported
  `residencyDecisionSurface(..., surface)` — but this splits the seam the
  spec's evidence cites as a single decision point, so the param version is
  preferred.
- `metrics_ctor.go` line budget: exactly one added line; the register body
  must not be inlined there or the 500-line gate trips.
- The `region` label's operator-boundedness relies on the middleware
  allowlist; a deployment with residency enabled but no `AllowedRegions`
  and an unconstrained resolver inherits the resolver's output domain as
  label cardinality. Documented in the observability section as an operator
  obligation.

## Decision: fail-open and resolver-failure alerting — counters where the log line already is, alerts keyed on a boot gauge

### Problem restated

The ONLY trace of a residency fail-open episode is one `logger.Error` in
`resolveResidencyPolicy`; the only trace of a region-resolution failure is
the `OnError` log in `wireRegion` (`build_app_selfservice.go:256-262`).
Every other fail-open subsystem has a metric-and-alert safety net
(`SSORiskScorerSilent` at `alerts.yaml:89` is the named precedent). The
control can go silently dark for a whole outage window.

### API surface

**1. `ObserveResidencyFailOpen(reason)` with `reason ∈ {store_error,
store_unwired}`** (closed set):

- `store_error` — bumped in the existing `err != nil` branch of
  `resolveResidencyPolicy`, beside the current log line (the log stays; the
  counter makes it alertable). Fires once per gated request during the
  outage — nothing is cached on error — so its rate is a direct measure of
  exposed traffic.
- `store_unwired` — bumped in the `s.tenantStore == nil` branch, reached
  only after a cache miss. `WithTenantResidencyCheck` allocates the cache
  unconditionally (`server_tenant_residency.go`), so this is the
  misconfiguration shape: engine on, no store — every gated check is a miss
  and every miss bumps it. Fires once per gated request, same class as the
  decision counter; that is correct, this state never self-heals until
  config changes.
- Not counted as fail-open: `t == nil, err == nil` (not-found tenant) —
  that is an unconstrained tenant under the existing contract, not a
  degraded control. The doc section says so.

**2. `sso_residency_enabled` gauge** — set to 1 by
`WithTenantResidencyCheck` via the nil-safe setter; never set when the
option is unused. Mirrors `FeatureGateEnabled` boot-time semantics
(`metrics.go:327-334`): `sso_residency_enabled == 1` is the existence
guard on both alert expressions, so a build that never wired residency
cannot alert on absent series, and an operator who enables residency gets
the safety net for free.

**3. `sso_region_resolution_errors_total`** (no labels) — bumped in
`wireRegion`'s `OnError` closure beside the existing
`b.logger.Error("region resolution failed", ...)`, via
`b.metricsRegistry.ObserveRegionResolutionError()` (nil-safe — the field is
`*metrics.Metrics`, nil when `WithMetrics` was never applied). Layering is
clean: `cmd` (composition) imports `platform/metrics` already;
`domains/region` and `interfaces/sso` are untouched by this piece.

**4. Two alert rules in `ops/deploy/grafana/alerts.yaml`**, following the
`SSORiskScorerSilent` annotation style:

```yaml
- alert: SSOResidencyFailOpen
  expr: |
    sso_residency_enabled == 1
      and
    sum(increase(sso_residency_failopen_total[5m])) > 0
  for: 10m
  labels: {severity: warning, component: sso-server}
  # description: tenant-store outage window; residency control is failing
  # open by design (availability over strictness). Point at the
  # region_not_allowed / region_denied audit trail for the window.
- alert: SSORegionResolutionDegraded
  expr: increase(sso_region_resolution_errors_total[10m]) > 0
  for: 15m
  labels: {severity: warning, component: sso-server}
  # description: malformed/absent region source; requests served unconstrained.
```

The fail-open description must restate the design intent from the
`checkTenantResidency` doc comment (AP/governance control, not a CP
invariant; store partition must not 4xx the fleet) so the on-call engineer
does not "fix" the alert by making residency fail closed.

### Storage model

None. Both counters and the gauge are registry-resident. The `store_error`
series exists only from the first fail-open episode (first bump creates the
series) — which is fine because the alert expression is guarded by the
always-present `sso_residency_enabled == 1` series, so a zero-rate window
evaluates correctly from boot.

### Failure modes

- Metrics unwired: `wireRegion`'s closure still logs; the bump is a no-op.
  The alert simply cannot exist (no series) — same contract as every other
  opt-in metric, and the acceptance test asserts the gauge is absent without
  `WithTenantResidencyCheck`.
- Counter reset on restart: `increase()` handles resets; a restart during an
  outage re-arms the alert on the next episode. The `for:` clause dampens
  single-spike flapping.
- The `store_unwired` reason could false-positive if a future build wires
  residency before the tenant store in a way that self-heals (store wired
  later at runtime). Today the store is fixed at boot (`options_misc.go:101`),
  so the series only grows — which is the point (a config mistake should be
  loud).

### What could break this

- `domains/region` must never import `platform/metrics`; the cmd wiring is
  the only allowed seam. If a future refactor moves the OnError closure into
  the middleware itself, the counter would have to move with it — flagged as
  an architectural coupling: the alert depends on cmd remembering to wire
  both the middleware option and the counter. The unit test on the closure
  (`build_app` test path) is what pins this.
- promtool availability: `ops/deploy/grafana/` has no promtool gate in
  `make ci`; the acceptance treats `promtool check rules` as best-effort with
  manual review fallback. The expressions are deliberately simple
  (guard-and-increase) so manual review is meaningful.
- `sso_residency_enabled == 1` as a guard breaks if someone later sets the
  gauge to 0 on shutdown — it is defined as boot-set-once; the doc comment
  must say "never written after boot" to prevent that drift.

## Decision: `region_denied` audit event on read-gate denials, and a Residency contract section in `docs/observability.md`

### Problem restated

Write gates are provable (`recordLoginFailure` → `login_failure` with the
wire reason, `server_helpers.go:280`); read gates emit NOTHING on a
residency denial. `residencyDeniedForAccess` returns `(code, true)` and
leaves all recording to callers, none of which record
(`mesh_authz.go:197` collapses to a body-less binary DENY by oracle-safe
design; `/userinfo` and `/me` return the 403 and move on). Compliance
evidence for "the read side was enforced in region X during window W" does
not exist. Separately, `docs/observability.md` has zero region/residency
content, so the existing `region.serving` enrichment
(`platform/audit/handler_helpers.go:25`) is undiscoverable and the new
metrics would ship undocumented — the drift the repo's own AGENTS.md §5
forbids.

### API surface

**1. New event type** — `audit.EventRegionDenied = "region_denied"`.
Registering an EventType in this repo is a five-surface change, all
compile-test-enforced (the spec named only one; the other four are
mandatory or CI fails):

| Surface | File | Enforced by |
|---|---|---|
| Const + `KnownEventTypes` entry | `platform/audit/auditspi/event_types.go` | `event_types_completeness_test.go` (`TestKnownEventTypesIsComplete` AST-parses every const) |
| Alias | `platform/audit/aliases_spi.go` | compilation |
| CEF name | `platform/audit/auditsink/cef.go` (`cefEventNames`) | `auditsink/conformance_test.go:155` (`TestConformance_EveryEventTypeHasCEFAndOCSFMapping`) |
| OCSF classification | `platform/audit/auditsink/ocsf.go` (`ocsfEventActivities`) | same conformance test (the `ocsfGenericActivity` fallback exists but the test demands explicit entries) |
| SOC2 bucket | `platform/audit/auditreport/control_areas.go` | `drift_test.go` (`TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized`) |

Classification: `CC6.1 Access control` — the same area that already owns
`EventLoginFailure` (`control_areas.go:44-47`); a residency denial is an
access-control outcome, not a new category.

**2. Emitter** — `audit.RecordRegionDenied(rec *Recorder, ctx core.HandlerContext,
tenantID, surface, code string)` added to
`platform/audit/recorder_events_session.go` beside `RecordLoginFailure`
(the sibling event, same shape: `EventFromRequest` + `SetMeta`). Metadata
via `audit.SetMeta` only (the hard constraint in
`docs/observability.md` Audit section): `region.serving` (the canonical key
from `handler_helpers.go:25` — reuses `EnrichRegion`'s namespace, never
`geo.region`), `tenant.id`, `surface` (`mesh`/`userinfo`/`me` — the same
closed set as the metric label), `code` (`region_not_allowed`; the write-only
`residency_violation` cannot fire on the read side, but the field carries
the mapped code for forward-proofing).

**3. Call site** — `residencyDeniedForAccess` emits the event at the
`(code, true)` return, after the verdict is final. Emitting inside the
helper (not in the three callers) is the same single-point rationale as the
metric choke point: the mesh DENY, `/userinfo` 403, and `/me` 403 all record
identically, and the oracle-safe wire shapes are untouched — the event is
server-side only, never reflected in the 401 body or status.

**4. Write-gate parity is unchanged**: `login_failure` with
`region_not_allowed`/`residency_violation` reasons already covers every
denied mint; no new event on that path.

**5. Documentation** — `docs/observability.md`:

- Metrics table (lines 7-66): five new rows with exact names/labels, so
  table and `consts.go` cannot drift silently through the normal review
  path.
- New `### Residency` subsection under Audit (or a top-level `## Residency`
  if it outgrows one section) documenting: the three counters + gauge with
  zero-traffic conditions; the fail-open contract and its two alert rules;
  the audit events (`login_failure` with residency reasons, `region_denied`,
  `region.serving` enrichment); the operator obligation that `region` label
  cardinality is bounded by `AllowedRegions` configuration.
- `docs/error-codes.md` `region_not_allowed` row: one-line pointer to the
  Residency section (no semantic change to the documented disposition).

### Storage model

The event flows through the existing durable audit pipeline
(`Async → Multi → Retry → leaf`, hash-chained, W3C trace IDs) — no new
storage, no new sinks, no schema change. Bounded dimensions hold: the new
metadata keys are fixed strings with bounded values (`surface` closed set,
`code` closed set, `tenant.id`/`region.serving` are the same
operator/tenant-bounded values the pipeline already carries). The
`region_denied` event is rare by construction (denial-only), so the
pipeline's existing retention/bucketing applies unchanged.

### Failure modes

- Audit sink outage: audit is fail-open with logging (AGENTS.md §3); a
  dropped `region_denied` never blocks or alters the denial. Emit
  best-effort after the verdict.
- `s.auditor == nil`: no-op, matching `recordLoginFailure`'s guard — a
  server without an auditor gets the metric (if wired) but no event.
- Double-record risk: the event is emitted exactly at the `(code, true)`
  return of the helper; the three callers must not add their own audit
  calls. The audit test asserts one event per denial.
- The mesh DENY stays body-less and byte-identical: the event is emitted
  after the verdict but the wire write happens in the caller — the e2e
  assertions on the binary 401 (`test/region_residency_access_test.go:262`)
  still pass unchanged.

### What could break this

- Forgetting any of the five registration surfaces: three different CI
  tests fail (completeness, conformance, drift), so this cannot silently
  ship — but it means the change is not "one file" and must be planned as
  five edits. The design lists them in the table above as a checklist.
- `auditreport` drift test's `wantUncategorizedEventTypes` list
  (`drift_test.go:28`): if the new type is bucketed in `CC6.1` the list is
  untouched; if a reviewer decides it belongs elsewhere, both files change
  together.
- A future third read surface (e.g. a new bearer endpoint) reusing
  `residencyDeniedForAccess` without a new surface value would mislabel
  decisions and events. Mitigation: the `surface` parameter is mandatory at
  compile time (no default), and the doc section enumerates the closed set
  with its call-site table, so extending it is an explicit contract change.
- `docs/observability.md` row/const name drift has no automated lint (the
  spec's own acceptance says manual cross-check) — the `### Residency`
  section plus the table rows are the mitigation, same as every other row.

## Decision: sequencing, gate compliance, and what could break the design overall

### Sequencing

The three improvements are independent and additive; land in one change set
(they share the `residency.go` file, the `surface` threading, and the doc
section, so splitting them would churn the same files twice):

1. `platform/metrics`: `consts.go` names/labels → `metrics.go` struct fields
   → new `residency.go` → one-line registration → `residency_test.go`.
2. `interfaces/sso`: `surface` threading through `checkTenantResidency` /
   `residencyDeniedForAccess` / `ResidencyDecision` + the two observation
   calls + fail-open bumps + `ResidencyEnabled` setter in
   `WithTenantResidencyCheck` + `RecordRegionDenied` call site.
3. `platform/audit`: five-surface event registration + emitter +
   `auditreport` bucket.
4. `cmd/sso-server`: OnError counter bump in `wireRegion`.
5. `ops/deploy/grafana/alerts.yaml` + `docs/observability.md` +
   `docs/error-codes.md`.
6. Tests: `platform/metrics/residency_test.go` (registry scrape + nil-safety
   on bare `&Metrics{}`); server test extending
   `interfaces/sso/tenant_residency_test.go` (denied mint →
   `code="region_not_allowed", surface="login"` +1, allowed mint → `allow`
   +1, unwired → series absent, failing tenant.Store fake → request allowed
   + `reason="store_error"` +1, gauge 1 after option / absent without);
   audit test (one `region_denied` with all four metadata keys per denial);
   `test/` e2e scrape on a mesh DENY (`surface="mesh"`) in
   `test/region_residency_access_test.go` or `mesh_authorize_test.go`
   (requires the test harness to wire `WithMetrics` — verify before
   starting; if no existing e2e wires metrics, extend the residency e2e
   server build, which is a test-only change).

### Gate compliance

- No new `interfaces/sso` file (ceiling 60); no new `domains/region` import;
  no upward import (cmd → platform/metrics is composition → platform, legal).
- `metrics_ctor.go` 497 → 498 lines; new `platform/metrics/residency.go`
  ~110 lines; no function near 50 lines (the register fn is declarative,
  observers are 4-6 lines each).
- Mandatory verification after every `.go` edit:
  `go build ./... && go vet ./...` then
  `go test -run 'TestMaintainability_|TestArchitecture_' .`; handoff runs
  `go test ./... -race`, `go test ./test/ -run TestE2E -v`, `make ci`.

### What could break the design overall

- **The `surface` threading is the highest-risk mechanical change**: three
  signatures change (`checkTenantResidency` unexported, `residencyDeniedForAccess`
  unexported, `ResidencyDecision` exported) with nine call sites. Every one
  is compile-checked in-repo, but the exported `ResidencyDecision` break is
  the only one external embedders would feel — the release note must call
  it, and the doc records the fallback (unexported surface variant) if SDK
  stability is demanded mid-review.
- **Mislabeling drift**: if any caller passes the wrong surface, both the
  metric and the audit event mislabel silently (no wire signal). The
  call-site table in this doc + the audit test asserting the metadata tuple
  are the guards; the mesh e2e scrape assertion pins the most
  operator-visible one.
- **Alert semantics drift**: `SSOResidencyFailOpen` fires on ANY fail-open
  bump, including the `store_unwired` misconfiguration — a deployment with
  residency enabled but the store wired late would page. That is intended
  (a config mistake should be loud), but the description must distinguish
  the two reasons so on-call triage is not misdirected.
- **The 60-file ceiling interacts with the audit emitter**: `RecordRegionDenied`
  lives in `platform/audit` (no ceiling there), not in `interfaces/sso` —
  keeping the sso-side edit to the existing residency file is what keeps
  the ceiling intact.
- **Test-harness gap**: if no `test/` e2e currently wires `WithMetrics`, the
  mesh scrape assertion needs a new or extended server build in the e2e
  harness — a test-only change, but it is the one acceptance item with a
  real unknown; verify the harness before committing to the plan.
- **Byte-identical off**: the whole design hinges on nil-safe observers and
  no-observation-before-`evaluateResidency`; the acceptance tests for
  "series absent when unwired" and the existing e2e suite (which runs
  unwired) are the regression boundary. If a future refactor moves an
  observation above the `tenantResidencyEnabled` check, unwired builds
  start emitting — the doc comments on every observer state this
  explicitly.
