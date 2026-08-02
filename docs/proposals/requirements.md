Spec delivered at `docs/auto/domains-region-observability-spec.md` (all cited lines verified against source). Grounded in the analysis doc's direction 1 — decision metrics + failure alerts for the fail-open residency control — with exactly 3 evidence-backed improvements:

## 1. Residency decision and cache counters (`sso_residency_decisions_total{code,region,surface}` + `sso_residency_cache_total{outcome}`)
- **Problem**: the only enforcement layer with zero metrics; the mesh DENY (`mesh_authz.go:197`) is countable nowhere.
- **Evidence**: `server_tenant_residency.go` `checkTenantResidency`/`resolveResidencyPolicy` (no `s.metrics` touch), `conditional_access.go` observe pattern, `metrics_ctor.go:54` (497/500 lines → new file split), 8 gate call sites enumerated.
- **Behavior**: `surface` parameter on the unexported choke point `checkTenantResidency` (4 call sites, single observation point, no drift); nil-safe observers; closed label sets.
- **Acceptance**: registry-scrape unit test + server test asserting `code="region_not_allowed"` increments and zero series when unwired.

## 2. Fail-open and resolver-failure alerting (`sso_residency_failopen_total{reason}` + `sso_residency_enabled` + `sso_region_resolution_errors_total` + 2 alert rules)
- **Problem**: store-outage fail-open leaves only one `logger.Error` line; every other fail-open subsystem has a metric-and-alert safety net (`SSORiskScorerSilent` precedent in `alerts.yaml:89`).
- **Evidence**: `resolveResidencyPolicy` fail-open branches, `middleware.go:14-19` OnError (log-only at `build_app_selfservice.go:256-262`), `SigningBackendUp`/`FeatureGateEnabled` gauge precedents.
- **Behavior**: `store_error`/`store_unwired` reasons, boot-time enabled gauge to key alerts, cmd OnError bumps the counter (layering-safe — `domains/region` never imports metrics).
- **Acceptance**: injected failing tenant.Store test (request still allowed, counter bumped), promtool check.

## 3. Read-gate denial audit trail + observability contract doc
- **Problem**: read-gate denials (`/userinfo`, mesh, `/me`) emit no audit event — unprovable enforcement; `docs/observability.md` has 0 region/residency hits.
- **Evidence**: `mesh_authz.go:197` binary DENY with no server-side record, `residencyDeniedForAccess` returns and records nothing, `audit/handler_helpers.go:25` `region.serving` enrichment is undocumented, `auditreport/drift_test.go` classification requirement.
- **Behavior**: new `region_denied` audit event (server-side only, wire shapes untouched), classified in `auditreport`, plus a `### Residency` doc section tying together counters, alerts, fail-open contract, and audit events.
- **Acceptance**: audit test + drift test + doc/consts name cross-check.

Constraints baked in: no `domains/region` import change, no new `interfaces/sso` file (60-file ceiling), `metrics_ctor.go` split into `platform/metrics/residency.go`, oracle-safe wire behavior byte-identical throughout.
