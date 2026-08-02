Specification written to `docs/auto/domains-threataction-direction3-spec.md`. It contains exactly 3 evidence-backed decisions, each verified against the code before writing:

## 1. Response metrics (`WithMetricsCallbacks` + `sso_threat_*` counters)
- **Problem**: `registry.go`'s doc claims executions are "logged, metric'd", but `ThreatExecutors` has no metrics field/option — `recordAudit` is the only outlet; `platform/metrics` has zero threat counters; `docs/observability.md` has no threat section.
- **Evidence**: `registry.go` struct/options; `domains/anomaly/options.go` `WithMetricsCallbacks` (the pattern to mirror); `metrics.go:124-135` (anomaly vectors only); `consts.go:25` (`sso_anomalies_detected_total` exists, no `sso_threat_*`); `cmd/sso-server/anomaly.go:195-203` (wiring style).

## 2. Execution history (`ExecutionHistoryStore` + `GET /api/v1/admin/threat-executions`)
- **Problem**: admin surface is policy CRUD only; forensics means correlating scattered `threat_action_executed` audit events by hand.
- **Evidence**: `admin.go` (4 policy handlers, no history); `registry.go` `recordAudit` choke point; the in-repo precedent `tokenexchange/chainstore.go` + `interfaces/admin/lifecycle.go:109` + its gated mount in `accessors_threat.go`; `openapi.yaml:7405`.

## 3. Real notification (honest `NotifyExecutor` + `threat_notify_executed` → `security_event`)
- **Problem**: `NotifyExecutor.Execute` returns `OK:true` with zero side effects — fabricated success; the platform's real pipeline never sees threat events.
- **Evidence**: `actions.go` (`NotifyExecutor.Execute` pass-through); `threataction.go:124` (event type is a local string, absent from `auditspi/event_types.go`); `notification/router.go:100,116-128` (`DefaultMappings` covers `anomaly_detected`, not threats); `email_sender.go:86` (nil mapping); `docs/notifications.md` mapping table; `core/password_reset.go:146` (`NotificationSecurityEvent` exists).

Each decision includes proposed behavior (mirroring existing repo patterns: anomaly's nil-safe callbacks, tokenexchange's fail-open store, local-interface SPI style) and an acceptance check tied to concrete tests and gates (`go build`/`go vet`, maintainability/architecture tests, `-race`, `make ci`). The header also flags the relevant engineering gates: `BuildThreatAction` is 32 lines (wiring must go in helpers), `interfaces/sso` is at its 60-file ceiling, and new audit event types must be classified in `auditreport`.
