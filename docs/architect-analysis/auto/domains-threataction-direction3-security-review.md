# Security Review: `domains/threataction` direction-3 design (response metrics, execution history, real notification)

Reviewer role: principal security engineer (adversarial production behavior).
Input: `docs/auto/domains-threataction-direction3-design.md` (591 lines).
Scope: the three decisions — `WithMetricsCallbacks` + `sso_threat_*` counters, append-only `ExecutionHistoryStore` + `GET /api/v1/admin/threat-executions`, and the honest `NotifyExecutor` routed through `notification.Router` — plus the four design-level findings the doc itself surfaced.

This is an advisory review of a **proposal**. None of the three decisions is implemented in the tree today (`sso_threat_*` does not exist in `platform/metrics` or `docs/`; `threat_notify_executed` is not in `auditspi`; there is no history store, endpoint, or config knob; `NotifyExecutor.Execute` still fabricates success).

## Verification run for this review

Claims below are labeled per the evidence standard. I re-verified every design claim I rely on against the current tree (no code changed):

- `domains/threataction/registry.go` 301 lines; `recordAudit` at line 240, exactly 3 internal call sites (rate-limit, no-handler, executed); no test touches `recordAudit`. **Verified**
- `cmd/sso-server/serverbuildplatform/build_governance.go:310` `BuildThreatAction` = 32 lines (design cites `build_governance.go` without the `serverbuildplatform` prefix — doc drift, not budget drift). **Verified**
- Wire order: `wireEmailSenders` (`build_app_selfservice.go:145`) runs in build order and calls `BuildNotifications` (`email_sender.go:51`, returns `([]sso.Option, error)` today — no router in the return); `finalize` (`build_app.go:238`) → `wireDetectionResponse` → `wireThreatAction` (`anomaly.go:67`) runs after; `appBuilder` has no router field today. The "one new builder field" claim is accurate. **Verified**
- Router is an auditor sink: `interfaces/sso/sso.go:161` `s.auditor.AddSink(s.notificationRouter)`. `Router.Record` (`router.go:207`) is public, non-blocking, drops on a full queue via `default:` and **always returns nil**. `suppressed` (`router.go:343`) early-returns `false` when `cooldown == 0`; `notifications.cooldown: 0` is an operator-supported value (`docs/config-reference.md:262`). **Verified**
- `DefaultMappings` (`router.go:116-128`) has no threat row; `docs/notifications.md` mapping table has no threat row; `docs/observability.md` has no threat section. **Verified**
- `EventThreatActionExecuted` is a local string const (`threataction.go:124`), absent from `auditspi`/`auditreport` (pre-existing gap, also recorded as F11 in `docs/proposals/architect.md`); CC7.2 holds `EventAnomalyDetected`. **Verified**
- Severity sets: anomaly `{info, warn, critical}` (`domains/anomaly/types.go:141-147`), tokenanomaly `{warn, critical}` (`tokenanomaly.go:43-51`); policy severity is free-form (`policy.go:35,156-166`). The design's "label from `threat.Severity`, never `policy.Severity`" constraint is correct. **Verified**
- Neither detection source populates `Threat.TenantID` (`runner.go:217-224`, `detector.go:411-419`); `LoginEvent` and `Finding` carry no tenant; `recordAudit` sets no `Event.TenantID`. SSE filter matching requires `ev.TenantID` equality when the subscriber filter sets a tenant (`platform/sse/broker.go:64-67`). **Verified**
- Admin gate: GET → `admin:read` via the AdminMiddleware method-scope rule (`interfaces/admin/middleware.go:29-74`), `Bearer realm="admin"` challenge (`middleware.go:364`). `PathAdminThreatPolicies` at `shared/core/consts_wire.go:488`; `openapi.yaml` has threat-policies but no threat-executions. **Verified**
- `platform/migrate.Run` takes a per-namespace version table (`platform/migrate/migrate.go:135`); sqlite policy store uses parameterized queries (`?`). `RunAuditRetention` exists (`interfaces/sso/server_admin_handlers.go`). **Verified**
- `sso_notifications_delivery_failed_total` exists with channel labels incl. `queue` (`platform/metrics/consts.go:15`, `metrics.go:472-478`, `docs/observability.md:19`); the router observer reports `("queue","dropped")`. **Verified**
- Anomaly `metricsCallbacks` nil-safe stub pattern (`domains/anomaly/runner.go:235-260`); eager `registerAnomalyMetrics` (`metrics_ctor.go:45`); `metrics_test.go` asserts exact `sso_anomaly_*` strings. **Verified**
- `interfaces/sso` production files = 60; `domains/threataction` non-test files = 6; `sqlite/` = 2; `memory/` = **1** (design says "memory/ +1 (2 → 3)" — actual is 1 → 2). Doc drift. **Verified**
- Email notification template is plain text (`infrastructure/defaultimpl/emailsmtp/notification.tmpl`) — no HTML injection vector via notification bodies. `FamilyID` is opaque random output of `GenerateAuthCodeBytes` (`protocols/oauth/oauthwire/auth_code_handler.go:240-244`), not a token-derived secret. **Verified**
- `threat_action.history.*` knob does not exist in `config.ThreatActionConfig` (Enabled/DefaultAction/Policies only). **Verified**

## 1. Assets, trust boundaries, attacker capabilities, entry points

### Assets touched by the design

| Asset | Trust level | Notes |
|---|---|---|
| Threat-policy set (YAML seed + admin CRUD, `threat_policies` table) | admin:write / operator config | Policy names flow into a Prometheus label (Decision 1) |
| In-process rate-limit state (`te.rateLimit`, swept at 1024 entries) | process-local | Per-replica windows; pre-existing |
| New `ExecutionHistoryStore` (memory append-only slice; sqlite `threat_executions` table) | write path = fail-open off-path; read path = admin:read | New durable store with **no retention** |
| New admin endpoint `GET /api/v1/admin/threat-executions` | admin:read bearer | Subject/client/tenant/trace data across tenants |
| New `sso_threat_*` counters | operator metrics endpoint | Policy-name + severity labels |
| New audit event type `threat_notify_executed` + meta `threat.severity`, `threat.notify.channel` | audit stream + webhook consumers | Wire-visible contract change |
| Notification pipeline (inbox, SSE, email) | existing router | New event source; double-enqueue edge |

### Trust boundaries

1. **Detector → Threat SPI boundary.** `Threat` values are constructed only by `anomaly.Runner` and `tokenanomaly.Detector` (verified — no other construction sites). Unauthenticated users influence detector *input* (login events) but never the `Threat` struct directly. The design correctly keeps severity labeling on this boundary (closed sets today) rather than on the admin-controlled policy severity.
2. **Admin API boundary.** The new endpoint sits behind the existing admin bearer + method-scope gate (GET → `admin:read`). It is a **global, cross-tenant** read surface, consistent with the rest of the admin API (audit query, token portfolio). Not a regression, but the tenant-scoping story matters (Finding 3).
3. **Audit sink fan-out boundary.** The router is already a sink (`sso.go:161`); the design adds a *second* enqueue path (`routerNotifier`). This is the double-enqueue edge (Finding 2).
4. **Composition root.** `BuildThreatAction` gains `*metrics.Metrics` + notifier + history-store inputs; wire order is safe (verified). The router notifier adapter is the only new cross-layer seam.

### Attacker capabilities

- **Unauthenticated attacker (login endpoint is public):** can generate anomaly signals at will (failed-login spray → brute-force-shadow/velocity threats; own-account logins → new-device/new-country threats). Drives: history-row writes (unbounded, Finding 4), notify queue saturation (Finding 1), cooldown-map growth, rate-limit state. Cannot forge a `Threat` or choose another subject's session directly — but can *induce* responses against subjects whose identifiers they guess.
- **Authenticated user:** can trigger subject-scoped threats on their own account only; no new capability.
- **Admin (admin:read):** full cross-tenant history query; sees subject IDs, client IDs, trace IDs, family IDs (opaque random), executor detail strings (may embed store error text).
- **Admin (admin:write):** policy names of unbounded length → metric labels (Finding 6); can point `notify` policies at any subject/severity combination; seed validation gap (config-seeded policies bypass `invalidPolicyReason` — pre-existing, now observable via `no_handler`/history).
- **Compromised detector or SDK embedder:** can emit arbitrary `Threat.Severity`/`Threat.Type` → the severity label is "closed" only for the two stock detectors; the SPI does not enforce it. Evidence is already bounded at `recordAudit` (`maxEvidence*`).

### Entry points (new or modified)

1. `GET /api/v1/admin/threat-executions` — admin:read, mounted only when a store is wired (byte-identical otherwise). Query params: `subject`, `action`, `type`, `limit` (default 100, max 1000; 400 on non-numeric/negative/>1000).
2. `/metrics` — four new `sso_threat_*` counter families.
3. Audit/webhook stream — new `threat_notify_executed` event + two meta keys; `threat_action_executed` no longer carries notify.
4. Notification pipeline — `notify` actions now produce real inbox/SSE/email delivery (and, per the design, a second enqueue).
5. Config — `threat_action.history.backend` (`""`|`memory`|`sqlite`) + `threat_action.history.dsn`.

No new authentication, authorization, proxy-trust, SSRF, or credential surface is introduced. The findings below are about the observability/notification layer, where the design's own honesty guarantees have gaps.

## 2. Findings (sorted by severity)

### F1 — High: `notify` success is still fabricated when the router queue is full

**Evidence (Verified):** `Router.Record` (`router.go:207-225`) enqueues non-blocking and **always returns nil**; on a full queue it silently calls `r.observe("queue", "dropped")` and drops the event. The design's `routerNotifier.Notify` calls `Router.Record` and reports success whenever the router is non-nil; `recordAudit` then stamps `OutcomeSuccess` and the history row `OK:true`. Queue capacity is 256 with 2 workers (`router.go` defaults); email delivery retries 3× with backoff (`router.go` `deliver()`), so a slow SMTP peer parks both workers and the queue fills under any sustained threat volume.

**Exploit preconditions:** `notifications.enabled`; a threat policy with action `notify`; sustained anomaly volume or slow email delivery (both reachable by an unauthenticated attacker via login spray, or by ordinary operational conditions).

**Steps:** attacker botnet drives failed-login anomalies → notify actions → queue fills → events dropped → audit event `threat_notify_executed` outcome=success, history row `ok:true`, while no inbox row, SSE event, or email is ever produced.

**Impact:** the exact misdirection this design exists to eliminate ("admin was notified" with zero side effects) persists in the failure mode where it matters most — under attack load. Incident responders and SIEM rules keyed on the success outcome are misled; the only counter-signal is `sso_notifications_delivery_failed_total{channel="queue"}` (Verified), which nothing in the design ties to the notify path.

**Remediation (required before merge):** give the notifier a drop-aware result. Minimal option: add a non-`audit.Sink` method on `Router` (e.g. `TryRecord(event) (accepted bool)`) that reports the `default:` branch, and have `routerNotifier.Notify` return that; `NotifyExecutor` then returns `OK:false, "notification queue full"` — an honest failure audit + history row. Fallback option: keep `Record`, but document the queue-drop counter as the mandatory alert companion to any `sso_threat_actions_total{action="notify",outcome="success"}` dashboard and state in `docs/observability.md` that `ok:true` means "enqueued" only.

**Regression test:** unit test building a `Router` with `WithQueueSize(1)` and a blocked worker, enqueuing once to fill the queue, asserting `Notify` returns an error / `OK:false` and the audit event outcome is `failure`; e2e under induced queue saturation asserting no success audit for a dropped delivery.

### F2 — Medium: `cooldown: 0` duplicate delivery is documented away, not fixed

**Evidence (Verified):** design finding #1 is real: the event reaches the router twice whenever notifications are enabled (`sso.go:161` auditor-sink tap + the `routerNotifier` enqueue). `suppressed` (`router.go:343`) returns `false` for `cooldown == 0`, and `notifications.cooldown: 0` is an operator-supported value (`docs/config-reference.md:262`). The design's resolution is "keep the tap, document the cooldown dependency, test the cooldown=0 case" — i.e., ship a known duplicate-delivery defect for a supported config.

**Preconditions:** `notifications.enabled` with `cooldown: 0` (or an SDK embedder passing `WithCooldown(0)`); a `notify` policy.

**Impact:** duplicate inbox rows and duplicate SSE events (including the broker ring-buffer replay), doubled router load, and notification spam to the affected user on every threat. For a security notification channel, duplicates also degrade trust in the channel's signal.

**Remediation (preferred):** adopt the design's own "single-path variant" — delivery exclusively via the existing auditor-sink tap; `routerNotifier` becomes a wiring gate whose `Notify` returns success when the router is wired (the audit event the registry emits is the delivery vehicle). This removes the duplicate path for every config, including `cooldown: 0`, and keeps the executor honest: `OK:false "notify action not wired"` when the router is absent. The stated tradeoff (honesty couples to `applyAuditSinkTaps` wiring) is acceptable because the stock binary is the only supported deployment of this feature and the design already documents the tap dependency. If the tap is kept, gate the notifier enqueue on a "router already registered as an audit sink" flag so the second path never exists.

**Regression test:** e2e with `notifications.cooldown: 0` + a `notify` policy asserting exactly one inbox row and exactly one SSE event per threat.

### F3 — Medium: the design ships a `tenant_id` field that will be empty in production

**Evidence (Verified):** `Threat.TenantID` is never populated — `anomaly.Runner` (`runner.go:217-224`) and `tokenanomaly.Detector.dispatchThreat` (`detector.go:411-419`) build `Threat` without it, and neither `LoginEvent` nor `Finding` carries a tenant. `recordAudit` (`registry.go:240-266`) sets no `Event.TenantID`. The design's `ExecutionRecord.TenantID` column and the notification `NotificationEvent.TenantID` therefore source from nowhere; the design adds no propagation step. Consequence for the notification path: the SSE broker matches `ev.TenantID` equality when a subscriber filter sets a tenant (`broker.go:64-67`); a tenant-scoped end-user stream silently never receives threat notifications, and inbox rows are tenant-less.

**Preconditions:** any deployment with the history store or `notify` policy; frontends that subscribe to SSE with a tenant filter.

**Impact:** the forensics surface ships a permanently-empty `tenant_id` column (dead schema, misleading queries); tenant-filtered notification delivery silently misses threat events; cross-tenant attribution of a response is impossible from the new surfaces (the pre-existing audit events for threats are tenant-less too).

**Remediation:** thread tenant through the detection sources (`LoginEvent`/`Finding` → `Threat` → `recordAudit` → `Event.TenantID` + history row) as part of this change, or explicitly drop the `tenant_id` column and the `NotificationEvent` tenant claim until propagation exists, documenting the limitation. Do not ship a column that is 100% empty by construction.

**Regression test:** e2e asserting a non-empty `tenant_id` on the history row and on the routed notification event once propagation lands; until then, a unit test asserting the documented empty behavior.

### F4 — Medium: unbounded append-only history growth is an unauthenticated write-amplification DoS

**Evidence (Verified):** every non-Noop attempt (executed, rate-limited, no-handler — all three `recordAudit` sites) writes a history row fail-open. The login endpoint is public; a spray across many identifiers drives brute-force-shadow/velocity threats (each producing rows), and per-subject rate limiting bounds executions per tuple, **not total row volume**. The design explicitly defers retention ("no retention in scope; the audit retention scheduler is the eventual precedent") while the audit store already has `RunAuditRetention` (`interfaces/sso/server_admin_handlers.go`). The stock-binary default backend is `memory` (unbounded per-process slice); `sqlite` grows the file without bound.

**Preconditions:** `threat_action.history.backend: sqlite` (or memory) with any enabled detector; sustained unauthenticated login traffic.

**Impact:** disk/memory exhaustion on a long-running server — an availability failure reachable by an attacker who never authenticates; backup/restore cost grows monotonically.

**Remediation (required before merge):** ship a retention/cap in the same change — a prune on `recorded_at` (mirroring `RunAuditRetention`'s scheduler) or a bounded row cap with documented semantics; at minimum bound the memory store. The `limit` cap (1000) bounds reads, not writes; the design's "document the growth tradeoff" is insufficient for a security-adjacent store written by unauthenticated traffic.

**Regression test:** store-level prune test (rows older than cutoff deleted; cap enforced) + e2e that the history endpoint never exceeds the cap under a burst.

### F5 — Low: event-type split silently removes `notify` from existing `threat_action_executed` consumers

**Evidence (Verified):** today `notify` executions emit `threat_action_executed` (`registry.go:246`); after the split they emit `threat_notify_executed`. Webhook filters, SIEM rules, and audit queries keyed on `threat_action_executed` will stop seeing the notification half of response activity after upgrade with no configuration change — a detection gap precisely during incidents.

**Remediation (the design already plans it — make it a gate):** the `docs/error-codes.md`/`docs/observability.md` contract callout and the webhook e2e assertion expecting the new type must ship in the same change; add a deprecation note to `docs/error-codes.md` listing `threat_action_executed`'s narrowed scope.

**Regression test:** webhook e2e asserting `threat_notify_executed` is delivered with `threat.action=notify` and `threat.severity` meta, and that suspend/revoke still emit `threat_action_executed`.

### F6 — Low: `matched` callback signature and metric labels disagree

**Evidence (Verified):** the design's `WithMetricsCallbacks` `matched` takes `(policy, threatType, severity)` but `ThreatPolicyHitsTotal` is declared with labels `(policy, severity)`. Either the vector gains a `threat_type` label (closed 8-value set — still bounded) or the callback drops the argument. A mismatch shipped as written means either a dead parameter or a label promised but never emitted — a wire-contract ambiguity the design's own "exact-name assertions" rule should pin.

**Remediation:** pick one; if `threat_type` is kept, add `LabelThreatType` to `platform/metrics/consts.go` and assert the exact label set in `metrics_test.go` alongside the `sso_threat_*` names.

### F7 — Low: policy-name label is unbounded in length and collides with the `_default` fallback

**Evidence (Verified):** `HandleAdminPutPolicy`/`invalidPolicyReason` (`admin.go`) validates action/rate-limit/operator but not name length; YAML-seeded policies bypass validation entirely (`BuildThreatAction` `store.Put` loop). `matched` labels `policy.Name`; the fallback path labels `_default` (`registry.go` `defaultPolicy()`), which an admin can also name explicitly — two distinct policies collapsing into one series.

**Impact:** admin-authored megabyte names become megabyte label values on `/metrics`; label collision muddies the "which policy fires" answer the metric exists to give. Admin-trusted, so bounded by trust, but trivially avoidable.

**Remediation:** bound policy-name length (e.g. 128 chars) at both the admin PUT and the config-seed path; document `_default` as reserved.

**Regression test:** PUT with an oversized name → 400; seed with `_default` name → boot error or documented collision handling.

### F8 — Info: `threat_action_executed` remains unclassified in `auditreport`

**Evidence (Verified):** pre-existing gap (architect F11): the parent type is absent from `auditspi`/`auditreport`, and the design classifies only the new `threat_notify_executed`. This change multiplies threat-event volume (every attempt now also writes history) without closing the SOC2 completeness gap for the parent type.

**Remediation:** classify both event types in the same change (one `auditspi` const + CC7.2 rows each) — two lines, closes F11.

### F9 — Info: design-doc drift

`memory/` non-test files are 1 (design says 2 → 3); `BuildThreatAction` lives at `cmd/sso-server/serverbuildplatform/build_governance.go:310` (design cites `build_governance.go`); `router.go:343`/`sso.go:161` line refs verified correct. No budget impact; fix the doc to keep the evidence trail clean.

## 3. Abuse-case table

| Abuse case | Attack surface | Reachable path | Verdict |
|---|---|---|---|
| Identity spoofing (forged threat subject) | Threat SPI | Threat built only by `anomaly.Runner`/`tokenanomaly.Detector` (Verified); attacker cannot inject a `Threat`. Subject-less threats → `OK:false "no subject for notification"` (design). | Not exploitable |
| Replay (duplicate notification) | routerNotifier + auditor tap | Double enqueue; deduped only when `cooldown > 0`; `cooldown: 0` (supported config) → duplicate inbox rows + SSE ring events (F2) | **Exploitable (config-dependent)** — operator misconfig, not attacker; fix per F2 |
| Replay (execution) | in-process rate limiter | Per-replica state; a multi-replica deployment multiplies the window by replica count — pre-existing, not introduced here; the new metrics/history make it observable | Residual risk (pre-existing) |
| Cross-tenant access | new admin endpoint | Global `admin:read` gate (Verified), consistent with the admin API; history rows carry subject/client/trace data of all tenants; `tenant_id` empty (F3) — an attribution gap, not an isolation break; inbox reads are subject-scoped | Not exploitable; F3 limits forensics |
| Proxy/header forgery | none | Design adds no header, XFF, forwarded-host, or mTLS trust; no `peertrust` consumer | Not applicable |
| Resource exhaustion (history growth) | sqlite/memory store, public login path | Unauthenticated spray → threats → fail-open rows, no retention (F4) | **Exploitable (availability)** |
| Resource exhaustion (queue) | router queue 256 × 2 workers | Sustained threat volume or slow SMTP → silent drops → fabricated success (F1) | **Exploitable (integrity of the audit trail)** |
| Resource exhaustion (maps) | `te.rateLimit`, router `recent` | `rateLimit` swept at 1024 (Verified, bounded); router `recent` (subject,type) map never evicts — pre-existing, amplified by notify paths | Residual risk (pre-existing) |
| Sensitive-data leakage | history endpoint, audit meta, metrics | Subject IDs, opaque family IDs, trace IDs, executor detail strings (may embed store error text) — admin:read parity with the audit stream; evidence deliberately excluded from history rows (privacy-positive); no secrets (FamilyID = opaque random, Verified); email bodies plain-text | Not exploitable |
| Injection (SQL) | history filters | sqlite precedent is fully parameterized (`policy_store.go:122,147`); design must keep `List` parameterized; filters are admin-only anyway | Not exploitable (assert in store test) |
| Injection (content) | notification body | `threat.detail` flows into notification/email bodies; email template is plain text (Verified); inbox rendering is frontend-owned; detail is detector/executor-controlled, not attacker-controlled | Not exploitable |

## 4. Positive controls verified

- **Oracle-safe and anti-enumeration behavior is untouched.** No credential endpoint, error code, or challenge changes; the new endpoint follows the sibling admin handlers (`ErrInvalidRequest`/`ErrInternal`/404-on-nil-store pattern verified against `HandleTokenExchangeChain`).
- **Fail-open/fail-closed asymmetry is correct** and matches the token-exchange precedent: fail-open writes (`RecordExecutionFailOpen` mirroring `RecordHopFailOpen`, Verified pattern), fail-closed reads (500 on store error). The design's "no fail-open creep on reads" guard is right.
- **Severity label cardinality is bounded by construction** for the stock binary: `threat.Severity` comes from closed sets (`anomaly` info/warn/critical, `tokenanomaly` warn/critical — Verified), and the design correctly refuses `policy.Severity` (free-form, Verified).
- **The `recordAudit` choke point** centralizes the `rateLimited` bool, event-type selection, and history write — the right call; it keeps the audit event and the history row from diverging.
- **Admin surface is gated and opt-in**: not mounted without a store; byte-identical otherwise; `Bearer realm="admin"` + GET→`admin:read` inherited (Verified).
- **Wire order is safe** (Verified): router exists before `wireThreatAction`; the new `appBuilder` field is the only wiring change needed.
- **Privacy-positive choices**: history rows exclude `Evidence` (bounded 32×1024-char meta stays audit-only); notify channel key omitted when absent; no secrets in `ExecutionRecord`.
- **Config isolation**: `threat_action.history.*` is independent of the policy backend and delivery knobs — correct for an observability concern.
- **The honesty fixes in Decision 3** (nil notifier → `OK:false`; empty subject → `OK:false`) close the current fabricated-success defect for the unwired and subject-less cases.

## 5. Residual risks

1. **F1/F2 unresolved by design as written** — the two defects above ship unless the remediation options are taken; both are operator-reachable, and F1 defeats the design's stated purpose under load.
2. Router `recent` cooldown map never evicts (pre-existing); threat-notify usage grows it with distinct (subject,type) pairs — bounded by real subjects, unbounded over time.
3. Per-replica rate-limit state: N replicas ⇒ N× window budget per subject (pre-existing; the new metrics make it visible).
4. Severity/type labels are closed only for the two stock detectors; the public `Threat` SPI allows arbitrary values (SDK embedders). Acceptable; note in the metrics help text.
5. `threat_action_executed` tenant-less audit events remain (pre-existing); F3's fix should cover the audit event too.
6. Config-seeded policies bypass `invalidPolicyReason` validation (pre-existing) — now observable via `no_handler` metrics and history rows; consider validating the seed at boot.

## 6. Prioritized validation plan

| # | Gate | What it proves | When |
|---|---|---|---|
| 1 | `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .` | Budget claims (registry ~420 <500, admin ~245, threataction 7 files, sqlite 3, memory 2; no new layerExemptions; `interfaces/sso` stays 60) | after every `.go` edit |
| 2 | `registry_test.go` additions | Callback fire points pinned per path (noHandler ≠ executed ≠ rate-limited; noop fires `matched` only); `recordAudit` `rateLimited` bool at all 3 sites; failing-stub store ⇒ result byte-identical (fail-open invariant); history rows for swallowed attempts | unit |
| 3 | `metrics_test.go` additions | Exact `sso_threat_*` wire names; label sets (`action`∈6 constants, `outcome`∈{success,failure}); no panic on bounded labels | unit |
| 4 | `router_test.go` additions | `DefaultMappings` row for `threat_notify_executed`; severity-aware presentation case; `suppressed` cooldown=0 pin (F2); queue-full `TryRecord`/drop behavior (F1) | unit |
| 5 | sqlite store test | Parameterized `List` filters; columnar schema + 3 indexes; per-namespace migrate (never touches `threat_policies` stamp); retention prune (F4) | unit |
| 6 | `test/` (package `ssotest`) e2e | Admin endpoint auth (401 no bearer, 403 without `admin:read`), limit validation (400 on `-1`/`abc`/`1001`), store-down 500; webhook receives `threat_notify_executed` and suspend still emits `threat_action_executed` (F5); cooldown=0 ⇒ exactly one delivery (F2); history `tenant_id` non-empty (F3) | integration |
| 7 | `make ci` | `auditspi` + `auditreport` classification (CC7.2), `docs/config-reference.md` `threat_action.history.*` rows, `docs/openapi.yaml` endpoint + schema (incl. "records attempts, not only executions" wording), `docs/notifications.md` mapping row, `docs/observability.md` threat section + notify-OK-means-enqueued caveat | handoff |

## Bottom line

The design is sound in its architecture (choke-point integration, fail-open/fail-closed split, bounded labels, honest unwired behavior) and its budget claims verified. It must not ship as written on three points: **F1** (queue-full `notify` success is the design's own "green lie" resurfacing under load — make the notifier drop-aware), **F2** (eliminate the double-enqueue rather than documenting the `cooldown: 0` duplicate), and **F3** (populate or drop the tenant fields). **F4** (retention) should ship in the same change since the write path is unauthenticated-amplifiable. The remaining findings are low-severity contract hygiene (F5-F9).
