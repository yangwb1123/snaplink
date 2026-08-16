# Observability

Metrics, audit and tracing reference for the API runtime. A separately deployed
frontend has its own browser/static-asset telemetry; it is not instrumented by
this process.

## Metrics

All metrics use bounded cardinality — **no per-path/per-user labels**.

| Metric | Type | Labels |
|---|---|---|
| `sso_http_requests_total` | Counter | method, status_class |
| `sso_http_request_duration_seconds` | Histogram | method |
| `sso_login_attempts_total` / `_duration_seconds` | Counter/Histogram | provider, outcome |
| `sso_tokens_issued_total` | Counter | strategy |
| `sso_risk_decisions_total` | Counter | decision |
| `sso_auth_hook_execution_duration_seconds` | Histogram | phase, hook, outcome (hook names are startup-registered; max 32 per phase) |
| `sso_notifications_delivery_failed_total` | Counter | channel (`in_app`\|`email`\|`queue`); increments for terminal delivery failures and bounded-queue drops |
| `sso_mfa_challenges_total` | Counter | mfa_method |
| `sso_mfa_completions_total` / `_duration_seconds` | Counter/Histogram | mfa_method, outcome |
| `sso_webauthn_{registrations,assertions}_total` | Counter | outcome |
| `sso_credential_health_signals_total` | Counter | signal |
| `sso_signing_key_rotations_total` | Counter | — |
| `sso_signing_operations_total` / `_duration_seconds` | Counter/Histogram | alg, outcome / alg |
| `sso_signing_backend_up` | Gauge | alg |
| `sso_signing_key_adoption_errors_total` | Counter | reason (decode\|adopt) |
| `sso_signing_key_aggregation_up` | Gauge | — |
| `sso_signing_key_cutover_total` | Counter | outcome |
| `sso_token_revocations_propagated_total` | Counter | direction (published\|adopted) |
| `sso_fapi_violations_total` | Counter | rule, mode |
| `sso_ciba_ping_total` | Counter | outcome |
| `sso_caep_sets_total` | Counter | outcome (success\|failed\|dropped\|retried) |
| `sso_refresh_rotation_velocity_exceeded_total` | Counter | — |
| `sso_client_store_cache_total` | Counter | outcome (hit\|miss) |
| `sso_audit_async_drops_{queue_full,closed,inner_error}_total` | Counter | — |
| `sso_audit_async_queue_{depth,capacity}` | Gauge | — |
| `sso_feature_gate_enabled` | Gauge | feature (oidc\|ciba\|caep\|federation\|self_service\|admin_api\|branding) — startup configuration only; 1=initially reachable / 0=initially disabled |
| `sso_dr_snapshot_replication_lag_seconds` | Gauge | — (absent until the first successful DR replication) |
| `sso_dr_last_recovery_seconds` | Gauge | — (absent until a recovery is timed via `RecoveryTimeTracker`) |
| `sso_dr_readiness` | Gauge | — (1 = verified replica within RPO target, 0 otherwise; see [dr-framework.md](dr-framework.md)) |
| `sso_zero_trust_session_stepup_total` | Counter | — (live sessions the continuous-verification agent marked for step-up because their decayed trust fell below the floor; zero until `session_trust_decay` is wired) |
| `sso_rate_limit_hits_total` | Counter | tenant (resolved tenant ID, or `unknown` when no tenant resolver is wired — see `WithRateLimit`/`ratelimit.Policy.TenantKeyFunc`) |
| `sso_signing_key_pruned_total` | Counter | — (peer-adopted verify-only keys removed by `Server.PruneVerifyKeys`'s retention-window safety net; distinct from the real-time per-announcement reconciliation) |
| `sso_signing_verify_key_set_size` | Gauge | — (current size of the peer-adopted verify-only key set; the memory footprint `PruneVerifyKeys` manages) |
| `sso_signing_key_usage_total` | Counter | alg, kid (in-process JWT signing operations; wire via `WithEd25519Metrics`/`WithECDSAMetrics`/`WithRSAMetrics`) |
| `sso_connection_health_probes_total` | Counter | type (oidc\|saml), outcome (healthy\|degraded\|unreachable) |
| `sso_invalidation_bus_{up,reconnects_total}` | Gauge/Counter | — |
| `sso_netpolicy_classifier_{up,reconnects_total}` | Gauge/Counter | — |
| `sso_ssf_sets_received_total` | Counter | outcome |
| `sso_conditional_access_decisions_total` | Counter | decision |
| `sso_token_policy_{evaluations,denials,renew_required}_total` | Counter | bounded policy outcome dimensions |
| `sso_token_usage_{events,dropped}_total` / `sso_token_usage_tracked_buckets` | Counter/Gauge | bounded outcome / — |
| `sso_token_anomaly_findings_total` | Counter | severity/type bounded by detector vocabulary |
| `sso_degradation_mode` / `sso_degraded_rejections_total` | Gauge/Counter | mode / mode, method |
| `sso_config_drift_detected_total` | Counter | — |
| `sso_dr_last_drill_success` | Gauge | — (absent before the first drill) |

Scope-registry (`oauth.scope_registry.enabled`) rejections introduce **no new
audit event type and no new metric**: they are plain 400 `invalid_scope`
responses covered by the existing per-request logging, preserving bounded
cardinality — the registry itself is build-once server config, so there is no
runtime state to observe beyond request outcomes.

`sso_feature_gate_enabled` is seeded once at boot. A supported SIGHUP reload
changes live route state but does not currently update this gauge, so use it as
startup configuration rather than current-state telemetry. ADR-0009's future
module manager centralizes transition state and metrics. The `branding` gate
(formerly labeled `web_spa`) represents only `/branding`; it does not indicate
that a static frontend is served.

## Audit

### Pipeline

Compose `Async → Multi → Retry → leaf`. Hash chain: `PrevHash`+`Hash`; verify via `sso-ctl audit-verify`. Bounded dimensions: outcome/type/client/provider (see the `platform/audit` invariant in AGENTS.md §2).

### Hard Constraints

- Use `SetMeta(e, k, v)`. NEVER `e.Metadata = map{...}` (clobbers enrichment).
- Every Event carries W3C `TraceID`/`SpanID`.
- Optional `FacetQuerier` (type-asserted, `GET /api/v1/audit/facets`); 501 when unsupported.
- `feature_gates_disabled` — emitted once at boot ONLY when an operator explicitly disabled ≥1 `feature_gates` surface; `Reason`/`disabled_gates` metadata lists the gate names (comma-joined). A build that never touches `feature_gates` emits nothing new here.
- `auth_hook_executed` / `auth_hook_failed` — one per registered authentication-pipeline Hook invocation; metadata includes phase, bounded hook name, duration, and whether the flow continued. Hook errors, headers, credentials, claims, and token material are excluded.
- `client_secret_expiring` — the client-secret expiry scanner (always
  wired with a client store) found a client whose `secret_expires_at`
  landed inside a 30/14/7-day warning window. `ClientID` names the machine
  identity and `Reason` is the window; emitted once per (client, window)
  per day. The metric `sso_client_secrets_expiring_total{window}` carries
  the same signal and the log message is the fixed `client secret
  expiring` with bounded `client_id`/`window`/`days_remaining` keys.
- `tenant_quota_store_failure` — the authenticated tenant token-rate check failed open because its backing store returned an operational error. `Reason` is the fixed `increment_failed` enum; `resource=token_rate` is added only through `SetMeta`; tenant/client identifiers remain internal to audit and never appear in the `rate_limited` wire response.
- Session quota lifecycle logs use the fixed messages `tenant session quota reservation failed open`, `tenant session quota reconciliation failed`, and `tenant session quota release failed`, with bounded `tenant_id`/`session_id` plus the dependency error. A definitive cap is not logged as an infrastructure failure and remains the stable `403 quota_exceeded` response.

### Retention Schedulers

| YAML | Function | label |
|---|---|---|
| `audit.retention.*` | `platform/audit/sqlite.Sink.Prune` | `audit` |
| `snapshot.retention.*` | `interfaces/snapshot.PruneOldest` | `snapshot` |
| `mfa.provider.push.prune_interval` | `infrastructure/defaultimpl/sqlite.PushApprovalStore.PruneExpired` | `push_approvals` |

### Config

| YAML | Effect |
|---|---|
| `metrics.tenant_label_allowlist` | `WithTenantMetricsAllowlist` — bounded per-tenant login/issue metrics + `"other"` bucket; empty = off |

## Standalone Billing Background Work

The separate `snaplink-billing` process logs a successful non-empty renewal
scan as `subscription renewal settlement completed: N results`. An operational
error records the number already committed before the failure and the error as
`subscription renewal settlement failed after N results`; context cancellation
during normal shutdown is suppressed. Individual business outcomes are durable
commerce outbox facts: `snaplink.billing.subscription.renewed`,
`snaplink.billing.subscription.renewal_failed`,
`snaplink.billing.subscription.status_changed`, and the paired wallet debit
where applicable.
They are relayed to the tenant-scoped Audit Governance source.

When an Audit Governance relay desired-state file is configured, bounded log
records report module transitions with module event type and generation only;
they never include config bytes, bearer tokens, tenant IDs or event payloads.
An invalid, equivocal or stale reload leaves the active generation in place
and changes `/readyz` check `audit_relay_module` to `error`. Restoring the
applied state or publishing a valid newer revision clears that condition. During blue/green replacement the old worker
holds a background lease only for its current outbox batch, so transition drain
status reflects real in-flight work rather than an immortal worker lease.

The billing process exposes unauthenticated Prometheus text at `GET /metrics`.
Renewal metrics have no tenant, subscription, plan, owner, or error-string
labels, so their cardinality is fixed:

| Metric | Meaning |
|---|---|
| `snaplink_billing_renewal_enabled` | `1` when this process runs the automatic renewal worker. |
| `snaplink_billing_renewal_due_subscriptions` | Durable global count of subscriptions eligible now; rows leased by another replica remain visible. |
| `snaplink_billing_renewal_backlog_oldest_age_seconds` | Age since the oldest row became eligible, using its later retry schedule when applicable. |
| `snaplink_billing_renewal_backlog_observed_timestamp_seconds` | Last successful durable backlog observation; use it to distinguish a real zero from a stale sample. |
| `snaplink_billing_renewal_last_successful_cycle_timestamp_seconds` | Last cycle that both drained available batches and inspected the backlog without an operational error. |
| `snaplink_billing_renewal_last_cycle_error` | `1` when the most recent completed cycle failed; no error value is exported as a label. |
| `snaplink_billing_renewal_cycle_{successes,errors}_total` | Per-process completed-cycle outcomes. |
| `snaplink_billing_renewal_settled_subscriptions_total` | Per-process count of committed settlement results. |
| `snaplink_billing_renewal_readiness_degraded` | Exact boolean verdict used by the renewal readiness check. |

When renewal is enabled, `/readyz` includes `subscription_renewals`. A single
cycle error records metrics and logs but does not evict the process. The check
changes to `error` only when the oldest observed due row is more than 15
minutes old, or when startup/the last fully successful cycle is more than 15
minutes old. This fixed tolerance is deliberately much larger than the default
one-minute scan interval. The alert rules warn on cycle errors before the
readiness fence, then page on sustained degradation. A failed batch leaves its
claim fenced until lease expiry while earlier per-subscription transactions
remain committed; workers keep running after readiness is withdrawn and can
recover the backlog. Counters and cycle timestamps are per process and reset on
restart, while due count and oldest age come from the shared durable store.

When Entitlement projection is configured, `/readyz` adds
`tenant_quota_projection`. It delegates to the durable leased Entitlement
cursor and turns `error` only when the oldest unfinished fact exceeds
`SNAPLINK_BILLING_QUOTA_MAX_LAG` or its store cannot be inspected. It does not
probe either sink on every readiness request. Each claimed revision is sent to
SSO quota and, when configured, Audit Governance retention; Billing
acknowledges the shared cursor only after both sinks succeed. Temporary
HTTP/token failures persist a bounded reason and retry time on that cursor;
logs use the fixed prefix `tenant quota projection relay paused after error`
and never contain bearer tokens, client secrets, response bodies, tenant IDs
or projection payloads. Alert on sustained readiness failure for two max-lag
evaluation windows and on repeated worker pauses. A green
`audit_relay_module` proves only the independent audit-event relay: it does not
prove retention projection is green. Conversely, a green Entitlement cursor
does not prove audit-event delivery.

## Stripe Payment Adapter

The standalone `snaplink-stripe-adapter` exposes `GET /livez`, `GET /readyz`
and Prometheus text at `GET /metrics` on its HTTPS operations listener.
Readiness checks only PostgreSQL and the configured Snaplink JWKS endpoint.
Inbox volume, age and quarantine are deliberately alert signals rather than a
readiness veto, so an out-of-order event or dependency backlog cannot evict all
workers and prevent recovery.

All metric names and labels are bounded; the adapter emits no tenant, order,
event, provider-object or error-string labels:

| Metric | Meaning |
|---|---|
| `snaplink_stripe_webhook_{accepted,ignored,rejected,conflict}_total` | Signed webhook ingestion outcomes; conflict includes same event id with a different digest. |
| `snaplink_stripe_checkout_{created,replay,expired,failed}_total` | Checkout creation and deterministic reservation outcomes. |
| `snaplink_stripe_relay_{delivered,retried,quarantined}_total` | Billing delivery worker outcomes since process start. |
| `snaplink_stripe_inbox_pending` | Undelivered, non-quarantined rows eligible now or after retry/lease expiry. |
| `snaplink_stripe_inbox_quarantined` | Durable rows requiring operator reconciliation. |
| `snaplink_stripe_backlog_threshold_exceeded` | Boolean count/oldest-age threshold verdict from `MAX_BACKLOG` and `MAX_BACKLOG_AGE`. |

Alert immediately on readiness failure and any increase in webhook conflict.
Alert on a sustained threshold verdict, growing quarantine, retries without
deliveries, Billing 401/403 responses at the edge, PostgreSQL saturation, and
signature/account/live-mode/API-version rejection rates. Correlate an incident
with Billing's immutable payment/ledger entries and Audit Governance receipts;
an adapter `delivered` counter alone is not settlement proof.

Worker logs use fixed messages such as `relay claim failed`, `relay deferred`,
`relay quarantined`, and `relay acknowledgement failed`, with only an event id
and bounded category where applicable. They never contain raw webhook bodies,
Stripe signature/API keys, OAuth tokens or Billing client secrets. After PITR,
observe pending decreasing, quarantined matching the reviewed exception
register, and delivered increasing before scaling out. Process counters reset
on restart, while inbox, effect receipts and quarantine remain durable in
PostgreSQL; recovery decisions must use both surfaces.

## Audit Governance Provisioner

The independent provisioner exposes `GET /livez`, `GET /readyz`, and
Prometheus text at `GET /metrics` on its operations listener. Readiness is green
only after an exact successful reconciliation. A stale revision,
same-revision-different-content, remote record drift, invalid manifest, OAuth
failure, or control-plane outage makes readiness fail while
`applied_revision` retains the last successful value.

Metrics use fixed labels only:

| Metric | Meaning |
|---|---|
| `snaplink_audit_provisioner_ready` | Boolean current readiness. |
| `snaplink_audit_provisioner_applied_revision` | Last exactly reconciled revision. |
| `snaplink_audit_provisioner_reconcile_total{result}` | Success/failure attempts. |
| `snaplink_audit_provisioner_revision_rejected_total{reason}` | Stale or conflict rejection. |
| `snaplink_audit_provisioner_created_total{kind}` | Tenant/source/schema creations. |

Logs contain only a fixed result class, revision, and creation counts; client
secrets, bearer tokens, response bodies, tenant IDs, and manifest content are
never logged. Alert when readiness remains zero for two poll intervals, any
revision-rejected counter increases, or the applied revision differs from the
deployment's reviewed manifest. A successful liveness probe alone does not
prove that desired state is applied.

## Tracing

Middleware stack (probes registered OUTSIDE):

```
/metrics, /livez, /readyz                         ← outside ratelimit
tracing → ratelimit → bodyLimit → metrics → CORS → router
```

`Tracing` stamps the W3C trace ID onto the request context
(`core.WithTraceID`, read back via `core.TraceIDFromContext`) as well
as the `X-Trace-Id` response header. Error responses written through
`interfaces/sso`'s `errorBody`/`authzErrorBody`/`authzErrorBodyDesc`
helpers also surface it as `trace_id` in the JSON body (see
`docs/error-codes.md`) so a client can correlate a failed request to
audit/trace records without inspecting response headers.

### Async-path spans

`platform/tracing` exposes `StartSpan`/`DetachedContext`/`ParentFromIDs`/`SetError`
so background code doesn't hand-roll `otel.Tracer(...)` lookups. Four
background paths that run after their triggering request has already
returned are instrumented with this seam:

| Span | Package | Parenting |
|---|---|---|
| `audit.sink.deliver` / `audit.sink.deliver_batch` | `platform/audit` (`AsyncSink`) | `Event.TraceID`/`SpanID` (ctx itself is `context.Background()` by design — see `AsyncSink.Record`) via `tracing.ParentFromIDs` |
| `audit.webhook.deliver` | `platform/audit/auditsink` (`WebhookSink`) | whatever span the caller's ctx carries (nests under `audit.sink.deliver` when composed via `AsyncSink`) |
| `audit.sink.retry` | `platform/audit/auditsink` (`RetryingSink`) | same as above; one span per `Record` call, attempts as an attribute, NOT one span per retry |
| `caep.transmitter.deliver` | `protocols/caep` (`Transmitter`) | `Record`'s live span via `context.WithoutCancel` (cancellation is dropped, the span AND every other context value — e.g. break-glass actor metadata — survive); re-attempts are span events, not child spans |
| `cluster.bus.publish` / `cluster.bus.subscribe` | `platform/cluster/{memory,etcd}` | `ctx` directly — these run synchronously on the caller's goroutine |
| `migrate.run` | `platform/migrate` | `ctx` directly; every shipped caller passes `context.Background()` at backend construction, so this is always a fresh root span in practice |

A rootless span here (no parent) is expected, not a bug: it means the
triggering request already returned before the background work ran.

## Access log

`interfaces/middleware.AccessLogger` (design
`docs/design/middleware-observability-unified.md`, Decision 1) emits exactly
one INFO `"access"` record per request with a fixed, low-cardinality field
set:

| Field | Source | Notes |
|---|---|---|
| `method` | `r.Method` | |
| `path` | `r.URL.Path` | never `RawQuery` — query strings can carry `code`/`token` |
| `status` | captured status code | default 200 when the handler never calls `WriteHeader` |
| `duration_ms` | wall-clock since middleware entry | includes rate-limit wait, matches operator intuition for "slow request" |
| `client_ip` | `peertrust.ClientIP(r)` | validated real IP under trusted proxies; legacy first-hop fallback otherwise (one implementation shared with audit `ClientIP`) |
| `request_id` | `X-Request-Id` request header | populated by the tracing middleware when installed; empty otherwise |
| `trace_id` | `core.TraceIDFromContext` | populated by the tracing middleware when installed; empty otherwise |

Chain slot (inside trusted proxies, outside rate limiting):

```
/metrics, /livez, /readyz                         ← outside ratelimit
trustedProxies → access-log → ratelimit → bodyLimit → metrics → CORS → router
```

- Outside rate limiting so a 429 rejection is logged with its status — a
  flood that gets rate-limited still leaves access evidence (mirrors how the
  metrics recorder counts 4xx statuses).
- Inside trusted proxies so `client_ip` is the validated real IP, not a
  forgeable raw XFF value (the same invariant rate limiting relies on).
- Probes `/livez` `/readyz` `/metrics` are served by `buildProbeMux` outside
  the whole chain, so they never produce access records — zero code.

Body capture is OPTIONAL and strictly policy-gated (`BodyLogPolicy`): the
zero value never reads or logs a body (credentials are structurally
impossible to log). Capture requires an exact-path allowlist (or the
deprecated `AllowAllPaths` escape hatch), an explicit `sample_rate > 0`, and
is bounded by `max_body_bytes` and a redaction engine — credential-shaped
keys (exact vocabulary + substring heuristic on
`secret`/`password`/`token`/`assertion`/`code`, case-insensitive) are
replaced with exactly `[redacted]` in form-urlencoded and JSON bodies at any
nesting depth; other content types pass through capped raw bytes. Operators
who need DEBUG verbosity still have `logging.level: debug`; the access log is
no longer behind that switch. `sso-server` enables the access log by default
(`logging.access_log.enabled`, tri-state); SDK embedders opt in via
`sso.WithAccessLogging` — `sso.WithRequestLogging(bool)` is deprecated and
now takes the policy (`BodyLogPolicy{AllowAllPaths: true}` reproduces the old
`logBodies=true` posture).

`client_ip` extraction moved to `shared/security/peertrust.ClientIP`
(peertrust owns the proxy-boundary trust decision); `audit.ClientIP`
delegates to it — byte-identical behavior, one implementation.
