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
