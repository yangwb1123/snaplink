# Observability

Metrics, audit, and tracing reference. Extracted from AGENTS.md.

## Metrics

All metrics use bounded cardinality — **no per-path/per-user labels**.

| Metric | Type | Labels |
|---|---|---|
| `sso_http_requests_total` | Counter | method, status_class |
| `sso_http_request_duration_seconds` | Histogram | method |
| `sso_login_attempts_total` / `_duration_seconds` | Counter/Histogram | provider, outcome |
| `sso_tokens_issued_total` | Counter | strategy |
| `sso_risk_decisions_total` | Counter | decision |
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
| `sso_connection_health_probes_total` | Counter | type (oidc\|saml), outcome (healthy\|degraded\|unreachable) |

## Audit

### Pipeline

Compose `Async → Multi → Retry → leaf`. Hash chain: `PrevHash`+`Hash`; verify via `sso-ctl audit-verify`. Bounded dimensions: outcome/type/client/provider (see AGENTS.md §4 cardinality rule).

### Hard Constraints

- Use `SetMeta(e, k, v)`. NEVER `e.Metadata = map{...}` (clobbers enrichment).
- Every Event carries W3C `TraceID`/`SpanID`.
- Optional `FacetQuerier` (type-asserted, `GET /api/v1/audit/facets`); 501 when unsupported.

### Retention Schedulers

| YAML | Function | label |
|---|---|---|
| `audit.retention.*` | `audit/sqlite.Sink.Prune` | `audit` |
| `snapshot.retention.*` | `snapshot.PruneOldest` | `snapshot` |
| `mfa.provider.push.prune_interval` | `sqlite.PushApprovalStore.PruneExpired` | `push_approvals` |

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
| `caep.transmitter.deliver` | `protocols/caep` (`Transmitter`) | `Record`'s live span via `tracing.DetachedContext` (cancellation is dropped, the span link is not); re-attempts are span events, not child spans |
| `cluster.bus.publish` / `cluster.bus.subscribe` | `platform/cluster/{memory,etcd}` | `ctx` directly — these run synchronously on the caller's goroutine |
| `migrate.run` | `platform/migrate` | `ctx` directly; every shipped caller passes `context.Background()` at backend construction, so this is always a fresh root span in practice |

A rootless span here (no parent) is expected, not a bug: it means the
triggering request already returned before the background work ran.
