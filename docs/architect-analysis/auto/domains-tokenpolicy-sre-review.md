# SRE Review: token-policy lifecycle design at the API/proxy boundary

Reviewer role: SRE engineer (detect / withstand / recover).
Input: `docs/auto/domains-tokenpolicy-design.md` (12 decisions, failure-mode
table, distributed-systems review) plus the current tree's operational
surface: the `sso-server` API backend, its readiness/metrics/audit/shutdown
machinery, and the external frontend/proxy boundary
(`ops/deploy/openresty`, `ops/deploy/openresty/fullstack`).

Scope: operators' ability to detect, withstand, and recover from failures of
(1) the API backend generally, (2) the proposed token-policy lifecycle
change, and (3) the edge/proxy boundary in front of it.

This is an advisory review of a **proposal**. The design's decisions are not
implemented (`WithTokenPolicyDefaultTTL` does not exist; `Store` is
`Policies()`-only; `ParseYAML` is a bare `yaml.Unmarshal`; the sqlite store,
the three `:name` routes, and `KindTokenPolicyChange` do not exist).

## Verification run for this review

Claims below are labeled per the evidence standard. Checks that actually ran
on this tree (no code changed):

- `interfaces/sso/server_health.go` — `/readyz` aggregate: 3s bound, named
  checks, error strings withheld from the body, per-check timeout support.
  **Verified**
- `cmd/sso-server` ready checks: redis (`build_bootstrap.go:222`), postgres
  (`build_bootstrap.go:314`), invalidation-bus (`build_app_cluster.go:161`),
  signing-key-aggregation (`build_app_cluster.go:237`), etcd-signing-key-registry
  (`build_app_cluster.go:249`), netpolicy-classifier (`build_app_core.go:470`),
  dr (`build_http.go:67`), saml (`build_http.go:408`), sqlite stores via
  `serverbuildsign.AppendReadyCheck` (`build_readiness.go:24`). **Verified**
- `interfaces/sso/server_invalidation.go` — bus self-heal: degraded flag,
  1s→30s exp backoff + deterministic jitter (`invalidationBusBackoff`),
  `resubscribeAndReseed`, one audit event per transition
  (`invalidation_bus_degraded`/`_recovered`), `InvalidationBusReady` →
  `/readyz` only when a bus is wired, `applyInvalidationSafe` recover guard,
  unknown-kind default arm. **Verified**
- `interfaces/sso/server_discovery_cache.go:293` `flushInvalidationCaches`
  (restore/reseed sweep — the design's recovery hook target). **Verified**
- `domains/tokenpolicy/{evaluate.go,clamp_issuer.go,tokenpolicy.go,yaml.go,
  admin.go}`, `memory/store.go` — fail-open `Policies()` errors, COW snapshot,
  deny reasons never on the wire. **Verified**
- `platform/metrics/metrics_token.go` — `sso_token_policy_{evaluations,
  denials,renew_required}_total`, zero series when unwired. **Verified**
- `ops/deploy/grafana/alerts.yaml` — 11 alert rules; none reference
  `sso_invalidation_bus_up`, `sso_dr_*`, `sso_config_drift_detected_total`,
  `sso_degradation_mode`, storage-health, or token-policy metrics.
  **Verified**
- `cmd/sso-server` grep for backup wiring: no `WithBackupSource` call site;
  `interfaces/sso/options_httpstack.go:196` is SDK-opt-in; the admin backup
  endpoint mounts only when sources are wired (`server_routes_admin.go:152`).
  `sso-ctl` has no backup command (`cmd/sso-ctl`: auditverify, config, import
  (Okta-only), migrate, snapshot, sessions, tokens). **Verified**
- `config/source.go:106,257-264` — strict decode with `DisallowUnknownField`,
  **warning + fallback re-decode** on unknown keys (config never fails on
  unknown keys). **Verified**
- `cmd/sso-server/serverbuildsign/build_readiness.go:44` `CheckSQLiteSchema`
  — boot gate, `migrate.CheckSchema` vs `binaryMax`. **Verified**
- `platform/migrate/migrate.go:161-206` — single-conn `BEGIN IMMEDIATE` +
  `busy_timeout`; `domains/threataction/sqlite/policy_store.go` package doc —
  "shared across replicas pointed at the same database file". **Verified**
- `cmd/sso-server/main_shutdown.go` — ordered shutdown: watch loops →
  schedulers → authenticator/notification drain → anomaly/usage/audit drains
  → SSE broker close before HTTP drain (`closeSSEBroker`). **Verified**
- `ops/deploy/openresty/{README.md,conf.d/sso.conf,conf.d/proxy_pass.inc,
  fullstack/lua/gateway.lua}` — prototype boundary statements, route table,
  `verify()` on `/api/v1/*`, X-Auth-* strip + X-Network stamp, edge
  `audit.jsonl`. **Verified**
- `docs/dr-framework.md` — failure levels with RPO/RTO **targets**;
  `docs/observability.md` — metrics/tracing/audit contracts. **Verified**

---

## 1. Service/dependency map and operational assumptions

```text
                     ┌────────────────────────────  external  ────────────────────────────┐
   browser SPAs ─────┤  OpenResty edge (prototype) ─ /app, /admin, /login static assets    │
 (separate projects) │  /api/v1/* → auth.verify() (user JWT) → proxy_pass                  │
                     └───────┬───────────────────────────────────────────────────────────┘
                             │ XFF / X-Auth-Subject / X-Network / Traceparent / X-Request-Id
                    ┌────────▼─────────────────────────┐
                    │  sso-server replica (stateless)  │   probes OUTSIDE ratelimit:
                    │  /livez /readyz /metrics         │   /livez /readyz /metrics
                    └───┬──────┬──────┬──────┬─────┬───┘
          shared durable│      │      │      │     │
        ┌───────────────▼┐ ┌───▼──┐ ┌──▼────┐┌────▼───┐┌──────────────┐
        │ SQLite files    │ │Redis │ │Postgres││ etcd   ││ KMS/HSM      │
        │ identity/oauth/ │ │hot   │ │durable ││ bus +  ││ signing      │
        │ audit/… + NEW   │ │stores│ │stores  ││ registry││ (fail closed)│
        │ token_policies  │ └──────┘ └────────┘└───┬────┘└──────────────┘
        └────────────────┘                         │ Watch/subscribe
                                    ┌──────────────▼───────────┐
                                    │ audit sinks (async→multi  │
                                    │ →retry→leaf sqlite/kafka/ │
                                    │ webhook), DR target dir,  │
                                    │ notification router       │
                                    └──────────────────────────┘
```

Per-replica in-process state that the design adds: the token-policy snapshot
(memory COW, or sqlite store's in-memory snapshot refreshed on write / bus
event / recovery flush).

Operational assumptions (from `docs/deployment.md`, `docs/dr-framework.md`,
AGENTS.md §3, READMEs):

- A1. Replicas are stateless app tier; shared state lives in backends; SQLite
  multi-replica deployments require all replicas to point at **the same file
  on a POSIX shared mount** (threataction/sqlite package doc). Per-replica
  DSNs silently split the single source of truth.
- A2. Probes bypass rate limiting; `/readyz` failing drains a pod via the
  kubelet; `failureThreshold: 4` at 5s in the prod overlay tolerates
  transient backend blips ("Tolerant readiness", `k8s-prod/patch-deployment.yaml:56`).
- A3. The invalidation bus is best-effort; dropped events converge via
  recovery reseed (`KindControlPlaneRestore`) or restart; bus degradation
  trips `/readyz` and emits one audit event per transition.
- A4. Token-policy evaluation is fail-open (governance, not credentials);
  the only fail-closed behavior is a matched policy's explicit deny.
- A5. The frontend is a separate deployment; the OpenResty gateway is a
  prototype, not a production authorization boundary (its own README).
- A6. RPO/RTO are **targets to configure and measure**, not enforced
  guarantees (`dr.rpo_target`/`dr.rto_target` feed a report-only verdict).

SLO/RTO/RPO status: documented RPO/RTO targets exist per failure level
(`docs/dr-framework.md` §2: L2 RTO minutes, L3 RTO tens of minutes, L4 RTO
hours / RPO bounded by `dr.interval`), measured via
`sso_dr_snapshot_replication_lag_seconds`, `sso_dr_readiness`, and
`RecoveryTimeTracker`. **No availability SLO (e.g. login-success or
token-issue percentage) is documented anywhere.** Needed decision: define an
SLO and its SLI before launch — the raw material exists
(`sso_login_attempts_total{outcome}`, `sso_tokens_issued_total`,
`sso_http_requests_total{status_class}`) but no target, no burn-rate alert.
For the token-policy feature specifically: define the governance-consistency
measure (see F2) since no SLO text exists for snapshot freshness.

---

## 2. Readiness table

| Signal | Dependency | Failure behavior | Alert today | Runbook today |
|---|---|---|---|---|
| `/livez` | process | always 200 when handler runs; kubelet liveness | `SSOInstanceDown` (via `up` metric) | `ops/deploy/baremetal-ha/RUNBOOK.md` (validation draft, not executable — its own header) |
| `/readyz` (aggregate, 3s bound) | named checks below | 503 + per-check map; pod drained from rotation | none per-check (only instance-down) | none |
| `/readyz: redis, postgres` | Redis/Postgres ping | drain replica; tolerant threshold 4×5s | none | none |
| `/readyz: invalidation-bus` | etcd/memory bus subscribe | drain replica while degraded (1s→30s backoff loop) | **none** — gauge `sso_invalidation_bus_up` exists but no rule references it (F1) | none |
| `/readyz: signing-key-aggregation, etcd-signing-key-registry` | registry watch | drain replica; unknown-kid validation failures follow next rotation | `SSOSigningKeyAggregationDegraded` (warning) | none |
| `/readyz: netpolicy-classifier` | netpolicy watch | drain replica | none | none |
| `/readyz: dr` | DR replica within RPO | drain replica | `sso_dr_readiness` gauge exists, **no rule** (F4) | dr-framework §6 drill procedure |
| `/readyz: sqlite-*` (jti-replay, account-lockout, ratelimit, …) | store Ping | drain replica | none | none |
| `/metrics` | — | outside ratelimit; scrape target | alert rules in `ops/deploy/grafana/alerts.yaml` (11 rules) | dashboard `sso-overview.json` |
| `/api/v1/admin/storage-health` | per-store Ping + schema versions | 200 with per-source status; admin:read | none (F2) | none |
| `/api/v1/admin/dr/status` | DR verdict, lag, RTO history | report-only, never affects requests | none (F4) | dr-framework §5 |
| `POST /api/v1/admin/backup` | `WithBackupSource` sources | **unmounted in the stock binary** (no cmd wiring — F3) | n/a | n/a |
| `/_gateway/health` (edge) | OpenResty itself | 200 when edge serves | none | none |
| Edge `logs/audit.jsonl` | per-request log_by_lua | non-tamper-evident JSONL; **not a substitute** for the audit pipeline (README) | none | none |
| Token-policy admin routes (design) | store + sqlite file | GET/PUT/DELETE `500` on store outage; evaluation unaffected (fail-open) | none planned (F2/F9) | none planned |
| Token-policy snapshot freshness (design) | bus events + refresh | stale snapshot serves indefinitely if events stop (design F2) | **no metric planned** — design residual risk 2 admits the gap (F2) | none |

---

## 3. Findings

### F1 [High] Invalidation-bus degradation: gauged and readiness-gated, but no alert and no runbook

- **Evidence**: `setInvalidationBusDegraded` (`server_invalidation.go:154`)
  sets `sso_invalidation_bus_up = 0`, emits `invalidation_bus_degraded`
  audit, and `InvalidationBusReady` flips `/readyz` to not-ready. Grep of
  `ops/deploy/grafana/alerts.yaml`: no rule matches `sso_invalidation_bus_up`
  (verified full file, 11 rules). The bus is the delivery mechanism the
  design's `KindTokenPolicyChange` arm depends on (决策 8).
- **Impact**: (a) a degraded bus drains the replica via `/readyz` but pages
  nobody — an operator notices only via dashboard spelunking; (b) if the bus
  outage is fleet-wide (etcd partition), **all** replicas drain → full
  outage surfaced only by `SSOInstanceDown`; (c) the design's stale-snapshot
  window (F2 in the design) is exactly the silent period this alert should
  bracket.
- **Remediation**: add `SSOInvalidationBusDegraded` —
  `sso_invalidation_bus_up == 0` for 5m, severity warning, annotation citing
  `invalidation_bus_degraded` audit events and the resubscribe backoff;
  plus a one-paragraph runbook entry (verify etcd health, do not restart
  pods — the loop self-heals; restart only if backoff is stuck).
- **Recovery validation**: apply the rule, stop etcd (or kill the bus),
  confirm alert within 5m and `/readyz` 503; restore etcd, confirm
  `invalidation_bus_recovered` audit + gauge 1 + `/readyz` 200 before
  declaring recovery.

### F2 [High] Token-policy sqlite store: no readiness decision, no write-failure signal, no snapshot-age metric

- **Evidence**: design 决策 11 registers the store with the storage-health
  reporter and boot `CheckSQLiteSchema` but does **not** mention
  `AppendReadyCheck`; metrics are bounded (no per-path labels,
  `docs/observability.md`), so admin-route failures are invisible to
  `SSOHighHTTPErrorRate` (5% of **total** traffic — admin traffic is a
  rounding error); the design's own residual risk 2 admits the missing
  `last_refresh` gauge. `serverbuildsign.AppendReadyCheck`
  (`build_readiness.go:24`) is the existing pattern the design omits.
- **Impact**: (a) the "sqlite DB down after boot → writes 500" failure mode
  (design failure table) is undetectable: no metric, no alert, no ready
  check; operators discover a broken governance surface only during an
  audit; (b) unbounded snapshot staleness (design F2) has no observable
  signal — the one instrument that would bound it (refresh timestamp) is
  explicitly deferred.
- **Remediation** (required for launch): (1) decide the `/readyz` question
  explicitly — recommendation: **do not** gate `/readyz` on the governance
  store (consistent with fail-open evaluation; a governance outage must not
  drain the fleet), but (2) add a `sso_token_policy_snapshot_last_refresh`
  timestamp gauge + a `sso_token_policy_admin_write_errors_total` counter
  (bounded labels) and alert on staleness > N × bus re-subscribe bound and
  on write-error increments; (3) keep the storage-health registration (design
  already has it) so `Ping` failures surface per-store.
- **Recovery validation**: with the gauge, kill the bus, verify the gauge
  freezes and the alert fires; restart the replica, verify refresh
  timestamp advances and the alert clears.

### F3 [High] Restore path for `token_policies` is undefined; the stock binary has no backup surface

- **Evidence**: no `WithBackupSource` call in `cmd/sso-server` (verified grep
  — the endpoint `POST /api/v1/admin/backup` mounts only when an embedding
  app wires sources, `server_routes_admin.go:152`); `sso-ctl` has no backup
  command and `import` is Okta-specific; the DR snapshot subset explicitly
  omits governance tables (dr-framework §1: "does not include tenants,
  … audit rows or other backend-specific tables"); design 决策 9-11 never
  mention backup/restore of the table.
- **Impact**: losing the shared SQLite file (volume loss, corruption, botched
  migration) resets governance to seed-or-empty (fail-open default) with
  **no restore procedure**: TTL clamping silently disappears and
  over-long tokens are issued until someone notices. Admin-authored policy
  state is unrecoverable from any in-tree mechanism (the GET list endpoint
  can capture state, but there is no import/restore tool for it).
- **Remediation**: document in `docs/config-reference.md` (with the `sqlite`
  knob): (1) the `token_policies` table must be covered by the same
  file/volume backup as the other SQLite stores — `VACUUM INTO` via
  `WithBackupSource` where the embedding app wires it, volume snapshot
  otherwise; (2) restore = replace file + restart (migration idempotency
  covers double-`New`); (3) capture-before-mutate via the admin GET list as
  an operator habit; optionally add a `sso-ctl` export/import for the
  policy set in a follow-up.
- **Recovery validation**: drill — delete the table from a copy, restore the
  file, boot, verify `Policies()` returns the pre-delete set and
  `CheckSQLiteSchema` passes.

### F4 [Medium] DR readiness is report-only with no alerting: RPO breach is silent

- **Evidence**: `sso_dr_readiness`, `sso_dr_snapshot_replication_lag_seconds`,
  and `sso_dr_last_recovery_seconds` exist (`docs/observability.md`); the
  DR verdict "never affects request handling" (dr-framework §5); no alert
  rule references `sso_dr_*` (verified alerts.yaml).
- **Impact**: an RPO breach (replication stalled, target dir full, mount
  lost) is detectable only by polling `/api/v1/admin/dr/status`; at DR
  cutover the restore is older than the RPO target and nobody was paged.
- **Remediation**: add `SSODRReadinessDegraded` — `sso_dr_readiness == 0`
  for 2 × `dr.interval`, severity warning; and
  `SSODRRpoLagExceeded` — `sso_dr_snapshot_replication_lag_seconds >
  dr.rpo_target` (configured target), severity critical. Both are pure
  Prometheus rules on existing series.
- **Recovery validation**: stop the replication scheduler, verify both
  alerts fire, restart, verify `sso_dr_readiness` returns to 1.

### F5 [Medium] Edge boundary: the prototype requires a *user* JWT for all `/api/v1/*`, including admin; and its own README declares it non-production

- **Evidence**: `ops/deploy/openresty/conf.d/sso.conf` — `location /api/v1/`
  runs `auth.verify()` (user access-token JWT, Ed25519-only); the admin API
  is separately gated by admin bearer tokens (`Bearer realm="admin"`,
  `interfaces/admin/middleware.go:364`); README: "not the sole production
  authorization boundary… Do not use it as the sole production authorization
  boundary without a dedicated security review and conformance tests".
- **Impact**: (a) admin-bearer-only clients (sso-ctl, gRPC :8081 traffic,
  service-to-service admin automation) **cannot pass the prototype edge** —
  the edge has no admin-token passthrough story; a team copying the
  prototype into production would silently break their own admin tooling;
  (b) the 60s permission cache over-allows up to 60s after revocation
  (documented prototype behavior); (c) the edge `audit.jsonl` stream is a
  second, non-tamper-evident audit trail with no alerting and no retention
  story.
- **Remediation**: before any production promotion of a derived gateway:
  (1) add an explicit `verify_with_admin()` bypass (or documented
  `internal` location) for `/api/v1/admin/*` so admin-bearer clients pass
  through; (2) execute the README's production-hardening list as a
  checklist gate (token-validation parity incl. ECDSA/RSA/PS256 or explicit
  rejection, authoritative authz on `X-Auth-*`, JWKS pre-shipping,
  permission-cache invalidation, stream sink, rate limit + WAF); (3) treat
  edge `audit.jsonl` as debug telemetry, never as the audit trail
  (AGENTS.md audit pipeline is authoritative).
- **Recovery validation**: conformance test — an admin-bearer-only PUT to
  `/api/v1/admin/token-policies/foo` through the gateway returns 200 with
  `realm="admin"` challenge on missing token, and is **not** blocked by the
  user-JWT gate.

### F6 [Medium] Strict-parse boot failure is a rollout hazard with no pre-flight validation surface

- **Evidence**: design 决策 1/4 — `ParseYAML` + `Validate` fail boot on
  typo'd/negative config (intended loud failure, risk 7 in the design); the
  config loader itself tolerates unknown keys (warning + fallback,
  `config/source.go:257-264`) so `sso-server config validate`
  (`cmd/sso-ctl/configcmd`) does not exercise the policy bundle parser;
  there is no `sso-ctl` command that parses + validates a
  `token_policies.file` bundle.
- **Impact**: a rollout with a typo'd bundle (`max_ttl_`) fails **boot**, not
  a canary check — with N replicas rolling, the first replica fails and the
  rollout tooling must already handle boot-failure (most do), but the
  failure is a crash-loop, not a clean pre-deployment rejection; the
  operator discovers it via `SSOInstanceDown`, not via CI.
- **Remediation**: add `sso-ctl config validate` coverage (or a tiny
  `sso-ctl token-policy validate --file` command) that runs
  `ParseYAML` + `Validate` + `AdvisoryWarnings` with the configured
  `server.token_ttl`, and wire it into the deploy pipeline's pre-flight
  step; document in config-reference (design already plans the migration
  note).
- **Recovery validation**: run the validator against a typo'd bundle — exit
  non-zero with the offending policy name before any replica restarts.

### F7 [Medium] Seed-skip surprise: config edits stop applying after first boot with no operational signal beyond a log line

- **Evidence**: design 决策 11 — seed only when the table is empty, "loud
  skip log" when skipped. No metric or audit event is planned for the skip;
  `sso_config_drift_detected_total` covers the *config file* digest across
  replicas, not the *DB contents* vs config divergence (design F3 notes
  this).
- **Impact**: an operator edits `token_policies.policies` expecting it to
  apply to an existing DB; it silently doesn't (by design), and the only
  trace is a boot log line. Across a fleet this becomes "governance drifted
  from source-of-truth" with no alert.
- **Remediation**: emit the skip as a fixed-cardinality counter
  (`sso_token_policy_seed_skipped_total`, label `reason=table_non_empty`)
  plus an audit event at boot, and alert on `increase(...) > 0` when
  `token_policies.policies`/`file` is configured alongside `sqlite` — the
  operator's intent (config governs) and the mechanism (DB governs) are in
  tension by design and should be loudly visible.
- **Recovery validation**: boot with a non-empty table + configured seed,
  verify the counter increments and the alert fires once.

### F8 [Low] LWW overwrite and DELETE-retry semantics need runbook wording

- **Evidence**: design 决策 7/9 — upsert is LWW with no versioning; DELETE of
  an unknown name returns `404 not_found` (threataction precedent, design
  F4). Both are documented in the design and consistent with threataction.
- **Impact**: a concurrent dual-writer PUT silently overwrites (audit records
  both); a retried DELETE misreads 404 as failure. Bounded, governance-only.
- **Remediation**: add one paragraph to the admin runbook: "same-name PUT is
  last-writer-wins; retried DELETE returns 404 once the name is gone —
  404 means already-deleted, not failed." No code change needed.

### F9 [Info] Admin-write failure visibility relies on future bounded counters (folded into F2)

The design's failure table ("store outage at admin GET/PUT/DELETE → 500
internal") is correct and oracle-safe, but with no per-path metrics the only
today-signal is `sso_http_requests_total{status_class="5xx"}` at a 5%
fleet-wide threshold — structurally unable to see a governance-surface-only
outage. F2's required counters close this. No separate action.

---

## 4. Failure drills

Each drill: trigger → expected behavior → detection → recovery → validation
gate. Drills are executable against the current tree plus the design's
acceptance tests; run them in staging before launch.

### D1 — Outage: shared SQLite file unavailable after boot

- Trigger: `token_policies` DB file unreadable / lock file stale (NFS
  hiccup) mid-flight.
- Expected: issuance unaffected (`Policies()` serves the snapshot — design
  决策 10; verified pattern: `enforceTokenPolicy` fails open,
  `server_helpers.go:86`); admin GET/PUT/DELETE `500 internal`; storage-health
  `Ping` reports error.
- Detection: F2 counters/alert (write errors), storage-health check; **today:
  nothing** — this is the drill that fails.
- Recovery: restore file reachability (mount/NFS); no restart needed for
  evaluation; writes recover on next request.
- Validation: PUT succeeds again; `Ping` green; snapshot gauge advances.

### D2 — Saturation: policy evaluation traffic + admin write storm

- Trigger: a `block_scope_combos` rule starts denying a large client's
  traffic, or an automation loop PUTs policies in a tight loop.
- Expected: `sso_token_policy_denials_total` rises (bounded reason labels);
  deny responses stay generic (`invalid_scope`/`invalid_grant` — oracle-safe);
  sqlite writes serialize on the file lock (`busy_timeout` for migrate only —
  store `Put` uses the driver's default; note: **no busy_timeout guarantee on
  the store's own writes** — a lock-storm returns SQLITE_BUSY → 500, which is
  acceptable and must be in the runbook as "retry", not "restart").
- Detection: denials alert (new — recommend
  `increase(sso_token_policy_denials_total[10m]) > threshold`), admin 5xx
  counter (F2).
- Recovery: adjust/delete the rule via the admin API (or config re-seed only
  on empty table); the family revokes itself via refresh rotation — no
  operator token surgery.
- Validation: denial rate returns to baseline; a golden-path login issues a
  token with the expected clamped TTL.

### D3 — Bad rollout: typo'd bundle + negative dimension

- Trigger: `max_ttl_` typo or `max_active_sessions: -1` shipped in
  `token_policies.file`.
- Expected: first replica **fails boot** with the policy name (design 决策 4);
  rollout tooling sees crash-loop; with F6 pre-flight validation the deploy
  pipeline rejects before any replica restarts.
- Detection: boot error log + `SSOInstanceDown` (if the rollout tool doesn't
  gate); the pre-flight validator's non-zero exit.
- Recovery: fix config, re-run validator, re-roll; existing replicas keep
  serving the previous config (no partial state).
- Validation: `sso-ctl` validator exits 0 on the fixed bundle; all replicas
  boot; `sso_token_policy_evaluations_total` resumes.

### D4 — Stale state: dropped `KindTokenPolicyChange` / bus permanently lost

- Trigger: etcd unreachable beyond the 30s backoff cap; or one event dropped
  in delivery.
- Expected: writer replica already consistent (write-sync refresh); peers
  serve a stale snapshot; `/readyz` **not-ready only when a bus is wired** —
  for the memory-bus/no-bus deployment there is no readiness signal at all.
- Detection: `sso_invalidation_bus_up == 0` (F1 alert — required); F2
  snapshot-age gauge.
- Recovery: bus restore → `resubscribeAndReseed` → `flushInvalidationCaches`
  (design adds the token-policy refresh here) → healthy; or restart the
  stale replica.
- Validation: after recovery, peer GET returns the new policy set; audit
  shows `invalidation_bus_recovered` with `re_seeded=true`.

### D5 — Restore: file loss / corruption of the shared DB

- Trigger: volume loss on the shared mount holding `token_policies`.
- Expected (with F3 remediation in place): restore the file from the
  file/volume backup (or `VACUUM INTO` artifact); boot; `New` reloads the
  snapshot; migration idempotency covers double-`New`; `CheckSQLiteSchema`
  passes (baseline v1).
- Detection: admin 500s + storage-health error + snapshot gauge frozen;
  `sso_token_policy_evaluations_total` continues (fail-open — the *absence*
  of denials is the silent tell that governance is gone; add a
  "governance enabled" gauge as part of F2 if desired).
- Recovery: restore file → restart → verify set; if no backup exists,
  re-seed from config (empty-table contract) and **reconcile admin-authored
  state from the GET-list capture habit** (F3).
- Validation: GET list matches pre-loss set; a default-client issue is
  clamped to `min(MaxTTL, DefaultTTL)`.

---

## 5. Launch blockers, rollback triggers, monitoring gaps, residual risks

### Launch blockers (must land with the design)

1. **F1 alert** (`sso_invalidation_bus_up == 0`) — the design's convergence
   mechanism has no page; ship the rule with the kind.
2. **F2 observability**: snapshot-last-refresh gauge + admin-write-error
   counter (the design's own residual risk 2 makes the gauge "suggested"; it
   is load-bearing for detection and should be required); explicit `/readyz`
   decision (recommend: not gated).
3. **F3 restore contract**: backup/restore section in config-reference for
   `token_policies.sqlite`; the design's failure table lists the outage mode
   but no recovery path.
4. Design's own F1 regression gate: rootcov test asserting default-client
   issuance ≤ configured non-1h `TokenTTL` — without it the
   min-clamp-widening class is unverifiable.
5. `sso-ctl` pre-flight validation for the bundle (F6) — or a documented
   pipeline step that runs the same parse+validate.

### Rollback triggers (stop-the-roll criteria)

- `sso_token_policy_denials_total` spikes for a rule that wasn't intended to
  bite (matched-policy deny is the only fail-closed path — treat any
  unexplained deny rate as rollback-worthy).
- The F1 regression test fails (default-client TTL > configured `TokenTTL`)
  — TTL-plumbing drift, the design's #1 risk, is live.
- Boot failures on strict parse across the fleet (config error, not code).
- Admin PUT/DELETE 500s sustained (sqlite file issue) while evaluation is
  unaffected — roll back the *wiring*, not the binary, unless the file is
  lost (then D5).
- Cross-replica divergence: peer GET returns a policy set that differs from
  the writer's after recovery flush — bus/convergence bug.

Rollback mechanics (verified safe): old binary ignores the `token_policies`
table (no migration state for a namespace it doesn't know; `CheckSQLiteSchema`
only runs for namespaces the binary wires); the config loader warns-and-
continues on the unknown `token_policies.sqlite` key (`config/source.go`);
**governance silently OFF during the rollback window** (fail-open default) —
state this in the runbook; re-apply policy state after rollback via the
admin API or empty-table re-seed. No downgrade migration exists (baseline v1
only, no forward migrations to reconcile).

### Monitoring gaps (post-launch backlog)

- No availability SLO/SLI defined (needed: login-success SLI + burn-rate
  alert; raw metrics exist).
- No DR alerts (F4), no config-drift alert
  (`sso_config_drift_detected_total` — governance divergence from
  config-digest is adjacent to F7).
- No edge/gateway alerting (edge 5xx, JWKS-fetch failure, permission-cache
  staleness) — the prototype has none; a promoted gateway needs its own.
- No degradation-mode alert (`sso_degradation_mode` transitions are audit +
  gauge only).
- No storage-health alert for any sqlite store (the design's new store would
  join a gap, not create one).

### Residual risks

1. **TTL-plumbing drift** (design risk 1) — remains the #1 risk; single
   wiring point + regression test are the only controls; add the boot
   invariant log ("token policy default TTL = issuer default TTL = X") so
   drift is visible in logs, not just in a test.
2. **Unbounded snapshot staleness** without the F2 gauge — accepted only
   with the gauge + alert.
3. **LWW dual-writer** — accepted, documented (F8); audit trail is the only
   reconstruction aid.
4. **Prototype edge as production boundary** — F5; must not be promoted
   without the hardening checklist + conformance tests.
5. **No stock-binary backup surface** (F3) — the token-policies table joins
   the other SQLite stores in relying on operator-managed file backup;
   document, don't assume.
6. **Seed-fleet skew** (design F5) — per-replica seed config must be
   identical; the design's empty-table check is the only guard.
7. **Mixed-version window** — old binaries ignore the new kind and enforce
   nothing; keep rollouts short and treat "governance off" during the window
   as the accepted state (eventual re-enforcement on full rollout).

### Bottom line

The design's fail-open, snapshot, and recovery-reseed choices are sound and
consistent with the tree's existing distributed machinery (verified). What is
missing is the **detection layer around them**: two of the three required
launch blockers (F1, F2) are pure alerting/metrics additions on existing
patterns, and F3 is a documentation + drill commitment. The outage,
saturation, and stale-state drills (D1, D2, D4) currently fail their
detection steps; with blockers 1-2 in place they pass. No credential or
data-loss path was found in the design; the only fail-closed surface remains
the matched-policy deny, which is the intended behavior.
