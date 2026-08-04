# domains/tokenanomaly — Direction 3 design: SRE review (operability of the detection→response chain and the proxy boundary)

Reviewer role: SRE. Input: `docs/auto/domains-tokenanomaly-direction3-design.md` +
`domains-tokenanomaly-direction3-spec.md`, evaluated against the running system an
operator actually operates: `sso-server` startup/shutdown wiring, middleware
stack, probes, metrics/audit/tracing surfaces, DR framework, deployment assets,
and the external frontend/proxy boundary (`docs/frontend-contract.md`,
`docs/deployment.md`).

**Revision reviewed:** worktree at `HEAD 35dee544` ("Stage: design"). The design
changes no `.go` files, so **no Go gates were run** — every claim below was
verified by static inspection (full-file reads, `grep`/`sed` scans, `wc -l`)
against the same revision the sibling security/QA/protocol/perf reviews used.
Unrelated worktree modifications (`cmd/sso-server/*`, `test/*`) were not touched.

**Scope note.** The direction-3 design is *operationally inert* on the request
path: it adds one string to a telemetry Event, one field to an admin read
schema, and in-memory detector state. Everything an SRE cares about — where the
new state lives, what happens on restart, replica splits, saturation, and
config drift — is a property of the *existing* subsystem the design extends.
This review therefore evaluates both: the design's delta (Decision 1–6) and the
pre-existing operational envelope it inherits, because the delta's failure
modes are only visible through that envelope.

## 0. Checks that actually ran

| Check | Result |
|---|---|
| Static verification of every design claim cited below (seam sites, `handle_introspect.go:358`, budgets 442/155/493, `sso.go` wiring, `main_shutdown.go` ordering) | Verified — matches the design and the sibling reviews |
| `docs/observability.md`, `docs/config-reference.md` (token_anomaly/threat_action/degradation sections), `docs/deployment.md`, `docs/dr-framework.md`, `docs/frontend-contract.md` | Read in full; metrics inventory, config keys, and DR RPO/RTO tables quoted below are from these |
| `interfaces/sso/server_health.go` (/readyz aggregate), `server_routes.go` (probe mux + middleware order), `internal/handler/health.go` | Verified |
| `domains/tokenanomaly/{detector,detect,tokenanomaly,admin}.go`, `domains/tokenanomaly/memory/store.go`, `domains/metering/token_recorder.go`, `domains/metering/memory/token_store.go`, `domains/threataction/actions.go` + `registry.go` recordAudit | Verified |
| `cmd/sso-server/build_app_security.go` (wireTokenAnomaly), `serverbuildplatform/build_governance.go` (BuildTokenAnomaly), `main_shutdown.go` (shutdown ordering), `build_app.go`/`build_stores.go`/`build_http.go` (ready checks) | Verified |
| `ops/deploy/grafana/alerts.yaml`, `ops/deploy/baremetal-ha/RUNBOOK.md`, `ops/deploy/compose/` | Verified — alert inventory and runbook status below |
| `go build`/`go test` | **Not run** — no `.go` changed; the QA review measured the baseline this revision (build+vet PASS; `make ci` blocked pre-existing at fmt on two unrelated files) |

## 1. Service/dependency map and operational assumptions

### 1.1 The subsystem under change (as built today)

```
 request path (unchanged by design)
   /token (5 grant seams) ──RecordRefreshTokenIssued──► interfaces/sso
   /token/introspect (refresh branch, handle_introspect.go:358) ──Offer──►
        │
        ▼
   metering.Recorder ──bounded queue (1024, drop-on-full, 1 drainer)──►
        │                                                    (off request path)
        ▼
   tokenanomaly.Detector (decorates memory usage store)
        ├─ observation table  (per-thumbprint geo/velocity, cap 4096, NO gauge)
        ├─ [NEW] subjectMinuteRates (cap 4096 × window ≈ 65k entries, NO gauge)
        └─ forwards to memory Bucket store (cap 4096, gauge: sso_token_usage_tracked_buckets)
        │
        ▼
   RunTokenAnomalyDetection sweep (interval = token_anomaly.sweep_interval, no default)
        ├─ findings → memory FindingStore (cap 1024, NO gauge) → GET /api/v1/admin/tokens/suspicious
        ├─ metric  → sso_token_anomaly_findings_total{type,severity}
        └─ threat  → ThreatExecutors (rate-limited, fail-open) → audit threat_action_executed
                     → RevokeFamilyExecutor → DeleteFamily | DeleteAllForSubject
                     → cluster bus KindTokenRevoked (cross-replica cache invalidation)
```

Everything left of the recorder is per-process: observation table, subject
table, finding store, and the usage bucket store are **replica-local memory**.
The only shared state the chain touches is (a) the refresh-token stores
(memory/sqlite/redis) that `Inspect`/`DeleteFamily`/`DeleteAllForSubject` read
and write, and (b) the cluster bus for revocation propagation.

### 1.2 The API backend / proxy boundary (verified)

- **API-only backend.** `sso-server` serves no static frontend; the stock
  binary mounts no `/login/` filesystem route (`docs/frontend-contract.md` §1,
  `docs/deployment.md` §1). Frontends are separate deployments reverse-proxied
  at the same origin; the edge (OpenResty/Envoy/NGINX) must strip and re-set
  `X-Forwarded-*` and `security.trusted_proxies.{cidrs,hops}` must name the
  edge (`docs/config-reference.md:64`, deployment.md §9). Unset =
  legacy first-hop trust — the documented unsafe default.
- **Middleware order (Verified, `server_routes.go:330-435`):**
  probes (`/livez`, `/readyz`, `/metrics`) served OUTSIDE the whole stack;
  then `tracing → trustedProxies → ratelimit → degradation → bodylimit →
  metrics → CORS → router`. trustedProxies wraps before rate limiting so the
  limiter keys on the validated real IP; probes are never rate-limited,
  never counted, never body-capped.
- **Admin plane.** `/api/v1/admin/*` gated by `admin:read`/`admin:write`
  bearer authz; `GET /api/v1/admin/tokens/suspicious` is admin:read and is
  mounted only when a detector is wired (`sso.go:381-390`, `options_misc.go:299`).
  The direction-3 `family_id` addition stays on that admin-gated read API —
  **no new proxy-facing surface, no new wire bytes on credential endpoints.**
- **DR degraded modes.** The degradation gate sits inside rate limiting and
  outside body-limit; probes + the DR toggle always pass
  (`server_health.go` `degradationPolicy`). The detection subsystem is not
  part of any degraded-mode policy — it keeps running (or not) regardless of
  posture. Correct: detection must not be shed by a read_only mode an
  operator might set during a token incident.

### 1.3 Operational assumptions the design (and this review) rely on

1. **Detection is best-effort telemetry.** The recorder drops events on a full
   queue; `detectRateSpike` returns nil on store error; executor errors are
   logged, never propagated; the sweep loop survives finding-processing
   panics via `processFindingSafe`. All Verified. Nothing in direction 3
   changes this posture — the subject fold cannot fail `Record`, and the
   `handle_introspect.go` edit is an Offer field.
2. **No SLOs exist for token telemetry** (no benchmark, no latency/correctness
   target anywhere in `docs/`). The de-facto detection-to-action latency is
   `sweep_interval` after the triggering event (a sighting at minute T
   produces a finding no earlier than the next sweep tick), and the
   de-facto response latency adds the executor's store round-trips. **An
   operator choosing `sweep_interval` is choosing their response-time budget
   for a stolen-token family revoke — nothing documents this.**
3. **Findings are a rolling operational view, not an archive** — the
   `FindingStore` doc's own words (`tokenanomaly.go:130`), cap 1024, no
   persistence, no audit event from the detector itself. The durable
   forensics trail is (a) `threat_action_executed` audit events when a threat
   executor fires (meta includes `threat.type`/`action`/`subject`/`detail`
   plus bounded Evidence, `registry.go:240-262`), (b) the pre-existing family
   audit events (`RecordRefreshTokenReuse`,
   `RecordRefreshRotationVelocityExceeded`, `server_helpers.go:477-487`), and
   (c) scraped metrics. Direction 3 adds `family_id` to Evidence, so the
   family-vs-subject revoke path becomes distinguishable in audit via
   `threat.detail` ("revoked N token(s) in family X" vs "...for subject Y",
   `actions.go`) and the `family_id` evidence key.
4. **Cross-replica detection is out of scope and stays out of scope.**
   Direction-1 documented the per-replica observation table as a wave-1
   limitation; direction 3 adds *another* per-replica table (subject rates)
   and a per-replica family field on findings. The *action* is global
   (`DeleteFamily` hits the shared store; `KindTokenRevoked` propagates), but
   the *detection evidence* is not combined across replicas.

## 2. Readiness table

Signals available to an operator, their dependencies, failure behavior, and
what alerts/runbooks exist today. **(A)** = alert exists in
`ops/deploy/grafana/alerts.yaml`; **(—)** = no alert; **(runbook)** = covered by
`ops/deploy/baremetal-ha/RUNBOOK.md` — which self-declares a **validation
draft, not an executable production runbook** (obsolete config paths, no TLS
on the HAProxy binding, no systemd units; verified in its header).

| Signal | Dependency | Failure behavior | Alert | Runbook |
|---|---|---|---|---|
| `/livez` | none — process up | always 200 | SSOInstanceDown (A) | — |
| `/readyz` | every `WithReadyCheck`: sqlite stores, etcd registry/netpolicy, signing backend(s), external signers, DR readiness (report-only default) | 503 + per-check `checks` map, 3s aggregate deadline; body never leaks error strings (`server_health.go:88-130`) | via kubelet/orchestrator | — |
| **Token-anomaly subsystem** | recorder drain, usage store, finding store, sweep loop, threat executor | **None of these are readyz dependencies** — by design (fail-open). A dead sweep, a saturated queue, or a full finding store leaves `/readyz` green | **— none** (see F1) | — |
| `sso_token_usage_dropped_total` | recorder queue (1024) | drop-on-full; **metric-only — no log line when metrics are off** (`token_recorder.go` `Offer` default branch) | **— none** | — |
| `sso_token_usage_tracked_buckets` | bucket store cap (4096) | gauge pinned at cap = window silently shrinking | **— none** | — |
| `sso_token_anomaly_findings_total` | sweep | counts **emissions**, incl. re-detections (F3) | **— none** | — |
| Observation table (4096) | — | eviction at cap; **no gauge** (Detector.TrackedBuckets forwards only the bucket store) | **— none** | — |
| **[NEW] subject table (4096 × 16m)** | — | eviction at cap; **no gauge** (design's own admission) | **— none** | — |
| Threat executor | refresh stores, session manager, bus | fail-open: errors logged, action skipped; `rate_limit` per (subject,type,action) caps dispatch | **— none** | — |
| Redis / Postgres / etcd (tier B) | shared hot/durable stores + bus | fail-closed on /token (fast timeouts); the **general Redis hot-store path (codes/refresh/sessions) has no ready check** — the only Redis-backed check is the optional `redis-bcl-failure-queue` (`build_app_oidc.go:112`); ready checks are otherwise sqlite/etcd/signing | SSOSigningBackendDown etc. (A) | baremetal-ha (draft) |
| Geo provider | `geo.*` + `WithGeoProvider` | lookup failure → `""` → no geo findings, silent by design (direction-1 Decision 9 documents it) | **— none** | — |
| Audit pipeline | audit backend + sinks | async drops counted (`sso_audit_async_drops_*`), sink errors fail-open with logging | SSOAuditEventsDropped / SSOAuditQueueSaturated (A) | — |
| DR replication | `dr.enabled`, snapshot pipeline | `sso_dr_readiness` 0 when lag > RPO; default report-only, opt-in /readyz gate | — | dr-framework.md + drills |

## 3. Findings

No **Critical** or **High**: nothing in the design is a verified availability
loss, data-loss path, or gate violation; the change is off the request path,
bounded, and fail-open as documented (agrees with all sibling reviews). The
findings below are the operator-facing gaps the design inherits or extends.

### F1 — Medium — The detection pipeline has no end-to-end liveness signal: no sweep-duration metric, no finding log/audit, no alert, and drops are metric-only

**Evidence (Verified).** (a) `Analyze` has no duration gauge — the only
subsystem metrics are `sso_token_usage_{events,dropped}_total`,
`sso_token_usage_tracked_buckets`, and `sso_token_anomaly_findings_total`
(`platform/metrics/metrics_token.go`); the sweep loop logs only on `Analyze`
error (`sso.go:398-413`). (b) The detector emits **no audit event and no log
line per finding** — `processFinding` persists to the store, fires the metric
hook, dispatches the threat, and logs nothing (`detector.go:390-405`); the
`domains/tokenanomaly` package imports no auditor (grep-verified).
(c) Recorder drops fire the `Dropped` hook **only when metrics are wired** —
no log line otherwise (`token_recorder.go:152-160`). (d) `alerts.yaml` has 11
rules (5xx/4xx rate, latency, risk-scorer silence, instance down, audit
drops/queue, signing backend, connection health, key aggregation) and **zero
covering token usage, token anomaly, or threat actions** (grep-verified).

**Production impact.** An operator cannot distinguish "no anomalies" from
"detection is broken": a deployment that enables `token_anomaly` without a geo
provider gets zero geo findings (documented, direction-1); a deployment whose
introspection traffic is nil gets family-less findings forever (protocol
review Finding 1); a saturated recorder loses events silently (design's own
fail-open). All three degrade the *promise* of the feature — and of
direction-3's flagship family revoke — with `/readyz` green and every existing
alert quiet. The design's Decision-4 admission ("operators watch via finding
output only") is the canary being absent.

**Remediation (in priority order):**
1. Add a sweep-duration histogram and a findings-store cardinality gauge
   (`FindingStore` has no `Tracked*` reporter today — the pattern exists in
   `metering.TrackedBucketReporter`).
2. Log one line per **new** finding (DedupKey not previously stored) at Info —
   cheap, bounded (findings ≤ 1024), and gives logs a correlate for the audit
   trail when no executor fires.
3. Ship alerts in `ops/deploy/grafana/alerts.yaml`: `sso_token_usage_dropped_total`
   increasing (5m) ⇒ detection coverage loss; `sso_token_anomaly_findings_total`
   rate by severity — with F3's semantics documented.
4. State in `docs/observability.md` that detection health = drops + sweep
   latency + findings freshness (admin API `LastSeen`), not `/readyz`.

**Recovery validation.** Drill: saturate the recorder (benchmark-grade issuance
burst), assert the drop counter rises and the new alert fires; restore queue
headroom, assert drops stop and findings resume within one sweep interval.

### F2 — Medium — All detection state is per-replica and in-memory: findings, observations, and the new subject table vanish on restart; the suspicious API is per-replica

**Evidence (Verified).** The observation table, `subjectMinuteRates` (new),
the bucket store, and the `FindingStore` are process-local fields with no
durable backend (memory stores, `domains/metering/memory`,
`domains/tokenanomaly/memory`). `GET /api/v1/admin/tokens/suspicious` lists
only the local replica's store (`sso.go:381-390`); nothing aggregates across
replicas. Direction-1 documented the per-replica observation table; direction 3
adds the subject table to the same envelope without restating it.

**Production impact.** (a) **Restart = detection amnesia**: a replica
restarting mid-incident loses its observations, subject rates, and findings;
an operator pulling the suspicious list from a fresh pod sees an empty list
even while the incident continues. (b) **LB lottery**: behind a load balancer,
replica A may hold the finding while the operator's admin call lands on
replica B. (c) The family-revoke *action* is global (shared store +
`KindTokenRevoked`), so the security outcome survives — but the *governance
view* does not. (d) DR snapshots do not cover any of this (snapshot schema
v1/v2 is a durable control-plane subset; findings are not durable state at
all) — see drill D5.

**Remediation.** No code change required for correctness — but the design's
docs must state, in the same change: (1) subject table + findings are
per-replica rolling state, lost on restart; (2) the E2E for family-revoke
precision must be single-server (already the direction-1 constraint, QA F8);
(3) the forensic source of truth for an incident is audit + metrics, never the
findings list. Optionally: a findings gauge so a restart's amnesia is visible
as a step-down.

**Recovery validation.** Drill D5 below.

### F3 — Medium — `sso_token_anomaly_findings_total` counts re-emissions, not distinct findings; the windowed scan inflates it by up to `window/sweep_interval` per burst, per replica

**Evidence (Verified).** `processFinding` fires the metric hook on **every**
sweep for **every** finding (`detector.go:390-405`), and the finding store
upserts on `DedupKey` — so the counter counts emissions, while the store holds
one row. The windowed scan (Decision 5) keeps a burst minute a candidate for
`window/sweep_interval` sweeps — 15 at defaults — and the design accepts the
re-dispatch. Nothing bounds the counter inflation when operators tune
`sweep_interval` *down* (e.g. 10s sweep ⇒ ~90 emissions per burst) or run N
replicas (each replica re-detects independently: emissions ≈ findings ×
sweeps × replicas).

**Production impact.** An operator alerting on a findings-rate threshold will
see per-burst inflation that looks like N incidents; conversely, a *rate* alert
cannot distinguish a persistent single anomaly (healthy re-detection) from a
real incident burst. The metric help text ("findings emitted... by type and
severity") is accurate but its operational semantics differ from "distinct
findings" — nothing documents this.

**Remediation.** Either (a) gate dispatch/finding emission on finding-state
transition (perf review's Medium — dispatch only when the stored row's
`FirstSeen`/`LastSeen` advances), which makes the counter ~distinct-incident
count, or (b) keep the accepted semantics and document the inflation formula
(`window/sweep_interval` × replicas) in `config-reference.md`/`observability.md`
alongside the alert guidance. F1's new gauge (stored-finding cardinality) gives
operators the distinct count either way.

**Recovery validation.** Drill D2 + the perf review's B4 experiment (spy
executor count over 20 sweeps; acceptance ≤ 1 per finding lifetime if gated,
else exactly the documented count).

### F4 — Low — The subject table's memory bound is understated and unobservable; the cap has no config surface

**Evidence (Verified).** The design claims the worst case "4096 rows × 16
minutes ≈ 65k entries, well under the observation table's equivalent
footprint". The 65k figure counts entries, not bytes: each (subject, client)
row is a nested map with string keys — ~3–5 MB at defaults (perf review §2),
**comparable to or larger than** the observation table's footprint, so "well
under" is wrong. The cap is `WithMaxTrackedSubjects` (code-only; QA F3
verified every sibling knob maps from `TokenAnomalyConfig` — this one does
not), and no gauge covers the table (design's own admission). A bug in the
empty-`SubjectID` feed guard (design breakage #6) would churn the cap
invisibly until finding output degrades.

**Production impact.** Bounded (cap enforced, fail-open) but unobserved memory
growth on the sweep path; a stock-binary operator cannot tune or see the cap.
At defaults the footprint is small next to a Go runtime heap — the risk is
drift, not size.

**Remediation.** (1) Make the QA F3 decision explicit (config key
`token_anomaly.max_tracked_subjects` or documented default-only); (2) correct
the memory-bound sentence to "~3–5 MB at defaults, comparable to the
observation table"; (3) extend the detector's reporting hook (F1's gauge) with
subject-row count so eviction is observable.

**Recovery validation.** Unit: drive the table to cap, assert eviction
determinism and the gauge tracking it exactly (perf review's experiment).

### F5 — Low — No validation or documentation couples `sweep_interval` to `window`; the re-dispatch arithmetic and detection latency are operator-configurable without guardrails

**Evidence (Verified).** `BuildTokenAnomaly` requires only `SweepInterval > 0`
(`build_governance.go:363-365`). Nothing constrains `sweep_interval` vs
`window` (15m default). Consequences the docs don't state: (a) the "≤ 15
re-dispatches" figure is `window/sweep_interval` — a 10s sweep against the
default window yields ~90; (b) with `sweep_interval ≥ window`, a burst minute
is evaluated at most once or twice (the amplification goes away, but a burst
can also age out of the window between sweeps — detection latency approaches
`sweep_interval` either way); (c) `sweep_interval` **is** the detection-to-
action latency budget (assumption 1.3.2).

**Production impact.** Operators can silently choose detection latency or
dispatch amplification with no config validation and no doc — both directions
are surprising.

**Remediation.** One `config-reference.md` sentence each: detection latency
bound = sweep_interval; re-emission count = `window/sweep_interval` per replica.
Optional: fail-loud or warn when `sweep_interval > window` at boot.

### F6 — Low — The family-revoke blast-radius change is behaviorally significant and only partially documented for operators

**Evidence (Verified).** Today every `velocity`/`multi_geo` revoke hits
`DeleteAllForSubject` (subject-wide; `actions.go:23-26` documents the
permanent-no-op). Direction 3 makes `DeleteFamily` reachable, so the *same
finding type* with `default_action: revoke` now kills one lineage **or** the
whole subject depending on whether the lineage was ever introspected —
security F1's asymmetry, and the protocol review's Finding 1 (the dependency
is refresh-introspection traffic). The design updates `config-reference.md`
with the family-scoped statement but not the *coverage dependency*.

**Production impact.** An operator who tuned policies around subject-wide
revoke sees narrower behavior on introspected lineages and unchanged
subject-wide behavior elsewhere — without a doc sentence, the asymmetry reads
as a bug. Audit distinguishes the paths (`threat.detail` names family vs
subject; `family_id` enters Evidence → audit meta), but nothing tells the
operator to look.

**Remediation.** Land protocol-review Finding 1's sentence + negative E2E with
this design (it is the same change); optionally add the
`family_id`/`subject` distinction to the `threat_action_executed` guidance in
`config-reference.md`.

**Recovery validation.** The negative E2E: same velocity scenario without
refresh introspection ⇒ family-less finding ⇒ subject fallback, byte-identical.

### F7 — Info — Startup/shutdown sequencing is correct and the design preserves it

**Verified.** `wireTokenAnomaly` calls `rec.Start()` **before** `NewServer`
(`build_app_security.go:257-275`), so the drainer is alive before the first
Offer; the sweep starts in `startGovernanceWorkers` post-construction
(`build_app_security.go:442-459`); shutdown cancels + awaits the sweep
(`main_shutdown.go:314`) **before** `recorder.Close` drains the queue
(`main_shutdown.go:175-180`) **before** the HTTP graceful drain — so
final-millisecond events still reach the detector, and no Analyze races the
close. Direction 3 adds the subject fold inside `Record` (drainer) and the
subject scan inside `Analyze` (sweep); both inherit the same lifecycle. No
change needed.

### F8 — Info — The detection subsystem is correctly excluded from /readyz and DR modes, which means "detector alive" has no signal at all

**Verified.** No ready check covers the sweep (by design — fail-open
detection must not gate auth traffic). But there is also no `last_sweep`
timestamp in `/api/v1/status` (`server_health.go` `handleStatus` probes only
`StorageHealthSource`s; the detector is not one), and SDK embeddings must
remember to start `RunTokenAnomalyDetection` themselves (`sso.go:398-413`
documents the operator-owned goroutine). A forgotten `go srv.Run...` in an
embedding is silent forever. Acceptable for a reporting-only subsystem;
one sentence in the design's docs ("the sweep is operator-started; the stock
binary starts it when `token_anomaly.enabled`") would close the gap for SDK
users.

### F9 — Info — Proxy boundary: nothing in the design touches it, and the admin read surface stays correctly gated

**Verified.** The design adds `family_id` only to (a) an in-process Event
(never wire-marshaled), (b) the admin-gated suspicious-tokens read schema
(`omitempty`, admin:read), and (c) threat Evidence → audit meta. No credential
endpoint, no no-store header, no discovery document, no CORS/trusted-proxy
behavior changes. The frontend/proxy contract (`frontend-contract.md`) is
unaffected. The one operational note: the suspicious API is per-replica behind
the proxy (F2), so an LB'd admin client should expect replica-dependent
lists — worth a line in the design's docs.

## 4. Failure drills

Each drill names the scenario, the expected system behavior (verified
properties), the operator actions, and the pass criteria. All are designed to
run against the direction-3 implementation once landed.

### D1 — Outage: shared refresh-token store (Redis) loss in tier B, mid-burst
- **Expected behavior:** `/token` refresh/introspect fail closed fast
  (`read_timeout: 300ms` guidance, deployment.md §6); the recorder keeps
  draining into the in-memory bucket/observation/subject tables (no store
  dependency on the drain path); the sweep keeps emitting findings; threat
  dispatch fails open (executor errors logged, `dispatchThreat`), so
  `DeleteFamily` silently no-ops **while the finding list keeps growing** —
  the classic "alarm works, fire department can't leave" state.
- **Operator actions:** verify via the finding list + `threat_action_executed`
  failure outcomes; restore Redis (noeviction policy per deployment.md §6);
  after restore, **the detector will not re-dispatch already-processed
  findings on its own** unless the finding state advances — the burst
  re-detection window (≤ window/sweep_interval sweeps) is the recovery path,
  so the family revoke fires once the store is back if the burst minute is
  still in-window. If the window expired, operator must revoke manually (admin
  bulk-revoke or store-side).
- **Pass criteria:** no request-path outage beyond the documented fail-closed
  behavior; executor failure visible in audit + logs; recovery completes via
  re-detection or documented manual revoke. **Gap to close first:** F1's
  executor-failure alert (today only the log line exists).

### D2 — Saturation: issuance burst exceeds recorder drain (queue 1024)
- **Expected behavior:** `Offer` drops events, `Dropped` hook fires; the drain
  (single goroutine + memory-store mutex) is the bottleneck; direction 3 adds
  a second lock+map fold per event on the drainer (~50–100 ns/event, perf
  review Low). No request-path latency effect ever.
- **Operator actions:** watch `sso_token_usage_dropped_total`; raise
  `token_anomaly.queue_size` or reduce issuance rate; confirm detection
  coverage loss is bounded to the drop window.
- **Pass criteria:** drops > 0 triggers the F1 alert; request p50/p99 flat
  (±5%, perf B3); findings resume within one sweep of the burst passing.

### D3 — Bad rollout: mixed-version fleet during the seam rollout
- **Expected behavior:** the seam change is compile-coupled (six interfaces +
  five call sites + CIBA test fake — decision 1's own gap list), so there is
  no partial-binary state: a replica runs either the old or the new signature.
  Old replicas emit family-less events; new replicas emit family-bearing
  events; `recordObservation`'s non-empty overwrite makes the observation
  table converge to the family once any family-bearing sighting lands.
  Mixed-fleet behavior is byte-identical-to-old, never an error (direction-1
  documented the same for JTI). No migration, no store schema change ⇒
  rollback is a binary swap.
- **Operator actions:** ship as a normal rolling deploy; no coordinated
  cutover needed.
- **Pass criteria:** during rollout, no finding carries a family from an old
  replica's sighting (it just doesn't); after full rollout, family-bearing
  findings appear on the introspection path within one window.

### D4 — Stale state: burst minute ages out of the window mid-incident
- **Expected behavior:** windowed scan stops re-emitting once the burst minute
  is older than `now - window` (sweep-time pruning for the subject table,
  observation freshness gate for geo). The finding row's `LastSeen` stops
  advancing; the row stays until eviction (cap 1024) — a **stale-but-present**
  row that looks current to a casual admin read.
- **Operator actions:** alert on `LastSeen` freshness for open critical
  findings (F1's gauge + alert); resolve or dismiss via the admin list.
- **Pass criteria:** a finding older than the window is distinguishable from a
  live one by `last_seen`; no new dispatch occurs after window exit
  (perf B4's acceptance).

### D5 — Restore: replica crash + DR cutover mid-incident
- **Expected behavior:** findings/observations/subject table are per-replica
  memory — a crash loses them (F2); DR snapshot restore does **not** restore
  them (snapshot schema v1/v2 is a durable subset; findings are not durable
  state — dr-framework.md §1/§2). The forensic trail that survives is the
  audit pipeline (threat_action_executed with evidence, reuse/velocity family
  events — durable per `audit.backend`) and scraped metrics.
- **Operator actions:** treat the findings list as ephemeral; reconstruct the
  incident timeline from audit + metrics; re-issue or wait for re-detection on
  the fresh replica.
- **Pass criteria:** post-restore, the new replica re-detects an *ongoing*
  pattern within one window (observations rebuild from live traffic); the
  audit trail fully reconstructs the pre-crash timeline. **Document this
  explicitly in the design's docs** (F2 remediation).

## 5. Launch blockers, rollback triggers, monitoring gaps, residual risks

### Launch blockers
None. The design is config-gated (`token_anomaly.enabled` /
`threat_action.enabled`, both default off), additive, fail-open, and carries
no migration or wire change. The items that must land **in the same change**
for the feature to be *operable* (not just correct):
1. Protocol-review Finding 1: the introspection-coverage doc sentence + the
   negative E2E (family-less ⇒ subject fallback). Without it, the flagship
   claim is silently unreachable and indistinguishable from a bug.
2. QA F3: the `max_tracked_subjects` config-surface decision, stated in the
   design.
3. QA F1/F2: the two compile/test-map gaps (`sso_usage_geo_test.go`; the
   introspect-Offer assertion) — the same gap class the design criticized in
   the spec, and the regression that would silently reinstate the permanent
   no-op.
4. F1's minimal observability (sweep gauge + finding log line) — cheap, and
   the only way to see the feature degrade.

### Rollback triggers and mechanics
- **Binary rollback is always safe and sufficient:** no migration, no schema
  change, no wire change; an old binary ignores nothing it doesn't know about
  (the seam is in-process). Roll back if: findings carry no family in a
  deployment with known refresh-introspection traffic (Decision-2 drift —
  the F2 seam test guards it), subject-scoped findings show up where
  client-wide spikes were expected (DedupKey collision regression), or the
  maintainability gate trips on `detect.go`/`server_helpers.go` (breakage #7).
- **Feature-level rollback:** disable `token_anomaly.enabled` (and/or
  `threat_action.enabled`) in config — the stock binary rebuilds nothing; a
  SIGHUP reload covers route state but **not** the anomaly subsystem (the
  detector/sweep are boot-wired; `SetRateLimitPolicy` is the only hot-swap
  seam and does not cover this) — so disabling requires a restart.
- **Do not** roll back by relaxing the one-per-client rule or the
  `family_id` evidence key — both are load-bearing (design breakage #4,
  security review positive controls).

### Monitoring gaps (all pre-existing or design-inherited; F1/F4 carry the fixes)
1. No sweep-duration metric; no findings-store cardinality gauge; no subject-
   table or observation-table gauge.
2. No alert on `sso_token_usage_dropped_total`, findings rate, executor
   failures, or stale open findings.
3. `sso_token_anomaly_findings_total` semantics (emissions, not distinct
   findings; × replicas) undocumented.
4. No `last_sweep`/detector-alive signal in `/api/v1/status` or metrics.
5. Recorder drops are invisible without metrics enabled (no log fallback).

### Residual risks
- **Detection is per-replica; evidence never combines** (pre-existing;
  direction 3 extends the envelope with the subject table). An attacker
  splitting sightings across replicas evades geo/velocity and subject-spike
  detection at fleet scale. Documented, not fixed, by this direction.
- **Family precision is introspection-gated** (security F1 / protocol F1):
  access-token-derived and rotation-first findings stay subject-wide. The
  design's fallback is byte-identical — but the self-inflicted-DoS blast
  radius the direction claims to fix persists for those paths.
- **Subject-table baseline pollution** (security F2/F4): folding all
  event kinds into the subject dimension lets self-introspection volume and
  legitimate burst waves move spike signals. SRE endorses the issuance-only
  fold recommendation — it also stabilizes the metric the operator will alert
  on.
- **Repeated dispatch × replicas** is idempotent and rate-limitable but
  unbounded by configuration (F5); the policy `rate_limit` is the only brake
  and it is per-(subject, type, action) — set it in the reference config for
  `revoke`.
- **No SLOs exist** for detection latency or coverage; the de-facto budget is
  `sweep_interval` (assumption 1.3.2). If the family-revoke path is promoted
  to a security control ("revoke a stolen lineage within X"), an SLO on
  detection-to-dispatch latency and a drop-rate budget must be defined and
  measured — F1's sweep gauge is the prerequisite.

**Bottom line:** the design is operationally sound — it is off the request
path, bounded, fail-open, correctly sequenced in startup/shutdown, and adds no
proxy-facing surface. The SRE-specific work is all about *visibility and
expectations*: (1) the subsystem has no liveness signal today and the design
adds none (F1 — sweep gauge, finding log, alerts); (2) the new state is
per-replica and ephemeral, so incident forensics rest on audit + metrics, not
the findings list (F2 — must be stated in the docs); (3) the metric the
design does have counts re-emissions that the windowed scan inflates by
`window/sweep_interval` per replica (F3 — gate or document); (4) the subject
table's memory bound is understated and unobservable (F4). None blocks
landing; the three doc sentences (introspection coverage, per-replica
ephemerality, sweep-interval-as-latency-budget) plus F1's minimal gauges are
the difference between a feature an operator can detect, withstand, and
recover from, and one they can only watch.
