# SRE Review: Post-Auth Rate Limiting (方向一) — Operability of the API backend and its frontend/proxy boundary

> Input: `docs/auto/interfaces-ratelimit-design.md` (all 9 decisions), the
> protocol/distributed/performance/security/QA deliverables, and the code.
> Role: SRE — can operators detect, withstand, and recover from failures of
> the three new post-auth checkpoints and the surfaces they protect?
>
> **Checks that ran this session:** read-only inspection (no Go code changed,
> no gates triggered): `interfaces/ratelimit/{middleware,ratelimit,
> memory_limiter,sqlite_limiter}.go`, `infrastructure/redis/ratelimit.go`,
> `interfaces/sso/server_{routes,token,userinfo,health,accessors_handlers,
> options_httpstack}.go`, `interfaces/admin/{governance,middleware}.go`,
> `protocols/oidc/handle_userinfo.go`, `config/reload/reload.go`,
> `cmd/sso-server/{main_wiring,main_shutdown,build_app,build_app_security,
> build_bootstrap,build_app_cluster,build_app_core}.go`,
> `cmd/sso-server/serverbuildsign/build_readiness.go`,
> `cmd/sso-server/serverbuildplatform/build_ratelimit_cluster.go`,
> `platform/metrics/{conditional_access,consts}.go`,
> `infrastructure/defaultimpl/memreaper/reaper.go`,
> `ops/deploy/{grafana/alerts.yaml,k8s/deployment.yaml,k8s-prod/{pdb,hpa,
> patch-deployment}.yaml,baremetal-ha/RUNBOOK.md,openresty/*,loadtest/*}`,
> `docs/{observability,config-reference,dr-framework,error-codes}.md`.
> The `modernc.org/sqlite` transaction-mapping claim is cited from the
> distributed-engineer deliverable (verified against the vendored driver);
> the Decision 9 latency numbers are cited measurements from the
> performance-engineer deliverable (same machine, `-count=3` medians).

## Verdict

The design is operationally sound in its core (shared `Checkpoint`, context
identity, per-surface stores, config/SIGHUP surface), and the two 429 wire
fixes are contract repairs. **No launch blocker is a design decision itself.**
But the SRE dimension has one High gap the design explicitly set out to close
and cannot close as written (fail-open observability — its own Decision 8
verification item fails), one High observability gap inherited from today
(admin rejections invisible to `sso_rate_limit_hits_total`, and the design
keeps it that way), and a set of Medium reload/readiness/alert-semantics gaps
that must be resolved in the same change as the implementation. The SQLite
backend's cross-replica semantics (Decision 7/8 claims) need correction before
operators are told `backend=sqlite` means "cross-replica limiting".

---

## 1. Service / dependency map and operational assumptions

```
SPA / native / admin-console frontends (separate projects)
   │  HTTPS
   ▼
Edge: OpenResty prototype (ops/deploy/openresty) OR HAProxy + keepalived VIP
   │  local EdDSA JWT verify (JWKS cache TTL 60s), permission cache 60s,
   │  per-request JSON log; NO edge rate limiting in the checked-in config
   ▼
sso-server (API-only, k8s 3-20 replicas HPA@70%CPU / PDB minAvailable:2,
           or baremetal-ha 3 VMs)  — probes /livez /readyz /metrics OUTSIDE
           the ratelimit chain (buildProbeMux, server_routes.go:468)
   │
   ├─ Redis Cluster (shared hot store): sessions, OAuth stores, JTI replay,
   │    rate-limit buckets (sso:ratelimit:*, fixed-window counters)
   ├─ Postgres/SQLite (durable identity/audit; SQLite default)
   ├─ etcd (invalidation bus, registry, signing-key aggregation, netpolicy)
   ├─ KMS/HSM (optional external signer — fail closed)
   ├─ outbound: federation IdPs, audit webhooks/Kafka, CAEP receivers,
   │    push notifications (all SSRF-guarded dialer)
   └─ phase-2 (this design): /token client bucket, /userinfo + mesh subject
        bucket, admin tier-1 (per-IP) + tier-2 (per-admin) — all consuming
        the SAME Limiter SPI/backends as phase-1
```

Operational assumptions the design rests on (all **Verified**):

1. **Middleware order preserved**: `tracing → ratelimit → bodyLimit → metrics
   → CORS → router`; probes outside rate limiting (observability.md,
   server_routes.go:468-485). Phase-2 checkpoints run in-handler, inside the
   metrics recorder, so their 429s land in `sso_http_requests_total`
   `status_class="4xx"` (options_httpstack.go:88-89). **Verified.**
2. **Reject metric fires for /token + /userinfo checkpoints**: Decision 3/4
   stores carry `Metrics: s.metrics`; `Checkpoint` calls `recordRejection`
   (middleware.go). Admin stores today have `Metrics: nil` and the design's
   tier-2 is "direct Allow" — **admin rejects stay invisible** (Finding H-2).
3. **Fail-open on store error is the documented doctrine and is real**: both
   backends return `(true, 0)` on every SQL/script/shape error
   (sqlite_limiter.go Allow; redis/ratelimit.go Allow). It is **silent**: no
   logger, no metric, no audit in either backend or in `interfaces/ratelimit`
   (grep: zero `log.*` calls). Decision 8's "Verify ... is logged" item
   **fails** (Finding H-1).
4. **Shared-state topology**: memory = per-replica (effective limit N× across
   N replicas, documented); redis/sqlite = cross-replica. `security.rate_limit`
   is **opt-in in every shipped deployment asset** (no block in
   ops/deploy/{k8s,compose,helm} configs) — phase-2 is opt-in too.
5. **SIGHUP semantics**: allowlist reloader (config/reload/reload.go); the
   rate-limit block rebuilds wholesale via `BuildRateLimitPolicy` and swaps
   into the `PolicyStore` (main_wiring.go `wireRateLimitReload`). Counters
   persist across reloads on redis/sqlite (same keys/bucket names — verified
   in `build_ratelimit_cluster.go`), reset on memory (config-reference.md:444).
6. **DR**: rate-limit counters are tier-2, deliberately excluded from
   snapshots (dr-framework.md §1); RPO/RTO targets exist per failure level
   (dr-framework.md §2) but **no production SLOs are committed anywhere**
   (grep across docs/ops: only proposals). Decision 9 numbers are design
   budgets, not SLOs.
7. **Edge boundary**: the OpenResty layer is a prototype (README disclaimer),
   Ed25519-only, JWKS cache TTL 60s, permission cache 60s, no `limit_req`
   directives in the checked-in config. It is not a production authorization
   boundary and adds no throttling layer.

---

## 2. Readiness table

Signal = what operators watch; dependency = what it covers; failure behavior
verified against code; alert = existing alert (ops/deploy/grafana/alerts.yaml);
runbook = where the procedure lives.

| Signal | Dependency | Failure behavior | Alert | Runbook |
|---|---|---|---|---|
| `/livez` | process | always 200 (server_health.go) | `SSOInstanceDown` | RUNBOOK §4 (baremetal-ha); k8s livenessProbe |
| `/readyz` | aggregate of named checks, 3s deadline, per-check error logged (server_health.go:97) | 503 with per-check body; logs `readyz check failed` | `SSOInstanceDown` (indirect), kubelet/HAProxy drain | RUNBOOK bring-up gates §2.4; k8s readinessProbe |
| `/readyz` `sqlite-ratelimit-*` | phase-1 sqlite **and** redis limiters (AppendReadyCheck type-asserts `Ping` — build_readiness.go:110; redis Limiter has `Ping` too; name prefix misleading) | 503 when the shared rate-limit backend is wedged; registered at boot only, phase-1 only | none dedicated | **none — gap** (Finding M-4) |
| `/readyz` phase-2 stores (this design) | token_client / userinfo / admin buckets | **no checks planned** — a wedged backend is invisible in phase-2-only deployments | none | **none — gap** (Finding M-4) |
| `sso_rate_limit_hits_total{tenant}` | phase-1 + phase-2 (/token, /userinfo) rejects | increments on reject only; label cardinality bounded; **admin rejects never increment it** | none (no alert uses it) | — (Finding H-2, M-3) |
| `sso_http_requests_total{status_class="4xx"}` | all client errors incl. 429s | `SSORateLimitSaturated` fires on **any** 4xx > 0.5/s (severity info), not on rate-limit hits specifically | `SSORateLimitSaturated` (semantics mismatch) | alerts.yaml (Finding M-3) |
| `sso_http_request_duration_seconds` p95 | full request path incl. checkpoint | Redis-outage stall pushes p95 > 1s → `SSOLatencyP95High` (the **only** signal for limiter-backend outage) | `SSOLatencyP95High` | — (Finding H-1) |
| audit pipeline | async sink | drops → `SSOAuditEventsDropped` (critical), queue >80% → `SSOAuditQueueSaturated` | both exist | alerts.yaml |
| signing backend (KMS/HSM) | token issuance (fail closed) | `SSOSigningBackendDown` | exists | alerts.yaml |
| Postgres (Patroni) | durable stores | leader failover <10s; writes retriable | `SSOHighHTTPErrorRate` (indirect) | RUNBOOK §3.1 |
| etcd | coordination | quorum loss | `SSOInstanceDown` / readyz | RUNBOOK §4.3 |
| edge JWKS cache | edge-local JWT verify | 60s staleness window after signing-key rotation → edge 401s on new-key tokens; revoked permissions linger ≤60s | none (edge not instrumented in repo) | openresty README (Finding I-1) |
| rate-limit **fail-open** events | redis/sqlite backends | **no signal at all** (no log, no metric) | none — silent | **none — gap** (Finding H-1) |

---

## 3. Findings

### H-1 — High — Limiter fail-open is silent AND stalled: the defense vanishes without a trace, and the Redis path pays multi-second stalls per checkpoint

**Evidence (Verified):** `SQLiteLimiter.Allow` returns `(true, 0)` on BeginTx
error, load error, persist error, and commit error (sqlite_limiter.go:161,
174, 190-191, 200-201). `redis.Limiter.Allow` returns `(true, 0)` on script
error, result-shape mismatch, and type mismatch (infrastructure/redis/
ratelimit.go:135-146). Neither backend holds a logger; `interfaces/ratelimit`
has zero `log.*` calls; no fail-open counter or audit event exists anywhere in
the path. The Redis `Allow` runs on `context.Background()` with **no
deadline**; `build_bootstrap.go:257-259` wires `redis.{max_retries,
dial_timeout, read_timeout}` — when unset, go-redis library defaults apply
(3 retries with backoff, 5s dial, 3s read; the config-reference at
docs/config-reference.md `redis.{dial,read,write,pool}_timeout` itself
recommends "~200-500ms so /token fails closed fast" — operator guidance only,
not enforced).

**Impact:** (1) The design's own Decision 8 verification item ("Verify the
Redis/SQLite limiter's fail-open on error is logged") **cannot pass** — it is
not logged. (2) A dead or black-holed Redis turns **every** checkpoint into a
multi-second stall before the fail-open allow — on `/token`, `/userinfo`,
and admin, in addition to phase-1 login. The common real-world trigger (the
flood itself saturating Redis) is exactly when the limiter stops limiting:
store overload ⇒ limiter off + added latency. The only alert that catches
this is `SSOLatencyP95High` (indirect). (3) SQLite's hung-filesystem case
blocks in the syscall with no timeout at all. Decision 8's "Limiting silently
off until recovery" row understates the stall dimension; the design must
state it.

**Remediation (required before launch):** pick one and commit it in the
design: (a) a fail-open counter (e.g. `sso_rate_limit_failopen_total{backend,
surface}` — bounded labels, consistent with observability.md's bounded-
cardinality rule) incremented at the `Checkpoint`/middleware layer on
`!ok && retry==0` + store-error path... simpler: add the counter in the
backends' Allow error paths (they are the only failure surface —
`PolicyStore.Get` cannot fail), or (b) explicitly accept silence and document
that limiter outage is detected via `SSOLatencyP95High`. Additionally:
document `redis.{max_retries,dial_timeout,read_timeout}` as a **hard
requirement** for any deployment with `security.rate_limit.backend=redis`
(phase-2 included), with the config-reference's 200-500ms numbers promoted
from guidance to requirement text.

**Recovery validation (staging drill):** kill Redis; measure p95 of `/token`
during outage (must be bounded by the configured timeouts); confirm requests
are allowed (fail-open) and the counter/log fires; restore Redis; confirm the
counter stops and limiting resumes at the pre-outage rate.

### H-2 — High — Admin rejections are unobservable: today and per the design, the admin surface never touches `sso_rate_limit_hits_total`

**Evidence (Verified):** `AdminMiddleware.SetRateLimit` builds
`ratelimit.NewPolicyStore(ratelimit.Policy{Default: ...})` with `Metrics:
nil` (interfaces/admin/governance.go:283-288); `checkRateLimit` (governance.go:
306-330) calls `lim.Allow` and writes the 429 with no `recordRejection`; the
config wiring `mw.SetRateLimit(rate, burst)` (build_app.go:305-307) is the
only production caller. The design's Decision 5 tier-2 is explicitly "direct
Allow" — no `Checkpoint`, no metrics. `sso_rate_limit_hits_total` has only a
`tenant` label (platform/metrics/conditional_access.go:56-62), so even the
token/userinfo checkpoints cannot be attributed per surface.

**Impact:** the design's headline scenario — admin A floods a shared NAT IP,
A 429s at tier-2 while B passes tier-1 — produces **zero** rate-limit metric
signal. Admin 429s appear only as undifferentiated `status_class="4xx"`. An
operator cannot tell "limiter protecting the admin plane" from "flood of
invalid admin tokens" without log forensics. Decision 1's "Metrics for free
for all three surfaces" claim holds for /token and /userinfo only.

**Remediation:** give both admin tiers a `Metrics`-wired store (tier-2 should
use `Checkpoint`-equivalent rejection recording rather than bare `Allow`; the
design's "no Policy.Key involvement" rationale doesn't preclude
`recordRejection`). Add an alert on admin-surface 4xx/429 rate once
observable.

**Recovery validation:** configure `admin.rate_limit.per_admin`, flood with
two admin tokens, assert `sso_rate_limit_hits_total` increments with a stable
label set and no cardinality growth.

### M-3 — Medium — `SSORateLimitSaturated` measures all 4xx, not rate limiting; nothing alerts on `sso_rate_limit_hits_total`

**Evidence (Verified):** alerts.yaml expr
`sum(rate(sso_http_requests_total{status_class="4xx"}[5m])) > 0.5` — no path
filter, no 429 filter; the annotation claims "429 rate from /auth/login".
No alert in the file references `sso_rate_limit_hits_total`. Phase-2 adds
three new 429-emitting surfaces without adding any signal dimension.

**Impact:** false positives (an `invalid_grant` flood trips "SSORateLimit-
Saturated" with zero 429s); blind spots (a /userinfo subject scraper or an
admin flood is invisible as such). Post-phase-2, this becomes the primary
"is the limiter doing real work" indicator and it is the wrong instrument.

**Remediation:** alert on `rate(sso_rate_limit_hits_total[5m])` with a
per-deployment threshold; optionally add a bounded `surface` label
(middleware|register|token|userinfo|admin — 5 fixed values) to
`ObserveRateLimitHit` so per-surface attribution is possible without breaking
bounded cardinality (this is a small, deliberate metric-contract change to
docs/observability.md — flag it explicitly in the design's contract
obligations). Keep the 4xx alert as a general client-error sentinel with a
corrected name/description.

**Validation:** after phase-2, run the token-client flood e2e; assert the
hits-based alert fires and the 4xx alert no longer needs to be the signal.

### M-4 — Medium — Phase-2 stores are outside /readyz and the SIGHUP lifecycle

**Evidence (Verified):** `AppendRateLimitReadyChecks` (serverbuildsign/
build_readiness.go:110) is called only for the phase-1 boot policy
(build_app_security.go:40); it registers any `Ping`-implementing limiter
(sqlite **and** redis — the `sqlite-` name prefix is misleading). The design
(Decision 6) plans no ready checks for the token_client/userinfo stores and
no close discipline for replaced phase-2 limiters. Phase-1's reload path
tracks `prev` and closes the previous generation (main_wiring.go:129-160),
which bounds phase-1's leak to the boot generation; the design's phase-2 hook
("rebuilds the limiters, calls the setters") leaves closing unspecified — a
naive implementation leaks one `*sql.DB` per limiter (plus re-runs
`migrate.Run`) or one pruner goroutine per SIGHUP, unbounded over process
lifetime.

**Impact:** (1) phase-2-only deployments (phase-1 disabled — every shipped
sample config has no rate_limit block, so this is the common shape) get zero
readiness signal for a wedged sqlite/redis rate-limit backend; (2) per-reload
resource leak; (3) a SIGHUP that switches the backend to a bad DSN fails the
hook cleanly (reported Ignored — verified reload.go contract), but a backend
that wedges *after* boot is invisible.

**Remediation:** extend `AppendRateLimitReadyChecks` (or an equivalent) to
the phase-2 stores; rename the `sqlite-` prefix since Redis participates;
specify in Decision 6 that the post-auth hook mirrors `closePolicyLimiters`
prev-tracking (and fix the false comment at main_wiring.go:165 — see M-6).

**Validation:** 10× SIGHUP with `backend=sqlite`; assert FD count stable and
`/readyz` still 200; kill the sqlite file (rename), assert readyz 503 with a
named check; restore, assert recovery.

### M-5 — Medium — Decision 7/8's cross-replica claims are wrong for SQLite: clock-coupled refill and a non-atomic cross-process decision

**Evidence (Verified in code; driver mapping cited from the distributed
deliverable):** `SQLiteLimiter.Allow` uses `BeginTx(ctx, nil)` — a **deferred**
`BEGIN` under modernc (plain `BEGIN` unless `_txlock` is in the DSN), so the
read precedes the write lock: two replicas with burst=1 can both read a full
bucket, both consume, both admit (decision race; the code comments at
sqlite_limiter.go:48,135 claiming BEGIN IMMEDIATE are false as written). The
refill math uses `s.now().UnixNano()` against `last_refill_at_ns` persisted by
whichever replica wrote last — wall-clock coupled across replicas: a
forward-skewed replica over-refills and stamps a future timestamp that starves
other replicas (negative elapsed ⇒ no refill) until its clock catches up. The
DSN carries no WAL/journal pragmas (default rollback journal,
`synchronous=FULL` fsync per Allow); `busy_timeout=10000` arrives incidentally
from `migrate.Run`'s migration connection — undocumented coupling. The design
Decision 7's "No clock coupling: reservations are monotonic" is true for
Memory only; Decision 8's acceptance must pick Redis fixed-window semantics as
the cross-replica contract ("bucket-exact cross-replica limiting" is not
achievable with the current sqlite backend).

**Impact:** over-admission (and under-admission) during clock-skew windows —
the limiter silently weakens exactly during incidents; concurrent-flood
validation at burst boundaries is not reproducible cross-replica.

**Remediation:** state an explicit skew bound for the sqlite backend (the
repo's "clocks slew, they do not step backward" doctrine), document required
DSN parameters (`_txlock=immediate`, `_pragma=busy_timeout(...)`,
`_pragma=journal_mode(WAL)`) or mandate `sqlite.SharedDB` +
`NewSQLiteLimiterWithDB`, and add the missing concurrent cross-instance test
(the existing `TestSQLiteLimiter_CrossInstanceSharing` is sequential only —
sqlite_limiter_test.go:121).

**Validation:** two limiters, burst=1, same key, parallel `Allow` — assert
exactly one admit today fails; after the fix, passes.

### M-6 — Low — Reload comment drift and the boot-generation leak (bounded, but misleading for the phase-2 hook author)

**Evidence (Verified):** main_wiring.go:165 claims SQLiteLimiter "is a silent
no-op" for `closeIfCloser` — false; `SQLiteLimiter.Close` exists and
`closePolicyLimiters` does close the previous reload generation. Because
`prev` starts nil, the **boot** policy's limiters are never closed by reloads
(bounded: one generation + boot, not a growing leak) — but the false comment
invites the phase-2 hook to skip close discipline entirely (ties to M-4).

**Remediation:** fix the comment; the phase-2 hook must explicitly close the
replaced generation.

### I-1 — Info — Edge boundary (OpenResty prototype): 60s JWKS staleness, 60s permission cache, no edge throttling

**Evidence (Verified):** `ops/deploy/openresty/lua/jwks_cache.lua` CACHE_TTL =
60; permission cache 60s; no `limit_req`/`limit_conn` in the checked-in
nginx.conf/conf.d; README disclaims prototype status (Ed25519-only, no
revocation/oracle parity). The server-side phase-1/2 limits are the **only**
throttle for SPA login flows behind this edge.

**Impact:** after a signing-key rotation, the edge verifies with a stale key
for up to 60s — new-key tokens 401 at the edge while the origin accepts them
(operational hazard to document next to the rotation procedures); revoked
permissions linger ≤60s at the edge.

**Remediation (optional):** document the 60s window in the rotation runbook;
consider edge `limit_req` for `/auth/login` as defense-in-depth.

### I-2 — Info — No committed SLOs; Decision 9 budgets are design budgets

**Evidence (Verified):** no SLO/error-budget document exists in docs/ or
ops/deploy (grep: proposals/requirements prose only). RPO/RTO targets exist
only in dr-framework.md §2 (tiered; rate-limit counters explicitly tier-2,
excluded from snapshots — so a DR cutover starts with fresh buckets, which
re-arms the limiter immediately; this is the right call and should be stated
in the config-reference DR section once).

**Recommendation:** define availability + latency SLOs for `/token` and
`/userinfo` (Decision 9's p99 budgets are the natural latency targets: ≤5 µs
memory / ≤100 µs sqlite / ≤2 ms redis checkpoint add-on). State explicitly
that `rate_limited` 429s are **excluded** from the availability error budget
(defense, not failure) while 5xx from the checkpoint paths are included.

---

## 4. Failure drills

All drills: action / expected detection / expected recovery / verify
continuity. Run in staging first; the baremetal-ha RUNBOOK is a validation
draft and does not yet cover the rate-limit dependency at all.

**D-1 Outage — rate-limit backend loss (redis):** kill/blackhole Redis.
Detection: `SSOLatencyP95High` (only signal today; H-1 counter/log after
remediation), requests still succeed after bounded stall. Recovery: restore
Redis. Verify: p95 back to baseline; counter stops incrementing; a fresh
flood gets 429s again at the pre-outage threshold. Watch: `/readyz` should
NOT trip (limiter is fail-open; Redis is shared with auth-code/session stores
whose /readyz checks WILL trip — distinguish the two in the runbook).

**D-2 Saturation — admin A floods shared NAT IP:** two admins behind one IP,
`admin.rate_limit.per_admin` configured, tier-1 per-IP sized above the flood
rate (Decision 9 constraint). Detection: A's requests 429 at tier-2
(`rate_limited`), B's succeed; after H-2 remediation, `sso_rate_limit_hits_total`
increments. Verify: A's 429 shape is constant regardless of A's session
state (no idle-timeout oracle — tier-2 precedes `enforceIdleTimeout`,
middleware.go ordering verified). Failure mode to rehearse: tier-1 sized
**below** the flood rate ⇒ B starves at tier-1 — the acceptance test's
dimension; add a production alert on aggregate admin 429 rate so a mis-sized
deployment is visible.

**D-3 Saturation — /userinfo subject scraper:** valid-token scraping with
many subjects. Detection: `sub:<subject>` buckets, per-subject 429 + the
hits metric (tenant=unknown unless TenantKeyFunc wired — design Decision 3/4
stores should keep the phase-1 defaulting behavior of
`SetRateLimitPolicy`/`resolvedRateLimitPolicy`, which fills
Metrics/TenantKeyFunc; state this explicitly for the phase-2 setters).
Verify: a single subject's 429s stop after Retry-After; other subjects
unaffected; memory bounded (10-min prune, memory_limiter.go:64-67; SQLite
rows pruned via `last_seen_at_ns`).

**D-4 Bad rollout — a bad rate config via SIGHUP:** lower a limit too far on
a shared backend. Detection: 429s rise fleet-wide **immediately** on the next
request to any replica (counters persist across reloads — the opposite of
the documented memory reset; design Decision 8 must add this row). Recovery:
SIGHUP the previous config (reloader reports Applied/Ignored via configaudit
diff; config-reference.md hot-reload table). Verify: configaudit log shows
the flip-flop; 429 rate returns to baseline. Also rehearse the sqlite
generation-close discipline from M-4 (10× SIGHUP, FD count flat).

**D-5 Stale state / restore — DR cutover with backend=redis:** promote DR
site. Detection: `sso_dr_readiness`, `sso_dr_snapshot_replication_lag_seconds`
(dr-framework.md §5). Recovery: Redis at the DR site starts empty —
rate-limit buckets are tier-2 and intentionally not snapshotted; the limiter
re-arms on first request per key (window starts full ⇒ brief excess
allowance, then steady state). Verify: a flood immediately after cutover is
bounded within one window; auth codes/sessions are expected to be lost
(re-auth), documented tier-2 behavior. This is correct as designed — the
drill exists to prove nobody treated buckets as durable.

---

## 5. Launch blockers, rollback triggers, monitoring gaps, residual risks

### Launch blockers

None of the design's decisions is a hard SRE blocker, **provided** the
implementation change resolves:

1. **H-1 fail-open observability decision** — the design's own Decision 8
   verification item cannot pass as written ("fail-open ... is logged" is
   false); the same change must either add the counter/log or rewrite the
   acceptance to "explicitly accepted silent, detected via latency alert",
   plus the redis-timeouts requirement text.
2. **M-4 phase-2 reload close discipline + readiness wiring** — without it,
   the design ships a per-SIGHUP resource leak and a phase-2 readiness blind
   spot.
3. **M-5 sqlite contract correction** — Decision 7/8 must not ship "no clock
   coupling" / "bucket-exact cross-replica" claims for the sqlite backend.

### Rollback triggers

- Mass 429s on legit traffic after SIGHUP (hits metric or 4xx rate; rollback
  = SIGHUP previous config, or restart for backend/`enabled` changes).
- `/readyz` red on a `sqlite-ratelimit-*` check after a reload (M-4 discipline
  broken).
- p95 latency breach on `/token`/`/userinfo` (checkpoint stall — H-1).
- The two deliberate wire changes (grant 429 body, admin configured-mode
  body): rollback = revert the change; clients that branch on
  `unsupported_grant_type`-on-429 were already broken (documented drift) —
  no compatibility rollback path exists, which is correct.

### Monitoring gaps (summary)

1. No fail-open signal (log/counter) for either limiter backend (H-1).
2. Admin rejections never reach `sso_rate_limit_hits_total` (H-2).
3. No per-surface attribution of rate-limit hits (M-3; add bounded `surface`
   label).
4. `SSORateLimitSaturated` measures all 4xx, not 429s (M-3).
5. Phase-2 stores absent from /readyz (M-4).
6. No Retry-After distribution metric (optional; clients ignoring
   Retry-After are otherwise invisible).
7. No alert on `sso_rate_limit_hits_total` at all.
8. Rate-limit backend loss has no alert-to-runbook mapping (RUNBOOK.md has
   no rate-limit section; Redis memory sizing omits the `sso:ratelimit:*`
   keyspace).

### Residual risks (accepted, documented)

- Public-client `/token` floods are IP-bounded only (both phase-1 and phase-2
  fallback) — a valid auth code can be replayed to burn the shared IP bucket.
- NAT-shared admin tier-1 starvation if the per-IP rate is mis-sized (Decision
  8/9; e2e guards the test, production needs the alert from D-2).
- Memory backend = N× effective limit across N replicas (documented phase-1
  limitation, unchanged).
- The `"client:"` namespace invariant (never share a limiter instance across
  phases; documented config-reference obligation).
- Pairwise-sub aliasing concentrates a user's buckets to a bounded handful on
  /userinfo (documented).
- SQLite cross-replica decision race + clock coupling until M-5 lands; Redis
  fixed-window edge burst (2× at window boundary) is the reference
  cross-replica semantics.

---

## Verification mapping (design claims vs this review)

| Design claim | Verdict |
|---|---|
| Decision 8: fail-open is "consistent with the codebase's fail-open-with-log doctrine"; verify it is logged | **False as written** — fail-open is real but unlogged, un-metric'd (H-1) |
| Decision 1: "Metrics for free" on all three surfaces | **Partial** — true for /token + /userinfo; admin tier-1/tier-2 bypass `recordRejection` (H-2) |
| Decision 7: "No clock coupling" | **Partial** — Memory/Redis yes; SQLite is wall-clock coupled cross-replica (M-5) |
| Decision 8: SIGHUP row "in-memory bucket state resets" | **Partial** — memory only; shared backends persist counters, so a raise un-locks fleet-wide instantly (D-4) |
| Decision 6: "same whole-block rebuild contract as today" | **Partial** — rebuild yes; close/readiness discipline for the new limiters unspecified (M-4) |
| Probes outside rate limiting; middleware order preserved | **Verified** |
| 429s land in `sso_http_requests_total` 4xx class; no-store headers preserved | **Verified** |
| Admin middleware ordering (tier-2 before idle-timeout) | **Verified** (middleware.go:330-345) |
| Decision 9 latency budgets | **Verified as measured** (cited); no SLO committed (I-2) |
