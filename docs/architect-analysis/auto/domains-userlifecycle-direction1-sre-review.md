# SRE Review: lifecycle state becomes an enforced auth gate (direction 1)

Reviewer role: SRE engineer. Input: `docs/auto/domains-userlifecycle-direction1-design.md`
(design-only; no `.go` changed) plus the current tree's operational surface:
`cmd/sso-server` build order and ready checks, `platform/audit` sink
composition, `domains/userlifecycle` + `memory` store, `protocols/
lifecyclereactions`, `ops/deploy/grafana/alerts.yaml`, `ops/deploy/openresty`
edge, `ops/deploy/baremetal-ha/RUNBOOK.md`, and the deployment/DR/
observability/config docs.

Scope: can operators **detect, withstand, and recover** from failures of the
three new mechanisms — the login gate, the refresh gate, and transition-time
revocation — given that the design converts a governance-metadata feature into
a fail-closed authentication dependency with a memory-only, per-process,
non-durable state store and a revocation trigger that rides the audit
pipeline?

**Verification run for this review.** Read-only; no `.go` files changed, no
build gates run (consistent with the sibling reviews for this design).
Evidence below was re-derived by direct file reads on the current worktree:

- Build order `cmd/sso-server/build_stores.go:33-74` — `wireFoundation`
  (audit, `build_app_core.go:198-232`, `b.recorder` set at `:221`) →
  `wireDomains` → `wireEdge` → `finalize` (`build_app.go:236-285`) →
  `wireGovernance` (`build_app_security.go:218`) → `wireUserLifecycle`
  (`:240`); **Verified** — `b.recorder` exists before `wireUserLifecycle`,
  so the design's `AddSink(bus)` wraps the fully composed sink chain
- Audit composition `composeAuditSinks` (`build_app_core.go:234-262`):
  `webhook → SIEM → kafka → async`, async outermost; `Recorder.AddSink`
  wraps the current sink in `MultiSink(r.sink, extra)`
  (`platform/audit/recorder.go:131-141`); `MultiSink.Record` iterates sinks
  synchronously in order (`multi_sink.go:24-34`); **Verified** — the bus is a
  **sibling** of the `AsyncSink`, not behind it: revocation fires
  synchronously on the admin request goroutine and is NOT subject to audit
  queue backpressure; the bus receives the **admin request context**
- `interfaces/admin/lifecycle.go:77-99` — `applyLifecycleTransition`:
  `Append` (state committed) → `RecordTransition(ctx.Request().Context(),
  d.Auditor(), ...)` → `ctx.JSON(200)`; **Verified** — reaction runs between
  state commit and the 200, under the request ctx
- `domains/userlifecycle/sweep.go:148-178` — `RecordTransition` emits
  `EventAdminUserLifecycleChanged` for sweep- and admin-driven transitions
  alike; sweep ctx is the background loop ctx, not request-scoped;
  **Verified**
- `domains/userlifecycle/memory/memory.go` — process-local map; package doc:
  "State is lost on restart"; **Verified**
- `cmd/sso-server/build_stores.go:95-131` — `haCoherenceIssues` covers
  oauth/sessions/jti/ciba/identity/mfa/self_service/pairwise; **no
  `user_lifecycle` entry**; `enforceHACoherence` (`:80-93`) fails boot for
  declared multi-replica topology with per-process critical stores;
  **Verified**
- `cmd/sso-server/serverbuildplatform/build_userlifecycle.go:18-24` — memory
  store is the only backend; `user_lifecycle` absent from shipped
  `config.yaml` (grep) — default-off; **Verified**
- Metrics: zero lifecycle references in `domains/userlifecycle`,
  `protocols/lifecyclereactions`, `interfaces/admin/lifecycle.go`, and
  `docs/observability.md` (grep); `recordLoginFailure`
  (`interfaces/sso/server_helpers.go:282-297`) bumps
  `sso_login_attempts_total{provider,"failure"}` + audit + anomaly — reason
  is NOT a label; refresh denials in `HandleRefreshGrant`
  (`internal/handler/tokengrant/token_refresh.go:57-114`) bump nothing
  (only `sso_refresh_rotation_velocity_exceeded_total` exists);
  **Verified**
- `ops/deploy/grafana/alerts.yaml` (full read) — 11 rules; **none reference
  lifecycle, suspension, refresh denials, or the lifecycle store**;
  `SSOHighLoginFailureRate` describes the failure class as "Possible
  credential-stuffing attack"; **Verified**
- `ops/deploy/baremetal-ha/RUNBOOK.md` (451 lines) — no lifecycle/suspension
  content (grep); `docs/dr-framework.md:76` — lifecycle state is NOT in the
  DR snapshot control-plane subset; **Verified**
- Line budgets re-measured with `wc -l`: `server_login_auth.go` 493,
  `server_login_resolve.go` 413, `server_mfa.go` 471, `server_mfa_trust.go`
  491, `server_oauth.go` 495, `options_admin.go` 474, `server_helpers.go`
  495, `token_refresh.go` 431, `userlifecycle.go` 164, `sweep.go` 178,
  `revoke_on_archive.go` 89; `interfaces/sso` = exactly 60 non-test files;
  **Verified** — the design's D1 budget arithmetic holds
- `docs/error-codes.md:139` — `account_locked` documented as 423 while the
  code writes 403 at every site (`server_login_auth.go:79,122`);
  **Verified**; OpenResty edge (`ops/deploy/openresty/conf.d/sso.conf`) —
  `/auth/*`, `/token`, `/health` pass through; `/api/v1/` JWT-verified;
  **Verified**

---

## 1. Service/dependency map and operational assumptions

```text
 browser SPAs ──► OpenResty edge (prototype boundary)
   (separate       /auth/*, /token, /health: pass-through (no edge auth)
    projects)      /api/v1/* (admin lifecycle incl.): local JWT verify
                   no edge rate limiting, no edge alerting
                   └──► sso-server replica (stateless)
                         /livez /readyz /metrics (outside ratelimit)
                         ├─ shared stores (fleet): redis/pg/sqlite
                         │    sessions, refresh tokens, auth codes, audit
                         ├─ per-process stores: lifecycle state (MEMORY),
                         │    token-policy, break-glass, ...
                         └─ audit pipeline: Recorder → MultiSink(
                              AsyncSink(webhook→SIEM→kafka→primary), bus )
                              bus fires sync on the admin request goroutine
        NEW after D1-D3:
        ├─ login gate: +1 lifecycle read per login leg (fail-closed)
        ├─ refresh gate: +1 lifecycle read per refresh (fail-closed, after Consume)
        └─ revocation: bus(OnUserSuspended|OnUserArchived) → session
             destroy + DeleteAllForSubject — sync inside the admin 200
```

**Operational assumptions (current tree, re-verified):**

- A1. **`user_lifecycle` is default-off and memory-only in the stock
  binary.** No shipped config enables it; `BuildUserLifecycle` returns a
  `memory.Store` (per-process map). Every production-relevant property of
  this design (durability, convergence, alerting) is exercised only by
  operators who opt in — and the design changes what opting in means: from
  "governance metadata" to "fail-closed auth enforcement".
- A2. **Restart = un-suspension.** The lifecycle store has no durability and
  no DR/backup story (not in the dr-framework snapshot subset,
  `docs/dr-framework.md:76`). After this design, a restart silently converts
  every SUSPENDED/ARCHIVED/INACTIVE account back to ACTIVE at the gates.
  Today that is an admin-state annoyance; after D1/D2 it is a security-
  invariant reset with no alert (F1).
- A3. **The revocation trigger and its evidence have different durability
  classes.** The bus fires synchronously (never rides the async buffer), but
  the `admin_user_lifecycle_changed` event that *proves* the transition
  rides the async buffer and can be dropped at saturation. A crash between
  `Append` and bus dispatch loses the reaction with no replay (F3/F4).
- A4. **The fail-closed gates are invisible to the existing metric surface.**
  Login denials collapse into `sso_login_attempts_total{failure}` (no reason
  label); refresh denials bump nothing; the transition itself has no
  counter. The design's only differentiators are log lines (which flood at
  login volume and are not trace-correlated on the login path) and audit
  meta (F2).
- A5. **The store cannot fail today** (memory map), so every "store-outage"
  property of the design is latent until the SQL peer lands (direction 3).
  The metric/alert/runbook surface must be wired now, or the peer ships
  blind (F2, F8).
- A6. **No availability SLO exists anywhere** (verified: dr-framework RPO/RTO
  are DR-report targets only). The design adds a per-login and per-refresh
  read; the latency budget and the outage posture ("lifecycle store down =
  all logins/rotations denied, byte-indistinguishably") need an operator-
  visible measurement or explicit acceptance (F8).
- A7. Frontend contract: the gates reuse the existing 403 `account_locked`
  and 400 `invalid_grant` wire shapes, so no new frontend handling is
  required **as long as frontends were built to the code, not to
  `docs/error-codes.md`** — the doc says 423 (F6 in this review; F-4 in the
  protocol review).

---

## 2. Readiness table

| Signal | Dependency | Failure behavior | Alert today | Runbook today |
|---|---|---|---|---|
| `/livez` | process | 200 while handler runs | `SSOInstanceDown` (critical) | `baremetal-ha/RUNBOOK.md` §1 |
| `/readyz` (aggregate, 3s bound) | named checks | 503 + per-check map; pod drained | none per-check | none |
| `/readyz: sqlite-identity-*`, `audit-<backend>` | store Pings | drains replica | `SSOSigningKeyAggregationDegraded` (bus only) | none |
| `/readyz: dr` | DR readiness (opt-in `dr.gate_readiness`) | report-only by default | `sso_dr_readiness` gauge; no alert | RUNBOOK §5 |
| **lifecycle store (NEW auth-path dependency)** | `userlifecycle.Store.Get` per login leg + per refresh | **no ready check; memory store cannot fail; SQL peer will need one** | **none** | **none** |
| **login gate (D1)** | lifecycle read, fail-closed | store error ⇒ 403 `account_locked` for every login, byte-identical to suspension | `SSOHighLoginFailureRate` fires, **misleading description** (F2) | none |
| **refresh gate (D2)** | lifecycle read after `Consume`, fail-closed | store error ⇒ 400 `invalid_grant`; presented token burned; retry kills the family | **none — refresh denials are metric- and audit-silent** | none |
| **revocation bus (D3)** | audit Recorder + sync reaction | `audit.enabled:false` ⇒ inert (boot warning only); ctx cancel mid-reaction ⇒ partial revocation, no retry path | **none** | none |
| audit async buffer | `audit.async` | queue_full drops — including the transition's evidence event | `SSOAuditEventsDropped` (critical) | dashboard note |
| edge `/auth/*`, `/token` | OpenResty | pass-through, no edge rate limiting | none (edge has no alerting) | none |

---

## 3. Findings

### F1 [High] — Enforcement state is non-durable and non-converged; nothing detects either

- **Evidence**: `memory.Store` is a process-local map ("State is lost on
  restart", `memory/memory.go:9`); the store is per-replica with no
  cross-replica propagation; `haCoherenceIssues` (`build_stores.go:95-131`)
  fails declared multi-replica boots for every per-process **critical**
  store (oauth, sessions, jti, ciba, identity, mfa, self-service, pairwise)
  but has no `user_lifecycle` entry — because today lifecycle is not a
  critical store. The design (Decision 4) keeps memory-only and inherits
  the state machine's divergence.
- **Production impact**: this design **reclassifies** the lifecycle store
  from governance metadata to a security invariant, but the inventory of
  "critical per-process stores" and its boot gate are not updated with it.
  Concretely: (a) any restart (deploy, crash, rollback, DR cutover) silently
  re-admits every suspended/archived user at all five login sites and the
  refresh gate on that replica — with no metric, no boot warning, and no
  alert; only a post-hoc audit query shows the truth (the durable audit
  events survive, the state that made them consequential does not); (b) in
  a multi-replica deployment (or during a rolling rollout with mixed
  binaries), replica B admits and issues fresh families to a user suspended
  on replica A indefinitely — the design's risk 10 "refresh gate narrows
  the blast radius" is only true for *existing* families; new logins on
  replica B mint new ones the gate cannot see (no record on B). The
  ds-review (F-2) and security review (F2) independently reach the same
  conclusion.
- **Remediation**:
  1. Add `{b.cfg.UserLifecycle.Enabled, "user_lifecycle.enabled", "memory"}`
     to `haCoherenceIssues` — in a declared multi-replica topology this
     fails boot (or at minimum logs the loud "HA INCOHERENCE" error) exactly
     as it does for oauth/sessions today. One line, uses the existing gate.
  2. Boot log line (extends the existing `wireUserLifecycle` info log):
     "lifecycle enforcement ACTIVE — state is per-process and lost on
     restart" when `user_lifecycle.enabled` is true in a shared-store or
     multi-replica config.
  3. Treat the direction-3 SQL peer + convergence as a **launch
     prerequisite for production enforcement**, not a follow-up: until it
     lands, `docs/config-reference.md` §User Lifecycle must state that
     enforcement is single-replica-only and restart-volatile.
- **Recovery validation**: stage a 2-replica deployment with
  `user_lifecycle.enabled` + shared redis sessions; suspend a user on A;
  assert B still admits them today; add the coherence entry; assert boot
  fails; then document the restart-reset with a drill (D5 below).

### F2 [High] — The fail-closed outage is detectable only through a misleading alert or log floods

- **Evidence**: the design pins fail-closed on read error (Decision 5) and
  acknowledges the only differentiators are "the fail-closed log line +
  `login_failure` audit stream" (risk 6.8). But: `recordLoginFailure`
  (`server_helpers.go:282-297`) bumps `sso_login_attempts_total{provider,
  "failure"}` with no reason label, so a lifecycle-store outage floods the
  exact metric `SSOHighLoginFailureRate` watches — whose description tells
  the operator "Possible credential-stuffing attack ... consider tightening
  the per-IP /auth/login bucket" (alerts.yaml:42-51). The design's own risk
  6.8 ("an operator ... may 'fix' it by suspending more accounts") is the
  runbook-shaped consequence. Refresh denials are worse: `HandleRefreshGrant`
  denials bump no metric and emit no audit event (log-only via
  `LogErrorCtx`), so a refresh-gate outage is invisible to Prometheus
  entirely, and every denial burns the presented token (gate runs after
  `Consume`, `token_refresh.go:62-69`) so client retries destroy families.
- **Production impact**: two outage classes with no correct detection:
  (a) login-path — wrong alert fires with wrong guidance; (b) refresh-path —
  nothing fires, families die silently. With the memory store neither can
  happen today; the moment the SQL peer (direction 3) lands, both are live
  outage modes. The design's "no new metrics" stance leaves the peer
  blind.
- **Remediation** (bounded cardinality, oracle-safe — the wire stays
  byte-identical; only the metric differs):
  1. `sso_lifecycle_gate_denials_total{reason}` with reason ∈ {state,
     store_error} (2 values) incremented at all five login sites and the
     refresh gate;
  2. an alert on `store_error` rate > 0 (5m) — "lifecycle store read
     failing; all logins/rotations denied fail-closed";
  3. fix `SSOHighLoginFailureRate`'s description (or add a runbook line):
     mass 403 `account_locked` at high concurrency can mean lifecycle-store
     outage — check the fail-closed log line before tuning rate limits;
  4. refresh-gate denials get the same `store_error` counter so both
     surfaces share one alarm.
- **Recovery validation**: inject a failing `Store` double in the
  acceptance harness (qa F2's 3-method failing store), assert the counter
  rises while the wire body stays byte-identical, and the alert fires;
  restore and assert recovery.

### F3 [High] — Synchronous revocation runs on the admin request context; disconnect/timeout cancels it after the state committed

- **Evidence**: `applyLifecycleTransition`
  (`interfaces/admin/lifecycle.go:77-99`) calls
  `RecordTransition(ctx.Request().Context(), d.Auditor(), ...)` — the
  request context flows through `Recorder.Record` → `MultiSink` →
  `bus.Record` → `RevokeAccessOnSuspend` synchronously, before the 200.
  The audit composition places the bus as a sibling of `AsyncSink`
  (`recorder.go:131-141`, `multi_sink.go:24-34`), so the reaction is NOT
  protected by the async buffer's detached context — it is a plain
  request-scoped call. A client disconnect or a gateway timeout (an LB
  that abandons the upstream at its timeout) cancels the context mid-
  reaction: `Append` already committed, session/token revocation stops at
  the first canceled store call, the error is logged and forgotten, and the
  operator's retry hits `409 lifecycle_state_conflict` (state is already
  SUSPENDED). The only remediation today is suspend → reactivate → suspend.
  The sweep path is unaffected (background loop ctx). ds-review F-1 and
  security-review F3 agree.
- **Production impact**: the design's headline guarantee — "the admin 200
  implies revocation completed" — holds only when the reaction completes
  before the client/edge gives up. Under load (slow store calls) or with an
  aggressive edge timeout, suspension degrades silently to "gate-only"
  enforcement: the user's *existing* live session and refresh family
  survive to TTL and keep working through the resource-server/refresh
  paths, exactly the access the reaction was supposed to cut.
- **Remediation**:
  1. Run the reaction on a context detached from the request:
     `context.WithoutCancel(ctx)` (in-repo precedent:
     `server_backchannel_logout.go:171`; caep transmitter drops
     cancellation the same way) — commit to doing this inside
     `LifecycleEventBus.Record` or at the `RevokeAccessOnSuspend` wrapper,
     so both admin- and sweep-driven dispatch get it;
  2. an idempotent reconcile (ds-review F-3/F-4): a startup or periodic
     `ListByState(SUSPENDED|ARCHIVED)` re-run of the reactions closes the
     crash window between `Append` and dispatch, and gives the operator a
     retry path that is not a 409 trap;
  3. note in the admin runbook: a `409 lifecycle_state_conflict` on retry
     after a timed-out suspend means "state committed; revocation may be
     incomplete — check session/token counts or run the reconcile".
- **Recovery validation**: drill D4 below — cancel the request context
  mid-reaction in a test harness (qa P2's concurrency set), assert the
  reaction resumes/retries on the detached context and the reconcile
  converges; assert the admin 200 is written only after the detached
  reaction completes.

### F4 [Medium] — `audit.enabled: false` disarms revocation with a boot warning only; evidence and trigger have different durability

- **Evidence**: `wireAudit` returns early when `audit.enabled` is false
  (`build_app_core.go:200-202`), leaving `b.recorder` nil; `AddSink` no-ops
  on nil (`recorder.go:131-140`). The design's boot warning is the only
  signal, and there is no metric or ready check for "reactions inert".
  Conversely, when audit IS enabled with the async wrap, the
  `admin_user_lifecycle_changed` event that evidences the transition rides
  the async buffer (`composeAuditSinks`, async outermost) and is drop-able
  at saturation (`SSOAuditEventsDropped`), while the bus — a sibling of the
  AsyncSink — fires regardless. So: revocation can happen without evidence
  (crash before the async worker drains), and evidence can be lost while
  revocation still fires (queue full).
- **Production impact**: an operator running `audit.enabled: false` +
  `user_lifecycle.enabled: true` (a valid, documented combination today)
  gets read-gate enforcement but zero revocation, indefinitely, with only a
  boot-time log line. The security review (F4) and ds-review flag the same
  configuration. The evidence-loss window is pre-existing audit
  architecture, but for a security invariant the ordering deserves an
  explicit statement.
- **Remediation**:
  1. Add the `sso_lifecycle_reactions_inert` gauge (1 when
     `user_lifecycle.enabled && recorder == nil`, 0 otherwise) or fold the
     condition into an existing boot-config gauge;
  2. document in `docs/config-reference.md`: the revocation reaction
     requires `audit.enabled: true`; the transition's audit evidence can be
     dropped at async-queue saturation — treat `SSOAuditEventsDropped` as a
     security-evidence alert for lifecycle transitions, not just a
     bookkeeping alert;
  3. the design's existing loud warning stays, but it should name the
     consequence ("SUSPENDED/ARCHIVED transitions will NOT revoke
     sessions/tokens").
- **Recovery validation**: boot with the pair
  `audit.enabled:false`/`user_lifecycle.enabled:true`, assert the gauge
  reads 1 and the warning names the consequence; flip audit on, assert 0.

### F5 [Medium] — Sweep-driven transitions become destructive with no transition metric and an unlimited default cap

- **Evidence**: the bus observes `RecordTransition` from `sweep.go:148`,
  so sweep-driven `INACTIVE → ARCHIVED` fires `RevokeAccessOnArchive` (the
  design calls this "a behavior improvement"); `max_per_sweep` defaults to
  0 = unlimited (`docs/config-reference.md:705`); the sweep uses
  `time.Now()` (`sweep.go:48-51`); there is no counter for transitions
  anywhere (`domains/userlifecycle`, `protocols/lifecyclereactions`,
  `interfaces/admin/lifecycle.go` are metric-free — grep verified).
- **Production impact**: a forward clock jump (ds-review F-6) or a
  misconfigured `dormant_after`/`archive_after` now converts a previously
  side-effect-free metadata sweep into fleet-wide access cutoff, in one
  sweep, with no pre-transition alert. The only signal is the subsequent
  login-failure storm. Operators cannot even see "how many accounts moved
  to ARCHIVED in the last hour" in Prometheus — audit query only.
- **Remediation**:
  1. `sso_user_lifecycle_transitions_total{to_state}` (6-value label,
   bounded) incremented in `RecordTransition` — one line, and it makes the
   bus's own firing rate observable;
  2. recommend a non-zero `max_per_sweep` in production config docs;
  3. runbook line: sweep cadence + clock discipline (NTP; `dormant_after`
   + `archive_after` should exceed any planned clock-skew window).
- **Recovery validation**: drill D3 below — set `archive_after` to
  seconds, run one sweep, assert the counter records N transitions and the
  reactions revoke; verify the alert threshold catches an anomalous spike.

### F6 [Medium] — Restart/rollback silently disables enforcement; the 423-vs-403 drift misleads frontends

- **Evidence**: (a) memory store + gates ⇒ any restart or rollback to a
  pre-design binary converts enforcement to metadata-only with no signal
  (F1 mechanics); the old binary is byte-identical pre-feature, so rollback
  is safe from lockout but silently disables the *reactions* too; (b)
  `docs/error-codes.md:139` documents `account_locked` as 423 while every
  code site writes 403 (`server_login_auth.go:79,122`) — a frontend or
  operator runbook written to the doc checks for the wrong status and
  never renders the "suspended" state.
- **Production impact**: during a rolling rollout, enforcement is
  fleet-wide only after the last replica rolls; suspension applied during
  the window is honored only by new binaries. That is tighten-only (safe),
  but it means "suspended" is *not* an instantaneous fleet state — and
  after a rollback, previously-suspended users become ACTIVE again on the
  memory store. Operators must be able to state "which binaries enforce"
  at a glance.
- **Remediation**:
  1. boot log line per replica: "lifecycle enforcement ACTIVE" vs
   "metadata-only" (extends the existing `wireUserLifecycle` info log);
  2. reconcile `docs/error-codes.md` to 403 in the design's contract
   change (design risk 4; protocol F-4 adds `openapi.yaml`);
  3. deployment note: suspension during rollout is honored per-replica;
   re-apply after rollout completes if immediate fleet-wide enforcement is
   required.
- **Recovery validation**: drill D5 — roll back one replica mid-rollout,
   assert it admits a suspended user (documented divergence), then roll
   forward and assert denial returns; assert a frontend compiled against
   the doc's 423 handles the real 403 after the doc fix.

### F7 [Medium] — Ungated paths remain: exchange/device-secret/auth-code residuals with no detection

- **Evidence**: security review F1 — RFC 8693 token exchange
  (`token_exchange_stages.go:417-482`) and the native-SSO device-secret
  exchange check subject/session *match*, never session *liveness* or
  lifecycle; the auth-code gap is the design's own risk 6. The design's
  residual list names only the auth-code gap.
- **Production impact**: "suspend = revoke access" has a measurable
  residual: fresh-TTL tokens can be minted via exchange/device-secret after
  suspension until direction work closes them, and a pre-suspension
  unexchanged auth code can mint a fresh family. From an operator's
  standpoint the promise is not the mechanism — the runbook must state the
  residual window and what closes it (token TTL, family death at first
  rotation, code TTL). No detection exists for these paths today.
- **Remediation**: one runbook paragraph in `docs/config-reference.md`
  §User Lifecycle enumerating the residual paths (auth-code exchange,
  token exchange, device-secret, CIBA — each with its TTL-bounded window)
  and the follow-up work that closes them; the design's own risk-6 wording
  extended with the exchange/device paths per security F1.
- **Recovery validation**: none needed (documentation); pin with the
  design's acceptance tests for the named residuals.

### F8 [Low] — No SLO, and the new reads have no latency or outage measurement

- **Evidence**: no availability SLO anywhere (verified grep of
  deployment/observability/dr docs; dr-framework RPO/RTO are DR-report
  targets only). The design adds one keyed read per login leg and per
  refresh with a fail-closed posture that converts store outage into
  total auth outage.
- **Production impact**: operators cannot state a login-availability
  target, cannot budget the new read's latency contribution (memory:
  negligible; SQL peer: one keyed read), and have no agreed meaning for
  "lifecycle store degraded". The fail-closed stance deserves an explicit
  degraded-mode entry: a lifecycle-store outage IS an auth outage by
  design — decide the measurement (e.g., "login availability excludes
  lifecycle-store outage" or "lifecycle read p99 budget = X") before the
  SQL peer ships.
- **Remediation**: measurement decision (not necessarily an SLO): login
  p95 budget including the lifecycle `Get`; document the fail-closed
  outage posture in `docs/config-reference.md` (design risk 6.8 already
  requires the prose) and consider wiring a `sso_degradation_mode`
  transition when the SQL peer reports read errors — the degradation
  manager and its gauge already exist.
- **Recovery validation**: benchmark login latency with the gate on the
  memory store (should be ~0) and record the delta; repeat with the SQL
  peer in the direction-3 acceptance harness.

### F9 [Low] — Alert-to-runbook coverage is absent for every lifecycle failure class

- **Evidence**: `ops/deploy/baremetal-ha/RUNBOOK.md` (451 lines) has no
  lifecycle/suspension content; `alerts.yaml` has 11 rules, none
  lifecycle-related; the only alert that fires on a fail-closed login storm
  (`SSOHighLoginFailureRate`) points at credential stuffing (F2).
- **Production impact**: an on-call engineer facing any lifecycle failure
  (mass 403s, "suspended user still logged in", "restart un-suspended
  everyone") has no runbook path and no alert naming the subsystem.
- **Remediation**: a lifecycle subsection in the runbook covering: mass
  403 diagnosis (fail-closed log line vs. real suspension vs. SCIM
  fail-open asymmetry), divergence checks (`GET /api/v1/admin/users/:id/
  lifecycle` per replica), restart-reset recognition, and the residual
  paths (F7).
- **Recovery validation**: tabletop the four scenarios against the new
  subsection (drill D5).

### F10 [Info] — Positive verifications (no finding)

- The bus does not ride the async buffer: revocation is not subject to
  audit backpressure, and `SSOAuditQueueSaturated` cannot delay a
  suspension (verified composition order).
- The design's wiring order claim holds: `b.recorder` exists before
  `wireUserLifecycle`; `AddSink` is a wiring-time call, pre-`NewServer`
  (design risk 12 satisfied by the existing build order).
- No new request input, no new endpoints, no new headers at the edge —
  the external boundary is unchanged; the edge's `/api/v1/` JWT gate
  already covers the admin lifecycle surface.
- `audit.SetMeta` bounded cardinality holds: `lifecycle.state` is a
  6-value enum; the login gate's meta addition is compliant
  (design D1.3).
- The 200-after-reaction ordering is real (F3's remediation need
  notwithstanding): the design's synchronous-reaction claim is
  mechanically correct.
- The D1/D2 budget arithmetic re-measured clean (all eight cited files
  within their claimed line counts; 60-file ceiling intact).

---

## 4. Failure drills

Each drill: trigger → expected behavior → detection → recovery → validation
gate. Runnable in staging against the current tree plus the design's
acceptance harnesses (qa review's five fixtures).

### D1 — Outage: lifecycle-store read failures (SQL peer, post-direction-3)

- Trigger: the durable lifecycle peer loses reachability mid-flight.
- Expected: login gates deny 403 `account_locked` (fail-closed,
  byte-identical to suspension); refresh gate denies 400 `invalid_grant`;
  every denied refresh has burned its token — client retries kill
  families.
- Detection: **fails today** — login denials flood
  `sso_login_attempts_total{failure}` tripping `SSOHighLoginFailureRate`
  with a misleading description; refresh denials are invisible (F2);
  `/readyz` has no lifecycle check.
- Recovery: restore the peer; gates recover on the next read (no cache).
  Families destroyed by retry amplification are not recoverable —
  re-authentication required.
- Validation (with F2 remediation): `sso_lifecycle_gate_denials_total{
  reason="store_error"}` rises, the dedicated alert fires, wire bodies
  stay byte-identical; restore and verify a login + refresh succeed.

### D2 — Saturation: login flood × gate + audit-queue saturation

- Trigger: credential-stuffing or probe traffic while lifecycle reads are
  slow; audit async queue fills.
- Expected: gate adds one keyed read per login leg (memory: ~0);
  revocation is NOT delayed by queue saturation (bus is the AsyncSink's
  sibling — F10); the transition's audit evidence CAN be dropped
  (`SSOAuditEventsDropped`).
- Detection: queue-depth gauge, drop counters (existing); no lifecycle
  contribution to p95 is measured today (F8).
- Recovery: rate-limit tuning; audit buffer/worker growth per existing
  runbook; no lifecycle change needed.
- Validation: login p95 delta with gate on/off recorded (F8 budget);
  suspend during saturation and verify revocation still completes while
  `SSOAuditEventsDropped` may fire for the evidence event.

### D3 — Bad rollout: destructive sweep + clock jump

- Trigger: (a) `archive_after` misconfigured small; (b) forward clock jump
  on a replica; (c) rolling rollout of the gates with a suspension applied
  mid-window.
- Expected: (a/b) one sweep moves a large cohort INACTIVE → ARCHIVED and
  each fires fleet-wide revocation (sessions + refresh families) — with
  `max_per_sweep` 0 = unlimited, the whole roster in one pass; (c)
  enforcement is per-replica — new binaries deny, old binaries admit.
- Detection: **fails today** — no transition metric (F5), no per-replica
  enforcement state (F6); the login-failure storm arrives after the fact.
- Recovery: (a/b) restore the config, re-activate affected accounts via
  the admin transition (their refresh families are gone — re-auth); audit
  query identifies the sweep actor ("system"); (c) finish the rollout, or
  re-apply suspensions after completion.
- Validation (with F5 remediation): transition counter spikes on the
  sweep; alert fires; reactivation drill (ACTIVE restore) completes within
  the acceptance suite's recovery test.

### D4 — Stale state: multi-replica divergence and interrupted revocation

- Trigger: (a) suspend on replica A, traffic served by replica B; (b)
  client disconnect / edge timeout mid-reaction.
- Expected: (a) B admits the user and mints fresh families indefinitely
  (F1); (b) `Append` committed, revocation partial, retry → 409 (F3).
- Detection: **fails today** — no divergence signal, no per-replica state
  comparison; the 409 + error log is the only clue.
- Recovery: (a) converge via the direction-3 peer; until then, re-apply on
  every replica or accept per-replica enforcement; (b) run the idempotent
  reconcile (F3 remediation) — no suspend/reactivate/suspend dance.
- Validation: drill with a 2-replica harness asserting B's admission (pins
  the documented divergence); ctx-cancel test asserting the detached
  reaction completes and the reconcile converges (ds-review's ctx-cancel +
  idempotency tests).

### D5 — Restore: restart un-suspension, rollback, DR cutover

- Trigger: (a) replica restart (deploy/crash); (b) rollback to a
  pre-design binary; (c) DR cutover to a fresh replica.
- Expected: (a/b/c) the memory lifecycle store is empty — every
  SUSPENDED/ARCHIVED account reads ACTIVE at the gates; reactions are
  unwired on old binaries; the durable audit trail still records the
  original transitions.
- Detection: **fails today** — no gauge, no boot warning, no alert (F1);
  the audit query ("who was suspended before the restart") is the only
  evidence.
- Recovery: operator re-applies suspensions from the audit trail (a
  replay script over `GET /api/v1/audit` events is the pragmatic tool), or
  the direction-3 peer restores state from its durable store.
- Validation: restart drill asserting the boot log names enforcement
  volatility (F1 remediation); re-apply-from-audit script verified against
  the acceptance suite's suspend-twin matrix.

---

## 5. Launch blockers, rollback triggers, monitoring gaps, residual risks

### Launch blockers (must land with the design)

1. **F1**: `haCoherenceIssues` entry for `user_lifecycle` (or the loud
   "HA INCOHERENCE" error path) + boot log naming the restart-volatile
   enforcement + `config-reference.md` stating enforcement is
   single-replica-only until the SQL peer lands. Without this, the design
   ships a security invariant with the durability of a cache and no signal
   when it resets.
2. **F2**: the bounded gate-denial counter (`reason ∈ {state,
   store_error}`) at all five login sites + the refresh gate, plus the
   `SSOHighLoginFailureRate` description fix. The fail-closed posture is
   only acceptable with a correct alarm; the SQL peer must not ship blind.
3. **F3**: `context.WithoutCancel` for the sync reactions + an idempotent
   reconcile path. The "200 implies revocation" guarantee is the design's
   headline; it is currently conditional on the client staying connected.
4. **F5**: the transition counter (one line in `RecordTransition`) so the
   now-destructive sweep is observable; production docs recommend a
   non-zero `max_per_sweep`.
5. The design's own acceptance tests (six-state table, byte-compare pairs,
   fail-closed injections, wiring tests), with the qa fixtures (failing
   store, two-token family fake, bus-aware test builder) — the qa lead's
   F1/F2 choreographies are needed to prove the outage behavior this
   review's drills rely on.
6. Contract reconciliation in the same change (AGENTS §5.6):
   `docs/error-codes.md` 423 → 403 (design risk 4) + `openapi.yaml`
   (protocol F-4) + the three "NEVER gates" texts (design risk 3) + the
   three stale docs the design already flags.

### Rollback triggers (stop-the-roll criteria)

- Mass 403 `account_locked` beyond the SCIM-deprovisioned baseline while
  `user_lifecycle.enabled` is configured (fail-closed storm — check the
  fail-closed log line before touching rate limits; if it is the store,
  roll back config first, then binary).
- Admin suspend returns 200 but the user's live session keeps working
  beyond TTL (reaction canceled or inert — F3/F4; verify
  `audit.enabled`).
- Post-restart, a previously-suspended user logs in successfully (memory
  reset — F1; the divergence is documented, so this is a trigger only for
  the *unannounced* case: no boot warning about enforcement volatility).
- Rollback mechanics (verified safe): old binaries are byte-identical
  pre-feature; no schema, no storage, no wire changes. Rollback silently
  disables enforcement and reactions — state it in the post-incident
  record; suspended users must be re-checked after a rollback (F6).
- The only destructive-rollout hazard is the sweep (F5): if a rollout
  coincides with `archive_after` crossing, revocation fires during the
  window — pin `max_per_sweep` before rolling.

### Monitoring gaps (post-launch backlog)

- No lifecycle metric of any kind (transitions, gate denials, gate store
  errors, reactions-inert gauge) — F2/F4/F5.
- No readiness check for the lifecycle store, and none proposed for the
  SQL peer (F2 table) — the peer must register a `/readyz` check in the
  same change that introduces it.
- No per-replica enforcement-state signal (boot log is the minimum; a
  `sso_lifecycle_enforcement{state}` gauge is the better surface) — F1/F6.
- No refresh-denial telemetry at all — F2.
- No alert references lifecycle/suspension/divergence — F9; runbook has
  no lifecycle section.
- No availability SLO or login-latency budget including the new reads —
  F8.

### Residual risks

1. **Restart = un-suspension** (F1) — accepted only with the boot warning
   + coherence entry + documentation; the SQL peer is the durable fix.
2. **Multi-replica divergence** (F1) — replica B admits suspended users
   indefinitely; per-replica enforcement is the documented steady state
   until direction 3 converges.
3. **Fail-closed self-lockout** (F2) — deliberate (Decision 5), but the
   only differentiators today are a misleading alert and log floods;
   blocked until the counter + alert land.
4. **Retry amplification destroys families** (F2/D1) — a transient
   lifecycle-store error burns tokens; client retries kill families.
   Documented in `config-reference.md` per ds-review F-5 before the SQL
   peer ships.
5. **Interrupted revocation** (F3) — partial revocation with a 409 retry
   trap; the reconcile is the recovery path.
6. **Ungated residual paths** (F7) — exchange/device-secret/auth-code
   windows mint fresh tokens after suspension; TTL-bounded, runbook-
   documented, closed by direction work.
7. **Destructive sweep** (F5) — clock jump or misconfig converts metadata
   transitions into fleet-wide revocation; counter + non-zero cap +
   clock discipline are the mitigations.
8. **No SLO** (F8) — the fail-closed outage posture is an availability
   decision the operator must make explicitly; nothing measures it today.

### Bottom line

The design's mechanics verify clean against the tree — build order,
synchronous bus placement (sibling of the async buffer, so revocation never
rides audit backpressure), the 200-after-reaction ordering, and every line
budget. The operational problem is that **the design converts the lifecycle
store into a fail-closed security dependency while leaving its production
posture untouched**: the state is memory-only (restart = un-suspension,
replica B admits), the outage signal is a misleading alert or nothing, the
revocation can be canceled by the client that requested it, and the
sweep — now destructive — has no metric and an unlimited default cap.
Every blocker here is detection/documentation surface plus two one-line
wiring changes (`haCoherenceIssues` entry, transition counter) and one
context fix (`context.WithoutCancel`) — none changes the design's seam
logic or its budgets. The SQL peer (direction 3) should be treated as the
enforcement-launch prerequisite, not a follow-up, and the metric/alert
surface must ship in this change so the peer does not arrive blind.
