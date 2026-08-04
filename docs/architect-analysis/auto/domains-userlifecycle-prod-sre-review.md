# SRE Review: production hardening of `domains/userlifecycle` (durable store, lease-serialized sweep, persistent last-active)

Reviewer role: SRE engineer. Input: `docs/auto/domains-userlifecycle-prod-design.md`
(design-only; no `.go` changed) plus the current tree's operational surface:
`cmd/sso-server` build order, ready checks and shutdown sequencing, the durable-
backend precedent (`identity_link`), `platform/metrics/consts.go`,
`docs/observability.md`, `ops/deploy/grafana/alerts.yaml`,
`ops/deploy/baremetal-ha/RUNBOOK.md`, the OpenResty edge, `docs/dr-framework.md`,
`docs/deployment.md`, and `docs/frontend-contract.md`.

Scope: can operators **detect, withstand, and recover** from failures of the
three new mechanisms — the durable SQL `Store` peer, the lease-serialized
cursor sweep, and the login-hot-path last-active writer — including the new
dependency the design adds to the API backend (admin lifecycle surface, sweep
loop, login path) and the external frontend/proxy boundary around it?

**Verification run for this revision.** Read-only; no `.go` files changed.
Gates executed: `go build ./... && go vet ./...` ✅, `go test -run
'TestMaintainability_|TestArchitecture_' .` → ok 0.156s ✅. All other claims
re-derived by direct file reads on the current worktree (HEAD `0235cc47`):

- `cmd/sso-server/build_stores.go:325-370` — `wireUserLifecycle`: store built,
  `WithUserLifecycle` appended, activity wired ONLY when
  `deprovision.Enabled()` (`:341` guard); **no `AppendReadyCheck`, no
  storage-health source, no schema gate** for the store; **Verified**
- `cmd/sso-server/build_stores.go:80-131` — `haCoherenceIssues`: identity_link
  IS listed (`:113`), `user_lifecycle` is NOT; **Verified**
- Durable precedent `wireIdentityLink` (`build_stores.go:372-427`): registers
  `checkIdentityLinkSchema` (CheckSchema/MaxVersion boot gate, both sqlite and
  postgres arms, `:403-424`), `AppendReadyCheck("identity-links", store)`
  (`:397`), `appendIdentityLinkHealth` storage-health source (`:398`, `:407`);
  the durable peer has `Ping` + `DB()` (`domains/identitylink/sqlite/store.go:
  81-84`); **Verified** — the design's durable store specifies none of these
- `interfaces/sso/options_admin.go:296-301` — `WithUserAutoDeprovision` is the
  ONLY seam setting `s.userLifecycleActivity`; `:319-333` —
  `RunUserAutoDeprovision` logs ONLY on `SweepOnce` error, a skipped tick is
  silent; **Verified**
- `domains/userlifecycle/sweep.go:148-178` — `RecordTransition` emits one
  `admin_user_lifecycle_changed` per applied transition; per-user errors are
  `logError` only; `:44-62` — full-roster walk; **Verified**
- `platform/metrics/consts.go` (full read) — zero lifecycle metrics;
  `docs/observability.md` — zero lifecycle rows; `alerts.yaml` (full read, 11
  rules) — zero lifecycle rules; `domains/userlifecycle` — zero prometheus
  references; **Verified**
- `SweepLeaser` / `StaleEnumerator` / `ActivityRecorder` — zero hits in
  `domains/` + `cmd/` (grep): all three are design-proposed new types;
  `memory.Store`/`ActivityTracker` today implement neither; **Verified**
- `cmd/sso-server/serverwebauthn/webauthn_handlers.go:120-158, 250-300` —
  `webauthnFinishLoginHandler` + conditional twin authenticate via
  `deps.Helper.FinishLogin` and mint tokens via `applyWebAuthnTokenIssuance` —
  they never call `authenticateUser` (`server_login_auth.go:98` anchor) or
  `finalizeCallbackSession` (`server_oauth.go:223` anchor); the MFA-factor
  replay path (`server_mfa.go`) does funnel through `finishLogin` (qa-lead
  verified at this revision); **Verified** — the design's "ceremonies are
  covered transitively" claim is false for the standalone/conditional
  ceremonies
- `cmd/sso-server/main_shutdown.go:289-318` — `shutdownSchedulers` cancels and
  awaits `userAutoDeprovisionDone` under the shared deadline; sweep loop has
  the standard cancel/done shutdown lifecycle; **Verified**
- `interfaces/sso/server_backup.go:76-89` — `POST /api/v1/admin/backup`
  (`VACUUM INTO`) covers only registered `core.BackupSource` (defaultimpl
  sqlite stores); `domains/identitylink/sqlite` registers none; the design's
  dedicated lifecycle SQLite DSN registers none; **Verified**
- `interfaces/snapshot` — zero lifecycle references (grep); `docs/dr-framework.
  md:76` — lifecycle state not in the snapshot control-plane subset;
  **Verified**
- `config/reload` — only feature-gate reload (`reload_feature_gates.go`);
  `user_lifecycle.*` changes require restart; **Verified**
- `ops/deploy/baremetal-ha/RUNBOOK.md` (451 lines) — zero lifecycle/
  deprovision/dormant content (grep); **Verified**

---

## 1. Service/dependency map and operational assumptions

```text
 browser SPAs (separate projects)
   │ same-origin /login/* /admin/* /portal/* /setup/*  (frontend-contract.md)
   ▼
 OpenResty/Envoy edge ── /auth/*, /token, /health: pass-through
                       ── /api/v1/* (admin lifecycle): local JWT verify
   ▼
 sso-server replica (stateless; /livez /readyz /metrics outside ratelimit)
   │
   ├─ shared stores (fleet): postgres (identity, audit, permissions, ...),
   │    redis (sessions/tokens), etcd (bus/registry) — pg shared *sql.DB pool
   ├─ per-process stores (default): lifecycle state (MEMORY), ...
   │
   └─ NEW after D1-D3 (durable build):
        ├─ user_lifecycle + user_lifecycle_history (PG shared pool, or
        │    dedicated SQLite DSN) ── admin lifecycle endpoints
        ├─ user_lifecycle_last_active ── login hot path Touch (fail-open)
        │    + sweep signal
        ├─ sweep_lease ── cross-replica sweep serialization
        └─ login hot path: +1 conditional upsert per successful login
```

**Operational assumptions (current tree, re-verified):**

- A1. **The durable backend is the first lifecycle store that can fail.**
  Today `BuildUserLifecycle` returns `memory.Store` unconditionally
  (serverbuildplatform/build_userlifecycle.go) — a process-local map that
  cannot fail and needs no readiness, no schema gate, no backup. The design
  ships a SQL store without adding any of the three surfaces every durable
  precedent registers (identity-link: schema boot gate, `/readyz` check,
  storage-health source). Until those land, the new dependency is
  undetectable when it fails (F4).
- A2. **The design makes dormancy real for the first time.** Stock wiring
  (`SessionLastActive`) is blind: no live session reads as "unknown", which
  `IsDormant` treats as do-not-deprovision (`dormancy.go:20-27`), so the
  sweep effectively never fires in stock builds. A durable last-active
  signal with a working producer turns the sweep into production behavior —
  and the design adds zero telemetry for it (F2).
- A3. **The login hot path gains a new dependency with no measurement.**
  One PK upsert per successful login on the durable backend, synchronously,
  before session creation. Fail-open for correctness (login never fails),
  but the latency cost rides the shared Postgres pool with no budget, and a
  sustained write outage freezes the signal (F3).
- A4. **The writer only exists when the sweep is enabled.** The single
  `WithUserAutoDeprovision` seam (options_admin.go:296-301) is gated on
  `auto_deprovision.enabled` in `wireUserLifecycle` (build_stores.go:341).
  Decision 3's "signal written from the login hot path" is therefore not
  independently shippable: disable/re-enable cycles freeze the signal for
  the gap and convert it into mass dormancy on re-enable (F7).
- A5. **Lifecycle state is still not in any backup or DR tier.** Not in the
  DR snapshot subset (dr-framework §1); the SQLite backend has no
  `BackupSource`; only the Postgres backend rides the operator's existing
  PG backup. Restore-time dormancy is an unaddressed recovery hazard (F6,
  F8).
- A6. **No availability SLO exists** (dr-framework RPO/RTO are configured
  DR-report targets only). The design adds a hot-path write and a new admin
  dependency; the latency budget and the outage posture need an explicit
  measurement decision (§5).
- A7. **The external boundary is unchanged.** No new endpoints, headers, or
  wire codes; the admin lifecycle surface stays behind the edge's `/api/v1/`
  JWT gate; the frontend contract is untouched. The sweep's consequences
  (INACTIVE/ARCHIVED states) are visible only in the admin console — users
  have no self-service signal that they were wrong-deprovisioned (F1, F3).
- A8. **Config changes require restart** (reload covers feature gates only);
  sweep thresholds, `max_per_sweep`, and the new `lease_ttl`/`backend` knobs
  are boot-time values.

---

## 2. Readiness table

| Signal | Dependency | Failure behavior | Alert today | Runbook today |
|---|---|---|---|---|
| `/livez` | process | 200 while handler runs | `SSOInstanceDown` (critical) | RUNBOOK §1 |
| `/readyz` (aggregate, 3s bound; probes outside ratelimit) | named checks | 503 + per-check map; pod drained | none per-check | k8s-prod README: "verify /readyz covers Redis, Postgres, etcd..." |
| `/readyz: sqlite-identity-*`, `audit-*`, etc. | store Pings | drains replica | none per-check | none |
| **lifecycle durable store (NEW)** | PG pool / SQLite DSN | store outage → admin lifecycle 500s, sweep page errors, Touch write errors (fail-open) | **none — no ready check registered** (F4) | **none** |
| **sweep loop (NEW mechanics)** | lease + cursor over durable store | lost lease → `(0, nil)` silent skip; page error → loop logs; cursor starvation (qa F2) | **none — no metric, no alert** (F2) | **none** |
| **login Touch (NEW)** | durable store upsert, fail-open | write errors logged; signal freezes; mass dormancy after `DormantAfter` (F3) | **none** (F3) | **none** |
| admin lifecycle endpoints | lifecycle store (memory today = cannot fail) | store error → 500; `ErrStateConflict` → 409 | `SSOHighHTTPErrorRate` (only if admin 5xx > 5% of all traffic) | none |
| audit async pipeline | audit sinks | queue_full drops — including sweep transition evidence | `SSOAuditEventsDropped` (critical), `SSOAuditQueueSaturated` | dashboard note |
| `/readyz: dr` | DR readiness (opt-in gate) | report-only by default | `sso_dr_readiness` gauge | RUNBOOK §5 |
| edge `/api/v1/` | OpenResty JWT gate | unchanged — admin lifecycle behind it | none (edge has no alerting) | none |

---

## 3. Findings

### F1 [High] — Standalone WebAuthn ceremony bypasses both Touch anchors; passkey-only users age into dormancy on stale signal

- **Evidence**: `webauthnFinishLoginHandler` (`serverwebauthn/webauthn_handlers.go:120-158`) and the conditional twin (`:250-300`) authenticate via `deps.Helper.FinishLogin` and mint tokens via `applyWebAuthnTokenIssuance` — neither calls `authenticateUser` (the design's first anchor, `server_login_auth.go:98`) nor `finalizeCallbackSession` (`server_oauth.go:223`). Both routes are stock-mounted whenever WebAuthn is enabled (`build_http.go:263-295`). The design's "ceremonies are covered transitively" claim holds only for the MFA-factor replay (`server_mfa.go` funnels through `finishLogin`; the primary login already Touched) and for `provider=webauthn` at `/auth/login`. The standalone/conditional ceremonies are today's stock code, not future risk. Sibling reviews (qa-lead F6, database-review F-DB-1) verified the same at this revision.
- **Production impact**: a deployment whose users sign in with passkeys (browser autofill / conditional UI, or a dedicated `/webauthn/login/finish` flow) writes no last-active for those users. Their signal ages on the durable table; after `DormantAfter` the sweep marks active users INACTIVE, and — with `archive_after` configured — ARCHIVED later. Lifecycle state does not gate auth today (config-reference: "GOVERNANCE metadata only"), so the user keeps logging in — but the governance state, admin console, and any wired `LifecycleEventBus` reactions (direction-1 work makes this an auth gate) are corrupted silently. From an operator's seat: no metric, no alert, no self-service signal to the user (A7).
- **Remediation**: (a) name the standalone `webauthnFinishLoginHandler` + conditional handler as a third Touch anchor in the design and wire `touchUserActivity` there after successful assertion+token issuance; or (b) explicitly scope them out with rationale and a runbook line. Add the qa-lead acceptance: after a ceremony login, `LastActive(userID)` == login time (SDK-level test with a recording `ActivityRecorder` stub).
- **Recovery validation**: E2E/SDK test driving the ceremony-mint path with a recording stub; assert the signal advances; then run one sweep with `DormantAfter` set below the ceremony gap and assert no transition for the ceremony user.

### F2 [High] — Zero lifecycle telemetry: the sweep becomes production behavior with no metric, no alert, and no backlog measurement

- **Evidence**: `platform/metrics/consts.go` (full read) has no lifecycle metric; `docs/observability.md` no lifecycle row; `alerts.yaml` (11 rules) none reference lifecycle; `domains/userlifecycle` contains no prometheus references; `RecordTransition` (sweep.go:148-178) bumps nothing; `SweepOnce` errors are logged only (`options_admin.go:331-333`); per-user errors are `logError` only (sweep.go); the design's lost-lease path returns `(0, nil)` silently; `RunUserAutoDeprovision` logs nothing for a skipped tick. `MaxPerSweep` semantics change on the cursor path (scanned vs applied), and the design leaves the per-tick page loop unspecified (single page per tick with a cursor restart — qa-lead F2's starvation reading — versus drain-all-pages with an unbounded tick); either way, convergence time and pending backlog are unmeasurable. Under A2 (dormancy now actually fires), mass INACTIVE/ARCHIVED transitions, sweep stalls, lease loss, and cursor starvation are all invisible except as log floods. Neither `SSOHighLoginFailureRate` (lifecycle doesn't gate auth) nor `SSOHighHTTPErrorRate` (background loop, not HTTP) can catch any of it.
- **Production impact**: the design's own acceptance tests need a "call counter on the store" to observe the lease and O(k) claims — production has no equivalent. A stuck or starved sweep (qa-lead F2: no-op prefix ahead of actionable users) is undetectable; a mass transition spike is undetectable until an admin notices state changes in the console. This is the same blind-launch class the direction-1 review flagged (its F2/F5), and the prod design ships the mechanism without closing it.
- **Remediation** (bounded cardinality — no per-user labels):
  1. `sso_user_lifecycle_transitions_total{to_state}` (6-value label) in `RecordTransition` — one line, makes the sweep's own firing rate observable;
  2. `sso_user_lifecycle_sweep_errors_total{phase}` with phase ∈ {list, page, lease, user} — user-phase covers the existing per-user skip-and-log;
  3. `sso_user_lifecycle_activity_write_errors_total` (F3's alarm input);
  4. `sso_user_lifecycle_sweep_duration_seconds` (histogram) + `sso_user_lifecycle_pending_candidates` (gauge: stale rows behind the cursor) — makes the F2 starvation and the lease-TTL-vs-duration margin measurable;
  5. alerts: transitions-rate collapse (the `SSORiskScorerSilent` shape: logins continue but transitions stop → cursor/lease stuck) and an anomalous transition spike (wrong-deprovisioning storm).
- **Recovery validation**: drill D4 — with a fixed clock and the qa-lead F2 fixture (`s1,s2` SUSPENDED stale ahead of actionable `u`), assert the `pending_candidates` gauge stays flat and the transitions counter flat while `u` is never reached; after the fix, assert `u` transitions and the counter moves.

### F3 [High] — Fail-open Touch plus a frozen monotone signal converts an activity-write outage into silent mass wrong-deprovisioning

- **Evidence**: design §3: "Activity-write failure: logged, login proceeds"; "The signal simply ages; dormancy then evaluates against the last good value". `TouchAt` is monotone (`WHERE last_active < EXCLUDED.last_active`), so nothing refreshes a frozen value except a successful future login; `IsDormant` (dormancy.go:20-27) needs only `last_active < now - DormantAfter`. There is no signal-freshness guard anywhere in `SweepOnce`. `SessionLastActive` is replaced by the durable signal when the durable backend is selected (design §3), so the sweep's only input is the writable table. During a sustained DB outage (or a broken writer), every user's value freezes in lockstep; after `DormantAfter` the sweep mass-transitions ACTIVE→INACTIVE; with `archive_after` set, ARCHIVED after `DormantAfter+ArchiveAfter`. Compounding: INACTIVE has no login-path reactivation today (db-review F-DB-2 verified; admin-reversible only), and the user has no self-service visibility (A7).
- **Production impact**: the fail-open posture is correct for login availability but turns the sweep into a slow-motion wrong-deprovisioning machine with zero alarm: the failure is deliberately invisible on the request path, and the consequence is visible only in governance state. `max_per_sweep=0` (default) means one tick can convert the whole roster. If `LifecycleEventBus` reactions are ever wired (direction-1), this becomes fleet-wide access cutoff on stale data.
- **Remediation**:
  1. alert: `sso_user_lifecycle_activity_write_errors_total` > 0 for 5m (per F2);
  2. freshness guard: suppress transitions while Touch is failing — the module's own doctrine is "the sweep never advances an account on incomplete data" (sweep.go doc); a `lastSuccessfulTouch` timestamp per replica compared against `2x sweep_interval` while logins are flowing is a conservative, cheap guard, or track write-error rate at the recorder and have `SweepOnce` skip-and-log when it is non-zero;
  3. runbook: activity-write outage → disable `auto_deprovision` (restart) or raise `dormant_after` above the outage window before restoring.
- **Recovery validation**: inject a failing `ActivityRecorder` stub (qa-lead's fixture), assert the alert fires and zero transitions apply while it fails; restore, assert only genuinely-dormant users transition.

### F4 [High] — The durable store ships without the three surfaces every durable precedent registers: `/readyz` check, storage-health source, schema boot gate

- **Evidence**: `wireUserLifecycle` (build_stores.go:325-370) registers nothing; the identity-link precedent (`wireIdentityLink`, build_stores.go:372-427) registers `checkIdentityLinkSchema` (CheckSchema/MaxVersion boot gate for sqlite and postgres, `:403-424`), `AppendReadyCheck("identity-links", store)` (`:397`), and a storage-health source (`:398`, `:407`), with `Ping`/`DB()` on the durable store (`domains/identitylink/sqlite/store.go:81-84`). The design specifies no `Ping`, no ready check, no storage-health entry, and no schema gate. `ops/deploy/k8s-prod/README.md:24` requires `/readyz` to cover Postgres-backed dependencies.
- **Production impact**: (a) a lifecycle-store outage is invisible to `/readyz` — replicas stay in rotation while the admin lifecycle surface 500s and the sweep errors; (b) the admin storage-health report (`GET /api/v1/admin/storage-health`) omits the new dependency; (c) without the CheckSchema boot gate, a future-schema database silently runs under an older binary (db-review F-DB-5 agrees) — the identity-link gate exists precisely because "a schema mismatch corrupts data before any request is served" (serverbuildsign/build_readiness.go doc).
- **Remediation**: durable stores implement `Ping`; `wireUserLifecycle` appends `AppendReadyCheck(opts, "user-lifecycle", store)` + `AppendStorageHealthSource` and calls `checkUserLifecycleSchema` mirroring `checkIdentityLinkSchema` (both arms). All three are type-assertion-gated and no-op for memory builds — zero byte-difference for unwired builds.
- **Recovery validation**: drill D1 — stop the DB, assert `/readyz` trips with the named check and the storage-health report lists the source; restore, assert recovery; boot an old binary against a newer schema and assert the boot gate fails.

### F5 [Medium] — The lease is unobservable, its TTL default is unvalidated, and clock skew silently starves the fleet

- **Evidence**: design §2: lease TTL default = 2x `sweep_interval`; "A skewed acquirer may over-lease or under-lease; both outcomes are benign". Over-lease (a fast-clock replica stamps `expires_at` up to TTL+skew into the future) makes every other replica skip every tick for the skew window; the loser returns `(0, nil)` with no log (F2) and `RunUserAutoDeprovision` logs nothing for a skipped tick (options_admin.go:331-333). The design's own race acceptance requires a call counter — production has none. The dormancy cutoff (`now − last_active`) is the correctness-sensitive comparison and shares the same app clock (ds-review F-DS-2).
- **Production impact**: a single skewed replica halts all deprovisioning fleet-wide for the skew window — invisible, self-correcting only when the skew resolves or the lease expires; the same skew also shifts the dormancy cutoff per replica, so replicas disagree on eligibility. Both failure classes have no detection.
- **Remediation**: (a) counters: lease acquire success/lost/expired (bounded, no labels beyond outcome); (b) log at info when a tick skips on a lost lease (qa-lead F5); (c) derive `expires_at` from the DB clock (`SELECT now()` at acquire) so replica app-clock skew cannot over-lease — the lease then compares against one clock; (d) runbook: NTP discipline and a `sweep_duration_seconds` alert when duration approaches the TTL default.
- **Recovery validation**: two-replica drill D4 — one replica with a +10m clock; assert the other loses the lease, logs the skip, and resumes within TTL+skew of clock repair; assert the counters record exactly one acquirer.

### F6 [Medium] — Restore-time dormancy: any Postgres PITR/restore with an RPO gap > `DormantAfter` mass-deprovisions on the next tick

- **Evidence**: `last_active` is plain data in the restored database; `IsDormant` needs only `last_active < now − DormantAfter` (dormancy.go:20-27); the sweep has no other input. The design's failure-mode list covers runtime outage, TTL expiry, clock skew, cursor races, and orphan rows — not restore. The bare-metal runbook's restore procedure (RUNBOOK §4.1, Patroni PITR) restores the shared PG database that now holds the lifecycle tables.
- **Production impact**: after any restore to a point older than `DormantAfter`, every user who logged in after the restore point reads dormant; the next tick mass-transitions them (INACTIVE, then ARCHIVED when configured) — with zero telemetry (F2), the operator discovers it in the admin console or a wired-reaction side effect.
- **Remediation**: (a) runbook procedure: after a lifecycle-state restore, either raise `dormant_after` above the RPO gap, disable `auto_deprovision` until `last_active` catches up through re-login, or re-touch users from audit (`admin_user_lifecycle_changed`/login audit events are durable and can drive a replay script — the same tool direction-1 review D5 proposed for suspensions); (b) state the RPO consequence for lifecycle state explicitly in `docs/config-reference.md` (which backup covers which backend: PG via the operator's pg_dump/PITR; SQLite: none today — F8).
- **Recovery validation**: drill D5 — restore a test DB to a point older than `DormantAfter`, assert the first sweep mass-transitions without the runbook guard and does not with `auto_deprovision` disabled; document the guard's restore time.

### F7 [Medium] — Decision 3's writer is coupled to decision 2's config; disable→re-enable cycles freeze the signal and mass-dormant on re-enable

- **Evidence**: `WithUserAutoDeprovision` is the only seam that sets `s.userLifecycleActivity` (options_admin.go:296-301); `wireUserLifecycle` returns before wiring activity when `!deprovision.Enabled()` (build_stores.go:328-348); the design's `touchUserActivity` type-asserts that field. With the durable backend but `auto_deprovision.enabled: false`, no Touch fires and the table stays empty; enabling later starts from an all-unknown signal (fail-safe at first enablement — good). But a disable→enable cycle freezes values at disable time; on re-enable, every user whose logins happened during the gap reads dormant and the first tick mass-transitions them. `config/reload` does not cover `user_lifecycle` (A8), so the toggle is a restart event — and restarts are exactly when operators tune this feature.
- **Production impact**: operators who disable the sweep to stop transitions (the F3/F6 runbook action!) and re-enable after a gap convert the gap into mass dormancy. The F3 and F6 remediations both recommend toggling this feature — the coupling makes those remediations unsafe without a signal-freshness guard (F3's guard also fixes this: on re-enable, the frozen values are indistinguishable from "no recent Touch" and transitions are suppressed until logins refresh them).
- **Remediation**: (a) wire the recorder independently of the sweep: when the durable backend is selected and the store implements `ActivityRecorder`, register Touch at `WithUserLifecycle` time (the store is already passed as `LastActiveSource` in the design's wiring — pass it as the recorder unconditionally); (b) boot log naming the recorder state ("user lifecycle: last-active recording active/inactive — durable/session-derived"); (c) the F3 freshness guard covers the re-enable case.
- **Recovery validation**: drill D3 variant — enable durable + sweep, let Touch run, disable (restart), simulate logins during the gap, re-enable, assert no mass transition when the freshness guard is present and a mass transition without it.

### F8 [Medium] — Unbounded tables and a backup gap: last-active grows O(users) forever, history grows per transition, and the SQLite backend has no backup path

- **Evidence**: design §1/§3: "History growth is unbounded... flagged as a future retention knob"; "Orphan rows: deleted users' last-active rows persist (no cascade)"; the table is keyed per user and rows are never pruned (deletion cleanup is a documented non-goal). Retention precedents exist (`audit.retention.*` → `platform/audit/sqlite.Sink.Prune`, `snapshot.retention.*` → `PruneOldest`, `push_approvals` → `PruneExpired`) — none lifecycle. Backup: `POST /api/v1/admin/backup` (`VACUUM INTO`) covers only registered `core.BackupSource` (interfaces/sso/server_backup.go:76-89); the design's dedicated lifecycle SQLite DSN registers none (identity-link precedent registers none either); lifecycle state is not in the DR snapshot subset (dr-framework §1; verified). Postgres rides the operator's PG backup.
- **Production impact**: (a) in the shared PG database, one row per ever-logged-in user + one history row per transition, forever — measurable storage growth with no retention knob; (b) SQLite lifecycle backend has zero backup: file loss resets all states to ACTIVE and empties the signal (fail-safe for deprovisioning — empty signal = unknown = no-op — but governance state and history are gone, and admin re-application from audit is the only recovery); (c) restore-time dormancy (F6) applies to whatever backup does exist.
- **Remediation**: (a) state the RPO per backend in `docs/config-reference.md` (PG: operator's backup cadence; SQLite: none — single-host-only warning, matching identity-link's posture); (b) decide retention for history (bounded per-user ring or prune older than a retention window) and last-active cleanup (cascade on user deletion or a sweep-side tombstone) — at minimum, surface table sizes via the storage-health report and measure growth before release; (c) optionally register the lifecycle SQLite store as a `BackupSource` so the admin backup endpoint covers it.
- **Recovery validation**: drill D5 — delete the lifecycle SQLite file, assert boot recreates an empty store (states reset, sweep no-ops on empty signal), and the runbook's re-apply-from-audit procedure restores the suspended set.

### F9 [Low] — A mass sweep tick is an audit-storm source: `max_per_sweep=0` (default) can emit thousands of `admin_user_lifecycle_changed` events through the async sink in one tick

- **Evidence**: `RecordTransition` emits one event per applied transition (sweep.go:148-178); `max_per_sweep` defaults to 0 = unlimited (config-reference:705); the async sink has a bounded queue with drop alerts (`SSOAuditEventsDropped` / `SSOAuditQueueSaturated`). With a working durable signal (A2), a first mass sweep or a wrong-deprovisioning event (F1/F3/F6) emits one event per user per tick.
- **Production impact**: the audit queue saturates exactly when the transitions that matter most happen — dropping the evidence of the sweep (the `SSOAuditEventsDropped` alert fires, which is at least a signal, but it points at audit capacity, not at the sweep).
- **Remediation**: recommend a non-zero `max_per_sweep` for production (direction-1 F5 said the same); runbook line: audit queue saturation coinciding with a transition spike = sweep tick; correlate with `sso_user_lifecycle_transitions_total` (F2).
- **Recovery validation**: none needed beyond the F2 fixtures; assert in the sweep acceptance that a capped run emits ≤ `max_per_sweep` events.

### F10 [Info] — `haCoherenceIssues` still lacks a `user_lifecycle` entry; the default memory backend remains per-process and divergent in declared multi-replica topologies

- **Evidence**: `haCoherenceIssues` (build_stores.go:95-131) lists identity_link (`:113`) but not `user_lifecycle`; the design keeps `BuildUserLifecycle` memory when `backend: ""|memory` — the default. Direction-1 review F1 flagged the same gap for the enforcement path.
- **Production impact**: with the durable backend, multi-replica lifecycle state converges (the design's whole point) — but the memory default in a declared multi-replica topology still diverges silently, and nothing at boot says so. The durable backend should be the documented production posture for `user_lifecycle` the moment it ships, exactly as the design's own text implies ("durable source becomes the default when SQL is wired").
- **Remediation**: add `{multi && b.cfg.UserLifecycle.Enabled, "user_lifecycle.backend", b.cfg.UserLifecycle.Backend}` to `haCoherenceIssues` (one line, identity-link-shaped), so a declared multi-replica topology with the memory backend fails boot or logs the loud HA-INCOHERENCE error; document "memory = single-replica only" in config-reference.
- **Recovery validation**: boot a declared multi-replica config with `backend: memory`, assert the coherence error; switch to `backend: postgres`, assert clean boot.

### F11 [Info] — Zero alert-to-runbook coverage for any lifecycle failure class

- **Evidence**: `alerts.yaml` (11 rules) has no lifecycle rule; `ops/deploy/baremetal-ha/RUNBOOK.md` (451 lines) has zero lifecycle/deprovision content; the storage-health report (F4) will list the store only after F4's remediation.
- **Production impact**: an on-call engineer facing any failure in this design (mass transitions, stuck sweep, lease loss, Touch outage, restore dormancy) has no runbook path and no alert naming the subsystem; the only existing alert that can fire (`SSOAuditEventsDropped`, F9) points at the wrong component.
- **Remediation**: a lifecycle subsection in the runbook covering: mass-transition diagnosis (transition counter vs. activity-write errors vs. restore events), lease/starved-sweep checks, the disable/re-enable coupling (F7), restore-time dormancy guard (F6), and the WebAuthn blind spot (F1); plus the F2/F3 alert set.
- **Recovery validation**: tabletop the five drills in §4 against the new subsection.

---

## 4. Failure drills

Each drill: trigger → expected behavior → detection → recovery → validation gate.

### D1 — Outage: lifecycle store unreachable (durable builds)

- Trigger: the shared PG pool (or lifecycle SQLite DSN) loses reachability mid-flight; or boot with the backend unreachable.
- Expected: boot fails loud (migration/connect error propagates — design §1, identity-link precedent) → orchestrator crash-loops until the DB returns; runtime outage: admin lifecycle endpoints 500, sweep pages error (`SweepOnce` error logged), Touch writes fail fail-open (logins succeed).
- Detection: **fails today** — no `/readyz` check, no storage-health entry (F4); the only signals are admin-500 rate (likely below `SSOHighHTTPErrorRate`'s 5%-of-all-traffic threshold) and log lines.
- Recovery: restore the backend; replicas recover on the next request/tick (no cache). A boot-time outage self-heals when the DB returns (crash-loop restart). Sweep resumes on the next tick; the lease row (if any) expires via TTL.
- Validation (with F4): `/readyz` trips with the named check; storage-health lists the source; restore → ready within one probe interval; a boot with an unreachable backend fails with the store name in the error.

### D2 — Saturation: login storm × Touch upsert on the shared Postgres pool

- Trigger: credential-stuffing or a legitimate peak while the durable backend is enabled; Touch adds one conditional upsert per successful login, in the request path, before session creation.
- Expected: login latency rises by the upsert RTT (unmeasured today — A6); a slow pool also slows identity/oauth/audit stores that share it; Touch errors fail open (F3).
- Detection: `SSOLatencyP95High` (existing) catches the aggregate; nothing isolates the lifecycle contribution (no `sso_user_lifecycle_activity_write_errors_total`, no Touch latency histogram — F2).
- Recovery: scale the pool; or disable `auto_deprovision` (restart) to stop Touch — but note F7: re-enabling later from frozen values mass-dormants without the freshness guard.
- Validation: benchmark login p95 with the durable backend on and off (record the delta — the A6 measurement decision); assert logins succeed while the injected writer fails (fail-open acceptance) and the F3 alert fires.

### D3 — Bad rollout: mixed-version fleet, schema drift, and the disable/re-enable trap

- Trigger: (a) rolling deploy where the new binary runs lifecycle migrations against a shared PG while old binaries still serve; (b) rollback of a binary that created a newer schema; (c) operator disables `auto_deprovision` during an incident and re-enables after the gap.
- Expected: (a) migrations are idempotent forward-only with an advisory lock (design §1) — old binaries simply don't touch the new tables (additive); (b) without the CheckSchema boot gate (F4), the older binary runs against a newer schema silently — the exact corruption class the identity-link gate prevents; (c) the signal froze during the gap; the first tick after re-enable mass-transitions users who logged in during the gap (F7).
- Detection: (b) nothing; (c) nothing (F2) — the transition spike is invisible.
- Recovery: (b) gate the boot (F4) so the rollback fails loud instead of running; (c) the F3 freshness guard, or a documented re-enable procedure (raise `dormant_after` for one window).
- Validation: schema-gate test in the conformance suite (migration test asserting the composite index + version table); a re-enable drill asserting no mass transition with the guard.

### D4 — Stale state: starved cursor, stuck lease, and WebAuthn-blind users

- Trigger: (a) the qa-lead F2 fixture — stale SUSPENDED/INACTIVE rows occupy every page ahead of actionable ACTIVE users (`MaxPerSweep` page, cursor restarts each tick); (b) a clock-skewed replica over-leases and starves the fleet (F5); (c) passkey-only users never Touch (F1).
- Expected: (a) the sweep reprocesses no-op rows every tick and never reaches actionable users — with `MaxPerSweep=0` the "sane default" page size makes convergence proportional to the stale set; (b) all replicas but the skewed one skip every tick; (c) active WebAuthn users age into dormancy.
- Detection: **fails today** — no transitions counter, no pending-candidates gauge, no lease counters (F2/F5); the first observable symptom is the admin console's state column.
- Recovery: (a) fix the cursor (skip-advance past non-actionable states or SQL-side state filter — qa-lead F2's fix) or raise `MaxPerSweep`; (b) fix the clock; (c) third Touch anchor (F1).
- Validation: the qa-lead acceptance (user `u` becomes INACTIVE despite the no-op prefix); the two-replica lease race test asserting exactly one acquirer and the loser's log line; the ceremony Touch acceptance (F1).

### D5 — Restore: PG PITR, SQLite file loss, DR cutover

- Trigger: (a) Patroni PITR restore to a point older than `DormantAfter` (F6); (b) lifecycle SQLite file deleted/corrupted (F8); (c) DR cutover to a fresh cluster with restored control-plane state (lifecycle tables are NOT in the snapshot subset — they come from the backend's own restore).
- Expected: (a) every user who logged in after the restore point reads dormant → mass INACTIVE/ARCHIVED on the next tick; (b) states reset to ACTIVE, signal empty → sweep no-ops (fail-safe), governance state + history gone; (c) same as (a) via the backend restore, with the sweep's `last_active` all older than `DormantAfter`.
- Detection: (a/c) nothing (F2); (b) nothing at boot (no boot log naming lifecycle-state loss).
- Recovery: (a/c) the F6 runbook guard (raise `dormant_after` / disable the sweep until re-login / replay Touch from audit); (b) re-apply state from the audit trail (direction-1 D5's replay script shape).
- Validation: a restore drill in `test/` (package `ssotest`): restore an older DB snapshot, assert the first sweep's transition count with and without the guard; document the measured restore-to-safe time against the A6 decision.

---

## 5. Launch blockers, rollback triggers, monitoring gaps, residual risks

### Launch blockers (must land with the design, before any durable backend merges)

1. **F2 metric set + alerts** — the design makes the sweep fire for the first time; it must ship with `sso_user_lifecycle_transitions_total{to_state}`, the sweep/lease/activity-error counters, and the transition-spike/transition-collapse alerts. Without these, mass wrong-deprovisioning (F1/F3/F6) is undetectable.
2. **F4 readiness/schema surfaces** — `Ping` on the durable stores, `AppendReadyCheck` + storage-health registration, and the CheckSchema/MaxVersion boot gate (identity-link shape). The design adds a production dependency without the three surfaces every durable precedent registers; k8s-prod's `/readyz` promise requires it.
3. **F1 third Touch anchor or explicit scope-out** — the standalone/conditional WebAuthn ceremonies are stock code today; the design's "transitive coverage" claim is false for them and must be corrected in the design text, with the qa-lead acceptance.
4. **F3 signal-freshness guard** (or explicit documented acceptance of mass-dormancy-on-outage) — the fail-open writer without a sweep-side guard converts any activity-write outage into silent mass transitions; the F6/F7 remediations depend on it.
5. **F7 wiring decoupling or documented coupling** — the disable/re-enable trap must be either fixed (recorder wired at `WithUserLifecycle` when the durable store implements `ActivityRecorder`) or documented with the re-enable procedure.
6. **F5 lease observability** — acquire/lost counters and the lost-lease log line (also the design's own race acceptance needs the counter to assert anything in production).
7. The design's own acceptance tests (conformance suite on memory + SQLite, two-holder race, O(k) with the no-op prefix, Touch monotonicity incl. empty-ID/zero-time guards — qa-lead F1/F2/F4) and the contract updates (`docs/config-reference.md` backend naming + caveat removal, in the same change as the wiring).

### Rollback triggers (stop-the-roll criteria)

- `sso_user_lifecycle_transitions_total` spikes while `sso_user_lifecycle_activity_write_errors_total` > 0 (wrong-deprovisioning storm from a frozen signal — F3).
- Transition counter collapses while logins continue (starved/stuck sweep — F2/F5).
- `/readyz` trips on the lifecycle check (F4) or boot fails on the schema gate (mixed-version fleet — D3).
- Post-restore first sweep mass-transitions (F6) — the F6 runbook guard is the immediate action, then roll back the config (raise `dormant_after` / disable the sweep) rather than the binary.
- Rollback mechanics (verified safe): old binaries are byte-identical pre-feature for memory builds; durable builds must never roll back a binary that wrote a newer lifecycle schema without the F4 boot gate in place — that is exactly what the gate exists to prevent.

### Monitoring gaps (post-launch backlog)

- No lifecycle metric of any kind (F2): transitions, sweep errors by phase, lease outcomes, activity-write errors, sweep duration, pending-candidate backlog.
- No `/readyz` check, storage-health entry, or schema boot gate for the durable store (F4).
- No Touch latency contribution to the login p95 budget (A6) and no availability SLO for the lifecycle store as a dependency of the admin surface.
- No per-replica lease-state or sweep-eligibility signal (F5); no clock-skew detection for the app clock the lease and dormancy cutoff share.
- No runbook or alert content for any lifecycle failure class (F11); no backup/RPO statement per backend (F8).

### Residual risks

1. **WebAuthn-blind users** (F1) — accepted only with the third anchor or an explicit scope-out naming the window; until anchored, passkey-only users age into dormancy on stale signal.
2. **Mass wrong-deprovisioning on signal freeze** (F3) — the fail-open writer is the right call for login availability; the sweep-side guard (or documented acceptance) must accompany it. Until then, the F6/F7 remediations (which toggle the feature) are themselves unsafe.
3. **Restore-time dormancy** (F6) — any PG restore with RPO gap > `DormantAfter` triggers mass transitions; runbook-guarded only.
4. **Cursor starvation** (qa-lead F2) — the design's keyset cursor can stall behind no-op rows in the default configuration (`ArchiveAfter=0`, SUSPENDED/orphan rows ahead of actionable users); undetectable without the F2 backlog gauge.
5. **Lease clock-skew starve** (F5) — one skewed replica halts deprovisioning fleet-wide, silently; DB-clock `expires_at` and the lost-lease log are the mitigations.
6. **Disable/re-enable coupling** (F7) — toggling the feature to stop transitions freezes the signal; re-enable mass-dormants without the freshness guard.
7. **No SLO and no latency budget** (A6) — the hot-path write and the admin dependency have no measured availability target; the fail-open posture is an availability decision the operator must make explicitly (direction-1 F8 remains open; this design adds a write to it).
8. **Governance-state backup gap** (F8) — SQLite lifecycle backend has no backup; memory is per-process; only PG rides an existing backup. Lifecycle state loss is fail-safe for deprovisioning but silently resets governance state.

### Bottom line

The design's mechanics verify clean against the tree: the durable-backend seams (builder signature, identity-link precedent, advisory-locked migrations), the login anchors, the shutdown lifecycle for the sweep loop, and the byte-identical fallback paths all hold; the external frontend/proxy boundary is untouched. The operational problem is that **the design converts the lifecycle module from an inert, memory-only, effectively-never-firing feature into a real production mechanism — a new durable dependency on the admin surface and login path, a destructive background transitioner, and a cross-replica coordination primitive — without adding any of the surfaces that would let an operator detect, withstand, or recover from its failures**: zero metrics, zero alerts, no readiness/storage-health/schema gates, no backup or restore story, and a fail-open writer whose failure mode is silent mass wrong-deprovisioning. Every blocker is detection/documentation surface plus three type-assertion-gated registrations that are byte-identical for memory builds (F4), a bounded metric set (F2), and one anchor fix or scope-out (F1) — none changes the design's seam logic or budgets. The conformance suite must pin the two-holder lease race and the Touch failure-injection before any durable backend merges; the metric/alert/runbook surface must ship in the same change, not after.
