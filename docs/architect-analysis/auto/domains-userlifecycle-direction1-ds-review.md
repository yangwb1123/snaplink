# Distributed-Systems Engineering Review: `domains/userlifecycle` direction 1 — lifecycle state as an auth gate + transition-time revocation

Review of `docs/auto/domains-userlifecycle-direction1-design.md` (454 lines)
from the distributed-systems standpoint: consistency, ordering, atomicity,
idempotency, ownership, conflict resolution, replication, partition/crash/
retry/clock behavior, and the documented fail-open/fail-closed boundary.
Advisory only; no files changed.

## 0. Method and verification

All claims below were verified by source inspection at this revision (no
`make ci` run — this review changes no code; the mandatory `.go` gates are
unaffected). Evidence labels: **Verified** = read in the tree at this
revision; **Partial** = confirmed but with a caveat; **Proposed** = design
intent not yet in code; **Unknown** = no evidence found.

Distributed-relevant claims checked:

| Claim | Status | Evidence |
|---|---|---|
| Refresh gate inserts after `Consume`, before rotation side effects | **Verified** | `internal/handler/tokengrant/token_refresh.go` — `store.Consume` (~line 55), `refreshBindGuard`, `refreshEnforceAbsoluteMaxLifetime`, `refreshCheckSessionLiveness` (~93), then `refreshResolveGrant` (~96), depth policy, `refreshVelocityGate` (calls `RecordRotation`), `refreshIssueAndRotate` |
| `RefreshGrantDeps` compile guard exists | **Verified** | `interfaces/sso/accessors_handlers.go:363` `var _ tokengrant.RefreshGrantDeps = (*Server)(nil)` |
| `LifecycleStore()` accessor at `options_admin.go:305`; `WithUserLifecycle` doc claims "NEVER gates authentication" (drift to fix) | **Verified** | `interfaces/sso/options_admin.go:277,305` |
| `docs/config-reference.md` §User Lifecycle says "GOVERNANCE metadata only — it NEVER gates authentication" (drift to fix) | **Verified** | `docs/config-reference.md:695` |
| `docs/error-codes.md` documents `account_locked` as 423; code writes 403 | **Verified** | `docs/error-codes.md:139` vs `interfaces/sso/server_login_auth.go:101,156` (`http.StatusForbidden`) |
| Four `rejectDeactivatedUser` sites + inline SCIM check at `server_oauth.go:221` | **Verified** | `server_login_auth.go:98`, `server_mfa.go:359`, `server_mfa_trust.go:256`, `server_oauth.go:221–227` |
| Admin transition: `Append` commits BEFORE `RecordTransition` (bus trigger) and before the 200 | **Verified** | `interfaces/admin/lifecycle.go:77–92` `applyLifecycleTransition` |
| The bus dispatches reactions with the ctx passed to `Recorder.Record` — i.e. the admin request ctx on the admin path | **Verified** | `interfaces/admin/lifecycle.go:89` (`ctx.Request().Context()`), `platform/audit/recorder.go` `Record` → sink, `domains/userlifecycle/bus.go` `Record` → `invoke(ctx, ...)` |
| `audit.enabled: false` → recorder nil → bus never observes transitions | **Verified** | `cmd/sso-server/build_app_core.go:198–201` (`wireAudit` early-returns before `b.recorder` is set) |
| `AddSink` wraps whatever sink exists at call time; bus stays synchronous even with `audit.async` | **Verified** | `platform/audit/recorder.go:131` (`r.sink = NewMultiSink(r.sink, extra)`); wiring order: `wireAudit` (build_app_core.go:221) before `wireUserLifecycle` (build_app_security.go:240) |
| Lifecycle store is per-process memory only | **Verified** | `cmd/sso-server/serverbuildplatform/build_userlifecycle.go:18–23` → `userlifecyclememory.New()`; `domains/userlifecycle/memory/memory.go` (map + mutex; "State is lost on restart") |
| Sessions/refresh tokens can be fleet-shared (redis/postgres/sqlite) | **Verified** | `cmd/sso-server/serverbuildstore/build_identity_stores.go:267–304` (`BuildSessionManager` switch; redis is the documented HA choice); refresh stores: `infrastructure/redis/refresh_token.go`, `infrastructure/defaultimpl/sqlite/refresh_tokens.go` |
| `DeleteAllForSubject` atomicity differs by backend | **Verified** | memory: single lock (`memory_refresh_token.go:308–333`); sqlite: TWO non-transactional `ExecContext` (families ledger, then tokens) (`sqlite/refresh_tokens.go:242–267`); redis: per-key DELs + SCAN-all-masters (`redis/refresh_token.go:313+`) |
| Reaction legs (`revokeRefreshTokens` / `destroySessions`) are idempotent, best-effort-across-stores | **Verified** | `protocols/lifecyclereactions/revoke_on_archive.go:24–89` |
| Cross-replica invalidation bus exists, is at-most-once (etcd watch), self-heals with subscribe→reseed→ready ordering; kinds include `KindTenantSuspension`, `KindSessionSuspended`, `KindTokenRevoked` | **Verified** | `platform/cluster/bus.go`; `platform/cluster/etcd/etcd.go:141`; `interfaces/sso/server_invalidation.go` (degraded/resubscribe/reseed); `interfaces/sso/server_login.go:465` publishes `KindTenantSuspension` |
| The D3 reaction publishes NOTHING on the cluster bus | **Verified** | `protocols/lifecyclereactions/revoke_on_archive.go` (no `cluster` import); design Decision 3 wires only `b.recorder.AddSink(bus)` |
| Re-presented consumed token → `ErrRefreshTokenReused` → whole-family kill | **Verified** | `infrastructure/defaultimpl/memorystoreoauth/memory_refresh_token.go:161–188`; `token_refresh.go` `refreshHandleConsumeError` → `DeleteFamily` |
| Grace cache `Remember` happens only on the success tail | **Verified** | `token_refresh.go` `refreshIssueAndRotate` (grace write after issue, before 200) |
| Device-context block in `server_login_auth.go` is 73 lines (268–340), the D1 pre-move | **Verified** | `wc -l` + read of `server_login_auth.go:260–345`; file is 493 lines; `server_login_resolve.go` 413, `token_refresh.go` 431 |
| `userlifecycle_wiring_test.go` asserts `len(b.opts)` ∈ {0,1,2} | **Verified** | `cmd/sso-server/userlifecycle_wiring_test.go:65,83,121` |
| `OnUserSuspended` has zero production callers today | **Verified** | grep: only `bus.go` + `bus_test.go:70` |
| `AuthCodeStore` has no per-subject delete SPI | **Verified** | `protocols/oauth/oauthspi/auth_code.go:114–125` (Issue/Consume only) |
| `context.WithoutCancel` is an in-repo precedent | **Verified** | `interfaces/sso/server_backchannel_logout.go:171,217`; `domains/authenticators/codestore.go:147`; go.mod `go 1.26.1` |

## 1. State map

Owner / store / durability / consistency / replication / failover, for every
piece of state the design reads or writes.

| State | Owner (writer) | Store | Durability | Consistency | Replication | Failover |
|---|---|---|---|---|---|---|
| Lifecycle record (`State` + append-only `History`) | Admin transition handler (`interfaces/admin/lifecycle.go`), dormancy sweep (`sweep.go`); gates read | `domains/userlifecycle/memory.Store` — in-process map + RWMutex | **None** — lost on restart (memory.go: "State is lost on restart") | Strong within one process: `Append` is CAS-like (From-match, `ErrStateConflict` on lost update, memory.go:44–66); NO cross-process ordering | **None** — one record per process; replicas diverge | None — a failed replica loses its view; no quorum/leader exists because nothing is coordinated |
| Live sessions | `core.SessionManager` (login path); D3 reaction destroys | memory \| sqlite \| redis \| postgres (`BuildSessionManager` switch) | memory: none; sqlite/postgres: durable; redis: per-policy | Per backend. D3 reaction is a read-list-then-delete LOOP (`ListByUser` then per-session `Destroy`) — NOT atomic; a session created between list and last destroy escapes | Redis cluster / PG replicas (async, per backend) | Per backend (redis cluster failover etc.) |
| Refresh tokens + family markers | `oauth.RefreshTokenStore` (issue/rotate); D3 reaction deletes | memory \| sqlite \| postgres \| redis | Per backend | Single-use `Consume` is atomic per key; `DeleteAllForSubject` atomicity varies (memory: one lock; sqlite: two non-transactional statements; redis: per-key DELs, no cross-key atomicity) | Per backend | Per backend |
| Auth codes (residual gap, design 6.6) | `oauth.AuthCodeStore` (`Issue`/`Consume` only) | per backend | per backend | Single-use atomic consume (AGENTS.md: DELETE RETURNING) | per backend | per backend |
| Login transactions / MFA challenges (the D1 gate's second-leg windows) | `interfaces/sso` login/MFA handlers | per backend (memory/redis) | per backend | Single-use consume; challenge TTL | per backend | per backend |
| Audit events (`admin_user_lifecycle_changed` — the D3 bus trigger) | `audit.Recorder.Record` from `RecordTransition` | primary sink (memory \| sqlite \| postgres) + in-process `LifecycleEventBus` (write-only tap) | per primary backend; `audit.async` may drop by contract | Bus sees the LIVE call only — no replay from the durable sink; at-most-once per process lifetime | none (per-process recorder) | none — a crash between `Append` and `RecordTransition` (or inside the sink fan-out) loses the reaction permanently (F-3) |
| Access-token revocation deny-sets | `/token/revoke` + cross-replica `KindTokenRevoked` | per-issuer in-process `revoked` map, seeded from durable `RevocationStore` | in-process; durable backing store | additive/idempotent; reseeded on bus recovery (`resubscribeAndReseed`) | via cluster bus | reseed on recovery |
| Cluster invalidation bus (etcd) | admin mutations publish; peers consume | etcd (lease + prefix watch) | etcd | at-most-once delivery; self-healing subscribe→reseed→ready | etcd cluster | degraded flag → /readyz red until resubscribe + reseed succeed |

**Ownership rule the design preserves**: the lifecycle store is written only
by the admin handler and the sweep; the gates are strict readers; the
reactions are strict writers on OTHER stores. No new store, no new write
path on the hot path. The one new ownership nuance: the sweep becomes a
*de facto* destructive writer (revocation) for the first time (F-6).

## 2. Findings

### F-1 — High — the synchronous reaction runs under the admin request context; "the admin response implies revocation completed" is not actually guaranteed, and the retry path is a 409 trap

**Evidence (Verified).** `applyLifecycleTransition` (`interfaces/admin/lifecycle.go:77–92`) commits `Append` first, then calls `RecordTransition(ctx.Request().Context(), ...)`; `Recorder.Record` forwards that ctx to the sink; the bus dispatches sync reactions with it (`domains/userlifecycle/bus.go` `Record` → `invoke(ctx, ...)`). The reaction is multi-RTT work — `clients.List` + per-client `DeleteAllForSubject` + `ListByUser` + per-session `Destroy` (`revoke_on_archive.go:24–89`) — on possibly remote stores (redis/postgres). `Recorder.Record` has no timeout or retry.

**Triggering failure.** Admin client disconnects, an admin-gateway/proxy timeout fires, or the admin HTTP server's write timeout elapses while the reaction is mid-flight. The request ctx cancels; `Destroy`/`DeleteAllForSubject` fail; the bus logs via `ReactionErrorFunc`; `applyLifecycleTransition` still returns (the transition already committed). The 200 is never written (or the gateway converts it to 502/504).

**User impact.** State is SUSPENDED but revocation is incomplete — the suspended user keeps sessions/refresh tokens until TTL. The operator cannot distinguish "revocation done, response lost" from "revocation failed" by re-reading state (the record says SUSPENDED either way), and the natural retry (POST the same transition) returns `409 lifecycle_state_conflict` — `SUSPENDED → SUSPENDED` is illegal (`transitions.go` `legalTransitions`). Recovery is a round-trip `SUSPENDED → ACTIVE → SUSPENDED`, which also fires `OnUserActivated` spuriously. The design's Decision 3.2 headline property is therefore only true when the client keeps the connection alive for the whole revocation.

**Recovery.** Manual double transition (as above), or wait for token TTL expiry. No automatic retry exists (the bus is at-most-once per process lifetime).

**Corrective pattern.** Detach the reaction's context from the request: `context.WithoutCancel(reqCtx)` (in-repo precedent: `server_backchannel_logout.go:171`, `codestore.go:147`), optionally with a bounded `WithTimeout` — the bus keeps dispatching synchronously on the admin goroutine (preserving "200 is written only after the reaction returned") while a client disconnect can no longer cancel revocation mid-flight. This is a small, contained change to either `LifecycleEventBus.Record`/`invoke` (detach there — it also fixes the sweep path and any future `On` user) or to `RecordTransition`. Alternatively register the reaction via `OnAsync` (bus-owned ctx, already correct) and give up the "200 implies done" property — worse for the stated contract. Also: document the 409 recovery path in `docs/error-codes.md`'s lifecycle section.

### F-2 — High — per-process lifecycle state meets fleet-wide revocation and re-admission; Decision 4's "reactions revoke per-replica credentials" is false for shared stores, and a stale replica (or a restart) voids the suspension

**Evidence (Verified).** Lifecycle store is per-process memory (`build_userlifecycle.go:18–23`); sessions and refresh tokens are routinely fleet-shared (`BuildSessionManager` — redis is the documented HA choice; refresh stores redis/postgres/sqlite). The reaction operates on the SHARED stores, so its revocation is fleet-wide when they are shared and local-only when they are memory. The gate reads only the per-process record. The design's Decision 4 ("the reactions revoke per-replica credentials — the same divergence…") is accurate only for the memory-backend topology.

**Triggering failure.** Replicas A and B, shared redis sessions/refresh tokens. Admin suspends via A: A's record flips to SUSPENDED and A's reaction destroys sessions + refresh families fleet-wide (shared store). B never saw the transition (no cluster event — the reaction publishes nothing; contrast `server_login.go:465` publishing `KindTenantSuspension`): B's gate reads no-record → ACTIVE → the user logs in via B, minting a fresh session and refresh family in the shared store, and B's refresh gate allows rotation indefinitely. The suspension is voided until someone re-applies it on every replica. Same story after a replica restart: the memory record evaporates, so the restarted replica re-admits the user even though the revocation side effects (shared stores) persist.

**User impact.** A "SUSPENDED ⇒ access revoked" guarantee that holds only on the replica that served the transition — the security invariant the whole design exists to provide is deployment-topology-dependent, silently.

**Recovery.** Re-apply the transition on every replica (no convergence mechanism exists); direction 3's SQL peer + cross-replica invalidation is the real fix.

**Corrective pattern.** At minimum: (a) correct Decision 4's wording in the design and state single-replica semantics in `docs/config-reference.md` §User Lifecycle ("with the memory lifecycle store, enforcement is per-replica; a replica that has not observed the transition, or has restarted, treats the user as ACTIVE"); (b) have the reaction publish a cluster event — `KindSessionSuspended` with the subject key already exists for exactly this shape (`platform/cluster/bus.go:123–140`) — so peers converge caches now and the seam is ready for direction 3; (c) treat "restart = un-suspension" as a first-class documented consequence of the memory backend, not an aside.

### F-3 — Medium — crash between `Append` commit and bus dispatch loses the reaction with no replay; the durable audit event (when one exists) never re-feeds the bus

**Evidence (Verified).** Ordering: `Append` → `RecordTransition` → 200 (`lifecycle.go:77–92`). A crash/panic between `Append` and the bus's `Record` (or inside `MultiSink.Record` before the bus sink runs — the primary sink is first, `platform/audit/multi_sink.go:24–35`) leaves the state committed with no reaction. The bus is write-only (`bus.go` `Get` → `ErrSinkWriteOnly`) and observes only live `Record` calls; nothing replays persisted `admin_user_lifecycle_changed` rows into it on restart. The in-repo contrast is the invalidation bus, which re-seeds missed state on recovery (`server_invalidation.go` `resubscribeAndReseed` / `reseedRevocationDenySets`).

**Triggering failure.** Process kill (or panic anywhere in the fan-out — `applyLifecycleTransition` has no recover of its own) in the sub-millisecond window after commit. Also: the transition commits while the admin request is still in flight; if the request then fails to reach the recorder (recorder nil on this build — see F-8's config-mix variant), the reaction never fires at all.

**User impact.** Suspended/archived user keeps sessions and refresh tokens with no automatic repair; with the memory store the record itself vanishes on restart anyway (F-2), so the window is moot until a durable store exists — but the design's own D2/D3 semantics are meant to outlive the memory backend, and the crash window is exactly the case that matters there.

**Recovery.** Manual re-transition (see F-1's 409 trap) or token TTL expiry.

**Corrective pattern.** Document at-most-once-per-process semantics for the bus in `lifecyclereactions/doc.go`. For direction 3, emit the transition and the audit event in the same transaction (outbox), or seed the bus from the durable audit store at boot using the `resubscribeAndReseed` pattern — the bus sink would need a read-side seam that deliberately does not exist today.

### F-4 — Medium — reaction failure is logged and forgotten; "never less locked out" degrades to "possibly not locked out at all", and there is no compensation

**Evidence (Verified).** `bus.go` `invoke` → `reportError` (logger + `onError` only); `applyLifecycleTransition` proceeds to the 200 regardless (`lifecycle.go:77–92`); `Recorder.Record` swallows sink errors unless an `onError` handler is configured (`recorder.go`). Combined with F-1's ctx-cancel, a failed reaction has no retry: `errors.Join` collects per-leg failures but nothing re-runs them.

**Triggering failure.** Any transient store error on one leg (redis hiccup during `Destroy`), or F-1's cancel.

**User impact.** Partial revocation with no signal on the admin surface beyond a log line; the gate still blocks NEW logins/rotations (on the transition's replica), so the residual exposure is existing sessions/access tokens until TTL.

**Recovery.** None automatic. **Corrective pattern (cheap and safe):** add a periodic reconcile — the legs are naturally idempotent (`DeleteAllForSubject` and `Destroy` both no-op on absent entries; `revoke_on_archive_test.go` pins idempotency), so a loop that enumerates `ListByState(SUSPENDED)` + `ListByState(ARCHIVED)` and re-runs the registered reactions (or just the two legs) on a cadence converges partial failures within one interval. This mirrors the revocation-deny-set reseed pattern already in the repo and costs one new sweep-style goroutine. If out of scope, say so in the design's failure-mode table — today the table's "Write error (reaction): best-effort… never fails the transition" row implies the failure is contained, when in fact it is silent.

### F-5 — Medium — the fail-closed refresh denial burns the presented token; a client retry after a TRANSIENT lifecycle-store read error trips family-reuse and kills the whole family

**Evidence (Verified).** D2's gate runs after `Consume` (design pins this) and denies with the same `invalid_grant` as every other path. A re-presented consumed token returns `ErrRefreshTokenReused` with `FamilyID` (`memory_refresh_token.go:161–188`) and `refreshHandleConsumeError` kills the whole family. The grace cache does not help: `Remember` runs only on the success tail (`refreshIssueAndRotate`).

**Triggering failure.** Lifecycle-store read error (fail-closed denial) for a HEALTHY user — impossible with today's memory store (Get never errors), reachable with an SDK embedder's custom `userlifecycle.Store` or direction 3's SQL peer. Client retries the same token (the standard OAuth retry pattern) → reuse detection → `DeleteFamily`.

**User impact.** One transient store blip + one client retry = the user's entire refresh family is destroyed and they must re-authenticate interactively. This is the correct outcome for a genuinely suspended user (the design says so) and a self-inflicted lockout for everyone else. The wire shape stays oracle-safe; the availability cost is hidden.

**Recovery.** Interactive re-login; the family is gone.

**Corrective pattern.** The design already documents the deliberate fail-closed posture; add the retry interaction to that same documentation (config-reference §User Lifecycle): "a refresh denied by the gate consumes the presented token; a client retrying it triggers family revocation — do not retry refresh on `invalid_grant`." Optionally: have the gate deny BEFORE `Consume` when the state read fails vs. after for a genuine block — but that splits the oracle (denial timing), so documentation is the right fix, not code.

### F-6 — Medium — wiring the sweep's `INACTIVE → ARCHIVED` to a destructive reaction converts a clock anomaly from harmless to fleet-wide access cutoff

**Evidence (Verified).** The design wires `OnUserArchived` → `RevokeAccessOnArchive` and notes sweep-driven `INACTIVE → ARCHIVED` now fires it ("a behavior improvement"). The sweep is wall-clock driven (`sweep.go`: `time.Now().UTC()`, `IsDormant` = `now.Sub(lastActive) > threshold`), runs per replica (`startUserAutoDeprovisionSweep`), and last-active is derived from the shared session store (`dormancy.go` `SessionLastActive` — newest `CreatedAt` among live sessions).

**Triggering failure.** A forward clock jump on a sweep replica larger than `DormantAfter + ArchiveAfter` (AGENTS.md's stated assumption is "clocks slew, they do not step backward" — a forward jump IS slew, so this is inside the stated assumptions), or a session-store clock stamping `CreatedAt` far in the past (cross-replica skew). Previously this produced only a state change on the per-process memory record (harmless, self-healing on restart); with D3 wired it now destroys sessions and refresh families — fleet-wide when the stores are shared — for every account the skewed clock deems dormant, bounded only by `MaxPerSweep` per iteration.

**User impact.** Mass, silent access cutoff with no per-account admin action; recoverable by re-login (the gate on the sweeping replica will deny while the record says ARCHIVED — reinstate via admin) but operationally severe and hard to attribute.

**Recovery.** Correct the clock; reinstate accounts via the admin API (ARCHIVED → ACTIVE restores the record, but the destroyed refresh families do not come back).

**Corrective pattern.** Document the clock assumption next to the `auto_deprovision` config row (it is currently documented only in the analysis), and note in `docs/config-reference.md` that the sweep's transitions now have destructive side effects once the D3 bus is wired. Consider making the archive reaction opt-in per the design's own principle ("an operator who does not want this behavior simply never registers it") — the composition root wires it unconditionally today (Proposed; Decision 3.2), so the blast radius is config-coupled to `user_lifecycle.enabled` + `audit.enabled` rather than to a dedicated knob.

### F-7 — Low — sqlite `DeleteAllForSubject` is two non-transactional statements; a crash between them leaves orphan family markers that fire a spurious reuse audit

**Evidence (Verified).** `infrastructure/defaultimpl/sqlite/refresh_tokens.go:242–267` — families-ledger DELETE then token DELETE, no explicit transaction.

**Triggering failure.** Process crash between the two statements during a reaction leg.

**User impact.** A future presentation of a wiped token hits the families map → `ErrRefreshTokenReused` → spurious "refresh token reuse detected — family revoked" audit event and a no-op `DeleteFamily`. Security-neutral (nothing left to kill), audit-noise only. Worth a one-line comment fix (wrap in a transaction) rather than a design change.

### F-8 — Low — with `audit.async.enabled`, the bus fires before the primary sink persists; a crash after the reaction but before the async flush = revocation with no durable audit evidence

**Evidence (Verified).** `AddSink` wraps the composed (async-outermost) sink (`recorder.go:131`; `composeAuditSinks` comment "so the buffered hot path always sits outermost"), so the bus runs synchronously on the admin goroutine while the durable event is still in the async buffer.

**Triggering failure.** Crash of the admin replica between reaction completion and the async worker's flush.

**User impact.** The suspension was applied and revoked, but the `admin_user_lifecycle_changed` evidence row is lost — the tamper-evident audit chain (`WithHashChain`) shows a gap. Consistent with the async sink's documented lossy contract, but the design should state that the D3 bus's "synchronous" property does not make the transition's audit evidence synchronous. **Corrective pattern:** none required beyond a doc line; if the evidence matters for SOC 2, the transition's own 200 should not depend on the async flush (it does not today).

### F-9 — Info — rolling deploy: an old binary replica enforces no gate and no reaction

**Evidence (Partial — topology consequence, no code change needed).** The gate and the bus live in the new binary only; wire shapes are unchanged (403 `account_locked` / 401 `callback_failed` / 400 `invalid_grant` all pre-exist), so a mixed-version fleet is wire-compatible — but a suspended user can authenticate on a not-yet-upgraded replica during the rollout, and that replica's audit sink does not observe the transition (no bus). This is a transient instance of F-2.

**Corrective pattern.** Document in the rollout notes (not in code): enforce the gate only after the fleet is fully upgraded; the admin transition's revocation is only meaningful once every replica runs the new binary.

### F-10 — Info — the design's D2 gate is partially redundant with session liveness, which is exactly why it is correct to add

**Evidence (Verified).** `refreshCheckSessionLiveness` denies when the session behind the SID is gone (`token_refresh.go`). After a successful D3 reaction, sessions are destroyed fleet-wide (shared store), so the liveness check alone would deny most rotations for the suspended user. D2's gate adds the cases the reaction cannot reach: the F-1/F-3/F-4 windows (reaction never ran), the audit-disabled config (F-8's sibling), and refresh tokens whose SID is empty or whose session was already gone before suspension. Defense in depth is the right call; the acceptance test should verify D2 independently of D3 (design Decision 6.11 already says this — confirmed as necessary, not optional).

## 3. Scenario table

| Scenario | Behavior under the design | Verdict | Notes / corrective |
|---|---|---|---|
| **Partition: admin replica loses the lifecycle store** (future durable peer) | Gates fail closed: login 403 `account_locked` (byte-identical to real suspension), refresh 400 `invalid_grant`; mass denial, no oracle leak | Deliberate (Decision 5) | Must be documented in config-reference; the design's log/audit differentiators are the only operator signal (design 6.8) |
| **Partition: replica without the record** (memory store) | Gate reads no-record → ACTIVE; user re-admits on that replica; shared-store revocation from the other replica does not stop re-login | High residual (F-2) | Single-replica semantics must be stated; direction 3 fix |
| **Partition: session/refresh store down during a reaction** | Leg fails → `errors.Join` → logged via `ReactionErrorFunc`; transition still commits; 200 still written | Contained by design; silent to admin (F-4) | Reconcile loop proposed |
| **Partition: invalidation bus down** | Irrelevant to D1–D3 (they use the audit sink, not the cluster bus); cross-replica cache/deny-set convergence degrades as today with degraded → /readyz red | No new exposure | — |
| **Crash after `Append`, before bus dispatch** | State committed, reaction lost, no replay | Medium (F-3) | At-most-once documented; outbox for direction 3 |
| **Crash mid-reaction (admin request alive)** | Partial revocation; next process start loses the memory record entirely (F-2) | Medium | Idempotent legs make a reconcile loop safe |
| **Crash after reaction, before async audit flush** | Revocation without durable audit evidence | Low (F-8) | Doc line |
| **Client disconnect mid-reaction** | Request ctx cancels the reaction; state committed; no 200; retry → 409 trap | High (F-1) | `context.WithoutCancel` — in-repo precedent |
| **Retry after fail-closed refresh denial** | Same token re-presented → reuse → whole family killed | Correct for suspended users; lockout amplification for healthy users on transient store errors (F-5) | Document "do not retry refresh on invalid_grant" |
| **Clock rollback on a sweep replica** | `IsDormant` with `lastActive > now` → not dormant → no transition | Safe | Zero-value last-active also conservative (`dormancy.go`) |
| **Clock FORWARD jump on a sweep replica** | Mass INACTIVE/ARCHIVED transitions; ARCHIVED now fires destructive revocation fleet-wide (shared stores) | Medium (F-6) | Bounded by `MaxPerSweep`; document |
| **Stale cache** | No per-replica lifecycle cache exists (direct store reads); tenant-suspension/client caches unaffected by D1–D3 | No new exposure | — |
| **Dependency outage: audit sink down** | `MultiSink` still runs the bus (bus errors don't disturb other sinks); `Recorder.Record` routes the joined error to `onError` only | Reaction still fires; evidence gap | Matches design intent |
| **Dependency outage: `audit.enabled: false`** | `b.recorder` nil → bus never fires (boot warning); gates still enforce on the transition's replica; other replicas un-enforced (F-2) | Design documents; mixed-config fleet halves enforcement | Loud boot warning confirmed |
| **Recovery: replica restart** | Memory lifecycle record evaporates → user re-admitted on that replica; revocation side effects on shared stores persist | High residual (F-2) | "Restart = un-suspension" must be documented |
| **Recovery: reaction failure later retried** | Nothing retries; manual double-transition is the only path (409 trap) | Medium (F-1/F-4) | Reconcile loop; document 409 recovery |
| **Concurrent admin transitions (two replicas, future durable store)** | `Append` From-check → second gets `ErrStateConflict` → 409; winner's reaction fires | Correct (optimistic concurrency) | Already enforced by `memory.Store.Append` |
| **Concurrent sweep + admin on same user** | Same `ErrStateConflict`; sweep logs + skips, re-evaluates next iteration | Correct | `sweep.go` `apply` |
| **Double sweep (two replicas, memory stores)** | Each replica transitions its own record; both reactions fire → idempotent double revocation on shared stores | Harmless but doubled work/audit | No dedup; acceptable |

## 4. Stated guarantees, unsupported topologies, validation tests, residual risks

### Guarantees the design can actually state (and the code supports)

1. **Single-process, post-transition, post-reaction:** after an admin SUSPENDED/ARCHIVED transition commits and the reaction returns without error on a live request context, every refresh token (all clients) and every session the reaction could enumerate is destroyed — fleet-wide when session/refresh stores are shared, locally otherwise. Idempotent: a second run finds nothing (Verified: `revoke_on_archive.go`, `DeleteAllForSubject`/`Destroy` semantics).
2. **Credentials-first ordering:** refresh tokens are revoked before sessions, so a crash mid-reaction always leaves the account MORE locked out, never less (`revoke_on_archive.go:24–89`).
3. **Reaction isolation:** a reaction failure, panic, or slow store never fails the transition, never disturbs other audit sinks, and never crashes the process (Verified: `bus.go` panic containment + `ReactionErrorFunc`; `MultiSink` fan-out).
4. **Oracle safety:** all three gate denials reuse pre-existing wire shapes — 403 `account_locked` (login legs), 401 `callback_failed` (federated leg), 400 `invalid_grant` (refresh) — byte-identical to the existing paths (Verified at the four sites + `server_oauth.go:221` + design Decision 2.2). State detail lands only in audit meta + logs.
5. **No-record = ACTIVE and nil store = no-op** — the backward-compatibility anchor, enforced by `Store.Get` itself (Verified: `userlifecycle.go`, `memory/memory.go:34`).
6. **Gate ordering:** after credential verification and the SCIM check, before any session/token side effect on login; after `Consume` (no token leak) and before `RecordRotation` on refresh (Verified: `token_refresh.go` structure).
7. **Fail-closed on read error, fail-open on absent wiring** — the deliberate asymmetry with SCIM and tenant-suspension lookups, pinned by the design and consistent with the `refreshCheckSessionLiveness` precedent (Verified).
8. **Optimistic concurrency on transitions:** concurrent admin/sweep transitions resolve via the `Append` From-check → 409 `lifecycle_state_conflict`, never a lost update (Verified: `memory.Store.Append`).

### Unsupported topologies (must be stated in `docs/config-reference.md` §User Lifecycle)

1. **Multi-replica with the memory lifecycle store** — gates and reactions do not converge; a replica that has not observed the transition, or has restarted, treats the user as ACTIVE (F-2). The design's own Decision 4 wording ("reactions revoke per-replica credentials") is inaccurate for shared session/refresh backends and must be corrected.
2. **`user_lifecycle.enabled: true` + `audit.enabled: false`** — the D3 reaction is inert everywhere (bus never observes a transition); only the D1/D2 gates on the transition's replica enforce. The boot warning is the mitigation; a mixed fleet (one replica with audit disabled) silently halves enforcement.
3. **Rolling deploys** — old binaries have no gate and no reaction; enforcement is version-dependent until the fleet is fully upgraded (F-9).
4. **Clock-skewed fleets with `auto_deprovision`** — a forward jump on a sweep replica now causes destructive archive transitions fleet-wide (F-6).
5. **Crash windows** — no replay of a lost transition/reaction across restarts; the audit event (when durable) never re-feeds the bus (F-3).

### Validation tests the acceptance suite must add (distributed-systems slice)

1. **Reaction ctx cancel (F-1):** in the `ssotest` harness, run the admin transition with a request context that is canceled while the reaction is blocked (a session store whose `Destroy` blocks on ctx) → assert the state is SUSPENDED, the 200 was not written, revocation is incomplete, and a second transition attempt returns 409. Then (if the `WithoutCancel` fix lands) assert the reaction completes despite the cancel.
2. **Crash window (F-3):** with a test hook between `Append` and `RecordTransition` (or between the sinks), simulate process death → assert no revocation ran and no replay exists.
3. **Retry amplification (F-5):** D2 gate with an injected lifecycle-store read error → assert `invalid_grant`; re-present the same token → assert the family is killed and the reuse audit event fires; document this as the expected (if unfortunate) contract for healthy users.
4. **Sweep-driven archive revocation (F-6):** `SweepOnce` with `Now` jumped forward past the archive threshold → assert `RevokeAccessOnArchive` fired, `MaxPerSweep` bounded the run, and a second run is a no-op.
5. **Reaction idempotency + leg isolation (F-4):** run `RevokeAccessOnSuspend` twice; inject one-store failure and assert the other leg completed (`errors.Join`), the transition still returned 200, and the error reached `ReactionErrorFunc`.
6. **`audit.enabled: false` + lifecycle enabled (F-2/F-8):** assert the boot warning, that the gates still enforce on the transition's replica, and that no reaction fires.
7. **Multi-replica divergence (F-2):** with shared stores, simulate the reaction on "replica A" and assert "replica B" (fresh memory store) re-admits the user — a test that pins the documented limitation so direction 3 has a regression anchor.
8. **Concurrent transitions:** two `Append`s with the same From → one 409 `lifecycle_state_conflict`, one success (already covered by `memory` tests; extend to the admin handler).

### Residual risks (accepted, must be documented in the endpoint contract)

- **TOCTOU between the login gate and the reaction** (design 6.5): a login that read ACTIVE just before the transition can mint a session + refresh family after the reaction ran; that family survives to TTL on the transition's replica and indefinitely on any replica without the record (F-2 widens this from "until TTL" to "until convergence"). The MFA-second-leg and login-transaction re-checks shrink but cannot eliminate it.
- **Auth-code exchange gap** (design 6.6): a pre-suspension, unexchanged auth code still exchanges after SUSPENDED, minting a fresh family; short TTL + single-use bound it. `AuthCodeStore` has no per-subject delete SPI (Verified: `oauthspi/auth_code.go:114–125`).
- **Access tokens are not revoked by the reaction**: only sessions and refresh families are destroyed; already-issued access tokens remain valid until exp, unless the resource server consults the (shared) session store. The access-token revocation deny-set is untouched by D3 (no `KindTokenRevoked` publish, no deny-set add).
- **Device/CIBA/token-exchange grant paths are outside the gate set** (the spec deliberately covers login + refresh): a suspended user can still complete a device flow or token exchange on the transition's replica if a credential-bearing artifact survives. The D1/D2 sites are the only enforcement points in scope.
- **Restart = un-suspension** with the memory lifecycle store (F-2): the record evaporates; revocation side effects on shared stores persist, so the asymmetry is "revoked everywhere, re-admittable on a fresh replica".
- **INVITED denial vs. the future invitation flow** (design 6.9): "accept invite = first login" must advance INVITED → ACTIVE before the user authenticates, or the gate silently blocks the flow; `AllowsAuthentication` is the single revisit point.
- **Fail-closed self-lockout on lifecycle-store outage** (design 6.8): with a durable peer (direction 3), a store outage mass-denies logins/rotations byte-indistinguishably from real suspension; the log line and `login_failure` audit stream are the only differentiators. Today (memory store) this path is unreachable in the stock binary and reachable only via SDK embedder stores.

## Bottom line

The design's mechanical claims re-verify cleanly against the tree (sites,
budgets, wiring order, oracle shapes, `RefreshGrantDeps` guard, opts-count
tests). The two findings that should gate implementation are F-1 (run the
synchronous reaction on a request-detached context — small, precedented
change that makes "200 implies revocation complete" actually true) and F-2
(correct Decision 4's shared-store wording and document single-replica
semantics + restart behavior in `docs/config-reference.md` in the same
change). F-3/F-4 (no replay, no compensation) are acceptable as documented
at-most-once semantics, but the proposed idempotent reconcile loop is cheap
and closes both. F-5's retry interaction must be documented before any
durable lifecycle store lands. Everything else is bounded, documented, or
inherited from the existing state machine.
