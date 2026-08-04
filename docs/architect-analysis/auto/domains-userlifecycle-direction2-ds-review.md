# Distributed-Systems Engineering Review: `domains/userlifecycle` direction 2 — erase-on-purge, INVITED provisioning, tombstone removal

Review of `docs/auto/domains-userlifecycle-direction2-design.md` (640 lines)
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

Distributed-relevant claims checked for this review:

| Claim | Status | Evidence |
|---|---|---|
| Lifecycle store is per-process memory only; state lost on restart | **Verified** | `cmd/sso-server/serverbuildplatform/build_userlifecycle.go:18-23` hard-codes `userlifecyclememory.New()`; `domains/userlifecycle/memory/memory.go` package doc: "State is lost on restart — fine for tests and small embedded deployments; a multi-replica production deploy should swap in a SQL-backed peer" |
| `Append` is a per-process CAS: seed requires no record; every other transition CASes on live state | **Verified** | `memory/memory.go:38-66` (`From == StateNone` branch; mismatch → `ErrStateConflict`) |
| Admin handler: user-existence 404 via the SHARED `UserProvider` before any lifecycle-store access | **Verified** | `interfaces/admin/lifecycle.go:28-31` (GET) and `:47-49` (POST) — `UserProvider().GetByID` on the request path |
| Transition validation uses the LOCAL record's state only; no generation/version check anywhere | **Verified** | `interfaces/admin/lifecycle.go:73-76` (`ValidateTransition(rec.State, to)`); `core.User` carries `UpdatedAt` only — no monotonic version (`shared/core/types_auth.go:395-410`) |
| Eraser side effects are keyed by userID only, with no epoch/generation guard; legs enumerate then mutate (read-modify-write, non-atomic across legs) | **Verified** | `protocols/compliance/erasure.go` (`EraseSubject`, `eraseSessions` ListByUser-then-Destroy, `revokeRefreshTokens` List-then-DeleteAllForSubject); per-leg best-effort, joined errors |
| The eraser publishes NOTHING on the cluster invalidation bus | **Verified** | `protocols/compliance/erasure.go` has no `platform/cluster` import; contrast `/token/revoke` and `/end_session`, which publish `KindTokenRevoked` (`interfaces/sso/server_logout.go:80`), and `domains/threataction/actions.go:99` publishing `KindSessionSuspended` |
| `DeleteAllForSubject` atomicity differs by backend | **Verified** | memory: single lock (`memory_refresh_token.go:308-333`); sqlite: TWO non-transactional `ExecContext`s (families ledger first, then tokens; `sqlite/refresh_tokens.go:242-267`); redis: per-key DELs |
| `rejectDeactivatedUser` treats a not-found user as active | **Verified** | `server_login_auth.go:144-155` (`uerr != nil || u.IsActive()` → pass; nil `User` is active via `IsActive` nil-receiver) |
| Login recreates a deleted user via upsert | **Verified** | `server_login.go:476-500` `upsertLoginUser` → `CreateOrUpdate`; same at `server_oauth.go:228` (federated callback) |
| Bus is an `audit.Sink`; reactions fire inside `Recorder.Record` fan-out, i.e. AFTER `Append` on the admin path; errors discarded; panic-contained | **Verified** | `bus.go` `Record`/`invoke`; `interfaces/admin/lifecycle.go:89` (`RecordTransition` after `Append` at `:80`) |
| `AddSink` is wiring-time only (pre-serving), so no Record/AddSink concurrency exposure | **Verified** | design 6.11; `build_app_security.go:240` (wireUserLifecycle) runs before `NewServer`; matches direction-1 review |
| Audit primary sink is MEMORY by default (`audit.backend` default `memory`), sqlite/postgres optional | **Verified** | `cmd/sso-server/serverbuildauthn/build_audit_secrets.go:34-60` |
| Sweep (`RunUserAutoDeprovision`) is a plain ticker loop; CAS conflicts and store errors are logged and skipped, re-evaluated next tick | **Verified** | `interfaces/sso/options_admin.go:319-341`; `sweep.go:139-157` |
| Direction 1 (gate) not landed; its gate denies everything but ACTIVE/none, fail-closed on read error | **Verified** | repo-wide absence of `AllowsAuthentication`/`rejectLifecycleBlockedUser`; `direction1-design.md` Decision 1 (`AllowsAuthentication`), Decision 2 (refresh gate) |
| `RecordTransition` variadic-meta "direction-1 precedent" is itself unlanded | **Verified** | `recordLoginFailure` (`server_helpers.go:282`) and `audit.RecordLoginFailure` are non-variadic today — citation defect, not design defect (see architect F3) |
| `ListByState` has zero production callers | **Verified** | repo-wide grep: interface decl + memory impl only |

The three spec corrections in the design's verification record (the
`memory_test.go:88-89` citation, the 404-check line numbers, direction 1
absent) were independently reproduced and are accurate.

---

## 1. State map: owner, store, durability, consistency, replication, failover

| State / data | Owner | Store | Durability | Consistency | Replication | Failover |
|---|---|---|---|---|---|---|
| Lifecycle record (state + ordered history) | `domains/userlifecycle` (memory impl) | per-process map + `RWMutex` (`memory/memory.go`) | **None — lost on restart** | Strong IN-process (single lock; `Append` CAS); **none ACROSS processes** | None — per-replica divergent views; no propagation, no cluster event | None; restart = empty store = every account reads ACTIVE |
| `core.User` records | `core.UserProvider` | memory / sqlite / postgres | Durable (sqlite/postgres) | Store-level | Shared store (multi-replica via pg; sqlite single-file) | Store-level |
| Password credentials (bcrypt verifiers) | credential stores (memory/sqlite) | memory / sqlite | Durable (sqlite) | Store-level | Shared | Store-level — **not touched by the Eraser** (security F1) |
| Sessions | `core.SessionManager` | memory (per-process) / sqlite / redis / postgres | Backend-dependent | Store-level | Shared only with redis/pg; per-process memory otherwise | Store-level |
| Refresh tokens + family ledger | `oauth.RefreshTokenSubjectIndex` | memory / sqlite / redis / postgres | Backend-dependent | `DeleteAllForSubject` atomicity varies (see §0); family kill atomic per backend | Shared only with redis/pg | Store-level |
| Consent / MFA / reset tokens / notifications | respective SPIs, late-bound | memory / sqlite / postgres | Backend-dependent | Store-level | Shared | Store-level |
| Audit trail (the design's only durable purge record) | `platform/audit` | **memory (default)** / sqlite / postgres | Default none | — | — | — |
| Eraser composition | `protocols/compliance.Eraser` | read/write over the above | n/a | Best-effort across legs; no transaction | **No cluster-bus publication** | n/a |
| Cluster invalidation bus | `platform/cluster` (etcd/memory) | etcd watch | Best-effort, at-most-once | Order-independent invalidation | N/A (the replication mechanism) | Resubscribe → flush → reseed → ready (`server_invalidation.go`) |

Two structural facts dominate everything below:

1. **The lifecycle record — the only state the new flows (seed, accept, gate,
   purge marker, tombstone) read and write — is volatile and per-process.**
   Every distributed property of direction 2 (and of direction 1's gate)
   is therefore a per-process property. Restart and replica routing both
   erase it.
2. **The erasure's side effects live in the shared/durable stores, but are
   not fenced**: they are keyed by userID only, run outside the lifecycle
   CAS, and are not coordinated across replicas (no cluster event, no
   generation token). The CAS protects the *record*; it protects *nothing
   else*.

---

## 2. Findings

### F-DS-1 — High: The erasure is not fenced; a concurrent transition (or a stale replica) can erase the wrong subject, and "repaired on next provisioning" is false for non-terminal winners

**Evidence (Verified):** erasure keyed by userID only, no epoch check
(`erasure.go` `EraseSubject`); validation from local `rec.State`
(`lifecycle.go:73-76`); user-existence check reads the SHARED `UserProvider`
(`lifecycle.go:28-31,47-49`); per-process store with no cluster publication
(§0); `core.User` has no monotonic version (`types_auth.go:395-410`).

**Triggering failures:**

(a) *In-process, fail-closed mode*: `EraseSubject` runs before `Append`
(design 1.3). A concurrent ARCHIVED→ACTIVE restore (legal edge) wins the
`Append` CAS after the erasure completed: the subject's data is gone — user
record deleted, sessions/refresh/consent/MFA erased — while the record reads
ACTIVE (the restore winner). "Repaired on provisioning" does not apply: the
record is non-terminal, no provisioning occurs, and the erased account
resurrects through the login upsert path (`server_login.go:476-500`) with the
surviving bcrypt hash. The design's failure table documents only the
concurrent-PURGED winner variant (design 1.3 residual; qa F3, security F4
independently reached the same non-terminal-winner gap).

(b) *Cross-replica (stale replica)*: replica B holds a stale ARCHIVED (or
INACTIVE/ACTIVE) record for u1; replica A purges u1 (Append, erase, Delete —
all on A's local store); SCIM re-provisions u1 (shared `UserProvider`; B's
store untouched). Admin on B POSTs ARCHIVED→PURGED: B's validation passes
(B's record still says ARCHIVED), the shared user-existence check passes
(the re-provisioned u1 exists), so B's eraser destroys the **fresh** account
— sessions, refresh families, consent, MFA, and the user record itself,
repeatedly re-deletable on every subsequent transition. The delete-then-seed
repair (Decision 3) actively *widens* this: after A's Delete, "no record =
ACTIVE" on A, while B's stale non-terminal record still authorizes the
purge. This is the classic delete/recreate race, and re-provisioning of the
same id is a first-class designed scenario (Decision 3), not an exotic
corner.

**User impact:** a purge can destroy a re-provisioned (or concurrently
restored) account; an operator-visible ACTIVE record conceals a deleted
subject. Data loss of the fresh account's credentials/MFA/consent.

**Recovery:** none automatic. The fresh account must be re-provisioned again
(SCIM create), and on the stale replica the poison record persists until
that replica restarts or is manually cleared (no admin path reaches it:
the admin 404 check passes because the user exists, so the transition is
servable, not blocked).

**Corrective pattern (required):** fence the erasure. Cheapest verified-fit
options: (1) add a generation token — a monotonic version on `core.User`
(or a reuse of `UpdatedAt` with documented clock caveats) captured at
handler `Get` time and re-checked immediately before `EraseSubject` and
before `Delete`; refuse with 409 when the user was re-created/modified. (2)
Publish a new cluster `EventKind` (e.g. `lifecycle.change`) on the terminal
sequence so peer replicas delete/refresh their local record for the user —
closing both the stale-purge and the stale-gate windows (F-DS-4). (3) At
minimum, declare the unsupported topology in `docs/config-reference.md`:
"purge/restore semantics require single-writer-per-user; multi-replica
deployments need the SQL lifecycle peer" — the design's Decision-5 row
"Multi-replica — idempotent, safe" is only true for the *erasure*, not for
the *decision*.

**Validation:** deterministic fault-injection test with a store fake that
blocks `Append` after `EraseSubject` returns, asserting the non-PURGED-winner
outcome is either impossible (fencing) or explicitly documented; two-store
test (A purges, B holds stale ARCHIVED, shared UserProvider) asserting B's
transition is refused once fenced.

---

### F-DS-2 — High: The purge marker is volatile; the design's crash analysis misses the dangerous window (crash between Append and erase), and its crash-window repair is vacuous for the memory store

**Evidence (Verified):** memory store "State is lost on restart" (package
doc); `audit.backend` defaults to memory (§0); reaction-mode order is
Append → erase (`lifecycle.go:80,89` + design 1.3); design 3.3 failure row
is "crash between erase and delete".

**Triggering failure:** with a volatile store, a crash cannot leave a PURGED
record behind — the record dies with the process. The design's "crash
between erase and delete leaves a PURGED record for a deleted user, repaired
by `SeedInvited`" is therefore **unconstructible via any real flow** with
the memory store; the only persistent orphan is a *Delete failure* in a
live process (which the security review's F2 shows is also unreachable from
admin/SCIM surfaces). Meanwhile the window the design does not list — crash
after `Append(PURGED)`, before/during the erasure (reaction mode, the
default) — produces the worst outcome: on restart the account reads ACTIVE
(no record), the erasure never ran or ran partially, the password hash
survives (security F1), and with a memory audit sink the purge event itself
is gone. Purged-but-not-erased, resurrected, and untraceable.

**User impact:** purge-as-incident-response silently fails exactly when the
operator needs it most (process crash during the purge request), with no
marker, no audit (memory default), and an authenticatable account.

**Recovery:** none detectable; the compliance erase endpoint can re-run the
idempotent erasure only if the operator knows the subject was purged.

**Corrective pattern (required):** (1) erase-before-Append in **both**
modes — the fail-closed ordering is strictly better under crash: a crash
then leaves an erased subject and no marker (safe) instead of a marker and
an un-erased subject (unsafe); the CAS-conflict-after-erase residual
(F-DS-1) is handled by the fencing fix. (2) State in `docs/config-reference.md`
that the terminal sequence is at-least-once best-effort with the memory
store, and that purge-as-compliance requires the SQL lifecycle peer plus a
durable audit backend (`audit.backend: sqlite|postgres`); the design's
Decision-3 claim "purge history lives on in the audit trail" is only true
with a durable audit sink. (3) Rewrite the Decision-3.3/5 crash rows: the
crash window that matters is "Append committed, erasure not" (marker loss),
not "erase committed, Delete not" (which cannot survive a restart).

**Validation:** restart test — purge in reaction mode, kill the process
before the erasure completes (deterministic fault injection on a leg),
restart with a fresh store → assert the account reads ACTIVE and
authenticates (documents the exposure); after the ordering fix, assert the
subject is erased and the account cannot authenticate even though the marker
is gone. A `test/` crash-window test can only be constructed by pre-seeding
a PURGED record into a fresh store — that is a unit test, not an end-to-end
scenario; the design's Decision-7 "Crash window" item should be re-labeled
accordingly (delete-failure injection, not crash).

---

### F-DS-3 — High: The delete rule (3.2) removes the only record direction 1's gate can deny on, exactly when surviving credentials may still be presented; the gate composes to fail-open after a clean purge

**Evidence (Verified):** `Delete` iff `rep.Err()==nil && rep.UserDeleted`
(design 3.2); after `Delete`, `Get` returns `{State: DefaultState}` = ACTIVE
(`memory.go:29-33`); direction-1 gate allows only ACTIVE/none
(`direction1-design.md` Decision 1) and reads the per-process store; the
password verifier never checks user existence (`domains/authenticators/password.go`,
security F1); refresh rotation is single-use atomic and a rotation in flight
during the purge can mint a token after `DeleteAllForSubject` returns.

**Triggering failure:** after a clean purge, no record exists on the
purge-handling replica — and possibly on *no* replica (restart). Any
surviving credential (leaked pre-purge password; a refresh token rotated
concurrently with the erasure; a session minted in the login/purge TOCTOU
window) is then presented against a gate that reads "no record = ACTIVE".
The refresh path is still protected by session liveness (the eraser deleted
the session), but the **login path is not**: `rejectDeactivatedUser` treats
not-found as active and `upsertLoginUser` recreates the user. Decision 3
turns the gate's fail-closed denial into fail-open ACTIVE at the exact
moment the purge's own audit trail is the only surviving evidence.

**User impact:** a purged subject re-authenticates; with MFA enrollments
erased, the resurrected account has no second factor (security F1's exploit,
made gate-invisible).

**Recovery:** the fencing/generation fix (F-DS-1) plus the credential leg
(security F1) are the fixes; the delete rule must additionally require
"credential deletion completed" (or refuse the tombstone removal when the
credential leg was skipped) so the gate keeps a PURGED marker to deny on.

**Corrective pattern (required):** change rule 3.2's condition to include a
completed password-credential leg; document that a clean purge removes the
gate's denial surface, so the login path must carry its own check (credential
deletion) rather than relying on the lifecycle record. This is the
distributed-systems restatement of security F1: the tombstone deletion and
the gate are two halves of one mechanism, and the design separates them.

**Validation:** ssotest — purge with a live password hash, then login with
the old password → assert 401 (after the credential leg); with the leg
unwired, assert the tombstone is kept and the gate (when D1 lands) denies.
Add a refresh-rotation-during-purge race test asserting the rotated token is
either destroyed or its presentation is denied.

---

### F-DS-4 — Medium: INVITED seed/accept/gate are per-replica; replica routing silently bypasses the invitation gate, and the design's "fail-closed via the gate" is only true on the seed-bearing replica

**Evidence (Verified):** seed writes the local store only (SCIM create on
one replica; `createUser` → seeder → `SeedInvited`); `AcceptInvitation` and
direction-1's gate read the local store; memory store per-process (§0);
design 2.4's fail-closed claim ("control falls to the lifecycle gate") and
its interim note assume the gate observes the seed.

**Triggering failure:** SCIM seeds INVITED on replica A; a login routed to
replica B (load balancer) reads B's empty store → `AcceptInvitation` no-ops
and, once direction 1 lands, the gate allows (no record = ACTIVE). The
invitation's whole point — "not yet accepted" — is unenforced fleet-wide;
`GET /lifecycle` on B reports ACTIVE. Restart of the fleet is the degenerate
case (database review F-DB-1): every INVITED record is lost and every
invited account becomes ACTIVE with no operator-visible signal.

**User impact:** invited-but-unaccepted accounts authenticate depending on
replica routing; an operator reading lifecycle state from one replica sees a
different truth than another. Governance metadata diverges silently.

**Recovery:** none until the SQL peer exists; per-replica repair only.

**Corrective pattern (required):** declare the unsupported topology in the
design (and `docs/config-reference.md`): the INVITED gate and acceptance
semantics are single-process guarantees; multi-replica deployments must back
`userlifecycle.Store` with the SQL peer (which the design already requires
of any future implementor — the `Delete` interface growth is a step in that
direction) before direction 1's gate can be a security boundary. Optionally
publish a cluster invalidation event on seed/accept/delete (shared corrective
with F-DS-1) so per-replica TTL caches of the record converge; note that
memory `Store` has no TTL mechanism, so the event must carry the full record
or trigger a re-read from a shared store — i.e., it only works once the peer
exists.

**Validation:** two-store unit test (shared `UserProvider` fake, two memory
lifecycle stores) — seed on A, login/accept on B, assert the documented
divergence; restart test — seed INVITED, fresh store, assert ACTIVE (pin
F-DB-1's behavior as a tested contract, not an accident).

---

### F-DS-5 — Medium: The purge erasure runs under the request context with no timeout policy; a client disconnect aborts a committed purge mid-erasure, and the lifecycle surface has no re-run

**Evidence (Verified):** handler passes `ctx.Request().Context()` to
`Append`/`RecordTransition` today (`lifecycle.go:80,89`); the design's
erasure call would use the same ctx; the erasure is per-leg best-effort
(`erasure.go`); `DeleteAllForSubject` is non-transactional on sqlite (two
`ExecContext`s) and per-key on redis (§0); the compliance erase endpoint
(`/api/v1/compliance/users/:id/erase`) re-runs `EraseSubject` without a
user-existence check (`compliance_routes.go:118-145`) but does not inform
the lifecycle record.

**Triggering failure:** admin client disconnects (or the LB times out)
mid-erasure. Reaction mode: the PURGED transition is already committed; the
report says partial; the record is kept (rule 3.2) — correct, but the only
re-run path is the separate compliance endpoint, whose result never updates
the lifecycle record or its audit meta. Fail-closed mode: the aborted
erasure returns an error → 500, state unchanged, retryable — clean, but the
request-context cancellation makes the "fail-closed" path depend on the
client's patience rather than a server-side deadline. No timeout/backoff is
specified for an operation that blocks an admin request across N clients ×
stores.

**User impact:** partially-erased purges with no lifecycle-coupled retry;
operators must know the compliance surface exists. Availability: admin
request latency bounded by the slowest store, no deadline.

**Recovery:** re-run via the compliance erase endpoint (documented, not
wired); the PURGED record honestly persists.

**Corrective pattern (recommended):** run the erasure with a server-side
timeout derived from the request ctx (or a configurable purge deadline) so
disconnect semantics are deterministic; document the re-run path in
`docs/config-reference.md` with the note that a compliance-surface re-run
does not trigger rule 3.2 (the record stays PURGED — safe, and the honest
tombstone). Note the sqlite families-ledger-first ordering means a crash
between the two `ExecContext`s leaves tokens that present as vanilla
`invalid_grant` (the wipe's documented intent) — benign, but worth one line
in the design's failure table.

**Validation:** ctx-cancellation fault-injection test for both modes;
assert the documented re-run converges and the tombstone rule does not fire
on the compliance-surface re-run.

---

### F-DS-6 — Low: `SeedInvited`'s delete-then-seed repair is a non-atomic pair; cross-process concurrent re-provisioning diverges

**Evidence (Verified):** `SeedInvited` = conditional `Delete` + `Append`
(design 2.1); `Append`'s CAS is per-process (design 4, §0).

**Triggering failure:** two replicas re-provisioning the same id
concurrently: each deletes (idempotent) and each seeds — both succeed
locally, producing two INVITED records on two replicas (divergent, each
internally consistent). In-process the pair converges (one `Append` wins,
other gets `ErrStateConflict` → 409). No data-loss; same per-replica class
as F-DS-4.

**Corrective pattern (optional):** fold into the F-DS-4 SQL-peer/topology
statement; no separate fix.

**Validation:** concurrent-seed race test (`-race -count=10`), asserting the
in-process 409 convergence and documenting the cross-process divergence.

---

### F-DS-7 — Info: Clock assumptions

No direction-2 code path reads wall clocks for correctness: `Delete`,
`SeedInvited`, `AcceptInvitation`, and `EraseOnPurge` are clock-free
(Verified — all are store/audit operations). `Transition.At` and audit
timestamps are `time.Now().UTC()` stamps (cosmetic; history is append-
ordered per process; cross-replica timestamp skew is display-only). The
inherited dormancy sweep remains wall-clock-sensitive: a forward clock jump
makes recently-active accounts look dormant → premature INACTIVE/ARCHIVED
(ARCHIVED is purge-eligible, but PURGED remains admin-only, so a jump alone
cannot purge); a rollback delays dormancy (fail-open, safe).
`ActivityTracker.TouchAt` explicitly refuses out-of-order regression
(`memory.go`). No new clock dependency; no action beyond the inherited note.

---

## 3. Scenario table (partition, crash, retry, clock, stale cache, outage, recovery)

| # | Scenario | Trace | Outcome | Design row | Verdict |
|---|---|---|---|---|---|
| S1 | Partition: B isolated while A purges u1; u1 re-provisioned during partition | B holds stale ARCHIVED; shared UserProvider re-created u1; B serves ARCHIVED→PURGED; user-existence check passes; B erases fresh account | Fresh account destroyed; B's record stays PURGED until restart | "Multi-replica — idempotent, safe" | **F-DS-1** — decision not fenced; claim only true for the erasure, not the decision |
| S2 | Partition: B isolated while A seeds INVITED | Login routed to B → no record → accept no-op; gate (D1) allows | INVITED account authenticates fleet-wide | 2.4 "fail-closed via the gate" | **F-DS-4** — gate is per-replica |
| S3 | Crash between Append(PURGED) and erase (reaction mode) | Record dies with process; erasure never ran; bcrypt survives; memory audit lost | Account reads ACTIVE; re-authenticates; purge untraceable | "Crash between erase and delete" (the other window) | **F-DS-2** — table lists the harmless window, not this one |
| S4 | Crash between erase and Append (fail-closed) | Subject erased; record + (memory) audit lost | Invisible erasure; re-provision clean; evidence gone | fail-closed row | Covered by F-DS-2 corrective (durable audit + SQL peer) |
| S5 | Crash between erase and delete | Memory store: **no orphan survives** (record gone with process) | Design's 3.3 repair is unreachable for the crash case; the real orphan is Delete failure in a live process | 3.3 "crash-window repair" | **F-DS-2** — repair vacuous for crashes; also security F2 (unreachable from admin/SCIM) |
| S6 | Delete failure (live process) | PURGED record + deleted user; admin 404s; SCIM re-provision on the same process repairs; on another replica does not | Orphan persists on replicas that hold it | 3.3 | Security F2 + F-DS-1 (per-replica repair) |
| S7 | Retry: duplicate purge POST | Second attempt: user gone → 404; user survived → PURGED→PURGED illegal → 400 | Converges; no double-erase (state machine blocks it) | 1.3 | Sound — verified by construction |
| S8 | Retry: fail-closed purge, erasure OK, Append lost the CAS | Retry re-reads: winner PURGED → 400; winner ACTIVE (restore) → 400; subject already erased | Erased subject behind a non-PURGED record; "repaired on provisioning" false | 1.3 residual | **F-DS-1** (qa F3, security F4) |
| S9 | Retry: duplicate seed (admin) | Atomic seed branch → 409 | Converges | 2.2 | Sound (Verified: `memory.go:52-55`) |
| S10 | Duplicate delivery: SCIM create retried | New id per create (`handler_users.go:23` `newID()`); no record conflict | No duplicate-seed hazard | 2.3 | Sound |
| S11 | Clock rollback | Dormancy delayed (fail-open); direction-2 paths clock-free | Safe; cosmetic stamps | Decision 5 | F-DS-7 (Info) |
| S12 | Clock forward jump | Premature INACTIVE/ARCHIVED by sweep; PURGED still admin-only | Bounded; inherited | — | F-DS-7 (Info, inherited) |
| S13 | Stale cache: per-replica lifecycle record | Post-purge-delete reads ACTIVE on every replica; D1 gate allows | Surviving credentials pass (F1); refresh rotation in flight outlives purge | 3.2 + TOCTOU row | **F-DS-3** |
| S14 | Stale cache: per-replica revocation deny-set | Eraser publishes no `KindTokenRevoked`/`KindSessionSuspended`; access tokens are stateless JWT to TTL | Pre-purge access tokens valid to TTL (accepted residual); no new exposure vs GDPR erase | F10 (protocol review) | Inherited, accepted |
| S15 | Dependency outage: one erasure leg down, reaction mode | Transition commits; report shows the error; record kept (rule 3.2) | Partially-erased purge visible, not claimed complete | 1.3 reaction row | Sound |
| S16 | Dependency outage: one leg down, fail-closed | No Append; 500 `internal_error`; state unchanged; `RecordTransitionFailure` audited | Retryable; oracle-safe | 1.3 fail-closed row | Sound (Verified shape) |
| S17 | Dependency outage: user store down during purge | Fail-closed: refusal; reaction: `user(not wired)`-style error in report, user survives, record stays PURGED | Honest tombstone; gate (D1) denies | 3.2 | Sound |
| S18 | Client disconnect mid-erasure | Request ctx cancelled; reaction mode: committed PURGED + partial report, no lifecycle re-run; fail-closed: 500 | Operability gap; re-run only via compliance surface | — (not in failure table) | **F-DS-5** |
| S19 | Split-brain: two replicas purge concurrently | Both Append locally (per-process CAS), both erase (idempotent), both Delete | Converges to no-record; double-erase safe | Decision 5 | Sound — erasure idempotency verified |
| S20 | Split-brain: purge vs restore (in-process, fail-closed) | Erasure wins, restore wins the CAS | Erased subject reads ACTIVE (S8) | 1.3 residual | **F-DS-1** |
| S21 | Recovery sequencing: replica restart | Empty store; all governance state (INVITED/ARCHIVED/PURGED) gone | Everything reads ACTIVE; D1 gate moot | 4 / 6.11 | F-DB-1 + **F-DS-2/4** |
| S22 | Recovery sequencing: invalidation-bus degraded | Design adds no bus kinds; resubscribe→reseed→ready path untouched | No interaction | 6.11 | Sound |
| S23 | Readiness: late-bind + AddSink | Wiring-time only, pre-`NewServer`; no Record/AddSink race; no new readiness surface | Sound | 6.11 | Sound (Verified) |
| S24 | Sweep racing purge (same process) | CAS conflict → logged, skipped, re-evaluated next tick | Safe (Verified `sweep.go:139-157`) | — | Sound |
| S25 | Sweep on a stale replica | B holds INACTIVE; purge+re-provision on A; B's sweep appends INACTIVE→ARCHIVED for the fresh id | Stale non-terminal record again authorizes transitions (same class as S1) | Decision 5 | **F-DS-1** (stale-writer family) |

---

## 4. Stated guarantees vs. reality, unsupported topologies, validation tests, residual risks

### Stated guarantees

| Design guarantee | Verdict |
|---|---|
| No record = ACTIVE | **Holds** — and is the mechanism behind F-DS-3 (post-delete fail-open) and F-DS-4 (per-replica bypass) |
| Unwired = byte-identical | **Holds** — every new seam is nil-default (Verified at each anchor) |
| "PURGED means erased, enforced when armed, never assumed" | **Partial** — enforced per-process, only when the request survives, only for the legs wired; not fenced against concurrent/stale writers (F-DS-1), not crash-robust (F-DS-2), not credential-complete (F-DS-3) |
| "Re-provisioning never inherits an inescapable PURGED record" | **Partial** — true per-process; false across replicas holding stale records (S1) |
| "Repaired on next provisioning" | **Partial** — only for terminal winners, only on the replica holding the orphan (S5/S8) |
| Multi-replica erasure "idempotent, safe" | **Partial** — idempotent (verified), but effective only with shared erasure stores, uncoordinated, and unpublishable on the cluster bus (F-DS-1, S1/S19) |
| Fail-closed refusal is oracle-safe and retryable | **Holds** — 500 `internal_error`, state unchanged, retryable (S16) |
| Bus single-execution rule | **Holds by construction** — cmd registers no `OnUserPurged` (design 1.1/1.4); embedder stacking is documented (architect F8) |

### Unsupported topologies (must be declared, per F-DS-1/2/4)

1. **Multi-replica lifecycle enforcement without a shared `userlifecycle.Store`** — the INVITED gate, acceptance trigger, purge marker, and tombstone are per-process values; direction 1's gate is only as strong as the replica that served the request.
2. **userID reuse across replicas without a generation/fencing token** — a stale replica's purge can destroy a re-provisioned account (S1).
3. **Per-process memory erasure stores in a multi-replica deployment** — sessions/refresh tokens survive a purge executed on a peer (inherited from the eraser's backend dependence; stock single-process deployments are unaffected).
4. **Purge-as-compliance with `audit.backend: memory`** — the only durable record of the purge is the audit trail; memory default loses it on crash (F-DS-2).

### Validation tests (distributed-systems additions to the design's Decision 7)

In priority order, all deterministic fault-injection (never timing-based):

1. **Fencing test (F-DS-1):** store fake blocking `Append` after `EraseSubject` returns; concurrent ARCHIVED→ACTIVE restore; assert the erasure/restore interleaving is refused (post-fix) or byte-documented (pre-fix). `-race -count=10`.
2. **Stale-replica purge test (F-DS-1):** two memory stores + one shared `UserProvider` fake; purge on A; re-provision + seed on A; B serves ARCHIVED→PURGED → assert refusal post-fix.
3. **Crash-window tests (F-DS-2, corrected):** (a) fault-inject a leg failure after `Append` in reaction mode, restart with a fresh store → assert ACTIVE + authenticatable (exposure pinned); (b) post-fix ordering (erase first) → assert subject erased even though the marker is lost. Re-label the design's "crash window" integration item as a delete-failure-injection unit test — a crash cannot leave a PURGED record with the memory store.
4. **Restart matrix (F-DS-4/F-DB-1):** seed INVITED → restart → assert ACTIVE and a documented login outcome; purge → restart → assert the resurrection outcome (S21) is pinned as a tested contract.
5. **Ctx-cancellation test (F-DS-5):** cancel the request ctx mid-erasure in both modes; assert the reaction-mode partial state + re-run path and the fail-closed 500 + unchanged state.
6. **Retry matrix (S7/S8):** duplicate purge → 400/404; fail-closed conflict retry → 400 with no second erasure (idempotency asserted via store fakes counting `Delete`/`Destroy` calls).
7. **Refresh-rotation-during-purge race (F-DS-3):** rotate a family concurrently with `DeleteAllForSubject`; assert the rotated token is destroyed or its presentation denied.
8. **In-process concurrency sweep (F-DS-6):** concurrent seed/accept/purge on one store — `-race -count=10`, assert CAS convergence (409/conflict-re-read).

### Residual risks (accepted by the design, re-affirmed here)

- Pre-purge access tokens remain valid to TTL (stateless JWT; no `KindTokenRevoked` publication — inherited from the GDPR erase surface, accepted).
- Login/purge TOCTOU (S13) and refresh-rotation/purge (F-DS-3) shrink, never eliminate, with fencing + credential-leg fixes.
- Per-replica divergence converges only via the future SQL peer or cluster invalidation; nothing in this design changes that.
- `SeedInvited` delete+seed non-atomicity (F-DS-6) and the sqlite two-step `DeleteAllForSubject` window (F-DS-5 note) are bounded, documented residuals.

**Bottom line:** the design's in-process atomicity story (CAS `Append`, idempotent eraser, oracle-safe failures, retry convergence) is sound and verified. What it under-specifies is the boundary of that story: the erasure is not fenced against concurrent or stale writers (F-DS-1), the purge marker is volatile and the failure table lists the harmless crash window rather than the dangerous one (F-DS-2), the delete rule composes with direction 1's gate into post-purge fail-open (F-DS-3), and every seed/accept/gate guarantee is per-process until a shared store exists (F-DS-4). Required fixes: fencing (generation token or cluster lifecycle event), erase-before-Append in both modes, the credential-leg condition on rule 3.2, and an explicit unsupported-topology statement for multi-replica lifecycle enforcement. F-DS-5/F-DS-6 are recommended; F-DS-7 needs no action.
