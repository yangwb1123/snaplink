# Database-Architect Review: `domains/userlifecycle` Direction 2 (erase-on-purge, INVITED provisioning, tombstone removal)

Review basis: `ai-dev/prompts/README.md`,
`docs/auto/domains-userlifecycle-direction2-design.md`,
`docs/auto/domains-userlifecycle-direction2-spec.md`,
`docs/auto/domains-userlifecycle-direction1-design.md`, current executable
code, `docs/config-reference.md`, `docs/error-codes.md`. The feature is
**Proposed** (design only; none of the three decisions has landed).

**Checks that ran (this revision):** source reads and greps only — store
constructors (`serverbuildplatform/build_userlifecycle.go`,
`serverbuildstore/build_identity_stores.go`, `build_oauth_stores.go`),
`domains/userlifecycle/{userlifecycle,memory/memory,transitions,sweep,bus}.go`,
`interfaces/admin/lifecycle.go`, `protocols/compliance/erasure.go`,
`cmd/sso-server/{build_stores.go,build_app_core.go,compliance_routes.go}`,
`protocols/scim/handler_users.go`, `infrastructure/defaultimpl/...`
user/refresh/session stores, audit sink builders, config structs, plus
`wc -l` for the budget claims. No build/test execution, no file
modifications. This is advisory analysis; every claim about current code is
**Verified** (code read) unless labeled; design claims are **Proposed**.

The design's verification record was re-checked against the tree: the
`memory_test.go:88-89` citation correction (it is `TestGet_ReturnsCopy`),
the admin-handler 404 line numbers (28-31), the `OnUserPurged` zero-caller
claim, the `Append`-then-`RecordTransition` order in `applyLifecycleTransition`,
the `ListByState` no-production-caller claim, the 10/60-file ceilings, and
direction 1's absence (`AllowsAuthentication`/`rejectLifecycleBlockedUser`
grep — zero non-test hits) are all **Verified** as stated.

---

## 1. Store inventory: purpose, durability, implementation, stock wiring, consistency

| # | Store | Purpose in direction 2 | Durability | Implementation | Stock binary wiring | Consistency requirement |
|---|---|---|---|---|---|---|
| S1 | `userlifecycle.Store` | per-user lifecycle state + ordered transition history (INVITED..PURGED); the write target of the purge terminal sequence, seed writers, and the acceptance trigger | **HOT only** — per-process map; **every record is lost on restart** | `domains/userlifecycle/memory` (`Store`, RWMutex + map); **no SQL peer exists** (`grep -rln userlifecycle infrastructure/` — zero non-test hits) | **Yes** — `serverbuildplatform.BuildUserLifecycle` (`build_userlifecycle.go:18-23`) returns `userlifecyclememory.New()` unconditionally when `user_lifecycle.enabled`; wired via `sso.WithUserLifecycle` (`build_stores.go:328-343`) | Per-key linearizability via global lock; `Append` is the only atomic primitive (CAS on `From` == live state); cross-replica divergence is accepted by the domain |
| S2 | `core.UserProvider` (eraser `Users` leg) | deletes the account; `rep.UserDeleted` drives the Decision-3 delete rule | memory: volatile; sqlite/postgres: **durable** | `defaultimpl/memorystoreidentity`, `infrastructure/defaultimpl/sqlite`, `infrastructure/postgresbackend` | **Yes** — `BuildUserProvider` (`build_identity_stores.go:244`) per `identity.backend` (default memory) | `Delete` idempotent — **Verified** for memory (`memory_users.go:204-216`, map delete) and sqlite (`users.go:258-262`, `DELETE ... WHERE id=?`); postgres assumed same shape (not read) |
| S3 | `core.SessionManager` (eraser `Sessions` leg) | destroys active sessions on purge | memory: volatile; sqlite/redis/postgres: shared/durable | defaultimpl, sqlitestores, redisbackend, postgresbackend | **Yes** — `BuildSessionManager` (`build_identity_stores.go:267`) per `identity.session_backend` (default = identity backend) | per-session `Destroy` idempotent |
| S4 | `oauth.RefreshTokenSubjectIndex` + `core.ClientStore` (eraser `Refresh`+`Clients` legs) | revoke refresh tokens across every client on purge | memory: volatile; sqlite: durable; redis: shared | all three implement `DeleteAllForSubject` (**Verified**: `memory_refresh_token.go:308`, `sqlite/refresh_tokens.go:242`, `redis/refresh_token.go:313`) | **Yes** — `BuildRefreshTokenStore` (`build_oauth_stores.go:71`) when `oauth.refresh_token.enabled`; client store always wired | per-(subject,client) delete idempotent; erasure fan-out is O(#clients) |
| S5 | `ConsentStore`, `MFAEnrollmentStore`, `PasswordResetRevoker` (eraser optional legs) | clear inheritable state before account deletion | backend-dependent (memory/sqlite/redis) | defaultimpl, sqlitestores, redisbackend | **Yes, late-bound** — `lateBindComplianceStores` (`compliance_routes.go:223-238`) after `wireGovernance` (`build_app.go:257`) | idempotent revoke (existing pattern) |
| S6 | `audit.Recorder` + sinks (incl. the proposed `LifecycleEventBus`) | the ONLY durable record of purge history, erasure reports, and seed/accept transitions | primary sink: memory (volatile) / sqlite / postgres — configurable (`BuildPrimaryAuditSink`, `build_audit_secrets.go:34`); `audit.enabled:false` → `b.recorder` nil (**Verified** `build_app_core.go:200`) | `platform/audit` | **Yes** when `audit.enabled`; the bus is added via `Recorder.AddSink` at wiring time | best-effort, fail-open (sink errors never block); the bus fires only when an event reaches the Recorder |

**Bottom line on "hot vs durable and does the stock binary wire it":**

- **S1 is hot-only.** The stock binary wires it whenever `user_lifecycle.enabled`
  is set, but the only implementation is a per-process map. Every record —
  INVITED seeds, ACTIVE/ARCHIVED/PURGED states, full transition history —
  is gone on restart. This is the single most important persistence fact for
  direction 2, because direction 2 makes S1's contents *operationally
  meaningful* (INVITED provisioning, purge tombstones) where today they are
  advisory metadata.
- The erasure legs (S2-S5) are all backend-selectable and durable-capable;
  the eraser itself is stock-reachable (`newSelfServiceEraser` +
  `lateBindComplianceStores` precedent, `compliance_routes.go:32,223`), so
  the *erasure* side of direction 2 has a durable story; the *lifecycle
  record* side does not.
- Direction 1's planned login gate (not landed) reads S1 on the auth path;
  direction 2's acceptance trigger writes S1 on the auth path. Both are
  per-replica state today.

---

## 2. Findings (sorted by severity)

### F-DB-1 (High): restart silently converts INVITED (and PURGED) records to ACTIVE — the store direction 2's new semantics depend on is hot-only

- **Evidence:** `BuildUserLifecycle` hard-codes `userlifecyclememory.New()`
  (`cmd/sso-server/serverbuildplatform/build_userlifecycle.go:18-23`); no
  durable peer exists under `infrastructure/` (grep-verified); `Get` returns
  `{State: DefaultState}` with empty history for an absent record
  (`domains/userlifecycle/memory/memory.go:26-33`); `Store` has no `Delete`
  and memory never removes records today, so "no record" is the only
  read-back after a restart. Direction 2 makes INVITED production-reachable
  (admin seed form, SCIM seeder), and direction 1 (per its design,
  `docs/auto/domains-userlifecycle-direction1-design.md` Decision 1) will
  deny INVITED at login via `AllowsAuthentication` reading this same store.
- **Impact:** a restart (or a rolling restart across replicas) drops every
  lifecycle record. INVITED accounts read ACTIVE: direction 2's acceptance
  trigger no-ops (no record) and direction 1's gate (once landed) admits
  them — an invitation policy silently fails open. PURGED tombstones and the
  entire per-record history vanish with them; in the reaction-mode crash
  window (Append committed, erasure not yet run, process dies) the purge
  intent is lost with **no audit event either** (RecordTransition runs after
  the erasure, design 1.3) — the operator has no durable trace that a purge
  was attempted. The design acknowledges per-replica divergence (Decision 4,
  6.11) but not the *restart-loss* case, which is strictly worse: it is not a
  bounded divergence window, it is total state loss.
- **Recommendation (required before direction 1's gate lands, or as part of
  direction 2):** ship a durable `userlifecycle.Store` peer (sqlite/postgres,
  following the existing `infrastructure/defaultimpl/sqlite` + postgres
  pattern with the codebase's schema-version boot gate) and make
  `BuildUserLifecycle` select it per config, mirroring `BuildUserProvider`.
  At minimum, if the memory store stays the only backend, document in
  `docs/config-reference.md` that INVITED/purge enforcement is
  single-process-only and resets on restart, and audit the transition
  *before* the erasure in reaction mode (or emit the purge-attempt event
  first) so a crash window is never silent.
- **Validation:** restart test — seed INVITED, rebuild the store, assert the
  documented read-back; grep `serverbuildplatform/build_userlifecycle.go` for
  backend selection.

### F-DB-2 (High): the fail-closed purge residual and Append-store-error row leave non-PURGED orphans with no repair path — the Decision-3 repair only covers PURGED records

- **Evidence:** design 1.3 fail-closed flow runs erasure BEFORE `Append`
  (erase → Append → conditional Delete); the accepted residual (1.3,
  Decision 5) is "Append conflicts after a clean erasure → 409, orphaned
  record". The same orphan class arises when `Append` fails with a *store
  error* after a clean erasure — a row missing from the Decision-5 table.
  Decision 3.3's repair is only `SeedInvited` over a **terminal** (PURGED)
  record; the admin seed form maps any other existing record to
  `400 illegal_lifecycle_transition` (2.2), and `SeedInvited` returns
  `ErrStateConflict` for non-terminal records (2.1). So a record left in
  ARCHIVED/ACTIVE for a deleted user blocks re-provisioning of that id via
  the admin surface with no repair path; SCIM recovers by accident (logs the
  conflict, keeps the account ACTIVE with a stale history).
- **Impact:** a concurrent restore (`ARCHIVED → ACTIVE`) racing a fail-closed
  purge, or an Append store error post-erasure, strands the subject id in a
  state where re-provisioning requires a manual detour (transition the stale
  record to PURGED again, then re-seed). The design's own "re-provisioning
  repair" guarantee (3.3) does not cover it.
- **Recommendation:** widen the repair rule from "record is PURGED" to "user
  no longer exists" — the admin handlers already hold the `UserProvider`
  read that proves absence (the existing 404 check, `lifecycle.go:28-31`);
  `SeedInvited` can delete any record whose user is gone. Add the
  Append-store-error row to the Decision-5 table.
- **Validation:** integration test — fail-closed purge with a lifecycle
  `Append` that fails after a clean erasure; then re-provision the same id
  and assert the outcome (repaired, or explicit documented 400).

### F-DB-3 (Medium): the delete rule (`Delete` iff `rep.Err()==nil && rep.UserDeleted`) depends on `UserProvider.Delete` idempotency that only the current backends happen to provide

- **Evidence:** `eraseUser` sets `UserDeleted` only on nil error
  (`protocols/compliance/erasure.go:243-258`); memory and sqlite `Delete`
  are idempotent nil on absent users (**Verified** — `memory_users.go:204`,
  `sqlite/users.go:258`), so a second purge (e.g., from a replica whose
  memory record still shows ARCHIVED/PURGED) converges and `UserDeleted=true`
  → record deleted. A backend that returns an error for an absent user would
  instead leave `UserDeleted=false` → the PURGED tombstone persists for an
  already-erased subject, and the re-provision repair becomes the only exit.
- **Impact:** cross-replica double-purge convergence and the "record never
  outlives the erased account" anchor are today accidental properties of two
  backends, not a contract.
- **Recommendation:** pin "delete of an absent subject is success" in the
  eraser's contract (or treat not-found as success in `eraseUser`), so the
  delete rule is backend-independent.
- **Validation:** unit test — eraser over a `UserProvider` whose `Delete`
  returns not-found; assert `UserDeleted=true` and the record is removed.

### F-DB-4 (Medium): `Record.Exists()` = `len(History) > 0` is an implicit invariant of the memory implementation, not a store contract

- **Evidence:** the design's `Exists` (2.1) derives existence from history
  length; it holds today only because the memory `Get` returns empty history
  for absent records (`memory.go:26-33`) and `Append` always appends
  (`memory.go:49-66`). The `Store` interface (`userlifecycle.go:76-150`)
  pins "no stored record → `{State: DefaultState}` with EMPTY history" in
  prose but nothing compile-enforces it, and nothing prevents a future SQL
  peer from persisting an empty-history row (or a compaction that trims
  history to zero entries).
- **Impact:** a peer that violates the invariant silently flips the admin
  seed form between "seed" and `400 illegal_lifecycle_transition` — a
  governance-correctness change with no schema or test signal.
- **Recommendation:** state the invariant as a first-class contract sentence
  of `Store.Get` (the design's doc comment already gestures at it) and add a
  conformance test any peer must pass; alternatively make `Exists` part of
  the interface so implementations own it.
- **Validation:** conformance-style test asserting Get-after-Delete returns
  empty history for the memory peer (already in the Decision-7 plan).

### F-DB-5 (Low): `accept_on_first_login` "default true when the invite knob is on" cannot be expressed with a plain bool — the config package has a tri-state convention for exactly this

- **Evidence:** the design's `UserLifecycleInviteConfig{Enabled,
  AcceptOnFirstLogin bool}` (2.5) with a plain bool makes YAML-unset ==
  `false`, contradicting the documented default `true`. The codebase already
  solves "operator did not mention" with `*bool`
  (`config/config.go:126`, `config_gates_test.go:9`).
- **Impact:** a silently-false default would make every seeded INVITED
  account stay INVITED with no auto-accept — the opposite of the documented
  interim behavior (2.4), and direction 1's gate would then deny those users
  at login until an admin accepts them.
- **Recommendation:** `AcceptOnFirstLogin *bool`, resolved at wiring time to
  `true` when unset and invite enabled; add a wiring test for the
  unset/true/false triangle.
- **Validation:** extend `userlifecycle_wiring_test.go` with the three config
  inputs.

### F-DB-6 (Low): the SCIM seed failure is logged but not audited — with direction 1 landed, a failed seed is a silent permissiveness change

- **Evidence:** the proposed hook sits between `CreateOrUpdate` and the 201
  (`handler_users.go:54-60`); a seed error "logs and still returns 201"
  (2.3). `SeedInvited` audits only its success path. A crash or store error
  in that window leaves the account ACTIVE (implicit default) — the
  direction-1 gate then *admits* it, inverting the INVITED deny-until-accept
  intent. The design accepts this fail-open deliberately ("user provisioning
  must not fail over governance metadata") — the gap is observability, not
  the choice.
- **Recommendation:** audit the seed failure (reuse
  `EventAdminUserLifecycleChanged`, OutcomeFailure, reason
  `invite_seed_failed`) so an operator can enumerate accounts that were
  created but never became INVITED; bounded (one event per failed seed).
- **Validation:** SCIM integration test with a failing seeder; assert the
  failure audit event and the 201.

### F-DB-7 (Info): unbounded per-record history growth and O(n) `ListByState`; purge fan-out is O(#clients) inside the request

- **Evidence:** every `Append` grows `History` without bound
  (`memory/memory.go:58`); the sweep can add one entry per account per
  dormancy cycle (`sweep.go` `apply`); the admin GET serializes the full
  history (`lifecycle.go:53-60`); `ListByState` is a full map scan
  (`memory.go:74-84`) and has **zero production callers** (grep-verified —
  the design's claim is correct). The fail-closed purge runs
  `EraseSubject`'s refresh leg, which is `Clients.List` + per-client
  `DeleteAllForSubject` (`erasure.go:220-240`), inside the request.
- **Impact:** memory growth is unbounded per record over an account's
  lifetime; a very large client registry makes a fail-closed purge's request
  latency scale with client count. Neither is a direction-2 regression, but
  Decision 3's tombstone removal makes long histories more likely to survive
  until deletion.
- **Recommendation:** record history length and purge latency in the
  integration test; specify a history cap (e.g., keep last N transitions)
  when the durable peer is designed.

### F-DB-8 (Info): a partially-erased account is indistinguishable from an untouched ARCHIVED account on the lifecycle surface

- **Evidence:** fail-closed erasure failure returns `500 internal_error`
  with no state change (1.3); `GET /lifecycle` still reads ARCHIVED while
  the account may be partially erased (sessions destroyed, tokens revoked).
  The design's own failure table says "state reads ARCHIVED"; the audit
  failure event + erasure meta is the only signal.
- **Impact:** an operator polling the lifecycle surface cannot see the
  partial-erasure state; acceptable per the design (the 500 is the signal),
  but worth a documented note in `docs/error-codes.md` alongside the
  `internal_error` row the design already adds.

---

## 3. Query/index and transaction analysis (demonstrated hot + atomic paths)

### 3.1 Hot path 1 — `AcceptInvitation` on first login (new; direction 2, 2.4)

- Shape: `Store.Get` + conditional `Append` per successful login, gated by
  `invite.enabled && accept_on_first_login` (config check first — zero reads
  when off, as designed).
- Memory implementation: one RLock map lookup + one locked CAS append —
  O(1), two lock acquisitions, no contention concern at any plausible login
  rate. No index exists or is needed (map key).
- For the future SQL peer: the design must pin the CAS to the codebase's
  atomic-consume convention — `UPDATE lifecycle SET state='active', history=
  ... WHERE user_id=? AND state='invited'` (affected-rows == 1), with the
  seed branch as `INSERT ... WHERE NOT EXISTS`. The design's
  "conflict → re-read → proceed if winner left ACTIVE" fallback is sound
  only because `Append` is a true CAS; it must remain one in the peer.
- The direction-1 gate (planned) reads the same record in the same request;
  the design's "merge accept+gate into one read" follow-up is the right
  consolidation for the peer (one query per login instead of two).

### 3.2 Hot path 2 — purge terminal sequence (new; decisions 1 + 3): three stores, no transaction

The sequence is `Append(ARCHIVED→PURGED)` (reaction mode) or
`EraseSubject` → `Append` (fail-closed), then `Delete`. There is no
cross-store transaction and the design does not pretend otherwise. The
interleavings and their outcomes:

| Window | Outcome | Covered? |
|---|---|---|
| crash after Append, before erase (reaction) | memory store: record lost on restart, user alive, no audit event; durable store: PURGED record + intact data | Design table covers the durable reading; the memory-store silent-loss case is **not** covered (F-DB-1) |
| erase partial failure | transition stands; 200 + `erasure.errors`; record kept (delete rule) | Yes (Decision 5) |
| erase clean, Append conflict (fail-closed) | 409; orphaned non-PURGED record for a deleted user | Accepted residual — but see F-DB-2 (no repair path) |
| erase clean, Append store error (fail-closed) | 500; same orphan class | **Missing row** (F-DB-2) |
| erase clean, Delete fails | PURGED tombstone persists; repaired on re-provision | Yes (3.3) |

The ordering itself (credentials first, user last) is **Verified** in
`EraseSubject` (`erasure.go:70-84`) and is the right call for the
partial-failure shape.

### 3.3 The only genuinely new atomic primitive: `Store.Delete`

- The design adds `Delete` (idempotent, absent-record → nil). The memory
  implementation must take the existing write lock; Get-after-Delete must
  return `{State: DefaultState}` with empty history (the "no record = ACTIVE"
  anchor, **Verified** at `memory.go:26-33`).
- `Append`'s seed branch (`memory.go:38-43`) already implements the
  no-record CAS the seed writers need — `ErrStateConflict` on any existing
  record is the atomic duplicate-seed guard (2.2's 409). **Verified**
  correct: the check and insert happen under one lock.
- The `Delete`-and-reseed repair in `SeedInvited` is two operations, not
  atomic: a concurrent `Get`/`Append` between them sees the window. For the
  memory store the window is closed by the global lock only if `SeedInvited`
  itself holds it across both (it cannot — it composes `Store` methods).
  Consequence: a concurrent admin transition racing the repair can still hit
  `ErrStateConflict`, which is the design's documented "caller decides
  400/409" path. Acceptable; the durable peer should expose
  delete-and-seed as one transaction.

### 3.4 Existing paths reused unchanged (verified, no new query surface)

- Sweep: `Users.List` full-roster scan + per-user `Get`/`LastActive` —
  unchanged; `ListByState(StatePurged)` consumers: none in production
  (grep-verified), so tombstone removal has no read-path blast radius.
- Eraser refresh leg: O(#clients) per purge — existing compliance behavior,
  reused.

---

## 4. Safe migration sequence, compatibility, rollback, validation

There is **no schema migration** in this design — the lifecycle store has no
durable schema to migrate, and the design adds none. The sequence is
therefore about config, interface growth, and behavioral defaults:

1. **Budget shuffles first (design 6.1/6.3)** — `interfaces/admin/lifecycle`
   subpackage extraction and the `interfaces/sso` option-cluster relocation.
   Zero behavior change; the repo gates (`go build ./... && go vet ./...`,
   `TestMaintainability_|TestArchitecture_`) are the validation. Verify
   `interfaces/admin` root stays at 10 non-test files and
   `interfaces/sso` at 60 (both **Verified** at ceiling today; the design's
   line counts for `lifecycle.go` 481, `options_admin.go` 474,
   `server_login_resolve.go` 413, `server_routes_admin.go` 332,
   `deps.go` 177 are exact).
2. **Interface growth: `Store.Delete`** — compile-enforced breakage across
   the single implementor (`memory.Store`) and test fakes; loud and
   mechanical. Compatibility window: none needed (no external implementors;
   `interfaces/sso` is the only consumer surface, and `WithUserLifecycle`
   keeps its signature).
3. **Config additions (2.5)** — all additive with safe defaults
   (`purge_requires_erasure=false`, `invite.enabled=false`). A stock config
   without the keys parses identically (zero-value structs match the
   documented off-defaults) **except** `accept_on_first_login`, whose
   documented default (`true` when invite is on) needs the `*bool`
   tri-state treatment (F-DB-5). Validation: `config` round-trip tests.
4. **Behavioral rollout order (design Decision 8)** — Decision 1 (PURGED
   semantics), then Decision 2 (seed writers; acceptance trigger is
   direction 1's dependency), then Decision 3 (record lifecycle). Each step
   is independently disable-able and byte-identical when unwired — the
   "unwired = byte-identical" anchor is the rollback story.
5. **Rollback** — remove the config keys / revert the commit. Records whose
   states were already written persist (memory: until restart); a PURGED
   record created by a rolled-back build stays terminal and is repaired by
   re-provisioning (3.3); a record deleted by Decision 3 reads ACTIVE after
   rollback (the anchor, unchanged). No data migration in either direction;
   the audit trail keeps the rolled-back transitions.
6. **Data-integrity checks (store-level, no SQL today)** — after
   purge+delete: `Get` returns `{State: DefaultState}` + empty history;
   `ListByState(StatePurged)` no longer lists the id; after crash-window
   repair: `SeedInvited` over a PURGED record re-seeds with history length 1.
   For the future durable peer: schema-version boot gate (the
   `serverbuildsign.CheckSQLiteSchema` pattern used by every sqlite store,
   `build_app_core.go:62-80`), `CHECK (state IN (...))`-style domain
   constraints, and a unique `user_id` PK.

**Roll-forward** is the normal path: nothing in the design blocks a later
durable peer (F-DB-1 recommendation); the peer implements the same
`Store` + `Delete` contract and is selected in `BuildUserLifecycle`, mirroring
`BuildUserProvider`'s memory|sqlite|postgres selector. The seed/accept CAS
semantics (3.1) are the contract the peer must honor.

---

## 5. Unknown volume, retention, and recovery assumptions

No workload evidence exists for any of these; the design supplies none, and
this review does not invent numbers. The measurements required:

1. **Lifecycle store scale** — record count, transitions/account/day,
   history length distribution. The sweep alone can add ~1 entry/account/
   dormancy cycle (`sweep.go` `apply`); nothing bounds history. Measurement:
   instrument history length in the sweep/admin-GET paths.
2. **Purge latency vs. client registry size** — fail-closed mode executes
   the O(#clients) refresh fan-out inside the request (3.4). Measurement:
   E2E purge with N clients for N in {10, 100, 1000}; set a budget against
   the admin request timeout.
3. **Multi-replica deployment behavior** — divergence window between
   replicas' memory stores, rolling-restart state loss (F-DB-1), and
   double-purge convergence. No deployment evidence exists in-tree.
4. **Backup/restore semantics** — lifecycle records are not backed up (S1
   hot); restoring the users DB from backup yields zero lifecycle records →
   every account reads ACTIVE, INVITED seeds are silently gone. This must be
   stated as the documented restore behavior (or fixed with the durable
   peer).
5. **PURGED tombstone retention** — today unbounded (no `Delete`); direction
   2 removes them on clean erasure; on `Delete` failure they persist until
   re-provisioning repairs them (3.3). No retention policy for the orphan
   state; `ListByState(PURGED)` has no production consumer, so an operator
   currently has no surface to observe orphans.
6. **Audit durability as the compliance record** — the design leans on the
   audit trail as the durable purge/seed record (Decision 8). The audit
   primary sink is memory by default (`BuildPrimaryAuditSink` default
   backend memory, **Verified**). A compliance-significant deployment that
   relies on purge history must set `audit.backend: sqlite|postgres`; the
   design's "audit.enabled:false → bus inert" warning (1.4) is verified
   consistent (`build_app_core.go:200`), but the *memory-sink* case
   (audit on, sink volatile) deserves an explicit config-reference note.

---

## 6. Priority validation tests (database-specific)

Ordered by the findings above:

1. **Restart-loss pin (F-DB-1):** seed INVITED → construct a fresh memory
   store → assert `Get` returns ACTIVE; document this as the contract until a
   durable peer exists.
2. **Fail-closed orphan (F-DB-2):** eraser succeeds, `Append` fails (inject)
   → assert 500, then assert re-provisioning the same id either repairs or
   fails with the documented code.
3. **Delete-rule idempotency (F-DB-3):** eraser over a not-found-returning
   `UserProvider` → assert `UserDeleted` semantics and record outcome.
4. **Exists invariant (F-DB-4):** Get-after-Delete returns empty history for
   the memory peer.
5. **Config tri-state (F-DB-5):** wiring test for
   `accept_on_first_login` unset/true/false × invite enabled/disabled.
6. **AcceptInvitation race:** two concurrent logins, one CAS wins; loser
   re-reads ACTIVE → nil (design 2.1/Decision 7).
7. **Crash-window repair:** PURGED record present, user absent →
   `SeedInvited` re-seeds without `ErrStateConflict`.
8. **E2E purge:** sessions destroyed, tokens revoked across clients,
   `user_deleted:true`, erasure view in the response, GET /lifecycle 404,
   re-provision + login succeeds.
9. **Wiring:** opts counts 0/1/2 (`userlifecycle_wiring_test.go` assertions
   updated per design 6.2); `purge_requires_erasure` with nil eraser → boot
   warning, knob inert.

---

## 7. Verdict

The design's persistence mechanics are sound at the level it claims: the CAS
`Append` is the right atomic primitive, the erasure ordering (credentials
first) is verified correct, the delete rule's intent is right, and the
failure-mode table is unusually honest. The material gap is **the store
itself**: direction 2 (and direction 1 after it) turns a per-process,
restart-volatile map into the enforcement surface for invitation policy and
purge semantics, with silent fail-open on restart and no durable peer in
tree. F-DB-1 and F-DB-2 should be resolved before the acceptance trigger
lands; F-DB-3/4 are contract pins for the inevitable SQL peer; F-DB-5 is a
one-line config fix; F-DB-6/7/8 are documentation and measurement items.
No Critical findings.
