# Review: `domains/permissions` SoD design — distributed-systems pass

Review of `docs/architect-analysis/auto/domains-permissions-sod-design.md` (509 lines) against
`docs/architect-analysis/auto/domains-permissions-sod-spec.md`, the current tree, and the
AGENTS.md engineering/security gates. Role: distributed-systems engineer —
consistency, ordering, atomicity, idempotency, ownership, conflict
resolution, outage/crash/retry/partition/clock behavior, and the
fail-open/fail-closed boundary.

## Evidence standard

Every claim below is labeled **Verified** (read from executable code/gates
this session), **Partial** (verified but with a caveat), **Missing** (absent
from the design), or **Proposed** (design intent, no code). Checks that ran
for this review: file/fan-out counts, all cited line anchors, the proto
files, both backends' transaction machinery, the ext-authz seam, the bundle
cache + invalidation bus, and the audit classification path. No `go build`/
`go test` ran (review-only; no code changed). Where the design and the tree
disagree, the tree wins.

## 1. State map

New state introduced by this change, plus the existing state it couples to.
"Owner" = the only writer. All new state is owned by the permissions
provider; the SSO server (login/logout hooks) writes only via the provider
interface.

| State | Owner (writer) | Store | Durability | Consistency | Replication | Failover |
|---|---|---|---|---|---|---|
| SSoD declarations (`permissions_sod_conflicts` / `ssodConflicts`) | `SoDAdminService.SetConflictSets` (admin); provider-internal | memory map / sqlite+pg table / redis doc | memory: none; durable backends: committed row/doc | Atomic whole-table SET per client (validate-before-write, no partial); last-writer-wins | Shared store (sqlite file / pg / redis) = one logical copy; memory = per-replica fork | No quorum/fencing; writer serialization per backend: memory mutex, sqlite `BEGIN IMMEDIATE` (multi-process needs busy_timeout), pg SERIALIZABLE+retry, redis single-slot Lua. **Verified**: `SetMaxOpenConns(1)` (sqlite.go:85), `runTx(serializable)` (postgres/tx.go:31), hash-tagged Lua keys (redis/permissions.go:66-78) |
| DSoD declarations (`permissions_activation_conflicts` / `dsodConflicts`) | `SetActivationConflictSets` | same | same | same as SSoD, independent table | same | same |
| Active sessions (`permissions_active_sessions` / `activeRoles`) | Login auto-activation (Proposed), `ActivateSessionRoles` (admin), `DeactivateSession` (logout/revocation hooks) | same + redis TTL | durable backends: committed; redis: TTL-bound | Atomic per `(user, client, session)` key; SET semantics; delete-vs-read races resolve deny-safely | Shared store = one logical copy; memory = per-replica fork | Store outage at write: fail-open with audit (login/logout); at read: fail-closed (`Internal`, no decision) |
| Assignments/roles/menus (existing) | admin RPCs + SCIM | same four backends | durable | Now read inside the SSoD check transaction on durable backends (isolation upgrade — **Partial**: today sqlite `AssignRoles` is a bare upsert, pg `AssignRoles` a bare upsert; only pg `UnassignRoles`/`AddRoleToUser` run SERIALIZABLE) | shared store | unchanged |
| Policy-bundle cache (existing) | role/menu mutations fire `invalidateAuthzPolicy` | per-replica in-memory, 5 min TTL | n/a | Local clear + `KindAuthzPolicyChange` bus publish; publish failures fail open to TTL | Bus-invalidated cross-replica; recovery re-subscribes and flushes | **Verified** (server_discovery.go:134-152, server_discovery_cache.go:246). Bundle today carries roles + wildcard semantics only — no SoD content (**Verified**, policy_bundle.go:29-53) |
| OIDC sessions (existing) | login/session manager | session store, `cfg.Server.SessionTTL` | durable | liveness read by mesh gate | shared store | mesh gate fails closed on liveness-store error (**Verified**, mesh_authz.go:226-252) |

Failover: the design inherits the single-store model — no quorum, no
leader election, no fencing. Correctness under failover comes entirely from
per-backend atomicity + the fail-closed decision point. That is adequate
for this feature **provided** the findings below are pinned; the design
does not say so explicitly.

## 2. Findings (severity-sorted)

### F1 — High — The "Consume" row: the mesh gate is not a `Check` caller today, and the design leaves the session-scoped verdict unmapped in the mesh path

**Evidence (Verified):** `MeshAuthorize` (mesh_authz.go:154-204) is a DENY
ladder — token → DPoP → mTLS → residency → session liveness → ALLOW. It
never evaluates a permission. The only permissions touch is
`deriveMeshIdentity` (mesh_authz.go:305-326): a **fail-open** `Roles`
lookup that feeds the `X-Auth-Roles` header. The documented mesh
enforcement model is sidecar-local: "no per-request Authorizer RPC"
(handlers.go:314-316), enforced from the role-definition bundle
(policy_bundle.go) plus the roles the sidecar already has. The ext-authz
service (infrastructure/extauthz/authz.go) is a wire↔seam mapping with a
binary ALLOW/DENY payload and no "Internal" state.

The design (§3.4 "Consume") says the mesh gate "passes `session_id` into
`Check`" and is "the only first-party caller that ever populates
`session_id`", and claims the fallback row is "unreachable from shipped
code". Three things are unspecified:

1. **Which permission?** `Check` requires a permission code. The mesh
   intercepts arbitrary HTTP requests; the mesh gate has no
   route→permission mapping today.
2. **What does the verdict do?** The design's matrix row "store error →
   `Internal`, no decision" has no representation in
   `MeshAuthorizeResult` (ALLOW/DENY only). DENY on store outage is an
   availability cliff for *all* mesh traffic (today the mesh ALLOWs with
   roles omitted); ALLOW breaks the fail-closed boundary.
3. **How does session scoping reach the sidecar?** If `X-Auth-Roles`
   keeps carrying the full **assigned** set, sidecar-local enforcement —
   the actual mesh enforcement point — stays DSoD-blind. DSoD would be
   inert in the exact topology the bundle/`X-Auth-Roles` design targets.

**Triggering failure:** an implementer follows the design literally: the
mesh gate starts calling `Check(session_id)` with no permission source and
no pinned failure mapping — either total mesh outage or a no-op compliance
control; or skips the `X-Auth-Roles` narrowing and DSoD silently never
enforces in mesh deployments.

**User impact:** mesh-wide outage, or a compliance control that is
audit-visible but inert where it matters.

**Recovery:** revert the mesh hook; the gRPC `Authorizer` path remains
functional.

**Corrective pattern (choose one, pin it in the design):** (a) narrow
`deriveMeshIdentity` to the ACTIVE set when the activator exists and
`claims.SID` is present, keeping the existing fail-open-with-audit posture
on store error — this makes `X-Auth-Roles` the session-scoped input to
sidecar-local enforcement and needs no new permission decision in the
seam; or (b) if a mesh-side permission gate is genuinely wanted, specify
the permission source and the store-down mapping explicitly (DENY, to
match `meshCheckSession`'s already-fail-closed posture — and state that
this flips today's fail-open roles posture). Add the end-to-end test:
login → activate → `MeshAuthorize(sid)` → assert narrowed roles/verdict;
logout → deactivate → assert deny.

### F2 — High — "Activate at session start" is anchored at accessors_handlers.go:69, which is the silent-renewal path only; interactive-login sessions never activate

**Evidence (Verified):** line 69 (`SessionID: claims.SID`) sits inside
`EnforceSilentRenewalPolicy` (accessors_handlers.go:52-54), whose only
caller is `protocols/oidc/handle_silent_renewal.go:130` (prompt=none
renewal). Interactive login mints the `sid` at server_login.go:122
(`SID: session.ID`), server_oauth.go:85, server_finish_login.go:304,
server_login_auth.go:45 — none pass through line 69. The spec anchors the
same wrong line ("accessors_handlers.go session material").

**Triggering failure:** implemented as cited, a fresh interactive login
produces a session with an empty active set; matrix row 3 ("present +
activator → project from `ActiveRoles`; unknown → DENY") denies every
session-scoped check until the session's first silent renewal — or forever
for clients that never silently renew.

**User impact:** after every normal login, all session-scoped mesh/
Authorizer checks deny. The design's headline guarantee — "fresh sessions
behave exactly like today (session-scoped Check == assigned Check)" —
fails for the primary login flow.

**Recovery:** activate at the sid-minting sites or at session creation.

**Corrective pattern:** enumerate the real session-start sites
(server_login.go:122, server_oauth.go:85, server_finish_login.go:304,
server_login_auth.go:45) or define activation explicitly as lazy
first-silent-renewal with the interim deny documented. Pin the write
failure semantics (fail-open with audit, bounded timeout) at each site. If
the hook stays at line 69, note the one good property: silent renewal is
also the session-TTL-extension path, so the redis active-set TTL would be
renewed there — but the design must then say interactive-only sessions are
born without an active set, deliberately.

### F3 — Medium — Session-scoped `Check` on the Authorizer path has no session-liveness coupling and no pairwise-subject resolution

**Evidence (Verified):** `AuthzService.Check` (authz.go:27-40) resolves via
`provider.Permissions(ctx, in.SubjectId, in.ClientId)` — no pairwise→local
resolution, no session-manager access. Compare `deriveMeshIdentity`
(mesh_authz.go:318-326), which resolves the local subject before the roles
lookup. `ActiveRoles` (sod.go) returns only the stored row; "expired" is
knowable only from row absence (deactivate/TTL/sweep).

Two consequences the design does not address:

1. **Pairwise clients:** a sidecar calling `Authorizer.Check` with a
   pairwise `subject_id` + `session_id` looks up `ActiveRoles(pseudonym,
   …)` → empty → DENY. False denials for every pairwise client that opts
   into session scoping. The mesh gate resolves the local subject for its
   roles lookup, but the design never says the session-scoped `Check`
   must be called with the resolved subject.
2. **"Missed deactivate is deny-only" is wrong for this path.** The
   design's failure-mode text (§3, "Logout without deactivate … deny-only")
   holds only behind the mesh gate's independent liveness check
   (`meshCheckSession`, fail-closed). On the raw Authorizer path, a
   lingering active-set row (missed hook, revocation by jti without sid,
   session expiry before sweep/TTL) keeps granting the activated subset to
   a dead session's sid for as long as a valid access token presents it.
   Bounded by token TTL and active-set TTL, and never exceeding the
   assigned set — but it is a grant, not a deny.

**Corrective pattern:** (1) resolve the local subject in the session path
or explicitly restrict session-scoped `Check` to local subjects and say
so; (2) document that `Authorizer.Check(session_id)` cannot distinguish
"dead session" from "never activated" and must only be used where the
caller independently verifies liveness; (3) pin the active-set TTL source
(see F5c).

### F4 — Medium — Auto-activation of the full assigned set makes the headline DSoD use case inoperable through the first-party path

**Evidence (Verified):** `ActivateRoles` validates assignment, then scans
SSoD+DSoD tables over the requested set (sod.go). The design auto-activates
the **full assigned set** at session start. A subject legitimately holding
a DSoD-exclusive pair (the headline scenario — conformance
`testSoDDynamicHoldBothActivateOne`) therefore hits `ErrRoleConflict` at
**every** login; the design's own outcome is "audit + empty active set".
Activation is keyed `(userID, clientID, sessionID)` (sod.go doc) and `sid`
is per-session (server_login.go:122), so an operator's subset activation
covers one session only; the next login starts empty again and denies
again.

**User impact:** every session of a DSoD-pair user is born denied at the
mesh gate until an operator manually activates a subset — per session, per
login. The compliance property holds (deny), but the product scenario
("hold both, pick one per workflow instance") is not operable without
per-session admin toil; the design names a "future self-service" that is
out of scope.

**Recovery:** per-session admin activation; audit trail shows the repeated
conflict.

**Corrective pattern:** the design should either (a) keep full-set
auto-activation only when the full set is conflict-free and *state the
per-session operational cost* for DSoD-pair users in the feature matrix,
or (b) add a small admin-declared per-user default-active-set that
auto-activation applies when the full set conflicts (additive; keeps the
decision fail-closed). Do not guess a conflict-free subset in code.

### F5 — Medium — Redis peer: cascade, key escaping, hash tags, and TTL are unspecified; as written the cascade cannot be atomic and the key format breaks cluster-slot discipline

**Evidence (Verified):** every redis permissions key carries a `{clientID}`
hash tag so multi-key Lua stays single-slot (redis/permissions.go:66-78);
`removeRoleScript` builds per-user akeys dynamically (line 146-175). The
design's proposed keys — `perm:sod:{client}`, `perm:dsod:{client}`,
`perm:active:{user}:{client}:{session}` — (a) drop the `sso:perm:` prefix
(style), (b) place no hash tag on `clientID` in the active key, (c) embed
the sessionID raw — and `SessionRoleActivator`'s doc says sessionID is
"caller-defined and opaque" — and (d) provide **no per-client index** of
active-session keys, so stripping a removed role from every active row for
a client (the design's own cascade requirement) cannot be expressed in one
Lua script: SCAN is not atomic, and a client-side scan + per-key Lua lets
a concurrent `ActivateRoles` re-add the stripped code between scan and
strip — the deleted-then-recreated silent-reactivation hole the design
explicitly closes on sqlite/postgres stays open on redis.

**Corrective pattern:** pin the redis layout in the design: hash-tagged
`{clientID}` keys plus either an index SET of active-session keys per
client (mirroring `sso:perm:assign:<client>:users`) or a per-client HASH
whose fields are escaped `user\x00session` keys, so the cascade runs in
one single-slot script; escape or hash userID/sessionID (NUL or hex)
exactly as the memory `sessionKey` does; TTL per F3.

### F5c — Medium — The active-set TTL has no source: "aligned to the OIDC session lifetime" is unwired

**Evidence (Verified):** the redis permissions provider is constructed
without any TTL input today (its doc even notes "TTL/eviction can't apply
here", redis/permissions.go:328); the OIDC session lifetime is
`cfg.Server.SessionTTL` consumed by `BuildSessionManager`
(build_app_core.go:48). The design's redis TTL and the sqlite/postgres
sweep both key off "the OIDC session lifetime", but no plumbing or config
knob is specified, and the conformance suite cannot exercise TTL (the
design admits the drift risk). A TTL shorter than the session lifetime
produces mid-session silent denials; longer produces stale grants (F3).

**Corrective pattern:** plumb `cfg.Server.SessionTTL` (or a dedicated
knob) into the redis permissions provider and the sweep, pin the value in
doc comments, and add an integration test with an injected short TTL.

### F6 — Medium — `invalidateAuthzPolicy` on conflict-set declarations busts a cache whose content the declarations do not change

**Evidence (Verified):** `PolicyBundle` "deliberately carries ONLY role
definitions" (policy_bundle.go:29-53). `invalidateAuthzPolicy` →
`InvalidateAuthzPolicyBundleCache` (server_discovery.go:134-152) clears the
local cache and publishes `KindAuthzPolicyChange` on the bus; the bundle
re-renders byte-identical bytes (same ETag → sidecars get 304). The
mechanism is correct and cross-replica (bus + 5 min TTL backstop + recovery
flush — **Verified**, server_discovery_cache.go:246), but the justification
"a conflict-set change alters every future assignment/activation outcome
and must bust the policy-bundle cache" does not hold for the bundle as it
exists: it alters **decisions**, not **bundle content**. The analysis doc's
方向 3 (analysis line 43) separately proposes adding SoD sets to the
bundle; the invalidation only becomes load-bearing if/when that lands.

**Corrective pattern:** either cross-reference 方向 3 and state that the
declaration invalidation is forward-compatible with a bundle that will
carry conflict sets (and that the bundle extension is part of the same
release), or drop the invalidation until the bundle carries the content.
As written, it is dead code with a misleading justification.

### F7 — Low — Postgres: reuse the existing `runTx(SERIALIZABLE)+40001` pattern instead of introducing `SELECT ... FOR UPDATE`

**Evidence (Verified):** pg `UnassignRoles`/`AddRoleToUser` already run
under `runTx(ctx, p.db, serializable, …)` with the 40001 retry
(permissions_assignments.go:47-53, 93-96; tx.go:31; migrate.go:26-60,
`serializableMaxRetries = 5`). tx.go's doc explicitly describes this
change's race: "plain PostgreSQL defaults to READ COMMITTED, under which a
SELECT (no FOR UPDATE) followed by a write does NOT serialize … SERIALIZABLE
(SSI) detects the read/write dependency and aborts one side". The design's
`SELECT ... FOR UPDATE` on the client's conflict row locks **nothing** when
the row does not exist (first declaration per client), leaving a
declare-vs-assign race that only the documented non-retroactive semantics
backstop; SSI detects the write skew and retries. The existing pattern is
also CockroachDB-safe (the package explicitly targets both dialects).

**Corrective pattern:** "reuse `runTx(serializable)` + `withRetry` for
`AssignRoles`/`AddRoleToUser`/`ActivateRoles` check-and-write" — one
pattern, no new isolation machinery. Keep the design's concurrent-assign
conformance subtest (`-count=10+`) as the proof.

### F8 — Low — Subtest counts in the design (and spec) are wrong: 10, not 11; 5+5, not 5+6

**Evidence (Verified):** `permissionstest/conformance.go:61-70` registers
ten SoD subtests; `sod_conformance.go` contains five `SoDProvider` skip
sites and five `SessionRoleActivator` skip sites. The design says "all 11
SoD subtests" and "`SoDProvider` in 5 subtests, `SessionRoleActivator` in
6". (The third type-assert inside `testSoDStaticConflictBlocksAddRoleToUser`
is `GroupMembershipWriter`, not SoD.) No code impact; correct the counts so
the skip→fail acceptance is measured against the right number.

### F9 — Low — "Existing maintenance cadence" for the active-session sweep does not exist

**Evidence (Verified):** no sweep or maintenance loop touches the
permissions sqlite/postgres tables today. Sweeper patterns exist in cmd
(`startBreakGlassSweeper`, `startTokenAnomalySweep`,
`startUserAutoDeprovisionSweep` — build_app_security.go,
build_stores.go:355-360) but none for permissions.

**Corrective pattern:** the design should say "a new sweeper following the
`startBreakGlassSweeper` pattern", with its cadence and clock source (see
F10), not "the existing maintenance cadence".

### F10 — Low — Sweep clock assumptions: `activated_at` written by Go means replica wall clocks decide retention

**Evidence (Verified):** the design's schema is
`activated_at TEXT NOT NULL DEFAULT ''` — a Go-side timestamp. The sweep
compares it against local `now`. Clock rollback delays reclamation
(rows linger → stale grants, bounded per F3); clock forward deletes early
(premature deny — fail-closed direction). Both directions are deny-safe at
the decision point, but the window is clock-dependent.

**Corrective pattern:** write DB-side timestamps (`CURRENT_TIMESTAMP`) or
document UTC wall-clock semantics plus the deny-safe direction, and add a
sweep test with a skewed clock.

### F11 — Low — Spec/design contradiction on post-deactivate `Check` semantics; the design pins one row without flagging the other

**Evidence (Verified):** the spec's acceptance text says "`DeactivateSession`
clears the session, after which session-scoped `Check` falls back to the
assigned set" — the opposite of the design's matrix row 3 (empty active set
→ DENY) and of the spec's own "unknown/expired → deny" sentence.

**Corrective pattern:** the design should record that it overrides the
spec's acceptance line with DENY (fail-closed) and the spec's acceptance
test must be corrected in the same change, or the enforcement change ships
with a test asserting the weaker behavior.

### F12 — Info — Admin-logout deactivate hook: verify the admin bearer token carries the OIDC `sid`

**Evidence (Partial):** `handleAdminLogout` (server_admin_handlers.go:427)
validates the admin bearer token and revokes by jti; admin tokens are
admin-flow tokens with their own session machinery
(interfaces/admin/middleware.go:396-405). Nothing verified shows the
permissions user's OIDC `sid` in admin token claims. If absent,
`DeactivateSession` cannot fire there — trim the hook list or specify the
sid source.

### F13 — Info — Repository hygiene: committed `.bak` files

`domains/permissions/memory.go.bak` and `cmd/sso-server/config.yaml.bak`
are committed (**Verified**, `git ls-files`). Not part of this change; no
gate counts them (non-`.go`). Optional cleanup, out of scope per AGENTS.md
"no while-here cleanup".

### F14 — Info — Memory multi-replica becomes fail-closed-deny for session-scoped checks

Previously a memory deployment forked SoD state silently per replica.
After enforcement, a session activated on replica A is denied on replica B
(fail-closed). This is a safety improvement but a silent availability
behavior change; the design should list "memory provider across multiple
replicas" as an unsupported topology for SoD enforcement (durable shared
stores required).

## 3. Scenario table

| Scenario | Mechanics (all Verified against code except where noted) | Outcome | Mitigation in design |
|---|---|---|---|
| Partition: admin declares on replica A, bus partition to B | Local clear + publish fail-open (server_discovery.go:146-151); B serves cached bundle ≤5 min TTL | Stale bundle on B; no SoD content in bundle today → no effect (F6) | TTL backstop; recovery re-subscribe + flush (server_discovery_cache.go:246) |
| Partition: redis slot for active keys unavailable | Check → `ActiveRoles` error → `Internal` (Proposed matrix) | Authorizer denies; mesh verdict unpinned (F1); login activation fails open with audit → session denies | Must pin mesh mapping; decision point fail-closed |
| Crash mid-`ActivateRoles` (durable) | sqlite/pg txn rollback → no partial row; redis Lua atomic | No partial state; client retry is idempotent (SET semantics) | **Verified** validate-before-write + per-backend atomicity (design §2) |
| Crash after token issuance, before login auto-activation | sid minted (server_login.go:122), active set empty | Session-scoped checks deny until first silent renewal — or forever (F2) | Move hook to sid-minting sites (F2) |
| Retry: admin `ActivateRoles` after timeout | SET semantics → idempotent re-run | Correct state; duplicate audit events (no dedup, consistent with `AssignRoles` today) | Document; bounded cardinality held (F6's event design is fine) |
| Retry: concurrent `AssignRoles` both pass check (pg READ COMMITTED) | Both read empty conflict table, both write | Conflicting assignment committed; non-retroactive semantics tolerate it | SERIALIZABLE + 40001 retry (F7); concurrent-assign subtest `-count=10+` |
| First declaration vs concurrent assign (pg) | No conflict row to lock; SSI detects write skew | One side aborts and retries → declaration or assignment wins cleanly | Only `runTx(serializable)` closes this (F7); FOR UPDATE does not |
| Clock rollback (replica) | Sweep defers (Go-written `activated_at` vs local now) | Stale active rows linger → stale grants on raw Authorizer (bounded by token TTL) | DB timestamps or documented UTC (F10); deny-safe direction |
| Clock forward (replica) | Sweep deletes early | Premature deny (fail-closed) | Same (F10) |
| Stale cache (bundle) | 5 min TTL; bus-invalidated; recovery flush | Stale role definitions ≤5 min | **Verified** existing machinery (server_discovery.go) |
| Dependency outage: permissions store down at login | Activation fails open with audit (Proposed) | Login succeeds; all session-scoped checks deny — availability cliff, fail-closed | Document the cliff (F2/F4); bounded activation timeout |
| Dependency outage: store down at `Check` | `Internal`, no decision (Proposed) | Authorizer: caller decides; mesh: unpinned (F1) | Pin mesh mapping (F1) |
| Dependency outage: store down at logout | Deactivate fails open with audit (Proposed) | Stale row → stale grants on raw Authorizer until TTL/sweep (F3); mesh liveness still denies | Acceptable if F3's liveness caveat is documented |
| Session expiry vs redis TTL drift | TTL < session lifetime → mid-session deny; TTL > → stale grants | Availability or staleness surprise | Pin TTL source (F5c); integration test with injected TTL |
| Recovery sequencing | Store returns; bus re-subscribes + flushes caches; next login re-activates; sweep reclaims rows | Self-healing; no re-seeding needed (declarations are store-resident) | Verified recovery path (server_discovery_cache.go:246) |

## 4. Stated guarantees, unsupported topologies, validation, residual risks

### Guarantees the design states and the tree can support (Verified)

- **Atomic check-and-write per backend**, no partial writes: memory mutex;
  sqlite `BEGIN IMMEDIATE` (correct — `SetMaxOpenConns(1)` is per-process
  only, and multi-process WAL upgrades need IMMEDIATE); pg SERIALIZABLE +
  retry (pin `runTx`, F7); redis single-slot Lua (pin layout, F5).
- **Validate-before-write** for declarations and activation; rejected calls
  are no-ops.
- **SET semantics everywhere** → all seven admin RPCs are retry-idempotent.
- **Fail-closed decision point**: store error → `Internal`, no decision;
  unknown session → deny; activation can never exceed the assigned set.
- **Fail-open with audit** at login availability and logout.
- **Non-retroactive `SetConflictSets`** (documented in sod.go) with
  `ActivateRoles` SSoD re-check as defense-in-depth — the design's
  backstop for the declare-after-assign gap is sound.
- **RemoveRole cascade** strips active sets (sqlite/postgres pattern
  verified — `collectRoleStrips`/`applyRoleStrips`; redis pending F5).
- **Oracle-safe SoD error family**: one wire code per failure class;
  `ConflictDetails` in status details + audit only. Correct — keeps the
  pair out of the code.
- **Cross-replica invalidation** for the bundle cache via the bus with
  recovery flush (Verified); publish failures fail open to TTL.

### Unsupported topologies / behaviors that must be documented

- Memory provider across multiple replicas for SoD enforcement (F14).
- Raw `Authorizer.Check(session_id)` without caller-side session liveness
  (F3) — the design must say this out loud.
- Redis cluster without hash-tagged keys and a per-client active-session
  index (F5).
- sqlite file shared across processes without `busy_timeout` +
  `BEGIN IMMEDIATE` (production DSNs set neither; only test DSNs do —
  **Verified**, sqlite_test.go:16).
- First-party mesh use of DSoD for subjects holding a DSoD pair (F4) —
  per-session admin toil until self-service activation exists.

### Validation tests (must run, mapped to the design + this review)

1. Conformance: all 10 SoD subtests (F8) run, no skip, on
   memory/sqlite/postgres/redis — skip→`t.Fatalf` as designed.
2. New conformance subtests: concurrent `AssignRoles` (pg, `-count=10+`),
   concurrent declare-vs-assign, concurrent `ActivateRoles` vs
   `DeactivateSession`.
3. Durability: restart-and-reread; cross-replica visibility on shared
   stores (spec §2 acceptance).
4. Cascade: `RemoveRole` strips every active row for the client, per
   backend including redis (F5); deleted-then-recreated code never
   reactivates.
5. `UnionPermissions` identity: `Permissions(user, client) ==
   Union(ActiveRoles(user, client, session))` when the full set is
   activated (design §3.3).
6. Mesh end-to-end: login → activate → `MeshAuthorize(sid)` → narrowed
   roles / pinned verdict; logout → deactivate → deny (F1).
7. Pairwise subject: session-scoped `Check` with a pairwise sub resolves
   the local subject (F3).
8. TTL/sweep: injected short TTL; skewed clock (F5c, F10).
9. Spec acceptance conflict: post-deactivate `Check` semantics resolved
   before implementation (F11).
10. Gates: `go build ./... && go vet ./...`, maintainability/
    architecture tests, `buf generate`, `make ci`, race with `-count=10+`;
    drift gates for `auditreport` classification, `docs/error-codes.md`,
    `docs/feature-matrix.md`, `docs/openapi.yaml` (all four required by
    the design and verified to be gated).

### Residual risks (accepted if the findings above are pinned)

- TTL drift between redis TTL and the sqlite/postgres sweep; the suite
  cannot exercise TTL — pin values and add the integration test (F5c).
- Stale active-set grants on the raw Authorizer path, bounded by token TTL
  and active-set TTL (F3).
- Bus publish failure leaves ≤5 min stale bundle (fail-open, Verified —
  acceptable, and moot until the bundle carries SoD content, F6).
- Postgres retry budget: `serializableMaxRetries = 5` is designed for
  CockroachDB contention; the new txn shape adds a hot per-client row —
  verify the budget under the concurrent-assign subtest.
- First-declaration race resolves to the documented non-retroactive
  semantic; acceptable, but the design should state it (F7).
- The spec/design contradiction in F11 must be resolved before any test
  is written, or the enforcement change ships with a test asserting the
  wrong (weaker) behavior.

### Bottom line

The design's three decisions are sound in shape — separate `SoDAdminService`
in `grpcserver` (gate-correct, Verified), three-table durable storage with
per-backend atomic check-and-write (pattern-correct; pin `runTx` for
postgres and the redis layout), and session-scoped `Check` with a
fail-closed matrix (correct direction). Before implementation: fix F1 and
F2 (both would ship a broken or inert feature), pin F3/F5/F5c, resolve F11,
and correct F8. Nothing in this review relaxes a gate or the
fail-open/fail-closed boundary; F1 is the only place the boundary is
currently ambiguous.
