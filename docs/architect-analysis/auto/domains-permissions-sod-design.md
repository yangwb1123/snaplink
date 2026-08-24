# Design: `domains/permissions` — SoD as an operable compliance control (方向 2)

Design counterpart to `docs/architect-analysis/auto/domains-permissions-sod-spec.md`. Covers the
API surface, storage model, failure modes, and breakage risks for the three
improvements (admin surface, durable backends, session-scoped enforcement).
Every decision below was checked against current code and the AGENTS.md
budgets; where the spec proposed a location that would breach a gate (the
`grpcadmin` fan-out), this document says so and relocates, and where the spec
left a decision matrix incomplete (session-aware `Check` with a provider that
does not implement the activator; what "activate at login" activates), this
document pins the missing row.

## Shipped implementation status (2026-08-21)

This design is now an implementation record. The shipped wire contract keeps
the methods on `PermissionAdminService`, implemented in
`interfaces/grpcserver/grpcadmin/admin_domains.go`; the separate
`SoDAdminService` and `sod_admin.go` described in the historical alternative
below were not introduced because the existing service and file split satisfy
the fan-out gate. The shipped routes are `/sod/conflicts`, `/dsod/conflicts`,
and `/sessions/{session_id}/roles`.

Durable providers use normalized SQLite/Postgres conflict and active-role rows
and Redis hash-tagged keys. SQLite's default constructor enables immediate
transaction locking and a busy timeout; Postgres uses serializable retries;
Redis TTL is opt-in through `NewPermissionProviderWithActiveSessionTTL` and is
not a stock `permissions.backend` configuration field. The 11 SoD conformance
cases run for first-party providers.

Session activation is wired after central session creation and deactivated on
logout/destroy. The Authorizer boundary resolves the local subject and checks
session liveness when configured; invalid sessions deny, active-role
projections are authoritative, and deactivation never falls back to assigned
roles. Decision audit records carry bounded reason/session/resource context,
and the OPA parity test evaluates `docs/examples/opa-authz-policy.rego` with
the direct test dependency `github.com/open-policy-agent/opa/v1/rego`.

The decision sections below retain the original design alternatives for
traceability; this status block supersedes any conflicting placement, method,
route, or post-deactivation claim.

Layer map used throughout:

```text
composition (cmd/sso-server, interfaces/sso)
  → interfaces (grpcserver, grpcadmin)
  → protocols (oauth/oauthvalidate)
  → domains (permissions)
  → platform, shared
```

Verified constraints that shape every decision:

- `interfaces/grpcserver/grpcadmin/` has exactly 10 non-test files — the
  fan-out ceiling. `admin_permissions.go` is 264 lines; 7 new RPCs at the
  established pattern (~20-25 lines each) would land near 440 lines and the
  file would be at ~90% of the 500-line budget with zero tolerance left.
- `interfaces/grpcserver/` has 6 non-test files (`aliases.go`, `audit.go`,
  `authz.go`, `discovery.go`, `netpolicy.go`, `recovery.go`) — room for one
  new file, no more.
- `domains/permissions/` has 10 non-test files — the ceiling. No new file
  may be added there.
- `interfaces/sso/` is at its frozen 60-file ceiling — no new file.
- Proto regeneration is `cd proto && buf generate` (Makefile:172), which
  also emits the `.pb.gw.go` grpc-gateway files.
- `grpcadmin.NewPermissionAdminService(prov, recorder, invalidateAuthzPolicy)`
  (admin_permissions.go:37) is the pattern to reuse. The audit helpers
  `recordAdmin`/`recordAdminMeta` are unexported in `grpcadmin`
  (admin_paginate.go:205-214) and derive the actor from
  `sso.AdminActorFromContext` (`interfaces/sso/options_admin.go`) plus
  `peer.FromContext` — `sod_admin.go` carries a local copy of that small
  derivation (same two imports, same fields) rather than exporting from
  grpcadmin, keeping the packages decoupled.

## Historical design alternative: admin surface — `SoDAdminService` in the proto file, implemented in `grpcserver`, not `grpcadmin`

### Problem restated

`SoDProvider`/`SessionRoleActivator` (`domains/permissions/sod.go`) have no
server surface: `SetConflictSets`/`ActivateRoles` are reachable only from
tests, and `ConflictError{ClientID, Set, Roles}` — built expressly for admin
explanations — is never returned by any transport.

### API surface

**1. Proto: additive service in the existing file, not new methods on
`PermissionAdminService`.** The spec says "extend `PermissionAdminService`
(additive)". Adding seven methods to that service forces their Go
implementation into the `grpcadmin` package (methods on a type live in its
package), and `grpcadmin` is at the 10-file ceiling: a new file there fails
the fan-out gate, and folding ~175 lines into `admin_permissions.go` puts it
at ~440/500 lines with no headroom. So the wire surface keeps the spec's
intent — same proto file, same package, same REST prefixes — as a separate
service:

```proto
service SoDAdminService {
  rpc SetConflictSets(SetConflictSetsRequest) returns (SetConflictSetsResponse);                 // SSoD
  rpc ListConflictSets(ListConflictSetsRequest) returns (ListConflictSetsResponse);
  rpc SetActivationConflictSets(SetActivationConflictSetsRequest)
      returns (SetActivationConflictSetsResponse);                                                // DSoD
  rpc ListActivationConflictSets(ListActivationConflictSetsRequest)
      returns (ListActivationConflictSetsResponse);
  rpc ActivateSessionRoles(ActivateSessionRolesRequest) returns (ActivateSessionRolesResponse);
  rpc ListActiveRoles(ListActiveRolesRequest) returns (ListActiveRolesResponse);
  rpc DeactivateSessionRoles(DeactivateSessionRolesRequest) returns (DeactivateSessionRolesResponse);
}
```

Adding a service to a STABLE package is additive under
[ADR-0008](docs/adr/ADR-0008-proto-versioning.md): existing clients never
call the new RPCs, and an old server answers them with `UNIMPLEMENTED`
(server and client ship together here). This also matches the placement
already reserved in `docs/architect-analysis/auto/domains-permissions-design.md` (decision 2),
so the two changes cannot collide.

REST via `google.api.http` annotations, scoped by `client_id` exactly like
the existing eight RPCs, and by `user_id`+`session_id` for session state:

```
PUT    /api/v1/admin/permissions/{client_id}/conflicts                  # SSoD replace (body: sets)
GET    /api/v1/admin/permissions/{client_id}/conflicts
PUT    /api/v1/admin/permissions/{client_id}/activation-conflicts       # DSoD replace
GET    /api/v1/admin/permissions/{client_id}/activation-conflicts
POST   /api/v1/admin/permissions/{client_id}/users/{user_id}/sessions/{session_id}/roles   # activate
GET    /api/v1/admin/permissions/{client_id}/users/{user_id}/sessions/{session_id}/roles   # list active
DELETE /api/v1/admin/permissions/{client_id}/users/{user_id}/sessions/{session_id}         # deactivate
```

Request messages: the four conflict RPCs carry `client_id` plus
`repeated ConflictSet sets` (`ConflictSet { repeated string roles = 1; }` —
a bare `repeated repeated string` is not expressible in proto3). Session
RPCs carry `client_id`, `user_id`, `session_id`, and (activate) `roles`.
`ActivateRoles` in the domain already has SET semantics and validates
before writing, so the admin RPCs are thin projections of the memory
semantics, exactly like `AssignRoles`.

**2. Implementation home: new file `interfaces/grpcserver/sod_admin.go`.**
`NewSoDAdminService(prov permissions.Provider, recorder *audit.Recorder,
invalidateAuthzPolicy func(context.Context, string))` mirrors
`NewPermissionAdminService` (plain callback, never the whole `*sso.Server`,
keeping the dependency one-directional). grpcserver goes 6/10 → 7/10 files;
`admin_permissions.go` is untouched. Audit emission uses a local
`recordAdminMeta`-equivalent (actor via `sso.AdminActorFromContext`, peer
IP via `peer.FromContext` — the same derivation `grpcadmin` uses, since
its copy is unexported). Registration adds two lines mirroring
`cmd/sso-server/main_servers.go:225` (`RegisterSoDAdminServiceServer`) and
`cmd/sso-server/build_http.go:437` (`RegisterSoDAdminServiceHandlerServer`),
which is what makes the REST routes above real.

**3. Error mapping** (one code per failure class; oracle-safe within the SoD
family — a violation is a violation, the pair is not part of the code):

| domain error | gRPC code | gateway HTTP | wire code |
|---|---|---|---|
| `ErrInvalidConflictSet` | `InvalidArgument` | 400 | `invalid_conflict_set` |
| `ErrRoleNotAssigned` | `FailedPrecondition` | 400 | `role_not_assigned` |
| `ErrRoleConflict` | `FailedPrecondition` | 400 | `role_conflict` |

`ErrRoleConflict` carries a new additive message `ConflictDetails
{ client_id, set, roles }` attached via `status.WithDetails` — this is the
"details" the spec asks for, and it keeps the machine-readable pair out of
the error CODE while giving admin UIs the `ConflictError` contents. The
same fields go into audit meta (details in audit only, per AGENTS.md §3).

**4. Audit events and invalidation.** Four new event types declared in
`auditspi` (`event_types_admin.go` region), aliased in
`platform/audit/aliases_spi.go`, and classified in
`auditreport/control_areas.go` — the `auditreport` drift test fails until
classification exists, which is the gate doing its job:

- `admin_sod_conflicts_set`, `admin_dsod_conflicts_set` (declaration
  replaced; meta carries the set count, never role values inline in the
  event type — bounded cardinality),
- `admin_session_roles_activated`, `admin_session_roles_deactivated`
  (meta: `user_id`, `session_id`, `roles`).

`invalidateAuthzPolicy(ctx, clientID)` fires on the four declaration RPCs:
a conflict-set change alters every future assignment/activation outcome and
must bust the policy-bundle cache. Session activation/deactivation does NOT
fire it (per-subject state, never in the bundle; the bundle cache is
untouched).

### Failure modes

- **Provider nil / store down on a declaration RPC**: `FailedPrecondition`
  / `Internal` — declarations are writes; failing them is correct.
- **`ActivateRoles` rejected mid-way**: the domain validates the whole
  request (assignment check, then SSoD+DSoD conflict scan) before any write,
  so a rejected call is a no-op — no partial activation, same guarantee the
  memory peer gives under its lock.
- **Concurrent declarations (SET semantics)**: last writer wins, like
  `SetMenus`/`AssignRoles` today; a lost update is an operator race, and the
  List RPCs let the loser see the winner's table. Documented, not mitigated
  — matching every other whole-table-replace admin RPC.

### What could break the design

- The spec's literal placement ("implement in `grpcadmin`", "extend
  `PermissionAdminService`") fails the fan-out gate and crowds
  `admin_permissions.go` to ~90% of the file budget. The relocation to
  `grpcserver/sod_admin.go` is mandatory; it changes no wire contract (same
  proto file/package/paths, new service type).
- Forgetting `buf generate` after editing the proto breaks both transports
  at once (stale `.pb.go` compiles, stale `.pb.gw.go` has no REST routes);
  the bufconn + REST acceptance tests are what catch it.
- `ConflictDetails` must stay a detail carrier. If a future change turns the
  pair into distinct codes, it breaks oracle-safety for the SoD family and
  the error-code table must not allow it.

## Historical design alternative: storage model — three tables per durable backend, atomic check-and-write everywhere

### Problem restated

Only `MemoryProvider` implements `SoDProvider`/`SessionRoleActivator`
(compile-time asserts in `sod.go`), so declarations and activations vanish
on restart and fork per replica — and `permissionstest/sod_conformance.go`
institutionalizes the gap by type-asserting and skipping all 11 subtests.
The state model is three JSON-able maps (`ssodConflicts`, `dsodConflicts`,
`activeRoles` keyed `userID\x00clientID\x00sessionID`), trivially mappable
to tables.

### Storage model

**sqlite** — append migration v2 to `domains/permissions/sqlite/sqlite.go`
(the versioned `platform/migrate` scheme; existing DBs get v2 applied):

```sql
CREATE TABLE IF NOT EXISTS permissions_sod_conflicts (
    client_id TEXT PRIMARY KEY,
    sets_json TEXT NOT NULL DEFAULT '[]'      -- JSON [][]string, SET semantics
);
CREATE TABLE IF NOT EXISTS permissions_activation_conflicts (
    client_id TEXT PRIMARY KEY,
    sets_json TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS permissions_active_sessions (
    user_id    TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    session_id TEXT NOT NULL,
    roles_json TEXT NOT NULL DEFAULT '[]',    -- JSON []string
    activated_at TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (user_id, client_id, session_id)
);
CREATE INDEX IF NOT EXISTS idx_active_sessions_client
    ON permissions_active_sessions(client_id);   -- RemoveRole cascade scan
```

`SET` semantics = read-modify-write of one row (`permissions_sod_conflicts`
upsert with the marshalled table, DELETE on clear — mirroring
`SetConflictSets`). Naming follows the existing `permissions_roles` /
`permissions_assignments` / `permissions_menus` convention. The NUL-free
`sessionKey` invariant carries over: `(user_id, client_id, session_id)` as a
PK triple cannot collide, and no ID may contain NUL — the sqlite/postgres
columns are TEXT and reject nothing, so validation stays Go-side (the same
invariant the memory `sessionKey` relies on; a crafted ID with a NUL would
only ever be its own row, never a spoofed key, because the PK is
triple-column, not delimited — this is strictly safer than the memory key).

**postgres** — identical tables in `infrastructure/postgres/permissions.go`
(`permissionsMigrations` v2, same namespace). Same TEXT-JSON style as the
existing three tables so Go-side marshalling is byte-identical across
backends.

**redis** — `infrastructure/redis/permissions.go` style:
`perm:sod:{client}` and `perm:dsod:{client}` as whole JSON documents
(`GET`/`SET`/`DEL` = SET semantics), and `perm:active:{user}:{client}:{session}`
as a JSON roles document with a TTL aligned to the OIDC session lifetime.
`sessionKey` collision-freedom via the existing key-scoping helpers.

**Atomicity is the sharp edge.** "Reject a conflicting assign with no
partial write" must hold under concurrency:

- sqlite: `AssignRoles`/`AddRoleToUser` move to a single transaction —
  read `permissions_sod_conflicts` for the client + read/upsert the
  assignment inside one `BEGIN IMMEDIATE` (the provider already runs
  `SetMaxOpenConns(1)`, so writers are serialized; IMMEDIATE prevents
  upgrade deadlocks). The Go-side `findConflict` runs on the row read in
  the txn; rejection rolls back — nothing partial. `ActivateRoles` reads
  both conflict tables + the assignment row in one txn.
- postgres: same check-and-write in one transaction; the conflict-table
  read must be race-safe against a concurrent declaration, so it takes
  `SELECT ... FOR UPDATE` on the client's conflict row (or SERIALIZABLE —
  verify the isolation level the peer already uses; the conformance suite
  adds a concurrent-assign subtest that proves it).
- redis: one Lua script per operation (read sets, run the conflict scan in
  the script, write) so check-and-act is atomic; no read-modify-write
  outside the script.
- memory: unchanged single mutex.

**`RemoveRole` cascade** mirrors `stripActiveRole`: extend the existing
`collectRoleStrips`/`applyRoleStrips` machinery (sqlite `assignments.go`,
same pattern in postgres/redis) so one transaction strips the removed code
from `permissions_assignments` AND every `permissions_active_sessions` row
for that client — a deleted-then-recreated role code can never silently
reactivate in a stale session.

**Conformance suite: skip becomes fail.** Convert the two SoD type-assert
sites in `permissionstest/sod_conformance.go` (`SoDProvider` in 5 subtests,
`SessionRoleActivator` in 6) from `t.Skip(...)` to `t.Fatalf(...)`. This
meets the spec's acceptance ("SoD subtests run, no skip, on sqlite and
postgres") in the stronger form: a first-party backend that omits SoD now
FAILS the suite instead of silently passing — which is the entire point of
removing the institutionalized gap. The type-assert stays as the
self-documenting "this interface is optional in the domain" marker, and the
unrelated `GroupMembershipWriter` skip (one subtest) is untouched. Memory +
sqlite + postgres + redis factories all implement both interfaces, so no
skip fires anywhere in the real matrix.

**Retention.** `permissions_active_sessions` grows if `DeactivateSession`
is never called (e.g. a client that never logs out cleanly). Stale rows are
deny-only — an empty or stale active set can never grant — so this is a
retention decision, not a correctness one: redis TTL handles expiry, and
sqlite/postgres get a documented sweep (delete rows whose `activated_at`
predates the configured session TTL) running on the existing maintenance
cadence.

### Failure modes

- **SoD tables down during `AssignRoles`/`ActivateRoles`**: fail closed —
  the mutation errors. Silently skipping a compliance check on a write is
  worse than refusing it (AGENTS.md fail-closed list).
- **Store down during a session-scoped `Check`**: `ActiveRoles` lookup
  error → `Internal`, no decision (see next decision).
- **Check-then-write without atomicity** lets two concurrent
  `AssignRoles` calls both pass the check and interleave writes — this is
  why the transaction/Lua requirement above is a requirement, not an
  optimization. The classic "works on memory, breaks on sqlite" bug lives
  exactly here.
- **Migration ordering**: v2 must be appended, never edited; `migrate.Run`
  stamps versions, and pre-v2 DBs apply v2 on next start. A hand-edited v1
  breaks every existing deployment.

### What could break the design

- `domains/permissions` is at 10/10 files: the shared permission-union
  helper (next decision) must fold into `matcher.go`, never a new file.
- Postgres isolation is the likeliest silent divergence: at READ COMMITTED,
  two concurrent assigns can both pass the conflict check. The
  concurrent-assign conformance subtest is what catches it — it must run
  with `-count=10+` per AGENTS.md.
- Redis TTL vs sqlite/postgres sweep drift: the suite cannot exercise TTL,
  so the redis peer's TTL must be pinned in its doc comment and the
  sqlite/postgres sweep cadence documented to match the same session TTL.
- A future minimal backend that omits SoD now fails the suite. Intentional
  (that is the point), but it makes the "optional" interfaces de-facto
  mandatory for first-party backends — the domain doc comments on
  `SoDProvider`/`SessionRoleActivator` should be updated to say so.

## Historical design alternative: enforcement — session-scoped `Check` over the ACTIVE set, with one shared projection

### Problem restated

Even on memory, `ActivateRoles` output is read by nobody: `authz` `Check`
(`interfaces/grpcserver/authz.go`) always evaluates `Permissions()` — the
full ASSIGNED set — and `CheckRequest` has no `session_id` slot, so
session scoping is not even expressible on the wire. The OIDC `sid` already
flows through the stack (`accessors_handlers.go:69`, `mesh_authz.go:226`,
`server_token_clientauth.go:334`).

### API surface

**1. `proto/authz/v1/authz.proto`**: add `string session_id = 6;` to
`CheckRequest`. Field 6, not 4: `docs/architect-analysis/auto/domains-permissions-design.md`
already reserved 4=`tenant_id`, 5=`resource`, 6=`session_id` for the
resource-catalog change; pinning 6 now keeps both changes compatible
whichever lands first (ADR-0008 forbids renumbering later). `Check` has no
`google.api.http` annotation today (authz is gRPC-only, sidecar-facing), so
there is no gateway route to mirror — the "HTTP gate" requirement is
satisfied by the mesh gate (see 3).

**2. Decision matrix in `Check`** (fills the row the spec left open):

| `session_id` | provider implements `SessionRoleActivator` | evaluation set |
|---|---|---|
| empty | any | full assigned set (`Permissions()`) — byte-identical to today |
| present | no | full assigned set — documented fallback, no error |
| present | yes | permissions projected from `ActiveRoles(user, client, session)`; unknown/expired session → empty active set → DENY (fail closed); store error → `Internal`, no decision |

The middle row is the spec's hole: a caller that sends `session_id` to a
provider without per-session state cannot be scoped by anything — denying
everything would break callers that pass `sid` unconditionally. The
fallback is documented, and the composition root closes the gap: the only
first-party caller that ever populates `session_id` (the mesh gate, see 3)
checks `SessionRoleActivator` before sending it, so the row is unreachable
from shipped code.

**3. One shared projection.** Extract the union loop from
`MemoryProvider.Permissions` (`memory.go:270`) into a domain free function
`permissions.UnionPermissions(roles []Role) []Permission`, folded into
`matcher.go` beside `Matches` (file budget: `domains/permissions` is at
10/10 files). `Permissions()` becomes `Roles()` + `UnionPermissions`;
the session path is `ActiveRoles()` + `UnionPermissions` — one code path
defines both modes. `ActiveRoles` already skips stale role codes the same
way `Roles()` does, so the projection is identical by construction.

**4. Lifecycle wiring** (all in `interfaces/sso`, which is at its frozen
60-file ceiling — helpers fold into existing files, no new files):

- **Activate at session start**: in the `accessors_handlers.go:69`
  session-material path, when the provider implements
  `SessionRoleActivator`, best-effort
  `ActivateRoles(userID, clientID, sid, fullAssignedCodes)`. This is the
  decision the spec leaves open ("activate at login" — with which roles?):
  the full assigned set, so a fresh session behaves exactly like today
  (session-scoped `Check` == assigned `Check`) whenever no DSoD constraint
  applies. If the subject legitimately holds a DSoD-exclusive pair
  (assignable — DSoD only restricts activation), `ActivateRoles` returns
  `ErrRoleConflict`; the login NEVER fails — the conflict is audit-logged
  and the active set stays empty, so session-scoped checks deny until an
  operator (or future self-service) activates a subset. Fail-closed at the
  decision point, fail-open with audit at login availability. Note SSoD
  conflicts cannot occur here: `AssignRoles` already enforces SSoD, so a
  held set is always SSoD-clean.
- **Deactivate on logout/revocation**: a small helper folded into
  `accessors_handlers.go` (beside `RecordLogout`, line 143) calling
  `DeactivateSession(userID, clientID, sid)`; invoked from `RecordLogout`,
  the OIDC end_session path (`handlers.go:171` → `oidc.HandleEndSession`),
  and admin logout (`server_admin_handlers.go:427`) — everywhere the `sid`
  is already in hand. Fire-and-forget, fail open with audit: logout
  availability wins, and a missed deactivate is deny-only.
- **Consume**: the mesh gate (`mesh_authz.go:226` `meshCheckSession`
  region) already reads `claims.SID`; when the provider implements the
  activator, it passes `session_id` into `Check`. This is the spec's
  "mirrored in the HTTP gate".

**5. Contracts in the same change**: `docs/error-codes.md` gains
`invalid_conflict_set` / `role_not_assigned` / `role_conflict` (400, admin
REST via the gateway's InvalidArgument/FailedPrecondition mapping);
`docs/feature-matrix.md` gains an SoD row (SSoD+DSoD declaration, session
activation, session-scoped Check); `docs/openapi.yaml` gains
`CheckRequest.session_id` plus the seven admin routes (regenerated with
`buf generate`).

### Failure modes

- **Store down during session-scoped `Check`**: `ActiveRoles` error →
  `Internal`, no decision — never a silent flip to allow because the store
  is down (same rule as the assigned path's lookup failure).
- **Unknown/expired session**: empty active set → deny. This is the
  fail-closed contract: a caller that opted into session scoping gets
  exactly the active subset, nothing more.
- **Logout without deactivate**: stale row lingers; effect is deny-only
  (empty or stale subset), and the sweep/redis TTL reclaims it.
- **Auto-activation conflict at login**: audit + empty active set; the
  session still logs in, and every session-scoped check denies until a
  subset is activated. The security property holds (deny), availability
  holds (login), and the compliance gap is visible in audit.
- **`ErrRoleConflict` details**: one wire code for every conflicting pair;
  `ConflictDetails` and audit meta carry which pair — details never
  become distinguishable codes (oracle-safe family).
- **Race: `DeactivateSession` vs concurrent `Check`**: delete-vs-read races
  resolve either way to the active-set read before or after the delete —
  both outcomes are deny-safe for a session that is ending.

### What could break the design

- **The `Check` semantic split is the riskiest behavioral change in the
  whole change**: any caller that starts sending `session_id` gets stricter
  answers. Mitigation is the matrix: behavior changes only when
  `session_id` is present AND the provider implements the activator, and
  the only first-party sender is the mesh gate (which checks the
  interface first). Old callers are byte-identical.
- **Multi-client sessions, one `sid`**: activation is keyed
  (user, client, session); a session's `sid` checked against a client that
  never activated it denies (fail closed). The login path activates only
  the origin client. This must be documented in the feature matrix —
  operators may expect one activation to cover all clients.
- **Auto-activation writes on every login**: a new per-login store write
  when the activator exists. Its failure mode is fail-open-with-audit, but
  the write cost and the redis TTL renewal must be part of the login path
  review; if it ever becomes a hot spot, activation can move to
  first-session-check lazily (documented future option, not speculative
  build).
- **Projection drift**: if the session path ever grows its own union loop,
  the two modes diverge (e.g., a dedup or ordering difference silently
  changes decisions). The `UnionPermissions` extraction exists precisely so
  this cannot happen; a conformance subtest asserting
  `Permissions(user, client) == UnionPermissions(ActiveRoles(user, client,
  session))` when the full set is activated pins it.
- **Docs drift gates**: `auditreport` classification, error-codes rows,
  feature-matrix row, and openapi regeneration all fail drift checks if
  omitted — they are part of this change, not follow-ups.

## Decision: sequencing, gate compliance, and what could break the design overall

### Sequencing

Land in this order; each step is independently green:

1. **Storage + conformance** (pure additive: new tables, new interface
   implementations, skip→fail in the suite). No behavior change for any
   caller; `make ci` proves the durable backends.
2. **Admin surface** (proto + `sod_admin.go` + registration + audit events).
   Works against memory immediately; the durable backends from step 1 make
   it multi-replica-correct.
3. **Enforcement** (the only caller-visible behavior change: `session_id`
   on `CheckRequest`, session-aware `Check`, lifecycle hooks, docs). Lands
   last so the decision-path change is isolated from the plumbing.

### Budget compliance (checked against the tree)

- `grpcserver`: 6 → 7 non-test files (`sod_admin.go`); a second file there
  would be the last one — keep `sod_admin.go` under 500 lines or split into
  at most `sod_admin.go` + `sod_admin_sessions.go`.
- `domains/permissions`: unchanged file count (10/10); `UnionPermissions`
  folds into `matcher.go`; `permissionstest` files are tests and exempt.
- `interfaces/sso`: unchanged file count (60-file ceiling); lifecycle
  helpers fold into `accessors_handlers.go`.
- `grpcadmin`: untouched — the spec's literal implementation home fails the
  fan-out gate and is the one mandatory deviation.
- `auditreport` classification for the four new event types is required by
  the drift test, not optional.

### What could break the design (cross-cutting)

- **Spec-literal placement breaching gates**: "implement in `grpcadmin`"
  (fan-out), "new file in `domains/permissions`" (10/10), "new file in
  `interfaces/sso`" (60-file ceiling). All three are relocated above; a
  reviewer should treat any re-introduction as a gate failure.
- **`session_id` field-number collision** with the resource-catalog change
  (reserved 4/5/6): pinned at 6 here; do not renumber to 4 on the theory
  that resources "might not land" — ADR-0008 makes that a breaking change
  later.
- **SetConflictSets not retroactive** is a documented `sod.go` semantic:
  a set declared after a conflicting assignment took effect only blocks the
  NEXT mutation. Admin UI copy must say so, or operators will believe
  existing assignments are safe. `ActivateRoles` checking SSoD too
  (defense-in-depth) is what catches exactly this gap at session time.
- **Conformance skip→fail is intentional but visible**: the suite now
  demands SoD of every first-party backend. If a future backend genuinely
  cannot support it, the conversation must be about capability, not about
  restoring the skip.
- **Behavioral drift between the two design docs**: `domains-permissions-
  design.md` (resource change) and this document both reserve
  `SoDAdminService` in `grpcserver` and `session_id = 6`. If both land,
  the services and fields must be merged in one regeneration pass, not
  stacked as two separate proto edits.
