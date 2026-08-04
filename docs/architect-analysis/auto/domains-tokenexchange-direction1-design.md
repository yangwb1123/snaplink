# Design: `domains/tokenexchange` direction 1 — ChainStore becomes a fail-closed revocation control plane

Design counterpart to `docs/auto/domains-tokenexchange-direction1-spec.md`. Covers the API
surface, storage model, failure modes, and breakage risks for the three
improvements. Every decision below was checked against current code, the
AGENTS.md budgets, and the wire contracts that are regression boundaries;
where the spec left an ambiguity (jti→token gap, deny TTL, subject/actor
mapping for agent mints, root-kill reachability from the admin surface), this
document pins the exact behavior and flags the spec deviation.

Layer map used throughout:

```text
composition (cmd/sso-server)                       ← wires stores; builds the expire closure
  → interfaces/sso (accessors_threat.go)           ← ChainRevoker accessor, expire closure, bus publish, /token/revoke seam
  → interfaces/admin (token_portfolio.go)          ← descendants GET + revoke POST handlers (no new files — ceilings)
  → protocols/oauth (handle_revoke.go)             ← type-asserted optional side-effect, oracle-safe
  → domains/tokenexchange (chainstore.go + chain_revoke.go) ← ChainRevoker SPI + orchestrator; agentidentity child package
  → infrastructure/defaultimpl (3 JWT issuers)     ← jti deny maps + RevokeByJTI + SeedJTIRevocations
  → shared/security, shared/core, platform/{cluster,audit,auditreport,migrate} ← deny primitives, paths, bus, events
```

Non-negotiable constraints re-verified against source:

- `ChainStore` (`domains/tokenexchange/chainstore.go`) keeps its 3-method
  read/append contract. The revocation primitive is a NEW optional extension
  interface so the fake stores in `test/` and package `_test.go` files keep
  compiling (spec acceptance: "the `ChainStore` interface itself gains no new
  method").
- Zero production callers of `GetDescendants` today (grep-verified: only
  `test/token_exchange_chain_store_test.go` and `_test.go` files) — the data
  plane is free to be consumed without a behavior-compat constraint, but the
  sqlite `maxChainWalk` cap (1000) is a silent-truncation hazard the revoke
  path MUST turn into an error (Decision 1).
- The RFC 9068 revocation deny-set is keyed by the FULL TOKEN STRING
  (`j.revoked[token]` in all three issuers; `revocation_set.go` prune-not-early
  discipline), while `ChainHop` records only `jti`. There is **no jti→token
  index anywhere in the codebase** (grep-verified). Every "mark this JTI
  denied" design therefore needs a NEW jti-keyed deny surface consulted by
  `Validate` — this is the keystone decision (Decision 2), not an
  implementation detail.
- File budgets: `interfaces/admin` is at its 10-file ceiling (no new file);
  `lifecycle.go` 481/500, `governance.go` 483/500, `connections.go` 498/500;
  `token_portfolio.go` 404/500 has the only usable headroom and is the
  thematic home (token views). `interfaces/sso/accessors_threat.go` 427/500
  already hosts the chain wiring and has headroom for mounts + accessors.
- Admin middleware scope policy (`interfaces/admin/middleware.go:72`):
  GET → `admin:read`, everything else → `admin:write`. POST routes mounted
  under the existing admin group get `admin:write` for free.
- `agentidentity.RevokeSession` / `RevokeAllForHuman` have ZERO production
  callers today (grep-verified; only a doc mention in
  `interfaces/sso/options_grants.go:410`). Their signatures may change
  freely; the cascade ships test-exercised (spec acceptance is unit +
  integration level) until a future admin surface wires them.
- Import direction: `protocols/oauth` → `domains/tokenexchange` is legal
  (protocols already imports `domains/tenant`); `domains/tokenexchange/
  agentidentity` → parent `domains/tokenexchange` is same-layer legal.
  `domains/tokenexchange` must NOT import `infrastructure/defaultimpl`
  (upward) — the deny-store wiring lives at the `interfaces/sso` layer and is
  injected as a callback.

---

## Decision 1: `ChainRevoker` — optional extension interface carrying the fail-closed cascade primitive

### Problem restated

The forward walk exists and is correct in both backends
(`sqlite/chain_store.go:185` BFS over `idx_tokenexchange_chain_hops_parent`,
`memory/chain_store.go:82` BFS over the children index) but has no consumer
and, critically, no failure semantics: both walks silently STOP at their
visited cap (`maxChainWalk = 1000` in sqlite; the memory walk is unbounded)
and return success. A cascade built on `GetDescendants` as-is would, on a
corrupted/cyclic graph or a >1000-node subtree, silently revoke a subset and
report success — the exact "partial revocation silently dropped" the spec
forbids. Revocation needs a walk that FAILS CLOSED on truncation.

### API surface

New file `domains/tokenexchange/chain_revoke.go` (domains has file
headroom; `chainstore.go` is ~250 lines):

```go
// ExpireFunc marks one chain hop's JTI denied until the hop's recorded
// expiry. Implementations are wired at the composition/interface layer
// (they touch the issuer deny-sets, the durable revocation store, and the
// invalidation bus). An error means "this JTI was NOT denied" and MUST
// abort the cascade (fail-closed).
type ExpireFunc func(ctx context.Context, hop ChainHop) error

// ChainRevoker is the OPTIONAL fail-closed revocation extension of a
// ChainStore. A store that implements it enables every cascade surface
// (admin revoke endpoint, /token/revoke side-effect, agent session
// revocation). Nil store / non-implementing store = byte-identical no-op
// everywhere.
type ChainRevoker interface {
    // RevokeDescendants walks the forward lineage of rootJTI (the same BFS
    // GetDescendants uses, same walk caps) and calls expire for every
    // descendant hop. rootJTI itself is NOT passed to expire — callers
    // kill the root via their own path. Fail-closed: the FIRST expire or
    // walk error aborts the walk and is returned alongside the partial
    // revoked list (never silently dropped — the caller audits both).
    // Idempotent: re-running over an already-marked subtree re-walks and
    // re-marks (deny marks are set-inserts) and succeeds.
    RevokeDescendants(ctx context.Context, rootJTI string, expire ExpireFunc) (revoked []ChainHop, err error)

    // HopsBySession returns every recorded hop whose SessionID matches,
    // newest-recorded first, bounded. Needed by the agent-session cascade
    // (Improvement 3), which has no root JTI to walk from — the session
    // IS the parent key. Not a full-table scan in sqlite: indexed query.
    HopsBySession(ctx context.Context, sessionID string) ([]ChainHop, error)
}
```

Plus one orchestrator free function both cascade call sites share:

```go
// RevokeRootAndDescendants composes the admin-revoke semantics: resolve
// rootJTI's own hop (expire it — the admin surface holds only a jti, never
// a token string), then cascade to every descendant. Returns the combined
// revoked list; aborts fail-closed on the first error.
func RevokeRootAndDescendants(ctx context.Context, store ChainStore,
    revoker ChainRevoker, rootJTI string, expire ExpireFunc) ([]ChainHop, error)
```

### Behavioral contract (deviations from the spec's sketch, pinned)

- **Spec deviation — `expire` receives the `ChainHop`, not just `jti`.**
  The deny entry needs the descendant's remaining lifetime
  ("with the descendant token's remaining lifetime" per spec), and
  `ChainHop` is the only carrier: `jti` + new `ExpiresAt` field (Decision 3).
  A `func(ctx, jti string)` callback cannot express the TTL; passing the hop
  is strictly more informative (audit, session correlation) and changes no
  semantics.
- **Truncation is an error, not a silent subset.** Both backends extract the
  walk into a shared internal helper
  (`walkDescendants(ctx, rootJTI, limit) ([]ChainHop, truncated bool, err)`)
  used by BOTH `GetDescendants` (which keeps its current contract: truncation
  still returns rows, as today) and `RevokeDescendants` (which turns
  `truncated` into `ErrChainWalkTruncated`). A >1000-node or cyclic subtree
  therefore surfaces as a 500 + failure audit on the admin endpoint, never a
  silent partial success. The memory store gains the same truncated flag
  (its walk is unbounded today; the cap is `maxChainWalk` parity, 1000).
- **Walk order is irrelevant to correctness** (marks are set-inserts), so
  `RevokeDescendants` reuses the existing newest-first collection order.
- **Idempotency is a property of the marks, not the walk.** The walk is
  read-only; the deny mark is a map set-insert. A concurrent or repeated
  cascade cannot double-revoke or error.

### Failure modes

| Failure | Behavior |
|---|---|
| Walk read error (sqlite query failure) | Abort; return partial + error; caller audits; admin → 500 with partial list |
| `expire` returns error | Abort remaining; return partial + error; caller audits (spec acceptance: "injected expire error propagates and returns the partial revoked list") |
| Walk truncation (`maxChainWalk` hit) | `ErrChainWalkTruncated`; treated as a walk error (fail-closed) |
| Unwired store / store not a `ChainRevoker` | No-op at every call site; admin revoke route → 501 (Decision 4) |
| Concurrent cascades | Race-clean by construction (RWMutex store + atomic map marks); `-race -count=10+` in acceptance |

---

## Decision 2: a jti-keyed revocation deny set is the keystone — `Validate` must consult it

### Problem restated

`RevokeDescendants` produces a list of JTIs. RFC 9068 validation rejects a
token only if its FULL STRING is in the issuer's in-process deny-set
(`j.revoked[token]`, all three issuers). Nothing maps jti → token (verified:
no such index exists). Without a new denial surface keyed by the `jti` claim,
the cascade would mark nothing observable and the "revoked" response would
lie. This is the one decision that makes or breaks the whole direction.

### Why NOT the `security.JTIReplayStore` family

The spec hedges ("the `security.JTIReplayStore` family / revocation
deny-set"). The replay store is the wrong primitive, on two axes:

1. **Fail-open direction.** `JTIReplayStore.MarkSeen` errors are fail-open
   (a store failure must not block the request). A revocation deny must be
   fail-closed: a failed mark means "token stays valid" — a security
   regression that must at minimum abort the cascade loudly.
2. **Semantic conflation.** The replay store also gates JAR/PAR/DPoP
   consumption; parking revocation entries in it would make a revoked
   access token's jti consume (and poison) unrelated replay defenses.

The design mirrors the existing token-string deny-set architecture exactly —
an in-process, exp-bounded map (the runtime authority, always available) with
an optional durable store + boot/recovery re-seed — extended with a jti key.

### API surface

**1. Issuer seam (both `domains`-visible and per-issuer).** Each JWT issuer
(`rsa_validate.go`, `ed25519_jwt_issuer.go`, `ecdsa` sibling) gains:

```go
// jtiRevoked map[string]int64 — same prune-not-early discipline as the
// token deny-set (revocation_set.go): keyed by jti, valued by exp (unix
// seconds), lazily pruned under the existing write lock.
func (j *XJWTIssuer) RevokeByJTI(ctx context.Context, jti string, expUnix int64) error
func (j *XJWTIssuer) SeedJTIRevocations(ctx context.Context) error
```

`Validate` consults both maps: the existing early `j.revoked[token]` check,
plus a `j.jtiRevoked[claims.JTI]` check after claims decode, before returning
success. The in-process map is authoritative and cannot fail → validation
stays fail-closed by construction and adds one O(1) map lookup per validation.

**2. Durable sibling store.** New optional interface next to
`RevocationStore` (same file `revocation_set.go` or sibling):

```go
type JTIRevocationStore interface {
    RevokeJTI(ctx context.Context, jti string, expUnix int64) error // idempotent
    LoadJTIs(ctx context.Context) (map[string]int64, error)
    PruneJTIs(ctx context.Context, nowUnix int64) error
}
```

Reference impls: `MemoryJTIRevocationStore` (in-process, test/single-replica)
and a sqlite backend: table `jti_revocations (jti TEXT PRIMARY KEY,
exp INTEGER NOT NULL)` + `idx_jti_revocations_exp`, same lazy-prune contract
as `infrastructure/defaultimpl/sqlite/revocations.go`. Redis is a natural
third backend but not required for this change.

**3. The `expire` closure — built once at the `interfaces/sso` layer.**
`interfaces/sso` owns the issuers, the durable store, and the bus; it builds
one `tokenexchange.ExpireFunc` (`s.chainExpireFunc()`) shared by the admin
handler wiring, the `/token/revoke` side-effect, and the agent cascade:

```go
func (s *Server) chainExpireFunc() tokenexchange.ExpireFunc {
    return func(ctx context.Context, hop tokenexchange.ChainHop) error {
        // 1. In-process deny mark on every armed issuer (RevokeByJTI).
        //    This is THE denial — atomic, cannot fail.
        // 2. Best-effort durable persist (JTIRevocationStore.RevokeJTI);
        //    error logged + metric, does NOT fail the mark (parity with
        //    the token path: "a store outage must not fail the revoke").
        // 3. Best-effort bus publish (KindTokenRevokedJTI, Decision 8).
    }
}
```

An `expire` error in production is therefore only possible if an issuer's
in-process mark fails (today: impossible; the map set cannot error). The
error channel exists for (a) orchestrator correctness — the abort semantics
are real and exercised by the acceptance tests' injected failing `expire` —
and (b) future issuers whose deny path is not a local map. The durable/bus
legs stay best-effort with logging, exactly like `PublishTokenRevocation` /
`RSAJWTIssuer.Revoke` today.

### Failure modes

| Failure | Behavior |
|---|---|
| In-process mark (any armed issuer) | Fail-closed: abort cascade, partial list + error surfaced |
| Durable persist outage | Best-effort: logged, metric; token still denied in-process; restart-resurrection window = the same gap the token deny-set had before `RevocationStore` (closed by seed, below) |
| Bus publish failure | Best-effort: logged, metric; other replicas converge on next re-seed |
| Re-seed failure at boot/recovery | Replica stays degraded (existing `reseedRevocationDenySets` path, extended to jti maps) |
| jti marked that no issuer owns | Clean no-op per issuer (a foreign jti never matches) — mirrors `ApplyTokenRevocation`'s "no local issuer owns it" no-op |

---

## Decision 3: storage model — `ChainHop.SessionID` + `ChainHop.ExpiresAt`, sqlite migration v2

### API surface

`ChainHop` (`domains/tokenexchange/chainstore.go`) gains two optional fields,
both `omitempty`, both set by the agent mint path and the token-exchange path
(which already has the minted token's lifetime at the record call site):

```go
// SessionID links a delegation MINT to the AgentSession that authorized it
// (agentidentity). Set only by the agent mint path — the natural parent
// key for a mint with no ParentJTI. Empty for token-exchange hops.
SessionID string `json:"session_id,omitempty"`
// ExpiresAt is the minted token's exp (unix seconds), recorded so a
// cascade can deny the JTI for exactly its remaining lifetime.
ExpiresAt int64 `json:"expires_at,omitempty"`
```

Storage decision: store `ExpiresAt` as unix SECONDS (the `exp` claim unit,
the `RevocationStore` unit) rather than `RecordedAt`'s UnixNano — the value
arrives from the token's `exp` and leaves the deny boundary without
conversion. `scanHop` (`sqlite/chain_store.go`) is the single scan path for
both `getHop` and `getChildren`; it extends to 9 columns.

Sqlite migration (append `{Version: 2}` to `chainMigrations` — `migrate.Run`
is versioned and additive):

```sql
ALTER TABLE tokenexchange_chain_hops ADD COLUMN session_id TEXT NOT NULL DEFAULT '';
ALTER TABLE tokenexchange_chain_hops ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_tokenexchange_chain_hops_session
    ON tokenexchange_chain_hops(session_id);
```

Memory store: `ChainHop` struct fields flow through automatically;
`HopsBySession` scans the hops map (bounded by the same 1000 cap); sqlite
`HopsBySession` is a plain indexed `WHERE session_id = ? ORDER BY recorded_at
DESC LIMIT ?` — no recursion, so no truncation hazard.

### Recording call sites

- `RecordExchangeHopFailOpen` (`chainstore.go`) gains an `expiresAt int64`
  parameter. Sole production call site:
  `internal/handler/tokengrant/token_exchange.go:227` — computes
  `time.Now().Add(st.token.ExpiresIn).Unix()`. (One call site; extending the
  signature beats a parallel function.)
- Agent mint: new sibling `RecordDelegationHopFailOpen(ctx, store,
  mintedAccessToken, humanSubject, agentID, clientID, sessionID string,
  expiresAt int64, logf)` — see Decision 6 for the hop assembly.

### Failure modes

| Failure | Behavior |
|---|---|
| Old DB without v2 columns | `migrate.Run` applies v2 at open; `NewWithDB` path identical |
| `expires_at` zero (pre-v2 row, or a hop recorded before expiry was plumbed) | Cascade denies with the hop's TTL unknown → deny entry would be pruned immediately; treat `ExpiresAt == 0` as "deny until the walk time + a conservative floor" — better, the ORCHESTRATOR refuses to expire a hop with no TTL and aborts with an error (fail-closed: never silently deny-for-zero). Pinned: abort with `ErrHopMissingExpiry`; pre-v2 rows are read-only history, never cascade targets. |
| `session_id` on a token-exchange hop | Never set (empty) — exchange hops are not session-scoped; `HopsBySession` cannot match them, which is correct |

---

## Decision 4: admin control surface — descendants view + one-click cascade revoke

### Problem restated

`HandleTokenExchangeChain` (`interfaces/admin/lifecycle.go:109`) exposes only
the ancestor query; the admin holds a jti, never a token string, so the
existing per-token `RevokeAcrossIssuers` path is unreachable from the admin
surface for the root itself. The jti deny set (Decision 2) closes that gap:
a jti-denied token fails validation regardless of which surface marked it, so
the admin revoke endpoint CAN kill the root AND its descendants.

### API surface

Two routes, mounted in `mountAdminTokenExchangeChainRoutes`
(`interfaces/sso/accessors_threat.go`, which already gates on a wired
store):

| Route | Scope | Handler |
|---|---|---|
| `GET /api/v1/admin/tokenexchange/chains/:jti/descendants` | `admin:read` (GET default) | `HandleTokenExchangeChainDescendants` |
| `POST /api/v1/admin/tokenexchange/chains/:jti/revoke` | `admin:write` (POST default) | `HandleTokenExchangeChainRevoke` |

New path consts in `shared/core/consts_wire.go` (consts.go is at budget):

```go
const PathAdminTokenExchangeChainDescendants = "/admin/tokenexchange/chains/:jti/descendants"
const PathAdminTokenExchangeChainRevoke     = "/admin/tokenexchange/chains/:jti/revoke"
```

**`GET .../descendants`** — `store.GetDescendants(jti, limit)` with a bounded
positive limit: default 100, `?limit=` query param capped at 1000
(`maxChainWalk`). 404 on unknown jti — the handler distinguishes "unknown"
from "known, no descendants" via `GetChain` first (empty chain → 404,
mirroring `HandleTokenExchangeChain`); empty descendants with a known jti →
200 `{jti, descendants: []}`. Response body `{status, jti, descendants}` with
`ChainHop` JSON, newest-first per the store contract.

**`POST .../revoke`** —

1. `store.(ChainRevoker)` type-assert; absent → `501 Not Implemented` with a
   new error code (registered in `docs/error-codes.md` per AGENTS.md §5).
2. `GetChain(jti)` → empty → 404 (unknown jti; also a root that was never
   recorded — fail-closed: never cascade from an unrecorded root).
3. `tokenexchange.RevokeRootAndDescendants(ctx, store, revoker, jti,
   s.chainExpireFunc())` — kills the root hop (jti deny, since no token
   string exists) and every descendant.
4. Success → `200 {status, jti, revoked: [jti...]}` (root jti first, then
   descendants) + success audit event.
5. Walk/expire error → `500 {status, revoked: [partial...]}` + failure audit
   event carrying the partial list and the error — never a silent partial
   success. (Spec's "on walk failure returns 500 with partial revoked list
   in the body AND in audit" — pinned.)

**Placement.** `interfaces/admin` is at its 10-file ceiling and
`lifecycle.go` at 481/500 — both handlers live in
`interfaces/admin/token_portfolio.go` (404/500, ~90 lines headroom, thematic
fit: token portfolio views). The audit helper and the response shapes stay
small because the orchestration lives in
`domains/tokenexchange.RevokeRootAndDescendants` (Decision 1) and the expire
closure lives in `interfaces/sso` — the handler is parse → call → respond →
audit. The sso-side additions (2 route registrations, 2 thin wrappers, 1
accessor, the expire closure) fit `accessors_threat.go`'s 73-line headroom;
if the closure plus mounts exceed it, the closure moves to
`server_token_clientauth.go` (the issuer/revocation home) and only mounts +
accessor stay in accessors_threat.go.

### Failure modes

| Failure | Behavior |
|---|---|
| Unknown jti | 404 (established `HandleTokenExchangeChain` pattern) |
| Store not a `ChainRevoker` | 501 + new error code; route still mounted (a wired plain `ChainStore` is a valid deployment) |
| Walk/expire/truncation error | 500 + partial list in body + failure audit event |
| Unwired store | Routes not mounted (existing gate) — byte-identical |
| Concurrent admin revokes | Idempotent marks; `-race -count=10+` acceptance |
| Root has no recorded hop but descendants do | Impossible by construction (a descendant's `parent_jti` references the root) — but GetChain-first ordering makes the 404 deterministic |

---

## Decision 5: `/token/revoke` opt-in chain-aware side-effect — oracle-safe by construction

### Problem restated

`revokeAccess` (`protocols/oauth/handle_revoke.go:152`) kills exactly the
presented token. The spec wants a wired-store side-effect that cascades to
descendants while preserving the byte-identical 200-always contract.

### API surface

`RevokeDeps` is UNCHANGED (adding a method would break every test fake).
`revokeAccess` type-asserts an optional capability — the established
`RefreshTokenInspector` pattern from `revokeRefresh` (same file):

```go
// optional, satisfied by *sso.Server
type chainRevokeCapability interface {
    RevokeTokenExchangeDescendants(ctx context.Context, rootJTI string) ([]tokenexchange.ChainHop, error)
}
```

`*sso.Server` implements it: extract `jti := tokenexchange.JTIFromJWTUnsafe(token)`
(the token was already revoked; advisory decode mirrors `JWTClaimsUnsafe` in
`internal/handler/cross_replica.go`), then `revoker.RevokeDescendants(ctx,
jti, s.chainExpireFunc())`.

Flow in `revokeAccess`, after the existing `RevokeAcrossIssuers`:

```go
if len(revoked) == 0 { return }              // root wasn't ours — no cascade
jti := tokenexchange.JTIFromJWTUnsafe(token) // "" for opaque/refresh → no cascade
if jti == "" { return }
if rc, ok := d.(chainRevokeCapability); ok {
    _, err := rc.RevokeTokenExchangeDescendants(ctx, jti)
    // err → log + failure audit; response is ALREADY 200 — never changed
}
```

Pinned semantics:

- **Oracle safety is by construction**: the 200-empty-body response is
  written by the existing path before/independent of the cascade; the cascade
  runs on a side channel and can only log/audit. Unknown token → `revoked`
  empty → no cascade → byte-identical. Credentials-only / wrong-hint paths
  untouched.
- **Cascade only when the root was actually revoked by a local issuer**
  (`len(revoked) > 0`). This keeps the side-effect out of the "unknown token"
  path entirely and is indistinguishable on the wire (both return 200 empty).
- **Root is killed by the existing per-token path** (`RevokeAcrossIssuers`);
  `RevokeDescendants` never re-kills it. No double-deny.
- Unwired store / non-`ChainRevoker` store → capability returns no-op →
  exactly today's behavior (spec acceptance: "unwired-store byte-identical
  no-op regression").

### Failure modes

| Failure | Behavior |
|---|---|
| Cascade walk/expire error | Logged + audited (`EventAdminTokenExchangeChainRevokeFailed` is admin-scoped; use a non-admin audit type here — see Decision 7), response stays 200 |
| Unknown/opaque/refresh token | No jti or no root revoke → no cascade, 200 |
| Store outage mid-cascade | Abort remaining (fail-closed cascade), audit, 200 |

---

## Decision 6: agent delegation joins the chain — mint recording, audit jti, session cascade

### Problem restated

`agentidentity` revocation is next-mint-only (`agent.go:43`); minted
`delegation_token`s live to TTL; `mintDelegationToken` never records a
`ChainHop` (sole `RecordExchangeHopFailOpen` call site is the token-exchange
handler, `token_exchange.go:227`); `auditDelegationMint` omits the minted
jti. Improvement 1/2's cascade is useless for the most common delegation
primitive without this.

### API surface

**1. Mint-path hop recording.** `HandleGrant`'s success path
(`grant.go:200-213`) gains a fail-open hop recording call after
`auditDelegationMint`. The chain store is OPTIONAL, so it enters via a
type-asserted capability on `Deps` — adding a method to the `Deps` interface
would break every `grant_test.go` fake; the optional-capability pattern is
this codebase's idiom for optional wiring:

```go
// optional, satisfied by interfaces/sso.agentDelegationHandler
type chainStoreProvider interface{ ChainStore() tokenexchange.ChainStore }
```

`agentDelegationHandler` (`options_grants.go:416`) implements
`ChainStore()` forwarding `s.TokenExchangeChainStore()`.

Hop assembly via the new `RecordDelegationHopFailOpen` (Decision 3):

| ChainHop field | Value | Rationale |
|---|---|---|
| `JTI` | `JTIFromJWTUnsafe(minted)` | minted token's jti |
| `ParentJTI` | `""` | a delegation mint has no subject_token; the session is the parent key |
| `SubjectID` | `agent.ID` | **spec deviation** — see below |
| `ActorSubject` | `sess.HumanSubject` | **spec deviation** — see below |
| `ClientID` | `client.ID` | minting client |
| `ChainDepth` | `1` | the minted token carries exactly one `act` hop (the human) |
| `SessionID` | `sess.ID` | the AgentSession that authorized the mint |
| `ExpiresAt` | `now + token.ExpiresIn` (unix seconds) | deny TTL |
| `RecordedAt` | `now` | — |

**Spec deviation — subject/actor mapping.** The spec's "subject = human,
actor = agent" is BACKWARD relative to `ChainHop`'s documented semantics and
the token-exchange call site. `ChainHop.SubjectID` is the freshly minted
token's `sub`; `ActorSubject` is its `act` subject
(`chainstore.go` docs; `tokExRecordChainHop` passes `st.claims.Subject` and
the actor from `tokExResolveActor`). The delegation mint produces a token
with `sub = agent.ID` and `act = human` (`grant.go` mints `Subject{ID:
agent.ID, Actor: &core.ActorClaim{Subject: sess.HumanSubject}}`). The
faithful mapping is therefore `SubjectID = agent.ID`, `ActorSubject =
sess.HumanSubject`. Getting this backwards would make `GetChain`/
`GetDescendants`/the admin UI mislabel every agent token as "human acting
for agent". Follow the minted token's claims, not the delegation's prose
direction.

**2. Audit jti.** `auditDelegationMint` (`grant.go:213`) adds
`audit.SetMeta(evt, core.KeyJTI, jti)` — `KeyJTI = "jti"` already exists
(`shared/core/consts_wire.go:177`). Logs ↔ chain ↔ token now correlate.

**3. Session cascade.** `RevokeSession` / `RevokeAllForHuman`
(`revoke.go:17,28`) gain an optional cascade parameter (zero production
callers today — signature change is free):

```go
type RevokeOptions struct {
    ChainRevoker tokenexchange.ChainRevoker // nil = no cascade, byte-identical today
    Expire       tokenexchange.ExpireFunc   // built by interfaces/sso (chainExpireFunc)
}

func RevokeSession(ctx context.Context, sessions AgentSessionStore,
    auditor *audit.Recorder, sessionID string, opts *RevokeOptions) error

func RevokeAllForHuman(ctx context.Context, sessions AgentSessionStore,
    auditor *audit.Recorder, humanSubject string, opts *RevokeOptions) (int, error)
```

Cascade step (after the store-side session revocation — which applies
regardless):

```go
if opts != nil && opts.ChainRevoker != nil {
    hops, err := opts.ChainRevoker.HopsBySession(ctx, sessionID) // or all sessions for the human
    for _, h := range hops {
        if e := opts.Expire(ctx, h); e != nil { err = errors.Join(err, e); break }
        if _, e := opts.ChainRevoker.RevokeDescendants(ctx, h.JTI, opts.Expire); e != nil {
            err = errors.Join(err, e); break  // fail-closed: abort remaining
        }
    }
    // err → auditRevoke/auditRevokeCohort outcome = failure + cascade meta
}
```

Each minted token is killed (expire its own hop) AND its whole derived
subtree (RevokeDescendants from it) — a revoked human session therefore kills
already-minted agent tokens AND anything a service later exchanged them into.
Fail-closed reporting: a cascade error flips the existing
`EventAgentSessionRevoked` event's outcome to failure and adds the partial
killed-jti list as meta — the session revocation itself still succeeded.

**4. Unwired.** `opts == nil` → no hop lookups, no expire calls, no new
audit meta — byte-identical to today (spec acceptance).

### Failure modes

| Failure | Behavior |
|---|---|
| Hop recording store error | Fail-open (RecordHopFailOpen contract) — mint succeeds, error logged |
| `HopsBySession` error in cascade | Joined into the revocation error; audit outcome failure; session store revocation still applied |
| `Expire`/`RevokeDescendants` error | Abort remaining (fail-closed), audit partial list, outcome failure |
| `opts == nil` | No cascade, no new audit — byte-identical |
| Human with many sessions | `RevokeAllForHuman` walks hops per session, each bounded by the walk caps; audit list is comma-joined and bounded (bounded cardinality, AGENTS.md §4) |

---

## Decision 7: audit events and observability

### API surface

New event types in `platform/audit/auditspi/event_types.go`, registered in
the known-types map AND classified in `auditreport` control areas (AGENTS.md
§4 — an unclassified type fails the auditreport gate):

| Event | Trigger | Meta |
|---|---|---|
| `EventAdminTokenExchangeChainRevoked` | `POST .../chains/:jti/revoke` success | root jti, revoked jti list (comma-joined, bounded), admin actor (existing `ActorID`/`ActorIP`), client |
| `EventAdminTokenExchangeChainRevokeFailed` | revoke walk/expire failure | root jti, partial revoked list, error reason |
| `EventTokenExchangeChainRevokeSideEffectFailed` (or reuse the failed type with a `surface` meta) | `/token/revoke` cascade failure (non-admin actor) | root jti, partial list, error |

Naming follows the `EventAdmin*` prefix convention
(`EventAdminRefreshTokensRevoked` exists); both new admin types classify into
the CC6.1 Access control area alongside `EventCrossTenantTokenExchange` /
`EventAgentDelegationTokenIssued` (`auditreport/control_areas.go:55`).

Agent-side: no new event types — `EventAgentSessionRevoked` gains cascade
meta (`killed_jtis`, `cascade_error`) and its outcome already flips via
`outcomeOf` (extended to join cascade errors). `auditDelegationMint` gains
`core.KeyJTI`. `EventAgentDelegationTokenIssued` stays the mint record.

Audit metadata is added only via `audit.SetMeta` (AGENTS.md §4) — no raw map
literals. New meta keys are package consts (`agentidentity/consts.go`,
`platform/audit/auditspi` consts), never inline strings.

### Failure modes

| Failure | Behavior |
|---|---|
| Auditor nil | Existing nil-safe no-op discipline (`auditRevoke` guards) |
| New types unclassified | auditreport gate fails — caught in `make ci`, not production |
| Bounded cardinality | Revoked lists are walk-capped (1000) and comma-joined; a SIEM sees one event per admin action |

---

## Decision 8: cross-replica invalidation and restart survival

### Problem restated

AGENTS.md §3: "Cross-replica invalidation covers token revocation...".
A jti denial marked on replica A must reach replicas B/C (a resource server
validating a descendant token on B) and survive restarts. The existing
`KindTokenRevoked` bus event carries the FULL TOKEN and peers re-decode it
(`ApplyTokenRevocation`, `cross_replica.go`) — that receiver cannot adopt a
jti-only denial.

### API surface

1. **Bus: new event kind** in `platform/cluster/bus.go`:
   `KindTokenRevokedJTI = "token_revoked_jti"` with payload keys
   `MetaRevokedJTI`, `MetaRevokedExp`, `MetaRevokedIssuer` (empty issuer =
   all armed issuers — the cascade does not resolve which issuer minted a
   hop, and marking a foreign jti is a clean no-op per issuer). The
   `ApplyTokenRevocation` arm type-switches and adopts into each armed
   issuer's `jtiRevoked` map; adoption uses the LOCAL-only mark (never
   re-publishes — same broadcast-loop guard as the token arm).
2. **Re-seed:** the boot/recovery `reseedRevocationDenySets`
   (`server_extensions.go:449`) loop gains a sibling seam
   `SeedJTIRevocations` for issuers that implement it; a failure keeps the
   replica degraded exactly as today. The sqlite `JTIRevocationStore` backs
   the re-seed (restart + late-join survival, parity with `RevocationStore`).
3. **Admin mutations invalidate caches:** the admin revoke endpoint and the
   `/token/revoke` cascade both go through `s.chainExpireFunc()`, which
   publishes — one publish path, no divergence.

### Failure modes

| Failure | Behavior |
|---|---|
| Bus publish error | Best-effort (logged, metric) — local deny already applied; peers converge at next re-seed |
| Restart before durable persist | Same resurrection window the token deny-set closes via `RevocationStore`; the sqlite `JTIRevocationStore` + boot seed closes it |
| Degraded replica (seed failure) | Stays degraded + audited (existing pattern) |
| Late-joining replica | Boot seed from the durable store covers it |

---

## Decision 9: failure modes and oracle safety — consolidated contract table

Fail-closed (a failure must be loud, partial results surfaced, never silent):

| Surface | Failure | Required behavior |
|---|---|---|
| `RevokeDescendants` | walk / expire / truncation error | Abort, return partial + error, caller audits |
| Admin `POST .../revoke` | any cascade error | 500 + partial list in body AND audit |
| `RevokeSession` cascade | lookup / expire / walk error | Audit outcome failure + partial killed list; session revocation still applies |
| Validation | jti in in-process deny map | Reject (fail-closed by construction — map always available) |
| Cascade on hop with `ExpiresAt == 0` | pre-v2 row / unrecorded TTL | Abort with `ErrHopMissingExpiry` — never deny-for-zero |

Fail-open (deliberate, documented):

| Surface | Failure | Required behavior |
|---|---|---|
| Hop recording (exchange + mint) | store error / nil store | Mint/exchange succeeds; logged (existing `RecordHopFailOpen`) |
| `/token/revoke` cascade | any error | Logged + audited; response stays byte-identical 200 |
| Durable jti persist / bus publish | store/bus outage | Logged + metric; in-process deny holds; re-seed converges |
| Unknown/opaque/refresh token at `/token/revoke` | no jti or no root revoke | No cascade; 200 — oracle-safe |

Oracle invariants preserved (regression boundaries):

- `/token/revoke` remains 200-always and byte-identical for
  known/unknown/consumed/mismatched tokens; the cascade is unobservable on
  the wire.
- Admin endpoints are NOT OAuth oracle surfaces — 404 for unknown jti and
  501 for a non-revoking store are explicit, audited states.
- No new credential surface: both admin routes ride the existing
  AdminMiddleware (GET → `admin:read`, POST → `admin:write`); 401 stays
  `Bearer realm="admin"`.
- The jti deny set is consulted only by RFC 9068 validation; no other
  protocol's acceptance changes.

---

## Decision 10: what could break the design

Ranked by severity; each with its mitigation. All were verified against
current code before inclusion.

1. **The keystone is a new validation seam (Decision 2), not a store
   method.** If `RevokeByJTI` + the `Validate` consultation land incomplete
   (one issuer missed, or the deny map never consulted), every cascade
   surface reports "revoked" while descendant tokens stay valid — a
   confidence-shattering silent failure. Mitigation: the acceptance check
   must include a validation-level test (mark a jti via the wired `expire`,
   then `Validate` a real token carrying that jti → rejected) on ALL THREE
   issuers, plus the spec's unwired-store no-op regression. The integration
   test (`test/`, `ssotest`) proving "descendant access token rejected before
   TTL after root revoke" is the end-to-end tripwire.

2. **`ChainHop.ExpiresAt` is a spec addition, not optional.** Without a real
   TTL the deny entry either uses `DefaultJTIReplayWindow` (5 min — tokens
   outlive it, revocation silently expires early) or exp=0 (pruned
   immediately by `pruneRevoked` — revocation does nothing). The design pins
   `ExpiresAt` (unix seconds from the minted token's `exp`) and makes a
   zero-TTL hop a cascade ABORT (`ErrHopMissingExpiry`), so a future
   recording site that forgets the field fails loudly, not silently.

3. **The spec's "subject = human, actor = agent" mapping is backwards**
   relative to `ChainHop` semantics and would mislabel every agent token in
   `GetChain`/`GetDescendants`/the admin UI. Pinned: follow the minted
   token's own claims (`sub → SubjectID`, `act → ActorSubject`), matching
   `tokExRecordChainHop`. Implementers must not "fix" the spec text over the
   code.

4. **`maxChainWalk` silent truncation.** Today `GetDescendants` stops at
   1000 visited nodes and returns success. As a cascade this is silent
   partial revocation. Mitigation: shared walk helper with a `truncated`
   flag; `RevokeDescendants` returns `ErrChainWalkTruncated`. The admin
   descendants READ keeps today's contract (bounded by its own 100 limit
   anyway).

5. **Interface growth breaks fakes.** Adding methods to `ChainStore`,
   `RevokeDeps`, or `agentidentity.Deps` breaks every fake store / handler
   fake in `test/` and package tests. Mitigation: `ChainRevoker` extension
   interface (Decision 1), `chainRevokeCapability` type-assert on
   `RevokeDeps` (Decision 5), `chainStoreProvider` type-assert on
   `agentidentity.Deps` (Decision 6) — the codebase's established optional-
   capability idiom (`RefreshTokenInspector`, `RefreshTokenSubjectIndex`,
   `JTIReplayForgetter`, `revocationSeeder`).

6. **File-budget collisions.** `interfaces/admin` is at its 10-file ceiling;
   `lifecycle.go` 481/500, `governance.go` 483/500, `connections.go` 498/500.
   Handlers MUST go into `token_portfolio.go` (404/500, ~90 lines headroom —
   tight; keep the handlers thin by pushing orchestration into
   `domains/tokenexchange` and audit into `auditspi`). `interfaces/sso/
   accessors_threat.go` (427/500) takes mounts + accessor + expire closure;
   if the closure overflows, it moves to `server_token_clientauth.go` (the
   issuer/revocation home). `shared/core/consts.go` is at budget — path
   consts go in `consts_wire.go`. These constraints are compile-enforced;
   the implementation must check `wc -l` before editing.

7. **`/token/revoke` oracle drift.** Any branch that changes the response
   shape, timing-sensitive early-return, or error surfacing from the cascade
   breaks the 200-always regression boundary. Mitigation: the cascade runs
   strictly after the response is decided, on a side channel, with
   `len(revoked) == 0` early-return; the acceptance suite re-runs the full
   existing revoke oracle tests plus the wired-store descendant test.

8. **Session cascade ships dead in production.** `RevokeSession` /
   `RevokeAllForHuman` have zero production callers today; the cascade is
   acceptance-tested but unreachable until an admin/self-service agent-
   session surface exists. This is a known, accepted gap (spec acceptance is
   unit + integration level) — flagged here so it is not mistaken for a
   wired production control. The `RevokeOptions` shape is designed so the
   future surface wires it with `s.chainExpireFunc()`.

9. **Cross-replica/restart resurrection.** A jti denial that never leaves
   the originating replica or dies on restart is weaker than the token
   deny-set it parallels. Mitigation: `KindTokenRevokedJTI` bus event +
   `SeedJTIRevocations` on boot/recovery + sqlite `JTIRevocationStore`
   (Decision 8) — parity with the existing revocation architecture, not a
   new pattern.

10. **jti collisions across issuers.** A denied jti is marked on every
    armed issuer; a (random) jti collision would deny another issuer's token
    sharing that jti. Risk is negligible (minted jtis are random per RFC
    9068 issue) and the alternative — resolving the minting issuer per hop —
    adds a store dependency the walk doesn't have. Accepted; per-issuer maps
    keep the blast radius to one jti.

11. **Admin surface "kills" the root via jti deny only.** The admin POST
    revoke marks the root's jti; a resource server that validates without
    consulting the jti deny (out-of-band/legacy validator) would still honor
    the root until TTL. The RFC 9068 path in this server consults it; any
    downstream validator using the same issuers is covered. Documented in
    the endpoint contract.

12. **Concurrency races on the deny maps.** The three issuers each gain a
    second map guarded by the EXISTING `revokedMu` — no new lock, no
    lock-ordering surface. The `-race -count=10+` acceptance covers
    concurrent cascades; the maps' set-insert semantics make double-marks
    harmless.

---

## Implementation order and acceptance mapping

| Step | Work | Spec acceptance covered |
|---|---|---|
| 1 | `ChainHop` + `SessionID`/`ExpiresAt`; sqlite migration v2; memory store; `RecordExchangeHopFailOpen` + `RecordDelegationHopFailOpen`; scanHop 9 columns | hop fields flow; pre-v2 read compatibility |
| 2 | jti deny seam: issuer `RevokeByJTI`/`SeedJTIRevocations`/`Validate` consultation; `JTIRevocationStore` (memory + sqlite); bus `KindTokenRevokedJTI`; reseed extension | validation-level deny test on all 3 issuers; unwired no-op |
| 3 | `ChainRevoker` + `walkDescendants` helper + `ErrChainWalkTruncated` + `RevokeRootAndDescendants` in both backends | 3-hop cascade marks a,b only; sibling subtree untouched; idempotent re-run; injected expire error → partial + error; `-race -count=10+`; sqlite index + cap test |
| 4 | Admin GET descendants + POST revoke; audit events + auditreport classification; path consts; docs (openapi, error-codes) | handler tests in the `tokenexchange_chains_test.go` pattern; bounded/ordered descendants; 404; 500 + partial; 501; unwired not mounted; audit assertions |
| 5 | `/token/revoke` side-effect via `chainRevokeCapability` | existing oracle tests pass unchanged; wired-store test proves descendant rejection before TTL |
| 6 | agentidentity: hop recording, `auditDelegationMint` jti, `RevokeOptions` cascade | mint hop SessionID/JTI match; per-human / per-session isolation; failing cascade audited while session revoke succeeds; nil store no-op |
| 7 | Integration (`test/`, `ssotest`) + `go build ./... && go vet ./...` + `go test ./... -race` + `make ci` | post-`RevokeAllForHuman` delegation_token rejected before TTL; mint audit carries jti; wire contracts unchanged |

Docs discipline (AGENTS.md §5): new endpoints → `docs/openapi.yaml`; new
error codes (`ErrChainWalkTruncated`, `ErrHopMissingExpiry`, the 501 revoke-
unavailable code) → `docs/error-codes.md`; new audit event types →
`docs/observability.md` + `auditreport` classification; `docs/feature-matrix.
md` notes the ChainStore role change from append-only observability to
opt-in revocation control plane. No new config knobs — the feature is
wiring-only, consistent with `WithTokenExchangeChainStore`'s existing opt-in
contract.
