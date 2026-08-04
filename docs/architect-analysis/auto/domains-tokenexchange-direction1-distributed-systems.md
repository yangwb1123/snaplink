# Distributed-Systems Engineering Review: `domains/tokenexchange` direction 1

Independent review counterpart to
[`domains-tokenexchange-direction1-design.md`](domains-tokenexchange-direction1-design.md).
Scope: the design's consistency, ordering, atomicity, idempotency, ownership,
conflict-resolution, and recovery guarantees, traced through the OAuth /
RFC 9068 / chain-hop / jti-deny / invalidation-bus state machines as they
exist in code today. Assumes replicas, retries, partial failure, partitions,
failover, and clock anomalies.

## 0. Method and verification

Checks that actually ran for this review revision:

- `rg` source scans: `revoked[` across `infrastructure/defaultimpl` (3 hits);
  `GetDescendants` (definitions + docs only, zero production callers);
  `agentidentity.RevokeSession|RevokeAllForHuman` (one doc mention in
  `interfaces/sso/options_grants.go:410`, zero production callers);
  `Prune(` callers; boot/recovery seed call sites; bus kinds and payload keys.
- `wc -l` on the ten budgeted files (`interfaces/admin` 10 non-test files;
  `lifecycle.go` 481, `governance.go` 483, `connections.go` 498,
  `token_portfolio.go` 404, `accessors_threat.go` 427,
  `server_token_clientauth.go` 483, `consts.go` 466, `consts_wire.go` 490,
  `chainstore.go` 155).
- Full reads of `domains/tokenexchange/chainstore.go`,
  `domains/tokenexchange/sqlite/chain_store.go`,
  `infrastructure/defaultimpl/revocation_set.go`, `rsa_validate.go`,
  `protocols/oauth/handle_revoke.go`, `internal/handler/cross_replica.go`,
  `platform/cluster/bus.go`, `interfaces/sso/server_extensions.go`
  (recovery arm), `domains/tokenexchange/agentidentity/{agent,grant,revoke,
  memory_session}.go`, `infrastructure/defaultimpl/sqlite/revocations.go`.

No `go build`/`go test`/`make ci` ran for this review; the design is not yet
implemented, so all behavior labels below are **Verified** (exists in code
today), **Proposed** (design contract, not yet code), or **Partial**
(verified in one place, extrapolated elsewhere).

Design claims re-verified against source before inclusion: all three issuers
deny by full token string (`rsa_validate.go:25`, `ed25519_validate.go:23`,
`ecdsa_validate.go:25`); zero production `GetDescendants` callers; zero
production `agentidentity.RevokeSession`/`RevokeAllForHuman` callers;
`maxChainWalk = 1000` with silent truncation (`sqlite/chain_store.go:51,185`);
prune-not-early discipline with raw wall clock
(`revocation_set.go:31-55`); bus is best-effort with no delivery/ordering
guarantees (`platform/cluster/bus.go` package doc); recovery order is
subscribe → re-seed → clear degraded (`server_extensions.go:409-427`);
delegation mint stamps `sub = agent.ID`, `act = human`
(`agentidentity/grant.go:185-194`) — the design's Decision 6 subject/actor
correction is correct; `KeyJTI = "jti"` exists (`consts_wire.go:177`);
admin scope policy GET→`admin:read` else→`admin:write`
(`interfaces/admin/middleware.go:71-75`); `auditDelegationMint` carries no
jti today (`grant.go:213-231`); `RevocationStore.Prune` has no production
caller (lazy prune inside `Load`/`Revoke` only).

---

## 1. State map

Every state item the design creates or touches, with owner, store,
durability, consistency, replication, and failover semantics. Labels:
**V** = verified in current code, **P** = proposed by the design.

| # | State | Owner | Store | Durability | Consistency | Replication | Failover / recovery |
|---|---|---|---|---|---|---|---|
| S1 | `jtiRevoked map[string]int64` per issuer (×3, new) **P** | per-replica issuer instance (`RSAJWTIssuer`/`Ed25519JWTIssuer`/`ECDSAJWTIssuer`), guarded by the existing `revokedMu` (V: `rsa_jwt_issuer.go:86-89`) | in-process map; **the runtime authority for validation** | none — rebuilt from S2 at boot/recovery; a crash loses all entries not durably persisted | linearizable per replica under `revokedMu`; O(1) `Validate` lookup after claims decode (P); prune-not-early discipline identical to the token set (V: `revocation_set.go`) | bus `KindTokenRevokedJTI` (P, S5) + re-seed from S2 (P, mirrors V: `seedRevokedFromStore` `revocation_set.go:142`) | boot seed (V pattern: `cmd/sso-server/serverbuildsign/build_signing.go:112`; a boot seed error fails server build — fail-closed at boot); invalidation-bus recovery re-seed (V: `server_extensions.go:449`); un-wired S2 = documented restart-resurrection gap (parity with the token path) |
| S2 | `jti_revocations (jti PK, exp)` table (new) **P** | sqlite `JTIRevocationStore` (new), memory sibling (new) | durable on sqlite (same migration/lifecycle as `infrastructure/defaultimpl/sqlite/revocations.go` V); memory = process-lifetime only | single-row upsert, idempotent; write path is best-effort from the `expire` closure (P) — never on the validation hot path | shared-file multi-replica (same topology claim as `RevocationStore` V: `sqlite/revocations.go` doc); no per-row ownership — last-writer-wins on `exp` | not replicated itself; it IS the re-seed source | replica crash → boot re-seed; store outage → persist best-effort, in-process deny holds (P: fail-open for durability, fail-closed for denial) |
| S3 | `tokenexchange_chain_hops` rows + v2 columns `session_id`, `expires_at` (new) **P** | `domains/tokenexchange/sqlite.ChainStore` (V) / `memory.ChainStore` (V) | durable on sqlite (V); memory = process-lifetime (V) | per-row upsert idempotent (V: `RecordHop` `ON CONFLICT`); **walks are non-transactional point-query sequences** (V: `GetDescendants` one `getChildren` per node) → read skew vs concurrent `RecordHop` | shared-file across replicas (V doc); no bus replication of hops | n/a — reads only; a crashed replica re-reads; no failover state of its own |
| S4 | deny entries in the three token-string sets (`revoked[token]`, existing) **V** | per-replica issuer, `revokedMu` | none (rebuilt from `RevocationStore`) | linearizable per replica; prune-not-early (V) | bus `KindTokenRevoked` (V) + boot/recovery seed (V) | unchanged; the cascade's root-kill via `/token/revoke` reuses it (P) |
| S5 | bus `KindTokenRevokedJTI` events (new) **P** | `platform/cluster.Bus` (etcd/memory, V) | **none — best-effort, no delivery or ordering guarantees** (V: `bus.go` package doc) | at-least-once-ish delivery; adoption is idempotent set-insert (P, mirrors V: `ApplyTokenRevocation` `cross_replica.go:98`) | pub/sub; per-replica adoption into S1 | lost/dropped event → peer converges only at its next boot or bus-recovery re-seed; **no periodic reconciliation exists today** (V: re-seed only at boot `build_signing.go` and recovery `server_extensions.go:417`) |
| S6 | `AgentSession` records (existing) **V** | `agentidentity.AgentSessionStore` (memory impl V) | memory only (V) — no durable impl shipped | idempotent `Revoke` (V: `memory_session.go:55-65`); next-mint fail-closed check (V: `agent.go` doc, `grant.go`) | none — sessions are per-process | sessions lost on restart (V, pre-existing); the design's session cascade (P) inherits this: cascade targets vanish with the store |
| S7 | admin/introspection caches (existing) **V** | per-replica caches | n/a | evicted on revoke (V: `oauth.InvalidateIntrospectionCache` at `server_token_clientauth.go:461`) | bus kinds for tenant/client (V) | unchanged; jti denial never feeds these caches (P: only RFC 9068 `Validate` consults S1) |

Ownership and conflict-resolution summary:

- **Single-writer per deny entry in practice.** Multiple replicas or
  concurrent cascades may mark the same jti; entries are set-inserts keyed by
  jti valued by `exp`, and every writer derives the same `exp` (the hop's
  immutable `ExpiresAt`), so last-writer-wins is value-identical. The only
  conflict axis is jti collision across issuers (accepted in Decision 10).
- **No fencing/quorum anywhere in the revocation path.** The cascade has no
  lock or epoch against the mint path; correctness rests entirely on
  idempotent marks + fail-closed reporting (findings F-4).
- **Ordering is load-bearing in exactly one place**: `resubscribeAndReseed`
  (V) — subscribe before re-seed, re-seed before clearing degraded. The
  design's jti seed must ride the same sequence; it does (Decision 8).

---

## 2. Findings

Sorted by severity. Each: severity, evidence, triggering failure, user
impact, recovery, corrective pattern.

### F-1 — High — `HopsBySession` bounds silently cap the session cascade (a silent-partial-revocation hole at the one boundary the design exempted)

- **Severity:** High.
- **Evidence:** Design Decision 3: sqlite `HopsBySession` is "a plain indexed
  `WHERE session_id = ? ORDER BY recorded_at DESC LIMIT ?` — no recursion, so
  no truncation hazard." The premise is wrong for its only consumer: the
  session cascade (Decision 6) walks `HopsBySession` results and expires each
  hop — a `LIMIT 1000` on a session with 1500 recorded mints silently returns
  1000 and the oldest 500 minted tokens (and every subtree derived from them)
  are never killed, with **no `truncated` signal**, no error, no audit
  marker. This is byte-for-byte the failure class the direction exists to
  eliminate ("silent partial revocation"), which Decision 1 explicitly turns
  into `ErrChainWalkTruncated` for the forward walk — the session path has no
  equivalent.
- **Triggering failure:** an `AgentSession` with >1000 recorded mints
  (`RevokeAllForHuman`'s cohort cascade, or a long-lived session).
- **User impact:** a revoked human's delegation tokens minted beyond the
  1000th remain valid until TTL; the operator sees a successful revocation
  audit with a bounded killed list. Silent, confidence-shattering in exactly
  the Decision-1 sense.
- **Recovery:** none automatic; the escaped hops are unreachable through the
  same API until their TTL lapses.
- **Corrective pattern:** make `HopsBySession` return
  `(hops []ChainHop, truncated bool, err error)` (fetch `LIMIT+1`), and have
  the cascade treat `truncated` as `ErrChainWalkTruncated` — abort remaining
  with the partial killed list in the audit, exactly like
  `RevokeDescendants`. Cost: one extra row fetch; no contract change for
  stores that implement the optional `ChainRevoker` interface (the method is
  new).

### F-2 — Medium — the jti bus event's `exp` is trusted as-is; the token arm's re-derivation safety net does not transfer

- **Severity:** Medium.
- **Evidence:** The token arm (`ApplyTokenRevocation`,
  `internal/handler/cross_replica.go:98`) adopts from `MetaRevokedToken` +
  advisory `MetaRevokedExp`; a bad `exp` is harmless because the receiver
  re-decodes the token and re-derives `exp` in its own `Revoke`
  (`rsa_validate.go` → `Revoke`). The jti arm (Decision 8) has **no token to
  re-derive from** — `MetaRevokedJTI` + `MetaRevokedExp` are the whole
  message, and `bus.go`'s contract explicitly provides no delivery or
  ordering guarantees. An absent/unparsable/zero `exp` adopted into `S1`
  yields an entry that `pruneRevoked` drops on the next sweep
  (`revocation_set.go:31-55`) — the peer silently never denies, while the
  origin replica believes the jti is denied everywhere. The design does not
  pin receiver-side validation of `exp` (it only pins "empty issuer = all
  armed issuers").
- **Triggering failure:** publisher bug, or a mixed-version peer that
  forwards the kind without the payload keys; no validation exists on the
  adopting arm.
- **User impact:** a descendant token stays valid on the stale replica until
  its own `exp`; indistinguishable from a dropped event (F-5) and invisible
  to the origin.
- **Recovery:** next boot/recovery re-seed from `S2` (when wired).
- **Corrective pattern:** pin the adopting arm: reject `exp <= now` and
  clamp to a conservative floor (e.g. `security.DefaultJTIReplayWindow`,
  `shared/security/jti_replay.go:51`, or the issuer TTL) rather than storing
  `0`. Over-denial is the safe direction and is already the accepted posture
  for jti collisions (Decision 10). Alternatively carry the hop's
  `ExpiresAt` and bound-check it against a plausible max TTL, dropping only
  absurd values — but clamp, never store 0.

### F-3 — Medium — every pre-v2 hop makes its whole subtree permanently un-revocable via the admin surface, and the root is never denied

- **Severity:** Medium (availability/operability, no security regression).
- **Evidence:** Design Decision 3 pins `ExpiresAt == 0` → cascade abort
  (`ErrHopMissingExpiry`), and the failure table says "pre-v2 rows are
  read-only history, never cascade targets." But `RevokeDescendants` /
  `RevokeRootAndDescendants` (Proposed) walk **all** recorded hops including
  v1 rows — nothing filters them out before `expire` is called, so the first
  v1 row encountered aborts the whole cascade. `RevokeRootAndDescendants`
  expires the root first: a pre-v2 root aborts immediately → admin POST
  returns 500 with an empty partial list and **the root's jti is never
  denied at all** (the per-token path is unreachable from the admin surface —
  Decision 4's premise). Hop rows are append-only permanent, so this state
  is permanent for every pre-v2 jti. A chain recorded one minute before the
  v2 upgrade can reference a token with 30 minutes of life left.
- **Triggering failure:** upgrading a deployment that recorded hops under v1,
  then using the admin revoke on any pre-v2 root, or any chain whose subtree
  contains a pre-v2 hop.
- **User impact:** operator cannot revoke live pre-v2 chains via the new
  surface; gets a 500 with no partial marks; must fall back to
  `/token/revoke` with the literal token string (which kills the root only,
  not descendants).
- **Recovery:** wait out TTLs, or use the per-token path.
- **Corrective pattern (optional refinement, keeps the abort):** make the
  walk/orchestrator skip hops whose `ExpiresAt` is **in the past** (their
  tokens are already dead — `Validate` rejects on `exp` regardless, so
  denial is provably unnecessary; no security regression), and abort only on
  `ExpiresAt == 0` that cannot be proven expired (e.g. `ExpiresAt == 0 &&
  RecordedAt` within the max plausible token TTL of now). At minimum,
  document the permanent-500 consequence in the endpoint contract and the
  migration notes. The abort itself stays as the fail-closed baseline.

### F-4 — Medium — the cascade is not linearizable against the mint path: a concurrent exchange escapes, silently and permanently

- **Severity:** Medium.
- **Evidence:** The sqlite walk is a sequence of non-transactional point
  queries (V: `chain_store.go:185-217`, one `getChildren` per visited node,
  no snapshot); the mint path records hops after the exchange response is
  decided, fail-open (V: `tokExRecordChainHop`,
  `internal/handler/tokengrant/token_exchange.go:227`). A `RecordHop`
  committing between the cascade's visit of a parent and its completion
  produces a descendant that is (a) not in the returned partial list, (b)
  not in any error, (c) not denied. Same race at the session cascade
  boundary (`HopsBySession` snapshot vs concurrent mint). The design
  mentions concurrent cascades (idempotent marks) but never the
  revoke-vs-mint interleaving.
- **Triggering failure:** an exchange in flight while the admin revoke (or
  session cascade) walks.
- **User impact:** a descendant minted concurrently with the revocation stays
  valid until TTL; the admin sees a success with a list that is already
  stale. No error, no audit marker.
- **Recovery:** re-run the revoke after the exchange storm settles
  (idempotent re-walk re-marks); or wait out TTL.
- **Corrective pattern:** this is inherent to a fail-open, unlocked mint path
  and should not be "fixed" with locks (the mint path must never block on
  the control plane). Instead: (a) state point-in-time semantics explicitly
  in the endpoint contract and audit meta (`walked_at`); (b) optionally add a
  bounded second walk after the marks (re-walk, expire any stragglers) to
  narrow the window; (c) the acceptance suite should include a
  concurrent-mint-during-cascade test asserting the documented outcome
  (escaped token listed in audit, not silently implied complete).

### F-5 — Medium — dropped-event staleness with no periodic reconciliation; the cascade multiplies the blast radius of a stale replica

- **Severity:** Medium (accepted parity, but worth stating as a gap).
- **Evidence:** Bus contract: "a dropped Event degrades a replica to its
  existing TTL fallback … the Bus needs no delivery or ordering guarantees"
  (`bus.go` package doc). Re-seed happens only at boot (`build_signing.go`)
  and invalidation-bus recovery (`server_extensions.go:417`); there is no
  periodic re-seed loop, and `RevocationStore.Prune` has no production
  caller (V). A replica that misses `KindTokenRevokedJTI` without a
  subscribe failure (silent partition, dropped message) honors the jti until
  the token's own `exp`. Parity with the token deny-set is explicit design
  intent (Decision 8), but a single admin click now denies N tokens, so a
  single stale replica is N times more consequential.
- **Triggering failure:** bus drop/partition without resubscribe.
- **User impact:** descendant tokens valid on the stale replica until TTL.
- **Recovery:** replica restart or bus-recovery re-seed.
- **Corrective pattern (optional, closes both the token and jti gaps):** a
  low-frequency periodic `SeedJTIRevocations`/`SeedRevocations` loop
  (idempotent, cheap, `Load`-bounded). If rejected, document the
  no-periodic-reconciliation guarantee explicitly.

### F-6 — Low — `/token/revoke` timing oracle: the cascade runs only for known tokens, before the 200 is written

- **Severity:** Low.
- **Evidence:** `HandleRevoke` writes the 200 **after** `revokeAccess`
  returns (`handle_revoke.go:63-101`); the design's cascade runs inside
  `revokeAccess` gated on `len(revoked) > 0` (Decision 5). A known token
  therefore pays a chain-store walk (N point queries) that an unknown token
  skips — a measurable latency delta. The endpoint already leaks timing
  through per-issuer `Validate` costs and `RevokeAcrossIssuers`, so this
  extends an accepted pattern (RFC 7009 §2.2 is a body contract, not a
  timing contract), and the design's "response is already decided" claim is
  precise only in the error-free sense — the cascade runs strictly before
  the write, not after.
- **Triggering failure:** a caller with fine-grained timing measurement.
- **User impact:** token-existence oracle under adversarial timing analysis
  (pre-existing class; delta widened).
- **Recovery:** n/a.
- **Corrective pattern:** accept and document (recommended); do **not** move
  the cascade to a post-response goroutine (request-context lifetime, audit
  correlation, and shutdown semantics all get worse). If desired, narrow the
  delta by running the walk on the empty-revoked path too — but that costs a
  store read per unknown-token revoke and buys little.

### F-7 — Low — repeated `/token/revoke` of the same token classifies as `failed`, not "already revoked"; the cascade gate interacts correctly

- **Severity:** Low (info for implementers).
- **Evidence:** A second revoke of an already-revoked token fails each
  issuer's `Revoke` (which calls `Validate` → `"rsa: token revoked"`); that
  string matches none of `IsUnknownTokenErr`'s needles ("not found",
  "unknown", "no such" — `internal/handler/validation.go:20-31`), so the
  repeat revoke lands in `failed` → `AuditPartialRevokeFailure` fires.
  The design's cascade gate (`len(revoked) > 0`) correctly yields no cascade
  on the repeat — idempotent by construction, verified compatible.
- **Corrective pattern:** none required; note in the design that the second
  revoke's failure audit is pre-existing behavior, not a cascade artifact.

### F-8 — Info — two factual nits in the design's budget section

- **Evidence:** `domains/tokenexchange/chainstore.go` is 155 lines, not
  "~250" (headroom direction unaffected); `shared/core/consts.go` is 466/500
  (34 lines headroom), so "at budget" is imprecise — the `consts_wire.go`
  placement remains correct and the constraint is still compile-enforced.

---

## 3. Scenario table

| # | Scenario | System behavior under the design | Verdict / notes |
|---|---|---|---|
| P1 | **Partition — bus split, subscriptions alive** | Admin revoke on A marks A's `S1`, persists `S2` (best-effort), publish dropped. B/C honor the jti until their next boot or bus-recovery re-seed. No periodic re-seed exists. | Accepted parity (F-5); token path identical today. Window = token TTL worst case. |
| P2 | **Partition — subscribe fails** | `resubscribeAndReseed` backoff loop (V: `server_extensions.go:409-427`); on reconnect: subscribe → re-seed (token + jti) → clear degraded. `S1` on B converges from `S2` before readiness goes green. | Verified recovery ordering; jti seed must be part of the same `reseedInvalidationState` (design says it is). |
| C1 | **Crash — admin replica mid-cascade** | In-process marks so far hold on A; durable persists best-effort (synchronous call, error swallowed — parity with `rsa_jwt_issuer.go` `Revoke`). Crash between mark and persist → those denies lost on restart; crash between persist and publish → peers stale until their next seed. Partial list is in the failure audit if the request completed. | Window is milliseconds or store-outage-sized; parity with the token path. Retry is idempotent. |
| C2 | **Crash — validating replica** | Restart empties `S1`; boot seed restores from `S2` (wired) — server **build fails** on seed error (V: `build_signing_issuers.go:59,83,112`), i.e. fail-closed at boot, stricter than "stays degraded". Un-wired `S2` (in-process-only) → documented resurrection gap. | Verified; jti seed must fail boot the same way. |
| C3 | **Crash — chain store (sqlite file) unavailable mid-walk** | Walk query error → abort, partial + error, admin 500 with partial list + failure audit; `/token/revoke` logs + audits, 200 stays. Marks already applied remain applied. | Fail-closed per Decision 9; recovery = store back + idempotent retry. |
| R1 | **Retry — admin POST revoke re-sent** | Re-walk + re-mark; set-insert marks; same 200; partial list stable. | Idempotent by construction. |
| R2 | **Retry — duplicate bus delivery** | Adoption is set-insert; no re-publish (local-only mark arm, mirrors `ApplyTokenRevocation`). | Verified pattern; no broadcast loop. |
| R3 | **Retry — `/token/revoke` repeated** | Second revoke: `revoked = []` (issuer `Revoke` fails "token revoked" → `failed`), cascade gate skips. Failure audit fires (pre-existing quirk, F-7). | No double cascade. |
| K1 | **Clock rollback** (replica clock steps back) | `pruneRevoked` uses raw wall clock (V); a rolled-back clock prunes **less** → deny entries live longer → over-denial until the clock catches up. Bounded by the deny `exp`. `exp`-check in `Validate` uses `maxClockSkew` the same direction. | Safe direction. |
| K2 | **Clock jump forward** (NTP step on the pruning replica) | A forward step prunes entries with `exp < fast-now` early → revoked jti (or token) validates again on that replica until its real `exp`. Shared-store variant: a fast-clock replica's `Load` prunes rows (`sqlite/revocations.go:100-119` pattern) a slow-clock peer still needs, and the slow peer's next seed cannot restore them. | **Pre-existing hazard for the token set; the jti set inherits it.** Residual; bounded by token TTL. No new clock dependency introduced (`ExpiresAt` is the token's own `exp`, same unit as `S4`). |
| S1c | **Stale cache — introspection** | Revoke paths evict via the single choke point (`server_token_clientauth.go:461`); the introspection path funnels through `ValidateAnyToken` (`protocols/oauth/handle_introspect.go:267` → issuer `Validate`), so a jti-denied token (V: design consults `S1` inside `Validate`) introspects as invalid on the marking replica — the same cross-replica staleness as any deny applies on peers (P1). No new cache state introduced. | Verified: introspection rides issuer `Validate`; `S1` consultation inside `Validate` covers it. |
| S2c | **Stale replica — no bus, no seed** | Stale until boot/recovery; see P1/F-5. | Accepted parity. |
| D1 | **Dependency outage — `S2` store down during cascade** | Persist best-effort → logged + metric; in-process mark holds; peers converge at next seed (may never come until store returns). | Fail-open for durability, fail-closed for denial (Decision 9). |
| D2 | **Dependency outage — agent-session store down during session cascade** | `HopsBySession` error → joined into revocation error → audit outcome failure; the store-side session revocation (already applied) stands. | Fail-closed reporting; session revocation applies regardless (Decision 6). |
| M1 | **Concurrent cascades (two admins, same root)** | Both walk + mark; set-inserts; same deny values; `-race -count=10+`. | Race-clean by construction (Decision 1). |
| M2 | **Concurrent mint during cascade** | Descendant minted mid-walk escapes; no error, not in partial list. | F-4; document + optional second walk. |
| X1 | **Truncated walk (>1000-node subtree / cycle)** | `ErrChainWalkTruncated` → admin 500 + partial + failure audit; `/token/revoke` logs + audits, 200. | Fail-closed, pinned (Decision 1). |
| X2 | **>1000-hop session** | `HopsBySession` LIMIT silently caps → oldest hops escape the session cascade. | **F-1 — High; must add a truncation signal.** |
| X3 | **Pre-v2 hop in subtree** | `ErrHopMissingExpiry` abort → admin 500, empty partial, root never denied. | F-3; permanent per pre-v2 jti. |
| X4 | **jti collision across issuers** | Denied on every armed issuer; a colliding foreign token is over-denied. | Accepted (Decision 10); safe direction. |
| X5 | **Late-joining replica** | Boot seed from `S2` covers it (wired). | Verified pattern. |
| X6 | **Seed failure at recovery** | Stays degraded, audited, retried with backoff (V: `server_extensions.go:417-427`); jti seed failure joins the same error join. | Fail-closed; readiness stays red. |

---

## 4. Stated guarantees, unsupported topologies, validation tests, residual risks

### Guarantees the design can actually state (and the code supports)

1. **Fail-closed denial, locally.** A jti marked in any armed issuer's `S1`
   is rejected by that issuer's `Validate`; `S1` is in-process and cannot
   fail, so the denial itself is atomic and total on the marking replica
   (Decision 2, parity with the token set's runtime authority).
2. **Fail-closed reporting, everywhere.** Every cascade surface returns
   partial results + error and audits both (walk error, expire error,
   truncation). No silent partial success — **except F-1 (session-cap
   truncation) and F-4 (concurrent mint)**, which are silent by construction
   and must be documented or fixed.
3. **Oracle safety of `/token/revoke`.** 200-always and byte-identical;
   cascade unobservable on the wire, gated on `len(revoked) > 0` (F-6
   narrows this to "unobservable modulo accepted timing deltas").
4. **Idempotency.** Marks, durable upserts, bus adoption, admin retries, and
   repeated revokes are all idempotent; order-independence holds because all
   writers derive the same `exp` from the hop's immutable `ExpiresAt`
   (S1/S2/S5).
5. **Recovery ordering.** subscribe → re-seed → clear degraded (verified);
   boot seed failure fails the build (verified) — the jti seed joins both
   seams with the same properties.
6. **Parity with the token deny-set.** Cross-replica propagation
   (best-effort bus), restart/late-join survival (durable store + boot
   seed), and the fail-open durability leg are exact mirrors of the existing
   revocation architecture, including its accepted gaps (F-2, F-5, K2).

### Unsupported topologies (must be stated in the endpoint/store docs)

- **Memory `ChainStore` + memory `JTIRevocationStore` across replicas**:
  process-lifetime only; every cascade mark, hop record, and session dies
  with the process. Single-replica/dev only — the design's "memory for
  test/single-replica" claim is correct and must stay explicit.
- **Shared sqlite file across replicas over a network filesystem**: the
  existing `ChainStore`/`RevocationStore` docs claim shared-file
  multi-replica; sqlite file locking over NFS-class filesystems is
  unreliable under concurrent writers. The cascade adds a new writer class
  (admin revoke + `/token/revoke` side-effect on any replica). Deployments
  using shared files must be on local/block storage or a single-writer
  layout; otherwise use per-replica files + bus (the bus then becomes the
  only cross-replica propagation and F-5's window applies in full).
- **In-process-only deployments (no `S2`)** accept restart-resurrection of
  every jti denial — parity with the token path, but the cascade makes one
  admin click resurrect N tokens on restart. Document.
- **Mixed-version peers**: an old peer drops `KindTokenRevokedJTI` at its
  default arm (verified `bus.go` kind-addition contract) — cascades degrade
  to single-replica scope until the fleet converges. Acceptable; state it.

### Validation tests the acceptance suite must add (distributed-systems slice)

1. **F-1**: session with >1000 hops → cascade must abort with the
   truncation signal + partial list in audit; assert the 1001st hop is
   reported, never silently dropped.
2. **F-2**: bus adoption of an event with absent/zero `MetaRevokedExp` →
   assert the adopted entry survives (clamped floor), never prunes
   immediately.
3. **F-3**: subtree containing a pre-v2 row (migration fixture) → 500 +
   empty partial + failure audit; root jti not denied; a skip-expired
   refinement, if adopted, asserts expired-hop subtrees revoke cleanly.
4. **F-4**: concurrent `RecordHop` during a cascade (`-race -count=10+`) →
   assert the documented outcome: escaped mint is absent from the partial
   list, no error, audit carries `walked_at`; a second walk, if adopted,
   catches it.
5. **K2**: clock-jump test — advance the pruning clock past a deny `exp`,
   assert the revoked token validates again (documenting the residual
   window), and assert the shared-store prune-on-load does not delete rows a
   slower-clock peer needs (or accept + document).
6. **P1/P2**: drop the bus, then resubscribe → assert re-seed restores both
   `S1` (jti) and `S4` (token) before degraded clears.
7. **C1**: crash-mid-cascade simulation (mark, kill before persist) →
   assert documented resurrection on restart without `S2`, and survival with
   `S2` wired.
8. **R1/R2/R3**: idempotency — admin retry, duplicate bus delivery, repeat
   `/token/revoke` (assert no second cascade and the F-7 failure-audit
   quirk).
9. **X1/X2**: truncation on both walk and session boundaries.
10. The design's own list (validation-level deny on all three issuers,
    unwired-store byte-identical no-op, existing revoke-oracle suite
    unchanged) remains the entry gate.

### Residual risks (accepted, must be documented in the endpoint contract)

- Cross-replica jti denial converges only via best-effort bus + boot/recovery
  re-seed; there is no periodic reconciliation (F-5). A stale replica honors
  a revoked jti until the token's own `exp`.
- A forward clock jump on a pruning replica (or shared-store pruner) can
  resurrect a deny early; bounded by the token's `exp` (K2). Pre-existing
  for the token set.
- The cascade is not linearizable against the mint path (F-4); concurrent
  exchanges can escape. Point-in-time semantics.
- Restart-resurrection for in-process-only deployments (unsupported topology
  above).
- Admin root-kill is jti-deny-only: any downstream validator that does not
  consult `S1` still honors the root until TTL (Decision 10 risk 11 —
  in-scope validators all go through `Validate`).
