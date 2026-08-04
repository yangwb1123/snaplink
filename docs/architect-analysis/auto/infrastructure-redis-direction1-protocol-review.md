# Protocol Review: Redis as the Cluster Coordination Layer (direction 1)

Role: identity-protocol reviewer. Advisory only; no files modified. Scope:
the design `docs/auto/infrastructure-redis-direction1-design.md` (663 lines)
for spec `docs/auto/infrastructure-redis-direction1-spec.md`. The change is
an internal transport cutover (invalidation bus backend) — no HTTP surface,
no token format, and no endpoint behavior changes. The protocol review
therefore evaluates the design against the identity-protocol contracts whose
**semantics the bus carries**: RFC 7009 revocation enforcement, RFC 9068
access-token deny-set behavior, RFC 7519 `exp`, RFC 7517/OIDC JWKS rotation,
RFC 8414/OIDC Discovery freshness, and the CAEP/SSF boundary.

Evidence labels: **Verified** (re-read against source or vendored dependency
in this revision), **Partial**, **Missing**, **Inaccurate**, **Proposed**
(design intent, not yet implemented). Line numbers are current-worktree or
vendored-module lines.

## 1. Protocol/profile scope and authoritative references

The design touches **zero request/response surfaces**: no handler, no route,
no discovery document, no error code, no token claim changes. The standards
actually in scope are the ones the coordinated state serves:

| Standard | Section | Relationship to this design |
|---|---|---|
| RFC 7009 OAuth 2.0 Token Revocation | §2.1, §2.2, §2.2.1 | `KindTokenRevoked` is the cross-replica enforcement arm of `/token/revoke` (Verified: `protocols/oauth/handle_revoke.go`; publish happens post-revocation in `internal/handler/cross_replica.go:63-88`) |
| RFC 9068 JWT Profile for Access Tokens | §2, §4 | The revoked artifact is an RFC 9068 access token; the deny-set is consulted at validation time (Verified: `infrastructure/defaultimpl/revocation_set.go`; `revoked` map per issuer) |
| RFC 7519 JSON Web Token | §4.1.4 `exp` | Deny-set entries are exp-bounded; `MetaRevokedExp` is advisory, receiver re-derives from the token (Verified: `revocation_set.go` prune-not-early gate; `internal/handler/cross_replica.go:105-115` re-decodes) |
| RFC 7517 JWK | §4.5 `kid` | `KindSigningKeyRotation` coordinates new-kid adoption + old-kid retirement deferral (Verified: `interfaces/sso/server_key_rotation.go` `applyCoordinatedKeyRotation`, `scheduleCoordinatedRetire`) |
| RFC 8414 / OIDC Discovery 1.0 | metadata caching | `KindDiscoveryReload`/`KindClientChange` flush the discovery snapshot + rendered docs + JWKS body cache (Verified: `interfaces/sso/server_discovery_cache.go:270-329`) |
| OpenID SSF v1 / CAEP | — | Boundary only: SETs flow to external RPs via `protocols/caep/`; the bus is mesh-internal and never touches CAEP delivery (Verified: `docs/feature-matrix.md:138-140`) |
| OAuth 2.0 Security BCP (RFC 9700) | §4.14 refresh-family | Refresh-family revocation is store-side (shared Redis store), explicitly NOT carried by the bus (Verified: `platform/cluster/bus.go` `KindTokenRevoked` doc; design state map) |

Explicitly out of scope and untouched by the design: OIDC Core authorization
code / PKCE / refresh flows, DPoP, mTLS, JAR/PAR, CIBA, introspection, client
authentication, redirect handling, replay controls (JTI store), and every
`/token/*` response shape. None of these appear in the diff surface.

## 2. Compliance matrix

Requirement level: MUST / SHOULD / MAY per the cited section; "profile"
marks Snaplink's own documented invariants (AGENTS.md, config-reference).

| Section / requirement | Level | Implementation evidence (verified) | Design impact | Status | Deviation | Test |
|---|---|---|---|---|---|---|
| RFC 7009 §2.1 — revoke with valid client creds always 200, empty body | MUST | `handle_revoke.go` `HandleRevoke` returns `200 {}` after both tiers; oracle-safe | None — bus publish is post-response, fire-and-forget | **Preserved** | None | Existing `rootcov_admin_token_revoke_test.go`, `test/admin_token_revoke_test.go` (unchanged) |
| RFC 7009 §2.2 — unknown/expired/consumed token indistinguishable from success | MUST | `HandleRevoke` doc + `revokeAccess`/`revokeRefresh` ignore per-tier errors | None — no new observable path; `KindTokenRevoked` is only published after a *successful local* revoke | **Preserved** | None | Existing revoke tests; new bus tests must not assert any HTTP difference |
| RFC 7009 §2.2.1 — client authentication (basic, body, JWT assertion) | MUST | `authenticateRevokeClient` collapses all failures to identical `401 invalid_client` | None | **Preserved** | None | Unchanged |
| RFC 7009 §2.1 + Snaplink — a revoked access token stops validating on **every** armed replica | profile (MUST per `cluster.cross_replica_revocation` doc) | `KindTokenRevoked` → `ApplyTokenRevocation` → local-only `RevokeAcrossIssuers` adds to deny-set (`internal/handler/cross_replica.go:98-117`); re-seed at boot and recovery (`server_extensions.go:443-461`) | **The design's central load-bearing claim.** G-2 "loss = closed channel" is NOT delivered by `PubSub.Channel()` on pinned go-redis v9.20.0 (Finding P-1); re-seed source is sqlite/memory, not Redis (Finding P-2) | **At risk** | See P-1, P-2 | T-1, T-2, T-3 below |
| RFC 9068 §4 — revoked access token rejected until `exp`; never a valid token wrongly rejected | MUST (fail-open direction) | `revocation_set.go`: additive deny-set; `markRevoked` exp-bounded; prune-not-early gate | Preserved — applying an event only ever ADDS tokens; garbage events dropped (`cross_replica.go:110-115`) | **Preserved** | None | Round-trip + garbage-drop unit tests |
| RFC 7519 §4.1.4 — `exp` honored; denial entries expire with the token | MUST | `pruneRevoked` strict `< nowUnix` cutoff; `MetaRevokedExp` advisory (receiver re-decodes) | Preserved — `MetaRevokedExp` never trusted over the token's own claim | **Preserved** | None | Round-trip fidelity incl. Payload |
| RFC 7517 §4.5 + OIDC — rotated key: new kid verifiable immediately, old kid verify-only until deadline | MUST (Snaplink profile: widen-only) | `applyCoordinatedKeyRotation` adopts new kid via alg-matched `adoptPeerKey`, defers retire with floor/ceiling clamping (`server_key_rotation.go:163-215`) | A lost `KindSigningKeyRotation` only delays retire (widen-only, never early); self-skip collision widens the window silently (P-3) | **Preserved** (fail-safe direction) | None | Existing key-rotation tests; self-skip edge tests (M1) |
| RFC 8414 / OIDC Discovery — metadata reflects current client state | SHOULD (Snaplink: discovery derived from server state) | `invalidateDiscoveryCaches` + `InvalidateJWKSBodyCache`; `KindDiscoveryReload` published on client mutations (`server_discovery_cache.go:303-329`) | Lost event → TTL fallback only; same as every peer today | **Preserved** | None | Cross-server convergence E2E |
| Snaplink §3 — recovery order: resubscribe → flush caches → re-seed deny-sets → clear degraded | profile (MUST) | `resubscribeAndReseed` subscribe-first ordering (`server_extensions.go:407-434`); partial re-seed keeps degraded | Preserved *only if* the bus surfaces loss as closure (P-1) and the re-seed source is durable (P-2) | **At risk** | See P-1, P-2 | T-2 |
| Snaplink §3 — revocation deny-set has NO TTL safety net; re-seed is the repair | profile | `revocation_set.go` RevocationStore doc; `reseedRevocationDenySets` | Design's own state map states this correctly ("NO TTL safety net") — but F-1/impact rows elsewhere say "TTL fallback" for revoked tokens (P-3) | **Wording drift** | P-3 | — |
| OpenID SSF v1 — CAEP receiver fail-closed, JTI replay, affected-clients-only delivery | profile | `protocols/caep/` receiver/broadcaster; `feature_gates.caep` | No interaction: different transport, different trust domain | **Preserved** | None | Unchanged |
| Wire compatibility — mixed-version fleets | profile (Snaplink §4) | `encoding/json` skips unknown fields; `applyInvalidation` default arm ignores unknown kinds (`server_invalidation.go:331`) | Additive optional `instance` field; absent instance ⇒ self-skip off ⇒ delivered | **Preserved** (Proposed, with edge tests M1) | None | Near-miss ID tests |
| Credential endpoints — `Cache-Control: no-store` | profile | `middleware.TokenNoStoreHeaders` in `HandleRevoke` | Unchanged — bus is not an HTTP surface | **Preserved** | None | Unchanged |

## 3. Findings

Severity per the shared rubric. Independent verification note: findings P-1
and P-2 corroborate, from the protocol side, the database review's Critical
and High; the vendored-source lines below were re-read in this revision.

### P-1 — Critical — G-2's central invariant is not delivered by `PubSub.Channel()` on the pinned go-redis v9.20.0; a replica can validate revoked access tokens until `exp` with `/readyz` green

**Requirement:** RFC 7009 §2.1 + Snaplink cross-replica revocation
(`cluster.cross_replica_revocation`); AGENTS.md §3 "invalidation-bus
recovery re-subscribes, flushes caches, and re-seeds ... before clearing
degraded readiness". The entire recovery loop is keyed on ONE signal: the
subscription channel closing under a live context
(`server_invalidation.go:138-188`).

**Evidence (Verified, vendored `go-redis@v9.20.0`):**
- `pubsub.go:718-751` `initMsgChan` (backing `Channel()`): on `Receive`
  error, only `err == pool.ErrClosed` closes `msgCh`; every other error
  increments `errCount` and loops forever (`continue`).
- `pubsub.go:709-717` health check (default 3s): on ping failure it calls
  `c.pubSub.reconnect(...)` — which redials and resubscribes
  (`pubsub.go:183-190`), never closes the channel.
- `pubsub.go:537-543`: `Receive` = `ReceiveTimeout(ctx, 0)`; with no ctx
  deadline, `internal/pool/conn.go` `deadline()` returns `noDeadline` — a
  half-open TCP connection blocks the read indefinitely.
- So the design's claim "go-redis closes its `PubSub` receive channel when
  reconnection fails" is **Inaccurate** for the API the design names
  (`rdb.Subscribe(...)` + message channel). The database review proved it
  empirically (channel open 8s+ after server kill; closes only on client
  `Close`).

**Impact:** a Redis outage/failover with the client open leaves the
subscription live-looking: no degraded audit, `sso_invalidation_bus_up == 1`,
`/readyz` green, and the deny-set misses every `KindTokenRevoked` published
during the outage — a revoked (possibly stolen, RFC 9068) access token keeps
validating until its own `exp`, and recovery never re-seeds. This is exactly
the "blind replica" the design exists to rule out.

**Corrective behavior (required before implementation):** the design must
specify a **bus-owned receive loop**, not `Channel()`: `Subscribe` returns
the `*PubSub`; a decode goroutine loops `ReceiveMessage`/`ReceiveTimeout`
with an explicit read deadline (heartbeat), closes `out` on ANY error, and a
ctx-done/`Close()` watcher calls `ps.Close()` to unblock a stuck read (the
only reliable unblock for `noDeadline` reads) with `defer ps.Close()` so the
dedicated pub/sub pool connection is released per cycle. With that shape,
G-2 holds; with `Channel()`, G-2 is false. This also decides the QA review's
L4 (decode API choice): `ReceiveTimeout` with a deadline is the only option
that satisfies both G-2 and the silent-stall row of the loss taxonomy.

### P-2 — High — the `KindTokenRevoked` re-seed source is sqlite/memory, not Redis; a "redis-only" fleet can get a no-op re-seed and resurrect revoked tokens

**Requirement:** Snaplink cross-replica revocation durability + AGENTS.md §3
"re-seeds revocation deny-sets before clearing degraded readiness". The
design's G-5 (fail-closed recovery) and its state map ("the durable
revocation store is the re-seed source") assume a durable store exists.

**Evidence (Verified):** `cmd/sso-server/serverbuildsign/build_signing.go:84-107`
`BuildRevocationStore` accepts only `""` | `memory` | `sqlite`
(`keys.signing.revocation_backend`); there is no Redis `RevocationStore`
(`infrastructure/redis/` has none; `docs/config-reference.md:124` lists
`memory · sqlite`). With `""`, `SeedRevocations` is a nil-store no-op
(`revocation_set.go` store doc: "Without one, a revoked-but-unexpired access
token RESURRECTS after a process restart ... and on a late-joining replica").
The design's own scenario table ("Stale cache ... deny-set entry stays
missing until exp") and G-5 depend on this store.

**Impact:** the direction's stated goal is collapsing the operational model
to "one Redis" — but a fleet that moves the bus to Redis while leaving
`keys.signing.revocation_backend` unset gets: boot re-seed no-op, recovery
re-seed no-op, and the degraded loop reporting `re_seeded=true` while the
deny-set stays empty. RFC 7009-revoked access tokens (the highest-value
artifact in the bus) survive restarts on every replica. The readycheck can
not see it (`InvalidationBusReady` only tracks the subscription).

**Corrective behavior:** in the same change, state in the design, in
`docs/config-reference.md` next to the bus row, and in the `BuildInvalidationBus`
redis-branch log line: `backend=redis` + `cross_replica_revocation` requires
`keys.signing.revocation_backend: sqlite` (or memory, with the documented
restart gap) for the re-seed to be non-empty. A redis `RevocationStore` is a
separate, optional follow-on; without the documentation, the direction's own
operational story is incomplete.

### P-3 — High — the self-skip ID-collision impact is understated: for `KindTokenRevoked` there is no TTL fallback, the denial window is the token's full remaining validity

**Requirement:** RFC 7009 §2.1 enforcement across replicas; the design's own
state map ("Access-token revocation deny-set ... NO TTL safety net").

**Evidence (Verified):** `revocation_set.go` deny-set entries are exp-bounded,
not TTL-bounded; `reseedInvalidationState` comment: "the one target with NO
TTL safety net: a missed KindTokenRevoked would otherwise honor a revoked
token until its own exp". The design's F-1 impact row ("stays honored on the
peer until its TTL; no signal anywhere") and its mitigation paragraph
("fail-safe in the direction of staleness (TTL fallback)") are **Inaccurate
for this kind**: a collided-instance-ID pair suppresses propagation for up to
the full token lifetime, with no TTL convergence. Every other kind degrades
to TTL; this one degrades to `exp`. The QA review's M4 (nothing pins the bus
instance ID to the signing-key replica ID at the build layer) is the
enforcement gap: `build_app_cluster.go:226-232` derives `replicaID` via
`ResolveServiceID`, and the wiring must pass exactly that value.

**Corrective behavior:** (1) correct the F-1 wording to name the exp-bounded
window for `KindTokenRevoked`; (2) require the build-layer equality test (QA
M4) so the bus ID cannot diverge from the signing-key replica ID; (3) adopt
the design's own suggestion — a startup log line recording the effective bus
instance ID — since the failure is otherwise invisible by construction.

### P-4 — Medium — the bus channel now carries full bearer credentials (RFC 9068 access tokens); the trust model must be stated as an operational requirement

**Requirement:** RFC 9068 §4 (the token is the credential); Snaplink's
existing trust model ("mesh-internal bus; same trust model as
KindTenantSuspension", `platform/cluster/bus.go`).

**Evidence (Verified):** `PublishTokenRevocation` places the FULL token in
`MetaRevokedToken` (`internal/handler/cross_replica.go:73-77`); the redis
envelope is that payload JSON-published on `snaplink:cluster:bus`. Redis
pub/sub messages are visible to every client that can `SUBSCRIBE` the
channel — a shared-password fleet, an ACL misconfiguration, a second
deployment on the same logical Redis (design F-6), or a Redis-side attacker
can harvest live access tokens without touching any keyspace key. etcd
achieves the same confidentiality via dedicated endpoints + mTLS/TLS in the
reference deployment; Redis typically shares one password across stores.

**Corrective behavior (documentation + operational, no code change to the
SPI):** the design's trust-model paragraph must state the requirement:
channel visibility is governed by Redis ACLs (`+subscribe|snaplink:cluster:bus`
scoping), network isolation, and TLS; deployments sharing one logical Redis
across tenants must set distinct `redis_channel` values (F-6) *and* treat the
channel as bearer-credential-equivalent. This is a MUST for any deployment
with `cluster.cross_replica_revocation` armed, not an optional hardening.

### P-5 — Medium — slow-consumer/silent drop is the only loss mode with an unbounded-until-exp consequence; the design should state the bound explicitly

**Requirement:** RFC 7009 enforcement; design G-8 (16-slot drop-not-block).

**Evidence (Verified):** every other kind's drop converges via TTL; the
deny-set has no TTL (`server_extensions.go:443-461`, `revocation_set.go`).
The design's F-8/F-5 rows say "TTL fallback" generically.

**Corrective behavior:** one sentence in the design stating: a dropped
`KindTokenRevoked` on a healthy connection leaves that replica validating the
token until `exp`; the repair is the next resubscribe's re-seed or the next
revocation of the same token — there is no intermediate convergence. This is
the honest bound of the best-effort SPI and matches the etcd/mqtt peers; it
must not be "fixed" with sequence numbers (design F-5) — but it should be
written down so operators size the buffer and the fleet correctly.

### P-6 — Low — the loss-taxonomy "Silent stall" row attributes heartbeat detection to go-redis that v9.20.0 does not perform

**Requirement:** none (design-internal factual accuracy).

**Evidence (Verified):** `pubsub.go:709-717` health check (3s default
interval, enabled by default in `newChannel`) responds to a failed ping by
calling `reconnect` — redial + resubscribe, never closure — so even with
the heartbeat the channel stays open across an outage; and with the
required receive-loop fix (P-1) there is no go-redis heartbeat at all — the
bus must own the read deadline.

**Corrective behavior:** rewrite the row to say: silent stalls are detected by
the bus-owned `ReceiveTimeout` deadline (P-1 fix); without it, a half-open
connection stalls forever (`internal/pool/conn.go` `noDeadline`).

### P-7 — Low — mixed-version `instance` field is wire-safe; the absent-instance case is the one edge that must be pinned by test

**Requirement:** Snaplink §4 mixed-version fleets.

**Evidence (Verified):** Go `encoding/json` skips unknown fields on decode
(older peer ignores `instance`); an older peer publishes without `instance`,
so a newer peer's self-skip filter (exact own-ID match only) must deliver it
— the design's M1 near-miss edges ("a", "a ", "A", "a\n", absent) cover this.

**Corrective behavior:** none beyond the QA M1 test; the design's "byte
identical unless opted in" default (`""` = self-skip off) is correct and
should not change.

### P-8 — Info — CAEP/SSF boundary is clean; operators should not conflate `sso_invalidation_bus_up` with SSF delivery health

**Evidence (Verified):** SET delivery to external RPs is `protocols/caep/`
(broadcaster → RP receiver), gated by `feature_gates.caep`, fail-closed with
JTI replay; the bus is a different transport in a different trust domain.
A Redis outage degrades the bus (drain via `/readyz`) but does not touch SSF
delivery, and vice versa.

**Corrective behavior:** none in code; one line in the design's observability
paragraph distinguishing the two gauges would prevent operator confusion.

## 4. Priority conformance tests, declared unsupported features, certification

### Priority tests (protocol-relevant subset of the design's plan)

| ID | Test | Protocol property it pins | Mechanism (Verified feasible) |
|---|---|---|---|
| T-1 | Transport loss closes the subscription; subsequent `Publish` errors (unit) | G-2/G-4 — the RFC 7009 enforcement signal | miniredis `Close()` (client survives) or `goredis.Client.Close()`; asserted against the *receive-loop* implementation, not `Channel()` (P-1) |
| T-2 | Forced-loss degraded→recover E2E: degraded audit ×1, gauge 0 → resubscribe → re-seed → healthy audit ×1 `re_seeded=true`; token revoked during the outage is rejected after recovery | RFC 7009 cross-replica enforcement + AGENTS.md §3 ordering | miniredis `Restart()` same-address (Verified: `miniredis.go:238`); two-replica harness per `test/cross_replica_revocation_test.go`; ≥10s polling deadlines (go-redis retry-exhaustion latency); production backoff (the `SetInvalidationBusBackoffBaseForTest` seam at `interfaces/sso/export_test.go:121` is not available in `package ssotest`) |
| T-3 | `Subscribe` on unreachable Redis returns a synchronous error; `NewBus(nil)` errors descriptively on first use | G-4 boot contract | go-redis `Subscribe` dials synchronously (`pubsub.go:74-113`); closed-port client |
| T-4 | Self-skip near-miss edges: own-ID dropped; `"b"`, absent instance, `"a "`, `"A"`, `"a\n"` delivered | P-3/P-7 mixed-version + collision safety | Unit, miniredis |
| T-5 | Build-layer equality: bus instance ID == `WithSigningKeyReplicaID` value (explicit `replica_id` and `ResolveServiceID` fallback) | P-3 enforcement | cmd build test; both derive from `build_app_cluster.go:226-232` |
| T-6 | Envelope round-trip with full token payload; garbage payload dropped, stream stays open; concurrent publish + drain + concurrent `Close` under `-race -count=10` | RFC 9068 payload fidelity; G-8 | `infrastructure/redis/bus_test.go`; raw-publish garbage injection |
| T-7 | `backend=redis` config validation (nil-rdb boot error shape; miniredis-backed non-nil bus); docs row `off · memory · etcd · redis` + `redis_channel` + P-2 revocation-store note | F-11, P-2 | `cluster_bus_test.go` extension |

### Declared unsupported (correct per the SPI; do not add)

Replay/durable backlog, sequence numbers, per-kind channels, internal
reconnect inside the bus (recovery loop is the single owner), blocking
publish, unbounded buffers, channel heartbeats (F-2 proxy blind spot), and
delivery guarantees of any kind. Also out of scope by the spec: store
observability, session-enumeration N+1, the `infrastructure/redis/doc.go`
nested-module drift, and a Redis `RevocationStore` (P-2 follow-on).

### Certification evidence

No OIDF or other conformance certification is claimed by this change, and
none should be: the design alters no certified surface (discovery documents
are derived from server state and unchanged; the only public-facing delta is
a config enum value and an internal transport). The current
`docs/feature-matrix.md` SSF rows (138-140) are unaffected. Remaining
evidence gaps: real-Redis reconnect-exhaustion timing (miniredis does not
emulate it — `cmd_pubsub.go` implements SUB/PUB only), Redis Cluster fan-out
behavior under a real multi-node topology, and real proxy behavior for the
F-2 blind spot — all accepted, documented, and bounded by the TTL/exp
fallbacks above.

## Bottom line

The design is protocol-preserving everywhere it touches a wire surface, and
its two genuinely dangerous failure modes are correctly identified (F-1
silent coordination loss; G-2 loss detection). But as written it cannot
discharge its own central invariant: **P-1** (the pinned go-redis version's
`Channel()` never surfaces transport loss) and **P-2** (the `KindTokenRevoked`
re-seed is not Redis-backed, so the direction's "one Redis" story has a
sqlite dependency that must be stated) must be resolved in the design before
implementation. P-3 is a wording + test-enforcement fix. None of P-1..P-3
change the SPI, the HTTP surfaces, or any token/discovery contract — they
are implementation-shape and documentation decisions.
