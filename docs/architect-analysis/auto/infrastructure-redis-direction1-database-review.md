# Database Review: Redis as the Cluster Coordination Layer (direction 1)

Review of `docs/auto/infrastructure-redis-direction1-design.md` (and its
spec companion) from the database-architect perspective: persistence
correctness, hot vs durable classification, stock-binary wiring, atomic
paths, migration safety, and recovery semantics.

Role constraints applied per `ai-dev/prompts/README.md`: advisory only;
claims labeled Verified / Partial / Missing / Proposed / Unknown; checks
that actually ran are listed in the appendix.

## Verdict

The direction is sound on the persistence axis — the design correctly
classifies the bus as a **hot, non-durable, stateless transport** (no
keyspace, no TTL, no replay, no retention), and correctly reuses the
shared Redis client rather than adding a second connection story. The
wire/storage model (single JSON envelope, additive `instance` field, one
non-slot-routed channel) is version-safe and cluster-correct.

However, **two mechanism-level defects block the design as written**, and
one of them invalidates the design's central invariant and its own
acceptance tests:

1. **Critical — the loss-detection invariant is not delivered by
   `PubSub.Channel()` on the pinned go-redis v9.20.0.** Empirically
   disproven: the receive channel does NOT close on connection loss with
   failed reconnection; it closes only on explicit client/PubSub `Close`.
   The design's failure-taxonomy row ("reconnect fails → go-redis closes
   the PubSub receive channel") and its "internal heartbeat closes the
   channel" row are both false for this dependency version. The forced-loss
   tests as specified therefore cannot validate the design: the
   client-close variant passes vacuously (the only case that closes), the
   miniredis-close variant fails to observe closure.
2. **High — `NewBus(rdb goredis.Cmdable, ...)` does not compile.**
   `Subscribe` is not on `Cmdable` (keyspace-only); it lives on
   `UniversalClient`. The fix is a parameter-type change; the wiring claim
   itself is verified and holds.

Fix #1 by having the bus own the receive loop (`ReceiveMessage` /
`ReceiveTimeout` with a bounded read deadline) and close the out-channel on
any error — empirically proven to surface transport loss as `EOF` and to
recover across a server restart. Fix #2 by changing the constructor
parameter to `goredis.UniversalClient`. Both are small, and neither
changes the storage model, wiring shape, or recovery-loop ownership that
make this direction attractive.

## 1. Store inventory

Verified against `docs/config-reference.md:95-131`, `cmd/sso-server/build_stores.go`,
`cmd/sso-server/build_bootstrap.go:203-233`, and `infrastructure/redis/`.

| Store / subsystem | Purpose | Durability class | Implementation | Stock-binary wiring | Consistency requirement |
|---|---|---|---|---|---|
| Sessions | Hot session state | Hot (TTL-bounded, lossy by design) | `infrastructure/redis/session.go` (Lua-guarded Refresh) | `identity.session_backend: redis` via shared client | Read-your-writes within a flow; fail closed on outage |
| OAuth hot stores (auth_code, refresh_token + family ledger, device_code, par) | Single-use grants | Hot; single-use atomicity | `auth_code.go`, `refresh_token.go`, `refresh_token_rotation.go`, `par.go`, `device_code.go` — GETDEL consume, Lua family rotation | `oauth.backend: redis` | Atomic consume; oracle-safe not-found; family reuse kills family |
| CIBA / MFA challenge / password_reset / temp_token / consent_challenge / account_lockout | Flow state | Hot | `ciba.go` (Lua pending-only transition), `mfa_challenge.go`, `password_reset.go`, `account_lockout.go` | `ciba.backend`, `mfa.challenge.backend`, `security.account_lockout.backend`, `self_service.password_reset.backend: redis` | Atomic single-use; oracle-safe collapse |
| JTI replay | Replay detection | Hot | `jti_replay.go` — `SET NX EX` | `security.jti_replay.backend: redis` | Atomic first-sighting |
| Rate limiter | Defense layer | Hot, fail-open | `ratelimit.go` — Lua INCR+EXPIRE | `security.rate_limit.backend: redis` | Atomic window; fail open |
| BCL subject-client index, refresh grace, users/clients caches, permissions | Lookup/aux | Hot | `bcl_failures.go`/`subject_client_index.go`, `refresh_grace.go`, `clients.go`, `users.go`, `permissions.go` | Various `redis` backends | Best-effort; TTL fallback |
| **Cluster bus (this design)** | Cross-replica invalidation | **Hot, NON-durable, stateless transport** | `infrastructure/redis/bus.go` (proposed): `PUBLISH`/`SUBSCRIBE` only, no keys, no TTL, no replay | `cluster.bus.backend: redis` (proposed) consuming the SAME shared client | Best-effort by SPI contract (`platform/cluster/bus.go` package doc); drop = TTL fallback, never a wrong answer |
| Signing-key registry / service registry / network store / bootstrap lock | Coordination | Durable-ish via etcd leases (not Redis) | etcd backends | `keys.signing_key_registry.backend`, `registry.backend`, `network.store`, `bootstrap.lock.backend` | Fail closed for registry lease; out of scope here |
| Identity (clients+users), audit, permissions durable | Authoritative durable state | Durable | sqlite / postgres | `identity.backend`, `audit.backend`, `permissions.backend` | The source of truth the bus's re-seed reads from |

Key classification facts (Verified):

- `infrastructure/redis` is a **root-module package** — no `go.mod`
  (`ls infrastructure/redis/go.mod` → absent); go-redis v9.20.0 and
  miniredis v2.38.0 are root `go.mod` deps. The `doc.go` nested-module
  claim is pre-existing drift, correctly excluded from scope.
- The stock binary builds ONE shared client: `wireRedis`
  (`cmd/sso-server/build_bootstrap.go:203`) → `NewUniversalClient`
  (`infrastructure/redis/universal.go:114`, returns `goredis.UniversalClient`),
  stored on `b.redis` (`cmd/sso-server/build_app.go:60`), readycheck
  `redis` registered (`build_bootstrap.go:222`), and runs **before**
  `wireCluster` (`build_stores.go:44` vs `build_app.go:240`). The design's
  "b.redis is ready when BuildInvalidationBus runs" claim is Verified.
- Redis-backed stores take `goredis.Cmdable` (e.g.
  `auth_code.go:65`, `session.go:51`, `ratelimit.go:49`) — keyspace-only
  ops. The bus needs `Subscribe`, which is not on `Cmdable` (see Finding 2).

## 2. Findings

### F1 — Critical: the loss-detection invariant is not delivered by `PubSub.Channel()` on the pinned go-redis v9.20.0

**Path/evidence (Verified, source + empirical):**

- go-redis v9.20.0 `pubsub.go:719-752` `initMsgChan` (what `ps.Channel()`
  returns): closes `c.msgCh` **only** when `Receive` returns
  `pool.ErrClosed`; **any other error** → `errCount++; continue`
  (100 ms sleep between attempts) — an unbounded internal retry loop. The
  loop's ctx is `context.TODO()` (`pubsub.go:720`), so even the caller's
  ctx cancellation does not close it.
- `Receive` → `ReceiveTimeout(ctx, 0)` (`pubsub.go:527-532`); with timeout
  0 and no ctx deadline, `Conn.WithReader` sets **no read deadline**
  (`internal/pool/conn.go:874-892, 964-980`) — a half-open connection
  blocks until the OS TCP stack gives up (minutes).
- The health check (`initHealthCheck`, `pubsub.go:690-717`) pings every 3 s
  and on ping failure calls `reconnect` (`pubsub.go:183-197`), which closes
  the dead connection and re-dials — but **never closes the message
  channel**.
- `conn` returns `pool.ErrClosed` only when the PubSub itself is closed
  (`pubsub.go:74-78`); `PubSub.Close` is the only path that sets `closed`
  (`pubsub.go:211-229`).
- Empirical proof (scratch program, exact pinned versions v9.20.0 +
  miniredis v2.38.0, run for this review):
  1. Round-trip publish/subscribe OK.
  2. `mr.Close()` (server death, client open) → channel **still open at
     8 s**, no closure signal, no error.
  3. `rdb.Close()` (client closed) → channel closes immediately
     (`ok: false`).
  4. Control experiment with a bus-owned `ReceiveMessage(ctx)` loop: server
     death surfaces as `EOF` promptly; restarting miniredis on the same
     address + fresh `Subscribe` delivers again.

**Contradicted design claims:** the failure-taxonomy row "Connection drops
mid-subscription, reconnect fails, or client closed → go-redis closes the
PubSub receive channel"; the silent-stall row "go-redis's internal
heartbeat ... closes the PubSub channel"; the API-surface bullet "the
out-channel closes exactly when (a) ctx cancelled, (b) Close() called, or
(c) the pub/sub connection is lost"; and spec line 72 ("reconnect-with-
backoff exhaustion (`PubSub` receives `redis.ErrClosed` / channel
closure)").

**Impact:** during any Redis outage, or pub/sub-connection death with
failed reconnection, the decode goroutine keeps waiting on a live-looking
channel. The replica is blind with: no `invalidation_bus_degraded` audit,
no `sso_invalidation_bus_up` gauge drop, `InvalidationBusReady` green.
Worst: on Redis recovery go-redis reconnects silently and the missed
events are **never re-applied** — `resubscribeAndReseed` never runs, so
`KindTokenRevoked` stays missing from peer deny-sets for the token's
remaining lifetime, and `KindSigningKeyRotation` peers converge only via
the per-replica grace fallback. This is precisely the "stale invalidation
window invisible to operators" that spec improvement 3 exists to close.

**Recommendation (required before implementation):** the bus must own the
receive loop instead of ranging `Channel()`:

```go
go func() {
    defer close(out)
    defer func() { _ = ps.Close() }()   // releases the dedicated pubSubPool conn
    for {
        msg, err := ps.ReceiveTimeout(subCtx, readDeadline) // or ReceiveMessage + ctx deadline
        if err != nil {
            return // any error = closure; runInvalidationBus distinguishes ctx vs loss
        }
        evt, ok := decodeEnvelope(msg.Payload)  // garbage → drop with counter, continue
        if !ok { continue }
        select { case out <- evt: default: /* slow consumer drop */ }
    }
}()
```

- Any non-nil error closes `out` exactly once (single `defer`), preserving
  the "lost subscription looks exactly like a closed channel" invariant —
  empirically verified above.
- A read deadline (e.g. 30-60 s) bounds the half-open window; the design's
  "internal heartbeat" claim cannot be relied on because the health check
  is part of `Channel()`, which the bus no longer uses. False-positive
  timeouts are safe: they trigger a resubscribe + idempotent re-seed.
- `ps.Close()` on exit is mandatory: PubSub connections come from the
  client's dedicated `pubSubPool` (`redis.go:1531-1552`) and go-redis's
  retry goroutine outlives the bus's goroutine otherwise — every
  degraded→recover cycle (or resubscribe attempt during an outage) would
  leak one pooled connection + goroutine for the life of the process.
- Update the failure taxonomy and the spec's mechanism claim in the same
  change.

**Executable validation:** unit test that closes the miniredis server
(not the client) with a live subscription and asserts the out-channel
closes and `Publish` returns an error; then restart miniredis on the same
address (`StartAddr`; proven workable) and assert a fresh `Subscribe`
receives events.

### F2 — High: `NewBus(rdb goredis.Cmdable, ...)` does not compile — `Subscribe` is not on `Cmdable`

**Path/evidence (Verified):** `commands.go:173-252` — `Cmdable` embeds
`PubSubCmdable` (Publish only, `pubsub_commands.go:9-11`); `Subscribe` is
on `UniversalClient` (`universal.go:349-361`) and on the concrete
`*Client`/`*ClusterClient`. `b.redis` is `goredis.UniversalClient`
(`cmd/sso-server/build_app.go:60`), and `NewUniversalClient` returns
`goredis.UniversalClient` (`universal.go:114`).

**Impact:** the design's API surface as written cannot call
`rdb.Subscribe(...)`; the "same `Cmdable` the stores take" rationale
conflates keyspace-only stores with the bus.

**Recommendation:** `NewBus(rdb goredis.UniversalClient, opts ...BusOption) *Bus`
(or a minimal local interface `interface { Publish(...); Subscribe(...) }`
if fakes are wanted). The wiring claim is unaffected — the call site
already passes a `UniversalClient`.

**Executable validation:** `go build ./...` with the declared signature.

### F3 — Medium: self-skip instance-ID uniqueness is per-host, not per-process; the fallback ID is identical across all replicas

**Path/evidence (Verified):** `ResolveServiceID` (`build_ratelimit_cluster.go:278-295`)
= explicit YAML, else `issuer + "-" + shortHostname`; on `os.Hostname()`
failure → the SAME `issuer + "-1"` for every replica. The design's stock
wiring would pass this ID whenever non-empty, so self-skip is effectively
**on by default** in the stock binary. Two replicas on one host sharing a
hostname (host-network containers, systemd units, bare-metal multi-process)
or the hostname-failure fallback collide → mutual silent suppression —
the design's own risk #1 — with no degraded signal (channel stays healthy).

**Impact:** silent coordination loss; `/readyz` green; TTL-only
convergence; `KindTokenRevoked` propagation silently disabled between the
colliding replicas.

**Recommendation:** (a) log the effective bus instance ID at construction
(startup line) so collisions are diagnosable; (b) derive uniqueness
per-process (append pid or a random suffix) or keep self-skip OFF in the
stock wiring until uniqueness per process is guaranteed; (c) document the
uniqueness requirement at the config key. The design lists the log line as
possible future work — it should be part of this change.

**Executable validation:** boot two replicas configured identically (same
issuer, no explicit replica id) on one host and assert distinct logged
instance IDs — fails today by construction on the hostname-failure path.

### F4 — Medium: the forced-loss acceptance tests as specified cannot validate the design

**Path/evidence (Verified, empirical):** the design's forced-loss test
("close the underlying go-redis client, assert the out-channel closes")
passes vacuously — client close is the ONLY case `Channel()` closes
(F1). The alternative in the test plan, "or miniredis", fails to observe
closure (empirically proven), and the recovery half (degraded → reconnect
→ healthy → event applied) has no specified mechanism to bring a server
back on the same address.

**Recommendation:** with F1's fix, use miniredis `mr.Close()` for loss and
a fresh `miniredis.NewMiniRedis().StartAddr(sameAddr)` for recovery
(empirically proven workable; the mqtt peer already has the analogous
precedent: `infrastructure/mqtt/subscribe_selfheal_test.go:20,52`).
Keep the client-close variant as a second case.

### F5 — Low: the silent-stall row needs a bus-owned read deadline, not go-redis's heartbeat

**Path/evidence (Verified):** with the F1 fix, `Channel()`'s health check
(3 s ping) is gone; `ReceiveTimeout(ctx, 0)` sets no read deadline
(`internal/pool/conn.go:874-892`), so a half-open connection blocks until
the OS TCP timeout. The design's taxonomy row claiming go-redis detects
the stall and closes the channel is false (F1).

**Impact:** a half-open pub/sub connection (e.g. proxy idle-drop without
RST) delays degradation detection by minutes instead of seconds.

**Recommendation:** pass a generous read deadline to `ReceiveTimeout` (or
a ctx deadline) and treat timeout as loss → close out → resubscribe.
Bounded, idempotent cost.

### F6 — Info: backend cutover is a transport switch, not a rolling upgrade

**Path/evidence (Verified):** `BuildInvalidationBus` builds exactly one
backend (`build_ratelimit_cluster.go:183-215`); etcd and redis buses share
no channel. `cluster.bus.backend: redis` on an OLD binary hits the default
arm → boot error `unknown cluster.bus.backend "redis"` (fail closed,
verified).

**Impact:** a fleet mid-rollout (some replicas etcd, some redis) has no
cross-invalidation between the groups until the rollout completes;
`redis_channel` renames have the same property. Bounded by the TTL
fallback, but invisible to the degraded loop.

**Recommendation:** document the cutover (flip all replicas within one
window; prefer a maintenance window); the mixed-version-fleet section of
the design should explicitly include the mixed-backend case, not just the
`instance`-field case.

## 3. Query / index / transaction analysis for the demonstrated hot and atomic paths

The bus introduces **no keyspace, no indexes, no TTL, no transactions,
and no retention** — this is its strongest property and is Verified:
`Publish` issues `PUBLISH` only; `Subscribe` holds a dedicated connection
from the client's `pubSubPool` (`redis.go:1531-1552`), so a stuck pub/sub
read cannot head-of-line-block keyspace commands. The analysis that
matters:

- **Channel routing (Verified correct):** pub/sub channels are outside the
  keyspace and are not slot-routed on Redis Cluster; `PUBLISH` on any node
  is forwarded cluster-wide, so one channel + one subscriber per replica is
  correct. `hashTag` correctly does NOT apply (`infrastructure/redis/cluster.go`
  is keyspace-only). The design's use of plain `PUBLISH` (not sharded
  `SPUBLISH`) is the right choice.
- **Envelope versioning (Verified):** `cluster.Event` is
  `{"kind","key","payload,omitempty"}` (`platform/cluster/bus.go`); the
  additive `instance` field is ignored by older peers (Go `encoding/json`
  skips unknown fields; the garbage-drop pattern mirrors
  `infrastructure/mqtt/decode.go:13-20`). No schema registry needed; kinds
  are an open set dispatched by the consumer.
- **Atomicity lives in the recovery loop, not the transport (Verified):**
  `runInvalidationBus` (`interfaces/sso/server_invalidation.go:140-186`)
  treats channel closure under a live ctx as the single degraded signal;
  `resubscribeAndReseed` (`server_extensions.go:396-441`) subscribes FIRST,
  then flushes caches + re-seeds revocation deny-sets
  (`reseedInvalidationState` = `flushInvalidationCaches` +
  `reseedRevocationDenySets` → `SeedRevocations`), and only then clears
  degraded. The bus must not auto-resubscribe internally (would race the
  subscribe-before-reseed ordering) and must not replay (the re-seed IS the
  repair). Both design decisions are Verified against the loop's one-owner
  property. Note: `KindSigningKeyRotation` is NOT covered by the re-seed —
  recovery relies on the per-replica grace-window fallback
  (`platform/cluster/bus.go`'s kind doc) — the design states this
  correctly.
- **Slow-consumer semantics (Verified):** buffer 16 with drop-not-block
  matches the peers exactly (`platform/cluster/memory/bus.go:89`,
  `platform/cluster/etcd/etcd.go:147`, `infrastructure/mqtt/subscribe.go:16,34`).
- **Publish error surface (Verified):** `Publish` returns transport errors
  as-is; `redis.Nil` never occurs on `PUBLISH`; callers log-and-continue
  because the local mutation already succeeded — matches the SPI contract.

## 4. Safe migration sequence

No schema, data, or backfill exists for a pub/sub channel; the migration
surface is config + binary, both additive:

| Step | Action | Compatibility |
|---|---|---|
| 0 | Baseline: record `redis-cli --scan` key inventory and `PUBSUB NUMSUB` on the bus channel (should be 0 subscribers) | n/a |
| 1 | Ship the new binary with `cluster.bus.backend` unchanged (`""`/`memory`/`etcd`) | Old config + new binary: boot works (new field defaulted) |
| 2 | Cut over ALL replicas to `cluster.bus.backend: redis` (+ optional `redis_channel`) in one window (F6) | New config + OLD binary: **boot error** (`unknown cluster.bus.backend "redis"`) — the config flip and binary rollout must be atomic; the additive `redis_channel` key alone is tolerated by old binaries (lenient fallback, `config/source.go:264-277`: strict decode warns and re-decodes ignoring unknown keys) |
| 3 | Validate (below) | n/a |
| 4 | Rollback: revert binary + config together (old binary refuses `backend: redis`; new binary with `backend: etcd` boots) | Symmetric with step 2 |

**Validation queries (post-cutover):**

- `redis-cli PUBSUB NUMSUB snaplink:cluster:bus` → equals replica count.
- Trigger an admin mutation (tenant suspension / client change) on replica
  A; observe replica B's cache flush (next read re-fetches) and
  `sso_invalidation_bus_up == 1` on both.
- `redis-cli --scan` after 24 h → no bus keys accumulated (stateless
  transport; the only Redis-side artifact is the channel registration).
- Forced-loss drill (with F1 fix): kill the Redis endpoint, assert
  `invalidation_bus_degraded` audit fires once, restore, assert
  `invalidation_bus_recovered` with `re_seeded=true` and deny-set
  convergence for a token revoked during the outage.
- Mixed-version fleet: old peer + new peer on the same channel — old peer
  must ignore `instance` (byte-level wire compat verified by envelope
  shape).

**Data-integrity checks:** none applicable to keyspace (no keys); the
integrity invariant is behavioral: a dropped event must degrade a replica
to its TTL fallback, never to a wrong answer — covered by the re-seed
ordering tests and the existing `invalidation_bus_reseed_test.go` /
`invalidation_bus_selfheal_test.go` suites extended to the redis backend.

## 5. Unknown volume, retention, and recovery assumptions

- **Volume (Unknown, no measurements exist):** event rate is
  admin-mutation-triggered, not per-request (`platform/cluster/bus.go`
  package doc), but no metric tracks publish rate, message-size
  distribution (`KindTokenRevoked` carries a full access token in
  `payload`; a few KB per message — not a Redis constraint, but material
  for the 16-slot buffer under mass-revocation bursts), fan-out count
  (replicas per issuer), or buffer-drop rate. Measurements required:
  events/sec under suspension/revocation/rotation storms; drop rate at
  buffer 16; publish p99 latency.
- **Retention (Verified N/A):** no persistence, no replay, no backlog.
  The design's "no sequence numbers" stance is correct — sequence numbers
  would turn a best-effort transport into a correctness dependency and
  break mixed-version peers.
- **Recovery (Partial):** re-seed covers cache flush + revocation
  deny-sets; `KindSigningKeyRotation` coordination loss is bounded by the
  per-replica grace-window fallback (deadline-based, only ever widens the
  verify window); RTO is a function of the existing backoff schedule
  (`invalidationBusBackoff`) plus Redis recovery — no SLO documented.
- **Operator unknowns (Unknown):** real Redis topology
  (single/sentinel/cluster), proxies in the path (pub/sub-terminating
  proxies are the one blind spot neither the `redis` readycheck nor the
  degraded loop can see — accepted in the design, correctly scoped out),
  and per-process instance-ID uniqueness in the deployment's networking
  model (F3).

## Appendix: checks that ran for this review

- `go build`-level source inspection of go-redis v9.20.0 `pubsub.go`,
  `commands.go`, `universal.go`, `redis.go`, `internal/pool/conn.go` from
  the module cache (root `go.mod` pins v9.20.0).
- Empirical scratch programs (outside the repo) with the exact pinned
  versions: (1) `Channel()` stays open 8 s+ after server death, closes on
  client `Close`; (2) bus-owned `ReceiveMessage` loop sees `EOF` on server
  death and recovers across same-address restart via
  `miniredis.StartAddr`.
- Repo source verification of every cited line: `platform/cluster/bus.go`,
  `infrastructure/mqtt/{bus,subscribe,publish,decode}.go`,
  `platform/cluster/{memory/bus.go,etcd/etcd.go}`,
  `cmd/sso-server/{build_bootstrap.go,build_stores.go,build_app.go,build_app_cluster.go}`,
  `cmd/sso-server/serverbuildplatform/build_ratelimit_cluster.go`,
  `config/config_keys.go`, `config/source.go`,
  `interfaces/sso/{server_invalidation.go,server_extensions.go}`,
  `infrastructure/redis/{cluster.go,universal.go,doc.go,redis_test.go}`,
  `docs/config-reference.md:95-131`.
- No full test suite ran for this review (read-only architectural review);
  `go test` gates remain the implementer's mandatory step per AGENTS.md §2.
