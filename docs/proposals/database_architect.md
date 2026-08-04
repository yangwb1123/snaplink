Review complete: `docs/auto/infrastructure-redis-direction1-database-review.md`. Summary of what was verified and found:

## Verification results (all design claims re-checked against source)

**Verified correct:** redis is a root-module package (no `go.mod`; go-redis v9.20.0/miniredis v2.38.0 in root module); `cluster.Bus` SPI shape; mqtt/etcd/memory peers all use buffer 16 with drop-not-block; `wireRedis` (build_bootstrap.go:203) builds one shared `goredis.UniversalClient`, registers the redis readycheck, and runs before `wireCluster` (build_stores.go:44 → build_app.go:240); `BuildInvalidationBus` covers only `""/memory/etcd` with the `redisRateLimitPolicy` nil-rdb pattern to copy; `runInvalidationBus`/`resubscribeAndReseed` subscribe-before-reseed ordering; `ResolveServiceID`; config-reference.md:127; lenient config fallback for unknown keys (config/source.go:264-277); hashTag is keyspace-only and pub/sub is correctly non-slot-routed.

## Findings (severity-sorted)

1. **Critical** — the design's central invariant ("a lost subscription must look exactly like a closed channel") is **not delivered by `PubSub.Channel()` on the pinned go-redis v9.20.0**. Read the vendored source (`initMsgChan` closes only on `pool.ErrClosed`, infinite retry otherwise; health-check ping never closes the channel; no read deadline with timeout 0) and **proved it empirically**: after killing the server with the client open, the channel stayed open 8s+; it closed only on explicit client `Close`. A replica would go silently blind during any Redis outage — no degraded audit, `/readyz` green, and no re-seed on recovery (missed `KindTokenRevoked` events never re-applied). The design's forced-loss tests as specified pass vacuously or fail. Fix (empirically proven): the bus owns a `ReceiveMessage`/`ReceiveTimeout` loop, closes `out` on any error, `defer ps.Close()` (the dedicated `pubSubPool` connection otherwise leaks per resubscribe cycle).
2. **High** — `NewBus(rdb goredis.Cmdable, ...)` can't compile: `Subscribe` is not on `Cmdable`; it's on `UniversalClient`. Trivial parameter-type fix; the wiring claim itself holds.
3. **Medium** — self-skip ID uniqueness is per-host, not per-process (`ResolveServiceID` fallback is identical `issuer+"-1"` across all replicas); stock wiring would enable self-skip by default, so a hostname collision is a silent coordination loss. Log the effective ID at construction.
4. **Medium** — forced-loss acceptance tests need miniredis `StartAddr` same-address restart (proven workable) to exercise the realistic loss path.
5. **Low** — silent-stall detection needs a bus-owned read deadline; go-redis's heartbeat can't be relied on once `Channel()` is abandoned.
6. **Info** — etcd→redis is a transport cutover, not a rolling upgrade (old binary refuses `backend: redis` at boot — fail closed, correct).

**Migration:** purely additive (one config field + internal signature change); the only atomic requirement is flipping binary + `backend: redis` together in one window; no data migration, backfill, or retention exists — the bus creates zero keyspace keys.

**Unknowns:** event rate/size distribution (full access tokens in payloads), buffer-drop rate under revocation storms, per-process ID uniqueness in the deployment's networking model — none measurable from the repo; the necessary measurements are listed.
