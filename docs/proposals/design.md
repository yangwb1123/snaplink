Design doc written to `docs/auto/infrastructure-redis-direction1-design.md`. Every decision is grounded in the verified evidence (line numbers re-checked against source during research).

## What the doc covers

**## API surface** — `redisbus` as `bus.go` in the existing root-module `redis` package (verified: no `go.mod` there; go-redis/miniredis are in the root module — the `doc.go` nested-module claim is the pre-existing drift the spec excluded). `NewBus(rdb goredis.Cmdable, opts ...BusOption) *Bus` with `WithChannel` / `WithInstanceID`, infallible constructor (nil-rdb errors at first use, but the build layer catches it earlier), `ErrClosed` after `Close`, mutex-guarded concurrency, one `Subscribe` per Bus, bus never closes the shared client.

**## Wire and storage model** — single JSON envelope (additive optional `instance` field, version-safe both directions) on one non-slot-routed pub/sub channel (channels are outside the keyspace, so `hashTag` deliberately does *not* apply); 16-slot buffer with drop-not-block slow-consumer semantics matching memory/mqtt/etcd peers; explicitly no persistence, no replay, no sequence numbers — that's the SPI's contract, and the re-seed path is the repair.

**## Wiring** — `ClusterBusConfig` gains `redis` backend + `RedisChannel` (empty ⇒ `snaplink:cluster:bus`, no new endpoint/credential fields — `RedisConfig` stays the single HA-tuning point); `BuildInvalidationBus` gains a third `rdb goredis.Cmdable` parameter (verified `wireRedis` runs before `wireCluster`, so `b.redis` is ready), with the descriptive nil-block boot error mirroring `redisRateLimitPolicy`; no new readycheck (the existing `redis` check covers transport; `InvalidationBusReady` covers bus-internal degradation only); doc-sync of `docs/config-reference.md:127` in the same change.

**## Failure modes** — a loss-taxonomy table mapping every failure to its surface (subscribe error / channel closure / ctx / garbage drop / slow consumer / publish error), with the central invariant: *a lost subscription must look exactly like a closed channel, never like a healthy one* — hence no internal reconnect (it would race `resubscribeAndReseed`'s subscribe-before-reseed ordering).

**## What could break the design** — ten risks, ranked: the self-skip ID-collision silent coordination loss (the one failure the degraded loop can't see — mitigated by `ResolveServiceID`-derived uniqueness), go-redis reconnect masking, miniredis fidelity gap, cluster fan-out assumptions, duplicate/ordering, slow-consumer liveness, channel collision on shared Redis, mixed-version fleets, signature-change ripple, and the ping-green-but-pub/sub-dead proxy blind spot (accepted, out of scope, documented).

**## Test plan** — mapped 1:1 to the spec's acceptance checks, including the forced-loss degraded→recover end-to-end and `-count=10+` race discipline.
