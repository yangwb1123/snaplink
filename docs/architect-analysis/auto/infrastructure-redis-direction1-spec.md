# Requirements Specification: Redis as the Cluster Coordination Layer

- Module: `infrastructure/redis` (root-module package; go-redis lives in the root `go.mod`)
- Expansion direction (from `docs/auto/infrastructure-redis-analysis.md`): 让 Redis 从"热路径存储层"升级为集群协调层 — 增加 `cluster.Bus` 的 Redis pub/sub 实现
- Scope: exactly 3 improvements. All other analysis findings (store observability, session-enumeration N+1, `doc.go` nested-module drift) are out of scope for this direction and must not be folded in.

The `cluster.Bus` contract (`platform/cluster/bus.go`) is deliberately best-effort: `Publish` is fire-and-forget from the caller's perspective, `Subscribe` returns a stream that closes on ctx cancellation or Bus close, and correctness never depends on delivery or ordering because a dropped event only degrades a replica to its existing cache-TTL fallback. This makes Redis pub/sub — a fire-and-forget, no-persistence transport — a faithful implementation surface, not a compromise.

## 1. New `redisbus` package: a `cluster.Bus` implementation over Redis pub/sub

**Name:** Add `infrastructure/redis/bus.go` implementing `cluster.Bus` (package `redis`, same module as the existing stores — no new nested module, no new go.mod).

**Problem:** A deployment that chose Redis as its hot-path store (`redis.backend` set for session/refresh/auth-code/JTI/rate-limit etc., per `cmd/sso-server/serverbuildplatform/build_ratelimit_cluster.go` `redisRateLimitPolicy`) must still stand up a second coordination system — etcd — to satisfy AGENTS.md §4 cross-replica invalidation (token revocation, signing-key rotation, client/authz changes, tenant suspension). The same fleet that stores in Redis coordinates over a different technology with a second HA surface, second monitoring, second failover drill. The SPI proves implementable by a message broker: `infrastructure/mqtt/bus.go` implements `cluster.Bus` (`var _ cluster.Bus = (*Bus)(nil)`) — but it is not wired into sso-server and requires an independent MQTT broker. Redis is already in the topology: `cmd/sso-server/build_bootstrap.go` (redis readycheck, ~line 222) treats Redis availability as an accepted operational dependency.

**Evidence:**
- `platform/cluster/bus.go` — `Bus` interface (`Publish(ctx, Event) error`, `Subscribe(ctx) (<-chan Event, error)`, `Close() error`); Event is JSON-serializable (`json:"kind"` / `json:"key"` / `json:"payload,omitempty"`), so the wire format is a single JSON document per event.
- `infrastructure/mqtt/bus.go` + `infrastructure/mqtt/publish.go:20` / `subscribe.go:24` — reference implementation of the same SPI on a pub/sub transport; marshals `cluster.Event` with `json.Marshal`, returns `ErrClosed` after `Close`, closes the out channel when the subscription dies.
- `cmd/sso-server/serverbuildplatform/build_ratelimit_cluster.go` `BuildInvalidationBus` — the switch handles only `""` / `memory` / `etcd`; no redis branch exists.
- `infrastructure/redis/universal.go` `NewUniversalClient` — single/shared client construction already supports single/sentinel/cluster topologies; the bus can reuse the same `goredis.Cmdable` the stores use.

**Proposed behavior:**
- `NewBus(rdb goredis.Cmdable, opts ...BusOption) *Bus` (or `New` returning `(*Bus, error)` mirroring `mqttbus.New`) where options set a channel namespace (default `snaplink:cluster:bus` — key-tagged per `infrastructure/redis/cluster.go` hash-tag conventions so it stays single-slot on Redis Cluster) and an optional `instanceID` used to skip a publisher's own events (a node must not invalidate its own caches for its own mutations; local invalidation already happens in-process).
- `Publish(ctx, evt)` = `json.Marshal(evt)` then `rdb.Publish(ctx, channel, body)`. Transport errors are returned and logged by the caller (fire-and-forget contract). `nil`/`ErrClosed` handling matches `mqttbus`: `ErrClosed` after `Close`.
- `Subscribe(ctx)` = `rdb.Subscribe(ctx, channel)`; a goroutine decodes each message into `cluster.Event` and forwards to a buffered out-channel; the channel closes on ctx cancellation, Bus close, or pub/sub connection loss (go-redis closes the `PubSub` channel on reconnect failure, which is exactly the signal `runInvalidationBus` needs — see Improvement 3). Unmarshal failures are dropped with a log counter, never propagated as events (a garbage message must not crash the consumer loop; this mirrors `applyInvalidation`'s default arm behavior).
- `Close()` is idempotent, releases the subscriber, and makes `Publish`/`Subscribe` return `ErrClosed`.
- Concurrency-safe for concurrent `Publish` from multiple goroutines (the interface requires it); `Subscribe` may be called once per Bus.

**Acceptance check:**
- `go build ./... && go vet ./...` and `go test -run 'TestMaintainability_|TestArchitecture_' .` pass after the edit (mandatory gate).
- New unit tests in `infrastructure/redis/bus_test.go` against the existing in-process miniredis fake (same pattern as `redis_test.go`): (a) publish → subscribe round-trip delivers a decoded `cluster.Event` with identical Kind/Key/Payload; (b) two separate `NewBus` instances (simulated replicas) over one miniredis deliver to each other; (c) `Close` then `Publish` returns `ErrClosed`; (d) ctx cancellation closes the subscription channel exactly once; (e) a subscriber does not receive its own published event when instance-self-skip is enabled.
- `go test ./... -race` passes for the new tests.

## 2. Wire the `redis` backend into `BuildInvalidationBus` and `ClusterBusConfig`

**Name:** Extend `config.ClusterBusConfig` with a `redis` backend and add the corresponding branch in `BuildInvalidationBus`; update `docs/config-reference.md`.

**Problem:** Even with a correct `redisbus`, operators cannot select it: `BuildInvalidationBus` (`cmd/sso-server/serverbuildplatform/build_ratelimit_cluster.go`) returns an error for any backend outside `memory`/`etcd`, and `config/config_keys.go:151` `ClusterBusConfig` documents `Backend string // "" | "memory" | "etcd"`. `docs/config-reference.md:127` lists the cross-replica bus as `off · memory · etcd`. The analysis's stated goal — collapse the operational model from "Redis + etcd/MQTT" to "one Redis" — is unreachable until the server build path accepts the redis backend and derives it from the already-shared `redis.addrs` connection instead of a second dial. This is also the point where AGENTS.md §5 contract-sync rules apply: a new config knob must be documented in the same change.

**Evidence:**
- `cmd/sso-server/serverbuildplatform/build_ratelimit_cluster.go` — `BuildInvalidationBus(cfg *config.ClusterBusConfig, logger spi.Logger)` switch: `""` → nil (safe single-node default), `memory`, `etcd`, `default` → `fmt.Errorf("unknown cluster.bus.backend %q", cfg.Backend)`.
- `config/config_keys.go:149-162` — `ClusterBusConfig` with only `Backend` + `Etcd*` fields; `Backend` comment enumerates `"" | "memory" | "etcd"`.
- `cmd/sso-server/build_bootstrap.go` — the server already builds one Redis client from `config.RedisConfig` and fans it out to all redis-backed stores; the bus must reuse this same client (one connection pool, one HA story) rather than open a second one.
- `docs/config-reference.md:127` — the documented backend enumeration that must gain `redis`.
- Precedent: `BuildRateLimitPolicy` in the same file already has a `case "redis"` branch that consumes the shared `rdb goredis.Cmdable` parameter — the wiring pattern to copy.

**Proposed behavior:**
- `ClusterBusConfig.Backend` accepts `"redis"`; add optional `RedisChannel string` (`yaml:"redis_channel"`, default `snaplink:cluster:bus` — empty means default) so multiple issuers sharing one logical Redis can namespace their buses. No new credentials/endpoints fields: the bus reuses the global `redis.addrs`/`redis.password` block via the already-built client, keeping `RedisConfig` the single HA-tuning point (per its doc comment).
- `BuildInvalidationBus` gains a `case "redis"` that takes the shared `goredis.Cmdable` (signature change or a sibling `BuildInvalidationBusRedis(cfg, rdb)` mirroring `BuildRateLimitPolicy(cfg, rdb)` — follow the existing parameter-passing precedent in the file) and returns `redisbus.New(rdb, ...)`. Log `invalidation bus backend=redis` like the other branches.
- Validation: `cluster.bus.backend=redis` with no redis block configured fails with the same error shape as `redisRateLimitPolicy` (`"cluster.bus.backend=redis but no redis block configured (set redis.addrs)"`).
- Like `etcd`, the redis bus is a fail-open transport (dropped events degrade to TTL) — intentionally gets no `/readyz` check of its own, consistent with the existing `BuildInvalidationBus` comment; the existing redis readycheck already covers transport availability.
- Update `docs/config-reference.md` bus row to `off · memory · etcd · redis` and document `cluster.bus.redis_channel`.

**Acceptance check:**
- `go build ./... && go vet ./...` and the maintainability/architecture gate tests pass.
- Config validation unit test: `backend=redis` without a redis block → descriptive error; with a redis block → a non-nil `cluster.Bus`.
- A cross-server test in `test/` (`package ssotest`, per AGENTS.md §5): build an `sso.Server` with redis-backed stores + the redis invalidation bus over miniredis, publish a `KindTenantSuspension` (or `KindSigningKeyRotation`) event from one simulated replica, and assert the second server's `InvalidationBusReady()` and cache behavior converge without the etcd backend — proving the wire path `BuildInvalidationBus → redisbus → runInvalidationBus` end to end.
- `docs/config-reference.md` shows the new backend; `make ci` passes.

## 3. Loss-detection and resubscribe/re-seed semantics: close the subscription channel on pub/sub disconnect

**Name:** Make `redisbus.Subscribe` surface transport loss as channel closure so the existing self-healing loop (`runInvalidationBus` resubscribe + re-seed) applies unchanged.

**Problem:** The analysis highlights that AGENTS.md §3's recovery semantics — "re-subscribes, flushes caches, and re-seeds revocation deny-sets before clearing degraded readiness" — map naturally onto pub/sub's "dropped events are repaired by re-seeding from source". But this only holds if the consumer machinery can detect the loss. `interfaces/sso/server_invalidation.go` `runInvalidationBus` (`~line 140`) treats a closed `<-chan cluster.Event` as the single signal to enter degraded state, back off, and call `resubscribeAndReseed`; readiness is gated on `InvalidationBusReady()` (`~line 259`), and recovery emits `invalidation_bus_degraded` / recovered audit events plus the `sso_invalidation_bus_up` gauge (`setInvalidationBusDegraded`/`setInvalidationBusHealthy`). A Redis pub/sub subscription has no built-in delivery guarantee: if the connection drops silently and the implementation kept a live-looking channel, the replica would believe it is coordinated while actually blind — the exact "stale invalidation window" the whole bus exists to close, but now invisible to operators. `mqttbus` already encodes this contract (its `Subscribe` doc: the stream "closes when ctx is cancelled or the Bus is closed"; `subscribe.go` closes `out` when the underlying session is lost); `redisbus` must match it, and the re-seed side must be exercised for the redis backend.

**Evidence:**
- `interfaces/sso/server_invalidation.go:140` `runInvalidationBus` — bare `for evt := range events`; `setInvalidationBusDegraded` (line ~186, audit `invalidation_bus_degraded` + `InvalidationBusUp` gauge 0) on channel close; `resubscribeAndReseed` (line ~175) — resubscribes, then flushes caches and re-seeds revocation deny-sets BEFORE `setInvalidationBusHealthy` (line ~220); `InvalidationBusReady` (line ~259) gates `/readyz`.
- `platform/cluster/bus.go` `Bus.Subscribe` contract — "returns a receive-only stream that closes when ctx is cancelled or the Bus is closed", and the package doc: "a dropped Event degrades a replica to its existing TTL fallback ... never to a wrong answer".
- `infrastructure/mqtt/subscribe.go:41-49` — the precedent: on `client.Done()` (session lost) the goroutine closes `out`; the generic consumer loop in `runInvalidationBus` is backend-agnostic and needs no change once closure is guaranteed.
- AGENTS.md §3: "invalidation-bus recovery re-subscribes, flushes caches, and re-seeds revocation deny-sets before clearing degraded readiness" — the semantic contract this improvement honors.

**Proposed behavior:**
- `redisbus.Subscribe` must guarantee: the returned channel closes on (a) ctx cancellation, (b) `Close()`, and (c) pub/sub connection loss or subscribe failure — including go-redis's reconnect-with-backoff exhaustion (`PubSub` receives `redis.ErrClosed` / channel closure). The implementation must not leave a silent, dead subscription open; a lost subscription must look exactly like the mqtt backend's session loss to `runInvalidationBus`.
- The self-skip publisher filter (Improvement 1) must never swallow events in a way that suppresses a peer's needed invalidation — filtering is strictly by own-instance ID.
- No event persistence, no replay buffer: dropped events are repaired by `resubscribeAndReseed`'s re-seed (flush caches + re-seed revocation deny-sets), which is the fail-closed-by-construction recovery the analysis calls out. `redisbus` must not add delivery guarantees that the SPI explicitly does not require.
- `Publish` must return a transport error (not silently succeed) when the underlying Redis client is unreachable, so the caller's existing error-logging path fires and the local-mutation-already-succeeded invariant is preserved (AGENTS.md: "fire-and-forget from the caller's perspective: it returns an error only for transport-level failures").

**Acceptance check:**
- Unit test simulating connection loss (close the underlying miniredis or the `*goredis.PubSub` handle) asserts the subscription channel closes; a subsequent `Publish` returns a non-nil error.
- Integration test in `test/` (or a `server_invalidation`-driven test with the redis bus): after a forced disconnect, `InvalidationBusReady()` reports degraded (`invalidation_bus_degraded` audit emitted once per transition, per `setInvalidationBusDegraded`), then after reconnect the replica re-seeds and reports healthy (`sso_invalidation_bus_up == 1`), and a `KindTokenRevoked` event published after recovery is applied — proving the degraded→resubscribe→reseed→healthy loop end to end on the redis backend.
- `go test ./... -race` passes, including `-count=10+` for the new bus tests (AGENTS.md §5 race-fix discipline); `make ci` passes.
