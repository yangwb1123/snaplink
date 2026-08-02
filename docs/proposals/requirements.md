Spec written to `docs/auto/infrastructure-redis-direction1-spec.md`. All cited evidence verified against source (line numbers confirmed: `build_bootstrap.go:222` redis readycheck, `config_keys.go:151` `ClusterBusConfig`, `server_invalidation.go:140/175/259`, `BuildInvalidationBus` switch, `mqtt/subscribe.go:41`).

**Summary — 3 evidence-backed improvements for direction 1 (Redis as cluster coordination layer):**

1. **`redisbus` package implementing `cluster.Bus` over pub/sub** — `platform/cluster/bus.go` SPI is JSON-shaped and best-effort (no delivery guarantees needed); `infrastructure/mqtt/bus.go` proves the SPI is implementable on a pub/sub transport; `BuildInvalidationBus` currently has no redis branch. New `bus.go` in the existing root-module redis package: JSON-marshaled `Event` on a namespaced, hash-tag-safe channel, own-event self-skip, `ErrClosed` semantics matching mqtt, miniredis-based tests.

2. **Wire `redis` backend into `BuildInvalidationBus` + `ClusterBusConfig`** — the config comment (`"" | "memory" | "etcd"`) and `docs/config-reference.md:127` enumerate only memory/etcd; the bus must reuse the single shared client built in `build_bootstrap.go` (one pool, one HA story), mirroring the existing `case "redis"` in `BuildRateLimitPolicy`. Includes config validation, doc sync, and a `test/` end-to-end cross-server test.

3. **Loss-detection semantics: close the subscribe channel on pub/sub disconnect** — `runInvalidationBus` treats channel closure as the sole degraded signal driving resubscribe + re-seed (`resubscribeAndReseed`, `invalidation_bus_degraded` audit, `InvalidationBusReady`); a silently-dead subscription would make the replica *believe* it is coordinated while blind. Matches `mqtt/subscribe.go`'s session-loss closure precedent and AGENTS.md §3 fail-closed recovery.

Not folded in (out of scope for this direction): store observability metrics, session-enumeration N+1, and the `doc.go` nested-module drift.
