The design doc is complete and fully verified. Summary of the work:

## Deliverable

**`docs/auto/infrastructure-redis-direction1-design.md`** (663 lines) — rewritten with every decision grounded in evidence re-checked against source, plus the four required distributed-systems outputs.

## Verification performed (all line numbers re-checked during research)

- **SPI**: `platform/cluster/bus.go` (`Publish`/`Subscribe`/`Close`, 11 event kinds, best-effort contract); mqtt reference impl (`publish.go:20/33`, `subscribe.go:24/41-49` `defer close(out)`)
- **Root module**: confirmed no `go.mod` in `infrastructure/redis/`; go-redis v9.20.0 + miniredis v2.38.0 in root `go.mod` (6/17)
- **Wiring**: `BuildInvalidationBus` switch at `build_ratelimit_cluster.go:183-215`; `redisRateLimitPolicy` nil-rdb error at :63-66; call site `build_app_cluster.go:137`; `wireRedis` at `build_bootstrap.go:203` (readycheck :222) called from `buildApp` (`build_stores.go:44`) before `wireCluster` (`build_app.go:240`)
- **Recovery loop**: `server_invalidation.go:114-188` (degraded :163, backoff 1s→30s jittered, healthy :184), `InvalidationBusReady` :259, `resubscribeAndReseed` `server_extensions.go:407` (subscribe→reseed→healthy), `reseedRevocationDenySets` :438
- **Peers**: 16-slot buffers in memory (`bus.go:89`) and etcd (`etcd.go:147`); `hashTag` (`cluster.go:33`) confirmed keyspace-only — channels are not slot-routed
- **Config/docs**: `ClusterBusConfig` `config_keys.go:151`; `docs/config-reference.md:127`; existing tests affected by the signature change (`cluster_bus_test.go`, `build_app_coverage_test.go`)

## Corrections to the prior draft

1. `wireRedis` runs in `buildApp` (`build_stores.go:44`), not a function named `wireStores`
2. `ResolveServiceID` **is** in scope in `build_app_cluster.go` — already used at :226-232 for `WithSigningKeyReplicaID`; the bus wiring reuses that derivation
3. `BuildInvalidationBus` body at :183-215, not :175-215

## Required outputs added

- **State map**: 11 coordinated states (owner/store/durability/consistency/replication/failover) + authoritative stores the bus never touches (JTI `SET NX EX`, refresh-family Lua, auth-code single-use consume) + readiness trace
- **Findings**: 11 severity-rated findings (F-1 High: silent self-skip ID collision — the one failure the degraded loop can't see; F-2/F-5 accepted blind spots; F-11 boot-time nil-rdb) with evidence/trigger/impact/recovery/corrective pattern
- **Scenario table**: 13 rows — partition (subscribed + at boot), replica crash, Redis failover, retry storm, duplicate delivery, clock rollback (deadline clamping, widen-only), stale cache, dependency outage, recovery sequencing, slow consumer, ID collision
- **Guarantees G-1…G-9**, unsupported topologies, validation tests (incl. `-count=10+` race discipline), residual risks

No Go files were touched, so the mandatory gates don't apply to this doc-only design-stage change.
