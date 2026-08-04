# Design: Redis as the Cluster Coordination Layer (direction 1)

Companion to `docs/auto/infrastructure-redis-direction1-spec.md`. This document
fixes the design decisions: API surface, wire/storage model, wiring, failure
modes, the state map, findings, and the ways the design could break. Scope is
exactly the spec's three improvements (new `redisbus`, `BuildInvalidationBus` +
`ClusterBusConfig` wiring, loss-detection semantics). Out of scope and
deliberately not folded in: store observability metrics, session-enumeration
N+1, and the stale `infrastructure/redis/doc.go` nested-module claim (redis has
no `go.mod` of its own — verified: `infrastructure/redis/` contains no
`go.mod`, and go-redis v9.20.0 + miniredis v2.38.0 are root-module deps in
`go.mod` lines 6/17; the doc comment is pre-existing drift).

Grounding evidence (line numbers re-checked against source at design time):

- `platform/cluster/bus.go` — `Bus` SPI: `Publish(ctx, Event) error`,
  `Subscribe(ctx) (<-chan Event, error)`, `Close() error`; `Event` is a
  JSON-shaped value (`json:"kind"` / `json:"key"` / `json:"payload,omitempty"`);
  package doc states best-effort delivery is the contract, and correctness never
  depends on delivery or ordering. Kinds are an open set (tenant suspension,
  discovery reload, authz policy change, residency, client change, connection
  change, control-plane restore, signing-key rotation, token revoked, session
  suspended, config digest).
- `infrastructure/mqtt/{bus,publish,subscribe}.go` — the reference
  implementation of the same SPI on a pub/sub transport: `var _ cluster.Bus =
  (*Bus)(nil)` (bus.go), `ErrClosed` (bus.go:11), `Publish` at publish.go:20
  with `json.Marshal(evt)` at publish.go:33, `Subscribe` at subscribe.go:24,
  subscriber channel closed on session loss via `defer close(out)` at
  subscribe.go:42 behind a `ctx.Done()` / `client.Done()` select
  (subscribe.go:41-49).
- `cmd/sso-server/serverbuildplatform/build_ratelimit_cluster.go:183-215` —
  `BuildInvalidationBus` switch covers only `""` / `memory` / `etcd`; the same
  file's `BuildRateLimitPolicy` (redis branch at :55) and `redisRateLimitPolicy`
  (nil-rdb boot error at :63-66:
  `"security.rate_limit.backend=redis but no redis block configured (set redis.addrs)"`)
  show the `case "redis"` + shared `goredis.Cmdable` pattern to copy.
  `ResolveServiceID(explicit, issuer)` lives in the same file (explicit YAML
  wins, else `issuer + "-" + short-hostname`).
- `config/config_keys.go:149-162` — `ClusterBusConfig` (`Backend` commented
  `"" | "memory" | "etcd"`, `Etcd*` fields only); `RedisConfig` doc comment:
  "One client is built from this block and fanned out to all redis-backed
  stores ... so HA tuning lives in one place."
- `cmd/sso-server/build_bootstrap.go:203-236` — `wireRedis` builds ONE shared
  `goredis.UniversalClient` from `config.RedisConfig`
  (`redisbackend.NewUniversalClient`, :213), registers the `redis` readycheck
  (`WithReadyCheck("redis", ping)` at :222), stores the client on `b.redis`.
  `wireRedis` is called at the top of `buildApp` (`build_stores.go:44`), which
  runs before `finalize` → `wireCluster` (`build_app.go:240`) — so `b.redis`
  is guaranteed non-nil by the time `BuildInvalidationBus` is called whenever
  a redis block is configured.
- `cmd/sso-server/build_app_cluster.go:127-164` — `wireCluster` calls
  `BuildInvalidationBus(&cfg.Cluster.Bus, logger)` at :137 and registers the
  `invalidation-bus` readycheck (`WithReadyCheck("invalidation-bus",
  InvalidationBusReady)`, :158-163) only when the bus is non-nil. The replica
  ID used by the signing-key registry is already computed in this file at
  :226-232 (`cfg.Keys.SigningKeyRegistry.ReplicaID` explicit, else
  `serverbuildplatform.ResolveServiceID(...)`) and passed via
  `sso.WithSigningKeyReplicaID`; the registry Service.ID uses the same helper
  at :482. `StartInvalidationBus` is invoked at :292; a boot-time Subscribe
  error surfaces there and fails boot.
- `interfaces/sso/server_invalidation.go` — `StartInvalidationBus` at :114
  (synchronous first `Subscribe` at :123 so an initial transport fault is a
  boot error, then `go s.runInvalidationBus` at :131);
  `runInvalidationBus` at :138-188 (bare `for evt := range events`; a closed
  channel under a live ctx is THE degraded signal — `setInvalidationBusDegraded`
  at :163, audit `invalidation_bus_degraded` (:90) + gauge 0, once per
  transition via `Swap`; backoff `sleepCtx` at :166 with
  `invalidationBusBackoff` 1s initial → 30s cap, exponential +
  deterministically jittered, :65-66/:266-277; `resubscribeAndReseed` at :175;
  `setInvalidationBusHealthy` at :184 with `invalidation_bus_recovered` audit
  (:91) + `re_seeded=true` meta (:81/:226)); `InvalidationBusReady` at :259
  gates `/readyz`. `applyInvalidationSafe` (:317) recovers per-event panics;
  `applyInvalidation`'s default arm (:331) ignores unknown kinds during
  mixed-version rollout; `applyControlPlaneInvalidation` (:340) is the
  cache-only dispatch.
- `interfaces/sso/server_extensions.go:396-455` — `resubscribeAndReseed` at
  :407: subscribe FIRST, then `reseedInvalidationState` (:417/:438) = cache
  flush + `reseedRevocationDenySets` re-seed; a failed re-seed keeps the
  replica degraded (fail-closed). `applyTokenRevocation` at :378.
- `interfaces/sso/server_key_rotation.go:163-215` — `applyCoordinatedKeyRotation`:
  new-kid verify-only adoption via the alg-matched `adoptPeerKey` path
  (best-effort), old-kid retire deferred to the carried deadline with
  floor/ceiling clamping (only ever DELAYS retire), synthetic replica id
  `coordinatedRotationReplicaID = "__coordinated_rotation__"`.
- `infrastructure/redis/cluster.go:22-33` — `hashTag` wraps keys in `{...}`
  braces to co-locate keys for atomic multi-key ops on Redis Cluster. Pub/sub
  channels are NOT keyspace keys, so hash-tagging does not apply to the bus
  channel.
- `platform/cluster/memory/bus.go:89` and `platform/cluster/etcd/etcd.go:147` —
  both peers use a 16-slot buffered out-channel with skip-on-full (memory
  bus.go:39); `redisbus` matches this.
- `infrastructure/redis/redis_test.go:15` — `newTestClient` (miniredis.Run +
  go-redis Client) is the existing in-process fake pattern; miniredis v2.38.0
  implements SUBSCRIBE/PUBLISH (cmd_pubsub.go:23/175) but not connection-death
  or reconnect emulation.
- `docs/config-reference.md:127` — `| Cross-replica bus | cluster.bus.backend |
  off · memory · etcd |` — the row that gains `redis`.
- Existing `BuildInvalidationBus` tests that the signature change must touch:
  `cmd/sso-server/cluster_bus_test.go` (UnsetIsNil/Memory/EtcdRequiresEndpoints/
  UnknownBackendErrors) and `cmd/sso-server/build_app_coverage_test.go`.

## API surface: `NewBus` over the shared client

**Decision:** Add `infrastructure/redis/bus.go` to the existing root-module
`redis` package. No new package, no new file elsewhere, no new nested module,
no `go.mod` change. The constructor takes the shared client — the same
`goredis.Cmdable` the stores take — so one pool and one HA story serve both
hot-path stores and the bus.

```go
// BusOption is a functional option (defaults when unset).
func WithChannel(channel string) BusOption         // default "snaplink:cluster:bus"
func WithInstanceID(id string) BusOption           // default "" = self-skip disabled

// NewBus returns a ready Bus. rdb must be non-nil. NewBus does not dial.
func NewBus(rdb goredis.Cmdable, opts ...BusOption) *Bus

var ErrClosed = errors.New("redis: cluster bus closed")

var _ cluster.Bus = (*Bus)(nil)  // compile-time SPI guard, mirrors mqttbus
```

Rationale and contract, decision by decision:

- **`*Bus` (no error return), unlike `mqttbus.New`.** mqtt validates required
  config fields at construction; `redisbus` has no required fields (the client
  is passed in, channel defaults), so there is nothing to fail. The
  constructor is infallible: a nil `rdb` yields a Bus whose first
  `Publish`/`Subscribe` returns a descriptive error rather than panicking. The
  `BuildInvalidationBus` layer does the nil-rdb validation with a proper boot
  error before construction (see "Wiring" below).
- **`Publish(ctx, evt)`**: check `closed` → `ErrClosed`; `json.Marshal(evt)`;
  `rdb.Publish(ctx, b.channel, body)`. Transport errors are returned as-is
  (wrapped with the channel for log correlation). Fire-and-forget is the
  caller's problem, not the bus's: the interface says Publish returns an error
  only for transport-level failures, and callers log-and-continue because the
  local mutation already succeeded. A `redis.Nil`-style no-op never occurs on
  Publish; any non-nil error is a real transport failure and must propagate.
- **`Subscribe(ctx)`**: `rdb.Subscribe(ctx, b.channel)`; a decode goroutine
  ranges the go-redis message channel and forwards decoded events to a buffered
  out-channel; the out-channel closes exactly when (a) ctx is cancelled,
  (b) `Close()` was called, or (c) the pub/sub connection is lost (go-redis
  closes its `PubSub` receive channel when reconnection fails / the client is
  closed). This closure-under-loss is the load-bearing decision — see
  "Failure modes".
- **`Close()`**: idempotent under a mutex (mirrors `mqttbus.Bus.Close`);
  sets `closed` so `Publish`/`Subscribe` return `ErrClosed`, and cancels the
  internal subscription context so an in-flight `Subscribe` stream closes. The
  shared `rdb` is NOT closed — the bus does not own the client (the bootstrap
  layer does, and closes it once at shutdown).
- **Concurrency**: `Publish` safe for concurrent goroutines (go-redis clients
  are concurrency-safe; the `closed` flag is mutex-guarded). `Subscribe` may be
  called once per Bus by the consumer loop; a second concurrent `Subscribe`
  would open a second pub/sub registration and is the caller's misuse, not
  supported (documented).
- **Instance self-skip**: when `WithInstanceID` is set, `Publish` attaches the
  ID as a JSON header field on the wire envelope and `Subscribe` drops messages
  carrying this Bus's own ID. Filtering is strictly by exact own-ID match — a
  peer's event is never suppressed. Rationale: a node already invalidates its
  own caches in-process at the mutation site (`InvalidateClientCache` etc. in
  server_invalidation.go:24-43); re-applying its own event is wasted work and,
  for `KindSigningKeyRotation`, would re-trigger coordination logic for its own
  rotation. Self-skip is disabled by default (`""`) so the wire behavior is
  byte-identical to the other backends unless an operator opts in; the sso-server
  wiring passes the replica ID it already synthesizes (`ResolveServiceID`) when
  one is available. No correctness dependency: receiving your own event is
  always safe (invalidation is idempotent), so a lost/mismatched ID only costs
  efficiency, never correctness.

## Wire and storage model: one JSON envelope on one namespaced channel

**Decision:** The transport has no storage. The "model" is: every event is a
single JSON document published to ONE channel; subscribers decode and dispatch.
This is the minimal faithful surface for the SPI — the etcd backend's
append-only-watch and the mqtt backend's topic both reduce to the same
fire-and-forget semantics, and the SPI explicitly does not require persistence,
replay, ordering, or delivery guarantees.

- **Envelope** (wire format, versioned by absence): the envelope adds
  `instance` (the publisher's ID, omitted when self-skip is off) plus the
  `cluster.Event` fields inline — NOT a nested struct, so the JSON is
  `{"kind":..., "key":..., "payload":..., "instance":...}` and an older peer
  that does not know `instance` ignores it (Go's `encoding/json` skips unknown
  fields). A decode failure drops the message with a log counter — never
  propagated as an event — mirroring `applyInvalidation`'s default arm (unknown
  kind from a newer peer is ignored during mixed-version rollout). There is no
  schema registry and no per-kind channel: the SPI's kinds are an open set and
  the consumer dispatches on `Kind`, so a single channel is the correct shape
  (matches mqtt's documented single-topic decision).
- **Channel name**: default `snaplink:cluster:bus`, overridable per issuer via
  `cluster.bus.redis_channel` so multiple issuers sharing one logical Redis can
  namespace their buses. The default carries no `{...}` hash tag — pub/sub
  channels are NOT part of the keyspace and are NOT slot-routed on Redis
  Cluster (a pub/sub message is delivered to every node and forwarded to every
  subscriber in the cluster), so hash-tagging the channel is meaningless. The
  existing `hashTag` helper (`infrastructure/redis/cluster.go:33`) applies to
  keyspace keys only; the bus does not use it. The channel name is still
  namespaced (prefixed) to avoid colliding with other applications sharing the
  instance and to keep it visually distinct from keyspace keys.
- **Buffer and slow consumers**: the out-channel is buffered
  (`subscribeChannelBuffer = 16`, matching mqtt/etcd/memory peers — memory
  bus.go:89, etcd etcd.go:147). A full buffer drops the event rather than
  blocking go-redis's receive loop — the documented TTL fallback is the safety
  net, exactly as `platform/cluster/memory/bus.go` and mqtt's `subscribe.go`
  document. No unbounded queue: a dead-but-not-yet-closed subscription must not
  accumulate memory without bound.
- **No persistence, no replay**: `Publish` issues `PUBLISH` only. There is no
  stream/consumer-group, no `LPUSH`+`BRPOP` fallback, no durable backlog. If an
  event is lost (disconnect, slow consumer, Redis restart), the affected
  replica(s) converge via `resubscribeAndReseed`'s re-seed (cache flush +
  revocation deny-set re-seed) on the next resubscribe, or via ordinary cache
  TTL — both already-shipped, already-correct fallbacks. Adding delivery
  guarantees would violate the SPI's stated contract ("a dropped Event degrades
  a replica to its existing TTL fallback ... never to a wrong answer") and
  would reintroduce the very operational complexity (backlog sizing, redelivery
  windows, duplicate handling) this direction exists to remove.

## State map: owners, stores, durability, consistency, replication, failover

The bus is a pure transport; it stores nothing. The honest way to state
consistency guarantees is per coordinated state: where it lives, who mutates
it, what durability it has, how replicas converge, and what happens on
failover. The table below is the complete inventory of state the bus touches,
plus the authoritative stores the bus explicitly does NOT touch (the OAuth/
session/JTI/refresh trace).

### State the bus coordinates (per-replica)

| State | Owner | Store | Durability | Consistency | Replication | Failover |
|---|---|---|---|---|---|---|
| Tenant suspension status | Tenant store (authoritative, admin-mutated) | Per-replica in-memory TTL cache (`tenantSuspensionCache`) | None — rebuilt from store on miss | Eventual; convergence window = TTL, narrowed to ~0 by bus | `KindTenantSuspension` per tenant key | TTL fallback; `/readyz` drains the replica while the bus is degraded |
| Tenant residency policy | Tenant store | Per-replica TTL cache (`tenantResidencyCache`) | None | Eventual (TTL) | `KindTenantResidency` | TTL fallback |
| Discovery snapshot + rendered docs + JWKS body cache | Union of all clients (admin/DCR mutations) | Per-replica discovery cache + JWKS body cache | None | Eventual (TTL); global, not per-key | `KindDiscoveryReload` (Key empty) | Flush + recompute on next request |
| Authz policy bundle (per client) | Permissions provider (admin role edits) | Per-replica bundle cache | None | Eventual (TTL) | `KindAuthzPolicyChange` per client ID | Flush + re-render on next sidecar pull |
| Client metadata (opt-in per-login cache) | Client store (authoritative) | Per-replica `ClientStore` cache | None | Eventual (TTL); credential path bypasses the cache entirely | `KindClientChange` per client ID | Evict + re-read; never affects a credential decision |
| Connection configs | Admin API → connection store | No per-replica cache exists yet; arm is an explicit placeholder | — | n/a today | `KindConnectionChange` | n/a today |
| Access-token revocation deny-set | Local revoke handler (`/token/revoke` on the mutating replica) | Per-process issuer `revoked` map (JWT issuers) | None in the bus; the durable revocation store is the re-seed source | Eventual, and the ONE fail-closed state: NO TTL safety net | `KindTokenRevoked` adds; boot `SeedRevocations` + recovery re-seed | Re-seed on recovery; replica stays degraded until re-seed succeeds |
| Signing-key rotation (peer kids + retire deadlines) | Rotating replica | In-process verify-key set + pending-retire timers | None; the per-replica grace window is the fallback | Eventual; deadline clamped floor/ceiling, retire can only be DELAYED | `KindSigningKeyRotation` (new-kid adopt + old-kid defer); leaderless aggregation loop is the independent fallback | Fail-safe widen-only; aggregation degradation has its own readycheck |
| Session suspension | SessionManager (authoritative store, already destroyed) | No per-replica session cache exists | — | Strong — the store is the source of truth; a lost event never resurrects a session | `KindSessionSuspended` arm is a placeholder for a future cache | Store-side destroy wins |
| Config digest | Per replica | In-memory digest | None | Report-only (audit + metric on mismatch, no behavior change) | `KindConfigDigest` (Key = publisher replica ID) | No-op by design |

### State the bus does NOT touch (authoritative stores — the trace)

These are the hot-path stores the shared Redis client already serves; the bus
neither carries nor repairs them. Their guarantees are unchanged by this design:

- **JTI replay** (`infrastructure/redis/jti_replay.go:58`): Redis `SET NX EX`
  atomic test-and-set, TTL-bounded, single-writer per token. Not replicated via
  the bus; a token replayed on another replica is handled by that replica's own
  store. Store-outage errors fail open per AGENTS.md (default JTI-replay-store
  errors).
- **Refresh-family rotation** (`infrastructure/redis/refresh_token.go`, family
  SETs + Lua): authoritative Redis/SQLite store; atomic consume, `FamilyID`
  carried through rotation, family reuse → `invalid_grant` + family delete.
  Cross-replica refresh revocation is store-side (shared Redis = shared store);
  the bus carries only `KindTokenRevoked` for ACCESS tokens.
- **AuthCode / PAR / Device / CIBA**: authoritative stores, single-use atomic
  consume; no bus role.
- **Sessions**: authoritative store; every session check reads it directly
  (`applySessionSuspension` has nothing to evict today).

### Readiness trace

`/readyz` on a redis-bus deployment has exactly two bus-relevant checks:
`redis` (transport ping, `build_bootstrap.go:222` — shared by every redis
store) and `invalidation-bus` (`build_app_cluster.go:158-163` →
`InvalidationBusReady`, `server_invalidation.go:259` — bus-internal
degradation only). No third check is added: the bus is fail-open (dropped
events degrade to TTL) and it consumes the already-probed client, so it cannot
be down while the `redis` check is green except in the transient reconnect
window the subscriber loop handles internally — which is exactly what the
`invalidation-bus` check exists to surface. The two checks therefore have
disjoint failure domains: transport (redis) vs. subscription-liveness
(invalidation-bus).

## Wiring: config + build path + docs

**Decision:** Extend `config.ClusterBusConfig` with a `redis` backend and one
optional field; extend `BuildInvalidationBus` with a `case "redis"` that
consumes the shared client; sync `docs/config-reference.md` in the same change
(AGENTS.md §5 contract-sync rule).

- **Config shape** (`config/config_keys.go:151`):

  ```go
  type ClusterBusConfig struct {
      Backend string `yaml:"backend"` // "" | "memory" | "etcd" | "redis"

      // RedisChannel namespaces this issuer's bus channel. Empty = default
      // ("snaplink:cluster:bus"). Only consulted when backend=redis. The
      // connection itself is always the shared redis.* block — no new
      // credentials/endpoints fields.
      RedisChannel string `yaml:"redis_channel"`

      EtcdEndpoints   []string      `yaml:"etcd_endpoints"`   // unchanged
      EtcdPrefix      string        `yaml:"etcd_prefix"`      // unchanged
      EtcdDialTimeout time.Duration `yaml:"etcd_dial_timeout"` // unchanged
      EtcdEventTTL    time.Duration `yaml:"etcd_event_ttl"`   // unchanged
      EtcdUsername    string        `yaml:"etcd_username"`    // unchanged
      EtcdPassword    string        `yaml:"etcd_password"`    // unchanged
  }
  ```

  The comment on `RedisConfig` ("One client is built from this block and fanned
  out to all redis-backed stores") extends naturally to the bus: `RedisConfig`
  stays the single HA-tuning point, and the bus gets no endpoint/password
  fields of its own.

- **Build path** — `BuildInvalidationBus` gains the shared client. Two shapes
  were considered; the chosen one keeps the existing two-arg signature and the
  etcd/memory branches untouched by taking a third parameter:

  ```go
  func BuildInvalidationBus(cfg *config.ClusterBusConfig, rdb goredis.Cmdable,
      logger spi.Logger) (cluster.Bus, string, error)
  ```

  (Rationale: `BuildRateLimitPolicy`'s precedent passes `rdb` through the same
  function rather than splitting a sibling; the call site in
  `build_app_cluster.go:137` passes `b.redis` — nil when no redis block is
  configured, which is exactly the validation trigger.) New branch:

  ```go
  case "redis":
      if rdb == nil {
          return nil, "", errors.New(
              "cluster.bus.backend=redis but no redis block configured (set redis.addrs)")
      }
      opts := []redisbus.BusOption{redisbus.WithChannel(cfg.RedisChannel)} // empty ⇒ default inside
      if instanceID != "" { opts = append(opts, redisbus.WithInstanceID(instanceID)) }
      bus := redisbackend.NewBus(rdb, opts...)
      logger.Info("invalidation bus", "backend", "redis", "channel", bus.Channel())
      return bus, "redis", nil
  ```

  The error shape matches `redisRateLimitPolicy`'s
  `"security.rate_limit.backend=redis but no redis block configured (set redis.addrs)"`
  (verified at build_ratelimit_cluster.go:63-66) and the config-reference's
  documented boot-error pattern. The replica-ID option: the wiring reuses the
  same derivation already computed in `build_app_cluster.go:226-232` for
  `WithSigningKeyReplicaID` (`keys.signing_key_registry.replica_id` explicit,
  else `ResolveServiceID(registry.service_id, server.issuer)`) — it is in
  scope in the same file and is unique per host by construction. The bus treats
  it as purely advisory (self-skip efficiency, see API surface). This is a
  single extra parameter computed in `build_app_cluster.go`, not a config knob.

- **Readiness**: the redis bus intentionally gets NO `/readyz` check of its own
  — it is fail-open (dropped events degrade to TTL), and the existing `redis`
  readycheck registered in `build_bootstrap.go:222` already covers transport
  availability (a dead Redis flips the `redis` check red, which is the honest
  signal). The bus is a consumer of that same client, so it cannot be "down"
  while the redis check is green except in the transient reconnect window the
  subscriber loop handles internally. This matches the existing
  `BuildInvalidationBus` doc ("the bus is fail-open, so it intentionally gets
  no /readyz check", build_ratelimit_cluster.go:181-182) and the `etcd`
  branch's precedent. `InvalidationBusReady` still gates `/readyz` via the
  existing `wireInvalidationBusOpts` wiring — but only for bus-internal
  degradation, not for Redis availability.

- **Docs**: `docs/config-reference.md:127` row becomes
  `off · memory · etcd · redis`; a short paragraph documents
  `cluster.bus.redis_channel` (default `snaplink:cluster:bus`, empty means
  default, only consulted when backend=redis) and the reuse of the shared
  `redis:` block (no new endpoints).

## Failure modes and recovery semantics

**Decision:** `Subscribe`'s channel closure is the single, unambiguous loss
signal; the bus must surface EVERY failure mode as that closure and nothing
else. `Publish` must surface transport failures as errors. The generic
self-heal loop (`runInvalidationBus`) then applies unchanged — that is the
entire point of improvement 3.

Loss taxonomy and how each maps to the contract:

| Failure | Surface | Consequence |
|---|---|---|
| Redis unreachable at subscribe time | `Subscribe` returns error (initial subscribe is synchronous in `StartInvalidationBus`, server_invalidation.go:123) | Boot failure surfaces to the caller (`build_app_cluster.go:292`) — same as etcd/mqtt |
| Connection drops mid-subscription, reconnect fails, or client closed | go-redis closes the `PubSub` receive channel → decode goroutine closes `out` | `runInvalidationBus` sees a closed channel under a live ctx → `setInvalidationBusDegraded` (audit + gauge 0) → backoff → `resubscribeAndReseed` |
| Silent stall (connection half-open, no traffic) | go-redis's internal heartbeat (dialer/read timeout on the pub/sub connection) detects the dead peer and closes the `PubSub` channel | Same as above — this is why the bus must NOT mask closure |
| `Close()` called | `closed` flag + internal ctx cancel close `out` | Clean shutdown; consumer exits via the ctx-done branch without degrading |
| ctx cancelled | `out` closes | Clean shutdown, no degraded state |
| Garbage/undecodable message | Dropped with log counter | Never propagated; consumer loop unaffected |
| Slow consumer (buffer full) | Event dropped | TTL fallback, same as memory/mqtt peers |
| Publish to unreachable Redis | Non-nil error returned | Caller logs; local mutation already succeeded; peers converge via TTL/re-seed |

The critical property, stated as an invariant: **a lost subscription must look
exactly like a closed channel, never like a healthy one.** The one way this
design could silently degrade (the "blind replica" hazard the spec calls out)
is if the decode goroutine kept the out-channel open after the go-redis
receive channel died. Therefore: the goroutine's only exit paths are
(a) ctx done, (b) go-redis channel closed, (c) internal close — and every one
of them closes `out` exactly once (single `defer close(out)`). There is no
path that returns to the receive loop after a closure, and no background
reconnect inside the bus: reconnection is `resubscribeAndReseed`'s job, and
doing it inside the bus would race the re-seed ordering (subscribe must precede
re-seed; a self-reconnecting bus could deliver an event into the re-seed
window and get flushed by it — harmless, but it would blur the one-owner
property of the recovery loop).

Re-seed ordering is inherited, not re-implemented: `resubscribeAndReseed`
(`server_extensions.go:407`) subscribes FIRST (no fresh loss window), then
flushes caches + re-seeds revocation deny-sets (`reseedInvalidationState`,
:438), and only then does `runInvalidationBus` call `setInvalidationBusHealthy`
— which emits `invalidation_bus_recovered` with `re_seeded=true`. Events
buffered on the new stream during the re-seed are applied right after;
invalidations are idempotent so the overlap is safe. The redis bus must do
nothing that breaks this ordering (notably: no internal auto-resubscribe, no
replay of missed events — see "Wire and storage model"). A partial re-seed
keeps the replica degraded (fail-closed, :417-425) and the loop retries the
whole subscribe+re-seed cycle after backoff.

Self-skip safety under failure: the instance-ID filter drops only messages
whose `instance` equals this Bus's own ID. If the ID is empty (self-skip off),
nothing is filtered. If two replicas accidentally share an ID, events between
them are filtered in BOTH directions — a coordination loss that the degraded
loop cannot detect (the channel stays open). Mitigation: the sso-server wiring
derives the ID from `ResolveServiceID` (issuer + short hostname, unique per
host by construction, per `build_app_cluster.go:226-232`'s documented
rationale) or an explicit `keys.signing_key_registry.replica_id`; the bus
documents that the option is advisory and must be unique per process. This is
the one residual operator-error mode, and it is fail-safe in the direction of
staleness (TTL fallback), never wrong answers — but it IS silent, so the design
calls it out explicitly (see "Findings" F-1 and "What could break the design").

## Findings: severity, evidence, trigger, impact, recovery, corrective pattern

Findings are about the DESIGN (the redis backend does not exist yet); each
names the corrective pattern the implementation must honor. Severity per the
shared rubric (Critical = release blocker; High = likely material availability/
correctness failure; Medium = bounded gap; Low = improvement; Info = context).

| ID | Severity | Finding | Evidence (verified) | Triggering failure | User impact | Recovery | Corrective pattern |
|---|---|---|---|---|---|---|---|
| F-1 | High | Self-skip ID collision = silent coordination loss; the one failure the degraded loop cannot see (channel stays open, no audit, `/readyz` green, TTL-only convergence) | Design's own-instance filter; ID derivation `build_app_cluster.go:226-232`; `ResolveServiceID` hostname-based | Operator sets identical `replica_id` on two replicas, or two replicas share a short hostname | A just-suspended tenant / rotated key / revoked token stays honored on the peer until its TTL; no signal anywhere | Manual detection (config review, audit logs); convergence happens anyway via TTL — never a wrong answer | Unique-by-construction ID (existing derivation); startup log line recording bus instance ID; document uniqueness requirement; partial detection path: `KindConfigDigest` carries the publisher replica ID (`platform/cluster/bus.go`) when the drift loop is enabled |
| F-2 | Medium | Ping-green-but-pub/sub-dead proxy: Redis answers PING but terminates SUBSCRIBE; bus blind with both readychecks green | `build_bootstrap.go:222` redis readycheck is a PING; the bus has no channel-level heartbeat | L7 proxy / Redis proxy misconfiguration in front of the fleet | Invalidations silently stop; TTL-only convergence, invisible to operators | None automatic — the connection never dies, so no closure fires | Accepted, out of scope (channel heartbeats violate the best-effort SPI); documented limitation; operators must not front pub/sub with a terminating proxy |
| F-3 | Medium | go-redis reconnect masking: if the bus ever owns its reconnect, the closure signal disappears and the "blind replica" returns | go-redis `PubSub` reconnect-with-backoff semantics; design forbids internal reconnect | A future refactor adds `Receive` retry inside the bus | Same as F-2, but self-inflicted | — | Review invariant: decode goroutine consumes the go-redis channel exactly once; closure on termination whatever the cause |
| F-4 | Medium | miniredis fidelity gap: transport-loss semantics (reconnect exhaustion, connection death mid-subscription) are not emulated in-process | miniredis v2.38.0 cmd_pubsub.go implements SUB/PUB only; `redis_test.go:15` newTestClient | Real-Redis reconnect cycle differs from miniredis behavior | Unit tests pass while production behaves differently (e.g. faster/slower closure) | Forced-disconnect integration test + operator-side real-Redis smoke test | SPI contract (TTL fallback) bounds the blast radius of any behavior miniredis misses; document the gap |
| F-5 | Medium | Redis Cluster fan-out silent drop: a partition/proxy that drops messages (not connections) is undetectable (no sequence numbers, no channel heartbeats) | Plain `PUBLISH`/`SUBSCRIBE` is cluster-wide; design has no seqno by contract | Network partition with connection keep-alive intact | Same TTL-only window as F-2, bounded and fail-safe | Re-seed path on next reconnect; otherwise TTL | Explicitly DO NOT add sequence numbers — would break mixed-version peers and turn best-effort into a correctness dependency |
| F-6 | Medium | Channel collision on shared Redis: two unrelated deployments on one logical Redis cross-invalidate each other's trusted mesh events | Default channel `snaplink:cluster:bus`; `redis_channel` knob is the namespace | Sharing one Redis across unrelated deployments without distinct channels | Wrong caches flushed on both sides; event stream is trusted mesh-internal | Set distinct `redis_channel` per issuer | Documented; default is namespaced; `redis_channel` exists for exactly this |
| F-7 | Low | Duplicate delivery / reordering: pub/sub can redeliver across reconnect windows and never orders | Redis pub/sub semantics; SPI idempotence contract | Re-subscribe while a message is in flight | Harmless — double invalidation is a no-op | None needed | No dedup, no ordering; `applyInvalidationSafe` recovers per-event panics |
| F-8 | Low | Slow-consumer liveness: a stuck consumer must not block the go-redis receive loop or grow memory without bound | memory bus.go:89 / etcd etcd.go:147 use 16-slot buffers; design matches | Consumer stuck behind a slow handler | Dropped events (TTL fallback), never a stall | Drop-not-block `select` with `default` | Fixed 16-slot buffer is the deliberate middle; never unbounded, never blocking |
| F-9 | Low | Mixed-version fleet wire compatibility: new `instance` field vs. old peers | `encoding/json` skips unknown fields; `applyInvalidation` default arm ignores unknown kinds (server_invalidation.go:331) | Rolling upgrade with redis bus on some replicas | None — additive field, graceful default arms | — | `instance` stays additive/optional; kinds stay an open set |
| F-10 | Low | `BuildInvalidationBus` signature-change ripple | Call site `build_app_cluster.go:137`; tests `cluster_bus_test.go` (4 cases) + `build_app_coverage_test.go` | The change itself | None if branches stay untouched | — | Nil-rdb guard BEFORE `NewBus` (descriptive boot error, not a runtime panic on first publish); memory/etcd branches byte-identical |
| F-11 | Info | Boot-time nil-rdb is a config error, not a runtime panic | `redisRateLimitPolicy` precedent (build_ratelimit_cluster.go:63-66) | `cluster.bus.backend=redis` with no `redis:` block | Boot fails with a descriptive message instead of a first-publish panic | Operator sets `redis.addrs` | Mirrored error shape `"cluster.bus.backend=redis but no redis block configured (set redis.addrs)"` |

## Scenario table

Distributed-systems scenarios, each traced through the design. "Guarantee
preserved" names the invariant from "Stated guarantees".

| Scenario | Trigger | Observed behavior | User impact | Recovery | Guarantee preserved |
|---|---|---|---|---|---|
| Partition: Redis unreachable from one replica (already subscribed) | Network partition; go-redis pub/sub conn dies | Out-channel closes → degraded (audit `invalidation_bus_degraded` once, gauge 0) → `/readyz` red → backoff 1s→30s jittered; `Publish` errors logged | Replica drains from LB; invalidations pause during outage (TTL fallback covers caches; deny-set waits for re-seed) | Partition heals → resubscribe → re-seed → `invalidation_bus_recovered` (`re_seeded=true`) → gauge 1 | G-2 (loss = closure), G-5 (fail-open caches / fail-closed recovery), G-6 (no internal reconnect) |
| Partition: Redis unreachable at boot | Replica starts while Redis is down | `StartInvalidationBus` first `Subscribe` returns error → boot fails (`build_app_cluster.go:292`) | Deployment controller restarts the pod; no half-armed replica ever serves | Redis back → clean boot | G-4 (initial transport fault is a boot error, matching etcd/mqtt) |
| Replica crash | Process kill / OOM | No bus state to lose; caches die with the process; peers unaffected | Brief capacity loss only; no stale invalidation state anywhere | Restart: boot-time `SeedRevocations` + fresh subscribe; empty caches re-fetch | G-1 (no persistence ⇒ no crash-recovery ordering problem) |
| Redis failover (sentinel/cluster) | Master failover while subscribed | go-redis `PubSub` dies or reconnects across the failover; at worst the channel closes | Transient degraded window while the subscriber loop resubscribes; `/readyz` red only if the closure fires | Same degraded→resubscribe→re-seed→healthy loop; `redis` readycheck pings the new master | G-2, G-6 |
| Retry storm: all replicas lose the bus at once | Redis restart / network blip fleet-wide | Every replica enters the same loop; backoff is deterministically jittered (no rand), so retries de-synchronize; degraded audit fires ONCE per transition (Swap guard) | Brief fleet-wide drain (readyz red) if the outage exceeds one backoff cycle | Staggered resubscribes; each replica re-seeds before going healthy | G-6 (single-owner recovery), once-per-transition audit |
| Duplicate delivery | Message in flight across a resubscribe | Event applied twice; `applyInvalidation` arms are idempotent (cache evict / deny-set add / retire defer) | None | None needed | G-3 (idempotent, order-independent) |
| Clock rollback on a replica | NTP step-back on publisher or receiver | Bus itself is clock-free (no timestamps). `MetaRetireDeadline` = publisher's now + grace, clamped floor/ceiling by the receiver; a stepped-back publisher emits a deadline in the past → clamped to the floor, retire DELAYED, never early | None — fail-safe direction is widen-only | n/a | AGENTS.md "Production clocks slew; they do not step backward"; rotation arm clamps garbage/past to a floor (server_key_rotation.go:163) |
| Stale cache (lost event, healthy connection) | Silent drop (F-5) or slow-consumer drop | Replica serves cached state until its TTL; deny-set entry stays missing until exp (no TTL) | Bounded staleness window, never a wrong answer; revoked token stays valid on that replica until exp in the worst case | TTL; re-seed on next resubscribe; `/token/revoke` deny-set is re-seeded from the durable store at recovery | G-5 (fail-open caches, fail-closed deny-set recovery) |
| Dependency outage: Redis down entirely | Full Redis outage | Publish errors (logged); subscription closes → degraded; `redis` readycheck red → replica drains | Fleet cannot serve redis-backed hot paths anyway (stores fail) | Redis back → both checks recover; bus re-seeds | Fail-open per-store contracts unchanged; bus adds no new failure surface |
| Recovery sequencing | Post-outage resubscribe | Subscribe FIRST, re-seed SECOND (flush caches + deny-set re-seed), healthy LAST; a partial re-seed keeps `/readyz` red and retries the whole cycle | No window where readiness is green over stale deny-sets | Loop retries with longer backoff; shutdown during backoff exits cleanly | G-5 (AGENTS.md §3 ordering), G-6 |
| Slow consumer | One replica's handler stalls | Its 16-slot buffer fills; events dropped for that replica only; publisher and other replicas unaffected | That replica converges by TTL | Consumer drains; buffer frees | G-8 (drop-not-block, bounded memory) |
| Two replicas share an instance ID (operator error) | `replica_id` duplicated | Mutual event suppression; channel healthy, no audit, readychecks green | TTL-only convergence (F-1); never a wrong answer | Operator corrects config; `KindConfigDigest` (if enabled) surfaces duplicate publisher IDs | G-3 (correctness never depends on self-skip) |

## Stated guarantees, unsupported topologies, validation tests, residual risks

### Stated guarantees

The redis backend commits to exactly these — no more, no less:

- **G-1 No persistence, no replay, no ordering, at-most-once delivery.** A
  dropped event is repaired by TTL or by the re-seed path, per the SPI contract.
- **G-2 A lost subscription looks exactly like a closed channel, never like a
  healthy one.** The out-channel closes on ctx cancel, `Close()`, and transport
  loss; there is no path that keeps it open after the go-redis channel dies.
- **G-3 Invalidation is idempotent and order-independent; self-skip never
  suppresses a peer's event** (filter is exact own-ID only). Correctness never
  depends on self-skip, dedup, or ordering.
- **G-4 `Publish` returns transport errors and `ErrClosed` after `Close`; the
  initial `Subscribe` is synchronous** so a transport fault at boot fails boot,
  exactly like the etcd/mqtt backends.
- **G-5 Fail-open for caches, fail-closed for recovery:** dropped events
  degrade a replica to its existing TTL fallback (never a wrong answer);
  recovery clears degraded readiness only after subscribe + full re-seed
  (cache flush + revocation deny-set re-seed) succeed (AGENTS.md §3).
- **G-6 The recovery loop is the single owner of resubscribe ordering.** The
  bus performs no internal reconnect; subscribe-before-reseed is never raced
  by the transport.
- **G-7 The bus never closes the shared client and adds no readycheck.** One
  pool, one HA story, two disjoint readiness checks (transport vs.
  subscription-liveness).
- **G-8 Bounded memory under slow consumers** (16-slot drop-not-block buffer,
  matching memory/mqtt/etcd peers) and safe concurrent `Publish` (mutex-guarded
  closed flag; go-redis clients are concurrency-safe).
- **G-9 Version-safe wire format:** `instance` is an additive optional field;
  an older peer ignores it, a newer peer treats its absence as self-skip-off.

### Unsupported topologies and usage

- More than one concurrent `Subscribe` per Bus (documented misuse; the
  consumer loop owns the single subscription).
- A bus constructed with a nil client: the build layer rejects
  `backend=redis` without a redis block at boot; a hand-constructed nil-rdb Bus
  returns a descriptive error on first use, never panics.
- Internal reconnect, replay, durable backlog, sequence numbers, per-kind
  channels — all deliberately unsupported (they would violate G-1/G-2/G-6).
- Blocking publish or unbounded buffers (violate G-8).
- One logical Redis shared by unrelated deployments without distinct
  `redis_channel` values (F-6).
- Real-Redis reconnect-exhaustion semantics as a unit-testable property —
  validated by the forced-disconnect integration test and an operator-side
  smoke test, not by miniredis (F-4).
- Any deployment that treats the bus as a delivery guarantee (the SPI forbids
  it; see `platform/cluster/bus.go` package doc).

### Validation tests

Mapped 1:1 to the spec's acceptance checks; see "Test plan" for the full list.
The load-bearing ones for the distributed-systems properties:

1. Loss-detection unit test: close the underlying go-redis client with a live
   subscription → the out-channel closes and a subsequent `Publish` returns a
   non-nil error (G-2, G-4).
2. Forced-loss end-to-end (`test/`, `package ssotest`): after a forced
   disconnect, `InvalidationBusReady()` reports degraded (`invalidation_bus_degraded`
   once per transition), recovery re-seeds and reports healthy
   (`sso_invalidation_bus_up == 1`), and a `KindTokenRevoked` published after
   recovery is applied — the full degraded→resubscribe→reseed→healthy loop on
   the redis backend (G-5, G-6).
3. Config validation: `backend=redis` without a redis block → the descriptive
   boot error; with a miniredis-backed client → non-nil `cluster.Bus`,
   backend kind `"redis"` (F-11).
4. Race discipline: new bus tests run with `-count=10+` under
   `go test ./... -race` (AGENTS.md §5).

### Residual risks

The ranked register in "What could break the design" below is the residual-risk
list. The two accepted blind spots are F-2 (ping-green-but-pub/sub-dead proxy)
and F-5 (cluster fan-out silent drop) — both undetectable by any design that
stays faithful to the best-effort SPI, both bounded by TTL fallback, and both
documented rather than "fixed" with sequence numbers or heartbeats. F-1
(self-skip ID collision) is the only residual risk that is silent, operator-
induced, and detectable in principle — the design mitigates it by
unique-by-construction ID derivation and calls it out in this doc.

## What could break the design

1. **Self-skip ID collision between replicas** (the silent coordination loss).
   Two replicas configured with the same instance ID would suppress each
   other's events while the subscription stays healthy — no degraded signal,
   no audit, `/readyz` green, TTL-only convergence. This is the most dangerous
   failure this design introduces, precisely because every other failure is
   loud by construction. Defenses: unique-by-construction ID derivation in the
   wiring (`ResolveServiceID`, `build_app_cluster.go:226-232`), documented
   uniqueness requirement, and — if a future direction wants belt-and-braces —
   a startup log line recording the bus instance ID. Not a correctness hole
   (never a wrong answer, only a wider staleness window), but worth stating.
   See F-1.

2. **go-redis reconnect masking.** If a future change lets the bus own its
   reconnect (e.g. calling `PubSub.Receive` in a retry loop), the closure
   signal disappears and the "blind replica" returns. The design fixes this by
   forbidding internal reconnect: the decode goroutine consumes the go-redis
   channel exactly once and closes `out` on its termination, whatever the
   cause. This must be a review invariant. See F-3.

3. **miniredis fidelity gap.** miniredis implements PUBLISH/SUBSCRIBE for
   in-process tests but does NOT emulate real Redis reconnect behavior,
   backpressure, cluster-wide fan-out, or connection death mid-subscription.
   The unit tests can verify round-trips, self-skip, `ErrClosed`, and ctx
   cancellation, and can simulate loss by closing the go-redis client or the
   miniredis server — but the "subscription channel closes on transport loss"
   path against a REAL go-redis reconnect cycle is only exercised by the
   forced-disconnect integration test (close the underlying client, assert the
   channel closes, assert the degraded audit fires, then verify
   `InvalidationBusReady` recovers). Real-Redis validation remains an
   operator-side smoke test; the design accepts this gap because the SPI's
   contract (TTL fallback) bounds the blast radius of any transport behavior
   miniredis misses. See F-4.

4. **Redis Cluster cross-node pub/sub fan-out assumptions.** PUBLISH on a
   cluster node fans out to all nodes, so a subscriber connected to any node
   receives every channel message — this is what makes the single-channel bus
   work on Cluster. A misbehaving proxy or network partition that drops
   messages (not connections) is undetectable by design (no sequence numbers,
   no heartbeats on the channel). Accepted: this is exactly the SPI's
   best-effort contract, and the re-seed path is the repair. The design must
   NOT add sequence numbers — that would break mixed-version peers and would
   turn a best-effort transport into a correctness dependency. See F-5.

5. **Ordering and duplicate delivery.** Redis pub/sub can deliver a message
   more than once in pathological reconnect scenarios (re-subscribe while a
   message is in flight) and never guarantees order. Both are safe:
   invalidation is idempotent and order-independent by the SPI's contract, and
   `applyInvalidationSafe` contains per-event panics. The bus does not attempt
   dedup or ordering. See F-7.

6. **Slow-consumer drop vs. the decode goroutine's liveness.** The
   drop-instead-of-block choice (`select` with `default`) keeps go-redis's
   receive loop alive at the cost of dropping events under load. If the buffer
   were ever made unbounded, a stuck consumer would grow memory without bound;
   if it were made blocking, a stuck consumer could stall the pub/sub
   connection and trip reconnect logic (a self-inflicted degradation loop).
   The fixed 16-slot buffer matching the other peers is the deliberate middle.
   See F-8.

7. **Channel collision with a second application or issuer sharing the
   Redis.** Two deployments publishing to the same channel would cross-
   invalidate each other's caches (events are mesh-internal and trusted).
   Default channel is namespaced (`snaplink:cluster:bus`); `redis_channel`
   exists specifically so a shared Redis can host multiple issuers. Operators
   who share one Redis across unrelated deployments must set distinct
   channels — documented. See F-6.

8. **Mixed-version fleets.** A newer replica publishing `instance` headers to
   older peers: ignored (unknown JSON field), fine. An older replica publishing
   to a newer one: no `instance` field, self-skip simply doesn't apply to those
   events, fine. New `EventKind`s already have a graceful default arm. No wire
   incompatibility is introduced, provided the envelope keeps `instance` as an
   additive optional field rather than a required one. See F-9.

9. **`BuildInvalidationBus` signature change ripple.** The third parameter
   touches one call site (`build_app_cluster.go:137`) and the existing unit
   tests for `BuildInvalidationBus` (`cluster_bus_test.go`,
   `build_app_coverage_test.go`); the memory/etcd branches are untouched so
   behavior is preserved. The nil-rdb guard must run BEFORE `NewBus` so the
   failure is a descriptive boot error, not a runtime panic on first publish.
   See F-10.

10. **Readycheck blind spot.** A Redis that accepts pings but silently drops
    pub/sub (e.g. a proxy that terminates SUBSCRIBE) would leave the redis
    readycheck green and the bus blind — the one case neither the redis
    readycheck nor the degraded loop can see (no messages flow, so the
    connection never dies). Accepted as out of scope: it requires
    channel-level heartbeats, which violate the best-effort SPI. Documented as
    a known limitation; the degraded path covers every case where the
    connection actually breaks, which is the overwhelming majority. See F-2.

## Test plan (mapped to spec acceptance)

- `infrastructure/redis/bus_test.go` (unit, miniredis via the existing
  `newTestClient` pattern): round-trip decode fidelity; two `NewBus` instances
  on one miniredis deliver to each other; `Close` → `Publish` returns
  `ErrClosed`; ctx cancellation closes the stream exactly once; self-skip
  filters only own events; garbage payload is dropped without closing the
  stream; slow-consumer drop doesn't block the publisher.
- Forced-loss test: close the underlying go-redis client (or miniredis) with a
  live subscription and assert the out-channel closes and a subsequent
  `Publish` returns a non-nil error (spec improvement 3; G-2/G-4).
- Config/build tests: `backend=redis` without a redis block → the descriptive
  boot error; with a redis block (miniredis-backed client) → non-nil
  `cluster.Bus` whose backend kind is `"redis"`.
- `test/` cross-server end-to-end (`package ssotest`): two `sso.Server`
  instances sharing one miniredis, redis-backed stores + redis bus; publish
  `KindTenantSuspension` (or `KindTokenRevoked`) on replica A; assert replica
  B's cache/deny-set converges without etcd; then force the loss and assert
  `InvalidationBusReady()` degrades, recovers after reconnect, and the
  degraded/recovered audit events fire once per transition.
- Gates: `go build ./... && go vet ./...`, maintainability/architecture tests,
  `go test ./... -race` (bus tests with `-count=10+`), `make ci`.
