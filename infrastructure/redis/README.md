# redis — Redis hot-path store backend for snaplink/sso

> **Current status:** `infrastructure/redis` is a package in the root Go module,
> not a nested module. Its import path is
> `github.com/snaplink/sso/infrastructure/redis`, `go-redis` is present in the
> root `go.mod`, and the stock `cmd/sso-server` wires single, Sentinel, and
> Cluster clients from the shared `redis:` configuration block.

Redis-backed implementations of the snaplink/sso **hot-path stores** — the
session, refresh-token, authorization-code, PAR, and JTI-replay SPIs — for
the **throughput / multi-replica scale layer** (>1k QPS, many replicas
sharing one logical store).

SQLite (`infrastructure/defaultimpl/sqlite`) is the embedded, persistent
single-instance fallback. A local SQLite file is **not shared state** and must
not be used independently by multiple replicas behind a load balancer. Redis is
the shared hot-state choice for multi-replica deployments: a network store with
native per-key TTL and atomic server-side scripting.

## Stock binary and SDK wiring

For the shipped binary, configure one `redis:` block and select
`backend: redis` for every enabled hot-state concern. Merely declaring the
connection block does not move a store off its default. In HA, sessions,
authorization codes, refresh families and grace records, PAR/device/CIBA
requests, JTI replay, MFA challenges, password-reset/temp-code state, rate
limits, and account lockout must all be shared when enabled.

SDK embedders can construct the stores directly as shown below.

## Wiring

Build one `*redis.Client` (or `ClusterClient` — any `redis.Cmdable`) and
hand it to each store constructor, then pass the store to the matching
`sso.WithXxx` option:

```go
import (
    goredis "github.com/redis/go-redis/v9"
    rstore "github.com/snaplink/sso/infrastructure/redis"
    sso "github.com/snaplink/sso/interfaces/sso"
    "github.com/snaplink/sso/protocols/oauth"
)

rdb := goredis.NewClient(&goredis.Options{Addr: "redis:6379"})

sm  := rstore.NewSessionManager(rdb, rstore.WithSessionTTL(24*time.Hour))
rts := rstore.NewRefreshTokenStore(rdb) // + rstore.WithFamilyTTL(...)
acs := rstore.NewAuthCodeStore(rdb)
par := rstore.NewPARStore(rdb)
jti := rstore.NewJTIReplayStore(rdb)

srv := sso.NewServer(
    sso.WithSessionManager(sm),
    sso.WithRefreshTokenStore(rts, 30*24*time.Hour),
    sso.WithAuthCodeStore(acs, 10*time.Minute),
    sso.WithPARStore(par, oauth.DefaultPARTTL),
    sso.WithJTIReplayStore(jti),
)
```

Each store also exposes `Ping(ctx)` so it can back `sso.WithReadyCheck`.

## Atomicity guarantees

The repository's oracle-leak, single-use, session-refresh, family-rotation, and
replay invariants are **gates, not advice** — a wrong Redis op is a
security regression. Each store mirrors its SQLite peer's atomic primitive:

| Store | Redis primitive | SQLite analogue | Invariant preserved |
|---|---|---|---|
| `SessionManager.Refresh` | **Lua script** (`redis.Script`): re-reads `revoked` + `expires_at`, extends only when `revoked==0 AND expires_at>now`, else no-op | `UPDATE … WHERE expires_at>now AND revoked=0 RETURNING` | "captured expired session id can't be resurrected" |
| `AuthCodeStore.Consume` / `PARStore.Consume` | **GETDEL** (atomic get-and-delete) | `DELETE … RETURNING` | single-use; unknown/expired/consumed collapse to one `not found` |
| `RefreshTokenStore.Consume` | **GETDEL** active key + consumed-marker → reuse detect | `DELETE … RETURNING` + `refresh_token_families` ledger | single-use rotation; replay-after-rotation → `ErrRefreshTokenReused` → `DeleteFamily` (BCP §4.13/§4.14) |
| `JTIReplayStore.MarkSeen` | **SET key NX EX ttl** — succeeds iff key absent | `INSERT … ON CONFLICT DO NOTHING` + rows-affected | atomic first-sighting vs replay |

Family / subject / client bulk operations ride parallel SET indexes
(`sso:rt:family:*`, `sso:rt:subject:*`, `sso:rt:client:*`); the consumed
marker (`sso:rt:consumed:<token>`) survives the active key's delete so a
rotated-away token is recognized as reuse, not a vanilla miss.

## Failover + cross-region semantics

Per the repository fail-mode contract, **`/token` fails closed** when atomic
state is required: if Redis is unreachable, refresh
rotation and single-use `Consume` return an error and the grant is rejected
rather than minting a token against unknown state — a Redis outage must
never let a replayed code/refresh-token through. (Audit, geo, and other
best-effort lookups remain fail-open per their own contracts.)

**Cross-region replication lag** is a correctness caveat for single-use
state: async replication means a code/refresh-token/jti written on the
primary may not yet be visible on a replica serving the follow-up request.
Run single-use + replay traffic against the **primary** (or a
strongly-consistent setup) within one region; do **not** split a single
auth flow across asynchronously-replicated regions, or a replay could
momentarily evade detection.

## Scope

Implemented hot-state stores include sessions, refresh tokens and rotation
grace, authorization codes, PAR, device codes, CIBA, JTI replay, MFA and
consent challenges, rate limiting, account lockout, password reset,
temporary codes/tokens, and subject/client indexes. Redis implementations also
exist for clients, users, permissions, consents, and password credentials;
choose Postgres when these records are the durable system of record.

## Testing

From the repository root, `go test -race ./infrastructure/redis/...` runs the
stores against an in-process miniredis fake
— no Redis daemon required. The suite mirrors the SQLite oracle-leak
enumeration (unknown / expired / consumed → one result), session-refuses-
expired/revoked, family rotation + reuse → `DeleteFamily`, and JTI
first-vs-repeat.
