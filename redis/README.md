# redis — Redis hot-path store backend for snaplink/sso

Redis-backed implementations of the snaplink/sso **hot-path stores** — the
session, refresh-token, authorization-code, PAR, and JTI-replay SPIs — for
the **throughput / multi-replica scale layer** (>1k QPS, many replicas
sharing one logical store).

SQLite (`defaultimpl/sqlite`) stays the **embedded fallback**: it's the
cluster-shareable default for any deployment that fits a single file or a
small fleet. Redis is the next step up — a network store with microsecond
ops, native per-key TTL, and atomic server-side scripting — purpose-built
for auth-heavy loads.

## Why a separate module

This is a **separate nested Go module** (`github.com/snaplink/sso/redis`)
so the `github.com/redis/go-redis` dependency **never enters the core `sso`
module's `go.mod`** — the core's zero-external-SDK invariant stays intact.
Operators who need Redis opt in by importing this submodule from their own
`cmd` binary. Mirrors `kms/awskms`. There is deliberately **no `go.work`**:
a workspace would merge the build lists and surface go-redis in the core's
`go list -m all`. The submodule resolves the core via a
`replace github.com/snaplink/sso => ../` directive; CI builds + race-tests
it via the Makefile `ci-modules` target against an in-process
[miniredis](https://github.com/alicebob/miniredis) fake — no real Redis
needed.

## Install

```bash
# from your operator cmd module
go get github.com/snaplink/sso/redis
```

## Wiring

Build one `*redis.Client` (or `ClusterClient` — any `redis.Cmdable`) and
hand it to each store constructor, then pass the store to the matching
`sso.WithXxx` option:

```go
import (
    goredis "github.com/redis/go-redis/v9"
    "github.com/snaplink/sso"
    "github.com/snaplink/sso/oauth"
    rstore "github.com/snaplink/sso/redis"
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

## Atomicity guarantees (the §2 invariants these stores preserve)

The §2 oracle-leak / single-use / session-refresh / family-rotation /
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

Per §2, **`/token` fails closed**: if Redis is unreachable, refresh
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

Implemented: `SessionManager`, `RefreshTokenStore` (+ `Inspector`,
`SubjectIndex`, `SubjectCounter`, `ClientPurger`, `FamilyTracker`),
`AuthCodeStore`, `PARStore`, `JTIReplayStore`.

Same-pattern follow-ups (single-use / TTL): rate-limit
(`ratelimit.Limiter`), device-code, MFA-challenge, CIBA. Until then those
subsystems use their memory or sqlite backends.

## Testing

`go test ./... -race` runs every store against an in-process miniredis fake
— no Redis daemon required. The suite mirrors the SQLite oracle-leak
enumeration (unknown / expired / consumed → one result), session-refuses-
expired/revoked, family rotation + reuse → `DeleteFamily`, and JTI
first-vs-repeat.
