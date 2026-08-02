Design doc written to `docs/auto/interfaces-ratelimit-direction2-design.md`. It grounds every claim in the code I read (all three backends, middleware, metrics layer, and the full caller graph).

## What the doc covers

**Per-decision sections (## 决策一/二/三), each with API surface, storage model, failure modes, and breakage analysis**, plus a global blast-radius inventory and a commit/verification plan.

## Key architect findings beyond the spec

1. **A coupling the spec misses: `selfservicecore.RateLimiter`** (`protocols/selfservice/selfservicecore/deps.go:21`) has a byte-identical signature to `ratelimit.Limiter`. Go has no covariance, so changing `Allow`'s return type silently breaks the documented public wiring `WithSelfServiceSignupRateLimiter(ratelimit.NewMemoryLimiter(...))` (options_passwd.go:139). Resolution: hoist the `Allowance` value type to `shared/spi` so `*MemoryLimiter` satisfies both interfaces structurally — zero adapters, zero breaks. Alternatives (type duplication, signature change) rejected with reasons.

2. **Deny-all vs fail-open are indistinguishable by value** (both have `Limit==0`). The header-writing rule needs a three-way table (`Limit>0` → all three headers; `!OK && Limit==0` → `Remaining: 0` only; `OK && Limit==0` → nothing), which the spec implied but didn't state.

3. **Redis deny-all needs an explicit `denyAll` marker** — `{limit:1, window:365d}` is value-indistinguishable from a legitimate config; it can't be inferred from numbers.

4. **The 1/64 sampling for `sso_rate_limit_remaining` must live in the middleware closure, not the backend**: `calls` is unexported, `{policy}` is only known there, and SQLite's prune sampling is clock-based not call-based — middleware-level sampling gives uniform semantics across all three backends.

5. **Memory's buckets gauge hook can't fire on the inline prune path** — that runs under a shard lock and `Buckets()` locks all shards (self-deadlock). It fires only inside `StartPruner`'s background sweep, meaning the gauge is gated on `prune_interval` (documented).

6. **Zero storage changes**: SQLite table and Redis Lua script stay untouched — both already hold or return the needed data; Memory reads `x/time`'s `Tokens()` after Cancel, inside the shard lock.

Also documented: the full caller graph (sso quota.go, admin governance.go, three test doubles, fuzz/bench), the `Reset` epoch-vs-delta draft ambiguity, and a risk register with severities and mitigations.
