# Design: Post-Auth Rate Limiting (方向一) — client/user/admin buckets

> Source: [interfaces-ratelimit-requirements.md](interfaces-ratelimit-requirements.md).
> Scope: three post-auth (post-authentication) rate-limiting improvements —
> per-client bucket on `/token`, per-subject bucket on `/userinfo`
> (production wiring of `KeyBySubject`), and per-admin bucket on the admin
> API — plus the two 429 contract-drift fixes they touch. Out of scope:
> 方向二 (X-RateLimit-* visibility), 方向三 (limiter-implementation
> convergence). All changes stay in `interfaces/` + `config/` + docs;
> `protocols/oidc` gains interface methods only (no new imports).
> `interfaces/sso` is at its 60-file ceiling: no new files there, ever.

## ## Decision 1 — One shared post-auth checkpoint mechanism in `interfaces/ratelimit`

All three improvements evaluate a token bucket **after** authentication,
where the key is only derivable from the authenticated identity. The
existing `DynamicMiddleware` cannot express this: it runs pre-auth, outside
the router, and closes over request-derived keys only. Instead of three
ad-hoc inline checks, `interfaces/ratelimit` gains two small exports that
reuse the existing `PolicyStore`/`Policy` machinery as-is:

```go
// Checkpoint evaluates store's CURRENT Policy for r without writing a
// response: the programmatic counterpart of DynamicMiddleware for
// post-authentication checkpoints. Uses the Policy's Key func (default
// KeyByClientIP), evaluates Prefix rules, and records the standard
// rejection metric on deny (Policy.Metrics/TenantKeyFunc). ok=false +
// retryAfter>0 means the caller must emit a 429.
func Checkpoint(store *PolicyStore, r *http.Request) (ok bool, retryAfter time.Duration)

// TooManyRequests writes the canonical rate_limited 429 (body
// {"error":"rate_limited"}) + Retry-After — the exported form of the
// existing unexported writeTooManyRequests, so post-auth rejection shapes
// stay byte-identical to the middleware's.
func TooManyRequests(w http.ResponseWriter, retryAfter time.Duration)
```

Rationale, in order of weight:

1. **Wire-shape single source.** `writeTooManyRequests` and `rateLimitedBody`
   stay unexported; `TooManyRequests` delegates. Every surface that rejects
   a rate-limited request (phase-1 middleware, `/register`, and the three
   new phase-2 checkpoints) emits the identical 429 that `docs/error-codes.md`
   documents for `rate_limited` (line 921) — including the fix for the two
   drift sites (grant limiter, admin limiter) this design explicitly repairs.
2. **Hot-reload for free.** `Checkpoint` reads `store.Get()` per request,
   exactly like `DynamicMiddleware`, so a `PolicyStore.Set` from the SIGHUP
   path applies immediately without rebuilding handler chains.
3. **Metrics for free.** The reject path records `sso_rate_limit_hits_total`
   via the existing `recordRejection` (with `TenantKeyFunc`), which inline
   checks would have to re-implement.
4. **No layering violation.** `interfaces/ratelimit` keeps importing only
   `interfaces/middleware` (existing edge). `protocols/oidc` never imports
   `interfaces/ratelimit` — it calls deps hooks implemented in
   `interfaces/sso` (Decision 5), mirroring the existing `MaybeSignUserInfo`
   precedent.

Each phase-2 surface owns a **dedicated** `*ratelimit.PolicyStore` whose
`Policy.Key` derives the authenticated identity from the request context
(Decision 2):

| Surface | Store | Policy |
|---|---|---|
| `/token` client bucket | `Server.tokenClientRateLimitStore` | `Default: limiter, Key: KeyByClientID` |
| `/userinfo` + mesh | `Server.userInfoRateLimitStore` | `Default: limiter, Key: KeyBySubject` |
| admin tier-2 | `admin.Middleware.perAdminRateLimitStore` | direct `Allow("admin:"+subject)` (see Decision 6) |

## ## Decision 2 — Authenticated identity lands in the request context at the auth-success point

`KeyBySubject` is dead today because `middleware.WithSubject` has zero
callers (verified by grep: only the doc comment in
`interfaces/ratelimit/middleware.go:97` and the definition itself reference
it), so `SubjectFromContext` always returns `""` and the key degenerates to
IP. The fix is to make the identity write real, at the exact point
authentication succeeds:

1. **`core.HandlerContext` gains `SetRequest(r *http.Request)`** (additive;
   `shared/core/router.go`). Implementations: `core.Context` (assign
   `c.r`), `backgroundHandlerContext` (`interfaces/sso/sso_wiring.go`), and
   any test fakes — a compile error lists them all. Precedent:
   `SetResponseWriter` already mutates request-scoped state.
2. **`interfaces/middleware/context.go` gains the client twin of
   `WithSubject`**: `WithClientID(ctx, clientID)` /
   `ClientIDFromContext(r)` — same unexported-key pattern, 6 lines.
3. **`interfaces/ratelimit` gains `KeyByClientID`** — the exact mirror of
   `KeyBySubject`: context client id → `"client:<id>"`, else
   `KeyByClientIP`.

The two write points:

- `/token`: `handleToken` writes `WithClientID` **only when the client
  authenticated with a real credential** (see Decision 3) — public-client
  auth leaves the context untouched, so `KeyByClientID` falls back to IP.
- `/userinfo` and mesh: the oidc deps hook stores the validated subject via
  `WithSubject` + `SetRequest` (Decision 5).

This makes `WithSubject`'s first production write and `KeyBySubject`'s first
functional consumer land in the same change, which is the requirements
spec's deliverable for 改进二. Today nothing downstream reads the subject
context; the write is forward-compatible plumbing that costs one
`context.WithValue` per authenticated request.

## ## Decision 3 — 改进一: `/token` phase-2 per-client bucket

**API** (all in existing files):

```go
// options_grants.go — follows the WithClientRegistrationRateLimit precedent
// (a Limiter, not numbers): Redis/SQLite cross-replica backends are
// expressible. nil = feature off (byte-identical default).
func WithTokenEndpointClientRateLimit(limiter ratelimit.Limiter) Option

// server_routes.go beside SetRateLimitPolicy — the SIGHUP hook. Returns
// false (no-op) when the option was never wired, mirroring
// SetRateLimitPolicy's "can't add a gate after boot" contract.
func (s *Server) SetTokenEndpointClientRateLimit(limiter ratelimit.Limiter) bool
```

The option wraps the limiter in `ratelimit.NewPolicyStore(ratelimit.Policy{
Default: limiter, Key: KeyByClientID, Metrics: s.metrics})`.

**Placement** in `handleToken` (`server_token.go`): immediately after
`authenticateTokenClient` returns success, before the residency gate.
Rationale: it is the earliest point the client identity is verified, and it
bounds every downstream cost — residency, FAPI enforcement (audit spam),
idempotency-cache writes, and the grant handler itself. Unauthenticated and
failed-auth requests return before the check and never touch the bucket
(oracle-safe; response byte-identical to a build without the feature).

**Credential-gated keying — the one design refinement over the spec's
letter.** The spec's key is `client:<client_id>`. That is safe for
confidential clients, but a **public client authenticates by presenting its
`client_id` with no credential** — the ID is public knowledge (it ships in
SPA/native binaries). Keying a public client's bucket on its ID lets any
attacker fill `client:<victim-public-client>` and 429 the victim's entire
PKCE flow — a *new* DoS vector created by the limiter itself, the same flaw
class as the documented-UNSAFE `KeyByClientIDOrIP`. Therefore:

```go
// Post-auth-success, a credential was genuinely verified iff:
credentialed := client.Secret != "" ||            // secret in body/Basic
    req.ClientAssertion != "" ||                  // private_key_jwt / workload / SPIFFE
    client.TokenEndpointAuthMethod == ClientAuthTLS ||
    client.TokenEndpointAuthMethod == ClientAuthSelfSignedTLS
```

Only credentialed requests write `WithClientID` (and thus key
`client:<id>`); public-client requests fall back to the IP key inside the
same store. Acceptance tests in the spec use `client_credentials` clients
(confidential), so they pass unchanged; the fallback keeps the phase-2
bucket un-spoofable. Residual (documented in config-reference): public-client
`/token` floods are IP-bounded only, by both phase-1 and this fallback.

**Grant-type limiter contract fix (same improvement, item 3).**
`rateLimiterEntry.limiter` migrates from `*rate.Limiter` to the
`ratelimit.Limiter` SPI (constructed via `ratelimit.NewMemoryLimiter`), so
`checkGrantRateLimit` can emit `Retry-After` and the canonical body.
`WithGrantTypeRateLimit`'s signature is unchanged; its `>=0`/negative
semantics are preserved (negative → nil limiter → unlimited). Rejection
changes from 429 + `errorBody(ErrUnsupportedGrantType)` to
`ratelimit.TooManyRequests` — a deliberate, documented wire fix:
`docs/error-codes.md` gains the phase-2/grant source note, and the
`unsupported_grant_type`-on-429 misread (SPAs branching per
`docs/error-codes.md:921`) is eliminated. Ordering: the grant check stays
inside `dispatchTokenGrant` (post-idempotency); the client check is
pre-idempotency — a replay flood consumes the client bucket, which is
correct (replays are still requests).

## ## Decision 4 — 改进二: `/userinfo` phase-2 per-subject bucket

**The layering problem.** The bearer validation runs inside
`protocols/oidc.HandleUserInfo` (`authenticateUserInfoBearer`), and
`protocols/oidc` may not import `interfaces/ratelimit` or
`interfaces/middleware` (DIRECTORY_MAP layering). A router-level phase-2
middleware with a pre-validation "subject capture" pass was considered and
rejected: it would double the signature verification on the exact attack
path (valid-token scraping) and any reject it emitted would risk drifting
from the handler's canonical 401 challenges. Instead, follow the
`MaybeSignUserInfo` precedent — deps hooks:

```go
// protocols/oidc/handle_userinfo.go — UserInfoDeps additions (2 methods):
StoreUserInfoSubject(ctx core.HandlerContext, sub string)      // sso impl: WithSubject + SetRequest
UserInfoRateLimited(ctx core.HandlerContext) bool             // sso impl: Checkpoint; true = 429 already written
```

`HandleUserInfo` calls them in order, between `authenticateUserInfoBearer`
success and the residency gate:

```
claims, ok := authenticateUserInfoBearer(d, ctx)   // 401 ladder unchanged
if !ok { return }
d.StoreUserInfoSubject(ctx, claims.Subject)        // first production WithSubject write
if d.UserInfoRateLimited(ctx) { return }           // phase-2 checkpoint
// residency gate, user lookup, body — unchanged
```

The `interfaces/sso` implementations:

```go
func (s *Server) StoreUserInfoSubject(ctx core.HandlerContext, sub string) {
    r := ctx.Request()
    ctx.SetRequest(r.WithContext(middleware.WithSubject(r.Context(), sub)))
}
func (s *Server) UserInfoRateLimited(ctx core.HandlerContext) bool {
    if s.userInfoRateLimitStore == nil { return false }   // byte-identical when off
    if ok, retry := ratelimit.Checkpoint(s.userInfoRateLimitStore, ctx.Request()); !ok {
        ratelimit.TooManyRequests(ctx.ResponseWriter(), retry)
        return true
    }
    return false
}
```

Options: `WithUserInfoRateLimit(limiter ratelimit.Limiter)` +
`SetUserInfoRateLimit(limiter) bool` (same shape as Decision 3), store
Policy `Key: KeyBySubject`.

**Mesh variant.** `handleMeshExtAuthz` is sso-owned and already has the
validated subject in `res.Subject` (`MeshAuthorizeResult`). After
`MeshAuthorize` succeeds (and only then): write `WithSubject` + `SetRequest`,
then the same `Checkpoint` against the same `userInfoRateLimitStore`; on
deny, write 429 via `TooManyRequests` and return (sidecar sees DENY). Denied
mesh requests (bad token) never consume a subject bucket — identity is
unknown, matching the oracle discipline.

**Bucket key: `claims.Subject` (the wire sub), not the resolved local user
ID.** The check must run before `ResolveLocalSubject`/`GetByID` — those
store reads are exactly what the limiter protects — so the local ID is not
available at the check point without adding a read. Pairwise subs alias one
user across sectors into a bounded handful of buckets; escape still requires
distinct valid tokens per distinct sub, i.e. distinct accounts. Documented
in config-reference.

## ## Decision 5 — 改进三: admin two-tier limiting

**Today**: `checkRateLimit` runs pre-auth with the constant key `"admin"`
(`interfaces/admin/governance.go:275-280`, `middleware.go:330`) and rejects
with body `{"error":"rate_limit_exceeded"}` — an undocumented code.
Consequences: one shared bucket (cross-admin starvation), and per-admin
keys are impossible pre-auth.

**Two tiers, configurable as a unit.** `interfaces/admin` gains:

```go
// governance.go — mirror of the existing SetRateLimit pair:
func (a *Middleware) SetPerAdminRateLimit(tokensPerSec float64, burst int)
func (a *Middleware) SetPerAdminRateLimitPolicyStore(store *ratelimit.PolicyStore)
```

- **Unconfigured (no call): byte-identical to today.** Tier-1 keeps the
  constant key `"admin"`, the `rate_limit_exceeded` body, Retry-After.
  Default compatibility is an explicit acceptance check.
- **Configured** (per-admin enabled): the admin surface opts into the
  corrected semantics as one unit:
  - **Tier-1 (pre-auth, coarse):** same `checkRateLimit`, same rate numbers,
    but the key becomes the real client IP (`middleware.RealClientIP(r)` —
    validated peer IP when `TrustedProxies` is wired, else TCP remote).
    Per-IP keying is *required* for the per-admin tier to deliver its
    promise: with a global tier-1 bucket, admin A's flood would exhaust it
    and admin B would be 429'd at tier-1 before ever reaching tier-2. The
    tradeoff — distributed unauthenticated spray is now bounded per-IP, not
    globally — is accepted and documented (same doctrine as the SSO
    phase-1 chain).
  - **Tier-2 (post-auth, fine):** immediately after `authenticateHTTP`
    succeeds and before `enforceIdleTimeout`/`checkWriteQuota`, keyed
    `"admin:"+claims.Subject` against `perAdminRateLimitStore.Get().Default`
    (direct `Allow`, mirroring `checkRateLimit`'s shape — no `Policy.Key`
    involvement, no context plumbing needed; the actor context already
    carries the identity for handlers). Placing it before the idle-timeout
    check means a flooding admin receives a constant 429 shape regardless
    of session-expiry state — no new auth-state oracle. The optional
    `client:<clientID>` stacking from the spec is deferred: subject-only
    satisfies the acceptance tests and avoids key-cardinality growth.
  - **Rejection shape on both tiers:** standard `rate_limited` +
    `Retry-After` via `ratelimit.TooManyRequests`. The undocumented
    `rate_limit_exceeded` code disappears from the admin surface — this is
    the admin twin of the grant-limiter fix, applied only in the
    opted-in mode so the byte-identical default acceptance holds.

Both tiers are separate `PolicyStore`s, both hot-swappable (SIGHUP wiring in
Decision 6); tier-2's store is only reachable with a valid token, so its
existence is not probeable.

## ## Decision 6 — Config surface, SIGHUP wiring, and the 429 contract table

**Config keys** (all new; `security.*` blocks in
`config/config_metrics_security.go` + `config/config_load.go`):

| Key | Semantics | Maps to |
|---|---|---|
| `security.rate_limit.token_client.{per_sec,burst}` | `(0,0)` absent = off; backend shared with `security.rate_limit.backend` | `sso.WithTokenEndpointClientRateLimit` |
| `security.rate_limit.userinfo.{per_sec,burst}` | same | `sso.WithUserInfoRateLimit` |
| `admin.rate_limit.per_admin.{per_sec,burst}` | configuring it also switches tier-1 to per-IP + standard `rate_limited` body (Decision 5) | `admin.SetPerAdminRateLimit*` |

**Hot reload.** `config/reload`'s `applyRateLimit` currently rebuilds only
the phase-1 `Policy` via the `setRateLimitPolicy` hook. Extend it with one
additional hook, `SetPostAuthRateLimitHook(fn func(config.RateLimitConfig)
error)`, wired in `cmd/sso-server/main_wiring.go`; the hook rebuilds the
`token_client` and `userinfo` limiters (same backend dispatch the phase-1
builder uses — extract a shared single-limiter builder from
`serverbuildplatform.BuildRateLimitPolicy`) and calls
`Server.SetTokenEndpointClientRateLimit` / `SetUserInfoRateLimit`. Called
once per Reload, same "whole block rebuild" contract as today. The admin
per_admin block is boot-config with a runtime `PolicyStore` swap, matching
the existing admin rate-limit lifecycle (not SIGHUP-reloaded today; wiring it
into the same hook is a one-line follow-up if the admin block ever joins the
reload set).

**429 contract table after this change** (all `rate_limited` unless noted):

| Surface | Before | After |
|---|---|---|
| phase-1 middleware | `rate_limited` + Retry-After | unchanged |
| grant-type limiter | 429 `unsupported_grant_type`, no Retry-After | `rate_limited` + Retry-After (fix) |
| `/token` client bucket (new) | — | `rate_limited` + Retry-After |
| `/userinfo` subject bucket (new) | — | `rate_limited` + Retry-After |
| admin, unconfigured | 429 `rate_limit_exceeded` + Retry-After | byte-identical |
| admin, per-admin configured | — | `rate_limited` + Retry-After, both tiers |

## ## Decision 7 — Storage model

No new storage. All three improvements consume the existing
`ratelimit.Limiter` SPI with the existing implementations:

- **State**: token-bucket entries per key (`client:<id>`, `sub:<subject>`,
  `admin:<subject>`, per-IP, `"admin"`), keyed by FNV-32a across 16 shards.
- **Lifecycle**: lazy 1-in-64 sampled pruning with a 10-minute idle horizon
  (`MemoryLimiter`); `StartPruner` available for high-cardinality
  deployments. Key cardinality is naturally bounded: clients are
  registered (confidential subset for the token bucket), subjects are
  users, admins are few. A scraper cycling many valid user tokens adds one
  bucket per distinct subject — pruned 10 minutes after each goes idle.
- **Backends**: `security.rate_limit.backend` (`memory` · `sqlite` ·
  `redis`) dispatches the phase-2 limiters too. Memory = per-replica
  enforcement (documented phase-1 limitation, unchanged); Redis = shared
  cross-replica buckets (the spec's reason for accepting a `Limiter` rather
  than numbers).
- **Single-use / atomicity**: rate limiting is not a consume-once store; no
  `DELETE RETURNING`-style invariants apply. `Allow` is atomic per shard.
- **No clock coupling**: `rate.Limiter` reservations are monotonic; the
  `Retry-After` ceiling-rounding (min 1s) already handles sub-second waits.

## ## Decision 8 — Failure modes

| Failure | Behavior | Acceptability |
|---|---|---|
| Limiter backend outage (Redis/SQLite) | The SPI has no error return; existing backends fail open (allow). Limiting silently off until recovery | Consistent with the codebase's fail-open-with-log doctrine for rate limiting; auth availability wins. Verify the Redis/SQLite limiter's fail-open on error is logged and preserved when reused |
| SIGHUP rebuild | In-memory bucket state resets (documented phase-1 behavior) | Brief excess-allowance window per reload; no correctness impact |
| Memory growth under token-cycling scrapes | Bounded by distinct authenticated identities; 10-min prune; `StartPruner` for large deployments | Same guarantees as phase-1 |
| Concurrent same-key requests | Shard-locked `Allow`; reservation cancelled on deny (no charge) | Correct; idempotent |
| Replay flood with `Idempotency-Key` | Client bucket consumed pre-idempotency; cached replays still counted | Correct: replays are requests |
| Public-client spoof | Closed by credential-gated keying (Decision 3); fallback IP bucket | Residual: public-client floods are IP-bounded |
| Distributed unauthenticated admin spray | Per-IP tier-1 bounds each source IP, not the aggregate | Accepted tradeoff, documented (Decision 5) |
| Admin A floods shared NAT IP | A 429s at tier-2 (own bucket); B passes tier-1 only while aggregate stays under the coarse IP budget | Documented residual of per-IP tier-1; e2e must size tier-1 > A's flood rate |
| Idle-expired admin floods | Constant 429 at tier-2 before idle-timeout check; session state not revealed | Oracle-safe by ordering |

## ## Decision 9 — Latency budget for the per-request checkpoints

Each checkpoint adds one bounded step to the `/token`, `/userinfo`, and
admin hot paths: `PolicyStore.Get()` (one `atomic.Pointer` load) + key
extraction + `Limiter.Allow(key)`. On deny only, it adds one metric
increment + the canonical 429 write — the allow path pays **zero** metric
cost (existing doctrine: `recordRejection` and `TenantKeyFunc` run only on
rejects). The identity write (`StoreUserInfoSubject` = `WithSubject` +
Request clone) precedes the `/userinfo` checkpoint.

Measured on this machine (AMD Ryzen AI MAX+ 395, `go test -bench
-count=3`, medians; modeled checkpoint = `store.Get()` + `Policy.Key` +
`Allow`, the exact `Checkpoint` shape):

| Component | Budget (p99) | Measured | Headroom |
|---|---|---|---|
| Identity write (`WithSubject` + clone) | ≤ 1 µs | 24 ns, 1 alloc | ~40x |
| Key extraction (`KeyBySubject` w/ ctx / IP fallback) | ≤ 1 µs | 19 ns / 11.5 ns | ~50x |
| Checkpoint, memory backend (Get + Key + Allow) | ≤ 5 µs | 0.19 µs, 2 allocs (80 B) | ~25x |
| Checkpoint, sqlite backend | ≤ 100 µs | 16.5 µs, 43 allocs (uncontended single writer) | ~6x |
| Checkpoint, redis backend | ≤ 2 ms | not measured (no server); one INCR round trip, ~50-200 µs loopback | ≥10x |
| Deny-path add-on (metric + Retry-After 429) | ≤ 1 ms | 0.14 µs over allow cost (0.33 µs total reject) | ~7,000x |
| Guarded work, for scale: EdDSA bearer verify on `/userinfo` | — | 30.7 µs, 12 allocs | — |

Reading the table:

- **The checkpoint is one to two orders of magnitude below the work it
  guards.** On memory it adds 0.19 µs against the 30.7 µs EdDSA
  verification alone (0.6%) — and a smaller fraction of `/token`'s
  credential auth + grant dispatch. The relative budget (≤ 10% of the
  guarded endpoint's p99) holds for memory with ~2 orders of magnitude of
  margin; the sqlite/redis floors are set by the backend itself (one disk
  write / one network round trip per `Allow`), which is the operator's
  explicit cross-replica choice and the same cost phase-1 already pays on
  every limited path — restated in config-reference so nobody reads the
  memory number as a backend-independent guarantee.
- **Allocation cost is negligible and bounded:** 2 allocs/request on the
  subject path (the `"sub:"+` concat, 16 B) and 1 on the IP-fallback
  path, vs. 12 allocs in the guarded EdDSA verify alone. Not worth a
  `[]byte` buffer optimization.
- **Backend dispatch is boot/SIGHUP-only.** `BuildRateLimitPolicy` and the
  extracted shared single-limiter builder (Decision 6) run once per
  reload; the SQLite migration likewise. Zero per-request dispatch cost —
  the per-request price is entirely the selected `Limiter`'s `Allow`.

### Rate-sizing constraint under burst (Memory 16-shard limiter)

The load-bearing e2e constraint (Decision 8: tier-1 per-IP rate must
**exceed** the flood rate F so admin B on the shared NAT IP is not
starved at tier-1 while A floods; A is stopped at tier-2) is config
arithmetic — and the limiter cannot distort it:

1. **Serialization ceiling.** A single key hashes to one shard; that
   shard's serialized `Allow` ceiling is 1/180 ns ≈ **5.5M ops/s** —
   three to four orders of magnitude above any F an operator can
   configure (the phase-1 defaults and realistic e2e floods are 10²-10⁴
   req/s) and above what an HTTP test harness can generate. The bucket
   refills at the configured rate regardless of request latency, so the
   limiter never under-delivers tokens at the sizing boundary: if
   R_t1 > F is satisfied arithmetically, it is satisfied in practice.
2. **Burst absorption.** Burst tokens are pre-credited; a same-key burst
   of B requests serializes on the shard mutex at 180 ns each (B = 10k →
   1.8 ms total). No queueing beyond the mutex, no head-of-line
   amplification.
3. **Cross-key contention.** The parallel benchmark (16 goroutines,
   32-key pool) shows 73-100 ns/op — sharding delivers its design goal;
   even the worst case of attacker-chosen keys concentrating on one shard
   keeps that shard at ≥ 5.5M ops/s (and the keys here are
   identity-derived — subjects, client IDs, IPs — not free-form input).
4. **Prune sampling.** The 1-in-64 sampled prune scans the touched shard
   (O(N/16)); measured 0.45 µs/op at 10k resident keys (2.5x baseline) —
   the e2e flood's handful of keys stays at the ~0.19 µs level.
   High-cardinality deployments get `StartPruner` via the shared builder
   (`PruneInterval`), which the phase-2 stores inherit.
5. **e2e wall clock.** Rejected requests cost 0.33 µs each (memory); the
   flood's 429s are emitted at the flood rate with no server-side
   queueing distortion of the test's assertions.

### Regression guard

`BenchmarkMemoryLimiterAllow*` is already in the opt-in bench gate
(`ops/deploy/benchgate/benchmarks.yaml`, 10% threshold vs. per-machine
baseline) and covers ~94% of the checkpoint cost (0.18 µs of the 0.19 µs);
the remaining ~19 ns is key extraction. Promoting a modeled checkpoint
benchmark into the gate is a deliberate follow-up in the implementation
change (the gate's doctrine requires explicit promotion — new benchmarks
never silently join). The numbers above are the acceptance reference for
that promotion and for the e2e's tier-1 sizing.

## ## What could break the design

1. **`HandlerContext.SetRequest` ripple.** The interface change is
   additive, but every implementation (2 production + test fakes) must
   compile; a fake that ignores `SetRequest` silently breaks
   subject-keyed tests. Mitigation: compile guard + the userinfo unit test
   asserts `KeyBySubject` returns `sub:<subject>` after the hook runs.
2. **Public-client bucket spoof** (the one genuine security refinement):
   if the credential gate (Decision 3) is implemented incorrectly — e.g.
   keying on `client.Secret != ""` alone, which is fine, or forgetting the
   mTLS/assertion methods — the limiter creates a new DoS vector. The gate
   reuses the exact classification `denyPublicClientCredentials` and the
   FAPI client-auth switch already compute; unit tests must cover
   secret-post, Basic, private_key_jwt, mTLS, and public-PKCE auth.
3. **`"client:"` key-namespace collision.** `KeyByClientIDOrIP` (UNSAFE,
   pre-auth) uses the same `client:<id>` prefix. The phase-2 stores are
   dedicated instances, so no state is shared — but an operator who wires
   the *same* limiter instance into both a phase-1 policy using
   `KeyByClientIDOrIP` and a phase-2 store reopens the Basic-username
   spoof. Hard rule, documented in config-reference: phase-2 limiters are
   always freshly constructed; the build layer never shares an instance
   across phases.
4. **Two deliberate 429 wire changes** (grant limiter:
   `unsupported_grant_type` → `rate_limited`; admin configured mode:
   `rate_limit_exceeded` → `rate_limited`). Existing clients that branch on
   the buggy codes change behavior. Both are contract fixes the spec
   mandates ("修正…漂移", "拒绝统一 rate_limited"), documented in
   `docs/error-codes.md` in the same change. The admin body change is
   scoped to the opted-in mode so the "byte-identical default" acceptance
   holds — if a stricter reading demands the body change unconditionally,
   the byte-identical default acceptance fails; the conditional scope is
   the only reading that satisfies both.
5. **Double-validation temptation for `/userinfo`.** A router-mounted
   phase-2 middleware with a pre-validation subject-capture pass would
   double signature verification on the scrape path and risk 401-challenge
   drift. The deps-hook design (Decision 4) avoids both; do not "simplify"
   toward the middleware.
6. **Admin tier-1 rekeying is load-bearing.** If tier-1 stays
   constant-keyed when per-admin is configured, admin A's flood exhausts
   the global bucket and tier-2 never gets to protect admin B — the 
   improvement silently fails its own acceptance test. The e2e (two admins,
   shared NAT IP) additionally requires tier-1's per-IP rate to exceed the
   test's flood rate.
7. **Hot-reload hook growth.** If `SetPostAuthRateLimitHook` is not wired
   in `main_wiring.go`, SIGHUP changes to `token_client`/`userinfo` numbers
   silently do nothing (the reloader reports Applied only when the hook is
   wired, so it degrades to "Ignored" — visible, not silent). Wire it in the
   same commit as the config keys.
8. **Budget ceilings.** No new `interfaces/sso` files (60-file ceiling);
   additions land in `options_grants.go`, `server_token.go`,
   `server_userinfo.go`, `server_routes.go`, `sso_wiring.go`. New functions
   stay under 50 lines (extract helpers, e.g. the credential-gate check and
   the mesh checkpoint). `interfaces/admin` and `interfaces/ratelimit`
   stay within their existing files and line budgets.
9. **Layering regression risk.** `protocols/oidc` must not import
   `interfaces/*` — the new `UserInfoDeps` methods are the only channel;
   `go vet`/architecture gate enforce this. `config/reload` already calls
   into sso via hooks; the new hook keeps that pattern.
10. **Backend floor misread.** The 0.19 µs memory number is not
    backend-independent: sqlite pays a disk write per `Allow` (16.5 µs
    measured) and redis one round trip. If an operator wires
    `security.rate_limit.backend=sqlite` and reads the memory budget
    elsewhere, the `/userinfo` checkpoint becomes a real cost —
    documented in config-reference next to the new keys, and covered by
    the Decision 9 per-backend budgets.
11. **Checkpoint latency regression.** The bench gate covers `Allow` but
    not key extraction; if a later change fattens `KeyByClientID`/
    `KeyBySubject` (e.g. a store-backed lookup on the allow path), the
    budget silently drifts. Mitigation: keep key funcs context-only
    (they are), and promote the modeled checkpoint benchmark into the
    bench gate in the implementation change (Decision 9, regression
    guard).

## ## Contract and documentation obligations (AGENTS.md §5.6, same change)

- `docs/config-reference.md`: `security.rate_limit.token_client.*`,
  `security.rate_limit.userinfo.*`, `admin.rate_limit.per_admin.*`
  (including the tier-1 rekey + body-unification note and the
  dedicated-instance invariant), hot-reload table entry for the post-auth
  hook, and the Decision 9 per-backend latency floor note (sqlite = one
  disk write per `Allow`, redis = one round trip) next to the new keys.
- `docs/error-codes.md`: `rate_limited` row gains phase-2 sources
  (grant limiter, `/token` client bucket, `/userinfo` subject bucket, admin
  configured mode); note the `unsupported_grant_type`-on-429 and admin
  `rate_limit_exceeded` fixes.
- `docs/feature-matrix.md`: post-auth limiting flags (metrics unchanged —
  rejection metrics come free via `Checkpoint`).
- No new `Err*` codes (reuse `rate_limited`).

## ## Verification mapping

| Spec acceptance | Where it lands |
|---|---|
| A floods client bucket → 429 `rate_limited` + Retry-After; B (different client) → 200 | `interfaces/sso` unit test (extend existing `server_token_test.go`): two confidential clients, same IP |
| Unauthenticated/failed-auth requests consume no client bucket; byte-identical | unit test: bad-secret and no-credential requests bypass; plus the credential-gate table |
| `WithSubject` → `KeyBySubject` = `sub:<subject>`; empty → equals `KeyByClientIP` | `interfaces/ratelimit` unit test + sso hook test via `SetRequest` |
| Users A/B same NAT IP: A 429, B 200; no-token still 401 | `interfaces/sso` integration-style test + `test/` e2e |
| Existing `KeyByClientIP` behavior byte-identical | default-path unit tests unchanged; `make ci` |
| Two admin tokens independent buckets; invalid-token spray only IP-bounded, byte-identical 401s | `interfaces/admin` unit tests (extend existing) |
| Unconfigured admin byte-identical | unit test with no `SetPerAdminRateLimit` |
| Two admins shared exit IP e2e | `test/` (`package ssotest`), tier-1 sized above flood rate |
| Latency budget (Decision 9) | p99 checkpoint ≤ 5 µs (memory) / 100 µs (sqlite) / 2 ms (redis); deny add-on ≤ 1 ms | modeled-checkpoint benchmark numbers in Decision 9; existing `BenchmarkMemoryLimiterAllow*` gate covers ~94% of the cost; e2e flood completes at the configured tier-1 rate |
| Gates | `go build ./... && go vet ./...` after each edit; `go test -run 'TestMaintainability_|TestArchitecture_' .`; then `go test ./... -race`, `go test ./test/ -run TestE2E -v`, `make ci` |
