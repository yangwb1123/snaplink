Design doc written to `docs/auto/interfaces-ratelimit-design.md`. All claims verified against the code before writing. Summary of the decisions:

## Decisions (one `##` heading each)

**1. Shared post-auth checkpoint mechanism** — `interfaces/ratelimit` gains two exports: `Checkpoint(store, r)` (programmatic evaluation of a `PolicyStore` without writing, reusing `Policy.Key`, prefix rules, and the rejection metric) and `TooManyRequests(w, retry)` (exported form of the existing `writeTooManyRequests`). This keeps the `rate_limited` wire shape in one place and gives hot-reload + metrics to all three surfaces for free, with no layering violation.

**2. Identity lands in the request context** — `core.HandlerContext` gains additive `SetRequest(r)`; `interfaces/middleware` gains `WithClientID`/`ClientIDFromContext` (twin of the dead `WithSubject`); `ratelimit` gains `KeyByClientID` (mirror of `KeyBySubject`). This is the spec's mandated "first production write of `WithSubject`".

**3. 改进一 `/token`** — `WithTokenEndpointClientRateLimit(limiter)` + `SetTokenEndpointClientRateLimit` (SIGHUP), checkpointed right after `authenticateTokenClient`, before residency. **One refinement over the spec's letter**: the `client:<id>` key is written only for credential-verified clients (secret/assertion/mTLS) — public clients authenticate with a publicly-known `client_id`, so keying their bucket on it would *create* a new DoS vector (the same flaw class as UNSAFE `KeyByClientIDOrIP`); they fall back to IP. Grant limiter migrates `*rate.Limiter` → `ratelimit.Limiter` to fix the `unsupported_grant_type`-on-429 drift.

**4. 改进二 `/userinfo`** — because `protocols/oidc` can't import `interfaces/*`, two new `UserInfoDeps` hooks (`StoreUserInfoSubject`, `UserInfoRateLimited`) are called between bearer validation and the residency gate, mirroring the `MaybeSignUserInfo` precedent. A router-level capture-middleware alternative is rejected (double signature verification on the scrape path + 401-challenge drift risk). Mesh ext_authz uses the same store after `MeshAuthorize`. Key = `claims.Subject`, not the resolved local ID (the lookup is what we're protecting).

**5. 改进三 admin** — two tiers as one opt-in unit: unconfigured = byte-identical (constant `"admin"` key, `rate_limit_exceeded` body); configured = tier-1 rekeyed per-IP (required, or A's flood exhausts the global bucket before tier-2 can protect B) + tier-2 `admin:<subject>` right after `authenticateHTTP`, before the idle-timeout check (constant 429 shape, no new oracle). Both tiers reject with standard `rate_limited`.

**6. Config/SIGHUP** — `security.rate_limit.token_client.*`, `security.rate_limit.userinfo.*` (shared backend dispatch, one new reload hook called once per Reload), `admin.rate_limit.per_admin.*` (boot + runtime `PolicyStore` swap, matching the existing admin lifecycle).

**7. Storage** — no new state; existing `Limiter` SPI (Memory 16-shard/10-min-prune, SQLite, Redis), cardinality naturally bounded by registered clients/subjects/admins.

**8. Failure modes + What could break** — the honest list: `SetRequest` ripple, public-client spoof, the `"client:"` namespace collision if an operator shares an instance across phases (hard documented invariant), the two deliberate 429 wire changes, admin tier-1 rekeying being load-bearing (and the e2e rate-sizing constraint), hot-reload hook wiring, and the 60-file/50-line budget ceilings. One spec ambiguity is resolved explicitly: the admin body unification is scoped to the opted-in mode, since unconditional unification would fail the "byte-identical default" acceptance.

No Go code was touched; per the requirements spec, no gates were triggered.
