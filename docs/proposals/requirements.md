Requirements spec written to `docs/auto/interfaces-ratelimit-requirements.md`, scoped to 方向一 (post-auth, per-client/per-user bucketing) with exactly 3 evidence-backed improvements:

## 改进一：/token 认证后按客户端分桶限流
- **Problem**: The only safe pre-auth key is IP; `KeyByClientIDOrIP` is documented UNSAFE (attacker-controlled Basic username). The sole post-auth limiter (`WithGrantTypeRateLimit`) buckets by grant-type URN only — one abusive client starves all clients in that grant class, and its 429 returns `unsupported_grant_type` (contract drift vs `docs/error-codes.md:921` `rate_limited`).
- **Evidence**: `interfaces/ratelimit/middleware.go:57-71`, `interfaces/sso/server_routes.go:345-392`, `interfaces/sso/options_grants.go:113-143`, `interfaces/sso/server_token.go:363-377`.
- **Proposed**: second-stage limiter after `authenticateTokenClient`, keyed `client:<client_id>`, `rate_limited` + `Retry-After`.

## 改进二：/userinfo 认证后按用户分桶（KeyBySubject 生产接线）
- **Problem**: `KeyBySubject` has zero production wiring — grep confirms `middleware.WithSubject` has no caller in `interfaces/sso`/`cmd/sso-server`, so `SubjectFromContext` always returns `""` and the key degenerates to IP. No per-user scrape protection on `/userinfo`.
- **Evidence**: `interfaces/ratelimit/middleware.go:94-105` (fallback comment), `interfaces/middleware/context.go:13-26`, `interfaces/sso/server_userinfo.go:13-34` (subject never stored post-validation).
- **Proposed**: first production write of `WithSubject` at the bearer-validation point; phase-2 `/userinfo` rule keyed by `KeyBySubject` with IP fallback.

## 改进三：admin 认证后按管理员分桶（常量键串扰修复）
- **Problem**: `adminRateLimitKey = "admin"` — every admin (and unauthenticated token-sprayers) shares one bucket, enabling cross-admin DoS; `checkRateLimit` runs *before* `authenticateHTTP`, so per-admin keys are currently impossible.
- **Evidence**: `interfaces/admin/governance.go:275-280`, `interfaces/admin/middleware.go:83, 325-349` (rate limit at :330 precedes auth at :334; `claims.Subject` only at :349).
- **Proposed**: two-tier admin limiting — retained pre-auth IP bucket (oracle-safe) plus post-auth `admin:<subject>` bucket on the same SPI/PolicyStore.

Each improvement lists proposed behavior (including config/contract doc obligations per AGENTS.md §5.6) and an acceptance check; the spec ends with the total gate (`make ci`, `-race`, e2e, no new `interfaces/sso` files — it's at its 60-file ceiling). No Go code was touched, so no build gates were triggered.
