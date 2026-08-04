# Requirements Spec: interfaces/ratelimit — 方向一（认证后限流）

> Source: [interfaces-ratelimit-analysis.md](interfaces-ratelimit-analysis.md) 方向一：
> "补齐'认证后'限流——按客户端/按用户分桶的安全落点（第二阶段限流）"。
> 范围仅限认证后（post-auth）按客户端/按用户分桶的安全落点及其 admin 串扰修复。
> 显式不在范围：方向二（X-RateLimit-* 剩余额度可见性）、方向三（五套限流实现收敛/SPI 下沉 shared）。
>
> 架构边界：`domains/` 与 `protocols/` 不得 import `interfaces/ratelimit`
> （DIRECTORY_MAP 分层），本规格全部改动停留在 `interfaces/` + 配置 + 文档。
> `interfaces/sso` 已到 60 文件上限：只扩展现有文件（如 `options_grants.go`、
> `server_token.go`），不新增文件。契约同步义务（AGENTS.md §5.6）：新配置项 →
> `docs/config-reference.md`；429 语义变更 → `docs/error-codes.md`。

## 改进一：/token 认证后按客户端分桶限流（client-keyed phase-2 limiter）

**问题**：标准中间件链运行在认证之前（`interfaces/sso/server_routes.go` 的
`buildMiddlewareChain`：trustedProxies → ratelimit → degradation → bodylimit → router），
因此整条链上唯一安全的键只有 IP。`KeyByClientIDOrIP`
（`interfaces/ratelimit/middleware.go:57-71`）被文档明确标注 UNSAFE：HTTP Basic
用户名是攻击者可控输入，逐请求轮换用户名即可无限开新桶逃逸全部节流。现有唯一的
认证后 `/token` 限流 `WithGrantTypeRateLimit`（`options_grants.go`）只按 grant type
URN 分桶、不按 client：一个滥用客户端即可耗尽整个 `client_credentials` 桶，
同 grant 类的合法客户端互相饿死；且其拒绝路径返回 **429 + `unsupported_grant_type`
错误码、无 Retry-After**，与 `docs/error-codes.md:921` 的 `rate_limited` 稳定契约
直接冲突（客户端会误判为自己的 grant_type 非法）。

**证据**：
- `interfaces/ratelimit/middleware.go:57-71` — `KeyByClientIDOrIP` 的 UNSAFE 文档
  （"unverified, attacker-chosen input"、"per-client bucket can only be keyed SAFELY
  on an AUTHENTICATED client, which is a post-auth concern this pre-auth middleware
  cannot satisfy"）。
- `interfaces/sso/server_routes.go:345-392` — `buildMiddlewareChain`：ratelimit 位于
  router 之外、认证之前；`SetRateLimitPolicy`/`DynamicMiddleware` 只热换这一段。
- `interfaces/sso/options_grants.go:113-143` — `rateLimiterEntry` 持有裸
  `*rate.Limiter`，`WithGrantTypeRateLimit(grantType, ...)` 仅按 grant type URN 分桶。
- `interfaces/sso/server_token.go:363-377` — `checkGrantRateLimit` 调
  `entry.limiter.Allow()`（无键），拒绝时 `errorBody(ctx, ErrUnsupportedGrantType)`。
- `docs/error-codes.md:921` — `rate_limited` 429 契约（"SPAs branch on this string"）。

**提议行为**：
1. 新增 opt-in 配置 `sso.WithTokenEndpointClientRateLimit(perSec, burst)`（落到
   `options_grants.go`，接受 `ratelimit.Limiter` 以便接 Redis 跨副本后端；`security.*`
   配置节按既有 SIGHUP 热更路径接入）。
2. 在 `server_token.go` 的 `handleToken` 中，`authenticateTokenClient` 成功后
   （client 身份已验证）再查第二阶段 limiter，键为 `client:<client_id>`；未认证请求
   不触碰该桶（认证失败仍只受第一阶段 IP 限流，保持 oracle 安全）。
3. 拒绝响应统一为 `rate_limited` 错误码 + `Retry-After`（修正现有 grant 限流
   `ErrUnsupportedGrantType` 漂移），沿用 `writeTooManyRequests` 的形状。
4. 文档同步：`docs/config-reference.md` 新配置节、`docs/error-codes.md` 补充
   phase-2 来源说明。

**验收检查**：
- 单元测试（`interfaces/sso` 扩展现有测试文件）：同 IP 下客户端 A 灌满
  client_credentials 桶 → 429 且 body 为 `rate_limited`、带 `Retry-After`；
  客户端 B（不同 client_id）仍 200。
- 未认证/认证失败请求不消耗任何 client 桶（仅 IP 桶），响应与无该功能时字节一致。
- `test/`（`package ssotest`）e2e：两客户端共享 NAT IP 场景覆盖；`go test ./test/ -run TestE2E -v`。
- `go build ./... && go vet ./... && go test -run 'TestMaintainability_|TestArchitecture_' .` 与 `make ci` 全绿。

## 改进二：/userinfo 认证后按用户分桶限流（KeyBySubject 的生产接线）

**问题**：`KeyBySubject` 已实现但**全库无生产接线**：`interfaces/middleware/context.go`
的 `WithSubject` 在 SSO 服务器路径上没有任何调用方（grep 全库仅定义本身、`KeyBySubject`
消费方，以及 `interfaces/ssoclient/dev/auth.go` 中同名的无关符号），因此
`SubjectFromContext` 恒返回空串，`KeyBySubject` 退化为 `KeyByClientIP`
（`middleware.go:105` 的 fallback 注释自述 "middleware ran before auth"）。后果双向
失效：共享 NAT IP 下，一个爬取 `/userinfo` 的用户耗尽整桶额度连累同 IP 所有用户；
分布在不同 IP 上的攻击者又完全绕开按 IP 的桶。`/userinfo` 是 OIDC §5.3 的
per-user 资源端点，正是按用户分桶的典型落点，目前无任何防护。

**证据**：
- `interfaces/ratelimit/middleware.go:94-105` — `KeyBySubject` 的 fallback 注释。
- 全库 grep：`middleware.WithSubject` 在 `interfaces/sso`、`cmd/sso-server` 无任何
  调用点（`options_security.go:145` 的 `WithSubjectClientIndex` 是无关符号）。
- `interfaces/middleware/context.go:13-26` — `WithSubject`/`SubjectFromContext` 已就绪，
  只缺写入方。
- `interfaces/sso/server_userinfo.go:13-34` — `handleUserInfo` 委托
  `oidc.HandleUserInfo`，bearer 在 handler 内校验（`server_userinfo.go:134` 一带），
  校验后的 subject 从未写入请求 context。

**提议行为**：
1. 在 `/userinfo`（及 mesh ext_authz 变体）的 bearer 校验通过点，用
   `middleware.WithSubject(ctx, sub)` 把已验证 subject 写入请求 context——
   这是 `WithSubject` 的首个生产写入方，`KeyBySubject` 随即可用。
2. 在 router 内、认证之后挂载第二阶段限流：`/userinfo` 前缀规则使用
   `KeyBySubject`（键 `sub:<subject>`），未认证请求自动回落 IP 键（身份保持：
   缺失 token 仍 401 由原 handler 处理，限流只作用于已认证的合法请求流）。
3. 可配置化：新增 `security.rate_limit` 的 post-auth 段（或等价
   `sso.WithUserInfoRateLimit(limiter)`），沿用 `PolicyStore` 热更；拒绝走标准
   `rate_limited` 429 + `Retry-After`。
4. 文档同步：`docs/config-reference.md`、`docs/error-codes.md`。

**验收检查**：
- 单元测试：`WithSubject` 后 `KeyBySubject` 返回 `sub:<subject>`；无 subject 时返回
  与 `KeyByClientIP` 相同的值。
- 集成测试：同一 NAT IP 下用户 A 爬取 `/userinfo` 触发 429（`rate_limited` +
  `Retry-After`），用户 B 同端点仍 200；无 token 请求不受用户桶影响（仍 401）。
- 既有 `KeyByClientIP` 行为字节不变（默认路径无回归）；`make ci` 全绿。

## 改进三：admin 接口认证后按管理员分桶（修复 adminRateLimitKey 常量键串扰）

**问题**：admin 限流使用常量键 `admin`（`interfaces/admin/governance.go:275-280`
`adminRateLimitKey`），且在认证**之前**执行（`interfaces/admin/middleware.go:330`
`checkRateLimit` 先于 `:334` 的 `authenticateHTTP`）——所有管理员共享**一个**桶：
任一管理员（或被攻陷的管理员 token）即可耗尽全管理员共享额度，管理员间互相 DoS；
未认证攻击者用无效 token 喷洒 `/api/v1/admin` 同样消耗该共享桶（无效 token 的 401
是恒定输出，喷洒成本低）。`claims.Subject`/`clientID` 直到认证之后（
`middleware.go:349` `withActor`）才可得，常量键是"认证前限流"约束的产物，而非设计选择。

**证据**：
- `interfaces/admin/governance.go:275-280` — `adminRateLimitKey = "admin"` 常量及注释
  （"every admin request shares ONE bucket"）。
- `interfaces/admin/middleware.go:83` — 字段注释 "gates the admin surface as one
  shared bucket (adminRateLimitKey)"。
- `interfaces/admin/middleware.go:325-349` — `HTTPMiddleware` 顺序：
  `checkIPPolicy` → `checkRateLimit`（:330）→ `checkDestructiveConfirm` →
  `authenticateHTTP`（:334）→ `withActor(r.Context(), claims.Subject, clientID)`（:349）。

**提议行为**：
1. 两级 admin 限流：(a) 保留认证前粗粒度 IP 桶（未认证喷洒的不可逃逸上界，
   维持 401 oracle 安全与现有常量键语义兼容的默认值）；(b) 在 `authenticateHTTP`
   成功之后新增认证后按管理员桶，键 `admin:<claims.Subject>`（可选叠加
   `client:<clientID>`），经 `SetPerAdminRateLimit(perSec, burst)` 或
   `SetRateLimitPolicyStore` 变体配置。
2. 两级均走同一 `ratelimit.Limiter` SPI 与 `PolicyStore` 热更；拒绝统一
   `rate_limited` 429 + `Retry-After`。认证后桶只在持有有效 token 时可达，
   响应形状对"合法 token 超限"恒定，不新增认证状态 oracle。
3. 文档同步：`docs/config-reference.md`（admin rate_limit 新键）、
   `docs/error-codes.md`（来源行补充 admin per-admin 场景）。

**验收检查**：
- 单元测试（`interfaces/admin` 扩展现有测试）：两个有效 admin token 各自独立桶——
  管理员 A 灌满后返回 429，管理员 B 同端点仍 200；无效 token 喷洒只受认证前 IP 桶
  约束，且响应与未开启 per-admin 功能时字节一致（无 oracle）。
- 未配置 per-admin 时行为与现状字节一致（默认兼容，`adminRateLimitKey` 语义保留）。
- `test/` e2e：两管理员共享出口 IP 场景；`make ci` 全绿。

---

## 总体验收门

1. 每项改动后即时执行 `go build ./... && go vet ./...` 与
   `go test -run 'TestMaintainability_|TestArchitecture_' .`（AGENTS.md §2）。
2. 交接前：`go test ./... -race`、`go test ./test/ -run TestE2E -v`、`make ci`。
3. 契约同步三件套随改动提交：`docs/config-reference.md`、`docs/error-codes.md`、
   `docs/feature-matrix.md`（如涉及可观测性开关）。
4. 不新增 `interfaces/sso` 文件（60 文件上限）；不触碰方向二/方向三范围；
   无 emoji、无 deferred-refactor TODO。
