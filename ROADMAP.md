# ROADMAP

> 站在资深架构师 / PM 的视角，结合 2026-05 时点对当前 `github.com/snaplink/sso`
> 代码库的全局扫描，列出未来 1–2 个迭代中投入产出比最高的扩展方向。
>
> 每一项都包括：**Why now**（为什么这件事比别的事更值得做）、**Scope**
> （拆到可独立 PR 的粒度）、**Edge cases / 当前实现的具体短板**、
> **Sequencing hint**（与既有功能的耦合点和先后约束）。
>
> 排序按"如果只能挑一件先做"的优先级。

---

## 1. 横向扩展（Horizontal Scale）—— 把"多副本部署"从「能跑」修到「正确」

### Why now

这是 **正确性 Bug**，不是性能优化。今天 `defaultimpl/` 下的所有 OAuth 流
存储（`MemoryAuthCodeStore` / `MemoryRefreshTokenStore` / `MemoryPARStore` /
`MemoryDeviceCodeStore` / `MemorySession` / `MemoryClientStore`）**仅有进程内
后端**，SQLite 也只解决了 `User` / `AuthCode` / `RefreshToken` /
`DeviceCode` 四种，其余仍走 memory。`ratelimit/` 同样只有 `MemoryLimiter`。

后果：

- 副本 A 在 `/par` 颁发的 `request_uri`，用户的浏览器 302 被负载均衡器
  路由到副本 B 时，`Consume` 直接返回 `invalid_request_uri`。Authorization
  Code、Device Code、Refresh Token 同理。
- `MemoryClientStore` 是 DCR (RFC 7591) 注册结果的唯一落地点；任一副本
  重启或 LB 切换都会让"刚 register 完的客户端"立刻不存在。
- `MemoryLimiter` 在 N 个副本下实际容量被放大到 N 倍 burst，
  `/auth/login` 暴力破解防御被打穿。
- 多个副本之间的 `RefreshToken` 家族复用检测（OAuth Security BCP §4.13）
  失效——副本 A 颁发→副本 B 验证不到家族记录，攻击者可以在副本间「漂移」
  绕过家族吊销。

### Scope

| 工作项 | 落地点 |
|---|---|
| `defaultimpl/redis/` 后端，覆盖六个 Store（含 `RefreshTokenFamilyTracker` 扩展） | 新包 |
| `ratelimit/redis/` 分布式令牌桶（lua script + `EVALSHA`） | 新包 |
| 配置层面新增 `storage.backend: redis|sqlite|memory` 与统一 DSN | `config/config.go` |
| 跨副本 cache 失效（PAR/AuthCode 单次消费要求 atomic `DEL` + 返回旧值） | 使用 `GETDEL` (Redis 6.2+) 或 lua |
| `cmd/sso-server` 启动期连通性 readiness check | `WithReadyCheck("redis", ...)` |
| 文档：Pinner/sticky-session 不是必须的——但 JWKS 私钥仍要避免在副本间漂移（key rotation 协调） | AGENTS.md |

### Edge cases / 当前实现具体短板

- **单次消费的竞态**：现在 `MemoryAuthCodeStore.Consume` 用 mutex。
  分布式后端必须用 `GETDEL` 或 `MULTI/EXEC + WATCH`，否则两个副本同时
  收到 `/token` 重放都会成功。SQLite 后端已经用 `DELETE ... RETURNING`
  这条 invariant 必须迁移到 Redis 实现。
- **时钟漂移**：JWT 的 `exp`/`nbf` 验证现在用副本本地时钟，副本间漂移
  > 5s 会导致 PAR、code、refresh 的 TTL 行为不一致。建议引入 `WithClockSource`
  注入点，生产环境强制走 NTP，并把 `max_clock_skew` 提升到 config 顶层。
- **Family Tracker 的数据丢失语义**：Redis 持久化（AOF vs RDB）默认配置
  下家族表可能丢一秒级别——必须在文档明确「家族表必须 AOF=always 或者
  接受短窗口内 reuse detection 误判（fail-open 到 plain invalid_grant）」。
- **graceful shutdown**：现有 `cmd/sso-server` 没有等待 in-flight 请求
  退出再关闭 Redis client，重启会观察到 `EOF` 错误。需要在 main 加
  `errgroup` + signal hook。

### Sequencing hint

**最先做**。所有其他方向（DPoP token store、CIBA ping/poll、Admin UI 的
事件流）都建立在"Store 是分布式且强一致"这个前提上，先把地基补全。

---

## 2. 人类侧认证现代化（Passkeys + MFA + Upstream IdP 联邦 + SCIM 2.0）

### Why now

当前 7 个 `Authenticator` 全部是 **primitive**——password/phone/email/
temp_token 是面向人但只覆盖"知识因素"和"占有因素的低保证版本"；
keypair/apikey/certificate 是 service-to-service。**没有任何一个是
2026 年企业 SSO 选型清单上的必选项**：

- 没有 **WebAuthn / FIDO2 / Passkey** —— 微软、谷歌、苹果三家已经默认
  把 Passkey 推为消费者首选，企业 SSO 没有这个直接出不了 POC。
- 没有 **TOTP / HOTP**（RFC 6238 / 4226）—— Google Authenticator /
  1Password / Authy 几乎是 SaaS 的最低门槛 MFA。
- 没有 **上游 IdP 联邦**——客户问"我们能不能用 Google Workspace / Okta /
  Azure AD 登录"时只能回答"不行"。
- 没有 **SCIM 2.0**——HR / IT 自动 provisioning 是企业版的标配。
- 没有 **账户级锁定 + 泄漏密码检测**——`ratelimit` 只防 per-IP 撞库，
  攻击者用 botnet 轮换 IP 同样可以慢速暴力破解一个具体账户。

### Scope

**A. WebAuthn / Passkey Authenticator**

- `authenticators/webauthn.go` 新增。复用 `go-webauthn/webauthn` 库。
- 两条新路由：`POST /auth/webauthn/begin-registration`、
  `POST /auth/webauthn/finish-registration`、`/auth/webauthn/begin-login`、
  `/auth/webauthn/finish-login`。
- `Subject.Attributes` 上加 `webauthn_credentials` 数组的 persistence
  契约（建议把 credential 落 SQLite 单独的 `webauthn_credentials` 表，
  字段：`credential_id` / `public_key` / `sign_count` / `aaguid`）。

**B. TOTP MFA + Step-up Auth (RFC 9470)**

- `authenticators/totp.go` —— 注册期生成 secret 返回 otpauth:// URI，
  登录期校验 6 位 code。
- 新概念 `acr` (Authentication Context Class Reference) 和 `amr`
  (Authentication Methods References) 写到 ID Token / Access Token claims。
- `/token` 在 `RequireMFA` 决策下返回 RFC 9470 `insufficient_user_authentication`
  + `acr_values` challenge，客户端用 `acr_values` 参数重发 `/auth/login`
  触发二次因子。
- 与 `RiskScorer` 联动：`RequireMFA` 决策不再「视为 Allow」，而是真正
  挂上 step-up 挑战。

**C. 上游 IdP 联邦（OIDC RP-side + SAML 2.0）**

- 新包 `federation/`：`Provider` 接口（`AuthorizeURL` / `Exchange` /
  `UserInfo`），内置 `oidc`（Google / Microsoft / Okta / Auth0
  通用）和 `saml`（用 `crewjam/saml`）两种实现。
- 路由：`GET /auth/federated/:provider`（302 到上游）、`GET/POST
  /auth/federated/:provider/callback`（接回调，JIT 创建本地 user，
  落 `Subject.Attributes` 写入 `idp` / `idp_subject` / `email_verified`
  等 claim）。
- per-tenant policy：`Tenant.Settings["federation"]` 决定可见的 IdP
  列表 + 强制策略（"@acme.com 强制走 Okta"）。

**D. SCIM 2.0 (RFC 7644)**

- 新包 `scim/`，挂在 `/scim/v2/Users` + `/scim/v2/Groups`。
- Bearer auth 用与 admin 同源的 token，gated by `scim:write` permission。
- 走现有 `UserProvider` + `permissions.Provider` 接口，不引入新存储。
- 关键的两个动作：HR 系统 push `PATCH /Users/{id}` 改状态触发 session 吊销；
  `DELETE /Users/{id}` 调用 `RefreshTokenSubjectIndex.DeleteBySubject`。

**E. 账户级防御**

- 新接口 `sso.AccountLockoutPolicy`，由 `handle_login` 在
  authenticator 返回前调用。默认实现 `MemoryAccountLockout`（5 次失败
  锁 15 分钟），生产替换 Redis backend。
- 密码 verifier 接入 HIBP k-anonymity API（可选，per-client policy）。
- 错误响应统一时长（fixed-window equalization），消除"账户存在 vs
  不存在"的 timing oracle。

### Edge cases / 当前实现具体短板

- 现在 `Subject.Attributes` 是 `map[string]string`——存
  WebAuthn credential 的 byte slice 必须 base64 编码，建议升级到
  `map[string]any` 或者把这些扩展属性挪到独立的 Attribute store。
- `acr`/`amr` claim 当前完全没有写到 `Ed25519JWTIssuer`——加上之后
  会引入和老客户端的兼容性问题，需要在 `Client.AcceptedACRs` 上
  做向后兼容标志。
- 联邦回调路径下 `RiskScorer.Score` 拿不到原始密码——`RiskRequest`
  字段必须改为可空，下游 scorer 不能假定永远有 password hash。
- SCIM 删除是危险动作：`HR 误删 user` → 全员 session 吊销。建议
  默认走 soft-delete（用 `User.Status="archived"`），90 天后真正
  调用 `DeleteBySubject`。

### Sequencing hint

WebAuthn + TOTP 是 SaaS 销售 demo 的硬需求，**第一波**先做。联邦和
SCIM 是企业版定价的分水岭，**第二波**。账户锁定可以并行于第一波，
代码量小。

---

## 3. 持有证明令牌（Sender-Constrained Tokens）—— DPoP + mTLS + RFC 9068

### Why now

今天颁发的 access_token 全部是 **bearer 语义**：偷到就能用。这在三个
场景下都是阻塞项：

1. **FAPI 2.0 / Open Banking / 金融监管**：合规线明确要求 sender-
   constrained。
2. **B2B 集成**：客户的 SOC 2 / ISO 27001 审计员开始把"token 是否绑定
   持有者"列入清单。
3. **零信任内网**：服务网格的 sidecar 已经在做 mTLS，把它复用到 token
   绑定可以一次性消除"中间服务偷 token 调下游"的横向移动风险。

同时还有一个 **资产清理**：现在 `Ed25519JWTIssuer` 输出的 JWT 不带
`typ: at+jwt`（RFC 9068），resource server 严格按规范实现时会拒绝；
也没有标准化的 `client_id` / `scope` claim。补 9068 同时把 DPoP 的
`cnf.jkt` claim 一起加进去最经济。

### Scope

**A. RFC 9068 JWT Access Token Profile（先做）**

- `Ed25519JWTIssuer.Issue` 输出 header 加 `typ: at+jwt`、claims 加
  `client_id`、`scope`、`auth_time`、`acr`、`amr`、`jti`。
- `Validate` 严格化：`typ` 必须匹配，`aud` 必须命中本服务声明的
  resource，签名算法 allowlist（防止 alg=none / RS256-as-Ed25519
  混淆）。
- 增加 `WithSupportedSigningAlgs([]string{"EdDSA"})` 选项，把允许
  算法显式声明出来；当前 `oidc-discovery` 是从 issuer 反推的，必须
  锁紧。

**B. RFC 9449 DPoP（核心）**

- 新中间件 `sso.DPoPMiddleware`，在 `/token`、`/userinfo`、`/introspect`
  路径上识别 `DPoP` header（一个 JWT，header `typ: dpop+jwt`，
  claims `htu` / `htm` / `iat` / `jti` / `ath`）。
- 颁发期：如果 `/token` 请求带 `DPoP` header，把 `jkt`（DPoP key 的
  SHA-256 thumbprint）写入 access_token 的 `cnf.jkt` claim。
- 验证期：resource server 调用 `/introspect` 时，比对 `DPoP` JWT 的
  `jkt` 与令牌中 `cnf.jkt` 必须相等。
- `jti` 防重放：进程内 LRU + Redis 后端的双层缓存，窗口 5 分钟。

**C. RFC 8705 mTLS Client Auth + Certificate-Bound Tokens**

- 复用现有 `authenticators/certificate.go` 的 root pool。
- `/token` 在 TLS 层拿到 client cert 后：
  - **mTLS client auth**：替代 client_secret，对应
    `token_endpoint_auth_method=tls_client_auth`。
  - **Certificate-bound access tokens**：把 cert 的 SHA-256
    thumbprint 写入 `cnf.x5t#S256`。
- 与 DPoP 互斥——同一 token 上 `cnf.jkt` 和 `cnf.x5t#S256` 不能同时
  存在；client 注册时声明 binding 类型。

### Edge cases / 当前实现具体短板

- `Ed25519JWTIssuer.aud` 已经修过 string-or-array 解析，但 `Validate`
  的 audience 匹配现在是 **接受任何一个 aud 成员匹配 issuer**——
  在 multi-resource token（RFC 8707 已经支持）下这是"水平越权"
  风险：A 服务收到本该给 B 的 token 也会接受。必须改为「resource
  server 配置自己的 aud，验证时必须包含」。
- DPoP `jti` 防重放需要分布式（见方向 1），否则副本切换后重放成功。
- `htu` 校验要兼容 reverse proxy 改写——`X-Forwarded-Proto/Host`
  的信任问题已经在 `oidc_discovery.go` 留过 note，DPoP 这里要把同一
  套提取器复用。
- mTLS 在 OpenResty 边缘终止时（`deploy/openresty/`），cert 需要
  通过 `X-SSL-Client-Cert` header 传给上游 Go——这是一条新的 trust
  contract，必须在 deployment 文档明确"只在私网 listener 接受这个
  header"。

### Sequencing hint

先做 9068（4 小时工作量，零破坏性升级），再做 DPoP（一两个 sprint，
有相当的协议细节），mTLS 留到客户真的提需求再做（涉及部署架构，
不是纯代码工作）。

---

## 4. OAuth 2.1 / FAPI 安全 Profile 收口 + 现代 OIDC 缺失能力

### Why now

当前 OAuth/OIDC 覆盖度很广（auth_code/refresh/device/token-exchange/
PAR/DCR/DCM/introspect/revoke 都有），但**安全 profile 没有收口**。
以下 3 类问题落在「单点改动小、组合起来防御一类完整攻击」的甜点上：

1. **Mix-up attack 防御**：客户端配置了多个 IdP 时（见方向 2），不带
   `iss` 响应参数（RFC 9207）会被攻击者诱骗到错误 IdP。
2. **Authorization Request 完整性**：`/auth/login` 的查询参数今天
   是明文 + URL，受 referer 泄漏和中间人篡改影响；JAR (RFC 9101)
   把整个请求打包成签名 JWT 是行业标准答案。
3. **隐式流（implicit flow）必须停用**：现在 `response_type=token`
   仍然在 `handleLogin` 接受——OAuth 2.1 明确 deprecate，FAPI 直接
   拒绝。

### Scope

| 工作项 | 大致工作量 | 标准 |
|---|---|---|
| 在 `/auth/login` 和 `/auth/callback` 响应 + AuthCode 回调 URL 上加 `iss` 参数 | XS | RFC 9207 |
| `authorization_response_iss_parameter_supported: true` 写入 discovery doc | XS | RFC 9207 |
| 接受 `request` 参数（JWT-wrapped 请求）和 `request_uri`（PAR 已支持）→ 把 JAR 落实 | M | RFC 9101 |
| 接受 `authorization_details` 参数（RFC 9396 RAR）→ 落到 AuthCode + AccessToken claim | M | RFC 9396 |
| 引入 `oauth_compliance: oauth_2_1 | fapi_2` 配置开关，开启后强制：`require_pkce=true` 全局生效、`response_type=token` 返回 `unsupported_response_type`、redirect_uri 必须 exact match + https + 不能含 fragment | S | OAuth 2.1 draft + FAPI 2 |
| `POST /backchannel-authentication` (CIBA) — 长轮询 / push 通知模式的认证 | L | OIDC CIBA |
| OIDC Back-Channel Logout — 服务端通知 RP 注销 | M | OIDC BCL 1.0 |
| OIDC Front-Channel Logout — iframe 通知 RP 注销 | S | OIDC FCL 1.0 |

### Edge cases / 当前实现具体短板

- `oidc_discovery.go` 的 `requestBaseURL` 已经吃 XFF 第一跳——在
  internet-facing 没有受信代理时这是 **scheme/host spoof** 风险
  （AGENTS.md 已 noted）。在做 JAR 之前必须先收紧：要么改默认行为
  为 r.Host-only，要么提供 `WithTrustedProxies(CIDR...)` allowlist。
- `response_type=token` 的 implicit 流今天通过 `direct_mint` 路径
  返回 token。废弃后所有现存集成在 OAuth 2.1 模式下会突然失败——
  必须先发 deprecation warning 给所有客户端 6+ 个月。
- Back-Channel Logout 要求服务端能主动 POST 到每个 RP 的
  `backchannel_logout_uri`——这是一个新出站方向，需要：
  (1) `WithLogoutNotifier`(HTTP client + timeout) 接口；
  (2) audit `logout_notified` 事件；
  (3) 失败重试策略（与 webhook sink 同源）。
- CIBA 的 ping 模式要求 client 暴露 `client_notification_endpoint`——
  client_credentials TLS 双向认证是默认假设，需要复用方向 3 的 mTLS。

### Sequencing hint

`iss` 参数 + discovery（**今天就能做完**）→ deprecate implicit flow
flag（一个 sprint）→ JAR / RAR（顺手）→ BCL/FCL（一个 sprint）→
CIBA（独立 sprint，依赖方向 3 的 mTLS）。

---

## 5. 运维 & 合规面：Admin Web Console + 用户自助 + GDPR/审计闭环

### Why now

当前管理面只有 gRPC + REST + （未来）SCIM。**面向人的操作面是
空白**：

- **运营**：客户公司 IT 想看"过去 24 小时谁登录失败、从哪个国家、
  是哪个 client" → 现在只能 `GET /api/v1/audit/events` 然后自己
  写脚本筛选。
- **终端用户**：想看"我的活跃会话有哪些设备、能不能注销"
  → 没有 UI，只有 `POST /token/revoke-all`。
- **合规**：GDPR Article 15 / 17 / 20（访问、删除、可移植）请求
  到来时，没有标准化的导出/删除流水线。`audit_handler.go` 也不做
  PII 红 acted——用户邮箱、IP 全部裸存。

这件事的 ROI 在于：**把已经写好的能力包装出来卖**。底层接口都在，
缺一层产品化。

### Scope

**A. Admin Web Console（独立 SPA，部署在 release 包里）**

- 新 repo 或 monorepo 子目录 `web/admin/`，建议 Next.js + shadcn/ui。
- 通过既有 admin REST gateway 调用，不引入新后端能力。
- 首批面板：
  1. **Dashboard** —— 登录成功率 / TPS / 错误率（直接消费 Prometheus
     metrics + audit events）。
  2. **Clients** —— CRUD + rotate secret + 可视化 redirect_uris
     allowlist。
  3. **Users / Roles / Menus** —— 树状选择器，复用 `permissions.MenuLister`。
  4. **Audit Explorer** —— 全文检索 + 按 (tenant, country, outcome,
     reason) facet 过滤；点 trace_id 跳 Grafana Tempo / Jaeger。
  5. **Sessions / Tokens** —— 列出活跃会话、按用户/客户端筛选、
     一键吊销整族（已有 `/token/revoke-all`）。
  6. **Releases** —— pin / rollback 按钮，挂 `/api/v1/admin/releases`。

**B. 终端用户自助门户**

- 同一 SPA 框架不同登录角色：`/me` 路由。
- 功能：查看活跃 sessions、登出某设备、改密码、绑定 Passkey/TOTP
  （依赖方向 2）、查看登录历史、下载我的数据（GDPR Article 20）。

**C. GDPR / 合规流水线**

- `POST /api/v1/admin/users/:id:export` —— 调用所有 Provider 的
  optional `Exporter` 扩展，打包 ZIP 返回（含 user / sessions /
  audit events / refresh tokens / permission assignments）。
- `POST /api/v1/admin/users/:id:erase` —— 触发 right-to-be-forgotten
  workflow：吊销所有 token → soft-delete user → schedule 30 天后
  audit 事件 pseudonymization（保留 trace 但替换 PII 为 hash）。
- 新模块 `audit/redactor/` —— 通过函数 `Redact(*Event) *Event` 在
  落 Sink 前对 `Email` / `Phone` / `IP` 做可配置的脱敏（hash /
  truncate / drop）。
- 审计哈希链外部锚定：每天定时任务把 `audit/chainer.go` 的 head
  hash 发布到 S3 + 写入区块链（可选）；防御「攻击者改最后一条事件」
  这个文档中已经提到的盲点。

**D. 异常检测信号通路**

- 新接口 `sso.AnomalyDetector`（与 `RiskScorer` 平行），在登录
  **成功后** 异步评估，输出 alert 到 audit + webhook。
- 内置检测器：
  - **Impossible travel**：基于现有 `geo.GeoInfo`，相邻成功登录
    跨度 > 物理可达。
  - **Velocity**：同一账户/IP 在窗口内成功登录次数 > 阈值。
  - **New device / new country**：相对历史基线。
- 这条与方向 2 的账户锁定共用一份事件流，但分工不同：lockout 在
  请求路径上 fail-closed，detector 在请求外 fail-open + 告警。

### Edge cases / 当前实现具体短板

- Audit Explorer 在 SQLite 后端走 `LIKE` 会很慢——必须先给
  `audit/` 加 SQLite 后端 + FTS5 索引，或者直接接 ClickHouse /
  OpenSearch 作为可选 sink。
- 用户自助"修改密码"会触发 **所有 session 吊销** 还是 **仅当前
  session 吊销**？需要在 `Client` 上加 policy 字段，默认前者
  （安全），允许 opt out 后者（体验）。
- GDPR erase 与 audit hash chain 冲突——擦除事件会断链。
  解决方案：擦除时不删事件，只把 PII 字段替换为常量 `[REDACTED]`，
  hash 仍可校验（因为内容确实变了，但链路一致性"事件 X 在时间 T
  存在过"得以保留）。这套语义必须写进 docs/error-codes.md 同源
  的合规手册。
- Admin UI 与后端 release 步调：UI 是前端 bundle，需要走方向 §6f
  的 `releases/pinner/static`——这一脚已经踩好，前端只是消费者。

### Sequencing hint

E2E 上看：Admin Console 是最大的"产品差异化杠杆"，但需要前端
工时；Audit Redaction 和 GDPR 接口可以**先行**（纯后端，1 个 sprint），
为后续合规销售铺路。异常检测可以作为 Risk Scorer 的"对偶模块"
随时并行加。

---

## 优先级摘要

| # | 方向 | 类型 | 阻塞下游 | 建议先后 |
|---|---|---|---|---|
| 1 | 横向扩展（Redis 等分布式后端） | **正确性 Bug** | 几乎所有其他方向 | **P0，立刻** |
| 2 | Passkeys/MFA/上游 IdP/SCIM | 产品差异化 | 销售 demo | P1，第一波 |
| 3 | DPoP + mTLS + RFC 9068 | 安全合规 | FAPI 客户 | P1，与 §2 并行 |
| 4 | OAuth 2.1 / FAPI Profile 收口 | 安全合规 | §2 联邦后必要 | P2，§2 落地后跟进 |
| 5 | Admin Console + GDPR + 异常检测 | 产品化 / 合规 | 企业版定价 | P2，前后端并行 |

---

## 未列入但已经考虑过的方向（明确不在 90% 完成度路径上）

- **HSM / KMS 集成签名密钥**：现在 `Ed25519JWTIssuer` 是软件签名，
  生产可以用 cloud KMS 签名服务但接入面较小，等真有客户提需求再加
  `SigningKeyProvider` 抽象层。
- **跨区域 active-active**：依赖方向 §1 完成，且 etcd → 跨区
  raft 是一个独立的容量规划课题，不属于 SDK 范畴。
- **CLI 工具 `ssoctl`**：admin REST 已经覆盖功能面；CLI 是体验改进
  不是能力扩展，留到 v2。
- **多算法 JWT（RS256 / ES256 / EdDSA 并存）**：今天只有 EdDSA。
  扩展到 RS256/ES256 是市场兼容性 nice-to-have，但每加一种算法
  就多一份算法混淆风险——除非有客户硬性要求，建议守住 EdDSA only
  + 严格的 `alg` allowlist。
- **GraphQL admin API**：REST gateway 已经从 proto 自动生成，再多
  一层 GraphQL 是维护成本，没有清晰需求场景。
