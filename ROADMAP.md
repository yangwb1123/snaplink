# ROADMAP

> 基于 2026-05 时点对 `github.com/snaplink/sso` 的全局扫描，从资深架构师 / PM
> 的视角列出下一阶段投入产出比最高的 5 个扩展方向。
>
> 每项包含 **Why now**（这件事为什么比别的事更值得做）、**Scope**
> （拆到可独立 PR 的颗粒度）、**Edge cases / 当前实现具体短板**、
> **Sequencing hint**（与既有功能的耦合点）。
>
> 排序按"如果只能挑一件先做"的优先级。文末附 **边界情况 & 性能优化**
> 清单，记录够不上独立方向但需要持续跟进的小颗粒。

---

## 现状自检

过去几个季度 OAuth/OIDC 协议覆盖度已经做到 2026 年同类产品 P95 水平：

- 完整 grant 集（auth_code / refresh / client_credentials / device /
  token-exchange + RAR）+ PAR + DCR/DCM + Introspect + Revoke。
- 现代安全 profile：DPoP、mTLS 持有证明、RFC 9068 at+jwt、JAR
  （inline + URL fetch）、`private_key_jwt`、`prompt=none` 静默续期、
  `iss` 响应参数（RFC 9207）、step-up 挑战（RFC 9470）、Form Post
  Response Mode、OAuth 2.1 严格模式。
- 端到端会话：BCL（多 RP 扇出）+ FCL + `sid` claim + 跨发行器吊销。
- 8 种 authenticator（含 TOTP RFC 6238）+ 账户级锁定 + risk
  scorer 钩子。
- 运维面：snapshot 导出/恢复、release pin/rollback、bootstrap
  builtin 步骤 + 分布式锁、admin REST + gRPC、netpolicy、tenant、
  geo、permissions（含菜单）、audit 哈希链 + PII redactor。
- HTTP 资源面：RFC 6749 §5.1 no-store、RFC 6750 §3 WWW-Authenticate
  challenge 全面落地。

**剩下的不再是"补协议"**，而是把这套发动机：**修到多副本正确 → 把
2026 年的认证因子补全 → 把密钥治理升级 → 把面向人的操作面 / 合规
做完 → 把最后一批协议补完位收口**。下面 5 个方向按这个顺序排。

---

## 1. 把"多副本部署"从「能跑」修到「正确」

### Why now

这是 **正确性 Bug**，不是性能优化。SQLite 后端已经覆盖 User /
AuthCode / RefreshToken（含 FamilyTracker）/ DeviceCode / Client
五种，但 **PARStore、SessionManager、RateLimiter、JTIReplayStore、
SubjectClientIndex、AccountLockout 六个 SPI 仍然只有 memory 实现**。
任何一个在多副本下都会出 bug：

| 缺失分布式后端 | 多副本下的具体故障 |
|---|---|
| `PARStore` | 副本 A 颁发 `request_uri` 后浏览器 302 被 LB 路由到副本 B → `Consume` 返回 `invalid_request_uri`，PAR 流彻底走不通 |
| `SessionManager` | `prompt=none` 静默续期、BCL 的 `sid` 绑定、`/end_session` 都依赖；副本切换 = 用户被强制重新登录 |
| `RateLimiter` | N 副本下 `default_per_sec` 实际容量被放大 N 倍，`/auth/login` 暴力破解防御被打穿 |
| `JTIReplayStore` | DPoP / JAR / `client_assertion` / token-exchange `actor_token` 的重放检测全部副本本地，攻击者在副本之间漂移即可重放 |
| `SubjectClientIndex` | BCL 多 RP 扇出索引落在颁发 token 那个副本上；另一台副本上的 `/end_session` 看不见，相当于单 SSO 失效 |
| `AccountLockout` | 滑窗失败计数器只在登录命中的那个副本累加，攻击者从不同副本视角各试 5 次 = 总共试 5N 次 |

### Scope

| 工作项 | 落地点 |
|---|---|
| `defaultimpl/redis/` 后端，覆盖上表六个 SPI（PARStore 用 `SET NX PX` + `GETDEL` 保证单次消费；SessionManager 走 hash + TTL；RateLimiter 用 lua script 实现令牌桶；JTIReplay 用 `SET NX PX exp`；SubjectClientIndex 用 set + sub-key TTL；AccountLockout 用 sorted set 滑窗） | 新包 |
| 配置层 `storage.backend: redis \| sqlite \| memory` + 统一 DSN，按 SPI 分别 override | `config/config.go` |
| `WithReadyCheck("redis", ...)` 启动期连通性检查，Redis 不可达时 503 而非颁发受损的 token | `cmd/sso-server` |
| `WithClockSource(time.Source)` 注入点 + 顶层 `max_clock_skew` 配置；多副本时钟漂移 > skew 直接报警 | `sso.go` |
| graceful shutdown：`errgroup` + signal hook + 让 in-flight `/token` 跑完再关 Redis client | `cmd/sso-server` |
| 文档：`AGENTS.md` 的 "Storage today" 表更新；deploy 文档解释为什么仍然推荐 sticky session（仅为 `/auth/login` 的 cookie 续期友好性，不是正确性必需） | docs |

### Edge cases / 当前实现具体短板

- **单次消费的竞态**：`MemoryAuthCodeStore.Consume` 是 mutex，Redis
  必须用 `GETDEL`（6.2+）或 `EVAL` lua。两副本同时收到 /token
  重放都成功 = code 反复被换 = 静默授权多个会话。
- **DPoP 时钟窗**：今天 `dpop.go` 的 `iat` 校验是 ±60s，副本时钟漂移
  > 60s 就开始合法请求被拒。绑定到 `WithClockSource` 后，
  `dpopProofMaxAge` 应改为 `clockSkew + protocolWindow`。
- **Family Tracker 持久化语义**：refresh-token reuse detection
  落 Redis 之前要先想清楚 AOF 策略——AOF=`always` 性能差，但
  `everysec` 在崩溃时可能丢一秒级别的家族表，会让一次合法 rotation
  被误判为 reuse → 误杀整族。建议 fail-open 改 fail-soft：家族表读
  失败时退化到 plain `invalid_grant`（普通失败），不杀全族。
- **JWKS 私钥不能在副本间漂移**：跨副本 key rotation 需要协调（见
  方向 §3 的 HSM 抽象，那里一并解决）。
- **graceful shutdown 的隐患**：现在 main 收到 SIGTERM 后直接退出，
  正在处理 /token 的连接会让 RP 看到 EOF。配 Kubernetes
  `terminationGracePeriodSeconds` 才有用。

### Sequencing hint

**P0，立刻**。其余四个方向（WebAuthn 持久化、HSM 抽象、Admin
Console 多副本实时面、CIBA 长轮询）都假设"Store 是分布式且强一致"。
这条不做掉，后面任何"加机器扛流量"的对话都没法谈。

---

## 2. 把 2026 年的认证因子补全（WebAuthn / Passkey + 上游 IdP 联邦 + SCIM 2.0）

### Why now

当前 8 种 authenticator 全部是 **primitive**：password / phone / email /
temp_token 覆盖知识因素和占有因素的低保证版本；keypair / apikey /
certificate 是 service-to-service；TOTP 是入门级 MFA。**没有一个
是 2026 年企业 SSO 选型清单上的差异化项**：

- **没有 WebAuthn / FIDO2 / Passkey**——苹果 / 谷歌 / 微软三家
  默认推 Passkey 已经两个完整产品周期，企业 SSO 没这个直接出不了
  POC。
- **没有上游 IdP 联邦**——客户问"能用 Google Workspace / Okta /
  Azure AD 登录吗"只能回答"不行"。SAML 2.0 是政府 / 大企业的硬
  门槛。
- **没有 SCIM 2.0**——HR / IT 自动 provisioning 是企业版定价的
  分水岭，没它就被卡在"开发者工具"层级。

### Scope

**A. WebAuthn / Passkey Authenticator**

- 新包 `authenticators/webauthn/`，复用 `go-webauthn/webauthn`。
- 4 条新路由：`/auth/webauthn/{begin,finish}-registration`、
  `/auth/webauthn/{begin,finish}-login`。
- 凭据持久化：SQLite 新表 `webauthn_credentials`（`user_id`、
  `credential_id`、`public_key`、`sign_count`、`aaguid`、`transports`、
  `last_used_at`）。**注意**：`sign_count` 的递增必须 atomic（防
  clone attack），用 `UPDATE … WHERE sign_count < ?`。
- AMR claim 上声明 `["hwk"]`（hardware key）/ `["swk"]`（software），
  ACR 推荐 `urn:mace:incommon:iap:silver` 或 FAPI 1 baseline 等
  常用值。
- 可发现凭据（discoverable credentials / resident keys）需要
  `userHandle` 注入到 `Subject.ID` 解析路径——这是 Passkey
  跨设备同步的核心，必须支持。

**B. 上游 IdP 联邦（OIDC RP-side + SAML 2.0）**

- 新包 `federation/`，接口 `Provider`：`AuthorizeURL(state) →
  redirectURL`、`Exchange(code) → IdentityClaim`、`UserInfo` 可选。
- 内置实现：
  - `federation/oidc/` —— 通用 OIDC RP，覆盖 Google / Microsoft /
    Okta / Auth0；走 `github.com/coreos/go-oidc/v3` 验证 id_token；
    自动从上游 discovery 文档摘 JWKS。
  - `federation/saml/` —— `crewjam/saml`；处理 SP-init 与 IdP-init，
    AssertionConsumerService URL 由本 SSO 提供。
- 路由：`GET /auth/federated/:provider`（302 到上游）、
  `GET/POST /auth/federated/:provider/callback`。
- JIT 用户创建走 `UserProvider.CreateOrUpdate`；填充
  `Subject.Attributes["idp"] = providerName`、`["idp_subject"]`、
  `["email_verified"]`。
- per-tenant policy：`Tenant.Settings["federation"]` 控制
  可见的 IdP 列表 + 强制策略（"`@acme.com` 域名强制走 Okta"）。
- `amr: ["fed"]` + 上游 ACR 透传到本服务 ACR。

**C. SCIM 2.0 (RFC 7644)**

- 新包 `scim/`，挂在 `/scim/v2/Users` + `/scim/v2/Groups`。
- Bearer auth 与 admin 同源，gated by 新权限 `scim:write` /
  `scim:read`。
- 走现有 `UserProvider` + `permissions.Provider`，不引入新存储。
- 关键动作：
  - `PATCH /Users/{id}` 改 status → 异步触发该 user 全部 session 吊销。
  - `DELETE /Users/{id}` → 调用 `RefreshTokenSubjectIndex.DeleteAllForSubject`
    + `SessionManager.ListByUser` → `Destroy`。
  - HR 误删保护：默认 soft-delete（`User.Status="archived"`），
    30/60/90 天可配置硬删；硬删走方向 §4 的 GDPR pipeline。

### Edge cases / 当前实现具体短板

- `Subject.Attributes` 是 `map[string]string`——存 WebAuthn
  credential 的 byte slice 必须 base64。要么升级到 `map[string]any`，
  要么把这类二进制属性挪到独立的 Attribute store（解耦后 token claim
  payload 也变小）。
- 联邦回调路径下 `RiskScorer.Score` 拿不到密码——必须把
  `RiskRequest` 的 `Authenticator` 字段改为可识别"上游 IdP 类型"
  的形式（如 `federation/google`）；现有 scorer 不要假定永远有
  password hash。
- WebAuthn 的 `clientDataJSON.origin` 必须在多 tenant + 多域名下匹配
  正确——`tenant/` 已经做了 hostname → tenant 映射，把
  `webauthn.RelyingPartyID` 设为 `tenant.PrimaryDomain` 即可，但
  跨子域 Passkey 共享需要显式声明 `apple-app-site-association` /
  `assetlinks.json`，文档要写清楚。
- SAML SP metadata 暴露面：`GET /federation/saml/:provider/metadata`
  必须缓存（一次 IdP 注册可能触发上游半小时一次的拉取），并签名
  以防元数据投毒。
- SCIM `bulkOperations` 极易被误用——一次性导入 10k 用户会让 admin
  token bucket 干涸。建议：`bulk` 请求必须 admin-bypass rate limit，
  同时落 audit `scim_bulk_imported` 并强制需要 `scim:bulk` 权限。

### Sequencing hint

WebAuthn + 上游 IdP 联邦 是 **第一波**——共 8-10 周工时，但锁定
两类销售场景（B2C Passkey 升级 + B2B "用我们的 IdP" 谈判）。SCIM
是 **第二波**——上线后 30 天内才会被 IT 真正使用，但报价单上
立刻需要这一行。账户级防御（HIBP k-anonymity、固定窗口 timing
equalization）可以与第一波并行，每项不到一个 sprint。

---

## 3. 签名密钥治理：HSM / KMS 抽象 + 多算法 + 自动轮换 + 密钥审计

### Why now

`Ed25519JWTIssuer.Issue` 直接调 `ed25519.Sign(j.privateKey, ...)`——
**私钥裸存进程内存**。这在三个客户对话里会立刻被拒：

1. **金融 / 政府客户**：合规要求签名密钥必须在 HSM / KMS 内，
   私钥永不离开硬件边界。
2. **SaaS 多租户**：同一进程持有所有 tenant 的签名密钥 = 单个
   memory dump 暴露所有 tenant 的伪造能力。
3. **密钥轮换审计**：今天密钥轮换是手动调 `RotateKey`，没有
   "轮换记录、谁触发、为什么轮换、上一版本何时停止接受签名"
   的审计闭环。

并且这件事还顺手解决两个长期 TODO：

- **多算法支持（RS256 / ES256 / EdDSA 并存）**：今天只有 EdDSA。
  联邦上游可能是 RS256，资源服务器要验上游签名也需要 RS256
  支持——一旦引入新算法，alg confusion 攻击的窗口立刻打开
  （AGENTS.md 已 noted）。统一的 `Signer` 抽象层是收口这个攻击
  面的唯一办法。
- **per-tenant 签名密钥**：多租户的 issuer 是不同的 `https://
  tenant-a.example/` vs `tenant-b`，理论上每个 tenant 应该有
  独立 JWKS。今天是共享一把 key——任何一个 tenant 的 token
  在另一个 tenant 的 issuer 校验语义下都"可疑"。

### Scope

**A. `SigningKeyProvider` 抽象**

```go
type SigningKeyProvider interface {
    Sign(ctx, kid, algorithm, payload) (signature, error)
    PublicJWKS(ctx) (JWKS, error)       // 公布给 JWKS endpoint
    ActiveKID(ctx, algorithm) (kid, error)
    Rotate(ctx, reason) (newKID, error) // 触发轮换 + audit
}
```

- 默认实现 `defaultimpl/software`：现有 Ed25519 软件签名走这个壳，
  零行为变更。
- `defaultimpl/awskms/` —— AWS KMS（用 `aws-sdk-go-v2`，
  `kms.Sign`）。
- `defaultimpl/gcpkms/`、`defaultimpl/azurekv/`、`defaultimpl/vault/`
  —— 同模式可由社区/客户按需加。
- `defaultimpl/hsm-pkcs11/` —— PKCS#11 通用层（YubiHSM / SoftHSM /
  Thales / Entrust 都走这套），用 `github.com/miekg/pkcs11`。

**B. 多算法 + alg allowlist 收紧**

- `Server.supportedJWTAlgs` 从 hardcoded `["EdDSA"]` 变成
  `WithSupportedSigningAlgs(...)` 配置；discovery 同步反映。
- `Validate` 严格化：header `alg` 必须在 allowlist 且必须与 `kid`
  对应密钥的算法一致（防 RS256 公钥被当 HS256 共享密钥用的经典攻击）。
- 引入 `WithSecondaryAlg(...)` 用于过渡：同时接受老 EdDSA + 新
  RS256，给现有 RP 6+ 个月迁移窗口。

**C. 自动轮换 + 重叠期 + 审计**

- 新配置块 `keys.rotation`：
  ```yaml
  keys:
    rotation:
      interval: 90d         # 每 N 天自动轮换
      grace_period: 7d      # 旧 kid 在 JWKS 多保留 N 天（让在飞行的 token 仍能验签）
      strategy: scheduled   # scheduled | manual | event-driven (HSM rekey)
  ```
- 轮换由 `bootstrap/builtin` 的 v5 step `ensure_signing_key_rotation`
  注册（首次启动检查 `last_rotated_at`，到期触发）。
- 每次轮换写 audit `signing_key_rotated`：包含 `from_kid` /
  `to_kid` / `algorithm` / `reason`（scheduled / manual / suspected_compromise）。
- 紧急轮换接口：`POST /api/v1/admin/keys:rotate {reason: "compromise"}`
  立即生成新 kid + 把所有现存 token 标记为 needs-revalidation；与
  既有 `/token/revoke-all` 配合可达成"全局 token 黑屏 30 秒"。

**D. per-tenant 签名密钥（可选第二阶段）**

- `Tenant.SigningKey` 可指向独立的 `SigningKeyProvider`；空则走全局。
- discovery 已经按 tenant 路由（`tenant/` 解析），加上 per-tenant
  JWKS endpoint 即可：`/tenant/{tenant-id}/.well-known/jwks.json`。
- 关键 invariant：跨 tenant 的 token 在错误 tenant 的 issuer 视角
  下永远拒签——`Validate` 必须先按 `iss` claim 路由到对应
  KeyProvider，而非用进程级 KeyProvider 验所有 token。

### Edge cases / 当前实现具体短板

- KMS 延迟：AWS KMS sign 是网络 RTT（5-50ms），把 ed25519.Sign 的
  µs 级响应拉慢三个数量级。需要：(1) KMS-signed token 的 TTL 适度
  拉长（10min → 30min）摊薄签名成本；(2) per-process LRU 缓存
  `(kid, payload_hash) → signature`（DPoP 的 `jti` 已经在防重放，
  签名缓存复用安全）；(3) p99 监控 + 熔断到本地缓存的 kid。
- JWKS endpoint 的 ETag：今天 ETag = `sha256(body)[:8]`，KMS 后端
  的公钥不会变，但缓存层引入后 `body` 字节顺序可能不稳定。改成
  `sha256(canonical(jwks))` 或 `kid_set || algorithm_set` 组合
  hash。
- 轮换期的 `kid` 选择竞态：grace_period 内同一 token issuance 路径
  可能命中老 kid（cache miss）和新 kid（cache hit）两种状态。
  `ActiveKID` 必须强一致（走分布式存储或单点 leader），不能在
  副本间漂移；否则 N 副本会颁发用 N 种 kid 签的 token，RP 端
  JWKS 缓存反而抓不到刚轮换出去的那个 kid。
- 算法切换的"算法混淆"攻击窗口：从 EdDSA 单算法过渡到 EdDSA +
  RS256 双算法时，必须在 `Validate` 严格做 `kid → algorithm`
  对应，不允许 RP 通过 header `alg` 选择算法——必须由 server-side
  键空间决定。

### Sequencing hint

**先做 A**（HSM/KMS 抽象）+ **B**（多算法 allowlist 收紧）作为一个
batch，约 3-4 周；**C**（自动轮换 + 审计）独立 sprint；**D**
（per-tenant 签名密钥）等真有 multi-tenant 客户提需求再做（涉及
discovery URL schema 演化，破坏性较大）。

---

## 4. 把面向人的操作面 / 合规闭环做完：Admin Web Console + 用户自助 + GDPR + 异常检测

### Why now

后端 capability 已经齐整，**面向人的操作面是空白**：

- **运营 / IT**：客户公司想看"过去 24 小时谁登录失败、从哪个国家、
  哪个 client" → 现在只能 `GET /api/v1/audit/events` 自己写脚本。
- **终端用户**：想看"我的活跃会话、能不能注销具体设备" → 没
  UI，只有 `POST /token/revoke-all`（全员注销）。
- **合规**：GDPR Art. 15 / 17 / 20（访问 / 删除 / 可移植）请求来
  时，没有标准化的导出/删除流水线；audit redactor 是工具，没人
  调它。
- **安全**：今天 risk scorer 是**请求路径上的同步决策**，但凭据
  撞库的真正信号通常是**事后聚合**（同一 IP 24 小时内 1000 次
  失败、impossible travel、新设备）——这是异步的、需要独立通路。

这件事的 ROI 不是写新协议，而是 **把已经写好的能力包装出来卖**。

### Scope

**A. Admin Web Console（独立 SPA）**

- 新 monorepo 子目录 `web/admin/`，Next.js 14 + shadcn/ui + tRPC
  over admin REST（gateway 自动生成，零后端改动）。
- 首批 6 个 panel：
  1. **Dashboard** —— 登录成功率 / TPS / 错误率，直接吃 Prometheus
     metrics + audit events 流。
  2. **Clients** —— CRUD + rotate secret + redirect_uris 可视化
     编辑器 + JWKS / cert binding 配置面板。
  3. **Users / Roles / Menus** —— 三方树状选择器，复用
     `permissions.MenuLister`。
  4. **Audit Explorer** —— 全文检索（依赖 §A.1）+ facet 过滤
     `(tenant, country, outcome, reason, client_id)`；trace_id 跳
     Grafana Tempo / Jaeger。
  5. **Sessions / Tokens** —— 活跃会话列表、按用户/客户端筛选、
     一键吊销整族；DPoP-bound / mTLS-bound token 显式标识。
  6. **Releases / Snapshots** —— `pin` / `rollback` / `export` /
     `restore` 按钮挂既有 admin endpoints。
- **认证流**：Console 本身用本 SSO 登录（典型的 dogfooding），
  `client_id=sso-admin-console`，scope=`admin:*`。

**A.1 Audit 后端升级（Console 的前置依赖）**

- 新 audit sink `audit/sink/sqlite/`（FTS5 全文索引 + 关键 facet
  字段加 index）。
- 可选 sink `audit/sink/clickhouse/`、`audit/sink/opensearch/`，
  接受运维选择列存 / 搜索引擎走更大规模。
- Query API 升级：`audit.Query` 增加 facet 字段聚合返回（让前端
  filter 面板直接渲染候选值）。

**B. 终端用户自助门户**

- 同一 SPA 框架不同入口：`/me` 路由，`scope=self:read,self:write`。
- 功能：
  - 活跃 sessions 列表 + per-session 登出 + 一键全部登出
  - 改密码 / 绑定 Passkey / 启用 TOTP / 设置备份码
  - 登录历史（来自 audit）+ "新设备登录" 邮件通知 opt-out
  - "下载我的数据"（依赖 §C 的 export 流水线）
- 关键 invariant：**改密码后默认吊销所有 session 除当前**——
  per-`Client` 可配置（默认安全，opt-out 便利）。

**C. GDPR / 合规流水线**

- `POST /api/v1/admin/users/:id:export` —— 调用所有 Provider 的
  optional `Exporter` 扩展，打包 ZIP 返回。结构：`user.json` /
  `sessions.json` / `audit_events.jsonl` / `refresh_tokens.json` /
  `permissions.json` / `webauthn_credentials.json`。
- `POST /api/v1/admin/users/:id:erase` —— right-to-be-forgotten
  workflow：
  1. 吊销所有 token + session
  2. soft-delete user（`Status="erased"`，可登录被拒）
  3. 排队 30 天后真正调用 `UserProvider.Delete` + `audit redactor`
     对历史 audit 事件做 PII 假名化（**保留事件 ID 与时间戳与
     hash 链**，仅替换 PII 字段为 `[REDACTED]`——hash 链仍可
     校验，因为内容确实变了，但"事件 X 在时间 T 存在过"得以
     保留）。
- 新模块 `compliance/erasure/` 持有 30 天 schedule，与 bootstrap
  Step 复用同一 tracker；崩溃恢复友好。
- 文档：`docs/compliance.md` 写明 GDPR / CCPA / PIPL 的字段映射。

**D. 异步异常检测（Anomaly Detector，与 Risk Scorer 平行）**

- 新接口 `sso.AnomalyDetector`：**登录成功后** 异步调用，输出
  alert 到 audit + 可选 webhook。
- 内置检测器（每个独立 PR）：
  - **Impossible travel**：基于现有 `geo.GeoInfo`，相邻成功登录跨度
    距离 / 时间 > 物理可达（800km/h 上限）。
  - **Velocity**：同一账户 / IP 在窗口内成功登录次数 > 阈值（默认
    `25/hour` / `200/day`）。
  - **New device / new country**：相对该用户的 7 天基线，新出现的
    UA fingerprint 或 country_code。
  - **Brute-force shadow**：同一账户失败计数 / 成功计数比 > 阈值，
    暗示 lockout 边缘的撞库行为。
- 告警出口：
  - audit event `anomaly_detected`，包含 detector 名 + score + 原始
    事件 ID
  - 可选 webhook（与 `audit.WebhookSink` 同源）push 到 SIEM
  - 可选 SMTP / Slack 推送到用户本人（"我们检测到来自新国家的
    登录…"）

### Edge cases / 当前实现具体短板

- Audit Explorer 在 SQLite `MemorySink` / `WriterSink` 后端走线性
  扫描，> 100k 事件即不可用——A.1 是 Console 真正能用的前提。
- GDPR erase 与 audit hash chain 的冲突：方案如上（保留事件 + 替换
  PII）。这套合规语义必须写进 `docs/error-codes.md` 同源的
  `docs/compliance.md`。
- 异常检测的 false positive 成本：impossible travel 在 VPN 用户身上
  几乎 100% 误报。所以默认输出是 audit + webhook，**不进请求路径**
  （不影响登录成功/失败）；只有运维 / 用户自己看到信号。让客户
  按自己的安全姿态决定是否升级到"自动锁账户"。
- Admin Console 的 release 步调：Console 是前端 bundle，已经有
  `releases/pinner/static` 走 atomic symlink swap——这是为什么
  release pinning 早早做好的原因。前端落 `web/admin/dist/`，由 nginx
  / CDN 提供。
- **重要**：Console 的访问控制必须能区分"我能看自己 tenant 的
  audit" vs "我能看所有 tenant 的"。新权限：`admin:read.tenant.{tid}`
  vs `admin:read.global`。

### Sequencing hint

**A.1 Audit SQLite/CK sink 是关键路径**——没它 Console 跑不动。
A.1 + B（用户自助门户）+ C（GDPR）三件可以**前后端并行**：前端
3-4 周做 Dashboard + Sessions 这两个最有 demo 价值的 panel，后端
2 周补 Audit SQLite sink。异常检测 D 完全独立，可作为
sprint-filler 随时加。

---

## 5. 最后一公里协议补完：CIBA + JWE + Signed Metadata + DPoP Nonces + Pairwise Subject

### Why now

这五件事单独看都不大，但放在 **2026 年 FAPI 2.0 客户清单 +
Open Banking 区域合规** 的视角下是 **一组**：缺一项就被 RFP 表筛出去。

- **CIBA**（OIDC Client-Initiated Backchannel Authentication）—— 银行
  柜员推到客户手机确认，IoT 设备推到用户 PIN 输入——FAPI Brazil /
  开放银行的硬需求。
- **JWE**（JSON Web Encryption）—— FAPI 2.0 baseline 要求
  `request` 参数可加密；某些金融 RP 要求 id_token 加密；JAR
  请求里带 PII（如 `login_hint` = 手机号）时也需要加密在传输层
  之上。
- **Signed Metadata**（RFC 8414 §2.1）—— discovery 文档本身用 JWS
  签名，防止 MitM 篡改 `token_endpoint` 等关键 URL。
- **DPoP Nonces**（RFC 9449 §8）—— server-issued nonce，让 DPoP proof
  必须包含 server-发送的 nonce 才能通过——彻底封死即使 jti 防重放
  也存在的"窗口期重放"。
- **Pairwise Subject Identifiers**（OIDC §8.1）—— 同一用户在不同 RP
  下 `sub` 是不同值，跨 RP 不能 correlate；GDPR 默认隐私要求 +
  消费者场景常需。今天 `subject_types_supported: ["public"]` 唯一。

### Scope

| 工作项 | 大致工作量 | 标准 |
|---|---|---|
| `POST /backchannel-authentication` + `/bc-authorize` 长轮询 + push notification 模式；用 SessionManager 持久化挂起请求 | L | OIDC CIBA |
| 引入 `defaultimpl/cibanotifier/{fcm,apns,http}` —— 推送到设备 / 应用 webhook | M | 同上 |
| `request` 参数支持 JWE 解包（外层加密 + 内层签名嵌套结构）；解密密钥从 `Client.JWKS` 中按 `enc=A256GCM` 等 alg 选择 | M | RFC 7516 + RFC 9101 §6.2 |
| id_token / userinfo 加密响应：`id_token_encrypted_response_alg` + `_enc` per-client 配置；输出从 JWS-only 升级到 JWE(JWS(...)) 嵌套 | M | OIDC Core §10.2 |
| `signed_metadata` 字段加入 discovery JSON：内容 = 整个 metadata JWS-signed；RP 端拿到后 `verify(sigingKey)` 才信任 endpoints | S | RFC 8414 §2.1 |
| DPoP nonce challenge：`/token` / `/userinfo` 返回 `DPoP-Nonce` header + 401 `use_dpop_nonce`；RP 第二次请求带 nonce 才放行 | S | RFC 9449 §8 |
| Pairwise subject：`Client.SubjectType=pairwise` + `Client.SectorIdentifierURI`；`sub = sha256(sector \|\| user_id \|\| salt)`；存储在新表 `pairwise_sub_map`（避免每次重算） | M | OIDC §8.1 |
| FAPI 2.0 compliance profile：单个 `oauth_compliance: fapi_2` 开关，开启后强制（PAR-only、`request` 必签 + 必加密、PKCE S256、DPoP-only or mTLS-only、no implicit、pairwise sub、signed_metadata、ACR `urn:openid:fapi:...`） | L（主要是测试） | FAPI 2.0 Security Profile |

### Edge cases / 当前实现具体短板

- CIBA 的 `binding_message` 必须显示给用户（防 phishing："你在
  pad 上点击的金额是 ¥{N}"）——这要求 device-side app 实现，
  服务端只能保证字段传递正确性，文档要写清楚 SDK 契约。
- JWE 解密失败 vs 签名验证失败 —— oracle-leak 风险。两者必须
  collapse 到同一个 `invalid_request_object`，不能透露"加密成功
  但签名失败"这种信号（攻击者可借此区分 alg 错误 vs key 错误）。
- Signed metadata 的 `signed_metadata` 字段如果与平铺字段不一致，
  RP 应该信哪个？RFC 8414 说签名版本优先。我们必须：(1) 先签名
  后序列化平铺字段，确保两者派生自同一 source；(2) discovery 加
  invariant test，强制两边一致。
- DPoP nonce 与 SessionManager 不依赖——nonce 是 server-issued
  ephemeral value，落到 JTIReplayStore 的同一 Redis namespace（不同
  prefix `nonce:`）即可。但 N 副本下 nonce issuance 必须是任一副本
  签发都被全部副本接受 —— 走方向 §3 的对称签名（HMAC with
  shared secret）或 Redis 集合查询。
- Pairwise sub 的 sector identifier 验证：必须 fetch
  `sector_identifier_uri` 拿到 RP 的 redirect_uri allowlist，验证
  当前 redirect_uri 在内——否则任何 client 都可以声明同一个 sector
  共享 `sub`，跨 client correlate 用户身份。这是 OIDC §5
  的精确要求，实现不到位 = 直接违反规范。
- FAPI 2.0 compliance profile 的"全或无"对客户是悬崖——必须配
  **inspection mode**：开关打开但只 audit 不拒绝，让运维 ramp-up
  看到哪些 RP / 配置违规。`fapi_2_inspection_only: true`。

### Sequencing hint

按 ROI 排序：**Signed Metadata + DPoP Nonces + Pairwise**（三个
小颗粒，合计一个 sprint）→ **JWE**（两 sprint，单独 review 防止
oracle leak）→ **CIBA**（独立 sprint，需要新基础设施 push notification）→
**FAPI 2.0 profile**（最后做，因为依赖前面四个全部到位）。

---

## 边界情况 & 性能优化（持续清单）

下面这些颗粒度不够独立方向，但建议作为常规迭代的"sprint filler"
逐项消化。每条都对应一个具体的代码位置或行为契约。

### 性能

- **Discovery 文档缓存**：当前 `handleOIDCDiscovery` 每次请求都重
  扫 client store 4 次（`oidc_discovery.go:255,277,478,514`）。建议
  TTL 5s 的进程内 single-flight 缓存——客户端会订阅这个文档但
  10k 客户端规模下不可能每个请求都扫全表。
- **BCL 多 RP 扇出并发化**：`backchannel_logout.go` 的 fan-out
  当前是串行 for-loop，10 个 RP × 500ms = 5s 阻塞 `/end_session`。
  改成 `errgroup` + `WithMaxConcurrent` 限流，p99 从秒级回到 ms 级。
- **Audit 异步化**：`audit.Recorder` 今天是同步 → Sink。webhook /
  网络 sink 失败会阻塞请求路径 timeout。建议加 `WithBufferedSink(cap)`
  把每个 Sink 包装为 goroutine + 有界 channel，溢出策略：drop oldest
  + 报 audit metric。
- **`validateAnyToken` 顺序优化**：`sso.go:921` 线性试每个 issuer。
  改成先 peek token 形态（含 `.` = JWT；不含 = opaque）再 dispatch；
  Session + JWT 双 issuer 下减少一次失败的 JWT 签名解析。
- **JWKS 缓存的 single-flight refresh**：`remote.JWKSCache` 已经有
  single-flight，但服务端 JWKS endpoint 本身没有；OpenResty 边缘
  缓存能扛但服务端被 N 副本同时拉时还是会重算。给 `handleJWKS`
  加 `sync.Once` per rotation epoch。

### 边界情况

- **Tenant 暂停的主动吊销**：今天 `Tenant.Status=suspended` 只让新
  请求失败，已经发出的 token / session 仍然有效。建议：suspend
  时触发后台 job 调用 `RefreshTokenSubjectIndex.DeleteByTenant`
  + `SessionManager.DeleteByTenant`（后两个 SPI 都还没有，需要
  补）。
- **`/par` 的 body 大小限制**：全局 `body_limit` 默认覆盖所有路径，
  但 JAR JWT（加密后）可能 > 全局默认。建议 per-endpoint
  override：`security.body_limit.per_endpoint: { "/par": "64KB" }`。
- **graceful shutdown**：`cmd/sso-server/main.go` 没有 SIGTERM
  handler；K8s rolling update 会让 in-flight `/token` 看到 EOF。
- **跨 issuer revoke 的最终一致**：`/token/revoke-all` 调
  `revokeAcrossIssuers` 但任一 issuer 失败不会阻断，也不报错。
  建议：失败的 issuer 名收集进 audit `partial_revoke_failure`，
  以便运维后续手动处理。
- **bootstrap admin password 只打印到 stdout**：容器化部署里
  stdout 经常是 journalctl + 异步 sink，丢失风险。建议加
  `--bootstrap-admin-password-file=/path/secret` 把首次密码写到
  指定路径并 chmod 0600。
- **OIDC `claims` 参数的深度处理**：`claims_param.go` 当前解析
  字段名但不强制 essential claim 必须 honor——upstream
  required claim 没法满足时应该返回 `invalid_request` 而非沉默
  忽略。
- **DPoP `htu` 与 reverse proxy**：`requestURLForDPoP` 已经吃 XFF，
  但 `htu` 校验在严格 FAPI 模式下要求精确匹配，proxy 改写过的
  URL 与 RP 看到的可能不一致。需要 deploy 文档明确"`X-Forwarded-*`
  必须在 ingress 层稳定 set"。

### 协议小颗粒

- **goreleaser publish 启用**：`.goreleaser.yaml` 当前 `disable: true`，
  CI 跑完不发布。挂目标：GitHub Releases + ghcr.io container +
  cosign signature。
- **SQLite 多表 schema 演化**：现在每个 backend 都 `CREATE TABLE
  IF NOT EXISTS`，无版本号。引入 `goose` 或 `golang-migrate`，
  在 `defaultimpl/sqlite/migrations/` 走 versioned migration——
  未来加列 / 改索引才有路径。
- **`/end_session` `state` 参数透传**：OIDC RP-Initiated Logout
  §3 要求 `state` 在 `post_logout_redirect_uri` 上原样回传，需
  spot-check 是否实现。
- **`acr_values` 在 token-exchange 上的处理**：今天透传 inbound
  ACR，但 step-up 后的 token 应该用更高 ACR——
  `handle_token_exchange.go` 需要支持 caller 显式声明
  `acr_values` 升级请求（同 `/auth/login`），由 server 验证可达
  性。

---

## 未列入但已经考虑过的方向

- **跨区域 active-active**：依赖方向 §1 完成。etcd 跨区 raft 是
  独立的容量规划课题，不属于 SDK 范畴；多区方案应交给运维而非
  SDK。
- **CLI 工具 `ssoctl`**：admin REST 已经覆盖所有 capability，CLI
  是 DX 优化不是能力扩展，留到 v2。
- **GraphQL admin API**：REST gateway 已经 proto 自动生成，多一层
  GraphQL 是维护成本，没有清晰需求场景。
- **多服务 SDK（Python / Node / Java client lib）**：标准 OAuth/OIDC
  生态有大量成熟 lib（`oidc-client-ts`、`authlib`、`Spring Security
  OAuth`），重复造轮没价值；focus 在让本服务输出 **正确的标准
  endpoints** 上。
- **OAuth 1.0a / Kerberos / RADIUS / NTLM 兼容层**：历史协议，企业
  里仍有但已经被网关产品（Keycloak、PingFederate）覆盖，不是新进
  入者的差异化点。
- **Custom JSON-RPC / SOAP authenticator**：客户自定义协议可以在
  应用层包装 `temp_token` 或 `keypair` 实现，无需进 SDK 核心。

---

## 优先级摘要

| # | 方向 | 类型 | 阻塞下游 | 建议先后 |
|---|---|---|---|---|
| 1 | 多副本分布式后端 + 时钟 + graceful shutdown | **正确性 Bug** | 几乎所有其他方向 | **P0，立刻** |
| 2 | WebAuthn / 上游 IdP 联邦 / SCIM 2.0 | 产品差异化 + 企业销售 | 销售 demo + RFP | P1，与 §3 并行 |
| 3 | HSM/KMS 抽象 + 多算法 + 自动轮换 + 密钥审计 | 安全合规 + 多租户 | 金融客户准入 + FAPI | P1，与 §2 并行 |
| 4 | Admin Web Console + 用户自助 + GDPR + 异常检测 | 产品化 + 合规闭环 | 企业版定价 + 上线公关 | P2，§1 落地后跟进 |
| 5 | CIBA + JWE + Signed Metadata + DPoP Nonces + Pairwise | 协议补完 + FAPI 2 准入 | Open Banking / 金融 RFP | P3，§3 落地后跟进 |
