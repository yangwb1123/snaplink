# 第十轮分析：SQLite 连接架构、MFA 恢复机制与外部 HTTP 超时治理

> 基于全局代码库扫描产生的全新视角，此前九轮未覆盖。

---

## 方向一：SQLite 连接窒息——20+ 独立 `sql.Open()` 争抢同一个文件

**问题：** 每个 SQLite 存储都通过 `New*Store(dsn)` 自行调用 `sql.Open("sqlite", dsn)`，并设置 `SetMaxOpenConns(1)`。这意味着部署后约有 **20 个独立的 `*sql.DB` 连接**（clients、sessions、refresh_tokens、auth_codes、par、jti_replay、account_lockout、password_reset、pairwise、subject_client_index、users、email_change、push_approvals、mfa_challenges、revocations、consent、device_secrets、ip_failure_counter、recent_login...），全部指向同一个 SQLite 文件。

每个连接：
- 拥有自己独立的 WAL 事务状态
- 设置 `SetMaxOpenConns(1)`（正确——WAL 模式下一次一个写入者）
- 通过 `busy_timeout=5000` 连接的全局钩子（`infrastructure/defaultimpl/sqlite/busy_timeout.go`）——在放弃前等待 5 秒

**后果：**
- 两个存储同时写入（例如 `token_authcode.go` 消耗 code → 写入 refresh_token + session + audit event）→ 连接 B（审计）可能在连接 A（refresh_token）持有 WAL 写入锁时发现 `SQLITE_BUSY` → 忙等 5 秒 → 延迟 + 尖峰
- 在吞吐量峰值时，20 个连接争抢 WAL，产生写入器护航——`busy_timeout` 掩饰了问题但没有消除它
- 写入器护航会放大 p99 延迟——即使每个操作只需要 5 毫秒的写入时间，12 个并发写入者串行化意味着第 12 个操作要等待 55 毫秒

**代码表明团队意识到了这一点：** 有些存储导出 `New*StoreWithDB(db *sql.DB)` 作为替代构造函数（例如 `NewClientStoreWithDB`、`NewEmailChangeStoreWithDB`）。但**实际的 `Build*` 函数从不使用它们**——每个函数都传递 DSN。

**修复：** 在服务器的 SQLite 配置中创建一个共享的 `*sql.DB` 单例（`sql.Open` 调用一次，`SetMaxOpenConns(1)` 设置一次），然后将其传递给所有的 `New*StoreWithDB()`。使用 `PRAGMA journal_mode=WAL` 和 `PRAGMA synchronous=NORMAL` 进行最佳共享。

**工作量：** M（重构 Build* 函数以提取共享 DB + 验证写入器护航的集成测试）| **影响：** **高**（在峰值吞吐量下 p50-p99 可能有 2-5 倍的改进）| **类型：** 性能

---

## 方向二：TOTP 缺少恢复码——丢失设备 = 完全锁定

**问题：** `domains/authenticators/totp.go` 和 `domains/authenticators/totp_enroller.go` 实现了完整的 TOTP 注册和验证流程。但 **没有恢复码系统**。

**具体缺口：**
- `TOTPEnroller`（`totp_enroller.go:10`）生成密钥、编码密钥、制作 `otpauth://` URI——但不生成单次使用恢复码
- 没有 `RecoveryCodeStore`（类似于 `PasswordResetStore` 但用于 MFA 恢复）
- 没有 `POST /auth/mfa/recovery` 端点用恢复码取代 TOTP 代码
- 没有管理端点可供管理员清除用户的 MFA 注册

**用户故事：** 用户 Bob 在手机上使用 Authy 注册了 TOTP。手机丢失了。没有备份恢复码，没有管理员解除锁定工具。**Bob 被永久锁定在他的账户之外。** 唯一的恢复路径是直接数据库访问 + 管理员手动 `DELETE FROM totp_enrollments WHERE user_id = ?`。

**修复：**
1. 添加 `RecoveryCodeStore`——生成 N 个单次使用加密-hash 恢复码（类似于 `password_reset` 模式）
2. 在 `TOTPEnroller.Confirm` 期间展示恢复码（注册确认后仅此一次）
3. 添加 `POST /auth/mfa/recovery`——验证恢复码，绕过 TOTP，要求立即重新注册
4. 添加管理 RPC `AdminUnlockMFA(userID)`——管理员发起的 MFA 注册清除

**工作量：** M（存储 + 端点 + 注册 UI + 管理 RPC）| **影响：** **高**（支持问题 #1——"我丢失了手机，无法登录"）| **类型：** 功能/运维

---

## 方向三：外部 HTTP 请求缺少结构化的超时传播——上游故障的服务降级

**问题：** 代码库对上游服务（OIDC 提供者、SAML IdP、CAEP 接收器、MDS 端点、联邦实体配置、信任标记、SCIM 目标）发出 HTTP 请求。但超时处理和传播是不一致的：

| 外部调用位置 | 超时 | 传播 |
|---|---|---|
| `authenticators/oidc_federation.go`（上游 OIDC） | `http.Client.Timeout`（由配置设置？） | 应用层异常（`callback_failed`） |
| `saml/sp/authenticator.go`（SAML IdP） | `client.Timeout` | 自定义错误包裹 |
| `caep/transmitter.go`（CAEP 推送） | `http.Client`（默认——无超时！） | 没有回退 |
| `federation/fetch.go`（实体配置） | `http.Client.Timeout`（硬编码 10 秒） | 错误冒泡 |
| `jarm.go`（JARM 推送） | 无自定义超时 | 静默失败 |
| `webauthn/mds.go`（MDS 获取） | `client.Timeout`（30 秒） | 引导时失败加载 |
| `extauthz/authz.go`（外部授权） | 无定义 | 同步于请求路径 → 挂起整个授权决策 |
| `securityverify/jar_fetch.go`（JAR 获取） | `defaultHTTPClient`（默认——可能无超时） | jar_fetch 应用程序错误 |

主要问题：
1. `caep/transmitter.go` 和 `extauthz/authz.go` 默认的 `http.Client`——**没有硬超时**。对慢速上游的请求会无限挂起。
2. 在没有上游超时的公共端点调用期间，`extauthz` 集成被同步调用——如果外部授权器挂起 60 秒，整个 `/token` 端点也挂起 60 秒
3. 没有标准化 `UpstreamHTTPClient(timeout)` 工厂——每个包都内联自己的 `&http.Client{Timeout: ...}`
4. 没有断路器——同步路径上的连续超时不会被跳过；每个请求再次尝试

**修复：**
1. 创建一个 `shared/security/upstream_client.go` → `NewUpstreamClient(timeout, retries) *http.Client` 并带有断路器选项
2. 添加 `GetEndpointsTimeout()` 到 `DiscoveryResponse`，以便 RP 可以了解超时边界
3. 用一致的 `ClientTimeout` 配置选项替换所有独立的 `&http.Client{}`
4. 将 `extauthz` 和 `caep` 标记为 Fail-Open（记录 + 允许）如果到达上游超时，以限制可用性影响

**工作量：** M（重构~5 个包以使用共享的 HTTP 客户端工厂 + 断路器）| **影响：** **高**（防止上游挂起级联为整个 SSO 超时）| **类型：** 性能/弹性

---

## 方向四：CORS 缺少路由级精细控制——全有或全无的跨域策略

**问题：** `interfaces/middleware/cors.go`（或等价物）将 CORS 中间件应用于整个路由器。这意味着：

- `/token` 端点禁用了 CORS（凭证端点——不应该有跨域）
- `/register` 禁用了 CORS（凭证端点）
- `/userinfo` 禁用了 CORS
- 但由于是在路由器级应用的，**所有端点共享相同的 CORS 配置**

**具体的缺失模式：**
1. **通配符源的 `/jwks`**：RP 需要从不同源获取 JWKS。目前，如果 CORS 严格配置了特定源，来自不同源的 RP 无法获取 JWKS。如果配置为通配符 `/jwks`，则 `/register` 也获得通配符。
2. **带 credentials 的 `/introspect`**：一些部署需要从管理控制台内省令牌，这需要不同的 CORS 策略。
3. **`/login` 和 `/admin` 的 CORS**：嵌入式 SPA 与服务器同源——不需要 CORS——但任何需要嵌入 SSO 登录页面的第三方应用都被锁定。

**修复：** 添加路由级 CORS 覆盖：
- `WithCORS(allowedOrigins, options)` → 路由器范围默认
- `WithRouteCORCOverride("/jwks", CORSPermissive)` → 特定路由覆盖
- 凭证端点用 `NoCORS()` 路由标记 → 忽略 `Access-Control-*` 标头

**工作量：** S（路由级 CORS 覆盖 ≈5 行 + 中间件路由匹配更改）| **影响：** 中（集成灵活性）| **类型：** 功能

---

## 方向五：多租户管理面缺口——租户管理员能做和不能做什么

**问题：** 管理 API 定义在 `gen/proto/admin/v1/` 中，并提供：
- 客户端 CRUD（`ClientAdminService`）
- 用户管理（`UserAdminService`）
- 会话管理（`TokenAdminService`）
- 租户配置（`TenantAdminService`）

但租户管理员（与超级管理员相对）有缺口：

| 操作 | 超级管理员 | 租户管理员 |
|------|-----------|-----------|
| `ListTenantUsers` | ✅ | ✅ |
| `CreateTenantUser` | ✅ | ✅ |
| `ListSessions`（所有） | ✅ | ❌（返回所有租户） |
| `ListSessionsByTenant` | ❌ | ❌（不存在） |
| `RevokeUserSessions(userID)` | ✅（需要 userID） | ❌（无租户范围） |
| `ExportAuditLog(tenantID)` | ❌ | ❌（不存在——审计日志是全局的） |
| `ListClients(tenantID)` | ✅（有过滤？） | ❌（无租户范围） |
| `ConfigureTenantSSO` | ✅ | ❌（但应该允许） |
| `ViewTenantMetering` | ✅ | ❌（不存在——`TenantUsageAggregator` 存在但无管理端点） |
| `ResetTenantMFA(userID)` | ✅ | ❌（不存在——恢复码方向一所需要） |

**缺少的核心模式：** 租户范围的资源过滤器。管理 `List*` RPC 要么返回所有内容（超级管理员），要么需要精确的 `userID`——没有"给我 X 租户中的所有资源"。

**修复：** 审计日志、会话和客户端存储中需要一个 `tenant_id` 索引。RPC 过滤器参数 `tenant_id`。审核租户管理员不能列出其他租户的资源。

**工作量：** L（跨 4 个 RPC 的租户 ID 过滤器 + 存储索引 + 授权检查）| **影响：** 中（多租户管理）| **类型：** 功能

---

## 优先级

| # | 方向 | 影响 | 工作量 | 类型 |
|---|-------|------|--------|------|
| 1 | SQLite 连接共享（20+ `sql.Open` → 1 个共享 DB） | **高**（峰值吞吐量下 2-5 倍延迟改进） | M | 性能 |
| 2 | TOTP 恢复码（丢失设备 = 锁定） | **高**（支持问题 #1——MFA 恢复） | M | 功能/运维 |
| 3 | 外部 HTTP 超时治理（断路器 + 共享客户端） | **高**（防止上游挂起级联） | M | 弹性 |
| 4 | 路由级 CORS 覆盖（`/jwks` 通配符，凭证端点受限） | 中（集成灵活性） | S | 功能 |
| 5 | 多租户管理面（ListByTenant、租户范围审计/会话导出） | 中（SaaS 可管理性） | L | 功能 |

**按 ROI 排列：** 方向 1（SQLite 连接——在写入 WAL 护航下，并发负载的 p99 降级是一个可测量的当前问题）→ 方向 3（上游 HTTP 超时——一个慢 CAEP 推送或挂起的 extauthz 请求可以阻塞子请求 goroutine 池）→ 方向 2（恢复码是 MFA 合规性的基本要求——没有它，丢失设备=支持灾难）→ 方向 5（按租户范围的列表是多租户 SaaS 管理者的痛点）→ 方向 4（CORS 灵活性对嵌入用例很重要，但影响低于其他项）。
