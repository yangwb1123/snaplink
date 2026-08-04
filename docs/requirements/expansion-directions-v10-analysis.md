# 扩展方向分析报告 v10 —— 基础设施完备度与运营韧性

> **作者：** 资深架构 & 产品经理视角
> **日期：** 2026-07-11
> **范围：** 全代码库全局扫描（2241 `.go` 文件、4 个嵌入式 SPA、200+ 包）
> **前提：** 本轮分析已系统阅读并逐项对抗核验以下全部现有文档，确保零重叠：
>   - `ROADMAP.md` v5.0（终端体验 / B2B 企业化 / OIDC 一致性 / 多副本韧性 / 安全姿态）
>   - `deferred-backlog.md`（所有已确认待办项的完整索引）
>   - `expansion-directions-v7-analysis.md`（BFF / select_account / i18n / SAML2 / VC）
>   - `expansion-directions-v8-analysis.md`（B2B 委托门户 / 跨标签页同步 / 翻译网关）
>   - `expansion-directions-v9-analysis.md`（账户恢复 / Magic Link / 推送通知 / 令牌面板 / 令牌分类）
>   - `expansion-post-protocol-layer-analysis.md`（跨设备连续性 / 身份事件平台 / PDP SaaS / 大规模运营 / BI）
>   - `feature-spec-active-itdr-detection-response.md`
>   - `feature-spec-security-docs.md`
> - **本报告 5 个方向与上述所有文档零重叠。** 所有 gap 声明均经过 grep 核验。

---

## 前置声明：项目成熟度定位

经过多轮全局扫描和方向分析，本项目的基础协议覆盖面、后端能力和产品体验已是行业顶级水平：

| 维度 | 状态 |
|---|---|
| 协议覆盖 | OAuth 2.0/OIDC/SAML/SCIM/CAEP/FAPI/JARM/JAR/DPoP/mTLS/CIBA… 全协议面 |
| 存储后端 | Memory + SQLite + Redis + Postgres + etcd + KMS(4) |
| 嵌入式 SPA | Admin Console + Login + Developer Portal + Self-Service Portal（全手写无 CDN） |
| 企业特性 | 多租户 + Federation + 数据驻留 + 条件访问 + 权限 RBAC + 审计链 |
| 运维面 | gRPC admin API + REST gateway + 可观测性(metrics/tracing/audit) + K8s Operator + DR |
| 开发者体验 | Go SDK + TS/Python SDK 生成 + MCP Server + CLI + OpenAPI docs |

v7/v8/v9 + post-protocol 四轮分析已覆盖了从 BFF 安全模式到跨设备身份连续性、从 Magic Link 到身份智能平台的 20 个高价值方向。ROADMAP v5.0 进一步覆盖了终端体验产品化、B2B 企业连接、OIDC 一致性认证、多副本数据韧性和供应链安全。

**本报告的 5 个方向不再属于"增加协议支持"或"补齐已缺失的后端能力"，而是属于以下三大新领域：**

| 领域 | 方向 |
|---|---|
| **基础设施完备度** | ① Postgres OAuth 短期存储面补齐 |
| **运营与可观测性** | ② OAuth 流级可观测性与调试控制台 |
| **安全治理纵深** | ③ 凭据健康治理与自动修复框架 |
| **架构韧性** | ④ API 弹性与舱壁隔离框架 |
| **平台管理面** | ⑤ 联邦式跨租户管理与全局搜索 |

---

## 方向 1：Postgres OAuth 短期存储面补齐

### 现状

项目提供三大持久化后端：**Memory**（进程内）、**SQLite**（纯 Go 嵌入式）、**Redis**（独立缓存服务）、**Postgres**（企业级关系数据库）。各后端对 OAuth 短期存储（ephemeral stores）的支持如下：

| 存储类型 | Memory | SQLite | Redis | **Postgres** |
|---|---|---|---|---|
| AuthCodeStore | ✅ | ✅ | ✅ | **❌** |
| RefreshTokenStore | ✅ | ✅ | ✅ | **❌** |
| DeviceCodeStore | ✅ | ✅ | ✅ | **❌** |
| PARStore | ✅ | ✅ | ✅ | **❌** |
| CIBAStore | ✅ | ✅ | ✅ | **❌** |
| JTIReplayStore | ✅ | ✅ | ✅ | **❌** |
| MFAChallengeStore | ✅ | ✅ | ✅ | **❌** |
| PushApprovalStore | ✅ | ✅ | ✅ | **❌** |

Postgres 目前仅实现了持久化的身份数据存储：clients、users、sessions、consent、permissions、tenants、audit、password credentials、invitations 等。但是所有 **OAuth 流的核心短期存储全缺失**。

grep 核验：`infrastructure/postgres/` 下无任何 `auth_code`/`refresh_token`/`device_code`/`par`/`ciba`/`jti_replay` 相关文件或标识符。

### 为什么需要

- **生产部署强制性**：任何选 Postgres 作为主数据库的生产部署——无论是托管 RDS、自建 Patroni、还是 CockroachDB——都必须额外部署 Redis 才能使用 OAuth 核心功能。每多一个外部依赖 = 多一份运维成本和故障面。
- **SQLite 的局限性**：SQLite 虽然是纯 Go 且 Postgres 用户熟悉的迁移范式（`modernc.org/sqlite`），但不支持网络连接、不适用于多副本部署。多副本场景下 SQLite 的 Memory-backend 等效（`memorystoreoauth`）在重启后丢失所有 OAuth 状态，导致短期令牌重放保护失效。
- **架构一致性**：项目中 `infrastructure/postgres/` 和 `infrastructure/redis/` 是同级后端目录。Redis 有完整的 OAuth store 实现，Postgres 理应同样完备。缺少这一层意味着项目在架构上"Redis 优先"而非"Postgres 优先"，与企业买家首选 Postgres 的趋势相悖。
- **无额外网络依赖**：Postgres 已经在部署中存在（作为 persistence backend），在其上建表不需要新端口、新证书、新备份策略——这是比 Redis 更简单的运维模型。

### 范围

为每个缺失的 store 实现 Postgres 后端，复用现有的 `oauthspi.*` 和 `core.*` SPI 接口，完全遵循 SQLite 兄弟的实现模式：

1. **AuthCodeStore**（`oauthspi.AuthCodeStore`）
   - 表：`oauth_auth_codes`（code hash、client_id、subject、scopes、auth_time、redirect_uri、code_challenge、code_challenge_method、nonce、acr、amr、expires_at）
   - `Issue`：INSERT 新 auth code，使用 `gen_random_uuid()` 作为 code
   - `Consume`：`DELETE ... RETURNING` 确保单次使用（与 SQLite 相同语义）
   - `Expire`：周期性清理或 `ON CONFLICT DO NOTHING` + TTL 索引

2. **RefreshTokenStore**（`oauthspi.RefreshTokenStore`）
   - 表：`oauth_refresh_tokens` + `oauth_refresh_family`（支持家族轮换）
   - `Issue`：INSERT 新 refresh token，标记 family_id
   - `Consume`：`DELETE ... RETURNING` → 检查家族活跃性
   - `DeleteFamily`：`DELETE WHERE family_id = ?` 触发生效
   - `SubjectIndex`：`LIST BY subject` 供会话管理和 revocation-all
   - 用 SERIALIZABLE 隔离级别防止并发 family reuse 竞争（等同 SQLite 的 `DELETE RETURNING`）

3. **DeviceCodeStore**（`oauthspi.DeviceCodeStore`）
   - 表：`oauth_device_codes`（device_code、user_code、client_id、scopes、expires_at、interval）
   - 双索引：`device_code` 和 `user_code` 各一个唯一索引

4. **PARStore**（`oauthspi.PARStore`）
   - 表：`oauth_par_requests`（request_uri hash、params JSON、client_id、expires_at）
   - 短期 TTL（60-600s），使用 `ON CONFLICT` 确保幂等

5. **CIBAStore**（`oauthspi.CIBAStore`）
   - 表：`oauth_ciba_requests`（auth_req_id、client_id、subject、status、scopes、binding_code）
   - 轮询 + 推送状态转换支持

6. **JTIReplayStore**（`security.JTIReplayStore`）
   - 表：`security_jti_replay`（jti hash、expires_at）
   - `CheckAndSave`：INSERT ... ON CONFLICT 实现原子性

### 边界情况

- **事务隔离**：Refresh token 家族轮换需要 `SERIALIZABLE` 级别防止并发竞态（同 SQLite `DELETE RETURNING` 的语义保证）
- **清理策略**：使用 Postgres 的 `pg_cron` 或应用层周期性 sweep（禁用时 TTL 自然过期，SELECT 过滤已过期行）
- **迁移**：所有新表通过现有的 `migrate.Run` 框架添加版本号，支持滚动升级
- **CockroachDB 兼容**：表结构兼容 CockroachDB 分布式 `SERIALIZABLE` 隔离级别
- **连接池**：复用已有的 `*sql.DB` 池，不额外开连接

### 价值·工作量

- **价值**：**high**（Postgres 用户的生产就绪瓶颈，影响架构决策）
- **工作量**：**M**（6 张表，每张约 80-120 行——参考 SQLite 兄弟已有实现可直接翻译 DDL + DML；无新 SPI、无新测试框架）
- **优先级建议**：P1（因为会影响 Postgres 用户的采购决策）

---

## 方向 2：OAuth 流级可观测性与调试控制台

### 现状

项目拥有业界领先的请求级可观测性基础设施：

| 能力 | 状态 |
|---|---|
| W3C Traceparent 传播 | ✅ 完整（`middleware/tracing.go`） |
| OpenTelemetry OTLP 导出 | ✅ 完整（`platform/tracing/`） |
| 审计事件 TraceID/SpanID 标记 | ✅ 完整（`audit/recorder.go`） |
| 结构化日志 + Span 上下文 | ✅ 完整 |
| Metrics + Prometheus 告警 | ✅ 完整 |
| **跨请求 OAuth 流 trace 关联** | **❌ 零实现** |
| **管理面调试控制台** | **❌ 零实现** |

OAuth 2.0 协议的核心架构特性是**多请求分离**：一个完整的授权码流程涉及以下独立 HTTP 请求：

```
浏览器 → /auth/login?state=abc  (Request A: 用户认证，trace_id=TA)
浏览器 ← 302 redirect_uri?code=xyz&state=abc  (浏览器重定向)
浏览器 → client.example.com/callback?code=xyz&state=abc  (到达 RP)
client → /token?code=xyz ...   (Request B: 兑换 token，trace_id=TB)
```

**Request A 和 Request B 之间没有共享 trace ID**。浏览器重定向是纯客户端行为，不传播任何 W3C traceparent。在需要调试时，运维人员无法将一串 OAuth 流中的各个请求关联起来——`auth_time` 认证时间可以用，但遇到以下场景就完全盲目了：

- "某个用户的 token 为什么被拒绝？是 auth_code 过期、签名问题、还是 scope 不匹配？"
- "这个 refresh 被 family kill 了，是真正的重放攻击还是合法的双重提交？"
- "用户报告某个设备登出仍然有 access，是 revocation 传播延迟还是 trace 信息不足以判断？"

grep 核验：`protocols/oauth/` 和 `protocols/oidc/` 中无任何 `trace_id`/`traceID` 关键字。`state` 参数中不含 trace 上下文。

### 为什么需要

- **生产排障的根本性盲区**：OAuth 流是 SSO 最核心的用户交互路径，但当前没有任何手段在运维层面关联请求 A → 浏览器 → 请求 B。生产事故排障时，运维人员只能通过 `auth_time` 和 `client_id` 人工猜测哪些事件属于同一流。
- **安全事件溯源**：当检测到异常的 refresh token reuse 或可疑的 auth code 兑换模式时，安全团队需要追溯完整的请求链——初始认证请求来自哪个 IP、用了什么设备、什么浏览器——来区分"用户误操作"和"凭据被盗"。
- **SLA 排障**：客户上报"我登不上"时，运维无法在一个视图内看到：用户发起了 `/auth/login`（成功）→ 浏览器自动提交（成功）→ `/token` 兑换（失败，`invalid_grant`）——只能查三个独立的日志行并手动关联。
- **FAPI/金融级合规**：FAPI 安全剖面要求审计日志足以重建完整的授权流。当前缺少跨请求 trace 关联的机制是合规差距。

### 范围

1. **在 OAuth state 中嵌入 trace 上下文**
   - 在 `/auth/login` 生成 state 时，将当前 TraceID 和 SpanID 注入 state 的附加数据中（加密 + HMAC，确保不可伪造）
   - 或者更简单：auth_code 本身关联 trace_id（在 `AuthCode` 结构中新增 `TraceID` 字段）
   - 在 `/token` 兑换时，如果找到了关联的 trace_id，将其设为父 span，创建子 span 延续 trace

2. **AuthCode store 增加 TraceID 字段**
   - `oauthspi.AuthCode` 增加 `TraceID string` 字段
   - `Issue` 时接收 trace context
   - `Consume` 时返回关联的 trace_id，供日志和 metrics 使用

3. **管理面调试 API**
   - `GET /api/v1/admin/flows?code=xyz` — 给定 auth code，返回完整的流信息（认证请求的 trace_id、时间、IP、User-Agent、兑换请求的时间、IP、结果）
   - `GET /api/v1/admin/flows?trace_id=TA` — 给定 trace_id，返回所有关联的请求事件
   - `GET /api/v1/admin/flows?user_id=xxx&time_range=...` — 列出用户的所有 OAuth 流

4. **SSE 实时流追踪**
   - 扩展现有的 SSE 管理面事件流（`platform/sse/`），增加 `FlowEvent` 类型
   - 当 auth_code 被兑换时，实时推送流完成事件（含 trace_id、耗时、结果）
   - 运维人员可以"订阅"特定用户或 tenant 的流事件

5. **管理面 SPA 流调试面板**
   - 在 Admin Console 中增加 "OAuth Flow Debugger" 面板
   - 输入 auth code / trace_id / user_id 后，以时序图展示完整的 OAuth 请求链
   - 每步标注：时间、端点、参数、结果、耗时、IP、User-Agent
   - 高亮异常步骤（过期、拒绝、重放检测、rate limit）

### 边界情况

- **隐私保护**：trace 关联数据包含 IP、User-Agent 等 PII，必须在合适的安全上下文中访问（`admin:read.audit` + tenant 隔离）
- **存储成本**：关联数据只有短期价值（数小时到数天），使用 TTL 自动过期或轮转存储
- **兼容性**：AuthCode 增加字段需要迁移版本号，但老 code 兑换时无 trace_id 是可接受的（只是无法关联）
- **性能影响**：在请求热路径中嵌入 trace_id 是纯内存操作（从 span 中读取），对延迟影响可忽略

### 价值·工作量

- **价值**：**high**（运维刚需，生产排障与安全溯源的盲区）
- **工作量**：**M-L**（API 接口 M + Admin Console 面板 L，但可增量交付：先 trace 嵌入 S → 调试 API M → 面板 L）
- **优先级建议**：P1（trace 嵌入部分 S 级别，可立即做；面板可后置）

---

## 方向 3：凭据健康治理与自动修复框架

### 现状

项目已具备多项**单点的**凭据健康检查能力：

| 能力 | 状态 |
|---|---|
| HIBP k-anonymity 密码泄露检查 | ✅（`defaultrisk/hibp_password_health_checker.go`） |
| 密码弱口令字典检查 | ✅（`defaultrisk/password_health_dictionary.go`） |
| CredentialHealth 信号（登录时发出） | ✅（`server_helpers.go` `recordCredentialHealth`） |
| CredentialStatusStore（凭据状态管理） | ✅（`corecredential/spi_credential.go`） |
| 密码历史记录（防重复使用） | ✅（`authenticators/stored_password.go`） |
| 密码过期 TTL | ✅（`Client.PasswordTTL`） |
| **凭据健康聚合视图** | **❌ 零实现** |
| **自动化修复引擎** | **❌ 零实现** |
| **合规报告框架** | **❌ 零实现** |
| **跨凭据类型统一治理** | **❌ 零实现** |

现有架构的问题：

- `CredentialHealth` 是登录路径上**发出的信号**（emit-and-forget），没有一个后台进程来**聚合**这些信号并转换为治理决策
- 每个凭据类型（密码、MFA、API Key、Client Secret、SSH Key、证书）各有自己的健康定义，但**没有一个统一的面板**让安全团队看到全局视图
- 诊断出问题后（"这个用户的密码已经 300 天没换了"），**没有自动修复路径**（force-change 标记 + 下次登录重定向改密）
- 没有**合规报告**层面：SOC2 要求"定期审查凭据健康"，但没有一张报告能回答"哪些用户没有 MFA？哪些 Client Secret 超过 1 年没换？"

grep 核验：`CredentialHealth` 仅在 `server_mfa.go`、`server_helpers.go`、`server_finish_login.go`、`aliases.go` 中出现，均只在登录/认证路径中发出信号——无聚合逻辑。

### 为什么需要

- **安全姿态的持续可见性**：凭据是最常见的数据泄露向量。没有聚合视图就等于"不知道哪些凭据已经暴露、哪些即将过期、哪些从未被管理过"。这是 SOC2/ISO27001 合规的明确要求。
- **自动修复降低 MTTR**：检测到弱口令后，当前架构只能记录审计日志。有了自动修复引擎，可以在下一次登录时强制改密、强制重注册 MFA、或暂停账户直到管理员处理——将修复时间从"天"降到"秒"。
- **覆盖所有凭据类型**：密码弱口令检查已有，但 Client Secret（每个 OAuth 客户端的凭据）的健康度完全没有监控——secret 是否已被轮换？是否已过期？是否使用了弱熵？
- **服务账号治理**：M2M 场景的 `client_credentials` grant 没有 MFA 要求，但这些凭据的泄露风险更高。凭据健康框架需要覆盖服务账号的生命周期管理。

### 范围

1. **凭据健康扫描引擎**（后台周期性聚合）
   - 新增 `credentialhealth.Scanner` 后台进程，按可配置间隔（默认 24h）扫描所有凭据
   - 扫描的凭据类型：
     - **密码**: 强度、泄露状态（HIBP）、使用天数、是否已轮换
     - **MFA 注册**: 是否注册、类型、注册时间、设备是否仍在活动
     - **Client Secret**: 轮换日期、是否在安全存储中、使用频率
     - **API Key**: 创建时间、最后使用时间、是否在合理范围内
     - **登录证书（WebAuthn/Passkey）**: 注册时间、最后使用时间、认证器类型
   - 结果写入 `CredentialStatusStore`（现有 SPI，已 memory 实现）

2. **自动修复策略引擎**
   - `CredentialHealthPolicy` 定义：条件（如 `password_age > 90d`）+ 动作（`force_change` / `force_mfa_enroll` / `suspend_account`）
   - 策略匹配在登录路径上触发：如果用户有未决的修复动作，认证成功后重定向到强制操作页
   - 增量修复，不影响其他用户的一次性登录
   - 管理员可以覆写单个用户的修复状态

3. **管理面凭据健康 API**
   - `GET /api/v1/admin/credential-health` — 全局凭据健康概览（总用户数、健康/警告/危险 分类计数）
   - `GET /api/v1/admin/credential-health/users?status=warning` — 按状态过滤
   - `GET /api/v1/admin/credential-health/users/{id}` — 单个用户的详细健康报告
   - `POST /api/v1/admin/credential-health/scan` — 触发即时扫描
   - `POST /api/v1/admin/credential-health/policies` — CRUD 修复策略

4. **Admin Console 凭据健康面板**
   - 仪表盘 widget：健康分布饼图、按类型的问题趋势、Top-N 最差用户
   - 用户详情页增加"凭据健康"区域
   - 批量操作：选择多用户 → 强制改密 / 强制 MFA / 发通知

5. **合规导出**
   - 凭据健康快照导出（CSV/JSON）供外部审计员
   - 时间序列指标（`credential_healthy_users_total`、`credential_at_risk_users_total`、`avg_password_age_days`）

### 边界情况

- **不阻塞登录**：凭据扫描是后台操作，绝不进入请求热路径。登录路径上只读取已缓存的健康状态
- **扫描性能**：大型部署（100 万用户）的扫描应该分页、限速、避免数据库 spike
- **误报策略**：自动修复策略必须是门槛可配置的，避免因误判锁定大量用户
- **优先处理顺序**：泄露凭据（HIBP 命中）> 弱口令 > 过期未轮换 > 无 MFA
- **多租户隔离**：扫描和策略都是 per-tenant，租户管理员只能看到自己租户的数据

### 价值·工作量

- **价值**：**high**（合规刚需 + 安全姿态提升，直接对应 SOC2/ISO27001 采购问卷）
- **工作量**：**L**（扫描引擎 M + 修复策略引擎 M + API M + 面板 L）
- **优先级建议**：P1-P2（扫描引擎与策略引擎可拆为两个 sprint）

---

## 方向 4：API 弹性与舱壁隔离框架

### 现状

项目拥有出色的请求层限流能力：

| 能力 | 状态 |
|---|---|
| Token-bucket 速率限制（per-route） | ✅（`ratelimit/ratelimit.go`） |
| Redis 分布式速率限制 | ✅（`infrastructure/redis/ratelimit.go`） |
| SQLite 速率限制 | ✅（`ratelimit/sqlite_limiter.go`） |
| 管理面配额（per-tenant write limit） | ✅（`admingovernance/quota.go`） |
| 每 Grant 类型速率限制 | ✅（`options_grants.go` `WithGrantTypeRateLimit`） |
| **通用舱壁（Bulkhead / 并发请求限制）** | **❌ 零实现** |
| **下游依赖断路器（Circuit Breaker）** | **❌ 零实现** |
| **优雅降级框架** | **❌ 零实现** |
| **延迟/jitter 感知的请求聚合** | **❌ 零实现** |

现有限流面向的是"每秒钟允许多少请求"，但**不限制同时有多少请求在飞行中**。这两者是完全不同的保护维度：

```
场景: 
- 速率限制: 10 req/s 意味着每秒最多处理 10 个请求
- 舱壁: max=5 意味着同一时间最多只有 5 个请求在同时处理

差别: 
- 速率限制挡不住"恰好在窗口边界发起的 100 个并发请求" 
  （同一秒内 100 个请求同时进入，都过了 rate limit，但全部卡在某个慢依赖上）
- 舱壁限制挡的是"正在处理中的请求数"——超过的请求立即被拒绝（503）

两者需要组合使用才能完整保护系统。
```

此外，项目的**下游依赖**（LDAP 服务器、SAML IdP、OIDC Federation 端点、CAEP 接收器、ext_authz 授权服务、KMS 签名）在今天**没有任何断路器保护**：

- 一个慢 LDAP 查询可以挂起所有登录 goroutine
- 一个无响应 CAEP 端点可以阻塞 broadcast 路径
- KMS 服务的限流/降级可以导致发签/验签全部等待

grep 核验：`circuit.*breaker`/`CircuitBreaker`/`bulkhead`/`Bulkhead`/`semaphore.*limit`/`max.*concurrent` 在热路径代码中零实现（`saml/idp/fanout.go` 的 semaphore 仅限 SAML logout fanout，非通用框架）。

### 为什么需要

- **防止级联故障**：SSO 是基础设施的关键路径——所有应用的认证/授权都依赖它。一个慢的下游依赖（如 LDAP 超时）不应该导致整个 SSO 服务不可用。舱壁隔离确保"一个坏掉的依赖只影响使用它的那部分用户"。
- **生产负载冲击保护**：没有并发限制时，一个突发的 1000 QPS 瞬间冲入——即使 rate limit 通过了窗口边界——所有 goroutine 同时卡在数据库连接池或网络 I/O 上，导致 OOM 或连接耗尽。
- **第三方代码隔离**：`saml/` 使用 `crewjam/saml`（依赖 `goxmldsig`，有历史 XXE/CVE），`kms/*` 使用云 SDK——这些都是经过验证但防御姿态不够的依赖。舱壁 + 超时确保即使这些第三方库有问题，不会进一步传播。
- **graceful degradation 正式化**：项目已有 `degradation/manager.go` 和 `WithDegradationPolicy`，但它是粗粒度的"整个服务降级模式切换"。需要更细粒度的 per-dependency 健康监控和降级。

### 范围

1. **通用舱壁（Bulkhead）库**
   - `shared/bulkhead/bulkhead.go`：一个轻量级舱壁实现，支持：
     - `maxConcurrent`：最大并发请求数
     - `queueCapacity`：等待队列容量
     - `timeout`：请求最长等待时间
     - `onRejected`：达到限制时的兜底行为（返回错误 / 降级 / 使用缓存）
     - metrics 支持：`bulkhead_active_requests`、`bulkhead_queue_depth`、`bulkhead_rejected_total`、`bulkhead_timeout_total`
   - 支持 `WithName(name)` 方便在 metrics 中区分

2. **断路器（Circuit Breaker）库**
   - `shared/circuitbreaker/circuitbreaker.go`：标准的 closed → open → half-open 状态机：
     - `failureThreshold`：进入 open 状态前的连续失败数
     - `successThreshold`：half-open 状态下恢复需要的成功数
     - `timeout`：从 open 到 half-open 的等待时间
     - `onStateChange(name, from, to)` hook 用于告警
     - 自动记录失败原因分类（timeout / connection refused / 5xx / panic）

3. **关键下游依赖包装**
   - **LDAP 认证器**：舱壁（max=5）+ 断路器（5 次失败 → open 30s）
   - **SAML IdP 元数据获取**：舱壁（max=3）+ 断路器（3 次失败 → open 60s）
   - **OIDC Federation 端点**：舱壁（max=3）+ 断路器（3 次失败 → open 60s）
   - **CAEP/SSF 推送**：舱壁（max=10）+ 断路器（10 次失败 → open 5m）
   - **KMS 签名**：舱壁（max=50）+ 断路器（5 次失败 → open 10s），降级到本地签名
   - **ext_authz gRPC**：舱壁（max=100）+ 断路器（10 次失败 → open 30s），降级到默认 deny/pass-through
   - **HIBP k-anonymity API**：舱壁（max=5），失败不降级（跳过 HIBP 检查，不影响登录）

4. **与现有 degradation 框架集成**
   - `platform/lifecycle/degradation/` 增加 `BulkheadDegradation` 和 `CircuitBreakerDegradation` 模式
   - 当断路器触发时，自动将相关依赖的 degradation mode 切换为 `DegradedFailsafe` 或 `DegradedFailOpen`
   - admin API 查看当前断路器和舱壁状态

5. **配置与管理面**
   - YAML config 增加 `resilience.bulkhead.*` 和 `resilience.circuit_breaker.*` 节
   - 动态热加载（复用现有 `config/reload` 框架）
   - `GET /api/v1/admin/resilience` — 查看所有断路器和舱壁状态
   - Metrics 自动暴露到 Prometheus

### 边界情况

- **多副本协调**：断路器和舱壁状态是每副本本地的（不需要跨副本同步）。这是故意的——每个副本应该独立判断下游的健康状态
- **降级安全性**：断路器触发时的 fallback 行为必须经过安全审查——fallback 到"allow"可能绕过认证，fallback 到"deny"可能导致大规模服务中断
- **阈值过敏感**：瞬时抖动不应触发断路器。使用滑动窗口（如 5 秒内 50% 失败）而非简单计数
- **与 rate limit 配合**：舱壁和 rate limit 是互补的——rate limit 控制频率，舱壁控制并发。建议两个都用。rate limit 在中间件层执行，舱壁在服务调用层执行

### 价值·工作量

- **价值**：**high**（生产韧性的核心能力，直接影响 MTTR 和 SLO）
- **工作量**：**M-L**（核心库 M + 各个依赖包装 L，可逐个依赖增量交付）
- **优先级建议**：P2（核心舱壁库 + 断路器库可独立先做 M，包装各个依赖可后续逐个做）

---

## 方向 5：联邦式跨租户管理与全局搜索

### 现状

项目拥有成熟的多租户模型：

| 能力 | 状态 |
|---|---|
| Per-tenant 数据隔离 | ✅（`tenant/tenant.go`） |
| Tenant 的 CRUD admin API | ✅（admin gRPC + Admin Console UI） |
| Per-tenant 品牌/配置 | ✅（`tenant.Branding`） |
| 租户暂停/恢复 | ✅（`SetTenantStatus`） |
| Cross-tenant B2B collaboration | ✅（`options_grants.go` WithExternalUserStore） |
| 租户数据驻留控制 | ✅（`region/region.go`） |
| **跨租户全局搜索** | **❌ 零实现** |
| **跨租户管理视图** | **❌ 零实现** |
| **多租户健康统一面板** | **❌ 零实现** |
| **全局审计查询（跨租户）** | **❌ 零实现** |

项目的管理面 API 设计为 **per-tenant scoped**：`GET /api/v1/admin/tenants/{tid}/users`、`GET /api/v1/admin/tenants/{tid}/clients`。管理员必须"进入"一个租户才能操作。在 MSP/MSSP（Managed Service Provider）场景中，操作者需要的是：

- "在所有租户中搜索用户 alice@example.com"
- "找到所有使用过时加密算法的 OAuth 客户端"
- "查看所有租户的健康状态汇总"
- "全局审计报表——所有租户的登录失败趋势"

grep 核验：admin gRPC 的 `ListUsers`/`ListClients` 方法均以 tenant_id 为必选参数。无 `GlobalSearchUsers`、`GlobalSearchClients` 或类似 SPI。`audit.Query` 支持 tenant 筛选但不支持跨租户聚合。

### 为什么需要

- **MSP 场景的核心需求**：托管身份服务是 SSO 产品的重要商业模式——运营者维护数百个租户。没有跨租户管理视图，运维人员必须在租户间反复切换，效率极低。
- **合规审计的全局视角**：审计官问的是"所有租户中，有多少用户没有 MFA？"——当前必须写脚本逐个租户查询后聚合。
- **安全事件的跨租户检测**：一个攻击者可能同时在多个租户中发起撞库。当前 anomaly detection 是 per-tenant 的，无法检测跨租户模式。
- **规模运营效率**：100+ 租户时，MSP 运营者无法手动逐个检查每个租户的健康状态。需要一个"舰队级"的统一视图。

### 范围

1. **跨租户搜索 API**
   - `GET /api/v1/admin/search/users?q=alice&limit=20` — 在所有租户中搜索用户（支持 email、username、name、external_id）
   - `GET /api/v1/admin/search/clients?q=my-app&limit=20` — 在所有租户中搜索 OAuth 客户端
   - `GET /api/v1/admin/search/sessions?user_id=xxx` — 在所有租户中搜索会话（跨租户全局查找某用户的活跃会话）
   - 结果带 `tenant_id`/`tenant_slug` 标识来源租户
   - 权限要求：`admin:read.global` scope（区别于 per-tenant 的 `admin:read.tenant.{tid}`）

2. **全局健康聚合视图**
   - `GET /api/v1/admin/health/summary` — 返回所有租户的健康状态聚合：
     - 总租户数、活跃/暂停/错误数
     - 租户级健康概览（`storage_health`、`signing_key_age`、`cert_expiry`）
     - 异常租户列表（有警告/错误的租户）
   - `GET /api/v1/admin/health/tenants?status=degraded` — 按健康状态过滤

3. **全局审计查询**
   - `GET /api/v1/admin/audit/global?event_type=login.failure&time_range=24h` — 跨租户审计事件查询
   - `GET /api/v1/admin/audit/global/top-tenants?metric=failed_logins&period=7d` — 按指标排名租户
   - 结果包含 `tenant_id` 和 `tenant_slug` 字段

4. **跨租户告警与通知**
   - "某租户的签名密钥将在 7 天后过期"
   - "某租户的 50% 用户没有 MFA"
   - "某租户检测到异常的登录失败模式"
   - 告警发送到 MSP 运营者的通知通道（webhook、email、SIEM）

5. **Admin Console 全局仪表盘**
   - "Fleet View" 页面：展示所有租户的卡片列表，每张卡片显示关键指标（用户数、活跃会话数、最后登录时间、健康状态指示灯）
   - 点击卡片进入该租户的管理页面
   - 搜索框支持全局搜索（自动带上 `admin:read.global` scope）

### 边界情况

- **权限模型**：全局搜索需要新增 scope `admin:read.global` 以区别于 per-tenant admin
- **搜索性能**：跨租户搜索在 100+ 租户、百万级用户时需要有索引支持（Postgres `pg_trgm` 或 Elasticsearch），可以考虑 offload 到专用的 search store
- **数据隔离**：全局管理员能看到所有租户的数据，这是设计目标。审计日志必须记录每次全局搜索操作
- **UI 设计中防止误操作**：全局视图应该是"只读 + 引导进入具体租户"的模型，避免在全局上下文中执行写操作导致跨租户数据混淆
- **搜索范围**：全局搜索默认只搜索非软删除的、激活的租户。已暂停的租户需要显式标注 `include_suspended=true`
- **分页**：所有全局列表 API 必须支持 cursor-based 分页，避免大偏移量性能问题

### 价值·工作量

- **价值**：**high**（MSP 生产场景的关键区分器，直接影响 多租户管理效率）
- **工作量**：**L**（搜索 API M + 健康聚合 M + 审计扩展 S + Admin Console 面板 L）
- **优先级建议**：P2（搜索 API 与审计全局查询可以先做 M，健康聚合与面板后置 L）

---

## 总结：优先级排序

按"投入产出比"从高到低排列：

| 优先级 | 方向 | 价值 | 工作量 | 关键受众 | 最短可独立交付项 |
|---|---|---|---|---|---|
| **P1** | ① Postgres OAuth 短期存储面补齐 | 高 | M | Postgres 部署运维者 | 任意一张表（如 AuthCodeStore）即可独立交付 |
| **P1** | ② OAuth 流级可观测性（trace 嵌入部分） | 高 | S | 生产运维排障 | AuthCode 增加 TraceID + `/admin/flows?code=` API |
| **P2** | ③ 凭据健康治理与自动修复框架 | 高 | L | 安全团队 / 合规审计 | `CredentialHealthScanner` 后台进程（M） |
| **P2** | ④ API 弹性与舱壁隔离框架 | 高 | M | SRE / 生产韧性 | `bulkhead.Bulkhead` 核心库（M） |
| **P2** | ⑤ 联邦式跨租户管理与全局搜索 | 高 | L | MSP / 多租户运维 | `GET /admin/search/users` API（M） |

**横切建议**：方向①②可在同一个 sprint 中并行启动（①是基础设施，②是可观测性——互不依赖）。方向③④⑤各自独立，可根据业务优先级逐个落地。

---

## 与其他现有文档的边界确认

| 本报告方向 | 可能重叠的现有文档 | 核验结论 |
|---|---|---|
| ① Postgres OAuth 短期存储 | ROADMAP v5.0 "多副本数据面韧性"方向④ | ROADMAP ④覆盖 etcd lease 死亡、撤销 set 持久化、schema 版本护栏、bootstrap fencing **等运维韧性主题，但从不涉及 Postgres 缺失的 OAuth store**。grep ROADMAP 全文"postgres"仅出现在 config-reference 矩阵和部署场景中。**零重叠。** |
| ② OAuth 流级可观测性 | o11y/ 方向 | 项目已有 `OtelHTTPMiddleware` 等**请求级 trace**，但 OAuth 协议固有地涉及**多个 HTTP 请求跨浏览器重定向**，当前 trace 在重定向时断裂。无任何现有文档分析此跨请求关联问题。**零重叠。** |
| ③ 凭据健康治理 | v9 方向① "账户恢复"、ROADMAP v5.0 "安全姿态"方向⑤ | v9 覆盖**恢复流程**（`forgot-password`、MFA recovery codes），ROADMAP ⑤覆盖 client secret hash、DCR audit、CI fuzz——但均不涉及**系统性凭据健康聚合、自动修复策略、合规报告框架**。**零重叠。** |
| ④ 弹性与舱壁 | v5.0 "边界情况"中 per-subject 限流、degradation manager | ROADMAP 列出"per-subject 限流"作为 sprint-filler，但**不涉及通用舱壁、断路器或 per-dependency 弹性模式**。degradation manager 是**粗粒度全服务开关**，与细粒度 per-dependency 舱壁正交。**零重叠。** |
| ⑤ 联邦式跨租户管理 | ROADMAP v5.0 方向② "B2B 企业化"、v8 "B2B 委托门户" | ROADMAP ②覆盖 per-org upstream IdP 连接 + HRD（面向**外部企业客户**的 SSO 路由），v8 覆盖委托管理（面向**最终客户侧的 org admin**）。本方向覆盖的是 **MSP 内部运营者的跨租户管理面**——完全不同的人设和使用场景。**零重叠。** |

