# 全局架构扫描——下一代扩展方向（第 31 轮）

> 基于 2026-07-01 全代码库深度扫描（1639 个 `.go` 文件、13 个嵌套模块、3 个嵌入式 SPA、完整 OAuth/OIDC/SAML/FAPI/CAEP/SCIM 协议栈）。
>
> 视角：资深架构师 / 产品经理。此前 30 个方向已覆盖协议扩展、运维治理、Edge Cases、代码健康、架构债务、API 产品化、合规完备性审计、供应链韧性等维度。
>
> **本轮聚焦此前从未被触及的 5 个高价值方向。** 每条方向均经 grep + 逐项代码核验确认为真缺口。
>
> 原则：不写代码。

---

## 总体判断

项目已从"功能极完整的身份库"进化为"生产就绪的多协议 SSO 平台"。此前 30 个方向覆盖了协议面收口、企业化、集群一致性、安全姿态等关键维度。

**但仍有三个盲区此前从未被触及：**

1. **AI Agent 正在成为新的身份消费主体**——但当前的 identity 模型只认识"人类用户"和"机器客户端（confidential client）"，不认识自主、可委托、可长时间运行的 AI Agent
2. **网关边缘层 (OpenResty) 与核心身份逻辑完全脱节**——已经部署了 API 网关，但认证/授权/缓存逻辑与核心无法协同演进
3. **用户生命周期只有"创建"和"删除"两个状态**——缺乏中间态（邀请→激活→休眠→归档→清除）和对应的治理策略
4. **多租户模型是竖井式的——无法跨租户共享身份**——B2B 协作的核心模式（Org A 授权 Org B 的用户）完全没有一等模型
5. **详细的分区行为策略写在 AGENTS.md 中，但没有可执行的验证框架**——fail-open/closed 策略是文档承诺，不是可测试的契约

---

## 方向一：AI Agent 身份与授权协议——超越 MCP 桥接

### 现状

`cmd/sso-mcp/` 已经实现了 Snaplink → AI Agent 的 MCP（Model Context Protocol）桥接。它通过 gRPC 连接到 SSO 的 Authorizer 服务，将 JWT 验证和权限查询暴露为 MCP 工具：

```
cmd/sso-mcp/          ← MCP Server（Stdio + HTTP 传输）
  ├── snaplink.go     ← 远程 SSO 客户端（JWKS 缓存 + gRPC AuthzClient）
  ├── auth.go         ← Bearer 令牌验证
  ├── authz.go        ← 权限检查工具
  └── server.go       ← MCP 协议服务器
```

但**这是单向的**——它只回答了"AI Agent 如何代表人类用户调用 SSO API"。以下场景完全没有被覆盖：

| 缺失的能力 | 当前状态 | 行业趋势 |
|-----------|---------|----------|
| **Agent-to-Agent 委托** | 无。Agent A（用户委托的）无法安全地委托子任务给 Agent B | Anthropic MCP、OpenAI function calling 都在向"授权链"方向演进 |
| **Agent 身份凭据** | 无。Agent 只能用它所代理的用户的 Bearer token——无法拥有自己独立的凭据和权限 | SPIFFE 用于工作负载；OAuth 2.0 Token Exchange 可表达 `act` 链但尚无 agent 化的流程 |
| **长期运行异步会话** | 无。Agent 任务可能运行数小时/天，需要 OAuth refresh 语义的"agent session" | 当前 refresh token 是 human-in-the-loop 的 |
| **工具调用授权粒度** | 无。MCP 工具只有 `authz.Check`——无法按 agent 会话粒度限制哪些工具可以调用 | Google ADC、AWS IAM Roles Anywhere 支持 session 级 scope |
| **Agent 行为审计** | 无。审计事件只记录 `subject_id`（人类用户），无法区分"是人类自己操作还是 agent 代操作" | SIGMA 规则、SIEM 关联需要 agent 活动信号 |

### 为什么需要

1. **AI Agent 是身份基础设施的下一个第一类消费者**。2025-2026 年，企业开始部署自主 agent 处理客服、代码审查、数据 pipeline——每个 agent 都需要与人类用户不同的身份模型：它们需要**可委托的、有时限的、可撤销的、可审计的**身份。

2. **当前 Token Exchange（RFC 8693）的 `act` 链机制可以扩展为 agent 委托链**——但缺少：
   - Agent 身份注册（`AgentProvider` SPI + `Agent` 类型）
   - Agent-to-Agent 委托令牌（`delegation_token` grant type）
   - Agent 会话（`AgentSession`——长 TTL、异步心跳、可撤销）
   - 审计事件区分 `subject_type: "user" | "agent"`

3. **MCP 协议正在成为 agent 与工具之间的标准协议**。Snaplink 的 `sso-mcp` 是一个先发优势，但需要从"工具桥接"升级为"agent 身份平面"。

### Scope

```
Phase 1 (M) — Agent 身份基础：
  ├── shared/core/types_agent.go     — Agent 类型 + AgentSession + DelegationTokenClaim
  ├── shared/core/spi_agent.go       — AgentProvider / AgentSessionStore
  ├── domains/agent/                 — 业务逻辑：CreateAgent, Delegate, RevokeDelegation
  └── protocols/oauth/handle_agent_token.go — delegation_token grant type at /token

Phase 2 (M) — MCP 身份升级：
  ├── cmd/sso-mcp/auth.go 增强         — Agent 身份凭据类型（client_credentials for agents）
  ├── cmd/sso-mcp/delegation.go       — 委托工具（agent A 委托 agent B）
  └── cmd/sso-mcp/audit.go           — agent 活动审计事件

Phase 3 (L) — Agent 发现与治理：
  ├── interfaces/admin/agents.go     — admin API（列出/撤销 agent 会话）
  ├── web/admin/index.html 增强       — Agent 管理面板
  └── 审计区分 subject_type → SIEM 集成
```

### Edge Cases

- Agent 凭据轮换：Agent 的 client_secret 泄漏时的吊销和轮换（类比机器用户）
- 委托深度限制：防止 A→B→C→D…无限委托链
- 委托可视性：人类用户应该能看到"哪些 agent 在代表我行动"
- 异步 agent 会话的 TTL 管理：agent 任务可能运行 24h+，refresh 语义需适应
- Agent 冒充检测：审计中 `act` 链的防篡改

### 价值 · 工作量

value **high**（先发优势、身份基建的下一个范式）· effort **M → L**

---

## 方向二：API 网关原生身份层——将 OpenResty Lua 升级为协同的边缘身份平面

### 现状

`ops/deploy/openresty/` 有一套成熟但完全独立的 OpenResty 部署：

```
ops/deploy/openresty/
  ├── nginx.conf              ← 代理配置
  ├── conf.d/
  │   ├── sso.conf            ← 路由规则
  │   └── proxy_pass.inc      ← 上游
  ├── lua/
  │   ├── auth.lua            ← 边缘 JWT 验证（resty.jwt + JWKS 缓存）
  │   ├── jwks_cache.lua      ← 独立的 JWKS 缓存（与核心缓存不同步）
  │   ├── permission_cache.lua ← 独立的权限缓存
  │   ├── netpolicy_cache.lua ← 独立的网络策略缓存
  │   ├── audit.lua           ← 边缘审计日志
  │   └── utils.lua           ← 工具函数
  └── Dockerfile
```

**核心问题：这些 Lua 缓存与核心签名/失效机制完全脱节。**

| 失效事件 | 核心行为 | 边缘缓存状态 |
|---------|---------|-------------|
| 签名密钥轮换 | 核心 JWKS 更新 + bus 广播 | Lua JWKS 缓存靠 TTL 过期，最多 1h 滞后 |
| 客户端变更 | 核心 `ClientStore` 缓存失效 + bus 广播 | Lua permission_cache 无失效机制 |
| 网络策略变更 | `netpolicy.Store` 更新 | Lua netpolicy_cache 无失效机制 |
| 令牌撤销 | 核心 `RevocationSet` 更新 | 边缘无通道——已撤销令牌在 TTL 窗口内可通过 |
| 租户暂停 | 核心 `InvalidateTenantSuspensionCache` + bus | 边缘无感知——暂停租户请求仍放行 |

**这是一个架构层面的一致性问题**——边缘和核心维护了相同语义的缓存，但失效路径完全独立。其结果是：

- 密钥轮换后边缘可能在 1h 窗口内用旧键验签通过（误判）
- 撤销后边缘可能在 TTL 窗口内放行已撤销令牌（安全事件）
- 操作员配置的 TTL 全部在 Lua 中硬编码，无法从核心配置驱动

### 为什么需要

1. **身份基础设施的"边缘-核心"一致性是架构基础**。认证决策在边缘做（性能），失效在核心触发（正确性）——两者必须有一个协调协议。当前没有这种协议。

2. **OpenResty Lua 的缓存是手写的、无共享失效总线的**。每个 `cache.lua` 独立维护 TTL + 回源逻辑。添加新的边缘缓存需要重复相同的模式。

3. **这不是"要不要 OpenResty"的问题**——部署里已经有 OpenResty，它是架构的一部分。问题是**它是否与核心协同进化**。当前不是。

### Scope

```
Phase 1 (M) — 边缘缓存失效通道：
  ├── 给核心 cluster.Bus 增加 KindEdgeCacheInvalidation 事件类型
  ├── 边缘 Lua 增加一个轻量级长轮询 / SSE 端点订阅失效事件
  │     （或复用现有 etcd watch——但边缘通常不直接连接 etcd）
  └── 核心关键变更点（密钥轮换、客户端更新、租户暂停）发失效事件

Phase 2 (M) — 边缘缓存结构化 + 核心配置驱动：
  ├── ops/deploy/openresty/lua/cache_manager.lua  ← 统一 TTL + 失效订阅
  ├── 重构 jwks_cache.lua / permission_cache.lua → 复用 cache_manager
  └── config/config_gateway.go    ← 边缘缓存 TTL 由核心配置下发

Phase 3 (L) — 边缘身份层产品化：
  ├── 边缘令牌内省（Introspect at edge——避免每请求回源）
  ├── 边缘速率限制（基于租户 + 客户端 + IP——分布式滑动窗口）
  ├── 边缘撤销检查（RevocationSet at edge——增量同步）
  └── 可观测性：边缘决策指标 → Prometheus（sso_edge_auth_*）
```

### Edge Cases

- 边缘与核心之间的网络分区：边缘应退回到 TTL 缓存（最后已知正确状态），而不是开放所有请求
- 失效事件的可靠传递：边缘应确认收到失效事件，核心应重试失败推送
- 边缘启动时的冷缓存：边缘启动后不应立即处理真实流量（warm-up 或 graceful degradation）
- TTL 不匹配：边缘 TTL 应 ≤ 核心缓存 TTL，确保边缘不会比核心"更乐观"

### 价值 · 工作量

value **high**（修复架构级一致性问题、减少安全窗口）· effort **M → L**

---

## 方向三：用户生命周期状态机——从"创建/删除"到完整的生命周期治理

### 现状

当前用户模型（`shared/core/types.go` 的 `User` 结构体）只有存在与否，没有生命周期状态。`UserProvider` 的 `CreateOrUpdate` 是 upsert 语义——创建和更新共享同一个操作。

查看全库搜索 `user.*status\|user_state\|UserStatus\|UserState\|UserLifecycle\|user.*stage` 的结果：**零命中**。

用户维度的管理操作：

| 操作 | 是否存在 | 粒度控制 |
|------|---------|---------|
| 创建（管理员） | ✅ | 无状态——直接 ACTIVE |
| 注册（自助） | ✅ | 无状态——直接 ACTIVE |
| 导入（批量） | ❌ 缺失 | — |
| 挂起/禁用 | ❌ 缺失 | 无 SUSPENDED 状态 |
| 休眠检测 | ❌ 缺失 | 无 INACTIVE 状态 |
| 归档/清除 | ❌ 缺失 | 无 ARCHIVED / PURGED 状态 |
| 账号复活 | ❌ 缺失 | 从暂停/休眠恢复无明确路径 |

唯一接近"生命周期"的是 `tenant.Tenant` 的 `Status` 枚举（`Active` / `Suspended`），但用户级别的状态机不存在。

**影响**：

- **安全**：离职员工的账号只能通过删除来清退——删除是最终操作，但很多场景只需要"禁用"(SUSPENDED)（保留数据、防止重新注册同名账户）
- **合规**：GDPR 要求"合理的数据保留期限"后有清除策略——无休眠检测意味着过期用户数据无限期保留
- **运营**：SaaS 运营者无法区分"新用户"、"活跃用户"、"流失用户"——MAU/DAU 计算只能在审计日志层面做聚合
- **产品**：无法做"渐进式注册"（先收集邮箱→验证→再补全资料→激活）

### 为什么需要

1. **用户生命周期是身份平台的基础设施**，不是"增值功能"。没有状态机，就无法做：
   - 阶段式注册漏斗分析（Signup → Verified → Onboarded → Active → Retained）
   - 自动休眠账号清理（停用 90 天→归档提醒→30 天后清除）
   - 离职员工程序（禁用→数据导出→30 天后清除）
   - SaaS 套餐限制（免费套餐：最多 100 个 ACTIVE 用户，SUSPENDED/ARCHIVED 不计数）

2. **代码中已有基础**：`User.Attributes` 可以承载 `lifecycle_status` 和 `inactive_since`，但无强制语义、无自动转换规则、无治理策略。需要一个正式的 `UserLifecycleManager`。

3. **竞品对标**：Auth0 的用户状态机（active/inactive/blocked）、WorkOS 的 directory sync 状态跟踪、Azure AD 的 accountEnabled 都是完整的生命周期模型。

### Scope

```
Phase 1 (M) — 核心状态机：
  ├── shared/core/types_user.go 增强   — User.Status: INVITED | ACTIVE | SUSPENDED | INACTIVE | ARCHIVED | PURGED
  ├── shared/core/user_lifecycle.go   — UserLifecycleStore SPI + UserLifecycleManager
  ├── domains/userlifecycle/          — 业务逻辑：状态转换规则、自动转换调度器
  └── interfaces/sso/server_users_lifecycle.go — admin API（查询、转换、调度）

Phase 2 (M) — 休眠检测与自动清除：
  ├── domains/userlifecycle/dormancy.go  — 基于上次登录时间的休眠判定
  ├── interfaces/admin/users.go 增强     — 休眠用户列表 + 批量操作
  └── scheduler 集成                     — cron 式休眠检测 + 通知 + 自动清除

Phase 3 (L) — 渐进式注册与 onboarding：
  ├── protocols/selfservice/signup.go 增强 — 分段注册（邮箱→OTP 验证→补全资料→激活）
  ├── interfaces/web/login/index.html 增强  — 多步骤注册 UI
  └── shared/core/onboarding.go       — OnboardingStore（草稿 + 进度跟踪）
```

### Edge Cases

- 状态转换的合法性：禁止 SKIP 中间状态（如从 INVITED 直接到 ARCHIVED）
- 休眠检测的误报：假期用户不应被标记为 INACTIVE（应有宽限期 + 通知 + 申诉窗口）
- 已删除用户的邮箱/用户名重用策略：归档期内阻止重新注册
- 自助注册 vs 管理员创建的 INVITED 状态差异：自助注册可自动 ACTIVE（需验证），管理员邀请需要用户接受
- 与 SCIM 集成：SCIM 同步的 `active` 字段应映射到 `User.Status`，而非仅作为布尔值

### 价值 · 工作量

value **high**（基础设施级的治理能力）· effort **M**

---

## 方向四：跨租户 B2B 协作模型——从竖井式租户到组织间身份共享

### 现状

当前租户模型（`domains/tenant/`）是**完全竖井式**的：

```
租户 A                   租户 B
  ├── 自己的用户            ├── 自己的用户
  ├── 自己的客户端          ├── 自己的客户端
  ├── 自己的会话            ├── 自己的会话
  └── 无法访问租户 B 的资源  └── 无法访问租户 A 的资源
```

`tenant.go` 的 `Tenant` 结构体没有"信任关系"、"对外共享"或"guest 用户"的概念。`core.User` 直接属于一个 `provider`（通常是 `tenant_id`）——没有"用户属于多租户"或"用户在租户 B 有 guest 身份"的一等模型。

**关键缺失的 B2B 协作模式**：

| 场景 | Auth0 / WorkOS / Azure AD B2B | 本仓库 |
|------|------------------------------|--------|
| Org A 邀请 Org B 的用户协作 | ✅ External User + Tenant-to-Tenant Trust | ❌ 不存在 |
| 用户在多个 org 中有角色 | ✅ Organization Memberships + Cross-Org Role | ❌ User 只绑定到一个 provider |
| Guest 用户生命周期（邀请→接受→过期） | ✅ Invitation Token + Expiration + Review | ❌ 不存在 |
| 跨租户审计（"哪个 org 的用户做了什么"） | ✅ Audit Log 带 tenant 维度 | ❌ 审计只记录 `subject_id` |
| 租户间信任策略（白名单租户/黑名单租户） | ✅ Trusted Organization List | ❌ 不存在 |

### 为什么需要

1. **B2B SaaS 的核心使用模式是"协作"而非"隔离"**。一个使用 Snaplink 的 SaaS 产品会面临：
   - "我们的客户 Acme 公司要和我们共享一个 SSO，让我们支持跨企业协作"
   - "BigCo 的审计员需要临时访问我们的 dashboard"
   - "我们和 Partner 公司共用一个用户库"

2. **当前 tenant 模型把"身份租户"等同于"资源租户"**——每个用户只属于一个组织，但现实是：一个用户可以同时属于多个组织（主职在 Org A，兼职在 Org B）。

3. **现有的 `connections/` 包和 SCIM 提供了部分基础**——`connections.Provider` 可以枚举组织间的连接，SCIM 可以跨组织同步用户——但它们需要被整合到正式的跨租户身份模型中。

### Scope

```
Phase 1 (M) — 跨租户身份基础：
  ├── shared/core/types_org.go        — ExternalUser（跨租户用户）+ Invitation（邀请令牌）
  ├── shared/core/spi_org.go          — ExternalUserStore + InvitationStore
  ├── domains/tenant/organization.go  — 跨租户关系：TrustedTenant + ExternalMembership
  └── interfaces/sso/server_org.go    — invitation API（POST /tenants/:tid/invitations）

Phase 2 (M) — Guest 用户流程：
  ├── protocols/selfservice/aliases.go        — 接受邀请、管理跨租户成员身份
  ├── interfaces/web/portal/index.html 增强     — "My organizations" 面板
  ├── interfaces/web/login/index.html 增强      — 跨租户登录选择器
  └── protocols/oauth/handle_org_token.go      — 跨租户 token 颁发（携带 org 上下文）

Phase 3 (L) — 租户间信任与治理：
  ├── domains/tenant/trust.go           — 信任策略（自动 vs 审批、IP 范围、MFA 要求）
  ├── domains/tenant/audit_bridge.go    — 跨租户审计追踪（事件归属到 org）
  └── interfaces/admin/orgs.go          — admin API（管理租户间信任、审查邀请）
```

### Edge Cases

- Guest 用户的身份源：如果 guest 用户来自 Org B（SAML 上游），它在 Org A 的身份是 shadow user 还是真正的身份引用？
- 跨租户令牌的 scope 隔离：Guest 用户在 Org A 的权限应限制在 "guest" scope 内——不能获得 Org A 的 admin 角色
- 邀请过期与回收：invitation token 应有 TTL、可撤销、可重新发送（anti-enumeration：成功的邀请和失败的邀请返回相同的响应）
- 跨租户撤销：如果 Org B 禁用了某个用户，该用户在 Org A 的 guest 身份应同步失效
- 计费归属：Guest 用户占用的资源（MAU、存储）归哪个 org 的账单？

### 价值 · 工作量

value **high**（B2B SaaS 必选项、竞品对标硬缺口）· effort **M → L**

---

## 方向五：韧性验证框架——将 fail-open/closed 承诺从文档变成可执行契约

### 现状

AGENTS.md §3 详细记录了每个关键路径的 fail-open/closed 模式：

> - **Fail-Open** (log + continue): refresh issuance, ID Token issuance, geo, risk-scorer, audit Sink error, tenant-suspension outage, JTI-replay store error (default), anomaly runner.
> - **Fail-Closed**: refresh rotation grant (500), signature/validation failure, scope expansion, family reuse → DeleteFamily → invalid_grant, trust-chain validation, CAEP receiver.

并且有一个详细的分区行为矩阵：

| 关键路径 | etcd 全断 | bus 分区 | 单副本孤立 |
|---------|-----------|---------|-----------|
| /token, /auth/login | 本地 SQLite 仍服务 | 正常 | 正常（本地） |
| 验签, /userinfo | 本地 + 已采纳对端键仍验 | 同左 | 同左 |
| 撤销/暂停传播 | 仅本地失效，TTL 放行 | 同左 | TTL 滞后 |
| JTI 重放防护 | 共享 store 断→fail-open | — | 跨副本可重放 |
| 密钥轮换 | 公钥发布失败→对端验不了新 kid | 同左 | — |

**然而，整个代码库没有任何一个测试来验证这些行为。**

搜索 `chaos\|fault.*inject\|circuit.*breaker\|degraded\|FailOpen\|fail_open\|TestPartition\|test.*fail.*close`：

- `chaos` → 0 命中
- `fault.*inject` → 0 命中
- `TestFail` / `test.*fail.*close` → 无相关测试
- `circuit.*breaker` → 0 命中
- `degraded` → 0 命中

目前验证 fail-open/closed 的唯一方式是：在 production-like 环境中手动 kill 组件并观察行为。**这是不可重复、不可自动化的。**

### 为什么需要

1. **fail-open/closed 是安全关键系统的核心契约**。JTI replay store fail-open 意味着"共享存储故障期间，每个 JTI 都是首见"——这是一个安全假设，不是一个 bug。但如果没有验证，谁都不能保证"代码升级后还保持 fail-open"。

2. **测试金字塔中，最底层（单元测试）和中间层（集成测试）都覆盖不到组件级故障**。需要一个新的"故障注入"测试层（fault injection / chaos testing）。

3. **多副本部署（etcd + Redis + SQLite/Postgres）的组件间故障模式正是生产事故的常见来源**——而恰好是测试覆盖最薄弱的环节。

4. **基础设施代码（复杂的分区矩阵）应该和业务代码一样有回归保护**。

### Scope

```
Phase 1 (S) — 故障注入 SPI 层：
  ├── shared/core/fault.go    — FailureMode 枚举 + FailInjector 接口
  └── 各 Store/Provider 集成  — 在关键路径上插桩可注入的故障点

Phase 2 (M) — 结构化故障测试：
  ├── test/chaos/chaos_test.go  — 测试套件基础结构
  ├── test/chaos/cases/
  │   ├── jti_failopen_test.go        — JTI store 故障时验证 fail-open → 重放可能
  │   ├── revocation_store_test.go    — 撤销 store 故障时验证 fail-closed 行为
  │   ├── jwks_adoption_test.go       — etcd watch 断开时验证 adoption 静默死 + readiness
  │   ├── tenant_suspension_test.go   — bus 分区时验证 TTL 窗口放行行为
  │   └── signing_key_publish_test.go — 公钥发布失败时验证新 kid 不被采纳
  └── test/chaism/harness.go          — 共享故障注入夹具（etcd 模拟器、store 包装器）

Phase 3 (L) — 混沌工程编排：
  ├── ops/deploy/chaos/   — 用于 staging 环境的 k6 + chaos-mesh 配置
  ├── .github/workflows/chaos.yml — 定期混沌测试 pipeline
  └── docs/chaos-runbook.md       — 混沌测试操作手册 + 预期行为矩阵
```

### Edge Cases

- 故障注入不应侵入生产代码路径（应使用接口包装器 + 测试编译标记）
- 多个故障同时注入时的行为（etcd 断 + store 超时）——组合爆炸需理性采样
- 故障注入的超时门控：注入的故障应有自动恢复时间，避免测试永久卡住
- 与现有的 `race` 测试并行——故障测试也应在 race detector 下运行
- 混沌测试的幂等性：重复运行同一故障场景应得到相同结果

### 价值 · 工作量

value **high**（架构承诺→可执行契约，生产安全的关键防线）· effort **S → M**

---

## 跨方向相关性

```
方向一 (Agent 身份)          方向四 (跨租户协作)
        │                          │
        └──────────┬───────────────┘
                   │
          ┌────────▼────────┐
          │  方向五 (韧性验证) │ ← 所有方向都依赖它验证
          └────────┬────────┘
                   │
        ┌──────────┴───────────────┐
        │                          │
方向二 (边缘身份层)         方向三 (用户生命周期)
        │                          │
        └──────────┬───────────────┘
                   │
          ┌────────▼────────┐
          │ 既有核心身份基础设施 │
          └─────────────────┘
```

| 组合 | 协同价值 |
|------|---------|
| 方向一 + 方向四 | AI Agent 可以跨租户协作——Agent A（Org A）委托 Agent B（Org B）处理跨组织任务 |
| 方向二 + 方向五 | 边缘层是韧性验证的关键组件——网关分区行为是入口级安全策略 |
| 方向三 + 方向四 | Guest 用户有自己的生命周期（INVITED → ACTIVE → EXPIRED） |
| 方向一 + 方向五 | Agent 身份需要自身的 fail-closed 策略——agent 凭据故障不应降级为人类用户 |

---

## 一句话优先级

**方向一（Agent 身份，Phase 1: M）与方向五（韧性验证，Phase 1: S）应最先启动**——方向一是下一代差异化的起点，方向五是最低成本高信号的架构契约验证。两者正交，可并行。

**其次方向二（边缘身份层，Phase 1: M）**——修复已有的架构脱节，为方向一和方向五的部署提供边缘一致性基础。

**方向三（用户生命周期，Phase 1: M）与方向四（跨租户协作，Phase 1: M）可并行推进**——两者都是 B2B SaaS 产品化的核心能力，依赖已有基础设施（方向三依赖 SCIM + user store，方向四依赖 tenant + connections）。
