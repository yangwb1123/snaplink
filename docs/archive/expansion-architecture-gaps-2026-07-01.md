# 资深架构师 / 产品经理视角：全局扫描与高价值扩展方向

> 基于 2026-07-01 全代码库深度扫描（1610 个 `.go` 源文件、55+ 包、7 层架构、3 个嵌入式 SPA）。
>
> 前置声明：此前已有 **40+ 方向分析文档** 覆盖了协议完备性、性能优化、安全纵深、架构债务、运维治理、企业功能、AI Agent、Passkeys、Edge Cases 等几乎所有维度。
>
> **本轮聚焦：此前从未被系统性审视的 5 个高价值方向。** 每条方向经对抗式 grep + 逐行代码核验，与既有 40+ 方向交叉对比，确认为真缺口。
>
> 原则：不写代码。每条锚定具体代码位置或模式。

---

## 总体判断

项目已完成从"身份协议 SDK"到"生产就绪多协议 SSO 平台"的跨越。40+ 方向覆盖了从协议面（OAuth 2.1 / OIDC / FAPI / SAML / CAEP / SCIM）到运维面（HA、灾备、密钥轮换、可观测性）到安全面（抗枚举、Oracle-leak、常量时间、纵深防御）的广阔维度。

**但仍有 5 个结构性和产品层面的盲区此前从未被触及。** 它们不引入新协议或新端点，而是解决**现有能力之间的裂缝**——跨步骤安全模型、跨协议身份融合、多维度限流防护、管理面产品化、以及开发者生态就绪度。

---

## 方向一：多步授权协议中的 TOCTOU 系统分析——登录→MFA→Consent→Token 之间的状态裂缝

### 概况

| 维度 | 值 |
|------|-----|
| 工作量 | **M**（~800 行验证逻辑 + ~400 行集成测试） |
| 价值 | **极高**（安全纵深——现有裂缝可能导致授权绕过） |
| 类型 | 安全纵深 + 正确性 |
| 覆盖检查 | 此前 40+ 方向未覆盖 |

### 当前状态验证

**OAuth 2.0 Authorization Code 流是一个多步协议**，每步之间有状态窗口：

```
Step 1: /auth/login        → 用户认证（密码/WebAuthn/SSO/LDAP…）
Step 2: /auth/mfa (可选)   → 多因素验证（TOTP/SMS/Push/WebAuthn…）
Step 3: Consent (可选)     → 用户授权 scope
Step 4: /token             → 用 code 换取 token
```

**已存在的局部防御**：

| 位置 | 防御 | 覆盖的 TOCTOU |
|------|------|--------------|
| `server_mfa.go:320` | MFA 完成后检查 Client 是否被停用 | ✅ MFA → Consent 之间的 client deactivation |
| `server_login.go:291` | `rejectDeactivatedUser` 在登录时检查 | ✅ 登录时的 user deactivation |
| `consent/challenge.go` | Challenge 绑定 (userID, clientID, scopes, authzDetails) 并限 5 分钟 | ✅ Consent 伪造/重放/过期 |
| `token_authcode.go:154` | `authCodeValidate` 单次消费 + oracle-collapse | ✅ Code 重用/伪造 |

**尚未系统覆盖的 TOCTOU 裂缝**：

| 步骤窗口 | 用户状态变化 | 当前行为 | 风险 |
|----------|------------|---------|------|
| 登录完成 → MFA 开始 | 账户被 SCIM 停用 (`active=false`) | ❌ 不检查——MFA 通过后直接发 token | 已停用用户完成 MFA→获得 token |
| 登录完成 → MFA 开始 | 密码被管理员重置 | ❌ 不检查——旧密码认证的 session 仍可完成 MFA | 密码已改但旧 session 仍有效 |
| 登录完成 → MFA 开始 | 用户被踢出租户 | ❌ 不检查——租户变更未反应到 MFA 流程 | 已移除的租户成员仍可完成认证 |
| MFA 完成 → Consent 提交 | 用户权限 scope 被管理员撤销 | ❌ 不检查——Consent challenge 只验证 scope 匹配，不验证 scope 当前有效性 | 已撤销的 scope 通过 consent 恢复 |
| Consent 完成 → Token 交换 | Auth code 发出到实际使用之间用户被停用 | ❌ 不验证——`authCodeValidate` 不检查 user active 状态 | 已停用用户的 code 仍可换 token |
| Consent 完成 → Token 交换 | Client 被管理员停用 | ⚠️ 部分检查——`authCodeValidate` 查 client 存在性但不查 active 状态 | 已停用的 client 的 code 仍可用 |
| 任意步骤之间 | 会话 (session) 被管理员/用户撤销 | ❌ 不检查——多步流程不使用 session 有效性验证 | 已撤销会话的用户在 MFA 中继续 |

### 为什么需要

1. **安全纵深**：这些不是理论风险——在大型多租户部署中，SCIM 供给和手动管理操作在每秒都在发生。一个 5 分钟的 TOCTOU 窗口足以让已离职员工在账户被停用后仍获取令牌。
2. **合规需求**：SOC2 / ISO 27001 / FedRAMP 要求"及时撤销访问权限"——如果已停用的用户在停用后数分钟内仍能获取令牌，审计会发现不合规项。
3. **竞品对标**：Keycloak 在 `/token` 端点重新验证用户状态；Okta 使用 session 指纹验证确保多步之间状态一致。当前项目在单步防御上做得很好（`rejectDeactivatedUser`），但**缺少跨步骤的全局状态验证**。

### 修复方向

```go
// 不在代码中实现，仅描述设计方案：

// 1. 为 ResumeState（MFA/Consent 之间冻结的登录状态）增加 version 字段
//    ResumeState 携带 loginUnixNano + lastVerifiedUserStateHash
//    每次用户状态变化（active, password, tenant membership, roles）更新 hash

// 2. finishLogin / resumeLoginAfterMFA / handleConsentGate 入口处
//    重新计算 userStateHash，与 ResumeState 中冻结的 hash 比较
//    不一致 → ErrStateChanged → 要求用户重新认证

// 3. authCodeValidate 在 /token 入口增加 user active + session active 检查
//    不增加 oracle 信息——统一 invalid_grant

// 4. 新增 handleStateStalenessError(ctx, code) 辅助函数
//    与 mfa_invalid 相同的 oracle-leak collapse

// 估算：~500 行核心逻辑 + ~300 行测试
```

---

## 方向二：跨协议身份关联与账户合并（Identity Linking & Account Merging）

### 概况

| 维度 | 值 |
|------|-----|
| 工作量 | **L**（~1200 行核心 + ~400 行测试 + SPI 定义） |
| 价值 | **极高**（B2B 联邦+多认证源场景的核心能力） |
| 类型 | 产品功能 + 身份模型 |
| 覆盖检查 | 此前 40+ 方向均未覆盖此主题 |

### 当前状态验证

项目支持 **9 种认证方式** + 多种联邦协议，但每个认证方式产生**独立的用户记录**：

```
Authenticators 支持：password / phone / email / temp_token / key_pair / api_key /
                     certificate / totp / oidc_federation（OIDC IdP 登录）
协议联邦支持：OIDC Federation / SAML SP/IdP / LDAP / Kerberos / RADIUS / SCIM
```

**证据：**

```bash
# UserProvider 接口定义
$ head -50 shared/core/user_provider.go
# GetByID / GetByExternalID / CreateOrUpdate — 没有 LinkIdentities / MergeAccounts

# 用户模型
$ head -40 shared/core/types.go
# type User struct { ID, ExternalID, Provider string; Attributes map[string]string }
# 没有 LinkedIdentities []LinkedIdentity / MergedFrom []string

# 登录流程
$ grep -rn "GetByExternalID\|external_id\|provider.*user_id" interfaces/sso/server_login*.go
# 每个 authenticator 独立调用 CreateOrUpdate，按 (provider, external_id) 或 username 匹配
# 没有"这个用户是否已在其他 provider 下存在"的检查
```

### 具体场景

| 场景 | 当前行为 | 应然行为 |
|------|----------|----------|
| 用户先通过 Google OIDC 登录（`user-alice@google`），后通过密码 + 邮箱登录 | 创建两个用户记录：`user-alice`（密码）和 `user-alice@google`（OIDC） | 系统识别同一人，提示/自动链接账户 |
| 企业通过 SAML IdP 认证，用户同时有本地密码 | SAML 登录创建 `user:alice@saml`；密码登录创建 `user:alice` | 两个认证方式指向同一用户 ID |
| 用户先从 LDAP 同步创建，后首次通过 OIDC 登录 | LDAP 有 `alice@acme.com`，OIDC 登录创建新用户 | email 匹配 → 自动链接 |
| 用户删除其中一个登录方式 | 无法安全移除 | 确保至少保留一个活跃登录方式 |

### 为什么需要

1. **B2B 多联邦源场景的刚需**：大型企业通常有多个上游 IdP（收购整合、部门自治），同一用户可能在多个 IdP 中有账户。没有身份关联意味着用户必须记住"我是用哪个 IdP 注册的"。
2. **密码+无密码过渡**：用户可能先用密码注册，后启用了 Passkey。没有关联意味着 Passkey 和密码指向两个不同的用户——用户登录后看到的是空数据。
3. **SCIM 供给 + 自注册冲突**：HR 系统通过 SCIM 创建了用户，用户随后通过自注册（signup）使用同一邮箱注册——产生重复账户。
4. **竞品对标**：Keycloak 有 User Federation + Identity Provider Linking；Auth0 支持 Account Linking（manual + automatic）；Okta 支持 Profile Mastering + Identity Linking。当前项目在认证方式的多样性上已超越多数竞品，但**缺乏将这些认证方式连接起来的身份关联层**。

### 修复方向

```go
// 不在代码中实现，仅描述设计方案：

// 1. 新增 IdentityLink SPI
//    type IdentityLinkStore interface {
//        Link(ctx, userID, provider, providerUserID string) error
//        Unlink(ctx, userID, provider string) error
//        GetLinkedIdentities(ctx, userID) ([]LinkedIdentity, error)
//        FindByLinkedIdentity(ctx, provider, providerUserID string) (string, error)
//    }

// 2. 新增 AccountMergePolicy SPI
//    type MergePolicy interface {
//        CanMerge(ctx, primaryUserID, secondaryUserID string) error
//        Merge(ctx, primaryUserID, secondaryUserID string) error
//    }

// 3. 在 authenticator 成功认证后插入 identity linking hook
//    finishLogin → 认证成功 → 检查该 (provider, providerUserID) 是否已关联 →
//    若否且策略允许 → 提示用户关联 / 自动关联

// 4. 新增 GET /me/identities + POST /me/identities/link + DELETE /me/identities/:provider
//    自服务身份管理

// 5. 管理 API: GET /api/v1/admin/users/{id}/identities + 管理关联
```

---

## 方向三：多维全局限流与滥用防护体系（Per-Tenant/Client/User Quota & Global Rate Limiting）

### 概况

| 维度 | 值 |
|------|-----|
| 工作量 | **M**（~600 行核心 + 中间件 + 配置 + 测试） |
| 价值 | **高**（多租户生产部署的稳定性和公平性保障） |
| 类型 | 运维治理 + 安全防御 |
| 覆盖检查 | 此前 40+ 方向均未覆盖此维度 |

### 当前状态验证

当前速率限制的完整情况：

```bash
# 1. 唯一的限流实现
$ cat interfaces/ratelimit/ratelimit.go
# MemoryLimiter: 每 IP token bucket（perSecond, burst）
# 键生成: KeyByClientIDOrIP — 优先使用 client_id，回退到 IP

# 2. 限流中间件
$ grep -rn "WithRateLimit\|RateLimitMiddleware\|ratelimit" interfaces/sso/options_security.go | head -5
# sso.WithRateLimit(policies...) — 按路径前缀配置 perSecond/burst

# 3. 默认策略
$ grep -rn "defaultPolicies\|DefaultPolicies" interfaces/ratelimit/
# /auth/login: 10/s burst 20, /auth/register: 2/s burst 5, /auth/forgot-password: 2/s burst 5
```

**当前的限流模型只有两个维度：路径 + IP（或 client_id）**。以下是完全缺失的维度：

| 缺失的维度 | 代码搜索证据 | 生产影响 |
|-----------|-------------|---------|
| **Per-Client 全局速率** | `grep -rn "client.*rate\|client.*quota\|per.client.*limit"` → 0 | 一个高流量 client（如移动 APP 的数百万用户）可以耗尽 `/token` 的 server 资源，影响其他 tenant 的 client |
| **Per-Tenant 令牌签发配额** | `grep -rn "tenant.*quota\|tenant.*limit\|issuance.*quota"` → 0 | 一个 tenant 的异常流量（如刷 token 攻击）影响整个部署 |
| **Per-User 操作频率门控** | `grep -rn "user.*rate\|user.*quota\|per.user.*limit\|action.*frequency"` → 0 | 暴力破解防护只在 IP 层面——攻击者可通过分布式 IP 绕过 |
| **Token 签发总量软限制** | `grep -rn "token.*quota\|issuance.*cap\|max.*token.*per"` → 0 | 运维无法对高价值 scope（如 `admin:*`）设置签发上限 |
| **动态限流（过载保护）** | `grep -rn "adaptive.*limit\|dynamic.*throttl\|load.*shed\|concurrency.*limit"` → 0 | 服务器负载高时无自动降级机制 |

### 为什么需要

1. **多租户公平性**：没有 per-tenant 配额意味着一个 tenant 的错误配置（如 mobile app 每秒请求 1000 次 `/token`）会触发全局 IP 限流，影响所有其他 tenant 的合法用户。这是多租户 SaaS 部署的核心稳定性需求。
2. **新型攻击面**：OAuth 2.0 的 `/token` 端点天然是令牌工厂。没有签发配额意味着攻击者即使只有一个有效 client credential，也可以批量签发访问令牌，用于后续的 DPoP/nonce 耗尽或资源服务器扫描。
3. **Scope 级治理**：高价值 scope（如 `admin:*`、`bank:transfer`、`health:record:read`）应该可以设置独立的签发速率限制——而不是和 `openid` 共享同一个 bucket。
4. **竞品对标**：Auth0 有 per-client rate limits + per-tenant token quota；AWS Cognito 有 per-user pool throttling；Azure AD 有 per-application + per-tenant rate limits。当前项目在单 IP 限流上实现正确，但**缺失多租户场景下必须的多维限流体系**。

### 修复方向

```go
// 不在代码中实现，仅描述设计方案：

// 1. 扩展 Limiter SPI 支持带维度的 Allow(key, dimensions...)
//    新增 TenantLimiter / ClientLimiter wrapper

// 2. 分层限流中间件:
//    GlobalLimiter(server-wide) → TenantLimiter(per-tenant) →
//    ClientLimiter(per-client) → UserLimiter(per-user, 可选) →
//    IPLimiter(当前实现)

// 3. 管理 API + Admin Console: 配置 per-tenant / per-client 配额
//    POST /api/v1/admin/tenants/{id}/rate-limits
//    POST /api/v1/admin/clients/{id}/rate-limits

// 4. Token issuance quota: 在 token 签发路径增加配额检查点
//    Grant → checkQuota(ctx, client, tenant, scope) → exceed → 429 + audit

// 5. Scope 级限流: 对高价值 scope 配置独立的 perSecond/burst
```

---

## 方向四：管理面 UI 产品化缺口——Admin Console 的读写不对称

### 概况

| 维度 | 值 |
|------|-----|
| 工作量 | **L**（前端 ~1500 行 + 后端少量辅助端点） |
| 价值 | **高**（直接影响企业采购决策和运维效率） |
| 类型 | 产品完备性 |
| 覆盖检查 | 此前仅提及安全头缺失（CSP），未分析功能缺口 |

### 当前状态验证

Admin Console（`interfaces/web/admin/index.html`，1096 行，单文件内联 HTML/CSS/JS）是运营者管理 SSO 服务器的核心界面。**当前功能与后端 API 能力之间存在巨大的读写不对称：**

| 管理功能 | 后端 gRPC/REST API | Admin Console UI | 缺口 |
|----------|-------------------|------------------|------|
| Client CRUD | `List / Get / Create / Update / Delete / RotateSecret` | ✅ 只读列表 + 详情 | ❌ 无创建/编辑/删除/密钥轮换 |
| User CRUD | `List / Get / Create / Update / Delete / ListSessions` | ✅ 只读列表 + 详情 | ❌ 无创建/编辑/删除/会话管理 |
| Tenant CRUD | `List / Get / Create / Update / Delete / SetStatus` | ❌ 完全不存在 | ❌ 无任何租户管理界面 |
| Domain CRUD | `List / Get / Create / Update / Delete` | ❌ 完全不存在 | ❌ 无域名管理界面 |
| Permission/Role | `List / Add / Update / Remove / Assign / Unassign` | ❌ 完全不存在 | ❌ 无权限管理界面 |
| Snapshot | `Export / List / Get / Restore / Delete` | ❌ 完全不存在 | ❌ 无快照管理界面 |
| Release | `Register / List / Get / Pin / Rollback` | ❌ 完全不存在 | ❌ 无版本管理界面 |
| Temp Token | `IssueTempToken` | ❌ 完全不存在 | ❌ 无法签发临时令牌 |
| Token 级撤销 | `Revoke(token)` | ⚠️ 仅 Session 级撤销 | ❌ 无法按 token 值撤销 |
| 健康 Dashboard | `/livez / /readyz / discovery` | ✅ 实现 | ✅ |
| 审计日志 | `/api/v1/audit/events` | ✅ 实现（搜索+分页） | ✅ |

此外，Admin Console 的认证方式是一个**原始 Bearer Token 输入框**：

```javascript
// interfaces/web/admin/index.html:643
function doLogin() {
  var t = document.getElementById('token-input').value.trim();
  // 无 OAuth 登录流，无 admin 专用 client（dogfood），无 scope 协商
  // token 存储在 sessionStorage——XSS 可窃取
}
```

### 为什么需要

1. **采购决策**：在 POC 阶段，采购方的第一印象来自 Admin Console 的成熟度。一个"只能看不能改"的管理控制台会直接导致"产品不成熟"的负面判断——即使后端 API 极其强大。
2. **运维效率**：没有 UI 意味着每个管理操作都需要 `curl` 或 `sso-ctl`。对于非技术运维人员（如安全管理员、合规审计员），CLI 是不可接受的。这直接限制了目标用户群。
3. **Dogfood 安全模型**：Admin Console 没有自己的 OAuth client（`client_id=sso-admin-console`），没有 PKCE，没有 session 管理。原始 Bearer token 输入框的可用性很低——用户需要先从 `/token` 或其他途径获取一个 `admin:*` scope 的 token，然后粘贴到输入框中。
4. **竞品对标**：Keycloak Admin Console 功能完善（用户/Client/角色/权限/会话全量 CRUD）；Auth0 Dashboard 覆盖所有管理能力；Okta Admin Console 是行业标准。当前实现处于"有胜于无"但远未达到"产品级"的阶段。

### 修复方向

```go
// 不在代码中实现，仅描述设计方案：

// 1. Admin Console 注册自己的 OAuth 2.0 Client（dogfood）
//    client_id = "sso-admin-console", redirect_uri = /admin/callback
//    通过 Authorization Code + PKCE 流程获取 admin:read + admin:write scope
//    基于 session 维护管理会话，不再依赖 raw Bearer token

// 2. 分阶段补全 CRUD UI（按优先级）:
//    Phase 1: Client 创建/编辑/密钥轮换 + Tenant 管理（列表/创建/挂起）
//    Phase 2: User 创建/编辑/停用 + 角色/权限管理
//    Phase 3: 快照管理 + 域名管理 + 版本管理

// 3. 前端架构升级（可选但推荐）:
//    单文件内联 JS 的 1096 行已触及可维护性上限
//    → 拆分为多文件/组件，或引入轻量框架
//    → 添加 Proper Loading Skeletons / Error Boundaries / Accessibility
```

---

## 方向五：SSO SDK 嵌入摩擦与开发者体验治理

### 概况

| 维度 | 值 |
|------|-----|
| 工作量 | **M**（~400 行文档/示例 + ~200 行验证/辅助代码） |
| 价值 | **高**（项目定位为"Go SDK"，嵌入体验是核心卖点） |
| 类型 | 开发者体验 + 架构治理 |
| 覆盖检查 | 此前方向提及 `NewServer` 选项验证缺失，但未系统性分析 SDK 嵌入体验 |

### 当前状态验证

项目在 README 中定位为"**Embed as a Go library (the SDK)**"，但嵌入者的实际体验存在多个摩擦点：

**摩擦 1：`Deps` 接口膨胀——从组合根到上帝接口的漂移**

```go
// interfaces/sso/server_deps.go — 当前 ~50+ 方法的接口
// protocols/selfservice/selfservicecore/deps.go — 另一个 ~30+ 方法的子集
// internal/handler/tokengrant/authcode.go — 专用的 AuthCodeGrantDeps
// internal/handler/tokengrant/token_jwt_bearer.go — 专用的 JWTBearerGrantDeps
```

每个新的 handler 或 feature 都可能向 `Deps` 接口添加新方法。`*sso.Server` 通过 `accessors.go` 满足所有这些接口，但接口的可组合性在下降——嵌入者无法清晰看到"我需要实现哪些方法"。

**摩擦 2：90+ Option 函数没有集中验证**

```go
// interfaces/sso/options*.go — 分布在 5 个文件中
// sso_newserver.go — 90+ 字段的 Server struct
// 无 WithValidator() 或 Server.Validate() 方法
// 冲突选项（如 OAuth 2.1 strict + FAPI 同时启用）运行时静默生效
```

嵌入者无法在构造时获知选项配置是否正确：误配的选项仅在运行时（某条请求路径上）表现为异常行为。

**摩擦 3：缺失"最小生产嵌入"参考示例**

```bash
$ find docs/examples/ -type f -name '*.go' | sort
# docs/examples/quickstart/ — 180 行的快速演示（内存存储、单文件）
# docs/examples/basic/ — 基础示例
# docs/examples/embedded-app/ — 嵌入示例
# docs/examples/appcore/ — 应用核心示例
# docs/examples/playground/ — 游乐场
# docs/examples/grpc-client/ — gRPC 客户端
# docs/examples/remote-app/ — 远程应用

# 缺失:
# - "最小生产嵌入"示例（SQLite 存储 + 健康端点 + 优雅关闭 + 信号处理）
# - "多副本嵌入"示例（etcd 集群 + 多 Server 实例）
# - "自定义 Store 实现"示例（嵌入者实现自己的 UserProvider/ClientStore）
```

**摩擦 4：SDK 消费者体验**

`interfaces/ssoclient/` 提供了 `local / remote / dev / bootstrap` 四种消费者客户端模式，但：
- 无独立文档说明每种模式的适用场景
- 无版本兼容性保证（消费者 SDK 与 Server SDK 的版本耦合）
- 无迁移指南（local → remote 的无缝切换）

### 为什么需要

1. **核心定位问题**：项目的 README 第一句就是"Embed as a Go library"。如果嵌入体验不是一等公民，项目的核心定位与用户实际体验之间存在裂痕。
2. **生态效应**：好的 SDK 体验驱动采用率。一个清晰的 `NewServer` 接口 + 可组合的 `Deps` + 完善的示例代码，是 Go 社区传播的自然基础。
3. **长期可维护性**：`Deps` 接口的持续膨胀不可持续。当前已有 `AuthCodeGrantDeps`、`JWTBearerGrantDeps`、`selfservicecore.Deps`、`admin.Deps` 等多个子接口——这是正确的方向（小接口组合），但**缺少治理机制防止** `*sso.Server` 的 `accessors.go` 回到上帝对象模式。
4. **竞品对标**：Zitadel 的 Go SDK 有清晰的 `Client` 构造和文档；Keycloak 提供多种语言的 Admin client。当前项目在 Go SDK 深度上超过两者（嵌入 SSO server 而非仅 admin client），但**开发者体验文档和示例远不够完善**。

### 修复方向

```go
// 不在代码中实现，仅描述设计方案：

// 1. Deps 接口治理
//    - 每条 Deps 接口加 doc 注释"谁需要它、要实现哪些方法"
//    - 在 accessors.go 中为 *sso.Server 增加编译时接口满足检查
//      var _ AuthCodeGrantDeps = (*Server)(nil)
//    - 接入 Graph of Deps 文档（依赖图可视化）

// 2. NewServer 验证
//    - 增加 Server.Validate() error（构造后可调用）
//    - 检测常见冲突：OAuth 2.1 strict + FAPI 同时启用；DPoP nonce 但无 replay store
//    - 构建时 Warning 日志：缺失但不致命的选项

// 3. 新增文档/示例
//    - docs/embedding-guide.md：从"最小嵌入"到"生产集群"的渐进式指南
//    - docs/examples/production-embed/：SQLite + 优雅关闭 + signal handling
//    - docs/examples/custom-store/：自定义 UserProvider + ClientStore

// 4. 消费者 SDK 文档化
//    - ssoclient/README.md：四种模式的适用场景和决策树
//    - 版本声明：明确 sso.Server 版本与 ssoclient 版本的兼容矩阵
```

---

## 优先级排序

| 优先级 | 方向 | 理由 |
|--------|------|------|
| **P0** | 方向一：多步 TOCTOU 系统分析 | 安全纵深——可能在多租户环境中导致授权绕过。虽然尚未发现实际利用案例，但理论风险存在，且 SOC2 合规审计会标记此类 gap |
| **P0** | 方向四：Admin Console 产品化 | 直接影响企业采购决策和运维效率。后端 API 强大但 UI 薄弱，形成"产品不成熟"的直观印象 |
| **P1** | 方向二：跨协议身份关联 | 功能缺口——在 B2B 联邦场景中直接导致可用性问题。但当前不影响安全性，优先级略低于 P0 |
| **P1** | 方向三：多维全局限流 | 运维稳定性——在部署规模扩展前不会触发。建议在达到 3+ 生产租户前完成 |
| **P2** | 方向五：SDK 嵌入体验 | 开发者体验——不影响现有功能，但影响社区采用和生态建设。建议在下一个大版本发布前治理 |

---

## 与已有分析的关系

| 方向 | 与已有分析的重叠说明 |
|------|---------------------|
| 方向一：TOCTOU | 此前 40+ 方向均未系统性分析多步协议之间的状态裂缝。`edgecases-and-perf` 涉及时间边界情况但覆盖的是 `time.Now()` 和 TOTP 漂移，非跨步骤状态变化 |
| 方向二：身份关联 | 此前 `expansion-novel-five` 和 `expansion-v2` 分别覆盖了身份生命周期管理和用户状态管理（邀请→激活→休眠→归档），但**未涉及跨认证源的身份关联**。这是正交维度 |
| 方向三：多维限流 | 此前 `expansion-2026-07-01-v2` 的"基础设施（SSE + Webhook 出站）"和"混沌工程"不涉及此方向。`health-and-dx` 也未覆盖 |
| 方向四：Admin Console | 此前 `expansion-novel-architectural-gaps` 分析了"Admin API 面一致性"（proto vs HTTP-only 端点），但**未分析 Admin Console UI 功能缺口**。`runtime-performance` 提及 SPA 安全头缺失但未分析产品功能 |
| 方向五：SDK 嵌入体验 | 此前 `architectural-debt` 分析了 `Deps` 接口膨胀，但**未从"开发者嵌入体验"的产品视角系统性审视**。`expansion-novel-architectural-gaps` 提及 `NewServer` 验证缺失但未扩展 |

---

*本文档基于 2026-07-01 全代码库扫描生成，不包含任何代码实现。*
