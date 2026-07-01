现在我对这份文档和交叉评估进行了全面审查。以下是基于完整上下文（原始分析文档 + 架构师交叉评估）的综合架构分析。

---

# 架构分析报告：SSO 平台的五个盲区方向

## 1. 架构评估

### 1.1 当前架构的优势

从分析文档可以提炼出架构设计中的几个关键优势：

- **多步防御面已铺设**：OAuth 2.0 授权码流的每个步骤已有独立的安全检查点（`rejectDeactivatedUser`、`authCodeValidate` 单次消费、Consent Challenge 时限绑定），证明架构设计者对单点安全有深入考量。
- **接口化存储层**：`UserProvider`、`ClientStore` 等 SPIs 的存在使得分析文档能够通过 grep 快速验证 Identity Linking 的缺失——这是架构可见性好的标志。
- **分层限流框架**：`MemoryLimiter` + 中间件模式的分层设计，使得扩展新维度（如 `KeyBySubject`）只需新增键生成函数，而不需要重写限流引擎。

### 1.2 关键架构债务

交叉评估中揭示的或可进一步深化的债务：

| 债务项 | 位置 | 严重程度 | 说明 |
|--------|------|----------|------|
| **ResumeState 无版本戳** | `server_mfa.go`、Consent 流、Account Select 流 | **高** | 冻结的登录快照在跨步骤传递过程中无法检测用户状态变更。交叉评估确认影响面从 1 处（MFA）扩展到 3+ 处 |
| **`Deps` 接口扁平滑** | `server_deps.go`（~50 methods） | **中-高** | 交叉评估指出：嵌入者需要实现的方法数从 15（最小嵌入）到 50+（完整功能）。统一的扁平接口违背了"按需实现"的嵌入原则 |
| **Admin Console 无独立认证模型** | `interfaces/web/admin/` | **中** | 原始 Bearer Token 输入框 + sessionStorage 既是安全风险也是产品成熟度瓶颈 |
| **Grep-validated Identity Gap** | 全库 `LinkIdentit\|MergeAccount` = 0 结果 | **中** | 不是一个代码级别的 bug，而是一个缺失的架构分层（Identity Linking Layer） |
| **限流键生成已有但未接入** | `ratelimit/middleware.go` 中 `KeyBySubject` 仅用于测试 | **低-中** | 有实现的代码但未达到生产状态——典型的半成品架构状态 |

### 1.3 架构层的责任分配检查

对照 AGENTS.md 中定义的七层结构（`shared → domains → protocols → platform → interfaces → infrastructure → cmd`）：

| 方向 | 应归属的层级 | 当前状况 |
|------|-------------|----------|
| TOCTOU stateHash | `protocols/oauth` + `interfaces/sso` | 分散在各 handler 中，缺少集中化的 state version 管理 |
| Identity Linking | `shared/core` (SPI) + `domains/` (链路逻辑) | 完全不存在的层级 |
| 多维限流 | `platform/` (跨切面) | 基础框架在 `interfaces/ratelimit`，位置偏上；扩展维度应下沉至 `platform/` |
| Admin Console | `interfaces/` (UI 层) + `interfaces/admin/` (BFF) | 缺少 BFF 层，交叉评估已验证此缺口 |
| SDK Embedding | 跨层（`interfaces/sso` + `infrastructure/defaultimpl`） | Deps 组合模式需重构 |

**关键结论**：是否将限流框架从 `interfaces/ratelimit` 下沉到 `platform/ratelimit` 是一个架构决策。当前位于 `interfaces/` 层意味着它服务于接口层的 HTTP 处理——如果要让内部处理器（如 token grant 的 quota check）也使用同一框架，则必须下沉。

---

## 2. 扩展方向

基于分析文档和交叉评估，我建议以下 **5 个架构扩展方向**（与文档方向对应但不完全相同）：

### 方向 A：Stateful Multi-Step Protocol Guard（替代方向一的"TOCTOU 修补"为系统性方案）

**为什么需要**：
- 不仅是修复 TOCTOU 窗口，而是建立跨步骤状态的一致性契约
- 安全合规（SOC2/FedRAMP 要求及时撤销）的直接响应
- 影响 3 个 ResumeState 结构，需要统一方案而非逐个修补

**核心挑战**：
1. **State Hash 的计算范围**：需要确定哪些用户属性变化应使 hash 失效（active、password、tenant membership、roles、scopes）。范围过小会遗漏，范围过大会产生大量误报（false positive re-auth）。
2. **性能开销**：每次 hash 验证（每个多步步骤边界）需要查询用户当前状态。缓存策略和过期间的权衡。
3. **Oracle-leak 约束**：状态不一致时必须返回通用的 `state_changed` 错误，不能透露具体哪个属性变化。

**架构变更**：
```
当前：
  (Auth) → [Login] → (ResumeState) → [MFA] → (ResumeState) → [Consent] → [Token]
  
建议新增 StateGuard 层：
  (Auth) → [Login] → StateGuard.validate → [MFA] → StateGuard.validate → [Consent] → StateGuard.validate → [Token]
                          ↑                          ↑                          ↑
                    UserStateHash              UserStateHash              UserStateHash
```

**对现有系统影响**：
- 新增 `security/validators/state.go`：`VerifyUserStateConsistency(ctx, userID, stateFingerprint) error`
- 修改 `server_mfa.go`、`server_consent.go`、`token_authcode.go`：插入验证点
- 新增 `mfaResumeState.stateFingerprint`、`ConsentChallenge.stateFingerprint` 字段
- 不改变外部 API 签名，向后兼容

### 方向 B：Identity Linking & Account Merging Layer

**为什么需要**：
- 解决多联邦源场景的"用户身份碎片化"问题（这也是分析文档的 P1 方向）
- 密码 → Passkey 过渡的刚需场景
- 与 SCIM 供给 + 自注册的身份去重

**核心挑战**：
1. **MergePolicy 的设计维度**：`automatic` 与 `manual` 的选择涉及 UX 和安全。自动关联需要置信度评分（email 匹配 vs phone 匹配 vs 全名匹配）。错误关联可能导致数据泄露。
2. **Session 面影响**：关联后的用户有多个活跃 session，撤销一种登录方式不应影响其他。需要 `SessionManager` 支持 `GetByUserID` 和按 provider 过滤。
3. **审计可追溯性**：关联和合并操作需要详细审计日志，支持合规审核。

**架构变更**：
```
新增层：
  shared/spi/identitylink.go: IdentityLinkStore interface
  domains/identitylink/: LinkService, MergePolicy, IdentityResolver
  
变更：
  UserProvider: GetByExternalID 的行为需要先查 IdentityLink 再 fallback
  SessionManager: 新增 GetByUserID 支持
  protocols/selfservice/signup: 注册后插入 identity linking hook
```

**对现有系统影响**：
- 新增 SPI + 实现（memory + SQLite）
- 新增管理 API 端点（REST + gRPC）
- 修改 UserProvider 的 `GetOrCreate` 行为（需配置开关，默认关闭保持向后兼容）
- 新增配置项：`identityLinking.policy`（auto/manual/disabled）

### 方向 C：Multi-Dimensional Rate Limiting Framework

**为什么需要**：
- 多租户公平性的基础保障
- Scope 级治理（高价值 scope 独立限流）
- Token 签发总量软限制——OAuth 2.0 的独特威胁面

**核心挑战**：
1. **分层限流的性能模型**：5 层限流（Global → Tenant → Client → User → IP）意味着每次请求最多 5 次 store 查询。需要基于内存（非持久化）的计数器，支持原子性。
2. **维度推演**：`KeyByTenant` 需要从 request context 中提取 tenant ID——但限流中间件在 auth middleware 之前执行，tenant 可能尚未解析。需要调整执行顺序或使用懒计算。
3. **Scope 级配额**：在 token 签发路径上检查配额是最准确的，但 `/token` 处理器已经是高性能瓶颈，添加配额检查不能增加 db 查询。

**架构变更**：
```
限流框架从 interfaces/ratelimit 下沉到 platform/ratelimit：
  platform/ratelimit/
    ├── limiter.go         # Limiter interface（不变量）
    ├── memory.go          # MemoryLimiter（现有）
    ├── layered.go         # LayeredLimiter（新增——组合多个维度）
    ├── key.go             # KeyByIP, KeyByClientID, KeyBySubject, KeyByTenant（提取 KeyBySubject 从测试到生产）
    └── quota.go           # TokenIssuanceQuota（新增——scope 级签发配额）
```

**对现有系统影响**：
- `interfaces/ratelimit` 保持兼容性包装器，调用 `platform/ratelimit`
- 新增管理 API 端点配置配额
- Admin Console 增加配额配置 UI
- 向后兼容：默认配置行为与当前一致

### 方向 D：Admin BFF (Backend for Frontend) + 产品化认证

**为什么需要**：
- 分析文档已指出 Admin Console 的读写不对称
- 交叉评估补充了 BFF 层的缺失——当前没有 admin 专用 API 聚合层
- admin 级限流、审计上下文、数据结构封装的需求

**核心挑战**：
1. **Dogfood OAuth Client**：Admin Console 需要自己的 OAuth 2.0 Client（`client_id=sso-admin-console`），通过 Authorization Code + PKCE 流程获取 token。这引入了一个鸡生蛋问题——如何在没有 Admin Console 的情况下创建 Admin Console 的 Client？
2. **BFF 的分层边界**：BFF 不应成为业务逻辑的泄洪闸。它的职责是（a）将多个后端调用聚合为单一 UI 响应；（b）注入 admin 审计上下文；（c）admin 级限流。不应包含 domain 逻辑。
3. **前端架构升级**：当前 3 文件结构（1072 行）虽然好于单文件，但仍缺少组件化。引入前端框架的抉择——项目是 Go 生态项目，引入 Vue/React/Svelte 会增加维护成本。

**架构变更**：
```
新增 interfaces/admin/ 层：
  interfaces/admin/
    ├── bff.go              # BFF handler（HTTP 代理 + 聚合）
    ├── middleware.go        # admin 级限流 + 审计
    ├── client.go            # Admin Console 专用 OAuth client 注册
    └── web/
        ├── index.html
        ├── style.css
        └── app.js           # 从 interfaces/web/admin/ 迁移

对 interfaces/sso/ 的影响：
  新增 SSO 启动时的 admin client 自注册逻辑
```

**对现有系统影响**：
- 新增 package 和路由前缀（`/admin/api/v1/...`）
- 不修改现有 API 端点，保持向后兼容
- 新增 configuration 项：`admin.bff.enabled`（默认 false）
- 前端代码从 `interfaces/web/admin/` 迁移到 `interfaces/admin/web/`

### 方向 E：`Deps` 接口分段组合（Componentized Deps）

**为什么需要**：
- 分析文档和交叉评估都指向了同一个核心问题：当前 `Deps` 的扁平接口无法满足嵌入者的"按需实现"需求
- 这是 SDK 嵌入体验的根本架构问题，不是文档可以解决的

**核心挑战**：
1. **分段粒度**：分段太细会增加组合复杂度（类似 DI 容器的饥饿），分段太粗则回到上帝接口。目标应该是 5-8 个子接口，每个代表一个独立的能力领域。
2. **默认实现的注入**：嵌入者只想自定义 `UserProvider` 和 `ClientStore`，其余使用默认（memory/SQLite）实现。当前 `NewServer` 接受 `Deps` 接口——如果改为接受分段接口，需要同时支持混合模式。
3. **向后兼容**：现有的 `*sso.Server` 通过 `accessors.go` 满足 `Deps` 接口。引入分段接口后，`Deps` 本身应该保持为 `composite interface`（由子接口组成），这样嵌入者既可以传入完整 `Deps`（向后兼容），也可以传入分段实现 + 默认值。

**架构变更**：
```
当前：
  type Deps interface {
      UserProvider() core.UserProvider
      ClientStore() core.ClientStore
      SessionManager() core.SessionManager
      TokenIssuer() core.TokenIssuer
      // ... 50+ methods
  }

建议：
  type Deps interface {
      StorageDeps
      TokenDeps
      AuthenticationDeps
      IdentityDeps
      AuditDeps
  }

  type StorageDeps interface {
      UserProvider() core.UserProvider
      ClientStore() core.ClientStore
      SessionManager() core.SessionManager
  }

  // 嵌入者可以实现 StorageDeps 自定义存储，其他使用默认
  // NewServer(Deps{T: storageDepsImpl}) → 自动填充剩余 default
```

**对现有系统影响**：
- `accessors.go` 需要为每个子接口添加编译时检查：`var _ StorageDeps = (*Server)(nil)`
- `NewServer` 签名不变（接受 `Deps`），但内部检测哪些子接口由嵌入者提供，哪些需要默认
- 新增 `defaultimpl/default-deps.go`：返回默认实现的 `StorageDeps`, `TokenDeps` 等
- 向后兼容：嵌入者当前的代码无需修改

---

## 3. 接口设计建议

### 3.1 关键接口设计原则

基于分析文档的五个方向，提炼出以下接口设计原则：

| 原则 | 适用方向 | 理由 |
|------|---------|------|
| **R1：每个跨步骤边界必须有可验证的状态契约** | A (TOCTOU) | ResumeState 结构的版本戳应该是强制性的，而不是可选的。接口应强制嵌入者提供 `StateFingerprint` 计算 |
| **R2：接口 segregate = 能力声明（capability）, 而非实现打包** | E (Deps) | 子接口应该代表嵌入者"声明我可以提供什么"，而不是"我需要导入所有这些" |
| **R3：存储 SPI 不变，查询行为可通过 hook 扩展** | B (Identity Linking) | Identity Linking 不应要求修改 `UserProvider` 接口，而是通过 hook 模式扩展 `GetByExternalID` 的行为 |
| **R4：横切关注点（限流、审计）不应在业务接口中声明** | C (Rate Limiting) | `TokenIssuer` 不应感知配额检查。限流应通过 middleware/inceptor 模式叠加 |

### 3.2 新增抽象层决策

| 建议的新增抽象层 | 说明 | 风险 | 缓释方案 |
|----------------|------|------|---------|
| `platform/ratelimit/` | 从 `interfaces/ratelimit` 下沉，暴露 `Limiter` 接口给内部处理器 | 已有调用方需要迁移 | 保持 `interfaces/ratelimit` 为薄包装器，内部委托给 `platform/ratelimit`，分阶段迁移 |
| `shared/spi/identitylink.go` | `IdentityLinkStore` SPI | 新 SPI 意味着新的 mocks 和测试责任 | 类似 `core.UserProvider` 模式，提供 `memory.IdentityLinkStore`，`identitylinktest` 包 |
| `interfaces/admin/`（BFF） | Admin 专用 API 聚合层 | 增加部署复杂度 | BFF 是可选组件，默认不启用 |
| `infrastructure/defaultimpl/default-deps.go` | 默认分段 Deps 实现 | 与现有 `Deps` 模式的兼容性 | 保持 `Deps` 接口不变，`default-deps.go` 只是辅助嵌入者的辅助类型 |

**不推荐的抽象层**：
- 不引入独立的 `StateGuard` 接口——方向 A 的 TOCTOU 验证应作为 `security/validators` 包中的纯函数，而不是接口，以避免不必要的 SPI 抽象
- 不引入独立的 `MergePolicy` 接口（当前阶段）——交叉评估建议 Sprint A 先构建 SPI + 存储，MergePolicy 的逻辑可以后续用配置项 + 短函数模式实现

### 3.3 向后兼容策略

| 变更 | 兼容性影响 | 策略 |
|------|-----------|------|
| 方向 A：ResumeState 增加字段 | 序列化兼容（新字段 optional） | 旧存储中的数据默认 stateFingerprint=""，跳过验证 |
| 方向 B：新增 SPI | 无影响（纯新增） | 新 SPI 的存储表在 schema 中新增，不对现有表做迁移 |
| 方向 C：限流框架下沉 | 内部重构 | `interfaces/ratelimit` 将调用委托给 `platform/ratelimit`，外部 API 不变 |
| 方向 D：Admin BFF | 无影响（纯新增） | 新路径 `/admin/api/v1/...`，不修改现有路径 |
| 方向 E：Deps 分段 | 接口层无变化 | `Deps` 保持为 composite interface，嵌入当前代码无需修改；新增的 `default-deps.go` 是可选辅助 |

---

## 4. 技术选型

### 4.1 引入新技术栈的评估

| 方向 | 建议技术 | 评估 | 结论 |
|------|---------|------|------|
| 方向 D（Admin Console 前端） | **Svelte**（轻量、编译时） | 项目是 Go 生态，引入前端框架增加构建工具链。但 Svelte 是编译时框架，产物是原生 JS，不需要 Node.js 运行时。构建由 `go:generate` 或 `make` 触发 | **推荐**，如果方向 D 的产品化目标包括完整的 Admin Console UI |
| 方向 D（Admin Console 前端） | **Vanilla JS + HTMX** | 无需构建工具链，与当前代码风格一致 | **备选**，对于"分阶段补全 CRUD"（下策）或保持低复杂度 |
| 方向 B（Identity Linking 存储） | **SQLite 关联表** | 新增 `identity_links` 和 `merge_operations` 表，使用现有的 migrate runner | **推荐**，与项目存储策略一致 |
| 方向 A（State Hash 缓存） | **内存 LRU（如 `hashicorp/golang-lru`）** | 减少每个多步边界的 db 查询 | **有条件推荐**——仅在实测中 hash 计算成为瓶颈时引入，初始版本可以直接查询 `UserProvider` |

**关于引入前端框架的决策树**：

```
是否计划 Admin Console 达到"产品级"（完整的 CRUD 管理界面）？
  ├── 是 → Svelte（编译时、轻量、类型安全）
  │     └── 理由：当前 3 文件 1072 行的 JS 在没有框架的情况下，
  │          扩展到 3000+ 行的管理 UI 会变成不可维护的 spaghetti code。
  │          选择 Svelte 是因为其编译时特性最小化了 Go 项目中的 JS 工具链侵入。
  │
  └── 否 → 继续 Vanilla JS
        └── 理由：如果方向 D 只做"OAuth 认证集成 + 少量 CRUD 补全"，
              当前 3 文件模式仍可维持一段时间。
```

### 4.2 第三方依赖评估标准

对于所有五个方向，引进第三方依赖应遵循以下标准：

1. **纯 Go、无 CGO**：新依赖必须是纯 Go。SQLite 已经使用了 `modernc.org/sqlite`（无 CGO），所有新存储实现也遵循此标准。
2. **零运行时外部进程**：不引入需要 sidecar 或外部进程的依赖。LRU 缓存使用内存即可。
3. **LICENSE 兼容**：必须是 MIT/BSD/Apache 2.0，避免 AGPL。
4. **Go 标准库优先**：方向 A 的 hash 计算使用 `crypto/sha256`；方向 C 的限流框架使用 `sync/atomic` + `time.Timer`。不需要第三方。
5. **版本锁定**：任何新增依赖都必须锁定版本并加入 `go.sum`，使用 `go mod verify`。

### 4.3 自建 vs 采购决策

| 方向 | 决策 | 理由 |
|------|------|------|
| 方向 A, B, C, E | **自建** | 这些是核心产品竞争力的差异化功能，不是通用可采购的商业组件 |
| 方向 D（Admin Console） | **自建**，但可借鉴竞品设计 | 管理 UI 是 Go 生态开源项目的一部分，采购商业管理面板不匹配项目定位 |

---

## 5. 实施路线图

### 5.1 优先级排序

基于交叉评估的修正，我的最终优先级排序与原始分析文档略有不同：

| 优先级 | 方向 | 工作量 | 风险 | 调整理由 |
|--------|------|--------|------|----------|
| **P0** | A：Stateful Multi-Step Guard | M+（~1200 行） | 低 | 安全红线，影响面广（3+ 个状态点），合规需求。修复后不可逆——不做此工作可能导致安全漏洞 |
| **P0** | E：Deps 分段组合 | M（~600 行框架 + ~200 行辅助） | 中 | 核心定位问题。越早做，迁移成本越低。当前已有 50+ 方法，每新增一个特征都在扩大接口膨胀 |
| **P1** | D：Admin BFF + 产品化认证 | L（~1500 行） | 中 | 企业采购直接影响。但 BFF 层可以在后端就绪后逐步补全前端 UI |
| **P1** | C：多维全局限流 | M-（~400 行，因 KeyBySubject 已有） | 低 | 已有可复用代码，加速实现。在多租户部署扩展前完成即可 |
| **P2** | B：Identity Linking Sprint A | M（~800 行 SPI + 存储 + API） | 中-高 | B2B 联邦场景的刚需，但实现复杂度高。建议在核心架构债务（方向 E）解决后启动 |

**交叉评估与原始文档的优先级差异说明**：
- 交叉评估将方向 E（SDK 嵌入体验）上调至 P0，方向 D（Admin Console）保持 P0，方向 A（TOCTOU 修正）仍为 P0——形成三个 P0
- 原始文档将方向 A 和 D 列为 P0，方向 E 列为 P2
- **我认同交叉评估的上调**：因为方向 E 的"Dep 接口组合"问题不是简单的文档问题，而是架构模式问题，影响的代码范围随着每个新 feature 在扩大

### 5.2 阶段划分和里程碑

```
Stage 1（2-3 sprint）: P0 — 安全 + 架构
  ├── Sprint 1: 方向 A — Stateful Multi-Step Guard
  │     - 定义 UserState hash 计算规则
  │     - 在 3 个 ResumeState 中植入 stateFingerprint
  │     - 在登录/MFA/Consent/Token 边界插入验证
  │     - 全面测试（正常路径、状态变更路径、边界条件）
  │     ✅ Milestone: go test 通过 + oracle-leak 验证
  │
  └── Sprint 2-3: 方向 E — Deps 分段组合
        - 定义子接口划分（StorageDeps / TokenDeps / AuthenticationDeps / IdentityDeps / AuditDeps）
        - 实现 default-deps.go（每个子接口的默认实现）
        - 修改 accessors.go 添加编译时检查
        - 更新示例代码展示分段用法
        ✅ Milestone: 向后兼容 + 新示例通过

Stage 2（2-3 sprint）: P1 — 产品化
  ├── Sprint 3-4: 方向 D — Admin BFF + OAuth 认证
  │     - 创建 interfaces/admin/ 包
  │     - 实现 Admin Console 的 dogfood OAuth client
  │     - 实现 BFF 层（admin 级限流 + 审计注入）
  │     - Admin Console 使用 Authorization Code + PKCE 认证
  │     ✅ Milestone: Admin Console 不再依赖 raw Bearer token
  │
  └── Sprint 4-5: 方向 C — 多维全局限流
        - 将 KeyBySubject 从测试移至生产
        - 新增 KeyByTenant 键生成函数
        - 实现 LayeredLimiter（Global → Tenant → Client → User → IP）
        - 实现 TokenIssuanceQuota（scope 级签发配额）
        - 新增管理 API 端点
        ✅ Milestone: 分层限流在生产路径上生效; 管理 API 可配置

Stage 3（2 sprint）: P2 — 身份融合
  └── Sprint 6-7: 方向 B Sprint A — IdentityLink SPI + 存储 + API
        - 定义 IdentityLinkStore SPI
        - 实现 memory + SQLite 存储
        - 新增管理 API（CRUD 身份关联）
        - UserProvider 中插入 identity linking hook（可选开关）
        - 自服务 API（GET / POST / DELETE /me/identities）
        ✅ Milestone: 管理 API 可查询和管理身份关联; 登录流程可自动/手动关联
```

### 5.3 风险点和缓解策略

| 风险 | 影响方向 | 概率 | 严重性 | 缓解策略 |
|------|---------|------|--------|---------|
| **State Hash 误报导致合法用户重新认证** | A | 中 | 中 | 提供配置项 `stateGuard.sensitivity`：strict（所有变更触发 re-auth）/ moderate（仅 active/password/tenant 变更）/ relaxed（仅 active 变更） |
| **Deps 分段后嵌入者混淆** | E | 高 | 中 | `Deps` 继续保持为复合接口向后兼容；新增文档 `docs/migration-deps-composition.md`；在 NewServer 构造时输出清晰的缺失实现错误提示 |
| **Admin BFF 变成业务逻辑泄漏点** | D | 中 | 高 | 严格的代码审查：BFF handler 只做聚合和内联，不包含业务条件判断业务逻辑。添加 `// BFF: only aggregation, no business logic` 注释惯例 |
| **Identity Linking 安全 oracle-leak** | B | 高 | 高 | `FindByLinkedIdentity` 设计为"不存在或错误不区分"；`Link` 操作成功后不返回是否是新创建的关联（类似 `upsert` 语义）；避免"这个邮箱已在其他账户使用"的错误消息 |
| **方向 A/B/C/D/E 并行开发冲突** | 所有 | 中 | 低 | 每个方向都在独立的包中（最小化交叉修改）；shared/core 的变更通过 code review 协调 |

### 5.4 检查清单

实施前、中、后的验证点：

```
前置检查（Stage 1 前）：
  ☐ 方向 A: stateFingerprint 的 hash 算法选择（sha256 vs blake2b）
  ☐ 方向 E: Deps 子接口的命名和职责边界一致
  ☐ 向后兼容策略文档化

实施中（每次 PR）：
  ☐ go build ./... + go vet ./... + make ci 通过
  ☐ 无新的 maintainability exemption（文件 ≤500 行，函数 ≤50 行/cyclo ≤15）
  ☐ 方向特定：oracle-leak 验证 / 向后兼容测试

后置验证：
  ☐ 方向 A: 渗透测试——尝试在 MFA→Consent 之间修改用户状态
  ☐ 方向 E: 嵌入者 onboarding 测试——新开发者首次嵌入的时间
  ☐ 方向 D: Admin Console 功能覆盖度 ≥80% 的后端管理 API
  ☐ 方向 C: 多租户负载测试——限流生效性和公平性
  ☐ 方向 B: 身份关联的 oracle-leak 验证
```

---

## 总结

这份分析文档（`analysis-five-directions-toctou-identitylink-ratelimit-adminconsole-sdk.md`）的质量在整个 SSO 项目的治理体系中处于**高层级**。它发现的 5 个方向的确是此前 40+ 方向文档未覆盖的盲区。

交叉评估中关于 Architecture/Administration Console 的更正（三文件结构）和 Ratelimit KeyBySubject 的更正（代码已存在测试中）不影响核心结论。

**我的关键分歧**是工作量估算的上调（方向 A 从 M 到 M+ 因为 3+ 状态点）和 Deps 分段（方向 E）的优先级上调至 P0。这两个调整背后的判断是：安全影响面广的问题和核心定位问题都应该在 Sprint 规划的早期 block 中处理，而不是 defer。
