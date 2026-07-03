现在我已深入阅读审计文档、架构文档和特征矩阵。以下是完整的架构分析报告。

---

# Snaplink 架构深度分析报告

> 基于 2026-07-01 完备性审计 + 架构文档 + 代码库结构  
> 分析定位：架构评审 / 技术战略规划  
> 视角：独立架构师（不参与具体实现）

---

## 1. 架构评估

### 1.1 当前架构的优势

**物理分层 + 强制依赖方向**是该架构最强的设计决策。第一段路径即为层（`shared/` → `domains/` → `protocols/` → `platform/` → `interfaces/` → `infrastructure/`），依赖方向指向 `shared/core`，由 `TestArchitecture_ImportBoundaries` 在编译期强制。这带来了：

- **绝对无循环导入**：编译期 + 门禁双保险，不会出现 Go 社区的典型循环噩梦。
- **精准的责任边界**：协议层（`oauth/`、`oidc/`）不会侵入基础设施层；基础设施层不会反向依赖协议。这意味替换 SQLite → PostgreSQL 不涉及任何 `protocols/` 变更。
- **可测试性设计**：`MemoryProvider` / `MemorySink` / `memory.Registry` 作为一等公民，取代 mock 框架。这是一个被低估的关键决策——它迫使每个 SPI 都有一个可独立运行的参考实现，天然防止了"接口太肥"或"接口与实现在语义上脱节"。

**六边形（Hexagonal）模式的一致性贯彻**也是关键优势：

```
HTTP → handlers.go → oauth.HandleXxx(deps) → core.SPI → defaultimpl/*
```

`*sso.Server` 通过 `accessors.go` 实现 `Deps` 接口，业务逻辑完全在无状态纯函数中。这使得：
- 单个 `Handle*` 函数可以在不启动 HTTP 服务器的情况下进行单元测试
- 切换路由框架（Echo → Gin → Chi）不影响业务逻辑
- 甚至可以将相同的 `Handle*` 暴露为 gRPC + HTTP（当前 proto 目录架构支持此方向）

**Oracle-leak 安全已内化到架构 DNA**：`DELETE RETURNING` 模式、`anonymousGreylist`、AMR 传播等模式都是"一次性设计正确，后续自动化"。这在身份平台是最重要的安全属性。

### 1.2 架构局限性

**物理分层的代价是跨层横切（cross-cutting）困难。** 例如审计文档识别出的"缓存 stale-while-revalidate"模式——它横跨 `oauth/`（自省端点）和 `security/`（JTI 防重放），需要在这两层之上引入一个没有独立层归属的缓存抽象。当前 `IntrospectionCache` 接口定义在 `oauth/` 内，但 `stale-while-revalidate` 是通用的缓存策略，不应绑定到 OAuth 领域。

**声明式配置以 opt-in 函数（`With*`）为主，缺少集中的能力注册表。** 当前需要在多个位置拼接特性注册（`sso.go`、`server_extensions.go`、`handlers.go`、`config/config.go`）。新增一个 OAuth grant 需要在至少 3 个文件中添加代码。这增加了新特性的入职成本。

**嵌套模块（nested modules）的治理成本被低估。** `infrastructure/` 下的 `saml/`、`ldap/`、`kerberos/`、`radius/`、`redis/`、`extauthz/`、`kms/*` 各自有自己的 `go.mod`。`make ci-modules` 解决了构建问题，但版本一致性、CVE 扫描、交叉测试（跨模块回归）是持续性负担。

**审计评分 73/90（81%）说明核心功能覆盖度尚好，但关键缺口（RBAC SSD/DSD、刷新令牌绝对上限）是安全合规的"硬杀伤"。** 对于一个定位为企业级的 SSO 平台，这些缺口的优先级可能超过任何新功能。

### 1.3 关键设计决策评估

| 决策 | 评价 | 风险 |
|------|------|------|
| 物理分层（路径即层） | **正确**。认知负担低，编译器可强制执行 | 学习曲线：新贡献者需要理解层映射 |
| 纯函数 `Handle*(deps, ctx)` | **正确**。可测试性最大化 | 函数签名膨胀：`Deps` 接口随需求增长 |
| nested modules | **正确但有代价**。独立版本控制有利 | 交叉回归、CVE 扫描增加维护成本 |
| `Memory*` 取代 mock | **优秀**。SPI 设计质量的强制检查 | 测试中可能遗漏并发竞争（MemoryStore 是线程安全的 → 掩盖问题） |
| commit gate 自检（TestMaintainability_*） | **正确**。防止架构债务积累 | 豁免列表有被滥用的倾向——审计确认豁免列表有 cap 机制 |
| YAML 配置决定 backend | **正确**。符合 12-factor | 运行时切换后不一致：memory → sqlite 切换丢失内存数据 |

### 1.4 识别的架构债务

| # | 债务 | 影响 | 严重程度 |
|---|------|------|---------|
| 1 | `claims_parameter_supported: true` 但 `essential`/`value`/`values` 未实现 | 采购审查信任度降低 | **中** |
| 2 | 自省缓存无 stale-while-revalidate | 高并发 mesh 场景惊群效应 | **中** |
| 3 | 刷新令牌无 `refresh_token_max_lifetime` | SOC 2 必查项 | **高** |
| 4 | 部分文件接近 500 行上限（`handle_register.go`） | 下一轮修改将触发拆分 | **低-中** |
| 5 | 跨模块测试覆盖率不一致（nested modules 的测试可能不完整） | 不可见的风险 | **中** |

---

## 2. 扩展方向

### 方向一：企业级 RBAC——静态/动态职责分离（SSD/DSD）+ 会话角色选择

**为什么需要：**
当前 RBAC 评分 7/11，缺失的两项（SSD、DSD）是 NIST RBAC 标准的核心组件。更关键的是——它们是 SOC 2、SOX、ISO 27001 合规审计的必查项。任何一个企业采购流程中，安全问卷的"职责分离"问题一旦回答"不支持"，大概率触发"进一步评估"延迟 3-6 个月。

**核心挑战：**
1. **互斥角色定义的表达力**：需要一种 DSL 或声明式配置来表达"角色 A 与角色 B 不可共存"。受 OPA（Open Policy Agent）的 `deny { ... }` 规则启发，但需更轻量。
2. **会话角色激活**：当前 JWT token 签发时嵌入了用户的所有角色。DSD 要求用户在会话中选择单一角色（或角色子集）操作。这意味着 token 签发需要一个新的 `active_roles` 或 `requested_role` 参数。
3. **现有架构兼容**：`permissions/` 包当前是纯 `Allow(principal, action, resource) → bool` 评估。SSD/DSD 要求 token 签发时做约束检查，token 使用时不检查——这是签发时 vs 运行时不同路径的验证。

**预期架构变更：**

```
permissions/
├── role.go                   ← 现有: 角色-权限关联
├── matcher.go                ← 现有: 通配符匹配
├── export.go                 ← 现有: 策略导出
├── ssd.go                    ← 新增: 静态职责分离验证器
├── dsd.go                    ← 新增: 动态角色激活检查
├── role_session.go           ← 新增: 会话角色选择
└── permissions_test.go
```

`ssd.go` 的核心接口：

```
type SeparationOfDuties interface {
    // 验证用户角色分配不违反 SSD 约束
    ValidateSSD(roles []string) error
    // 返回互斥角色对列表（用于 admin API）
    MutuallyExclusiveRoles() [][2]string
}
```

**对现有系统的影响：**
- **低**影响。新增接口即可，现有 `Permit()` 调用不变。
- 需要修改 token 签发路径，支持 `active_roles` 参数。
- Discovery 文档需新增 `role_endpoint`，使 RP 可以查询用户可选的角色列表。

**选项与权衡：**

| 选项 | 优点 | 缺点 |
|------|------|------|
| A. 纯代码声明：`role.exclude: [auditor]` | 最简单，零依赖 | 互斥规则不可热更新 |
| B. YAML 策略文件：声明式互斥 + 断言 | 可热加载，支持复杂约束 | 需要 DSL 解析器 |
| 推荐 | **A** 作为第一版，**B** 作为后续扩展 | — |

---

### 方向二：令牌生命周期治理——按维度批量回收 + 绝对过期 + 清理策略

**为什么需要：**
审计指出三个缺口：① 无 `refresh_token_max_lifetime`（安全审计必查）、② 缺少按用户/租户/client 的批量回收（运维必查）、③ 过期令牌存储空间无限累积。这三个缺口合起来是运维安全的主要痛点——如果管理员无法快速回收离职员工的 refresh token，当前只能 `DeleteFamily` 逐条处理。

**核心挑战：**
1. **索引结构的设计**：按用户/租户/client 批量回收需要对 refresh token 存储建立二级索引。当前只有 `FamilyID` → token 的正向映射。新增索引需考虑 `MemoryStore` + `SQLiteStore` 双实现的一致性和并发安全。
2. **绝对过期 vs 滑动过期的协调**：两种策略不是二选一。标准推荐是混合模式——滑动窗口（每次刷新重置 TTL）+ 绝对上限（从首次签发算起 N 天）。这需要在 `RefreshTokenStore` 接口中引入 `issued_at` 时间戳，并在 `HandleRefresh` 中增加绝对值检查。
3. **过期令牌自动清理**：需要后台定时任务（`ticker` 或 `gc` goroutine），但当前架构是事件驱动的，没有调度框架。引入 `cleanup` goroutine 需要一个生命周期管理机制（启动/停止/健康检查）。

**预期的架构变更：**

```
oauth/
├── refresh_token.go          ← 当前: 签发 + 轮换 + family
├── refresh_grace.go          ← 当前: 并发容忍窗口
├── refresh_reclaim.go        ← 新增: 按维度批量回收
├── refresh_cleanup.go        ← 新增: 过期清理 + 时间维护
```

需要对 `RefreshTokenStore` 接口增加方法：

```
type RefreshTokenStore interface {
    // 现有
    Create(...)
    Consume(tokenHash string) (*RefreshToken, error)
    DeleteFamily(familyID string) error
    // 新增
    ReclaimByUser(userID string) (int, error)
    ReclaimByTenant(tenantID string) (int, error)
    ReclaimByClient(clientID string) (int, error)
    CountExpired(before time.Time) (int, error)
    DeleteExpired(before time.Time) (int, error)
}
```

**对现有系统的影响：**
- **中**。接口变更会影响 `MemoryRefreshTokenStore` + `SQLiteRefreshTokenStore` 两个实现。
- 需要更新 admin API（新增 `POST /api/v1/admin/tokens/reclaim` 端点）。
- 需要在文档中声明新的行为。

---

### 方向三：自省缓存 stale-while-revalidate + DPoP token_type 修复

**为什么需要：**
这是审计三的两个技术性缺口。虽然不像合规那样显式，但在高并发 mesh 环境中，自省端点的惊群效应是实际性能瓶颈。`token_type` 的错误声明是 RFC 7662 的语义违规——如果资源服务器依赖 `token_type` 来决定验证策略（DPoP vs Bearer），当前返回永远 `"Bearer"` 会误导其行为。

**核心挑战：**
1. **stale-while-revalidate 的 CAS 竞争**：多个并发请求同时发现缓存过期（TTL 的 80%-100% 窗口），都需要触发后台刷新，但只需一个实际回源。需要 `CompareAndSwap` 或 `sync.Once` 模式确保只有一个协程执行刷新。
2. **DPoP token 的自省 metadata 传播**：当前自省端点只看到 token 的 hash/claims，不知道它是否 DPoP-bound。需要将 DPoP binding 的状态编码到令牌存储或缓存中。

**预期的架构变更：**

```
oauth/
├── introspection_cache.go    ← 当前: IntrospectionCache 接口
├── introspection_cache.go    ← 扩展: 加入 stale-while-revalidate 语义
├── introspection.go          ← 修复: DPoP token_type 识别
```

具体的 SPI 扩展已在审计文档中给出，重复价值不大。关键点是：**缓存语义的变更不应该改变 `IntrospectionCache` 接口签名**——通过内部实现转型（在 memory/sqlite 实现中支持 `staleTTL` 字段），而不是迫使所有调用方变更。

**对现有系统的影响：**
- **低**。接口不变，仅实现层增强。
- `IntrospectionCache` 的 `Get` 返回新增 `staleOk` 布尔值，不影响现有调用方（兼容的默认值：`staleOk = false`）。
- 性能测试需要验证惊群效应是否消除。

---

### 方向四：OIDC Session Management 1.0——如果rame + RP 侧 session 轮询

**为什么需要：**
审计四指出 `check_session_iframe` 和 `end_session_iframe` 缺失。虽然这不是规范 REQUIRED，但它在企业场景有实际需求——当一个用户在一个标签页中登出后，其他标签页的 RP 需要立即感知到状态变化而不需要全页面刷新。当前 Backchannel Logout 可以实现这一点，但依赖 OP → RP 的直接通信，并非所有 RP 都支持。Session Management iframe 是纯客户端机制，部署成本低。

**核心挑战：**
1. **跨域 iframe 的 postMessage 通信**：需要实现 OIDC §4 定义的 `op.cookie` → `RP iframe` 的 postMessage 协议。这本质上是前端代码，但需要与后端 session cookie 的 SameSite/HttpOnly 属性协调。
2. **session state 的生成和管理**：规范定义的 `session_state` 值是盐化哈希（`sha256(client_id + origin + salt)`）。当前没有 session state 的生成和存储机制。需要新增 `SessionStateGenerator` 接口。
3. **与现有 logout 机制的集成**：当前支持 RP-Initiated Logout、Backchannel Logout、Frontchannel Logout。Session Management iframe 不能独立于 logout 流程工作——session state 必须在 logout 时更新。

**预期的架构变更：**

```
oidc/
├── session_state.go           ← 新增: session_state 生成 + 验证
├── check_session_iframe.go   ← 新增: iframe 端点
├── handle_end_session.go     ← 修改: logout 时更新 session state
interfaces/web/
├── check_session.html        ← 新增: 静态 iframe HTML
```

**对现有系统的影响：**
- **低-中**。功能独立，不需要修改现有 grant 流程。
- 但应与现有 logout 流程集成，避免信息不一致。
- 如果 RP 普遍支持 Backchannel Logout（已实现），则本方向的投入产出比 **不高**。

> **决策建议：** 将本方向标记为 P2（可选），**仅当**下游客户明确要求 RP 侧 session 主动轮询时才实现。

---

### 方向五：Fine-Grained Authorization 抽象层——为 ReBAC/ABAC 建立 SPI

**为什么需要：**
审计五指出当前是"粗粒度 scope-level"，缺少 resource-level 和 attribute-based 权限。虽然这不是 NIST RBAC 标准的要求，但它是企业级 IAM 平台的竞争分水岭。Google IAM、AWS IAM、Auth0 FGA（Fine-Grained Authorization）都在往这个方向走。

**核心挑战：**
1. **数据模型选择**：RBAC × ABAC × ReBAC 各有优劣。RBAC 最简单但粒度粗；ABAC 灵活但难以审计；ReBAC（基于关系的访问控制，Google Zanzibar 模型）适用于大规模多租户场景但实现复杂度高。当前架构是为 RBAC 优化的，引入 ReBAC 需要对整个授权模型重新思考。
2. **与现有权限系统的集成**：当前 `permissions.Permissions`（`Allow(principal, action, resource)`）是简单的布尔评估。ABAC/ReBAC 需要上下文（用户属性、资源属性、环境条件）。设计一个可扩展的 `Evaluator` SPI，使新范式能逐步引入而不破坏现有 RBAC。
3. **性能要求**：授权决策通常需要在 1-5ms 内完成。ABAC/ReBAC 的评估复杂度高于 RBAC 的通配符匹配，需要缓存和预计算策略。

**预期的架构变更：**

```
shared/spi/
├── authorization.go           ← 新增: 抽象 AuthorizationEvaluator 接口
domains/permissions/
├── ...
├── evaluator.go               ← 新增: 组合评估器（RBAC + ABAC + ReBAC 管道）
├── abac.go                    ← 新增: 属性条件评估
├── rebac.go                   ← 新增: 关系查询接口（Zanzibar 风格）
├── rebac_memory.go            ← 新增: 内存实现（测试用）
```

接口设计草案：

```
type AuthorizationEvaluator interface {
    // RBAC: 当前路径
    Evaluate(ctx context.Context, p Principal, a Action, r Resource) (Decision, error)
}
// 扩展: 引入条件
type ConditionalEvaluator interface {
    AuthorizationEvaluator
    EvaluateWithContext(ctx context.Context, p Principal, a Action,
        r Resource, env Environment) (Decision, error)
}
```

**对现有系统的影响：**
- **低**（初始设计）。新接口不会替代现有 `Permissions`，而是作为补充。
- 中间件层的 tenant 隔离（当前基于 tenant ID）可以与 ReBAC 的关系模型协同。
- 一旦引入，所有新增授权点都应通过 `AuthorizationEvaluator`，但现有路径保持原样。

| 选项 | 优点 | 缺点 | 推荐阶段 |
|------|------|------|---------|
| A. 新增 `Condition` 接口，附加到现有角色 | 渐进式，最小变更 | 不如 ReBAC 优雅，大数据量性能差 | P2 短期 |
| B. 实现 Zanzibar 风格的 Tuple 模型（object#relation@user） | Google 验证的生产模型 | 存储模型（全量关系图）复杂 | P2 中期 |
| C. OPA 集成（Rego 策略语言） | 行业标准，策略即代码 | 引入 C 依赖（wasm）或外部进程，增加运维复杂度 | P2 可选 |
| 推荐 | **A → B** 的两步路径。先用轻量条件，后续演进 | — | — |

---

## 3. 接口设计建议

### 3.1 核心原则

1. **SPI 优先，实现其次**：每个新能力先定义 `shared/spi/` 或 `shared/core/` 中的接口，再在 `infrastructure/` 中提供默认实现。现有架构已遵循此规则，需要在新方向中持续保持。

2. **一元组接口（One-Method Interface）**：现有 `IntrospectionCache` 等接口已经够小。新增接口也应是"一个方法一个接口"（如 `SSDValidator`、`RoleActivationResolver`）。接口越小，替换和测试越容易。

3. **以 `With*` 函数作为配置入口**：现有模式（`WithSSDValidator(v)`）保持一致。不要在 server constructor 上添加新的必需参数。

4. **向前兼容的默认行为**：任何新接口的缺失不应导致运行时错误，而应降级到现有行为。例如，没有注册 `SSDValidator` → 不检查互斥角色（保持现有行为，不是拒绝所有请求）。

### 3.2 是否需要新的抽象层

**短期（P0-P1）不需要新的架构层。** 现有六层结构（shared → domains → protocols → platform → interfaces → infrastructure）足够容纳所有新增能力：

- SSD/DSD → `domains/permissions/`
- 刷新令牌回收 → `protocols/oauth/`
- 自省缓存增强 → `platform/`（新 `cache/` 包）或 `protocols/oauth/`
- Session management iframe → `protocols/oidc/`
- Fine-grained auth → `domains/permissions/` + `shared/spi/`

**中期值得讨论的问题：是否应该引入 `cache/` 作为平台层（`platform/`）的正式子包。** 当前缓存逻辑分散在各模块（`oauth/introspection_cache.go`、`oidc/discovery_doc_cache.go`、`security/jti_replay.go`），都是独立的 memory map + TTL 实现。抽出一个 `platform/cache/` 统一缓存策略（支持 TTL、stale-while-revalidate、eviction callback）可以减少重复代码，并使惊群效应修复更容易。

### 3.3 向后兼容性

| 变更类型 | 兼容策略 | 示例 |
|---------|---------|------|
| 接口新增方法 | Go 接口新增方法就是破坏性变更——**必须用新接口** | `RefreshTokenStoreV2` 继承 `RefreshTokenStore` |
| Deps 接口新增 | 如果 `Deps` 是 server 的内部聚合，新增方法不影响外部调用方 | `Deps` 是 `*sso.Server` 的内部契约 |
| 配置项新增 | YAML/环境变量新增，默认值保持行为不变 | `refresh_token_max_lifetime: 0` → 无上限 |
| 新 `With*` 选项 | 新增即兼容，不影响现有构造调用 | `WithSSDValidator(nil)` = 无操作 |

---

## 4. 技术选型

### 4.1 当前评估：不需要引入新的大框架

审计文档识别的缺口没有一个需要引入新的大技术栈（不用 OPA、不用 Istio、不用 Cassandra）。项目是纯 Go，当前架构完全能承载这些工程改进。以下是几个可能引入的领域及其评估：

| 潜在引入 | 是否必要 | 理由 |
|----------|---------|------|
| OPA（Open Policy Agent） | **不必要** | 当前 RBAC 扩展可以用纯 Go 实现。OPA 引入 Rego 语言学习成本 + 外部进程依赖，不符合项目"纯 Go + 最小依赖"的原则 |
| Redis 集群作为集中缓存 | **不必要** | 单机 MemoryCache + cross-replica invalidation（已有 cluster bus）即可。如果是多副本场景，引入 Redis 会增加部署复杂度 |
| 消息队列（NATS/Kafka） | **不必要** | 当前 cluster bus（memory/etcd）足够满足令牌回收事件。消息队列引入的至少延迟和运维成本 > 收益 |
| Prometheus 指标 | **已引入** | metrics 包已存在，保持即可 |

### 4.2 第三方依赖的评估标准

| 标准 | 阈值 | 说明 |
|------|------|------|
| CGO | 零 | 必须是纯 Go。CGO = 排除 |
| 许可证 | 必须兼容 | Apache 2.0 / MIT / BSD。AGPL = 排除 |
| 传递依赖数 | ≤ 3 | 新增依赖不应引入超过 3 个传递依赖 |
| 代码行数 | ≤ 5000 | 小型库优先，避免"只需要一个函数就引入整个框架" |
| 内审可用 | 需要 | 如果源码少于 2000 行，优先内建而非依赖 |

### 4.3 自建 vs 采购决策

当前项目定位是 SDK + runnable binary，没有 SaaS 层。因此"采购"通常不适用（不需要买第三方 SaaS）。但有两种情况需要考虑：

| 场景 | 决策 | 理由 |
|------|------|------|
| RBAC SSD/DSD 策略语言 | **自建 DSL，不采购** | 互斥角色定义可以用 JSON/YAML 配置，不需要完整的策略引擎 |
| 缓存 stale-while-revalidate | **自建，不采购** | 纯本地策略，不需要外部缓存系统 |
| 跨区域数据同步 | **评估同时** | 如果客户要求跨区域同步令牌，需要评估是否引入 CRDT 库或使用数据库级复制 |

对 Snaplink 来说，"自建"几乎是默认选择——因为纯 Go + 零外部依赖是核心产品属性。

---

## 5. 实施路线图

### 5.1 优先级排序

```
P0: 修复构建 + 合规必查项（构建失败阻塞一切）
P1: 运维安全缺口（刷新令牌治理 + 自省缓存）
P2: 协议完备性补充（session iframe + select_account + claims 细化）
P3: 长期架构演进（Fine-Grained Authorization 抽象层）
```

### 5.2 阶段划分

#### 阶段一：基础修复（~1 周）

| 项目 | 工作量 | 依赖 | 交付物 |
|------|--------|------|--------|
| 修复构建断裂 | 0.5d | 无 | `go build ./...` 通过 |
| `refresh_token_max_lifetime` 配置项 | 1d | 无 | 新配置 + 文档 + 测试 |
| `claims_parameter_supported` 声明修正 | 0.5d | 无 | Discovery 文档修正（`false` + 注释说明限制） |
| **门禁** | | | `TestMaintainability_*` 全部通过 |

**里程碑 M1：构建通过，合规缺口补齐**

#### 阶段二：RBAC 职责分离（~2 周）

| 项目 | 工作量 | 依赖 | 交付物 |
|------|--------|------|--------|
| SSD 声明式互斥角色定义（YAML schema） | 1d | 无 | `role.exclude` 配置解析 |
| SSD 验证器（`ssd.go`） | 1d | 配置解析 | `ValidateSSD()` 实现 |
| DSD 会话角色选择（`requested_role` 参数） | 2d | 无 | 角色子集 token 签发 |
| Admin API：角色互斥查询 | 1d | SSD 验证器 | `GET /api/v1/admin/roles` 返回互斥信息 |
| 文档更新（feature-matrix.md、error-codes.md） | 0.5d | — | — |
| 集成测试 | 1.5d | 功能实现 | `permissionstest.ConformanceSuite` 扩展 |
| **门禁** | | | 全通过 + 新豁免为零 |

**里程碑 M2：SOC 2 职责分离需求可答"是"**

#### 阶段三：令牌生命周期治理（~2 周）

| 项目 | 工作量 | 依赖 | 交付物 |
|------|--------|------|------|
| `RefreshTokenStore` 接口扩展 | 1d | 无（设计评审） | `ReclaimByUser/Tenant/Client` + Count/DeleteExpired |
| MemoryStore 实现 | 0.5d | 接口定义 | 二级索引 |
| SQLiteStore 实现 | 1d | 接口定义 | 数据库 migration |
| Admin API：批量回收 + 过期统计 | 2d | 存储实现 | `POST /token/reclaim` + `GET /token/stats` |
| 超时清理 goroutine | 1d | 无 | 生命周期管理 + 健康检查 |
| 文档 + 测试 | 1.5d | — | — |
| **门禁** | | | 全通过 |

**里程碑 M3：运维安全性满足企业审计要求**

#### 阶段四：自省缓存增强 + 协议补齐（~2 周）

| 项目 | 工作量 | 依赖 | 交付物 |
|------|--------|------|------|
| `platform/cache/` 统一缓存包（可选） | 2d | 设计决策 | TTL + stale-while-revalidate + eviction callback |
| 自省缓存迁移到新 cache 包 | 1d | cache 包 | 惊群效应缓解 |
| DPoP `token_type` 修复 | 1d | 无 | 自省响应 `"token_type": "DPoP"` |
| `select_account` prompt 实现（降级到 `login`） | 1d | 无 | 规范合规 + 自动降级 |
| `state` 参数 OIDC 模式强制检查 | 0.5d | 无 | OAuth2 Security BCP 合规 |
| 文档 + 测试 | 1.5d | — | — |
| **门禁** | | | 全通过 |

**里程碑 M4：核心协议完备性 ≥ 90%**

#### 阶段五：长期架构能力（~3 周，可并行）

| 项目 | 工作量 | 依赖 | 交付物 |
|------|--------|------|------|
| `ConditionalEvaluator` 接口设计 | 1d | 架构评审 | 设计文档 + SPI |
| 基于条件的权限扩展（客户 IP、时间、客户端类型） | 2d | 接口 | 简单 ABAC 能力 |
| OIDC Session Management iframe | 2d | 架构评审 | `check_session_iframe` + `session_state` |
| 文档 + 测试 | 2d | — | — |
| **门禁** | | | 全通过 |

**里程碑 M5：架构可扩展性达到"下一个增量为零债务"**

### 5.3 风险点与缓解策略

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| RBAC SSD/DSD 设计过度复杂 | 中 | 高（延期） | 严格约束 MVP 范围：仅互斥角色列表 + 会话角色选择。免除条件表达式 |
| RefreshTokenStore 接口变更破坏现有实现 | 低 | 中 | 使用 V2 接口模式：`RefreshTokenStoreV2` 嵌入 `RefreshTokenStore` |
| 自省缓存性能改进收益不明显 | 中 | 低 | 先做基准测试（benchmark），用数据决定是否实施 |
| 编译/门禁修复期间发现更多隐藏问题 | 中 | 中 | 预留缓冲时间（Phase 1 的 0.5d → 1d） |
| 跨模块一致性——nested modules 是否需要同等更新 | 低 | 中 | `make ci-modules` 覆盖；如果影响大，分解为独立任务 |

### 5.4 治理建议

1. **每次阶段完成执行 `make ci` 全量检查**。所有门禁必须在阶段边界通过，允许阶段内临时性失败。
2. **每个阶段交付一个可部署的版本**。避免"半完成"代码进入主线。
3. **文档变更**与代码变更**同 commit**。不允许"先写代码，回头补文档"——这是当前 `claims_parameter_supported` 问题的根源。
4. **构建断裂必须先于任何架构工作修复**（M1 的 P0 状态）。没有通过编译的代码库不存在"架构评审"议题。

---

## 总结

| 维度 | 核心结论 |
|------|---------|
| **架构健康度** | 优秀的基础——物理分层 + 纯函数六边形模式是身份平台的最佳实践。现有债务可控。 |
| **最紧急缺口** | RBAC SSD/DSD（合规） + 刷新令牌绝对上限（安全）——两个都是 P0 |
| **最佳投资方向** | 企业级 RBAC > 令牌生命周期治理 > 缓存增强 > 协议补齐 > 权限抽象层 |
| **关键风险** | 设计过度复杂（尤其是 RBAC）。必须坚持 MVP 范围的严格边界。 |
| **总预估** | 5 个阶段约 8-10 周，含缓冲和回归测试。M1-M2 为硬性依赖——先合规，再功能。 |

**最终建议：** 优先完成 M1（修复构建+合规配置），然后 M2（RBAC SSD/DSD），再并行推进 M3+M4。M5 可以推迟到下一季度——它没有合规/安全的紧急约束，且有更成熟的开源参考设计可以学习。
