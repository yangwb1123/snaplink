# 架构债务、系统性风险与横切关注点分析

> 基于 2026-07-01 对全代码库的收尾扫描。  
> 分析视角：资深架构师 / 产品经理。  
> 定位：此前 4 轮分析均针对"新增什么方向"或"修复什么 bug/边界"。本轮聚焦 **已有架构中隐含的债务、系统性风险、以及不易被"功能需求"覆盖的横切关注点**。  
> 覆盖：接口膨胀、配置蔓延、多后端一致性、文档与实现漂移、可替换性。  
> 原则：不写代码。

---

## 总体视角

先前 4 轮分析回答了"还要加什么"（新功能/修复/优化）。本报告回答一个截然不同的问题：**截止 2026-07-01，已有架构的哪些内在特征正在积累债务，不加干预会演变为未来瓶颈？**

---

## 方向一：`Deps` 接口膨胀——从组合根到上帝接口的缓慢漂移

### 现状

Server 用单一 `Deps` 接口（或多种 `Deps` 变体）向 handler 暴露依赖：

```go
// interfaces/admin/deps.go
type Deps interface {
    ConnectionStore() connections.Store          // +
    TenantUserStore() core.TenantUserStore       // +
    InvitationStore() core.InvitationStore       // +
    InvitationSender() spi.InvitationSender      // +
    ConsentStore() core.ConsentStore             // +
    MFAEnrollmentStore() core.MFAEnrollmentStore // +
    PasswordCredentialStore() core.PasswordCredentialStore // +
    UserProvider() core.UserProvider             // +
    AccountLockout() security.AccountLockout     // +
    DeviceSecretStore() core.DeviceSecretStore   // +
    PasswordResetStore() core.PasswordResetStore // +
    EmailChangeStore() core.EmailChangeStore     // +
    Auditor() *audit.Recorder                    // +
    Logger() spi.Logger                          // +
    InvalidateConnectionCache(connID string)     // +
}
```

当前共 **15 个方法**，且仍在增长（本次扫描确认方向二中的 10 个 admin 操作需要更多的 store 方法）。同样模式的接口存在于：

| 接口 | 位置 | 方法数 | 用途 |
|------|------|--------|------|
| `handler.Deps` | `internal/handler/` | ~25+ | 核心 HTTP handler 的依赖 |
| `Server.Deps` (内隐) | `accessors.go` | ~60+ | 所有 `*Server` 的访问器 |
| `RegisterDeps` | `oauth/handle_register.go` | ~8 | DCR 注册 |
| `TokenExchangeDeps` | `internal/handler/tokengrant/` | ~10+ | Token exchange |

### 风险

| 问题 | 具体表现 |
|------|----------|
| 依赖隐式化 | 一个 handler 声明 `Deps` 但有 15 个方法，实际只用其中 3-4 个。**列出的依赖不等于真正需要的依赖**——测试时需要 mock/提供全部 15 个 |
| 循环依赖 | 接口定义在消费方包(`interfaces/admin/`)而非提供方包(`interfaces/sso/`)。随方法数增长，接口签名可能引用提供方尚未导入的包→在 Go 中这造成编译失败（当前构建断裂即是此原因） |
| 测试负担 | `*Server` 满足接口意味着所有 15 个 store 都必须初始化。测试用 `rcovNewServer` 不得不 seed 全部 store，即使只测一个 handler |
| 构建断裂传播 | 接口增加一个方法 → 所有实现方编译失败。当前构建断裂已证实此风险 |

### 根本原因

Go 接口的隐含满足（duck typing）使得接口膨胀不立即报错，而是等到**实现类型被传递时**才编译失败。项目中多个 `Deps` 接口各自独立演化、缺乏统一治理。

### 缓解方向

1. **面向接口隔离（ISP）重构**：将 `admin.Deps` 拆为多个细粒度接口，每个 handler 只声明它实际需要的：

   ```go
   // Before
   type Deps interface {
       ConnectionStore() connections.Store
       UserProvider() core.UserProvider
       Auditor() *audit.Recorder
       // ... 12 more
   }
   
   // After
   type ConsentDeps interface {
       ConsentStore() core.ConsentStore
       Auditor() *audit.Recorder
   }
   type PasswordDeps interface {
       PasswordCredentialStore() core.PasswordCredentialStore
       Auditor() *audit.Recorder
   }
   ```

   `HandleAdminListUserConsents` 只声明 `ConsentDeps`，`HandleAdminResetUserPassword` 只声明 `PasswordDeps`。`*Server` 可通过一个**适配器映射**将自身按需适配为任何子接口：

   ```go
   type Server struct { /* fields */ }
   
   func (s *Server) Adapt(intf any) bool {
       switch d := intf.(type) {
       case *ConsentDeps:
           *d = s // *Server satisfies ConsentDeps
           return true
       case *PasswordDeps:
           *d = s
           return true
       }
       return false
   }
   ```

   或将 handler 注册改为 `server.Handle(path, s.HandleAdminListUserConsents)` 模式，每个 handler 方法内部只从 `s` 取自己需要的访问器——根本不需要接口参数。

2. **编译期守卫**：在每个 `Deps` 接口定义后加：

   ```go
   var _ Deps = &Server{}  // 编译期确保实现
   ```

   让接口扩展时立即报错，而非在调用处才能发现。

3. **接口方法计数门禁**：在 `checks/` 中添加规则——单个 `Deps` 接口不得超过 10 个方法（在 `checks/invariants.py` 中添加 `MaxInterfaceMethods` 检查）。

### 工作量与影响

- **工作量**：L（重构分裂接口 + 更新所有调用方 + 添加守卫）
- **当前风险**：中（构建断裂已证实，其他 `Deps` 接口可能同样断裂）
- **长期收益**：降低构建断裂概率、减少测试负担、提高可读性

---

## 方向二：配置蔓延——30+ 配置结构体的演进治理

### 现状

`config.Config` 根结构体包含 **~35 个嵌套配置结构体**：

```
ServerConfig, AuthenticatorsConfig, LoggingConfig, AuditConfig,
PermissionsConfig, NetworkConfig, ClientConfig[], AdminConfig,
BootstrapConfig, SnapshotConfig, ReleasesConfig, GeoConfig,
RegionConfig, TenantConfig, ConnectionsConfig, SecurityConfig,
MetricsConfig, OAuthConfig, BackchannelLogoutConfig,
ClientRegistrationConfig, IdentityConfig, WebAuthnConfig,
RegistryConfig, RiskConfig, MFAConfig, AnomalyConfig,
ClusterConfig, RedisConfig, PostgresConfig, KeysConfig,
CIBAConfig, OIDCConfig, SCIMConfig, DPoPConfig, CAEPConfig,
SPIFFEConfig, MeshConfig, FederationConfig, SAMLConfig,
HostedLoginConfig, SelfServiceConfig, NativeSSOConfig,
ProtectedResourceMetadataConfig
```

逐轮演进的后果：

| 问题 | 示例 |
|------|------|
| 嵌套深度 4+ | `config.Keys.Rotation.CoordinatedCutover.GracePeriod` |
| 相同概念不同命名 | `oauth.jar.fetcher.timeout` vs `caep.receiver_timeout` vs `federation.fetch_timeout` |
| 零值歧义 | `timeout: 0` 是"用默认值"还是"禁用超时"？不同配置体有不同解释 |
| 文档滞后 | `docs/config-reference.md` 记录了约 60 个配置键，但实际 YAML 中可用配置键 >200 |
| 无版本化 | 重命名一个配置键（如 `dpop.proof_max_age` → `dpop.max_proof_age`）需手动处理旧文件 |

### 具体风险点

#### 2.1 默认值散布

默认值定义在三个地方：

| 位置 | 类型 | 问题 |
|------|------|------|
| `config/*.go` 的 `applyDefaults()` | ~15 个结构体各有一个 applyDefaults | 分散——修改一处容易漏掉另一处 |
| `config/config_*.go` 的 struct 字面量 | 部分默认值在此 | 与 applyDefaults 可能不一致 |
| `interfaces/sso/options_*.go` 的 function options | ~100+ With* Option | 多个层次定义同一默认值 |

#### 2.2 配置与代码的耦合

部分配置只能在 Go 代码中设置（`With*` option），无法通过 YAML 表达：

```go
// config/config.go:8 — 注释自认的边界
// Code-only inputs (password verifier, SMS sender, CA pool, ...)
// are still wired in Go because they're not safely expressible in YAML.
```

但哪些是 "not safely expressible" 没有形式化定义，随着时间推移，这个边界在漂移。

### 缓解方向

1. **配置 lint 工具增强**（依赖方向四的 `sso-ctl config validate`）：增加 `--strict` 模式，检查：
   - 已废弃的配置键（通过 `deprecated.yaml` 清单）
   - 配置值超出合理范围（`timeout: -1s`、`pool_size: 0`）
   - 必填字段缺失（`redis.master_name` 在 sentinel 模式下）

2. **配置值归一化**：统一命名约定——所有超时配置使用 `*_timeout`，所有 TTL 使用 `*_ttl`，所有后端使用 `*.backend`。在 `Source.Load()` 中自动映射旧名→新名。

3. **配置 schema 生成**：从 Go 结构体自动生成 JSON Schema / YAML schema 文件，用于 IDE 自动补全和 CI 验证。参考 `goccy/go-yaml` 的 struct tag → schema 的转换。

### 工作量与影响

- **工作量**：M（配置 lint + schema 生成 + 命名规范化）
- **当前风险**：低-中（仅影响操作体验，不影响运行时正确性）
- **长期收益**：降低配置事故概率、IDE 自动补全、CI 提前捕获配置错误

---

## 方向三：多后端语义一致性——Memory/SQLite/Redis/Postgres 的隐性漂移

### 现状

项目提供了 4 个后端实现（memory、sqlite、redis、postgres），每个覆盖不同的 store 子集：

| Store | Memory | SQLite | Redis | Postgres |
|-------|--------|--------|-------|----------|
| AuthCode | ✅ | ✅ | ✅ | ❌ |
| RefreshToken | ✅ | ✅ | ✅ | ❌ |
| DeviceCode | ✅ | ✅ | ✅ | ❌ |
| PAR | ✅ | ✅ | ✅ | ❌ |
| CIBA | ✅ | ✅ | ✅ | ❌ |
| Session | ✅ | ✅ | ✅ | ❌ |
| Client | ✅ | ✅ | ✅ | ✅ |
| User | ✅ | ✅ | ✅ | ✅ |
| Consent | ✅ | ✅ | ✅ | ✅ |
| JTIReplay | ✅ | ✅ | ✅ | ❌ |
| AccountLockout | ✅ | ✅ | ✅ | ❌ |
| MFAChallenge | ✅ | ✅ | ✅ | ❌ |
| DeviceSecret | ✅ | ✅ | ❌ | ✅ |
| PairwiseSubject | ✅ | ✅ | ❌ | ✅ |
| RevocationSet | ✅ | ✅ | ❌ | ❌ |
| RateLimit | ✅ | ✅ | ✅ | ❌ |

**4 个后端没有一个覆盖全部 16 个 store**。Postgres 缺了 8 个关键热路径 store（AuthCode、RefreshToken、DeviceCode、PAR、CIBA、Session、JTIReplay、MFAChallenge）。

### 具体风险

#### 3.1 语义差异 vs 接口契约

相同的 SPI 接口在不同后端上有微妙的语义差异：

| 语义 | Memory | SQLite | Redis | 影响 |
|------|--------|--------|-------|------|
| 单用删除 | 返 true/false | `DELETE ... RETURNING` 一条 SQL | `GETDEL` 原子 | Redis 的 GETDEL 在 key 不存在时返回 nil → Go 中 `val, err := ...` err==nil, val=="" |
| 并发安全 | `sync.Mutex` 全序列化 | WAL 模式 + `busy_timeout` | 单线程 | Memory 在 16 核上的扩展性最差 |
| 过期清理 | 惰性 + 写前扫描 | `expires_at < datetime('now')` WHERE 子句 | `TTL`/`EXPIRE` 自动过期 | Redis 自动清理，Memory 不清理导致 OOM |
| 事务 | 不适用 | `BEGIN IMMEDIATE` + ROLLBACK | Lua/MULTI | SQLite 可用事务，Redis 需 Lua 脚本做 CAS |

#### 3.2 错误类型不统一

同一错误条件在不同后端返回不同 Go 错误：

| 条件 | Memory | SQLite | Redis | Postgres |
|------|--------|--------|-------|----------|
| Client 不存在 | `ErrNoSuchClient` | `sql.ErrNoRows` | `redis.Nil` | `pgx.ErrNoRows` |
| Token 已消费 | `ErrTokenConsumed` | `sql.ErrNoRows` (DELETE 影响 0 行) | `redis.Nil` | N/A |

每个后端都需要在接口实现层将驱动级错误转换为 `core.Err*` 常量。当前所有后端都做了这个转换，但人工维护——新增一个 store 接口方法时，4 个后端各有一份独立的错误映射。

#### 3.3 测试覆盖偏差

| 后端 | 测试文件数 | 集成测试覆盖 |
|------|-----------|-------------|
| Memory | ~150 | 完整 |
| SQLite | ~30 | 主要路径 |
| Redis | ~10-stores × 小测试 | 热路径 |
| Postgres | ~10-stores | 部分 |

Memory 是测试覆盖率最全的（因为它也是单测默认后端），而 Postgres 和 Redis 的测试覆盖了主要路径但遗漏了大量边界。

### 缓解方向

1. **后端语义契约测试**（扩展第三卷的混沌测试方向⑤）：为每个 SPI 定义一个可执行契约（`*test.ConformanceSuite`），所有后端必须通过相同套件。参考 `permissionstest.ConformanceSuite` 模式（已存在！）：

   ```go
   // oauthspitest/auth_code.go
   func AuthCodeConformance(t *testing.T, factory func() oauth.AuthCodeStore) {
       t.Run("ConsumeSingleUse", ...)
       t.Run("ConsumeTwiceReturnsError", ...)
       t.Run("ExpiredCodeReturnsErrNotFound", ...)
       t.Run("ConcurrentConsumeExactlyOneWins", ...)
   }
   ```

   此模式已存在于 `domains/permissions/permissionstest/conformance.go`——应推广到所有核心 SPI。

2. **错误映射审计**：确保每个 store 的 `Get`、`Consume`、`Delete` 等方法返回 `core.ErrNoSuchClient` / `core.ErrNotFound` / `core.ErrTokenConsumed` 等标准化错误。添加 CI 门禁检查。

3. **Postgres 热路径补齐**：Session、AuthCode、RefreshToken、DeviceCode、PAR、JTIReplay——这些是 OAuth 2.0 的核心热路径。操作者选择 Postgres 作为主存储时，不应被迫依赖 SQLite 做这些 store。

### 工作量与影响

- **工作量**：XL（契约测试框架 ~200 行 + 各 Store 测试 ~50 行/条 × 30 条）
- **风险**：中（后端漂移不会导致功能缺失，但可能导致难以调试的线上问题——如 SQLite 环境下测试通过的 refresh 轮换在 Redis 环境下静默失败）
- **长期收益**：后端实现的一致性、在 CI 中捕获回归、降低"每个后端行为不同"的运维认知负担

---

## 方向四：文档与实现的漂移检测

### 现状

项目有多份「声明式」文档，记录了开放给外部消费方的契约：

| 文档 | 大小 | 生命周期管理 |
|------|------|-------------|
| `docs/openapi.yaml` | 8350 行 / 126 个端点 | 手动维护 |
| `docs/error-codes.md` | ~150 个 error code | 手动维护 |
| `docs/feature-matrix.md` | ~40 个特性 | 手动维护 |
| `docs/config-reference.md` | ~100 个配置键 | 手动维护 |
| `docs/security-policy.md` | 安全策略 | 手动维护 |
| `cmd/sso-server/config.yaml` | 默认配置 | 随代码修改 |

**风险**：这些文档与运行时行为**没有自动化的一致性检查**。

#### 具体漂移证据

| 检查 | 代码 | 文档 | 差距 |
|------|------|------|------|
| OpenAPI 声明的端点 vs 实际路由 | `sso.go` + `server_routes.go` + Server 路由 | `docs/openapi.yaml` | 已知差距（06-30 方向一发现 3 处 `claims_parameter_supported` 与实际行为不符） |
| 已签发 error code vs 文档 | `shared/core/errors.go` | `docs/error-codes.md` | 无 CI 检查 error code 是否都已文档化 |
| 实现特性 vs feature-matrix | 源代码 | `docs/feature-matrix.md` | 无 CI 检查特性声明与实际实现是否一致 |
| 配置键 vs 文档 | `config/*.go` | `docs/config-reference.md` | 无 CI 检查 |

### 缓解方向

1. **OpenAPI → 路由一致性检查**（`checks/` 中新 checker——~60 行 Python）：解析 `docs/openapi.yaml` 提取所有 `operationId`，然后 grep `server_routes.go` 和 `options_*.go` 确认每个端点有对应的路由注册。CI 中运行，不一致则警告。

2. **Error code 完整性检查**（~40 行 Python）：grep `shared/core/errors.go` 提取所有 `Err*` 常量，grep `docs/error-codes.md` 确认每个 code 有文档条目。PR 添加新 `Err*` 但未更新文档→ CI 失败。

3. **配置键文档完整性**（~40 行 Python）：grep `config/config*.go` 提取所有 `yaml:"..."` 标签键，与 `docs/config-reference.md` 交叉比对。

4. **特性矩阵验证**（S，~30 行）：`feature-matrix.md` 添加 Checked 日期列 + CI 作业验证每个特性有对应的集成测试。

### 工作量与影响

- **工作量**：M（~200 行 Python checker + CI 集成）
- **当前风险**：中（文档滞后不会导致运行时错误，但会导致采购方的安全审查失败——他们逐行对照 `feature-matrix.md` 与代码检查声明是否属实）
- **长期收益**：文档成为可测试的契约，而非事后追记

---

## 方向五：版本兼容性与升级治理

### 现状

项目的版本管理策略是语义化版本 + 独立子模块，但缺少系统性的向后兼容保障：

| 兼容性维度 | 当前策略 | 风险 |
|-----------|----------|------|
| HTTP API | 新增端点 + 非破坏性参数扩展 | 无版本前缀（`/api/v1/admin/` 有但未承诺不向后变更） |
| gRPC API | proto 文件中的 `package v1` | 字段不可删除（proto 3） |
| 存储 schema | `migrate.Run` forward-only + `maxVersions` | 无 down-migration，回滚需手动操作 |
| 配置格式 | 未版本化 | 重命名/删除配置键在旧文件上静默忽略（`DisallowUnknownField` 当前只 warning） |
| 错误代码 | 文档约定"不可重命名/删除" | 无 CI 检查 |
| 审计事件类型 | 添加新类型 OK，删除旧类型破坏 SIEM 集成 | 无版本控制 |

### 具体风险点

#### 5.1 `DisallowUnknownField` 的 warning-only 策略

`config/source.go` 当前在检测到未知配置键时**仅打印 WARNING**，配置仍正常加载：

```go
slog.Warn("config: unknown keys detected ... they are ignored")
```

这是一项有意的向前兼容（旧配置在新版本上不退后），但在 `v1.0` 之后应成为硬错误。

#### 5.2 已废弃 API 的清理策略

项目没有「废弃 API 声明」模式。没有 `Deprecated: ` 注释标记、没有 `X-Deprecated` 响应头、没有移除时间线。采购方无法知道哪些 API 会在下个版本移除。

#### 5.3 go.mod replace 指令阻止 `go install`

`go.mod` 中的 `replace` 指令（`redis`、`postgres` 等嵌套模块）使 `go install` 无法工作（22 轮分析方向二已覆盖）。这是一个影响版本兼容性和可分发的结构性问题。

### 缓解方向

1. **废弃 API 策略**（`docs/DEPRECATIONS.md`——~1 页文档 + ~40 行 CI）：废弃端点添加 `X-Sunset: <date>` 响应头 + `Deprecated: true` OpenAPI 标注。CI 检查确保废弃端点在 2 个 minor 版本后才移除。

2. **配置版本化**（`config/` 扩展——~60 行）：`config.yaml` 支持 `version: 1` 顶层字段。加载器根据版本自动应用迁移函数（重命名键名、转换格式）。不指定版本时使用当前版本，并打印升级提醒。

3. **兼容性 gate CI 作业**（~30 行 CI 配置）：从上一个标签检出旧 `docs/openapi.yaml`，对比新版本——禁止删除或重命名端点（仅允许新增和向后兼容的字段扩展）。

4. **go.mod replace 治理**（子模块拆分，22 轮分析已覆盖）：为 `go install` 路径做专项治理。每个 minor 版本检查一次。

### 工作量与影响

- **工作量**：M（文档 + CI 配置 + config 版本化）
- **当前风险**：低（项目现在还处于 `v0.x`，但一旦进入 `v1.0`，上述差距会成为破坏性变更）
- **长期收益**：v1.0 的稳定承诺、企业采购的 API 稳定性契约

---

## 优先级摘要

| # | 方向 | 工作量 | 风险 | 时间窗口 | 核心收益 |
|---|------|--------|------|----------|----------|
| **1** | **Deps 接口膨胀治理** | L | 高 | v0.x 期间 | 消除构建断裂根源、降低接口耦合 |
| 2 | 多后端语义一致性 | XL | 中 | v1.0 之前 | redis 迁移等同于 sqlite 行为 |
| 3 | 配置蔓延治理 | M | 低-中 | v1.0 之前 | 减少配置事故、IDE 支持 |
| 4 | 文档与实现一致性 | M | 中 | v1.0 之前 | 采购安全审查通过率 |
| 5 | 版本兼容性治理 | M | 低 | v1.0 标记 | API 稳定性契约 |

### 与先前 4 轮的关系

| 维度 | 卷一二三（功能/边缘/性能） | 卷四（健康/生态） | 本卷（债务/风险） |
|------|------------------------|------------------|------------------|
| 时间窗口 | 任何时间 | 现在 | **v1.0 之前** |
| 修复成本 | 随时间线性增长 | 随时间线性增长 | **随时间指数增长**（接口膨胀不治→v2 重构） |
| 可见性 | 用户/运营可见 | 开发者/集成者可见 | **仅架构师可见** |
| 自动检测 | 通常 CI 可捕获 | CI 可部分捕获 | **无自动检测**（需专项审查） |

### 执行建议

**Phase 0（当前 Sprint）**：
1. 修复 `go build ./...` 构建断裂（第四卷方向①）
2. 在 `interfaces/admin/deps.go` 加编译期守卫 `var _ Deps = &Server{}`
3. 开始 `Deps` 接口拆分（先拆 `ConsentDeps`、`PasswordDeps`、`MFADeps` 三个独立子接口）

**Phase 1（本月）**：
1. 建立多后端语义一致性契约测试（扩展 `permissionstest.ConformanceSuite` 模式到 oauthspitest、credentialstest、sessiontest）
2. 添加文档-代码一致性 CI checker（OpenAPI→路由、error-code→consts）
3. 启动 `config.yaml` 版本化

**Phase 2（v1.0 门禁）**：
1. 配置 `DisallowUnknownField` 从 warning 升级为 error
2. 废弃 API 策略文档化 + `X-Sunset` 头实施
3. go.mod replace 治理完成（使 `go install` 可用）
4. 完成所有 store 的后端覆盖矩阵（Postgres 补齐 AuthCode/RefreshToken/JTI/Session 等热路径）
