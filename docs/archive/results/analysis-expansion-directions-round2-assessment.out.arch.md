现在我已掌握完整的项目背景。以下是我的架构分析。

---

# 架构分析报告：Postgres Hot Stores 与系统演进

## 1. 架构评估

### 1.1 当前架构优势

项目的**物理分层 + 六边形架构**组合是该系统最突出的架构优势：

| 维度 | 评估 | 依据 |
|------|------|------|
| **依赖方向** | ✅ 优秀 | 严格的单向依赖（`oauth/` → `security/` → `core/`），通过 committed gate 强制，无运行时意外 |
| **接口隔离** | ✅ 优秀 | 每个存储关注点都是接口（`oauthspi.AuthCodeStore` 等），无 mock，实现完全可替换 |
| **多后端策略** | ✅ 强 | 每个 store 至少有 memory + SQLite 双后端，Redis 覆盖全部 6 个 hot stores |
| **安全一致性** | ✅ 强 | Oracle-leak 统一处理（所有 unknown/expired/consumed 坍塌为同一错误码），anti-enumeration 贯穿所有端点 |
| **可测试性** | ✅ 强 | 无 mock 策略 + 集成测试套件 + bufconn 跨线测试 |

### 1.2 架构债务与技术债

**已识别的架构债务（优先级从高到低）：**

| 债务 | 严重度 | 当前状态 |
|------|--------|---------|
| **根目录业务代码**（Phase 3-10 迁移中） | 中 | 已知，正在按路线图迁移，`check-root` gate 已就位 |
| **Postgres hot stores 不一致** | **高** | 6 个 hot store 有 SQLite + Redis 实现，但无 Postgres 实现。`Session` 是唯一完成 Postgres 移植的 hot store |
| **OAuth/RefreshToken 文件 402 行接近阈值** | 中 | `refresh_tokens.go` 402 行（阈值 500），加新逻辑须提前拆分 |
| **SQLite CIBA 324 行和 DeviceCode 297 行** | 低 | 存在拆分空间，但目前安全 |
| **Redis RefreshToken 472 行** | **高** | 472 行，距离 500 行阈值仅 28 行。这是新增 Postgres 后端前必须拆分的风险文件 |
| **事件总线泛化不足** | 低 | cluster Bus 目前支持 4 种 event kind，扩展新事件类型须改动 `Kind*` 常量，无发布-订阅的通用路由层 |

### 1.3 关键设计决策合理性

| 决策 | 合理性评估 |
|------|-----------|
| **`oauth/` 禁止导入 `oidc/`** | ✅ 正确。两者间的所有协调通过 `handlers.go` 路由，避免了循环依赖和职责混淆 |
| **所有 SPI 在 `core/` 或 `protocols/*/oauthspi/` 定义，实现放在 `infrastructure/`** | ✅ 符合 Hexagonal + 物理分层。实现不污染接口包 |
| **Session Postgres 完成后，其他 6 个 hot store 缺失** | ⚠️ 合理但有缺口。Redis 已是官方推荐的热路径后端，但统一 DB 栈的需求是真实存在的（尤其中小部署和嵌入式场景） |
| **审计使用 `SetMeta` 而非直接赋值 `e.Metadata`** | ✅ 正确。控制审计数据的写入路径，保证不可篡改性和有界基数 |
| **Fail-Open vs Fail-Closed 的区分** | ✅ 优秀。安全敏感路径（trust-chain、refresh rotation）fail-closed，可用性敏感路径（geo、risk-scorer）fail-open |
| **SQLite for single-replica, Redis for multi-replica** | ✅ 合理的默认值分层。但 Postgres 的缺失意味着"统一 DB 技术栈"场景缺少首选项 |

---

## 2. 扩展方向

### 方向 1：补齐 Postgres Hot Stores（P0 — 高价值，中等工作量）

**为什么需要：**
- 核验报告已确认 6 个 hot stores（AuthCode、RefreshToken、PAR、DeviceCode、CIBA、JTIReplay）有 SQLite + Redis 但无 Postgres
- Session 的 Postgres 实现已投产，可以作为模式参考
- 统一 DB 技术栈的部署场景（尤其是中小团队、合规敏感环境）是目前架构的一个真实缺口
- 当前 Redis 是官方推荐的 HA 热路径，但 Redis 增加了运维复杂性（独立集群、哨兵、内存管理）

**核心挑战：**
- `RefreshToken` 的 Postgres 实现必须处理家族旋转 + 并发安全（`DELETE ... RETURNING` 语义），SQLite 用 `DELETE RETURNING`，Redis 用 Lua 脚本或 `WATCH/MULTI/EXEC`，Postgres 可用 `RETURNING` + 行锁或可序列化隔离级别
- 每个 store 的 schema 迁移必须独立版本化，且不能与 SQLite 迁移冲突
- 圈复杂度控制：Redis 的 `RefreshTokenStore` 已达 472 行，Postgres 实现在代码预算内需分割为多个文件

**预期架构变更：**
- 新增 `infrastructure/postgres/auth_code.go`、`refresh_token.go`、`par.go`、`device_code.go`、`ciba.go`、`jti_replay.go`
- 每个文件遵循 Session 的 `postgres/session.go` 模式：`New*Store(cfg Config)` → schema migration → CRUD
- 更新 `config/config.go` 的 YAML 配置支持 `oauth.*.backend = postgres`
- 接线层（`sso.go` 中的 `buildStores` 或等价函数）新增 Postgres factory branch

**对现有系统的影响：**
- 零破坏性。现有 SQLite/Redis 实现不受影响
- 新增的 switch branch 增加接线函数的长度（如 `buildStores` 可能超 50 行 > 需要拆分为工厂方法）
- 测试方面：每个新 store 需要 8-12 个测试用例（参考 Session 的 9 个测试用例模式）

**参考模式（来自 `postgres/session.go`）：**
```
New*Store(cfg, ttl) → Open(cfg.DSN) → Run(schema migration) → store struct → SPI impl
接口守卫：var _ oauthspi.AuthCodeStore = (*AuthCodeStore)(nil)
```

### 方向 2：引入 Backend Registry/Factory（P1 — 高价值，中等复杂度）

**为什么需要：**
- 当前每个 store 的 backend 选择散布在接线层中（switch/case），新增一个 backend 需要修改接线函数
- 随着 Postgres 完成后有 4 种后端（memory / sqlite / redis / postgres），工厂逻辑膨胀
- 配置文件中的 backend 选择逻辑与 store 实现耦合，不利于第三方扩展

**核心挑战：**
- 需要定义统一的 `StoreFactory` 接口，不能破坏现有 SPI 设计
- 要避免引入反射或代码生成
- Go 的泛型可能帮助减少样板代码，但早于 Go 1.18 的代码风格可能拒绝泛型

**预期的架构变更：**
```
// 新增 infrastructure/stores/registry.go
type AuthCodeStoreFactory interface {
    CreateAuthCodeStore(cfg Config) (oauthspi.AuthCodeStore, error)
}

type BackendRegistry struct {
    authCodeFactories  map[string]AuthCodeStoreFactory
    refreshFactories   map[string]RefreshTokenStoreFactory
    // ...
}

func (r *BackendRegistry) NewAuthCodeStore(backend string, cfg Config) (oauthspi.AuthCodeStore, error)
```

**对现有系统的影响：**
- 影响接线层的重构，但不改变任何 store 的 SPI 接口
- 需要将现有的 switch/case 逻辑迁移到 registry 注册模式
- 测试需要新的 conformance test 来保证 registry 能正确实例化所有 backend

**替代方案权衡：**

| 方案 | 优点 | 缺点 |
|------|------|------|
| **Option A：Registry Pattern** | 可扩展，第三方可实现自定义 backend | 额外的抽象层，Go 的接口类型擦除需要 type switch |
| **Option B：泛型 Factory** | 类型安全，编译期检查 | Go 泛型在复杂类型参数上可读性差 |
| **Option C：保持现状 switch/case** | 简单，无需新抽象 | 每加一个 backend 改一次接线层，违反开闭原则 |

> **建议：** 先完成 Postgres hot stores（方向 1），再评估接线层的膨胀程度。如果接线函数超过 100 行或 switch 分支超过 8 个，执行方向 2。

### 方向 3：冷热存储分离策略（P1 — 中等价值，高复杂度）

**为什么需要：**
- 当前所有 store 在同一数据库后端的同一 schema 空间中。Postgres 作为统一后端时，hot stores（AuthCode、PAR、DeviceCode 等 TTL 短、写密集）与冷数据（users、clients、tenants）共享连接池
- 高频写入导致的 Postgres 表膨胀（尤其是 AuthCode 和 DeviceCode 不断 INSERT + DELETE）会影响同一连接池上的读查询
- 没有存储类别标注（hot/warm/cold），运维人员无法针对性调优

**核心挑战：**
- 需要区分存储类别（每 store 的可接受延迟、持久性要求、备份策略）
- 连接池管理：hot stores 可能需要独立的连接池或不同的 max_connections
- 配置复杂度：用户需要理解存储类别并做出选择
- 与现有 backend 选择机制（backend = memory|sqlite|redis|postgres）的交互

**预期的架构变更：**
```
config:
  stores:
    auth_code:
      backend: redis        # hot: Redis
      pool: 10              # 独立连接池
    refresh_token:
      backend: postgres     # warm: Postgres
      pool: 5
    session:
      backend: postgres     # warm: Postgres
      pool: 5
    users:
      backend: postgres     # cold: Postgres
      pool: 3
```

**对现有系统的影响：**
- 重大配置变更。当前配置文件可能需重构
- 接线层需要支持每 store 独立 backend 选择 + 独立连接池
- 需要确保同一 DB 后端的迁移按顺序执行
- 增加运维复杂度

> **建议：** 方向 3 应该作为方向 1 + 方向 2 完成后的大版本功能。如果当前项目的目标市场是中小部署，"统一后端"（方向 1）已有足够价值；冷热分离是 HA 部署场景的需求。

### 方向 4：支持事务性存储操作（P2 — 中价值，高复杂度）

**为什么需要：**
- 当前 RefreshToken 的家族旋转需要跨多个 row 的原子操作（Insert new + Delete old family）。SQLite 用 `DELETE RETURNING` 在同一语句中完成；Redis 用 Lua 脚本保证原子性；Postgres 可以用 `WITH ... DELETE RETURNING ... INSERT ... SELECT` 或事务块
- 如果用户选择 Postgres 作为 RefreshToken 后端，但没有统一的"存储事务"抽象，每个 store 自行处理分布式/本地事务，边界不一致
- 未来可能出现的跨 store 操作（如 token exchange 中同时消耗 grant token 和创建新 token）将需要事务保证

**核心挑战：**
- 事务抽象会破坏当前的 SPI 设计（每个方法独立的 context + 参数）
- Go 的 `database/sql.Tx` 无法跨不同 `*sql.DB` 实例（跨 Postgres + SQLite 的分布式事务是反模式）
- 过度设计：当前所有单 store 操作都是原子的，跨 store 事务的需求尚未出现

**预期架构变更：**
```
// 方式一：Transaction SPI（侵入式）
type TransactionalStore interface {
    Begin(ctx context.Context) (Tx, error)
}

// 方式二：面向操作的原子性（非侵入式，当前模式）
// 每个 store 的复杂操作在内部保证原子性
// RefreshTokenStore.Rotate(ctx, oldToken) (...)
```

> **建议：** 不引入事务抽象。保持当前模式——每个 store 在其内部保证操作的原子性（SQLite 的 `DELETE RETURNING`、Postgres 的 `WITH ... DELETE RETURNING ...`、Redis 的脚本/事务）。只在出现真实的跨 store 事务需求时再考虑抽象。

### 方向 5：存储健康探针与自动降级（P2 — 中价值，中等复杂度）

**为什么需要：**
- 当前 `Ping()` 方法作为就绪探针（`WithReadyCheck`）存在，但没有自动降级机制
- 当 Redis 集群不可用时，当前 Fail-Open 策略会"日志 + 继续"，但请求仍然命中失败的 store，产生无意义的数据
- 当 Postgres 后端部分表不可用（如 `auth_codes` 表损坏但 `sessions` 表正常）时，没有部分降级能力

**核心挑战：**
- 降级决策需要在请求路径上做（低延迟）还是后台线程做（异步）
- 降级后的行为定义：是返回错误（fail-closed），还是使用后备后端（fallback），还是跳过该操作（fail-open）
- 需要与前端路由信息沟通（如负载均衡器识别降级实例）

**预期的架构变更：**
```
type HealthStatus int
const (
    HealthUnknown HealthStatus = iota
    HealthHealthy
    HealthDegraded  // store 不可用，使用 fallback
    HealthUnhealthy
)

type StoreHealth interface {
    Health(ctx context.Context) (HealthStatus, string)  // status + message
    Fallback() bool                                      // 是否有后备
}
```

> **建议：** 优先级 P2。在方向 1 和方向 2 完成后，再考虑健康探针的完整方案。目前 `Ping()` 方法已经提供了基础的 readiness 检查。

---

## 3. 接口设计建议

### 3.1 关键设计原则

| 原则 | 说明 | 已在项目中体现 |
|------|------|---------------|
| **面向 SPI 而非实现** | 每个关注点都是接口，实现可替换 | ✅ `oauthspi.AuthCodeStore`、`oauthspi.RefreshTokenStore` 等 |
| **Oracle-safe 错误** | 所有 unknown/expired/consumed 坍塌为统一错误码 | ✅ `ErrAuthCodeNotFound`、`ErrRefreshTokenNotFound` |
| **实现包中的接口守卫** | 类型断言在实现包中，不在接口包中 | ✅ `var _ oauthspi.AuthCodeStore = (*AuthCodeStore)(nil)` |
| **无 mock 策略** | 测试使用 memory impl 而非 mock 框架 | ✅ 项目规范 |
| **迁移版本化** | schema 变更通过 migration runner | ✅ `platform/migrate` |

### 3.2 是否需要新的抽象层

**现状评估：**

当前模式是：
```
core/oauthspi/*.go  (SPI 接口定义)
    ↕ 实现
infrastructure/{postgres,redis,sqlite}/*.go  (具体实现)
    ↕ 工厂
sso.go / config*.go  (接线层 - switch/case)
```

**决策：暂时不需要新的抽象层。** 理由：
- 当前 3 种 backend（memory/sqlite/redis）已经各有一个接线分支，加上 Postgres 后为 4 种
- 4 个分支的 switch/case 仍在可控范围内（参考圈复杂度 ≤ 15 的限制）
- 引入 registry 会增加学习成本，且 Go 的接口类型系统需要 type switch 或反射

**什么时候需要引入：**
- 当 backend 数量 ≥ 6（如新增 etcd、file、mongo 等）
- 当接线层文件超过 500 行
- 当第三方需要注册自定义 backend

### 3.3 保持向后兼容性

**Postgres Hot Stores 的兼容策略：**

1. **SPI 接口不变**：不修改 `oauthspi.AuthCodeStore`、`oauthspi.RefreshTokenStore` 等现有接口定义
2. **配置兼容**：现有 `backend: memory|sqlite|redis` 继续有效，新增 `backend: postgres` 作为可选值
3. **迁移兼容**：Postgres 的 schema 迁移使用独立的 `platform/migrate` runner，与 SQLite 的迁移版本空间隔离
4. **测试兼容**：新 store 的测试遵循 `infrastructure/postgres/postgres_test.go` 的模式（testmain + 临时数据库）

---

## 4. 技术选型

### 4.1 是否需要引入新技术栈

**现有技术栈评估：**

| 栈 | 当前覆盖范围 | 是否需要新增 |
|----|-------------|-------------|
| SQLite | 单 replica、嵌入式 | 已覆盖，无需新增 |
| Redis | 多 replica 热路径 | 已覆盖全部 6 个 hot stores |
| Postgres | Session 已完成，其他 6 个缺失 | **需要优先补齐** |
| etcd | Cluster Bus 后端 | 已覆盖 |
| KMS (AWS/GCP/Azure/PKCS11) | 密钥管理 | 已覆盖 nested modules |

**结论：不需要引入新技术栈。** 当前缺口是同一技术栈（Postgres）的覆盖面不一致，而非缺少新技术栈。

### 4.2 第三方依赖评估标准

对于 Postgres 驱动的选择：

| 候选方案 | 评估 |
|----------|------|
| `lib/pq` | 维护模式，不再接受新特性 |
| `jackc/pgx/v5` | ✅ 当前行业标准，性能最好，支持 `pgxpool` 连接池 |
| `database/sql` + `pgx/stdlib` | ✅ 当前 `postgres/pool.go` 使用的方案，兼容 `database/sql` |

**项目当前选择**（`postgres/pool.go`）使用 `database/sql` + `pgx/stdlib` 是合理的——它既保留了 `database/sql` 的接口一致性（与 SQLite 共享同一 abstraction），又获得了 pgx 的性能。

### 4.3 自建 vs 采购的决策依据

| 场景 | 自建 | 采购/集成 |
|------|------|----------|
| Postgres hot stores | ✅ 自建。~120-250 行/个，代码量可控 | N/A |
| 冷热分离引擎 | ❌ 自建但推迟。复杂度高，需要先证明业务需求 | N/A |
| 存储 Registry | ✅ 自建。Go 标准接口，无商业替代 | N/A |
| 存储健康探针 | ✅ 自建。`Ping()` 已有基础，扩展 Health 状态即可 | N/A |

---

## 5. 实施路线图

### 优先级定义

| 优先级 | 定义 | 时间窗口 |
|--------|------|---------|
| **P0** | 架构缺口，必须补齐 | 当前 Sprint |
| **P1** | 高价值，需规划 | 下 1-2 个 Sprint |
| **P2** | 有价值的增强，可排期 | 下季度 |

### 阶段划分

#### 阶段 1：补齐 Postgres Hot Stores（P0 — 当前 Sprint）

```
Phase 1a：JTIReplayStore（~80 行 + 测试）
  └─ 最简单的 store，只有 Check + Store 两个方法
  └─ 参考：SQLite `jti_replay.go`（170 行）+ Redis `jti_replay.go`（80 行）
  └─ 预计：80-100 行实现 + 60 行测试
  └─ 迁移版本: V2 in `infrastructure/postgres/migrate.go`

Phase 1b：PARStore（~120 行 + 测试）
  └─ 中等复杂度，有 TTL + atomic consume
  └─ 参考：SQLite `par.go`（228 行）+ Redis `par.go`（86 行）
  └─ 预计：100-140 行实现 + 80 行测试

Phase 1c：AuthCodeStore（~150 行 + 测试）
  └─ 与 PAR 类似模式，有 Issue + Consume
  └─ 参考：SQLite `auth_codes.go`（186 行）+ Redis `auth_code.go`（87 行）
  └─ 预计：120-160 行实现 + 80 行测试

Phase 1d：DeviceCodeStore（~200 行 + 测试）
  └─ 中等复杂度，有轮询/批准/拒绝状态机
  └─ 参考：SQLite `device_codes.go`（297 行）+ Redis `device_code.go`（326 行）
  └─ 预计：180-220 行实现 + 100 行测试

Phase 1e：CIBAStore（~200 行 + 测试）
  └─ 与 DeviceCode 类似的异步批准模式
  └─ 参考：SQLite `ciba.go`（324 行）+ Redis `ciba.go`（277 行）
  └─ 预计：200-250 行实现 + 100 行测试

Phase 1f：RefreshTokenStore（~250 行 + 测试）[最高风险]
  └─ 最复杂的 store：家族旋转、并发安全、grace window
  └─ 参考：SQLite `refresh_tokens.go`（402 行）+ Redis `refresh_token.go`（472 行）
  └─ 注意：必须先拆分 Redis 的 `refresh_token.go`（472 行接近 500 阈值）
  └─ 预计：250-300 行实现 + 120 行测试
  └─ 关键：使用 Postgres CTE 实现原子旋转：
      WITH deleted AS (
          DELETE FROM refresh_tokens WHERE token = $1 RETURNING family, client_id, user_id
      ), rotated AS (
          DELETE FROM refresh_tokens WHERE family = (SELECT family FROM deleted) AND family IS NOT NULL
      )
      INSERT INTO refresh_tokens (...) VALUES (...)
      RETURNING *
```

**里程碑：Phase 1 完成条件：**
- ✅ 6 个新 `infrastructure/postgres/*.go` 文件，均 ≤ 500 行
- ✅ `go build ./...` + `go vet ./...` 通过
- ✅ 每个 store 的 conformance test 覆盖：Create/Consume/Expired/NotFound
- ✅ 接线层（`sso.go` 或 `config.go`）支持 `backend: postgres`
- ✅ 所有现有 SQLite/Redis 测试不受影响

#### 阶段 2：接线层重构（P1 — 下个 Sprint）

```
任务 2a：评估接线层膨胀
  └─ 统计 `sso.go`/`config.go`/`buildStores` 的行数和复杂度
  └─ 如果 backend switch 分支 > 8 或接线函数 > 100 行 → 执行方向 2

任务 2b：Backend Registry（按需）
  └─ 新增 `infrastructure/stores/` package
  └─ 定义 `BackendRegistry` + `StoreFactory` 接口
  └─ 迁移现有 switch/case 到 registry 模式

任务 2c：配置统一
  └─ 确保 YAML/ENV/etcd 三种配置源都支持 `backend: postgres` 值
  └─ 更新 `docs/config-reference.md`
```

#### 阶段 3：冷热分离可行性验证（P2 — 下季度）

```
任务 3a：benchmark 基线
  └─ 基准测试：Postgres hot store vs Redis vs SQLite
  └─ QPS：单个 store 的读写延迟 p50/p99
  └─ 资源：连接数、内存、磁盘 IO

任务 3b：架构决策
  └─ 基于 benchmark 数据决定是否需要冷热分离
  └─ 如需要：设计配置方案 + store routing
  └─ 如不需要：更新文档，明确 Postgres hot stores 的适用范围
```

### 风险点与缓解策略

| 风险 | 概率 | 影响 | 缓解策略 |
|------|------|------|---------|
| **RefreshToken Postgres 实现的并发竞争** | 中 | 高 | • 使用 Postgres 的 `SERIALIZABLE` 隔离级别 + 重试逻辑<br>• 编写 `-count=10` 的并发测试<br>• 参考 SQLite 的 `refresh_tokens_rotation.go` 的并发处理模式 |
| **接线层文件超 500 行** | 中 | 中 | • 提前拆分为 `build_auth_code.go`、`build_refresh.go` 等<br>• 或使用 Backend Registry 模式 |
| **Postgres schema 迁移版本冲突** | 低 | 中 | • Session 占用 V1，新增 stores 从 V2 开始<br>• 每个 store 的 migration 在 `Run()` 中独立版本化<br>• 添加 migration 名称前缀来隔离 |
| **用户混淆（4 种 backend 选择）** | 中 | 低 | • 更新 `config-reference.md` 的文档，明确每个 backend 的适用场景<br>• 添加配置校验：不合法的 backend 值给出错误提示 |
| **Redis refresh_token.go 472 行在新增 Postgres 实现期间不被触碰** | 低 | 低 | • 在实现 Postgres 版时，严格不修改 Redis 版的任何代码<br>• 将 Redis 版的拆分列为一个独立任务（纯重构） |

---

## 总结

| 维度 | 结论 |
|------|------|
| **架构质量** | 高。严格的依赖方向、接口隔离、安全性约束、多后端策略，已达到企业级水平 |
| **核心缺口** | 6 个 Postgres hot stores 缺失（Session 已完成，P0 修复） |
| **技术债** | Redis `refresh_token.go` 472 行接近阈值（需先拆分），根目录代码迁移 Phase 3-10 进行中 |
| **最有价值扩展** | 方向 1（Postgres hot stores，P0）→ 方向 2（Backend Registry，P1）→ 方向 3（冷热分离，P2） |
| **最低风险路径** | 严格遵循 `postgres/session.go` 模式，每 store 独立文件 + 独立迁移版本，不修改现有 SPI |
| **不需要做的事** | 事务抽象、新技术栈引入、mock 框架、`TODO` 遗留 |
