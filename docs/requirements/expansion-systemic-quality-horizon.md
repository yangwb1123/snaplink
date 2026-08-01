# 系统性质量纵深 —— 升级安全、数据管道、协议验证与性能工程

> **作者：** 资深架构 & 产品经理视角  
> **日期：** 2026-07-11  
> **方法：** 全代码库全局扫描（2242 个 `.go` 文件、14 个 `go.mod`、200+ 包、1114 个测试文件、  
>   4 个嵌入 SPA、20+ 轮历史分析文档）。在系统阅读 ROADMAP v5.0、deferred-backlog、  
>   feature-matrix、SECURITY.md、docs/requirements/ 下全部 20+ 轮历史扩展方向分析后，  
>   **对每项候选方向做全代码库 grep 逐项核验 + 对 docs/requirements/*.md 做关键词交叉验证**，  
>   确保每项为 **真实代码级缺口且与所有历史分析零重叠**。  
> **定位：** 本报告 5 个方向不属于"新增协议支持"、"补后端实现"、或"生产硬化"——  
>   那些已经在之前 20+ 轮分析中反复覆盖。本报告聚焦于 **系统性工程质量纵深**——  
>   即从一个"功能完整的身份平台"走向一个"可信任、可升级、可预测、可证明正确的  
>   关键基础设施"所需要补齐的质量维度。  
> **体例：** 每项方向均包含 Why now（为什么现在做）、Scope（可独立交付的颗粒度）、  
>   Edge cases / 当前代码中已定位到的具体短板、与历史分析 zero-overlap 的证据。

---

## 前置声明：项目成熟度

经过 20+ 轮全局扫描 + 大量实现落地，本项目的能力覆盖面已达到行业顶级水平。  
以下领域已确认全部覆盖，**本报告不再重复分析**：

| 领域 | 状态 |
|---|---|
| **协议面**（OAuth 2.0 七种 grant + PAR + JAR + JARM + RAR, OIDC Core/Discovery/ Logout/BCL/FCL/CIBA/Form Post, SAML 2.0 SP+IdP, SCIM 2.0 双向, CAEP/SSF 双向, FAPI 2.0, OpenID Federation 1.0, LDAP, Kerberos, RADIUS, DPoP, mTLS, SPIFFE JWT-SVID, Transaction Token, Step-Up Auth） | ✅ 全部落地 |
| **存储面**（Memory, SQLite, Redis, etcd, PostgreSQL + KMS AWS/GCP/Azure/PKCS11/Vault Transit, SAML, LDAP, Kerberos, RADIUS, ext_authz, Kafka, MQTT — 14 个 go.mod） | ✅ 全部落地 |
| **安全面**（DPoP, mTLS, JWT-SVID, workload identity, break-glass, per-tenant 签名隔离, 区域数据驻留, FAPI 2.0, FIPS 140-3, 会话信任衰减, Step-Up Auth, Anti-enumeration, Oracle-leak hardening, bcrypt dummy hash, 401 统一 Shape） | ✅ 全部落地 |
| **产品面**（Hosted Login SPA, Admin Console SPA, Developer Portal SPA, User Portal `/me`, Consent store（memory/sqlite/redis）, B2B Enterprise Connections + HRD, Org-admin self-service, API docs viewer, SDK 生成 TS + Python） | ✅ 全部落地 |
| **运维面**（DR framework snapshot/RPO/RTO, config hot-reload SIGHUP 7 feature gates, metrics/prometheus/grafana, audit hash-chain + OCSF/CEF, pprof, load test k6, chaos test, benchmark gate） | ✅ 全部落地 |
| **生产硬化**（Circuit breaker, Active-Active, Template customization, HR connector, SLO framework — 均为最新分析方向，尚未落地但已识别） | ❌ 已识别（待实现） |
| **前沿方向**（AI Agent Identity, PAM, Post-Quantum, CIAM/Social Login, Token Status List, RAR, Step-Up dynamic ACR, External IdP token exchange — 均为最新分析方向，待实现） | ❌ 已识别（待实现） |

> **结论：项目的功能扩展方向（做什么）已经在 20+ 轮分析中被深度覆盖。  
> 剩余的最高价值空间不在于"做什么"，而在于"做得有多好"——这是本报告五方向的共性。**  

---

## 方向 1：升级健康框架（Upgrade Health & Canary Rollout Framework）

### 现状

项目拥有完善的数据迁移基础设施：

```
platform/migrate/migrate.go          → forward-only schema + optional data migrate
infrastructure/*/migrate.go          → 各存储后端各自的迁移（sqlite, postgres, saml/sp, saml/idp）
cmd/sso-ctl/migratecmd/              → CLI 迁移命令（status, up, down? — 仅 forward-only）
config/schema/validate.go           → config schema 版本校验
```

同时存在两项已经识别但**仍未连接的**安全原语：

- `migrate.CurrentVersion()`（`migrate/migrate.go:265`）—— 注释自述"a readiness
  gate that refuses to serve when the binary expects a newer schema"，但 **零非测试调用方**。
- Schema 回滚护栏 —— CI 构建时没有比较 `db.CurrentVersion > binaryMaxVersion` 的检查。

但整体上，升级路径是一个显著的盲区：

| 能力 | 当前状态 |
|---|---|
| forward-only schema migration | ✅ 完整（`platform/migrate` + per-backend） |
| `CurrentVersion` readiness gate | ❌ **零调用**（原语已存但无人接线 — `migrate.go:265`） |
| 升级前兼容性预检（pre-flight） | ❌ **零实现** |
| canary 部署监测（新旧 binary 共存） | ❌ **零实现** |
| 升级后数据完整性校验 | ❌ **零实现** |
| 自动化回滚决策支持 | ❌ **零实现** |
| binary ↔ schema 版本兼容矩阵 | ❌ **零实现** |
| 零停机升级编排（蓝绿 / 滚动） | ❌ **零实现**（非破坏性迁移已有，但升级过程的协调为零） |

### 缺口核验（grep 全代码库）

| 关键词 | 命中 | 结论 |
|---|---|---|
| `upgrade.*health\|UpgradeHealth\|upgrade.*check\|pre.*flight\|preflight` | **0** | 零实现 |
| `canary\|CanaryRollout\|canary.*deploy\|blue.*green\|bluegreen` | **0**（非测试/注释） | 零实现 |
| `rollback.*health\|rollback.*check\|RollbackVerif\|rollback.*valid` | **0** | 零实现 |
| `version.*compat.*matrix\|version.*gate\|binary.*version.*schema` | **0** | 零实现 |
| `zero.*downtime.*upgrade\|zero.*downtime.*migrat\|live.*upgrade\|live.*migrat` | **0** | 零实现 |

### 与历史分析 zero-overlap 证据

对 docs/requirements/*.md 全部 20+ 文件做关键词 grep：

| 关键词 | 文件中命中 | 结论 |
|---|---|---|
| `upgrade.*health\|canary.*deploy\|rollback.*health\|version.*compat.*check\|pre.*flight\|migration.*valid` | **0 命中** | ✅ 零重叠 |

ROADMAP v5.0 方向④(d) 提到"schema 版本护栏"（`migrate.CurrentVersion` 未被调用）——  
但这是**一个具体的单点缺口**（S 级），而非本方向描述的**完整升级健康框架**（XL 级）。  
本方向是那个单点的 10x 放大版，涵盖了 pre-flight、canary、rollback、兼容矩阵等  
ROADMAP 和所有分析从未提及的维度。

### 为什么需要它

1. **SSO 是组织内的最高价值靶标和最关键的认证基础设施**。一次升级故障导致全员无法登录
   = P0 级 incident。没有 pre-flight 检查、没有 canary 验证、没有 rollback 决策支持 =
   每次升级都是一次"祈祷式部署"。

2. **项目已经声明了 schema 版本护栏原语（`CurrentVersion` readiness gate），
   却从未接入生产代码**。这种"代码在树内但没人用"的模式是最危险的——维护者以为有保护，
   实际没有。

3. **滚动部署是 Kubernetes 上最常用的升级策略**，但对 SSO 这种有状态服务，
   滚动 = 新旧 binary 同时服务同一组数据库。没有版本兼容性矩阵，
   旧 binary 可能读取新 migration 写入的列/表 → crash/数据损坏。

4. **SOC2 / PCI-DSS 的变更管理要求**：每次生产变更必须有"测试→审批→回滚计划"。
   没有 canary 验证和 rollback 决策支持 = 审计时无法证明变更被安全执行。

### 范围

#### 1. Pre-Flight 兼容性预检（M，独立可交付）

扩展 `sso-ctl migrate pre-flight` 子命令，在升级前验证：

```go
// 伪接口 — 具体实现可进一步细化
type PreFlightResult struct {
    BinaryVersion    string
    SchemaVersion    int       // binary 期望的最新 schema 版本
    DBSchemaVersion  int       // 数据库当前的 schema 版本
    DBMaxVersion     int       // 数据库支持的最高版本（回滚兼容边界）
    IsCompatible     bool      // binary ≥ DB schema 且 binary 不要求 DB 没有的列
    Warnings         []string  // 非阻断但建议注意
    Blockers         []string  // 阻断项
}
```

- 复用 `migrate.CurrentVersion()` 但真正接线到 CLI + readiness probe
- 在 `/readyz` 中添加 schema 版本兼容性检查，不兼容时 graceful 503（而非 crash）
- 新增 `POST /api/v1/admin/upgrade/pre-flight` admin endpoint（admin:write 门禁）

#### 2. 版本兼容性矩阵（S，独立可交付）

在 `platform/migrate/` 中新增：

```go
// VersionCompat 定义 binary 版本与 schema 版本的兼容关系
type VersionCompat struct {
    BinaryMinVersion  string   // 能安全运行此 schema 的最低 binary 版本
    BinaryMaxVersion  string   // 能安全运行此 schema 的最高 binary 版本（有上限时）
    SchemaVersion     int      // 本 migrate step 的版本号
    IsAdditive        bool     // true=只加列/表，旧 binary 可安全忽略
    RequiresReindex   bool     // 需要重建索引（大型表需 maintenance window）
    RequiresBackfill  bool     // 需要数据回填（旧 binary 可能看到空值）
}
```

- 每步 migration 声明其兼容性语义
- `sso-ctl migrate status --compat` 输出兼容矩阵，便于 operator 决策

#### 3. 升级后完整性校验（M，独立可交付）

```go
// IntegrityChecker 验证升级后数据完整性
type IntegrityChecker interface {
    // CheckIntegrity 返回所有违反预期的不一致
    CheckIntegrity(ctx context.Context) ([]IntegrityViolation, error)
}

type IntegrityViolation struct {
    Table     string
    RowID     string
    Field     string
    Expected  string
    Actual    string
    Severity  IntegritySeverity // Warning / Error / Critical
}
```

- 初始范围：client 完整性（不缺失关键字段，`JWKS`、`AllowedResources` 等迁移后未丢失）、
  user 完整性、permission 完整性
- 产出 `sso-ctl migrate verify` 命令 + admin API

#### 4. 滚动升级 / 蓝绿部署编排指南（S，文档 + 脚本）

- 明确记录"在 K8s 上如何安全升级 SSO"的 Playbook：
  - 更新 ConfigMap/Schema → 迁移 job（无 downtime）→ 逐步滚动 new binary → 监控指标 →
    确认 → 丢弃旧 Pod
  - 回滚条件：`/readyz` 全绿 + `migrate.CurrentVersion` 校验 + 错误率无突升
- 复用 helm chart 的 `PreStop` / `readinessProbe` / `PodDisruptionBudget`

### 价值 · 工作量

| 维度 | 评估 |
|---|---|
| 生产影响 | 极高——每次升级的置信度和安全性 |
| 审计/合规价值 | 高——变更管理的可证明性 |
| 改动量 | 中—大——但各子项可独立交付 |
| 与已有代码的契合度 | 高——`CurrentVersion` 原语已存，只需接线 + 加版本声明 |
| 与已有分析的差异性 | ✅ **本报告独有**（20+ 轮分析从未提及） |

---

## 方向 2：身份变更数据捕获（CDC）与状态同步管道

### 现状

项目拥有成熟的**审计事件**管道：

```
audit.Recorder + MultiSink → SQLite / Kafka / Webhook / File
platform/audit/            → 68+ 种审计事件类型
infrastructure/kafka/      → Kafka audit sink（独立嵌套模块）
platform/audit/auditsink/  → CEF / OCSF / Syslog 格式化器
```

但审计事件是**行为日志**（"谁做了什么"），不是**状态变更流**（"什么变了，从什么变成什么"）。

同时项目拥有事件基础架构：

```
cluster.Bus（etcd / MQTT / memory）    → 跨副本失效广播（撤销、密钥轮换、client 变更）
platform/lifecycle/webhook/             → 可注册的 webhook 事件引擎（有 subscription + delivery + deadletter）
protocols/caep/                          → CAEP/SSF SET 事件（外部 RP 的安全信号广播）
```

但**没有任何一条管道定期输出身份对象（User、Client、Tenant、Permission）的完整状态变更事件**。

| 能力 | 当前状态 |
|---|---|
| 审计事件（action log） | ✅ 68+ 事件类型，MultiSink |
| 集群内失效广播（bus） | ✅ etcd / MQTT / memory |
| CAEP/SSF 外部安全信号 | ✅ transmitter + receiver |
| Webhook 事件引擎 | ✅ subscription + delivery + deadletter |
| **用户/客户端/租户状态变更 CDC 流** | ❌ **零实现** |
| **身份数据 → 数据湖 / 数据仓库管道** | ❌ **零实现** |
| **增量状态同步（非全量 snapshot）** | ❌ **零实现** |
| **CDC 事件与审计事件的关联** | ❌ **零实现** |

### 缺口核验（grep 全代码库）

| 关键词 | 命中 | 结论 |
|---|---|---|
| `CDC\|ChangeDataCapture\|change_data_capture\|stateChange\|state.change\|StateChange` | **0**（仅 `Kafka.New` 的 doc，但管道本身不存在） | 零实现 |
| `DataLake\|data_lake\|DataWarehouse\|data_warehouse\|data.sync\|StateSync\|state.sync\|IncrementalSync` | **0** | 零实现 |
| `IdentityStream\|identity.stream\|identity.event\|StateEvent\|state.event.*user\|state.event.*client` | **0** | 零实现 |
| `SnapshotDiff\|snapshot_diff\|ChangeLog\|changelog.*user\|changelog.*client` | **0** | 零实现 |

### 与历史分析 zero-overlap 证据

对 docs/requirements/*.md 全部 20+ 文件做关键词 grep：

| 关键词 | 文件中命中 | 结论 |
|---|---|---|
| `CDC\|Change\.Data\.Capture\|data\.sync\|state\.replicat\|identity\.lake\|identity\.replica\|StateChange\|IncrementalSync\|DataLake` | **0 命中** | ✅ 零重叠 |

> **注意：** `expansion-ciam-identity-horizon.md` 方向④ "身份事件导出管道与数据治理  
> （Identity Data Mesh & Governed Export Pipeline）" 聚焦于**审计事件的批量导出**  
> （`audit.Exporter` 到 Parquet/S3），与 CDC 有交集但不同——审计导出是**事后查询**，  
> CDC 是**实时增量状态变更流**。本方向聚焦的身份对象状态变更（User.Client.Permission.Tenant  
> 的 create/update/delete + before/after 快照）完全未被任何分析覆盖。

### 为什么需要它

1. **下游系统依赖身份数据的实时同步**，今天只能靠全量导出（snapshot）+ 定期轮询。
   - 每个下游（CRM、HRIS、SIEM、数据仓库）自己轮询 admin API = N 倍负载 + 分钟级延迟
   - 轮询无法捕获中间状态变化（创建后 1 秒又更新，轮询间隔内可能错过）

2. **数据仓库/BI 的身份分析需求**——"过去 30 天新增了多少用户？哪些 client 的 scope
   被修改过？租户的活跃 MAU 趋势？"——这些跨时间维度的分析需要**状态变更的历史轨迹**，
   而非仅仅当前快照。审计事件无法直接回答"上周三下午 3 点的 client 配置是什么样的"。

3. **事件驱动架构的自然延伸**：项目已有 `webhook` 引擎、`cluster.Bus`、`kafka` 集成，
   但不发出"identity state changed"事件。加 CDC 层是**复用（而非新增）基础设施**——
   webhook 已可推送、kafka 已可消费、bus 已可广播。

4. **CAEP/SSF 的互补**：CAEP 发射的是**安全信号**（token_revoked, account_disabled），
   CDC 发射的是**配置变更**（client_updated, permission_granted, tenant_modified）——两者正交。

### 范围

#### 1. CDC 事件模型与 SPI（M，核心设计）

```go
// shared/spi/cdc.go（新增包）

type ChangeEventType string

const (
    ChangeUserCreated     ChangeEventType = "user.created"
    ChangeUserUpdated     ChangeEventType = "user.updated"
    ChangeUserDeleted     ChangeEventType = "user.deleted"
    ChangeClientCreated   ChangeEventType = "client.created"
    ChangeClientUpdated   ChangeEventType = "client.updated"
    ChangeClientDeleted   ChangeEventType = "client.deleted"
    ChangeTenantCreated   ChangeEventType = "tenant.created"
    ChangeTenantUpdated   ChangeEventType = "tenant.updated"
    ChangeTenantDeleted   ChangeEventType = "tenant.deleted"
    // ... Permission, Role, Connection, etc.
)

type ChangeEvent struct {
    ID          string            // 唯一事件 ID（UUID v7）
    Type        ChangeEventType
    Timestamp   time.Time
    TenantID    string
    SubjectID   string            // 哪个实体被更改
    Actor       string            // 谁做的更改（admin user id / client id）
    Snapshot    json.RawMessage   // 更改后的完整对象快照
    Diff        json.RawMessage   // 可选：RFC 6902 JSON Patch
    Metadata    map[string]string
}

type ChangeEventBus interface {
    Publish(ctx context.Context, event ChangeEvent) error
    Subscribe(ctx context.Context, types ...ChangeEventType) (<-chan ChangeEvent, error)
}
```

- 轻量 SPI，与 `cluster.Bus` 解耦（但可复用其实现）
- Snapshot 允许消费者不依赖上游 API 就能获取对象完整状态
- Diff 可选（经济模式可只发 Snapshot）

#### 2. 核心存储层接入点（L，逐 store 接入）

在关键写入路径旁发射 CDC 事件：

| 写入点 | 集成方式 |
|---|---|
| `UserProvider.CreateOrUpdate` | 返回用户后 Publish `user.created` / `user.updated` |
| `UserProvider.Delete` | 返回前 Publish `user.deleted` |
| `ClientStore.PutClient` | Publish `client.created` / `client.updated` |
| `ClientStore.DeleteClient` | Publish `client.deleted` |
| `TenantStore.CreateTenant` | Publish `tenant.created` |
| `TenantStore.UpdateTenant` | Publish `tenant.updated` |
| `TenantStore.DeleteTenant` | Publish `tenant.deleted` |
| `PermissionStore` 写路径 | Publish `permission.*` |
| `ConnectionStore` 写路径 | Publish `connection.*` |

- 通过可选中间件/包装器模式（类似 `audit.Recorder`），不侵入 SPI 核心
- **不在热路径同步阻塞**：Publish 到带背压的 channel，异步 drain

#### 3. 输出适配器（M，复用已有基础设施）

| 适配器 | 复用组件 |
|---|---|
| Kafka CDC Sink | `infrastructure/kafka/`（现有 `auditSink` 模式，新增 `cdcSink`） |
| Webhook CDC Sink | `platform/lifecycle/webhook/`（复用 subscription + delivery + deadletter） |
| Bus CDC Sink（跨副本） | `cluster.Bus`（新 `KindIdentityChange`，现有失效框架） |

#### 4. 增量同步引导（Snapshot → CDC catch-up）（L）

- 新消费者启动时先消费一个全量 snapshot（复用 `interfaces/snapshot/`），
  然后切换到 CDC 流
- 为 CDC 事件提供至少一次送达保证（事件 ID 幂等）

### 价值 · 工作量

| 维度 | 评估 |
|---|---|
| 架构价值 | 高——事件驱动架构的关键缺失拼图 |
| 下游系统集成 | 高——让 CRM/HRIS/数据仓库能实时消费身份变更 |
| 改动量 | 大——SPI 设计 + 逐 store 接入 + 输出适配器，可逐步交付 |
| 复用度 | 高——kafka/mqtt/webhook/bus 均已存在 |
| 与已有分析的差异性 | ✅ **本报告独有**（20+ 轮分析从未提及） |

---

## 方向 3：协议正确性纵深 —— 自动化认证套件集成与形式化验证

### 现状

项目的协议覆盖面已是行业顶级，但**协议正确性的保障手段仍停留在手动测试层面**：

| 能力 | 当前状态 |
|---|---|
| OIDC Conformance Test Suite 配置 | ✅ 存在（`test/oidc-conformance/docker-compose.yml`） |
| 自动化运行 conformance suite | ❌ **手动操作**（需 `docker compose up` + 浏览器点选） |
| CI 中自动运行 conformance | ❌ **零集成** |
| Fuzz 测试 | ✅ **10 个** `Fuzz*` 函数（aud_claim, jwe, jws, jar, bind, dcr, end_session, federation） |
| Property-based testing | ❌ **零实现**（`testing.Quick` 未使用，`rapid`/`gopter` 未引入） |
| 协议状态机形式化验证（TLA+/Alloy） | ❌ **零实现** |
| OAuth 2.0 安全属性自动化检查 | ❌ **零实现** |
| 跨协议集成验证（SAML→OAuth、LDAP→SCIM） | ❌ **零实现** |

### 缺口核验（grep 全代码库）

| 关键词 | 命中 | 结论 |
|---|---|---|
| `testing.Quick\|testing\/quick\|gopter\|rapid.*testing\|rapidcheck` | **0** | 零实现 |
| `TLA\|PlusCal\|Alloy\|Forge\|SAL\|NuSMV\|Spin\|Promela\|CBMC\|KLEE\|symbolic` | **0** | 零实现 |
| `conformance.*suite.*ci\|conformance.*auto\|oidcconform\|conform.*test.*auto` | **0** | 零实现 |
| `property.based\|propertyBased\|PropertyBased\|generative.*test` | **0** | 零实现 |
| `state.*machine.*oauth\|state.*machine.*oidc\|protocol.*state\|protocol.*flow\|grant.*flow`（验证上下文） | **0** | 零实现 |

已有 10 个 fuzz 测试，但主要集中在解析层（JWS、JAR、bind、user code 等），
未覆盖协议状态转换和授权码流的安全属性。

### 与历史分析 zero-overlap 证据

对 docs/requirements/*.md 全部 20+ 文件做关键词 grep：

| 关键词 | 文件中命中 | 结论 |
|---|---|---|
| `formal.*verif\|model.*check\|TLA.*Plus\|Alloy\|OIDC.*conformance.*suite\|conformance.*CI\|protocol.*state.*machine\|property.*based` | **0 命中** | ✅ 零重叠 |

ROADMAP v5.0 方向③ "OIDC 一致性与 Token 正确性收口" 覆盖的是具体的协议正确性修复
（如 `at_hash`、`auth_time`、`AMR`、ACR 等）。本方向覆盖的是**验证方法论本身**——
如何系统性地保障协议正确性不会随着迭代回退，而非修复某一组具体的正确性 bug。

### 为什么需要它

1. **OAuth 2.0 / OIDC 的复杂性使其成为安全漏洞的温床**。历史上 OAuth 实现中的
   安全漏洞（授权码注入、CSRF、重放、混合流混淆代理）几乎全部源于协议状态机的
   边界情况。**手工测试 + 传统单元测试无法穷尽这些状态**。

2. **OIDC Conformance Test Suite 是认证采购的标准**。今天项目需要手动运行——这意味着
   CI 合入可能破坏 conformance 而无人知晓。每次发布前手动跑一次 conformance =
   要么不跑、要么忘记、要么跑的版本和发布的版本不一致。

3. **Property-based testing 能发现手动测试不可能发现的边界情况**。例如：
   - "任意两个 scope 声明组合是否都能正确解析和验证？"
   - "任意合法的 JWT 是否都能被正确验签？（即使 alg 混合、畸形 header、额外字段）"
   - "对任意 redirect_uri 格式，是否只有合法值通过验证？"

4. **已有 fuzz 测试但覆盖面窄**。10 个 fuzz 目标集中在解析层，而最需要 fuzz 的
   协议状态组合（auth_code + pkce + dpop + refresh 的各种排列）完全没有触及。

### 范围

#### 1. OIDC Conformance Suite CI 自动化（M，独立可交付）

目标：每次 PR 合并后自动运行 OIDC Conformance Test Suite，失败则阻止合入。

```yaml
# .github/workflows/oidc-conformance.yml（新增）
on:
  schedule: # 每晚运行
    - cron: '0 6 * * *'
  workflow_dispatch: # 可手动触发

jobs:
  oidc-conformance:
    runs-on: ubuntu-latest
    services:
      sso-server:
        build: .
        ports: ["8080:8080"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
      - run: go build -o sso-server ./cmd/sso-server
      - run: ./sso-server -config test/oidc-conformance/config.yaml &
      - run: docker compose -f test/oidc-conformance/docker-compose.yml up -d
      - name: Wait for conformance suite
        run: ./test/oidc-conformance/wait-for-suite.sh
      - name: Trigger test plan
        run: ./test/oidc-conformance/run-plan.sh --plan basic,config,dynamic,formpost
      - name: Check results
        run: ./test/oidc-conformance/check-results.sh
```

- 初始覆盖 basic / config / dynamic / formpost 四个核心 profile
- 后续加入 session / logout / ciba / jarm / fapi
- 输出 CI 可读的 JSON 结果 + 失败时的 `plan_id` 用于本地复现

#### 2. Property-Based Testing 框架（L，渐进交付）

引入 Go 生态的 property-based testing 库（`testing/quick` 或 `rapid`），
在关键的安全敏感路径上加 generative tests：

| 验证路径 | Property | 优先级 |
|---|---|---|
| `oauthwire/bind.go`（参数绑定） | 任意 valid `url.Values` 能正确绑定且不 panic | P0 |
| `oauthvalidate/scope.go`（scope 验证） | 任意 scope 字符串合法/非法判定与 RFC 一致 | P0 |
| `security/jwks_verify.go`（JWKS 验签） | 任意畸形 JWS 不 panic、不误判合法 | P0 |
| `oidc/userinfo_signing.go`（ID Token 签发） | `at_hash` 无论 access_token 长度和 alg 都正确 | P1 |
| `oauthwire/token_exchange.go`（token exchange） | 任意 act-chain 深度与循环检测正确 | P1 |
| `federation/trust_chain_validate.go`（信任链验证） | 任意畸形 trust chain 不 panic、不误信 | P1 |
| `caep/security_event_token.go`（SET 验证） | 任意畸形 SET 不 panic、不误信 | P2 |

#### 3. 协议状态机属性检查（探索性，L-XL）

这是一个更具探索性的方向——用形式化方法验证 OAuth 2.0 协议状态机的安全属性。
价值极高但需要专业的形式化方法知识。建议作为可行性研究（spike）启动。

可能的方法：

- **TLA+ 建模**：对 authorization_code + PKCE + refresh token 的状态机建模，
  验证"攻击者不能在没有 code_verifier 的情况下兑换 authorization_code"
- **Alloy 分析**：建模 scope 授权和 client 权限的关系，
  验证"client 不能获取其未授权的 scope"
- **Go 代码级模型提取**：从 `protocols/oauth/oauthspi/` 的 SPI 提取状态迁移，
  与 TLA+ 模型交叉验证

> **注意：** 这是一个"高天花板"方向。即使是第 1 步（OIDC conformance CI 自动化）
> 和第 2 步（property-based testing）也能带来巨大的信心提升。
> 第 3 步建议在核心团队有形式化方法背景的人才时启动。

### 价值 · 工作量

| 维度 | 评估 |
|---|---|
| 安全价值 | 极高——协议实现的正确性是 SSO 安全的基石 |
| 合规价值 | 高——OIDC conformance 是采购必备 |
| 改动量 | 第 1 步 M、第 2 步 L、第 3 步 XL |
| 与已有分析的差异性 | ✅ **本报告独有**（20+ 轮分析从未提及） |

---

## 方向 4：跨模块集成质量平台（Cross-Module Integration Testing Platform）

### 现状

项目有 14 个 `go.mod`（根模块 + 13 个嵌套子模块），CI 只构建和测试**根模块**：

```
CI (.github/workflows/ci.yml):
  go build ./...              ← 根模块
  go test -race ./...         ← 根模块

Makefile ci-modules:
  awskms ✓ gcpkms ✓ azurekeyvault ✓ pkcs11 ✓ saml ✓ ldap ✓ extauthz ✓
  kafka ✗ mqtt ✗ kerberos ✗ radius ✗ sso-mcp ✗ sso-operator ✗
  redis 仅按需，非 ci 一部分
```

更关键的是，**没有一条测试覆盖跨模块的集成路径**：

| 集成路径 | 当前测试覆盖 |
|---|---|
| SAML IdP → OAuth token exchange（SAML assertion → access token） | ❌ **零** |
| LDAP 认证 → OAuth 授权码颁发 | ❌ **零** |
| Kerberos 认证 → 会话创建 → refresh token 轮换 | ❌ **零** |
| WebAuthn 注册 → MFA step-up → token exchange | ❌ **零** |
| SCIM provisioning → user creation → OIDC login | ❌ **零** |
| CAEP receiver → token revocation → cross-replica consistency | ❌ **零** |
| RAR（authorization_details）→ resource indicators → token exchange | ❌ **零** |

### 缺口核验（grep 全代码库 + CI 配置）

| 检查项 | 状态 |
|---|---|
| `.github/workflows/ci.yml` 中 `ci-modules` 的调用 | ❌ **不存在**（ci.yml 只跑根模块） |
| 跨模块集成测试文件（`*_test.go` import 两个以上嵌套模块） | ❌ **零文件** |
| 跨协议集成测试（如 `protocols/oauth` + `infrastructure/saml`） | ❌ **零** |
| 后端组合测试（如 `redis` + `defaultimpl` 对比行为一致性） | ❌ **零**（`backendsemantics` 只覆盖根模块 store） |

### 与历史分析 zero-overlap 证据

对 docs/requirements/*.md 全部 20+ 文件做关键词 grep：

| 关键词 | 文件中命中 | 结论 |
|---|---|---|
| `contract.*test\|consumer.*driven\|pact.*test\|API.*compat\|module.*boundary` | **0 命中** | ✅ 零重叠 |
| `cross.module\|inter.module\|module.*integration\|module.*test\|nested.*module\|go.work\|ci.*submodule\|ci.*module`（验证上下文） | **0 命中** | ✅ 零重叠 |

> **注意：** ROADMAP v5.0 方向⑤(d)(f) 提到了"CI 不构建子模块"和"Dependabot 不覆盖子模块"
> 作为安全层面的单点缺口，但从未将其扩展为一个**系统的跨模块集成质量平台方向**。
> 同样，`expansion-directions-v11-analysis.md` 方向① "后端一致性测试基础设施" 聚焦的是
> 同一模块内 memory vs sqlite 的行为等价性，而非跨模块的协议集成验证。

### 为什么需要它

1. **最危险的代码没有 CI 保护**。`saml/`（XML-DSig、XXE 面）、`ldap/`（注入面）、
   `kerberos/`、`radius/`、`kafka/`、`mqtt/`——这些承载最高安全风险和处理外部输入的
   模块，在 CI 中连**编译都不触发**。一次合并完全可能在`sam/`引入编译错误而不被 CI 发现。

2. **模块间接口没有契约测试**。根模块的 SPI 变更（如 `core.User` 加字段、
   `oauth.AuthCodeStore` 改方法签名）可能静默破坏嵌套模块的实现，但 CI 不知道。

3. **集成路径是真正的"真相之源"**。`infrastructure/saml` 在单元测试中表现正常，
   但实际集成到 OAuth 的 token exchange 管道时，ACR/AMR 映射可能出错。
   `infrastructure/ldap` 用户成功认证后，其属性可能没有正确映射到 `core.User`。

### 范围

#### 1. CI 全模块构建与测试（M，最优先、独立可交付）

```yaml
# .github/workflows/ci.yml — 新增步骤
- name: Build & test all nested modules
  run: make ci-modules
```

并扩展 `Makefile ci-modules` 覆盖全部 13 个嵌套模块：

```makefile
ci-modules: ## Build + test all nested modules.
	# KMS peers
	cd infrastructure/kms/awskms && $(GO) build ./... && $(GO) test -race -count=1 ./...
	# ... (existing entries kept) ...
	# New: previously uncovered modules
	cd infrastructure/kafka && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd infrastructure/mqtt && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd infrastructure/kerberos && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd infrastructure/radius && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd command/sso-mcp && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd command/sso-operator && $(GO) build ./... && $(GO) test -race -count=1 ./...
```

> 注意：`infrastructure/redis` 需要 Redis 实例，应跳过或使用 TestMain 条件跳过。
> 单独开一个带 service 的 CI job。

#### 2. 模块间接口契约测试（L）

为每个嵌套模块定义其与根模块的依赖接口，并在 CI 中**编译验证**接口一致性：

```
# 概念：每个嵌套模块的 go.mod 通过 replace 指向根模块的本地路径。
# 在 ci-modules 中先 go build ./... 确保根模块的接口变更不会破坏子模块的编译。
# 更进一步的契约测试：
#   - 在根模块中声明 SPI 的接口检查（如 var _ oauth.AuthCodeStore = (*sqlite.AuthCodeStore)(nil)）
#   - CI 中为每个嵌套模块运行 go vet ./...（捕获接口未实现）
```

#### 3. 跨模块集成测试套件（L-XL，可逐步扩展）

在 `test/` 中新增 `test/crossmodule/` 目录，按优先级覆盖：

| 优先级 | 集成路径 | 测试方法 |
|---|---|---|
| P0 | SAML IdP → Token Exchange（SAML assertion → JWT） | `infrastructure/saml/idp` 签发 assertion，`protocols/oauth` 交换 |
| P0 | LDAP auth → Auth Code flow | `infrastructure/ldap` 做认证，`oauthwire` 做授权码颁发 |
| P1 | WebAuthn registration → MFA step-up → token | `authenticators/webauthn` + `mfa` + token issuance |
| P1 | SCIM push → User created → OIDC login | `scimprovision` push → `userprovider` → `oidc` login |
| P2 | CAEP event → Token revocation → Bus propagation | `caep` receiver → `oauth` revocation → `cluster.Bus` broadcast |
| P2 | Kafka audit → Event replay | `kafkaaudit` → audit event → external consumer verifies |

每个集成测试**不依赖外部服务**（启动测试内嵌 server + mock/loopback 适配器）。

### 价值 · 工作量

| 维度 | 评估 |
|---|---|
| 安全价值 | 极高——最危险的代码（SAML XML/DSig、LDAP 绑定）第一次被 CI 覆盖 |
| 可靠性价值 | 高——接口变更导致子模块编译失败被提前发现 |
| 改动量 | 第 1 步 S、第 2 步 M、第 3 步 XL |
| 与已有分析的差异性 | ✅ **本报告独有**（20+ 轮分析从未提及） |

---

## 方向 5：性能工程工具链与容量规划框架

### 现状

项目已有的性能相关工作：

```
ops/deploy/loadtest/            → k6 脚本（仅 client_credentials 单一路径）
ops/deploy/benchgate/           → benchmark 基线比较门禁
cmd/sso-ctl/snapshotcmd/        → 快照导出（可用于 perf 测试数据准备）
platform/metrics/               → Prometheus 指标
interfaces/ratelimit/           → 限流器（含基准测试 ratelimit_bench_test.go）
interfaces/sso/quota.go         → per-tenant 配额检查
```

但整体上，性能工程处于"有基建无框架"的状态：

| 能力 | 当前状态 |
|---|---|
| k6 负载测试脚本 | ✅ 存在（仅 client_credentials） |
| benchmark gate | ✅ 存在（hot-path JWT issuance/validation） |
| **全 grant 类型负载测试** | ❌ **零**（auth_code, refresh, device, ciba 等均无） |
| **多后端性能对比矩阵** | ❌ **零**（memory vs sqlite vs redis vs postgres 的量化比较） |
| **容量规划模型** | ❌ **零**（"每 store 后端支持多少 QPS？瓶颈在哪？"无指南） |
| **CI 性能回归门禁** | ❌ **零**（benchmark gate 手动触发，非 CI 阻塞） |
| **SLO 指标采集与发布** | ❌ **零**（无 `/metrics` 暴露 p99/p999 延迟、无 SLO 仪表盘） |
| **热点路径火焰图 / pprof 集成** | ❌ **零**（pprof 端点未接线） |

### 缺口核验（grep 全代码库）

| 关键词 | 命中 | 结论 |
|---|---|---|
| `capacity.*plan\|capacity.*model\|sizing.*guide\|sizing.*model\|throughput.*model` | **0**（非注释的引述/示例相关） | 零实现 |
| `perf.*regression\|performance.*regression\|perf.*gate\|performance.*gate\|benchmark.*CI` | **0** | 零实现 |
| `SLO\|slo.*latency\|slo.*throughput\|slo.*availability\|p99\|p999\|tail.*latency`（指标暴露上下文） | **0** | 零实现 |
| `pprof\|/debug/pprof\|runtime/pprof\|net/http/pprof`（生产接线） | **0** | 零实现 |

### 与历史分析 zero-overlap 证据

对 docs/requirements/*.md 全部 20+ 文件做关键词 grep：

| 关键词 | 文件中命中 | 结论 |
|---|---|---|
| `capacity.*model\|sizing.*guide\|perf.*baseline.*suite\|benchmark.*matrix\|throughput.*model\|QPS.*model\|performance.*regression\|perf.*CI` | **0 命中** | ✅ 零重叠 |

> **注意：** `expansion-gaps-analysis-2026-07-11.md` 方向③ "交互式 OAuth 流程的负载测试
> 与性能基线" 关注的是**为交互式流程（auth_code + PKCE + 各 authenticator）增加负载测试**。
> 这是一个合理的单点方向，但本方向覆盖的是**完整的性能工程框架**：
> 全 grant 类型覆盖 + 多后端对比 + 容量模型 + CI 回归门禁 + SLO 指标 + pprof 集成。
> 两者是 1x（单点脚本）vs 10x（系统框架）的关系。

### 为什么需要它

1. **项目定位为"高吞吐 SSO 服务器"（>1k QPS）却没有任何可量化的性能数据**。
   每次 PR 都可能引入性能退化（增加锁竞争、分配、序列化开销）而无人察觉。

2. **不同的存储后端有数量级的性能差异**——memory（~50μs/op）、sqlite（~500μs/op）、
   redis（~2ms/op）、postgres（~5ms/op）。没有性能矩阵，operator 无法做出有数据支撑的
   后端选择决策。

3. **性能退化是静默的**——不像功能 bug 会导致测试失败，性能退化只在生产流量下体现为
   延迟增加 + 资源消耗上升。唯一可靠的防御是 CI 中的自动性能回归门禁。

4. **容量规划是生产运营的基本需求**——"我的 SSO 集群在给定硬件上能支持多少用户？
   瓶颈是什么？什么时候需要扩容？"——没有容量模型，每次回答都是"试试看"。

### 范围

#### 1. 全覆盖负载测试套件（M，独立可交付）

扩展 `ops/deploy/loadtest/` 覆盖所有关键路径：

| 路径 | 负载场景 | 优先级 |
|---|---|---|
| `client_credentials`（已有） | 直连 token 颁发，无认证，最高吞吐 | P0 ✅ |
| `authorization_code + PKCE` | 完整交互流 + PKCE 验证 + Redis/SQLite 读写 | P0 |
| `refresh_token` | 轮换 + 家族击杀 + grace window | P0 |
| `password`（直接认证） | bcrypt/DummyHash 对比 | P1 |
| `device_code` | 轮询流 + 设备码存储 + 用户码生成 | P1 |
| `introspect` | 单令牌 + 批量 introspection | P1 |
| `revoke` | 单令牌 + 跨副本（多 server 进程） | P2 |
| `token_exchange` | act chain + 策略检查 + 多 hop | P2 |
| `ciba` | 后台认证 + ping notifier | P2 |
| `userinfo` | JWT 验签 + claims 投影 | P1 |

每个负载场景输出：p50/p95/p99 延迟、吞吐量（QPS）、错误率、CPU/内存基线。

#### 2. 多后端性能对比矩阵（M，独立可交付）

| 后端组合 | 对比维度 |
|---|---|
| Memory（所有 store） | 基准线 —— 理论最高吞吐 |
| SQLite（所有 store） | WAL 模式的单机持久化性能 |
| Redis（热路径 store） | 跨副本共享 + 原子操作的开销 |
| PostgreSQL（spi store） | 中心化后端的网络开销 |
| Mixed（SQLite + Redis） | 典型生产配置 |

矩阵产出 operator-facing 文档："在给定 QPS 目标下如何选择后端"。

#### 3. 性能回归门禁（M，CI 集成）

在 CI 中增加**非阻塞性能回归检测 job**：

```yaml
# .github/workflows/perf-regression.yml
name: performance-regression
on:
  pull_request:
    paths: ['**.go', 'go.mod', 'go.sum']

jobs:
  perf-regression:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: make load-test-record    # 用 PR 的代码跑负载测试，记录结果
      - name: Compare with baseline
        run: make load-test-compare    # 与 main 分支的基线比较
        # 如果 p95 延迟退化 > 10% → PR label "perf-regression"
```

- **不阻塞合入**（性能测试有噪声，不应作为硬门禁）
- 退化时自动添加 `perf-regression` 标签 + PR comment 报告对比数据
- 基线定期更新（每周自动记录新 baseline）

#### 4. pprof 端点与持续 profiling（S，独立可交付）

在生产 binary 中激活 pprof：

```go
// cmd/sso-server/main.go 或 options.go
import _ "net/http/pprof"

// WithPprofEndpoint enables /debug/pprof/* on the admin port (default: off, opt-in).
// 仅在 admin 端口监听（生产环境不暴露给外部）
func WithPprofEndpoint(enable bool) Option { ... }
```

- pprof 仅通过 admin 端口（`:8081`）暴露，不占用业务端口
- 可选集成 `pyroscope`/`parca` 进行持续 profiling
- 作为 benchmark 失败的排查工具

#### 5. 容量规划指南（S，文档）

产出 `docs/capacity-planning.md`，内容包括：

- 每个后端组合的吞吐量基准数据（从 1. 和 2. 获取）
- 瓶颈分析（CPU → memory-bound → IO-bound → network-bound，取决于后端）
- 推荐部署拓扑：
  - < 100 QPS：单进程 SQLite（嵌入式无依赖）
  - 100–1000 QPS：单进程 + Redis（共享 session/JTI）
  - 1000+ QPS：多副本 + Redis/PG + 水平扩展
- 扩展策略：读扩展（增加副本）vs 写扩展（分区 tenant）
- 每个租户的配额模型（复用 `interfaces/sso/quota.go`）

### 价值 · 工作量

| 维度 | 评估 |
|---|---|
| 运营价值 | 极高——每次扩容/选型/PR 的决策数据支持 |
| 销售价值 | 高——"支持 >5k QPS"有量化数据支撑 |
| 改动量 | 中——多工具链集成（k6 + prometheus + benchstat），核心 Go 代码改动小 |
| 与已有分析的差异性 | ✅ **本报告独有**（20+ 轮分析从未提及） |

---

## 总结

本报告 5 个方向共同的定位是：**把项目的工程质量从"功能完整"提升到"可信任基础设施"级别**。
它们不增加任何面向用户的协议功能，而是建设让维护者、operator、审计员和下游消费者
对系统有信心的质量纵深：

| 方向 | 解决的问题 | 核心交付物 | 优先级 |
|---|---|---|---|
| ① 升级健康框架 | 每次升级的"祈祷式部署" | Pre-flight check, compat matrix, rollback guide | **P0** |
| ② 身份 CDC 与状态同步 | 下游系统依赖身份数据的实时同步 | CDC SPI + store hooks + 输出适配器 | **P1** |
| ③ 协议正确性纵深 | 协议的隐性正确性假设无 CI 验证 | Conformance CI + Property-based tests + Formal modeling | **P1** |
| ④ 跨模块集成质量平台 | 最危险的嵌套模块无 CI 保护 | Full ci-modules + 接口契约 + 跨模块集成测试 | **P0** |
| ⑤ 性能工程工具链 | 无可量化的性能基线 | 全路径负载测试 + 后端矩阵 + perf regression CI + 容量文档 | **P1** |

**一句话优先顺序：** ④（CI 全模块构建——S 级改动、零决策成本、立刻做）→
①（Pre-flight check——M 级，让下次升级不再祈祷）→ ⑤（负载测试 + 基准矩阵 ——
为所有后续性能工作提供基线）→ ③（Conformance CI 自动化——M 级，采购流程必备）→
②（CDC 框架——XL 级最大但价值最高的架构投资，需要最审慎的设计）。
