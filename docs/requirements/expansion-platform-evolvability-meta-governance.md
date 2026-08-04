# 扩展方向分析 —— 平台演化能力、系统级质量治理与开发者认知基础设施

> **分析视角：** 资深架构 & 产品经理  
> **日期：** 2026-07-11  
> **方法：** 对当前代码库（2241 个 `.go` 文件、200+ 包、14 个嵌套 `go.mod`、4 个嵌入 SPA、  
>   1114 个测试文件、50+ 协议/安全/产品特性）全局扫描。在系统阅读了 `docs/requirements/` 下  
>   全部 46+ 份已有扩展方向分析文档的基础上，**对每项候选方向做全代码库 grep 核验 +  
>   与 46+ 份已有分析做全关键词交叉验证**，确保本报告的每个方向在已有分析中  
>   **零覆盖或仅浅层触及**，且代码中**零实现或仅部分存在**。
>
> **前置声明：** 经过 46+ 轮扩展分析，本项目的普通 feature 缺口已接近理论上限。  
>   已有分析覆盖了：全部协议扩展、安全纵深、产品化能力、运营 SRE 框架、隐私工程、  
>   FinOps、开发者体验、业务可观测性、运行时治理、系统质量纵深、生产硬化、边缘场景、  
>   身份治理等等。**本报告不再重复这些方向。**
>
> **本报告定位：** 聚焦于一个拥有 2241 个源文件、14 个独立 Go 模块、50+ 功能特性、  
>   46+ 份分析文档的复杂系统**在长期演化中自身面临的治理与质量挑战**——  
>   不是"这个产品还能做什么"，而是"这个平台能否可持续地发展下去"。

---

## 项目成熟度：关键规模数据

本报告的分析基于以下实际维度的项目规模评估：

| 维度 | 数据 | 影响 |
|---|---|---|
| **Go 源文件** | 2241 个 `.go` 文件 | 开发者全量阅读不现实，需要导航工具 |
| **测试文件** | 1114 个测试文件 | 测试覆盖率不等同于系统级质量保证 |
| **独立 Go 模块** | 14 个嵌套 `go.mod` | 依赖治理、版本协调、构建时间的挑战 |
| **协议/安全/产品特性** | 50+ 独立功能 | 组合交互空间 > 2^50，无法穷举测试 |
| **存储后端实现** | Memory/SQLite/PostgreSQL/Redis/etcd 五类 200+ 实现 | 每个后端行为可能不同，互换性需要验证 |
| **扩展分析文档** | 46+ 份（~23,000 行） | 提案 > 实现，需要决策治理机制 |
| **根包 (root)** | ~143 个 `interfaces/sso/` 下的 Go 文件 | 根目录文件数接近 gate 上限，架构压力 |
| **代码硬门禁** | 文件 ≤500 行 / 函数 ≤50 行 / 圈复杂度 ≤15 / 目录深度 ≤3 | 质量控制已自动化，但门禁本身带来维护负担 |

---

## 方向一：组合特性交互混沌 & 系统级集成验证基础设施（Combinatorial Feature Interaction Testing）

> **全代码库核验：** grep `combinat.*test\|feature.*interact.*test\|cross.*feature.*test\|matrix.*test\|interaction.*test\|combinat.*chaos`  
> 在全部 46+ 份已有分析中 **0 命中**。代码中零实现。

### 现状

项目拥有极其丰富的测试资产：

```
test/                  → 200+ 端到端测试文件
  ├── e2e_test.go      → 基础 E2E 流程
  ├── dpop_test.go     → DPoP 专测
  ├── mfa_test.go      → MFA 编排测试
  ├── oath_enabled_test.go → 几乎每项功能都有专测
  └── ...              → 200+ 文件
chaos/                 → 4 个混沌测试（网络分区、时钟偏斜等）
benchmark gate         → 基准回归门禁
fuzz tests             → 10+ 模糊测试
race CI                → -race 全部测试
```

**但是：没有任何测试同时组合 3 个以上的功能特性。**

具体来说，以下完全合理的生产组合从未被系统性测试：

| 组合场景 | 涉及的特性 | 测试覆盖 |
|---|---|---|
| **DPoP + Token Exchange + Cross-Tenant + Session** | DPoP 约束密钥 → token exchange 传播 → 跨租户令牌 → session 创建 | ❌ 零 |
| **SAML IdP-initiated + MFA + Conditional Access + Region** | SAML SSO → MFA step-up → 条件访问策略评估 → 区域驻留检查 | ❌ 零 |
| **CIBA + WebAuthn + Session Quota + Audit** | CIBA 推送认证 → WebAuthn 设备签名 → 会话配额检查 → 审计事件链 | ❌ 零 |
| **Device Code + Token Exchange + SCIM Deprovision** | 设备流授权 → token exchange 委派 → SCIM 下游撤销传播 | ❌ 零 |
| **Federation 1.0 + Federation 信任链 + DCR + Token Policy** | 联邦信任解析 → 自动客户端注册 → token 策略应用 | ❌ 零 |
| **Workload Identity + Token Exchange + Propagation Chain** | Workload 身份认证 → act 链构建 → 跨协议传播 | ❌ 零 |

**核心问题：** 身份平台的核心价值在于多特性同时使用时**行为可预测**。每项特性单独通过
测试只能证明它"在真空中工作"。真实生产环境中的故障往往发生在特性的**交集**——例如
"DPoP-bound token 在 token exchange 后的 act 链传播中丢失了 cnf 声明"或"区域驻留检查
与跨租户协作的组合导致 EU 租户的 US 合作伙伴无法正确验证令牌"。

### 为什么需要它

1. **长期演化安全的基本保障**：当前每增加一个新特性，只能验证它不与已有特性冲突
   （通过已有测试的回归）。无法验证它与多个已有特性**组合后**的行为正确性。随着
   特性数量从 50 增长到 100，这个问题会指数级恶化。

2. **组合缺陷的修复成本远高于普通 bug**：组合缺陷的特点是：两个都正确的特性放在一起
   产生错误行为。这种 bug 需要跨多个包/团队/协议的调试，修复周期通常是以周为单位。

3. **竞品分析：** Auth0/Okta 的内部 CI 都包含组合矩阵测试（Feature Interaction Test
   Suite），这是它们敢于快速添加新特性的基础信心来源。没有这个，每个新特性都面临
   "会不会破坏某个未注意到的组合"的未知风险。

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **1. 组合特征矩阵定义** | 定义组合矩阵：维度 = 特性集，值 = on/off。从 50+ 特性中精选 15-20 个高影响特性（DPoP、mTLS、Token Exchange、CIBA、Device Code、SAML IdP、SCIM、CAEP、Federation、Conditional Access、Region、Session Quota、Audit、Token Policy、MFA、WebAuthn、Workload Identity、Cross-Tenant、JAR、PAR）。生成 20 个高价值组合场景。 | M |
| **2. 组合测试框架** | 扩展 `test/testkit`：新增 `CombinatorialTestRunner` 自动开启/关闭 feature gates 并运行端到端断言。每个组合场景产生一个可独立运行的 Go 子测试。使用 build tags 或环境变量控制特性启用。 | L |
| **3. 组合测试 CI 门禁** | 将组合测试作为 CI 的可选检查（压力过大不阻塞 PR，但阻塞 merge）。每月全量组合矩阵运行一次，结果发布到 `docs/combinatorial-test-report.md`。 | M |
| **4. 特性交互影响矩阵文档** | 在 `docs/` 中发布交互影响矩阵：每对特性和每三个特性组合的已知交互行为（兼容/冲突/需要特殊配置/未测试）。新特性加入时更新此矩阵。 | M |
| **5. 增量特性交互检查** | 在 PR CI 中新增一个脚本：当 PR 修改涉及某个特性的代码时，自动提示 Reviewer "此改动影响特性 A/B/C，请确认是否触发了相关的组合测试场景"。 | S |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 组合测试的执行时间爆炸 | 每个组合测试场景的 timeout 单独配置。全量矩阵每月跑一次。CI 中运行精选的 5 个核心组合场景。 |
| 组合测试结果的不稳定性 | 组合测试中可能引入竞态条件（特性 A 关闭后特性 B 的初始化状态不正确）。测试应幂等，至少 3 次重试失败后才标记为失败。 |
| 新特性加入时组合矩阵的维护 | 新特性在代码审查时就必须附带"此特性与哪些其他特性有已知交互"，更新交互影响矩阵文档。 |
| 组合测试的断言强度弱于单特性测试 | 组合测试不追求全量断言，只验证"组合后不崩溃 + 核心行为正确"。组合测试中发现的不一致应降级为单独的特性交互缺陷进行深入测试。 |

---

## 方向二：跨后端行为一致性验证框架（Cross-Backend Behavioral Conformance Suite）

> **全代码库核验：** grep `conformance.*backend\|backend.*conformance\|cross.*backend.*test\|backend.*interchange\|store.*conformance\|storage.*agreement`  
> 在已有分析中 **0 命中**。当前仅有 `permissionstest.ConformanceSuite` 这一个 conformance suite。

### 现状

项目拥有五个主要存储后端（Memory、SQLite、Redis、etcd、PostgreSQL），每个后端
覆盖不同的存储接口（client store、session manager、consent store、token store、
permission store、user store、auth code store 等 20+ 个 SPI）。

**后端实现分布（部分统计）：**

| SPI | Memory | SQLite | Redis | PostgreSQL | etcd |
|---|---|---|---|---|---|
| ClientStore | ✅ | ✅ | ✅ | ✅ | ❌ |
| SessionManager | ✅ | ❌ | ✅ | ❌ | ❌ |
| ConsentStore | ✅ | ❌ | ✅ | ❌ | ❌ |
| AuthCodeStore | ✅ | ❌ | ✅ | ❌ | ❌ |
| RefreshTokenStore | ✅ | ❌ | ✅ | ❌ | ❌ |
| UserStore | ✅ | ✅ | ✅ | ✅ | ❌ |
| TenantStore | ✅ | ✅ | ❌ | ✅ | ❌ |
| PermissionStore | ✅ | ✅ | ✅ | ✅ | ❌ |

**核心问题：** 没有任何跨后端的**行为一致性验证套件**。这意味着：

| 风险场景 | 后果 |
|---|---|
| 开发者在 Memory 后端上测试通过 → 部署到 PostgreSQL 后端时竞态条件行为不同 | 生产事故 |
| SQLite 使用 `DELETE RETURNING` 实现原子读取-删除 → Memory 后端用 `sync.Mutex + map` 实现 | 并发行为不同，复杂 bug 在 Memory 测试中不暴露 |
| Redis 后端对 key 有 TTL 自动过期 → Memory 后端需要手动 GC | 测试中的过期行为不同 |
| PostgreSQL 的序列化隔离级别比 SQLite 更强 | 在高并发下不同的错误行为 |

**已有模式参考：** `domains/permissions/permissionstest` 已经定义了一个
`ConformanceSuite` 模式——为每个 `PermissionProvider` 实现提供可复用的验证套件。
这个模式**应推广到所有存储 SPI**。

### 为什么需要它

1. **后端的可替换性是架构核心承诺**：项目架构明确承诺"每个 concern 都有 memory +
   可选的后端实现"。如果不同后端的行为不一致，那么 memory 后端就失去了作为"参考实现"
   的价值——开发者不能相信在 memory 上通过的测试在 PostgreSQL 上同样正确。

2. **SQLite 和 PostgreSQL 的语义差异**：SQLite 使用 `BEGIN IMMEDIATE` 而 PostgreSQL
   使用 `SERIALIZABLE` 隔离级别。这些差异在高并发场景下会导致完全不同的失败模式。
   如果没有 conformance suite，这些差异只有在生产环境才会暴露。

3. **Redis vs 内存后端的语义差异**：Redis 后端对存储的数据有隐式的 TTL 过期和 LRU 驱逐。
   Memory 后端没有这些。如果一个测试只在 memory 上运行并通过，部署到 Redis 后可能
   因为 TTL 导致数据过早消失——这种 bug 极难调试。

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **1. Conformance Suite SPI 模式推广** | 提取 `permissionstest` 的模式为通用模式（一个 `ConformanceSuite` 类型，每个 Store interface 对应一个测试套件）。为以下 SPI 创建 conformance suite：`ClientStore`、`SessionManager`、`ConsentStore`、`AuthCodeStore`、`RefreshTokenStore`、`UserStore`、`TenantStore`、`TokenStore`。 | L |
| **2. 每个 conformance suite 的测试内容** | 每个套件测试：CRUD 基础操作、并发访问（竞态条件）、错误路径（不存在/已过期/已删除）、边界条件（空字符串/nil/超长输入）、事务行为（如果支持）。 | L |
| **3. 后端一致性报告** | 每个 CI 构建自动运行所有后端的 conformance suite，生成一致性报告（`go test -run Conformance ./... -backends=memory,sqlite,redis,postgres`）。结果显示在 CI 中。 | M |
| **4. 后端行为差异文档** | 在 `docs/` 中发布已知的后端行为差异（"SQLite 使用 `DELETE RETURNING`，Memory 使用 map delete——在读后删除的竞态条件下行为不同"）。每个新后端实现必须更新此文档。 | S |
| **5. 参考实现定义** | 明确指定 Memory 后端为"参考实现"（Reference Implementation）。其他后端的行为应尽可能与 Memory 一致——有差异的地方必须是文档化的、合理的（如 TTL 过期）。 | S |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 某些后端不支持某些功能（如 Redis 不支持复杂查询） | Conformance suite 应有 `Optional` 标签，后端可以声明"不支持"。但核心 CRUD 行为必须一致。 |
| 后端的性能特征不同 | Conformance suite 不测试性能，只测试行为正确性。性能测试在单独的 benchmark 中。 |
| 新后端加入时的验证成本 | Conformance suite 设计为"一个 import + 几行配置"即可运行，降低新后端验证的阻力。 |

---

## 方向三：配置面完整性治理与自动化验证（Configuration Surface Completeness Governance）

> **全代码库核验：** grep `config.*document.*complete\|config.*schema.*validat.*complete\|config.*field.*undoc\|config.*option.*untest\|config.*discover\|config.*lint.*complete`  
> 在已有分析中 **0 命中**。代码中已有 `config/config.go` 基础设施但无配置面完整性验证。

### 现状

项目拥有 YAML 驱动的配置系统（`config/config.go`），支持 SIGHUP 热加载，并且
已有 feature gates 的配置 diff 和 drift 检测。

**但是，没有以下能力：**

| 配置治理能力 | 状态 | 影响 |
|---|---|---|
| 所有 config 字段的文档覆盖率检查 | ❌ 零 | 新用户不知道有哪些配置项可用 |
| Config 字段的默认值与零值语义自动验证 | ❌ 零 | `false` 表示"关闭"还是"使用系统默认"？ |
| 配置选项间的互斥/依赖关系自动验证 | ❌ 零 | `WithX` 和 `WithY` 同时使用是否合法？ |
| 废弃配置项的分阶段退役流程 | ❌ 零 | 无法安全移除旧配置项 |
| 配置模板生成器（从 Go 结构体生成 YAML 模板） | ❌ 零 | 文档与代码同步 |
| 配置变更的向后兼容性自动检查 | ❌ 零 | 无通知的 breaking change 风险 |

**核心问题：** 随着 50+ 特性的增加，配置项数量也会线性增长。如果没有系统性的配置面
治理，将面临以下风险：

- 配置项文档落后于代码
- 用户不知道新配置项的存在
- 废弃配置项在代码中永久残留（因为不敢移除）
- 配置项间的互斥关系靠运行时 panic 发现

### 为什么需要它

1. **配置是用户看到的第一样东西**：用户在集成 SSO 平台时，首先接触的就是 `config.yaml`。
   如果配置项没有文档、没有自动补全、没有验证，开发者体验就从这里开始下降。

2. **配置复杂性随着特性数量线性增长**：50 个特性 × 每个 2-3 个配置项 = 100-150 个配置项。
   没有系统治理的话，配置文档一定会落后于代码实现。

3. **配置变更的 Breaking Change 检测**：当前 Go 结构体字段的重命名、类型变更、默认值
   变更都没有自动检测。这会导致部署升级时用户的配置文件突然不兼容。

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **1. Config 字段扫描器** | 一个 Go 工具，扫描 `config/config.go` 和所有 `options*.go` 文件，提取所有配置字段及其类型、默认值、可选标签。输出 JSON 清单。 | M |
| **2. 文档覆盖率门禁** | 在 CI 中运行扫描器，对比 `docs/config-reference.md` 中记录的配置项。未记录的配置项使 CI 失败。新配置项必须伴随文档更新。 | M |
| **3. Config 模板生成器** | 从 Go 结构体生成完整的 YAML 配置文件模板，包含所有字段的注释（从代码中的 doc comment 提取）。结果写入 `docs/config-template.yaml`。 | M |
| **4. 配置验证增强** | 在启动时运行全量配置验证：检查互斥项（如 `WithA` 和 `WithB` 同时使用 → 告警）、依赖项（`WithC` 需要 `WithD` 前置 → 告警）、值范围（`timeout < 0` → 错误）。 | L |
| **5. 配置弃用流程** | 支持 `Deprecated(since, useInstead)` 标签。废弃配置项在日志中打印 `WARN`，在 YAML 模板中被标记为废弃。弃用后 N 个版本正式移除，有门禁检查移除时间。 | M |
| **6. 配置变更兼容性检查** | 在 PR CI 中运行：diff 当前 `config.go` 的扫描结果与主分支的扫描结果。如果有 breaking change（字段类型变更、默认值变更、字段移除），在 PR 上自动评论。 | M |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 配置项太多导致文档过长 | 将文档拆分为按功能域的多个页面，自动生成索引。 |
| 配置项默认值在代码中变更 | 自动检测 + PR 评论 + 在 changelog 中注明。Breaking change 需要 major 版本号变更。 |
| 用户使用旧版本配置文件启动新版本服务器 | 启动时验证配置文件版本（`config_version` 字段），版本不匹配时发出 WARN + 建议升级路径。 |
| 动态热加载的配置项 vs 启动时配置项 | 明确分离两类配置项：热加载项在 `config.yaml` 中标记为 `# hot-reloadable: true`。不支持热加载的配置变更需要重启。 |

---

## 方向四：Go 模块依赖治理与构建系统成熟化（Go Module Governance & Build System Maturity）

> **全代码库核验：** grep `module.*govern\|go.mod.*govern\|depend.*graph\|depend.*upgrade.*plan\|build.*time.*optim\|module.*lifecycl\|circular.*depend\|diamond.*depend`  
> 在已有分析中 **0 完整方向**（`expansion-runtime-governance` 方向五部分涉及依赖完备性验证但不涉及模块治理）。

### 现状

项目目前拥有 **14 个嵌套 `go.mod` 文件**，每个管理自己的依赖集：

```
/                          → github.com/snaplink/sso
/kms/awskms/              → 依赖 AWS SDK
/kms/gcpkms/              → 依赖 GCP KMS SDK
/kms/azurekeyvault/       → 依赖 Azure SDK
/kms/pkcs11/              → 依赖 crypto11
/saml/idp/                → 依赖 SAML 库
/saml/sp/                 → 依赖 SAML 库
/ldap/                    → 依赖 LDAP 库
/kerberos/                → 依赖 Kerberos 库
/radius/                  → 依赖 RADIUS 库
/extauthz/                → 依赖 Envoy API
/redis/                   → 依赖 go-redis
/kafka/                   → 依赖 sarama
/mqtt/                    → 依赖 paho
```

**核心挑战（grep 核验为真缺口）：**

| 挑战 | 状态 | 影响 |
|---|---|---|
| 模块间的依赖版本一致性检查 | ❌ 零 | 不同模块可能依赖同一库的不同版本 |
| 模块间的间接依赖冲突检测（diamond dependency） | ❌ 零 | `go mod tidy` 可能选择不兼容版本 |
| 模块依赖的自动升级和回归测试 | ❌ 零 | Dependabot 发 PR 但无系统性回归验证 |
| 模块的可选性文档（哪些模块是可选的？如何裁剪？） | ❌ 零 | 构建者不知道最小依赖集是哪些 |
| 构建时间监控和回归门禁 | ❌ 零 | 不清楚全部构建 + 测试需要多长时间 |
| 模块生命周期流程（添加新模块的检查清单） | ❌ 零 | 新模块随意添加，无标准化流程 |

### 为什么需要它

1. **构建时间是开发者效率的关键**：14 个模块的全部构建 + 测试可能在 CI 中花费 20+ 分钟。
   没有构建时间监控和优化，开发者等待 CI 的时间会线性增长。

2. **依赖冲突在 14 模块的场景下是真实风险**：如果两个模块依赖了同一第三方库的不同
   minor 版本，`go mod tidy` 可能选择不被两者都兼容的版本。在 14 模块 + 近百个
   依赖的实际场景下，这种冲突迟早会发生。

3. **模块入口的增加需要治理**：目前添加新模块是自由的。随着模块数量增长到 20+，
   "模块太多"本身就成了问题——每个模块需要维护、升级依赖、修复 lint 问题。

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **1. 模块依赖关系图生成** | 工具分析所有 14 个 `go.mod`，生成依赖关系图（DAG），标注每个依赖在多少个模块中被引用、版本是否一致。输出为 SVG/Mermaid。 | M |
| **2. 依赖版本一致性门禁** | CI 脚本检查所有模块共享的依赖（如 `golang.org/x/crypto`）的版本是否一致。不一致则 CI 告警。 | S |
| **3. 构建时间预算** | 每个模块设定构建时间的软限制和硬限制。构建时间超限在 CI 中打印告警。可选项：缓存优化（Go build cache / Docker 层缓存）。 | M |
| **4. 模块添加检查清单** | 在 `CONTRIBUTING.md` 中记录添加新模块的必做项：为什么放在嵌套模块而非主模块、依赖集审计、构建时间影响评估、与现有模块的 API 边界定义。 | S |
| **5. 最小依赖集文档** | 记录"零外部依赖"的核心构建路径（`CGO_ENABLED=0` 且仅使用主模块）。其他非核心模块按类别（KMS/SAML/LDAP/队列）分组标注可选性。 | M |
| **6. 依赖升级影响预览** | 在 Dependabot PR 中自动评论："此升级会影响 3 个模块（A/B/C）。在这 3 个模块中运行了 conformance suite（全部通过）。查看完整依赖关系图：[link]"。 | L |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 两个模块需要同一依赖的不同 major 版本 | 这通常意味着模块之间的 API 存在不兼容。评估是否将两个模块解耦更远（分层为独立仓库）。 |
| 构建时间优化的收益递减 | 如果构建时间从 20 分钟优化到了 10 分钟但投入了 50 小时工程时间，需要评估 ROI。建议只关注最慢的 3 个模块。 |
| 外部依赖的新版本引入了行为变化 | Dependabot 的 automerge 不适用于本仓库。所有依赖升级 PR 需要手动审查，CI 必须运行全量 conformance suite。 |

---

## 方向五：开发者认知负载管理与代码库导航基础设施（Developer Cognitive Load Management & Codebase Navigation Infrastructure）

> **全代码库核验：** grep `onboard\|codebase.*navig\|code.*map\|learn.*path\|developer.*guide.*index\|cognitive.*load\|code.*understand\|project.*map`  
> 在已有分析中 **0 完整方向**（`expansion-novel-v4` 方向二覆盖了 SDK/DX，但不覆盖内部代码库导航）。

### 现状

项目的代码库规模：

```
2241 个 .go 源文件
200+ 个包
14 个独立 go.mod
50+ 功能特性
46+ 份分析文档（23,000+ 行）
143 个 interfaces/sso/ 下的文件
1114 个测试文件
20+ 个存储 SPI
```

而当前的开发者入门资源：

| 资源 | 状态 | 覆盖 |
|---|---|---|
| `README.md` | ✅ 存在 | 30 秒快速入门 |
| `docs/developer-guide.md` | ✅ 存在 | 架构概述 |
| `docs/architecture/DIRECTORY_MAP.md` | ✅ 存在 | 目录导航图 |
| `docs/examples/quickstart/` | ✅ 存在 | 可运行示例 |
| **交互式代码库浏览器** | ❌ 不存在 | — |
| **架构演进可视化** | ❌ 不存在 | — |
| **"如何添加 X" 的标准化指南** | ❌ 不存在 | 仅有 AGENTS.md 片段 |
| **代码库搜索索引/知识图谱** | ❌ 不存在 | — |
| **语义化的包依赖图** | ❌ 不存在 | — |
| **已知设计模式与惯用法的文档** | ❌ 不存在 | — |

**核心问题：** 一个 2241 文件的代码库对新开发者（包括 AI agent）有很高的"冷启动"
成本。每次学习时都需要回答：

- 这个功能应该放在哪个包？
- 这个接口在哪里定义？有哪些实现？
- 添加一个新 grant 需要修改哪些文件？
- 这些包之间的依赖关系是怎么样的？

### 为什么需要它

1. **AI agent 和人一样需要导航工具**：AGENTS.md 已经制定了严格的规则（架构层次、
   目录深度、import 方向）。但一个 AI agent 在修改代码时仍然需要手动 read 数十个文件
   来理解上下文。结构化的代码库知识图谱可以大幅降低每次修改的"认知预热"成本。

2. **新功能的添加速度与代码理解深度成正比**：随着代码库增长到 2241 文件，添加一个新
   OAuth grant 不再只是"写 handler + store + test"。开发者需要理解路由注册、middleware
   栈、feature gate 系统、配置注入、审计事件注册、错误码更新、API 文档同步等多层
   基础设施。没有结构化的"修改清单"，很容易遗漏步骤。

3. **代码库规模已达人工理解的极限**：没有任何一个人能记住 200 个包的接口签名和依赖
   关系。工具化的导航支持（而不是依赖"老成员的记忆力"）是代码库可持续发展的前提。

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **1. 语义化的 Go 包索引** | 从 Go 源文件自动生成索引数据：包 → 暴露的接口、接口 → 实现、函数 → 调用者、类型 → 使用位置。输出为 JSON，可被 IDE 插件或 CLI 工具消费。 | L |
| **2. 架构交互关系图** | 从架构层测试（`architecture_layer_test.go`）和实际 import 路径自动生成包依赖关系图（D3.js/SVG）。标记违反架构层规则的"坏依赖"。 | M |
| **3. "如何添加 X" 的模板化清单** | 为常见修改类别（添加新 OAuth grant、添加新存储后端、添加新 authenticator、添加新 audit event、添加新 endpoint）生成 checkable 清单模板。每个模板列出需要修改的文件、需要更新的文档、需要添加的测试。存储在 `docs/guides/`。 | M |
| **4. 代码库变更影响分析工具** | CLI 工具 `sso-ctl analyze-change <file>`：分析给定文件修改可能影响哪些其他包/测试/文档。基于静态调用图和包依赖关系计算影响范围。 | L |
| **5. 开发者学习路径** | 在 `docs/` 中发布分等级的学习路径：Level 1（了解项目结构 + 运行 quickstart + 理解核心 SPI）、Level 2（修改现有 handler + 添加测试 + 运行 CI 门禁）、Level 3（添加新特性 + 更新文档 + 创建新包）。每级包含阅读清单 + 实践练习。 | M |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 索引和图表可能过时 | 索引和图表在 CI 中自动生成（`make docs`），与代码同步。PR 必须通过 `make docs` 来确认图表与代码一致。 |
| 分析工具的误报和漏报 | 静态分析工具的结果应作为**参考**而非**门禁**。工具的高确信度结果（如"确定会影响的包"）可用于自动 PR 评论。低确信度结果（"可能影响"）只作为开发者的检查清单。 |
| 新开发者 vs 老开发者的需求差异 | 学习路径面向新开发者。代码索引和影响分析工具对所有开发者都有价值。模板化清单对两者都有用。三者覆盖了从入门到日常开发的全谱系需求。 |

---

## 优先级与实施建议

| 方向 | 核心价值 | 工作量 | 独立交付 | 优先级 |
|---|---|---|---|---|
| **① 组合特性交互测试** | 长期演化安全，防止"正确特性的错误组合" | L | ✅ | **P1**（在增加第 60 个特性之前必须建立） |
| **② 跨后端 Conformance Suite** | 后端互换性的可信度保证，修复架构核心承诺 | L | ✅ | **P0**（架构承诺的技术债务，应立即还） |
| **③ 配置面完整性治理** | 用户的第一印象，运维的安全网 | M | ✅ | **P1**（特性数量翻倍前建立） |
| **④ Go 模块依赖治理** | 构建效率，依赖风险管理 | M | ✅ | **P2**（当前 14 模块尚可管理，20+ 时紧急） |
| **⑤ 开发者认知基础设施** | 长期生产力，降低 AI agent 和人的冷启动成本 | L | ✅ | **P2**（持续构建，无明确截止时间） |

### 阶段建议

- **阶段一（当前 Sprint）：** 方向② 的后端 Conformance Suite 建立。从 `permissionstest`
  模式提取通用框架，先覆盖 `ClientStore` 和 `SessionManager` 两个最常用 SPI。
  方向① 的组合特征矩阵定义。

- **阶段二（下个 Sprint）：** 方向③ 的 Config 字段扫描器 + 文档覆盖率门禁。
  方向① 的组合测试框架 MVP（5 个高优先级场景）。

- **阶段三（月度）：** 方向④ 的依赖关系图生成 + 版本一致性门禁。
  方向⑤ 的模板化清单（OAuth grant + 存储后端）。

- **持续：** 方向⑤ 的学习路径 + 语义索引逐步构建，与项目增长同步。

---

## 与已有 46+ 份分析的零重叠验证

| 方向 | 验证关键词 | 已有分析命中 | 结论 |
|---|---|---|---|
| ① 组合测试 | `combinat.+(feature\|test\|interact\|matrix)` | **0 命中** | ✅ 全新增 |
| ② Conformance Suite | `conformance.*backend\|backend.*conformance\|cross.*backend.*conform\|store.*conform` | **0 命中** | ✅ 全新增 |
| ③ 配置面治理 | `config.*(complete\|document.*coverage\|template.*generat\|deprecat.*config\|breaking.*config)` | **0 命中** | ✅ 全新增 |
| ④ 模块治理 | `module.*govern\|go.mod.*govern\|depend.*graph\|build.*time.*optim\|module.*lifecycl` | **0 命中**（仅 `expansion-runtime-governance` 方向五的"完成性验证"部分涉及依赖，非模块治理） | ✅ 全新增 |
| ⑤ 认知负载 | `onboard\|cognitive.*load\|code.*navigat\|learn.*path\|code.*map.*index\|knowledge.*graph` | **0 命中**（`expansion-novel-v4` 方向二 SDK DX 面向外部开发者，非内部代码库导航） | ✅ 全新增 |

---

*本报告 5 个方向聚焦于项目作为复杂系统在长期演化中的自身治理与质量挑战。*
*它们不增加对外可见的功能特性，但决定了项目能否在特性数量持续增长的情况下*
*保持可持续的演化速度、代码质量和开发者信心。*
