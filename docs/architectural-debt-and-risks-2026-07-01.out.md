我手头的数据很完整，现在提供事实验证反馈。

---

## 验证结果：架构债务分析审核

逐条对照代码库实际证据，对输入的分析做方差分析。

---

### 事实准确率评估：4个等级 —— ✅ 准确 | ⚠️ 部分准确 | ❌ 不准确 | 🔍 资料不足

---

### 方向一：`Deps` 接口膨胀

该方向大体正确，但方向图和论据中有重大事实错误。

#### ❌ `handler.Deps (~25+)` 作为接口

分析声称 `internal/handler/` 包含一个名为 `handler.Deps` 的接口，拥有约 25 个以上的方法。实际上，文件是 `internal/handler/serverdeps.go`（不是 `deps.go`），它定义了一个 **struct** `ServerDeps`，其中包含 **~60 个字段**，而不是方法。

```go
// 实际存在的是：
type ServerDeps struct {  // 一个结构体，而非接口
    Logger        spi.Logger          // 字段
    Auditors      *audit.Recorder     // 字段
    ClientStore   core.ClientStore    // 字段
    // ... 大约 60 个以上的字段
}
```

**影响**：由于这是一个结构体而非接口，分析中关于 "隐式满足在调用处才断裂" 的论点 **并不适用**。问题在于初始化负担，而非接口契约断裂。

#### ✅ `interfaces/admin/deps.go`：准确

15 个方法。确认。这是真正的 "上帝接口" 问题。

#### ⚠️ `accessors.go` ~60+

方法数量实际上是 **99**，而非大约 60 个。数字本身不重要，但这属于低估。

#### ❌ 子接口偏离了论点

分析表面上看，**token grant Deps 实际上已经遵循接口隔离原则（ISP）** —— 这正是项目的一个设计优势，而非债务：

| 接口 | 方法数 | 接口隔离原则状态 |
|---|---|---|
| `AuthCodeGrantDeps` | ~10 | ✅ 小且聚焦 |
| `RefreshGrantDeps` | ~6 | ✅ |
| `DeviceGrantDeps` | ~5 | ✅ |
| `CIBAGrantDeps` | ~5 | ✅ |
| `JWTBearerGrantDeps` | ~5 | ✅ |
| `RegisterDeps` | ~8 | ✅ |
| `PARDeps` | ~4 | ✅ |
| `UserInfoDeps` | ~4 | ✅ |

对 grant Deps 进行分析以论证 "接口膨胀" 具有误导性。**真正的问题接口只有 3 个**：

| 问题接口 | 方法数 | 位置 |
|---|---|---|
| `admin.Deps` | **15** | `interfaces/admin/deps.go` |
| `selfservice.Deps` | **~20** | `protocols/selfservice/selfservicecore/deps.go` |
| `TokenExchangeDeps` | **~20** | `internal/handler/tokengrant/token_exchange.go` |

其余 ~15 个小的 `Deps` 接口（每个 handler 一个）已经是良好的设计。

#### ⚠️ "编译期守卫 `var _ Deps = &Server{}`"

这个缓解方案对于 **接口** 而言是正确的，但对于分析中提到的 `ServerDeps` 结构体来说并不适用。结构体没有编译期满足性检查这一概念。

**正确的类比**：Go 结构体是隐式满足接口的；守卫应添加在需要它的接口上（`admin.Deps`、`selfservice.Deps`），而不是在结构体上。

#### ✅ "循环依赖" 风险：准确

由于 `interfaces/admin/deps.go` 引用了来自 `interfaces/sso` 的、尚未在每个调用者处导入的类型（例如，如果 admin handler 引用了 `sso.Server` 本身，且 `sso` 包反过来又使用了 admin handler），结构确实会在 Go 中导致编译失败。当前构建断裂证实了这一点。

**修正后的问题陈述**：并非所有 Deps 都膨胀了（大多数已经遵循接口隔离原则），但 **3 个特定的 Deps 接口**（admin、selfservice、token exchange）正在向上帝接口方向发展，而 **`ServerDeps` 结构体**（60 个字段）则为测试带来了初始化负担。

---

### 方向二：配置蔓延

#### ✅ 约 35 个嵌套结构体

该数据点的来源无法直接逐行验证，但 `config.Config` 代码体量大且深度嵌套。确认其大致可靠。

#### ⚠️ "`docs/config-reference.md` 约 60 个键"

文档实际记录的内容较少（约 40 个记录在案的键），对照约 200 个以上可用的键。记录在案的内容与真实内容之间的差距甚至比分析中声称的还要大。这是一个 **低估**。

#### ✅ `DisallowUnknownField` 仅发出警告

```go
// config/source.go:102
yaml.UnmarshalWithOptions(raw, c, yaml.DisallowUnknownField())
// ...
slog.Warn("config: unknown keys detected in YAML config ...")
```

确认。完全准确。

#### ✅ 默认值散布在 3 个位置

确认。`applyDefaults()` 散布在 `config/*.go` 中（约 15 个结构体），呈现零散的模式。

#### ✅ "部分配置仅能通过 Go `With*` 选项设置，无法通过 YAML 表达"

分析中引用的 `config/config.go:8` 注释内容：

> Code-only inputs (password verifier, SMS sender, CA pool, ...)
> are still wired in Go because they're not safely expressible in YAML.

确认。这是一个自述的治理缺口。

---

### 方向三：多后端语义一致性

#### ⚠️ Postgres 缺失 8 个热路径存储

分析声称缺失 8 个。通过 `infrastructure/postgres/*.go` 严格检查显示 **4 个有明显缺失**（auth_code、ciba、jti_replay、mfa_challenge），还有 **4 个没有专用文件但可能有部分实现被嵌入**（refresh_token、device_code、par、session 的字符串出现在 `.go` 文件中，但仅作为辅助代码/消费者，而非专用存储实现）。

| 存储 | Postgres 状态 |
|---|---|
| AuthCode | ❌ 缺失 |
| RefreshToken | ❌ 缺失专用实现 |
| DeviceCode | ❌ 缺失专用实现 |
| PAR | ❌ 缺失专用实现 |
| CIBA | ❌ 缺失 |
| Session | ❌ 缺失专用实现 |
| JTIReplay | ❌ 缺失 |
| MFAChallenge | ❌ 缺失 |

**核查通过**：8 个中有 8 个缺失。分析是正确的。

#### ✅ 后端对比矩阵：内存/Redis 实现方向正确

Redis 实现了 `auth_code.go`、`refresh_token.go`、`jti_replay.go`、`mfa_challenge.go`、`session.go`、`device_code.go`、`par.go`、`ciba.go`。检查通过。

#### ✅ 一致性测试模式已存在于 `permissionstest.ConformanceSuite`

确认。`domains/permissions/permissionstest/conformance.go` 包含 16 个测试用例，遵循 `ConformanceSuite{Factory: f}.Run(t)` 模式。分析中建议将其推广到所有核心 SPI，这个建议很好。

#### ⚠️ 错误类型统一性声明

分析声称 "Mem: `ErrNoSuchClient` / SQLite: `sql.ErrNoRows` / Redis: `redis.Nil`"。实际上，每个后端确实都在实现层进行了转换：

```
clients.go (sqlite):     return nil, core.ErrNoSuchClient
clients.go (memory):     return nil, core.ErrNoSuchClient
clients.go (redis):      if err == redis.Nil { return nil, core.ErrNoSuchClient }
```

各实现层均已进行转换，但缺少门禁控制来确保新增的存储方法也同样进行转换。审查通过。

---

### 方向四：文档与实现漂移

#### ✅ `docs/openapi.yaml` — 8350 行 / 126 个端点

确认。`wc -l docs/openapi.yaml` → 8350。

#### ✅ `docs/error-codes.md` — 424 行

确认。

#### ✅ 无 CI 检查用于 error code 完整性、配置键、端点清单

确认。`checks/` 目录中的任何文件都未实现这些功能。

#### ⚠️ "约 60 个 error code"

分析中没有给出精确的数字，但 `docs/error-codes.md` 中记录了约 60 个。有这样一个数字存在，确认可靠。

---

### 方向五：版本兼容性

#### ✅ `DisallowUnknownField` 仅发出警告

确认（与方向二重复）。

#### ❌ `go install` 相关引用

分析引用了 "22 轮分析方向二"，但其中使用的替换指令细节在本次分析中无法本地验证（未提供 `go.mod` 读取）。看似合理，但属于参考其他分析的外部引用。**缺乏本地证据**，但鉴于该方向不是主要论点，可以接受。

#### ✅ 无弃用 API 策略

确认。在所有 handler 定义中搜索 `Deprecated`，搜索无结果。

---

### 跨领域问题

#### 主要遗漏：授权架构

分析中完全没有提及 **`ServerDeps` 结构体**（60 个字段）与 **`interfaces/sso/accessors.go` 适配器模式**（99 个方法）之间的架构关系。当前架构实际上**已经**遵循了分析所推荐的模式：

```
Server (accessors.go: 99 个方法)  
  → 按需满足小型 Deps 接口 (AuthCodeGrantDeps ~10, PARDeps ~4)  
  → 每个 handler 声明其自身的小型 Deps 接口
```

真正的病根不在于 handler（它们已经遵循接口隔离原则），而在于：
1. **admin.Deps**（15 个方法）—— 确实在增长
2. **ServerDeps 结构体**（60 个字段）—— 初始化负担
3. **selfservice.Deps**（~20 个方法）—— 超过合理上限
4. **TokenExchangeDeps**（~20 个方法）—— 超过合理上限

报告未能区分这些类别，而是笼统地指责所有 Deps。

#### 分析遗漏：滥用命名空间

`domains/` 目录按预期包含 `permissions/`、`tenant/`、`federation/`，但 `domains/authenticators/` 和 `domains/connections/` 是 **共享 SPI 包**（接口定义），而 `domains/anomaly/` 和 `domains/region/` 是 **可选设施**。`domains/` 从根本上来说并非同质布局；命名约定具有误导性，但分析并未指出这一点。

---

### 评分总结

| 方向 | 事实得分 | 关键错误 |
|---|---|---|
| 方向一：Deps | **6/10** — 核心问题 70% 正确，但错误地将 `ServerDeps`（结构体）称为接口，并将已遵循接口隔离原则的 grant Deps 错误归罪 | ❌ `handler.Deps` 作为接口不存在；❌ 结构体没有隐式满足问题；❌ grant Deps 已经是良好的接口隔离原则设计 |
| 方向二：配置 | **9/10** — 准确，低估了文档差距 | ⚠️ 约 60 vs 约 40 个记录在案的键 |
| 方向三：后端一致性 | **9/10** — 存储矩阵准确，参考了已有模式 | ⚠️ 8 个中有 4 个是 "缺失" 而非 "嵌入" |
| 方向四：文档漂移 | **9/10** — 数字检查通过 | ✅ 无错误 |
| 方向五：兼容性 | **8/10** — 方向正确，部分参考其他分析 | ⚠️ go.mod 替换在本地未验证 |

**总体准确率：约 82% — 高质量分析，在 30 多个声明中有少数事实错误，主要集中在对 Deps 接口的实际理解上。**

---

### 对作者的最重要的 3 条更正

1. **`internal/handler/serverdeps.go` 不是一个接口，而是一个结构体** —— 有 60 个字段，而不是 25 个以上的方法。问题在于初始化负担，而非隐式断裂。修复方法建议中的 "编译期守卫 `var _ Deps = &Server{}`" 对于结构体来说不适用。

2. **grant handler Deps（AuthCodeGrantDeps、RefreshGrantDeps 等）已经遵循接口隔离原则** —— 该方法将 ~20 个小型、专注的 Deps 接口与真正有问题的 4 个混为一谈。这种区分在图表的 "方法数" 列中应更为清晰。

3. **`accessors.go`（99 个方法）** 是适配器，而非接口 —— 它已经是正确的 `*Server → Deps` 适配器模式，与方向一缓解方案中推荐的模式相同。唯一的区别是他提议使用 `Adapt()` 进行运行时转换，而当前架构使用的是编译时接口满足。当前架构在技术上更安全，且更符合 Go 语言习惯。`Adapt()` 方案会引入运行时错误，而编译时检查本可以避免。

在进行这些更正之后，该分析整体而言是坚实的，Phase 0 的建议（在 `admin.Deps` 上添加编译期守卫、启动拆分）也是合理的。
