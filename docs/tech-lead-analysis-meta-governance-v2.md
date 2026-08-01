# Tech Lead 实施分析报告：五项元治理方向

> **分析者：** Tech Lead Agent  
> **日期：** 2026-07-12  
> **基准：**  
> - `docs/requirements/expansion-platform-evolvability-meta-governance.md`（原始分析，433 行，5 方向）  
> - 代码库实地核验：2241 `.go` 源文件、1114 测试文件、14 嵌套 `go.mod`、143 `interfaces/sso/` 文件  
> - Peer Review 修正建议（75+ 分析文档，~79,000 行；方向③正交修正；5 项深化的洞见）  
> **方法：** 逐方向 grep 核验 → 工程依赖推演 → 任务粒度可执行分解 → 风险矩阵 → 分阶段实施计划  

---

## 目录

1. [方向优先级重评估](#1-方向优先级重评估)
2. [任务分解](#2-任务分解)
3. [执行顺序与并行任务组](#3-执行顺序与并行任务组)
4. [技术风险评估](#4-技术风险评估)
5. [资源评估与里程碑](#5-资源评估与里程碑)
6. [质量保证策略](#6-质量保证策略)
7. [分阶段实施计划](#7-分阶段实施计划)
8. [对 Peer Review 建议的逐项裁决](#8-对-peer-review-建议的逐项裁决)

---

## 1. 方向优先级重评估

### 原始优先级（来自原始分析，Peer Review 修正）

```
原始：
P0 │ 方向② Conformance Suite           ← 架构核心承诺的技术债务
P1 │ 方向① 组合交互测试                ← 长期演化安全
P1 │ 方向③ 配置面治理                  ← 用户第一印象
P2 │ 方向④ 模块依赖治理                ← 当前14模块尚可
P2 │ 方向⑤ 认知负载降低                ← 持续构建，无截止时间
```

### Tech Lead 调整后优先级

```
P0 │ 方向② Conformance Suite           ← 保持：架构核心承诺，沉没成本最高
P0 │ 方向⑤ 认知负载基础设施             ← 升级：AI agent 主动确认需导航工具
P1 │ 方向① 组合交互测试（阶段一）       ← 保持：组合特征矩阵定义可先于框架
P1 │ 方向③ 配置面治理（阶段一）         ← 升级：与 方向④ 共享 sso-ctl 基础设施
P2 │ 方向④ 模块依赖治理                ← 保持：14模块可管理，但构建时间可优化
   │
   │ 后续阶段：
P2 │ 方向① 阶段二（全矩阵 CI）+ 方向③ 阶段二（模板生成器 + 弃用流程）
P3 │ 方向④ 阶段二（依赖升级预览）+ 方向⑤ 阶段二（语义索引 + 影响分析工具）
```

### 调整理由

| 方向 | 调整 | 理由 |
|------|------|-------|
| **方向⑤** | P2→P0 | Peer Review 中 AI agent 确认："方向⑤ 中强调的 'AI agent 需要导航工具'是真实的痛点。目前每次修改需要手动 read 10-30 个文件才能理解上下文。"2241 文件已超过单人记忆极限。结构化知识图谱（接口→实现映射、依赖关系、修改清单）能大幅降低每次的"认知预热"成本。 |
| **方向③** | P1（阶段一先行） | Peer Review 指出已有 `docs/requirements/expansion-runtime-governance-2026-07-11.md` 的"方向四：配置进化治理"覆盖了配置版本化演化。方向③ 的缺口（文档覆盖率/模板生成/字段互斥验证）是**正交的、更基础的层**。第一阶段（字段扫描器 + 文档覆盖率门禁）工作量仅 M，且与方向④ 的依赖图生成共享 `sso-ctl analyze` 子命令基础设施，边际成本更低。 |
| **方向①** | P1（阶段一先行） | 组合特征矩阵定义（子项1）是纯文档工作，门槛低、价值高。可以在组合测试框架（子项2）之前独立完成。矩阵本身已是团队"心智模型对齐工具"。 |
| **方向④** | P2→保持P2 | 14 个嵌套模块尚可管理。但当模块数增长到 20+（预计 Q4 添加 WebAuthn 等新模块）时，依赖版本一致性门禁（子项2）将成为必须。建议 Q3 先完成依赖关系图生成（子项1）作为基线。 |

### 最终优先级矩阵

```
        高 │ 方向⑤ 认知负载（P0）             方向② Conformance Suite (P0)
           │   AI agent + 新人冷启动             架构核心承诺的技术债务
           │
   价值    │ 方向① 组合测试阶段一（P1）       方向③ 配置治理阶段一（P1）
           │   特征矩阵定义先行                  字段扫描器+文档覆盖率门禁
           │
        低 │ 方向④ 模块治理（P2）              方向①/③/④/⑤ 阶段二（P2-P3）
           │   依赖图生成+版本一致性门禁         全矩阵CI/模板生成器/语义索引
           │
           └──────────────────────────────────────────────
              低                        高
                    实现复杂度（投入工时）
```

---

## 2. 任务分解

### 2.1 方向②：Conformance Suite（P0，架构核心承诺）

**背景：** 项目有五个存储后端（Memory/SQLite/Redis/PostgreSQL/etcd），200+ 个实现。当前仅有 `permissionstest.ConformanceSuite` 一个 conformance suite 和 `facets_conformance_test.go` 和 `auditsink/conformance_test.go` 两个局部 conformance 实例。需要将模式推广到所有核心 Store SPI。

| 任务 ID | 标题 | 涉及文件 | 前置依赖 | 预估工时 | 验收标准 |
|---------|------|---------|---------|---------|---------|
| TASK-100 | `ConformanceSuite[T]` 泛型框架提取 | `test/conformance/suite.go`（新建），`test/conformance/options.go`（新建） | 无 | 4h | 通用 `ConformanceSuite[T any]` 类型：`type ConformanceSuite[T any] struct { Factory func(*testing.T) T; SkipList []string }`；`Run(t)` 执行所有非 skip 的 subtest；支持 `Optional(label string)` 标签标记可选测试；从 `permissionstest.ConformanceSuite` 模式提取，保持向后兼容 |
| TASK-101 | `ClientStore` Conformance Suite | `test/conformance/clientstore.go`（新建） | TASK-100 | 4h | 测试：`Create`/`GetByID` roundtrip、`Update` 字段正确性、`Delete` 后 Get 返回 not found、重复 `Create` 返回错误、`List` 分页正确性、并发 10 goroutine 创建无竞态、`GetByID` 对不存在 ID 返回 sentinel error |
| TASK-102 | `SessionManager` Conformance Suite | `test/conformance/session.go`（新建） | TASK-100 | 3h | 测试：`Create`/`FindByID`/`Delete` roundtrip、`Update` 过期时间、过期 session `FindByID` 返回 not found、并发创建 10 个 session 后 ListByUserID 返回全部、`Delete` 不存在 session 是 no-op |
| TASK-103 | `ConsentStore` Conformance Suite | `test/conformance/consent.go`（新建） | TASK-100 | 3h | 测试：`RecordConsent`/`ListByUser`/`RevokeConsent` roundtrip、撤销后 ListByUser 不包含、重复撤销 no-op、ListByUser 空列表返回空 slice 非 nil、`RevokeConsent` 不存在条目 no-op |
| TASK-104 | `AuthCodeStore` + `RefreshTokenStore`+ `PARStore` Conformance Suites | `test/conformance/authcode.go`，`test/conformance/refreshtoken.go`，`test/conformance/par.go`（新建） | TASK-100 | 5h | AuthCode：`Create`/`Consume`（`DELETE RETURNING` 语义）、已消费 code 再次 Consume 返回错误、过期 code Consume 返回错误；RefreshToken：`Create`/`Consume`（带 `FamilyID` 旋转）、family 重用 → `DeleteFamily` → sentinel error、`Consume` 过期 token 返回错误；PAR：`Store`/`Load`/`Delete` roundtrip、过期 `request_uri` Load 返回错误 |
| TASK-105 | `UserStore` + `TenantStore` Conformance Suites | `test/conformance/user.go`，`test/conformance/tenant.go`（新建） | TASK-100 | 3h | UserStore：`CreateOrUpdate` upsert 语义、`GetByID`/`GetByEmail`/`Exists` roundtrip、删除后 Exists 返回 false、并发 email 唯一性约束；TenantStore：`Create`/`GetByID`/`Update`/`Delete`、`List` 分页 |
| TASK-106 | 后端一致性 CI 工作流 | `.github/workflows/backend-conformance.yml`（新建），`scripts/run-conformance.sh`（新建） | TASK-101~105 | 4h | CI 工作流：运行 `go test -run Conformance ./test/conformance/... -backends=memory,sqlite,postgres,redis`；生成 `docs/backend-conformance-report.md` 摘要（哪些后端通过/跳过/失败）；使用 build matrix 并行运行 |
| TASK-107 | 已知后端行为差异文档 | `docs/backend-differences.md`（新建） | TASK-101~105 | 2h | 记录：SQLite 使用 `DELETE RETURNING` vs memory 使用 map delete（竞态差异）、Redis TTL 过期 vs memory 手动 GC（过期行为差异）、PostgreSQL SERIALIZABLE vs SQLite IMMEDIATE（隔离差异） |

**方向② 总计：** ~28 小时（约 3.5 开发日）

### 2.2 方向⑤：认知负载基础设施（P0，AI agent + 新人冷启动）

**背景：** 2241 个文件、200+ 包、14 模块。当前仅 README + developer-guide + DIRECTORY_MAP。AI agent 明确确认每次修改需手动 read 10-30 文件。需结构化导航工具。

| 任务 ID | 标题 | 涉及文件 | 前置依赖 | 预估工时 | 验收标准 |
|---------|------|---------|---------|---------|---------|
| TASK-500 | 包索引自动生成器（接口→实现映射） | `tools/pkgindex/main.go`（新建），`Makefile`（新增 `docs-index` target） | 无 | 6h | Go 工具扫描所有 `.go` 文件，提取：`package` → `exports[]`（接口/结构体/函数/常量）、`interface` → `implementations[]`（`implements` 断言）、`type` → `usages[]`（引用位置）。输出 `docs/_data/pkgindex.json`。`make docs-index` 一次性运行 < 5s |
| TASK-501 | "如何添加 X" 模板化清单（3 类） | `docs/guides/add-new-oauth-grant.md`，`docs/guides/add-new-storage-backend.md`，`docs/guides/add-new-authenticator.md`（新建） | 无 | 5h | 每份清单是 checkable checklist：OAuth grant checklist（~12 项：bindOAuthParams、DELETE RETURNING、oracle-leak、wire in sso.go、discovery、tokenNoStoreHeaders、setBearerChallenge、audit event、error code、OpenAPI spec）；存储后端 checklist（~8 项：implement interface、conformance suite import、wire in options、config schema、test with race、memory ref impl comparison、backend differences doc）；authenticator checklist（~6 项） |
| TASK-502 | 架构交互可视化图生成器 | `tools/archviz/main.go`（新建） | 无 | 6h | 从 `architecture_layer_test.go` 的 `layerName()` + 实际 `import` 路径生成 Mermaid/D3.js SVG 依赖图；标注层违反（"坏依赖"）；CI 中 `make docs-arch` 自动更新 `docs/architecture/arch-graph.md` |
| TASK-503 | 开发者分等级学习路径 | `docs/guides/learning-path.md`（新建） | TASK-501 | 3h | Level 1（了解项目结构 + run quickstart + 理解核心 SPI 模式）→ Level 2（修改 handler + 添加测试 + 运行 CI 门禁）→ Level 3（添加新特性 + 更新文档 + 创建新包）。每级包含阅读清单 + 实践练习 |
| TASK-504 | AGENTS.md 索引与 cross-reference 生成 | `tools/docref/main.go`（新建），`Makefile`（新增 `docs-ref` target） | 无 | 3h | 扫描 `docs/` 下所有 `.md` 文件，提取标题/`##` 节/`[link](...)`/关键词。生成 `docs/_data/doc-index.json`。`make docs-ref` 运行 < 2s |
| TASK-505 | CLI 快速导航命令：`sso-ctl pkg <name>` | `cmd/sso-ctl/pkg.go`（新建） | TASK-500 | 4h | `sso-ctl pkg oauth` → 显示包信息（位置、暴露的接口、实现、子包、依赖的其他包、被哪些包依赖、文件列表、总行数）；`sso-ctl pkg oauth --graph` → Mermaid 子图；`sso-ctl pkg oauth --json` → JSON（IDE 插件消费） |
| TASK-506 | PR 影响范围自动评论 | `.github/workflows/impact-analysis.yml`（新建），`tools/impact/main.go`（新建） | TASK-500 | 5h | PR 提交时自动运行：`git diff HEAD~1 --name-only` → 分析修改文件 → 基于包索引计算影响范围 → PR 评论："本 PR 修改了 A/B/C 包，可能影响 D/E 包的测试和 F/G 包的文档。建议运行 `make test-affected`。" |

**方向⑤ 总计：** ~32 小时（约 4 开发日）

### 2.3 方向①：组合交互测试（P1，阶段一先行）

**背景：** 50+ 特性组合交互空间 > 2^50，当前无任何跨特性组合测试。但 Peer Review 指出可复用 `test/testkit` 和 `chaos/` 目录。

| 任务 ID | 标题 | 涉及文件 | 前置依赖 | 预估工时 | 验收标准 |
|---------|------|---------|---------|---------|---------|
| TASK-010 | 高影响特性清单 + 组合矩阵定义 | `docs/combinatorial-matrix.md`（新建） | 无 | 4h | 从 50+ 特性中选出 15-20 个高影响特性（DPoP、mTLS、Token Exchange、CIBA、Device Code、SAML IdP、SCIM、CAEP、Federation、Conditional Access、Region、Session Quota、Audit、Token Policy、MFA、WebAuthn、Workload Identity、Cross-Tenant、JAR、PAR）。生成 20 个高价值 3-5 特性组合场景。每组合附带：涉及特性、预期行为、风险等级 |
| TASK-011 | 组合测试运行器 — 扩展 `test/testkit` | `test/testkit/combinatorial.go`（新建） | TASK-010 | 6h | `CombinatorialTestRunner`：接收 feature gate 配置（`map[string]bool`）+ 测试函数；调用 `sso.WithFeatureGate` 开/关特性；每个组合场景是一个 `t.Run` 子测试；使用 `build tags` 或环境变量控制特性启用 |
| TASK-012 | 5 个最高优先级组合场景测试 | `test/combinatorial/cases_test.go`（新建） | TASK-011 | 6h | 场景1：DPoP + Token Exchange + Cross-Tenant（验证 cnf 传播 + 跨租户令牌正确性）；场景2：SAML IdP-initiated + MFA + Conditional Access（MFA step-up + 条件访问评估）；场景3：CIBA + WebAuthn + Audit（推送认证 + 设备签名 + 审计事件链）；场景4：Federation + DCR + Token Policy（信任解析 + 自动注册 + 策略应用）；场景5：Workload Identity + Token Exchange + act 链（workload 认证 + act 传播） |
| TASK-013 | 组合测试 CI 门禁 | `.github/workflows/combinatorial-ci.yml`（新建），`scripts/run-combinatorial.sh`（新建） | TASK-012 | 3h | PR CI 中运行 5 个核心组合场景（不阻塞 PR 合并）；每周全量矩阵运行一次；结果发布到 `docs/combinatorial-test-report.md`；超时配置：单场景 timeout=2m |
| TASK-014 | 特性交互影响矩阵文档 | `docs/feature-interaction-matrix.md`（新建） | TASK-010 | 3h | 交互影响矩阵（每对 + 每三特性组合的已知交互：兼容/冲突/需要特殊配置/未测试）。新特性 PR 必须更新此矩阵的关联行 |
| TASK-015 | 增量特性交互提醒脚本 | `scripts/check-feature-interaction.sh`（新建） | TASK-010 | 2h | PR CI 脚本：`git diff HEAD~1 --name-only` → 匹配特性代码目录模式 → 自动评论："此 PR 修改了 SAML 相关代码，建议确认组合测试场景 #2 (SAML+MFA+ConditionalAccess) 是否通过" |

**方向① 总计：** ~24 小时（约 3 开发日）

### 2.4 方向③：配置面治理（P1，阶段一先行）

**背景：** YAML 配置系统存在但无文档覆盖率检查、模板生成器、互斥验证。Peer Review 指出已有 `expansion-runtime-governance` 的配置版本化演化分析（正交层面）。方向③ 聚焦更基础的完整性治理。

| 任务 ID | 标题 | 涉及文件 | 前置依赖 | 预估工时 | 验收标准 |
|---------|------|---------|---------|---------|---------|
| TASK-300 | Config 字段扫描器（扩展 `sso-ctl`） | `cmd/sso-ctl/configscan.go`（新建），`tools/configscan/scanner.go`（新建） | 无 | 5h | 扫描 `config/config.go` 和所有 `options*.go`，提取每个配置字段：name、type、default、tags、doc comment。输出 JSON 清单（`docs/_data/config-fields.json`）。通过 `sso-ctl config scan` 访问 |
| TASK-301 | 文档覆盖率 CI 门禁 | `scripts/check-config-docs.sh`（新建），`.github/workflows/config-docs-check.yml`（新建） | TASK-300 | 3h | CI 中运行扫描器 → 对比 `docs/config-reference.md` 中记录的配置项 → 未记录的项使 CI 失败（黄色告警而非硬阻断）。新配置项必须伴随文档更新 |
| TASK-302 | 配置启动验证增强 | `config/validate.go`（新建） | TASK-300 | 4h | 启动时全量验证：互斥项检查（`WithA` + `WithB` → 告警）、依赖项检查（`WithC` 需要 `WithD` → 告警）、值范围检查（`timeout < 0` → error）、零值语义检测（`false` 是关闭还是默认？） |
| TASK-303 | Config YAML 模板生成器 | `cmd/sso-ctl/configtemplate.go`（新建），`tools/configscan/template.go`（新建） | TASK-300 | 4h | 从 Go 结构体 + doc comment 生成完整 YAML 配置文件模板（`docs/config-template.yaml`）。每个字段带有注释（从代码 doc comment 提取）。通过 `sso-ctl config generate-template > docs/config-template.yaml` 访问 |
| TASK-304 | 配置变更兼容性检查 | `scripts/check-config-breaking.sh`（新建） | TASK-300 | 4h | PR CI 脚本：diff 当前 `config-fields.json` vs 主分支版本。如有 breaking change（字段类型变更、默认值变更、字段移除）→ PR 自动评论 + CI 告警。非 breaking change（新增字段、扩展枚举）→ 仅记录 |

**方向③ 总计：** ~20 小时（约 2.5 开发日）

### 2.5 方向④：模块依赖治理（P2，阶段一先行）

**背景：** 14 个嵌套 `go.mod`，无版本一致性检查、无构建时间预算、无模块添加流程。Peer Review 确认当前尚可管理但需基线。

| 任务 ID | 标题 | 涉及文件 | 前置依赖 | 预估工时 | 验收标准 |
|---------|------|---------|---------|---------|---------|
| TASK-400 | 模块依赖关系图生成器（扩展 `sso-ctl`） | `cmd/sso-ctl/modgraph.go`（新建），`tools/modgraph/graph.go`（新建） | 无 | 5h | 解析所有 14 个 `go.mod` → 生成 DAG：每个依赖标注在多少模块中被引用、版本是否一致。输出 Mermaid 图（`docs/architecture/module-deps.md`）+ JSON（`docs/_data/module-deps.json`）。通过 `sso-ctl mod graph` 查看，`sso-ctl mod graph --dot` 输出 Graphviz |
| TASK-401 | 依赖版本一致性 CI 门禁 | `scripts/check-mod-consistency.sh`（新建），`.github/workflows/mod-consistency.yml`（新建） | TASK-400 | 2h | 检查所有模块共享的依赖（如 `golang.org/x/crypto`、`google.golang.org/grpc`）的版本是否一致。不一致 → CI 失败。支持 `exceptions` 列表（有理由的版本差异） |
| TASK-402 | 构建时间预算 + 监控 | `scripts/measure-build-times.sh`（新建） | TASK-400 | 3h | 每周全量构建时间测量（`go build ./...` for each module + `go test ./... -count=1`）。记录到 `docs/build-times.md`。每个模块设软限制（告警）和硬限制（CI 失败）。初始基线从当前构建时间设定 |
| TASK-403 | 模块添加检查清单（更新 CONTRIBUTING） | `CONTRIBUTING.md`（扩展） | TASK-400 | 2h | "添加新模块必做项"：为什么放在嵌套模块而非主模块、依赖集提前审计、构建时间影响评估、与现有模块的 API 边界定义、更新 `module-deps.md` |
| TASK-404 | 最小依赖集文档 | `docs/minimal-dependencies.md`（新建） | TASK-400 | 2h | 记录"零外部依赖"核心构建路径（`CGO_ENABLED=0`，仅主模块）。其他非核心模块按类别分组（KMS/SAML/LDAP/队列），标注可选性。构建者可据此按需裁剪 |

**方向④ 总计：** ~14 小时（约 2 开发日）

### 2.6 阶段二任务（P2-P3）

| 任务 ID | 标题 | 方向 | 前置依赖 | 预估工时 | 验收标准 |
|---------|------|------|---------|---------|---------|
| TASK-016 | 全量组合矩阵 CI（每周） | ① | TASK-013 | 4h | 全量组合矩阵（20 场景）每周运行一次。结果发布到 `docs/combinatorial-test-report.md`。失败自动创建 GitHub Issue |
| TASK-305 | 配置弃用流程 + 退役门禁 | ③ | TASK-300 | 4h | `Deprecated(since, useInstead)` 标签支持。废弃配置项在日志中打印 `WARN`。弃用后 N 个版本正式移除。CI 检查是否到移除时间 |
| TASK-405 | 依赖升级影响预览（Dependabot PR 自动评论） | ④ | TASK-400, TASK-401 | 5h | Dependabot 发 PR → 自动分析依赖受影响模块 → PR 评论："此升级影响 3 模块（A/B/C）。在这 3 模块运行了 conformance suite（全部通过）。" |
| TASK-507 | 语义化代码库搜索索引 + IDE 插件 | ⑤ | TASK-500 | 8h | 从 `pkgindex.json` 生成 `TAGS` 文件（Vim/Emacs）和 `ctags` 兼容索引。VSCode 插件最小版本（`sso-code-navigator`）：包列表、接口→实现跳转、依赖图嵌入 |
| TASK-508 | 影响分析工具：`sso-ctl analyze-change <file>` | ⑤ | TASK-500 | 6h | 基于包索引 + 调用图：分析文件修改可能影响哪些其他包/测试/文档。输出 JSON 报告 + 终端彩色输出 |

**阶段二总计：** ~27 小时（约 3.5 开发日）

---

## 3. 执行顺序与并行任务组

```mermaid
graph TD
    %% ====== 方向②: Conformance Suite (P0) ======
    T100["TASK-100<br/>泛型ConformanceSuite框架<br/>4h"] --> T101["TASK-101<br/>ClientStore Conformance<br/>4h"]
    T100 --> T102["TASK-102<br/>SessionManager Conformance<br/>3h"]
    T100 --> T103["TASK-103<br/>ConsentStore Conformance<br/>3h"]
    T100 --> T104["TASK-104<br/>AuthCode/Refresh/PAR Conformance<br/>5h"]
    T100 --> T105["TASK-105<br/>User/TenantStore Conformance<br/>3h"]
    T101 --> T106["TASK-106<br/>后端一致性CI工作流<br/>4h"]
    T102 --> T106
    T103 --> T106
    T104 --> T106
    T105 --> T106
    T106 --> T107["TASK-107<br/>后端差异文档<br/>2h"]

    %% ====== 方向⑤: 认知负载 (P0) ======
    T500["TASK-500<br/>包索引自动生成器<br/>6h"] --> T501["TASK-501<br/>'如何添加X'模板清单<br/>5h"]
    T500 --> T502["TASK-502<br/>架构可视化图生成器<br/>6h"]
    T500 --> T505["TASK-505<br/>sso-ctl pkg 导航命令<br/>4h"]
    T500 --> T506["TASK-506<br/>PR影响范围自动评论<br/>5h"]
    T504["TASK-504<br/>文档交叉引用索引<br/>3h"] --> T501
    T501 --> T503["TASK-503<br/>学习路径文档<br/>3h"]

    %% ====== 方向①: 组合测试 (P1, 阶段一) ======
    T010["TASK-010<br/>特性矩阵定义<br/>4h"] --> T011["TASK-011<br/>组合测试运行器<br/>6h"]
    T010 --> T014["TASK-014<br/>交互影响矩阵文档<br/>3h"]
    T010 --> T015["TASK-015<br/>增量交互提醒脚本<br/>2h"]
    T011 --> T012["TASK-012<br/>5个核心组合场景<br/>6h"]
    T012 --> T013["TASK-013<br/>组合测试CI门禁<br/>3h"]

    %% ====== 方向③: 配置治理 (P1, 阶段一) ======
    T300["TASK-300<br/>Config字段扫描器<br/>5h"] --> T301["TASK-301<br/>文档覆盖率CI门禁<br/>3h"]
    T300 --> T302["TASK-302<br/>配置启动验证增强<br/>4h"]
    T300 --> T303["TASK-303<br/>Config模板生成器<br/>4h"]
    T300 --> T304["TASK-304<br/>配置变更兼容性检查<br/>4h"]

    %% ====== 方向④: 模块治理 (P2, 阶段一) ======
    T400["TASK-400<br/>模块依赖图生成器<br/>5h"] --> T401["TASK-401<br/>版本一致性CI门禁<br/>2h"]
    T400 --> T402["TASK-402<br/>构建时间预算监控<br/>3h"]
    T400 --> T403["TASK-403<br/>模块添加检查清单<br/>2h"]
    T400 --> T404["TASK-404<br/>最小依赖集文档<br/>2h"]

    %% ====== 跨方向依赖 ======
    T300 -.-> T010["(Config字段也是特性交互的一维)"]
    T400 -.-> T500["(模块依赖图→包索引数据源)"]
    T100 -.-> T101~105["(Conformance是后端互换性保障)"]

    %% ====== 阶段二 ======
    T013 --> T016["TASK-016<br/>全量组合矩阵CI<br/>4h"]
    T300 --> T305["TASK-305<br/>配置弃用流程<br/>4h"]
    T400 --> T405["TASK-405<br/>依赖升级预览<br/>5h"]
    T500 --> T507["TASK-507<br/>语义搜索索引+IDE插件<br/>8h"]
    T500 --> T508["TASK-508<br/>影响分析工具<br/>6h"]

    %% ====== 并行组标注 ======
    subgraph Parallel_A["并行组 A — Conformance 基建"]
        T100
    end

    subgraph Parallel_B["并行组 B — 认知负载基建"]
        T500
        T504
    end

    subgraph Parallel_C["并行组 C — 配置+模块扫描器"]
        T300
        T400
    end

    subgraph Parallel_D["并行组 D — 组合测试定义"]
        T010
    end
```

### 可并行执行的任务组

| 并行组 | 包含任务 | 说明 |
|--------|---------|------|
| **A（Conformance）** | TASK-100（框架），TASK-101~105（Store suites） | 框架定稿后，5 个 Store suite 可并行实现（不同开发者各 1-2 个） |
| **B（认知负载）** | TASK-500（包索引），TASK-504（文档索引） | 两个索引生成器可并行开发；TASK-501/502/505 依赖 TASK-500 |
| **C（扫描器）** | TASK-300（Config 扫描器），TASK-400（模块依赖图） | 共享 `sso-ctl analyze` 基础设施；可合并为同一个 CLI 子命令 |
| **D（组合测试）** | TASK-010（矩阵定义），TASK-014（交互文档），TASK-015（提醒脚本） | 纯文档 + 脚本工作，无代码依赖，可并行 |
| **E（阶段二）** | TASK-016/305/405/507/508 | 依赖各自阶段一完成后启动 |

---

## 4. 技术风险评估

### 4.1 分方向风险矩阵

| 方向 | 风险 | 等级 | 缓解策略 |
|------|------|------|---------|
| **②** | 泛型 `ConformanceSuite[T]` 可能导致 Go 1.18+ 兼容性问题（项目 Go 版本约束） | **低** | 验证项目 Go 版本 ≥ 1.21（泛型稳定）；如果使用 1.18，避免 `interface` 约束中的类型参数嵌套 |
| **②** | 某些后端的 conformance suite 可能暴露设计差异（如 Redis 不支持 `ListByUser` 查询） | **高** | Conformance suite 使用 `Optional(label)` 标签区分核心 vs 可选行为。Redis 后端的查询限制提前在 `backend-differences.md` 文档化 |
| **②** | `DELETE RETURNING` 在 SQLite 和 PostgreSQL 中原子性一致，但 Redis 的 Lua script 实现可能行为不同 | **中** | Conformance suite 的 `Consume` 测试必须同时验证**数据删除 + 返回**原子性。Redis 实现使用 EVALSHA 确保原子性 |
| **⑤** | 包索引生成器可能成为性能瓶颈（2241 文件全量扫描 > 30s） | **中** | 使用并发扫描（`filepath.Walk` + `sync.Worker` pool）；增量模式（只扫描 git diff 的文件）；CI 中运行 `make docs-index` 结果缓存 |
| **⑤** | PR 影响分析评论可能误报（静态分析的高确信度 vs 低确信度） | **中** | 区分"确定影响"（直接 import 链）和"可能影响"（间接依赖）；高确信度用 `⚠️`，低确信度用 `💡` 前缀 |
| **①** | 组合测试的执行时间可能膨胀到不可接受（5 个核心场景 × 2m = 10m CI 时间） | **中** | 单场景 timeout=2m；CI 中运行 5 个核心场景（不阻塞 PR）；全量矩阵每周运行一次（非阻塞） |
| **①** | 组合测试结果的不稳定性（竞态条件导致 flaky test） | **中** | 每个组合场景至少 3 次重试才标记失败；flaky test 自动创建 GitHub Issue 但不阻塞 PR |
| **③** | `config.go` 文件行数可能接近 500 行限制 | **中** | 在修改前检查行数；如果 > 480，先拆分到 `config/` 子包（`config/config.go` + `config/options.go` + `config/validate.go`） |
| **③** | 配置模板生成器可能无法完整保留 doc comment 的格式（Markdown 在 struct tag 中被截断） | **低** | 使用 `go/doc` 包的 AST 注释解析，而非 struct tag；`//` 注释直接映射为 YAML 的 `#` 注释 |
| **④** | `go mod tidy` 在某些嵌套模块上可能选择不兼容的传递依赖版本 | **中** | CI 中增加 `mod-tidy-all` 检查：所有模块的 `go mod tidy` 结果与仓库一致；不一致则 CI 失败 |

### 4.2 技术难点

| 难点 | 涉及方向 | 解决方案 |
|------|---------|---------|
| Go 泛型 `ConformanceSuite[T]` 中 `T` 约束为 Store 接口时的方法签名一致性 | ② | `Suite[T any]` + `Run(t, func(T))` 模式，不约束 T 为一个特定接口（允许多个 Store 接口共享同一个 Suite 类型） |
| 组合测试中 `feature gate` 的动态开关 | ① | `CombinatorialTestRunner` 在 `TestMain` 中设置全局变量；每个 feature gate 通过 `sso.WithFeatureGate` Server 选项控制；不修改全局状态的 gate 通过 `go test -tags` 控制 |
| 包索引生成器的准确度（Go 的 `implements` 关系推断） | ⑤ | 编译期接口断言的运行时反射 + AST 静态分析双验证；`var _ Interface = (*Impl)(nil)` 模式是 Go 标准做法，AST 解析精确度 > 99% |
| `sso-ctl` 子命令的合并（configscan + modgraph + pkg） | ③④⑤ | 统一使用 `sso-ctl analyze` 命名空间：`sso-ctl analyze config`、`sso-ctl analyze mod`、`sso-ctl analyze pkg`、`sso-ctl analyze change <file>` |

### 4.3 外部依赖风险

| 依赖 | 风险 | 影响方向 | 缓解 |
|------|------|---------|------|
| Go 标准库 `go/parser` + `go/types` | 包索引生成器依赖 AST 解析，Go 语言版本更新可能引入语法变化 | ⑤ | 使用 `go/parser` 的 `AllErrors` 模式确保兼容性；CI 中针对 Go 1.21/1.22/1.23 测试索引生成 |
| `go mod graph` 内部命令 | 模块依赖图生成依赖 `go mod graph` 输出格式，Go 团队可能改变输出格式 | ④ | `go mod graph` 输出格式已稳定 ~10 年；使用 `golang.org/x/mod/modfile` 库解析 `go.mod`（官方维护，版本稳定） |

### 4.4 性能风险

| 场景 | 风险 | 数据 | 优化策略 |
|------|------|------|---------|
| 全量包索引生成 | 2241 文件 AST 扫描 | < 5s（并发扫描，8 核） | `filepath.Walk` + `sync.Worker`（每个 worker 处理一个文件）；跳过 `vendor/` 和 `testdata/` |
| 组合测试全量矩阵 | 20 场景 × 2m = 40m 运行时间 | 40m（每周一次，可接受） | 运行时并行（`t.Parallel`）；核心 5 场景在 PR CI 中运行；全量矩阵仅 nightly |
| Config 字段扫描器 | 50+ 配置结构体 AST 扫描 | < 1s | 单次扫描，无性能问题 |

---

## 5. 资源评估与里程碑

### 5.1 人员需求

| 角色 | 所需技能 | 数量 | 主要负责方向 |
|------|---------|------|-------------|
| **Platform Go 工程师** | Go 泛型、测试模式、CI 编排、存储后端知识 | 1 人 | 方向② Conformance Suite（框架 + 6 个 Store suites + CI 工作流） |
| **Tooling Go 工程师** | `go/parser`、AST 分析、CLI 工具设计、静态分析 | 1 人 | 方向⑤ 认知负载（包索引、架构可视化、PR 影响分析） **+** 方向③ 配置扫描器 **+** 方向④ 模块依赖图 |
| **测试/质量工程师** | 特性组合矩阵设计、混沌测试、E2E 测试模式 | 1 人 | 方向① 组合测试（特征矩阵、组合运行器、5 个核心场景、交互矩阵文档） |

**建议最小团队：2 人**（1 Platform + 1 Tooling）  
- **冲刺 1-2**：Platform 完成 方向②；Tooling 完成 方向⑤（包索引 + 文档清单）+ 方向③（Config 扫描器）  
- **冲刺 3-4**：Platform 完成 方向①（组合测试）；Tooling 完成 方向④（模块图）+ 方向⑤（PR 影响分析）  

**优化配置：3 人**（各 1 人），6-8 周完成所有阶段一

### 5.2 关键里程碑

```
Week 1-2  │ 方向② Conformance 框架 + ClientStore/SessionManager suites ✅
          │ 方向⑤ 包索引生成器 + "如何添加X"模板清单 ✅
          │ 方向③ Config 字段扫描器 + 文档覆盖率门禁 ✅
          ──── 里程碑 1：核心基础设施就绪 ────

Week 3-4  │ 方向② 剩余 4 个 Store suites + CI 工作流 ✅
          │ 方向⑤ 架构可视化 + sso-ctl pkg 命令 + PR 影响分析 ✅
          │ 方向① 组合特征矩阵 + 组合测试运行器 ✅
          ──── 里程碑 2：工具链可工作 ────

Week 5-6  │ 方向① 5 个核心组合场景 + CI 门禁 ✅
          │ 方向③ 配置启动验证 + YAML 模板生成器 + 兼容性检查 ✅
          │ 方向④ 模块依赖图 + 版本一致性门禁 ✅
          ──── 里程碑 3：所有方向阶段一交付 ────

Week 7-8  │ 方向② 后端差异文档 ✅
          │ 方向⑤ 学习路径文档 ✅
          │ 方向④ 构建时间预算 + 模块添加清单 + 最小依赖集文档 ✅
          ──── 里程碑 4：完整阶段一收尾 ────
```

### 5.3 阻塞点（Blockers）与解决策略

| 阻塞点 | 影响方向 | 解决策略 |
|--------|---------|---------|
| `core/spi.go` 文件行数（接近 500 行）可能在添加 Conformance Suite 的 SPI 扩展时超限 | ② | 拆分为 `core/spi.go`（核心 SPI）+ `core/store_interfaces.go`（Store 接口） |
| Go 版本兼容性：泛型 `ConformanceSuite[T]` 需要 Go 1.18+；但如果项目使用更早版本 | ② | 确认项目 Go 版本。如果 < 1.18，使用 `interface{}` + 类型断言替代泛型（但失去编译期类型安全） |
| `sso-ctl` 当前子命令较少，但本计划建议新增 4 个子命令（config scan、config template、mod graph、pkg） | ③④⑤ | 统一使用 `sso-ctl analyze` 命名空间；子命令之间共享 `go/parser` 基础设施包（`tools/analyze/`） |
| 组合测试的 feature gate 系统可能不存在（需要新建 "feature flag" 注入机制） | ① | 验证 `sso.WithFeatureGate` 是否存在；如果不存在，先实现最小 feature flag 系统（`map[string]bool` + Server 选项） |

---

## 6. 质量保证策略

### 6.1 单元测试覆盖

| 任务 | 测试要求 | 覆盖率目标 |
|------|---------|-----------|
| TASK-100 `ConformanceSuite[T]` 框架 | 泛型类型正确实例化、`Factory` nil panic、`SkipList` 过滤、`Optional` 标签跳过 | 100% |
| TASK-101~105 Store Conformance suites | 每个 suite 的每个 subtest 都应通过至少一个后端实现（memory 作为参考实现） | 100%（suite 本身，非后端） |
| TASK-500 包索引生成器 | 扫描已知 Go 文件 → 验证输出 JSON 正确包含 interfaces/implementations/functions/consts | 95%+ |
| TASK-505 `sso-ctl pkg` 命令 | 对已知包名输出正确路径、行数、依赖列表；`--json` 输出格式正确 | 95%+ |
| TASK-300 Config 字段扫描器 | 扫描已知 config struct → 输出字段列表匹配预期 | 100% |
| TASK-400 模块依赖图生成器 | 解析已知 `go.mod` 文件 → 输出 DAG 正确 | 100% |
| TASK-011 组合测试运行器 | 验证 feature gate on/off 能正确开启/关闭特性；门禁逻辑正确 | 90%+ |
| TASK-302 配置启动验证 | 互斥项检测、依赖项检测、值范围检测各自正确触发 | 100% |

### 6.2 集成测试策略

| 测试场景 | 范围 | 策略 |
|---------|------|------|
| **Conformance Suite 端到端** | 方向② | 对 `memory` 后端运行所有 6 个 Conformance Suite。作为 CI 基线（确保 conformance suite 本身正确） |
| **包索引端到端** | 方向⑤ | 在 CI 中运行 `make docs-index` → 验证 `docs/_data/pkgindex.json` 生成成功 → 验证 JSON schema 合规 |
| **Config 扫描器端到端** | 方向③ | 在 CI 中运行 `sso-ctl config scan` → 验证 `docs/_data/config-fields.json` 生成 → 验证文件不为空 |
| **模块图端到端** | 方向④ | 在 CI 中运行 `sso-ctl mod graph` → 验证 `docs/architecture/module-deps.md` 生成 → 验证 Mermaid 图包含所有 14 模块 |
| **组合测试 CI 端到端** | 方向① | 运行 `scripts/run-combinatorial.sh --ci` → 验证 5 个核心场景全部通过 → 验证 `docs/combinatorial-test-report.md` 生成 |

### 6.3 代码审查要点

| 方向 | 审查要点 |
|------|---------|
| **所有方向** | 文件 ≤ 500 行、函数 ≤ 50 行、cyclomatic ≤ 15、import 方向正确（向下指向 shared/core） |
| **方向②** | Conformance Suite 的 `Factory` 每个 subtest 返回新实例（非共享状态）；`Optional` 标签文档化原因；泛型签名不退化 |
| **方向⑤** | 包索引生成器跳过 `vendor/` 和 `generated/` 目录；`sso-ctl pkg` 输出不暴露内部路径；模板化清单的步骤可验证 |
| **方向①** | 组合场景选择理由充分、预期行为文档化、组合测试不依赖外部服务（mock 所有依赖）；CI 门禁非阻塞但显式 |
| **方向③** | 扫描器不泄露敏感配置值（密码 / secret）；模板生成器不将代码注释中的 URL/token 写入 YAML 模板 |
| **方向④** | 依赖版本一致性检查的 `exceptions` 列表有注释解释原因；构建时间预算合理（初始基线 + 20% 缓冲） |

### 6.4 性能测试需求

| 场景 | 测试工具 | 阈值 | 触发条件 |
|------|---------|------|---------|
| 包索引生成器全量扫描 | Go benchmark | 总时间 < 10s | 2241 文件 + 8 核 CPU |
| Config 字段扫描器 | Go benchmark | 总时间 < 2s | 50+ 配置结构体 |
| 模块依赖图生成 | Go benchmark | 总时间 < 3s | 14 go.mod + 100+ 第三方依赖 |
| 组合测试核心 5 场景 | `-count=3 -timeout=15m` | 全部通过无 flaky | CI 中每次提交 |
| `sso-ctl pkg oauth` 响应时间 | manual | < 500ms | 含 JSON 输出 |

---

## 7. 分阶段实施计划

### 阶段 1：核心基础设施就绪（第 1-2 周）

```
Week 1                  │ Week 2
────────────────────────┼────────────────────────
TASK-100 Conformance框架 │ TASK-101 ClientStore Suite
TASK-500 包索引生成器    │ TASK-102 SessionManager Suite
TASK-504 文档交叉引用    │ TASK-105 User/Tenant Suite
TASK-300 Config扫描器   │ TASK-501 "如何添加X"清单
TASK-400 模块依赖图      │ TASK-301 文档覆盖率门禁
                        │ TASK-401 版本一致性门禁
```

**交付物：**
- `test/conformance/suite.go` — 泛型 ConformanceSuite 框架 ✅
- `test/conformance/clientstore.go` + `session.go` + `user.go` + `tenant.go` — 4 个 Store Conformance Suites ✅
- `tools/pkgindex/main.go` — 包索引自动生成器 ✅
- `tools/docref/main.go` — 文档交叉引用索引 ✅
- `cmd/sso-ctl/configscan.go` — Config 字段扫描器 ✅
- `cmd/sso-ctl/modgraph.go` — 模块依赖图生成器 ✅
- `docs/guides/add-new-oauth-grant.md` + `add-new-storage-backend.md` + `add-new-authenticator.md` ✅
- `.github/workflows/config-docs-check.yml` — 文档覆盖率门禁 ✅
- `.github/workflows/mod-consistency.yml` — 版本一致性门禁 ✅

**门禁：** `go build ./...` + `go vet ./...` + `go test ./... -race -count=3` + `python cli.py check` 全部通过

### 阶段 2：工具链可工作（第 3-4 周）

```
Week 3                  │ Week 4
────────────────────────┼────────────────────────
TASK-103 ConsentSuite   │ TASK-106 后端一致性CI
TASK-104 AuthCode/Refr. │ TASK-107 后端差异文档
TASK-502 架构可视化     │ TASK-505 sso-ctl pkg
TASK-010 特征矩阵定义   │ TASK-011 组合测试运行器
TASK-302 启动验证增强   │ TASK-303 Config模板生成器
TASK-402 构建时间预算   │ TASK-014 交互矩阵文档
```

**交付物：**
- `test/conformance/consent.go` + `authcode.go` + `refreshtoken.go` + `par.go` — 剩余 4 个 Store Suites ✅
- `.github/workflows/backend-conformance.yml` — 后端一致性 CI 工作流 ✅
- `docs/backend-differences.md` — 已知后端行为差异文档 ✅
- `tools/archviz/main.go` — 架构交互可视化图生成器 ✅
- `cmd/sso-ctl/pkg.go` — `sso-ctl pkg <name>` 导航命令 ✅
- `docs/combinatorial-matrix.md` — 高影响特性清单 + 20 个组合场景 ✅
- `test/testkit/combinatorial.go` — 组合测试运行器 ✅
- `config/validate.go` — 配置启动验证增强 ✅
- `cmd/sso-ctl/configtemplate.go` — YAML 模板生成器 ✅
- `docs/feature-interaction-matrix.md` — 特性交互影响矩阵 ✅

**门禁：** `go test -run 'TestMaintainability_|TestArchitecture_' ./...` + `python cli.py accept` 全部通过

### 阶段 3：所有方向阶段一交付（第 5-6 周）

```
Week 5                  │ Week 6
────────────────────────┼────────────────────────
TASK-012 5个核心组合场景 │ TASK-013 组合测试CI门禁
TASK-304 配置兼容性检查  │ TASK-015 增量交互提醒脚本
TASK-403 模块添加清单   │ TASK-404 最小依赖集文档
TASK-503 学习路径文档   │ TASK-506 PR影响分析评论
```

**交付物：**
- `test/combinatorial/cases_test.go` — 5 个核心组合场景测试 ✅
- `.github/workflows/combinatorial-ci.yml` — 组合测试 CI 门禁 ✅
- `scripts/check-feature-interaction.sh` — 增量交互提醒脚本 ✅
- `scripts/check-config-breaking.sh` — 配置变更兼容性检查 ✅
- `CONTRIBUTING.md`（扩展）— 模块添加检查清单 ✅
- `docs/minimal-dependencies.md` — 最小依赖集文档 ✅
- `docs/guides/learning-path.md` — 开发者分等级学习路径 ✅
- `.github/workflows/impact-analysis.yml` — PR 影响范围自动评论 ✅

**门禁：** `make ci` + `make acceptance` + `python cli.py harness` 全部通过

### 阶段 4：阶段二增强（第 7-8 周，可选）

```
Week 7                  │ Week 8
────────────────────────┼────────────────────────
TASK-016 全量组合矩阵CI  │ TASK-507 语义搜索索引
TASK-305 配置弃用流程    │ TASK-508 影响分析工具
TASK-405 依赖升级预览    │
```

**交付物：**
- 全量组合矩阵每周运行 ✅
- 配置弃用 `Deprecated` 标签 + 退役门禁 ✅
- Dependabot PR 自动依赖影响评论 ✅
- 语义搜索索引（TAGS + ctags + VSCode 插件 MVP） ✅
- `sso-ctl analyze-change <file>` 影响分析工具 ✅

**门禁：** `make acceptance` + `python cli.py harness` 全部通过

### 总体工作量估算

| 阶段 | 内容 | 总工时 | 开发日（8h/天） | 2 人团队 | 3 人团队 |
|------|------|-------|----------------|---------|---------|
| 阶段 1 | 核心基础设施 | ~38h | ~5 天 | ~2.5 周 | ~1.5 周 |
| 阶段 2 | 工具链可工作 | ~48h | ~6 天 | ~3 周 | ~2 周 |
| 阶段 3 | 阶段一交付 | ~28h | ~3.5 天 | ~2 周 | ~1.5 周 |
| 阶段 4 | 阶段二增强（可选） | ~27h | ~3.5 天 | ~2 周 | ~1.5 周 |
| **阶段 1-3 总计** | | **~114h** | **~14 天** | **~7-8 周** | **~5 周** |
| **全部（含阶段二）** | | **~141h** | **~18 天** | **~9-10 周** | **~6-7 周** |

**推荐策略：** 2 人团队（1 Platform + 1 Tooling），按阶段顺序推进。方向② 和方向⑤ 互为独立，可完全并行。

---

## 8. 对 Peer Review 建议的逐项裁决

| # | 建议 | 裁决 | 处理方式 |
|---|------|------|---------|
| R1 | 方向⑤ 应为 P1 而非 P2（AI agent 确认需要导航工具） | **采纳 → P0** | 已在 §1 优先级表中将方向⑤ 升级为 P0。TASK-500/501/502/504 为冲刺 1 任务 |
| R2 | 方向③ "0 命中" 声明应修正为"正交" | **采纳** | 已在 §1 修正说明中澄清。方向③ 与已有配置版本化演化分析（`expansion-runtime-governance` 方向四）正交——前者聚焦文档完整性/模板/互斥验证，后者聚焦版本化迁移 |
| R3 | 引用 `test/testkit` 扩展而非新建组合测试框架 | **采纳** | 方向① TASK-011 明确扩展到 `test/testkit/combinatorial.go`，复用现有 `testkit.Harness` 基础设施 |
| R4 | 引用 `permissionstest.ConformanceSuite` + `facets_conformance_test` 作为双参考 | **采纳** | 方向② TASK-100 从 `permissionstest.ConformanceSuite` 提取泛型框架，参考 `facets_conformance_test` 的 `Optional` 标签模式 |
| R5 | 方向③ 和方向④ 共享 `sso-ctl analyze` 子命令 | **采纳** | 所有扫描器统一到 `sso-ctl analyze` 命名空间。§4.2 中已记录此架构决策 |
| R6 | 分析文档数量修正为 75+ 份（~79,000 行） | **采纳** | 已在本文档全文使用修正数据。原始分析的 46+ 份估算是基于早期的分析轮次计数 |

### 未采纳建议说明

所有 6 项 Peer Review 建议均已采纳。未采纳项：无。

---

*本报告将 5 个元治理方向分解为 32 个可执行任务（含阶段二 5 个任务），总计 ~141 工时。*
*这些方向不增加对外可见的功能特性，但决定了项目在 2241 文件 + 14 模块规模下*
*能否保持可持续的演化速度、代码质量和开发者信心。*
