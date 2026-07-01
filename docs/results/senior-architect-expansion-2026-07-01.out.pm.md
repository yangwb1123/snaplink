现在我对项目有了一个清晰的了解。让我来写出产品管理分析。

---

# 产品经理分析报告：Snaplink SSO 五个改进方向

## 1. 需求梳理

### 1.1 核心用户群体及使用场景

| 用户画像 | 典型组织 | 痛点与现有差距 |
|---------|---------|--------------|
| **平台工程负责人** | 用 Go 嵌入 SSO SDK 的中等规模 SaaS 公司（12-50 人工程团队） | 配置错误在部署后才发现，缺少 schema 校验；基准性能退化在合并后才暴露 |
| **安全/合规工程师** | 需要 SOC 2 / FedRAMP / FISMA 合规的组织 | 缺少 CSP 使 SPA 暴露在 XSS 之下；异步追踪断裂导致安全审计难以根因分析；FIPS 缺位阻断政府市场 |
| **运维/SRE 工程师** | 通过 `sso-ctl` 和 GitOps 流水线运营 SSO 的组织 | CI 验证层不够（运行时配置验证 + schema 校验）；缺少基准预算门槛；链路追踪缺失导致事故排查慢 |
| **SPA 前端开发者** | 在 React / Vue / Angular 应用中嵌入 SSO 登录的组织 | 嵌入式登录门户缺少现代安全头；form_post 响应模式在 CSP 严格模式下失败 |
| **托管服务提供商** | 为其客户（租户）共同管理 SSO 实例的组织 | 多租户安全边界亟需 CSP + FIPS + 可审计追踪能力 |

### 1.2 关键功能需求

#### 方向一：CSP 与 Web 安全头治理（Must Have — 快速见效，高安全影响）

- **FR-01**：为三个嵌入式 SPA（`admin/`、`login/`、`portal/`）+ form_post 模式页面注入 HTTP 安全头（`Content-Security-Policy`、`Permissions-Policy`、`Referrer-Policy`、`Clear-Site-Data`）
- **FR-02**：安全的 `form_post.html` 渲染——在服务器端植入 per-response nonce，以允许内联脚本，无需 `unsafe-inline`
- **FR-03**：Report-Only 模式，通过可配置的数据收集窗口，过渡到 Enforce 模式
- **FR-04**：中间件框架，实现对 `handler.go` 中所有端点一致的头部添加（复用现有的中间件模式）
- **FR-05**：可导出的安全头策略文档（机器可读格式，用于 SOC 2 审计证据）

#### 方向二：声明式配置 Schema 与 GitOps 验证（Should Have — 防止静默故障）

- **FR-06**：从 Go 结构体标签自动生成 JSON Schema（`yaml:"server"` → `"$ref": "#/$defs/ServerConfig"`）
- **FR-07**：自定义 Go 验证器注册表，用于 JSON Schema 无法表达的约束（跨字段互斥、环境覆盖优先级、版本迁移模式）
- **FR-08**：`--validate-only --schema-only` 模式——轻量级 YAML 解析 + schema 校验 + Go 验证链，无数据库/审计/运行时开销
- **FR-09**：CI 集成——每个 PR 的 `make config-validate-all` 步骤（schema 校验，非仅运行时启动）
- **FR-10**：导出配置更改的机器可读变更日志（例如，用于审计的 `config_changed` 事件）

#### 方向三：异步链路追踪完整性（Should Have — 诊断静默故障的最大 ROI）

- **FR-11**：在异步 goroutine（审计 sink、CAEP 推送、集群事件、键轮转处理程序）中传递 OTel span 上下文
- **FR-12**：修复审计的 `TraceContext` 与 OTel span 层次结构之间的断链——要么通过延迟根 span 生命周期（路径 B），要么创建独立的追踪（路径 A）并记录预期行为
- **FR-13**：为异步工作流中最关键的缺失路径添加仪表化：审计批量写入、CAEP SET 传送、集群事件传播、键轮转后处理
- **FR-14**：用于追踪健康状态的可观测仪表板，指示异步路径中哪里存在"孤儿" span

#### 方向四：Benchmark 预算与 CI 集成（Must Have — 基础设施先决条件）

- **FR-15**：机器可读的基准预算文件（`.benchmarks.yaml`），包含 P99 延迟、每操作分配数和每操作纳秒数
- **FR-16**：分层基准运行——**关键**（每个 PR：令牌颁发、内存限速器、Ed25519 签名）与 **扩展**（按计划：SQLite 路径、审计批量写入、刷新族轮转）
- **FR-17**：基准比较 CI 步骤——在 PR 合并之前将当前结果与预算进行比较（不允许退步）
- **FR-18**：基准退化时通过 `sso_benchmark_regression_total` 发出告警指标

#### 方向五：FIPS 140-3 合规构建模式（Won't Have — 市场驱动里程碑）

- **FR-19**：`GOEXPERIMENT=systemcrypto` 构建标签 + `Dockerfile.fips` 基于 Red Hat UBI 或 `golang:1.24-fips-alpine`
- **FR-20**：可配置的允许算法——保守默认值（仅 P-256/P-384），可选 Ed25519 用于更快/更小的签名
- **FR-21**：密码哈希从 bcrypt → PBKDF2-HMAC-SHA256（在 FIPS 构建模式下的 `crypto/sha256` 中运行）
- **FR-22**：文档化的 FIPS 操作模式，包含 CAVP 编号、镜像签名要求和 SCA 扫描覆盖范围
- **FR-23**：FIPS 模式下的 CI 构建（仅构建，不推送）以确保不破坏构建

### 1.3 Must-Have 与 Nice-to-Have 对比

| 分类 | 需求 |
|------|------|
| **Must-Have**（MVP） | CSP 安全头（方向一 Phase 1）· Benchmark 预算关键层（方向四 Phase 1）· `form_post.html` nonce 注入（方向一 Phase 1.5）· 现有 CI 中配置验证的阶段性改进（方向二 Phase 1 的子集） |
| **Should-Have**（下一版） | JSON Schema 自动生成（方向二 Phase 1）· 异步 goroutine 的 OTel span 传递（方向三 Phase 1）· 基准扩展层（方向四 Phase 2）· 报告模式 CSP 策略执行（方向一 Phase 2） |
| **Could-Have**（未来门控） | 自定义 Go 验证器注册表（方向二 Phase 1.5）· 异步追踪健康仪表板（方向三 Phase 2）· 基准退化告警指标（方向三 Phase 3）· CI 中的 CSP 报告聚合 |
| **Won't-Have**（市场驱动） | FIPS 140-3 构建模式——仅在进入 FedRAMP/FISMA 市场时触发 |

---

## 2. 用户故事

### 方向一：CSP 与 Web 安全头

**US-1：SPA 安全头交付**

> **作为** 一名 SSO 服务器实例的**运营者**，**我希望**所有嵌入式 SPA（管理员、登录、门户）在 HTTP 响应中自动包含 `Content-Security-Policy` 和 `Permissions-Policy` 头，**以便**我的用户免受 XSS 和权限滥用的侵害，无需我为每个 SPA 侧单独加固。

**验收标准：**
- 当用户在无 CSP 头的 SPA 上通过旧浏览器访问 `/admin/` 时 → 头被注入到响应中
- 当运营者在 `config.yaml` 中将 `csp.mode: report-only` 设置为开时 → 使用 `Content-Security-Policy-Report-Only` 头，而非 Enforce
- 使用 `curl -I http://sso/admin/index.html` → 响应包含：
  - `Content-Security-Policy: default-src 'self'; script-src 'nonce-{random}'; ...`
  - `Permissions-Policy: camera=(), microphone=(), ...`
  - `Referrer-Policy: no-referrer`
  - `Clear-Site-Data: "cache"`（仅限登出路径）

**US-2：Form-Post Nonce 注入**

> **作为** 一名使用 OIDC form_post 响应模式的**SPA 开发者**，**我希望** `form_post.html` 的非注入机制能生成一次性 nonce，**以便**激活 CSP 时，自动表单提交的 JavaScript 不被阻塞，终端用户获得无缝的 SSO 体验。

**验收标准：**
- 给定 `sso` 通过 `response_mode=form_post` 或 `response_mode=form_post.jwt` 渲染 `form_post.html`
- 当页面在浏览器中加载时
- 那么 `<script nonce="{{ .CSPNonce }}">document.forms[0].submit()</script>` 被渲染出来，并且 nonce 在每个响应中都是唯一的

**US-3：CSP 报告数据分析**

> **作为** 一名**安全工程师**，**我希望**在 `Content-Security-Policy-Report-Only` 模式下运行两周的收集期，**以便**我能在切换到强制执行阻塞违规之前，发现并修复合法的脚本因 CSP 而被错误阻止的情况（假阳性）。

**验收标准：**
- 给定运营者配置 `csp.report_uri: "/api/v1/csp/reports"` 和 `csp.mode: report-only`
- 当来自合法应用的 CSP 报告到来时
- 那么运营者可以通过 `GET /api/v1/csp/reports?since=2w` 查看聚合报告，并在收紧策略之前识别假阳性

### 方向二：配置 Schema 与 GitOps 验证

**US-4：运算符侧配置验证**

> **作为** 一名**平台工程师**，负责在多个环境中维护 7 个 YAML 配置文件，**我希望**在开发时（IDE 中）和 CI 流水线中执行 JSON Schema 验证，**以便**那些本可在提交前捕获的简单错别字、缺失字段和类型错误，不会在凌晨 3 点导致生产部署失败。

**验收标准：**
- 给定一个格式错误的配置文件（例如，`server.listen: 8080`——整数，应为字符串）
- 当运行 `./sso-server --validate-only --schema-only -c config.yaml` 时
- 那么它以非零退出码退出，并显示友好的错误信息："字段 `server.listen`：预期字符串，得到整数"
- 给定一个语义上无效的配置（例如，同时将 SQLite 和 Postgres 设为 `primary`）
- 当运行相同的命令时
- 那么它还捕获跨字段约束："存储后端：SQLite 和 Postgres 不能同时为主要存储"

**US-5：GitOps 流水线门控**

> **作为** 一名**SRE**，负责运营 GitOps 驱动的部署，**我希望**每个 PR 都经过 `make config-validate-all` 步骤（schema 校验 + Go 验证器），**以便**从不正确的配置导致的宕机从一个遥不可及的问题，变为在合并之前就被 gate 阻止的问题。

**验收标准：**
- 给定一个 PR 修改了 `config/dev.yaml`
- 当 CI GitHub Actions 流水线运行时
- 那么 `make config-validate-all` 步骤执行，如果在任何一个 YAML 文件中检测到 schema 或 Go 验证器级别的违规，则构建失败

### 方向三：异步链路追踪

**US-6：审计异步追踪传递**

> **作为** 一名**SRE**，正在调查一个"用户令牌被撤销但集群内第二个 Pod 未收到"的罕见问题，**我希望**审计的异步集群事件发布器能延续 OTel span 上下文，**以便**我能在 Jaeger 或 Grafana 中追踪从"令牌被撤销"到"其他 Pod 收到通知"的完整路径，而无需 grep 十个不同的日志文件。

**验收标准：**
- 给定 `POST /token/revoke-all` 经由集群总线发布 `KindTokenRevoked`
- 当接收者 Pod 处理该事件时
- 那么在 OTel 后端中，存在一个单一的追踪，将原始 HTTP 请求（根 span）连接到接收者的处理代码（子 span）
- 运营者可以在一次追踪视图中可视化完整的异步传播路径

**US-7：孤儿 Span 文档记录**

> **作为** 一名**平台工程师**，计划对审计框架进行性能优化，**我希望**知道审计的异步写入是设计上允许成为孤儿 span，还是需要延迟 HTTP handler 的生命周期，**以便**我了解在流量高峰期间我的追踪图的完整性限制。

**验收标准：**
- 给定 `/docs/observability.md` 中关于追踪的章节
- 当工程师阅读时
- 那么他们看到一个清晰的解释，说明异步审计 span 是否附着在其父 HTTP span 上，或者它们启动独立的追踪，以及每种选择对可观测性的影响

### 方向四：Benchmark 预算与 CI

**US-8：性能退化门控**

> **作为** 一名**后端工程师**，在对 `protocols/oauth` 模块进行重构时，**我希望** CI 流水线能自动将关键路径（令牌颁发、内存限速器、签名）的基准结果与已提交的预算进行比较，**以便**我不会在无意中引入 3 倍的延迟回归，然后在三周后的生产峰值时才发现。

**验收标准：**
- 给定一个 PR 修改了 `protocols/oauth/refresh_token.go`
- 当 CI 运行基准测试时
- 那么如果 `RefreshRotation` 的 P99 超过 15 毫秒或分配超过 30 次/操作，则 `make bench-compare` 步骤失败
- 失败信息包含："基准回归：RefreshRotation P99=18ms（预算：15ms），分配/操作=45（预算：30）"
- 只有在明确的三位评审者一致同意覆盖的情况下，才能添加豁免（与架构测试豁免使用相同的枚举机制）

**US-9：分层基准运行**

> **作为** 一名**基础设施负责人**，关注 CI 成本，**我希望**在 **关键**（每个 PR）和 **扩展**（每日计划）基准测试之间建立明确的层级划分，**以便**开发者在每次提交时都能获得子 2 分钟的快速反馈，而更慢的 SQLite 后端基准测试则单独在夜间运行，不会减慢 CI 速度。

**验收标准：**
- 给定 `.benchmarks.yaml` 文件
- 当运营者查看层级时
- 那么 `critical` 包含 3 个基准测试（令牌颁发、内存限速器、Ed25519 签名），可在于 120 秒内完成
- 那么 `extended` 包含其余 5 个基准测试，计划在 cron 上每 24 小时运行一次

### 方向五：FIPS 140-3 合规

**US-10：FIPS 构建模式**

> **作为** 一名寻求 FedRAMP 认证的**安全工程师**，**我希望**一个 `Dockerfile.fips` 能使用 `GOEXPERIMENT=systemcrypto` 和 Red Hat UBI 基础镜像构建 snaplink SSO，**以便**加密操作（签名、验证、密码哈希）通过 FIPS 140-3 CAVP，我们的 SSO 组件可以包含在 FedRAMP 授权边界内。

**验收标准：**
- 给定一个运行 `docker build -f Dockerfile.fips -t sso:fips .` 的 CI 构建
- 当生成的二进制文件运行时
- 那么它拒绝非 FIPS 算法（`Ed25519` 默认禁用；必须显式启用）
- 那么密码哈希使用 PBKDF2-HMAC-SHA256，在 `crypto/sha256` 的 FIPS 模块内运行
- 那么文档包含 FIPS CAVP 编号列表、镜像签名要求和 SCA 扫描覆盖范围的确认

---

## 3. 边界场景分析

### 3.1 方向一：CSP 与安全头

| 边界场景 | 问题 | 缓解措施 |
|---------|------|---------|
| **内联样式**：SPA 使用 `<style>` 标签或 `style="..."` 属性 | CSP 的 `style-src 'self'` 会阻塞内联样式（旧版 SPA 的常见故障模式） | 配置 `'unsafe-hashes'` 或迁移到外部样式表；在 Report-Only 阶段通过报告数据发现 |
| **第三方脚本**：SPA 嵌入了分析/错误追踪工具（Sentry、DataDog RUM） | 如果 `script-src` 未将它们列入白名单，将被阻止 | 配置 `csp.script_src.append: ["https://*.sentry.io"]`；必须在切换 Enforce 模式之前在 Report-Only 中测试 |
| **Form-Post + CSP 冲突**：`form_post.html` 使用内联脚本进行自动提交 | 如果没有 per-response nonce，CSP 以 `'strict-dynamic'` 会阻塞该脚本 | **FR-02** 以 per-response nonce 渲染它是关键修复 |
| **旧版浏览器**：CSP 头在旧版浏览器中不同 | 示例：IE 的 `X-Content-Security-Policy` | 对于真正关键的安全部署，需要 polyfill 头或仅支持现代浏览器 |
| **API 与 HTML 路径**：CSP 头仅适用于 HTML 页面，而不适用于 JSON API 端点 | 将 `Content-Security-Policy` 应用于 `/token` 等端点是正确但多余的 | 检查中间件中的 `Content-Type`；仅对 `text/html` 页应用 CSP 头 |
| **并发 nonce 碰撞**：在高并发下，`form_post.html` nonce 生成可能产生冲突 | 极不可能（加密随机数生成器），但安全的 fallback 需要重试 | 使用 `crypto/rand` 生成 256 位 nonce 值；碰撞概率可忽略不计 |

### 3.2 方向二：配置 Schema

| 边界场景 | 问题 | 缓解措施 |
|---------|------|---------|
| **环境覆盖改变了语义**：YAML 设置 `audit.backend: sqlite` 被 `SSO_AUDIT__BACKEND=memory` 覆盖 | Schema 校验 YAML，不校验最终合并后的值 | Go 验证器链（Phase 1.5）在覆盖合并后运行 |
| **跨字段互斥**：`webauthn.enabled: true` + `authenticators.password.enabled: false` | JSON Schema 无法强制执行跨字段互斥 | 需要自定义 Go 验证器；依赖 Phase 1.5 |
| **向后兼容迁移**：配置文件从 v0.5 迁移到 v1.0，字段被重命名 | Schema 验证"当前"，不验证迁移路径 | 单独的 `config_migrate.go` 版本感知迁移逻辑；在启动时运行 |
| **Etcd 覆盖优先级**：来自 etcd 的配置值在运行时动态变更 | Schema 验证 YAML 文件，不验证 etcd 存储的运行时状态 | 运行时启动验证是最后一道防线；schema 检测与运行时检测不同 |
| **模式验证的循环依赖**：`server.issuer` 需要是有效的 URL，但 `iss` 也以 `server.issuer` 为基础进行验证 | 无循环——URL 验证是直接的 | 无问题；单独注意 |

### 3.3 方向三：异步链路追踪

| 边界场景 | 问题 | 缓解措施 |
|---------|------|---------|
| **异步 goroutine 寿命超过请求**：审计 sink 在 HTTP handler 返回后完成写入 | OTel 导出器在 audit goroutine 完成之前已经导出了根 span | 要么路径 B（延迟根 span 生命周期），要么路径 A（创建新的独立追踪）——必须记录选择 |
| **高吞吐量下的 span 爆炸**：每个请求都衍生出多个异步子 span，由于 goroutine 并发，导致 span 数量激增 | OTel 导出器不堪重负；内存压力 | 为异步 span 使用采样策略（仅对错误或以 1:100 比率采样） |
| **集群范围追踪 ID 关联**：跨 Pod 边界的异步事件（通过集群总线）携带原始的 TraceID | 需要将 TraceID 序列化/反序列化为 Protobuf 消息 | 在 `Kind*` Protobuf 消息中添加可选的 `trace_id`/`span_id` 字段 |
| **审计的 TraceContext 与 OTel SpanContext 之间的混淆**：审计从其自己的解析器中生成 TraceID，该解析器从 HTTP 头读取——与 OTel 从同一点读取的方式相同 | 它们共享 TraceID，但不共享 span 父子关系 | **关键修复**：审计应调用 `otel.SpanFromContext(ctx).SpanContext()`，而非重新解析 `traceparent` 头 |
| **CAEP 推送失败**：向远程 RP 接收者的推送失败，但根请求已返回 | 失败丢失在异步 void 中；没有 OTel span 记录失败 | 为 CAEP 推送 goroutine 添加 span 上下文传递；失败在 span 中显示为错误事件 |

### 3.4 方向四：Benchmark 预算

| 边界场景 | 问题 | 缓解措施 |
|---------|------|---------|
| **GitHub Actions CPU 抖动**：共享 vCPU 导致单次运行中的基准数字不可靠 | 伪回归 | 使用 `-count=10` 并取中位数/均值；如果样本变异 > 20%，则将基准标记为不稳定 |
| **SQLite 后端基准测试不可重现**：SQLite 性能取决于文件系统缓存状态 | 相同二进制文件在不同机器上产生 2 倍差异 | SQLite 基准属于"扩展"层级；使用 `GOGC=off` 运行以最小化 GC 影响 |
| **基准预算变得陈旧**：团队进行了架构重构，令牌颁发从 5ms 变为 8ms，但这是有意且不可逆的 | 预算需要重新校准 | 建立每季度基准预算审查流程；变更需要三位评审者的显式批准（与架构测试模型相同） |
| **分配预算触发了 Go 编译器优化**：编译器内联翻转，分配从 0 升到 1 | 零分配热路径被破坏 | 预算允许一些余量（例如，分配预算为 0，但允许 2 个作为噪声底线） |

### 3.5 方向五：FIPS 140-3

| 边界场景 | 问题 | 缓解措施 |
|---------|------|---------|
| **FIPS + form_post nonce 生成**：`crypto/rand` 在 FIPS 模式下具有不同的熵源 | 在严格加固的环境中，`crypto/rand` 可能从硬件 HSM 中读取 | 记录 FIPS 模式在启动时必须存在可用的熵源 |
| **缺少 Go 基础镜像**：FIPS 构建需要 `golang:1.24-fips-alpine`，该镜像在拉取前需要认证 | CI 流水线因拉取凭证而失败 | 在第一个 FIPS CI 步骤中记录并测试镜像拉取；使用 OIDC 对注册表进行身份验证 |
| **Ed25519 因 FIPS 性能而被禁用，但密钥已存在**：从非 FIPS 模式迁移的现有 Ed25519 签名密钥在 FIPS 模式下被拒绝 | 无法验证旧签名 | 迁移路径：用 P-256 密钥替换签名密钥，重叠验证窗口允许旧 Ed25519 证书到期 |
| **PBKDF2 向后兼容性**：使用 bcrypt 存储的现有密码哈希在启用 FIPS 时变得不可用 | 在启用 FIPS 后无法登录 | 在登录时自动升级密码哈希：用 bcrypt 验证，然后用 PBKDF2 重新哈希；保留 bcrypt 以通过重哈希窗口进行验证 |

---

## 4. 功能优先级（MoSCoW）

### Must Have（MVP — 1-2 个冲刺）

| 需求 ID | 功能 | 原因 |
|---------|------|------|
| US-1 | SPA 安全头注入（CSP、Permissions-Policy、Referrer-Policy） | 零成本安全提升；6 小时内完成；保护嵌入式 SPA |
| US-2 | Form-post nonce 注入 | 防止 CSP 阻塞 form_post；OIDC 的硬依赖 |
| US-8 | 关键基准预算 CI 门控 | 防止性能退化在合并前未被发现 |
| US-9 | 分层基准运行（关键 vs 扩展） | 确保 CI 反馈快速；扩展基准在夜间运行 |
| FR-08 | `--validate-only --schema-only` 标志 | 为配置验证提供轻量级路径，无需启动完整的服务器 |

**总 MVP 工作量估算**：~2 个冲刺（4 周），约 80% 的精力在安全头上，20% 在基准门控上。

### Should Have（下一里程碑 — 2-3 个冲刺）

| 需求 ID | 功能 | 原因 |
|---------|------|------|
| FR-06 | JSON Schema 自动生成 | 开发时配置错误检测；在合并前捕获问题 |
| FR-09 | CI 中配置验证的 schema 级集成 | 建立在 `--validate-only` 之上；schema 校验 + Go 验证器 |
| US-6 | 异步 goroutine 的 OTel span 传递 | 防止静默故障变得不可调查 |
| FR-07 | 自定义 Go 验证器注册表（Phase 1.5） | 捕获 JSON Schema 无法表达的约束 |
| US-3 | CSP 报告数据收集/切换 | 使安全工程师能够安全地过渡到执行模式 |

### Could Have（未来门控 — 3-4 个冲刺 +）

| 需求 ID | 功能 | 原因 |
|---------|------|------|
| FR-13 | CAEP 推送 + 集群事件传播的仪表化 | 高价值但依赖于方向三的 Phase 1 奠定基础 |
| US-7 | 异步追踪健康仪表板/文档 | 在 goroutine 仪表化之后 |
| FR-18 | 基准退化告警指标 | 在基准门控证明其在版本控制中有效之后 |
| FR-04 | 公共安全头策略导出（机器可读） | SOC 2 合规的证据，但并非核心产品需求 |

### Won't Have（市场驱动 — 仅在 FedRAMP 触发时）

| 需求 ID | 功能 | 原因 |
|---------|------|------|
| US-10 | FIPS 140-3 构建模式 | L 工作量；需要专门的镜像管理和 HSM 测试基础设施；仅对寻求政府合同的团队有价值 |
| FR-20 | PBKDF2 密码哈希迁移 | 仅 FIPS 构建模式需要；对 95% 的用户增加认知负担却无收益 |
| FR-22 | FIPS 镜像签名 + SCA 扫描要求 | 仅在 FIPS 构建成为主线之前进；为工具链增加显著的复杂性 |

---

## 5. 成功指标

### 5.1 采纳率指标

| 指标 | 目标 | 测量方式 | 初始基准 |
|------|------|---------|---------|
| **CSP 采用率** | 在启用功能 3 个月内，50% 的现有部署开启 CSP 头 | 匿名使用遥测（选择加入）或社区调查 | 当前：0% |
| **基准门控合规** | 在部署 3 个月后，60% 的 PR 通过基准门控 | CI 流水线指标 | 当前：100%（通过——因为没有基准门控）→ 目标：90% 通道率 |
| **配置验证采用** | 在 6 个月内，80% 的操作员使用 `--validate-only` | CLI 版本检查 | 当前：未知（新功能） |
| **GitOps 流水线集成** | 在 6 个月内，40% 的 CI 流水线添加了 schema 验证步骤 | 社区案例研究 + GitHub 星标活动 | 当前：0（新功能） |

### 5.2 性能指标

| 指标 | 当前基准 | 目标 | 驱动因素 |
|------|---------|------|---------|
| **令牌颁发 P99** | ~5ms（内存），~15ms（SQLite） | 门控在 10ms（内存）/ 20ms（SQLite） | 安全头注入和配置验证的额外延迟不应使颁发减慢超过 1ms |
| **内存限速器 P99** | ~50μs | 门控在 200μs（预算中） | 零分配热路径 — 无回归 |
| **Ed25519 签名 ns/op** | ~35,000 ns/op | 门控在 50,000 ns/op（预算中） | FIPS 模式稍慢（P-256 vs Ed25519） |
| **配置验证时间** | N/A | `< 100ms` 用于 `--validate-only --schema-only` | 不应显著减慢部署自动化 |

### 5.3 用户满意度指标

| 指标 | 测量方式 | 目标 |
|------|---------|------|
| **配置错误票证** | 每周与配置相关的支持请求计数 | 在配置验证部署 3 个月后减少 80% |
| **性能回归事故** | 归因于 PR 合并后被忽略的退化的生产事件 | 门控上线后归零 |
| **安全头覆盖** | 使用 `securityheaders.com` 等工具的第三方扫描 | A+ 评分（当前：F——无 CSP 头） |
| **事故平均解决时间（MTTR）** | 从事件创建到根本原因识别的时间 | 异步追踪启用后减少 40%（假设目前定位配置问题的平均时间为 2 小时） |

### 5.4 业务价值指标

| 指标 | 原因 | 测量方式 |
|------|------|---------|
| **政府 RFP 合格性** | FIPS 模式解锁 FedRAMP 市场；没有它就失去资格 | # 在 FIPS 功能完成后提及 FIPS/SOC 2 的 RFP 回复 |
| **CVE 减少** | CSP 缓解 XSS；FIPS 阻止降级攻击 | 在实施后一年内，与 snaplink 相关的 CVE 减少 50% |
| **社区增长** | 更高质量的基础设施推动开源采用 | 在方向一 + 方向四上线 6 个月后，GitHub 星标 +50% |

---

## 6. 发布策略

### 6.1 MVP 范围定义

**MVP 版本 2.5.0（目标：方向一 Phase 1 + 方向四 Phase 1）**

范围：
```
方向一 Phase 1（CSP 安全头注入）：
  - 所有 3 个 SPA + 错误页面的 Content-Security-Policy 头
  - Permissions-Policy、Referrer-Policy、X-Content-Type-Options
  - form_post nonce 注入（Phase 1.5）
  - 可配置的 Report-Only 模式

方向四 Phase 1（关键基准预算）：
  - .benchmarks.yaml 文件（P99 + allocations + ns/op）
  - CI 中的关键层级基准门控（令牌颁发、内存限速器、Ed25519）
  - make bench-compare 目标
  
方向二 Phase 1 子集：
  - --validate-only --schema-only 标志
  - 现有的 make config-validate-all 已通过运行时验证增强
```

**为什么是此 MVP：**
- 方向一是最高价值，最低工作量
- 方向四对于基础设施的健康至关重要（没有门控的性能退化是 Silent killer #1）
- 配置验证部分是一项低成本的巩固，可在 2 天内完成

**非 MVP（延迟发布）：**
- FIPS 模式（方向五）— 重型市场驱动功能
- 异步追踪（方向三）— 中期冲刺功能
- JSON Schema 生成（方向二 Phase 1）— 依赖于基准基础

### 6.2 灰度计划

#### 安全头

| 阶段 | 时间线 | 受众 | 机制 |
|------|--------|------|------|
| **Alpha** | 发布 v2.5.0-alpha.1 | 内部 + 3-5 名 beta 用户 | `csp.mode: report-only` 默认开；功能标志：`WithCSPReportOnly()` |
| **Beta** | v2.5.0-beta.1 | 所有 opt-in 用户 | 相同，但 CSP 头默认启用（Report-Only）；文档显示如何使用 |
| **GA** | v2.5.0 | 全部 | 默认开启（Report-Only）；清晰的升级指南指向执行模式 |

**功能标志设计：**
```yaml
csp:
  enabled: true                   # 主开关
  mode: report-only               # "report-only" | "enforce"
  report_uri: ""                  # 设置后启用报告端点
  enforce_after: 2026-08-15       # 自动从 report-only 切换到 enforce
  script_src:                     # 额外的允许列表
    - "'strict-dynamic'"
    - "'unsafe-hashes'"
```

#### 基准门控

| 阶段 | 时间线 | 行为 |
|------|--------|------|
| **信息性** | v2.5.0-alpha.1 | CI 运行基准测试并记录结果；从不阻塞构建 |
| **警告** | v2.5.0-beta.1 | CI 在回归时产生警告注释，但允许合并（三位评审者可以覆盖） |
| **阻断** | v2.6.0 | CI 在关键层级回归上阻止合并；扩展层级保持警告 |

#### 配置验证

| 阶段 | 时间线 | 行为 |
|------|--------|------|
| **Alpha** | v2.5.0-alpha.1 | `--validate-only --schema-only` 标志存在，但尚未在 CI 中强制执行 |
| **Beta** | v2.5.0-beta.1 | 现有 PR 中 `make config-validate-all` 的增强版本（添加了 schema 步骤 0） |
| **GA** | v2.5.0 | `make config-validate-all` 验证所有 7 个 YAML 文件 + schema + Go 验证器；阻塞构建 |

### 6.3 回滚策略

| 功能 | 回滚方法 | 回滚时间 |
|------|---------|---------|
| CSP 头 | 从引擎中移除中间件；重启无代码变更 | < 30 秒（无迁移） |
| Benchmark 门控 | 从 `.benchmarks.yaml` 中删除有问题的基准测试；提交修复 | < 5 分钟（无部署） |
| 配置验证 | 回滚 `--validate-only` 不改变行为——它仅用于验证，不影响运行时 | N/A——验证不在操作路径上 |
| 异步追踪仪表化 | 从 goroutine 启动器中移除 `otel.Span` 包装器；部署新二进制文件 | 标准部署时间（< 5 分钟） |
| FIPS 模式 | 如果 FIPS 镜像失败，使用普通的非 FIPS 镜像部署回滚 | 标准部署回滚 |

**每个功能的回滚就绪检查：**
- [x] 无需数据库迁移（所有方向均无模式变更）
- [x] 无需 etcd 数据格式变更
- [x] 无需 API 契约 ABI 变更

### 6.4 功能标志矩阵

| 功能标志 | 默认值 | 阶段 | 配置路径 | 移除时间线 |
|---------|--------|------|---------|---------|
| `csp.enabled` | `true` | Alpha → GA | `csp.enabled` | 永不移除——保持可配置 |
| `csp.mode` | `"report-only"` | Alpha → GA | `csp.mode` | 永不移除——操作选择 |
| `bench.policy` | `"informational"` | Alpha → Beta 中的 `"warning"` → GA 中的 `"blocking"` | 环境变量 `SSO_BENCH_POLICY` | 在 v3.0 中移除——保持默认 |
| `trace.async.enabled` | `false` | 对于方向三 Phase 1 → `true` 阶段 | `trace.async_enabled` | 在 v3.0 中弃用——默认始终开 |
| `fips.enabled` | `false` | 仅在 FIPS 构建中 | 构建标签（不是运行时开关） | N/A——构建时的选择 |

---

## 执行路线图总结

```
冲刺 1-2（v2.5.0 MVP）          冲刺 3-4（v2.6.0）             冲刺 5-7（v2.7.0）
══════════════════════════     ═══════════════════════        ═══════════════════════

方向一 Phase 1                   方向一 Phase 2                方向三 Phase 1
├── SPA 安全头注入                ├── 从 Report-Only 迁移       ├── 审计 goroutine 的 OTel span
├── form_post nonce               ├── 报告数据分析              ├── 集群事件传播
├── Report-Only 就绪              ├── 策略导出                  ├── CAEP 推送仪表化
                                  ├── 添加第三方白名单          ├── 孤儿 span 文档
方向四 Phase 1                    
├── .benchmarks.yaml             方向二 Phase 1                方向二 Phase 1.5
├── 关键层级门控                  ├── JSON Schema 自动生成      ├── Go 验证器注册表
├── make bench-compare            ├── CI 集成                   ├── 环境覆盖校验
                                  ├── --validate-only --schema-only
方向二 Phase 1（子集）                                        
├── --validate-only --schema-only                              方向四 Phase 2
├── 现有的 config-validate 增强                                  ├── 扩展层级基准测试
                                                               ├── 退化告警指标

                                                                方向五（仅在 FedRAMP 触发时）
                                                                ├── Dockerfile.fips
                                                                ├── PBKDF2 迁移
                                                                ├── 允许算法配置
```

**建议起点：** 方向一，Phase 1（安全头）。这是 6 小时内实现的最大安全影响。基准预算门控应作为并行工作流开始，在第二个冲刺中上线。配置验证的 `--schema-only` 增强应在基准工作流之后加入，以确保持续的 CI 基础设施就位。

**产品经理对团队的最终建议：** 方向一 + 方向四的组合是一份 "低成本、高安全" 的套餐，在 2 个冲刺内交付可量化的价值。推迟 FIPS 模式，直到看到实际的客户需求（RFP 要求提及 "FedRAMP"）。不要为了异步追踪而放松基准门控——性能质量的下降是无法挽回的声誉风险，而可观测性的缺陷虽然令人痛苦，但却是功能性的。
