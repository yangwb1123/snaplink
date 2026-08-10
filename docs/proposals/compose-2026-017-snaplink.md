提案文档已完成并通过完成证据校验（`COMPLETION: OK`）。交付物 `docs/proposals/compose-2026-017-snaplink.md` 全文如下：

---

# COMPOSE-2026-017 — Snaplink 协作职责提案（权限注册 + fail_closed 授权 + 审计决策事件）

Status: proposed（本文档为提案，不修改代码）
Scope: 本仓库（snaplink）在已批准组合变更 COMPOSE-2026-017
（管理员删除文件 → 通知所有者 → 审计）中的协作职责：

1. permission-catalog 注册 `vault.file.delete`（`<domain>.<resource>.<action>` 命名规范，domain 白名单含 `vault`）；
2. authorization-check 支持该 action 的 fail_closed 判定（无权限 403，返回 `decision_id` 供审计关联）；
3. 审计：删除操作的授权决策事件（`decision_id`/`policy_id`/`decision`）通过 AuditSink 端口异步入
   snaplink-audit-governance（durable_async，不阻塞主流程；L0/L1/L2 分级，不硬编码）。

文件删除与"通知所有者"的业务编排属于 Aero Vault（`aero-vault` OIDC 客户端，见
`ops/deploy/k8s-distributed/config.yaml`），本提案只覆盖 snaplink 侧三件事。

---

## 1. 现状核实（已验证的事实基线）

| 主题 | 现状 | 位置 |
|---|---|---|
| 权限模型 | 权限码为 `domain:action` 冒号两段式（`user:read`），通配 `user:*` / `*`；精确匹配对分隔符无关 | `domains/permissions/types.go`、`matcher.go` |
| 资源目录 | `ResourceProvider` 扩展已存在（`RegisterResource`/`ResolveResource`），`ResourceType` 枚举尚无 `file` | `domains/permissions/resources.go` |
| 授权端口 | gRPC `authz/v1.Authorizer.Check` 只返回 `{allowed bool}`，无 decision_id；`proto/authz/v1` 为 STABLE 包（ADR-0008：可加字段、不可删改） | `proto/authz/v1/authz.proto`、`interfaces/grpcserver/authz.go` |
| 403 语义 | HTTP 403 统一 `{"error": "forbidden"}`（`core.ErrForbidden`）；admin gRPC 拒绝用 `codes.PermissionDenied`；`WWW-Authenticate: Bearer realm="admin"` 属 admin 面，本功能不走该面 | `shared/core/errors.go`、`interfaces/admin/middleware.go`、`docs/error-codes.md` |
| 审计端口 | `audit.Recorder → MultiSink{ primary, webhook/cef/ocsf/syslog/kafka }`，`audit.async`（AsyncSink）包裹整条链，Record 永不阻塞；webhook 订阅支持事件类型过滤（精确 + 尾 `*` 通配）；`RetryingSink` 提供投递重试 | `platform/audit/async_sink.go`、`auditsink/filtering_sink.go`、`auditsink/retrying_sink.go`、`cmd/sso-server/serverbuildauthn/build_audit_async.go`、`docs/config-reference.md` |
| 既有权限查询事件 | `EventPermissionQuery = "permission_query"`（/me/* 查询），与授权决策事件语义不同 | `platform/audit/auditspi/event_types.go`、`domains/permissions/handlers.go` |
| 事件分类门禁 | 新事件类型必须：进 `KnownEventTypes`、`auditreport/control_areas.go` 分类（drift 测试强制）、`auditsink/severity.go` 覆盖表、`auditsink/cef.go` 名称表（conformance 强制） | `platform/audit/auditreport/drift_test.go`、`auditsink/cef.go` |
| 工程预算 | `domains/permissions` 恰好 10 个非测试文件（上限），**不可新建包内文件**；`interfaces/sso` 60 文件上限 | `maintainability_budget_test.go`、`docs/design/permissions-resource-catalog-wiring.md` §R1 |
| 资源目录设计先例 | 已提案对 `CheckRequest` additive 追加 `resource_type/tenant_id/attributes`（字段 4–6） | `docs/design/permissions-resource-catalog-wiring.md` |

---

## 2. 职责 1：permission-catalog 注册 `vault.file.delete`

### 2.1 命名规范

新权限码采用 `<domain>.<resource>.<action>` 点分隔三段式，与既有冒号两段式并存：

```
vault.file.delete        # domain=vault, resource=file, action=delete
```

校验规则（目录注册/分配时执行）：

```
domain:   ^[a-z][a-z0-9_]{0,31}$
resource: ^[a-z][a-z0-9_\-]{0,63}$
action:   ^[a-z][a-z0-9_]{0,31}$
```

### 2.2 目录形态

- 新增只读 **permission catalog 数据表**（code / domain / resource / action / description /
  default_grade / fail_closed），首条注册 `vault.file.delete`（`default_grade=L2`，
  `fail_closed=true`）。
- **放置位置**：`domains/permissions` 已达 10 非测试文件上限，目录常量与校验函数必须放入
  现有文件（建议 `types.go` 或 `matcher.go`，与 `docs/design/permissions-resource-catalog-wiring.md`
  §R1 同约束）；或下沉到 `shared/core`（共享内核，符合 imports 方向）。禁止新建包内文件、
  禁止 `layerExemptions`。
- **domain 白名单**：配置驱动 `permissions.catalog.domains`（默认含 `vault`），运行时白名单
  可从配置/目录表读取，**不硬编码为 switch**。校验点：role 的 `AddRole`/`UpdateRole`、
  `AssignRoles`、admin 权限 CRUD、`BuildPolicyBundle` 导出时（脏码在源头被拒，sidecar 只见干净数据）。

### 2.3 通配符兼容（关键决策）

- `permissions.Matches` 的**精确匹配**与分隔符无关：`vault.file.delete` 精确命中照常工作；
  `*` 全通配照常。既有 `user:*` 冒号语义零改动。
- 点分域通配（`vault.*`、`vault.file.*`）需要扩展 `WildcardSemantics`
  （`policy_bundle.go`）：作为 **PolicyBundle v2（additive）** 引入——`PolicyBundleVersion`
  bump 到 2，`WildcardSemantics` 追加 `DotDomainSuffix` 字段，sidecar 按 `Version` 分支；
  不重排、不删改 v1 字段。**v1 阶段只承诺精确匹配 + `*`**，域通配列为 v2，避免静默放宽
  sidecar 强制语义。
- `:` 与 `.` 两个分隔符互不相交，目录校验保证新码不落入旧匹配器误判空间。

---

## 3. 职责 2：authorization-check 的 fail_closed 判定

### 3.1 域内决策函数（单点事实源）

`domains/permissions` 新增导出决策（放入现有文件，如 `resources.go`，与 §2.2 同约束）：

```go
// Decision 是一次授权判定的完整结果。
type Decision struct {
    Allowed    bool   // false ⇒ 调用方必须 403
    DecisionID string // 响应与审计事件共用，供关联
    PolicyID   string // 命中的策略/目录资源 ID；目录无条目时 "catalog:none"
    Reason     string // 内部原因（仅审计可见，不上 403 响应体）
}

// Decide 对 want 执行 fail_closed 判定：
//   - Provider/目录查询错误          → Allowed=false（fail closed，绝不因故障放行）
//   - 未知 subject / 无角色映射      → Allowed=false（本 action 不走 ErrUserNotFound 容忍）
//   - 精确码或通配命中               → Allowed=true
func Decide(...) Decision
```

与既有 `Matches` 的差别必须写进注释：`Matches` 是"集合是否含码"的纯函数（`ErrUserNotFound`
容忍、供 /me/* 与登录嵌入用）；`Decide` 是**强制判定**（fail_closed，错误即拒绝）。

### 3.2 gRPC 端口（方案 A，推荐：additive 扩展，ADR-0008 合规）

`proto/authz/v1/authz.proto` 只追加字段，不重排：

```proto
message CheckRequest {
  string subject_id = 1;
  string client_id  = 2;
  string permission = 3;           // "vault.file.delete"
  bool   audit      = 4;           // true ⇒ 生成 decision_id 并审计（本变更启用）
  // resource_type/tenant_id/attributes 按资源目录设计文档字段 5–7（可选）
}

message CheckResponse {
  bool   allowed     = 1;
  string decision_id = 2;          // 与审计事件 decision_id 一致
  string policy_id   = 3;
  string decision    = 4;          // "allow" | "deny"（审计判定枚举的镜像）
}
```

- 旧服务端忽略 `audit` 字段 → 行为与今天字节一致；旧客户端读不到新字段（proto3 零值）→
  滚动部署安全。`make proto-breaking` 作为可选验证，不入 `make ci`。
- 备选方案 B：新增 `Decide` RPC。语义更干净但要求所有调用方升级，本变更选 A 以最小化
  兼容面（与资源目录设计文档同一策略）。
- `decision_id` 生成：复用 `auditspi.NewEventID` 模式（`crypto/rand` 12 字节 hex），
  放 `shared/core` 或直接引 auditspi，保证响应与审计事件同一 id。

### 3.3 HTTP/错误映射

| 结果 | HTTP（若经网关暴露） | gRPC |
|---|---|---|
| 无权限（deny） | `403 {"error":"forbidden","decision_id":"<id>"}` | `codes.PermissionDenied` + `status.Details(decision)`（含 decision_id） |
| 判定内部错误 | `403 {"error":"forbidden"}`（fail closed；原因只在审计） | `codes.Internal`（fail closed，不返回 allowed） |
| 允许 | 业务放行；`decision_id` 随响应头 `X-Decision-Id` 或响应体扩展字段回传 | `CheckResponse{allowed:true, decision_id, policy_id, decision:"allow"}` |

- 403 响应体保持 `{"error": ...}` OAuth 风格信封，`decision_id` 为**附加字段**，不改变
  既有错误码与状态码（`docs/error-codes.md` 的 `forbidden` 条目追加说明）。
- 失败路径的 `reason`/`policy_id` 只进审计，绝不进 403 响应体（防枚举，与 AGENTS.md
  反枚举原则一致）。

---

## 4. 职责 3：授权决策审计事件 → snaplink-audit-governance

### 4.1 新事件类型

`platform/audit/auditspi/event_types*.go` 新增：

```go
EventAuthzDecision EventType = "authz_decision"
```

同时登记进 `KnownEventTypes`。事件载荷：

| 字段 | 值 |
|---|---|
| `Type` | `authz_decision` |
| `Outcome` | `success`（allow）/ `failure`（deny） |
| `ActorID` | 发起删除的管理员 subject_id |
| `ClientID` / `TenantID` | 请求上下文（`EventFromRequest` + 租户中间件） |
| `RequestID` / `TraceID` | 透传 W3C trace（`EventFromRequest` 已填充） |
| Metadata（`audit.SetMeta`） | `decision_id`、`policy_id`、`decision`（allow\|deny）、`permission`（`vault.file.delete`）、`resource_type`（`file`）、`resource_id`（文件 id）、`target_user`（文件所有者，供通知侧关联）、`grade`（L0/L1/L2，见 §4.2） |

敏感原则：事件只携带 `resource_id`/`target_user` 引用，**不携带文件内容、路径或任何
载荷数据**。

### 4.2 L0/L1/L2 分级：配置驱动，不硬编码

- 分级映射表放配置：`audit.governance.grading`（`map[event_type|decision|permission_prefix] → grade`）。
  事件发射器**不含任何分级 switch**，只把配置解析出的 `grade` 写入 Metadata。
- 默认表（配置缺省值，可被部署覆盖）：

| 匹配 | grade | 语义 |
|---|---|---|
| `authz_decision` + `decision=deny` | L2 | 关键：拒绝的管理员删除，须治理侧强制关注 |
| `authz_decision` + `decision=allow` | L1 | 常规：放行的删除，可审计追踪 |
| `permission_query`（既有事件） | L0 | 信息：只读权限查询 |

- grade 同时作为 governance 订阅的**路由/过滤依据**（治理侧按 grade 分队列）；snaplink
  只负责携带与投递。配置缺失/未知事件类型 → 默认 L0（fail-open 于分级，不影响投递本身）。

### 4.3 事件分类门禁（必须同变更落地，否则 `make ci` 红）

按 AGENTS.md「New event types must be classified in auditreport」及既有 conformance：

1. `platform/audit/auditreport/control_areas.go` → 归入 **CC6.1 Access control**
   （`drift_test.go` 的 `TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized` 强制）。
2. `platform/audit/auditsink/severity.go` `severityOverrides` → deny 事件 `severityHigh`、
   allow 事件 `severityLow`（对 SIEM/OCSF/syslog 投影一致）。
3. `platform/audit/auditsink/cef.go` `cefEventNames` → 显式条目 `"Authorization Decision"`
   （conformance 测试强制每 const 有条目）。
4. `docs/notifications.md` 事件映射表 → **可选**登记 `authz_decision`（带 `target_user`
   元数据 → `security_event`，默认不启用）。通知所有者本身是 Aero Vault 的职责，
   snaplink 的通知路由器只作为兜底通道，不承担文件所有权判定。

### 4.4 投递拓扑（durable_async，不阻塞主流程）

沿用现有 AuditSink 端口与组合，不新增端口：

```
请求路径 ──► audit.Recorder.Record（永不阻塞）
                │
                ▼
         MultiSink ──┬─ primary：sqlite / postgres（持久，重启不丢）
                     ├─ governance：RetryingSink( FilteringSink( WebhookSink,
                     │       event_types=["authz_*"] ) ) → snaplink-audit-governance
                     └─ （既有 cef/ocsf/syslog/kafka 可选）
                ▲
          audit.async（AsyncSink 包裹整链，buffer 满 drop +
          AsyncDropHandler 记日志 + sso_audit_async_* 指标）
```

- **durable_async 的含义**：主 sink 持久化保证事件本体不因重启丢失；对 governance 的
  投递经 `audit.async` 异步化（非阻塞）并由 `RetryingSink` 重试（webhook 端点来自
  **配置**，与 AGENTS.md「receiver endpoints come from validated HTTPS client attributes,
  never request input」一致）。sink 错误/超时按既有 fail-open 语义：不阻塞主流程、记日志、
  走 drop 指标。
- **配置注意**：`audit.async.batch_size > 1` 与 webhook 的 `MultiSink` 组合**启动即 fail loud**
  （见 `build_audit_async.go` 与 config-reference）。governance 订阅启用时 `batch_size`
  必须保持 `0`/`1`；这是既有硬约束，部署文档须写明，避免运维踩坑。
- governance webhook 订阅建议：`audit.webhook.subscriptions[]` 新增命名订阅
  （如 `governance`），`event_types: ["authz_*"]`，HMAC 签名（`signing_secret` 经
  `secret://` 注入），TLS 端点。

---

## 5. API / 权限变更汇总

| 面 | 变更 | 兼容性 |
|---|---|---|
| 权限码 | catalog 注册 `vault.file.delete`（`<domain>.<resource>.<action>`） | additive；未分配前无人拥有，零影响 |
| 配置 | `permissions.catalog.domains`（含 `vault`）、`audit.governance.grading`、governance webhook 订阅 | 全部新键，缺省即现状 |
| gRPC authz/v1 | `CheckRequest.audit`（+资源字段可选）、`CheckResponse{decision_id,policy_id,decision}` | additive，ADR-0008 合规；旧端字节兼容 |
| HTTP 403 | `forbidden` 错误体追加 `decision_id` 附加字段 | 信封不变；旧客户端忽略新键 |
| PolicyBundle | v1 不变；域通配属 v2（additive） | sidecar 按 Version 分支，无静默语义变化 |
| 审计 | `EventAuthzDecision` + 分类/严重度/CEF 表 + governance 订阅 | 新事件类型 additive；`authz_*` 过滤不触碰既有订阅 |

## 6. 兼容性分析

1. **既有权限码零回归**：catalog 只校验/登记，不自动授权；`Matches` 冒号语义与
   `user:*` 通配完全不动；点分码仅精确匹配（v1），`:`/`.` 空间不相交，无匹配器歧义。
2. **proto 兼容**：`proto/authz/v1` 只加字段（ADR-0008 明示允许）；滚动部署期间新旧
   server/client 任意组合行为一致；`buf breaking` 可跑 `make proto-breaking` 复核。
3. **403 表面**：状态码与 `error` 码不变，仅追加 `decision_id` 键；不支持该键的既有
   调用方（网关/前端）行为不变。`decision_id` 不出现在失败原因中，无枚举风险。
4. **审计面**：新增事件类型对既有订阅（精确类型过滤）无影响；governance 订阅按
   `authz_*` 前缀过滤只收新事件；`KnownEventTypes` 只是 filter/UX 辅助，不在记录路径
   上被查询（custom types 本就合法）。
5. **回滚**：配置级回滚（移除 governance 订阅、grade 表、catalog 条目）即可恢复现状；
   proto additive 字段无需回滚；`authz_decision` 事件在旧版本二进制中不再产生（旧二进制
   不认识该发射点，天然干净）。
6. **预算约束**：`domains/permissions` 不加文件（10/10）；不新增 `layerExemptions`；
   不触碰 `interfaces/sso` 60 文件上限。

## 7. 部署顺序

| 步 | 内容 | 门禁/验证 |
|---|---|---|
| 1 | 配置先行：`permissions.catalog.domains`（含 `vault`）、`audit.governance.grading` 默认表、governance webhook 订阅（staging 先开，`batch_size` 保持 ≤1） | 配置校验 + boot 测试 |
| 2 | 域内 catalog 注册与校验（放入现有文件）+ 单测；memory/sqlite conformance 追加 catalog 用例 | `go test ./...`、conformance |
| 3 | proto additive 扩展 + `buf generate` + 提交 `gen/` | `make proto-breaking`（可选）、架构测试 |
| 4 | `Decide` 实现 + `AuthzService.Check` 接线 + 403/`PermissionDenied` 映射（含 `X-Decision-Id`） | bufconn 测试、`go vet` |
| 5 | `authz_decision` 事件 + 分类表（auditreport/severity/cef）+ 发射点 | drift/cef conformance 测试 |
| 6 | 与 Aero Vault 联调：删除接口携带 subject/permission/resource 属性，消费 decision_id 关联审计 | 跨仓测试（`test/` 侧） |
| 7 | 生产 rollout：先 allow 全量（观察 L1 事件量），再开 deny 灰度；监控 `sso_audit_async_*` drop 与 governance 投递延迟 | `make ci`、E2E |

发布顺序不变式：配置（1）先于代码（2–5），代码先于 Aero Vault 消费方（6）；任一阶段
回退只回退到上一阶段，不做 `git reset --hard`/force-push。

## 8. 验收标准

- 工程门禁：`go build ./... && go vet ./...`；
  `go test -run 'TestMaintainability_|TestArchitecture_' .`；`make ci`（含嵌套模块、示例、配置）。
- 行为门禁：`vault.file.delete` 无权限 → 403（HTTP）/ `PermissionDenied`（gRPC）且响应含
  `decision_id`；Provider 故障 → 拒绝而非放行；`authz_decision` 事件与响应同 `decision_id`；
  事件含 `policy_id`/`decision`/`grade`，`grade` 来自配置、代码内无分级常量；
  governance 订阅收到事件且主流程无阻塞（drop 指标可观测）。
- 分类门禁：`auditreport` drift 测试、CEF conformance、severity 覆盖表全绿。

## 9. 边界与明确不做

- 本文档是提案，**不修改任何代码**（对应任务约束）。
- 不做：文件删除业务、所有者通知编排、文件所有权判定（Aero Vault 职责）。
- 不做：硬编码 L0/L1/L2 分级（配置驱动）；PolicyBundle v2 域通配（列为后续项，不随本变更
  静默引入）；`layerExemptions`、文件/函数豁免、预算放宽。
- 不新增 proto 破坏性变更；governance 端点一律来自配置的 HTTPS 地址，绝不接受请求输入。

---

## 10. 完成证据（completion_report）

```yaml
completion_report:
  summary: "COMPOSE-2026-017 snaplink 协作职责提案已完成：vault.file.delete 权限目录注册（点分三段式命名 + 配置驱动 domain 白名单）、authorization-check fail_closed 判定（403 + decision_id 关联）、authz_decision 审计事件经 AuditSink 异步入 snaplink-audit-governance（durable_async、L0/L1/L2 配置驱动分级）。任务约束为仅输出提案文档、不修改代码，故本报告验证范围限于文档交付与仓库状态核实。"
  changed_files:
    - docs/proposals/compose-2026-017-snaplink.md
  requirements_covered:
    - "permission-catalog 注册 vault.file.delete（<domain>.<resource>.<action> 命名规范，domain 白名单含 vault）"
    - "authorization-check fail_closed 判定：无权限 403，返回 decision_id 供审计关联"
    - "审计：authz_decision 事件（decision_id/policy_id/decision）经 AuditSink 端口异步入 snaplink-audit-governance（durable_async，不阻塞主流程；L0/L1/L2 分级，不硬编码）"
    - "输出提案文档：API/权限变更、审计事件类型、兼容性分析、部署顺序"
    - "不修改代码"
  tests_added: []
  commands_executed:
    - command: "git status --short -- docs/"
      result: passed
    - command: "wc -l docs/proposals/compose-2026-017-snaplink.md"
      result: passed
    - command: "python3 -c \"import yaml; yaml.safe_load(open('docs/campaigns/tasks-compose-2026-017.yaml'))\""
      result: passed
    - command: "python3 /home/u1/ai-batch-runner/scripts/check-completion-report.py docs/proposals/compose-2026-017-snaplink.md"
      result: passed
    - command: "go build ./... && go vet ./..."
      result: not_executed
    - command: "go test -run 'TestMaintainability_|TestArchitecture_' ."
      result: not_executed
    - command: "make ci"
      result: not_executed
  not_executed:
    - check: "go build ./... && go vet ./..."
      reason: "本任务为纯文档提案（任务明确要求不修改代码），无 .go 变更，编译/静态检查门禁不适用"
    - check: "go test -run 'TestMaintainability_|TestArchitecture_' ."
      reason: "同上：无 .go 变更；提案中的工程预算约束（domains/permissions 10 文件上限等）已通过阅读 maintainability_budget_test.go 与设计文档核实，非运行验证"
    - check: "make ci"
      reason: "同上：无代码变更，全量门禁留待实施阶段执行"
    - check: "buf breaking / make proto-breaking"
      reason: "提案设计为 additive 扩展（ADR-0008），未生成 proto 代码，无法运行；兼容性论证见正文第 6 节"
  architecture_checks: not_executed
  security_checks: not_executed
  compatibility:
    breaking_change: false
  migration:
    required: false
    rollback_verified: false
  residual_risks:
    - "提案未实施，所有设计（Decide 函数、proto 扩展、事件载荷、投递拓扑）均为方案论证，实施后必须重跑完整工程门禁与行为测试"
    - "PolicyBundle v2 域通配（vault.file.*）仅列为后续方向，sidecar 兼容未验证，v1 阶段只承诺精确匹配与 * 全通配"
    - "governance 投递复用既有 webhook/async 机制，端到端延迟与 drop 指标未实测；batch_size>1 与 MultiSink 组合启动 fail loud 的约束已核实（build_audit_async.go）"
    - "L0/L1/L2 分级为跨仓约定，本仓库无既有分级常量；默认表需在联调阶段与 snaplink-audit-governance 对齐"
  assumptions:
    - "任务输出为提案文档且不修改代码（任务原文约束），仓库中仅新增本文件"
    - "'管理员删除文件 → 通知所有者'的业务编排由 Aero Vault 承担（aero-vault OIDC 客户端），snaplink 只负责权限注册、授权判定与审计三项协作职责"
    - "snaplink-audit-governance 为外部治理系统，经 audit.webhook.subscriptions 配置的 HTTPS 端点接入（ops/deploy/audit-provisioner 先例）"
```
