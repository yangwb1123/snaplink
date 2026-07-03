# 企业级扩展方向：产品-架构交叉分析

> 基于 2026-07-01 全代码库深度扫描。  
> 分析视角：资深架构师 / 产品经理。  
> 定位：此前 30+ 轮分析覆盖了协议扩展、Edge Cases、性能优化、代码健康、架构债务、运维就绪、规范审计。  
> **本轮完全不同：不是"还缺什么功能"，而是"哪些已存在的模式在规模化后必然成为瓶颈，且缺失哪些中间件/治理层导致企业客户不买账"。**  
> 原则：不写代码。每条锚定具体代码位置或模式。

---

## 总体判断

代码库在协议覆盖（OAuth 2.1/OIDC/FAPI/CAEP/Federation/SCIM）和安全性（oracle-leak、anti-enumeration、fail-closed、constant-time）上已达到极高的完成度。这是一个**开发者友好、架构清晰的单体身份平台内核**。

但**从开发者工具到企业级身份平台的跳跃**，需要以下 5 个维度。它们不是"新功能"，而是已有能力的**缺失中间层**——缺少它们，企业客户会直接拒绝采购。

---

## 方向一：SCIM 推模式供给（Provisioning Push Client）——有接收器，但没有发射器

### 核心命题

现有 SCIM 2.0 实现（`protocols/scim/`）是一个 **SCIM 接收器（Service Provider）**——用户/组可以通过 SCIM API 管理。但缺少 **SCIM 客户器（Push Client）**——即 SSO 作为 SCIM 权威源，主动把用户/组的创建、更新、禁用推送到下游应用（SaaS、企业应用）。

### 当前证据

```
protocols/scim/
├── handler.go            # SCIM HTTP handler (接收 SCIM 请求)
├── handler_users.go      # GET/POST/PUT /Users
├── handler_group.go      # GET/POST/PUT /Groups
├── patch.go              # RFC 7644 PATCH 操作
├── filter.go             # RFC 7644 过滤语法解析/求值
├── bulk.go               # RFC 7644 Bulk 操作
├── dispatch.go           # 用户/组 CRUD 分发
├── user.go / group.go    # 核心 Schema 类型
└── ...
```

SCIM 数据模型、CRUD handler、过滤器（含 lexer/evaluator）、PATCH、Bulk、Sort、ETag——全部完整实现。但它完全是**被动**的：SCIM 调用者提供数据。

### 产品价值

企业身份平台的核心价值主张是 **Identity Lifecycle Automation**：

| 场景 | 当前 | 有 SCIM Push |
|------|------|-------------|
| HR 系统创建新员工（OKTA/Workday/BambooHR 传入 SCIM） | 用户创建在 SSO 中，停止 | SSO 自动将用户推送到 Slack/Google Workspace/Salesforce |
| 员工离职 | 管理员手动在各系统删除 | SSO 自动推 SCIM DELETE 到所有下游应用 |
| 邮箱变更 | 仅在 SSO 中更新 | SSO 自动推 PATCH 到所有下游应用 |
| 组/角色变更 | 仅在 SSO 中更新权限 | SSO 自动推组成员关系变更到下游 |

**没有 SCIM Push，SSO 只是一个认证代理，不是身份平台。**

### 当前代码中已有的基座

以下能力已存在，可直接复用构建 Push 层：

```go
// 1. SCIM 类型系统已完成
protocols/scim/user.go     → User Resource (RFC 7643 §4.1)
protocols/scim/group.go    → Group Resource (RFC 7643 §4.2)
protocols/scim/patch.go    → PatchRequest (RFC 7644 §3.5.2)

// 2. 事件触发机制已存在
platform/cluster/bus.go    → Publish/Kind*
// 但没有 KindUserProvisioned, KindUserDeprovisioned 等事件类型

// 3. 外部 HTTP 客户端基础设施
platform/audit/auditsink/webhook_sink.go → HTTP POST Sink (可复用模式)
protocols/caep/transmitter.go → push 到 receiver 的 HTTP 模式

// 4. 下游应用注册关联
// Client.Attributes 可存储 scim_push_url, scim_push_token, scim_push_auth_header
```

### 架构缺口

| 需要的东西 | 当前状态 | 工作估算 |
|-----------|---------|---------|
| `SCIMProvisioner` SPI（`PushUser`, `PushGroup`, `PushDelete`, `RetryFailed`, `GetStatus`） | 不存在 | 中型（新 package + 接口设计） |
| 事件触发器（用户创建 → SCIM Push） | 不存在（cluster bus 有 `Kind*` 但没有 lifecycle 事件） | 小型（新增 event types + handler） |
| 推送队列 + 重试 + 幂等性 | 不存在（CAEP transmitter 有基础重试模式） | 中型（背压、持久队列） |
| 与 DCR/Wire 同步（下游应用注册时自动检测 SCIM 支持） | 不存在 | 小型（`Client.Attributes` 扩展） |
| 推送状态仪表板 + 重新推送 | 不存在 | 中型（管理面 API + 审计事件） |

### 为什么不只是"加一个 SCIM 客户端"

因为这不是一个纯技术问题——它涉及：

- **一致性模型**：SSO 中的变更与下游系统之间的最终一致性窗口。推成功才算成功；纯推后验证 vs 推后轮询验证。
- **全量 Provisioning vs 增量 Sync**：初始全量同步（一次性推送所有现有用户） vs 持续增量变更。两者的错误处理、进度报告不同。
- **增量重试的幂等性**：SCIM PUT/PATCH 要求 is idempotent。使用 `externalId`（SCIM 标准的不可变 ID）做匹配键。
- **去 Provisioning**：禁用 vs 删除。企业场景倾向于禁用（保留审计记录），SaaS 场景倾向于删除（节省 license）。

### 工作量价值评估

| 维度 | 评估 |
|------|------|
| **产品价值** | **极高**——企业客户 RFP 中的 Must-Have。无 Push → 否决 |
| **架构影响** | 中——新包不改变现有依赖方向，复用已有 SCIM 类型 |
| **工作量** | L（~1500 行：SPI + 事件桥接 + 推送引擎 + 管理 API + 重试） |
| **竞品对标** | Okta Provisioning Agent、Azure AD Provisioning、Keycloak 无原生 SCIM Push |

---

## 方向二：管理面治理——Break-Glass 紧急访问 + 操作审批工作流

### 核心命题

Admin API 由 `admin:read` / `admin:write` RBAC scope 保护（`interfaces/admin/middleware.go`），gRPC interceptor（`interfaces/grpcserver/interceptor.go`）同样做了 scope 验证。但**没有任何以下治理机制**：

| 治理需求 | 当前状态 |
|---------|---------|
| 紧急访问（管理员需要临时绕过 scope 限制修复事故） | ❌ 不存在——要么提前赋予 `admin:write`，要么做不到 |
| 敏感操作审批（"删除此 client"→ 需另一个人批准） | ❌ 不存在——任何有 `admin:write` 的人都可以删 |
| 管理员会话录制（哪个人在哪个 admin 会话中做了什么） | ❌ 不存在——审计事件有 ActorID，但无"admin 会话"概念 |
| 托管权限（授权特定管理员在特定时间窗口内执行特定操作） | ❌ 不存在 |
| 变更审批通知（敏感操作触发通知给安全团队） | ❌ 不存在 |

### 当前证据

```go
// interfaces/admin/middleware.go — 纯 scope 检查，无上下文
func AdminMiddleware(d Deps, resource, action string) echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            // 1. 从 context 提取 token claims
            // 2. 检查 scopes 是否包含 admin:{resource}:{action}
            // 3. 通过 → next；不通过 → 403
        }
    }
}
```

没有 `AdminContextWithSession`、`OperatingReason`、`ApprovalTicketID`。

每个 admin handler 只做：

```go
// interfaces/admin/users.go:97
func HandleAdminResetUserPassword(d Deps, ctx core.HandlerContext) {
    // 1. 解析参数
    // 2. 验证权限（通过中间件 scope 检查）
    // 3. 执行操作
    // 4. 记录审计事件
}
```

**没有**"这个操作是否需要额外审批？""当前是否有紧急访问模式生效？"。

### 架构缺口

#### 2.1 Emergency Access / Break-Glass

需要的模式：

```go
// 当前
type AdminMiddleware struct {
    scopeChecker ScopeChecker
}

// 需要
type AdminMiddleware struct {
    scopeChecker ScopeChecker
    emergencyAccess *EmergencyAccessStore  // 新增
    breakGlassConfig BreakGlassConfig      // 新增
}

// Break-Glass 流程：
// 1. 运维人员调用 POST /api/v1/admin/break-glass 
//    Body: {reason, duration, approver (可选)}
// 2. 系统生成一次性紧急访问码 + 启动计时器
// 3. 运维人员在敏感操作 request header 中传递 X-Break-Glass-Code
// 4. AdminMiddleware 检测到 header → 绕过常规 scope check
// 5. 审计事件记录：actor, operation, break_glass=true, code=xxx
// 6. 超时后自动失效
```

**代码位置**：`interfaces/admin/middleware.go`（~150 行扩展）

**关键设计约束**：

- Break-Glass 必须是**有时限的**（默认 30 分钟），必须明确记录原因
- 紧急访问码必须是**高熵一次性使用**（类似 TOTP）
- **必须记录审计事件**：`admin_break_glass_activated` / `admin_break_glass_operation`
- Break-Glass **不支持静默**——应触发告警（安全团队即时得知"有人 bypass 了 RBAC"）
- 应支持"在 Break-Glass 期间的所有操作打标签"供事后 review

#### 2.2 敏感操作审批工作流

不是所有操作都需要审批——但以下操作在受监管环境中需要：

| 操作 | 风险等级 | 需要审批 |
|------|---------|---------|
| `DELETE /api/v1/admin/clients/:id` | **高**（使所有依赖此 client 的应用无法登录） | ✅ |
| `POST /api/v1/admin/keys/rotate` | **高**（立即失效所有现签发的 JWT） | ✅ |
| `POST /api/v1/admin/users/:id/password` | **高**（帮助台可以重置任何人的密码） | ✅ |
| `GET /api/v1/admin/users/:id/consents` | 中（读取用户的隐私数据） | ⚠️ 可选 |
| `GET /api/v1/admin/metrics` | 低 | ❌ |

**实现模式**：

```go
type AdminOperation struct {
    Method      string      // POST, DELETE, PUT
    Path        string      // /api/v1/admin/clients/:id
    RiskLevel   RiskLevel   // Low | Medium | High | Critical
    RequiresApproval bool
    ApprovalScope  string  // admin:approve:clients (独立于 admin:write)
}

func (m *AdminMiddleware) requiresApproval(op AdminOperation) bool {
    if !op.RequiresApproval {
        return false
    }
    // 1. 检查请求头 X-Approval-Ticket-Id
    // 2. 验证 ticket 状态 = approved, 未过期, 操作匹配
    // 3. 记录审批人与操作人的关联
    // 4. 记录 audit: admin_operation_approved, admin_operation_executed
}
```

#### 2.3 管理面工作流的状态

当前 gRPC admin interceptor：

```go
// interfaces/grpcserver/interceptor.go
// 已实现：scope 检查、audit 拦截
// 未实现：approval ticket 验证、break-glass 检查
```

**扩展点**：Interceptor 链已经是 plugin 模式（`WithAdminInterceptor`）。将 `ApprovalInterceptor` 和 `BreakGlassInterceptor` 作为可选的 `grpc.UnaryServerInterceptor` 注入。

### 工作量价值评估

| 维度 | 评估 |
|------|------|
| **产品价值** | **极高**——SOC 2 Type II、HIPAA、PCI DSS 审计的常见发现项 |
| **架构影响** | 低——新的 SPI + middleware 扩展，不修改现有 handler 逻辑 |
| **工作量** | M-L（Break-Glass: ~200 行 + 审批: ~400 行 + 审计: ~100 行） |
| **竞品对标** | Okta Privileged Access、Azure AD PIM、Auth0 Actions（PostLogin 可做但无原生审批） |

---

## 方向三：后端依赖弹性框架——统一断路器、连接池与优雅降级

### 核心命题

SSO 依赖于大量后端服务：Redis、SQLite、etcd、LDAP、SAML IdP、KMS（AWS/GCP/Azure/PKCS#11）、ExtAuthz Envoy、SCIM（下游）、Webhook Sinks、CAEP Receiver。**每个后端的故障应对策略各不相同**，且大多数是：

- 无超时覆盖（使用 `http.DefaultClient` 的默认 zero timeout）
- 无断路器（故障后端持续遭受请求，浪费资源、增加延迟）
- 无健康检查集成（`/readyz` 不知道单个后端是否不可用）
- 无 graceful degradation（LDAP 挂了 → `/auth/login` 返回 500 而不是降级为密码验证）

### 当前证据

扫描发现的连接/后端模式分布：

```go
// 1. HTTP 客户端（多个独立实例）
domains/federation/fetch.go:                           → http.Client{Timeout: 10 * time.Second}
protocols/caep/transmitter.go:                         → http.Client{Timeout: 30 * time.Second}
platform/audit/auditsink/webhook_sink.go:               → http.Client{Timeout: DefaultWebhookTimeout}
platform/releases/probehttp/http.go:                    → http.Client{Timeout: 5 * time.Second}
security/jar_fetch_http.go:                             → http.Client{Timeout: JARFetchTimeout}
// 每个有自己的 Timeout，但都没有 Transport 级别的 connection pooling / circuit breaker

// 2. gRPC 客户端（独立连接参数）
interfaces/ssoclient/remote/grpc.go:                    → grpc.NewClient(addr, ...)
cmd/sso-mcp/snaplink.go:                                → grpc.NewClient(cfg.SnaplinkGRPC, ...)
// 没有统一的重试/超时/断路器配置

// 3. 数据库/SQLite 连接
infrastructure/defaultimpl/sqlite/*.go:                  → *sql.DB (每个 store 独立？)
// SQLite 连接池：sql.Open("sqlite3", dsn) 默认 maxOpenConns=1（SQLite 限制）
// 但多个文件可能有多个 *sql.DB 实例 → 连接数失控

// 4. Redis
infrastructure/redis/*.go:                               → *redis.Client (universal options)
// 有健康检查吗？扫描显示没有显式的 Ping 循环

// 5. LDAP
infrastructure/ldap/conn.go:                             → ldap.DialURL(addr, ldap.DialWithTimeout(5*time.Second))
// 连接池管理模式？扫描显示每次认证操作获取一个新连接

// 6. KMS（每个都有自己的重试策略）
infrastructure/kms/awskms/signer.go:                     → session.Must(session.NewSession())
infrastructure/kms/azurekeyvault/signer.go:              → keyvault.NewClient(...)
infrastructure/kms/gcpkms/signer.go:                     → kms.NewKeyManagementClient(ctx)
infrastructure/kms/pkcs11/signer.go:                     → p11Ctx.OpenSession(slot)
```

### 核心架构缺口

**缺少一个统一的 `BackendConnector` 框架**，提供：

```go
// 需要的新 SPI
type BackendConnector interface {
    // Health returns nil if the backend is reachable and ready.
    Health(ctx context.Context) error
    
    // CircuitState returns the current circuit breaker state.
    CircuitState() CircuitState // Closed | HalfOpen | Open
    
    // Name returns the backend identifier (for metrics/logging).
    Name() string
}

type CircuitState int

const (
    CircuitClosed   CircuitState = iota // Normal operation
    CircuitHalfOpen                     // Probing after cooldown
    CircuitOpen                         // Failing fast
)
```

### 具体影响分析

#### 3.1 级联故障模式

```
LDAP 服务器超负荷（响应 15s+）
  ↓
所有 login 请求的 LDAP Authenticator 路径超时（15s × 10 个并发 goroutine）
  ↓
/login 端点 goroutine 泄漏（每个请求一个 goroutine 在等待）
  ↓
Echo server 的 goroutine pool 耗尽
  ↓
所有端点（包括不需要 LDAP 的 endpoints）开始 503
  ↓
SSO 整体不可用——仅仅因为 LDAP 挂了
```

**当前没有断路器中断此链条**。每个请求都尝试连接 LDAP，每次等待 timeout，每次`connection refused` 重试。

#### 3.2 当前已有的健康检查基础设施

```go
// platform/health/health.go (如果存在)
// 扫描发现：
interfaces/sso/server_health.go → /livez, /readyz 端点
platform/audit/health.go → Audit health probe
platform/bootstrap/probe.go → Bootstrap probe
```

健康检查模式存在但**没有集成到客户端连接管理**中。`/readyz` 应反映后端的连通性状态：

```go
// 需要
func (s *Server) readinessProbe() error {
    probes := []struct{
        name string
        fn   func(context.Context) error
    }{
        {"redis", s.RedisHealth},
        {"ldap", s.LDAPHealth},
        {"kms", s.KMSHealth},
        {"sqlite", s.SQLiteHealth},
    }
    for _, p := range probes {
        if err := p.fn(ctx); err != nil {
            // log degraded state but don't fail /readyz?
            // 决定：fail /readyz only for hard dependencies
        }
    }
}
```

### 具体建议

| 组件 | 当前模式 | 弹性缺口 | 建议 |
|------|---------|---------|------|
| HTTP 出站客户端 | 5+ 独立 `http.Client` | 无统一超时/重试/断路器 | `NewBackendHTTPClient(name string, opts ...Option) *http.Client` 工厂 |
| SQLite | `*sql.DB` | 单写者限制、无只读副本 | 连接池参数显式配置 + 只读副本路由 |
| Redis | `*redis.Client` | 无连接健康定期检查 | Sentinel ping goroutine |
| LDAP | 每次认证 Dial | 无连接池 | 连接池 + 超时断路器 |
| KMS | SDK 默认配置 | 无断路/回退 | 软件回退签名（KMS 不可用时降级为 local signer） |

### 工作量价值评估

| 维度 | 评估 |
|------|------|
| **产品价值** | **高**——生产可靠性直接决定 SLA。每一起 LDAP 引发的 SSO 熔断都是 P0 事故 |
| **架构影响** | 中——新抽象层不影响现有 handler，但需逐步迁移各后端 |
| **工作量** | L（~2000 行：`BackendConnector` 框架 + 各后端适配 + 集成测试 + 健康检查集成） |
| **竞品对标** | Okta 无开源方案；Keycloak 同样没有统一断路器——这是行业通病，做出来就是差异化优势 |

---

## 方向四：配置漂移管理与 GitOps 式身份运维

### 核心命题

配置系统（`config/`）目前已支持 YAML + 环境变量 + etcd + 命令行 flags 的层次覆盖（`config/internal/parse/` + `config/sources/`），且支持热加载某些配置项。但**整个配置模型是被动的**——加载后无人监督与期望状态是否一致。

### 当前证据

```go
// config/config.go — 配置加载路径
// 1. YAML 文件读取 → 2. 环境变量覆盖 → 3. etcd 覆盖 → 4. 命令行 flags 覆盖
// 加载后 Config 实例被传出，不再追踪来源或检查漂移

// interfaces/sso/options.go — Server 选项
// WithConfig(cfg) 接受整个 Config 结构体
// 但 Config 中的 Client、Authenticator、Tenant 可在运行时通过 admin API 修改
// 修改后：内存中的 Config 与 etcd/YAML 中的配置产生漂移
```

**现实场景**：

1. 运维团队通过 `config.yaml` 定义了 3 个 client
2. 管理团队通过 admin API 创建了 5 个额外 client
3. 运维团队更新 config.yaml（增加了一个 client）并重启 SSO
4. 重启后：admin API 创建的 5 个 client 仍在数据库中（因为 client store 是持久的）
5. 但 config.yaml 中的 client 也重新加载——如果 config YAML 中没有 `preserve_existing` 标记，会发生什么行为？
6. **不可预知**——当前没有"配置来源 vs 运行时状态"的一致性模型

### 架构缺口

#### 4.1 期望状态引擎（Desired-State Reconciliation）

类似 Kubernetes 的控制器模式：

```go
type ConfigReconciler struct {
    desired Config        // 从 YAML/etc 加载的期望状态
    actual  ConfigView    // 运行时状态（admin API 修改后）
    drift   ConfigDiff    // desired - actual 的差异
}

func (r *ConfigReconciler) Reconcile(ctx context.Context) error {
    diff := r.computeDiff()
    for _, d := range diff.Clients {
        switch d.Type {
        case DiffAdded:
            // desired 中有但 actual 中没有 → 创建
            r.adminClient.Create(ctx, d.Client)
        case DiffRemoved:
            // desired 中没有但 actual 中有 → 删除？（或标记为 orphan）
            // 必须决定：是"精准匹配"还是"基线+附加"
        case DiffModified:
            // 属性变更 → 更新
            r.adminClient.Update(ctx, d.Client.ID, d.Changes)
        }
    }
}
```

**关键决策**：三种治理模式

| 模式 | 语义 | 适用场景 |
|------|------|---------|
| **严格（Strict）** | desired 是完整的——actual 中不在 desired 里的都被删除 | 完全 GitOps |
| **基线（Baseline）** | desired 是最低要求——actual 可以有额外内容 | 混合管理（YAML 定义底线 + admin API 做临时变更） |
| **追加（Append-Only）** | desired 中的被创建/更新，但 actual 中的额外内容永不删除 | 开发环境 |

#### 4.2 配置漂移检测和告警

```go
type DriftDetector struct {
    checkInterval time.Duration
    notifiers     []DriftNotifier  // Slack, PagerDuty, audit event
}

func (d *DriftDetector) detectAndAlert() {
    drift := d.computeDrift()
    if drift.HasDifferences() {
        for _, n := range d.notifiers {
            n.Notify(drift)
        }
        // 记录 audit: config_drift_detected {source, diff}
    }
}
```

#### 4.3 配置版本化和回滚

当前 snapshot 系统（`interfaces/snapshot/`）可以导出/导入全状态。但 **config 本身没有版本历史**：

```go
// 需要
type ConfigVersion struct {
    ID        string    // version hash
    Config    Config    // 完整配置快照
    Source    string    // "yaml" | "etcd" | "admin_api" | "reconcile"
    CreatedAt time.Time
    CreatedBy string    // actor
    Reason    string    // commit message 或 API 调用描述
}
```

admin API 的 client/tenant/connection CRUD 操作应该自动生成新的 `ConfigVersion`，供回滚使用。

### 工作量价值评估

| 维度 | 评估 |
|------|------|
| **产品价值** | **高**——企业客户将 GitOps（Git 作为配置单一来源）视为身份运维现代化的基本要求 |
| **架构影响** | 中——新引擎不修改现有 config 加载；但与 admin API 的 write path 需要集成 |
| **工作量** | L（扩散到多个包） |
| **竞品对标** | Okta 的 Terraform Provider（外部），无原生 GitOps。Auth0 Deploy CLI（外部）。有差异化空间 |

---

## 方向五：授权引擎演进路径——从 RBAC 到 ABAC/ReBAC 的架构预备

### 核心命题

当前 `domains/permissions/` 实现了功能完整的 RBAC——角色（roles）、权限（permissions）、菜单（menus）、通配符匹配（`user:*`）、策略包（policy bundle）。但**授权模型被硬编码为角色-权限的二元关系**，没有任何策略引擎抽象。

### 当前证据

```go
// domains/permissions/matcher.go — 核心匹配逻辑
// Check(user, permission) → bool
// 实现：user → roles[] → permissions[] → wildcard match

// domains/permissions/provider.go — SPI
type Provider interface {
    Check(ctx context.Context, subjectID string, permission string) (bool, error)
    ListRoles(ctx context.Context, subjectID string) ([]string, error)
    ListPermissions(ctx context.Context, subjectID string) ([]string, error)
    // ... AssignRole, RevokeRole, CreateRole, etc.
}
```

Provider 接口完全是 RBAC 原生的。

### 架构缺口

#### 5.1 缺少 Policy Decision Point (PDP) 抽象

当前授权调用链：

```
Request → AdminMiddleware (scope check) → HandleAdminXxx (logic)
                ↓
          permissions.Provider.Check(user, permission)
                ↓
          matcher.wildcardMatch(rolesPermissions, permission)
                ↓
          return bool
```

`Check` 方法被硬编码为通配符匹配。如果企业需要：

- **ABAC**：`"允许用户查看本部门的文档"` — 需要属性 `department=engineering` 和资源属性 `resource.department=engineering`
- **ReBAC（Relationship-Based）**：`"允许用户编辑他们拥有的文档"` — 需要 `subject -> owner -> resource` 关系
- **Policy-as-Code**：`"拒绝来自非公司 IP 且在非工作时间的访问"` — 需要运行时策略评估引擎

**这些场景在当前架构中都需要绕过 `Provider` 接口。** `Provider.Check` 的签名只接受 `(subjectID, permission)`，不传递 `resource`, `context`, `environment`。

#### 5.2 进化路径（不破坏现有代码）

**阶段一：扩展 Provider SPI**

```go
// 新增（向后兼容）
type CheckInput struct {
    SubjectID  string
    Permission string
    Resource   *ResourceContext   // 可选 — 用于 ABAC/ReBAC
    Context    map[string]any     // 可选 — IP、时间、设备状态
}

type Provider interface {
    // 原有方法保持
    Check(ctx context.Context, subjectID string, permission string) (bool, error)
    
    // 新方法
    CheckWithContext(ctx context.Context, input CheckInput) (*CheckResult, error)
}

type CheckResult struct {
    Allowed  bool
    Reasons  []PolicyMatch    // 审计可追溯
    Decision DecisionType     // Allow | Deny | NotApplicable | Indeterminate
}
```

**阶段二：策略引擎抽象**

```go
type PolicyEngine interface {
    Evaluate(ctx context.Context, input EvaluationInput) (*EvaluationResult, error)
}

type EvaluationInput struct {
    Subject   SubjectInfo
    Resource  ResourceInfo
    Action    string
    Context   EnvironmentContext
}

// OPA/Rego 集成：
type RegoPolicyEngine struct {
    rego    *rego.Rego
    bundles map[string]string // policy name → rego module
}

// 或 SQL-based：
type SQLPolicyEngine struct {
    db      *sql.DB
    queries map[string]string
}
```

**阶段三：PIP（Policy Information Point）集成**

ABAC 需要额外的属性来源——用户的部门、资源的分类、IP 的地理位置、当前时间。当前 `Permission` 只有 name，没有属性元数据。

```go
type PolicyInfoPoint interface {
    GetSubjectAttributes(ctx context.Context, subjectID string) (map[string]any, error)
    GetResourceAttributes(ctx context.Context, resourceType string, resourceID string) (map[string]any, error)
    GetEnvironmentContext(ctx context.Context) (map[string]any, error)
}
```

当前代码中已有的 PIP 基座：

```go
domains/tenant/          → TenantInfo (可能用于 resource 属性)
platform/geo/            → GeoInfo (IP → location — 环境上下文)
domains/region/          → ResidencyInfo (环境上下文)
```

### 工作量价值评估

| 维度 | 评估 |
|------|------|
| **产品价值** | **高**——ABAC 在金融、医疗、政府等受监管行业是必须的 |
| **架构影响** | 中——`Provider.Check` 签名变更需所有实现更新。但通过 `CheckWithContext` 可选扩展可避免 break |
| **工作量** | M-L（SPI 扩展: ~100 行 + OPA 集成: ~300 行 + PIP: ~200 行 + 测试: ~500 行） |
| **竞品对标** | Okta 有 Okta Expression Language（类似 ABAC）；Azure AD 有 Conditional Access（丰富但专有）；Keycloak 无原生 ABAC |

---

## 优先级与路线图建议

| # | 方向 | 产品价值 | 架构影响 | 工作量 | 推荐阶段 |
|---|------|---------|---------|-------|---------|
| **P0** | 方向一：SCIM Push 供给 | 极高（否决项） | 中 | L | 立刻启动（MVP: 2 周） |
| **P0** | 方向二：管理面治理（Break-Glass） | 极高（合规否决项） | 低 | M | 立刻启动（MVP: 1 周） |
| **P1** | 方向三：后端弹性框架 | 高（SLA 承诺前提） | 中 | L | 方向一/二完成后（4 周） |
| **P1** | 方向四：配置漂移治理 | 高（GitOps 必备） | 中 | L | 与方向三并行（4 周） |
| **P2** | 方向五：ABAC 策略引擎 | 高（差异化竞争点） | 中 | M-L | 方向一~四稳定后（6 周+） |

### 与已有分析的关系

| 现有 doc | 覆盖范围 | 本报告的不同点 |
|----------|---------|-------------|
| `expansion-v2-2026-07-01.md` 方向二（身份生命周期） | 生命周期管理的高层级描述 | **本报告聚焦 SCIM Push 的具体架构缺口**（有接收器无发射器） |
| `expansion-v2-2026-07-01.md` 方向五（外部化授权） | OPA 集成概念 | **本报告聚焦 Provider SPI 的渐进式演化路径**（不破坏现有 RBAC） |
| `analysis-round14-sprint-audit-batch.md` | 审计批处理 | **本报告聚焦管理面治理的操作审批和 Break-Glass** |
| `analysis-round10-sqlite-connections-mfa-recovery-upstream-http.md` | 上游 HTTP 超时治理 | **本报告扩展到所有后端的统一断路器框架** |
| `edgecases-and-perf-2026-07-01.md` 方向四（context.Background） | 单个 goroutine 泄漏 | **本报告聚焦后端健康检查集成到 /readyz** |
| `architectural-debt-and-risks-2026-07-01.md` 方向一（Deps 膨胀） | 接口膨胀 | **本报告聚焦配置漂移和 GitOps 治理** |

---

## 总结

| 指标 | 当前状态 | 目标状态 | 差距本质 |
|------|---------|---------|---------|
| 协议覆盖（OAuth/OIDC/FAPI/SCIM） | **9/10** | 10/10 | 少数 opt-in |
| 安全性保护 | **9/10** | 10/10 | 少数纵深防御 |
| 企业集成能力（Provisioning, Events） | **2/10** | 8/10 | **存在架构缺口** |
| 生产可靠性和弹性（Circuit Breakers, Graceful Degradation） | **3/10** | 8/10 | **缺少中间件层** |
| 运维治理（GitOps, Break-Glass, Approval Workflows） | **1/10** | 8/10 | **功能完全不存在** |
| 授权深度（ABAC/ReBAC） | **2/10** | 6/10 | SPI 需要进化路径 |

此前 30+ 轮分析主要贡献在**协议/功能/修复**层面。本报告揭示了在 **企业级中间件和治理层**上存在的决定性的架构缺口——它们不通过"加一个 endpoint"或"优化一段代码"来解决，而是需要**引入新的抽象层和运行模式**。
