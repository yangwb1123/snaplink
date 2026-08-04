# 架构师分析：同行评审回响与深度架构设计

> **分析日期：** 2026-07-11  
> **评审依据：** `docs/requirements/PEER_REVIEW_architect-expansion-novel-horizons-2026-07-11.md`  
> **原始分析：** `docs/requirements/architect-expansion-novel-horizons-2026-07-11.md`  
> **角色：** 资深架构师  
> **方法：** 对抗式代码核验 + 架构影响分析 + 一致性模型推演

---

## 1. 架构评估：同行评审的三项重大发现对架构的影响

### 1.1 发现一：开发者门户已存在——对方向二的架构缩减

**代码证据：** `interfaces/sso/sso_selfservice.go:414` → `WithDeveloperPortalFS` + `pathDeveloperPortalPrefix = "/developer/"` + 提交 `4c79fb82`（自助 DCR 注册 SPA）。

**架构含义：**

原始分析将方向二（API 安全产品化）估计为 L（~1200 行），其中 (B) API 密钥自助门户 500 行。评审将其修正为 M（~700 行），原因在于存在一个**已部署、已挂载、可嵌入**的开发者门户 SPA。

从架构角度看，这不仅仅是工作量的缩减——它改变了方向二的**依赖结构**：

```
原始假设：                          实际状态：

开发者门户 = 全新构建                开发者门户 = 现有 SPA
         ↓                                   ↓
全栈：前端 + 后端 + API            仅需：前端扩展（新增标签页）
                                   后端 API 已在（DCR CRUD）
                                   复用：现有 auth 层 + 路由
```

**架构决策影响：**
- (B) API 密钥自助门户不再需要新的路由、新的认证机制、新的 `fs.FS` 嵌入——只需扩展现有 SPA 的视图层
- (D) 范围市场可以作为一个页面组件（scope selector widget）实现，而非独立应用
- 方向二的总架构 footprint 从"新子产品线"降低为"现有产品的功能扩展"

### 1.2 发现二：ConsentStore 是隐藏的前置依赖——对方向一的架构约束

**代码证据：** `core/consts.go:383` → `ErrConsentRequired` 已声明但零调用方；全树无 `ConsentStore` 接口或实现。

**架构含义：**

这是三项发现中**架构影响最大**的一项。方向一（身份编排）的 (B) 声明式认证流程的一半用例依赖 Consent 基础设施：

| 用例 | 对 ConsentStore 的依赖 |
|------|----------------------|
| "首次登录需额外范围同意" | **硬依赖**——需要存储 per-user-per-client 同意记录 |
| "撤销已授权应用" | **硬依赖**——需要枚举同意记录 + 级联吊销 |
| "高风险操作 step-up" | 间接依赖——需要会话记录中的同意状态 |
| "SSO 失败回退" | **无依赖**——纯路由逻辑 |

**架构约束图：**

```
方向一(A) Pipeline Hooks
    ├── 钩子注册表（无 Consent 依赖） → 可独立启动
    ├── pre-auth 钩子（无 Consent 依赖）→ 可独立
    └── post-auth 钩子（需要 Consent 状态）→ 需要 ConsentStore
         ↓
方向一(B) 声明式流程
    ├── 流程解释器（无 Consent 依赖）→ 可独立
    ├── consent 步骤（硬）→ 需要 ConsentStore
    └── scope 变更流程（硬）→ 需要 ConsentStore
```

**架构决策：** ConsentStore 不是方向一的"可选组件"，而是**ROADMAP v5.0 方向①(a) 与方向一(B) 的共同前置依赖**。必须作为第一优先级实施。

### 1.3 发现三：SSOConfigDrift CRD + MQTT/SSE 已存在——对方向五的架构缩减

**代码证据：** 提交 `a635191d` → SSOConfigDrift CRD + controller；`mqtt/` 嵌套模块；`sse/` 跨副本事件流；`cluster/etcd` 现有总线。

**架构含义：**

原始分析将方向五（多集群联邦）估计为 XL（~2200 行），其中 (C) 全局策略冲突检测 500 行 + 新通信层。评审将其修正为 L+XL（~1700 行）。

更重要的是，**通信层的架构选择被重新定义**：

```
原始假设：                              实际状态：

需要新的集群间通信层                    现有通信原语：
    ↓                                       ├── SSE（跨副本事件流）
    全新设计                                ├── MQTT（嵌套模块）
                                            ├── gRPC（extauthz 已有）
                                            └── etcd cluster.Bus（已有）
                                            
SSOConfigDrift CRD = 不存在              SSOConfigDrift CRD = 已存在
    ↓                                       ↓
    从零构建策略冲突检测                  扩展 CRD（~200 行）
```

**架构决策影响：**
- 方向五的通信层架构从"新建"变为"选型"——现有 4 种原语可选
- (C) 的范围从"构建全局条件访问策略"收窄为"扩展现有 CRD 做跨集群策略同步 + 漂移校正"
- 一致性模型的选择（MQTT 的 QoS vs SSE 的 at-most-once vs etcd 的线性一致性）成为关键架构决策

---

## 2. 架构缺口：评审未明确提及但需关注的深层问题

### 2.1 出口连接器框架（Egress Connector Framework）——横切架构债务

评审在末尾讨论了此问题，应提升至**一等架构关注点**。当前状态：

| 组件 | 出站连接管理 | 健康检查 | 熔断 | 密钥轮换 |
|------|-------------|---------|------|---------|
| emailsmtp | 自有连接池 | ❌ | ❌ | ❌ |
| oidc_federation | 自有 HTTP 客户端 | ❌ | ❌ | ❌ |
| caep/ push | 裸 `http.Post` | ❌ | ❌ | ❌ |
| KMS peers | 每个 peer 自有 | ❌ | ❌ | ❌ |
| SAML IdP fetch | 自有 HTTP 客户端 | ❌ | ❌ | ❌ |
| extauthz/ gRPC | 自有连接池 | ❌ | ❌ | ❌ |

**架构缺口分级：** 这不是一个独立方向，而是一个**架构基础设施层**，应在实现任何出口密集型方向之前建立。否则，方向一（编排 → SSO 连接器调用）、方向二（网关适配器 → 外部网关）、方向五（跨集群通信）都会独立解决连接管理问题，导致 3-5 倍重复实现。

**建议的架构位置：** `platform/egress/`——与 `platform/cluster/`（集群内部通信）、`platform/audit/`（审计）平级。

### 2.2 Token 生命周期可追溯性——合规缺口

评审未提及但 ROADMAP v5.0 和原始分析均部分涉及的问题：当前令牌生命周期不可追溯。

**代码证据：** 审计事件不记录令牌 `jti`；token exchange 的 `act` 链仅在 JWT claim 中——令牌过期后丢失全部链信息；Token usage 和审计是两个独立子系统，设计未要求关联。

**架构影响：** 方向一（编排）的钩子系统将引入更多令牌衍生关系（钩子可触发新令牌颁发），使可追溯性问题恶化。应在方向一之前或与之并行解决。

### 2.3 配置验证门禁——运维缺口

评审未直接提及，但原始分析方向四讨论的问题：配置错误是 SSO 停机的首要原因。

**当前状态：** 配置验证是 `sso-ctl` 的手动 CLI 模式——没有 `--ci` 退出码、没有版本兼容矩阵、没有能力注册表。

**架构影响：** 方向一 (B) 声明式流程引入 YAML/JSON 可配置认证策略后，配置验证从"好实践"升级为"正确性门禁"——无效的流程定义可能导致认证死循环或安全绕过。

---

## 3. 扩展方向：修正后的架构设计建议

### 3.1 方向一：身份编排（修正后 P1）

#### 核心架构决策：Pipeline Hooks 的注册模型

**选项 A：中间件风格（推荐）**

```go
// 类型定义
type AuthPipelineHook func(ctx *AuthContext, result *AuthResult) (*AuthMutation, error)

// 注册点——方法与现有 With* 模式一致
sso.WithPreAuthHook(name string, hook AuthPipelineHook, opts ...HookOption)
sso.WithPostAuthHook(name string, hook AuthPipelineHook, opts ...HookOption)
sso.WithPreTokenIssuanceHook(name string, hook AuthPipelineHook, opts ...HookOption)
```

- **优点：** 与项目现有的 `WithXxx` 选项模式完全一致；编译时类型安全；零动态加载风险
- **缺点：** 运行时不可热加载（需重启）；第三方无法编写插件

**选项 B：WASM 钩子（复用 `wasmauthz` 底座）**

```go
// WASM 钩子注册——通过文件系统加载
sso.WithWasmAuthHook("risk_check", "wasm/risk_check.wasm", wasm.Config{
    MemoryLimit: 128 * 1024,   // 128KB
    Timeout:     100 * time.Millisecond,
    OnError:     HookOnErrorFailOpen,
})
```

- **优点：** 运行时热加载；隔离性好（沙箱执行）；第三方可编写钩子
- **缺点：** WASM 编译时类型丢失；调试困难；项目 `wasmauthz` 当前用于授权决策（同步、延迟敏感），用于编排钩子（可异步）需要扩展接口

**推荐：** 两步走——**在 v1 中采用选项 A**（中间件风格），与现有 `WithXxx` 模式一致，零新运行时依赖。**在 v2 中评估选项 B**（WASM 钩子），当需要第三方/客户自编写钩子的需求被验证后。

#### ConsentStore SPI 接口设计

```go
// ConsentStore 是一个面向记录的用户-客户端授权同意存储。
// 这是 GDPR 合法性依据和方向一声明式流程的前置依赖。
// 实现：memory（开发/测试）+ sqlite（生产单节点）+ redis（生产多副本）
type ConsentStore interface {
    // RecordGrant 记录用户对指定 scope 集合的授权同意。
    // 如果同一用户-客户端对相同或更小子集的已授权记录存在且未撤销，
    // 此操作应更新为 scope 的并集。
    RecordGrant(ctx context.Context, grant *ConsentGrant) error

    // HasGrant 检查用户是否已授权指定的 scope 集合。
    // 返回 true 当且仅当：
    //   1. 存在对应该用户-客户端的有效（未撤销）授权记录
    //   2. 该记录的 scope 集合是 requestedScopes 的超集
    // 这确保了 scope 扩展会触发重新同意。
    HasGrant(ctx context.Context, userID, clientID string, requestedScopes []string) (bool, error)

    // ListGrants 返回用户已授权的所有客户端记录。
    // 用于"已授权应用"枚举（自助门户）和 GDPR 数据可移植性。
    ListGrants(ctx context.Context, userID string) ([]*ConsentGrant, error)

    // ListGrantedClients 返回用户已授权的客户端 ID 列表。
    // 用于"撤销已授权应用"的快速枚举。
    ListGrantedClients(ctx context.Context, userID string) ([]string, error)

    // RevokeGrant 撤销用户对特定客户端的授权。
    // 撤销后，任何包含该客户端 scope 的令牌颁发请求都必须重新获得同意。
    // 此操作应触发级联事件（通过 cluster.Bus 传播撤销）。
    RevokeGrant(ctx context.Context, userID, clientID string) error

    // RevokeAllUserGrants 撤销用户对所有客户端的授权。
    // 用于 GDPR 删除用户、账户停用等场景。
    RevokeAllUserGrants(ctx context.Context, userID string) error
}

// ConsentGrant 是一条授权同意记录。
type ConsentGrant struct {
    UserID       string    `json:"user_id"`
    ClientID     string    `json:"client_id"`
    Scopes       []string  `json:"scopes"`
    GrantedAt    time.Time `json:"granted_at"`
    ExpiresAt    *time.Time `json:"expires_at,omitempty"` // 可选：有限期同意
    RevokedAt    *time.Time `json:"revoked_at,omitempty"`
    // 审计追踪
    GrantedByIP  string    `json:"granted_by_ip,omitempty"`
    GrantedByMethod string `json:"granted_by_method,omitempty"` // "interactive" | "admin" | "api"
}
```

**关键设计决策：**
1. **Scope 超集检查** vs 精确匹配：选择超集检查——用户同意了 `openid profile`，后续请求 `openid profile email` 应触发重新同意，而非静默放行
2. **有效期**：可选字段，默认为无限期（GDPR 允许用户随时撤销）；企业租户可配置 `max_consent_ttl`
3. **撤销传播**：`RevokeGrant` 应通过 `cluster.Bus` 发布 `KindGrantRevoked` 事件，CAEP 方向可消费此事件向 RP 推送

#### 声明式流程定义的一致性模型

```yaml
auth_pipeline:
  version: "1"
  steps:
    - name: identify
      provider:
        - password
        - webauthn
        - oidc:okta
      on_error: next_provider
    - name: evaluate_risk
      policy: conditional_access
      on_error: fail_open
    - name: mfa
      if: "risk_score > 0.7"
      providers: [totp, webauthn]
      on_error: fail_closed
```

**架构约束：**
- 流程定义在启动时静态校验（fail-loud），不可在运行时加载语法错误的流程
- 流程版本与 client/tenant 绑定，继承语义：tenant 默认流程 → client 覆盖（仅覆盖指定步骤）
- `if` 表达式必须是纯函数（无副作用、无 I/O、无随机），可静态验证

### 3.2 方向四：组织级治理与委托管理（修正后 P2）

#### 现有 helpdesk 桩代码的复用策略

**代码证据：** `interfaces/admin/deps.go:66` → 注释中的 helpdesk 用户模式；`interfaces/admin/users.go:16-193` → 部分实现的 helpdesk 处理程序（密码重置、MFA 恢复、强制状态更改）。

**架构决策：** 不是将 helpdesk 处理程序从其当前的 `admin:write` 绑定迁移到细粒度 scope，而是采用**双阶段**策略：

**阶段一（审计 + 门禁）：** 在现有 helpdesk 处理程序前插入 scope 检查中间件，验证调用者是否具有 `admin:write.tenant:{tid}/user:password_reset`。此阶段只拒绝不合规请求，不改变处理程序逻辑。

**阶段二（迁移）：** 将 helpdesk 处理程序从 `grpcserver/admin_users.go` 提取到独立的 `handlers/helpdesk.go`，明确绑定到 helpdesk scope，使其不再需要 `admin:write`。

#### Admin 角色模型设计

```go
// 预定义角色——用 permissions 包的 scope 通配符表达
var BuiltInRoles = map[string]ScopeSet{
    "org_admin":     {Scope("admin:read.tenant:{tid}"), Scope("admin:write.tenant:{tid}")},
    "user_admin":    {Scope("admin:read.tenant:{tid}/user:*"), Scope("admin:write.tenant:{tid}/user:*")},
    "audit_viewer":  {Scope("admin:read.tenant:{tid}/audit:*")},
    "helpdesk":      {Scope("admin:write.tenant:{tid}/user:password_reset"),
                      Scope("admin:write.tenant:{tid}/session:revoke")},
    "api_admin":     {Scope("admin:read.tenant:{tid}/api:*"), Scope("admin:write.tenant:{tid}/api:*")},
}
```

**关键设计决策：**
- 不创建新的"角色"表——角色是 scope 通配符的命名组合，`permissions` 包已有完整的通配符匹配器
- 角色在配置时静态定义（`WithBuiltInRoles`），非运行时动态创建（避免角色爆炸）
- 自定义角色是 future work——可委托给外部 IDP 的角色映射

### 3.3 方向二：API 安全产品化（修正后 P3——工作量下调，但优先级不变）

#### 开发者门户扩展架构

由于开发者门户已存在，方向二 (B) 和 (D) 的设计模式从"构建新 SPA"变为"扩展现有 SPA"：

```
现有 SPA 架构：

    /developer/
        ├── index.html          ← 现有入口
        ├── app.js              ← 现有应用入口
        ├── components/
        │   ├── RegisterApp.js  ← 现有 DCR 注册组件
        │   └── AppList.js      ← 现有应用列组件
        └── styles/
            └── main.css
        
扩展：

    /developer/
        ├── components/
        │   ├── ApiKeys.js       ← 新增：API 密钥自助管理
        │   ├── ApiUsage.js      ← 新增：用量仪表板
        │   └── ScopeSelector.js ← 新增：范围选择器（复用于方向四）
        └── api/
            └── developer.js     ← 已有：DCR API 客户端
```

**架构约束：**
- 扩展必须与现有 SPA 的 auth 层兼容（当前使用 bearer token，应与 admin console 的短时 JWT + refresh 模式一致）
- 新增的 API key 管理标签页必须在现有的 SPA 路由结构中运行（不要求前端框架升级）

### 3.4 方向五：多集群联邦（修正后 P3——优先级提升）

#### 通信层选型

评审指出 `mqtt/`、`sse/`、gRPC、`cluster/etcd` 已存在。通信层选型应根据一致性需求：

| 原语 | 一致性 | 延迟 | 适用场景 | 现有代码 |
|------|--------|------|---------|---------|
| etcd cluster.Bus | **线性一致性** | 5-50ms | 强一致撤销传播、全局配置 | `cluster/etcd/` |
| SSE | **at-most-once** | 1-5ms | 跨副本事件流（可容忍丢事件） | `sse/` |
| MQTT | **QoS 0-2 可配** | 10-100ms | 跨区域事件中继（需要持久化订阅） | `mqtt/`（嵌套模块） |
| gRPC | **请求-响应** | 1-200ms | 跨区域写转发、查询 | `grpcserver/` |

**推荐：** 不选择单一原语，而是采用**分层通信架构**：

```
区域 A etcd ──→ 区域 B etcd
    │                  │
    │ 跨区域事件桥       │  （MQTT / SSE relay）
    │                  │
    ▼                  ▼
区域 A 副本 ←─── 区域 B 副本
（gRPC 写转发）
```

- **写路径（强一致）：** 通过 gRPC 转发到 leader 区域——适合 session 写入、令牌颁发
- **事件路径（最终一致）：** 通过 MQTT/SSE 跨区域广播撤销、租户暂停、配置变更——适合可容忍最终一致的通知
- **读路径（本地）：** 本地副本直接服务——适合 `/userinfo`、`/.well-known/jwks.json`

#### SSOConfigDrift CRD 的扩展方向

```yaml
# 现有 CRD（简写）
apiVersion: sso.snaplink.io/v1
kind: SSOConfigDrift
spec:
  cluster: cluster-a
  configType: conditional_access
  drift:
    - field: policies[0].rules[1].action
      expected: "require_mfa"
      actual: "allow"
```

**扩展：**
- 添加 `resolutionStrategy: merge | strict | local_wins` 字段
- 添加 `autoCorrect: true | false`——漂移检测的 CRD controller 可自动将漂移集群回滚到期望状态
- 添加 `complianceMode: true | false`——在合规模式下，漂移是一个审计事件而非阻断事件

### 3.5 方向三：AI-Native 身份运维（修正后 P4——优先级不变）

#### 身份图作为独立交付物

评审建议将 (D) 身份图从方向三的"子项"提升为**具有独立运维价值**的主要交付物。

**架构设计：**

```go
// IdentityGraph 是一个只读查询接口，用于可视化用户-应用-角色-权限关系。
// 它不引入新数据库——数据来自现有 store 的聚合。
type IdentityGraph interface {
    // GetUserAccessPath 返回用户获取特定资源权限的完整路径。
    // 例如：用户 A → 角色 B（通过 group membership）→ 权限 C（RBAC）→ 资源 D
    GetUserAccessPath(ctx context.Context, userID, resourceID string) ([]*AccessPath, error)

    // GetPolicyImpact 返回修改条件访问策略的影响范围。
    // 用于"如果修改此策略，将影响 N 个用户的 MFA 要求"的可视化。
    GetPolicyImpact(ctx context.Context, policyID string) (*PolicyImpact, error)

    // GetUnusedPermissions 返回未使用的权限（90 天内无匹配审计事件）。
    GetUnusedPermissions(ctx context.Context, since time.Time) ([]*UnusedPermission, error)
}
```

**关键设计决策：** 身份图是**物化视图**（materialized view）而非实时查询。数据来自 `audit.Store`、`permissions.Provider`、`core.SessionManager`、`oauth.AuthCodeStore` 的异步聚合。这允许它在现有 store 上构建，不增加热路径延迟。默认每 15 分钟刷新一次，可配置。

---

## 4. 出口连接器框架：横切架构基础设施的详细设计

### 4.1 为什么这是优先级最高的架构基础设施

评审已指出这是横切关注点。让我量化其必要性：

| 方向 | 需要新出站连接的组件 | 无框架时重复实现的特性 |
|------|---------------------|---------------------|
| 方向一 | SSO 连接器（上游 IdP 调用） | 健康检查、超时、熔断、重试 |
| 方向二 | API 网关适配器（Kong/APISIX） | 连接池、认证刷新、证书轮换 |
| 方向三 | LLM API 调用（NL 查询） | 限流、密钥轮换、超时 |
| 方向四 | 无新出站连接 | —— |
| 方向五 | 跨区域通信层 | 连接管理、健康检查、TLS 轮换 |

**总计：** 如果没有框架，上述 4 个方向的 ~10 个新出站连接将产生 **~30 处重复实现**（每个连接 × 3-5 个横切特性）。

### 4.2 框架设计

```go
// platform/egress/connector.go

// Connector 是所有外部依赖的统一抽象。
// 每个外部依赖（KMS、SAML IdP、CAEP webhook、LLM API）都作为一个 Connector 注册。
type Connector interface {
    // Name 返回连接器唯一标识（用于 metrics、health、config）。
    Name() string

    // Health 返回连接器的健康状态。
    // 实现方应检查：TCP 连通性 → TLS 握手 → 应用层探活（如 KMS 可用性）。
    // 状态缓存（默认 5s），不应在热路径上每次调用都发起网络请求。
    Health(ctx context.Context) *HealthStatus

    // RoundTrip 是统一的出站调用方法。
    // 熔断器、舱壁、重试、指标都在此方法中自动注入。
    RoundTrip(ctx context.Context, req *Request) (*Response, error)
}

// ConnectorConfig 是连接器的通用配置。
// 每个具体连接器可在此基础上添加自有配置字段。
type ConnectorConfig struct {
    // 基础连接
    Endpoint   string        `yaml:"endpoint"`
    Timeout    time.Duration `yaml:"timeout" default:"10s"`

    // mTLS
    CertFile   string `yaml:"cert_file"`
    KeyFile    string `yaml:"key_file"`
    CAFile     string `yaml:"ca_file"`

    // 熔断器（可选，nil = 不启用）
    CircuitBreaker *CircuitBreakerConfig `yaml:"circuit_breaker,omitempty"`

    // 舱壁隔离（可选，nil = 不启用）
    Bulkhead *BulkheadConfig `yaml:"bulkhead,omitempty"`

    // 重试（可选，nil = 不重试）
    Retry *RetryConfig `yaml:"retry,omitempty"`

    // 速率限制（可选，nil = 不限流）
    RateLimit *RateLimitConfig `yaml:"rate_limit,omitempty"`
}

// HealthStatus 是健康检查的结果。
type HealthStatus struct {
    Status      HealthStatusEnum `json:"status"`       // healthy | degraded | unhealthy
    LastChecked time.Time        `json:"last_checked"`
    Latency     time.Duration    `json:"latency_ms"`
    Error       string           `json:"error,omitempty"`
}

type HealthStatusEnum int
const (
    HealthStatusHealthy   HealthStatusEnum = iota // 正常
    HealthStatusDegraded                           // 降级（延迟高、部分可用）
    HealthStatusUnhealthy                          // 不可用
)
```

### 4.3 接线点位置

框架本身是基础设施（`platform/egress/`），不引入任何运行时开销。接线点在具体连接器初始化时：

```go
// cmd/.../main.go（操作者侧接线，非核心 SDK）
connector := egress.NewConnector("kms_aws", egress.ConnectorConfig{
    Endpoint: "https://kms.us-east-1.amazonaws.com",
    Timeout:  5 * time.Second,
    CircuitBreaker: &egress.CircuitBreakerConfig{
        Duration:            60 * time.Second,
        MinRequestCount:     5,
        FailureRateThreshold: 0.5,
        OpenDuration:        30 * time.Second,
    },
    Bulkhead: &egress.BulkheadConfig{
        MaxConcurrent: 5,
        MaxWaitDuration: 500 * time.Millisecond,
    },
})

// 作为 sso.With* 选项注入
sso.WithConnector("kms_aws", connector)
```

### 4.4 对现有代码的侵入性

- **注意：** 现有 KMS 客户端、SAML IdP fetcher、CAEP pusher 等都有自己的 HTTP 客户端和连接管理
- **迁移策略：** 框架提供包裹器，将现有客户端包装为 Connector（`egress.WrapExisting(name string, existingClient)`）
- **不强制迁移：** 现有组件可继续使用自有连接，只有新添加的出口连接才需要对接框架
- **渐进采用：** 方向一率先采用，方向二/五在开发时采用，方向三在开发时采用

---

## 5. 一致性模型：跨方向的关键架构决策

### 5.1 覆盖五个方向的一致性需求矩阵

| 数据/操作 | 方向 | 所需一致性 | 当前模型 | 缺口 |
|----------|------|-----------|---------|------|
| Consent 记录 | 方向一 | **CP**（不可丢失同意的记录） | 不存在 | 需构建 |
| 认证流程定义 | 方向一 | AP（最终一致，可 TTL 缓存） | 不存在 | 需构建 |
| API 产品目录 | 方向二 | AP（最终一致） | 不存在 | 需构建 |
| 管理员角色分配 | 方向四 | **CP**（权限变更不可丢失） | 部分（memory store） | 需持久化 |
| 委托授权 | 方向四 | **CP** | 不存在 | 需构建 |
| 跨集群 session | 方向五 | **CP**（令牌语义不可宽松） | 不存在 | 需构建 |
| 跨集群配置同步 | 方向五 | AP（最终一致，漂移检测兜底） | SSOConfigDrift CRD | 需扩展 |
| 身份图 | 方向三 | AP（物化视图，周期性刷新） | 不存在 | 需构建 |
| AI 洞察 | 方向三 | AP（纯上层查询） | 不存在 | 需构建 |

### 5.2 关键决策：ConsentStore 的一致性选择

**选项 A：强一致（CP）**

- 使用 etcd/PostgreSQL 作为后端
- `HasGrant` 始终读取最新数据
- 优点：scope 扩展场景下不可能漏检
- 缺点：每登录路径多一次跨网络读取（5-50ms）；etcd 不可用时登录降级

**选项 B：最终一致（AP）**

- 使用内存 + bus 失效传播
- `HasGrant` 在 TTL 内可能读到旧数据（scope 已撤销但缓存未到期）
- 优点：低延迟（本地读），不存在可用性问题
- 缺点：scope 撤销后至多 TTL（默认 30s）内仍被认为是已同意

**推荐：** **选项 A**——选择 CP。理由：
1. Consent 是 GDPR 合法性依据——丢失同意的记录是合规风险
2. scope 撤销的及时性直接影响安全姿态（"我已撤销某应用的权限，但它还能访问"是用户可见的 bug）
3. 性能影响可控：`HasGrant` 的结果可 TTL 缓存（同意极少变更），`RecordGrant` 和 `RevokeGrant` 才需要强一致写（发生频率低）

### 5.3 关键决策：声明式流程定义的加载策略

**选项 A：启动时全量加载**

- 所有流程定义在 `sso.New()` 时从配置/数据库加载
- 语法校验失败 → `sso.New()` 返回错误
- 优点：fail-loud，不可部署无效配置
- 缺点：流程定义变更需要重启

**选项 B：运行时动态加载**

- 流程定义通过 admin API CRUD
- 语法校验在 API handler 中进行（异步返回错误）
- 优点：零停机变更
- 缺点：复杂（需要有状态的热替换协调）

**推荐：** **选项 A**——与项目现有模式一致（`config/config.go` 的配置也是启动时加载）。**阶段二**再评估选项 B，当热加载需求被验证后。

---

## 6. 技术选型指南

### 6.1 新技术引入决策树

```
这个功能需要引入新的第三方依赖吗？
    ├── 是 → 外部依赖属于"非核心"吗？（如 SDK、网关适配器）
    │        ├── 是 → 放入嵌套模块（仿 `kms/*`、`saml/` 模式）
    │        │        核心 go.mod 不新增依赖
    │        └── 否 → 验证候选库的：
    │                  ├── 许可证兼容性（MIT/Apache 2.0/BSD）
    │                  ├── 安全审计历史（CVE 记录）
    │                  ├── Go 模块兼容承诺（go 1.x）
    │                  └── 替代方案：自建是否可行？（≤200 行？）
    │
    └── 否 → 利用现有能力：
              ├── 遗留：audit.Store → 令牌溯源
              ├── 遗留：permissions → 治理角色
              ├── 遗留：cluster.Bus → 跨副本协调
              ├── 遗留：wasmauthz → WASM 钩子（方向一 v2）
              └── 遗留：config/reload → 热加载模式
```

### 6.2 具体选型建议

| 决策项 | 建议 | 理由 |
|--------|------|------|
| ConsentStore 后端 | memory + sqlite（phase 1）, redis（phase 2） | 与项目现有模式一致；等吞吐需求再加 Redis |
| 声明式流程格式 | YAML + JSON Schema 校验 | 与现有 config 格式一致；Schema 校验已在树 |
| 声明式流程存储 | 配置文件（phase 1），admin API CRUD + Store（phase 2） | 渐进式复杂度 |
| 跨集群通信初始选型 | SSE（跨副本事件）+ gRPC（写转发） | SSE 零新增依赖；gRPC 已在树 |
| 身份图后端 | 现有 store 的异步聚合（无新数据库） | 避免新增有状态依赖 |
| LLM 集成 | OpenAI API + 本地 fallback（无 LLM 降级） | 不锁定供应商；气隙部署可用结构化查询 UI |

### 6.3 决不考虑引入的技术

| 技术 | 建议 | 理由 |
|------|------|------|
| Kafka/CDC 管道 | **不引入** | PostgreSQL 流复制 + 应用层 ReplicaRole 已足够 |
| hystrix-go/resilience4j | **不引入** | 已归档（hystrix-go）或非 Go 生态（resilience4j）；自建 ≤200 行 |
| OPA Rego/Cedar | **阶段二评估** | 当前 `permissions` 通配符 + `conditionalaccess` 策略已够用 |
| GraphQL | **不引入** | 无客户端需要 GraphQL 查询模式；REST + 导出已覆盖 |
| WebAssembly 系统接口（WASI） | **阶段二评估** | WASM 钩子仅在客户需求明确时引入 |

---

## 7. 实施路线图（修正版）

### 7.1 优先级矩阵（接受同行评审的修正）

```
     高 │ 方向一（身份编排）          出口连接器框架（横切）
         │     P1 ─────── 差异化最高          P0 ─── 架构基础设施
         │
 商业    │ 方向四（治理委托）           方向五（多集群联邦）
 价值    │     P2 ─── 最佳工作量/价值比      P3 ─── 成本因 CRD 大幅降低
         │
     中  │ 方向二（API 安全）           方向三（AI 运维）
         │     P4 ─── 市场信号待确认           P5 ─── 身份图可先行
         │
         └──────────────────────────────────────────
           低                            高
                     技术复杂度
```

### 7.2 阶段划分

#### 阶段零：出口连接器框架 + ConsentStore SPI（3-4 周）
*这是所有后续阶段的架构基础设施。*

| 子项 | 工作量 | 产出 | 前置依赖 |
|------|--------|------|---------|
| `platform/egress/` 包（Connector SPI + ConnectorConfig + Health） | M | 统一出站连接框架 | 无 |
| `ConsentStore` SPI + memory impl | M | 同意存储基础 | 无 |
| `ConsentStore` sqlite impl | M | 同意存储生产就绪 | 上方 |
| 方向一 (A) Pipeline Hooks SPI + 中间件注册 | M | 钩子注册表 + 3 个 seam | 无 |
| KMS client 接线到 egress 框架 | S | 首个出站连接器接入 | `platform/egress/` |

**验证标准：** `go build ./...` + `go vet ./...` + `go test ./...` 全绿；ConsentStore 单元测试覆盖 Record+HasGrant+Revoke 三个路径；出口连接器框架的 Health + RoundTrip 通过集成测试。

#### 阶段一：方向一（A）Pipeline Hooks + ConsentStore 整合（3-4 周）

| 子项 | 工作量 | 产出 | 前置依赖 |
|------|--------|------|---------|
| Pipeline Hooks 与 handler.go 的 6 个 seam 整合 | L | 工作管线钩子 | 阶段零钩子 SPI |
| `hasGrant` 在 post-auth 钩子中的调用 | M | 声明式流程前置 | ConsentStore |
| 管道钩子审计事件 | S | 可观测的钩子执行 | 上方 |
| `prompt=consent` 消费 | S | OIDC 一致性 | ConsentStore |
| "已授权应用"枚举 API | M | 自助门户前置 | ConsentStore |

**验证标准：** 用户首次登录时被要求同意 scope → 后续登录不再要求 → 撤销授权后重新要求。`prompt=consent` 被消费（与 ROADMAP v5.0 方向①(a) 一致）。

#### 阶段二：方向四（A）内置管理员角色（2-3 周）

| 子项 | 工作量 | 产出 | 前置依赖 |
|------|--------|------|---------|
| 预定义角色 seed + scope 通配符表达式 | S | 角色定义 | 无 |
| 现有 helpdesk 处理程序 scope 审计门禁 | M | 安全合规 | 角色定义 |
| Admin UI 角色选择器（开发者门户扩展） | M | UI 角色分配 | 角色定义 |

**验证标准：** `admin:write.tenant:{tid}/user:password_reset` 只允许密码重置而不允许修改配置。`admin:write` 用户可看到所有租户 → `org_admin` 只看到自己的租户。

#### 阶段三：方向五（A）（C）跨集群基础（3-4 周）

| 子项 | 工作量 | 产出 | 前置依赖 |
|------|--------|------|---------|
| SSOConfigDrift CRD 扩展 + resolution strategy | M | 策略同步 | 现有 CRD |
| 跨区域 SSE 事件桥 | L | 区域间通信 | 现有 `sse/` |
| 跨区域 gRPC 写转发 | M | 强一致写路径 | 现有 `grpcserver/` |
| 全局 subject mapping（federation_hint claim） | M | 跨集群身份标识 | 无 |

**验证标准：** 双区域部署验证：集群 A 的配置变更 → SSOConfigDrift 检测同步到集群 B。跨区域 session 共享（通过加密 session assertion）。

#### 阶段四：方向二（B）（D）API 安全 + 方向三（D）身份图（3-4 周）

| 子项 | 工作量 | 产出 | 前置依赖 |
|------|--------|------|---------|
| 开发者门户 API 密钥标签页 | M | API key 自助管理 | 现有开发者门户 |
| 范围市场 UI 组件 | S | scope 自助选择 | 开发者门户 |
| IdentityGraph SPI + memory impl | M | 身份可视化 | 无 |
| IdentityGraph 前端组件 | M | 身份图 UI | 上方 |

**验证标准：** 开发者门户中可创建 API 密钥、选择 scope、查看用量。身份图显示用户-应用-角色的完整路径。

### 7.3 风险与缓解

| 风险 | 概率 | 影响 | 缓解 |
|------|------|------|------|
| ConsentStore 的实现复杂度过高（scope 超集检查 + 级联撤销 + 跨副本传播） | M | H | 分步实施：阶段 0 只实现基本 Record/HasGrant/Revoke，阶段 1 再加 bus 传播 |
| Pipeline Hooks 的 seam 位置选择错误导致协议层侵入 | L | H | 6 个 seam 全部位于 `HandlerContext` 内部，不改变 wire contract——如果 seam 位置错了，只需移动钩子调用点，不改变钩子 SPI |
| 出口连接器框架被看作"过度设计" | M | M | 不强制现有连接器迁移；仅新开发需要对接框架；渐进采用 |
| 方向一和 ROADMAP v5.0 的 ConsoltStore 方向重复工作 | L | M | 将 ConsentStore SPI 设计为 ROADMAP 方向①(a) 的直接输出，不在两个方向中做重复实现 |
| SSOConfigDrift CRD 的扩展与现有 controller 冲突 | L | M | CRD 扩展保持向后兼容——新增字段全 optional，默认值与现有行为一致 |
| LLM 集成的成本控制（方向三 | H | L | 不阻止 LLM 集成，但确保所有路径在无 LLM 下降级——方向三 (D) 身份图可在无 LLM 时独立交付 |

### 7.4 与 ROADMAP v5.0 的协作策略

| ROADMAP 方向 | 本文协作策略 | 冲突规避 |
|-------------|-------------|---------|
| ①(a) Consent 存储 | **协作**——本分析的 ConsentStore SPI 设计作为 ROADMAP 方向①(a) 的技术实现规范 | 无冲突——双方指向同一个代码工件 |
| ①(b) Hosted Login SPA | **独立**——本分析不涉及 SPA 构建 | 无冲突 |
| ①(d) Admin Console SPA | **协作**——方向四 (B) 委托管理 UI 构建在 Admin Console SPA 之上 | 需等待 ROADMAP 的 Admin Console 基础框架就绪 |
| ② B2B 企业连接 | **独立**——本分析与方向二无重叠 | 无冲突 |
| ③ OIDC 一致性 | **协作**——方向一 (A) Pipeline Hooks 的"post-auth 钩子"可消费方向③ 修复后的 AMR/AuthTime/ACR 字段 | 钩子 SPI 设计需考虑这些字段的存在性 |
| ④ 多副本韧性 | **互补**——出口连接器框架的熔断器可保护 inter-region gRPC 连接 | 无冲突 |
| ⑤ 安全姿态 | **互补**——方向二 (C) 网关适配器属于扩展的外围，非核心 | 无冲突 |

---

## 8. 架构治理建议

### 8.1 新增的架构约束

| 约束 | 类型 | 适用范围 |
|------|------|---------|
| 所有新的出站连接必须通过 `platform/egress` 框架 | **硬门禁** | 方向一、二、五的新连接器 |
| Pipeline Hooks 必须是纯函数（无 I/O、无随机、无副作用） | **硬门禁** | 方向一 (A) |
| 声明式流程定义必须在 `sso.New()` 时静态校验 | **硬门禁** | 方向一 (B) |
| ConsentStore 必须是 CP（强一致） | **架构决策** | 方向一 |
| 新存储层必须遵循 SPI + memory + sqlite/redis 三件套模式 | **硬门禁** | ConsentStore 等 |

### 8.2 需在架构测试中新增的门禁

```go
// architecture_gate_test.go 新增：
func TestArchitecture_EgressConnectorUsage(t *testing.T) {
    // 检查 platform/egress 包是否被正确引用
    // 所有通过 `WithConnector` 注册的连接器必须实现 egress.Connector 接口
}

func TestArchitecture_PipelineHookPurity(t *testing.T) {
    // 检查 AuthPipelineHook 类型的函数是否引用了 I/O 包
    // （net/http、database/sql、os 等）——如果引用，build 失败
}
```

### 8.3 新增的维护性门禁

| 门禁 | 阈值 | 违规后果 |
|------|------|---------|
| `platform/egress/` 包大小 | ≤ 300 行 | 分割 |
| 每个 Connector 实现 | ≤ 200 行 | 分割 |
| Pipeline Hooks 注册点 | ≤ 10 个 | API 稳定性预警 |
| 每个声明式流程的步骤数 | ≤ 15 步 | 复杂度预警 |

---

## 9. 总结

### 同行评审的三项发现对架构的影响

| 发现 | 对架构的影响 | 对路线图的影响 |
|------|-------------|--------------|
| ① 开发者门户已存在 | 方向二从"新 SPA"缩减为"SPA 扩展" | 工作量从 L→M，但优先级不变（P4） |
| ② ConsentStore 是隐藏障碍 | 方向一 (B) 的半数用例被阻塞 | 将 ConsentStore 提升为阶段 0 交付物；方向一 (A) 可独立先行 |
| ③ SSOConfigDrift CRD + 通信原语已存在 | 方向五从"架构 RFC"缩减为"CRD 扩展工程" | 工作量从 XL→L，优先级从 P5 提升至 P3 |

### 修正后的五方向优先级

| 优先级 | 方向 | 修正后工作量 | 关键前置依赖 |
|--------|------|------------|-------------|
| **P0（横切）** | 出口连接器框架 | M | 无 |
| **P1** | 方向一：身份编排 | XL（含 ConsentStore） | 出口连接器框架（钩子可能调用外部 IdP） |
| **P2** | 方向四：治理委托 | M | 无（独立于方向一） |
| **P3** | 方向五：多集群联邦 | L（现有 CRD 降低门槛） | 出口连接器框架（跨集群通信） |
| **P4** | 方向二：API 安全 | M（SPA 已存在） | 出口连接器框架（网关适配器） |
| **P5** | 方向三：AI 运维 | M（身份图可独立交付） | 出口连接器框架（LLM API） |

### 核心架构原则（新增）

1. **出口统一**：所有出站连接通过 `platform/egress` 框架管理生命周期
2. **Consent 先行**：ConsentStore 是方向一 (B)、方向二 (D)、ROADMAP v5.0 方向①(a) 的共同前置依赖
3. **渐进采用**：新框架不强制现有组件迁移；新功能必须对接
4. **CP 安全边界**：Consent 记录、权限委派、令牌语义必须强一致；其他容忍最终一致
5. **fail-loud 配置**：声明式流程、出口连接器配置在启动时严格校验、失败时拒绝启动
