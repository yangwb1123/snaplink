# 资深架构师 / 产品经理视角：全局扫描与高价值扩展方向

> 基于 2026-07-02 全代码库深度扫描（1600+ `.go` 源文件、55+ 包、7 层架构）。
>
> **声明：** 此前已有 60+ 轮分析文档、200+ 扩展方向覆盖了协议、安全、性能、运维、产品、合规等几乎所有维度。本轮分析与此前所有方向**逐一交叉核验**，聚焦**此前从未被系统性分析的高价值缺口**。
>
> 原则：不写代码。每条锚定具体代码位置或模式。

---

## 总体判断

项目已完成从"身份协议 SDK"到"生产就绪多协议 SSO 平台"的跨越。200+ 方向覆盖了从 OAuth 2.1/OIDC/FAPI/SAML/SCIM/CAEP/Federation 到运维治理、密钥轮换、可观测性、安全纵深防御的广阔维度。**本轮分析聚焦 5 个此前从未被系统性审视的产品/架构方向——它们解决的是"已有能力之间的裂缝"而非"缺少的协议"。**

---

## 方向一：跨租户 B2B 协作模型与外部用户身份（Cross-Tenant B2B Collaboration & External Identity）

### 概况

| 维度 | 值 |
|------|-----|
| 工作量 | **XL**（~2000 行核心逻辑 + 存储 + 前端 + admin API） |
| 价值 | **极高**——企业采购 RFP 必问项，B2B SaaS 核心差异化 |
| 类型 | 产品功能 + 安全模型 |
| 此前覆盖 | 200+ 方向中仅简单提及"跨租户 B2B 协作模型"，未做系统性分析和实现设计 |

### 当前状态验证

当前租户模型（`domains/tenant/`）是完全**竖井式**的：

| 能力 | 状态 | 代码证据 |
|------|------|----------|
| 租户 A 的用户可以访问租户 B 的资源 | ❌ **不存在** | 每个 `Client` 绑定一个 `TenantID`，无跨租户能力 |
| 邀请外部用户（guest user） | ❌ **不存在** | `UserProvider` 没有 "external" 或 "guest" 标记 |
| 跨租户 token exchange | ❌ **不存在** | `Subject` 只绑定一个 identity |
| 外部用户 & 内部用户在同一组织协作 | ❌ **不存在** | 无"成员类型"概念（owner/member/guest） |
| 跨租户审计线索关联 | ❌ **不存在** | Audit 事件仅记录操作者租户，无"原始身份"字段 |
| 邀请流程（邀请链接 + 接受 + 激活） | ❌ **不存在** | 仅有 `Invitation` 结构体（`core/invitation.go`），用于租户成员邀请，非跨租户 |
| 租户间 SCIM 供给（Org A 供给用户到 Org B） | ❌ **不存在** | SCIM 仅为单实例接收器 |

当前跨组织协作的替代路径：

```go
// 1. 唯一的"外部"概念是 Federation Authenticator
domains/authenticators/oidc_federation.go  // 上游 OIDC IdP 认证
infrastructure/saml/sp/                     // 上游 SAML IdP 认证
// 这些都是外部认证，不是外部用户管理

// 2. JIT 成员身份自动供给（WithJITMembership）
// 仅在同一租户内，非跨组织
interfaces/sso/options_passwd.go:349 // WithJITMembership()
```

### 产品价值

B2B SaaS 平台的核心需求——Org A 需要与 Org B 协作者共享资源：

| 场景 | 无此功能 | 有此功能 |
|------|---------|---------|
| 跨公司项目协作 | 每个公司独立注册，数据分离 | Org A 邀请 Org B 用户作为 guest，有限访问项目资源 |
| 代理商管理 | 代理商管理员管理多个客户组织 | 单一身份跨多个客户组织 |
| 供应链协作 | 供应商员工需要额外账号 | 供应商员工用自己公司 SSO 访问当前平台 |
| 收购合并场景 | 两个租户完全隔离，无法融合 | guest → merge 路径，逐步整合 |

### 架构缺口

| 需要的组件 | 当前状态 | 工作量 |
|-----------|---------|--------|
| `ExternalUserStore`——外部用户影子记录 + 源身份映射 | 不存在 | M |
| 跨租户 token exchange grant——将 Org A 的 token 交换为 Org B 的 token | 不存在 | L |
| `TenantCollaboration`——租户间的信任关系和共享配置 | 不存在 | M |
| Guest user 生命周期——邀请、激活、过期、撤销 | 仅有 `Invitation` 模型 | M |
| 跨租户审计事件——`original_subject`/`original_tenant` 字段 | 不存在 | S |
| 跨租户管理 API——邀请管理、guest 用户管理、连接管理 | 不存在 | L |
| 外部用户自助门户——guest 用户可以查看自己的跨租户访问 | 不存在 | M |

### 关键设计与安全模型

- **Guest User 模型**：`User` 增加 `Type` 字段（`member`/`guest`），guest 在宿主租户有影子记录但无独立登录凭据
- **Token Exchange**：guest 用自己的原生 token 交换宿主组织的 scope-limited token（类似 RFC 8693 但跨租户）
- **最小权限**：guest 角色默认只读，宿主组织管理员可以授权 guest 角色
- **邀请生命周期**：邀请链接含加密 payload（目标租户/角色/过期时间），一次使用 + 48h TTL
- **去激活**：宿主租户管理员可以撤销 guest 访问，源身份变更（离职）通过 CAEP 信号传播

### 为什么此前 200+ 方向未覆盖

此前分析聚焦于"已有能力的增强"和"单租户的完整"——SCIM Push、Admin Console、Passkeys、OIDC conformance 等都是单租户视角。跨租户协作是**多租户模型的自然延伸**，但它需要一个完整的产品层设计，不是简单加一个 API 端点。此前方向虽有"跨租户 B2B 协作模型"的提及，但未进行系统性的模型分析和实现路径设计。

---

## 方向二：条件认证策略引擎——可配置的 DAG 认证流（Conditional Authentication Flow Engine）

### 概况

| 维度 | 值 |
|------|-----|
| 工作量 | **XL**（~3000 行引擎 + DSL + 存储 + 集成） |
| 价值 | **极高**——从"固定线性路径"到"任意条件分支"是身份平台的关键跨越 |
| 类型 | 平台能力 |
| 此前覆盖 | 仅有"自适应认证"方向，聚焦风险评分而非流程编排 |

### 当前状态验证

当前认证流程是**固定线性管道**：

```
/auth/login → {认证器校验} → (可选 MFA 挑战) → (可选 Consent) → /token
```

代码证据：

```go
// interfaces/sso/server_finish_login.go 中完整的认证完成逻辑
// 线性调用链：
// 1. HandleLogin → authenticate
// 2. HandleMFA → if mfa_required
// 3. HandleConsent → if consent_required
// 4. HandleToken → exchange
```

**缺失的编排能力：**

| 策略需求 | 当前能否实现 |
|---------|------------|
| "Admin 角色用户登录敏感应用时要求 WebAuthn" | ❌——MFA 是全局配置，无法基于角色/应用/资源条件触发 |
| "从新设备首次登录时增加邮箱验证步骤" | ❌——无设备信誉模块 |
| "中国区用户登录要求短信 MFA" | ❌——MFA 方法选择无条件路由 |
| "已知设备且低风险评分则跳过 MFA" | ⚠️ 部分——RiskScorer 存在但未接入流程决策 |
| "符合 ACR 级别 'phr' 的认证要求" | ❌——ACR 在声明中但未被强制执行 |
| "API 客户端必须使用 mTLS 认证" | ⚠️ 存在（mTLS bound tokens）但非条件式 |
| "refresh token 轮换时重新检查用户状态" | ✅ 部分——有 user active 检查但不够全面 |

**现有基础（可用但未组装）：**

```go
// interfaces/sso/server_mfa.go —— MFA Provider 接口
// interfaces/sso/server_login.go —— 认证结果
// internal/handler/serverdeps.go —— RiskScorer, StepUpACR 等
// domains/authenticators/webauthn/mfa.go —— WebAuthn MFA
// security/step_up_auth.go —— Step-Up ACR 验证
// spi/risk.go —— RiskScorer 接口
```

### 架构设计

```
认证策略 DSL (YAML) → 编译为 DAG →
  执行引擎依条件分支执行节点 →
    节点类型: {认证, MFA 挑战, 同意, webhook, 重定向, 拒绝}

示例策略:
flows:
  default:
    - authenticator: password
    - if: ${risk_score > 0.7 || device.unknown}
      then:
        - mfa: webauthn
    - if: ${required_acr == "phr"}
      then:
        - mfa: totp
    - consent: auto

  api_access:
    - authenticator: client_credentials
    - if: ${client.mtls_required}
      then:
        - verify: mtls
```

### 核心组件

| 组件 | 说明 | 是否需要新代码 |
|------|------|--------------|
| **Flow DSL 解析器** | YAML-based 策略定义，编译为 DAG | **全新** |
| **Flow 执行引擎** | 运行时 DAG 执行，条件分支，状态传递 | **全新** |
| **条件表达式求值器** | `${risk_score > 0.7}` 等表达式的求值 | **全新** |
| **认证节点库** | 现有认证器包装为可执行节点 | 适配（现有认证器包装） |
| **MFA 节点路由器** | 按条件路由到不同的 MFA 方法 | 适配 |
| **Webhook 节点** | 认证流程中回调外部系统 | **全新** |
| **Fallback 策略** | 所有条件不匹配时的默认路径 | **全新** |

### 为什么此前未覆盖

此前分析的"自适应认证"方向专注于风险评分和动态 MFA 触发，但**没有涉及"可编程的认证流程"**——这是一个更根本的平台能力，是 Keycloak Authentication Flows / Auth0 Actions / Azure AD Conditional Access 的等价物。它是一个完整的编排层，不只是给现有管道加一个条件检查点。

---

## 方向三：产品级控制面风险管控与运营治理框架（Admin Control Plane Governance & Abuse Prevention）

### 概况

| 维度 | 值 |
|------|-----|
| 工作量 | **L**（~1500 行核心 + admin API 调整 + 测试） |
| 价值 | **高**——运维安全 PoC / SOC2 合规需求 |
| 类型 | 安全纵深 + 运维治理 |
| 此前覆盖 | 仅有单点提及（Admin 速率限制、管理员会话等），未做系统性框架设计 |

### 当前状态验证

Admin API（gRPC + REST gateway）当前状态：

```go
// interfaces/grpcserver/grpcadmin/ —— admin CRUD
// interfaces/admin/middleware.go —— authz interceptor

var adminRoutes = []struct{ ... }{
  // 全部 CRUD 操作直接对存储执行
  // 无操作频率限制（除最近添加的 WithAdminRateLimit）
  // 无敏感操作确认
  // 无变更审批
  // 无操作验证（ValidatingAdmissionHook 模式）
}
```

**具体缺口矩阵：**

| 治理需求 | 当前状态 | 最近变更 |
|---------|---------|---------|
| per-endpoint 速率限制 | ✅ **新加** `WithAdminRateLimit` | git: e375997 |
| 敏感操作二次确认（`POST /clients/:id/delete` 需确认参数） | ❌ 不存在 | — |
| 写操作配额（tenant A 每小时内最多创建 10 个 client） | ❌ 不存在 | — |
| 并发管理员会话限制 | ⚠️ 会话管理存在但未绑定 admin 登录 | — |
| 管理员操作地理约束 | ❌ 不存在 | — |
| 跨管理员冲突检测（同时编辑同一 client） | ❌ 不存在 | — |
| 变更审批工作流（创建 client → 待审批 → 激活） | ❌ 不存在 | — |
| 操作回滚（undo last operation） | ❌ 不存在 | — |
| 管理端变更通知（管理员操作通知其他管理员） | ❌ 不存在 | — |
| 管理 API 敏感字段掩码（secret 永不回显） | ⚠️ 部分——大多数 secret 不回显但未统一框架 | — |
| 操作原因声明（所有写操作需附带 reason 字段） | ❌ 不存在 | — |
| 管理 IP 白名单（仅特定 CIDR 可访问 admin） | ❌ 不存在 | — |

### 产品设计

**三层治理模型：**

```
Layer 1: 防护（Prevention）
  ├── 速率限制（per-endpoint, per-admin, per-IP）✅ done
  ├── 敏感操作确认（DELETE / PUT 需 reason + confirm 参数）
  ├── 写操作配额（per-tenant / per-admin 的时间窗口配额）
  └── IP 白名单 / 地理锁定

Layer 2: 审核（Review）
  ├── 操作预审（Pending changes）
  ├── 管理员冲突检测
  └── 变更影响分析（"删除这个 client 会影响 500 个活跃用户"）

Layer 3: 审计（Audit）
  ├── 操作原因审计
  ├── 失败尝试审计（谁在试图做什么而被限/拒）
  └── 管理行为分析（异常管理行为检测）
```

### 关键实现组件

| 组件 | 说明 |
|------|------|
| `AdminWriteQuota`——写配额计数器 + 超阈值阻拦 | 基于 `TenantQuotaStore` 扩展 |
| `DestructiveActionGuard`——DELETE 操作的二次确认 | 新增中间件层 |
| `AdminConflictDetector`——基于 keyed mutex 的并发编辑保护 | 复用 `keyed_mutex` 模式 |
| `ChangeApprovalWorkflow`——审批队列 + Webhook 通知 | 全新，依赖 cluster bus |
| `AdminSessionManager`——管理员专用会话管理 | 复用 `SessionManager` 扩展 |
| `AdminAuditRecorder`——管理操作审计（包含 reason、旧值、新值） | 已有 `Recorder` 扩展 |

### 为什么此前未覆盖

此前 200+ 方向中，虽然有零散提及 "Admin 速率限制"（最近已实现）、"管理员会话管理"、"缺少变更通知"等，但**没有从"控制面风险管控"的完整产品视角进行分析**。这不是单一功能的缺失，而是一个系统性的运维治理框架——类似于云平台（AWS IAM / GCP IAM）的 admin protection suite。最近刚合并的 `WithAdminRateLimit` 是 Layer 1 的开始，但整个治理框架（3 层共 8 个组件）需要统一设计。

---

## 方向四：资源服务器（RS）Token 生命周期智能与分析平台（Token Lifecycle Intelligence for Resource Servers）

### 概况

| 维度 | 值 |
|------|-----|
| 工作量 | **M**（~800 行后端 + ~400 行前端 + 新 gRPC 服务） |
| 价值 | **高**——帮助 RS 理解 token 生态的安全状况和使用趋势 |
| 类型 | 产品功能 + 运维可视化 |
| 此前覆盖 | 零覆盖——所有分析均从 IdP 视角出发，未考虑 RS 视角 |

### 当前状态验证

当前 RS 可用的工具：

| 能力 | API | 限制 |
|------|-----|------|
| 单个 token 验证 | `/userinfo`, `ValidateToken(client)` | 返回 token 是否有效，无聚合信息 |
| 单个 token 自省 | `/token/introspect` | 单个 token，无批量/聚合 |
| 列出所有活跃 token（admin） | `TokenLister.ListActive()` | admin-only，全局视角，未按 RS 分片 |
| 获取 JWKS 密钥 | `/.well-known/jwks.json` | 仅公钥，无 token 元信息 |
| 订阅 token 状态变化 | ❌ **不存在** | 无 RS 可订阅的事件通道 |

**缺口分析：**

```go
// 当前 RS 验证路径
// ssoclient/remote/auth.go —— ValidateToken 方法
// 只能回答"这个 token 有效吗？"
// 无法回答：
//   - "我的应用程序有多少活跃用户？"
//   - "最近我的 token 使用量是否有异常增长？"
//   - "有多少 token 即将在 24h 内过期？"
//   - "我的 token 有哪些 scope 组合？"
//   - "是否有同一个用户从多个设备高频刷新 token？"
```

### 产品设计

**Token Intelligence Service**——面向 RS 的 token 分析平台：

```
RS 注册（指定 client_id）
  → 获取专属 API Key / 证书
  → 使用 TokenIntelligence gRPC/REST API
```

| API | 说明 |
|-----|------|
| `TokenStats(client_id)`——聚合指标 | active user count, token distribution, avg TTL, top scopes |
| `TokenExpiryForecast(client_id, window)`——过期预警 | 未来 N 小时内过期的 token 数量/用户 |
| `SuspiciousTokenActivity(client_id)`——异常检测 | 同一 token 多 IP 使用、高频刷新、异常地理分布 |
| `TokenUsageTrend(client_id, period)`——趋势分析 | 日/周/月的签发量、验证量、撤销量 |
| `SubscribeTokenEvents(client_id)`——事件订阅 | 实时推送 token 状态变化（过期、撤销、刷新） |

### 实现基础

已有可直接复用的组件：

```go
// 1. IntrospectionCache —— 已有 token 验证缓存
oauth/introspect_cache.go

// 2. TokenLister —— 已有活跃 token 枚举
core/spi.go: ListActive() ([]TokenMeta, error)

// 3. Audit Recorder —— 已有 token 签发/撤销/验证事件
platform/audit/recorder_events.go

// 4. Anomaly Detection —— 已有异常检测框架
domains/anomaly/

// 5. TokenIssuer 统计接口
// 现有 Issuer 可以扩展为 TokenStatProvider 接口
```

### 为什么此前未覆盖

所有 200+ 方向的分析视角都是 **IdP 视角**（"我如何更好地发出 token"）或 **RP/应用视角**（"我如何验证 token"）。**资源服务器（RS）视角**——那些持有和消费 token 的后端服务——从未被考虑。这是产品去中心化授权故事的最后一公里：让每个服务理解其 token 生态。这与 Token Governance 方向有重叠但完全不同——Token Governance 是管理 token 生命周期的策略，Token Intelligence 是 visibility/debugging 工具。

---

## 方向五：全局声明式多集群配置治理与 GitOps 原生集成（Declarative Multi-Cluster Config Governance & GitOps Native Integration）

### 概况

| 维度 | 值 |
|------|-----|
| 工作量 | **L**（~1200 行核心 + 工具 + 文档 + CRD 定义） |
| 价值 | **高**——GitOps 模式运营多集群 SSO 是云原生运维的必由之路 |
| 类型 | 运维基础 + 治理 |
| 此前覆盖 | 有方向提及"声明式配置 Schema 与 GitOps 验证管道"，但聚焦单集群配置验证，未覆盖多集群和配置一致性治理 |

### 当前状态验证

当前配置模型：

```yaml
# config.yaml —— 单集群配置
# 低→高：file < env (`SSO_SERVER__LISTEN=:9090`) < etcd (opt-in) < flags
```

```go
// config/ —— 配置加载器
// 支持文件/环境/etcd/flag，但全生命周期无以下能力：
//   1. 多集群配置一致性验证
//   2. 配置漂移自动检测与修复
//   3. GitOps 驱动的配置同步
//   4. 配置版本控制与回滚
//   5. 灰度配置发布（先蓝后绿/金丝雀）
```

**核心缺口：**

| 运维需求 | 当前状态 |
|---------|---------|
| 多集群配置一致性保证（prod-us / prod-eu 配置一致） | ❌ 人工同步 |
| 配置漂移自动检测 | ❌ 不存在 |
| GitOps（git push → SSO 集群配置自动更新） | ❌ 不存在 |
| 配置版本化与回滚 | ⚠️ 仅 `bootstrap` tracker 记录版本号 |
| 灰度配置发布（5% 流量使用新配置） | ❌ 不存在 |
| 配置影响分析（修改此配置会如何影响集群） | ❌ 不存在 |
| 跨集群/跨区域的配置差异可视化 | ❌ 不存在 |
| 配置模式验证（schema-based config validation） | ✅ 部分——recent `--validate-only` flag |

### 架构设计

```
Git Repository (声明式配置)
  ↓
Config Controller (operator)
  ↓
Config Validation (schema + cross-reference + impact analysis)
  ↓
Config Distribution (etcd / gRPC sync)
  ↓
SSO Cluster (多副本应用配置)
  ↓
Config Drift Detection (定期 reconcile)

组件说明:
├── CRD 定义 (Kubernetes CRD: SSOConfig, SSOCluster, SSOTenant)
├── Config Controller (Operator: 监控 ConfigMap/CRD 变更)
├── Config Validator (schema → cross-cluster → impact)
├── Config Distributor (发布到 etcd 或直接 gRPC push)
├── Config Reconciler (定期拉取、检测漂移、自动修复)
└── Config Auditor (记录配置变更历史 + who changed what + 结果)
```

### 具体组件

| 组件 | 说明 | 工作量 |
|------|------|--------|
| **Config CRD**——Kubernetes 自定义资源定义 | 声明式 SSO 配置（client, tenant, auth, policy 等） | M |
| **Config Operator**——控制器监控 CRD 变更 | 验证 + 转换 + 发布到集群 | L |
| **Config Diff Engine**——跨集群配置差异检测 | 两个 cluster 的配置 diff + 一致性报告 | M |
| **Config Drift Detector**——定期 reconcile | 检测 etcd 中配置与 CRD 声明的差异 | M |
| **Config Impact Analyzer**——变更影响分析 | "修改 client X 的 redirect_uri 会影响 3 个集成" | M |
| **Config Rollback Controller**——配置回滚 | 一键回滚到上一个已知好配置 | S |

### GitOps 工作流

```
开发者: git push config/cluster-us.yaml
  → CI: 配置 schema 验证 + 跨集群一致性检查
  → CD: Config Controller 检测到 CRD 变更
  → Phase 1: 验证配置在 staging 集群生效（smoke test）
  → Phase 2: 发布到 prod-us 集群（5% canary → 100%）
  → Phase 3: 配置 reconcile + 漂移检测
  → Phase 4: 配置审计记录
```

### 为什么此前未覆盖

此前方向虽有"声明式配置 Schema 与 GitOps 验证管道"的提及，但**仅聚焦于单集群的配置验证和 schema 校验**。本方向将其扩展为**多集群配置治理的完整框架**——包括配置漂移检测（跨集群对比）、GitOps 原生集成（K8s CRD + Controller 模式）、配置影响分析、灰度发布等。这是从"可以管理一个集群"到"可以一致地管理 N 个集群"的跨越。近期合并的 `--validate-only` 和 `config-validate-all` 是此方向的第一步基础。

---

## 优先级排序

| 优先级 | 方向 | 努力 | 价值 | 依赖 | 建议启动 |
|--------|------|------|------|------|---------|
| **P0** | 方向三：Admin 治理框架 | L | 高 | 已有 `WithAdminRateLimit` 基座 | **立即** |
| **P1** | 方向四：RS Token Intelligence | M | 高 | 依赖 `TokenLister` + Audit | **下一 sprint** |
| **P1** | 方向五：多集群配置治理 | L | 高 | 依赖 K8s CRD / Operator | 下一 sprint |
| **P2** | 方向一：跨租户 B2B 协作 | XL | 极高 | 依赖 tenant + connections 模型 | 专项立项 |
| **P2** | 方向二：条件认证策略引擎 | XL | 极高 | 大型架构变化 | 设计先行 |

### 一句话建议

**方向三（控制面治理）和方向四（RS 智能）是快速见效的安全/产品差异化项——立即启动。方向五（多集群 GitOps）是运维质变项——设计后可并行。方向一（B2B 协作）和方向二（条件认证流）是架构级能力——需要专项设计和分阶段交付。**

---

## 与已有 200+ 方向的关系矩阵

| 本轮方向 | 最接近的已有方向 | 关键差异 |
|---------|----------------|---------|
| 一：B2B 协作 | "跨租户 B2B 协作模型" | 已有方向仅提及概念；本轮给出了完整的模型定义（guest user、跨租户 token exchange、邀请生命周期、审计关联）和实现路径 |
| 二：条件认证流 | "自适应 / 风险等级驱动的动态认证" | 已有方向聚焦风险评分；本轮提出了完整的 DAG 编排引擎（DSL、执行器、节点库），不仅是条件判断 |
| 三：Admin 治理 | 零散提及（admin 限流、admin 会话、变更通知） | 已有方向为单点功能；本轮设计了 3 层治理模型（防护→审核→审计），共 8 个组件的完整框架 |
| 四：RS 智能 | ❌ 无对应方向 | 完全从 RS 视角出发的 token 分析平台——此前所有方向均为 IdP/RP 视角 |
| 五：多集群 GitOps | "声明式配置 Schema 与 GitOps 验证管道" | 已有方向聚焦单集群 schema 验证；本轮扩展为多集群（drift detection、CRD Operator、canary 发布、impact analysis） |

---

## 附录：代码库关键统计

| 维度 | 数据 |
|------|------|
| Go 源文件 | ~1639 |
| 包（目录） | ~150 |
| 架构层 | 7（shared → domains → protocols → platform → infrastructure → interfaces → cmd） |
| 存储实现后端 | 4（memory / sqlite / redis / postgres） |
| 嵌入 SPA | 3（login / admin / portal） |
| 认证器类型 | 9+（password, TOTP, SMS, Email, WebAuthn, OIDC Federation, LDAP, Kerberos, RADIUS + SAML） |
| 协议支持 | 10+（OAuth 2.1, OIDC, SAML 2.0, SCIM 2.0, FAPI 2.0, CAEP, Federation, CIBA, Device, Token Exchange） |
| 已有分析文档 | ~65 个 .md 文件、数百页分析 |
| 已有扩展方向 | 200+（跨 60 个方向文件） |
| 本轮新增方向 | 5（均经过交叉核验，确认为此前未覆盖的真缺口） |
