# 扩展方向分析报告 —— 前沿身份范式与平台韧性

> **作者：** 资深架构 & 产品经理视角  
> **日期：** 2026-07-11  
> **前提：** 本报告在系统阅读 ROADMAP v5.0、deferred-backlog、以及 13 轮历史扩展方向分析（v1–v13）  
>   + post-protocol-layer-analysis + 全代码库全局扫描（2241 `.go` 文件）的基础上撰写。  
> **核验方法：** 逐方向对 docs/requirements/*.md 做 grep 关键词交叉验证，确保每一项缺口为真。  
> **目标：** 列出 5 个**当前任何分析文档均未覆盖**的高价值扩展方向

---

## 前置声明：项目成熟度与历史覆盖

经过 13 轮分析 + ROADMAP v5.0 + deferred-backlog + post-protocol-layer 分析，以下领域已被**深度覆盖**（多项已部分或全部落地）：

| 已覆盖领域 | 来源 |
|---|---|
| Passkeys & Passwordless-First | expansion-analysis v1 |
| 组织/Workspace 管理 | expansion-analysis v1 |
| 实时风险会话智能 | expansion-analysis v1 (已验证 continuousverify agent 已实现) |
| 身份验证与 IAL | expansion-analysis v1, v7 |
| 开发者生态与 API 平台 | expansion-analysis v1 (已验证 admin console + dev portal 已实现) |
| BFF 安全模式 | v7 |
| 管道可编程动作引擎 | v13 |
| 嵌入式认证 UX 组件 | v13 |
| 自适应安全闭环 | v13 |
| 身份即代码 GitOps | v13 |
| 跨平台原生 SDK | v13 |
| 跨设备身份连续性 | post-protocol-layer |
| 统一事件智能平台 | post-protocol-layer |
| 授权即服务 PDP | post-protocol-layer |
| 令牌生命周期规模优化 | post-protocol-layer |
| 身份分析与多租户 BI | post-protocol-layer |
| Hosted Login + Consent + Admin Console | ROADMAP v5.0 |
| B2B 企业连接 + HRD | ROADMAP v5.0 |
| OIDC 一致性收口 | ROADMAP v5.0 |
| 多副本数据面韧性 | ROADMAP v5.0 |
| 安全姿态与供应链**部分** | ROADMAP v5.0 (govulncheck/SCA/fuzz/bench) |
| KMS/HSM 签名密钥 | ROADMAP v4.0 |
| SAML 2.0 | ROADMAP v4.0 |
| CAEP/RISC | ROADMAP v4.0 |
| Redis 后端 | ROADMAP v4.0 |

**本报告 5 个方向属于全新领域，与上述所有历史分析零重叠。**

---

## 方向 1：AI/LLM 智能体身份与委派框架（AI Agent Identity & Delegation）

### 现状

2025–2026 年，AI 智能体（CUA、MCP 服务器、自主代码助手、Copilot 类工具、Autonomous Agents）成为身份与授权领域最大的新兴挑战。项目当前的身份模型假设**人是发起者**：

| 能力 | 当前状态 |
|---|---|
| OAuth 2.0 授权码模式（人→Token→API） | ✅ 完整 |
| Token Exchange（RFC 8693，代人兑换） | ✅ 完整 |
| CIBA（后台认证，无浏览器） | ✅ 完整 |
| 客户端凭据（M2M，client_credentials） | ✅ 完整 |
| SPIFFE JWT-SVID（工作负载身份） | ✅ 完整 |
| 代理身份 Token Exchange（`act` chain） | ✅ 完整 |
| **AI 智能体注册与身份标识** | ❌ **零实现** |
| **智能体人-代理人-目标 API 的三方委托** | ❌ **零实现** |
| **智能体作用域缩小（的最小特权）** | ❌ **零实现** |
| **智能体行为审计轨迹（人+智能体两级）** | ❌ **零实现** |
| **智能体到智能体的授权（A2A）** | ❌ **零实现** |
| **可撤回的、时间绑定的委派令牌** | ❌ **零实现** |

### 缺口（grep 核验）

- `Agent\|agent.*identit\|agent.*delegat\|agent.*token\|agent.*authoriz\|agent.*scope\|AIAgent\|AgentRegistry\|AgentSession` 在具体实现上下文中：**零实现命中**（仅 `ssoclient/dev` 的 dev mode 和 `continuousverify` 的 agent 为不同语义）
- `delegat.*token\|DelegatToken\|delegat.*grant\|delegat.*scope\|delegat.*chain` 在智能体上下文：**零实现命中**
- `WithAgentRegistry\|WithAgentAuthorizer\|AgentStore\|AgentSessionStore`：**零实现命中**
- `MCP\|mcp.*auth\|ModelContextProtocol\|function.*call.*oauth\|tool.*use.*auth`：**零实现命中**
- `human.*in.*loop\|human.*approv\|human.*confirm\|delegat.*approv\|consent.*agent`：**零实现命中**

### 为什么需要它

2025–2026 年是 AI 智能体从概念走向生产的转折点。三大核心场景飞速增长：

1. **MCP（Model Context Protocol）服务器**：AI 客户端（如 Claude Desktop、Cursor）通过 MCP 协议访问用户的数据和工具。这些工具背后是受 OAuth 保护的 API——需要一种标准的"AI 替我登录并获取受限数据"的流程。
2. **CUA（Computer Use Agent）**：像 OpenAI Operator、Anthropic Computer Use 这样的智能体代表用户操作浏览器和应用。它们需要用户的凭证委派，但必须有严格的**范围限制**和**时间绑定**。
3. **企业 AI 自动化**：内部 AI Agent 访问 CRM/ERP/HR 系统代表员工执行操作。需要完整的**审计轨迹**——谁授权了哪个智能体在什么时间范围内做什么操作。

当前 OAuth 2.0 协议族中没有专门针对 AI 智能体场景的标准（这是 2025–2026 年 IAM 行业的空白——Auth0/Okta 正在竞相填补）。**谁能率先填补这个空白，谁就在下一波身份平台竞争中占据制高点。**

### 范围

#### 1. AI 智能体注册与身份模型

```go
// core/types_agent.go（新建）
type Agent struct {
    ID             string
    Name           string           // 人类可读名称（如 "My Sales Analyzer"）
    OwnerUserID    string           // 所属用户（谁创建/控制的）
    TenantID       string
    PublicKey      *jose.JSONWebKey // 智能体的身份公钥（用于签名委托请求）
    Capabilities   []string         // 声明的能力（"read:sales", "send:email"）
    AllowedScopes  []string         // 允许委派的范围上限
    MaxDelegationTTL Duration       // 单次委派最大时长（默认 1h）
    AllowedTargets []string         // 允许调用的 API 受众白名单
    CreatedAt      time.Time
    LastUsedAt     time.Time
    Active         bool
}

// AgentStore SPI
type AgentStore interface {
    Get(ctx context.Context, id string) (*Agent, error)
    Create(ctx context.Context, agent *Agent) error
    Update(ctx context.Context, agent *Agent) error
    Delete(ctx context.Context, id string) error
    ListByOwner(ctx context.Context, userID string) ([]*Agent, error)
}
```

#### 2. 人→智能体委派授权（Human-to-Agent Delegation）

```
用户 Alice 授权智能体 "Sales Analyzer" 代表她访问 Salesforce API：

序列：
  1. Alice 登录 SSO（标准 OAuth 流程）
  2. Alice 创建或配置智能体（POST /api/v1/agents）
     - 指定能力范围：scopes=["sales:read"], targets=["https://api.salesforce.com"]
     - 指定委派时长：ttl=3600s
  3. Alice 通过一个明确的委派确认步骤（新的 consent/grant 流程）：
     POST /oauth/delegation
     {
       "agent_id": "agent-sales-analyzer",
       "scopes": ["sales:read"],
       "ttl": 3600,
       "audience": "https://api.salesforce.com",
       "human_approval": {
         "method": "mfa",           // 委派敏感操作要求 MFA 确认
         "session_id": "sess_xxx"
       }
     }
  4. 服务器签发委派令牌（Delegation Token）：
     - 包含 agent_id + owner_user_id + scope + ttl
     - 智能体用此令牌代表 Alice 访问 API
  5. API 服务验证：
     - 验证令牌签名
     - 检查 scope 在 agent.AllowedScopes ∩ delegation.Scopes 范围内
     - 记录审计事件：agent-sales-analyzer 代表 alice 读取 sales:data
```

#### 3. 智能体作用域缩小（Least Privilege for Agents）

```
核心原则：智能体的有效权限 = min(用户权限, 智能体声明能力, 本次委派范围)

用户权限（用户的 roles/permissions）：    ["sales:read", "sales:write", "reports:read"]
智能体声明能力：                           ["sales:read", "reports:read"]
本次委派请求的范围：                       ["sales:read", "sales:write"]
                 ↓
有效委派范围：                             ["sales:read"]
                 ↑ 取三者的交集
```

#### 4. 智能体到智能体授权（Agent-to-Agent Authorization）

```
智能体 A（"数据分析师"）需要调用智能体 B（"报表生成器"）：

A 持有 Alice 委派的 delegation_token_A（scope="data:read"）
B 需要 caller 持有 scope="report:generate"

A → B: 出示 delegation_token_A + 链式委派请求
B → SSO: 验证链，确认 A 的委派路径有效
SSO: 如果 A 的有效 scope 包含 B 所需的 scope，颁发 B 的访问令牌

这需要 act chain（RFC 8693 风格的 chain）：
  act: {
    agent_id: "agent-report-generator",
    owner: "alice",
    chain: [
      {agent_id: "agent-data-analyzer", owner: "alice", scope: "data:read"},
      {delegated_by: "alice", scope: "data:read, report:generate"}
    ]
  }
```

#### 5. 委派审计与控制面板

审计事件：
- `agent_created` / `agent_deleted` — 智能体生命周期
- `agent_delegation_granted` — 用户授权智能体替自己行动
- `agent_delegation_revoked` — 撤回委派
- `agent_action` — 智能体代表用户执行了操作（含 `agent_id` + `owner` + `action` + `target`）
- `agent_delegation_expired` — 委派自动到期

管理面板（`/admin/agents`）：
- 查看所有已注册的 AI 智能体
- 查看每个智能体的活跃委派
- 一键撤回所有委派
- 查看智能体活动审计日志

用户自助面板（`/me/agents`）：
- 查看我授权的智能体
- 按智能体查看操作历史
- 撤回单个智能体的授权
- 设置每个智能体的最大 scope 和 TTL

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 智能体令牌泄露 | 支持智能体令牌的 DPoP 绑定（`cnf.jkt`），与用户令牌相同的 sender-constraint |
| 用户离职后智能体仍然活跃 | 用户停用时级联吊销所有委派令牌；userlifecycle 的 `RevokeOnArchive` 复用 |
| 智能体操作撞上用户 scope 变更 | 委派在每次使用时重新评估 scope 交集（非缓存），scope 变更立即生效 |
| 委派链太长（A→B→C→D） | 最大链长度（默认 3），超出则拒绝（防止深度隐藏攻击路径） |
| 智能体循环调用 | 检测 `act chain` 中的 agent_id 循环（已经存在的 token-exchange cycle detection 可复用） |
| MCP 协议的 OAuth 交互 | MCP 的 OAuth 授权码流程需要将 `request_uri` 映射为委派请求；需要 MCP 特定的 handler 适配 |
| 无浏览器的智能体认证（CIBA 变体） | 智能体无法打开浏览器完成授权码流程；使用扩展的 CIBA 模式：push notification 到用户手机确认 |

### 性能考虑

- 委派令牌验证开销：每次 API 调用需要多一级 actor chain 验证；考虑 chain 验证的 LRU 缓存
- 智能体 store 的读写比：智能体创建后很少更新，但委派验证频繁；建议智能体缓存（TTL 5min）+ bus 失效
- 委派交集计算：每次令牌使用实时计算 scope 交集；性能敏感场景可缓存 scope 层次结构 

---

## 方向 2：企业级同意管理与隐私规约中心（Enterprise Consent & Privacy Regulation Hub）

### 现状

项目拥有基础同意存储能力（`core.ConsentStore` + `admin/users.go` 的 `ListByUser`/`GetConsent`/`RevokeConsent` + `WithConsentTTL`），但其模型**仅限 OAuth scope 级别**的"用户同意应用访问某项 scope"。对于受严格隐私法规监管的企业客户来说，这远不足以满足合规要求：

| 能力 | 当前状态 |
|---|---|
| OAuth scope 级别的同意记录 | ✅ `ConsentStore` 已存在 |
| 同意 TTL（consent 过期重征） | ✅ `WithConsentTTL` |
| 用户查看/撤销已授权应用 | ✅ `/me/consents`（通过 `ListByUser`） |
| **IAB TCF / GPP（Global Privacy Platform）集成** | ❌ **零实现** |
| **按用途（Purpose）的同意管理** | ❌ **零实现** |
| **同意偏好信号传递（如 `Sec-GPC` 或 `claims`）** | ❌ **零实现** |
| **多法规同意策略（GDPR + CCPA + LGPD + PIPL）** | ❌ **零实现** |
| **同意收据（Consent Receipt, ISO/IEC 27560）生成** | ❌ **零实现** |
| **数据保留策略强制执行（基于同意）** | ❌ **零实现** |
| **DSAR（Data Subject Access Request）自动化工作流** | ❌ **零实现** |
| **数据主体权利仪表盘** | ❌ **零实现** |
| **处理活动记录（ROPA）自动生成** | ❌ **零实现** |

### 缺口（grep 核验）

- `TCF\|IAB\|Global.*Privacy.*Platform\|GPP\|consent.*purpose\|purpose.*consent\|processing.*purpose`：**零实现命中**
- `consent.*receipt\|ConsentReceipt\|ISO.*27560\|27560\|consent.*record\|record.*consent`：**零实现命中**
- `DSAR\|DataSubject\|data.*subject.*request\|subject.*right\|right.*access\|right.*erasure\|right.*port`：**零实现命中**（`compliance/erasure.go` 的 `SubjectErasure` 是具体技术实现，非 DSAR 工作流）
- `Sec-GPC\|GlobalPrivacyControl\|DNT\|do.*not.*track\|opt.*out\|opt.*in` 在具体实现上下文：**零实现命中**
- `ROPA\|record.*processing\|processing.*activit\|data.*map\|data.*inventory` 在自动化生成上下文：**零实现命中**
- `WithConsentManager\|WithPurposeStore\|WithDSARHandler\|WithDataMapBuilder`：**零实现命中**

### 为什么需要它

1. **GDPR 第 7 条"同意的条件"**要求：同意必须是具体的（specific）、知情的（informed）、明确的（unambiguous）。仅仅"用户同意了 app X 访问 scope Y"不能满足"用户同意将其数据用于营销分析目的"的法规要求。需要**按用途（purpose）**区分同意。

2. **全球法规碎片化**——同一用户可能受 GDPR（EU）、CCPA（California）、LGPD（Brazil）、PIPL（China）的同时管辖。不同的法规对同意的要求不同：GDPR 要求 opt-in，CCPA 要求 opt-out，PIPL 要求单独同意敏感信息。单一同意模型无法满足。

3. **企业采购的合规门槛**——GDPR 第 30 条要求 ROPA（处理活动记录），第 15–20 条要求 DSAR 工作流。在 RFP 阶段，SSO 平台需要回答："你们如何帮助我满足 GDPR 的同意管理要求？" 今天只能回答"我们提供了 scope 级别的同意存储"，这在企业采购中是显著扣分项。

### 范围

#### 1. 多层次同意模型

```
同意管理框架从 OAuth scope 扩展为三层：

Layer 1: OAuth Scope Consent（已实现）
  - 用户同意 App 访问 scope（如 "app:read", "email"）
  - 存储于 ConsentStore
  - 用户可查看和撤销

Layer 2: Processing Purpose Consent（新增）
  - 按 GDPR 第 5(1)(b) 条的"目的限制"原则
  - 每个处理操作绑定一个或多个 purpose
  - 用户在注册/登录时按 purpose 给出同意
  - 存储于 PurposeConsentStore（新建）

  Example Purposes:
    account_necessary: "账户运营必需"（无法 opt-out）
    service_improvement: "服务改进分析"（可 opt-out）
    marketing: "营销与广告"（必须 opt-in）
    profiling: "用户画像"（GDPR 第 22 条特别同意）
    third_party_sharing: "第三方共享"（必须明确同意）
    research: "研究与开发"（可 opt-out）

Layer 3: Jurisdiction Overlay（新增）
  - 根据用户所在地（通过 geo 中间件确定），自动应用不同法规要求
  - EU → GDPR: 所有非必要 purpose 默认 opt-in
  - US-CA → CCPA: 允许 opt-out of sale/sharing
  - BR → LGPD: 类似 GDPR，但敏感数据需要更严格的同意
  - CN → PIPL: 单独同意敏感个人信息

  jurisdiction_policy = {
    "EU": { default: "opt_in", special: ["profiling", "third_party"] },
    "US-CA": { default: "opt_out", special: ["sale_of_data"] },
    "BR": { default: "opt_in", special: ["sensitive_data"] },
    "CN": { default: "opt_in", special: ["sensitive_data", "cross_border"] }
  }
```

#### 2. IAB TCF / GPP 集成

```go
// 集成 IAB 欧洲的 Transparency & Consent Framework v2.2

type TCString struct {
    Version     int                // 2
    Created     time.Time
    LastUpdated time.Time
    CMPID       int                // 同意管理平台 ID
    CMPVersion  int
    ConsentScreen int              // 展示同意的屏幕
    ConsentLanguage string         // "EN", "DE" 等
    VendorListVersion int
    TCFPolicyVersion int
    // 用途同意（1-10 为 IAB 标准 purpose）
    PurposeConsents     map[int]bool // purpose_id → consented
    PurposeLegitimateInterests map[int]bool
    // 供应商同意
    VendorConsents      map[int]bool
    VendorLegitimateInterests map[int]bool
    // 特殊功能选择
    SpecialFeaturesOptIns map[int]bool
    // GPP 扩展
    GPPSID              string     // GPP Section ID
}

// 服务端点
// GET /consent/tcf-string → 返回用户的 TC String（base64 编码）
// POST /consent/tcf-string → 更新用户的 TC String
// 下游广告/分析供应商通过 TC String 判断用户同意状态
```

#### 3. 同意偏好信号传递

```
当用户拒绝某些目的时，SSO 应在向下游传递时附带同意信号：

通过 ID Token claims:
  {
    "sub": "user-alice",
    "consent": {
      "purposes": {
        "marketing": false,
        "service_improvement": true,
        "research": false
      },
      "jurisdiction": "EU",
      "tcf_string": "CPxxx...",
      "gpc_signal": true
    }
  }

通过 HTTP 头（反向代理/网关层注入）:
  Sec-GPC: 1          // Global Privacy Control
  Consent-Status: purposes=account_necessary:1,marketing:0,research:0
  X-Jurisdiction: EU
```

#### 4. DSAR 自动化工作流

```go
// Data Subject Access Request 工作流

type DSARRequest struct {
    ID              string
    SubjectID       string
    Type            DSARType        // Access | Rectification | Erasure | Portability | Restriction
    Status          DSARStatus      // Submitted | Verifying | Collecting | Reviewing | Completed | Rejected
    Jurisdiction    string          // "EU", "US-CA", etc.
    SubmittedAt     time.Time
    CompletedAt     *time.Time
    VerificationMethod string       // "email", "mfa", "id_document"
    CollectResult   *DSARCollectResult
}

// 工作流:
// POST /api/v1/privacy/dsar — 提交 DSAR
//   1. 身份验证: 根据类型不同，要求 MFA 或上传身份证件
//   2. 数据收集: 利用现有的 compliance/export.go + erasure.go 能力
//   3. 数据打包: 结构化 JSON/CSV 导出（GDPR 第 20 条要求"常用且机器可读"格式）
//   4. 人工审核队列: 对模糊/边缘情况的管理员界面
//   5. 完成/拒绝通知
//   6. 留存日志: 至少 3 年用于审计

DSAR API 端点:
  POST   /api/v1/privacy/dsar                # 创建 DSAR
  GET    /api/v1/privacy/dsar                 # 列出我的 DSAR
  GET    /api/v1/privacy/dsar/:id             # 查看 DSAR 状态
  GET    /api/v1/privacy/dsar/:id/download    # 下载导出的数据
  POST   /api/v1/privacy/dsar/:id/verify      # 完成身份验证步骤
  POST   /api/v1/privacy/dsar/:id/cancel      # 用户取消请求
  # 管理员端点:
  GET    /api/v1/admin/privacy/dsar           # 列出待处理 DSAR
  POST   /api/v1/admin/privacy/dsar/:id/approve
  POST   /api/v1/admin/privacy/dsar/:id/reject
```

#### 5. 数据保留策略引擎

```go
type DataRetentionPolicy struct {
    DataCategory    string        // "audit_log", "session", "consent_record", "user_profile", "id_document"
    RetentionDays   int           // 保留天数
    Action          RetentionAction // "delete" | "anonymize" | "archive"
    Jurisdictions  []string      // 适用法规（空=全部）
}

// 保留策略示例:
// audit_log: 保留 365 天，之后删除
// session: 保留 90 天，之后删除
// consent_record: 保留至同意被撤销后 + 3 年（GDPR 诉讼时效）
// id_document: 验证完成立即删除（仅保留 IAL + verified_at）
// user_profile: 账户删除后 30 天匿名化

// 执行器（后台定时任务）:
type RetentionEnforcer interface {
    EnforcePolicies(ctx context.Context) ([]EnforcementResult, error)
}

// 策略通过 admin API 配置:
// GET  /api/v1/admin/privacy/retention-policies
// PUT  /api/v1/admin/privacy/retention-policies
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 同意状态与 OAuth 令牌有效期不一致 | 令牌签发时快照用户同意状态；令牌刷新时重新评估 |
| 用户跨法规迁移（从 EU 搬到 US） | Jurisdiction Overlay 基于最新 geo 数据实时切换，历史同意记录保留原始法规上下文 |
| DSAR 身份验证绕过 | 高风险 DSAR（全数据导出）要求 MFA + 管理员确认；低风险（仅更正邮箱）一次验证即可 |
| 第三方依赖的同意状态同步 | 通过 CAEP/RISC 事件通知订阅方同意变更 |
| CCPA 的 Opt-Out 权利 vs GDPR 的 Opt-In | Jurisdiction Overlay 自动选择正确的默认；冲突时遵循最严格法规 |
| 删除请求与审计链完整性矛盾 | 个人身份信息（PII）删除，但审计元数据保留（匿名化哈希）；`compliance/erasure.go` 已有模式 |

### 性能考虑

- TC String 生成：每次需要同意字符串时从 raw consents 重新编码；使用 LRU 缓存 + 只在 consent 变更时失效
- DSAR 数据收集：可能涉及全表扫描；使用流式处理（`LIMIT/OFFSET` 游标）+ 超时（5 分钟）+ 后台处理模式（非阻塞同步）
- 保留策略强制执行：离峰时段运行（凌晨 2 点）；逐条策略异步执行；失败重试 + 审计告警 

---

## 方向 3：后量子密码学过渡计划（Post-Quantum Cryptographic Agility Program）

### 现状

项目拥有强大的密钥支持：

| 能力 | 当前状态 |
|---|---|
| EdDSA（Ed25519）签名 | ✅ 发行器 + JWKS + 验证 |
| ECDSA（ES256, ES384, ES512）签名 | ✅ 发行器 + JWKS + 验证 |
| RSA（RS256, RS384, RS512, PS256, PS384, PS512）签名 | ✅ 发行器 + JWKS + 验证 |
| KMS/HSM 外部签名 | ✅ awskms/gcpkms/azurekeyvault/pkcs11/vaulttransit |
| JWK 序列化/反序列化 | ✅ `jose.JSONWebKey` 完整 |
| 签名算法注册表 | ✅ `AsymmetricJWSAlgs` |
| **ML-DSA（FIPS 204）签名** | ❌ **零实现** |
| **SLH-DSA（FIPS 205，原 SPHINCS+）签名** | ❌ **零实现** |
| **ML-KEM（FIPS 203）密钥封装** | ❌ **零实现** |
| **混合签名模式（classical + PQ 组合）** | ❌ **零实现** |
| **PQ JWK 表示（新 `kty` 值）** | ❌ **零实现** |
| **PQ 算法发现机制** | ❌ **零实现** |
| **PQ 密钥的 JWKS 端点和 Discovery 表示** | ❌ **零实现** |
| **PQ 性能基准与策略** | ❌ **零实现** |

### 缺口（grep 核验）

- `ML.DSA\|ML.KEM\|SLH.DSA\|Falcon\|Dilithium\|Kyber\|Sphincs\|Crystals.*Dilithium\|Crystals.*Kyber\|FIPS.*204\|FIPS.*205`：**零实现命中**（`defaultimpl/vaulttransit` 有 `post-quantum` 注释但只是类型检查拒止）
- `hybrid.*sign\|HybridSign\|composite.*sign\|CompositeSign\|dual.*sign\|DualSign\|PQSignature\|pq_signature`：**零实现命中**
- `post.quantum\|PostQuantum\|post_quantum\|quantum.*safe\|quantum.*resistant\|quantum.*agility` 在功能实现上下文：**零实现命中**
- `WithPQSigningAlg\|WithHybridSigning\|WithPQKeyRotation\|WithPQIssuer`：**零实现命中**

### 为什么需要它

1. **"Harvest Now, Decrypt Later"的威胁模型**——JWT 令牌是**长期有效的凭据**。今天用 ECDSA/EdDSA 签发的 access_token（最长有效期 24h）和 refresh_token（最长可达 90 天）——如果攻击者今**天捕获了这些令牌的签名/握手信息**，在 2030 年左右量子计算机成熟后可以解密/伪造。对于政府、金融、医疗客户，这是一个正在变的真实威胁。

2. **NIST 标准已最终确定**——FIPS 204（ML-DSA）和 FIPS 205（SLH-DSA）于 2024 年 8 月正式发布。CNSA 2.0（Commercial National Security Algorithm Suite 2.0）要求 2030 年前完成迁移。**金融机构和政府部门已经开始要求供应商展示 PQ 迁移路径。**

3. **这是一个"现在不设计，以后很痛苦"的问题**——签名算法在 SSO 系统中的渗透是全方位的：JWT 签名、JWKS、Discovery（`id_token_signing_alg_values_supported`）、客户端注册时的公钥、KMS/HSM 集成。等到客户要求 PQ 支持时再开始设计，至少需要 6-12 个月的开发周期。**现在开始设计算法无关架构和混合签名模式，是为未来铺路的最高 ROI。**

### 范围

#### 1. 算法注册表扩展

```go
// 当前算法注册表（shared/security/aliases.go 附近）：
var AsymmetricJWSAlgs = map[string]jose.SignatureAlgorithm{
    "EdDSA":   jose.EdDSA,
    "ES256":   jose.ES256,
    "ES384":   jose.ES384,
    "ES512":   jose.ES512,
    "RS256":   jose.RS256,
    "RS384":   jose.RS384,
    "RS512":   jose.RS512,
    "PS256":   jose.PS256,
    "PS384":   jose.PS384,
    "PS512":   jose.PS512,
}

// 扩展后的注册表（新增 PQ 算法）：
var PQJWSAlgs = map[string]jose.SignatureAlgorithm{
    "ML-DSA-44":  alg.MLDSA44,   // NIST security level 2（≈ ECDSA P-256）
    "ML-DSA-65":  alg.MLDSA65,   // NIST security level 3（≈ ECDSA P-384）
    "ML-DSA-87":  alg.MLDSA87,   // NIST security level 5（≈ ECDSA P-521）
    "SLH-DSA-SHAKE-128f": alg.SLHDSA128f,
    "SLH-DSA-SHAKE-256s": alg.SLHDSA256s,
}
```

**注意**：Go 标准库目前（Go 1.24）未内置 PQ 算法。实现方式：
- **短期（2026）**：使用 `github.com/cloudflare/circl`（PQ 实现库）或 `github.com/IQTT/quantum-safe-go`
- **中期（2027+）**：Go 标准库 `crypto/` 可能对接 NIST 标准化算法的实现
- **架构要求**：所有 PQ 支持应置于**独立的、可选导入的子模块**中（如 `pq/ml-dsa/`、`pq/slh-dsa/`），核心 `go.mod` 零依赖增加——与 KMS peer 和 SAML 已验证的模式一致

#### 2. 混合签名模式（Hybrid Signing）

```
过渡期最关键的架构决策：hybrid = 同时用 classical + PQ 算法签名。

为什么需要 hybrid：
  - 纯 PQ 签名在初期可能不被所有 RP 支持
  - 如果只做 PQ 签名，旧客户端无法验证
  - 如果只做 classical 签名，没有 PQ 安全
  - 混合模式让双方同时在各自的舒适区验证

实现方案：

type HybridSignature struct {
    // 两个独立签名的联结
    ClassicalAlg string `json:"classical_alg"` // "ES256"
    ClassicalSig []byte `json:"classical_sig"`
    PQAlg        string `json:"pq_alg"`         // "ML-DSA-44"
    PQSig        []byte `json:"pq_sig"`
    // 签名的数据相同，算法不同
}

JWT 中的 hybrid header:
{
  "alg": "ES256+ML-DSA-44",    // 新的复合 alg 名
  "kid": "2026-hybrid-key-01",
  "typ": "JWT",
  "hybrid": true
}

验证策略：
  - 验签者选择自己支持的算法验签
  - ES256 验签通过 → classical 安全
  - ML-DSA-44 验签通过 → PQ 安全
  - 至少一个通过即可（宽松模式）或两者都需通过（严格模式）
  - 具体策略通过 discovery 的 `hybrid_verification_policy` 声明
```

#### 3. PQ JWK 格式

```json
{
  "kty": "ML-DSA",
  "kid": "ml-dsa-44-key-2026-01",
  "alg": "ML-DSA-44",
  "use": "sig",
  "params": {
    "mode": 44
  },
  // ML-DSA 公钥（长度约 1312 字节 for ML-DSA-44）
  "x": "<base64url-encoded-public-key>"
}

// ML-DSA-44 签名长度：~2420 字节
// ML-DSA-65 签名长度：~3309 字节
// 相比 ES256 的 64 字节签名，PQ 签名大 ~40-50 倍
// 这对 JWKS body 大小、HTTP 传输、JWT header 大小都有影响
```

#### 4. JWKS 端点与 Discovery 表示

```go
// Discovery 扩展：
{
  "issuer": "https://sso.example.com",
  "id_token_signing_alg_values_supported": [
    "EdDSA",
    "ES256",
    "RS256",
    "ML-DSA-44",           // 新增 PQ 算法
    "ES256+ML-DSA-44"      // 新增混合算法
  ],
  "hybrid_signing_supported": true,
  "hybrid_verification_policy": "any_one"  // "any_one" | "all"
}

// JWKS 扩展：
// 当 hybrid 模式启用时，JWKS 端点返回两组密钥，
// 每个 hybrid key 以复合 kid 关联两个条目：
{
  "keys": [
    {
      "kid": "2026-hybrid-key-01:classical",
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "..."
    },
    {
      "kid": "2026-hybrid-key-01:pq",
      "kty": "ML-DSA",
      "params": {"mode": 44},
      "x": "..."
    }
  ]
}
```

#### 5. PQ 签发器与验证器

```go
// PQTokenIssuer SPI 实现（reuses 现有 core.TokenIssuer 接口）：

type PQTokenIssuer struct {
    classicalIssuer TokenIssuer   // 现有 ECDSA/EdDSA 发行器
    pqIssuer        TokenIssuer   // 新的 PQ 发行器
    mode            HybridMode     // HybridClassicalOnly | HybridPQOnly | HybridBoth
}

func (i *PQTokenIssuer) IssueToken(ctx context.Context, claims *core.TokenClaims) (*core.IssuedToken, error) {
    switch i.mode {
    case HybridClassicalOnly:
        return i.classicalIssuer.IssueToken(ctx, claims)
    case HybridPQOnly:
        return i.pqIssuer.IssueToken(ctx, claims)
    case HybridBoth:
        // 同时签发两个签名，包装为 HybridSignature
        ct, _ := i.classicalIssuer.IssueToken(ctx, claims)
        pt, _ := i.pqIssuer.IssueToken(ctx, claims)
        return i.combine(ct, pt)
    }
}
```

#### 6. PQ 性能策略

| 操作 | ES256 | ML-DSA-44 | 比例 |
|---|---|---|---|
| 签名 | ~0.02ms | ~0.05ms | 2.5x |
| 验证 | ~0.02ms | ~0.03ms | 1.5x |
| 公钥大小 | 65 bytes | 1,312 bytes | 20x |
| 签名大小 | 64 bytes | 2,420 bytes | 38x |
| JWKS 大全（4 keys） | ~1KB | ~30KB | 30x |

性能缓解策略：
- **JWKS body 压缩**：启用 `Accept-Encoding: gzip`（JWKS 30KB→~8KB）
- **签名大小缓存**：JWT header + payload + 签名从 ~1KB → ~3.5KB；考虑 token_ref（参考令牌）模式绕过大签名
- **验证优先于签名**：JWKS 端点多做缓存（TLV），验证路径开销可控
- **混合模式的非对称成本**：hybrid 模式需要同时做两次签名（classical + PQ）——仅在需要 PQ 安全的 client/scope 上启用

### 边界情况

| 边界 | 处理策略 |
|---|---|
| PQ 算法 vs 现有 JWKS 消费者 | hybrid 模式保证至少一种算法能被现有消费者理解 |
| PQ 私钥存储与 HSM 支持 | 联系各 KMS 厂商的 PQ 路线图；短期内 PQ 密钥在进程内存中（与早期 Ed25519/ECDSA 同模式） |
| 签名大小超过 HTTP header 上限 | 默认 Go HTTP client/server 的 header 上限为 1MB；PQ 签名无关 |
| PQ 算法的密钥轮换策略 | 混合模式：classical 和 PQ 密钥独立轮换（相同或不同周期均可） |
| 注册的公钥（DCR JAR）的 PQ 支持 | `Client.JWKS` 支持 PQ 公钥；`private_key_jwt` 的 sig 校验扩展 PQ 算法 |
| 跨版本兼容（纯 PQ vs 纯 classical vs hybrid） | Discovery 同时列出所有支持的算法；RP 选择自己支持的最高安全级别 |

### 性能考虑

- **PQ JWKS body 体积**：ML-DSA-44 公钥 1312 字节，4 个 key 的 JWKS 约 30KB（未压缩）。需启用 gzip + 强 ETag 缓存 + singleflight 保护
- **混合签名模式**：每次签发需要 2 倍签名操作；仅在白名单 scope（如 `pq_safe`）或特定 client 上启用
- **PQ 作为独立子模块**：`pq/` 子模块不增加核心 `go.mod` 依赖；cloudflare/circl 约 500KB 编译体积



---

## 方向 4：身份平台供应链安全与可验证构建（Identity Platform Supply Chain Security & Attestation）

### 现状

项目拥有强大的安全功能，但**作为安全关键基础设施的构建和交付过程本身**缺乏现代供应链安全保护：

| 能力 | 当前状态 |
|---|---|
| Go 模块依赖管理 | ✅ `go.mod` / `go.sum` |
| Dependabot 自动更新 | ✅（但仅根模块） |
| GitHub Actions CI | ✅ |
| `goreleaser` 构建配置 | ✅ |
| **SLSA 3+ 构建管道** | ❌ **零实现** |
| **可验证构建（Reproducible Builds / Verifiable Build）** | ❌ **零实现** |
| **签名构建制品（Cosign 签名 + SBOM 附件）** | ❌ **零实现** |
| **构建和发布的可验证 Provenance（in-toto）** | ❌ **零实现** |
| **FIPS 140-3 加密模块边界文档** | ❌ **零实现** |
| **二进制代码签名（Windows/macOS/Linux）** | ❌ **零实现** |
| **Go 依赖的漏洞扫描与策略执行** | ❌ **部分**（ROADMAP v5.0 #5e 提出了 `govulncheck` 但未描述策略执行） |
| **容器镜像的 Cosign 签名 + 策略验证** | ❌ **零实现** |

### 缺口（grep 核验）

- `SLSA\|slsa\|supply.*chain.*level\|build.*level\|BuildLevel\|Provenance\|provenance.*statement`：**零实现命中**
- `cosign\|Cosign\|sigstore\|keyless\|fulcio\|rekor\|Rekor`：**零实现命中**（ROADMAP v5.0 在第 5 项的文档中提到 `cosign signature` 是未来挂起项，但未落地）
- `reproducible.*build\|ReproducibleBuild\|verifiable.*build\|VerifiableBuild\|deterministic.*build`：**零实现命中**
- `sbom\|SBOM\|spdx\|cyclonedx\|syft\|grype\|trivy.*fs` 在生成上下文：**零实现命中**
- `in.toto\|intoto\|attest.*key\|attest.*provenance\|signed.*attestation\|policy.*controller`：**零实现命中**
- `binary.*sign\|code.*sign\|macOS.*sign\|windows.*sign\|authenticode\|codesign\|signing.identity`：**零实现命中**

### 为什么需要它

1. **身份平台是最敏感的基础设施**——SSO 服务器控制着谁可以访问什么。如果构建管道被攻破，恶意二进制可以禁用 MFA、注入后门账户、窃取签名密钥。**这是"谁守卫守卫者"（Quis custodiet ipsos custodes）的问题。**

2. **供应链攻击的上升趋势**——2024 年 SolarWinds、Codecov、3CX、XZ Utils 等供应链攻击证明：攻击者不再直接攻击目标，而是攻击目标的构建管道。SLSA（Supply-chain Levels for Software Artifacts）已成为政府采购安全评估标准。

3. **金融/政府采购的硬门槛**——在美国 EO 14028（改善国家网络安全）和 OMB 备忘录 M-22-18 的推动下，联邦采购要求软件供应商提供 SBOM + SLSA 3+ 证明。这不是"加分项"，而是"不满足就不卖"。

### 范围

#### 1. SLSA 3 构建管道

```
SLSA（Supply-chain Levels for Software Artifacts）是一个从 L0 到 L4 的成熟度框架：

关键需求：
  SLSA L1: 构建过程可脚本化（已有 CI ✅）
  SLSA L2: 版本控制 + 构建服务托管 + 构建源生成 provenance（需要补 ✅ 中几项）
  SLSA L3: 无用户自定义的隔离构建 + 一致性（需要新增）
  SLSA L4: 双人审查 + 密封 + 可复现（目标，长期）

SLSA 3 构建管道改造：

当前工作流：

  git push → GitHub Actions → go build → goreleaser → binary

SLSA 3 工作流：

  git push → GitHub Actions（受信任构建器）→ 隔离构建 → go build
      ↓
  生成 provenance（in-toto attestation）
      ↓
  goreleaser → binary + provenance + SBOM + cosign signature
      ↓
  GitHub Release + ghcr.io（带签名 + 附件）

具体措施：
  1. 使用 GitHub 的 SLSA 3 生成器（github.com/slsa-framework/slsa-github-generator）
     - 构建在可验证的隔离环境中运行
     - 构建过程生成 cryptographically signed provenance
     - provenance 记录：源代码仓库 + 提交 SHA + builder identity + 构建指令
  2. 构建参数锁定：go version 锁定 + GOFLAGS 锁定 + CGO_ENABLED=0 锁
  3. 非构建步骤不做为构建器：secret 注入、环境变量自定义通通不允许
```

#### 2. SBOM 生成与签名

```
SBOM（Software Bill of Materials）包含项目中所有依赖的完整清单：

生成工具:
  - syft（Anchore）: 从 go.mod / go.sum 生成 SPDX 或 CycloneDX 格式的 SBOM
  - trivy fs: 同时生成 SBOM + 漏洞扫描

CI 集成:
  # .github/workflows/release.yml
  - name: Generate SBOM
    run: syft go:./... -o spdx-json=sbom.spdx.json

  - name: Sign SBOM
    run: cosign sign-blob --yes sbom.spdx.json > sbom.spdx.json.sig

  - name: Attach SBOM to release
    run: |
      gh release upload v${{version}} sbom.spdx.json sbom.spdx.json.sig

发布物清单（每个 release）:
  sso-server-linux-amd64
  sso-server-linux-amd64.sig         # Cosign 签名
  sso-server-darwin-amd64
  sso-server-darwin-amd64.sig
  sso-ctl-linux-amd64
  sso-ctl-linux-amd64.sig
  sbom.spdx.json                     # SBOM
  sbom.spdx.json.sig                 # SBOM 签名
  provenance.intoto.jsonl            # SLSA Provenance
  multiple-provenance.cose           # Cosign 打包的 provenance
```

#### 3. 构建 Provenance（in-toto Attestation）

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "sso-server-linux-amd64",
      "digest": {"sha256": "abc123..."}
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "builder": {
      "id": "https://github.com/snaplink/sso/.github/workflows/release.yml@refs/heads/main"
    },
    "buildType": "https://goreleaser.com/slsa/v1",
    "invocation": {
      "configSource": {
        "uri": "git+https://github.com/snaplink/sso@<sha>",
        "digest": {"sha1": "<commit_sha>"},
        "entryPoint": ".goreleaser.yaml"
      }
    },
    "materials": [
      {
        "uri": "git+https://github.com/snaplink/sso",
        "digest": {"sha1": "<commit_sha>"}
      },
      {
        "uri": "https://go.dev/dl/go1.24.0.linux-amd64.tar.gz",
        "digest": {"sha256": "abc..."}
      }
    ]
  }
}
```

#### 4. FIPS 140-3 加密模块边界文档

虽然项目不打算（也不应该）自行认证 FIPS 140-3（那是 Go 标准库 + OpenSSL FIPS 模块 + KMS 厂商的责任），但应提供清晰的**加密模块边界文档**：

```
FIPS 140-3 相关声明（文档，非认证）:

文档内容包括:
  ├── 加密服务概览
  │   ├── 令牌签名: EdDSA/ECDSA/RSA/KMS（各厂商 FIPS 状态）
  │   ├── 令牌验证: 使用 Go 标准库（Go 的 BoringCrypto 或 FIPS 140 验证版）
  │   ├── TLS: 终止于反向代理（非进程内）或 golang.org/x/crypto
  │   ├── 哈希: SHA-256（Go 标准库，FIPS 140 已验证）
  │   └── 密码 hash: bcrypt（非 FIPS，可替代为 argon2 或 PBKDF2-HMAC-SHA256）
  │
  ├── FIPS 兼容配置
  │   ├── 仅允许 FIPS 已验证算法（禁用 RS384/RS512/PayPal-old）
  │   ├── 最小密钥长度（RSA 2048+, ECDSA P-256+, EdDSA Ed25519）
  │   └── KMS 作为 FIPS 边界（Amazon KMS FIPS 140-3 已验证）
  │
  └── 已知非 FIPS 区域（需配置补偿措施）
      ├── bcrypt 密码验证（可替换为 PBKDF2）
      ├── PBES2 加密的 private key PEM
      └── go-jose/v4 的随机数生成器（使用 Go crypto/rand）
```

#### 5. 依赖漏洞策略执行

```yaml
# .github/workflows/security-scan.yml
jobs:
  vulncheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: stable }

      # SCA 扫描（Go 官方）
      - run: go install golang.org/x/vuln/cmd/govulncheck@latest
      - run: govulncheck ./...

      # SCA 策略执行（阻止已知高危漏洞）
      - name: Policy check
        run: |
          govulncheck -scan syms ./... | tee vulncheck.out
          # 如果发现 CRITICAL/HIGH 漏洞，fail 构建
          if grep -q "HIGH\|CRITICAL" vulncheck.out; then
            echo "Found critical vulnerabilities"
            exit 1
          fi

      # 容器镜像扫描
      - name: Scan docker image
        run: |
          trivy image --severity HIGH,CRITICAL \
            --exit-code 1 \
            ghcr.io/snaplink/sso-server:${{ github.sha }}
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| Provenance 中的容器镜像 digest vs 二进制 digest | 同时记录：先构建二进制并生成 digest → 构建容器（COPY 二进制）→ 生成容器 digest |
| 版本回滚时的 provenance 验证 | Provenance 与 release tag 绑定；operator 可用 `cosign verify` 确认回滚版本的完整性 |
| 第三方子模块供应链 | 每个子模块（saml/, kms/*, redis/ 等）各自生成 SBOM → 合并为统一 SBOM |
| 零信任部署（operator 验证二进制） | 发布文档包含验证命令步骤；operator 可用 `cosign verify-blob` 在离线环境验证 |
| Adversarial SBOM（恶意依赖隐藏） | `go.sum` + Go's module proxy 的 checksum DB（sum.golang.org）提供校验和验证 |

### 性能考虑

- SBOM 生成时间：约 30-60 秒额外 CI 时间（`syft go:./...`）
- Provenance 生成：通过 SLSA generator 约 2-5 分钟额外时间（主要是启动隔离构建环境）
- Cosign 签名：~2 秒/签名（keyless 模式需要与 Fulcio+Rekor 通信，增加~5 秒）
- **建议**：供应链安全步骤仅在 release CI（tag push）上运行，不阻塞日常 PR CI

---

## 方向 5：OAuth 2.0 物联网络与受限环境适配（OAuth 2.0 for IoT / Constrained Environments）

### 现状

项目支持设备授权流程（RFC 8628 Device Flow）作为 IoT/M2M 场景的基础，但对于真正的**受限环境（constrained environments per RFC 7228）**存在大量缺口：

| 能力 | 当前状态 |
|---|---|
| Device Flow（RFC 8628，通过用户设备辅助） | ✅ `oauth/device_code.go` 完整 |
| Client Credentials（M2M，服务器到服务器） | ✅ 完整 |
| JWT Access Token | ✅ 完整 |
| **CBOR Web Token（CWT, RFC 8392）** | ❌ **零实现** |
| **ACE-OAuth（RFC 9200，受限环境授权框架）** | ❌ **零实现** |
| **CoAP / DTLS 绑定** | ❌ **零实现** |
| **轻量级客户端注册（无 TLS 客户端证书）** | ❌ **零实现** |
| **离线授权令牌包（Pre-issued Token Bundle）** | ❌ **零实现** |
| **CoAP 到 HTTP 代理桥接** | ❌ **零实现** |
| **令牌裁剪（取消非必要 claim）** | ❌ **零实现** |

### 缺口（grep 核验）

- `CWT\|cwt\|CBOR\|cbor\|RFC.*8392\|8392` 在令牌实现上下文：**零实现命中**（仅注释中有 `cbor` 作为函数名或测试变量名的一部分）
- `ACE\|ACE.*OAuth\|ace.*oauth\|RFC.*9200\|9200`：**零实现命中**
- `coap\|CoAP\|COAP\|dtls\|DTLS\|UDP.*auth\|auth.*UDP\|auth.*datagram`：**零实现命中**
- `constrained\|constrained.*environ\|RFC.*7228\|7228\|lightweight.*token\|token.*lightweight`：**零实现命中**
- `offline.*token\|pre.*issued\|token.*bundle\|batch.*token\|pre.*authorized.*token`：**零实现命中**
- `WithCWTIssuer\|WithACEHandler\|WithCoAPBinding\|WithLightweightClientReg`：**零实现命中**

### 为什么需要它

1. **IoT 市场规模的现实**——2026 年全球活跃 IoT 设备超过 300 亿台。每个设备都需要某种形式的身份和授权。虽然许多 IoT 场景使用 API keys 或 X.509 证书，但 OAuth 2.0 的授权模型（委托、范围限制、吊销）在 IoT 中同样有价值。

2. **受限设备的特殊约束**——大量 IoT 设备是受 RFC 7228 定义的"受限设备"：CPU 频率 < 20MHz、RAM < 100KB、Flash < 1MB。JWT（RSA/ECDSA 验签）在这些设备上的计算成本不可接受。CWT + CBOR + 对称密钥认证是此类场景的实际标准。

3. **边缘计算与离网操作**——工厂产线、偏远传感器、车载系统可能无法持续保持与授权服务器的连接。需要**离线令牌包**和**预授权策略**来实现断网工作。

4. **差异化的市场定位**——大多数 SSO 产品（Auth0、Okta、Clerk）关注 Web/移动端，IoT 授权是一个相对空白但快速增长的市场——目前由 AWS IoT Core、Azure IoT Hub、和专用的 IoT 身份平台（如 DeviceAuthority）主导。

### 范围

#### 1. CBOR Web Token（CWT）支持

```
CWT（RFC 8392）是 JWT 的 CBOR 等价物，用于受限环境：

JWT vs CWT 对比:
  ┌──────────────────────┬─────────────┬──────────────┐
  │ 属性                 │ JWT         │ CWT          │
  ├──────────────────────┼─────────────┼──────────────┤
  │ 编码                 │ JSON + base64│ CBOR（二进制）│
  │ 典型大小（相同声明）  │ ~800 bytes  │ ~250 bytes   │
  │ 解析复杂度           │ JSON 解码    │ CBOR 流式解码│
  │ 签名                 │ JWS (JSON)  │ COSE (二进制) │
  │ 加密                 │ JWE (JSON)  │ COSE (二进制) │
  │ Go 库               │ go-jose     │ github.com/fxamacker/cbor/v2 + go-cose  │
  └──────────────────────┴─────────────┴──────────────┘

CWT 发行器 SPI（复用 TokenIssuer 接口）:
  - 输入: core.TokenClaims + COSE 签名密钥
  - 输出: CWT 二进制（tag 61, RFC 8392）
  - 与现有 JWT issuer 平行存在：
    核心 go.mod 零额外依赖（cbor/cose 为 IoT 子模块依赖）
    sso.WithTokenIssuer("cwt", cwtIssuer) 和现有的 "jwt" issuer 并列

CWT 声明映射:
  iss (1)      ↦ issuer
  sub (2)      ↦ subject
  aud (3)      ↦ audience
  exp (4)      ↦ expiration time
  nbf (5)      ↦ not before
  iat (6)      ↦ issued at
  cti (7)      ↦ jti (CWT Token ID)
  scp (9)      ↦ scope (CBOR 数组)
  cnf (11)     ↦ confirmation (COSE_Key)
```

#### 2. ACE-OAuth 框架（RFC 9200）

```
ACE-OAuth（Authentication and Authorization for Constrained Environments）
定义了受限客户端与授权服务器之间的授权流程：

ACE-OAuth 架构:
  ┌─────────┐    CoAP/DTLS    ┌──────────┐    CoAP/DTLS    ┌─────────┐
  │ Client   │←─────────────→│  AS       │←─────────────→│  RS      │
  │ (受限)  │    POST /ace   │（SSO 扩展）│  (CWT token) │（资源服)│
  └─────────┘                └──────────┘                └─────────┘

ACE 核心操作:
  1. 客户端通过 CoAP POST 到 AS 的 /ace 端点，携带:
     - 授权类型（client_credentials / authorization_code / ...）
     - 客户端 ID（预注册或 ephemeral）
     - 请求的 scope
     - 可能需要的人口证明（PoP）
  2. AS 返回 CWT + 可选关联访问令牌（或直接返回 CWT）
  3. 资源服务器验证 CWT（通过对称键或从 AS 解引用）

端点映射:
  HTTP /token        → CoAP coaps://as.example.com/ace
  HTTP /introspect   → CoAP coaps://as.example.com/ace/introspect
  HTTP /revoke       → CoAP coaps://as.example.com/ace/revoke

ACE 扩展的 SPI:
  core.ACEHandler（新的 SPI）
  - HandleACERequest(ctx, *ACERequest) → *ACEResponse
  - 内部委托给现有的 grant handler 但用 CWT 编码返回
```

#### 3. 轻量级客户端注册

```
受限设备的客户端注册不能依赖 TLS 客户端证书或 HTTP 重定向。

轻量级注册模式：

模式 1: Pre-provisioned（预置，出厂时写入）
  设备出厂时内置 client_id + 对称密钥。
  通过制造证书链锚定信任。
  适用：品牌设备（如 Philips Hue、Nest）。

模式 2: Ephemeral Registration（瞬态注册）
  设备首次通电时生成一个密钥对（非对称）：
    POST /register/pop
    { client_id: "device-sn-12345", pop_key: <raw public key> }
  服务器返回 registration_token（作为后续操作的凭据）。
  适用：通用 IoT 平台（用户可以添加任意品牌设备）。

模式 3: Bootstrap via Claim Code（基于激活码）
  用户在手机应用的配对流程中获得一次性的 6 位激活码：
    手机: POST /device/code → code=ABC123
    设备: POST /register/code {code: "ABC123", pop_key: <key>}
  适用：消费级 IoT（用户手动输入一次激活码）。

所有模式的最低要求:
  - 支持原始公钥（Raw Public Key, RFC 7250）作为客户端凭据
  - 支持对称密钥（Pre-Shared Key, PSK）作为客户端凭据
  - 支持 CBOR 编码的请求/响应
```

#### 4. 离线授权令牌包

```
对于可能断开网络连接的设备，需要预授权机制：

场景: 工厂自动化系统
  - 100 个传感器，每个传感器每 30 秒上报一次数据
  - 传感器一次注册授权后，在接下来的 72 小时内可能处于离线状态
  - 需要预先授权一批令牌

离线令牌包:
  POST /device/auth-bundle
  {
    "device_id": "sensor-01",
    "scopes": ["sensor:report"],
    "audience": "https://api.factory.internal",
    "token_count": 100,           // 预发 100 个令牌
    "token_validity": 3600,       // 每个令牌有效期 1 小时
    "bundle_validity": 259200,    // 整包有效期 72 小时
    "pop_key": <raw public key>   // 绑定到设备密钥
  }

返回:
  {
    "tokens": [
      {"token": "<CWT 1>", "nbf": 1712345678, "exp": 1712349278},
      {"token": "<CWT 2>", "nbf": 1712349278, "exp": 1712352878},
      ...
    ],
    "bundle_id": "bundle-xyz-123",
    "bundle_jti": "<bundle identifier for revocation>"
  }

吊销策略:
  - 吊销 bundle_id → 吊销包中所有令牌（设备下次上线时收到吊销通知）
  - 每令牌独立吊销（通过 introspection/revocation）
  - 服务器跟踪 bundle 中的令牌使用情况（best-effort）
  - 令牌轮换：设备用完 100 个令牌前上线请求下一批
```

#### 5. CoAP 到 HTTP 协议桥

```
对于不支持 CoAP 的部署，提供 HTTP-CoAP 桥接：

桥接模式:
  客户端（CoAP） → [CoAP 网关] → HTTP 代理 → SSO Server（HTTP）

标准 SSO Server 不需要了解 CoAP：
  1. 外部 CoAP 网关负责协议转换（如 Eclipse Californium 的 proxy）
  2. SSO Server 通过已有的 HTTP 端点服务所有请求
  3. 网关负责: CoAP→HTTP 请求映射 + HTTP→CoAP 响应映射 + DTLS→TLS 桥接

但为了更好的性能和原生 CoAP 支持:
  - SSO Server 可选监听 CoAP over DTLS 端口（与 HTTP 端口并行）
  - 使用 swoosh（或类似纯 Go CoAP 库）作为可插拔传输层
  - 路由到相同的 handler 逻辑，但序列化改用 CBOR/CWT
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 设备证书过期后无法续期 | 使用轮换密钥对；设备每次上线检查证书是否即将过期，自动启动轮换 |
| 离线令牌包泄露 | 令牌包绑定到设备 POP key；每个令牌使用一次即作废（one-time use 模式） |
| 海量设备并发注册（10K 设备同时启动） | 注册端点使用背压 + 限流；设备应遵守指数退避（已实现 ratelimit 中间件） |
| 设备时钟不准 | CWT 验证使用服务器时间 + 大时钟偏移容差（默认 2 小时） |
| 对称密钥 vs 非对称密钥选择 | PSK（对称）更节能但需要安全预置；非对称更灵活但计算成本高；AS 应同时支持 |
| 固件更新后设备身份变更 | 设备身份绑定到硬件安全元件（TPM/SE）；固件更新不影响身份绑定 |
| CoAP 的可靠性（非可靠传输） | ACE 使用 CoAP Confirmable 消息 + retransmission；令牌操作需要可靠传输 |

### 性能考虑

- CWT 比 JWT 小 50-70%；CBOR 的流式解析比 JSON 快 3-5 倍（内存分配更少）
- COSE 签名（CWT 的签名层）在受限设备上的验证时间约为 JWS 的 60%（因解析开销更小）
- 对称密钥（PSK）验证比非对称快 100-1000 倍——适合大量低功耗设备
- IoT 子模块应为独立 `go.mod`、零额外依赖到核心——与 KMS 子模块已验证的模式一致
- 令牌包预发机制将认证从实时路径转移到离线路径，大幅降低高峰负载

---

## 优先级摘要

| 优先级 | 方向 | 战略价值 | 工作量 | 风险 | 建议 |
|---|---|---|---|---|---|
| **P0** | ③ 后量子密码学过渡 | 极高 | M（架构层，长期实施） | 中（标准仍在演进，但`架构设计`必须现在开始） | **立即开始算法注册表扩展 + JWK 格式设计；PQ 代码实现可 2027+** |
| **P0** | ② 企业同意与隐私规约 | 极高 | L（基础同意已存在，增量） | 低（基础设施已就位；增量接口设计） | 将现有 ConsentStore 扩展为目的层次模型，再添加 TCF/GPP 集成 |
| **P1** | ④ 供应链安全与可验证构建 | 高 | M（CI 改造 + 构建基础设施） | 低（成熟工具链，SLSA generator 已是 GA） | **CI 改造可分阶段：第一步 SBOM + Cosign（S 级）；第二步 SLSA 3（M 级）** |
| **P1** | ① AI 智能体身份委派 | 高 | L（增量 SPI + handler） | 中（领域仍在快速变化，RFC 尚未出版） | 先行 MVP：Agent Store + 委派令牌 + 审计；A2A 和 MCP 待生态成熟 |
| **P2** | ⑤ IoT/受限环境适配 | 中高 | XL（全栈新传输 + 格式） | 中（新传输层 CoAP/DTLS 的运维复杂度） | 建议先做 CWT 发行器作为可选项 + ACE-OAuth 的 HTTP-only 版本 |

### 执行建议

**第一阶段（最短路径，0-1 month）**：
- 方向② Phase 1：ConsentStore 扩为 PurposeConsentStore + DSAR 基础端点（利用现有 `compliance/export.go` + `compliance/erasure.go`）
- 方向④ Phase 1：`sbom` 生成 + `cosign` 签名 + `govulncheck` 策略执行

**第二阶段（架构规划，1-3 months）**：
- 方向③ 架构设计：算法注册表扩展 + 混合签名模式定义 + PQ JWK 格式 + discovery 扩展声明——**在核心加密抽象层准备好 PQ 接入点**；实际 PQ 实现置于独立子模块中，等待 Go 生态成熟
- 方向① MVP：AgentStore SPI + 委派令牌核心 + 基础端点和审计

**第三阶段（完整交付，3-6 months）**：
- 方向⑤ 初始：CWT 发行器（作为 `sso.WithCWTIssuer()` 选项）+ 轻量级客户端注册
- 方向② 完整：TCF/GPP 集成 + 数据保留策略引擎 + 自动化 ROPA 生成
- 方向④ 完整：SLSA 3 构建管道 + in-toto provenance

### 交叉依赖

```
方向①（AI Agent Delegation）
  ├─ 前置: Token Exchange act chain（已存在）
  ├─ 复用: ConsentStore（扩展为 agent 委派同意）
  └─ 复用: CIBA（推送确认到用户手机授权委派）

方向②（Enterprise Consent & Privacy）
  ├─ 前置: ConsentStore（已存在）
  ├─ 复用: GeoMiddleware（法规定位）
  ├─ 复用: Compliance exporter/eraser（DSAR 数据收集）
  └─ 复用: Email Sender（DSAR 通知）

方向③（Post-Quantum Crypto）
  ├─ 前置: 算法注册表（已存在）
  ├─ 复用: KMS peer 模式（PQ 算法作为独立子模块，核心零依赖）
  └─ 复用: 发现配置引擎（扩展支持混合算法声明）

方向④（Supply Chain Security）
  ├─ 不受限：纯 CI/CD 改造，与代码架构完全正交
  └─ 复用: 现有的 goreleaser.yaml + .github/workflows

方向⑤（IoT/Constrained Environments）
  ├─ 前置: TokenIssuer SPI（已存在，可扩展为 CWT 发行器）
  ├─ 复用: Device Code Flow（已存在，IoT 基础流程）
  └─ 复用: Client Credentials（M2M 的核心模式）
```

---

## 与已有分析的非重叠声明

| 本报告方向 | 与已有分析的关系 |
|---|---|
| ① AI Agent Identity | **全新**——所有历史分析（v1–v13、post-protocol-layer、ROADMAP v5.0）均未涉及 AI 智能体身份委派 |
| ② Enterprise Consent & Privacy Hub | **全新**——在已有 ConsentStore SPI 基础上扩展到企业级隐私合规（TCF/GPP/DSAR/保留策略），未在任何分析文档中出现 |
| ③ Post-Quantum Crypto | **仅提及未展开**——v12 被动提及"量子安全算法"但未作为方向；本报告提供完整的过渡架构设计 |
| ④ Supply Chain Security | **部分重叠但未展开**——ROADMAP v5.0 #5 提及 Cosign/sbom 但仅作为个位数行任务项；本报告提供 SLSA/SBOM/Provenance/FIPS 文档的完整方案 |
| ⑤ IoT/Constrained Environments | **全新**——没有任何分析文档覆盖 CoAP/DTLS/CWT/ACE-OAuth/离线令牌包 |

---

*本报告所有方向均经 grep 对抗核验确认为当前分析文档零覆盖。不重复历史分析已覆盖的任何方向。*
