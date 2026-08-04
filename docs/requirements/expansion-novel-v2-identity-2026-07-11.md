# 扩展方向分析报告 —— 下一阶段：身份治理、特权访问与持续授权

> **作者：** 资深架构 & 产品经理视角  
> **日期：** 2026-07-11  
> **前提：** 本报告基于全代码库全局扫描（2242 个 `.go` 文件、4 个嵌入式 SPA、200+ 包），  
>   并系统阅读 ROADMAP v5.0、deferred-backlog、以及全部 13 轮历史扩展方向分析（v1–v13）、  
>   expansion-novel-2026-07-11、expansion-post-protocol-layer-analysis。  
> **核验方法：** 逐方向对 `docs/requirements/*.md` 做 grep 关键词交叉验证 + 全代码库全局  
>   grep 验证当前实现状态，确保每项缺口为真、每项新方向与历史分析零重叠。  
> **目标：** 列出 5 个**当前任何分析文档均未覆盖**的高价值扩展方向，且与当前能力正交。

---

## 前置声明：项目成熟度与历史覆盖

本项目的协议覆盖面和后端能力经过多轮迭代已达到行业顶级水平——90+ `WithXxx` 选项、  
4 个嵌入式 SPA、6+ 存储后端、10+ 企业协议、OIDC/OAuth/SAML/FAPI/CAEP/SCIM 全覆盖。  
13 轮历史分析 + ROADMAP v5.0 + novel + post-protocol-layer 已经覆盖了：

| 已覆盖领域 | 来源 |
|---|---|
| Passkeys & Passwordless-First | v1 |
| 组织/Workspace 管理 | v1 |
| 实时风险会话智能 | v1 |
| 开发者生态 & API 平台 | v1 |
| BFF 安全模式 | v7 |
| IAL2 身份验证 & VC | v7 |
| B2B 委托管理 & select_account & i18n | v8 |
| 账户恢复 & Magic Link & 推送通知 | v9 |
| Terraform Provider & Active ITDR & 时钟偏差 | v6/v10 |
| CI/CD 身份 & OIDC for CI | v11 |
| MCP 协议 & LLM 智能体集成 | v12 |
| 可编程管道 & 自适应安全 & GitOps | v13 |
| AI 智能体身份 & 零知识证明 & 后量子密码 & 通用钱包 & Edge Mesh | novel-2026-07-11 |
| 跨设备身份连续性 & 事件智能 & PDP 即服务 & 令牌规模优化 & 身份分析 BI | post-protocol-layer |
| Hosted Login + Consent + Admin Console & B2B 连接 & OIDC 一致性 & 多副本韧性 & 安全供应链 | ROADMAP v5.0 |

**本报告 5 个方向属于全新领域，与上述所有历史分析零重叠。**

---

## 🌟 方向 1：特权访问管理（PAM）—— 零信任管理员工作流与临时权限提升

### 现状

项目拥有完善的 **break-glass 紧急访问** 机制（`interfaces/admin/break_glass.go`）  
和基础 admin scope 模型（`readonly`/`impersonate`/`escalate`），但：

- **零时间绑定的权限提升工作流**：没有"申请→审批→自动过期"的特权提升管道
- **零临时凭据铸造**：所有 admin 操作使用长效 bearer token，从不颁发短时、单操作、  
  自动撤销的临时凭据
- **零特权会话审计**：没有记录 admin 操作全过程的"会话录像"或按键级记录
- **零审批链条**：break-glass 是自我声明式的，没有多层审批（如 "需要安全主管 +  
  值班经理同时 approve"）

### 缺口（grep 核验）

| 概念 | 实现状态 |
|---|---|
| `PrivilegeElevation\|privilege_elevation\|ElevatedSession\|elevated_session` | **零实现** |
| `EphemeralCredential\|ephemeral_credential\|TempCredential\|temp_credential\|TimeBoundToken\|time_bound_token` | **零实现** |
| `AdminApproval\|admin_approval\|ApprovalWorkflow\|approval_workflow\|ApprovalChain\|approval_chain` | **零实现** |
| `PrivilegedSession\|privileged_session\|SessionRecording\|session_recording` | **零实现** |
| `JustInTimeAdmin\|jit_admin\|JustInTimePrivilege\|jit_privilege` | **零实现** |

### 为什么需要它

1. **SOC2 / ISO27001 / PCI-DSS 合规硬需求**：所有这三个框架要求"特权访问必须被  
   审查、批准、记录，且权限不应是永久的"。SOC2 CC6.3 明确要求"特权用户的活动必须  
   被监控和记录"。无 PAM = 在金融/医疗/上市 SaaS 企业 RFP 第一轮被筛掉。
2. **真正的零信任管理员**：今天 break-glass 是静态 scope + 认证用户自声明。  
   在真正的零信任模型中，admin 在获得批准前没有特权，每次提升都是临时、一次性的。
3. **内部威胁缓解**：最危险的攻击面来自拥有永久 admin 令牌的内部人员。  
   PAM 将"我能一直做任何事"变为"我只能在批准后短时做特定事"。

### 范围

#### 1. PAM 核心 SPI（`shared/core` / `shared/spi`）

```go
// PrivilegedAccessStore 管理特权提升请求、审批和临时凭据。
type PrivilegedAccessStore interface {
    // CreateRequest 创建一个特权提升请求（操作、时长、理由）。
    CreateRequest(ctx, userID, clientID, operation string, duration time.Duration, reason string) (*PrivilegeRequest, error)
    // ApproveRequest 由授权审批者批准请求。
    ApproveRequest(ctx, requestID, approverID string) error
    // DenyRequest 拒绝请求。
    DenyRequest(ctx, requestID, approverID, reason string) error
    // MintEphemeralToken 在审批通过后铸造一个绑定的短时 token。
    MintEphemeralToken(ctx, requestID string) (*EphemeralToken, error)
    // RevokeEphemeralToken 提前撤销临时 token（超时自动撤销）。
    RevokeEphemeralToken(ctx, tokenID string) error
    // ListPendingRequests 列出待审批的请求（用于审批人面板）。
    ListPendingRequests(ctx, approverID string) ([]*PrivilegeRequest, error)
}

type PrivilegeRequest struct {
    ID, UserID, ClientID, Operation string
    Status       RequestStatus  // pending, approved, denied, expired
    Duration     time.Duration
    Reason, CreatedAt string
    ApprovedBy, ApprovedAt string
}

type EphemeralToken struct {
    ID, TokenValue string
    ExpiresAt      time.Time
    BoundOperation string
    Scope          []string
}
```

#### 2. 审批工作流（`protocols/pam/`）

- 审批链定义：单层 → 多层（链式审批），审批人可以是用户、角色或外部系统
- 紧急覆盖：当审批人不可达时，可配紧急审批人组（与 break-glass 集成但不替代）
- 审计事件：每个阶段（requested/approved/denied/minted/revoked）输出独立审计事件

#### 3. 临时凭据铸造（`infrastructure/defaultimpl/defaultpam/`）

- 基于 OAuth token-exchange 铸造：使用 `grant=token-exchange` + `actor_token`  
  作为身份证明，产出 scope 受限、TPR 内嵌的 access token
- 自动撤销：token 过期自动撤销，也可被审批者/admin 提前吊销
- 会话绑定：临时 token 绑定到创建的 `PrivilegedSession`，所有操作记录到该会话上下文

#### 4. Admin 面板集成（`interfaces/web/admin/`）

- 请求创建面板：选择操作、时长、理由
- 审批面板：待审批队列 + 审批/拒绝按钮
- 活跃特权会话仪表盘：查看所有当前活跃特权会话
- 审计回放视图：按 session 查看所有 admin 操作（利用已有 `audit.Query`）

### 边界情况

- 审批人不可达时的 fallback：紧急联系人组 / 法定人数（N-of-M）审批
- 避免审批疲劳：低风险操作（如只读指标查看）可自动批准，高风险（如删除租户）强制
  多人审批
- 跨时区审批超时：审批窗口可配（默认 15 分钟），超时自动拒绝
- 与现有 break-glass 的关系：PAM 是计划内提升，break-glass 是紧急降级覆盖，  
  两者共存但不重叠——break-glass 仍然是非审批的自声明提升（需审计），PAM 审批  
  后提升

### 工作量估算

| 组件 | 大小 | 依赖 |
|---|---|---|
| PAM SPI + 核心类型 | M（~300 行） | 无 |
| Memory 参考实现 | S（~150 行） | SPI |
| 审批工作流引擎 | L（~600 行） | SPI |
| 临时凭据铸造（复用 token-exchange） | M（~300 行） | token-exchange |
| Admin 面板 UI | M（~400 行前端） | 已有 admin 前端 |
| sqlite/postgres/redis 持久化 | 各 S | SPI |

---

## 🌟 方向 2：身份联邦代理 / 跨域身份网关（Identity Federation Broker）

### 现状

项目拥有 **上游 SAML / OIDC IdP 连接器**（`domains/authenticators/oidc_federation.go` +  
`infrastructure/saml/sp/`）和 **OpenID Federation 1.0**（`domains/federation/`），  
但它们是**点到点**的——每个连接器对应一个固定上游 IdP，没有：

- **多协议翻译**：不能把 SAML Assertion 翻译为 OIDC ID Token 或反之
- **Hub-and-Spoke 联邦代理**：IdP 之间没有信任中间人，每个下游 RP 需要独立信任  
  每个上游 IdP
- **跨域身份路由**：没有基于 email domain / org 属性的智能路由到正确的上游 IdP
- **联邦会话桥接**：用户从一个 IdP 认证后，期望无缝访问另一个 IdP 保护的资源

### 缺口（grep 核验）

| 概念 | 实现状态 |
|---|---|
| `FederationBroker\|federation_broker\|IdentityBroker\|identity_broker` | **零实现** |
| `CrossDomainTrust\|cross_domain_trust\|DomainBridge\|domain_bridge` | **零实现** |
| `ProtocolTranslation\|protocol_translation\|SAML2OIDC\|oidc2saml\|SAMLTransformer` | **零实现** |
| `IdentityRouter\|identity_router\|AuthnRouter\|authn_router` | **零实现** |
| `FederationGateway\|federation_gateway\|TrustGateway\|trust_gateway` | **零实现** |

### 为什么需要它

1. **M&A 场景的企业刚需**：公司收购后需要快速桥接两个组织的身份系统——Acme 用 Okta  
   （OIDC），BigCo 用 ADFS（SAML），两者需要互信。点到点配置需要 N² 个 trust，  
   联邦代理降为 N。
2. **B2B SaaS 的多 IdP 路由**：大型 SaaS 平台（Slack、Salesforce）需要让每个企业客户  
   使用自己的 IdP（SAML 或 OIDC），同时提供一个平台级 IdP 选项（hosted login）。  
   代理模型比"每个客户建一个连接器"更具扩展性。
3. **政府/教育联邦**：eduGAIN、InCommon、SWAMID 等学术联邦要求 IdP 通过一个  
   代理（Proxy IdP）接入，而非直接注册到每个 SP。这是 SAML 联邦的标准模式。
4. **协议迁移路径**：组织从 AD FS（SAML）迁移到 Azure AD（OIDC）期间需要 bridge  
   组件来保持服务连续性。身份网关可以作为迁移代理。

### 范围

#### 1. 代理 IdP SPI

```
Protocol Layer: SAML ↑  ↔  Federation Broker  ↔  OIDC ↓
                      ↑                         ↓
                 SP-facing                   IdP-facing
```

核心 SPI 定义：

```go
type FederationBroker interface {
    // DetermineIdP resolves which upstream IdP should handle this authn request.
    DetermineIdP(ctx, domain, acrValues, clientMetadata string) (UpstreamIdP, error)
    // BridgeSession creates a federated session linking the upstream identity
    // to a local identity or asserting a transient one.
    BridgeSession(ctx, upstreamSubject string, attrs map[string]interface{}, idp UpstreamIdP) (*FederatedSession, error)
    // TranslateAssertion converts between assertion formats.
    TranslateAssertion(ctx, sourceFormat, targetFormat string, assertion []byte) ([]byte, error)
}

type UpstreamIdP struct {
    ID             string
    Type           IdPType  // saml, oidc, ws-fed
    EntityID       string
    SSOEndpoint    string
    MetadataURL    string
    CertificatePEM string
    // Protocol-specific config
    OIDCConfig  *OIDCUpstreamConfig
    SAMLConfig  *SAMLUpstreamConfig
    // IdP-initiated SLO / logout URL
    SLOSupport bool
    // Trust attributes
    AuthnContextClassRef []string
    IAL                  int  // identity assurance level if known
}
```

#### 2. 协议翻译引擎（`protocols/broker/translators/`）

- **SAML → OIDC**：把 SAML Assertion 的 NameID/AttributeStatement 翻译为  
  ID Token claims。核心映射：`eduPersonPrincipalName` → `sub`、`mail` → `email`、  
  `eduPersonScopedAffiliation` → `groups`。扩展属性通过 `claims` 参数投影。
- **OIDC → SAML**：把 ID Token claims 翻译为 SAML 2.0 Assertion。OIDC `sub` →  
  SAML NameID（persistent format），`claims` 映射到 AttributeStatement。
- **WS-Fed → OIDC（未来）**：ADFS 常用 WS-Trust/WS-Federation，翻译为 OIDC 令牌。

#### 3. 无缝 SSO 会话桥接（`protocols/broker/session/`）

- 用户在 IdP_A 认证后，在资源域（IdP_B 的 RP）访问时无需重新认证
- 使用 OAuth token-exchange + 联邦断言：`actor_token` 携带 IdP_A 的 assertion，  
  `subject_token_type=urn:...:saml2:assertion`，换取 IdP_B 域的本地 access token
- 会话声明周期：联邦会话 TTL < 各 IdP 会话 TTL 的最小值

#### 4. 发现与元数据聚合（`protocols/broker/discovery/`）

- 统一的 Entity Metadata 注册表（聚合所有上游 IdP 的 SAML/OIDC 元数据）
- 跨域 `/.well-known/` 端点：代理暴露统一的发现端点，聚合多条元数据
- 信任锚管理：每个域的可信 CA 证书列表 + 证书自动轮换检测

### 边界情况

- **循环检测**：IdP_A 的 SP 指向 Broker，Broker 又把认证路由回 IdP_A——必须检测  
  并拒绝
- **断网降级**：上游 IdP 不可到达时，Broker 回退到本地备用 IdP（hosted login），  
  并记录审计
- **属性冲突**：两个上游 IdP 返回冲突属性（如不同 email）——需要可配的冲突解决策略  
  （"IdP_A 优先级更高" / "合并" / "拒绝"）
- **SLO 传播**：用户从一个 IdP 登出，Broker 必须向所有相关 IdP 和 RP 传播登出信号  
  （复用现有 backchannel/frontchannel logout 机制）

### 工作量估算

| 组件 | 大小 | 依赖 |
|---|---|---|
| Broker SPI + 核心类型 | M（~400 行） | 无 |
| SAML↔OIDC 翻译引擎 | XL（~1500 行） | SAML + OIDC 现有物 |
| 会话桥接（复用 token-exchange） | M（~400 行） | token-exchange |
| 发现与元数据聚合 | M（~500 行） | 现有 discovery 缓存 |
| Admin 面板：联邦拓扑可视化 | L（~600 行前端） | admin 前端 |

---

## 🌟 方向 3：零常驻权限（ZSP）与持续授权评估

### 现状

项目拥有完善的 **OAuth scope + 权限系统**（`domains/permissions/`）和  
**条件访问策略**（`domains/conditionalaccess/`），但授权模型全部基于"请求时"  
检查——令牌颁发后权限不再更新。问题：

- **无持续授权**：令牌在 TTL 内即使权限被撤销仍有效
- **无零常驻权限模型**：用户（包括管理员）默认拥有一些权限，而非"零权限、按需申请"
- **无上下文敏感细粒度授权**：授权决策在请求者上下文中做出（IP、时间、设备状态），  
  但决策是二元的——没有"允许但仅 X 次"、"允许但仅从 Y 地点"、"允许但需附加验证"  
  等条件
- **无风险敏感降权**：高风险操作在高风险上下文中不应自动拒绝，而应自动降权或  
  要求附加 MFA 验证

### 缺口（grep 核验）

| 概念 | 实现状态 |
|---|---|
| `ZeroStandingPrivileges\|ZSP\|zero_standing\|ZSP` | **零实现** |
| `ContinuousAuthorization\|continuous_authorization\|ContinuousAccess\|continuous_access` | **零实现** |
| `ContextSensitiveAuthz\|context_sensitive\|RiskBasedAuthz\|risk_based_auth\|AdaptiveAuthz\|adaptive_authz` | **零实现** |
| `OperationLevelAuthz\|operation_level\|MethodLevelAuthz\|method_level_authz\|ActionBasedPolicy\|action_based` | **零实现** |
| `JustInTimePermission\|jit_permission\|PermissionElevation\|permission_elevation\|ScopeElevation\|scope_elevation` | **零实现** |

### 为什么需要它

1. **新兴行业标准**：Google BeyondCorp、Microsoft Zero Trust、NIST SP 800-207  
   全部要求"持续验证，从不信任"——令牌不得被当作永久通行证。
2. **OAuth 安全最佳实践当前缺口**：BCP（RFC 9700 草案）建议持短 TTL + 实时撤销，  
   但最安全模式是**每次操作都重新评估**。
3. **真正解决"被盗令牌"问题**：即使 JWT 被盗，持续授权引擎在每次使用时重新评估  
   ——如果请求来自不可信的网络/设备/时间，即时拒绝。
4. **Fine-Grained Authorization (FGA)** 趋势：Google Zanzibar、Auth0 FGA、  
   Oso、Cedar 让授权从"笨重的 RBAC"进化为"灵活的关系/属性模型"。

### 范围

#### 1. 持续授权中间件（`protocols/continuousauthz/`）

```go
// ContinuousAuthorizer is evaluated on EVERY API request (not just at token issuance).
type ContinuousAuthorizer interface {
    // Authorize returns an AuthorizationDecision for the current request context.
    // Called as middleware BEFORE every protected handler.
    Authorize(ctx context.Context, req *AuthorizationRequest) (*AuthorizationDecision, error)
}

type AuthorizationRequest struct {
    Subject    string        // user ID
    ClientID   string        // OAuth client
    TokenID    string        // JTI of the presented token
    Operation  string        // e.g., "user:read", "user:write:email"
    Resource   string        // e.g., "user/abc123", "tenant/acme"
    Context    AuthzContext  // IP, geo, time, device posture, risk signals
}

type AuthorizationDecision struct {
    Allowed        bool
    ElevationRequired bool   // if false, suggest step-up
    RequiredACR    string     // e.g., "phr" for phishing-resistant
    Reason         string
    // Degradation policy: allow but log, allow but audit, deny
    EnforcementMode EnforcementMode
    // Session-bound token re-issuance
    SessionTTL time.Duration
}
```

#### 2. ZSP 权限存储 + 管理 API（`domains/zsp/`）

- 用户默认无权限；权限通过以下方式获得：
  - **会话内授权**：每次 api 调用时，如果用户无此操作权限，自动触发生成式授权
  - **时间-bound 角色分配**：admin 给用户分配角色时，必须指定有效期
  - **操作级提权**：与方向 1 PAM 类似，但不一定是 admin 操作——任何 scope 提升  
    都需要审批或 MFA step-up
- 权限存储：每条权限记录带 `expires_at`，过期自动删除
- API：`POST /api/v1/admin/zsp/grants`、`GET /api/v1/admin/zsp/active`、  
  `DELETE .../grants/:id`

#### 3. 风险自适应降权引擎（复用 `shared/trust` + `domains/conditionalaccess`）

- 高可信上下文（公司内网 + 注册设备）→ 快速通行
- 低可信上下文（陌生国家 + VPN）→ 所有操作要求 step-up MFA
- 异常上下文（新设备 + 午夜）→ 只读模式，写操作被拒绝直到认证提升
- 与现有 `conditionalaccess` 的关系：现有的是"登录时"策略，这是"每次操作时"策略

#### 4. 与现有授权系统的集成

| 现有组件 | 集成方式 |
|---|---|
| `permissions.Provider` | 作为 ZSP 的"角色定义源"，ZSP 是运行时决策层 |
| `conditionalaccess.Evaluator` | 降级的时候调用评估器做上下文检查 |
| `trust.TrustScorer` | 作为上下文决策的输入信号（信任分数） |
| `oauth.token-exchange` | 作为临时 scope elevation 的协议出口（铸造受限 token） |

### 边界情况

- **写密集型操作的性能**：持续授权在内核热路径上（每请求），必须 <1ms 延迟。  
  使用本地缓存 + bus 异步失效（与现有 client-cache 模式一致）
- **降级风控**：如果授权 store 不可达，fallback 到现有 token-scope 模型而不拒绝服务
- **授权膨胀**：持续授权可能被运维忽略为"总是 approve"——需要周期性 access  
  certification（方向 4）来补上
- **与现有 SCIM/权限的关系**：ZSP 是运行态授权层，不替代持久角色/权限定义

### 工作量估算

| 组件 | 大小 | 依赖 |
|---|---|---|
| 持续授权 SPI + 核心类型 | M（~400 行） | `shared/trust`, `domains/permissions` |
| ZSP 权限存储 + 管理 API | L（~800 行） | SPI |
| 风险自适应降权引擎 | XL（~1200 行） | conditionalaccess + trust |
| 中间件集成 | M（~300 行） | server 中间件链 |
| Admin 面板：ZSP 管理 | M（~500 行前端） | admin 前端 |

---

## 🌟 方向 4：身份治理与自动化权限认证（Identity Governance & Access Certification）

### 现状

项目拥有**合规框架**（`protocols/compliance/`——GDPR 导出/擦除、Soc2 报表、  
DataMap、Consent 记录、租户导出）和 **SoD 约束**（`domains/permissions/sod.go`），  
但仍然缺少企业身份治理的核心能力：

- **零认证活动**：没有"谁拥有什么权限"的周期性审查（access certification）流程
- **零合规仪表盘**：没有给 CISO/审计员看的"组织身份健康"仪表盘
- **零自动违规检测**：没有"张三同时是财务经理和审计员→违反职责隔离"的运行时检测
- **零权限分析**：没有"最有权力的用户"、"最活跃的授权"、"孤儿账户"等分析视图
- **零角色工程**：没有基于角色的最小权限推荐的自动化工具（role mining）

### 缺口（grep 核验）

| 概念 | 实现状态 |
|---|---|
| `AccessCertification\|access_certification\|CertificationCampaign\|certification_campaign` | **零实现** |
| `IdentityGovernance\|identity_governance\|IGA\|GovernanceReview\|governance_review` | **零实现** |
| `RoleMining\|role_mining\|RoleEngineering\|role_engineering\|LeastPrivilegeRecommend\|least_privilege\|PermissionMining\|permission_mining` | **零实现** |
| `OrphanAccount\|orphan_account\|InactiveUser\|inactive_user\|DormantAccount\|dormant_account` | **零实现** |
| `ComplianceDashboard\|compliance_dashboard\|IdentityDashboard\|identity_dashboard\|CISO\|ciso\|GovernanceDashboard` | **零实现** |

### 为什么需要它

1. **SOC2 / ISO27001 / SOX 合规刚性要求**：这三个框架全部要求"组织必须定期审查  
   用户对系统和数据的访问权限"且"审查过程必须有记录"。无 access certification =  
   直接审计不合格。
2. **最小权限原则的验证闭环**：项目已经实现了最小权限的技术控制（scope、permissions、  
   SoD 约束），但没有验证这些控制**在工作实践中是否有效**。certification 是技术控制  
   的"人的验证"。
3. **企业采购的最长尾问题**：CISO 问的第一个问题不是"支持什么协议"，而是  
   "我如何知道谁有权访问什么、并且确保合规"。无治理 = 无大企业采购。
4. **与现有能力的杠杆效应**：项目已有 audit、permissions、SoD、compliance、  
   tenant 模型，身份治理是整合这些能力的高价值产品层。

### 范围

#### 1. Certification Campaign 引擎（`protocols/governance/certification/`）

```go
type CertificationCampaign struct {
    ID             string
    Name           string
    Description    string
    Scope          CampaignScope  // org, tenant, role-based, user-based
    Reviewers      []string       // who must certify
    DueDate        time.Time
    Status         CampaignStatus // draft, active, completed, archived
    AutoRemediate  bool           // auto-revoke uncertified access
}

type CertificationItem struct {
    UserID        string
    Permissions   []string
    Roles         []string
    LastAccessAt  time.Time
    Justification string
    Decision      ReviewDecision // approved, revoked, modified
    ReviewedBy    string
    ReviewedAt    time.Time
}
```

- **创建 campaign**：按租户/角色/用户范围创建审查活动
- **审查工作流**：审查人收到通知 → 逐条审查 → approve/revoke/modify
- **自动修正**：超时未审或标记为 revoke 的权限自动移除
- **审计链**：每个 campaign 的每个决定都记录到 audit trail（利用现有 `audit.Recorder`）

#### 2. 权限分析仪表盘（`protocols/governance/analytics/`）

| 视图 | 数据源 |
|---|---|
| **最有权力的用户**（按分配的 scope/role 数量排序） | `permissions.Provider` |
| **最活跃的权限**（按使用频率排序） | `audit.Query`（统计 token 使用） |
| **孤儿账户**（有角色但从未登录的用户） | `UserProvider` + `audit.Query` |
| **权限分布**（每个 scope 被多少用户持有） | `permissions.Provider` |
| **SoD 违规实时仪表盘** | `permissions.SoDProvider` + 用户角色扫描 |
| **角色重叠**（哪些角色实际被分配了相同 scope 集） | `permissions.Provider` |

#### 3. 角色挖掘引擎（`protocols/governance/rolemining/`）

- 输入：当前所有用户的权限分配矩阵
- 输出：推荐的角色定义 + 每个用户应在哪些角色中的建议
- 算法：基于权重的角色聚类（与 Amazon Identity Role Mining、SailPoint 模式一致）
- 用途：帮助组织从扁平权限模型演进为结构化 RBAC

#### 4. 合规报告模块（与现有 `compliance` 包集成）

| 报告 | 说明 |
|---|---|
| **访问认证报告** | 某次 campaign 的完整结果 |
| **SoD 违规报告** | 当前所有 SoD 冲突 + 最近解决的历史 |
| **权限漂移报告** | 自从上次认证以来新增/移除的权限 |
| **身份健康评分** | 综合评分（孤儿账户比例、过期角色、未认证权限数等） |

### 边界情况

- **超大型 enterprise 的 campaign 规模**：5 万用户 × 100 项权限 = 500 万条审查项  
  必须支持抽样审查 + 基于角色的批量 approve
- **回避 SoD 审查疲劳**：连续 approve 的审查人需要确认对话（"您连续 approve 了  
  50 项，确认继续？"）
- **campaign 并发冲突**：两个 campaign 同时修改同一用户的权限 → 后一个生效  
  并记录冲突
- **与方向 1 PAM 的集成**：certification 发现的"从不使用 PAM 但拥有永久特权"的  
  用户应被建议迁移到 PAM 模型

### 工作量估算

| 组件 | 大小 | 依赖 |
|---|---|---|
| Certification Campaign SPI + 引擎 | XL（~1500 行） | `permissions`, `audit` |
| 权限分析仪表盘 API | M（~500 行） | `audit.Query`, `permissions` |
| 角色挖掘引擎 | L（~800 行） | `permissions` |
| SoD 违规实时扫描 | M（~400 行） | `permissions.SoDProvider` |
| Admin 面板：Governance | L（~800 行前端） | admin 前端 |

---

## 🌟 方向 5：身份数据平台 / 目录即服务（Identity Data Hub & Directory-as-a-Service）

### 现状

项目拥有**用户存储**（UserProvider）、**SCIM API**（`protocols/scim/` 作为  
SCIM 服务提供者）、**LDAP 认证器**（`infrastructure/ldap/` 认证用，非同步用），  
但缺少企业身份目录的核心能力：

- **零出站 HR 系统同步**：无法从 Workday / BambooHR / Rippling 自动创建/更新/  
  禁用用户
- **零入站 AD/LDAP 同步**：无法从 Active Directory 或 LDAP 目录同步用户和组  
  （现有 LDAP 只能认证，不能同步）
- **零属性生命周期管理**：没有属性映射、转换、默认值、源优先级等目录工程能力
- **零组织管理层级**：没有部门树/汇报关系/成本中心等组织结构数据
- **零批次导入与冲突解决**：现有 cmd 级别的 YAML 导入无法处理"增量同步 vs 全量  
  覆盖"、"外部唯一 ID 冲突"、"已删除用户恢复"等 production 级需求

### 缺口（grep 核验）

| 概念 | 实现状态 |
|---|---|
| `DirectorySync\|directory_sync\|SyncEngine\|sync_engine\|DirSync\|dir_sync` | **零实现** |
| `HRProvisioning\|hr_provisioning\|HRSync\|hr_sync\|WorkdayProvision\|BambooProvision\|RipplingProvision` | **零实现** |
| `AttributeMapping\|attribute_mapping\|AttributeTransformation\|attribute_transform\|AttributeLifecycle\|attribute_lifecycle` | **零实现** |
| `OrgStructure\|org_structure\|OrgTree\|org_tree\|DepartmentHierarchy\|department_hierarchy\|CostCenter\|cost_center\|ManagerChain\|manager_chain` | **零实现** |
| `BulkImport\|bulk_import\|ConflictResolution\|conflict_resolution\|Reconciliation\|reconciliation` | **零实现** |

### 为什么需要它

1. **身份数据的"第一公里"**：企业身份系统的基础不是认证/授权，而是**从哪里来**。  
   HR 系统是权威用户来源（入职/转岗/离职），AD 是权威组来源。没有数据进入管道，  
   SSO 服务器就是个空壳。
2. **SCIM 的完整闭环**：现在 SCIM 只做了"别人可以调 SCIM API 管理用户"（Provider），  
   没有做"自动调别人的 SCIM API 去抓用户"（Client for upstream）。企业需要双向。
3. **Auth0/Okata/Azure AD 的核心差异化**：这些竞品不只是认证代理——它们是  
   身份目录平台。Azure AD 的核心是目录，Auth0 的 Users Store 是产品核心。  
   没有目录层，项目只是个"认证引擎"，不是"身份平台"。
4. **Deferred-backlog 的实证缺口**：`deferred-backlog.md` 确认"核心 User 模型无密码  
   hash 字段、无批量导入、无懒迁移"。这是数据层的缺口，不补则企业迁移场景不可行。

### 范围

#### 1. 目录连接器框架（`protocols/directory/connectors/`）

```go
// DirectoryConnector is the SPI for connecting to an external identity authority.
type DirectoryConnector interface {
    // Connect establishes the connection to the external directory.
    Connect(ctx context.Context) error
    // FullSync performs a full synchronization of all users and groups.
    FullSync(ctx context.Context) (*SyncResult, error)
    // IncrementalSync performs an incremental sync since the last watermark.
    IncrementalSync(ctx context.Context, since time.Time) (*SyncResult, error)
    // Disconnect closes the connection.
    Disconnect(ctx context.Context) error
}

type DirectoryConfig struct {
    Type     DirectoryType  // azuread, ldap, workday, scim, generic
    BaseDN   string         // for LDAP
    TenantID string         // for Azure AD
    // Auth
    ClientID     string
    ClientSecret string
    Certificate  []byte
    // Sync config
    SyncInterval    time.Duration
    AttributeMap    AttributeMapping
    ConflictPolicy  ConflictPolicy  // source_wins, newest_wins, manual
    DeletionPolicy  DeletionPolicy  // soft_delete, disable, delete
}
```

预置连接器：

| 连接器 | 协议 | 方向 |
|---|---|---|
| **Active Directory / LDAP** | LDAP(S) | 双向（读用户/组，可选写禁/启） |
| **Azure AD** | Microsoft Graph API | 入向（同步用户、组、许可证） |
| **Workday** | Workday RaaS / SCIM | 入向（员工入职/转岗/离职） |
| **SCIM 2.0 Client** | SCIM 2.0 | 入向或双向（与其他 SCIM 服务互操作） |
| **Google Workspace** | Admin SDK / Directory API | 入向（同步用户/组） |
| **Okta / OneLogin** | SCIM / API | 入向 |

#### 2. 属性生命周期引擎（`protocols/directory/attrlifecycle/`）

```
外部属性 (HR source)       映射规则              内部属性 (core.User)
─────────────────    ────────────────    ─────────────────
workday:EmployeeID    → 1:1               external_id
workday:PreferredName → concat(first,last) display_name
workday:Email         → lower+dedup       email
workday:Department    → enum_map          部门树 → tenant.department
workday:ManagerID     → ref_resolve       manager_id
workday:CostCenter    → passthrough       attribute.scim:cost_center
workday:IsActive      → status_map        status (active/inactive/suspended)
ad:distinguishedName  → ignore            (不导入内部)
ad:memberOf           → group_lookup      → group membership
default               → if null, set      → attribute.scim:department (默认值)
```

- 映射支持：直接映射、转换函数（lower/md5/date_format）、条件映射（if attribute X exists）、  
  默认值、优先级（多个源冲突时哪个源优先）
- 属性历史：每次属性变更写入审计事件（`audit_recorder`）并保留历史值

#### 3. 同步编排引擎（`protocols/directory/orchestrator/`）

```go
// SyncOrchestrator manages the full lifecycle of directory sync operations.
type SyncOrchestrator struct {
    Connectors   map[string]DirectoryConnector
    Mappings     AttributeMapping
    Scheduler    *cron.Scheduler
    EventBus     *cluster.Bus  // publish on user create/update/delete
}
```

- 调度器：可配的 cron 表达式（`sync_interval`），也支持 webhook 触发增量同步
- 冲突解决策略：
  - `source_wins`：外部源的值覆盖内部
  - `newest_wins`：按时间戳最近者胜
  - `manual`：标记为冲突，等待管理员在 admin console 解决
- 删除策略：
  - `soft_delete`：设置用户 status=inactive（保留数据）
  - `disable`：禁用用户（保留但不能登录）
  - `delete`：从 UserProvider 删除
- 审计：每次同步输出 `audit.Event`（同步开始、记录数、新增、更新、删除、失败）

#### 4. 组织模型扩展（`domains/organization/`）

```go
type Organization struct {
    ID          string
    Name        string
    Type        OrgType // company, department, team, cost_center
    ParentID    string  // for hierarchy
    ExternalID  string  // from HR system
    Attributes  map[string]string
}

type OrgMembership struct {
    UserID         string
    OrganizationID string
    Role           string  // member, manager, head, etc.
    StartDate      time.Time
    EndDate        *time.Time
}
```

- 与现有 `Tenant` 模型的关系：Organization 是 Tenant 内部的层级结构。  
  Tenant 是隔离/计费单位，Organization 是身份/权限组织单位。
- 支持：部门树展示、按部门分配角色、经理审批链（与方向 1 PAM 审批人解析联动）

#### 5. 批次导入与拖放 API

- `/api/v1/admin/import`：接受 CSV/JSON 格式的批次用户导入
- `/api/v1/admin/import/status/:job_id`：查看导入任务状态
- 冲突处理：可选的 `upsert`（创建或更新）vs `create_only` vs `update_only`
- 预览模式：先预览变化再提交（diff）
- 导入任务驱动模式：后台异步执行 + WebSocket 进度推送（复用现有 SSE broker）

### 边界情况

- **同步风暴**：HR 系统一次性推送上千个变更（如年度重组）→ 限流的批量处理（每秒 N 条）
- **属性漂移**：外部源删除了一个属性但本地被手动修改过 → 源不得覆盖手动标记过的属性
- **循环同步**：Connector A → 写入 UserProvider → 触发 Connector B 的同步事件 →  
  写入外部系统 → 反馈回 Connector A → 无限循环。必须加同步来源标记防回传。
- **慢速外部目录**：AD 全量同步 >10 万用户可能分钟级。分批 + progress 通知 + 可中断。
- **操作者误操作**：误触发全量导入删除了 5000 个用户 → 软删除 + 可恢复窗口（7 天回收站）

### 工作量估算

| 组件 | 大小 | 依赖 |
|---|---|---|
| 目录连接器框架 SPI | M（~500 行） | 无 |
| AD/LDAP 连接器 | L（~800 行） | `infrastructure/ldap` |
| Azure AD 连接器 | L（~800 行） | Microsoft Graph API |
| Workday 连接器 | M（~600 行） | Workday RaaS |
| SCIM 2.0 Client 连接器 | M（~500 行） | `protocols/scim` （反用）|
| 属性生命周期引擎 | L（~1000 行） | `core.User` 扩展 |
| 同步编排引擎 | XL（~1500 行） | `cluster.Bus` |
| 组织模型 | M（~400 行） | `domains/tenant` |
| 批次导入 API | M（~500 行） | 现有 YAML 导入模式 |
| Admin 面板：目录管理 + 组织视图 | L（~800 行前端） | admin 前端 |

---

## 优先级矩阵

| 方向 | 商业价值 | 工程复杂度 | 合规驱动力 | 差异化 | 优先级 |
|---|---|---|---|---|---|
| **① PAM / 临时特权** | 🔴 高 | 🟡 中 | 🔴 SOC2/SOX/PCI | 🟢 强 | **P0** |
| **② 联邦代理 / 跨域网关** | 🔴 高 | 🔴 高 | 🟡 NIST 800-207 | 🟢 极强 | **P0** |
| **③ 零常驻权限与持续授权** | 🟡 中高 | 🔴 高 | 🟡 NIST 800-207 | 🟢 极强 | **P1** |
| **④ 身份治理与权限认证** | 🔴 高 | 🟡 中 | 🔴 SOC2/SOX/ISO27001 | 🟡 中 | **P0** |
| **⑤ 身份数据平台 / 目录服务** | 🔴 高 | 🔴 高 | 🟡 无直接 | 🟢 强 | **P1** |

### 一句话优先级

**①（PAM）与 ④（身份治理）并行驱动合规采购（SOC2/SOX 直接问这两项）→  
②（联邦代理）打开复杂的 M&A/跨域企业场景，是竞品（Auth0/Okta）也没有的差异化  
→ ③（持续授权）与 ⑤（目录平台）作为平台基础能力持续建设。**  
①和④复用大量现有基础设施（audit、permissions、SoD、compliance），是最短路径到  
企业采购清单的高 ROI 方向。

---

## 与当前代码库的交叉关系

| 方向 | 直接复用的现有模块 |
|---|---|
| ① PAM | `interfaces/admin/break_glass.go`（紧急覆盖模式）· `protocols/oauth/token-exchange`（临时凭据铸造）· `platform/audit`（审计链）· `interfaces/admin/middleware.go`（授权拦截） |
| ② 联邦代理 | `infrastructure/saml/sp/`（SAML SP）· `domains/authenticators/oidc_federation.go`（OIDC IdP）· `domains/federation/`（OpenID Federation）· `shared/security/jwks_verify.go`（多算法 JWKS） |
| ③ 持续授权 | `shared/trust/`（信任评分器）· `domains/conditionalaccess/`（条件访问策略）· `domains/permissions/`（权限引擎）· `platform/metrics/`（可观测性） |
| ④ 身份治理 | `domains/permissions/sod.go`（SoD 约束）· `protocols/compliance/`（GDPR/SOC2）· `platform/audit/`（审计查询）· `domains/permissions/memory_resources.go`（权限存储） |
| ⑤ 目录平台 | `infrastructure/ldap/`（LDAP 连接）· `protocols/scim/`（SCIM Provider）· `shared/core/spi.go`（UserProvider SPI）· `platform/cluster/bus.go`（事件广播） |
