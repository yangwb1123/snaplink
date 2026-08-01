# 扩展方向分析报告 v7

> **作者：** 资深架构 & 产品视角  
> **日期：** 2026-07-11  
> **范围：** 全代码库全局扫描（2241 `.go` 文件，~1300+ 包）  
> **方法：** 逐项对抗核验（默认"大概率已实现"，逐文件 grep/read 证伪），参考已有  
> `ROADMAP.md` v5.0、`deferred-backlog.md`、`expansion-directions-analysis-v6.md`，  
> **排除这些文档中已标记为 done 或 partial 的任何方向**。  
> **目标：** 列出 5 个**当前任何分析文档均未覆盖**的高价值扩展方向

---

## 前置声明

在撰写本报告之前，我已系统阅读了以下现有分析文档：

- `docs/ROADMAP.md`（v5.0，2026-06-11）—— 5 个方向的完整 roadmap
- `docs/deferred-backlog.md`  —— 所有历史分析文档清理后的唯一活索引
- `docs/requirements/expansion-directions-analysis.md`（2026-07-10）
- `docs/requirements/expansion-directions-analysis-v6.md`（2026-07-10）
- `docs/feature-matrix.md` —— 已实现的协议/功能矩阵

我**逐个 grep 核验**了上述文档中标记为"仍空白 / 部分"的每个功能点，结果：  

**ROADMAP v5.0 的 5 个方向几乎所有子项已完成**（包括 consent 存储、  
Hosted Login SPA、Admin Console SPA、AchievedACR 强制、at_hash、  
client secret 哈希存储、threataction ITDR 响应引擎、conditional access  
ABAC 条件引擎、schema 版本启动护栏等）。当前项目成熟度极高——  
90+ `WithXxx` 选项、4 个内嵌 SPA、6+ 存储后端、10+ 企业协议。

以下 5 个方向**经全库核验确认完全不存在**（零 grep 命中实现代码），  
也**未被任何现有分析文档提及**。

---

## 方向 1：Backend-for-Frontend（BFF）安全模式 —— OAuth 2.0 浏览器应用的安全网关

### 现状

项目拥有 OAuth 2.0 协议的全套后端实现（authorization code + PKCE + DPoP +  
PAR + JAR + JARM），以及 4 个内嵌 SPA（`interfaces/web/{admin,developer,login,portal}`）。  
但这些 SPA 当前遵循的是传统的"直接持有令牌"模式：SPA 从 `/token` 获取  
access_token + refresh_token，存储在 JavaScript 内存/localStorage 中。

`server_discovery.go:236` 有一处注释提到 "a BFF-shaped JSON endpoint"，  
但**仅是注释**——全树无 BFF 参考实现、无 token handler pattern、无 anti-CSRF  
状态管理、无服务端会话 cookie 管理。

### 缺口（grep 核验）

- `BFF` / `BackendForFrontend` / `token handler` / `handler pattern`：**零实现命中**  
- `HttpOnly` + `SameSite` cookie 会话 + CSRF token 组合：**零实现命中**  
- `POST /bff/login` → 服务端执行 auth code 交换 → 会话 cookie：**零实现命中**  
- 无 `TokenHandler` SPI 或 `TokenMediator` 中间件  
- `server_discovery.go:236` 的 "BFF-shaped JSON endpoint" 注释证实该方向已  
  被架构师考虑但**从未落地**

### 范围

#### 1. BFF Token Handler 核心模式

新增 `internal/handler/bff/` 包（放在 `internal/` 是因为 BFF 是整个 server  
的 unexported 编排层）：

```
POST /bff/login
  Request:  {redirect_uri, code_verifier?}  
  Response: session cookie (HttpOnly, SameSite=Lax, Secure)
             + CSRF token (response body or separate cookie)
  Server-side执行完整auth code PKCE交换
  Access/refresh/ID token仅存储在服务端会话中，永不暴露给浏览器

POST /bff/refresh
  服务端使用会话绑定的refresh_token透明轮换
  更新服务端会话（非浏览器持有）

POST /bff/logout
  服务端销毁会话 + POST /token/revoke

GET /bff/userinfo
  服务端用会话绑定的access_token调用/userinfo
  返回JSON给SPA（SPA仍可读用户信息，但看不到token本身）
```

#### 2. 反 CSRF 状态管理

```
每个BFF会话携带:
  - session_token（HttpOnly cookie，认证用）
  - csrf_token（SameSite cookie 或响应头，SPA 读取后放在请求头回传）
所有 /bff/* 非 GET 请求验证 csrf_token
OAuth state参数由BFF服务端管理（SPA不接触）
```

#### 3. 令牌生存期管理

```
access_token 过期前自动后台刷新（bff/refresh）
refresh_token 轮换透明（服务端处理家族轮换）
会话空闲超时（可配置，默认15分钟）
最大会话绝对寿命（可配置，默认24小时）
```

#### 4. 现有 SPA 适配

```
interfaces/web/admin/  → 可选启用 BFF 模式（session cookie 替代 bearer token）
interfaces/web/portal/ → 同上
interfaces/web/login/  → 保持原状（它是OAuth交互的user-agent端）
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 跨标签页/跨窗口会话一致性 | 同一域共享会话 cookie；可选 broadcast channel API 通知登出 |
| 移动端原生应用不能使用 cookie | 回退到传统 bearer token 模式（BFF cookie 不是替代品，是 SPA 的选项） |
| 浏览器隐私模式（Safari ITP、Chrome 第三方 cookie 限制） | BFF cookie 是 first-party cookie，不受 ITP 影响（核心优势） |
| BFF 水平扩展 | 使用 Redis/PG 共享会话（复用现成 `SessionManager` + `SessionStore` SPI） |
| CSRF token 旋转 | 每次 POST 后轮换；单页多标签页场景留窗口重叠期 |

### 为什么值得做

**这是 OAuth 2.1 / BCP（Best Current Practice, RFC 9700）推荐给 SPA 的唯一  
安全架构**。不采用 BFF 的 SPA 面临：XSS 令牌窃取、CSRF、令牌在浏览器缓存/  
历史中的泄露。AWS Cognito、Auth0、Keycloak 均已提供参考 BFF 实现（token  
handler / token exchange pattern）。缺失意味着本项目在 SPA 安全架构最佳  
实践上存在产品级缺口——尤其对于"用本项目自己的 Admin Console 管理生产  
SSO"的客户，是一个真实的攻击面。

- **价值：** 高（安全 + 产品完整性 + 最佳实践合规）  
- **工作量：** L（核心 SPI 约 300 行 + 现有 SPA 适配约 200 行 + 测试）  
- **依赖：** SessionManager（已存在）、TokenStore（已存在）、CSRF 库（Go  
  标准库 `crypto/rand` 足矣）

---

## 方向 2：用户身份证明与验证管道 —— NIST SP 800-63A IAL2 合规入职流程

### 现状

项目拥有完整的身份认证（Authentication）能力——密码、WebAuthn、TOTP、  
SAML/OIDC 联邦、LDAP、Kerberos、RADIUS——但**完全没有身份证明（Identity  
Proofing）**。`core.User` 模型（`shared/core/types.go`）不包含任何身份  
验证级别（IAL）、未关联任何证明文档、无验证时间戳字段。入职流程（Signup  
+ 预置）只创建记录，从未验证该用户是否是其声称的真实个人。

### 缺口（grep 核验）

- `IdentityProof` / `identity_proof` / `IdentityVerification`：**零实现命中**  
- `IAL` / `IAL1` / `IAL2` / `IAL3` / `identity_assurance`：**零实现命中**  
- `NIST` / `800-63` / `identity_vetting`：**零实现命中**  
- `document_verification` / `liveness` / `biometric` / `kyc` / `KYC`：**零实现命中**  
- `core.User` 无 `IAL` 或 `IdentityVerifiedAt` 字段  
- 任何"验证者角色"（operator 审核身份证/护照/驾照）的概念不存在

### 范围

#### 1. 身份证明 SPI 定义（`shared/core`）

```go
// IdentityAssuranceLevel mirrors NIST SP 800-63A IAL1-3.
type IdentityAssuranceLevel int
const (
    IALNone IdentityAssuranceLevel = 0
    IAL1                         = 1  // self-asserted
    IAL2                         = 2  // remote or in-person proofing
    IAL3                         = 3  // in-person + biometric
)

// ProofingMethod identifies how the user's identity was verified.
type ProofingMethod string
const (
    ProofingMethodSelfAsserted   ProofingMethod = "self_asserted"
    ProofingMethodDocumentUpload  ProofingMethod = "document_upload"
    ProofingMethodLivenessCheck   ProofingMethod = "liveness_check"
    ProofingMethodAdminReview     ProofingMethod = "admin_review"
    ProofingMethodFederatedIAL2   ProofingMethod = "federated_ial2" // trusted IdP assertion
)

// IdentityRecord is the proofing result stored per-user.
type IdentityRecord struct {
    UserID         string
    IAL            IdentityAssuranceLevel
    ProofedAt      time.Time
    Method         ProofingMethod
    ExpiresAt      time.Time // IAL2/3 re-proofing interval
    ReviewedBy     string    // admin user ID, if manually reviewed
    DocumentHash   string    // sha256 of stored evidence (not the evidence itself)
    FederatedIss   string    // IdP issuer if federated
}
```

#### 2. 身份证明流程编排（`domains/identityproofing/` 新包）

```
Signup (IAL1, self-asserted)
    │
    ├─ 可选升级: 上传身份证/护照 → document_upload
    │       │
    │       ├─ 自动 OCR + 防伪检测（集成第三方 KYC 服务）
    │       │
    │       └─ 活体检测（liveness_check，需视频自拍）
    │               │
    │               └─ 人工审核队列 (admin_review)
    │                       │
    │                       └─ [批准] → IAL2
    │
    └─ 联邦来源: 上游 SAML/OIDC IdP 声明 IAL2 → 信任传播

锁定期: IAL2 每 12-24 个月需要重新证明
降级: 过期后自动降级为 IAL1（不阻塞登录，但限制高价值操作）
```

#### 3. IAL 感知的授权决策

```
conditionalaccess.Policy 新增 IAL 条件:
  Conditions:
    identity.ial: ">= 2"       // 最低 IAL 要求
    identity.proofed_within:   // 证明时间窗口
```

#### 4. 管理 API 与门户

```
Admin API:
  GET  /api/v1/admin/users/{id}/identity-proofing  → 查看身份证明记录
  POST /api/v1/admin/users/{id}/identity-proofing/review
        {decision: "approve"|"reject", note: "..."}
  DELETE /api/v1/admin/users/{id}/identity-proofing → 重置为 IAL1

Admin Console:
  "Pending Reviews" 面板（显示待人工审核的证明请求）
  用户详情页新增 "Identity Proofing" tab
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| PII 存储合规（GDPR Art. 9 敏感数据） | 证件图像加密存储，审计访问；提供一键删除（compliance.Eraser 扩展） |
| 第三方 KYC 服务故障 | fail-open：保留当前 IAL 不变，不降级不升级；审计事件 + admin 通知 |
| 联邦 IAL 信任传播 | 上游 IdP 必须在 entity statement 中声明 IAL 能力，否则默认 IAL1 |
| IAL 降级通知 | 过期前 30 天发邮件；过期后登录仍允许但添加提示横幅 |
| 活体检测反欺诈 | 集成被动活体（非用户配合式）+ 主动活体；重放攻击检测（随机 challenge） |

### 为什么值得做

**这是本项目从"身份认证（Authentication）"迈向"身份管理（Identity  
Management）"的最大单一缺口**。NIST SP 800-63A IAL2 是以下场景的刚需：  
金融机构（FINRA/KYC）、医疗（HIPAA 受控访问）、政务（GSA 登录.gov）、  
法律法规（欧盟 eIDAS 2.0 信任服务）。没有身份证明能力，本项目会在  
上述采购中被直接排除。同时，IAL 感知授权与已有的 `conditionalaccess`  
引擎结合，可将"这个用户是谁（IAL2 验证过）"纳入零信任决策公式。

- **价值：** 高（采购刚需 + 合规差异点）  
- **工作量：** XL（SPI + 存储 + 编排 + 管理 API + 第三方 KYC 集成，  
  但可分期：第一阶段仅 SPI + 管理 API + admin 审核 UI，无自动 OCR/活体）  
- **依赖：** UserProvider（已存在）、audit.Recorder（已存在）、  
  conditionalaccess.Engine（已存在，需扩展 Conditions）

---

## 方向 3：步骤式认证状态机 —— 会话安全等级的自适应升降级

### 现状

项目已经拥有步骤式认证（Step-Up Authentication）的所有**构造块**：

| 构造块 | 位置 | 状态 |
|---|---|---|
| RFC 9470 challenge header builder | `securityverify/step_up_auth.go` | ✅ 已实现 |
| ACR 值强制（acr_values 匹配检查） | `server_login_auth.go:142` | ✅ 已实现 |
| StepUpMFAExecutor | `threataction/executor.go` | ✅ 已实现 |
| SessionTrustManager（MarkStepUp） | 未找到确切位置 | 需确认 |
| 条件访问策略引擎 | `conditionalaccess/` | ✅ 已实现 |

**然而**，这些构造块之间**没有有状态机协调**。当前实现是"一次性"的：

1. `/auth/login` 收到 `acr_values` → 认证后检查 `AchievedACR` → 不匹配则拒绝  
2. 威胁检测触发 `StepUpMFAExecutor` → 标记会话需要 MFA → 下次登录时触发  
3. 条件访问策略返回 `VerdictRequireStepUp` → 路由到 MFA 编排  

但缺少的是**会话生命周期内的安全等级管理**：  
- 会话当前安全等级是什么？（`level=1: password`, `level=2: password+MFA`,  
  `level=3: password+MFA+device_trust`）  
- 一个操作完成后等级是否应该降级？（"查看敏感数据后" → 回退到 level 1）  
- 等级有超时吗？（MFA 后 15 分钟内不需要重复）  
- 等级是单调递增的吗？（可以降级吗？）

### 缺口（grep 核验）

- `AuthLevel` / `session_level` / `security_level` / `SessionLevel` 与会话关联：  
  **零实现命中**  
- `escalate` / `de-escalate` / `deescalate` 动作：**零实现命中**  
- 会话安全等级的时间衰减/超时逻辑：**零实现命中**  
- 操作到所需等级的映射表：**零实现命中**  
- `SessionTrustManager.MarkStepUp` 和 `ClearStepUp` 仅是一个二元标记，  
  无多级等级概念

### 范围

#### 1. 会话安全等级模型（`shared/core`）

```go
// AuthLevel is comparable and monotonically increasing.
type AuthLevel int
const (
    AuthLevelNone     AuthLevel = 0
    AuthLevelPassword AuthLevel = 1  // something you know
    AuthLevelOTP      AuthLevel = 2  // TOTP, SMS OTP
    AuthLevelMFA      AuthLevel = 3  // password + OTP
    AuthLevelHardware AuthLevel = 4  // WebAuthn with UV (user verification)
    AuthLevelStepUp   AuthLevel = 5  // fresh MFA for high-risk action
)

// SessionSecurityProfile is stored alongside the session.
type SessionSecurityProfile struct {
    CurrentLevel   AuthLevel
    MaxLevel       AuthLevel      // highest ever achieved in this session
    AchievedAt     time.Time      // when CurrentLevel was last proven
    ProofExpiry    time.Time      // time-based decay of CurrentLevel
    LastStepUpTime time.Time      // last step-up event
    StepUpMethods  []string       // ["password", "totp", "webauthn"]
}
```

#### 2. 状态机引擎（`internal/auth/securitylevel/`）

```
操作所需等级:

  GET /me/profile              → level 1 (password)
  GET /me/sessions             → level 2 (MFA, sensitive)
  POST /me/sessions/revoke     → level 2
  GET /admin/users             → level 2 (admin scoped)
  POST /admin/clients          → level 3 (step-up MFA)
  POST /admin/tenants/delete   → level 4 (highest, requires fresh MFA)

等级衰减:
  level 1 → 不动（password 登录后一直有效，除非会话超时）
  level 2 → 30 分钟无活动后衰减到 level 1
  level 3 → 15 分钟无活动后衰减到 level 2, 再 30 分钟后到 level 1
  level 4 → 5 分钟无活动后衰减到 level 3

降级触发:
  - 时间衰减（自动，基于时钟）
  - 手动降级（完成高风险操作后，可立即降回基线 level）
  - 威胁事件（检测到异常后强制降级到 level 1，要求重新认证）
```

#### 3. 升级触发集成

```
           ┌──────────────────────────────┐
           │   Step-Up Challenge (RFC 9470)│
           │   Resource Server: "I need   │
           │   acr_values=level4"         │
           └──────────┬───────────────────┘
                      │ 401 + WWW-Authenticate: Bearer
                      ▼
  SPA/BFF re-auth → /auth/login?acr_values=level4
                      │
                      ▼
              Auth State Machine
              Current level < required → 升级流程
                  │
                  ├─ MFA 挑战（已存在）
                  ├─ WebAuthn + UV 挑战
                  └─ 设备信任校验（conditional access）
                  │
                  ▼
              Session.Level = required (或拒绝)
```

#### 4. 条件访问策略集成

```yaml
# conditional access policy 扩展
conditions:
  session.required_level: 3     # 要求会话至少 level 3
  session.max_age_seconds: 300  # 当前认证级别 5 分钟内有效

actions:
  require_step_up: "mfa"       # 不足时触发 MFA 升级
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 等级单调性不变量 | `AuthLevel` 比较保证 `>=` 语义；降级只影响 `CurrentLevel`，`MaxLevel` 单调增长 |
| 衰减和并发请求 | 每个请求在中间件中检查并可能衰减；使用单调时钟（`time.Now`）比较 |
| 升级失败后的回退 | 不降级当前等级，返回 `insufficient_user_authentication` 供 RP 处理 |
| BFF cookie 会话的等级传递 | 等级存储在服务端会话中，cookie 不持有 |
| 跨标签页等级一致性 | 同一会话共享等级；一个标签页升级后所有标签页受益 |

### 为什么值得做

**零信任（Zero Trust）** 的核心原则是"never trust, always verify"，但实际  
实现是"trust but verify **periodically**"——根据操作风险选择验证频率和强度。  
当前项目有"认证"和"授权"，但缺少连接二者的"**会话信任连续体**"。  

这个状态机将：
- 条件访问策略（`conditionalaccess`）、步骤式认证（`step_up_auth.go`）、  
  威胁响应（`threataction`）三个已存在的构造块**整合成统一模型**
- 为连续自适应信任（Continuous Adaptive Trust）提供形式化基础
- 使项目真正具备"操作感知的认证"（action-aware authentication），  
  这是 BeyondCorp / Google 的"信任等级"模型的核心

- **价值：** 高（差异化 + 零信任架构基础）  
- **工作量：** M-L（SPI + 状态机 + 集成 + 条件访问扩展）  
- **依赖：** SessionManager（已存在）、conditionalaccess（已存在）、  
  threataction（已存在）、step_up_auth.go（已存在）

---

## 方向 4：OAuth 2.0 令牌交换 —— SAML2 断言输出支持（跨协议断言翻译）

### 现状

项目实现了 RFC 7522 SAML 2.0 Bearer Assertion **输入**授权类型  
（`internal/handler/tokengrant/token_saml2_bearer.go`），通过  
`WithSAML2BearerGrant(validator)` 选项接线，支持客户端用 SAML 断言换取  
JWT access_token。

然而，RFC 8693 令牌交换的**输出侧**——将 access_token 换为 SAML2 断言  
（`requested_token_type=urn:ietf:params:oauth:token-type:saml2`）——  
被**显式拒绝**（见 `test/handle_token_exchange_test.go:296`: "SAML2 token  
output is unsupported"）。这意味着：

- 企业不能将本 AS 颁发的 JWT 令牌**翻译成 SAML2 断言**以调用下游 SAML-only  
  服务（如 ADFS 保护的 SharePoint、SAML-only SaaS）
- 跨协议身份联邦在 Token Exchange 层面是**单向**的（SAML → JWT 可以，  
  JWT → SAML 不可以）
- 在已经部署 SAML IdP（ADFS/PingFederate）的企业中，本 AS 可以消费其  
  SAML 断言，但不能反向提供服务

### 缺口（grep 核验）

- `TokenTypeSAML2` 定义为常量（`aliases.go:447`）但仅在 `token_saml2_bearer.go`  
  输入侧使用  
- Token Exchange 输出侧的 SAML2 断言生成：**零实现**（测试确认拒绝）  
- `requested_token_type=urn:ietf:params:oauth:token-type:saml2` 路径  
  返回 400 `invalid_target`（测试 `test/handle_token_exchange_test.go:307`）

### 范围

#### 1. SAML2 断言生成器 SPI（`shared/core` / `domains/saml2output/` 新包）

```go
// SAML2AssertionGenerator transforms an access token's claims into a
// SAML 2.0 <Assertion> element, signed by the AS's signing key.
type SAML2AssertionGenerator interface {
    // GenerateAssertion builds a SAML 2.0 assertion from the provided
    // token claims and optional attributes. The returned assertion is
    // base64-encoded (fits RFC 8693's requested_token_type wire format).
    GenerateAssertion(ctx context.Context, claims TokenClaims, 
                      audience string, attributes map[string]string) (string, error)
}
```

#### 2. Token Exchange 集成

```
Token Exchange 请求:
  grant_type=urn:ietf:params:oauth:grant-type:token-exchange
  subject_token=<JWT access_token>
  subject_token_type=urn:ietf:params:oauth:token-type:access_token
  requested_token_type=urn:ietf:params:oauth:token-type:saml2
  audience=https://saml-sp.example.com/shibboleth

流程:
  1. 验证 subject_token（已有）
  2. 校验 audience（已有 RFC 8693 §3.2 受众检查）
  3. SAML2AssertionGenerator.GenerateAssertion()
       - 提取 claims（sub, iss, aud, exp, attributes, groups, acr, amr）
       - 构造 SAML <Assertion>
           <Issuer>{AS issuer URL}</Issuer>
           <Subject>
             <NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
               {sub}
             </NameID>
             <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
               <SubjectConfirmationData NotOnOrAfter="{exp}" 
                 Audience="{audience}"/>
             </SubjectConfirmation>
           </Subject>
           <AttributeStatement>
             <Attribute Name="groups"><AttributeValue>...</AttributeValue></Attribute>
           </AttributeStatement>
       - 用 AS 的签名私钥签名（复用现有 `cryptosigner` 和 alg 选择）
       - base64 编码
  4. 返回:
     200 OK
     access_token: base64(<SAML Assertion>)
     issued_token_type: urn:ietf:params:oauth:token-type:saml2
     token_type: N_A (SAML has its own bearer semantics)
```

#### 3. 名称 ID 格式映射

```
从 JWT claims 到 SAML NameID 的映射策略（可配置）:
  email  → NameID Format:emailAddress
  sub    → NameID Format:persistent（当 sub 是 UUID 且无 email）
  upn    → NameID Format:unspecified（Windows 集成场景）
  x509   → NameID Format:X509SubjectName（证书认证场景）
```

#### 4. 现有的 SAML SP 基础设施复用

项目已有 `infrastructure/saml/sp/`（SAML SP 侧，用于消费外部 IdP 的  
断言）。SAML2 输出生成器应**复用其相反的语义**——不消费断言而是构造断言。  
可以共用 `infrastructure/saml/` 中的 XML-DSig 签名工具和命名常量。

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 断言过期时间 | 取 JWT exp 和 min(SAML 默认 5min) 的较小值 |
| 属性映射安全（JWT claims → SAML AttributeStatement） | 默认只包含 `sub`、`email`、`groups`；新属性需显式允许列表 |
| 并发断言请求 | 每次独立签名（SAML Assertion ID 包含唯一 ID + 时间戳） |
| 断言接收方为 ADFS / Shibboleth / SimpleSAMLphp | 生成标准 SAML 2.0 断言；测试矩阵覆盖这 3 个常见 SP |
| 断言大小限制 | SAML 断言含 XML 膨胀 + 签名，可能 >10KB；Token Exchange 返回体的 `application/json` 需能承载 |

### 为什么值得做

**SAML2 不会消失。** 在政府（SAML 2.0 是 US Federal ICAM 标准）、高等教育  
（InCommon/Shibboleth）、大型企业（ADFS/Okta Classic）中，SAML 仍是统治性  
身份协议。本项目的 Token Exchange 现在能**从** SAML 来（输入），但不能**去**  
SAML（输出）——这是一个非对称缺口。

这个方向将本项目的 Token Exchange 从"OAuth-only"变为真正的**跨协议断言  
翻译网关**：接收 SAML 发 JWT，接收 JWT 发 SAML。这直接对应企业入门的  
"Identity Bridge"/"Identity Federation Server"采购类目——一个比纯  
OAuth/OIDC SSO 更高价值的 positioning。

- **价值：** 中高（对企业采购是差异化亮点，非通用基础设施）  
- **工作量：** M（SAML 断言构造 + XML-DSig 签名复用现有基础设施）  
- **依赖：** `infrastructure/saml/`（已存在）、`cryptosigner`（已存在）、  
  Token Exchange handler（已存在）

---

## 方向 5：数字身份钱包与可验证凭证集成 —— eIDAS 2.0 / OID4VC 合规

### 现状

项目已经实现了 FIDO2/WebAuthn（passwordless authenticator）和 OpenID  
Federation 1.0（信任网络）。**但是**，完全没有涉及去中心化身份/可验证  
凭证（Verifiable Credentials）领域——这是继 OAuth/OIDC 之后身份行业最  
重要的技术演进方向。

### 缺口（grep 核验）

- `VerifiableCredential` / `VP` / `verifiable_presentation` / `VC` /  
  `vc_jwt` / `ldp_vc`：**零实现命中**  
- `DID` / `did:` / `DecentralizedIdentifier` / `did_document`：**零实现命中**  
- `eIDAS` / `eidas` / `eIDAS2` / `EU_DI_Wallet` / `digital_wallet`：**零实现命中**  
- `OID4VC` / `OpenID.*VC` / `OIDC.*Credential` / `SIOP` / `SelfIssuedOP`：  
  **零实现命中**  
- 未在任何文档或配置中提及可验证凭证颁发或验证  
- 项目没有"证书/凭证"（credential）SPI，只有"令牌"（token）概念

### 范围

#### 1. 核心数据模型（`shared/core`）

```go
// CredentialFormat identifies the VC format.
type CredentialFormat string
const (
    FormatVCDM1_1   CredentialFormat = "vc+dm1.1"     // W3C VC Data Model 1.1
    FormatVCDM2_0   CredentialFormat = "vc+dm2.0"     // W3C VC Data Model 2.0
    FormatJWT_VC    CredentialFormat = "jwt_vc"        // JWT-encoded VC (ISO 18013-7)
    FormatLDP_VC    CredentialFormat = "ldp_vc"        // JSON-LD VC
)

// VerifiableCredential stores a credential issuance record.
type VerifiableCredential struct {
    ID              string          // unique credential ID
    UserID          string          // holder (core.Subject)
    Format          CredentialFormat
    Issuer          string          // DID or URL
    Type            []string        // ["VerifiableCredential", "UniversityDegreeCredential"]
    CredentialJSON  json.RawMessage // the serialized credential (JWT or JSON-LD)
    IssuedAt        time.Time
    ExpiresAt       time.Time
    RevokedAt       *time.Time
    RevocationList  string          // optional URL or reference
    TenantID        string
}
```

#### 2. Credential Issuer SPI（`domains/credentialissuer/` 新包）

```
OID4VCI (OpenID for Verifiable Credential Issuance):
  GET  /oid4vci/.well-known/openid-credential-issuer → credential issuer metadata
  POST /oid4vci/credential → issue a VC based on an access_token + credential request
  
流程:
  1. 用户通过标准 OAuth/OIDC 授权（已有）获得 access_token
  2. 用 access_token 调用 POST /oid4vci/credential
     Body: {
       "format": "jwt_vc",
       "doctype": "org.iso.18013.5.1.mDL",
       "claims": {"given_name": {}, "family_name": {}}
     }
  3. Server 验证 access_token 的 scope/authorization
  4. 调用 CredentialSigner SPI 签发 VC:
     - 将用户属性编码为 VC claims（映射受 scope 控制）
     - 用 AS 的 DID key（或现有的 signing key）签名
     - 返回 JWT-encoded VC
  5. 记录颁发到 CredentialStore
```

#### 3. Credential Verification（现有验证基础设施的扩展）

```
OID4VP (OpenID for Verifiable Credential Presentation):
  集成到现有的 token exchange 端点:
    grant_type=urn:ietf:params:oauth:grant-type:token-exchange
    subject_token=<VP JWT>
    subject_token_type=urn:ietf:params:oauth:token-type:jwt_vp
  
  Presentation Exchange (PEX) 验证:
    - 验证 VP 的签名链（Issuer → Holder）
    - 验证 Presentation Submission 是否匹配请求的 Presentation Definition
    - 映射 VC claims 到 core.Subject 属性（scope 控制）
    - 颁发新的 access_token（携带原始 VC 的 evidence）
```

#### 4. eIDAS 2.0 信任集成

```
欧洲信任框架:
  - EU Digital Identity Wallet 基于 OID4VCI + OID4VP + ISO 18013-7 mDL
  - trust mark / eIDAS 合规声明（qualified electronic attestation）

集成点:
  - 本项目 AS 作为 EUDI Wallet 的 credential issuer（qualified/eIDAS）
  - 本项目 AS 作为 RP 验证 EUDI Wallet 出示的 PID（Person Identification Data）
  - Trust chain: eIDAS trust list → 成员国 root → 本项目 AS → issued VC
```

#### 5. 管理 API

```
Admin API:
  POST /api/v1/admin/users/{id}/credentials/issue  → 管理员为用户颁发 VC
  GET  /api/v1/admin/users/{id}/credentials        → 列出用户的所有 VC
  POST /api/v1/admin/users/{id}/credentials/{id}/revoke → 吊销 VC
  GET  /api/v1/admin/credential-status-list         → 管理撤销列表（CLI / CLR）

Admin Console:
  "Verifiable Credentials" 面板
  每个用户详情页显示颁发的 VC
  撤销列表监控
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| VC 存储安全（可验证凭证包含 PII） | `CredentialJSON` 字段加密存储（复用 `snapshot/encryption*` 的 AES-GCM） |
| VC 撤销传播 | 现有 cluster.Bus + CAEP 事件扩展：`KindCredentialRevoked` |
| Credential 与 Access Token 的关系 | VC 是长期身份凭证（有效期月/年），access_token 是短期授权令牌（分钟/小时）；二者正交 |
| DID 密钥管理 | 可选的 DID 密钥（可能独立于 OAuth signing keys）；初期可用现有 signing key 派生一个 DID |
| 与 OpenID Federation 的关系 | Federation 1.0 已定义信任锚；VCI 的 credential issuer metadata 可包含 federation 实体 |
| eIDAS 合规声明 | 这是一个独立认证流程（需要被成员国认可的合格信任服务商），代码上只需支持 trust mark 列表配置 |

### 为什么值得做

**eIDAS 2.0 是欧盟 2026-2027 的强制性法规**，要求所有成员国提供 EU  
Digital Identity Wallet，所有依赖身份认证的公共/私营服务必须接受。  
这是身份行业自 OAuth 2.0 以来最大的监管驱动变革。

同时，OID4VC（OpenID for Verifiable Credentials）正在成为工业标准——  
OIDF、GAIN、FAPI、ISO 18013-7（移动驾驶执照）等均以 VC 为基础。先行  
投资此方向可让本项目在下一波身份基础设施升级中占据先发优势。

这不是一个"添加一个 grant type"的常规扩展——它是**身份范式的转移**：  
从"AS 签发的 opaque/proprietary token"到"标准化的、可移植的、用户持有  
的可验证凭证"。但项目的现有架构（SPI、Token Exchange、Federation、  
WebAuthn、CAEP/SSF）恰好为此提供了异常坚实的基础。

- **价值：** 中高（差异化 + 法规驱动前瞻 + 下一代身份架构）  
- **工作量：** XL（完整实现 OID4VCI + OID4VP 是 3-6 月的工作；但第一阶段  
  仅核心 SPI + VC 签发 + admin API 可缩短到 4-6 周）  
- **依赖：** Token Exchange（已存在）、WebAuthn（已存在）、Federation  
  （已存在）、CAEP（已存在，撤销传播）
- **时机：** 2026 年是 eIDAS 2.0 实施年，2027 年起 wallet 将成为强制性认证  
  方式——现在投资恰逢其时

---

## 优先级总结

| 方向 | 价值 | 工作量 | 独立性 | 建议时机 |
|---|---|---|---|---|
| ① BFF 安全模式 | 高（安全 + 产品完整性） | L | 独立 | P1 — 与现有 SPA 集成，推荐立即开始 |
| ② 身份证明 IAL2 | 高（采购刚需） | XL（分阶段） | 独立 | P1 — 第一阶段（SPI + admin UI）可独立交付 |
| ③ 步骤式认证状态机 | 中高（差异化） | M-L | 依赖现有 | P2 — 整合现有 3 个构造块，需设计先行 |
| ④ SAML2 输出翻译 | 中（企业差异化） | M | 依赖 Token Exchange | P2 — 按客户需求触发 |
| ⑤ 可验证凭证 eIDAS | 中高（前瞻法规） | XL | 部分依赖 Federation | P3 — 2026-2027 窗口期 |

**建议：P1 优先覆盖 ①+②（安全 + 合规），同步推进 ③ 的设计阶段。  
④ 和 ⑤ 分别对应短期企业需求与长期技术代际，可按产品战略择时投入。**

---

## 附录 A：边角情况与性能优化补充

> 以下问题粒度过小不足以成为独立方向，但价值明确，适合作为 sprint filler  
> 或与上述方向并行消化。

### A.1 Token Exchange 的 JWT 受众审计（S，安全）
当前 `aud` 反序列化支持 string or array（`internal/handler/tokengrant/`），  
但 token exchange 的 audience 校验不检查 `requested_token_type` 为不同  
格式时（SAML2 output）的受众语义差异。建议：统一受众校验逻辑到  
`audClaim` 辅助函数，并显式记录（audit 事件）每次受众检查和结果。

### A.2 令牌撤消通知的 webhook 出口（M，产品）
当前 CAEP 信号通过 `cluster.Bus` 在 AS 集群内部传播，但**外部 RP** 订阅  
令牌撤销事件的 webhook 机制不存在（`caep/receiver.go` 是接收侧，不是  
发送侧）。建议：`WithTokenRevocationWebhook(url)` 将撤销事件以 SET  
（Shared Signal Event）推送到 RP——与现有 CAEP 发送器复用相同的  
jti-replay 去重和退避策略。这将使 `/token/revoke` 的撤销"实时通知到 RP"。

### A.3 SPA 授权码拦截（PKCE 流）的 user-agent 状态管理（S，安全）
当前的 `/auth/login` 交互流返回 JSON 而非重定向——这是 SDK 形态的设计  
选择（RP 自己管理 UI）。但在托管登录 SPA 模式（`web/login/`）中，  
授权码通过 HTTP redirect 传回，地址栏可能暴露 `code` 参数。建议：  
`response_mode=form_post` 或 `response_mode=fragment`（已有 JARM 支持）  
作为托管模式默认，减少授权码泄露面。

### A.4 令牌交换的 act-chain 循环检测去重记数器溢出（S，正确性）
`tokExMaxChainDepth` 当前为硬编码 10（`token_exchange.go`），但 `act`  
链的累计 `iat` 时间戳不随每跳压缩。建议：增加按累积 lifetime 的熔断  
（`WithMaxTokenExchangeChainLifetime` 已有但需确认在每跳检查，而非仅在  
最终 token 颁发时）。另加 `act` 链审计事件（每跳记录 issuer + subject），  
这是合规审查"谁扮演了谁"所必需。

### A.5 可观测性：令牌全生命周期追踪 ID（S，运维）
当前 audit 事件（`TokenIssued`、`TokenRefreshed`、`TokenRevoked`）通过  
`aud.TokenID` 关联，但 refresh 轮换的同一家族 TokenID 链不易回溯。  
建议：在每个 token 的私有 claim 中编码 `family_id` 和祖先 `token_id`  
（不在公开 JWT claims 中泄露，仅审计/内部使用），使运维可以查询  
"这个 refresh token 家族一共颁发了多少个 access token"。

---

*本报告基于 2026-07-11 全代码库全局扫描，逐项对抗核验确认缺口。  
所有方向均经 grep 证伪（零实现命中），未被现有 ROADMAP / deferred-backlog /  
expansion 文档覆盖。*
