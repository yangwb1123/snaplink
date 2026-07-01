# 架构级扩展方向分析报告

> 基于 2026-07-01 对全代码库（1630 个 `.go` 文件，~230K 行）的全局扫描。  
> 分析视角：资深架构师 / 产品经理。  
> 定位：**ROADMAP v5.0（06-11）及 `analysis-final-project-expansion-directions.md`（06-30）均未覆盖的新方向**。  
> 原则：不写代码，只分析。每条方向经对抗式 grep 核验为真缺口。

---

## 总体判断

项目已完成从**协议 SDK** 到**可运行身份平台**的关键跨越：

| 维度 | 状态 |
|------|------|
| OAuth 2.0 / OIDC 协议面 | 极完整（30+ RFC，含 CIBA/RAR/JARM/DPoP/FAPI） |
| 嵌入存储 | memory + SQLite + Redis + Postgres + etcd 全覆盖 |
| 企业联邦 | SAML SP/IdP + OIDC Federation + LDAP/Kerberos/RADIUS |
| 多副本集群 | 签名密钥聚合 + 总线失效 + 跨副本撤销广播 |
| 运维面 | 管理 gRPC/REST API + 托管 SPA 门户 + Admin Console |
| 安全 | 抗枚举 + Oracle-leak 加固 + 常量时间 + Fuzz 测试 |

以下 5 个方向是**ROADMAP 及此前 22 轮分析均未提及**的真正新缺口，按"如果只能挑一件先做"排序。

---

## 方向一：OAuth 2.0 JWT Bearer Token Grant（RFC 7523）——缺失的核心 grant_type

### 概况

- **工作量**：M（~200 行 + 测试）
- **价值**：高（基础性 gap，直接影响云原生/CI/CD 场景采纳）
- **类型**：协议扩展

### 为什么需要

当前 `SupportedGrants` 列表（`shared/core/consts_oauth.go:119`）包含 6 种 grant_type，但**缺少 `urn:ietf:params:oauth:grant-type:jwt-bearer`**（RFC 7523）：

```
authorization_code, refresh_token, client_credentials,
urn:ietf:params:oauth:grant-type:device_code,
urn:ietf:params:oauth:grant-type:token-exchange,
urn:openid:params:grant-type:ciba
```

JWT Bearer Grant 允许一个客户端**出示一个外部 IdP 签发的 JWT 作为授权授权**来换取 access token。这是以下场景的核心协议：

| 场景 | 典型 JWT 来源 | 重要性 |
|------|---------------|--------|
| GCP Workload Identity | GCP 元数据服务器颁发的 OIDC token | 极高——K8s 上 GKE 工作负载的首选方式 |
| AWS 跨账户访问 | STS `AssumeRoleWithWebIdentity` 接受 JWT | 高——AWS EKS 服务账户令牌 |
| Azure Managed Identity | IMDS 端点提供的 OIDC token | 高——Azure 容器/VM 的默认身份 |
| DevOps CI/CD | GitHub Actions OIDC token / GitLab CI JWT | 高——无凭据管道部署 |
| External IdP | 非 OIDC 上游（Legacy SAML IdP 签发的 JWT） | 中 |

**现状对比**：
- Token-exchange（RFC 8693）已实现，但要求双方都理解 token-exchange 协议
- JWT Bearer Grant 更简单——**接受一个 JWT 就签发 access token**，无需 `subject_token_type` / `actor_token_type` 协商
- SAML Bearer Grant（`saml/saml_bearer_grant.go`）**已存在**，JWT 等价物反而缺失，形成不对称

### 范围

1. **Grant handler**（~80 行）：`HandleJWTBearer` 函数，解析 `assertion` 参数，验签（复用 `security.VerifyCompactJWS`），验证 `iss`/`sub`/`aud`/`exp`，映射到 client/subject，签发 token
2. **常量声明**（~10 行）：`GrantJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"`，加入 `SupportedGrants`
3. **可配置的信任锚**（~60 行）：`WithJWTBearerIssuers(map[string]*jwkSet)`——每个 `iss` 对应一个 JWKS，用于验证断言签名。支持 OIDC Discovery URL 自动获取
4. **可选的客户端绑定**（~30 行）：`Client.JWTBearerAllowedIssuers`——限制哪些 issuer 的 JWT 可以被此客户端使用
5. **测试**（~150 行）：Happy path + 签名失败 + 过期 + 未知 iss + 错误 aud + 恶意 assertion

### 关键设计约束

- **Oracle-leak**：所有验证失败（坏签名、过期、未知 iss、格式错误）坍缩为单一 `invalid_grant`
- **Clock skew**：可配置 `WithJWTBearerMaxClockSkew`（默认 30s）
- **Audience 验证**：`aud` 必须匹配客户端 ID 或资源指示器
- **Replay 防护**：可选的 `jti` + `JTIReplayStore` 检查（复用现有 `WithJTIReplayStore`）
- **Act 链**：不应影响 token-exchange 的 act 链语义；这是独立 grant，不产生 act 链
- **与现有 token-exchange 的关系**：两者独立共存。JWT Bearer 从外部 JWT 直接签发 access token；token-exchange 从一个存续的 access token 兑换另一个

### ROI

- **假设**：GCP/Azure 上的 K8s 部署可以直接交换其工作负载身份 token。GitHub Actions 管道可以直接使用 OIDC token 做 SSO 登录
- **竞品差距**：Keycloak、Auth0、Okta **均支持** JWT Bearer Grant。缺少它对"云原生身份平台"的定位是一个可证实的短板
- **工作量**：M（200 行 + 核心逻辑 + 测试），因为项目的 JWT 验证底座已经完备（`security.VerifyCompactJWS`、`JWKS`、`JTIReplayStore`）

---

## 方向二：Transaction Tokens（TxT，RFC 9321）——细粒度事务级授权

### 概况

- **工作量**：L（新 API 表面 + 事务状态管理 + 客户端 SDK）
- **价值**：中-高（前瞻差异化项目）
- **类型**：协议扩展

### 为什么需要

TxT（OAuth 2.0 Transaction Tokens）定义了授权服务器如何签发一个**绑定到特定事务上下文**的 token。客户端在向 RS 请求时**同时**出示 access token 和 transaction token，RS 据此验证操作是否被授权。

**当前状态**：项目已实现 RFC 9396（RAR），允许客户端在授权请求时携带细粒度的 `authorization_details`。但此信息在当前 token 中**未显式编码**为可消费的结构化 token——RS 只能看到 scope + claims，无法知道 authorization_details 的原始 intent。

**TxT 解决的问题**：

| 问题 | 当前状态 | TxT 后 |
|------|----------|--------|
| RS 审计粒度 | 仅记录 scope + subject | 可记录具体操作类型 + 资源 + 条件 |
| 分布式授权决策 | RS 需自己解析 authorization_details | RS 验签 TxT 即可获得完整事务上下文 |
| 细粒度委托 | access token 是 bearer，TxT 绑定到具体操作 | 操作级委托 + 不超过 scope 的子集 |
| 操作链路追踪 | 跨服务无法关联一次授权决策与具体操作 | TxT 携带 `authorization_details` + `parent_txt_id` |

### 范围

1. **TxT SPI**（~60 行）：`TransactionToken` struct + `TransactionTokenStore`（创建/验证/撤销）
2. **TxT 签发端点**（~120 行）：`POST /txt`（经 `/token` 扩展：`grant_type=urn:ietf:params:oauth:grant-type:transaction-token` 或独立端点）。可选 `authorization_details`、`resource`、`location` 参数
3. **TxT 验证端点**（~80 行）：`POST /txt/introspect`（RS 侧验证 TxT 有效性 + 返回原始事务上下文）
4. **与现有 RAR 集成**（~40 行）：RAR 的 `authorization_details` 在 TxT 签发时作为事务上下文携带
5. **与 token-exchange 集成**（~50 行）：token-exchange 可以产出 TxT 作为输出 token_type，或在其 act 链中携带 parental TxT
6. **JWT 格式的 TxT**（~80 行）：TxT 编码为独立 JWT（`typ=transaction-token+jwt`），使用现有 issuer 底座签发
7. **客户端/RS SDK**（~100 行）：TxT 的构造/验证 helper，用于 RP 和服务间调用

### 关键设计约束

- **TxT 不是 access token 的替代品**：客户端仍需要 access token；TxT 是并行出示的
- **绑定**：TxT 可以可选地通过 `cnf` 绑定到 DPoP key / mTLS 证书
- **TTL**：TxT 的 TTL 通常短于 access token（分钟级到小时级），因为它绑定到特定事务
- **一致性模型**：AP 即可——TxT 的验证依赖签发时的事务上下文快照，无需跨副本强一致
- **与 CAEP 的集成点**：事务撤销可以通过 CAEP 信号广播（`EventVerification`），闭环了 From "coarse-grained token revocation" → "fine-grained transaction revocation"

### ROI

- **假设**：金融级 API（FAPI 2.0 消息级签名）、开放银行（PSD2）、医疗（FHIR）场景需要事务级授权审计
- **竞品差距**：TxT 是 2024 年标准化的较新 RFC。多数竞品尚未支持——先发优势
- **与 RAR 的化学作用**：项目已经有了 RAR + token-exchange + FAPI profile——TxT 补全了最后一块拼图，形成"请求授权（RAR）→ 事务绑定（TxT）→ 令牌交换（token-exchange）→ 持续评估（CAEP）"的完整链路
- **工作量**：L 但大部分是已知模式的组合复用

---

## 方向三：正式威胁模型与对抗性测试框架

### 概况

- **工作量**：M（文档 + 可执行测试套件 + CI 集成）
- **价值**：高（安全基线，SOC 2 / Pentest 预备项）
- **类型**：安全工程

### 为什么需要

项目有坚实的防御编码（抗枚举、Oracle-leak、常量时间、fail-closed 红线），但**缺乏正式的威胁模型文档和自动化的对抗性测试框架**：

| 缺失项 | 后果 | 典型场景 |
|--------|------|----------|
| 无 STRIDE / 攻击树文档 | SOC 2 审核员无法验证威胁是否被系统性处理 | 采购安全问卷问题 #27："请描述您的威胁建模过程" |
| 无自动化渗透测试 | 回归安全属性无保障 | 修改了 grant 处理写了一个新的 oracle-leak → 旧测试通过但新路径泄露 |
| 无已知攻击模式测试矩阵 | 无法证明"已知攻击已被测试" | 同一请求被重放攻击、JWT alg=none、SSRF 等 |
| 无安全回归 CI 门禁 | 新功能可能静默降级安全属性 | 添加了新 grant_type 但忘了 `tokenNoStoreHeaders` |

**现有安全测试覆盖**：
- Fuzz 测试 7 个目标（JWT 解析、JAR URL 校验、bind_params、JWE unwrap、aud_claim 等）✅
- 安全不变式检查（`checks/invariants.py`）✅
- 但无**端到端攻击场景测试**：模拟攻击者进行完整的 token 重放、会话固定、授权码拦截等

### 范围

1. **威胁模型文档**（~2 页）：以 STRIDE 分类法分析三大攻击面：① 令牌端点（/token、/introspect、/revoke）② 授权端点（/auth/*）③ 管理端点与数据存储。每项列出：威胁描述、当前缓解措施、残余风险、测试引用
2. **对抗性测试套件**（~500 行）：`test/adversarial/`（`package adversarialtest`）——一个可执行的、文档化的测试套件，每个已知攻击模式一个测试用例：

   | 攻击类别 | 测试用例数 | 示例 |
   |----------|-----------|------|
   | Token 重放 | 3 | 同 JAR request_uri 被重放 → invalid_grant |
   | 授权码拦截 | 2 | 攻击者获取 auth_code 后尝试在 /token 出示 |
   | Alg none 绕过 | 2 | JWT alg=none 被拒绝 |
   | 会话固定 | 2 | /auth/login 后 session_id 不变 |
   | Oracle-leak 回归 | 5 | 未知 vs 过期 vs 已消费 vs 不匹配 → 相同错误 |
   | 跨副本重放 | 2 | 负载均衡到副本 B 的已使用 refresh token → 家族击杀 |
   | SSRF | 2 | JAR / federation fetch 的 DNS rebind |
   | Claim 注入 | 2 | JWT 中额外 claim 通过 (scope 外) |
   | 时序侧信道 | 1 | 未知用户的 bcrypt dummy hash 耗时 ≈ 真实用户 |
   | 权限提升 | 2 | admin:write 但只持有 admin:read → 403 |

3. **安全回归 CI 门禁**（~30 行 CI 配置）：对抗性测试套件作为 CI 中独立作业运行（`make adversarial-test`），与常规单元测试分离。失败 = 硬阻断 PR
4. **已知攻击模式文档**（~1 页）：公开文档（`docs/known-attacks.md`），列出已知攻击类别以及本系统的缓解措施。既指导渗透测试人员，也作为采购安全问卷的"答案"文档

### 关键设计约束

- **测试必须真实**：不要 mock——使用真实的 `Memory*` 后端 + 真实的 HTTP 调用（httptest / bufconn）
- **不可见性**：攻击者不应从测试命名/文档中学习到源代码中未文档化的 oracle 信息
- **免维护**：不要为攻击测试写特殊的生产代码——所有缓解措施已经在生产代码中。测试只验证现有行为
- **低误报**：测试必须幂等，不依赖时钟敏感操作（time.Now 对比固定 fixture 时间）

### ROI

- **假设**：一个结构化、可执行的安全验证框架，每次 CI 运行都自动测试已知的攻击向量。渗透测试人员可以引用"攻击 3.2 已知被以下测试覆盖：`TestReplayJARRequestURI`"
- **竞品差距**：Keycloak 和 Ory Hydra 有安全测试但没有结构化的、文档化的威胁模型
- **工作量**：M（主要是一次性测试编写 + 文档编写）
- **前置依赖**：方向一（JWT Bearer Grant）和方向二（TxT）的新功能会增加攻击面——威胁模型应在它们落地后更新

---

## 方向四：云原生工作负载身份连接器（AWS/GCP/Azure 免密接入）

### 概况

- **工作量**：L（每个云约 120 行 + 集成测试）
- **价值**：中-高（云部署的"零配置"入场券）
- **类型**：生态集成

### 为什么需要

项目已支持 SPIFFE JWT-SVID token-exchange（`security/spiffe_svid.go`），全面覆盖 **K8s 原生**工作负载身份。但**三大云厂商**的工作负载身份是独立生态、使用不同的凭证格式：

| 云平台 | 凭证形态 | 使用场景 |
|--------|----------|----------|
| AWS | IAM Roles Anywhere 凭证 / EKS Pod Identity 的 OIDC token | EKS 上运行的工作负载、EC2 实例 |
| GCP | GKE Workload Identity 的 OIDC token / VM 元数据 token | GKE、Compute Engine |
| Azure | Managed Identity 的 OIDC token（IMDS 端点） | AKS、Azure VM、Azure Container Apps |

**现状**：token-exchange 或未来 JWT Bearer Grant（方向一）理论上可以接受这些 token，但需要运营者自己写：
1. 从云元数据端点获取凭证的逻辑
2. 验证云平台签发的 JWT 的 JWKS 配置
3. 云平台 `aud` / `iss` 的正确映射

这三点每个云都不一样，且配置易出错。一个开箱即用的适配器可以屏蔽所有差异。

### 范围

1. **`infrastructure/cloudidentity/` 包**——三个独立的适配器：

   | 适配器 | 凭证获取 | 验证 |
   |--------|----------|------|
   | `cloudidentity/aws.go` | EKS Pod Identity Agent 文件 / IMDSv2 端点 | AWS OIDC provider 的 JWKS（`cognito-identity` / `sts.amazonaws.com`） |
   | `cloudidentity/gcp.go` | GKE 元数据服务器 / GCE 元数据端点 | `googleapis.com` 的 OIDC JWKS |
   | `cloudidentity/azure.go` | IMDS 端点（169.254.169.254） | Azure AD 的 OIDC 发现文档 |

2. **统一 SPI**（~40 行）：

   ```go
   type WorkloadIdentityProvider interface {
       // Acquire returns a signed JWT (or other credential) that can be
       // exchanged for an SSO access token. error if the workload is not
       // running on the corresponding cloud platform.
       Acquire(ctx context.Context, audience string) (string, error)
       
       // Verify returns the trust anchor JWKS for validating this
       // platform's signed assertions.
       Verify(ctx context.Context) (*jose.JSONWebKeySet, error)
   }
   ```

3. **直接令牌交换集成**（~60 行）：`WithCloudWorkloadIdentity(providers...)`——服务启动时检测云环境，自动执行 token-exchange（或未来的 JWT Bearer Grant），无需运营者配置 client_id/secret

4. **自动发现示例**（~30 行）：`cmd/sso-server` 中的条件初始化：如果运行在 GKE 且有 Workload Identity 注解，自动检测并使用

### 关键设计约束

- **零依赖**：每个云适配器使用其对应的 SDK（`aws-sdk-go-v2`、`gcp cloud.google.com/go`），但这些 SDK 不应进入核心 go.mod。使用 `infrastructure/kms/*` 模式——嵌套模块 + 运营者 cmd 侧接线
- **Fallback 语义**：非云部署（裸机/VM）应当干净地跳过——`Acquire` 返回错误，不 panic、不 block
- **凭证轮换**：云平台凭证通常有 1h TTL。适配器应透明处理轮换（内部缓存 + 提前刷新）
- **Audience 验证**：云平台签发的 OIDC token 的 `aud` 可能是 SPIFFE 格式（`spiffe://...`）或 URL 格式。适配器需要可配置的 audience 映射

### ROI

- **假设**：GKE 上的一个 pod 连接到 SSO 目前需要：生成 client_id + secret → 注入为 K8s Secret → 挂载为环境变量 → SSO 用它做 client_credentials。有了云工作负载身份连接器后：**零配置**——SSO 自动检测 Pod 的 Workload Identity，自动交换为 SSO access token
- **竞品差距**：Auth0 有 `aws:iam` token-exchange 集成但需要手动配置。此方向提供自动检测
- **工作量**：L——每个云适配器约 120 行代码 + 集成测试，模式高度重复

---

## 方向五：会话风险实时重评估与持续认证引擎

### 概况

- **工作量**：L（SPI 扩展 + 事件驱动评估器 + 告警）
- **价值**：中（差异化安全能力，风控需要）
- **类型**：安全引擎

### 为什么需要

当前身份安全模型是**一次性**的——登录时评估一次风险，之后 token/session 到期前不再重新评估。这导致：

| 场景 | 问题 |
|------|------|
| 登录后设备被入侵 | token/session 继续有效直到过期 |
| 用户行为突变 | 正常用户突然从异常地理位置大量请求——无法触发重新认证 |
| 凭据泄露（事后发现） | 无法主动使已签发的 token 失效（除手动撤销） |
| 内部威胁 | 已授权用户开始下载大量数据——无权自动干预 |

**现状**：
- `anomaly/` 包存在但异步、不在请求路径上——检测到事件后无法实时影响 auth 决策
- `RiskScorer` SPI 存在但在登录时只起门禁或触发 MFA——一次评估，非连续
- CAEP 信号发送（`caep/`）存在但只向外推送给 RP，不向内评估会话风险
- `cluster.Bus` 已就绪——可以作为实时风险评估的通信骨干

### 范围

1. **Session Risk Score 字段**（`shared/core/types_session.go`）：Session 增加 `RiskScore int` + `RiskEvaluatedAt time.Time` + `RiskFlags []string` 字段，使用 bounded cardinality

2. **实时风险评估 SPI**（`shared/spi/risk.go` 扩展）：

   ```go
   // SessionRiskEvaluator assesses the risk level of an active session
   // based on recent activity and signals. Called inline on the request
   // path for risk-sensitive operations.
   type SessionRiskEvaluator interface {
       // Evaluate returns a risk score (0-100) and optional flags
       // for the given session. An error means "evaluation unavailable"
       // (fail-open, keep current score).
       Evaluate(ctx context.Context, session *Session, activity ActivityEvent) (score int, flags []string, err error)
   }
   
   type ActivityEvent struct {
       Type       ActivityType  // TokenIssued, TokenUsed, ScopeChanged, GeoChanged, DeviceChanged
       IP         string
       Geo        *GeoHint
       Resource   string
       ClientID   string
       Timestamp  time.Time
   }
   ```

3. **内置行为评估器**（`domains/anomaly/session_evaluator.go`——~200 行）：

   | 规则 | 条件 | 触发 | 评价 |
   |------|------|------|------|
   | 地理位置跳跃 | 新的 `geo.country_code` 与上一个不同且在 N 分钟内 | `sso_session_risk_changed{reason=geo_jump}` | score +30 |
   | 请求速率异常 | session 的请求速率 > per-user P99（按 client） | `sso_session_risk_changed{reason=request_rate}` | score +20 |
   | 资源访问模式变化 | session 开始访问之前未访问过的敏感资源 | `sso_session_risk_changed{reason=new_resource}` | score +15 |
   | 已知受损设备 | device_id 出现在已知受损设备列表中（CAEP 信号） | `sso_session_risk_changed{reason=known_compromised}` | score +50 |
   | 凭据健康度回归 | 登录后密码被标记为已泄露（HIBP） | `sso_session_risk_changed{reason=credential_compromised}` | score +80 |

4. **风险阈值策略**（`interfaces/sso/options_security.go` 扩展——~50 行）：

   ```go
   type SessionRiskPolicy struct {
       // Thresholds define risk score ranges that trigger actions.
       RequireStepUp int  // score >= this → force MFA step-up before sensitive ops
       ForceReAuth   int  // score >= this → invalidate session, require full re-auth
       AuditOnly     int  // score >= this → audit escalate but don't block
   }
   ```

5. **CAEP 信号反馈闭环**（~60 行）：当 session 风险分数到达 `ForceReAuth` 阈值时，自动广播 `TokenRevoked` / `SessionRevoked` CAEP 信号

### 关键设计约束

- **Fail-open**：评估器错误或超时不阻塞请求路径——保留当前风险分数，记录审计事件
- **Bounded cardinality**：`RiskFlags` 使用预定义的枚举集（`geo_jump`、`request_rate`、`new_resource`、`known_compromised`、`credential_compromised`），不是自由文本
- **性能**：评估器在请求路径上同步调用——内建的基于规则的评估器应 < 1ms p99。外部 SPI 调用可以异步更新分数，不在关键路径上等待
- **无学习阶段**：没有"先学习 7 天再起作用"的模式——规则立即生效。用于机器学习的时间序列分析是 future work（offline ML pipeline → 导出规则 → 应用到在线评估器）
- **审计**：每个风险分数变化都记录 `session_risk_changed` 事件，含 `old_score`、`new_score`、`reason`、`threshold_action`。不得在 token 或 wire 响应中暴露分数

### ROI

- **假设**：一个被盗的 refresh token 在异常地理位置被使用时 → session 风险分数从 0 跳到 60 → 应用配置的 `RequireStepUp` 阈值是 40 → 在下一次 `/token` 请求时强制 MFA step-up → 攻击者无法在没有第二因素的情况下刷新 token
- **竞品差距**：Auth0 有"Anomaly Detection"但这是独立产品（需要额外的"Attack Protection"订阅）。Okta 有实时风险评估但需要 "Okta Identity Engine"。此方向将基础行为检测内建到授权服务器中
- **与项目的协同作用**：复用现有的 `anomaly/` 异步检测器 + `cluster.Bus` + `RiskScorer` SPI + CAEP 收发器。大部分基础设施已到位，缺的是**实时会话风险反馈回路**
- **工作量**：L——新 SPI 定义 + 内置规则评估器 + CAEP 接线 + 阈值配置

---

## 优先级摘要

| # | 方向 | 工作量 | 价值 | 适合时机 | 核心收益 |
|---|------|--------|------|----------|----------|
| 1 | JWT Bearer Grant (RFC 7523) | **M** | **高** | 立刻 | 填补基础协议空白，解锁云原生工作负载身份 |
| 2 | 威胁模型与对抗性测试 | **M** | **高** | 与方向 1 并行 | SOC 2 / Pentest 预备，安全回归 CI 门禁 |
| 3 | 连续认证与风险引擎 | **L** | **中-高** | 方向 1 之后 | 授权从"一次性"升级为"持续"，差异化的安全能力 |
| 4 | 云工作负载身份连接器 | **L** | **中-高** | 方向 1 之后 | 零配置云原生部署入场券 |
| 5 | Transaction Tokens (RFC 9321) | **L** | **中** | FAPI 深度采用时 | 前瞻差异化，完整 RAR→TxT→CAEP 链路 |

### 阶段建议

**Phase 1（当前 Sprint）**：方向①（JWT Bearer Grant）—— 这是最清晰的缺失基础能力。200 行核心逻辑 + 150 行测试，复用 `security.VerifyCompactJWS` 和现有 grant handler 模式。落地后即可宣布支持 `urn:ietf:params:oauth:grant-type:jwt-bearer`。

**Phase 1 并行**：方向③（威胁模型与对抗性测试）—— 文档 + 测试套件编写。这个过程可能会发现现有代码中未预期的安全缺口，反馈到修复。测试套件上线后自动防止新方向（①、④、⑤）引入相同的攻击向量。

**Phase 2（本月）**：方向④（云工作负载身份连接器）—— 依赖方向①的 JWT Bearer Grant 作为后盾。与方向①组成"JWT Bearer Grant + 云连接器"的故事线。

**Phase 3（下月）**：方向③（连续风险引擎）—— 与 ROADMAP v5.0 中第②方向（B2B 企业化）的用量计量报表有数据复用协同。复用 `anomaly/` + `cluster.Bus` 底座。

**Phase 4（待定）**：方向⑤（TxT）—— 当 FAPI 2.0 深度采用或开放银行场景出现时触发。与已有 RAR + token-exchange + CAEP 形成完整链路。

---

## 与既有路线图的关系

| 本报告方向 | 与 ROADMAP v5.0 的关系 | 与 `analysis-final-project-expansion-directions.md` 的关系 |
|-----------|----------------------|------------------------------------------------|
| ① JWT Bearer Grant | 正交——新 grant_type，ROADMAP 未覆盖 | 正交——未被 06-30 分析覆盖 |
| ② Transaction Tokens | 正交——新 RFC 9321，ROADMAP 未覆盖 | 正交——未被 06-30 分析覆盖 |
| ③ 威胁模型与对抗性测试 | 互补——ROADMAP ⑤（安全门禁）聚焦 SAST/SCA/CI，本方向聚焦系统性威胁建模 | 互补——06-30 分析方向④（变更管理）聚焦治理，本方向聚焦攻击面验证 |
| ④ 云工作负载身份连接器 | 正交——ROADMAP ②（B2B 上游 IdP）聚焦人/组织，本方向聚焦机器/工作负载 | 正交——06-30 分析未覆盖 |
| ⑤ 连续风险引擎 | 互补——ROADMAP ③（OIDC 一致性）聚焦协议正确性，本方向聚焦运行时安全 | 互补——06-30 分析方向③（跨副本 Coherence）聚焦共享状态正确性，本方向聚焦行为检测 |

## 附录：核验方法

每个方向的确立经历了以下过程：

1. **关键词 grep**：每个方向的使用 5-15 个关键词在全树 `.go` 文件中搜索
2. **排除测试文件**：排除 `*_test.go` 避免单测 stub 干扰
3. **文档交叉验证**：读取 ROADMAP v5.0 + 22 轮分析报告 + feature-matrix.md + security-policy.md + config-reference.md + PHASE_D_DESIGN.md，验证每个结论未被覆盖
4. **参数核验**：验证 `SupportedGrants` 列表、`consts_oauth.go` 常量、`With*` 选项函数

### 方向① 核验过程

```bash
# grep 确认 urn:ietf:params:oauth:grant-type:jwt-bearer 不存在于全树（测试文件除外）
$ grep -rn "grant-type:jwt-bearer" --include="*.go" . | grep -v "_test.go"
# 输出为空 → 确认未实现

# grep 确认 SupportedGrants 列表中不包含 jtw-bearer
$ grep -A5 "SupportedGrants =" shared/core/consts_oauth.go
# 输出仅 5 种 → 确认缺口

# 确认 consts_oauth.go 也无 GrantJWTBearer 常量
$ grep "GrantJWTBearer" shared/core/consts_oauth.go
# 输出为空 → 确认
```

### 方向② 核验过程

```bash
# grep 确认 RFC 9321 或 TransactionToken 无命中
$ grep -rn "TransactionToken\|rfc9321\|RFC 9321\|transaction.token\|grant-type:transaction-token" --include="*.go" . | grep -v ".git/"
# 输出为空 → 确认未实现
```

### 方向③ 核验过程

```bash
# 确认 docs/ 下无威胁模型或攻击树文档
$ find docs -name "*threat*" -o -name "*attack*" -o -name "*adversar*" -o -name "*STRIDE*" 2>/dev/null
# 输出为空 → 确认缺口

# 确认 test/ 下无对抗性测试套件
$ find test -name "*adversar*" -o -name "*attack*" -o -name "*penetra*"
# 输出为空 → 确认缺口
```

### 方向④ 核验过程

```bash
# grep 确认无 AWS/GCP/Azure 工作负载身份代码
$ grep -rn "WorkloadIdentity\|AssumeRole\|AssumeRoleWithWebIdentity\|GCPWorkload\|GKEWorkload\|AzureManagedIdentity\|IMDS\|workload.*identity" --include="*.go" . | grep -v "_test.go"
# 输出仅 SPIFFE 相关 → 确认无云适配器
```

### 方向⑤ 核验过程

```bash
# 确认无 session 风险分数或实时风险评估
$ grep -rn "RiskScore\|RiskFlags\|SessionRisk\|risk_score\|session.*risk\|continuous.*auth\|re-eval\|reasses" --include="*.go" . | grep -v "_test.go"
# 输出仅登录时一次的 RiskScorer 引用 → 确认无连续评估
```
