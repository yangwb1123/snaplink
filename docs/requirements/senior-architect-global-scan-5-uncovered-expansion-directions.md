# 资深架构师全局扫描：五项未覆盖的高价值扩展方向

> **分析师角色：** 资深架构师 & 产品经理
> **日期：** 2026-07-11
> **方法：** 全代码库全局扫描（2241 `.go` 文件，~200 包，12 嵌套子模块，4 嵌入 SPA）。
>   系统性阅读 ROADMAP v5.0、deferred-backlog、feature-matrix、SECURITY.md、全部 50+ 份
>   历史分析文档（`docs/requirements/*.md`）及最新 6 份今日分析（`architect-global-analysis`、
>   `deep-read-production-hardening`、`architect-final-five`、`architect-scan`、
>   `expansion-edge-cases`、`architect-expansion-5-directions`）。
>   每项方向通过全代码库 grep + 历史文档关键词反查双重核验，确保**零重叠、真缺口**。

---

## 前置声明：项目成熟度评估

经过 50+ 轮架构分析 + 大量代码落地，本项目的能力覆盖面已达行业顶级。所有主要身份协议、
安全防线、产品前端、运维基础设施、质量基建均已落地。

| 维度 | 状态 | 关键数据 |
|---|---|---|
| **协议** | ✅ 全面 | OAuth 2.0×7 grants + OIDC + SAML 2.0 + SCIM 2.0 + CAEP/SSF + FAPI 2.0 + Federation 1.0 + LDAP/Kerberos/RADIUS/WebAuthn/SPIFFE/Workload Identity |
| **存储** | ✅ 全面 | Memory + SQLite + PostgreSQL + Redis + etcd + KMS×5 + SAML×4 + Kafka/MQTT/Vault Transit |
| **安全** | ✅ 全面 | DPoP/mTLS/JKT/SPIFFE、Break-Glass、FIPS 140-3、Anti-enumeration×9、Oracle-leak×10、Account Lockout、Conditional Access、Anomaly Detection×4 |
| **产品** | ✅ 全面 | Hosted Login SPA、Admin Console SPA（全 CRUD）、Developer Portal SPA、User Portal（`/me`）、Consent Store×3、B2B Connections、SDK Generation、MCP Server |
| **运维** | ✅ 全面 | DR Framework、Config Hot-reload、80+ Metrics、Audit Chain（OCSF/CEF/Syslog/Kafka）、OTel tracing、k6 + Chaos、K8s Operator |
| **质量** | ✅ 全面 | 架构层 import 边界强制、File≤500/Func≤50/Cyclo≤15 强制、500+ maintainability tests、govulncheck/CodeQL/Trivy/Dependabot、Fuzz×10+、Race CI |

**核心发现：** 经过 50+ 轮分析，项目已不存在"缺失某标准协议"或"缺少某存储后端"这类
传统缺口。剩余的高价值方向聚焦于**跨实例的信任桥接**、**面向用户的透明安全体验**、
**会话级风险自适应**、**租户品牌域自动化**、以及**去中心化的组织间协作发现**——
这些方向横跨"产品化最后一公里"与"新一代身份拓扑"的交集，且均与现有 50+ 份分析
文档零重叠。

---

## 方向一：跨实例身份桥接（Cross-Instance Identity Bridge）

### 类型

身份拓扑 / 企业互联 / 实例间信任

### 为什么需要

本项目支持三种身份联邦/连接模式：

| 模式 | 描述 | 代码状态 |
|---|---|---|
| OpenID Federation 1.0 | 服务器间客户端注册信任（去中心化注册） | ✅ 实现 |
| B2B Enterprise Connections | 每租户上游 IdP 配置（SAML/OIDC） | ✅ 实现 |
| 跨租户 Token Exchange | 同一实例内跨租户 B2B 协作 | ✅ 实现 |

但**缺失一种核心企业场景**：**两个独立运行的 SnapLink SSO 实例直接信任彼此的
用户**，例如：

- **M&A 合并**：公司 A 用一套 SnapLink SSO，收购的公司 B 也用 SnapLink SSO。
  需要两套 IdP 互信，让 A 的员工可以直接用 A 的账号登录 B 的应用，反之亦然。
- **集团企业**：各子公司独立运营自己的 SnapLink SSO 实例（各自的数据主权、合
  规边界），但需要集团层面的跨子公司 SSO。
- **合作伙伴**：Org A 需要将部分用户身份共享给 Org B，而不通过上游 IdP 串联
  （Org B 本身也是 SnapLink SSO 实例）。

**这与现有能力的差异：**

| 对比维度 | 现有 B2B Connections | 跨实例身份桥接 |
|---|---|---|
| 对端是什么 | 上游 IdP（Okta/Azure AD/ADFS） | 另一个 SnapLink SSO 实例 |
| 配置方式 | 每租户静态配置连接参数 | 实例间动态信任发现 + 协议协商 |
| 用户属性映射 | 上游 IdP 的 token 声明 → 本地用户 | 对端实例的 JWT/JWT-SVID → 本地用户 |
| 会话主权 | 对端会话不被识别 | 携带对端实例会话状态 |
| 注销传播 | 不支持跨实例 | 需跨实例 Backchannel Logout |
| 审计 | 仅本实例可见 | 需跨实例审计追踪 |

### 当前代码缺口

| 检查项 | 结果 |
|---|---|
| 两个 SSO 实例互信用户登录 | ❌ 无任何实现 |
| 跨实例会话传播/注销 | ❌ 无任何实现 |
| 跨实例信任发现协议 | ❌ 无任何实现 |
| 实例间 metadata 交换 | ❌ 无任何实现 |
| 跨实例属性的声明映射 | ❌ 无任何实现 |
| 已有分析文档覆盖 | ❌ grep `instance.*trust\|cross.*instance\|org.*trust.*bridge\|instance.*bridge\|org.*bridge` 在全部 50+ 份历史分析文档中 **0 命中** |

### Scope

1. **信任关系模型** — `InstanceTrust` 实体：对端实例的 `issuer`、JWKS 端点、元数据
   端点、允许的 `tenant_id` 范围、声明映射规则（`{theirs}` → `{ours}`）、审计追踪
   配置、双向/单向模式。可持久化于 SQLite/Redis/etcd。

2. **用户映射策略** — 三种模式：
   - **直接映射**（by subject）：对端 `sub=alice@acme.com` → 本端 `sub=alice@acme.com`
   - **声明转换**（by attribute）：对端 `sub=alice` + `iss=https://acme.sso.com` →
     本端 `sub=acme:alice`（避免 sub 冲突）
   - **托管映射**（需要本地账户）：对端用户首次登录时 auto-provision 本地影子账户

3. **认证流** — 新建 `instance_identity` 认证协议（非 SAML 非 OIDC 联邦，专用于
   SSO-to-SSO 互信）：对端签名的 assertion JWT（包含 `iss`、`sub`、`aud`、
   `iat`、`exp`、`tenant_id`、`claims`），本端按 InstanceTrust 验签 + 映射。

4. **跨实例注销** — 扩展 Backchannel Logout：当用户在 Org A 登出时，通过配置的
   对端实例 BCL 端点通知 Org B 登出该用户的跨实例会话。

5. **发现协议** — 可选扩展：`/.well-known/instance-trust` 端点暴露实例的信任能力，
   让对端实例自动发现支持的声明映射、签名算法、协议版本。

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 对端实例密钥轮换 | 定期（或按 TTL）重新获取对端 JWKS；Key rotation 事件广播到所有受信任实例 |
| 信任关系吊销 | 信任关系被删除后，已有跨实例令牌如何处理？按 `iat`+`max_ttl` 窗口允许继续使用或立即失效 |
| 循环信任（A→B→A） | 令牌链路上做 `iss` 去重检测，阻止循环 assertion（类似于 token-exchange 的 act chain 去重） |
| 声明冲突 | 映射规则必须显式定义（FAIL-CLOSED 默认拒绝所有未映射声明） |
| 对端实例下线 | 无法获取 JWKS 时 fail-CLOSED（trust 不可验证 = 拒绝）；fail-OPEN 会让对端假冒令牌通过 |
| 跨实例审计 | 本端审计记录包含 `peer_instance` 字段；对端需要提供审计查询接口用于事件联动调查 |

### 价值·工作量评估

| 维度 | 评估 |
|---|---|
| 市场价值 | **高** — M&A 和集团企业是最常见的 SSO 采购场景之一；当前只能通过复杂的联邦串联模拟 |
| 技术复用 | **高** — 复用现有 JWT 验签（`security.VerifyCompactJWS`）、TLS 传输、Backchannel Logout 框架 |
| 工作量 | **L-XL** — 信任模型 + 认证流 + 注销传播为 M，+ 发现协议为 L，+ 跨实例审计为 XL |
| 独立性 | 高 — 与现有功能解耦，可独立开发 |
| 建议优先级 | **P1** |

---

## 方向二：用户安全活动时间线与仪表盘（User Security Dashboard）

### 类型

产品体验 / 用户安全透明性

### 为什么需要

本项目拥有**全量审计能力**（`platform/audit`，OCSF 格式、hash-chain、多 Sink 扇出）、
**用户会话管理**（`/me/sessions`）、**用户 MFA 因子管理**（`/me/mfa`）、**身份链接**
（`/me/identities`）、**最近登录记录**（`recent_logins` 表）。

但**缺乏一个统一的、用户可读的安全时间线视图**——这是 Auth0、Okta、Google Account、
Microsoft Account、Apple ID 等所有主流身份平台的标准功能。

**用户安全时间线告诉用户**：
- 什么时候、从哪个 IP/设备/位置登录
- 密码是什么时候修改的
- MFA 因子是什么时候添加/移除的
- Consent 记录是什么时候授权/撤销的
- Email 是什么时候变更/验证的
- 管理员执行了什么操作（如果用管理账号登录）
- 异常检测触发了什么事件

### 当前能力与缺口

| 能力 | 后端存在？ | 用户面 API？ | 用户面 UI？ |
|---|---|---|---|
| Audit Event（完整） | ✅ `platform/audit` | ❌ 仅 admin API | ❌ |
| Recent Logins | ✅ `sqlite.recent_logins` | ❌ 仅 anomaly 消费 | ❌ |
| Session Listing | ✅ `SessionManager.ListByUser` | ✅ `/me/sessions` | ✅ Admin Console |
| MFA Factor Changes | ✅ Audit Event | ❌ | ❌ |
| Password/Email Changes | ✅ Audit Event | ❌ | ❌ |
| Consent Grants/Revocations | ✅ ConsentStore + Audit | ❌ | ❌ |
| Admin Actions on Account | ✅ Audit Event | ❌ | ❌ |

现有数据源已覆盖全部所需信息，但**没有用户可消费的聚合层**。

### Scope

1. **`GET /me/security/timeline` API** — 逆序分页返回该用户相关的安全事件。数据
   源 = `audit.Event`（按 `SubjectID` 过滤） + `recent_logins`（按 `subject_id`）。
   无新建数据模型——这是已存在数据的投影 + 聚合。

   ```json
   GET /me/security/timeline?limit=20&from=2026-06-01T00:00:00Z
   → {
       "events": [
         {"type": "login", "at": "2026-07-10T14:23:00Z",
          "summary": "Signed in with passkey", "ip": "203.0.113.42",
          "device": "Chrome 128 / macOS", "location": "San Francisco, US"},
         {"type": "password_changed", "at": "2026-07-05T09:15:00Z",
          "summary": "Password changed"},
         {"type": "mfa_added", "at": "2026-07-01T18:00:00Z",
          "summary": "TOTP authenticator app added"},
         {"type": "session_ended", "at": "2026-06-28T22:00:00Z",
          "summary": "Session ended on MacBook Pro", "ip": "10.0.0.5"}
       ],
       "next": "2026-06-01T00:00:00Z
     }
   ```

2. **用户面 UI**（`/me/security`）— 时间线视图，嵌入 `User Portal` 框架内。
   无 build step 的轻量内嵌页面（与现有 SPAs 同模式）。

3. **事件摘要生成** — 每个 `audit.EventType` → 本地化、可读的 `summary` + `category`
   （login/credential/session/consent/admin 等）。SPI 可扩展。

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 审计事件保留期限 | 只展示保留窗口内的事件，`from` 参数早于保留期限返回空而非错误 |
| 高频率登录用户 | 限制每页 20 条，自动聚合同类相邻事件（同一 IP 的连续密码错误合为一次"多次登录失败"） |
| 事件中的 PII | IP 仅显示前 3 段（`203.0.113.*`），完整 IP 保留在 audit store 中供合规导出 |
| 事件间排序 | 主时序 = `EventAt`（精确到毫秒），同毫秒时按 `EventID` 排序 |
| 跨设备同步 | 用户在设备 A 登出，在设备 B 看时间线——事件应即时可见（无需跨实例同步，单 store 查询即可） |

### 价值·工作量评估

| 维度 | 评估 |
|---|---|
| 市场价值 | **高** — 这是现代 IdP 的基本功能；无此功能的 IdP 在消费者和员工体验上存在明显差距 |
| 技术复用 | **极高** — 0 新数据 schema，纯现有数据的读取 + 聚合 |
| 工作量 | **M** — API（S）+ 用户 UI（M）+ 事件摘要生成（S） |
| 独立性 | 高 — 不依赖任何其他方向 |
| 建议优先级 | **P1**（S/M 付出，高用户可见度） |

---

## 方向三：会话风险自适应生命周期（Session Risk-Adaptive Lifecycle）

### 类型

安全 / 运行时自适应策略

### 为什么需要

本项目已有：

- **登录级风险评估**（`RiskScorer.Score`）：在 `/auth/login` 时评估风险，做出
  deny/require MFA/allow 决策。
- **会话信任衰减**（`WithSessionTrustDecay`）：会话信任分数随时间衰减，低于阈值
  时要求 step-up。
- **条件访问策略**（`conditionalaccess`）：基于设备/位置/IP 的实时策略评估。

但**缺少一个跨会话全生命周期的自适应风险引擎**——它的决策不是一次性的（登录时的
风险评估），而是持续性的、随风险信号动态调整的：

| 场景 | 当前行为 | 想要的行为 |
|---|---|---|
| 用户正常使用中发现从新 IP 登录 | 不做任何事 | 自动缩短当前会话到期时间 + 标记下次刷新需 step-up |
| 用户刷新 token 时处于高风险网络 | 正常发放新 token | 降低 refresh token 的 max_ttl、要求重新认证 |
| 管理员报告某用户密码泄露 | 仅 admin 可吊销 | 自动触发该用户所有会话的风险升级 + 限流 |
| 用户换设备后 | 新 session 开始 | 旧 session 自动降级（敏感操作需 step-up） |
| Anomaly Detector 报告异常行为 | 仅记录 + audit | 自动向该用户的所有会话注入临时信任衰减加速 |

**一句话：当前的风险评估是 request-bound（请求绑定），未来的风险评估应当是
session-bound（会话绑定）且持续演变的。**

### 当前代码缺口

| 检查项 | 结果 |
|---|---|
| 会话级别动态 TTL 调整 | ❌ SessionManager 无 `ExtendTTL`/`ReduceTTL` 方法 |
| 实时风险注入到已有会话 | ❌ 风险信号只在登录时刻评估 |
| 跨会话风险联动 | ❌ 一个会话检测到风险不传播到该用户的其他会话 |
| 风险驱动的刷新策略 | ❌ Refresh 时从不重新评估风险 |
| 已有分析文档覆盖 | ❌ grep `session.*risk.*adapt\|dynamic.*session.*ttl\|session.*risk.*inject\|risk.*driven.*refresh\|adaptive.*session.*lifetime` 在全部 50+ 份历史分析文档中 **0 命中** |

### Scope

1. **`SessionManager` 扩展** — 新增方法：
   - `ReduceTTL(ctx, sessionID, reducedBy time.Duration)` — 将会话剩余的 TTL 缩减指定值，永远不倒拨（单调减少）
   - `SetRiskLevel(ctx, sessionID, level RiskLevel)` — 注入风险等级（low/normal/elevated/high/critical），影响最终 TTL
   - `MarkRequiresStepUp(ctx, sessionID)` — 标记会话在下一次敏感操作前需要 step-up 认证
   - `ListByRiskLevel(ctx, level, since)` — admin 查询高风险会话（已有 ListByUser）

2. **风险注入管道** — 一个 `SessionRiskListener` SPI：
   - 接收来自 `RiskScorer`、`anomaly.Detector`、`conditionalaccess.Engine`、管理员
     手动操作的风险信号
   - 将信号路由到目标用户的活跃会话（`SessionManager.ListByUser` + `SetRiskLevel`/`ReduceTTL`）
   - 异步、fail-OPEN（审计记录注入失败，不影响业务）

3. **Refresh 时重评估** — 在 `internal/handler/tokengrant/token_refresh.go` 中
   refresh token 时重新运行 `RiskScorer.Score`（目前 refresh 路径无风险评估）。
   - 风险升高 → 缩短新 refresh token 的 absolute max lifetime
   - 风险极高 → 拒绝 refresh（`invalid_grant`），强制用户重新登录

4. **Admin UI 风险热图** — `/api/v1/admin/sessions/risk-heatmap`：
   - 按风险等级、租户、用户分布的实时热图
   - 高风险会话的批量操作（批量降级/批量要求 step-up/批量吊销）

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 风险信号风暴（多个检测器同时报告） | 聚合器做 dedup + 冷却窗口（同一 session 的同类风险 30 秒内只应用一次最严重等级） |
| ReduceTTL 永不倒拨 | `ReduceTTL` 是单调的——无法"延长已缩短的会话"，防止攻击者通过恢复信号绕过缩短 |
| 离线检测延迟 | 离线检测到的历史风险（错过时段），注入时按实际时间计算已过期的会话应忽略 |
| 跨会话传播的广播噪声 | 一个用户有 50 个 session？`ListByUser` 全量处理；批量操作使用 worker pool + 有界并发 |
| 与现有 TTL 冲突 | `ReduceTTL` 始终取 min(现有 TTL, 新 TTL)；`sessionMgr.Create` 时带默认 TTL |

### 价值·工作量评估

| 维度 | 评估 |
|---|---|
| 市场价值 | **高** — 面向金融/安全敏感客户的核心卖点；Auth0、Okta 以类似风险引擎作为高级产品线 |
| 技术复用 | **中** — 需新增 SessionManager SPI 方法（破坏现有 memory/sqlite/redis 实现） |
| 工作量 | **XL** — SPI 变更（M）+ 风险注入管道（L）+ Refresh 重评估（M）+ 热图（S）= XL |
| 独立性 | 中 — 依赖 SessionManager + RiskScorer + anomaly 现有接口 |
| 建议优先级 | **P2**（高价值但工程量较大，宜先做方向一/二） |

---

## 方向四：租户自定义域名 + 自动 TLS（Per-Tenant Custom Domain with Auto TLS）

### 类型

产品体验 / 企业品牌化 / 运维自动化

### 为什么需要

本项目支持**租户域路由**（`domains/tenant`，`WithTenantStore`）：通过 `hostname`
将请求路由到对应租户的登录页和 API 端点。这是多租户 SaaS 的基础。

但缺少一个企业客户直接问的典型需求：**"我们想用自己的域名，比如 `login.acme.com`，
不要 `sso.acme.snaplink.io`。"**

| 能力 | 当前状态 | 缺失 |
|---|---|---|
| hostname → tenant 路由 | ✅ `tenant/middleware.go` | — |
| 域名验证（DNS TXT/ACME） | ✅ `connections/domain_verification.go` | — |
| 每租户品牌配置 | ✅ `tenant.Tenant.Branding`（键值映射） | — |
| **自动 TLS 证书（Let's Encrypt/ACME）** | ❌ 不存在 | 用户必须手动管理证书 |
| **多租户 SNI 分发** | ❌ 不存在 | 需额外反向代理组件 |
| **租户域自我管理** | ❌ 不存在 | 仅 admin API，无自助 UI |

### 当前代码缺口

| 检查项 | 结果 |
|---|---|
| ACME 自动 TLS 证书管理 | ❌ 无任何实现 |
| 租户自服务域名添加/验证/切换 UI | ❌ 不存在（admin gRPC + REST API 存在但无用户面） |
| 多租户 SNI 路由 | ❌ 不存在 |
| 域到租户的 DNS 验证状态持久化 | ✅ `DomainVerificationStore` 存在 |
| 已有分析文档覆盖 | ❌ grep `auto.*tls\|ACME\|Let.*Encrypt\|cert.*management\|custom.*domain.*tls\|tenant.*certificate` 在全部 50+ 份历史分析文档中 **0 命中** |

> 注意：`admin/connections.go:195` 提到 "ACME dns-01 style" 但仅作为 DNS 验证的
> 类比说明，非 ACME 证书管理实现。

### Scope

1. **租户域自助管理 API** — 已有 `DomainVerificationStore` + `admin/` handler，
   缺用户面 API。新建 `/me/organizations/:tid/domains` 端点（已有 `mountOrgAdminSelfService`
   框架可直接承载）。

2. **ACME 自动 TLS** — 一个可选的证书管理器组件：
   - 在 `cmd/sso-server` 层组装（不是 core SDK 必须）
   - 监听租户域添加事件 → 从 DNS 验证到证书签发的全自动流程
   - 证书存储：SQLite（BLOB）+ 定期检查续期（`crypto/tls` 的 `GetCertificate` callback）
   - 实现一个 `tls.GetCertificate` callback，在 TLS 握手时根据 SNI 提取对应证书

3. **租户品牌化托管登录** — 使用 `Branding` 字段（颜色、logo URL、字体）渲染
   自定义登录页。目前 `Branding` 存储但**从未被任何渲染器消费**。

### 技术方案示意

```
Client → HTTPS → TLS Termination (SNI解析)
                       │
                 GetCertificate callback
                 根据 client hello 的 SNI
                 查找 tenant 的证书
                       │
                 TenantMiddleware (路由)
                 根据 hostname → tenantID
                       ↓
                 Branded Login Page
                 使用 Tenant.Branding 渲染
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 速率限制（Let's Encrypt） | 每个域每周最多 5 次证书签发——因此需要"先验证域所有权，确认后再请求证书"两阶段 |
| 证书续期失败 | 故障告警 + 保留旧证书直到过期（允许操作者手动介入窗口） |
| 根域 vs 子域名 | `login.acme.com`（子域）比 `acme.com`（根域）更容易自动处理——方案首选子域模式 |
| 域所有权过期 | 域不再属于租户（DNS 记录被移除）→ 自动撤销证书 + 停止路由 |
| 多租户共享 IP | SNI 完全基于 TLS 握手，多个租户可以共享同一个 IP |
| Wildcard 证书 | 对于 `*.sso.acme.io` 类型的子域名，一期只需一纸通配符证书覆盖所有租户；二期才做每租户独立证书 |

### 价值·工作量评估

| 维度 | 评估 |
|---|---|
| 市场价值 | **高** — 企业客户的典型首批要求，"我们能不能用自己域名"在采购技术评估中常占一票否决权重 |
| 技术复用 | **高** — 域验证（已有）+ 租户路由（已有）+ Branding 字段（已有，待消费者） |
| 工作量 | **L** — ACME 管理器（M）+ 用户面域管理（S）+ 品牌渲染（M）+ SNI GetCertificate（S） |
| 独立性 | 高 — 不干扰现有功能 |
| 建议优先级 | **P1**（高企业价值，中等工作量） |

---

## 方向五：去中心化组织间协作发现（Decentralized Org-to-Org Collaboration Discovery）

### 类型

身份拓扑 / 去中心化 B2B 生态

### 为什么需要

本项目已实现：

| 能力 | 状态 |
|---|---|
| 跨租户 Token Exchange（B2B 协作） | ✅ 双向、受信白名单 |
| 企业连接（Enterprise Connections） | ✅ 上游 IdP 配置 |
| 租户间用户映射（Identity Link） | ✅ 自服务身份链接 |
| JIT 组织成员自动预配 | ✅ 登录时自动加入 |

但所有 B2B 协作目前是 **admin 手动配置、集中式的**：

1. 租户 A 的管理员发现需要与租户 B 协作
2. 通过电话/邮件/工单联系租户 B 的管理员
3. 租户 B 的管理员手动在控制台配置信任关系
4. 租户 A 的管理员手动在控制台配置白名单

在大规模 SaaS 生态中（例如一个身份平台上有数千个组织），这种手动模式不可扩展。

**缺少一个"去中心化的协作发现"模型**——组织可以：
- 发布自己的协作声明（"我接受跨租户协作，声明映射规则如下"）
- 发现其他组织（基于行业目录、已知列表、手动输入对端 URL）
- 请求与另一个组织建立信任关系
- 协商跨组织访问的 scope 和声明映射

### 当前代码缺口

| 检查项 | 结果 |
|---|---|
| 组织协作声明发布（`/.well-known/org-collaboration`） | ❌ 不存在 |
| 协作请求/接受/撤销协议 | ❌ 不存在 |
| 协作目录（基于行业/区域/已知组织的发现） | ❌ 不存在 |
| 自动化跨组织配置传播 | ❌ 不存在 |
| 协商式 scope 和声明映射 | ❌ 不存在 |
| 已有分析文档覆盖 | ❌ grep `org.*discovery\|collaboration.*protocol\|org.*catalog\|federated.*directory\|trust.*negotiat\|org.*registry\|b2b.*discovery` 在全部 50+ 份历史分析文档中 **0 命中** |

### Scope

1. **组织元数据端点** — `GET /.well-known/org-metadata`（或从已有 `openid-configuration`
   扩展）：返回该组织（租户）的协作能力声明：
   - `collaboration_enabled: true/false`
   - `collaboration_policy_url`：协作文档链接
   - `supported_claim_mappings`：支持的声明映射规则
   - `supported_scope_mappings`：支持的 scope 转换
   - `trust_negotiation_endpoint`：信任协商 API（可选）

2. **信任协商协议** — 两个组织之间的 `request/accept/reject/revoke` 握手：
   - `POST /api/v1/org/trust-requests` — 向目标组织发起信任请求
   - `POST /api/v1/org/trust-requests/{id}/accept` — 接受信任请求
   - `POST /api/v1/org/trust-requests/{id}/reject` — 拒绝
   - `DELETE /api/v1/org/trusts/{id}` — 撤销已有信任

3. **目录服务（可选）** — 公共组织目录，允许组织按名称、行业、区域搜索。
   轻量实现：可基于现有 `TenantStore.List` 扩展（搜索可见性作为租户设置）。

4. **与现有跨租户 Token Exchange 集成** — 协商成功的信任关系自动写入
   `TenantCollaborationStore`，无需 admin 手动配置。

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 未托管的组织 | 不在同一实例的组织需通过 OIDC Federation 或 OpenID Federation 协议桥接 |
| 信任关系滥用 | 全局限流（每个组织每天最多发起 N 个信任请求）；请求可携带不可否认签名 |
| 信任撤销级联 | 信任被撤销后，所有基于该信任兑换的 token 如何处理？按 `max_ttl` 窗口 + audit 通知 |
| 声明映射不一致 | 协商时必须确认双向同意的映射规则；映射冲突 → 信任请求被拒绝 |
| 跨版本协议兼容 | 元数据端点包含 `protocol_version`，向下兼容 |

### 价值·工作量评估

| 维度 | 评估 |
|---|---|
| 市场价值 | **中-高** — 对生态型产品（多家企业围绕一个平台协作）战略价值高；对单一企业场景价值中 |
| 技术复用 | **中** — 复用 Tenant/Token Exchange 但需新建协商协议 |
| 工作量 | **XL** — 元数据端点（S）+ 协商协议（L）+ 目录服务（L）+ 集成（M） |
| 独立性 | 高 — 可独立开发 |
| 建议优先级 | **P3**（战略性创新，投入产出比低于方向一/二/四） |

---

## 综合优先级与工作量矩阵

| 方向 | 市场价值 | 技术复用 | 工作量 | 优先级 | 建议日程 |
|---|---|---|---|---|---|
| ① 跨实例身份桥接 | 高 | 高 | L-XL | P1 | 方向②之后 |
| ② 用户安全时间线 | 高 | 极高 | M | **P0** | **最快可交付** |
| ③ 会话风险自适应 | 高 | 中 | XL | P2 | 依赖 SessionManager SPI |
| ④ 租户自定义域名 + 自动 TLS | 高 | 高 | L | **P1** | 可与②并行 |
| ⑤ 去中心化协作发现 | 中-高 | 中 | XL | P3 | 战略储备 |

### 一句话推荐

**先做方向②（用户安全时间线，2 周，纯读取聚合，无 schema 变更）→ 方向④
（租户自定义域名，3 周，企业需求最高频）并行 → 方向①（跨实例桥接，6 周）
→ 方向③（会话自适应，10 周）→ 方向⑤（去中心化协作发现，战略储备）。**
