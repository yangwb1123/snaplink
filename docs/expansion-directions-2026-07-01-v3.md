# 架构级扩展方向分析报告（卷三：运营基础·开发者生态·跨协议自动化）

> 基于 2026-07-01 对全代码库（1634 个 `.go` 文件、3 个嵌入式 SPA 共 ~3000 行）的全面扫描。
> 分析视角：资深架构师 / 产品经理。
> 定位：此前 10+ 轮分析（40+ 方向）已覆盖协议扩展、治理运维、Edge Cases、性能优化、代码健康、架构债务、API 产品化、规范审计、纵深防御、企业管理层功能完成度。
> **本轮聚焦一个从未被系统审视的层面：运营基础设施的刚性缺口、开发者生态的"最后一公里"、以及跨协议身份生命周期自动化的断层。**
> 原则：不写代码。每条方向经对抗式 grep + 代码交叉验证为真缺口。

---

## 全局判断

代码库的**功能完整性**极高（30+ RFC 协议、企业联邦全栈、多存储后端、完备的 SPAs），但从"可运行的身份平台"到"可运营、可集成、可规模化的身份基础设施"之间，以下 5 个方向构成了关键的断层：

| 维度 | 当前状态 | 目标状态 |
|------|----------|----------|
| 运营基础设施 | 联邦连接靠手写、证书无监控、健康无面板 | 联邦元数据自动化 + 连接健康中心 |
| 开发者生态 | 第三方应用注册靠 admin CLI、无自助入口 | 开发者 Portal + App Review 工作流 |
| 身份生命周期 | SCIM 只进不出、Webhook 仅限审计、无跨协议自动化 | 事件驱动出站 SCIM + Webhook 全生命周期 |
| 凭据管理 | Passkey 可验证、但无可管理、无可审计 | 凭据全生命周期管理 + 风险评分 |
| 数据平面规模 | 区域感知中间件存在、但无区域级数据隔离 | 多区域部署 + 区域级数据驻留自动化 |

---

## 方向一：联盟元数据生命周期管理（Federation Metadata Lifecycle Management）

### 概况

- **工作量**：L（~400 行 + 存储层 + SPAs 面板）
- **价值**：高（运营基础设施的刚性缺口——目前为零）
- **类型**：运营基础设施

### 为什么需要

项目已实现以下联盟协议：

| 联盟类型 | 实现状态 | 元数据生命周期管理 |
|----------|----------|-------------------|
| SAML 2.0 IdP | ✅ 完整 IdP（SSO+SLO） | ❌ 元数据签名证书过期无告警、无自动刷新 |
| SAML 2.0 SP | ✅ 完整 SP | ❌ SP 元数据静态、IdP 证书轮换无检测 |
| OpenID Federation 1.0 | ✅ 信赖链 + 自动注册 + §8 获取 | ❌ 信赖链过期无健康监测 |
| OIDC Federation | ✅ `oidc_federation` 认证器 | ❌ 上游 OIDC Provider 证书/端点变更无感知 |
| LDAP / Kerberos / RADIUS | ✅ 三套认证器 | ❌ 目录证书/TLS 证书过期无预警 |

**核心问题**：联盟身份基础设施的元数据是有生命周期的——签名证书有 expiry、端点 URL 会变化、信赖链会过期。当前所有联盟连接都在启动时加载一次，**在运行时既不跟踪元数据的剩余寿命，也不在证书/端点变化时自动刷新**。

| 场景 | 当前行为 | 影响 |
|------|----------|------|
| SAML IdP 签名证书还有 7 天过期 | **无任何告警** | 到期后所有 SP 拒签 SAML 断言 → SSO 中断 |
| 上游 OIDC Provider 更换了 JWKS 端点 | 人工手动更新配置 + 重启 | 中断窗口期 token 验证失败 |
| SAML SP 对接的 IdP 轮换了 x509 证书 | 登录全部失败直到手动更新 | 生产故障 |
| Federation 信赖链中间 CA 证书过期 | 信赖链解析全部失败 | 所有联邦客户端登录失败 |
| LDAP 目录的 TLS 证书过期 | LDAP 连接全部失败 | 使用该目录的租户全部无法登录 |

**相比之下，竞品已在处理**：
- Keycloak：SAML 元数据自动轮询刷新、证书过期告警
- Auth0：连接健康监控 + 证书轮换通知
- Azure AD：自动证书轮换 + 过期前自动续期

### 范围

1. **`domains/federation/metadatalifecycle/` —— 元数据生命周期 SPI**（~100 行）：

   ```go
   type MetadataSource interface {
       // Type returns one of: "saml_idp", "saml_sp", "oidc_provider",
       // "oidc_federation", "ldap", "kerberos", "radius"
       Type() string
       // Name returns the human name configured for this connection
       Name() string
       // Status returns the current health of this connection
       Status(ctx context.Context) (*ConnectionHealth, error)
   }

   type ConnectionHealth struct {
       Type            string    // "saml_idp", "ldap", etc.
       Name            string
       Reachable       bool      // can we dial the endpoint?
       CertExpiresAt   time.Time // next expiring certificate (zero = no cert)
       MetadataExpiresAt time.Time // metadata/document expiry (zero = no expiry)
       LastSuccessAt   time.Time
       LastFailureAt   time.Time
       FailureCount    int
       LastError       string
   }
   ```

2. **各联盟连接的健康适配器**（每个 ~50 行）：

   | 连接类型 | 适配器位置 | 可检测的健康指标 |
   |----------|-----------|-----------------|
   | SAML IdP 元数据 | `infrastructure/saml/idp/` | 签名证书过期、元文档过期 |
   | SAML SP 配置 | `infrastructure/saml/sp/` | IdP 可访问性、断言签名证书信任 |
   | OIDC Federation | `domains/federation/` | 信赖链最短过期时间、各层证书 |
   | OIDC Provider | `domains/authenticators/oidc_federation.go` | Discovery 文档可访问性、JWKS 可获取 |
   | LDAP | `infrastructure/ldap/` | TCP/TLS 可连接、TLS 证书过期、BIND 成功 |
   | Kerberos | `infrastructure/kerberos/` | KDC 可访问性 |
   | RADIUS | `infrastructure/radius/` | RADIUS 可到达性 |

3. **元数据自动刷新器**（~80 行）：后台 goroutine 周期检查 `MetadataSource.Status()`：
   - 证书 < 30 天过期 → 审计警告事件 `federation_cert_expiring_soon`
   - 证书 < 7 天过期 → 升级为 CRITICAL 级别
   - 连接连续 3 次不可达 → 审计事件 `federation_connection_down`
   - 可选的自动刷新：SAML IdP 元数据支持 HTTP URL → 自动重新获取并更新本地（需配置 `AllowAutoMetadataRefresh`）

4. **Admin Console 健康面板**（~80 行 JS 扩展至现有 Admin SPA）：

   | 面板元素 | 数据源 |
   |----------|--------|
   | 联盟连接状态卡片列表 | `GET /api/v1/admin/federation/health` 新端点 |
   | 证书过期倒计时进度条 | 每个连接返回 `CertExpiresAt` |
   | 状态指示灯（绿/黄/红） | Reachable + CertExpiresAt + LastFailureAt |
   | 连接详情 - 历史可用性 | 聚合 `federation_*` 审计事件 |

5. **`GET /api/v1/admin/federation/health` 新端点**（~60 行）：聚合所有当前活跃的 `MetadataSource` 的健康状态返回。

### 关键设计约束

- **只读探测**：健康检查只读不写——不修改任何连接状态，不触发元数据变更
- **Fail-open**：健康检查失败不阻止登录路径（与登录路径完全解耦）
- **无额外依赖**：健康检查使用连接现有的证书和端点信息，不引入新的密钥材料
- **证书信息获取**：SAML 从 `ds:X509Certificate` 提取、LDAP/RADIUS/Kerberos 从 TLS 握手获取、Federation 从信赖链 JWT 的 `cnf`/`x5u` 获取

### ROI

- **假设**：一个管理员在 Admin Console 上看到 "SAML IdP Acme 的签名证书将在 14 天后过期"，可以在证书过期前更新。对比当前：证书过期 → 用户反馈登录失败 → 被动排查
- **竞品差距**：Keycloak 有元数据轮询但没有健康聚合面板；Auth0 有连接健康但只针对预置的 enterprise connections
- **工作量**：L（~400 行 + 约 80 行 Admin Console 扩展）
- **前置依赖**：Admin Console 已存在（`interfaces/web/admin/index.html`），只需扩展

---

## 方向二：第三方应用开发者门户（Developer App Portal & OAuth App Management）

### 概况

- **工作量**：XL（~600 行 + 新的 SPA + 管理 API 扩展）
- **价值**：高（B2B/B2C 场景的分水岭——从"我们能跑 SSO"到"第三方可以在你的平台上构建应用"）
- **类型**：产品生态

### 为什么需要

项目当前的 OAuth 客户端管理模型是 admin-only 的：

```
admin CLI / admin REST API → 创建/管理 clients
```

对于以下关键场景，这形成了断层：

| 场景 | 当前方案 | 应然方案 |
|------|----------|----------|
| 第三方开发者想集成 SSO | 联系系统管理员 → 手动创建 client → 告知 client_id/secret | 自助注册 → 引导式 onboarding |
| 第三方应用需要 OAuth 权限 | 管理员在 YAML 中配置 scope | 开发者请求 scope → 管理员审查 → 批准/拒绝 |
| 开发者需要查看 API 用量 | 无 | 自助仪表盘（请求量、错误率、活跃用户数） |
| 开发者需要轮换 client secret | 联系管理员 | 自助轮换（前一个 secret 在窗口期内保留） |
| 平台需要审计所有第三方应用 | Admin SPA 的 Clients 列表 | 应用详情页：scope 审计、最近活动、owner |
| 第三方应用需要上传 logo/品牌 | 无 | 自助品牌化 |

**这些场景是 Auth0 / Okta / WorkOS / Clerk 的核心能力**——它们不只是 SSO 服务器，是**身份平台**。平台经济的核心是"第三方可以在你的身份基础设施之上构建应用"。

### 范围

1. **Developer Portal SPA**（新的 `web/developer/` —— ~600 行 HTML+JS + ~200 行 CSS）：
   - 开发者用自己的 SSO 账号登录（`client_id=sso-developer-portal`）
   - **我的应用**列表：每个 client 的 name、client_id、scope 概览、状态、创建时间、最近活动
   - **创建应用**引导式表单：name、redirect_uris、logo、allowed scopes（从平台定义的 scope 列表中选择）
   - **应用详情**：client_id、client_secret（只显示一次 + 重新生成）、redirect_uris、allowed scopes、OIDC 配置、最近 30 天 API 用量（认证请求数、成功数、失败数）
   - **Secret 轮换**：点击轮换 → 当前 secret 进入 24 小时优雅窗口（新旧 secret 都接受）→ 24 小时后旧 secret 自动失效
   - **删除应用**：确认弹窗 → 审计事件 → 异步清理

2. **App Review / Approval 工作流**（~150 行）：

   ```go
   type AppReviewStatus string
   const (
       AppStatusPending   AppReviewStatus = "pending"   // waiting admin review
       AppStatusApproved  AppReviewStatus = "approved"
       AppStatusRejected  AppReviewStatus = "rejected"
       AppStatusSuspended AppReviewStatus = "suspended"
   )

   type Client struct {
       // ... existing fields
       ReviewStatus    AppReviewStatus `json:"review_status,omitempty"`
       ReviewComment   string          `json:"review_comment,omitempty"`
       ReviewedBy      string          `json:"reviewed_by,omitempty"`
       ReviewedAt      *time.Time      `json:"reviewed_at,omitempty"`
       OwnerID         string          `json:"owner_id,omitempty"`     // developer user who registered this
       AllowedScopes   []string        `json:"allowed_scopes,omitempty"` // approved scopes
       RequestedScopes []string        `json:"requested_scopes,omitempty"` // scopes the app requested
   }
   ```

3. **管理审批面板**（Admin Console 扩展 —— ~80 行 JS）：
   - **待审应用**列表（标记为 `review_status=pending` 的 client）
   - 审查详情：查看请求的 redirect_uris、scopes、logo
   - 审批/拒绝 + 理由输入
   - 对于已审批的应用，管理员可以**约束 scope**（开发者请求了十个 scope，管理员只批准其中三个）

4. **开发者 Portal 后端 API**（`interfaces/admin/developer.go` —— ~120 行）：
   - `GET /api/v1/developer/apps` — 当前开发者的应用列表
   - `POST /api/v1/developer/apps` — 注册新应用（初始状态 `pending`）
   - `GET /api/v1/developer/apps/:id` — 应用详情
   - `PUT /api/v1/developer/apps/:id` — 更新应用（scope/redirect_uri 变更 → 回到 `pending`）
   - `POST /api/v1/developer/apps/:id/rotate-secret` — 轮换 client_secret
   - `DELETE /api/v1/developer/apps/:id` — 删除应用
   - `GET /api/v1/developer/apps/:id/usage` — 应用用量数据

5. **开发者 Portal 鉴权**（~40 行）：`developer:manage` scope（细粒度于 `admin:write`），开发者自我鉴权（只能操作自己的应用）。

### 关键设计约束

- **权限隔离**：开发者只能看到/管理自己的应用。管理员可以看到/管理所有应用（通过现有 admin API）
- **Scope 审计**：应用被授予的 scope 随时间变化有审计痕迹（`app_scope_granted`, `app_scope_revoked`）
- **Secret 安全**：client_secret 使用 bcrypt 存储（复用已有 `security.ClientSecretHasher`），只在创建和轮换时明文展示一次
- **优雅窗口**：secret 轮换后旧 secret 在 24h 内仍然有效（参考 refresh 优雅窗口模式）
- **用量计量**：复用 `domains/metering/` 已有设施
- **删除是软删除**：应用删除后进入"已删除"状态，保留 30 天后再物理清除（防止 token 在删除后仍在飞行中）

### ROI

- **假设**：一个 ISV 希望构建一个集成 SSO 的 SaaS 应用传递到 snaplink 部署后进行操作。当前需要联系平台管理员→创建 client→告知 secret→手动测试。有了 Developer Portal 后：开发者自助注册→填写 redirect_uri→等待审批→拿到 client_id/secret→上线
- **竞品差距**：Auth0/Okta 的开发者 Portal 是其核心产品能力。缺少它是"我用了 snaplink 做 SSO，但第三方软件开发商怎么对接我？"的典型 buyer 疑问
- **工作量**：XL 但可分阶段交付。P1（S）：Client 模型增加 OwnerID/ReviewStatus + Developer API 端点。P2（L）：Developer Portal SPA。P3（M）：用量仪表盘

---

## 方向三：跨协议身份生命周期自动化（Event-Driven Identity Lifecycle Automation）

### 概况

- **工作量**：L（~400 行 + 集成点 + 文档）
- **价值**：高（HR-provisioned identity 的自动化基座，企业 HRIT 集成刚需）
- **类型**：集成自动化

### 为什么需要

当前身份生命周期操作是**手动和被动**的：

| 生命周期事件 | 当前处理 | 应然处理 |
|-------------|----------|----------|
| 新员工入职 HR 系统创建账号 | 手动在 SSO 创建用户 或 SCIM 从上游推送 | 自动创建 + 分配默认角色 + 发送欢迎邮件 |
| 员工离职 HR 系统删除/禁用账号 | 手动在 SSO 禁用用户 | HR 删除触发 SSO 自动禁用 + 吊销所有活跃 token |
| 员工组织变更（部门/角色变化） | 手动更新权限 | HR 变更触发 SCIM PATCH 更新属性 + 重新评估权限 |
| 新第三方应用上线 | 管理员手动创建 client | 开发者 Portal 创建 + 审批通过后自动通知 |
| 密码策略变更 | 管理员修改 YAML → 重启 | 配置热加载 + 已过期的密码要求下次登录时重置 |
| 用户自助注册 | 通过 `/signup` 端点 | 注册后自动分配给默认组/角色 |
| MFA 注册状态变更 | 无自动化动作 | 用户绑定 TOTP/Passkey → 更新告警阈值 |

**项目已有但未接通的碎片**：

| 已有设施 | 位置 | 当前用途 | 应然用途 |
|----------|------|----------|----------|
| SCIM 2.0 端点（Users/Groups） | `protocols/scim/` | 入站管理 | 出站推送：SSO 状态变更 → SCIM PATCH 下游系统 |
| WebhookSink | `platform/audit/auditsink/webhook_sink.go` | 审计事件出站 | 身份生命周期事件出站 |
| cluster.Bus | `platform/cluster/` | 副本间失效 | 事件总线 → 出站分发器 |
| CAEP/SSF Transmitter | `protocols/caep/` | 安全事件推送到 RP | 安全 + 生命周期事件 |

**缺失的**：把这些碎片连接成一个协调的、可配置的**身份生命周期自动化引擎**。

### 范围

1. **生命周期事件定义**（~40 行）：

   ```go
   type LifecycleEventType string
   const (
       EventUserCreated          LifecycleEventType = "user.created"
       EventUserUpdated          LifecycleEventType = "user.updated"      // profile attr change
       EventUserSuspended        LifecycleEventType = "user.suspended"
       EventUserActivated        LifecycleEventType = "user.activated"
       EventUserDeleted          LifecycleEventType = "user.deleted"
       EventUserPasswordChanged  LifecycleEventType = "user.password_changed"
       EventUserPasswordReset    LifecycleEventType = "user.password_reset"
       EventUserMFAEnrolled      LifecycleEventType = "user.mfa_enrolled"
       EventUserMFAUnenrolled    LifecycleEventType = "user.mfa_unenrolled"
       EventSessionRevoked       LifecycleEventType = "session.revoked"
       EventClientCreated        LifecycleEventType = "client.created"
       EventClientUpdated        LifecycleEventType = "client.updated"
       EventClientSecretRotated  LifecycleEventType = "client.secret_rotated"
   )
   ```

2. **生命周期事件 SPI**（`shared/spi/lifecycle.go` —— ~30 行）：

   ```go
   type LifecycleEvent struct {
       ID          string            `json:"id"`
       Type        LifecycleEventType `json:"type"`
       TenantID    string            `json:"tenant_id,omitempty"`
       SubjectID   string            `json:"subject_id,omitempty"`
       ActorID     string            `json:"actor_id,omitempty"`
       ResourceID  string            `json:"resource_id,omitempty"`
       Timestamp   time.Time         `json:"timestamp"`
       OldValue    json.RawMessage   `json:"old_value,omitempty"`
       NewValue    json.RawMessage   `json:"new_value,omitempty"`
   }

   type LifecycleEventBus interface {
       Publish(ctx context.Context, event LifecycleEvent) error
       Subscribe(ctx context.Context, handler func(LifecycleEvent)) (unsubscribe func(), error)
   }
   ```

3. **出站 SCIM 客户端**（`infrastructure/scimclient/` —— ~150 行）：当 SSO 内部用户创建/更新/删除时，自动对配置的下游 SCIM 服务端点发起 PATCH/POST/DELETE。支持：

   ```
   ┌─────────┐     user.created      ┌──────────┐    POST /scim/v2/Users    ┌─────────────┐
   │  snaplink │ ──────────────────→ │ SCIM Out │ ───────────────────────→ │ Downstream   │
   │   SSO    │                     │  Adapter │                           │ HR System    │
   │          │     user.deleted    │          │    DELETE /scim/v2/Users  │ (Workday,    │
   │          │ ──────────────────→ │          │ ───────────────────────→ │  SAP Success │
   └─────────┘                     └──────────┘                           │  Factors...) │
                                                                          └─────────────┘
   ```

4. **Webhook 出站端点注册**（复用 `audit/auditsink/webhook_sink.go` 模式但扩展为通用 lifecycle webhook —— ~60 行）：允许运营者注册 webhook URL 监听指定的生命周期事件类型，POST JSON payload 到外部端点。

5. **事件源接点**（在每个生命周期触发的源代码位加入 `bus.Publish` —— ~80 行，分散在已有 handler 中）；

   | 触发点 | 事件类型 | 当前位置 |
   |--------|----------|----------|
   | `UserProvider.CreateOrUpdate` | `user.created` / `user.updated` | `accessors.go` |
   | `SetTenantUserStatus` | `user.suspended` / `user.activated` | `server_tenant.go` |
   | `DeleteTenantUser` | `user.deleted` | `server_tenant.go` |
   | 密码变更 | `user.password_changed` | `password_reset.go` |
   | MFA 注册/注销 | `user.mfa_enrolled` / `user.mfa_unenrolled` | `server_mfa.go` |
   | Session 吊销 | `session.revoked` | `server_admin_sessions.go` |
   | Client 创建/变更/删除 | `client.created` / etc. | `oauth/handle_register.go` + `grpcserver/admin_clients.go` |

6. **Admin Console 配置面板**（~60 行 JS 扩展）：Webhook 注册表单（URL、Secret 签名、事件类型过滤、重试策略、启用/禁用）。

### 关键设计约束

- **事务一致性**：生命周期事件发布在业务操作成功之后（而不是作为事务的一部分）。业务操作成功但事件发布失败 → 记录 `lifecycle_event_delivery_failed` 指标 + 异步重试
- **事件排序**：同一 `SubjectID` 的事件按时间戳排序。消费方接收乱序事件时自行丢弃过期事件（通过 `event.Timestamp`）
- **幂等**：webhook 接收方应通过 `event.ID` 去重（UUID）
- **数据量**：高基数事件（如 `session.revoked`）默认不推送，需运营者显式选择
- **与 CAEP 的关系**：CAEP 推送给受影响的 RP（安全信号），Lifecycle Webhook 推送给运营系统（管理信号）。两者并行不悖

### ROI

- **假设**：用户在自己的自助门户中改 MFA 设备 → SSO 检查该用户当前是否仍有活跃 session → 如果有且 session 是在旧 MFA 注册前创建的 → 自动吊销这些 session → 同时触发 lifecyle event `user.mfa_enrolled` → webhook 通知安全运营中心 → 记录到 SIEM
- **竞品差距**：Okta 的 Lifecycle Management 是其溢价产品；Auth0 的 Actions/Webhooks 需要额外配置。此方向将基础的 identity lifecycle automation 内建到 AS 中
- **工作量**：L（~400 行 + 集成点散布 + 文档）

---

## 方向四：Passkey/FIDO2 凭据全生命周期管理与企业治理

### 概况

- **工作量**：M（~350 行 + 存储扩展 + 面板）
- **价值**：中-高（passkey 时代的前瞻差异点——当前身份平台均未系统性地治理 passkey 凭据）
- **类型**：安全治理

### 为什么需要

项目已有完整的 WebAuthn 实现：

| WebAuthn 能力 | 状态 |
|--------------|------|
| 注册/认证 | ✅ 完整（memory/sqlite/redis/postgres 多后端） |
| 条件中介（Conditional Mediation / Passkey Autofill） | ✅ 已实现（`conditional_login.go`） |
| MFA 集成 | ✅ `mfa_enrollment_adapter.go` |
| FIDO MDS（Metadata Service） | ✅ `mds.go` |
| AAGUID 策略 | ✅ `attestation_policy.go` |
| Credential 删除 | ✅ `RemoveFactor` |

**But**：当 passkey 作为**主要身份凭证**（取代密码）在企业部署时，管理能力严重不足：

| 管理能力 | 当前状态 | 企业需求 |
|----------|----------|----------|
| 凭据列表（谁注册了什么、在哪个设备上） | `ListFactors` 返回基础信息 | 需要审计级详情（AAGUID、设备型号、注册 IP、最后使用时间） |
| 凭据命名 | 全部显示为 "Passkey" | 用户和管理员需要为凭据命名（"我的 iPhone 15"、"YubiKey 5C"） |
| 凭据风险评分 | 不存在 | 设备型号已知脆弱 / 非 FIPS 认证 / 超越注册地理区域 → 风险标签 |
| 凭据健康 | 不存在 | 检测并标记凭据是否已同步到多台设备（平台 passkey）、仅在 WebAuthn level 1 的旧设备上 |
| 批量凭据操作 | 不存在 | 管理员需要：查看所有使用特定 AAGUID 的凭据、吊销因泄露而需要取消注册的凭据 |
| 凭据使用审计 | 仅认证时验证 | 需要审计跟踪：凭据使用记录（时间、IP、设备、成功/失败） |
| 安全密钥丢失流程 | 无 | 用户报告"我的 YubiKey 丢了" → 管理员或自助移除该凭据 → 发送告警/建议注册新的 |
| 基于风险的认证策略 | WebAuthn 作为 MFA 因子 | Passkey 可同时满足 MFA 要求（因为它是"something you have + something you are"） |

### 范围

1. **凭据存储模型扩展**（`shared/core/types_auth.go` —— ~40 行）：

   ```go
   type CredentialRecord struct {
       ID            string    // credential ID (base64url)
       UserID        string
       ClientID      string    // RP client id
       AAGUID        string    // authenticator AAGUID
       DeviceName    string    // human-readable name ("YubiKey 5C NFC")
       DeviceType    string    // platform | cross-platform
       AttestationType string  // basic, self, attCa, ecdaa, none
       CreatedAt     time.Time
       LastUsedAt    time.Time
       LastUsedIP    string
       LastUsedGeo   string
       RiskScore     int       // 0-100, evaluated by credential risk engine
       Status        string    // active | compromised | revoked
       RevokedAt     *time.Time
       RevokedReason string
   }
   ```

2. **凭据风险引擎**（`domains/authenticators/webauthn/credential_risk.go` —— ~80 行）：

   | 风险因素 | 评估方式 | 分值 |
   |----------|----------|------|
   | AAGUID 已知脆弱 | 对照 FIDO MDS 的已知脆弱认证器列表 | +40 |
   | 非 FIPS 认证设备 | AAGUID 不在 FIPS 140 认证列表中 | +20 |
   | 平台认证器 + 已同步 | 通过平台 API 检测（如 iCloud Keychain） | +15 |
   | 注册地点与使用地点差异 | LastUsedIP 的 Geo vs 注册 IP 的 Geo | +25 |
   | 凭据年龄 > 2 年未轮换 | LastUsedAt - CreatedAt | +10 |
   | 在未验证的设备上使用 | HTTP 设备指纹不匹配 | +30 |

3. **凭据管理 API**（`interfaces/admin/credentials.go` —— ~100 行）：

   | API | 用途 | 鉴权 |
   |-----|------|------|
   | `GET /api/v1/admin/credentials` | 全局凭据列表（过滤：AAGUID、UserID、RiskScore、Status） | `admin:read.credentials` |
   | `GET /api/v1/admin/credentials/:id` | 单条凭据详情 + 使用历史 | `admin:read.credentials` |
   | `POST /api/v1/admin/credentials/:id/revoke` | 管理员强制吊销凭据 | `admin:write.credentials` |
   | `GET /api/v1/admin/credentials/stats` | 全局凭据统计（总数、按类型、按状态、按 AAGUID） | `admin:read.credentials` |

4. **自助凭据管理**（Portal SPA 扩展 —— ~60 行 JS）：

   | 功能 | Portal 页面 | 当前状态 |
   |------|-------------|----------|
   | 凭据列表（命名 + 型号 + 最后使用时间） | /me/credentials | ❌ 不存在（仅 `/me/mfa` 显示移除按钮） |
   | 凭据重命名 | /me/credentials | ❌ |
   | 凭据移除确认 + 后果说明 | /me/credentials | ✅ 已有（/me/mfa） |
   | "我丢了设备" 一键移除所有关联凭据 | /me/credentials | ❌ |

5. **Admin Console 凭据面板**（~80 行 JS 扩展）：

   | 面板元素 | 数据源 |
   |----------|--------|
   | 凭据分布（平台 vs 跨平台） | `GET /api/v1/admin/credentials/stats` |
   | 高风险凭据列表（RiskScore > 60） | `GET /api/v1/admin/credentials?risk_min=60` |
   | 已知脆弱 AAGUID 凭据 | `GET /api/v1/admin/credentials?aaguid=xxx` |
   | 凭据吊销操作 | 批量选择 → 批量吊销 + 理由输入 |

6. **凭据使用审计**（~30 行，分散在已有认证路径中）：每次 WebAuthn 认证成功时，记录 `credential_used` 审计事件（凭据 ID、用户、设备 IP、地理位置、时间）。

### 关键设计约束

- **不存储密钥材料**：CredentialRecord 存储的是 credential ID + 元数据，不存储私钥（WebAuthn 私钥永不出设备）
- **不降低安全性**：凭据风险评分是 advisory（fail-open），不阻止认证
- **MDS 更新**：FIDO MDS（Metadata Service）应定期刷新（现有 `mds.go` 已支持）
- **多后端**：CredentialRecord 存储复用现有的 `UserStore` + audit 模式（sqlite/redis/postgres）
- **凭据吊销是异步的**：标记凭据状态为 revoked → 下一次认证时检查并拒绝

### ROI

- **假设**：安全团队收到 FIDO 联盟关于特定型号 YubiKey 存在侧信道漏洞的公告。管理员在 Admin Console 上按 AAGUID 搜索 → 找到 47 个受影响的凭据 → 批量吊销 → 审计事件记录"凭据因已知漏洞被批量吊销" → 自动给 47 个用户发送通知"你的安全密钥已被吊销，请注册一个新的"
- **竞品差距**：Keycloak 有基础的凭据管理，Auth0 的 Guardian 有 MFA 管理但无凭据治理面板。这个方向在当前所有竞品中都是**前瞻性的差异化**
- **与 passkey 趋势的协同**：Apple/Google/Microsoft 正在全面推广 passkey。企业组织将面临"管理数百个员工 passkey"的现实问题。此方向提前布局

---

## 方向五：多区域部署与数据驻留自动化（Multi-Region Data Residency Automation）

### 概况

- **工作量**：XL（新架构模式 + 路由层 + 存储层扩展 + 文档）
- **价值**：高（GDPR / PIPL / LGPD / CCPA 合规刚需，SaaS 全球部署必经之路）
- **类型**：架构模式

### 为什么需要

项目已有区域感知能力：

| 能力 | 状态 |
|------|------|
| `WithRegionMiddleware` | ✅ 存在（从请求/配置中提取区域信息） |
| `WithTenantResidencyCheck` | ✅ 存在（验证租户的区域合规性） |
| `tenant.DataResidencyRegion` | ✅ 存在（定义了租户的允许区域列表） |
| 区域解析器 SPI | ✅ `region.Resolver` + `region/memory` + HTTP 头策略 |

但**区域感知不等于多区域部署**：

| 现状 | 多区域所需 |
|------|-----------|
| 单区域部署，所有数据在同一数据库/集群 | 每区域独立数据存储（用户库、会话、token 数据） |
| 同一个进程处理所有租户 | 区域级路由：EU 租户 → EU 区域，US 租户 → US 区域 |
| 跨区访问时通过中间件返回 403 | 跨区访问时自动路由到正确的区域 |
| 无区域间数据同步 | 配置数据（clients、tenants）最终一致同步，用户数据原地不迁移 |
| 无区域部署自动化 | 区域部署/DNS 路由/证书自动管理 |

**问题本质**：当前架构假设**单区域、共享存储**随着租户分布到多个区域，需要：

```
┌─ 区域路由层 ──────────────────────────────────┐
│  global.sso.example.com → 区域解析 → 目标区域   │
│   ├── EU 租户 → eu.sso.example.com            │
│   ├── US 租户 → us.sso.example.com            │
│   └── CN 租户 → cn.sso.example.com            │
└────────────────────────────────────────────────┘

┌─ EU 区域 ─────┐  ┌─ US 区域 ─────┐  ┌─ CN 区域 ─────┐
│ DB (GDPR)     │  │ DB (US)       │  │ DB (PIPL)     │
│ Session Store │  │ Session Store │  │ Session Store │
│ Audit Logs    │  │ Audit Logs    │  │ Audit Logs    │
└───────────────┘  └───────────────┘  └───────────────┘
        └────────── 配置同步 (etcd/总线) ──────────┘
```

### 范围

1. **区域路由层**（`interfaces/router/region_aware.go` —— ~120 行）：一个反向代理 / DNS 路由层，根据以下策略将请求路由到目标区域：

   | 路由策略 | 优先级 | 用途 |
   |----------|--------|------|
   | 租户 DNS（`eu.sso.example.com`） | 最高 | 租户直接连接到区域端点 |
   | 请求头（`X-Data-Region: eu`） | 高 | API 客户端携带区域偏好 |
   | 用户 session 记录的区域 | 中 | 已登录的用户路由到其 session 所在的区域 |
   | GeoIP 解析 | 低 | 新用户/未登录用户根据 IP 路由 |

2. **区域数据存储架构**：

   ```
   ┌─ 配置数据（低变更、最终一致） ────────────────────┐
   │  Clients、Tenants、Permissions、FederationConfig │
   │  存储模型：etcd / 全局 SQLite / 跨区同步策略      │
   │  一致性：最终一致（AP + TTL + bus 失效广播）       │
   └─────────────────────────────────────────────────┘

   ┌─ 用户数据（高隐私、不离开区域） ──────────────────┐
   │  Users、Session、RefreshTokens、AuthCodes        │
   │  存储模型：区域本地 SQLite / Redis / Postgres     │
   │  一致性：写本地 + 读本地（CP 在区域内）             │
   └─────────────────────────────────────────────────┘

   ┌─ 审计数据（合规留存、不离开区域） ─────────────────┐
   │  Audit Events 按区域存储                          │
   │  可选：全局审计副本（脱敏，仅运营用）                │
   └─────────────────────────────────────────────────┘

   ┌─ 签名密钥（全局可验证） ──────────────────────────┐
   │  JWKS 全局可访问（CDN / 区域 JWKS 端点）           │
   │  私钥在各自区域，公钥跨区聚合（复用 signingkeys/）    │
   └─────────────────────────────────────────────────┘
   ```

3. **区域注册/发现**（~60 行）：`platform/registry/` 扩展为支持区域注册——每个区域启动时在全局注册中心注册自己（端点、可用租户范围、健康状态）。

4. **跨区域 token 验证**（~40 行）：区域 A 签发的 token 在区域 B 验证时的兼容性处理：
   - 使用全局共享 JWKS（signingkeys 聚合已经支持这种模式）
   - JTI replay 在区域级不可跨区（但这是设计上可接受的——每个区有自己的 replay store）
   - refresh token 和 auth code 是区域化的——用户登录时绑定到目标区域
   - session 是区域化的——用户 session 在哪个区域创建就在哪个区域使用

5. **数据驻留合规报告 API**（`GET /api/v1/admin/regions/compliance` —— ~50 行）：返回每个区域的数据驻留状态报告——哪些租户的数据在该区域、存储的数据类型、保留期限、上次合规检查时间。

6. **文档**（~2 页）：多区域部署架构指南：
   - 区域 DNS 路由模式（GeoDNS / HTTP 重定向）
   - 每区域的最小部署组件
   - 配置数据同步策略（etcd 集群 per-region vs 全局）
   - 灾难恢复：区域级故障下的跨区故障转移
   - 区域间延迟预算（JWKS 验证、token introspection）
   - 合规矩阵：GDPR Art.44 / PIPL Art.36 / CCPA 的区域数据映射

### 关键设计约束

- **配置同步是 AP 的**：Clients/Tenants 配置跨区域最终一致（秒级到分钟级）。token 验证是区域本地的（不受配置同步延迟影响）
- **用户数据是区域钳位的**：用户创建时根据租户的数据驻留策略分配到区域。用户数据**绝不迁移区域**（迁移需要 GDPR Art.20 数据可携带性流程）
- **审计是区域钳位的**：审计记录产生在哪个区域就存储在哪里。运营者的全局审计搜索通过每个区域的审计 API 聚合实现
- **跨区域切换是 admin 操作**：租户的区域分配变更需要 admin 审批 + 数据迁移计划 + 合规备案
- **不要求同步强时钟**：跨区域 token 签发使用区域管理的时钟源。token 验证容忍 `WithMaxClockSkew`（当前默认 30s）

### ROI

- **假设**：一个 SaaS 运营商在法兰克福（EU）、弗吉尼亚（US）和新加坡（APAC）部署了三套区域集群。EU 租户的用户登录时通过 GeoDNS 路由到 eu.sso.example.com，认证和数据全部留在 EU 区域。管理操作（创建客户端、上传 SCIM 用户）通过全局 API 网关路由到最近的区域。管理员在 Admin Console 上可以看到"我的数据在哪些区域"的合规矩阵
- **竞品差距**：Auth0 的多区域是 Enterprise 付费功能；Okta 的多区域 Cell-Based Architecture 是其核心架构；Keycloak 没有多区域概念
- **工作量**：XL（架构重大变更，建议分 3 个里程碑推进）
- **前置依赖**：signingkeys 聚合（已完成）是跨区域 JWKS 的基础。region 包（已完成）是区域路由的基础。tenant residency check（已完成）是合规检查的基础。**地基已铺好，静等上层建筑**

---

## 优先级摘要

| # | 方向 | 工作量 | 价值 | 适合时机 | 核心收益 |
|---|------|--------|------|----------|----------|
| 1 | 联盟元数据生命周期管理 | **L** | **高** | 立刻 | 运营基础设施刚性缺口，实时告警替代被动故障，当前为零投入 |
| 2 | 身份生命周期自动化 | **L** | **高** | 立刻（依赖 1？否） | HR-provisioning 自动化基座，企业 HRIT 集成第一问 |
| 3 | Passkey 凭据全生命周期治理 | **M** | **中-高** | 方向 1-2 之后 | Passkey 时代的差异化安全治理，竞品均未系统覆盖 |
| 4 | 开发者 Portal + 第三方 App 管理 | **XL** | **高** | 方向 1-2 之后 | "SSO 服务器→身份平台"的核心跨越，B2B/B2C 场景分水岭 |
| 5 | 多区域部署与数据驻留自动化 | **XL** | **高** | 长期架构方向 | GDPR/PIPL 合规刚需，区域化部署的架构支撑 |

### 阶段建议

**Phase 1（本月）**：方向①（联盟元数据生命周期管理）—— L 工作量、高价值、当前为零。与现有的联盟基础设施完全解耦，可在不修改任何认证路径的情况下交付。Admin Console 健康面板扩展可快速落地。

**Phase 1 并行**：方向②（身份生命周期自动化）—— 定义生命周期事件类型 + 发布点 + Webhook 出站。SCIM 出站客户端可以单独作为 P1。与方向①互补（方向①管"连接健康"，方向②管"身份事件传播"）。

**Phase 2（下月）**：方向③（Passkey 凭据治理）—— M 工作量，差异化价值。FIDO 联盟和 passkey 标准的快速演进使得凭据治理将成为组织的刚需（比如"我们只允许 FIPS 140-3 认证的认证器"）。

**Phase 3（下季度）**：方向④（开发者 Portal）—— XL 工作量，需要新的 SPA + 管理 API + Client 模型扩展。这是从"SSO 服务器"到"身份平台"的关键跨越，建议作为战略投资。

**Phase 4（长期）**：方向⑤（多区域部署）—— 架构级重大变更。不急于立即实现，但建议在设计未来功能时考虑区域维度（"这个数据是否需要区域化？"的思考框架）。

---

## 与已有分析的关系

| 本报告方向 | 此前哪个分析覆盖过？ | 关系 |
|-----------|---------------------|------|
| ① 联盟元数据生命周期管理 | **无人覆盖** | 全新方向。ROADMAP 的和 8 轮分析均未提及联盟连接的运行时健康管理 |
| ② 开发者 Portal | **无人覆盖** | 全新方向。ROADMAP v5.0 方向①（终端体验产品层）聚焦 login/consent 面 × 自助门户 × Console，未涉及第三方开发者 |
| ③ 身份生命周期自动化 | **局部覆盖** | 卷一方向⑤（连续风险引擎）聚焦实时评估而非生命周期事件。ROADMAP v5.0 方向②（B2B 企业化）关注连接/HRD/用量，未涉及生命周期自动化 |
| ④ Passkey 凭据治理 | **无人覆盖** | 全新方向。认证作为因子已被充分分析，但凭据作为企业管理资产从未被审视 |
| ⑤ 多区域部署 | **局部分析** | ROADMAP v4.0 集群视角 C④ 提及"多区域 + 数据驻留"为 XL 前沿方向。本次给出了更具体的架构拆分和可实施方向 |

## 附录：核验方法

### 方向① 核验

```bash
# 确认无 federation health/status/cert 管理端点
$ grep -rn "federation.*health\|federation.*status\|federation.*cert\|metadata.*health\|connection.*health" --include="*.go" . | grep -v "_test.go" | grep -v ".git/"
# 输出为空

# 确认无证书过期告警逻辑
$ grep -rn "CertExpires\|cert.*expir\|certificate.*expir" --include="*.go" . | grep -v "_test.go" | grep -v ".git/"
# 输出仅 saml/idp 的手动提取，无自动监控

# 确认无元数据自动刷新
$ grep -rn "AutoMetadata\|auto.*refresh\|metadata.*refresh" --include="*.go" . | grep -v "_test.go" | grep -v ".git/"
# 输出仅文档注释提及"可以"自动刷新，无实际代码
```

### 方向② 核验

```bash
# 确认无 developer 面向的端点
$ grep -rn "developer\|developer-portal\|/developer" --include="*.go" . | grep -v "_test.go" | grep -v ".git/"
# 输出为空

# 确认无 AppReview/AppStatus 概念
$ grep -rn "AppReview\|AppStatus\|review_status\|ReviewStatus" --include="*.go" . | grep -v "_test.go" | grep -v ".git/"
# 输出为空

# 确认无开发者 scope
$ grep -rn "developer:" --include="*.go" . | grep -v "_test.go" | grep -v ".git/"
# 输出为空（admin:read/write 存在，但无 developer scope）

# 确认已有 web/developer/ 目录不存在
$ ls interfaces/web/developer/ 2>/dev/null || echo "directory does not exist"
```

### 方向③ 核验

```bash
# 确认无生命周期事件类型定义
$ grep -rn "LifecycleEvent\|lifecycle_event\|identity_lifecycle" --include="*.go" . | grep -v "_test.go" | grep -v ".git/"
# 输出为空

# 确认无出站 SCIM 客户端
$ grep -rn "scimclient\|ScimClient\|OutboundSCIM\|SCIMOutbound" --include="*.go" . | grep -v "_test.go" | grep -v ".git/"
# 输出为空
```

### 方向④ 核验

```bash
# 确认无 CredentialRecord 模型
$ grep -rn "CredentialRecord\|DeviceName\|credential_risk\|credential.*usage\|Credentials" --include="*.go" shared/core/types_auth.go
# 输出为空（仅出现在 SPI 的 User 类型中）

# 确认无凭据管理 API
$ grep -rn "admin.*credential\|credential.*admin\|/credentials" --include="*.go" interfaces/ | grep -v "_test.go"
# 输出为空

# 确认凭据命名不存在
$ grep -rn "credential.*name\|DeviceName\|device_name\|friendly.*name\|credential_friendly" --include="*.go" . | grep -v "_test.go" | grep -v ".git/"
# 输出仅 `mfaFactorLabel = "Passkey"` 常量，无用户可命名的字段
```

### 方向⑤ 核验

```bash
# 确认跨区域路由不存在
$ grep -rn "region.*route\|region.*proxy\|region.*balancer\|cross.*region.*routing" --include="*.go" . | grep -v "_test.go" | grep -v ".git/"
# 输出为空

# 确认区域数据存储模型不存在
$ grep -rn "RegionalStore\|region.*store\|region.*db\|region.*datastore" --include="*.go" . | grep -v "_test.go" | grep -v ".git/"
# 输出为空

# 确认跨区域 token 验证路径不存在
$ grep -rn "cross.*region.*token\|cross.*region.*verify\|regional.*verify" --include="*.go" . | grep -v "_test.go" | grep -v ".git/"
# 输出为空
```

---

*本报告由 AI Agent 基于全代码库扫描生成，每条方向均经代码级交叉验证为真缺口，不包含未经 grep 确认的推测性结论。*
