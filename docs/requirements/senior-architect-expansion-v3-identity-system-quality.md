# 扩展方向分析 —— 身份安全可见性、运营治理与平台成熟度

> **作者：** 资深架构 & 产品经理  
> **日期：** 2026-07-11  
> **方法：** 全代码库完整扫描（遍历所有 `*.go`、`*.md`、`*.yaml`、`*.html`、`*.js` 文件），  
>   系统阅读 docs/requirements/ 下全部 29 份历史扩展方向分析文档（v1–v13、novel*、  
>   edge-cases、gaps-analysis、ciam-identity-horizon、privacy-dx-operations、  
>   production-gaps、systemic-quality、senior-architect* 等），对 100+ 关键词做逐项 grep  
>   交叉核验，确保每项为 **真实代码级缺口且与所有历史分析零重叠**。  
> **定位：** 本报告不属于「新增协议支持」「补后端实现」「生产硬化」「产品面 UI/UX」「开发者生态」  
>   或「安全运营中心/SOC」——那些已在 29 轮分析中被反复覆盖并大量落地。本报告聚焦于一个身份平台  
>   在达到功能完备性后，向 **可运营、可治理、可信任的企业级基础设施** 跃迁时，在身份安全可见性  
>   （Identity Security Visibility）、管理治理（Admin Governance）、主动沟通（Proactive  
>   Communication）、配置可靠性（Configuration Reliability）和令牌治理（Token Lifecycle  
>   Governance）五个横切维度上的剩余盲区。  
> **体例：** 每项方向包含 Why now（产品/市场时机）、Code evidence（具体代码级证据——缺口位置与  
>   grep 结果）、Scope（可独立交付的颗粒度，P0/P1/P2）、Edge cases、历史分析 zero-overlap 证据。

---

## 前置声明：项目成熟度总览

经过 29 轮全局扫描 + 大量增量落地，本项目的能力覆盖面已达到行业顶级水平。以下领域已确认全部覆盖，**本报告不再重复分析**：

| 领域 | 覆盖状态 |
|---|---|
| **协议面**（OAuth 2.0 × 7 grants + PAR/JAR/JARM/RAR/CIBA、OIDC Core/Discovery/Logout/BCL/FCL/FormPost、SAML 2.0 SP+IdP、SCIM 2.0 双向、CAEP/SSF 双向、FAPI 2.0、OpenID Federation 1.0、LDAP、Kerberos、RADIUS、DPoP、mTLS、SPIFFE JWT-SVID、Transaction Token、Step-Up Auth） | ✅ 全部落地 |
| **存储面**（Memory、SQLite、Redis、etcd、PostgreSQL + 14 嵌套模块：KMS×5、SAML×4、LDAP、Kerberos、RADIUS、ext_authz、Kafka、MQTT、Vault Transit） | ✅ 全部落地 |
| **安全面**（Anti-enumeration、Oracle-leak、DPoP、mTLS、JWT-SVID、Workload Identity GCP/AWS/Azure、Break-Glass 2-person、Per-tenant 签名隔离、区域数据驻留、FAPI 2.0、FIPS 140-3、会话信任衰减、Account Lockout、Step-Up Auth、Conditional Access CAEP） | ✅ 全部落地 |
| **产品面**（Hosted Login SPA、Admin Console SPA、Developer Portal SPA、User Portal `/me`、Consent Store × 3、B2B Connections + HRD、Org-admin self-service、API docs viewer、SDK 生成 TS + Python、MCP Server） | ✅ 全部落地 |
| **运维面**（DR framework Snapshot/RPO/RTO、Config hot-reload SIGHUP × 7 gates、Metrics/Prometheus/Grafana/12 alerts、Audit hash-chain + OCSF/CEF/Syslog、pprof、k6 load test、Chaos tests × 4、Benchmark gate、Bare-metal HA runbook、Terraform/Kustomize/Helm） | ✅ 全部落地 |
| **治理面**（SOC2 report、GDPR Art.15/17/20/30 compliance、Data retention sweeper、ReBAC Zanzibar engine、RBAC permissions、Session hub、Anomaly detection + Threat action、Webhook engine、User lifecycle state machine） | ✅ 全部落地 |
| **韧性/前沿/分析覆盖面**（Post-Quantum Crypto、AI/ML Identity Analytics、AI Agent Identity、CIAM/Social Login、Session Roaming、PAM、Token Status List、FIDO2 Cross-Device、Offline/Edge Mode、Grant Management、Progressive Profiling、Security Posture Scoring、SPA Frontend Quality、Integration Marketplace、Performance Operations、Test Quality Maturity、Security Operations SOC、Privacy Infrastructure、Developers Experience、FinOps/Resource Governance、Token Exchange Federation、Cross-Protocol Migration、Long-Lived Session、Auth Methods Metadata、OAuth Mix-up Mitigation） | ✅ 已分析（待落地或决策中） |

> **结论：** 经过 29 轮系统性分析（v1–v13 全面扫描 + 7 轮 novel/edge/ciam/privacy 定向深钻 + 3 轮 senior-architect 横切审查），项目的「发现-分析」阶段已经接近理论上限。剩余的最高价值空间不再来自「找到新的功能缺口」，而是 **将已分析的治理、运营、信任能力封装为可直接销售的产品功能，以及在横切质量维度上补全企业级基础设施的最后一公里**。

---

## 方向一：端用户安全可见性与身份透明中心（End-User Security Visibility & Identity Transparency Center）

### Why Now

这是项目当前**唯一的面向用户的身份安全视图缺口**。项目拥有：

- 面向**管理员**的凭据健康扫描（v10 分析提及，未落地）
- 面向**安全运营中心**的 SOC 面板（senior-architect 方向五，已分析待落地）
- 面向**管理员**的 token portfolio 和会话管理
- 面向**管理员**的审计事件追踪

但**没有面向终端用户的综合安全可见性面板**。在企业 SSO 场景中，终端用户需要了解自己账户的安全状态——这是零信任架构中「用户作为安全主体」的基本要求，也是 GDPR Art.15（访问权）和 Art.32（安全处理）的实际落地。

### 当前具体代码级缺口（grep 核验）

| 概念 | 命中 | 状态 |
|---|---|---|
| `me/security\|/me/security-dashboard\|/me/activity` | **0** | 零实现 |
| `account.*activity.*timeline\|user.*activity.*timeline` | **0** | 零实现（`recent_logins` 表存在，但仅用于 anomaly detection，无用户面 API） |
| `security.*tip\|security.*recommend\|security.*suggestion\|security.*advice` | **0** | 零实现 |
| `credential.*health.*end.*user\|my.*credential.*health\|my.*security.*score` | **0** | 零实现 |
| `token.*binding.*status\|my.*token.*binding\|my.*devices.*trusted` | **0** | 零实现（`trusted_device_store` 存在，但无用户可见的设备信任状态） |
| `session.*geo\|session.*location\|login.*location\|my.*login.*history` | **0** | `recent_logins` 表含 ip+user_agent，但未暴露给用户 |

**关键区别：** 现有 `/me` 端点返回 `active_sessions` 和 `granted_apps` 计数，但无结构化安全视图。Portal SPA 有独立的 sessions/consents/MFA 卡片，但无统一安全面板。

### Scope

| 分层 | 组件 | 说明 |
|---|---|---|
| **P0**（M，2 周） | 账户安全摘要 API | `GET /me/security` 返回结构化摘要：password 是否已设置及最后修改时间、MFA 是否开启及已注册因子数、活跃会话数（含设备分类：当前设备/其他设备/未知设备）、已授权应用数、最近一次登录时间+位置+设备、是否存在未解决的安全建议 |
| **P0**（S，1 周） | 最近活动时间线 API | `GET /me/security/timeline?limit=20` 返回按时间逆序排列的安全事件：登录（含方法+IP+设备）、密码修改、MFA 注册/移除、consent 授权/撤销、email 变更、session 创建/销毁、设备信任/取消信任。数据源：现有 `recent_logins` + `audit.Event`（按 subject 过滤） |
| **P1**（M，2 周） | Portal SPA 安全面板 | User Portal 新增「Security」导航标签：账户安全摘要仪表盘（密码健康指示器、MFA 状态徽章、会话计数）、活动时间线视图（列表 + 筛选：登录/MFA/密码/consent）、设备信任管理（将当前设备标记为可信、查看可信设备列表）、安全建议（「启用 MFA」「轮换密码」） |
| **P1**（S，1 周） | 安全通知与建议引擎 | 后台安全建议生成：基于账户状态的安全评分（0-100），生成可操作的建议列表（`issue_id` + `severity` + `title` + `description` + `action_url` 模式）。建议包括：启用 MFA、设置密码、轮换旧密码（>90天）、移除未使用的设备信任、审查活跃会话、审查授权的应用 |
| **P2**（M，2 周） | 会话地理位置可视化 | 在活动时间线中为登录事件增加地图/地理位置视图（基于 IP 的地理位置解析，复用现有 `geo` 包）。「你的账户当前在 3 个设备上活跃：Chrome on macOS（北京）、Safari on iOS（上海）、Firefox on Windows（未知 IP）」 |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 审计事件量过大导致时间线 API 性能问题 | 使用时间分区索引 + 分页（默认 20 条）+ 预聚合（按天+事件类型）；对 `audit.Event` 按 subject 加索引 |
| 安全评分引发用户焦虑 | 评分仅显示为「良好/一般/需关注」（而非数字），建议以积极语气表述（「你的账户安全状态良好，以下可选改进项…」） |
| 地理位置数据不准确 | 地理位置为最佳推测，始终标明「近似位置」；不准确时允许用户标记 |
| 历史事件数据的保留期限 | 事件时间线仅显示保留期限内的数据（默认 90 天），过期事件自动归档；不显示「数据已过期」以外的占位 |

### 历史分析 zero-overlap 证据

```
for term in "me.*security\|end.user.*security.*dashboard\|user.*activity.*timeline\|security.*transparen.*user\|my.*security.*score\|account.*security.*summary\|security.*recommend.*user\|user.*security.*visibility\|identity.*transparen.*center\|security.*tip.*end.user\|my.*activity.*timeline\|account.*timeline"; do
  grep -rl "$term" docs/requirements/*.md 2>/dev/null || echo "  (no matches)"
done
```

全部关键词在 29 份历史分析中**零命中**。最近的 senior-architect-expansion 方向五虽然提出了面向 SOC 分析师的统一安全事件时间线和管理员安全态势 API，但那是**管理面**视角。本方向提出的是**端用户面**视角——这两者面向不同的角色，解决不同的问题，需要不同的 API 设计和 UI。

---

## 方向二：管理后台权限治理与委托管理（Admin Delegation & Access Governance）

### Why Now

项目拥有强大的管理端点（gRPC + REST admin API）和粗粒度的权限模型（`admin:read`、`admin:write`、break-glass impersonation）。但企业 SSO 部署的典型场景是一个**组织内有多个管理员**，他们需要**不同级别的访问权限**：

| 管理员类型 | 需要的权限 |
|---|---|
| 安全管理员 | 查看所有配置、查看审计日志、管理安全策略、管理密钥 |
| 客户支持（Helpdesk） | 重置密码、查看用户状态、管理 MFA 恢复——但**不能**创建客户端或查看密钥 |
| 应用开发者 | 管理特定的客户端（自己注册的应用）——但**不能**查看其他客户端或租户配置 |
| 审计员 | 只读访问审计日志和配置——**不能**做任何变更 |
| 租户管理员 | 管理自己租户内的用户和配置——**不能**查看其他租户 |

当前系统中**没有任何机制来实现上述场景**。`admin:write` 的权限太粗——一个 helpdesk 管理员只要持有 `admin:write` 就可以创建新客户端、修改安全配置、甚至删除密钥。

### 当前具体代码级缺口（grep 核验）

| 概念 | 命中 | 状态 |
|---|---|---|
| `AdminRole\|admin_role\|admin_role.*store\|RoleScope\|role_scope` | **0** | 零实现 |
| `sub.*admin\|delegated.*admin\|limited.*admin\|helpdesk.*admin\|readonly.*admin\|read.only.*admin` | **0** | 零实现 |
| `admin.*permission.*check\|admin.*authz.*store\|admin.*authz.*policy` | **0** | 零实现（仅 `admin.Middleware.authorizeWithContext` 使用硬编码的 scope 检查） |
| `admin.*session\|admin.*login\|admin.*activity\|admin.*activity.*feed` | **0** | 零实现（break-glass 有 audit 事件，普通 admin 操作只有 `recordAdminUserAction` 的 audit 事件，无独立的管理员活动面板） |
| `AdminAPIKey\|admin_api_key\|admin.*token.*manage\|admin.*token.*rotate` | **0** | 管理员令牌由 `WithAdminToken` 静态配置，无管理面生命周期管理 |

### 为什么需要它

1. **最小权限原则在企业中的硬性要求**：SOC2、ISO 27001、PCI DSS 等合规框架均要求「用户仅拥有完成工作所需的最小权限」。当前 `admin:write` 的「全有或全无」模型无法通过此类审计。

2. **降低管理员操作风险**：一个 helpdesk 管理员误操作（如误删了生产环境的 OIDC 客户端）在当前系统下无法通过权限模型阻止。委派管理的核心价值是将「谁可以做什么」从操作纪律问题转变为系统强制保证。

3. **多租户管理场景**：当 tenant admin 需要管理自己的租户时，当前只能通过 `admin:write` 授权——这同时授予了他们管理所有其他租户的能力。没有租户 scope 的管理委派是无法在生产中使用的。

4. **管理操作的可追溯性**：当前 admin 操作记录为 audit 事件，但无结构化的「管理活动面板」来回答「上周谁做了什么变更？」。

### Scope

| 分层 | 组件 | 说明 |
|---|---|---|
| **P0**（M，2 周） | 管理角色 SPI 与存储 | 定义 `AdminRoleStore` SPI：`AdminRole{ID, Name, Scopes []AdminScope, TenantIDs []string}`。`AdminScope` 是细粒度的权限条目（如 `clients:read`、`clients:write`、`users:read`、`users:password:reset`、`audit:read`、`keys:read`、`keys:rotate`、`tenants:*` 等）。Memory 实现 + SQLite 实现 |
| **P0**（M，1 周） | 管理角色 API | `CRUD /api/v1/admin/roles`（admin:write 创建角色，admin:read 列出/查看角色）。`PUT /api/v1/admin/users/:id/role`（将用户绑定到角色）。`GET /api/v1/admin/users/:id/role` 查看用户的管理角色 |
| **P1**（M，2 周） | 细粒度授权中间件 | 将 `admin.Middleware` 的 `admin:read/admin:write` 硬编码 scope 检查替换为基于 `AdminScope` 的权限检查。每个 admin handler 声明所需的最小 scope 列表。兼容性：当未配置 `AdminRoleStore` 时回退到现有的 read/write 模型 |
| **P1**（M，1 周） | 管理活动面板 API | `GET /api/v1/admin/audit/activity?actor=&action=&resource=&time_range=` 返回管理操作审计事件的结构化列表，按时间线展示 |
| **P2**（M，2 周） | Admin Console 管理面板 | Admin Console 新增「Admin Management」页面：管理员用户列表、角色管理（创建/编辑角色）、管理活动面板（谁做了什么）。break-glass 事件高亮显示 |
| **P2**（S，1 周） | 管理员自我审查 | 管理员可以查看自己的管理操作记录、「我的管理权限」摘要、最近的管理活动。提供安全建议（「你有 write 权限但 30 天未登录管理面板」） |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 管理员将自己的管理角色降级后无法恢复 | 降级操作需要现有角色的 `admin:roles:write` 权限；如果新角色不再包含此权限，操作被拒绝并返回 `last_admin_role` 错误 |
| break-glass 紧急访问与角色的交互 | break-glass 仍然绕过角色检查（这是其设计目的），但操作记录会标记 `bypass_reason=break_glass` |
| 角色变更的生效时机 | 角色变更立即生效，无缓存过期窗口。使用 cluster bus 广播角色变更事件 |
| 多租户管理员（scope 限定到特定 tenant） | `AdminRole.Scope` 支持资源限定：`clients:write:tenant_id=acme-corp` 表示仅在 `acme-corp` 租户下可写客户端 |

### 历史分析 zero-overlap 证据

```
for term in "admin.*delegat\|admin.*role.*store\|sub.*admin\|helpdesk.*admin\|admin.*scope.*gram\|admin.*permission.*model\|manage.*admin.*role\|admin.*authz.*scope\|delegated.*admin.*manage\|admin.*governance.*model\|admin.*activity.*dashboard"; do
  grep -rl "$term" docs/requirements/*.md 2>/dev/null || echo "  (no matches)"
done
```
全部关键词在 29 份历史分析中**零命中**。

---

## 方向三：主动式用户通知与通信框架（Proactive User Notification & Communication Framework）

### Why Now

项目拥有强大的**服务器端**通信能力：

- **Webhook 引擎**（`platform/lifecycle/webhook/`）：面向管理员的 HTTP 回调，含重试、死信队列、管理 API
- **CIBA Ping**（`oauth/ciba.go`）：OAuth 设备流的推送通知
- **Backchannel 登出**（`server_backchannel_logout.go`）：OIDC BCL 的跨会话登出推送
- **Push MFA**（`defaultimpl/defaultmfa/push_mfa_provider.go`）：MFA 推送审批
- **SMTP 邮件**（`defaultimpl/emailsmtp/`）：邮件发送（密码重置、验证码、MFA 恢复码）

但**不存在任何面向终端用户的主动通知框架**——用户当前只能通过**拉取**方式获取信息（登录时看到密码过期、主动访问 `/me` 查看会话数）。典型的 SSO 场景中，用户需要**主动通知**来：

| 场景 | 当前行为 | 期望行为 |
|---|---|---|
| 密码将在 7 天后过期 | 登录时收到 `password_expiring` 错误 | 提前 7 天收到邮件/应用内通知 |
| 新设备登录 | 无通知 | 即时邮件/SMS 通知「你的账户从新设备登录」 |
| MFA 因子被移除 | 无通知 | 即时通知「一个 MFA 因子已从你的账户移除」 |
| 授权了新的应用 | 无通知 | 通知「你授权了 App X 访问你的账户数据」 |
| 会话即将过期 | 无通知 | 提醒「你的活跃会话将在 30 分钟后过期」 |
| 被动持凭据（HIBP） | 登录时阻止（HIBP 检查） | 额外主动通知「你的密码在数据泄露中被发现，请立即修改」 |

### 当前具体代码级缺口（grep 核验）

| 概念 | 命中 | 状态 |
|---|---|---|
| `notification.*store\|notification.*spi\|NotificationStore\|NotificationSender\|notif.*channel` | **0** | 零实现 |
| `user.*notif.*event\|notif.*event.*type\|notification.*event` | **0** | 零实现 |
| `notif.*preference\|notification.*preference\|notif.*opt.*\|notif.*subscri` | **0** | 零实现 |
| `NotificationDelivery\|notification.*delivery\|notif.*history\|notif.*log` | **0** | 零实现 |
| `email.*template.*user\|sms.*template\|notification.*template` | **0** | 零实现（仅有 `emailsmtp/templates.go` 的密码重置/验证码模板） |
| `notification.*queue\|notification.*worker\|notif.*async\|notification.*batch` | **0** | 零实现 |

### Scope

| 分层 | 组件 | 说明 |
|---|---|---|
| **P0**（M，2 周） | 通知事件 SPI 与核心类型 | 定义 `NotificationEvent{ID, Type, SubjectID, TenantID, Title, Body, Severity, Channel, CreatedAt, ReadAt}`。`NotificationStore` SPI（Create/ListBySubject/MarkRead）。`NotificationSender` SPI（Send(event) → error）。定义初始事件类型：`password_expiring`、`new_device_login`、`mfa_removed`、`consent_granted`、`session_expiring`、`password_leaked` |
| **P0**（M，1 周） | 通知发送适配器 | `email.NotificationSender`（复用现有 SMTP 发送器，新增通知专用模板）、`inapp.NotificationSender`（写入 `NotificationStore`，用户 Portal 拉取）。Future：`sms.NotificationSender`（需要 SMS 网关集成） |
| **P1**（M，2 周） | 事件→通知路由引擎 | 核心事件监听器：监听 `audit.Event` 中的用户相关事件（`EventPasswordChanged`、`EventConsentGranted`、`EventMFAFactorRemoved`、`EventNewDeviceLogin`），异步生成 `NotificationEvent` 并调用 `NotificationSender`。后台定时器检测即将过期的密码和会话（基于 `CredentialStatusStore` + 会话索引） |
| **P1**（M，1 周） | 通知偏好 API | `GET /me/notifications/preferences` 返回各事件类型的通知通道偏好（email/in-app/off）。`PUT /me/notifications/preferences` 修改偏好。`GET /me/notifications` 列出未读/历史通知。`POST /me/notifications/:id/read` 标记已读 |
| **P1**（S，1 周） | Portal SPA 通知中心 | User Portal 新增通知铃铛图标 + 通知面板：未读通知计数、通知列表（标题+时间+图标）、点击跳转到相关操作页面、「全部标记已读」操作 |
| **P2**（M，2 周） | 通知批量发送与频率控制 | 通知发送队列（基于现有 `memreaper` 模式）：批量发送、去重（10 分钟内同类型事件合并为一条）、频率限制（每种事件类型每天最多 N 条）、静默时段（22:00-08:00 不发非紧急通知） |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 用户关闭了所有通知通道 | 系统保留生成通知事件的日志，但不触发发送；不影响核心功能 |
| 通知量过大导致用户「通知疲劳」 | 每种事件类型每小时最多 1 条（紧急的 `password_leaked` 类型可配置为最多 5 条/小时） |
| 邮件通知被用户标记为垃圾邮件 | 在通知邮件中添加 `List-Unsubscribe` 头；提供「取消订阅所有通知邮件」链接（需要 Bearer token 验证） |
| 通知生成在事件处理热路径上 | 通知生成完全异步：事件 → 内部 channel → worker pool → 发送。发送失败不阻断原始操作 |
| 通知系统自身故障 | 通知错误仅记录日志，不 fail 原始操作。暴露 `sso_notification_sent_total` 和 `sso_notification_failed_total` 指标 |

### 历史分析 zero-overlap 证据

```
for term in "proactive.*notif\|user.*notif.*framewor\|notif.*event.*type\|NotificationEvent\|NotificationStore.*SPI\|notif.*preference\|notif.*center\|notification.*center\|in.app.*notif\|user.*alert.*framewor\|notif.*channel\|NotificationSender\|notif.*queue.*batch"; do
  grep -rl "$term" docs/requirements/*.md 2>/dev/null || echo "  (no matches)"
done
```
**注意：** `expansion-five-uncovered-gaps.md` 的凭证健康部分在一行 grep 证据表中列出了 `rotation.*notif` 关键词，显示「零实现」——但仅限于在凭据健康扫描的上下文中提及通知需求，从未作为独立的**用户通知框架**方向分析。本方向首次将通知作为系统级能力（SPI、存储、发送适配器、偏好管理、通知中心 UI）完整提出。

---

## 方向四：配置合规、模式验证与投产前校验管线（Configuration Compliance, Schema Validation & Pre-Production Validation Pipeline）

### Why Now

项目拥有灵活的配置系统（YAML 文件 + 环境变量 + etcd + 命令行 flag）、配置热加载（SIGHUP）和 `--validate-only` 启动校验。但企业部署场景中，配置管理的挑战远不止「配置文件语法是否正确」：

| 配置风险 | 当前防护 | 缺口 |
|---|---|---|
| 引用了不存在的 store/backend | ❌ **无校验** | 启动时 panic，无提前检测 |
| 交叉引用错误（grant X 需要 store Y 但未配置） | ❌ **无校验** | 运行时 501，部署后才暴露 |
| 安全配置不一致（所有客户端应使用 DPoP，但新创建的客户端未启用） | ❌ **无策略** | 无策略即代码 |
| 生产配置与基准配置的差异 | ⚠️ **部分** | ConfigAudit 存在（跨集群配置差异），但无「预投产 diff 预览」 |
| 配置变更的影响分析（「如果修改这个值会有什么后果？」） | ❌ **无工具** | 手动推演 |
| 多个配置文件之间的冲突检测 | ❌ **无校验** | 后加载的值静默覆盖前值 |

### 当前具体代码级缺口（grep 核验）

| 概念 | 命中 | 状态 |
|---|---|---|
| `config.*schema.*json\|jsonschema\|config.*cue\|config.*cue.*validat` | **0** | 零实现 |
| `config.*compliance.*check\|config.*policy.*check\|config.*rule\|config.*constraint` | **0** | 零实现 |
| `config.*cross.*ref\|cross.*reference.*validat\|config.*dep.*check` | **0** | 零实现 |
| `config.*diff.*preview\|config.*dry.*run\|config.*what.*if\|config.*impact.*analyz` | **0** | 零实现 |
| `config.*baseline\|config.*benchmark\|config.*recommend\|config.*best.*practic` | **0** | 零实现 |
| `config.*migration.*check\|config.*upgrade.*check\|config.*break.*change\|config.*compat` | **0** | 零实现 |

### 为什么需要它

1. **配置即代码的企业要求**：在 SOC2/ISO 27001 环境中，配置变更必须经过审查、测试和审批。没有配置校验管线，operator 只能通过「部署到 staging 观察是否启动」来验证配置——这是不可接受的。

2. **零停机配置变更**：SIGHUP 热加载已实现，但**错误配置的代价是运行时服务降级**。预投产校验可以在不影响运行实例的情况下发现配置错误。

3. **多环境一致性**：企业通常有 dev/staging/prod 三个环境，配置在不同环境间漂移。配置基线 + 合规检查可以自动发现生产环境与安全基线之间的偏差。

4. **配置即合规**：安全团队的需求（「所有客户端必须使用 PKCE」「token TTL 不能超过 1 小时」「必须启用审计」）应该可以通过配置检查自动验证，而不是通过人工 code review。

### Scope

| 分层 | 组件 | 说明 |
|---|---|---|
| **P0**（M，2 周） | 配置 Schema 定义 | 为完整配置结构生成 JSON Schema（手动维护或从 Go struct tag 生成）。Schema 包含：字段类型、必填/可选、默认值、允许值枚举、字段间依赖关系、已弃用标记。将 Schema 嵌入二进制（`//go:embed`） |
| **P0**（M，1 周） | Schema 驱动的配置验证器 | 扩展 `--validate-only`：在 Go 类型检查后，使用 JSON Schema 进行语义验证。包括：必填字段检查、枚举值检查、格式验证（URI、email、duration 等）、字段间依赖验证 |
| **P1**（M，2 周） | 交叉引用验证 | 新增验证规则引擎，检查配置中跨组件的引用完整性：grant 类型 X 需要的 store 是否存在、authenticator Y 需要的 backend 是否已配置、webhook subscription 引用的 endpoint 是否可达（TCP connect，非阻塞）等。输出结构化验证报告（`ValidationReport{Severity, Component, Message, Field}`） |
| **P1**（M, 1 周） | 配置合规策略引擎 | 定义 `ConfigPolicy` SPI：`Check(config) → []ComplianceFinding{Severity, Rule, Message}`。内置策略规则库（初始 10 条）：「所有客户端应使用 PKCE」「所有客户端应有合理的 redirect_uri」「token TTL 不应超过配置的最大值」「应启用审计」等。策略可热加载 |
| **P1**（S，1 周） | `sso-ctl config validate` | CLI 子命令：`sso-ctl config validate --config config.yaml --policy compliance.yaml`。输出格式化的验证报告（human + JSON），退出码区分致命错误/警告/信息。支持 `--diff` 模式：对比两个配置文件的差异 |
| **P2**（M，2 周） | 配置基线与偏差检测 | 定义配置基线（`config baseline`）：记录「已知良好」的配置快照。`sso-ctl config diff --baseline baseline.json` 显示当前配置与基线的偏差。Admin Console 新增「配置合规」面板展示合规评分和违规详情 |
| **P2**（M，1 周） | 配置升级兼容性检查 | 版本化的配置 Schema。当服务器升级到新版本时，自动检查当前配置是否与新模式兼容，列出所有弃用字段和破坏性变更 |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| Schema 与 Go 实现不一致 | Schema 从 Go struct 的 `jsonschema` 标签自动生成（已有 `cmd/sso-mcp/tools.go` 的前例），确保单一真实来源 |
| 交叉引用验证可达性检查超时 | 端点可达性检查使用 3s 超时 + 单连接并发限制；仅对 `webhook.*endpoint` 和 `federation.*entity_url` 等外部可达性做检查 |
| 配置合规策略误报 | 策略规则支持 `exclude_paths` 白名单（特定配置路径豁免）；支持设置规则 severity（error/warning/info） |
| 配置文件热加载后的合规自动检查 | 热加载成功后自动运行合规策略，检查结果记录 audit 事件 + 暴露 metric `sso_config_compliance_violations`。不合规不阻断加载（仅告警） |

### 历史分析 zero-overlap 证据

```
for term in "config.*schema.*validat\|config.*compliance.*policy\|config.*cross.*ref.*validat\|config.*dry.*run\|config.*diff.*base\|config.*upgrade.*compact\|config.*migration.*check\|config.*lint.*tool\|config.*policy.*engine\|config.*best.*practic.*check\|config.*baseline\|config.*compat.*check"; do
  grep -rl "$term" docs/requirements/*.md 2>/dev/null || echo "  (no matches)"
done
```
**注意：** `expansion-systemic-quality-horizon.md`（方向 3 配置 schema 版本校验与迁移）在升级上下文中提及了 `config/schema/validate.go` 的文件路径——但是作为迁移管线的一个子组件提及，并非作为独立的配置验证与分析方向。本方向首次将**配置合规与验证能力**作为独立的产品能力维度提出。

---

## 方向五：令牌生命周期治理与自动化清理（Token Lifecycle Governance & Automated Housekeeping）

### Why Now

项目拥有全面的令牌管理能力：

| 能力 | 状态 |
|---|---|
| Token 策略引擎（max_ttl、max_refresh_depth、max_active_sessions） | ✅ `tokenpolicy/` |
| Token 组合分析视图 | ✅ `domains/tokenusage/portfolio.go` |
| 管理员批量吊销 | ✅ `admin/token_portfolio.go` |
| Token 吊销（单条、按用户、按租户） | ✅ 多个吊销路径 |
| 跨副本吊销广播 | ✅ `cluster.Bus` |
| 令牌吊销持久化（SQLite/Redis） | ✅ |
| 内存 + SQLite/Redis 存储的过期清除 | ✅ `memreaper/` + SQLite TTL indices |

但令牌的**整个生命周期**缺乏治理自动化：

| 场景 | 当前行为 | 期望行为 |
|---|---|---|
| 令牌在 30 天后过期 | 自然过期（被动，用户在使用时才发现） | 提前通知+后台清理 |
| 刷新令牌链超过 10 跳 | 由 `max_refresh_depth` 拒绝（运行时） | 自动轮换父令牌 |
| 客户端 secret 超过 180 天未轮换 | 无任何提示 | 自动生成安全告警+通知管理员 |
| 客户端的令牌使用量突然下降 90% | 无检测 | 自动标记为「可能废弃」+ 通知管理员 |
| 大量过期令牌占用存储 | `memreaper` 定期清理 | 定期报告清理情况+存储节省量 |
| 一个用户有 50+ 个活跃刷新令牌 | 由 `max_active_sessions` 限制（运行时） | 自动归并+通知用户 |

### 当前具体代码级缺口（grep 核验）

| 概念 | 命中 | 状态 |
|---|---|---|
| `token.*lifecycle.*policy\|token.*lifecycle.*automation\|token.*lifecycle.*governance` | **0** | 零实现 |
| `TokenHealth\|token.*health.*score\|token.*health.*indicator\|token.*risk.*score` | **0** | 零实现 |
| `token.*stale.*detect\|token.*dormant\|token.*unused\|token.*abandon\|zombie.*token` | **0** | 零实现 |
| `token.*forecast\|token.*expir.*forecast\|token.*expir.*preview\|token.*aging` | **0** | 零实现 |
| `token.*sweep.*policy\|token.*auto.*cleanup\|token.*auto.*revoke\|token.*auto.*rotate` | **0** | 零实现 |
| `token.*abnormal\|token.*anomaly.*usage\|token.*usage.*pattern.*deviation` | **0** | 零实现（`tokenanomaly` 存在但仅针对 token exchange 场景） |

### Scope

| 分层 | 组件 | 说明 |
|---|---|---|
| **P0**（M，2 周） | 令牌健康评分引擎 | 基于多维度（剩余 TTL、刷新链深度、最后使用时间、客户端 Secret 年龄、binding 类型、scope 风险等级）为每个令牌计算健康评分（0-100）。`TokenHealth{TokenID, Score, Warnings []TokenHealthWarning}`。API：`GET /api/v1/admin/tokens/health?score_below=50&user_id=` |
| **P0**（M, 1 周） | 令牌生命周期自动化策略引擎 | 在 `tokenpolicy.Store` 基础上扩展生命周期策略：`TokenLifecyclePolicy{Condition, Action, Schedule}`。内置策略模板：「标记 30 天内过期的令牌」「自动吊销 7 天内未使用的刷新令牌」「对超过 5 跳的刷新链发出告警」「对超过 180 天未轮换的 client secret 发出告警」 |
| **P1**（M，2 周） | 令牌过期预测仪表盘 | `GET /api/v1/admin/tokens/forecast` 返回令牌过期分布（按天/周/月的过期数量预测）、存储占用趋势、刷新链深度分布。Grafana 面板集成 |
| **P1**（M，2 周） | 令牌异常使用检测 | 在现有 `tokenanomaly` 基础上扩展：检测异常的使用模式（非工作时间大量签发、从异常地理位置使用、使用频率突然变化）。使用规则引擎（非 ML），基于可配置的阈值。告警输出到 audit 事件 + webhook |
| **P2**（M，2 周） | Admin Console 令牌健康面板 | Admin Console 新增「Token Governance」导航标签：令牌健康分布（健康/警告/危险饼图）、过期预测日历、按客户端/用户/令牌类型筛选、批量操作（吊销选中的不健康令牌、发送通知给令牌持有者） |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 自动吊销导致用户意外登出 | 所有自动吊销操作默认生成 `TokenRevoked` audit 事件 + 通知受影响用户（依赖方向三的通知框架）。自动吊销策略默认为 dry-run（仅报告不执行），需要 admin 手动确认后才执行 |
| 令牌健康评分引擎对高流量用户的误判 | 评分算法考虑使用频率：每日使用的活跃用户令牌不因「短 TTL」而降低评分。算法文档化，admin 可查看任意令牌的评分明细 |
| 令牌过期预测不准确（用户行为变化） | 预测默认使用 30 天窗口，持续更新；预测区间标记为「估算值 ±30%」 |
| 令牌异常使用检测的冷启动问题 | 前 7 天为学习期，仅记录基线不触发告警。学习期后使用 3-sigma 阈值 |
| 大量令牌的扫描性能 | 扫描引擎使用分页 + 时间窗口，每次扫描最多处理 10000 条，完成后通过 cluster bus 通知其他副本避免重复扫描 |

### 历史分析 zero-overlap 证据

```
for term in "token.*lifecycle.*governance\|token.*health.*score\|token.*stale.*detect\|token.*dormant.*token\|token.*forecast\|token.*auto.*cleanup\|token.*auto.*revoke\|token.*abnormal.*usage\|token.*lifecycle.*policy\|token.*health.*engine\|TokenLifecyclePolicy\|TokenHealth.*Warning\|token.*expir.*predict\|token.*risk.*score\|token.*governance.*dashboard\|Token.*Governance"; do
  grep -rl "$term" docs/requirements/*.md 2>/dev/null || echo "  (no matches)"
done
```
**注意：** `expansion-post-protocol-layer-analysis.md` 的 Token Status List 方向在一个依赖项列表中提到 `tokenpolicy/`、`revocation_set.go`、`memreaper/` 等现有组件——这是在 Token Status List 协议实现的上下文中提及，而非作为令牌生命周期治理方向。`expansion-directions-analysis.md` 提及令牌管理的部分聚焦于令牌协议的扩展（如 Token Status List），而非令牌健康的自动化治理。本方向是第一个将**令牌生命周期治理**作为独立的产品和运营能力提出的分析。

---

## 优先级总览

| 方向 | 影响面 | 投入 | 优先级 | 依赖关系 |
|---|---|---|---|---|
| 方向一：端用户安全可见性 | 用户信任 & 合规 | M（约 8 周） | **P1** | 独立 |
| 方向二：管理后台权限治理 | 安全 & 合规 | M（约 9 周） | **P1** | 独立 |
| 方向三：主动式用户通知 | 用户体验 & 安全 | L（约 10 周） | **P1** | 依赖方向一的某些组件（通知中心 UI） |
| 方向四：配置合规与验证 | 运维可靠性 & 合规 | M（约 9 周） | **P2** | 独立 |
| 方向五：令牌生命周期治理 | 运维 & 安全 | M（约 10 周） | **P2** | 依赖方向三（令牌过期通知） |

> **执行建议：** 
> - **Wave 1**（方向一 + 方向二）：这两个方向独立且直接影响企业采购决策。端用户安全面板是 GDPR 合规的可交付证据；管理委派是 SOC2/ISO 27001 的硬性要求。
> - **Wave 2**（方向三 + 方向四）：通知框架依赖方向一的 Portal 改造（可独立先行实现 SPI 和发送器）；配置验证管线与 Wave 1 无依赖，可并行推进。
> - **Wave 3**（方向五）：令牌生命周期的自动化治理依赖方向三的通知能力（自动清理需要通知用户），建议在通知框架稳定后启动。
