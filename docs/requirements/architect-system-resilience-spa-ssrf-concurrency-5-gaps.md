# 扩展方向分析 —— 系统韧性、SPA 治理、出站保护与并发控制

> **视角：** 资深架构 & 产品经理  
> **日期：** 2026-07-11  
> **方法：** 全代码库全局扫描（2241 个 `.go` 文件、1114 个测试文件、2892 行前端代码、  
>   12 个嵌套模块、14 个 `go.mod`）。在系统阅读 ROADMAP v5.0、deferred-backlog、  
>   docs/requirements/ 下全部 22 轮历史扩展方向分析的基础上，对每项候选方向做  
>   **全代码库 grep 逐项核验 + 与全部历史分析文档的关键词交叉比对**，确保每项为  
>   **真实代码级缺口且与所有历史分析零重叠**。  
> **定位：** 本报告 5 个方向不属于"新增协议支持"、"补后端能力"、"生产硬化"、"产品面"、  
>   或"系统性质量纵深"——那些已经在之前 22 轮分析中反复覆盖并基本落地。  
>   本报告聚焦于 **身份系统作为一个分布式系统的隐含契约断裂**——即一个身份平台在  
>   同时扮演 IdP、SP、Federation Hub、Admin API Server、SPA Host 等多重角色时，  
>   那些被独立实现但从未被系统性地连接或保护的"隐形边界"。

---

## 前置声明：项目成熟度

经过 22 轮全局扫描 + 大量实现落地，本项目的能力覆盖面已达到行业顶级水平。  
以下领域已确认全部覆盖，**本报告不再重复分析**：

| 领域 | 覆盖状态 |
|---|---|
| **协议面**（OAuth 2.0 七种 grant + PAR + JAR + JARM + RAR, OIDC Core/Discovery/ Logout/BCL/FCL/CIBA/Form Post, SAML 2.0 SP+IdP, SCIM 2.0 双向, CAEP/SSF 双向, FAPI 2.0, OpenID Federation 1.0, LDAP, Kerberos, RADIUS, Transaction Token, Step-Up Auth, DPoP, mTLS, SPIFFE JWT-SVID） | ✅ 全部落地 |
| **存储面**（Memory, SQLite, Redis, etcd, PostgreSQL + 14 个嵌套子模块：KMS×5, SAML×4, LDAP, Kerberos, RADIUS, ext_authz, Kafka, MQTT, Vault Transit） | ✅ 全部落地 |
| **安全面**（Anti-enumeration、Oracle-leak、DPoP、mTLS、JWT-SVID、Workload Identity、Break-Glass、Per-tenant 签名隔离、区域数据驻留、FAPI 2.0、FIPS 140-3、会话信任衰减、Step-Up Auth） | ✅ 全部落地 |
| **产品面**（Hosted Login SPA、Admin Console SPA、Developer Portal SPA、User Portal `/me`、Consent Store memory/sqlite/redis、B2B Enterprise Connections + HRD、Org-admin self-service、API docs viewer、SDK 生成 TS + Python） | ✅ 全部落地 |
| **运维面**（DR framework snapshot/RPO/RTO、config hot-reload SIGHUP 7 feature gates、metrics/prometheus/grafana、audit hash-chain + OCSF/CEF/Syslog、pprof、k6 load test、chaos tests ×4、benchmark gate） | ✅ 全部落地 |
| **韧性面**（Coordinated Key Rotation、Leaderless Peer-Key Adoption、Cross-Replica Revocation、Circuit Breaker Framework、Active-Active、Upgrade Health/Canary、SLO Framework） | ✅ 已分析待落地 |
| **前沿面**（Post-Quantum Crypto、AI/ML Identity Analytics、CIAM/Social Login、Session Roaming、PAM、Developer API Key、Token Status List、FIDO2 Cross-Device、AI Agent Identity） | ✅ 已分析待落地 |

> **结论：项目的"做什么"已经在 22 轮分析中被深度覆盖。剩余的最高价值空间是在  
> "身份系统多重角色下的隐含契约断裂"——那些横切多个子系统、从未被系统性审视  
> 的连接点与边界。**  

---

## 方向 1：跨协议统一登出 —— Session Hub 的登出侧集成缺口

### 现状

项目拥有一个设计精良的跨协议会话协调器（`platform/lifecycle/sessionhub`）：

```go
// Coordinator creates links at login and terminates linked sessions at logout.
// It holds narrow SPIs for core sessions, OIDC BCL, and SAML SLO.
```

创建测的集成已完成：

- **OIDC 登录**：`server_helpers.go:377` 调用 `sessionHub.Link(rctx, gsid, ProtocolCore, sessionID, userID)`
- **SAML SP 登录**：`infrastructure/saml/saml.go:278` 通过 `Deps.SessionHub` 类似地注册链接
- 代码注释明确声明跨协议链接在执行（`server_helpers.go:368`）

但是，**登出侧的集成从未发生**：

| 注销路径 | 调用 Coordinator.Logout()？ | 证据 |
|---|---|---|
| `POST /logout`（`server_logout.go`） | **❌ 否** | 零 `sessionHub`/`Coordinator` 引用 |
| `GET /end_session`（`protocols/oidc/handle_end_session.go`） | **❌ 否** | 零 `sessionHub`/`Coordinator` 引用 |
| SAML IdP-initiated SLO | **❌ 否** | `infrastructure/saml/idp/` 有独立 SLO 逻辑 |

### 为什么这是一个缺口（grep 全代码库核验）

| 关键词 | 命中位置 | 结论 |
|---|---|---|
| `\.Logout\(` | `platform/lifecycle/sessionhub/coordinator.go:128` | **方法已存在但零调用方** |
| `Coordinator.*Logout\|sessionHub\.Logout\|Coordinator\.Logout` | **0（非测试代码）** | 无人调用 |
| `global_sid.*log\|global_sid.*dest\|log.*global_sid` | **0** | 登出路径不涉及 global_sid |

这意味着：

1. **一个通过 OIDC 登录、同时持有 SAML SP 会话的用户，通过 `/logout` 注销后，SAML SP 会话仍然存活**。攻击者只要持有未过期的 SAML session cookie，仍可访问下游 SP。

2. **SessionHub 的整个登出协调器是一个"只写不读"的对象**——它在登录时积累链接数据，但从未被消费。LinkStore 只增不减（无对应的 Delete 或 Get 调用），导致孤立的链接记录永久占用存储。

3. **这与代码注释的声称矛盾**：`server_helpers.go:368` 注释声称 sessionhub 用于 "terminates every linked leg"，但实际上登出路径完全不涉及 sessionhub。

### 修复范围

**SPI 层无变更**——`Coordinator.Logout` 方法接受 `(ctx, globalSID, userID)` 并依次调用 `CoreSessionTerminator.Destroy` → `OIDCLogoutTrigger.TriggerBackchannelLogout` → `SAMLLogoutTrigger.Fanout`。所有 SPIs 已经定义并已实现。

只需在以下两处各加约 5 行：

1. **`interfaces/sso/server_logout.go`**：在 `handleLogout` 的某处（捕获 global_sid 后）调用 `s.sessionHub.Logout(...)`
2. **`protocols/oidc/handle_end_session.go`**：对应用 `/end_session` 路径

**障碍：** global_sid 需要在登录或 session 创建时与 bearer token / session cookie 关联存储，以便在注销路径中重新获取。当前 `SessionManager` 的 Session 对象没有 `GlobalSID` 字段。

### 边界情况

| 场景 | 处理 |
|---|---|
| **SessionHub 未配置**（`nil`） | `Logout` 应为安全 no-op |
| **部分链接的记录已过期** | Coordinator 应逐一尝试每条链接，不会因为一条失败而中止全局注销 |
| **并发登出**（多标签页） | Session destroy 是幂等的（`DELETE RETURNING`）；`LinkStore.Delete` 也应是幂等的 |
| **SAML SLO 异步执行** | 设计上 Coordinator 是异步的最佳努力——不应阻塞 OIDC 登出响应 |

### 价值 · 工作量

| 维度 | 评估 |
|---|---|
| **安全影响** | 中等——SSO "一次登出即全部登出"是用户的基本安全预期，也是 SOC2/SOX 的控制项 |
| **改动量** | 小——~30 行改动（2 个调用点 + Session 模型增加 GlobalSID） |
| **与既有分析的差异** | ✅ **本报告独有**——22 轮分析从未提及 SessionHub 登出未集成的问题 |
| **是否影响向后兼容** | 否——所有现有行为 100% 不变，新集成是纯附加的 |

---

## 方向 2：前端 SPA 安全治理 —— 2892 行无防护的客户端代码

### 现状

项目已落地 4 个嵌入式 SPA（`interfaces/web/{admin,login,portal,developer}`），
共 2892 行手写原生 JS/CSS/HTML。在每轮扩展方向分析中，这些 SPAs 均被标记为
"✅ 全部落地"，但**从未有分析文档深入审视过它们的安全性、可测试性、可访问性或可维护性**。

### 具体缺口

#### 2.1 零前端测试（风险最高）

| SPA | JS 行数 | 测试文件数 |
|---|---|---|
| Admin Console | 1385 | **0** |
| Portal | 565 | **0** |
| Login | 694 | **0** |
| Developer | 248 | **0** |

**后果：** 任何对 Admin Console（CRUD client/tenant/user）的 JS 改动都只能在生产环境
或手动测试中验证。无回归保护，无 E2E 测试。考虑到 SPAs 直接操作管理 API（创建、删除、
更新 OAuth 客户端、租户、用户），一次无声的 JS bug 可能导致生产数据丢失或配置泄露。

#### 2.2 安全性盲点

| 问题 | 表现 | 严重性 |
|---|---|---|
| **Content-Security-Policy 无违规上报** | 服务端设置 CSP header 但未配置 `report-uri`/`report-to`。实际 CSP 违规无人知晓 | 中 |
| **无 SRI（Subresource Integrity）** | `embed.FS` 提供的静态资源无法被浏览器验证完整性——虽然服务端不会加载外部资源，但 CDN 或镜像部署可能改变文件内容 | 低（但违反行业最佳实践） |
| **Admin Console 使用 sessionStorage 存储 bearer token** | 同一源下的任何 XSS 或恶意脚本均可窃取 token。无 HttpOnly cookie 选项 | 中（已通过 CSP 缓解，但非消除） |
| **Login SPA 信任 URL 参数** | OAuth 参数（`redirect_uri`、`client_id`）直接从 `URLSearchParams` 读取和使用，无客户端侧验证 | 低（服务端会验证） |
| **Referrer-Policy 仅由服务端设置** | SPA 页面本身无 `<meta name="referrer">` 标签，服务端 header 可能被浏览器忽略 | 低 |

#### 2.3 可访问性（Accessibility / a11y）

全代码库仅发现 **1 处** 无障碍属性（`aria-hidden="true"` in `login/index.html:13`）。
无 `role` 属性、无 `tabindex` 治理、无键盘导航支持、无 ARIA live regions 用于
动态内容更新、无焦点管理（模态对话框打开时无焦点捕获）。这不仅是合规问题
（WCAG 2.1 AA 对公共采购是硬要求），也意味着屏幕阅读器和键盘用户无法使用
Admin Console 管理生产系统。

#### 2.4 构建管线与版本管理

- **无构建步骤**——JS/CSS/HTML 直接作为 `embed.FS` 原始文件服务
- **无压缩/混淆**——1385 行 Admin Console JS 以原始格式传输（含详细注释）
- **无静态分析**——HTML/CSS/JS 无 lint、无类型检查、无死代码检测
- **无缓存失效**——嵌入文件更新后，浏览器无法区分新旧版本（需硬刷新）

#### 2.5 国际化（i18n）

后端已有完整的 i18n 框架（`shared/i18n` + `WithLocalizer`），支持
`Accept-Language` 头部协商和备用语言。但 4 个 SPAs 全部使用硬编码英文文本。
登录页面的错误信息、MFA 操作说明、Consent 屏描述均无法翻译。

### 为什么需要它

1. **Admin Console 是管理门户**：如果因为 JS 错误导致 client CRUD 在某种浏览器
   上无声失败，运营团队无法管理生产配置。这是运维安全（OpsSec）的一部分。

2. **采购合规**：欧洲公共采购（EN 301 549）要求 WCAG 2.1 AA。美国政府（Section 508）
   要求无障碍。企业 RFP 中无障碍是一票否决项。

3. **DevOps 现代化**：4 个 SPA 的现状相当于"2010 年之前的 jQuery 式开发"。无 CI
   安全检查、无版本锁定、无自动化测试——这是整个项目中技术债务集中度最高的部分。

### 范围

| 分层 | 建议 | 工作量 |
|---|---|---|
| **P0 安全** | CSP report-uri/report-to 端点；关键操作的 XSS 审计；Service Worker 级别的安全策略 | 小（2-3 天） |
| **P0 测试** | Playwright/Cypress E2E 测试覆盖 Admin Console 的核心 CRUD 路径 | 中（1 周） |
| **P1 构建** | 引入轻量构建步骤（esbuild）：压缩、版本 hash、css minify | 小（2 天） |
| **P2 i18n** | SPA 侧 i18n 框架 + 中文/日文/德文 bundle 示例 | 中（1 周） |
| **P2 a11y** | 逐步完成 WCAG 2.1 AA 合规：键盘导航、ARIA 标签、焦点管理、颜色对比度 | 大（迭代多轮） |

### 价值 · 工作量

| 维度 | 评估 |
|---|---|
| **安全影响** | 中——SPA 安全边界是整套系统的攻击面入口；当前状况与后端的高安全标准不匹配 |
| **产品质量** | 高——4 个 SPAs 是用户（管理员/开发者/终端用户）看到的第一界面，质量直接影响采购评估 |
| **与既有分析的差异** | ✅ **本报告独有**——22 轮分析均将 4 个 SPA 标记为"已落地"，从未审计其代码质量 |
| **改动量** | 渐进式——可按 P0/P1/P2 分步迭代，不必一次性完成全部 |

---

## 方向 3：出站身份协议的 SSRF 统一防护框架

### 现状

项目日益扮演**双向身份角色**——不仅是 IdP（接受入站认证请求），也是 SP/Client
（发出出站 HTTP 请求到外部系统）。出站 HTTP 调用的数量持续增长：

| 出站调用 | 位置 | 现有 SSRF 防护 |
|---|---|---|
| Federation 信任链获取 | `domains/federation/fetch.go` | 有（`dialWithSSRFCheck`） |
| SAML 元数据刷新 | `infrastructure/saml/idp/metadata.go` | 仅 HTTPS 检查（`isHTTPSURL`） |
| Webhook 引擎投递 | `platform/lifecycle/webhook/engine_delivery.go` | URL 来自订阅（operator 配置） |
| CAEP/SSF 推送到 RP | `protocols/caep/broadcaster.go` | URL 来自 client 属性 |
| JAR 请求对象获取 | `shared/security/securityverify/jar_fetch.go` | `AllowedRequestURIs` 白名单 |
| OIDC Federation 认证 | `domains/authenticators/oidc_federation.go` | 无 |
| 邮件/SMS 发送 | `infrastructure/defaultimpl/emailsmtp/` | 无（SMTP 非 HTTP） |
| 推送通知 | `protocols/caep/broadcaster.go` | 部分检查 |

### 为什么这是一个缺口

1. **攻面聚集**：7+ 种出站 HTTP 调用散布在代码各处，各有不同的 URL 来源（上游声明、
   admin 配置、client 属性、operator 配置）。其中部分 URL 来源不受 operator 直接控制
   （如 federation 上游、JAR request_uri、CAEP 接收端点）。

2. **现有防护不统一**：SAML 路径有 HTTPS 门控、JAR 路径有白名单、但 Federation 路径
   无任何校验。攻击者若能在 federation 上游中注入恶意 URL，可诱导 SSO 服务器访问
   内部服务（如 `http://169.254.169.254/` 云元数据端点）。

3. **缺乏审计**：出站 HTTP 请求无统一审计跟踪——无法回答"本服务器在过去 24 小时内
   访问过哪些外部端点"。

### 具体缺口（grep 核验）

| 防护机制 | 代码命中 | SSRF 覆盖面 |
|---|---|---|
| `isHTTPSURL\|scheme == "https"\|MustHTTPS` | 仅在 `saml/idp/` 和 `saml/sp/` 存在（两处副本） | 仅覆盖 SAML |
| `AllowedRequestURIs\|allowedRequestURIs` | `server_login_gates.go` + JAR | 仅覆盖 JAR |
| `DialContext\|DialTLS\|net.Dialer\|net.Conn` 自定义 Dialer | `domains/federation/fetcher.go` | 仅覆盖 Federation（最佳实现） |
| `HTTPProxy\|NO_PROXY\|no_proxy` 配置 | **0** | 无法通过代理隔离内部网络 |
| `DNS.*resolver\|custom.*resolver\|ResolveIPAddr\|net.Resolver` 自定义 | **0**（所有调用使用系统 DNS） | 无法检测 DNS 重新绑定攻击 |
| 统一出站 HTTP 客户端工厂 | **0**（每个模块创建自己的 `http.Client`） | 超时、TLS 配置、重试策略不统一 |

### 建议范围

#### 1. 统一出站 HTTP 客户端（新增 `shared/outbound` 包）

```go
// OutboundClient is a hardened, audited HTTP client for server-originated
// requests. Every outbound identity-protocol call MUST use this client.
type OutboundClient struct {
    *http.Client
    // Mandatory URL validation before any request
    ValidateURL func(url *url.URL) error
}
```

- 强制 HTTPS（除非显式豁免，如 SMTP 或本地 dev）
- DNS 重新绑定防护（在 DNS 解析后验证 IP 地址是否变化）
- 内部 IP 地址拒绝（`10.x`、`172.16-31.x`、`192.168.x`、`169.254.x`、`127.x`）
- 默认超时（15s 连接 + 30s 总请求）
- 所有出站请求的审计事件

#### 2. URL 来源分级策略

| 来源 | 校验级别 | 例 |
|---|---|---|
| Operator 配置（`config.yaml`） | 仅 HTTPS + DNS rebind | Webhook 端点 |
| Client 属性（`Client.Attributes`） | HTTPS + 白名单 | CAEP 接收端点 |
| 上游声明（federation metadata） | HTTPS + 白名单 + 域后缀匹配 | Federation 获取 |

#### 3. 迁移路径

不破坏现有代码：保留现有 `http.Client` 用法，新增可选包装器。逐步迁移。

### 边界情况

- **本地开发**：需允许 `http://localhost` 和 `http://127.0.0.1` 豁免（需显式配置）
- **DNS 重新绑定窗口**：默认外发客户端应 DNS 解析后验证 IP 是否与预期一致
- **内部网络代理**：对于有 HTTP 代理的企业部署，SSRF 校验应在代理处理后进行
- **IPv6**：内部 IP 校验需覆盖 IPv6（`fc00::`、`fe80::`、`::1`）

### 价值 · 工作量

| 维度 | 评估 |
|---|---|
| **安全影响** | 高——SSRF 是 OWASP Top 10（A10:2021 SSRF），且云环境下的内部元数据端点风险极高 |
| **改动量** | 中——新增 `shared/outbound` 包 + 逐步迁移 7+ 调用点 |
| **与既有分析的差异** | ✅ **本报告独有**——22 轮分析未涉及出站身份协议的 SSRF 统一防护 |
| **是否影响向后兼容** | 最小——初始版本是可选包装器，不改变现有代码行为 |

---

## 方向 4：管理 API 丢失更新防护 —— 乐观并发控制

### 现状

Admin API（`/api/v1/admin/clients/*`、`/api/v1/admin/tenants/*`、
`/api/v1/admin/users/*`）的处理模式为**最后写入者获胜（Last-Writer-Wins, LWW）**：

- `PUT /api/v1/admin/clients/:id` 接受完整客户端对象并原地替换
- `PUT /api/v1/admin/tenants/:id` 类似替换整个租户配置
- `PUT /api/v1/admin/users/:id` 类似替换用户属性

**无资源版本号、无 ETag、无 `If-Match` 头部支持。**

### 具体场景

两个管理员同时编辑同一个 OAuth 客户端：

1. 管理员 A 获取客户端配置（`GET .../clients/abc`）→ `grant_types=["authorization_code","refresh_token"]`
2. 管理员 B 获取同一客户端配置 → 看到 `grant_types=["authorization_code","refresh_token"]`
3. 管理员 A 添加 `client_credentials` → `PUT .../clients/abc` 成功
4. 管理员 B 修改 `redirect_uris` → `PUT .../clients/abc` 成功，但**覆盖了管理员 A 刚添加的 `client_credentials`**

**结果：管理员 A 的变更被无声覆盖，无错误、无告警。**

这在单管理员的运维场景中可接受，但在企业级多管理员运维中，这是一个已知的
**丢失更新（Lost Update）** 安全场景。

### 为什么这是一个缺口

1. **行业标准已建立**：Auth0 Management API、Okta API 均支持资源版本号。
   IETF RFC 7232（HTTP Conditional Requests）定义了 `ETag`/`If-Match` 语义。

2. **与现有架构的对比**：项目已有完整的变更审批工作流（`admin/governance.go` 的
   `HandleAdminCreateChange`→`ApproveChange`），但那只覆盖**需审批的破坏性操作**
   （如删除租户）。日常的配置编辑（client/tenant/user）完全无保护。

3. **审计盲区**：即使审计日志记录了两次 PUT 请求，也无法在事后区分第二次 PUT
   是无意的覆盖还是恶意的回滚。

### 具体缺口（grep 核验）

| 能力 | 命中 | 分析 |
|---|---|---|
| `ETag\|etag`（admin API 响应中） | **0**（仅 `ssoclient/rs/` 的 JWKS 缓存使用 ETag） | Admin API 响应无资源版本标识 |
| `If-Match\|If-None-Match`（admin API 请求处理） | **0** | 请求无前置条件校验 |
| `ResourceVersion\|resource_version\|resourceVersion` | **0** | 存储模型中无版本字段 |
| `OptimisticLock\|optimistic.*lock\|version.*check.*update\|version.*conflict` | **0** | 乐观锁机制不存在 |

### 建议范围

#### SPI 层

在现有的 `ClientStore`、`TenantStore`、`UserStore` 接口中，为 Update 方法新增
可选的 `expectedVersion` 参数：

```go
// Current design (no version):
Update(ctx context.Context, client *Client) error

// Proposed (optional optimistic lock):
Update(ctx context.Context, client *Client, expectedVersion *int64) error
```

当 `expectedVersion != nil` 且与存储中的版本不匹配时，返回 `ErrVersionConflict`（HTTP 409）。

#### API 层

- `GET .../clients/:id` 响应头中增加 `ETag: "<version>"`
- `PUT .../clients/:id` 检查 `If-Match` 头部，与存储版本比较
- 不使用版本号的现有请求（无 `If-Match`）继续以 LWW 模式工作——**完全向后兼容**

#### 存储层

- Memory 存储：每个资源增加 `version int64` 字段，每次 Update 自增
- SQLite 存储：增加 `version INTEGER NOT NULL DEFAULT 1` 列；`UPDATE ... WHERE id=? AND version=?`

### 边界情况

| 场景 | 处理 |
|---|---|
| 新创建的资源（无版本号） | 不强制版本检查（创建时无需 `If-Match`） |
| `If-Match: *` | 通配符表示"资源必须存在但不检查版本号" |
| 版本号溢出（int64 max） | 理论上不可达（每毫秒更新一次需 2.9 亿年溢出） |
| 跨存储原子性 | 版本检查与 Update 必须在同一事务中执行 |

### 价值 · 工作量

| 维度 | 评估 |
|---|---|
| **数据完整性** | 中——丢失更新在企业多管理员场景中是真实风险 |
| **改动量** | 中——SPI 签名变更 + 3 个存储后端变更 + Admin API handler 变更 |
| **向后兼容** | ✅ 100%——不提版本号的旧请求继续以 LWW 模式工作 |
| **与既有分析的差异** | ✅ **本报告独有**——22 轮分析未谈及 Admin API 的并发控制 |
| **跨领域价值** | 高——版本号也是审计和变更回滚的基础设施 |

---

## 方向 5：分布式会话状态垃圾回收 —— SessionHub 链接生命周期管理

### 现状

`platform/lifecycle/sessionhub` 的 `LinkStore` 有以下设计特征：

```go
type LinkStore interface {
    // Set records one protocol-specific leg for a global_sid.
    Set(ctx context.Context, gsid GlobalSID, protocol Protocol, id, userID string) error
    // Get retrieves all legs for a global_sid.
    Get(ctx context.Context, gsid GlobalSID) ([]LinkRecord, error)
    // Delete removes ALL legs for a global_sid.
    Delete(ctx context.Context, gsid GlobalSID) error
}
```

**缺口：LinkStore 缺少 TTL 过期机制，且 `Set` 无对应的单条 Delete 方法。**

### 三个具体问题

#### 5.1 孤立链接永不回收

每次登录创建一条 `LinkRecord`。由于方向 1 所述的登出侧未集成，这些记录
**从未被删除**。当前没有后台清理机制。对于高活跃度的用户群体，LinkStore
（尤其是 Memory 实现）将无限增长。

#### 5.2 缺少单条 Delete

`Delete` 删除的是一个 `global_sid` 的全部链接。如果某条协议腿提前终止
（如用户手动从 SP 登出但未全局登出），没有方法移除该腿而不影响其他协议腿。

#### 5.3 无 TTI（Time-To-Idle）过期

用户的 Session 可能因不活跃而过期（`SessionManager` 支持 `maxAge`），但 LinkStore
的记录不会随 Session 过期而自动清理。这意味着 Session 已过期多时的用户仍有一条
"死链接"占用存储。

### 为什么需要它

1. **内存污染**：Memory `LinkStore` 在长期运行的服务器上会积累大量死链接。
   假设每用户每日登录一次、100K MAU，年累积量可达 3650 万条记录——足以导致
   显著的 GC 压力和内存占用。

2. **一致性缺口**：Session 过期（销毁）与 LinkRecord 删除是两个独立的操作，
   缺少协调意味着安全审计时 LinkStore 中可能存在"幽灵链接"（声称存在的
   session_id 实际已销毁）。

3. **规模化障碍**：SessionHub 的设计意图是跨协议登出协调器。在当前无回收的
   情况下，随着用户量和部署时间的增长，LinkStore 会成为 `sessionhub` 功能
   的规模化瓶颈。

### 具体缺口（grep 核验）

| 关键词 | 命中 | 结论 |
|---|---|---|
| `TTL\|ttl\|expir\|Expire\|expire.*link\|link.*expir` | `platform/lifecycle/sessionhub/linkstore.go` 中无任何 TTL 引用 | LinkStore 无过期机制 |
| `Reap\|reap\|prune\|Prune\|cleanup\|Cleanup\|sweep\|Sweep` | `sessionhub/linkstore.go` 中零实现 | 无后台清理 |
| `DeleteLeg\|deleteLeg\|delete.*protocol\|RemoveLeg` | **0** | 无单条删除方法 |
| `ListByUser\|listByUser\|GetByUser\|getByUser` | `sessionhub/linkstore.go` 中零实现 | 无法按用户查询所有链接 |

### 建议范围

#### 1. LinkStore 接口扩展

```go
type LinkStore interface {
    // 现有方法
    Set(ctx context.Context, gsid GlobalSID, protocol Protocol, id, userID string) error
    Get(ctx context.Context, gsid GlobalSID) ([]LinkRecord, error)
    Delete(ctx context.Context, gsid GlobalSID) error
    
    // 新增
    DeleteLeg(ctx context.Context, gsid GlobalSID, protocol Protocol) error
    ListByUser(ctx context.Context, userID string) ([]LinkRecord, error)
}
```

#### 2. TTL 过期

- 为 `LinkRecord` 增加 `expiresAt time.Time` 字段
- `Set` 时计算 `expiresAt`（基于 session 的 `maxAge` 或独立 TTL 配置）
- 后台周期性的清理（reaper goroutine）删除已过期的记录

#### 3. 集成 Session 过期事件

当 `SessionManager.Destroy` 被调用时（如管理员强制注销），通过 Bus 或回调
通知 SessionHub 清理对应的链接。这可以复用现有的 `cluster.KindTokenRevoked`
事件总线机制。

### 边界情况

| 场景 | 处理 |
|---|---|
| **TTL 太短** | `expiresAt` 按 user session 的实际最大生命周期计算（不是登录时刻固定值） |
| **并发清理与查询** | 清理 goroutine 与 Get/Set 之间需要免锁的过期标记（参考 `sync.Map` 的 `Range+Delete` 模式） |
| **跨副本一致性** | TTL 清理应在每个副本本地执行（无需广播）；`ListByUser` 应考虑过期记录的可见性 |
| **清理延迟** | 清理周期不应短于 1 分钟（避免高频率争用锁），TTL 过期后短时的可见性是可接受的 |

### 价值 · 工作量

| 维度 | 评估 |
|---|---|
| **规模化影响** | 中——LinkStore 无回收是长期运行的可扩展性风险 |
| **产品完整性** | 中——SessionHub 设计意图是跨协议协调器，但无回收机制意味着它不适合生产部署 |
| **改动量** | 小——接口扩增 + Memory/SQLite 实现 + reaper goroutine（约 150 行） |
| **与既有分析的差异** | ✅ **本报告独有**——22 轮分析均未涉及 LinkStore 的生命周期管理 |
| **与方向 1 的关系** | 互补——方向 1 解决入口（登出不调用 Logout），方向 5 解决出口（过期不清理）；两者都需要 |

---

## 优先级总结

| 优先级 | 方向 | 投入产出比 | 建议开始 |
|---|---|---|---|
| **P0** | 方向 1：跨协议统一登出 —— SessionHub 登出侧集成 | 6 分（安全影响 + 极小改动） | 立即 |
| **P0** | 方向 2：前端 SPA 安全治理 —— 测试 + 安全 + 构建管线 | 8 分（产品质量 + 安全基线） | 立即（可分批执行） |
| **P1** | 方向 3：出站身份协议 SSRF 统一防护框架 | 5 分（安全纵深 + 攻面缩小） | 与方向 4 并行 |
| **P1** | 方向 4：管理 API 乐观并发控制 —— 丢失更新防护 | 4 分（数据完整性 + 企业需求） | 与方向 3 并行 |
| **P2** | 方向 5：SessionHub 链接生命周期管理 —— TTL + 清理 | 3 分（可扩展性） | 方向和 1 之后 |

---

## 与历史分析的差异化声明

| 方向 | 相关历史分析 | 差异说明 |
|---|---|---|
| 方向 1 | 无 | SessionHub 在 deferred-backlog 中被列为"done"（登陆测集成），但登出侧从未被审计。22 轮分析均未涉及此缺口 |
| 方向 2 | 无 | 所有分析标记 4 个 SPAs 为 "✅ 全部落地"，但这是从功能存在性角度，非质量角度。本方向是首次对 SPA 代码质量做系统性审计 |
| 方向 3 | expansion-production-hardening-analysis（Circuit Breaker 方向） | 那篇分析聚焦通用 circuit breaker/bulkhead 模式。本方向聚焦身份协议特有的 SSRF 防护——URL 来源分级、DNS rebind 防护、内部网络检测——与 CB 正交 |
| 方向 4 | 无 | 22 轮分析未涉及 Admin API 的并发控制 |
| 方向 5 | 无 | SessionHub 的分析仅存在于 deferred-backlog 中的"done"条目。无分析涉及 LinkStore 生命周期管理 |

---

*本报告与 docs/requirements/ 下全部 22 轮历史分析文档做了关键词交叉验证，
确保每项方向为真实代码级缺口且零重叠。*
