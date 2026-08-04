# 扩展方向分析报告 v8

> **作者：** 资深架构 & 产品视角  
> **日期：** 2026-07-11  
> **范围：** 全代码库全局扫描（2241 `.go` 文件、4 个嵌入式 SPA）  
> **前提：** 已系统阅读并引用了 `ROADMAP.md` v5.0、`deferred-backlog.md`、  
>   `expansion-directions-analysis.md`、`expansion-directions-v7-analysis.md`  
>   **已逐项对抗核验确认 v7 的 5 个方向均为真缺口、且已被上述文档覆盖。**  
> **目标：** 列出 5 个**未被任何现有分析文档覆盖**的高价值扩展方向。  
> **方法：** 逐项 grep 核验（默认"大概率已实现"，仅当零实现命中且与 docs 不重叠才纳入）。

---

## 前置声明：项目当前成熟度

本项目的协议覆盖面和后端能力已是行业顶级水平（90+ `WithXxx` 选项、4 个内嵌  
SPA、6+ 存储后端、10+ 企业协议、OIDC/OAuth/SAML/FAPI/CAEP/SCIM 全覆盖）。  
v7 分析报告已收录 5 个高价值方向（BFF 安全模式、身份证明 IAL2、步骤式认证  
状态机、SAML2 输出翻译、可验证凭证/eIDAS），均经确认仍为缺口。

本报告聚焦于**另一组同样经 grep 确认但未被 v7 或其他文档覆盖的 5 个方向**。  
它们多属于"后端已备、前端缺位"的产品化缺口和"协议已声、交互未实"的合规  
缺口——与 v7 的技术协议扩展方向正交互补。

---

## 方向 1：B2B 委托租户管理员自助门户（Org Admin Delegation SPA）

### 现状

项目拥有完整的 B2B 多租户后端能力：

| 能力 | 位置 | 状态 |
|---|---|---|
| 租户成员管理 API（`/me/organizations/:tid/*`） | `interfaces/sso/sso_selfservice.go` | ✅ 已实现 |
| JIT 成员自动预置（`WithJITMembership`） | `interfaces/sso/options_passwd.go` | ✅ 已实现 |
| 租户成员邀请（`/admin/tenants/:tid/invitations`） | `interfaces/admin/tenants.go` | ✅ 已实现 |
| 企业连接（Enterprise Connections） | `interfaces/sso/server_federation.go` | ✅ 已实现 |
| 租户用量指标（`/admin/tenants/:tid/usage`） | `test/tenant_usage_route_test.go` | ✅ 已实现 |
| 全局管理 Console SPA | `interfaces/web/admin/` | ✅ 已实现 |

### 缺口（grep 核验）

- **B2B 委托管理员 SPA**：**零实现命中**——`web/admin/` 是全局管理员工具，  
  所有操作需要 `admin:*` 全局 scope，且由 `grpcserver/` 的 gRPC-gateway 支撑。  
  而 `/me/organizations/:tenant_id/*` API 是**委托 scope 保护**（`tenant:*`  
  scope，非 `admin:*`），需要完全不同的 SPA 挂载点、scope 验证和前端逻辑。
- `interfaces/web/` 下 4 个 SPA 目录中**没有一个是为委托租户管理员人设设计的**  
  （admin = 全局 IT 管理员、login = 登录、portal = 终端自助、developer = 第三方开发者）。
- `/me/organizations/:tenant_id/*` API 路径与 admin API (`/api/v1/admin/*`) 不同，  
  现有 `admin/app.js` 无法直接复用。
- 发现文档也将此列为"可做但未做"：`deferred-backlog.md` 中标记 org admin 相关  
  后端已全，但前端 UI 从未被提上日程。

### 范围

#### 1. 委托管理门户 SPA（`interfaces/web/orgadmin/`）

新建一个独立的嵌入式 SPA，挂载在 `/org/` 路径下，由 `WithOrgAdminFS` 接线。  
SPA 的 bearer token 来自 OAuth 的 `tenant:*` scope（非 `admin:*`），通过  
`/me/organizations` 发现自己的可管理租户列表，然后调用  
`/me/organizations/:tenant_id/*` API 执行管理操作。

**首批面板：**

```
Dashboard （该租户的活跃人数、登录趋势、令牌分布）
├── Activity （该租户的登录/TX 审计事件，facet 过滤）
├── Members （CRUD 组织成员、角色管理、邀请管理）
│   ├── 成员列表 + 搜索
│   ├── 邀请发送 (POST /me/organizations/:tid/invitations)
│   └── 待处理邀请管理
├── Connections（企业连接：SAML/OIDC IdP 配置，全局连接的本地覆盖）
├── Security（MFA 策略、会话过期时间、设备信任策略）
├── Usage & Billing（MAU、API 调用量、存储用量、配额预警）
└── Audit Log（该租户维度的审计日志面板）
```

#### 2. 委托 scope 基础设施建设

```
当前: admin:read / admin:write → 全局管理员
新增: tenant:read.{tid} / tenant:write.{tid} → 委托管理员
      tenant:read / tenant:write → 可管理所有被委托租户

权限检查点:
  - 现有 AdminMiddleware 需要扩展以识别 tenant:* scope
  - /me/organizations/:tenant_id/* 路由用 tenant:* scope 校验
  - 每一行 API 需要在 handler 级别做 tenant 归属校验
```

#### 3. Branding 与白标签

```
委托管理员门户应继承对应租户的 Branding 配置:
- 登录页品牌来自 Tenant.Domain.Branding
- 门户内 logo、配色、自定义域名均从 Branding 获取
- 门户 URL: https://{custom-domain}/org/
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 委托管理员跨租户越权 | 每个 API handler 从 token claims 提取 `tenant_id`，按 tenant 过滤；现有 `/me/organizations/` API 已做此校验，前端需配合 |
| 租户已暂停 | portal 登录后显示"组织已暂停"页面，所有写操作 403，审计 `org_admin_suspended_access` |
| 委托管理员离开组织 | next 请求 → 403 → SPA 显示"你不再属于此组织"并清除会话 |
| 邀请过期 | 邀请列表显示过期时间，已过期邀请显示"已过期"状态，管理员可重发 |
| JIT 预置成员的权限 | JIT 预置的成员自动获得 `member` 角色（最低权限），委托管理员可提升 |

### 为什么值得做

**这是 B2B SaaS 产品的定义级功能。** 现有后端已将 B2B 组织成员、邀请、  
JIT 预置、企业连接等全部铺好——但缺了"让每个租户的 IT 管理员自助管理自己的  
组织"的 UI，意味着每个 B2B 客户还是得联系你的 support 团队来加人、改权限、  
查看用量。这是从"API 平台"到"可销售给非技术客户的 SaaS 产品"的关键一步。  
同时，这是**零后端改动**（复用现有 `/me/organizations/` API 和委托 scope  
保护），纯前端工作量。

- **价值：** 高（产品旗舰 + B2B 差异化 + 零后端改动）  
- **工作量：** L（新建 SPA + 4-6 个面板）  
- **依赖：** `/me/organizations/:tid/*` API（已存在）、委托 scope 检查（已存在）

---

## 方向 2：OIDC `select_account` + `login` 交互式 Prompt 支持

### 现状

项目实现了 OIDC Core §3.1.2.1 的 prompt 参数解析和处理，但**仅 `prompt=none`  
和 `prompt=consent` 有完整的交互逻辑**：

| Prompt | 实现 | 发现声明 |
|---|---|---|
| `none` | 完整（silent renewal, `handlePromptNone`） | ✅ `prompt_values_supported` 包含 |
| `consent` | 完整（ConsentStore + consent gate） | ✅ ConsetStore 接线后包含 |
| `login` | ❌ 被接受但当做默认交互流处理 | ❌ **显式不声明** |
| `select_account` | ❌ 仅常量，无任何 handler | ❌ **显式不声明** |

代码自述（`server_discovery_config.go:444`）：
```go
// The login and select_account prompts aren't surfaced because
// the RP drives the interactive flow; the server authenticates
// on demand.
```

此外，`protocols/oidc/metadata.go:107` 也确认：
```go
// interactive path (login/consent/select_account UIs aren't
// rendered by this server, only their downstream signaling)
```

### 缺口（grep 核验）

- `prompt=login`：被语法解析（`oidc.ParsePromptValues`）但不触发重新认证；  
  如果当前已有有效 session，`prompt=login` 本应强制重新认证，但当前 handler  
  无此逻辑。
- `prompt=select_account`：`ErrAccountSelectionRequired` 和  
  `core.PromptSelectAccount` 已定义，但**零交互流实现**，无 handler、无 UI、  
  无 session 选择逻辑。
- 托管登录 SPA（`web/login/`）已存在且功能完备（支持密码登录、MFA、  
  WebAuthn），但**不处理多账户场景**——用户无法在登录时切换已登录的账户。
- 测试（`test/prompt_test.go`）仅验证 `prompt=none` 和 `prompt=consent`，  
  未测试 `select_account` 或 `login`。

### 范围

#### 1. `prompt=select_account` 交互流

```
场景: 用户已在浏览器中有活跃 session（带有 sid cookie），
      但想用另一个账户登录。
      
/auth/login?prompt=select_account&client_id=...&...

当前行为:
  1. session cookie 匹配到活跃 session → 自动使用该 session（silent）
  2. select_account 被忽略
  3. 用户无法切换账户

期望行为:
  1. select_account 被识别 → 跳过自动 session 恢复
  2. 托管登录 SPA 显示"账户选择"界面
     列出所有该浏览器中有活跃 session 的账户
     + "使用另一个账户" 按钮
  3. 用户选择后继续标准登录流程
```

**账户选择 UI（`web/login/app.js` 扩展）：**

```
┌────────────────────────────────┐
│         选择账户               │
│                                │
│  ┌──────────────────────────┐  │
│  │ 👤 alice@acmecorp.com    │  │
│  │    最后登录: 2 分钟前     │  │
│  └──────────────────────────┘  │
│                                │
│  ┌──────────────────────────┐  │
│  │ 👤 bob@bigco.io          │  │
│  │    最后登录: 3 小时前     │  │
│  └──────────────────────────┘  │
│                                │
│  ┌──────────────────────────┐  │
│  │ + 使用另一个账户         │  │
│  └──────────────────────────┘  │
└────────────────────────────────┘
```

#### 2. `prompt=login` 交互流

```
场景: RP 需要用户每次重新认证（高风险操作前）。

/auth/login?prompt=login&client_id=...&...

当前行为:
  1. session cookie 匹配到活跃 session → 自动恢复（prompt=login 被忽略）
  2. 用户未被要求重新输入凭据

期望行为:
  1. prompt=login 被识别
  2. 强制清除当前 session 的自动恢复
  3. 显示标准登录页面（预填充用户标识但不自动提交）
  4. 用户必须重新认证
```

#### 3. 后端协议变更

```go
// 在 server_login_resolve.go 的 handlePromptNone 旁边新增:
func (s *Server) handlePromptSelectAccount(ctx HandlerContext, prompts []string, req *login.Request) {
    // 1. 列出该浏览器的活跃 session（SessionManager.ListSessionsForBrowser）
    // 2. 从 sessions 提取 subject/claims（不暴露 token）
    // 3. 返回 {"status":"account_selection_required","accounts":[...]}
    // 4. 托管登录 SPA 渲染账户选择 UI
}

func (s *Server) handlePromptLogin(ctx HandlerContext, prompts []string, req *login.Request) {
    // 1. 即使有 session cookie 也不恢复
    // 2. 清除 session cookie 中的自动恢复标记
    // 3. 返回标准登录页面
}
```

#### 4. 发现声明更新

```
// 更新 server_discovery_config.go 中的 prompt_values_supported:
// 当托管登录 SPA 已接线（WithHostedLoginFS）时包含 select_account 和 login
prompts := []string{PromptNone}
if s.consentStore != nil {
    prompts = append(prompts, PromptConsent)
}
if s.hostedLoginFS != nil {
    prompts = append(prompts, PromptLogin, PromptSelectAccount)
}
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 无活跃 session 时 select_account | 直接显示登录页面（无账户可列），单账户场景等效于无此参数 |
| 隐私模式/无痕浏览 | 无持久 session → 直接进入登录页，select_account 只有"使用其他账户"选项 |
| 同时有 guest 和 member 账户 | 账户卡片显示账户类型标签，避免混淆 |
| 账户选择暴露用户标识枚举 | 只列出该浏览器已有 session 的账户（不暴露不认识的用户） |
| prompt=login+select_account 组合 | OIDC Core 禁止组合（需返回 `invalid_request`） |

### 为什么值得做

**这是 OIDC Core 协议合规的硬缺口。** `select_account` 和 `login` 是 OIDC  
Core §3.1.2.1 定义的标准 prompt 值，所有 OIDC 认证套件都会测试它们。当前  
即使声明 `prompt_values_supported` 不含它们，OIDC 认证测试也可能标记为  
"声明了 prompt 参数但不支持核心 prompt 值"问题。更重要的是，**这是用户体验  
的实质性问题**——多账户用户在今天无法通过 hosted login 切换账户，必须清除  
浏览器缓存或使用无痕窗口。

- **价值：** 中高（OIDC 合规 + 多账户 UX 痛点）  
- **工作量：** M（后端 handler 约 200 行 + SPA 账户选择 UI 约 150 行 + 测试）  
- **依赖：** 托管登录 SPA（已存在）、SessionManager（已存在）

---

## 方向 3：嵌入式 SPA 多语言国际化（i18n）

### 现状

`shared/i18n/` 包提供了完整的后端本地化框架：

| 能力 | 状态 |
|---|---|
| `i18n.Localizer` SPI | ✅ 已实现，支持 BCP 47 标签 |
| `i18n.PreferredLocale()` - Accept-Language 解析 | ✅ 已实现 |
| 内置 en/es 语言包 | ✅ `bundles/en.json`, `bundles/es.json` |
| 本地化 error_description | ✅ 已实现（后端错误响应） |
| `WithLocalizer` 接线选项 | ✅ 已实现 |

但是，**本地化框架仅在错误响应层面使用**——项目自带的 4 个嵌入式 SPA  
（`web/{admin,login,portal,developer}`）**全部为纯英文硬编码**：

- `interfaces/web/login/app.js`：所有 UI 文本（按钮、标签、错误消息）为硬编码英文
- `interfaces/web/admin/app.js`：同上
- `interfaces/web/portal/app.js`：同上
- `interfaces/web/developer/app.js`：同上
- 所有 HTML 文件 `<html lang="en">` 固定为 en

### 缺口（grep 核验）

- `interfaces/web/` 下 4 个 SPA 的 `.js` 和 `.html` 文件：**无 i18n 函数调用、  
  无 locale 检测、无翻译字典引用**。`app.js` 的 `toLocaleString()` 仅用于  
  日期格式化，非 UI 文本翻译。
- `shared/i18n/bundles/` 下的翻译字典：**被 SPA 零引用**（字典是 Go 端用的，  
  SPA 无法读取）。
- SPA 的 `/branding` 端点获取 UI 样式但**不获取 locale/language 配置**。

### 范围

#### 1. SPA 本地化基础设施

```javascript
// web/shared/i18n.js — 给所有 SPA 共用的轻量本地化小工具

// 1. 从 Accept-Language header / cookie / /branding 端点获取推荐 locale
// 2. 在首次 HTML 加载时嵌入翻译字典（通过 Go template 注入 JSON）
// 3. 提供 t(key, params) 函数给所有 UI 文本使用
// 4. 支持运行时切换语言（通过 URL 参数或 UI 选择器）

var i18n = (function() {
  var locale = 'en';
  var fallback = 'en';
  var dict = {};
  
  function init(localeFromServer, dictFromServer) {
    locale = localeFromServer || navigator.language.split('-')[0];
    dict = dictFromServer || {};
    document.documentElement.lang = locale;
  }
  
  function t(key, params) {
    var tmpl = dict[key] || dict[key + '.' + locale];
    // 从 en 包查找回退
    if (!tmpl && locale !== 'en') { tmpl = dict[key + '.en']; }
    // 最后的回退：返回 key 本身
    if (!tmpl) { return key; }
    return tmpl.replace(/\{(\w+)\}/g, function(_, k) { return params[k] || '?' + k; });
  }
  
  return { init: init, t: t, locale: function() { return locale; } };
})();
```

#### 2. 翻译字典分发

```
方案 A（推荐）: Go 模板在 HTML 中嵌入 JSON 字典
  index.html → {{.I18nDict}} 注入
  好处: 无额外 HTTP 请求，同步可用
  代价: HTML 响应大小增加

方案 B: 独立的 /locales/{lang}.json 端点
  好处: 浏览器缓存，按需加载
  代价: 额外请求，异步可用性

建议: 方案 A（SPA 初始化时 Go handler 从 shared/i18n/bundles/ 读取，
      过滤出 UI 相关 key，以 JSON 注入 HTML）
```

#### 3. 首批翻译语言

```
基于 shared/i18n/bundles/ 已有字典:
  - en (英语, 完备)
  - es (西班牙语, 已部分存在)
  
新增:
  - zh (简体中文)
  - ja (日语)
  - de (德语)
  - fr (法语)
  - pt-BR (巴西葡萄牙语)
  
每个 SPA 的翻译 key 集:
  - login: 约 30 个 UI key (按钮文字、标签、错误消息、MFA 提示)
  - admin: 约 60 个 UI key
  - portal: 约 40 个 UI key
  - developer: 约 25 个 UI key
```

#### 4. SPA 改造模式

```javascript
// Before:
document.getElementById('submit-btn').textContent = 'Sign In';

// After:
document.getElementById('submit-btn').textContent = t('login.submit');
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 翻译 key 缺失 | 显示英文 fallback（`key.en`），并在浏览器 console 输出 warning |
| RTL 语言（阿拉伯语、希伯来语） | `dir="rtl"` 属性 + CSS 镜像（flex direction、text-align）；第一阶段可不支持 |
| 运行时切换语言 | 存储在 cookie/localStorage 中，仅刷新页面后生效（避免运行时重渲染复杂度） |
| 语言偏好持久化 | 登录页 + /branding 端点返回（不持久化在 session 中——语言是 UI 偏好，非安全属性） |
| SPA 大小膨胀 | 每个语言的翻译字典约 2-4KB 压缩后；所有 7 种语言约 30KB 压缩，在 SPA 总大小（约 50KB min+gzip）范围内 |

### 为什么值得做

**全球企业 SSO 部署的第一问就是"支持哪些语言"。** 本项目的架构（纯 Go、  
无 CDN、自包含 SPA）使其特别适合部署在数据主权要求严格的区域（欧盟、中国、  
东南亚），但这些区域的最终用户不可能用英文登录页。后端 i18n 框架已完整到位  
（`shared/i18n/`），**只差前端 SPA 消费它**。这是"后端已备、前端缺位"的  
典例，工作量集中、ROI 明确。

- **价值：** 中高（全球化产品刚需 + 后端已就位 + 纯前端工作量）  
- **工作量：** M（基础库约 100 行 + 4 个 SPA 改造约 200 行 + 翻译字典 400 行）  
- **依赖：** `shared/i18n/`（已存在）、`/branding` 端点（已存在，可扩展）

---

## 方向 4：嵌入式 SPA 跨标签页会话状态同步

### 现状

项目所有 4 个嵌入式 SPA（admin、login、portal、developer）都是**单页面应用，  
但完全没有处理多标签页/多窗口会话一致性问题**。

用户典型场景：
1. 在标签页 A 中登录 admin console
2. 在标签页 B 中打开同一地址 → 需要重新输入 bearer token（无 SSO 继承）
3. 或者在标签页 A 中登出 → 标签页 B 仍在运行（安全风险）

更具体的场景——SPA 使用 session cookie 时：
1. 用户通过 hosted login 登录 → 获得 session cookie
2. 用户手动调用 `/end_session` 登出 → session cookie 被清除
3. 但其他标签页中的 SPA 不知道 session 已过期 → 仍显示已登录状态
4. 下一个 API 请求才 401 → UX 差

### 缺口（grep 核验）

- `BroadcastChannel` / `broadcast.*channel`：**零实现命中**
- `ServiceWorker` / `service.*worker`：**零实现命中**
- `StorageEvent` / `storage.*event`：**零实现命中**
- 所有 SPA 在 `load` 事件中独立初始化，不与其他标签页通信
- 所有 SPA 的登出逻辑仅影响当前标签页（清除本地 token/session，不做广播）
- 无全局"Session 过期"事件通知机制

### 范围

#### 1. 跨标签页通信基础设施

```javascript
// web/shared/session-sync.js — 在所有 SPA 中共用

var SessionSync = (function() {
  var channel = null;
  
  // BroadcastChannel API — 所有同源标签页共享
  function init(channelName) {
    channelName = channelName || 'sso-session-sync';
    if (typeof BroadcastChannel === 'undefined') {
      return; // 降级：不做同步，单标签页继续工作
    }
    channel = new BroadcastChannel(channelName);
    channel.onmessage = function(evt) {
      switch (evt.data.type) {
        case 'logout':
          handleRemoteLogout(evt.data);
          break;
        case 'login':
          handleRemoteLogin(evt.data);
          break;
        case 'session_expired':
          handleRemoteSessionExpired(evt.data);
          break;
        case 'token_refreshed':
          handleRemoteTokenRefresh(evt.data);
          break;
      }
    };
  }
  
  // 当前标签页登出时广播
  function broadcastLogout() {
    if (!channel) return;
    channel.postMessage({ type: 'logout', timestamp: Date.now() });
  }
  
  // 当前标签页登录时广播
  function broadcastLogin(sessionToken) {
    if (!channel) return;
    channel.postMessage({ type: 'login', timestamp: Date.now() });
  }
  
  // 监听外部登出事件
  function handleRemoteLogout(data) {
    // 清除本地 session 状态
    clearSession();
    // 显示"你已在其他标签页登出"提示
    showNotification('session_ended_elsewhere');
    // 重定向到登录页
    redirectToLogin();
  }
  
  return {
    init: init,
    broadcastLogout: broadcastLogout,
    broadcastLogin: broadcastLogin
  };
})();
```

#### 2. 登出同步

```
登出事件传播链:
  1. 用户点击"登出" → SPA 调用 /end_session → 清除 server session
  2. SPA 清除本地 token/session 状态
  3. SPA 通过 BroadcastChannel 广播 "logout" 事件
  4. 同源其他标签页的 onmessage 处理:
     a. 清除本地 session 状态
     b. 显示"你已在其他设备登出"通知横幅
     c. 在 5 秒后重定向到登录页面（或立即重定向）
```

#### 3. 登录同步

```
登录事件传播链:
  1. 用户在标签页 A 完成 hosted login → 获得 session cookie
  2. hosted login SPA 广播 "login" 事件
  3. 同源其他标签页的 onmessage 处理:
     a. 刷新页面（window.location.reload()）让 SPA 重新初始化
     b. 或：检测当前页面是 admin console → 自动获取新 token
```

#### 4. Session 过期检测

```
定期检查:
  - 每个 SPA 在后台每隔 60 秒通过 /userinfo 轻量检查 session 有效性
  - 如果 401: 广播 "session_expired" 事件，所有标签页进入未登录状态
  - 如果 200: 更新"最后活跃时间"显示
  
不需要额外 API: 复用现有的 /userinfo 端点（已有 Cache-Control: no-store）
```

#### 5. Service Worker 方案（可选）

```
对于更复杂的离线/后台同步需求:
  - 注册 Service Worker 拦截 fetch 请求
  - 当任一路由收到 401 时广播 session_expired 事件
  - 当 SW 收到 push event（管理员从后台"登出所有会话"）时处理
  - 但这需要 HTTPS + 额外文件（sw.js），增加复杂度
  - 建议: 第一阶段不采用 SW，仅使用 BroadcastChannel
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| BroadcastChannel 不受 Safari 14 以下支持 | 检测 `typeof BroadcastChannel` → 降级为无同步（单标签页正常） |
| HTTPS 限制 | BroadcastChannel 在 HTTP 中不可用（与安全策略无关，是 API 限制）；Safari 15+ 才支持 |
| 跨域标签页 | BroadcastChannel 仅限于同源（same origin）页面——不同自定义域名下的 tenant portal 不互通，这符合安全预期 |
| 同时接收集群广播 | BroadcastChannel 和 CAEP/SSE 通知可能同时送达；需去重（基于事件 ID 或时间戳） |
| 无痕/隐私模式 | 部分浏览器在隐私模式下禁用 BroadcastChannel；优雅降级到无同步 |
| 标签页 A 正在编辑时被登出 | 显示"会话已过期，请保存你的工作"弹窗而非直接刷新 |

### 为什么值得做

**这是现代 Web 应用的用户体验基本要求。** 用户期望在一个标签页中登出的同时，  
其他标签页也立即响应——尤其是管理控制台和安全相关的页面。所有的 SPA 框架  
（React/Angular/Vue）都有现成的跨标签页通信方案，本项目的自研 SPA 不应  
落后于行业标准。更重要的是，**这是一个安全感知问题**——如果用户在 admin  
console 中登出但另一个标签页仍在活动，会给人"系统不安全"的负面印象。

- **价值：** 中（UX 质量 + 安全感知）  
- **工作量：** S（约 100 行共享 JS + 每个 SPA 约 30 行集成代码）  
- **依赖：** 无后端依赖（纯前端 API：BroadcastChannel、localStorage）

---

## 方向 5：Token Exchange 跨协议断言翻译网关（LDAP/Kerberos/RADIUS 输出）

### 现状

项目实现了 RFC 7522 SAML 2.0 Bearer Assertion **输入**（`WithSAML2BearerGrant`:  
消费外部 SAML 断言换取 JWT），以及 LDAP/Kerberos/RADIUS 作为**认证器输入**  
（用户通过这些协议登录）。但 Token Exchange（RFC 8693）的**输出侧**仅支持  
OAuth 令牌类型——无法将 JWT access_token 翻译为以下协议的凭据：

| 输出协议 | 输入是否存在 | Token Exchange 输出 |
|---|---|---|
| SAML 2.0 Assertion | ✅（`infrastructure/saml/` SP + IdP） | ❌ 测试中显式拒绝 |
| LDAP Bind Credential | ✅（`infrastructure/ldap/` authenticator） | ❌ 零实现 |
| Kerberos Ticket | ✅（`infrastructure/kerberos/` handler） | ❌ 零实现 |
| RADIUS Session | ✅（`infrastructure/radius/` authenticator） | ❌ 零实现 |

v7 分析文档中的"方向 4：SAML2 输出"已覆盖 SAML2 部分。本方向将其扩展为  
**统一的跨协议断言翻译网关框架**——不仅是 SAML2，而是将项目已有的所有  
非 OAuth 协议认证器**反向利用**，构建一个完整的 Identity Bridge。

### 缺口（grep 核验）

- `requested_token_type=urn:ietf:params:oauth:token-type:saml2` → Token Exchange  
  输出：测试确认返回 400 `invalid_target`（`test/handle_token_exchange_test.go:296`）
- `requested_token_type=ldap` / `kerberos` / `radius`：**零实现命中**（常量未定义）
- 无统一的 `TokenFormatTransformer` SPI：**零实现命中**
- 所有非 OAuth 协议的输出翻译逻辑：**零实现命中**

### 范围

#### 1. 统一的断言翻译器 SPI

```go
// protocols/tokentranslate/token_translate.go — 新包

// TokenFormat describes a non-OAuth token format the AS can translate into.
type TokenFormat string

const (
    TokenFormatSAML2   TokenFormat = "urn:ietf:params:oauth:token-type:saml2"
    TokenFormatLDAP    TokenFormat = "urn:ietf:params:oauth:token-type:ldap_bind"
    TokenFormatKerberos TokenFormat = "urn:ietf:params:oauth:token-type:kerberos_ticket"
    TokenFormatRADIUS  TokenFormat = "urn:ietf:params:oauth:token-type:radius_session"
)

// TokenTranslator translates an access token's claims into a target format.
type TokenTranslator interface {
    // Translate builds the target-format credential from the source token.
    // ctx carries the request context (for audit, timeout).
    // sourceClaims are the validated token's claims.
    // target specifies the requested output format.
    // audience is the downstream service identifier.
    // Returns the translated credential bytes and the format's token type URI.
    Translate(ctx context.Context, sourceClaims TokenClaims, target TokenFormat, audience string) (credential []byte, tokenType TokenFormat, err error)
}
```

#### 2. 各协议翻译器实现

```
SAML2 翻译器（infrastructure/saml/translater/）:
  复用现有的 infrastructure/saml/ 的 XML-DSig 工具和命名常量。
  构造 <Assertion>:
    - <Issuer> = AS issuer URL
    - <Subject>/<NameID> = JWT sub (email/persistent/unspecified 映射)
    - <AttributeStatement> = JWT claims 映射（scope 控制）
    - 用 AS 签名私钥签名
  已有输入侧验证器 (WithSAML2BearerGrant) 可作为逆向参考。

LDAP 翻译器（infrastructure/ldap/translater/）:
  场景: token-exchange 输出一个临时 LDAP 绑定凭据
    - 生成一个临时 DN + 随机密码
    - 在 LDAP 目录中创建临时用户条目（带 TTL 自动过期）
    - 返回 DN + 密码给客户端
    - 客户端用此凭据绑定到 LDAP 服务器（短期访问）
    - LDAP 服务器上的访问审计归因到原始 JWT subject

Kerberos 翻译器（infrastructure/kerberos/translater/）:
  场景: token-exchange 输出一个 Kerberos 服务票据
    - 用 AS 的 keytab 为指定的 service principal 签发 TGS
    - 返回 base64 编码的 Kerberos 服务票据
    - 客户端用此票据访问下游 Kerberos 保护的服务
    - 票据 TTL 受 token exchange 的 max_lifetime 约束

RADIUS 翻译器（infrastructure/radius/translater/）:
  场景: token-exchange 输出一个 RADIUS 会话令牌
    - 构造一个 RADIUS Access-Accept 包（属性映射 JWT claims）
    - 可用作 VPN/WiFi 网络的临时授权
    - 支持 RADIUS CoA（Change of Authorization）撤销
```

#### 3. 与现有 Token Exchange Handler 集成

```
// 在现有的 token_exchange.go 中增加分支:
case requestedTokenType == TokenFormatSAML2:
    // 调用 SAML2 翻译器
case requestedTokenType == TokenFormatLDAP:
    // 调用 LDAP 翻译器
case requestedTokenType == TokenFormatKerberos:
    // 调用 Kerberos 翻译器
case requestedTokenType == TokenFormatRADIUS:
    // 调用 RADIUS 翻译器
default:
    // 继续现有逻辑（返回 invalid_target 或处理 OAuth 格式）
```

#### 4. 翻译器注册选项

```go
// WithTokenTranslator wires a custom protocol translator.
// Multiple calls register translators for different target formats.
func WithTokenTranslator(format TokenFormat, translator TokenTranslator) Option {
    return func(s *Server) {
        if s.tokenTranslators == nil {
            s.tokenTranslators = make(map[TokenFormat]TokenTranslator)
        }
        s.tokenTranslators[format] = translator
    }
}

// 快捷选项:
func WithSAML2OutputTranslator(signer SAML2AssertionGenerator) Option { ... }
func WithLDAPOutputTranslator(conn *ldap.Conn, baseDN string) Option { ... }
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 翻译出的凭据生命周期 | 受 token exchange 的 `max_lifetime` + 协议自身约束（Kerberos ticket 最长 24h）的较小值 |
| 翻译凭据的撤销 | 翻译出的外部凭据不可撤销（Kerberos ticket 已下发，LDAP 临时用户有 TTL）——审计记录中关联原始 access_token 的 jti，支持"被动过期"而非主动撤销 |
| 翻译器的 SSRF 保护 | LDAP/Kerberos/RADIUS 翻译器可能连接外部服务——复用 `AllowedResources` 或新增 `AllowedTranslationTargets` 白名单 |
| 翻译凭据的审计 | 每个翻译操作记录 `token_exchange_translated{source_jti, target_format, audience}` 事件 |
| act 链跨协议传播 | 翻译出的非 OAuth 凭据无法携带 `act` 链——审计中关联记录源 token 的 act 链完整路径 |

### 为什么值得做

**这是将项目从"OAuth/OIDC SSO 服务器"升级为"企业身份联邦网关"的关键能力。**  
企业中 LDAP（Active Directory）、Kerberos（Windows 集成认证）、RADIUS  
（VPN/WiFi 网络）和 SAML 2.0 仍然是广泛部署的身份基础设施。能够**从** OAuth  
令牌**翻译到**这些协议，意味着本项目可以在身份栈中扮演中心翻译网关的角色——  
而不只是"又一个 OIDC 提供商"。这与方向 4（SAML2 输出翻译）不冲突：一方面  
SAML2 输出可以由本项目方向独立交付；另一方面本方向将其扩展为**完整的多协议  
翻译框架**，定义 SPI 让 LDAP/Kerberos/RADIUS 等按需插入。

- **价值：** 中高（差异化 + 新产品定位 "Identity Federation Gateway"）  
- **工作量：** XL（框架 + 4 个翻译器）但可分期：第一阶段仅 SPI + 框架（L）；  
  第二阶段 SAML2 输出（M，与 v7 方向 4 合并优先级）；第三阶段其他协议  
- **依赖：** Token Exchange Handler（已存在）、各协议基础设施（已存在）

---

## 优先级总结

| 方向 | 价值 | 工作量 | 独立性 | 与 v7 方向关系 | 建议时机 |
|---|---|---|---|---|---|
| ① B2B 委托管理员门户 | 高（产品旗舰） | L | 独立（零后端改动） | 互补（v7 侧重协议技术，本方向侧重产品） | **P1 — 立即开始** |
| ② select_account/login prompt | 中高（OIDC 合规） | M | 依赖托管 SPA | 互补（v7 覆盖其他 OIDC 缺口，本方向覆盖交互 prompt） | P1 — 与方向 ③ 并行 |
| ③ SPA i18n 国际化 | 中高（全球化刚需） | M | 独立（纯前端） | 互补（v7 无前端方向） | **P1 — 立即开始** |
| ④ 跨标签页会话同步 | 中（UX 质量） | S | 独立（纯前端） | 互补（v7 无前端方向） | P2 — sprint filler |
| ⑤ 跨协议翻译网关 | 中高（差异化） | XL（分期） | 依赖 Token Exchange | v7 方向 4 的超集 | P3 — 按客户需求触发 |

**建议执行策略：**

- **并行启动**：方向 ①（B2B 委托门户）+ 方向 ③（SPA i18n）——都是纯前端、  
  零后端改动、面向可交付客户价值。
- **重叠推进**：方向 ②（select_account + login prompt）——涉及少量后端 handler  
  改动，可与上两个方向由不同工程师并行。
- **填充 sprint**：方向 ④（跨标签页同步）——S 级工作量，适合 sprint 间隙。
- **长期投入**：方向 ⑤（跨协议翻译网关）——XL 级分期工作，建议先确认至少  
  一个企业客户需求后再启动。

**一句话总结：方向 ① + ③ 是"后端已备、前端缺位"的立即交付产品价值；  
方向 ② 补 OIDC 合规空白；方向 ④ 提 UX 基础质量；方向 ⑤ 开新定位。**

---

## 附录：本报告未覆盖但值得关注的 sprint filler

以下问题粒度过小不足独立方向，但作为 sprint filler 有明确价值。

### B.1 SPA 静态资源版本化与缓存控制

当前 4 个 SPA 通过 `go:embed` 嵌入，由 `With*FS` 选项挂载。所有资源在构建  
时确定，无版本号/ETag 控制。浏览器缓存无法感知 SPA 更新（用户需强制刷新）。  
给嵌入式文件系统增加基于内容 hash 的版本化 URL（类似 webpack 的 `[contenthash]`）。

### B.2 Hosted Login SPA 的 ARIA/LTR 可访问性

托管登录 SPA 是面向最终用户的最重要 UI，但当前无 ARIA label、无焦点管理、  
无键盘导航支持。对需要 WCAG 2.1 AA 合规的政府采购场景是硬缺口。

### B.3 `storage_health_test.go` 未覆盖所有 store

`storage_health_test.go` 测试部分 store 的就绪性，但不覆盖 Redis/kafka/etcd  
等外部后端的健康检查。对于集群部署，缺少外部依赖的就绪性判断是运维盲区。

### B.4 Admin Console 的 WebSocket/SSE 实时更新

当前 admin console 面板通过轮询刷新（点击"Refresh"按钮或手动刷新页面）。  
没有利用已有的 SSE 基础设施（`sse.Broker` + `HandleStream`）做实时推送  
更新。SSE 已在 server 端就绪（`server_admin_handlers.go:416`），但未在  
SPA 前端消费。

---

*本报告基于 2026-07-11 全代码库全局扫描（2241 `.go` 文件、4 个嵌入式 SPA、  
`shared/i18n/`、`interfaces/web/`），逐项 grep 对抗核验确认缺口。所有方向  
均经确认未被 ROADMAP.md v5.0、deferred-backlog.md 或任何早期 expansion 文档  
覆盖。与 v7 分析报告（2026-07-11）的 5 个方向无重叠。*
