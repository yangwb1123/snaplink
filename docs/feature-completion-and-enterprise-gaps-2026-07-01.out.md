现在我已经获取了所有证据。以下是逐条事实核查回复。

---

## 事实核查：对您的分析进行验证

感谢这份详尽且结构化的分析。我已经逐方向用代码库进行了验证。以下是我的发现——某些论断**非常准确**，但有几个关键点在事实层面上**不正确**。

---

### ✅ 方向一：密码策略——结论正确，证据充分

您说的完全正确。

| 论断 | 验证结果 |
|------|----------|
| `PasswordPolicyConfig` 无 YAML 配置 | ✅ **确认**。`grep -rn "password_policy" config/config*.go` 返回 0。已有 SPI 完美定义，但无配置节。 |
| 登录路径未检查密码策略 | ✅ **确认**。`authenticators/password.go` 中**零引用** `checkPasswordPolicy`。该函数仅在 `signup.go:121`、`password_reset.go:111` 和 `selfserviceaccount/security.go:48` 中调用。 |
| `MaxAgeDays` 从未被检查 | ✅ **确认**。`MaxAgeDays` 字段存在于 `spi.PasswordPolicyConfig`，但没有任何代码读取密码的 `updated_at` 与当前时间比较。 |
| 密码历史检查未使用 | ✅ **确认**。`PasswordHistoryStore` 已在 `stored_password.go:47` 定义，拥有 `MemoryPasswordHistoryStore` 实现，且接口已定义 `CheckHistory`，但 `checkPasswordPolicy` 只调用 `v.Validate(password)`——从不调用 `CheckHistory()`。需要一个额外的 SPI 方法如 `CheckPasswordHistory(userID, password)`，但从未被连接。 |

**仅有遗漏**：您提到 `checkPasswordPolicy` 仅在注册和密码重置中被调用，但**还有一个额外路径**——`selfserviceaccount/security.go:48`（`/me/password` 端点）。不过，这仍然不包括登录路径，所以您的主要观点仍然成立。

Gap 总结：**SPI 完美，配置层为空，登录路径为盲区。**

---

### ❌ 方向二：并发会话限制——**已存在功能，被标记为"完全缺失"**

这是您的分析中最大的事实错误。**并发会话限制已经存在且已集成。** 搜索词过于严格。

**实际状态：**

```
interfaces/sso/options_passwd.go:422:   func WithMaxSessionsPerUser(n int) Option {
interfaces/sso/server_logout.go:386-445: 全量实现
shared/core/spi.go:290:                   MaxSessions int `json:"max_sessions,omitempty"`
```

**证据：**
- `WithMaxSessionsPerUser(n)` 是暴露给 `sso.New()` 的公开 `Option`
- `createSession()` → `evictOldestSession()` 逻辑（`server_logout.go:395-445`）：
  1. 列出该用户在当前租户下的所有会话
  2. 若 `count >= limit`，找到最早创建的会话
  3. 销毁该最早会话（滚动淘汰），然后创建新会话
  4. **Fail-open**：列举/淘汰失败仅记日志，永不阻止登录
- 此外还有**租户级别配额**：`memory_quota.go:76` 在 `MaxSessions > 0` 时强制限制

**缺失部分**（您仍有部分正确）：此功能暂无 YAML 配置项——它仅支持编程式选项 `WithMaxSessionsPerUser`。应添加：

```yaml
server:
  session:
    max_concurrent_sessions: 5
```

但**声明"完全缺失"是不准确的**——运行时层和存储层均已实现。

---

### ⚠️ 方向三：自定义品牌化——**部分实现，且比描述的要完整得多**

您的分析声称 SPA 是"静态硬编码 HTML"且"没有任何配置机制"。这是**不准确的**。存在完整的品牌化通道。

**实际品牌化架构：**

```
租户存储 (SQLite/Postgres)
  └── branding_json TEXT 列 —— 存储 map[string]string
       │
       ▼
  GET /branding 处理器 (server_me.go:51-86)
       │  从租户域名解析品牌化信息
       │  未认证的端点 —— 返回空对象而非 404（防列举）
       │
       ▼
  SPA 应用 (login/app.js:87-117)
       在页面加载时 fetch("/branding")
       应用：
       ├── primary_color  → --brand-primary CSS 变量
       ├── logo_url       → 替换 <img id="brand-logo">（含 SVG 降级）
       └── brand_name     → document.title
```

**现有方式：**
- `interfaces/web/login/index.html:12` —— 已有 `<img id="brand-logo">`（`style="display:none"` 作为默认态）
- `interfaces/web/login/style.css:5` —— 使用 `--brand-primary: #6366f1`（CSS 变量，将被子写覆盖）
- `interfaces/web/login/app.js:87-117` —— 完整的运行时品牌化 fetch + 应用逻辑
- `comments` 中包含 `// --- White-label branding (async, best-effort) ---`

**您正确指出的问题**（这也是有效的批评）：品牌化**仅**在登录 SPA 中实现。Admin 控制台（`admin/index.html`、`admin/app.js`）和用户门户（`portal/index.html`、`portal/app.js`）完全不使用品牌化，且拥有固定标题 "SSO Admin Console" / "Your account"。同一基础设施（每个租户的 `Branding` map 已存储）可用于这些 SPA，但从未被使用。

**修正后判断**：`login/` → ✅ 已品牌化；`admin/` + `portal/` → ❌ 未品牌化。您完全遗漏了已有的登录品牌化。

---

### ✅ 方向四：管理员用户模拟——结论正确

这是完全正确的。`impersonat`、`masquerade`、`act_as`、`switch.*user` 在非测试 Go 代码中全部零命中。除此之外，也不存在：
- ✅ 管理员 API 端点（无 `POST /admin/users/:id/impersonate`）
- ✅ Token `act` claim 支持（无 `ImpersonatorID` 字段）
- ✅ Session 标记（无 `is_impersonation` 标记）
- ✅ 审计事件（无 `EventAdminUserImpersonated`）

**已验证。** 这是一个完全缺失的功能。

---

### ⚠️ 方向五：运营功能——部分正确，但遗漏了现有内容

| 您的论断 | 验证结果 |
|----------|----------|
| **批量导入**：CLI 存在但无 Admin API | ✅ 正确，但遗漏了 CLI 的存在。`cmd/sso-ctl/importcmd/` 包含完整的批量导入实现，支持 Auth0/Keycloak/CSV。 |
| **目录导出**：无批量用户导出 API | ✅ 正确。`GET /api/v1/admin/users/export` 不存在。 |
| **密码到期通知**：缺失 | ✅ 正确。密码到期通知调度器不存在。 |
| **Webhook 审计推送**："webhook_sink.go 存在但未文档化" | ⚠️ **存在但已文档化。** `platform/audit/auditsink/webhook_sink.go` 是一个完整的 `audit.Sink` 实现，通过 `audit.NewMultiSink(..., WebhookSink)` 接入，支持 `WithWebhookHeader`、`WithWebhookTimeout`、`WithWebhookHTTPClient`——可通过接口配置项配置。 |

---

## 修正后的优先级总表

| # | 方向 | 原始判定 | 修正后判定 | 工作量 | 风险 |
|---|------|----------|-----------|--------|------|
| **1** | **密码策略 SPI→配置层** | ⚠️ 半成品 | ⚠️ 半成品 ✅ | S | 低 |
| **2** | **并发会话限制** | ❌ 缺失 | ✅ **已实现（仅缺 YAML 配置）** | XS | 低 |
| **3** | **自定义品牌化** | ❌ 缺失 | ⚠️ **Login 已实现，Admin/Portal 缺失** | S | 中 |
| **4** | **管理员用户模拟** | ❌ 缺失 | ❌ 缺失 ✅ | M | 中-高 |
| **5** | **批量管理 + 通知** | ⚠️ 半成品 | ⚠️ **批量导入 CLI 已存在，Webhook 已存在** | S-M | 中 |

---

## 额外重大发现（您的分析中未涉及）

在验证您的过程中，我还发现以下您未涵盖的企业管理缺口：

### 🔥 发现 A：审计事件 → 无可查询的 Admin UI

审计事件已由 `audit.Recorder` 完美记录，且 `audit.Sink` 接口支持 `Get`/`Query`。然而：

```
# Admin SPA 中的审计 UI（admin/app.js 约 20 行）
# 仅列举事件，带基本分页，但无：
# - 按类型筛选（无 ?event_type=user_created）
# - 按用户筛选（无 ?actor_id=xxx）
# - 日期范围选择器
# - CSV/JSON 导出按钮
```

Admin 控制台中的审计查看器是**极简**的——只有分页列表，无筛选器、无搜索、无导出。对于 SOC 团队来说，这构成了可用性差距。

### 🔥 发现 B：MFA 管理——管理员无法为用户重置 MFA

如果用户丢失了他们的 WebAuthn 令牌或 TOTP 种子，**没有管理 API 来重置其 MFA 注册**。当前的 workaround 是直接操作数据库。这违反了 help-desk 的 SLA。

### 🔥 发现 C：无"只读管理员"角色概念

权限系统（`permissions/`）支持 `admin:read` / `admin:write` 作用域，但 Admin SPA 没有应用这种粒度——如果你有有效的 Bearer token，你可以使用全部功能。不存在"查看者"模式下禁用的 UI 元素。

---

## 总结

您的分析在 5 个方向中有 3 个方向正确，且方向一（密码策略）的研究尤其扎实。然而两个重大错误需要修正：

1. **并发会话限制已实现**（方向二）——YAML 配置层缺失，但运行时层完整
2. **登录 SPA 品牌化已实现**（方向三）——admin/portal 缺失，但整体的像素级管控通道存在

这实际上强化了您论点的核心主题：**SPI 和运行时层水平很高，但配置层和管理 UI 层存在缺口**，且这遵循着一种一致的模式——功能深度随与运营者的距离增大而下降。

您的 5 个方向中有 3 个（密码策略配置化、用户模拟、批量导出/密码通知）仍算作已确认且有价值的未来工作，只是顺序可能需要调整：

**建议新优先级：**
1. **管理员用户模拟**（高风险、高价值、从零开始构建）
2. **密码策略配置化 + 登录集成**（SPI 已完成，仅缺 YAML + 30 行代码）
3. **Admin UI 品牌化**（复用已有基础设施，扩展至 2/3 个 SPA）
4. **批量导出 API + 密码到期调度器**（新功能，但价值明确）
5. **并发会话 YAML 配置**（~10 行代码，几乎零成本）
