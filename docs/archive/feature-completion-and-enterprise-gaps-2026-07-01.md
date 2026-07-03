# 既有功能完成度与企业管理层缺失分析

> 基于 2026-07-01 全代码库扫描。  
> 分析视角：资深架构师 / 产品经理。  
> 定位：此前 8 轮分析（40 个方向）覆盖了新功能、边界修复、代码健康、架构债务、运维就绪、规范审计、运行时性能、纵深防御。  
> 本轮回答一个全新的问题：**哪些既有的功能只有"一半"——SPI 定义了、接口写了、但未配置化、未集成、未接通？哪些企业级管理功能完全缺失？**  
> 方法论：检查既有功能中"声明了但未完成"的 Gap，以及标准 IdP 必有的管理功能。  
> 原则：不写代码。

---

## 总体判断

前 8 轮的扫描都基于"有什么功能，缺什么功能"的二元判断。本轮采用四分法：

| 状态 | 定义 | 扫描方法 |
|------|------|----------|
| ✅ 完整实现 | 接口 + 实现 + 配置 + 测试 | 全链路可运行 |
| ⚠️ 半成品 | 接口/SPI 定义 + 部分实现 | grep 接口定义但 grep 不到配置引用 |
| ❌ 完全缺失 | 既无接口也无实现 | grep 零命中 |
| 🔲 声明但未集成 | 代码存在但未被任何构建路径引用 | grep 定义 vs grep 调用 |

---

## 方向一：密码策略——已定义 SPI 但未配置化、未集成到登录路径

### 现状

**已实现的**：
- `PasswordPolicyValidator` 接口 + `NewPasswordPolicyValidator()` 函数（`shared/spi/reg_gate.go`）
- `PasswordPolicyConfig` 包含：`MinLength`, `RequireUpper`, `RequireLower`, `RequireDigit`, `RequireSpecial`, `MaxHistory`, `MaxAgeDays`
- `PasswordHistoryStore` 接口（`stored_password.go`）用于存储最近 N 个密码哈希
- 密码重置和注册流程调用了 `checkPasswordPolicy()`

**未完成的**：

| 缺口 | 类型 | 证据 |
|------|------|------|
| **配置不可用** | ⚠️ 半成品 | `PasswordPolicyConfig` 定义在 `shared/spi/` 包中，但 `config/config*.go` 中**没有任何 password_policy 配置节**。运营者无法通过 YAML 设置密码策略 |
| **登录路径未集成** | ⚠️ 半成品 | `checkPasswordPolicy` 仅在注册（`signup.go:121`）和密码重置（`password_reset.go:111`）中调用。**登录路径（`authenticators/password.go`）不检查密码策略**——用户可以使用弱密码登录 |
| **MaxAgeDays 不生效** | ⚠️ 半成品 | `MaxAgeDays` 字段存在但没有任何"检查密码是否过期"的调用点。密码永不过期 |
| **密码历史不生效** | ⚠️ 半成品 | `PasswordHistoryStore` 接口定义了 `MaxHistory`，但没有检查"新密码不能在最近 N 个历史密码中"的校验 |

### 影响

| 场景 | 当前行为 | 应然行为 |
|------|----------|----------|
| 用户注册设密码 "123456" | ✅ 被拒绝（注册路径 checkPasswordPolicy） | ✅ |
| 用户在控制台改密码 "123456" | ✅ 被拒绝 | ✅ |
| 用户通过 /auth/login 登入 | ❌ 不检查密码强度 | ✅ 应在登录时提示"密码太弱，请修改" |
| 3 年前设置的密码 | ❌ 永不提示更改 | ✅ 管理员可配置 90 天过期策略 |
| 用户把密码改回 2 年前用过的 | ❌ 通过 | ✅ 应拒绝（密码历史检查） |

### 与竞品的差距

| 平台 | 密码策略可配置性 |
|------|----------------|
| Keycloak | ✅ 完整的密码策略（长度、字符集、历史、过期、最大失败次数） |
| Auth0 | ✅ 通过 Dashboard 或 API 配置 |
| Okta | ✅ 完整的 Password Policy 对象 |
| **Snaplink** | ⚠️ **SPI 定义了但配置层缺失 → 用户不可用** |

### 修复范围

1. **YAML 配置层**（~20 行）：在 `config/config_authn.go` 的 `PasswordConfig` 中添加 `Policy` 字段：

   ```yaml
   authenticators:
     password:
       policy:
         min_length: 8
         require_upper: true
         require_lower: true
         require_digit: true
         require_special: false
         max_history: 5
         max_age_days: 90
   ```

2. **登录路径集成**（~20 行）：在 `authenticators/password.go` 的认证成功后，如果密码不符合策略或已过期，返回 `password_weak` / `password_expired` audit 事件，不阻止登录（fail-open）但记录给运营者。

3. **密码过期检查**（~15 行）：在登录路径中检查密码最后修改时间 vs MaxAgeDays。

4. **密码历史校验**（~10 行）：在新密码设置时，调用 `PasswordHistoryStore.CheckHistory()`。

### 工作量价值评估

- **工作量**：S（~50 行）
- **当前风险**：低（不影响运行正确性，但企业合规审查的密码策略问题必问）
- **收益**：SOC 2 / ISO 27001 密码策略合规要求

---

## 方向二：并发会话限制——完全缺失的管理功能

### 现状

搜索 `MaxSessions`、`concurrent_session`、`session_limit`、`max_sessions` 在非测试代码中全部 **零命中**。

**当前状态**：**没有用户级并发会话限制**。

| 场景 | 当前行为 | 企业要求 |
|------|----------|----------|
| 用户同时在 10 台设备登录 | ✅ 全部允许——10 个活跃 session | ❌ 大多数企业限制为 3-5 个并发 |
| 用户分享账号给 20 人 | ✅ 全部允许——无限制 | ❌ 安全违规 |
| 用户找回密码后旧 session 仍有效 | ✅ 不自动撤销 | ❌ 应撤销其他 session |
| 管理员禁用用户 | ⚠️ 依赖于 store 实现 | ✅ 应立即终止所有 session |

### 影响

| 风险 | 严重程度 | 场景 |
|------|----------|------|
| 账号共享 | 中 | 无并发限制→20 人共享一个账号→审计追踪失败 |
| 会话固定攻击 | 低 | 非 OIDC spec 要求，但最佳实践 |
| 特权账号监控 | 高 | SOC 团队无法知道 admin 账号同时在 5 个 IP 登录 |

### 修复范围

1. **SessionManager 接口扩展**（~10 行）：添加 `CountByUser(ctx, userID) (int, error)` 和 `RevokeExcess(ctx, userID, maxSessions int) (revoked int, error)`

2. **配置层**（~10 行）：在配置中添加 `max_concurrent_sessions`：

   ```yaml
   server:
     session:
       max_concurrent_sessions: 5  # 0 = 无限制
   ```

3. **登录路径集成**（~15 行）：在签发新 session 时，检查用户当前 session 数，超过限制则撤销最旧的 session（FIFO）或拒绝新的 session。

4. **Session 后端支持**（每后端 ~20 行）：

   | 后端 | 当前能力 | 需要的能力 |
   |------|----------|-----------|
   | Memory | `sync.Map` | 添加 `CountByUser` + Redis-style ZREM 删除 |
   | SQLite | `SELECT COUNT(*) FROM sessions WHERE user_id=?` | 添加索引 |
   | Redis | ZSET by user | `ZCOUNT` + `ZREMRANGEBYRANK` |

### 工作量价值评估

- **工作量**：M（接口扩展 ~50 行 + 后端实现 ~60 行 + 配置 ~10 行 + 测试 ~40 行）
- **当前风险**：中（账号共享是企业 IdP 采购的否决项）
- **收益**：企业安全合规的"最小权限"原则的会话维度

---

## 方向三：自定义品牌化——三个嵌入 SPA 完全不可定制

### 现状

三个 SPA（`interfaces/web/login/`, `admin/`, `portal/`）全部是**静态硬编码 HTML**：

```html
<!-- login/index.html -->
<svg id="brand-mark" viewBox="0 0 44 44" ...>
  <!-- 固定的 snaplink logo -->
</svg>
<h1>Sign in</h1>
```

没有任何配置机制可以：

| 定制需求 | 状态 | 竞品支持 |
|----------|------|----------|
| 更换 Logo | ❌ 需修改源代码 | ✅ Keycloak/Auth0/Okta 均支持 |
| 更换品牌色彩（CSS 变量） | ❌ 需修改源代码 | ✅ |
| 设置公司名称 | ❌ 需修改源代码 | ✅ |
| 自定义 Favicon | ❌ | ✅ |
| 自定义登录页面的 HTML/CSS/JS | ❌ 完全静态 | ✅ Auth0 支持完整的自定义模板 |
| 自定义字体 | ❌ | ✅ |
| 自定义页脚链接（隐私政策、服务条款） | ❌ | ✅ |
| 多语言品牌 | ❌（见卷四 i18n 分析） | ✅ |

### 为什么重要

| 角色 | 需求 | 当前体验 |
|------|------|----------|
| 采购决定者（CTO） | "登录页面看起来不像第三方平台" | 嵌入 SPAs 显示"Sign in" + 未知 logo |
| 安全团队 | "我们需要在登录页面显示隐私政策和安全通知" | 无法添加页脚链接 |
| 市场营销 | "SSO 页面应使用我们的品牌色调和 logo" | 完全不可定制 |
| 合规团队 | "登录页面必须显示 CCPA/ GDPR 声明" | 无法添加 |

### 修复范围

1. **最小可行方案**（~40 行 Go + ~20 行 HTML 模板）：将 SPAs 从纯 HTML 改为 Go `html/template` 渲染，注入配置变量：

   ```yaml
   server:
     branding:
       logo_url: "https://company.com/logo.svg"
       company_name: "Acme Corp"
       primary_color: "#1a73e8"
       favicon_url: "https://company.com/favicon.ico"
       footer_links:
         - text: "Privacy Policy"
           url: "https://company.com/privacy"
         - text: "Terms of Service"
           url: "https://company.com/terms"
   ```

2. **CSS 变量注入**（~10 行）：在 SPA 的 `<head>` 中注入自定义 CSS 变量（品牌色）和 logo URL。

3. **自定义页脚**（~15 行）：在 Login/Admin/Portal SPA 底部渲染可配置的链接列表。

4. **完全自定义模板**（未来方向，非当前范围）：允许运营者提供完整的自定义 HTML 模板替换内建 SPA。这需要模板引擎支持（Go `html/template` 或 Lua）。

### 工作量价值评估

- **工作量**：M（Go template 渲染 ~30 行 + 配置 ~15 行 + SPA 修改 ~40 行）
- **当前风险**：中（企业采购的白标需求是硬性要求）
- **收益**：提高采购 POC 阶段通过率

---

## 方向四：管理员提权/用户模拟——完全缺失的 Help-desk 功能

### 现状

搜索 `impersonat`、`masquerade`、`su`（switch user）、`as_user`、`act_as`——在非测试 Go 代码中全部**零命中**。

**当前状态**：Help-desk 管理员**无法模拟用户**来诊断问题。

### 影响

| Help-desk 场景 | 当前 workaround | 模拟后的理想流程 |
|---------------|----------------|-----------------|
| 用户说"我登录时报错" | 让用户截图、发给 support | 管理员直接模拟用户，复现流程 |
| 用户说"这个应用请求的权限我不理解" | 让用户描述授权页面 | 管理员模拟用户，直接查看授权页面 |
| 用户说"我重置密码后仍无法登录" | 手动重置密码 + 让用户再试 | 管理员模拟用户，检查 session 状态 |
| 用户说"MFA 认证失败" | 让用户录屏 | 管理员模拟用户，看到相同的 MFA 提示 |

### 安全设计

用户模拟是一个**高安全风险**的功能。需要：

| 要求 | 设计 |
|------|------|
| 审计追踪 | 每次模拟都有 `admin_user_impersonated` 审计事件，记录 actor + target + 时间 |
| 模拟范围限制 | 仅允许模拟同一租户下的用户 |
| 模拟标记 | 签发的 access_token 和 session 要标记 `impersonator` 字段，使下游 RP 知道操作者不是原始用户 |
| 模拟时限 | 模拟 session 有较短 TTL（如 15 分钟） |
| 权限控制 | 需要 `admin:impersonate` 权限，普通 admin 不可用 |
| 透明标记 | Token 的 `act`（actor）claim 记录模拟者身份 |

### 实现范围

1. **Admin API**（~40 行）：`POST /api/v1/admin/users/:id/impersonate` → 返回一个模拟 token，具有目标用户的身份但包含 `act` claim。

2. **Token Issuer 扩展**（~15 行）：支持在签发 access_token / id_token 时附加 `act` claim（RFC 8693 §4.4 定义的 actor claim）。

3. **Session 标记**（~10 行）：模拟 session 在 session store 中标记 `is_impersonation: true` + `impersonator_id`。

4. **审计**（~10 行）：添加 `EventAdminUserImpersonated` 事件类型。

5. **SPA/Admin Console 集成**（~20 行 JS）：admin console 中出现"模拟用户"按钮，点击后切换到用户视角。

### 工作量价值评估

- **工作量**：M（~100 行 Go + ~20 行 JS）
- **当前风险**：中-高（企业帮助台的基本工具）
- **注意**：安全风险高，必须有严格的审计和权限控制

---

## 方向五：Admin 操作面缺失的 5 个运营功能——批量管理、变更历史、通知、密码到期、目录导出

### 核心缺口

| 运营功能 | 状态 | 竞品（Keycloak/Auth0/Okta） |
|----------|------|---------------------------|
| **批量用户导入/导出** | ⚠️ CLI `importcmd` 存在、但 Admin API 无批量操作 | ✅ 所有竞品都支持 |
| **Admin 操作审计历史的导出** | ✅ 审计事件已记录、但无"管理员操作变更历史"的完整报告 API | ✅ |
| **密码到期通知** | ❌ 密码永不过期 | ✅ Keycloak 支持密码到期前 N 天发邮件提醒 |
| **目录导出（所有用户 CSV/JSON）** | ❌ 无批量用户导出 API | ✅ |
| **审计事件实时推送（Webhook）** | ⚠️ `webhook_sink.go` 存在但未文档化 | ✅ Webhook 是企业审计必查项 |

### 批量管理缺失的具体影响

| 场景 | 当前 | 需要 |
|------|------|------|
| 从 HR 系统导入 500 个新员工 | API 按用户逐一 POST（500 次 HTTP 往返） | 批量导入端点（1 次 POST + 500 条记录） |
| 导出所有用户做安全审计 | 无 API → 管理员逐页抓取或直接查数据库 | `GET /api/v1/admin/users/export?format=csv` |
| 通知用户密码将在 7 天后过期 | 无此功能 | 调度器 + 邮件/通知发送 |
| 查看"上周谁做了什么变更" | 审计查询 API 存在但需自建 UI | Admin Console 中直接展示变更历史 |

### 最小范围

| 功能 | 工作量 | 说明 |
|------|--------|------|
| 批量用户导入 | M（~150 行） | `POST /api/v1/admin/users/bulk` 接受 JSON 数组，原子性（全部成功或全部回滚） |
| 目录导出 | S（~80 行） | `GET /api/v1/admin/users/export?format=json` 流式返回所有用户 |
| 密码到期通知调度器 | M（~100 行） | 每日扫描即将到期的密码，发送通知（通过 SPI `CodeSender`） |

### 工作量价值评估

- **工作量**：M（~330 行）
- **当前风险**：中（企业 HR 系统的员工入职/离职周期要求批量操作）
- **收益**：HR 系统集成的基础设施

---

## 优先级总表

| # | 方向 | 类型 | 工作量 | 风险 | 核心收益 |
|---|------|------|--------|------|----------|
| **1** | **密码策略 SPI→配置层打通** | ⚠️ 半成品 | S | 低 | 合规审计通过率提升 |
| **2** | **并发会话限制** | ❌ 缺失 | M | **中** | 账号共享风险控制 |
| **3** | **自定义品牌化** | ❌ 缺失 | M | 中 | 采购 POC 阶段通过率 |
| **4** | **管理员用户模拟** | ❌ 缺失 | M | **中-高** | Help-desk 工作效率 |
| **5** | **批量管理 + 密码到期通知** | ⚠️ 半成品 | M | 中 | HR 系统集成能力 |

### 跨 9 轮的总结

| 轮次 | 视角 | 发现的"缺口类型" |
|------|------|-----------------|
| 卷一 | 协议专家 | 还没实现的协议 |
| 卷二 | SRE | 生产环境缺失的能力 |
| 卷三 | QA | 边界条件下的破坏 |
| 卷四 | 开发者 | 代码库健康度 |
| 卷五 | 架构师 | 设计不可持续性 |
| 卷六 | 产品经理 | 运维就绪度 |
| 卷七 | 审计员 | 规范覆盖度 |
| 卷八 | 性能工程师 | 运行时效率 |
| **本卷** | **企业架构师** | **半成品功能 + 企业管理缺口** |

### 核心观点

经过 9 轮 45 个方向的分析，我注意到一个模式：**这个项目的 SPI 和接口设计水平远高于其配置化和集成化水平**。密码策略、MFA、审计、日志等核心能力都有完善的接口定义，但 YAML 配置层、Admin UI、运营者通知、批量管理等面向最终用户的"最后一公里"功能普遍缺失。

最优先的 3 个行动：

1. **密码策略从 SPI 级提升到配置级**——接口定义优良但 YAML 不可配置等于不存在
2. **添加并发会话限制**——账号共享是企业 IdP 的硬性否决项
3. **自定义品牌化**——白标是采购 POC 阶段的"第一印象"
