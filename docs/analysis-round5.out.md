Now I have a comprehensive understanding of all 5 directions. Let me compile the full findings report.

---

## 分析验证结果

我系统性地验证了每项声明。以下是逐方向的实际现状：

---

### ✅ 方向一：用户会话自我管理 — **已完全实现**

| 分析声称 | 实际状态 |
|----------|----------|
| `GET /me/sessions` 不存在 | ✅ 已存在 — 路由注册于 `server_routes.go:171`，处理于 `HandleMySessions(s, ctx)` |
| `DELETE /me/sessions/:id` 不存在 | ✅ 已存在 — 路由注册，处理于 `HandleDeleteMySession(s, ctx)` |
| `POST /me/sessions/revoke-all` 不存在 | ✅ 已存在 — 路由注册，处理于 `HandleRevokeAllMySessions(s, ctx)` |

**代码证明：**
- 常量：`shared/core/consts.go:48-50` — `PathMeSessions`, `PathMeSessionByID`, `PathMeSessionsRevokeAll`
- 路由：`interfaces/sso/server_routes.go:169-175` — 注册三个 `/me/sessions*` 端点
- 处理函数：`interfaces/sso/server_me.go:137-152` — 代理到 `protocols/selfservice/` 处理器
- 业务逻辑：`protocols/selfservice/sessions.go` — `HandleMySessions`, `HandleDeleteMySession`, `HandleRevokeAllMySessions`
- 测试：`test/me_sessions_test.go` — 完整测试套件

**结论：** 双向命名空间 `/sessions/me*` 和 `/me/sessions*` 均存在且已路由。自分析撰写后已实现。

---

### ✅ 方向二：密码策略 SPI — **已完全实现（含少量未接入组件）**

| 分析声称 | 实际状态 |
|----------|----------|
| `PasswordPolicy` 命中数为 0 | ✅ `PasswordPolicyValidator` 存在于 `shared/spi/reg_gate.go:39` |
| 无复杂度规则 | ✅ `PasswordPolicyConfig` 含 `MinLength`, `RequireUpper`, `RequireLower`, `RequireDigit`, `RequireSpecial`（第 45-53 行） |
| 无密码历史 | 🔶 `PasswordHistoryStore` 已定义（`domains/authenticators/stored_password.go:47`），`MemoryPasswordHistoryStore` 已存在，但 **未接入任何流程** |
| 无密码过期 | 🔶 `MaxAgeDays` 存在于 `PasswordPolicyConfig`（第 52 行），但 **服务端未强制实施** |
| 修改密码时无策略验证 | ✅ `checkPasswordPolicy()` 调用于 `signup.go:121/189`、`password_reset.go:111` 和 `selfserviceaccount/security.go:49` |
| 无 `ErrPasswordPolicyViolation` | ✅ 存在于 `shared/core/errors.go:131` |

**接入流程：**
- 注册：`protocols/selfservice/signup.go:306-316`
- 密码重置：`protocols/selfservice/password_reset.go:110-111`
- 修改密码：`protocols/selfservice/selfserviceaccount/security.go:47-51`
- 限流器选项：`interfaces/sso/options_passwd.go:406` — `WithPasswordPolicy(v)`

**结论：** 密码策略已全面实现并接入三个密码设置路径。`PasswordHistoryStore` 作为基础设施存在但尚未接入 `checkPasswordPolicy()`。`MaxAgeDays` 已定义但未强制实施。

---

### 🔶 方向三：Per-subject 限流 — **部分实现**

| 分析声称 | 实际状态 |
|----------|----------|
| 限流 key 格式为 `{path}:{client_id}:{ip}` | ❌ 实际 key 仅为 `KeyByClientIP`（客户端 IP）—— `build_ratelimit_cluster.go:67` |
| 无 per-subject key 变体 | ✅ `KeyBySubject(r)` 已存在于 `ratelimit/middleware.go:90`，但**默认策略未使用它** |
| 异常检测器不阻断 | ✅ 正确——`anomaly.Runner` 定义为异步只读，设计上不阻断 |
| `OnAnomaly` 事件无内置动作 | ✅ 正确——无 `auto_block_duration` 或`WithAnomalyAction` |

**`KeyBySubject` 存在但未被使用：**
```go
// interfaces/ratelimit/middleware.go:90-94
func KeyBySubject(r *http.Request) string {
    if sub := middleware.SubjectFromContext(r); sub != "" {
        return "sub:" + sub
    }
    return KeyByClientIP(r)
}
```
但限流中间件在认证**之前**运行，因此 `KeyBySubject` 不可用于登录端点——需对登录流程进行中间件位置调整。

**账户锁定已存在：**
```go
// shared/security/account_lockout.go — 基于滑动窗口的每个账户限制
// 包含 LockoutKey(clientID, credential)
```

**结论：** `KeyBySubject` 可用但针对登录端点用处有限（在认证之前运行）。`AccountLockout` 已针对每账户暴力破解提供保护。密码喷洒攻击（每个用户一次，跨全组织）仍是一个覆盖缺口——`AccountLockout` 按 `client_id:identifier` 键控，每个用户名仅一次失败无法触发阈值。

---

### ✅ 方向四：品牌化消费 — **登录页面已完全实现**

| 分析声称 | 实际状态 |
|----------|----------|
| `Branding` 存储于 `Domain.Branding` 但未渲染 | ✅ `GET /branding` 端点已存在（`server_me.go:51`） |
| 登录页面不读 Branding | ✅ **login SPA 确实消费 Branding** — 见 `app.js` 中的 `(function loadBranding() {...})` |
| Branding 数据为 `map[string]string` | ✅ 正确——于 `domains/tenant/tenant.go:73` |

**login SPA 品牌化实现（`interfaces/web/login/app.js`，约第 90 行）：**
```javascript
(function loadBranding() {
    fetch(brandingURL, {headers: {"Accept": "application/json"}})
      .then(function(r) { return r.ok ? r.json() : null; })
      .then(function(data) {
        var b = data && data.branding;
        if (!b) return;
        if (b.primary_color) {
          document.documentElement.style.setProperty("--brand-primary", b.primary_color);
        }
        if (b.logo_url) {
          // 显示租户 logo，隐藏默认标记
          img.src = b.logo_url;
        }
        if (b.brand_name) {
          document.title = "Sign in · " + b.brand_name;
        }
      })
      .catch(function() { /* 保留默认主题 */ });
})();
```

**未消费 Branding 的页面（分析正确之处）：**
- `admin/app.js` — 未获取品牌化数据（仅显示服务器状态面板）—— 恰当的设计决定
- `portal/app.js` — 检查同上
- 邮件模板 — 未检查，但可能存在缺口

**结论：** 登录页面已完整品牌化。核心分析声明是误导性的——代码在分析之前就已存在。

---

### ✅ 方向五：Sudo 模式 — **已完全实现**

| 分析声称 | 实际状态 |
|----------|----------|
| `POST /me/password` 不需要当前密码 | ✅ `HandleChangeMyPassword` 要求 `current_password` + `new_password` |
| XSS session 窃取可导致账户接管 | ✅ 密码修改时旧密码验证可防止 |
| 新密码未验证 | ✅ 密码策略验证已接入 |

**`POST /me/password` 实现（`protocols/selfservice/selfserviceaccount/security.go:11-60`）：**
```go
func HandleChangeMyPassword(d Deps, ctx core.HandlerContext) {
    // ...认证 + 驻地门禁...
    var req struct {
        CurrentPassword string `json:"current_password"`
        NewPassword     string `json:"new_password"`
    }
    oauth.BindParams(ctx, &req)
    // 拒绝空 current_password
    if req.CurrentPassword == "" || req.NewPassword == "" { ... }
    // 验证旧密码
    d.PasswordCredentialStore().VerifyPassword(ctx, userID, req.CurrentPassword)
    // 策略验证
    d.PasswordPolicyValidator().ValidatePassword(ctx, req.NewPassword)
    // 设置新密码
    d.PasswordCredentialStore().SetPassword(ctx, userID, req.NewPassword)
}
```

**其他 `sudo` 模式场景（尚未验证）：**
- `POST /me/mfa/totp/begin` — 不要求密码（分析正确）
- `POST /me/mfa/webauthn/begin` — 不要求密码（分析正确）
- `POST /me/account/erase` — 有确认步骤（分析正确）
- 基于时间的 sudo 确认（旧 session 需重新认证）— 未实现

---

## 总结矩阵

| 方向 | 分析声称 | 实际状态 | 真实工作量 |
|------|----------|----------|------------|
| **① 会话自我管理** | 不存在 | ✅ **已完全实现** | 0（无工作待做） |
| **② 密码策略 SPI** | 不存在 | ✅ **已完全实现** | 微小：连接 `PasswordHistoryStore` + 强制 `MaxAgeDays` |
| **③ Per-subject 限流** | 完全缺失 | 🔶 **部分实现**（`KeyBySubject` 存在；`AccountLockout` 存在；无自动阻断异常检测；密码喷洒仍有缺口） | L：中间件顺序、配置可插拔键控、异常检测器动作注册表 |
| **④ Branding 消费** | 未渲染 | ✅ **登录页面已完全实现** | 微小：管理员/门户 SPA 邮件模板可能仍需关注 |
| **⑤ Sudo 模式** | 缺失 | ✅ **密码修改已完全实现** | S：MFA 注册时增加密码确认；可选的基于 session 年龄的 sudo |

### 真正的待办事项（分析中未提及但实际存在）

1. **`PasswordHistoryStore` 未接入** — 定义于 `authenticators/stored_password.go` 但未在 `checkPasswordPolicy` 或密码设置流程中调用
2. **`MaxAgeDays` 未强制实施** — 存在于 `PasswordPolicyConfig` 但 `passwordPolicyValidator` 不检查
3. **无基于时间的 sudo 窗口** — session 年龄 >1 小时需重新认证，目前未实现
4. **`KeyBySubject` 未用于登录限流** — 由于中间件顺序限制（登录认证前运行），在登录时无效，但可用于后续的 `/token`、`/userinfo` 等

### 方向三：真正值得关注的攻击面

分析在识别**密码喷洒（每个用户 1 次尝试）**方面完全正确——`AccountLockout` 按 `client_id:identifier` 键控，每个用户名仅一次失败不会触发阈值。最直接的防护措施是在 `AccountLockout` 现有功能基础上，将 `RegisterFailure` 与跨所有用户的总失败率结合使用，或将限流器绑定到 `target` 用户名。这目前是一个实际存在的安全缺口。
