现在我已掌握了完整的代码事实。以下是综合验证报告。

---

## 第 8 轮审计 — 逐方向验证结果

### 验证方法
对代码库的 5 个方向逐一检查，确认事实是否正确、问题是否已存在。

---

### 方向 1：注册邮箱验证 — ⚠️ 审计结论不准确（功能已实现，默认关闭）

审计称"全程零邮箱验证操作"，但代码库有**完整的强制邮箱验证注册流程**：

| 组件 | 位置 | 状态 |
|------|------|------|
| `WithSignupRequireVerification(true)` | `interfaces/sso/options_passwd.go:83-91` | ✅ 存在 |
| `HandleSelfRegister` Mode B 分支 | `protocols/selfservice/signup.go:90-95` | ✅ 不创建用户，发验证 token |
| `HandleVerifyEmail` | `protocols/selfservice/verify_email.go:23` | ✅ 消费 token → 创建用户 |
| `EmailVerificationStore` SPI | `shared/core/spi.go` | ✅ 存在 |
| `EmailVerificationSender` SPI | `shared/core/spi.go` | ✅ 存在 |
| Mode A 可选验证 `?send_verification=true` | `signup.go:202-210` | ✅ 存在 |
| `EventSelfRegistered` 审计事件 | `event_types.go` | ✅ 存在 |

**当前风险**：默认关闭（`signupRequireVerification = false`），简单的 `NewServer()` 不需要验证。这是有意的向后兼容设计，但文档应在显眼位置提示。

**当前结论**：✅ 基础设施完整，无需加新代码。但应 **提升默认安全的文档可见性**。

---

### 方向 2：Device Flow HTML 页面 — ❌ 审计结论错误（已完整实现）

审计称"JSON API 而非 HTML 页面"，但实际代码有**完整的 RFC 8628 HTML 验证页面**：

| 路由 | 处理器 | 功能 |
|------|--------|------|
| **`GET /device/verify`** | `handleDeviceVerifyPage` | 内容协商：HTML 给浏览器，JSON 给 CLI |
| **`GET /device/verify?check=CODE`** | `handleDeviceVerifyCheck` | JS 轮询状态 |
| **`POST /device/verify`** | `handleDeviceVerify` | 程序化批准 API（需 Bearer + JSON） |

HTML 页面流（`protocols/oidc/device_verify_html.go`）：
```
Step 1: 输入 user_code 表单 → Step 2: 展示设备信息（client_name, scopes, code）
→ Step 3: 内嵌 /auth/login（用户名+密码）→ Step 4: 自动 POST /device/verify 批准
→ Step 5: ?check= 轮询池 → 成功/拒绝/过期
```

**当前结论**：❌ 方向 2 的审计声明不成立。实现完整，无需改动。

---

### 方向 3：TTL 生命周期不匹配 — ✅ 确认存在问题

```go
DefaultSessionDuration = 24 * time.Hour       // Session: 24小时
DefaultRefreshTokenTTL = 30 * 24 * time.Hour  // Refresh Token: 30天
```

**缺少的审计事件**：
- `EventRefreshTokenUsedAfterSessionExpiry` — **不存在**
- Session 过期后 Refresh Token 仍在使用的场景无迹可寻

**当前结论**：✅ 方向有效，需加新审计事件类型。

---

### 方向 4：审计版本盲区 — ❌ 审计结论错误（已完整实现）

审计称"缺少 `server_version` 字段"，但代码已实现：

```go
// Event 结构体（platform/audit/auditspi/event.go:55-60）
ServerVersion string `json:"server_version,omitempty"` // 已存在

// Recorder 选项（platform/audit/recorder.go:68-73）
func WithServerVersion(version string) Option { ... }  // 已存在

// Record() 自动填充（recorder.go:128）
e.ServerVersion = r.serverVersion                      // 已实现
```

**当前结论**：❌ 方向 4 的审计声明不成立。功能已完整实现。

---

### 方向 5：自服务审计缺口 — ✅ 确认存在问题

| 操作 | 当前审计事件 | 所需事件 |
|------|------------|----------|
| 用户修改密码 (`POST /me/password`) | ❌ 无 | `password_changed` |
| 用户删除 MFA 因子 (`DELETE /me/mfa/:id`) | ❌ 无 | `factor_removed` |
| 用户删除 passkey | ❌ 无 | `webauthn_removed` |
| 管理员删除 MFA（对比） | ✅ `admin_mfa_factor_removed` | — |
| 用户添加 TOTP（对比） | ✅ `mfa_totp_enrolled` | — |
| 用户注册 passkey（对比） | ✅ `webauthn_registered` | — |

**核心问题**：`HandleDeleteMyMFAFactor`（`selfserviceaccount/mfa.go:48-70`）和 `HandleChangeMyPassword`（`selfserviceaccount/security.go:19-56`）在成功操作后**没有调用 `Auditor().Record()`**。

**当前结论**：✅ 方向有效，需加 3 个事件类型 + 2 个 handler 中的审计调用。

---

### 优先级重新排序

| # | 方向 | 价值 | 工作量 | 验证状态 | 建议 |
|---|------|------|--------|----------|------|
| 1 | **方向 5：自服务审计缺口** | 中 | S | ✅ 确认（2-3 处修改） | **立即修复** |
| 2 | **方向 3：TTL 生命周期不匹配** | 中-高 | S | ✅ 确认（1 个新事件类型+文档） | **立即修复** |
| 3 | ~~方向 1：注册邮箱验证~~ | — | — | ❌ 已实现（默认关闭） | 文档改进 |
| 4 | ~~方向 2：Device Flow HTML~~ | — | — | ❌ 已实现 | 无需操作 |
| 5 | ~~方向 4：审计版本盲区~~ | — | — | ❌ 已实现 | 无需操作 |

**实际有价值的工作项**（从 5 个方向中清洗后）：

1. **方向 5** — 在 `HandleChangeMyPassword` 和 `HandleDeleteMyMFAFactor` 中添加审计事件
2. **方向 3** — 新增 `EventRefreshTokenUsedAfterSessionExpiry` 事件类型（如果有这个检测逻辑的话）+ 记录在 `docs/ttl-matrix.md`

需要我执行这些修复吗？
