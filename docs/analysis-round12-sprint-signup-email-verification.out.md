## 深度规划代码审查报告

我通读了整个规划文档并对代码库进行了全面的覆盖率检查。以下是评估结果：

---

### ✅ 已完成（规划中 90%+ 已实现）

| 组件 | 文件 | 状态 |
|------|------|------|
| `EmailVerificationToken` + `EmailVerificationStore` + `EmailVerificationRevoker` | `shared/core/email_change.go` | ✅ |
| `EmailVerificationSender` SPI | `shared/spi/email_verification.go` | ✅ |
| `ErrVerificationInvalid` + `ErrEmailNotVerified` | `shared/core/errors.go` | ✅ |
| `PathVerifyEmail` 常量 | `shared/core/consts.go` | ✅ |
| signup.go — Mode A / Mode B 完整逻辑 | `protocols/selfservice/signup.go` | ✅ |
| `HandleVerifyEmail` — 完整 handler | `protocols/selfservice/verify_email.go` | ✅ |
| `Deps` 接口 — 所有新增方法 | `protocols/selfservice/selfservicecore/deps.go` | ✅ |
| Server accessor 方法 | `interfaces/sso/server_signup.go` | ✅ |
| 路由注册 (`PathVerifyEmail`) | `interfaces/sso/server_routes.go` | ✅ |
| Options: `WithSignupRequireVerification`, `WithEmailVerificationStore`, `WithEmailVerificationSender` | `interfaces/sso/options_passwd.go` | ✅ |
| Server struct 字段 | `interfaces/sso/sso_selfservice.go` | ✅ |
| `rejectUnverifiedEmail()` 登录门控 | `interfaces/sso/server_login_verification.go` | ✅ |
| Memory EmailVerificationStore | `infrastructure/defaultimpl/memorystorecredential/memory_email_verification.go` | ✅ |
| 集成测试 | `test/auth_signup_email_verification_test.go` | ✅ |
| Config YAML | `cmd/sso-server/config.yaml` — `self_service.registration` section | ✅ |
| `go build ./...` — **零错误** | | ✅ |

---

### ❌ 剩余缺口（3 项）

#### 缺口 1：Bug — `email_change.go` 不设置 `email_verified = "true"`

`protocols/selfservice/email_change.go:HandleMyEmailVerify` 验证成功后更新邮箱但不标记已验证。

```go
// 第 85-87 行 — 当前代码：
u.Email = tok.NewEmail
if err := d.UserProvider().CreateOrUpdate(rctx, u); err != nil {
```

**需要添加**：验证成功后设置 `u.Attributes["email_verified"] = "true"`

#### 缺口 2：`config_self.go` 缺少 `Registration` 配置字段

`cmd/sso-server/config.yaml` 已有 `self_service.registration` 段，但 Go 结构体 `SelfServiceConfig` 未定义对应字段。

#### 缺口 3：`cmd/sso-server` 未将配置连线到 Server options

`build_app_selfservice.go` 未调用 `WithEmailVerificationStore()`、`WithEmailVerificationSender()`、`WithSignupRequireVerification()`。

---

### 🎯 建议行动顺序

1. **修复 bug**：`email_change.go` 设置 `email_verified = "true"`
2. **添加配置**：`config_self.go` 添加 `Registration` 字段
3. **连线**：`build_app_selfservice.go` 读取配置并调用 options

需要我直接开始实现这三个剩余修复吗？
