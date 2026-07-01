# 第十五轮分析：CSRF 防护、Session Cookie 安全、OIDC 认证文档与配置陈旧

> 基于全局代码库扫描产生的全新视角，此前十四轮未覆盖。

---

## 方向一：SPA 令牌存储使用 sessionStorage 但无 CSRF 保护——登录端点易受攻击

**问题：** 管理 UI（`admin/index.html:627`）和门户（`portal/index.html:220`）将 Bearer 令牌存储在 `sessionStorage` 中。登录 SPA（`login/index.html:692`）通过 `u.searchParams.set("access_token", data.access_token)` 将 `access_token` 放在 URL 查询参数中。但**登录表单本身缺乏 CSRF 保护**：

`login/index.html:741`：
```javascript
$("login-form").addEventListener("submit", function(e) {
    e.preventDefault();
    // POST /auth/login 使用 JSON body 中的 username+password
    // 没有 CSRF 令牌！
});
```

**为什么这是一个问题：**
- 没有 CSRF 令牌：恶意网站可以诱骗已认证用户浏览器的 `/auth/login` POST 端点，从而执行登录
- `access_token` 在 URL 查询参数中：暴露于浏览器历史记录、Referer 标头和服务器日志
- 没有 `Content-Type` 检查：Echo 的 JSON 绑定器接受 `application/x-www-form-urlencoded`——CSRF 攻击可以发送表单编码的凭证
- 没有 `Origin`/`Referer` 验证：服务器不检查 `Origin` 标头是否与已注册的源匹配

**修复：**
1. 登录 SPA 中的 POST 前生成并附加 CSRF 令牌（通过 `GET /auth/login/csrf-token` 端点）
2. 在服务器端验证 CSRF 令牌
3. 从 URL 查询参数迁移 `access_token` 到 POST 响应体 + 前端存储在 `sessionStorage` 中
4. 添加 `Origin` 标头验证中间件

**工作量：** M（CSRF 令牌端点 + SPA 更改 + Origin 验证 + 令牌传递更改）| **影响：** **高**（CSRF + 令牌泄露漏洞）| **类型：** 安全

---

## 方向二：Session Cookie 缺少 Secure & SameSite 属性——会话可能被中间人攻击泄露

**问题：** 会话管理 SPI（`SessionManager.Create`）需要返回 sessionID。sessionID 传递给客户端的方式未经检查，但凭经验，SPA 在 `sessionStorage` 中存储 Bearer 令牌。服务器**没有显式设置会话 cookie 的安全属性**：

**证据：** 在 `interfaces/sso/`、`internal/handler/` 或 `domains/session/` 中搜索 `http.SetCookie` + `&http.Cookie{}` 未返回任何 Set-Cookie 实现。会话令牌作为 Bearer 标头（而不是 cookie 方式）在 `Authorization: Bearer <token>` 中传递。但**关于 cookie 属性的问题仍然存在：**

- 如果服务器在某个地方设置 cookie，`Secure` 标志未指定
- `HttpOnly` 未指定——JS 可以读取会话 cookie
- `SameSite` 未指定——默认的 SameSite=Lax 在不同浏览器上行为不同
- `Path` 未指定——cookie 可能作用于整个域

**为什么这是一个问题：** 对于与服务器同源的 SPA，`sessionStorage` 存储 Bearer 令牌是一种合理的方法。但如果令牌**也**存储在 cookie 中（例如旧的重定向流程），未设置 `Secure` + `HttpOnly` + `SameSite=Strict` 会创建 XSS 和 CSRF 攻击面。

**修复：**
1. 审计所有设置 cookie 的代码路径
2. 对于任何 Set-Cookie：使用 `Secure=true`、`HttpOnly=true`、`SameSite=Strict`、`Path=/`
3. 对于 Bearer 令牌：添加文档说明令牌应仅存储在 `sessionStorage` 中的位置，切勿放在 cookie 中

**工作量：** S（审计 + 修复 + 文档）| **影响：** 中（会话安全性）| **类型：** 安全

---

## 方向三：OIDC/OAuth 认证实现缺少文档化的认证测试结果

**问题：** 该项目实现了完整的 OIDC 协议栈——授权码、隐式、混合、JARM、表单帖子、静默续期、RP 发起登出、会话管理。但**没有认证测试结果**。

缺乏：
- 没有 `CONFORMANCE.md`——解释认证状态和已知差异
- 没有 OIDC 认证测试套件配置——`/test/oidc/` 测试特定行为，但未针对认证配置文件运行
- 没有已知的 RP/OP 互操作性矩阵——与 Auth0、Okta、Keycloak、Azure AD 的互操作性
- 没有 FAPI 1.0/2.0 认证配置文件测试结果

**为什么这是一个问题：** 政府、医疗保健和金融客户要求 OIDC 认证。如果没有文档化的认证状态，每个客户必须在自己的环境中重复测试——浪费所有相关方的时间。

**修复：**
1. 添加 `docs/sso/oidc-conformance.md`，记录已知的认证状态和差异
2. 添加 `/test/oidc/conformance_setup.go`，提供用于认证测试套件的测试配置
3. 添加互操作性矩阵（`docs/sso/interoperability-matrix.md`），记录测试结果

**工作量：** M（文档 + 测试配置 + 在至少一个认证环境中手动运行测试）| **影响：** **中高**（企业 RFP 响应的要求）| **类型：** 文档/互操作性

---

## 方向四：Godoc 覆盖率中只有一个 Example 函数——面向下游消费者的可运行文档严重不足

**问题：** 在 5523 个测试函数中，只有 **1 个 `func Example` 函数**（在整个代码库中）。Go 的 `Example*` 测试函数在 `go test -v` 运行时会作为可运行文档出现在 `pkg.go.dev` 中。

**为什么这是一个问题：** 这个项目被设计为可嵌入的 SDK（`import "github.com/snaplink/sso"`）。下游消费者需要在不深入源代码的情况下，了解如何使用核心 API，包括：

- 如何创建和配置 `sso.Server`
- 如何实现 `CodeSender` SPI
- 如何集成自定义认证器
- 如何注册自定义 grant 处理程序
- 如何挂载管理 UI

没有 `ExampleServer_WithConfig`、`ExampleCodeSender`、`ExampleServer_Mount`，下游开发人员只能通过阅读源代码来学习——这与 Go 的可运行文档哲学背道而驰。

**修复：** 为以下内容添加 `Example*` 函数：
- `sso.New()` → `ExampleNew()`
- `sso.WithHostedLoginFS()` → `ExampleServer_WithHostedLoginFS()`
- `spi.CodeSender` → `ExampleCodeSender()`
- `oauth.GrantHandler` → `ExampleGrantHandler()`
- `DefaultImpl` → `ExampleDefaultImpl()`

**工作量：** M（15-20 个 `Example*` 函数，分散在 5-8 个包中）| **影响：** 中（SDK 采用/开发者体验）| **类型：** 文档

---

## 方向五：`config.yaml` 示例与默认值偏离实际代码——文档陈旧

**问题：** `config.yaml`（`cmd/sso-server/config.yaml`）是一个 1300+ 行的配置参考。但它与 `config/config.go` 中定义的实际代码结构是**手动维护的**。没有自动验证确保 YAML 中的字段与 Go 结构体匹配。

**陈旧的具体迹象：**
- `config.yaml` 中的一些选项可能属于不再存在的旧模块
- 新的配置结构体可能添加到 `config/config.go` 中但未反映在 `config.yaml` 中
- `config/config.go` 中的 `yaml` 标签可能在不匹配 YAML 的情况下重命名
- `config.yaml` 中的文档注释可能描述过时的行为

**为什么这是一个问题：** 操作员将 `config.yaml` 复制到他们的部署中，并根据它进行配置。如果 YAML 是陈旧的，他们的配置会在未知情况下失败或静默地使用默认值。

**修复：**
1. 添加 `config/validate.go` → `Config.ValidateSample(sampleYAML) []Diff`——将每个 YAML 键与 Go 结构体字段进行比较
2. 添加 CI 步骤：`go run ./cmd/sso-server --config-schema > /tmp/schema.yaml && diff <(yq eval '.. | path' config.yaml) <(yq eval '.. | path' /tmp/schema.yaml)`
3. 为每个新配置结构体添加 CI 检查：`sample-yaml-stale` 如果任何配置包中的字段没有对应的 YAML 示例条目则失败

**工作量：** M（配置模式验证工具 + CI 步骤 + 当前陈旧条目的修复）| **影响：** 中（配置正确性/运维）| **类型：** 运维/文档

---

## 优先级

| # | 方向 | 影响 | 工作量 | 类型 |
|---|-------|------|--------|------|
| 1 | SPA 登录 CSRF + SQL 查询参数中的 access_token | **高**（CSRF + 令牌泄露） | M | 安全 |
| 2 | Session Cookie 缺少 Secure/SameSite/HttpOnly | **高**（会话劫持） | S | 安全 |
| 3 | OIDC 认证测试结果缺失 | **中高**（企业 RFP 要求） | M | 文档/互操作性 |
| 4 | Godoc Example 覆盖率（仅 1 个 Example 函数） | 中（SDK 采用） | M | 文档 |
| 5 | config.yaml 示例与代码结构脱节 | 中（运维正确性） | M | 运维 |

**按 ROI 排列：** 方向 1（CSRF + 令牌泄露——暴露面最广，用户可见的安全漏洞）→ 方向 2（Cookie 安全属性——快速修复，直接的安全增益）→ 方向 3（OIDC 认证——企业销售周期中的关键阻碍因素）→ 方向 5（Config 陈旧——可能导致运行时意外）→ 方向 4（Example 函数——对 SDK 采用重要但对现有操作员影响较小）。
