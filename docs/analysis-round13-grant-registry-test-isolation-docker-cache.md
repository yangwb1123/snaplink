# 第十三轮分析：Grant 可扩展性、测试基础设施重构、Docker 构建与速率限制细化

> 基于全局代码库扫描产生的全新视角，此前十二轮未覆盖。

---

## 方向一：Grant 类型分发是硬编码的 switch 语句——无法扩展自定义 Grant

**问题：** `interfaces/sso/server_token.go:74` 的分发逻辑是一个硬编码的 switch 语句：

```go
switch req.GrantType {
case GrantAuthorizationCode:
    HandleAuthCodeGrant(...)
case GrantRefreshToken:
    HandleRefreshGrant(...)
case GrantDeviceCode:
    HandleDeviceGrant(...)
case GrantCIBA:
    HandleCIBAGrant(...)
case GrantTokenExchange:
    HandleTokenExchangeGrant(...)
case GrantClientCredentials:
    HandleClientCredentialsGrant(...)
default:
    // 返回 unsupported_grant_type
}
```

**问题：** 添加新的 grant 类型（例如 SAML Bearer Assertion Grant RFC 7522、JWT Bearer Grant RFC 7523、CDR/Open Banking grants）需要对 `server_token.go` 进行侵入式修改。没有：
- `GrantTypeRegistry`——用于注册自定义 grant 处理程序的插件映射
- `GrantHandler` 接口——用于外部包注册自己
- `WithCustomGrant(name, handler)` 服务器选项
- 在 `/token` 的发现中声明的自定义 grant

**影响：** 想要添加专有或行业特定 grant 的操作员必须 fork 整个代码库。对于 Open Banking（CDR、STET、BERLIN）或受监管行业（eIDAS、PSD2），这是一个严重的采用障碍。

**修复：** 创建一个 `GrantHandler` 接口：

```go
type GrantHandler interface {
    GrantType() string
    Handle(ctx HandlerContext, client *Client, req TokenRequest) error
}
```

添加一个 `GrantTypeRegistry`，自定义 grant 可以注册到其中。更改 switch 语句以首先检查注册表，如果未找到，则回退到内置 grant。

**工作量：** M（接口 + 注册表 + 服务器选项 + 将内置 grant 适配到注册表）| **影响：** **高**（启用自定义 grant 作为架构特征）| **类型：** 架构/功能

---

## 方向二：Docker 多阶段构建未缓存子模块依赖——每次构建重新下载 12+ go.mod

**问题：** Dockerfile 使用标准模式来缓存 Go 模块：

```dockerfile
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /out/sso-server ./cmd/sso-server
```

但**这只缓存根模块的依赖**。12+ 个子模块（`infrastructure/saml/`、`infrastructure/redis/`、`infrastructure/ldap/` 等）的 `go.mod` 文件被忽略，直到 `COPY . .` 步骤，该步骤清除了模块缓存。

**影响：** 对 `protocols/oauth/` 中的 Go 文件进行一行更改会触发完整的 Docker 构建：
1. `COPY . .`——使所有 12+ 个子模块的依赖项无效
2. `go build`——为子模块的依赖项（`crewjam/saml`、`go-redis`、`go-ldap`、`mattn/go-sqlite3` 等）重新下载整个依赖树
3. 在缓慢的 CI 或缓慢的连接上，每次构建增加 2-5 分钟

**修复：**

```dockerfile
# 缓存根模块
COPY go.mod go.sum ./
RUN go mod download

# 为每个子模块缓存
COPY infrastructure/saml/go.mod infrastructure/saml/go.sum ./infrastructure/saml/
RUN go mod download ./infrastructure/saml/

COPY infrastructure/redis/go.mod infrastructure/redis/go.sum ./infrastructure/redis/
RUN go mod download ./infrastructure/redis/

# ...更多子模块...

COPY . .
RUN go build -o /out/sso-server ./cmd/sso-server
```

**工作量：** S（Docker 中约 3 行/子模块）| **影响：** 中（每次构建 2-5 分钟）| **类型：** 构建/性能

---

## 方向三：自助服务注册漏斗缺少转化分析——用户在哪个环节放弃？

**问题：** `interfaces/sso/options_passwd.go` 定义了完整的自助服务注册流程：
- `POST /auth/register`——创建用户（可选需要验证）
- `POST /auth/verify-email`——完成电子邮件验证
- `POST /auth/login`——首次登录
- `POST /auth/forgot-password` + `POST /auth/reset-password`——密码重置

但**这些流程中没有任何步骤被测量**：
- 没有 `sso_signup_started_total` 计数器
- 没有 `sso_signup_verified_total` 计数器（已启动与已验证的比率）
- 没有 `sso_signup_completed_total` 计数器（已注册 + 已验证 + 首次登录的比率）
- 没有 `sso_password_reset_requested_total` / `sso_password_reset_completed_total` 指标
- 没有电子邮件验证点击率的指标

**为什么这是一个问题：** 如果 80% 的用户在注册时放弃，是因为验证电子邮件（a）从未到达，（b）到达但链接已过期，还是（c）到达但用户不确认？目前无法判断。操作员只会看到很少的新活跃用户，而不知道为什么。

**修复：**
1. 向 `Metrics` 添加 `SignupStartedTotal`、`SignupVerifiedTotal`、`SignupCompletedTotal`（带 `provider` 和 `outcome` 标签）
2. 在 `HandleRegister`、`HandleVerifyEmail`、首次 `HandleLogin` 中增加计数
3. 为密码重置添加 `PasswordResetRequestedTotal`、`PasswordResetCompletedTotal`
4. 为 Grafana 仪表盘添加一个"注册漏斗"面板

**工作量：** S（5 个计数器 + 4 个检测点 + 1 个仪表盘面板）| **影响：** 中（自助服务 UX 优化）| **类型：** 可观测性

---

## 方向四：集成测试隔离不完善——共享全局变量阻止并行化

**问题：** 在所有 789 个测试文件中，有 5523 个测试函数。其中 760 个文件（96%）在 `package ssotest` 中。但是：

1. **共享的 `BcryptCost` 全局变量**：`infrastructure/defaultimpl/memorystoreidentity/client_secret.go:15` 中的 `var BcryptCost = bcrypt.DefaultCost` 是包级可变全局变量。测试修改它为 `bcrypt.MinCost`（`client_secret.go:13` 的注释："changed to bcrypt.MinCost (4) to keep suite runtimes acceptable"）。**没有 goroutine-safe 的恢复机制**——测试可以通过 `defer` 恢复它，但并非所有测试都这样做。

2. **共享的 SQLite 数据库**：多个测试写入同一个临时数据库文件，在 `TestMain` 中设置。

3. **全局注册表**：`sqlited.RegisterConnectionHook`（`busy_timeout.go` 中的 `init()`）在进程范围内注册一个连接钩子——影响所有 SQLite 测试。

4. **没有 `t.Parallel()` 安全**：由于全局状态，大多数测试无法安全地并行运行。

**影响：**
- 测试以 O(5523) 串行运行——在 CI 中需要 25-40 分钟
- 不可预测的失败——如果测试 A 修改了 `BcryptCost` 但没有恢复，测试 B 会意外地运行 bcrypt cost=4
- 没有测试分片——不能跨 4 个并行作业分割测试

**修复：**
1. 将 `BcryptCost` 从包级变量改为结构体上的字段——影响大约 8 个使用者
2. 为每个包创建独立的 `TestMain` 函数，以实现包级并行
3. 将 760 个 `ssotest` 文件拆分到 `test/auth/`、`test/oidc/`、`test/admin/` 等——每个都是独立的 Go 包

**工作量：** L（重构全局变量 + 拆分测试包）| **影响：** **高**（CI 时间缩短 4 倍）| **类型：** 测试基础设施

---

## 方向五：缺少按 Grant 类型的速率限制——一个尺寸不适合所有人

**问题：** `interfaces/ratelimit/middleware.go` 应用全局速率限制器。`server_token.go` 中的 `/token` 处理程序有一个 `dispatchTokenGrant` 函数，该函数在分发 grant 之前应用**单个速率限制检查**。但不同的 grant 类型有不同的攻击面：

| Grant 类型 | 速率限制需求 |
|-----------|-------------|
| `authorization_code` | 严格——每次授权尝试多了一个消耗的代码 |
| `refresh_token` | 宽松——合法客户端在令牌轮换期间频繁轮询 |
| `client_credentials` | 宽松——服务器到服务器，通常高吞吐量 |
| `device_code` | 中等——速率限制绑定到设备代码 |
| `token_exchange` | 严格——阶梯令牌是攻击者的高价值目标 |
| `ciba` | 宽松——推送通知，低吞吐量 |

**当前状态：** `WithRateLimit(rate, burst)` 配置了一个全局令牌桶。这意味着：
- 每秒 100 个 `client_credentials` 速率限制也会限制 `authorization_code`——反之亦然
- 限流 `refresh_token` 以防止滥用也会限流合法客户端
- 恶意 actor 可以用高吞吐量的 `client_credentials` 调用淹没共享桶，从而为低吞吐量的 `authorization_code` 创建 DoS

**修复：** 添加 `WithGrantTypeRateLimit(grantType, rate, burst)`——按 grant 类型的独立桶。在 `dispatchTokenGrant` 的分发期间应用。

**工作量：** S（每个 grant 类型的配置映射 + 分发逻辑中的一次额外检查）| **影响：** 中（防止跨 grant 类型的 DoS 污染）| **类型：** 安全/性能

---

## 优先级

| # | 方向 | 影响 | 工作量 | 类型 |
|---|-------|------|--------|------|
| 1 | Grant 类型注册表（自定义 grant 的可扩展性） | **高**（架构特征——实现自定义 grant 需要 fork） | M | 架构 |
| 2 | 集成测试隔离（全局变量 + 包拆分） | **高**（CI 25-40 分钟 → 约 10 分钟） | L | 测试 |
| 3 | 按 Grant 类型的速率限制（授权码与 client_creds） | 中（跨 grant 类型的 DoS 污染） | S | 安全 |
| 4 | Docker 子模块缓存（12+ go.mod，每次构建 2-5 分钟） | 中（CI 构建时间） | S | 构建 |
| 5 | 自助服务注册漏斗指标（用户在哪个环节放弃） | 中（UX 优化） | S | 可观测性 |

**按 ROI 排列：** 方向 2（测试隔离——CI 时间可能是团队最大的抑郁因素，25-40 分钟的串行执行）→ 方向 1（Grant 注册表——使 SSO 成为一个平台，用户可以为其扩展，而无需 fork）→ 方向 3（Grant 类型速率限制——解决真实的安全问题：恶意 actor 通过 client_credentials 淹没授权码桶）→ 方向 4（Docker 缓存——最小的工作量，显著的构建速度提升）→ 方向 5（注册漏斗——数据驱动的 UX 改进）。
