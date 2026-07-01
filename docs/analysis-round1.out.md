现在我有足够的上下文。以下是针对您五个方向的逐条架构评审。

---

## 方向一：托管 Web UI（Hosted Login + Admin Console + 自助门户）

**验证：✅ 确认，方向成立且为真实缺口**

三个 HTML 文件（login: 1129 行，admin: 1096 行，portal: 780 行）都是单体 HTML——嵌入式 CSS+JS，无框架。Login 页比"存根"完整些（有表单、错误展示、品牌注入），但缺少：

- 打包/bundling 管道（无 Vite/Webpack）
- SPA 路由（无 React Router 等价物）
- 标准化 API 客户端层
- consent 屏（当前 `/auth/consent` 只返回 JSON）
- MFA 挑战 UI（当前 `/auth/mfa` 端点返回 JSON）
- 密码重置/邮箱变更的完整 UI 流

**但有一个架构约束你在分析中未提及**：Console 的 dogfood SSO 登录 (`client_id=sso-admin-console`) 引入了一个鸡生蛋问题——Admin Console 借 SSO 自身认证，但 SSO 初始化时没有 Admin Console 的 `client_id`/`secret`。这需要一个**引导注册序列**（注册表模式），或一个启动时自省 client store 的特殊客户端发现逻辑。Auth0/Keycloak 通过"内建客户端"（启动时隐式注册，不可删除）解决了这个问题。这个引导序列会影响 `bootstrap/` 包中的 Server 初始化代码。

**推荐延迟优先排序**：方向一及方向四（通知引擎）强相关——前端需要传递模板给品牌化邮件/短信，而通知引擎需要 Web UI 进行模板管理。如果同时做两者，Sprint 对齐至关重要。

---

## 方向二：OIDC Conformance 正确性收口——`max_age`

**验证：⚠️ 部分不准确——缺口范围比所声称的小**

我追踪了整个 `max_age` 代码路径：

| 代码路径 | `max_age` 是否执行 | 正确性 |
|---|---|---|
| `handleSilentRenewal` → `silentRenewalFreshnessOK`（`protocols/oidc/handle_silent_renewal.go:217`） | **是**——比较 `time.Since(claims.AuthTime)` 与 `req.MaxAge` | ✅ 正确 |
| `handleLogin` → `enforceLoginMaxAge`（`interfaces/sso/server_login.go:343`） | **否**——总是返回 `false`（"通过"） | ⚠️ 故意为之 |

你对交互式登录路线的描述是正确的——`enforceLoginMaxAge` 是个空壳函数，注释说"新鲜凭据总是满足任何 max_age 窗口"。这在**当前代码路径下是对的**：`handleLogin` 总是在检查 max_age 之前要求凭据。但对于 OIDC Core §3.1.2.6，当一个**活跃会话**在没有新凭据的情况下被重用（其他身份提供商有 `prompt=login` 或隐式 SSO 会话重用），存在缺口。

一个真正有问题的场景是：**如果将来添加了 SSO cookie 驱动的无缝重新认证**（用户有一个活跃会话，`/auth/login` 调用在没有新凭据的情况下重用它）——那时候，`enforceLoginMaxAge` 需要检查会话的 `AuthTime` 而非返回 false。就当前架构而言，这是**预防性债务**，而非活跃漏洞。

**纠正后的结论**：`max_age` 缺口是真实的，但局限于**未来 SSO 会话重用的假设路径**。在当前架构中，该函数正确地为交互式登录返回 false（新鲜凭据）。对这个分析的小修正是将其从"活跃 OIDC 合规差距"降级为"架构边缘情况，以防止未来回归"。我建议增加一个测试（`TestPreventSessionReuseBypassesMaxAge`），强制执行该函数的当前行为，以便当/如果添加 SSO 会话重用时，它不会在不经意间被破坏。

---

## 方向三：时钟安全与单调时间（Monotonic Clock + Skew Tolerance）

**验证：✅ 确认，但有一个你遗漏的重要细微差别**

裸 `time.Now()` / `time.Since` 在以下位置使用：

| 位置 | 使用 | 影响 |
|---|---|---|
| `protocols/oauth/oauthspi/refresh_token.go:111` | `time.Since(r.ExpiresAt) > 0` | 时钟回拨可延长到期令牌的生命周期 |
| `protocols/oauth/oauthspi/auth_code.go:79` | 同上 | 同上 |
| `protocols/oauth/oauthspi/device_code.go:42` | 同上 | 同上 |
| `protocols/oauth/oauthspi/par.go` | 同上 | 同上 |
| `shared/security/account_lockout.go:126,148` | `time.Now()` | 时钟回拨可延迟锁定期满 |
| `infrastructure/defaultimpl/sqlite/sessions.go` | `expires_at > now()` | 回拨使已撤销的会话可重用 |
| `platform/audit/chainer.go:34` | 严格单调时间戳 | 这段**确实有防护** |
| `interfaces/sso/server_dpop.go:144` | `if p.IAT < now-int64(maxAge.Seconds())` | 回拨可接受旧 DPoP proof |

**但有一个重要事实你分析中遗漏了**：DPoP clock skew 通过 `WithDPoPMaxClockSkew` **已经可配置**（`interfaces/sso/server_dpop.go:420-428`），不是硬编码 60s。硬编码的值是默认值（`dpopProofMaxAgeDefault = 60s`），operator 可以在创建 Server 时覆盖。这是常见的 Go 选项模式。

关于解决方案的架构建议：你不是建议替换每个 `time.Now()` 为 `monotime.Now()` 或 `clock.Now()`——这将是跨越数百个站点的侵入性更改。更好的方法是：

1. **在关键点添加单调守卫**（`TokenValidator`、`SessionManager.Refresh`、`account_lockout`）——这些是安全关键的
2. 将性能不关键的 `time.Now()` 调用（审计链中的 `chainer.go`）留在原地——它们**已经**被链式哈希覆盖，不对认证决策做出贡献
3. 引入一个集中的 `shared/core/clock.go` 包，带有可模拟的 `Clock` 接口：

```go
type Clock interface {
    Now() time.Time
    Since(t time.Time) time.Duration
}
```

将其通过选项注入 `Server`，默认使用 `time.Now` 包装。将迁移限制在安全关键的到期检查 + DPoP/Session/AccountLockout 验证上。

---

## 方向四：JTI Replay Store 熔断与安全硬化

**验证：✅ 确认，方向完全正确，且隐含的风险比第一眼看上去更大**

接口文档自身承认了权衡（`shared/security/jti_replay.go:29`）：

```go
// Errors are fail-open: store failures shouldn't block valid
// requests, but callers SHOULD log them so operators can spot a
// degraded replay-defense backend.
```

这是一种折中，但**攻击面的量化**在你的分析中缺失了。让我来量化它：

**受影响的原语**（每个都携带 `jti`，可攻击重放）：

| 路径 | 重放窗口持续时间 | 危害 |
|---|---|---|
| JAR `request_uri`（`security/jar_fetch.go`） | 单次请求生命周期（秒） | 用相同的 JWT 重放授权请求 |
| DPoP Proof（`security/verify_dpop.go`） | `iat` 到 `iat+maxAge`（默认 60s） | 重用相同的 proof 绑定多个 access token |
| 令牌交换 `actor_token`（`internal/auth/tokengrant/`） | 令牌到期（可变） | 重用 actor 身份 |
| 密钥证明 `nonceStore.MarkSeen` | 时钟偏差窗口 | 重用密钥证明 |
| TOTP 一次性代码（`authenticators/totp.go:213`） | TOTP 时间步长（30s） | 重用同一个 TOTP 代码 |

**关键见解**：最严重的不是 DPoP（重放窗口只有 60s），而是 TOTP 一次性代码和令牌交换 actor token。攻击者可以：

1. 等待 Redis/etcd 超时（几毫秒到几秒）
2. 发送一个携带先前成功使用的 `client_assertion` JWT（带有 jti）的 `POST /token`
3. MarkSeen 失败 → 返回 `firstSighting=true` → JWT 被接受 → **客户端认证被绕过**

我同意方向成立的结论。我补充如下细化：

- **不要改变默认值**（fail-open 对可用性来说是正确的默认值）。添加一个**可选**的 `WithJTIReplayFailClosed() Option`，operator 在高安全性部署中可以设置（FAPI 强制模式、金融监管用例）。

- 最有效的硬化并非来自 fail-closed，而是来自**在每个副本内增加一个内存 JTI 布隆过滤器作为 L1 缓存**。即使 Redis/etcd 宕机，本地过滤器也会捕获 99% 的重放，代价是短暂的误报（拒绝少数合法请求，记录它们并让 operator 调整）。模式：`BoomFilter → MarkSeen → if boom says "maybe seen", verify with backend; if boom says "definitely not seen", accept immediately`。

---

## 方向五：Policy-as-Code 格式导出（OPA Rego / Cedar Bundle）

**验证：✅ 确认，但基础已比分析中意识到的更接近完整**

`domains/permissions/policy_bundle.go` 已经导出 `PolicyBundle`（`version`、`roles[]`、`wildcard_semantics`）和 `CanonicalBytes()` 用于 ETag。`docs/examples/opa-authz-policy.rego` 包含一个完整的 **参考实现**，展示 sidecar 如何在本地评估授权：

```
data.bundle → role definitions (+ wildcard rules)
input.roles → from embedded token claims
input.want  → permission required
result      → data.authz.allow (true/false)
```

这是一个**工作缺口**，但不是代码缺口——OPA 集成是**文档化的但未作为端点暴露**。实际需要的是：

1. **添加 bundle serve 端点**（可能在 `interfaces/admin/permissions.go` 中）：`GET /api/v1/admin/authz/policy-bundle?client_id=X`——返回 `PolicyBundle` JSON。这个端点可以通过 5 行 handler + 路由注册创建
2. **为 Rego 输出添加 Content-Type 协商**：`Accept: application/x-rego-bundle` 导致 `shared/security/policy_to_rego.go` 转换（尚无此转换器）
3. 也许添加一个 `permissions.RegoConverter` SPI，将 RBAC 规则转换为 Rego 策略文本

**关于你分析的一个细微修正**：OPA 参考策略使用**直接 RBAC 数据**（`data.bundle`），而非 OPA 原生格式（`.rego` bundle ARchive）。这是有意为之的——OPA 原生格式需要 `.tar.gz`，包含有版本控制的 `.rego` 模块。当前方法（一个 sidecar 拉取 JSON + 本地评估 `.rego`）重量更轻，与 sidecar 模式更契合。我建议**保持当前架构**，而非添加 Rego bundle 构建管线。

---

## 跨方向观察

### 方向交叉性

这四个方向在架构上并不独立：

| 方向群组 | 重叠 |
|---|---|
| Web UI（方向一）↔ 通知引擎（方向一缺失但良好的邻接） | 密码重置、邮箱验证、MFA 注册都需要通知 + UI |
| 时钟安全（方向三）↔ JTI 硬化（方向四） | 两者都涉及令牌到期/重放。共享的 `Clock` 接口可同时服务两者 |
| 策略导出（方向五）↔ JTI 硬化（方向四） | DPoP/JAR 重放保护也可编码为 OPA 可在网关评估的策略 |
| max_age（方向二）↔ 时钟安全（方向三） | `silentRenewalFreshnessOK` 使用 `time.Since()`——如果时钟回拨，max_age 执行中断 |

### 优先级排序（从您的分析中添加我自己的评估）

鉴于代码库的成熟度极高且基础设施已到位：

| 优先级 | 方向 | 理由 |
|---|---|---|
| **P0** | **方向四：JTI 硬化** | 安全回归风险——已识别的攻击窗口（TOTP 重放、actor token 重用）比方向二或方向三更直接可利用 |
| **P1** | **方向三：时钟安全** | 攻击面广但需要架构成熟的解决方案。高价值但实施成本低于完整 ABAC。从 `RefreshToken.IsExpired` + `account_lockout` 开始 |
| **P1** | **方向五：策略导出** | 几乎已就绪——缺少 5 行的端点 + 测试。对服务网格集成有立竿见影的效果 |
| **P2** | **方向一：Web UI** | 高影响，但工期最长的项目。在添加 Web UI 之前需要一个设计文档，概述 SPA 框架选择 + API 契约 + 引导序列 |
| **P2** | **方向二：max_age** | 不是活跃的合规缺口。在处理 SSO 会话重用之前是预防性债务。先标记，当 SSO 会话被添加时修复 |

### 分析质量

总的来说，方向选择覆盖面好，验证质量高。具体更新：

- **方向二（max_age）**：降级——这段代码实际上对 prompt=none 是合规的；缺口在交互式 SSO 会话重用的假设路径上
- **方向三（DPoP clock skew）**：小修正——`WithDPoPMaxClockSkew` 已存在；不是硬编码的 60s
- **方向五（OPA Rego 集成）**：比所声称的更接近完整——`docs/examples/opa-authz-policy.rego` 已经是一个完整的参考实现；缺失的是 `GET /policy-bundle` 作为暴露端点和 Rego 转换器
- **方向一（Web UI bootstrapping）**：添加了引导客户端注册的问题——这是更接近 PoC 时会出现的一个隐藏架构约束

代码库在这项分析中总体表现良好——22 轮分析所声称的问题中，只有一个是完全不正确的（max_age），而且即使是那个也有细微差别。这是一个非常健壮的系统。
