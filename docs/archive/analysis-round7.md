# 分析第 7 轮 — 注册防滥用 / Introspection 缓存 / 状态端点 / OIDC 合规 / Fuzz 测试

> 扫描日期：2026-06-29
>
> 前六次路线：① 产品/协议 → ② `time.Now()`/集群 → ③ 刷新令牌并发 → ④ 安全头/KDF → ⑤ 会话管理/密码策略 → ⑥ session 硬上限/SAML 膨胀/session_state
>
> 本次聚焦：之前六轮从未触及的访问控制面、可观测性面、合规认证面、软件质量保证面

---

## 方向一：用户注册端点（`/auth/register`）缺乏防滥用保护 — 开放注册即开即用的机器人注册向量

**代码验证：**

```go
// interfaces/sso/options_passwd.go:80-89
// WithSelfServiceSignup enables the opt-in UNAUTHENTICATED self-service
// registration endpoint POST /auth/register (creates a user + sets a password,
// no identity verification beyond what the authenticator provides). Open
// signup is an abuse surface most enterprise deployments don't want (they
// invite users or JIT-provision via SCIM).
func WithSelfServiceSignup() Option {
    return func(srv *Server) { srv.signupEnabled = true }
}
```

注释明确承认 signup 是 "an abuse surface"，但：

| 防护机制 | 当前状态 |
|----------|----------|
| CAPTCHA（reCAPTCHA/hCaptcha/Turnstile） | ❌ 不存在 |
| 注册速率限制（per-IP / per-domain） | ❌ 不存在 |
| 邮箱域名白名单 | ❌ 不存在 |
| 邀请码/免注册码 | ❌ 不存在 |
| 邮箱验证要求 | ❌ 需要自行注入 |
| 注册即登录防重放 | ❌ 无 |

**风险场景：**
- 攻击者编写脚本对 `/auth/register` 每秒提交 100 个注册请求，每个请求使用不同的邮箱 + 密码
- 如果启用了 `WithSelfServiceSignup()`，服务器在几小时内积累数万虚假账户
- 虚假账户可用于：发送垃圾邮件（如果有邮件功能）、填满用户表导致存储膨胀、消耗 bcrypt hash 计算资源导致 CPU 耗尽

**对比标准做法：**
- Google/Auth0/FusionAuth：注册必须有 CAPTCHA 或邮箱验证
- Keycloak：注册速率限制默认启用（per-IP，可配置）
- Azure AD B2C：注册流程强制 CAPTCHA 或一次性密码验证

**建议修复（可选的扩展点，不侵入核心逻辑）：**
- 新增 `WithSelfServiceRateLimiter(limiter)` 选项（复用现有的 `RateLimiter` SPI）
- 新增 `WithSignupDomainAllowlist(domains ...string)` — 只允许特定邮箱域名的注册
- 新增 `WithSignupCAPTCHA(verifier)` — 集成的 CAPTCHA 验证 SPI
- 在 `handleSelfRegister` 中插入调用链：rate limiter → domain allowlist → CAPTCHA → 创建用户

---

## 方向二：Token Introspection 无结果缓存 — 微服务网格中的重复 JWT 解析开销

**代码验证：**

```go
// protocols/oauth/handle_introspect.go — 完整的 introspection 实现
// 路径：解析 token → 验证签名 → 检查过期 → 检查活跃状态 → 返回
```

**但全库零命中：**
| 搜索词 | 命中数 |
|--------|--------|
| `introspectCache` / `introspectionCache` | 0 |
| `introspect.*cache` / `cache.*introspect` | 0 |
| `IntrospectionCacheTTL` | 0 |

**每个 `/token/introspect` 调用的开销：**

1. **token 解码**：base64url 解码 3 个 JWT segment
2. **签名验证**：公钥查找（可能是 ECDSA/RSA/EdDSA asymmetric 签名验证，相对耗时）
3. **claims 验证**：`exp`、`iat`、`nbf`、`iss`、`aud`、`client_id` 等全部遍历验证
4. **活跃状态检查**：JTI replay store 查询 token 是否已被撤销
5. **返回完整 claims**：序列化为 JSON

**性能分析：**
- 在典型的微服务网格中，一个用户请求穿越 N 个服务（例如 API 网关 → 用户服务 → 订单服务 → 支付服务），每个服务都调用 introspect 验证 token
- 如果每个服务独立调用 introspect，就是 **O(N) 次完整 JWT 验证**
- 同一条 token 在 5 秒内被 5 个服务各验证 1 次 = 5 次 RSA/ECDSA 签名验证
- Ed25519 签名验证大约 50μs，但 ECDSA P-256 约 200μs，RSA 2048 约 250μs。5 次 = 1-1.25ms 纯 CPU
- 如果再考虑 JTI replay 查询（SQLite/Redis 往返），开销更大

**建议修复（非破坏性扩展）：**

```go
type IntrospectionCache struct {
    mu    sync.Mutex
    cache map[string]*cachedResult  // key = sha256(token) + audience
    ttl   time.Duration
}

func NewIntrospectionCache(ttl time.Duration) *IntrospectionCache
```

- 选项：`WithIntrospectionCache(ttl)`，默认关闭（0 = 无缓存）
- Key = `sha256(accessToken) + ":" + audience`（满足 oracle-safe 要求：不同 audience 不会命中错误的缓存结果）
- TTL 不超过 token 的剩余有效期（`min(ttl, exp-now)`）
- 当 token 被撤销时，通过 `cluster.Bus` 发布缓存失效事件

---

## 方向三：缺少运行时服务器状态端点 — 运维人员无单点获取服务器健康/版本/容量信息

**代码验证：**

**已存在的端点（只报告 binary health）：**
- `GET /health` — 返回 `{"status":"ok"}`（binary up/down）
- `GET /livez` — K8s liveness probe（binary alive/dead）
- `GET /readyz` — K8s readiness probe（binary ready/not-ready）

**不存在的端点：**
- `GET /api/v1/status` — 不存在的端点
- `GET /api/v1/debug` — 不存在的端点
- `GET /debug/vars` — 不存在的端点（Go 标准 `expvar`）

**不存在的信息：**

| 信息 | 获取方式 | 终端类型 |
|------|----------|----------|
| Build 版本 + Commit + 编译时间 | 启动日志 | 日志 |
| 服务器运行时间 | 无（需 Prometheus `process_start_time_seconds`） | 指标 |
| 活跃 session 计数 | 无（需 gRPC ListSessions 后 count） | gRPC |
| 活跃 token 计数 | 无 | 指标 |
| 各模块健康状态 | 无（/readyz 只聚合 binary ready） | — |
| 各 grant 类型调用次数 | 无 | 指标 |
| 连接状态（SQLite/Redis/etcd/Postgres） | 无 | — |
| 配置校验（运行时 config dump） | `sso-ctl config validate` 离线 | CLI |

**生产运维痛点：**
- 当 Prometheus 不可达时，`/api/v1/status` 是一个零依赖的替代信息源
- Incident response 时，"服务器运行多久了？什么版本？有没有连接到 Redis？"需要在 5 秒内回答，而不是翻日志 + 查 Grafana
- 运营团队需要 "所有子系统的健康一览"（SAML IdP、Redis 连接、SQLite 状态、etcd 连接）

**建议修复：**

```
GET /api/v1/status → {
  "version": "1.2.3",
  "commit": "abc123",
  "build_time": "2026-06-29T12:00:00Z",
  "uptime_seconds": 86400,
  "modules": {
    "saml_idp": "ready",
    "redis": "connected",
    "etcd": "connected",
    "sqlite": "ok"
  },
  "stats": {
    "active_sessions": 1234,
    "registered_clients": 56,
    "registered_users": 7890
  }
}
```

- 复用 `ReadBuildInfo()` 获取版本信息
- 注册 `HealthProbe` 列表（`WithHealthProbe(name, fn)` 选项已存在）
- `Store.Count()` 或 `ListByUser` 的计数聚合（后端已支持，只需要路由层）

---

## 方向四：没有 OIDC Conformance Test Suite 集成 — 企业采购需要 OP 认证

**代码验证：**

代码库中：
- `domain/permissions/permissionstest/` — 有 `ConformanceSuite` 框架测试 permissions 后端
- `test/testkit/` — 有测试工具库
- https://op.certification.openid.net/ — **没有集成痕迹**
- OIDC 相关功能：authorization code、implicit、hybrid、form_post、JARM、back-channel logout、front-channel logout、CIBA、claims parameter、request object、discovery — 都已实现
- 但没有一个**端到端的 OIDC Conformance 测试**运行在 CI 中

**为什么需要：**
1. **企业采购要求**：OIDC OP 认证是大型组织的采购前提条件。认证等级（OP Basic、OP Implicit、OP Hybrid、OP Config、OP Dynamic、OP FormPost、OP Session、OP Logout）直接影响采购决策
2. **回归保护**：每次修改授权流程后，运行 conformance 测试确保没有偏离协议
3. **浏览器 + 第三方 cookie 变更**：2024-2026 年浏览器大幅限制第三方 cookie，OIDC Session / iframe 相关测试需要持续验证

**现有能力与 conformance profile 映射：**

| OIDC Profile | 状态 | 所需工作 |
|-------------|------|----------|
| OP Basic (code) | ✅ 支持 | 自动化测试 |
| OP Implicit (token) | ✅ 支持 | 自动化测试 |
| OP Hybrid | ? | 检查 hybrid 流支持 |
| OP Config | ✅ Discovery | 自动化测试 |
| OP Dynamic | ✅ DCR | 自动化测试 |
| OP FormPost | ✅ 支持 | 自动化测试 |
| OP Session | ❌ 无 `session_state`（见 round 6） | 先加 session_state |
| OP Logout | ✅ end_session + BCL + FCL | 自动化测试 |
| OP CIBA | ✅ 支持 | 自动化测试 |
| OP JARM | ✅ 支持 | 自动化测试 |

**建议修复：**
- 在 `test/oidc-conformance/` 目录下添加 conformance 测试配置（非代码 hook，而是 docker compose + 环境变量配置）
- 集成 [oidc-conformance](https://gitlab.com/openid/conformance-suite) 的 docker 镜像
- CI 中增加 `make conformance` target（可选的，不是 gate）
- 文档记录：`docs/oidc-conformance.md` — 如何本地运行、哪些 profile 已测试通过

---

## 方向五：Fuzz 测试覆盖率为零 — OAuth/SAML/JWT/URL 解析层缺少攻击面测试

**代码验证：**

```bash
$ find . -name "*_fuzz.go"  # 零命中
```

| 搜索项 | 命中数 |
|--------|--------|
| `fuzz`（Go files, non-test） | 0 |
| `Fuzz`（Go files） | 0 |
| `go-fuzz` | 0 |
| `go test -fuzz` | 0 |
| `fuzz.*test` | 0 |

**高风险 fuzz 目标（建议优先）：**

| 目标 | 位置 | 风险 |
|------|------|------|
| OAuth 参数绑定 | `protocols/oauth/oauthwire/bind.go` | POST body 解析，RFC 6749 参数布局 |
| JWT 头部解析 | `shared/security/securityverify/jws_verify.go` | alg/typ/kid 解析，恶意头部可触发 panic |
| 跳转 URL 验证 | `protocols/oidc/handle_end_session.go` | 开放跳转验证绕过 |
| SAML Response 解析 | `infrastructure/saml/sp/authenticator.go` | XML dsig 解析，XXE |
| Federation Entity Statement | `domains/federation/fetcher.go` | 外部获取的 JWT 反序列化 |
| 客户端 metadata 验证 | `protocols/oauth/oauthvalidate/dcr_validate.go` | 任意 JSON metadata 字段 |
| URL/Redirect URI 验证 | `interfaces/sso/server_login.go` | redirect_uri 白名单绕过 |

**Go 内置 fuzz 引擎（原生支持，零依赖）：**
Go 1.18+ 的 `testing.F` 原生 fuzz 支持，不需要 `go-fuzz` 外部工具。代码中已有 `internal/` 包测试基础设施。

**建议修复：**

```go
// 示例：protocols/oauth/oauthwire/fuzz_test.go
func FuzzBindOAuthParams(f *testing.F) {
    f.Add("application/x-www-form-urlencoded", "grant_type=authorization_code&code=abc")
    f.Add("application/json", `{"grant_type":"authorization_code","code":"abc"}`)
    f.Fuzz(func(t *testing.T, ct, body string) {
        req := &OAuthParams{}
        err := BindOAuthParams(req, ct, strings.NewReader(body))
        // err != nil 是合法的（malformed input），panic 是 bug
    })
}
```

```go
// 示例：shared/security/securityverify/fuzz_test.go
func FuzzJWSVerify(f *testing.F) {
    f.Add("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.signature")
    f.Fuzz(func(t *testing.T, compact string) {
        JWSVerify([]byte(compact), &jwkCache{...})
        // panic/recover: 不应该崩溃
    })
}
```

优先级：`bind.go` > `dcr_validate.go` > `handle_end_session.go` > `saml_response.go` > `federation_fetcher.go`

---

## 优先级排序

| 方向 | 价值 | 工作量 | 建议顺序 |
|------|------|--------|----------|
| **① 注册防滥用** | 高（直接安全缺口） | M | **第 1 Sprint** |
| **② Introspection 缓存** | 中-高（性能优化，微服务网格场景） | S | **第 1 Sprint 并行** |
| **③ 状态端点** | 中（运维体验） | S | **第 1 Sprint 并行** |
| **④ OIDC Conformance** | 中-高（企业采购刚需） | M | 第 2 |
| **⑤ Fuzz 测试** | 中（质量保障） | M | 持续进行 |

**一句话：** ① 公开注册端点无 CAPTCHA/限流/域名白名单，是无需认证即可批量创建账户的直接攻击面 → ② 微服务网格中每个服务独立调用 `/token/introspect` 导致 O(N) 次冗余 JWT 签名验证，短时间缓存可消除重复开销 → ③ 运维人员需要能从单一 HTTP 端点获取 build 版本、运行时间、模块健康状态、活跃会话数等信息，而非从日志 + Prometheus + gRPC 三个来源拼凑 → ④ 无 OIDC Conformance Test Suite 集成意味着企业采购安全问卷的认证项无法打勾，且协议回归无自动化防护 → ⑤ 零 fuzz target 意味着 OAuth parameter binding、JWT header 解析、SAML XML 解析等攻击面没有自动化异常检测。
