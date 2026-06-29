# 分析第 4 轮 — HTTP 安全头 / KDF 成本对齐 / 跨区域 / SPIFFE / Go 模块版本

> 扫描日期：2026-06-29
>
> 前三次路线：① 产品/协议全局 → ② `time.Now()`/集群/Postgres → ③ 刷新令牌并发/事件流/配置热重载
>
> 本次聚焦：之前三轮从未触及的网络层安全、密码学基元、跨区域拓扑、工作负载身份、供应链保障

---

## 方向一：HTTP 安全响应头系统性缺失 — 多处端点无防护头

**代码验证：**

**已设置 `X-Frame-Options: DENY` 的路径（正确）：**
- `protocols/oidc/jarm.go:157`（JARM response）
- `protocols/oidc/oidcsupport/form_post.go:59`（Form Post HTML）
- `interfaces/sso/server_backchannel_logout.go:401`（back-channel logout）
- `interfaces/sso/server_discovery.go:285`（silent renewal iframe）

**所有不设安全头的地方：**

| 路径 | 输出 | 风险 |
|------|------|------|
| `POST /auth/send-code` | JSON | 无 `Cache-Control` |
| `/auth/mfa` | JSON | 无 `Cache-Control` |
| `/auth/forgot-password` | JSON | 无 `Cache-Control` |
| `/auth/reset-password` | JSON | 无 `Cache-Control` |
| 所有 `/api/v1/admin/*` | JSON | 无 `Cache-Control` |
| 所有 gRPC REST gateway | JSON | 无安全头 |
| SSF receiver `/ssf/receive` | JSON | 无安全头 |
| SAML 端点 `/saml/*` | auto-POST HTML | 无 `X-Frame-Options` |
| `/userinfo` | JSON（含 PII） | 无 `Cache-Control` |

**全局缺失的安全头（0 命中）：**
- `X-Content-Type-Options: nosniff` — 全无
- `Referrer-Policy: no-referrer` — 全无
- `Strict-Transport-Security`（HSTS） — 全无
- `Cache-Control: no-store` 仅在 `/token`、`/introspect`、`/revoke` 等凭据端点有

**风险场景：**

1. **Form Post Response Mode**（`/auth/login?response_mode=form_post`）返回自动提交 HTML。当前 `form_post.go` 设了 `X-Frame-Options: DENY`，但 **SAML IdP 的 auto-POST HTML**（`infrastructure/saml/idp/slo_handler.go`）未设 → 点击劫持。

2. `/userinfo` 返回用户 PII（姓名、邮箱、手机号）。无 `Cache-Control: no-store` ⇒ CDN/浏览器可缓存 → 公共终端 PII 泄露。

3. HSTS 完全缺失。OAuth/OIDC 重定向链（`/auth/login` → 外部 IdP → callback）可能被中间人降级。

**建议修复：** 全局 HTTP 中间件统一添加安全头选项 `sso.WithSecurityHeaders()`（默认启用 `X-Content-Type-Options`、`Referrer-Policy`、`X-Frame-Options`、`Strict-Transport-Security`）。

---

## 方向二：密码 Key Derivation 成本不匹配 — 抗枚举 dummy hash 与真实 hash 成本不同

**代码验证：**

```go
// domains/authenticators/stored_hash_verifier.go:12-19
// DefaultStoredHashDummyCost = 10（bcrypt.DefaultCost）
```

`StoredHashVerifier` 在用户不存在时执行成本相同的 bcrypt dummy hash，使未知用户的耗时与已知用户匹配。

**但存在缺口：**

- 真实用户密码可能是 **bcrypt cost=12**（从 Auth0/Keycloak 使用 `sso-ctl import` 导入）或 **argon2id**
- Dummy hash 固定为 `bcrypt cost=10`（`DefaultCost`）
- Dummy cost < 真实 cost ⇒ 未知用户响应更快 ⇒ **计时侧信道可区分"用户不存在"与"用户存在但密码错误"**
- 这直接违反 `AGENTS.md §2` 的 anti-enumeration 要求

相关代码：
- `domains/authenticators/password_hash.go:25-27` — 支持 `argon2id` / `pbkdf2-sha256` / `pbkdf2-sha512`
- `domains/authenticators/rehash.go` — lazy rehash 在登录时把非 bcrypt 升级为 bcrypt
- `domains/authenticators/stored_hash_verifier.go:115` — 预置 hash 升级到 bcrypt

**建议修复：** 在验证用户凭证时，读取真实存储 hash 的格式和成本参数，动态生成匹配的 dummy 计算。工作量 < 50 行，安全信号高。

---

## 方向三：跨区域部署一致性 — 当前代码和部署拓扑无任何支持

**代码验证：**

- `domains/region/` — 有数据驻留 SPI（`resolver.go`、`middleware.go`）
- 全文 grep 无 `failover` / `Failover` — 0 命中
- 全文 grep 无 `disaster.*recovery` / `DR` — 0 命中
- 全文 grep 无 `multi.*region` / `cross.*region` — 0 命中
- `platform/cluster/memory/bus.go` — 单进程；`platform/cluster/etcd/bus.go` — 只在单 etcd 集群内工作
- `signingkeys/` — per-region etcd，区域间不可见
- session 写入 region-local store（SQLite/Redis），跨区域无 session 共享
- `deployment.md §6-distributed-architecture` 写了 Tier A/B/C，无 Tier D（多区域）

**缺失的场景：**

1. **无跨区域 Bus**：region A 的 tenant 暂停事件不会传播到 region B
2. **无跨区域 JWKS 联邦**：各区域 signing keys 隔离，region A 停服后 token 不能被 region B 验证
3. **无跨区域 session 共享**：用户 region A 认证、请求落到 region B → `session_invalid`
4. **无故障转移**：某区域 SSO 停服，流量不能自动路由到其他区域

**建议设计：**

1. **跨区域 JWKS 联邦**：核心 signing key 跨区域共享（KMS 管理），各区域缓存的 JWKSCache 拉取中心化 JWKS
2. **跨区域事件广播**：`cluster.Bus` 增加区域间路由（当前 bus 只在一个 etcd 集群内工作）
3. **Buffer 区域化**：`geo` middleware 已区域感知，可基于 geo 域路由到最近 SSO 区域
4. **数据驻留 + DR**：`region` 包已做数据驻留路由。加上 failover 模式

---

## 方向四：工作负载身份桥的不对称 — SPIFFE JWT-SVID 只能入不能出

**代码验证：**

**入方向已实现：**
- `shared/security/securityverify/spiffe_svid.go` — SPIFFE JWT-SVID ⇒ `Subject` inbound，完整验签（SPIRE trust bundle）、audience 检查、trust domain 校验
- `interfaces/sso/server_native_sso.go` — token-exchange 接受 `subject_token_type=urn:ietf:params:oauth:token-type:jwt` + SPIFFE JWT-SVID
- `interfaces/sso/options_security.go:53-54` — strict aud-binding 对 SPIFFE SVID 有效

**出方向缺失（对称缺口）：**

SSO 服务器自身不能出示 SPIFFE JWT-SVID 给其他网格服务验证。Envoy 的 `envoy.filters.http.jwt_authn` 可以验证 SPIFFE SVID，但 SSO 作为网格内工作负载没有本地 SVID 签发。

**建议修复：**
- 添加 SPIFFE Workload API 集成（UNIX socket 连接 SPIRE Agent，获取实时 SVID + bundle）
- `WithSPIFFEWorkloadAPI(socketPath)` 选项：SVID 周期性轮换
- 与现有 SPIFFE inbound 侧对称，完成"SSO 既是网格身份的验证方，也是网格身份的持有方"的闭环

---

## 方向五：Go 模块依赖版本兼容性保障 — `cmd/sso-mcp` 未在 CI 中

**代码验证：**

CI（`.github/workflows/ci.yml:44-84`）：
```yaml
jobs:
  test:
    steps:
      - run: go test -race -count=1 ./...  # 只对根模块
  modules:
    strategy:
      matrix:
        module:
          - infrastructure/kms/awskms
          - infrastructure/kms/gcpkms
          - infrastructure/redis
          - infrastructure/saml
          - ...
```

**已发现的问题：**

1. **`cmd/sso-mcp` 不在 CI modules matrix 中**（当前 `feat/sso-mcp` 分支有待修复）
2. **零定期 `go mod tidy -check`** — 根模块和 12 子模块的 `go.sum` 不会因 `tidy` 不一致而失败
3. **零 `go mod verify`** — 无 `go.sum` 篡改检测（供应链安全）
4. **CGO 模块跳过** — `infrastructure/kms/pkcs11/` 依赖 CGO，CI 中默认不构建，但无 CGO 回退构建命令
5. **`infrastructure/saml/`** 依赖 `github.com/crewjam/saml`，该库自身依赖 `goxmldsig`（已知 XXE/DoS 攻击面）

**建议修复：**
1. 将 `cmd/sso-mcp` 加入 CI `modules` matrix
2. 每个嵌套模块的 CI 步骤加入 `go mod tidy -check`
3. 增加 `go mod verify` 步骤
4. 新增 CGO 跳过的 `pkcs11` 模块 CI 编译（`CGO_ENABLED=0 go build -tags no_pkcs11 ./...`）
5. 定期 `go list -m -json all` 审计传递依赖

---

## 优先级排序

| 方向 | 价值 | 工作量 | 建议顺序 |
|------|------|--------|----------|
| **① HTTP 安全头系统** | 高（安全合规刚性） | S | **最先 Sprint** |
| **② 密码 KDF 成本对齐** | 高（anti-enumeration oracle） | S | **同 Sprint ①** |
| **③ 跨区域部署** | 中-高（全球 SaaS 刚需） | L（架构级） | Roadmap 级 |
| **④ SPIFFE 工作负载身份出向** | 中（网格原生故事补完） | M | 第 4 |
| **⑤ Go 模块版本保障** | 中（供应链安全） | S | 可并行 |

**一句话：** ① 是补全产品级 Web 安全门禁（HSTS/CSP/XFO 一键开启）→ ② 是 anti-enumeration oracle 的已确认缺口（dummy bcrypt cost ≠ 真实 cost 可被计时攻击利用）→ ③ 使产品能部署到全球多区域、满足 GDPR 数据驻留 + 可用性要求 → ④ 完成 SPIFFE 工作负载身份从"只能验证"到"也能出示"的闭环 → ⑤ 保障 12 个嵌套模块不因依赖不一致在 CI 中静默回归。
