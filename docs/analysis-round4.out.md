以下是基于实际代码库对所有五个方向的分析验证：

---

## 分析结果

### 方向一：HTTP 安全响应头 — **部分不准确**

**中间件已存在**，并非缺失：

```
internal/handler/security_headers.go  →  SecurityHeaders()
interfaces/sso/options_passwd.go:395  →  WithSecurityHeaders()
```

安全头中间件设置：
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`（仅限 TLS）

它通过 `server_routes.go:377-378` 以最内层路由器的包装形式连接——因此它会覆盖所有通过 SSO 路由器的端点。**但默认情况下为关闭状态**（需要显式调用 `WithSecurityHeaders()`）。

**您在报告中指出的多个端点已经设置了 `TokenNoStoreHeaders`：**
- `/auth/forgot-password` — ✅ `password_reset.go:23`：`middleware.TokenNoStoreHeaders(ctx)`
- `/auth/reset-password` — ✅ `password_reset.go:86`：`middleware.TokenNoStoreHeaders(ctx)`
- `/auth/mfa` — ✅ `server_mfa.go:175`：`tokenNoStoreHeaders(ctx)`
- `/auth/login` — ✅ `server_login.go:127`：`tokenNoStoreHeaders(ctx)`（通过 `bootstrapLoginRequest`）
- `/userinfo` — ✅ `handle_userinfo.go:43`：`d.TokenNoStoreHeaders(ctx)`
- SAML SLO — ✅ `slo_handler.go:71`：`noStore(w)` 设置 `Cache-Control: no-store`

**关于 `/auth/send-code` 的差异被证实**：
- `handleSendCode`（`server_logout.go:122`）**没有**设置 `TokenNoStoreHeaders` — 这是一个真正的缓存漏洞

**关于 SAML 自动提交表单的 `X-Frame-Options` 差异被证实**：
- `slo_handler.go` 在渲染 `sloAutoPostForm` HTML 模板时没有设置 `X-Frame-Options: DENY`（而 `/auth/login?response_mode=form_post` 通过 `form_post.go:59` 设置了）

**验证关键点**：所有凭据端点（`/token`、`/introspect`、`/revoke`、`/par`）通过 `tokenNoStoreHeaders` / `setBearerChallenge` 接收 `Cache-Control: no-store`。相关的 [AGENTS.md §2 / Wire Contracts](file:///home/dwp/snaplink/AGENTS.md) 规则已执行。

---

### 方向二：KDF 成本 — **部分不准确；代码比报告指出的更成熟**

**报告称** `DefaultStoredHashDummyCost = 10`（`bcrypt.DefaultCost`）

**实际：**

```go
// stored_hash_verifier.go:15
const DefaultStoredHashDummyCost = 12
```

代码注释明确解释了从 `10` 提升到 `12` 的原因（来自代码库的默认成本不匹配，以及 `12` 是现代 bcrypt 进口哈希的基准）。此外，**`WithHasher`** 选项（第 44-48 行）使虚拟哈希成本能够动态跟踪操作员配置的哈希器成本：

```go
func WithHasher(h Hasher) StoredHashOption {
    return func(c *storedHashConfig) { c.hasher = h }
}
```

当设置了显式的 `WithStoredHashDummyCost` 时，它会胜出；否则使用 `hasher.Cost()`；否则回退到 `DefaultStoredHashDummyCost`（12）。

**但存在一个真正的残留缺口**：如果导入的哈希是 argon2id/PBKDF2，交叉格式的虚拟哈希（始终是 bcrypt）永远无法精确匹配——生产者和虚拟哈希在不同的算法上运行。代码注释（第 14-19 行）明确承认了这一点。**真正的修复是执行与真实哈希相同 KDF 的动态虚拟计算。** 到目前为止，这仍然是一个未解决的问题。

---

### 方向三：跨区域 — **准确**

`domains/region/` 提供了基本的 SPI 骨架：
- `Resolver` 接口（`ConfigPinnedResolver`、`HeaderResolver`、`ChainResolver`）
- `PolicyStore` 接口（数据驻留策略）
- 处理程序上下文的中间件设置

**缺失**项与报告所描述的一致：
- 无跨区域 `cluster.Bus`
- 无跨区域 JWKS 联邦
- 无跨区域会话共享
- 无故障转移/灾难恢复拓扑
- 无 Tier D 部署模型

这是一个需要全局架构改变的路线图级项目。

---

### 方向四：SPIFFE — **准确**

入站方向（`securityverify/spiffe_svid.go`）完整：
- SPIFFE URI 解析 + 验证
- JWT-SVID 签名验证（针对 SPIRE 信任包）
- 严格的受众绑定 + 信任域检查
- 通过 `server_native_sso.go` 的令牌交换集成

出站方向完全缺失——没有 SPIRE 工作负载 API 集成（UNIX 套接字连接以获取实时 SVID）。SSO 无法向网格同伴出示 SPIFFE JWT-SVID。正如报告所指出的，这是对称性缺口。

---

### 方向五：Go 模块 — **部分不准确；问题已修复但留下隙缝**

**报告称** `cmd/sso-mcp` 不在 CI 模块矩阵中：

```yaml
# ci.yml 第 66 行 — modules 任务
matrix:
  module:
    - kms/awskms
    ...
    - cmd/sso-mcp         # ✅ 已经包含！
```

同样适用于 `govulncheck`、`gosec` 和 `lint` 矩阵——所有这些都包含 `cmd/sso-mcp`。自 CI 文件撰写以来，这个具体的断言已经过时。

**真正缺失的间隙：**
1. ❌ **没有 `go mod tidy -check`** — 没有任何工作流因 `go.sum` 陈旧或 `go.mod` 不一致而失败
2. ❌ **没有 `go mod verify`** — 无 `go.sum` 篡改检测（供应链安全）
3. ⚠️ **PKCS#11 在没有 CGO 的 CI 中已处理**（`CGO_ENABLED: ${{ matrix.module == 'kms/pkcs11' && '1' || '' }}`），但 `CGO_ENABLED=0 go build -tags no_pkcs11` 回退未测试

---

## 按严重性排序的关键发现汇总

| # | 发现问题 | 文件 | 严重性 |
|---|---------|------|--------|
| 1 | `/auth/send-code` 缺少 `Cache-Control: no-store` | `interfaces/sso/server_logout.go:122` | **高** — 凭据相关代码发送端点；如果被 CDN/代理缓存，可能会暴露重放代码 |
| 2 | SAML SLO 正在渲染的 HTML 自动提交表单缺少 `X-Frame-Options: DENY` | `infrastructure/saml/idp/slo_handler.go` (在 `noStore` 行之后附近) | **中** — 通过 SAML 响应的点击劫持 |
| 3 | argon2id/PBKDF2 导入的虚拟 bcrypt 成本不匹配（交叉格式时序间隙） | `domains/authenticators/stored_hash_verifier.go:12` | **中** — 承认的缺口；需要动态的 KDF 匹配虚拟 |
| 4 | 安全头中间件默认关闭 | `interfaces/sso/options_passwd.go:395` | **中** — 部署在没有 `WithSecurityHeaders()` 的情况下会错过 HSTS/XFO/CTO/Referrer-Policy |
| 5 | 跨区域 JWKS 联邦 / 总线 / 会话共享 / DR 不存在 | `domains/region/` | 路线图 |
| 6 | SPIFFE 工作负载 API 出站集成缺失 | — | 路线图 |
| 7 | CI 缺乏 `go mod tidy -check` | `.github/workflows/ci.yml` | **低-中** — `go.sum` 可能会与 `go.mod` 不一致 |
| 8 | CI 缺乏 `go mod verify` | `.github/workflows/ci.yml` | **低-中** — 无供应链完整性检查 |
