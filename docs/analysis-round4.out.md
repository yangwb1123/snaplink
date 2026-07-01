Now I have enough evidence to provide a comprehensive analysis. Let me compile my findings:

## 第 4 轮分析评审 — 事实核查与修正

经过对代码库的详细验证，该分析文档存在**多处事实错误**。以下是逐项核查结果：

---

### 方向一：HTTP 安全头 — **大部分错误**

文档声称这些安全头"全局缺失（0 命中）"，但实际情况：

**已实现的防护（文档未提及）：**

1. **全局安全头中间件已存在**：
   - `internal/handler/security_headers.go` 实现了完整的 `SecurityHeaders` 中间件
   - 添加 `X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`、`Referrer-Policy: no-referrer`
   - TLS 请求添加 `Strict-Transport-Security: max-age=31536000; includeSubDomains`
   - 通过 `WithSecurityHeaders()` 选项暴露，在 `server_routes.go:377-378` 已接入

2. **`/userinfo` 已有 `Cache-Control: no-store`**：
   - `protocols/oidc/handle_userinfo.go:46` 调用 `d.TokenNoStoreHeaders(ctx)`

3. **`/auth/mfa` 已有 `no-store`**：
   - `interfaces/sso/server_mfa.go:173` 调用 `tokenNoStoreHeaders(ctx)`

4. **`/auth/login` 已有 `no-store`**：
   - `interfaces/sso/server_login.go:98` 调用 `tokenNoStoreHeaders(ctx)`

5. **`/auth/forgot-password` 和 `/auth/reset-password` 已有 `no-store`**：
   - `protocols/selfservice/password_reset.go:23` 和 `:86` 调用 `middleware.TokenNoStoreHeaders(ctx)`

6. **SAML 端点已有 `no-store`**：
   - `infrastructure/saml/saml.go:300` 和 `saml_sp_slo.go:34` 设置 `Cache-Control: no-store`

**唯一有效的关切：**

- `WithSecurityHeaders()` 是**可选的**，未在 `cmd/sso-server` 二进制文件中默认启用
- `/auth/send-code` 的 `handleSendCode`（`server_logout.go`）未显式调用 `tokenNoStoreHeaders`，但如果启用安全头中间件会获得防护

**修正后的优先级**：从"最先 Sprint"降为"使安全头中间件成为默认配置"（工作量从 S 降为 XS）。

---

### 方向二：KDF 成本对齐 — **完全错误**

文档声称 `DefaultStoredHashDummyCost = 10`（bcrypt.DefaultCost），但实际代码：

```go
// domains/authenticators/stored_hash_verifier.go:22
const DefaultStoredHashDummyCost = 12
```

**代码注释明确说明**：

> "DefaultStoredHashDummyCost = 12（bcrypt.DefaultCost 之上），因为导入的 hash 通常是现代成本（12+）或非 bcrypt KDF；cost=10 的 dummy 会比真实验证更快完成，泄露'此用户名未知'作为计时侧信道。"

**已实现的机制**：

1. `WithStoredHashDummyCost(cost int)` — 显式固定成本
2. `WithHasher(h Hasher)` — 自动匹配 hasher 的当前成本
3. 优先级：显式固定 > hasher 成本 > 默认值 12

**修正**：此方向已完全解决，无需修复。从优先级列表中移除。

---

### 方向三：跨区域部署 — **正确**

验证结果：

- `grep -rn "failover\|disaster.*recovery\|multi.*region"` — 0 命中
- `platform/cluster/memory/bus.go` 和 `etcd/bus.go` 仅在单集群内工作
- `signingkeys/` per-region etcd，区域间不可见
- 无跨区域 session 共享
- `deployment.md` 无 Tier D（多区域）

**修正**：此方向正确，是合法的架构缺口。优先级保持。

---

### 方向四：SPIFFE 出向身份 — **正确**

验证结果：

- 入向已实现：`shared/security/securityverify/spiffe_svid.go` 完整验签
- 出向缺失：无 SPIFFE Workload API 集成（UNIX socket 连接 SPIRE Agent）
- `grep -rn "spiffe.*workload\|WorkloadAPI\|SPIFFEWorkloadAPI\|spire.*agent"` — 0 命中

**修正**：此方向正确。优先级保持。

---

### 方向五：Go 模块版本保障 — **部分错误**

**文档错误**：

1. **`cmd/sso-mcp` 不在 CI matrix**：正确，但它在 `feat/sso-mcp` 分支，尚未合入 main
2. **`infrastructure/kms/pkcs11/` 依赖 CGO，CI 中默认不构建**：**错误**
   - CI matrix 已包含 `kms/pkcs11`
   - 针对该条目安装 `libltdl-dev` 并设置 `CGO_ENABLED=1`
   - 构建命令：`go build ./... && go test -race -count=1 ./...`

**正确的关切**：

1. CI 未运行 `go mod tidy -check` — 合法缺口
2. CI 未运行 `go mod verify` — 合法缺口
3. 无定期传递依赖审计（`go list -m -json all`）— 合法关切

**已有的保障（文档未提及）**：

- `govulncheck` 作业覆盖根模块 + 所有嵌套模块
- `gosec` 安全扫描覆盖根模块 + 所有嵌套模块
- `golangci-lint` 覆盖根模块 + 所有嵌套模块
- `dependabot.yml` 自动处理 Go 模块更新

**修正后的优先级**：从"可并行"调整为"添加 `go mod tidy -check` 和 `go mod verify` 到 CI"（工作量 XS）。

---

## 修正后的优先级排序

| 方向 | 原始优先级 | 修正后优先级 | 理由 |
|------|------------|--------------|------|
| **① HTTP 安全头系统** | 最先 Sprint (S) | **XS：使 `WithSecurityHeaders()` 成为默认** | 中间件已存在，只需在 `cmd/sso-server` 中默认启用 |
| **② 密码 KDF 成本对齐** | 同 Sprint ① (S) | **已解决，移除** | 默认成本已是 12，且已有 `WithHasher` 自动匹配机制 |
| **③ 跨区域部署** | Roadmap 级 (L) | **保持 Roadmap 级** | 合法的架构缺口 |
| **④ SPIFFE 出向身份** | 第 4 (M) | **保持第 4** | 合法的对称缺口 |
| **⑤ Go 模块版本保障** | 可并行 (S) | **XS：添加 `tidy -check` + `verify`** | 部分关切有效，但 pkcs11 已在 CI 中 |

---

## 一句话总结

第 4 轮分析的 **① 和 ② 基于过时或错误的代码理解**——安全头中间件和 KDF 成本对齐机制均已实现，只需将安全头中间件设为默认配置（①）即可关闭缺口；② 已完全解决。**③④⑤ 的分析基本正确**，其中 ⑤ 的 pkcs11 CI 声称错误。建议优先完成 XS 工作量的配置变更（使安全头默认启用 + 添加 `go mod tidy -check`），然后聚焦 ③④ 的架构级工作。
