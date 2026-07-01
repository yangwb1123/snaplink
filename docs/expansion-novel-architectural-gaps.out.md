至此已完成全部 5 个方向的代码验证。以下是我的评估：

---

## 代码验证结果总结

### 方向一：Feature Interaction Validation — ✅ **确认，且比你描述的范围更急需**

`interfaces/sso/sso_newserver.go:23` 中 `NewServer` 末尾 **没有任何 `validateServer()`**。90+ 个 option 全部无交叉校验。但有一个重要发现：

已有 `WithReadyCheck` 基础设施（`interfaces/sso/options_misc.go:298-350`）和两个具体的 Ready 方法：
- `SigningKeyAggregationReady()` in `signing_key_aggregation_loop.go:117`
- `InvalidationBusReady()` in `server_invalidation.go:219`

**这意味着 "Ready check 框架"已经有了** —— 缺失的是：
1. 将这些 Ready per-check 聚合为 `Server.Ready()` 的统一入口
2. **Feature interaction 的声明式依赖矩阵**（如 FAPI ↔ PAR/JAR/DPoP、BCL ↔ SubjectClientIndex）
3. `/readyz`（`server_routes.go:342` 只是路由注释，真正的聚合逻辑尚未实现）

**你的 claim 不仅正确，而且比描述的更 urgent**：已有框架只差一个 `validateServer()` 函数和一个声明式 feature 依赖 map。工作量比"M"更接近 **S**（~1 天核心逻辑）。

---

### 方向二：Admin API Surface Coherence Gap — ✅ **确认，但有一个结构上的好消息**

所有你列出的 HTTP-only 端点均 **已确认存在于 `interfaces/sso/server_routes_admin.go`**，且对应的 handler 分布在：
- `server_admin_handlers.go` (consents, MFA, password reset, connections, tenant members, invitations...)
- `server_admin_tokens.go` (admin bearer token lifecycle)
- `server_admin_sessions.go` (global session listing)
- `server_backup.go` (SQLite backup trigger)

而 proto 定义的只有 7 个 service（clients, users, permissions, tenants, tokens, snapshots, releases）。

**好消息**：所有路由的注册都是 **conditional gating**（`if s.consentStore != nil { ... }`），这意味着迁移到 proto 时不会破坏现有功能。但你的核心论点 —— "一个只通过 gRPC 集成的 operator 无法完成 helpdesk 操作" —— **完全成立**。proto admin/v1/users.proto 只定义了 CRUD + sessions，没有 MFA/consent/password reset 的任何 RPC。

**数据点补充**：proto 文件 header 包含一个版权声明"6-month deprecation window"，但这是 **纯文本注释**，不是代码强制。

---

### 方向三：Playground Supply Chain Risk — ✅ **确认，需要紧急修复**

`go build ./docs/examples/playground/` ✅ 成功编译。无 `//go:build` tag。硬编码密钥：
- `main.go:80`: `demoTOTPSecret = []byte("12345678901234567890")`（RFC 6238 §B 测试密钥）
- `main.go:62-63`: `demoUser = "alice"`, `demoPassword = "secret"`
- `main.go:64-65`: `demoClient = "playground-client"`, `demoSecret = "playground-secret"`

**重要 nuance**：TOTP 密钥只用于 MFA 演示流程，**不用于 token 签名**。Token 签名使用 `defaultimpl.NewEd25519JWTIssuer`（`main.go:107-110`），该 issuer 在 playground 启动时随机生成 Ed25519 密钥。所以**令牌不会被硬编码密钥绕过**。但 MFA 流程和整个可安装二进制 + 硬编码凭据的风险仍然成立。

**供应链风险的精确评估**：中等（不是灾难性，但仍应修复）。

你建议的 Phase 1（加 build tag + Makefile 保护）确实可以在 30 分钟内完成。

---

### 方向四：Configuration Incoherence Detection — ✅ **确认，但需要修正一个重要事实**

**最大发现**：`--validate-only` flag **已经存在**（`cmd/sso-server/main_wiring.go:53`），并且在 `cmd/sso-server/main.go:94-97` 有完整实现。但它只做 YAML 解析验证（调用 `config.LoadFromSources`），**不做任何跨块语义验证**。

**需要纠正的点**——`geo.backend=maxmind` 的 claim：

你的分析说"服务器回退到 no-op geo provider"——**这与实际代码不符**。

`cmd/sso-server/serverbuildstore/build_tenant_geo_region.go:132-150` 中的 switch：
```go
switch strings.ToLower(cfg.Geo.Backend) {
case "", "static":
    // ... build static provider ...
default:
    return nil, fmt.Errorf("unknown geo.backend %q", cfg.Geo.Backend)
}
```

配置 `maxmind` 会**报错启动失败**，不是静默降级！而且有一个专门的测试 `TestBuildGeoProvider_UnknownBackendErrors`（`subsystem_builders_test.go:333`）验证这一点。

**但你分析的其他模式正确**，特别是：

| 模式 | 验证结果 |
|------|---------|
| `self_service.signup=true` + `require_verification` + 无 `EmailVerificationSender` | **运行时 panic**（nil pointer dereference），而非静默降级。`handleMandatoryVerificationSignup` → `issueVerificationToken` 中直接调 `d.EmailVerificationSender().SendEmailVerificationToken(...)` 无 nil 检查 |
| `admin.enabled=true` + 无 `permissions.Provider` | 正确。`Interfaces/admin/middleware.go` 依赖 Provider，无启动时检查 |
| `federation.auto_registration=true` + 无 federation signer | 正确。有 partia l validation in `build_federation.go:30` 但仅限 trust mark |

---

### 方向五：API Version Negotiation — ✅ **完全确认，且情况比你描述的更空白**

`grep -rn "Accept-Version\|X-API-Version\|Sunset\|api.version" --include="*.go" interfaces/ proto/ cmd/` → **零命中**（排除了 protoc 生成的 Deprecated 方法注释）。

Proto 文件的 header 注释承诺了"6-month deprecation window"，但：
1. 这是纯文本，**没有代码强制**
2. 没有 `v2alpha` 包路径（`grep v2alpha proto/admin/v1/*.proto` → 零命中）
3. ADR-0008 设计了版本策略但**从未实现**

**精确风险**：低概率但高影响。作为 SSO 平台，所有客户端都依赖稳定的 `/token`、`/.well-known/openid-configuration`、`/api/v1/admin/*` 端点。**第一次 breaking change 发生时，没有迁移路径。** 你关于 Auth0 3 年 / Okta 5 年 / Keycloak 2 年迁移窗口的类比非常准确。

---

## 修正后的优先级建议

基于代码验证，我调整了工作量评估和风险等级：

| 修正 | 方向 | 工作量 | 风险 | 关键发现 |
|------|------|--------|------|---------|
| ⬆ **P0** | **方向三：Playground 供应链风险** | **S（~30 min）** | 中 | 编译成功，无 build tag，硬编码凭据 |
| ⬆ **P0** | **方向一：Feature Interaction 验证** | **S~M（~1 天）** | **高** | Ready check 框架已存在，只需添加 `validateServer()` + 声明式依赖 map。**启动时无声失败 → 上线后 500** |
| → **P1** | **方向四：Config 跨块验证** | **M（~2 天）** | 中 | `--validate-only` 功能骨架已有，需要增强语义验证。其中 geo.backend 的 claim 需要修正——实际是 fail-LOUD |
| → **P1** | **方向二：Admin API 迁移到 proto** | **M~L（~1 周首批）** | 中 | 路由已 conditionally gated，迁移安全。首批推荐 audit query + user operations |
| ⬇ **P2** | **方向五：API 版本协商** | **XL（~2-4 周）** | 低（当前）→ 高（首次 breaking change） | 完全空白的基础设施，但当前无 breaking change 计划。建议只做 Phase 1（Sunset header 框架），Phase 2/3 延迟到第一次 breaking change 提案 |

**值得立即动工的精确位置**：

```
方向三 Phase 1：
  docs/examples/playground/main.go:1    → 添加 //go:build demo_example
  Makefile                              → 阻止 go install ./docs/examples/... 不带 demo tag

方向一 Phase 1：
  interfaces/sso/sso_newserver.go:44    → 在 for range opts 后添加 validateServer(s)
  interfaces/sso/sso_newserver.go       → 新增 feature_deps.go 声明式依赖 map
  interfaces/sso/server_health.go       → 新增 Server.Ready() 聚合所有 ready check

方向四 Phase 1（基于已有基础）：
  cmd/sso-server/main.go:94             → 增强 --validate-only 调用链，加入跨块语义验证
  config/config_geo_tenant.go           → 添加 GeoConfig.Validate() error
  interfaces/sso/options_passwd.go      → 添加 signup option set 的交叉验证
```

要我开始实现其中任何一个方向吗？我推荐从 **方向三 Phase 1**（30 分钟，最大安全收益/最小代码变更）和 **方向一 Phase 1**（~1 天，最高风险缓解）开始。
