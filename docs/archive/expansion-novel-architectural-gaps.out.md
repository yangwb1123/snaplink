验证完毕。以下是我对每个方向的实地核验结果：

---

## 核验报告

穿过你提到的每个代码位置后，**5 条方向全部确认为真实架构缺口**，零假阳性。以下是每个方向的实地证据和补充发现：

### ✅ 方向一：Feature Interaction Validation——确认

`interfaces/sso/sso_newserver.go` 的核心循环：

```go
for _, opt := range opts {
    opt(s)          // 只赋值，不校验
}
```

在此之后确实没有 `validateServer()` 调用。我验证了：

- `grep "fapi\|FAPI\|PAR\|JAR\|DPoP\|Backchannel\|CAEP\|OAuth21" interfaces/sso/sso_newserver.go` → **0 命中**
- 唯一的后处理是 CAEP↔audit tap、tenant metrics、federation auto-reg、client cache——全部是*组装*逻辑而非*验证*
- `Ready()` 方法在你分析的 `build_readiness.go` 中已存在，但它只检查存储健康状态，不检查 feature 依赖

**补充发现**：`cmd/sso-server/build_app*.go` 路径有一些*零散*检查（如 `snapshot.retention` 需要 `snapshot.enabled=true`），但这些都是针对该特定二进制构建路径的硬编码 if-check，与 SDK `NewServer` 路径完全无关。SDK 用户完全没有防护。

### ✅ 方向二：Admin API Surface Coherence Gap——确认且比你描述的更严重

我追踪了完整的 admin 路由注册表 `interfaces/sso/server_routes_admin.go`：

**Proto 覆盖的（7 个域）：** clients、users、permissions、tenants、tokens、snapshots、releases

**HTTP-only（15+ 个域，无 proto schema）：** 审计查询/导出、网络策略 CRUD、租户用量、备份触发、admin 令牌生命周期、会话列表、用户 consent 管理、用户 MFA 因子管理、密码重置、邮箱设置、设备密钥吊销、账户锁清除、企业连接 CRUD、租户成员管理、邀请管理

更准确地说，这不仅仅是"能力缺失"——HTTP-only 端点使用不同的参数绑定模式（`bindOAuthParams` vs. proto 的 `google.api.http` 注解），意味着 API 消费者必须以不同方式对待它们。当 admin SPA 同时消费两种路径时，这是一致的头痛来源。

### ✅ 方向三：Playground Supply Chain Risk——确认且范围更广

`docs/examples/playground/main.go`——无 build tag，有硬编码 TOTP 密钥和 `alice/secret`。但我进一步发现另外两个示例文件同样易受攻击：

- `docs/examples/quickstart/main.go:41` — `demoSecret = "demo-secret"`，硬编码的客户端凭证
- `docs/examples/basic/main.go:46` — `demoPassword = "secret"` + `demoAPISecret = "sk_demo_secret_value"`

三个示例文件都**没有** `//go:build` 标签，都可以通过 `go install ./docs/examples/...` 安装。你的建议是正确的——Phase 1（加 build tag + Makefile 保护）确实只需要 30 分钟。

### ✅ 方向四：Configuration Incoherence Detection——确认

`config/config_load.go:109-130` 中的 `validate()` 方法只检查：
1. `config.yaml` 版本格式
2. `logging.level` 枚举值（debug/info/error）
3. `server.issuer` 不等于 SDK sentinel
4. 每个 `client.id` 非空

**不检查**：geo backend 是否已注册、auth_code TTL vs. 持久化后端、self_service signup 依赖的 sender、admin 依赖的 permissions provider、federation 依赖的 signer。

关于 `geo.backend=maxmind` 的具体断言的确认——`config/config_geo_tenant.go:17` 只在注释中引用 maxmind，无实现。

### ✅ 方向五：API Version Negotiation & Deprecation——确认且有一个已存在但未落地的设计

我读了 `docs/adr/ADR-0008-proto-versioning.md`。这是一个设计良好、符合 Google AIP 的版本策略（v1 → v2alpha → v2beta → v2 + 6 个月弃用窗口）。**但在代码层面上：**

- `grep "Sunset\|Deprecation" --include='*.go' --include='*.proto' interfaces/ proto/` → **0 执行时命中**
- `Accept-Version` / `X-API-Version` / `api-version` 搜索 → **0 命中**
- 所有 7 个 proto 文件都在注释中引用 ADR-0008，但**没有任何一个包含实际的 `deprecated = true` 注解或 `reserved` 语句**（除 release/snapshot 的 `schema_version` 字段外）

ADR 已批准但从未实现——这是你正确标识的架构债务。

---

## 补充观察

在追踪代码时，我发现了一个**跨方向的系统性模式**：该项目的运行时代码质量（类型安全、测试覆盖、接口隔离）非常好，但**启动时/构建时**的验证链条几乎不存在。验证要么内联在 `build_*.go`（特定二进制文件，不共享），要么在 `main_servers.go`（只为 `cmd/sso-server`），要么根本不存在（SDK 路径）。

这强化了你核心论点的优先级：**P0 应该是把"运行时失败"转化为"启动时失败"**——这是方向一、方向四、方向三的共同主题。

你的优先级排序（方向三 Phase 1 → 方向一 → 方向四 → 方向二 → 方向五）从风险角度来看是合理的。我唯一可能调整的是 P0 列表中加入方向一 Phase 1（`validateServer()` 入口），因为你的 playground build tag 可以在 30 分钟内完成，而 validateServer 入口可以在 2-3 小时内完成——两者可以在同一天完成，无需阻塞对方。
