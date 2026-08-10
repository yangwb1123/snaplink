实施提案已产出并通过校验：**`docs/proposals/audit-contract-batch-snaplink.md`**

## 核心结论

**验证结果**（清单 20+ 条路径全部逐行核对，HEAD `b3c839bb` 与清单一致）：
- **16 处 Verified**：`issue_payload.go:26`、`server_token.go:17/122`、`server_token_clientauth.go:193/239`、`server_discovery.go:251`、`server_discovery_config.go:61/142`、`consts.go:9/21-23`、`bind.go:28`、kid 三处（`ed25519_types.go:12`/`ecdsa_jwt_issuer.go:439`/`rsa_jwt_issuer.go:436`）、auditgovernance 三件套、`cmd/snaplink-audit-provisioner/` 等
- **1 处路径不准**：`shared/core/spi.go:171` 实为 `SessionMeta.TenantID`；`Subject.TenantID` 在 `types_token.go:231`（已在提案中修正并标注）
- **清单"已存在"复核全部成立**：kid、per-client scope allowlist、introspection 认证、cc 无 refresh_token + no-store、constant-time 比较（`security.CompareClientSecret`）
- **关键新发现**：cmd/sso-server **从未接线 `sso.WithIssuer`**（`server.issuer` 只喂 JWT 的 `iss` claim，`resolveIssuer` 永远 Host 派生）；`auditgovernance` 包在 cmd 零引用；relay 目前 drain 的是计费 outbox

**设计要点**：
- B4-1：tenant_id（`Subject.TenantID` 已三 grant 填充，只加发射）+ roles（`permissions.Provider.Roles` fail-open）+ iss 配置化（allowlist + `require_configured` 开关，避免一次性破坏多主机）
- B4-2：新 `ScopeRegistry` 接口 + Memory 实现，**可选接线**（不接线 = 字节兼容），矩阵表内容标 [PROPOSED] 待契约 pack
- B4-3：本仓无 legacy 缺陷测试（grep 零匹配），核心交付 = sweep 真值断言；`/revoke` 已实现、code 流广告与实现一致
- B4-4：唯一确定性破坏 = 禁 JSON（严格模式 + 配置回退）；constant-time 已存在只补测试
- B4-5：outbox + in-tx（login 失败 post-commit 为唯一许可类）+ 复用 `managed_relay.go` + backend 默认 memory→sqlite；`auth.token.issue` 映射与 L1 聚合位置标 [PROPOSED]

**10 项未验证标注**全部列出（scope-matrix-v2 表、T-8(b/c/e) 精确语义、T-2 断言形式、事件名映射等均不冒充 Verified）。
