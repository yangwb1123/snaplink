现在我已完成全面核验（读码 + 对抗式 grep）。以下是逐方向的验证结论：

---

## 核验报告

### ✅ 数据基准确认

| 指标 | 文档声称 | 实际 | 状态 |
|------|---------|------|------|
| `.go` 文件数 | 1639 | **1639** | ✅ |
| 嵌套模块数 | 13 | **13** (`go.mod`) | ✅ |
| 测试文件数 | 460+ | **790** (实际更多) | ✅ |

---

### 方向一：WebAuthn 作为主认证

| 声称 | 验证结果 |
|------|----------|
| `webauthn.go` 明确声明**不实现** `sso.Authenticator` | ✅ **确认** — 文件第 4 行原文：*"The package intentionally does NOT implement [sso.Authenticator]"* |
| WebAuthn 仅用于 MFA 第二因素/Passkey 注册/条件登录 | ✅ **确认** — 所有路由走 `/me/mfa/webauthn/*`，不走 `/auth/login` |
| 无 `provider=webauthn` 在 `/auth/login` | ✅ **确认** — grep `provider.*webauthn\|webauthn.*primary` 空 |
| `signup.go` 回滚"避免留下 passwordless 用户" | ✅ **确认** — `signup.go:209` 原文：*"Roll back the just-created user so we don't leave a passwordless orphan account"* |
| 无 `ErrWebAuthnChallengeRequired` | ✅ **确认** |
| **⚠️ 声称"与所有先前分析文档无重叠"** | ❌ **有重叠** — `expansion-v2-2026-07-01.md`（11:11 创建）**方向一** 已是 *"Passkeys 作为主认证（Passwordless-First Login）"*，论证结构和工作量预估都高度相似 |

**结论：代码缺口真实，但 novelty 声明不成立。**

---

### 方向二：Resource Server SDK with RAR Enforcement

| 声称 | 验证结果 |
|------|----------|
| `authorization_details` 仅在 AS 侧 | ✅ **确认** — 全部 20+ 命中都在 `protocols/oauth/`、`shared/core/`、`config/`。**零 RS 侧代码** |
| 无 `oauthrs/` 或 `ssoclient/oauthrs/` 包 | ✅ **确认** |
| 无 `AuthorizationDetail` struct、`CheckOperation`、`CheckAccess` | ✅ **确认** |
| `ssoclient.Subject` 不含 `AuthorizationDetails` | ✅ **确认** — `types.go:27` 的 `Subject` 只含 `ID, Audience, Scopes, ExpiresAt, Attrs` |
| 无 `ErrInsufficientAuthorizationDetails` 错误 | ✅ **确认** |
| ** novelty claim ** | ✅ **真缺口** — 此前所有 expansion/analysis 文档均未覆盖此方向 |

**结论：真缺口，无重叠。**

---

### 方向三：Passwordless OTP HA 加固

| 声称 | 验证结果 |
|------|----------|
| `redis/code_store.go` 文档记载 HA bug | ✅ **确认** — `code_store.go:24-27` 原文：*"on a no-affinity load balancer the verify lands on a different replica...passwordless login breaks under HA"* |
| 默认使用 memory 后端 | ✅ **确认但需 nuance** — `buildCodeStore` (`build_authenticators.go:93-97`) 在 `rdb != nil` 时自动选 Redis，否则 memory。零配置部署用 memory |
| 无 HA 模式启动警告 | ✅ **确认** — 已有的 `warnHACoherence()` (`build_stores.go:75-130`) 检查了 oauth.backend / session_backend / JTI / CIBA，**但未检查 code_store**。这使缺口更突出——模式已存在，code_store 被遗忘 |
| 无 `isHA()` 检测 | ✅ **确认** — `warnHACoherence` 用 `redisHA := b.cfg.Redis.Configured()` 而非 `cluster.Mode == HA` |
| ** novelty claim ** | ✅ **真缺口** — 此前所有文档未覆盖此具体修复 |

**结论：真缺口。这是唯一一个被开发者自己标记为已知生产 bug 的方向。**

---

### 方向四：通用 Webhook 事件桥

| 声称 | 验证结果 |
|------|----------|
| 无 `EventBridge` SPI | ✅ **确认** — grep `EventBridge\|Publish.*Event\|event.*webhook` 仅返回 audit webhook sink 和 cluster bus |
| 无 `EventUserCreated`、`EventClientCreated` 等事件类型 | ✅ **确认** — grep `user\.created\|client\.secret\|session\.created` 零命中 |
| 无 `WebhookService` admin API | ✅ **确认** — `proto/admin/v1/` 下 7 个 service（releases/tenants/permissions/tokens/clients/users/snapshots），无 webhook |
| 仅 audit webhook sink 存在 | ✅ **确认** — `platform/audit/auditsink/webhook_sink.go` 仅发审计事件，不是结构化 OAuth 事件 |
| **⚠️ 声称"与所有先前分析文档无重叠"** | ❌ **有重叠** — `expansion-v2-2026-07-01.md`（11:11 创建）**方向三** 已是 *"事件驱动生态——通用 Webhook / Egress 事件系统"*，且论证了相同的缺口（grep 证据、场景分析几乎相同） |

**结论：代码缺口真实，但 novelty 声明不成立。**

---

### 方向五：加密材料全局清单治理

| 声称 | 验证结果 |
|------|----------|
| 无 `KeyType` / `KeyInfo` / `CryptoInventory` 类型 | ✅ **确认** |
| 无 `CryptoInventoryService` proto 或实现 | ✅ **确认** |
| 10 种加密材料分散在不同包中，无集中注册 | ✅ **确认** — grep 确认每个子系统独立管理自己的密钥 |
| 无密钥生命周期审计事件 | ✅ **确认** |
| ** novelty claim ** | ✅ **真缺口** — 此前所有文档未覆盖此方向 |

**结论：真缺口，无重叠。**

---

## 总结

| # | 方向 | 代码缺口 | Novelty | 优先级 |
|---|------|---------|---------|--------|
| 1 | WebAuthn 主认证 | ✅ 真实 | ❌ 有重叠（卷九方向一） | — |
| 2 | RAR RS SDK | ✅ 真实 | ✅ 真缺口 | **第二优先** |
| 3 | Passwordless OTP HA | ✅ 真实（已知生产 bug） | ✅ 真缺口 | **第一优先** |
| 4 | 通用 Webhook 事件桥 | ✅ 真实 | ❌ 有重叠（卷九方向三） | — |
| 5 | 加密材料清单 | ✅ 真实 | ✅ 真缺口 | **第三优先** |

**最重要的两个发现：**

1. **方向 3（OTP HA 修复）是唯一有硬代码证据标注为已知生产 bug 的方向**（`redis/code_store.go:24-27`）。且 `warnHACoherence()` 已检查了其他 4 种跨副本存储却遗漏了 `code_store`——这是一个被遗忘的补丁缺口，工作量极小（~20 行加一行 `if perPod(b.cfg.CodeStore.Backend)` 检查）。

2. **方向 1 和方向 4 已存在于 `expansion-v2-2026-07-01.md`（卷九，11:11 创建，早于本文档 22 分钟）**——分别是方向一"Passkeys 作为主认证"和方向三"事件驱动生态"。本文档的"无重叠"声明不准确。

建议将**真缺口**（方向 2/3/5）提炼为独立方向的 actionable 工作项，将方向 1/4 标注为与卷九重叠并引用原文避免重复劳动。
