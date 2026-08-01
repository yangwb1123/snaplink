# 代码验证与同行评审：v2 五项扩展方向

> **评审者：** 架构验证引擎（基于全代码库 grop 验证）
> **日期：** 2026-07-11
> **依据：** 对 v2 文档每项声明的逐条代码库反查 + 50+ 份历史文档交叉核验
> **等级标准：** ✅ = 准确 | ⚠️ = 部分准确（需修正） | ❌ = 不准确（已有实现或已有分析文档覆盖）

---

## 总体评价

这份 v2 文档的代码覆盖率扫描方法**扎实**（2241 `.go` 文件 + 历史文档反查），边界情况分析**深度优秀**（特别是方向①的 Hook 超时/沙箱/防泄漏设计）。但代码缺口验证环节因为 **grep 关键词设计过窄**，遗漏了已实现的核心组件，导致方向 ②④⑤ 的"零命中"声明不完全准确。

**准确率：** 5 个方向中，1 个完全准确（①），2 个需修正声明但方向本身仍成立（②⑤），1 个已有核心实现 ≠ 方向不成立（④），1 个已被历史文档覆盖（③）。

---

## 逐方向验证

### 方向①：认证流水线中间件引擎 ✅ **完全准确，真缺口**

| 声明 | 验证 | 证据 |
|---|---|---|
| `WithAuthHook` / `WithPreLoginHook` / `WithPostAuthHook` 不存在 | ✅ 完全正确 | grep 全代码库 0 命中 |
| `platform/lifecycle/authpipeline/` 不存在 | ✅ 完全正确 | 目录不存在 |
| 已有分析文档零命中 | ✅ 完全正确 | 50+ 文档中 0 命中 |

**结论：** 这确实是目前唯一完全未被覆盖的方向。文档的 Hook SPI 设计（`LoginPhase` 五个阶段、`AuthHook` 接口、`HookInput`/`HookOutput`）合理且在现有硬编码链的坐标点注入不会破坏现有逻辑。

**值得注意的补充：** 
- WASM 集成路径已经在 `platform/lifecycle/wasmauthz` 中有现成的沙箱（wazero），可复用。
- 需要额外关注 `PhasePreAuthenticate` 阶段的错误映射——文档中已提到但不妨强调：PreAuth 的 `access_denied` 不应与凭据错误的 `invalid_grant` 混淆。

---

### 方向②：令牌与会话批量运维治理 ⚠️ **部分准确**

| 声明 | 验证 | 证据 |
|---|---|---|
| `POST /api/v1/admin/tokens/bulk-revoke` 不存在 | ❌ 不准确 | `HandleBulkRevoke` 已在 `interfaces/admin/token_portfolio.go` 实现——支持 subject/client 过滤、confirm 门禁、软上限 100/硬上限 10000、审计事件 `admin_tokens_bulk_revoked` |
| 审计事件已记录但无可查询 API | ⚠️ 需要区分 | 审计事件 `eventAdminTokensBulkRevoked` 确实已记录，但**无独立 `RevocationLogStore` SPI 或 `GET /api/v1/admin/tokens/revoked` 查询接口**——所以"无吊销日志查询 API"准确，但"无吊销日志记录"不准确 |
| SessionRecord 无 IP/LastActiveAt | ✅ 准确 | `SessionRecord` 确实无 `ClientIP`、`LastActiveAt`、`DeviceFingerprint` 字段 |
| `POST /api/v1/admin/sessions` 批量操作不存在 | ✅ 准确 | 未有 session 级别的批量操作 |
| SLO 框架不存在 | ✅ 准确 | 无 `platform/slo/` 包 |
| `GET /api/v1/admin/tokens/expiring` 不存在 | ✅ 准确 | 无预过期查询 API |

**修正建议：**
- 文档中的"当前不支持"表和"缺口验证"表应反映 token 批量吊销**已存在**（`HandleBulkRevoke`，`RefreshTokenClientPurger`，`RefreshTokenSubjectIndex`）
- 方向的市场价值评估需要调整——token 批量吊销的"缺失在采购评估中失分"已不成立
- 方向应该聚焦在**剩下的真缺口**：session 批量操作、SessionRecord IP/LastActiveAt、吊销日志查询 API、SLO 框架

**方向本质仍然成立**（session 批量操作和 SLO 框架确实缺失），只是 scope 应该缩小。

---

### 方向③：用户通知基础设施 ❌ **已被历史文档覆盖**

| 声明 | 验证 | 证据 |
|---|---|---|
| 仓库中 `NotificationStore|NotificationSender|NotificationEvent` 为 0 命中 | ✅ 代码中确实无实现 | grep 全代码库 0 命中 |
| 与所有 50+ 份历史分析文档零重叠 | ❌ **不准确** | `senior-architect-expansion-v3-identity-system-quality.md` **方向三：主动式用户通知与通信框架** 已完整覆盖该方向——包括 `NotificationEvent` 核心类型、`NotificationStore` SPI、`NotificationSender` SPI、email 适配器、in-app 通知、偏好 API、通知中心 UI、事件路由引擎、频率控制、批量发送 |

**直接对比：**

| 要素 | v2 文档方向三 | v3 文档方向三 |
|---|---|---|
| `NotificationEvent` 核心类型 | ✅ 定义 | ✅ 定义（`ID, Type, SubjectID, TenantID, Title, Body, Severity, Channel, CreatedAt, ReadAt`） |
| `NotificationStore` SPI | ✅ Create/ListBySubject/MarkRead | ✅ Create/ListBySubject/MarkRead |
| `NotificationSender` SPI | ✅ Send(event) → error | ✅ Send(event) → error |
| Email 通知适配器 | ✅ 复用现有 SMTP | ✅ 复用现有 SMTP |
| In-app 通知适配器 | ✅ 写入 NotificationStore | ✅ 写入 NotificationStore |
| 通知偏好 API | ✅ GET/PUT /me/notifications/preferences | ✅ GET/PUT /me/notifications/preferences |
| 通知中心 UI | ✅ 铃铛图标 + 下拉通知面板 | ✅ 通知铃铛图标 + 通知面板 |
| 事件→通知路由 | ✅ 异步 goroutine | ✅ 事件监听器 + worker pool |
| 通知频率控制 | ❌ 未提及 | ✅ 聚合冷却 + 频率限制 + 静默时段 |
| 优先级/P0-P2 分解 | ❌ 未分解 | ✅ P0/P1/P2 对应 1-2 周 sprint |

**结论：** 方向三已作为 v3 文档的"方向三：主动式用户通知与通信框架"完整分析过，且分析深度超过本 v2 版本（v3 覆盖了频率控制、批量发送、静默时段等 v2 未覆盖的细节）。v2 声明"零重叠"不正确。

**建议：** 
- 如果保留该方向，应引用 v3 文档作为前序分析，并指出 v3 文档**未落地的状态**（3 个月后仍未实现）作为"为什么 now"的论据
- 或者合并 v3 的分析深度并在 Scope 中引用 v3 的 P0/P1/P2 分解

---

### 方向④：跨协议会话桥接 ❌ **核心引擎 sessionhub 已存在**

| 声明 | 验证 | 证据 |
|---|---|---|
| `SessionBridge` / `LinkedSession` 实体不存在 | ❌ 不准确 | `platform/lifecycle/sessionhub/sessionhub.go`：`GlobalSID`（OPAQUE string，32 字节 crypto/rand）+ `LinkRecord{GlobalSID, Protocol, ExternalRef, Subject, CreatedAt}` 已实现 |
| 跨协议 Session 关联机制不存在 | ❌ 不准确 | `Coordinator.Link(ctx, gsid, protocol, externalRef, subject) error` 已实现 |
| SAML SLO 不触发 OIDC 注销 | ❌ 不准确 | `Coordinator.Logout()` 在 terminateLegs 后调用 `OIDCLogoutTrigger.TriggerBackchannelLogout()` + `SAMLLogoutTrigger.Fanout()` |
| OIDC BCL 不触发 SAML 注销 | ❌ 不准确 | 同上——`Coordinator.Logout()` 处理双向传播 |
| 跨协议 Session 统一查询 API 不存在 | ✅ 准确 | `LinkStore` 仅有 `List(gsid)` 和 `ListBySubject` 未实现 |
| 仓库中 `session.*bridge|cross.*protocol.*session` 为 0 命中 | ❌ 不准确 | `platform/lifecycle/sessionhub/` 包含 5 个文件（`sessionhub.go`, `coordinator.go`, `coordinator_test.go`, `linkstore.go`, `linkstore_test.go`） |

**已有代码的实际组件：**
- `GlobalSID` — UNGUESSABLE（crypto/rand 32 字节 hex）— 比文档设计的 `BridgeID`（UUID v7）更安全
- `LinkRecord` — 支持 `ProtocolCore` + `ProtocolSAML` — 可扩展更多协议
- `Coordinator.Link()` — 调用侧在 `infrastructure/saml/saml.go`（`linkGlobalSession`）
- `Coordinator.Logout()` — 同时销毁 core session + OIDC BCL fan-out + SAML SLO fan-out
- `MemoryLinkStore` — LRU 内存存储，过期自动驱逐
- `SetSAMLTrigger` — 后构造注入 SAML 触发器的设计模式
- `OIDCLogoutTrigger` / `SAMLLogoutTrigger` — 窄接口设计（不导入 concrete 包）

**方向本质是否成立：** 方向的核心（跨协议会话关联 + 注销传播）**已存在且已实现**。文档识别的剩余缺口（管理面统一查询 API + 用户面扩展）是合理的增量工作，但远不足以上升为一个独立方向——更适合作为 sessionhub 的"管理面补齐"任务。

**建议：** 
- 将该方向降级为 sessionhub 的后续任务（2-3 sprint），而不是独立方向
- 文档应注明 `sessionhub` 已存在，只补齐管理面 API 和 UI
- 或者，如果目标是真缺口——将方向重新定义为"Broken：OIDC→SAML→OIDC 循环防护需要修复 + 统一管理面 API 缺失"

---

### 方向⑤：密码生命周期策略管理 ⚠️ **部分准确，已有一半基础**

| 声明 | 验证 | 证据 |
|---|---|---|
| `PasswordHistoryStore` 不存在 | ❌ 不准确 | `PasswordHistoryStore` interface（`Record` / `CheckHistory`）+ `MemoryPasswordHistoryStore` 已实现（`domains/authenticators/stored_password.go`） |
| `PasswordPolicyValidator` 零引用实现 | ❌ 不准确 | `NewPasswordPolicyValidator(cfg PasswordPolicyConfig)` 在 `shared/spi/reg_gate.go` 已实现——含 minLen/upper/lower/digit/special，`WithPasswordPolicy()` 已在 `options_passwd.go` 中作为 Server Option 暴露 |
| `MaxAgeDays` 在 `PasswordPolicyConfig` 中定义但未使用 | ✅ 准确 | `reg_gate.go:52` 定义了 `MaxAgeDays int`，但 `PasswordPolicyValidator` 中未引用——仅用于配置定义 |
| `ForcePasswordChange` / `PasswordExpiresAt` 不存在 | ✅ 准确 | `User` 实体无这些字段 |
| 登录时不检查密码年龄 | ✅ 准确 | `handleLogin` 路径不检查 `PasswordExpiresAt` |
| Admin expire-password API 不存在 | ✅ 准确 | 无相关 admin API |

**已有代码清单：**
- `shared/spi/reg_gate.go`:
  - `PasswordPolicyConfig{MinLength, RequireUpper, RequireLower, RequireDigit, RequireSpecial, MaxHistory, MaxAgeDays}`
  - `PasswordPolicyValidator` interface + `NewPasswordPolicyValidator()` 引用实现
  - `ErrPasswordPolicyViolation` sentinel error
- `domains/authenticators/stored_password.go`:
  - `PasswordHistoryStore` interface (`Record`, `CheckHistory`)
  - `MemoryPasswordHistoryStore` implementation
- `interfaces/sso/options_passwd.go`:
  - `WithPasswordPolicy(v spi.PasswordPolicyValidator) Option`
- `protocols/selfservice/signup.go:310` + `selfserviceaccount/security.go:49` — 注册和设置密码路径已使用 `PasswordPolicyValidator`

**方向本质是否成立：** 部分成立。密码策略验证 + 历史存储的**基础设施已完整就绪**。真正的缺口在：
1. **`PasswordExpiresAt` / `ForcePasswordChange` 在 User 实体上缺失** — 无法标记密码过期状态
2. **登录路径无密码年龄检查** — 即使 `MaxAgeDays` 已配置，`handleLogin` 从不强制执行
3. **无管理面密码状态 API** — 无法查看/管理密码生命周期
4. **用户面无改密强引导** — 无法在登录时引导用户改密

**建议：**
- 方向名称改为"密码过期强制与生命周期管控"以准确反映 scope
- 文档应注明已有的 `PasswordHistoryStore` + `PasswordPolicyValidator` 基础设施
- 工作量应从 **M-L** 降为 **M**（利用已有基础设施）
- 剩余工作量主要在 User 实体扩展 + 登录路径检查 + admin API（3 个模块，约 4-5 周）

---

## 交叉重叠矩阵

| v2 方向 | 已有代码 | 已覆盖分析文档 | 真缺口评分 |
|---|---|---|---|
| ① 认证流水线中间件引擎 | 0% | 0 份文档 | ★★★★★（真缺口） |
| ② 批量运维治理 | 30%（token bulk revoke 已有） | v3 方向五部分覆盖 | ★★★☆☆（部分缺口） |
| ③ 用户通知基础设施 | 0% | v3 方向三完全覆盖 | ★☆☆☆☆（已分析未落地） |
| ④ 跨协议会话桥接 | 80%（sessionhub 引擎已存在） | v2 + v3 部分提及 | ★☆☆☆☆（已有实现） |
| ⑤ 密码生命周期 | 50%（validator+history+config 已有） | fresh-scan-5-directions 提及 | ★★★☆☆（部分缺口） |

---

## 结论

**唯一完全准确的真缺口：** 方向①（认证流水线中间件引擎）。

方向②⑤ 有价值但需要修正代码状态声明；方向④ 已存在核心引擎，管理面补齐是增量任务而非独立方向；方向③ 已被 v3 文档完整覆盖（代码虽未落地但分析已完成）。

**建议行动：**
1. 修正方向② 的文档——确认 `HandleBulkRevoke` 已存在，聚焦 session 批量操作 + SLO 框架
2. 方向③ 引用 v3 文档作为前序分析，更新"为什么 now"论据
3. 方向④ 降级为 sessionhub 后续任务，确认已有 GlobalSID + LinkRecord + Coordinator
4. 方向⑤ 修正代码状态，注明已有的 `PasswordHistoryStore` + `PasswordPolicyValidator` + `NewPasswordPolicyValidator`

以上。文档仍具有高价值——边界情况分析和 Scope 设计质量优秀，经过上述修正后可成为可靠的开发输入。
