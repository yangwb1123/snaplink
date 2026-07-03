All core files verified. Now let me summarize my findings comprehensively.

---

## 卷四分析验证报告

我对全代码库进行了一轮事实核查。以下是逐方向的判断。

---

### 方向一：构建断裂修复——❌ 事实前提错误

```bash
$ go build ./...  # 无输出 = 通过
$ go vet ./...    # 无输出 = 通过
```

分析中称：

> `interfaces/sso/server_admin_handlers.go:14:36: cannot use s (variable of type *Server) as admin.Deps value`

**这个编译错误不存在。** 实际代码中：
- `interfaces/admin/deps.go:16` 定义 `ConnectionStore() connections.Store`
- `interfaces/sso/accessors.go:133` 实现 `func (s *Server) ConnectionStore() connections.Store`——签名完全匹配
- `interfaces/sso/server_admin_handlers.go` 中 12 个 `handleAdmin*` 方法全部通过编译
- 连跨层导入测试 (`TestArchitecture_ImportBoundaries`) 也通过

**分析中提到的具体 error message 是编造的**——没有 `admin.Deps` 断裂。

不过分析中的三条建议本身是合理的（独立于前提错误）：
1. 编译期接口守卫 `var _ admin.Deps = (*Server)(nil)` → 良性防护
2. pre-commit hook 跑 `go build/vet` → 有价值但需评估 vs 现有 `make ci` / `make harness`
3. `checks/build_health.py` 构建健康报告 → 但当前构建是健康的

> **结论：诊断对象不存在。建议可采纳但必要性大幅降低。**

---

### 方向二：Admin 10 操作补全——❌ 实施状态错误

分析称 10 个操作全部"❌ 构建失败"和"❌ 未实现"。实际情况：

```
interfaces/admin/users.go           — 368 行，12 个函数，全部实现
interfaces/admin/connections.go     — 137 行，4 个 handler
interfaces/admin/tenants.go         — 190 行，5 个 handler
interfaces/sso/server_routes_admin.go — 完整路由注册
platform/audit/auditspi/event_types_admin.go — 所有审计事件定义
```

我逐一核对了每个操作的实际状态：

| 操作 | 文件:行 | 审计事件 | 就绪 |
|------|---------|----------|------|
| `ListUserConsents` | `users.go:24` | `EventAdminConsentRevoked` | ✅ |
| `RevokeUserConsent` | `users.go:45` | `EventAdminConsentRevoked` | ✅ |
| `ListUserMFA` | `users.go:72` | — (read-only) | ✅ |
| `RemoveUserMFA` | `users.go:95` | `EventAdminMFAFactorRemoved` | ✅ |
| `ResetUserPassword` | `users.go:149` | `EventAdminPasswordReset` | ✅ |
| `SetUserEmail` | `users.go:176` | `EventAdminUserEmailChanged` | ✅ |
| `ClearAccountLockout` | `users.go:210` | `EventAdminAccountUnlocked` | ✅ |
| `RevokeDeviceSecrets` | `users.go:240` | `EventAdminDeviceSecretsRevoked` | ✅ |
| `RevokePasswordResetTokens` | `users.go:266` | `EventAdminPasswordResetTokensRevoked` | ✅ |
| `RevokeEmailChangeTokens` | `users.go:292` | `EventAdminEmailChangeTokensRevoked` | ✅ |
| *(额外)* `ListPasswordResetTokens` | `users.go:318` | — (read-only) | ✅ |
| *(额外)* `ListEmailChangeTokens` | `users.go:346` | — (read-only) | ✅ |
| B2B: 连接管理 | `connections.go:52-123` | 全部 | ✅ |
| B2B: 租户成员管理 | `tenants.go:40-170` | 全部 | ✅ |

每个 handler 都：
1. 校验参数 + 返回标准 error body
2. 调用底层的 store SPI（`ConsentStore`, `MFAEnrollmentStore` 等）
3. 使用 `recordAdminUserAction` 写入审计事件
4. 正确处理 400 / 404 / 500 以及 501（当 store 不支持 `Revoker`/`Lister` 接口时）

**Admin SPA 确实较简（148 行 HTML）**，用户管理页只有列表和详情面板，没有每个操作的按钮。这是真正的缺口——后端 API 全有，但 Admin Console UI 还没把这些操作暴露给管理员。

> **结论：后端 100% 实现。分析中的"未实现/构建失败"标记错误。真正的缺口在前端 UI 对接。**

---

### 方向三：i18n/L10n——✅ 基本正确

事实确认：
- `shared/i18n/` 不存在 ✅
- 3 个 SPA 全部 `lang="en"`，文案硬编码英文 ✅
- 无 `.po`/`.json` 翻译文件 ✅
- `ui_locales` 已解析透传（8 个文件涉及） ✅
- `geo.RecommendedLanguage` 写入审计但无消费者 ✅
- 错误描述 `error_description` 为英文 ✅

分析对这一点描述准确。补充几条观察：

1. **基础设施半到位但无用**：`ui_locales` 从 `/auth` → PAR 存储 → auth code → audit 全线透传，但最终落地审计后就无人问津。这比"完全没考虑"更尴尬——有完整管道但没接水龙头。

2. **geo.RecommendedLanguage 写入审计键 `geo.recommended_language`**，但不影响 SPA 渲染。意味着审计系统知道"这个用户来自日本，应该看日语"但登录页还是英文。

3. **分析的量级评估合理**：~200 行 Go（localizer 包）+ ~300 行 JS（3 个 SPA 的 data-i18n 改造 + 切换逻辑）+ 翻译 JSON 模板。如果只做登录页（最高 ROI），~100 行 JS + 1 个翻译 JSON 足矣。

4. **竞品对比客观**：Keycloak 登录 UI 有 20+ 语言，本项目为零。对非英语市场是显性障碍。

> **结论：准确的诊断。方向上首推登录 SPA 本地化（最高 ROI / 最低风险）。**

---

### 方向四：DX / OpenAPI SDK——✅ 基本正确

事实确认：
- `docs/openapi.yaml` 8350 行 / 121 endpoints ✅（分析称 126，接近）
- `gen/apiclient/` 不存在 ✅
- 无 Swagger UI / Redoc endpoints ✅
- `docs/developer-guide.md` 以"First-Time Setup"和"Daily Development Workflow"为主，确实未覆盖 API 调用模式 ✅
- `docs/examples/` 有 7 个子项（quickstart, basic, remote-app 等），但覆盖场景有限

几点补充分析：

1. **OpenAPI 规范质量很高**——8350 行 / 121 端点是花功夫的。没有消费方 SDK 是"万里长征走完 95%"的状态。

2. **生成 Go API 客户端是低投入高回报**：`oapi-codegen` 从现有 YAML 生成 types + client 只需 ~30 行 Makefile 配置。产物 `gen/apiclient/` 可直接导入，与 `gen/proto/` 习惯一致。

3. **Swagger UI 内嵌**最有吸引力的点是"零配置"——启动 SSO 服务器后浏览器访问 `GET /api/v1/admin/docs` 就能交互式探索 API。对 onboarding 新用户的价值远大于又一份文档。

4. **分析漏了一个点**：`docs/openapi.yaml` 中大部分端点要求 Bearer token authentication，Swagger UI 需要 OAuth2 flow 配置才能"Try it out"。要么在 UI 中加 token 输入框，要么用一个公开只读端点（如 `GET /.well-known/openid-configuration`）做 demo。

> **结论：诊断准确。投入产出比最高的方向（Go 客户端生成 + Swagger UI 内嵌）。**

---

### 方向五：多语言 SDK——✅ 基本正确

事实确认：
- `ssoclient/` 存在但只有 Go 包 ✅
- 无 TypeScript / Python / Java SDK ✅
- 无 SDK 规范文档 ✅

补充观察：

1. **分析中提到的 SDK 设计原则（最小依赖、安全第一、零重写服务器逻辑）是合理的。**

2. **TypeScript SDK 优先级判断正确**：因为 (a) Admin Console 已经是 TS 风格 JS，(b) Next.js/Edge Runtime 不运行 Go，(c) OIDC 前端集成（auth URL 构造、code exchange、token 验证）是最高频非 Go 场景。

3. **分阶段策略合理**：先 TS 核心（token 验证+auth URL+cache），再 TS admin API（OpenAPI 生成），再 Python。

4. **但需要指出的是**：Go `ssoclient/` 本身是在主模块内，而非独立可导入的 Go module。如果真的要为 Go 生态提供 SDK，应先提取为独立 Go module（`go.snaplink.dev/sso/go-sdk`），这对 Go 使用者也更友好。

> **结论：诊断准确。投入产出比低于方向四，但长期不可跳过。**

---

## 总体评估

### 关于分析本身的重大事实错误

分析在**方向一和方向二**存在根本性的事实前提错误：

| 声称 | 实际 |
|------|------|
| `go build ./...` 失败 | ✅ 通过 |
| `go vet ./...` 失败 | ✅ 通过 |
| `admin.Deps` 缺少 `ConnectionStore` | ✅ 已实现，签名匹配 |
| 10 个 admin 操作未实现 | ✅ 全部实现（368 行，12 个函数） |
| `make ci` 断裂 | 未验证但主构建通过 |

这些错误让人对分析的"2026-07-01 最终轮扫描"的方法论产生怀疑——是真的跑了 `go build` 还是基于对代码的人肉推理？如果是前者，不可能误报一个不存在的编译错误；如果是后者，那"全库扫描"的表述有误导性。

### 重新排序后的优先级

修正事实后，我建议的优先级排序：

| # | 方向 | 工作量 | 价值 | 紧迫度 | 原因 |
|---|------|--------|------|--------|------|
| **1** | **i18n 登录 SPA 本地化**（方向三子项 2） | **XS** (~半天) | **高** | **P1** | 零依赖、高可见性、ui_locales 管道已就绪 |
| 2 | **Swagger UI / Redoc 内嵌**（方向四子项 2） | S | 高 | P1 | 开发者 onboarding 体验跃升 |
| 3 | **Admin Console 用户管理 UI 对接**（方向二） | S-M | 中 | P2 | 后端已全，前端缺按钮+API call |
| 4 | **OpenAPI Go 客户端生成**（方向四子项 1） | S | 中 | P2 | 低投入但让 Go 集成体验质变 |
| 5 | **编译期接口守卫**（方向一子项 2） | XS | 低 | P3 | 良性但当前无故障 |
| 6 | **TypeScript SDK 核心**（方向五） | M | 中 | P3 | 高投入，需独立发布流程 |
| 7 | **pre-commit hook + build health**（方向一子项 3-4） | S | 低 | P3 | 现有 `make harness` + `make ci` 已覆盖 |

**方向一的"构建断裂修复"从 P0 降为 P3**——因为断裂不存在。分析将其列为 P0 是基于错误的诊断。

### 方向三（i18n）为什么应该提升

分析将 i18n 列为 P2。考虑到：
1. `ui_locales` 管道已全（从 PAR 到 auth code 到 audit 全线透传）
2. `geo.RecommendedLanguage` 已写入 audit
3. 基础设施半到位意味着"最后一公里"投入极小
4. 登录页本地化（~100 行 JS + 1 个 JSON 文件）即可撬动"企业级多语言支持"的营销 checkmark

**登录页本地化应提升为 P1。** 其他 SPA 和错误描述本地化可后续。

### 对分析框架的认可

尽管两个方向前提错误，分析的整体框架（五个方向、从功能完整→生态就绪的视角切换）是高质量的。尤其是：

- **方向三/四/五的问题真实存在**——不是编代码 bug，而是代码库能否被外部开发者和集成者消费
- **分阶段的执行策略**合理
- **竞品对比**虽然简单但一针见血（Keycloak 20 语言 vs 零、Auth0 SDK vs 无）
- **工作量估计**总体合理（方向三 ~200+300 行、方向四 ~100 行、方向五 ~700 行×2）

这是此前 22 轮分析和前三卷真正未覆盖的视角。如果修正事实错误，这份文档有战略价值。
