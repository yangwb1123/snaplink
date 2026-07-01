现在我已掌握全部源码证据，以下为**带代码验证的完整分析报告**。

---

## 分析第 6 轮 — 源码验证报告

扫描日期：2026-06-29，代码检出 HEAD。

---

### 方向一：每用户并发会话硬限制 — 会话积累不受控

**状态：❌ 分析结论错误 — 已完整实现**

搜索词 `MaxSessions` / `max_sessions` / `maxSession` 确实零命中，但该功能的实际命名是 `MaxSessionsPerUser`，且已完整实现：

**配置入口** — `interfaces/sso/options_passwd.go:410-423`：
```go
func WithMaxSessionsPerUser(n int) Option {
    return func(s *Server) { s.maxSessionsPerUser = n }
}
// 0（默认值）= 不限，向后兼容
// 超限时：滚动淘汰（踢掉最旧的 session）
```

**执行路径** — `interfaces/sso/server_logout.go:372-430`：
```go
func (s *Server) createSession(ctx HandlerContext, userID, tenantID string) {
    // 租户级 session 配额检查（硬上限，返回 403）
    if s.tenantQuotaStore != nil && tenantID != "" {
        if err := s.tenantQuotaStore.IncrementUsage(rctx, tenantID, core.ResourceSessions, 1); err == core.ErrQuotaExceeded {
            ctx.JSON(http.StatusForbidden, errorBody("quota_exceeded"))
            return
        }
    }
    // 每用户软上限（滚动淘汰）
    if s.maxSessionsPerUser > 0 {
        s.evictOldestSession(rctx, userID, tenantID, s.maxSessionsPerUser)
    }
    // ...创建新 session
}
```

`evictOldestSession` 按 `tenantID` 作用域列出用户 session，超限时踢掉 `oldestSession()`。

**评价：** 分析中描述的"滚动淘汰"策略与实际代码一致。分析失败的原因是搜索词不匹配——代码中使用 `MaxSessionsPerUser` 而非 `MaxSessions`。该方向的代码复杂度评估为 **S（Small）** 仍然正确，但实际工作量是 0，因为已经完成。

---

### 方向二：SAML IdP session_index 表无 TTL/清理

**状态：❌ 分析结论过时 — TTL + 后台清理 + 每用户上限已全部实现**

分析声称的缺失项在 `infrastructure/saml/idpsqlite/session_index.go` 中全部存在：

| 分析声称缺失 | 实际代码 | 行号 |
|---|---|---|
| 无 `expires_at` 列 | `expires_at INTEGER NOT NULL DEFAULT 0` + 索引 | :30, :37 |
| 无最大条目限制 | `DefaultSPsPerSubject = 64` + upsert 事务内淘汰 | :66, :201-213 |
| 无后台清理 | `StartCleanup(ctx, interval)` + `PruneExpired()` | :247-270 |
| 无 TTL 配置 | `WithSessionTTL(d time.Duration)`，默认 24h | :99-102 |
| 无过期清理 | `PruneOlderThan(cutoff)` + `PruneExpired(before)` 操作钩子 | :232-254 |
| 无迁移支持 | v2 迁移：`ALTER TABLE ADD COLUMN expires_at` + 24h 回填 | :47-59 |

`Record()` 方法执行 `INSERT ... ON CONFLICT DO UPDATE` 带 `expires_at = now + sessionTTL`，随后在同一个 `BEGIN IMMEDIATE` 事务内执行 per-subject SP 上限淘汰：

```go
// 第 201-213 行
DELETE FROM saml_session_index
 WHERE subject = ? AND sp_entity_id NOT IN (
     SELECT sp_entity_id FROM saml_session_index
      WHERE subject = ? ORDER BY recorded_at DESC LIMIT ?
 )
```

**评价：** 分析可能基于过时的代码快照（在 v2 迁移和 `StartCleanup` 添加之前）。当前代码不仅解决了所有指出的问题，还增加了分析中未预见的 `WithMaxSPsPerSubject` 和 `WithSessionTTL` 配置选项。**工作量：0（已完成）**。

---

### 方向三：OIDC Session Management 1.0 `session_state` 完全缺失

**状态：✅ 分析正确 — 真实缺口**

全库搜索确认零命中：
```
session_state   → 0
SessionState    → 0
postMessage     → 0
check_session   → 0
opbs            → 0
browser_state   → 0
```

**缺少的组件：**

1. **授权响应中无 `session_state` 参数** — `protocols/oidc/handle_authorize.go` 的响应结构中无此字段
2. **无 `GET /session/check` 端点** — RP 没有可嵌入的 iframe URL
3. **无 postMessage 通信** — RP 无法通过 `postMessage` 查询 OP 会话状态
4. **无 OP 端会话侧通道（opbs cookie/browser state）** — 无法维持 OP 会话和浏览器状态之间的关联

**影响：** 对于第三方 cookie 已被禁用的现代浏览器（2026 年已是常态），`postMessage` iframe 是 OIDC Session Management 1.0 定义的唯一能把 OP 侧会话终止信号传递到 RP 的方式。缺少这个机制，RP 只能：
- 等到用户主动点登出（RP-Initiated Logout）
- 或用短生命周期 access token 被动发现 session 过期

**建议实现量：M（Medium）**。需要：
- 新增 `protocols/oidc/session_check.go` 处理 `session_state` 生成逻辑（加盐 hash）
- 新增 `GET /session/check` 端点渲染一个简单的 HTML iframe（约 30 行）
- 修改授权响应路径注入 `session_state` 参数
- 新增 `WithSessionCheckEnabled(enabled)` 开关（默认关）

---

### 方向四：无每租户功能开关系统

**状态：✅ 分析正确 — 真实缺口**

搜索确认：
```
TenantFeatures  → 0
HasFeature      → 0
FeatureStore    → 0
featureStore    → 0
```

`domains/tenant/tenant.go:26` 的注释明确提到了 "per-tenant feature flags" 的意图：
```go
// Settings is intentionally loose —
// per-tenant feature flags, default locale, branding tokens —
// without forcing a wide table for every new toggle.
type Tenant struct {
    Settings map[string]string `json:"settings,omitempty"`
}
```

但 `Settings` 只是一个无类型 `map[string]string`，没有类型安全的 feature 结构、没有 `HasFeature` 查询方法、没有任何 handler 层面的 feature 检查逻辑。

当前所有功能切换都通过编译时的 `With*` 选项绑定：
- `s.connectionStore != nil` → B2B 连接可用
- `s.scimStore != nil` → SCIM 可用
- `s.federation != nil` → Federation 可用
- 所有租户共享同一功能集

**建议量：L（Large）**。这是一个架构级变更：
- 定义 `shared/core/tenant_features.go` （`TenantFeatures` 结构 + 类型安全常量）
- `Tenant.Features` 字段替代原始的 `Settings` map
- `HasFeature(ctx, tenantID, key)` 查询方法
- handler 层逐步迁移 `if s.connStore != nil` → `if features.HasFeature(tenantID, "b2b_connections")`
- 配置层支持 YAML `tenants[].features: { scim: true, self_service: false }`

这是五个方向中最有价值但工作量最大的方向，适合 road map。

---

### 方向五：管理 API 表面 REST vs gRPC 不对称

**状态：❌ 分析结论过时 — 两端均已实现**

分析声称 REST `GET /users/{id}/sessions` 缺失，但实际代码显示双向均已存在：

**gPRC 端：** 有两条路径都支持按用户列出 session：

| gRPC 服务 | 方法 | 代码位置 |
|---|---|---|
| `TokenAdminService` | `ListSessions(in.UserId)` 可选按用户过滤 | `grpcadmin/admin_tokens.go:70-95` |
| `UserAdminService` | `ListUserSessions(in.Id)` 必须指定用户 | `grpcadmin/admin_users.go:114-129` |

**REST 端（通过 gRPC-gateway 挂接）：**

`cmd/sso-server/build_http.go:249` 注册了 gRPC-gateway：
```go
adminv1.RegisterUserAdminServiceHandlerServer(ctx, gw,
    grpcserver.NewUserAdminService(a.userProvider, a.sessionMgr, a.recorder))
```

Proto 生成的 HTTP 路径：
```
GET /api/v1/admin/users/{id}/sessions  ← ListUserSessions
```

`cmd/sso-server/log_endpoints.go:58` 确认已注册：
```
"GET    /api/v1/admin/users/{user_id}/sessions",
```

**原生 REST 端（非 gateway）：** `GET /api/v1/admin/sessions`（全局列表，`ListAll`）也在 `server_routes_admin.go:48` 挂接：
```go
if s.sessionMgr != nil {
    api.GET(PathAdminSessions, s.handleAdminListSessions)
}
```

对比表（修正后）：

| 用户管理操作 | REST `/api/v1/admin/users/...` | gRPC |
|---|---|---|
| 列出用户 consent | ✅ `GET /all/consents` | ✅ |
| 列出用户 MFA | ✅ `GET /all/mfa` | ✅ |
| 列出用户 session | ✅ **`GET /{user_id}/sessions`**（gateway） | ✅ `ListUserSessions` |
| 列出全部 session | ✅ **`GET /admin/sessions`**（原生） | ✅ `ListSessions(null)` |
| 清空锁定 | ✅ `POST /clear-lockout` | ✅ |
| 密码 | ✅ `POST /password` | ✅ |

**评价：** 分析错误。REST `GET /users/{id}/sessions` 通过 gRPC-gateway 已可用。唯一的细微之处：该端点走 gateway 而非原生 Echo handler，但 API 表面一致，功能对等。**工作量：0。**

---

## 修正后的优先级排序

| 方向 | 分析结论 | 实际状态 | 剩余工作量 | 建议 |
|---|---|---|---|---|
| **① 每用户 session 上限** | ❌ 缺失 | ✅ 已实现 | **0** | 无需操作 |
| **② SAML 索引膨胀** | ❌ 缺失 | ✅ 已实现 | **0** | 无需操作 |
| **③ session_state** | ✅ 真实缺口 | ✅ 真实缺口 | **M** | **第 1 Sprint** |
| **④ 租户功能开关** | ✅ 真实缺口 | ✅ 真实缺口 | **L** | **Roadmap** |
| **⑤ 管理 API 不对称** | ❌ 缺失 | ✅ 已实现 | **0** | 无需操作 |

**有效剩余缺口降到两个方向**（而非分析声称的五个），其中：

- **第 1 优先级：OIDC Session Management `session_state`** — 这是一个真实的 OIDC 协议合规缺口，在现代浏览器第三方 cookie 禁令下直接影响 RP 的会话状态感知能力
- **Roadmap：租户功能开关** — 这是产品能力的架构节点，从"编译时决定一切"进化到"运行时按租户弹性编排"，但实现量较大（需要定义类型安全 feature 系统、迁移所有 handler 的 feature 检查、配置层支持）

**对分析流程的建议：** 分析中的搜索词（`MaxSessions` / `session.*limit` 等）与代码实际命名（`MaxSessionsPerUser`）不匹配，且未能发现 `infrastructure/saml/idpsqlite/session_index.go` 中的 TTL/清理实现。建议在未来的分析中：
1. 先用 `grep -rn "Max\|Limit\|Cap\|TTL\|expir\|Prune\|Cleanup"` 做宽泛的模式扫描找到实际命名，再针对性搜索
2. 对 SAML 等子系统需要完整读取其代码，不要仅依赖 SQL schema 的早期行判断
3. 管理 API 两侧（gRPC 和 REST）都需要检查，不应仅看 `server_routes_admin.go` 中的原生路由而忽略 gRPC-gateway 注册的路径
