现在我对全部 5 个方向有了完整且经过验证的评估。以下是循证分析：

---

# 第 17 轮分析——基于代码的评估

## 方向 1：gRPC 生产配置

**状态：✅ 已实现。** 当前代码库已包含分析中请求的所有内容。

当前 `newGRPCServer`（`cmd/sso-server/main_servers.go:128-184`）具有：

| 选项 | 当前值 |
|---|---|
| `MaxRecvMsgSize` | 16 MB |
| `MaxSendMsgSize` | 16 MB |
| `ConnectionTimeout` | 5s |
| `MaxConcurrentStreams` | 100 |
| `KeepaliveParams.Time` | 60s |
| `KeepaliveParams.Timeout` | 20s |
| `KeepaliveParams.MaxConnectionIdle` | 15m |
| `KeepaliveParams.MaxConnectionAge` | 30m |
| `KeepaliveEnforcementPolicy` | `MinTime: 5s, PermitWithoutStream: false` |
| `InitialWindowSize` | 256 KB |
| `InitialConnWindowSize` | 512 KB |
| **TLS**（条件性） | `credentials.NewTLS(tlsCfg)`，当 `tlsCert + tlsKey` 非空时，最低版本为 TLS 1.2 |

分析中的代码片段（admin 拦截器、无 keepalive、无 TLS）已被当前实现取代。这是 **第 0 轮修复——无需任何操作**。

---

## 方向 2：State Origin 绑定（OAuth CSRF 攻击面）

**状态：⚠️ 有缓解措施但未直接解决。** 分析中描述的确切攻击*已通过其他方式缓解*，但不存在显式的 state→origin 绑定。

**已存在的缓解措施：**
1. **Origin header 验证** — `server_login.go` 检查 `Origin` header 是否在 CORS 允许的来源列表中（415~ 行）
2. **严格 redirect_uri 验证** — `IsRedirectURIValid`（`core/types.go:382`）对已注册的 URI 进行精确匹配；注册流程在客户端创建时验证 URI
3. **PKCE 支持** — 可按客户端通过 `RequirePKCE` 配置；`oauth21Strict` 模式下强制使用仅 S256
4. **内置客户端注册要求 `require_pkce=true`** — `bootstrap/builtin/builtin.go:318`

**未实现：**
- 不存在 state 内容中的 `origin_hash`（HMAC(client_secret, origin)）

**影响评估：** 分析中描述的攻击向量（客户端注册了恶意的 `redirect_uri`）被*客户端注册验证*（元数据编辑时检查 redirect_uri）缓解，而非服务器端 state 绑定。如果 redirect_uri 注册流程允许通配符/子路径匹配，这才是一个真正的问题——但在本代码库中，`IsRedirectURIValid` 进行精确匹配。**优先级应降至 L**，因为实际攻击面被现有的 redirect_uri 验证 + PKCE 支持所覆盖。

---

## 方向 3：授权请求参数长度限制

**状态：✅ 已完全实现。** 全部到位——精确如分析中所描述。

`protocols/oauth/paramlimits.go`：
```go
const (
    MaxStateLen       = 2048
    MaxRedirectURILen = 2048
    MaxScopeLen       = 4096
    MaxNonceLen       = 256
    MaxResourceLen    = 2048
    MaxCustomParamLen = 4096
)
```

具有 `ValidateAuthRequestParamLength(key, value)` 针对单个参数，以及 `CheckAuthParamLengths(state, redirectURI, scope, nonce, resources)` 这个便捷封装。

**在两个调用点中调用：**
- `handle_par.go:182`——PAR 存储写入前
- `server_login.go:252`——授权码流程中

这是 **第 0 轮修复——无需任何操作**。

---

## 方向 4：OpenAPI 不含 Admin API

**状态：✅ 已实现。** OpenAPI 规范（8350 行，OpenAPI 3.0.3）确实包含 admin 端点。

46 个已记录的 `/api/v1/admin/*` 端点：

```
/admin/authz/policy-bundle
/admin/storage-health
/admin/snapshots, /admin/snapshots/{id}, /admin/snapshots/{id}:restore
/admin/releases, /admin/releases:current, /admin/releases/{id}, …（变体）
/admin/tenants, /admin/tenants/{id}, /admin/tenants/{id}/usage, …
/admin/clients, /admin/clients/{id}, /admin/clients/{id}/rotate-secret
/admin/users, /admin/users/{id}, /admin/users/{id}/sessions, …（10+ 个子路径）
/admin/account-lockout/clear
/admin/connections, /admin/connections/{id}
/admin/tenants/{id}/members, …/invitations
/admin/tokens/sessions, /admin/tokens/revoke, /admin/tokens/temp
/admin/permissions/{client_id}/roles, …/assignments, …/menus
```

规范文件头（第 17-22 行）明确说明：*"gRPC-gateway 下暴露的完整 admin gRPC 服务表面……覆盖范围现已完整涵盖 cmd/sso-server 在其参考配置中注册的每个端点。"*

**唯一的差距：** 规范是手动维护的而非自动生成。这意味着 proto 更改可能使其过期，除非使用 `make docs-validate`。**工作量：** S（添加 `make openapi-gen` 构建步骤，从 proto 生成），但**影响：低**（现有文档已相当出色）。

---

## 方向 5：Build 配置路径覆盖率

**状态：⚠️ 部分覆盖，但整体良好。** 存在于 3 个测试文件中：

| 文件 | 测试数量 | 覆盖内容 |
|---|---|---|
| `build_app_coverage_test.go` | 13 | 完整功能集、最小配置、gRPC 启动、日志记录、Pprof |
| `build_more_coverage_test.go` | 20 | 所有 SQLite 后端、Federation、Release、Bootstrap lock、Snapshot、PasswordResetStore（memory/sqlite/未知）、CAEP receiver（8 个测试）、SPIFFE（5 个测试）、CIBA（5 个测试） |
| `build_stores_coverage_test.go` | ~30 | Subordinate constraints、SigningKeyRegistry、RegionResolver、PasswordHealthChecker、PushWebhookTransport、存储构建器 |

**覆盖的组合：**
- 后端：memory、sqlite、etcd（当适用时）
- 路径：通过/失败、空/已配置、未知后端错误
- Federation：nil constrains、满约束、缺失 JWKS 文件
- CAEP：缺失受众、缺失 JWKS、错误的主体模式
- CIBA：memory 传输、sqlite、webhook、未知后端

**缺失的内容：** 没有工具来证明*每个* `if/else` 分支都被覆盖。重构可能留下未经测试的后端路径。

**建议：** 添加一个 `ci-config-coverage` target，枚举 `config.Schema()` 中的配置选择，并对照测试注册进行验证。**工作量：M**（非 L——schema 枚举仅约 100 行），**影响：M**（重构安全性）。

---

## 修订后的优先事项

| # | 方向 | 经评估的影响 | 工作量 | 判定 |
|---|---|---|---|---|
| 1 | ✅ gRPC 生产配置 | — | — | **已关闭——已实现** |
| 2 | ⚠️ State Origin 绑定 | 低（有缓解措施） | M | 现有缓解措施就绪；如需额外加固则保持开放 |
| 3 | ✅ 参数长度限制 | — | — | **已关闭——已实现** |
| 4 | ✅ OpenAPI Admin | — | — | **已关闭——已实现** |
| 5 | ⚠️ 配置路径覆盖率 | **中** | M（非 L） | **唯一可操作的项**——添加 schema 枚举 + CI 检查 |

**实际剩余工作：** 方向 5（配置路径覆盖率）是唯一报告了尚未完全解决的实际差距的方向。方向 2 有一个缓解后的剩余风险，但需要的是显式的 state→HMAC→origin 绑定，而非分析中建议的新端点保护。

**我会推荐的方向（按 ROI）：**
1. **（新）`config.Schema()` + `ci-config-coverage`** ——枚举所有配置分支，对照测试进行验证
2. **（可选）State origin HMAC** ——向 `state` 添加 HMAC(origin)，在 token 请求时验证——针对 PKCE+redirect_uri 验证无法触及的剩余攻击面进行深度防护
