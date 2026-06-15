# ARCHITECTURE.md — 系统架构

## 包依赖图
```
core/ ← 所有包依赖（无内部依赖）
  ↑
security/ ← 纯安全层
  ↑
oauth/ ←── oidc/   （oidc→oauth 允许，反之禁止）
  ↑        ↑
  └── sso/ ──┘  （编排层）
  ↑        ↑
admin/  grpcserver/
  ↑        ↑
cmd/sso-server/  （只能被 cmd 包导入）
```

## 严格依赖规则
| 规则 | 说明 |
|---|---|
| `oauth/` → `oidc/` | 禁止 |
| `oidc/` → `admin/` | 禁止 |
| `*` → `cmd/` | 禁止 |
| `core/` → `*` | 禁止（纯 SPI） |

## 路由注册
所有路由在 `sso.go` 的 `Mount()` 中注册。
中间件栈（由外到内）: `tracing → ratelimit → bodyLimit → metrics → CORS → router`

| 前缀 | 中间件 | 用途 |
|---|---|---|
| `/health`, `/livez`, `/readyz` | 无 | 健康检查 |
| `/.well-known/*` | 无 | 发现文档 |
| `/auth/*` | 完整栈 | 认证 |
| `/token*` | 完整栈 + no-store | 令牌 |
| `/me*` | Bearer 认证 | 自助服务 |
| `/api/v1/admin/*` | AdminMiddleware | 管理 |

## 存储后端
每个存储 = SPI 接口 + 默认内存 + 可选 SQLite/etcd/Redis。

| 子系统 | 配置键 |
|---|---|
| 身份 | `identity.backend` |
| OAuth 存储 | `oauth.<store>.backend` |
| JTI/Lockout | `security.{jti_replay,account_lockout}.backend` |
| 审计 | `audit.backend` |
| 权限 | `permissions.backend` |
| 租户 | `tenant.backend` |
