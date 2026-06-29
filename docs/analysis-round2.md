# 功能扩展方向分析 —— 第二轮

> 日期：2026-06-29
> 扫描范围：深度聚焦 `time.Now()`、etcd lease 自愈、Postgres 配置化
> 视角：运维/安全/规模

---

## 方向一：单调时钟保护 — 时钟回拨可使过期 token 复活

**经 grep 逐行核验，约 30+ 处使用裸 `time.Now()`：**

| 路径 | 文件 | 行 |
|------|------|----|
| JWT 验签 `exp` | `ed25519_validate.go` | 111 |
| JWT 验签 `exp` | `ecdsa_validate.go` | 103 |
| JWT 验签 `exp` | `rsa_validate.go` | 105 |
| Session refresh | `memory_session.go` | 40, 112 |
| SessionToken cache refresh | `defaulttoken/jwt_issuer.go` | 94 |
| AuthCode/Refresh/Device/PAR/CIBA `IsExpired` | `oauthspi/*.go` | 5 处 |
| Rate limiter | `ratelimit/ratelimit.go` | 133 |
| SQLite rate limiter | `sqlite_limiter.go` | 151 |
| Token exchange auth_time | `server_native_sso.go` | 192 |
| Federation `FederationNow()` | `accessors.go` | 315 |
| Cert auth CurrentTime | `certificate.go` | 104 |
| Login finish `AuthTime` | `server_finish_login.go` | 198, 235, 306 |

**风险场景：**
- 运维 ntpdate 步进使时钟回拨 600 秒
- K8s 节点时钟 drift 被 NTP 纠正（ntpd step）
- VM 快照回滚
- 容器冷启后从 NTP 获取更早的时间

**影响：** 过期 session 可被无限续期；Rate limiter token bucket 重置；AuthTime 非单调触发 step-up 误判。

**建议：**
- `IsExpired` 检查用 `time.Since(t) > 0`（Go 自动携带 monotonic offset）
- Rate limit 窗口比较用 `now.Sub(b.lastSeen)`
- Session refresh 加 `monotonicNow` 注入

**工作量：** S（~15-20 处安全路径替换）

---

## 方向二：集群一致性硬化 — etcd watch/lease 静默黑洞

**经代码核验——此方向部分已被证伪、部分仍有缺口：**

### 证伪：etcd watch 自愈已实现

`interfaces/sso/server_invalidation.go:152`：
```go
s.logger.Error("invalidation bus subscription closed while running; ... resubscribing")
```
有 `setInvalidationBusDegraded()` / `setInvalidationBusHealthy()` 的自愈模式，有 metrics（`InvalidationBusUp`、`InvalidationBusReconnectsTotal`），有 readiness 集成。

### 证伪：signingkeys/etcd KeepAlive 自愈已实现

`platform/signingkeys/etcd/etcd_keepalive.go:106`：
```go
func (r *Registry) supervisedKeepAlive(...)
```
lease 过期后标记 degraded → 指数退避 → 重新 grant → 重新发布 → 恢复，有 `ReadyzCheck()` 集成。

### 仍为缺口：跨副本撤销持久化

`infrastructure/defaultimpl/revocation_set.go` 是纯内存 `map[string]int64`，无 sqlite/redis peer。`With{Algo}RevocationStore` 选项存在但只有 `memory` backend。**这意味着滚动重启可以复活已被撤销但未过期的 access token。**

**工作量：** M（三个 issuer peer + 启动时 `SeedRevocations` re-seed）

---

## 方向三：Postgres 后端配置化投产

**经代码核验——最初假设被证伪：**

`cmd/sso-server/build_stores.go:283` 有 `wirePostgres()` 将 Postgres 接入二进制。`config/config.go:40` 定义了 `PostgresConfig`。`infrastructure/postgres/` 有 25 个文件覆盖 clients/users/tenants/permissions/consent/audit/pairwise。

**真正的剩余缺口：**

1. **Hot stores 无 Postgres 后端** — AuthCode、RefreshToken、PAR、DeviceCode、CIBA、JTIReplay、Session 的 Postgres 实现完全不存在
2. **Session 无 Postgres 后端** — `infrastructure/postgres/session.go` 不存在
3. **配置树已集成但 store 分派未覆盖全部** — 如 `oauth.backend: postgres` 的 dispatch 路径需验证

Tier B HA 拓扑（hot→Redis, durable→Postgres）的 durable 层 Postgres 故事已基本完整，但热路径的 Postgres 缺失意味着如果用户想全部用 Postgres（统一 DB 技术栈），没有办法。

---

## 方向四：Token 撤销持久化与滚动重启安全

（与方向二 ③ 重叠，聚焦不同角度）

**当前状态：**
- `revoked` map 仅内存（`map[string]int64`）
- 重启后 map 空，无 `SeedRevocations` 调用
- 滚动更新期间，新副本启动时 `IsRevoked` 对已撤销的 token 返回 `false`

**风险场景：**
1. K8s 滚动更新 → 副本 B 启动时 `revoked` map 为空
2. 已被撤销但未过期的 access token 在副本 B 上 IsRevoked 为 false → **token 复活**
3. 滚动更新越慢（PDB 优雅停止 ~5min），攻击窗越长

**建议：**
- 为 `RevocationSet` 添加 sqlite/redis peer
- 启动时 `SeedRevocations(ctx, afterTime)` 回填内存 map（有界于 `max_token_ttl`）

**工作量：** M

---

## 方向五：Discovery 产品化 — 补齐 `prompt=consent/login/select_account` 声明

**代码验证：**
```go
// interfaces/sso/server_discovery_config.go:423
cfg.PromptValuesSupported = []string{PromptNone}
```
注释明确说"交互式 prompt 不声明因为服务器不渲染 UI"。

**但能力已在：**
- `handleConsentGate`（`server_logout.go:189`）完整处理 `prompt=consent`
- `ConsentStore` 三后端齐全
- `PromptLogin` / `PromptConsent` / `PromptSelectAccount` 常量完整定义

**建议：** `if s.consentStore != nil { append(PromptConsent) }`

**工作量：** S（~10 行配置逻辑）

---
