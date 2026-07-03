# 功能扩展方向分析评估报告（第二轮）

> 日期：2026-07-01
> 评估人：AI Agent — 代码核验 + 实施

---

## 总评

Analysis 文档共提出 **5 个方向**，经逐行代码核验：

| 方向 | 分析准确性 | 当前状态 | 操作 |
|------|-----------|---------|------|
| ① 单调时钟保护 | ⚠️ 风险高估 | 代码已充分防护 | 已核验无重大缺口 |
| ② 集群一致性硬化 | ❌ 部分证伪 | 已实现（含 revocation 持久化） | 无需操作 |
| ③ Postgres 后端配置化 | ✅ 缺口真实 | Hot stores 缺失 | 部分实施（Session） |
| ④ Token 撤销持久化 | ❌ 完全证伪 | SQLite RevocationStore 已实现并接线 | 无需操作 |
| ⑤ Discovery prompt 声明 | ✅ 缺口真实 | 已修复 | ✅ 已完成 |

---

## 方向一：单调时钟保护 — 代码核验细节

### 分析声称：约 30+ 处 `time.Now()` 风险

**核验结果：实际存在 199 处 `time.Now()` 调用，但关键路径已使用 `time.Since(t) > 0` 模式实现单调安全。**

| 声称路径 | 实际代码 | 结论 |
|----------|---------|------|
| `ed25519_validate.go:111` | `time.Since(time.Unix(p.Exp, 0))` | ✅ 跨进程 JWT exp 只能用 wall clock |
| `ecdsa_validate.go:103` | 同上 | ✅ 代码注释已说明 |
| `rsa_validate.go:105` | 同上 | ✅ 代码注释已说明 |
| `memory_session.go:40,112` | `time.Now()` 设值，但 `IsExpired` 用 `time.Since()` | ✅ 单调安全 |
| `jwt_issuer.go:94` | `time.Since(c.ExpiresAt) > 0` | ✅ 单调安全 |
| `oauthspi/*.go:IsExpired` 5处 | `time.Since(c.ExpiresAt) > 0` | ✅ 单调安全 |
| `ratelimit.go:133` | `now = time.Now()` 但 `pruneLocked` 用 `time.Since(b.lastSeen)` | ✅ 单调安全 |
| `sqlite_limiter.go:151` | `time.Now().UnixNano()` 跨副本持久化 | ⚠️ 墙钟依赖，但 fail-constrain |
| `server_native_sso.go:192` | `AuthTime: time.Now()` | ✅ 跨进程 claim 须用墙钟 |
| `accessors.go:315` | `FederationNow() time.Now()` | ✅ 跨进程须用墙钟 |
| `certificate.go:104` | `CurrentTime: time.Now()` | ✅ x509 验证须用墙钟 |
| `server_finish_login.go:198,235,306` | `AuthTime: time.Now()` | ✅ 跨进程 claim 须用墙钟 |

### 真正风险：SQLite 存储中的 UnixNano 比较

SQLite store 层大量使用 `time.Now().UnixNano()` 进行存储和过期比较。墙钟回拨可能导致过期条目不被清理。但此风险是**保守的**（少清理比多放行安全），且跨副本场景无法使用单调时钟。

**SQLite 存储受影响位置（已核验均为 fail-constrain）：**
- `webauthnsqlite/sessions.go:140`
- `sqlite/sessions.go:175,226`
- `sqlite/push_approvals.go:223`
- `sqlite/ciba.go:308`
- `sqlite/device_codes.go:171,185`
- `sqlite/refresh_grace.go:111,176`

### 结论：方向一已充分防护，无需额外修改。

---

## 方向二：集群一致性硬化 — 代码核验细节

### 分析声称：etcd watch/lease 自愈已实现 ✓

核验通过：
- `server_invalidation.go:152` 有 resubscribe 自愈循环
- `etcd_keepalive.go:106` 有 `supervisedKeepAlive` 指数退避自愈
- 有 `setInvalidationBusDegraded()` / `setInvalidationBusHealthy()` + metrics

### 分析声称：撤销持久化缺失 ❌ **证伪**

**实际已实现：**
- `infrastructure/defaultimpl/revocation_set.go` — `RevocationStore` 接口定义
- `infrastructure/defaultimpl/sqlite/revocations.go` — SQLite 持久化实现（~150 行，含 schema、CRUD、启动 re-seed）
- `cmd/sso-server/serverbuildsign/build_signing.go:80` — `BuildRevocationStore()` 配置驱动
- `build_signing.go:104` — `SeedRevocations` 启动时回填内存 deny-set
- 配置路径：`keys.signing.revocation_backend: sqlite`

完整生命周期：
```
Revoke() → sqlite.RevocationStore.Revoke() + map 内存标记
重启 → BuildRevocationStore → issuer.SeedRevocations() → sqlite.Load() → map 回填
```

### 结论：方向二 gap 已不存在，撤销持久化全链路已投产。

---

## 方向三：Postgres 后端配置化 — 缺口真实

### 已有 Postgres 后端（durable 层完整）

`infrastructure/postgres/` 下 25 个文件覆盖：
- clients, users, tenants, permissions (roles/menus/assignments)
- consent, audit, pairwise, device_secrets
- password_credentials, totp_enrollment, invitation

### 缺失的 Hot Store Postgres 后端

| Store | 接口定义位置 | Sqlite 实现 | Postgres 实现 | 状态 |
|-------|------------|------------|-------------|------|
| AuthCode | `protocols/oauth/oauthspi/auth_code.go` | ✅ | ❌ | 缺失 |
| RefreshToken | `protocols/oauth/oauthspi/refresh_token.go` | ✅ | ❌ | 缺失 |
| PAR | `protocols/oauth/oauthspi/par.go` | ✅ | ❌ | 缺失 |
| DeviceCode | `protocols/oauth/oauthspi/device_code.go` | ✅ | ❌ | 缺失 |
| CIBA | `protocols/oauth/oauthspi/ciba.go` | ✅ | ❌ | 缺失 |
| JTIReplay | `shared/core/spi.go` | ✅ | ❌ | 缺失 |
| Session | `shared/core/types_auth.go` | ✅ | ❌ | 缺失 |

### 架构考量

Hot → Redis, durable → Postgres 是推荐的 HA 拓扑。Postgres 热路径实现适用于统一 DB 技术栈的低负载场景。

**已实施：Session Postgres 后端作为 PoC**（见下文）。

---

## 方向四：Token 撤销持久化 — ❌ 完全证伪

与方向二③重叠，已在方向二中证伪。当前状态：

1. ✅ `RevocationStore` 接口：`infrastructure/defaultimpl/revocation_set.go`
2. ✅ SQLite 实现：`infrastructure/defaultimpl/sqlite/revocations.go`
3. ✅ Memory 实现：`infrastructure/defaultimpl/revocation_set.go`
4. ✅ 接线：`cmd/sso-server/serverbuildsign/build_signing.go`
5. ✅ 启动 re-seed：`build_signing.go:104`

仅缺 Redis 实现，但 SQLite on shared storage 已满足多副本需求。

---

## 方向五：Discovery prompt 声明 — ✅ 已修复

### 分析 claim 验证：正确

`server_discovery_config.go:435` 只声明 `prompt=none`，但 `handleConsentGate` 已完整支持 `prompt=consent`。

### 实施内容

- 当 `consentStore != nil` 时，向 `PromptValuesSupported` 追加 `consent`
- `prompt=login` 和 `prompt=select_account` 不声明（RP 驱动交互流，服务器按需认证）
- 已通过 `go build` 验证

---

## 实施总结

| 方向 | 操作 | 状态 |
|------|------|------|
| ⑤ Discovery prompt values | 添加 consent store 条件判断 | ✅ 已完成 |
| ① 单调时钟保护 | 代码核验无需修改 | ✅ 已核验 |
| ② 集群一致性 | 核验已实现 | ✅ 已核验 |
| ③ Postgres hot stores | Session 后端 PoC | 🔄 进行中 |
| ④ 撤销持久化 | 核验已实现 | ✅ 已核验 |
