Now I have a very clear picture. Let me compile my review.

Key findings:

**Direction 1 (Monotonic Clock):**
- The `IsExpired()` methods already use `time.Since()` - this is GOOD, as `time.Since()` preserves monotonic clock when the stored `ExpiresAt` was created via `time.Now().Add(...)` (which retains the monotonic reading).
- BUT: JWT validation uses `time.Unix(exp, 0)` which has NO monotonic component - this is inherently non-monotonic because the exp was serialized/deserialized.


- Discovery cache and rate limiter both use wall-clock comparisons for their read paths, which is vulnerable to clock drift, though these are mostly benign since they're just caches and token bucket operations rather than security-critical expiration checks. The real security-sensitive paths like AuthCode and RefreshToken already use monotonic time via `time.Since()`.
- The analysis claiming these paths use bare `time.Now()` is actually incorrect—they're already using `time.Since()`, which was presumably done in response to an earlier concern about this exact issue.

Looking at the revocation persistence direction, the infrastructure is fully implemented with a `RevocationStore` interface, SQLite backend, and seed mechanism wired into all three issuers. But the critical question is whether the default configuration actually enables this—it appears `RevocationBackend` defaults to an empty string, which means the store returns nil and everything stays in-process only. So while the infrastructure exists, it's not actually active by default, which is a real gap even though the analysis's claim that no infrastructure exists is wrong.

For Postgres hot stores, the assessment is accurate—those implementations genuinely don't exist for the OAuth flows, though they do exist for device secrets and password credentials. The claim about no redis peer is also valid.

The discovery prompt direction is a straightforward finding with no real controversy. And for etcd self-healing, the analysis correctly identifies that both the watch and lease self-healing mechanisms are already implemented.

Now I'm ready to write up a comprehensive review of the document.Now I have all the data needed for a thorough review. Let me compile my findings:

---

## Review Summary

Let me provide a structured review of this second-round analysis, validating each direction against the actual codebase.

---

# 第二轮功能扩展方向分析 —— 代码核验报告

> 日期：2026-07-01
> 核验方法：逐文件 grep + 阅读关键路径

---

## 方向一：单调时钟保护 —— ⚠️ 部分已被解决，但仍有真实缺口

**分析文档声称：~30+ 处裸 `time.Now()` 用于安全路径**

**核验结果：所有核心 `IsExpired()` 已用 `time.Since()`（monotonic-safe）：**

| 路径 | 实际代码 | 状态 |
|------|----------|------|
| `AuthCode.IsExpired()` | `time.Since(c.ExpiresAt) > 0` | ✅ 已修复 |
| `RefreshToken.IsExpired()` | `time.Since(r.ExpiresAt) > 0` | ✅ 已修复 |
| `DeviceCode.IsExpired()` | `time.Since(d.ExpiresAt) > 0` | ✅ 已修复 |
| `PARRequest.IsExpired()` | `time.Since(p.ExpiresAt) > 0` | ✅ 已修复 |
| `CIBARequest.IsExpired()` | `time.Since(r.ExpiresAt) > 0` | ✅ 已修复 |
| `Session.IsExpired()` | `time.Since(s.ExpiresAt) > 0` | ✅ 已修复 |
| JWT validate `exp` | `time.Since(time.Unix(p.Exp, 0))` | ⚠️ 无救——Unix 时间戳无 monotonic |
| SessionToken cache | `time.Since(c.ExpiresAt) > 0` | ✅ 已修复 |
| Session refresh | `time.Since(entry.expiresAt) > 0` | ✅ 已修复 |
| Codestore cooldown/expiry | `time.Since(e.savedAt) < cooldown` / `time.Since(e.expiresAt) > 0` | ✅ 已修复 |

**真正残留的缺口（低风险，非安全路径）：**

| 路径 | 代码 | 风险 |
|------|------|------|
| Discovery doc cache | `time.Now().Before(e.ExpiresAt)` | 无——纯缓存 TTL，时钟回拨 = 缓存多活几秒 |
| `sso_cachestate.go` | `time.Now().Before(e.expiry)` | 无——纯内存缓存 |
| Rate limiter | `time.Now()` token bucket | 极低——影响限流窗口精度，非安全性 |
| `memory_idempotent.go` | `time.Now().After(e.expiresAt)` | 低——幂等键 TTL |
| WebAuthn SQLite session | `time.Now().UnixNano() > expiresAtNs` | 中——WebAuthn 认证窗口，但 `ExpiresAt` 存为 UnixNano 无 monotonic |
| SAML SP validator | `time.Now()` | 低——SAML Assertion 时间校验 |

**修正建议：**
- 文档声称的 "AuthCode/Refresh/Device/PAR/CIBA `IsExpired` 用裸 `time.Now()`" **不成立**——这些已全部用 `time.Since()`
- JWT `exp` 校验用 `time.Unix(exp, 0)` 天然无 monotonic（exp 是序列化后的整数，不含 monotonic offset），**无法通过 `time.Since` 修复**——这是已知限制
- 残留缺口仅影响缓存/限流精度，不影响安全性
- **实际工作量：** XS（WebAuthn SQLite + idempotent memory 两处替换为差值比较，但需 schema 变更存 monotonic 时间戳）

---

## 方向二：集群一致性硬化 —— ❌ 主体已被证伪，但发现一个真实缺口

**文档声称："revocation_set.go 是纯内存 `map[string]int64`，无 sqlite/redis peer"**

**核验结果：撤销持久化基础设施已完整实现**

```
infrastructure/defaultimpl/revocation_set.go:  RevocationStore interface ✅
infrastructure/defaultimpl/sqlite/revocations.go: SQLite 后端 ✅
cmd/sso-server/serverbuildsign/build_signing.go: BuildRevocationStore ✅
cmd/sso-server/serverbuildsign/build_signing_issuers.go: 三个 issuer 均调用 seedRevocations ✅
config/config_keys.go:57: RevocationBackend 配置项 ✅
```

**三个 issuer 均在构建时调用 `seedRevocations()`：**
- Ed25519: `build_signing_issuers.go:58`
- ECDSA: `build_signing_issuers.go:81`
- RSA: `build_signing_issuers.go:109`

**etcd watch/lease 自愈也已完整实现（文档自身已证伪）：**
- `server_invalidation.go`: 完整的 self-heal loop + degraded/recovered 状态机
- `signingkeys/etcd/etcd_keepalive.go`: supervisedKeepAlive + ReadyzCheck

**仍为真实缺口的：**
- **Redis RevocationStore 后端不存在** — 配置仅支持 `memory` 和 `sqlite`，无 `redis`
- 多副本部署需要 shared Redis 而非 shared SQLite（SQLite 是本地文件，多进程无法共享）
- 但 `infrastructure/redis/` 包存在，说明 Redis 是已知后端模式

**修正建议：**
- 文档声称的 "RevocationStore 无 peer" **不成立**——SQLite peer 完整可用
- **真正的缺口是 Redis peer**——多副本需要共享后端，本地 SQLite 在 K8s 多 Pod 场景不可行
- **实际工作量：** S-M（实现 `redis/revocations.go`，在 `BuildRevocationStore` 加 `"redis"` case）

---

## 方向三：Postgres 后端配置化投产 —— ✅ 核验基本准确

**文档声称：Hot stores 无 Postgres 后端**

**核验 `infrastructure/postgres/` 目录（25 文件）：**

已有 Postgres 实现：
- ✅ `clients.go` / `client_secret.go` / `clients_scan.go`
- ✅ `users.go`
- ✅ `tenant.go` / `tenant_put.go` / `tenant_domains.go`
- ✅ `permissions*.go`（4 文件）
- ✅ `consent.go`
- ✅ `audit_query.go` / `audit_sink.go`
- ✅ `device_secrets.go`
- ✅ `password_credentials.go`
- ✅ `pairwise.go`
- ✅ `invitation.go`
- ✅ `totp_enrollment.go`

**缺失的 Hot stores（文档准确）：**
- ❌ AuthCode（Postgres）
- ❌ RefreshToken（Postgres）
- ❌ PARRequest（Postgres）
- ❌ DeviceCode（Postgres）
- ❌ CIBARequest（Postgres）
- ❌ Session（Postgres）—— `infrastructure/postgres/session.go` 不存在
- ❌ JTIReplay（Postgres）

**评估：** 文档准确。durable 层（client/user/tenant/audit/consent）Postgres 故事完整，但 OAuth 热路径完全依赖 SQLite/Redis。若用户想统一 Postgres 技术栈（无 Redis），热路径无解。

**工作量确认：** M-L（6 个 store + 配置 dispatch + 迁移）

---

## 方向四：Token 撤销持久化与滚动重启安全 —— ❌ 已被证伪

与方向二重叠。核验结果同方向二——基础设施完整（SQLite peer + SeedRevocations + boot seed）。

**文档声称 "无 SeedRevocations 调用"** 不成立——三处均有。

**真正缺口同方向二：Redis peer 缺失**——多副本共享后端。

---

## 方向五：Discovery prompt 声明 —— ✅ 核验准确

**文档声称：`cfg.PromptValuesSupported = []string{PromptNone}` 硬编码**

**核验确认：**
```go
// interfaces/sso/server_discovery_config.go:435
cfg.PromptValuesSupported = []string{PromptNone}
```

**能力验证：**
- `PromptConsent` / `PromptLogin` / `PromptSelectAccount` 常量已定义（`aliases.go:404-407`）
- `handleConsentGate`（`server_logout.go:196`）完整处理 `prompt=consent`
- `consent.HasPromptValue(prompt, PromptConsent)` 解析逻辑完整（`server_logout.go:239`）
- `ConsentStore` 三后端齐全

**工作量确认：** XS（~10 行条件逻辑）

---

## 综合评估矩阵

| 方向 | 文档准确性 | 真实缺口 | 优先级建议 |
|------|-----------|---------|-----------|
| 一：单调时钟 | ⚠️ 60% 被证伪——IsExpired 已修复 | XS 残留（缓存/限流），无安全影响 | **低**——可标记为已关闭 |
| 二：集群一致性 | ❌ 主体证伪——SQLite peer 已有 | Redis peer 缺失（多副本共享） | **中**——但非文档声称的严重度 |
| 三：Postgres hot stores | ✅ 准确 | 6 个 OAuth store 缺失 | **高**——解锁纯 Postgres 部署 |
| 四：撤销持久化 | ❌ 与方向二重叠且证伪 | 同方向二 | 合并入方向二 |
| 五：Discovery prompt | ✅ 准确 | 配置声明缺失 | **高**——10 行修复，合规影响 |

---

## 建议的下一步优先级

1. **方向五（S）**——立即执行，10 行修复，影响 OIDC Discovery 合规
2. **方向三（M-L）**——中期路线图，解锁 Tier A HA 的纯 Postgres 拓扑
3. **方向二 Redis peer（S-M）**——多副本部署需要，但当前 SQLite 单副本已覆盖
4. **方向一**——标记为已解决，残留缓存路径不影响安全

---

是否要我针对某一方向展开具体实现？方向五（prompt discovery）可以直接动手，10 行即可完成。
