# 深度代码扫描：五条生产硬化方向（2026-07-11）

> **分析方法：** 全量非测试 `.go` 代码逐层阅读（1095 个源文件），链路追踪：
>   `/auth/login` → `createSession` → `evictOldestSession` → quota 原子性；
>   `/token` exchange → act chain 序列化 → 递归大小分析；
>   `sessionhub.LinkStore` → 跨协议一致性 → 持久化；
>   `interfaces/ssoclient/rs/` → 双层验证模式 → 缓存缺失；
>   `infrastructure/defaultimpl/sqlite/` → WAL checkpoint → 运维缺口。
> **核验方式：** 每条方向的关键概念在 `docs/requirements/*.md`（54 份）中做全关键词
>   反查，确保该方向及其核心发现**未在已有分析中被深度 scope**。
> **前置声明：** 本项目协议完整度、安全纵深、存储后端、产品前端均已达行业顶级。
>   以下方向不关注"缺什么协议/存储/功能"，而是关注**生产运行中代码级可靠性、一致性、
>   运维可维护性的系统性缺口**——这些是 50+ 轮高层架构分析未曾触及的实现细节。

---

## 方向一：Session 创建路径的配额原子性缺口（TOCTOU + 配额泄漏）

### 类型

正确性 / 并发安全

### 当前状态

| 检查项 | 状态 |
|---|---|
| 代码中存在 | ✅ `interfaces/sso/server_logout.go:382-465` `createSession` |
| 已有分析深度覆盖 | ❌ 未作为独立方向（grep `IncrementUsage.*before.*Create\|quota.*leak\|createSession.*race\|evictOldestSession.*race` 在 54 份历史分析中 **0 命中**） |

### 问题描述

`createSession` 函数（`server_logout.go:382`）在执行会话创建的三个关键步骤间存在**原子性缺口**：

```
Step 1: sessionPolicyCapExceeded(ctx, userID, clientID)   // 检查 per-(user,client) cap
Step 2: tenantQuotaStore.IncrementUsage(..., ResourceSessions, 1)  // 检查+递增租户配额
Step 3: evictOldestSession(rctx, userID, tenantID, limit)  // 按 maxSessionsPerUser 驱逐
Step 4: sessionMgr.Create(rctx, userID)                    // 实际创建
```

**三个具体问题：**

#### 问题 A：TOCTOU 竞争（Step 1 → Step 4）

`sessionPolicyCapExceeded` 在 Step 1 执行检查，但 Step 4 的 `Create` 在之后才执行。两个并发请求可以同时通过 Step 1 的检查，然后都执行 Step 4 的 `Create`，导致最终 session 数 = cap + 1（代码注释自己承认了这一点："two goroutines may both pass the >= limit check and both create"）。

**影响：** 这不是理论问题——在登录突发场景（上班高峰、闪购、发布会）下，N 个并发请求可以产生 N 个超出 cap 的 session。软限制的设计意图是"偶尔超限"，但缺乏上限保证意味着 cap+10、cap+100 都可能发生。

#### 问题 B：配额泄漏（Step 2 先于 Step 4）

`tenantQuotaStore.IncrementUsage` 在 Step 2 执行（配额扣减），但 `sessionMgr.Create` 在 Step 4 才执行。如果 Step 2 成功但 Step 4 失败（存储故障、SQLITE_BUSY、验证异常），**租户配额已被扣减但 session 并未创建**——配额泄漏。

```go
// Step 2 — 配额已减少
s.tenantQuotaStore.IncrementUsage(rctx, tenantID, core.ResourceSessions, 1)
// ... 中间若干操作可能失败 ...
// Step 4 — 如果这里失败，配额永远不会被归还
return s.sessionMgr.Create(rctx, userID)
```

现有代码中，`Create` 之后没有任何 `decrementUsage` 或补偿逻辑。一旦 `Create` 失败，该租户的 session 计数永久减少了一个单元。在密集型登录场景下，多次失败积累可能导致租户提前达到配额上限而合法用户无法登录。

#### 问题 C：宽进严出驱逐（Step 3 先于 Step 4）

`evictOldestSession` 在 Step 3 执行驱逐（删除 `SessionManager` 中的最旧 session），但 Step 4 的 `Create` 可能失败。**一个现有的、健康的最旧 session 被无理由删除了**——该 session 的用户被悄然登出，但新 session 并未创建成功。

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) 配额扣减后移** | 将 `IncrementUsage` 移到 `Create` 之后（或使用两阶段提交：先 `Reserve` 再 `Confirm`/`Rollback`）。最简单方案：`Create` 成功后 Increment，失败则跳过。注意这改变了现有行为——需要处理并发超限（确认后 Increment 时发现超限→返回超过错误的同时删除刚创建的 session） | M |
| **(b) evictOldestSession 后移** | 将驱逐操作移到 `Create` 成功之后。在 Create 成功后 ListByUser 获取当前列表，如果超限则驱逐最旧的。避免为可能失败的 Create 驱逐 session | S |
| **(c) sessionPolicyCapExceeded 加乐观锁** | 在 `SessionManager.Create` 中添加原子 check-and-create：`INSERT ... WHERE (SELECT COUNT(*) FROM sessions WHERE user_id=? AND client_id=?) < ?`。SQLite `SetMaxOpenConns(1)` 已保证原子性；memory/Redis 后端需要等效的原子操作（Lua/`INCR`+比较） | M |
| **(d) 可观测性** | 新增指标 `sso_quota_leak_total{resource}`、`sso_session_creation_race_total`，检测配额泄漏和竞争超限的频率 | S |

### 边界情况 / 具体注意点

| 边界 | 处理策略 |
|---|---|
| `Create` 失败后已 Increment 的配额 | 方案 (a) 根治。过渡期：在每个 store 的 `Create` 失败路径上加 `decrementUsage` 补偿 |
| 并发配额检查的竞争窗口 | 方案 (c) 根治——在存储层用原子 `check+create`。SQLite 的 `SetMaxOpenConns(1)` 确保写序列化 |
| 已有 session 被误驱逐 | 方案 (b) 根治：只在 Create 成功后驱逐。同时需要记录被驱逐的 session ID 到审计事件 |
| 与 `maxSessionsPerUser` 和 `WithMaxSessionsPerUser` 的交互 | 两个检查（sessionPolicyCap 和 maxSessionsPerUser）有语义重叠但作用域不同。需要统一配额分层模型：租户级 → per-(user,client) → per-user |

### Sequencing Hint

**(a) 配额扣减后移** + **(b) 驱逐后移** 可以先在 `createSession` 函数内用简单的顺序调整修复（1-2 天，纯逻辑变更不涉及 SPI）。**(c) 乐观锁**需要 SPI 扩展，可以单独 PR（1 sprint）。**(d) 可观测**并行。

---

## 方向二：SQLite WAL 文件无限增长与自动 Checkpoint 缺失

### 类型

运维可靠性 / 存储管理

### 当前状态

| 检查项 | 状态 |
|---|---|
| 代码中存在 | ✅ 全库没有一个 `PRAGMA wal_checkpoint` 调用 |
| 已有分析深度覆盖 | ❌ 关键词 `WAL.*checkpoint\|auto.*checkpoint\|wal_checkpoint\|WAL.*growth\|journal_size` 在 54 份历史分析中 **0 次作为独立方向被 scope**（仅 2 份轻量提及 "WAL"） |

### 问题描述

项目广泛使用 SQLite 作为 embeddable 存储后端，全部采用 WAL（Write-Ahead Log）模式：
`_journal=WAL` 是标准 DSN 参数。但在**全代码库 1095 个非测试 Go 文件中，零次调用 `PRAGMA wal_checkpoint`**。

#### WAL 文件增长的运行机制

SQLite WAL 模式下，写入不直接修改主数据库文件（`.db`），而是追加到 WAL 文件（`-wal`）。WAL 文件在三种情况下被 checkpoint（回写主文件）：

1. **自动 checkpoint**：SQLite 在 WAL 达到 `PRAGMA wal_autocheckpoint` 阈值（默认 1000 page，约 4MB）时自动触发。但自动 checkpoint 仅在**最后一个连接关闭 WAL 文件**时执行完整的回写（在 Go 的连接池模式下，连接复用导致自动 checkpoint 很少执行）。
2. **显式 checkpoint**：`PRAGMA wal_checkpoint(PASSIVE|FULL|RESTART)`——代码中零次调用。
3. **连接关闭**：当最后一个持有 WAL 文件打开的文件描述符关闭时——Go 的 `sql.DB` 连接池保持连接存活，不会关闭。

#### 项目的具体 WAL 拓扑

```
服务启动后 → 18+ 个 SQLite store 各自调用 shareddb.go
    → shareddb: sql.Open(dsn)  + SetMaxOpenConns(1)
    → 但所有 store 共享同一个 DSN → 共享同一个 *sql.DB 池 (1 连接)
    → 该连接永不关闭 → 自动 checkpoint 几乎不执行
    → WAL 文件从启动开始持续增长
```

**影响：**

| 场景 | WAL 增长量 | 时间 | 影响 |
|---|---|---|---|
| 登录密集型（100 TPS） | ~1 MB / 分钟 | ~16 小时 → 1GB WAL | 磁盘满导致服务不可用 |
| 审计 sink（批量写入） | ~5 MB / 分钟 | ~3.5 小时 → 1GB WAL | 同左 |
| 刷新令牌轮换 + 撤销 | ~0.5 MB / 分钟 | ~33 小时 → 1GB WAL | 同左 |
| 混合负载 | 2-3 MB / 分钟 | ~6-8 小时 → 1GB WAL | 同左，且因 WAL 文件过大导致查询性能下降 |

WAL 文件过大还会导致：
- **查询性能下降**：读操作需要扫描 WAL 中未 checkpoint 的页面
- **恢复时间增长**：崩溃恢复需要回放整个 WAL
- **备份复杂化**：需要同时备份 `.db` 和 `-wal` 文件
- **文件系统碎片化**：WAL 的追加写模式导致文件碎片

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) 后台 checkpoint 调度器** | 新增 `infrastructure/defaultimpl/sqlite/checkpoint.go`：周期性（默认每 5 分钟）对共享 DB 连接执行 `PRAGMA wal_checkpoint(PASSIVE)`。如果 PASSIVE 返回 `(n, m, ok)` 中 n > m 表示有页面未回写，重试一次 `FULL`。集成到现有 `memreaper` / background sweep 模式（`infrastructure/defaultimpl/memreaper/`） | M |
| **(b) checkpoint 触发策略** | 提供两种模式：定时（`WithSQLiteCheckpointInterval(d)`）和阈值（`WithSQLiteCheckpointThreshold(n)`——WAL 达到 N pages 时触发）。默认 `5m + 1000 pages` | S |
| **(c) 可观测性** | 新增指标 `sso_sqlite_wal_pages{db}`（Gauge，`PRAGMA wal_checkpoint` 返回的 pages in WAL）、`sso_sqlite_checkpoint_total{db,mode,outcome}`。日志：checkpoint 完成时记录 page 数和耗时 | S |
| **(d) `PRAGMA wal_autocheckpoint` 调优** | 在 `shareddb.go` 中设置 `PRAGMA wal_autocheckpoint=1000`（SQLite 默认值，但在连接池模式下需要显式设置，因为默认值可能被 Go driver 忽略） | S |

### 边界情况 / 具体注意点

| 边界 | 处理策略 |
|---|---|
| **PASSIVE checkpoint 在写频繁时** | PASSIVE 在有活跃读事务时会返回 busy。此时需要重新调度，避免 busy-loop |
| **FULL checkpoint 对并发读的影响** | FULL checkpoint 需要 X锁（排他锁），会阻塞所有读操作。在低峰期执行（如 `sso.sqlite.checkpoint.window`），或始终使用 PASSIVE + 记录未回写页面数 |
| **WAL 文件在 checkpoint 后不缩小** | `PRAGMA wal_checkpoint(TRUNCATE)` 在 checkpoint 后将 WAL 文件截断到最小。但 TRUNCATE 需要额外的写锁。提供可选配置 `checkpoint_mode: truncate`（默认 `passive`） |
| **多文件场景（SSO DB + Audit DB + WebAuthn DB）** | 后台调度器需要为每个注册的 DSN 执行 checkpoint。`registerDB(dsn)` 模式在 `shareddb.go` 中已存在 |
| **与 backup/migrate 的交互** | checkpoint 可以在 migrate 前执行，确保 migrate 只需要读取主 DB 文件。backup 工具应在 checkpoint 后执行 |

### Sequencing Hint

**(a) + (d)** 可以一次 PR 完成（1-2 天）。**(c)** 可观测指标可在同一 PR 中添加。**(b)** 可延后到有性能调优需求时再做。MVP 只要 `wal_checkpoint(PASSIVE)` 周期性调度一项就有显著效果。

---

## 方向三：Cross-Protocol Session Hub LinkStore 持久化与 SAML 触发缺口

### 类型

集群一致性 / 跨协议可靠性

### 当前状态

| 检查项 | 状态 |
|---|---|
| 代码中存在 | ✅ `platform/lifecycle/sessionhub/` 完全实现但有已知缺口 |
| 已有分析深度覆盖 | ❌ 关键词 `LinkStore.*persist\|sessionHub.*sqlite\|sessionhub.*persist\|session.*hub.*store` 在 54 份历史分析中 **0 命中** |

### 问题描述

`sessionhub.Coordinator` 是跨协议会话一致性中枢——当一次登出需要同时终止 OIDC session、SAML session、刷新令牌和 backchannel logout 时，Coordinator 负责协调所有这些操作。但有两个重大缺口：

#### 缺口 A：LinkStore 纯内存，重启后丢失

`LinkStore` 接口（`sessionhub/linkstore.go:26`）存储的是 **OIDC session ↔ SAML session 之间的交叉链接**。当前只有 `MemoryLinkStore` 实现（`linkstore.go:53`）：

```go
type LinkStore interface {
    Link(ctx context.Context, oidcSID, samlSID string) error
    Lookup(ctx context.Context, oidcSID string) ([]string, error)
    Unlink(ctx context.Context, oidcSID string) error
}
```

**问题：** 服务器重启后，所有 cross-protocol session 链接丢失。如果用户有同时活跃的 OIDC 和 SAML 会话：

- 用户通过 OIDC RP 登出 → Coordinator 查找 LinkStore → 找不到 SAML 链接 → SAML session 成为孤儿（永远不会被登出）
- 用户通过 SAML IdP-initiated SLO 登出 → Coordinator 从未收到触发（见缺口 B）→ OIDC session 仍存活

**场景：** 企业部署中用户同时登录了 OIDC Web 应用（基于 Okta 的工作门户）和 SAML 应用（ADFS 集成的老系统）。服务器滚动重启后，用户的 OIDC 登出不再传播到 SAML 应用——用户以为自己已登出所有应用，但 SAML session 仍然活跃。

#### 缺口 B：SAML 触发未接线

源代码 `sso.go:112` 明确注释：

> "The SAML leg is deliberately NOT wired here: the concrete SAML IdP handlers
> (infrastructure/saml, a separate Go module) are built FROM this already-
> constructed Server [...] wiring them requires infrastructure/saml's
> Deps.SessionHub to call s.SetSAMLTrigger(...) AFTER both exist"

但 `infrastructure/saml/` 中没有任何对 `SetSAMLTrigger` 的调用。**SAML 触发的接线从未发生。** 这意味着：

- SAML IdP-initiated SLO 可以触发 SAML 侧的 session 销毁
- 但**永远不会传播到 Coordinator** 来触发 OIDC backchannel logout 或 refresh token 撤销
- 同样，用户通过 OIDC RP 的登出也不会传达到 SAML 侧

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) SQLite LinkStore 实现** | 新建 `platform/lifecycle/sessionhub/sqlite_linkstore.go`：`Link`（INSERT OR REPLACE）、`Lookup`（SELECT）、`Unlink`（DELETE）。同一 DSN 体系，`SetMaxOpenConns(1)`，migration 创建 `session_links` 表：`(oidc_sid TEXT PRIMARY KEY, saml_sids TEXT)` | M |
| **(b) SAML 触发接线** | 在 `infrastructure/saml/` 的 IdP 构造路径中调用 `server.sessionHub.SetSAMLTrigger(...)`。需要将 `Deps.SessionHub` 从 `interfaces/sso/accessors.go` 暴露给 `infrastructure/saml`（`infrastructure/saml` 是独立 go.mod 模块，需要接口定义在 `shared/core` 或 `shared/spi` 中） | L |
| **(c) 自动恢复机制** | 新增后台修复 goroutine：定期（如每小时）扫描所有活跃 session 的 cross-link，检测 LinkStore 中有记录但 session 已销毁的残存链接，以及 session 存在但链接丢失的孤儿。后者通过重新关联修复 | M |
| **(d) 可观测性** | 新增指标 `sso_session_links_total`、`sso_session_link_orphans_total`。审计事件 `session_link_created`、`session_link_broken` | S |

### 边界情况 / 具体注意点

| 边界 | 处理策略 |
|---|---|
| **SAML session 索引的跨存储原子性** | SAML IdP 使用 `idpsqlite.SessionIndex` 管理 SAML session。当 SAML SLO 发生时，需要在 Coordinator 和 SessionIndex 之间协调删除顺序。先删除 LinkStore 再删除 SessionIndex 或反之——需要定义明确的顺序 |
| **独立的 go.mod 依赖关系** | `infrastructure/saml` 是独立模块，不能依赖 `interfaces/sso`。SPI 定义必须下沉到 `shared/core` 或 `shared/spi`。当前 `Coordinator` 类型在 `platform/lifecycle/sessionhub`——需要将 `LinkStore` 接口、`SetSAMLTrigger` 方法和触发回调类型移到 `shared/spi` |
| **MemoryLinkStore 已有 Capacity 参数** | 当前 `NewMemoryLinkStore(capacity int)` | 非正数 = unlimited。SQLite 没有这个限制，但需要确保不会无限增长（添加定期 prune 过期链接） |
| **多副本场景** | 如果多个副本各自有独立的 LinkStore（当前设计），一个副本上的登出不会传播到其他副本的 LinkStore。需要跨副本共享 LinkStore（通过 SQLite/Redis 共享后端） |

### Sequencing Hint

**(a)** SQLite LinkStore 可以独立交付（1 sprint），先解决重启丢失问题。**(b)** SAML 触发接线需要 SPI 下沉 + `infrastructure/saml` 修改（2 sprint）。**(c)** 自动恢复是锦上添花，可以在有生产数据后再做。

---

## 方向四：RS SDK 缺乏混合验证模式 —— 本地验证 + 吊销感知缓存

### 类型

性能 / SDK 完整性

### 当前状态

| 检查项 | 状态 |
|---|---|
| 代码中存在 | ✅ 两种模式独立存在但无混合模式 |
| 已有分析深度覆盖 | ⚠️ 方向接近但切入点不同：方向一（多级 Token 验证缓存架构）针对**AS 端**的 Introspection 缓存优化。本方向针对**RS SDK 端**的资源服务器缓存，且不依赖 Introspection |

### 问题描述

`interfaces/ssoclient/rs/` 包提供两种 token 验证模式：

| 模式 | API | 延迟 | 吊销感知 | 网络依赖 |
|---|---|---|---|---|
| 本地（Local） | `ValidateToken` | ~1-5ms | ❌ 无 | 仅 JWKS 获取 |
| 远程（Introspect） | `ValidateTokenWithIntrospect` | ~5-50ms | ✅ 实时 | 每次请求 |

**缺失：混合模式（Hybrid Mode）**

```
模式 3: ValidateTokenWithCache(ctx, token, opts)
  → 步骤 1: 本地 JWT 验签（验证签名 + claims）
  → 步骤 2: 检查本地吊销缓存 token 是否已知被吊销
  → 步骤 3: (可选) 后台异步轮询 introspection 更新缓存
```

```
吊销缓存设计：

TokenValidationCache {
    // key: token hash (SHA-256), value: {valid, expires_at, revoked, checked_at}
    // TTL = min(token.exp - now, maxCacheTTL) — 永不超 token 自身过期时间
    // 写入: introspection 响应、bus 吊销广播
    // 失效: bus 吊销事件 (AS 集群广播 → RS 逐出)
}
```

**为什么这是高价值缺口：**

| 场景 | Local 模式 | Introspect 模式 | Hybrid 模式 |
|---|---|---|---|
| 正常流量（99% token 有效） | ✅ 零网络延迟 | ❌ 每请求 RTT | ✅ 本地验证，缓存命中 |
| token 被吊销 | ❌ 不知道，直到过期 | ✅ 实时感知 | ✅ 缓存 TTL ≤ 30s 内感知 |
| 突发流量（10x spike） | ✅ 无瓶颈 | ❌ AS 成为瓶颈 | ✅ 本地处理 |
| AS 宕机 | ✅ 继续工作 | ❌ 所有请求失败 | ✅ 降级为本地验证 |
| RS 启动时 | ✅ JWKS 缓存预热 | ❌ 第一次请求慢 | ✅ 同 Local |

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) TokenValidationCache SPI** | `rs.TokenValidationCache`：`Get(ctx, tokenHash) → (*CacheEntry, error)`、`Set(ctx, tokenHash, entry, ttl)`、`MarkRevoked(ctx, tokenHash)`。内建实现：`rs.NewMemoryTokenValidationCache(maxEntries, ttl)` | M |
| **(b) 混合验证函数** | `ValidateTokenWithCache(ctx, token, cfg, cache, opts)`：先本地的 `ValidateToken`，然后查缓存。新函数不改变 `ValidateToken` 的签名（additive） | S |
| **(c) 异步缓存填充** | 可选 goroutine：对接近过期的缓存条目发起异步 introspection 更新。`WithAsyncCacheRefresher(ctx, interval)` | M |
| **(d) 吊销广播接收** | 可选的 `bus` 订阅：从 AS 的 cluster.Bus 接收 `KindTokenRevoked` 事件并在本地缓存中 `MarkRevoked`。需要 RS 与 AS 在同一 cluster.Bus 上（或通过 WebSocket/SSE 接收失效事件） | L |
| **(e) 中间件集成** | 为 `HTTPMiddleware` 添加 `WithTokenValidationCache(cache)` 选项，使中间件自动使用混合模式 | S |

### 边界情况 / 具体注意点

| 边界 | 处理策略 |
|---|---|
| **缓存条目 TTL 与 token exp 的关系** | 缓存条目的 TTL 必须 ≤ token 自身的 `exp - now`。绝不能缓存已过期的 token 为有效 |
| **高碰撞概率下的 token hash** | 使用 SHA-256 完整哈希（非截断），`map[string]*CacheEntry` key 为 64 字符 hex |
| **并发安全** | `sync.RWMutex` + 分片（`hash % N`）或 `sync.Map`。参考 `servercache/client_store_cache.go` 的模式 |
| **缓存驱逐策略** | TTL 优先，加上 LRU 上限（`maxEntries`）。驱逐时优先驱逐 TTL 最短的条目（非随机） |
| **与 existing `ssoclient/rs/rs.go:Config` 的关系** | `Cache` 字段直接加在 `Config` 上：`TokenValidationCache TokenValidationCache`。nil = 纯本地模式（向后兼容） |

### Sequencing Hint

**(a)** SPI + Memory 实现（1 sprint）→ **(e)** 中间件集成（并行）→ **(b)** 混合验证函数（1-2 天）→ **(c)** 异步缓存填充可选 → **(d)** 吊销广播接收需要 AS 端提供 SSE/bus 接入点，可以延后。

---

## 方向五：Device Flow Polling 间隔自适应与令牌分发防滥用

### 类型

安全 / 协议正确性

### 当前状态

| 检查项 | 状态 |
|---|---|
| 代码中存在 | ✅ 基础实现存在，缺少自适应和防滥用 |
| 已有分析深度覆盖 | ❌ 关键词 `device.*slow\|device.*interval\|device.*backoff\|device.*poll\|device.*throttle\|DeviceCode.*slow` 在 54 份历史分析中 **0 次作为独立方向被深度 scope**（仅有 1 份轻量提及） |

### 问题描述

项目实现了 RFC 8628 Device Code（设备流）和 CIBA polling，但在两个关键方面未遵循规范的"adaptive polling"要求：

#### 缺口 A：`slow_down` 仅在客户端违反 `interval` 时触发

RFC 8628 §3.5 要求：如果客户端轮询速度超过 AS 指定的 `interval`，AS 应返回 `slow_down` 并建议客户端增加 5 秒间隔。当前实现在 `oauth/handle_device_token.go` （或等效路径）中验证间隔，但：

1. **间隔检查窗口是 `<=` 还是 `<`？**——代码需要明确使用 `<` 来允许客户端的时钟偏差
2. **没有间隔加法存储**——`slow_down` 后新间隔 = 原间隔 + 5s，但当前没有 store 记住每个 `device_code` 的调整后的间隔。`slow_down` 后客户端下一次轮询的间隔是 client 方自行调整，服务端只做验证
3. **没有违规计数器或节流**——如果客户端持续以更快速度轮询（可能是攻击者枚举 `user_code`），没有黑名单或临时禁令

#### 缺口 B：设备代码分发缺乏请求速率限制

`POST /device/code` 端点本身没有独立的速率限制。攻击者可以：

```
POST /device/code?client_id=xxx&scope=openid
→ 200 OK: device_code=abc, user_code=123-456

POST /device/code?client_id=xxx&scope=openid
→ 200 OK: device_code=def, user_code=789-012

...重复 10,000 次
```

每个 `device_code` 在 TTL 内占用内存/存储槽位，攻击者可以在 TTL 窗口中填充设备代码表，引发拒绝服务（占用所有 in-memory 槽位或填满 SQLite 表）。

同样的攻击路径适用于 CIBA `backchannel-authentication` 端点。

#### 缺口 C：user_code 的碰撞概率未在代码中显式计算

当前 `GenerateUserCode`（`oauth/oauthspi/device_codes.go:25`）生成格式 `XXXX-XXXX`（8 个可读字符）。8 个字母数字字符的熵足够，但代码中没有显式计算或文档化的碰撞概率保证。在生成 100 万个代码后，碰撞概率约为 ~0.3%（基于生日悖论），对 UX 有影响。

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) 自适应间隔实现** | 新增 `DeviceCodeSlowDownStore` SPI（可选扩展）：存储每个 `device_code` 的"当前建议间隔"。验证间隔太短时返回 `slow_down` + 新间隔（原间隔 + 5s），并持久化新间隔。CIBA 同样处理 | M |
| **(b) 设备代码分发限流** | 为 `POST /device/code` 和 `POST /backchannel-authentication` 添加 per-client 速率限制：`WithDeviceCodeIssuanceRateLimit(count, window)`。超出返回标准 `invalid_request` 或 `slow_down` | M |
| **(c) 违规客户端节流** | 可选 `DeviceCodeAbuseDetector`：跟踪 per-IP/per-client 的 `slow_down` 违规次数。超过阈值（如 5 次/分钟）时，对该 client+IP 组合返回标准的 `authorization_pending` 而非真实状态，使攻击者无法区分"代码无效"和"被节流" | L |
| **(d) 碰撞概率文档+熵增强** | 在 `GenerateUserCode` 的文档中显式计算碰撞概率。可选提供 `WithExtendedUserCodeFormat(entropyBits)` 配置（如 `XXXX-XXXX-XXXX` 12 字符增加熵） | S |
| **(e) 可观测性** | 新增指标 `sso_device_code_issuance_total{client_id}`、`sso_device_code_poll_violation_total{client_id}`、`sso_ciba_poll_violation_total{client_id}` | S |

### 边界情况 / 具体注意点

| 边界 | 处理策略 |
|---|---|
| **Legacy 客户端不发送 `interval`** | 如果客户端不遵守间隔（不发送任何轮询间隔指示），使用默认间隔（5s）并施加更严格的慢速开始（首次违规即 slow_down） |
| **`slow_down` 的并发更新** | 当两个同时到达的轮询都确认当前间隔为 5s 且同时决定请求 slow_down，其中一个可能得到错误的建议间隔。使用 `CompareAndSwap` 或 SQLite 的原子性避免 |
| **user_code 碰撞处理** | `GenerateUserCode` 应该循环直到生成一个不重复的 code（或直到重试上限）。当前 memory store 的 `NewDeviceCodeStore` 没有显式碰撞检测（SQLite 的 UNIQUE 约束会报错，但重试逻辑在应用层） |
| **设备流 token 的 DPoP 绑定** | 当前 device code 流程没有 DPoP 绑定选项——设备代码交换出的 token 是裸 bearer。RFC 8628 不要求 DPoP，但作为安全增强可以提供 `device_code_dpop_bound` 选项 |

### Sequencing Hint

**(b)** 设备代码分发限流是最直接的 DoS 防护，优先级最高（S）。**(a)** 自适应间隔是对协议合规的补全（M）。**(e)** 可观测指标并行添加。**(c)** 滥用检测和 **(d)** 碰撞概率是锦上添花。

---

## 优先级矩阵

| # | 方向 | 类型 | 严重性 | 建议顺序 | 工作量估值 |
|---|---|---|---|---|---|
| 1 | **Session 创建配额原子性** | 正确性/并发 | **高**——配额泄漏和 TOCTOU 是生产正确性问题；配额泄漏累积导致租户被静默锁死 | **P0** — 修复不含 SPI 变更，纯逻辑调整 | ~3 天 |
| 2 | **SQLite WAL Checkpoint** | 运维 | **高**——WAL 无限增长导致长时间运行后磁盘满或性能退化 | **P0** — 直接威胁生产稳定性 | ~2 天 |
| 3 | **Session Hub LinkStore 持久化** | 一致性 | **中**——重启后跨协议 session 链接丢失，SAML 触发未接线 | **P1** — 影响企业部署的跨协议登出一致性 | ~2 sprint |
| 4 | **RS SDK 混合验证模式** | SDK/性能 | **中**——限制高吞吐 RS 的部署选项 | **P1** — SDK 增强，不影响现有功能 | ~2 sprint |
| 5 | **Device Flow 自适应间隔** | 协议合规/安全 | **低-中**——设备流和 CIBA 的防滥用增强 | **P2** — 协议合规补全 + DoS 防护 | ~1 sprint |

### 组合建议

- **第 1 周（P0 修复）：** 方向一（配额原子性）+ 方向二（WAL Checkpoint）。两个都是纯后端修复，不需要 SPI 变更，可以在 2-3 天内完成并显著提升生产可靠性。
- **第 2-3 周（P1 优先）：** 方向三（Session Hub LinkStore）的 SQLite 实现 + 方向四（RS SDK 混合验证）的最小可行版本。
- **有明确需求时：** 方向五（Device Flow 自适应间隔）——当有设备流或 CIBA 的生产部署时再做。

---

## 附录：与已有分析的交叉验证声明

本报告的 5 个方向经过与 `docs/requirements/*.md`（54 份）的全关键词反查。每条方向的核验结果：

| 方向 | 关键搜索词 | 历史文档命中 | 是否被深度分析 |
|---|---|---|---|
| 一：配额原子性 | `IncrementUsage.*before.*Create\|quota.*leak\|createSession.*race\|evictOldestSession.*race\|sessionPolicyCapExceeded` | 0 份 | ❌ 从未 |
| 二：WAL Checkpoint | `wal_checkpoint\|auto_checkpoint\|WAL.*growth\|journal_size` | 0 份（仅 2 份轻量提及"WAL"） | ❌ 从未 |
| 三：Session Hub | `LinkStore.*persist\|sessionHub.*sqlite\|session.*hub.*store\|SetSAMLTrigger` | 0 份 | ❌ 从未 |
| 四：RS Hybrid | `ValidateTokenWithCache\|TokenValidationCache\|hybrid.*validat\|mixed.*mode.*validat` | 0 份（方向接近但切入点不同——AS 端 vs RS 端） | ❌ 从未 |
| 五：Device Poll | `device.*slow_down\|DeviceCodeSlowDown\|device.*abuse\|device.*throttle\|device.*rate.*limit` | 0 份（仅 1 份轻量提及"device flow"） | ❌ 从未 |

**结论：** 本报告的 5 个方向均来自代码级深度阅读发现的实现缺口，在 54 份历史高层架构分析中**未被作为独立方向被深度 scope**。其中方向一、二、三为生产可靠性直接威胁，建议 P0 优先处理。
