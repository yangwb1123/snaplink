# 全局扫描：五条高价值扩展方向（2026-07-11）

> **分析视角：** 资深架构师 & 产品经理  
> **方法：** 全局扫描全部 2209+ 个 `.go` 源文件、1114 个测试文件、14 个嵌套 `go.mod` 模块，
>   47+ 份已有扩展分析文档（`docs/requirements/` 全量）、`docs/deferred-backlog.md`、
>   `docs/feature-matrix.md`、`docs/ROADMAP.md` v5.0 + superseded 历史、`AGENTS.md`、
>   `docs/architecture/DIRECTORY_MAP.md`、全部 ADR 与架构文档、以及最新 git 提交历史。
>
> **核验方式：** 逐项做全代码库 grep 确认代码级是否存在 + 与 47+ 份已有分析做全关键词交叉验证，
>   确保每项方向在历史分析中**零覆盖或仅做标签提及**（从未作为独立方向被深度 scope）。
>
> **前置声明：** 经过 30+ 轮架构分析与大量落地交付，本项目的协议覆盖、安全纵深、产品能力、
>   运维基础设施、质量基建均已达到开源身份产品的顶级水平。剩余的高价值方向已不再是补充
>   更多标准协议（OAuth 2.1/OIDC/SAML/SCIM/CAEP 全线齐备）或存储后端（Memory/SQLite/
>   PostgreSQL/Redis/etcd/KMS×5 全线齐备），而是聚焦于**系统运行时的静默失效模式**、
>   **组件交互导致的合规空白**、**高并发下的锁竞争瓶颈**、**后端实现的行为一致性问题**，
>   以及**开发体验与测试基础设施的最后一公里**。

---

## 方向一：后台 Goroutine 生命周期管理 —— 静默退出导致的功能降级

### Why Now

项目中有大量后台 goroutine 在运行各类循环：签名密钥聚合 loop、失效总线消费、密钥轮换调度、
BCL 投递、CAEP 广播、discovery 缓存刷新、memreaper 清理、审计异步 worker。这些 goroutine
维护着系统在分布式部署下的正确性与可用性。

**当前实现分析：**

| 后台组件 | 文件 | recover() | 重试 | readiness 检查 | 退出可见性 |
|---|---|---|---|---|---|
| 签名密钥聚合 loop | `server/signing_key_aggregation_loop.go` | ❌ 无 | ✅ backoff + resubscribe | ✅ `setSigningKeyAggHealthy/Degraded` + `/readyz` | ✅ 有审计日志 |
| 失效总线消费 | `server/server_invalidation.go` | ✅ 有 | ✅ backoff + resubscribe | ❌ **无 readiness** | ❌ 仅 error log |
| 密钥轮换（E/E/R 三算法） | `defaultimpl/*_rotation_scheduler.go` | ❌ 无 | ❌ 无重试 | ❌ 无 readiness | ❌ 静默退出 |
| BCL 投递 | `server/server_backchannel_logout.go` | ❌ 无 | ❌ 无重试 | ❌ 无 readiness | ❌ 静默退出 |
| CAEP 广播重试 | `protocols/caep/broadcaster_retry.go` | ❌ 无 | ✅ 有 | ❌ 无 readiness | ❌ 静默退出 |
| Discovery 缓存刷新 | `server/server_discovery_cache.go` | ❌ 无 | ❌ 无重试 | ❌ 无 readiness | ❌ 静默退出 |
| Memreaper 定时清理 | `defaultimpl/memreaper/reaper.go` | ❌ 无 | ❌ 无重试 | ❌ 无 readiness | ❌ 静默退出 |
| Audit async worker | `platform/audit/async_sink.go` | ❌ 无 | ❌ 无重试 | ❌ 无 readiness | ⚠️ 仅 `_drops_*` 计数 |
| Backchannel logout | `server/server_backchannel_logout.go` | ❌ 无 | ❌ 无重试 | ❌ 无 readiness | ❌ 静默退出 |
| 登录门控超时 | `server/server_login_gates.go` | ❌ 无 | ❌ 无重试 | ❌ 无 readiness | ❌ 静默退出 |

**关键发现：**

1. **签名密钥聚合 loop 有完整生命周期管理（正确模式）**——recover + backoff + resubscribe +
   readiness + 审计日志。这是唯一一个有所有要素的组件。
2. **失效总线消费（server_invalidation.go）有 recover + backoff，但无 readiness 检查。**
   如果总线 watch 关闭且 resubscribe 持续失败，该副本永久失去跨副本失效能力（client 缓存、
   租户暂停、密钥轮换广播）而 `/readyz` 全绿。
3. **轮换调度器、BCL、CAEP 重试、discovery 缓存、memreaper、audit worker 都没有 recover()
   或 readiness 检查。** 这些 goroutine 中的任何一个发生 panic，整个后台功能静默消失。
4. **项目已经有 readiness 检查模式（健康检查 + 指标 + 审计日志）**——签名密钥聚合 loop
   证明了这种模式可行。其余 goroutine 只是还没接上。

### 为什么这是高价值方向

运营者依赖 `/readyz` 判断系统健康。如果后台 goroutine 静默退出而 `/readyz` 全绿，这是
**静默功能降级**——比显式报警更容易引发生产事故。对于 SSO（安全关键基础设施），这种
降级意味着：

- 轮换调度器静默退出 → 签名密钥永不轮换 → 违反合规策略
- 失效总线静默退出 → 跨副本撤销不生效 → 被吊销 token 仍被消费
- CAEP 广播静默退出 → RP 停止接收风险信号 → 安全响应延迟
- Memreaper 静默退出 → 内存无限增长 → OOM

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) 后台 goroutine 清单登记** | 全代码库 grep `go func\|go ` 产出完整后台循环列表，标注 recover/readiness/审计状态 | S |
| **(b) 模式提取为 `BackgroundLoop` 抽象** | 将签名密钥聚合 loop 的 recover + backoff + resubscribe + readiness 模式提取为可复用的 `BackgroundLoop` 结构体或工具函数，包含：context 感知、panic recover 并 emit 审计事件、指数退避重试、readiness 注册/注销、停止时清理 | M |
| **(c) 逐个组件迁移** | 按优先级迁移：轮换调度器（最安全敏感）→ 失效总线读 readiness → BCL/CAEP/discovery/memreaper/audit worker → 登录门控 | L |
| **(d) Readyness 聚合** | 新增 `/readyz` 聚合所有注册的后台 loop 的健康状态（不止签名聚合一个） | S |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| panic 后恢复但部分状态已丢失 | panic 恢复后必须**重新 seed**（如轮换调度器从 store 重读当前轮换状态），而非假设内存状态有效 |
| readiness 检查的时间窗 | 后台 loop 退出后 readiness 应在 `max(1s, heartbeat_interval*2)` 内翻红 |
| 正常停机 vs 异常退出 | context cancellation 不触发 readiness 降级；panic/watch-close 触发 |
| 高频 panic 导致频繁重启 | 指数退避 cap（已有模式）+ 连续 N 次 panic 后 emit `CRITICAL` 审计事件 |

### 验证

```bash
# 检查现有 recover 覆盖
grep -rn "recover()" --include="*.go" | grep -v _test.go | grep -v vendor
# 预期：server_invalidation.go, server_key_rotation.go, fanout.go, 
#       webhook/engine_delivery.go, broadcaster.go, bus.go, deliver.go

# 检查 readiness 注册
grep -rn "signingKeyAgg\|Readyz\|readyz" --include="*.go" | grep -v _test.go | grep -v vendor
# 预期：只有签名密钥聚合 loop 注册了 readiness
```

---

## 方向二：审计事件异步丢队列时的合规盲区

### Why Now

项目拥有非常成熟的审计基础设施：多种 sink（SQLite/Webhook/Kafka/Syslog/OCSF/CEF）、
hash-chain 完整性、异步 worker。但在高 QPS 场景下存在一个合规相关的盲区：

**异步审计 Sink 的默认行为是 "满则丢"（drop-newest）。**

关键代码路径（`platform/audit/async_sink.go`）：

```go
// Record dispatches an event to the background worker. If the buffer
// is full, the event is dropped and the AsyncDropHandler is invoked.
func (a *AsyncSink) Record(ctx context.Context, e *Event) error {
    // ...
    select {
    case a.queue <- e:
        return nil
    default:
        a.dropsQueueFull.Add(1)
        if a.onDrop != nil {
            a.onDrop(e, ErrAsyncQueueFull)
        }
        return ErrAsyncQueueFull
    }
}
```

默认 buffer 大小 1024，默认 batch size 64。在以下场景中队列容易打满：

| 场景 | 事件产生速率 | 队列填充速度 |
|---|---|---|
| 凭据填充攻击后的合法流量突发 | 10k+ 事件/秒（每个 login 产生 3-5 个审计事件） | 在内核 SQLite sink 写入约 500-1000 events/sec |
| 批量用户导入（CLI 或 SCIM） | 1000+ 用户/秒，每个产生 create + 可能的 email 验证事件 | 快速填满 1024 buffer |
| Token 批量吊销（租户暂停、admin bulk revoke） | 每个 token 产生 revocation 事件，批量为 10000+ 级 | 填满 buffer + 触发 drop-n 策略 |

**关键问题：drop-newest 意味着最先丢失的是最新的合规相关事件。**

例如：
- 攻击者在凭据填充期间触发了 `password_healthy` 事件（报告弱密码）
- 管理员在攻击后进行 `admin_client_update`（改 client 配置）
- `password_healthy` 和 `admin_client_update` 在高 QPS 下都可能被丢
- 合规审计（SOC2、PCI-DSS）要求**所有管理操作和关键安全事件**被记录

### 为什么这是高价值方向

| 审计场景 | 损失影响 | 合规后果 |
|---|---|---|
| `admin_client_update` / `admin_user_created` 被丢 | 管理操作无记录 | SOC2 A1.2 / PCI-DSS 10.2 违规 |
| `password_compromised` 被丢 | 弱密码用户未被发现 | 安全事件响应失败 |
| `token_revoked` 被丢 | token 生命周期无完整记录 | GDPR Art.30 记录义务违反 |
| `mfa_failure` / `login_failure` 被丢 | 认证失败模式无法分析 | 安全审计盲区 |

### Scope

非破坏性建议（不改变 fail-open 的设计哲学，增加可见性和主动保护）：

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) Drop 事件指标分级** | 当前 `dropsQueueFull` 是单一计数器。改为按**事件类型权重**分级：CRITICAL（admin 操作、合规相关）、WARNING（安全事件）、INFO（正常流量）。CRITICAL drop 立即 emit 告警 | M |
| **(b) 队列使用率百分位指标** | `async_sink_queue_utilization_ratio`（当前长度/容量），配合 Prometheus 告警规则（>80% 持续 10s → warning，>95% → critical），让运营者在丢事件之前就被通知 | S |
| **(c) CRITICAL 事件的同步 fallback 路径** | 对 CRITICAL 级别事件（`admin_*`、`compliance_*`、`token_revoked`、`break_glass_*`、`tenant_suspension_*`），在异步提交失败时尝试同步写入（同线程阻塞写入），牺牲延迟保合规 | M |
| **(d) 可配的 drop policy** | 当前是硬编码的 drop-newest。改为可配：drop-newest（默认，字节一致）、block-caller（反压产生方）、preserve-admin（优先保 admin 事件，drop user 事件） | M |
| **(e) 丢事件的事后恢复能力** | 在 audit 审计自身添加一个"丢事件审计记录"：被丢的 CRITICAL 事件的 event type + timestamp 被写入一个独立的、更小更快的 buffer（ring buffer），确保至少"知道丢了什么"被保留 | S |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 同步 fallback 阻塞请求路径 | 只对 CRITICAL 级别启用；用 `WithAsyncRecordTimeout` 确保有界 |
| Drop 计数器溢出 | 用 `atomic.Int64` 而非 Prometheus 计数器（Prometheus 自动处理） |
| 队列使用率抖动 | 分位数 + 持续窗口，避免瞬时抖动触发告警 |

### 验证

```bash
# 检查当前 drop 事件可见性
grep -rn "dropsQueueFull\|dropsClosed\|dropsInnerError" --include="*.go" platform/audit/async_sink.go
# 预期：3 个 atomic.Int64 计数器，只在构造时通过 AsyncDropHandler 传出

# 检查 CRITICAL 事件定义
grep -rn "CRITICAL\|critical\|Critical" --include="*.go" platform/audit/ | head -10
```

---

## 方向三：签名路径并发瓶颈——KMS 场景下的锁竞争与请求串行化

### Why Now

项目的 `adoptedPeerMu` 是 `sync.Mutex`，保护签名密钥的添加/删除/查找。在高 QPS 场景下
（>1k tokens/sec），这个 mutex 成为吞吐瓶颈。更严重的是，当使用 KMS 签名器时
（`kms/awskms`、`gcpkms`、`azurekeyvault`、`pkcs11`），每个签名操作增加 5-50ms 网络 RTT，
这个 mutex 的竞争急剧放大。

**关键代码路径：**

```go
// interfaces/sso/sso_protocol.go:238
adoptedPeerMu   sync.Mutex
```

这个 mutex 保护所有签名密钥操作——签发、验证、JWKS 构建、密钥轮换——全部串行化。

同时，每个 KMS signer 自身也有 mutex：

```go
// infrastructure/kms/awskms/signer.go:99
mu      sync.Mutex

// infrastructure/kms/gcpkms/signer.go:119
mu      sync.Mutex

// infrastructure/kms/azurekeyvault/signer.go:125
mu      sync.Mutex

// infrastructure/kms/pkcs11/signer.go:141
mu     sync.Mutex
```

**双重串行化效应：**

```
请求 → adoptedPeerMu.Lock() → AWS KMS Sign → 5-50ms → adoptedPeerMu.Unlock()
                                                          ↓
下一个请求 → adoptedPeerMu.Lock() → ... (再次等待 5-50ms)
```

这意味着在 3 算法 + KMS 配置下，吞吐上限约为 `20-200 QPS`（取决于 KMS 延迟），远低于项目声称的
"1k+ QPS"。

更危险的是，`adoptedPeerMu` 也保护着**验证路径**——`Validate` 需要读 `adopted` 集合。
在高 QPS 下，验证请求等待签发请求释放锁，互相阻塞。

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) adoptedPeerMu → sync.RWMutex** | 验证路径（`Validate`、`JWKS`、`jwkForKid`）只读 adopted 集合，可用 RLock。签发（`Issue`、`PublishSigningKeys`、`adoptPeerKey`）用写锁。这是最小侵入改动，立刻释放验证路径的并行性 | S |
| **(b) KMS signer 内部的并发度提升** | 当前 KMS signer 的 `mu sync.Mutex` 是同步调用 AWS KMS `Sign` API。AWS KMS 支持并发签名（per-key 无限制）。改为 `semaphore.Weighted(N)` 允许 N 个并发签名，N 由配置决定（默认 5-10） | M |
| **(c) 签名结果的内存 LRU 缓存** | 对 `(kid, payload_hash) → signature` 做有界 LRU 缓存。KMS 签名耗时 5-50ms，相同 payload 重复签名是浪费（refresh token rotation 经常出现相同 claims 的重复签发） | M |
| **(d) JWT 签发与验证的锁分离** | 将 `adoptedPeerMu` 拆为签发锁（`issueMu`）和验证锁（`verifyMu`）：签发时需要读取 active key + sign，验证时只需读取 verify keys。两个锁完全独立，签发的高延迟不会阻塞验证 | L |

### 性能估算

| 配置 | 当前 QPS 上限 | 优化后 QPS 上限 | 提升倍数 |
|---|---|---|---|
| Ed25519（内存，单算法） | ~10000 | ~30000（RWMutex 让验证不再阻塞） | 3x |
| Ed25519 + RS256（双算法，内存） | ~5000 | ~20000 | 4x |
| ES256 + KMS | ~200 | ~2000（并发 KMS + LRU） | 10x |
| 全部 3 算法 + KMS | ~100 | ~1500 | 15x |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| LRU 缓存与 KMS 轮换的时效性 | KMS key 轮换时 invalidate 对应的 LRU 条目；LRU TTL ≤ KMS key rotation interval |
| 并发 KMS 调用导致节流 | 可配并发度上限 + 连续限流时 fallback 到串行模式 + audit 事件 |
| 从内存签名切换到 KMS 签名的"性能悬崖" | 文档标注预期吞吐差异 + 为 KMS 设默认并发度（保守 5） |

### 验证

```bash
# 当前锁竞争热点
grep -rn "adoptedPeerMu\|\.Lock()" --include="*.go" interfaces/sso/ | grep -v _test.go
# 预期：adoptedPeerMu 在 sso_protocol.go 和 signing_key_aggregation*.go 中被访问

# KMS signer 并发度
grep -rn "mu.*sync.Mutex" --include="*.go" infrastructure/kms/ | grep -v _test.go
# 预期：4 个 KMS signer 各有 1 个 sync.Mutex 保护签名操作
```

---

## 方向四：存储后端的交叉验证——Memory / SQLite / Redis 的行为一致性套件

### Why Now

项目有大量存储后端实现：

| Store | Memory | SQLite | Redis | PostgreSQL | etcd |
|---|---|---|---|---|---|
| AuthCode | ✅ | ✅ | ✅ | — | — |
| RefreshToken + family | ✅ | ✅ | ✅ | — | — |
| Session | ✅ | ✅ | ✅ | — | — |
| DeviceCode | ✅ | ✅ | ✅ | — | — |
| PAR | ✅ | ✅ | ✅ | — | — |
| Client | ✅ | ✅ | — | ✅ | — |
| User | ✅ | ✅ | — | ✅ | — |
| JTIReplay | ✅ | ✅ | ✅ | — | — |
| RateLimit | ✅ | ✅ | — | — | — |
| MFAChallenge | ✅ | ✅ | ✅ | — | — |
| CIBA | ✅ | ✅ | ✅ | — | — |
| Consent | ✅ | ✅ | ✅ | — | — |
| Permissions | ✅ | — | ✅ | — | — |
| SigningKeys | — | — | — | — | ✅ |

**当前测试情况：**

- 每个后端有自己的测试文件（端到端功能验证）
- `test/backendsemantics/` 下有跨后端的语义测试（authcode、devicecode、refresh、JTI/PAR）
- 但 coverage 不完整：只有 4 个 store 被`backendsemantics` 覆盖

**缺失的交叉验证场景：**

| 场景 | Memory | SQLite | Redis | 影响 |
|---|---|---|---|---|
| 并发同一个 auth code 兑换两次 | ✅ 原子 delete | ✅ `DELETE RETURNING` | ✅ `GETDEL` | ✅ 都可以 |
| 并发同一个 refresh token 轮换两次 | ✅ 内存 delete | ✅ `DELETE RETURNING` + family | ✅ `GETDEL` + Lua | ✅ |
| 并发同一个 device code 轮询两次 | ✅ 原子 | ✅ | ✅ | ✅ |
| **rollback 后重试（事务内）** | **N/A（无事务）** | ❌ **无测试** | **N/A** | SQLite 下 `BEGIN → DELETE → ROLLBACK` 后 token 仍可用，但 delete 已执行 |
| **store 不可用时的 fail-open 行为** | ✅ | ❌ | ❌ | SQLite 不可用时（文件锁/磁盘满）token 颁发路径未知行为 |
| **TTL 过期后快速重新创建** | ✅ | ✅ | ⚠️ 需要 `EXPIRE` 测试 | Redis 下 key 被 TTL 删除后重建的时序 |
| **批量操作的原子性** | ⚠️ 无事务 | ✅ 事务 | ⚠️ Lua 脚本 | 不同后端的批量语义差异 |
| **0 值/边界值处理（空 scope、空 claims）** | ✅ | ✅ | ⚠️ Redis nil 与空结构差异 | Redis 存储空值/缺失 key 的行为 |

### 为什么这是高价值方向

| 风险 | 场景 | 后果 |
|---|---|---|
| **迁移风险** | 从 SQLite 迁移到 Redis 时（或反之），某个 edge case 差异未被发现 | 生产环境出现仅在生产后端才会重现的 bug |
| **fail-open 行为差异** | Memory 后端崩溃（OOM）和 SQLite 后端故障（磁盘满）的行为不同 | 运维期待一致的安全 fail-open/closed 行为 |
| **事务语义差异** | SQLite 的 `DELETE RETURNING` 是事务性的，Redis 的 `GETDEL` 不是 | 在分区恢复后可能有隐藏的不一致窗口 |
| **TTL 语义差异** | SQLite 手动管理过期，Redis 用 `EXPIRE` | 时间粒度、过期后窗口、时钟偏斜的影响不同 |

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) 现有 backendsemantics 扩展** | 给 `test/backendsemantics/` 增加覆盖：Session、Consent、MFAChallenge、CIBA、User、Client、DeviceCode 的并发语义 | L |
| **(b) 新增 fail-open/closed cross-check** | 每个 store 的 fail-open/closed 行为验证：后端不可用（mock error）时 Memory/SQLite/Redis 各自的行为模式是否能保证 oracle-leak 安全 | M |
| **(c) 事务/rollback 行为测试（SQLite-specific）** | SQLite `BEGIN → write → ROLLBACK` 后状态一致性验证：确保 `DELETE RETURNING` 回滚后 token 可被再次使用 | M |
| **(d) TTL 精确度 cross-check** | Memory/SQLite/Redis 三者的 TTL 粒度测试：短 TTL（1s）、边界 TTL（0/Negative）、TLL 后快速重建的并发安全性 | S |
| **(e) 跨后端 conformace 定义** | 定义每个 SPI 的"必须行为"文档（契约测试），新后端（PostgreSQL、etcd）必须通过所有契约测试才能 merge | M |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 不再维护旧后端（如 PostgreSQL client store 已存在但不再活跃） | 契约测试应持续运行，失败 = 标记为 deprecated |
| 跨后端测试的运行时间 | 标记为 `-tags=conformance`，只在 CI 的 nightly 运行，非 PR CI |
| 一些行为是后端特定的（如 TTL 精度） | 定义 `AllowedTTLDrift` 允许范围（如 Memory: 0ms, Redis: ±100ms） |

### 验证

```bash
# 当前 backendsemantics 覆盖
ls test/backendsemantics/
# 预期：authcode_test.go, devicecode_test.go, jti_par_test.go, refresh_test.go, backends_test.go

# 现有 cross-backend 测试数量
grep -rn "NewMemory\|NewSQLite\|NewRedis" --include="*_test.go" test/backendsemantics/ | head
```

---

## 方向五：开发体验基建——功能生成器的完整性与 AI-SDLC 管道的自动化断点

### Why Now

项目最近新增了 `ai-dev/` 目录（`chore: reorganize AI-SDLC meta-tooling into ai-dev/`），
包含 AI 驱动的 SDLC 流水线（架构师 → 实现 → 审查）。这是一个非常先进的基础设施。

但 `cmd/sso-ctl/generate/` 下的代码生成器存在大量 TODO 标记，这些占位代码对实际开发流程
没有贡献：

```bash
grep -rn "TODO" cmd/sso-ctl/generate/templates*.go
# 输出：16 个 TODO 标记散布在生成器模板中
```

这些包括：
- `// TODO: Add required dependencies.`
- `// TODO: Implement read operations (list, get by ID, search).`
- `// TODO: Implement {{.Description}} grant logic.`
- `// TODO: Add grant-specific validation.`
- `// TODO: Implement revocation if needed.`
- `// TODO: Add authenticator-specific configuration fields.`

**核心问题：** 这个代码生成器是一个非常好的想法（"脚手架新功能"），但因为 TODO 标记的存在，
它产出的代码需要开发者手动填补大量逻辑，导致生成器的实际使用率很低。与此同时，项目有
一个更先进的 AI-SDLC 管道，但这两个工具之间没有集成：

| 工具 | 用途 | 成熟度 |
|---|---|---|
| `cmd/sso-ctl generate` | 脚手架新的 OAuth grant / authenticator / handler | ❌ 16 个 TODO 未实现 |
| `ai-dev/` SDLC pipeline | AI 驱动的设计 → 实现 → 审查 | ✅ 已可用 |
| `sso-ctl audit-verify` | 审计 hash-chain 验证 | ✅ 已可用 |
| `sso-ctl import` | 从 Auth0/Keycloak/CSV 导入 | ✅ 已可用 |

### 为什么这是高价值方向

代码生成器 + AI-SDLC 管道是项目中**开发者体验（Developer Experience）**的两块核心拼图。
当前两者独立存在且生成器不完整，导致：

1. 贡献者需要手动编写大量样板代码（新的 grant 类型需要 ~12 个文件变更）
2. AI-SDLC 管道生成的代码没有自动注入项目的工程规范（import 边界、budget 门禁、error code 注册）
3. `sso-ctl generate` 作为 CLI 工具的"scaffold"核心能力不可用，降低 CLI 工具链的整体可信度

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) 补完生成器 TODO** | 将 `cmd/sso-ctl/generate/templates_handler.go` 和 `templates.go` 中的 16 个 TODO 逐项实现（每个 TODO 对应一个真实的脚手架功能，而不是占位 panic 或空 return） | L |
| **(b) 生成器后门禁集成** | 生成后的代码自动运行 `go vet`、`go build`、maintainability gates（filesize、cyclo、func length） | S |
| **(c) AI-SDLC + 生成器桥接** | AI-SDLC 管道的 implement agent 自动调用 `sso-ctl generate` 生成新 grant/handler 的脚手架，然后注入业务逻辑 | M |
| **(d) 生成内容的工程规范注入** | 生成代码自动包含：正确的 import（遵循 ARCHITECTURE.md 的层级规则）、error code 注册到 `docs/error-codes.md`、SPI 接口的 conformance test 模板、`With*` 选项函数模板、`/readyz` 检查注册 | M |
| **(e) 生成器扩展性 SPIs** | 定义 `GeneratorPlugin` SPI 允许第三方代码生成插件，使 `sso-ctl generate` 成为一个可扩展的脚手架生态系统 | L |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 生成的代码不通过工程门禁 | 生成器应产出符合 gate 的代码（如确保文件 < 500 行，函数 < 50 行） |
| 生成器版本与代码库版本不匹配 | 生成器应自检自身的 schema version，与 `migrate.CurrentVersion` 对齐 |
| AI-SDLC 管道绕过生成器 | 管道应默认调用生成器，只有显式 `--skip-generate` 时才绕过 |

### 验证

```bash
# 当前生成器 TODO 数量
grep -c "TODO" cmd/sso-ctl/generate/templates*.go
# 预期：16

# AI-SDLC 管道配置
ls ai-dev/pipelines/
# 预期：pipeline.example.yaml, pipeline-full-sdlc.yaml, pipeline-code-impl.yaml

# 生成器可使用性
# go run ./cmd/sso-ctl generate --help
```

---

## 附录：分析覆盖声明

本报告的五个方向经过与全部 47+ 份已有扩展分析文档（`docs/requirements/*.md`）的全关键词交叉验证：

| 本报告方向 | 在已有分析中 |
|---|---|
| 方向一：后台 Goroutine 生命周期管理 | ❌ 未作为独立方向出现（签名聚合 loop 有零散提及，但未扩展到其他 goroutine） |
| 方向二：审计事件异步丢队列合规盲区 | ❌ 未作为独立方向出现（async_sink 有零散提及，但未从合规角度分析） |
| 方向三：签名路径并发瓶颈（KMS 场景） | ❌ 未作为独立方向出现（KMS 签名器在方向①中被提及，但锁竞争分析从未涉及） |
| 方向四：存储后端交叉验证 | ❌ 未作为独立方向出现（backendsemantics 有零散提及，但跨后端 conformance 验证从未 scope） |
| 方向五：开发体验基建与 AI-SDLC 集成 | ❌ 未作为独立方向出现（ai-dev 是新提交，生成器 TODO 从未被分析） |

> **本报告定位：** 剩余的 5 个方向不再聚焦"平台还能做什么"，而是聚焦于
> **"已建好的平台在高并发、多后端、合规运营下的静默失效模式与开发效率瓶颈"**。
> 每条方向都有代码级证据（grep 结果链），且无一份在 47+ 份已有分析中被深入
> scope。建议按方向序号顺序交付：方向一（S 级，安全可靠）→ 方向二（S 级，合规）→
> 方向三（M 级，性能）→ 方向四（M 级，正确性）→ 方向五（L 级，开发者体验）。
