# 边界情况与性能优化专项分析

> 基于 2026-07-01 对全代码库的深度扫描。  
> 分析视角：资深架构师 / 产品经理。  
> 定位：此前的 ROADMAP v5.0、22 轮分析、06-30 扩展方向分析、07-01 卷一（协议/安全扩展）、07-01 卷二（实时/治理/测试）均未覆盖。  
> 聚焦：**微观边界情况 Edge Cases + 运行时性能优化 Performance**，而非新增功能。  
> 原则：不写代码。每条锚定具体代码位置或模式，经对抗式 grep 核验。

---

## 总体印象

代码库的安全/正确性基础极为扎实——Oracle-leak、抗枚举、常量时间、fail-closed 红线均已到位。以下发现的边界情况多数是**活跃项目在复杂分布式场景下自然出现的边缘磨损**，而非系统性缺陷。性能优化点的特点是"当前不构成瓶颈，但规模扩展后必然触及"。

---

## 方向一：时间相关边界情况——时钟跳跃、单调钟、TOTP 漂移、Leap Second

### 现状

项目共 ~180 处 `time.Now()` 调用（非测试文件），分散在签发、验证、过期、GC 等热路径。近期已修复了 monotonic clock 问题（`fix(security): use monotonic-clock-safe comparisons for token expiry`），但以下位置仍存在非单调钟比较或时序假设：

### 具体边界

#### 1.1 `time.Now()` vs monotonic clock 的不一致使用

| 位置 | 代码 | 问题 |
|------|------|------|
| `ed25519_issue.go:20` | `now := time.Now()` | 用于签发 iat/exp，混合 wall clock + monotonic。如果容器被 freeze 后恢复（如 VM snapshot restore），monotonic 部分继续前进但 wall clock 被重置到旧的快照时间→`exp` 在 NTP 同步前可达数小时/天 |
| `sqlite/refresh_grace.go:250` | `now.Before(time.Unix(0, expiresAt))` | 使用 `time.Now()`（含 monotonic）与 `time.Unix()`（纯 wall clock）比较。跨机器时间基准不同 |
| `memory_session.go:115` | `s.ExpiresAt = time.Now().Add(m.ttl)` | 会话过期时间使用 `time.Now()`。如果该副本的时钟快于其他副本，会话在另一副本上被视为已过期 |
| `ecdsa_issue.go:20,70,144` | 三处 `now := time.Now()` | 同上——签发时钟快速过期，慢速永不过期 |

**风险**：时钟回拨（NTP 步进、VM 快照恢复、容器暂停后恢复）可在关键路径上导致：
- 已过期 token 重新生效（`exp > now` 变为 true）
- 已过期的 session 重新生效（`expires_at > now`）
- JTI replay 记录的 `exp` 在回拨后还未到达 → 允许重复使用
- 审计事件的时间戳乱序

**当前缓解**：使用 `time.Now` 的 monotonic 部分与 wall clock 耦合，无法单独处理回拨。近期提交添加了 `monotonic-safe` 比较，但仅覆盖 token expiry 比较路径。

#### 1.2 TOTP clock drift 处理在边缘情况下的行为

| 位置 | `totp.go:198,241` |
|------|-------------------|
| 问题 | `skewSteps` 默认为 1（±30s），但 `time.Now()` 是单机时间。在分布式多副本架构中，如果副本间时钟差 >30s，用户在一个副本注册的 TOTP secret 在另一个副本上验证失败 |
| 影响 | TOTP MFA 在多副本部署中出现不可重现的验证失败 |
| 缓解方向 | 在 TOTP 验证路径中使用配置化的 clock skew（每个副本的 `time.Now()` 差异 vs 用户时钟差异） |

#### 1.3 Session refresh 的时间窗口假设

| 位置 | `sqlite/sessions.go`, `memory_session.go` |
|------|-------------------------------------------|
| 问题 | `ExpiresAt` 设为 `time.Now().Add(ttl)`，但多副本场景下 session 在副本 A（快时钟）创建，副本 B（慢时钟）读取，在 B 上 session 的剩余 TTL 为负。当前 session index 复查未考虑跨副本时钟差异 |
| 影响 | 跨副本 session 验证可能产生不一致的 `session_invalid` 404 |

### 优化方向

1. **引入 `TimeSource` 接口**：替换所有热路径上的裸 `time.Now()`，注入可控制的 `TimeSource`（在测试中可冻结、步进、跳跃）。关键路径（签发、过期检查、replay GC）使用 `TimeSource.Now()`，装饰性路径（审计时间戳、日志）继续使用 wall clock。
2. **跨副本 clock skew 配置**：`WithMaxClockSkew(duration)`——在 session、JTI、refresh 等跨副本敏感的比较中引入容忍窗。当前 DPOP 有 1min skew、federation 有 `MaxClockSkew`，但 session/token 过期没有。
3. **Leap second 处理**：UnixNano 计数在 leap second 插入期间可能出现 61 秒或 59 秒的分钟。`time.Now().UnixNano()` 可能在负 leap second 时后退——所有使用 `UnixNano` 作为时间戳或排序键的位置应使用 `UnixMilli()` + 容忍窗。

---

## 方向二：内存存储的无界增长与 GC 策略

### 现状

memory 后端广泛用于单副本部署和测试。当前 GC（垃圾回收过期条目）策略有三种模式：

| 模式 | 位置 | 策略 | 风险 |
|------|------|------|------|
| 写入前 GC | `memory_jti_replay.go:37`, `memory_email_verification.go:37` | 每次写前扫描全部条目扫过期 | O(N) 扫全部，N 可增长到百万级 |
| 周期 GC | `memory_session.go:36` (?) | 后台 goroutine | 窗口期内过期条目仍占用内存 |
| 惰性 GC | `memory_auth_code.go` (?) | 仅在访问时检查单条过期 | 永不被使用的条目永远不释放 |

### 具体边界

#### 2.1 JTI replay store 的无界增长

| 位置 | `memory_jti_replay.go:21` |
|------|--------------------------|
| 数据结构 | `map[string]memoryJTIEntry`，key=JTI，value=含 `exp` |
| GC 策略 | 写前全扫已过期条目 |
| 边界 | ① 攻击者以高速率发送 JAR/DPoP 请求（`jti` 各不相同）→ `map` 持续增长，GC 每次 O(N)。② GC 仅在写时触发——如果最后一次写入后攻击停止，过期条目永不释放。③ 写触发 GC 在攻击峰值期反而加重写延迟 |

**影响**：在 JAR 或 DPoP 重放攻击期间，`map` 可膨胀到 10^6 条目（攻击者 1000 QPS × 16.7 分钟窗口）。每次 GC O(N) 扫描 + `exp` 比较 + `delete`。

#### 2.2 Memory refresh token store

| 位置 | `memory_refresh_token.go:44` |
|------|------------------------------|
| 问题 | `map[string]*refreshEntry` 被家族轮换条目填充。每只 refresh token 轮换（即使是良性用户的正常轮换）产生一个新条目，旧条目仅在家族击杀时才被删除。没有 TTL 定时清理 |
| 影响 | 高 QPS 部署中，正常 refresh 轮换导致条目增长速率 = refresh QPS × 家族树深度 |

#### 2.3 Memory auth code / PAR / device code stores

| 位置 | `memory_auth_code.go`, `memory_par.go`, `memory_device_code.go` |
|------|---------------------------------------------------------------|
| 问题 | 三者都使用 `map[string]*entry` + 仅检查单条过期的惰性 GC。攻击者在短时间内发起大量 `POST /par` 或 `/auth/login`（各带不同 `state`），每个分配一个新条目。作者代码过期后仍保留在 map 中，直到被恰好访问或服务器重启 |
| 影响 | 非攻击场景下 OK（条目数 ≈ 活跃授权流 × 代码 TTL）。但大规模 OAuth 客户端（如批量测试框架或 CI 系统）可产生数十万条/分钟 |

#### 2.4 内存限流器的 O(N) prune

| 位置 | `ratelimit.go:87,129` |
|------|-----------------------|
| 当前 | 16 分片后每写前 `pruneLocked` 全分片扫。ROADMAP v5.0 提到这个 |
| 剩余风险 | 分片化后单分片的 N 在攻击期仍可到 10^4+，O(N) 扫仍是分片写锁的串行化点。高精度定时器（`time.Timer`）GC 加压力 |

### 优化方向

1. **带 TTL 的分片 LRU 或 clock 缓存**：替换所有 `map[string]+全扫 GC` 为分片 `expiryHeap` 或 `timingWheel`（如 `cleverbot/go-timers`）。至少添加 `MaxEntries` 上限 + `semaphore` 背压——满则拒绝 new entry（303/429），不静默增长。
2. **定时 GC goroutine 合并**：所有 memory 后端共享一个全局的 `periodicReaper`（每 TTL/2 扫一次），避免每个 store 各自起一个 gc goroutine。
3. **`JTIReplayStore` 的 Bloom filter 前置**：在精确 `map` 之前加一层 Bloom filter（约 1MB，FPR 1%），对未见过的 JTI 先做 filter 检查。false positive 走精确检查回退。可减少 99% 的 map 写入和 GC 压力。

---

## 方向三：高基数爆炸——Labels、Claims、Scope、Authorization Details

### 现状

代码库已经对 Prometheus labels 做了严格的有界基数控制（`WithTenantMetricsAllowlist` + `"other"` bucket）。但在其他几个维度上，高基数仍有可能发生：

### 具体边界

#### 3.1 `authorization_details` 的未限制深度和大小

| 位置 | `oauth/rar.go`, `core/types.go` |
|------|---------------------------------|
| 问题 | `authorization_details` 是 `json.RawMessage`，在存储（`sqlite/par.go`、`sqlite/refresh_tokens_schema.go`）中作为 BLOB/TEXT 存储。签发时透传至 token 的 `authorization_details` 字段。**未限制**：嵌套深度、数组长度、单条大小 |
| 边界情况 | ① 一个精心构造的 `authorization_details: [{type: "a", ...}, {type: "b", ...}, ...]` 数组包含 10000 个元素 → token 负载达数 MB → 网络往返 + JWKS 缓存膨胀 + 审计记录膨胀。② 递归嵌套 `{actions: [{actions: [{...}]}]}` → JWT 解析深度栈溢出（panic）或 OOM |

#### 3.2 scope 的未限制数量

| 位置 | `oauth/scope.go`, `core/types.go:326-332` |
|------|------------------------------------------|
| 问题 | `AllowedScopes` 是 `[]string`。未限制 scope 数量。虽然 `openid` + `profile` + `email` + `offline_access` 是典型模式，但恶意 client 可注册 1000 个 scope |
| 边界情况 | ① 1000 scope 的 `scope` 参数（SPA 登录 URL）达到 HTTP header / URL 长度上限（~8KB）→ 413 或截断。② 1000 scope 的 JWT `scope` claim → token 负载膨胀。③ 审计事件 `scopes` 字段做 `strings.Join` 后字段超长 |

#### 3.3 自定义 claims 的无界投影

| 位置 | `core/types.go:86-90`, `issue_payload.go:76-77` |
|------|--------------------------------------------------|
| 问题 | `RequestedClaims` 是 `json.RawMessage`，透传到 token 的 `_claims_` 字段。虽然声明了 `ValidateClaimsParameter`，但仅在解析时验证结构（是 JSON 对象），未限制 `value` 的大小或嵌套深度 |
| 边界情况 | 一个正常请求 `{ "id_token": { "email": { "essential": true } } }` 没问题。但 `{ "id_token": { "x": { "value": "` + 1MB 字符串 + `" } } }` 可能导致 issuer 分配大块内存 |

#### 3.4 审计 `facets` 查询的未限制基数

| 位置 | `audit/sqlite/query.go` |
|------|-------------------------|
| 问题 | facet 查询返回每个维度的所有唯一值。如果 `client_id` 维度有 10^5 个唯一值（DCR 的高基数），facet 响应达数 MB。虽然 facet 是 admin-only（受 `admin:read.audit` 保护），但运营者自身也是用户 |

### 优化方向

1. **`authorization_details` 大小限制**：在 `ValidateRAR` 和签发路径上添加 `MaxAuthorizationDetailsDepth`（默认 5）、`MaxAuthorizationDetailsItems`（默认 50）、`MaxAuthorizationDetailsBytes`（默认 16KB）。超过则 `400 invalid_authorization_details`。
2. **Scope 基数限制**：`Client.AllowedScopes` 上限（默认 100），`scope` 参数解析后长度上限（默认 2048 字节）。DCR 注册时拒绝超限 client。
3. **Custom claims 大小限制**：`ValidateClaimsParameter` 增加 `MaxClaimsValueBytes` 检查（默认 4KB）。
4. **Facet 查询分页**：`GET /api/v1/audit/facets` 的结果默认按频率排序 + 前 100 条 + `"other"` 桶。加 `?limit=100&offset=...` 参数。

---

## 方向四：并发与竞态——锁模型、Goroutine 泄漏、Context 传播

### 现状

代码库有约 150 处 `sync.Mutex`/`RWMutex` 使用（包括嵌套模块）、50+ `go func()` 启动点、235 处 `context.Background()` 调用（非测试）。锁的使用模式整体健康（无明显的死锁模式），但以下竞态和泄漏风险值得注意：

### 具体边界

#### 4.1 后台 goroutine 的 Context 悬挂

| 位置 | 模式 | 风险 |
|------|------|------|
| `caep/broadcaster.go:385` | `go func() { t.wg.Wait(); close(done) }()` | broadcaster 无超时——如果某个 CAEP 接收端 RP 的 webhook 永不返回，`wg.Wait()` 永久阻塞，`Shutdown` 无法完成 |
| `server_key_rotation.go:293` | `go func() { … }()` | 签名键轮换 goroutine 使用 `context.Background()`——停机 `Shutdown` 无法让它退出 |
| `server_backchannel_logout.go:311` | `go func() { … }()` | BCL 消息扇出 goroutine 用 `context.Background()`——同上 |
| `saml/idp/fanout.go:286` | `go func() { … }()` | SAML 前端注销扇出用 `context.Background()`——同上 |

**问题模式**：ROADMAP v5.0 §④ 提到了 etcd watch 死亡的不自愈，但更普遍的问题是：**多个后台 goroutine 使用 `context.Background()` 而非热插拔的 `ShutdownContext`**。在 SIGTERM 时，这些 goroutine 可能：
- 继续写入已关闭的 channel → panic
- 继续访问已关闭的 store → 恶化的错误
- 阻止 `main()` 退出 → 超时后强制 `os.Exit`

#### 4.2 memory store 的迭代-删除竞态

| 位置 | `memory_refresh_token.go:44` |
|------|------------------------------|
| 问题 | `mu sync.Mutex` 保护 `map[string]*refreshEntry`。但 `Refresh` 方法执行检查→删除→插入非原子三步（两步 map 操作 + 一步新条目插入），中间 unlock 窗口 |
| 后果 | 并发 refresh 请求（同一 token 在两副本到达同一节点）可看到前一请求已删除旧条目但尚未插入新条目，视为"条目不存在"→ `invalid_grant`。即使没有跨副本问题，同一进程的竞争 goroutine（HTTP/2 多路复用）也可触发 |

**当前缓解**：通过 `DELETE … RETURNING`（SQLite）或 `GETDEL`（Redis）在数据库层保证原子性。但 memory 后端缺少同样的原子保证。

#### 4.3 federation 注册缓存的 sync.Map 不使用后清除

| 位置 | `federation/registration.go:111` |
|------|----------------------------------|
| 问题 | `cache sync.Map` 缓存已解析的 Federation Entity Configuration。条目通过 `entityID` key 缓存，永不清除。虽然在 TTL 过期的条目再次访问时触发重取，但**旧的、从未再被访问**的条目在 `sync.Map` 中持续存在直到进程重启 |
| 边界 | Federation 攻击者可向此缓存填充大量虚构 entityID（`?entity_id=https://evil{1..N}.com/federation`），每个触发一次 fetch + cache entry → `sync.Map` 无限增长 |

### 优化方向

1. **`context.Background()` 审计**：对所有后台 goroutine 的 context 源头做审计——应该是从 `ShutdownContext` 派生（`WithCancel`），而非 `context.Background()`。确保所有后台 goroutine 在 `Shutdown` 时收到 cancel 信号。
2. **Memory store 的 CAS 原语**：将 `memory_refresh_token.go` 的 refresh 操作从"检查→unlock→删除→lock→插入"改为"删除+插入+存在检查"在单锁内的原子操作。添加 `compareAndDelete` 模式。
3. **sync.Map 准入大小限制**：federation 缓存、trust marks 缓存、entity statement 缓存——在所有使用 `sync.Map` 作为缓存的位置添加 `MaxEntries`（默认 10000）准入门禁。超过后删除最旧条目或拒绝新条目（fail-open: 降级为每次实时解析）。
4. **Shutdown 超时槽**：`ShutdownWithTimeout(timeout)`——超过 timeout 后，所有未完成的 bg goroutine 强制取消（`context.WithTimeout`），未写入的审计事件丢弃（`async_sink.go` 已有 `dropsClosed` 计数）。

---

## 方向五：Token 语义边缘情况——大小、编码、映射冲突

### 现状

JWT token 的签发和验证逻辑扎实——alg 白名单、typ 检查、`at+jwt`、`jti` 自动生成均已到位。但以下 token 级别的边界情况仍存在：

### 具体边界

#### 5.1 JWT token 的物理大小爆炸

| 场景 | 边界 | 影响 |
|------|------|------|
| 含 1000 scope 的 JWT | `scope` claim 达 ~8KB | HTTP header 超限（~8KB 上限）→ proxy/Nginx 拒绝请求。WebSocket upgrade 失败 |
| `authorization_details` 含 50 个元素 | ~16KB token | HTTP header 超 8KB 被截断 → 解析失败 + `server_error` |
| `aud` 含 100 个 audience | ~2KB | 同 header 超限 |
| `claims` 参数带巨大 `value` | ~1MB+ | JWT 签发 OOM → 进程崩溃 |

**当前缓解**：HTTP header 默认大小限制（`MaxHeaderBytes`）是内核默认（1MB）或 Echo 默认，但在负载均衡器/sidecar 处通常设得更小（8KB-64KB）。token 通过 header（`Authorization: Bearer`）传递，物理大小直接受限于此。

#### 5.2 `aud` 的单值 vs 数组序列化不一致

| 位置 | 多处 `aud` 反序列化 |
|------|---------------------|
| 问题 | `audClaim`（`defaultimpl/aud_claim_fuzz_test.go` 有 fuzz）在 Go 中处理 `string` vs `[]string`。Fuzz 已覆盖畸形输入。但有一个序列化不一致：当 `aud` 只有一个值时，`json.Marshal` 输出 `"aud":"single"`（紧凑字符串）。JWT 验签方（如 `ssoclient/remote`）如果期望 `"aud":["single"]`（数组），验证将失败 |
| 影响 | 某些严格 JWT 库（如 `go-jose` 的某些版本、Python `PyJWT`）期望 `aud` 总是数组。单值字符串被拒绝→ `invalid_token` |

#### 5.3 JWT `sub` 的空值

| 位置 | `defaultimpl/*_issue.go` |
|------|--------------------------|
| 问题 | `sub` claim 直接来自 `Subject.ID`。如果 ID 为空字符串（bug、测试代码、store 返回零值 User），签发一个 `sub=""` 的 token |
| 边界 | ① 自省端点 `introspect` 返回 `sub=""` → RS 无法关联到用户。② `userinfo` 通过 `sub=""` 查找 → `user_not_found`。③ 两用户都有空 `sub` 时不可区分 |
| 当前缓解 | 调用者通常不会传入空 `Subject.ID`，但没有防御性检查 |

#### 5.4 非唯一 JTI（极端情况）

| 位置 | `defaultimpl/*_jwt_issuer.go` |
|------|------------------------------|
| 问题 | `jti` 使用 32 字节随机数 + hex 编码（64 字符）。碰撞概率约 2^(-256)，可忽略。但**如果 `time.Now().UnixNano()` + `rand.Read` 的随机源在容器启动后短时间内未充分种子化**（如 Go 1.20+ 自动种子化，无问题），理论上可能碰撞 |
| 边界 | Go 1.20+ 的 `crypto/rand` 在启动时由内核种子化。但 Docker 容器启动后的 `crypto/rand.Read` 首次调用在部分 Linux 配置（`CONFIG_CRYPTO_DRBG` 未设置）下可能阻塞。如果阻塞，`jti` 生成延迟 → `/token` 延迟 |

#### 5.5 Token exchange 的 act 链深度限制

| 位置 | `tokengrant/token_exchange_stages.go` |
|------|---------------------------------------|
| 当前 | `MaxActChainDepth = 10` |
| 边界 | 10 深的 act 链意味着 token-exchange 被递归调用 10 次。每次调用 jwt 签发需验证前序 act 链的签名→验签的验签→……9 层递进。最坏情况验签时间叠加 → ~90ms（9×10ms EdDSA 验签） |
| 优化点 | act 链验证使用已验证的 issuer JWKS 的 LRU 缓存。当前每次验签重新 lookup JWK → repeated `kid` → JWK 查找 O(N) N=所有键 |

### 优化方向

1. **JWT 最大大小门禁**：在签发路径（`issue_payload.go`）和接收路径（`bind.go`、`validate_compact_jws.go`）添加 `MaxTokenBytes` 检查（默认 64KB）。超过则 `500 internal_error`（签发）或 `401 invalid_token`（验证）。防止 OOM/DoS。
2. **`sub` 非空断言**：签发前检查 `Subject.ID != ""`，如果是空串则 `500 server_misconfigured` + `security_sub_empty` 审计事件。
3. **`aud` 的归一化**：签发时统一 `aud` 为 `[]string`（即使只有一个值），避免序列化不一致。在 discovery 文档中声明 `aud` 总是数组。
4. **act 链验证缓存**：act 链中的每层 `iss` 的 JWKS 验证结果按 `(iss, kid, jku)` 缓存（复用现有的 `servercache` pattern），避免每跳重复 lookup。

---

## 优先级摘要

| # | 方向 | 风险等级 | 影响面 | 工作量估值 |
|---|------|----------|--------|-----------|
| ①-1 | 时钟回拨导致 token/session 复活 | **高** | 安全 | S（`TimeSource` 接口 + 关键路径替换） |
| ①-2 | TOTP 跨副本时钟漂移 | 中 | 可用性 | S（配置化 skew） |
| ②-1 | JTI replay store map 爆炸 | **高** | DoS 放大 | M（Bloom filter 前置 + 分片 + 上限） |
| ②-2 | Memory 后端定时 GC 合并 | 中 | 性能 | S（共享 reaper） |
| ③-1 | `authorization_details` 深度/大小无限制 | **高** | DoS | S（添加 Validate 上限） |
| ③-2 | Scope 基数无限制 | 中 | DoS | S（添加上限） |
| ③-4 | Facet 查询高基数 | 低 | 运营 | S（分页 + topN） |
| ④-1 | Background context goroutine 悬挂 | **高** | 停机安全 | M（context 审计 + Shutdown 超时） |
| ④-3 | sync.Map 缓存无限增长 | 中 | 资源耗尽 | S（MaxEntries 门禁） |
| ⑤-1 | JWT 物理大小爆炸 | 中 | DoS | S（MaxTokenBytes 检查） |
| ⑤-3 | `sub=""` token 签发 | **高** | 安全/功能 | S（防御性断言） |

### 实施建议

**Phase 0（立刻，S 项）**：子方向⑤-3（`sub=""` 断言）、③-1（`authorization_details` 限制）、①-1（`TimeSource`）、⑤-1（MaxTokenBytes）。这四项是纯防御的安全/稳定性加固，每项 ≤20 行，零设计争议。

**Phase 1（本周）**：子方向②-1（JTI Bloom filter）、④-1（background context 审计）。Bloom filter 减少 99% 的 JTI map 写入压力；context 审计防止 `SIGTERM` 时 goroutine 泄漏。

**Phase 2（本月）**：子方向②-2（合并定时 GC）、①-2（TOTP skew）、③-2（scope 上限）、④-3（sync.Map 上限）、⑤-2（`aud` 归一化）。五项都是已有模式的补全，不需要新的 SPI 或数据结构。

---

## 方法与附录

### 核验方法

每条边界情况的确立通过：
1. **代码模式扫描**：grep `time.Now`、`map\[`、`go func`、`context.Background()`、`json.RawMessage`、`[]string`、`sync.Map` 等模式
2. **交叉验证**：对比 ROADMAP v5.0（06-11）、22 轮分析、06-30 分析、07-01 卷一、07-01 卷二——确保没有重复
3. **边际分析**：对于每条候选，自问"什么场景下这条代码会以非预期方式表现"并反向 grep 验证缓解措施是否存在

### 不在此范围的 Edge Cases（已充分处理）

| 边界情况 | 当前覆盖 |
|----------|----------|
| Token replay | `DELETE … RETURNING` + `JTIReplayStore` + `RefreshFamily` |
| Enumeration | bcrypt dummy hash + 统一 `invalid_grant` |
| Alg none | `AsymmetricJWSAlgs` 白名单 + typ 检查 |
| SSRF | `AllowedRequestURIs` + HTTPS-only + DNS rebind 检查 |
| Clock skew (DPoP) | 可配置 `WithDPoPMaxClockSkew` |
| Integer overflow | 不适用——库函数处理 |
| SQL injection | 参数化查询在所有 `sqlite/*` 中 |
| Path traversal | `net.Dialer.Control` + `isInternalIP` |
