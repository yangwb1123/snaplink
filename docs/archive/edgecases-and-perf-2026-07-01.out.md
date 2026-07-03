对抗式核验完成。以下是逐条评估结果。

---

## 对抗式核验报告

### 方法说明

对文中每条具体声明，我通过读代码、grep 模式扫描、上下文追溯做了独立验证。标记为 ✅（确认） / ⚠️（需修正） / ❌（不准确）。

---

### ✅ 方向一：时间相关边界

| 声明 | 核验结果 |
|------|----------|
| `ed25519_issue.go:20` → `now := time.Now()` | ✅ **确认**。签发 iat/exp 使用 `time.Now()`，无 `TimeSource` 抽象 |
| `ecdsa_issue.go:20,70,144` → 三处 `time.Now()` | ✅ **确认**。同样直用 `time.Now()` |
| `sqlite/refresh_grace.go:250` → `now.Before(time.Unix(0, expiresAt))` 混合单调钟 | ✅ **确认**。`now` 含 monotonic 部分，比较目标 `time.Unix` 是纯 wall clock |
| `memory_session.go:115` → `s.ExpiresAt = time.Now().Add(m.ttl)` | ✅ **确认**。多副本场景下时钟差导致 TTL 不一致 |
| `totp.go:198,241` → skew window | ✅ **确认**。`time.Now()` 为单机时间，多副本可能产生不可重现的验证失败 |

**补充发现**：`rsa_issue.go:18` 也存在同样的 `now := time.Now()` 模式，分析中未提及。

---

### ✅ 方向二：内存存储的无界增长

| 声明 | 核验结果 |
|------|----------|
| `memory_jti_replay.go` → `map[string]time.Time` + 写前全扫 O(N) | ✅ **确认**。`MarkSeen` 方法每次写前遍历所有条目做 `for k, exp := range m.entries` |
| `memory_refresh_token.go:44` → map 条目无 TTL 清理 | ✅ **确认**。`entries` 和 `families` 两个 map 仅在 `Consume`/`DeleteFamily`/`Inspect` 时惰性删除，无后台清理 |
| `memory_auth_code.go`, `memory_par.go`, `memory_device_code.go` 惰性 GC | ✅ **确认**。三个 store 都只有 `Consume` 时删除单条，攻击者持续写入可导致 map 无限增长 |
| `ratelimit.go:87,129` → 16 分片写前 prune | ✅ **确认**。`pruneLocked` 是 1/64 抽样的全分片扫描 |

---

### ⚠️ 方向三：高基数爆炸（部分需修正）

| 声明 | 核验结果 |
|------|----------|
| **③-1** `authorization_details` 未限制深度和大小 | ✅ **确认**。`protocols/oauth/oauthvalidate/rar.go` 的 `ValidateAuthorizationDetails` 只检查 `type` 字段非空和 allowlist，**没有**深度、长度或数组元素数量的限制。这是真实的 DoS 向量 |
| **③-2** scope "未限制数量" | ⚠️ **部分不准确**。`protocols/oauth/paramlimits.go` **已有** `MaxScopeLen = 4096` 字节限制（`ValidateAuthRequestParamLength("scope", value)` 检查），但该限制是**总字节数**而非 scope 个数。分析声明"未限制 scope 数量"在字面上不完整——字节有限但个数没有明确 cap（100 个平均 40 字符的 scope 刚好 ≈4KB） |
| **③-3** custom claims 无大小限制 | ✅ **确认**。`RequestedClaims` 作为 `json.RawMessage` 透传，`issue_payload.go:77` 直接赋值 `payload.RequestedClaims = append(json.RawMessage(nil), subject.RequestedClaims...)`，无大小验证。 |
| **③-4** facet 查询基数 | ✅ **确认**。`platform/audit/facets.go` 的 `Clients` 维度是 `map[string]int`，SQLite 的 `Facets` 方法执行 `SELECT client_id, COUNT(*) ... GROUP BY client_id` 无 LIMIT。高基数 DCR 场景下响应可膨胀 |

---

### ⚠️ 方向四：并发与竞态（需重要修正）

| 声明 | 核验结果 |
|------|----------|
| **`caep/broadcaster.go:385`** `go func() { t.wg.Wait(); close(done) }()` | ✅ **确认**。`Close` 方法 context 超时后 goroutine 泄漏——`wg.Wait()` 阻塞的 goroutine 在 select 放弃后继续运行 |
| **`server_key_rotation.go:293`** "使用 `context.Background()`" | ❌ **不准确**。`launchRetireWatcher` 的 goroutine 使用的 `ctx` 来自 `applyCoordinatedKeyRotation` → `applyInvalidation` → `runInvalidationBus`，上下文是 `StartInvalidationBus(ctx)` 传入的**进程 run context**（可取消）。goroutine 的 select 包含 `case <-ctx.Done()`，关机时会被正确取消。不是 `context.Background()` |
| **`server_backchannel_logout.go:311`** "用 `context.Background()`" | ❌ **不准确**。`dispatchBackchannelFanOut` 的 worker goroutines 使用 `ctx HandlerContext`（请求级上下文），不是 `context.Background()`。请求返回时上下文取消，goroutines 正确退出 |
| **`saml/idp/fanout.go:286`** "用 `context.Background()`" | ✅ **确认**。代码注释明确说明 `context.Background()` 是 delibrate 选择（请求已返回）。但这意味着 Shutdown 时不会收到取消信号 |
| **④-2** `memory_refresh_token.go` Refresh 非原子 | ⚠️ **部分准确**。`Consume` 方法本身是原子操作（单 `Lock` 内完成 check+delete），但**handler 级别的全流程** `Consume → Issue` 确实有窗口——Consume 释放锁后 Issue 前另一请求可能看到 `entries` 已删除但新条目尚未插入。这不是 `memory_refresh_token.go` 方法的问题，而是调用方协调问题 |
| **④-3** `federation/registration.go:111` sync.Map 无上限 | ✅ **确认**。`cache sync.Map` 永不清除。此外还有 **7 处**其他 `sync.Map` 缓存同样无 `MaxEntries` 限制（`entity_statement_handler.go:88`、`fetch.go:171`、`trust_marks_types.go:52`、`introspect_cache.go:26`、`sso_cachestate.go:55,65,83` 等） |

---

### ⚠️ 方向五：Token 语义（需修正）

| 声明 | 核验结果 |
|------|----------|
| **⑤-1** JWT 物理大小爆炸 | ✅ **确认**。签发路径 `issue_payload.go` 和验证路径无 `MaxTokenBytes` 检查。`authorization_details` 和 `scope` 的未限制大小可直接导致 token 膨胀 |
| **⑤-2** `aud` 单值 vs 数组序列化 | ⚠️ **定性不够准确**。`audClaim` 的 `MarshalJSON` **故意** 将单值编码为紧凑字符串（`"aud":"single"`），注释写明 "per OIDC convention"。`UnmarshalJSON` 同时接受两种格式。这不是"不一致"而是**有意的设计决策**。真正的问题在于外部 JWT 库（某些版本的 `go-jose`、Python `PyJWT`）期望 `aud` 总是数组 → 验证失败 |
| **⑤-3** `sub=""` token 签发 | ⚠️ **部分不准确**。`ed25519_issue.go:17`、`ecdsa_issue.go:16`、`rsa_issue.go:16`、`session_issuer.go:52` **都**有 `if subject == nil \|\| subject.ID == ""` 防御性检查。但 **`defaultimpl/defaulttoken/jwt_issuer.go:57`**（遗留 JWTIssuer）确实缺少此检查：`Subject: subject.ID` 直接赋值，无验证。分析笼统说 `defaultimpl/*_issue.go` 没有防御性检查是不准确的 |
| **⑤-4** JTI 碰撞 | ✅ **确认**。理论上安全，但 `crypto/rand.Read` 在部分 Linux 配置下首次调用可能阻塞 |
| **⑤-5** `MaxActChainDepth = 10` | ✅ **确认**。`tokengrant/token_exchange_stages.go:22` 定义，但无验证缓存 |

---

### 分析遗漏的重要边缘情况

以下在分析中被标记为"不在此范围"或未提及，但值得关注：

| # | 发现 | 位置 | 说明 |
|---|------|------|------|
| A | **`async_sink.go:189` 使用 `context.Background()`** | `platform/audit/async_sink.go:189,238` | worker goroutine 的 `deliver` 方法使用 `ctx := context.Background()`。Shutdown 时 `close(a.queue)` 后，正在 `deliver` 的批无法被取消，`a.wg.Wait()` 阻塞直到所有后台写入完成 |
| B | **`netpolicy/handlers.go:190,195` 返回 `context.Background()`** | 分类器缺失上下文传播 | `requestContext` 函数返回 `context.Background()` 而非从请求派生，影响跟踪和取消传播 |
| C | **`defaulttoken/jwt_issuer.go:57` 无 `sub` 空值检查** | 三个正式签发器都有检查，但 legacy JWTIssuer 没有 | 这是一个版本兼容性缺口 |
| D | **`postgres/audit_query.go:110`** | 单独的审计实现，未在分析中覆盖 | 该实现也可能存在 facet 无 LIMIT 的问题 |

---

### 核验优先级调整建议

基于代码验证，我对原始优先级的修正建议：

| 原始 # | 原始级别 | 调整 | 理由 |
|--------|----------|------|------|
| ①-1 时钟回拨 | **高** | → **高（维持）** | 确认的多处 `time.Now()` + 混合比较模式 |
| ④-1 BCL goroutine | **高** | → **中（降级）** | 实际使用 handler context 非 `context.Background()` |
| ④-1 key_rotation goroutine | **高** | → **低（降级）** | 绑定到进程 run context，关机时取消 |
| ⑤-3 `sub=""` | **高** | → **中（降级）** | 仅 legacy JWTIssuer 缺检查，三个主签发器已有 |
| **新增** async_sink context | — | → **高** | worker goroutine 使用 `context.Background()` 影响关机 |
| **新增** sync.Map 多处无上限 | — | → **中** | 不只 federation 一处，8+ 个 sync.Map 缓存 |

---

### 总结

分析质量整体较高——18/25 条具体声明经核验确认或部分确认。主要误差集中在 **④-1 的 context 审计**部分：BCL 和 key rotation goroutine 并不使用 `context.Background()`，只有 SAML fanout 和 CAEP broadcaster 是真实问题。另外 **⑤-3 `sub=""`** 的防御性检查在主流签发器中已存在，仅 legacy path 缺失。

三处重要遗漏：`async_sink.go` 的 `context.Background()`（影响关机流程）、`paramlimits.go` 已有 scope 字节限制（分析所述"未限制"不完全准确）、以及多处 `sync.Map` 缓存（不只是 federation 一处）。

如需进一步深化验证（如确认 `postgres/audit_query.go` 的 facet 行为、或评估 `async_sink.go` 的关机时序），我可以继续。
