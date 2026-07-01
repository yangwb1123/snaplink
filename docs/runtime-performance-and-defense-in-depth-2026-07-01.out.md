以上是代码库的实际状态。现在给你一个**地面实况验证 + 补充视角**的回复。

---

## 地面实况验证结果

### ✅ 方向一：sync.Pool 零使用 — 确认

代码库中 **`sync.Pool` 使用次数 = 0**。你的分配估计基本准确，不过让我补充一个更精确的审计：

我从 `ed25519_issue.go` 的 `Issue()` 函数追踪到的每次调用的堆分配：

| 步骤 | 分配 | 大小估计 |
|------|------|---------|
| `generateJTI()` → `make([]byte, 16)` + `EncodeToString` | 2 次 | ~48B + 24B string |
| `json.Marshal(header)` — 完整 JOSE header | 1 次 | ~100B |
| `json.Marshal(payload)` — 完整 claim 集（scopes, jti, exp...） | 1 次 | ~400-600B |
| `EncodeToString(hb)` — header base64 | 1 次 | ~136B |
| `EncodeToString(pb)` — payload base64 | 1 次 | ~600B |
| `[]byte(encoded)` — 签名输入 | 1 次 | ~740B |
| `sgn.Sign()` → Ed25519 签名结果 | 1 次 | 64B |
| `EncodeToString(sig)` | 1 次 | ~88B string |
| 字符串拼接 `token := string(...) + "." + ...` | 1 次 | ~850B |
| `&sso.Token{...}` 返回 | 1 次 | ~120B |
| `buildAccessPayload` 内部的 `strings.Join(scopes, " ")` | 1 次 | ~50-200B |
| `buildAccessPayload` 内部的 `map[string]any{}` 构造 | 1 次 | ~300B |

**保守合计：~13 次堆分配，~3.5KB/次调用。**

**优化潜力更大的部分**其实不是 `sync.Pool` 复用 `bytes.Buffer`，而是：
1. **`json.Marshal`** — 每次调用反射遍历结构体。如果你用 `github.com/goccy/go-json` 或 `jsoniter`，或者直接用静态预编码 header（header 几乎不变），可以省掉 2 次 json.Marshal。
2. **Base64 编码链** — 当前模式是先 `Marshal` 得到 `[]byte`，再 `EncodeToString` 产生新 `string`，再拼接到一起。这个"bytes→string→concat"模式每次产生 4-5 个临时分配。

---

### ⚠️ 方向二：纵深防御 — 部分确认，部分已有但不能松懈

你分析最准的是 **CSP 缺失**。代码库确实 **没有任何 `Content-Security-Policy` 响应头**。

但 CSRF 的图景比你描述的好一些：

```go
// interfaces/sso/server_login.go 中已有：
// CSRF protection: the login SPA sends application/json; reject
// non-JSON content types as a defense-in-depth CSRF measure.
```

并且 `interfaces/sso/origin_validation_test.go` 中已经测试了 **Origin header 校验**：

```go
expectBlockedByCSRF: true, // Origin not allowlisted → blocked
```

这是 **CSRF 的第一道防线**（检查 Origin/Referer header + JSON content-type 约束）。但它不是 CSRF token——确实**没有 CSRF token 机制**。

关于 Cookie 安全标记，我可以看到 SecurityHeaders 中间件设置了：

| Header | 状态 |
|--------|------|
| `Strict-Transport-Security` | ✅ `max-age=31536000; includeSubDomains` (仅 TLS) |
| `X-Content-Type-Options` | ✅ `nosniff` |
| `X-Frame-Options` | ✅ `DENY` |
| `Referrer-Policy` | ✅ `no-referrer` |
| `Content-Security-Policy` | ❌ **缺失** |

**你的 CSP 建议完全合理**，但有一点需要注意：所有 SPA 使用**内联 `<script>` 标签**，所以 CSP 要么需要 `'unsafe-inline'`（严重削弱防护），要么为每个页面注入 **nonce**。后者需要修改 SPA 的 HTML 模板引擎，工作量比单纯加 middleware 大。

---

### ❌ 方向三：Discovery 文档缓存 — 已经存在

这里的分析**不准确**。代码库已经有一个**精细的 Discovery 缓存系统**：

```
interfaces/sso/server_discovery_cache.go
```

具体实现包括：
- **TTL 驱动的缓存**（可配置 `WithDiscoveryCacheTTL`）
- **Double-checked locking** 防止缓存击穿
- **Fingerprint 快速路径**：如果 `ClientStoreStats` 接口可用，通过比对 store 的 count+hash 在 TTL 过期后**避免重算**
- **Stale-then-revalidate**模式：store 不可用时返回过期缓存，不报错
- **跨 replica 失效**：`invalidationBus.Publish` 在角色变更时通知其他 replica

所以 OIDC Discovery **不是每次请求动态生成的**。但它确实只在 `TTL > 0` 时启用——如果部署没有调用 `WithDiscoveryCacheTTL()`，默认就是每请求生成。

**修正后的判断**：代码已有缓存框架，问题可能是**默认没有启用** + **仅缓存了 client-discovery 信息，未缓存 JWKS 文档**。`/jwks.json` 端点是否也有类似缓存需要查。

---

### ✅ 方向四：Memory Store 分片锁 — 确认

所有 memory store 都使用简单的 `sync.Mutex`：

```
MemoryAuthCodeStore:   sync.Mutex（验证）
MemoryRefreshTokenStore: sync.RWMutex（需要确认）
MemoryDeviceCodeStore: sync.RWMutex
MemoryPARStore:       sync.RWMutex
MemoryCIBAStore:      sync.RWMutex
MemorySessionStore:   sync.Mutex
```

但有一个重要的**架构背景**：这些 memory backend 的**设计目标是单进程开发/测试**，生产部署应该用 `sqlite/`、`redis/` 或 `postgres/`。所以分片锁的 ROI 取决于生产部署模式：
- **单进程 memory 部署**（小型自托管）：分片锁收益高
- **SQLite/PostgreSQL/Redis 部署**（生产中预期的方式）：分片锁不适用（数据库自己处理并发）

---

### ⚠️ 方向五：Context.Background 泄漏 — 确认，但数量比估计少

我 grep 了所有非 test 文件，`context.Background()` 的 **请求路径中真正有问题的** 是：

| 文件 | 行 | 问题 |
|------|----|------|
| `platform/audit/async_sink.go:189` | `ctx := context.Background()` | `deliver()` 方法丢失请求 trace |
| `platform/audit/async_sink.go:238` | `ctx := context.Background()` | `deliverBatch()` 同理 |
| `platform/netpolicy/handlers.go:190` | `return context.Background()` | 回退路径，非常规请求 |
| `interfaces/ratelimit/sqlite_limiter.go:143` | `ctx := context.Background()` | rate limit 查询缺少上下文 |

其余 100+ 处 `context.Background()` 调用分两类，**都可以接受**：
1. **初始化/迁移代码**（~80 处）：`db.PingContext(context.Background())`、`migrate.Run(context.Background(), ...)`、构造器中的 seeds。这些在启动时运行，没有请求上下文可传播。
2. **后台 goroutine**（~20 处）：etcd keepalive、key rotation、retention policy。有独立的生命周期管理。

所以**真正需要修复的 = 3-4 处**，不是 11 处。

---

## 我的优先级重排

基于代码库实际状态，我会调整你的优先级：

| # | 方向 | 原优先级 | 调整后 | 理由 |
|---|------|---------|--------|------|
| **1** | **CSP 安全头** | 2 | **1** 🔺 | 缺失是实际安全缺口；企业安全审查硬性要求 |
| **2** | **sync.Pool + JWT 分配优化** | 1 | **2** | 高吞吐场景收益大，但纯内存优化（非安全） |
| **3** | **async_sink context 传播** | 5 | **3** 🔺 | 修复成本极低（~30行），恢复 trace 关联 |
| **4** | **Memory store 分片锁** | 4 | **4** | 仅影响 memory backend，生产部署使用 SQL/Redis |
| **5** | **Discovery 缓存默认启用** | 3 | **5** 🔻 | 框架已存在，核实默认是否启用即可 |

另外建议**追加一个发现**——我发现两个未曾进入分析方向的新问题：

### 追加 A：JTI 生成用 `crypto/rand` 读取 16 字节

```go
func generateJTI() (string, error) {
    buf := make([]byte, 16)
    if _, err := rand.Read(buf); err != nil { ... }
    return base64.RawURLEncoding.EncodeToString(buf), nil
}
```

每次 JWT 签发都调用 `crypto/rand.Read`——这是一个**系统调用**（读 `/dev/urandom`）。在 Linux 上这很快，但在高吞吐（2000+ token/s）下，这比 `sync.Pool` 优化更值得关注。替代方案：用 `math/rand/v2` 的 PCG 生成器 + 递增计数器组合，只在启动时从 `crypto/rand` 拿种子。可以省掉每次 token 签发的系统调用。

### 追加 B：ECDS256 / Ed25519 签发函数有大量重复代码

`ecdsa_issue.go` 和 `ed25519_issue.go` 的 `jwtSigningInput`、`idTokenSigningInput`、`SignJWT` 三个函数在两种算法间**完全重复**——结构体类型不同但逻辑完全一样。每次签发都有同一个 `json.Marshal` + `base64.Encode` 模式。可以通过泛型或接口抽象消除重复，但这是代码健康问题而非性能/安全问题。
