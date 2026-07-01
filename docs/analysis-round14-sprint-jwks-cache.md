# Round 14 Sprint Analysis — JWKS Body Cache (1-5s TTL In-Process Cache)

## 1. 背景

JWKS endpoint `/.well-known/jwks.json` 是 OIDC 依赖方轮询最频繁的端点之一。
每次请求都调用 `ComputeJWKSDocument`，后者需要：

- 遍历所有注册的 `TokenIssuer`（每个实现 `core.JWKSProvider`）
- 调用每个 issuer 的 `JWKS(ctx)` 方法取 key 集合
- 合并 JWE decrypter 的 enc key
- 对整个 keyset 做 `json.Marshal`

在没有 body 缓存时，**每个 serial 请求都完整重算**。虽然并发请求被 `jwksFlight`
（singleflight）折叠为一次计算，但 serially 到达的请求仍然每次都重算。

## 2. 变更前状态

变更前 `ComputeJWKSDocument` 已经有缓存骨架，但**默认关闭**（`jwksCacheTTL = 0`）：

- 使用 `sync.RWMutex + []byte + time.Time` 存储单条缓存
- 结果只有 body，不缓存 ETag
- 无 jitter，所有 replica 同时过期 → thundering herd
- 缓存默认关闭，必须通过 `WithJWKSCacheTTL(x)` 或 config 手动开启

## 3. 变更摘要

| 维度 | 变更前 | 变更后 |
|---|---|---|
| 存储结构 | `sync.RWMutex` + `[]byte` + `time.Time` | `sync.Map` + `jwksCacheEntry{body, etag, expiry}` |
| 默认 TTL | 0（禁用） | `5s`（`defaultJWKSCacheTTL`） |
| Jitter | 无 | ±20% 随机 jitter（`jitterTTL()`） |
| ETag 缓存 | 每次请求在 `writeJWKSResponse` 中 `sha256(body)` | 在 cache write 时计算并存 `etag` field；`CachedJWKSETag()` 读取 |
| Cache-Control | 当 `jwksCacheTTL=0` 回退到 `DefaultJWKSCacheMaxAge`（5min） | 默认 `max-age=5`（与 body cache TTL 一致） |
| Invalidation | `jwksBodyExp = time.Time{}` (zero) + RWMutex Lock | `sync.Map.Delete("default")` |

## 4. 文件修改清单

### 4.1 `interfaces/sso/server_discovery.go`

添加 `defaultJWKSCacheTTL = 5 * time.Second` 常量。5s 落在需求 1-5s 范围内，
足够短使 key rotation 在几个 poll 周期内传播，足够长安逸 issuer-walk + marshal 开销。

### 4.2 `interfaces/sso/sso_cachestate.go`

- 添加 `math/rand` 导入
- 添加 `jitterTTL(base time.Duration) time.Duration` — 在 base 基础上 ±20% 随机偏移，
  防止多 replica 同时过期打爆后端
- 添加 `jwksCacheEntry` 结构体：`{body []byte, etag string, expiry time.Time}`

### 4.3 `interfaces/sso/sso_newserver.go`

在 `NewServer()` 中设置 `s.jwksCacheTTL = defaultJWKSCacheTTL`（5s），
使缓存默认开启。`WithJWKSCacheTTL(0)` 仍可显式关闭。

### 4.4 `interfaces/sso/sso_selfservice.go`

替换三个 field：

```go
// 移除
jwksBodyMu    sync.RWMutex
jwksBodyCache []byte
jwksBodyExp   time.Time

// 添加
jwksBodyCache sync.Map
```

### 4.5 `interfaces/sso/accessors.go`

- 添加 `crypto/sha256`、`encoding/base64` 导入
- 添加 `computeETag(body) string` 辅助函数
- 重写 `ComputeJWKSDocument`：
  - 读路径：`sync.Map.Load("default")` + 类型断言 → 检查 `entry.expiry`
  - 写路径：`jitterTTL(s.jwksCacheTTL)` 计算 jittered TTL → `sync.Map.Store()`
  - 每个 cache entry 存 body + etag + expiry
- 新增 `CachedJWKSETag() string` — lock-free 读取缓存 entry 的 etag field
- 重写 `InvalidateJWKSBodyCache`：`sync.Map.Delete("default")`

### 4.6 `protocols/oidc/handlers.go`

- `JWKSDeps` 接口新增 `CachedJWKSETag() string` 方法
- `HandleJWKS` 在调用 `ComputeJWKSDocument` 后获取 `d.CachedJWKSETag()`，
  传递给 `writeJWKSResponse`
- `writeJWKSResponse` 新增 `etagHint string` 参数：
  - 非空时直接使用（避免 SHA-256 计算）
  - 为空时回退到 `sha256(body)`（兼容无缓存的 deps 实现，如测试 mock）

### 4.7 `protocols/oidc/handlers_jwks_test.go`

测试 mock `jwksDeps` 新增 `CachedJWKSETag() string { return "" }` 以满足接口。

### 4.8 `test/jwks_cache_test.go`

`TestJWKS_DefaultTTLAppliesWithoutOverride` 的预期值从 `max-age=300`（5min）改为 `max-age=5`（新默认值 5s）。

## 5. 缓存命中/失效时序图

```
Request A ──→ sync.Map.Load("default")
                │
                ├── hit + expiry valid ──→ return body (lock-free)
                │
                └── miss / expired ──→ jwksFlight.Do(compute)
                        │                 │
                        │                 └── marshalJWKSDocument()
                        │                     ├── walk issuers
                        │                     ├── walk JWE decrypter
                        │                     └── json.Marshal({keys})
                        │
                        └── jitterTTL(5s) → 4.0~6.0s
                        └── sync.Map.Store("default", entry{body, etag, expiry})
```

## 6. 测试结果

```
go build ./...      → PASS
go vet ./...        → PASS
go test -run 'TestJWKS' ./... → ALL PASS (28 tests)
```

相关测试覆盖：

| 测试 | 包 | 验证点 |
|---|---|---|
| `TestJWKSBodyCache_Disabled` | `sso` | TTL=0 时缓存不生效，每次调用重算 |
| `TestJWKSBodyCache_Enabled` | `sso` | TTL>0 时连续调用命中缓存 |
| `TestJWKSBodyCache_Invalidate` | `sso` | `InvalidateJWKSBodyCache` 使缓存失效 |
| `TestHandleJWKS_*` (9 tests) | `oidc` | JWKS 端点功能、ETag、304、500 |
| `TestJWKS_*` (8 tests) | `test` | 集成测试：Cache-Control、ETag 稳定、304、TTL 覆盖 |

## 7. 性能影响

- **正常请求**（缓存命中）：1 次 `sync.Map.Load` + 1 次 `time.Now().Before()`，
  ≈ 几十纳秒开销
- **缓存失效后第一个请求**（缓存 miss）：与变更前同样的 issuer-walk + marshal 开销，
  加上 1 次 SHA-256（ETag 计算）≈ 几微秒，不影响 P99
- **内存**：每个缓存 entry ≈ body size + ~100 bytes overhead。单个 entry 常驻内存
- **ETag 计算时机**：从每次请求都计算 → 仅在 cache miss 时计算一次

## 8. 注意事项

- `JWKSCacheMaxAge()` 返回 `s.jwksCacheTTL`，两者现在是同一值。
  这意味着 Cache-Control `max-age` 与 body cache TTL 相同（默认 5s）。
  如果希望 HTTP CDN 缓存更久而服务端缓存更短，需要分离两个配置。
- 现有 `WithJWKSCacheTTL(0)` 可以完全禁用 body cache（恢复到变更前行为）。
- Jitter 使用 `math/rand` 全局源（Go 1.26 自动 seed），线程安全。
