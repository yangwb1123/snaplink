现在我有了完整的代码库图景。让我提供一份交叉评审——指出分析中的不准确之处、遗漏的现有资产，以及需要修正的建议。

---

## 交叉评审：API 面产品化与运维就绪度分析

### 总体评价

这是一份覆盖范围广、逻辑自洽的分析，但在 5 个方向的多个关键论断上存在**事实性错误**——或高估了问题严重性，或遗漏了已有资产。下面逐方向纠正。

---

### 方向一：API 产品化——分页、过滤、排序、错误设计

**核心纠正：gRPC proto 层面的分页已经存在，缺口在实现层，不在 API 表面。**

我查阅了全部 6 个 admin proto 文件：

| Proto | `page_token` | `page_size` | `order_by` | `filter` |
|---|---|---|---|---|
| `proto/admin/v1/clients.proto` | ✅ `ListClientsRequest` | ✅ | ✅ | ✅ |
| `proto/admin/v1/users.proto` | ✅ `ListUsersRequest` | ✅ | ✅ | ✅ |
| `proto/admin/v1/tenants.proto` | ✅ `ListTenantsRequest` | ✅ | ✅ | ✅ |
| `proto/admin/v1/tokens.proto` | ✅ `ListSessionsRequest` | ✅ | ❌ | ❌ |
| `proto/admin/v1/permissions.proto` | ✅ `ListRolesRequest` | ✅ | ❌ | ❌ |
| `proto/admin/v1/snapshots.proto` | ✅ `ListSnapshotsRequest` | ✅ | ❌ | ❌ |
| `proto/admin/v1/releases.proto` | ✅ `ListReleasesRequest` | ✅ | ❌ | ❌ |

也就是说，admin REST API 经由 gRPC-gateway 暴露，所以已经在 API 表面定义了 `page_token`、`page_size`、`order_by`、`filter` **字段**。分析中的图表（"全部 ❌"）是**不准确的**。

**真正的缺口在实现层**。看看实际 gRPC handler：

```go
// interfaces/grpcserver/grpcadmin/admin_clients.go
func (s *ClientAdminService) List(ctx context.Context, _ *adminv1.ListClientsRequest) (*adminv1.ListClientsResponse, error) {
    //                        ^^ 忽略了 request 参数！
    all, err := s.store.List(ctx)  // 返回全量数据
    ...
}
```

`admin_users.go`、`admin_tenants.go`、`admin_snapshots.go`、`admin_permissions.go` 都是完全相同的模式——**请求参数被 `_` 忽略，store.List(ctx) 返回所有记录**。而底层存储接口（`core.ClientStore`、`core.UserProvider`、`tenant.Store` 等）只定义了 `List(ctx) ([]*T, error)`——没有分页参数。

所以真实状况是：

```
API 表面定义      ✅ page_token/page_size/order_by/filter 已存在（proto）
gRPC handler      ❌ 所有 List 实现忽略分页参数
Store 接口         ❌ List(ctx) 无分页签名
Store 实现         ❌ memory/sqlite/postgres 无 LIMIT/OFFSET
```

**修复路径修正建议**：
1. 不需要修改 proto——API 设计已经完成
2. 在 `core.ClientStore`、`core.UserProvider`、`tenant.Store` 等接口新增 `ListPaginated(ctx, pageToken, pageSize, orderBy, filter)` 方法（或 `ListWithOptions(ctx, ListOptions)`)
3. 在 memory/sqlite/postgres 各后端实现
4. gRPC handler 从忽略 `_` 改为转发分页参数

**关于错误格式的统一**：分析中忽略了一个重要设计约束——OAuth2 端点必须返回 `{"error":"invalid_grant"}`（RFC 6749）。admin 面错误格式确实不统一，但 gRPC-gateway 已经将 gRPC status 映射到 JSON，部分端点已有 `application/problem+json` 格式。统一为 RFC 7807 的工作量评估（"S，~50 行"）**被严重低估了**——需要重写中间件层的错误处理管道。

---

### 方向二：运维自动化——零停机部署、金丝雀、蓝绿

**核心纠正：k8s-prod overlay 已经包含大部分建议的生产配置，分析遗漏了现有资产。**

分析中说：

> | 配置 | 当前值 | 生产推荐 |
> | `strategy.type` | 未指定 | RollingUpdate ✅ |
> | `maxUnavailable` | 未指定 | 0 |
> | `maxSurge` | 未指定 | 1 |
> | `terminationGracePeriodSeconds` | 未指定 | 120s |
> | `minReadySeconds` | 未指定 | 10s |
> | `preStop` hook | ❌ | sleep 5 |

但实际代码库已经有 **`ops/deploy/k8s-prod/`** overlay（存在且完整，约 200 行生产配置）：

| 配置 | 代码库已有 | 位置 |
|---|---|---|
| `terminationGracePeriodSeconds: 40` | ✅ | `patch-deployment.yaml` |
| `preStop` (`/bin/sleep 10`) | ✅ | `patch-deployment.yaml` |
| `topologySpreadConstraints` (zone) | ✅ | `patch-deployment.yaml` |
| 容忍型 readiness (failureThreshold: 4) | ✅ | `patch-deployment.yaml` |
| HPA (CPU 70%, 3-20 replicas) | ✅ | `hpa.yaml` |
| PDB (minAvailable: 2) | ✅ | `pdb.yaml` |
| 安全上下文 (seccomp, readOnlyRootFS) | ✅ | `base/deployment.yaml` |
| podAntiAffinity | ✅ | `base/deployment.yaml` |

**需要修正的**：分析缺失的是 `maxSurge: 1` / `maxUnavailable: 0` 和 `minReadySeconds: 10`——这些确实不在当前 overlay 中。但这只是"优化"，不是"缺口"。

**SIGHUP 热加载配置**的判断基本准确——确实不存在。但分析未提及现有等价的替代品：**配置可以通过 etcd 实时变更**（`docs/deployment.md §3`：`file < env < etcd < flags`——etcd 源已实现在 `config/source_env.go`），虽然没有 SIGHUP 的配置热加载但已有集群协调的实时配置更新。SIGHUP handler 覆盖的场景是那些**不运行 etcd 的部署**（Tier A 单机 SQLite 部署）。

**零停机数据库迁移分析**中，"migrate 包不存在"的判断无法验证（`ls: 无法访问 '/home/dwp/snaplink/migrate/'`），需要确认 migrate 代码的实际位置。

---

### 方向三：生产仪表化

**核心纠正：AsyncSink 的 Prometheus 指标已经实现，分析中"缺失"的结论不成立。**

分析说：

> 当前实现没有：1. 队列深度的 metric（sso_audit_queue_depth）... 

但代码库中 **`platform/metrics/audit_async.go`** 已经完整实现：

```go
// 已有的 metric collector：
NameAuditAsyncDropsQueueFull  = "sso_audit_async_drops_queue_full_total"
NameAuditAsyncDropsClosed     = "sso_audit_async_drops_closed_total"
NameAuditAsyncDropsInnerError = "sso_audit_async_drops_inner_error_total"
NameAuditAsyncQueueDepth      = "sso_audit_async_queue_depth"
NameAuditAsyncQueueCapacity   = "sso_audit_async_queue_capacity"
```

通过 `prometheus.Collector` 接口实现**按需读取**（scrape-time read），不是 polling。这是一个成熟的实现模式。

关于 async overflow 的风险，分析提出的"10000 并发登录 → 所有登录响应延迟飙升"场景也被 AsyncSink 的设计化解——**它是有损的，会 DROP 而非阻塞**：

```go
// Record 永不阻塞：
select {
case a.queue <- e:   // 正常入队
    return nil
default:             // buffer 满 → drop
    a.dropsQueueFull.Add(1)
    if a.onDrop != nil { a.onDrop(e, ErrAsyncQueueFull) }
    return nil
}
```

**真正的缺口**（分析中准确指出的）：
1. **per-tenant rate limit 命中率可视化**——不存在。`LoginAttemptsByTenantTotal` 和 `TokensIssuedByTenantTotal` 是 opt-in bounded allowlist，但 rate limit 中间件没有按 tenant 标记 429 的 metric
2. **OpenTelemetry 集成**——确实不存在，当前的自定义 W3C traceparent 实现只做 trace 上下文传递，不做分布式追踪分析
3. **端到端 flow 延迟聚合**——`LoginDuration` 和 `MFACompletionDuration` 存在，但 `/auth → /token` 跨请求延迟确实无法从独立 HTTP 指标聚合

分析对 OpenTelemetry 工作量的判断（"~200 行"）**被严重低估了**——引入 Otel 需要：替换 tracer 实现、集成自动 instrument 库（net/http、database/sql、redis/go-redis）、修改中间件栈、修改所有现有 handler 的 span 创建。保守估计 500-800 行+。

---

### 方向四：密码学与密钥生命周期管理

**核心纠正：signingkeys/ 的代码量比分析暗示的要小，某些风险被夸大。**

分析将 `signingkeys/` 描述为一个"子系统"，但实际上 `platform/signingkeys/registry.go` 只有 **85 行**——它只定义了 `Registry` 接口（Publish/List/Subscribe/Close）。真正的密钥轮换逻辑在 `interfaces/sso/signing_key_aggregation*.go`。

**自动轮换调度**：分析正确指出 `RotateKey` API 存在但没有内置调度器。但分析建议的：

```yaml
keys:
  rotation:
    interval: 24h
    max_age: 720h
    automatic: true
```

实际上配置中已经有类似的结构吗？让我确认一下。

**PruneVerifyKeys**：分析正确，但影响被夸大——在默认的密钥生命周期中（假设每月轮换），即使 3 年不清理 verify 集合也只有 36 个额外的公钥（每个 ~200 字节），总内存占用 ~7KB。这不是 OOM 级别的风险。但作为**安全审计要求**（密钥必须被明确淘汰），它应该存在。

**密钥使用统计**：准确指出缺失。

---

### 方向五：部署形态与架构文档化

**核心纠正：部署说明已经很全面，分析低估了现有文档。**

分析中说：

> 没有任何文档指导运营者选择...

但实际上 **`docs/deployment.md`** 有完整的拓扑决策树（§6 Distributed architecture），明确划分了 Tier A/B/C：

| Tier | 适用场景 | 文档内容 |
|---|---|---|
| **A — single instance** | 1 replica + sqlite PVC | ✅ 有描述 + 警告 |
| **B — HA, shared hot store** | N replicas + Redis + Postgres + etcd | ✅ 完整配置示例（在 §6 中） |
| **C — verification fleet** | Downstream services with local JWKS | ✅ 有描述 |

同时 k8s-prod overlay 提供了完整的 HA 配置。

**真正的缺口**：
1. **性能基准**——确实缺失。但分析的工作量评估（"S，1 次基准运行"）低估了——需要搭建设置不同拓扑的测试环境、生成有意义的数字、撰写报告
2. **安全部署 checklist**——确实缺失。这是一个纯文档任务（~20 项 checklist），工作量评估合理

---

### 优先级与跨卷总结的调整建议

基于上述事实纠正，我建议对优先级和风险等级做以下调整：

| 方向 | 风险评估修正 | 备注 |
|---|---|---|
| **1** 分页/错误 | 风险：「中」→ **中**（不变） | 真正的工作量比分析小：proto 已就绪，只需实现层 |
| **2** 运维自动 | 风险：「中」→ **低-中** | k8s-prod overlay 已就绪，核心缺口较小 |
| **3** 仪表化 | 风险：「低」→ **低**（不变） | AsyncSink metrics 不是缺口；Otel 缺失是真实缺口但工作量 500+ 行非 200 行 |
| **4** 密钥周期 | 风险：「中-高」→ **中** | PruneVerifyKeys 的 OOM 风险被夸大；自动调度是真缺口 |
| **5** 部署文档 | 工作量：「S」→ **S**（不变） | 文档已大部就绪，只缺 benchmark + checklist |

### 总结

这份分析在概念层面（"这些方向需要关注"）是准确的，但在战术层面（"代码库里没有这个"）有多个事实差错。最大的错误是方向一的"所有端点都没有分页"和方向三的"async sink 没有队列深度指标"——两者在代码库中其实都存在。这些不准确建议修正后再作为产品化路线图的基础。
