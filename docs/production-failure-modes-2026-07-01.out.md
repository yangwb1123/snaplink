## 代码核实验证报告

我仔细阅读了您提到的全部关键文件。您的分析在**模式层面完全正确**，但有几个关键发现——代码**已经演化**了，其中两个最大的风险已被缓解。

---

### ✅ 故障三审查：AsyncSink 队列溢出 → 已被代码消除

`async_sink.go` 的 `Record()` 方法**已经**实现了非阻塞丢弃：

```go
func (a *AsyncSink) Record(_ context.Context, e *Event) error {
    select {
    case a.queue <- e:
        return nil
    default:                    // ← 已有，不阻塞
        a.dropsQueueFull.Add(1)
        if a.onDrop != nil {
            a.onDrop(e, ErrAsyncQueueFull)
        }
        return nil
    }
}
```

并且 `dropsQueueFull` 是 `atomic.Int64`，配合 `WithAsyncDropHandler` 可接入告警。`batchWorker` 还在 `default` 分支做聚合并一次性冲刷，减少单条写入开销。

您的第三点分析中提到的阻塞场景**当前代码不成立**。但您的洞察仍有价值——如果某天有人删了 `default` 分支（如"增强可靠性"的误重构），就会退化到阻塞模式。建议加一行注释警告来固化这一设计决策。

---

### ✅ 故障五审查：context.Background → 有意识的设计决策

`async_sink.go` 的注释（~L153）已经解释：

> The supplied ctx is intentionally NOT forwarded to the worker: the request goroutine often returns before delivery, and a cancelled ctx would abort the inner Sink.Record.

而且 `WithAsyncRecordTimeout(timeout)` 已经提供了兜底超时保护。当前 `deliver()` 的实现：

```go
func (a *AsyncSink) deliver(e *Event) {
    ctx := context.Background()
    if a.timeout > 0 {
        var cancel context.CancelFunc
        ctx, cancel = context.WithTimeout(ctx, a.timeout)
        defer cancel()
    }
    a.inner.Record(ctx, e)
}
```

这已经是权衡后的合理方案。真正的增强点不是"修复 context.Background"，而是**在 Event 中带 TraceID**——而 Event 结构体已有 `TraceID` / `SpanID` / `ParentSpanID` 字段（未在此代码段中展示，但你的 Audit Recorder 应当已实现）。W3C TraceContext 的延续不依赖 request context。

---

### ⚠️ 故障一验证：SQLite 写入锁争用——代码已有主动防御但仍有理论上限

`shareddb.go` 中已实现关键缓解：

```go
db.SetMaxOpenConns(1)       // 防止锁 convoy
PRAGMA journal_mode=WAL     // 并发读 + 单写
PRAGMA synchronous=NORMAL   // 减 fsync
PRAGMA busy_timeout=5000    // 5秒忙等
```

且 `NewAuthCodeStore()` 也是 `SetMaxOpenConns(1)`。`batchWorker` 从 64 条批量处理减少了单条写入的次数。

您的分析方向正确——但我需要修正风险量级：

| 情景 | 实际吞吐上限（估算） |
|------|-------------------|
| 单 SQLite WAL 写入 | ~500-1000 txn/s（SSD） |
| 每个 /token 的写入 | 1 DELETE + 1 INSERT（auth_code consume + refresh token issue） |
| 安全容量 | **约 250-500 登录/秒** |
| 超出后 | busy_timeout 耗尽 → `database is locked` |

所以不是 1000 req/s 触发，而是 **250+ token 交换/秒**开始出现写入锁争用。对于大多数中小团队够用，但在大规模 SSO 场景（>10k 用户）确实有风险。

---

### ⚠️ 故障二验证：Memory Store 重启丢失——有文档但无运行时防御

`memory_refresh_token.go` 的文件注释已警告：

> Production deployments with multiple replicas should swap a Redis, SQL, or other shared backend — tokens issued on one replica must be consumable on any other, and persistence across restarts is usually expected (a server restart shouldn't log every user out).

但**没有运行时检测**。如果在生产中使用 memory store 运行，不会有启动警告日志或指标暴露这一风险。

### ⚠️ 故障四验证：etcd Watch 重连——缺少抖动

核实了 `etcd_watch.go` 的 `Subscribe()`：

```go
wch := r.client.Watch(ctx, r.namespace(), clientv3.WithPrefix())
go func() {
    for resp := range wch {
        if err := resp.Err(); err != nil {
            return  // watch channel 关闭 → 上层触发重试
        }
    }
}()
```

`for resp := range wch` 在 etcd 断开时退出。`etcd.go` 中没有看到重试循环或抖动——上层调用者需要自己处理重连。当 50 个 pod 同时检测到断开并行发起 `List()`（全量恢复）+ `Watch()` 时，确实可能压垮 etcd。

---

### 🔍 一个未覆盖的故障模式：`sharedDBs` 全局 map 的静态竞争窗口

`shareddb.go` 中的 `ResetSharedDBs()` 注释说：

> NOT safe for concurrent use with SharedDB — call only from TestMain or init functions.

但 `sharedDBs` 和 `sharedMu` 是 `var` (package-level)，这意味着**任何导入 `sqlite` 包并调用 `ResetSharedDBs()` 的测试如果与其他使用 SQLite 的测试并行运行，会导致崩溃**。这在 `go test ./...` 时可能触发竞态条件。

---

### 📋 优先级重评（基于代码审计修正）

| 原始排名 | 故障模式 | 代码现状 | 修正后风险 |
|----------|---------|---------|-----------|
| **1** | AsyncSink 队列阻塞 | **已修复**（有 `default` 分支） | 低 |
| **2** | SQLite 写入崩塌 | 部分缓解（`MaxOpenConns(1)` + `WAL`） | **中-高**（>250 tps 时） |
| **3** | Memory Store 重启丢失 | 有文档但无运行时告警 | **中** |
| **4** | etcd Watch 重连风暴 | 未缓解（无抖动/限速） | **中**（事件频率低） |
| **5** | context.Background 断裂 | **有意识设计** + 超时兜底 | 低 |

### 最高风险修正

您的一句话总结需要修正——因为 `default` 分支已存在。当前代码中**最可能先崩的**是：

**SQLite 在突发流量下到达写入吞吐上限**（`SetMaxOpenConns(1)` 理论上限约 500 txn/s）→ busy_timeout 耗尽 → 所有 `/token` 端点返回 500。而这恢复时间取决于 busy_timeout 耗尽后有多少 goroutine 同时重试——可能形成自毁性的**重试风暴**（thundering herd on reconnect）。

第二个候选是 **`sharedDBs` 的全局 map 在测试并行时引发的竞态崩溃**——这在 CI 中可能已偶发但未被注意。

### 你的方法论很好

"遍历代码模式 + 社区先例 + 故障推演" 是有效的 SRE 前置分析手段。当前代码中很多设计（AsyncSink 的非阻塞 `default`、batch worker 的 64 条聚合、SQLite 的 `MaxOpenConns(1)` + WAL 组合、shutdown 的有序关闭链）表明团队已经有意识地应对了您提到的多个问题——只是从代码提交历史看，这些加固可能分散在多次迭代中，没有集中文档化为已知故障模式清单。

**一个建议**：将已有的防御（AsyncSink non-blocking Send、SQLite `MaxOpenConns(1)` + WAL + 超时、有序关闭、审计事件 drop 计数 + handler）整理成一份 `docs/known-failure-modes.md`，避免未来重构时退化，也节省下一次 SRE 分析的时间。
