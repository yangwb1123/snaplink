Now I have all the facts. Here is my review:

---

## 审查结论：分析中存在两个重大事实错误

逐条对照代码验证，五个方向的结论如下：

---

### ① Grace 窗口跨副本 — ⛔ 前提错误，该功能已完整实现

分析声称：
> "SQLite 无 RefreshGraceStore"
> "Memory 后端无 Grace 窗口概念"

**代码实际情况：**

| 声明 | 事实 |
|---|---|
| "SQLite 无 RefreshGraceStore" | ❌ **已有完整实现**：`infrastructure/defaultimpl/sqlite/refresh_grace.go`，约 235 行，含 schema 建表、`Remember`/`Lookup`、`DELETE...RETURNING` 原子消费、后台定期清理 |
| "Memory 后端无 Grace 窗口" | ❌ **已有**：`internal/handler/tokengrant/refresh_grace.go` 的 `RefreshGraceCache` 单副本内存实现 |
| 未接线 | ❌ **已完整接线**：`cmd/sso-server/build_app_oauth.go:242-267`，支持 `memory` / `sqlite` / `redis` 三种后端 |

真实情况是：**默认后端是 `memory`（单副本）**，运维需要在配置中显式设置 `oauth.refresh_token.rotation_grace_backend: sqlite` 或 `redis` 才能跨副本生效。这是一个**文档/默认值**问题，不是缺失实现。

**建议**：此方向不需要写新代码。可以做的改善是：将默认后端从 `memory` 改为自动探测（有 SQLite DSN 则默认 sqlite，有 Redis 则默认 redis），或在日志中打印 warning 提醒多副本未配置跨副本 grace 后端。

---

### ⑤ 审计日志结构化导出 — ⚠️ 部分错误：Webhook Sink 已存在

分析声称：
> "无 webhook 导出器"

**代码实际情况：**

`WebhookSink` 已完整实现（`platform/audit/auditsink/webhook_sink.go`），且已在 `cmd/sso-server/build_app_core.go:277-303` 完整接线，配合 `RetryingSink` 提供指数退避重试。配置路径 `audit.webhook.*` 已可用。

**分析中真正缺失的部分：**
- S3/GCS/Azure Blob 合规归档 sink — 确实不存在
- 原生 syslog / Elasticsearch / Loki sink — 确实不存在

**建议**：此方向的范围应缩小为"对象存储归档 sink"（SOC2/GDPR 合规驱动），webhook 部分已经覆盖了 SIEM 集成场景。

---

### ② 认证事件发布体系 — ✅ 前提正确，真实空白

验证结果：

- `dispatchLoginAnomaly()` 确实存在，但仅服务于 `anomaly.Runner`（行为检测），是**内部**消费路径
- `anomaly.LoginEvent` 结构体存在但不对外开放
- **无任何**面向外部系统的结构化认证事件发布机制（无 SIEM push、无 Slack 通知、无事件总线 fan-out）
- `cluster.Bus` 存在但仅用于内部副本间消息（`KindTokenRevoked` 等）

**判断**：这是真实的空白。已有的 `cluster.Bus` 发布/订阅模式 + `audit.Sink` 链 + `WebhookSink` 重试机制为构建"认证事件发布"提供了良好基础，可以在不新建基础设施的前提下增加一个 `LoginEventSink` 或扩展 `audit.Sink` 过滤机制。

---

### ③ 运行时配置热重载 — ✅ 前提正确，真实空白

验证结果：

- `config/etcd/source.go` 注释明确写着："The Source intentionally re-fetches on every Load and does NOT watch — ... watching would require either a hot-reload pathway through *Config (**which doesn't exist**)"
- 无 `Config.Watcher`、无 `*Server.ApplyDelta()`、无运行时配置变更通知机制
- `*Server` 的访问器（`accessors.go`）是只读快照

**判断**：真实空白，分析准确。

---

### ④ SMTP 内置实现 — ✅ 前提正确，真实空白

验证结果：

- `shared/spi/password_reset.go` 定义了 `PasswordResetSender` 接口
- 全代码库无 `defaultimpl/smtp/` 或任何 `net/smtp` 使用
- `domains/anomaly/sink.go` 中 "SMTP" 仅出现在注释中描述"可选的 fan-out 目标"

**判断**：真实空白。嵌入者必须自行实现 `PasswordResetSender`，二进制部署的 `sso-server` 开箱不可用密码重置邮件功能。

---

## 修正后的优先级建议

| # | 方向 | 状态 | 真实工作量 |
|---|---|---|---|
| ① | Grace 窗口默认值/文档 | **已完成，仅改默认值** | XS（~20行） |
| ② | 认证事件发布体系 | 真实空白 | M |
| ③ | 配置热重载 | 真实空白 | L |
| ④ | SMTP 内置实现 | 真实空白 | S（~200行） |
| ⑤ | 审计对象存储归档 Sink | **Webhook 已有**，仅需 S3 sink | S-M（~150行） |

建议执行顺序：**① → ④ → ② → ⑤ → ③**，其中 ① 几乎零成本但立即消除多副本部署的隐性陷阱。
