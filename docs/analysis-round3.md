# 功能扩展方向分析 —— 第三轮

> 日期：2026-06-29
> 扫描范围：刷新令牌并发安全、认证事件流、配置热重载、SMTP 实现、审计导出
> 视角：运维/合规/规模化

---

## 方向一：刷新令牌 Grace 窗口在集群部署下不可靠

**代码验证：**

刷新令牌旋转流程是项目中最复杂的并发流程之一：

1. `Consume()` 以 `DELETE RETURNING` 原子消耗旧令牌（单用）
2. 检查家族复用（`DeleteFamily`）
3. 旋转：签发新令牌到同一家族
4. Grace 窗口：缓存返回的响应，让并发二次提交返回同一响应

**关键发现：**

`RefreshGraceStore` 只有两个后端：
- **进程内内存**（`internal/handler/tokengrant/refresh_grace.go`）— `RefreshGraceCache`
- **Redis**（`infrastructure/redis/refresh_grace.go`）— `RefreshGraceStore`

**缺失：**
- **SQLite 无 RefreshGraceStore**：`infrastructure/defaultimpl/sqlite/refresh_tokens.go` 和 `refresh_tokens_schema.go` 均无 Grace 窗口相关代码
- **Memory 后端无跨副本 Grace 窗口**：`memorystoreoauth/memory_refresh_token.go` 无 Grace 窗口概念

**具体攻击面：**

多副本部署（Tier A 模式，2 副本 + SQLite，无 Redis）：
1. 副本 A 处理令牌旋转 → `Consume` 成功 → `Remember` 缓存在副本 A
2. 响应 200 但网络丢包 → RP 重试
3. 请求落在副本 B → 副本 B 无 Grace 窗口缓存
4. `Consume` 失败（已被消费）→ `DeleteFamily`
5. **用户被登出**

**为什么值得做：**
这是多副本部署下每次滚动都会撞到的问题。Grace 窗口的**设计意图**是防止此场景，但它的实现**默认不生效**在 SQLite 和 Memory 后端。而文档（`deployment.md §6b`）说 Tier A 是合理部署模式。

**建议修复（~100 行）：**
- 为 SQLite 后端实现 `RefreshGraceStore`（一个表：consumed_token_hash TEXT, successor_response BLOB, expires_at TIMESTAMP）
- 定期清理过期条目
- 文档化 multi-replica + SQLite 的 Grace 窗口覆盖

---

## 方向二：认证事件发布体系

**代码验证：**

登录成功后（`interfaces/sso/server_finish_login.go`）：
- 记录审计事件（`eventLogin`）
- +1 指标计数器
- 签发 token
- **无任何结构化事件推送到外部系统**

**已具备的可复用基础设施：**

| 组件 | 位置 | 用途 |
|------|------|------|
| `audit.Event` | `platform/audit/` | 结构化事件类型：`Type, Outcome, ActorID, Metadata` |
| `cluster.Bus` | `platform/cluster/` | 跨副本发布/订阅 `Publish` / `Subscribe` |
| CAEP broadcaster | `protocols/caep/broadcaster.go` | 对外 push webhook，完整重试/超时/审计 |
| `audit.Sink` | `platform/audit/` | 插入式 sink 链 |

**三个组件无人组装成"登录事件流"。**

**具体场景：**
1. "当用户从新地理位置登录时发送 Slack 通知"
2. "当管理员登录时通知安全团队"
3. SIEM 集成：认证事件推送到 Splunk/Datadog
4. 事件驱动架构：登录成功触发下游工作流

**边界情况：**
- 事件流必须 fail-open（不阻塞登录路径）
- 速率控制：不能在高频登录时冲垮下游
- Payload 隐私：不泄露密码 hash 或 secret
- 重试/背压：webhook 不可达时的事件重试

---

## 方向三：运行时配置热重载

**代码验证：**
- `config/config_load.go`：file → env → etcd → flags，仅在启动时解析一次
- etcd source 支持启动后拉新值，但**没有 `config.Watcher`** 监听变化推送到 `*Server`
- `*Server` 的 `Xxx()` 访问器是只读的（`accessors.go`）

**已具备的原语：**
- `config/etcd/source.go`：`clientv3.NewWatcher` 订阅 etcd 变化
- `platform/signingkeys/` 的"监听 + 自愈 + readiness"模式可复用

**具体高价值热更新项：**

| 配置项 | 热更新意义 |
|--------|-----------|
| `security.rate_limit.default_per_sec` | 遭遇 DDoS 时实时降低，不重启 |
| 认证器 `password.enabled: false → true` | 紧急禁用某个认证方式 |
| `dpop.proof_max_age` | 放宽/收紧 DPoP 时间窗口 |
| `audit.retention.max_age` | 合规要求的实时调整 |
| `identity.client_cache.ttl` | 调整缓存粒度 |
| 日志级别 `debug / info` | 排障时实时打开调试日志 |

**架构设计：**
```
etcd Watcher → ConfigDelta (diff 计算)
               ↓
  可热更新字段 → *Server.ApplyDelta()
               ↓
  不可热更新字段 → log + 提醒重启
```

---

## 方向四：配置化 SMTP 集成 — 密码重置/邮件验证无内置实现

**代码验证：**
```go
// interfaces/sso/options_passwd.go:37
func WithPasswordResetSender(sender spi.PasswordResetSender) Option
```
`spi.PasswordResetSender` 的接口：`Send(ctx, email, token string) error`

**无内置 SMTP 实现。** 没有 `defaultimpl/smtp/` 或任何发送器的内置后端。

意味着**二进制部署的 `sso-server` 不能直接发送邮件**——密码重置、邮箱验证都不可用除非嵌入者提供 SPI 实现。

**对比：**
- 内置 SQLite + Memory 后端覆盖了几乎所有协议路径
- 但密码重置在实际部署中需要邮件发送
- `sso-ctl import` 导入用户后不能自动发送邀请邮件

**建议：**
`defaultimpl/smtp/` ~200 行：`net/smtp` 基础 + STARTTLS + HTML template。配置路径：`email.smtp.host/port/from/tls/template`。

---

## 方向五：审计日志结构化导出 — 无可配置的 SIEM/对象存储下行

**代码验证：**
- `audit.Sink` 实现：memory、sqlite、async、multi、retrying、writer
- **无 S3/GCS/Azure Blob 导出器**
- **无 syslog/Elasticsearch/Loki 发送器**
- **无 webhook 导出器**
- 日志（`slogLogger`）只写 stdout

**当前审计日志唯一获取途径：**
1. 直接查 SQLite 文件（停机后查）
2. 通过 admin REST API `/api/v1/audit/events*` 拉取

**为什么值得做：**
1. **合规驱动**：SOC2/PCI/GDPR 要求审计日志自动流向不可变存储
2. **规模化**：SQLite 在 50-100GB+ 后查询变慢
3. **可观测**：Loki/Elasticsearch 中可视化审计事件、报警规则

**建议设计：**
```
audit.Event → MultiSink ─┬─ SQLite（主存储）
                          ├─ S3 Sink（合规归档，JSONL 格式）
                          ├─ Webhook Sink（SIEM 接收器）
                          └─ Fluentd/Loki（可观测）
```

复用 `audit.Sink` 接口，新增约 150 行即可完成一个后端。

---

## 优先级排序

| 方向 | 价值 | 工作量 | 建议顺序 |
|------|------|--------|----------|
| **① Grace 窗口跨副本** | 高（多副本高发） | S | **最先** |
| **② 认证事件发布** | 高（SIEM/集成刚需） | M | 第 2 |
| **③ 配置热重载** | 中-高（运维韧性） | L | 第 3 |
| **④ SMTP 内置实现** | 中（开箱即用） | S | 可并行 |
| **⑤ 审计日志导出** | 中（合规规模化） | M | 第 4 |

**一句话：** ① 是小修复解决多副本刷新令牌的双提交风暴（每个多副本部署都会撞到）→ ② 是为 sso-server 添加与外部世界通信的第一条桥梁（SIEM/风控/webhook）→ ③ 使 etcd 配置热更新生效 → ④ 补最后一个"不能开箱即用"的能力缺口 → ⑤ 满足合规自动归档要求。
