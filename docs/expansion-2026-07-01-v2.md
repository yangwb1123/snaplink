# 架构级扩展方向分析报告（卷二）

> 基于 2026-07-01 对全代码库的全面复扫。  
> 分析视角：资深架构师 / 产品经理。  
> 定位：**此前的 ROADMAP v5.0、22 轮分析、06-30 扩展方向分析、以及 07-01 卷一（expansion-2026-07-01.md）均未覆盖的新方向**。  
> 侧重：**实时基础设施、企业安全治理、运行时运维、部署模型、测试工程**。  
> 原则：不写代码，只分析。每条经对抗式 grep + 代码交叉验证。

---

## 总体判断

项目已经达到极高的成熟度：

| 维度 | 状态 |
|------|------|
| 协议覆盖 | 30+ RFC，极为全面 |
| 企业联邦 | SAML/SPIFFE/OIDC Fed/LDAP/Kerberos/RADIUS/CAEP |
| 存储后盾 | memory + SQLite + Redis + Postgres + etcd 全面覆盖 |
| 运维操作面 | admin gRPC/REST API + sso-ctl CLI + 托管管理 SPA |
| 安全工程 | 抗枚举、Oracle-leak、常量时间、fuzz 测试、正式安全策略 |
| 可观测性 | Prometheus 指标 + OTLP tracing + 审计哈希链 + Grafana 仪表盘 |
| CI/CD | 多模块 lint/build/test + codeql + trivy + govulncheck + dependabot |
| 测试 | 130+ 端到端集成测试 + 7 个 fuzz 目标 + 4 个 benchmark + rootcov 全路径覆盖 |

以下 5 个方向是**此前所有分析的空白**。

---

## 方向一：实时事件推送基础设施（SSE + Webhook 出站）

### 为什么需要

当前架构中，所有事件流动方向是**内向的**：

```
audit.Recorder → Sink (sqlite/file/network)   [异步注入, 不出站]
cluster.Bus → 同一集群内的副本                           [副本间, 无外部订阅]
CAEP/SSF → 配置的 RP webhook 端点                               [仅外推到 RP]
```

但对于运营场景，缺少一个**开放给 Admin Console / 监控系统 / SIEM 的实时事件出口**：

| 场景 | 当前方案 | 问题 |
|------|----------|------|
| Admin Console 审计面板 | 轮询 `GET /api/v1/audit/events` | 延迟 30-60s，高 QPS 下轮询压力大 |
| 运维监控实时告警 | 无——事件是异步写入，无实时流出 | 无法在事件发生瞬间触发 webhook 通知 |
| 跨集群事件同步 | 无——`cluster.Bus` 是单 etcd 集群内的 | 多集群部署无法实时同步租户暂停/撤销 |
| 集成方事件驱动 | 无——外部系统只能轮询 | webhook 驱动集成（Zapier, PagerDuty）不存在 |

**技术选型**：SSE（Server-Sent Events）> WebSocket

| 理由 | 说明 |
|------|------|
| 单向推送符合场景 | Admin Console 只需接收事件，极少需要客户端→服务器实时 |
| 浏览器原生支持 | `EventSource` API 零依赖，天然穿越 HTTP 代理和负载均衡器 |
| 自动重连 | SSE 规范内建断线重连 + `Last-Event-ID` |
| 简单 | 不需要 WebSocket 升级握手、帧协议、心跳保活 |
| 可与现有 Echo/Gin 栈集成 | 标准的 `Content-Type: text/event-stream` 响应 |

### 范围

1. **事件流 API 端点**（~120 行）：`GET /api/v1/admin/events/stream` —— 返回 `text/event-stream`，Admin Console 用 `EventSource` 消费。过滤器：`?event_types=...&tenant_id=...&since=...`。
   ```
   event: client_registered
   data: {"client_id":"abc","actor":"admin@org","at":"..."}
   
   event: session_revoked
   data: {"session_id":"...","reason":"admin","tenant":"..."}
   ```

2. **SSE 代理 / 扇出**（~100 行）：`sse.Broker` —— 通过 Go channel（缓冲 + 背压感知）扇出到 N 个活跃 SSE 连接。慢消费者自动断开（`WriteTimeout`）。

3. **事件源接入**（~60 行）：在 `audit.Recorder` 或 `cluster.Bus` 订阅者后添加 `sse.Broker.Publish`。高基数事件（如 `client_access`）可选过滤。

4. **Webhook 出站预配置**（~80 行）：`POST /api/v1/admin/webhooks` —— 注册一个 URL 接收指定事件类型的 JSON POST。复用现有的 CAEP webhook 重试/退避设施。

5. **Admin Console 消费端**（JS ~80 行）：Admin Console SPA 的 `EventSource` 连接，实时更新审计面板和事件通知（无需轮询）。

### 关键设计约束

- **鉴权**：SSE 端点需要 `admin:read.audit` scope。初始连接时验证 bearer token，之后在事件流中定期验证（或使用短期 token + `Last-Event-ID` 重连）
- **背压**：慢消费者不阻塞其他消费者。可配置 `MaxSubscribers` 和 `BufferSize`
- **幂等性**：事件是 at-least-once（重连后从 `Last-Event-ID` 继续）。消费方应幂等处理
- **敏感事件**：`client_secret`、`token` 等敏感数据绝不包含在事件体中。事件携带引用的 `id`，详情通过 admin API 获取
- **与 CAEP 的关系**：CAEP 向外推送给受影响的 RP，SSE/webhook 向内推送给运营者。两者互补

### 工作量价值评估

- **工作量**：M（~300 行 Go + ~80 行 JS）
- **价值**：高
- **依赖**：Admin Console SPA 已存在（`web/admin/index.html`），`audit.Recorder` 已存在
- **竞品差距**：Auth0/Okta 提供管理审计日志流 API，但在线流式推送是付费功能

---

## 方向二：企业支持组管理——Break-Glass 管理会话与操作审计

### 为什么需要

**定义**：Break-Glass（紧急破窗）模式允许授权的支持人员在受控、可审计的方式下代表最终用户操作。这是 SOC 2 CC6.1/CC6.2、PCI DSS 7.2、HIPAA §164.312(a) 的合规要求。

**当前状态**：管理员可以：
- 通过 `admin:read` / `admin:write` scope 管理租户、client、用户
- 通过 `POST /api/v1/admin/tokens/revoke` 撤销用户 token
- 通过 SCIM 管理用户属性

但**不能**：
- 以用户身份登录（模拟用户会话）来排查用户反馈的问题
- 在受限窗口内（"接下来 15 分钟，支持 alice 做一次密码重置"）代表用户操作
- 在审计日志中区分"管理员自身操作" vs "管理员代表用户的操作"
- 对支持组设置"先审批后执行"的变更策略

### 范围

1. **Break-Glass Session SPI**（`shared/core/` —— ~60 行）：新类型 `AdminSession`，包含 `AdminID`、`TargetUserID`、`Reason`、`ExpiresAt`、`Scope`（readonly / full）、`ApprovedBy`。

   ```go
   type AdminSession struct {
       ID           string
       AdminUserID  string
       TargetUserID string
       TenantID     string
       Reason       string       // ticket/incident reference
       Scope        AdminScope   // readonly | impersonate | escalate
       ExpiresAt    time.Time
       CreatedAt    time.Time
       ApprovedBy   string       // empty if self-approved
       AuditID      string       // link to approval audit event
   }
   ```

2. **Break-Glass 管理端点**（`grpcserver/` —— ~200 行）：

   | 操作 | 端点 | 鉴权 |
   |------|------|------|
   | 创建模拟会话 | `POST /api/v1/admin/break-glass` | `admin:write.break-glass` + 理由 |
   | 列出活跃模拟会话 | `GET /api/v1/admin/break-glass` | `admin:read.break-glass` |
   | 撤销模拟会话 | `DELETE /api/v1/admin/break-glass/{id}` | `admin:write.break-glass` |
   | 审批待定会话 | `POST /api/v1/admin/break-glass/{id}/approve` | `admin:write.break-glass.approve` |

3. **审计富化**（`audit/event.go` —— ~40 行）：所有在 break-glass 会话中发出的操作在审计事件中携带 `{ admin_id, target_user_id, admin_session_id, break_glass_reason }` metadata。这是 SOC 2 审核员查找"谁在何时因何故以谁的身份做了什么"的关键证据链。

4. **控制措施**：
   - 每次 break-glass CREATE 发出 `admin_break_glass_created` 审计事件（SOC 2 CC6.1）
   - 可选二次审批流（先创建 PENDING 状态，另一管理员批准后才生效）
   - 会话 TTL（默认 15 分钟，最长 1 小时，到期自动撤销所有衍生 session/token）
   - 时间窗口外不得创建（可配置：仅 09:00-17:00 工作时间内允许，紧急 override 需额外批准）

### 关键设计约束

- **最小权限**：break-glass session 自动获得 `Scope: readonly`，仅在需要（`escalate`）时升级为 impersonate
- **全审计**：break-glass 不对用户可见（不会在用户会话列表/审计中暴露"管理员模拟了你"），但管理员审计日志完整记录
- **自动过期**：session 到期后，任何使用该 session 颁发的 token 或 session cookie 立即失效
- **与已有 SessionManager 的关系**：break-glass session 创建时，为管理员签发出一个**标记的 session**（`type=admin_impersonation`），该 session 在目标用户的 API 调用中作为 bearer 使用
- **非绕开**：break-glass 不绕过 scope/resource 检查——目标用户的权限边界仍然适用

### 工作量价值评估

- **工作量**：M（~300 行 + 测试）
- **价值**：高（SOC 2 / PCI / HIPAA 合规刚需，企业采购安全问卷必问项）
- **依赖**：现有 admin permission scope 系统已就位，`SessionManager` 已就位，`audit.Recorder` 已就位

---

## 方向三：运行时配置审计与漂移检测

### 为什么需要

当前配置管线为：

```
YAML 文件 + 环境变量 + etcd + flags → deepMerge → validate → *Config
```

配置生命周期在启动时结束。**一旦服务器运行**：

| 场景 | 当前行为 | 问题 |
|------|----------|------|
| 操作员通过 admin API 修改了 client 配置 | 直接应用，无 old-vs-new 对比 | 回滚需要手动恢复旧值 |
| 有人手动修改了 YAML 配置文件 | 服务器无感知 | 下次重启才生效，期间运行配置 ≠ 文件配置 |
| CI 部署了新配置 | 服务器重启 | 无法确认哪些配置项实际变更了 |
| 审计被问到"此 tenant 的 rate_limit 在过去 7 天被修改了几次" | 无版本历史 | 合规审核无法回答 |
| 多副本集群 | 每个副本从相同配置源加载 | 副本间配置漂移无声 |

**当前已有的基础设施**：
- `cluster.Kind*Change` 总线事件（`client_change`、`connection_change`、`authz_policy_change`）
- `sso-ctl config validate`（离线验证）
- 深度合并管线 + `DisallowUnknownField` 检查

**缺少的**：运行时配置的版本化、审计、漂移检测。

### 范围

1. **运行时配置快照 API**（`interfaces/sso/` —— ~80 行）：
   - `GET /api/v1/admin/config/running` —— 返回当前运行配置的 JSON 快照
   - `GET /api/v1/admin/config/applied` —— 返回上次启动时加载的配置（与 running 对比可发现 drift）
   - `GET /api/v1/admin/config/diff` —— 返回 running 与 applied 的 JSON Patch 差异

2. **配置变更审计**（`config/source.go` 扩展 —— ~40 行）：每次 admin API 调用 `POST /api/v1/admin/clients` 等修改运行时状态时，在审计事件中包含 `{ config_diff: json.RawMessage, config_version: int }`。使用标准的 RFC 6902 JSON Patch 格式。

3. **配置版本历史**（`platform/configaudit/` —— ~150 行）：一个新的轻量级包，存储每次配置变更的 JSON Patch + 时间戳 + 操作者。后端可以是 sqlite/内存（复用 `audit` 的保留/清理机制）。

   ```
   TABLE config_history (
     id         INTEGER PRIMARY KEY,
     recorded_at TEXT NOT NULL DEFAULT (datetime('now')),
     actor      TEXT NOT NULL,         -- admin subject id
     tenant_id  TEXT,
     resource   TEXT NOT NULL,         -- "client" / "tenant" / "policy"
     resource_id TEXT NOT NULL,
     patch      TEXT NOT NULL,         -- RFC 6902 JSON Patch
     prev_hash  TEXT,                  -- optional hash chain for integrity
     reason     TEXT                   -- optional operator-supplied reason
   );
   ```

4. **漂移检测**（`cmd/sso-ctl/` 或运行时 goroutine —— ~60 行）：后台 goroutine（或 `sso-ctl config drift` 离线命令）定期比较：
   - running 配置 vs 启动时配置（文件漂移）
   - 本副本配置 vs 同集群其他副本（跨副本漂移，通过 `cluster.Bus` 广播配置摘要）

5. **配置变更通知**（~40 行）：配置版本变更时通过 cluster.Bus 广播 `KindConfigChange`，各副本可选择重新加载或记录不一致。

### 关键设计约束

- **不存储敏感字段**：config patch 中的 `secret`、`password`、`dsn` 字段自动替换为 `"***"`（复用 `audit.Redactor` 模式）
- **保留策略**：config_history 复用现有 `audit.retention` 配置
- **与集群已存在的 `Kind*Change` 的关系**：互补而非替代。`KindClientChange` 是运行时状态失效，config_history 是配置变更的持久化审计记录
- **性能**：config_history 写入频率低（与 admin API 调用频率相同），无性能关注点

### 工作量价值评估

- **工作量**：M（~300 行 Go + 测试）
- **价值**：中-高（SOC 2 CC7.1 变更管理 + 运维排障）
- **独特性**：Keycloak 和 Ory Hydra 没有这项能力，是差异化点

---

## 方向四：资源服务器（RS）令牌验证与授权 SDK

### 为什么需要

项目作为授权服务器（AS）功能极全。但**资源服务器侧**（RS —— 验证 token、执行授权决策的一方）的工具链明显薄弱：

| 能力 | AS 侧（本项目） | RS 侧（ssoclient/remote） |
|------|----------------|--------------------------|
| Token 验证 | 完整（alg 白名单 + typ + exp + nbf + jti + cnf） | 基础（`ValidateCompactJWS` + JWKS 缓存） |
| DPoP 验证 | 完整（nonce + jti + htm/htu + thumbprint） | 无 |
| mTLS 绑定验证 | 完整（x5t#S256） | 无 |
| 授权决策 | `Authorizer.Check` + `permissions.Provider` | 无（仅验证 token，不检查 scope/permission） |
| 令牌自省 | `POST /introspect`（RFC 7662） | 简单（解析 JWT claim，无回源验证） |
| 缓存 & 性能 | JWKS single-flight + ETag + jitter TTL | 基本（5 分钟最小刷新间隔） |
| 错误处理 | `setBearerChallenge` + 标准 error code | 基础错误类型 |
| 可观测 | token 签发/验证/失败指标全 | 无指标、无 trace |

**业务影响**：消费本 SSO 签发 token 的微服务需要自己从头实现：
1. JWKS 获取 + 缓存 + 轮换（复用 `remote/jwks.go` 但需要额外代码）
2. DPoP proof 验证（完全没有提供 RS 侧实现）
3. mTLS client cert 绑定验证（没有提供 RS 侧实现）
4. `permissions.Check` 集成（没有 RS 侧 SDK）
5. Token 自省（`introspect` 端点存在但 RS 侧 SDK 没有封装）

这导致：
- 每个集成方重复实现同样的验证逻辑
- 错误实现导致安全缺口（如缺少 DPoP 验证、使用未缓存的 JWKS）
- 无法快速采用 RFC 9068 的 `token_type` 指示器

### 范围

1. **RS 验证库**（`ssoclient/rs/` —— ~200 行）：一把完整的 token 验证函数：

   ```go
   package rs
   
   type Config struct {
       Issuer          string          // 必填：验证 iss claim
       JWKSCache       *JWKSCache      // 可选：JWKS 缓存（默认构建一个）
       AllowedAlgs     []string        // 可选：alg 白名单（默认 AsymmetricJWSAlgs）
       ExpectedAud     string          // 可选：验证 aud claim
       DPoPVerifier    *DPoPVerifier   // 可选：DPoP proof 验证
       MaxClockSkew    time.Duration   // 可选：时钟偏斜（默认 30s）
       IntrospectURL   string          // 可选：回源自省端点（替代本地 JWT 验证）
       IntrospectCreds *ClientCreds    // 可选：自省端点客户端凭据
   }
   
   func ValidateToken(ctx context.Context, token string, cfg Config) (*Claims, error)
   func ValidateTokenWithDPoP(ctx context.Context, token, dpopProof, htm, htu string, cfg Config) (*Claims, error)
   func ValidateTokenWithIntrospect(ctx context.Context, token string, cfg Config) (*Claims, error)
   ```

2. **JWKS 缓存改进**（`ssoclient/remote/jwks.go` —— ~40 行）：增加 ETag 支持（`If-None-Match` 304 跳过重新下载）、增加后台轮换 goroutine（`StartRefresher`）、增加抖动 TTL。

3. **DPoP 验证辅助**（`ssoclient/rs/dpop.go` —— ~60 行）：RS 侧验证 DPoP proof（复用 `security/jwk_thumbprint.go` 中的 JWK thumbprint 计算）。

4. **授权决策辅助**（`ssoclient/rs/authz.go` —— ~40 行）：`CheckScope`、`CheckPermission`、`assertAuthorized` 等辅助函数，封装标准的 `Authorizer` 调用。

5. **中间件集成**（`ssoclient/rs/middleware.go` —— ~80 行）：为常见框架（net/http、Echo、Gin）提供现成的中间件包装器：

   ```go
   // Example: Echo middleware
   func EchoMiddleware(cfg Config) echo.MiddlewareFunc
   
   // Example: net/http middleware  
   func HTTPMiddleware(cfg Config, next http.Handler) http.Handler
   ```

6. **测试夹具**（`ssoclient/rs/rstest/` —— ~60 行）：`NewTokenIssuer` —— 测试用的最小 token 签发器（复用 `defaultimpl/ed25519_jwt_issuer.go`），无需启动整个服务器。

### 关键设计约束

- **零依赖 minimal**：RS SDK 应最小化依赖（仅 `go-jose` + net/http，无 gRPC、无 Prometheus）
- **无状态可选**：支持"直连 AS 做自省"和"本地 JWT 验签"两种模式。本地模式无需 AS 在线
- **缓存友好**：JWKS 缓存使用 `sync.Map` + jitter TTL（参考 `accessors.go:226`），不引入 Redis/外部缓存依赖
- **错误分类**：`ErrTokenExpired`、`ErrTokenMalformed`、`ErrDPoPInvalid` 等标准错误类型
- **导出为独立子模块**：使用 `infrastructure/kms/` 相同的嵌套模块模式，避免向核心 go.mod 引入额外依赖

### 工作量价值评估

- **工作量**：L（~500 行 + 测试 + 示例文档）
- **价值**：高（"完整的身份平台"和"好用的身份平台"的分水岭）
- **竞品差距**：Auth0 有 `express-oauth2-jwt-bearer`（Node.js）、Keycloak 有 `keycloak-js`（浏览器）、Ory 有 ORY SDK（多语言）。本项目缺少官方 RS 侧 SDK
- **依赖**：`ssoclient/remote` 已存在可作为基础

---

## 方向五：混沌工程与确定性测试设施

### 为什么需要

项目的测试工程非常健全：130+ 集成测试（`test/`）、fuzz 测试（7 目标）、benchmark（4 包）、rootcov 全路径覆盖。但缺少两个关键薄弱环节测试：

| 薄弱环节 | 当前覆盖 | 风险 |
|----------|----------|------|
| 网络分区 / 后端故障 | 个别测试有 `erroring*Store` 故障注入，但无系统性分区测试 | etcd 分区时新副本无法采纳对端公钥的静默 bug（已在 ROADMAP v5.0 §④ 描述） |
| 并发竞态 | race detector 在 CI 中运行，但未用 `-count=10` + `-race` 组合 | 稀有的 time-of-use/time-of-check 类 bug |
| 配置边缘情况 | 空白配置 / 部分配置 / 非法值未系统性测试 | 启动时 panic 或静默降级 |
| 存储后盾语义一致性 | memory/sqlite/redis/postgres 未测试语义等价性 | 行为差异在切换后端时悄然出现 |

混沌工程的目标不是"测试所有故障路径"（太多），而是**测试已知的、高影响的故障模式**。

### 范围

1. **故障注入测试套件**（`test/chaos/` —— ~300 行 `package chaostest`）：

   | 故障模式 | 注入点 | 验证 |
   |----------|--------|------|
   | etcd 不可达 | `signingkeys/etcd` 的 lease KeepAlive 返回错误 | 验证聚合循环 degrade + readiness 503 + 重新连接 |
   | SQLite 写入锁定 | `sqlite/*` 的模拟 `database is locked` 错误 | 验证退避重试逻辑（`build_stores.go` 已有重试） |
   | Redis 超时 | `infrastructure/redis/*` 模拟超时 | 验证 fail-open/fail-closed 正确切换 |
   | 时钟跳跃 | token issuer 中的 `time.Now()` 可重写 | 验证 JWT iat/nbf/exp 的正确性 |
   | 内存 OOM | `memory/*` 返回 `ErrOutOfMemory` | 验证降级路径 |
   | 恐慌恢复 | 处理程序中注入 panic | 验证 `recover()` 中间件 + 审计事件 |
   | 配置丢失 | 启动时删除 `config.yaml` | 验证默认值 + 错误消息 |
   | 并发现象测试 | `-count=10 -race` | 验证无数据竞争 |

2. **实现策略**——函数级 seam（非接口 mock）：

   ```go
   // Fault injection via seam — no interface mock needed
   type Clock interface {
       Now() time.Time
   }
   
   type faultClock struct {
       Clock
       jump func() time.Time  // injectable: nil = normal, non-nil = fault
   }
   ```

   关键点：使用与"注入可替换时间源"相同的模式（已有 `HandlerContext` 携带 `time.Now`），**不引入新的 mock 框架**。

3. **后端语义一致性测试**（`test/backendsemantics/` —— ~200 行）：

   验证同一个 SPI（如 `AuthCodeStore`、`JTIReplayStore`、`RefreshTokenStore`）的 memory、sqlite、redis 实现在关键语义上行为一致：

   - `SingleUseStore.Delete`：第二次调用返回错误（`ErrNotFound` / `ErrConsumed`）
   - `JTIReplayStore.MarkSeen` + `IsSeen`：标记后立即检查返回 true
   - `RefreshTokenStore.Consume`：成功后原 token 不可再次消费
   - 所有后端返回相同的 sentinel error（`core.ErrNotFound` vs 驱动程序特定的 `sql.ErrNoRows`）

4. **CI 集成**（~20 行 CI 配置）：`make chaos-test` 目标，仅在 `main` 分支或标签发布前运行（因为较慢）。`make backend-semantics` 在每个 PR 中运行（3-5s）。

### 关键设计约束

- **非 mock**：故障注入通过 seam 实现，而非接口 mock 替换。区分"我们替换了整个 store"（mock）和"我们在这个 seam 上注入了一次故障"（seam）
- **幂等**：每个故障测试必须能安全重跑——注入的故障不留下全局状态
- **零侵入**：故障注入代码不污染生产二进制（通过 build tag `//go:build chaos` 隔离）
- **与 fuzz 的关系**：fuzz 测试畸形输入，chaos 测试组件间故障。互补而非重叠

### 工作量价值评估

- **工作量**：L（~500 行 + 测试容器编排）
- **价值**：中-高（发现"CI 全绿但生产掉线"的静默 bug 的最佳手段）
- **依赖**：测试基础设施已极为完善
- **竞品差距**：大部分开源身份项目没有正式的混沌测试套件。此方向建立差异化信心

---

## 优先级摘要

| # | 方向 | 工作量 | 价值 | 适合时机 | 核心收益 |
|---|------|--------|------|----------|----------|
| 1 | 实时事件推送（SSE） | **M** | **高** | 立刻 | Admin Console 秒级实时审计 → 用户体验质的飞跃 |
| 2 | Break-Glass 管理会话 | **M** | **高** | 跟随方向 1 | SOC 2 CC6.1 合规刚需，企业采购必问 |
| 3 | RS Token 验证 SDK | **L** | **高** | 方向 1-2 之后 | "完整的身份平台" → "好用的身份平台" 的分水岭 |
| 4 | 配置审计与漂移检测 | **M** | **中-高** | 与方向 2 并行 | SOC 2 CC7.1 变更管理 + 运维能力 |
| 5 | 混沌工程测试设施 | **L** | **中-高** | 持续，按周填 | 发现 CI 绿但线上黑的静默 bug |

### 阶段建议

**Phase 1（本月）**：方向①（SSE 实时事件）—— 工作量最小（~300 行 Go + ~80 行 JS）、价值最高（Admin Console SEO 体验从"轮询、30s 延迟"升级到"实时"）。与现有的 `audit.Recorder` + Admin Console SPA 直接整合。

**Phase 1 并行**：方向⑤（混沌测试）—— 先做 `test/backendsemantics/`（后端语义一致性测试，~200 行），再逐步添加故障注入测试。持续进行。

**Phase 2（下月）**：方向②（Break-Glass）+ 方向④（配置审计）并行。两者都增强运营合规性，一起打包为"企业治理包"。

**Phase 3（下季度）**：方向③（RS SDK）—— 这是投入最大但回报也最大的方向。将本项目的身份平台能力"出口"为消费方 SDK，让集成方从"我们自己写验证"变成"一行 import 搞定"。

---

## 与已有分析的对比

| 本报告方向 | 与 ROADMAP v5.0 的关系 | 与我之前各文档的关系 |
|-----------|----------------------|---------------------|
| ① SSE 实时事件 | ROADMAP ①（UI/UX）侧重终端用户门户和管理面板，本方向侧重实时运维管道 | 卷一（protocol/security 方向）未覆盖 |
| ② Break-Glass | 正交——ROADMAP 侧重功能完整性和集群韧性，未涉及支持组治理 | 卷一未覆盖 |
| ③ RS SDK | ROADMAP ③（OIDC 一致性）侧重 AS 侧正确性，本方向侧重 RS 侧易用性 | 卷一方向①（JWT Bearer Grant）是协议扩展，本方向是 SDK 易用性 |
| ④ 配置审计 | ROADMAP ②④⑤ 未覆盖配置生命周期管理 | 卷一未覆盖 |
| ⑤ 混沌测试 | 不重复 ROADMAP ③⑤（OIDC 正确性 + 安全门禁）的已有测试，聚焦故障模式 | 卷一方向③（威胁模型）聚焦攻击面，本方向聚焦系统韧性 |
