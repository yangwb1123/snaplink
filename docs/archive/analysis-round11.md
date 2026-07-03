# 第 11 轮分析 — MQTT 和 WASM 集成可行性

> 扫描日期：2026-06-29
>
> 前 10 轮覆盖 50 个独立方向，包括产品、安全、运维、性能、测试、工程治理等所有维度。
>
> 本轮专门分析用户提出的两个技术栈 — **MQTT（消息队列遥测传输）** 和 **WASM（WebAssembly）** — 在 snaplink/sso 代码库中的集成点和可行性。

---

## 代码库当前状态（与 MQTT/WASM 相关）

| 维度 | 当前实现 | MQTT/WASM 切入点 |
|------|----------|------------------|
| 集群总线（`platform/cluster/`） | `memory.Bus`（进程内）+ `etcd.Bus`（etcd watch） | MQTT 作为第三种 `Bus` 实现 |
| CAEP/SSF 事件推送（`protocols/caep/`） | 每个接收者 HTTP POST（434 行 goroutine 管理） | MQTT 发布替代逐个 HTTP 推送 |
| Envoy ext_authz（`infrastructure/extauthz/`） | gRPC Check 服务 | WASM 授权过滤器可下放到 Envoy |
| 认证器（`domains/authenticators/`） | 9 种内置认证器 + WebAuthn | WASM 插件式自定义认证器 |
| MFA 推送（`domains/authenticators/push/`） | Webhook 轮询（`/auth/mfa` 轮询） | MQTT 直接推送认证请求到设备 |
| 授权策略（`domains/permissions/`） | 内置角色 + 通配符匹配器 | WASM 插件自定义策略评估 |
| 令牌吊销传播 | 集群事件 `KindTokenRevoked` + JWT 拒绝集合 | MQTT topic 实时推送到所有副本 + 资源服务器 |
| OAuth 授权类型 | 硬编码 grant_type（auth_code/refresh/client_creds/device/ciba/token_exchange） | WASM 插件实现自定义授权类型 |
| SCIM 过滤 | Go 内置过滤器 | WASM 沙盒化过滤表达式求值 |

---

## 方向一：MQTT 集群总线 — 替代 etcd 的轻量级多副本协调方案

**当前实现：**

```
platform/cluster/bus.go  — cluster.Bus 接口（Publish / Subscribe / Close）
  ├── platform/cluster/memory/bus.go  — 进程内扇出（单副本）
  └── platform/cluster/etcd/etcd.go  — etcd watch（多副本，依赖 etcd v3）
```

**Bus 接口（15 行核心契约）：**

```go
type Bus interface {
    Publish(ctx context.Context, evt Event) error  // 即发即忘
    Subscribe(ctx context.Context) (<-chan Event, error)  // 接收流
    Close() error
}
```

事件类型（当前 7 种）：`KindTenantSuspension`、`KindDiscoveryReload`、`KindAuthzPolicyChange`、`KindTenantResidency`、`KindClientChange`、`KindSigningKeyRotation`、`KindTokenRevoked`

**MQTT 作为 `platform/cluster/mqtt/bus.go` 的可行性分析：**

```
MQTT 主题映射（每个 Event.Kind 独立主题，实现 topic-per-kind 隔离）：

sso/cluster/tenant_suspension/{tenant_id}    → 租户级精确路由
sso/cluster/discovery_reload                  → 全局（Key 为空）
sso/cluster/authz_policy_change/{client_id}   → 客户级精确路由
sso/cluster/tenant_residency/{tenant_id}      → 租户级精确路由
sso/cluster/client_change/{client_id}         → 客户级精确路由
sso/cluster/signing_key_rotation              → 全局（多 kid 在 payload）
sso/cluster/token_revoked                     → 全局（token 在 payload）
```

**优势：**

| 对比项 | etcd | MQTT |
|--------|------|------|
| 外部依赖规模 | etcd 集群（至少 3 节点，Raft） | 单 MQTT broker（Mosquitto < 10MB 内存） |
| 部署复杂度 | 证书配置、集群初始成员管理、快照维护 | `apt install mosquitto` + 单向配置 |
| 消息持久化 | 租约 + 键生命周期管理 | 内置 Clean Session / Persistent Session + QoS |
| 网络断开恢复 | 客户端内置 watch 重连 | MQTT 内置自动重连 + 持久会话回放 |
| 主题过滤 | 前缀匹配（需要 `client.Get` 后缀过滤） | 原生通配符主题过滤器（`+`、`#`） |
| 资源开销 | 3 进程数百 MB | 单进程 < 50MB |
| 适用场景 | 生产大规模集群（>10 副本） | 小到中型部署、边缘部署、开发/测试 |

**架构推演：**

```go
// platform/cluster/mqtt/bus.go  — 新文件，约 200 行
package mqtt

import (
    "context"
    "github.com/eclipse/paho.golang/paho"  // MQTT v5 客户端
    "github.com/snaplink/sso/platform/cluster"
)

type Bus struct {
    cli     *paho.Client
    prefix  string  // "sso/cluster"
    qos     byte    // 默认 1（至少一次送达）
    subs    map[string]func(cluster.Event)
}

// Publish: topic = prefix + "/" + kind + "/" + key → QoS 1
// Subscribe: topic 通配符 prefix + "/#" → 收到后按 kind 分发
// Close: 断开连接 + Disconnect()
```

**风险与缓解：**

| 风险 | 缓解 |
|------|------|
| MQTT broker 单点故障 | 高可用模式、MQTT v5 共享订阅 |
| 非 etcd CRDT 保证（无 revision 排序） | Bus 契约承诺 best-effort（阅读 `bus.go` 注释），过期 TTL 兜底 |
| 消息风暴（1000 次/s 事件） | QoS 0（最多一次） + 去重合并策略 |
| 安全（broker 暴露） | TLS + 用户名/密码认证 + ACL 隔离 |

**评估：高价值，中工作量**

MQTT Bus 实现约 200 行 Go 代码，不修改任何现有事件消费代码。适合作为 `cluster.Bus` 的第三种后端，配置驱动：

```yaml
cluster:
  backend: mqtt  # memory | etcd | mqtt
  mqtt:
    broker: tcp://localhost:1883
    client_id: sso-server-1
    topic_prefix: sso/cluster
```

---

## 方向二：WASM 授权策略引擎 — 可插拔自定义授权，无需重新编译

**当前实现：**

```go
// domains/permissions/ — 内置 RBAC 系统
//   Provider 接口：Role{Code, Name, Permissions []string}
//   Matcher：通配符匹配（"user:*" ⊇ "user:read"）
//   Export：导出策略束 JSON

// infrastructure/extauthz/ — Envoy ext_authz 网关集成
//   AuthorizationServer.Check()  →  mesh_authz.MeshAuthorize()
//   决策固定：Bearer token → 用户 → 角色 → 权限比较
```

**WASM 授权引擎架构：**

```
请求 → 认证 → WASM 授权模块（sandbox）
                   │
         [wazero 运行时代理]
                   │
           用户自定义逻辑
        (Go/Rust/AssemblyScript → WASM)
```

**在代码库中的集成点：**

```
interfaces/sso/mesh_authz.go:  // HTTP 模式 ext_authz 端点
    → 在 perm 检查前插入 WASM 授权钩子
    → 可自定义拒绝消息、审计标签、降级策略

infrastructure/extauthz/authz.go:  // gRPC 模式 Envoy ext_authz
    → AuthorizationServer.Check() 可以调用 WASM 模块
    → 响应 OkHttpResponse / DeniedHttpResponse

domains/permissions/:
    → Provider 接口 + Export（策略束导出）
    → WASM 作为 Export 的自定义转换后端
    → "策略 → WASM 二进制" 编译流水线
```

**具体实现方案：**

```go
// 新增：domains/authzwasm/ 包
package authzwasm

import (
    "context"
    "github.com/tetratelabs/wazero"
    "github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// ModulerLoader 加载 WASM 字节码（从文件系统、HTTP、嵌入二进制）
type ModuleLoader interface {
    Load(ctx context.Context, name string) ([]byte, error)
}

// Evaluator 包装单个 WASM 模块的调用
type Evaluator struct {
    runtime wazero.Runtime
    module  wazero.CompiledModule
}

// Authorize 调用 WASM 模块的 authorize 函数
// 输入：context（包含 subject + resource + action）
// 输出：decision（allow/deny）+ 元数据
func (e *Evaluator) Authorize(ctx context.Context, req AuthorizationRequest) (*AuthorizationResult, error)
```

**四种可用模式（按风险升序）：**

| 模式 | 事务隔离 | 性能 | 适用场景 |
|------|----------|------|----------|
| ① WASM 后决断（Post-decision hook） | 无 | 纳秒级 | 审计标签、自定义元数据、日志 |
| ② WASM 并行决断（Parallel check） | 只读 | 微秒级 | 自定义白名单、租户特定规则 |
| ③ WASM 主决断（Primary decision） | 关键路径 | 微秒级 | 完全自定义授权逻辑 |
| ④ WASM 降级引擎（Degradation） | 安全降级 | 毫秒级 | 第三方或客户自写策略 |

**推荐集成路径（从轻到重）：**

1. **Phase 1**：在 `domains/permissions/` 中添加 WASM 过滤器钩子
   - `Provider 接口` 新增可选的 `WASMFilter(ctx, subject, action)` 方法
   - 默认 nil（当前行为不变）
   - wazero 运行的 WASM 模块传入请求上下文，返回 allow/deny
   - 模块来源：配置指定 `.wasm` 文件路径

2. **Phase 2**：构建 `sso-ctl policy compile` CLI
   - 从 YAML/JSON 策略定义 → WASM 二进制
   - 支持策略热重载（监控文件变化 → 重新编译/加载）
   - 与现有 `bundle export` 集成

3. **Phase 3**：Envoy ext_authz 中的 WASM 集成
   - Envoy 本身就支持 WASM 过滤器（`envoy.wasm.vm`）
   - 同一 WASM 二进制可以：
     - 在 SSO 服务器内运行（通过 wazero）
     - 在 Envoy 边车中运行（通过 `envoy.filters.http.wasm`）
   - 实现策略一次编写，两地运行

**性能基准（wazero 参考）：**

| 操作 | 耗时 |
|------|------|
| 编译 WASM 模块（首次加载） | ~50-200µs |
| WASM 函数调用（预热后） | ~0.5-2µs |
| 传递 1KB 输入/输出 | ~1-5µs |

对比 Go 原生函数调用（~3-10ns）慢约 100-500 倍，但对于一次授权检查（通常 100µs-5ms 范围），WASM 的 2µs 开销是完全可以接受的。

**评估：中-高价值，中-大工作量**（Phase 1 约 200 行，Phase 3 约 500 行）

WASM 策略引擎最大的价值在于**与 Envoy 共享同一套策略逻辑** — SSO 服务器内和 Envoy 边车中运行相同的 `.wasm` 二进制，消除策略漂移。

---

## 方向三：MQTT 替代 CAEP/SSF HTTP 单点推送 — 消除 goroutine 池和超时管理

**当前实现（`protocols/caep/broadcaster.go:434` 行）：**

```go
// 每个接收者一个 goroutine + context.WithTimeout
t.wg.Add(1)
go t.deliver(c.ID, endpoint, auth, req)

// deliver 内部的 go func（430-600 行）：
//   1. mintSET — 签名 SET JWT
//   2. http.Post — 发送到接收者端点
//   3. 失败处理 — 指标 + 审计事件 + 日志
//   4. recover() — panic 保护
//   5. io.CopyN — 响应体排空以复用连接
```

**问题：**
- N 个接收者 → N 个非受管 goroutine（每个最多等待 10s 超时）
- HTTP 重定向安全关闭（`CheckRedirect: ErrUseLastResponse`）
- 接收者端点必须是 HTTPS（SSRF 防护），限制部署场景
- 失败时无重试（best-effort 契约），丢失事件

**MQTT 推送架构：**

```
CAEP Transmitter (Broadcaster)
    │
    ├── HTTP 模式（当前，保留）：逐接收者 POST
    │     └── 用于传统 HTTPS 接收者（外网 RP）
    │
    └── MQTT 模式（新增）：发布到 SSo 主题
          ├── sso/caep/client/{client_id}     ← 单客户事件
          ├── sso/caep/tenant/{tenant_id}      ← 租户范围事件
          └── sso/caep/global                  ← 全局事件

MQTT Broker
    │
    ├── 接收者 A（MQTT 客户端订阅 sso/caep/client/A）
    ├── 接收者 B（MQTT 客户端订阅 sso/caep/client/B）
    └── 接收者 C（MQTT 客户端订阅 sso/caep/client/C）

接收者侧（受管 by snaplink agent 或直接 MQTT 客户端库）：
    1. 接收 SET（MQTT 消息 payload = compact JWS）
    2. 验证签名 + jti + iss
    3. 执行撤销
```

**对比：**

| 对比项 | HTTP POST（当前） | MQTT 发布 |
|--------|-------------------|-----------|
| 发送线程模型 | N 个 goroutine / 接收者 | 1 个 MQTT 连接 |
| 超时处理 | `context.WithTimeout(10s)` | MQTT Keep Alive（可配） |
| 重试机制 | 无（best-effort） | MQTT QoS 1/2 + 持久会话 |
| 接收者要求 | HTTPS 端点（公网可达） | MQTT broker（公网或 VPN） |
| 接收者离线 | 事件丢失 | MQTT 持久会话保留直到接收者上线 |
| 背压控制 | 无（goroutine 无限增长） | MQTT 流量控制（Receive Maximum） |
| 安全 | HTTPS + Bearer token | MQTT TLS + 用户名/密码/ACL |

**评估：中价值，小工作量**

MQTT 推送不是替换而是补充当前 HTTP 推送。对于内部的、受管接收者（同数据中心的资源服务器），MQTT 比 HTTP 更可靠（持久会话 + 离线消息保留）。外网接收者仍然使用 HTTPS。

配置形态：
```go
// Transmitter 新增 NewWithMQTT 选项：
t, err := caep.NewTransmitter(signer, clients,
    caep.WithMQTTBroker("tcp://mqtt:1883"),
    caep.WithMQTTTopicPrefix("sso/caep"),
    caep.WithHTTPFallback(true), // MQTT 不可用时回退到 HTTP
)
```

---

## 方向四：WASM 自定义认证器 — 可插拔认证逻辑，无需重新编译

**当前实现（`domains/authenticators/`）：**

```go
// Authenticator 接口：
type Authenticator interface {
    Type() core.AuthenticatorType
    Authenticate(ctx context.Context, creds core.Credential) (*core.AuthResult, error)
}
```

内置 9 种认证器：
- `password/` — bcrypt 密码验证
- `webauthn/` — FIDO2 WebAuthn（passkey）
- `totp/` — 基于时间的一次性密码
- `push/` — Webhook 推送认证
- `oidc_federation.go` — 外部 OIDC 身份提供商
- `mfa_backup_code/` - 备用码
- 等

**WASM 自定义认证器补丁点：**

```go
// 新增：domains/authenticators/wasm/wasm_authenticator.go
package wasm

type Config struct {
    ModulePath  string            // .wasm 文件路径（或嵌入式 []byte）
    Schema      map[string]string // 自定义凭证字段定义
    Timeout     time.Duration     // WASM 调用超时
    MemoryLimit uint64            // WASM 堆限制（默认 4MB）
}

type WASMAuthenticator struct {
    module   wazero.CompiledModule
    runtime  wazero.Runtime
    config   Config
}
```

**调用模式：**

```
Authenticate(ctx, creds) 被调用
    │
    ├── 1. 将 creds 序列化为 JSON（≈1KB）
    ├── 2. 调用 WASM 函数 authenticate(data []byte) -> []byte
    │     └── [wazero] 运行时在沙箱中执行
    │     └── wasi_snapshot_preview1 导入（文件系统权限可选关闭）
    ├── 3. 解析返回的 JSON 为 AuthResult
    └── 4. 如果失败，返回 core.ErrAuthenticationFailed
```

**适用场景：**

| 场景 | WASM 实现优势 |
|------|--------------|
| 企业自定义硬件 Token | 客户自写认证逻辑，不暴露私钥算法 |
| 遗留系统 LDAP/Kerberos 桥 | 沙盒化实现，即使崩溃不影响主进程 |
| 自定义 SMS/邮件 OTP | 每个地域不同的 SMS 网关实现 |
| 时间限制密码 | WASM 中实现自定义密码有效期策略 |
| 多因素评分因子 | WASM 中实现设备指纹 → 认证强度映射 |

**安全控制：**

WASM 沙箱确保：

| 风险 | wazero 防护 |
|------|-------------|
| 无限循环 | WithNanotime（主机时钟）+ Context 取消 |
| 内存泄漏 | WithMemoryLimitPages(256) = 约 4MB |
| 文件系统访问 | WASI 默认关闭，显式打开（仅指定目录） |
| 网络访问 | 无 WASI socket 导入不提供 |
| 主机 crash | WASM panic 在 Go recover 范围内 |
| 计时攻击 | 无细粒度计时器（wazero 不暴露 monotonic 计数器） |

**评估：中价值，小-中工作量**（约 250 行核心代码 + 配置集成）

WASM 认证器让 SSO 服务器在不需要重新编译的情况下支持任意自定义认证逻辑。这是第 5 轮分析中"密码策略 SPI 缺失"的更通用解 — 不仅自定义密码策略，还自定义整个认证器。

---

## 方向五：Edge 部署中的 MQTT + WASM 组合模式 — 轻量级 Edge SSO

**架构模式：**

```
[Edge / K3s / Raspberry Pi]
    │
    ├── sso-server（单副本，无 etcd 依赖）
    │     ├── cluster.Bus = mqtt（与远端副本协调）
    │     ├── MFA Push = mqtt（设备直接接收推送）
    │     └── CAEP/SSF = mqtt（内部接收者）
    │
    ├── mosquitto（MQTT broker，容器内 < 20MB）
    │
    └── WASM 模块（可选）
          ├── 离线授权策略（断网时使用 WASM 本地决策）
          ├── 自定义认证器（企业硬件 Token）
          └── Edge-specific 令牌变换逻辑
```

**为什么 Edge 场景受益最大：**

1. **无 etcd 依赖** → 单容器部署（sso-server + mosquitto，< 100MB）
2. **MQTT 同步** → 多个 Edge 节点通过 MQTT broker 同步租户状态
3. **WASM 授权** → Edge 可以运行与云端相同的授权策略 WASM 模块，断网时本地决策
4. **MFA 推送** → 边缘设备的 MFA 认证请求通过本地 MQTT broker 路由，无需公网可达

**现有部署模式下 Etcd 大而全但边缘裸奔：**

```
标准部署：
┌─────────────────────────────────────────────┐
│  sso-server (×3)    etcd (×3)    Postgres   │
│     │                    │                    │
│     └── etcd watch ──────┘                    │
│     └── HTTP/Postgres ──────────────────────┘ │
│     需要：3 台服务器 + 3 节点 etcd + Postgres │
└─────────────────────────────────────────────┘

Edge 部署（MQTT + WASM）：
┌──────────────────────────────────────┐
│  sso-server (×1)    mosquitto (×1)   │
│     │                                    │
│     └── MQTT 主题 ────────────────────┘  │
│     └── 本地 SQLite ──────────────────┘  │
│     需要：1 台边缘设备 + < 100MB 内存   │
│     断网：WASM 本地授权决策              │
└──────────────────────────────────────┘
```

---

## 实现路径总结

### 最短路径（1 Sprint）

```
MQTT Bus：platform/cluster/mqtt/bus.go
  约 200 行，实现 cluster.Bus 接口
  配置：cluster.backend: mqtt
  零修改现有代码（Bus 接口抽象已存在）
```

### 中路径（2 Sprints）

```
① MQTT Bus（同上）
② WASM 授权过滤钩子：domains/permissions/ 中添加可选的 WASM 过滤器
  约 200 行 + wazero 依赖（已为业务就绪，纯 Go，无 CGO）
③ mqtt 作为 caep 补充推送通道
```

### 完整路径（3-4 Sprints）

```
①-③ 同上
④ WASM 认证器：domains/authenticators/wasm/
  约 250 行
⑤ sso-ctl policy compile：CLI 将 YAML 策略编译为 WASM 二进制
⑥ Envoy ext_authz WASM 集成（共享同一模块）
```

### 依赖影响

| 技术栈 | 依赖 | 类型 | 大小 |
|--------|------|------|------|
| MQTT v5 | `github.com/eclipse/paho.golang` | 纯 Go | ~5MB |
| MQTT v3.1.1 | `github.com/eclipse/paho.mqtt.golang` | 纯 Go | ~3MB |
| WASM 运行时 | `github.com/tetratelabs/wazero` | 纯 Go，无 CGO | ~8MB |
| WASM 编译（CLI） | `github.com/tetratelabs/wazero` + existing | 同上 | 同上 |

两者都不会引入 CGO 依赖（与项目的纯 Go 策略一致），适合作为嵌套模块放在 `infrastructure/` 层。

---

## 总优先级排序（相对于前 10 轮的 50 个方向）

| 优先级 | 方向 | 理由 |
|--------|------|------|
| **P1** | 方向一：MQTT Bus | 消除 etcd 依赖是运维人员的长期需求，`cluster.Bus` 接口已完美抽象，约 200 行实现 |
| **P2** | 方向四：WASM 认证器 | 解决第 5 轮中"密码策略 SPI 缺失"的更通用方案，无需编译即可扩展认证器 |
| **P3** | 方向二：WASM 授权 | 高价值但需要与 ExtAuthz 共同设计（Phase 1 价值较低） |
| **P4** | 方向三：MQTT CAEP | 增强 CAEP 推送可靠性，但 HTTP 推送 + best-effort 已足够 |
| **P5** | 方向五：Edge 部署模式 | 组合价值最高但前置依赖最多——需要先有 MQTT Bus + WASM 授权 |

**一句话总结：** MQTT 可以在 **200 行代码** 内替代 etcd 作为集群总线（利用现有 `cluster.Bus` 接口），WASM 可以在 **450 行代码** 内提供可插拔授权和认证机制（利用 wazero 纯 Go 运行时）——两者皆不引入 CGO、不改变现有架构、不破坏现有供应商。组合使用时可以实现无 etcd 的 Edge 部署模式，这是项目当前最显著的部署形态缺口。
