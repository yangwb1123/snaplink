# 测试覆盖缺口与风险量化分析

> 基于 2026-07-01 全代码库的最终扫描。  
> 分析视角：资深架构师 / 产品经理。  
> 定位：此前 10 轮分析（50 个方向）全部以"阅读代码找缺口"方法进行。本轮完全不同——**不用阅读代码逻辑，而是对代码库做定量分析**，用数据而非观察判断质量。  
> 方法论：统计每个包的生产代码行数与测试代码行数，结合代码复杂度找到最高风险的无测试代码。  
> 原则：不写代码。

---

## 整体定量发现

| 指标 | 值 |
|------|-----|
| 总生产代码行数（含 gen/） | ~172K |
| 总测试代码行数 | ~171K |
| 总体测试/生产比 | ~99% |
| **无测试文件的生产包数量** | **20 个** |
| **无测试文件的生产代码行数** | **11,655 行** |
| 单元测试中 `time.Sleep` 调用数 | 14 处（脆性测试） |
| `t.Parallel` 使用数 | 4,532 处（良好，但部分缺少 cleanup） |
| `context.Background()` 在测试中 | 3,749 处（应使用 context.WithTimeout 防止 hang） |

---

## 方向一：`interfaces/grpcserver/grpcadmin/`——1,825 行零测试的 gRPC Admin 层

### 现状

| 度量 | 值 |
|------|-----|
| Go 文件数 | 8 |
| 代码行数 | 1,825 |
| 测试文件数 | **0** |
| 测试行数 | **0** |
| 风险等级 | **极高** |

### 包含的内容

```
interfaces/grpcserver/grpcadmin/
├── admin_clients.go    # gRPC ClientAdminService 实现
├── admin_permissions.go
├── admin_releases.go
├── admin_snapshots.go
├── admin_tenants.go
├── admin_tokens.go
├── admin_users.go
└── server.go           # gRPC 服务器注册
```

**为什么这很重要**：
- 这是**所有 gRPC admin RPC 的处理层**
- 覆盖了 client CRUD、用户管理、权限管理、租户管理、token 管理、releases、snapshots
- 每个 RPC 的处理逻辑调用底层 service/store 并返回 protobuf 响应
- 无测试意味着：RPC 输入验证、错误映射（gRPC status code ↔ 业务错误）、权限检查、审计事件记录——所有这些都未直接测试
- 部分功能通过 `test/admin_grpc_*.go` 做了 E2E 测试，但**gRPC handler 自身逻辑**（参数校验、错误转换、边界条件）未覆盖

### 风险场景

| 场景 | 风险 |
|------|------|
| gRPC 请求缺少必填字段 | handler 能否正确返回 `InvalidArgument`？ |
| 无效的 page_token | handler 能否优雅降级而非 panic？ |
| 超大规模响应（>4MB gRPC limit） | 未测试分页边界 |
| Permission 错误映射 | database error → `Internal` status code 转换是否正确？ |

### 建议缓解

1. **为每个 gRPC handler 编写单元测试**（~200 行/文件 × 8 = 1600 行）：mock Deps 接口，验证：
   - 成功路径的响应正确性
   - 空列表的边缘情况
   - 无效输入的 gRPC status code
   - 权限不足的 gRPC status code

2. **特别审查**：`admin_clients.go` 和 `admin_users.go` 因为是 gRPC→REST 双暴露路径，测试覆盖尤为关键。

### 工作量价值评估

- **风险**：高（1825 行生产代码零测试 = 重构时必然出现回归）
- **收益**：gRPC admin API 的合同测试基础

---

## 方向二：`protocols/selfservice/`——用户自服务全链路零测试

### 现状

| 度量 | 值 |
|------|-----|
| Go 文件数 | 14（3 个子包合计） |
| 代码行数 | 1,838（1075 + 627 + 136） |
| 测试文件数 | **0** |
| 测试行数 | **0** |
| 风险等级 | **极高** |

### 包含的内容

```
protocols/selfservice/
├── signup.go           # 用户注册流程
├── password_reset.go   # 密码重置流程
├── email_change.go     # 邮箱变更流程
├── verify_email.go     # 邮箱验证流程
├── data_export.go      # 数据导出（GDPR）
├── sessions.go         # 会话自我管理
├── aliases.go          # 别名
│
protocols/selfservice/selfserviceaccount/
├── profile.go          # 用户资料
├── mfa.go              # MFA 管理
├── consents.go         # 已授权应用管理
├── security.go         # 安全设置
├── aliases.go
├── organizations.go
│
protocols/selfservice/selfservicecore/
└── deps.go             # 依赖接口
```

**为什么这很重要**：
- 这是用户**日常交互**的核心功能（注册、改密码、改邮箱、管理 MFA、导出数据）
- 任何 bug 都会直接影响最终用户体验
- 注册流程的 bug 意味着新用户无法注册
- 密码重置的 bug 意味着用户无法登录
- 数据导出的 bug 意味着 GDPR 合规问题

### 风险场景

| 功能 | 未测试的边界 |
|------|-------------|
| 注册（signup.go） | 重复注册、已存在用户名、rate limit 过期、邮箱验证 token 过期 |
| 密码重置（password_reset.go） | 多次重置 token 重用、已撤销 token 的重置 |
| 邮箱变更（email_change.go） | 新旧邮箱相同、"邮箱已被使用"的 oracle 防护 |
| 数据导出（data_export.go） | 大用户的全量数据导出超时、空用户的导出 |
| MFA 管理 | 移除最后一个 MFA 因子后账户无防护、添加重复因子 |
| 会话管理 | 撤销当前 session 后用户被登出、尝试撤销不存在的 session |

### 建议缓解

1. **为自服务 handler 添加单元测试**（~100 行/功能 × 5 功能 = 500 行）：mock Deps 接口，测试每个 handler 的成功 + 错误路径。

2. **特别审查**：`signup.go` 的 `rate_limited` 降级逻辑——使用 `http.StatusTooManyRequests` 作为 rate limit 响应。如果 rate limit 检查出错，可能错误地阻止所有注册。

### 工作量价值评估

- **风险**：**高**（用户核心交互路径无测试）
- **收益**：影响最大的功能获得测试覆盖

---

## 方向三：`platform/audit/auditspi/` + `auditsink/`——824 行零测试的审计层

### 现状

| 度量 | 值 |
|------|-----|
| Go 文件数 | 11（auditspi 7 + auditsink 4） |
| 代码行数 | 824（456 + 368） |
| 测试文件数 | **0** |
| 测试行数 | **0** |
| 风险等级 | **高** |

### 包含的内容

``` 
platform/audit/auditspi/
├── event.go              # 审计事件定义
├── event_types.go        # 全部 EventType 常量（~70 个）
├── event_types_admin.go  # Admin 事件类型
├── event_types_system.go # 系统事件类型
├── query.go              # 审计查询 SPI
├── sink.go               # 审计 Sink SPI
├── filter.go             # 审计事件过滤

platform/audit/auditsink/
├── webhook_sink.go       # Webhook 审计 Sink
├── writer_sink.go        # 标准输出审计 Sink
├── discard_sink.go       # 空审计 Sink
├── nop_sink.go           # No-op 审计 Sink
```

**为什么这很重要**：
- `event_types.go` 定义了所有 ~70 个 EventType 常量——任何拼写错误会导致审计事件不可查询
- `webhook_sink.go` 是生产环境的关键组件——发送审计事件到外部 SIEM
- `query.go` 定义了审计查询 SPI——所有查询 API 依赖此接口
- 这些是 SPI 定义和接口类型——虽然逻辑简单，但任何变更都会传播到所有实现方

### 风险场景

| 组件 | 未测试的内容 |
|------|-------------|
| `event_types.go` | EventType 字符串格式、序列化/反序列化一致性 |
| `webhook_sink.go` | HTTP 超时处理、重试逻辑、TLS 配置、认证 header 注入 |
| `query.go` | TraceID 过滤、Facet 字段类型转换 |
| `sink.go` | Sink 接口的 Close 语义、并发安全 |

### 建议缓解

1. **EventType 常量测试**（~20 行）：验证所有 EventType 字符串符合 `^[a-z_]+$` 模式，无拼写错误。

2. **WebhookSink 测试**（~80 行）：使用 `httptest.NewServer` 模拟接收端，测试：
   - 正常 POST 发送
   - 接收端返回 500 时的重试
   - 接收端超时

### 工作量价值评估

- **风险**：中（SPI 类型定义简单，但错误传播到所有消费者）
- **收益**：审计事件类型的合同一致性

---

## 方向四：`infrastructure/defaultimpl/memorystoreoauth/`——996 行零专用测试的热路径 Store

### 现状

| 度量 | 值 |
|------|-----|
| Go 文件数 | 6 |
| 代码行数 | 996 |
| 测试文件数 | **0**（包内） |
| ✅ 间接测试 | `test/` 目录的集成测试覆盖 |
| 风险等级 | 中（有间接测试覆盖） |

### 包含的内容

```go
infrastructure/defaultimpl/memorystoreoauth/
├── memory_auth_code.go       # 内存 AuthCodeStore
├── memory_refresh_token.go   # 内存 RefreshTokenStore
├── memory_device_code.go     # 内存 DeviceCodeStore
├── memory_par.go             # 内存 PARStore
├── memory_ciba.go            # 内存 CIBAStore
└── memory_device_secret_store.go  # 内存 DeviceSecretStore
```

**为什么这很重要**：
- 这些是**所有内存后端的核心实现**
- 被 `infrastructure/defaultimpl/aliases_memory.go` 引用为默认后端
- 没有包级测试意味着**专门针对这些 store 的边界条件**（并发访问、空 map、nil panic）没有覆盖

**现有间接测试覆盖**：
- ✅ `test/auth_code_test.go`（534 行）集成测试
- ✅ `test/refresh_token_test.go`（509 行）集成测试
- ✅ `test/handle_device_test.go`（387 行）集成测试
- ✅ `test/handle_par_test.go`（498 行）集成测试
- ✅ `test/handle_ciba_test.go`（219 行）集成测试

### 风险场景（间接测试不覆盖的）

| 场景 | 描述 |
|------|------|
| 并发 get + delete 的竞态 | 集成测试基于 HTTP，无法精确控制 goroutine 交错 |
| map nil 写入 panic | memory store 未初始化时的 panic |
| 内存增长（GC 压力） | 大量 token 写入后未释放 |
| 单测友好的 mock | 没有包级测试意味着重构 store 时不能快速反馈 |

### 建议缓解

1. **为每个 memory store 添加包级单元测试**（~50 行/store × 6 = 300 行）：测试：
   - 基本 CRUD
   - 并发安全（`go test -race`）
   - 空 store 的操作
   - TTL 过期后的 Get

### 工作量价值评估

- **风险**：中（有间接测试保护）
- **收益**：开发时的快速反馈循环

---

## 方向五：`cmd/sso-server/serverbuild*`——3,426 行零测试的组装层

### 现状

| 包 | 行数 | 测试 | 功能 |
|----|------|------|------|
| `serverbuildstore` | 1,470 | 0 | Store 初始化 + Option 组装 |
| `serverbuildauthn` | 985 | 0 | Authenticator 组装 |
| `serverbuildplatform` | 971 | 0 | 平台组件组装（JTI、SPIFFE、CAEP、等） |
| `serverassets` | 65 | 0 | SPA 嵌入式文件系统 |
| **合计** | **3,491** | **0** | |

**为什么这很重要**：
- 这是**将配置 YAML 转换为运行时 `*sso.Server` 的组装层**
- 任何组装错误（缺少依赖、错误参数顺序、配置不兼容）都会导致 server 在启动时 panic
- 无测试意味着：配置变更→启动失败→生产宕机

### 风险场景

| 场景 | 当前 | 需要 |
|------|------|------|
| 配置 YAML 中 `backend: postgres` 但 pg 连接串缺失 | server 启动 panic | 单元测试验证配置校验逻错 |
| 同时启用 SAML + OIDC Federation（互斥？） | 未验证 | 测试检查互斥配置的报错 |
| Redis 密码错误但后端配置正确 | 启动成功但运行时报错 | 测试验证连接失败的错误传播 |

### 建议缓解

1. **Build 单元测试**（~50 行/函数 × 10 = 500 行）：mock config 对象，验证每个 build* 函数的 Option 正确性。

2. **特别审查**：`serverbuildstore` 中的 `wireMTLSLockoutProxiesCORS()` 和 `wireBodyAndRateLimit()`——这些函数将安全配置映射到 runtime Option，任何错误都会影响全局安全。

### 工作量价值评估

- **风险**：高（启动时 panic = 生产宕机）
- **收益**：配置→运行时的合同测试

---

## 优先级总表

| # | 包 | 行数 | 风险 | 现有间接测试 | 建议优先级 |
|---|----|------|------|-------------|-----------|
| **1** | `interfaces/grpcserver/grpcadmin/` | 1,825 | **极高** | 部分（admin_grpc_*.go E2E） | **P1** |
| **2** | `protocols/selfservice/` | 1,838 | **高** | 无 | **P1** |
| **3** | `cmd/sso-server/serverbuild*` | 3,491 | **高** | 无 | **P2** |
| **4** | `platform/audit/auditspi/` + `auditsink/` | 824 | 中 | 无 | P2 |
| **5** | `infrastructure/defaultimpl/memorystoreoauth/` | 996 | 中 | ✅ 有（test/ 集成测试） | P3 |

### 核心结论

**20 个生产包，11,655 行代码没有专用测试文件**。虽然部分包通过 `test/` 目录下的集成测试获得了间接覆盖，但：

| 覆盖类型 | 优势 | 劣势 |
|----------|------|------|
| 集成测试（test/） | 验证真实 HTTP 端点交互 | 启动慢、难覆盖边界条件、失败时诊断困难 |
| 单元测试（包内 `_test.go`） | 启动快、覆盖边界条件、快速反馈 | 需要 mock、不验证端到端 |

**最优先**：`grpcadmin`（1825 行）和 `selfservice`（1838 行）是用户和管理员日常核心功能路径，但零测试覆盖。任何重构或功能扩展在此区域都可能引入回归。

### 跨 11 轮的关系

| 轮次 | 视角 | 方法 | 产出 |
|------|------|------|------|
| 卷1-6 | 架构/产品/运维 | 阅读代码找缺 | 新功能 + 治理 + 运维 |
| 卷7-8 | 审计/性能 | 检查规范 + Runtime | 合规 + GC |
| 卷9-10 | 企业/SRE | 完成度 + 故障模式 | 管理功能 + 生产风险 |
| **本卷** | **QA/测试** | **量化分析** | **未测试的代码 + 风险量化** |
