# 扩展方向分析报告 —— 协议层收口后的下一阶段

> **作者：** 资深架构 & 产品经理视角  
> **日期：** 2026-07-11  
> **范围：** 全代码库全局扫描（2241 `.go` 文件、4 个嵌入式 SPA、200+ 包）  
> **前提：** 本轮分析已系统阅读并逐项对抗核验 `ROADMAP.md` v5.0、`deferred-backlog.md`、  
>   `expansion-directions-v7-analysis.md`（BFF/IAL2/Step-up/SAML2输出/VC）、  
>   `expansion-directions-v8-analysis.md`（B2B委托管理/select_account/i18n/跨标签页同步/翻译网关）、  
>   `expansion-directions-v9-analysis.md`（账户恢复/Magic Link/推送通知/令牌治理面板/令牌敏感度分类）、  
>   `expansion-directions-v6-analysis.md`（Terraform Provider/Active ITDR/时钟偏差修复）、  
>   `feature-spec-active-itdr-detection-response.md`。**本报告 5 个方向与上述所有文档零重叠。**  

---

## 前置声明：项目成熟度定位

经过多轮全局扫描和方向分析，本项目的基础协议覆盖面和后端能力已是行业顶级水平（90+ `WithXxx` 选项、4 个嵌入式 SPA、6+ 存储后端、10+ 企业协议、OIDC/OAuth/SAML/FAPI/CAEP/SCIM 全覆盖）。前三轮分析（v7/v8/v9）分别覆盖了从 BFF 安全模式到 Magic Link 免密登录、从 B2B 委托门户到账户恢复的 15 个高价值方向。ROADMAP v5.0 进一步覆盖了终端体验产品层、企业 B2B 连接、OIDC 一致性、多副本数据韧性、安全姿态与供应链。

**本报告的 5 个方向不再属于"增加协议支持"或"补齐已缺失的后端能力"，而是属于以下三大新领域：**

| 领域 | 本报告方向 |
|---|---|
| **身份连续性 & 跨设备体验** | ① 跨设备身份连续性与凭据桥接 |
| **数据驱动身份智能** | ② 统一身份事件智能平台 |
| **平台化 & 开放生态** | ③ 授权即服务（Policy Decision Point as a Service） |
| **规模 & 性能深度** | ④ 令牌生命周期的大规模运营边缘 |
| **产品化 & 商业智能** | ⑤ 身份分析与多租户商业智能平台 |

---

## 方向 1：跨设备身份连续性与凭据桥接（Cross-Device Identity Continuity）

### 现状

项目拥有完整的 WebAuthn/Passkey 支持：

| 能力 | 状态 |
|---|---|
| Passkey 注册（平台认证器 + 跨平台认证器） | ✅ 完整 |
| WebAuthn 作为主认证（无密码登录） | ✅ `conditional_login.go` + `primary_auth_enabled` |
| WebAuthn 作为 MFA | ✅ `mfa.go` |
| WebAuthn MDS（元数据服务） | ✅ `mds.go` |
| FIDO2 条件式中介（Conditional Mediation） | ✅ `conditional_login.go` |
| **FIDO2 CTAP 2.2 混合跨设备认证（Hybrid/CA）** | ❌ **零实现** |
| **跨设备会话漫游（Session Roaming）** | ❌ **零实现** |
| **已认证设备网格（Device Mesh）** | ❌ **零实现** |
| **跨设备凭据桥（Credential Bridge）** | ❌ **零实现** |

### 缺口（grep 核验）

- `cross.device` / `CrossDevice` / `crossDevice` / `device.to.device`：**零实现命中**
  （仅 `expansion-directions-analysis.md` 文档中有提及，但该文档为 v1 历史文档且未被任何后续分析拣起）
- `hybrid.*auth\|HybridAuth\|hybrid_auth`：**零实现命中**
- `session.*roam\|SessionRoam\|session.*migrat\|SessionMigrat`：**零实现命中**
- `device.*mesh\|DeviceMesh\|device.*grid\|credential.*bridge\|CredentialBridge`：**零实现命中**
- 无 `POST /auth/session/transfer`、`GET /auth/device/claim`、`POST /auth/device/link` 端点
- 无 `DeviceLinkStore` SPI 或 `CrossDeviceSessionManager` SPI

### 范围

#### 1. FIDO2 混合跨设备认证（CTAP 2.2 Hybrid）

```
用户场景: 小王在办公电脑（Chrome，无内置生物识别）上要登录。
         他的手机有 Passkey。他选择"用手机上的通行密钥"。

流程:
  Step 1: 电脑上点击"用手机上的通行密钥登录"
  Step 2: 服务器生成一次性挑战 QR 码 (POST /auth/hybrid/initiate)
  Step 3: 用手机扫描 QR 码（蓝牙/网络传输）
  Step 4: 手机上用 Face ID 确认（Passkey 签名）
  Step 5: 手机返回签名 + 证书到服务器
  Step 6: 服务器完成认证，电脑收到授权码

技术实现:
  - 遵循 FIDO2 CTAP 2.2 Hybrid 规范（草案）
  - 使用 Web Bluetooth / Web NFC / QR 码进行设备间传输
  - 服务端做 relay 或 P2P（取决于部署场景）
  - 新增端点:
    POST /auth/hybrid/initiate  → 生成挑战
    POST /auth/hybrid/complete  → 完成认证
  - 安全设计:
    - 挑战 TTL = 120 秒（一次性）
    - 绑定客户端 IP（检测 relaying 攻击）
    - 挑战使用后立即作废
    - 速率限制：每用户每 300 秒 3 次
```

#### 2. 跨设备会话漫游（Session Roaming）

```
用户场景: 小张在办公室电脑登录了公司系统。下班后在地铁上用手机
         打开同一个应用——不用重新登录，会话自动迁移。

架构设计:
  ┌──────────────────┐      ┌──────────────────┐
  │  设备 A (电脑)    │      │  设备 B (手机)    │
  │  - session_id     │      │  - session_id    │
  │  - device_token_a │      │  - device_token_b│
  └────────┬─────────┘      └────────┬─────────┘
           │                         │
           └──────────┬──────────────┘
                      │
              ┌───────▼────────┐
              │  Session Hub    │
              │  - 用户级会话组  │
              │  - 每设备子会话  │
              │  - 共享的 AuthN │
              │    状态 + 声明  │
              └────────────────┘

漫游流程:
  Step 1: 用户从新设备发起 authorized 请求
  Step 2: 新设备出示已认证设备的凭据（claim_token）
          POST /auth/session/claim {claim_token, device_info}
  Step 3: 服务器验证 claim_token → 新的已认证子会话
  Step 4: 新设备获得授权码（无需完整登录流程）

Claim Token 安全模型:
  - 由已认证设备在用户确认后生成
  - 单次使用 + 短 TTL（60 秒）
  - 包含绑定信息: source_session_id, target_device_token
  - 通过带外渠道传输（用户扫描、复制粘贴、邮件）
```

#### 3. 并发会话管理

```
在上面的 Session Hub 基础上增加:

| 能力 | 说明 |
|---|---|
| 会话注册 | 每登录创建设备记录（device_id + session_id + user_agent + ip） |
| 会话列表 | GET /me/sessions → 返回所有活跃会话 |
| 会话吊销 | DELETE /me/sessions/:id → 远程登出设备 |
| 并发限制 | 每用户最大活跃会话数（可配置）超出则拒绝或踢出最早 |
| 异地登录检测 | 新设备登录 → 通知所有已有设备 |
| 设备信任升级 | 频繁使用的设备自动提升信任等级 |

管理员端点:
  GET  /api/v1/admin/users/:id/sessions          → 查看用户所有活跃会话
  DELETE /api/v1/admin/users/:id/sessions/:sid    → 强制终止指定会话
  GET  /api/v1/admin/users/:id/devices            → 查看已注册设备
  POST /api/v1/admin/users/:id/sessions/limit     → 设置并发会话上限
```

#### 4. Session Hub 数据结构

```go
// domains/sessionhub/sessionhub.go （已存在，需要扩展）

// 已有: SessionHub 是"当前用户的活跃会话"管理中心
// 需要扩展的能力:

// DeviceSession 将一个会话绑定到一个特定设备。
type DeviceSession struct {
    DeviceID     string    // 本设备唯一 ID（浏览器/客户端生成）
    SessionID    string    // 父会话 ID
    UserID       string
    TenantID     string
    LastSeen     time.Time
    DeviceInfo   DeviceInfo // 用户代理、屏幕尺寸、OS、指纹
    IsTrusted    bool      // 设备信任标志
    TrustedSince time.Time // 成为信任设备的时间
    IP           string    // 最后活跃 IP
    Geo          GeoInfo   // 最后活跃地理位置
}

// ConcurrentSessionLimit 定义每个用户的会话上限策略。
type ConcurrentSessionLimit struct {
    Enabled bool   // true = 启用限制
    Max     int    // 0 = 不限制
    Action  string // "deny" (拒绝新) / "evict_oldest" (踢最旧)
}
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 用户手机丢失，会话 claim token 泄漏 | Claim token 短 TTL + 单次使用 + 设备确认 + 风险评分上下文绑定 |
| 多设备同时 claim 同一会话 | 第一次成功后该 claim token 立即作废，后续失败 |
| 二维码中继攻击（人在中继 Relay Attack） | 挑战绑定原始 IP 和设备指纹；地理位置突变标记为可疑 |
| 蓝牙传输碰撞 | 使用唯一会话标识符（连接码）+ 用户确认配对 |
| 用户在公共电脑上登录后忘记登出 | 短时间内（15分钟）无操作自动登出 + 管理员远程清理 |
| 非 HTTPS 环境（二维码扫描 URL） | 二维码仅包含不敏感的一次性挑战码（非 token） |
| 新旧设备时钟偏差大 | 基于服务器时间而非客户端时间做 TTL 判断 |
| 批量设备注册攻击 | 每 IP 每 10 分钟限制 5 次 claim 尝试 |

### 为什么值得做

**跨设备身份连续性是现代用户的核心预期。** 用户不希望在手机上重新输入密码、不想每次新设备都走完整登录流程，更不希望在设备间切换时丢失登录状态。FIDO2 CTAP 2.2 Hybrid（跨设备认证）是 FIDO Alliance 2024 标准化的能力，已被 Chrome/Safari/Edge 原生支持——目前项目虽已实现 WebAuthn 全栈，但跨设备的"用手机的 Face ID 登录电脑"场景缺位。**这是补齐 "Passwordless Across Devices" 故事的最后一块拼图。**

同时，Session Roaming 是企业级 SSO 的重要差异化能力——Citrix、VMware Workspace ONE 的核心功能就是"一次登录，随处可用"。在消费端，Google/Apple/Microsoft 的跨设备登录早已成为用户习惯。

- **价值：** 高（关键 UX 差异化 + 企业远程办公必选项）  
- **工作量：** L~XL（Hybrid CA 需要 CTAP 2.2 协议组装 + 设备交互 UX；Session Roaming 需要 Session Hub 扩展 + 安全模型设计 + 前端 API）  
  - Phase 1：Session Roaming + 并发会话管理（L 级，先交付）  
  - Phase 2：FIDO2 Hybrid 跨设备认证（XL 级，依赖浏览器 API 成熟度）
- **依赖：** `SessionStore`（已存在）、`SessionHub`（已存在 `platform/lifecycle/sessionhub/`）、`webauthn/`（已存在）、`DeviceFingerprint`（已存在 `domains/conditionalaccess/`）

---

## 方向 2：统一身份事件智能平台（Unified Identity Event Intelligence Platform）

### 现状

项目拥有多个松散、面向不同用途的事件出口：

| 出口 | 用途 | 状态 |
|---|---|---|
| `platform/audit` | 审计事件记录与查询 | ✅ 完整 |
| `protocols/caep` | CAEP/RISC 安全事件推送（SET） | ✅ 完整 |
| `webhook/engine` | 通用事件 webhook 出口 | ✅ 完整 |
| `platform/sse` | 管理面实时事件流 | ✅ 完整 |
| `cluster/bus` | 跨副本内部事件总线 | ✅ 完整 |
| **统一事件关联引擎** | **跨事件源的模式检测** | ❌ **零实现** |
| **事件智能告警规则引擎** | **可配置的告警规则** | ❌ **零实现** |
| **事件保留与重放** | **完整的事件存储与回放** | ❌ **零实现** |
| **统一事件订阅与过滤器** | **跨所有事件类型的声明式订阅** | ❌ **零实现** |

### 缺口（grep 核验）

- `event.*correlat\|EventCorrelat\|correlation.*engine`：**零实现命中**
  （`decay.go:19` 的 `scoreCorrelation` 是信任分数内的相关性系数，不是事件关联引擎）
- `alert.*rule\|AlertRule\|alerting.*engine\|alert.*condition`：**零实现命中**
  （Prometheus 监控告警由外部的 `prometheus+alertmanager` 处理，不是内置能力）
- `event.*retent\|EventRetent\|event.*replay\|EventReplay\|event.*store.*event`：**零实现命中**
- `event.*subscript\|EventSubscri`：仅 `webhook` 包有订阅概念（但只用于 webhook 出口）
- `event.*schema\|EventSchema\|event.*registry\|EventRegistry`：**零实现命中**
- 无 `POST /api/v1/events/rules`、`GET /api/v1/events/rules`、`POST /api/v1/events/query/correlate` 等管理端点
- 无 `EventCorrelationEngine` SPI 或 `EventIntelligenceStore` SPI

### 范围

#### 1. 统一事件模型与注册表

```
所有事件源统一到一个类型系统:

Event {
  ID          string
  Type        EventType    // login_succeeded, token_issued, admin_client_created, caep_set_delivered, ...
  Source      string       // "audit", "caep", "webhook", "sse", "cluster"
  Severity    EventSeverity // info, warning, critical
  Timestamp   time.Time
  Actor       string       // user_id / admin_id / system
  Target      string       // affected resource
  Context     map[string]any  // event-specific attributes
  Metadata    map[string]string  // tenant_id, session_id, request_id, correlation_id
}

统一的类型注册:
  - 每个事件源注册自己发射的事件类型
  - 包含 JSON Schema 作为事件载荷的规范描述
  - 支持向后兼容性验证（新增字段不破坏现有订阅者）
```

#### 2. 事件关联引擎

```
规则驱动的关联引擎:

规则示例:
  Rule 1: "15 分钟内同一用户登录失败 > 5 次 → 合成 AccountBruteForce 事件"
  Rule 2: "同一 IP 在 5 分钟内登录 > 3 个不同用户 → 合成 IPCredentialStuffing 事件"
  Rule 3: "token_revoked 后 60 秒内同一用户有新 token 签发 → 合成 TokenRotationAnomaly 事件"
  Rule 4: "敏感 API 调用（admin:*）前 5 分钟内有登录事件 → 关联为 AdminSession 序列"

架构:
  ┌─────────┐  ┌────────┐  ┌──────────┐  ┌──────────┐
  │  Audit  │  │  CAEP  │  │  Webhook │  │  SSE     │
  └────┬────┘  └───┬────┘  └────┬─────┘  └────┬─────┘
       │           │            │              │
       └───────────┴────────────┴──────────────┘
                       │
              ┌────────▼────────┐
              │  Event Store     │ ← 统一事件存储（时间序列窗口）
              │  (memory/sqlite/ │
              │   postgres/      │
              │   elasticsearch) │
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │  Correlation     │ ← 规则引擎匹配事件窗口
              │  Engine          │
              └────────┬────────┘
                       │
              ┌────────▼────────┐  ┌─────────┐  ┌──────────┐
              │  Synthesized     │→│ Audit   │→│ Webhook  │
              │  Events          │  │ Sink    │  │ Forward  │
              └─────────────────┘  └─────────┘  └──────────┘
```

#### 3. 事件驱动的自动化响应

```
基于关联事件的自动化响应链:

| 关联事件 | 自动响应动作 | 严重程度 |
|---|---|---|
| AccountBruteForce | 锁定账户 + 通知用户 + 通知租户管理员 | high |
| IPCredentialStuffing | 临时封禁源 IP + 通知管理员 | critical |
| TokenRotationAnomaly | 吊销该用户所有 token + 强制 MFA step-up | critical |
| AdminUnusualHour | 记录审计 + 通知管理员 | medium |
| APIKeyBurst | 临时降级 API key 到只读模式 | high |

基于策略的可配置性:
  - 每种威胁类型映射到一个 O(1) lookaside 动作表
  - 管理员可通过 admin API 配置: 启用/禁用、调整阈值、修改动作
  - 支持动作链: 锁定账户 → 发送通知 → 触发 SIEM webhook
  - 支持抑制窗口: 同一事件在 N 分钟内不重复触发相同动作
```

#### 4. 事件智能 API

```go
// 管理端点:
// 事件查询:
//   POST /api/v1/events/query
//     {types, time_range, tenant_id, actor, target, severity, page_token, page_size}
//   GET /api/v1/events/rules
//   GET /api/v1/events/rules/:id
//   POST /api/v1/events/rules
//   DELETE /api/v1/events/rules/:id
//
// 关联分析:
//   POST /api/v1/events/correlate
//     {events: [id1, id2, id3]}
//     → 返回关联图谱（root_cause, related_events, timeline）
//
// 时间序列:
//   GET /api/v1/events/timeseries
//     {types, interval: "5m", range: "24h"}
//     → 返回时间桶计数（用于趋势分析）
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 事件风暴（DDoS 触发的海量事件） | 事件管道使用有界缓冲区 + 背压；Event Store 支持采样（每 N 条记 1 条） |
| 关联规则循环（A→B→A） | 每次关联事件打 `generation` 标签，达到最大深度（3）后终止循环 |
| 事件延迟到达（网络分区恢复后） | 关联窗口使用"事件时间"而非"处理时间"；后到事件触发重新评估 |
| 规则误触发（假阳性） | 所有自动响应设"冷静期"（可配置）；支持抑制规则（Suppression Rule） |
| 存储爆炸 | Event Store 有 TTL（默认 7 天）+ 速率限制 + 有界内存窗口 |
| 跨租户事件泄露 | Event Store 强制租户隔离；关联引擎只在单租户窗口内执行 |

### 为什么值得做

**项目的事件出口基础设施已极完整（审计、CAEP、webhook、SSE、集群总线），但它们是彼此孤立的竖井——它们产生数据，从不消费数据。** 这意味着当前：
- 一个攻击者在 5 分钟内尝试了 3 个不同账户：`anomaly.Runner` 记录了 3 条独立审计事件，但没有人能从这 3 条事件中关联出 "这是在撞库（credential stuffing）"
- 一个被吊销的 token 在 60 秒后被一个不同 IP 重新签发：审计流水上 2 条无关记录，没有自动化的安全响应
- 管理员需要编写自定义脚本从审计 API + 事件流 API 分别拉取数据才能做手动关联

**统一事件智能平台将被动的事件记录器转变为主动的安全智能系统。** 这不是增加新协议——它是将所有既有的数据资产（审计、CAEP、SSE 流、webhook 状态、甚至 cluster bus 的内部信号）编织成一张可查询、可告警、可响应的智能网络。

- **价值：** 极高（安全运维刚需 + 差异化智能能力）  
- **工作量：** XL（跨 4 个事件源的统一存储 + 关联引擎 + 响应执行器）  
  - Phase 1：统一事件存储 + 查询 API + 简单规则引擎（L）  
  - Phase 2：事件关联引擎 + 自动化响应（XL）  
  - Phase 3：可配置规则 UI + 时间序列分析仪表盘（L）
- **依赖：** `caep/`（已存在）、`webhook` engine（已存在）、`platform/audit`（已存在）、`anomaly/`（已存在）、`threataction/`（已存在 `domains/threataction/` 动作注册表 + 执行器）

---

## 方向 3：授权即服务 —— Policy Decision Point as a Service

### 现状

项目拥有以下授权相关组件：

| 能力 | 状态 |
|---|---|
| OAuth 2.0 令牌（token = 授权凭证） | ✅ 完整 |
| 权限 RBAC 系统（Roles + Permissions） | ✅ `domains/permissions/` 完整 |
| ReBAC 关系检查（Relationship-Based Access Control） | ✅ `platform/lifecycle/rebac/` 完整（`Check` 方法） |
| gRPC Authorizer 服务 | ✅ `interfaces/grpcserver/authz.go`（`Check`、`ListPermissions`、`ListRoles`） |
| 权限策略 Bundle 导出（供 OPA 边车消费） | ✅ `domains/permissions/policy_bundle.go` |
| 边车网格授权（Envoy ext_authz HTTP+gRPC） | ✅ `mesh_authz.go` + `extauthz/` |
| **REST 化授权决策端点** | ❌ **零实现**（gRPC 需要 grpcurl 客户端，非 RESTful） |
| **策略管理 UI** | ❌ **零实现** |
| **条件授权引擎（Context-Aware Policy）** | ❌ **零实现**（现有权限只检查 scope，不检查设备、地点、时间、风险） |
| **策略测试/模拟工具** | ❌ **零实现** |
| **细粒度授权决策日志** | ❌ **零实现**（现有审计记"who did what"但不记"why was it allowed"） |

### 缺口（grep 核验）

- `POST /authorize` / `POST /authz/check` / `POST /v1/authorize`：**零实现命中**
  （`mesh_authz.go` 中的 `HandleMeshExtAuthz` 是 Envoy 格式的授权，不是标准 REST 授权端点）
- `policy.*test\|PolicyTest\|authz.*simulat\|AuthorizeSimul`：**零实现命中**
- `authz.*decision.*log\|AuthorizationDecision\|decision.*reason` 作为授权日志字段：**零实现命中**
- 无 `WithAuthorizeEndpoint` 配置选项
- 无 `AuthorizationDecisionStore` SPI
- 无策略管理的前端 UI（`web/admin/` 中没有权限策略 tab）

### 范围

#### 1. REST 授权决策端点

```
POST /api/v1/authorize
  Authorization: Bearer <access_token>
  Content-Type: application/json

  Request:
  {
    "subject": {
      "user_id": "user-alice",
      "tenant_id": "tenant-acme",
      "session_id": "sess_abc123"
    },
    "action": "read",
    "resource": {
      "type": "document",
      "id": "doc-42",
      "attributes": {
        "classification": "internal",
        "project": "project-x"
      }
    },
    "context": {
      "ip": "203.0.113.42",
      "device_id": "dev-xyz",
      "time": "2026-07-11T14:30:00Z",
      "geo": {"country": "US", "region": "CA"},
      "risk_score": 0.12
    }
  }

  Response (200):
  {
    "decision": "allow",
    "reason": "user-alice has doc:read permission on project-x",
    "evaluated_policies": [
      {"id": "pol-1", "name": "document-read-rbac", "matched": true},
      {"id": "pol-2", "name": "project-x-access", "matched": true},
      {"id": "pol-3", "name": "us-only-geo", "matched": true}
    ],
    "ttl_seconds": 300,
    "decision_id": "dec_efg456"
  }

  Response (403):
  {
    "decision": "deny",
    "reason": "user-alice lacks doc:admin permission",
    "evaluated_policies": [
      {"id": "pol-1", "name": "document-read-rbac", "matched": false},
      {"id": "pol-4", "name": "admin-only-geo", "matched": true}
    ],
    "decision_id": "dec_hij789"
  }
```

#### 2. 条件授权引擎

```
将现有的权限检查（RBAC）+ ReBAC 关系检查 + 环境上下文检查整合为一个
统一的授权决策管道:

  决策管道:
  1. 身份解析: token → subject {user_id, tenant_id, roles, permissions}
  2. RBAC 检查: 用户是否有足够权限执行该动作？
  3. ReBAC 检查: 用户与该资源存在 allowed 关系？
  4. 条件检查: 当前上下文（IP、设备、时间、风险）是否满足策略条件？
  5. 决策产出: allow/deny + 理由 + 策略 ID

条件检查示例:
  - "仅允许 US IP 访问" → 检查请求 IP 地理位置
  - "仅允许公司设备访问" → 检查 device_id 是否在信任设备列表中
  - "仅允许工作时间访问" → 检查请求时间（UTC→用户时区）
  - "风险评分 > 0.7 时拒绝" → 检查 trust.TrustScore
  - "MFA 未启用时要求 step-up" → 检查用户是否注册了 MFA
```

#### 3. 策略定义 DSL 与管理 API

```yaml
# YAML 策略定义示例

policies:
  - id: "pol-document-read"
    name: "Document Read Access"
    type: "rbac"
    rules:
      - effect: "allow"
        actions: ["document:read"]
        roles: ["reader", "editor", "admin"]
      - effect: "allow"
        actions: ["document:write"]
        roles: ["editor", "admin"]
      - effect: "deny"
        actions: ["document:delete"]
        roles: ["reader"]

  - id: "pol-restricted-project"
    name: "Restricted Project Access"
    type: "conditional"
    conditions:
      all:
        - has_permission: "project-x:access"
        - ip_country: "US"
        - device_trusted: true
    rules:
      - effect: "allow"
        roles: ["member", "admin"]

  - id: "pol-high-risk-session"
    name: "High Risk Session Deny"
    type: "conditional"
    conditions:
      any:
        - risk_score: { gt: 0.8 }
        - device_unknown: true
        - geo_velocity_anomaly: true
    rules:
      - effect: "deny"
        message: "Session risk too high. Please re-authenticate."

管理端点:
  POST   /api/v1/admin/policies                 # 创建策略
  GET    /api/v1/admin/policies                 # 列策略
  GET    /api/v1/admin/policies/:id             # 读策略
  PUT    /api/v1/admin/policies/:id             # 更新策略
  DELETE /api/v1/admin/policies/:id             # 删除策略
  POST   /api/v1/admin/policies/:id/test        # 模拟测试策略
  POST   /api/v1/admin/policies/reorder         # 重排序（策略优先级）
  GET    /api/v1/admin/policies/evaluation-log  # 决策日志（含 reason）
```

#### 4. 授权决策日志与可观测性

```
每个授权决策记录:

AuthorizationDecision {
  DecisionID   string
  Subject      string     // user_id
  TenantID     string
  Action       string
  Resource     ResourceRef
  Decision     string     // allow / deny
  Reason       string     // human-readable
  PolicyIDs    []string   // matched policy IDs
  Context      DecisionContext  // IP, geo, device, risk, time
  LatencyMs    int
  Timestamp    time.Time
}

指标暴露:
  sso_authz_decisions_total{decision="allow",policy_id="pol-xxx"}
  sso_authz_decisions_total{decision="deny",policy_id="pol-xxx"}
  sso_authz_evaluation_duration_seconds{policy_id="pol-xxx"}
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 策略过多导致决策延迟 | 策略索引 + 短路评估（deny 优先）+ 条件分级（先低成本条件后高成本条件） |
| 死锁策略（A→B→A 的依赖循环） | 静态策略 DAG 循环检测 + 编译期报错 |
| 策略更新后已有缓存决策过期 | 决策响应带 TTL；策略更新时通过 cluster bus 广播缓存失效 |
| 条件评估依赖外部服务（如第三方设备信任 API） | 外部服务超时使用"宽松模式"（失败则转换为更低确定性的决策） |
| 资源数量太大无法枚举（如 SaaS 应用有百万文档） | ReBAC 方式只检查关系而非枚举资源；资源类型通过 attributes 匹配 |
| 请求中携带大量 resource.attributes | attributes 大小限制（4KB，与 JWT 声明一致） |

### 为什么值得做

**这是从"令牌颁发者"到"授权决策者"的架构跃迁。** 目前项目拥有行业最完整的令牌签发能力——但它签发完 token 后就不再参与授权决策了。资源服务器自己解读 scope 并决定允许/拒绝，每个资源服务器重复实现相同的授权逻辑，策略不一致是必然的。

将 Policy Decision Point（PDP）以 REST 服务的形式暴露出来，配合现有的 RBAC/ReBAC 系统和条件的上下文感知引擎，让整个组织在同一套策略框架下做授权决策——**这正是 OAuth 2.0 架构中"Token 是授权的结果发布形式、但真正的授权决策应在统一 PDP 中完成"的最佳实践。**

对于企业客户，这不仅意味着安全策略的一致性（"一个员工在所有 SaaS 和内部应用中的访问权限都走同一套策略"），更是合规审计的刚需——"我们有 10 万条授权决策，每条都有完整的策略 ID 和推理链"。

- **价值：** 极高（架构跃迁 + 企业合规 + 安全一致性 + 运营效率）  
- **工作量：** XL（策略定义 DSL + REST 端点 + 条件引擎 + 决策日志 + 管理 UI）  
  - Phase 1：REST 授权端点（利用现有 `permissions.Provider` + `rebac.Check` + `conditionalaccess.Evaluate`）+ 决策日志（M）  
  - Phase 2：条件引擎 + 策略 DSL 编译器（L）  
  - Phase 3：策略管理 UI + 模拟测试工具（L）
- **依赖：** `permissions.Provider`（已存在）、`rebac.Store`（已存在）、`conditionalaccess`（已存在）、`trust.TrustScorer`（已存在）、`shared/trust/`（已存在 Phase 1 评分器）

---

## 方向 4：令牌生命周期的大规模运营优化（Token Lifecycle at Scale）

### 现状

项目拥有完整的令牌生命周期管理：

| 能力 | 状态 |
|---|---|
| 令牌签发（JWT access_token + id_token + refresh_token） | ✅ 完整 |
| 令牌吊销（单令牌、用户全部、批量） | ✅ 完整 |
| 令牌内省（RFC 7662 + 签名内省） | ✅ 完整 |
| 令牌刷新（含 family 轮换 + grace window） | ✅ 完整 |
| 令牌交换（RFC 8693 + 多 hop act chain） | ✅ 完整 |
| 令牌策略引擎（签发前/后策略） | ✅ `domains/tokenpolicy/` 完整 |
| **分布式吊销集（跨副本持久化）** | ❌ **ROADMAP v5.0 #4 已确认：仅进程内内存、重启后空** |
| **O(1) 令牌验证（10M+ 令牌规模）** | ❌ **无专门优化** |
| **CDN 友好的内省（edge caching）** | ❌ **无 CDN 缓存策略** |
| **令牌压缩（JWT 瘦身/claim 过滤）** | ❌ **零实现** |
| **DPoP 非标量扩展（高并发场景）** | ❌ **固定窗口 TTL，无分层淘汰** |
| **JTI 重放存储的 GC 与分片** | ❌ **memreaper 已实现但仅内存后端** |

### 缺口（grep 核验）

- `distributed.*revoc\|DistributedRevoc\|revoc.*set\|RevocSet`：**零实现命中**
  （`defaultimpl/revocation_set.go` 是进程内 `map[string]time.Time`，无持久化 peer）
- `token.*compact\|TokenCompact\|token.*compress\|TokenCompress\|token.*lite\|TokenLite`：**零实现命中**
- `introspect.*cache.*CDN\|introspect.*edge\|edge.*introspect\|CDN.*introspect`：**零实现命中**
- `token.*validat.*shard\|TokenValidat.*Shard`：**零实现命中**
- 无 `WithPersistentRevocationSet`、`WithTokenCompression`、`WithCDNFriendlyIntrospection` 选项

### 范围

#### 1. 分布式持久化吊销集（Persistent Deny-Set）

```
当前状态（ROADMAP v5.0 #4c 已确认问题）:
  - revocation_set.go 使用 sync.Map + expiry
  - 仅进程内，不跨副本同步（除 bus 尽力广播外）
  - 重启后全部丢失
  - 无 sqlite/redis 持久化 peer

解决方案:
  ┌─────────────────┐
  │  RevocationSet   │  ← 内存缓存层（LRU + TTL）
  ├─────────────────┤
  │  Persistent       │  ← 持久化层（sqlite/postgres/redis）
  │  Deny-Store       │
  └─────────────────┘

  写路径:
    POST /token/revoke → 写入持久层 + 总线广播 → 更新本地缓存
  
  读路径:
    token 验证 → 从本地缓存检查 → 缓存 miss → 从持久层检查 → 缓存填充
  
  批加载:
    启动时从持久层批量加载未过期吊销条目（按 TTL 排序，前 N 条）
    
  过期清理:
    持久层支持 TTL 自动清理（Postgres/SQLite 的过期索引，Redis 的 TTL key）
    内存缓存维护大小上限 + 近期最少使用淘汰
```

#### 2. JWT 令牌瘦身（Token Slimming）

```
问题: JWT access_token 当前携带完整 claim 集合（sub, iss, aud, exp, iat,
      jti, client_id, sid, auth_time, amr, acr, scp, roles, tenant_id,
      cnf...），在多 claim 场景下 JWT 净荷可达 2-4KB。10M 令牌每秒验证
      1000 次的场景下，每个 base64 解码 + 签名的额外字节都影响 P99。

解决方案:
  a) 按 scope 过滤 claim
     email scope → email 声明
     profile scope → profile 声明
     无 openid 范围 → 省略 id_token 专属声明（sub 除外）
  
  b) 压缩令牌引用（Token Reference）
     极短令牌 + 服务器端声明存储。
     适用于内网场景（存储比传输便宜）:
       Option 1: `token_ref`（参考令牌）= 64 位 ID + HMAC → 2KB → 40 字节
       Option 2: `token_jwt`（完整 JWT）= 当前默认
  
  c) 声明打包（Claim Bundling）
     将可推导的声明打包为短字符串:
       "urn:ietf:params:oauth:auth_time" → auth_t
       "urn:ietf:params:oauth:amr" → amr（已经是短数组）
     这不是简单的重命名——是映射到已知值。
  
  d) 声明类型优化
     auth_time 从 full RFC3339 改为 Unix 时间戳 int
     roles 从 []string 改为 bitmask（在已知角色集有限时）
```

#### 3. CDN 友好的内省缓存

```
问题: POST /token/introspect 不能缓存（POST 请求通常不被 CDN 缓存）。
      签名内省（RFC 9701）提供了可缓存的自省令牌，但当前实现是
      每次实时生成签名自省令牌，这增加了签发开销。

解决方案:
  a) 签名自省令牌（已实现）→ 放置 CDN TTL
  
  b) 内省缓存层次:
     L1：进程内缓存（map + TTL，已实现 `IntrospectionCache`）
     L2：分布式缓存（Redis，跨副本共享）
     L3：CDN 缓存（仅适用于签名自省令牌）
     
     缓存策略:
       - active tokens（TTL=access_token 剩余寿命的 50%）
       - revoked tokens（TTL=吊销集合的剩余 TTL）
       - unknown tokens（负缓存，TTL=30 秒，防止重放攻击）
  
  c) 批量内省（已实现部分）
     支持一次请求检查多个令牌（`WithIntrospectionBatch(maxSize)`）
     批量响应的缓存键 = 令牌列表哈希
```

#### 4. DPoP 非标伸缩

```
问题: DPoP nonce 需要防重放 + 唯一性验证。
      高并发下（10K req/s），nonce 存储成为瓶颈。

优化:
  a) 分片 nonce 存储
     基于 jti 的前 2 个字节分 256 个分片
     每个分片独立 GC
  
  b) 分级 nonce 验证
     L1 检查（内存 bloom filter）: 99% 的重复 jti 在此层被拒绝
     L2 检查（精确存储）: bloom filter 假阳性时 fallback
  
  c) nonce 窗口滑动
     不使用固定 TTL 淘汰，而是使用滑动窗口
     保留最近 N 秒（可配置）内的 nonce
     超出窗口的 nonce 即使从未见过也视为过期
```

#### 5. JTI 重放存储优化

```
当前: `memory_jti_replay.go` + `sqlite/jti_replay.go` + `redis/jti_replay.go`
      已有 memreaper 做内存 GC

优化方向:
  a) 分层存储（基于使用频率）
     热（最近 5 分钟）: 内存 map + sample
     温（5-60 分钟）: 内存压缩 bitmap + 批量淘汰
     冷（>60 分钟）: 磁盘/redis + 懒加载
  
  b) 概率性验证（可选）
     对于非关键令牌操作（如 refresh 的旧令牌），允许小概率的遗漏检测
     使用 bloom filter 计数: 1/10000 概率的假阴性
  
  c) 业务分区
     不同租户的 JTI 存储物理隔离
     高音量租户不会污染其他租户的 JTI 存储
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 吊销集和令牌 TTL 的时钟差（令牌过期后吊销条目仍存在） | 吊销集的 TTL 上限 = 令牌最大 TTL + 时钟偏移容差（5 分钟） |
| 令牌瘦身后下游系统无法处理参考令牌 | 通过 discovery 的 `token_types_supported` 声明参考令牌，下游选择信任类型 |
| CDN 缓存中毒（被吊销的令牌仍被 CDN 缓存为"有效"） | 签名内省令牌的 TTL 由服务器控制（短 TTL） + CDN 不缓存 deny |
| DPoP bloom filter 误判导致合法请求被拒绝 | bloom filter 误判后回退到精确检查（非拒绝）；bloom filter 以 false > false 而非 false > deny |
| 分片不均衡（热点租户的 nonce 分片） | 使用一致性哈希 + 虚拟节点；监控分片大小并自动重新平衡 |

### 为什么值得做

**这是从"功能完整"到"生产就绪"的必经之路。** 协议覆盖和功能存在是采购评估的第一步，但生产运行中真正区分产品和玩具的，是这些运营层面的工程深度。

对于意图部署在大型企业（>10万用户）或 SaaS 服务（>100万用户）场景的 SSO 项目，以下是具体痛点：
- 进程内吊销集重启即空 = 滚更新/扩容期间已吊销的 access token 复活（安全漏洞）
- 2KB+ 的 JWT 在 10M 令牌规模下，每次验证的网络 IO + 解码成本堆积为 P50 的显著延迟
- DPoP nonce 的固定窗口 TTL 在 10K req/s 下导致存储膨胀和 GC 压力
- 未优化的内省路径是常见的 P99 性能热点

- **价值：** 高（安全修正（吊销集持久化）+ 规模性能优化）  
- **工作量：** L（四项均为明确、可验证、可独立交付的工作包）  
  - Phase 1：分布式吊销集持久化 - 最高安全收益（M）  
  - Phase 2：DPoP 非标伸缩 + JTI 分层存储（L）  
  - Phase 3：令牌瘦身 + CDN 友好内省（L）  
  - Phase 4：综合性能基准 + 调优（M）
- **依赖：** `tokenpolicy/`（已存在）、`revocation_set.go`（已存在）、`introspect_cache.go`（已存在）、`memreaper/`（已存在）、Redis/sqlite/postgres 持久化后端（均已存在）

---

## 方向 5：身份分析与多租户商业智能平台（Identity Analytics & Multi-Tenant BI）

### 现状

项目拥有以下可观测性设施：

| 能力 | 状态 |
|---|---|
| Prometheus 指标（令牌/API/会话/审计/条件访问等） | ✅ 完整 |
| 结构化审计事件记录 | ✅ `platform/audit` 完整 |
| Syslog/CEF/OCSF/Sentry 审计出口 | ✅ `auditsink/` 完整 |
| 管理员实时事件流（SSE） | ✅ `platform/sse` 完整 |
| 审计导出（JSON/CSV） | ✅ `audit/auditexport` 完整 |
| 审计查询与 facet 过滤 | ✅ `audit/handlers.go` 完整 |
| **多租户维度分析仪表盘** | ❌ **零实现** |
| **身份分析引擎（趋势/异常/模式）** | ❌ **零实现** |
| **导出报告（PDF/定时发送）** | ❌ **零实现** |
| **租户健康评分** | ❌ **零实现** |
| **MAU/DAU 趋势追踪** | ❌ **零实现** |
| **认证方法采纳率分析** | ❌ **零实现** |

### 缺口（grep 核验）

- `dashboard.*tenant\|tenant.*dashboard\|TenantDashboard`：**零实现命中**
- `analytics.*engine\|AnalyticsEngin\|analytics.*dashboard\|identity.*analytics\|IdentityAnalytics`：**零实现命中**
- `mau\|MAU\|dau\|DAU\|monthly.*active\|daily.*active`：**零实现命中**
  （`metrics/` 中的 Prometheus 指标是技术监控，非业务 MAU/DAU）
- `report.*export\|ReportExport\|report.*generat\|ReportGenerat\|scheduled.*report`：**零实现命中**
- `adoption.*rate\|AdoptionRate\|auth.*method.*breakdown\|method.*distribution`：**零实现命中**
- 无 `WithIdentityAnalyticsEngine`、`WithTenantHealthDashboard` 等配置选项
- 无 `AnalyticsStore` SPI 或 `TenantHealthScorer` SPI

### 范围

#### 1. 多租户身份分析仪表盘

```
为全局管理者和委托租户管理员（方向 1）提供不同粒度的分析面板:

全局管理员视图:
  ├── 平台概览
  │   ├── 总租户数 / 活跃租户数 / 不活跃租户数
  │   ├── 总用户数 / MAU / DAU（含趋势图）
  │   ├── 总令牌签发数 / 活跃令牌数
  │   └── 平台健康评分（聚合租户评分）
  │
  ├── 租户列表（排序: 按用户数/MFA率/风险评分）
  │   ├── 每个租户的 MAU 趋势
  │   ├── MFA 采纳率（%用户使用 MFA）
  │   └── 风险指标（异常事件数/锁定账户数/可疑登录数）
  │
  ├── 认证分析
  │   ├── 认证方法分布（密码/Passkey/MFA-TOTP/推送/SMS/SAML/OIDC）
  │   ├── 登录成功率 / 失败率 / 速率受限率
  │   ├── 平均登录耗时 P50/P95/P99
  │   └── 热门认证时间（时段热力图）
  │
  ├── 安全态势
  │   ├── 账户锁定事件趋势
  │   ├── 令牌吊销统计（自愿 vs 管理员 vs 自动）
  │   ├── 权限变更频率
  │   └── 异常检测触发率
  │
  └── API 使用分析
      ├── 最活跃的 OAuth client
      ├── 最活跃的 grant type
      └── API 错误率 / 延迟 P95

委托租户管理员视图（限于该租户数据）:
  ├── 租户概览
  │   ├── 成员数 / MAU / 新增成员 / 离职成员
  │   ├── 活跃会话数 / 平均会话时长
  │   └── MFA 强制率 / 当前符合率
  │
  ├── 成员分析
  │   ├── 登录频率分布
  │   └── 成员角色分布
  │
  ├── 连接分析（企业连接使用情况）
  │   └── 上游 IdP 的认证分布
  │
  └── 安全报告
      ├── 最近安全事件
      └── 合规检查表

租户健康评分:
  Score = weighted_sum(
      MFA采纳率 * 0.25,
      登录成功率 * 0.20,
      异常事件趋势 * 0.20,
      账户锁定率 * 0.15,
      API合规率 * 0.10,
      会话过期合规 * 0.10
  )
  
  评分区间:
    0.0-0.4: 危险（标红，建议管理员干预）
    0.4-0.7: 警告（标黄，建议优化）
    0.7-1.0: 健康（标绿）
```

#### 2. 身份分析引擎

```
分析引擎将原始审计事件转换为聚合指标和趋势线:

# 原始事件流:
#   login_succeeded {user, tenant, auth_method, ip, geo, time}
#   login_failed    {user, tenant, reason, ip, time}
#   token_issued    {user, tenant, grant_type, client_id, scopes, time}
#   token_revoked   {user, tenant, revocation_reason, time}
#   admin_action    {admin_id, tenant, action, target, time}

分析输出:
  ┌─────────────────────────────┐
  │  指标聚合器 (Time Bucket)     │
  │  按 5m/1h/1d/30d 分桶        │
  │  count, unique_user, p50/p95 │
  ├─────────────────────────────┤
  │  趋势检测器                   │
  │  环比增长、季节性模式、         │
  │  异常峰值（2σ 偏差）           │
  ├─────────────────────────────┤
  │  组成分析器                   │
  │  认证方法占比、Grant 类型分布、 │
  │  设备平台分布                  │
  ├─────────────────────────────┤
  │  归因引擎                     │
  │  ？为什么 MAU 下降了？          │
  │  → 某租户批量删除用户           │
  │  → 某客户端不再使用             │
  └─────────────────────────────┘

存储:
  - 原始数据: audit store（已有，默认 90 天 TTL）
  - 聚合数据: 新建 AnalyticsStore（内存/sqlite/postgres）
    - 按时间桶预聚合（避免全表扫描）
    - 保留策略: 5m 桶保留 7 天，1h 桶保留 90 天，1d 桶保留 3 年
```

#### 3. 定时报告与导出

```
支持计划报告:

| 报告类型 | 频率 | 接收者 | 格式 |
|---|---|---|---|
| 每日安全摘要 | daily | 租户管理员 | email (HTML) |
| 每周使用报告 | weekly | 租户管理员 | email (PDF) |
| 月度合规报告 | monthly | 合规团队 | PDF + CSV |
| 实时告警 | real-time | 运维团队 | webhook + email |

报告内容示例（每日安全摘要）:
  ┌─────────────────────────────────┐
  │   Daily Security Digest          │
  │   Tenant: Acme Corp              │
  │   Date: 2026-07-10               │
  │                                   │
  │   📊 Overview                     │
  │   Active Users: 1,234 (+12)      │
  │   Login Attempts: 45,678         │
  │   Success Rate: 97.2%            │
  │   MFA Adoption: 68% (+2%)        │
  │                                   │
  │   🚨 Alerts                       │
  │   Failed logins >5/user: 3 users  │
  │   New device logins: 45          │
  │   Admin actions: 12              │
  │                                   │
  │   🔐 Security                     │
  │   Locked accounts: 2             │
  │   Revoked tokens: 8              │
  │   Suspicious IPs: 1 (blocked)    │
  └─────────────────────────────────┘

API:
  POST   /api/v1/admin/analytics/reports          # 创建报告计划
  GET    /api/v1/admin/analytics/reports           # 列报告计划
  DELETE /api/v1/admin/analytics/reports/:id       # 删除报告计划
  POST   /api/v1/admin/analytics/reports/:id/run   # 立即执行
  GET    /api/v1/admin/analytics/queries           # 执行即时分析查询
```

#### 4. 分析 API 端点

```go
// 即时分析（无预聚合，直接从审计 + 指标存储计算）
// GET /api/v1/admin/analytics/mau?tenant_id=acme&range=90d
// Response:
// {
//   "data": [
//     {"month": "2026-05", "mau": 1234},
//     {"month": "2026-06", "mau": 1301},
//     {"month": "2026-07", "mau": 1156}
//   ],
//   "trend": "declining",
//   "change_percent": -11.2,
//   "anomaly": false
// }

// GET /api/v1/admin/analytics/auth-methods?tenant_id=acme&range=30d
// Response:
// {
//   "data": [
//     {"method": "password", "count": 45678, "percent": 45.2},
//     {"method": "passkey", "count": 23456, "percent": 23.2},
//     {"method": "totp_mfa", "count": 18900, "percent": 18.7},
//     {"method": "push_mfa", "count": 8900, "percent": 8.8},
//     {"method": "saml_federation", "count": 4123, "percent": 4.1}
//   ]
// }

// GET /api/v1/admin/tenants/:tid/health
// Response:
// {
//   "score": 0.82,
//   "level": "healthy",
//   "factors": [
//     {"name": "mfa_adoption", "score": 0.75, "weight": 0.25},
//     {"name": "login_success_rate", "score": 0.92, "weight": 0.20},
//     {"name": "anomaly_trend", "score": 0.85, "weight": 0.20}
//   ]
// }
```

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 租户数据量巨大（百万级用户） | 预聚合桶 + 按需查询原始数据；长范围（>30d）仅返回聚合数据 |
| 不同租户的自定义分析需求 | 租户维度的自定义指标存为 tenant 元数据；分析引擎根据租户配置选择指标 |
| 分析查询影响主请求路径 | 分析查询使用单独的只读副本/连接池；超时上限（5 秒） |
| 数据隐私（跨租户泄露） | 分析引擎强制租户隔离；全局管理员需要显式 scope override |
| 指标口径不同（什么是 MAU？登录算一次还是活跃会话算一次） | 统一指标字典（`/docs/metrics-definitions.md`）完全定义每个指标的计算方式 |
| 冷租户（长时间不活跃） | 健康评分为 0 时不自报告/告警（无意义）；仅记录"不活跃"标签 |

### 为什么值得做

**当 SSO 平台支持了所有协议、补齐了所有认证方法后，下一个问题就是：你怎么让管理员了解自己的租户在发生什么？**

目前项目的可观测性面是面向**运维**的（Prometheus 指标监控服务器的健康、延迟、吞吐量），但**不是面向业务的**——没有一个端点能回答以下任何一个问题：
- "我的租户 Acme Corp 上个月的 MAU 是多少？趋势是涨还是跌？"
- "MFA 采纳率在多租户中分别是多少？哪个租户最低？"
- "上周哪些 OAuth client 的令牌使用量异常增长？"
- "密码认证正在被 Passkey 取代吗？替代速度有多快？"

**缺少身份分析平台，意味着 SSO 运营团队对"谁在用什么方式使用身份系统"完全没有可见性。** 对于 SaaS 运营商，这意味着无法做客户成功分析（"租户的健康度如何？什么信号预示流失？"）；对于企业 SSO 管理员，意味着无法衡量安全策略推行效果（"强制 MFA 后采纳率从 30% 提升到 80%——但还有哪 20% 的用户没配合？"）。

这与 ROADMAP v5.0 #2d（租户用量计量）的区别在于：计量是计费导向的（本月签发了多少次令牌、消耗了多少配额），而分析是**运营决策导向的**——帮助管理员理解行为模式、跟踪安全策略效果、发现异常趋势。计量是 BI 的一个子集，而非 BI 本身。

- **价值：** 高（运营决策刚需 + 客户成功 + 安全合规可视化）  
- **工作量：** XL（分析引擎 + 预聚合管道 + 仪表盘 API + 定时报告）  
  - Phase 1：分析 API + 预聚合指标桶（L，零前端）  
  - Phase 2：租户健康评分 + 趋势检测（M）  
  - Phase 3：定时报告 + 导出（M）  
  - Phase 4：仪表盘前端 SPA（L）
- **依赖：** `platform/audit` 事件记录（已存在）、`platform/metrics`（已存在）、`EmailSender` 报告投递（已存在）、`domain/tenant` 多租户模型（已存在）

---

## 优先级摘要

| 优先级 | 方向 | 价值 | 工作量 | 核心交付物 |
|---|---|---|---|---|
| P0 | ③ 授权即服务 | 极高 | XL | REST 授权端点 + 条件引擎 + 决策日志 |
| P0 | ② 统一身份事件智能平台 | 极高 | XL | 统一事件存储 + 关联引擎 + 自动响应 |
| P1 | ④ 令牌生命周期大规模优化 | 高 | L（分阶段） | 持久化吊销集 + 令牌瘦身 + 分层缓存 |
| P1 | ① 跨设备身份连续性 | 高 | L~XL | Session Roaming + 并发会话 + Hybrid CA |
| P2 | ⑤ 身份分析与多租户 BI | 高 | XL | 分析引擎 + 仪表盘 API + 定时报告 |

**第一优先级执行建议：**
- 若团队偏向后端/基础设施 → 先做 ③ 授权即服务（Phase 1 纯后端，复用现有能力最多）
- 若团队偏向安全/运维 → 先做 ② 统一事件智能平台（Phase 1 事件存储加规则引擎）
- 若团队偏向产品化/客户旅程 → 先做 ① 跨设备身份连续性 Phase 1（Session Roaming）
- 性能修正（所有偏序中最高优）：④ Phase 1（持久化吊销集）应作为安全修正**最先做**

---

*本报告所有方向均经 grep 对抗核验确认为零实现。依赖于当前代码库中已有的基础设施，不引入新的外部依赖。*
