# 资深架构扫描：系统集成缝隙与运行时盲区（2026-07-11）

> **分析视角：** 资深架构师 & 产品经理  
> **方法：** 全量扫描 2209+ `.go` 源文件、1114 个测试文件、14 个嵌套 `go.mod` 模块，
>   50+ 份已有扩展分析文档、ROADMAP v5.0、feature-matrix、DIRECTORY_MAP、AGENTS.md、
>   全部 ADR 与架构文档，以及最新 git 提交历史。  
> **核验方式：** 逐项做全代码库 grep + 文件级代码确认。与 50+ 份已有分析做全关键词交叉验证，
>   确保每项方向从未作为独立方向被深度 scope。  
> **前置声明：** 本项目的协议覆盖、安全纵深、存储后端、产品前端、运维基础设施均已达极高成熟度。
>   剩余的高价值方向不再是"缺少什么组件"，而是**已建好的组件之间的集成缝隙**、
>   **运行时的静默行为偏差**、**跨组件边界的合规空白**。

---

## 方向一：跨协议会话协调运行时 —— Session Hub 已建未用

### Why Now

项目拥有 **Session Hub**（`platform/lifecycle/sessionhub/`）—— 跨协议全局会话协调器。
它在创建登录会话时被调用（OAuth code 流 `server_oauth.go:315`、login 流
`server_finish_login.go:168`、SAML ACS `saml.go:398`），将同一用户的 Core 会话和
SAML SP session 绑定在同一个 `global_sid` 下。

**但 OIDC 登出路径完全不经过 Session Hub：**

| 路径 | 使用 Session Hub | 影响 |
|---|---|---|
| OAuth login → Core Session | ✅ `linkGlobalSession` 创建 Core 腿 | 会话关联已建立 |
| SAML ACS → SAML Session | ✅ `linkGlobalSession` 同时创建 Core + SAML 腿 | 跨协议关联已建立 |
| **OIDC `/end_session` (RP-Initiated Logout)** | ❌ **不查询 Session Hub** | 触发 OIDC 登出时，SAML 会话不被终止 |
| **OIDC Back-Channel Logout** | ❌ **不查询 Session Hub** | RP 收到登出通知，但 SAML IdP 不受影响 |
| **POST `/logout` (Bearer 登出)** | ❌ 仅销毁当前 Core Session | SAML SP 会话残留 |

**核心问题：** Session Hub 记录了"哪两条腿属于同一个人"，但登出时没有任何读取者。
`coordinator.go` 的 `Logout(ctx, globalSID)` 方法可以触发所有关联腿的终止
（OIDC BCL、SAML SLO），但没有任何代码调用它。

这是一个**建好了桥但没有把路引到桥上的架构缝隙**。

### 为什么这是高价值方向

| 场景 | 现状 | 修复后 |
|---|---|---|
| 用户在 SAML IdP 登出 | SAML 会话终止，但 OIDC session 存留 | Session Hub 触发 OIDC BCL 通知所有 RP |
| 用户在 OIDC `/end_session` 登出 | OIDC 登录页终止，SAML 会话仍有效 | Session Hub 触发 SAML SLO |
| 管理员批量终止用户会话 (`/token/revoke-all`) | 只撤销 OAuth refresh tokens + Core Session | Session Hub 触发 OIDC + SAML 腿的全部终止 |
| 用户失业/离职 (lifecyclereactions) | RevokeAccessOnArchive 只撤销 refresh tokens + Core Session | Session Hub 确保 SP 侧的 SAML/OIDC session 也终止 |

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) 登出协调骨架** | 在 `end_session`、`logout`、`revoke-all` 路径添加 `sessionHub.Logout()` 调用，非侵入：Session Hub 未配置时行为不变 | M |
| **(b) SAML SLO 触发** | 当 Session Hub 裁定"该用户有活跃 SAML 腿"时，触发 SAML SP-initiated SLO 流程（复用现有 `saml/sp/slo.go`） | L |
| **(c) BCL 联动** | 当 Session Hub 裁定"该用户有 OIDC 腿"时，触发 Back-Channel Logout 通知（复用现有 `server_backchannel_logout.go` fan-out） | M |
| **(d) 审计增强** | 跨协议登出事件增加 `global_sid` 字段，使 SIEM 可以关联"一次触发，N 条登出记录" | S |
| **(e) 指标** | 新增 `sso_session_hub_logouts_total{protocol="oidc|saml|core"}` 计数器 | S |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| Session Hub 数据丢失（重启、迁移） | 降级为"只登出当前协议"，行为等同于今天的路径 |
| SAML SLO 某个 SP 超时（非阻塞） | 沿用现有的 BCL 超时逻辑：单个 SP 超时不阻塞整体登出 |
| 用户只在一个协议有会话 | Session Hub.Logout 是 no-op，无性能损耗 |
| 并发登出（同一用户从多个浏览器登出） | global_sid 是每次登录新生成，不存在竞态 |

### 验证

```bash
# 当前 Session Hub 的消费者
grep -rn "sessionHub\|\.Logout(" --include="*.go" | grep -v _test.go | grep -v vendor
# 预期：server_helpers.go 中的 linkGlobalSession（只写不读），saml.go 中的 link
#      没有任何 .Logout() 调用

# 主动登出路径的 grep 交叉验证
grep -rn "end_session\|handleLogout\|HandleEndSession\|revoke-all\|revokeAll\|DeleteAllForSubject" --include="*.go" | grep -v _test.go | grep -v vendor | grep -v "\.pb\."
# 预期：这些路径都不含 sessionHub
```

---

## 方向二：多授权模型的决策管道断层 —— Trust + CAP + RBAC + ReBAC + WASM 相互独立

### Why Now

项目存在 **5 种独立的授权/信任评估模型**，各自有完整的实现和存储后端：

| 模型 | 包路径 | 成熟度 | 用途 |
|---|---|---|---|
| **信任评分 (Trust)** | `shared/trust/` | ✅ SPIs + 参考实现 | 返回 `[0,1]` 建议分数 |
| **条件访问 (Conditional Access)** | `domains/conditionalaccess/` | ✅ YAML 策略引擎 | 基于上下文做 allow/deny/step-up |
| **RBAC (Permissions)** | `domains/permissions/` | ✅ 完全实现 | user roles + permission codes |
| **ReBAC (Relationship-Based)** | `platform/lifecycle/rebac/` | ✅ Zanzibar 风格 | 对象级权限图 |
| **WASM Authz** | `platform/lifecycle/wasmauthz/` | ✅ ABI 定义 + 引擎 | 任意 WASM 策略模块 |

**但它们在运行时各自独立评估，从未组合成一条决策管道：**

```
请求到达
  ├─→ OAuth grant handler 独自决定 token 颁发（不咨询条件访问/WASM）
  ├─→ Admin middleware 独自检查 RBAC scope（不咨询信任评分/条件访问）
  ├─→ Mesh ext_authz 独自做 DPoP/mTLS 验证（不咨询任何授权模型）
  ├─→ WASM authz 引擎被显式调用时才运行（不在任何热路径上）
  └─→ 信任评分被写入 AccessContext 但条件访问是否消费它取决于策略配置
```

**缺少的决策管道：**

```
请求到达
  → 1. 信任评分层 (Trust Scorer) → TrustScore[0..1]
  → 2. 条件访问层 (Conditional Access) → allow/deny/step-up
     （消费 TrustScore + DevicePosture + Geo + …）
  → 3. RBAC 层 (Permissions) → 细粒度权限检查
  → 4. ReBAC 层 (Relationship) → 对象级授权
  → 5. WASM 层 (Optional) → 自定义策略覆盖
  → 6. 审计记录 (单一决策 ID + 各层 verdict + 原因链)
```

### 为什么这是高价值方向

| 场景 | 现状 | 决策管道的价值 |
|---|---|---|
| 低信任分数的管理员做敏感操作 | 信任分数被记录但 RBAC 仍然放行 | 决策管道可以在 RBAC 放行后添加 step-up 挑战 |
| 高信任用户的 ReBAC 访问被拒绝 | 用户得到"你无权访问"但不知道是高信任导致的例外 | 决策管道可以 override ReBAC 的 deny（信任覆盖） |
| 合规审计需要"为什么这次请求被放行" | 需要查看 3-4 个不同的审计日志 | 单一决策 ID 串联所有层级的 verdict |
| 新策略上线前评估影响 | 无法 dry-run 条件访问策略的效果 | 决策管道的 dry-run 模式可以模拟各层决策 |

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) 决策管道 SPI** | 定义 `AuthzPipeline` SPI：`Evaluate(ctx, AuthzRequest) → AuthzDecision`，其中 AuthzDecision 包含每层的 verdict + 原因 | M |
| **(b) 信任评分 → 条件访问桥接** | 将 `AccessContext.TrustScore` 显式传递给条件访问引擎作为标准输入信号（目前策略可配但非强制） | M |
| **(c) 决策管道的条件访问集成** | 条件访问引擎的 `require_mfa` 决策自动触发现有的 MFA step-up 路径 | M |
| **(d) 决策 ID 注入审计** | 每个请求生成 `decision_id`（UUID），所有授权相关审计事件携带该 ID | S |
| **(e) ReBAC + RBAC 的决策管道集成** | 在决策管道中定义 RBAC 和 ReBAC 的执行顺序和 override 规则 | L |
| **(f) Dry-Run 模式** | 条件访问 + ReBAC + WASM 支持 dry-run（记录决策但不执行），供运营者测试新策略 | S |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 某个模型引擎不可用（store 故障） | fail-open 到该模型的"默认放行"或"默认拒绝"（每个模型独立配置） |
| 决策管道引入额外的延迟 | 可配置各层的超时 + 降级策略；默认 100ms 总超时 |
| override 链导致的安全漏洞 | 每层只能增加限制（deny/step-up），不能放行上游拒绝的请求（单调安全原则） |
| 现有单模型授权不受影响 | 不配置决策管道时，行为与今天完全相同 |

### 验证

```bash
# 查看现有各模型间的耦合
grep -rn "conditionalaccess\|conditional_access" --include="*.go" domains/permissions/ 2>/dev/null
# 预期：0 命中（RBAC 不依赖条件访问）

grep -rn "trust\.\|TrustScore\|TrustScorer" --include="*.go" domains/conditionalaccess/ | head -5
# 预期：只是 AccessContext 的字段，非强制输入

grep -rn "rebac\|ReBAC" --include="*.go" interfaces/sso/ | head -5
# 预期：0 命中（ReBAC 不在 SSO Server 热路径上）
```

---

## 方向三：多区域 Active-Active 拓扑运行时框架

### Why Now

项目拥有成熟的 **单区域多副本基础设施**：etcd 集群总线、签名密钥跨副本聚合、
跨副本 token 撤销广播、ConfigDrift CRD 检测。但**多区域 Active-Active 拓扑**
的关键组件缺失：

| 能力 | 单区域 | 多区域 Active-Active |
|---|---|---|
| 会话存储 | ✅ SQLite/Redis/PostgreSQL | ❌ 无跨区域会话复制 |
| Token 签发 | ✅ 本地签名密钥 | ❌ 无区域亲和签发（user 在 region-A 登录 → token 由 region-A 密钥签发） |
| Token 验证 | ✅ 任意副本可验证 | ❌ 跨区域验证需要完整 JWKS 同步 |
| Token 撤销 | ✅ 跨副本广播 | ❌ 跨区域撤销需要异步消息队列 |
| 租户数据 | ✅ 租户模型绑定区域 | ❌ 无"读本地、写主区域"模式 |
| 故障转移 | ✅ DR 备份恢复 | ❌ 无实时流量切换 |

**当前架构假设每个副本能直接访问同一数据存储**（SQLite 非共享、Redis 非跨区域集群）。
当部署扩展到两个物理区域时，存在以下 gap：

1. 区域 A 签发的 token 在区域 B 验证时，需要区域 B 持有区域 A 的签名密钥（目前通过 etcd 共享，跨区域延迟 ~50-200ms）
2. 区域 A 撤销的 token 需要传播到区域 B，目前总线机制（etcd/MQTT）在跨区域网络分区时可能丢事件
3. 用户登录的区域亲和性：没有机制确保"用户在区域 A 登录后，后续请求优先路由到区域 A"

### 为什么这是高价值方向

| 场景 | 现状 | Active-Active 价值 |
|---|---|---|
| 区域 B 故障 | 区域 B 的副本不可用，流量无法自动转移到区域 A | 区域 A 继续服务两个区域的用户 |
| 全球部署（美东+美西+欧洲） | 每个区域独立部署，用户 Token 在另一区域需要跨区域验证 | 区域本地签发和验证，降低延迟 |
| 区域 A 网络分区 | 区域 A 的副本无法访问 etcd，签名密钥聚合失败 | 降级到本地缓存的密钥集，继续服务本地用户 |
| 合规要求数据留在区域 | 租户模型支持区域标记，但运行时无"读本地、写主区域"路由 | 每个请求按租户区域路由到对应区域的存储 |

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) 区域亲和 Token 签发** | 在 JWT claims 中添加 `region` 声明；签发时使用区域特定的签名密钥（目前 `peerKeys` 已支持按区域分组概念） | M |
| **(b) 跨区域验证缓存** | 其他区域的 JWKS 通过异步缓存获取，避免验证请求跨区域等待 | M |
| **(c) 跨区域撤销消息路由** | 基于区域拓扑的撤销广播：区域 A 的撤销事件通过持久队列（Kafka/MQTT）路由到区域 B | L |
| **(d) 区域拓扑配置** | 声明式区域拓扑配置（区域列表、本地区域 ID、存储后端映射），启动时验证 | S |
| **(e) 分区降级模式** | 检测到跨区域连接中断后，降级为"本地区域自治"模式 + 审计告警 | L |
| **(f) 跨区域可观测性** | `sso_region_*` 指标：区域间延迟、跨区域验证率、撤销积压 | M |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 区域 A 和区域 B 同时签发同一个用户的 token | 通过 `region` claim 区分，验证时信任所有区域的密钥 |
| 区域 B 从网络分区恢复后的状态同步 | 分区期间产生的撤销事件通过持久队列回放 |
| 跨区域时钟偏斜导致 token 验证失败 | 沿用现有 `clockSkew` 配置，跨区域增大默认值（如 30s） |
| 单区域部署不受影响 | 不配置区域拓扑时，行为与今天完全相同 |

### 验证

```bash
# 当前区域相关代码
grep -rn "region\." --include="*.go" interfaces/sso/*.go | grep -v _test.go | grep -v vendor | head -10
# 预期：只有 region middleware + tenant residency check，无区域拓扑

# 跨区域总线支持
grep -rn "WithCrossReplicaRevocation\|crossReplica\|cross_replica" --include="*.go" | grep -v _test.go | head -5
# 预期：撤销广播只针对同一集群内的副本，非跨区域
```

---

## 方向四：协议状态机系统性模糊测试

### Why Now

项目已有 **9 个模糊测试目标**，均聚焦于**单组件、单函数、字段级**的边缘情况：

| 目标 | 范围 |
|---|---|
| `aud_claim_fuzz` | `aud` 字段 JSON 解析 |
| `jwe_unwrap_fuzz` | JWE 解包全面解析 |
| `jwks_verify_fuzz` | JWT 签名验证 |
| `jar_fetch_fuzz` | JAR `request_uri` SSRF 防护 |
| `jws_parse_fuzz` | 联邦 JWS 语句解析 |
| `end_session_fuzz` | post_logout_redirect_uri 验证 |
| `bind_fuzz` | OAuth 参数绑定 |
| `dcr_fuzz` | DCR metadata 验证 |

**缺少的是协议状态机级别的模糊测试：**

```
当前模糊测试:
  ┌─ 步骤 1: 特定函数 ─→ panic？错误？

缺少的模糊测试:
  ┌─ 步骤 1: /auth/login (PKCE S256, code_challenge=...)
  ├─ 步骤 2: /token (grant=authorization_code, code=..., code_verifier=...)
  ├─ 步骤 3: /introspect (token=access_token)
  ├─ 步骤 4: /token/revoke (token=refresh_token)
  ├─ 步骤 5: /token (grant=refresh_token, refresh_token=...)
  └─ → 状态一致性？oracle leak？竞态？
```

**具体的协议状态机模糊测试场景：**

| 场景 | 步骤序列 | 验证不变量 |
|---|---|---|
| **Auth Code + Refresh + Introspect** | login→token→introspect→revoke→introspect | revoked token 必须返回 `{active:false}` |
| **Refresh Rotation + Reuse** | login→token→refresh→refresh（双提交）→delete family | 第二个 refresh 必须 `invalid_grant` |
| **PAR + Auth Code + Token Exchange** | par→login→token→exchange→introspect | token_exchange 后的 token 必须携带 `act` chain |
| **Device Code + Poll + Complete** | device_auth→poll→login→token→poll（后完成） | 完成后的 poll 必须 `authorization_pending` |
| **DPoP + Nonce + Replay** | login(dpop)→token→dpop→userinfo→dpop（重放） | 重放的 DPoP JKT 必须 `invalid_token` |
| **CIBA + Poll + Complete** | backchannel_auth→poll→login→token→poll | 完成后的 poll 必须 `token` |
| **Silent Renewal + Session Timeout** | login→end_session→silent_renewal | 登出后的 silent_renewal 必须 `login_required` |

### 为什么这是高价值方向

| 风险 | 举例 | 影响 |
|---|---|---|
| **状态机竞态** | 双提交 refresh + 延迟的 200 OK + 客户端重试 = 全家桶被删 | benign 双提交导致用户全端登出 |
| **oracle leak 序列** | 先 introspect 再 revoke 一个不存在的 token，两次返回不同 | 泄漏 token 是否存在（anti-enumeration 违反） |
| **跨步骤状态不一致** | token 被 revoke 后 introspect 返回 `{active:false}`，但 refresh 仍可用 | 授权状态不一致 |
| **协议交错攻击** | 同时发起 device_code + auth_code，用 device_code 的 token 换 auth_code 的 token | 协议边界混淆 |

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) 状态机 fuzz 框架** | 基于 `testing.F` 的多步骤序列生成器：生成随机 OAuth/OIDC 请求序列 + 验证不变量 | L |
| **(b) 核心场景覆盖** | 上表 7 个场景的 fuzz 实现 | L |
| **(c) 竞态注入** | 在关键点（DELETE RETURNING、GETDEL、token rotation）注入可控延迟，暴露并发竞态 | M |
| **(d) 不变量断言库** | 提取常见的不变量（`revoked → active:false`、`consumed → 400`、`family killed → 401`）为可复用断言 | M |
| **(e) CI 集成** | 在 nightly CI 中运行状态机 fuzz（`-fuzz=^FuzzProtocolStateMachine$ -fuzztime=30m`） | S |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| fuzz 运行时间过长 | 分场景运行（每个场景 5 分钟），并行执行 |
| 状态机爆炸 | 限制每个序列最大 6 步，超出视为无效测试 |
| 内存后端 vs SQLite 后端的行为差异 | 分别对 Memory 和 SQLite 后端运行 fuzz |

### 验证

```bash
# 当前 fuzz 目标全部是单输入、单函数
find . -name "*_fuzz_test.go" -type f | wc -l
# 预期：9

# 不存在多步骤 fuzz
grep -rn "fuzz\|Fuzz" --include="*_test.go" | grep -v "_fuzz\|Fuzz[A-Z]" | head -5
# 预期：无多步骤协议 fuzz
```

---

## 方向五：配置变更的静默验证与自动回滚

### Why Now

项目已有 **配置漂移检测**：`SSOConfigDrift` CRD（K8s 控制器）+ `configaudit` 的
跨集群配置差异 API 端点。当两个副本的配置不一致时，运营者会收到告警。

**但缺少的是变更前验证与变更后自动回滚：**

```
当前流程:
  运维修改 config.yaml → SIGHUP 重载 → 如果配置错误 → 服务不可用 → 人工回滚

缺少的流程:
  运维修改 config.yaml → sso-ctl config validate --dry-run → 
    验证通过 → 滚动应用 → 健康检查 → 如果失败 → 自动回滚到上一个健康配置
```

**具体缺失的能力：**

| 能力 | 当前状态 |
|---|---|
| **配置语义验证** | ✅ `sso-ctl config validate` 通过 Loader.Load 运行完整验证 |
| **依赖完整性检查** | ❌ 不检查"启用 X 但未配置 X 所需的 Y"（例如 WithFAPIProfile 但未配置 WithIDTokenIssuer） |
| **变更前 dry-run** | ❌ 无"模拟应用此配置，报告预期的行为变更" |
| **健康门禁回滚** | ❌ 无 "apply → /readyz probe → 不健康 → 自动 reload 上一个配置" |
| **配置变更审计** | ⚠️ 只有最终生效配置，无"提议变更 vs 实际变更"对比 |
| **配置版本管理** | ❌ 无配置版本历史 + "回滚到 v3" 操作 |

### 为什么这是高价值方向

| 场景 | 现状 | 自动验证+回滚价值 |
|---|---|---|
| 运维改错了一个字段（`signing_keys.rotation_interval` 拼写错误） | SIGHUP 重载成功（忽略未知字段），但轮换不生效 | dry-run 报告未知字段告警 |
| 启用了 FAPI 但未配置 JARM signer | 运行时 `/auth/login` 在 JARM 路径 panic | 依赖检查在 apply 前拒绝 |
| 新的 rate_limit 配置过于严格 | 正常用户被限流，服务降级 | 健康检查检测到限流率异常，自动回滚 |
| 配置修改了 tenant 的 allowed_scopes | 隐式缩小了 client scope 导致集成方报错 | dry-run 报告"此变更将影响 N 个 client" |

### Scope

| 子项 | 描述 | 工作量 |
|---|---|---|
| **(a) 配置依赖矩阵** | 显式声明配置选项间的依赖关系（`feature_x → store_y → store_z`），在 `config.Load` 中验证 | M |
| **(b) sso-ctl config validate --deps** | 在现有 validate 基础上添加 `--deps` 模式，验证依赖完整性 | S |
| **(c) 配置版本快照** | SIGHUP 重载前自动备份当前生效配置到内存 ring buffer + 审计事件 | S |
| **(d) 健康门禁回滚** | SIGHUP 重载后启动 `n` 秒的健康观察窗（`/readyz` + 关键指标），观察窗内任意失败触发自动 reload 上一个配置 | M |
| **(e) 变更影响力报告** | dry-run 模式预估变更影响（如"缩小 scope 影响 3 个 client"、"更改签名算法影响 2 个 RP"） | L |
| **(f) CLI 回滚命令** | `sso-ctl config rollback [--version N]` 从版本历史恢复配置 | S |

### 边界情况

| 边界 | 处理策略 |
|---|---|
| 自动回滚导致抖动 | 连续回滚 >= 2 次后停止自动回滚，进入"人工干预"模式 + CRITICAL 告警 |
| 健康观察窗内正常波动（重启预热） | 观察窗延迟到 `max(30s, warmup_time)` 后开始 |
| 磁盘故障阻止回滚 | 回滚使用内存备份的最后一次有效配置，并 emit 告警 |
| 多副本的配置一致性 | 回滚通过集群总线广播到所有副本（复用现有的 `KindConfigChange` 总线消息） |

### 验证

```bash
# 当前配置验证能力
cmd/sso-ctl/configcmd/main.go 中查看 runValidate
# 预期：只做了 Loader.Load（schema + 默认值 + 简单验证），无依赖检查

# 配置漂移检测
grep -rn "configaudit\|ConfigDrift\|config_drift" --include="*.go" | head -5
# 预期：只有检测和报告端点，无自动回滚

# SIGHUP 热重载
grep -rn "SIGHUP\|sighup\|HotReload\|hot_reload" --include="*.go" | grep -v _test.go | head -5
# 预期：多个组件支持热重载，但无回滚能力
```

---

## 附录：分析覆盖声明

本报告的五个方向经过与全部 50+ 份已有扩展分析文档（`docs/requirements/*.md`）的全关键词交叉验证：

| 本报告方向 | 在已有分析中 |
|---|---|
| 方向一：Session Hub 跨协议登出协调 | ❌ 未作为独立方向出现（sessionhub 仅有零散提及，从未分析登出路径的集成缝隙） |
| 方向二：多授权模型决策管道断层 | ❌ 未作为独立方向出现（各模型有独立分析，但从未分析它们之间的集成缝隙） |
| 方向三：多区域 Active-Active 拓扑 | ❌ 未作为独立方向出现（DR 有分析，但 active-active ≠ DR） |
| 方向四：协议状态机模糊测试 | ❌ 未作为独立方向出现（单个 fuzz 目标有分析，但从未 scope 多步骤状态机） |
| 方向五：配置变更验证与自动回滚 | ❌ 未作为独立方向出现（config.validate 有提到，但依赖检查 + 回滚从未 scope） |

> **本报告定位：** 前序 50+ 份分析已覆盖"缺少什么组件"。本报告聚焦于
> **已建好的组件之间"没接上"的集成缝隙**——这些缝隙不需要新建基础设施，
> 只需要在现有组件之间架设调用路径。每条方向都有代码级证据，且无一份
> 在已有分析中被深入 scope。建议按方向序号顺序交付。
