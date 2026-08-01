# Architect Expansion: Five High-Value Directions (2026-07-11)

> **Analyst:** Architect Agent | **Method:** Full codebase scan (2269 Go files, 15 nested modules)
>
> **前置声明：** 经过 60+ 轮已有分析（docs/requirements/ 现存 67 个文件），本项目在协议覆盖、基础设施、
> 企业治理、合规、前端产品、运维等方面已达到行业顶级水平。本文不再重复"方向型"的分析（OID4VC、
> Terraform Provider、IGA、PQC 等已被覆盖），而是聚焦于**当前代码中实证空白、但投入产出比高、
> 并能与既有能力产生化学反应的 5 个方向**。每条方向均经过 grep 对抗核验（默认"它可能已实现"，逐项读码证伪）。

---

## 方向一：状态协议 Fuzzing 框架（Stateful Protocol Fuzzing）

### 为什么需要它

项目已有 10+ 个 stateless fuzz targets（`FuzzBindParams`、`FuzzVerifyCompactJWS`、
`FuzzJWEUnwrap`、`FuzzAudClaimUnmarshal`、`FuzzParseStatement`、`FuzzValidateDCRMetadata`、
`FuzzComposePostLogoutTarget`、`FuzzIsJARFetchableURI`、`FuzzIsRequestURIAllowed` 等），
覆盖单步输入解析。4 个 chaos 测试（JTI replay、clock jump、panic recovery、refresh rotation）
覆盖特定并发场景。但**没有任何 stateful multi-step fuzzing**。

OAuth 2.0 / OIDC 协议的核心复杂度在于**多步状态机**：

```
设备码流：   /device/code → 用户输入 code → /device/verify → /token → 轮询 → 超时 → 重试
授权码流：   /auth/login → consent → /token → refresh → 重用 → family kill → 再交换
CIBA 流：   /backchannel-authentication → 轮询 auth_req_id → 用户批准 → /token
PAR → JAR： /par → /auth/login (request_uri) → /token → 携带不一致的参数重放
```

这些状态机中，**步骤顺序变异、状态回滚、并发交织、超时边界、token 重用与撤销的时序**是
协议实现中最常出现安全 bug 的源头（TOCTOU、step-skip、state confusion、race condition）。
真实世界的案例：OAuth 实现中的 "mix-up attack"、refresh token 旋转中的 "race condition window"、
device code 流的 "polling amplification"。

### 当前代码证伪

```bash
# 全项目不存在 stateful fuzz / multi-step fuzz / scenario fuzz
grep -rn "stateful.*fuzz\|fuzz.*scenario\|multi.*step.*fuzz\|flow.*fuzz\|fuzz.*flow\|sequence.*fuzz" . --include="*_test.go"
# → 0 命中（排除 stateless 单步目标后）
```

已有 4 个 chaos 测试是 **pre-scripted 场景**（人工编写断言），不是 **fuzzer 自动生成的状态序列**。
差异在于：chaos 测试验证已知风险，fuzzing 探索未知状态。

### 具体做什么

1. **状态机建模**：为每个 OAuth 流定义一个 formal state machine（状态 = 当前 phase，事件 =
   HTTP 调用、超时、用户交互），用 Go 的 `fsm` 或手写状态表表示合法/非法转换。
2. **Fuzzing 引擎**：`go test -fuzz` 生成随机状态序列（合法转换 + 非法跳转 + 并发交织 + 超时注入），
   每个序列在一个 `httptest.Server` + `*sso.Server` 实例上回放。
3. **断言钩子**：序列执行完后验证：
   - 无 token 泄漏（过期 token 不能再使用）
   - 无 family 重用（旋转后的 refresh token 收到 `invalid_grant`）
   - 无跨用户/跨客户端 token 混淆
   - 审计事件序列与协议步数一致
4. **初始目标流**（按风险排序）：
   - 授权码：login → consent → exchange → rotate → reuse → family kill → re-login → exchange
   - 设备码：device → poll → user_code 输入 → poll → timeout → re-device → verify → exchange
   - CIBA：auth_req_id → poll → approve → poll → token → rotate → poll with old
   - PAR + 授权码：par → auth (request_uri) → 修改 query → auth → token
   - Refresh 旋转 + 并发双提交：refresh → 同时两个 refresh → 两个 token

### 边界情况要点

- 状态机必须排除**逆向不可能**的序列（如 exchange 后登录不应该产生新的 auth code），
  否则 fuzzer 生成大量无效序列浪费算力
- 并发交织需要 hook 关键点（store write、token issue），在 hook 点注入延迟
- 超时边界：`device_code` expires_in=0、`auth_code` TTL 刚好在 exchange 时过期、
  `refresh_token` absolute_max_lifetime 在旋转瞬间过期
- 跨用户混淆：一个用户获取 code，另一个用户交换它（当前 anti-enumeration 应该拒绝，
  但 fuzzer 应自动发现是否有遗漏路径）

### 价值评估

| 维度 | 评价 |
|---|---|
| **安全 impact** | 高 — 多步状态机 bug 是 OAuth 实现中最高危的漏洞类别之一 |
| **投入** | 中（~1500 行建模 + 引擎代码 + CI 集成） |
| **差异化** | 极高 — 目前无主流 OAuth 项目做系统化的 stateful fuzzing |
| **与既有能力的关系** | 复用现有 `test/chaos/` 的 httptest wiring 和 `*sso.Server` 构造模式 |
| **可维护性** | 每次新增 grant 只需加状态表，引擎和断言钩子通用 |

---

## 方向二：独立可部署的边缘 Token 验证代理（Edge Token Proxy）

### 为什么需要它

项目提供：

- `interfaces/ssoclient/rs` — Go 资源服务器 SDK（middleware、introspect、validate、DPoP 验证）
- `interfaces/sso/mesh_authz.go` — Envoy ext_authz HTTP endpoint（sidecar 调用）
- `infrastructure/extauthz/` — Envoy ext_authz gRPC endpoint（sidecar 调用）

但所有这些都要求**调用方是 Go 程序，或部署了 Envoy sidecar**。对于非 Go 服务（Python/Node/Java/.NET/Rust），
集成路径是：

```
服务 → 内部 HTTP 调用 /mesh/ext-authz → SSO 服务端
```

这带来了：
- **远程调用延迟**：每个请求都需穿过服务网格到达 SSO 实例，而非本地校验
- **SSO 实例负载**：ext_authz 端点和 `/userinfo` 成为所有网格流量的瓶颈
- **语言绑定问题**：没有标准化的 OAuth 2.0 Token Proxy 协议（如 Pomerium/Ory Oathkeeper 的模式），
  每个运行时团队各自实现 token 校验

### 当前代码证伪

```bash
# 不存在 standalone 可部署的 token proxy 组件
grep -rn "TokenProxy\|token_proxy\|proxy.*validate\|oauth.*proxy\|sidecar.*proxy" . --include="*.go" | grep -v "_test\|ext_authz\|grpc_gateway\|gateway_test"
# → 仅 ext_authz 端点配置，无独立 proxy

# ssoclient/rs 是 Go library，不可独立部署
ls interfaces/ssoclient/rs/*.go  # middleware.go, validate.go, dpop.go — 全是 library 代码
```

### 具体做什么

构建一个 **独立的、可部署的边缘 Token 验证代理**（类似 Ory Oathkeeper 但更专注），作为
SSO 的 companion process 部署。

核心功能：

1. **Token 验证管道**：
   - 接收 HTTP 请求，提取 Bearer/DPoP proof/mTLS 证书
   - 本地验证 JWT 签名（缓存 JWKS，singleflight 避免 thundering herd）
   - 可选回退到 `/token/introspect`（适合 opaque token 或签名验证失败降级）
   - DPoP proof 验证（`htm`/`htu`/`ath`/`nonce`）
   - mTLS `cnf.x5t#S256` 验证
   - 结果缓存：TTL 缓存允许通过/拒绝决策（introspect 结果按 `sub+client_id+scope` 做缓存键）

2. **声明转换管道**：
   - 基于路由的 claim 映射（`/api/v1/*` → 删除敏感 claim，只留 `sub` + `scope`）
   - Scope-based downscoping（`/admin/*` 要求 `admin:read`，否则注入降级 claim）
   - 自定义头注入（把 `sub` 和 `email` 映射为 `X-Auth-User` / `X-Auth-Email`）

3. **运维面**：
   - `GET /livez` / `GET /readyz`（readyz 检查上游 SSO 可达性 + 本地 JWKS 缓存新鲜度）
   - Prometheus 指标：验证决策分布、缓存命中率、上游延迟
   - 配置热重载：路由规则、scope 映射、缓存 TTL 均可通过 SIGHUP 或 HTTP endpoint 更新

### 边界情况要点

- **JWKS 缓存失效时序**：SSO 侧密钥轮换后，proxy 缓存的旧 JWKS 会短暂验证通过已撤销 token。
  需要 TTL-based 被动失效 + `/mesh/authz` bus 主动失效（复用 `cluster.Bus`）
- **DPoP nonce 同步**：proxy 作为中间层，nonce 是从上游 SSO 获取还是 proxy 自己签发？
  推荐 proxy 传递 SSO 的 nonce（存于 `WWW-Authenticate: DPop nonce="..."`），
  proxy 不做 nonce 独立管理
- **introspect 缓存中毒**：introspect 结果缓存后，上游撤销 token 时 proxy 仍允许。
  解决方案：短 TTL（15-30s）+ bus 失效订阅
- **语言无关性**：二进制分发（单一静态链接 Go binary），零运行时依赖

### 价值评估

| 维度 | 评价 |
|---|---|
| **产品 impact** | 高 — 消除"非 Go 服务集成 SSO"的最后障碍 |
| **投入** | 中（~3000 行，独立 Go 模块，不修改核心） |
| **差异化** | 中 — Pomerium/Oathkeeper 已存在，但本项目可以做到更紧密的 upstream 集成 |
| **与既有能力的关系** | 复用 `ssoclient/rs` + `cluster.Bus` + `shared/security` 的全部验证逻辑 |
| **可维护性** | 与 SSO 共用同一验证代码路径，不会 drift |

---

## 方向三：跨组织 Workload 身份联邦（Cross-Org SPIFFE ↔ OAuth Bridge）

### 为什么需要它

当前支持三种 workload 身份模式：

| 模式 | 范围 | 实现 |
|---|---|---|
| 云 workload identity（GCP/AWS/Azure） | 在**同一云账号**内作为 client auth | `securityverify/workload_identity.go` |
| SPIFFE JWT-SVID token-exchange | 在**同一信任域**内做 token exchange | `security/spiffe_svid.go` |
| B2B 租户协作（cross-tenant） | 预置**用户级别**的幽灵记录 | `domains/tenant/tenant_collab.go` |

但缺少的是：**Org A 的 Kubernetes 工作负载（持有 Org A 的 SPIRE 签发的 SPIFFE SVID）自动获得
Org B 的访问令牌，无需在 Org B 预注册 client**。

场景：

```
Org A 的 payment-service 需要调用 Org B 的 invoice-api
Org A: SPIFFE trust domain "org-a.example.com", workload "payment-service"
Org B: OAuth 资源服务器，只接受 token（不部署 SPIRE）

当前路径：Org A 运维在 Org B 手动注册 client → 获取 client_secret → 流量
目标路径：payment-service 用 SVID 直接兑换 Org B scoped token，零手动配置
```

### 当前代码证伪

```bash
# SPIFFE 跨信任域联邦不存在
grep -rn "SPIFFE.*federat\|trust.*domain.*federat\|cross.*domain.*identity\|spiffe.*cross" . --include="*.go"
# → 0 命中

# TenantCollaborationStore 是用户级别的，不是 workload 级别的
grep -rn "TenantCollaborationStore\|ExternalUserStore" . --include="*.go" | head -3
# → 用户幽灵记录 + B2B 成员管理，不涉及 workload 身份
```

### 具体做什么

1. **联邦信任策略注册**：Org B 通过 admin API 注册一个 `WorkloadTrustPolicy`：
   ```yaml
   trust_domain: "org-a.example.com"
   spiffe_jwks_url: "https://org-a.example.com/.well-known/spiffe-jwks"
   allowed_workloads:
     - spiffe_id: "spiffe://org-a.example.com/ns/prod/sa/payment-service"
       scopes: ["invoice:read", "invoice:write"]
       max_token_ttl: "1h"
   ```

2. **SVID → Access Token 兑换端点**：新增 `POST /token` grant_type=
   `urn:ietf:params:oauth:grant-type:spiffe-token-exchange`（非标准，或复用
   token-exchange 的 actor_token + actor_token_type=spiffe），验证：
   - SVID 签名（通过信任域的 JWKS URL）
   - SVID 的 trust domain 匹配已注册的策略
   - SVID 的 spiffe_id 在白名单中
   - 发行 scoped access token（有效期 capped by 策略）

3. **信任域 JWKS 发现与缓存**：
   - 首次加载信任域策略时，从 `.well-known/spiffe-jwks` 获取 JWKS
   - 定期刷新 + 缓存（复用现有的 `servercache/jwks_singleflight.go` 模式）
   - 失败语义：JWKS 不可达 → fail-closed（`invalid_client`）→ 不暴露信任域是否存在

4. **Admin 管理面**：
   - CRUD `WorkloadTrustPolicy`（`POST /api/v1/admin/workload-trust`）
   - 审计事件：trust domain 添加/删除、workload 权限变更
   - 策略预览：`POST /api/v1/admin/workload-trust/evaluate` — 测试一个 SVID 能获得什么 scope

### 边界情况要点

- **SVID 过期 vs Token 过期**：SVID 是短期的（SPIRE 默认 1h），token 也是短期的（默认 15m）。
  哪个来控制？设计原则：SVID 是客户端身份证明，token 时长由策略的 `max_token_ttl` 限制，
  但**不超过 SVID 剩余有效期**（防 SVID 过期后 token 仍有效）
- **信任域 JWKS 的信任根**：JWKS URL 如果被劫持，攻击者可伪造 SVID。需要：
  初始指纹绑定（operator 首次录入时 pin JWKS thumbprint），或通过 OpenID Federation 的
  trust chain 锚定信任域的公钥
- **跨组织撤销**：Org A 撤销了 payment-service 的 SVID 签发权，但 Org B 毫不知情。
  解决方案：短 token TTL（5m）+ token-exchange 每次都需要新鲜 SVID
- **工作负载实例级别的吊销**：如果一个具体的 pod 被攻破，需要能吊销**那个 pod** 的 SVID
  （SPIFFE 支持 SPIFFE Key Revocation List，或通过 SVID 中的 `eid` claim 做细粒度 JTI 吊销）

### 价值评估

| 维度 | 评价 |
|---|---|
| **产品 impact** | 高 — B2B SaaS 和多集群组织间的零接触服务到服务身份 |
| **投入** | 中（~2500 行，核心 + admin API + 测试） |
| **差异化** | 极高 — 目前无主流 OAuth 产品支持 SPIFFE 跨域联邦 token-exchange |
| **与既有能力的关系** | 复用 token-exchange grant 框架、SPIFFE JWT-SVID 验证、JWKS 缓存、cluster bus |
| **可维护性** | 新 grant type，独立于现有流，不修改已有行为 |

---

## 方向四：Active-Active 多区域部署拓扑（Multi-Region Active-Active）

### 为什么需要它

当前部署模型：

| 维度 | 当前能力 | 限制 |
|---|---|---|
| DR | Warm-standby（RPO/RTO targets，`test/dr/` 框架） | 切换需要手动或半自动触发，切换期间不可写 |
| 多副本 | Bus 广播（`cluster.Bus`），Redis 共享存储 | Bus 无跨区域保证，Redis 感知延迟 |
| 读取扩展 | SQLite/Redis 读取可本地 | 写流量必须回到主区域 |
| 区域选择 | 租户数据驻留（`region/`） | 限制了**数据存放地**，不是**流量路由** |

缺失的是：**两个或更多区域同时为同一个租户提供服务，任一区域故障不影响可用性**。
这与 DR warm-standby 的区别是：active-active 下两个区域都在服务读+写流量，
故障时只丢失 ~50% 容量（而非完全不可用）。

### 当前代码证伪

```bash
# 没有多区域写合并逻辑、跨区域冲突检测、split-brain prevention
grep -rn "split.brain\|multi.master\|read.local.*write.global\|conflict.*reconcile\|CRDT\|global.*lock" . --include="*.go"
# → 0 命中（identityMergePolicy 是 identity linking 的冲突策略，不是数据复制）

# Redis doc 提到了跨区域语义的挑战
cat infrastructure/redis/doc.go | grep -A3 "cross-region"
# → 仅文档提示，无实现
```

### 具体做什么

1. **存储层按类型分类**：

| 数据类型 | 模式 | 示例 |
|---|---|---|
| 租户配置 | Read-local, write-global（通过 bus + 乐观锁） | Client、Tenant、Permission |
| 会话令牌 | Write-local, read-local（不跨区域复制） | Session、AuthCode、DeviceCode |
| 吊销状态 | Write-global（通过 bus 广播 + local cache） | Revocation、JTI Replay |
| 审计事件 | Write-local + 异步汇聚到中心 | Audit Events |

2. **Bus 升级为跨区域消息总线**：
   - 当前 `cluster.Bus` 是单区域（内存 / Redis PubSub / MQTT）
   - 跨区域扩展：添加区域感知的 topic（`sso/us-east-1/revoke`），
     每个区域订阅所有区域的 topic + 本地发布
   - 消息至少送达一次保证 + 去重（幂等事件如 revoke 天然可去重）
   - 区域间延迟监控：`sso_cross_region_bus_lag_seconds` 指标

3. **Latency-aware 区域路由**：
   - 区域端点注册到租户发现文档（`.well-known/openid-configuration` 的 `additional_issuers`）
   - 客户端选择最近区域（标准 DNS 地理路由 + HTTP `region_hint` 参数）
   - Token `iss` claim 包含发行区域（`https://us-east-1.sso.example.com`），
     跨区域验证时通过 JWKS 跨区域 fetch 验证

4. **写冲突检测**：
   - 租户配置使用乐观锁（`Client.Version` 或 `updated_at` 时间戳）
   - 跨区域更新冲突 → 409 + 冲突详情（非静默覆盖）
   - 不适合乐观锁的数据（如 session）不跨区域复制——使用亲和性路由

5. **部署模型**：提供一个 `docker-compose.multiregion.yaml` + 配置模板，
   操作手册说明跨区域 k8s 部署（每个区域一个 StatefulSet + 一个区域级的 Redis Sentinel）

### 边界情况要点

- **Token `iss` 不匹配**：区域 A 发行的 token 在区域 B 验证时，JWKS URL 不同。
  解决方案：每个区域发布其自身的 JWKS（独立 kid），但共享签名密钥池——
  或所有区域使用同一域名（通过全局负载均衡），此时 `iss` 一致
- **时钟偏差**：区域 A 和 B 之间的时钟 skew 导致 token `nbf`/`exp` 不一致。
  需要 `clock_skew_tolerance` 配置，且跨区域 token 验证时 tolerance
  设置为 2x 区域间最大 NTP 偏差
- **租户迁移**：租户从区域 A 迁移到区域 B 时，旧 token 在 A 仍有效直到过期。
  支持 `POST /api/v1/admin/tenants/:id/migrate-to-region` 操作，
  新旧区域双写一段时间后切换

### 价值评估

| 维度 | 评价 |
|---|---|
| **产品 impact** | 极高 — 对金融/医疗/全球化企业的采购必备条件 |
| **投入** | 大（~5000 行，涉及存储层、bus、区域路由、admin API、测试） |
| **差异化** | 高 — 开源 SSO 中（Keycloak、Ory）均无原生 active-active 支持 |
| **与既有能力的关系** | 扩展 `cluster.Bus`、`region/`、DR 框架；复用租户模型 |
| **可维护性** | 存储层模式清晰，新 store 只需决定其复制类 |

---

## 方向五：硬件锚定设备身份与 Attestation-Bound 会话

### 为什么需要它

当前设备相关能力：

| 能力 | 实现 |
|---|---|
| WebAuthn 平台 passkey（设备绑定的密钥） | `domains/authenticators/webauthn/` |
| 受信设备（"记住此设备"跳过 MFA） | `trustedDeviceStore` + `/me/devices*` |
| mTLS 客户端证书认证 | `certificate.go` + `ClientCertExtractor` |
| DPoP token 绑定到特定 HTTP 客户端 | DPoP proof + `cnf.jkt` claim |

但所有这些都**不提供硬件级 attestation**——即密码学证明"这句话是在某个特定硬件设备上签名
的，且该设备的硬件是未被篡改的"。

具体缺失：

- WebAuthn **attestation 验证**：`domains/authenticators/webauthn/attestation_policy.go`
  存在 attestation policy 框架，但没有完整的 attestation statement 验证管道
  （Android KeyStore attstn、Apple App Attest、TPM attstn、Packed attstn）
- 无 **TPM 2.0 远程证明**：不能验证 Linux 设备的启动度量（measured boot）和 PCR 值
- 无 **Android SafetyNet / Play Integrity** 集成
- 无 **Apple DeviceCheck / App Attest** 集成

### 当前代码证伪

```bash
# 没有 TPM attestation / Android attestation / Apple App Attest
grep -rn "TPM\|tpm.*attest\|android.*attest\|keystore.*attest\|safetynet\|play.*integrity\|devicecheck\|app.*attest\|Apple.*Attest\|hardware.*attest" . --include="*.go" | grep -v "_test.go\|Fuz\|wasi\|wasm\|middleware\|x509"
# → 0 命中

# WebAuthn attestation policy 存在但只是 policy 框架（验证信任锚），不是完整 attestation 验证
wc -l domains/authenticators/webauthn/attestation_policy.go
# → 只有 provider 列表 + 策略评估，无 attestation 语句解析
```

### 具体做什么

1. **Attestation 验证框架**：
   - 定义 `AttestationVerifier` SPI（验证 raw attestation statement → 设备身份声明）
   - 内置 verifier：
     - **Android KeyStore / Play Integrity**：验证 Android 设备的 hardware-backed key attestation
       certificate chain，提取设备标识（bootloader 状态、设备完整性）
     - **Apple App Attest**：验证 Apple 设备的 attestation object，验证 App ID + 设备唯一 ID
     - **TPM 2.0**：验证 AIK（Attestation Identity Key）签名 + PCR 引用，验证 OS 完整性
     - **WebAuthn Packed / TPM / Android** attestation：解析 WebAuthn 注册时的 attestation
       statement，验证信任锚链（参考 MDS 3.0）

2. **Attestation-Bound Session**：
   - 登录时如果设备提交了 attestation，在 session 中记录 `device_attestation` claim
   - Session trust 初始值 = base + 设备 attestation 等级加分（attested device = 更高信任）
   - 策略引擎可以根据 attetation 等级做条件访问决策
     （`require_attested_device: true` → 只允许从 attested 设备登录）

3. **设备身份吊销**：
   - 用户标记设备丢失 → 吊销该设备的 attestation 绑定 → 所有使用该设备 attestation
     的 session 被标记为步降（需要 step-up auth）
   - 企业可以吊销所有非 attested 设备的访问权限

4. **管理员面**：
   - `GET /api/v1/admin/users/:id/devices` — 显示用户的 attested 设备列表
   - `POST /api/v1/admin/devices/revoke` — 吊销特定设备 identity

### 边界情况要点

- **Attestation 隐私**：TPM 的 AIK 是设备唯一 ID，Android KeyStore attestation
  包含设备序列号信息。需要存储时做盐值哈希，避免成为跨服务追踪标识符
- **Attestation 新鲜度**：一次 attestation 验证只在注册时刻有效。需要定期 re-attestation
  （Android Play Integrity 的 token 有效期短）
- **降级攻击**：攻击者可能剥离设备的 attestation claim 来绕过硬件的安全检查。
  策略引擎应该对**缺少** attestation 的 session 降低信任（而非只对有 attestation 的提升）
- **WebAuthn 已有 attestation**：FIDO2 注册时浏览器可能提供 attestation statement。
  当前代码的 `attestation_policy.go` 只检查信任锚策略，未解析 attestation 类型
  （`"fmt-pki"`、`"android-key"`、`"apple"`、`"tpm"`、`"packed"`）并提取设备身份

### 价值评估

| 维度 | 评价 |
|---|---|
| **产品 impact** | 高 — 金融/医疗/政府行业的"设备合规"采购要求 |
| **投入** | 中（~4000 行，多个 verifier + session 扩展 + admin UI） |
| **差异化** | 高 — 主流 OAuth 服务器（Auth0/Okta/Keycloak）均无端到端硬件 attestation 集成 |
| **与既有能力的关系** | 扩展 WebAuthn attestation policy、session trust、条件访问、CAEP |
| **可维护性** | 每个硬件平台一个 verifier，SPI 不变 |

---

## 优先级总结

| 方向 | 价值(1-5) | 投入(1-5) | 性价比 | 竞品差异 | 依赖 |
|---|---|---|---|---|---|
| ① 状态协议 Fuzzing | ★★★★☆ | ★★☆☆☆ | ★★★★★ | 极高 | 无，独立新增 |
| ② Edge Token Proxy | ★★★★☆ | ★★★☆☆ | ★★★★☆ | 中 | 复用 rs + bus |
| ③ 跨组织 Workload 联邦 | ★★★★★ | ★★★☆☆ | ★★★★☆ | 极高 | 复用 token-exchange |
| ④ Active-Active 多区域 | ★★★★★ | ★★★★★ | ★★★☆☆ | 高 | 扩展 bus + region |
| ⑤ 硬件设备 Attestation | ★★★★☆ | ★★★★☆ | ★★★☆☆ | 高 | 扩展 webauthn + trust |

**首批实施建议：** 方向①（Fuzzing）投入最小、差异化最大、零架构风险，可立即启动。
方向②和③可以并行推进（独立 Go 模块，零核心改动）。方向④和⑤影响面较大，建议
在方向①/②/③验证了工具链后再启动。
