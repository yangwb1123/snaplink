# Snaplink SSO：下五个高价值扩展方向

> **视角**：资深架构师 / 产品经理  
> **范围**：一次完整的代码库全局扫描（~2241 个 Go 源文件、42 层包结构）  
> **规则**：不编写任何代码；不提已在 ROADMAP.md v5.0 或 deferred-backlog.md 中已列出的方向；每项必须有对抗式 grep 实证为"未实现或仅部分"  
> **日期**：2026-07-11

---

## 前提：当前平台成熟度

Snaplink 是目前最为完备的开源 OAuth 2.0 + OIDC SSO 平台之一。已具备：

| 领域 | 覆盖程度 |
|---|---|
| OAuth 2.0 grants | authorization_code, client_credentials, refresh_token (family rotation), device_code, CIBA, token-exchange, JAR, PAR, RAR |
| OIDC Core | Discovery, ID Token, UserInfo, RP-Initiated Logout, BCL, FCL, JARM, Form Post, silent renewal, `sid`, `login_hint` |
| FAPI 2.0 | 完整 profile (Inspection / Enforce) |
| SAML 2.0 | SP + IdP, SSO + SLO, 完整子模块 |
| SCIM 2.0 | 标准 CRUD + filter + patch / bulk + push provisioning |
| WebAuthn / Passkey | registration, assertion, attestation policy, MDS, conditional UI (autofill), MFA adapter |
| Security | DPoP, mTLS, PKCE, private_key_jwt, workload identity (GCP/AWS/Azure), SPIFFE JWT-SVID, JWE, step-up |
| Multi-tenancy | Tenant + Residency + Region 全模型, per-tenant signing isolation |
| Federation | OpenID Federation 1.0 (5 slices), trust chains, trust marks, auto-registration |
| CAEP/SSF | Transmitter + Receiver, MQTT delivery |
| Permissions | ReBAC with policy bundles, SOD, resource-level entitlements |
| Compliance | GDPR data export, erasure, retention, SOC2 reporting, consent records (SPI + sqlite) |
| Audit | Chain hash, facet query, async multi-sink, SOC2 report, CEF/OCSF format |
| DR / Resilience | Coordinator, orchestrator, readiness tracker, config drift operator |
| Infrastructure | SQLite, PostgreSQL, Redis, etcd, Kafka, MQTT, 4x KMS (AWS/GCP/Azure/PKCS11), Vault Transit |
| Signing Keys | Leaderless peer aggregation, coordinated cutover, FIPS 186-5, ed25519/ecdsa/rsa/ps256 |
| Self-service | Signup, password reset, email change, profile management, trusted devices |
| Admin API | gRPC + REST gateway, full CRUD for clients/users/tenants/tokens/keys |
| Embedded SPAs | Admin console, developer portal, hosted login, API docs viewer |
| sso-ctl CLI | Audit verify, migrate, snapshot, config validate, import (Auth0/Keycloak/CSV) |
| sso-mcp | Model Context Protocol server for AI-assisted identity management |
| Observability | ~40 Prometheus metrics, W3C trace context, structured logging |

**核心结论**：协议面、安全面、存储后端已极为完整。下阶段的最高价值工作不再是铺设更多标准协议，而是将现有能力**产品化、企业化、可运营化**，并填补面向未来的身份技术栈（去中心化身份、无密码跨设备认证、移动原生 SDK、实时威胁响应、声明式基础设施）中的空白。

---

## 方向一：Passkey 跨设备认证（FIDO2 Hybrid Transport）

### 为什么需要

现有的 WebAuthn 支持已经覆盖了**平台认证器**（本机生物识别/ PIN）和**条件式 UI**（autofill 免输用户名）。但 FIDO2 规范的第三大支柱——**跨设备认证（Cross-Device Authentication / Hybrid Transport）**——尚未实现。

跨设备认证的场景是：用户在一台设备（如手机）上注册了 passkey，通过扫描另一台设备（如桌面电脑）屏幕上的 QR 码，利用 BLE/CA 通道完成加密挑战，使桌面设备可以用手机上的 passkey 登录。这是 2024-2026 年 FIDO Alliance 和 W3C 推动的核心体验升级，也是 iCloud Keychain / Google Password Manager 跨设备同步之外的**无需云同步**的认证路径。

**有没有第三方库实现？** Go 生态中 `github.com/go-webauthn/webauthn`（项目当前使用的库）在 v0.10+ 中已开始支持 hybrid 协议的关键原语（如 JSON Metadata、CBOR 编码），但**完整的 Hybrid Transport 握手（QR 码生成与解析、WebSocket 中继、BLE 连接管理、CTAP 帧级消息交换）需要自行构建**，库层面仅提供密钥操作原语。

### 当前缺失的具体内容（对抗式 grep 实证）

| 需求 | 状态 |
|---|---|
| QR 码会话发起端点 | `grep -r "hybrid\|Hybrid\|cross.device\|CrossDevice" -i` → 0 命中 |
| BLE/WebSocket 中继服务 | `grep -r "cable\|caBLE\|BLE" -i *.go` → 仅连接健康检查，无 auth 用途 |
| Hybrid Authenticator 客户端 JS SDK | `grep -r "hybrid\|ctap\|FIDO.*Cable\|cable.*auth" -i` → 0 命中 |
| 跨设备认证的 AMR 值 | `amr` 映射表中无 `["hwd", "swk", "hybrid"]` |
| 降级兜底策略（平台不受支持时的 UX） | 无 |

### 边界情况

- **QR 码 reuse / replay**：一次性的 QR 码会话必须单次使用 + 短 TTL，防止中间人在会话有效期内中途介入。
- **混合蓝牙和互联网中继**：根据安全等级需求，提供纯本地 BLE 模式和 WebSocket 中继模式（用于跨网络认证）。
- **无摄像头的设备**：在纯命令行的 CI/CD / SSH 场景，需设备名输入 + 推送通知替代 QR 码。
- **混合认证中的 Privacy CA**：FIDO2 Hybrid 规范使用 Privacy CA（EID 隧道）保护用户隐私，需要实现 EID 密钥协商和隧道终止。

### 工作量估计

| 子项 | 工作量 |
|---|---|
| QR 码会话存储 + 状态机 | L（~2000 行 Go） |
| WebSocket 中继端点 + 帧编排 | L（~2500 行 Go + JS） |
| 客户端 JS hybrid adapter SDK | M（~800 行 JS） |
| 集成测试 + FIDO2 conformance | M |
| **合计** | **XL** |

### 价值评估

- **安全**：高。跨设备认证将 passkey 的使用场景从"单设备"扩展到"多设备"，且不需要依赖云同步（适用于高安全/气隙环境）。
- **产品差异**：极高。Auth0 和 Okta 的 passkey 支持同样缺少 hybrid transport，率先实现此功能将形成技术领先。
- **生态位**：与 EU Digital Identity Wallet / eIDAS 2.0 兼容（wallet 需要使用跨设备协议呈现凭证）。

---

## 方向二：Verifiable Credentials 与去中心化身份（OID4VCI / OID4VP）

### 为什么需要

当前身份平台基于**中心化的 OIDC Provider**：平台为用户签发 claims，RP 信任平台。Verifiable Credentials（W3C VC）引入了一种不同的范式：**用户持有凭证，按需零知识呈现**。

欧盟 eIDAS 2.0 法规（2026 年陆续生效）强制要求成员国提供符合 **EUDI Wallet** 标准的数字身份钱包，其核心协议栈正是 **OID4VCI**（Verifiable Credential Issuance）和 **OID4VP**（Verifiable Presentation）。日本的 JPKI、新加坡的 Singpass 等也在朝此方向演进。

虽然 snaplink 已经实现了 OpenID Federation 1.0（信任链）和 trust marks，但**这是两个不同的标准栈**：Federation 解决的是 Provider 间的信任关系，而 VC 解决的是**用户持有型凭证的签发与呈现**。两者可以互补（Federation 用于发现信任锚，VC 用于凭证格式），但不能互相替代。

### 当前缺失的具体内容（对抗式 grep 实证）

| 需求 | 状态 |
|---|---|
| `credential_offer` endpoint | `grep -r "credential_offer\|credential_issuer\|OID4VCI" -i *.go` → 0 命中 |
| `credential` endpoint (VC 签发) | 同上 |
| `credential_response` (VP 呈现) | `grep -r "verifiable.*presentation\|verifiable_presentation\|OID4VP" -i *.go` → 0 命中 |
| DID 方法解析器 | `grep -r "did:.*\|DecentralizedIdentifier\|DIDResolver" -i *.go` → 0 命中（唯一匹配 `did` 是多语言错误消息的助动词） |
| 凭证状态管理（撤销/挂起） | 无 VC 专用撤销机制 |
| Holder Binding（用户密钥绑定） | 无 VC-specific key binding |
| Zero-Knowledge Proof 支持（BBS+/SD-JWT） | `grep -r "BBS\+\|BBSplus\|SD.JWT\|sd_jwt\|selective.*disclosure" -i *.go` → 0 命中 |
| Wallet SDK / Wallet Relying Party adapter | 无 |
| eIDAS 合规文档 | 无 |

### 边界情况

- **凭证撤销的异步传播**：VC 撤销与 OAuth 的 access token 撤销不同——VC 有更长的生命周期（月/年级），撤销后需要通知所有依赖方。若使用 Status List 2021，需构建一个高性能的 status list 端点 + 缓存更新策略。
- **SD-JWT 的选择性披露**：用户在出示凭证时应能选择只披露必要字段（如"证明我超过 18 岁"而非暴露出生日期）。SD-JWT 的 salted hash disclosure 需要 issuer 和 holder 端都实现对应的 hash 验证和盐值管理。
- **EUDI Wallet 合规**：eIDAS 2.0 要求凭证符合 ARF（Architecture Reference Framework）定义的具体 profile，包括特定 claim 名称、证明格式、PID（Person Identification Data）schema——需要持续跟踪标准变化。
- **跨信任域的 DID 解析**：在未建立双边信任的域间解析 DID Document 时，需要防 SSRF（`did:web` 可能指向内网地址）和缓存中毒防护。
- **隐私的 Holder Binding**：密钥泄露后的凭证吊销与重签发的用户流程设计。

### 工作量估计

| 子项 | 工作量 |
|---|---|
| OID4VCI Issuer 端点（credential_offer + credential） | XL（~5000 行） |
| OID4VP Verifier 端点（presentation_definition 处理） | L（~3000 行） |
| SD-JWT 选择性披露支持 | L（~2000 行） |
| DID 解析器（did:web + did:key 最低适配） | M（~1000 行） |
| Status List 2021 实现 | M（~1000 行） |
| EUDI Wallet ARF profile 适配 | L |
| **合计** | **XXL** |

### 价值评估

- **战略定位**：极高。去中心化身份是 2026-2030 年身份基础设施的核心趋势。率先支持 OID4VCI/OID4VP 将把 snaplink 从"OAuth/OIDC 服务器"提升为"下一代数字身份平台"。
- **合规刚需**：eIDAS 2.0 对欧盟市场是硬性要求。全球范围内，日本、新加坡、加拿大（Pan-Canadian Trust Framework）也在推进类似框架。
- **差异化**：到目前为止，支持 OID4VCI/OID4VP 的开源身份平台极少（Keycloak 有实验性扩展，但尚未产品化）。这是真正的蓝海。

---

## 方向三：原生移动端 SDK（iOS / Android）

### 为什么需要

Snaplink 拥有完整的 Go SDK（`ssoclient`）和 HTTP/gRPC 契约。但**任何原生移动应用**（iOS 或 Android）若想集成 snaplink 做 SSO 认证，今天只有两条路径：

1. **Web 视图 / ASWebAuthenticationSession / Chrome Custom Tabs**：通过系统浏览器代理 OAuth 流程。这条路可行，但缺失原生 SDK 提供的"额外安全保障"：
   - 没有 DPoP 绑定的自动注入（需要手动从 WebView 提取 token 再附加）
   - 没有 Keychain / EncryptedSharedPreferences 中的加密 token 存储
   - 没有 App Attestation（iOS DeviceCheck / Android Play Integrity）绑定
   - 没有 Push MFA 的原生集成
   - 断网/弱网下没有离线 token 刷新队列

2. **自建 SDK**：每个移动团队自己实现 ASWebAuthenticationSession 回调处理 + token 存储 + 刷新逻辑，重复造轮子且安全风险高。

Okta、Auth0、Firebase Auth、AWS Cognito 都将**第一方移动 SDK** 作为产品核心——它们是"集成体验"的一部分。作为定位为"Auth0/Okta 的开源替代"的平台，缺少官方移动 SDK 是一个可见的产品差距。

### 当前缺失的具体内容（对抗式 grep 实证）

| 需求 | 状态 |
|---|---|
| Swift / iOS SDK 包 | `grep -r ".swift\|Podfile\|Package.swift"` → 0 命中 |
| Kotlin / Android SDK 包 | `grep -r ".kt\|.kts\|build.gradle\|libs.*android"` → 0 命中 |
| DPoP 原生支持（iOS SecKey / Android KeyStore） | 无 |
| App Attestation 集成 | 无 |
| 安全 token 存储（Keychain / EncryptedSharedPreferences） | 无 |
| Passkey / Platform Authenticator native API 调用 | 仅 Go SDK 端调用 HTTP 接口 |
| Push MFA 原生集成（APNs / FCM） | 现有 Push MFA 通过 WebHook webhook，不面向原生设备 |
| 离线 / 弱网下的 token 刷新队列 | 无 |
| 编译示例 app | 无 |
| 平台间的 autofill credential provider 扩展 | 无 |

### 边界情况

- **iOS App Attestation 和 Android Play Integrity 的差异处理**：两个平台的 attestation 流程完全不同（iOS 需要在 Xcode 中配置 App Attestation Environment，Android 需要与服务端同步 nonce 和 integrity verdict）。SDK 需要同时支持两种实现，对 SDK 使用者透明。
- **Keychain 与 iCloud Keychain 同步策略**：某些应用希望 token 跨设备同步（如 iCloud Keychain），某些不希望（银行应用）。提供可配置的 `Accessibility` 级别。
- **多窗口 / 多账号场景**：移动端的多实例 OAuth 流程（如 iOS 的 multi-window、Android 的 multi-instance），需要会话隔离。
- **App 从 Keychain 中删除后的恢复**：用户卸载重装后，attestation key 丢失，需要重新注册设备身份。需要设计"恢复密钥"机制避免用户被永久锁定。
- **SSO 扩展（iOS 12+ ASAuthorization）**：与系统密码自动填充框架的集成，提供一键登录体验。

### 工作量估计

| 子项 | 工作量 |
|---|---|
| iOS SDK 核心（OAuth 流程 + token 管理 + DPoP） | XL（~5000 行 Swift + 文档） |
| Android SDK 核心 | XL（~5000 行 Kotlin + 文档） |
| App Attestation 服务端验证端点 | M（~1000 行 Go） |
| API 对齐测试 | L |
| 编译示例 app x 2 | M |
| **合计** | **XXL** |

### 价值评估

- **产品完整性**：极高。这是从"后端 SDK"到"全平台 SDK"的必经一步。
- **安全提升**：高。App Attestation + DPoP 提供比 Web 视图认证强得多的设备绑定。
- **开发体验**：高。移动开发者可以一句话集成 SSO，不需要理解 ASWebAuthenticationSession / PKCE / 刷新轮换 / JWT 验证的任何细节。

---

## 方向四：声明式 GitOps 身份基础设施与版本化配置管理

### 为什么需要

当前项目的配置管理模型是**文件 + 环境变量 + 运行时 API** 的混合体：
- YAML 配置文件（`config.yaml`）在启动时加载
- 运行时 mutating API（gRPC / REST admin / DCR）可以修改身份对象（clients、users、permissions、policies、tenants）
- `SSOConfigDrift` 算子可以检测两个集群间配置的**差异**，但不能**应用**，更不能从 Git 同步

这造成了一个经典问题：**Drift-Creep**。API 修改了配置 → config.yaml 被遗忘 → Git 中的"源码真相"与实际运行时配置不一致 → 回滚时意外还原/丢失业务关键配置 → 安全审计找不到变更记录。

完整的 GitOps 模型要求：

```
Git Repo (YAML 声明) → 控制器 → API Server (DRY RUN) → API Server (APPLY)
                                ↑                        ↓
                           差异检测 ← ← ← ← ← ← ← ← 回滚失败时自动
```

Kubernetes 生态中有成熟的 GitOps 工具（Argo CD、Flux），但身份基础设施的 GitOps 与 K8s 资源不同：
- 身份变更（如吊销客户端、挂起用户）可能影响数千用户，需要**审批流程**
- 敏感字段（client secret、JWK）需要在 git 中加密存储（SOPS / sealed secrets）
- 需要版本化的**回滚**：不仅仅是 revert commit，还需要协调下游的**令牌吊销** 和**会话终止**

现有项目已经在 `configaudit` 中实现了 diff+digest+drift，在 `cmd/sso-operator` 中实现了 K8s CRD 驱动的高层差异检测——**应用方向的原语已部分存在，但条理尚未贯通**。

### 当前缺失的具体内容（对抗式 grep 实证）

| 需求 | 状态 |
|---|---|
| 全量导出为声明式 YAML（GET `/admin/config/export`） | `grep -r "export.*config\|config.*export\|config.*yaml\|config.*dump" -i *.go` → 无"导出为 Git -ready YAML"的端点 |
| 声明式 APPLY 端点（非 upsert，三向 diff + dry-run + apply） | `grep -r "config.*apply\|apply.*config\|config.*dry.run\|dryrun.*apply" -i *.go` → 0 命中 |
| Git 仓库同步控制器 | 仅 K8s CRD 检测器，无 Git 仓库源 |
| 敏感字段加密（age / SOPS）集成 | `grep -r "age\|sops\|sealed.*secret\|secret.*encrypt\|encrypt.*secret"` → 仅有 `client_secret` 的 hash-at-rest 提议，无 Git 加密 |
| 回滚的自动令牌吊销 / 会话失效 | `grep -r "rollback.*revoke\|config.*rollback\|version.*rollback\|rollback.*token" -i *.go` → 0 命中 |
| PR → 差异预览 webhook | `grep -r "preview\|diff.*preview\|pr.*comment" -i *.go` → 0 命中 |
| 身份变更的审批流程 | `admin_governance` 有 destructive action 审批，无配置变更审批 |

### 边界情况

- **Secret 的零知识 diff**：Git diff 不能显示 secret 明文，但 operator 需要知道"secret 是否已变更"。使用 blinded hash（HMAC with a per-cluster key）做 diff，实际值在 apply 时从 target 集群读取。
- **部分更新 vs 全量声明的语义差异**：K8s 的声明式模型是"全量期望状态"，而身份 API 多是部分更新（PATCH）。在 GitOps 模型下，需要定义"未在 YAML 中声明的字段在 apply 时是保持不变（传统 PATCH 语义）还是清空（K8s 语义）"。建议默认为"保留（保守）"，但在 dry-run diff 中标记为"隐式继承"。
- **依赖关系解析**：一个 permission 引用了不存在的 role，或者一个 client 引用了不存在的 allowed_resource。APPLY 前需要做依赖拓扑排序和 DAG 验证。
- **并发 GitOps 与运行时 API 写入**：如果管理员同时改了 Git 和 API，谁赢？需要 fencing / last-writer-wins 策略 + 审计警告。
- **跨版本的迁移兼容**：schema 版本 `v1 -> v2` 迁移后，旧的 YAML 文件需要自动迁移或死得漂亮。

### 工作量估计

| 子项 | 工作量 |
|---|---|
| 全量导出端点 + YAML schema 定义 | L（~2500 行） |
| 声明式 APPLY 端点（三向 diff + dry-run + apply） | XL（~4000 行） |
| Git 同步控制器（可运行于 K8s 或 standalone） | XL（~4000 行 + 已有 K8s operator 经验） |
| 敏感字段加密 / 解密集成 | M（~800 行） |
| PR webhook 集成（GitHub / GitLab） | L（~2000 行） |
| 审批流程与配置变更 audit trail | M（~1500 行） |
| **合计** | **XXL** |

### 价值评估

- **运营效率**：极高。平台团队可以用管理 K8s 资源的同一套 GitOps 流程管理身份基础设施。
- **合规与审计**：极高。每一个身份变更都有 Git commit 记录、PR 审查流、签名提交、不可篡改。这是 SOC2 / SOX 合规的加分项。
- **故障修复**：高。回滚不再是"手动执行 SQL"，而是一个 `git revert` + PR merge。
- **差异化**：中高。虽然 GitOps 概念在云基础设施中已成熟，但在身份平台中仍属前沿——Keycloak 没有原生 GitOps，Okta 的 Terraform provider 是配置即代码但不是 GitOps 式的声明式同步。

---

## 方向五：跨集群联邦身份数据面（Multi-Cluster Workload Identity Mesh）

### 为什么需要

项目已经具备了多个与"集群间身份"相关的组件：

| 组件 | 功能 |
|---|---|
| `ext_authz` | Envoy HTTP + gRPC 的授权检查端点 |
| `mesh_authz.go` | HTTP 网格授权中间件 |
| `SPIFFE JWT-SVID` | 工作负载身份 JWT 的签发和验证 |
| `Workload Identity` | GCP/AWS/Azure 云工作负载身份认证 |
| `platform/cluster` | 跨副本控制面总线（etcd / memory） |
| `dr/orchestrator` | 跨集群 DR 编排器 |
| `caep/transmitter` | CAEP 事件推送 |

但缺少一个**统一的工作负载身份数据面**：能让跨多个 Kubernetes 集群、跨云和本地机房的微服务/工作负载，使用统一的可信身份进行 mTLS 或令牌认证，**且认证决策不依赖中央 SPOF**。

当前模式的局限：
- 每个集群有独立的 snaplink 实例，ext_authz 仅在本集群生效
- 跨集群调用时，Service A（cluster-1）→ Service B（cluster-2）：B 必须重新调用本集群的 ext_authz，无法信任 A 的 JWT-SVID（因为 B 不知道 A 的 SPIFFE trust domain）
- 没有"身份网关"：跨集群 / 跨云 / 跨 Presto → Mixer 路径的令牌桥接能力
- 工作负载身份的生命周期管理（证书轮换、自动注册、吊销传播）没有统一的编排

这与 "方向四"（GitOps 配置）不同：方向四关注**控制面**（管理员如何管理配置），此方向关注**数据面**（运行时的工作负载如何认证和授权）。

### 当前缺失的具体内容（对抗式 grep 实证）

| 需求 | 状态 |
|---|---|
| 跨集群 SPIFFE trust domain 联合 | 仅支持单一 trust domain 的 JWT-SVID 签发 |
| 身份感知的跨集群 mTLS（SPIFFE SPIFFE） | 无 |
| 中心化的 Workload Identity Registry | `grep -r "workload.*registry\|workload_registry\|spiffe.*bundle\|spiffe_bundle"` → 0 命中 |
| 边缘身份缓存（CDN 侧 token 验证） | `grep -r "edge.*cache\|data.*plane\|replica.*tier\|validation.*cache"` → 无数据平面缓存 |
| 跨集群令牌交换 / 桥接端点 | 现有 token-exchange 在 issuer 内部，非跨集群 |
| 跨集群 mTLS CA 签发和管理 | `grep -r "intermediate.*CA\|workload.*CA\|spiffe.*CA\|certificate.*chain\|cross.*cluster.*tls"` → 0 命中 |
| 工作负载身份吊销的跨集群传播 | 现有 `cluster.Bus` 仅处理签名密钥/客户端/租户/撤销事件，无工作负载身份特定事件 |

### 边界情况

- **跨集群令牌的 act chain 传播**：当 Service A 调用 B，B 调用 C 时，RFC 8693 的 `act` claim 需要在集群边界上保持连续，不能因集群间的 token 桥接而丢失。
- **延迟敏感的本地验证**：边缘集群可能无法实时回中心查询 revocation status。需要类似"CRLite"的压缩吊销集 + 有界 TTL。
- **冷启动 / 新集群引导**：新加入的集群如何初始获取 trust bundle、工作负载 CA、全局策略？需要初始信任播送协议。
- **降级模式**：中心不可用时，边缘集群应能继续根据缓存的策略做出认证决策（fail-open 或 fail-close 可配置）。
- **联邦信任的旋转**：信任锚（根 CA、trust bundle）的旋转需要在所有参与的集群间协调，避免"过半集群信任新锚、过半信任旧锚"导致的跨集群调用断裂。

### 工作量估计

| 子项 | 工作量 |
|---|---|
| SPIFFE trust domain federation CRD + controller | XL（~4000 行） |
| 跨集群 token 交换 / 桥接端点 | L（~2000 行） |
| 边缘身份缓存 + 压缩吊销集 | XL（~3500 行） |
| 工作负载身份注册表（CRD + API） | L（~2500 行） |
| 跨集群 mTLS CA 生命周期管理器 | XL（~5000 行） |
| **合计** | **XXXL**（多个子项可迭代） |

### 价值评估

- **架构价值**：极高。跨集群身份数据面是云原生时代"身份平台"的自然演进方向——从"认证服务器"到"身份基础设施操作系统"。
- **与 Istio / Linkerd / Consul 的互补**：Service Mesh 提供 mTLS 和传输安全，但缺少上层身份语义（令牌交换、act chain、跨信任域策略）。此方向补上了这个缺口。
- **利基市场**：目前几乎没有开源方案同时提供完整的 OAuth/OIDC + 跨集群工作负载身份面。Tetrate 的商用量子产品接近此目标，但开源侧仍空白。
- **可与 方向四（GitOps）联动**：跨集群联邦的信任锚、策略、注册表配置天然适合声明式 GitOps。

---

## 优先级排序与序列建议

| 优先级 | 方向 | 原因 | 前置条件 |
|---|---|---|---|
| 🥇 P0 | **方向三：移动端 SDK** | 最高产品可见收益。其他四个方向都是基础设施级别的，AI 时代移动为先。Okta/Auth0 都有 SDK | 无（独立开发） |
| 🥈 P1 | **方向一：Passkey 跨设备认证** | FIDO2 Hybrid 是 2026 无密码认证的最后一个大缺口；乘 WebAuthn 已就绪的东风 | 现有 WebAuthn 基础设施已就绪 |
| 🥉 P1 | **方向五：跨集群工作负载身份面** | 与项目已有的 ext_authz、SPIFFE、DR 组件高度互补；差异化最大的方向 | 需要 SPIFFE、cluster.Bus 基础设施已就绪 |
| ④ P2 | **方向四：GitOps 身份基础设施** | 运营工程价值高，但"非必须"；先从导出 endpoint 和 APPLY endpoint 开始 | ROADMAP v5.0 中 DR 和 config audit 组件已就绪 |
| ⑤ P2 | **方向二：Verifiable Credentials** | 战略价值极高，但标准仍处于快速演进期，过早投入可能追错版本 | 等待 OID4VCI/OID4VP 核心规范进入 REC 后启动 |

### 快速见效的子任务（各方向的"最先做"候选）

- **方向三**：先做一个 iOS Swift Package 的"最小可用版本"（OAuth 授权码 + PKCE + DPoP + Keychain token 存储），而非完整的 SDK 套件。
- **方向一**：先实现 QR 码会话端点 + WebSocket 中继（不需要 BLE 支持），覆盖最常见的"手机扫桌面 QR 码"场景。
- **方向五**：先从 SPIFFE trust domain bundle 自动同步开始（每个集群的 validate-ingress 需要其他集群的 SPIFFE root），而非完整的数据面。
- **方向四**：先实现 `GET /admin/config/export` 全量导出 YAML + `POST /admin/config/dry-run` 三向 diff（预览），再实现 APPLY。
- **方向二**：先支持 SD-JWT（IETF SD-JWT 已成为标准）做 VC 格式，而非完整 OID4VCI endpoint。

---

## 附录：扫描方法学

- **工具**：`grep -r` 配合 `find . -type f -name "*.go"`，在不打开 IDE 的情况下对抗式验证
- **交叉验证**：对每个候选方向，先在 AGENTS.md / ROADMAP.md / deferred-backlog.md 中搜索确认是否已被覆盖
- **概率兜底**：若 grep 返回少量匹配，逐一读取文件上下文确认不是误匹配
- **计数**：本项目共 2241 个 `.go` 源文件，约 42 个一级包目录
- **已排除的候选**（被认为已在 ROADMAP/deferred-backlog 中覆盖）：Consent 记录存储、Enterprise Connections / HRD、OIDC conformance 修复（at_hash/AMR/remote alg）、多副本静默故障（etcd watch/lease/deny-set）、安全姿态（secret hash/DCR audit/CI-modules/fuzz）、Hosted Login SPA、Admin Console、性能（MemoryLimiter/SQLite pool/JWKS cache）
