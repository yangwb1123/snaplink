# SnapLink 文档功能需求点清单

> 本文档整理自对 `docs/` 目录下 237 个文件（81 个正式产品文档 + 79 个需求分析产出 + 77 个架构设计稿）的
> 逐一提取与去重合成，并结合当前代码库做了核实。姊妹文档：[docs-audit-implementation-detail.md](docs-audit-implementation-detail.md)（工程实现阶段的任务分解、评审与安全发现、已核实的现状差异）。
>
> 本文档不是路线图或承诺清单——"提议中/未来方向功能"部分绝大多数来自 AI 生成的架构头脑风暴文档
> （`docs/requirements/`、`docs/results/`），尚未经产品/工程正式评审排期。


## 分析范围与方法

`docs/` 目录下共有 **821** 个 Markdown 文件。经抽样确认，其中 `docs/results/` 下约 505 个文件
（`*.code.md` / `*.code.review.md` / `*.code.security-review.md` / `*.tests.md` / `*.impl-plan.md` 等后缀）
是同一批约 76 个"架构扩展方向"主题在 AI-SDLC 流水线（`ai-dev/pipelines/`）中产出的**工程实现层面**产物
（代码草稿、代码评审、安全评审、测试任务分解），不包含新增的功能需求点，因此本报告未逐一展开阅读。

本报告完整分析了以下 **237** 个文件（覆盖全部"需求点承载"文档）：

| 来源 | 文件数 | 说明 |
|---|---|---|
| 正式产品文档 | 81 | `docs/` 根目录 + `adr/`、`architecture/`、`skills/`、`sdks/`、`tech-lead*/`、`superpowers/` 等，描述当前已实现能力，以及部分"扩展方向"分析 |
| `docs/requirements/*.out.md` | 79 | 需求分析阶段产出（79 个主题的"扩展方向 / gap 分析"最终稿）|
| `docs/results/*.out.arch.md` | 77 | 上述主题对应的架构设计稿（同一流水线的下一阶段，常比需求稿更具体）|

提取阶段由 43 个并行 subagent 完成，每个 subagent 完整阅读 5-8 个文件并抽取"功能需求点"
（title / description / status / category / source）；共抽取原始条目 **3034** 条。
由于源文档本身存在大量重复的头脑风暴（同一个方向被"architect-expansion-*"、"senior-architect-*"、
"tech-lead-analysis-*" 等十余份文档反复以不同措辞提出），随后按 12 个功能域分桶，由 12 个并行 subagent
分别做语义去重与合并，最终整理为 **395 条已实现功能** + **653 条提议中/未来方向功能**（去重后）。

**状态判定口径**：
- **已实现（implemented）**：有 feature-matrix / ADR / config-reference / error-codes / developer-guide /
  observability / deployment / skills 等正式文档作为依据，或代码路径被直接引用。
- **提议中/未来方向（proposed）**：仅出现在"architect-analysis"、"tech-lead-analysis"、"expansion-*"、
  "senior-architect-*" 等头脑风暴 / gap-analysis 类文档中，尚无正式文档或代码证据表明已落地。

## 总体统计

| 功能域 | 已实现 | 提议中 | 原始条目(去重前) |
|---|---:|---:|---:|
| 核心协议 (OAuth2/OIDC) | 39 | 56 | 285 |
| 身份认证与登录 | 55 | 75 | 516 |
| 联邦身份与信任链 | 11 | 42 | 146 |
| 密钥管理与加密 | 36 | 37 | 175 |
| 管理与多租户 | 39 | 70 | 283 |
| 合规与审计 | 31 | 58 | 272 |
| 可观测性与运维韧性 | 30 | 51 | 275 |
| 风控与反滥用 | 52 | 96 | 276 |
| 开发者体验与SDK | 52 | 64 | 341 |
| 平台治理与元治理(AI-SDLC) | 46 | 79 | 395 |
| 计量与计费 | 1 | 10 | 25 |
| 其他 | 3 | 15 | 45 |
| **合计** | **395** | **653** | **3034** |

---

## 代码核实说明（本次新增）

在原始分析基础上，对下方"已实现功能"中出现的可校验代码引用（文件路径、包名、CLI 命令、配置键等，
393 条中约 178 条含此类引用）做了针对当前代码库的机械核实（`grep`/文件存在性检查，范围覆盖全仓库、
不限于 `.go` 文件）：**124 条直接命中，其余 6 条在放宽匹配后仍未命中**，经人工复核确认这 6 条均为
真实存在的能力，只是文档描述用词（CLI flag 名、配置键全称等）与代码中的确切拼写略有出入，并非虚构或过时。
未附代码引用的其余条目（约 215 条）均直接源自 `feature-matrix.md`、ADR、`config-reference.md`、
`error-codes.md` 等正式文档，视为已有权威来源背书，未重复核实。

结论：**"已实现功能"清单与当前代码库状态基本一致，可信度较高。**

---
## 核心协议 (OAuth2/OIDC)

### 已实现功能

- **分层架构与依赖方向治理**：core 包为无内部依赖的 SPI/类型/哨兵值叶子包；oauth 与 oidc 禁止互相导入（两处历史遗留反向导入受棘轮式收缩约束）；oauth/oidc/saml/scim 等协议包保持扁平结构而非归入 protocols/ 分组；ldap/kerberos/radius/extauthz 等嵌套协议模块以独立 go.mod 作为隔离边界。（来源：docs/adr/ADR-0002-layering-and-import-boundaries.md, docs/adr/ADR-0003-protocol-grouping.md）
- **多协议身份平台全覆盖**：作为可嵌入 Go SDK 与可运行服务端二进制发布，完整支持 OAuth 2.0、OIDC、SAML2、SCIM、CAEP/SSF、FAPI 2.0、OpenID Federation、WebAuthn/FIDO2。（来源：docs/architecture/DIRECTORY_MAP.md, docs/architecture/architect-analysis-expansion-five-directions.md, docs/results/senior-architect-expansion-v7-true-gaps-2026-07-11.out.arch.md, docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.review.out.arch.md）
- **OAuth 2.0 核心 grant 全集**：authorization_code（含 PKCE）、client_credentials、refresh_token（轮换宽限窗口+家族绝对最大生命周期）、device_code（RFC 8628，含 slow_down 节流）、CIBA（poll 与 ping 通知模式，含结果指标）、token_exchange（RFC 8693，含 act 链深度上限与跳授权策略）均已实现。（来源：docs/feature-matrix.md, docs/migration-roadmap.md, docs/config-reference.md, docs/ROADMAP.md, docs/requirements/deep-read-production-hardening-2026-07-11.out.md）
- **PKCE (RFC 7636)**：在 `/auth/login` 捕获、`/token` 仅对 authorization_code 校验，OAuth 2.1 严格模式下强制 S256。（来源：docs/feature-matrix.md, docs/SECURITY.md, docs/sso/oidc-conformance.md）
- **刷新令牌家族轮换与重用检测（fail-closed）**：FamilyID 贯穿每次轮换；检测到已轮换令牌重放即 `DeleteFamily`→`invalid_grant`；单次消费统一用 `DELETE...RETURNING` 避免 read-then-delete 竞态。（来源：docs/architecture/analysis-detection-response-gap.md, docs/SECURITY.md, docs/feature-matrix.md）
- **刷新令牌轮换宽限窗口**：`WithRefreshRotationGrace` + Redis `RefreshGraceStore` 支持并发双提交幂等，窗口外重放仍触发家族撤销。（来源：docs/architecture/analysis-detection-response-gap.md, docs/feature-matrix.md, docs/ROADMAP.md）
- **令牌内省 (RFC 7662)**：`/token/introspect` 支持响应缓存、RFC 9701 签名 JWT 内省响应、批量内省。（来源：docs/feature-matrix.md, docs/config-reference.md）
- **令牌撤销 (RFC 7009) 与持久化撤销存储**：`/token/revoke[-all]` 支持主体索引批量撤销与跨副本传播；`RevocationStore` SPI + SQLite 实现已集成到 Ed25519/ECDSA/RSA 三种签发器（含启动时播种）。（来源：docs/feature-matrix.md, docs/tech-lead-analysis-post-protocol-layer.md, docs/ROADMAP.md）
- **RFC 9126 Pushed Authorization Requests (PAR)**：`/par` 端点。（来源：docs/feature-matrix.md, docs/sso/oidc-conformance.md）
- **RFC 7591/7592 动态客户端注册**：`/register[/:id]`。（来源：docs/feature-matrix.md）
- **OIDC Discovery 与 RFC 8414 元数据别名**：`/.well-known/openid-configuration` 与 `/.well-known/oauth-authorization-server` 均基于实时服务器状态派生并带缓存。（来源：docs/feature-matrix.md, docs/migration-roadmap.md）
- **JARM（JWT Secured Authorization Response Mode）**：`query.jwt`/`fragment.jwt`/`form_post.jwt`，可插拔 `JARMSigner`，未配置时 fail-closed。（来源：docs/feature-matrix.md, docs/ROADMAP.md）
- **RFC 9207 授权服务器发行方标识**：每个 `/auth/login` 响应携带解析后的 `iss`，防混淆攻击。（来源：docs/feature-matrix.md, AGENTS.md）
- **RFC 9068 JWT 访问令牌与声明规范**：结构化 JWT 访问令牌（算法门控 `WithSupportedSigningAlgs`）；`Subject.ClientID`/`jti` 强制设置；登录路径 `AuthTime`+`AMR` 取自实时事件、`acr` 取自 `AchievedACR`；`auth_code` 授予从 `AuthCode.AuthTime`（真实登录时刻而非兑换时刻）标记 `auth_time`；refresh 传播原始 AMR 不重置 `AuthTime`；token-exchange 传播入站 `AuthTime`/`ACR`/`AMR`/`SID` 并前置多跳 `act` 链。（来源：docs/feature-matrix.md, AGENTS.md）
- **OAuth 2.1 严格模式**：阻断 implicit 授予、强制 PKCE/S256 等更严格合规选项。（来源：docs/feature-matrix.md）
- **RFC 9396 富授权请求 (RAR)**：`authorization_details` 参数，按客户端授权详情类型白名单。（来源：docs/feature-matrix.md）
- **RFC 9101 JWT 安全授权请求 (JAR，含 JWE 加密)**：签名/加密请求对象（`request`/`request_uri`），可选 URL 拉取（HTTPS 无重定向）与按客户端强制要求；JWE 采用 RSA-OAEP-256/A256GCM。（来源：docs/feature-matrix.md, docs/ROADMAP.md, docs/config-reference.md）
- **RFC 9321 交易令牌**：经令牌交换授予颁发的工作负载身份绑定短期交易令牌。（来源：docs/feature-matrix.md）
- **RFC 8707 资源指示符**：按客户端 `AllowedResources` 在每条签发路径强制 `resource`/`audience`。（来源：docs/feature-matrix.md）
- **OIDC 会话管理与登出**：后端登出通知、RP 发起端会话结束端点（`id_token_hint`/`post_logout_redirect_uri` 校验+跨客户端前端登出通知）、`session_state` 计算与 `check_session_iframe`。（来源：docs/migration-roadmap.md, docs/sso/oidc-conformance.md）
- **OIDC UserInfo 端点**：Bearer 鉴权，支持 JWT/JSON 声明输出、签名与 JWE 加密（嵌套于 JWS）响应。（来源：docs/migration-roadmap.md, docs/ROADMAP.md, docs/sso/oidc-conformance.md）
- **OIDC 隐式流程（含弃用警告）与混合流程**：`id_token`/`token`/`id_token+token` 及 `code+id_token` 等组合。（来源：docs/sso/oidc-conformance.md）
- **跨协议会话桥接引擎 SessionHub**：`GlobalSID`、`LinkRecord`（含 Core/SAML 协议维度），`Coordinator.Link/Logout` 联动 OIDC 后端登出与 SAML SLO。（来源：docs/requirements/architect-fresh-scan-five-directions-2026-07-11.out.md）
- **DPoP 发送端约束令牌**：服务端签发 nonce + JTI 重放跟踪，proof 新鲜度窗口经 `--dpop-skew` 等可配置。（来源：docs/ROADMAP.md, docs/SECURITY.md, docs/config-reference.md, docs/requirements/architect-scan-2026-07-11.out.md）
- **令牌策略与用量域**：`domains/tokenpolicy.Policy` 在签发时强制 `MaxTTL`/`BlockScopeCombos`/`MaxRefreshDepth`；`domains/tokenusage` 提供聚合分析视图。（来源：docs/requirements/architect-scan-2026-07-11.out.md, docs/results/senior-architect-expansion-v3-identity-system-quality.out.arch.md）
- **基于内省的服务端强制续期**：`IntrospectionRenewExceeded` 在令牌超过 `RenewAfter` 阈值后强制内省返回 `active:false`，配合专用 Prometheus 指标。（来源：docs/requirements/architect-scan-2026-07-11.out.md）
- **多副本一致性存储**：Redis 子模块覆盖所有热路径临时存储（session/refresh+family/auth code/PAR/JTI/限流/设备码/MFA/CIBA）；十余个 SPI 另有集群共享 SQLite 后端。（来源：docs/ROADMAP.md）
- **FAPI 2.0 合规档位**：单开关 `oauth_compliance:fapi_2` 强制 PAR/JAR/DPoP-mTLS/pairwise-sub，并提供仅审计不拒绝的检查模式。（来源：docs/ROADMAP.md）
- **可信代理 (X-Forwarded-*) 支持**：请求管道已实现 `TrustedProxies` 处理。（来源：docs/tech-lead-analysis-cross-verified-five-directions.md）
- **凭据端点安全响应头治理**：统一经 `bindOAuthParams` 绑定参数；`tokenNoStoreHeaders` 无缓存响应头；401 经 `setBearerChallenge` 质询；单次凭据消费统一 `DELETE RETURNING` 模式。（来源：docs/SECURITY.md, docs/security-policy.md, docs/review-checklist.md, docs/skills/add-new-handler/SKILL.md, docs/skills/code-review.md）
- **双监听单实例运行时**：单进程同时提供 HTTP:8080（OAuth2/OIDC+REST 管理面）与 gRPC:8081（管理/控制面，可关闭）。（来源：docs/deployment.md）
- **链外分布式令牌校验**：下游服务基于缓存 JWKS 本地校验自包含 JWT，撤销经集群总线传播，无需逐请求回调 SSO 服务器。（来源：docs/deployment.md）
- **正向单调时钟运维要求**：会话续期正确性要求时钟只能前移，运维需 slew 而非 step 系统时钟。（来源：docs/deployment.md, docs/SECURITY.md）
- **MCP 协议网关**：`cmd/sso-mcp` 提供基于官方 MCP SDK 的完整 Model Context Protocol 网关。（来源：docs/requirements/expansion-novel-2026-07-11.out.md）
- **Postgres 系统记录型存储既定架构**：Postgres 有意限定于持久化 SPI（用户/客户端/同意/租户/权限/审计），临时协议存储放 Redis，属既定架构分工而非缺口。（来源：docs/requirements/expansion-strategic-gaps-2026-07-11.out.md）
- **MemoryPARStore 容量上限 + 回收器模式**：`shardedMap` + `MaxEntries` + `memreaper.Reaper`，作为其他内存存储应遵循的参考模式。（来源：docs/results/senior-architect-5-gaps-2026-07-11.out.arch.md）
- **SPI 优先设计 + Memory 实现测试模式**：每个关注点均为接口+Memory实现（可选 SQLite/etcd/Redis），测试统一使用真实 Memory Provider 而非 mock 框架。（来源：docs/results/expansion-directions-analysis.out.arch.md）
- **签名的授权服务器元数据**：可插拔 `MetadataSigner` 对元数据文档进行签名。（来源：docs/ROADMAP.md）

### 提议中/未来方向功能

- **持久化跨副本令牌撤销 deny-set**：当前撤销集合仅存于内存（`defaultimpl/revocation_set.go`），滚动重启后已撤销 access token 可能"复活"，需持久化（SQLite/Redis/Postgres）并支持启动重放/重新播种。（来源：docs/agent-os/architect-analysis/expansion-post-protocol-layer-architecture-review.md, docs/feature-spec-architecture-synthesis-five-directions.md, docs/tech-lead-analysis-post-protocol-layer.md, docs/results/PEER_REVIEW_architect-expansion-novel-horizons-2026-07-11.out.arch.md, docs/results/senior-architect-expansion-v5-post-scan.out.arch.md）
- **资源服务器主动撤销推送 (RevocationSubscriber/Webhook)**：令牌撤销时复用现有 webhook 引擎（签名/重试/死信队列）主动推送通知给 RS，缩短仅靠 `/introspect` 轮询发现撤销的时间窗口。（来源：docs/requirements/architect-deep-code-scan-5-undiscovered-gaps.out.md, docs/requirements/architect-expansion-novel-5-directions-2026-07-11.out.md, docs/requirements/architect-gap-analysis-2026-07-11.out.md, docs/results/architect-deep-code-scan-5-undiscovered-gaps.out.arch.md）
- **Token Status List（IETF draft-ietf-oauth-status-list）**：AS 定期发布签名的紧凑位图/CBOR 撤销状态列表及发现端点，供 RS 离线/边缘校验令牌状态，支持增量获取。（来源：docs/requirements/architect-gaps-analysis-2026-07-11.out.md, docs/requirements/expansion-edge-cases-2026-07-11.out.md, docs/results/expansion-edge-protocol-hardening-platformization.out.arch.md, docs/results/expansion-edge-cases-2026-07-11.out.arch.md）
- **多级令牌验证/内省缓存 (L1/L2/L3)**：RS 端本地缓存+Redis+introspection 分层缓存拓扑，配合 singleflight/`GetOrRefresh` 语义与撤销驱动的写失效，避免撤销风暴下的 cache stampede。（来源：docs/requirements/architect-expansion-5-directions.out.md, docs/results/architect-expansion-5-directions.out.arch.md, docs/results/architect-gap-analysis-2026-07-11.out.arch.md）
- **令牌沙箱化 / TokenConstraints 约束传播**：新增 `ReadOnly`/`AllowedCIDRs`/`TimeWindows` 等统一约束结构，在签发/交换/内省/刷新各阶段强制并按类型做交集收窄，内省响应暴露 `constraints` 字段。（来源：docs/requirements/architect-expansion-5-directions.out.md, docs/results/architect-expansion-5-directions.out.arch.md）
- **UMA 2.0（User-Managed Access）支持**：资源注册（`/resource_set`）、许可票据（ticket）grant 与 RPT 颁发，复用现有令牌签发基础设施，含共享授权工作流状态机抽象。（来源：docs/requirements/architect-expansion-5-directions.out.md, docs/results/architect-expansion-5-directions.out.arch.md）
- **Edge Token Proxy（边缘令牌校验代理）**：独立部署的边缘节点二进制，本地缓存 JWKS/introspection 结果并自主管理 DPoP nonce，减少跨区域令牌校验延迟。（来源：docs/architecture/architect-analysis-expansion-five-directions.md, docs/requirements/architect-expansion-five-directions-2026-07-11.out.md, docs/results/architect-expansion-five-directions-2026-07-11.out.arch.md）
- **Postgres OAuth 短期/临时存储补全**：为 Postgres 补齐 AuthCodeStore/RefreshTokenStore/DeviceCodeStore/PARStore/CIBAStore/JTIReplayStore/MFAChallengeStore，使其与 SQLite/Redis 功能对等。（来源：docs/architecture/architect-analysis-expansion-v10-directions.md, docs/tech-lead-expansion-analysis.md, docs/requirements/expansion-strategic-gaps-2026-07-11.out.md）
- **令牌绑定 (cnf) 跨协议/跨交换传播**：DPoP/mTLS 的 `cnf`（jkt/x5t#S256）确认绑定在 RFC 8693 令牌交换委派链与跨协议路径（SAML 续期、管理后台颁发）中传播，绑定不兼容时 fail-closed 拒绝。（来源：docs/tech-lead/expansion-five-directions-v2-peer-review-implementation.md, docs/requirements/expansion-directions-v12-analysis.out.md, docs/requirements/architect-fresh-code-scan-2026-07-11.out.md, docs/results/architect-fresh-code-scan-2026-07-11.out.arch.md）
- **认证流水线钩子/中间件引擎**：注册式 pre-auth/post-auth/pre-token/post-token 钩子 SPI，支持 WASM 沙箱与 webhook 动作类型，可配置失败模式（block/bypass）与超时预算。（来源：docs/tech-lead-analysis-cross-verified-five-directions.md, docs/requirements/architect-fresh-scan-five-directions-2026-07-11.out.md, docs/results/expansion-directions-v13-analysis.out.arch.md）
- **声明式认证流程引擎**：YAML 定义的 `AuthFlowDefinition`（步骤/提供方/错误处理/同意要求），按客户端/租户绑定并支持热重载。（来源：docs/tech-lead-analysis-cross-verified-five-directions.md）
- **OAuth 2.0 物联网/受限设备适配**：CWT（RFC 8392）令牌格式、ACE-OAuth（RFC 9200）端点、CoAP/DTLS 传输、离线预签发令牌包。（来源：docs/tech-lead-analysis-frontier-paradigms-2026-07-12.md, docs/requirements/architect-frontier-identity-paradigms-platform-resilience-2026-07-11.out.md, docs/requirements/expansion-novel-2026-07-11.out.md）
- **CAEP 撤销联动广播**：同意撤销/会话驱逐时向客户端注册的 CAEP 接收端点推送安全事件（fail-open）。（来源：docs/tech-lead-analysis-peer-review-corrections.md, docs/requirements/architect-expansion-2026-07-11.out.md）
- **at_hash 全授予类型覆盖 + AMR/ACR 传播一致性修复 + 远程多算法 JWKS**：确保 authorization_code/device_code/refresh_token/token_exchange 等所有返回 access_token 的授予均计算 `at_hash`；修复 refresh 不重置 `auth_time`、token-exchange 正确传播入站 AMR；`ssoclient/remote` 支持多签名算法 JWKS 与 `private_key_jwt` 客户端认证互操作。（来源：docs/ROADMAP.md, docs/requirements/expansion-strategic-gaps-2026-07-11.out.md, docs/results/expansion-strategic-gaps-2026-07-11.out.arch.md）
- **属性置信度传播至 ID Token 声明**：从 `AttributeStore` 验证元数据在签发时派生 OIDC `verified_claims`/`email_verified`。（来源：docs/tech-lead-analysis-peer-review-corrections.md）
- **统一撤销存储服务端选项与多后端**：新增单一 `WithRevocationStore` 服务器选项一次性接入所有签发器；补充 Redis/PostgreSQL 撤销存储后端；重启存活验证测试与指标。（来源：docs/tech-lead-analysis-post-protocol-layer.md）
- **授权即服务 PDP 引擎**：统一 `AuthorizationEngine` 管道整合 RBAC/ReBAC/条件访问，deny-first 短路评估，暴露 `POST /api/v1/authorize` 决策端点与可查询决策日志，含 LRU 决策缓存及集群总线失效。（来源：docs/tech-lead-analysis-post-protocol-layer.md, docs/results/expansion-novel-v2-identity-2026-07-11.out.arch.md）
- **DPoP nonce 分片/布隆过滤器存储 与 JTI 租户分层重放存储**：分片两层（bloom+精确表）DPoP 重放检测存储；热/温/冷分层、按租户分区的 JTI 重放存储，防噪声租户争用。（来源：docs/tech-lead-analysis-post-protocol-layer.md）
- **令牌瘦身（scope 声明过滤 + 引用令牌模式）**：按 scope 过滤签发声明缩小 JWT 体积，并提供可选的服务端存储引用令牌（opaque reference token）模式。（来源：docs/agent-os/architect-analysis/expansion-post-protocol-layer-architecture-review.md, docs/tech-lead-analysis-post-protocol-layer.md, docs/results/expansion-post-protocol-layer-analysis.out.arch.md）
- **CDN 可缓存签名内省响应 + 分层缓存**：为已实现的签名内省响应新增边缘缓存头策略与 L1(进程)/L2(Redis)/L3(CDN) 缓存层级。（来源：docs/agent-os/architect-analysis/expansion-post-protocol-layer-architecture-review.md, docs/tech-lead-analysis-post-protocol-layer.md）
- **SessionHub LinkStore 生命周期治理与跨协议会话桥接管理 API**：新增 `expiresAt`/`DeleteLeg`/`ListBySubject`/`ListByUser`、后台 GC、管理端统一会话端点、用户端已链接会话端点、OIDC/SAML 登出回路保护及持久化后端。（来源：docs/architect-analysis-system-resilience-spa-ssrf-concurrency-5-gaps.md, docs/requirements/architect-global-scan-v2-true-new-gaps-2026-07-12.out.md, docs/results/architect-system-resilience-spa-ssrf-concurrency-5-gaps.out.arch.md, docs/results/deep-read-production-hardening-2026-07-11.out.arch.md）
- **SQLite ClientStore 字段持久化完整性修复**：修复重启后丢失 JWKS/AllowedResources/AllowedRequestURIs/RegistrationAccessToken/JWE alg-enc/Federation/PostLogoutRedirectURIs 等字段的静默安全降级，需 schema 迁移扩展列覆盖完整 Client 结构体。（来源：docs/feature-spec-architecture-synthesis-five-directions.md, docs/requirements/architect-gaps-analysis-2026-07-11.out.md, docs/results/PEER_REVIEW_architect-expansion-novel-horizons-2026-07-11.out.arch.md, docs/results/senior-architect-expansion-v5-post-scan.out.arch.md）
- **RS 端令牌续期可见性（RequireRenewAfter）**：内省响应新增 `renew_after` 字段与 `X-Token-Renew-After` 响应头，RS SDK 新增 `RenewRequired` 读取方法。（来源：docs/requirements/architect-scan-2026-07-11.out.md, docs/results/architect-scan-2026-07-11.out.arch.md）
- **claims 请求参数强制执行**：实际投影/强制 OIDC `claims` 请求参数（含 essential claims），否则应停止在 discovery 中声明 `claims_parameter_supported:true`。（来源：docs/ROADMAP.md）
- **Redis 覆盖 ClientStore/UserProvider/permissions**：将 Redis 后端从纯临时存储扩展到 `/auth/login` 与 `/token` 热路径上仍回落 SQLite/memory 的 ClientStore、UserProvider、permissions。（来源：docs/ROADMAP.md）
- **多步骤协议状态机模糊测试 + OIDF 一致性套件 CI 化**：构建跨多步骤流程（撤销后刷新、设备码换授权码、并发刷新双提交竞态）的 fuzz harness 与共享不变量断言库，并将现有 OIDC Conformance Suite 自动化纳入夜间 CI。（来源：docs/requirements/architect-scan-deep-gaps-2026-07-11.out.md, docs/results/expansion-systemic-quality-horizon.out.arch.md）
- **设备码 user_code 唯一性保障**：为 8 字符（约 40 位）`user_code` 生成器补充碰撞概率文档与显式唯一性校验循环。（来源：docs/requirements/deep-read-production-hardening-2026-07-11.out.md）
- **JWT Bearer 授予类型 (RFC 7523)**：作为现有 SAML Bearer 授予的对等实现，云工作负载身份连接器的前置条件。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **令牌交换治理增强**：作用域默认交集、actor 链环检测、`may_act` 强制执行、可配置链深度上限（`WithMaxActChainDepth`）、链/令牌量监控告警、每跳审计事件、委派链持久化存储（`ExchangeChainStore`）与按链撤销（`ListTokensByChainID`）。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md, docs/requirements/expansion-production-deployment-gaps.out.md, docs/results/global-scan-expansion-directions.out.arch.md）
- **dpop_jkt 授权码绑定 (RFC 9449 §10)**：签发授权码时绑定 DPoP 密钥指纹，关闭被盗授权码窗口。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **OpenID4VCI/VP + SD-JWT VC**：支持颁发/出示可验证凭据，服务 eIDAS 类使用场景。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **内省响应 DPoP token_type 修复**：修复 DPoP 绑定令牌在 `/introspect` 中可能误报 `token_type=Bearer` 的问题。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **MCP 场景 OAuth 资源服务器网关**：HTTP 传输上完整的按代理 Bearer 令牌校验（aud/scope），并在 `/.well-known/oauth-protected-resource` 提供 RFC 9728 保护资源元数据。（来源：docs/superpowers/specs/2026-06-29-sso-mcp-design.md）
- **ACE-OAuth 受限设备协议族**：CWT/COSE 签发器、`/ace` 端点复用现有 grant handler 并 CBOR 序列化、可选 CoAP/DTLS 监听器。（来源：docs/results/expansion-novel-2026-07-11.out.arch.md）
- **会话感知令牌内省**：内省校验 `sid` 是否仍活跃，双层缓存（token-hash + sid+jti 会话活跃缓存），`SessionManager.Destroy` 触发缓存失效回调或经 `cluster.Bus` 分发。（来源：docs/requirements/senior-architect-expansion-v8-2026-07-11.out.md, docs/results/senior-architect-expansion-v8-2026-07-11.out.arch.md）
- **CIBA Push 通知交付模式**：新增 Push 模式的 CIBA 交付器直接向 `backchannel_token_delivery_uri` POST 令牌（对比现有 Ping-only），复用 `ClientNotificationToken` 鉴权，支持重试/死信队列与可选 JWE 加密。（来源：docs/requirements/senior-architect-expansion-v8-2026-07-11.out.md, docs/results/senior-architect-expansion-v8-2026-07-11.out.arch.md）
- **令牌生命周期治理域（健康评分/异常检测/自动清理）**：新增 `domains/tokenhealth`，提供健康评分、废弃令牌检测、过期预测与自动清理（依赖通知基础设施先行交付）。（来源：docs/results/senior-architect-expansion-v3-identity-system-quality.out.arch.md）
- **客户端密钥生命周期管理**：`core.Client` 新增 `SecretExpiresAt`（RFC 7591 §3.2.1），`ValidateSecret` 校验过期，新旧密钥轮换宽限期与过期前通知。（来源：docs/results/senior-architect-expansion-v6-true-gaps-2026-07-11.out.arch.md）
- **软件声明 (RFC 7591 software_statement) 支持**：DCR 中完整支持 `software_statement`，含模型字段、JWT 解析、签名/信任链校验与持久化存储。（来源：docs/results/global-scan-expansion-directions.out.arch.md）
- **DCR 客户端元数据策略引擎**：独立于联邦信任链，新增 `DCRClientMetadataPolicy` SPI 强制字段黑白名单、约束、最大重定向 URI 数、允许的 URI 模式与 grant types。（来源：docs/results/global-scan-expansion-directions.out.arch.md）
- **令牌声明管线（自定义声明注入）**：`domains/pipeline` 提供 Pipeline/Stage/Chain SPI，按可配置阶段注入自定义声明（org/department/role 映射），默认无操作保持现状。（来源：docs/results/expansion-production-deployment-gaps.out.arch.md）
- **客户端类型分级与策略模板**：`core.Client` 新增 `ApplicationType`（web/native/service）与 `TrustLevel` 字段及 `PolicyTemplate` 机制，将客户端类型映射到必需安全策略（pkce/jkt/private_key_jwt）与默认声明值；含 first/third-party 分类以自动跳过同意屏。（来源：docs/requirements/architect-gaps-analysis-2026-07-11.out.md, docs/results/expansion-production-deployment-gaps.out.arch.md）
- **声明式令牌治理策略引擎 (TokenPolicy Engine)**：按客户端/租户/授予类型/运行时条件（IP/地理/时间/风险分）声明式设置 TTL/scope/deny 规则，支持 Dry-Run 观察模式与三个策略评估注入点（access token 签发后/refresh 前/exchange 前）装饰器。（来源：docs/results/expansion-gaps-analysis-2026-07-11.out.arch.md）
- **RAR 动态同意 UI 与细粒度治理**：为已实现的 RAR 后端补齐 Hosted Login SPA 动态授权详情同意屏、单项批准/取消、`ConsentStore` 持久化 `authorization_details`、差异化重新同意（re-consent）检测、DCR `authorization_details_types` 声明字段。（来源：docs/requirements/expansion-edge-cases-2026-07-11.out.md, docs/results/expansion-edge-protocol-hardening-platformization.out.arch.md, docs/results/expansion-edge-cases-2026-07-11.out.arch.md）
- **RS 声明 ACR 需求双通道 + ACR 发现**：HTTP 头（`WWW-Authenticate`/`X-ACR-Required` insufficient_acr）与客户端注册（DCR `acr_requirements`）两种方式声明最低 ACR 触发 step-up；新增 `/.well-known/acr-values` 发现端点与 discovery 中 `acr_values_supported` 字段。（来源：docs/results/expansion-edge-cases-2026-07-11.out.arch.md, docs/results/expansion-edge-protocol-hardening-platformization.out.arch.md）
- **select_account / login prompt 支持**：实现 OIDC `prompt=select_account` 账户选择器 UI。（来源：docs/results/expansion-directions-v8-analysis.out.arch.md）
- **TokenTranslator SPI（跨协议令牌翻译）**：将外部身份令牌（SAML2/LDAP/Kerberos/RADIUS）翻译为内部 OAuth2 令牌，使服务器成为通用协议令牌枢纽。（来源：docs/results/expansion-directions-v8-analysis.out.arch.md）
- **scope 感知的令牌签发算法/声明选择**：`IssueToken`（`defaulttoken/jwt_issuer.go`）按客户端 scope 差异化选择签发算法或声明的分支逻辑。（来源：docs/requirements/expansion-directions-v9-analysis.out.md, docs/results/expansion-directions-v9-analysis.out.arch.md）
- **跨协议身份传播上下文 (PropagationContext)**：跨协议边界（如 OAuth 令牌交换触发 SAML 断言或 SCIM 事件）携带原始 subject/auth_time/ACR/AMR/SID。（来源：docs/results/global-scan-expansion-directions.out.arch.md）
- **ConsentStore SPI 实现**：新增同意存储接口及 memory/sqlite 实现，记录/查询/撤销用户对客户端的授权范围同意。（来源：docs/results/expansion-directions-v7-analysis.out.arch.md）
- **TLS Token Binding (RFC 8471/8472)**：将令牌绑定到底层 TLS 连接（legacy tls_unique 或 TLS 1.3 exporter 模型），面向遗留移动 SDK 场景。（来源：docs/requirements/architect-gaps-analysis-2026-07-11.out.md）
- **零拷贝令牌处理性能优化**：降低令牌签发/校验热路径上的内存分配与拷贝。（来源：docs/requirements/architect-global-scan-novel-ops-biz-gaps.out.md）
- **区域亲和令牌签发与区域化 JWKS**：令牌 claims 新增 `region` 字段，签发密钥按区域分组，JWKS 端点支持区域过滤，并新增持久化的跨区域撤销事件队列。（来源：docs/results/architect-scan-deep-gaps-2026-07-11.out.arch.md）
- **Session Cap 原子化 / SessionQuotaGuard**：修复会话数上限检查中的 TOCTOU 竞态（软约束在极端并发下可能超限），新增 SPI 提供原子配额获取与补偿释放。（来源：docs/results/architect-fresh-code-scan-2026-07-11.out.arch.md, docs/results/deep-read-production-hardening-2026-07-11.out.arch.md）
- **Monotime 单调时钟基础设施**：新增 `shared/core/monotime` 包替换 session TTL/刷新过期/DPoP iat/JTI 重放窗口等关键路径的裸 `time.Now()` 调用，防范 NTP 回跳复活已撤销令牌。（来源：docs/results/expansion-directions-analysis.out.arch.md）
- **内存后端原子单次消费操作**：为 memory 后端补充与 SQL `DELETE RETURNING` 等效的原子单次消费操作。（来源：docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.review.out.arch.md）
- **形式化验证协议状态机**：使用 TLA+/Alloy 等形式化方法验证 OAuth/OIDC 协议状态机正确性，超越现有基于示例的测试。（来源：docs/requirements/expansion-systemic-quality-horizon.out.md）

---
## 身份认证与登录

### 已实现功能

- **OIDC ID Token 签发（at_hash 规则）**：签发 ID Token，当响应中同时包含 access_token 时强制要求 at_hash 声明（来源：docs/feature-matrix.md, docs/error-codes.md）
- **OIDC RP-Initiated Logout**：`/end_session` 端点支持依赖方发起的会话终止（来源：docs/feature-matrix.md）
- **OIDC Back-Channel Logout 1.0**：可选启用，向依赖方推送后端信道登出通知，支持基于 subject-client 索引的多 RP fan-out（来源：docs/feature-matrix.md）
- **OIDC Front-Channel Logout 1.0**：`/end_session` 调用各客户端注册的前端信道登出 URI（来源：docs/feature-matrix.md）
- **OIDC `sid` 会话声明**：SessionManager 接入时在 access/ID/logout token 中包含 `sid`（来源：docs/feature-matrix.md）
- **OIDC `login_hint` 支持**：`/auth/login`、`/par`、JAR 请求均支持该参数（来源：docs/feature-matrix.md）
- **OIDC Form Post 响应模式**：`response_mode=form_post` 通过自动提交 HTML 表单投递授权响应（来源：docs/feature-matrix.md）
- **OIDC `prompt=none` 静默续期**：需同时具备 SessionManager 与 IDTokenIssuer（来源：docs/feature-matrix.md）
- **RFC 7521/7523 `private_key_jwt` 客户端认证**：在 `/token`、`/par`、`/introspect`、`/revoke` 使用客户端注册 JWKS 验证 JWT 断言，且算法校验先于签名验证（来源：docs/feature-matrix.md, docs/SECURITY.md）
- **RFC 9470 Step-Up 认证辅助能力**：供资源服务器基于 ACR 声明强制步升认证（来源：docs/feature-matrix.md, docs/results/expansion-gaps-analysis-2026-07-11.out.arch.md）
- **OIDC CIBA（Client-Initiated Backchannel Authentication）**：支持 poll 与 ping 两种模式及认证设备集成（来源：docs/feature-matrix.md, docs/sso/oidc-conformance.md）
- **Dynamic Client Registration（DCR）**：`POST /register`，支持 software statement 与客户端元数据校验（来源：docs/sso/oidc-conformance.md）
- **MFA 编排框架**：`/auth/login` 返回 `mfa_required` 挑战，`POST /auth/mfa` 完成第二因素，失败统一折叠为 `mfa_invalid` 防枚举（来源：docs/feature-matrix.md, docs/error-codes.md）
- **Push 式 MFA（Webhook）**：PushMFAProvider 实现推送挑战/轮询闭环（来源：docs/architecture/architect-analysis-expansion-v9-five-directions.md）
- **TOTP 自助注册**：`/me/mfa/totp/begin`、`/me/mfa/totp/confirm`（来源：docs/error-codes.md）
- **WebAuthn/Passkey 完整实现**：四调用注册/断言仪式、Conditional UI 免用户名自动填充登录、`webauthn.primary_auth_enabled` 主认证、MFA 二次注册、SQLite 存储与凭据注册员（来源：docs/error-codes.md, docs/config-reference.md, docs/ROADMAP.md, docs/requirements/architect-gaps-analysis-2026-07-11.out.md, docs/results/architect-scan-2026-07-11.out.arch.md）
- **可信设备（Trusted Device）跳过 MFA**：`/me/devices*` 自助注册/列出/撤销，持久化设备令牌默认 30 天 TTL，需先完成一次步升认证方可注册（来源：docs/error-codes.md, docs/requirements/architect-fresh-scan-2026-07-11.out.md, docs/requirements/Senior-Architect-Expansion-Directions-2026-07-11.out.md）
- **SPIFFE JWT-SVID 校验 / Workload Identity**：严格校验 audience 与 trust domain 后接受工作负载身份，并支持作为令牌交换 subject token（来源：docs/SECURITY.md, docs/feature-matrix.md, docs/requirements/architect-scan-2026-07-11.out.md）
- **云工作负载身份客户端认证**：客户端可用 GCP/AWS/Azure 云签发身份令牌替代 client secret 在 `/token` 认证（来源：docs/feature-matrix.md）
- **Kerberos/SPNEGO 认证**：嵌套模块提供 `/auth/kerberos`（来源：docs/feature-matrix.md）
- **RADIUS 认证器**：可通过 `WithAuthenticator` 接入（来源：docs/feature-matrix.md）
- **可配置 mTLS 后端**：`security.mtls.backend` 支持原生 TLS 客户端证书或反向代理头模式（来源：docs/config-reference.md）
- **WebAuthn Attestation 策略**：`webauthn.attestation.policy_mode` 支持 allowlist/denylist，并集成 FIDO MDS（来源：docs/config-reference.md, docs/error-codes.md）
- **自助注册（Signup）+ 强制邮箱验证**：`POST /auth/register` 及 `POST /auth/verify-email`（来源：docs/error-codes.md, docs/migration-roadmap.md, docs/skills/hexagonal-extraction.md）
- **自助邮箱变更**：`/me/email/change` + `/me/email/verify`（来源：docs/error-codes.md, docs/migration-roadmap.md, docs/skills/hexagonal-extraction.md）
- **自助忘记密码/重置密码**：`/auth/forgot-password`（恒返回 200 防枚举）与 `/auth/reset-password`（来源：docs/error-codes.md, docs/migration-roadmap.md）
- **自助 Profile / 安全设置管理（/me）**：用户查看管理个人资料、安全设置（来源：docs/migration-roadmap.md）
- **自助身份关联/解绑（/me/identities）**：列出并解绑外部/联邦身份，拒绝解绑最后一个认证方式，含登录时身份冲突合并策略（来源：docs/error-codes.md）
- **Pairwise Subject Identifiers**：PairwiseSubjectStore 为每客户端签发假名化 sub（来源：docs/migration-roadmap.md, docs/ROADMAP.md）
- **ConsentStore 多后端 + 自助同意管理**：Memory/SQLite/Redis/PostgreSQL 四种实现，`GET /consents/me`、`DELETE /consents/me/:client_id`（来源：docs/tech-lead-analysis-peer-review-corrections.md, docs/tech-lead-analysis-cross-verified-five-directions.md, docs/results/expansion-ciam-identity-horizon.out.arch.md, docs/requirements/architect-unique-gaps-scan-2026-07-11.out.md）
- **同意授权 TTL/过期强制执行 + 登录时刷新**：`ConsentGrant.ExpiresAt` 校验、`ConsentRefreshInterval` 配置生命周期，登录时刷新 `GrantedAt`（来源：docs/requirements/architect-unique-gaps-scan-2026-07-11.out.md, docs/config-reference.md, docs/results/expansion-ciam-identity-horizon.out.arch.md）
- **SCIM 2.0 入站用户/组供给**：CRUD、PATCH、RFC 7644 过滤评估（来源：docs/ROADMAP.md, docs/feature-matrix.md）
- **SCIM 出站推送供给**：`scim.push.enabled` 将变更推送至下游 SCIM 应用（来源：docs/config-reference.md）
- **AI Agent 身份核心模型与委派授权**：Agent 结构体、AgentProvider SPI、`delegation_token` 授权类型（RFC 8693 act 链）、`IntersectScopes` 三重作用域收窄、可撤销限时 AgentSession，透传 DPoP/mTLS 绑定（来源：docs/error-codes.md, docs/requirements/architect-frontier-identity-paradigms-platform-resilience-2026-07-11.out.md, docs/results/expansion-novel-2026-07-11.out.arch.md）
- **MCP 协议网关**：`cmd/sso-mcp/` 基于 MCP SDK v1 实现智能体接入认证（来源：docs/requirements/architect-frontier-identity-paradigms-platform-resilience-2026-07-11.out.md, docs/results/expansion-novel-2026-07-11.out.arch.md）
- **五种独立授权模型并存**：Trust Scoring、Conditional Access、RBAC/permissions、ReBAC、WASM Authz 各自独立评估、互不整合（来源：docs/architecture/architect-analysis-expansion-five-directions.md, docs/wasmauthz.md）
- **可插拔 WASM 授权引擎（wasmauthz）**：基于 wazero 纯 Go 运行时，固定 ABI 契约，每次调用实例化新模块保证并发安全（来源：docs/wasmauthz.md）
- **WASM 托管自定义认证器**：`domains/authenticators/wasmauth` 通过标准 `core.Authenticator` SPI 接入 WASM 托管的自定义 MFA/免密/桥接认证逻辑（来源：docs/wasmauthz.md, docs/deferred-backlog.md）
- **跨协议 Session Hub 核心引擎（写路径）**：`platform/lifecycle/sessionhub` 已实现 `Coordinator.Link/Logout`、`GlobalSID`、`LinkRecord`、`MemoryLinkStore`，登录时正确写入跨协议绑定（登出路径尚未接线，见提议部分）（来源：docs/architecture/architect-analysis-expansion-five-directions.md, docs/results/architect-fresh-scan-five-directions-2026-07-11.out.arch.md, docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.out.arch.md）
- **密码策略基础组件（未接线）**：`PasswordPolicyValidator` SPI、内置万级弱密码字典检测、基于 K-匿名的 HIBP 泄露检查、`PasswordHistoryStore`（内存实现）均已存在，但尚未被任何 SetPassword 路径实际调用（来源：docs/requirements/senior-architect-5-gaps-2026-07-11.out.md, docs/results/senior-architect-5-gaps-2026-07-11.out.arch.md, docs/requirements/architect-fresh-scan-five-directions-2026-07-11.out.md, docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.out.arch.md）
- **Phone/SMS 认证器核心逻辑**：`PhoneAuthenticator` 完整实现双段流（SendCode/Authenticate）、锁定、回调，`SMSSender` SPI（含桩实现），`phone_number`/`phone_number_verified` 已暴露于 userinfo（来源：docs/results/global-architecture-scan-four-production-blindspots-2026-07-11.out.arch.md, docs/requirements/Senior-Architect-Expansion-Directions-2026-07-11.out.md）
- **API Key 认证解析器**：`APIKeyResolver` SPI + `MemoryAPIKeyStore`，SHA-256 哈希与常量时间比较（来源：docs/requirements/architect-unique-gaps-scan-2026-07-11.out.md, docs/results/tech-lead-analysis-expansion-next-wave.out.arch.md）
- **Break-Glass 紧急访问**：双重控制授权、限时紧急凭据与身份模拟（来源：docs/results/expansion-novel-v2-identity-2026-07-11.out.arch.md）
- **条件访问策略引擎（Conditional Access）**：既有运行时条件访问决策引擎（来源：docs/results/expansion-novel-v2-identity-2026-07-11.out.arch.md）
- **会话信任衰减 + Step-Up（SessionHub）**：既有 trust decay 与 RFC 9470 step-up 集成（来源：docs/results/expansion-novel-v2-identity-2026-07-11.out.arch.md）
- **用户账户生命周期状态机**：`domains/userlifecycle/` 记录 invited→active→suspended→inactive→archived→purged 状态迁移（来源：docs/results/example-user-api.out.arch.md）
- **UserProvider 多后端存储抽象**：Memory/SQLite/Postgres/Redis 四种实现（来源：docs/results/example-user-api.out.arch.md）
- **密码凭证独立隔离存储**：bcrypt 哈希存于独立 `PasswordCredentialStore`，与用户属性物理隔离（来源：docs/results/example-user-api.out.arch.md）
- **Admin Console 自举 OAuth/PKCE 登录**：管理控制台自身登录页对接托管登录页完成 RFC 6749 + PKCE S256 流程（来源：docs/deferred-backlog.md）
- **本地化错误描述**：`sso.WithLocalizer` 按 `Accept-Language`/geo 返回 `error_description_localized`（来源：docs/error-codes.md）
- **无密码专属客户端强制**：`allow_passwordless_only` 拒绝密码登录但保留其他认证器（来源：docs/error-codes.md）
- **内置 SMTP 邮件发送器**：异步投递密码重置/邮箱验证/邮箱变更/组织邀请/邮件 OTP（来源：docs/config-reference.md, docs/results/global-architecture-scan-four-production-blindspots-2026-07-11.out.arch.md）
- **Consent Grant Max TTL 配置**：`self_service.consent.max_ttl` 服务端强制上限（来源：docs/config-reference.md）
- **MFA/WebAuthn 可观测性与运维任务**：MFA 挑战/完成指标、WebAuthn 注册/断言指标、MFA push-approval 定时清理任务（来源：docs/observability.md）
- **SessionManager SPI 基础 CRUD**：会话创建/查询/列表/撤销基础接口（来源：docs/results/senior-architect-expansion-v8-2026-07-11.out.arch.md）

### 提议中/未来方向功能

- **FIDO2 Hybrid Transport 跨设备 Passkey 认证**：QR 码 + BLE/WebSocket 中继完成跨设备 WebAuthn 认证，含 HybridCapable SPI、FIDO 中继服务、CTAP 帧处理、隐私 CA/EID 隧道、移动端扫码 SDK、无摄像头降级方案、浏览器 JS SDK（来源：docs/agent-os/architect-analysis/expansion-post-protocol-layer-architecture-review.md, docs/architect-analysis-five-verified-expansion-directions.md, docs/tech-lead-analysis/cross-validated-five-new-directions.md, docs/tech-lead/expansion-analysis-2026-07-11.md, docs/requirements/architect-fresh-scan-5-directions.out.md）
- **WebAuthn 扩展能力与凭据管理协议**：credProps/PRF/largeBlob 扩展支持、Credential Management Protocol（枚举/更新/删除凭据）、跨设备同步 backup_eligible/sync 生命周期策略（来源：docs/requirements/architect-gaps-analysis-2026-07-11.out.md, docs/results/senior-architect-expansion-v5-post-scan.out.arch.md）
- **移动原生 Passkey SDK 集成**：iOS `ASAuthorizationController`、Android Credential Manager API 原生注册/断言（来源：docs/tech-lead-analysis/cross-validated-five-new-directions.md）
- **Verifiable Credentials 签发（OID4VCI）**：DID 解析、SD-JWT 选择性披露、credential_offer/issuer 元数据端点等（来源：docs/architect-analysis-five-verified-expansion-directions.md, docs/tech-lead-analysis/cross-validated-five-new-directions.md, docs/requirements/high-value-expansion-directions.out.md）
- **Verifiable Credentials 验证（OID4VP）**：接受 presentation_definition/vp_token 并验证呈现凭证（来源：docs/architect-analysis-five-verified-expansion-directions.md, docs/tech-lead-analysis/cross-validated-five-new-directions.md）
- **自助会话管理 API（/me/sessions）**：列出/终止单个或全部会话，展示设备/IP/登录时间/最近活跃（来源：docs/feature-spec-architecture-synthesis-five-directions.md, docs/ROADMAP.md, docs/results/global-architecture-scan-four-production-blindspots-2026-07-11.out.arch.md, docs/results/senior-architect-expansion-v2-identity-gaps.out.arch.md）
- **并发会话配额限制与驱逐策略**：可配置每用户/租户最大并发会话数，支持严格拒绝/LRU 驱逐/仅告警，并修复配额检查-创建-驱逐的 TOCTOU 竞态（来源：docs/requirements/architect-expansion-2026-07-11.out.md, docs/results/architect-expansion-2026-07-11.out.arch.md, docs/requirements/deep-read-production-hardening-2026-07-11.out.md, docs/requirements/architect-fresh-code-scan-2026-07-11.out.md）
- **跨设备会话漫游**：短 TTL 单次声明令牌，让用户在新设备继续已认证会话，扩展 SessionHub 支持 User→SessionGroup→DeviceSession[] 模型（来源：docs/agent-os/architect-analysis/expansion-post-protocol-layer-architecture-review.md, docs/tech-lead-analysis-post-protocol-layer.md, docs/requirements/expansion-post-protocol-layer-analysis.out.md）
- **跨协议登出协调接线**：将已实现但零调用方的 `Coordinator.Logout()` 接入 `/logout`、`/end_session`、`/token/revoke-all`、lifecyclereactions 等路径，并加入循环防护标记（来源：docs/architecture/architect-analysis-expansion-five-directions.md, docs/tech-lead-plan-system-resilience-5-gaps.md, docs/tech-lead/tech-lead-analysis-five-true-new-gaps-2026-07-12.md, docs/requirements/architect-scan-deep-gaps-2026-07-11.out.md）
- **SessionHub LinkStore 生命周期管理**：新增 TTL、后台 reaper、`DeleteLeg`、`ListByUser` 及 SQLite/Redis 持久化，避免链接记录无限增长或重启丢失（来源：docs/tech-lead-plan-system-resilience-5-gaps.md, docs/requirements/architect-system-resilience-spa-ssrf-concurrency-5-gaps.out.md, docs/requirements/expansion-novel-v3-identity-system-quality.out.md, docs/requirements/deep-read-production-hardening-2026-07-11.out.md）
- **Session 感知的持续访问评估**：`mesh_authz` 校验 `sid` 对应会话是否仍存活，结合 SessionHealthCache 支撑高吞吐场景（来源：docs/results/expansion-gaps-analysis-2026-07-11.out.arch.md, docs/results/senior-architect-expansion-v8-2026-07-11.out.arch.md, docs/requirements/senior-architect-expansion-v8-2026-07-11.out.md）
- **统一授权决策管道（AuthzPipeline）**：将 Trust Scoring、Conditional Access、RBAC、ReBAC、WASM Authz 整合为单一决策，共享 decision_id，支持 dry-run 模拟与单调安全保证（拒绝不可被静默覆盖）（来源：docs/architecture/architect-analysis-expansion-five-directions.md, docs/requirements/architect-scan-deep-gaps-2026-07-11.out.md, docs/results/architect-unique-gaps-scan-2026-07-11.out.arch.md, docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.review.out.arch.md）
- **Authorization-as-a-Service PDP REST 端点**：新增 `POST /api/v1/authorize`，基于 CEL 表达式语言的策略 DSL（定义→编译→评估）（来源：docs/agent-os/architect-analysis/expansion-post-protocol-layer-architecture-review.md, docs/requirements/expansion-post-protocol-layer-analysis.out.md）
- **认证流水线 Hook 引擎（AuthHook）**：定义 pre/post-authenticate、pre/post-token-issuance 等阶段的可插拔钩子 SPI，支持优先级、超时与 fail-open/fail-closed 语义（来源：docs/architecture-analysis-peer-review-response.md, docs/tech-lead/tech-lead-analysis-five-true-new-gaps-2026-07-12.md, docs/results/architect-gap-analysis-2026-07-11.out.arch.md, docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.out.arch.md）
- **WASM 托管认证编排钩子**：复用现有 wasmauthz 沙箱，支持热加载 WASM Hook 用于第三方/客户自定义认证编排逻辑（来源：docs/architecture-analysis-peer-review-response.md, docs/tech-lead/tech-lead-analysis-five-true-new-gaps-2026-07-12.md, docs/results/architect-global-scan-v2-true-new-gaps-2026-07-12.out.arch.md）
- **声明式认证流程定义**：YAML/JSON 定义、静态校验的 auth_pipeline，支持分步 provider、风险分支、条件 MFA、租户/客户端继承（来源：docs/architecture-analysis-peer-review-response.md, docs/results/tech-lead-analysis-expansion-next-wave.out.arch.md）
- **密码生命周期策略强制执行**：新增 `PasswordSetAt`/`PasswordExpiresAt`/`ForcePasswordChange` 字段，登录路径检测密码过期返回 `password_expired`，配套管理员强制改密 API、过期提醒通知与宽限期（来源：docs/ROADMAP.md, docs/tech-lead/tech-lead-analysis-five-true-new-gaps-2026-07-12.md, docs/requirements/architect-deep-code-scan-5-undiscovered-gaps.out.md, docs/results/architect-fresh-scan-five-directions-2026-07-11.out.arch.md）
- **密码策略组件全流程接入**：将已存在的字典弱密码检测、HIBP 泄露检查、密码历史库实际接入注册/改密路径，并支持租户级策略差异化（来源：docs/requirements/senior-architect-5-gaps-2026-07-11.out.md, docs/results/senior-architect-5-gaps-2026-07-11.out.arch.md）
- **密码强度实时评估 API**：注册/改密流程中实时评估密码强度的独立端点（来源：docs/requirements/senior-architect-5-gaps-2026-07-11.out.md）
- **PasswordHistoryStore 持久化存储**：为当前仅内存实现的密码历史库新增 SQLite/Postgres 适配器（来源：docs/superpowers/plans/2026-07-02-wave2-tranche1.md, docs/results/architect-fresh-scan-five-directions-2026-07-11.out.arch.md）
- **MFA 恢复码（Recovery Codes）**：`RecoveryMFAProvider`、`/me/mfa/recovery-codes` 自助生成/重生成、管理员重置能力，持久化存储与配置化 provider kind（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md, docs/superpowers/plans/2026-07-02-wave2-tranche1.md）
- **SMS OTP 传输与短信服务商实现**：Twilio/AWS SNS/Vonage 等真实 SMS 传输后端及手机号自助注册/验证 UI（来源：docs/superpowers/plans/2026-07-02-wave2-tranche1.md, docs/requirements/Senior-Architect-Expansion-Directions-2026-07-11.out.md, docs/results/Senior-Architect-Expansion-Directions-2026-07-11.out.arch.md）
- **原生推送 MFA（APNs/FCM）**：移动 SDK 与服务端集成，通过原生推送完成 MFA 挑战，FCM HTTP v1 OAuth 令牌管理与 APNS HTTP/2 连接池（来源：docs/tech-lead/expansion-analysis-2026-07-11.md, docs/architecture/architect-analysis-expansion-v9-five-directions.md, docs/requirements/expansion-directions-v9-analysis.out.md）
- **“信任此设备”前端交互与分级信任级别**：登录 SPA 补充信任设备复选框、Portal 设备管理面板，及 TrustBasic/Extended/Managed 等信任级别枚举（来源：docs/feature-spec-architecture-analysis-five-verified-directions.md, docs/requirements/architect-fresh-scan-2026-07-11.out.md, docs/requirements/Senior-Architect-Expansion-Directions-2026-07-11.out.md）
- **自助“已授权应用”面板与撤销流程**：Portal SPA 展示已授权应用并对接 `DELETE /consents/me/:client_id`（来源：docs/tech-lead-analysis-peer-review-corrections.md, docs/results/expansion-ciam-identity-horizon.out.arch.md, docs/results/expansion-directions-v7-analysis.out.arch.md）
- **同意授权过期自动撤销后台任务**：可配置 sweeper 自动吊销过期同意授权并输出审计/指标（来源：docs/tech-lead-analysis-peer-review-corrections.md）
- **同意粒度与生命周期扩展**：Claim 级授权（`GrantedClaims`）、scope 修改 API、客户端 scope 漂移检测触发重新同意（来源：docs/requirements/architect-unique-gaps-scan-2026-07-11.out.md, docs/results/architect-unique-gaps-scan-2026-07-11.out.arch.md, docs/requirements/architect-fresh-code-scan-2026-07-11.out.md）
- **同意页面渲染器**：复用现有 form-post 降级模板体系构建同意屏（来源：docs/requirements/senior-architect-expansion-v5-post-scan.out.md）
- **Magic Link 无密码登录**：`POST /auth/magic-link`、`GET /auth/magic-link/verify`，复用 TempTokenStore + EmailSender + SessionManager（来源：docs/architecture/architect-analysis-expansion-v9-five-directions.md, docs/requirements/architect-gap-analysis-2026-07-11.out.md, docs/results/expansion-directions-v9-analysis.out.arch.md）
- **社交登录 Provider SPI（Google/GitHub/Microsoft）**：SocialProvider SPI、配置热重载、SPA 登录按钮、自动账户关联与档案属性丰富（来源：docs/tech-lead-analysis-peer-review-corrections.md）
- **外部 IdP 令牌交换（移动端）**：`ExternalTokenVerifier` SPI 支持 Google/Apple/GitHub id_token/access_token 直接换发本地令牌，含自动用户预配置与账户关联（来源：docs/results/expansion-edge-cases-2026-07-11.out.arch.md, docs/results/expansion-edge-protocol-hardening-platformization.out.arch.md）
- **Passkey 作为主认证方式包装**：新增 `provider=passkey` 包装层，使既有 WebAuthn 栈可作为主认证方式使用（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **身份核验/KYC/KYB/IAL 身份保证引擎**：`domains/identityproofing/` 状态机、活体检测/文档验证 SPI、第三方供应商适配器（Persona/Onfido/Jumio）、人工审核工作流、注册流程集成、User IAL 字段及条件访问维度（来源：docs/requirements/architect-expansion-analysis.out.md, docs/results/architect-expansion-analysis.out.arch.md, docs/results/expansion-directions-v7-analysis.out.arch.md, docs/results/expansion-directions-v9-analysis.out.arch.md）
- **非人类身份（NHI）/机器身份生命周期管理**：独立 ServiceAccount 实体模型、凭据轮换、NHIProvider SPI、级联吊销、`core.Subject.Type` 扩展与 MachineIdentityStore SPI（来源：docs/architect-analysis/nhi-posture-pq-architecture-review-2026-07-11.md, docs/requirements/architect-expansion-novel-5-horizons-scan.out.md, docs/results/senior-architect-expansion-v7-true-gaps-2026-07-11.out.arch.md）
- **跨协议身份自动解析与合并**：`IdentityResolver`/`IdentityMerger` 自动识别并合并跨 IdP 身份，限定为已验证邮箱匹配 + 管理员确认门控（来源：docs/architect-analysis/nhi-posture-pq-architecture-review-2026-07-11.md, docs/requirements/architect-expansion-novel-5-horizons-scan.out.md）
- **AI Agent 自助与管理控制台 UI**：`/me/agents` 自助管理页、`/admin/agents` 管理面板（含租户过滤与一键吊销）（来源：docs/tech-lead-analysis-frontier-paradigms-2026-07-12.md, docs/requirements/expansion-novel-2026-07-11.out.md, docs/results/expansion-novel-2026-07-11.out.arch.md）
- **多跳 Agent-to-Agent（A2A）授权链**：扩展现有单跳 `act` 委托链支持多跳，含最大链深度限制与循环检测（来源：docs/tech-lead-analysis-frontier-paradigms-2026-07-12.md, docs/requirements/architect-frontier-identity-paradigms-platform-resilience-2026-07-11.out.md, docs/results/expansion-novel-2026-07-11.out.arch.md）
- **MCP 工具调用人工审批（HITL）**：CIBA 风格的推送批准步骤，超时自动拒绝并审计（来源：docs/tech-lead-analysis-frontier-paradigms-2026-07-12.md, docs/requirements/expansion-novel-2026-07-11.out.md）
- **MCP 授权工具集与协议网关增强**：introspect_token/check_permission/list_permissions/list_roles/get_menus 五工具、RFC 9728 Protected Resource Metadata 端点、MCP Streamable HTTP 传输 + OAuth 资源服务器门控（来源：docs/superpowers/plans/2026-06-29-sso-mcp.md, docs/superpowers/specs/2026-06-29-sso-mcp-design.md）
- **特权访问管理（PAM）与临时权限提升**：`domains/pam/` 审批工作流、限时权限铸造、Admin 面板集成，Break-Glass 作为独立紧急旁路且不可用于批准 PAM 请求（来源：docs/requirements/expansion-novel-v2-identity-2026-07-11.out.md, docs/results/expansion-novel-v2-identity-2026-07-11.out.arch.md）
- **零常驻权限（ZSP）与持续授权评估引擎**：持续授权中间件（PEP）、ZSP 权限存储与管理 API、风险自适应降权，及拒绝后自动生成 PAM 提升建议（来源：docs/requirements/expansion-novel-v2-identity-2026-07-11.out.md, docs/results/expansion-novel-v2-identity-2026-07-11.out.arch.md）
- **HR 系统连接器框架**：Workday/SuccessFactors/通用 HRIS Connector SPI、字段映射管道、增量同步与冲突解决、CSV 批量导入、SCIM 客户端拉取模式（来源：docs/requirements/expansion-production-hardening-analysis.out.md, docs/results/expansion-production-hardening-analysis.out.arch.md, docs/results/expansion-novel-v2-identity-2026-07-11.out.arch.md）
- **批量用户迁移/导入 CLI**：支持 Auth0/Okta/Keycloak 导出格式，多格式密码哈希验证与懒重哈希，避免强制重置密码（来源：docs/ROADMAP.md, docs/results/expansion-directions-v7-analysis.out.arch.md）
- **统一多渠道通知基础设施**：`domains/notifications` Channel SPI（email/SMS/push/webhook）、用户通知偏好 API、同步/异步渠道区分，覆盖密码重置、邮箱验证、账户恢复、MFA 挑战、异常登录告警（来源：docs/feature-spec-architecture-synthesis-five-directions.md, docs/results/PEER_REVIEW_architect-expansion-novel-horizons-2026-07-11.out.arch.md, docs/results/global-architecture-scan-four-production-blindspots-2026-07-11.out.arch.md, docs/results/expansion-platform-evolvability-meta-governance.out.arch.md）
- **渐进式档案属性验证与来源追踪**：`AttributeStore`/`ProfileStore` SPI（验证状态、来源、置信度、过期）、`AttributeVerifier` SPI（邮箱/电话 OTP）、SCIM 属性同步、来源优先级冲突解决策略（来源：docs/tech-lead-analysis-peer-review-corrections.md, docs/results/expansion-ciam-identity-horizon.out.arch.md）
- **联邦 ACR 归一化映射与认证强度量表**：`ACRMapper` SPI 将 SAML AuthnContextClassRef/OIDC acr/WebAuthn 凭据类型映射为 0-100 统一认证强度量表，支持跨协议 step-up 判定（来源：docs/requirements/architect-expansion-novel-5-directions-2026-07-11.out.md, docs/results/architect-expansion-novel-5-directions-2026-07-11.out.arch.md）
- **AchievedACR 字段与 acr_values/max_age/prompt=login 强制执行**：实现目前不存在的 `AuthResult.AchievedACR`，并在登录时真正强制执行相关参数（来源：docs/ROADMAP.md）
- **动态 ACR 挑战与 ACRLevelRegistry**：`WWW-Authenticate: error="insufficient_acr"` 驱动动态步升，自定义 ACR 层级偏序比较（来源：docs/requirements/expansion-edge-cases-2026-07-11.out.md, docs/results/expansion-edge-cases-2026-07-11.out.arch.md, docs/results/expansion-edge-protocol-hardening-platformization.out.arch.md）
- **令牌交换链中 ACR/AMR 传播修复**：多跳 token exchange 沿 `act` 链一并传播 acr/amr，避免静默 ACR 升级（来源：docs/results/architect-expansion-novel-5-directions-2026-07-11.out.arch.md）
- **准确的多因素 AMR 声明**：从真实认证方法集合（含 MFA 步升）填充 `amr`，替代硬编码单一 provider（来源：docs/ROADMAP.md）
- **客户端应用分类与差异化安全策略**：`Client` 新增 `ApplicationType`/`TrustLevel`/`IsFirstParty`/`SoftwareID`/`SoftwareVersion` 字段驱动策略差异化（来源：docs/requirements/expansion-production-deployment-gaps.out.md, docs/results/architect-gaps-analysis-2026-07-11.out.arch.md）
- **客户端密钥过期强制执行与轮换宽限期**：`client_secret_expires_at` 从死代码变为真正校验，并提供轮换重叠宽限期（来源：docs/requirements/senior-architect-expansion-v6-true-gaps-2026-07-11.out.md）
- **证明式客户端认证（Attestation-based）**：基于设备/App 证明的客户端认证方法，草案阶段（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **个人访问令牌（PAT）自助管理**：`PATStore` SPI + `/me/tokens` 端点支持创建/列出/撤销（来源：docs/requirements/architect-unique-gaps-scan-2026-07-11.out.md）
- **硬件设备证明验证管道**：`AttestationVerifier` SPI 覆盖 Android Key Attestation、Apple App Attest、TPM 2.0、WebAuthn attestation，FIDO MDS 3.0 同步及 `require_attested_device` 策略，含移动端 `/auth/attestation/nonce`、`/verify` 端点（来源：docs/architecture/architect-analysis-expansion-five-directions.md, docs/requirements/architect-expansion-five-directions-2026-07-11.out.md, docs/results/architect-scan-2026-07-11.out.arch.md, docs/results/architect-next-five-horizons-2026-07-11.out.arch.md）
- **设备身份注册与生命周期管理**：`DeviceStore`/`DeviceLifecycleManager` SPI，复用现有 DeviceFingerprint 基础设施，支撑零信任设备身份支柱（来源：docs/requirements/architect-scan-2026-07-11.out.md, docs/results/architect-scan-2026-07-11.out.arch.md）
- **离线/边缘身份认证与令牌验证**：撤销列表缓存、离线 Token Validator SDK、IETF Token Status List JWT 消费、断线重连增量同步、IoT 设备离线令牌包（来源：docs/requirements/expansion-five-uncovered-gaps.out.md, docs/results/expansion-five-uncovered-gaps.out.arch.md, docs/results/expansion-novel-2026-07-11.out.arch.md）
- **邀请撤销（Invitation Revocation）**：为待处理的管理员邀请提供撤销开关（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **登录-MFA-同意-令牌全流程 TOCTOU 重验证**：修复用户在流程中途被停用仍可完成登录的潜在漏洞（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **邮箱变更验证闭环修复**：`email_change` 流程从未设置 `email_verified=true` 的缺陷修复（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **Backend-for-Frontend（BFF）安全模式模块**：独立部署模块为 SPA 提供服务器端会话管理，避免令牌暴露于浏览器（符合 OAuth 2.1 BCP/RFC 9700）（来源：docs/requirements/expansion-directions-v7-analysis.out.md）
- **select_account / 多账户选择器**：实现当前为死常量的 `prompt=select_account`，配合会话列表 SPI 与登录 SPA 账户选择 UI（来源：docs/requirements/expansion-directions-v8-analysis.out.md, docs/results/expansion-directions-v8-analysis.out.arch.md）
- **跨标签页会话同步**：BroadcastChannel/StorageEvent 同步多标签页登录/登出状态，缩小登出后令牌仍可用的安全窗口（来源：docs/requirements/expansion-directions-v8-analysis.out.md, docs/results/expansion-directions-v8-analysis.out.arch.md）
- **用户安全摘要与活动时间线**：`GET /me/security`、`GET /me/security/timeline` 聚合现有审计与近期登录数据，零新存储（来源：docs/requirements/architect-global-scan-five-uncovered-high-value-directions-v2-2026-07-11.out.md, docs/results/architect-global-scan-five-uncovered-high-value-directions-v2-2026-07-11.out.arch.md, docs/requirements/senior-architect-expansion-v3-identity-system-quality.out.md）
- **令牌健康评分与生命周期治理**：令牌健康/风险评分、废弃检测、过期预测、自动化清理（来源：docs/requirements/senior-architect-expansion-v3-identity-system-quality.out.md）
- **Identity-Aware Auth Proxy**：类 OAuth2 Proxy 的独立反向代理二进制，基于 OIDC/CAEP 栈网关化保护后端应用（来源：docs/requirements/architect-global-analysis-2026-07-11.out.md）
- **跨协议主体身份传播 SPI**：`PropagationContext` 在 OAuth/SAML/SCIM 边界传递原始主体身份，及 SAML 感知的 Pairwise Subject 映射（来源：docs/requirements/global-scan-expansion-directions.out.md, docs/requirements/senior-architect-expansion-v7-true-gaps-2026-07-11.out.md）
- **SCIM 企业扩展属性支持**：employeeNumber/costCenter/organization/division/department/manager 等企业用户属性及经理引用循环检测（来源：docs/requirements/senior-architect-expansion-v8-2026-07-11.out.md, docs/results/senior-architect-expansion-v8-2026-07-11.out.arch.md）
- **App-to-App 平台 SSO 抽象**：`PlatformSSOProvider`（iOS Associated Domains + 共享 Keychain、Android App Links + Digital Asset Links），让移动 SDK 复用同设备其他应用的登录态（来源：docs/results/expansion-directions-v13-analysis.out.arch.md）
- **按租户实例化认证器**：认证器工厂从全局 map 改为按租户懒加载，支撑企业租户差异化认证方式配置（来源：docs/results/expansion-directions-v7-analysis.out.arch.md）
- **统一身份会话抽象层（IdentitySessionHub）**：以 `SessionKind` 区分统一管理用户会话与管理员令牌，支持全局可视性、批量撤销与跨协议绑定传播（来源：docs/results/architect-fresh-code-scan-2026-07-11.out.arch.md）
- **自助账户恢复框架**：新增恢复令牌类型、隔离恢复会话、`RecoveryProvider` SPI 多方式验证、管理员审核/break-glass 集成，用于失去全部凭据的用户找回账户（来源：docs/architecture/architect-analysis-expansion-v9-five-directions.md, docs/results/expansion-directions-v9-analysis.out.arch.md）
- **认证证据组合编排（Evidence SPI）**：各认证器返回已验证证据等级，弥补认证方式间缺乏组合编排的架构缺口（来源：docs/results/expansion-directions-v9-analysis.out.arch.md）
- **移动 SDK 推送式远程撤销通知**：接收 CAEP 推送并在会话被远程撤销时清除本地存储令牌（来源：docs/architect-analysis-five-verified-expansion-directions.md）
- **CredentialStatusStore SPI**：跟踪凭据状态的独立存储抽象设计（来源：docs/results/expansion-directions-v10-analysis.out.arch.md）

---
## 联邦身份与信任链

### 已实现功能

- **OpenID Federation 1.0（信任链建立 + Fetch 端点 + 元数据策略）**：opt-in 五段式实现，涵盖 entity configuration、`/fetch` 端点（作为 federation superior/intermediate 对配置的下级实体签发签名 Subordinate Statement）、信任链校验 fail-closed（任何错误均判定失败，且从不直接抓取 anchor keys）、MetadataPolicy（对应 OpenID Federation 第10节的元数据约束）。（来源：docs/feature-matrix.md, docs/error-codes.md, docs/migration-roadmap.md, docs/SECURITY.md, docs/results/global-scan-expansion-directions.out.arch.md）
- **CAEP/SSF 双向共享信号（Shared Signals Framework）**：作为 transmitter 可选择性向 relying party 推送 Security Event Token，作为 receiver 通过 `/ssf/receive` 消费可信 transmitter 的签名安全事件并撤销本地访问；receiver fail-closed、校验 JTI 重放，接收端点仅在注册时校验为 HTTPS；transmitter 侧已具备事件投递结果指标（成功/失败/丢弃/重试）、投递协程 panic 恢复、以及可选的带指数退避+抖动的重试（每次重试重新签发 SET 以避免重放拒绝）。（来源：docs/feature-matrix.md, docs/error-codes.md, docs/observability.md, docs/ROADMAP.md, docs/SECURITY.md）
- **SAML 2.0 SP/IdP 支持（含跨协议单点注销）**：`saml/` 嵌套模块提供完整 SAML 2.0 SP+IdP、SSO+SLO 能力，内置 XSW/证书锁定/ACS 白名单/SSRF 防护；`SAMLLogoutTrigger` 接口经 `SessionHub.Fanout()` 接入跨协议会话中心，实现 SAML SLO 与 OIDC 会话联动注销（SAML IdP 启用时由 `saml.Build()` 自动调用 `SetSAMLTrigger` 完成接线）。（来源：docs/feature-matrix.md, docs/ROADMAP.md, docs/requirements/architect-global-scan-v2-true-new-gaps-2026-07-12.out.md, docs/requirements/deep-read-production-hardening-2026-07-11.out.md）
- **Mesh-native 身份数据面（单集群）**：HTTP+gRPC ext_authz filter 供服务网格 sidecar 调用、SPIFFE JWT-SVID 令牌交换、去中心化授权策略包导出，构成完整的单集群 mesh 身份控制面。（来源：docs/ROADMAP.md, docs/results/high-value-expansion-directions.out.arch.md）
- **上游 OIDC 联邦身份提供方（全局映射）**：内置 Google/Microsoft/GitHub/Auth0/Keycloak 五个上游 OIDC IdP 集成，基于既有 OIDC Federation Authenticator SPI；当前为全局扁平映射，所有租户共享同一上游 IdP 池，尚未按租户区分（后者见提议中的“租户级企业 Connections”）。（来源：docs/ROADMAP.md, docs/tech-lead-analysis-peer-review-corrections.md, docs/results/expansion-ciam-identity-horizon.out.arch.md）
- **B2B Connection 域名归属校验**：`connections.domain_verification.enabled` 要求管理员通过 DNS TXT 记录挑战证明域名控制权，才允许新连接声明一个已被其他连接验证过的域名，防止 home-realm-routing 域名被抢注。（来源：docs/config-reference.md）
- **B2B Connection / 联邦对端健康探测**：管理员触发的探测抓取 Connection 的 OIDC discovery 或 SAML metadata，持久化 healthy/degraded/unreachable 状态、时间戳及有界最近错误，并通过健康端点/管理路由（含证书到期阈值检查）读取，配套按类型和结果标注的健康探测指标。（来源：docs/config-reference.md, docs/observability.md, docs/results/senior-architect-expansion-v2-identity-gaps.out.arch.md）
- **云工作负载身份联邦连接器（GCP/AWS/Azure）**：GCP、AWS、Azure workload-identity 校验器基于运营方提供的租户 ID 推导出租户级 issuer 与 JWKS URL，使云工作负载可通过 `WithWorkloadIdentityProviders` 向 `/token` 完成认证。（来源：docs/deferred-backlog.md）
- **跨租户 B2B 协作令牌交换**：跨租户 token-exchange 要求同时存在 `TenantCollaboration` 信任记录与匹配的 `GuestRecord`，默认拒绝，并生成可追溯到源租户的内部审计事件。（来源：docs/error-codes.md）
- **Home Realm Discovery（登录期域路由，基础版）**：登录时依据 Connection 对象将用户路由到正确的归属 IdP 认证路径；当前该路由能力已可用，但对应的上游认证器实例仍为静态配置构建（动态实例化见提议中的相关条目）。（来源：docs/migration-roadmap.md, docs/requirements/architect-expansion-novel-5-horizons-scan.out.md）
- **Kubernetes Operator + CRD + MQTT/SSE 传输基础设施**：已有的 K8s Operator、CRD 定义及 MQTT/SSE 传输原语，为后续跨集群策略同步等能力提供了现成的基础设施基座。（来源：docs/results/tech-lead-analysis-expansion-next-wave.out.arch.md）

### 提议中/未来方向功能

- **跨集群令牌桥接端点（Cross-Cluster Token Bridge）**：新增 `POST /token/bridge`（或扩展 `/token/exchange`），将一个集群/信任域颁发的令牌转换为另一集群本地有效的等效令牌，保留 RFC 8693 `act` 声明链；可扩展为携带跨集群 SPIFFE JWT-SVID 作为 `subject_token`。（来源：docs/architect-analysis-five-verified-expansion-directions.md, docs/tech-lead-analysis/cross-validated-five-new-directions.md, docs/tech-lead/expansion-analysis-2026-07-11.md, docs/results/architect-next-five-horizons-2026-07-11.out.arch.md, docs/results/high-value-expansion-directions.out.arch.md）
- **Workload Identity Registry（SPIFFE 工作负载身份注册表）**：新增 SPI/CRD 支持跨集群、跨信任域注册、解析、列举、撤销 SPIFFE 工作负载身份，可选支持 Kubernetes ServiceAccount/Pod 的 informer 自动发现。（来源：docs/architect-analysis-five-verified-expansion-directions.md, docs/tech-lead-analysis/cross-validated-five-new-directions.md, docs/tech-lead/expansion-analysis-2026-07-11.md, docs/results/high-value-expansion-directions.out.arch.md）
- **多信任域 SPIFFE 联邦（Trust Bundle 同步）**：支持注册与联合多个 SPIFFE 信任域，各集群去中心化发布并互相验证 trust bundle，使一个集群签发的 JWT-SVID 能在另一集群通过验证，避免中心化信任的单点故障。（来源：docs/tech-lead-analysis/cross-validated-five-new-directions.md, docs/tech-lead/expansion-analysis-2026-07-11.md, docs/results/architect-next-five-horizons-2026-07-11.out.arch.md, docs/requirements/architect-expansion-five-directions-2026-07-11.out.md）
- **跨集群边缘身份缓存（Edge Identity Cache）**：边缘节点缓存授权决策与 JWKS 密钥以降低跨集群延迟，采用 TTL 最终一致失效策略，可选引入 CRLite 风格压缩撤销集合，支持 fail-open/fail-closed 配置。（来源：docs/architect-analysis-five-verified-expansion-directions.md, docs/tech-lead/expansion-analysis-2026-07-11.md）
- **跨集群策略同步（Cross-Cluster Policy Sync）**：可插拔 `PolicySyncTransport` SPI（主 MQTT/备 SSE，支持 HA broker 列表），周期性策略包同步、漂移检测（新增/移除/修改/冲突分类）、可配置冲突解决模式（`remote_wins`/`manual_review`）、带 `generation`/`observedGeneration` 的 Global Conditional Access Policy CRD 避免 reconcile 风暴、新增 `cluster.Bus` 事件类型驱动跨域信任变更与撤销广播、Envoy ext_authz 代理带熔断路由跨集群鉴权请求，以及分层通信架构（gRPC 写转发到主区域保证强一致、SSE/MQTT 用于最终一致的撤销/配置广播、JWKS/userinfo 本地读取）。（来源：docs/tech-lead-analysis/cross-validated-five-new-directions.md, docs/tech-lead-analysis-cross-verified-five-directions.md, docs/results/tech-lead-analysis-expansion-next-wave.out.arch.md, docs/results/architect-expansion-novel-horizons-2026-07-11.out.arch.md, docs/architecture-analysis-peer-review-response.md）
- **冷启动跨集群信任引导（Cold-Start Trust Bootstrap）**：新加入集群通过带外引导令牌安全获取初始信任包与策略的机制。（来源：docs/tech-lead/expansion-analysis-2026-07-11.md）
- **跨组织 Workload 联邦身份**：区别于同组织多集群联邦，提议支持 B2B 场景下跨独立组织的 SPIFFE 工作负载身份信任联邦。（来源：docs/requirements/architect-expansion-five-directions-2026-07-11.out.md）
- **可验证凭证基础设施（SD-JWT + DID Resolver）**：选择性披露 SD-JWT 签发/验证核心库，配合支持 `did:web`（依赖 DNS 信任）与 `did:key`（无域名场景）的 DID 解析器 SPI，作为可验证凭证能力的密码学基础。（来源：docs/tech-lead/expansion-analysis-2026-07-11.md, docs/results/architect-next-five-horizons-2026-07-11.out.arch.md）
- **OID4VCI 可验证凭证签发端点**：新增 `credential_offer` 与 `credential` 端点，符合 OpenID for Verifiable Credential Issuance 规范，复用现有签名密钥签发 SD-JWT 凭证，支持 Holder Binding 与 offer 生命周期管理。（来源：docs/tech-lead/expansion-analysis-2026-07-11.md, docs/results/architect-next-five-horizons-2026-07-11.out.arch.md, docs/requirements/expansion-directions-v7-analysis.out.md）
- **OID4VP 可验证凭证呈现验证端点**：处理 `presentation_definition` 请求并验证钱包提交的可验证呈现（Verifiable Presentation）。（来源：docs/tech-lead/expansion-analysis-2026-07-11.md, docs/results/architect-next-five-horizons-2026-07-11.out.arch.md）
- **凭证撤销状态列表（Status List）**：基于 Bitstring Status List（取代已退役的 Status List 2021）实现可验证凭证撤销状态查询，并通过集群消息总线异步向钱包传播撤销事件。（来源：docs/tech-lead/expansion-analysis-2026-07-11.md, docs/results/architect-next-five-horizons-2026-07-11.out.arch.md）
- **EUDI Wallet / eIDAS 2.0 互操作适配**：将可验证凭证签发适配至欧盟数字身份钱包架构参考框架（ARF），支持 eIDAS 2.0 PID 声明及跨信任域 SSRF 防护。（来源：docs/tech-lead/expansion-analysis-2026-07-11.md, docs/requirements/expansion-directions-v7-analysis.out.md）
- **跨实例身份桥接（Cross-Instance Identity Bridge）**：两个独立 SnapLink 实例间建立信任引导与主体身份双向映射（`InstanceTrustStore`/`SubjectMapper`/`ExternalInstanceStore` SPI，含 TTL 缓存），新增 `POST /token/bridge`（复用 RFC 8693）或 `grant_type=...instance-identity` 的 `/token` 分支，可拆分为实例发现（统一 `/.well-known/identity-platform` 元数据+能力声明）、主体映射、桥接令牌交换三层能力，用于 M&A/集团企业跨实例 SSO 场景。（来源：docs/requirements/architect-global-scan-five-uncovered-high-value-directions-v2-2026-07-11.out.md, docs/requirements/senior-architect-fresh-scan-2026-07-11.out.md, docs/requirements/senior-architect-global-scan-5-uncovered-expansion-directions.out.md, docs/results/senior-architect-fresh-scan-2026-07-11.out.arch.md, docs/results/senior-architect-global-scan-5-uncovered-expansion-directions.out.arch.md）
- **跨实例 Backchannel Logout**：持久化跨实例会话记录（`peer_instance+peer_subject→本地 session_ids`），新增传入 BCL 接收端点与传出 BCL 中继，实现跨 SSO 实例的单点注销传播。（来源：docs/requirements/architect-global-scan-five-uncovered-high-value-directions-v2-2026-07-11.out.md）
- **去中心化组织间协作发现（Decentralized Collaboration Discovery）**：组织间无需中心化预注册即可发现并协商 B2B 协作/联邦关系；分阶段落地为 `/.well-known/org-metadata` 声明式端点 + 信任请求 request/accept/reject/revoke CRUD API，并与既有 `TenantCollaborationStore` 集成，长期可扩展为跨组织联邦信任网络。（来源：docs/requirements/architect-global-scan-five-uncovered-high-value-directions-v2-2026-07-11.out.md, docs/requirements/senior-architect-fresh-scan-2026-07-11.out.md, docs/requirements/senior-architect-global-scan-5-uncovered-expansion-directions.out.md, docs/requirements/expansion-directions-analysis-v6.out.md, docs/results/architect-global-scan-five-uncovered-high-value-directions-v2-2026-07-11.out.arch.md）
- **动态联盟信任锚管理（Dynamic Trust Anchor Management）**：在 `domains/federation/` 中新增 `TrustAnchorCache`（自动续期 LRU）、`TrustGraph`（DAG + 环检测，最大信任深度2）与 `DynamicTrustAnchorLoader`，支持运行时增删信任锚而无需重启，防御递归信任与拒绝服务风险。（来源：docs/requirements/architect-fresh-scan-5-directions.out.md, docs/results/architect-fresh-scan-5-directions.out.arch.md）
- **租户级企业 Connections（per-tenant 上游 IdP 绑定）**：为 Tenant 模型新增 Connections 字段，使每个 B2B 企业租户可绑定自己的上游 SAML/OIDC 连接，取代当前单一全局认证器映射，实现员工登录各自企业 IdP。（来源：docs/ROADMAP.md, docs/results/expansion-ciam-identity-horizon.out.arch.md, docs/results/expansion-directions-v7-analysis.out.arch.md）
- **HRDResolver SPI（可插拔 Home-Realm Discovery）**：按用户邮箱域名将登录请求路由到匹配的租户企业连接（memory/sqlite/redis 可插拔实现），在 `/auth/login` 之前解析并重定向，无匹配则走默认密码认证。（来源：docs/ROADMAP.md, docs/results/expansion-ciam-identity-horizon.out.arch.md, docs/results/expansion-directions-v7-analysis.out.arch.md）
- **Connection 驱动的动态上游 IdP 认证器实例化**：`ConnectionAuthenticatorFactory` 在运行时按 Connection 对象创建并缓存 Authenticator 实例（LRU+TTL+失效），消费当前"死代码"的 `Connection.Config` 按租户动态实例化 SAML/OIDC 上游 IdP（含 HRD 交互与密钥/密文处理），取代一次性静态配置构建。（来源：docs/architect-analysis/nhi-posture-pq-architecture-review-2026-07-11.md, docs/requirements/architect-expansion-novel-5-horizons-scan.out.md, docs/superpowers/plans/2026-07-02-implementation-roadmap.md, docs/results/architect-expansion-novel-5-horizons-scan.out.arch.md）
- **上游 IdP 故障切换（Failover Orchestrator）**：`FailoverOrchestrator`/`SignerSwitcher`/`IdPSelector` 基于健康探测结果在多个上游 IdP 后端间自动切换活跃 IdP（v1 范围限定为同一 EntityID 下的多实例），SAML IdP 连接可在同一 EntityID 下列出多个 metadata URL 并接受任一实例的签名证书，暴露当前活跃 IdP 与故障切换回调供审计。（来源：docs/tech-lead-analysis/analysis.md, docs/requirements/senior-architect-expansion-v2-identity-gaps.out.md, docs/results/senior-architect-expansion-v2-identity-gaps.out.arch.md）
- **端到端 SSO 主动健康探测**：在现有轻量元数据/JWKS 端点被动探测基础上，增加模拟完整 SSO 登录流程的端到端主动探测，产出结构化 `IdPProbeResult`/`IdPHealth` 数据。（来源：docs/tech-lead-analysis/analysis.md, docs/requirements/senior-architect-expansion-v2-identity-gaps.out.md）
- **跨 IdP 故障切换的身份关联**：故障切换场景下不同上游 IdP 返回的 NameID/sub 可能不一致，需复用/扩展 `domains/identitylink` 完成跨 provider 用户关联。（来源：docs/requirements/senior-architect-expansion-v2-identity-gaps.out.md）
- **SAML 元数据版本管理**：对 SAML IdP 元数据进行版本管理，包括差异检测、新旧签名验证兼容滚动窗口，以及回滚触发活跃 SP 会话重新验证。（来源：docs/requirements/senior-architect-expansion-v2-identity-gaps.out.md）
- **SAML SLO 通过 revoke-all 扇出**：扩展 `POST /token/revoke-all`，同时清理 SAML SP 会话索引，并向每个下游 SP 发起前端通道 LogoutRequest 扇出。（来源：docs/requirements/senior-architect-expansion-v2-identity-gaps.out.md）
- **同意撤销事件的 CAEP/SSF 传播（consent_revoked SET）**：扩展 CAEP transmitter 新增 `consent_revoked` SET 类型，`ConsentStore.RevokeGrant` 通过 `cluster.Bus` 发布 `KindGrantRevoked` 并联动 CAEP transmitter 推送，取代当前仅记录审计事件的做法（`handleRevokeConsent` 中相关联动目前为未接线的 TODO），复用既有 kafka/MQTT 投递通道。（来源：docs/requirements/architect-unique-gaps-scan-2026-07-11.out.md, docs/requirements/expansion-ciam-identity-horizon.out.md, docs/results/architect-unique-gaps-scan-2026-07-11.out.arch.md, docs/results/expansion-ciam-identity-horizon.out.arch.md）
- **Anomaly-to-CAEP/RISC 事件映射扩展**：将内部异常检测事件映射为更多 CAEP/RISC 信号类型（如凭证泄露、会话撤销、令牌声明变更），扩展目前仅覆盖 3 种事件类型的 `event_mapper.go`。（来源：docs/requirements/global-scan-expansion-directions.out.md）
- **CAEP 广播多主体扇出**：当一次威胁处置影响多个主体时，复用现有 `SubjectClientIndex.ListBySubject` 基础设施，将 CAEP scopeSubject 广播批量扇出至所有受影响主体。（来源：docs/requirements/global-scan-expansion-directions.out.md）
- **CAEP 重试默认值与可观测性增强**：将 CAEP 广播默认重试次数从当前的 1 次提升为可配置的更高值，并新增重试成功/耗尽计数及首次尝试与重试延迟指标。（来源：docs/results/global-scan-expansion-directions.out.arch.md）
- **CAEP/SSF 接收端点注册的 SSRF 过滤缺口**：CAEP/SSF 接收端点虽仅限管理员配置且校验 HTTPS，但未做 SSRF 过滤，transmitter 会向任意已注册 HTTPS 主机 POST 已签名 SET，因此该 client attribute 的写权限不应下放给不受信的租户管理员。（来源：docs/SECURITY.md）
- **联邦/JAR 抓取的 DNS 重绑定 SSRF 防护**：在联邦元数据与 JWT 保护的授权请求对象（JAR）抓取时，对连接时刻实际解析出的 IP（而非仅字面主机名）重新校验，关闭指向内网/链路本地地址的 DNS 重绑定窗口。（来源：docs/ROADMAP.md, docs/requirements/expansion-directions-analysis.out.md）
- **联合 IdP 认证上下文（ACR）映射 SPI**：新增 `ACRMapper` SPI 与 `Session.ACR`/`FederatedACR` 字段，将 SAML `AuthnContextClassRef`、OIDC `acr` claim、LDAP、WebAuthn、Password+MFA 等异构联邦认证强度指示规范化映射为统一的 OIDC `acr` 值（当前联合登录用户无论上游认证强度如何都被赋予相同默认 ACR），可为映射引入随时间衰减机制以保障条件访问策略判断的时效性，使条件访问策略能基于联合登录认证强度做决策。（来源：docs/requirements/architect-deep-code-scan-5-undiscovered-gaps.out.md, docs/requirements/architect-expansion-novel-5-directions-2026-07-11.out.md, docs/requirements/architect-gap-analysis-2026-07-11.out.md, docs/results/architect-deep-code-scan-5-undiscovered-gaps.out.arch.md）
- **SAML NameID 主体映射器**：独立于现有 OIDC pairwise subject mapper 的 `SAMLSubjectMapper` SPI，按服务提供方需求将传播身份映射为不同的 SAML NameID 格式（persistent/transient/emailAddress/X509SubjectName）。（来源：docs/results/global-scan-expansion-directions.out.arch.md）
- **跨协议令牌翻译网关（TokenTranslator：SAML2/LDAP/Kerberos/RADIUS）**：新增 `TokenTranslator` SPI 与 `protocols/tokentranslate` 框架，分阶段将内部令牌翻译输出为 SAML2 断言（含 XML-DSig 签名，对应 token-exchange 的 `requested_token_type=saml2`，目前显式返回 `400 invalid_target`）、LDAP 绑定认证结果（可选触发临时用户置备）、Kerberos、RADIUS 等异构协议格式，亦可扩展为更广义的身份联邦代理/跨域身份网关（协议翻译引擎+无缝 SSO 会话桥接+发现元数据聚合）。（来源：docs/requirements/expansion-directions-v8-analysis.out.md, docs/requirements/expansion-directions-v7-analysis.out.md, docs/requirements/expansion-novel-v2-identity-2026-07-11.out.md, docs/results/expansion-directions-v7-analysis.out.arch.md, docs/results/expansion-directions-v8-analysis.out.arch.md）
- **外部 IdP 令牌交换（External IdP Token Exchange）**：新增 `ExternalTokenVerifier` 链，插入现有 `VerifyLocallyIssuedIDToken` 失败路径之前，支持将社交/外部 IdP（如仅签发 `access_token` 而无 `id_token` 的 GitHub）颁发的令牌交换为本系统令牌，通过调用其 userinfo API 构造 `VerifiedExternalToken`。（来源：docs/requirements/expansion-edge-cases-2026-07-11.out.md, docs/requirements/expansion-edge-protocol-hardening-platformization.out.md）
- **零信任网络接入（ZTNA）身份代理集成**：新增 `protocols/ztna/` 包定义 `ZTNAAssertionValidator`（校验设备信任/会话绑定/组等厂商特定 JWT 断言）与可组合的 `ZTNAGroupMapper` SPI（将验证后身份的组/角色映射为 ZTNA 厂商策略标签），并提供 Cloudflare Access 参考适配器校验 `CF-Access-Jwt-Assertion` 及 `session_iss`/`session_dur` 会话绑定检查。（来源：docs/requirements/expansion-five-uncovered-gaps.out.md, docs/results/expansion-five-uncovered-gaps.out.arch.md）
- **云 IAM 联邦角色映射（Cloud IAM Federation）**：通过配置声明的 scope→role 映射表（而非实时调用云厂商 IAM API）将 SSO scope 映射到 AWS/GCP/Azure 云角色，为工作负载身份联邦到云 IAM 提供角色发现与 scope 注入能力，避免引入云厂商 SDK 依赖；当前代码库零实现。（来源：docs/requirements/senior-architect-expansion-v7-true-gaps-2026-07-11.out.md, docs/results/senior-architect-expansion-v7-true-gaps-2026-07-11.out.arch.md）
- **跨协议主体传播 SPI（Principal Propagation）**：新增 `PrincipalPropagator` SPI，在 SAML↔OAuth、Token Exchange、CAEP/SSF 事件等协议边界传播统一的 Principal 身份标识，实现跨协议身份追踪（区别于统一身份归一化）。（来源：docs/results/senior-architect-expansion-v7-true-gaps-2026-07-11.out.arch.md）
- **SAML Bearer grant 断言签名校验缺口**：疑似缺口——SAML Bearer grant 可能在未检查断言 XML 中 `ds:Signature` 元素的情况下即完成反序列化，导致断言可被伪造。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **SAML↔Token Exchange 跨模块集成测试**：补充覆盖最高风险路径（SAML 断言被消费并交换为访问令牌）的跨模块集成测试，因嵌套模块目前各自独立构建，从未联合集成测试。（来源：docs/results/expansion-systemic-quality-horizon.out.arch.md）
- **OIDC 到 SAML 注销传播（SAML IdP 未启用时）**：提供机制使 OIDC 注销即便本地 SAML IdP 未启用（`SetSAMLTrigger` 仅在 `cfg.IdP.Enabled` 为 true 时才接线）也能传播到 SAML SLO。（来源：docs/requirements/deep-read-production-hardening-2026-07-11.out.md）
- **联邦威胁情报共享（Federated Threat Intelligence）**：将 CAEP/SSF 从单实例扩展为跨信任链实例间的联邦威胁指标共享，新增 `ThreatIndicator` SPI 与 `ThreatFeed` 存储，支持 TTL/撤销、去重、联邦信任链校验及 GDPR 第49条数据共享保护。（来源：docs/results/expansion-directions-v12-analysis.out.arch.md）
- **SSF 流管理/元数据/轮询投递**：在当前仅支持推送式 CAEP 投递的基础上，完善共享信号框架（SSF）的流管理、流元数据与轮询式投递能力，同时保持 receiver 侧 fail-closed。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）


---
## 密钥管理与加密

### 已实现功能

- **统一 JWT 签发与 DPoP/mTLS 发送者约束绑定**：defaulttoken/jwt_issuer.go 单一签发器已支持 DPoP/mTLS 发送者约束绑定与刷新令牌轮换的统一 JWT 签发。（来源：docs/architecture/architect-analysis-expansion-v9-five-directions.md）
- **JWE 加密 OIDC 响应（ID Token / UserInfo）**：`oidc.response_encryption.backend` 按客户端注册的算法（RSA-OAEP-256 和/或 ECDH-ES）对 id_token 与 `/userinfo` 响应加密，对应 OIDC §10.2/§5.3.2 加密 ID Token 与 UserInfo 规范。（来源：docs/config-reference.md, docs/feature-matrix.md）
- **可配置签名算法选择**：`keys.signing.alg` 支持选择 EdDSA、ES256、RS256 或 PS256 作为服务端签名算法。（来源：docs/config-reference.md）
- **定时签名密钥轮换循环**：`keys.rotation.*` 自动轮换密钥，发出 `signing_key_rotated` 审计事件与指标，并失效已签名的发现文档缓存。（来源：docs/config-reference.md）
- **签名密钥轮换宽限/重叠窗口**：`keys.rotation.grace_period` 控制降级密钥保持 verify-only 的时长，同时也是按需管理员轮换的默认重叠窗口。（来源：docs/config-reference.md）
- **按需管理员密钥轮换与列表 API**：`POST /api/v1/admin/keys/rotate` 立即轮换主签名密钥，`GET /api/v1/admin/keys` 列出公钥元数据。（来源：docs/config-reference.md）
- **多副本协调式签名密钥切换**：`keys.rotation.coordinated_cutover` 经集群总线广播降级/新密钥 ID 与退役截止时间，fail-safe 保证延迟退役只会扩宽验证窗口，绝不提前退役；JWK Set 端点本身也支持轮换重叠窗口以避免验证失败。（来源：docs/config-reference.md, docs/deployment.md, docs/ROADMAP.md, docs/sso/oidc-conformance.md）
- **持久化签名密钥吊销存储**：`keys.signing.revocation_backend` 跨重启持久化签名密钥吊销记录，启动时重新播种。（来源：docs/config-reference.md）
- **无主（Leaderless）跨副本签名密钥聚合与采纳**：`keys.signing_key_registry`/`platform/signingkeys` 让各副本经 etcd 或集群总线互相聚合、算法匹配后采纳彼此的签名公钥，无需选主，保持 JWKS 全集群一致，不健康时降级 `/readyz`。（来源：docs/config-reference.md, docs/deployment.md, docs/ROADMAP.md）
- **FIPS 140 签名模式与启动断言**：`keys.signing.fips_mode` 要求激活的 FIPS Go 密码模块，启动时调用 `fipspolicy.ValidateIssuerAlg` 校验签名算法是否在 FIPS 186-5 批准列表内（可选 `fips_allowed_algs` 进一步收窄），否则拒绝启动。（来源：docs/config-reference.md, docs/fips.md）
- **独立内省签名密钥与 JWKS 内省密钥发布（RFC 9701）**：`keys.introspection_signing.enabled` 构建拥有独立密钥和轮换周期的内省专用签发器，JWKS 发布独立 `use: introspection` 条目，经 `application/token-introspection+jwt` Accept 头协商。（来源：docs/config-reference.md, docs/feature-matrix.md）
- **快照加密**：`snapshot.encryption.backend` 用 argon2id+XChaCha20-Poly1305 口令派生密钥或算子提供的密钥（如 KMS 签发的 DEK）封装配置快照信封，生产环境使用，`none` 后端仅供测试。（来源：docs/config-reference.md, docs/SECURITY.md）
- **定时凭证轮换（webhook HMAC 密钥等）**：`rotation.*` 构建带重叠窗口的轮换注册表/调度器，确保在途投递仍可用旧凭证认证。（来源：docs/config-reference.md）
- **紧急凭证泄露强制轮换**：`POST /api/v1/admin/credentials/{type}/compromise` 立即 off-schedule 强制轮换泄露的凭证类别，无重叠窗口，并记录合规证据链。（来源：docs/config-reference.md, docs/error-codes.md）
- **FIPS 140-3 构建模式与运行时切换**：`GOFIPS140=latest, CGO_ENABLED=0` 构建纯 Go FIPS 合规二进制/镜像（默认关闭），也可通过 `GODEBUG=fips140=on/only` 在已编译二进制上运行时切换，无需重新构建。（来源：docs/deployment.md, docs/fips.md）
- **可配置 TLS 终止**：`--tls-cert`/`--tls-key` 均设置时进程内终止 TLS，否则由前置边缘（如 OpenResty）终止。（来源：docs/deployment.md）
- **FIDO MDS 签名的 attestation 证书链校验**：接入 FIDO Metadata Service blob 后，WebAuthn attestation 证书链校验至 FIDO 根，使 AAGUID 允许列表具备抗伪造自签名证书能力。（来源：docs/error-codes.md）
- **密码材料清单与应急上报端点**：只读目录列出服务端已知的全部密钥（签名、JWE、KMS 托管、信任锚点），并提供尽力而为触发所属机制退役的应急上报端点。（来源：docs/error-codes.md）
- **SDK 出站 webhook HMAC 签名与验证**：出站 webhook 传输可用 HMAC-SHA256（Stripe/Svix 风格）签名投递，并提供 SDK 辅助函数供接收方验证签名与新鲜度；另有提案将该机制扩展至 MFA/CIBA 推送 webhook 投递。（来源：docs/error-codes.md, docs/superpowers/plans/2026-07-02-wave1-quick-wins.md）
- **RFC 8705 mTLS 发送者约束令牌、证书绑定别名与吊销检查**：`/token`、`/userinfo` 经可插拔客户端证书提取器实现 mTLS 绑定令牌；客户端认证证书与终端用户 X.509 登录均支持可选吊销检查，检查器出错时 fail-open。（来源：docs/feature-matrix.md）
- **RFC 9449 DPoP 发送者约束令牌**：`/token`、`/userinfo` 的 DPoP proof-of-possession 校验，含重放保护与可选 nonce 质询。（来源：docs/feature-matrix.md, docs/migration-roadmap.md）
- **RFC 8414 §2.1 签名的发现元数据**：可选的加密签名 discovery 文档。（来源：docs/feature-matrix.md）
- **RFC 9101 §6.4 加密 JAR（JWE）**：支持通过算子提供的 `use: enc` 密钥解密 JWE 加密的授权请求对象。（来源：docs/feature-matrix.md）
- **原生 Go FIPS 140-3 密码模块支持**：纯 Go（非 cgo/BoringCrypto）FIPS 140-3 验证密码模块，构建期（`GOFIPS140`）或运行期启用，四种签名算法（EdDSA/ES256/RS256/PS256）均为 FIPS 186-5 批准并经自检，可选择模块成熟度（off/latest/pinned/inprocess/certified）。（来源：docs/fips.md）
- **签名密钥相关可观测性指标族**：轮换计数、按算法签名操作计数/耗时/结果、签名后端健康、对等密钥采纳/聚合/切换指标、保留窗口内对等采纳密钥修剪计数、验证专用密钥集大小、进程内签名使用等指标。（来源：docs/observability.md）
- **KMS/HSM 外部签名后端统一接口**：AWS KMS、GCP KMS、Azure Key Vault、PKCS#11、HashiCorp Vault 五个后端已实现统一的 KeyManager 接口，满足 FIPS/PCI-DSS/SOC2 密钥托管要求，各自以独立互斥锁保护签名调用。（来源：docs/ROADMAP.md, docs/tech-lead/expansion-analysis-2026-07-11.md, docs/results/architect-expansion-5-directions.out.arch.md, docs/requirements/global-scan-five-directions.out.md）
- **四算法签名矩阵与运行时轮换**：EdDSA、ES256、RS256、PS256 签发器均支持运行时密钥轮换、调度、KMS 签名器接缝与严格的算法混淆防护。（来源：docs/ROADMAP.md）
- **JWT 签名算法允许列表与算法加固**：仅 EdDSA、ES256/384/512、RS256、PS256 被接受为 JWS 算法，显式禁用 `alg=none`；`private_key_jwt` 在验签前先校验算法。（来源：docs/SECURITY.md, docs/security-policy.md）
- **多活跃 kid 的 JWKS 轮换支持**：JWKS 缓存支持多个同时生效的 key ID，轮换密钥不中断在途验证。（来源：docs/SECURITY.md）
- **OIDC 签发算法与密钥治理**：ID Token 支持 RS/PS/ES 256/384/512 与 EdDSA 等可配置签名算法，EdDSA 优先于 ECDSA 优于 RSA，弱算法（HS256、小 RSA 密钥）不受支持。（来源：docs/sso/oidc-conformance.md）
- **集中式 JWT 签名验证入口 VerifyCompactJWS**：所有外部 JWT 验证路径（rs/validate、remote/auth、federation、JAR、private_key_jwt）统一收敛，解析前拒绝 `alg=none` 和对称算法。（来源：docs/requirements/senior-architect-5-gaps-2026-07-11.out.md）
- **KMS 密钥管理包（kms/）**：已有的密钥管理服务集成包，可复用于保护跨集群 CA 私钥等场景。（来源：docs/tech-lead/expansion-analysis-2026-07-11.md）
- **集群协调式切换模式（可复用）**：`signingkeys.CoordinatedCutover` 实现的集群协调、fail-safe、基于截止时间的切换模式，可复用于其他协调场景（如事件溯源检查点）。（来源：docs/requirements/architect-remaining-horizon-2026-07-11.out.md）
- **签名操作指标包装器（instrumentedSigner）**：已有包装 `crypto.Signer` 的组件，记录本地与 KMS 签名器的延迟与结果指标。（来源：docs/requirements/expansion-runtime-infrastructure-analysis.out.md）
- **签名密钥轮换调度引擎（platform/lifecycle/rotation）**：已有的密钥轮换调度引擎，被引用为未来通用凭证 Rotator SPI 的实现模板。（来源：docs/requirements/expansion-secrets-slo-challenge-posture-billing.out.md）
- **对等采纳密钥缓存互斥锁保护（现状）**：`adoptedPeerMu` 目前以 `sync.Mutex` 保护无主对等签名密钥采纳的缓存/验证器结构。（来源：docs/results/global-scan-five-directions.out.arch.md）

### 提议中/未来方向功能

- **后量子密码学（PQC）混合签名与算法注册表**：引入 ML-DSA、SLH-DSA 等后量子签名算法，支持经典+PQ 双签名（HybridSignature 结构、复合 alg 命名如 `ES256+ML-DSA-44`、复合 JWKS kid），将静态签名算法枚举重构为可运行时注册的 AlgorithmRegistry SPI 以插件化接入 PQ 算法（独立 `pq/` 子模块，基于 cloudflare/circl），配套 PQ 迁移指南、性能基准测试与 FIPS 140-3 密码边界文档，并提供令牌体积膨胀告警机制。（来源：docs/architect-analysis/nhi-posture-pq-architecture-review-2026-07-11.md, docs/tech-lead-analysis-frontier-paradigms-2026-07-12.md, docs/results/expansion-novel-2026-07-11.out.arch.md, docs/requirements/senior-architect-expansion-v5-post-scan.out.md, docs/results/architect-expansion-novel-5-horizons-scan.out.arch.md）
- **密码算法生命周期迁移框架（双签发/双公钥 + 状态机 + 管理 API）**：建立算法迁移状态机（Announce/Planning → DualIssuance/DualWriteVerify → Cutover/RollingIssue → Cleanup/Complete），协议层双签发使 JWKS 同时发布新旧公钥（alg 后缀 kid），CompositeIssuer 包装多个 TokenIssuer 支持新旧算法并存验证，发现文档新增 `alg_migration` 字段，并提供管理员 API 与 `sso-ctl migrate algorithm` CLI（含 dry-run）以启动/推进/回滚迁移。（来源：docs/tech-lead-analysis-five-directions.md, docs/tech-lead/expansion-five-directions-v2-peer-review-implementation.md, docs/requirements/expansion-directions-v12-analysis.out.md, docs/results/architect-final-five-2026-07-11.out.arch.md, docs/results/global-architecture-scan-five-uncovered-high-value-directions-2026-07-11.out.arch.md）
- **客户端密钥哈希存储与全生命周期管理**：将 OAuth 客户端 secret 由明文/`!=` 比较改为 bcrypt/argon2 哈希 + 常量时间比较（双列迁移支持灰度回滚），并扩展为自动轮换、过期、版本历史，DCR 与联邦自动注册产生的密钥应有独立轮换策略。（来源：docs/ROADMAP.md, docs/superpowers/plans/2026-07-02-implementation-roadmap.md, docs/requirements/architect-fresh-scan-5-directions.out.md, docs/results/architect-expansion-novel-5-directions-2026-07-11.out.arch.md）
- **KMS 复合签名器自动故障切换与状态生命周期**：CompositeSigner 包装现有 AWS/GCP/Azure/PKCS11 等 KMS 签名器，超时后自动切换到备用后端（含冷备懒初始化），引入 Normal→Degraded→RetireWindow→Normal 状态机，降级期签发密钥标记 degraded 并进入退役窗口并记录审计事件；KeyStatusController 按 TTL 从已发布 JWKS 中剔除降级密钥。（来源：docs/tech-lead-analysis/analysis.md, docs/requirements/senior-architect-expansion-v2-identity-gaps.out.md, docs/results/senior-architect-expansion-v2-identity-gaps.out.arch.md）
- **KMS 降级期回退签名算法的下游识别**：`securityverify` 等下游验证路径（DPoP proof 验证、JWKS）需新增回退算法映射，以识别 KMS 降级期签发令牌所用的回退算法标签（如 `ES256_FALLBACK`）。（来源：docs/tech-lead-analysis/analysis.md, docs/requirements/senior-architect-expansion-v2-identity-gaps.out.md）
- **KMS 签名限流与熔断保护**：throttledSigner 在每次 KMS `Sign()` 调用前获取可配置信号量，超出吞吐配额时拒绝（503）或排队；`shared/resilience` CircuitBreaker 包装对外部 KMS/HSM 调用，持续错误/限流时快速失败并回退本地签名器（状态暴露于 `/readyz`），并支持三种可配置降级模式（fail_closed/fallback_local/fallback_cached）。（来源：docs/requirements/expansion-runtime-infrastructure-analysis.out.md, docs/results/expansion-runtime-infrastructure-analysis.out.arch.md, docs/results/architect-fresh-scan-5-directions.out.arch.md）
- **跨云 KMS 密钥编排与 BYOK**：在现有 AWS/GCP/Azure/PKCS11/Vault 五个 KMS 后端之上新增跨云密钥轮换编排层（公钥同步、故障切换后提升、领导者选举/租期协调），并支持企业客户将同一密钥材料导入并同步到多个 HSM/KMS 后端（Bring Your Own Key）。（来源：docs/requirements/architect-expansion-5-directions.out.md, docs/results/architect-expansion-5-directions.out.arch.md）
- **硬件密钥/设备 Attestation（HSM KeyOrigin + TPM + FIDO MDS 3.0）**：为 TokenIssuer 新增可选 KeyOrigin 概念（Unattested/HSMGenerated/Imported/Unknown）并在 JWK 上暴露来源字段，各 KMS 后端分别实现来源查询以满足 FIPS/PCI-DSS/SOC2 审计；新增硬件设备 attestation SPI（Android KeyStore/iOS App Attestation/TPM/平台证书）并集成 FIDO MDS 3.0 用于设备可信度验证。（来源：docs/requirements/architect-scan-2026-07-11.out.md, docs/requirements/senior-architect-expansion-v8-2026-07-11.out.md, docs/results/senior-architect-expansion-v8-2026-07-11.out.arch.md, docs/results/architect-expansion-five-directions-2026-07-11.out.arch.md）
- **非人类身份（NHI）凭证存储与轮换**：新增 CredentialStore SPI，以单事务原子方式为 ServiceAccount 签发/吊销/批量吊销（RevokeAll）API Key、X.509、OAuth2 客户端凭证，配套拉模型凭证轮换调度器（含轮换截止时间，旧凭证到期未激活则强制吊销）。（来源：docs/architect-analysis/nhi-posture-pq-architecture-review-2026-07-11.md）
- **刷新令牌查找哈希抗量子加固**：将刷新令牌数据库查找哈希从 HMAC-SHA-256 升级到 SHA-384/512，以在 Grover 算法与 harvest-now-decrypt-later 风险下保留安全裕度。（来源：docs/architect-analysis/nhi-posture-pq-architecture-review-2026-07-11.md）
- **分片 DPoP nonce 存储**：提出一致性哈希 + 布隆过滤器 + 滑动窗口的分片方案，以支持大规模多节点部署下的 DPoP nonce 跟踪。（来源：docs/agent-os/architect-analysis/expansion-post-protocol-layer-architecture-review.md）
- **SD-JWT 选择性披露凭证格式**：新增基于 JWT 的 `_sd`/`_sd_alg` 选择性披露凭证格式，复用现有 EdDSA/ES256/RS256 签名基础设施，实现签发（salted hash 管理）、持有者呈现与选择性披露验证。（来源：docs/architect-analysis-five-verified-expansion-directions.md, docs/results/architect-next-five-horizons-2026-07-11.out.arch.md）
- **GitOps 敏感配置字段加密（SOPS/age）**：对 Git 配置文件中存储的 `client_secret` 等敏感字段使用 SOPS/age 加密，由协调器在 apply 前解密。（来源：docs/architect-analysis-five-verified-expansion-directions.md, docs/requirements/high-value-expansion-directions.out.md）
- **字段级加密/E2EE 框架**：依托 KMS 层级密钥管理，为 TOTP 密钥、刷新令牌等敏感字段提供信封加密（含既有明文行迁移路径），并以按租户密钥层级支持按表/按行的透明 AEAD 字段级加密或端到端加密能力。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md, docs/requirements/expansion-novel-v4-privacy-dx-operations.out.md, docs/results/expansion-novel-v4-privacy-dx-operations.out.arch.md）
- **运行时 API 密钥/密钥对轮换 API**：复用现有签名密钥轮换机制（重叠窗口、集群总线广播）新增运行时轮换 API Key/密钥对的接口。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **JWS/JWE 统一头部校验强化（typ/crit/jku/x5u/jwk）**：扩展 VerifyCompactJWS 新增 `allowedTyps` 参数以统一目前分散在四处（rs/validate、server_pairwise、server_jar、server_dpop）的 typ 头校验；显式拒绝 JWS crit 头；将 defaultjwe/*.go 中绕过统一校验、直接调用 `jose.ParseEncryptedCompact` 的 JWE 解密路径纳入统一头部校验；新增对 jku/x5u/jwk 头部的显式白名单拒绝以防 SSRF/密钥混淆。（来源：docs/requirements/senior-architect-5-gaps-2026-07-11.out.md, docs/results/senior-architect-5-gaps-2026-07-11.out.arch.md）
- **时序攻击审计测试套件**：可重复运行的测试套件系统性验证所有安全敏感比较均使用常量时间比较，并审计 SQL 查询模式是否存在行存在性时序泄露。（来源：docs/results/senior-architect-5-gaps-2026-07-11.out.arch.md）
- **跨集群 mTLS 证书颁发机构与信任锚点轮换协调**：工作负载 mTLS CA SPI（签发/验证/轮换/吊销，可选 SPIRE 集成），支持自动证书轮换、CRL 分发、基于 SPIFFE-ID 的 mTLS 入口中间件，并配套联邦信任锚点轮换协调协议，确保参与集群同步切换信任锚点。（来源：docs/tech-lead-analysis/cross-validated-five-new-directions.md, docs/tech-lead/expansion-analysis-2026-07-11.md, docs/requirements/high-value-expansion-directions.out.md）
- **自定义域名 TLS 证书自动化（ACME）与通用证书生命周期管理**：新增 CertificateProvisioner/ACMEProvisioner SPI（基于 go-acme/lego 对接 Let's Encrypt/ZeroSSL，支持 HTTP-01/DNS-01/TLS-ALPN-01 challenge）自动签发、分级到期告警续期（30/14/7/1 天）并吊销租户自定义域名证书，比照现有签名密钥轮换的重叠窗口语义实现通用证书自动续期/轮换/吊销以避免停机。（来源：docs/feature-spec-architecture-synthesis-five-directions.md, docs/results/architect-expansion-2026-07-11.out.arch.md, docs/results/architect-scan-deep-gaps-2026-07-11.out.arch.md, docs/results/global-architecture-scan-four-production-blindspots-2026-07-11.out.arch.md）
- **快照 gRPC 连接的 mTLS 加固（延期项）**：计划将 sso-mcp-to-snaplink gRPC Authorizer 连接由 insecure 升级为 TLS/mTLS。（来源：docs/superpowers/plans/2026-06-29-sso-mcp.md）
- **通用密钥/凭证轮换 SPI 与密钥治理**：引入统一 SecretRef 类型与 SecretResolver SPI（支持 inline/env/file/AWS/GCP/Azure/Vault/K8s 后端）取代配置中的明文凭证字段，并提供 Rotator/CredentialRotator SPI 将现有签名密钥轮换调度器泛化到任意运维凭证（SMTP/DB/Redis 密码等），复用双凭证重叠窗口轮换语义。（来源：docs/requirements/expansion-secrets-slo-challenge-posture-billing.out.md, docs/results/expansion-secrets-slo-challenge-posture-billing.out.arch.md）
- **自动化凭证生命周期策略引擎与轮换后验证**：CredentialPolicyEngine 提供全局→租户→单个凭证的分层策略叠加与 ResolvePolicy 方法自动确定任意凭证类型的轮换节奏，轮换后由 RotationValidator 自动运行完整 OAuth 流程（签发/内省/userinfo/撤销）验证新凭证并在失败时回滚，并扩展现有轮换调度器驱动 OAuth 客户端密钥的定时自动轮换。（来源：docs/requirements/expansion-five-uncovered-gaps.out.md, docs/results/expansion-five-uncovered-gaps.out.arch.md）
- **令牌水印追踪机制**：在已签发 JWT 中嵌入 `wmk` 声明编码签发租户、区域、风险标签与 jti 指纹以支持泄露令牌溯源；更隐蔽的方案将水印编码并用专用水印加密密钥加密于 JWT 头部；针对不透明刷新令牌则在其前导字节编码溯源/水印信息以获得最高信息密度。（来源：docs/results/global-architecture-scan-five-uncovered-high-value-directions-2026-07-11.out.arch.md）
- **分区域签名密钥 ID 与区域感知 JWKS 过滤**：签名密钥 kid 前缀化区域标识（如 `eu-west-1:abcd1234`）并将区域标签贯穿审计/指标/追踪；JWKS 端点可选按区域过滤已发布密钥，同时验证时仍接受所有区域密钥（联合验证集）。（来源：docs/tech-lead/expansion-five-directions-v2-peer-review-implementation.md, docs/requirements/Senior-Architect-Expansion-Directions-2026-07-11.out.md）
- **跨区域 JWKS 验证缓存**：新增基于 TTL 的跨区域公钥缓存（默认 5 分钟），区域间通过 HTTP 拉取并缓存彼此 JWKS，签发区域不可用时回退本地缓存，避免验证请求的实时跨区域网络依赖。（来源：docs/requirements/global-scan-expansion-directions.out.md, docs/results/architect-scan-deep-gaps-2026-07-11.out.arch.md, docs/results/global-architecture-scan-four-production-blindspots-2026-07-11.out.arch.md）
- **JWKS 缓存与令牌缓存联动失效**：密钥轮换导致 JWKS 更新时同步失效 L1 令牌缓存，防止已缓存的有效令牌因签名密钥失效而在验证时产生不一致。（来源：docs/results/architect-expansion-5-directions.out.arch.md）
- **多信任域 JWKS 聚合端点（联邦）**：JWKS 端点聚合本地集群密钥与所有已注册对等信任域的公钥（域前缀化 kid），发现文档新增 `trust_domains_supported` 字段。（来源：docs/tech-lead-analysis/cross-validated-five-new-directions.md）
- **签名密钥采纳路径读写锁优化（RWMutex 审计）**：将 `adoptedPeerMu` 的 `sync.Mutex` 替换为 `sync.RWMutex`，避免并发验签读操作被对等密钥采纳写操作阻塞串行化，并作为代码库范围内读多写少互斥锁（如 discovery 缓存）审计转 RWMutex 的一部分，以提升 KMS 高延迟场景下的读路径并行度。（来源：docs/requirements/global-scan-five-directions.out.md, docs/results/global-scan-five-directions.out.arch.md）
- **远程客户端 SDK 多算法 JWT 验证**：升级 `ssoclient/remote` 目前仅支持 EdDSA 的令牌验证器与 JWKS 缓存以支持 ES256/RS256/PS256，与服务端及 KMS 对等节点已签发的算法保持一致。（来源：docs/ROADMAP.md）
- **签名密钥发布方 lease 健康监控与自愈**：检测并恢复签名密钥发布侧 etcd KeepAlive lease 失效（重新授租/重新发布），防止租约静默过期导致副本自身公钥在集群范围内被悄然丢弃而该副本仍继续使用其签名，并补齐缺失的 readiness 降级与审计。（来源：docs/ROADMAP.md, docs/results/expansion-directions-analysis.out.arch.md, docs/results/expansion-directions-v7-analysis.out.arch.md）
- **SQLite ClientStore 安全字段持久化补全**：持久化 SQLite 后端当前静默丢弃的安全承载 Client 字段（JWKS、AllowedResources、AllowedRequestURIs、RegistrationAccessToken、JWE alg/enc、Federation、PostLogoutRedirectURIs），避免重启后归零。（来源：docs/ROADMAP.md, docs/superpowers/plans/2026-07-02-implementation-roadmap.md, docs/results/expansion-directions-analysis.out.arch.md）
- **JWKS 服务端响应体缓存**：为计算得到的 JWKS 文档体新增短时有界缓存（目前仅做 single-flight 合并、每次轮询都重新序列化和哈希），与发现文档的 body+ETag 缓存对齐。（来源：docs/ROADMAP.md）
- **令牌敏感度分级与自适应保护**：基于 scope 推导令牌敏感度等级，驱动差异化 TTL、敏感 scope 强制 DPoP、按敏感度隔离刷新令牌家族，取代当前统一的令牌策略。（来源：docs/architecture/architect-analysis-expansion-v9-five-directions.md, docs/results/expansion-directions-v9-analysis.out.arch.md）
- **智能体委派令牌 DPoP 绑定**：为智能体委派令牌支持 DPoP 密钥绑定（`cnf.jkt`），并在使用时校验。（来源：docs/tech-lead-analysis-frontier-paradigms-2026-07-12.md）
- **密码材料清单的 PQ 算法分类扩展**：在运行时密钥清单基础上增加按经典/后量子/混合算法分类的报告，支撑后量子迁移规划。（来源：docs/architect-analysis/nhi-posture-pq-architecture-review-2026-07-11.md）
- **边缘身份缓存与 CRLite 压缩吊销集**：为跨集群工作负载提供边缘 JWKS/内省缓存，以及基于 CRLite（cuckoo filter + 级联哈希）的压缩证书吊销集，支持边缘脱机验证。（来源：docs/results/architect-next-five-horizons-2026-07-11.out.arch.md）
- **API 密钥格式与安全存储**：API 密钥携带可识别前缀（`apk_live_`/`apk_test_` 区分环境）并以 SHA-256 哈希而非 bcrypt 存储，因该鉴权路径无需慢哈希。（来源：docs/results/tech-lead-analysis-expansion-next-wave.out.arch.md）


---
## 管理与多租户

### 已实现功能

- **管理面 gRPC/REST API 全家桶**：clients/users/tenants/permissions/releases/snapshots/tokens 等管理服务通过 gRPC :8081 与 REST /api/v1/admin/* 暴露，由 admin:read/admin:write scope 门控，并有可运行的 gRPC 管理客户端示例。（来源：docs/deployment.md, docs/README.md）
- **Admin Console SPA（客户端/用户/租户/域名 CRUD）**：手写的管理 SPA 支持客户端创建/编辑/删除/换密钥/审批、用户 CRUD、租户 CRUD 及专用 Suspend/Activate 操作、域名与品牌字段管理，无需构建步骤或 CDN 依赖。（来源：docs/deferred-backlog.md）
- **DCR 客户端注册审核工作流**：client_registration.default_active=false 使动态注册客户端进入 pending 状态，需管理员通过 ClientAdminService API 批准/拒绝后才能参与任意授权流程。（来源：docs/config-reference.md）
- **租户暂停检查缓存**：tenant.suspension_check.cache_ttl 缓存暂停状态查询（默认 30s TTL），并在管理员状态变更时失效。（来源：docs/config-reference.md）
- **多区域数据驻留强制执行**：region.* 配置在登录时做写入门控、在资源访问时做读取门控，基于服务区域与允许区域列表实施驻留策略与发放门控。（来源：docs/config-reference.md, docs/migration-roadmap.md, docs/requirements/Senior-Architect-Expansion-Directions-2026-07-11.out.md）
- **Break-glass 应急管理会话**：break_glass.enabled 提供 propose/approve/list/delete 生命周期，配有到期清理器，在 TTL 到期时销毁授权衍生的会话。（来源：docs/config-reference.md, docs/architecture/architect-analysis-expansion-v9-five-directions.md）
- **管理员写操作配额**：admin_write_quota.enabled 对租户或管理员在管理 API 上强制固定窗口的写操作预算，独立于令牌桶限流器，超限返回 429 并带 Retry-After。（来源：docs/config-reference.md, docs/error-codes.md）
- **双人/通用管理变更审批工作流**：admin_change_approval.enabled 将 break-glass 的 propose/approve 模式推广为任意管理变更类型，要求第二人审批并拒绝自我批准（当前缺少变更前后状态快照）。（来源：docs/config-reference.md, docs/error-codes.md, docs/results/global-architecture-scan-four-production-blindspots-2026-07-11.out.arch.md）
- **破坏性操作确认防护**：admin_destructive_actions.enabled 对配置的 (method, path前缀) 管理请求要求携带 X-Confirm: true 头，否则返回 409。（来源：docs/config-reference.md, docs/error-codes.md）
- **管理员 IP 白名单/地理位置限制**：admin_ip_allowlist.enabled 在鉴权前基于 CIDR 和/或 ISO 国家代码限制管理 API 访问。（来源：docs/config-reference.md, docs/error-codes.md）
- **Admin SQLite 在线备份端点**：POST /api/v1/admin/backup 执行在线 VACUUM INTO 备份，支持可配置输出目录与保留数量。（来源：docs/dr-framework.md）
- **快照校验/恢复 CLI**：sso-ctl snapshot verify/restore-from 及 --bootstrap-restore-from 支持离线校验 DR 快照并通过首次启动或管理 RPC 恢复控制面状态。（来源：docs/dr-framework.md）
- **委托组织管理自助面**：/me/organizations/{tenant_id}/* 让租户组织管理员自助管理本组织，且将租户不存在/非成员/非管理员统一收敛为反枚举安全的 forbidden 响应。（来源：docs/error-codes.md）
- **末位组织管理员保护**：移除或降级组织最后一名管理员（含自我移除）会被拒绝并返回 last_org_admin。（来源：docs/error-codes.md）
- **租户资源配额（会话/客户端注册数）**：对并发会话数、DCR 注册客户端数等资源设置租户级上限，超限返回治理性的 quota_exceeded 而非凭证预言机。（来源：docs/error-codes.md）
- **自助组织邀请接受**：POST /me/invitations/accept 允许用户接受组织管理员签发的邀请令牌加入租户。（来源：docs/error-codes.md）
- **网络策略管理 API**：/api/v1/netpolicy/* 暴露基于可配置存储的命名网络策略 CRUD。（来源：docs/error-codes.md）
- **ReBAC 关系型授权引擎**：可选启用的 Zanzibar 风格 ReBAC 引擎，经 /api/v1/admin/rebac/check 支持运维驱动的关系型访问检查。（来源：docs/error-codes.md）
- **可插拔 WASM 授权引擎与调试端点**：可选的 WebAssembly 托管授权决策引擎，经 /api/v1/admin/wasmauthz/check 暴露（需 admin:read），任何客户机陷阱或超时均 fail-closed。（来源：docs/error-codes.md, docs/wasmauthz.md）
- **管理员用户账户 CRUD**：当所接入的 UserProvider 支持相应扩展接口时，提供创建/查询/更新/删除用户账户的管理端点。（来源：docs/error-codes.md）
- **用户生命周期状态机**：受治理的账户生命周期（invited→active→{suspended,inactive}→archived→purged），含合法迁移表、管理员驱动的状态变更及可选的休眠账户自动清退扫描。（来源：docs/error-codes.md）
- **SCIM 2.0 入站配置**：/api/v1/scim/v2/ 实现 SCIM 2.0 入站用户/组配置。（来源：docs/feature-matrix.md）
- **SCIM 2.0 出站推送配置**：可选启用向下游 SCIM 应用 /Users、/Groups 端点推送用户/组变更。（来源：docs/feature-matrix.md）
- **租户暂停/删除联动批量撤销**：暂停或删除租户会通过 RefreshTokenClientPurger 主动撤销该租户跨客户端的刷新令牌，尽力而为并记录审计。（来源：docs/ROADMAP.md, docs/migration-roadmap.md）
- **授权策略包管理**：管理用于权限/授权决策评估的版本化策略包。（来源：docs/migration-roadmap.md）
- **按租户签名密钥隔离**：WithTenantTokenIssuer 为每个租户提供独立签发器，覆盖 access/id_token/JARM/userinfo/WebAuthn 签发，未注册租户 fail-closed。（来源：docs/ROADMAP.md）
- **多租户数据隔离**：既有的按租户数据隔离与 scope 模型为跨租户管理特性提供隔离保证基础。（来源：docs/architecture/architect-analysis-expansion-v10-directions.md）
- **Helpdesk 管理员操作处理器**：已实现（部分）支持密码重置、MFA 恢复、强制状态变更、清除暴力破解锁定、列出用户同意等操作，目前仅受粗粒度 admin:write scope 约束。（来源：docs/architecture-analysis-peer-review-response.md, docs/tech-lead-analysis-cross-verified-five-directions.md, docs/results/tech-lead-analysis-expansion-next-wave.out.arch.md）
- **管理员同意（consent）查询与撤销端点**：GET/DELETE /api/v1/admin/users/:id/consents 支持查看和撤销用户的授权同意，撤销时触发 audit.EventAdminConsentRevoked。（来源：docs/error-codes.md, docs/results/expansion-ciam-identity-horizon.out.arch.md）
- **批量令牌吊销 API**：HandleBulkRevoke（interfaces/admin/token_portfolio.go）支持按 subject/client 过滤的批量令牌吊销，含确认阈值（软上限 100/硬上限 10000）与审计事件，以及按用户查询令牌的接口。（来源：docs/requirements/architect-fresh-scan-five-directions-2026-07-11.out.md, docs/requirements/architect-gap-analysis-2026-07-11.out.md, docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.out.arch.md）
- **RBAC/ReBAC/条件访问授权引擎组合能力**：permissions.Provider（RBAC）、rebac.Check（关系型访问控制）、conditionalaccess.Evaluate 引擎均已实现，可组合成更高层授权服务。（来源：docs/tech-lead-analysis-post-protocol-layer.md）
- **Admin API 区域字段 CRUD**：admin_tenants.go 已提供租户 HomeRegion/AllowedRegions 的完整 gRPC CRUD 能力。（来源：docs/requirements/Senior-Architect-Expansion-Directions-2026-07-11.out.md）
- **角色与权限管理基础设施**：domains/permissions 已实现完整 Role 类型、Provider CRUD（AddRole/UpdateRole/RemoveRole/ListAllRoles）、角色分配与查询、gRPC PermissionAdminService、SQLite 后端、静态+动态职责分离（SoD）及管理角色审计事件。（来源：docs/requirements/senior-architect-expansion-v3-identity-system-quality.out.md, docs/results/senior-architect-expansion-v3-identity-system-quality.out.arch.md）
- **管理员用户管理 Handler 集合**：interfaces/admin/ 已承载 consent 管理、MFA、密码重置、邮箱变更、账户锁清除、设备密钥、刷新令牌吊销等多个用户管理 handler。（来源：docs/results/example-user-api.out.arch.md）
- **租户品牌化字段存储（Tenant.Branding）**：Tenant 实体已存储品牌化配置数据，但目前仅通过 /branding JSON API 暴露，尚无渲染消费者。（来源：docs/results/senior-architect-fresh-scan-2026-07-11.out.arch.md, docs/results/expansion-ciam-identity-horizon.out.arch.md）
- **域名所有权验证**：基于 DNS TXT 挑战的域名所有权验证 SPI，含令牌生成、可配置超时及 memory+SQLite 双后端，防止域名劫持。（来源：docs/results/global-architecture-scan-four-production-blindspots-2026-07-11.out.arch.md, docs/requirements/global-architecture-scan-four-production-blindspots-2026-07-11.out.md）
- **管理操作治理审批工作流（admingovernance）**：platform/lifecycle/admingovernance/ 已实现管理员操作的 Propose/Approve/Apply 审批生命周期、配额与破坏性操作防护。（来源：docs/results/architect-expansion-analysis.out.arch.md）
- **区域解析器与驻留策略存储**：region.Resolver、PolicyStore 与 cluster.Bus 已提供生产可用的地理区域解析与跨副本策略传播能力。（来源：docs/results/tech-lead-analysis-expansion-next-wave.out.arch.md）

### 提议中/未来方向功能

- **策略管理 API（PolicyStore）**：提议 PolicyStore SPI（List/Get/Create/Update/DeletePolicy），支持租户范围授权策略的 CRUD，经管理 API 暴露。（来源：docs/agent-os/architect-analysis/expansion-post-protocol-layer-architecture-review.md）
- **租户隔离分析查询强制执行**：要求分析引擎对每次查询强制施加租户过滤，防止跨租户数据泄漏。（来源：docs/agent-os/architect-analysis/expansion-post-protocol-layer-architecture-review.md）
- **租户健康评分与仪表盘/API**：基于登录成功率、MFA 覆盖率、错误率、用量趋势、近期事件等构建加权租户健康评分，配套趋势/异常检测、聚合指标与只读管理端点。（来源：docs/agent-os/architect-analysis/expansion-post-protocol-layer-architecture-review.md, docs/tech-lead-analysis-post-protocol-layer.md, docs/requirements/expansion-novel-v4-privacy-dx-operations.out.md, docs/results/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.arch.md）
- **嵌入式租户自助分析仪表盘 SPA**：提议内嵌图表化 SPA 仪表盘，让租户管理员直接查看用量模式与健康评分。（来源：docs/agent-os/architect-analysis/expansion-post-protocol-layer-architecture-review.md, docs/requirements/Senior-Architect-Expansion-Directions-2026-07-11.out.md）
- **定时分析报告生成与投递**：提议调度器定期从分析引擎生成 PDF 报告并通过既有邮件发送器投递。（来源：docs/agent-os/architect-analysis/expansion-post-protocol-layer-architecture-review.md）
- **Admin API 乐观并发控制（ETag/If-Match）**：为 ClientStore/TenantStore/UserStore 等新增版本化 Update（如 UpdateWithVersion/WithExpectedVersion）及 ErrVersionConflict 语义，配合 ETag/If-Match HTTP 语义防止并发覆盖，未提供版本号时保持现有 LWW 行为。（来源：docs/architect-analysis-system-resilience-spa-ssrf-concurrency-5-gaps.md, docs/tech-lead-plan-system-resilience-5-gaps.md, docs/requirements/architect-system-resilience-spa-ssrf-concurrency-5-gaps.out.md, docs/results/expansion-novel-v3-identity-system-quality.out.arch.md, docs/results/global-architecture-scan-four-production-blindspots-2026-07-11.out.arch.md）
- **内置管理员角色模型与角色分配**：预定义角色（org_admin/user_admin/audit_viewer/helpdesk/api_admin）以 scope-wildcard 组合表达，配套角色分配 CRUD API、实时跨副本传播、租户作用域权限模板、自贬保护及资源级细粒度角色存储（含无配置时的向后兼容降级）。（来源：docs/architecture-analysis-peer-review-response.md, docs/tech-lead-analysis-cross-verified-five-directions.md, docs/results/tech-lead-analysis-expansion-next-wave.out.arch.md, docs/requirements/senior-architect-expansion-v3-identity-system-quality.out.md, docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.review.out.arch.md）
- **跨租户全局管理与全局搜索**：新增 admin:read.global/admin:write.global scope，提供跨租户搜索索引、全局审计查询、Fleet View 面板及全局健康聚合告警，服务平台级/MSP 管理员。（来源：docs/architecture/architect-analysis-expansion-v10-directions.md, docs/tech-lead-expansion-analysis.md, docs/requirements/expansion-directions-v10-analysis.out.md）
- **Admin Console 批量管理能力**：为管理 SPA 增加用户/客户端/租户的批量操作（CSV 批量导入/预览/列映射、批量删除、CSV 导出）、跨资源搜索及配套的异步 BatchJobStore 作业跟踪。（来源：docs/feature-spec-architecture-analysis-five-verified-directions.md, docs/requirements/architect-fresh-scan-2026-07-11.out.md, docs/results/architect-fresh-scan-2026-07-11.out.arch.md）
- **自定义租户域名验证增强与自动 TLS（ACME）**：DomainVerifier/DNSProvider SPI（DNS TXT/CNAME/DNS-01）验证域名所有权，配合 ACME/Let's Encrypt 自动证书签发续期与证书生命周期状态机，实现自定义登录域名。（来源：docs/feature-spec-architecture-synthesis-five-directions.md, docs/requirements/architect-expansion-2026-07-11.out.md, docs/results/senior-architect-expansion-2026-07-11.out.arch.md, docs/requirements/senior-architect-global-scan-5-uncovered-expansion-directions.out.md, docs/results/global-architecture-scan-four-production-blindspots-2026-07-11.out.arch.md）
- **租户品牌化 SPA 渲染**：基于 Host header 的域名/租户解析中间件与路由，向 Hosted Login/Admin Console/User Portal 注入租户品牌 CSS 变量与 Logo，并将品牌数据抽取为独立多主题实体。（来源：docs/results/architect-expansion-2026-07-11.out.arch.md, docs/requirements/global-architecture-scan-four-production-blindspots-2026-07-11.out.md, docs/results/senior-architect-global-scan-5-uncovered-expansion-directions.out.arch.md）
- **租户级通知模板定制**：新增 TemplateStore 支持租户覆盖内嵌的邮件/短信通知模板，并与 Domain.Branding 数据结合渲染。（来源：docs/feature-spec-architecture-synthesis-five-directions.md, docs/requirements/expansion-production-hardening-analysis.out.md, docs/results/expansion-production-hardening-analysis.out.arch.md）
- **MCP 只读管理工具集**：check_permission/list_permissions/list_roles/get_menus 等基于既有 Authorizer 的权限查询 MCP 工具。（来源：docs/superpowers/plans/2026-06-29-sso-mcp.md）
- **MCP 写/管理工具（Phase 2）**：规划中的 create_user/revoke_token/assign_role 等写能力 MCP 工具，映射到 admin:write REST 面并要求管理凭证。（来源：docs/superpowers/plans/2026-06-29-sso-mcp.md, docs/superpowers/specs/2026-06-29-sso-mcp-design.md）
- **Admin 列表分页/过滤/排序**：将 page_token/page_size/filter 字段真正贯通至各 Store 实现（含可选 ListPage 扩展），解决大规模部署下列表 OOM 问题。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md, docs/superpowers/plans/2026-07-02-wave2-tranche1.md）
- **租户配额强制执行落地**：将当前处于死代码状态的 checkQuotaBeforeCreate 接入客户端创建/用户创建/令牌签发/DCR 等各类守卫点，并引入独立 QuotaProfile 实体、多后端存储与按租户限流叠加层及管理配额 API。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md, docs/superpowers/plans/2026-07-02-wave2-tranche1.md, docs/requirements/expansion-five-uncovered-gaps.out.md, docs/results/expansion-five-uncovered-gaps.out.arch.md）
- **委托组织管理深化**：真正消费当前仅存储未被读取的 TenantRoleAdmin 角色，提供组织成员名单/邀请管理、管理员自助委派及 B2B 门户 UI，辅以 scope 门控中间件而非重构 handler。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md, docs/requirements/expansion-directions-v8-analysis.out.md, docs/results/expansion-directions-v8-analysis.out.arch.md, docs/results/expansion-platform-evolvability-meta-governance.out.arch.md）
- **租户范围导出能力**：提议面向单租户下线/迁移的数据导出能力，以及为 Tenant-as-Code 协调器提供的批量导出端点。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md, docs/requirements/senior-architect-expansion-v2-identity-gaps.out.md）
- **四眼原则（Dual-Control）审批中间件钩子**：作为 AdminMiddleware 前置检查钩子实现双重控制审批，供未来 break-glass/ABAC 特性复用。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **RBAC 静态职责分离约束**：为权限模型增加静态 SoD 约束，如禁止同一主体同时持有互斥角色。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **Admin 写幂等性与 trace_id**：为管理写端点增加幂等键支持，并通过既有但未使用的 ErrorBodyWithTrace 在错误响应体中带上 trace_id。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **Admin SSE 事件流**：为管理控制台提供 Server-Sent Events 实时事件流。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **批量数据导入与惰性密码哈希迁移**：批量导入工具与访问时懒迁移旧哈希格式的密码迁移路径。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **租户级功能标志**：新增 featureflag 领域包与 TenantFeatureStore，支持按租户覆盖全局功能开关（全局 OFF 为硬上限不可被租户覆盖为 ON）、三级解析与分层缓存，配套管理 API 与 Admin Console UI。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md, docs/requirements/architect-final-five-2026-07-11.out.md, docs/results/architect-final-five-2026-07-11.out.arch.md, docs/requirements/global-architecture-scan-five-uncovered-high-value-directions-2026-07-11.out.md, docs/results/Senior-Architect-Expansion-Directions-2026-07-11.out.arch.md）
- **Admin Console 全 CRUD UI + PKCE 登录**：构建完整 CRUD 管理控制台 UI，自身通过 Authorization Code + PKCE 登录。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **租户邀请批量撤销**：新增管理端点，按租户+邮箱批量撤销所有待处理组织邀请，避免误发邀请在 TTL 内持续作为有效凭证。（来源：docs/superpowers/plans/2026-07-02-wave1-quick-wins.md）
- **声明式 Tenant-as-Code（TenantSpec YAML）**：版本化（apiVersion）YAML schema 描述租户配置（slug/域名/品牌/连接/允许区域），配合 diff 引擎、reconciler（sso-ctl apply -f/--dry-run）、密钥引用管理及可选自动协调（自愈）模式，支撑 GitOps 式租户管理。（来源：docs/tech-lead-analysis/analysis.md, docs/requirements/senior-architect-expansion-v2-identity-gaps.out.md, docs/results/senior-architect-expansion-v2-identity-gaps.out.arch.md）
- **Config 元治理工具集**：包括配置字段扫描器与文档覆盖率门禁、启动校验增强（互斥项/依赖/值域检查）、YAML 模板生成器、破坏性变更检测器及字段弃用工作流。（来源：docs/tech-lead-analysis-meta-governance-v2.md）
- **Admin SPA 用户授权（Consent）管理面板**：用户详情页展示并允许撤销用户的 OAuth 授权同意。（来源：docs/tech-lead-analysis-peer-review-corrections.md）
- **声明式策略 DSL + CRUD + 模拟引擎**：YAML 策略 DSL 编译为可评估授权规则，配套 CRUD 管理、dry-run 模拟与管理 UI 编辑。（来源：docs/tech-lead-analysis-post-protocol-layer.md）
- **Session Hub 管理仪表盘端点**：暴露聚合活跃会话统计（分协议/租户、平均信任分）及完整的单会话链路树，供运维可视化。（来源：docs/tech-lead-analysis/analysis.md）
- **会话批量查询与批量终止 API**：扩展 SessionManager 增加 ListByFilter（按租户/客户端/用户/IP/最近活跃时间过滤）与 LastActiveAt/ClientIP 字段，新增 DELETE /api/v1/admin/sessions 批量终止端点（含确认门与后台批处理框架）及 SLO 框架。（来源：docs/tech-lead/tech-lead-analysis-five-true-new-gaps-2026-07-12.md, docs/requirements/architect-global-scan-v2-true-new-gaps-2026-07-12.out.md, docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.out.arch.md, docs/requirements/senior-architect-scan-v2-true-gaps-2026-07-11.out.md）
- **跨协议统一会话查询（管理端+用户端）**：新增 GET /api/v1/admin/sessions/unified 及 /me/sessions?include_linked=true，按 GlobalSID 分组列出并检视用户跨 OIDC/SAML 关联会话。（来源：docs/tech-lead/tech-lead-analysis-five-true-new-gaps-2026-07-12.md, docs/results/architect-fresh-scan-five-directions-2026-07-11.out.arch.md）
- **密码生命周期管理 API**：新增管理端点查看用户密码状态、强制密码过期、清除强制修改标记，以及跨租户/用户集批量密码过期。（来源：docs/tech-lead/tech-lead-analysis-five-true-new-gaps-2026-07-12.md）
- **组织层级管理**：为扁平 Tenant 模型新增 ParentOrgID/组织树、祖先/后代查询与子树移动、策略继承与覆盖引擎、Provisioning→Active→Frozen→Archived 生命周期状态机、组织并购合并工作流及跨组织 SCIM 过滤。（来源：docs/requirements/architect-expansion-analysis.out.md, docs/results/architect-expansion-analysis.out.arch.md, docs/requirements/architect-gap-analysis-2026-07-11.out.md）
- **跨集群条件访问策略冲突检测**：基于既有 SSOConfigDrift 基础设施构建全局条件访问策略冲突检测，识别跨集群策略不一致。（来源：docs/requirements/architect-expansion-novel-horizons-2026-07-11.out.md）
- **管理令牌与用户会话统一生命周期可见性**：打通 AdminTokenStore 与 SessionManager，使管理员令牌纳入 /me/sessions 可见性，撤销时联动会话销毁并触发 CAEP 事件。（来源：docs/requirements/architect-fresh-code-scan-2026-07-11.out.md, docs/results/architect-fresh-code-scan-2026-07-11.out.arch.md）
- **智能体自助与管理端 UI/API**：补齐 /me/agents 用户自助面板、/admin/agents 管理员面板及 Agent 创建/管理/强制吊销 REST API。（来源：docs/requirements/architect-frontier-identity-paradigms-platform-resilience-2026-07-11.out.md, docs/results/expansion-novel-2026-07-11.out.arch.md）
- **访客协作用户生命周期**：构建 B2B 访客协作邀请→接受→预配→审计→自动撤销闭环，需明确访客身份归属宿主租户或原生租户。（来源：docs/requirements/architect-gap-analysis-2026-07-11.out.md）
- **act 委托链管理面可见性**：为 Token Exchange 产生的 act 委托链提供管理后台可见性面板，便于审查委派关系。（来源：docs/requirements/architect-gap-analysis-2026-07-11.out.md）
- **企业目录同步**：企业目录同步连接器（如 Azure AD/Entra ID），从外部目录导入并持续同步用户/组，解决企业迁移的主要障碍。（来源：docs/requirements/architect-global-analysis-2026-07-11.out.md）
- **Org Admin Console / B2B 委托组织管理门户**：面向租户管理员的 B2B 自助组织管理控制台，管理成员/角色/设置，以 tenant:* scope 而非 admin:* scope 保护。（来源：docs/requirements/architect-global-analysis-2026-07-11.out.md, docs/requirements/expansion-directions-v8-analysis.out.md）
- **令牌聚合管理面**：新增 domains/tokenportfolio/ 及统计/过期日历预测/按条件批量吊销/组合健康评分端点。（来源：docs/requirements/architect-gap-analysis-2026-07-11.out.md, docs/results/architect-gap-analysis-2026-07-11.out.arch.md）
- **Admin 配置快照与回滚**：为管理面资源配置提供快照与回滚到已知良好版本的能力。（来源：docs/requirements/architect-system-resilience-spa-ssrf-concurrency-5-gaps.out.md）
- **Admin API 试运行变更预览（dry-run）**：新增 WithDryRun() 更新选项，返回变更差异预览而不持久化。（来源：docs/requirements/architect-system-resilience-spa-ssrf-concurrency-5-gaps.out.md）
- **租户级导出隔离保证**：确保事件/数据导出按租户隔离，防止一个租户的导出数据泄漏到另一租户的处理管道。（来源：docs/requirements/expansion-ciam-identity-horizon.out.md）
- **声明式 GitOps 配置流水线**：管理端点支持将运行配置导出为 Git 就绪 YAML、三方 diff/dry-run 对比目标状态并声明式应用；配套 Git 仓库同步控制器（轮询/webhook）、age/SOPS 密钥加密集成及回滚触发的令牌/会话自动撤销。（来源：docs/tech-lead/expansion-analysis-2026-07-11.md）
- **会话配额管理 Admin API**：新增管理面 API 用于查询和设置租户/用户级会话配额策略。（来源：docs/results/architect-expansion-2026-07-11.out.arch.md）
- **Grant 高风险 scope 审批工作流**：客户端请求高风险 scope 时创建 GrantApproval 挂起请求（返回 pending_approval），需管理员批准/拒绝后颁发令牌；并提议共享 Approver SPI 及从 admingovernance 提取通用 Propose/Approve/Apply SPI 供复用。（来源：docs/results/architect-expansion-5-directions.out.arch.md, docs/results/architect-expansion-analysis.out.arch.md）
- **用户管理内部重构 SPI 集合**：新增 internal/adminuser/ 编排层（UserCRUDService）及可选扩展接口 UserLookupProvider（按用户名/邮箱查询）、UserPaginationProvider（分页）、UsernameCheckProvider（唯一性预检）、UserProviderTx（双存储事务一致性）、UserStatusProvider（统一状态查询）与 SoftDelete（软删除）。（来源：docs/results/example-user-api.out.arch.md）
- **多租户用户隔离**：为用户 List/Create 增加按 TenantID 过滤的租户级隔离能力。（来源：docs/results/example-user-api.out.arch.md）
- **统一搜索与运营智能（Admin 全局搜索）**：新增基于 SQLite FTS5 的 SearchIndex SPI，支持管理员跨用户/客户端/租户全局搜索。（来源：docs/results/expansion-directions-analysis.out.arch.md）
- **Token 血缘查询与级联吊销 API**：GET /admin/tokens/{jti}/lineage 可视化令牌签发链（auth_code→access_token→refresh），并提供可选、默认关闭的链式级联吊销能力。（来源：docs/results/expansion-directions-v11-analysis.out.arch.md）
- **Admin Console SPA 面板深化**：深化现有功能稀疏的管理控制台前端，充分暴露既有 admin gRPC/REST API 能力。（来源：docs/results/expansion-directions-v7-analysis.out.arch.md）
- **身份证明审核 Admin API**：新增管理端点用于人工审核第三方 KYC 提交的身份证明记录（如 IdentityProofStore.ListPendingReviews）。（来源：docs/results/expansion-directions-v7-analysis.out.arch.md）
- **Admin API Key 管理端点**：管理端点列出所有 API Key、代表用户创建 Key、吊销任意 API Key。（来源：docs/results/expansion-next-wave-analysis.out.arch.md）
- **区域策略路由中间件与管理 API**：组合 region.Resolver/PolicyStore/cluster.Bus 构建鉴权前区域访问策略中间件，配套 CRUD 管理端点及可配置的区域解析失败模式（默认 fail-closed）。（来源：docs/results/expansion-next-wave-analysis.out.arch.md）
- **Ext-Authz Admin API**：GET/POST 端点用于观测和更新 mesh 授权策略包。（来源：docs/results/expansion-next-wave-analysis.out.arch.md）
- **Admin Agent 管理 API**：/admin/agents 端点让管理员列出并强制吊销任意租户的 AI 代理。（来源：docs/results/expansion-novel-2026-07-11.out.arch.md）
- **PAM（特权访问管理）Admin API**：管理端点列出、批准并查看 PAM 提权请求历史。（来源：docs/results/expansion-novel-v2-identity-2026-07-11.out.arch.md）
- **Identity Graph（身份关系图谱）**：只读、定期刷新的物化视图 SPI，提供用户访问路径、策略影响、未使用权限及身份 DAG 查询，聚合自现有用户/权限/会话/审计数据。（来源：docs/results/expansion-platform-evolvability-meta-governance.out.arch.md）
- **Admin 令牌水印解码调试端点**：POST /api/v1/admin/tokens/decode-watermark 用于事件/泄漏调查中解码嵌入的令牌水印。（来源：docs/results/global-architecture-scan-five-uncovered-high-value-directions-2026-07-11.out.arch.md）
- **租户开通/预配工作流引擎**：以状态机形式实现租户创建→DNS验证→密钥初始化→品牌配置→健康检查→激活的预配流程，含欢迎邮件、激活清单、种子 OAuth 客户端及安全基线模板向导，支持故障处理与幂等重入。（来源：docs/requirements/Senior-Architect-Expansion-Directions-2026-07-11.out.md, docs/results/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.arch.md, docs/results/Senior-Architect-Expansion-Directions-2026-07-11.out.arch.md）
- **客户 SLA 分级管理**：定义并强制执行按租户方案区分的差异化 SLA 等级。（来源：docs/requirements/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.md）
- **跨租户商业智能报表**：聚合跨租户用量与业务指标形成面向平台运营方的 BI 报表。（来源：docs/requirements/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.md）
- **受信设备管理 Admin Console UI**：为管理员提供查看/管理用户受信设备列表的管理控制台界面（当前仅有用户侧 /me/devices）。（来源：docs/requirements/Senior-Architect-Expansion-Directions-2026-07-11.out.md）
- **机器身份 Admin API**：为 MachineIdentityStore 新增管理 API，支持机器身份的列出、查看与吊销。（来源：docs/results/senior-architect-expansion-v7-true-gaps-2026-07-11.out.arch.md）
- **DCR 元数据策略框架**：ClientMetadataPolicy 框架对动态客户端注册元数据实施字段级约束，独立于既有 OpenID Federation metadata_policy。（来源：docs/requirements/global-scan-expansion-directions.out.md）
- **自动客户端休眠/自动禁用**：自动标记或禁用长期未使用（休眠）的 OAuth 客户端。（来源：docs/requirements/global-scan-expansion-directions.out.md）
- **software_statement 签名验证与信任注册表**：解析并密码学验证 DCR 中的 software_statement 字段（目前既不解析也不存储），配套 SoftwareProvider 信任注册表用于校验签发者。（来源：docs/requirements/global-scan-expansion-directions.out.md）

---
## 合规与审计

### 已实现功能
- **安全不变量自动化检查套件**：`make check-invariants` 等十项自动化安全不变量检查覆盖 oracle-leak 抗性、反枚举行为与凭据端点缓存头要求，作为回归防护跑在 harness 中（来源：docs/agent-os/TODO.md, docs/developer-guide.md）
- **审计事件 SetMeta 强制规范**：审计事件元数据只能通过 `SetMeta(e,k,v)` 追加写入，禁止直接 `e.Metadata = map{...}` 覆盖，防止无界基数与既有增强信息丢失（来源：docs/architecture/architect-analysis-expansion-v10-directions.md, docs/observability.md, docs/review-checklist.md, docs/skills/code-review.md）
- **异常检测审计记录贯通**：所有异常/威胁检测结果统一通过 `audit.Recorder` 记录，作为检测结果唯一的可观测性契约（来源：docs/architecture/analysis-detection-response-gap.md）
- **有界维度审计元数据**：审计事件元数据限制在有界维度（outcome/type/client/provider），控制指标与日志基数（来源：docs/observability.md）
- **分层审计 Sink 管道与严重度分级/有界队列背压**：组合 Async→Multi→Retry→leaf 管道可靠投递审计事件；已有 Critical/High/Medium/Low/Info 严重度分级体系投影到 CEF/OCSF/Syslog；异步 Sink 采用有界队列 + drop-newest 背压策略，并暴露丢弃/队列深度指标（来源：docs/observability.md, docs/requirements/global-scan-five-directions.out.md, docs/results/global-scan-five-directions.out.arch.md）
- **防篡改哈希链审计日志**：审计事件构成 PrevHash/Hash 哈希链，可通过 `sso-ctl audit-verify` CLI 校验篡改；SQLite 审计 Sink 提供哈希链持久化、检索、保留调度与 PII 脱敏（来源：docs/observability.md, docs/ROADMAP.md, docs/results/expansion-novel-v2-identity-2026-07-11.out.arch.md）
- **审计日志/快照保留与修剪调度**：`audit.retention.*` 与 `snapshot.retention.*` 配置周期性修剪审计事件与数据/配置快照（来源：docs/config-reference.md）
- **HMAC 签名审计 Webhook 与多订阅分发/自定义外部 Sink**：`audit.webhook.signing_secret` 为每次 Webhook POST 添加 `X-Signature` HMAC-SHA256；`audit.webhook.subscriptions[]` 支持多个带独立事件过滤与重试/签名配置的命名端点；也可实现自定义 `audit.Sink` 发往外部防篡改存储（来源：docs/config-reference.md, docs/SECURITY.md）
- **运行时配置变更审计追踪（Config Audit）**：`config_audit.*` 在启动时捕获脱敏后的已应用配置快照，暴露 running/applied/diff/history 端点及客户端/租户/策略变更捕获钩子；diff 引擎产出 RFC 6902 JSON Patch，支持漂移检测与配置摘要（来源：docs/config-reference.md, docs/error-codes.md, docs/results/global-architecture-scan-four-production-blindspots-2026-07-11.out.arch.md）
- **SIEM 多格式审计导出（CEF/OCSF/Syslog/Kafka）**：`audit.cef.*`/`audit.ocsf.*`/`audit.syslog.*` 分别输出 ArcSight 兼容 CEF、OCSF NDJSON、RFC 5424 syslog；`audit.kafka.enabled` 以 JSON/CEF/OCSF/syslog 编码发布审计事件到 Kafka（来源：docs/config-reference.md）
- **SSF/CAEP 共享信号收发与 MQTT 投递通道**：`caep.*` 配置 SET 推送超时/重试退避/TTL；MQTT `TopicPublisher` 提供 CAEP/SSF Security Event Token 的 MQTT 投递通道（来源：docs/config-reference.md, docs/deferred-backlog.md）
- **快照密钥脱敏**：`snapshot.redact_secrets` 在导出的快照副本上清空客户端密钥字段（来源：docs/config-reference.md）
- **审计 Facets 查询 API**：可选 `FacetQuerier` 能力通过 `GET /api/v1/audit/facets` 暴露，后端不支持时返回 501，并有一致性测试覆盖（来源：docs/observability.md, docs/requirements/expansion-platform-evolvability-meta-governance.out.md）
- **特性门禁禁用审计事件**：运营方显式禁用某些特性门禁时，启动阶段一次性记录审计事件说明禁用了哪些门禁（来源：docs/observability.md）
- **合规管理 Admin API 集合**：`/api/v1/admin/compliance/{soc2-evidence, data-map, consents}` 分别提供聚合角色分配/管理变更/令牌会话吊销的 SOC2 证据包生成（含 `protocols/compliance/soc2.go` 报告引擎）、GDPR Art.30 静态处理活动记录（Data Map）、系统级有效同意授权列表（来源：docs/error-codes.md, docs/ROADMAP.md, docs/results/expansion-ciam-identity-horizon.out.arch.md）
- **数据保留清理框架与按需清理触发 API**：`WithDataRetentionSweep`/`RunDataRetentionSweep` 及 `protocols/compliance/retention.go` 策略引擎实现会话 TTL/休眠账户清理，并通过 `POST /api/v1/admin/compliance/retention-sweep`（含 dry-run 选项）按需触发（来源：docs/error-codes.md, docs/requirements/expansion-ciam-identity-horizon.out.md, docs/results/expansion-ciam-identity-horizon.out.arch.md）
- **FAPI 2.0/1.0 Advanced 金融级 API 安全 Profile**：可选启用的 Inspection/Enforce 模式覆盖登录/令牌/发现端点，含 mTLS 客户端认证与 intent-to-apply 模式，并有按规则/模式标记的违规指标（来源：docs/feature-matrix.md, docs/sso/oidc-conformance.md, docs/observability.md）
- **多区域数据驻留基础设施与写入强制执行**：`domains/region` 提供 Resolver/PolicyStore/ResidencyPolicy SPI 及治理错误哨兵；region-aware 中间件覆盖登录/userinfo/mesh/WebAuthn 端点；`server_tenant_residency.go` 的 `EnforceWrites` 依据 HomeRegion 路由/拒绝写操作（来源：docs/feature-matrix.md, docs/requirements/Senior-Architect-Expansion-Directions-2026-07-11.out.md, docs/results/global-scan-expansion-directions.out.arch.md, docs/results/Senior-Architect-Expansion-Directions-2026-07-11.out.arch.md）
- **地理位置感知司法辖区中间件**：`platform/geo/` 中间件解析请求地理位置，为辖区相关判断提供基础（来源：docs/results/expansion-novel-2026-07-11.out.arch.md）
- **SAST/SCA 安全扫描**：`make security-scan` 运行 govulncheck 与 gosec 捕获已知漏洞与静态安全问题（来源：docs/developer-guide.md）
- **依赖许可证合规报告与 CI 门禁**：`make licenses` 生成依赖许可证 CSV 报告，`make licenses-check` 作为 CI 门禁拒绝 GPL/AGPL/SSPL 依赖（来源：docs/developer-guide.md）
- **自助账户擦除与 GDPR 数据导出/擦除工作流**：`POST /me/account/erase` 要求 `confirm` 匹配自身 subject；compliance 包提供 Exporter（Art.15/20 导出，含 `HandleMyDataExport` 自助导出）与 Eraser（Art.17 跨存储删除：吊销令牌/销毁会话/删除用户）（来源：docs/error-codes.md, docs/migration-roadmap.md, docs/skills/hexagonal-extraction.md, docs/ROADMAP.md, docs/results/expansion-novel-2026-07-11.out.arch.md）
- **审计日志导出能力（查询导出+CLI+租户导出+多租户隔离）**：`audit.Query` 支持按既有过滤条件导出 JSON/CSV；`cmd/sso-ctl/auditexport` 提供命令行导出工具；`HandleAdminExportTenant` 提供管理员租户级审计导出；SQLite 审计 Sink 具备 `tenant_id` 列/索引及查询层过滤，实现多租户审计隔离（来源：docs/requirements/expansion-ciam-identity-horizon.out.md, docs/requirements/architect-scan-2026-07-11.out.md）
- **加急安全发布流程**：安全发布遵循热修复流程，可跳过完整变更日志更新以加快发布（来源：docs/RELEASE.md）
- **发布物 SBOM 生成（CycloneDX）**：`make sbom` 通过 `cyclonedx-gomod` 生成 CycloneDX SBOM，自动化发布流水线为每个 GitHub Release 生成并附加 SBOM（来源：docs/RELEASE.md, docs/SECURITY.md）
- **私密漏洞披露渠道与响应 SLA**：通过专用邮箱与已发布 PGP 公钥私下报告安全漏洞（而非公开 issue），明确报告内容模板；公开响应时间线承诺 24 小时确认、7 天初步分诊、严重问题 30 天修复、低/中危 90 天修复（来源：docs/security-policy.md）
- **Scope 级 OAuth 同意存储（ConsentStore SPI）**：`RecordGrant`/`HasGrant`/`ListGrants`/`ListGrantedClients`/`RevokeGrant`/`RevokeAllUserGrants` 等方法的 ConsentStore SPI，提供 memory/SQLite/Redis/Postgres 多后端实现，经 `WithConsentStore` 接入登录流程，记录并强制 OAuth scope 级用户同意（来源：docs/results/PEER_REVIEW_architect-expansion-novel-horizons-2026-07-11.out.arch.md, docs/results/expansion-novel-2026-07-11.out.arch.md）
- **跨发行方部分吊销审计追踪**：revoke-all 对任一发行方失败时记录审计事件，便于运营方核对部分吊销情况（来源：docs/ROADMAP.md）
- **管理员变更审批工作流**：`HandleAdminProposeChange`/`ApproveChange`/`RejectChange` 的 propose/approve/reject 流程，通过 `recordChangeEvent()` 记录审批审计事件（来源：docs/results/global-architecture-scan-four-production-blindspots-2026-07-11.out.arch.md）
- **管理审计事件目录**：覆盖平台管理操作的 50+ 预定义审计事件类型（来源：docs/results/global-architecture-scan-four-production-blindspots-2026-07-11.out.arch.md）
- **Agent 委派审计事件**：通过 `EventAgentDelegationTokenIssued` 与 `EventAgentSessionRevoked` 等审计事件记录 AI 智能体委派令牌的签发与吊销轨迹（来源：docs/requirements/expansion-novel-2026-07-11.out.md）

### 提议中/未来方向功能
- **统一授权决策审计追踪（Decision Logging）**：提议 `AuthorizationDecision` 结构（decision_id/matched_policies/reason/context）与 `DecisionLogger` SPI，以单一 decision_id 关联 RBAC/ReBAC/条件访问/WASM 等跨模型鉴权结果，弥补当前审计事件缺少 reason 字段与跨模型统一追踪的缺口（来源：docs/agent-os/architect-analysis/expansion-post-protocol-layer-architecture-review.md, docs/requirements/architect-scan-deep-gaps-2026-07-11.out.md, docs/results/expansion-post-protocol-layer-analysis.out.arch.md）
- **Token Exchange 单跳授权审计装饰器**：以装饰器包装 `tokenexchange.Policy.Allow`，使每一跳 token exchange 都产生审计事件，且不改动 Policy 接口本身（来源：docs/results/expansion-production-deployment-gaps.out.arch.md）
- **令牌全生命周期谱系追踪与溯源查询 API（Token Lineage/Provenance）**：新增 TokenEvent/TokenFamilyIndex/ActChainStore 等模型记录令牌 mint/use/refresh/exchange/revoke 事件与 act 委托链，提供 `GET /admin/tokens/{jti}/lineage` 等查询 API 重建完整 DAG，支持可选的有界深度级联吊销与环检测（来源：docs/architecture-analysis-peer-review-response.md, docs/tech-lead-analysis-five-directions.md, docs/results/architect-fresh-scan-5-directions.out.arch.md, docs/results/PEER_REVIEW_architect-expansion-novel-horizons-2026-07-11.out.arch.md, docs/requirements/architect-expansion-novel-5-directions-v6-code-scan.out.md）
- **令牌签发取证水印与取证查询工作台（Token Forensics）**：在签发的令牌中嵌入 SHA-256 指纹并写入审计事件，新增 `platform/forensics` 包与 `GET /admin/forensics/token?hash=` 查询端点重建令牌全生命周期，并作为同一令牌哈希被多 IP/User-Agent 使用的异常检测信号源（来源：docs/tech-lead-analysis-five-directions.md, docs/requirements/architect-final-five-2026-07-11.out.md, docs/results/architect-final-five-2026-07-11.out.arch.md, docs/results/architect-deep-code-scan-5-undiscovered-gaps.out.arch.md）
- **审计事件 jti/TokenID 字段补全**：修复 token 生命周期审计路径，使所有相关事件一致填充 jti/parent_jti/TokenID 字段，为令牌溯源与跨系统关联提供基础（来源：docs/results/architect-unique-gaps-scan-2026-07-11.out.arch.md, docs/results/expansion-platform-evolvability-meta-governance.out.arch.md, docs/results/architect-remaining-horizon-2026-07-11.out.arch.md）
- **吊销日志与会话/令牌取证查询 API**：新增 RevocationLogStore（memory+SQLite）记录每次令牌吊销的 actor/reason/timestamp 并提供查询/清理端点；新增只读 LineageStore 从既有 `audit.Store` 重建会话-令牌生命周期关联，提供 `GET /admin/forensics/sessions/{id}/lineage` 会话取证时间线查询（来源：docs/tech-lead/tech-lead-analysis-five-true-new-gaps-2026-07-12.md, docs/results/architect-fresh-scan-five-directions-2026-07-11.out.arch.md, docs/results/architect-remaining-horizon-2026-07-11.out.arch.md）
- **令牌交换链（Exchange Chain）垃圾回收与归档策略**：结合 TTL 过期与引用计数归档，复用现有合规保留清理调度器为 exchange-chain 记录提供 GC 策略（来源：docs/results/global-scan-expansion-directions.out.arch.md）
- **凭据轮换合规证明报告**：基于既有 `audit.Store` 基础设施生成证明凭据轮换符合策略要求的合规就绪证明报告（来源：docs/results/expansion-five-uncovered-gaps.out.arch.md）
- **结构化管理员变更日志 SPI（ChangeLogStore）**：新增独立于现有审计事件流的 ChangeLogStore SPI，记录结构化 (actor, action, resource_type, resource_id, before, after, approved_by) 变更条目，支持多后端（memory/SQLite/PostgreSQL）、写入前 PII 脱敏（client_secret/email/password_hash 等）及约 7 年保留目标，满足 SOC2/SOX/HIPAA/PCI-DSS 审计要求；recordChange 辅助函数以 fail-open 方式嵌入各 Admin handler 写路径（来源：docs/feature-spec-architecture-synthesis-five-directions.md, docs/tech-lead-analysis/implementation-plan-five-directions.md, docs/requirements/architect-expansion-2026-07-11.out.md, docs/results/architect-expansion-2026-07-11.out.arch.md, docs/results/PEER_REVIEW_architect-expansion-novel-horizons-2026-07-11.out.arch.md）
- **管理变更查询与追溯能力增强**：为 Tenant/Client/User/Policy 增加 Version 字段与历史版本查询；乐观锁冲突时记录期望/实际版本号；变更审批通过时刻捕获完整资源快照；提供跨租户审计事件查询与排名端点；通过通用 AuditWrapper 透明包装任意 Store 的 Put 操作自动生成变更记录；管理面（Admin API）变更审计规范对齐数据面 grant handler（来源：docs/tech-lead-plan-system-resilience-5-gaps.md, docs/requirements/global-architecture-scan-four-production-blindspots-2026-07-11.out.md, docs/results/global-architecture-scan-four-production-blindspots-2026-07-11.out.arch.md, docs/tech-lead-expansion-analysis.md, docs/results/senior-architect-expansion-2026-07-11.out.arch.md）
- **Admin Console 变更历史视图**：管理控制台资源详情页新增“变更历史”标签，展示可按时间/操作者/操作类型过滤的前后 diff（来源：docs/feature-spec-architecture-synthesis-five-directions.md, docs/results/architect-expansion-2026-07-11.out.arch.md）
- **动态客户端注册（DCR）审计事件补全**：为 RFC 7591/7592 的注册/更新/删除及管理员审批/拒绝操作补充 EventClientRegistered/Updated/Deleted/Approved/Rejected 等审计事件，消除当前 DCR 操作零审计与 Admin gRPC 路径审计不一致的缺口（来源：docs/ROADMAP.md, docs/requirements/expansion-strategic-gaps-2026-07-11.out.md, docs/results/architect-expansion-novel-5-directions-2026-07-11.out.arch.md, docs/results/expansion-strategic-gaps-2026-07-11.out.arch.md, docs/results/Senior-Architect-Expansion-Directions-2026-07-11.out.arch.md）
- **批量/组提交审计写入路径**：为 `audit.Sink` 接口新增 `RecordBatch` 组提交路径，避免高 QPS 下单次登录的多个事件逐条串行 INSERT 通过 SQLite 哈希链写入器（来源：docs/ROADMAP.md, docs/requirements/expansion-directions-analysis.out.md）
- **读侧区域数据驻留校验补齐**：将显式 ServingRegion 贯穿 `validateAnyToken` 及 userinfo/introspect/mesh ext_authz/token-exchange/admin/refresh 等约 6 个调用点，使读路径请求也依据数据驻留规则校验，而不仅是写路径（来源：docs/requirements/expansion-gaps-analysis-2026-07-11.out.md, docs/results/expansion-gaps-analysis-2026-07-11.out.arch.md）
- **多区域租户驻留跨副本强制执行与区域感知令牌签发**：基于 `region.Resolver`/`PolicyStore` 与 `cluster.Bus` 区域级广播（KindTenantResidency）跨副本路由/强制执行区域策略；将区域驻留检查抽取为纯函数供中间件与多区域存储包装器复用；为签发令牌打上 `issuer_region` 声明并在签发前校验；将登录/令牌签发/会话持久化通过区域化存储路由钉选到租户配置的驻留区域（来源：docs/tech-lead-analysis-expansion-next-wave.out.md, docs/results/global-scan-expansion-directions.out.arch.md, docs/results/senior-architect-expansion-2026-07-11.out.arch.md, docs/ROADMAP.md）
- **安全政策文档整合与规范化**：合并 `.github/SECURITY.md` 与 `docs/SECURITY.md` 为单一权威安全策略文档；扩充硬化区域清单与 Fail-Open/Fail-Closed 决策矩阵（关联 Go 包路径与测试文件）；提供 [auto]/[manual] 标记的可自动化开发者安全检查清单；保留并增强运维部署硬化检查清单（来源：docs/feature-spec-security-docs.md）
- **协调披露 PGP 公钥端点与统一 SLA**：提供 `.well-known/pgp-key.txt` 端点发布 PGP 公钥以支持加密漏洞报告，并统一披露 SLA（3 个工作日确认、7 个工作日分诊、高危 30 天修复、90 天或修复发布孰早协调公开披露），消除现有文档间矛盾的 SLA 表述（来源：docs/feature-spec-security-docs.md）
- **供应链安全强化（Cosign 签名 + SLSA3 溯源 + FIPS 边界文档）**：启用已在 goreleaser.yaml 中配置但未完全生效的 Cosign 容器/构件签名与 SBOM 生成，新增 SLSA 3 来源证明（in-toto provenance）及 FIPS 140-3 加密模块边界正式文档（来源：docs/requirements/architect-frontier-identity-paradigms-platform-resilience-2026-07-11.out.md, docs/results/expansion-novel-2026-07-11.out.arch.md）
- **CI 集成 SCA/SAST/镜像漏洞扫描**：在 CI 流水线中加入 govulncheck、CodeQL、Trivy 等静态分析与依赖/镜像漏洞扫描，补齐当前仅本地 make target 而无 CI 门禁的缺口（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md, docs/results/architect-expansion-novel-5-directions-2026-07-11.out.arch.md）
- **依赖许可 NOTICE.txt 生成**：在既有许可证 CI 门禁基础上补充生成 NOTICE.txt 依赖声明文件（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **Consent 治理增强（Scope Drift 检测/同意收据/过期扫描）**：`Client.AllowedScopes` 变更后标记受影响的旧同意为 stale 并在下次使用时重新校验；为 ConsentGrant 增加 ConsentReceiptHash 结构化收据；新增后台任务主动扫描过期同意授权并发出审计事件；配套 Portal SPA“已授权应用”管理面板（来源：docs/requirements/architect-unique-gaps-scan-2026-07-11.out.md, docs/results/architect-fresh-code-scan-2026-07-11.out.arch.md, docs/results/senior-architect-expansion-v5-post-scan.out.arch.md）
- **GDPR 同意记录匿名化删除**：用户行使被遗忘权时对同意记录进行级联匿名化而非物理删除，兼顾数据擦除权与审计链不可篡改性要求（来源：docs/results/architect-unique-gaps-scan-2026-07-11.out.arch.md）
- **企业级隐私同意管理平台（IAB TCF v2.2 / GPP）**：构建独立于现有 OAuth scope 同意机制的按目的×供应商×状态的隐私法规同意模型，支持 IAB TCF v2.2 同意字符串（TC String）编解码、GPP 全球隐私平台信号编码及优先级仲裁、全球供应商列表（GVL）版本同步（来源：docs/tech-lead-analysis-frontier-paradigms-2026-07-12.md, docs/requirements/architect-expansion-analysis.out.md, docs/requirements/expansion-novel-2026-07-11.out.md, docs/results/architect-expansion-analysis.out.arch.md, docs/results/expansion-novel-2026-07-11.out.arch.md）
- **司法辖区感知合规叠加与同意信号传播**：基于既有 geo 中间件按用户地理位置自动选用适用的隐私法规默认值（GDPR/CCPA/LGPD/PIPL，可手动覆盖），并将同意状态通过 ID Token 同意声明、Sec-GPC 请求头识别、Consent-Status 响应头传播给下游系统（来源：docs/tech-lead-analysis-frontier-paradigms-2026-07-12.md, docs/results/expansion-novel-2026-07-11.out.arch.md）
- **数据主体访问请求（DSAR）工作流**：端到端 DSAR 提交、身份核实、数据收集/导出（复用既有 `compliance/export.go`）、打包、人工审核与通知的编排工作流及管理面板（来源：docs/tech-lead-analysis-frontier-paradigms-2026-07-12.md, docs/results/expansion-novel-2026-07-11.out.arch.md）
- **隐私同意与授权 UX 融合 + 同意历史时间线**：将隐私同意流程与现有 OAuth scope 授权同意 UI 融合，用户在同一界面完成 scope 授权与隐私处理同意；提供用户/管理员查看隐私同意变更历史（给予/撤回/过期）的时间线视图（来源：docs/results/architect-expansion-analysis.out.arch.md）
- **细粒度数据保留策略引擎**：提供按数据类别（DataCategory）与司法辖区（Jurisdictions）差异化的 DataRetentionPolicy 模型及管理 API（`GET/PUT /api/v1/admin/privacy/retention-policies`），配套后台强制执行器在非高峰期清除/匿名化超期数据，扩展现有仅做存活期清理的 Retention Sweep 框架（来源：docs/tech-lead-analysis-frontier-paradigms-2026-07-12.md, docs/requirements/expansion-novel-v4-privacy-dx-operations.out.md, docs/results/expansion-novel-2026-07-11.out.arch.md, docs/results/expansion-novel-v4-privacy-dx-operations.out.arch.md）
- **自动化 ROPA/ISMS 合规报告生成**：在现有静态 GDPR Art.30 data-map 基础上，自动生成动态化的完整处理活动记录（ROPA）及 ISMS 合规审计报告，含法规覆盖矩阵与合规健康仪表盘（来源：docs/tech-lead-analysis-frontier-paradigms-2026-07-12.md, docs/results/expansion-novel-2026-07-11.out.arch.md）
- **Legal Hold 与 ToS 接受追踪**：支持将数据置于法律保留（Legal Hold）以阻止删除/过期（因客户需求各异而推迟）；复用现有同意基础设施追踪用户对服务条款（ToS）的接受情况（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **身份治理与访问认证（IGA）**：提供定期访问认证/审查活动（Access Certification Campaign）引擎、认证者分配与周期调度、身份健康评分、权限提升路径检测、职责分离（SoD）违规检测、僵尸/孤立账户检测、角色挖掘引擎及权限分析/治理仪表盘（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md, docs/requirements/architect-global-analysis-2026-07-11.out.md, docs/requirements/architect-expansion-analysis.out.md, docs/requirements/expansion-novel-v2-identity-2026-07-11.out.md, docs/results/architect-expansion-analysis.out.arch.md）
- **KYC/IDV 身份核验流水线**：面向 FinTech/HealthTech/政府等受监管行业的文档/生物特征身份核验（Know Your Customer）流程（来源：docs/requirements/architect-global-analysis-2026-07-11.out.md）
- **持续安全姿态管理与合规能力（ISPM）**：PostureRule/Checker SPI 结合安全基线即代码（声明式 YAML DSL 定义预期安全配置状态），PostureScanner/持续扫描器定时评估客户端配置/令牌 TTL/密码健康/审计覆盖等安全规则，产出加权综合姿态评分与 Critical/High 发现告警；对非关键违规提供带冷却期与管理员升级机制的可撤销自动漂移修复；按需生成含检查结果、配置快照、审计记录与哈希链签名防篡改的合规证据包；CISO 仪表盘展示姿态趋势、合规缺口与修复建议（来源：docs/architect-analysis/nhi-posture-pq-architecture-review-2026-07-11.md, docs/requirements/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.md, docs/results/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.arch.md, docs/results/architect-global-scan-novel-ops-biz-gaps.out.arch.md, docs/requirements/expansion-secrets-slo-challenge-posture-billing.out.md）
- **配置合规策略引擎**：评估服务器/租户配置是否符合组织合规规则（如密钥算法、MFA 策略）的策略引擎，支持 exclude_paths 白名单避免误报；扩展 `sso-ctl config validate` 增加交叉引用一致性校验（L1）、NIST SP 800-63/PCI DSS 等合规基线比较（L2）及升级兼容性检查（L3）；支持配置变更 PGP 签名验证及可在租户开通时应用的安全基线预设（来源：docs/requirements/senior-architect-expansion-v3-identity-system-quality.out.md, docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.review.out.arch.md, docs/results/senior-architect-expansion-v3-identity-system-quality.out.arch.md, docs/tech-lead-analysis/cross-validated-five-new-directions.md, docs/requirements/Senior-Architect-Expansion-Directions-2026-07-11.out.md）
- **租户合规报告生成**：为租户生成合规报告的能力（当前缺失）（来源：docs/requirements/Senior-Architect-Expansion-Directions-2026-07-11.out.md）
- **证书到期告警引擎与 Provider 元数据版本审计**：CertWatcher 扫描联邦对端/SAML IdP/OIDC IdP 的证书到期情况，在可配置的 30 天/7 天预警/严重阈值触发事件；MetadataAudit 在每次探测成功后存储 Provider 元数据（端点 URL/证书指纹/JWKS 摘要）的历史版本，供运营方审查变更历史（来源：docs/tech-lead-analysis/analysis.md）
- **IdentityGraph SPI（访问关系可视化）**：只读、周期刷新的物化视图接口（GetUserAccessPath/GetPolicyImpact/GetUnusedPermissions），聚合现有存储以可视化用户-应用-角色-权限关系（来源：docs/architecture-analysis-peer-review-response.md）
- **凭据健康治理与自动修复**：将当前仅 emit-and-forget 的凭据健康信号扩展为闭环治理体系：CredentialStatusStore SPI + 后台扫描器 + 策略引擎驱动自动修复动作（强制改密/强制 MFA 注册/暂停账户），并提供 Admin 仪表盘与 CSV/JSON 合规导出、Prometheus 指标（来源：docs/architecture/architect-analysis-expansion-v10-directions.md, docs/requirements/expansion-directions-v10-analysis.out.md, docs/tech-lead-expansion-analysis.md）
- **审计查询多维度过滤增强**：扩展 `audit.Query` 支持按租户、按主体（subject）、按令牌 jti 等维度过滤，弥补当前仅支持按时间范围查询的缺口（来源：docs/results/architect-expansion-novel-5-directions-2026-07-11.out.arch.md）
- **外部数据平台导出治理层**：新增可插拔 AuditExporter/Exporter SPI（S3/GCS/BigQuery/Snowflake 对象存储 + Splunk HTTP Event Collector 等目标），配套事件 Schema Registry 版本管理与兼容性校验、导出审批工作流（申请→管理员批准→导出前 Schema 校验），将现有通用 Kafka/MQTT sink 升级为治理化导出管道（来源：docs/tech-lead-analysis-peer-review-corrections.md, docs/requirements/expansion-ciam-identity-horizon.out.md, docs/results/expansion-ciam-identity-horizon.out.arch.md）
- **租户级审计导出与保留策略增强**：新增基于 `tenant:audit:read`（区别于 `admin:write`）的租户自服务审计导出端点、按租户差异化的审计保留策略与定时导出调度（如 S3/Splunk HEC）、租户输出隔离（一个租户导出失败不影响其他租户），并提供 `/admin/tenants/:id/export-policy` 端点配置每租户导出目标/格式/脱敏规则（来源：docs/requirements/architect-scan-2026-07-11.out.md, docs/tech-lead-analysis-peer-review-corrections.md, docs/results/expansion-ciam-identity-horizon.out.arch.md, docs/results/senior-architect-expansion-v5-post-scan.out.arch.md）
- **按严重度加权的审计队列背压与丢弃告警**：新增可插拔 AsyncDropPolicy（如 DropBySeverity），在队列满时淘汰当前缓冲中优先级最低的事件而非固定丢弃最新事件，复用既有严重度分级体系，并将丢弃事件计数接入告警系统（来源：docs/requirements/global-scan-five-directions.out.md）
- **用户自助安全活动时间线**：`GET /me/security/timeline` 聚合既有审计/会话/MFA/同意事件生成用户可读的安全活动时间线，含 EventSummarizer SPI 本地化摘要及 IP/设备信息 PII 脱敏；用户账户删除后延迟 30 天再匿名化时间线数据；事件量超阈值时可切换为物化 TimelineEventStore（来源：docs/requirements/senior-architect-fresh-scan-2026-07-11.out.md, docs/requirements/senior-architect-global-scan-5-uncovered-expansion-directions.out.md, docs/results/senior-architect-fresh-scan-2026-07-11.out.arch.md, docs/results/senior-architect-global-scan-5-uncovered-expansion-directions.out.arch.md）
- **用户通知基础设施（Notification SPI）**：新增 NotificationEvent/NotificationStore/NotificationSender SPI 及事件路由引擎，将审计事件转为用户可见通知（去重聚合，email/in-app/push 多通道），提供 `GET /me/notifications` 用户面 API，并扩展 GDPR 数据擦除覆盖 NotificationStore 中的记录（来源：docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.out.arch.md, docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.review.out.arch.md）
- **密码生命周期引擎端到端集成**：新增 UserPasswordMeta SPI 及密码生命周期校验逻辑，在登录路径集成密码过期检查（`password_expired` 错误码，非 oracle-leak）与强制改密，并将 PasswordHistoryStore 落地为 SQLite 持久化，支撑合规密码策略证据链（来源：docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.out.arch.md）
- **统一安全事件模型与安全时间线查询 API**：新增归一化 SecurityEvent 模型及适配器，将 Anomaly、ThreatAction、SOC2 发现、证书到期信号转换为单一可查询事件类型；提供分页、可按严重度/类型/来源/租户/时间范围过滤的管理 REST 端点，支持 CSV 导出（来源：docs/tech-lead-analysis-peer-review-corrections.md）
- **授权许可（Consent Grant）全生命周期审计事件链**：完整发出 EventConsentGranted/EventConsentRevoked 等审计事件（含 client_id/user_id/scopes/trace_id），可通过审计系统查询，实现从授予到刷新到吊销的端到端审计追踪（来源：docs/tech-lead-analysis-peer-review-corrections.md, docs/requirements/expansion-ciam-identity-horizon.out.md）
- **属性元数据生命周期审计事件**：新增 EventAttributeSet/EventAttributeVerified/EventAttributeExpired 等审计事件类型，捕获属性生命周期变化并对敏感字段做哈希处理（来源：docs/tech-lead-analysis-peer-review-corrections.md）
- **数据分类与 PII 标记体系**：引入 ClassificationPolicy SPI 及 Public/Internal/Confidential/Restricted/PII 五级数据分类/字段标记机制，为脱敏、加密、配额统计等能力提供统一的数据敏感度元数据基础（来源：docs/requirements/expansion-novel-v4-privacy-dx-operations.out.md, docs/results/expansion-novel-v4-privacy-dx-operations.out.arch.md）
- **审计日志脱敏/PII 编辑管线**：为 `audit.Sink` 增加可选的 SanitizeBeforeRecord 钩子，在写入审计日志前对邮箱、IP 等 PII 字段做自动脱敏，覆盖现有 24+ 种审计事件类型（来源：docs/requirements/expansion-novel-v4-privacy-dx-operations.out.md, docs/results/expansion-novel-v4-privacy-dx-operations.out.arch.md）
- **HMAC PII 脱敏身份数据导出**：导出命令支持 `--mask` 选项，以 pepper 文件管理的 HMAC-SHA256（或 AES/none）对 PII 字段脱敏，使导出数据在开发/测试环境保持一致但不可逆（来源：docs/results/expansion-five-uncovered-gaps.out.arch.md）
- **身份事件溯源与状态重建**：为审计事件附加 BeforeState/AfterState（哈希而非全量快照）以支持通过事件重放做时间点状态重建，参照现有 `signingkeys.CoordinatedCutover` 模式做集群协调检查点（CheckpointStore）（来源：docs/requirements/architect-remaining-horizon-2026-07-11.out.md, docs/results/architect-remaining-horizon-2026-07-11.out.arch.md）
- **身份变更数据捕获（CDC）事件管线**：构建独立于内部审计追踪与跨副本集群总线的结构化外部面 CDC 事件管线（schema/发出点/重放），复用现有 Kafka 基础设施向外部消费者做至少一次投递（来源：docs/requirements/architect-unique-gaps-scan-2026-07-11.out.md）
- **审计表复合索引性能修复**：为 audit_events 表新增 (actor_id, type, timestamp) 与 (type, timestamp) 复合索引，解决当前单列时间索引在大数据量下退化为全表扫描的性能问题（来源：docs/results/architect-remaining-horizon-2026-07-11.out.arch.md）
- **GDPR 合规威胁情报数据共享协议**：提供数据共享协议模板及强制 mTLS/TLS 1.3 传输加密、租户加盐主体哈希，用于跨境威胁指标交换，缓解 GDPR 第 49 条风险（来源：docs/tech-lead/expansion-five-directions-v2-peer-review-implementation.md）
- **官方 OpenID Foundation 认证（规划中）**：计划运行官方 OIDF 一致性测试套件、解决差距并提交结果，以获取 OP Basic/Implicit/Hybrid Profile 认证（来源：docs/sso/oidc-conformance.md）
- **SubjectExporter 接口标准化实现**：实现当前零实现的 SubjectExporter 接口（GDPR Art.15 导出），尽管对应的 Eraser 已可删除主体数据（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **降级认证审计事件与 AMR 标记**：提议 auth_degraded_failover 审计事件，以及在故障切换期间签发的令牌中携带 `amr:["degraded_failover"]` 之类声明，供依赖方识别降级风险（来源：docs/requirements/senior-architect-expansion-v2-identity-gaps.out.md）
- **审计事件用户状态快照与状态过滤合规查询**：在认证审计事件捕获时嵌入 UserSnapshot（状态/部门/经理/雇佣类型），支持根因分析（如检测已离职用户的登录尝试）；提供 `GET /admin/audit?user_status=terminated` 风格的状态过滤合规查询 API（来源：docs/results/expansion-novel-v2-identity-2026-07-11.out.arch.md）

---
## 可观测性与运维韧性

### 已实现功能

- **SSE 跨副本实时事件流与端到端管道**：完整的 SSE broker/handler/sink 实现，支持 Last-Event-ID 断点续传、订阅者驱逐、优雅关闭，已有 E2E 测试覆盖，实现跨副本近实时、至多一次的事件传播（管理端 `/api/v1/admin/events/stream`）。（来源：docs/architecture-analysis-peer-review-response.md, docs/error-codes.md, docs/results/expansion-next-wave-analysis.out.arch.md, docs/results/tech-lead-analysis-expansion-next-wave.out.arch.md, docs/requirements/tech-lead-analysis-expansion-next-wave.out.md）
- **分布式追踪基础设施（W3C Traceparent/OTel OTLP/审计 TraceID-SpanID）**：W3C Trace Context 传播、OpenTelemetry OTLP 导出、审计事件携带 TraceID/SpanID 已作为可观测性基础设施上线；异步后台路径（审计投递、webhook 投递、重试 Sink、CAEP 推送、集群总线发布/订阅、迁移任务）也已正确挂载追踪 span 并正确关联父级 trace/span。（来源：docs/architecture/architect-analysis-expansion-v10-directions.md, docs/observability.md, docs/results/senior-architect-fresh-scan-2026-07-11.out.arch.md）
- **错误响应 Trace ID 关联**：Tracing 中间件生成 W3C trace ID 写入 `X-Trace-Id` 响应头，错误响应体同步携带 `trace_id` 字段，便于客户端向支持团队提供唯一关联标识。（来源：docs/error-codes.md, docs/observability.md）
- **租户级指标标签白名单（基数控制）**：`metrics.tenant_label_allowlist` 通过白名单 + "other" 兜底桶限制按租户维度的登录/签发指标基数。（来源：docs/config-reference.md, docs/observability.md）
- **核心 Prometheus 指标族（HTTP/登录/令牌签发/客户端缓存）**：已暴露 HTTP 请求计数与延迟直方图（按方法/状态类）、登录尝试计数（按 provider/outcome）、令牌签发计数（按策略）、客户端存储缓存命中/未命中等指标，均遵循无路径/用户高基数标签的有界基数设计。（来源：docs/observability.md）
- **固定中间件顺序与探针隔离**：`/metrics`、`/livez`、`/readyz` 位于限流中间件之外；其余请求走固定 tracing→ratelimit→bodyLimit→metrics→CORS→router 链路。（来源：docs/observability.md, docs/deployment.md）
- **日志级别热重载（SIGHUP）**：`logging.level` 变更通过 SIGHUP 立即生效，无需重启，不丢日志行。（来源：docs/config-reference.md）
- **健康探测端点族（/livez /readyz /metrics）**：`/readyz` 聚合所有已注册 `WithReadyCheck`（DB 连通性、etcd 可达性、签名后端健康），探针位于中间件栈之外。（来源：docs/deployment.md）
- **本地可观测性 Docker Compose 技术栈**：`ops/deploy/compose/` 提供预置 Prometheus + Grafana（含仪表盘与告警规则）的本地一体化观测栈。（来源：docs/deployment.md）
- **代码库健康诊断与架构报告**：`make diagnose` 与 `make health-report` 生成代码库健康诊断与架构健康报告。（来源：docs/developer-guide.md）
- **工程指标趋势快照**：`make trend` 周期性采集工程指标快照存入 `.trends/`，用于跟踪代码库健康趋势。（来源：docs/developer-guide.md）
- **四级故障分级与 RPO/RTO 目标体系**：定义组件级/副本级/持久存储丢失/站点区域丢失四级故障，各含影响范围、RPO/RTO 目标与操作响应规范。（来源：docs/dr-framework.md）
- **DR 就绪状态管理端点**：`GET /api/v1/admin/dr/status` 报告 DR 就绪判定、复制延迟 vs RPO 目标、最近复制错误、RTO 历史与 DR 留存清单。（来源：docs/dr-framework.md）
- **DR 就绪性 Prometheus 指标**：`sso_dr_readiness`、`sso_dr_snapshot_replication_lag_seconds`、`sso_dr_last_recovery_seconds`、`sso_dr_last_drill_success`。（来源：docs/dr-framework.md）
- **RecoveryTimeTracker 实测 RTO 记录**：运维通过 `Start`/`Stop` 记录真实恢复/演练的 RTO 历史，并与配置的 `dr.rto_target` 比较。（来源：docs/dr-framework.md）
- **热路径性能优化（对象池/分片锁/可注入时钟）**：JWT 签发使用 `sync.Pool` 缓冲池，内存授权码/PAR 存储采用分片锁，签名颁发器支持可注入 Clock，降低请求路径开销。（来源：docs/deferred-backlog.md）
- **内存存储容量上限与后台回收器**：JTI 重放、刷新令牌、设备码、PAR 内存存储支持可选 `MaxEntries` 上限与 opt-in 后台回收器（仅内存后端，默认关闭）。（来源：docs/deferred-backlog.md）
- **客户端存储 TTL 缓存与总线失效**：ClientStore 查询按租户/客户端维度缓存并设 TTL，通过集群总线主动失效而非被动等待过期。（来源：docs/ROADMAP.md）
- **优雅 SIGTERM 关闭**：服务器在 SIGTERM 时协调保留调度器与在途请求的有序关闭，而非直接终止。（来源：docs/ROADMAP.md）
- **跨副本缓存失效总线（InvalidationBus）**：`cluster.Bus` SPI（内存 + etcd peers）传播租户暂停与发现文档重载事件，使各副本及时清理本地缓存。（来源：docs/ROADMAP.md）
- **令牌使用量按分钟聚合引擎（tokenusage）**：`domains/tokenusage` 提供按客户端/主体/端点/时间段（分钟粒度）聚合的离线令牌使用统计管道，含地理国家维度，可直接支撑使用分析仪表盘。（来源：docs/requirements/architect-remaining-horizon-2026-07-11.out.md, docs/results/architect-expansion-analysis.out.arch.md）
- **Prometheus 告警规则评估框架**：`platform/metrics` 已实现基于指标条件触发的告警规则框架。（来源：docs/requirements/expansion-ciam-identity-horizon.out.md, docs/results/expansion-ciam-identity-horizon.out.arch.md）
- **手动 pprof 调试端点**：`/debug/pprof/` 绑定独立可配置监听地址（默认 `127.0.0.1:6060`），受 `PprofConfig` 控制，支持按需手动性能剖析。（来源：docs/requirements/expansion-runtime-infrastructure-analysis.out.md, docs/requirements/expansion-systemic-quality-horizon.out.md）
- **基准性能回归门禁框架（benchgate）**：`ops/deploy/benchgate` 已用于门禁性能基准回归，可作为未来剖析回归门禁的基础。（来源：docs/requirements/expansion-runtime-infrastructure-analysis.out.md）
- **关键路径延迟直方图**：Prometheus 直方图已采集登录、MFA、KMS 签名延迟（`sso_http_request_duration_seconds`），可通过 `histogram_quantile` 查询 p99。（来源：docs/requirements/expansion-systemic-quality-horizon.out.md）
- **Kafka/MQTT 审计事件流式出口**：`infrastructure/kafka/` 与 `infrastructure/mqtt/` 已实现审计事件的流式 Sink 出口，支持外部消费。（来源：docs/results/expansion-ciam-identity-horizon.out.arch.md）
- **连接健康状态跟踪**：`domains/connections/health.go` 已提供连接健康状态跟踪能力。（来源：docs/results/senior-architect-expansion-v2-identity-gaps.out.arch.md）
- **Fail-Open/Fail-Closed 故障模式标注**：每个组件明确标注故障模式（Fail-Open 或 Fail-Closed），是系统可操作性设计的基础保证，并已在 AGENTS.md 中系统化文档化（§3 Fail Modes）。（来源：docs/results/senior-architect-expansion-v8-2026-07-11.out.arch.md, AGENTS.md）
- **OTel 追踪 + 多指标 + OCSF 审计哈希链**：平台已具备基于 OpenTelemetry 的分布式追踪、80+ 项 Prometheus 指标，以及 OCSF 格式的审计事件哈希链与多 Sink 扇出能力。（来源：docs/results/senior-architect-fresh-scan-2026-07-11.out.arch.md）
- **安全运营数据面基础（令牌统计/异常检测/威胁响应/SSE）**：`tokenusage`/portfolio 统计、异常检测器（anomaly detectors）、威胁响应执行器（threataction executors）与 `sse.Broker` 已提供安全仪表盘所需的数据与事件源。（来源：docs/architecture/architect-analysis-expansion-v9-five-directions.md）

### 提议中/未来方向功能

- **统一身份事件模型与事件存储（EventStore）**：提出共享 Event 类型与 EventRegistry/EventStore（内存 + SQLite/Postgres），统一目前互相孤立的审计、CAEP、webhook、SSE、集群总线五类事件源，支持 Append/Query/Correlate 及基于 event-time 的迟到事件处理，作为新 `domains/eventintelligence` 包的基础。（来源：docs/agent-os/architect-analysis/expansion-post-protocol-layer-architecture-review.md, docs/tech-lead-analysis-post-protocol-layer.md, docs/requirements/expansion-post-protocol-layer-analysis.out.md, docs/results/expansion-post-protocol-layer-analysis.out.arch.md, docs/requirements/architect-global-analysis-2026-07-11.out.md）
- **跨源事件关联引擎与索引化规则匹配（AIOps）**：基于按事件类型索引的规则引擎，在事件到达时以近 O(1) 方式匹配关联规则（而非全量扫描），跨多源事件在时间窗口内关联合成高阶安全/身份事件；并延伸出面向身份运维的 AIOps 式异常/趋势洞察分析能力。（来源：docs/agent-os/architect-analysis/expansion-post-protocol-layer-architecture-review.md, docs/tech-lead-analysis-post-protocol-layer.md, docs/results/architect-global-scan-novel-ops-biz-gaps.out.arch.md, docs/results/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.arch.md, docs/requirements/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.md）
- **事件查询 REST API 与 TTL/后台 GC**：面向租户隔离、游标分页的事件查询端点（按类型/时间范围/actor/target/severity），配合可配置保留 TTL 与后台垃圾回收及大小/驱逐指标。（来源：docs/tech-lead-analysis-post-protocol-layer.md, docs/results/expansion-post-protocol-layer-analysis.out.arch.md）
- **多租户身份/业务分析引擎（BusinessAnalyticsStore, MAU/DAU）**：基于 tokenusage/metering 管道构建的分层预聚合分析引擎（5 分钟/1 小时/1 天桶，不同留存期），提供 MAU/DAU 趋势、认证方式采纳率（MFA/密码/WebAuthn/社交登录）分布、令牌组合健康评分与到期日历、按客户端/地理维度的日报月报，以及 Admin Console 业务级仪表盘可视化与业务视角 Grafana 仪表盘。（来源：docs/agent-os/architect-analysis/expansion-post-protocol-layer-architecture-review.md, docs/tech-lead-analysis-post-protocol-layer.md, docs/requirements/architect-remaining-horizon-2026-07-11.out.md, docs/results/architect-remaining-horizon-2026-07-11.out.arch.md, docs/requirements/expansion-novel-v4-privacy-dx-operations.out.md）
- **定时安全/分析报表引擎**：cron 驱动的报表引擎，按可配置计划生成 HTML/CSV 报表并通过邮件投递。（来源：docs/tech-lead-analysis-post-protocol-layer.md）
- **外部依赖韧性框架：熔断器与舱壁隔离/统一 Egress 连接器**：新增 `platform/resilience` 或 `platform/egress` 包，提供自建滑动窗口熔断器（失败率/计数模式）与基于有界信号量的舱壁隔离 SPI，统一包装 KMS 签名、SAML IdP 抓取/断言验证、CAEP webhook 推送、Federation fetch、SMTP、ext_authz gRPC、LDAP 连接池、HIBP 等外部依赖调用及所有出站 HTTP 请求（含审计事件与 `outbound_requests_total` 等指标、敏感头脱敏），防止单一慢依赖耗尽共享 goroutine/连接池，接入 `/readyz`（按 connector 维度健康检查）与 Prometheus 可观测性，并含熔断器状态变更审计事件与 Admin Resilience Status API。（来源：docs/architect-analysis-v6-five-directions.md, docs/feature-spec-architecture-synthesis-five-directions.md, docs/tech-lead-analysis/implementation-plan-five-directions.md, docs/results/architect-gaps-analysis-2026-07-11.out.arch.md, docs/results/senior-architect-expansion-2026-07-11.out.arch.md）
- **SLO/SLI 错误预算与多窗口烧尽率告警框架**：定义 SLI/SLO/ErrorBudget 类型，基于既有 Prometheus 指标计算错误预算与多窗口多烧尽率（burn rate）告警，提供核心服务（令牌签发可用性、令牌验证延迟、登录可用性、认证流水线分阶段 SLI）基线指标，以 fail_open 方式集成进 `/readyz`，并提供管理端查询 API 与 `make slo-check` CI 性能门禁。（来源：docs/tech-lead/tech-lead-analysis-five-true-new-gaps-2026-07-12.md, docs/requirements/expansion-secrets-slo-challenge-posture-billing.out.md, docs/results/expansion-production-hardening-analysis.out.arch.md, docs/results/architect-global-scan-v2-true-new-gaps-2026-07-12.out.arch.md, docs/requirements/expansion-novel-v4-privacy-dx-operations.out.md）
- **etcd Watch/Lease 自愈与自动重订阅**：修复 etcd 监听在网络分区/连接断开后不会自我恢复的问题，增加退避重连、重新订阅、状态重新播种及 readiness 上报，避免副本永久失去跨副本撤销/租户暂停/密钥轮换事件传播却仍报告 `/readyz` 健康。（来源：docs/ROADMAP.md, docs/feature-spec-architecture-synthesis-five-directions.md, docs/results/architect-expansion-novel-5-directions-2026-07-11.out.arch.md, docs/results/expansion-directions-analysis.out.arch.md, docs/results/architect-unique-gaps-scan-2026-07-11.out.arch.md）
- **OAuth/OIDC 流级追踪（FlowID）与调试面板**：引入 FlowID 作为一等追踪概念，贯穿 AuthCode 签发/消费及请求上下文，关联 `/auth/login` 与 `/token` 跨浏览器重定向的完整 OAuth 流程；提供管理端按 code/trace_id/user_id 查询完整流程及 SSE 实时推送的调试 API，以及 Admin Console 可视化时间线面板（高亮异常步骤）。（来源：docs/architecture/architect-analysis-expansion-v10-directions.md, docs/tech-lead-expansion-analysis.md, docs/requirements/expansion-directions-v10-analysis.out.md, docs/results/expansion-directions-v10-analysis.out.arch.md）
- **安全运营中心（SOC）仪表盘与统一安全事件时间线**：新增 `platform/securityhub` 包聚合 Audit/Anomaly/ThreatAction 三类数据源为统一 SecurityEvent 时间线（支持 open/acknowledged/resolved 状态管理与关联 ID），配合 SecurityScorer 安全评分引擎（基于 MFA 覆盖率/令牌健康/异常密度/凭据健康/审计覆盖率计算 0-100 分），提供聚合管理端点（`GET /admin/security/overview`、批量会话终止、事件时间线查询）及 Admin Console 安全导航区（时间线面板、严重告警卡片、一键响应动作、告警规则配置、按 IP/用户的事故聚合）。（来源：docs/architecture/architect-analysis-expansion-v9-five-directions.md, docs/tech-lead-analysis-peer-review-corrections.md, docs/requirements/expansion-ciam-identity-horizon.out.md, docs/results/expansion-ciam-identity-horizon.out.arch.md, docs/requirements/tech-lead-analysis-expansion-next-wave.out.md）
- **统一依赖健康图谱与降级传播仪表盘**：声明式依赖图谱 SPI，为存储/消息/外部依赖节点注册健康探针、延迟与错误率指标，构建 DAG 并支持循环依赖检测，提供影响分析（ImpactAnalysis）引擎计算某依赖降级时受影响的上游组件与租户，通过管理端 API（`/admin/health/graph`、`/admin/dependency-graph`、`/propagation`）与交互式 DAG 可视化面板呈现故障传播路径以降低事故 MTTR，并与 `/readyz` 降级状态集成。（来源：docs/tech-lead-analysis-five-directions.md, docs/results/architect-final-five-2026-07-11.out.arch.md, docs/results/global-architecture-scan-five-uncovered-high-value-directions-2026-07-11.out.arch.md, docs/requirements/architect-final-five-2026-07-11.out.md, docs/requirements/global-architecture-scan-four-production-blindspots-2026-07-11.out.md）
- **统一提供商健康聚合与故障切换指标（KMS/IdP/LDAP/联邦/SAML）**：ConnectionHealth 扩展 ProviderType 字段（federation_peer/oidc_idp/saml_idp/ldap/smtp），新增 `GET /api/v1/admin/health/providers` 聚合端点；新增 `sso_kms_failover_total`/`sso_kms_key_status_total` 及 `kms_failover` 审计事件、`sso_idp_failover_total`/`sso_idp_probe_latency_seconds` 及 `idp_failover` 审计事件；SuccessRateAggregator 计算按提供商滚动窗口认证成功率。（来源：docs/tech-lead-analysis/analysis.md, docs/requirements/senior-architect-expansion-v2-identity-gaps.out.md, docs/results/senior-architect-expansion-v2-identity-gaps.out.arch.md）
- **后台守护协程生命周期治理框架（Loop Registry）**：将当前 15+ 个后台循环/调度器（BCL 投递、CAEP 广播 worker、发现缓存刷新、内存回收器、审计异步 worker、失效总线消费者、密钥轮换调度器等）零散的 recover/backoff/resubscribe 模式统一为 Loop/Runner SPI 与 LoopRegistry，暴露 per-loop 健康状态（`sso_background_loop_up`）及 `/debug/loops` 端点，并与 `/readyz` 集成使单个组件降级不会导致整机不可用；含运行时性能热点检测与自愈重启（防抖动熔断）及按依赖状态的功能级降级恢复循环。（来源：docs/requirements/expansion-runtime-governance-2026-07-11.out.md, docs/results/expansion-runtime-governance-2026-07-11.out.arch.md, docs/results/global-scan-five-directions.out.arch.md, docs/requirements/global-scan-five-directions.out.md）
- **统一系统健康模型与 Schema 版本护栏**：`platform/lifecycle/health` 聚合器通过 Dimension SPI 整合依赖校验、后台循环健康、Schema 版本状态、配置版本状态，输出 `/debug/system-health`（HEALTHY/DEGRADED/UNHEALTHY）；将现有但零调用方的 `migrate.CurrentVersion` 接入 `/readyz` 与 `/debug/schema`，防止版本回滚时旧二进制对已前向迁移的数据库静默服务。（来源：docs/requirements/expansion-runtime-governance-2026-07-11.out.md, docs/results/expansion-runtime-governance-2026-07-11.out.arch.md, docs/ROADMAP.md, docs/results/architect-expansion-novel-5-directions-2026-07-11.out.arch.md, docs/results/expansion-directions-v7-analysis.out.arch.md）
- **持续性能剖析流水线（Continuous Profiling）**：自动周期性采集 CPU/堆/mutex pprof 剖析（取代当前仅支持手动 `/debug/pprof/`），提供剖析对比工具并与既有 benchgate 框架集成实现剖析回归门禁。（来源：docs/requirements/expansion-runtime-infrastructure-analysis.out.md, docs/results/expansion-runtime-infrastructure-analysis.out.arch.md）
- **SQLite WAL Checkpoint 调度与连接池调优**：新增 WALConfig 及后台 checkpoint 循环，基于 WAL 文件大小阈值（默认 10MB）与时间间隔（默认 5 分钟）自适应触发 `PRAGMA wal_checkpoint`；独立后台连接执行 FULL/RESTART checkpoint 避免阻塞主路径（`MaxOpenConns` 从 1 提升至 2）；修复 `busy_timeout` DSN 参数被 modernc.org/sqlite 驱动静默忽略的问题，改用 `_pragma` 形式设置；新增 WAL 相关四项 Prometheus 可观测性指标。（来源：docs/ROADMAP.md, docs/requirements/deep-read-production-hardening-2026-07-11.out.md, docs/results/deep-read-production-hardening-2026-07-11.out.arch.md, docs/requirements/expansion-directions-analysis.out.md）
- **容量规划模型与预测性扩缩容指南**：文档化内存/吞吐模型（每会话/每 JTI/每刷新令牌内存开销、各后端吞吐基线）、MAU 分级 Kubernetes 资源与 HPA 配置建议、TTL 策略集中化管理；并提供基于指数加权移动平均与季节性分解的预测性容量规划（时序预测置信区间，复杂场景可切换至 MCP 上的 Python 模型）。（来源：docs/requirements/expansion-gaps-analysis-2026-07-11.out.md, docs/results/expansion-gaps-analysis-2026-07-11.out.arch.md, docs/requirements/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.md, docs/results/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.arch.md, docs/results/architect-global-scan-novel-ops-biz-gaps.out.arch.md）
- **交互式 OAuth 流程负载测试与 CI 性能回归门禁**：构建 k6 交互式登录/授权流程负载测试脚本（authorization_code+PKCE+userinfo、并发刷新轮换/家族复用检测、令牌交换、内省），建立系统吞吐/延迟性能基线；将现有仅手动触发的基准门禁升级为基于 benchstat 的自动化 CI 回归门禁，含跨后端（内存/SQLite/Redis/Postgres）BenchmarkSuite 统一接口与多后端性能对比矩阵；并跟踪各模块构建/测试耗时预算。（来源：docs/requirements/expansion-gaps-analysis-2026-07-11.out.md, docs/results/expansion-gaps-analysis-2026-07-11.out.arch.md, docs/results/expansion-systemic-quality-horizon.out.arch.md, docs/tech-lead-analysis-meta-governance-v2.md, docs/requirements/expansion-secrets-slo-challenge-posture-billing.out.md）
- **内省缓存/限流器/内存存储可观测性补全**：为 IntrospectionCache 新增 `Stats()`/`ResetStats()` 暴露命中率、大小与驱逐计数；为限流器暴露命中/拒绝计数、活跃 key 数与桶深度分位指标；为所有内存存储补充 EntryCount Prometheus Gauge 指标；新增统一管理端 `GET /admin/observability/*` 端点族聚合结构化诊断快照。（来源：docs/requirements/expansion-production-deployment-gaps.out.md, docs/results/expansion-production-deployment-gaps.out.arch.md, docs/requirements/senior-architect-5-gaps-2026-07-11.out.md）
- **令牌签发细分指标与令牌大小监控**：为 `sso_tokens_issued_total` 等指标增加 `grant_type` 与 `factor_type`（MFA 因子）维度标签；新增令牌大小估算与告警（接近约 6KB HTTP 头部限制时触发，含 PQ 签名算法场景）；将 `/token` 等端点的 Prometheus Histogram 分桶精度调整到毫秒级；引入结构化 EventContext（GrantType/ClientID/AuthMethod/TokenType/ErrorCode/Duration/IsSuccess）传给审计方法以支持 SIEM 转发，并考虑补充 p99 Summary 类型指标。（来源：docs/requirements/architect-fresh-code-scan-2026-07-11.out.md, docs/results/architect-fresh-code-scan-2026-07-11.out.arch.md, docs/architect-analysis/nhi-posture-pq-architecture-review-2026-07-11.md, docs/requirements/senior-architect-expansion-2026-07-11.out.md, docs/requirements/expansion-novel-v4-privacy-dx-operations.out.md）
- **按客户端（应用所有者）令牌可观测性与 API 消费分析**：异步批量采集 per-client 令牌生命周期事件（签发/交换/内省/撤销/刷新），配合白名单限制 Prometheus 标签基数与 "other" 兜底桶；新增 `GET /api/v1/admin/clients/:id/metrics` 返回按客户端隔离的签发/成功率/延迟快照（p50/p95/p99）及 Admin Console "Metrics" 标签页；从既有审计事件提取 per-client_id API 调用模式（频率/端点分布/错误率）用于生态使用分析。（来源：docs/tech-lead/expansion-five-directions-v2-peer-review-implementation.md, docs/requirements/expansion-directions-v12-analysis.out.md, docs/results/expansion-directions-v12-analysis.out.arch.md, docs/requirements/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.md, docs/results/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.arch.md）
- **身份关系图谱（Identity Graph）与自然语言查询接口**：基于 SQLite 邻接表构建身份图谱（用户/客户端/组/角色/权限/会话/令牌为节点/边），事件驱动收集器订阅集群总线保持同步（首次启动全量重放）；提供有界 BFS 遍历查询 API（硬性 `max_depth=5`、分页、访问集防环）及管理端查询/路径/统计 API 与 Admin Console 可视化；基于规则引擎（可选插拔 LLM 适配器，经白名单模板过滤而非自由执行，对 LLM 输出施加降级约束以保证运维决策可靠性）的自然语言到图查询翻译接口，含可解释结果 API 与限流。（来源：docs/tech-lead-analysis-cross-verified-five-directions.md, docs/requirements/PEER_REVIEW_architect-expansion-novel-horizons-2026-07-11.out.md, docs/results/tech-lead-analysis-expansion-next-wave.out.arch.md, docs/requirements/expansion-directions-v10-analysis.out.md, docs/results/architect-expansion-novel-horizons-2026-07-11.out.arch.md）
- **分布式边缘身份/授权决策缓存**：通用分布式缓存（Redis + 本地 LRU，cache-aside 语义）加速跨集群的工作负载注册表查询与 ext_authz 授权决策，含命中/未命中指标；并为 mesh 数据面提供本地化身份/授权决策缓存以降低对中心身份控制面的延迟与依赖。（来源：docs/tech-lead-analysis/cross-validated-five-new-directions.md, docs/requirements/high-value-expansion-directions.out.md）
- **令牌/会话链路取证与 Act 链溯源**：跨会话/令牌/授权码存储通过 TokenID/SessionID 关联（含审计表复合索引）的取证工作台以重建事故时间线降低 MTTR；新增 ActChainStore 持久化令牌交换（token exchange）多跳 act 委托链（当前仅存在于 JWT 签发时的内存构造中），提供 `GET /admin/tokens/{jti}/lineage` 令牌族谱溯源 API 及链深度分布告警指标与容量告警/P99 延迟指标。（来源：docs/requirements/architect-deep-code-scan-5-undiscovered-gaps.out.md, docs/requirements/architect-expansion-novel-5-directions-2026-07-11.out.md, docs/results/architect-expansion-novel-5-directions-2026-07-11.out.arch.md, docs/results/architect-deep-code-scan-5-undiscovered-gaps.out.arch.md, docs/results/senior-architect-expansion-v5-post-scan.out.arch.md）
- **自动化根因分析与运行手册引擎（AIOps）**：给定 user_id 与时间范围，追踪登录→授权码→令牌交换→刷新的完整请求链，基于既有审计/追踪/会话数据报告最可能失败点的根因分析引擎；持久化状态机形式的 Runbook 自动化执行器（触发条件、步骤如轮换签名密钥/限流客户端、回滚步骤与审批要求，默认仅建议模式）；基于 Z-score/MAD 对比历史基线自动标记性能退化趋势；基于历史使用模式推荐配置优化的配置推荐引擎。（来源：docs/requirements/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.md, docs/results/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.arch.md, docs/results/architect-global-scan-novel-ops-biz-gaps.out.arch.md, docs/requirements/architect-global-scan-novel-ops-biz-gaps.out.md）
- **前端错误监控与 Web Vitals/RUM 采集**：接入 `window.onerror` 全局处理器捕获前端运行时异常（当前完全静默丢失）；通过 PerformanceObserver 与 `navigator.sendBeacon` 采集 Web Vitals 与真实用户监控（RUM）数据，当前前端完全未实现。（来源：docs/requirements/senior-architect-expansion-2026-07-11.out.md, docs/results/senior-architect-expansion-2026-07-11.out.arch.md）
- **合成监控（Synthetic Monitoring）**：引入带 `is_synthetic` 标记的合成探测客户端（独立 CLI/sidecar，如 `cmd/sso-synthetic`）周期性演练 `/auth/login` 等关键业务流程可用性并发出可用性指标与告警。（来源：docs/requirements/expansion-novel-v4-privacy-dx-operations.out.md, docs/results/expansion-novel-v4-privacy-dx-operations.out.arch.md）
- **通知投递状态跟踪**：新增 DeliveryStore 跟踪各通知渠道的投递状态（成功/失败/退回/重试），供审计与用户/管理员查询，当前完全无此可观测性。（来源：docs/requirements/global-architecture-scan-four-production-blindspots-2026-07-11.out.md, docs/results/global-architecture-scan-four-production-blindspots-2026-07-11.out.arch.md, docs/results/architect-expansion-2026-07-11.out.arch.md）
- **运行时数据面一致性校验器**：新增 ConsistencyChecker SPI（起步为 CheckUserConsistency）交叉校验 UserProvider/SessionManager/RefreshTokenIssuer 状态漂移，可选接入 `/readyz`，弥补现有配置面漂移检测未覆盖运行时数据面的空白。（来源：docs/requirements/architect-unique-gaps-scan-2026-07-11.out.md）
- **身份维度可观测性标签与 SIEM 联邦审计**：在既有 metrics/tracing/audit 基础上增加 subject_type、auth_method 等身份维度标签（默认关闭高基数 user_id，按需开启并做基数控制）；新增身份链路追踪属性与 SIEM 告警馈送/`platform/audit/federation` 包，弥补当前无身份维度指标与联邦审计包的空白。（来源：docs/requirements/senior-architect-expansion-v7-true-gaps-2026-07-11.out.md, docs/results/senior-architect-expansion-v7-true-gaps-2026-07-11.out.arch.md, docs/requirements/expansion-directions-v11-analysis.out.md, docs/results/expansion-directions-v11-analysis.out.arch.md）
- **会话信任评分指标（sso_session_trust_score）**：按会话计算信任评分指标，聚合设备指纹、IP 地理变化、登录频率异常和 MFA 级别等信号（超出现有 `shared/trust` 衰减模型范畴）。（来源：docs/requirements/senior-architect-expansion-v2-identity-gaps.out.md）
- **裸金属高可用（HA）参考部署方案**：一套可复现的生产级裸金属 HA 部署拓扑（Postgres+Patroni+VIP 三节点同步复制、Redis Cluster 3 主 3 从 AOF 持久化 noeviction、HAProxy+keepalived VRRP 边缘、三节点 etcd 兼作协调基座、无状态多副本应用层各自暴露 `/readyz`/`/livez`），以 docker-compose 单机复现整拓扑，配合生产运行手册（启动顺序、故障切换演练与预期检测/恢复时间、备份恢复流程、容量估算公式、安全加固清单）及跨副本冒烟测试，零应用代码改动。（来源：docs/superpowers/plans/2026-06-26-baremetal-ha-data-layer.md, docs/superpowers/specs/2026-06-26-baremetal-ha-data-layer-design.md）
- **sso-mcp 健康探测与 Kubernetes 部署清单**：为 sso-mcp 自身提供 `/livez` 与 `/readyz` 端点（就绪性反映后端 snaplink gRPC 连接可达性），并规划 `ops/deploy/k8s` Deployment/Service/HPA 部署清单。（来源：docs/superpowers/plans/2026-06-29-sso-mcp.md）
- **SQLite 备份运维加固**：将当前硬编码的 `/tmp` 备份路径改为可配置目录，并增加备份响应元数据与留存策略处理。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **审计丢失与签名密钥健康告警规则**：新增 4 条 Prometheus 告警规则（审计事件丢弃、审计队列饱和、签名后端宕机、签名密钥聚合降级）及配套 Grafana 仪表盘面板，消费当前无告警消费者的既有指标。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md, docs/superpowers/plans/2026-07-02-wave1-quick-wins.md）
- **面板恢复（recover）默认中间件**：声称的缺口——中间件栈可能缺少默认开启的 `recover()` 处理器，导致 panic 可能直接使进程崩溃而非返回 500，需补齐面板恢复中间件。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **持久化、可重放的跨副本撤销拒绝集合**：为当前仅存在于进程内存的已撤销令牌拒绝集合（deny-set）增加持久化对等存储（SQLite/Redis）及启动时重新播种，避免滚动重启期间任一副本上已撤销但未过期的 access token 复活。（来源：docs/ROADMAP.md）
- **文档化分区故障 Fail-Open/Fail-Closed 行为矩阵**：发布明确的、面向运维的真值表，说明 etcd 中断、总线分区或单副本隔离场景下各代码路径的 Fail-Open/Fail-Closed 行为，当前该信息仅散落在代码注释中。（来源：docs/ROADMAP.md）
- **生产运维小修复批次**：一批 8 项低风险的小型运维修复与打磨项。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **缓存雪崩防护（Singleflight）**：使用 `golang.org/x/sync/singleflight` 为 L1 缓存增加防雪崩机制，避免热点令牌验证同时大量并发回源查询。（来源：docs/results/architect-expansion-5-directions.out.arch.md）
- **JWKS 响应体缓存**：缓存已序列化的 JWKS 响应体而非每次请求重新计算，解决 discovery/JWKS 端点的性能缺口。（来源：docs/requirements/expansion-directions-analysis.out.md）
- **时钟偏移（Clock Skew）硬化与 NTP 安全校验**：增加针对影响令牌签发/校验窗口的时钟偏移与 NTP 相关计时攻击的校验与硬化。（来源：docs/requirements/expansion-directions-analysis-v6.out.md）
- **数据库查询性能治理与索引管理**：通过迁移框架执行的集中式索引注册表（取代当前散落在各存储初始化代码中的临时 CREATE INDEX 语句），包括为审计表 `(actor_id, type, timestamp)` 组合查询新增复合索引。（来源：docs/requirements/architect-remaining-horizon-2026-07-11.out.md）
- **数据库/连接池可观测性**：暴露连接池利用率指标（`sql.DB.Stats()`）、慢查询日志、调优 SQLite `MaxOpenConns`（读写分离连接池）及 Redis/etcd 连接池指标，当前均未暴露。（来源：docs/requirements/expansion-runtime-infrastructure-analysis.out.md）
- **SAML IdP 未启用时 Session Hub 静默降级告警**：当 SessionHub 已配置但 SAML IdP 未启用时，添加告警日志说明跨协议登出传播不会工作，避免运维误判该功能正常运行。（来源：docs/results/deep-read-production-hardening-2026-07-11.out.arch.md）
- **Admin Console 实时事件流前端**：消费既有 SSE 后端的 Admin Console "Live Events" 前端页面，含自动重连/指数退避、按事件类型过滤（`?types=`）、搜索与虚拟化渲染；`GET /api/v1/admin/events/history` 提供离线期间事件的非流式回补查询；`event-stream.js` 封装 EventSource 自动重连与基于 Last-Event-ID 续传。（来源：docs/requirements/expansion-next-wave-analysis.out.md, docs/results/expansion-next-wave-analysis.out.arch.md, docs/results/tech-lead-analysis-expansion-next-wave.out.arch.md, docs/requirements/tech-lead-analysis-expansion-next-wave.out.md）
- **Mesh Workloads 管理端 UI**：面向 mesh 授权工作负载的查看与管理管理端 UI 界面，属于 mesh authz 扩展方向的一部分。（来源：docs/requirements/tech-lead-analysis-expansion-next-wave.out.md）
- **身份数据搜索索引**：在身份/审计数据之上构建搜索索引层，评估了三种候选架构并给出分阶段实施建议路径。（来源：docs/results/expansion-directions-v10-analysis.out.arch.md）
- **统一身份决策事件模型（IdentityDecision/DecisionTrace）**：IdentityDecision 事件模式携带按策略节点在决策时刻快照的嵌入式 DecisionTrace，由 EventEmitter 从限流引擎桥接产生，避免昂贵的事后关联，面向 SRE/运维/租户管理员的统一身份数据面观测能力（与安全威胁检测场景边界明确区分）。（来源：docs/requirements/expansion-directions-v11-analysis.out.md, docs/results/expansion-directions-v11-analysis.out.arch.md）
- **集成/Webhook 健康监控与生命周期管理**：监控生产环境中外部集成（webhook、连接器）的健康状况与投递成功率；对已注册的 RS webhook 订阅进行可达性健康探测，自动暂停不可达订阅并触发管理员告警。（来源：docs/requirements/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.md, docs/results/architect-deep-code-scan-5-undiscovered-gaps.out.arch.md）
- **安全态势自动化评估**：面向平台整体安全态势的持续、自动化评估与整改建议能力，超越当前仅时点性的审计快照。（来源：docs/requirements/architect-global-scan-novel-ops-biz-gaps.out.md）

**统计**：已实现功能 30 条；提议中/未来方向功能 51 条（原始 275 条经语义去重合并后共 81 条）。


---
## 风控与反滥用

### 已实现功能
- **令牌端点统一 invalid_grant 响应**：AuthCode/Refresh/Device/PAR 的未知、过期、已消费或不匹配凭据均折叠为同一 400 invalid_grant，防止 oracle 泄露。（来源：docs/error-codes.md, docs/SECURITY.md, docs/skills/oracle-leak/SKILL.md, docs/sso/oidc-conformance.md, docs/review-checklist.md）
- **PAR 统一 invalid_request_uri 响应**：request_uri 过期或缺失时统一返回，不区分具体原因。（来源：docs/SECURITY.md, docs/skills/oracle-leak/SKILL.md）
- **DPoP/mTLS 失败统一 invalid_token 响应**。（来源：docs/skills/oracle-leak/SKILL.md, docs/SECURITY.md）
- **private_key_jwt 失败统一 invalid_client 响应**。（来源：docs/SECURITY.md, docs/skills/oracle-leak/SKILL.md）
- **/register/:client_id 统一 401 invalid_token**：无论令牌缺失、错误还是未知，防止客户端枚举。（来源：docs/skills/oracle-leak/SKILL.md）
- **Introspection 非活跃令牌统一响应**：任意非活跃/未知令牌统一返回 200 {"active":false}。（来源：docs/skills/oracle-leak/SKILL.md, docs/error-codes.md）
- **未知用户 bcrypt 成本匹配哑哈希比较**：防止基于时序的用户枚举。（来源：docs/SECURITY.md, docs/skills/oracle-leak/SKILL.md, docs/sso/oidc-conformance.md, docs/review-checklist.md）
- **MFA 统一 mfa_invalid 响应**：所有失败场景统一返回，详情仅记录于 mfa_failure 审计事件。（来源：docs/skills/oracle-leak/SKILL.md, docs/sso/oidc-conformance.md）
- **WebAuthn 统一 404 session_invalid**：未知用户/会话统一返回。（来源：docs/SECURITY.md, docs/skills/oracle-leak/SKILL.md）
- **刷新令牌家族追踪与重放检测**：FamilyID 贯穿轮换，重用触发 DeleteFamily 撤销整个家族，宽限窗口内并发请求幂等。（来源：docs/sso/oidc-conformance.md）
- **授权码重用检测联动家族撤销**。（来源：docs/sso/oidc-conformance.md）
- **JAR request_uri 受限拉取**：HTTPS-only、禁止重定向、大小受限。（来源：docs/SECURITY.md）
- **跨副本一致的防枚举/oracle-leak 响应**：杜绝任何改变错误码的副本级快速路径。（来源：docs/deployment.md）
- **Oracle-leak/防枚举评审门禁**：新增 handler 规范与代码评审清单强制统一响应要求。（来源：docs/skills/code-review.md, docs/skills/add-new-handler/SKILL.md, docs/review-checklist.md）
- **安全不变量校验发布门禁**：make check-invariants 自动校验 10 项安全不变量作为合并前置条件。（来源：docs/RELEASE.md, docs/review-checklist.md）
- **内存令牌桶限流器（MemoryLimiter）**：支持可配置突发容量。（来源：docs/requirements/expansion-directions-analysis.out.md, docs/requirements/expansion-production-deployment-gaps.out.md）
- **可插拔 Redis 固定窗口限流后端**：多副本部署可配置切换，多算法+突发容量已验证实现。（来源：docs/SECURITY.md, docs/feature-matrix.md, docs/requirements/expansion-production-deployment-gaps.out.md, docs/results/expansion-production-deployment-gaps.out.arch.md）
- **限流策略 SIGHUP 热更新**：整体原子重建并热替换运行中间件，无需重启。（来源：docs/config-reference.md）
- **JTI 重放存储 fail-closed 可选模式**：存储查询错误可配置为按重放拒绝而非默认 fail-open。（来源：docs/config-reference.md, docs/ROADMAP.md）
- **可信代理 CIDR 白名单**：控制真实 IP 提取，供限流键与 geo/风险评分使用。（来源：docs/config-reference.md, docs/deployment.md）
- **异步行为异常检测管道（anomaly.Runner）**：内置不可能旅行、速度异常、新设备/国家、暴力破解影子检测等检测器，off 请求路径运行，溢出丢弃、永不阻塞登录。（来源：docs/ROADMAP.md, docs/architecture/analysis-detection-response-gap.md, docs/results/expansion-next-wave-analysis.out.arch.md, docs/results/expansion-novel-v2-identity-2026-07-11.out.arch.md）
- **细粒度异常检测 SPI 拆分**：RecentLoginStore、IPFailureCounter、FindingStore 独立接口，按需接入。（来源：docs/architecture/analysis-detection-response-gap.md, docs/requirements/tech-lead-analysis-expansion-next-wave.out.md, docs/results/tech-lead-analysis-expansion-next-wave.out.arch.md）
- **令牌使用异常检测器（tokenanomaly.Detector）**：装饰器模式包装 tokenusage.Store，含刷新令牌轮换速度异常检测与指标。（来源：docs/architecture/analysis-detection-response-gap.md, docs/observability.md）
- **行为信任评分器**：shared/trust/behavior_scorer.go，基于规则而非机器学习。（来源：docs/requirements/tech-lead-analysis-expansion-next-wave.out.md, docs/results/tech-lead-analysis-expansion-next-wave.out.arch.md）
- **信任分数时间衰减机制**：shared/trust/decay.go。（来源：docs/requirements/expansion-directions-analysis.out.md）
- **HIBP 密码泄露健康检查器**。（来源：docs/requirements/expansion-directions-analysis.out.md）
- **登录后凭据健康检查**：bcrypt 校验通过后异步扫描弱/泄露密码，fail-open、不泄露进令牌，仅审计记录。（来源：docs/ROADMAP.md）
- **设备安全姿态评分占位实现**：预留未来 MDM 集成。（来源：docs/requirements/architect-scan-2026-07-11.out.md）
- **设备指纹 SPI**：Lookup/Record 接口及 MemoryDeviceFingerprint 内存实现。（来源：docs/requirements/architect-scan-2026-07-11.out.md）
- **持续验证后台代理（continuousverify.Agent）**：fail-open 周期扫描（默认1分钟），含生命周期管理与事件钩子。（来源：docs/requirements/architect-scan-2026-07-11.out.md）
- **会话信任衰减与 Step-up 门控**：core.Session 携带 TrustScore/TrustSetAt/StepUpRequired，session_trust_decay.* 驱动指数衰减与最低信任 Step-up（RFC 9470）。（来源：docs/config-reference.md, docs/requirements/senior-architect-scan-v2-true-gaps-2026-07-11.out.md）
- **风控可观测性指标**：风险决策结果、凭据健康信号、零信任持续 Step-up 计数、按租户限流命中等。（来源：docs/observability.md）
- **条件访问（零信任）策略引擎与强制执行**：基于 risk_score/user_member_of/device_managed 条件在凭据校验后、令牌颁发前裁决，enforce 时可拒绝登录（conditional_access_denied）。（来源：docs/config-reference.md, docs/error-codes.md, docs/architecture/analysis-detection-response-gap.md, docs/requirements/architect-scan-2026-07-11.out.md）
- **条件访问信任评分器/设备指纹钩子**：WithTrustScorer / WithDeviceFingerprint。（来源：docs/config-reference.md）
- **Active ITDR 基础闭环**：ThreatExecutor + threataction 威胁策略存储，可自动挂起会话、撤销刷新令牌家族或强制 MFA Step-up，off 请求路径运行、fail-open，并通过 /api/v1/admin/threat-policies/* 暴露管理端 CRUD。（来源：docs/error-codes.md, docs/SECURITY.md, docs/tech-lead-analysis-post-protocol-layer.md）
- **账户失败次数锁定**：按 (client_id, identifier) 键在阈值后锁定，返回 423 account_locked。（来源：docs/error-codes.md, docs/feature-matrix.md）
- **发送验证码冷却限制**：/auth/send-code 按目标强制冷却窗口（默认60秒），超频返回 resend_too_soon。（来源：docs/error-codes.md）
- **可配置密码策略校验**：PasswordPolicyValidator，注册/改密拒绝弱密码。（来源：docs/error-codes.md）
- **可插拔注册准入网关与 CaptchaVerifier/CaptchaGate SPI**：CAPTCHA/黑白名单/滥用启发式，可拒绝注册并返回 registration_denied。（来源：docs/error-codes.md, docs/results/expansion-secrets-slo-challenge-posture-billing.out.arch.md）
- **管理端批量撤销令牌风暴防护**：超软上限需显式确认、超硬上限拒绝。（来源：docs/error-codes.md）
- **请求限流与请求体大小限制中间件**（WithBodyLimit）。（来源：docs/error-codes.md）
- **按路径可配置请求体大小限制**。（来源：docs/ROADMAP.md）
- **Federation 出站 SSRF 防护拨号器**：dialWithSSRFCheck，含 DNS-rebind 防护，用于外部元数据抓取。（来源：docs/results/expansion-production-deployment-gaps.out.arch.md, docs/results/expansion-novel-v3-identity-system-quality.out.arch.md）
- **CSP/Permissions-Policy/Clear-Site-Data 安全响应头**：每请求 nonce 的 CSP，覆盖 Admin/登录/自助门户等 SPA，登出与账户擦除附加 Clear-Site-Data。（来源：docs/config-reference.md, docs/feature-matrix.md）
- **深度、系统化协议安全防护体系**：DPoP、mTLS、PKCE、private_key_jwt、FAPI 2.0、防枚举/oracle-leak，并延伸至 JWT-SVID/Workload Identity/Break-Glass 应急访问/按租户签名密钥隔离等纵深机制。（来源：docs/architecture/architect-analysis-expansion-five-directions.md, docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.review.out.arch.md, docs/results/senior-architect-expansion-v7-true-gaps-2026-07-11.out.arch.md, docs/results/senior-architect-expansion-v8-2026-07-11.out.arch.md）
- **单步无状态协议 Fuzz 目标**：9个 fuzz target 覆盖协议解析单输入单函数路径。（来源：docs/architecture/architect-analysis-expansion-five-directions.md）
- **WASM 授权沙箱 fail-closed**：引擎任何错误均视为拒绝，调试端点返回 500 而非伪造结果。（来源：docs/wasmauthz.md）
- **WASM 授权沙箱调用超时中断**：强制中断卡死/循环的 guest 模块，仅销毁该次调用实例。（来源：docs/wasmauthz.md）
- **WASM 授权沙箱内存上限**：单实例线性内存上限 256 页（16MiB），防止耗尽宿主内存。（来源：docs/wasmauthz.md）
- **五种并行授权决策模型并存**：信任评分、条件访问、RBAC、ReBAC、WASM Authz 均已运行，尚缺统一决策管道。（来源：docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.review.out.arch.md）
- **X-Forwarded-* 信任运维约束**：仅受信边缘每跳剥离并重设时可信。（来源：docs/deployment.md）
- **灾难恢复演练 fail-safe 中止语义**：首个失败步骤即中止，不将未验证数据判定为可恢复。（来源：docs/dr-framework.md）

### 提议中/未来方向功能
- **统一出站 SSRF 防护框架**：新增 shared/outbound 包提供 HardenedClient/IsInternalIP，替代 Federation/CAEP/SAML/Webhook/JAR/CIBA/SCIM 等 20+ 处裸 http.Client。（来源：docs/architect-analysis-system-resilience-spa-ssrf-concurrency-5-gaps.md, docs/requirements/architect-system-resilience-spa-ssrf-concurrency-5-gaps.out.md, docs/tech-lead-plan-system-resilience-5-gaps.md, docs/results/architect-system-resilience-spa-ssrf-concurrency-5-gaps.out.arch.md, docs/requirements/expansion-novel-v3-identity-system-quality.out.md）
- **DNS 重绑定攻击防护**：出站请求连接后对 DNS 解析结果做二次 IP 校验，闭合 TOCTOU 窗口。（来源：docs/architect-analysis-system-resilience-spa-ssrf-concurrency-5-gaps.md, docs/requirements/architect-system-resilience-spa-ssrf-concurrency-5-gaps.out.md）
- **出站请求来源信任分级策略**：运营商配置/客户端属性声明/上游声明三档 URL 信任层级。（来源：docs/tech-lead-plan-system-resilience-5-gaps.md）
- **外部 JWKS 拉取 SSRF 白名单约束**：复用 JARFetcher 安全模式。（来源：docs/results/expansion-edge-cases-2026-07-11.out.arch.md）
- **CSP 违规上报端点（/csp-report）**：收集 SPA 违规报告并记录为限流保护的审计事件。（来源：docs/architect-analysis-system-resilience-spa-ssrf-concurrency-5-gaps.md, docs/tech-lead-plan-system-resilience-5-gaps.md, docs/requirements/architect-system-resilience-spa-ssrf-concurrency-5-gaps.out.md, docs/results/architect-system-resilience-spa-ssrf-concurrency-5-gaps.out.arch.md）
- **管理控制台 CSP 加固**：为 Admin 控制台 JS 应用 CSP 缩小 XSS 面。（来源：docs/results/expansion-novel-v3-identity-system-quality.out.arch.md）
- **Admin/Login SPA Bearer 令牌存储安全审计**：移除易受 XSS 攻击的存储方式（如 localStorage）。（来源：docs/tech-lead-plan-system-resilience-5-gaps.md）
- **安全响应头/时序加固批次**：send-code no-store、SecurityHeaders 默认开启、SPA CSP+nonce、KDF 时序不匹配、联邦 SSRF connect-time 复检。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **限流覆盖完备化**：为 DCR 注册、Admin API、/.well-known/*、/me/*、/userinfo、/end_session 接入统一限流策略并合并 admin 限流域。（来源：docs/architect-analysis-v6-five-directions.md, docs/tech-lead-analysis/implementation-plan-five-directions.md, docs/requirements/architect-expansion-novel-5-directions-v6-code-scan.out.md, docs/results/architect-fresh-scan-5-directions.out.arch.md, docs/results/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.arch.md）
- **按已认证主体（per-subject）限流维度**：新增 KeyBySubject 限流键，防御跨 IP 撞库/暴力破解。（来源：docs/architect-analysis-v6-five-directions.md, docs/ROADMAP.md, docs/results/architect-fresh-scan-5-directions.out.arch.md）
- **认证后按客户端（per-client）限流**：在 client_id 认证后而非可伪造预认证阶段限流，覆盖 /register、/token、/introspect、/revoke、/par、/userinfo。（来源：docs/requirements/expansion-runtime-infrastructure-analysis.out.md, docs/results/expansion-runtime-infrastructure-analysis.out.arch.md, docs/requirements/expansion-strategic-gaps-2026-07-11.out.md）
- **管理端可配置按客户端限流/API 用量配额策略**：ClientRateLimitPolicy/ClientQuotaPolicy 数据模型与管理 API，strict/warn 模式，X-RateLimit-* 响应头。（来源：docs/requirements/expansion-strategic-gaps-2026-07-11.out.md, docs/results/expansion-strategic-gaps-2026-07-11.out.arch.md, docs/results/architect-global-scan-novel-ops-biz-gaps.out.arch.md, docs/results/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.arch.md）
- **MemoryLimiter 自我 DoS 放大修复**：全 map O(N) 剪枝改为后台协程/分片锁异步剪枝。（来源：docs/architecture/analysis-detection-response-gap.md, docs/ROADMAP.md, docs/requirements/expansion-directions-analysis.out.md, docs/requirements/senior-architect-expansion-v6-true-gaps-2026-07-11.out.md, docs/results/senior-architect-expansion-v6-true-gaps-2026-07-11.out.arch.md）
- **多维协调限流与滥用检测**：跨 IP/ClientID/UserID/Endpoint/GrantType 协同判定预定义攻击模式，Count-Min Sketch 近似计数。（来源：docs/requirements/expansion-directions-v11-analysis.out.md, docs/results/expansion-directions-v11-analysis.out.arch.md）
- **可配置限流算法策略层**：声明式算法选择（token_bucket/fixed_window/leaky_bucket/concurrency），新增漏桶与并发数限流器，支持热重载策略存储。（来源：docs/requirements/expansion-production-deployment-gaps.out.md, docs/results/expansion-production-deployment-gaps.out.arch.md）
- **设备码端点限流与轮询滥用检测**：per-IP/per-client 双维度限流 + DeviceCodeAbuseDetector 滑动窗口轮询滥用检测。（来源：docs/requirements/deep-read-production-hardening-2026-07-11.out.md, docs/results/deep-read-production-hardening-2026-07-11.out.arch.md）
- **user_code 碰撞概率安全文档化**：形式化计算8字符 user_code 碰撞概率并声明安全保证。（来源：docs/results/deep-read-production-hardening-2026-07-11.out.arch.md）
- **通知限流/风暴抑制**：按用户/租户限制通知频率，紧急通知豁免，同类通知窗口内合并。（来源：docs/requirements/global-architecture-scan-four-production-blindspots-2026-07-11.out.md, docs/results/global-architecture-scan-four-production-blindspots-2026-07-11.out.arch.md, docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.review.out.arch.md）
- **撤销事件风暴抑制/聚合**：批量撤销场景合并为聚合通知。（来源：docs/results/architect-deep-code-scan-5-undiscovered-gaps.out.arch.md）
- **Active ITDR 扩展-管理员通知响应动作**：结构化审计事件+可选 webhook。（来源：docs/feature-spec-active-itdr-detection-response.md）
- **Active ITDR 扩展-重新认证挑战响应动作**：要求下次访问以指定方式（FIDO2/TOTP）重新认证。（来源：docs/feature-spec-active-itdr-detection-response.md）
- **Active ITDR 扩展-响应动作限速**：按 (主体,威胁类型,动作) 维度限速防止响应风暴。（来源：docs/feature-spec-active-itdr-detection-response.md, docs/results/expansion-directions-analysis.out.arch.md）
- **Active ITDR 扩展-跨副本响应协调**：复用 cluster.Bus 广播，可能新增 KindSessionPolicyChange。（来源：docs/feature-spec-active-itdr-detection-response.md）
- **条件访问 ThreatType 策略条件扩展**：基于近期威胁标签的自动拒绝/要求 MFA。（来源：docs/architecture/analysis-detection-response-gap.md, docs/feature-spec-active-itdr-detection-response.md, docs/results/expansion-directions-analysis-v6.out.arch.md）
- **默认开箱即用威胁响应策略集**。（来源：docs/feature-spec-active-itdr-detection-response.md）
- **统一检测管道抽象（DetectionPipeline）**：多检测器共享工作队列/工作池。（来源：docs/feature-spec-active-itdr-detection-response.md）
- **事件相关性引擎与规则 DSL**：滑动窗口关联规则合成高级安全事件，含防循环保护。（来源：docs/tech-lead-analysis-post-protocol-layer.md）
- **内置关联规则与自动化响应**：暴力破解/撞库/令牌轮换异常规则+响应执行器。（来源：docs/tech-lead-analysis-post-protocol-layer.md）
- **关联规则管理 API**：启用/禁用/优先级/干运行测试。（来源：docs/tech-lead-analysis-post-protocol-layer.md）
- **自动化事件触发响应动作**：扩展 threataction 动作注册表，新增事件到动作映射。（来源：docs/agent-os/architect-analysis/expansion-post-protocol-layer-architecture-review.md）
- **一键安全事件响应工作流**：安全事件到响应动作映射，带确认与进度跟踪。（来源：docs/tech-lead-analysis-peer-review-corrections.md, docs/requirements/expansion-ciam-identity-horizon.out.md）
- **客户端级信任评分**：ClientTrustStore SPI + ClientActivity/ClientAnomaly，行为基线+信任分数，含冷启动默认值与变化速率限制。（来源：docs/requirements/architect-deep-code-scan-5-undiscovered-gaps.out.md, docs/requirements/architect-expansion-novel-5-directions-2026-07-11.out.md, docs/requirements/architect-gap-analysis-2026-07-11.out.md, docs/results/architect-deep-code-scan-5-undiscovered-gaps.out.arch.md, docs/results/architect-expansion-novel-5-directions-2026-07-11.out.arch.md）
- **客户端行为基线异常检测器（ClientBehaviorDetector）**：联动信任分数触发 Step-up/缩短TTL/告警/暂停。（来源：docs/results/architect-expansion-novel-5-directions-2026-07-11.out.arch.md）
- **客户端信任评分变更 Webhook 告警**。（来源：docs/results/architect-deep-code-scan-5-undiscovered-gaps.out.arch.md）
- **统一信任评估引擎**：domains/trust/ 融合会话信任分、异常检测、条件访问、风险评分、IP失败计数为单一信任分数。（来源：docs/results/architect-deep-code-scan-5-undiscovered-gaps.out.arch.md）
- **身份健康评分**：融合 anomaly/tokenanomaly/threataction 计算 0-100 分数。（来源：docs/results/architect-expansion-analysis.out.arch.md, docs/requirements/expansion-ciam-identity-horizon.out.md）
- **租户安全评分引擎**：MFA采用率/异常覆盖率/认证方式多样性/API密钥轮换构成的 0-100 综合评分。（来源：docs/tech-lead-analysis-peer-review-corrections.md）
- **权限提升路径图分析**：用户-组-角色-权限建模为图，路径查找算法。（来源：docs/results/architect-expansion-analysis.out.arch.md）
- **会话风险自适应生命周期**：扩展 SessionManager SPI（ReduceTTL/SetRiskLevel/MarkRequiresStepUp/ListByRiskLevel）+ SessionRiskListener 管道，运行时持续风险评估。（来源：docs/requirements/architect-global-scan-five-uncovered-high-value-directions-v2-2026-07-11.out.md, docs/results/architect-global-scan-five-uncovered-high-value-directions-v2-2026-07-11.out.arch.md, docs/requirements/senior-architect-fresh-scan-2026-07-11.out.md, docs/results/senior-architect-fresh-scan-2026-07-11.out.arch.md, docs/requirements/senior-architect-global-scan-5-uncovered-expansion-directions.out.md）
- **独立可插拔 RiskEvaluator 风险评估中间件**：与 SessionManager SPI 解耦，支持多后端，分阶段启用。（来源：docs/results/senior-architect-global-scan-5-uncovered-expansion-directions.out.arch.md）
- **原子化配额检查+会话创建**：消除 check-then-create 竞态窗口。（来源：docs/results/senior-architect-expansion-2026-07-11.out.arch.md）
- **跨区域会话配额全局视图**：多区域部署下基于 cluster.Bus 的全局会话视图。（来源：docs/results/senior-architect-expansion-2026-07-11.out.arch.md）
- **并发会话配额策略与 LRU 驱逐引擎**：全局/租户/用户三级 SessionPolicy，满足 NIST 800-63B/PCI DSS/SOC2。（来源：docs/feature-spec-architecture-synthesis-five-directions.md, docs/results/PEER_REVIEW_architect-expansion-novel-horizons-2026-07-11.out.arch.md）
- **登录渐进式挑战升级编排器（ChallengeOrchestrator）**：综合风险信号升级至 CAPTCHA/MFA Step-up/延迟/阻断。（来源：docs/requirements/expansion-secrets-slo-challenge-posture-billing.out.md, docs/results/expansion-secrets-slo-challenge-posture-billing.out.arch.md）
- **低速分布式扫描检测器（Low-and-Slow Scan Detection）**。（来源：docs/results/expansion-secrets-slo-challenge-posture-billing.out.arch.md）
- **联邦跨实例威胁情报共享**：经 CAEP 事件跨实例发布/订阅威胁指标，含数据共享协议模板与跨区域加密。（来源：docs/tech-lead/expansion-five-directions-v2-peer-review-implementation.md, docs/requirements/expansion-directions-v12-analysis.out.md）
- **威胁指标撤回机制**：经 CAEP SET 事件撤回已发布威胁指标，含防循环保护。（来源：docs/tech-lead/expansion-five-directions-v2-peer-review-implementation.md）
- **自适应安全闭环策略引擎**：UserRiskProfile+AdaptivePolicyEngine+效果分析反馈环，分阶段上线，GDPR TTL/导出/一键关闭。（来源：docs/requirements/expansion-directions-v13-analysis.out.md, docs/results/expansion-directions-v13-analysis.out.arch.md）
- **影子模式自适应风险引擎**：初期非阻塞运行。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **通用 Bulkhead 并发限制库**：附 Prometheus 指标。（来源：docs/tech-lead-expansion-analysis.md）
- **通用熔断器库**：三态状态机+滑动窗口失败率。（来源：docs/tech-lead-expansion-analysis.md）
- **外部依赖弹性包装**：对 LDAP/SAML/OIDC联邦/CAEP/KMS/ext_authz/HIBP 应用舱壁+熔断器。（来源：docs/tech-lead-expansion-analysis.md）
- **弹性-降级框架集成**：熔断触发自动切换降级模式，管理端状态 API，热重载配置。（来源：docs/tech-lead-expansion-analysis.md）
- **移动端应用证明校验**：iOS App Attestation/Android Play Integrity 绑定 OAuth 客户端。（来源：docs/tech-lead/expansion-analysis-2026-07-11.md）
- **凭据健康扫描引擎**：密码/MFA/客户端密钥/API密钥周期扫描。（来源：docs/tech-lead-expansion-analysis.md）
- **HIBP与客户端密钥轮换健康检查批量集成**。（来源：docs/tech-lead-expansion-analysis.md）
- **自动化凭据整改策略引擎**：条件-动作策略，登录时评估不阻塞正常登录。（来源：docs/tech-lead-expansion-analysis.md）
- **中继攻击防护**：跨设备认证挑战绑定 IP/设备指纹+地理异常检测。（来源：docs/agent-os/architect-analysis/expansion-post-protocol-layer-architecture-review.md）
- **RFC 9728 兼容 MCP 401 挑战响应**：含 resource_metadata 的 WWW-Authenticate。（来源：docs/superpowers/plans/2026-06-29-sso-mcp.md）
- **Streamable HTTP 跨域/DNS重绑定加固（延后）**：面向浏览器暴露场景，当前延后。（来源：docs/superpowers/plans/2026-06-29-sso-mcp.md）
- **MCP 工具调用人工审批介入流程**：高风险操作前人工批准。（来源：docs/requirements/architect-frontier-identity-paradigms-platform-resilience-2026-07-11.out.md）
- **服务凭据委托而非令牌透传**：受限服务令牌认证，避免 confused-deputy。（来源：docs/superpowers/specs/2026-06-29-sso-mcp-design.md）
- **Webhook HMAC 载荷签名**：来源、完整性、防重放。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **内置可信代理支持完善**：统一 WithTrustedProxies(CIDR,hops)，替代对首跳的无条件信任。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md, docs/ROADMAP.md）
- **DoS/健壮性加固批次**。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **威胁模型文档与协议 Fuzz 测试套件**：FSM 多步骤模糊测试+不变量断言库+并发注入钩子。（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md, docs/architecture/architect-analysis-expansion-five-directions.md, docs/results/architect-expansion-five-directions-2026-07-11.out.arch.md）
- **恒定时间比较审计测试套件**：TestConstantTime 系统性验证所有安全敏感比较均使用 subtle.ConstantTimeCompare。（来源：docs/requirements/senior-architect-5-gaps-2026-07-11.out.md）
- **会话信任评分接入 Session Hub**：Session Hub Coordinator 暴露聚合的每会话信任分数，来源于 geo/IP信誉/行为/设备姿态等多个 shared/trust 评分器，评分器出错时 fail-open 取底值。（来源：docs/tech-lead-analysis/analysis.md）
- **令牌水印**：在颁发的令牌中嵌入可追溯水印，辅助检测和追踪泄露或被滥用的凭据。（来源：docs/requirements/global-architecture-scan-five-uncovered-high-value-directions-2026-07-11.out.md）
- **HTTP 方法白名单中间件**：新增统一的 MethodGuard 集中式中间件限制各路径允许的 HTTP 方法，替代目前仅 SAML handler 分散的 405 检查。（来源：docs/requirements/senior-architect-5-gaps-2026-07-11.out.md, docs/results/senior-architect-5-gaps-2026-07-11.out.arch.md）
- **严格 Content-Type 校验**：新增 ContentTypeGuard 严格拒绝非预期 Content-Type（如 text/plain、application/xml），替代默认按 JSON 解码。（来源：docs/requirements/senior-architect-5-gaps-2026-07-11.out.md, docs/results/senior-architect-5-gaps-2026-07-11.out.arch.md）
- **UTF-7 Content-Type 编码混淆防护**：JSON 解码路径未防范 charset=utf-7 参数，属于 OWASP 记载的编码混淆攻击向量。（来源：docs/requirements/senior-architect-5-gaps-2026-07-11.out.md）
- **重复参数/参数污染防护**：新增 ParamSanitizer 检测并拒绝 OAuth 请求绑定层的重复参数或参数污染。（来源：docs/requirements/senior-architect-5-gaps-2026-07-11.out.md, docs/results/senior-architect-5-gaps-2026-07-11.out.arch.md）
- **SMS OTP 生产级加固**：补齐 SIM Swap 检测、10DLC 合规与按租户成本/配额控制等生产级特性。（来源：docs/requirements/Senior-Architect-Expansion-Directions-2026-07-11.out.md）
- **OAuth 授权范围漂移检测**：检测客户端本次请求的 scope 与此前已同意 scope 之间的漂移。（来源：docs/requirements/senior-architect-expansion-v5-post-scan.out.md）
- **内存存储容量管理（MaxEntries + Reaper）**：为 MemorySessionManager、MemoryAuthCodeStore 添加容量上限与周期性清理协程，与现有 MemoryPARStore 模式对齐，防止无界增长/OOM/DoS。（来源：docs/results/senior-architect-5-gaps-2026-07-11.out.arch.md）
- **身份感知网络策略**：新增独立 IdentitySelector 模型，提供 K8s NetworkPolicy、AWS Security Group、Envoy ExtAuthz 三种适配器，实现基于身份而非仅 CIDR 的网络策略。（来源：docs/results/senior-architect-expansion-v7-true-gaps-2026-07-11.out.arch.md）
- **跨实例通信弹性与安全防护**：为实例间 HTTPS 通信引入超时、并发舱壁隔离、mTLS/签名 JWKS 验证防 DNS 欺骗，以及最大桥接跳数循环检测。（来源：docs/results/senior-architect-global-scan-5-uncovered-expansion-directions.out.arch.md）
- **ML 驱动的异常检测特征管线**：复用现有 IPFailureCounter 作为首选特征来源，经 anomaly.Runner 异步管线持续积累特征数据，用于训练/驱动机器学习异常检测模型。（来源：docs/requirements/expansion-next-wave-analysis.out.md, docs/requirements/tech-lead-analysis-expansion-next-wave.out.md）
- **扩展 ML 特征工程维度**：从单纯按 IP 计数扩展到 client_id+IP 组合、滑动时间窗统计、跨 IP 的 User-Agent 指纹关联。（来源：docs/results/expansion-next-wave-analysis.out.arch.md）
- **异常检测管理控制台仪表盘与查询 API**：可视化面板与查询接口展示高风险 IP 排名等，替代目前只能通过审计事件/指标观测。（来源：docs/results/expansion-next-wave-analysis.out.arch.md）
- **异常检测误报反馈闭环**：管理端 UI 工作流用于审阅被标记流量、标记为误报，并将该信号反哺检测模型。（来源：docs/results/expansion-next-wave-analysis.out.arch.md）
- **异常检测到决策闭环**：将 IPFailureCounter 输出接入 RiskScorer，使检测到的异常能同步触发 Step-up MFA 挑战，从仅观测升级为影响决策。（来源：docs/results/expansion-next-wave-analysis.out.arch.md）
- **异常检测事件桥接至 CAEP 风险信号**：扩展 CAEP 事件映射器将异常检测事件转译为 credential-compromise、session-revoked 等风险信号。（来源：docs/results/global-scan-expansion-directions.out.arch.md）
- **CAEP 事件映射防重入循环保护**：基于 TTL 的重入防护，防止新映射的 CAEP 事件再次触发自身形成无限广播循环。（来源：docs/results/global-scan-expansion-directions.out.arch.md）
- **跨客户端主体维度撤销/通知扇出**：新增 SubjectClientIndex.ListBySubject 能力，使威胁响应可覆盖被盗用主体关联的所有客户端。（来源：docs/results/global-scan-expansion-directions.out.arch.md）
- **休眠客户端自动禁用检测器**：新增 ClientDormancy 检测器，自动禁用超过可配置阈值处于闲置状态的客户端。（来源：docs/results/global-scan-expansion-directions.out.arch.md）
- **嘈杂邻居租户检测器**：复用 anomaly 异步检测管道识别令牌颁发或 API 调用出现异常峰值的租户。（来源：docs/results/expansion-five-uncovered-gaps.out.arch.md）
- **JTI 重放集中式熔断机制**：将 fail-open/fail-closed 决策从单次存储错误提升为集中熔断——连续 N 次存储失败后对所有重放敏感端点整体切换为 fail-closed。（来源：docs/results/architect-expansion-novel-5-directions-2026-07-11.out.arch.md）
- **发现服务 JWKS 缓存并发与内存 pruner 硬化**：拆分职责并优化高并发下的 O(N) pruner 清理性能，避免成为 DoS 放大器。（来源：docs/results/expansion-directions-v7-analysis.out.arch.md）
- **安全治理数据回流管道**：为当前"发出即遗忘"的安全治理信号构建回流管道，接入策略引擎形成检测-决策闭环。（来源：docs/results/expansion-directions-v9-analysis.out.arch.md）
- **ACR 与信任衰减双维度 Step-up 校验**：将认证强度（ACR）与行为信任分数（Trust Decay）作为两个正交维度共同评估，任一维度不满足即触发 Step-up。（来源：docs/results/expansion-edge-protocol-hardening-platformization.out.arch.md）
- **事件驱动持续授权扫描**：扩展 continuousverify.Agent 为 MultiScannerAgent，新增 TokenPolicyScanner 定期扫描过期/违规刷新令牌家族并触发策略变更事件，fail-open 不阻塞令牌颁发。（来源：docs/requirements/architect-scan-2026-07-11.out.md, docs/results/architect-scan-2026-07-11.out.arch.md）
- **HAProxy 边缘代理 XFF 加固与健康检查路由**：L7 边缘按 /readyz 健康检查负载均衡到各副本，并在每跳剥离/重设 X-Forwarded-* 头以确保仅信任首跳。（来源：docs/superpowers/plans/2026-06-26-baremetal-ha-data-layer.md）
- **配额滥用趋势/异常判别**：配额引擎在以 429 拒绝请求前先评估用量趋势与异常标记，区分合法流量增长与恶意/失陷客户端滥用。（来源：docs/results/expansion-novel-v4-privacy-dx-operations.out.arch.md）
- **登录风险特征聚合检测器**：新增 Detector 实现（如组合 IP 失败计数等信号）注册进现有 anomaly.Runner，在不修改 Runner 本身的前提下增强登录风险评分。（来源：docs/requirements/tech-lead-analysis-expansion-next-wave.out.md）


---
## 开发者体验与SDK

### 已实现功能

- **Root 文件数量上限门禁与根目录极简主义**：`python cli.py check-root`（checks/root_business_code.py、checks/root_files.py）强制非豁免根目录文件数 ≤15，只允许 README、构建配置、`cmd/` 等入口目录存在，业务逻辑一律移入领域包（来源：docs/adr/ADR-0001-directory-layout.md, docs/skills/project-reorganization/SKILL.md）
- **六边形 Deps 接口模式与 accessors.go 桥接**：跨层耦合通过下游包定义的 `Deps` 接口而非反向依赖根包；`accessors.go` 为 `*sso.Server` 提供最小化访问器以满足各领域包的 `Deps` 接口，`HandleX(deps, ctx)` 纯函数 + 根目录薄包装是标准提取模式（来源：docs/adr/ADR-0002-layering-and-import-boundaries.md, docs/skills/hexagonal-extraction.md, docs/developer-guide.md, docs/migration-roadmap.md）
- **SPI 化 + 强制真实实现的可插拔架构**：User/Client/Session/Token/Authenticator/TokenIssuer/RiskScorer/Bus 等每个可替换关注点都定义为接口（SPI）并至少配一个真实实现，代码库暴露 638 个 `WithXxx` 配置项与 100+ SPI 接口（来源：docs/adr/ADR-0004-domain-boundaries.md, docs/agent-os/architect-analysis/expansion-post-protocol-layer-architecture-review.md, docs/results/senior-architect-expansion-v7-true-gaps-2026-07-11.out.arch.md）
- **按后端并行包实现模式**：memory（必备）+ sqlite/etcd/redis/file/vaulttransit/kms 等后端各自作为独立自包含适配器包，而非同一文件内分支判断（来源：docs/adr/ADR-0004-domain-boundaries.md）
- **禁用 Mock、强制使用真实 Memory* 实现测试**：测试须使用真实 `MemoryProvider`/`MemorySink`/`memory.Registry` 而非手写 mock，确保测试反映真实的顺序与 fail-open/closed 路径；代码评审同样把该策略作为强制门禁（来源：docs/adr/ADR-0004-domain-boundaries.md, docs/review-checklist.md, docs/skills/code-review.md）
- **check-invariants CLI 领域边界校验**：`python cli.py check-invariants` 结合 review-checklist 人工评审，防止新关注点仅以 mock 实现或基础设施类型泄漏进领域包（来源：docs/adr/ADR-0004-domain-boundaries.md）
- **可维护性预算提交式 Go 测试门禁体系**：文件行数 ≤500（maintainability_budget_test.go）、函数长度 ≤50/圈复杂度 ≤15（maintainability_complexity_test.go）、导入边界（architecture_gate_test.go）、七层认知架构边界（architecture_layer_test.go）、目录扇出 ≤10 文件/≤15 子目录（directory_fanout_test.go）、目录深度 ≤3（maxdepth_test.go）均作为提交式 `go test` 而非仅 CI 脚本，随处可跑且不受 `cli.py harness` 脚手架重生成影响（来源：docs/adr/ADR-0005-size-and-complexity-budgets.md, docs/maintainability-gates.md, docs/agent-os/TODO.md, docs/review-checklist.md）
- **可维护性豁免清单收缩式棘轮机制**：每类门禁维护一份只能收缩的历史豁免清单，新增违规直接构建失败，已修复文件应从豁免清单移除，逼近零豁免；无法拆分的文件（如 sso.go）作为最后手段才加入豁免（来源：docs/maintainability-gates.md, docs/skills/refactor-large-file.md）
- **安全的 Post-edit 验证流程与 post-edit-check 技能**：`go build ./... && go vet ./...`、定向 maintainability/architecture 测试、`cli.py check-root|complexity|architecture` 等安全命令，以及 `python skills/post-edit-check/run.py`（跑 `make check-quick`）在每次 Go 文件修改后立即执行，避免误触发脚手架重生成（来源：docs/adr/ADR-0005-size-and-complexity-budgets.md, docs/skills/post-edit-check/SKILL.md）
- **DIRECTORY_MAP.md 包导航地图**：按认知层级分组呈现所有扁平包及依赖方向图，衔接物理目录树与逻辑分层模型（来源：docs/adr/ADR-0006-cognitive-architecture.md）
- **Re-export facade 包拆分标准手段**：以类型别名 + var/const 转发的“re-export facade”作为拆分超预算公共包为内聚子包的标准机制，且不改变对外导入路径（来源：docs/adr/ADR-0007-directory-fanout-and-the-monolith-exemption-class.md）
- **Proto 破坏性变更迁移指南强制要求**：任何破坏性 proto 变更必须在 proto 文件头注释中附带迁移路径，面向用户的 API 变更还需在 `docs/migrations/` 提供配套指南（来源：docs/adr/ADR-0008-proto-versioning.md）
- **buf 稳定性分级配置**：`buf.yaml`/`buf.gen.yaml` 将 v1 包标记稳定、v2alpha/v2beta 标记不稳定，使 `buf breaking` 按层级施加不同兼容性规则（来源：docs/adr/ADR-0008-proto-versioning.md）
- **CI 层 buf breaking wire 兼容性检查**：既有 proto-breaking Make 目标在 CI 中对比 main 分支运行 `buf breaking`，检测任意版本层级的线上不兼容变更（来源：docs/adr/ADR-0008-proto-versioning.md）
- **结构性变更前强制编写 ADR**：任何改动 `.arch/rules.yaml` 规则、新增顶层目录或迁移包公开导入路径的变更，必须先写新 ADR（来源：docs/adr/README.md）
- **组合验收门禁体系（make harness/acceptance）**：单一验收门禁整合构建、vet、文件大小、架构、安全不变量与覆盖率检查，配套两条 CI workflow 与十一项自测保证门禁基础设施本身可靠（来源：docs/agent-os/TODO.md, docs/developer-guide.md）
- **工程 CLI 入口与 G1-G7 门禁体系（cli.py）**：`python cli.py`（经 Make 封装）提供 harness、check-filesize、complexity、architecture、check-root、skill 等子命令，是文件大小/复杂度/构建测试/架构/无 mock/安全不变量/根目录策略等 G1-G7 自动化门禁的统一入口（来源：docs/developer-guide.md）
- **拆分大文件重构技能（split-large-file）**：触发于 Go 文件超过或将超过 500 行，通过声明清单分析（`grep "^func \|^type \|^const \|^var "`）、拆分边界启发式（types.go/consts.go/helpers.go 或按域拆分）、同包拆分（Mode A）与跨包六边形提取（Mode B）两种模式、领域目标包映射表、引用/导入更新扫描及拆分后 `go build/vet/test -race` + `check-root` 全套验证完成拆分（来源：docs/skills/refactor-large-file.md, docs/skills/split-large-file/SKILL.md）
- **降低圈复杂度重构技能（refactor-high-complexity）**：触发于函数圈复杂度 >15、认知复杂度 >20、if 嵌套 >3 层或分支 >10 的 switch，提供守卫子句、子函数提取、策略表（`map[string]func`）替代大 switch、条件合并等模式，并通过 `python skills/refactor-high-complexity/run.py` 自动化执行、以 `gocyclo` + `make check-quick` + `make acceptance` 验证（来源：docs/skills/refactor-high-complexity.md, docs/skills/refactor-high-complexity/SKILL.md）
- **项目自动重组织技能（project-reorganization）**：`python skills/project-reorganization/run.py` 在根目录违规或 `check-root` 失败时触发，按分析→迁移（每批 ≤5 文件 `git mv`）→验证→报告四阶段执行，遵循 feature-first 分组、单入口点、禁用 `utils/`/`helper.go` 等反模式命名、迁移优先级映射表、受保护根文件清单及风险信号响应表（导入环、被 >10 包依赖等）（来源：docs/skills/project-reorganization/SKILL.md）
- **代码评审技能与检查清单**：评审要求可维护性门禁通过、`TestArchitecture_ImportBoundaries` 通过、真实 Memory* 实现代替 mock、无表情符号、注释解释 WHY 而非 WHAT、新错误码同步 `docs/error-codes.md`、端点变更同步 `docs/openapi.yaml`、遵循 Conventional Commits，并产出结构化通过项/问题/建议报告（来源：docs/review-checklist.md, docs/skills/code-review.md）
- **新增 Handler 标准化模式技能（add-new-handler）**：新增 Handler 存储须通过 `WithXxxStore(...)` functional option 暴露，保证存储实现可插拔（来源：docs/skills/add-new-handler/SKILL.md）
- **测试覆盖率报告（make coverage）**：生成代码库测试覆盖率报告（来源：docs/developer-guide.md）
- **Protobuf lint/codegen 流水线**：`make proto-lint`/`make proto-gen` 对 `.proto` 源文件进行 lint 与代码生成（来源：docs/developer-guide.md）
- **容器镜像构建目标（make docker）**：构建 SSO 服务器的部署用容器镜像（来源：docs/developer-guide.md）
- **灾备演练测试框架（DR drill harness）**：`test/dr/`（`package drtest`）以真实 Snapshotter/Pipeline/Replicator/Restorer（无 mock）驱动临时挂载点，验证完整性中止、恢复往返、密钥存活与审计链连续性不变量（来源：docs/dr-framework.md）
- **嵌入式管理员级 API 文档查看器**：只读 API 文档 UI 挂载于 `/api/v1/admin/docs`（配套 `/openapi.json`），经 `WithAPIDocsUI` 选择性开启，无 CDN 或第三方打包依赖（来源：docs/deferred-backlog.md, docs/feature-matrix.md）
- **消费者 SDK 生成器（TypeScript + Python，从 OpenAPI 生成）**：`cmd/gensdk` 从 `docs/openapi.yaml` 生成并提交单文件 TypeScript/Python 客户端，覆盖核心 OAuth2/OIDC、令牌生命周期与自助服务端点；Python 端零依赖仅用 stdlib `urllib.request` + `TypedDict`，方法名遵循 PEP 8 蛇形命名并保留 operationId 追溯；TypeScript 端方法名与 operationId 逐字对应、支持自动 Bearer 注入、可注入 `fetch` 实现、oneOf/anyOf 映射为联合类型；两语言共享同一 Go 定义的核心操作白名单，保证覆盖面不漂移（来源：docs/deferred-backlog.md, docs/sdks/python/README.md, docs/sdks/typescript/README.md）
- **开发者自助服务门户 SPA（DCR 自助注册与管理）**：挂载于 `/developer/`（经 `WithDeveloperPortalFS` 选择性开启）的单页应用，支持匿名第三方开发者通过 RFC 7591 DCR 自助注册客户端，并用返回的 `registration_access_token` 经 RFC 7592 管理（GET/PUT/DELETE）（来源：docs/deferred-backlog.md, docs/architecture-analysis-peer-review-response.md, docs/requirements/architect-expansion-novel-horizons-2026-07-11.out.md, docs/results/tech-lead-analysis-expansion-next-wave.out.arch.md, docs/results/PEER_REVIEW_architect-expansion-novel-horizons-2026-07-11.out.arch.md）
- **双二进制发布模式（sso-server + sso-ctl）**：运行时 `sso-server` 与离线运维工具箱 `sso-ctl`（audit-verify/import/migrate/snapshot/config validate/hash/version）作为两个独立二进制发布（来源：docs/deployment.md）
- **部署前配置校验 CLI（sso-ctl config validate）**：`sso-ctl config validate --file config.yaml` 无需启动服务器即可校验配置有效性（来源：docs/deployment.md）
- **下游服务客户端 SDK 多模式（remote/local/dev/bootstrap）**：`interfaces/ssoclient` 提供远程模式（本地缓存 JWKS 校验令牌，授权/审计走 gRPC）、本地嵌入、开发全通过及引导模式（来源：docs/deployment.md）
- **可嵌入 Go SDK 入口（sso.NewServer）**：`sso.NewServer(opts...).Handler()` 让 Go 应用直接在任意 `net/http` 监听器上嵌入 SSO 服务器（来源：docs/deployment.md, docs/README.md）
- **ssoclient 消费者集成包（含 RS 令牌校验库）**：专用 `ssoclient` 包支持消费应用集成运行中的 SSO 服务器；`interfaces/ssoclient/rs` 让下游资源服务器本地（JWKS）或远程（内省）校验访问令牌并验证 DPoP 证明，无需重新实现 AS 的安全门禁（来源：docs/README.md, docs/error-codes.md）
- **sso-ctl 运维 CLI 工具**：专用命令行工具支撑审计链校验、代码生成等管理运维任务（来源：docs/README.md）
- **端到端快速上手与多场景示例项目**：单条 `go run` 演示嵌入→PKCE 登录→令牌交换→userinfo→本地 JWKS 验证全流程；另有覆盖全部客户端认证方式的示例与 remote-app/embedded-app/appcore 集成模式示例（来源：docs/README.md）
- **OpenAPI 3 HTTP 接口契约文档**：完整 HTTP API 表面以 OpenAPI 3 规范文档化（来源：docs/README.md, docs/openapi.yaml）
- **架构决策记录系列（ADR series）**：从初始目录布局到认知架构的系列 ADR 文档化架构决策（来源：docs/README.md, docs/adr/README.md）
- **功能规格说明模板（feature-spec template）**：标准化 Markdown 模板（目标/模块分类/验收标准/文件清单/边界/依赖）供 Architect Agent 向 Implement/Reviewer Agent 交接功能规格（来源：docs/templates/feature-spec.md, docs/README.md）
- **发布流程规范**：发布分支工作流（`release/vX.Y.Z`）、变更日志驱动的发布说明整理、`make ci`/`harness`/`diagnose`/`coverage` 发布前验证，以及发布后核实 GitHub release、更新下游 SDK/文档并公告的完整流程（来源：docs/RELEASE.md）
- **CI 强制执行的开发者安全检查清单**：no-store 头、bearer challenge、oracle-leak 规避、审计元数据模式、错误码文档化、架构门禁、文件/函数大小限制等提交前检查清单，部分由 `make check-invariants`/`make ci` 自动强制（来源：docs/SECURITY.md, docs/security-policy.md）
- **CI 供应链完整性检查（go mod verify + govulncheck）**：CI 对已锁定的 `go.sum` 运行 `go mod verify` 做模块完整性校验，独立的安全扫描 workflow 定期运行 `govulncheck`（来源：docs/SECURITY.md）
- **WASM 模块构造期 ABI 校验**：`wasmauthz.New` 在实例化前一次性编译 WASM 模块并检查导出表，确认 alloc/authorize/dealloc 存在且签名/内存导出正确，非合规模块启动即失败而非首次调用才失败（来源：docs/wasmauthz.md）
- **自动化 OIDC 一致性测试套件（docker-compose）**：基于 docker-compose 的一致性套件（`make oidc-conformance-basic/full`）及本地 OIDC playground 支持手动探索测试（来源：docs/sso/oidc-conformance.md）
- **四个内嵌产品级 SPA（登录/管理/门户/开发者）**：已交付 Hosted Login、Admin Console、Developer Portal、User Portal 四个经 `embed.FS` 内嵌的单页应用（来源：docs/requirements/expansion-directions-analysis.out.md, docs/results/expansion-gaps-analysis-2026-07-11.out.arch.md）
- **配置 JSON Schema 生成与 CLI 校验（含启动时告警）**：`sso-ctl config schema`/`config validate-schema` 从 Config 结构体反射生成并校验 JSON Schema；每次服务器启动都对完整合并后的配置文档重跑校验器并打印警告（不阻断启动）（来源：docs/config-reference.md, docs/results/senior-architect-expansion-v3-identity-system-quality.out.arch.md）
- **权限后端一致性测试套件（permissionstest.ConformanceSuite）**：Factory+Run(t) 风格的一致性套件，验证任意 `permissions.Provider` 后端满足统一行为契约（来源：docs/requirements/expansion-platform-evolvability-meta-governance.out.md, AGENTS.md）
- **CI 全覆盖嵌套 Go 子模块构建与测试（ci-modules）**：`make ci` 的 `ci-modules` 目标已对 `kms/*`、`saml/`、`ldap/`、`kerberos/`、`radius/`、`extauthz/`、`redis/`、`kafka/`、`mqtt/` 等无 `go.work` 的嵌套模块执行构建与竞态测试（来源：AGENTS.md, docs/requirements/expansion-systemic-quality-horizon.out.arch.md）
- **i18n 基础设施（后端共享层）**：位于 shared 层、可被所有领域包复用的国际化资源包基础设施（来源：docs/results/global-architecture-scan-four-production-blindspots-2026-07-11.out.arch.md）
- **跨后端语义一致性测试套件（Memory+SQLite）**：`backendsemantics` 测试套件验证 AuthCode/RefreshToken/DeviceCode/JTI-PAR 等存储实现在 Memory 与 SQLite 后端间行为一致（暂未覆盖 Redis）（来源：docs/results/global-scan-five-directions.out.arch.md）
- **sso-ctl 代码生成器脚手架（含已知待修复 TODO）**：现有基于模板生成 Authenticator/Store 样板代码的生成器，含 31 项待修复 TODO（含哨兵错误类型签名问题）（来源：docs/results/global-scan-five-directions.out.arch.md, docs/feature-spec-architecture-analysis-five-verified-directions.md）
- **AI-SDLC 工程文档体系**：AGENTS.md/HARNESS.md/BOOTSTRAP.md/EVALUATION.md/CHECKS_REGISTRY.md 构成结构化文档集，为 AI 辅助开发规范质量门禁（来源：docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.review.out.arch.md）

### 提议中/未来方向功能

- **原生 iOS/Android/跨端移动 SDK 矩阵**：Swift（ASWebAuthenticationSession/SecKey Keychain）与 Kotlin（Chrome Custom Tabs/KeyStore/EncryptedSharedPreferences）原生 SDK，封装授权码+PKCE+DPoP 流程、安全令牌存储、并发安全自动刷新、离线刷新队列（BGTaskScheduler/WorkManager），并延展至 React Native/Flutter，配套 CI/发布流水线与安全审计（来源：docs/architect-analysis-five-verified-expansion-directions.md, docs/tech-lead-analysis/cross-validated-five-new-directions.md, docs/tech-lead/expansion-analysis-2026-07-11.md, docs/results/architect-next-five-horizons-2026-07-11.out.arch.md, docs/results/expansion-directions-v13-analysis.out.arch.md）
- **SPA 自动化端到端测试（Playwright）**：为登录/管理/门户/开发者四个 SPA（约 4800+ 行零测试 JS）引入 Playwright E2E 测试，覆盖登录、MFA、Admin CRUD 等核心路径，经 `make e2e` 集成（来源：docs/architect-analysis-system-resilience-spa-ssrf-concurrency-5-gaps.md, docs/tech-lead-plan-system-resilience-5-gaps.md, docs/requirements/architect-system-resilience-spa-ssrf-concurrency-5-gaps.out.md, docs/results/expansion-novel-v3-identity-system-quality.out.arch.md）
- **SPA 构建流水线（esbuild）**：为四个手写 JS SPA 引入 esbuild 打包/压缩/CSS 压缩/内容哈希文件名的构建管线，经 `make build-spa` 接入 `embed.FS`（来源：docs/architect-analysis-system-resilience-spa-ssrf-concurrency-5-gaps.md, docs/tech-lead-plan-system-resilience-5-gaps.md, docs/results/architect-system-resilience-spa-ssrf-concurrency-5-gaps.out.arch.md）
- **SPA 无障碍合规（WCAG 2.1 AA）**：为 SPA 增加 ARIA 属性、键盘导航与焦点管理，满足 WCAG 2.1 AA/Section 508/EN 301 549 采购要求；Admin Console 当前仅 1 处 a11y 属性（来源：docs/architect-analysis-system-resilience-spa-ssrf-concurrency-5-gaps.md, docs/requirements/architect-system-resilience-spa-ssrf-concurrency-5-gaps.out.md, docs/results/senior-architect-expansion-2026-07-11.out.arch.md, docs/results/expansion-novel-v3-identity-system-quality.out.arch.md）
- **SPA 国际化（i18n）支持**：扩展现有后端 i18n 基础设施到前端，为四个 SPA（当前硬编码 `lang="en"`）提供动态语言切换/翻译资源加载，如经 `i18nFSInjector` 中间件按 locale 注入字典（来源：docs/architect-analysis-system-resilience-spa-ssrf-concurrency-5-gaps.md, docs/requirements/expansion-directions-v8-analysis.out.md, docs/results/senior-architect-expansion-v5-post-scan.out.arch.md, docs/results/senior-architect-expansion-2026-07-11.out.arch.md）
- **SPA 前端工程治理（代码预算/模块化/共享组件库/quality.js）**：为前端 JS 引入类似后端的行数预算约束、将 1385 行的 `admin/app.js` 拆为按功能拆分的页面模块、构建 `admin/lib/` 共享组件库（路由/API客户端/事件流/表格/表单构建器），并新增 `_shared/quality.js` 统一注入错误捕获、RUM 与 CSP 违规上报（来源：docs/results/expansion-directions-v8-analysis.out.arch.md, docs/results/tech-lead-analysis-expansion-next-wave.out.arch.md, docs/requirements/senior-architect-expansion-2026-07-11.out.md）
- **开发者门户 API 密钥自助管理**：在现有开发者门户 SPA 基础上新增 `/me/api-keys` 端点及 UI，支持开发者自助创建、查看、轮换与吊销 API 密钥，密钥值仅创建时展示一次（来源：docs/architecture-analysis-peer-review-response.md, docs/requirements/architect-expansion-novel-horizons-2026-07-11.out.md, docs/results/expansion-novel-v4-privacy-dx-operations.out.arch.md, docs/results/tech-lead-analysis-expansion-next-wave.out.arch.md, docs/results/expansion-next-wave-analysis.out.arch.md）
- **开发者门户使用分析仪表盘**：基于现有 `domains/tokenusage/` 数据，在开发者门户构建令牌/API 调用量可视化使用分析仪表盘（来源：docs/architecture-analysis-peer-review-response.md, docs/results/architect-expansion-analysis.out.arch.md, docs/results/expansion-novel-v4-privacy-dx-operations.out.arch.md）
- **开发者体验平台扩展（API 游乐场/Webhook 调试器/SDK 游乐场/应用健康监控）**：在现有轻量开发者门户与 SDK 生成能力基础上新增浏览器内 API 测试工具、SDK 交互式代码示例及应用健康监控（来源：docs/requirements/architect-expansion-analysis.out.md, docs/results/architect-expansion-analysis.out.arch.md, docs/requirements/expansion-directions-analysis.out.md）
- **Terraform Provider（SSO 资源基础设施即代码）**：基于 `terraform-plugin-framework` 的独立 Go Provider，管理客户端/租户/连接/权限策略等 SSO 资源，含敏感密钥写时返回处理、ETag 乐观并发与数据源支持（来源：docs/requirements/expansion-directions-analysis-v6.out.md, docs/results/expansion-directions-analysis.out.arch.md, docs/requirements/senior-architect-expansion-v6-true-gaps-2026-07-11.out.md, docs/results/senior-architect-expansion-v6-true-gaps-2026-07-11.out.arch.md）
- **GitOps 化配置管理（OAuth IaC + PR 差异预览）**：以版本控制的声明式方式管理 OAuth/OIDC 服务器配置（客户端/scope/策略），配合 GitHub/GitLab webhook 自动在 PR 上评论配置差异预览并在批准后应用（来源：docs/requirements/architect-global-scan-novel-ops-biz-gaps.out.md, docs/requirements/architect-next-five-horizons-2026-07-11.out.md, docs/tech-lead/expansion-analysis-2026-07-11.md）
- **属性基测试基础设施**：为 OAuth 参数绑定、签名验证、JWT `aud` 序列化等关键包引入 rapid/gopter 等属性基测试工具，捕获示例测试遗漏的边界缺陷（来源：docs/requirements/architect-gaps-analysis-2026-07-11.out.md, docs/results/architect-gaps-analysis-2026-07-11.out.arch.md）
- **变异测试基础设施**：引入变异测试工具链衡量并提升现有测试套件的缺陷检测能力，当前代码库完全缺失（来源：docs/requirements/architect-gaps-analysis-2026-07-11.out.md, docs/requirements/senior-architect-expansion-2026-07-11.out.md, docs/results/senior-architect-expansion-2026-07-11.out.arch.md）
- **模糊测试扩展（JWT/JWS/aud 解析 + 协议状态机）**：为手写 JWKS/JWS 解析、`aud` 字符串-数组解码、表单绑定、联邦信任链解析新增 go fuzz 目标；另建自定义状态机 fuzzer 捕获 Revoke 后 Refresh 复用、双重提交授权码等跨步骤状态不一致场景（来源：docs/ROADMAP.md, docs/requirements/architect-expansion-five-directions-2026-07-11.out.md, docs/results/architect-scan-deep-gaps-2026-07-11.out.arch.md）
- **组合式功能交互测试框架**：扩展现有 `test/testkit` 基础设施，验证功能/配置开关组合间的正确交互，当前完全缺失（来源：docs/requirements/expansion-platform-evolvability-meta-governance.out.md）
- **Store SPI 跨后端一致性测试标准化（含 Redis/Postgres）**：将 `permissionstest.ConformanceSuite` 模式泛化为可应用于所有 Store SPI 的 `ConformanceSuite[T]`，覆盖 memory/sqlite/redis/postgres/etcd 等后端在原子性（`DELETE RETURNING` vs `GETDEL`）等语义上的一致性，并将现有仅覆盖 Memory+SQLite 的 backendsemantics 套件扩展到 Redis（来源：docs/requirements/expansion-platform-evolvability-meta-governance.out.md, docs/requirements/expansion-directions-v11-analysis.out.md, docs/results/expansion-directions-v11-analysis.out.arch.md, docs/results/global-scan-five-directions.out.arch.md）
- **覆盖率门禁阈值提升**：将 `engineering.yaml` 中 core/oauth/oidc/security 等偏低的覆盖率目标分阶段提升（如 security ≥80%、oauth ≥75%、oidc ≥65%），以增强安全敏感代码的回归检测能力（来源：docs/requirements/architect-gaps-analysis-2026-07-11.out.md, docs/results/architect-gaps-analysis-2026-07-11.out.arch.md）
- **覆盖率地板门禁（roadmap）**：规划中的 `tools/covercheck` 加只能上升的 `coverage_budget.json` 定义各包覆盖率下限，作为 CI 步骤而非纯 `go test`（来源：docs/maintainability-gates.md）
- **热路径延迟预算门禁（roadmap）**：规划中针对 `/auth/login`、`/token` 等热路径的内存态延迟测试（p95 灾难性上限）及 CI 中 benchstat 基线回归检测（来源：docs/maintainability-gates.md）
- **CI 阻断式性能回归门禁**：将现有需手动触发的 `workflow_dispatch` 基准门禁转换为 CI 阻断式性能回归检查（来源：docs/requirements/expansion-systemic-quality-horizon.out.md）
- **全量 OAuth 授权类型负载测试套件**：将负载测试从仅覆盖 `client_credentials` 扩展到所有 OAuth/OIDC 授权类型（来源：docs/requirements/expansion-systemic-quality-horizon.out.md）
- **基准测试/性能剖析/负载测试基础设施**：新增 Go benchmark、pprof 接线与 k6/vegeta 负载测试脚本，验证吞吐量声明并防范分配/锁竞争回归（来源：docs/ROADMAP.md）
- **导出的 ssotest 测试夹具包**：将真实签发者+JWKS+令牌铸造测试工具（`ssotest.NewServer`）导出为可供下游集成测试导入的包，而非锁在 test-only 包中（来源：docs/ROADMAP.md）
- **配置校验 CI 门禁模式（--ci/--strict + 能力注册表）**：新增 `sso-ctl config validate --ci --strict` 命令与复用 `buildinfo` 的能力注册表，把配置校验从运行时 CLI 检查升级为部署前非零退出码的 CI 门禁，静态校验配置组合合法性（来源：docs/results/architect-fresh-scan-5-directions.out.arch.md, docs/results/architect-gaps-analysis-2026-07-11.out.arch.md, docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.review.out.arch.md, docs/results/architect-expansion-novel-5-directions-v6-code-scan.out.arch.md）
- **配置文档缺口补全（Postgres 后端矩阵/刷新宽限期等）**：为 `config-reference.md` 补充已实现但未文档化的 Postgres 后端配置矩阵，以及既有但未暴露的刷新令牌轮换宽限窗口（`sso.security.refresh_grace`）配置项（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md, docs/architecture/analysis-detection-response-gap.md, docs/results/expansion-directions-analysis-v6.out.arch.md）
- **CI 供应链/安全扫描扩展（SCA/SAST/镜像扫描）**：CI 增加 govulncheck、CodeQL/gosec 静态分析及 Trivy/Grype 镜像扫描，目前均未运行（来源：docs/ROADMAP.md）
- **嵌套子模块 Dependabot 覆盖**：为 saml/kms/*/redis/ldap/kerberos/radius/extauthz 等十个承载最重第三方 CVE 面的嵌套模块新增 Dependabot 目录条目，实现自动补丁 PR（来源：docs/ROADMAP.md, docs/results/architect-expansion-novel-5-directions-2026-07-11.out.arch.md）
- **代码生成器模板 TODO 清理与正确性修复（sso-ctl generate）**：修复生成的 Authenticator/Store/Handler/Grant 模板返回通用 `fmt.Errorf("not implemented")` 而非正确哨兵错误的问题，补全 Handler 的 Deps 接口与被注释掉的 Store CRUD/Grant 错误码，解决 31 项待修复 TODO 并加入生成代码编译检查（来源：docs/feature-spec-architecture-analysis-five-verified-directions.md, docs/requirements/architect-fresh-scan-2026-07-11.out.md, docs/results/architect-fresh-scan-2026-07-11.out.arch.md, docs/results/global-scan-five-directions.out.arch.md, docs/requirements/global-scan-five-directions.out.md）
- **文档漂移检测 CI 检查器**：新增 CI 检查检测代码与文档间的漂移，此前测量发现文档化配置键与实际配置键存在 22 倍差距（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **安全文档同步校验 CI**：新增 `make check-docs` 目标或脚本，在安全政策文档与安全架构参考文档失步时使 CI 失败（来源：docs/feature-spec-security-docs.md）
- **RS SDK 混合本地+内省令牌校验模式**：为资源服务器 SDK 新增本地校验（无撤销感知）与远程内省（撤销感知）之外的混合验证模式（含 `TokenValidationCache` SPI），并配套 `StatusListVerifier` 供 RS 缓存校验签名状态列表（来源：docs/requirements/deep-read-production-hardening-2026-07-11.out.md, docs/results/expansion-edge-cases-2026-07-11.out.arch.md, docs/requirements/architect-system-resilience-spa-ssrf-concurrency-5-gaps.out.md）
- **SDK 全量接口覆盖扩展（Admin CRUD/SCIM/CAEP/联邦等）**：将生成器的核心操作白名单机械扩展到约 150 条 Admin CRUD 路由及 SCIM、CAEP/SSF、OpenID Federation、Webhook、合规导出/擦除等全量操作（来源：docs/sdks/typescript/README.md, docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **SDK 发布自动化流水线（npm/PyPI）**：新增将 SDK 发布至 npm/PyPI 的 CI job，目前 `docs/sdks/` 仅有静态文档，无发布自动化（来源：docs/requirements/senior-architect-expansion-2026-07-11.out.md, docs/results/senior-architect-expansion-2026-07-11.out.arch.md）
- **SDK/API 破坏性变更检测与兼容性 CI 门禁**：新增 `make ci-sdks`/`tools/openapidiff` 等目标，检测新增必填字段/响应类型/状态码等破坏性 OpenAPI 变更并自动构建测试各语言 SDK，失败即阻断合并；同时自动生成变更日志（来源：docs/results/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.arch.md, docs/results/architect-global-scan-novel-ops-biz-gaps.out.arch.md, docs/requirements/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.md）
- **v2 消费者导入路径迁移 codemod**：随 v2 标签发布一次性 sed 脚本，自动改写下游消费者的 v1 导入路径为新的 v2 分层路径（来源：docs/architecture/V2-MIGRATION.md）
- **可嵌入认证 Web Component 组件生态**：提供框架无关的 `<sso-login>` Web Component（及 React 包装），自动处理 PKCE OAuth 流程，通过 CDN/npm（`@snaplink/auth-widget`）分发并以 SRI 哈希保障供应链安全，复用现有 `/auth/login` JSON 契约（来源：docs/requirements/expansion-directions-v13-analysis.out.md, docs/results/expansion-directions-v13-analysis.out.arch.md）
- **集成市场/连接器目录与预构建连接器模板**：新增 `ApplicationTemplate` 接口与 YAML 模板（`config/app-templates/`）预设 grant_types/redirect_uris/scopes 并复用现有 DCR 流程，配合发现第三方集成的市场/目录页面及常见 IdP/SaaS 预构建连接器（来源：docs/requirements/senior-architect-expansion-2026-07-11.out.md, docs/results/senior-architect-expansion-2026-07-11.out.arch.md）
- **第三方 API 网关适配器**：允许服务器 API 安全策略与外部 API 网关集成的适配层，如 Envoy ext-authz 网关适配器验证边缘处的 API 密钥（来源：docs/requirements/PEER_REVIEW_architect-expansion-novel-horizons-2026-07-11.out.md, docs/tech-lead-analysis-cross-verified-five-directions.md）
- **自然语言运维查询适配器（LLM）**：轻量 LLM 适配器，让运维人员用自然语言查询身份关系图谱与运维数据（来源：docs/requirements/PEER_REVIEW_architect-expansion-novel-horizons-2026-07-11.out.md）
- **sso-mcp 标准化 MCP 服务器**：新独立二进制 `cmd/sso-mcp`（嵌套模块）将只读身份/授权面暴露为 5 个 MCP 工具，供 AI agent 通过 gRPC Authorizer 消费，支持 Streamable HTTP（远程多 agent）与 stdio（本地可信子进程）双传输（来源：docs/superpowers/plans/2026-06-29-sso-mcp.md, docs/superpowers/specs/2026-06-29-sso-mcp-design.md）
- **MCP 工具注册表与 OpenAPI 规范自动同步**：将 MCP 工具注册表与 OpenAPI 端点规范自动同步，为 AI 辅助开发者提供支持（来源：docs/results/architect-expansion-analysis.out.arch.md）
- **集成事件目录与负载版本化**：定义 `EventManifest`（semver、JSON Schema、废弃/日落时间）与注册表，产出可浏览的 `/api/v1/events` 事件目录；同时对 webhook/审计事件负载引入版本化结构（`EventV1`/`EventV2`），支持按 `Accept-Version` 头转换或双发射迁移期兼容（来源：docs/requirements/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.md, docs/results/architect-global-scan-novel-ops-biz-gaps.out.arch.md, docs/results/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.arch.md）
- **集成一致性认证测试套件**：新增 `cmd/integration-cert`/`test/ssointegrator` 等可打包的一致性测试套件（授权码流程/client_credentials/刷新轮换/OIDC discovery），供第三方集成方在自有 CI 中运行认证（来源：docs/requirements/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.md, docs/results/architect-global-scan-novel-ops-biz-gaps.out.arch.md, docs/results/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.arch.md）
- **API 废弃策略框架**：通过 Go 结构体标签为端点附加 `DeprecatedAt`/`SunsetAt`/`MigrationGuide`/`NotifySubscribers` 等废弃元数据，形成端点生命周期治理契约（来源：docs/results/architect-global-scan-novel-ops-biz-gaps.out.arch.md）
- **跨环境身份数据同步 CLI 工具**：新增 `sso-ctl sync export/import`（含 HMAC 脱敏 pepper 管理），复用 Admin API JSON schema 在环境间同步租户/客户端/用户/策略；默认仅追加（`--sync-deletions=false`），全量同步删除需先 `--diff` 并显式确认，防止误删生产数据（来源：docs/requirements/expansion-five-uncovered-gaps.out.md, docs/results/expansion-five-uncovered-gaps.out.arch.md）
- **代码库导航与依赖关系可视化工具集**：AST 扫描生成接口-实现-依赖映射的包索引生成器（`make code-index`）、Mermaid/SVG 依赖图谱生成器（含层级违规高亮）、`sso-ctl pkg` 包导航 CLI、ctags/IDE 插件语义搜索、文档交叉引用索引生成器，以及依赖健康图谱（版本/漏洞/陈旧度），共同降低约 2241 个 Go 文件规模下的人工 grep 分析成本（来源：docs/tech-lead-analysis-meta-governance-v2.md, docs/results/architect-fresh-scan-five-directions-2026-07-11.out.arch.md, docs/requirements/global-architecture-scan-five-uncovered-high-value-directions-2026-07-11.out.md, docs/requirements/expansion-platform-evolvability-meta-governance.out.md）
- **变更影响分析与 PR 自动化工具**：`sso-ctl analyze-change` 结合包索引与调用图报告变更文件影响的其他包/测试/文档，配合 PR 影响范围自动评论机器人及 Dependabot PR 的依赖升级影响预览（自动跑一致性套件并评论结果）（来源：docs/tech-lead-analysis-meta-governance-v2.md）
- **开发者分级学习路径与 How-to 模板清单**：面向新开发者/agent 的分级（Level 1-3）入门指南，以及新增 OAuth 授权类型/存储后端/认证器的可勾选步骤检查清单，固化必要接线点（来源：docs/tech-lead-analysis-meta-governance-v2.md）
- **通知中心 UI**：供用户查看与管理其收到通知的 UI 界面（来源：docs/requirements/senior-architect-scan-v2-true-gaps-2026-07-11.review.out.md）
- **统一通知通道抽象与调度服务**：新增 `shared/notifications/spi/` 定义 Channel/Message/TemplateRenderer 接口取代硬编码通道选择；新建 `domains/notifications/` 调度器统一模板选择/多语言渲染/通道路由；新增 `/me/notification-preferences` 用户通道偏好端点及 SMS 通知通道（Twilio/AWS SNS/Azure ACS）集成（来源：docs/results/architect-expansion-2026-07-11.out.arch.md）
- **Webhook 传递调试器与传递日志存储**：开发者门户中提供实时 webhook 传递日志与重放查看（时间戳/HTTP 状态/请求响应头/重试次数），复用现有引擎的 DeadLetterStore/SubscriptionStore，并新增持久化存储记录成功传递尝试（当前仅存失败死信）（来源：docs/results/architect-expansion-analysis.out.arch.md）
- **浏览器内 API 游乐场与 SDK 交互式代码示例**：基于 OpenAPI 的浏览器内 API 测试工具（用登录用户自身权限而非管理凭据）与 TypeScript/Python 交互式 SDK 代码示例，自动注入用户租户凭证演示常见流程（来源：docs/results/architect-expansion-analysis.out.arch.md）
- **API 安全范围市场化（Scope Marketplace）**：以扩展现有开发者门户 SPA 的方式提供可插拔 widget 形态的 API scope 市场功能（来源：docs/results/architect-expansion-novel-horizons-2026-07-11.out.arch.md）
- **分面 Server 配置重构（ServerConfig）**：引入 `ServerConfig` 结构体及子配置分组（OAuthConfig/SecurityConfig/StorageConfig 等），经 `WithConfig(ServerConfig)` 注册替代当前 174 个扁平 `With*` 函数，旧 API 保留为薄包装保证向后兼容（来源：docs/results/expansion-directions-analysis.out.arch.md）
- **BFF 侧车参考实现（cmd/sso-bff）**：新增独立 Backend-for-Frontend 侧车模块参考实现，避免引入有状态会话架构破坏现有无状态水平扩展假设（来源：docs/results/expansion-directions-v7-analysis.out.arch.md）
- **配置字段完整性治理工具**：配置字段扫描器，覆盖文档完整性、模板生成与字段互斥校验，与既有配置版本/迁移治理分析正交互补（来源：docs/requirements/expansion-platform-evolvability-meta-governance.out.md）
- **Portal SPA 已授权应用面板**：在 Portal SPA 新增“已授权应用”面板，消费现有 `/consents/me` API 展示客户端授权列表及 scope，支持一键撤销（来源：docs/results/expansion-ciam-identity-horizon.out.arch.md）
- **可复用 SSE 客户端 JS 模块**：共享 `sse-client.js` 模块（连接/断开、退避重连、事件路由），供所有内嵌 SPA 而非仅 Admin Console 复用（来源：docs/results/expansion-next-wave-analysis.out.arch.md）
- **跨模块高风险路径集成测试覆盖**：新增覆盖 SAML→Token Exchange、LDAP→Auth Code 等跨协议路径的集成测试，弥补现有仅按模块划分测试的盲区（来源：docs/requirements/expansion-systemic-quality-horizon.out.md）
- **sso-ctl 批量导入器 Postgres 目标支持**：为 sso-ctl 批量用户导入工具（Auth0/Keycloak/CSV）及迁移工具新增 `--backend postgres`/`--dialect postgres|cockroach` 支持，使身份数据可直接迁入 HA Postgres 后端而无需经 SQLite 中转（来源：docs/superpowers/plans/2026-07-02-wave1-quick-wins.md, docs/superpowers/plans/2026-07-02-implementation-roadmap.md）
- **内置 SMTP 邮件发送器**：新增 `infrastructure/defaultimpl/emailsmtp` 叶子包实现异步 fire-and-forget 的模板化 SMTP 邮件发送，经新 `smtp:` 配置块配置，并规划支持隐式 TLS（465 端口）提交（来源：docs/superpowers/plans/2026-07-02-wave2-tranche1.md）
- **出站 HTTP 调用静态分析门禁**：新增自定义 `go/analysis` linter，标记 `shared/outbound` 包之外直接构造 `&http.Client{}` 的用法，把 SSRF 安全用法从文档约定升级为编译期门禁（来源：docs/requirements/architect-system-resilience-spa-ssrf-concurrency-5-gaps.out.md）
- **OIDC 一致性测试 CI 自动化集成**：将现有需手动浏览器操作的 `test/oidc-conformance/` docker-compose 一致性套件接入 CI 工作流/Makefile，覆盖 OIDC Core、FAPI 2.0、CIBA 等多配置矩阵测试（来源：docs/requirements/senior-architect-expansion-v6-true-gaps-2026-07-11.out.md, docs/results/senior-architect-expansion-v6-true-gaps-2026-07-11.out.arch.md）
- **sso-ctl tenants apply/validate 声明式租户配置 CLI**：新增 `sso-ctl tenants apply -f tenants.yaml`（支持 dry-run/自动批准）与 `sso-ctl tenants validate` 命令，配合密钥引用模型（vault/env/base64）实现租户规格的声明式协调与 CI 校验（来源：docs/tech-lead-analysis/analysis.md）


---
## 平台治理与元治理(AI-SDLC)

### 已实现功能
- **扁平化领域目录布局与组合根目录治理**：拒绝将扁平库目录（oauth/、oidc/、core/、security/、defaultimpl/ 等）强制retree为domains/application/infrastructure层级；根目录仅允许server composition/wiring文件（sso.go、server_*.go、accessors*.go、options*.go等），禁止业务逻辑或*_handler.go/*_service.go落地根目录（来源：docs/adr/ADR-0001-directory-layout.md, docs/developer-guide.md, docs/adr/README.md）。
- **物理分层架构与单向依赖强制门禁**：六/七层架构（shared→platform→domains→protocols→infrastructure→interfaces→composition，即handlers→oauth|oidc→security→core），由architecture_layer_test.go/architecture_gate_test.go（TestArchitecture_ImportBoundaries/LayerBoundaries）作为提交时门禁强制单向导入，禁止任何包导入cmd/（来源：docs/adr/ADR-0002-layering-and-import-boundaries.md, docs/adr/ADR-0006-cognitive-architecture.md, docs/architecture/DIRECTORY_MAP.md, docs/developer-guide.md, docs/results/senior-architect-expansion-v7-true-gaps-2026-07-11.out.arch.md）。
- **共享内核无扇入上限策略**：不对core（约219个导入方）、audit（约160个导入方）设扇入上限，将高扇入视为健康内聚而非god-object风险，由根目录扇出与体量/复杂度预算另行把控（来源：docs/adr/ADR-0002-layering-and-import-boundaries.md, docs/adr/ADR-0004-domain-boundaries.md, docs/adr/ADR-0005-size-and-complexity-budgets.md）。
- **协议扁平分组与门禁路径同步维护**：oauth/oidc/saml/scim保持稳定扁平公共导入路径而非嵌套protocols/目录；协议包重命名时必须原子更新architecture_gate_test.go中的字面量路径前缀，否则oauth↔oidc环检测会静默失效（来源：docs/adr/ADR-0003-protocol-grouping.md, docs/adr/README.md）。
- **SPI-per-concern与真实后端实现，禁止在已有Memory\*实现处使用mock**：每个横切关注点定义为接口，配套memory实现及可选sqlite/etcd/redis/postgres实现，测试必须使用真实MemoryProvider/MemorySink/memory.Registry（来源：docs/adr/ADR-0004-domain-boundaries.md, docs/adr/README.md, docs/skills/code-review.md）。
- **重/可选依赖通过独立go.mod嵌套模块隔离**：saml/、ldap/、kerberos/、radius/、extauthz/、redis/、kafka/、mqtt/、kms/{awskms,gcpkms,azurekeyvault,pkcs11}等14个模块各自独立go.mod，经make ci-modules验证依赖树（来源：docs/adr/ADR-0004-domain-boundaries.md, docs/SECURITY.md, AGENTS.md）。
- **文件/函数/复杂度预算门禁**：文件≤500行、函数≤50行、圈复杂度≤15、认知复杂度≤20，由maintainability_budget_test.go/maintainability_complexity_test.go等提交测试强制执行，并配合golangci-lint次级阈值（来源：docs/adr/ADR-0005-size-and-complexity-budgets.md, docs/developer-guide.md）。
- **维护性例外清单只缩不增的棘轮规则**：各预算门禁的历史违规豁免清单只能缩小，新增违规与"已达标却仍在清单"的陈旧豁免均会导致构建失败，经SEED_MAINTAINABILITY=1重新生成，make check-exemptions校验同步（来源：docs/adr/ADR-0005-size-and-complexity-budgets.md, docs/developer-guide.md）。
- **目录扇出预算门禁**：directory_fanout_test.go限制每目录≤10个非测试.go文件、≤15个子目录，并定义5类永久豁免（单体共享状态/二进制组合根/深度受限/内核高爆炸半径/安全时序关键），根目录另享15→20子目录的常设豁免（来源：docs/adr/ADR-0007-directory-fanout-and-the-monolith-exemption-class.md）。
- **层级归类的显式文档化决策**：对security→shared、audit→platform、geo/anomaly→platform/domains、根sso→interfaces、ssoclient→interfaces等歧义包给出明确层级判定，历史上游导入违规通过只缩不增的layerExemptions清单容忍（来源：docs/adr/ADR-0006-cognitive-architecture.md）。
- **四层Proto API版本分级模型**：采用Google AIP风格稳定性分级——v1（稳定长期）、v2alpha（预览，可自由破坏）、v2beta（近稳定，wire冻结，至多2个发布周期）、v2（稳定，v1获得6个月+弃用窗口），预览/近稳定包位于独立proto/*/v2alpha|v2beta/目录及匹配URL前缀（来源：docs/adr/ADR-0008-proto-versioning.md, docs/adr/README.md）。
- **Proto变更治理规则**：稳定v1字段移除须先reserved（名称+编号）满一个发布周期才能真正删除；字段类型变更须启用新字段号并将旧字段标记deprecated=true；所有废弃字段/消息/枚举/RPC须显式deprecated=true；每个.proto文件头须注明稳定性分级并引用版本ADR（来源：docs/adr/ADR-0008-proto-versioning.md）。
- **就地v1安全的分层目录迁移已执行**：约38个库包已物理迁移入6个分层目录且全部导入路径已重写，未提升模块路径，根目录子目录从60降至15、根目录.go文件从53降至4，全部门禁保持绿色（来源：docs/architecture/V2-MIGRATION.md）。
- **分层配置源解析与SIGHUP热重载**：配置按file<env(SSO_<SECTION>__<KEY>)<etcd<CLI优先级解析；cmd/sso-server支持SIGHUP重读配置并安全应用可热重载子集（限流策略重建、7个feature_gates双向实时切换），门禁检查在路由匹配层生效，被禁用路由与从未注册的路由字节级不可区分，无侧信道泄露（来源：docs/config-reference.md, docs/deployment.md, docs/deferred-backlog.md）。
- **按存储关注点独立可插拔后端选型矩阵**：identity、sessions、OAuth热存储（AuthCode/Device/Refresh/PAR）、CIBA、MFA、TOTP、WebAuthn、JTI replay、lockout、rate limiter、pairwise subjects、BCL索引、native SSO、self-service、tenants、audit、permissions、anomaly、签名密钥撤销/注册表、cluster bus、registry、netpolicy、bootstrap lock均各自通过独立backend key选择实现（来源：docs/config-reference.md, docs/deployment.md）。
- **统一Redis/Postgres共享后端配置**：单一redis:（single/sentinel/cluster模式）及postgres:（含dialect切换支持CockroachDB序列化重试）配置块分别fan-out到所有backend: redis/postgres的存储，随infrastructure/redis、infrastructure/postgres独立模块引入stock binary（来源：docs/config-reference.md, docs/deployment.md）。
- **HTTP/2服务端支持可配置化**：server.http2.enabled允许通过config.yaml按需开启/关闭服务端HTTP/2支持，默认关闭以适配反向代理场景（来源：docs/config-reference.md）。
- **跨副本配置漂移检测**：config_audit.drift.interval周期性广播配置摘要并跨副本比对，检出不一致时产生审计事件与指标，report-only不阻断（来源：docs/config-reference.md）。
- **跨副本协调事件总线**：platform/cluster提供etcd支持的pub/sub Bus，覆盖KindTokenRevoked/KindSigningKeyRotation/KindClientChange/KindAuthzPolicyChange/KindDiscoveryReload/KindTenantResidency/KindTenantSuspension等事件类型，免除跨副本DB往返（来源：docs/config-reference.md, docs/deployment.md, docs/migration-roadmap.md, docs/architecture-analysis-peer-review-response.md）。
- **跨副本令牌撤销广播与集群级缓存失效**：WithCrossReplicaRevocation将撤销令牌及过期时间广播给对等副本并以可加性、oracle-safe、fail-open方式采纳；WithAuthzPolicyBundleCacheTTL经KindAuthzPolicyChange失效授权策略缓存；identity.client_cache经KindClientChange失效客户端查询缓存；三者均含Prometheus传播指标（来源：docs/config-reference.md, docs/observability.md, docs/migration-roadmap.md）。
- **快照/发布/灾备运维子系统**：snapshot.storage.backend支持本地文件/内存快照存储；releases.*提供应用版本锁定/回滚（含部署后健康探针驱动自动回滚）；dr.*运行SnapshotReplicator后台任务将校验和验证过的快照复制到DR目标并跟踪RPO/RTO，可选dr.gate_readiness门控/readyz（来源：docs/config-reference.md, docs/dr-framework.md, docs/observability.md）。
- **按需数据库备份API**：POST /api/v1/admin/backup触发VACUUM INTO快照，时间戳文件名，支持backup.keep按来源保留裁剪（来源：docs/config-reference.md, docs/superpowers/plans/2026-07-02-wave1-quick-wins.md）。
- **Token策略治理引擎与降级运维模式**：token_policies.*对client/scope维度的最大TTL、最大刷新深度、最大活跃会话、强制续期、禁止scope组合等实施只收紧不放宽的规则并只读暴露于GET /api/v1/admin/token-policies；degradation.*支持admin可切换的read_only/auth_only/local_only/maintenance运维模式，按类别以503+Retry-After限流请求（来源：docs/config-reference.md, docs/error-codes.md）。
- **攻击面收缩型功能开关**：feature_gates.{oidc,ciba,admin_api,web_spa,caep,federation,self_service}可整组禁用路由，探测请求收到路由层原生404而非可达但拒绝的处理器（来源：docs/config-reference.md, docs/feature-matrix.md, docs/observability.md）。
- **WASM可插拔授权策略引擎**：sso.WithWASMAuthzEngine提供opt-in的WASM策略评估（fail-closed），配套POST /api/v1/admin/wasmauthz/check调试端点（来源：docs/deferred-backlog.md, docs/README.md, docs/wasmauthz.md, docs/results/tech-lead-analysis-expansion-next-wave.out.arch.md, docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.out.arch.md）。
- **MQTT/SSE跨集群通信原语**：基于eclipse/paho.golang的MQTT实现cluster.Bus，经既有sso.WithInvalidationBus接入；mqtt/、sse/包已提供可直接复用于配置分发与多集群联邦的通信层原语，无需新建（来源：docs/deferred-backlog.md, docs/wasmauthz.md, docs/requirements/architect-expansion-novel-horizons-2026-07-11.out.md, docs/results/architect-expansion-novel-horizons-2026-07-11.out.arch.md）。
- **只读跨集群配置漂移对比端点与SSOConfigDrift CRD**：POST /api/v1/admin/config/cluster-diff接受对端集群配置快照返回RFC 6902 patch而不主动拉取对端；独立cmd/sso-operator模块提供SSOConfigDrift CRD与控制器，轮询两集群配置计算差异并报告DriftDetected/PatchOpCount状态，瞬时错误fail-open（来源：docs/deferred-backlog.md, docs/architecture-analysis-peer-review-response.md, docs/tech-lead-analysis-cross-verified-five-directions.md, docs/results/expansion-gaps-analysis-2026-07-11.out.arch.md, docs/results/PEER_REVIEW_architect-expansion-novel-horizons-2026-07-11.out.arch.md）。
- **分层部署拓扑指导与K8s部署产物**：文档化Tier A（单实例sqlite无HA）/Tier B（Redis Cluster+Postgres+etcd高可用）/Tier C（下游本地JWKS验证）三档拓扑；ops/deploy/k8s提供Kustomize基础（反亲和、非root+seccomp、ConfigMap哈希触发滚动）；ops/deploy/k8s-prod叠加HPA、PDB、zone拓扑约束、preStop drain、宽容readyz探针（来源：docs/deployment.md）。
- **横向可扩展模块化单体拓扑与微服务化选项**：通过N个同构副本+L7负载均衡横向扩展；支持将令牌签发/消费拆分为独立可部署模块（Redis/etcd/KMS-HSM/SAML-IdP/LDAP/RADIUS/ext-authz），gRPC控制面可选独立于公共OAuth数据面暴露（来源：docs/deployment.md）。
- **Envoy ext_authz集成**：/mesh/ext-authz提供HTTP外部授权端点，独立extauthz嵌套模块实现envoy.service.auth.v3.Authorization gRPC服务，供服务网格授权使用（来源：docs/feature-matrix.md, docs/requirements/tech-lead-analysis-expansion-next-wave.out.md, docs/results/tech-lead-analysis-expansion-next-wave.out.arch.md）。
- **Mesh gRPC授权扩展预留点**：mesh_authz.go已显式注释预留"Phase B"扩展点，供未来gRPC授权集成使用（来源：docs/requirements/tech-lead-analysis-expansion-next-wave.out.md, docs/results/tech-lead-analysis-expansion-next-wave.out.arch.md）。
- **通用事件/Webhook出站引擎**：platform/lifecycle/webhook提供HMAC签名、指数退避重试与死信队列（DeadLetterStore）的出站webhook投递能力（来源：docs/error-codes.md, docs/results/architect-deep-code-scan-5-undiscovered-gaps.out.arch.md）。
- **API版本协商与弃用响应头**：opt-in的Accept-Version请求协商，及Deprecation/Sunset/Link响应头用于整API或路由级弃用信号（来源：docs/error-codes.md, docs/adr/ADR-0008-proto-versioning.md）。
- **灾备两层数据分类与恢复验证工具**：区分持久控制面状态（clients/users/roles/network policy/bootstrap）与瞬时热会话/令牌状态，仅前者纳入DR复制；文档化各后端复制/备份策略（SQLite VACUUM INTO、Postgres流复制/PITR、Redis RDB/AOF、etcd快照）；提供手动恢复runbook与RecoveryOrchestrator自动化演练（verify_integrity→promote_replica→restore_state→readiness_probe，首步失败即中止并产出结构化RecoveryReport）（来源：docs/dr-framework.md）。
- **发布治理体系**：遵循语义化版本2.0.0；minor每2-4周、patch按需（关键修复24小时内）、安全发布验证后立即发布；打tag触发GitHub Actions经goreleaser构建并附checksum与SBOM；关键bug走hotfix分支流程；发布前须通过make ci、make harness（6项工程门禁）、make check-invariants（10项安全不变量）、make diagnose及文档更新（来源：docs/RELEASE.md）。
- **SQL schema迁移框架与运维工具链**：dependency-free的platform/migrate跨命名空间前向迁移运行器，配套状态CLI sso-migrate；离线CLI与自动化处理配置快照、发布锁定/回滚、引导排序、数据保留调度（来源：docs/ROADMAP.md）。
- **Fail-open/fail-closed策略矩阵文档化**：正式表格映射audit sink、geo、risk scorer、tenant suspension、JTI replay、refresh issuance（fail-open）与signature validation、scope扩展、refresh family reuse、联邦信任链、CAEP receiver（fail-closed）等组件及理由（来源：docs/SECURITY.md, docs/security-policy.md）。
- **配置文件权限加固指导与分布式引导锁**：要求配置文件设为非world-readable权限（默认0640，owner root）；bootstrap.lock后端（file或etcd）协调多副本首次启动初始化，noop在多副本部署下显式禁止（来源：docs/SECURITY.md）。
- **架构修复与代码评审技能集**：run.py自动检测导入环与依赖方向违规；跨协议类型共享经core/+handlers.go路由而非oauth/oidc互相导入；security/、oidc/对defaultimpl/的耦合通过SPI提取+With*注入解耦；.check-architecture.sh配合make acceptance验证修复；代码评审清单强制无oauth/oidc循环导入、无包导入cmd/、根目录无新业务逻辑（python cli.py check-root）、领域包归属正确、对象/函数体量与if嵌套/switch分支上限、禁止"TODO: refactor later"延期重构（来源：docs/skills/architecture-fix/SKILL.md, docs/skills/code-review.md）。
- **Schema版本启动期fail-closed围栏**：platform/migrate/migrate.go的CheckSchema在数据库schema版本超出二进制支持的最大版本时返回ErrSchemaTooNew，并接入所有应用构建路径的启动可用性检查，触发时进程fail-closed退出（os.Exit(1)）（来源：docs/requirements/senior-architect-expansion-v6-true-gaps-2026-07-11.out.md）。
- **Region抽象与驻留感知路由**：domains/region已实现Region ID、Resolver、ChainResolver等抽象及RegionTier（global/regional/local）+ResidencyValidator，用于限流、geo-IP与数据驻留校验（来源：docs/requirements/Senior-Architect-Expansion-Directions-2026-07-11.out.md, docs/requirements/global-scan-expansion-directions.out.md）。
- **MemoryPARStore容量上限与后台回收器**：已实现MaxEntries条目上限及StartReaper后台清理协程（来源：docs/requirements/senior-architect-5-gaps-2026-07-11.out.md）。
- **一致性测试套件先例**：已有permissions-provider的ConformanceSuite及本地化的facets/audit sink一致性测试，作为更广泛通用一致性测试框架的模式基础（来源：docs/tech-lead-analysis-meta-governance-v2.md）。
- **大规模功能式选项配置扩展面**：服务器已暴露174个跨7个options_*.go文件的WithXxx函数式选项构造器，用于模块化功能配置（来源：docs/requirements/expansion-directions-analysis.out.md）。
- **文档化的Postgres后端支持矩阵**：config-reference.md新增权威矩阵列出每个SDK存储的backend key及取值，证实Postgres已是约14类存储（identity、tenant、permissions、audit、webauthn等）的既有可用持久后端（来源：docs/superpowers/plans/2026-07-02-wave1-quick-wins.md）。
- **供应链签名与SBOM生成配置已就绪（未激活）**：.goreleaser.yaml已配置cosign sign-blob、容器镜像签名（docker_signs）及SBOM（syft）生成，当前在release.yml中标记为future尚未在发布流程中启用（来源：docs/requirements/expansion-novel-2026-07-11.out.md, docs/results/expansion-novel-2026-07-11.out.arch.md）。

### 提议中/未来方向功能
- **声明式GitOps配置Apply API**：新增POST /admin/config/apply端点，接受完整期望状态配置快照，支持dry-run与fail/force/merge应用策略及冲突报告（来源：docs/architect-analysis-five-verified-expansion-directions.md, docs/tech-lead-analysis/cross-validated-five-new-directions.md, docs/requirements/high-value-expansion-directions.out.md）。
- **GitOps协调器与PR审批工作流**：独立sso-gitops-reconciler模块（或K8s Operator）轮询/webhook触发同步Git仓库配置到SSO服务器，将dry-run diff作为PR评论展示，merge后自动应用，支持可配置的敏感字段审批策略（来源：docs/architect-analysis-five-verified-expansion-directions.md, docs/requirements/high-value-expansion-directions.out.md, docs/results/architect-next-five-horizons-2026-07-11.out.arch.md）。
- **配置三方diff引擎与版本管理回滚**：比较desired（Git）/running（运行态）/baseline（上次应用态）三态配置以检测并解决并发冲突变更；持久化配置版本（hash/时间戳/diff摘要）并提供rollback API重新应用历史版本（来源：docs/architect-analysis-five-verified-expansion-directions.md, docs/tech-lead-analysis/cross-validated-five-new-directions.md）。
- **配置变更canary灰度发布**：对配置变更采用按标签子集应用的canary模式，监控错误率/延迟指标并基于阈值自动晋升或回滚（来源：docs/tech-lead-analysis/cross-validated-five-new-directions.md, docs/results/expansion-gaps-analysis-2026-07-11.out.arch.md）。
- **配置漂移自动修复/自愈闭环**：在现有只读SSOConfigDrift检测基础上扩展resolutionStrategy（merge/strict/local_wins）、autoCorrect自动回滚、complianceMode字段，非破坏性drift自动应用、破坏性drift排队人工审批（来源：docs/architecture-analysis-peer-review-response.md, docs/requirements/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.md, docs/results/expansion-gaps-analysis-2026-07-11.out.arch.md）。
- **GitOps敏感字段加密**：集成SOPS（age加密）对声明式配置中的敏感字段加解密，支持任意Git工作流而不绑定K8s（来源：docs/results/architect-next-five-horizons-2026-07-11.out.arch.md）。
- **安全的GitOps配置APPLY端点**：新增POST /api/v1/admin/config/cluster-apply（opt-in，admin:write.config scope，幂等token保护，完整前后diff审计），补齐现有只读cluster-diff能力（来源：docs/results/expansion-gaps-analysis-2026-07-11.out.arch.md）。
- **声明式全量配置导出端点与ConfigSpec模型**：导出tenant/client/user/permissions/connections完整配置为声明式YAML，版本化ConfigSpec schema含引用完整性与密钥引用校验，作为GitOps基础（来源：docs/tech-lead-analysis/cross-validated-five-new-directions.md, docs/requirements/high-value-expansion-directions.out.md）。
- **Identity-as-Code声明式编译引擎**：sso-ctl apply将YAML编译为bootstrap.Snapshot格式，经拓扑依赖排序计算plan/diff，资源标记managed_by（gitops/admin-api/terraform）拒绝对GitOps管理资源的API级直接编辑以防漂移（来源：docs/requirements/expansion-directions-v13-analysis.out.md, docs/results/expansion-directions-v13-analysis.out.arch.md）。
- **GitOps密钥引用解析**：Phase 1支持`$ENV:`/`$FILE:`密钥引用，规划Phase 2支持Vault/AWS Secrets Manager/K8s Secrets，`sso-ctl plan`输出中解析值始终脱敏（来源：docs/results/expansion-directions-v13-analysis.out.arch.md）。
- **配置验证CI/CD严格门禁**：sso-ctl config validate --ci模式，基于构建期能力注册表与版本兼容矩阵产出JSON报告及非零退出码，部署前阻断无效配置（来源：docs/architect-analysis-v6-five-directions.md, docs/architecture-analysis-peer-review-response.md, docs/requirements/architect-expansion-novel-5-directions-v6-code-scan.out.md, docs/results/expansion-strategic-gaps-2026-07-11.out.arch.md）。
- **配置JSON Schema自动生成**：基于Go struct tag经go:embed自动生成服务器配置JSON Schema，建立配置校验单一事实来源（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md, docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.review.out.arch.md）。
- **配置交叉引用一致性校验引擎**：在现有逐字段JSON Schema类型校验之外，新增跨配置段依赖一致性校验（如WithFAPIProfile须依赖WithIDTokenIssuer与WithJARM），并支持validateServer()冲突检测（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md, docs/requirements/senior-architect-expansion-v3-identity-system-quality.out.md, docs/requirements/architect-scan-deep-gaps-2026-07-11.out.md, docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.review.out.arch.md）。
- **配置依赖矩阵声明与能力注册表校验**：通过struct tag（dep:/capability:）为50+配置项声明依赖关系，`sso-ctl config validate --ci`据此拒绝无效配置组合（来源：docs/requirements/architect-scan-deep-gaps-2026-07-11.out.md, docs/results/architect-scan-deep-gaps-2026-07-11.out.arch.md）。
- **配置基线比对与升级兼容性检查体系**：捕获配置基线并与当前配置差异比对；版本升级过程中校验配置/schema兼容性，提供预检、兼容矩阵、升级后自动完整性验证（来源：docs/requirements/senior-architect-expansion-v3-identity-system-quality.out.md, docs/requirements/expansion-systemic-quality-horizon.out.md, docs/results/expansion-systemic-quality-horizon.out.arch.md）。
- **配置变更dry-run影响面报告**：新增dry-run模式在应用前报告配置变更的影响范围（例如"缩小此scope将影响3个客户端"）（来源：docs/requirements/architect-scan-deep-gaps-2026-07-11.out.md）。
- **配置热加载健康门禁自动回滚**：复用现有发布注册表健康探针/自动回滚机制到热加载配置变更，失败健康检查时自动回滚到上一快照（来源：docs/requirements/architect-scan-deep-gaps-2026-07-11.out.md, docs/results/architect-scan-deep-gaps-2026-07-11.out.arch.md, docs/results/expansion-runtime-governance-2026-07-11.out.arch.md）。
- **Config.Version强制执行与SIGHUP allowlist完整性校验**：WithStrictConfigVersion选项将现存但未启用的Config.Version字段变为启动期硬性门禁；新增自动化测试验证每个新增可热重载配置字段都已登记在SIGHUP safeReloadPaths允许清单中（来源：docs/requirements/expansion-runtime-governance-2026-07-11.out.md, docs/results/expansion-runtime-governance-2026-07-11.out.arch.md）。
- **基于etcd watch的配置热更新机制**：分类安全可热重载的配置键，新增etcd watcher生成ConfigDelta并经ApplyDelta实时应用，无需重启（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）。
- **多区域主动-主动数据面部署架构**：为跨区域主动-主动部署引入region-scoped签名密钥kid命名空间、跨区域会话复制、region感知JWKS分发与token验证/签发（issuer_region、additional_issuers），需解决同域名vs区域域名下iss claim策略一致性（来源：docs/tech-lead/expansion-five-directions-v2-peer-review-implementation.md, docs/requirements/expansion-directions-v12-analysis.out.md, docs/requirements/architect-expansion-five-directions-2026-07-11.out.md, docs/requirements/global-scan-expansion-directions.out.md）。
- **Store包裹器模式实现跨区域一致性复制**：以泛型ConsistentStore[T]/ConsistentSessionStore装饰器包裹现有Store SPI，引入ReplicationTopology与按端点ReadConsistency（leader-read/local-read/local-write+async-replicate）声明，零改动65+现有SPI签名，单区域部署零开销（来源：docs/feature-spec-architecture-synthesis-five-directions.md, docs/results/architect-fresh-scan-5-directions.out.arch.md, docs/results/architect-global-analysis-2026-07-11.out.arch.md, docs/results/PEER_REVIEW_architect-expansion-novel-horizons-2026-07-11.out.arch.md）。
- **简化版灾备协调器（全域zone outage）**：将DR协调器重构为仅处理整区域级故障而非逐节点故障，经gRPC心跳与区域健康指标判定（来源：docs/tech-lead/expansion-five-directions-v2-peer-review-implementation.md, docs/requirements/expansion-directions-v12-analysis.out.md）。
- **跨区域会话复制**：经双向gRPC流异步远程写会话状态，采用last-writer-wins/CRDT冲突解决与熔断器保护；RegionBridge组件本地发布事件并尽力而为fan-out到对等区域（来源：docs/tech-lead/expansion-five-directions-v2-peer-review-implementation.md, docs/results/expansion-gaps-analysis-2026-07-11.out.arch.md）。
- **全局区域注册表、GSLB路由与区域故障自动切换**：新增RegionRegistry作为租户数据驻留写入路由仲裁者，集成DNS GSLB/Anycast跨区域流量路由，及区域级自动故障排水与切换（来源：docs/requirements/Senior-Architect-Expansion-Directions-2026-07-11.out.md, docs/results/Senior-Architect-Expansion-Directions-2026-07-11.out.arch.md）。
- **声明式区域拓扑配置与分区降级模式**：新增RegionTopology结构声明区域布局/复制/路由；定义跨区域连接性中断时的分区降级运行模式，弥补当前无fallback行为的空白（来源：docs/requirements/architect-scan-deep-gaps-2026-07-11.out.md）。
- **Region-affinity令牌签发与跨区域JWKS/撤销队列**：为token claim添加区域信息并按区域分组签名密钥；新增跨区域JWKS验证TTL缓存；将撤销广播从同集群副本扩展为持久化跨区域投递队列（来源：docs/requirements/architect-scan-deep-gaps-2026-07-11.out.md）。
- **RegionForwarder抽象**：将同步跨区域写转发（gRPC请求/响应）与异步数据复制（cluster.Bus发布订阅）解耦，独立配置比HTTP handler更短的超时以避免级联延迟放大（来源：docs/results/senior-architect-expansion-2026-07-11.out.arch.md）。
- **etcd watch/lease自愈重订阅**：为etcd watch/lease复制循环增加自动重订阅与就绪恢复能力，修复当前首次resp.Err()后永久退出、该副本不再响应撤销事件的问题（来源：docs/results/PEER_REVIEW_architect-expansion-novel-horizons-2026-07-11.out.arch.md）。
- **外部依赖熔断器与舱壁隔离框架**：新增platform/resilience，为KMS、SAML IdP、CAEP等外部依赖调用提供滑动窗口/计数熔断器与基于并发信号量的舱壁隔离，防止级联故障（来源：docs/architecture-analysis-peer-review-response.md, docs/requirements/expansion-directions-v10-analysis.out.md, docs/results/architect-fresh-scan-5-directions.out.arch.md, docs/results/senior-architect-expansion-v5-post-scan.out.arch.md）。
- **熔断器状态持久化SPI**：新增可选CircuitBreakerStore（GetState/SetState）持久化后端，防止重启后熔断状态重置为closed而对仍不可用的下游（如KMS）发起请求风暴（来源：docs/results/senior-architect-expansion-2026-07-11.out.arch.md）。
- **统一出口连接器框架**：新增platform/egress包及Connector SPI，为约10个出站连接器（KMS、SAML IdP、CAEP push、联邦、SMTP、OIDC联邦拉取、extauthz gRPC等）提供统一健康检查/熔断/舱壁/重试/限流/证书轮换，替代约30处重复实现，支持渐进式采用（来源：docs/architecture-analysis-peer-review-response.md, docs/requirements/PEER_REVIEW_architect-expansion-novel-horizons-2026-07-11.out.md, docs/results/architect-expansion-novel-horizons-2026-07-11.out.arch.md, docs/results/expansion-platform-evolvability-meta-governance.out.arch.md）。
- **跨后端事务一致性Saga协调器**：新增platform/saga包（Step Do/Compensate、Coordinator、DeadLetterStore），将/token/revoke-all与管理模拟登录会话铸造等跨SQLite/Redis/cluster.Bus的多后端操作改造为可补偿流程，配合后台一致性哨兵（来源：docs/tech-lead-analysis-five-directions.md, docs/results/architect-final-five-2026-07-11.out.arch.md）。
- **事务性SPI扩展与Outbox模式**：新增Transaction/TxTokenStore SPI扩展支持跨存储原子写（内存事务模拟/SQLite-Postgres原生事务/Redis MULTI-EXEC），或采用写先落Postgres outbox表再异步中继到最终存储的Outbox模式（来源：docs/results/global-architecture-scan-five-uncovered-high-value-directions-2026-07-11.out.arch.md）。
- **分布式缓存一致性与失效框架**：新增CacheInvalidator SPI及基于cluster.Bus的CacheSubscriber失效广播机制，覆盖sessionhub、JWKS、租户配置、授权策略等缓存区域，内建region-based单飞去重防止并发回填惊群效应（来源：docs/results/senior-architect-expansion-v5-post-scan.out.arch.md, docs/requirements/senior-architect-expansion-v5-post-scan.out.md）。
- **存储层一致性等级接口与变更事件总线**：定义ConsistencyLevel类型（Eventual/ReadCommitted/Linearizable/AtomicConsume）并为各Store显式声明一致性契约，配合ConsistencySuite契约测试；新增进程内ChangeEvent+ChangeSubscriber接口使ClientStore.UpdateClient等变更可被依赖方最终一致订阅（来源：docs/results/architect-fresh-code-scan-2026-07-11.out.arch.md）。
- **域事件驱动的外部分发总线与统一事件路由层**：新增platform/domainbus（DomainEvent类型+Publisher/Subscriber SPI）将cluster.Bus内部事件转为带幂等键的外部域事件；platform/eventbus提供EventRouter包装cluster.Bus、webhook、SSE推送，统一撤销通知/CAEP-SSF广播/SCIM配置/审计webhook的事件出口模型（来源：docs/results/architect-expansion-novel-5-directions-2026-07-11.out.arch.md, docs/results/architect-gap-analysis-2026-07-11.out.arch.md）。
- **通用ConformanceSuite[T]框架与Store一致性测试套件**：提取可复用的泛型测试套件类型（Factory+SkipList+Optional标签），覆盖Client/Session/Consent/AuthCode/Refresh/PAR/User/Tenant等Store SPI跨Memory/SQLite/Redis/PostgreSQL的行为一致性（来源：docs/tech-lead-analysis-meta-governance-v2.md）。
- **后端一致性CI工作流与差异文档化**：新增CI工作流并行跑一致性测试套件覆盖memory/sqlite/postgres/redis四类后端并发布pass/skip/fail摘要报告；文档化各后端间有意的行为差异（如DELETE RETURNING vs map delete、TTL过期 vs 手动GC、隔离级别差异）（来源：docs/tech-lead-analysis-meta-governance-v2.md）。
- **组合式功能交互测试矩阵与影响文档**：定义高影响功能组合场景矩阵及切换feature gate的测试runner；维护记录已知功能组合兼容性/冲突状态的活文档，要求新功能PR同步更新（来源：docs/tech-lead-analysis-meta-governance-v2.md）。
- **模块依赖图生成器与CI版本一致性门禁**：解析全部嵌套go.mod生成依赖DAG，CI门禁在共享第三方依赖版本不一致时失败，可暴露为sso-ctl analyze子命令（来源：docs/tech-lead-analysis-meta-governance-v2.md, docs/requirements/expansion-platform-evolvability-meta-governance.out.md）。
- **嵌套子模块纳入主CI编译测试门禁**：将saml/、kms/*、redis/、ldap/等独立go.mod子模块纳入主CI编译与测试流程，消除当前"高风险代码无门禁覆盖"的缺口（来源：docs/results/expansion-directions-analysis.out.arch.md）。
- **供应链安全激活与门禁**：激活已配置但处于dormant状态的Cosign keyless签名与SBOM CI生成；新增SLSA Level 3供应链溯源生成器（slsa-framework/slsa-github-generator）、in-toto证明；govulncheck+trivy镜像扫描CI门禁阻断CRITICAL/HIGH漏洞发布；新增发布完整性验证CI job（来源：docs/tech-lead-analysis-frontier-paradigms-2026-07-12.md, docs/requirements/expansion-novel-2026-07-11.out.md, docs/results/expansion-novel-2026-07-11.out.arch.md）。
- **第三方WASM插件生命周期平台**：基于wazero WASM运行时构建插件生命周期平台，含签名Manifest声明hook与权限、Registry（Register/Unregister/List/AttachToTenant）、HealthCheck、per-tenant资源隔离、per-call实例池化及PluginChainBudget延迟预算（默认5ms）限制token签发路径执行开销（来源：docs/requirements/expansion-directions-v11-analysis.out.md, docs/results/expansion-directions-v11-analysis.out.arch.md）。
- **WASM策略Bundle数据库化与热重载**：将wasmauthz策略bundle存入数据库（而非仅文件系统）以支持admin API CRUD，并经cluster.Bus跨副本原子热替换（来源：docs/results/expansion-next-wave-analysis.out.arch.md）。
- **Terraform Provider模块**：独立Terraform Plugin Framework provider经admin HTTP API管理clients、tenants、conditional-access策略、signing keys、audit sinks（来源：docs/architecture/analysis-detection-response-gap.md, docs/results/expansion-directions-analysis-v6.out.arch.md）。
- **OpenFeature标准集成**：采纳OpenFeature标准作为功能开关SPI，统一平台各处的feature gating机制（来源：docs/requirements/architect-global-scan-novel-ops-biz-gaps.out.md）。
- **中心化跨域策略引擎与共享PolicyEvaluator SPI**：统一授权/条件访问/租户策略决策为单一评估路径；新增通用shared/spi/policy.go PolicyEvaluator接口，支撑组织策略继承、访问认证范围判定、身份健康评分权重等多方向的可配置策略解析需求（来源：docs/requirements/architect-global-scan-novel-ops-biz-gaps.out.md, docs/results/architect-expansion-analysis.out.arch.md）。
- **可编程认证管道动作引擎**：构建认证管道PreAuth/PostAuth/PreToken可插拔hook机制，支持内置动作类型（如rate_limit_override）并提供failure_mode（block/bypass）控制超时/panic时的失败模式，弥补当前仅授权路径（wasmauthz）具备可编程扩展点而认证路径缺失等价能力的空白（来源：docs/requirements/expansion-directions-v13-analysis.out.md, docs/requirements/architect-expansion-novel-horizons-2026-07-11.out.md, docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.out.arch.md）。
- **声明式同意编排流程与授权工作流持久化**：基于ConsentStore构建覆盖范围同意与用户撤销授权应用的声明式编排流程；将挂起中的授权工作流状态（Grant审批、UMA许可票据等）持久化到SQLite/Postgres确保重启可恢复；新增独立GrantApprovalWorkflow对敏感授权请求引入人工审批流程（来源：docs/requirements/architect-expansion-novel-horizons-2026-07-11.out.md, docs/requirements/architect-expansion-5-directions.out.md, docs/results/architect-expansion-5-directions.out.arch.md）。
- **零停机后端迁移框架**：新增MigrationSource/MigrationTarget/MigrationCoordinator抽象及`sso-ctl migrate export/import/diff/verify/switch/rollback`CLI，采用异步双写、健康监控与人工确认门控完成后端切换（来源：docs/requirements/expansion-directions-v11-analysis.out.md, docs/requirements/architect-remaining-horizon-2026-07-11.out.md, docs/results/expansion-directions-v11-analysis.out.arch.md）。
- **跨后端数据迁移与差异化迁移策略**：分阶段实现跨存储后端（如SQLite到PostgreSQL）原子导出/导入，简单store（Client/User/Role/Scope）先行，有状态store（refresh token/session/auth code）需保留family/rotation一致性与审计哈希链连续性；按存储类型定义差异化MigrationStrategy（来源：docs/requirements/architect-remaining-horizon-2026-07-11.out.md, docs/results/architect-remaining-horizon-2026-07-11.out.arch.md）。
- **Schema版本新增型vs破坏型变更区分围栏**：迁移引擎区分additive（新表/新可空列/新索引，WARN+继续）与non-additive（列重命名/类型变更，硬失败）两类变更，取代当前对任何前向schema漂移一律fail-closed的策略（来源：docs/requirements/senior-architect-expansion-v6-true-gaps-2026-07-11.out.md, docs/results/senior-architect-expansion-v6-true-gaps-2026-07-11.out.arch.md）。
- **升级兼容性预检与版本矩阵治理**：新增`sso-ctl migrate pre-flight`预检CLI（可扩展PreFlightChecker：schema版本/磁盘空间/备份新鲜度）；维护二进制/schema/config三维版本兼容矩阵并接入CI门禁；滚动升级期经cluster.Bus广播KindSchemaVersion实现canary/版本不匹配检测；将CurrentVersion兼容性检查接入/readyz作为HTTP就绪探针；升级完成后自动验证系统完整性；接线现有CurrentVersion检测防止回滚旧二进制损坏已迁移新schema（来源：docs/requirements/expansion-systemic-quality-horizon.out.md, docs/results/expansion-systemic-quality-horizon.out.arch.md, docs/results/expansion-directions-analysis.out.arch.md, docs/results/expansion-runtime-governance-2026-07-11.out.arch.md）。
- **声明式索引注册表与多后端schema版本治理**：新增声明式索引注册表（SchemaDeclaration）供各Store集中声明表结构与索引，替代散落14+文件的CREATE INDEX语句；新增SchemaRegistry两阶段版本注册（初始化期望版本+运行时Check()）产出人类可读per-namespace版本diff摘要（来源：docs/results/architect-remaining-horizon-2026-07-11.out.arch.md, docs/requirements/expansion-runtime-governance-2026-07-11.out.md）。
- **服务器启动治理（依赖校验+阶段编排）**：新增构造时Server.Validate()及WithBootFailHandler钩子，将构造从"永不失败"变为fail-fast；引入显式Phase ID+依赖门控系统结构化当前隐式的apply*调用顺序，捕获如指标回调早于指标初始化注册等接线顺序bug（来源：docs/requirements/expansion-runtime-governance-2026-07-11.out.md, docs/results/expansion-runtime-governance-2026-07-11.out.arch.md）。
- **运维完备性检查清单门禁**：在CHECKS_REGISTRY.md新增强制门禁，要求每个新SPI组件在合并前证明具备后台清理、资源版本化、重试/超时策略、指标暴露、审计事件、安全nil/no-op默认值（来源：docs/requirements/architect-system-resilience-spa-ssrf-concurrency-5-gaps.out.md, docs/results/architect-system-resilience-spa-ssrf-concurrency-5-gaps.out.arch.md）。
- **内存存储容量治理**：为MemoryAuthCodeStore新增MaxEntries上限与后台reaper；为MemorySessionManager新增容量上限与TTL清扫器；将MemoryRefreshTokenStore的全局sync.Mutex优化为类似PAR/AuthCode的分片存储以消除锁争用热点；为MemoryClientStore新增条目数量上限保护（来源：docs/requirements/senior-architect-5-gaps-2026-07-11.out.md）。
- **API废弃/Sunset策略框架与破坏性变更检测门禁**：中间件级自动为注册在弃用登记表（端点、弃用起始版本、sunset日期）中的端点附加Deprecation/Sunset响应头及日志告警；自建OpenAPI diff引擎分类breaking vs non-breaking变更（移除端点/必填参数/响应字段、收紧约束、枚举变更）并在CI中阻断breaking变更（来源：docs/results/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.arch.md）。
- **API生命周期治理框架**：为SnapLink公共API建立正式的版本化、弃用与生命周期管理流程/工具，超越现有ADR-0008仅覆盖proto的范畴（来源：docs/requirements/architect-global-scan-novel-ops-biz-gaps.out.md）。
- **SaaS运营成熟度与统一资源搜索**：补齐运行SnapLink作为多租户SaaS所需的运营手册、租户生命周期操作等成熟度缺口；新增跨users/clients/tenants/sessions等身份平台资源的统一搜索能力（来源：docs/requirements/architect-global-scan-novel-ops-biz-gaps.out.md, docs/requirements/expansion-directions-analysis-v6.out.md）。
- **运行时能力自描述注册表**：新增GET /api/v1/capabilities端点，让系统运行时自我声明已支持的SPI、存储实现与API端点，避免架构分析依赖反复的对抗式grep重新发现已实现能力（来源：docs/results/expansion-ciam-identity-horizon.out.arch.md）。
- **集成完成度审计维度与缺口清单整合**：新增架构治理维度，为每个核心组件定义"调用边集成完成度"检查清单以区分"组件不存在"与"组件未集成"两类缺口；将30+份重叠架构分析文档整合为一份含优先级与工作量估算的机器可读缺口清单（docs/known-gaps.md/yaml），替代持续增殖的竞争性分析文档（来源：docs/results/architect-fresh-scan-five-directions-2026-07-11.out.arch.md, docs/results/expansion-systemic-quality-horizon.out.arch.md）。
- **用户通知基础设施**：新增通用NotificationStore/NotificationSender SPI及NotificationEvent域模型（区别于现有单一用途的PasswordResetSender），涵盖邮件适配器、应用内通知、用户通知偏好API、事件路由引擎、频率控制与批量发送能力（来源：docs/requirements/senior-architect-scan-v2-true-gaps-2026-07-11.out.md, docs/requirements/senior-architect-scan-v2-true-gaps-2026-07-11.review.out.md）。
- **EventOutbox持久化事件发送SPI**：新增EventOutbox+SubscriptionStore SPI，提供at-least-once持久化事件投递、event_id去重及RS订阅注册/注销/健康检查生命周期管理（来源：docs/results/architect-deep-code-scan-5-undiscovered-gaps.out.arch.md）。
- **Webhook订阅模型与持久化异步作业队列**：将当前接收全量事件的单一全局webhook URL替换为支持按订阅事件过滤的订阅模型；新增共享的持久化outbox模式支撑SCIM出站配置、webhook重试、revoke-all等操作，弥补cluster.Bus仅尽力而为的不足（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md）。
- **Identity变更数据捕获(CDC) SPI**：新增轻量SPI发布基于Snapshot的User/Client存储变更事件，复用而非替代audit/Bus/webhook基础设施，供下游CRM/HRIS/数据湖订阅而非轮询（来源：docs/results/expansion-systemic-quality-horizon.out.arch.md）。
- **platform/scheduler周期性任务调度框架**：新增轻量级一次性/周期性作业调度抽象（Job/PeriodicJob/Scheduler），填补当前完全没有定时任务基础设施的空白（来源：docs/results/expansion-edge-cases-2026-07-11.out.arch.md）。
- **后台批量作业框架**：引入通用Job SPI（含进度跟踪与取消），经memory/SQLite job store持久化，用于异步运行大型管理批量操作（来源：docs/tech-lead/tech-lead-analysis-five-true-new-gaps-2026-07-12.md）。
- **Workload Identity Registry与platform/relay中继抽象层**：新增WorkloadIdentity、TrustDomain、TrustBundle三类K8s CRD声明式管理跨集群工作负载身份与信任域配置；新增通用Relay/Channel SPI提供双向有状态中继通道原语（WebSocket/gRPC stream/mTLS tunnel），供Passkey Hybrid与跨集群身份场景共享复用（来源：docs/results/architect-next-five-horizons-2026-07-11.out.arch.md）。
- **自助租户注册与套餐权益（Entitlement）系统**：新增EntitlementStore SPI与Plan/PlanLimits模型，将全局7个atomic.Bool功能门控迁移/扩展为按租户维度的权益检查（含向后兼容的EnabledForTenant并行路径）；复用cluster.Bus模式新增KindPlanChanged事件跨副本广播计划变更并失效本地缓存；新增ErrPlanLimitExceeded标准错误；套餐降级采用控制面锁定（管理控制台只读、禁止新客户端注册）而非数据面锁定语义（来源：docs/results/expansion-edge-cases-2026-07-11.out.arch.md, docs/results/expansion-edge-protocol-hardening-platformization.out.arch.md）。
- **租户自助注册API与Quickstart Wizard**：新增POST /api/v1/tenants/self-service自助注册端点及配套4步引导式前端向导（创建应用→配置登录→集成→验证），支撑产品驱动增长（PLG）获客漏斗（来源：docs/results/expansion-edge-protocol-hardening-platformization.out.arch.md）。
- **HTTP/2监听器级细粒度可配置化**：在现有全局server.http2.enabled开关基础上，提议per-listener粒度配置以避免全局禁用意外影响需要HTTP/2的gRPC等客户端（来源：docs/results/global-scan-five-directions.out.arch.md）。
- **v2主版本破坏性拓扑迁移执行方案**：将模块路径升级至github.com/snaplink/sso/v2，按层表重写导入路径并重生成proto stub，仅在真正需要破坏性变更时执行；14个嵌套模块（saml、ldap、kerberos、radius、extauthz、redis、kms/*）需各自独立打v2标签；ADR-0001同时明确该retree须伴随major版本弃用别名窗口，当前仅为概念文档非可执行迁移（来源：docs/architecture/V2-MIGRATION.md, docs/adr/ADR-0001-directory-layout.md）。
- **分层多集群/多区域通信拓扑抽象**：引入ReplicationTopology分层组合SSE（跨副本最多一次事件，如撤销传播）、gRPC（强一致写转发到leader区域）、etcd/SSOConfigDrift CRD（全局配置协调），MQTT保留用于高延迟跨区域消息；非leader区域对写请求fail-closed返回503+Retry-After而非静默转发以避免脑裂（来源：docs/results/expansion-platform-evolvability-meta-governance.out.arch.md）。
- **自动化ACME TLS证书签发**：集成go-acme/lego库自动化TLS证书签发与续期（来源：docs/results/expansion-platform-evolvability-meta-governance.out.arch.md）。
- **插件权限模型专项评审与统一协议扩展SPI目录**：为第三方插件扩展的scope/permission模型设立独立设计评审而非简单常量新增；将新提案的协议层SPI（binding传播、威胁情报、客户端指标、算法生命周期）集中到统一的protocols/extensions/目录而非散落各包（来源：docs/results/expansion-directions-v10-analysis.out.arch.md, docs/results/expansion-directions-v12-analysis.out.arch.md）。
- **内建可信代理配置设施**：新增WithTrustedProxies(CIDRs, hops)单点配置统一管理X-Forwarded-*信任边界，避免运营方为每个XFF消费者手工配置导致的IP欺骗风险（来源：docs/results/architect-expansion-novel-5-directions-2026-07-11.out.arch.md）。
- **Gateway ext-authz适配器含撤销感知缓存**：基于extauthz模块构建Gateway适配器（如Envoy ext-authz gRPC）用于服务网格授权，决策缓存30秒并在KindTokenRevoked事件时主动失效，60秒硬上限TTL（来源：docs/results/tech-lead-analysis-expansion-next-wave.out.arch.md）。
- **健壮的引导锁防护令牌(fencing token)实现**：实现真实的bootstrap lock MarkApplied防护令牌校验（文档中描述的FencedTracker类型当前并不存在），或修正文档以准确描述现有heartbeat-cancel/幂等保证机制（来源：docs/ROADMAP.md）。


---
## 计量与计费

### 已实现功能
- **租户用量计量计数器（TenantUsage）**：`domains/metering` 包已实现 `TenantUsage` 类型及 `Aggregator`（内存与 sqlite 两种后端），按租户/周期（日/月）聚合登录数等用量指标，并已内部提供 `Usage()`、`TopTenants()` 查询能力，用于支撑计费场景的基础用量统计（来源：docs/requirements/architect-remaining-horizon-2026-07-11.out.md）

### 提议中/未来方向功能
- **Per-tenant 用量聚合报表与导出 API**：在现有 per-tenant 计量计数器基础上，构建 MAU、活跃客户端数、配额等维度的聚合报表与导出 API，弥补 Tenant 作为计费关系主体却缺乏对外报表/导出能力的缺口（来源：docs/ROADMAP.md, docs/results/expansion-directions-v7-analysis.out.arch.md）
- **TopTenants 管理排行榜端点**：新增 `GET /api/v1/admin/usage/top-tenants` 管理端点，将 metering 后端已在内部实现的 `Aggregator.TopTenants` 能力对外暴露，返回指定周期内登录/用量最高的 N 个租户排行（来源：docs/superpowers/plans/2026-07-02-implementation-roadmap.md, docs/superpowers/plans/2026-07-02-wave1-quick-wins.md）
- **统一分析数据管道/查询（TokenUsage + Metering）**：将并行的 tokenusage（按分钟/客户端/地理维度的高基数运营分析）与 metering（按租户/日/月的计费级聚合）两条独立管道，通过统一查询接口（UnifiedAnalyticsStore/BusinessAnalyticsStore）整合，支持客户端排名与月度计费报表的联合查询，但不强制合并底层存储（来源：docs/requirements/architect-remaining-horizon-2026-07-11.out.md, docs/results/architect-remaining-horizon-2026-07-11.out.arch.md）
- **身份分析引擎与跨租户 BI 仪表盘**：构建租户健康仪表盘、身份分析引擎、MAU/DAU 业务指标，以及面向多租户运营方的独立分析汇总表（由审计/计量/指标 ETL 定期填充），支持跨租户商业智能查询，避免直接查询生产数据存储或依赖单实例 Prometheus 拉模式；当前实现为零（来源：docs/requirements/expansion-post-protocol-layer-analysis.out.md, docs/results/architect-global-scan-novel-ops-biz-gaps.out.arch.md）
- **租户自助分析门户（含 CSV/PDF 用量报告导出与定时投递）**：面向租户管理员的自助用量与安全分析门户，复用现有 metering 聚合 SPI，提供总览卡片、日志时间序列、CSV/PDF 格式用量报告导出与定时投递能力；当前底层 metering SPI/后端已存在但缺失该导出能力（来源：docs/requirements/Senior-Architect-Expansion-Directions-2026-07-11.out.md, docs/results/Senior-Architect-Expansion-Directions-2026-07-11.out.arch.md）
- **自助租户开通与套餐权益/MAU 配额校验**：复用现有 WebAuthn signup + 邮箱验证流程实现租户自助注册开通，新增 EntitlementStore（内存实现，复用 MemoryProvider 模式）管理套餐权益/配额（PlanLimits），并在 metering 包新增 `CurrentMAU(ctx, tenantID)` 方法，在授权时与套餐 MaxMAU 限额比较以判断是否超出计划用量，与现有 FeatureGate 打通（来源：docs/requirements/expansion-edge-cases-2026-07-11.out.md, docs/requirements/expansion-edge-protocol-hardening-platformization.out.md, docs/results/expansion-edge-cases-2026-07-11.out.arch.md）
- **租户配额引擎与席位管理**：提供按租户维度的资源配额（token 签发量、用户数、API 调用量）与用户席位（seat）管理能力，新增 QuotaStore/QuotaEngine 支持软/硬限额，触及硬限额时返回 429 QuotaExceeded，与现有按 IP/客户端的公平限流机制互补；当前系统尚无此类管理机制（来源：docs/requirements/expansion-novel-v4-privacy-dx-operations.out.md, docs/results/expansion-novel-v4-privacy-dx-operations.out.arch.md）
- **租户分级服务（TenantTier）**：在 `shared/core/tenant.go` 新增 TenantTier 枚举及 `DefaultsByTier()`，供限流、审计留存期、地理围栏等组件按租户层级分支行为，实现分级付费服务能力（来源：docs/results/architect-global-scan-novel-ops-biz-gaps.out.arch.md）
- **计费连接器/适配器平台（对接 Stripe/Chargebee/Recurly）**：扩展 domains/metering，新增幂等 MeterEvent 记录（按 EventID 去重）、聚合管道、billing-cycle/plan-tier 模型；在 `shared/spi/billing.go` 定义 BillingReporter/BillingAdapter 接口（Subscribe/CancelSubscription/CurrentSubscription），配套 Stripe、Chargebee、Recurly 等外部计费系统的独立模块适配器实现（含 webhook 接收器），将权益核心与外部计费系统解耦，按租户用量上报计费，故障开放且不影响身份处理主路径，实现最终一致的用量计费集成（来源：docs/requirements/expansion-secrets-slo-challenge-posture-billing.out.md, docs/requirements/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.md, docs/results/architect-global-scan-novel-ops-biz-gaps.out.arch.md, docs/results/expansion-edge-protocol-hardening-platformization.out.arch.md, docs/results/expansion-secrets-slo-challenge-posture-billing.out.arch.md）
- **租户计费用量聚合连接器与配额联动导出**：将 QuotaProfile 用量数据接入 domains/metering/，使超额可自动触发套餐升级或计费事件；并提供支持按 MAU、按 token、按租户固定费率等多种计费模型的聚合查询，通过 `/api/v1/admin/billing/usage` 端点暴露月度计费周期的历史用量聚合数据（来源：docs/results/expansion-five-uncovered-gaps.out.arch.md, docs/results/global-scan-ops-biz-readiness-5-uncovered-directions-2026-07-11.out.arch.md）


---
## 其他

### 已实现功能

- **可信代理链配置（Trusted Proxy Chain）**：通过 `WithTrustedProxies` 配置受信任的 CIDR 网段与跳数（hop count），用于在可信边缘节点后安全地采信 X-Forwarded-* 请求头。（来源：docs/requirements/PEER_REVIEW_architect-expansion-novel-horizons-2026-07-11.out.md）
- **文档化威胁模型**：将 IdP 进程边界定义为主要信任边界，明确说明传输中数据（TLS/DPoP）、静态数据（凭证哈希、加密快照）保护措施，以及侧信道缓解手段（bcrypt 常数时间比较、防枚举）。（来源：docs/SECURITY.md）
- **后端 i18n 本地化基础设施（shared/i18n Localizer）**：已提供 `i18n/` 包及 Localizer，为内嵌 SPA 提供多语言文本的后端消息目录/本地化管线基础设施（注：该管线尚未被前端 SPA 实际消费，前端集成部分见"提议中"）。（来源：docs/results/expansion-novel-2026-07-11.out.arch.md）

### 提议中/未来方向功能

- **用户通知基础设施核心 SPI（NotificationEvent/NotificationStore/NotificationSender）**：定义 NotificationEvent 核心类型及 NotificationStore/NotificationSender SPI（memory + SQLite 实现），支持已读/未读状态跟踪、按事件类型与渠道的用户级通知偏好、GDPR 合规的按主体范围删除，异步、非阻塞、fail-open 地从 audit.Recorder 消费事件投递。（来源：docs/tech-lead/tech-lead-analysis-five-true-new-gaps-2026-07-12.md, docs/results/architect-fresh-scan-five-directions-2026-07-11.out.arch.md, docs/results/architect-global-scan-v2-true-new-gaps-2026-07-12.out.arch.md, docs/results/senior-architect-expansion-v3-identity-system-quality.out.arch.md, docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.review.out.arch.md）
- **通知事件路由引擎**：基于可配置的事件类型映射与用户渠道偏好，将审计/领域事件（audit.Event → 内部 channel → worker pool → sender）路由为通知；提供 5 分钟级聚合/去重冷却窗口以防止通知风暴，冷却状态建议基于 SQL 时间窗口而非内存 map 实现以保证跨副本一致性；支持密码过期等时间驱动事件的调度触发。（来源：docs/tech-lead/tech-lead-analysis-five-true-new-gaps-2026-07-12.md, docs/requirements/senior-architect-expansion-v3-identity-system-quality.out.md, docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.review.out.arch.md, docs/results/architect-global-scan-v2-true-new-gaps-2026-07-12.out.arch.md）
- **多通道通知发送与统一渠道抽象（Email/In-App/SMS/Push）**：提供 Channel SPI 抽象邮件（复用现有 emailsmtp.Sender）、站内信、SMS（Twilio/AWS SNS 等）、Push 等投递渠道，支持路由、降级、重试及租户级可定制模板；新增独立的通用 SMS 通知渠道（密码重置提醒、安全通知等），区别于现有仅用于验证码发送的短信能力。（来源：docs/tech-lead-analysis/implementation-plan-five-directions.md, docs/requirements/architect-expansion-2026-07-11.out.md, docs/requirements/global-architecture-scan-four-production-blindspots-2026-07-11.out.md, docs/results/architect-global-analysis-2026-07-11.out.arch.md, docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.review.out.arch.md）
- **用户通知偏好设置 API**：新增 `GET`/`PUT /me/notifications/preferences` 自服务端点，允许用户配置希望接收的通知渠道与事件类型。（来源：docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.review.out.arch.md, docs/requirements/global-architecture-scan-four-production-blindspots-2026-07-11.out.md, docs/tech-lead/tech-lead-analysis-five-true-new-gaps-2026-07-12.md）
- **用户门户通知中心 UI**：在 User Portal SPA 新增铃铛图标通知面板，含未读数徽标、近期通知下拉列表及完整通知历史页面。（来源：docs/tech-lead/tech-lead-analysis-five-true-new-gaps-2026-07-12.md, docs/requirements/senior-architect-expansion-v3-identity-system-quality.out.md, docs/results/senior-architect-scan-v2-true-gaps-2026-07-11.review.out.arch.md）
- **前端 SPA 国际化（i18n）集成**：为 Login/Admin/Portal/Developer 四个内嵌 SPA 构建轻量级自研 JS i18n 引擎（外部化消息字符串、per-SPA 翻译 JSON、navigator.language 自动检测），渲染已端到端打通但从未被使用的 `ui_locales` 参数，翻译后端下发的同意页 scope 描述，预留 RTL 支持；通过 i18nFSInjector 中间件为 go:embed 静态 SPA 资产注入语言字典而不破坏不可变嵌入式文件系统，并以共享 `spa.js` 前端运行时统一提供 i18n 查找等公共能力。目前后端 i18n 基础设施完备但从未被前端消费，四个 SPA 仍为硬编码英文。（来源：docs/feature-spec-architecture-analysis-five-verified-directions.md, docs/superpowers/plans/2026-07-02-implementation-roadmap.md, docs/tech-lead-plan-system-resilience-5-gaps.md, docs/requirements/architect-fresh-scan-2026-07-11.out.md, docs/results/expansion-directions-v8-analysis.out.arch.md）
- **SPA/管理控制台无障碍访问性（WCAG 2.1 AA / ARIA）**：改进键盘导航、焦点管理与 ARIA live region，系统性补充 role、aria-label、aria-describedby 等无障碍标记（当前四个 SPA 合计仅有一处 aria-hidden），达到 WCAG 2.1 AA 标准并以 axe-core 验证。（来源：docs/tech-lead-plan-system-resilience-5-gaps.md, docs/requirements/senior-architect-expansion-2026-07-11.out.md）
- **JSON 序列化层优化（goccy/go-json）**：将代码库中 203+ 处非测试调用点使用的 `encoding/json` 替换为已作为间接依赖存在的 `goccy/go-json`，属低风险的即插即用性能与内存分配优化，需针对 `json.RawMessage` 边界情况验证兼容性。（来源：docs/requirements/expansion-runtime-infrastructure-analysis.out.md, docs/results/expansion-runtime-infrastructure-analysis.out.arch.md）
- **身份变更数据捕获（CDC）管道**：新增 ChangeEventBus SPI，为 ClientStore/UserStore/TenantStore/PermissionStore 的变更发出快照+差异（snapshot+diff）事件，支持 Kafka/MQTT 传输及重放/归档。（来源：docs/requirements/expansion-systemic-quality-horizon.out.md）
- **跨存储后端事务一致性**：为跨越多个存储后端（memory/SQLite/Redis/Postgres）的单一逻辑事务操作提供一致性保证。（来源：docs/requirements/global-architecture-scan-five-uncovered-high-value-directions-2026-07-11.out.md）
- **身份感知网络策略**：基于 IdentitySelector 生成网络策略（如 K8s NetworkPolicy、云安全组适配器）并与工作负载身份绑定；当前 `platform/netpolicy/types.go` 仅支持 CIDR/主机名，无身份相关字段。（来源：docs/requirements/senior-architect-expansion-v7-true-gaps-2026-07-11.out.md）
- **类型化 RAR 同意组件库**：为 payment_initiation、account_access、document_sharing、location_access 等 Rich Authorization Requests 授权详情类型构建专属前端渲染组件，未知类型统一使用通用 JSON 展示兜底。（来源：docs/results/expansion-edge-protocol-hardening-platformization.out.arch.md）
- **可插拔 LLM 集成（AI 辅助身份运维）**：新增可选、可降级的 OpenAI API 后端插件，用于自然语言策略查询等 AI 辅助身份运维场景，通过 SPI 隔离，失败时回退至结构化查询 UI。（来源：docs/results/expansion-platform-evolvability-meta-governance.out.arch.md）
- **主动-主动多区域复制（Active-Active Multi-Region Replication）**：提供 ReplicationTopology 抽象及按端点的 ReadConsistency 级别（LocalRead/LeaderRead），通过 Store 包装器将写操作转发至主区域，支持满足租户数据驻留合规要求的多区域 SSO 部署并降低全球访问延迟。（来源：docs/results/expansion-production-hardening-analysis.out.arch.md）
- **PostgreSQL 作为统一单一后端**：为 `infrastructure/postgres` 补齐 10 类缺失的临时/TTL 存储实现（auth_code、device_code、refresh_token、PAR、CIBA、revocation、jti_replay、MFA challenge、password_reset、account_lockout），使部署可完全运行在 Postgres 上而无需独立 Redis 实例。（来源：docs/results/expansion-strategic-gaps-2026-07-11.out.arch.md）

---

## 说明与后续建议

- 以上"提议中/未来方向"条目绝大多数来自 `docs/requirements/` 与 `docs/results/` 中的 AI 生成架构头脑风暴文档，
  尚未经过产品/工程正式评审排期，请勿直接当作已批准的路线图。
- 若需要工程实现层面的细节（具体代码改动、测试用例、安全评审意见），可在 `docs/results/` 对应主题的
  `*.out.arch.code*.md` / `*.tests.md` / `*.impl-plan.md` 文件中查阅，本报告未展开这部分内容。
- 报告生成方式：Workflow 编排 55 个 subagent（43 提取 + 12 合成）并行完成，全部一次性成功（0 失败）。
