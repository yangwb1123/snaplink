# ROADMAP

> **当前生效：v6.0（2026-07-11）。** 基于对 `github.com/snaplink/sso`
> 的又一轮多智能体全局复扫（六路视角 + 逐项对抗核验），从资深架构师 / PM
> 视角列出下一阶段投入产出比最高的 5 个扩展方向。v5.0 的 37 项已全部收口
> （见下节"自 v5.0 以来已落地"），v5.0 及更早为 superseded 历史，保留备查。
>
> 每项包含 **Why now**（这件事为什么比别的事更值得做）、**Scope**
> （拆到可独立 PR 的颗粒度）、**Edge cases / 当前实现具体短板**、
> **Sequencing hint**（与既有功能的耦合点）。
>
> 排序按"如果只能挑一件先做"的优先级。文末附 **边界情况 & 性能优化**
> 清单 + **优先级摘要**。

---

## v6.0（2026-07-11）—— 协议后端已"极完整"之后：认证合规化、产品化、韧性诚实化【取代 v5.0，以下 v5.0 为 superseded 历史】

> 2026-07-11 对全代码库的又一次多智能体并行复扫：六路视角（协议规范符合性 /
> 产品企业可售性 / 多副本一致性与 DR / 安全威胁模型 / 性能规模 / 研发质量与
> 采购合规）各自独立成结论，再对**每一条**候选做对抗式核验（默认"它大概率已
> 实现或已被 v5.0 波次落地"，逐项读码证伪）。**15 项候选全部通过核验为真缺口
> 或部分缺口，0 项被驳回**——其中多项由代码库自己的 package doc 显式标注为
> "out of scope (v2)"或计划性延期，佐证并非扫描遗漏。
>
> reframe：v5.0 把"后端协议面收口"作为主题；本轮确认**协议后端确已极完整**，
> 但恰好停在**可认证 / 可售 / 可信 HA** 的最后一公里前。v6.0 的五方向不再是
> "补更多协议原语"，而是：把深协议栈做到**能拿认证 listing**、把已建能力**包
> 装成自助可售的产品面**、开一条 **VC 新赛道**、把 HA/DR 的宣称做到**与代码一
> 致（诚实化）**、补上**采购安全问卷必答的纵深与供应链**。

### 自 v5.0 以来已落地（grep / 代码核验，v5.0 五方向全部收口）

v5.0 列为缺口或部分的 37 项，本轮在代码中确认**已全部交付**（其中 12 项在
2026-07-11 的多智能体实现波次中落地，均通过预算 / 架构 / oracle-leak 门禁 +
`-race`）：

- **方向① 产品/consent**：`ConsentStore` SPI（memory + sqlite）+ `prompt=consent`
  / 新 scope 重提示、"已授权应用"枚举/撤销；Hosted Login / Admin Console /
  终端自助门户 SPA（`interfaces/web/{login,admin,portal}`）落地首批 panel。
- **方向② B2B 企业化**：企业连接**运行时派发**——`/auth/login`
  `provider=<connection id>` 经 `domains/connections.AuthenticatorFactory`
  （静态 provider 名优先、跨租户守卫、未知/停用/跨租户/构建失败全部塌缩为同一
  `unsupported_provider` 反枚举，失败详情仅入 `connection_authenticator_build_failed`
  审计）；HRD；Okta JSON/NDJSON 迁移导入（bcrypt/PBKDF2 重组，不支持算法
  fail-loud）；计量 `TenantUsage.ActiveClients` + 审计 `tenant_id` 过滤。
- **方向③ OIDC/协议**：`claims` 参数端到端（`AuthCode.RequestedClaims` 贯穿全
  store → ID token / access token 投影，PAR 透传，discovery 广告）等一组
  conformance 单点。
- **方向④ 多副本一致性**：失效总线 **re-seed-on-recovery**（先 resubscribe，
  再 flush 缓存 + 对每个暴露 `SeedRevocations` seam 的 issuer 重播撤销 deny-set，
  才清 degraded；re-seed 失败保持 degraded、`/readyz` 红、逐次 `reseed_failed`
  审计）；etcd 签名密钥 registry `ReadyzCheck` 接入 `/readyz`；etcd LeaseID
  fencing 语义注释纠正（ADVISORY，非跨 holder 单调）。
- **方向⑤ 安全 / 性能 / 研发**：所有 X-Forwarded-* 消费点的
  `security.trusted_proxies` CIDR **peer-trust 门**（`shared/security/peertrust`：
  BaseURL / DPoP htu / mesh ext_authz / region resolver / mtls header / ratelimit
  keying）；JAR + federation 抓取的 **dial 时 SSRF 防护**（`SSRFGuardedDialer`
  阻断 DNS-rebind，错误串 oracle 稳定）；trust 评分器接线（`cfg.Trust` →
  `WithTrustScorer` + anomaly→trust 适配器）；审计异步 `batch_size` →
  `NewBatchAsyncSink`；dependabot 覆盖全部 14 个 go.mod。

### 本轮 15 项 → 五方向归类

协议规范 4、产品 4、多副本/DR 3、安全 3、性能 1（性能项并入文末清单）。下文
五方向按"如果只能挑一件先做"的优先级排序；每条缺口锚定具体 `file:line`，均经
对抗核验（0 项被驳回为"已实现"）。

---

**① 认证合规化：把已建的深协议栈做到"能拿 OIDF/开放银行认证 listing"**
—— *P0。SSF/Federation/FAPI 的核心逻辑都已实现，缺的只是规范定义的最后一公里
端点/策略 + CI 里的无头一致性套件。ROI 最高：小颗粒 M/L，直接解锁采购清单上的
认证勾选项。*

- **Why now**：本仓库的协议**后端**已极深（CAEP SET 签名/事件映射/重试/接收方
  撤销、Federation 信任链校验/metadata policy/constraints、FAPI 骨架 + DPoP +
  PAR + JARM + CIBA poll/ping 全在），但三处都**恰好停在可认证的控制面之前**，
  而 OIDF 的 Shared Signals / Federation / FAPI 2.0 认证、以及英/巴西/沙特/澳
  的开放银行 RFP，测的正是这层控制面与 alg 策略一致性。"OpenID Certified"是采
  购的字面勾选框，且任何一个已声明 profile 的回归今天只能靠人肉重跑浏览器 UI
  才能发现。
- **Scope**：
  - (a) **Shared Signals Framework 1.0 控制面**（L）：补
    `/.well-known/ssf-configuration` transmitter 元数据 + Stream Management
    API（创建/读/改/删 stream、加/减 subject）+ RFC 8936 poll 投递 +
    verification events；今天 `shared/core/consts.go:406` 仅有 `PathSSFReceive`，
    `protocols/caep/broadcaster.go:236-284` 是 push-only、endpoint 硬编码在
    `Client.Attributes[caep_receiver_endpoint]`——`protocols/caep/doc.go:55-60`
    自己把它列为 "Out of scope (v2)"。
  - (b) **OpenID Federation 1.0 补齐到 intermediate/trust-anchor 级**（M）：
    `mountFederationEndpoints`（`interfaces/sso/server_federation.go:294-317`）
    今天只挂 entity-config + fetch；补 §8.2 `/list`、§8.3 `/resolve`、§8.4
    `/trust_mark_status`、§8.5 historical keys——全是**在已实现的信任链/policy
    逻辑上加端点**，解锁"自建联邦 / 做 trust anchor"部署故事（SPID/CIE、EUDI、
    教育/医疗联邦替换 SAML metadata aggregate）。
  - (c) **FAPI 2.0 + CIBA 认证缺口闭合**（M）：`protocols/fapi/` 今天无 alg 禁
    用规则（`profile.go:54-84` 只有 par/pkce/sender-constrained 等），enforce
    模式仍**广告**并接受 RS256（`securityverify.AsymmetricJWSAlgs` 含 RS256，
    discovery override 不收窄 alg 列表 + auth-method 列表——见边界 E2/E3）；补
    FAPI2 SP crypto 策略 + enforce 模式 discovery/runtime 一致性 + CIBA
    push/user_code。
  - (d) **无头一致性套件进 CI + 归档认证 artifact**（M，与研发质量交叉）：把
    OIDC/FAPI/SSF conformance 做成 nightly 无头跑，回归即红——今天 11 个已声明
    profile 的回归无自动门。
- **Edge cases**：SSF stream 的 subject 增删必须租户隔离（E20）；Federation
  `/resolve` 输出不得泄露未授权 metadata；FAPI enforce 收窄 alg 后要同步
  discovery 的 `*_signing_alg_values_supported` 与 `token_endpoint_auth_methods_supported`，
  否则 RP 元数据校验被误导（E3）。
- **Sequencing**：(b) Federation 端点最独立（纯加端点，L→M）；(a) SSF 控制面复
  用现成 SET/重试/撤销机具（L）；(c)(d) 咬合——先补 alg 策略与 discovery 一致
  性，再让无头套件把它钉死。
- **价值·工作量**：value **high**（认证 listing = 采购门票）· effort **M**
  （多为"在已实现逻辑上加端点/策略"，非绿地）。

---

**② 产品化：把已落地的后端"包装成自助可售的 identity 平台"**
—— *P0 收入面。v5.0 落地了企业连接**运行时**与首批 SPA，但每个企业上线仍需平
台运维用 `admin:write` 代劳；FGA 有引擎无产品 API；SDK 只有 Go。这是"auth 库 →
可被非 Go 团队采购的平台"的临门一脚。*

- **Why now**：运行时刚落地（连接派发、HRD、跨租户守卫），但**自助**这一半仍
  空：`protocols/selfservice/selfserviceaccount/orgadmin.go` 的委派面只到
  members + invitations，无"客户 IT admin 自建 Okta/ADFS 连接 + 域名验证 + 品牌
  化"（WorkOS Admin Portal / Auth0 self-service-SSO 的旗舰动作）；FGA 有
  Zanzibar 引擎却只暴露一个 `admin:read` debug 端点
  （`platform/lifecycle/rebac/handlers.go:15-27`，`docs/openapi.yaml:5188` 明说
  "not a tuple-management CRUD surface"），唯一 tuple store 是 MemoryStore；管
  理台只有 7 个 panel（`interfaces/web/admin/index.html:42-61`）覆盖 ~102 条
  admin API 里的一小部分，break-glass / usage / connections / webhooks / keys /
  governance 全是 grpcurl-only；SDK 生成器 `cmd/gensdk` 的 `coreSurface` 只白名
  单了 239 个 operationId 里的 32 个。
- **Scope**：
  - (a) **自助企业 SSO 上线**（L）：委派给租户 admin 的 connection CRUD + 域名
    所有权验证 + 品牌化，复用已有的 `requireTenantAdmin` 门与连接 Store，零平台
    运维介入。
  - (b) **FGA 产品化**（L）：`/api/v1/authz/check` + `/authz/tuples`（client-
    credentials 门）+ 按仓库自身 SPI 教条补 sqlite `RelationTupleStore` peer +
    list-objects + 变更 feed，达到 OpenFGA/SpiceDB 平价。
  - (c) **管理台扩面**（XL）：按 demo 价值把 7-panel 扩向 break-glass（双人审
    批）/ DR modes / hash-chain 审计验证 / per-tenant usage / webhook 死信重放 /
    key rotation / RBAC 编辑器——骨架（auth/nav/CRUD/分页）已在 `app.js` 证明，
    扩面是 panel 复制。
  - (d) **GA 采纳计划**（M，与研发质量交叉）：拓宽 `coreSurface` 到全 admin/
    SCIM/webhook 面 + 发布 TS/Python SDK 到 npm/PyPI + Go 公共 API 稳定性门
    （镜像现成 buf-breaking 门的 apidiff）+ v1.0 里程碑 + Entra/Cognito 全量
    （clients/groups/orgs/MFA enrollments）导入器。
- **Edge cases**：委派面前端用短时 JWT 非长效 admin token（E12）；secret 永不
  回显；最后一个 admin 的 TOCTOU（E7）；邀请 email 规范化 + per-org 邀请配额/限
  流，否则平台 SMTP 变外发 spam relay（E8/E9）；FGA check 必须 fail-closed。
- **Sequencing**：(a) 复用刚落地的连接运行时，最独立（L）；(b) FGA 引擎已在、
  只加产品端点（L）；(c) 管理台 XL 但零后端起步、吃现成 REST；(d) SDK 拓面机
  械、可持续推进。
- **价值·工作量**：value **high** · effort **L→XL**（(a)(b) 两个 L 是最高 ROI，
  建议先做）。

---

**③ 可验证凭证（VC）新赛道：OID4VCI 发行者 + SD-JWT VC + Token Status List（后续 OID4VP）**
—— *P1 新 SKU。把 SSO 服务器变成凭证发行者，是现有加密机具上的一条新产品线，
由 eIDAS 2.0 / EUDI 钱包合规驱动。*

- **Why now**：全树对 `oid4vci|oid4vp|sd-jwt|credential_endpoint|wallet|status_list`
  零命中——这个规范族**完全缺席**；`protocols/oidc/metadata.go` 的
  `ProviderMetadata` 无 `credential_endpoint` / `credential_issuer` /
  `credential_configurations_supported`。而 eIDAS 2.0 强制欧盟 RP 在 2026-2027
  截止日接受 EUDI 钱包凭证，OIDF 跑 OID4VCI/VP 认证，竞品（Entra Verified ID /
  Ping / Keycloak OID4VC 扩展）都在发行。要件都已具备——JWE
  （`shared/security/jwe.go`）、pairwise subject（`shared/security/pairwise.go`）、
  DPoP + PAR + 密钥轮换——缺的只是 credential 端点、jwt proof-of-possession、
  `pre-authorized_code` grant、status-list 发布。（`docs/superpowers/plans/...
  :71` 已把它标为计划性延期"re-evaluate in 2 quarters"——本轮到点重估。）
- **Scope**：(a) OID4VCI 发行者最小闭环（credential 端点 + `pre-authorized_code`
  grant + jwt proof）；(b) SD-JWT VC 选择性披露编码；(c) Token Status List 发布
  + 撤销；(d) 后续 OID4VP 验证者（钱包出示）。
- **Edge cases**：credential 绑定的 holder key 校验；status-list 的
  cardinality/隐私（不可成为跨 RP 关联信道）；pre-authorized code 单用 + 防重放
  复用现成 `DELETE RETURNING` 教条。
- **Sequencing**：(a)→(b)→(c) 为发行侧一条链；(d) OID4VP 是独立后续。整体 XL，
  故列 P1——是新产品线而非现有面的补齐。
- **价值·工作量**：value **high**（新 SKU + 合规刚需）· effort **XL**。

---

**④ 多副本韧性"诚实化"：让 HA / DR 的宣称与代码一致**
—— *P0/P1 韧性。今天多处"启用了但静默降级为 per-pod"，DR restore 静默丢失半个
控制面。这不是加功能，是把已宣称的能力做到可信。*

- **Why now**：三处"静默黑洞"：
  - **DR snapshot 只覆盖 6 类**（clients/users/roles/assignments/menus/netpolicy，
    `interfaces/snapshot/snapshot.go:36` `SchemaVersion="1"`）——**区域故障切换
    restore 静默丢失租户组织 + residency/suspension 策略、每一条企业 IdP 连接、
    以及所有 pairwise sub 映射**（最后一项是永久身份断裂：每个 RP 看到全新 sub、
    账号链接不可恢复地断开）。
  - **签名密钥不跨重启/故障切换续存**：pod 驱逐或滚动重启使该副本签发的所有未
    过期 access token 失效（`WithEd25519Key` 持久化 seam 已在
    `infrastructure/defaultimpl/ed25519_jwt_issuer.go:190-198`，但 cmd 从不
    config 接线）；崩溃副本的 lease 过期**瞬间**全队撤下其 adopted verify key，
    违反 widen-only 教条（E13）。
  - **backend 奇偶不全 + operator 不拦静默降级**：多副本今天需 redis+postgres+
    etcd 同时在场，任一缺腿即静默把某功能降级为 per-pod（**包括本周旗舰的企业连
    接**）；`cluster.bus.backend=memory` 却能满足 coordinated-cutover /
    cross-replica-revocation 的 fail-closed 启动门（`build_app_cluster.go:182-190`
    只查 `bus!=nil`，E14）；redis 无 pub/sub `cluster.Bus`，mqtt bus 未 config
    暴露（`infrastructure/mqtt/doc.go:15-31` 自己说明）。
- **Scope**：(a) **snapshot schema v2**（L）：覆盖 tenants / connections /
  pairwise subjects / MFA enrollments，经现成 `ErrUnsupportedRestore` seam 做
  per-category 能力协商，密封机具已在；(b) **签名密钥续存**（M）：可选密封软件
  密钥持久化（复用 snapshot sealer）+ EventKeysRemoved 的 widen-only 延迟 drop
  （镜像 coordinated-rotation 的 deadline 延期）+ DR 公钥托管；(c) **HA backend
  奇偶 + operator v2**（XL）：redis pub/sub `cluster.Bus` + 暴露 mqtt bus +
  postgres/redis 连接 store + postgres refresh/metering backend，配 sso-operator
  v2 拦截静默 per-pod 降级并调度 snapshot/DR 演练。
- **Edge cases**：snapshot restore 必须发 `KindClientChange`/`KindDiscoveryReload`/
  `KindAuthzPolicyChange` 总线失效，否则 peer 服务陈旧缓存到 TTL（E16）；
  `KindTokenRevoked` 今天把**完整活 bearer** 写进 etcd keyspace，会进 DR 备份，
  应改传 digest（E17）；redis 异步复制会在 Sentinel/Cluster 故障切换时复活已消费
  的 auth code / 丢失 refresh-family kill（E18）。
- **Sequencing**：(a) snapshot v2 最独立、身份断裂最痛，**先做**（L）；(b) 密钥
  续存次之（M，seam 已在）；(c) backend 奇偶 + operator 是 XL 长跑。
- **价值·工作量**：value **high**（"HA/DR"宣称的可信度）· effort **L→XL**
  （snapshot v2 的 L 是最高 ROI 起点）。

---

**⑤ 安全纵深与供应链：采购安全问卷/红队复审的下一批必答**
—— *P1 采购门。DB 泄露即全量 token 明文、检测不联动响应、供应链无 provenance
——三条都是安全评审/政府采购的字面问项。*

- **Why now**：
  - **DB 泄露无遏制**：refresh token / auth code / device code 在每个持久 store
    **逐字明文**作为查找键存储（`infrastructure/defaultimpl/sqlite/
    refresh_tokens_schema.go:28` 裸 `token TEXT PRIMARY KEY` + 明文 INSERT；auth
    code 同）——偷到 SQLite 文件/Redis 快照/DB 备份即拿到每个活 token，无需破解，
    且 refresh-family 轮换检测被绕过（偷到的 token 就是存的值）。Okta/Auth0/
    Keycloak 都 hash-at-rest。
  - **检测不联动响应**：一个 critical `tokenanomaly` Finding（impossible travel，
    `detect.go:55`）终止于 `FindingStore.Add` + 一个 metric hook，唯一消费者是只
    读的 `GET /api/v1/admin/tokens/suspicious`——**看见了却不自动做任何事**，是红
    队报告的头号 finding。
  - **供应链无 provenance**：`slsa|provenance|attest` 全树零命中；`.goreleaser.yaml`
    生成 SBOM 并签名却从不 attest，扫描器全非强制（critical CVE 照发）。EO
    14028 / SSDF 要求 SLSA Build L3 provenance + 签名 SBOM attestation。
- **Scope**：(a) **token 机密静态化**（XL）：查找键 HMAC-SHA256（部署级 pepper）
  + 行 blob 可选信封加密，覆盖 refresh/authcode/device 及次级 secret（nonce /
  requested_claims / amr / acr / sid 明文列，E22）；(b) **异常→遏制闭环**（L）：
  opt-in 异步响应器（critical finding → CAEP session-revoked SET + refresh-family
  `DeleteFamily` + 下次使用强制 step-up），**严格 OFF 同步 auth 路径**以保异常检
  测不喂 auth 决策的不变式；(c) **供应链到 SLSA-provenance 级**（M）：build
  provenance + SBOM attestation + 强制 vuln 门 + SHA-pin actions + 全 artifact
  覆盖。
- **Edge cases**：token hashing 要保持 oracle-leak 不变式（未知/已消费仍塌缩为
  `invalid_grant`）；异常响应的 CAEP 撤销必须先解析租户再推，否则跨租户共享 sub
  泄露撤销信号（E20）；redis 限流 fail-open 会被针对性 Redis DoS 关掉全部限流
  （E21）。
- **Sequencing**：(b) 异常→遏制闭环最独立、红队价值最高（L，复用 CAEP 发射器 +
  撤销机具）；(c) 供应链多为流水线补齐（M）；(a) token 静态化 XL、跨切但采购可
  售"defense-in-depth"。
- **价值·工作量**：value **high** · effort **L→XL**（(b) 的 L 是最高 ROI 起点）。

---

### 边界情况 & 性能优化（持续清单，sprint-filler）

> 颗粒度不足独立方向；每条锚定具体代码位置。本轮 36 边界 + 27 性能，摘其要。

**性能 / 热路径**（本轮新发现，含 v5.0 性能方向未落地的三个 headline）

- **验证过的 client-secret 摘要缓存**（高，M）：`client_credentials` M2M 是生产
  最高 QPS grant，每请求跑 bcrypt（`server_token_clientauth.go:206` +
  `shared/security/client_secret.go:19`）烧的是服务交互式登录的 CPU；补 opt-in
  正向验证摘要缓存（SHA-256(client_id,secret) 命中即跳过 bcrypt），负结果永不缓
  存以保 fail-closed，evict on rotate/update/`KindClientChange`——约 1000× 降本。
- **SQLite 读池拆分**（高，M）：热 store 池 `SetMaxOpenConns(1)`
  （`shareddb.go:44`）；WAL 原生支持 N reader + 1 writer，加第二个只读
  `*sql.DB`（MaxOpenConns=NumCPU）供 Get/List/Inspect，写仍单连接，读吞吐倍增、
  零语义变化。
- **全流程 benchmark 套件 + per-backend 容量模型**（中，M）：今天大量热路径无
  benchmark，无法回答"这个 backend 每秒扛多少"。
- **`ClientStoreCache` 命中即 alloc-free**（中，M）：每次缓存命中深拷整个 client
  （8 slice + JWKS + Attributes map，`servercache/server_client_cache.go:200-284`）
  于 >1k QPS 路径；改为发不可变共享快照（copy-on-write）。
- **`AsymmetricJWSAlgs()` 每次验证 alloc 新 map**（中，S）：
  `jwks_verify.go:413` 每次返回新 6-entry map，DPoP/JAR/private_key_jwt 每请求都
  调；换成冻结只读 lookup。
- **CAEP 广播每 client-event 一个无界 goroutine + per-event `ListByTenant`**
  （中，M）：`broadcaster.go:265-282` 租户级撤销对上千 client 生成上千并发签名+
  HTTP goroutine；补 worker pool + 缓存 per-tenant receiver（`KindClientChange`
  失效）。
- **metering `Usage()` 每次 5 条串行 COUNT + `TopTenants` 无缓存 GROUP BY**
  （中，M）：`domains/metering/sqlite/aggregator.go:69-159` 打的
  `audit_events` 只有单列索引；补 `(tenant_id,type,ts_unix_ns)` 复合索引 + 每日
  rollup / 短 TTL body 缓存。
- **失效总线恢复"flush-the-world"**（中，M）：etcd bus Subscribe 总从当前 revision
  起 watch（`platform/cluster/etcd/etcd.go:147` 无 WithRev），每次抖动触发全队冷
  缓存 herd（`server_extensions.go:461-491`）；持久化 last-seen revision、只重放
  漏掉的事件。
- **SQLite 限流器每请求 BEGIN IMMEDIATE 写事务**（高，M）：
  `interfaces/ratelimit/sqlite_limiter.go:49` 全局写锁串行化所有流量；批量/合并
  或热桶移到 Redis 限流。
- **SPA 资源在中间件栈外用 `http.FileServerFS`**（中，S）：`server_routes.go:462`
  绕过 `WithCompression`，embed.FS 零 ModTime 压掉 Last-Modified——每次访问未压
  缩重下全量；mount 时预算 gzip + 强 ETag。
- 其余（redis pipeline `Issue`/`Consume` 折 RTT、refresh_tokens 无后台 GC、SCIM
  list 全表扫、批量 introspect 串行验签、metrics 标签随 kid/tenant 单调增长等）
  见完整清单。

**安全 / 正确性边界**

- **X-Forwarded-Host 租户解析仍无条件信首跳**（中，M）：
  `domains/tenant/middleware.go:188` 未接 v5.0 落地的 `peertrust` CIDR 门，直连
  origin 可伪造租户路由（E23）。
- **审计 IP 富化信首跳 XFF**（中，M）：`platform/audit/handler_helpers.go:123`
  取第一跳 XFF 写进 hash-chain 审计，攻击者可选源 IP 毒化取证归因（E24）；接
  `peertrust` 记 `RealClientIP`。
- **`/token` Idempotency-Key 在客户端认证前按裸 header 命中重放**（高，M）：
  `interfaces/sso/server_token.go:49` 在 `authenticateTokenClient` 前跑、键为裸
  header 值——任何调用者拿别的 client 的 key 就能领到那个 client 的 token 响应；
  键绑定到已认证 `client_id`、仅认证后重放（E26）。
- **device-verify `user_code` 无暴力节流**（中，M）：`server_device.go:253` 对攻
  击者输入 `GetByUserCode` 无 per-bearer/IP 上限，user code 又短，敌意但已认证用
  户可枚举劫持他人待授权（E19）。
- **最后一个 admin 的 TOCTOU**（中，M）：`orgadmin.go:123-140` 先 `ListByTenant`
  读、后 `Remove`，两个并发 DELETE 都看到对方仍在、都成功，组织永久无 admin
  （E7）；需原子守卫或 per-tenant 串行化。
- **discovery doc 缓存按攻击者变化的 Host 无界增长**（中，M）：
  `server_discovery_config.go:68` 每 `requestBaseURL` 一条，`sync.Map` 仅同键再查
  才淘汰——唯一 Host 洪泛涨到 OOM（E25）；加 max-entries/LRU 或 Host 白名单。
- 其余（RFC 8628 device endpoint 未进 discovery、RAR 不进 introspection、
  `prompt=create` 未识别、导入器静默导入不可登录用户、billing 过计数、CI
  workflow 语法/CGO/skipDirs 门洞 E31-E33、九个 fuzz 靶无调度跑等）见完整清单。

### 一句话优先级

**①(认证合规化：SSF 控制面 + Federation resolve/list + FAPI2 alg 策略，一组
M/L 直接换认证 listing) 与 ②(产品化：自助企业 SSO 上线 + FGA 产品 API 两个 L
先行，管理台/SDK 长跑) 并行驱动"可售"面 → ④(韧性诚实化：snapshot schema v2 的
L 最先，闭合区域故障切换的身份断裂黑洞；签名密钥续存次之) → ⑤(安全纵深：异常→
遏制闭环 L 红队价值最高，供应链 provenance M，token 静态化 XL) → ③(VC 新赛道
XL，新 SKU 但可延后到 eIDAS 截止日临近)。** 性能清单中**验证过的 client-secret
摘要缓存**、**SQLite 读池拆分**、**SQLite 限流器每请求写事务**三项是高优先
sprint-filler。**横切诚实说明**：本轮 0 项被驳回，多项由代码库 package doc 自己
标注"out of scope (v2)"或计划延期——即协议后端确已极完整，v6.0 是"把已建能力做
到可认证 / 可售 / 可信"的收口，而非补更多协议原语。

---

## v5.0（2026-06-11）—— 后端协议面收口后的下一阶段【已被 v6.0 取代；取代 v4.0，以下为 superseded 历史】

> 2026-06-11 对全代码库的一次多智能体并行复扫：六路视角（协议 / 规模
> 性能 / 多副本集群一致性 / 安全威胁模型 / 企业产品 / 研发体验与质量
> 基建）各自独立成结论，再对**每一条**候选缺口做对抗式 grep 核验
> （默认"它大概率已实现"，逐项读码证伪）。37 项候选全部通过核验为
> **真缺口或部分缺口，0 项被驳回为"已实现"**——说明本仓库的协议/安全
> 后端面确已极完整，剩余高价值工作**不再是更多协议 feature，而是把已建
> 好的能力包装成可售产品、补齐企业化与一致性、并通过采购侧的合规/质量
> 门禁**。仍沿用 Why now / Scope / Edge cases / Sequencing 体例。

### 自 v4.0 以来已落地（grep / 代码核验，v4.0 五方向几近收口）

v4.0 列为"仍空白/部分"的项，本轮在代码与 AGENTS.md 中确认**已交付**：

- **方向① 签名密钥治理**：`kms/{awskms,gcpkms,azurekeyvault,pkcs11}` +
  `defaultimpl/vaulttransit` 五个具体外部签名 peer；same-kid 多副本
  **deadline 协调翻转**（`WithCoordinatedKeyRotation` /
  `cluster.KindSigningKeyRotation`，fail-safe 只 widen verify 窗）；聚合
  可观测（`sso_signing_key_adoption_errors_total`、adoption-loop 纳入
  `/readyz`）。
- **方向③ SAML 2.0**：`saml/` 子模块全 SP+IdP、SSO+SLO（XSW/证书 pin/
  ACS 白名单/SSRF 门齐全）。
- **方向④ CAEP / RISC**：`caep/` 双向（transmitter + `/ssf/receive`
  receiver）。
- **方向⑤ Redis 后端**：`redis/` 子模块覆盖全 ephemeral 热路径
  （session/refresh+family/authcode/par/jti/ratelimit/device/mfa/ciba）。
- **集群视角 C① 网格身份数据面**：HTTP+gRPC `ext_authz`（`mesh_authz.go`
  + `extauthz/`）、SPIFFE JWT-SVID token-exchange、去中心化 authz
  policy-bundle 导出，全部落地。
- **C② 控制面韧性（部分）**：跨副本 access-token 撤销广播
  （`WithCrossReplicaRevocation`）、可选 JTI fail-closed
  （`WithJTIReplayFailClosed`）、client-store TTL 缓存 + bus 失效、per-tenant
  有界指标、body-limit 安全默认、CIBA ping recover+超时、anomaly per-detector
  超时、refresh 家族轮换速率限制。

**v4.0 唯一整体未动的方向 = ②（Admin Console + 终端自助门户，仍零前端）**
——本轮把它扩成 v5.0 方向①，并补上一个本轮才 grep 实证的硬缺口：**consent
记录存储根本不存在**（不止是"没 UI"）。

### 本轮 37 项 → 五方向归类

协议/正确性 7、产品 8、集群一致性 6、安全 8、性能 4、研发质量 4。下文五
方向按"如果只能挑一件先做"的优先级排序；每条缺口锚定具体 `file:line`，
均经对抗核验。

---

**① 终端体验产品层：Hosted Login + Consent 存储 + 终端自助 + Admin Console**
—— *P0 产品旗舰。把已建好的后端能力"包装出来卖"；"auth 库 → identity
平台"的临门一脚。v4.0 方向②的延续 + consent 硬缺口。*

- **Why now**：`/auth/login` 是**纯 JSON 契约**——返回 token JSON、error
  JSON 或 `{error:mfa_required,...}` JSON（`handler.go:98-303`）；SDK 唯一
  吐出的 HTML 全是机器自提交管道（`oidc/form_post.go:55`、`oidc/jarm.go:156`、
  FCL iframe `server_extensions.go:1740`），**无任何托管登录页 / consent 屏 /
  MFA 挑战页 / 改密页 / 品牌化**。源码自己承认：`handlers.go:2318` "the RP
  is responsible for the interactive flow"，discovery 只敢声明
  `prompt_values_supported=["none"]`。**每个集成方都得自建、自保、自本地化
  一套登录/MFA/consent 前端**（还得自己把 PKCE、step-up replay、错误处理做
  对）——这是对 Auth0/Okta/Keycloak/Cognito 的最大单点差距，常在采购首屏被
  直接筛掉。
- **Scope**：
  - (a) **Consent 记录存储（本轮新实证的硬缺口，先做）**：`prompt` 被解析
    但**只有 `prompt=none` 被消费**（`oidc/prompt.go:50` 仅 `PromptHasNone`），
    `ErrConsentRequired` 是**声明即死代码**（`core/consts.go:383`，零调用），
    全树**无 `ConsentStore`/grant 记录/per-user-per-client 授权持久化**
    （grep 0 命中）；scope 仅按 `Client.AllowedScopes` 授予
    （`oauth/scope.go:80`），用户从未被询问、从未被记录同意。补一个 hexagonal
    `ConsentStore` SPI（memory+sqlite）+ "honor `prompt=consent`/新 scope
    重提示" + "已授权应用"枚举/撤销——GDPR 合法性依据所必需。
  - (b) **Hosted Login SPA**（`web/login/`，可选托管模式）：登录/MFA/consent/
    改密/账户选择页，吃租户 `Branding`（`tenant/tenant.go:73` 已存但从未被
    任何渲染器消费）做品牌化；以 form-post→`/auth/login` JSON 桥接，零协议
    改动。
  - (c) **终端自助门户**（`/me` 入口）：`SessionManager.ListByUser`
    （`core/spi.go:121`）现仅接 admin RPC（`grpcserver/admin_tokens.go:58`，
    `admin:read` 门），无"看我的会话 / 登出此设备 / 全端登出 / 我的授权应用 /
    Passkey·TOTP 自助启用与解绑 / 改密重置"。（注：粗粒度"全端登出"已存在
    = `POST /token/revoke-all`，凭自身 bearer，但需 `RefreshTokenSubjectIndex`
    扩展。）
  - (d) **Admin Console SPA**（`web/admin/`，dogfood `client_id=
    sso-admin-console`）：全管理面今天**仅 gRPC + REST gateway**
    （`grpcserver/admin_*.go`，无 `go:embed`/FileServer/`web/` 目录），
    help-desk / IT-admin 人设无法用 grpcurl 运维。首批 panel 按 demo 价值：
    Dashboard / Sessions（一键吊销）/ Audit（facet 过滤+导出）/ Clients /
    Users-Roles / Compliance（GDPR 按钮 + hash-chain verify）。
- **Edge cases**：前端 auth 用短时 JWT + refresh（非长效 admin token）；
  secret 永不回显（仅显"已轮换"）；多租户权限隔离
  （`admin:read.tenant.{tid}` vs `.global`，wildcard matcher 可表达，需把
  tenant context 注入权限检查）；consent 记录的撤销需联动 §④ CAEP 向 RP
  广播；自助门户必须强制"用户只能操作自己的数据"（现有 session/user RPC 全
  是 admin 门，需新建 per-user 授权门）。
- **Sequencing**：(a) consent 存储是纯后端、可独立先交付（L）；(b)(d)
  前端并行（XL，零后端起步，吃现成 REST gateway）；(c) 自助门户复用 (a) 的
  ConsentStore + 现有 session API（L）。
- **价值·工作量**：value **high** · effort **XL**（其中 (a) consent 存储
  L、是合规刚需且纯后端，建议**最先做**）。

---

**② B2B 企业化：per-org 上游 IdP 连接 + Home-Realm Discovery + 迁移导入 + 用量计量**
—— *P0/P1 产品。让"为 B2B SaaS 而建"的 tenant 模型真正能卖给企业。*

- **Why now**：`Tenant`（`tenant/tenant.go:28`）只带 id/slug/status/residency
  字段，**没有任何到本租户上游 IdP（SAML/OIDC connection）的绑定**；上游联邦
  仅以**全局、按 `?provider=` 选择**的形态存在（`authenticators/
  oidc_federation.go`、`sso.go:43` 单一扁平 `map[string]Authenticator`）。于是
  B2B SaaS 的定义级能力——"Acme 员工走 Acme 的 Okta、BigCo 走 BigCo 的 ADFS，
  按邮箱域自动路由"——**无一等模型**（`tenant/tenant.go:68` 的 Domain 是
  hostname→tenant 多域托管，非 email-domain 路由）。这是 Auth0 Organizations /
  WorkOS / Keycloak realms 的核心卖点，缺它则 tenant 模型空有骨架。
- **Scope**：
  - (a) **企业连接（Enterprise Connections）**：`Tenant` 增 `Connections`
    （每条 = 上游 SAML/OIDC 配置）；运行期按 tenant 实例化对应 authenticator
    （复用现成 `oidc_federation` + `saml/` SP）。
  - (b) **Home-Realm Discovery 路由**：email-domain → connection 解析器
    （登录前置），把"用户在哪个 org"映射到"走哪个上游"。
  - (c) **迁移/导入工具**：今天 `UserProvider` 仅单条 `CreateOrUpdate`
    （`core/spi.go:24`），`core.User` **无密码 hash 字段**
    （`core/types.go:18`），唯一内置 verifier 是 bcrypt-only 且按用户 YAML
    逐条种入（`cmd/.../main.go:4380`）——**无批量导入、无"首登懒迁移"
    （旧 hash 校验通过后透明 re-hash）、无 hash 兼容矩阵**。补 Auth0/Okta/
    Keycloak 导出的 bulk import CLI + 多格式 verifier + lazy-migration shim。
    这是企业"不强制全员改密就能迁过来"的第一问。
  - (d) **per-tenant 用量计量/报表**：`tenant.go:3,12` 自述为"billing
    relationship"，却**无计量/配额/MAU/活跃 client 报表**（grep
    `quota|metering|seats|mau` 0 命中）；`audit.Query` 连 tenant 字段都没有
    （`audit/query.go:14`），facet 显式排除 per-user（`audit/facets.go`）。补
    一个 per-tenant 用量聚合 + 报表/导出 API（计费、套餐限额、给客户看自己
    用量所必需）。
- **Edge cases**：connection 的证书/密钥轮换；HRD 对未知域的兜底
  （回退到默认 connection 或拒绝）；导入的 hash 格式枚举需 fail-loud 拒未知
  格式（现 bcrypt verifier 已这么做）；计量的基数控制（沿用 §5 有界标签 +
  "other" 桶）。
- **Sequencing**：(a)(b) 一个 epic（connection 模型 + HRD，L）；(c) 独立可
  并行（L）；(d) 独立（L，依赖 audit 增 tenant 维度）。
- **价值·工作量**：value **high**（(a)(b)）/ **medium**（(c)(d)）·
  effort 各 **L**。

---

**③ OIDC 一致性与 Token 正确性收口：通过认证套件与 FAPI 采购**
—— *P1。多为 S/M 颗粒、单点高 ROI；企业/FAPI 采购会跑 conformance 套件
逐项验，"声明了却不兑现"是采购陷阱。*

- **Why now**：协议面虽全，仍有一组**会被认证套件直接标红、或在 FAPI/金融
  级部署集成时才爆**的正确性缺口；多数极小、却是硬互通阻断。
- **Scope（按 ROI 排）**：
  - (a) **id_token 缺 `at_hash`**（S，conformance 阻断）：三个 issuer 的
    id_token payload 均无 `at_hash`，`oidc.IDTokenRequest` 连 access token
    入参都没有（`oidc/types.go:14`、`defaultimpl/ed25519_jwt_issuer.go:510`）。
    OIDC Core §3.1.3.6 在"同响应返回 access_token"时**要求** `at_hash`；严格
    RP（认证套件常开）会拒登。补 `sha256` leftmost-128 即可。
  - (b) **`ssoclient/remote` 验签器硬编码 EdDSA-only**（M，与 FAPI 故事自相
    矛盾）：`ssoclient/remote/auth.go:98` 对非 EdDSA 直接 `unsupported alg`，
    JWKS 缓存只能解析 OKP（`jwks.go:22`）。但 server 全支持 es256/rs256/ps256
    （`config.go:728` 称 es256 为"the common FAPI choice"），AWS/Azure KMS
    更**不支持 Ed25519**。选了 FAPI 的 ES256 或任何 KMS peer 的买家，会在集成
    时发现官方 remote client 无法验签。直接复用已在树的
    `security.VerifyCompactJWS`（多 alg）即可。
  - (c) **`auth_time` 在 code 流盖的是兑换时刻而非认证时刻**（M，OIDC Core §2
    偏离）：`oauth.AuthCode` 不存 AuthTime/ACR/AMR（`oauth/auth_code.go:25`），
    `/token` 兑换时用 `time.Now()` 盖 `auth_time`（`handler.go:1513,1558`）。
    RP 据 `auth_time` 做 `max_age`/step-up 会被误导。给 AuthCode 增字段携带真实
    登录时刻。
  - (d) **`acr_values`/`max_age`/`prompt=login` 解析但不强制 + `AchievedACR`
    字段不存在**（L）：交互式 `/auth/login` 只消费 `prompt=none`；`acr_values`
    转发给 authenticator 却从不强制（`handler.go:539`），签发的 token `acr`
    恒空；`core/types.go:650` 注释承诺的 `AuthResult.AchievedACR` **根本不存在**
    （grep 仅注释）。补 AchievedACR 字段 + 交互流 max_age/essential-acr 强制。
  - (e) **AMR 被压成单一 provider id**（S，RFC 8176）：所有签发点硬编码
    `AMR:[]string{provider}`（`handler.go:832,910,1514,1559`…），从不读
    `result.AuthMethods`（grep 0 命中）；做过 MFA 的 step-up 仍发
    `amr=["password"]`，下游 step-up/风控失真。MFA/直登路径上 `result`
    在作用域内，线进去即可（auth_code/refresh 路径需 AuthCode 增字段）。
  - (f) **`claims` 参数验形却不投影/不强制，discovery 硬编码
    `claims_parameter_supported:true`**（M，采购陷阱）：`RequestedClaims` 被
    线进 `AuthRequest`（`handler.go:541`）后**无任何消费者**；essential-acr
    step-up 请求被静默忽略。要么兑现（投影 requested/essential claims），要么
    别声明 true。
  - (g) **refresh 并发双提交无 grace 窗 → 击杀整个 family**（M）：rotation
    严格单用（memory delete / sqlite `DELETE…RETURNING` / redis `GETDEL`），
    多标签 SPA、移动端冷启竞态、丢响应后重试**与盗用重放无法区分**，benign
    双提交直接 `DeleteFamily` 触发登出风暴。补有界 reuse-grace（N 秒内对前一
    叶 token 返回同一已铸后继），不削弱 BCP §4.13。
- **Edge cases**：at_hash 的 hash 须随 id_token 签名 alg 选（ES256/RS256/
  EdDSA→SHA-256）；grace 窗须与"真正过窗重放"区分；AchievedACR 须 fail-safe
  默认空。
- **价值·工作量**：value **high**（整组 conformance+FAPI 阻断）· effort 单点
  **S–M**，整方向 **M**。**(a)(b)(e) 三个 S 项建议立刻做**。

---

**④ 多副本数据面韧性：消除静默的集群正确性与回滚黑洞**
—— *P1 运维/安全。这些缺口**静默失败且 `/readyz` 仍绿**——正是 SRE 在分区/
回滚演练里才发现的那类；多处的自愈范式已在树内存在（聚合 loop），不对称读作
疏漏。*

- **Why now**：本轮集群视角抓到一组"看着健康、实则对控制面失聪 / 令牌作废
  复活 / 回滚踩雷"的硬缺口，多数 fail-silent。
- **Scope**：
  - (a) **失效总线 etcd watch 死亡后不自愈**（M）：`StartInvalidationBus`
    （`server_extensions.go:2222`）裸 `for evt := range events`，channel 关闭即
    永久退出；etcd `Subscribe` 首次 `resp.Err()`（compaction/leader 变更/抖动）
    即返回且**从不重订阅**（`cluster/etcd/etcd.go:129`）；**无 `/readyz` 检查**
    （对比聚合 loop 有 `signing-key-aggregation`）。一次 etcd 抖动后该副本永久
    停止 honor 租户暂停、client 失效、协调轮换、**跨副本撤销**——而最严重的
    `KindTokenRevoked` **无 TTL 兜底**（其余缓存类有 TTL 收敛）。照搬聚合
    loop 的"degraded+审计+backoff+重订阅+re-seed+readiness"即可。
  - (b) **`signingkeys/etcd` KeepAlive 死亡静默作废自身公钥**（M，最隐蔽）：
    `Publish` 起 KeepAlive 后交给 `drainKeepAlive` = `for range ch {}`
    （`signingkeys/etcd/etcd.go:157,334`）；lease 过期（分区超 TTL/leader churn）
    后 channel 关闭，**无人重新 grant 或重发布**（`PublishSigningKeys` 仅启动
    与轮换时调）。该副本仍在用自己的 kid **签发**，但其公钥已从 etcd 删除 →
    对端 drop 其 verify key → **该副本签的 token 在全集群被拒**，且 `/readyz`
    全绿、无审计无指标。补 publish 侧 lease 健康监控 + 重 grant/重发布 +
    readiness。
  - (c) **跨副本撤销 deny-set 仅进程内、不持久、不重放**（L）：三个 issuer 的
    `revoked` map 仅内存（`defaultimpl/revocation_set.go`），无 sqlite/redis
    peer（不同于 session/refresh/jti 都有）；bus 仅向**当前在线**订阅者尽力
    扇出、无重放（`cluster/etcd/etcd.go:10` "never replays Events published
    before it joined"）；重启后 map 空、无 re-seed。**滚动重启/扩容期，被撤销
    但未过期的无状态 access token 在任一副本复活**——正是盗用 token 最值钱、
    pod 在轮换的窗口。补持久 deny-set peer + 启动 re-seed。
  - (d) **无 schema 版本护栏，回滚的旧二进制会对更新 schema 服务**（S，原语
    已存却没接）：`migrate.Run` forward-only；`migrate.CurrentVersion`
    （`migrate/migrate.go:265`，注释自述"a readiness gate that refuses to
    serve when the binary expects a newer schema"）**零非测试调用方**。canary
    回滚（最常见 DR 动作）今天静默对 forward-migrated DB 运行。各 backend 暴露
    其 slice 最大版本，cmd 比较 DB CurrentVersion > 最大 → boot error / readyz
    fail。
  - (e) **bootstrap fencing-token 是空壳 + 文档事实错误**（M）：
    `bootstrap/lock/lock.go:17` 文档承诺 `FencedTracker` 防 GC 停顿超租约的
    脑裂，但**该类型不存在**（grep 仅两处文档注释），`MarkApplied` 无 token
    入参、token 只被 log 从不比较；且 `etcd.go:12` 声称 LeaseID "monotonic"
    **事实错误**（etcd LeaseID 高位是 member id、按重启重播种，非单调）。要么
    实现带 token 的 `MarkApplied`，**要么（更诚实/更省）删掉 FencedTracker/
    单调 LeaseID 文档、改记 heartbeat-cancel + 幂等模型为实际保证**。
  - (f) **SQLite `ClientStore` 静默丢弃安全承重字段**（M）：sqlite clients
    schema 仅 10 列，`core.Client` 的 **JWKS（private_key_jwt/JAR 验签公钥）、
    AllowedResources（RFC 8707 受众域）、AllowedRequestURIs（JAR-fetch SSRF
    白名单）、RegistrationAccessToken（RFC 7592）、JWE alg/enc、Federation、
    PostLogoutRedirectURIs** 在持久化时被丢，重启后归零
    （`defaultimpl/sqlite/clients.go:23-35` vs `core/types.go:62-284`）。
    这是**操作者看不见的安全降级**。按 `migrate/` 范式追加列 + JSON blob 的
    v2 迁移。
- **Edge cases**：(a)(b) 的 readiness 要区分"干净 ctx 取消（正常停机）"与
  "watch/lease 死亡（degrade）"；(c) 的 re-seed 须 exp-bounded 不无限增长；
  (d) 须容忍 additive 迁移（仅在非 additive 时硬拒）。
- **价值·工作量**：value **high**（(a)(b)(c) 静默且安全相关）· effort
  **S–M**。**(d) schema 护栏是 S 且原语已在树，最先做。**

---

**⑤ 安全姿态与供应链 / 质量门禁：通过 SOC2 / Pentest 问卷**
—— *P1 安全/质量。SSO 是组织内最高价值靶标；多项是 CI 一行、信号极高；最
危险的第三方代码（SAML XML/DSig、KMS）今天无任何自动门。*

- **Why now**：AGENTS.md 反复以 FIPS/PCI/SOC2/FAPI 定位，但采购安全问卷直接
  问的几样（at-rest hash、SAST/SCA、审计完整性、供应链）恰恰缺位；且多是极
  低成本高信号补丁。
- **Scope**：
  - (a) **client secret 明文存储 + 非常量时间比较**（M）：`core.Client.Secret`
    /`RegistrationAccessToken` 逐字持久（`defaultimpl/sqlite/clients.go:26`），
    `ValidateSecret` 用裸 `!=`（`memory_clients.go:51`）——而同仓 RFC 7592
    token 已用 `security.ConstantTimeStringEq`（`oauth/handle_register.go:399`），
    原语在树却没用于机密客户端。DB/备份泄露即全量客户端冒充。补 hash-at-rest
    （bcrypt/argon2）+ 常量时间比较。
  - (b) **自助 DCR（RFC 7591/7592）创建/改/删零审计**（S）：`RegisterDeps`
    无 Recorder，`HandleRegister`/Put/Delete 成功**不发审计事件**
    （`oauth/handle_register.go`，oauth 包从不引用 Recorder）——而 admin 改
    client **有**审计（`grpcserver/admin_clients.go:117`）。铸/改/删可请求
    token 的凭据却无防篡改链记录。补 `EventClientRegistered/Updated/Deleted`。
  - (c) **无内建 trusted-proxy / 转发跳设施**（M）：XFF/X-Auth 消费者
    （`requestBaseURL`、ratelimit IP key、header-mTLS、region Header、mesh
    ext_authz）全**无条件信第一跳**，无 CIDR 信任集/跳数概念；AGENTS.md §2
    "edge MUST strip" 重复 6 次的负担全压给操作者；两处 `[TrustedProxies]`
    文档链接指向**从未实现**的伴生中间件（`ratelimit/middleware.go:64`、
    `security/header_client_cert_extractor.go:41`）。补
    `WithTrustedProxies(CIDRs, hops)`，各 extractor 统一消费。
  - (d) **CI 从不构建/竞态测试 10 个子模块**（S，最危代码无门）：`make ci`
    含 `ci-modules`，但 `.github/workflows/ci.yml` 只对**根模块**跑
    `go build/test ./...`（无 go.work → 不下探子模块）。`saml/`（crewjam XML/
    DSig，经典 XXE/XSW 面）、四个 `kms/*`、`redis/`、`ldap/`、`kerberos/`、
    `radius/`、`extauthz/`（共 ~58 测试文件）**从不被 CI 编译或测**，回归绿色
    合并。CI 显式进入每个子模块即可。
  - (e) **CI 无 SCA/SAST/镜像扫描**（S）：无 `govulncheck`（对 go.sum 的官方
    CVE 扫描）、无 CodeQL/gosec、无 `.golangci.yml`、docker job 无 Trivy/Grype。
    `govulncheck` 是一行 CI、信号最高。
  - (f) **Dependabot 仅覆盖根模块**（S）：`.github/dependabot.yml` 单条
    `directory:"/"`，gomod 不下探嵌套——10 个**承载最重最活跃 CVE 面**的子
    模块（aws/azure/gcp SDK、crewjam/saml、go-redis、gokrb5）零自动补丁。每个
    嵌套目录加一条即可。
  - (g) **JWT/JWS/aud 解析面零 fuzz**（M）：全树 `func Fuzz` 0；而最承重的
    解析（`security/jwks_verify.go` 手搓 dot-scan+base64、`audClaim` 两份独立
    string-or-array 反序列化、`oauth/bind.go`、federation trust-chain JWT
    走链）全是攻击者可控字节。凭据校验服务里"畸形 JWT panic = 远程 DoS、解析
    分歧 = 鉴权绕过"。补 `testing.F` 目标 + 语料。
  - (h) **无 benchmark/profiling/load-test 基建**（M）：全树 `func Benchmark`
    0、无 pprof 接线、无 k6/vegeta、无 `make bench`。卖 ">1k QPS / hot-path"
    却**无任何可跑的数**，也无回归护栏防未来分配/锁竞争退化。补 bench + pprof
    + 一个 load-test 脚本。
  - (i) **无导出的 `ssotest` 消费者测试夹具**（M）：真实链路夹具
    （real issuer + JWKS + token mint）困在 test-only `package ssotest`
    （`test/e2e_test.go:80` 不可被下游 import）；`ssoclient/dev` stub 又**恰好
    跳过签名/JWKS**。导出 `ssotest.NewServer(t, opts...)` 大幅降低集成成本。
- **价值·工作量**：value **high**（(a)(d)(e) 合规硬问 + 最危代码无门）·
  effort 多为 **S**。**(b)(d)(e)(f) 四个 S 项是本方向最高 ROI，建议立刻清。**

---

### 边界情况 & 性能优化（持续清单，sprint-filler）

> 颗粒度不足独立方向；每条锚定具体代码位置。本轮新发现。

**性能 / 热路径**

- **`MemoryLimiter` 每请求全 map O(N) prune + 单全局锁**（高，S）：
  `ratelimit/ratelimit.go:87` `Allow` 持单 `sync.Mutex` 后无条件
  `pruneLocked` 全 map 扫（`:129`）；默认限流器、位于中间件链最前对**每个
  请求**跑，而 N（活跃 key）正是其防御的撞库攻击所放大的——攻击期合法登录被
  串行化在 O(N) 扫后，**自成 DoS 放大器**。sqlite 兄弟已 `%64` 采样
  （`sqlite_limiter.go:204`），照搬 + 分片锁即可。
- **SQLite 无连接池调优 + 文档的 `busy_timeout` 是 driver no-op**（高，M）：
  全树无 `SetMaxOpenConns` 等；cmd 对同一 WAL 文件开 ~18 个独立 `*sql.DB`
  池（各默认无上限），WAL 仅一个 writer → `SQLITE_BUSY` 抖动。且
  `modernc.org/sqlite` **不认 `_busy_timeout` DSN 参**（只认
  `_pragma=busy_timeout(N)`，migrate.go:141 自己知道），而 config.yaml 全用
  失效写法。写池设 1 / 经现成 `WithDB` 共享一个调优过的池 + 真正用 `_pragma`。
- **`ClientStore`/`UserProvider`/permissions 无 Redis/cluster peer**（中，L）：
  Redis 只覆盖 ephemeral 单用 store；每次 `/auth/login`+`/token` 的
  `clientStore.Get`（`handler.go:148,253,318,1322`）与登录的 user
  **upsert 写**（`handler.go:638` `CreateOrUpdate`）在规模层仍落 SQLite 单
  writer/内存——选 Redis 逃离嵌入 store 的买家会意外。补 Redis `ClientStore`/
  `UserProvider` peer，或返指针的 copy-on-write 缓存避免每命中深拷。
- **JWKS 无服务端 body 缓存（仅 single-flight）**（低，S）：
  `ComputeJWKSDocument` 仅合并并发、每次串行 poll 重走 issuer + 重 marshal +
  重 sha256（`accessors.go:226`）；与 discovery 的 body+ETag 缓存不对称
  （federation 还缓存了同样的 issuer-JWKS 走查）。补 1-5s 有界 body 缓存。
- **审计无批量写路径**（低，M）：`Sink` 仅单条 `Record`；async worker 逐条
  drain，sqlite 每事件一条 INSERT（`audit/sqlite/sink.go:171`），hash-chain
  同步串行。一次登录发多事件，高 QPS 下单 writer SQLite 封顶审计吞吐，队列满
  则 drop-newest（合规风险）。补 `RecordBatch` group-commit。

**安全 / 正确性边界**

- **Federation/JAR SSRF 不在 connect 时复核解析 IP**（中，M，partial）：
  `validateFederationURL` 仅拒**字面** private/loopback IP，域名 DNS 解析到
  169.254.169.254/RFC1918 可过（`federation/fetcher.go:173`）；federation
  目标受攻击者影响（恶意 leaf 自报 authority_hints）且无白名单。补
  `net.Dialer.Control` 钩子对**解析后 IP** 复核 `isInternalIP`，闭合 DNS-
  rebind 窗（JAR 侧已有 `AllowedRequestURIs` 强缓解）。
- **无 per-subject 限流 / 横向撞库同步刹车**（中，M，partial）：限流 key 只
  client_id/IP，无 KeyBySubject；`BruteForceShadow` 只观测不决策。垂直分布式
  （多 IP 单账号）已被 per-account lockout 挡住；未覆盖的是**横向 spray**
  （每用户一次、铺开千用户）。`RiskScorer` seam 本可同步 Deny/RequireMFA，但
  内置 `RuleBasedRiskScorer` 不读 `IPFailureCounter`。补 KeyBySubject 或把
  IP-failure 计数接入软节流/强制 MFA。

### 一句话优先级

**①(consent 存储先行 + Console/门户进企业采购清单) 与 ②(B2B 连接+HRD，
让 tenant 模型真能卖) 并行驱动收入面 → ③ 一组 S/M conformance 单点
（at_hash·remote 多 alg·AMR 立刻做）通过 FAPI/认证采购 → ④ 多副本静默黑洞
（schema 护栏 S 最先，signingkeys lease 死亡与撤销复活次之）→ ⑤ 采购安全
问卷（DCR 审计·ci-modules·govulncheck·dependabot 四个 S 项立刻清）。**
性能清单中 **MemoryLimiter O(N) prune** 与 **SQLite busy_timeout no-op** 两项
是高优先 sprint-filler。**横切诚实说明**：①②是刻意的 SDK-vs-产品边界选择
（非 bug），但对"可直接运行的企业级 IdP"定位是真实的买家可见差距；③④⑤多为
小颗粒高 ROI、且多处修复范式已在树内存在。

---

## v4.0（2026-06-02）—— 全局复扫：交付物收口后的下一阶段【已被 v5.0 取代；取代 v3.1，以下为 superseded 历史】

> 2026-06-02 对全代码库的一次多维全局复扫（协议 / 安全密钥治理 / 规模性能 /
> 产品竞争 / 边界与技术债，五路并行 + 逐项 grep 核验）。**v3.1 及以下结论已
> 大量被落地，本节取而代之，作为当前生效的优先级。** 仍沿用 Why now /
> Scope / Edge cases / Sequencing 体例。

### 复扫确认的当前边界（grep 核验，非记忆）

**自 v3.1 以来新落地**（本轮在代码中确认 —— v3.1 多列为"仍剩/刻意不做"，已过期）：

- **per-tenant 签名密钥隔离**：`WithTenantTokenIssuer` → 每租户 issuer，覆盖
  access / id_token / JARM / userinfo / WebAuthn 全部签发面，未注册的租户
  issuer fail-closed，opaque 策略省略。
- **SCIM 2.0**（`scim/`）：Users + Groups CRUD + PATCH + RFC 7644 filter
  语法/求值；SCIM 属性存于 `core.User.Attributes` 的 `scim:` 命名空间，
  **无需富化核心 User 模型**（v3.1 把"先富化 User"列为前置，证伪）。
- **租户暂停的主动吊销**：`Server.RevokeTenantRefreshTokens` 经
  `oauth.RefreshTokenClientPurger` 按租户枚举 client 清 refresh；admin
  `SetTenantStatus`(→Suspended)/`DeleteTenant` 触发；best-effort + 审计
  `tenant_tokens_revoked`。（会话本就 user-scoped，按设计不按租户清。）
- **凭据健康度**：登录后（bcrypt 通过后，唯一明文触点）跑弱密码字典，
  fail-open、不阻塞登录、**绝不入 token**（`AuthResult.CredentialHealth`
  带 `json:"-"`），审计 `password_weak`/`password_compromised`。
- **无 leader 多副本 JWKS 公钥聚合**（`signingkeys/`，memory+etcd）：各副本
  发布自身签名公钥、verify-only 采纳对端公钥（全三 alg），JWKS+Validate
  服务全集而各副本仍只用自有私钥签发；opt-in nil-default 字节一致。期间
  **对抗审计抓到并修复了一个 CRITICAL 伪造漏洞**（`decodeRSAJWK` 接受
  e=1 致恒等验签）。这是 v3.1"方向① ActiveKID 多副本"的零依赖可自主子集。
- 另：CIBA ping 交付、per-endpoint body limit、SIGTERM 优雅停机、
  cross-issuer partial-revoke 审计、cross-replica `InvalidationBus`。

**仍为空白 / 部分**（逐项 grep 确认，构成下方五方向）：KMS/HSM **具体**
peer（仅 seam）、Admin Console + 终端自助门户（零前端）、SAML 2.0、CAEP/RISC
持续访问评估信号、Redis 后端、same-kid 多副本签名（需共享密钥材料）、
CIBA push/user_code、HIBP 网络校验。

### 排序后的 5 个方向

**① 签名密钥治理收口：KMS/HSM 具体 peer + same-kid 多副本一致 + 聚合可观测**
—— *P0，最硬合规门槛、最小剩余工作量。*

- **Why now**：四算法矩阵 + 运行时轮换 + 调度 + `{Algo}Signer` seam
  （`defaultimpl/cryptosigner` 桥接任意 `crypto.Signer`）+ per-tenant + 无
  leader 公钥聚合**已全部铺好**——唯独私钥仍裸存进程内存这一项，让
  FIPS 140-2/3、PCI-DSS、SOC2 Type II 在 RFP 第一页就筛掉。"地基全铺、
  只差一块砖"的最高 ROI 项。
- **Scope**：(a) `defaultimpl/awskms/`（`aws-sdk-go-v2` 的 `kms.Sign` +
  `GetPublicKey`，约 100-150 行），之后 `gcpkms`/`pkcs11`
  （YubiHSM/SoftHSM/Thales）同形——**置于 operator cmd fork / 独立子模块，
  核心 go.mod 零增**，与 etcd/push-transport 已验证的模式一致；(b)
  **same-kid 多副本一致**：轮换期经 `cluster.Bus` 广播
  `signing_key_rotation_{start,complete}{old_kid,new_kid,deadline}`，各副本
  延迟到 deadline 再同步翻转 active kid，消除 grace 期 kid 漂移（公钥聚合
  解决"验得了"，这一项解决"不漂移"）；(c) 补齐本轮 `signingkeys/` 聚合的
  运维盲点：采纳失败指标 `sso_signing_key_adoption_errors_total{peer}`、
  adoption-loop 存活纳入 readiness、watch 关闭/退出审计。
- **边界**：KMS sign 是网络 RTT（5-50ms，比 `ed25519.Sign` 慢三个数量级）
  → token TTL 拉长 + 进程内 `(kid,payload_hash)→sig` LRU + p99 熔断到本地
  fallback kid；JWKS ETag 改 `sha256(canonical(jwks))` 防 KMS 公钥字节序
  抖动；轮换 grace 重叠保留新旧 verify key。
- **Sequencing**：(a) awskms 单独可交付（1-2 周）；(b) same-kid 独立 sprint
  （复用本轮聚合 + cluster.Bus 底座）；(c) 可观测随 (a)(b) 顺带。

**② 运维与终端操作面：Admin Console + 终端用户自助门户**
—— *P0/P1：把已建好的能力包装出来卖；"auth 库 → identity 平台"的临门一脚。*

- **Why now**：后端能力本轮已极完整——admin gRPC/REST 全 CRUD
  （client/user/token/permission/tenant/snapshot/release）+ SCIM +
  compliance（GDPR export/erase）+ audit + per-tenant，**但面向人的操作面
  仍是 0**。竞品（Auth0/WorkOS/Stytch/Ory）卖的是"5 分钟 demo→生产，含
  dashboard + 报表 + GDPR 按钮"。无 Console = 进不了企业采购清单。**零后端
  改动起步**（吃现成 admin REST gateway）。
- **Scope**：(a) `web/admin/` SPA（Next.js + shadcn，与 Go 二进制 co-locate）
  首批六 panel 按 demo 价值排序：Dashboard / Sessions-explorer（一键吊销）/
  Audit-explorer（facet 过滤 + 导出）/ Clients / Users-Roles /
  Compliance（GDPR 按钮 + hash-chain verify）；Console 自身经本 SSO 登录
  （dogfood，`client_id=sso-admin-console`，`scope=admin:*`）；(b) 终端自助
  门户（同框架 `/me` 入口）：活跃会话 + 远程登出、Passkey/TOTP 自助启用、
  登录历史、"下载我的数据"（吃 compliance `Exporter`）；(c) 配套
  `audit.Query` facet 聚合返回（前端 filter 关键路径，唯一后端改动）。
- **边界**：前端 auth 用短时 JWT + refresh（非长效 admin token）；敏感字段
  绝不回显（secret 仅显"已轮换"）；大规模列表分页 + 搜索；多租户权限隔离
  （`admin:read.tenant.{tid}` vs `.global`，现有 wildcard matcher 可表达，
  需把 tenant context 注入权限检查）；审计时间戳 UTC 客户端本地化。
- **Sequencing**：facet（后端 1-2 周）→ Console 三 panel（前端 3-4 周）→
  自助门户（前端 2-3 周），前后端并行。

**③ 企业联邦补完：SAML 2.0（IdP/SP）**
—— *P1：SCIM 已落，SAML 是 RFP 表上仅剩会被直接筛掉的一行。*

- **Why now**：OIDC 上游联邦已全（5 provider）。SAML 2.0 仍是 30-40%
  政府/金融/传统企业 IdP（AD FS / PingFederate / Okta classic）的唯一语言。
  `core/consts.go` 已留 `TokenTypeSAML2` 常量但无 validator（token-exchange
  当前显式拒 SAML2 输出，`test/handle_token_exchange_test.go` 锁此行为）。
- **Scope**：`saml/` 包 —— Assertion 解析 + XML-DSig 验签 + 可选 xmlenc
  解密；HTTP-POST/Redirect binding；`/auth/saml/acs`（Assertion Consumer
  Service）→ NameID/AttributeStatement 映射进 `core.User`（复用
  `oidc_federation` 旁的 Authenticator 接入点）；`/saml/metadata`（SP
  元数据）；Single-Logout。
- **边界（关键取舍）**：**XML-DSig / C14N / xmlenc 在纯 Go 零依赖下手搓是
  安全雷区**（XXE、签名包装 wrapping 攻击、C14N 歧义）——应像 KMS peer 一样
  **引入经审计的 SAML 库（`crewjam/saml` 或 `russellhaering/gosaml2`）置于
  operator cmd 侧，核心 go.mod 不污染**。其余边界：assertion replay（接
  `JTIReplayStore`）、NameID format 路由（email/persistent/transient）、IdP
  多签名证书轮换、SLO binding。
- **Sequencing**：独立立项（≈4-6 周），不阻塞①②。先 SP 侧（消费外部 SAML
  IdP）再 IdP 侧（对外发 SAML，按需）。

**④ 持续访问评估：CAEP / RISC 共享安全信号**（OpenID Shared Signals）
—— *P1-P2：新晋差异化方向，把"事后审计"升级为"实时跨 RP 撤销"。*

- **Why now**：今天"立即跨 20 个 RP 撤销某用户"只能靠 token TTL 或各 RP
  各自调 `/revoke`。CAEP（Continuous Access Evaluation Profile）+ RISC 定义
  IdP 如何向所有持有该 subject token 的 RP **广播**撤销/风险/账户停用信号。
  本仓库底座**已就位**：`audit.Recorder` + `cluster.Bus` + 租户暂停 + 异步
  异常检测——缺的只是一个**面向外部 RP 的事件出口 + 订阅管理**。这是安全侧
  从"auth 库"迈向"identity 平台"的差异化（多数竞品也才刚起步）。
- **Scope**：(a) CAEP 形态事件（`{sub,iss,aud,jti,iat,txn,events{}}`）：
  `token_revoked`/`grant_revoked`/`account_disabled`/`session_revoked`/
  `risk_detected`；(b) 新 `audit.Sink` `CAEPSink` 向注册的 RP webhook 推送
  （订阅存于 client metadata）；(c) `POST /caep/events`（admin-scoped）+ RP
  webhook 注册/注销 admin RPC + 重试退避；(d) 与既有事件源接线：租户暂停→
  `account_disabled`、refresh 家族复用→`token_revoked`、anomaly critical→
  `risk_detected`。
- **边界**：重放去重接 `JTIReplayStore`；事件乱序 → 带 timestamp + RP 拒收
  早于本地状态的事件；webhook auth 用 mTLS 或签名 JWT；推送 best-effort
  （不阻塞主路径，失败进重试队列 + 审计）。
- **Sequencing**：(a)(b) 事件模型 + sink 一个 sprint；(c)(d) 出口 + 接线
  一个 sprint。

**⑤ 吞吐层：Redis 后端 + 热路径性能** —— *P2：正确性已完备，扩容课题，
按 QPS 需求触发。*

- **Why now / why not**：15+ store 的 SQLite peer 已保证**正确性**（含
  migrate + cluster.Bus）；Redis 的 ROI 是**吞吐（>1k QPS）** 而非正确性，
  代价是新有状态依赖——等真有高 QPS 客户再做。架构已就绪（每个 store 都是
  SPI，`WithXxxStore` 直接插，`defaultimpl/memory_*.go` 注释已明指 Redis）。
- **Scope**：(a) 热路径 store 的 Redis peer（Session / RefreshToken+family /
  JTIReplay / RateLimit / AuthCode / PAR / MFAChallenge / CIBA）：单用经
  `GETDEL`/Lua 原子、family 经 `HSET`、索引经 `ZSET`、TTL 经 `EXPIRE`；
  (b) 顺带清下方热路径清单项。
- **边界**：Lua 保证 `check+mark` 原子（family tracker）；跨区复制延迟
  （A 区发的 refresh 在 B 区消费的 stale 检查）；OOM 用 `noeviction` +
  fail-loud（绝不静默驱逐 auth code）；网络分区下 `/token` fail-closed。
- **Sequencing**：按 store 逐个 PR（Session/Refresh/JTI 最先，是 QPS 瓶颈）。

### 边界情况 & 性能优化（持续清单）

> 颗粒度不足独立方向，建议作为 sprint-filler 逐项消化；每条锚定具体代码
> 位置。本轮复扫新发现 + 仍有效项。

**安全 / 正确性边界**

- **时钟回拨复活已过期 session/token**（高）：`SessionManager.Refresh`
  （`defaultimpl/sqlite/sessions.go`，`UPDATE … WHERE expires_at>now`）+
  refresh `IsExpired`（`oauth/refresh_token.go`）+ DPoP iat 校验
  （`server_extensions.go`，skew 硬编码 1min）均用裸 `time.Now()`、无 skew
  容差。NTP 步进 / VM 快照回滚可让刚过期的 session 通过 `expires_at>now`
  被无限续期（与 §2"Session Refresh 拒已过期"的保证相悖）。建议：关键路径
  用 monotonic 比较 + 可配 `WithDPoPMaxClockSkew`/session skew，并在
  AGENTS.md §2 显式记录假设。
- **JTI replay store fail-open 无熔断**（高）：`security/jti_replay.go`
  `MarkSeen` 错误 fail-open——store 瞬时故障（Redis 超时/etcd 分区）期间
  **每个 JTI 都被当作首见**，攻击者可在故障窗口重放同一 JAR
  `request_uri`/DPoP proof/actor_token。建议：可选熔断（连续 N 次失败后对
  replay-敏感端点 fail-closed）+ per-store-error 审计。
- **V18 聚合 adoption-loop 静默退出 / 无可观测**（中-高，本会话功能的运维
  补完）：`StartSigningKeyAggregation` 订阅 loop 在 `Subscribe` 成功后若
  watch channel 关闭（etcd 不可达）会**静默退出**，本地 Publish 仍成功但
  停止采纳对端键 → 对端 token 验签 `unknown kid`，而 readiness 仍绿。
  建议：adoption-loop 存活纳入 readiness + 退出审计 + 采纳失败指标。
- **无 leader 轮换的 kid 采纳延迟 → 滚动部署期硬 401**（中）：副本 A 轮换到
  kid A2 并发布，副本 B 尚未订阅到时，A2 签的 token 命中 B 的 `/userinfo`
  直接 fail-closed `unknown kid`（非 backoff）。建议：kid-mismatch 401 带
  `Retry-After`；或 same-kid 一致（方向①b）根治。
- **租户暂停跨副本收敛窗口**（中-高）：`InvalidateTenantSuspensionCache`
  经 bus best-effort，分区/丢事件时某副本最长按 TTL（默认 30s）继续放行已
  暂停租户。建议：在 AGENTS.md §2 显式记录收敛窗口；可选 stale-hit 回源。
- **refresh 家族复用检测窗口无界**（中）：攻击者偷到 refresh token 后**先于**
  合法持有者轮换一次，铸出的 access token 存活至过期，只有当同一叶 token
  被二次出示才触发家族击杀。建议：可选 per-family 轮换速率限制 + 家族击杀
  审计信号。
- **CIBA ping goroutine 无 recover/超时**（低）：`ResolveBackchannelAuthRequest`
  用 `context.Background()` 起的 ping goroutine 无 `recover()`、无超时——
  webhook 挂起则泄漏，panic 则静默退出。建议：`recover()` +
  `context.WithTimeout` + `sso_ciba_ping_errors_total`。
- **snapshot 明文模式不脱敏 `client.Secret`**（中）：`snapshot.Resources.Clients`
  序列化保留 `Secret`；`encryption:none` 导出裸 secret。建议：可选
  `SnapshotRedactSecrets()`（仿 `audit.Redactor`）+ 脱敏审计。
- **body-limit 默认未设的 footgun**（中）：`WithBodyLimitForPath` 已存在，
  但全局默认不设上限时 `/token` 的巨型 `request` object 在 size 校验前可
  触发 JWE/JAR 大缓冲分配。建议：设保守默认（如 1MB）+ unmarshal 前校验
  size + 413。

**性能 / 热路径**

- **每登录 `ClientStore.Get` / `TenantStore` 查找**（`handler.go` 多处）：
  加 per-tenant/per-client TTL 缓存（30s）+ 失效经 bus。
- **`adoptedPeerMu` 写锁竞争**（`sso.go`，签名键高 churn 集群）：考虑
  RWMutex 让验证并行。
- **discovery 双缓存 stale-ETag 窗口**（低）：snapshot 与 body 两个 TTL 非
  协同失效，失效后短窗口内可能服务旧 ETag。建议：统一单 TTL 原子更新 +
  doc version 字段。
- **anomaly dispatch 丢弃可见性**（低）：仅有 `_drops_total` 计数无 rate/
  比例；慢 detector 填满队列时静默丢弃。建议：丢弃率指标 + 可配 per-detector
  超时。
- **观测覆盖补完**（中）：部分 handler 缺 span；slog 缺 W3C TraceID 注入；
  可加 per-tenant/per-client（有界基数）登录/颁发速率。

### 一句话优先级

**①（KMS peer 收口合规 gate，地基全铺只差一块砖）+ ②（Console+门户，进
企业采购清单、零后端起步）并行 → ③（SAML，补 RFP 最后一行，引经审计的
XML-DSig 库置 operator 侧）→ ④（CAEP/RISC，安全侧差异化，吃现成 audit+bus
底座）→ ⑤（Redis，等吞吐需求）。** 边界/性能清单作为各 sprint 的 filler
并行消化——其中**时钟回拨**、**JTI fail-open 熔断**、**V18 adoption 可观测**
三项安全优先级最高。

### 分布式微服务集群视角：再排序、一致性模型与分区矩阵

> 上方五方向偏产品/协议/合规。若部署目标是 **N 个无状态副本 + 服务网格
> （k8s + Istio/Linkerd）、可能多区域**，优先级应重排。核心 reframe：把本
> 项目从**"被调用的 SSO 服务器"**升级为**"服务网格的身份控制平面"**——网格
> 内每个 pod 以最小延迟、无中心瓶颈地拿到身份与授权。分三层看：控制平面
> （SSO 集群自身协同）/ 数据平面（每个工作负载的验签+授权）/ 跨区域。

#### 跨副本状态的 CP-vs-AP 一致性模型（核验代码后归类）

| 跨副本状态 | 当前模型 | 应为 | 缺口 |
|---|---|---|---|
| discovery / JWKS / 租户暂停缓存 | AP（TTL + bus 失效，幂等清除） | AP ✓ | 合理 |
| 签名公钥聚合（verify-only 全集） | AP（lease + watch，`signingkeys/`） | AP ✓ | adoption-loop 静默死无可观测；晚加入副本无历史追平 |
| active-kid 轮换（same-kid 场景） | 各副本独立翻转 | **需 deadline 协调** | 滚动部署期 kid-lag → 对端硬 401 `unknown kid` |
| JTI 单用重放 | AP（per-store，fail-open） | **趋 CP**（单用是安全不变量） | 跨副本/store 故障窗口可重放 JAR/DPoP/actor |
| refresh 家族复用检测 | per-store，本地击杀 | **趋 CP** | 被盗 token 在另一副本/区呈现为首见 → 重放成功 |
| 撤销 / 租户暂停传播 | AP（默认 30s TTL + bus） | AP 但需短窗 | access-token 撤销是 **lazy**（仅清 refresh）；分区下放行 |
| session 读写 | region-local SQLite | 跨区需共享或 home-pin | 跨区 `session_invalid` 404 |
| 审计 | AP（async，满则丢） | AP ✓ | 跨副本无全局事务 id（SIEM 关联弱） |

#### 集群视角的再排序（C①-C⑤）

**C① 网格原生身份数据平面**（ext_authz + SPIFFE + 去中心化授权）—— *集群
旗舰方向，v4.0 完全未覆盖；把"server"变成"mesh 身份控制平面"。*
- **Why cluster**：今天 `authz.v1.Authorizer` gRPC 是 **app-pull**——每请求
  回调 SSO = 中心瓶颈 + 延迟尾。网格里每请求应在 **sidecar 本地**完成。
- **Scope**：(a) **Envoy/Istio `ext_authz` v3 gRPC filter**（sidecar 接管入站、
  向 `Authorizer.Check` 取一次决策、TTL 缓存、bus 失效推送）——吃现成
  Authorizer + permission Check，约 200-300 行，置 sidecar/operator 侧；
  (b) **SPIFFE/SPIRE 工作负载身份桥**：验 JWT-SVID（信 SPIRE CA）→ 映射
  `spiffe://…/ns/sa` 到 `core.Subject` → token-exchange 接受新
  `subject_token_type`（mesh 原生服务间身份，差异化于 Auth0/Okta）；
  (c) **去中心化授权 bundle**：把 `permissions.Provider` 导出为 OPA Rego /
  Cedar policy bundle（`GET /api/v1/admin/policies/bundle`，cache-control +
  bus `KindAuthzPolicyChange` 失效），sidecar 拉取后本地 eval——100+ 服务
  规模下把 authz 从"每请求 RPC"降为"缓存 + 本地判定"。
- **一致性**：均 AP（决策/bundle 只读缓存 TTL，bus 触发失效）；无需共识。
- **ROI/effort**：highest / M（核心 SDK 零改，全在 sidecar/operator 侧）。

**C② 控制平面一致性与韧性硬化** —— *正确性-under-分布；从 v4.0 边界清单
promote 为一等方向。*
- **同步密钥轮换**：轮换副本经 `cluster.Bus` 广播
  `signing_key_rotation{old_kid,new_kid,retire_deadline}`，各副本延迟到
  deadline 才 `DropVerifyKey(old)`，消除滚动部署期 `unknown kid` 硬 401
  （复用本会话聚合 + bus 底座，约 60 行）。
- **共享 JTI replay + 可选 fail-closed**：跨副本/store 故障窗口现可重放——
  提供共享后端（Redis/etcd）+ 对 replay-敏感端点的可选熔断（连续失败转
  fail-closed）。同理 **refresh 家族复用**需跨副本失效广播。
- **撤销传播收紧**：access-token 撤销今天是 lazy（仅清 refresh + 暂停缓存
  TTL）——可选缩短 TTL / 经 bus 即时 + （与对外 §④ CAEP/RISC 互补）。
- **DPoP nonce key 跨副本共享 + 轮换**（今天每副本进程内随机 key，多副本
  必须手动同步、无轮换）：`WithSharedDPoPNonceKey` + etcd 分发 + grace 轮换。
- **readiness 补全 + adoption 可观测**：`/readyz` 现仅聚合 SQLite Ping——
  补 bus 连通、**signingkeys adoption-loop 存活**（静默死则 503 而非假绿）、
  schema-version 兼容；加 `sso_signing_key_adoption_errors_total{peer}`。
- **ROI/effort**：high / M（多数复用现有 bus/registry 原语）。

**C③ 共享存储基座：Redis**（承自 v4.0 ⑤，集群视角**提级**）—— *跨副本/跨区
强一致 session/refresh/JTI 的前置基座，而非单纯吞吐。*
- 单进程 SQLite WAL ~1k QPS 写竞争见顶；更重要的是 **session/refresh/JTI
  单用语义在多副本下需要一个共享原子层**——Redis（`GETDEL`/Lua/`ZSET`/
  `EXPIRE`）正是 C② 那几项强一致的落地载体。SQLite 保留为嵌入式 fallback。

**C④ 多区域 + 数据驻留** —— *XL 前沿；GDPR/PIPL 把它从"扩容"升级为"合规
硬约束"。*
- **数据驻留**（最高）：`Tenant.DataResidencyRegion`（EU/CN/US）→ 登录/颁发/
  session 持久化 pin 到匹配区；`RegionalStoreRouter` 按租户区路由 store；
  审计富化 region + 越界标志。GDPR Art.44 要求**强一致**驻留。
- **读本地/写 home 拆分**：缓存区域化（最终一致）；用户库只读副本各区（快
  登录）；session/refresh/JTI 写 home 区（强一致）。
- **跨区 JWKS 联邦**：`signingkeys` 是 per-region etcd——要么单一**共享 KMS
  key**（同 kid，跨区 JWKS 聚合 trivial，见 C⑤）、要么跨区 registry 桥、
  要么 CDN-cached 中心 JWKS。
- **etcd 跨区**：raft 50-100ms RTT + 脑裂——建议**每区独立 etcd + 应用层
  联邦**（幂等失效/公钥聚合本就适合 AP），而非跨区单一 raft。

**C⑤ KMS（承自 v4.0 ①）—— 集群视角多一层意义**：单一共享 KMS key →
全副本同 kid → **跨区 JWKS 聚合退化为平凡**（C④ 的最简解）；且 `ActiveKID`
轮换共识本就是分布式问题，与 C② 同源。仍是合规 P0。

#### 分区行为矩阵（建议显式写入 AGENTS.md / SECURITY.md）

> 当前各路径的 fail-open/closed 散落在代码注释，缺一张运维可查的真值表。

| 关键路径 | etcd 全断 | bus 分区 | 单副本孤立 |
|---|---|---|---|
| `/token`、`/auth/login` | 本地 SQLite 仍服务；**bootstrap lock 不可得 → 无法首发初始化** | 正常 | 正常（本地） |
| 验签、`/userinfo` | 本地 + 已采纳对端键仍验；**新对端键停止采纳**（adoption 静默死）→ 新 kid `unknown` | 同 etcd 断 | 同 etcd 断 |
| 撤销 / 暂停传播 | 仅本地失效，他副本按 TTL（30s）继续放行 | 同左 | 孤立副本按 TTL 滞后 |
| JTI 重放防护 | 共享 store 断 → **fail-open → 重放窗口** | — | per-replica → 跨副本可重放 |
| 密钥轮换 | 公钥发布失败 → 对端验不了新 kid | 同左 | — |

**结论矩阵的价值**：多数为**有意的 AP fail-open**（可用性优先、缓存幂等、
短窗）；但 **JTI 重放 + refresh 家族复用 + active-kid 轮换**三项在分区下的
行为是**安全敏感**的，应是 C② 的最高优先子项。

#### 集群视角一句话优先级

**C①（mesh 数据平面：ext_authz+SPIFFE+OPA bundle，把库变控制平面、核心零
改）→ C②（控制平面一致性硬化：同步轮换 + 共享/可熔断 JTI + readiness/adoption
可观测）→ C③（Redis 共享基座，承载 C② 的强一致）→ C⑤（KMS，兼跨区 JWKS
最简解）→ C④（多区域 + 数据驻留，XL 前沿）。** 与产品视角（①②）正交：
若客户是"网格内大规模微服务"，C① 高于产品 Console（②）；若客户是"企业采购
单租户运维"，②③仍领先。

---

## v3.1（2026-05-25）—— 第七个 10 轮：方向 ①②⑤ 落地（KMS 接线 + GDPR + EC JWE）

v3.0 复扫后的 10 轮开发,沿三个方向交付。每轮严格走"分析→编码→自测→
建议"SOP,各自独立 commit、`go test`/`make ci` 绿:

- **方向 ①(签名密钥治理)R1–3**:`defaultimpl/cryptosigner` 把任意
  stdlib `crypto.Signer`(KMS/HSM/PKCS#11 通用面)桥接进三种 issuer 接缝
  (含 ECDSA 的 DER→R‖S 转换),重 SDK 留在 operator cmd fork(go.mod 零
  增);cmd `keys.signing.external` 注册接缝 + 与进程内轮换互斥守卫;
  `sso_signing_operations_total{alg,outcome}` + `_duration_seconds` 观测
  KMS round-trip(roadmap ① 的 p99 边界)。**剩**:`awskms`/`gcpkms`/
  `pkcs11` 具体 peer(operator 侧)、ActiveKID 多副本强一致、per-tenant 签名。
- **方向 ②(GDPR 闭环)R4–7**:新 `compliance` 包 —— `Eraser`(Art.17 跨
  store 删除:撤 refresh→销 session→删 user,凭据先行、best-effort、幂等)
  + `Exporter`(Art.15/20,`SubjectExporter` 可扩展,排除凭据);admin HTTP
  端点 `GET/POST /api/v1/compliance/users/{id}/{export,erase}`(scope 自动
  read/write,审计落账,openapi + `ErasureReport` schema);
  `RefreshTokenSubjectCounter` 让 dry-run 非破坏性预览 token 数。**剩**:
  软删除/PII 假名化(需富化 User 模型)、Admin Console SPA、SCIM/SAML。
- **方向 ⑤(协议收尾)R8–10**:id_token/userinfo + JAR 双向 JWE 多算法 ——
  `ECDHJWEResponseEncrypter`/`ECDHJWEDecrypter`(ECDH-ES[+A256KW]+A256GCM,
  crypto/ecdh on-curve 校验)补齐 EC 侧;`MultiJWE{ResponseEncrypter,
  Decrypter}` 按 alg 路由 RSA+EC、JWKS 聚合、discovery 自动广告;cmd
  `oidc.response_encryption.backend: rsa|ecdh|multi`。**剩**:CIBA ping/push
  delivery(需完成钩子,低优)。

**本轮刻意不做**:方向 ③(SCIM/SAML)—— 当前 `core.User` 模型精简(无
username/name/active 字段),忠实 SCIM 映射需先富化 User 模型,非单轮可
净交付;方向 ④(Redis)—— 引入有状态新依赖,等 >1k QPS 客户再做。二者
仍是下一阶段最高 ROI。

---

## v3.0（2026-05-25）—— post-v2.9 复扫：重排后的 3–5 个方向【已被 v3.1 部分落地】

> 这是 v2.7–v2.9 三轮交付（FAPI 2.0 profile + 四算法签名矩阵 + JARM）
> 之后做的一次全局复扫。**下方 v2.6 节的 ①②已落地、结论已过期**，本
> 节取而代之，作为当前生效的优先级。grep 核验、非记忆。

### 复扫确认的当前边界

**已落地**（协议层 ≈ 98%）：完整 grant 集 + PAR/DCR/Introspect/Revoke/
Token-Exchange/RAR + DPoP + mTLS-bound + 9068 + 9207 + JAR（signed +
JWE 双向）+ Signed Metadata + Pairwise + OAuth 2.1 strict + step-up +
BCL/FCL + RP-logout + CIBA poll + **JARM** + **FAPI 2.0 profile
（Inspection/Enforce）** + **四算法签名矩阵（EdDSA/ES256/RS256/PS256，
均含运行时轮换 + 调度 + `{Ed25519,ECDSA,RSA}Signer` KMS 接缝 + 严格
alg-confusion 防护）**；认证因子 9 + WebAuthn + TOTP/Passkey/Push MFA +
上游 OIDC 联邦；**异步行为异常检测**（`AsyncAnomalyRunner` + 5 个
detector，旧 §2 已落地）；多副本正确性（15+ store SQLite peer +
`migrate/` 版本化迁移 + `cluster.Bus` 跨副本失效）；运维面
Snapshot/Release/Bootstrap/Retention + 4 个离线 CLI。

**仍为空白**（逐项 grep 确认）：KMS/HSM **具体** peer
（`awskms`/`gcpkms`/`pkcs11` 均无；接缝已就位）、统一
`SigningKeyProvider` 抽象、per-tenant 签名密钥、`web/` Admin Console、
`compliance/` GDPR 闭环、`scim/`、`saml/`、Redis 后端、CIBA 的
ping/push delivery、id_token/userinfo JWE 的多 alg（仅 RSA-OAEP-256）。

### 排序后的方向

**① KMS/HSM 具体 peer + ActiveKID 多副本强一致** —— *新晋明确 P0：
剩余工作量最小，合规门槛最硬。*

- **Why now**：四算法矩阵 + 运行时轮换 + 调度 + 审计 + `{Ed25519,
  ECDSA,RSA}Signer` 接缝在 v2.9 已 **100% 铺好**——私钥仍裸存进程内存
  这一项却让金融/政府 RFP 第一页就筛掉（FIPS 140-2/3、PCI-DSS、SOC2
  Type II 要求私钥永不出硬件）。现在缺的只是 **把接缝接到一个具体
  后端**：首个 `defaultimpl/awskms/`（`aws-sdk-go-v2` 的 `kms.Sign`），
  之后 `gcpkms`/`pkcs11`（YubiHSM/SoftHSM/Thales 通吃）同模式。这是
  "地基全铺好、只差一块砖"的最高 ROI 项。
- **Scope**：(a) 抽出统一 `SigningKeyProvider`（`Sign`/`PublicJWKS`/
  `ActiveKID`/`Rotate`），现有三 issuer 套壳零行为变更；(b) `awskms`
  peer + aws-sdk 依赖决策；(c) **多副本 `ActiveKID` 强一致**——轮换期
  各副本不能漂移 kid（否则 N 副本颁发 N 种 kid 签的 token，RP 端 JWKS
  缓存抓不到刚轮出的 kid）。`cluster.Bus` 底座已就位，把 ActiveKID
  选择经 bus/共享存储收口即可。
- **边界**：KMS sign 是网络 RTT（5–50ms），比进程内 `ed25519.Sign`
  慢三个数量级——需 token TTL 拉长 + 进程内 `(kid,payload_hash)→sig`
  LRU + p99 熔断到本地 fallback kid。JWKS ETag 改 `sha256(canonical)`
  防 KMS 公钥 JSON 字节序抖动。详见下方 ## 1（A/B/C）。

**② Operator/EndUser UX：Admin Console + GDPR 跨 store 闭环** ——
*企业采购 gate；把已建好的能力"包装出来卖"。*

- **Why now**：后端 capability 齐整，**面向人的操作面仍是 0**。竞品
  （Auth0/WorkOS/Stytch）卖的是"5 分钟 demo→生产，含 UI + 报表 +
  GDPR 按钮"。无 Console = 进不了企业采购清单。零后端改动即可起步
  （吃现成 admin REST gateway）。两件事：(a) `web/admin/` SPA，首批
  Dashboard/Sessions/Audit-Explorer 三 panel 最有 demo 价值 + 终端
  用户自助门户；(b) **GDPR erase/export 跨 store 工作流**
  （`compliance/erasure/`）——`DeleteAllForSubject` 已有，但多步幂等的
  revoke→soft-delete→后台 PII 假名化（保留 hash 链可校验性）没串起来。
- **复用点**：**与"租户暂停的主动吊销"共用同一份跨 store 删除流水线**
  ——今天 suspend 只挡新请求（已发 token 仍有效），缺 `DeleteByTenant`
  SPI。两个需求一次 SPI 解决。详见下方 ## 3。

**③ 企业 Provisioning：SCIM 2.0 + SAML 2.0** —— *RFP 表上仅剩的两行。*

- **Why now**：认证因子与上游 OIDC 联邦已全，**SCIM**（HR/IT 自动
  开户/停用，`/scim/v2/Users`+`Groups`）与 **SAML 2.0**（大量政府/
  传统企业 IdP 只说 SAML）是仅剩会被直接筛掉的两项。各自独立立项
  （SCIM ≈ 3–4 周，SAML ≈ 4–6 周），不阻塞其他方向。

**④ 吞吐层：Redis 后端 + 热路径性能** —— *正确性已完备，扩容课题。*

- **Why now / why not**：15+ store 的 SQLite peer 已保证 **正确性**；
  Redis 的 ROI 是 **吞吐（>1k QPS）** 而非正确性，代价是新有状态依赖
  ——等真有高 QPS 客户 inbound 再做。可顺手清掉热路径项：BCL 多 RP
  扇出 `errgroup` 并发化、`validateAnyToken` 先 peek token 形态再
  dispatch、`handleJWKS` 加 per-rotation-epoch single-flight、SIGTERM
  优雅停机串 `http.Server.Shutdown(ctx)` 等 in-flight `/token`。详见
  文末"边界情况 & 性能优化"清单。

**⑤（协议收尾）per-tenant 签名密钥 + CIBA ping/push + 多 alg JWE** ——
*last-mile，新方向随 v2.9 浮现。*

- **Why now**：四算法矩阵 + KMS 接缝就位、tenant SPI 成熟后，
  **per-tenant 签名密钥** 成为合乎逻辑的下一步——今天同进程持所有
  tenant 私钥，单次 memory dump 暴露所有 tenant 的伪造能力；
  `Tenant.SigningKey` 指向独立 Provider + `/tenant/{id}/.well-known/
  jwks.json` + 按 `iss` claim 路由验签即可。附带：CIBA ping/push
  delivery（仅做了 poll）、id_token/userinfo JWE 的多 alg（仅
  RSA-OAEP-256）。低优，按客户需求触发。

### 一句话优先级

**先做 ①（KMS peer，地基全铺好只差一块砖，最硬合规证据）→ ②
（Console + GDPR，进企业采购清单，零后端改动起步）→ ③（SCIM/SAML，
补销售清单）→ ④（Redis，等吞吐需求）→ ⑤（per-tenant 签名 + CIBA
ping/push，协议收尾）。** ① 与 ② 可并行（无共享前置）。

---

## v2.6（2026-05-25）—— 复扫后的下一阶段 3–5 个高价值方向【已被 v3.0 取代】

> 本节是在 v2.5（JWE 响应加密 + CIBA poll）落地后做的一次全局复扫
> 结论，**重排**了优先级。下方 v2.5→v2.1 是交付历史，再下方
> "## 1.～## 5." 是各方向的详细 Scope（未落地部分仍然有效，可直接当
> 实施蓝本）。本节只回答："如果现在只投 3–5 件事，按 ROI 投哪几件、
> 为什么。"

### 复扫确认的当前边界（grep 核验，非记忆）

**已落地**（协议层 ≈ 97%）：完整 grant 集 + PAR/DCR/Introspect/Revoke/
Token-Exchange/RAR + DPoP + mTLS-bound + 9068 + 9207 + JAR（signed +
**JWE 双向**：请求 §6.4 + **响应 §10.2/§5.3.2，v2.5 新落地**）+ Signed
Metadata + Pairwise + OAuth 2.1 strict + step-up + BCL/FCL +
RP-initiated logout + **CIBA poll（v2.5）**；认证因子 9 个 + WebAuthn +
TOTP/Passkey/Push MFA + 上游 OIDC 联邦；多副本正确性（15+ store SQLite
peer + `migrate/` 版本化迁移 + `cluster.Bus` 跨副本失效）；运维面
Snapshot/Release/Bootstrap/Retention + 3 个离线 CLI；签名密钥**运行时
轮换 + `Ed25519Signer` KMS 接缝 + 审计 + 指标**（v2.3）。

**仍为空白**（逐项 grep 确认）：`web/` Console、`compliance/` GDPR 闭环、
SAML / SCIM、KMS/HSM **具体** peer（`awskms`/`gcpkms`/`pkcs11` 均无）、
`SigningKeyProvider` 抽象、**多算法签名**（`supportedJWTAlgs` 仍是
EdDSA-only map，未配置化）、**FAPI 2.0 profile 总开关**、CIBA 的
ping/push delivery、Redis 后端（仅 ratelimit 注释提及）。

### 排序后的 3–5 个方向

**① FAPI 2.0 Compliance Profile + Inspection Mode** —— *新晋 P0，因为
v2.5 补齐了最后一块零件。*

- **Why now**：FAPI 2.0 baseline 的所有强制零件**现在全部就位**——PAR
  + JAR（必签 + 可加密）+ DPoP/mTLS + pairwise + signed_metadata +
  **响应 JWE（v2.5 刚补上的最后一块）**。剩的只是 **一个
  `oauth_compliance: fapi_2` 总开关** + 严格 `alg` allowlist 配置化 +
  **inspection mode**（"开关打开但只 audit 不拒绝"，发
  `fapi_compliance_violation{rule_id,client_id}`，让运维拿合规缺口
  清单逐项 fix）。这是当前**投入最小、销售证据最硬**的一件：开
  inspection mode 即可对金融/开放银行 RFP 宣称"支持 FAPI 2.0
  baseline"。详见下方 ## 5 的 profile + inspection 行。
- **唯一前置依赖**：把 `defaultimpl/ed25519_jwt_issuer.go` 的
  `supportedJWTAlgs`（EdDSA-only map）做成 `WithSupportedSigningAlgs`
  配置项 + `kid→alg` 强对应校验（防 alg-confusion）——这块与方向 ②
  的多算法部分重叠，可合并一个 sprint。

**② 签名密钥治理收口：KMS/HSM 具体 peer + 多算法 + 多副本 ActiveKID
强一致** —— *合规硬 gate，地基已铺好。*

- **Why now**：v2.3 已落地 `Ed25519Signer` 接缝 + 运行时轮换 + 审计 +
  `cluster.Bus`，但**私钥仍裸存进程内存**——金融/政府 RFP 第一页就筛
  掉。剩三件：(a) 一个**具体** KMS peer（`defaultimpl/awskms/`，
  `kms.Sign`，私钥永不出硬件）作为 `SigningKeyProvider` 首个实现；
  (b) 多算法（RS256/ES256 并存，与 ① 共用 allowlist 配置化）；
  (c) **多副本 `ActiveKID` 强一致**——轮换期各副本不能漂移 kid，否则
  RP 端 JWKS 缓存抓不到刚轮出的 kid。`cluster.Bus` 底座已就位，把
  ActiveKID 选择经 bus/共享存储收口即可。详见 ## 1（A/B/C）。
- **边界**：KMS sign 是网络 RTT（5–50ms），需 token TTL 拉长 + 进程内
  `(kid,payload_hash)→signature` LRU + p99 熔断到本地 fallback kid。

**③ Operator/EndUser UX + GDPR 跨 store 闭环** —— *企业采购 gate，把已
建好的能力"包装出来卖"。*

- **Why now**：后端 capability 齐整，**面向人的操作面是 0**。竞品
  （Auth0/WorkOS/Stytch）卖的是"5 分钟 demo→生产，含 UI + 报表 +
  GDPR 按钮"。两件事：(a) Admin Web Console（`web/admin/`，吃现成 admin
  REST gateway，零后端改动；首批 Dashboard/Sessions/Audit-Explorer
  三个 panel 最有 demo 价值）+ 终端用户自助门户；(b) **GDPR erase/export
  跨 store 工作流**（`compliance/erasure/`）——`DeleteAllForSubject`
  已有，但多步幂等的 revoke→soft-delete→后台 PII 假名化（保留 hash
  链可校验性）没串起来。**与"租户暂停的主动吊销"复用同一份跨 store
  删除流水线**（今天 suspend 只挡新请求，已发 token 仍有效；缺
  `DeleteByTenant` SPI）。详见 ## 3。

**④ 企业 Provisioning：SCIM 2.0 + SAML 2.0 联邦** —— *企业销售清单上
仅剩的两行。*

- **Why now**：认证因子与上游 OIDC 联邦已全，**SCIM**（HR/IT 自动开
  户/停用，`/scim/v2/Users`+`Groups`）与 **SAML 2.0**（仍有大量政府/
  传统企业 IdP 只说 SAML）是 RFP 表上仅剩会被直接筛掉的两项。各自独立
  立项（SCIM ≈ 3–4 周，SAML ≈ 4–6 周），不阻塞其他方向。

**⑤（可选）吞吐层：Redis 后端 + 热路径性能** —— *正确性已完备，这是
扩容课题，等 >1k QPS 客户 inbound 再做。*

- **Why now / why not**：15+ store 的 SQLite peer 已保证**正确性**；
  Redis 的 ROI 是 **吞吐（>1k QPS）** 而非正确性，代价是引入新有状态
  依赖。同时可顺手清掉持续清单里的热路径项：BCL 多 RP 扇出
  `errgroup` 并发化、`validateAnyToken` 先 peek token 形态再 dispatch、
  `handleJWKS` 加 per-rotation-epoch single-flight、SIGTERM 优雅停机串
  `http.Server.Shutdown(ctx)` 等 in-flight `/token`。详见文末"边界情况
  & 性能优化"清单。

### 一句话优先级

**先做 ①（FAPI profile，最小投入最硬证据，仅需顺带把 alg allowlist
配置化）→ ②（KMS peer 收口合规 gate，与 ① 的多算法合并）→ ③（Console +
GDPR，进企业采购清单）→ ④（SCIM/SAML，补销售清单）→ ⑤（Redis，等吞吐
需求）。** ①②可并行（共享 alg-allowlist 配置化这一前置），③④为产品化
与销售补完，⑤ 按需。

---

## v2.9（2026-05-25）—— 第六个 10 轮：多算法签名矩阵收口（RS256/PS256 + 轮换调度）

直接开发（无 agent），闭合 v2.8 标记的"方向 ② 多算法"与"ES256 StartRotation
缺口"：

- **`RSAJWTIssuer`（RS256 + PS256）**：镜像 `ECDSAJWTIssuer` 全接口集，
  `WithRSAAlg` 选 RS256（PKCS1v15）或 PS256（PSS，FAPI 首选），均 SHA-256；
  `RSASigner` KMS/HSM 接缝；强制 2048 位最小密钥；JWKS 发布 kty:RSA n/e
  （minimal big-endian e）；**严格 per-issuer alg gate**——RS256 issuer 拒
  PS256 反之，EdDSA/ES256/none 全在签名校验前挡下（结构性 kid→alg）。
- **轮换调度补齐**：ES256 + RSA 各加 `StartRotation`（共享 `RotationConfig`，
  镜像 Ed25519：首次轮换在首个 Interval 后、降级 key 过 GracePeriod 退役、
  ctx-cancel 退出）。补上了 ES256 track 遗留的 ES256 StartRotation 缺口，
  并让 cmd `keys.rotation` 对全部三种 alg 生效（rotation 类型断言现匹配）。
- **Server 接入 + cmd**：`WithSupportedSigningAlgs` gate 接纳 RS256/PS256；
  cmd `keys.signing.alg: eddsa|es256|rs256|ps256`（ps256=FAPI 首选）；
  discovery 的 id_token/userinfo/JARM signing-alg 列表均经 `SigningAlgValues`
  反映真实 alg（不再硬编码 EdDSA）。
- **测试**：RSA issuer 单测（双 alg round-trip + JWKS + alg-confusion +
  轮换重叠 + 密钥/alg 守卫）、ES256+RSA 轮换调度 race 测试、Server alg-gate
  白盒 + 真实 RSAJWTIssuer 端到端（login→introspect→JWKS，RS256+PS256）。

**多算法矩阵现已完整**：EdDSA / ES256 / RS256 / PS256 四种签名 alg，均含
运行时轮换 + 调度 + KMS 接缝 + 严格 alg-confusion 防护。**仍剩**：方向 ②的
KMS/HSM **具体** peer（awskms/gcpkms/pkcs11——接缝 `{Ed25519,ECDSA,RSA}Signer`
已就位，缺具体实现 + aws-sdk 依赖决策）、per-tenant 签名密钥；方向 ③ Console/
GDPR；方向 ④ SCIM/SAML。

## v2.8（2026-05-25）—— 第五个 10 轮：ES256 签名 + JARM + FAPI client-auth

两条并行 worktree agent 主线，闭合 v2.7 capstone 标记的"方向 ① 仍剩"与
"方向 ② 的多算法签名"：

- **ES256（ECDSA P-256）签名**（方向 ②）：新 `defaultimpl/ecdsa_jwt_issuer.go`
  —— `ECDSAJWTIssuer` 镜像 Ed25519 issuer 的全部接口集（TokenIssuer/
  IDTokenIssuer/MetadataSigner/UserinfoSigner/LogoutToken/JWKS +
  RotateKey/RetireKey + `ECDSASigner` KMS 接缝），go-jose v4 签验，JWKS
  发布 EC 公钥（kty:EC/crv:P-256/x/y）。`WithSupportedSigningAlgs` 把
  Validate alg allowlist 配置化；**严格 kid→alg**（结构性：ES256 token
  只过 ES256 issuer、EdDSA 只过 EdDSA，alg=none/RS256/篡改全在签名校验前
  挡下，R‖S 定长拒 DER）。cmd `keys.signing.alg: eddsa|es256`（rotation
  调度仍 eddsa-only，es256 + rotation 降级为 warn 跳过）。
- **JARM（JWT Secured Authorization Response Mode）**（方向 ①）：新
  `oidc/jarm.go` —— `response_mode=jwt`/`query.jwt`/`fragment.jwt`/
  `form_post.jwt`，授权响应签为 JWT（iss/aud/exp/code/state）经
  `oidc.JARMSigner` 接缝（Ed25519/ECDSA issuer 均满足；不碰 issuer 内部）。
  `WithJARM`，无 signer → `invalid_request` fail-closed。discovery 广告
  `authorization_signing_alg_values_supported` + 四个 jwt response mode。
  cmd `oauth.jarm.enabled`。
- **FAPI client-auth rule**（方向 ①）：`fapi:client_auth` —— 禁
  client_secret_basic/post/none，要求 private_key_jwt 或 mTLS（FAPI 2.0
  §5.3.2）。接入既有 `CheckToken` 强制点（enforce 拒 + 审计），随
  `WithFAPIProfile` 自动生效。

**集成说明**：两 agent 顺序提交到同一分支，Track A 在 Track B 之上构建，
共享文件（sso.go/handlers.go/fapi/handler.go）已自然整合无冲突；主控补
cmd 接线（signingIssuer 接口 + rotation 类型断言 + JARM/ES256 选择）+
capstone。

**仍剩**：RS256/PS256 签名（ES256 已落，RS256 是 stretch 未做）、ES256 的
StartRotation 调度循环、DPoP/JAR 客户端证明的 ES256 接受、方向 ②的 KMS
具体 peer（接缝 `ECDSASigner`/`Ed25519Signer` 已就位）、方向 ③ Console/
GDPR、方向 ④ SCIM/SAML。

## v2.7（2026-05-25）—— 第四个 10 轮：FAPI 2.0 Compliance Profile + Inspection Mode

v2.6 复扫把 FAPI 2.0 profile 列为新晋 P0（v2.5 响应 JWE 补齐了最后一块
前置零件）。第四个 10 轮交付了方向 ① 的 profile + inspection mode 主体：

- **`fapi/` 纯逻辑包**：`Mode`（Off/Inspection/Enforce）+ `Validator`
  + 稳定 rule id（`par_required`/`signed_request`/`pkce_s256`/
  `no_implicit`/`sender_constrained`）。`CheckAuthorization`/`CheckToken`
  接收已抽取的请求信号、返回违规列表，nil/Off-safe；零 Server 耦合、
  零环、可隔离单测（8 个单测全覆盖）。
- **强制点接入**：`/auth/login`（PAR/JAR-merge 之后，信号
  `usedPAR=request_uri 存在`、`signedRequest=request 存在`）+ `/token`
  （grant switch 之前，`senderConstrained=DPoP JKT 或 mTLS x5t 存在`，
  统一覆盖所有 grant）。Inspection 只审计不改响应（FAPI 1 "全或无悬崖"
  教训）；Enforce 拒为标准 `invalid_request`（rule id 进 error_description
  + 审计，无新增 wire code、无 oracle）。
- **Discovery 反映**：Enforce 模式广告 `require_pushed_authorization_requests`
  / `require_signed_request_object` / `response_types_supported:[code]` /
  `code_challenge_methods_supported:[S256]`；Inspection 不改 discovery。
- **可观测**：`fapi_compliance_violation` 审计事件（`fapi_rule`/
  `fapi_detail`/`fapi_mode`）+ `sso_fapi_violations_total{rule,mode}`
  指标（inspection ramp-up dashboard：按 rule 看哪些 RP 不合规）。
- **cmd 接线**：`oauth.compliance.{profile=fapi_2,inspection_only}`。

**刻意不做（已记录原因）**：多算法签名（RS256/ES256）——在只有 EdDSA
signer 时扩展 Validate allowlist 会接受无法验签的 token（footgun），且
alg-confusion 已被 EdDSA-only allowlist 挡住（none/HS256 不在内）；待真正
落地 RS256/ES256 signer（方向 ②）时再一并做。

**方向 ① 仍剩**：FAPI 2.0 的 JARM（签名授权响应）、client-auth 方法约束
（禁 client_secret_basic）、per-rule 配置化（FAPI 2.0 Advanced）。**方向 ②
③④ 未动**（KMS peer / Console+GDPR / SCIM+SAML）。

## v2.5（2026-05-25）—— 第三个 10 轮：§5 最后一公里协议（JWE 响应加密 + CIBA）

第三个 10 轮交付，按 §5 的 ROI 排序闭合两条主线（两条并行 worktree
agent 开发，主线整合 + cmd 接线 + capstone 由主控完成）：

- **OIDC JWE 响应加密（OIDC Core §10.2 / §5.3.2）**：镜像既有请求方向
  JWE-JAR 基础设施做响应方向。`Client` 新增 4 个 OIDC-Core 命名字段
  （`IDTokenEncryptedResponseAlg`/`_Enc`、`UserinfoEncryptedResponseAlg`/
  `_Enc`）+ DCR 映射；新 `security.JWEEncrypter` SPI + 默认
  `RSAJWEResponseEncrypter`（RSA-OAEP-256 + A256GCM）；`WithJWEResponseEncrypter`
  接线。id_token 产出 `JWE(JWS(...))` 嵌套，`/userinfo` 输出
  `application/jwt` JWE。**fail-closed / 无 oracle**：opted-in 客户端加密
  失败 → id_token 省略 / userinfo 单一 `server_error`，绝不区分"缺 RP 公钥"
  与"加密计算失败"。discovery 在 wire 后才广告 4 个
  `*_encryption_{alg,enc}_values_supported`。cmd 经 `oidc.response_encryption`
  接入；WebAuthn `/webauthn/login/finish` 的 id_token 也补走加密
  （堵住 Track A 发现的明文泄漏缺口）。
- **OIDC CIBA Core 1.0 poll 模式**：复用 push 流的"服务端 challenge →
  带外确认 → 轮询"语义。新 `oauth.CIBAStore`（memory + sqlite，经 §4
  migrate 框架，ns `ciba_requests`）+ `oauth.CIBATransport`（结构等同
  `defaultimpl.PushTransport`，避免 root→defaultimpl 环）+
  `/backchannel-authentication` Hexagonal handler + `/token` 的
  `grant_type=urn:openid:params:grant-type:ciba`，poll 复用 device-flow
  的 `authorization_pending`/`slow_down` + oracle-leak collapse。
  `WithCIBA` 接线；discovery 广告 `backchannel_*`；3 个审计事件经
  `setMeta`。cmd 经 `ciba.*` 接入（log/webhook transport + sqlite
  PruneExpired 调度器，镜像 push approval retention loop）。

**§5 仍剩**（非阻塞）：CIBA 的 ping/push delivery 模式（仅做了 poll）、
id_token/userinfo 加密的多 alg（仅 RSA-OAEP-256）、FAPI 2.0 profile 总
开关 + inspection mode（前置零件现已更齐——PAR + JAR + DPoP/mTLS +
pairwise + signed_metadata + 响应 JWE 都在了，缺统一开关 + 严格 alg
allowlist 配置化）。**§1 仍剩** KMS/HSM 具体 peer + 多算法签名 +
per-tenant；**§3 Console + GDPR** 未动。

## v2.4（2026-05-25）—— §4 Schema Migration 框架已落地

第二个 10 轮交付，闭合 roadmap §4（"今天不做明天更贵"的 P1）：

- **`migrate/` 纯 Go 迁移 runner**（零外部依赖，未引 goose——符合仓库
  低依赖取向）：`Migration{Version,Name,SQL|Func}` + `Run` 在单个
  `BEGIN IMMEDIATE` 事务内按序前向应用，per-namespace 版本表
  （`schema_migrations_<ns>`）。baseline = 现有 schema，已有库 no-op +
  盖 v1，新库照建。`Func` 步支持条件/数据迁移（PRAGMA 查列后补列）。
  并发副本经 runner 的 `PRAGMA busy_timeout` 串行化（修正：mattn 式
  `_busy_timeout` DSN 参数 modernc 不认）。
- **全部 6 个 SQLite 落点已纳管**：audit / permissions / tenant /
  webauthn(users+sessions) / defaultimpl(14 store) / ratelimit；
  refresh_tokens 用 `Func` 迁移保留其遗留补列升级（且修了旧路径可能漏建
  family_id 索引的隐患）。
- **`migrate.Status` + `cmd/sso-migrate status --dsn`**：离线读取任意
  库的 per-namespace schema 版本（部署前检查 / DR 演练），与
  `sso-audit-verify`/`sso-snapshotctl` 同属只读离线 CLI。
- **附带修复**：`loadAESGCMKey` 对结尾为 0x0A/0x0D 的 32 字节裸密钥
  （KMS DEK）误做换行裁剪 → 截断失败（~0.78% 概率，曾间歇性 flake CI）。

**§4 仍剩**（非阻塞）：cmd 共享 `*sql.DB` 后的 schema-version 指标/就绪
门、跨 store 物理备份的 snapshot v2、down-migration（生产仍建议
restore-from-snapshot 而非 schema 回滚）。

## v2.3（2026-05-25）—— 上一轮已落地

10 轮开发交付了两条主线，更新如下：

- **跨副本失效总线（v2.2 边界情况 → 已落地）**：新 `cluster/` 包 ——
  `Bus` SPI（Publish/Subscribe/Close）+ `Event{Kind,Key,Payload}` +
  memory peer（进程内扇出）+ etcd peer（跨进程，prefix WATCH + 短租约
  自清理）。`Server.InvalidateTenantSuspensionCache` /
  `InvalidateDiscoveryCache` 现在本地失效后经 bus publish，各副本
  `StartInvalidationBus` 订阅并清本地缓存。cmd 经 `cluster.bus.backend`
  接入（fail-open，非 readiness 依赖）。两个消费者：
  `KindTenantSuspension`（暂停跨副本即时生效）+ `KindDiscoveryReload`
  （client 改动后各副本重算 discovery）。
- **§1 签名密钥治理（部分落地）**：
  - `Ed25519Signer` 接缝 + `WithEd25519ExternalSigner`——签名操作可换成
    KMS/HSM 后端，私钥不入进程；5 个签名点全部 fail-closed 传播错误。
  - `RotateKey`/`RetireKey` 运行时重叠期轮换（keyMu 守护，`-race` 验证），
    旧 kid 降级 verify-only 在 JWKS 保留至 TTL。
  - `StartRotation` 自动轮换调度器 + cmd `keys.rotation.*` 配置 +
    `signing_key_rotated` 审计 + `sso_signing_key_rotations_total` 指标 +
    轮换时 bus 广播 discovery 重载。
  - **仍缺**：KMS/HSM 具体 peer（awskms/gcpkms/pkcs11）、多算法 allowlist
    配置化（RS256/ES256）、per-tenant 签名密钥、multi-replica `ActiveKID`
    强一致（需共享密钥存储——bus 底座已就位）。

下面 5 个方向中，**§1 的轮换闭环已大部分落地**（剩 KMS peer + 多算法 +
per-tenant）；§2 异常检测此前 v2.1 已落地；**§3 Console、§4 Migration、
§5 CIBA/JWE/FAPI 仍未动**。

## v2.1（2026-05-22）之后的复扫结论（2026-05-25）

复扫确认：**v2.1 之后的 40 个 commit 全部是内部结构重构，零新增产品
能力**——因此本文档的 5 个方向**全部仍然成立、全部未落地**（已逐项
核验代码：无 `SigningKeyProvider`/KMS/HSM、无 `migrations/` 目录、无
`web/` Console、无 `compliance/erasure`、无 CIBA、无 Redis 后端）。
（注：此结论为 v2.2 复扫时点；上方 v2.3 段记录此后 10 轮开发的落地。）

这一轮结构性里程碑（影响"在哪里加代码"，不影响"加什么能力"）：

- **Hexagonal handler 抽取**：根目录从 ~68 个 `.go` 收敛到 **6 个非
  测试源文件**。`handle_introspect` / `handle_revoke[all]` / `handlePAR`
  / `handleRegister`+`Registration{Get,Put,Delete}` 迁入 `oauth/`；
  `handleEndSession` / `handleSilentRenewal` / JWKS / form_post /
  userinfo-sign + discovery-doc cache 迁入 `oidc/`。模式：handler body
  变 `HandleX(deps Deps, ctx)` 自由函数，`*sso.Server` 经 `accessors.go`
  实现 `Deps`，根目录留一行委托。**约束：`oauth/` 不能 import `oidc/`**
  （`oidc` import `oauth`，会成环）。
- **测试按功能归位**：94 个根目录黑盒测试中，89 个集成测试（构建完整
  `*sso.Server` 走 HTTP、共享一套 harness）迁入 `test/`（`package
  ssotest`）；真单元测试随代码进子包（如
  `security/step_up_auth_test.go`）。根目录 `.go` 从 101 → 8。
- **AGENTS.md 压缩** 977 → 709 行（保留全部 19 条 wire-contract 不变量
  + 33 行规范表，只砍叙述）。

**对 roadmap 的影响**：下面 5 个方向的 *Scope* 里凡提到"新建
`defaultimpl/awskms/`""新建 `audit/sink/clickhouse/`"等子包的，现在落
在一个更干净的分层上落地；凡涉及 handler 改动的（如 §5 CIBA 的
`/backchannel-authentication`、§1 的 `/api/v1/admin/keys:rotate`），
新 handler 应按 Hexagonal `Deps` 模式写进对应子包，而非堆回根目录。

---

## 上一版 ROADMAP（2026-05-21）之后已落地的能力

读这份文档前先承认进度——上一版的五个方向有大量已经实现：

| 上版方向 | 当时状态 | 现在状态 |
|---|---|---|
| §1 多副本正确性（6 个 SPI 缺分布式后端） | 全部 memory-only | **SQLite peer 全部到位**：PAR / Session / RateLimiter / JTIReplay / SubjectClientIndex / AccountLockout、再 + MFAChallenge / PushApproval / Tenant / Permissions / Audit / WebAuthn — 共 15 个 store 都有 cluster-shared 后端 |
| §2A WebAuthn / Passkey | 未实现 | **完整 4-call ceremony** + cmd 路由 + SQLite UserStore/SessionStore + MFA-as-step-up |
| §2B 上游 IdP 联邦 | 未实现 | **OIDC RP 端 5 个内置 provider**（Google/Microsoft/GitHub/Auth0/Keycloak）— SAML 仍缺 |
| §2C SCIM 2.0 | 未实现 | 仍缺 |
| §3 HSM / KMS / 自动轮换 | 未实现 | 仍缺 — Ed25519 私钥仍在进程内存 |
| §4A Audit Explorer 后端（SQLite FTS） | 未实现 | **Audit SQLite Sink 落地**（含 Query API + 保留调度器 + 哈希链 + PII redactor + Async/Retry/Multi sink composition + Webhook sink） |
| §4B 用户自助 / Admin Web Console | 未实现 | 仍缺 |
| §4C GDPR erase pipeline | 未实现 | 仍缺 — `RefreshTokenSubjectIndex.DeleteAllForSubject` 已经有，但跨 store 删除工作流没串起来 |
| §4D 异步异常检测 | 未实现 | 仍缺 — `RiskScorer` 是同步路径决策 |
| §5 Signed Metadata | 未实现 | **已落地**（`WithMetadataSigner`） |
| §5 DPoP Nonces | 未实现 | **已落地**（`WithDPoPNonceProvider`） |
| §5 Pairwise Subject | 未实现 | **已落地**（`PairwiseSubjectStore` + SQLite peer） |
| §5 JWE for JAR | 未实现 | **已落地**（RFC 9101 §6.4，RSA-OAEP-256 + A256GCM） |
| §5 CIBA | 未实现 | 仍缺 |
| §5 JWE for id_token/userinfo | 未实现 | 仍缺 |
| §5 FAPI 2.0 profile | 未实现 | 仍缺（前置零件齐了，缺单开关 + inspection mode） |

**新增能力**（上版未列入，但这一轮做了）：

- **MFA orchestration**：TOTP / WebAuthn / Push / Multi-composer 全套
  factor，`MFABeginner` 双 call ceremony SPI，cmd YAML 完整 wire（含
  `kind=multi` 组合）。
- **Push 全栈**：`PushTransport` SPI + 内置 `log` / `webhook` 两种
  transport + 参考回调处理器 `/push/approval/:id/:decision`。
- **Snapshot AES-GCM Sealer**：除 argon2id+chacha20poly1305
  passphrase 外，新增 KMS-friendly 直接 32 字节密钥 sealer。
- **观测全面升级**：`sso_login_duration_seconds{provider,outcome}`
  + `sso_mfa_completion_duration_seconds{outcome}` +
  `sso_webauthn_{registrations,assertions}_total{outcome}` +
  `sso_retention_{pruned,prune_errors}_total{subsystem}` + `/health`
  含 build info（version + VCS revision）。
- **三套 retention scheduler**：`audit.retention` /
  `snapshot.retention` / `mfa.provider.push.prune_interval`，cmd 统一
  shutdown 协调。
- **`WithReadyCheckTimeout` 单 check 超时**：聚合 3s 内的 per-check
  override。
- **安全修复**：`SessionManager.Refresh` 拒绝复活已 expired/revoked
  session（两后端同时修）。
- **Permissions conformance suite**：memory / sqlite 等价性锁定
  （`permissions/permissionstest`）。

---

## 现状自检

按一份成熟 OAuth/OIDC 平台的 RFP 评估表对照：

- **协议覆盖** —— 完整 grant 集 + PAR + DCR + Introspect + Revoke +
  Token Exchange + RAR；DPoP + mTLS-bound + 9068 + 9207 + JAR
  (signed + JWE) + Signed Metadata + Pairwise + OAuth 2.1 strict +
  step-up + BCL/FCL + RP-initiated logout。**协议层 ≈ 95%**。
- **认证因子** —— 9 个 primitive + WebAuthn + TOTP/Passkey/Push 三种
  MFA + 上游 OIDC 联邦。**剩 SAML / SCIM 是企业销售清单的两行**。
- **多副本正确性** —— 15 个 store 都有 SQLite peer，cluster-shared
  路径走得通。**剩 Redis / 跨区一致是吞吐 + 跨区课题，不是正确性**。
- **运维面** —— Snapshot / Release / Bootstrap / Retention 自动化都
  到位，CLIs（`sso-audit-verify`/`sso-snapshotctl`）齐备。**剩没有面
  向人的 Web Console**。
- **安全 / 合规** —— Audit 哈希链 + PII redactor + 退化策略全面落
  地。**密钥治理（HSM）、合规闭环（GDPR erase）、行为异常检测三块
  是空白**。
- **协议补完位** —— CIBA + JWE 响应加密 + FAPI 2.0 profile 三件。

**这一阶段剩下的不是"做协议"**，而是：**把密钥升到 HSM → 把行为
异常这条异步通路补上 → 把面向人的操作面做出来 → 把多表 schema 演化
路径修通 → 把最后一公里协议（CIBA / 响应 JWE / FAPI 2.0）收口**。
下面 5 个方向按这个顺序排。

---

## 1. 签名密钥治理：HSM / KMS 抽象 + 自动轮换 + per-tenant 隔离

### Why now

`Ed25519JWTIssuer.Issue` 直接调 `ed25519.Sign(j.privateKey, ...)` —
**私钥裸存进程内存**。这一项在三个客户对话里会立刻被拒，是这个
项目今天面向**金融 / 政府 / 高敏感 SaaS** 销售的 **唯一硬阻塞**：

1. **金融 / 政府客户合规**：FIPS 140-2/3、PCI-DSS、SOC2 Type II
   要求签名密钥在 HSM 内，私钥永不出硬件边界。今天 SDK 不提供这
   条路径——这是 RFP 第一页就会被筛掉的项。
2. **多租户内存隔离**：同一进程持有所有 tenant 的签名密钥 = 单个
   memory dump 暴露所有 tenant 的伪造能力。Tenant SPI 已经落地，
   per-tenant signing 是逻辑下一步。
3. **轮换审计闭环缺失**：今天密钥轮换是手动调 `RotateKey`，没有
   "轮换记录、谁触发、为什么轮换、上一版本何时停止接受签名" 的
   审计追溯。SOC2 Type II 复审强制要求这条记录。

附带解决两个长期待办：

- **多算法（RS256 / ES256 / EdDSA 并存）**：今天只有 EdDSA。
  联邦上游可能是 RS256；资源服务器要验上游签名也需要 RS256；
  FAPI 客户硬要 PS256。引入新算法本身不难，难的是 alg-confusion
  攻击窗口的收口（AGENTS.md §2 已 noted 的 `alg+typ allowlist`
  是基础，但当前 `supportedJWTAlgs` 是 hardcoded `["EdDSA"]`，
  扩展需要先把它做成配置项）。
- **per-tenant JWKS**：tenant 解析层已经按 hostname → tenant 路由
  齐备；缺的是 `/tenant/{id}/.well-known/jwks.json` 入口 + 按 `iss`
  claim 选 KeyProvider 验签的 dispatch 逻辑。

### Scope

**A. `SigningKeyProvider` SPI**

```go
type SigningKeyProvider interface {
    Sign(ctx, kid, algorithm, payload) (signature, error)
    PublicJWKS(ctx) (JWKS, error)
    ActiveKID(ctx, algorithm) (kid, error)
    Rotate(ctx, reason) (newKID, error)
}
```

- 默认实现 `defaultimpl/software`：现有 `Ed25519JWTIssuer` 走这个
  壳，零行为变更（一次重构 commit）。
- `defaultimpl/awskms/` —— AWS KMS（`aws-sdk-go-v2`, `kms.Sign`）。
- `defaultimpl/gcpkms/`、`defaultimpl/azurekv/`、`defaultimpl/vault/`
  —— 同模式，社区/客户按需加。
- `defaultimpl/pkcs11/` —— PKCS#11 通用层（YubiHSM / SoftHSM /
  Thales / Entrust 都走这套），用 `github.com/miekg/pkcs11`。

**B. 多算法 + alg allowlist 配置化**

- `Server.supportedJWTAlgs` 从 hardcoded `["EdDSA"]` 变成
  `WithSupportedSigningAlgs(...)`；discovery 同步反映。
- `Validate` 严格化：header `alg` 必须在 allowlist 且必须与 `kid`
  对应密钥的算法一致（防 RS256 公钥被当 HS256 共享密钥用的经典
  攻击）。
- `WithSecondaryAlg(...)` 过渡期支持：同时接受老 EdDSA + 新 RS256，
  给现有 RP 6+ 个月迁移窗口。

**C. 自动轮换 + 重叠期 + 审计**

```yaml
keys:
  rotation:
    interval: 90d
    grace_period: 7d
    strategy: scheduled   # scheduled | manual | event-driven
```

- 轮换由 `bootstrap/builtin` 的 v5 step `ensure_signing_key_rotation`
  注册（首次启动检查 `last_rotated_at`，到期触发）。
- 每次轮换写 audit `signing_key_rotated`：`from_kid` / `to_kid` /
  `algorithm` / `reason`（scheduled / manual / suspected_compromise）。
- 紧急轮换接口：`POST /api/v1/admin/keys:rotate
  {reason:"compromise"}` 立即生成新 kid + 把所有现存 token 标记为
  needs-revalidation；与 `/token/revoke-all` 配合达成 "全局 token
  黑屏 30 秒"。

**D. per-tenant 签名密钥（可选第二阶段）**

- `Tenant.SigningKey` 可指向独立的 `SigningKeyProvider`；空走全局。
- 路由：`/tenant/{tenant-id}/.well-known/jwks.json`。
- Validate 必须按 `iss` claim 路由到对应 KeyProvider，不能用进程级
  KeyProvider 验所有 token。

### Edge cases / 当前实现具体短板

- **KMS 延迟**：AWS KMS sign 是网络 RTT（5-50ms），把 `ed25519.Sign`
  的 µs 级响应拉慢三个数量级。需要：(1) KMS-signed token 的 TTL
  适度拉长（10min → 30min）摊薄签名成本；(2) per-process LRU 缓存
  `(kid, payload_hash) → signature`（DPoP 的 `jti` 已经在防重放，
  签名缓存复用安全）；(3) p99 监控 + 熔断到本地 fallback kid。
- **JWKS endpoint ETag 稳定性**：今天 ETag = `sha256(body)[:8]`，
  KMS 后端的公钥不变但 JSON 序列化字节顺序可能不稳定。改成
  `sha256(canonical(jwks))` 或 `kid_set || algorithm_set` 组合
  hash。
- **轮换期 `kid` 选择竞态**：grace_period 内同一 token issuance 路径
  可能命中老 kid（cache miss）和新 kid（cache hit）两种状态。
  `ActiveKID` 必须强一致（走分布式存储或单点 leader），不能在
  副本间漂移；否则 N 副本会颁发用 N 种 kid 签的 token，RP 端
  JWKS 缓存反而抓不到刚轮换出去的那个 kid。
- **算法切换的算法混淆窗口**：从 EdDSA 单算法过渡到 EdDSA + RS256
  双算法时，必须在 `Validate` 严格做 `kid → algorithm` 对应，不允许
  RP 通过 header `alg` 选择算法——必须由 server-side 键空间决定。

### Sequencing hint

**先做 A**（HSM/KMS 抽象）+ **B**（多算法 allowlist 配置化）作为一
个 batch，约 3-4 周；**C**（自动轮换 + 审计）独立 sprint；**D**
（per-tenant 签名密钥）等真有 multi-tenant 客户提需求再做（涉及
discovery URL schema 演化，破坏性较大）。

---

## 2. 异步行为异常检测（Anomaly Detector）+ 凭据健康度

### Why now

`RiskScorer` 今天是 **请求路径上的同步决策**——`Allow` / `Deny` /
`RequireMFA` 三选一，毫秒级响应。这套适合"已知签名 IP 黑名单"、
"国家级 geo 拒绝" 这类硬规则，**完全无法处理凭据撞库 / impossible
travel / 新设备登录 / 时段异常 / brute-force 横扫副本** 这类需要
**窗口聚合** + **个体基线** 的真信号。

观察：

- 当前 `RuleBasedRiskScorer` 是 IP / country 拒绝-允许清单，零
  动态学习。
- `AccountLockout` 已经按账户滑窗，但只在登录路径触发；不对
  "同一 IP 一夜之间 1000 次失败登录但每个账户都只试 4 次（保持
  在 lockout 阈值之下）" 这类**横向撞库**敏感。
- 真实安全运营靠 **事后聚合 + 告警 + 人审** 工作流，不是请求
  路径上的"直接拒绝"。今天 SDK 强制把所有风控决策塞进同步
  Score()，导致客户只能选择"激进拒绝（误报扰民）"或"什么都不
  做（撞库横行）"。
- 凭据健康度（HIBP / pwned password / 弱密码 / 过期未轮换）今天
  完全缺失——password authenticator 只验 bcrypt 匹配，不告诉用户
  "你的密码在 2023 数据泄漏里出现过 14 万次"。

**这是把"auth 库"升级到"identity 平台"的关键差异化**。

### Scope

**A. `AnomalyDetector` SPI（与 `RiskScorer` 平行的异步通路）**

```go
type AnomalyDetector interface {
    // 登录成功 / 失败后异步调用，不阻塞请求路径
    Inspect(ctx, *LoginEvent) []*Anomaly
}

type Anomaly struct {
    Type      string  // impossible_travel | new_country | velocity | brute_force_shadow | ...
    Severity  string  // info | warn | critical
    Score     float64
    Evidence  map[string]string
    SubjectID string
}
```

调用点：`audit.Recorder` 之后启动 `defaultimpl.NewAsyncSink` 类似的
有界 worker pool，把 `LoginEvent`（含 geo、UA、success/failure、
trace_id）排队 → 每个 detector 独立消费 → 输出 `anomaly_detected`
audit + 可选 webhook。**请求路径完全不知情**——这是关键设计契约。

**B. 内置 detector**（每个独立 PR）

- **Impossible travel**：基于现有 `geo.GeoInfo`，相邻成功登录跨度
  距离 / 时间 > 物理可达（800km/h 上限）。状态需要 per-subject
  滑窗 → 新接口 `RecentLoginStore`（memory + sqlite，schema：
  `(subject_id, timestamp, country_code, ip_hash)` + index）。
- **Velocity**：同一账户 / IP 在窗口内成功登录次数 > 阈值（默认
  `25/hour` / `200/day`）。复用 `AccountLockout` 类似的滑窗 store
  即可，schema 类似。
- **New country / new device**：相对该用户的 7 天基线，新出现的
  UA fingerprint hash 或 country_code。需要 `KnownDeviceStore`
  （subject_id, ua_fingerprint, country_code, last_seen_at）。
- **Brute-force shadow**：同一 IP 在 N 个账户上累计失败次数（绕
  per-account lockout），分布全部副本（依赖 SQLite 共享 store）。
- **Off-hours**：用户基线工作时段 + 容差，新登录在基线外触发
  warn。低优，做最后。

**C. 凭据健康度（CredentialHealthChecker）**

- **HIBP k-anonymity 检查**：password verifier 在 hash 校验通过后，
  异步查 `api.pwnedpasswords.com` 的 k-anonymity API（提交 SHA-1
  前 5 位，比对返回的密码列表是否含完整 SHA-1）。命中 → audit
  `password_compromised` + 下次登录强制改密 UI flag。
- **弱密码字典**：bootstrap 集成可选字典（top 10k common passwords），
  注册 / 改密时拒绝（403 + `password_too_weak`）。
- **密码年龄**：可选 `password.max_age_days`，过期 → 强制走改密
  流程（但不锁登录，避免 lockout 闪退）。

**D. 告警通路**

- `audit.EventAnomalyDetected` 类型，包含 detector 名 + score +
  原始事件 ID + evidence map。
- 可选 webhook (`AnomalyWebhookSink`)：与 `audit.WebhookSink` 同源
  设计，push 到 SIEM / Slack。
- 可选 SMTP / Slack 推送到 **用户本人**："我们检测到来自新国家的
  登录…"——这是终端用户感知到的"为什么这家产品安全"。
- 新 metric：`sso_anomalies_detected_total{type, severity}`。

### Edge cases / 当前实现具体短板

- **误报成本**：impossible travel 在 VPN 用户身上几乎 100% 误报。
  所以默认输出是 audit + webhook，**不进请求路径**（不影响登录
  成功/失败）；只有运维 / 用户自己看到信号。让客户按自己的安全
  姿态决定是否升级到"自动锁账户"。
- **状态 store 体量**：N 用户 × 30 天 login history 是真实数据
  膨胀点。需要：(1) `RecentLoginStore` 强制 TTL（默认 30 天）；
  (2) 配套 retention 调度器复用 §1 中的 scheduler 框架；(3) 文档
  示例规模数字（10k 用户 ≈ 1GB SQLite）。
- **detector 排序与短路**：N 个 detector 串行跑会拖延后续处理。
  worker pool 模型让每个 detector 独立消费，互不阻塞；只在 audit
  写入时聚合。
- **隐私**：UA fingerprint 是 PII 的近邻——不要直接落原始 UA，
  落 `sha256(ua || subject_id_salt)`。同样 IP 应当 `ipv4 /24
  truncate` 或 `ipv6 /64 truncate` 后再持久化。复用现有
  `RedactIPTruncate` / `RedactUserAgent`。
- **冷启动**："new country" 需要历史基线——前 7 天 every login is
  new，告警洪水。引入 `bootstrap_grace_period: 7d` 字段，首次见
  到 subject 后这段时间内 new-country detector 静默。
- **HIBP 网络依赖**：`api.pwnedpasswords.com` 不可达时不能阻塞登录
  （fail-open）。可缓存 hash prefix → 命中结果，TTL 24h。

### Sequencing hint

**A**（SPI + AsyncRunner）+ **B.impossible_travel**（最有 demo
价值）作为 **第一波**，2-3 周；**B.velocity** + **B.new_country**
作为 **第二波**；**C.HIBP** 独立 sprint（涉及外部依赖 + 缓存），
最后做。**D 告警通路** 与 A 并行。

---

## 3. Operator UX：Admin Web Console + 终端用户自助门户 + GDPR 工作流

### Why now

后端 capability 已经齐整，**面向人的操作面是 0**：

- **运营 / IT**："过去 24 小时谁登录失败、从哪个国家、哪个 client"
  → 现在只能 `GET /api/v1/audit/events` 自己写脚本 / 接 Grafana
  Loki。
- **终端用户**："我的活跃会话、能不能注销具体设备" → 没 UI，
  只有 `POST /token/revoke-all`（全员注销）。
- **合规**：GDPR Art. 15 / 17 / 20（访问 / 删除 / 可移植）请求来
  时，没有标准化的导出 / 删除流水线；audit redactor 是工具，没人
  调它。
- **客户认知**：今天产品的销售姿态是"开发者工具"——竞品（Auth0
  / WorkOS / Stytch）的销售姿态是 "5 分钟从 demo 到生产，包含
  UI + 报表 + GDPR 按钮"。**没有 Admin Console = 不能进入企业
  采购清单**。

这件事的 ROI 不是写新协议，而是 **把已经写好的能力包装出来卖**。

### Scope

**A. Admin Web Console（独立 SPA）**

- 新 monorepo 子目录 `web/admin/`，Next.js 14 + shadcn/ui + tRPC
  over admin REST（gateway 自动生成，零后端改动）。
- 首批 6 个 panel：
  1. **Dashboard** —— 登录成功率 / TPS / 错误率，直接吃 Prometheus
     metrics + audit events 流。
  2. **Clients** —— CRUD + rotate secret + redirect_uris 可视化
     编辑器 + JWKS / cert binding 配置面板。
  3. **Users / Roles / Menus** —— 三方树状选择器，复用
     `permissions.MenuLister`。
  4. **Audit Explorer** —— 全文检索 + facet 过滤 `(tenant, country,
     outcome, reason, client_id)`；trace_id 跳 Grafana Tempo / Jaeger。
  5. **Sessions / Tokens** —— 活跃会话列表、按用户/客户端筛选、
     一键吊销整族；DPoP-bound / mTLS-bound token 显式标识。
  6. **Releases / Snapshots** —— `pin` / `rollback` / `export` /
     `restore` 按钮挂既有 admin endpoints。
- **认证流**：Console 本身用本 SSO 登录（典型的 dogfooding），
  `client_id=sso-admin-console`，scope=`admin:*`。

**A.1 Audit Query API 升级**

- `audit.Query` 增加 facet 字段聚合返回（让前端 filter 面板直接
  渲染候选值，避免 N+1 round trip）：`OutcomesCount`、`ClientsCount`、
  `CountriesCount`。
- 大规模部署可选 sink `audit/sink/clickhouse/`、
  `audit/sink/opensearch/`——SQLite FTS5 在 > 10M 事件后会吃力，
  列存 / 搜索引擎是下一档。

**B. 终端用户自助门户**

- 同一 SPA 框架不同入口：`/me` 路由，`scope=self:read,self:write`。
- 功能：
  - 活跃 sessions 列表 + per-session 登出 + 一键全部登出
  - 改密码 / 绑定 Passkey / 启用 TOTP / 设置备份码
  - 登录历史（来自 audit）+ "新设备登录" 邮件通知 opt-out
  - "下载我的数据"（依赖 §C 的 export 流水线）
- 关键 invariant：**改密码后默认吊销所有 session 除当前**——
  per-`Client` 可配置（默认安全，opt-out 便利）。

**C. GDPR / CCPA / PIPL 合规流水线**

- `POST /api/v1/admin/users/:id:export` —— 调用所有 Provider 的
  optional `Exporter` 扩展，打包 ZIP 返回。结构：`user.json` /
  `sessions.json` / `audit_events.jsonl` / `refresh_tokens.json` /
  `permissions.json` / `webauthn_credentials.json` /
  `mfa_credentials.json`。
- `POST /api/v1/admin/users/:id:erase` —— right-to-be-forgotten
  workflow：
  1. 吊销所有 token + session（已有 `RefreshTokenSubjectIndex.
     DeleteAllForSubject` + `SessionManager.ListByUser → Destroy`
     可复用）
  2. soft-delete user（`Status="erased"`，可登录被拒）
  3. 排队 N 天后真正调用 `UserProvider.Delete` + `audit redactor`
     对历史 audit 事件做 PII 假名化（**保留事件 ID 与时间戳与
     hash 链**，仅替换 PII 字段为 `[REDACTED]` —— hash 链仍可
     校验，因为内容确实变了，但 "事件 X 在时间 T 存在过" 得以
     保留）。
- 新模块 `compliance/erasure/` 持有 N 天 schedule，与 bootstrap
  Step 复用同一 tracker；崩溃恢复友好。
- 文档：`docs/compliance.md` 写明 GDPR / CCPA / PIPL 的字段映射。

### Edge cases / 当前实现具体短板

- **Audit Explorer 查询性能**：SQLite 无 FTS5 索引时全表扫，10w
  events 后端响应 > 2s。建议先加 `audit_events_fts5` virtual table
  on `(actor_id, client_id, reason, metadata_json)`，再决定是否上
  ClickHouse / OpenSearch。
- **GDPR erase 与 audit hash chain 的冲突**：方案如上（保留事件 +
  替换 PII）。这套合规语义必须写进 `docs/compliance.md`。
- **跨 store 删除的事务边界**：今天没有跨 store 事务（每个 SQLite
  backend 独立 DB connection）。erase pipeline 必须设计成 **多步
  + 幂等**：先 revoke（幂等）→ 标记 erased（幂等）→ 后台清理（幂等
  + 可恢复）。任一步崩溃，下次启动 bootstrap 的 erasure scheduler
  会从 checkpoint 继续。
- **Console 的多 tenant 权限隔离**：Console 的访问控制必须能区分
  "我能看自己 tenant 的 audit" vs "我能看所有 tenant 的"。新权限
  分隔：`admin:read.tenant.{tid}` vs `admin:read.global`。已有的
  permissions wildcard matcher 可以表达（`admin:read.tenant.*`），
  但需要把 tenant context 注入到权限检查路径。
- **改密后 session 处理**：默认吊销除当前会话外的所有 session
  这条 invariant 必须可被 client 单独 opt-out（B2C 场景常常希望
  "保留我的所有设备"），不要硬编码。

### Sequencing hint

**A.1 Audit Query facet 是关键路径**——前端 filter 没它跑不动。
A.1（2 周后端）+ B（用户自助门户，3 周前端）+ C（GDPR pipeline，
2 周后端 + 1 周 audit redactor 集成）可以前后端并行。Admin Web
Console panel 按 demo 价值排序：Dashboard + Sessions + Audit
Explorer 三个最早做，Releases / Snapshots 可以晚 1-2 sprint。

---

## 4. Schema 演化与多 store 数据治理：migration runner + 跨 store 一致性 + multi-table 备份

### Why now

`AGENTS.md` 明文写着 **"The next multi-table backend MUST bring
goose/golang-migrate"**——这条判定是在只有 User/Client/Session
三个表的时候写的。今天的 multi-table 后端清单：

- `defaultimpl/sqlite/`：users / clients / sessions / auth_codes /
  refresh_tokens / device_codes / par_requests / jti_replay /
  account_lockout / pairwise_subjects / subject_client_index /
  mfa_challenges / push_approvals / rate_limiter（共 14 张表）
- `audit/sqlite/`：audit_events（1 张表 + 6 index）
- `permissions/sqlite/`：permissions_roles / permissions_assignments
  / permissions_menus（3 张表）
- `tenant/sqlite/`：tenants / tenant_domains（2 张表 + FK CASCADE）
- `authenticators/webauthn/sqlite/`：webauthn_users / webauthn_sessions
  （2 张表）

**= 22 张表，全部用 `CREATE TABLE IF NOT EXISTS` 在 `New()` 阶段
裸建，无版本号、无回滚、无变更日志**。

后果：

1. **任何 schema 变更都是 "破坏性"**：加列、改索引、改默认值都没
   有迁移路径。今天只能让运维 "下线 + dump + 手动 sed + 重启" ——
   一次次迭代的运维代价指数级。
2. **`bootstrap/builtin` 没法和 schema 联动**：bootstrap 知道
   "applied step version"，但 schema 不知道"current version"——
   bootstrap 升级到 v5 + 新 SQL 字段，运维滚动升级时一半副本拿
   不到字段。
3. **备份 / 还原跨 store 不一致**：snapshot 工具只导出 SDK 资源
   层（clients/users/roles/...），不导出 SQLite 物理表。DR 演练
   时 SQLite 表恢复 = `cp old.db new.db` + 祈祷格式不变。

### Scope

**A. Migration framework**

- 选型：`goose`（项目本来已经有 Go 生态共识）或 `golang-migrate`。
  推荐 `goose`——内嵌迁移 + Go-native API + 支持 SQLite。
- 新目录 `defaultimpl/sqlite/migrations/`（embed-fs 内嵌）+
  `audit/sqlite/migrations/` + `permissions/sqlite/migrations/` +
  `tenant/sqlite/migrations/` + `authenticators/webauthn/sqlite/migrations/`。
- 每个 backend 的 `New()` 改成 `goose.Up(db, "migrations")`；首次
  跑 `001_baseline.up.sql` = 把现有 schema 导成 baseline。
- 一次性脚本：扫现有运维 DB → 检查表 schema 与 baseline 一致 →
  写入 `goose_db_version`。**升级路径文档化**。

**B. SDK 层 SchemaVersion API**

```go
type SchemaVersioned interface {
    CurrentSchemaVersion(ctx) (int64, error)
    RequiredSchemaVersion() int64
}
```

- 每个 backend 实现，cmd 启动期检查 `Current < Required` → fail
  fast，"运维需要先跑 `sso-migrate up`"。
- 新 CLI `cmd/sso-migrate`：`up | down | status | force <ver>`。
- bootstrap.builtin 加 v0.5 `verify_schema_version`：在所有
  seed step 之前 fail fast。

**C. 跨 store 一致性：snapshot v2 + multi-store backup**

- `snapshot.Snapshotter` 升级：除了 SDK 资源层（已有），新增
  `physical_backup` mode 走每个 SQLite backend 的 `BACKUP TO`
  pragma → 输出 tar.gz 含每个表的 `.db` 文件。
- `Restorer.Restore` 对应支持物理还原：先 stop server → 替换文件
  → 启动 → bootstrap 校验 schema version。
- 新模式 `ModeMigrate`：导入旧版 snapshot，自动跑 `goose.Up` 拉到
  current。

**D. 多 store 健康度报表**

- 新 admin REST `GET /api/v1/admin/storage:health` —— 列每个 store
  的 schema_version / row_count / db_size / last_migration_at /
  ping_latency_ms。
- Console 的 Storage panel 一眼可见集群健康度。

### Edge cases / 当前实现具体短板

- **Goose 与 modernc.org/sqlite 兼容**：goose 默认走 `database/sql`
  driver，需要 verify modernc 的 sqlite driver 兼容（应该 OK，
  但需要 smoke test）。
- **多 backend 共享同一 DSN**：当前若操作员把所有 backend 指向
  同一 SQLite 文件（cluster-shared 推荐模式），每个 backend 跑
  migrations 必须用独立 `goose_db_version` 表，否则版本号互相
  覆盖。每个 backend 用独立 table name：
  `goose_db_version_<backend>`（如 `goose_db_version_audit`）。
- **生产环境的迁移 downtime**：加列在 SQLite 是元数据操作，瞬时；
  加索引在 10GB+ DB 上会锁写 N 分钟。文档需要明确写"哪些迁移会
  锁写多久"——已有 `audit_events` 已经 indexed 7 个字段，未来加
  索引就有 downtime。Mitigation：迁移文档约定 `large_index:
  true` 标记 + 部署建议（先在副本 A 跑、A 暂时下流量、跑完拉
  上、轮流）。
- **降级 / 回滚**：`goose down` 在生产是危险动作（删字段 = 数据
  丢失）。建议：production deploy 时 cmd 接 `--migrations
  forward-only`，禁用 down migration；只在 dev 环境允许。
- **MFA challenge / push approval 等 TTL 短的表，迁移时数据是否
  保留**：这些表的内容 TTL < 1 天，迁移时 `DROP TABLE + RECREATE`
  比 `ALTER TABLE` 简单且安全。document 哪些表可以 wipe-and-recreate。

### Sequencing hint

**A**（migration runner + baseline）+ **B**（SchemaVersion API +
cmd CLI）作为 **第一波**，3-4 周。**C**（snapshot v2 物理备份）独
立 sprint，依赖 A 完成。**D**（storage health admin REST）插在
Console（方向 §3）里实现，1 周。

不能再拖：每加一个 multi-table backend，这件事的迁移成本就翻倍。
今天 22 张表，再迟 6 个月可能 30+。

---

## 5. 最后一公里协议：CIBA + JWE response encryption + FAPI 2.0 compliance profile

### Why now

上一版 ROADMAP §5 的 6 个项目里，已经做完 4 个（Signed Metadata
/ DPoP Nonces / Pairwise Subject / JWE for JAR）。**剩下 3 个未做项
放在 FAPI 2.0 / Open Banking 客户清单视角下是 "一组"——缺一项就
被 RFP 表筛掉**：

- **CIBA**（OIDC Client-Initiated Backchannel Authentication）——
  银行柜员推到客户手机确认，IoT 设备推到用户 PIN 输入——FAPI
  Brazil / 开放银行的硬需求。**今天 0 实现**。
- **JWE for id_token / userinfo response**（OIDC Core §10.2）——
  FAPI 2.0 baseline 要求；某些金融 RP 要求 id_token 加密；当
  `id_token` 含 PII 时业务要求传输层之上再加密。今天我们已经实现
  了 JAR 的 JWE（请求方向），**响应方向（id_token + userinfo）的
  JWE 是缺的**。
- **FAPI 2.0 profile 总开关**：所有零件都在了（PAR + JAR-required
  + DPoP / mTLS + pairwise + signed_metadata + 严格 alg allowlist），
  缺 **single `oauth_compliance: fapi_2` 开关 + inspection mode**。

### Scope

| 工作项 | 大致工作量 | 标准 |
|---|---|---|
| `POST /backchannel-authentication` + `/bc-authorize` 长轮询 + push notification 模式；复用 `defaultimpl.PushMFAProvider` 已有的 `PushApprovalStore` 实现 pending request 的 store | L | OIDC CIBA |
| `id_token` 加密响应：`id_token_encrypted_response_alg` + `_enc` per-client 配置；输出从 JWS-only 升级到 JWE(JWS(...)) 嵌套；解密密钥从 `Client.JWKS` 中按 `enc=A256GCM` 等 alg 选择 | M | OIDC Core §10.2 |
| `userinfo` 加密响应：同上但 endpoint 是 `/userinfo`；client 通过 `userinfo_encrypted_response_alg` registration 字段声明 | M | OIDC Core §5.3.2 |
| FAPI 2.0 compliance profile：单个 `oauth_compliance: fapi_2` 开关，开启后强制（PAR-only、`request` 必签 + 必加密、PKCE S256、DPoP-only or mTLS-only、no implicit、pairwise sub、signed_metadata、ACR `urn:openid:fapi:...`、严格 alg allowlist） | L（主要是测试 + inspection mode） | FAPI 2.0 Security Profile |
| FAPI 2.0 inspection mode（"开关打开但只 audit 不拒绝"）—— 让运维 ramp-up 看到哪些 RP / 配置违规：`fapi_2_inspection_only: true` 时所有违规走 audit `fapi_compliance_violation` 而非拒绝 | S | 自定义 |

### Edge cases / 当前实现具体短板

- **CIBA 与 PushMFAProvider 复用**：CIBA 的"等待用户确认"语义与
  Push MFA 完全一致——都是 **server-issued challenge → out-of-band
  device confirm → server polls/notifies**。现有
  `PushApprovalStore` + `PushTransport` SPI 直接可以复用，只需要
  在 `PushApproval` 上多挂一个 `request_context`（CIBA 的
  authorization params 序列化）；CIBA 的 polling endpoint 是
  `/token` 的 `grant_type=urn:openid:params:grant-type:ciba`，
  实际上就是 Push 流的 long-poll 包装。**这件事在我们当前架构下
  比从头实现轻得多**，是个隐藏的 ROI 高点。
- **CIBA 的 `binding_message`**：必须显示给用户（防 phishing：
  "你在 pad 上点击的金额是 ¥{N}"）——这要求 device-side app
  实现，服务端只能保证字段传递正确性。文档要写清楚 SDK 契约。
- **JWE 解密 / 加密失败 vs 签名验证失败 —— oracle-leak 风险**：
  在请求方向已经处理（`jwe.go` 已 collapse 到
  `invalid_request_object`）。响应方向有不同问题——加密失败时
  不能透露"找不到 RP 公钥"vs"加密计算失败"。统一返回
  `server_error`。
- **id_token / userinfo 加密的密钥管理**：响应加密需要 RP 的公钥
  （在 `Client.JWKS` 里以 `use:enc` 标记）。当前 SDK 已经能区分
  `use:sig` 和 `use:enc`（JWE-JAR 已经走这套），但 `Client` SPI
  没有显式 "encryption alg/enc registration" 字段，需要加：
  `id_token_encrypted_response_alg` / `_enc` / `userinfo_*` 6 个
  string 字段（与 OIDC Core 命名严格一致，方便 DCR 自动映射）。
- **FAPI 2.0 inspection mode 的设计**：必须是"开关打开但只 audit
  不拒绝" → 让运维看到哪些 RP / 配置违规。每条违规走 audit
  `fapi_compliance_violation` + 包含 `rule_id` + `client_id` +
  `violation_detail`，运维拿这个清单逐项 fix。**全或无切换对客户
  是悬崖**——这是 FAPI 1 失败案例的核心教训。
- **CIBA 的 polling rate-limit**：与 device flow 类似，client 会
  100ms 间隔狂轮——必须强制 `slow_down` 响应（RFC 8628 §3.5），
  与 device flow 的实现复用。

### Sequencing hint

按 ROI 排序：**JWE response encryption**（2 sprint，单独 review
防 oracle leak）→ **FAPI 2.0 profile + inspection mode**（1
sprint，主要工作是测试矩阵）→ **CIBA**（独立 sprint，复用
PushMFAProvider 基础设施）。

如果一定要先做一件——**FAPI 2.0 inspection mode**。理由：所有
零件已经齐了，只是统一开关 + audit 出口。客户开 inspection mode
立刻就能拿到合规缺口清单——这是销售对话里"我们已经支持 FAPI
2.0 baseline" 的硬证据。

---

## 边界情况 & 性能优化（持续清单）

下面这些颗粒度不够独立方向，但建议作为常规迭代的 "sprint filler"
逐项消化。每条都对应一个具体的代码位置或行为契约。

### 性能

- **Discovery 文档缓存命中**：`WithDiscoveryDocCacheTTL` 已默认
  5s，但 `handleOIDCDiscovery` 内部 client store 4 次 List 仍然
  在 cache miss 时全表扫。规模上去后可以加 `ClientStore.Stats()
  → (count, hash)` 廉价方法，cache 用 hash invalidate。
- **BCL 多 RP 扇出并发化**：`backchannel_logout.go` 的 fan-out
  当前是串行 for-loop，10 个 RP × 500ms = 5s 阻塞 `/end_session`。
  改成 `errgroup` + `WithMaxConcurrent` 限流。
- **`validateAnyToken` 顺序优化**：`sso.go` 线性试每个 issuer。
  改成先 peek token 形态（含 `.` = JWT；不含 = opaque）再 dispatch；
  Session + JWT 双 issuer 下减少一次失败的 JWT 签名解析。
- **JWKS endpoint single-flight refresh**：`remote.JWKSCache` 已经
  有 single-flight，但服务端 `handleJWKS` 本身没有；OpenResty 边缘
  缓存能扛但服务端被 N 副本同时拉时还是会重算。给 `handleJWKS` 加
  `sync.Once` per rotation epoch。
- **MFA Push polling 优化**：当前 `PushMFAProvider.Verify` 是固定
  间隔 polling。条件变量 / channel-of-id 模型（callback 主动 push
  到等待的 Verify goroutine）可以把响应延迟从 ~poll_interval 减
  到 ms 级。SDK 已 noted "production deployments wanting
  push-without-polling fork PushMFAProvider"，做成内置可选项。

### 边界情况

- **Tenant 暂停的主动吊销**：今天 `Tenant.Status=suspended` 只让
  新请求失败，已经发出的 token / session 仍然有效。建议：suspend
  时触发后台 job 调用 `RefreshTokenSubjectIndex.DeleteByTenant`
  + `SessionManager.DeleteByTenant`（后两个 SPI 都还没有，需要
  补）。**关联方向 §3 的 GDPR pipeline**：跨 store 删除工作流是
  一份，suspend / erase / archive 都复用。
- **跨副本缓存失效需要事件总线（多副本正确性盲点）**：
  `Server.InvalidateTenantSuspensionCache(id)`
  （`server_extensions.go:1769`）是**进程内 map 清除**——管理员在副本
  A 暂停某 tenant 后，副本 B/C 仍按本地 30s TTL
  （`tenant.suspension_check.cache_ttl`）继续放行该 tenant 的 token。
  discovery snapshot / discovery-doc / JWKS 三个缓存同样是 per-replica
  TTL。**安全语义边界**："立即暂停 / 立即吊销 client" 在多副本下实际
  传播延迟 = 缓存 TTL，这正是已知坏主体仍在工作的窗口；唯一缓解是缩
  小 TTL，反而加重 §1 deferred Redis 想解的查询压力——两难。仓库已有
  现成范式：`etcd.Watch` 已驱动 netpolicy + registry 的集群实时更新，
  但没接到这些 auth 安全缓存上。**建议**：抽 `InvalidationBus` SPI
  （`Publish(event)` / `Subscribe()`），memory（单节点 no-op）+ etcd
  （复用 Watch）双 peer；缓存变更点（暂停失效、discovery busting、未来
  §1 的密钥轮换事件、token 吊销）统一 publish，各副本订阅清本地缓存。
  这把一次性的失效回调升级成一等公民的集群协调原语，是 §1 密钥轮换的
  `ActiveKID` 强一致（line 189-193）和"全局 token 黑屏 30 秒"
  （line 166-169）的共同底座。
- **DPoP nonce 进程内密钥不安全（多副本）**：`main.go:991` 自带告警
  *"dpop nonce: no key_file configured — generating process-local key
  (NOT safe for multi-replica)"*——未配 `key_file` 时每副本各持一把
  nonce 密钥，nonce 在副本间不可互验。短期：文档强制多副本必须配置
  共享 `key_file`；长期：nonce 密钥纳入 §1 的 `SigningKeyProvider` /
  共享存储统一治理。
- **`/par` 的 body 大小限制**：全局 `body_limit` 默认覆盖所有路径，
  但 JWE-wrapped JAR JWT 可能 > 全局默认。建议 per-endpoint
  override：`security.body_limit.per_endpoint: {"/par": "64KB"}`。
- **graceful shutdown**：cmd 已有三套 retention scheduler 的
  cancel coordinated（audit/snapshot/push），但 SIGTERM 主路径
  还没有显式 "等 in-flight `/token` 跑完再退出"。需要 `errgroup`
  + signal handler + http.Server `Shutdown(ctx)` 串联起来。
- **跨 issuer revoke 的最终一致**：`/token/revoke-all` 调
  `revokeAcrossIssuers` 但任一 issuer 失败不会阻断、也不报错。
  建议：失败的 issuer 名收集进 audit `partial_revoke_failure`，
  以便运维后续手动处理。
- **bootstrap admin password 只打印到 stdout**：容器化部署里
  stdout 经常是 journalctl + 异步 sink，丢失风险。建议加
  `--bootstrap-admin-password-file=/path/secret` 把首次密码写到
  指定路径并 chmod 0600。
- **OIDC `claims` 参数的深度处理**：`claims_param.go` 当前解析
  字段名但不强制 essential claim 必须 honor——upstream required
  claim 没法满足时应该返回 `invalid_request` 而非沉默忽略。
- **DPoP `htu` 与 reverse proxy**：`requestURLForDPoP` 已经吃 XFF，
  但 `htu` 校验在严格 FAPI 模式下要求精确匹配，proxy 改写过的
  URL 与 RP 看到的可能不一致。需要 deploy 文档明确 "`X-Forwarded-*`
  必须在 ingress 层稳定 set"。
- **Push 回调 IP allowlist 与 IPv6**：`callbackClientIP` 当前从
  RemoteAddr / XFF 取，但 `net.ParseCIDR` 对 IPv4-mapped IPv6
  地址（`::ffff:10.0.0.1`）的匹配在某些 ingress 下不稳定。需要
  在 doc 标注，或在 helper 内做 IPv4 提取。

### 协议小颗粒

- **`goreleaser publish` 启用**：`.goreleaser.yaml` 当前
  `disable: true`，CI 跑完不发布。挂目标：GitHub Releases +
  ghcr.io container + cosign signature。
- **`/end_session` `state` 参数透传**：OIDC RP-Initiated Logout
  §3 要求 `state` 在 `post_logout_redirect_uri` 上原样回传，需
  spot-check 是否实现。
- **`acr_values` 在 token-exchange 上的处理**：今天透传 inbound
  ACR，但 step-up 后的 token 应该用更高 ACR——`handle_token_exchange.go`
  需要支持 caller 显式声明 `acr_values` 升级请求（同 `/auth/login`），
  由 server 验证可达性。
- **SAML 2.0 AS / IdP 角色**：上一版 §2B 拆出来的 SAML 联邦没做。
  企业 / 政府客户仍需。**单独立项**（约 4-6 周）。
- **SCIM 2.0**：上一版 §2C 没做。HR / IT 自动 provisioning 的硬
  需求。**单独立项**（约 3-4 周）。

---

## 未列入但已经考虑过的方向

- **Redis 后端**：上一版 §1 的 Redis 没做（SQLite peer 覆盖了
  正确性）。Redis 的 ROI 是 **performance**（>1k QPS）而不是
  correctness——但代价是引入一个新的有状态依赖。建议：等真有
  >1k QPS 客户 inbound 时再做，否则维护成本不划算。SPI 已稳定，
  社区/客户自己实现也行。
- **跨区域 active-active**：依赖方向 §1（HSM 解决密钥跨区分发）+
  Redis（解决 store 跨区一致）。etcd 跨区 raft 是独立的容量
  规划课题，不属于 SDK 范畴；多区方案应交给运维而非 SDK。
- **CLI 工具 `ssoctl`**：admin REST 已经覆盖所有 capability，
  CLI 是 DX 优化不是能力扩展，留到 v2。Console（§3）做完后 CLI
  的需求会变弱。
- **GraphQL admin API**：REST gateway 已经 proto 自动生成，多一层
  GraphQL 是维护成本，没有清晰需求场景。
- **多语言 SDK（Python / Node / Java client lib）**：标准 OAuth/OIDC
  生态有大量成熟 lib，重复造轮没价值；focus 在让本服务输出 **正确
  的标准 endpoints** 上。
- **OAuth 1.0a / Kerberos / RADIUS / NTLM 兼容层**：历史协议，企业
  里仍有但已经被网关产品（Keycloak / PingFederate）覆盖，不是新
  进入者的差异化点。

---

## 优先级摘要

| # | 方向 | 类型 | 阻塞下游 | 建议先后 |
|---|---|---|---|---|
| 1 | 签名密钥 HSM/KMS 抽象 + 自动轮换 + per-tenant 隔离 | **合规 / 安全 gate** | 金融 / 政府 / FAPI 客户准入 | **P0**，金融客户对话开始就拦下 |
| 2 | 异步行为异常检测 + 凭据健康度 | 产品差异化（auth lib → identity 平台） | 防撞库 / 防 ATO / SOC2 监测 | **P0**，与 §1 可并行 |
| 3 | Admin Web Console + 用户自助 + GDPR 工作流 | 产品化 + 合规闭环 | 企业版定价 + 上线公关 | **P1**，§2 落地后跟进 |
| 4 | Schema migration framework + 跨 store 一致性 | 操作债 / 长期可维护性 | 任何 schema 变更 | **P1**，越拖代价越高 |
| 5 | CIBA + JWE response encryption + FAPI 2.0 profile | 协议补完位 | Open Banking / 金融 RFP | **P2**，§1 + §2 落地后跟进 |

**单独提示**：方向 §4（migration framework）虽然排第 4 位，但它的
"今天不做、明天就更贵" 特性强于其他几项——每加一个 multi-table
backend，未来的迁移成本就翻倍。如果资源允许，§4 可以 **作为
sprint-filler 与 §1/§2 并行**，每次任意一个 PR 顺带把它对应的
backend 接入 migration runner，3 个 sprint 就摊完。

---

## 文档版本

| 时间 | 版本 | 编辑 |
|---|---|---|
| 2026-05-21 | v1 | 初版（多副本正确性 / WebAuthn / HSM / Console / 协议补完） |
| 2026-05-22 | v2 | 上版 §1 / §2A-B / §5 已大量落地；refocus 到 HSM + 异步异常检测 + Console + migration + FAPI 2.0 |
| 2026-05-22 | v2.1 | **§2（异步行为异常检测）整组落地**：`AnomalyDetector` SPI + `AsyncAnomalyRunner` 调度池 + `RecentLoginStore` / `IPFailureCounter` 两套 SPI（memory + sqlite peer 双后端）+ 5 个参考 detector（impossible_travel / velocity_burst / new_device / new_country / brute_force_shadow）+ 3 个新 metric vector + cmd YAML 完整 wire。剩 §1 HSM / §3 Console / §4 Migration / §5 CIBA。 |
| 2026-05-25 | v2.2 | **复扫确认 5 方向全部成立、全部未落地**（v2.1 后 40 个 commit 均为内部重构）。记录结构性里程碑：Hexagonal handler 抽取（根目录 → 6 源文件，handler 迁入 oauth//oidc/，`oauth` 不可 import `oidc`）+ 测试按功能归位（89 集成测试入 `test/`，根目录 `.go` 101 → 8）+ AGENTS.md 压缩 977 → 709。新增两条边界情况：**跨副本缓存失效需要 `InvalidationBus` 事件总线**（`InvalidateTenantSuspensionCache` 仅进程内，多副本传播延迟 = 缓存 TTL）+ **DPoP nonce 进程内密钥多副本不安全**。 |
| 2026-05-25 | v2.3 | **10 轮开发落地**：(1) `cluster/` InvalidationBus（SPI + memory + etcd + cmd wiring + tenant-suspension/discovery 两个消费者）——闭合 v2.2 的跨副本失效边界情况；(2) §1 签名密钥治理大部分落地 —— `Ed25519Signer` KMS/HSM 接缝 + 运行时 `RotateKey`/`RetireKey` 重叠期轮换 + `StartRotation` 自动调度 + cmd `keys.rotation` 配置 + `signing_key_rotated` 审计 + `sso_signing_key_rotations_total` 指标。剩 §1 的 KMS peer/多算法/per-tenant、§3 Console、§4 Migration、§5 CIBA。 |
| 2026-05-25 | v2.9 | **第六个 10 轮：多算法签名矩阵收口**：`RSAJWTIssuer`（RS256/PS256，PKCS1v15/PSS，2048 位最小，KMS 接缝，严格 per-issuer alg gate）+ ES256/RSA `StartRotation` 调度（补 ES256 缺口，cmd rotation 对四种 alg 生效）+ `WithSupportedSigningAlgs` 接纳 RS256/PS256 + cmd `keys.signing.alg: rs256|ps256` + discovery/JARM alg 列表经 `SigningAlgValues` 反映真实 alg。签名矩阵现完整（EdDSA/ES256/RS256/PS256，均含轮换+调度+KMS 接缝+alg-confusion 防护）。剩 KMS 具体 peer、per-tenant 密钥、方向③④。 |
| 2026-05-25 | v2.8 | **第五个 10 轮：ES256 签名 + JARM + FAPI client-auth**（两条并行 worktree agent）：(1) `ECDSAJWTIssuer`（ES256/P-256，go-jose，全接口集 + `ECDSASigner` KMS 接缝 + JWKS EC 公钥）+ `WithSupportedSigningAlgs` 配置化 alg gate + 严格 kid→alg + cmd `keys.signing.alg`；(2) JARM（`oidc/jarm.go`，`response_mode=jwt`+三变体，经 `oidc.JARMSigner` 接缝，fail-closed，discovery 广告，cmd `oauth.jarm.enabled`）；(3) FAPI `fapi:client_auth` 规则（禁 shared-secret，要求 private_key_jwt/mTLS）。剩 RS256、ES256 StartRotation、KMS peer、方向③④。 |
| 2026-05-25 | v2.7 | **第四个 10 轮：FAPI 2.0 Compliance Profile + Inspection Mode**：新 `fapi/` 纯逻辑包（Mode + Validator + 5 条 baseline rule，nil/Off-safe，8 单测）+ `/auth/login` 与 `/token` 强制点接入（inspection 只审计、enforce 拒为标准 `invalid_request`）+ enforce 模式 discovery 反映约束 + `fapi_compliance_violation` 审计 + `sso_fapi_violations_total{rule,mode}` 指标 + cmd `oauth.compliance.{profile,inspection_only}`。刻意不做多算法签名（无 RS256/ES256 signer 时扩 allowlist 是 footgun）。剩方向 ① 的 JARM/client-auth 约束、方向 ②③④。 |
| 2026-05-25 | v2.5 | **第三个 10 轮：§5 最后一公里协议（前两件）落地**：(1) OIDC JWE 响应加密 —— id_token (Core §10.2) + userinfo (Core §5.3.2)，`Client` 4 个 enc 字段 + DCR 映射 + `security.JWEEncrypter`/`RSAJWEResponseEncrypter` + fail-closed 无 oracle + discovery 广告 + cmd `oidc.response_encryption` + WebAuthn 路径补加密；(2) OIDC CIBA Core 1.0 poll 模式 —— `oauth.CIBAStore`(memory+sqlite/migrate) + `CIBATransport` + `/backchannel-authentication` + `grant=urn:openid:params:grant-type:ciba` poll(`authorization_pending`/`slow_down`) + discovery + 审计 + cmd `ciba.*`(含 PruneExpired 调度)。两条主线并行 worktree agent 开发。剩 §5 的 CIBA ping/push、多 alg、FAPI 2.0 profile；§1 KMS/多算法/per-tenant；§3 Console/GDPR。 |
| 2026-05-25 | v2.4 | **第二个 10 轮：§4 Schema Migration 框架落地**：`migrate/` 纯 Go runner（versioned / per-namespace / forward-only / `BEGIN IMMEDIATE` 串行 / SQL+Func 步）+ 全部 6 个 SQLite 落点纳管（含 refresh_tokens 的 Func 补列迁移）+ `migrate.Status` + `cmd/sso-migrate` 离线 CLI。附带修复 `loadAESGCMKey` 裸密钥换行裁剪 bug（曾间歇 flake CI）。剩 §1 KMS peer/多算法、§3 Console、§5 CIBA/JWE/FAPI。 |
