# ROADMAP

> 基于 2026-05-25 复扫对 `github.com/snaplink/sso` 的全局扫描，从资深
> 架构师 / PM 视角列出下一阶段投入产出比最高的 5 个扩展方向。
>
> 每项包含 **Why now**（这件事为什么比别的事更值得做）、**Scope**
> （拆到可独立 PR 的颗粒度）、**Edge cases / 当前实现具体短板**、
> **Sequencing hint**（与既有功能的耦合点）。
>
> 排序按"如果只能挑一件先做"的优先级。文末附 **边界情况 & 性能优化**
> 清单 + **优先级摘要**。

---

## v3.0（2026-05-25）—— post-v2.9 复扫：重排后的 3–5 个方向【当前生效】

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
