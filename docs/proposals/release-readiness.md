# Release readiness implementation

## Goal and boundary

Deliver a reproducible stock SSO container and a gated multi-platform Docker Hub
release, then validate the first business integration and production state
boundaries. This is an implementation tracker, not release or certification
proof. Browser applications, Billing and Stripe remain separate deployments.

## Ordered work

| Wave | Scope | Completion evidence |
|---|---|---|
| 1 | Explicit deploy-artifact refresh; retain the read-only drift gate | Targeted sync tests and complete `make ci` |
| 2 | Bounded idempotency responses without bypassing grant/session validation | Negative, expiration and backend tests; race repetition |
| 3 | Reproducible development container/Compose startup | Clean bootstrap, nonroot writable state, probes and restart tests |
| 4 | Opt-in Docker Hub version publication | Protected dispatch/tag, gates, both architectures, digest/SBOM/signature checks |
| 5 | Reference application, shared-state and recovery acceptance | Tenant/client isolation, refresh/logout, key rotation, recovery and load evidence |

## Product decisions and external dependencies

- Docker Hub namespace, repository visibility and minimum-privilege registry
  credentials must be provisioned by the operator. Do not publish implicitly.
- ARM CI and a real Apple Silicon machine must execute runtime acceptance;
  cross-compilation/ELF inspection alone are not native runtime evidence.
- Capacity, P99, revocation latency and RPO/RTO need a named deployment target.
- Persistent Webhook delivery, optional resource-server event revocation,
  incremental session scans and primary Passkey recovery each need their own
  bounded specification and security review. They are not prerequisites for a
  small single-process evaluation deployment, nor silently promised features.
- Official OIDC/FAPI certification requires an externally reachable trusted
  HTTPS issuer, a chosen certification profile and an OIDF account/result.

## Owners and files

- Deploy sync: `checks/sdk_drift.py`, `checks/test_sdk_drift.py`, `Makefile`.
- Idempotency: existing SSO/middleware adapters, OAuth grant handlers and real
  memory/Redis stores; keep production Go budgets and the 60-file SSO ceiling.
- Containers: `ops/deploy/compose`, existing Dockerfile/CI/deployment contracts.
- Publication: a dedicated opt-in workflow and its contract tests; do not
  reinterpret the existing GoReleaser/GHCR flow as a Docker Hub release.
- Integration: `test/` (`package ssotest`); frontend implementation stays external.

## Acceptance and non-goals

- Apply `AGENTS.md`, U1-U9, O1-O11 and S1-S7 as relevant; preserve each existing
  oracle-safe response and fail-open/fail-closed policy.
- Never bypass hooks, weaken gates or add exemptions. Cold profile operations
  do not mutate root Go modules; the separately bounded
  [dependency security remediation](release-dependency-security.md) owns only
  the required root security-version update.
- Artifact sync is explicit, validates canonical generation first, overwrites
  only the three declared derived copies and rejects paths escaping the tree.
- Generic token replay is limited to built-in client credentials, retained for
  at most one minute and revalidated against current authorization/revocation.
  Stateful grants use their own stores; local coordination is not cluster-wide
  first-miss ownership or exactly-once issuance.
- Refresh grace never extends the original grant/access deadline. Replays need
  reuse evidence, a live same-family successor, current session/user/client,
  scopes and sender bindings. Apply deadlines to all four store backends.
- Persist Redis family-reuse evidence before atomic GETDEL, refusing consume
  on marker-write error; its TTL must cover the remaining original grant.
  Grace keys must not contain raw credentials. DSN-owned grace databases must
  close after their cleanup workers drain; panic recovery must release local
  client-credentials locks without caching an unfinished response.
- Development credentials/ephemeral state are not production configuration.
- No new protocol family, general plugin platform or universal queue framework.

## Compatibility and rollout

Keep feature-off behavior unchanged. Changes to optional replay semantics must
be documented and tested. Use additive optional storage capabilities rather
than breaking existing storage implementations. Production deployments stage
configuration and persistent state before switching traffic. Deadline-less
legacy grace responses and Redis's former plaintext grace keys are not
replayed; old entries expire on their existing TTL. Rolling upgrades may need
fresh authorization. Registry pushes are opt-in; no pull request can publish,
and credentials are never build args.

## Verification

After every Go edit: build, vet and committed architecture/maintainability gates.
Each wave adds adjacent targeted tests and an independent diff/contract review.
Before handoff: root race tests, E2E tests and `make ci`; module/profile changes
also validate module metadata and final binary inventory. Native ARM, registry
publication and certification stay incomplete until their external evidence
exists.

## Execution status

Container/scan/promotion results below describe the checkpoint **before** the
[lifecycle follow-up](refresh-grace-startup-cleanup.md). They remain evidence for
those older bytes, not acceptance of the updated lifecycle source; updated OCI
artifacts require rebuild, runtime verification and rescanning.

- Wave 1 implemented: explicit deploy-copy refresh, scanner regression tests
  and backchannel-logout test scheduling fix. Complete `make ci` passed at that
  wave; this does not certify subsequent worktree changes.
- Wave 2 implemented and reviewed: Redis marker ACK before consume, hashed
  grace keys, bounded retention, a shutdown drain/close helper and panic-safe
  lock release. The later lifecycle follow-up found and fixed the missing stock
  app handoff; the original helper-only test did not prove that wiring. Optional pending protection closes the consume-to-Remember
  window; final expiry and ready sender/client failure checks retain strict
  reuse revocation. Memory/SQLite/Redis/real PostgreSQL concurrency and binding
  tests passed under `-race -count=10`. This is not distributed first-miss
  ownership or exactly-once issuance; legacy custom stores/mixed replicas
  retain the documented limitations.
- Wave 3 latest-image development acceptance passed: isolated clean Compose
  bootstrap, readiness/discovery/JWKS, token no-store, restart, stable signing
  keys and durable revocation. The standalone nonroot/read-only smoke passed
  against the same loaded OCI image. This does not certify optional Compose
  profiles, browser business flows or production recovery.
- Wave 4 workflow and 47 container contracts are implemented; CI and publication
  builds refresh bases. Latest five-target amd64/arm64 artifacts passed index,
  static ELF/nonroot, SPDX/SLSA payload and subject-link checks. The same SSO
  executable/attestation digests survived loopback-only registry transfer,
  two-platform index merge and raw-byte digest verification. Local provenance
  is not authenticated builder identity or a public release/signature. These
  local readiness artifacts explicitly contain dirty-worktree build metadata;
  they are not clean-tag release artifacts and must not be published as such.
- Actual SSO scans blocked HIGH findings in cached Go 1.26.5, crypto, gRPC and
  subsequently net. Go 1.26.9 bases and the separately scoped security versions
  are selected; necessary nested-module MVS updates preserve ownership. The
  current combined source passed build/vet/root gates, repeated security races,
  E2E and complete `make ci` with real PostgreSQL16 (300 connections) and Go
  package parallelism 8, without changing test assertions or thresholds.
  Static dependency review found no P0/P1. Evidence: ignored artifacts under
  `dist/release-readiness/`, including `ci.log`, `grace-backends-race.log`,
  `token-security-race.log`, `e2e.log` and `dependency-review.txt`.
- Registry access recovered after earlier network timeouts. All five current-
  security-version OCI artifacts were rebuilt with fresh Go 1.26.9 bases,
  SBOM and maximum provenance. All ten architecture-specific Trivy scans
  exited zero: no HIGH/CRITICAL vulnerability or secret findings, without
  ignore-unfixed or severity exceptions. Scans read verified original OCI blobs,
  with explicit platform selection; imported Docker config normalization is not
  used as digest evidence. `scan-binding.json` records original config IDs,
  matching report IDs, report/archive hashes, scanner arguments and exit codes.
  Reports: `dist/release-readiness/scans/`;
  artifact inventory, runtime, Compose and promotion results are alongside
  them. This is a scanner/database checkpoint, not absence-of-vulnerabilities
  proof. Independent closure review found no remaining scoped P0/P1 after
  archive-resource and digest-binding fixes. Native ARM, Docker Hub protected
  publication and authenticated signature/evidence acceptance remain incomplete.
- Concurrent Browser SSO/schema/auth-time changes are preserved and covered by
  the combined-tree gate, not claimed as this task's implementation. SDK regen
  and explicit deploy sync passed; the earlier generation drift is resolved.
- Lifecycle follow-up: failure cleanup now cancels/drains grace before unrelated
  cleanup; successful assembly now transfers its cancel/done handles to the app.
  Real SQLite owned-handle close, caller-owned PostgreSQL pool survival, later
  grant-wiring failure, real stock boot/shutdown, feature-off/memory, repeated
  cleanup and deadline-expired asynchronous drain have adjacent tests. The wait
  uses the existing shutdown timeout; it is not a bound on all startup cleanup.
  No OAuth issuance/replay or helper fail-open policy changes. Final real-backend
  and token-security race10, E2E and complete real-PG-backed `make ci` passed;
  source-only independent review found no scoped P0/P1. Its forced-shutdown
  concurrent-close P2 is addressed by the separately bounded
  [grace wrapper follow-up](refresh-grace-concurrent-close.md). Logs/reviews are under
  `dist/release-readiness/lifecycle/`; no new container acceptance or publication
  is claimed by this source-only follow-up.
- Grace concurrent-close follow-up completed: real SQLite/PostgreSQL races and
  nil-pointer panics were reproduced, then fixed with per-operation atomic DB
  snapshots and joined close. Owned SQLite closes after pruner drain; borrowed
  SQLite/PostgreSQL wrappers become terminal without closing caller pools.
  Nil SQLite construction now returns an error. Final backend/stock forced-HTTP
  shutdown/grace-security race10, E2E and full real-PG `make ci` passed; read-only
  closure review found no scoped P0/P1/P2. Evidence:
  `dist/release-readiness/concurrent-close/`. This establishes safety for these
  wrappers, not all store shutdowns, foreground-request draining or new OCI
  acceptance. Pre-detach operations can finish with their original snapshot.
- Wave 5a local reference acceptance is implemented: four confidential BFF/RP
  registrations span Orders/Reports and two tenants, with real HTTP AS/API
  listeners, stored-password authentication and memory stores. Six scenarios
  cover independent grants/PKCE/ID-token binding, API tenant/client/scope/live-
  permission isolation, refresh/reuse, explicit online-vs-offline revocation,
  selected-session logout and single-signer JWKS key overlap. Tests also exposed
  and fixed the existing logout no-store gap; OpenAPI and its declared deploy
  copy agree. Reference/adjacent race10, compatibility race3, E2E and final
  real-PG `make ci` passed; independent source/contract reviews found no scoped
  P0/P1/P2. [Run and boundaries](../sso/reference-apps.md);
  evidence: `dist/release-readiness/reference-apps/`. This uses SDK composition
  in one process, not a deployed UI, stock service or cross-process shared-state
  acceptance; Browser SSO implementation remains separately owned.
- Wave 5b adds independent SDK AS processes sharing real PostgreSQL identity,
  password/client/tenant/session/code/refresh stores, with parent-only seed,
  private shared signing/lookup keys and one loopback issuer gateway. Three
  scenarios verify cross-process grants/session resume, pinned concurrent code
  single-use, completed-operation survival across explicit AS kill/restart,
  persisted refresh-family reuse and shared-session logout denying peer refresh.
  Final process and lifecycle-guard race10, compatibility, E2E and full real-PG
  `make ci` passed; source review closed crash-classification and reap-before-
  schema-DROP findings, with no remaining scoped P0/P1/P2. See
  [bounded scope](reference-process-acceptance.md) and
  `dist/release-readiness/reference-process/`. No production code changed in
  this slice. It is not stock deployment, database crash/failover, in-flight
  exactly-once, key/JWT-revocation distribution, multi-host HA or RPO/RTO proof.
- Wave 5c exercises two real freshly built root `cmd/sso-server` command
  processes, not SDK helper binaries: explicit multi topology without unsafe
  override, shared PostgreSQL identity/session/tenant/password/OAuth, runtime
  readiness and SIGTERM shutdown. The three existing cross-process grant/
  atomic-code/crash-restart assertions are reused, plus a specific boot refusal
  for process-local critical state. This exposed SQLite schema probing against
  PostgreSQL; the driver predicate and native ordered-inventory/ahead-schema
  constructor guards are now regression-tested. Final stock40 and SDK30 race
  scenario passes, lifecycle/schema race10, compatibility, E2E and complete
  real-PG `make ci` passed. Independent review has no remaining scoped P0/P1/P2.
  [Bounded stock scope](stock-process-acceptance.md); evidence:
  `dist/release-readiness/stock-process/`. Binary digest/module metadata is local
  evidence, not authenticated source provenance or a clean-tag release. This
  is one-host stock command configuration, not fresh OCI, a browser application,
  distributed keys/JWT revocation, multi-host HA or database/DR/load acceptance.
- Wave 5 and the separately scoped extension projects remain incomplete.
  External publication, Apple Silicon, production HA/recovery/load targets and
  certification have no completed acceptance evidence.

## 历史 OCI 检查点：cycle-01（以下保留解决阶段记录）

后续 runner 根门禁和只读验收已通过，见该轮 `gates/result.json` 和
`acceptance.md`；以下 pending 字段是当时记录，不覆盖最终历史结论。
**cycle-02 工具/声明修改后 COPY-context 指纹已变化，该检查点不再是新工作树的
current-source OCI acceptance。** 原始 archive、扫描和验收证据保留不变。

2026-10-15 本轮五个服务的 AMD64/ARM64 OCI 构建均退出 0，使用
`--pull --sbom=true --provenance=mode=max`。初次扫描因私有布局访问被拒退出 1，
报告为空；该失败记录保留，不计为无 findings。独立只读审查提出两项 P2：
扫描身份不匹配，以及 attestation manifest 自身的 `subject` descriptor 未校验。

有界解决的代码和新证据位于下述证据根目录的 `resolve-01/`：

- 扫描器显式使用宿主 UID/GID 1000:1000；只对新 owned 缓存卷初始化权限。
  真实 Trivy 容器读取 0700/0600 布局、写入私有缓存的回归退出 0；未放宽
  cap-drop、只读根文件系统/输入挂载或文件权限。
- 补查存在的 manifest `subject` 类型、blob hash/size，以及与 executable 和
  annotation 的一致性。重算外层摘要后的错误 digest/size/mediaType/平台目标
  等负向用例先失败后通过；五份原始 archive 在新验证器下重新验证退出 0。
- 19 项纯守卫、1 项真实容器访问回归及 48 项现有容器契约均退出 0、无 skip。
  新输出父目录和 Skopeo 私有临时目录的编排失败、对应回归及新输出也均保留。
- `resolve-01/scan-02/scan-binding.json` 绑定十份原始平台布局的有效报告：
  全部退出 0，无 HIGH/CRITICAL 漏洞或秘密 findings；没有 ignore-unfixed 或
  severity 例外。Trivy 0.75.0 数据库本轮重新下载于 08:11:37 UTC，数据库
  UpdatedAt 为 07:10:08 UTC。这是该扫描器/数据库检查点，不是无漏洞证明。
- 同一 AMD64 SSO/healthcheck 可执行字节的独立 smoke、干净卷默认三服务
  Compose 均退出 0，覆盖 nonroot/read-only、readiness/discovery、no-store、
  重启后 JWKS、live token、精确 inactive 的持久撤销和状态文件身份。
- loopback-only registry 转移、双平台合并和本地提升退出 0，保留四个原始
  executable/attestation descriptors，并验证实际下载的 index 及 30 个
  子 manifest/blob 的原始 digest、长度和内容；没有重建或外部推送。
- 解决阶段账本登记的 35 个容器、6 个卷及 1 个 network 均带运行标签并已清理；
  最终 owned 实际缺席检查另存。初始阶段的 3 个容器、1 个卷清理记录不覆盖。

生产 Go、依赖、Dockerfile 和运行配置未修改；冻结输入指纹仍为
`fde465a3d7c28b59af0f0065ad3071f5c0e3ee6ef5eccf9547c110aaaceeaf2a`，
因此复用的是本轮当前源码 archive，不是上文历史镜像或旧扫描。仅报告文字和
私有编排发生变化。完整 root race/E2E/`make ci`、新 stock binary metadata 和
最终独立审查仍待 runner 后续执行；**当前完整 OCI acceptance 保持 false**，
不得把本地字节检查等同于最终批准、认证 builder、clean-tag 发布或 ARM/Apple
原生运行。可选 Compose profiles、浏览器业务、HA/数据库恢复及生产 SLA 未验收。

证据根目录：
`/home/u1/.abr/projects/snaplink-844a48d827366599/runs/snaplink-24h-20261015T070416Z/cycles/cycle-01/evidence/`。
本轮 `builds.json`/`archives/` 保留不变；新验证、扫描、运行、Compose、提升、
资源和命令日志均在 `resolve-01/`。未来根门禁结果由 runner 写入相邻
`gates/result.json` 及 leaf logs；这里没有预写这些门禁 PASS。

## SDK 覆盖决策与 Swift 声明对账：cycle-02（审查 P2 已修正，最终门禁 pending）

仅实现已批准的覆盖 sidecar、fail-closed 检查/只读报告与 Swift/Go 所有权声明
纠正；不扩展生成 allowlist、不修改生产 Go/Swift、API、依赖或默认值。
当前实数为 366 documented = 321 included + 45 excluded，13 个 included groups
与原 registry 一致。sidecar 的 11 个排除组有身份、理由和源码/访问/默认/授权边界；
OpenAPI security 保留 operation/root/unspecified 来源，不当作真实授权证据。
Swift 16 项逐项审计：两个内部注入 seam 不再宣称公开能力；五项已有实现保留为
验证债务而非缺少源码。声明为 100/112，onboarding 仍 false，parity 不变。
Go SDK 保持 `sdks/go` 独立模块/子目录 tag 所有权。

先复现的五项 coverage 缺陷及声明不实均以非零退出记录；实施中自检还补回原有
component-schema 守卫，并封闭坏引用/坏 schema 的异常诊断。实施阶段聚焦测试为
54 + 35 + 37 项通过、无 skip；`gensdk -race -count=1`、build、vet 和根架构/
维护性检查各退出 0，不能当成 race10 或完整 root gate。两次 canonical 生成
退出 0、字节确定，TS/Python sync/async 都仅含原 321 项，45 项排除未进入输出。
显式部署同步前，三个副本已逐字节一致；同步和随后只读检查均退出 0
（regen 2/2、deploy 3/3）。显式基线 diff 的增/删/迁移及 schema breaking/additive
均为 0。完整 race、E2E、`make ci` 和最终独立验收仍 pending，不继承 cycle-01 PASS。
首次编辑后 OCI freshness 为 **stale**，本轮不重建、不扫描、不声明新 OCI 闭环。
新证据仅在本运行 `cycles/cycle-02/evidence/`；最终根门禁由 operator-owned
stage 执行，正式发布和 Apple 原生验收仍未完成。

独立只读审查的一项 P2 已接受并修正：CIBA 声明现区分 confidential 的 secret/
已验证 JWT assertion 与已注册 public client 的 `none` 身份声明；后者不要求
secret/assertion，也不是匿名免策略访问，两条路径仍检查注册/active、tenant、
resource 和 scope。仅修正 sidecar/文档及相邻回归，未改生产认证行为或既有断言。
两项新增声明测试先退出 1、修正后退出 0；复验 56 + 35 + 37 项通过、无 skip。
既有 CIBA handler 的 25 个子用例及 gensdk 各以 `-race -count=1` 退出 0，
不是 race10、真实持久后端或完整根门禁。两次新 coverage 报告字节一致，仍为
366/321/45；surface/paradigm/versions 和只读 drift check 均退出 0
（regen 2/2、deploy 3/3），生成/部署字节未变。新证据位于
`cycles/cycle-02/evidence/resolve-01/`，不覆盖先前记录。
后续 operator-owned `cycle-02/gates/result.json` 及 leaf logs、最终独立验收均
pending；OCI 继续 stale，无重建/扫描/runtime 或新 current-source OCI 结论。

## SDK discovery netpolicy 声明修正：cycle-02-fix-01（编辑后门禁 pending）

上节 pending 是较早解决阶段快照；cycle-02 后续机械根门禁实际通过，但
`resumes/resume-01/acceptance.md` 的最终独立结论为 **FAIL**：discovery 声明
把有意开放的 `resolveMeNetPolicy` 错写为 authenticated netpolicy resolution。
该失败和全部旧日志保留，不把已通过的旧源码门禁继承为本次编辑后的通过。

本次只允许修正 sidecar 认证说明/真实 owner 引用和相邻 Python 回归：区分
当前请求 peer/host 自分类与由 AdminMiddleware 保护的任意输入 classify/管理
操作，不改生产认证、OpenAPI、allowlist、生成客户端、Go/Swift、配置或依赖。
两项新增回归在未改动的旧 sidecar 上先实际退出 1（18 个失败子断言），最小修正
后同两项退出 0、无 skip。回归核对 included/discovery、GET 精确路径、OpenAPI
unspecified/null 来源，对比五项 managed admin 操作的显式 bearer 声明，并要求
真实 handler、middleware、route、stock 接线及相邻测试引用；不只匹配新措辞。

实际源码表明 `resolve-me` 使用当前请求的 `r.RemoteAddr` 和 `r.Host`，自身及
AdminMiddleware 均不做 bearer 认证；任意输入 `/netpolicy/classify` 和 policies
路径由已安装的 AdminMiddleware 执行 bearer + GET `admin:read`/变更
`admin:write`。SDK/custom composition 仍需自行提供保护，stock admin-disabled
接线没有该 gate；不能仅从缺失 OpenAPI security 推导公开性。

聚焦 surface/coverage、paradigm/source、drift/route 分别 **58 + 35 + 37** 项
通过、无 skip。现有 netpolicy/admin owner、HTTP 集成和 gensdk 各以
`-race -count=1` 退出 0（顶层 134/20/26 项，嵌套 18/3/5 项，均无 skip），
只证明这些本地 memory/HTTP/生成器用例，不是 race10 或持久后端验收。
两次 coverage 报告字节一致，SHA256 为
`14d49504a33770e10d6797001eea5a1b23cc9bd6f612710e99a7ed5583861c3d`，
仍为 366/321/45；surface/paradigm/versions 均退出 0，声明仍为 100/112，
Swift onboarding/parity 不变。只读 drift check 退出 0（regen 2/2、deploy 3/3），
未重新 sync-deploy；显式 pre-fix baseline diff 各类变化均为 0、退出 0。
`docs/sdk-paradigm.md` 没有对应错误 netpolicy 文字，故本次不改。

所有新证据只在本运行 `cycles/cycle-02-fix-01/evidence/`，包括保留的实际红灯、
每条命令退出/输入摘要/叶日志和 `focused-summary.json`。新鲜 operator-owned
build/vet/root/full race/E2E/real-PG `make ci` 与独立复审仍 **pending**，
本阶段不是最终接受。OCI 继续 **stale/false**，没有重建、扫描或
runtime/promotion 验收，也没有发布。

## 当前源码 OCI 新鲜度恢复：cycle-03（pending，非最终接受）

本轮只重新构建并验证 cycle-02 最终对账后的当前工作树，不修改产品 Go、依赖、
API 或部署默认值。入场核对的 4950 项源码、symlink、HEAD 及逻辑/原始 Git index
与本轮快照和上一轮收尾一致；不恢复或暂存既有 dirty work。
新编排、archive、扫描、运行及清理证据仅在本运行
`cycles/cycle-03/evidence/`，旧检查点保持不变。本阶段的本地 artifact 检查点已完成；
**新根门禁及独立接受仍 pending，`accepted=false`**，不继承旧扫描或根门禁。

- 新编排先以纯测试复现继承的 `commands.json`/`command-leaves.json` 接口错误
  （退出 1），修正后通过。首次只读预检因本轮误设的 docker-container-only
  假设退出 1；没有创建资源。实际现有 Docker driver 使用 containerd image store，
  补充兼容能力回归、保留 classic/stopped builder 拒绝断言后，纠正预检退出 0；
  未 bootstrap、创建或修改共享 builder。两份失败及原编排版本均保留。
- 48 项既有容器契约、25 项纯守卫、1 项真实私有 scanner 访问回归均退出 0，
  无 skip。新增守卫检查本轮路径、helper 漂移、构建叶账本及现有 builder 能力；
  没有放宽扫描、资源权限、提取预算或 runtime 时序。
- 五条既有 `make docker-multiarch` 新导出均退出 0，使用 `--pull`、SPDX SBOM
  和最大 provenance。五份原始 archive 的十个平台、十二个静态 ELF 二进制、
  config/layer/diffID/module/VCS 及 attestation/subject 均验证通过；实际编译器
  全部为 Go 1.26.9。不是复制旧 archive，也不认证 builder 身份。
- 新 owned 缓存实际下载 Trivy 0.75.0 DB：UpdatedAt 为
  `2026-10-16T01:13:54.947090392Z`，DownloadedAt 为
  `2026-10-16T02:56:47.774990436Z`。十次原始平台布局扫描实际退出 0，
  `vuln,secret`、HIGH/CRITICAL、exit-code=1、ignore-unfixed=false，无所选 findings。
  `scan-binding.json` 绑定原始 archive/index/manifest/config、选择 index、report、
  scanner 身份、实际容器 wait 退出及 metadata/DB SHA256；不是用 daemon config
  normalization 或旧扫描补位，也不是无漏洞保证。
- 同批 AMD64 SSO/healthcheck 的独立 nonroot/read-only runtime 和干净卷默认
  三服务 Compose 均退出 0：复制并比较实际二进制，验证 readiness/discovery/JWKS、
  credential no-store、重启后 live token、精确 inactive 撤销、mint 及六项状态身份。
  未运行可选 profiles、其他四服务业务或浏览器流程。
- OWNED loopback-only registry 转移、双平台合并和本地提升退出 0；保留四个原始
  executable/attestation descriptors，按本轮图库存核对实际下载的 index 及
  30 个子对象；原始 index CLI digest 校验退出 0。无重建、外部推送或发布。
- 本轮 30 个容器、4 个卷及 1 个网络均依实际账本 ID 与双标签清理；实际缺席及
  子进程 reap 已记录。未清理共享资源、其他 cycle 的对象或 BuildKit 缓存。

冻结源码指纹为 `5fa242873ebedf7b182db1fb8540de825f4e0fa69537d33165244e2912853e89`，
helper 指纹为 `a5f8fc3836808591a64e4fdbcc50dc262a77755baac469057a4e9087ddccdd1a`；
构建/验证/扫描/runtime/promotion 前后和本地收尾核对一致。源码算法只排除本 tracker
的报告文字，另存前后摘要及 diff；ignored status 不进入 Docker context。生产源码、
依赖、默认配置、Dockerfile、canonical/derived contracts 和 Git index 未改变。
该指纹范围不同于 operator 全量指纹，不直接横比；只证明本轮冻结范围的本地检查。

实际记录见 `local-summary.json`、`builds.json`、`oci-verified.json`、
`scan-binding.json`、`runtime-result.json`、`compose-result.json`、
`promotion-result.json`、`owned-resources-final.json` 与不可覆盖的 `invocations/`
及 `command-leaves/`。新 stock race binary/module inventory、真实 PG/full race/E2E/
`make ci` 由后续 operator-owned stage 执行；本报告不预写通过。
独立初审 P2-01 已接受、复现并最小修正：原新工作截止守卫同时阻断 owned 清理，
最早会在冻结前两分钟拒绝默认 inspect。本轮原清理发生在冻结前，不据此声称已有
泄漏。仅私有 `checkpoint.py` 将 owned removal 的准入与新工作分离：新工作仍按
05:17:45 UTC 冻结；清理只使用原 `control.json` 的 07:17:45.071586 UTC 绝对截止，
另预留既有命令子进程两次十秒 reap 等待。没有放宽原 command/stop timeout、身份
授权或 reap-before-volume-delete；原 helper、旧测试与失败日志均保留。

新增 5 项纯回归先退出 1、修正后退出 0；全部 30 项纯守卫及 48 项容器契约均
退出 0、无 skip，覆盖冻结前后准入、实际账本 ID＋双标签、失败 stop／无法 reap
保留卷及绝对截止。另 2 项真实 Docker 回归分别模拟冻结前／后一分钟，保持真实
Docker subprocess：新工作在 spawn 前被拒，owned 容器停止、PID 归零后才删卷；
新增的 2 个容器与 2 个卷均已确认实际缺席。fixture 使用原 20 秒停止宽限后退出
137，是有界强制停止/reap，不声明优雅应用退出，也没有修改宿主时钟。

新证据仅在 `cycles/cycle-03/evidence/resolve-01/`，包括命令退出/叶日志、前后 helper
与 `checkpoint.diff`。上文 helper 摘要对应原 artifact 执行；修正后摘要单独为
`6ebe36b12f88732ec72c3d73a57e940e04c17a631adb1512ce8218162d3bcf50`。
冻结生产/build 输入指纹未变；没有 Go、并发或持久后端行为改动，故本次未重复
OCI 构建/扫描/runtime，也不新增 OCI 接受声明。`accepted=false`，新 stock binary、
build/vet/root/full race/E2E/真实 PG `make ci` 和最终独立复审仍待 runner 后续执行。
附加收尾报告首次退出 1：substring 检查把通过用例名中的 `skipped` 误当作实际 skip，
当时尚未执行资源核对命令；失败脚本/日志及已知局部输出保留。修正为匹配真实
verbose／summary skip 标记，3 项回归退出 0，仍拒绝实际 skip；新收尾输出仅写
`resolve-01/audit-02/`，不覆盖失败结果，也不替代任何根门禁。
原生 ARM/Apple、外部发布、认证 provenance、UI、HA/数据库恢复及生产 SLA 仍不在结论内。

## 客户端凭据实例内固定分片协调：cycle-04（聚焦验证通过，最终接受待定）

仅实现已批准的 SDK opt-in 内建 CC 协调切片：实例内单锁改为固定
`[256]sync.Mutex`，原完整缓存键的 SHA-256 首字节选锁；不改变缓存键、授权、
TTL、quota、默认配置或分布式语义。生产修改限两个原 owner 文件，无新生产文件。
同键保护仍覆盖缓存提交，碰撞只等待，不共享响应；不是任意不同键无碰撞并行。

首次夹具误将空 assertion 参数序列化为显式存在，测试退出1但未进入签发，
该记录保留且不算复现。修正夹具、尚未修改产品时，因果红灯实际退出1：
A 的完整键映射153、B映射225，A进入受控真实签发后不释放，B被全键锁阻塞。
最小修复后的同一测试退出0，B在A仍被阻塞时完成并通过真实JWT身份验证。
新增白盒、20并发仅签发一次、受控碰撞、Get/Issue/Set panic/error释放、quota剩余
一份容量、认证/tenant/resource/client/scope/撤销、DPoP证明/nonce与bypass回归均有
单次通过记录；Set panic已写出响应的原行为未更改。每次Go编辑后共10组即时
build/vet/root快速门禁均退出0。有限TTL/错误与空body的middleware及真实memory
cache各以`-race -count=10`退出0、无skip，不代表Redis或新持久后端接受。

**初次实施停止原因**：必需SSO聚焦`-race -count=10`触发本轮600秒编排timeout，包装器
退出124，Go进程SIGTERM退出-15且已reap；7轮完整、部分第8轮，共181个顶层及
118个子测试PASS实例，日志未见FAIL/SKIP/race warning，仍不能称race10通过。
按规格停止产品编辑及后续验证，没有重试或放宽watchdog/断言/次数。
当时相邻完整包race、额外mTLS/private_key_jwt回归及独立审查尚未完成；后续有界
解决结果见下文。新stock inventory、full race、E2E、`make ci`和最终复审仍待runner，
**accepted=false**；本记录不是最终接受。
无新Docker资源或数据库schema；测试子进程已回收，最终进程/所有权审计另存。

首次本轮仓库输入编辑后 OCI freshness 为 **stale/false**；cycle-03 最终接受
只保留为其冻结输入的历史检查点。本轮没有重建、扫描、runtime或新OCI接受。
证据仅在本运行`cycles/cycle-04/evidence/`：每条命令有input/result/stdout/stderr，
包括原始失败、`different-stripes-red-02/`、`different-stripes-green/`、
`sso-focused-race10/`与`measured-tests.json`。旧证据、index及其他owner工作保留。
初次停止后由本次用户请求重新准入；原失败记录、600秒命令上限及编辑截止不变。

### cycle-04 有界解决：测试清理 P2-01

接受独立审查发现：客户端context取消只回收客户端goroutine，不能解除服务端
`Mutex.Lock`；随后`httptest.Server.Close()`可能无限等待。只修改测试生命周期：
九个新增HTTP场景在当前test executable的owned辅助进程执行，原请求/等待的一秒
断言不变。客户端取消/回收后，通过独立pipe标记同步`Server.Close`的开始/结束；
一秒清理watchdog发现卡住时，父进程kill并明确`Wait`回收子进程，事件reader也join。
没有后台遗留Close、生产锁超时或授权/失败策略修改；额外一分钟执行包络只负责
辅助进程监督，不替代原断言。负向夹具真实将handler阻塞于不可取消Mutex，验证
原一秒请求断言失败、Close清理卡住、子进程被kill/reap，`-race -count=10`完成。

新的`evidence/resolve-01-*`记录以下实际结果，均退出0：

- 四组Go编辑后的即时build/vet/root门禁。
- 新HTTP/分片/负向夹具12项各race10，120个父测试PASS；子进程输出另计，不重复
  当作顶层接受。十次负向夹具均记录实际`signal: killed`及`reaped=true`。
- 原聚焦集合其余13项各race10，130个顶层PASS；两条命令各保留600秒上限，按当前
  实际25个测试名做不相交且完整的集合核对，不减少次数或删除用例。旧超时仍不算PASS。
- capture/真实Memory cache四项各race10，40个顶层PASS；mTLS/private_key_jwt相邻
  九项各race10，90个顶层PASS；均无skip/race warning。
- SSO、middleware及CC handler三个完整相邻包race单次：694个顶层PASS，无skip。

测量明细：`resolve-01-measured-tests.json`；集合核对：
`resolve-01-selection-coverage.json`；每次调用各有input/result/stdout/stderr。
本解决阶段不再修改生产字节、不涉及新持久backend、Docker fixture或数据库schema；
SDK/Memory实测不外推为新Redis/PG接受。当前OCI仍stale/false，未重建/重扫。
后续operator-owned `cycle-04/gates/result.json`及叶日志才是新stock inventory、
full race、E2E和真实PG `make ci`的结果；本阶段不提前声明通过，也不代替最终独立复审。

## 2026-10-17 新运行 cycle-02：stock PG TCP 中断测试（阻塞）

本轮只新增测试及 schema DROP 的额外合取 guard，不修改生产实现、公开契约、
依赖或 profile。准入确认 HEAD、4954 项源码和 index 与新运行基线一致；新的 owned
PG16、当前新建 race stock binary 上既有 CrossReplicaGrants 控制测试实际退出 0。

新增场景在注入故障之前稳定 red：健康 `/readyz` 为 200，但缺少规格要求的
`postgres` check；实际仅含 identity/tenant 及 PostgreSQL OAuth checks。
`build_stores.go` 先调用 `wirePostgres` 注册 option，后由
`build_app_core.go` 的 `wireSigningIssuer` 重建 `b.opts`，丢失先前注册项。
首次失败和补充净化诊断后的确认失败均退出 1，保留全部记录。未执行 PG cut、
故障期间凭据状态比较或恢复流程，不据此推断中断期间 readiness 仍为 200。
该阻塞需要另行批准生产 owner 修复；本轮按测试切片停止，未放宽断言。

五次 Go 编辑后的 build/vet/root 组合均退出 0；五项新 helper 各 race10 和两项
原 lifecycle guard 各 race10 实际通过，无目标 skip/race/fail。这不是六项目标
集合的完整 race10，更不是 stock outage 接受。最终 full-race/E2E/真实 PG
`make ci`、operator 新 stock inventory 和独立接受未完成，不能继承旧 PASS。
新 fixture 按实际 ID/三项 label 清理；child Wait/proxy join、零残留私有 schema、
PG stop/PID0/remove/实际缺席记录在新运行 `cycles/cycle-02/evidence/`。

首次测试/COPY 输入改动已使当前 OCI **stale/false**。上一轮对固定源码
`77b491…` 的 OCI finalizer 接受仍是历史结论；本轮未重建、重扫或发布。
运行方法及严格边界见 [reference-apps](../sso/reference-apps.md)。

### Cycle-02 同范围审查修复：最终门禁仍 pending

两项 scoped P2 均接受并作最小修复，原 helper、red 和历史结果不覆盖：

- P2-01：新私有清理 helper 在 stop 前合取 exact ID/三标签、命令树 Wait/reap、
  命令/日志绑定的 proxy join 和实际 PG 无残留 schema/其他连接证明。schema 保留、
  join 不明或核验失败时连 stop 都不执行。旧 helper 的三个因果 red 保留；修复后
  12 项私有回归通过。新 owned PG 上实际残留 schema 和故意失败的只读查询均保留
  同一运行中 backend；仅显式移除本回归自己创建的 schema，重新核验后才完成
  stop/PID0/remove/实际缺席。没有删除未知的测试失败状态，也未改 operator helper。
- P2-02：仅改 proxy 测试。pipe 读设原五秒界限，受控 release 幂等且无条件执行；
  writer/Cut/Close 均有界 join。新增独立子进程回归覆盖 dial/copy 提前断言失败及
  forwarding 不启动；修复前不能完成 join/触发 timeout，修复后要求实际 exit1、
  Wait、started=finished、active=0，panic/timeout/race 不当作预期成功。

两次 Go 编辑后的即时 build/vet/root 均退出 0；六项 helper 各 race10（60 个顶层
PASS，含新失败路径回归）、两项原 lifecycle guard 各 race10（20 PASS），无目标
skip/race/fail。新 race stock build/metadata/inventory 和新 PG 上控制测试退出 0；
outage E2E 再次退出 1，仍在同一健康 readiness 断言、PG cut 前阻塞。四个新 stock
child 已 Wait/reap 并确认缺席，proxy join 及安全清理叶记录完整。

新证据仅在本轮 `evidence/resolve-01/`，聚焦通过不代替最终独立接受。生产 Go、
公开契约、配置、schema、依赖、profile、既有 fail-open/closed 策略和断言未改变。
readiness option 覆盖仍需另行批准；实际 outage/凭据保留/恢复及原六项目标完整
race10 未完成。runner 后续的新 build/vet/root/stock metadata/full race/E2E/真实
PG `make ci` 及最终审查均 **pending**；不会继承旧 PASS。当前 OCI 仍 **stale/false**，
无重建、重扫、发布或生产/HA 接受。

### 生产 readiness option 保全前置修复：聚焦通过，最终门禁 pending

用户继续授权后另立有界规格，生产改动仅为 `build_app_core.go` 的初始化表达式：
先保留已有 `b.opts`，再按原顺序追加 configured/base options，避免丢失早期 Redis/PG
readiness 注册。文件仍500行，不增加豁免、默认配置、公开 API/SPI、schema、依赖或
profile。相邻组成回归在旧实现退出1；一行修复后健康/失败/恢复及 livez 断言通过，
连同既有 signing/readiness 目标 race10 通过。此前所有红灯和测试切片归属保留。

新构建的 stock race binary、新 owned PG16 上原 CrossReplicaGrants 控制通过；
原 outage E2E 又以 `-race -count=1` **独立执行10次且每次退出0**，不描述成一个
`-count=10` 进程。实际 TCP cut/restore、双进程不重启、503 readiness/200 liveness、
故障期拒签/不消费、恢复后的单次使用/family reuse/租户隔离均由原断言验证；没有放宽
时限或改变 token fail-open/closed 策略。原 guarded cleanup 完成命令 Wait、proxy join、
实际空 schema/无其他连接核验以及 exact-ID/三标签 stop/PID0/remove/实际缺席。

新证据位于当前运行的 `production-readiness-fix-01/`。当前条目仅为聚焦检查点：
新 full-race/E2E/真实 PG `make ci` 及最终独立接受仍 pending，不继承先前源摘要 PASS。
生产字节已变，当前 OCI 继续 **stale/false**；不以旧 archive/scan/runtime 补位，
没有新镜像验收、数据库 crash/failover、HA、原生平台、生产容量或发布接受。
