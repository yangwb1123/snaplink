All committed content verified: B12-1-only in the 5 files B12-3 also touched (`requestIDMW`/`WithTracingMiddleware` retained, no OTel CHANGELOG/openapi content). Worktree holds only B12-3 changes, uncommitted and preserved.

## 任务收尾报告 — B12-1 per-client id_token 签名算法

### 提交
`07832dda` `feat(sso): per-client id_token signing algorithm (id_token_signed_response_alg)` — **31 文件 +1031/−94**，已推送 `origin/main`。AI co-author trailer: `Co-authored-by: pi <pi@earendil.dev>`。

### 核验（未重写，逐文件 diff 确认）
B12-1 全链路完整且相互一致：
- **数据模型**：`core.Client.IDTokenSignedResponseAlg`（JWS 声明字段，紧邻 JWE 元数据）；DCR `DCRRequest/DCRResponse`、`oauthvalidate.DCRMetadata` 同步。
- **DCR**（RFC 7591/7592）：`ValidateDCRMetadata` 第 5 参携带存活签名集；register/GET/PUT 持久化+回显；未知 alg → 400 `invalid_client_metadata`；`none` 全路径拒绝（option 构造期 panic、config boot 失败、DCR 400）。
- **静态配置**：`clients[].id_token_signed_response_alg` 经 `canonicalSigningAlg(keys.signing.alg)` boot 校验，不匹配即失败。
- **签发选择**：`wiringState.idTokenIssuerAlgs` + `WithIDTokenIssuerAlg`（whitelist = AGENTS.md §3 `AsymmetricJWSAlgs`）；`idTokenIssuerForClient` 每客户端 alg 优先、未接线 fail-closed（省略 id_token，绝不用其他密钥）；authcode/device/CIBA/token-exchange/login/native-SSO/silent-renewal/userinfo 全部汇入该单点。
- **Discovery**：`IDTokenSigningAlgValues` 并集访问器（空 map 逐字节等于 `SigningAlgValues`）；`id_token_signing_alg_values_supported` 与 DCR 校验集同源；userinfo 广告门放宽到任一接线签发器。
- **持久化**：sqlite migration v7、postgres schema v5；openapi.yaml（2 schema）、config-reference.md、CHANGELOG、设计裁决 `docs/design/per-client-id-token-alg.md`（六项裁决齐备）同改。

### 发现并修复的缺口
`make ci`（race 步）捕获：`test/storage_health_test.go` 硬编码 sqlite clients schema 版本 **6**，而 B12-1 migration v7 将其推至 7 —— 迁移落地未同步版本断言。根因修复（改 7 + 注释补 v7 说明），并入本提交。

### 门禁（全部实际运行）
| 命令 | 结果 |
|---|---|
| `go build ./... && go vet ./...` | PASS（worktree 与**提交树独立**均验证） |
| `go test ./interfaces/sso/... ./protocols/oauth/... ./protocols/oidc/... -count=1` | PASS |
| `go test ./config/... ./infrastructure/defaultimpl/... -count=1` | PASS |
| `go test ./test/ -run 'OIDC\|Register\|IDToken' -count=1` | PASS（含 FAPI 解锁 E2E） |
| `go test -count=1 -run 'TestMaintainability_\|TestArchitecture_\|TestDirectory' .` | PASS |
| `python3 cli.py check-routes` / `sdk-surface check` | PASS |
| `gofmt -l` 本方向文件 | 空（全格式化） |
| `make ci` 全链（fmt vet race build examples proto-lint ci-modules config-validate-all modules-check modules-smoke route-contract proto-openapi-parity capabilities-check sdk-surface-check profiles-evidence adapters-check） | PASS（初始 race 失败即上述缺口，修复后全绿） |

**提交树独立验证**：以 HEAD+仅 B12-1 hunks 重建的暂存树（`git apply` 到临时 worktree）build/vet/相关测试全 PASS —— 提交不含任何 B12-3 依赖，`requestIDMW`/`WithTracingMiddleware` 等 B12-3 移除点均保留在提交内。

### 边界遵守
- **零豁免**；新文件均 ≤500 行/函数 ≤50 行/cyclo ≤15（门禁验证通过）。
- `interfaces/sso` 60 文件上限未破（本方向新增 1 个 `_test.go`，不计入）。
- **B12-3 文件原样保留**：5 个双方向混合文件（sso_wiring/server_helpers/build_app_core/CHANGELOG/openapi）提交只含 B12-1 hunks，B12-3 hunks 留在工作树未提交；其余 B12-3 文件（middleware/tracing/audit/sso-minimal/main_wiring/observability 等）零触碰、零暂存。
- 工作树当前：0 staged，仅剩 B12-3 改动 + harness 未跟踪文件。
