完成。所有交付物已落地并如实记录。

## 执行摘要

**核验（未重写，仅核验保留的修改）**
- `config-fapi.yaml` 与 `config.yaml` 的差异仅三处已文档化 delta：`keys.signing.alg: es256`、`oauth.par.enabled: true` + `compliance: fapi_2/inspection_only`、头部注释。其余字节一致。
- 默认拓扑字节不变证明：`docker compose --env-file config.env config`（default vs `CONFORMANCE_CONFIG=config-fapi.yaml`）解析后，唯一差异是 sso-server 的 config mount source（`config.yaml` vs `config-fapi.yaml`）；其余所有服务字段逐一相同。默认解析即提交版 `./config.yaml` 挂载。
- 默认参数等价性：`PLAN_NAME`/`PLAN_VARIANT`/`MODULE` 默认值复现 basic 计划；variant URL 编码与旧硬编码值逐字符一致（已用 python 验证）。计划/模块名 `fapi2-security-profile-final-test-plan`、`fapi2-security-profile-final-happy-flow` 经套件 jar 反编译确认存在。

**运行（如实报告）**
`./run-headless.sh --fapi --timeout 600`：config 校验 PASS → harness 启动 PASS → DCR 注册 PASS → admin 注册 PASS → suite 重启 PASS → **suite 登录 8/8 次失败**（`invalid_id_token: Signed JWT rejected: Another algorithm expected`）→ 未到 plan 创建，模块未运行。**无虚构通过。**

**阻塞点（根因已证明，非臆测）**
- 套件镜像 `release-v5.2.1` 自带管理登录的 ID-token 解码器为 Spring Security 默认 `OidcIdTokenDecoderFactory`，其 `jwsAlgorithmResolver` 硬编码 **RS256**（反编译 `spring-security-oauth2-client-6.5.11` 证实；套件未覆写；Spring Boot 3.5.15 无 `jws-algorithm` 属性）。
- FAPI 2.0 SP 要求 ID-token 算法 ∈ {PS256, ES256, EdDSA/Ed25519}（套件自身检查 `FAPI2CheckDiscEndpointIdTokenSigningAlgValuesSupported.FAPI2_ALLOWED_ALGS`）。
- 控制实验：用套件自身 jar 在套件容器内对实时 ES256 token 做 `JwtDecoders.fromIssuerLocation` → `DECODE OK`，证明 token 本身有效，拒绝纯粹来自解码器硬编码。
- snaplink 无 `id_token_signed_response_alg`（每客户端签名算法）支持，无法只给登录客户端签发 RS256。修复建议（helper RS256 登录 issuer 或产品级 per-client alg）已写入 `BLOCKER.md`。

**归档** `test/oidc-conformance/results/39ecdf7a-fapi/`（gitignored 本地留存）：config.yaml、discovery.json、jwks.json、suite-login-failure.log、commit.txt、worktree.txt、BLOCKER.md（含根因 + basic 38 模块 vs FAPI 17 模块对比）。plan/log/info 因阻塞于 plan 创建之前而缺失——已在文档中如实说明。

**文档同步（同提交）**：README.md allowlist `fapi` 行→实测"blocked"+原因；`docs/sso/oidc-conformance.md` 证据表新增 FAPI 行 + 矩阵更新；CHANGELOG.md 记录 harness 变更。

**验证命令**：compose `config --quiet` OK；`go build ./... && go vet ./...` OK；`TestMaintainability_/TestArchitecture_` **pre-existing 失败**（`config/config_load.go` 501 行、`interfaces/sso/aliases.go` 504、`options_httpstack.go` 504——均来自无关的 access-logger 未提交工作，非本次改动，另行报告）；`git status --porcelain` 见上。

**提交**：`b3074cd1 test(conformance): land FAPI 2.0 harness variant and archive the blocked first run`（imperative + `Co-authored-by: pi` trailer；仅 7 个 FAPI 范围文件）。推送被 pre-push 钩子（`cli.py harness` 维护性门禁）拦截，原因是无关任务的未提交 Go 改动——按 AGENTS.md 未绕过钩子、未动他人工作；提交已在本地 `main`。

**环境还原**：`docker-compose.yml` 已从 `.bak` 恢复（去除运行时 sed 注入的凭据）；我添加的 `/etc/hosts` 条目已删除。
