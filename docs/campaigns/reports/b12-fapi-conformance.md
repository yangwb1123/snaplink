The only compose-graph difference is the config mount source — topology discipline intact. All race tests pass.

## 完成总结

**前置确认（步骤 1）**：HEAD `07832dda` 已含 per-client id_token alg（B12-1 合并，`IDTokenSignedResponseAlg` 57 处引用；B12-R2-A 报告在场）→ 执行主路径。

**产品使能（本次发现并实现）**：DCR 校验只接受已接线 alg 集，FAPI 配置的 ES256 主密钥无法签发 RS256 登录客户端——SDK 的 `WithIDTokenIssuerAlg` 没有 sso-server 二进制的 config 通道。新增 **`keys.id_token_algs[]`**（config 形态的 per-client 密钥）：boot 门禁（禁止与主 alg 重复/条目重复）、`WithTokenIssuer` 注册（聚合 JWKS + hint 校验）、discovery 并集广告。空配置逐字节不变。

**运行（`./run-headless.sh --fapi --timeout 1200`）**：
| 阶段 | 结果 |
|---|---|
| config validate / harness up | PASS（重建镜像含新接线） |
| DCR 注册登录客户端（`id_token_signed_response_alg: RS256`，仅 FAPI 分支） | PASS |
| 套件登录（历史阻塞点） | **PASS**（attempt 2）——硬编码 RS256 的 Spring 解码器现在能解 RS256 登录 ID token |
| plan 创建 | PASS（56 模块，vs basic 38）——修掉 variant 重复 `fapi_request_method/fapi_response_mode` 的 400 问题 |
| `fapi2-security-profile-final-happy-flow` | **12 SUCCESS + 1 FAILURE，INTERRUPTED** |

**模块失败项（如实）**：`GetStaticClientConfiguration: As static client was selected...`。反编译套件 jar 证明：FAPI2 SP FINAL 服务端测试硬编码静态客户端（plan 无 `client_registration` variant），且其回调 redirect 为每次测试实例动态生成（`https://localhost:8443/test/{testId}/callback`），snaplink 的 `IsRedirectURIValid` 是精确匹配——无法预注册。下一步（可选通配符 redirect 注册，安全敏感，需独立设计）已写入归档 BLOCKER.md。**未虚构任何通过。**

**归档** `results/07832dda-fapi/`（gitignored 本地留存）：plan/log/info/config/commit/worktree/BLOCKER.md。

**提交**（均含 AI co-author trailer，已推送）：
- `4b3c364e` `feat(sso): wire additional per-client id_token signing keys via keys.id_token_algs`
- `b90362e9` `test(conformance): run FAPI 2.0 SP through the module's static-client gate`

**验证命令**（实际运行）：FAPI 运行命令 ✓；`go build ./... && go vet ./...` ✓（exit 0）；`go test -run 'TestMaintainability_|TestArchitecture_' .` ✓；相关包 `-race` ✓；compose 默认 vs FAPI 拓扑仅 config 挂载不同 ✓；`git status --porcelain` 见上（仅剩 B12-3 OTel 工作树——原样保留、未提交，混合文件经 `git apply --cached` 精确分块）。
