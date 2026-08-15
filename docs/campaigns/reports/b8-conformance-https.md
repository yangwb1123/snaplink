任务完成。`9f4b182f` 已提交并推送。

## 交付摘要

**1. HTTPS issuer 拓扑**（`test/oidc-conformance/`）
- 新增 `issuer-proxy` 服务（nginx，host 8181→443，复用 `certs/` 自签证书与 nginx 模式，带 `X-Forwarded-Proto https`），置于 `issuer-https` compose profile 下——默认 HTTP 拓扑启动的服务集与之前逐字节一致。
- `ISSUER_URL`/`ISSUER_TLS_JVM_ARGS` 通过 compose 插值参数化：未设置时回落到原 HTTP 默认值（已用 `compose config` 验证字节相同）。
- pinned tag（`release-v5.2.1`）、healthcheck、模块 allowlist、config.yaml 均未改动。
- `run-headless.sh` 新增参数解析与 `--issuer-https`：自签证书再生（补 `sso-issuer` SAN，suite JVM 做 hostname 校验）、从 pinned 镜像默认 cacerts + 本地证书构建 JVM truststore（实证：裸 truststore 会让 suite 在启动时解析硬编码的 `accounts.google.com` 而崩溃）、8181 https 健康等待、归档 `results/<commit>-https/`。
- `drive_test.py` 支持 https issuer 的登录 POST（unverified SSL + Host 头）。

**2. 运行结果（如实统计）**
- HTTPS 拓扑（HEAD `7400ba0c`，`--timeout 900 --issuer-https`）：**60 SUCCESS + 0 FAILURE**，`VerifyClientManagementCredentials` 由 FAIL 翻转为 PASS（`registration_client_uri` 现为 `https://sso-issuer:8181/register/...`）；3 个 WARNING 与基线相同（id_token 非请求声明，非拓扑相关）。
- 同提交 HTTP 路径复跑（要求的验证命令 `./run-headless.sh --timeout 900`）：**59 SUCCESS + 1 FAILURE**，与 `af3bc485` 基线计数/步骤序列完全一致，证明 HTTP 路径未变。

**3. 归档**：`results/7400ba0c-https/`（plan/log/info/config/commit/worktree，gitignore 本地留存）与 `results/7400ba0c/` 并存，同提交 HTTP↔HTTPS 对比。

**4. 文档真值化（同一提交）**：README 头部重写（headless 可运行、CI 外、有 gitignore 归档、保留 "Implemented ≠ certified" 边界）；`deferred-backlog.md` 认证段更新（pinned image、headless harness、归档结果、剩余边界 = 外部可达 HTTPS 官方运行 + OIDF listing）；`oidc-conformance.md` 增补 HTTPS 拓扑运行记录并修正两处 "browser-interactive"/"HTTP-only" 过时表述。

**5. 硬边界**：未改生产代码、未动模块 allowlist、harness 保持 CI 外。

**6. 验证命令输出**：`run-headless.sh --timeout 900`（上述）、`go build ./... && go vet ./...` → OK、`git status --porcelain` 仅剩批处理运行器既有的 `state.jsonl`/`campaign`/`tasks-b8` 等未跟踪文件（按纪律保留未动）。

**7. Commit**：`feat(conformance): add HTTPS issuer topology to the headless OIDF harness`（imperative + `Co-authored-by: pi <pi@earendil-works.local>`）。
