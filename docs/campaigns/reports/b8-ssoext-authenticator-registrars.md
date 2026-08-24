任务完成。提交 `5aed41d3` 已推送到 origin/main。

## 核验结果（按契约逐项）

**1. 实现审读（未重写任何代码）**
- **注册器语义与 SAML 逐字对齐**：LDAP/Kerberos/RADIUS 三族均用 `platform/registrar` 的 `registrar.New[T]()`（进程本地）；`Register*` 对空名/nil/重名 panic（有测试覆盖）；`Lookup*` 未注册时返回 `ok=false`；`Registered*` 返回排序名。每个 `*ServerDeps` 仅含 stdlib + 根模块类型（`spi.Logger`/`sso`/`oidc`/`audit`），无 go-ldap/gokrb5/layeh 泄漏进根模块 go.mod；包级注释保留"非热插件注册表"纪律（saml_registry.go 包文档已扩展说明三类注册表的消费方差异）。
- **模块侧适配正确**：`ldapauth.Deps`/`radiusauth.Deps`（新增 build.go）与 `kerberosauth.Deps`（重构 kerberos.go）都**嵌入**对应 `ssoext.*ServerDeps`（单字段构造，无逐字段拷贝），与 `saml.Deps` 嵌入 `ssoext.SAMLServerDeps` 的模式完全一致。`kerberos_test.go` 相应迁移到嵌入字段。
- **文档一致**：三个 doc.go 的 copy-pasteable 示例引用真实符号（`NewGokrb5Validator`、`Build`）；CHANGELOG / DIRECTORY_MAP / profile-isolation / deferred-backlog 均表述"LDAP/Kerberos/RADIUS 已迁移、KMS 族为剩余工作"。
- **fail-closed 查表**：grep 确认 stock `cmd/` 无 LDAP/Kerberos/RADIUS 查表（`mountSAMLHandler` 是唯一 stock 消费者），与"operator 自有 boot composition 消费"的文档声明一致。

**2. 测试实跑（全部通过）**
- `go build ./... && go vet ./...`（根模块）✅
- `go test ./interfaces/ssoext/... -count=1` ✅
- 三嵌套模块各自 `go test ./... -count=1` + build + vet ✅
- `go test -count=1 -run 'TestMaintainability_|TestArchitecture_|TestDirectory' .` ✅
- 触及包 race 测试（ssoext + 三模块）✅
- `go mod tidy -diff` 三模块零输出 —— 嵌套模块早已 `require` 根模块，未新增模块引用，**无需 tidy，go.mod/go.sum 零变更**。

**3. 修复的缺口**：**无**。审读未发现需要修复的不一致，未推倒/重写任何实现，故报告无修复根因条目。

**4. 硬边界**：未加豁免、未改分层、未新增第三方依赖。

## 提交说明
- Commit：`5aed41d3 feat(ssoext): add LDAP/Kerberos/RADIUS authenticator-family registrars`（imperative + `Co-authored-by: pi <pi@earendil-works.local>`，21 文件，+936/−90）
- 无关的 batch-runner 产物（`.pi-batch.lock`、`docs/architect-analysis/auto/state.jsonl`、`docs/campaigns/*`）按 AGENTS.md 保留在工作树未动，未纳入提交。
