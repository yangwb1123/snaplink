收尾完成。提交 `9c1e53fa` 已落地并推送；工作区仅剩 batch-runner 的无关注入（`.pi-batch.lock`、`docs/campaigns/*`、`docs/architect-analysis/*`），按"保留无关 worktree 变更"要求未动。

## 核验结论（未重写，通读保留实现）

**实现与设计契约一致**：固定 7 字段（method/path/status/duration_ms/client_ip/request_id/trace_id）；`path` 仅 `r.URL.Path`（测试断言 RawQuery 凭据不出现在任何字段）；status 默认 200；`BodyLogPolicy` 零值永不捕获 body；捕获栈用 LimitReader+MultiReader 全量恢复（下游读 body 两次字节一致）；redaction 精确词表 + 子串启发式 + `[redacted]` 字面量；探针豁免靠 `buildProbeMux` 在链外（零代码）；`WithRequestLogging` 改为 policy 签名（deprecated 别名，`AllowAllPaths:true` 复现 logBodies=true），DEBUG `RequestLogger` 及其字段已删除；`peertrust.ClientIP` 单实现、`audit.ClientIP` 委托（字节一致）。

## 修复的缺口（根因：上一轮把函数/文件推过预算）

| 缺口 | 根因 | 修复 |
|---|---|---|
| 5 个文件 gofmt 不净 | 上一轮手写缩进 | `gofmt -w` |
| `config_load.go` `validate()` 52 行 / `ServerOptions()` 51 行超函数 50 行预算 | access_log 校验+wiring 各 +3 行 | 提取 `validateLogging()`、`securityMiddlewareOptions()`、`backupOptions()`（沿用既有 helper 模式） |
| `config_load.go` 524 / `aliases.go` 504 / `options_httpstack.go` 504 超文件 500 行预算 | access_log 代码落入三个近满文件 | access-log 选项+`BodyLogPolicy` 别名迁入 `sso_wiring.go`（紧邻 `accessLogPolicy` 字段）；config helper 迁入 `config_server.go`（紧邻 `accessLogOptions`）。`interfaces/sso` 保持 60 文件上限、`interfaces/middleware` 保持 10 文件 |

`logging.access_log.*` 的 `ignored_requires_restart` 由 reload 包默认拒绝（allowlist 制）自动满足，无需改码。request_log.go 341 行 < 500，零豁免。

## 验证（全部实际运行）

- `go build ./... && go vet ./...` ✅
- `go test ./interfaces/middleware/... -count=1` ✅
- `go test ./interfaces/sso/... -count=1 -run 'Log|Request'` ✅
- `go test ./config/... -count=1` ✅
- `go test ./test/ -run 'AccessLog|Log' -count=1` ✅
- `go test -count=1 -run 'TestMaintainability_|TestArchitecture_|TestDirectory' .` ✅
- `python3 cli.py check` ✅（另跑 check-invariants 9 passed / check-root PASS）
- `gofmt -l` 相关文件 ✅ 全净
- `go test ./... -race` ✅（一次满负载运行曾报 `infrastructure/defaultimpl` 与 `infrastructure/redis` 的既有时序 flake——键轮换/令牌桶测试，隔离跑 ×3 与复跑均 PASS，且本改动不触碰这两个包，已在提交体注明）
- `make ci` ✅ exit 0（含嵌套模块、examples、config、route/OpenAPI 契约、适配器）

## 文档同步（同提交）

- `docs/config-reference.md`：新增 `## Logging` 节（`logging.access_log.*` 全键 + 契约/探针豁免/不可热加载），热重载表加 `ignored_requires_restart` 行
- `CHANGELOG.md`：`[Unreleased] Added` 首条
- `docs/observability.md`：新增 `## Access log` 节（字段表、链槽位、body 策略、deprecation 说明）
- 设计文档状态标注经核验与实现范围一致（Decision 1/2/3/9 已实现，7/8 OTel 关联明确未实现）

提交：`feat(middleware): add always-on structured access log`（imperative + `Co-authored-by: pi <pi@earendil.dev>`），21 文件 +1562/−189，已推送 origin/main。
