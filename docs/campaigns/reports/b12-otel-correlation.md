提交完成并已推送（post-commit hook 同步到 origin/main，`b90362e9..b487103e`）。

## 总结

**核验（只读，未重写）** — 保留实现与设计契约逐条对上，未发现缺口：

- **Decision 7 装配**：`middleware.Correlation` 并入既有 `interfaces/middleware/middleware.go`（10 文件上限守约，无新文件；D7-1 drift 与 addendum 一致）；`buildMiddlewareChain` 在同一最外层槽位替换原 otelhttp wrap，`Use(TracingMiddleware())` 删除，`buildProbeMux` 探针豁免与中间件顺序不变。`Traceparent` 由 wrapper 从活 span 显式设置（D7-2：otelhttp v0.68.0 不注入响应头），`formatTraceparent` 携带真实 sampled 位。
- **request-id 路径迁移**：`WithTracingMiddleware`/`WithRequestIDMiddleware`/`requestIDMW` 从 options_security.go、aliases.go、sso_wiring.go、build_app_core.go、sso-minimal（经 `composition.Edition.ExtraOptions`，D7-3）、examples/basic 全部删除；`WithTracing(operation)` 为单一开关。
- **Decision 8 同源关联**：`audit.EventFromRequest` span-first + traceparent 头兜底，`ParentSpanID` 走 `tracing.ParentSpanID` seam（D8-1：otel 公共接口无 `Parent()`）；`X-Parent-Span-Id` 表面删除（D8-2）；login-anomaly 经共享 `requestTraceID`（D8-3）。access log 与 audit 的 `trace_id` 与 span 同源（test/access_log_test.go 有断言）。
- 唯一注意到的是 build_app_core.go 内一段孤儿注释的删除（本方向文件内既有状态），未改动。

**门禁（全部实际运行）**：

| 命令 | 结果 |
|---|---|
| `go build ./... && go vet ./...` | PASS |
| `go test ./interfaces/middleware/... ./platform/tracing/... -count=1` | PASS |
| `go test ./interfaces/sso/... -count=1 -run 'Trace\|Correl\|Log'` | PASS |
| `go test ./test/ -run 'Trace\|Correl\|Log' -count=1` | PASS |
| `go test -count=1 -run 'TestMaintainability_\|TestArchitecture_\|TestDirectory' .` | PASS |
| `gofmt -l`（本方向全部 .go） | 干净 |
| `go test ./... -race` | PASS |
| `go test ./test/ -run TestE2E -v` | PASS（5/5） |
| `make ci` | PASS（route/OpenAPI、proto parity、capabilities、profiles、adapters） |

**硬边界**：`interfaces/middleware` 非测试 .go 恰 10 个；`request_log.go` 341 行 ≤ 500；零豁免改动。

**提交**：路径限定 `git add` 恰 29 个本方向文件，conventional commit（imperative + `Co-authored-by: pi <pi@earendil.dev>`），已推送。工作树其余改动（`docs/architect-analysis/auto/state.jsonl`、campaign yaml、B12-R2 的 fapi 报告与未跟踪 campaign 文件、`.pi-batch.lock`）原样保留，未提交。
