完成。提交 `39ecdf7a`（已推送），工作区仅剩批处理 runner 的预存在变更（未触碰）。

## 摘要

**第一步——设计**：`docs/design/operator-config-apply.md` 裁决了全部 7 个问题：

1. **权威模型**：opt-in 用 Spec 字段 `spec.apply.enabled`（默认 false → 既有 CR 逐字节不变；Spec 变更 bump Generation 即时生效）；审批用一次性注解 `sso.snaplink.io/apply-approve: "true"`（瞬态、不入 GitOps 期望态、注解不变更 Generation → 天然节流）；reason 用 `spec.apply.reason`（CEL 准入 + controller 双层防护）。RBAC 边界不变（可写 CR ⊆ 可读同命名空间 Secret，doc.go 已有 trust model 覆盖）。
2. **时序**：触发 = opt-in + 已审批 + diff 非空 + check 成功；每次审批最多一次 apply（成功即消费注解）；注解不 bump Generation → 生效延迟 ≤ PollInterval，天然"不每轮打 apply"；失败沿用 shortRequeue（30s），审批保留待重试。
3. **结果上报**：`status.apply{state, lastAttemptAt, versionID, digest, message}`，与既有 drift 字段并存；apply 失败不压制 drift 报告（fail-open）。
4. **回滚**：operator 永不驱动 rollback（无可观测触发信号——apply 不改 running config），留手工；`versionID` 给出精确回滚目标；无 `rollbackPath` 常量。
5. **安全**：token 仍只经 Secret；apply 请求体是 A 已服务端脱敏的 running 快照；operator 不持久化快照（仅内存 + 哈希）；digest 与 `configaudit.Digest` 逐字节一致。
6. **硬边界**：未 opt-in CR 路径逐字节不变；零豁免；嵌套模块 go.mod 零新增依赖（digest 用 stdlib 重实现 + 已知答案固定，避免拖入 otelhttp）。
7. **验收断言**：10 条，全部由测试覆盖。

**第二步——实现**：CRD 类型（`ApplySpec`/`ApplyStatus` + 手写 DeepCopy）+ CRD YAML（含 CEL）+ controller（`maybeApply`/`runApply`/`consumeApproval`/`snapshotDigest`，函数均 <50 行）+ http.go（`postConfigApply`，复用 `describeAPIError`）+ 38 个测试全绿（含 fake 服务端请求形状断言、opt-in/审批矩阵、409/500 注入、零调用断言、已知答案 digest parity、one-shot 节流）。

**验证输出**（全部实跑）：
- `cd cmd/sso-operator && go build ./... && go vet ./... && go test ./... -count=1` ✓（38 tests）`-race` ✓
- `cd /home/u1/workspace/demo/snaplink && go build ./... && go vet ./...` ✓
- `go test -count=1 -run 'TestMaintainability_|TestArchitecture_|TestDirectory' .` ✓ ok

**文档同步**：`doc.go`（non-goals 改为 no canary/no remediation、apply opt-in、rollback 手工）、`main.go`、`deferred-backlog.md`、根 `CHANGELOG.md`（Added 条目，记嵌套模块变更）。

一个值得注意的实现点：审批消费用无 resourceVersion 的 JSON merge patch（DeepCopy 上执行），与先行的 `Status().Update` 天然无冲突——这是对照 controller-runtime fake client 源码（`copyStatusFrom`/RV 强制）与真实 apiserver 语义（merge patch 无条件、`.Into()` 回写 RV）验证后确定的。
