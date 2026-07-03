`go build ./...` 和 `go vet ./...`（仅有一个不在我改动范围内的预存 `example_test.go` 问题）均通过。以下是我所完成工作的总结：

---

## 各个方向的完成摘要

### 方向 1：跨配置文件验证 — 已修复并已扩展 ✅

我认为是缺失的，然后被验证且确实缺失的：
- **`--validate-only` 标志** — ✅ 自第 53 行起，`cmd/sso-server/main_wiring.go` 中已存在
- **`config-validate` / `config-validate-all` Makefile 目标** — ✅ 已存在
- **`config-validate-all` 无法传播错误** — ❌ **已修复**。现在在循环时使用 `fail=1; ... exit $fail`，并且在循环前有 `SKIP (not found)` 和 `==> Validating...` 头部。已加入 CI `ci-full` 组。
- **找到并修复了 2 个配置漂移 bug** — `ops/deploy/compose/config.yaml` 和 `ops/deploy/k8s/config.yaml`（加上新的 `kustomize/base/config.yaml`）使用了 SDK 哨兵值 `issuer: snaplink-sso`，这在验证中被拒绝。已修复为 `sso-server`。

### 方向 2：烟雾测试 — 早已足够 ✅

`ops/deploy/baremetal-ha/smoke.sh` 已经包含 6 项检查（发现、就绪检查、副本轮询、令牌发放、用户信息、吊销 + 自省）。不需要改动。

### 方向 3：负载测试 CI/基线 — 已添加 ❌→✅

- **`load-test-record`**、**`load-test-compare`**、**`load-test-ci`** — 在 `.PHONY` 中声明但**没有配方**。❌ 现在已经有了完整的实现。
  - `load-test-record`：运行 k6，提取指标，保存到 `baseline.json`
  - `load-test-compare`：运行 k6，对照基线比较 p95/p99/失败率，阈值可配置（默认 20%），失败时返回退出码 1
  - `load-test-ci`：在 CI 中智能选择——如果基线存在则进行比较，否则先录制

### 方向 4：Kustomize 基础/覆盖层 — 重构并已记录 ✅

虽然已有工作模式（`k8s-prod` 引用 `../k8s`），但缺少清晰的 `base/overlays` 布局：
- **创建了 canonical 结构**：`ops/deploy/kustomize/base/` + `overlays/{dev,prod}/`
- 覆盖层之间的 diff 现在清晰地显示了哪些内容发生了变化（配置后端、HPA、PDB、副本数、secret 引用、区域分布、优雅关闭、就绪探针容忍度）
- 遗留目录（`k8s/`、`k8s-prod/`）保留了弃用说明并保持功能
- 更新了 `k8s-render` 和 `k8s-diff` Makefile 目标 —— 使用新的 canonical 路径，回退支持 `kubectl kustomize`
- 所有三层（base、dev、prod）均能正确渲染

### 方向 5：Terraform IaC — 早已存在 ✅

AWS VPC、RDS、Elasticache、EKS 的完整 Terraform 模块，`environments/{dev,prod}`，README，以及 Makefile 目标都已经存在。不需要改动。

---

## 新增 CI 集成

已向 `.github/workflows/ci.yml` 添加了 3 个新任务，使得配置漂移、Kustomize 语法和 Terraform HCL 错误现在都能在 PR 中被捕获：

| CI 任务 | 内容 |
|---|---|
| `config validate (all 7 config.yaml files)` | 加入到 `test` 任务中，在每个 PR 上针对服务器二进制文件验证所有 7 个配置文件 |
| `kustomize` | 全新任务：安装 kustomize，渲染所有覆盖层，比较 dev/prod diff |
| `terraform` | 全新任务：安装 terraform，对所有 HCL 执行 `init -backend=false + validate` |

已更新 Makefile `ci-full` 目标，同时运行 Terraform 和 Kustomize 检查。
