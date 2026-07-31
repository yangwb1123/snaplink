# 可用示例：给 snaplink 提功能需求提案

一个完整跑通的小场景：让 agent 分析项目的 OIDC logout 子系统、提出 3 个
新增功能点，再把最优提案细化成 feature spec——覆盖 ai-dev 的核心机制：
任务批次、共享会话、错误重试、断点续跑、工程质量门禁与评审闭环。

## 0. 前置

```bash
uv sync                      # 安装 PyYAML（pyproject.toml 已管理）
python ai-dev/pi-batch.py --help   # 确认 runner 可用
```

## 1. 基本运行：两个任务 + 共享会话

```bash
python ai-dev/pi-batch.py ai-dev/examples/snaplink-proposals.yaml \
  --mode serial \
  --session-mode shared --session-name logout-proposals \
  --log-file logs/proposals.log
```

- 任务 1 分析项目并提 3 个功能点 → `docs/proposals/oidc-logout-3-features.md`
- 任务 2 细化 feature spec → `docs/proposals/oidc-logout-feature-spec.md`
- `--session-mode shared`：两个任务在**同一个会话**中执行，任务 2 能看到
  任务 1 的分析上下文（会话 id 可重现：`--session-name logout-proposals`）
- 两个任务 `validate: ""`：纯分析产出，显式跳过工程质量门禁
- `--log-file` 落盘日志，`tail -f logs/proposals.log` 可监控

## 2. 额度 / 速率 / 断网：自动重试

agent 返回 `rate_limit_error`、`insufficient_quota`、`connection refused`
等错误回复时（即使退出码为 0），输出**不会落盘**，并自动重试：

```bash
python ai-dev/pi-batch.py ai-dev/examples/snaplink-proposals.yaml \
  --mode serial \
  --retries 3 --retry-delay 30 --retry-backoff 2
```

速率/网络类错误每次重试至少等 30 秒（给限流窗口恢复），重试仍在同一会话内。
日志示例：

```
[WARNING] agent output REJECTED: agent reported provider failure (rate_?limit_?error)
[WARNING] RETRY 1/3 for task [1/2] in 30s (reason: ...)
[INFO] WROTE docs/proposals/oidc-logout-3-features.md
```

## 3. 中断 / 崩溃：断点续跑

任何时刻中断（Ctrl-C、断网、机器重启），已完成的任务输出都在磁盘上；
重新运行加 `--reuse` 只重跑失败的任务：

```bash
python ai-dev/pi-batch.py ai-dev/examples/snaplink-proposals.yaml \
  --mode serial --reuse --session-mode shared --session-name logout-proposals
```

```
[INFO] Reuse: 1 task(s) already have outputs, skipped
[INFO] WROTE docs/proposals/oidc-logout-feature-spec.md
```

`--max-rounds 0 --round-delay 300` 可让 runner 循环重试直到全部通过
（7×24 无人值守，见 `docs/RUNNING_247.md`）。

## 4. 工程质量验证（按需）

示例任务不生成代码，所以跳过了门禁。若任务是生成 Go 代码，用注册表
验证器（`pi-batch.yaml` 的 `validators`，与 `cli.py` 门禁体系一致）：

```bash
python ai-dev/pi-batch.py code-tasks.yaml --validate quick,gofmt
```

生成结果先写临时文件，`python cli.py check`（filesize+vet）与 gofmt 全部
通过才原子落盘；失败则删除临时文件并触发重试。

## 5. 评审闭环：用 run-review 评审提案

```yaml
# docs/proposals/review-ctx.yaml
project: Snaplink SSO
subsystem: OIDC RP-Initiated Logout proposals
files:
  - docs/proposals/oidc-logout-3-features.md
  - docs/proposals/oidc-logout-feature-spec.md
```

```bash
python ai-dev/ai/run-review.py --all \
  --context docs/proposals/review-ctx.yaml \
  --session-mode shared --session-name logout-review
```

10 个评审阶段共享一个会话依次执行；`--resume` 可在中断后续跑，失败的
阶段自动跳过接力（评审输出同样先过校验：额度/断网错误回复不落盘）。

## 预期输出

```
docs/proposals/
├── oidc-logout-3-features.md      # 3 个功能点（问题/证据/行为/验收）
└── oidc-logout-feature-spec.md    # 最优提案的 bounded spec
logs/proposals.log                 # 运行日志
```

把 AI 产出当**提案**而非结论：按 AGENTS.md 的证据标准核对后，将验证过的
结论提升到 `docs/feature-matrix.md` / `docs/deferred-backlog.md`，或按
`docs/templates/feature-spec.md` 走正式特性流程。
