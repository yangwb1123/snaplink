# SDLC 角色流水线案例：OIDC Front-Channel Logout

一个用 ai-dev 驱动的、贴合实际软件开发流程与角色分工的小案例：
给 snaplink 的 OIDC logout 子系统新增 **front-channel logout** 特性，按
需求 → 架构 → 安全 → 质量 四个阶段、六种角色依次产出交付物。

## 案例流程（阶段 × 角色 × 交付物）

| 阶段 | 角色（prompt） | 输入 | 交付物 |
|---|---|---|---|
| 1. 需求分析 | Business Analyst（`business_analyst.md`） | `sdlc-inputs/oidc-logout-frontchannel.md` | 需求理解 + MVP 范围 |
| 2. 架构设计 | Architect（`architect.md`）+ Tech Lead（`tech_lead.md`）并行 | 阶段 1 全部产出 | 架构方案 + 实现任务拆解 |
| 3. 安全审查 | Security Engineer（`security_engineer.md`）+ Protocol Expert（`protocol_expert.md`）并行 | 阶段 2 全部产出 | 威胁模型 + 协议合规检查 |
| 4. 质量验收 | QA Lead（`qa_lead.md`） | 阶段 3 全部产出 | 测试策略 + 验收清单 |

阶段间 `from_outputs` 串联，`aggregate: true` 让每个角色一次性看到上游
全部证据（Architect 和 Tech Lead 都基于同一份需求，Security 审查基于
方案 + 计划，QA 基于设计 + 审查结论）。

## 运行

```bash
# 从仓库根运行
python ai-dev/pi-batch.py ai-dev/examples/sdlc-mini-pipeline.yaml \
  --log-file logs/sdlc.log
```

预期输出（`docs/proposals/`）：

```
docs/proposals/
├── combined.arch.md          # 架构方案
├── combined.impl-plan.md     # 实现计划
├── combined.security.md      # 安全威胁模型
├── combined.protocol.md      # 协议合规检查
├── combined.qa.md            # 测试策略与验收清单
ai-dev/examples/sdlc-inputs/oidc-logout-frontchannel.out.md   # 需求理解
```

## 会话语义（角色如何协作）

- **阶段内并行角色**（Architect ∥ Tech Lead）：各自独立会话。并行调用
  共享同一会话会打乱对话顺序，runner 会拒绝该组合（守卫）。
- **阶段间串联**：默认每个任务新会话。若希望后续阶段延续前面对话，把
  阶段改为 `mode: serial` 后加 `--session-mode shared`（整条流水线一个
  会话）或 `--session-mode per-stage`（每阶段一个会话，重试仍在会话内）。

## 与 ai-dev 机制的组合

```bash
# 额度/断网自动重试（速率类错误至少等 30s）
python ai-dev/pi-batch.py ai-dev/examples/sdlc-mini-pipeline.yaml \
  --mode serial --retries 3 --retry-delay 30 --log-file logs/sdlc.log

# 中断后续跑：--reuse 只重跑失败阶段的任务
python ai-dev/pi-batch.py ai-dev/examples/sdlc-mini-pipeline.yaml --reuse

# 7×24：循环直到全部交付物通过（0 = 无限）
python ai-dev/pi-batch.py ai-dev/examples/sdlc-mini-pipeline.yaml \
  --reuse --max-rounds 0 --round-delay 300 --log-file logs/sdlc.log
```

本案例是纯文档产出（方案/审查/计划），无需工程质量门禁；若阶段生成
代码，加 `validate_cmd`（如 `go build ./... && go vet ./...`）或引用
`pi-batch.yaml` 的命名验证器（`--validate quick,gofmt`）。

## 评审闭环

对交付物做一轮角色评审（AI-SDLC 十阶段框架）：

```yaml
# docs/proposals/review-ctx.yaml
project: Snaplink SSO
subsystem: OIDC front-channel logout
files:
  - docs/proposals/combined.arch.md
  - docs/proposals/combined.security.md
  - docs/proposals/combined.protocol.md
```

```bash
python ai-dev/ai/run-review.py --all --context docs/proposals/review-ctx.yaml \
  --session-mode shared --session-name fc-logout-review
```

评审结论按 AGENTS.md 证据标准核对后，把验证过的部分提升到
`docs/feature-matrix.md` / `docs/deferred-backlog.md` 或走
`docs/templates/feature-spec.md` 正式流程——AI 产出是提案，不是结论。
