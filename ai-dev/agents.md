# ai-dev — AI-SDLC 工具集说明（Agent 使用指南）

`ai-dev/` 是 Snaplink 仓库内的可选 AI 编排框架：用 CLI agent（pi，可换成
claude/codex/gemini 等）驱动软件开发流程——分析任意项目/想法、按角色产出
交付物、自优化增删角色、7×24 无人值守。它**补充而非替代**仓库的工程门禁
（`make ci`、`python cli.py check` 等）；AI 产出是**提案**，须按证据标准
核对后提升到维护文档。

## 1. 组件清单

| 组件 | 用途 |
|---|---|
| `pi-batch.py` | 批量/流水线执行器：任务、阶段串联、meta 编排、7×24 运营 |
| `ai/run-review.py` | 十阶段评审 runner（`--all`/`--resume`/共享会话/验证门禁） |
| `ai/prompts/00-09` | 评审阶段模板（产品发现→CTO 决策） |
| `prompts/` | 19 个专家角色模板（architect、security_engineer、qa_lead…） |
| `pipelines/` | 完整 SDLC 角色图（实验性设计图） |
| `examples/` | 三个可用案例：提案工作流、SDLC 角色流水线、通用 meta 分析 |
| `tests/` | 77 个回归测试（`make ai-dev-test`） |
| `docs/` | 机制文档（`RUNNING_247.md`、`AUTOMATION_WORKFLOW_SUMMARY.md` 等） |
| `pi-batch.yaml` | 声明式配置：agent 二进制、会话标志、验证器注册表 |

## 2. 能力机制

### 2.1 任务与输入方式

| 起点 | 用法 |
|---|---|
| 一句话 | pipeline 阶段 `from_prompt: "..."` + `output`（无需任何输入文件） |
| 目录文档 | 阶段 `from_dir: docs/requirements` |
| 阶段串联 | `from_outputs: <前阶段名>`（`aggregate: true` 把上游全部产出合并为一份证据） |
| 单批 | `-p "prompt"` / stdin / YAML `tasks:` 列表 |

### 2.2 结果校验（错误处理）

agent 回复**不是正确输出时一律不落盘**：

- 退出码非 0、空输出 → 拒绝
- 失败签名（即使退出码 0）→ 拒绝：
  - 额度/速率/计费/认证：`insufficient_quota`、`rate_limit_error`、
    `quota_exceeded`、`429 Too Many Requests`、`authentication_error`…
  - 网络/断网：`network is unreachable`、`no route to host`、DNS 失败、
    `connection refused/reset`、`curl: (N)`、`ECONNREFUSED`…
  - CLI 横幅：行首 `ERROR:` / `fatal:`
- 防误判：不匹配宽泛词（`error`/`timeout`/`401`），评审正文不会被误杀
- `--timeout`（默认 600s）超时 → 进程组 SIGKILL，拒绝并零孤儿进程
- 拒绝 = 无产物文件；任务失败 → 可自动重试/下轮重跑

### 2.3 工程质量验证

声明式验证器注册表（像 `engineering.yaml` 之于 `cli.py`）：

```yaml
# pi-batch.yaml
validators:
  quick: "python cli.py check"
  gofmt: 'test -z "$(gofmt -l {output})"'
  build: "go build ./... && go vet ./..."
  config: "python cli.py config-validate"
```

- `--validate quick,gofmt`：命名引用，AND 语义（全部通过才落盘）
- **每阶段可选**：任务 `validate` > 阶段 `validate_cmd` > CLI > 无；
  空字符串显式禁用（分析类任务跳过，代码生成类保留）
- 机制：输出写临时文件（`{output}` 占位符）→ 验证命令 → 通过则原子
  rename，失败则删除零残留

### 2.4 断点续跑与 7×24

| 参数 | 作用 |
|---|---|
| `--reuse` | 跳过已有输出的任务（pipeline 与单批均支持），只重跑失败项 |
| `--retries N` | 任务失败自动重试，指数退避；速率/网络类至少等 30s |
| `--max-rounds N`（0=无限） | 轮循环直到全部通过，`--round-delay` 轮间休息 |
| `--min-interval` | 成功任务间节流 |
| `--log-file` | 时间戳日志落盘（配合 `tail -f`/systemd 监控） |

配套：`run-review.py --all --resume` 从磁盘输出续跑并接力链上下文。

### 2.5 会话模式

```bash
--session-mode new        # 默认：每次调用新会话
--session-mode shared     # 整个批次/流水线一个会话（后续步骤延续上下文）
--session-mode per-stage  # 流水线每阶段一个会话
```

- 标志来自 `pi-batch.yaml` `agent.session_flags`（pi 风格默认，可适配其他 CLI）
- 共享会话要求串行（并行会乱序，runner 拒绝该组合）
- 会话 id 由 `--session-name` 派生（可重现）→ 断点续跑延续同一会话

### 2.6 自优化（meta 动态角色编排）

```yaml
stages:
  - name: kickoff
    from_prompt: "Analyze the idea: offline-first sync."   # 一句话起点
    output: docs/reviews/kickoff.md
  - name: review
    from_outputs: kickoff
    meta: true                       # 编排者动态挑角色
    role_dir: ai-dev/prompts         # 命名角色模板目录（可缺省）
    output_dir: docs/reviews
    max_iterations: 3
```

编排循环：**分析当前交付物 → 输出 JSON 角色计划 → 执行 → 产出折回证据 →
再问 → 收敛**。角色计划两种形式：

```json
["security_engineer", "qa_lead"]                       // 命名角色：role_dir 模板
[{"role": "perf_reviewer", "task": "分析性能瓶颈"}]      // ad-hoc 角色：任务描述+当前语境，无需模板
```

- 选中角色**并发执行**，各自独立 agent 会话
- 证据折叠：下一轮编排者/角色能看到前几轮结论（自优化闭环）
- 安全：编排输出不可信——命名角色模板查找限制在 role_dir 内（防路径
  穿越），ad-hoc 角色名 sanitize 为安全文件名

## 3. 命令速查

```bash
# 一句话 → 动态角色分析（任意项目）
python ai-dev/pi-batch.py ai-dev/examples/meta-review-pipeline.yaml

# SDLC 角色流水线（需求→架构→安全→质量，6 角色）
python ai-dev/pi-batch.py ai-dev/examples/sdlc-mini-pipeline.yaml \
  --log-file logs/sdlc.log

# 功能需求提案（同会话两任务）
python ai-dev/pi-batch.py ai-dev/examples/snaplink-proposals.yaml \
  --mode serial --session-mode shared --session-name logout-proposals

# 7×24 无人值守
python ai-dev/pi-batch.py tasks.yaml --mode serial --reuse --retries 3 \
  --max-rounds 0 --round-delay 300 --min-interval 5 --log-file logs/run.log

# 评审闭环（十阶段，共享会话，可续跑）
python ai-dev/ai/run-review.py --all --context ctx.yaml \
  --session-mode shared --resume --validate quick
```

## 4. 测试与门禁

```bash
make ai-dev-test            # 77 个回归测试（runner 机制）
python -m pytest checks/    # 仓库工程门禁自测（147 个）
```

修改 ai-dev 后：跑 `make ai-dev-test` + 与改动相称的仓库门禁；涉及 Go
代码时按仓库 `AGENTS.md` 强制验证流程执行。

## 5. 安全与信任边界

- **不可信输入**：agent 输出、编排者 JSON——失败签名拒绝落盘、角色模板
  查找防穿越、角色名 sanitize
- **失败零产物**：拒绝/验证失败的结果不留任何文件（临时文件删除）
- **AI 产出是提案**：按证据标准（Verified/Partial/Missing/Proposed）核对后
  提升到 `docs/feature-matrix.md`、`docs/deferred-backlog.md` 或正式
  feature spec，不直接作为需求/测试结果/发布批准
- **仓库硬门禁不变**：本工具集不豁免 `make ci`、`cli.py` 检查、AGENTS.md
  的安全/线协议不变量

## 6. 文档索引

| 文档 | 内容 |
|---|---|
| 本文件 | 能力总览与使用指南 |
| `docs/RUNNING_247.md` | 7×24 运营、验证门禁、会话、meta 编排细节 |
| `docs/AUTOMATION_WORKFLOW_SUMMARY.md` | runner 状态与机制速览 |
| `docs/ROLES_SUMMARY.md` | 角色 prompt 边界说明 |
| `ai/README.md` | 十阶段评审框架用法 |
| `examples/README.md` / `SDLC_CASE.md` | 提案工作流与角色流水线案例 |
| 仓库根 `AGENTS.md` | 项目执行契约（本工具集必须遵守的硬门禁） |
