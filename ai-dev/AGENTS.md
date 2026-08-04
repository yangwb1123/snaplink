# ai-dev — AI-SDLC 工具集说明（Agent 使用指南）

`ai-dev/` 是 Snaplink 仓库内的可选 AI 编排框架：用 CLI agent（pi，可换成
claude/codex/gemini 等）驱动软件开发流程——分析任意项目/想法、按角色产出
交付物、自优化增删角色、交叉对抗验证、7×24 无人值守。它**补充而非替代**
仓库的工程门禁（`make ci`、`python cli.py check` 等）；AI 产出是**提案**，
须按证据标准核对后提升到维护文档。

## 1. 组件清单

| 组件 | 用途 |
|---|---|
| `pi-batch.py` | 入口薄壳（24 行）：原命令全部不变，实现见 `pbatch/` 包 |
| `pbatch/config.py` | 声明式配置解析（pi-batch.yaml）、agent 默认值、会话标志、验证器注册表 |
| `pbatch/models.py` | 数据模型：Task / TaskResult / Stage / Pipeline |
| `pbatch/runner.py` | 任务执行：硬超时、失败签名拒绝、重试、验证门禁、摘要 |
| `pbatch/pipeline.py` | 流水线：阶段构建、meta 角色编排、gate 裁决、决策日志、归档 |
| `pbatch/cli.py` | 命令行：参数解析、main、轮循环、单批/流水线分发 |
| `quality.py` | 代码组织质量扫描器（纯标准库）：函数 ≤50 行、复杂度 ≤15、文件 ≤1000 行 |
| `ai/run-review.py` | 十阶段评审 runner（`--all`/`--resume`/共享会话/验证门禁） |
| `ai/prompts/00-09` | 评审阶段模板（产品发现→CTO 决策） |
| `ai/prompts-shared/` | 评审共享片段（工程原则、输出格式、检查清单、角色定义） |
| `prompts/` | 19 个专家角色模板（architect、security_engineer、qa_lead…） |
| `pipelines/` | SDLC 角色图与代码实现流水线（设计图） |
| `examples/` | 5 个可用案例：提案工作流、SDLC 角色流水线、通用 meta 分析、MFA 分析、完整闭环 |
| `tests/` | 91 个回归测试（`make ai-dev-test`） |
| `docs/` | 机制文档（`RUNNING_247.md`、`AUTOMATION_WORKFLOW_SUMMARY.md` 等） |
| `pi-batch.yaml` | 声明式配置：agent 二进制、会话标志、6 个验证器（含 `pyquality`） |

**可移植性**：把 `pi-batch.py`（薄壳）+ `pbatch/` 目录 + `pi-batch.yaml`
复制到其他项目即可用；配置查找顺序为入口脚本旁 → 包目录 → 工作目录。

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
- `--timeout`（默认 900s，配置 `default_timeout` 可覆盖）超时 → 进程组
  SIGKILL，拒绝并零孤儿进程。硬超时按绝对截止时间执行（管道线程不延长
  窗口）；pi 侧 HTTP 空闲超时 `httpIdleTimeoutMs` 默认 300s（项目级
  `.pi/settings.json` 已调大到 900s，两者对齐）
- 拒绝 = 无产物文件；任务失败 → 可自动重试/下轮重跑

### 2.3 工程质量验证

声明式验证器注册表（像 `engineering.yaml` 之于 `cli.py`）：

```yaml
# pi-batch.yaml（6 个已注册）
validators:
  quick: "python cli.py check"
  gofmt: 'test -z "$(gofmt -l {output})"'
  build: "go build ./... && go vet ./..."
  config: "python cli.py config-validate"
  root: "python cli.py check-root"
  pyquality: "python {cwd}/ai-dev/quality.py {cwd}/ai-dev"
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
- **相关性预判（先判断再执行）**：`ai-dev/role_keywords.yaml` 给 19 个角色
  配关键词（中英双语）；编排前按交付物关键词重叠打分，把
  `Relevance suggestions (0-10)` 列表注入编排者 prompt，并限定**最多选
  3 个角色**——防止编排者每次遍历全部角色（无关角色不再被选，省 API）
- 安全：编排输出不可信——命名角色模板查找限制在 role_dir 内（防路径
  穿越），ad-hoc 角色名 sanitize 为安全文件名；`role_dir` 可完全缺省
  （纯 ad-hoc 角色即可运转）；编排者 JSON 解析容忍 ```json``` 围栏和
  任务文本中的 `]`（贪婪回退）

### 2.7 裁决门（交叉对抗验证的阶段目标确认）

```yaml
stages:
  - name: adversarial_review   # 编排者挑多个角色并发交叉审查（对抗视角）
    from_outputs: design
    meta: true
    role_dir: ai-dev/prompts
    output_dir: docs/proposals
    max_iterations: 2
  - name: gate                  # 独立 gatekeeper 裁决：VERDICT: PASS/FAIL
    from_outputs: adversarial_review
    aggregate: true
    gate: true
    tasks:
      - prompt: "... output VERDICT: PASS or VERDICT: FAIL - <reasons>"
        output: docs/proposals/gate.md
```

- `gate: true` 阶段读取产出中的 `VERDICT: PASS|FAIL|REJECT` 行；
  FAIL/REJECT **阻断后续所有阶段**（流水线停止并报告 GATE REJECTED）；
  无 VERDICT 行视为 FAIL（fail closed，未显式通过不放行）
- 交叉对抗由 meta 阶段提供：security_engineer 挑战架构、qa_lead 找缺陷、
  protocol_expert 验线协议……并发执行、证据折叠；gatekeeper 独立裁决

### 2.8 决策日志（每个决策的思考点与理由）

```yaml
# pipeline 顶层，或 CLI --decision-log FILE 覆盖（单批同样支持）
decision_log: docs/DECISIONS.md
```

每个阶段/单批轮次完成后自动追加一条结构化记录：时间、阶段、PASS/FAIL、
裁决结果、决策点摘录（交付物的 markdown 标题 + 首句，完整理由在产物文件
里）、证据路径。追加式保留全程历史——包括被否定的方案和 gate 裁决。
滚动分析（`for i in ...` 循环）每轮追加一条，历史不因覆盖丢失。

### 2.9 git 提交与归档（完成即处理，保持目录整洁）

```yaml
# pipeline 顶层（单批用 --git-commit / --archive-dir）
git_commit: true            # 每阶段完成后提交产物
archive_dir: docs/archive   # 全部成功完成后，把交付物移入 docs/archive/<name>-<时间戳>/
```

- 阶段/任务完成后 git commit（`git_commit: true` 或 `--git-commit`），
  交付物进入版本历史
- **全部成功（无失败阶段、gate 全部 PASS）后才归档**：中间 md 移入
  `archive_dir` 时间戳子目录，工作区只剩决策日志与归档；git 历史保留
  一切，可随时找回
- 滚动分析（`for i in ...` 单批循环）：每轮成功后自动归档
  `--archive-dir docs/archive`，输出目录只留最新一轮
- gate FAIL / 任务失败：不归档（阶段目标未达成，保留现场供排查）

### 2.10 代码组织质量门禁（dogfooding）

```bash
python ai-dev/quality.py ai-dev/          # 组织质量扫描（纯标准库）
python ai-dev/quality.py --strict ai-dev/ # 严格模式（含文件行数预算）
# 注册为 validator 后可在流水线中调用：--validate pyquality
```

- 预算与仓库 Go 门禁对齐：函数 ≤50 行、复杂度 ≤15、文件 ≤1000 行、
  重复函数体检测（测试文件预算 ×2）
- `pi-batch.yaml` 的 `validators.pyquality` 已注册，可在流水线阶段当
  工程门禁使用；重构 ai-dev 自身时用它对标验收（当前全树严格模式达标）

### 2.11 特性与流程环节映射（整套流程 = 全部特性）

| 流程环节 | 使用的特性 |
|---|---|
| 发现问题 | 滚动分析脚本（会话延续/决策日志/归档/节流）或 meta 编排 |
| 需求分析 | `from_prompt` 一句话起点 |
| 阶段串联 | `from_outputs` + `aggregate`（上游全部产出合并为一份证据） |
| 交叉对抗 | meta 动态角色：命名/ad-hoc、并发独立会话、证据折叠 |
| 阶段目标确认 | `gate` 裁决门：VERDICT PASS/FAIL，fail closed 阻断 |
| 真实实现 | agent 直接改仓库代码（`full-sdlc-implement.yaml`），`validate: build` 工程门禁 |
| 验收 | 第二个 gate（QA 核对验收标准覆盖） |
| 决策记录 | `decision_log`（每阶段思考点+理由+证据，追加式） |
| 完成即处理 | `git_commit`（每阶段）+ `archive_dir`（全成功后归档） |
| 韧性 | 失败签名拒绝落盘、`--reuse` 断点续跑、`--retries`、7×24 轮循环 |

## 3. 命令速查

```bash
# 一句话 → 动态角色分析（任意项目，无需输入文件）
python ai-dev/pi-batch.py ai-dev/examples/meta-review-pipeline.yaml

# 完整闭环：一句话 → 需求 → 设计 → 对抗审查 → 裁决门 → 实现+工程门禁 → 验收门
#          → git 提交 → 归档 → 决策日志
python ai-dev/pi-batch.py ai-dev/examples/quickstart-full-sdlc.yaml \
  --log-file logs/full-sdlc.log

# 全流程真实实现版：同一闭环，但 implement 阶段 agent 直接修改仓库代码
# （go build/vet 门禁 + QA 验收门把关），建议先 --dry-run 预览再跑
python ai-dev/pi-batch.py ai-dev/examples/full-sdlc-implement.yaml \
  --log-file logs/full-impl.log

# 一体式入口：滚动分析发现方向 → 选择方向 → 自动跑完整 SDLC（含真实实现）
#   full-flow.sh [轮数] [间隔秒] [方向]
# 交互模式：不给方向参数，展示候选后输入；非交互：直接传方向
bash ai-dev/scripts/full-flow.sh 3 300            # 3 轮分析 + 交互选方向
bash ai-dev/scripts/full-flow.sh 3 300 "设备信任"  # 3 轮分析 + 直接实现该方向

# 全自动：按项目架构模块逐个分析 → 自动提取每个方向 → 每个方向跑完整实现
#   full-auto.sh [--modules m1,m2] [--max-directions N] [--dry-run]
# 默认扫描 domains/interfaces/infrastructure/platform/protocols/shared 全部
# 模块；gate FAIL 等失败记录到 SUMMARY 并继续下一项，无人值守
bash ai-dev/scripts/full-auto.sh --dry-run                     # 先看计划
bash ai-dev/scripts/full-auto.sh --max-directions 3            # 全模块自动跑
bash ai-dev/scripts/full-auto.sh --modules "domains/mfa"       # 限定模块

# MFA 子系统分析（一句话起点 + 动态角色审查）
python ai-dev/pi-batch.py ai-dev/examples/quickstart-snaplink-analysis.yaml

# SDLC 角色流水线（需求→架构→安全→质量，6 角色）
python ai-dev/pi-batch.py ai-dev/examples/sdlc-mini-pipeline.yaml \
  --log-file logs/sdlc.log

# 功能需求提案（同会话两任务）
python ai-dev/pi-batch.py ai-dev/examples/snaplink-proposals.yaml \
  --mode serial --session-mode shared --session-name logout-proposals

# 滚动分析（替代 for i in {1..200} 裸循环：会话延续 + 决策日志 + 归档）
python ai-dev/pi-batch.py -p "基于当前代码库分析扩展方向" \
  --output "docs/requirements/runs/run-$(date +%Y%m%d-%H%M%S).md" \
  --session-mode shared --session-name ext-rolling \
  --min-interval 60 --retries 3 --log-file logs/ext.log \
  --decision-log docs/DECISIONS.md --git-commit --archive-dir docs/archive

# 7×24 无人值守
python ai-dev/pi-batch.py tasks.yaml --mode serial --reuse --retries 3 \
  --max-rounds 0 --round-delay 300 --min-interval 5 --log-file logs/run.log

# 评审闭环（十阶段，共享会话，可续跑）
python ai-dev/ai/run-review.py --all --context ctx.yaml \
  --session-mode shared --resume --validate quick

# 代码组织质量检查（重构 ai-dev 后用）
python ai-dev/quality.py --strict ai-dev/
```

## 4. 测试与门禁

```bash
make ai-dev-test            # 91 个回归测试（pi-batch 66 + run-review 20 + quality 5）
python -m pytest checks/    # 仓库工程门禁自测（147+ 个）
python ai-dev/quality.py --strict ai-dev/   # 组织质量门禁（当前全绿）
```

修改 ai-dev 后：跑 `make ai-dev-test` + `quality.py` + 与改动相称的仓库
门禁；涉及 Go 代码时按仓库 `AGENTS.md` 强制验证流程执行。

## 5. 安全与信任边界

- **不可信输入**：agent 输出、编排者 JSON——失败签名拒绝落盘、角色模板
  查找防穿越、角色名 sanitize、gate 缺失裁决 fail closed
- **失败零产物**：拒绝/验证失败的结果不留任何文件（临时文件删除）；
  阶段未完成（gate FAIL）不归档，保留现场
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
