已完成并提交 `47fa431e`，post-commit hook 已同步远端。

completion_report:
  summary: "新增 SDK registry SemVer/API diff 检查；不修改生成 SDK 或版本号。"
  changed_files:
    - ".github/workflows/sdk-ci.yml"
    - "CHANGELOG.md"
    - "Makefile"
    - "cli.py"
    - "docs/ROADMAP.md"
    - "docs/agent-os/CHECKS_REGISTRY.md"
    - "docs/deferred-backlog.md"
    - "ops/build/sdk-surface.json"
    - "ops/scripts/sdk_surface.py"
    - "ops/scripts/test_sdk_surface.py"
  requirements_covered:
    - "支持 --baseline-ref 和 --baseline-file，必须显式指定 baseline。"
    - "稳定报告 added、removed、relocated operationId。"
    - "移除/改名及跨 group 移动为 breaking；新增为 additive。"
    - "坏 JSON、坏 ref、缺失 baseline、重复 operationId fail closed。"
    - "无 --allow-breaking 绕过；不自动修改版本。"
    - "SDK CI PR 使用 base SHA；make ci 不隐式执行 baseline diff。"
  tests_added:
    - "14 个 Python unittest，覆盖 baseline 文件/ref、added、removed、relocation、无变化及全部坏输入路径。"
  commands_executed:
    - command: "python cli.py sdk-surface check"
      result: passed
    - command: "python -m unittest discover -s ops/scripts -p 'test_sdk_surface.py' -v"
      result: passed
    - command: "make docs-validate"
      result: passed
    - command: "go build ./... && go vet ./..."
      result: passed
    - command: "go test -run 'TestMaintainability_|TestArchitecture_|TestDirectory' ."
      result: passed
    - command: "make ci (首次运行)"
      result: failed
      note: "瞬时 race 失败：TestAsyncSink_ConcurrentWorkers；已实际重跑。"
    - command: "make ci (重跑)"
      result: passed
    - command: "git diff --check"
      result: passed
    - command: "post-commit hook pull/push"
      result: passed
  architecture_checks:
    - "未新增 Go 包、维护性豁免、skipDirs 或 layerExemptions。"
    - "diff 路径仅使用 Python 标准库和本地 git/JSON。"
  security_checks:
    - "git ref 通过无 shell 的 subprocess 解析，且不执行 fetch。"
    - "坏输入 fail closed；不存在 breaking bypass。"
    - "比较 registry group/operation 数据，不读取生成代码文本。"
  compatibility:
    current_vs_head_parent: "无 added、removed 或 relocated operationId；结果 compatible。"
    relocation_policy: "跨 registry group 移动按 breaking 处理。"
  migration:
    version_change: "无自动版本修改。"
    publication: "versioned package publication 仍是后续边界。"
  residual_risks:
    - "工具当前只检查 operationId/group surface，不检查 schema/type 级别 API 变化。"
    - "PR diff 依赖 SDK CI 的 full checkout 获取 base SHA。"
    - "工作树保留原有未跟踪 .pi-batch.lock，未纳入提交。"
  assumptions:
    - "registry group id 是公开 surface ownership 标识。"
    - "改名按旧 operationId removed + 新 operationId added 报告，不进行启发式 rename 推断。"
