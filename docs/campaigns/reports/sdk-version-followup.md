completion_report:
  summary: "修复非 diff action 忽略 baseline 参数的问题；提交 7e0d3f8e，post-commit hook 已同步。"
  changed_files:
    - ops/scripts/sdk_surface.py
    - ops/scripts/test_sdk_versions.py
    - docs/deferred-backlog.md
  requirements_covered:
    - "所有非 diff action 拒绝三个 baseline 参数。"
    - "保持 diff 行为不变，未增加 breaking bypass。"
    - "准确区分 TypeScript/Python generated clients 与 Rust/PHP 独立 package gates。"
    - "未修改 manifest、版本号、生成 SDK 或发布 workflow。"
  tests_added:
    - "覆盖 check/generate/list/versions 与 baseline-ref/file/openapi-file 组合，共 12 组。"
  commands_executed:
    - command: "python -m unittest discover -s ops/scripts -p 'test_sdk_*.py' -v"
      result: passed
    - command: "python cli.py sdk-surface versions"
      result: passed
    - command: "python cli.py sdk-surface versions --baseline-ref HEAD^"
      result: passed
      notes: "按预期拒绝，退出码 1"
    - command: "python cli.py sdk-surface check"
      result: passed
    - command: "python cli.py sdk-surface diff --baseline-ref HEAD^"
      result: passed
    - command: "make docs-validate"
      result: passed
    - command: "make ci"
      result: passed
    - command: "git diff --check"
      result: passed
  architecture_checks:
    - "无 Go 变更。"
    - "未新增豁免、skip 或 layerExemptions。"
  security_checks:
    - "baseline 参数在非 diff dispatch 前 fail closed。"
    - "未提供任何 breaking-change bypass。"
  compatibility: "diff 分支保持原有选择、读取和比较语义。"
  migration: "无需迁移；版本与发布边界未改变。"
  residual_risks:
    - "无新增残余风险；现有 bounded schema diff 限制保持不变。"
  assumptions:
    - "未跟踪的 .pi-batch.lock 为 harness 状态，未纳入提交。"
