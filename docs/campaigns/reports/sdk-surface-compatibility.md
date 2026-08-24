已在 `47fa431e` 的 registry operationId/group gate 上补齐 schema compatibility residual；本次仍不是 SDK 发布。

completion_report:
  summary: "为 SDK surface diff 增加显式、fail-closed 的 OpenAPI components.schemas 结构兼容性比较；不修改生成 SDK 或 package 版本。"
  changed_files:
    - ".github/workflows/sdk-ci.yml"
    - "CHANGELOG.md"
    - "Makefile"
    - "docs/ROADMAP.md"
    - "docs/agent-os/CHECKS_REGISTRY.md"
    - "docs/campaigns/reports/sdk-surface-compatibility.md"
    - "docs/deferred-backlog.md"
    - "ops/build/sdk-surface.json"
    - "ops/scripts/sdk_baseline.py"
    - "ops/scripts/sdk_report.py"
    - "ops/scripts/sdk_schema.py"
    - "ops/scripts/sdk_surface.py"
    - "ops/scripts/test_sdk_surface.py"
  requirements_covered:
    - "--baseline-ref 从同一 local git ref 读取 registry 与 docs/openapi.yaml，不 fetch、不执行 shell。"
    - "--baseline-file 保留 registry-only 语义，并通过 --baseline-openapi-file 显式启用 schema 比较；不使用当前 OpenAPI 充当 baseline。"
    - "稳定分组报告 operation surface 与 schema breaking/additive；operation removal/relocation 和 breaking schema 变化返回非零。"
    - "schema/property removal、required 增加、$ref/type/format、additionalProperties 收紧、enum 删除、items/嵌套变化按 breaking 报告。"
    - "新增 schema、optional property、required 约束移除和 enum 增加按 additive 报告；description/title/examples/default 变化不触发 breaking。"
    - "oneOf/anyOf/allOf 等 composition 与未支持 schema keyword 变化采用可解释的 conservative-breaking policy；坏 ref、JSON、YAML、缺失文件和不支持结构 fail closed。"
    - "无 --allow-breaking 绕过、无自动版本变更；SDK CI PR base-ref job 与本地 make target 均实际覆盖 schema diff，make ci 不隐式比较 baseline。"
  tests_added:
    - "32 个 focused Python unittest 覆盖 ref bundle、registry-only 边界、显式 OpenAPI pairing、无变化、breaking/additive schema 规则、坏输入、composition 和稳定输出。"
  commands_executed:
    - command: "python -m unittest discover -s ops/scripts -p 'test_sdk_surface.py' -q"
      result: passed
    - command: "python cli.py sdk-surface check"
      result: passed
    - command: "python cli.py sdk-surface diff --baseline-ref HEAD^"
      result: passed
    - command: "make sdk-surface-diff SDK_SURFACE_BASELINE_REF=HEAD^"
      result: passed
    - command: "python cli.py sdk-surface diff --baseline-ref definitely-not-a-local-ref"
      result: passed
      note: "按预期以 exit 1 拒绝坏 ref。"
    - command: "make docs-validate"
      result: passed
    - command: "go build ./... && go vet ./..."
      result: passed
    - command: "go test -run 'TestMaintainability_|TestArchitecture_|TestDirectory' ."
      result: passed
    - command: "go test ./... -race"
      result: passed
    - command: "go test ./test/ -run TestE2E -v"
      result: passed
    - command: "make ci"
      result: passed
    - command: "git diff --check"
      result: passed
  architecture_checks:
    - "未新增 Go 包、维护性豁免、skipDirs 或 layerExemptions；Python 实现按 baseline/schema/report 责任拆分到现有 ops/scripts。"
    - "根门禁、race、E2E、nested modules、profile isolation 与 make ci 均通过。"
  security_checks:
    - "git ref 只通过参数数组调用本地 git rev-parse/show，禁止 fetch 与 shell；registry/OpenAPI 必须来自同一已解析 commit。"
    - "坏输入 fail closed；baseline 不存在时不会回退到当前 OpenAPI；不存在 breaking-change bypass。"
  compatibility:
    current_vs_head_parent: "HEAD^ 比较结果为 compatible，operation 与 schema breaking/additive 均为 0。"
    baseline_file_boundary: "registry-only baseline 明示 schema comparison unavailable；schema 文件必须显式配对。"
    schema_policy: "删除/收紧/约束变化保守判定 breaking，安全的新增/放宽变化 additive，输出排序和字段固定。"
  migration:
    version_change: "无自动版本修改。"
    generated_artifacts: "未修改已生成 SDK 或 package 版本。"
    publication: "versioned package publication 仍是剩余外部边界。"
  residual_risks:
    - "schema diff 只覆盖 bounded components.schemas structural subset，不是完整 OAS/vendor-level diff；未支持的语义不会被宣称已覆盖。"
    - "composition 与其他未支持 keyword 的变化按 conservative-breaking 处理，可能产生保守 false positive。"
    - "PR diff 依赖 SDK CI 的 full checkout 能解析 pull request base SHA；浅 checkout 或缺失 ref 会 fail closed。"
  assumptions:
    - "registry group id 是公开 SDK surface ownership 标识。"
    - "改名按旧 operationId removed + 新 operationId added 报告，不进行启发式 rename 推断。"
