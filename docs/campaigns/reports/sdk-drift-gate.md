# SDK regeneration-drift and deploy-tree sweep gate

T-9 is an artifact-only gate. The current generator reproduced both canonical
SDK files without a tracked refresh. The external static tree was absent at
handoff; stale-copy drills created it temporarily, verified all three failures,
and restored then removed it.

completion_report:
  summary: "Implemented T-9 SDK regeneration-drift and deploy-tree sweep gate."
  changed_files:
    - checks/sdk_drift.py
    - checks/test_sdk_drift.py
    - cli.py
    - Makefile
    - docs/agent-os/CHECKS_REGISTRY.md
    - docs/ROADMAP.md
    - CHANGELOG.md
    - docs/campaigns/reports/sdk-drift-gate.md
  requirements_covered:
    - "R1: temporary go run regeneration with explicit TS/Python outputs, byte comparison, bounded samples, cleanliness scan, and fail-closed tool errors."
    - "R2: three deploy comparisons; absent ignored static/ prints SKIP and succeeds; partial or stale trees fail."
    - "R3: canonical SDKs were regenerated and had no current drift; ignored static copies were used only for validation and were not tracked."
    - "R4: CLI, Makefile, CI prerequisite, and CHECKS_REGISTRY wiring."
    - "R5: fixture matrix, generator/tool/git failures, cleanup, dist exclusion, capped samples, wiring, and determinism tests."
  tests_added:
    - "checks/test_sdk_drift.py: 21 tests passed, including regeneration, deploy absence/identity/staleness/missing targets, stray files, dist dirt, failure handling, cleanup, wiring, and real-generator determinism."
  commands_executed:
    - command: "python cli.py check-test"
      result: passed
    - command: "python cli.py sdk-drift check"
      result: passed
    - command: "python cli.py sdk-surface check"
      result: passed
    - command: "python cli.py sdk-surface versions"
      result: passed
    - command: "real stale-copy drills with temporary backup/restore"
      result: passed
    - command: "make -n ci"
      result: passed
    - command: "make docs-validate"
      result: passed
    - command: "go build ./... && go vet ./..."
      result: passed
    - command: "go run ./cmd/gensdk --lang=all"
      result: passed
    - command: "go test -run 'TestMaintainability_|TestArchitecture_|TestDirectory' ."
      result: passed
    - command: "make ci"
      result: passed
    - command: "git diff --check"
      result: passed
    - command: "git status --porcelain"
      result: passed
  architecture_checks: "passed: no Go production changes, exemptions, skipDirs, layerExemptions, or new packages"
  security_checks: "passed: generation uses TemporaryDirectory, package output is disabled, git status fails closed, and diff samples are capped"
  compatibility:
    breaking_change: false
    details: "sdk-surface semantics and package manifests/versions remain unchanged; generated additions were absent because canonical outputs were already current"
  migration:
    required: false
    rollback_verified: false
  residual_risks:
    - "static/ is intentionally ignored by .gitignore, untracked, and absent at handoff; present external copies are checked byte-for-byte."
    - "docs/sdks/typescript/dist/ is intentionally excluded because it is a separate TypeScript build product."
    - "The pre-existing untracked .pi-batch.lock is harness state and was not committed."
  assumptions:
    - "The embedded OpenAPI document and ops/build/sdk-surface.json are authoritative generator inputs."
    - "An absent external static tree is valid for a fresh checkout."
    - "No canonical SDK refresh is manufactured when regeneration produces identical bytes."
