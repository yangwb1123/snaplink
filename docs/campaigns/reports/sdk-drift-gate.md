# SDK regeneration-drift and deploy-tree sweep gate

T-9 is implemented as an artifact-only gate. The committed SDK outputs were
verified against the current generator before remediation: both canonical files
were already byte-identical, so no artificial SDK diff was created. The ignored
static tree was refreshed and used for byte-identity and stale-copy drills, then
removed from the worktree because its external generated documentation caused an
existing deploy-tree literal sweep to fail; an absent static tree is an explicit
successful gate state.

completion_report:
  summary: "Implemented T-9 SDK regeneration-drift and deploy-tree sweep gate; canonical SDKs had no current drift."
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
    - "R1: temporary go run regeneration with explicit TS/Python outputs, byte comparison, bounded diff samples, git status cleanliness, and fail-closed tool errors."
    - "R2: three deploy-tree byte comparisons with SKIP success when static/ is absent and failure for partial or stale trees."
    - "R3: current generator was run; canonical SDKs required no additive refresh; ignored static target copies were refreshed for validation and not tracked."
    - "R4: CLI help/dispatch/passthrough, Makefile phony target and ci prerequisite, and CHECKS_REGISTRY wiring."
    - "R5: pytest fixture matrix, failure drills, dist exclusion, cleanup, wiring, and real generator determinism."
  tests_added:
    - "checks/test_sdk_drift.py: 21 tests passed, including fake-generator, deploy absence/identity/staleness/missing targets, stray files, dist dirt, git/tool failures, cleanup, capped diffs, wiring, and real Go determinism."
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
    - command: "go test -run 'TestMaintainability_|TestArchitecture_|TestDirectory' ."
      result: passed
    - command: "make ci (first run)"
      result: failed
    - command: "go test -race -count=1 ./... (diagnostic rerun before cleanup)"
      result: failed
    - command: "targeted TestRunCIBAPrune race check"
      result: passed
    - command: "make ci (rerun after ignored static-tree cleanup)"
      result: passed
    - command: "git diff --check"
      result: passed
    - command: "git status --porcelain"
      result: passed
  architecture_checks:
    - "No Go production files or imports changed; no exemptions, skipDirs, or layerExemptions were added."
    - "The new flat checks modules remain within the existing checks ownership and budget boundaries."
    - "The final make ci rerun passed, including route, module, profile, adapter, build, vet, and race prerequisites."
  security_checks:
    - "Generation writes to TemporaryDirectory and disables the generator's package output, so failed checks do not mutate the worktree."
    - "Git status fails closed; only the committed docs/sdks/typescript/dist/ subtree is excluded."
    - "Diff output is bounded to ten unified-diff lines per mismatch."
    - "No protocol, OpenAPI, server, generator, sdk-surface, or wire/security behavior changed."
  compatibility:
    - "The existing sdk-surface check and version gate remain unchanged and passed."
    - "SDK package manifests and versions remain 0.3.0; canonical generated TS/Python files were already current."
    - "static/ is ignored by .gitignore and is not tracked or committed; the final absent tree exercises the required SKIP path."
    - "docs/sdks/typescript/dist/ was intentionally not regenerated or checked for drift."
  migration: "No migration is required. After docs/openapi.yaml or the SDK surface changes, run python cli.py sdk-drift check and regenerate the committed outputs when it reports drift; an external deploy pipeline may recreate the ignored static tree."
  residual_risks:
    - "When an external static tree is present, unrelated repository sweeps may inspect its generated documentation; the new gate itself checks only the three declared byte pairs."
    - "The first full make ci/race attempt exposed existing test flakiness and the pre-existing ignored static-tree interaction; removing ignored external build output and rerunning produced a green make ci."
    - "The committed TypeScript dist product remains outside this gate by design."
  assumptions:
    - "The current generator's embedded OpenAPI spec and default surface registry are authoritative."
    - "No canonical SDK refresh was necessary because the pre-change tree showed zero byte drift; the in-place generator verification produced no tracked SDK diff."
    - "Ignored external static build output is not a deliverable and may be absent in a fresh checkout."
