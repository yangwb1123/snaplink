# Prompt: architecture review

Periodic structural audit (read-only). Goal: catch erosion the per-change gates
can't — drift between `.arch/rules.yaml`/ADRs and reality, latent layering
inversions, and god-package growth.

## Inputs
- `AGENTS.md` (invariants and gates),
  `docs/architecture/DIRECTORY_MAP.md` (canonical package map), `docs/adr/`,
  `.arch/rules.yaml`, and `docs/maintainability-gates.md`.
- Real tree only: enumerate with `git ls-files`; **ignore** `.claude/worktrees/`,
  `.qoder/`, `.qwen/` (they are full repo copies that inflate every count ~50×).

## Checklist
1. **Gates green?** Run `go test -run 'TestMaintainability_|TestArchitecture_' .`.
   Treat Python checks as supplementary and report any disagreement with the
   committed Go gates or `engineering.yaml`.
2. **Budget headroom.** Files approaching 500 lines; functions approaching the
   cyclo/cognit/len caps. Flag the next god-file before it lands.
   `git ls-files '*.go' | grep -v _test.go | grep -v gen/proto | while read f; do wc -l "$f"; done | awk '$1>450' | sort -rn`
3. **Layering reality.** Re-derive the import graph; confirm `shared/core`
   imports no internal package and the direction
   `composition → interfaces → infrastructure → protocols → domains → platform → shared`
   holds. Look for upward edges and for either peer import between
   `protocols/oauth` and `protocols/oidc`.
4. **Composition-package fan-out.** Count non-test files in
   `interfaces/sso`; compare the measured value with `AGENTS.md`,
   `engineering.yaml`, and `directory_fanout_test.go`. A changed exemption
   ceiling is itself a finding.
5. **Manifest accuracy.** Does every number/command in `AGENTS.md`,
   `engineering.yaml`, `.arch/rules.yaml`, and the executable enforcer agree?
   No source silently wins: report and reconcile drift.
6. **ADR drift.** Any merged change that altered a rule without an ADR?

## Output
1. Current architecture analysis (grounded counts)
2. Issues (separate real gate violations from latent risks)
3. Recommendations (sequenced; flag breaking/public-API moves as v2-only)
4. Risk assessment
Do **not** modify code in this mode — propose, then await confirmation.
