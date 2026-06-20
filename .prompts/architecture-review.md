# Prompt: architecture review

Periodic structural audit (read-only). Goal: catch erosion the per-change gates
can't — drift between `.arch/rules.yaml`/ADRs and reality, latent layering
inversions, and god-package growth.

## Inputs
- `AGENTS.md` (module map, gates), `docs/adr/`, `.arch/rules.yaml`,
  `docs/maintainability-gates.md`.
- Real tree only: enumerate with `git ls-files`; **ignore** `.claude/worktrees/`,
  `.qoder/`, `.qwen/` (they are full repo copies that inflate every count ~50×).

## Checklist
1. **Gates green?** `go test -run 'TestMaintainability_|TestArchitecture_ImportBoundaries' ./...`
   and `python cli.py {check-root,complexity,architecture,check-invariants}`.
2. **Budget headroom.** Files approaching 500 lines; functions approaching the
   cyclo/cognit/len caps. Flag the next god-file before it lands.
   `git ls-files '*.go' | grep -v _test.go | grep -v gen/proto | while read f; do wc -l "$f"; done | awk '$1>450' | sort -rn`
3. **Layering reality.** Re-derive the import graph; confirm `core` is still a
   leaf and the direction holds. Look for new *upward* edges and **latent
   inversions** (a "domain" package importing an infra adapter). Known watch
   items: `spi/risk.go → geo`, `anomaly/types.go → geo + defaultimpl`,
   `metering/sqlite → audit/sqlite`, the grandfathered `oidc → oauth` pair.
4. **God-package fan-out.** Is the root `package sso` shrinking or growing?
   Count root non-test files; is decomposition progressing (ADR-0001)?
5. **Manifest accuracy.** Does every number/command in `.arch/rules.yaml` still
   match its enforcer? The enforcer wins — fix the manifest, not the gate.
6. **ADR drift.** Any merged change that altered a rule without an ADR?

## Output
1. Current architecture analysis (grounded counts)
2. Issues (separate real gate violations from latent risks)
3. Recommendations (sequenced; flag breaking/public-API moves as v2-only)
4. Risk assessment
Do **not** modify code in this mode — propose, then await confirmation.
