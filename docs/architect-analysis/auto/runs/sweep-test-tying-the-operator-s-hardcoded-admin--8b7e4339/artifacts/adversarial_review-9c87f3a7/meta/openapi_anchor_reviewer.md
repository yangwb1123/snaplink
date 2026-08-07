Hardening review complete. Report written to `docs/architect-analysis/auto/runs/cmd-sso-operator-controller-b4-3-adminpaths-sweep/artifacts/hardening-2d8b4f61/task-1-hardening.md`. Findings on the four questions:

## 1. Provenance: hand-maintained, not generated
- No generator tooling anywhere (no oapi-codegen/swag/redocly/spectral); the only `Stoplight` mention is the header's consumer list. First commit `48fa7250` is a hand-authored spec; feature commits (`7f03d382`, `ef747aed`) hand-add endpoints alongside code.
- Tooling touching the file is **validation-only**: kin-openapi `validate@latest` (`make docs-validate`, hosted CI job at `ci.yml:375` — **not** in `make ci`), `route-contract` (`cli.py check-routes`, **in** `make ci`), `docs-check` (existence).

## 2. Existing gates — the premise's real correction
`route-contract` already pins **both** paths: `server_backup.go:52,55` registers them via the `api` receiver inside its scan scope, and I confirmed both in its live 241-route inventory (`python cli.py check-routes` passes). Consequences:
- **§5 row 1's "the only tripwire that sees it" is false**: a value-changing coordinated rename fails `route-contract` in `make ci` (new routes undocumented) *and* the committed literals at `HEAD:config_audit_test.go:54,75,110,132` (404s), before R1 ever runs.
- R1's genuine, non-redundant value: reverse direction (doc key must *equal* the operator const, not merely contain the runtime route), operator-module-local detection inside the `ci-modules` boundary, strict yaml.v3 duplicate-key behavior (PyYAML in route-contract silently keeps the last), and durability after the direction's own no-literals refactor removes the literal copies.
- Full 12-mode interaction matrix in the report (e.g., doc path rename/method flip are already root-gated; operator-side const drift is R1/R2-only).

## 3. The two path keys — structurally inert
Whole-doc scans: **zero duplicate keys anywhere** (yaml.v3 hard-errors on dupes; PyYAML doesn't — currently moot), **zero anchors/aliases/merge keys**. Each key appears exactly once as a YAML key, both only under `paths` (5340, 5607). A yaml.v3 v3.0.1 probe (exact promoted version, isolated module) decodes the full 18,219-line doc, `paths` → 275-entry `map[string]any`, running→`[get]`, cluster-diff→`[post]`. The two extra raw occurrences are prose descriptions.

## 4. Durability — presence-only is the right shape
Append-dominant evolution (last 12 commits +4,916/−253; 161 path additions, zero feature-level removals). Both keys were introduced by their own feature commits and never renamed. Caveat: history shows **whole-doc rewrites at merge boundaries** (lineage jumps) — a realistic event class the design should name; presence-only exact-string assertions survive all observed legitimate changes and trip only on deliberate renames or rewrites that drop the keys, which is exactly the intended contract.

**Also corrected in the report (11 items)**: row-11's budget justification is void (maintainability gates skip `_test.go`), the table has 11 rows not 12, E12 is 14 `TestReconcile_*` not 10, no CRD-parity test exists (F3), the root gates *do* descend into `cmd/sso-operator` (F8, name-based `skipDirs`), §8's gate quote trims the `go build` segment, plus the pre-existing root-gate reds (ed25519_jwt_issuer.go 539 lines, auto/runs fan-out) that will make §6 step 4's `make ci` red today for unrelated reasons.

The core mechanics — E15 path fix, zero-add yaml.v3 promotion, R2/R3 pins, and the anchor test's failure behavior — are all confirmed sound; only the "only tripwire" framing and the four stale rationale claims need rewording before the test ships.
