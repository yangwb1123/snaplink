All blocking findings have been independently verified against the repository. Evidence chain:

**Resolved blockers (with in-repo confirmation):**
1. **R3 config-test break** — `config/scope_registry_test.go:116-129` "membership rejects unregistered allowed_scope" confirmed present, uses `billing:checkout:create` with `Matrix = scopecontract.Matrix()` + `Enabled=true` (breaks on registration). Design R3 rebases onto `tenant-quota:projection:write`; verified `shared/core/consts.go:26` defines that real const and it is absent from `Matrix()`; mutation testing proved the rebased test stable red-before/green-after in both directions.
2. **TestMatrixShape break** — `interfaces/scopecontract/consts.go` `Matrix()` confirmed exactly 8 rows, no checkout; R1 updates the pin (mutation-proven FAIL 8≠9 → PASS).
3. **A1 fixture trap** — `cmd/sso-ctl/configcmd/main_test.go:123` `matrixYAML` confirmed an explicit 8-row literal; A1 (exit 1) depends on checkout being absent. Design's acceptance table explicitly pins "fixtures use explicit matrixYAML, unaffected", and the final adversarial stage pinned the comment-rebase direction (name the omission; do not say "nine-row"). Trap probe confirmed live (row appended → exit 0) and the design's invariance keeps A1 exit-1.
4. **matrixOnly slice** (`registry_test.go:90` confirmed as fixed probe list) — explicitly triaged non-blocking: not a red/green pin, guard-coverage only, proven stable post-change.
5. **Comment enumerations** — all comment-only; 8th file (`registry_test.go:14` "eight-scope" comment) lands in R2's same-file edit; `options_misc.go:488`, `compose/config.yaml:57` confirmed comment-only; compose already registers the scope via `extra_scopes` (line 66).
6. **Pre-existing gate failures** (ed25519_jwt_issuer.go 539 lines; docs fanout/depth) — verified byte-identical pre/post mutation, unrelated tooling-tree drift, separately reported per AGENTS.md §5.7.
7. **Security** — no widening beyond the single exact scope at post-allowlist points; oracle-safe shape untouched; architecture edge legal with no exemption (adapter already imports `interfaces/*`).

No unresolved or unrejected blocking finding remains; every breakage is covered by a named pin with two-directional mutation evidence.

VERDICT: PASS - all blocking findings (config-test rebase, matrix-shape pin, A1 fixture trap) are resolved in design R1-R6 with mutation-proven pins and a validated rebase target; remaining items are comment-only or explicitly triaged non-blocking with evidence.
