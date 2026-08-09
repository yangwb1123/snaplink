All fixes are in place and verified. Final report:

## Verification results (all measured, not assumed)

**1. `bun run build` fails on a clean checkout — CONFIRMED, reproduced.**
`docs/sdks/typescript/package.json` has `"build": "tsc -p tsconfig.json"` and **zero `devDependencies`**; no lockfile is tracked (`git ls-files` finds no bun.lock/package-lock/yarn.lock), no `node_modules` committed, no global `tsc`. Running `bun run build` → `tsc: command not found`, exit 127.

**2. Fix applied — migration step 4 (and every gate reference) rewritten to `bunx tsc -p tsconfig.json`.**
Chose on-demand fetch over committing a typescript devDependency + lockfile: smaller change, no new lockfile in a Go repo, and verified `bunx tsc -p tsconfig.json` exits 0 and **reproduces the committed `dist/` byte-identically** (worktree clean afterward). Re-verified `bun test`: **9/9 pass** (7 hosted-login + 2 client), and `client.test.mjs:53` is exactly the confidential-token test's Basic-header assertion that AC3's TS arm targets. Fixed in the design doc (step 4, step 7, §7 universal gates, F8 row, AC1, §8 files) and the parent requirements doc (step 5, §7, files list) so both deliverables agree.

**3. `make ci` absence — CONFIRMED and re-documented as explicitly out-of-band.**
Makefile:268 `ci:` = `fmt vet race build examples proto-lint ci-modules config-validate-all modules-check modules-smoke route-contract proto-openapi-parity capabilities-check sdk-surface-check profiles-evidence adapters-check`; `grep bun` over Makefile and cli.py → zero hits. I did **not** wire them in: bun is not a declared repo toolchain, `bunx tsc` requires a network fetch, and the Makefile has no precedent for JS tooling (only Go + `python cli.py` checks). §7 now states explicitly: the two bun gates run manually in the SDK directory as publish-side verification, not as `make ci` prerequisites (mirroring the repo's existing `chaos-test`/`dr-drill` out-of-band pattern).

**4. Rollback must be git-revert-based — CONFIRMED; ordering hazard now called out.**
`dist/*.js` cannot be rebuilt in a clean environment (no committed typescript dependency or lockfile). The rollback paragraph now states: revert order is **sibling-first** — after the strict binder lands, reverting only the gensdk commit returns the SDKs to JSON emission and every credential SDK call 400s `invalid_request` against the form-only server; and there is no artifact-rebuild fallback, so rollback is git-revert-only.

**5. AC4 vs the regeneration-drift campaign — no double-implementation; deferral is correct and now precise.**
The T-9 gate (`checks/sdk_drift.py`, `sdk-drift check`, direction `add-a-regeneration-drift-and-deploy-tree-sweep-t-03b3762e`) passed its design gate but is **not yet implemented at HEAD** (no `sdk-drift` target anywhere). Its regeneration leg byte-compares regenerated `client.ts`/`client.py` vs committed — exactly AC4's stale-copy scenario — and it **deliberately excludes `dist/`** (design non-goal P2). AC4 now: names the sibling gate, keeps "no new gate added here" and explicitly forbids a drift test in `emit_test.go` (T-9 is the single implementation), states the sequencing dependency (until T-9 lands, byte-identity is enforced by AC1's regeneration-diff step + the single-commit rule), and notes the `dist/` scope gap is covered by the commit rule.

**Bonus consistency fix:** the dangling `§6.5` cross-references in the F1 failure row and migration step 8 → corrected to `§6` (the actual interlock section).

No Go code was touched (docs-only change), so the Go gates are unaffected; the SDK worktree is clean after the `bunx` rebuild.
