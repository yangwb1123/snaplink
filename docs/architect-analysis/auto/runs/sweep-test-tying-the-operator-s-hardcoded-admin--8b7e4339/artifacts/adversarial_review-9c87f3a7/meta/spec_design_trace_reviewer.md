All verification complete. Here is the full report.

## Verification result: design fully incorporates all 3 corrections; acceptance coverage complete; no spec/design contradictions

### Correction 1 — consts line drift to controller.go:39–42 ✅

| Claim | Worktree measurement |
|---|---|
| Design §1 E1: doc comment 36–38, `const (` 39, `runningConfigPath` 40, `clusterDiffPath` 41, `)` 42 | Exact match (`grep -n` + read: 36 `// runningConfigPath and clusterDiffPath…`, 39 `const (`, 40 running, 41 cluster) |
| Design's verdict "claimed 48–51 is stale, cosmetic; tests reference symbols, never lines" | Correct reasoning — no other design section cites these line numbers |

### Correction 2 — `TestAdminPathConstsMatchRootOwnedConstants` naming ✅

- Worktree: untracked `cmd/sso-operator/controller/adminpaths_parity_test.go:17` holds exactly that name; its body asserts `runningConfigPath == core.PathAPIPrefix+core.PathAdminConfigRunning` (and cluster-diff twin) — matches design E11, §3.3, §5, §6 step 1, §7 cases 6/8.
- Design correctly separates it from `TestConfigAudit_OperatorPaths_GateAwareTruthiness` (`interfaces/sso/config_audit_test.go:88`, worktree-modified) and even cites the `fghrAssertIdentical` byte-identity helper (verified: `feature_gate_hotreload_test.go:46`, same package, used at `config_audit_test.go:119–120`).
- The stale `root_consts_parity_test.go` header self-reference the design plans to fix is real (parity file line 2).

### Correction 3 — R1 relative path fixed to `../../../docs/openapi.yaml` ✅

- Verified: `ls cmd/sso-operator/controller/../../../docs/openapi.yaml` resolves; `../../docs/openapi.yaml` fails (would be `cmd/docs/…`).
- Design carries the fix everywhere it matters: E15 verdict row, §3.4 (corrected path + CWD rationale + CRD-parity precedent), a dedicated §5 failure-mode row ("spec's wrong `../../…` path accidentally implemented — prevented by design"), and §7 case 1 uses the corrected path.

### Acceptance criteria coverage (spec §5, 8 cases → design §7)

All 8 cases map to named tests with explicit assertion mechanics: cases 1–5 → net-new `TestAdminPathsMatchOpenAPIDocumentation` (presence / method-fidelity / operator-const equality / doc-vs-root-consts equality / file-missing `t.Fatalf`), case 6 → parity test unchanged, case 7 → root-suite three-phase R3, case 8 → whole `./...` suite. Gate boundaries match (operator cases under `Makefile:263` `ci-modules`; case 7 under root suite). The "graded 9/9 machine-checked" characterization is preserved.

### §3/§6/§7 consistency with spec

- **§3**: no production API matches spec non-goals; yaml.v3 v3.0.1 indirect→direct is verified (go.mod:58; `sigs.k8s.io/yaml v1.6.0` stays indirect at :66; no `go.work` anywhere); test names match spec R1/R2/R3; openapi anchors verified (running `get` 200/401/501 at 5340–5370; cluster-diff `post` 200/400/401/501 at 5607–5655). The only deliberate delta — the corrected path — is explicitly documented as E15, not silently contradicted.
- **§6**: 6 ordered steps match spec §7 file surface (single file + comment fix), §8 additive rollback, and §10 command sequence.
- **§7**: consistent with spec §5; the spec's "contains exactly the two keys" is disambiguated as presence-of-the-two-exact-keys (design §3.4/§4: legitimate doc growth never false-positives), which is consistent with the spec's own acceptance cases (only removals fail).

### Minor findings (non-blocking, no plan impact)

1. **Design §1 E12 parenthetical undercount**: "10 package-wide" is wrong — `ssoconfigdrift_truthiness_test.go` holds **6** `TestReconcile_*` (lines 97, 151, 182, 211, 232, 263), so the package-wide count is **14** (8+6), not 10. The two named functions are real and in that file, and the core claim "8 in `ssoconfigdrift_controller_test.go`" is exact. No acceptance assertion or plan depends on the count (case 8 runs the whole suite), but the number should be corrected if the design is revised.
2. E1's "~8 lines stale" is technically 9 lines (48−39); labeled approximate, and the corrected numbers are exact — cosmetic.

**Bottom line:** the three evidence corrections are fully and accurately incorporated (correction 2 is the strongest — the design never conflates the two test legs and even names the correct byte-identity helper), all 8 acceptance cases are covered with named tests, and there is no contradiction between the spec and the design's §3/§6/§7 — the spec's two stale claims (lines 48–51, `../../docs/openapi.yaml`) are precisely the ones the design corrects explicitly rather than silently. The only defect worth a one-line fix is the E12 "10 package-wide" count.
