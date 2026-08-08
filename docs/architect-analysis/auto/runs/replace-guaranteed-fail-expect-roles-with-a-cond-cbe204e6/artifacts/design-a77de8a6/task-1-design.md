Evidence verified; design produced. Summary:

## Verification verdicts (evidence treated as untrusted)

**All load-bearing claims confirmed** against the working tree:
- Commit `ad4f12f4` — exactly 2 files, 808 insertions, docs-only ✓
- `check.go:78` bool flag, usage at 169, wiring at 117; `sweep.go:60` `expectRoles bool` ✓
- `token.go:225-229` roles branch; `verifyClaims` = 175-229 (55 lines, over budget) ✓
- `check_test.go:921` `TestMint_RolesExpectationFailsOnCC`; `goldenGreenStdout` at :32 (asserted at 433/453/475/534) ✓
- Server side: `token_client_credentials.go:50-58` Roles-less Subject; `issue_payload.go:83-88` non-empty guard; `ed25519_types.go:57` wire shape; `TestTenantRoles_ClaimsPerIssuer` at tenant_roles_test.go:77 ✓
- 11 pre-existing module failures — exactly 11, names match spec §1.8 ✓; `go build ./cmd/sso-ctl/...` passes ✓
- B4-1 scope guard (line 41) and design-doc row 16 (line 365) ✓

**Discrepancies found (non-load-bearing but real):**
1. **Artifact/mirror "byte-identical" is false in the current tree.** The pair *was* identical at `ad4f12f4` (verified by diffing the blobs), but stage commit `fdf2d9fd` overwrote the pipeline artifact with a 26-line summary; the 404-line spec now lives only in the mirror.
2. Minor citation drift: `TestClaimsMatrix_FailureDiagnostics` starts at :993, not :1008 (substantive claim — no roles row — verified true).
3. "980 pre-existing" ≈ 982 current status entries minus the campaign's own ~5 files.

## Design delivered

`docs/architect-analysis/auto/runs/replace-guaranteed-fail-expect-roles-with-a-cond-cbe204e6/artifacts/design-324ba6fc/design.md` (+ byte-identical mirror `docs/architect-analysis/auto/cmd-sso-ctl-apiclient-expect-roles-conditional-design.md`), containing:

- **API changes** — `--expect-roles` bool→`stringList` value flag (conditional set-equality, absence tolerated, `""` = empty set); new `--expect-no-roles` bool; mutual exclusion → exit 2; bare flag → exit 2; extracted `verifyRolesClaims` helper (mandatory — `verifyClaims` is at 55 lines); 4-file edit list with exact locations
- **Compatibility constraints** — server/wire frozen; 0/1/2 exit contract and `goldenGreenStdout` byte-identity preserved; deliberate breaking change at the same flag name (no deprecation window possible); B4-1 divergence documented
- **Failure modes** — 11-row truth table (F1-F11), including the **residual gap F10**: absence-tolerance means `--expect-roles` cannot detect total loss of roles emission on user paths — the defaultimpl unit pin is the real regression guard, and spec §1.2's claim is only true for value mismatches
- **Migration steps** — fields → helper → flags/usage → tests → deploy-tree callers (loud exit-2 break, no script changes in this direction) → gates
- **Acceptance mapping** — A1-A5 verbatim → REQ-1..6 → criteria → `-run` filtered test commands, plus a grep-based check that no test still asserts the codified exit-1 landmine

No `.go` files touched; the baseline 11 failures are reported separately per AGENTS.md.
