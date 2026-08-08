Done. Requirements specification produced, evidence-verified, and committed (`ad4f12f4`, 2 files only; the 980 pre-existing worktree changes were left untouched).

## Deliverables

- **Pipeline artifact**: `docs/architect-analysis/auto/runs/replace-guaranteed-fail-expect-roles-with-a-cond-cbe204e6/artifacts/requirements-10762e10/requirements.md`
- **Repo-visible mirror**: `docs/architect-analysis/auto/cmd-sso-ctl-apiclient-expect-roles-conditional-requirements.md` (byte-identical; matches the module's doc placement precedent and the sibling campaign's mirror convention)

## Evidence verification (all citations confirmed)

| Citation | Verdict |
|---|---|
| `check.go:78` bool `--expect-roles` + usage at 169 | Verified |
| `token.go:225-229` roles branch, "flag is a declaration, not a guess" | Verified |
| `check_test.go:921` `TestMint_RolesExpectationFailsOnCC` (live-cc exit 1) | Verified (func at exactly 921) |
| `token_client_credentials.go:50-58` Subject without Roles/Claims | Verified (structural, unchanged) |
| `issue_payload.go:83-88` `applyOptionalClaims` non-empty guard | Verified, plus `ed25519_types.go:57` wire shape |
| `goldenGreenStdout` (check_test.go:32) | Verified, byte-asserted by 4 green-path tests |

## Spec contents

- **Acceptance preserved verbatim** and mapped to REQ-1–REQ-6, all with testable criteria: `--expect-roles` → declared-set assertion via the package's existing `stringList` (absent/empty tolerated; set-equality on present roles, order-insensitive; malformed non-array → fail); `--expect-no-roles` cc pin (always passes on a live server); mutual exclusion → exit 2; `goldenGreenStdout` byte-identity; defaultimpl `TestTenantRoles_ClaimsPerIssuer` stays the server-side pin; usage-text update.
- **Landmine removal codified**: the replaced test matrix inverts `live-cc-fails` (live cc + `--expect-roles admin` → exit 0) and keeps the stub-with-roles green subtest; the existing `expect-roles-without-creds` misuse row stays green via the flag package's argument error.
- **Constraint surfaced**: `verifyClaims` is already 55 lines (over budget) — the spec mandates extracting the roles assertion into a helper.
- **Baseline reported separately**: the module's 11 pre-existing test failures (untracked WIP + `interfaces/sso` drift) are documented in §1.8 and excluded from the new work, per AGENTS.md.

No `.go` files were touched, so no build gates were triggered; the verification plan (`go build/vet`, maintainability/architecture gates, `-race`, `TestTenantRoles`, `make ci`) is in §6.
