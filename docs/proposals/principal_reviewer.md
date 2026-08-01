Principal review written to `docs/principal-review-mfa-subsystem-gaps.md`. Summary:

## Advisory recommendation: **Conditionally ready** (high evidence confidence)

All three findings survive independent re-verification — I re-read the load-bearing code myself, not just the supplied reports: the four mutation handlers gate on `MeSubjectOrChallenge` only (`mfa.go:40/107/159`, `security.go:149`) while `HandleTrustMyDevice` enforces the AMR check (`trusted_devices.go:66`); `mfaLockoutKey` is subject-only vs the client-scoped password leg; the risk path consults `trustedDeviceAllowsSkip` while the CA path issues unconditionally. The condition: implementation with the acceptance tests, docs rows, and AGENTS.md gates — nothing is implemented yet, and `make ci` has not run on any code change.

## Consolidated findings (dedup of 3 reviewers × 3 points)

- **High — F1** (all three agree): step-up gate missing on 4 MFA-mutating endpoints. Adopt the security engineer's refinement: bootstrap exemption only on first-factor commit; `DELETE` and recovery-code regeneration gated unconditionally. Existing enroll-with-plain-token tests pin the vulnerable behavior and must be updated.
- **Medium — F2** (all agree): lockout key → per-(client, subject), keep the namespace prefix, document `mfa_locked`, wire shape unchanged.
- **Medium — F3** (severity disagreement resolved): security-Low vs protocol-Medium is a lens difference, not a factual one — AGENTS.md §1 classifies the doc/code split as drift, so Medium-contract/Low-security, and both lenses prescribe the identical fix (docs + `trusted_device_overridden` marker via the sanctioned `audit.SetMeta`).
- **Info**: bootstrap-window residual (accepted), and one scope gap no reviewer covered — `HandleChangeMyPassword` also lacks step-up but is protected by current-password proof; flagged for a separate maintainer decision, deliberately excluded.

## Notable ledger decisions

- Ledger 3.4: F1's gate depends on `amr` surviving refresh — AGENTS.md contract-backs it, but no test pins it today; ship the P3 positive assertion in the same change set (rollback trigger if it fails).
- Ledger 3.6: keep the existing empty-key guard symmetric for `clientID`.
- No CTO/compliance authority needed — no OIDC/OAuth wire surface changes, no certification posture (none claimed), no regulated-data changes.

**Evidence gaps**: no full-suite/make-ci run at `6c8fb33c` (correct for docs-only), no AMR-across-refresh pin, no CA-override test — all scheduled as preconditions/acceptance checks. Owners are named per ledger entry; no sign-offs fabricated.
