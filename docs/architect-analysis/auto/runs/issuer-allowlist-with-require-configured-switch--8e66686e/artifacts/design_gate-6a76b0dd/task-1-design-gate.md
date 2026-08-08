All independent checks are complete. Here is my verification summary.

## Verified resolved (against HEAD `0561d529` + worktree)

| Finding | Resolution in `task-1-design.md` / reconciliation | Verified |
|---|---|---|
| C1 — `handleMFAComplete` is a second authorization entry | G3 at `server_mfa.go` (+ A9a); entry set `{handleLogin, handleMFAComplete}` confirmed by security-reviewer census | Route `server_routes.go:176` ✓ |
| C2 — deploy configs already carry `issuer_allowlist` | A15a + §1.15/§4.3; key present in all 3 deploy configs (verified) | ✓ |
| C3/C4 — gate ordering, no-store | G1 before body-cache lookup; header-first no-store on G2–G4 | ✓ |
| Budget arithmetic (deployment F1 / acceptance) | R2-4 relocation: `issuerStrictnessOptions` in `config_server.go` (195→~223), logic in `shared/core/consts_oauth.go`, `sso_wiring.go` ~481, `config_load.go` 497–499; all file counts re-measured and match (456/499/498/195/188/340/483/487/488/487/495/436/441) | ✓ |
| A12 (deployment F2) | A7: `iss == "https://sso.test/"`, comparison-only normalization | ✓ |
| Sibling conflict + landing order (F3) | R1 point-in-time re-scope, R3 phase chain, A6 migration caveat in §6 | ✓ |
| Entry validity (F4) | R4 L1-L2: `core.ValidateIssuerConfig` + `IsAbsoluteIssuerURL` at boot, `[sso-server]` hole closed | ✓ |

## Verified NOT resolved (blocking)

**1. `NewServer` function-gate failure (implementation-budget reviewer flag #1).** I measured `NewServer` at `sso.go:58-107` = exactly 50 lines; the gate `TestMaintainability_FunctionLength` fails at `> 50` (`maintainability_complexity_test.go:43`). The design §3.2 adds `s.validateIssuerConfig()` **inside** `NewServer` → 51 lines → the committed gate fails. Both the design §8 and reconciliation R2-4 only check the *file* gate ("499+1=500 exactly — passes"); neither states the required −1-line absorption. The same unchecked arithmetic affects `ServerOptions` (currently exactly 50 lines, `config_load.go:301-350`): the reconciliation's "+1 → 499" form trips the function gate at 51, while the design §3.1's collapse form (49 lines) passes — the trap the budget reviewer demanded be stated explicitly is not stated.

**2. Signed-introspection issuer leak (security-reviewer F1, acceptance A17) and federation entity-config (protocol-reviewer F1, A18) are deferred, not resolved or rejected.** Verified: `protocols/oauth/handle_introspect.go:184` signs `iss = d.ResolveIssuer(ctx)` — a Host-derived issuer in an RFC 9701 signed artifact on a credential endpoint with **no gate covering it** in strict-unconfigured mode, contradicting the design's own invariant; `server_federation.go:387` is the same un-gated projection. The design contains zero mentions of G5/A17/A18, and §4 constraint 5's residual list still carries only the old 8-item list — the security reviewer's F4 census enumeration (`/branding`, SSF config, FCL iframe `iss`, TOTP `otpauth_uri`, native-SSO body `iss`) was never applied. Reconciliation §5 explicitly says "decide at implementation" — a deferral, not a resolution or an evidence-based rejection.

All other items (Retry-After, A15a fixture-scoping, test-mock compile note, pre-existing `ed25519_jwt_issuer.go` 539-line failure) are carried/optional or reported separately and do not block.

VERDICT: FAIL - `NewServer` gains one call inside its exactly-50-line body (sso.go 58-107) tripping the committed function-length gate with no −1 absorption planned, and the material issuer-pinning gaps (RFC 9701 signed introspection at handle_introspect.go:184 and federation entity config at server_federation.go:387) remain deferred "decide at implementation" with the residual census never enumerated in §4 — neither resolved nor rejected with evidence.
