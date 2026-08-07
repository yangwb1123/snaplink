All verification complete. Here is my independent assessment:

## Verification of each blocking finding

**Design-correction reviewer's 7 blockers** (previously FAIL):

| Blocker | Status | Evidence (verified at HEAD `2e1d4e4e`) |
|---|---|---|
| Split-first plan → nonexistent `build_app_trust.go` | **RESOLVED** | Plan now targets existing `options_admin.go` (474 lines ✓) and drops `build_app_trust.go`; wiring hosts in `build_stores.go` (477 lines, `WithMaxScopeCount` at :293 ✓); `build_app_security.go` = 500 lines, untouched ✓; `cmd/sso-server` = 24/24 files ✓ |
| Config host file unnamed | **RESOLVED** | `config/config_oauth2.go` named (243 lines ✓); `config/` = 26/26 ✓ |
| Per-branch effective-scope checks | **RESOLVED** | Step 5 + §2 table; all 8 points verified in code: `token_authcode.go:273` (`info.Scopes`), `token_refresh.go:359-365`, `token_device.go:199`, `token_ciba.go:282`, `token_exchange_stages.go:343`, `token_exchange.go:453`, `token_client_credentials.go:34-38`, `token_jwt_bearer.go:88`/`token_saml2_bearer.go:96` |
| `/token` re-scoping | **RESOLVED** | task-2 §2 jurisdiction statement names unchecked direct mints (`webauthn.go:164`, `kerberos/handler.go:253` — both `GrantedScopes` calls verified) |
| Seam ordering before `denyTokenScopeCombo` | **RESOLVED** | Pin in §2/FM-9/Step 4; code order verified: split `:121-125` → `denyTokenScopeCombo` `:128` → custom grants |
| `extra_scopes` validation | **RESOLVED** | FM-3: bare `"*"`/non-`:*` rejected, boot failure; precedent `billing/config.go:360` exact-enforcement verified |
| A-1b body pin | **PRESENT + verified** | `errorBody` at `handlers.go:399` wraps `ErrorBodyWithTrace` (✓); all 8 branches emit plain `core.ErrorBody(ErrInvalidScope)` (verified in each snippet) |

**OIDC-standard-scope bypass** (wire-compat/security blocker): **RESOLVED** — `task-2-oidc-standard-scopes.md` (273 lines, on disk) specifies Memory pre-seeding of 7 protocol scopes (no seam exemption list), rejects options B/C with concrete break cases, and the discovery claim is corrected and verified: `computeDiscoverySnapshot` (:135) → `projectClientFields` (:182) → `ScopesSupported` emission (`server_discovery_config.go:339`, `server_resource.go:195`), plus the webauthn bridge (`webauthn.go:164,192,315-318,336` all verified).

**8-step migration / 9 failure modes**: **RESOLVED** — fully specified with per-step gates, rollback criteria, byte-compat statements, and per-FM mitigations+pins. SAML2 mapping caveat stated (custom-grant dispatch verified at `server_setup.go:271`).

**Revision actually happened**: `task-1-design.md` diff vs HEAD = +319/-10 lines (the previously-committed version contained the flawed `build_app_trust.go` plan; the working-tree version does not). All other citations re-verified against current HEAD: matrix constants (commerce `consts.go:24-27`, metering `consts.go:12-13`, billing `config.go:22`, `admin:*` at `middleware.go:31`), wildcard semantics (`matcher.go:17-29`, `evaluate.go:203`), bypass constants (`consts_wire.go:241,246`, `scope.go` rules 2-4), single `/token` route (:180), login-only scope cap (`server_login_gates.go:318`), and the `anything`/`api:read` regression fixtures. No `.go` files touched by the design run — docs-only, per the worktree status.

VERDICT: PASS - every blocking finding (split-target defect, config host, per-branch checks, /token re-scoping, seam ordering, extra_scopes validation, OIDC-scope mechanism, migration/failure-mode specification) is resolved in the revised artifacts with code citations I re-verified against current HEAD, and the A-1b byte-compat anchor plus default-unwired regression guarantee are preserved.
