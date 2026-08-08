All verification complete. Full report:

# C1 Refactor Plan Verification — PASS with 4 doc corrections

## 1. Function budgets: every planned function ≤50 lines / cyclo ≤15 / nesting ≤3 — **CONFIRMED by construction**

I applied the refactor exactly as §2.2/§2.3/§2.4/§2.5 specifies to a scratch copy of the real package and measured with the gate's own algorithm (`maintainability_complexity_test.go`: line span func-keyword→closing-brace; cyclo with nested literals):

| Function | lines | cyclo | Function | lines | cyclo |
|---|---|---|---|---|---|
| `parseCheckFlags` | 33 | 6 | `verifyJWTClaims` | 23 | 7 |
| `CheckRun` (post) | 43 | 11 | `verifyIssuerClaims` | 11 | 4 |
| `runT8a` (+variance wiring) | 41 | 11 | `verifyDeclaredClaims` | 27 | 9 |
| `mintBody` | 14 | 3 | `verifyTenantClaim` | 18 | 5 |
| `mintPost` | 16 | 4 | `verifyRolesClaim` | 7 | 2 |
| `mintWithHost` | 34 | 8 | `revokeToken` | 21 | 5 |
| `mint` | 7 | 2 | `revoke` | 31 | 8 |
| `verifyClaims` | 7 | 1 | `hostVarianceProbe` / `variancePreflight` | 23 / 17 | 7 / 4 |

Max if-nesting in all new code: 2. The patched copy `go build`+`go vet` clean. Current red state re-confirmed: `CheckRun` 66, `verifyClaims` 58/19 — the split is load-bearing, exactly as C1 says.

## 2. File budgets — **CONFIRMED, with one estimate correction**

Measured on the real patched files: check.go 306, token.go **498**, sweep.go 372, apiclient.go 205. All ≤500; non-test files/dir = 4 (no new files); no new subdirs.

**Correction 1 (material): token.go lands at 498, not the design's ~445** — comment overhead for 7 new functions + preserved doc comments adds ~50 lines over the design's body-only estimate. Still under budget, but headroom is 2 lines. **Correction 2 (material): §7's file table lists `hostVarianceProbe` under token.go, contradicting §3/§2.5 (sweep.go).** Following §7 literally yields token.go ≈570 — over budget. The §3 placement (`mintPost`+`hostVarianceProbe`+`variancePreflight` in sweep.go, 284+~88) is mandatory and verified: sweep.go 372, token.go 498. Fix §7 before implementation.

## 3. Diagnostic row-emission order — **CONFIRMED; pinned signatures survive**

Traced end-to-end through the actual `runT8a` flow on the `hostDerivedIssuer` fixture: mint-1 silent (lockstep: `iss1 == doc.Issuer == --expect-issuer`), `verifyClaims` silent, then the variance leg emits **differs → discovery → declared** in exactly the §2.6 order; both revoke legs silent → stderr == the pinned 3-row signature verbatim; stdout `discovery: OK\nmint: FAIL\ninvalid_scope: OK\nintrospect: OK\ncheck FAIL\n`, exit 1. `verifyIssuerClaims` preserves discovery-then-declared fixed order (no short-circuit), and `TestExpectIssuer_Mismatch`'s count==2 pin is robust (mint-1 R1 row + variance row 4; partial implementations yield 1). Supporting facts re-verified: 401-collapse oracle (`server_token_clientauth.go:140/147/196/211/215/260`, wrong secret → `rejectTokenClientAuth`), cc-path ctx threading (`token_client_credentials.go:50`), `Validate` never checks `iss` (`ed25519_validate.go`), `WithEd25519Issuer/Key/KeyID` + `WithTokenIssuer(name, TokenIssuer)` + JWKS via `ti.(core.JWKSProvider)` all exist, request-base discovery derivation (`server_discovery_config.go:62/144/264`).

**Correction 3 (minor):** the split moves the iss rows after jti (was: before sub/client_id/jti). No existing test is order-sensitive (all `Contains`; single-fault mutations), and §2.6's exact-equality pin only sees variance rows — so §3's "stderr text byte-identical" holds for every test but is a slight overstatement for multi-fault runs. **Correction 4 (minor):** §2.5's `claims: host-variance mint:` prefix vs §2.3's `mintWithHost` returning `mint: ...` diags is unspecified; my draft resolves via prefix-remap in `hostVarianceProbe` (no acceptance row pins the prefix — cosmetic, but state it).

## 4. E11 fixture fix — **VERIFIED FEASIBLE, proven by temporary application**

Applied both fixes to check_test.go in the worktree (backup → patch → test → byte-exact restore, `cmp` confirmed):

- **R5** (`WithEd25519Issuer(addr)` in `newLiveServer`): all six iss-misalignment rows flip green — `TestSweep_GreenPath`, `TestStdoutDeterministic`, `TestMint_ClaimsMatrix`, `TestMint_ScopeContainsRequested`, `TestMint_AudContainsResource`, `TestRevoke_RoundTrip` — PASS.
- **Suffix fix** (advertise `/oauth2/tokenz` + updated expected diagnostic): `TestSweep_TokenEndpointSuffix` — PASS. Confirmed the current failure is exactly E11's shape (404-first; `/oauth2/token` satisfies the suffix predicate so the diagnostic can never fire).

Current red state matches E11: 11 failures = 6 iss rows + 4 tracked out-of-scope + the suffix row. No worktree changes remain.

**Verdict:** the C1 refactor is verifiably budget-correct, the pinned stderr signatures survive, and both fixture fixes work. Fix §7's file placement and the ~445→~498 token.go estimate before implementation; keep comment density in check (token.go has 2 lines of headroom).
