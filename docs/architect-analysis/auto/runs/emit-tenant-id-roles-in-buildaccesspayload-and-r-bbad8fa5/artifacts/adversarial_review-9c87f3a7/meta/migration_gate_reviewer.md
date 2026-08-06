Verification complete. All anchors were checked against the tree. Here is the independent validation report.

---

## Validation verdict

**The 6-step ordering is NOT independently `make ci`-green as written.** Two blockers found (steps 2 and 3); the `500/500` and `60-file` headline numbers are real. Full detail below.

### 1. `token_exchange_stages.go` net-zero claim — line count CONFIRMED (500), arithmetic NOT sound

- **Count**: `wc -l` = 500, exactly. `token_exchange.go` = 495, `consts_wire.go` = 500, `options_security.go` = 500. The maintainability gate is real: `maintainability_budget_test.go:34` `maxFileLines = 500`, `fileSizeExemptions` frozen **empty**, `_test.go` excluded. 501 lines ⇒ `make ci` fails.
- **Off-by-one**: the design says the `roles []string` field is "added in `token_exchange.go` (495→496)" — but `type tokExState` lives at **`token_exchange_stages.go:36`**, not in `token_exchange.go`. Adding the field costs +1 in the 500-line file. The documented arithmetic (+1 `roles := d.Roles(...)`, 0 for the `ID:`-line merge, −1 comment compression) reclaims only the roles line. **Net = +1 → 501.**
- **Second defect**: the design's own placement claim is unimplementable — "at the `tokExState{...}` construction (`token_exchange.go:130`)" cannot work because the pinned lookup key `localSub` (design §1.1) is not resolved until `token_exchange_stages.go:365-366`, and `st.claims` isn't even populated at :130.
- **The outcome IS achievable** — via the variant the design doesn't document: `roles := d.Roles(...)` as a local (+1), threaded through `tokExSubject`'s signature line (:393) and call site (:373) as same-line edits (0), `Roles: roles,` merged onto the `ID:` line (0), and the 6-line pairwise comment block (:360-365) compressed 6→5 (−1) ⇒ stages stays exactly 500 and `token_exchange.go` is untouched (495, not 496). So "net-zero by construction" (§7) is wrong for the documented mechanism but salvageable; the doc must be corrected before the design gate.

### 2. Step-3 independence — BROKEN: 6 un-re-pointed tests pin the flipped surfaces

The design re-points only the trusted-proxy trio (§5 step 3, §6 A3-6), but `resolveIssuer`'s flip to the sentinel breaks these SDK-default tests (no `WithIssuer`), all on surfaces the design itself lists in §3.2 "Flips":

| Test | Anchor | Flipped surface |
|---|---|---|
| `TestRFC9207_CodeFlowResponseCarriesIss` | `test/iss_response_test.go:63-64` | RFC 9207 login-response `iss` == `httpSrv.URL` |
| `TestRFC9207_DirectMintResponseCarriesIss` | `:90-91` | same |
| `TestRFC9207_ErrorResponseCarriesIss` | `:122-123` | same |
| `TestRFC9207_ProviderListResponseCarriesIss` | `:223` | same |
| `TestIntrospectionJWT_SignedResponseWhenRequested` | `test/introspection_jwt_test.go:132-133` | RFC 9701 introspection-JWT `iss` == `srv.URL` (comment there: "iss comes from s.resolveIssuer(ctx) — the request's own base URL") |
| `TestRcov_DirectMintLogin` | `interfaces/sso/rootcov_flow_test.go:235-236` | RFC 9207 `iss` == `s.http.URL` (rcov harness opts :64-76 have no `WithIssuer`) |

The rest of the suite is genuinely safe (verified): `oidc_test.go:127`, `frontend_contract_test.go:280`, `oidc_integration_test.go:194`, `oidc_discovery_test.go:83`, federation/SSF e2e all use `WithIssuer`; `backchannel_logout_test.go:215` sources `iss` from the signer (`WithEd25519Issuer("https://sso.test")` at :95), not the resolver; `prompt/me/form_post/scope_authorization/region_residency` checks are presence-only; `TestRFC9207_DiscoveryIssAndResponseIssAgree` is internal consistency (both sides flip together). Fix is mechanical (re-point the six like the trio, or add `WithIssuer` where the test's purpose isn't default-state semantics) — but it's absent from the migration.

### 3. `sso.go`/`config_load.go` fallbacks — CONFIRMED with one nuance

- `sso.go` = 499 (gate-verified), `recordFeatureGateStartup()` at :105; the +1 `applyIssuerAllowlistGate()` call lands exactly 500 — at ceiling, not over. **No extraction fallback is documented for `sso.go`** (none is needed; 500 ≤ 500).
- `config_load.go` = 498; `DefaultServerIssuer` at :60; sentinel rejection at :183-185 (design cites :183-184 — the `if` is :183). +2 lines → exactly 500. The extraction fallback is sound: the block + comment (:176-185 = 7 comment + 3 code lines) moved into a `config.go` helper (236 lines, ample room) with a 1-line call ≈ −7 net → ~493. Verified plausible.
- Note: `config/config_load.go` already carries pre-existing unrelated worktree modifications — the 498 count reflects the current worktree, which is what gates measure.

### 4. `interfaces/sso` 60-file ceiling — CONFIRMED

`ls interfaces/sso/*.go | grep -cv _test` = **60**, exactly. Design adds no new files (§8); the ceiling is an AGENTS.md contract (the maintainability gate enforces per-file lines, not directory counts). Compliant.

### 5. Acceptance tests — falsifiable and executable, but "16" is wrong and executability is conditioned on steps 2-3

- **Count**: §6 actually names **23 test functions** (A1: 4, A3: 8 incl. the trio, A4 ID-token: 3, supporting: 8; A2 rides A1). The evidence's "16" is not reproducible from the design — an undercount, not a defect of the design itself.
- **Falsifiable**: yes — concrete expected values throughout (`tenant_id=="t1"`, `roles==["r1","r2"]`, `ext=={"ok":"v"}`, byte-identical 500 across Hosts, panic-vs-no-panic by option order, `serving_region` still echoed, etc.).
- **Executable**: all 12 cited test files exist; patterns verified (`TestRcov_ClientCredentialsGrant` at `rootcov_flow_test.go:514`, `fixedClock` at `ed25519_jwt_issuer_test.go:171-176`, `TestConfigRejectsSDKSentinel` at `cmd/sso-server/issuer_test.go:38`, trio at `trusted_proxy_gate_test.go:267-311`). Each test lands in the step that ships its machinery. Two caveats: (a) `TestRcov_TenantIDRoles_ClientCredentialsAndRefresh` requires wiring a permissions provider into `rcovNewServer` (its current opts have none; `(*Server).Roles` fails open to nil) — the spec says "seeded client with TenantID+roles", so executable but the harness change must be part of the step; (b) the byte-identity tests' nil-vs-`[]string{}` distinction is not observable — `encoding/json` `omitempty` drops both — so the tests are valid byte-identity regressions but not discriminating (the design's "both cases" framing is sound).
- **Doc-only status**: confirmed for this run (the run's artifacts are `.md` only; the worktree's other `.go` diffs are pre-existing unrelated changes). The acceptance tests are future-work specifications — correctly not executable in this run — but the claim that the migration is step-green, which the mapping presupposes, fails at steps 2 and 3 as written.

### Bottom line

Confirmed: 500/500 count, `sso.go` 499→500, `config_load.go` 498→500 + sound −7 extraction fallback, 60-file ceiling, and all §6 test files/patterns/falsifiable assertions. **Rejected as written**: the exchange net-zero arithmetic (off-by-one struct-field attribution + unimplementable :130 placement; use the param variant or compress the comment block by 2 lines) and step-3 independence (6 un-re-pointed SDK-default tests: 4× `iss_response_test.go`, 1× `introspection_jwt_test.go:132`, 1× `rootcov_flow_test.go:235`). Both fixes are small, but the design document must be amended — and step 2/step 3 re-validated — before the migration order can be called independently `make ci`-green.
