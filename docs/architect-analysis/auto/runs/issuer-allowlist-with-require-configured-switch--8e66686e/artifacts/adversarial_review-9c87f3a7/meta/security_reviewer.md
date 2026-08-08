Audit complete. Report: `docs/architect-analysis/auto/runs/issuer-allowlist-eliminate-the-host-derived-fall-bbdb82eb/artifacts/entry-set-oracle-audit-60ae4d69/entry-set-oracle-audit.md`

## Part A — Entry-set re-proof: `{handleLogin, handleMFAComplete}` CONFIRMED exhaustively

Method: full route census (70+ handlers) → emission-primitive inventory → transitive caller closure → four-path audit.

- **All 4 `wrapAuthorizationResponse` callers** (`server_login.go:241` via `preAuthLoginGates`; `server_mfa.go:382` via `resumeLoginAfterMFA`; `server_mfa_trust.go:181,230` via `resumeLoginTransaction`/`resumeFederatedLoginTransaction`) trace to exactly those two handlers. **All 3 `finishLogin` callers** likewise. All 20 `authzErrorBody`-using files are login-subtree helpers/accessors (signup has comment-only mentions). All 8 RFC 9207 sites verified at the cited lines.
- **Token-exchange**: no `resolveIssuer` anywhere in `tokengrant/`; response maps (`token_exchange.go:154`, refresh, id-token branches) carry no `iss`; JWT `iss` is signer-derived. One nuance: the Native SSO device-secret sub-exchange DOES put `KeyIss: resolveIssuer` in the token response body (`server_native_sso.go:225`) — but it's inside `handleToken`, so G4 covers it at runtime.
- **Device**: zero issuer emission anywhere (`respondDeviceCode` fields verified; redemption is a G4-covered `/token` grant; `verification_uri` is Host-derived but not an issuer).
- **Session-resume (prompt=none)**: *does* emit issuers (success body `KeyIss` at `handle_silent_renewal.go:369` + `AuthzErrorBody` errors) — but the whole subtree is reachable only from `handleLogin:46` → G2 covers it.
- **Cookie continuation**: `login_transaction_id`'s sole consumer is `handleLoginContinuationOrPromptNone` inside `handleLogin`; federated callback + SAML ACS both end in a 302 back to `/auth/login`.

## Part B — Oracle-safety: CONFIRMED, plus one material finding (F1)

- **Unconfigured vs misconfigured**: every misconfigured variant (empty allowlist, issuer ∉ allowlist, normalization mismatch) is boot-fatal — zero wire surface. The only runtime refusal state emits a byte-uniform 503 on all four gates. Indistinguishable by construction.
- **Per-row uniformity**: G1–G4 all fire *before* any row-dependent logic (client auth, DPoP, grant dispatch, store Consume, provider dispatch, MFA challenge consume) — verified at the exact insertion lines. No client/credential/grant/provider/MFA oracle; idempotency replay can't serve a stale 503 (2xx-only cache); gates read only static fields.
- **Envelope**: single new code, plain `errorBody` (no `iss`/`state`/desc; `trace_id` request-scoped like every error); no-store structural on G2/G3/G4 (header-first), G1 matches the `quota.go:205` pattern. §3 rows on gated endpoints are shadowed *uniformly* (strictly stronger than required); non-gated rows (revoke 200, register 401, inactive introspect) unchanged.
- **F1 (material)**: RFC 9701 signed introspection (`protocols/oauth/handle_introspect.go:184`) signs `iss = ResolveIssuer` on a §3-table credential endpoint that **no gate covers and the design's non-goal list omits** — strict-unconfigured mode still serves Host-derived `iss` in a signed artifact, contradicting the §3.1 invariant. Recommend one-line G5 on `handleIntrospect` (before client auth), or at minimum explicit non-goal documentation.
- **F2/F3 (minor)**: "next to the existing issuer field" is wrong — `issuer` is in `protocolState` (`sso_protocol.go:147`, 500 lines, zero headroom); `sso_wiring.go` placement stands. `sso.go` +1 lands exactly at 500 (flag only). **F4**: §4.5/§5 residual lists should enumerate the complete A.5 census (signed introspection, `/branding`, login-UI metadata, SSF config, FCL iframe `iss`, TOTP `otpauth_uri`, native-SSO body `iss`).

No `.go` files were modified; budget numbers and gate lines all re-verified against the worktree.
