Specification written to `docs/auto/interfaces-ssoclient-direction2-spec.md`. All evidence was verified against the code before writing — here's the summary:

## Deliverable: `docs/auto/interfaces-ssoclient-direction2-spec.md`

**Contract principle**: the `AuthClient` facade must never be weaker than the `rs` layer it wraps or the server endpoint it calls.

### ## Improvement 1: Mandatory issuer pinning in `remote.AuthClient`
- **Problem**: `iss` is parsed and dropped — `remote.ValidateToken` verifies only signature + exp/nbf, so a multi-App central-SSO deployment accepts tokens minted for other clients.
- **Evidence**: `remote/auth.go` `jwtPayload.Iss:74` never read; `AuthOption` has no issuer option; vs. `rs/rs.go:88-89` (Issuer REQUIRED), `rs/claims.go:162-164` (exact match), `rs/validate.go:26-28` (fail-closed).
- **Proposed**: `WithIssuer` option + `ErrIssuerRequired` fail-closed gate + exact-match `ErrIssuerMismatch`; surface `Subject.Issuer` in both implementations (`local` drops `TokenClaims.Issuer` today).
- **Acceptance**: cross-issuer rejection tests; existing multi-alg matrix passes with the option wired.

### ## Improvement 2: Audience enforcement in `remote` and `local`
- **Problem**: `aud` passes through to `Subject.Audience` unchecked in both implementations — a horizontal privilege boundary across Apps.
- **Evidence**: `remote/auth.go` `normalizeAudience` pass-through; `local/auth.go:42-50` unchecked copy; `docs/examples/embedded-app/main.go:35-38` admits the gap with its `clientID=""` workaround; vs. `rs/claims.go:179-181` + `rs/introspect.go:124-127` `ExpectedAud` gate.
- **Proposed**: `WithExpectedAud` on both implementations with rs-mirroring semantics (empty = skip, set = mandatory containment, `ErrAudienceMismatch`); fix the example to mint `aud` and delete the workaround.
- **Acceptance**: cross-client token rejection tests (string and array `aud` forms); example builds with a real client ID.

### ## Improvement 3: `Logout` revocation contract
- **Problem**: `remote.Logout`'s first line `if c.logoutURL == "" || req == nil { return nil }` silently claims success when no request was sent, while the server's RFC 7009 endpoint (`protocols/oauth/handle_revoke.go`) answers definitively and `local.Logout` already errors on empty requests — the two facade implementations disagree.
- **Evidence**: `remote/auth.go` Logout + `WithLogoutURL` doc ("silently skips"); `server_routes.go:182` `POST PathRevoke`; `handle_revoke.go` "always 200 OK ... regardless of whether the token existed"; `local/auth.go:64-66`.
- **Proposed**: `ErrLogoutNotConfigured` + argument error instead of nil; new `WithRevokeURL(url, clientID, clientSecret)` speaking the server's actual form-bound `token`/`token_type_hint` + Basic-auth contract (keeping `WithLogoutURL` for the OIDC end-session path).
- **Acceptance**: loud-failure unit tests; no caller depends on silent nil; both implementations agree on the no-op contract.

The spec also includes non-goals (direction 1's token-acquisition scope excluded), budget checks (no new packages, `interfaces/sso` 60-file ceiling untouched), and a landing order. No code was modified — this is spec-only, per the request.
