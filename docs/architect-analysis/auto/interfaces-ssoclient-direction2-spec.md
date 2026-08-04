# Requirements Specification: `interfaces/ssoclient` Direction 2 — Unify and harden the validation contract

Source: expansion direction 2 of `docs/auto/interfaces-ssoclient-analysis.md`:

> 2. 统一并加固验证契约：ssoclient 门面缺失 iss/aud 强制，弱于其封装的 rs 层

Scope: three additive hardening decisions for the `AuthClient` facade. All are
contract-level fixes inside `interfaces/ssoclient/{remote,local}`; zero server-side
changes and zero changes to the `rs` package. Priority per the analysis: this direction
first (pure hardening, lowest cost, highest risk — a security asymmetry).

## Contract principle

The facade must never be weaker than the layer it wraps or the endpoint it calls:

1. `ssoclient/rs` enforces `iss` (required, exact) + `aud` (when `ExpectedAud` set);
   the `AuthClient` facade it coexists with must enforce at least the same gates.
2. The server's RFC 7009 `/token/revoke` answers definitively (200 on valid
   credentials, regardless of token existence); the facade's `Logout` must never
   silently claim success when no revocation happened.

## Non-goals

- No new token-acquisition surface (that is direction 1, already covered by
  `docs/auto/interfaces-ssoclient-oauth-client-design.md`).
- No changes to `rs` semantics, `rs.Config`, or `rs` errors.
- No changes to `sso-server` routes or handlers.
- No DPoP/mTLS client-auth helpers (direction 1 scope).

---

## Improvement 1: Mandatory issuer pinning in `remote.AuthClient` (`iss` enforcement)

### Name

Require and exactly match the `iss` claim in the remote facade: `WithIssuer` option +
fail-closed `ValidateToken`.

### Problem

`remote.AuthClient.ValidateToken` verifies signature and time only. The `iss` claim is
parsed and then dropped, so in the documented multi-App shared-central-SSO deployment
(`doc.go`: "remote — calls a remote SSO server... when the App is one of many that
share a central SSO deployment") an App accepts any token whose JWS verifies against a
key it can fetch — including tokens minted for another issuer/client. The wrapped `rs`
layer requires the issuer; the facade is strictly weaker.

### Evidence

- `interfaces/ssoclient/remote/auth.go`:
  - `jwtPayload.Iss` (line 74) is decoded by `json.Unmarshal` inside `ValidateToken` and
    never read afterwards; `validateTokenTime` checks only `exp`/`nbf`;
    `subjectFromPayload` maps `Sub`/`Exp`/`Scope`/`Extra`/`Aud` and omits `Iss`.
  - `AuthOption` offers only `WithAuthHTTPClient` and `WithLogoutURL` — no way to
    express an expected issuer.
- Contrast, the layer the facade wraps:
  - `interfaces/ssoclient/rs/rs.go:88-89`: `Issuer` is "REQUIRED: the expected `iss`
    claim, matched exactly".
  - `interfaces/ssoclient/rs/validate.go:26-28`: empty `Config.Issuer` fails with
    `ErrConfig` before any token work.
  - `interfaces/ssoclient/rs/claims.go:162-164`: `if c.Issuer != cfg.Issuer {
    return fmt.Errorf("%w: iss %q", ErrIssuerMismatch, ...) }` — exact match.
- `interfaces/ssoclient/local/auth.go:42-50`: `ValidateToken` also drops the verified
  `claims.Issuer` (`shared/core/types_token.go:44`, `TokenClaims.Issuer`) when mapping
  to `ssoclient.Subject`.

### Proposed behavior

1. Add `WithIssuer(string)` to `remote.AuthOption`; store on `AuthClient`.
2. `remote.ValidateToken` returns a typed error (new exported sentinel, e.g.
   `ErrIssuerRequired` in `interfaces/ssoclient/remote`) when no issuer is configured —
   fail-closed at call time, mirroring `rs/validate.go:26`; the constructor signature
   stays variadic so existing callers compile but fail loudly on first use.
3. After signature + time verification, compare the token's `iss` with the configured
   issuer using exact string match (rs semantics, `claims.go:162`); mismatch returns a
   typed `ErrIssuerMismatch`. Error text must not echo attacker-controlled claim values
   beyond what rs already does (keep rs's `iss %q` shape for parity).
4. Add `Issuer string` to `ssoclient.Subject` (`types.go`), populated by both
   implementations (`remote` from `p.Iss`, `local` from `claims.Issuer`), so the
   verified identity is observable at the facade boundary instead of dropped.
5. Update `remote/auth_test.go` and `remote/auth_multialg_test.go` to configure the
   issuer; update the package doc comment in `remote/auth.go`.

### Acceptance check

- New unit tests in `interfaces/ssoclient/remote`:
  - Token minted by issuer B (valid signature, valid exp/nbf, correct aud) is rejected
    by an `AuthClient` pinned to issuer A with `ErrIssuerMismatch`.
  - `ValidateToken` with no `WithIssuer` returns `ErrIssuerRequired` (never a nil
    error / never a subject).
  - Token with `iss` missing from the payload is rejected.
  - A token from the configured issuer still validates and `Subject.Issuer` equals the
    configured value.
- Existing `auth_multialg_test.go` EdDSA/ES256/RS256/PS256 matrix passes unchanged
  after adding the issuer option to the shared fixture (`signerAndCache`).
- `go build ./... && go vet ./...` and
  `go test -run 'TestMaintainability_|TestArchitecture_' .` pass.

---

## Improvement 2: Audience enforcement in `remote` and `local` (`aud` enforcement)

### Name

`WithExpectedAud` on both `AuthClient` implementations; reject tokens not minted for
this client; remove the documented `clientID=""` example workaround.

### Problem

`aud` is surfaced to the caller but never validated against an expectation in either
implementation: `remote` passes it through (`normalizeAudience` → `Subject.Audience`),
`local` maps `claims.Audience` unchecked. With one shared central SSO, an App can
accept a token minted for a *different* client — a horizontal privilege boundary the
facade was designed to enforce (per-App policy is the documented model in
`client.go`/`AuthzClient`). The embedded example documents the gap by registering under
`clientID=""` to dodge the missing `aud` claim.

### Evidence

- `interfaces/ssoclient/remote/auth.go`: `subjectFromPayload` → `normalizeAudience`
  is pure pass-through; no expectation exists to check against (`AuthOption` list).
- `interfaces/ssoclient/local/auth.go:42-50`: `Audience: append([]string{},
  claims.Audience...)` — copied, never compared.
- `docs/examples/embedded-app/main.go:35-38`: comment admits the dodge — "We register
  under clientID=\"\" because the demo token below has no `aud` claim, and
  appcore.Handler reads aud[0] — so the role MUST be findable under \"\" ... A real
  App would either set aud at issue-time or pass its known client_id explicitly."
- Contrast, the wrapped `rs` layer:
  - `interfaces/ssoclient/rs/rs.go:100-101`: "ExpectedAud, when set, requires the
    token's `aud` to contain it."
  - `interfaces/ssoclient/rs/claims.go:179-181`: `if cfg.ExpectedAud != "" &&
    !c.HasAudience(cfg.ExpectedAud) { return ErrAudienceMismatch }` — enforced in both
    local-JWT (`validateClaims`) and introspection (`rs/introspect.go:124-127`) modes.

### Proposed behavior

1. Add `WithExpectedAud(string)` to `remote.AuthOption` and a matching
   `WithExpectedAud(string)` to `local.Option`; store on both `AuthClient` types.
2. In both `ValidateToken` implementations, when the expectation is set, require the
   token's `aud` (string or array form, via the existing `normalizeAudience` /
   `HasAudience` logic) to contain it exactly; mismatch returns a typed
   `ErrAudienceMismatch` sentinel (exported from the `remote`/`local` package or the
   facade as decided in implementation). Semantics mirror `rs`: empty expectation =
   skip, non-empty = mandatory containment; fail-closed, no oracle text.
3. Fix the example: mint the demo token with `aud` = the app's client ID
   (`defaultimpl` issuer `Issue` with audiences, or the documented equivalent),
   register permissions under a real `appClientID`, and delete the `clientID=""`
   workaround comment. Wire `local.NewAuthClient(issuer, local.WithSessionManager(s),
   local.WithExpectedAud(appClientID))` to prove the gate end-to-end.
4. Update the `AuthClient.ValidateToken` doc in `interfaces/ssoclient/client.go` to
   state that `aud` is enforced when the implementation is configured with an expected
   audience.

### Acceptance check

- New tests, both `remote` and `local`:
  - Token minted for client B (valid signature/time/iss) is rejected by a client
    pinned to `WithExpectedAud("client-A")` with `ErrAudienceMismatch`.
  - Token with `aud` as an array containing the expectation validates; array without
    it and missing `aud` are both rejected when the expectation is set.
  - Unset expectation keeps current behavior (no behavioral regression for callers
    that do not opt in).
- `docs/examples/embedded-app/main.go` builds and runs with a non-empty client ID and
  no `clientID=""` comment (grep for the workaround returns nothing).
- `go build ./... && go vet ./...` and the committed architecture/maintainability
  gates pass; `go test ./... -race` green for the two packages.

---

## Improvement 3: `Logout` revocation contract — no silent no-op, aligned with the server's RFC 7009 semantics

### Name

Make `remote.AuthClient.Logout` fail loudly when revocation cannot happen, and give it
a wire contract that matches the server's `POST /token/revoke`.

### Problem

`remote.Logout` returns `nil` when no logout URL is configured (and when `req == nil`),
so callers believe revocation succeeded when no request was ever sent — the worst kind
of best-effort: silent. The server contract it should mirror is definitive (RFC 7009
§2.2: always 200 on valid credentials, regardless of token existence), and the local
implementation already rejects empty requests (`local/auth.go:64-66`:
"session_id or access_token required") — the two facade implementations disagree on
what a no-op is. The current `remote` wire shape (JSON `{"session_id": ...}` to a
free-form `logoutURL`) also does not match the server's revoke endpoint
(`POST /token/revoke`, form-bound `token`/`token_type_hint` + client auth), so the
"unify" half of this direction is unmet.

### Evidence

- `interfaces/ssoclient/remote/auth.go`:
  - `Logout` first line: `if c.logoutURL == "" || req == nil { return nil }` — silent
    success.
  - `WithLogoutURL` doc: "Without it, Logout silently skips the server round-trip."
  - `Logout` body marshals `map[string]string{"session_id": ...}` as JSON — not the
    RFC 7009 form fields the server binds.
- Server contract:
  - `interfaces/sso/server_routes.go:182`: `s.router.POST(PathRevoke, s.handleRevoke)`.
  - `protocols/oauth/handle_revoke.go` `HandleRevoke`: "the wire response is always
    200 OK with an empty body when the credentials are valid, regardless of whether
    the token existed"; `revokeRequest` binds `token` / `token_type_hint` /
    `client_id` / `client_secret` via `BindParams` with HTTP-Basic precedence.
  - Note `PathLogout` (`server_routes.go:194`) is the OIDC RP-initiated
    end-session endpoint, not a token-revocation endpoint — the current remote
    `logoutURL` wiring conflates the two.
- Facade doc admits the gap: `interfaces/ssoclient/client.go` `Logout` — "Best-effort:
  a success from this call does not guarantee every downstream cache has invalidated"
  (correct for caches, but today even the revocation request itself may never have
  been sent).
- `interfaces/ssoclient/local/auth.go:64-66`: the local implementation already errors
  on empty `req` — evidence of the intra-facade contract split.

### Proposed behavior

1. `remote.Logout` never returns nil-success for an unsatisfiable request:
   - `req == nil` → argument error (mirrors local).
   - `logoutURL == ""` (or no revoke URL configured) with a non-empty request →
     typed exported error `ErrLogoutNotConfigured`; delete the "silently skips"
     behavior and its doc.
2. Add a revocation path that speaks the server's actual contract:
   `WithRevokeURL(url, clientID, clientSecret)` targeting `POST /token/revoke` with
   form-encoded `token` + `token_type_hint=access_token` and HTTP Basic client
   credentials — matching `protocols/oauth/handle_revoke.go` `revokeRequest` and
   `BasicClientCreds` precedence. When configured, `Logout` with an `AccessToken`
   revokes via this endpoint; 2xx = success (server's "always 200" semantics), any
   non-2xx = error. Keep `WithLogoutURL` for the OIDC end-session path, documented as
   session-logout, not token revocation.
3. Document the resulting contract in `client.go` `Logout`: "returns an error if
   revocation could not be performed (not configured, bad request, or transport
   failure); success means the server accepted the revocation."
4. Update `remote/auth_test.go` logout cases that currently rely on the silent-nil
   path to assert the typed error instead.

### Acceptance check

- New `remote` unit tests:
  - `Logout` with `req != nil` and no URLs configured returns `ErrLogoutNotConfigured`
    (never `nil`).
  - `Logout(ctx, nil)` returns an argument error.
  - With `WithRevokeURL`: `Logout` sends a POST to the revoke URL with
    `token`/`token_type_hint` form fields and Basic auth; a 200 response yields nil,
    a 401/400/5xx yields an error.
  - No test or caller in `interfaces/ssoclient/` and `docs/examples/embedded-app`
    depends on the silent-nil behavior (grep for the removed comment/behavior).
- `local.Logout` behavior unchanged (already loud); both implementations now agree on
  the no-op contract.
- `go build ./... && go vet ./...` and the committed gates pass.

---

## Cross-cutting notes

- Contract updates land in the same change per AGENTS.md §5.6: `remote`/`local` error
  sentinels are documented in `docs/error-codes.md` only if they surface on a wire
  endpoint (they do not — they are SDK-side), so the doc impact is limited to the
  package docs and `docs/examples/embedded-app`.
- Budgets: `remote/auth.go` grows by ~50-60 lines (still well under the 500-line file
  limit); no new top-level packages, no `interfaces/sso` file additions (its 60-file
  ceiling is untouched), no new upward imports.
- Ordering: Improvement 1 and 2 are independent of each other and of Improvement 3;
  all three are pure facade changes with zero server-side or `rs`-side impact, so they
  can land as one change or three sequential changes, each green on `make ci`.
