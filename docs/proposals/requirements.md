# Requirements Specification: `interfaces/ssoclient` — App-side token acquisition layer (OAuth Client)

**Scope** (expansion direction 1 from `docs/auto/interfaces-ssoclient-analysis.md`): give `ssoclient` a first-class, server-compatible OAuth client. The server's full grant surface already exists (`/token`, `/par`, `/device`); the client side has zero encapsulation. Three decisions below. All credential calls follow the AGENTS.md wire contracts: `Cache-Control: no-store` + `Pragma: no-cache` on every credential request, HTTP Basic client auth wins over form body, oracle-safe error mapping.

---

## Decision 1: Add a `TokenClient` facade with remote HTTP implementation for `authorization_code` (PKCE S256), `refresh_token`, and `client_credentials`

**Name**: Token acquisition facade — `ssoclient.TokenClient` + `ssoclient/remote` HTTP implementation.

**Problem**: `ssoclient` is verify/authz/audit only. An App embedding the SDK cannot obtain tokens from its own SSO server: it must hand-write the `/token` protocol (form binding, Basic-vs-body precedence, PKCE capture, no-store headers) or pull in a third-party OAuth client. The server's grant dispatch is complete and tested, but unreachable from the SDK surface.

**Evidence**:
- `interfaces/ssoclient/client.go` — `AuthClient` interface comment: "The Login flow is intentionally NOT in this interface"; only `ValidateToken`/`Logout`. `remote/auth.go` `NewAuthClient(jwks, opts...)` has no token method and no HTTP path to `/token`.
- `interfaces/sso/server_routes.go:180-187` — `POST PathToken → handleToken`, `POST PathIntrospect`, `POST PathRevoke`, `POST PathDeviceCode`, `GET PathDeviceVerify`, `POST PathPAR` all exist server-side.
- `interfaces/sso/server_token.go:148-168` — grant switch dispatches `GrantAuthorizationCode`, `GrantRefreshToken`, `GrantClientCredentials` (+ device/CIBA/exchange); `interfaces/sso/aliases.go:261-265` exports the grant constants.
- `interfaces/sso/server_token.go:377` `denyPublicClientCredentials` — client_credentials is gated to confidential clients; a client must carry client auth, so the facade needs both secret-based and (later) mTLS/JWT auth.

**Proposed behavior**:
- New `TokenClient` interface in `interfaces/ssoclient/client.go` (or `token.go`): `ExchangeCode(ctx, code, verifier)` → `*TokenResponse`; `Refresh(ctx, refreshToken)`; `ClientCredentials(ctx, scopes)`; later extended by Decision 2 (device, PAR). `TokenResponse` carries `AccessToken`, `RefreshToken`, `ExpiresIn`, `Scope`, `TokenType`, and `IDToken` if present.
- `remote` implementation: `NewTokenClient(tokenURL string, opts ...TokenOption)` with `WithClientCredentials(clientID, secret)` (sent as HTTP Basic, mirroring `protocols/oauth/handle_par.go`'s "Basic wins when both present" rule), `WithPKCE(true)` (client generates `code_verifier` 43–128 chars, `code_challenge = base64url(SHA256(verifier))` — S256 only, matching `core.PKCEMethodS256`/`interfaces/sso/aliases.go:436`).
- Every request stamps `Cache-Control: no-store` / `Pragma: no-cache` (client-side half of the AGENTS.md credential-endpoint contract; server stamps via `tokenNoStoreHeaders`).
- Server errors are mapped to typed sentinels (`invalid_grant`, `invalid_client`, `unsupported_grant_type`, `invalid_scope`) by parsing the RFC 6749 §5.2 error body; unknown/ambiguous responses stay opaque (oracle-safe, no client-side detail invention).

**Acceptance check**: New test file `interfaces/ssoclient/remote/token_test.go` using `test/`-style server harness: (1) full code+PKCE exchange round-trip against `interfaces/sso` `handleToken` succeeds and `Subject` claims match; (2) wrong verifier returns `invalid_grant`; (3) refresh rotation succeeds once and reuse of the rotated-out token fails with `invalid_grant`; (4) `client_credentials` with a public client returns `invalid_client`/`unauthorized_client`; (5) wire assertions: every request carries no-store headers and Basic auth when both Basic and body creds are set. `go build ./... && go vet ./...` plus the root gates pass.

---

## Decision 2: PAR (`request_uri` flow) and Device flow (polling state machine) on the same `TokenClient`

**Name**: PAR + Device grant support — `TokenClient.StartPAR`, `TokenClient.DeviceFlow`.

**Problem**: The server's Pushed Authorization Request and Device Authorization endpoints exist and are feature-matrix commitments, but there is no client counterpart. Without PAR, an App using the SDK cannot get the URL-shortening/request-integrity guarantees the server provides; without Device, there is no TV/CLI login path. The device flow's polling semantics (interval, `slow_down`, `authorization_pending`, `expired_token`) are error-prone to hand-roll and the SDK currently leaves that to each App.

**Evidence**:
- `interfaces/sso/server_routes.go:184-187` — `POST PathDeviceCode`, `GET PathDeviceVerify`, `POST PathPAR` are routed; `interfaces/sso/handlers.go:99` `handlePAR` → `oauth.HandlePAR(s, ctx)` (`protocols/oauth/handle_par.go:54`).
- `interfaces/sso/accessors.go:97-101` — `DeviceCodeStore()`, `DeviceCodeTTL()`, `DeviceCodeInterval()` (the server defines the polling interval the client must honor).
- `protocols/oauth/oauthspi/device_codes.go:17-25` — `GenerateDeviceCode`, `GenerateUserCode` (8-char dashed `XXXX-XXXX` user_code); `oauthspi/device_code.go:41` `IsExpired`.
- `interfaces/sso/server_token.go:153` — `handleDeviceTokenGrant` consumes the `device_code` at `/token`.

**Proposed behavior**:
- `StartPAR(ctx, req) (*PARResponse, error)` — POSTs to `PathPAR` with client auth, returns `request_uri` + `expires_in` (RFC 9126 §3.2); callers pass `request_uri` (plus `client_id`) to the authorize endpoint. PAR requests also carry PKCE params and, when a DPoP key is present (Decision 3), a proof.
- `DeviceFlow(ctx, scopes) (*DeviceSession, error)` — POSTs to `PathDeviceCode`; returns `device_code`, `user_code`, `verification_uri`, `expires_in`, `interval`.
- `DeviceSession.Wait(ctx)` — polling state machine: poll `/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`; honor server `interval`; translate `authorization_pending` → retry, `slow_down` → backoff (RFC 8628 §3.5, interval + 5s), `expired_token`/`access_denied` → terminal typed errors. Context cancellation aborts cleanly.
- Both flows go through the same client-auth, no-store, and error-mapping plumbing as Decision 1 (single code path).

**Acceptance check**: `token_test.go` additions or a new `device_test.go`: (1) PAR returns a `request_uri` accepted by the server's authorize handling; (2) device `Wait` succeeds after simulated approval, returns tokens; (3) `slow_down` and `authorization_pending` produce correct backoff/retry, `expired_token` produces a typed error; (4) interval from `DeviceCodeInterval()` is honored (assert no early poll). Run `go test ./interfaces/ssoclient/...` and `make ci`.

---

## Decision 3: DPoP proof generator (`dpop+jwt` minting, RFC 7638 thumbprint, nonce challenge retry) wired into the token client

**Name**: Client-side DPoP proof generation — `ssoclient/dpop` signer + `WithDPoPKey` integration.

**Problem**: The entire sender-constraint chain exists — RS verification (`rs/dpop.go`), AS nonce issuance and `cnf.jkt` binding at `/token` — but the proof itself is only ever minted by hand in test code. No production code in the repository can generate a `dpop+jwt`; `shared/security` has no signing primitive at all. Without a generator, DPoP-bound access tokens are unobtainable by SDK users, and the RS-side verifier (which fails closed on missing `cnf.jkt`) is dead weight.

**Evidence**:
- `interfaces/ssoclient/rs/dpop.go` — `ValidateTokenWithDPoP`/`verifyDPoPProof` implement the full RFC 9449 §7.1 verifier ladder (typ check, `VerifyCompactJWS`, htm/htu/iat/jti/ath binding, replay cache, `cnf.jkt` thumbprint match). The counterpart generator does not exist anywhere.
- `interfaces/ssoclient/rs/dpop_test.go:23-52` — `newDPoPKey`/`proof()` mint proofs by hand with `"typ": "dpop+jwt"` in test code only — the production generator is missing.
- `interfaces/sso/server_dpop.go:374-412` — `HeaderDPoPNonce = "DPoP-Nonce"`, `DPoPNonceProvider`/`HMACNonceProvider` (issue/verify), `DefaultDPoPNonceTTL = 5 * time.Minute`; `server_dpop.go:468` `stampDPoPNonce` and `interfaces/sso/mesh_authz.go:217` emit the `use_dpop_nonce` challenge the client must answer.
- `interfaces/sso/server_token.go:46-51` — `captureSenderConstraint` binds DPoP at `/token`, so a proof-capable client is the prerequisite for the whole `cnf.jkt` security model.
- `shared/security/` — only `VerifyCompactJWS` (verification); grep for signing primitives finds only `securityverify/webhook_signature.go:30` `SignWebhookPayload` (HMAC webhook, not JWS).

**Proposed behavior**:
- New `interfaces/ssoclient/dpop` package: `GenerateKey()` (ephemeral asymmetric key, EdDSA or ES256 — must be within `AsymmetricJWSAlgs()`), `Proof(key, method, uri, accessToken, nonce)` minting `dpop+jwt` with `jwk` header (public members only) and claims `htm`, `htu`, `iat`, `jti` (random), `ath` (when an access token is presented, SHA-256 binding), optional `nonce`; RFC 7638 thumbprint helper (`jwkThumbprintRFC7638` semantics, matching `rs/dpop.go`'s check).
- `TokenOption` `WithDPoPKey(...)`; the token client then (a) generates a proof per credential request, (b) on `use_dpop_nonce` (400) or `DPoP-Nonce` challenge header, captures the nonce, re-signs, and retries once (RFC 9449 §8, mirroring the server comment at `server_dpop.go:404-409` that the first request costs one extra round-trip).
- The key's thumbprint is the client identity for the token: the returned `TokenResponse` exposes the `cnf.jkt` so the App can correlate with the RS verifier's expectation; the same key is reusable for subsequent RS calls (`ValidateTokenWithDPoP`) and PAR requests from Decision 2.
- Nonce handling is stateless per challenge; proofs never reuse `jti` (replay cache at `rs/dpop.go` `dpopReplayCapDefault` would reject them).

**Acceptance check**: New `interfaces/ssoclient/dpop/dpop_test.go`: (1) generated proof verifies against `rs.ValidateTokenWithDPoP` with a token carrying `cnf.jkt` (cross-package end-to-end, the exact inverse of the existing hand-minted test); (2) `ath` binds the presented token; (3) nonce round-trip: mock server responds `use_dpop_nonce` + `DPoP-Nonce` header once, client retries with the nonce and succeeds; (4) two proofs with the same `jti` are rejected by the replay cache. Root gates (`go build ./...`, `go vet ./...`, `TestMaintainability_|TestArchitecture_`) pass; the new package is classified in `layerName()` per `architecture_layer_test.go`.

---

**Sequencing**: Decision 1 is the foundation (single request/auth/error pipeline); Decision 2 reuses it; Decision 3 can land in parallel (pure addition, no dependency on 1/2 beyond `WithDPoPKey` hookup). All three are additive to `interfaces/ssoclient` (no existing symbol changes), keeping within the 60-file ceiling by extending existing files where possible (`remote/auth.go`, `client.go`) and adding at most two new files (`remote/token.go`, `dpop/dpop.go`).
