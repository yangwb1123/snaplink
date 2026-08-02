All claims in the doc are verified against the code. Design doc written to `docs/auto/interfaces-ssoclient-oauth-client-design.md`.

## Summary

**Grounded scope**: every endpoint the client will talk to already exists and is gate-tested — `/token` grant dispatch (`server_token.go:148`), Basic-wins client auth (`oauthwire`), PAR (`handle_par.go`), device flow with `slow_down`/`pending`/`invalid_grant` semantics (`token_device.go`), DPoP nonce challenge (`server_dpop.go`), and the RS verifier ladder (`rs/dpop.go`). Zero server changes; this is pure client-side addition.

**## Decision 1 — TokenClient facade + remote HTTP implementation**
- API: `TokenClient` interface (in existing `client.go`) with `GeneratePKCE`/`ExchangeCode`/`Refresh`/`ClientCredentials`; `remote/token.go` with `NewTokenClient(tokenURL, opts...)`, Basic-vs-form credential options mirroring the server's precedence, and typed sentinels in `types.go`.
- Storage: fully stateless client; PKCE verifier and refresh tokens are App-owned by design (multi-instance safety, rotation persistence).
- Failure modes: no auto-retry anywhere (single-use artifacts → `invalid_grant`), oracle-safe error mapping (known §5.2 codes → sentinels, everything else opaque), fail-closed on 2xx-without-`access_token`.
- Break risks: `remote/token.go` line budget (mitigated by hosting the form-POST helper in `auth.go`; the 500-line gate outranks the "two new files" planning number), complexity budget of the error switch, and the test-harness rule (must not import `test/` — composition layer; existing `auth_test.go` pattern instead).

**## Decision 2 — PAR + Device flow**
- API: `StartPAR(PARRequest) → PARResponse{RequestURI, ExpiresIn}`; `DeviceFlow(scopes) → DeviceSession`; `Wait(ctx)` state machine honoring server `interval`, `slow_down → interval+5s`, terminal `access_denied`/`expired_token`/`invalid_grant`, local-expiry cutoff, transient-error retry within the session window.
- Key finding: this server collapses expired/unknown device codes to `invalid_grant` at `/token` (CIBA alone uses `expired_token`), so the client maps both terminally and self-terminates on local expiry — an App sees `ErrExpiredToken` regardless of wire-code drift.

**## Decision 3 — DPoP proof generator**
- API: new `interfaces/ssoclient/dpop` package (`GenerateKey`, `Key.Proof(method, uri, accessToken, nonce)`, RFC 7638 thumbprint); `WithDPoPKey` wires proofs onto every credential request, with a bounded one-shot nonce retry and a fail-closed downgrade check (`token_type: "DPoP"` expected).
- Sharpest constraint found: `shared/security` root **and** `securityverify/` are both at the 10-file ceiling, and `jwks_verify.go` is 476 lines — a shared JWS signer cannot be added there today. The signer stays private in `dpop.go` (stdlib ed25519), which must be flagged when `private_key_jwt` client auth eventually lands.
- Layer gate: no `layerName()` change needed — first path segment `interfaces` already classifies the new package; no exemptions.

Budget accounting verified: `interfaces/sso` stays at exactly 60 files, ssoclient root 4→4, remote 4→5, two new non-test files total, all within limits.
