# Design: `ssoclient` OAuth token acquisition layer — TokenClient, PAR/Device, DPoP proofs

Scope: expansion direction 1 from `docs/auto/interfaces-ssoclient-analysis.md`. Gives the
App-facing SDK a first-class OAuth client that reaches the server's existing grant surface
(`POST /token`, `POST /par`, `POST /device`). Three additive decisions; no existing
`ssoclient` symbol changes; zero server-side changes.

## Grounding and non-goals

Everything the client will talk to already exists and is gate-tested:

- Grant dispatch: `interfaces/sso/server_token.go:148` (`GrantAuthorizationCode`,
  `GrantRefreshToken`, `GrantClientCredentials`, `GrantDeviceCode`), client auth with
  Basic-wins precedence (`protocols/oauth/oauthwire/bind.go`, `BasicClientCreds`),
  sender-constraint capture (`server_token.go:44` `captureSenderConstraint`).
- PAR: `protocols/oauth/handle_par.go:54` `HandlePAR` (201 `{request_uri, expires_in}`,
  TTL default 90s), server route `POST PathPAR`.
- Device: `interfaces/sso/server_device.go` `handleDeviceCode` (response carries
  `device_code`, `user_code`, `verification_uri[_complete]`, `expires_in`, `interval`;
  TTL default 10 min, poll floor `DefaultDevicePollMin` 5s) and
  `internal/handler/tokengrant/token_device.go` `HandleDeviceGrant` (RFC 8628 §3.5
  sentinels: `authorization_pending`, `slow_down`, `access_denied`; unknown/expired/
  consumed codes collapse to `invalid_grant`; `ConsumeIfApproved` makes the code
  single-use under concurrency).
- DPoP: AS nonce issuance (`interfaces/sso/server_dpop.go` `HMACNonceProvider`,
  `HeaderDPoPNonce`, `ErrUseDPoPNonce` = `"use_dpop_nonce"`, 400 challenge + header
  stamp), RS verification (`interfaces/ssoclient/rs/dpop.go` — typ check, htm/htu/iat/jti/
  ath binding, jti replay cache, `cnf.jkt` thumbprint), `dpopTokenTypeOr` emits
  `token_type: "DPoP"` when the issued token is JKT-bound.

Non-goals (explicitly out): mTLS/`private_key_jwt` client auth (flagged as the "later"
extension in Decision 1), CIBA, token exchange, `Idempotency-Key` plumbing, CAEP
receiver (expansion direction 3). Login/authorize URL construction stays App-side —
the browser flow is out of process by architecture.

### Budget and gate accounting (checked against AGENTS.md §2)

| Item | Before | After | Limit |
|---|---|---|---|
| New non-test files | — | `remote/token.go`, `dpop/dpop.go` (2) | "at most two" (requirement) |
| Extended files | — | `ssoclient/client.go` (interface), `ssoclient/types.go` (types/sentinels) | — |
| New test files | — | `remote/token_test.go`, `remote/device_test.go`, `dpop/dpop_test.go` | tests don't count |
| `interfaces/ssoclient` root files | 4 | 4 | 10 |
| `remote/` non-test files | 4 | 5 | 10 |
| `interfaces/sso` files | 60 | 60 (untouched) | 60 |
| `shared/security` root files | 10 | 10 (untouched) | 10 |
| `securityverify/` files | 10 | 10 (untouched) | 10 |
| New packages | — | `interfaces/ssoclient/dpop` | classified by first segment `interfaces` in `layerName()` — no new entry, no exemption |

`interfaces/ssoclient/dpop` imports only `shared/core` + `shared/security` (downward);
`remote/token.go` imports `ssoclient/dpop` (same layer). No upward edges, so the
architecture gate needs no `layerExemptions` entry.

---

## Decision 1 — `TokenClient` facade with remote HTTP implementation

### API surface

`TokenClient` (added to `interfaces/ssoclient/client.go`, next to `AuthClient`; the
comment on `AuthClient` that "Login is intentionally NOT in this interface" stays true —
this is token *acquisition*, not the browser login UI):

```go
type TokenClient interface {
    // GeneratePKCE mints a fresh RFC 7636 S256 pair: verifier 43-128 chars
    // (crypto/rand, base64url — matches core.PKCEVerifierMinLen/MaxLen = 43/128),
    // challenge = base64url(SHA256(verifier)). S256 only (core.PKCEMethodS256).
    // The verifier is returned to the caller, never stored by the client.
    GeneratePKCE() (verifier, challenge string, err error)

    // ExchangeCode redeems an authorization_code. verifier is the value from
    // GeneratePKCE ("" allowed only when PKCE is not enforced — see WithPKCE).
    ExchangeCode(ctx context.Context, code, verifier string) (*TokenResponse, error)

    // Refresh rotates a refresh token. The response carries the NEW refresh
    // token; the caller must persist it (see storage model).
    Refresh(ctx context.Context, refreshToken string) (*TokenResponse, error)

    // ClientCredentials performs an RFC 6749 §4.4 grant. Only confidential
    // clients succeed server-side (denyPublicClientCredentials); a public
    // client gets ErrInvalidClient surfaced as-is, oracle-safe.
    ClientCredentials(ctx context.Context, scopes ...string) (*TokenResponse, error)

    // Decision 2:
    StartPAR(ctx context.Context, req *PARRequest) (*PARResponse, error)
    DeviceFlow(ctx context.Context, scopes ...string) (*DeviceSession, error)
}
```

`TokenResponse` (in `types.go`, beside `Subject`):

```go
type TokenResponse struct {
    AccessToken  string   // required; absent on a 2xx is a fail-closed error
    RefreshToken string   // rotation: always persist the newest value
    ExpiresIn    int64    // seconds, per RFC 6749 §5.1
    Scopes       []string // split from wire scope (matches Subject.Scopes)
    TokenType    string   // "Bearer" or "DPoP" (Decision 3)
    IDToken      string   // present when scope included "openid"
    CnfJKT       string   // RFC 7638 thumbprint of the DPoP key, when bound
}
```

Remote implementation (`interfaces/ssoclient/remote/token.go`):

```go
func NewTokenClient(tokenURL string, opts ...TokenOption) *TokenClient
func WithClientCredentials(clientID, secret string) TokenOption      // HTTP Basic
func WithFormClientCredentials(clientID, secret string) TokenOption  // form body
func WithRedirectURI(uri string) TokenOption                          // sent on code exchange
func WithPKCE(enabled bool) TokenOption       // true: ExchangeCode rejects empty verifier
func WithHTTPClient(c *http.Client) TokenOption                       // default 10s timeout
// Decision 2:
func WithPARURL(url string) TokenOption       // default: tokenURL's sibling path
func WithDeviceURL(url string) TokenOption    // default: tokenURL's sibling path
// Decision 3:
func WithDPoPKey(k *dpop.Key) TokenOption
```

`TokenOption` mirrors the `AuthOption` style of `remote/auth.go`. `NewAuthClient`'s
defaults (5s client, caller-owned caches) are the template; the token client is
stateless so it needs no lifecycle methods.

### Wire contract (the client-side half of the AGENTS.md credential rules)

- Every request is `POST application/x-www-form-urlencoded` with
  `Cache-Control: no-store` + `Pragma: no-cache` — the client-side mirror of the
  server's `tokenNoStoreHeaders`. One builder stamps all four endpoints (token, PAR,
  device code, device poll), so the contract cannot drift per method.
- Client auth precedence mirrors the server's `BasicClientCreds` rule exactly: when
  `WithClientCredentials` is set, the request carries `Authorization: Basic` and the
  body omits `client_secret`; `WithFormClientCredentials` is the fallback (and exists
  so the precedence is testable: with both set, the wire shows Basic and no body
  secret — the same resolution the server applies).
- Body always carries `client_id` (public-client device flow and PAR need it; the
  server ignores it when Basic wins).
- PKCE params (`code_challenge`, `code_challenge_method=S256`) are included in the
  code exchange; `code_verifier` is included only for `authorization_code` — never on
  refresh (AGENTS.md: "Refresh never carries a verifier").
- Server errors map to typed sentinels by parsing the RFC 6749 §5.2 body
  (`{"error": ...}`). Known codes: `invalid_grant`, `invalid_client`,
  `unsupported_grant_type`, `invalid_scope` (device poll adds `authorization_pending`,
  `slow_down`, `access_denied`, `expired_token`, Decision 2). Unknown codes, unparseable
  bodies, and 5xx stay opaque in a `*TokenError{Status, Code, Description}` — the
  description is the server's own words, never client-invented detail (oracle-safe).
- Fail closed on protocol violations: a 2xx without `access_token` is an opaque error,
  not a success.

Sentinels live in `interfaces/ssoclient/types.go` (the shared vocabulary file), as
`errors.New` values so callers use `errors.Is`: `ErrInvalidGrant`, `ErrInvalidClient`,
`ErrUnsupportedGrantType`, `ErrInvalidScope` (plus Decision 2's set). Interface-level
so local/remote implementations share them.

### Storage model

The `TokenClient` is **stateless**: no caches, no key-value state, safe for
multi-instance Apps behind a load balancer. State ownership is explicit:

- **PKCE verifier**: held by the App between the authorize redirect and the callback
  (session storage). `GeneratePKCE` returns it; `ExchangeCode` consumes it; the client
  never persists it. This is deliberate — client-held verifier state would break on
  instance failover between redirect and callback.
- **Refresh token**: returned to the App, which persists it. Rotation means the App
  must store the newest value from each `Refresh` response; a lost response (crash
  between server rotation and App persistence) loses the family — the server's grace
  window only covers concurrent same-token retries.
- **Server side**: untouched. Auth-code, refresh, PAR, and device stores already exist;
  this decision adds no storage anywhere.

### Failure modes

| Failure | Behavior |
|---|---|
| Network error / timeout / 5xx | Opaque wrapped error (`ssoclient/remote: token: ...`); no auto-retry. An `ExchangeCode` retry after an ambiguous failure can hit an already-consumed code (`invalid_grant`) — surfacing is the correct default |
| 400 `invalid_grant` | Typed sentinel; terminal. Code consumed/expired/mismatched (or refresh family dead) — never retry |
| 401 `invalid_client` | Typed sentinel; configuration error |
| 400 `invalid_scope` / `unsupported_grant_type` | Typed sentinels; request error |
| 2xx without `access_token` | Opaque protocol error, fail closed |
| Unknown error code / unparseable body | Opaque `*TokenError` — no detail invented |
| `client_credentials` from a public client | Server answers 401 `invalid_client` (`denyPublicClientCredentials`) → surfaced as `ErrInvalidClient` |

### What could break the design

- **File budget**: `remote/token.go` must stay ≤ 500 lines. The shared pipeline
  (builder + send + error map) plus three grants plus Decision 2's PAR/device code is
  ~480 lines only if the form-POST helper lives in `remote/auth.go` (extending the
  existing file, allowed) and the device poller is split into focused functions. If
  the poller still overflows, AGENTS.md's 500-line gate outranks the "at most two new
  files" planning constraint: split the poller into `remote/device.go` (a third new
  file) rather than let a file cross budget. Flag for the implementation pass.
- **Complexity budget**: the error-mapping switch must stay under 15 branches — split
  the device sentinel mapping into its own function (Decision 2) instead of growing
  the token mapping.
- **No auto-retry**: the single exception is the DPoP nonce challenge (Decision 3,
  protocol-mandated). Any other retry reuses single-use artifacts and turns into
  `invalid_grant` — the design deliberately surfaces instead.
- **Test harness**: `remote/token_test.go` must NOT import `test/` (composition layer —
  upward edge, architecture gate). The existing `remote/auth_test.go` pattern is the
  template: build `sso.NewServer(...)` with `defaultimpl` stores in the test file,
  `httptest.NewServer(srv.Handler())`, plus the `var _ ssoclient.TokenClient =
  (*remote.TokenClient)(nil)` guard per `iface_check.go` convention.
- **Server-side precedent drift**: `denyPublicClientCredentials` proves mTLS clients
  pass without a secret — irrelevant to v1 (no mTLS), but the client-credentials
  surface must keep mapping 401 to `ErrInvalidClient` regardless of *why* the server
  rejected.

---

## Decision 2 — PAR (`request_uri`) and Device flow (polling state machine)

### API surface

```go
// types.go
type PARRequest struct {
    ResponseType        string   // "code"
    RedirectURI         string
    Scope               []string
    State               string
    Nonce               string
    CodeChallenge       string   // from GeneratePKCE
    CodeChallengeMethod string   // "S256"
    Resource            []string // RFC 8707
    LoginHint           string
}

type PARResponse struct {
    RequestURI string // pass to the authorize endpoint with client_id
    ExpiresIn  int    // seconds (server DefaultPARTTL floor is 90s)
}

// DeviceSession is the transient polling state machine. It is NOT safe to
// share: exactly one Wait caller may own it (the device_code is single-use).
type DeviceSession struct {
    DeviceCode      string
    UserCode        string        // dashed XXXX-XXXX form for display
    VerificationURI string
    ExpiresIn       int64         // seconds from server (default TTL 10 min)
    Interval        time.Duration // server's poll interval (floor 5s)
    // unexported: client ref, nextPollAt, local expiry
}

func (s *DeviceSession) Wait(ctx context.Context) (*TokenResponse, error)
```

`StartPAR` POSTs the request to `PathPAR` through the shared pipeline (client auth,
no-store headers, error mapping). A 201 yields `{request_uri, expires_in}`; the App
composes the authorize URL itself (`authorize_base?client_id=...&request_uri=...`),
which is the documented PAR contract (RFC 9126 §3.1). PAR carries the PKCE challenge
and, when a DPoP key is configured (Decision 3), a proof — the same request body shape
the App would have put in the redirect, moved upstream where the server validates it
before the user agent ever moves.

`DeviceFlow` POSTs `client_id` (+ scope, + optional resource) to `PathDeviceCode` and
returns the parsed session. `Wait` implements RFC 8628 §3.4-3.5:

```text
loop:
  if now >= session expiry:            return ErrExpiredToken      (no further polls)
  sleep until nextPollAt (or ctx.Done)                             (honor interval)
  poll /token, grant_type=urn:ietf:params:oauth:grant-type:device_code
  success:                 return *TokenResponse
  authorization_pending:   nextPollAt = now + Interval             (retry)
  slow_down:               nextPollAt = now + Interval + 5s        (RFC 8628 §3.5)
  access_denied:           return ErrAccessDenied                  (terminal)
  expired_token:           return ErrExpiredToken                  (terminal)
  invalid_grant:           return ErrInvalidGrant                  (terminal: consumed/
                               expired/revoked — server collapses these)
  network error / 5xx:     nextPollAt = now + Interval             (transient: keep
                               polling within the session window)
```

Server evidence pins the semantics: the first poll is legal (the server's `slow_down`
check only fires when `LastPoll` is set); a poll earlier than `interval` after the
previous one earns `slow_down` from `devicePollGate`; `ConsumeIfApproved` makes exactly
one concurrent poll win and every loser collapse to `invalid_grant`.

### Storage model

`DeviceSession` holds only in-memory, transient poll state (`nextPollAt`, local expiry,
backoff). Deliberately not durable: a crashed App restarts the device flow — server
codes are single-use and short-lived (10 min default) so persistence would be dead
weight. PAR has no client-side state at all: `request_uri` is used once by the user
agent and expires server-side. No new server storage; `DeviceCodeStore`/`PARStore`
already exist with per-client TTL/interval resolution.

### Failure modes

| Failure | Behavior |
|---|---|
| `authorization_pending` | Retry at `Interval` — bounded by local `ExpiresIn` |
| `slow_down` | Backoff `Interval + 5s`; the server enforces the same rule, so a compliant client should never see this (defense in depth) |
| `access_denied` / `expired_token` / `invalid_grant` | Terminal typed errors; the session is dead (server deleted/consumed the code) |
| Local expiry reached | `ErrExpiredToken` without another round-trip — stops hammering a dead code |
| Context cancellation | Returns `ctx.Err()` cleanly, drops the session |
| Transient network / 5xx | Retried at the interval cadence within the session window — a single blip must not kill a flow the user is mid-approval on |
| Server without PAR configured | 501 → opaque `*TokenError` (server emits `ErrPARNotConfigured`); the App can fall back to a direct authorize URL |

### What could break the design

- **Line budget pressure**: the poller is the largest single chunk of `remote/token.go`
  (~150 lines with the sentinel switch). Mitigation as in Decision 1: extract
  `pollOnce`/`nextPollDelay` into focused functions; if the file still crosses 500,
  split `remote/device.go` (documented fallback — the gate outranks the file-count
  planning number).
- **Interval contract**: the client must treat `interval` from the *response* as
  authoritative (server already clamps it to `DefaultDevicePollMin` 5s). Client-side
  defensive clamp: `interval <= 0 → 5s`, and the acceptance test asserts no poll
  happens before the interval elapses after a `pending` response.
- **Single-waiter invariant**: two concurrent `Wait` calls on one session — the second
  polls a consumed code and gets `invalid_grant`. Documented, not defended: the
  terminal error is the honest outcome.
- **Server mapping drift**: RFC 8628 names `expired_token`, but this server collapses
  unknown/expired device codes to `invalid_grant` at `/token` (CIBA uses
  `expired_token`). The client maps both to terminal errors, and additionally
  self-terminates on local expiry — so an App sees `ErrExpiredToken` exactly when the
  session window lapses, regardless of which wire code the server chose.
- **Device verify test path**: `Wait` success requires an approval. The honest test
  path is the server's own `POST /device/verify` endpoint (bearer + user_code +
  `approve: true`); where the harness needs determinism, mutate the in-memory
  `DeviceCodeStore` directly — both live in the test file per the harness rule above.

---

## Decision 3 — DPoP proof generator (`dpop+jwt` minting, RFC 7638 thumbprint, nonce retry)

### API surface

New package `interfaces/ssoclient/dpop` (single file `dpop.go`; new package = first
segment `interfaces`, so `layerName()` already classifies it — no gate change):

```go
// GenerateKey mints an ephemeral Ed25519 proof key (crypto/rand). Ed25519 is
// the repo's established DPoP test key and is within AsymmetricJWSAlgs();
// ES256 is a trivial later extension. The private key never leaves the
// process and is not exported.
func GenerateKey() (*Key, error)

type Key struct { /* private key + cached public JWK + jkt */ }

func (k *Key) Thumbprint() string      // RFC 7638 jkt, canonical form identical to
                                       // rs/dpop.go jwkThumbprintRFC7638
func (k *Key) PublicJWK() core.JWK     // public members only
// Proof mints a dpop+jwt bound to method/uri. accessToken != "" adds the
// ath claim (SHA-256 binding); nonce != "" adds the nonce claim. Fresh jti
// (16 random bytes, base64url) and iat=now on EVERY call — proofs are
// minted at request time, never cached (the 60s iat window and the jti
// replay cache on both AS and RS sides reject reuse).
func (k *Key) Proof(method, uri, accessToken, nonce string) (string, error)
```

Wire shape (mirrors what `rs/dpop.go` verifies and what the server's
`verifyDPoPProof` ladder checks, in reverse):

- Header: `{"alg":"EdDSA","typ":"dpop+jwt","jwk":{public members}}` — only public
  members, matching `parseProofJWK`'s projection.
- Claims: `htm`, `htu` (normalized per RFC 9449 §4.3 — query/fragment stripped,
  identical to `rs.normalizeHTU`; a mismatch fails RS verification), `iat`, `jti`,
  optional `ath` (b64url of SHA-256 of the presented access token) and `nonce`.
- Signature: `ed25519.Sign` over `b64url(header).b64url(payload)` — the same shape
  `security.VerifyCompactJWS` accepts, so the inverse test (mint here, verify in
  `rs.ValidateTokenWithDPoP`) is exact.

`TokenClient` integration — `WithDPoPKey(k *dpop.Key)`:

1. Every credential request (token, PAR, device poll) carries
   `DPoP: k.Proof("POST", requestURL, "", "")`.
2. On a non-2xx whose body is `use_dpop_nonce` AND whose headers carry
   `DPoP-Nonce` (the server stamps both in `captureSenderConstraint`), re-mint the
   proof with the nonce and retry **once** (RFC 9449 §8; the server documents the
   first request costing one extra round-trip). The retry mints a NEW jti/iat — the
   first proof's jti is already in the server's replay store.
3. A second challenge is surfaced as an opaque error — no loop.
4. `TokenResponse.CnfJKT = k.Thumbprint()` when DPoP is configured; the client also
   asserts the response `token_type` is `"DPoP"` (server emits it via
   `dpopTokenTypeOr` whenever a JKT was bound). A 200 with `token_type: "Bearer"`
   after a valid proof means the server ignored the proof — fail closed with an
   opaque downgrade error rather than return an unconstrained token.

The same `Key` serves the RS side: the App mints `k.Proof(method, uri, accessToken, "")`
per RS request and hands proof+token to `rs.ValidateTokenWithDPoP`, whose `ath` and
`cnf.jkt` checks close the loop.

### Storage model

- **Key**: App-owned; ephemeral in-memory is the recommended default. A lost key
  makes DPoP-bound tokens unusable — that is the sender-constraint model working as
  intended (the token is bound to key possession), and the App re-authenticates.
- **Nonce**: stateless per challenge by design — the client holds a nonce only for the
  single retry it is about to send, then discards it. The server's provider is
  stateless HMAC, so there is no client-side nonce cache to invalidate.
- **jti**: never stored, never reused — the replay caches (AS `JTIReplayStore`, RS
  `dpopReplayCache` 4096 cap) reject reuse.
- No new server or client storage.

### Failure modes

| Failure | Behavior |
|---|---|
| Proof too old / future | Minted at request time with `iat=now`, so only clock skew matters; AS default skew 60s, RS `ProofMaxAge` 60s — a skew-broken deployment gets `invalid_dpop_proof`/`ErrDPoPInvalid`, surfaced opaque |
| Nonce challenge | One bounded retry with the stamped nonce; second challenge = opaque error (server/client disagreement, not a loop) |
| jti replay | Impossible by construction (fresh jti per mint); a transport-level retry reusing the same proof would be rejected — another reason credential POSTs never auto-retry |
| Lost key | DPoP-bound tokens unusable; App re-auths. Fail closed, by design |
| `ath` mismatch at RS | Client-side bug (minting a proof for a different token than presented) — `ErrDPoPInvalid` from the verifier |
| Server ignores proof | 200 `Bearer` while a proof was sent → opaque downgrade error, token not returned |

### What could break the design

- **No shared signing primitive — the sharpest constraint.** `shared/security` root
  and `securityverify/` are both AT the 10-non-test-files-per-directory ceiling, and
  `securityverify/jwks_verify.go` (431+ lines) is too close to 500 to absorb a signer.
  Therefore the compact-JWS signer is a private helper inside `dpop.go` (stdlib
  ed25519 only, ~40 lines), NOT a new `shared/security` primitive. Consequence: the
  repo keeps one verifier (`security.VerifyCompactJWS`, alg-confusion-safe) and one
  private signer. When `private_key_jwt` client auth lands (Decision 1's flagged
  extension), it either reuses `dpop`'s signer or forces a budget decision in
  `securityverify` — call that out explicitly rather than discover it mid-change.
- **Algorithm discipline**: only `AsymmetricJWSAlgs()` members; never `none`/HS*. The
  `alg` is fixed at `"EdDSA"` for v1 and the server's per-issuer gate accepts it.
- **Header hygiene**: the embedded `jwk` must contain public members only — a private
  key member would leak the key in every request. `PublicJWK()` is the only path into
  the header.
- **htu normalization parity**: a single character of divergence from
  `rs.normalizeHTU` fails RS verification — the thumbprint and normalization helpers
  must be copied deliberately (the repo already accepts this pattern: `rs/dpop.go`
  documents its own local thumbprint copy because the AS helper is unexported).
- **File budget**: `dpop.go` (~250-300 lines: keygen + thumbprint + proof + signer)
  is comfortably within limits; the risk is scope creep (ES256, key export, nonce
  caching) — keep v1 to the surface above.
- **Test independence**: `dpop_test.go` must pin the wire format independently (the
  existing `rs/dpop_test.go` pattern: hand-computed canonical thumbprint, hand-minted
  expected JWS) rather than calling the code under test tautologically. The
  cross-package acceptance (mint → `rs.ValidateTokenWithDPoP`) is the real inverse
  check.
- **Nonce challenge shape drift**: the retry triggers on the exact pair (400 +
  `use_dpop_nonce` + `DPoP-Nonce` header) the server emits today; if the server ever
  challenges with a different code, the client surfaces the error instead of
  retrying — safe by construction.

---

## Sequencing and verification

Decision 3 can land in parallel with Decision 1 (pure addition; its only coupling is
the `WithDPoPKey` option, which can be a no-op hookup until both land). Decision 2
sits on Decision 1's pipeline. Suggested order: 1 → 2 → 3-hookup, with the dpop
package itself first (it is needed by tests of both 1 and 2).

Per-change gates (AGENTS.md §2): `go build ./... && go vet ./...` and
`go test -run 'TestMaintainability_|TestArchitecture_' .` after every `.go` edit;
before handoff `go test ./interfaces/ssoclient/... -race`, `go test ./test/ -run
TestE2E -v` (unchanged server behavior), and `make ci`. Acceptance per decision:
code+PKCE round-trip with matching `Subject` claims and wrong-verifier
`invalid_grant`; refresh rotation success + rotated-out reuse `invalid_grant`;
public-client `client_credentials` → `invalid_client`; wire assertions for no-store
headers and Basic-vs-body precedence; PAR `request_uri` accepted by authorize
handling; device `Wait` success, `slow_down`/`pending` timing, `expired_token`
terminal; DPoP proof verifying through `rs.ValidateTokenWithDPoP`, `ath` binding,
nonce round-trip, and jti replay rejection.

Known pre-existing drift to report, not fix here: `remote.AuthClient.Logout` silently
no-ops without `WithLogoutURL` and `ssoclient`'s `ValidateToken` does not enforce
iss/aud — expansion direction 2, deliberately out of scope for this change.
