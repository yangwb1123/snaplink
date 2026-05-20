# AGENTS.md

Operational guide for AI agents working in this repository. Follows the
[agents.md](https://agents.md) convention.

If a section here conflicts with explicit user instructions, prefer the user
instructions for the current task.

---

## Project overview

`github.com/snaplink/sso` is a Go SSO server SDK plus a runnable binary.
It implements OAuth 2.0 + OIDC + a swappable authenticator set + audit +
permissions + service registry + admin gRPC/REST plane + snapshot &
release lifecycle. Every concern is an interface; every default backend
is in `defaultimpl/` (memory) or `defaultimpl/sqlite/`. There is no
external SaaS dependency. The consumer-facing `ssoclient/` package lets
each app pick **embedded** (in-process via `ssoclient/local`) or
**centralized** (gRPC + JWKS via `ssoclient/remote`) per capability —
same business code, two deployment shapes.

---

## Repository layout

```
.
├── sso.go / handler.go / router.go    Core Server, HandlerContext, routing
├── consts.go                          All literals (paths, headers, error codes)
├── handle_*.go                        Per-endpoint HTTP handlers
├── oauth_bind.go                      form+JSON dispatcher for OAuth endpoints
├── *.go (root)                        AuthCode/Refresh/PAR/Device/etc. types + options
├── authenticators/                    7 pluggable AuthN implementations
├── defaultimpl/                       Default TokenIssuer + Memory* stores
│   └── sqlite/                        Pure-Go SQLite stores (no CGO)
├── adapters/{echo,gin}/               Router adapters for the Handler
├── audit/                             Recorder + Sinks + optional hash chain
├── permissions/                       Roles + menus + wildcard matcher + resources
├── netpolicy/{memory,etcd}/           Network-classification control plane
├── registry/{memory,etcd}/            Service discovery
├── bootstrap/{file,memory,builtin,lock}/  Versioned first-run init + dist lock
├── snapshot/{storage,encryption,loader}/  Export/restore admin-managed state
├── releases/{store,pinner,probe}/     Frontend+backend release pinning
├── geo/{static}/                      IP → country/region/lang enrichment
├── tenant/{memory}/                   Multi-tenant + multi-domain routing
├── metrics/  tracing/  ratelimit/  cors/   Middleware
├── config/{etcd}/                     YAML + env + etcd + flag multi-source loader
├── proto/  +  gen/proto/              Protobuf sources + generated Go
├── grpcserver/                        gRPC services + REST gateway impls
├── ssoclient/{local,remote,dev,bootstrap}/  Consumer-facing clients
├── cmd/sso-server/                    Production binary (config.yaml lives here)
├── deploy/{openresty,k8s,compose,grafana}/  Operator artifacts
└── examples/{basic,grpc-client,embedded-app,remote-app,appcore}/
```

`examples/embedded-app` and `examples/remote-app` share **exactly** the
same `appcore.Handler` — only the wiring differs. That is the demo of
the ssoclient local/remote split.

---

## Setup, build, test

```bash
go build ./...
go run ./cmd/sso-server --config cmd/sso-server/config.yaml
go run ./cmd/sso-server --config cmd/sso-server/config.yaml \
  --listen :18080 --grpc-listen :18081
go run ./cmd/sso-server --config cmd/sso-server/config.yaml --grpc-listen ""

# Makefile mirrors CI:
make build      # bin/sso-server
make ci         # gofmt + vet + race + build + proto-lint
make docker     # snaplink/sso-server:dev image (distroless)
make docs-validate  docs-serve
make release-check  release-snapshot   # dist/ multi-OS/multi-arch (no publish)

# In-cluster: kubectl apply -k deploy/k8s/

go vet ./...
go test ./...
go test -race ./...
go test -run TestE2E -v .                 # cross-wire E2E (HTTP + JWKS + bufconn gRPC)
go test -run TestX -count=10 ./pkg/...    # flake hunt
```

The E2E suite (`e2e_test.go`, package `sso_test`) stands up an httptest
`sso.Server` + bufconn gRPC and drives `examples/appcore.Handler`
through `ssoclient/remote`. **Run it whenever you change anything that
crosses the gRPC or JWKS wire.**

Regenerate protobuf code (rarely needed; stubs are checked in):

```bash
protoc -I proto \
  --go_out=gen/proto --go_opt=paths=source_relative \
  --go-grpc_out=gen/proto --go-grpc_opt=paths=source_relative \
  proto/<svc>/v1/<svc>.proto
```

---

## Architecture rules

These are the invariants that touch many files; respect them when
adding code.

### Plugin SPI pattern
Every concern (TokenIssuer, AuthCodeStore, RefreshTokenStore,
DeviceCodeStore, PARStore, ClientStore, UserProvider, SessionManager,
permissions.Provider, registry.Registry, netpolicy.Store, audit.Sink,
geo.Provider, tenant.Store, RiskScorer, ReadyCheck, ratelimit.Limiter,
release.Pinner, snapshot.Storage / Codec / Sealer, bootstrap.Lock) is a
Go interface in the parent package + a `memory` impl + optionally a
`sqlite` / `etcd` / `file` impl. New backends slot in via `WithXxx`
options. **Don't introduce mocks** — use the Memory* impl in tests.

### Storage backends today
Memory (default) or SQLite (`defaultimpl/sqlite/`) for User / AuthCode /
RefreshToken / DeviceCode. Everything else (PAR, Session, Client,
RateLimiter, RefreshTokenFamily) is memory-only. **Multi-replica
deployments break OAuth flows** until those grow distributed backends:
a code minted on replica A is not consumable on replica B.

### Wire format: form OR JSON via `bindOAuthParams`
All OAuth/OIDC endpoints (`/token`, `/token/introspect`, `/token/revoke`,
`/device/code`, `/device/verify`, `/par`) accept both
`application/x-www-form-urlencoded` and `application/json` bodies. RFC
6749 §3.2 etc. mandate form-encoded — JSON-only would be incompatible
with every off-the-shelf OAuth library. The dispatcher is in
`oauth_bind.go`; it decodes into the same struct via `json:"..."` tags.

### HTTP Basic > body credentials (RFC 6749 §2.3.1)
On `/token`, `/token/introspect`, `/token/revoke`, `/par`, if both an
`Authorization: Basic ...` header AND `client_id` + `client_secret`
appear in the body, **Basic wins**. Tests cover this precedence on
every endpoint.

### Oracle-leak hardening
For single-use-code consumption (AuthCode / Refresh / Device / PAR /
PKCE verifier), **never distinguish unknown vs expired vs consumed
vs client-mismatch** on the wire — all collapse to `400 invalid_grant`
(or `invalid_request_uri` / `invalid_pkce_method` per endpoint). RFC
6749 §5.2, RFC 7636 §4.6, RFC 7662 §2.2, RFC 7009 §2.2 all spell this
out. Tests enumerate the failure cases to lock the behavior.

### Anti-enumeration on identifier endpoints
- `/register/:client_id` (RFC 7592): missing bearer / wrong bearer /
  unknown client_id all return **401 invalid_token identically** — no
  404. Otherwise an unauth'd caller could probe for client_id
  existence. Bearer compare uses `crypto/subtle.ConstantTimeCompare`.
- `/token/revoke` (RFC 7009 §2.2): always 200 OK on valid client
  credentials regardless of whether the token existed.
- `/token/introspect` inactive path returns `{"active":false}` ONLY —
  no claims leak.

### Fail-open vs fail-closed
- **Fail-open** (log + continue): refresh-token issuance during
  `/auth/login` or `/token grant=authorization_code` exchange,
  ID-Token issuance, geo lookup, risk scorer error, audit Sink error
  (don't drop the request because a sink hiccuped).
- **Fail-closed** (return error): refresh-token rotation grant
  itself (a rotation that can't mint the new pair returns 500),
  signature/validation failures, scope expansion, family-reuse
  detection (kills the whole family + 400 invalid_grant).

### PKCE binding is first-exchange only
`code_challenge` captured at `/auth/login` is verified against
`code_verifier` at `/token grant=authorization_code`. Subsequent
`refresh_token` rotations carry no verifier; the chain is bound
independently by the `client_id` check on the refresh token.

### Refresh token family rotation (OAuth Security BCP §4.13/§4.14)
Every refresh token carries a `FamilyID` stamped at first issue and
propagated unchanged through every rotation. Stores opt into reuse
detection by implementing `RefreshTokenFamilyTracker`. A `Consume` of
a previously-consumed token returns `ErrRefreshTokenReused`; the
rotation grant catches it, calls `DeleteFamily(fid)` to invalidate
all siblings/descendants, emits
`refresh_token_reuse_detected` audit, returns `invalid_grant`.
Empty `FamilyID` opts out.

### Audit metadata: use `setMeta(e, k, v)`
The geo + tenant middleware enrich every event with `geo.*` +
`tenant.*` keys via `Event.Metadata`. **Do not** write
`e.Metadata = map{...}` — that clobbers the enrichment. Always use
`setMeta(e, k, v)` (or equivalent). Audit consumers can rely on
presence rather than value of those keys.

### X-Forwarded-* trust assumption
`requestBaseURL` (OIDC discovery), `DefaultGeoIPExtractor`, and
`DefaultHostExtractor` (tenant) all honor `X-Forwarded-Proto` /
`X-Forwarded-Host` / `X-Forwarded-For` first-hop. This is correct
**ONLY** when a known edge proxy strips and re-sets them.
Internet-facing deployments without a trusted edge MUST install a
stricter middleware — otherwise the discovery doc can be made to
advertise the wrong scheme, geo can be spoofed, tenant routing can
be flipped. The standard answer is a `TrustedProxies(CIDR...)`
allowlist in front of these extractors.

### `aud` claim parsing
Per RFC 7519 §4.1.3, `aud` may be a string or an array. The
`Ed25519JWTIssuer.Validate` path uses the `audClaim` type that
unmarshals either shape and marshals single-aud as a compact string
per OIDC convention. Don't reintroduce array-only parsing — OIDC ID
tokens always use string form.

### `alg` + `typ` allowlist on Validate (RFC 9068 §4)
Header `alg` MUST be in `supportedJWTAlgs` (EdDSA today) and `typ`
MUST be in `supportedJWTTypes` (`at+jwt` / `application/at+jwt` /
`JWT` for legacy back-compat) — checked BEFORE signature verify so
alg-confusion attacks (alg=none, wrong-key-shape spoofs) fail
early. When adding a new signer, add its alg to the allowlist
explicitly — don't loosen the check.

### RFC 9068 access-token claim population
`Subject.ClientID` / `AuthTime` / `AMR` / `ACR` are the
populate-at-issue claim sources for RFC 9068. Every Issue call site
in handler.go + handle_token_exchange.go + handle_device.go MUST set
`ClientID` (it's REQUIRED by §2.2); login + auth_code + device set
`AuthTime` + `AMR` from the live auth event; refresh propagates the
original `AMR` without resetting `AuthTime` (rotations don't
represent a fresh authentication); token-exchange propagates
`AuthTime` + `ACR` + `AMR` from the inbound subject_token's claims
so downstream services see the original factor strength;
client_credentials populates ClientID only (no end-user event).
`jti` is always auto-generated (16-byte base64url).

### Discovery is derived, not declared
`/.well-known/openid-configuration` is computed dynamically from
server state: endpoints from request base URL, issuer from
`WithIssuer`, grant_types from `SupportedGrants`, scopes from the
union of `openid` + every client's `AllowedScopes`, signing algs
from the wired ID token issuer, `pushed_authorization_request_endpoint`
when `WithPARStore` is wired, `registration_endpoint` when
`WithDynamicClientRegistration` is wired, `end_session_endpoint`
always, `authorization_response_iss_parameter_supported: true`
always (RFC 9207). Adding a new opt-in feature → also branch the
discovery doc.

### `iss` on authorization responses (RFC 9207)
Every `/auth/login` JSON response — success, error, and the empty-
provider "list providers" probe — carries `iss` via
`s.resolveIssuer(ctx)`. `resolveIssuer` returns `WithIssuer` value
if set, else `requestBaseURL(r)` — **identical** to the discovery
doc's `issuer` field. That equality is the load-bearing invariant
that makes mix-up attack defense work; tests assert it directly.
New authorization-flow handlers MUST use `s.authzErrorBody(ctx, code)`
/ `s.authzErrorBodyDesc(ctx, code, desc)` for error responses (NOT
plain `errorBody` — that's reserved for non-authorization endpoints
like `/token`, `/userinfo`, `/auth/callback`).

### JWKS caching
`/.well-known/jwks.json` sets `Cache-Control: public, max-age=300`
and a strong `ETag = sha256(body)[:8]` base64url. RPs that send
`If-None-Match` get `304 Not Modified`. ETag is recomputed
deterministically every request so cache correctness survives a
server restart. During rotation, BOTH outgoing and incoming keys are
served so RPs that hold pre-rotation tokens can still verify until
expiry.

---

## OAuth 2.0 / OIDC — implemented standards

One row per RFC; each one points at the file that owns it. The
gotchas above (oracle-leak, anti-enumeration, fail-open) apply across
every grant.

| Spec | Endpoint(s) | Opt-in | File | Notes |
|---|---|---|---|---|
| RFC 6749 §4.1 authorization_code | `/auth/login` + `/token` | `WithAuthCodeStore(store, ttl)` | `auth_code.go` | redirect_uri allowlist; single-use; default TTL 10 min |
| RFC 6749 §4.4 client_credentials | `/token` | always | `handle_token_*.go` | no end-user → no refresh, no ID token |
| RFC 6749 §6 refresh_token | `/token` | `WithRefreshTokenStore(store, ttl)` | `refresh_token.go` | rotation pattern; family tracking optional via `RefreshTokenFamilyTracker`; default TTL 30 days |
| RFC 7636 PKCE | param on /auth/login + /token | per-request, or per-client via `Client.RequirePKCE` | `auth_code.go` | S256 + plain; verifier compared in constant time; first-exchange binding only |
| RFC 7662 introspection | `/token/introspect` | always | `handle_introspect.go` | inactive → `{"active":false}` only; `RefreshTokenInspector` extension for refresh tier |
| RFC 7009 revocation | `/token/revoke`, `/token/revoke-all` | always (bulk needs `RefreshTokenSubjectIndex`) | `handle_revoke.go` | always 200 OK; `revoke-all` is bearer-authed user logout |
| RFC 8628 device authorization | `/device/code`, `/device/verify`, `/token` grant | `WithDeviceCodeStore(store, ttl, pollMin, verifyBaseURL)` | `handle_device.go` | user_code normalized (dashless+uppercase); `slow_down` enforced |
| RFC 8693 token exchange | `/token` grant `urn:...:token-exchange` | always; refresh-token output needs `WithRefreshTokenStore` | `handle_token_exchange.go` | only access_token/jwt subject types in v1; scope narrowing per §6; `act` claim stamps the actor when `actor_token` is supplied (§4.1) AND nests across multi-hop chains (§4.1.1) — outermost = most recent actor, deepest = first to delegate. Output: `requested_token_type=access_token` (default) mints just an access token; `requested_token_type=refresh_token` ALSO mints a refresh token alongside (`issued_token_type` field reflects which was the requested type per §2.2.1). The exchanged refresh token is rotatable via the standard refresh grant — full single-use semantics. SID + AMR + AuthTime + ACR propagate from the inbound subject_token so the rotated chain inherits the original authorization context. Without `WithRefreshTokenStore` wired, refresh-output requests fail upfront with `refresh_token_not_configured`. SAML2 / id_token output remains future-scope |
| RFC 8707 resource indicators | `resource` param on every issuance path | `Client.AllowedResources` allowlist | per-grant | captured-at-authorization wins on rotation/exchange |
| RFC 9126 PAR | `/par` | `WithPARStore(store, ttl)` | `handle_par.go` | request_uri `urn:ietf:params:oauth:request_uri:<token>`; single-use; default TTL 90s |
| RFC 7591 dynamic client registration | `/register` | `WithDynamicClientRegistration(policy)` | `handle_register.go` | initial access token OR `AllowOpenRegistration: true`; public clients force `RequirePKCE=true` |
| RFC 7592 dynamic client management | `/register/:client_id` (GET/PUT/DELETE) | same as 7591 | `handle_register.go` | bearer compare constant-time; PUT preserves secret + registration_access_token |
| OIDC Core ID Token | `id_token` in token responses with `openid` scope | `WithIDTokenIssuer(issuer)` | `oidc.go` | nonce echoed per §3.1.3.7; UserInfo scope→claim filter per §5.4 |
| OIDC Discovery 1.0 | `/.well-known/openid-configuration` | always | `oidc_discovery.go` | derived from server state (see above) |
| OIDC RP-Initiated Logout 1.0 | `/end_session` | always | `handle_end_session.go` | id_token_hint signature MUST verify; post_logout_redirect_uri exact-match allowlist; unknown URI → 204 no Location |
| OIDC Back-Channel Logout 1.0 | `/logout`, `/end_session` | `WithBackchannelLogout(issuer, notifier)`; multi-RP fan-out adds `WithSubjectClientIndex(idx)` | `backchannel_logout.go` + `subject_client_index.go` | POSTs signed `logout_token` (typ=logout+jwt + events claim) to every relevant `Client.BackchannelLogoutURI`; carries `sid` claim when the inbound bearer / id_token_hint had one. Without `SubjectClientIndex`: notifies only the client present in the bearer / id_token_hint (single-RP, backwards compatible). With it: every (subject → client_id) pair recorded at token-mint time is iterated and notified at logout — true single sign-out across all of a user's active RPs. After a successful notification the (subject, client) pair is `Forget`ten so subsequent no-op logouts don't re-notify. Fail-open: notify failures logged + audited, never block the logout response. `backchannel_logout_session_supported: true` advertised in discovery when `WithSessionManager` is wired (sid is sourced from the session manager) |
| OIDC Front-Channel Logout 1.0 | `/end_session` | per-client via `Client.FrontchannelLogoutURI` | `frontchannel_logout.go` | when the resolved client opts in, `/end_session` renders an HTML page with a hidden iframe pointing at the RP's logout URI (browser-fired session-cookie clear); meta-refresh navigates to `post_logout_redirect_uri` after 2s when allowlisted; HTML hardened with `X-Frame-Options: DENY` + `no-store` + `no-referrer`; `frontchannel_logout_supported` advertised in discovery when any client opts in; `frontchannel_logout_session_supported: true` when `WithSessionManager` is wired (sid plumbing now active across access + id tokens); single-RP only today (same scope as BCL) |
| OIDC Core §2 `sid` claim | access tokens + id tokens + logout tokens | `WithSessionManager` (sid source) | `defaultimpl/ed25519_jwt_issuer.go` + `handler.go` | `sid` = SessionManager-assigned session id; stamped at login (direct mint), propagated through refresh-token rotation (`RefreshToken.SID`), preserved on `prompt=none` silent renewal, threaded into logout tokens from `id_token_hint.sid` at `/end_session`. Empty on grants with no end-user session (`client_credentials`, device flow w/o session, code flow until session plumbing extends — see Subject.SID comment) |
| Per-account lockout | `/auth/login` (server-wide) | `WithAccountLockout(AccountLockout)` | `account_lockout.go` | sliding-window failure counter keyed on `<clientID>:<identifier>` (username/target/identifier/phone/email from credential map); locks at threshold; auto-unlocks after duration; successful login clears counter; complements (not replaces) the IP rate limiter; off by default — opt-in via `NewMemoryAccountLockout()` or a custom impl |
| OIDC UserInfo | `/userinfo` | needs ID token issuer wired | `oidc.go` | claim projection driven by access token's `scope` |
| OIDC Core §3.1.2.1 `login_hint` | `/auth/login`, `/par`, JAR JWT | always accepted; pushed through PAR (PAR wins on conflict, same precedence as scope / redirect_uri) and merged from JAR JWT claims | `handler.go` + `par.go` + `jar.go` | RP's hint about the End-User's identifier (email / phone / account name) threaded into `AuthRequest.LoginHint` so authenticators can pre-fill UI or pre-validate credentials. No format enforcement (RFC keeps it free-form) — authenticators decide what to do with non-matching hints |
| OIDC Form Post Response Mode 1.0 | `/auth/login` (`response_type=code`), `/par`, JAR JWT | always accepted (`response_mode=form_post`) | `form_post_response_mode.go` | When the RP sets `response_mode=form_post`, the code-flow success path returns an HTML page (auto-POSTs to `redirect_uri` via `<body onload=...>`) instead of the JSON body — for RPs that prefer parsing POST bodies over fragment/query parameters or that need larger payloads than URL length limits permit. Hardened with `X-Frame-Options: DENY` + `Cache-Control: no-store` + `Referrer-Policy: no-referrer`. All hidden-field values pass through html/template auto-escaping so untrusted `state` can't break out of the attribute context. `<noscript>` block degrades to a manual Continue button. Unknown response_mode rejected with `invalid_request`. PAR-pushed `response_mode` overrides any caller-supplied value at the redirect (same precedence as scope / login_hint). Discovery advertises `response_modes_supported: ["query", "fragment", "form_post"]` |
| RFC 7521 + RFC 7523 JWT bearer client authentication (`private_key_jwt`) | `/token`, `/par`, `/token/introspect`, `/token/revoke` | `Client.JWKS` (per-client opt-in, same JWK set JAR uses) | `jwt_client_assertion.go` | Clients authenticate by signing a JWT instead of presenting `client_secret`. Request shape: `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` + `client_assertion=<JWT>`. JWT MUST have `iss==sub==client_id`, `aud` MUST include AS issuer, `exp` MUST be within `DefaultClientAssertionMaxLifetime` (5m), `kid` selects the verification key from `Client.JWKS`. EdDSA only today (matches JAR). Replay defense reuses `JTIReplayStore` when wired. When assertion authenticates the request, the `client_secret` check is skipped entirely (RFC 7521 §4.2 forbids requiring both). Failures collapse to `invalid_client` (oracle-resistance). Discovery advertises `private_key_jwt` in `token_endpoint_auth_methods_supported`. SAML2 bearer assertion type rejected with `invalid_request` |
| OIDC Core §3.1.2.1 `prompt=none` (silent auth) | `/auth/login` | needs `WithSessionManager` (gate) + `WithIDTokenIssuer` (hint validation) | `prompt.go` | RP loads /auth/login in a hidden iframe with `prompt=none` + `id_token_hint`; server validates the hint signature, asserts the hint's client matches the requesting client (cross-RP confused-deputy defense), asserts `SessionManager.ListByUser(sub)` returns at least one live (non-revoked, non-expired) session, then mints a fresh access + id token reusing `auth_time` / `amr` / `acr` from the original — silent renewal is NOT a fresh end-user auth event, so downstream factor-strength signals are preserved. Failures collapse to `login_required` (bad-sig hint, no session, mismatched client — oracle-resistance). `prompt=none` combined with another value → `invalid_request`. Also honors `max_age`: when the RP sets the OIDC Core §3.1.2.1 max-auth-age, a silent renewal whose hint `auth_time` is older than `max_age` seconds returns `login_required` (the AS would need to re-authenticate, but `prompt=none` forbids UI). `max_age=0` collapses to "always reauthenticate". Discovery advertises `prompt_values_supported: ["none"]`. Interactive prompt values (`login` / `consent` / `select_account`) are accepted on the wire but currently fall through to the standard credential path — visible UIs aren't rendered by this server |
| RFC 9207 AS Issuer Identification | every `/auth/login` response (success + error + provider list) | always | `iss_response.go` | `iss` stamped via `s.resolveIssuer(ctx)`; must equal discovery `issuer` field — mix-up defense |
| RFC 9068 JWT Access Token Profile | access tokens minted by `Ed25519JWTIssuer` | always (single signer today) | `defaultimpl/ed25519_jwt_issuer.go` | header `typ: at+jwt`; jti always generated; client_id from `Subject.ClientID`; Validate enforces alg + typ allowlist (alg=none rejected); typ=JWT still accepted for legacy back-compat |
| RFC 8705 §3 mTLS-bound access tokens (issuance + resource-side) | `/token` (issuance) + `/userinfo` (verification) | `WithClientCertExtractor` (pluggable so reverse-proxy-terminated TLS works) | `mtls_bound.go` | **Issuance**: when the wired extractor returns a client cert from the inbound /token request, the issued access token's `cnf.x5t#S256` claim carries the cert's SHA-256 thumbprint per §3.1. **Resource**: when a token presented at /userinfo carries `cnf.x5t#S256`, the inbound connection's client cert MUST have the matching thumbprint — mismatch (or cert missing) collapses to `invalid_token` on the wire (oracle-resistance, same shape as DPoP failures). Token type stays `Bearer` per §3 (mTLS doesn't introduce a new type — the binding is implicit in the cnf claim). Mutually exclusive with DPoP at the caller level. Default extractor (`DefaultTLSPeerCertExtractor`) reads `r.TLS.PeerCertificates[0]`; envoy/nginx deployments inject a header-parsing extractor. Discovery: `tls_client_certificate_bound_access_tokens: true` when wired |
| RFC 9449 DPoP (issuance + resource-side) | `/token` (header `DPoP: <jwt>`) + `/userinfo` (header re-presented per request) | always accepted when header present (opt-in per request); JTI replay defense via `WithJTIReplayStore` | `dpop.go` | **Issuance**: client supplies a fresh signed JWT (typ=`dpop+jwt`, alg=EdDSA, header `jwk` carries the public key) on every /token call it wants bound. AS validates `htm` / `htu` / `iat` within ±60s window / `jti` (replay defense). On success: RFC 7638 SHA-256 JWK thumbprint stamped into `cnf.jkt` (RFC 7800), `token_type` response flips from `Bearer` to `DPoP`. **Resource**: when a token presented at /userinfo carries `cnf.jkt`, the request MUST also carry a fresh DPoP proof whose JWK thumbprint matches the bound value — mismatch collapses to `invalid_token` (oracle-resistance). Tokens without `cnf.jkt` keep the legacy bearer path with zero behavior change. Discovery advertises `dpop_signing_alg_values_supported: ["EdDSA"]`. Issuance-side failures collapse to `invalid_dpop_proof` per §5.2 |
| OAuth 2.1 strict mode | `/auth/login` (server-wide flag) | `WithOAuth21StrictMode(true)` | `handler.go` (`isSecureRedirectURI`) | rejects `response_type=token` (and empty); forces PKCE globally; requires https redirect_uri (localhost excepted). Default off → zero breaking change for OAuth 2.0 callers |
| RFC 9396 Rich Authorization Requests | `authorization_details` on `/auth/login` (direct mint + code flow) + `/par` (pushed) | per-client allowlist (always accepted; allowlist optional) | `rar.go` | preserved as `json.RawMessage` so extension fields pass through; `Client.AllowedAuthorizationDetailsTypes` allowlist enforces element `type` field at every entry point (PAR rejects upstream of the redirect when an allowlist is set); persists through PAR → /auth/login merge (PAR's payload beats caller-supplied at the redirect, same precedence as scope / redirect_uri), through AuthCode → exchanged access token, AND through `RefreshToken.AuthorizationDetails` on every rotation (multi-hop binding); discovery advertises union of all client allowlists. Device grant doesn't accept the parameter today |
| RFC 9101 JWT-Secured Authorization Request (JAR) | `request` (inline) + `request_uri` (URL-fetched) on `/auth/login` | `Client.JWKS` (per-client opt-in); JTI replay defense per RFC 9101 §10.8 enabled by `WithJTIReplayStore`; URL-fetched variant enabled by `WithJARFetcher` + per-client `AllowedRequestURIs` allowlist | `jar.go` + `jar_fetch.go` + `jti_replay.go` | client signs the authorization request as a JWT; server picks the verification key by `kid` from header against `Client.JWKS`; merges JWT claims into the request with JWT taking precedence (matches PAR's merge semantics); JWT `aud` MUST include AS issuer (mix-up defense), `iss` SHOULD equal client_id, `client_id` claim MUST match the outside one; EdDSA only today; when a `JTIReplayStore` is wired AND the JWT carries a non-empty `jti`, the store's `MarkSeen` atomically rejects a second use within the JWT's `exp` window (or `DefaultJTIReplayWindow` when `exp` is absent) — store errors fail open with a log line, empty `jti` skips the check (RFC keeps it OPTIONAL). The URL-fetched variant (§5.2.2) routes `request_uri=https://...` through `JARFetcher.Fetch` BEFORE the merge — the fetched body goes through full signature verification just like inline `request`. SSRF defense: per-client `Client.AllowedRequestURIs` exact-match allowlist (empty = denied), HTTPS-only, redirects disabled, 5s timeout, 16KB body cap. The `urn:ietf:params:oauth:request_uri:` prefix still routes to PAR (distinguished by scheme). Discovery: `request_parameter_supported: true`, `request_uri_parameter_supported: true` when JAR fetcher wired |

**Token strategies** are picked per-client via
`token_strategy: jwt|session`:

- `TokenStrategyJWT` — Ed25519, JWKS-publishable, stateless verify.
  Pass the same `Ed25519JWTIssuer` instance to both `WithTokenIssuer`
  and `WithIDTokenIssuer` so one signing key covers both token types.
- `TokenStrategySession` — opaque token backed by `SessionManager`.

The Server resolves `TokenIssuer` by the client's strategy name
registered via `sso.WithTokenIssuer(name, issuer)`. Custom strategies
slot in the same way.

---

## Subsystems

Each block lists what's already implemented and only the
non-obvious facts. For "how to wire", grep `WithXxx` in `sso.go`.

### Authenticators (`authenticators/`)

7 pluggable implementations of `sso.Authenticator`:

| Method | Use case | Constructor |
|---|---|---|
| `password` | Classic web login | `NewPasswordAuthenticator(verifier)` |
| `phone` | SMS code | `NewPhoneAuthenticator(codeStore, smsSender)` |
| `email` | Email code | `NewEmailAuthenticator(codeStore, emailSender)` |
| `temp_token` | One-time link / magic token | `NewTempTokenAuthenticator(store, ttl)` |
| `keypair` | Ed25519 service-to-service | `NewKeyPairAuthenticator(pubKeyStore, skew)` |
| `apikey` | Long-lived service credential | `NewAPIKeyAuthenticator(store)` |
| `certificate` | mTLS / X.509 | `NewCertificateAuthenticator(rootPool)` |
| `totp` | RFC 6238 Time-based OTP (Google Authenticator / 1Password / Authy) | `NewTOTPAuthenticator(store)` |

A client's `allowed_authenticators:` allowlist gates which methods
the client may use. TOTP (RFC 6238) is the first human-MFA method
shipped — WebAuthn / Passkey support and upstream IdP federation
(Google / Okta / SAML) remain on the ROADMAP.

### Persistence — SQLite (`defaultimpl/sqlite/`)

Pure-Go via `modernc.org/sqlite` — no CGO, distroless/static-image
compatible. Four backends today: `UserProvider`, `AuthCodeStore`,
`RefreshTokenStore` (+ `RefreshTokenInspector` + `FamilyTracker`),
`DeviceCodeStore`. The three single-use-code stores use
`DELETE ... RETURNING` (SQLite 3.35+) for true single-use atomicity —
the standard SELECT-then-DELETE has a race.

DSN cookbook:

| DSN | Use |
|---|---|
| `file:/var/lib/sso/sso.db?_journal=WAL&_busy_timeout=5000` | Production single-node |
| `:memory:` | Per-connection in-memory (each conn = isolated DB) |
| `file::memory:?cache=shared` | Shared in-memory across pool (right for tests) |

Schema migration is `CREATE TABLE IF NOT EXISTS` at construction.
When a multi-table SQL backend lands, it MUST bring a real migration
runner (goose/golang-migrate). Pattern for new SQL Providers:
`New<Provider>(dsn)` opens+migrates+returns; `Close()` releases;
`New<Provider>WithDB(db)` for shared-pool deployments;
`sql.ErrNoRows` → typed `ErrNoSuchX`; timestamps as INTEGER Unix
nanoseconds.

### Audit (`audit/`)

`audit.Recorder` fans Events out to one or more `Sink`s. Built-in:
`MemorySink(cap)` (ring buffer, queryable via
`GET /api/v1/audit/events`), `WriterSink(w)`, `WebhookSink(url)`,
`MultiSink(sinks...)`.

Every Event carries W3C `TraceID` / `SpanID` / `ParentSpanID` so
audit records correlate with traces without OpenTelemetry as a
dependency.

**Hash chain (opt-in)**: `audit.New(sink, audit.WithHashChain())`
stamps `PrevHash` + `Hash` (sha256 over canonical JSON) on every
event. `audit.VerifyChain(events)` validates — expects events in
chain order (oldest first); `MemorySink` returns newest-first by
default. Caveats: in-process only (restart = new genesis), the
*last* event isn't detectable from the chain alone (needs external
attestation), reordering fields in `Event` rotates every chain.

**PII redaction (opt-in)**: `audit.WithRedactor(r)` runs BEFORE
the chainer so the chain validates over the redacted form (a
SIEM verifier doesn't need pre-redaction values). Built-in
helpers: `RedactActorIDHash(salt)` (sha256-16-byte prefix; salt
REQUIRED), `RedactIPTruncate` (v4 → /24, v6 → /48), `RedactUserAgent`
(clear), `RedactMetadataKeys(...)` + `RedactMetadataKeyPrefixes(...)`,
`DefaultPIIRedactor(salt)` (composes the first three). Mutate
in place — fast, simple, ownership transferred at `Record`.

### Permissions (`permissions/`)

`permissions.Provider` is the storage interface. `MemoryProvider`
gives: per-APP role registries (different clients can name different
role codes), wildcard matcher (`user:*` matches `user:read`, `*`
matches all), menu tree filtering (branches the user can't see are
pruned), login response embedding via
`WithEmbedPermissionsInLogin()` so SPAs don't need a second roundtrip.
`MenuLister` is the optional extension snapshots / admin RPCs use.

### Service registry (`registry/`)

`Registry` interface with two backends: `registry/memory` (in-process,
TTL eviction, Watch fan-out) and `registry/etcd` (etcd v3 client +
lease + automatic KeepAlive). `cmd/sso-server` self-registers under
`Name: "sso"` in whichever registry is wired.

### gRPC services (`proto/` + `grpcserver/`)

Four service families (auto-generated REST gateway sits beside each):

| Family | Services | REST prefix |
|---|---|---|
| Phase A (core) | `audit.v1.AuditWriter`, `authz.v1.Authorizer`, `discovery.v1.Discovery` | — (gRPC only) |
| Phase B (netpolicy) | `netpolicy.v1.PolicyService` | `/api/v1/netpolicy/` |
| Phase C (admin) | `admin.v1.{Client,User,Token,Permission}AdminService` | `/api/v1/admin/` |
| Phase D | `admin.v1.{Snapshot,Release}AdminService` | `/api/v1/admin/{snapshots,releases}` |

The gRPC services **reuse the same audit.Recorder / permissions.Provider
/ registry.Registry instances the HTTP layer uses** — no business-logic
duplication.

Admin auth: `sso.AdminMiddleware` validates Bearer via
`(*sso.Server).ValidateToken`, requires `admin:read` for
List/Get/Search and `admin:write` for everything else (`admin:*`
matches both), stashes actor in context via `AdminActorFromContext`.
Every mutation emits an `admin_*` audit event.

`Discovery.Watch` flushes initial headers via `SendHeader` once the
registry subscription is live — clients block on `stream.Header()`
before issuing mutations whose events they expect to receive.

### Network policy (`netpolicy/`)

Named classes of network (intranet, public, dmz, …) each with CIDRs +
hostnames + URLs to advertise back. Classifier applies **hostname-beats-
CIDR, priority-breaks-ties**. `Store` = persistence + Watch; `Classifier`
= hot priority-sorted snapshot subscribed to Watch via `Classifier.Start`
(synchronous subscribe before the seed Reload to avoid lost events).
HTTP at `/api/v1/netpolicy/{policies,classify,resolve-me}`; gRPC at
`netpolicy.v1.PolicyService`. Server-side helper:
`(*sso.Server).ClassifyRequest(r) *Policy`.

### Bootstrap (`bootstrap/`)

Versioned first-run init for both the SDK AND consumer apps.
`bootstrap.Step` = `Name()/Version()/Run(ctx)`; the Runner only re-runs
steps with `Version > tracker high-water mark`. Trackers:
`bootstrap/memory` (tests), `bootstrap/file` (atomic-rename JSON;
default for single-node). Distributed lock SPI in `bootstrap/lock/`
with `noop` / `file` (flock) / `etcd` (lease + Txn) backends; wired
via `WithLock`+`WithLockTTL`+`WithLockBlocking`. Lock loss → cancels
in-flight Steps + surfaces `ErrLockLost`.

Built-in `bootstrap/builtin/` Steps under namespace `"sso-server"`:

| v | Name | Effect |
|---|---|---|
| 1 | `seed_admin_role` | creates `sso-admin` role with `admin:*` permission |
| 2 | `seed_admin_user` | creates `admin` user, prints generated password ONCE to stdout |
| 3 | `seed_default_netpolicy` | registers "intranet" RFC1918 policy if none exist |
| 4 | `seed_admin_client` | creates `sso-admin` client (skipped if YAML already declares) |

Capture the admin password from the boot log — it's never re-emitted.

**Consumer-app helper**: `ssoclient/bootstrap` wraps file tracker +
namespaced runner. Namespace `"sso-server"` is reserved — pick
something else.

### Snapshot (`snapshot/`)

Export/restore the operator-managed state (clients, users, role
definitions, role assignments, menus, network policies, bootstrap
high-water mark).

SPI layers: `Snapshotter` pulls every wired backend's `List()`;
`Restorer` applies in dependency order with three modes
(`ModeMerge` insert-only, `ModeOverwrite` upsert, `ModeReplace`
wipe+seed — requires `Confirm == SnapshotID`). `DryRun: true`
returns counts with no mutations. `AdvanceBootstrap: true` bumps
the destination Tracker to the snapshot's recorded version.

Other SPIs: `Codec` (JSONCodec is canonical, schema version `"1"`);
`Sealer` (`encryption/none` typed no-op, `encryption/passphrase`
argon2id + XChaCha20-Poly1305 with OWASP-2024 defaults);
`Storage` (`storage/file` atomic+0o600, `storage/inline` in-memory);
`Pipeline` composes Codec+Sealer+Storage with sha256 verify via
`ErrChecksumMismatch`. `snapshot/loader.FromURI` parses
`file:///abs/path` + `inline:<base64>`.

Admin RPCs at `admin.v1.SnapshotAdminService` (`admin:*` gate). REST:
`POST/GET /api/v1/admin/snapshots`,
`GET/POST /api/v1/admin/snapshots/{id}[:restore]`,
`DELETE /api/v1/admin/snapshots/{id}`.

**First-boot auto-restore**: `snapshot.restore_from` YAML +
`--bootstrap-restore-from` CLI override. CLI wins. Runs via
`bootstrap/builtin.ApplyRestore` BEFORE the bootstrap Runner so
`AdvanceBootstrap=true` can bump the Tracker and skip seeds the
snapshot already covers. Mode defaults to Overwrite.

### Releases (`releases/`)

Admin app version pin / rollback. A `Release` pairs frontend +
backend `Artifact` halves so a deploy doesn't land mismatched
versions. `Validate` refuses one-sided releases.

`ReleaseStore` separates current-pointer from registration (pin is
one mutation, not a re-register). Backends: `memory`, `file`
(atomic+0o600).

`Pinner` has two methods — `PinForward` + `PinRollback` — to encode
the asymmetric ordering (backend-first forward, frontend-first
rollback). Backends: `noop`, `static` (atomic symlink swap of a
frontend bundle dir), `docker` (rewrite a managed `.env` + run
`docker compose pull && up -d`).

`Registry` composes Store+Pinner: Pinner runs first, only on success
does Store advance the current pointer. Forward Pin rejects schema
regression with `ErrSchemaRegress` — operators must use Rollback for
that direction.

Optional `HealthProbe` (e.g. `releases/probe/http`) gates forward Pin:
polls `ProbePolls × ProbeBackoff` after Pin; first nil result wins;
all-fail triggers auto-rollback. No probe runs on Rollback.

Optional `SnapshotRestorer` hook on Rollback: when the rollback
target's `ConfigSnapshot` is non-empty, restore that admin state
BEFORE flipping the Pinner. Restorer errors abort before Pinner.

Admin REST: `POST/GET /api/v1/admin/releases`,
`/api/v1/admin/releases:current`,
`/api/v1/admin/releases/{id}[:pin,:rollback]`. `GetCurrent` returns
empty (not error) when nothing pinned.

### Geo (`geo/`)

IP → geo enrichment as a **UX hint, NOT a security signal**.
`Lookup` runs under a 200ms timeout; `ErrNotFound` is non-fatal; nil
Provider makes the whole path no-op. `geo/static` is CIDR → GeoInfo
longest-prefix-match (tests + private RFC1918 overrides). A
`geo/maxmind` backend would stack behind the same interface.

Login response carries `country_code` + `recommended_language` when
the authenticator didn't supply a stronger signal. Every audit Event
gets `geo.country_code` / `geo.region` / `geo.city` /
`geo.recommended_language` keys in `Metadata` when the middleware
ran (presence-check friendly — only non-empty keys are projected).
**Use `setMeta` for new event metadata** so geo enrichment isn't
clobbered.

### Tenant (`tenant/`)

Multi-tenant + multi-domain routing. A `Tenant` is a business
boundary; a `Domain` is a hostname mapped to one Tenant. Hostname
normalized to lowercase + trailing-dot-stripped per RFC 1035.
**Tenant sits one level above `sso.Client`** — one tenant typically
owns multiple clients (admin-portal + customer-portal + mobile-API)
sharing one audit trail.

`sso.Client.TenantID` (YAML `tenant_id`): when set, login + token
endpoints reject requests whose resolved tenant doesn't match → 403
`tenant_mismatch` audited as `login_failure`. Empty = served from
any tenant (single-tenant + platform-admin clients keep working).

Optional `TenantScopedClientStore.ListByTenant(ctx, tenantID)`
extension for admin UIs that show "all clients owned by tenant X".

Suspended tenants resolve to "no tenant" by default
(`IncludeSuspended=true` flips this for maintenance pages). Every
audit Event gets `tenant.id` / `tenant.slug` / `tenant.domain` keys.

### ssoclient (the local/remote split)

```go
// Embedded — everything in-process:
handler := &appcore.Handler{
    Auth:  local.NewAuthClient(issuer, local.WithSessionManager(sessions)),
    Authz: local.NewAuthzClient(prov),
    Audit: local.NewAuditClient(recorder),
}

// Centralized — gRPC + JWKS:
handler := &appcore.Handler{
    Auth:  remote.NewAuthClient(remote.NewJWKSCache(jwksURL)),
    Authz: remote.NewAuthzClient(grpcConn),
    Audit: remote.NewAuditClient(grpcConn),
}
```

Each capability chooses independently. `remote.JWKSCache` does
periodic background refresh + single-flight refetch on unknown
`kid`, so key rotation lands within one extra HTTP RTT.

`ssoclient/dev` provides bypass stubs for local UI iteration:
`ValidateToken` returns a configurable fake Subject, `Check`
defaults to AllowAll, `Record` is a no-op. **Every constructor
emits a one-time stderr `AUTH BYPASS ACTIVE` warning** on first
non-silent call so accidental production use is loud. Suppress in
tests via `WithSilent` / `WithSilentAuthz` / `WithSilentAudit`.

### Edge integrations (`deploy/`)

- **OpenResty** (`deploy/openresty/`) — `lua-resty-jwt` verifies
  signature + exp/nbf from our `/.well-known/jwks.json`. Decoded
  `X-Auth-Subject` + `X-Auth-Scopes` forwarded downstream.
  `netpolicy_cache.lua` pulls policies, classifies the request,
  stamps `X-Network: <class>`. **Edge is fast-reject, not a trust
  boundary — the Go server still re-validates.**
- **Kubernetes** (`deploy/k8s/`) — Kustomize base with distroless
  pod security: `runAsNonRoot`, `readOnlyRootFilesystem`, drop ALL
  caps, `seccompProfile: RuntimeDefault`. `configMapGenerator`
  hashes the name so file edits trigger rolling restarts on next
  apply. Ingress / HPA / NetworkPolicy / PDB / ServiceMonitor are
  deferred to overlays (see `deploy/k8s/README.md`).
- **docker compose** (`deploy/compose/`) — sso-server + etcd, plus
  optional `--profile observability` (Prometheus + Grafana with
  the snaplink dashboard auto-provisioned). For onboarding +
  smoke tests, NOT production-grade.
- **Grafana** (`deploy/grafana/`) — `sso-overview.json` 12-panel
  dashboard with `$instance` template; `alerts.yaml` 6 rules (5xx
  rate, login failure rate / creds-stuffing, rate-limit
  saturation, p95 latency, risk scorer silent, instance down).
  All thresholds are starting points — tune to your baseline.

### Middleware stack

Order matters. The Server's `Handler()` chain when all options are
wired:

```
/metrics, /livez, /readyz   (registered OUTSIDE everything — never rate
                             limited, never counted, never body-capped)
  ↓
tracing (otelhttp span; honors W3C traceparent)
  ↓
ratelimit (token bucket; 429 with Retry-After; bots get rejected before
           risk scoring sees them)
  ↓
bodyLimit (Content-Length fast path + MaxBytesReader streaming guard)
  ↓
metrics (records count + duration AFTER limiters so 4xx/5xx are counted)
  ↓
CORS (Vary: Origin; preflight 204 short-circuits before routing;
       "*" + AllowCredentials degrades to echo Origin)
  ↓
router (registered handlers)
```

Wire each with `sso.With{Tracing, RateLimit, BodyLimit, Metrics,
CORS}`. Probe endpoints are **always served outside the stack** so
kubelet probes can't be throttled.

**Metrics** are bounded by design:

| Metric | Type | Labels |
|---|---|---|
| `sso_http_requests_total` | Counter | method, status_class |
| `sso_http_request_duration_seconds` | Histogram | method |
| `sso_login_attempts_total` | Counter | provider, outcome |
| `sso_tokens_issued_total` | Counter | strategy |
| `sso_risk_decisions_total` | Counter | decision |

Plus standard Go runtime + process collectors. `status_class` is
2xx/4xx/5xx, not raw code; `method` not path; `provider` not user
id. Per-endpoint breakdowns come from traces, not labels.

**Tracing** boots via `tracing.Init(ctx, ...)`; OTLP gRPC exporter
flips on with `OTEL_EXPORTER_OTLP_ENDPOINT=...`. Init is a no-op
when unset — zero exporter overhead.

**Ratelimit** policy: `Default` limiter + ordered `Prefixes`.
Keying default `KeyByClientIP` honors XFF/X-Real-IP/RemoteAddr —
**operators behind an untrusted edge MUST layer a TrustedProxies
check upstream**. Composes with `RiskScorer` — limiter rejects bot
traffic BEFORE scoring runs.

**ReadyCheck** is a pluggable SPI: any `WithReadyCheck(name, check)`
returning error → 503 from `/readyz`. Bounded by 3s context
deadline. Empty check list = always ready.

### Risk scoring (`risk.go`)

`sso.RiskScorer` runs on every `/auth/login` AFTER credential
validation but BEFORE token issuance. Returns `Allow` / `RequireMFA`
(reserved; treated as Allow today — see ROADMAP §2 for the step-up
flow) / `Deny` (HTTP 403 + audit `login_failure
reason=risk_denied`).

Two contract guarantees:
- **Fail-open** on scorer error (alert on "risk scorer failed" log).
- **Zero overhead** when option unset — nil check in `handleLogin`.

`defaultimpl.NoopRiskScorer` is the typed no-scoring stand-in.
`RiskRequest` carries subject id, client id, authenticator, remote
IP, UA, geo, timestamp. Scorers that need richer signals query their
own store from inside `Score` — don't pad the input struct.

---

## Configuration

`cmd/sso-server/config.yaml` is the reference. Top-level keys:

```yaml
server:        # listen, issuer, TTLs, default_token_strategy
logging:       # level: debug|info|error
audit:         # enabled, api_enabled, memory_capacity
permissions:   # apps[] (roles + menus per client_id), user_roles[], embed_in_login
network:       # enabled, api_enabled, store, policies[]
clients:       # per-APP id, secret, allowed_authenticators, token_strategy,
               # redirect_uris, post_logout_redirect_uris, allowed_resources,
               # require_pkce, tenant_id
authenticators: # per-method enable + tuning
admin:         # enabled, api_rest_enabled
bootstrap:     # disabled, state_path, admin_user_id, admin_client_id, admin_role_code
               # lock: { backend(noop|file|etcd), key, ttl, blocking, file.dir, etcd.endpoints }
snapshot:      # enabled, restore_from (URI; --bootstrap-restore-from overrides)
               # storage: { backend(file|inline), file.dir }
               # encryption: { backend(none|passphrase), passphrase, passphrase_file }
releases:      # enabled
               # store: { backend(file|memory), file.dir }
               # pinner: { backend(noop|static|docker), static.bundle_dir,
               #          docker.{bundle_dir, cmd} }
               # probe: { backend("" | http), http.url, polls, backoff }
               # snapshot_integration: bool — Rollback restores ConfigSnapshot
geo:           # enabled, backend(static), lookup_timeout
               # static.entries[]: { cidr, country_code, region, city, time_zone, recommended_language }
security:      # body_limit.max_bytes (0=off)
               # rate_limit: { enabled, default_per_sec, default_burst, prefixes[] }
               # cors: { enabled, allowed_origins[], allowed_methods[], allowed_headers[],
               #         exposed_headers[], allow_credentials, max_age }
tenant:        # enabled, backend(memory), lookup_timeout, include_suspended
               # tenants[]: { id, slug, name, status, settings }
               # domains[]: { hostname, tenant_id, default_client_id, is_apex, branding }
```

`client_id: ""` is a valid bucket (used by the demo so tokens
without `aud` still resolve to a role). Production tokens should
carry an explicit audience and key permissions under the real
client_id.

### Multi-source loader

`config.Loader` composes prioritized `Source`s (lowest priority first;
last source wins per key):

| Source | When |
|---|---|
| `config.NewFileSource(path)` | Baseline YAML at `--config` |
| `config.NewEnvSource()` | 12-factor overrides (`SSO_<UPPER>__...`) |
| `etcd.New(cfg)` | Centralized live config; opts in via `--etcd-endpoints` |
| `config.NewFlagSource(fs)` | Explicit CLI overrides via `Bind()` |

Maps deep-merge, scalars+slices overwrite. Leaf string values from
env/etcd run through `yaml.Unmarshal` so `"true"` → bool, `"42"`
→ int, `"5s"` falls through for downstream `time.Duration` parsing.
`config.Load(path)` is the legacy single-source entry point —
zero call sites had to change when the Loader landed.

---

## Release pipeline

`goreleaser` drives binary distribution. Configured in
`.goreleaser.yaml`; triggered from `.github/workflows/release.yml`
on `vX.Y.Z` tag push. Build matrix: linux+darwin × amd64+arm64,
plus windows/amd64. Each archive bundles LICENSE + SECURITY.md +
CHANGELOG.md; `checksums.txt` + per-archive syft SBOMs ship alongside.

Today `release.disable: true` short-circuits publish — CI runs the
full build+SBOM matrix without uploading. Flip to `false` once a
target is wired (GitHub Releases / container registry / cosign).
Locally: `make release-snapshot` runs the full matrix into `dist/`.

---

## API specifications

| Surface | Source of truth | Consumers |
|---|---|---|
| HTTP | `docs/openapi.yaml` (OpenAPI 3.0) | swagger-ui, Postman, ReadMe.io, OpenAPI Generator |
| gRPC | `proto/*.proto` | `protoc` / `buf generate`, BSR, grpc-gateway |

OpenAPI covers the core auth flow + self-service endpoints. The admin
REST surface, audit query, and netpolicy CRUD are not in OpenAPI yet —
additive layering only when added.

When you change a documented HTTP endpoint, update `docs/openapi.yaml`
in the same commit. CI runs `make docs-validate`.

`docs/error-codes.md` is the stable wire-contract catalog of every
`error` value the server can emit. SPAs branch on `error`, never on
`error_description`. **When you add a new `Err*` constant in
`consts.go`, update the catalog in the same commit.**

---

## Conventions

- **No literals leak** — all paths, headers, error codes, claim
  names live in root `consts.go` or the package's own `consts.go`.
  When a string is referenced from another file, add a constant.
- **No mocks for storage** — tests use the real `MemoryProvider` /
  `MemorySink` / `memory.Registry`. Mocks invite test-prod drift.
- **No emojis** in code, comments, or commits. Prose in chat is fine
  if the user uses them first.
- **Comments explain why, not what.** Identifiers carry "what".
  Reach for a comment only for hidden constraints, invariants, or
  workarounds a future reader would otherwise reverse-engineer.
- **Interface guards in implementation packages, not parent.** Use
  `var _ ssoclient.AuthClient = (*remote.AuthClient)(nil)` inside
  `ssoclient/remote/` — never in `ssoclient/` (import cycle).
- **gRPC field name renames** — protoc-gen-go does `ID → Id`,
  `URL → Url`. Refer to generated Go names in Go code, not .proto names.
- **Tests live in the same package as the behavior they test.** When
  fixing a race or ordering bug, prove the fix with `-count=10` or
  higher.

---

## Common tasks

### Add a new authenticator
1. Implement `sso.Authenticator` in `authenticators/<name>.go`.
2. Add the YAML knob under `authenticators:` in `config/config.go`.
3. Wire it in `cmd/sso-server/main.go`'s `buildAuthenticators`.
4. Whitelist under a client's `allowed_authenticators:` to test.

### Add a new audit Sink
1. Implement `audit.Sink` (one method: `Write(ctx, *Event) error`).
2. If it has lifecycle, also implement `audit.Closer`.
3. Wire via `audit.New(sink1, sink2, ...)` or `audit.MultiSink`.

### Add a new permission storage backend
1. Implement `permissions.Provider` in `permissions/<name>/`.
2. Plumb via `sso.WithPermissionProvider(...)`.
3. Keep the wildcard matcher semantics — `*` and `pkg:*` must match.

### Add a new network policy at runtime
1. `POST /api/v1/netpolicy/policies` (or gRPC `PolicyService.Apply`)
   with `{"name":..., "cidrs":[...], "hostnames":[...], "priority":...}`.
   Both transports mirror to audit automatically.
2. Watchers (OpenResty edge cache, in-process classifier) pick up the
   change via Watch — no restart.
3. To seed at boot, add to `network.policies:` in config.

### Add a new gRPC service
1. Write `proto/<name>/v1/<name>.proto`.
2. Regenerate (see Setup commands).
3. Implement the server in `grpcserver/<name>.go` over an interface
   the HTTP layer already uses — no business-logic duplication.
4. Register in `cmd/sso-server/main.go`'s `newGRPCServer`.
5. Add a `bufconn`-based test in `grpcserver/`.

### Add a new OAuth/OIDC grant
1. Add a handler in `handle_<grant>.go` using `bindOAuthParams` for
   the request body so form + JSON both work.
2. Honor HTTP Basic > body credentials on client auth.
3. Map errors to `400 invalid_<...>` sentinels — follow the
   oracle-leak hardening pattern (unknown / expired / consumed →
   identical wire response).
4. If single-use, use `DELETE ... RETURNING` (SQLite) or atomic
   delete-and-return semantics (Redis: `GETDEL`).
5. Wire it on the Server in `sso.go` (`s.router.POST(...)`) AND
   advertise in `oidc_discovery.go` AND add the option type with
   `WithXxxStore(store, ttl)`.
6. Tests in the same package; cover the oracle-leak failure cases by
   enumeration.

---

## Commit conventions

- Conventional Commits: `feat(area): summary`, `fix(area): summary`,
  `chore: summary`, `docs: summary`.
- Subject short and imperative; one blank line; body explains why.
- Co-author trailer when commits are AI-assisted.
- Don't commit binaries — `/sso-server` and `cmd/sso-server/sso-server`
  are ignored. If new top-level binaries appear, add to `.gitignore`.

---

## Things not to do

- Don't run `git reset --hard`, `git push --force`, or delete
  branches without explicit user authorization.
- Don't init or modify git config.
- Don't bypass pre-commit hooks (`--no-verify`, `--no-gpg-sign`).
- Don't introduce mocks where a real in-memory implementation exists.
- Don't add features, refactors, or "while I'm here" cleanup the
  user didn't ask for.
- Don't write Markdown files unless the user asked for them. (This
  file itself was explicitly requested. ROADMAP.md likewise.)
- Don't ignore the oracle-leak hardening pattern — it's a stability
  contract, not a stylistic choice. Failing it is a security
  regression.
- Don't bypass `setMeta` for audit event metadata — it clobbers the
  geo/tenant enrichment that downstream SIEM filters rely on.
