# AGENTS.md

Operational guide for AI agents. Follows [agents.md](https://agents.md).
User instructions override conflicts. **§2 invariants are gates, not
style — violating one is a regression.** §4 is a map, not a manual: it
points at the code; the code is the source of truth.

---

## 1. Orient

`github.com/snaplink/sso` — Go SSO server SDK + runnable binary: OAuth
2.0 + OIDC, swappable authenticators, audit, permissions, service
registry, admin gRPC/REST, snapshot + release lifecycle. Every concern
is an interface; defaults in `defaultimpl/` (memory) +
`defaultimpl/sqlite/` (pure-Go, no CGO). No external SaaS dep. Consumers
wire **embedded** (`ssoclient/local`) or **centralized**
(`ssoclient/remote`, gRPC + JWKS) per capability;
`examples/{embedded-app,remote-app}` share one `appcore.Handler`.

### Build, test

```bash
go build ./...
go test ./... -race
go test ./test/ -run TestE2E -v     # cross-wire HTTP + JWKS + bufconn
make ci                              # gofmt + vet + race + build + proto-lint
make docker | make release-snapshot
```

Run E2E whenever changing anything crossing the gRPC or JWKS wire.
Protobuf stubs are checked in (regen: `protoc -I proto --go_out=...
--go-grpc_out=... proto/<svc>/v1/<svc>.proto`).

### Layout

Root `package sso` is **6 non-test files**: `sso.go` (Server + Options +
routes), `handler.go` (login orchestrator), `handlers.go` (discovery +
delegators), `server_extensions.go` (Server-coupled DPoP/mTLS/JAR/JWE/
BCL/FCL/pairwise/tenant-susp/client-assertion/buildinfo), `accessors.go`
(field accessors backing the hexagonal `Deps` ifaces), `aliases.go`
(re-exports). Server-level integration tests live in `test/` (`package
ssotest`, full `*sso.Server` over HTTP on a shared harness — add new ones
there); subpackage unit tests sit beside their code; root keeps only a
few `package sso` unit tests (`example`, `header_client_cert_extractor`,
`jwks_singleflight`, `signing_algs`).

```
core/          Foundational types + SPIs (User/Client/Session/Token/Subject/
               AuthRequest/AuthResult/HandlerContext/Router/MiddlewareFunc +
               Authenticator/UserProvider/ClientStore/SessionManager/TokenIssuer/
               JWK/JWKSProvider + wire consts + sentinels)
oauth/         AuthCode/Device/Refresh/PAR stores, DCR+RAR+claims validators;
               Hexagonal handlers (HandleIntrospect/Revoke/PAR/Register/CIBA)
oidc/          ID Token SPIs (IDTokenIssuer/UserinfoSigner/MetadataSigner);
               Hexagonal handlers (JWKS/EndSession/SilentRenewal/FormPost/JARM)
security/      Lockout, JTI replay, JAR fetch/JWE, step-up, mTLS extractor,
               pairwise, subject-client index, ConstantTimeStringEq, QuoteAuthParam
spi/           Standalone SPIs: Logger, CodeSender, RiskScorer, MFAProvider
fapi/          FAPI 2.0 Validator (Inspection|Enforce) + baseline rules
anomaly/       Async behavioral-detection SPIs
cluster/       Cross-replica Bus (Publish/Subscribe) for cache invalidation; memory+etcd
middleware/    Auth, CORS, Logger, Tracing, RequestID, no-store, base-URL
admin/         Admin auth: HTTP middleware + gRPC interceptor + scope rules
tenant/ geo/   Tenant resolution + Geo enrichment middleware
authenticators/  9 pluggable + webauthn/ helper
defaultimpl/   Default issuers (Ed25519/ECDSA/RSA, each w/ CryptoSigner() stdlib
               seam) + Memory* stores + JWE (RSA/ECDH/Multi) + cryptosigner KMS
               bridge; /sqlite (pure-Go); /detectors; /vaulttransit (DEP-FREE
               net/http HashiCorp Vault transit crypto.Signer — HIBP precedent) (§3,§4)
authenticators/webauthn/  WebAuthn helper + AAGUID attestation policy + FIDO MDS (§3,§4)
region/{memory}/   IN-CORE multi-region / data-residency SPI + resolvers (§3,§4)
kms/awskms/    SEPARATE nested module — concrete AWS KMS crypto.Signer peer
               for the cryptosigner bridge (aws-sdk-go-v2 stays OUT of core go.mod) (§3,§4)
kms/gcpkms/    SEPARATE nested module — GCP Cloud KMS crypto.Signer peer; supports
               Ed25519 (cloud.google.com/go/kms stays OUT of core go.mod) (§3,§4)
kms/azurekeyvault/  SEPARATE nested module — Azure Key Vault crypto.Signer peer
               (azure-sdk-for-go stays OUT of core go.mod) (§3,§4)
kms/pkcs11/    SEPARATE nested module — PKCS#11 HSM/smart-card crypto.Signer peer,
               CGO (miekg/pkcs11 stays OUT of core go.mod) (§3,§4)
saml/          SEPARATE nested module — full SAML 2.0 SP+IdP (SSO+SLO), own
               importable Deps/HandlerSpec (crewjam/saml stays OUT of core go.mod) (§3,§4)
ldap/          SEPARATE nested module — LDAP/AD sso.Authenticator, search-then-bind
               over TLS (go-ldap/ldap/v3 stays OUT of core go.mod) (§3,§4)
kerberos/      SEPARATE nested module — SPNEGO/Kerberos Negotiate handler (Windows
               Integrated Auth) (gokrb5/v8 stays OUT of core go.mod) (§3,§4)
extauthz/      SEPARATE nested module — gRPC Envoy ext_authz over the in-core
               MeshAuthorize seam (go-control-plane stays OUT of core go.mod) (§3,§4)
redis/         SEPARATE nested module — Redis hot-path store peers (session/
               refresh/authcode/par/jti/ratelimit/device/mfa/ciba) for the
               >1k-QPS multi-replica scale layer; Lua/GETDEL/SETNX/INCR atomics
               (go-redis stays OUT of core go.mod) (§4)
adapters/{echo,gin}/   Router adapters
audit/         Recorder + Sinks + hash chain
permissions/   Roles + menus + wildcard matcher
compliance/    GDPR/CCPA/PIPL data-subject erasure + export (composes existing SPIs; no new store)
netpolicy/{memory,etcd}/   Network classification
registry/{memory,etcd}/    Service discovery
bootstrap/{file,memory,builtin,lock}/   First-run init + dist lock
snapshot/{storage,encryption,loader}/   State export/restore
releases/{store,pinner,probe}/   Frontend+backend release pinning
signingkeys/{memory,etcd}/   Opt-in leaderless multi-replica JWKS public-key aggregation (§3)
ratelimit/ cors/ metrics/ tracing/   Middleware + observability
config/{etcd}/   YAML + env + etcd + flag loader
proto/ gen/proto/ grpcserver/   Protobuf + generated Go + gRPC + REST gateway
ssoclient/{local,remote,dev,bootstrap}/   Consumer-facing clients
migrate/       Pure-Go SQLite migration runner (versioned, per-namespace, forward-only)
cmd/{sso-server,sso-audit-verify,sso-snapshotctl,sso-migrate}/   Binary + offline CLIs
deploy/{openresty,k8s,compose,grafana}/   Operator artifacts
test/          Server-level integration suite (package ssotest)
```

---

## 2. Wire-contract invariants

- **Plugin SPI + storage.** Every concern is an interface in its parent
  package + a `memory` impl + optionally `sqlite`/`etcd`/`file`; new
  backends slot in via `WithXxx`. **No mocks** — use Memory* in tests.
  SQLite covers every OAuth/OIDC + WebAuthn + MFA flow (§4). Redis is the
  recommended next step for SaaS-scale auth-heavy loads.
- **Form + JSON via `bindOAuthParams`** (wraps `oauth.BindParams`,
  `oauth/bind.go`). All OAuth/OIDC endpoints accept both form-urlencoded
  (RFC-mandatory) and JSON; JSON-only breaks off-the-shelf clients.
- **HTTP Basic > body credentials** (RFC 6749 §2.3.1) on `/token`,
  `/token/introspect`, `/token/revoke`, `/par`.
- **Oracle-leak hardening.** Single-use consumption (AuthCode/Refresh/
  Device/PAR/PKCE verifier) MUST collapse unknown/expired/consumed/
  client-mismatch into ONE response: `400 invalid_grant` (/token),
  `invalid_request_uri` (on `/auth/login` consuming a stale/missing PAR
  `request_uri`). DPoP/mTLS failure → `invalid_token`;
  `private_key_jwt` → `invalid_client`. Tests enumerate failures to lock it.
- **Anti-enumeration.**
  - `/register/:client_id` (RFC 7592): missing/wrong/unknown bearer →
    identical 401 `invalid_token` (compare via `crypto/subtle`).
  - `/token/revoke` (RFC 7009 §2.2): 200 on valid client creds
    regardless of token existence.
  - `/token/introspect` inactive → `{"active":false}`.
  - Bcrypt verifier runs a cost-matched dummy hash for unknown users.
  - WebAuthn unknown user/session → `404 session_invalid`.
  - MFA unknown/expired/consumed challenge, unsupported method, wrong
    factor → `400 mfa_invalid` on `/auth/mfa`; detail only via the
    `mfa_failure` audit event.
- **Fail-open** (log + continue): refresh issuance during login/auth_code
  exchange, ID Token issuance, geo, risk-scorer error, audit Sink error,
  tenant-suspension lookup outage, JTI-replay store error (default —
  availability; the JAR/DPoP/client_assertion/actor_token jti is treated
  first-seen). **Fail-closed**: refresh rotation grant (500),
  signature/validation failure, scope expansion, family-reuse (kills family
  → 400 `invalid_grant`). JTI-replay opts in via `WithJTIReplayFailClosed`
  for replay-sensitive multi-replica deploys — a store error then rejects
  with that site's detected-replay code (same wire shape, no store-health
  oracle); the detected-replay + happy paths stay unchanged either way.
- **PKCE: first-exchange only.** `code_challenge` captured at
  `/auth/login`, verified at `/token` `grant=authorization_code`. Refresh
  rotations carry no verifier (bound via `client_id`).
- **Refresh-token family rotation** (BCP §4.13/§4.14). Every token carries
  `FamilyID` through every rotation. Opt into reuse detection via
  `RefreshTokenFamilyTracker`: replay → `ErrRefreshTokenReused` →
  `DeleteFamily(fid)` → audit `refresh_token_reuse_detected` →
  `invalid_grant`. Empty `FamilyID` opts out.
- **Session Refresh refuses expired/revoked.** Memory + SQLite
  `SessionManager.Refresh` filter expired/revoked rows BEFORE extending —
  a captured expired session id can't be resurrected. Assumes a
  FORWARD/MONOTONIC wall clock: a backward step (NTP step, VM-snapshot
  rollback) can transiently let a just-expired session pass `expires_at >
  now`. Session + refresh expiry are deliberately EXACT (no skew slack —
  unlike DPoP/JWT iat-window, which gets configurable skew; loosening
  expiry would accept slightly-expired tokens). Ops MUST slew, never step,
  the clock (chrony).
- **Audit metadata via `SetMeta(e, k, v)`.** Geo + tenant middleware
  enrich `Event.Metadata`; **never** assign `e.Metadata = map{...}`
  (clobbers enrichment).
- **X-Forwarded-* trust.** `requestBaseURL` + `DefaultGeoIPExtractor` +
  `DefaultHostExtractor` honor first-hop `X-Forwarded-Proto/Host/For` —
  **only safe behind a trusted edge** that strips + re-sets them.
  Internet-facing without one MUST install `TrustedProxies(CIDR...)`. The
  same "edge must strip untrusted headers" model governs
  `security.mtls.backend: header`, ratelimit IP keying, and the mesh
  ext_authz `X-Auth-*` identity headers — the mesh MUST strip any
  client-supplied `X-Auth-*` at ingress (the endpoint DERIVES them from
  the validated token, never trusts an inbound one) (§3, §4, §6).
- **`aud` claim parsing** (RFC 7519 §4.1.3): `audClaim` unmarshals string
  or array, marshals single-aud as a compact string per OIDC.
- **`alg` + `typ` allowlist on Validate** (RFC 9068 §4), checked BEFORE
  signature verify, so alg-confusion (`alg=none`, wrong-key-shape) fails
  early. New signer → extend `supportedJWTAlgs` explicitly.
- **RFC 9068 access-token claims.** Every Issue MUST set `Subject.ClientID`
  (REQUIRED §2.2). Login/auth_code/device set `AuthTime`+`AMR` from the
  live event; refresh propagates original `AMR` without resetting
  `AuthTime`; token-exchange propagates `AuthTime`+`ACR`+`AMR`+`SID` from
  the inbound subject_token (multi-hop `act` chain prepended,
  time-ordered); `client_credentials` sets `ClientID` only. `jti` always
  auto-generated.
- **Discovery is derived** from server state — endpoints from request base
  URL, scopes from `openid` ∪ every client's `AllowedScopes`, opt-in
  features (PAR/DCR/JARFetcher/mTLS/BCL/MFA/JWE-JAR) flip flags only when
  wired. New opt-in → branch the doc.
- **`iss` on authorization responses** (RFC 9207). Every `/auth/login`
  response (success/error/provider-list) carries `iss` via
  `s.resolveIssuer(ctx)` (= discovery `issuer`). New authorization
  handlers MUST use `s.authzErrorBody(ctx, code)`, not `errorBody`.
- **JWKS + discovery caching.** JWKS stamps `Cache-Control: public,
  max-age=<ttl>` + strong `ETag=sha256(body)[:8]` (default 5min,
  `WithJWKSCacheTTL`); rotation serves outgoing + incoming keys; concurrent
  doc computes are single-flighted (TTL-free, so a rotation still shows on
  the next poll). Discovery double-cached: `WithDiscoveryCacheTTL` (5s,
  snapshot) + `WithDiscoveryDocCacheTTL` (5s, body + `ETag` per base URL,
  multi-host safe, `If-None-Match` → 304). Body TTL 0 disables in-process
  cache AND headers.
- **Cache headers on credential endpoints** (RFC 6749 §5.1): `/token`,
  `/token/introspect`, `/token/revoke[-all]`, `/par`, `/auth/login`,
  `/userinfo`, `/register*` stamp `Cache-Control: no-store` +
  `Pragma: no-cache` via `tokenNoStoreHeaders(ctx)` — including error
  responses (a cached cross-user 401 from `/userinfo` is catastrophic).
- **WWW-Authenticate on 401** (RFC 6750 §3) via `setBearerChallenge`:
  missing-token omits `error=`; validation failure carries
  `error="invalid_token"`. Descriptions pass `security.QuoteAuthParam`
  (anti auth-param injection).

---

## 3. OAuth 2.0 / OIDC surface

One row per spec. **File** = current owner: Server-coupled glue lives in
`server_extensions.go`/`handlers.go` (root), hexagonal bodies in
`oauth/`+`oidc/`. §2 gotchas apply across grants.

| Spec | Endpoint(s) | Opt-in | File |
|---|---|---|---|
| RFC 6749 §4.1 authorization_code | `/auth/login` + `/token` | `WithAuthCodeStore` | `oauth/auth_code.go` |
| RFC 6749 §4.4 client_credentials | `/token` | always | `oauth/client_creds.go` |
| RFC 6749 §6 refresh_token | `/token` | `WithRefreshTokenStore` | `oauth/refresh_token.go` |
| RFC 7636 PKCE | `/auth/login` + `/token` | per-request / `Client.RequirePKCE` | `oauth/auth_code.go` |
| RFC 7662 introspection | `/token/introspect` | always | `oauth/handle_introspect.go` |
| RFC 7009 revocation | `/token/revoke[-all]` | always; bulk via `RefreshTokenSubjectIndex` | `oauth/handle_revoke.go` |
| RFC 8628 device | `/device/{code,verify}`, `/token` | `WithDeviceCodeStore` | `oauth/device_code.go` |
| RFC 8693 token-exchange | `/token` | always; refresh via `WithRefreshTokenStore`; actor replay via `WithJTIReplayStore` | `handlers.go` + `oauth/token_exchange_helpers.go` |
| RFC 8707 resource indicators | every issuance | `Client.AllowedResources` | per-grant |
| RFC 9126 PAR | `/par` | `WithPARStore` | `oauth/handle_par.go` |
| RFC 7591/7592 DCR | `/register[/:id]` | `WithDynamicClientRegistration` | `oauth/handle_register.go` |
| OIDC Core ID Token | `id_token` w/ `openid` | `WithIDTokenIssuer` | `handler.go` + `oidc/userinfo_signing.go` |
| OIDC Discovery 1.0 | `/.well-known/openid-configuration` | always | `handlers.go` + `oidc/discovery_doc_cache.go` |
| OIDC RP-Initiated Logout | `/end_session` | always | `oidc/handle_end_session.go` |
| OIDC BCL 1.0 | `/logout`, `/end_session` | `WithBackchannelLogout`; multi-RP via `WithSubjectClientIndex` | `server_extensions.go` |
| OIDC FCL 1.0 | `/end_session` | `Client.FrontchannelLogoutURI` | `server_extensions.go` |
| OIDC `sid` claim | access + id + logout | `WithSessionManager` | `defaultimpl/ed25519_jwt_issuer.go` |
| OIDC `login_hint` | `/auth/login`, `/par`, JAR | always | `handler.go` + `oauth/par.go` + `server_extensions.go` |
| OIDC Form Post Response Mode | `/auth/login`, `/par`, JAR | always | `oidc/form_post.go` |
| JARM | `/auth/login` `response_mode={jwt,query.jwt,fragment.jwt,form_post.jwt}` | `WithJARM(signer)` (reuse signing issuer; fail-closed without) | `oidc/jarm.go` |
| OIDC `prompt=none` | `/auth/login` | `WithSessionManager` + `WithIDTokenIssuer` | `oidc/handle_silent_renewal.go` |
| RFC 7521+7523 `private_key_jwt` | `/token`, `/par`, `/introspect`, `/revoke` | `Client.JWKS` | `server_extensions.go` |
| RFC 9207 AS Issuer Id | every `/auth/login` | always | `handlers.go` |
| RFC 9068 JWT Access Token | `{Ed25519,ECDSA,RSA}JWTIssuer` (EdDSA/ES256/RS256\|PS256) | always; alg gate `WithSupportedSigningAlgs`, strict per-issuer kid→alg; `Rotate`/`Retire`/`StartRotation` + `With{Algo}ExternalSigner` KMS/HSM seam (peers: `kms/{awskms,gcpkms,azurekeyvault,pkcs11}` + in-core `defaultimpl/vaulttransit`; EdDSA only on gcp/pkcs11/vault) + `CryptoSigner()` stdlib accessor (SAML XML-DSig) | `defaultimpl/{ed25519,ecdsa,rsa}_jwt_issuer.go` + `defaultimpl/crypto_signer.go` |
| RFC 8705 mTLS-bound + aliases | `/token` + `/userinfo` | `WithClientCertExtractor` | `server_extensions.go` |
| RFC 9470 Step-Up | resource-server helper | always | `security/step_up_auth.go` |
| RFC 9449 DPoP | `/token` + `/userinfo` | header-triggered; replay via `WithJTIReplayStore`; nonce via `WithDPoPNonceProvider`; iat window via `WithDPoPProofMaxAge`/`WithDPoPMaxClockSkew` (default 60s each) | `server_extensions.go` |
| RFC 8414 §2.1 signed_metadata | discovery | `WithMetadataSigner` | `handlers.go` |
| OAuth 2.1 strict | `/auth/login` | `WithOAuth21StrictMode` | `handler.go` |
| FAPI 2.0 profile | `/auth/login` + `/token` + discovery | `WithFAPIProfile(Inspection\|Enforce)`; rules: PAR-only, signed request, S256, code-only, sender-constrained, no shared secret | `fapi/` + `handler.go` |
| RFC 9396 RAR | `authorization_details` | per-client allowlist | `oauth/rar.go` |
| RFC 9101 JAR | `request`, `request_uri` | `Client.JWKS`; URL fetch `WithJARFetcher` + `AllowedRequestURIs`; required via `Client.RequireSignedRequestObject` | `server_extensions.go` + `security/jar_fetch.go` |
| RFC 9101 §6.4 JWE JAR | `request` (JWE) | `WithJARDecrypter`; enc key auto-published in JWKS `use:enc` | `security/jwe.go` |
| OIDC Core §10.2 id_token JWE | `id_token` (encrypted) | `WithJWEResponseEncrypter` + per-client `IDTokenEncryptedResponseAlg`/`_Enc`; RP key from `Client.JWKS` `use:enc` | `oidc/userinfo_signing.go` + `server_extensions.go` |
| OIDC Core §5.3.2 userinfo JWE | `/userinfo` (encrypted) | `WithJWEResponseEncrypter` + per-client `UserinfoEncryptedResponseAlg`/`_Enc` | `oidc/userinfo_signing.go` |
| OIDC CIBA Core 1.0 (poll + ping) | `/backchannel-authentication`, `/token` (`grant=…:ciba`) | `WithCIBA`; ping via `WithCIBAPingNotifier` + `ResolveBackchannelAuthRequest` (detached ping goroutine is supervised: bounded `cibaPingDeliveryTimeout` + recover + `sso_ciba_ping_total` / `ciba_ping_failed` audit) | `oauth/ciba.go` + `oauth/handle_ciba.go` |
| MFA orchestration | `/auth/login` + `/auth/mfa` | `WithMFAProvider` + `WithMFAChallengeStore` (gated by Risk `RequireMFA`) | `handlers.go` + `spi/mfa.go` |
| Per-account lockout | `/auth/login` | `WithAccountLockout` | `security/account_lockout.go` |
| SPIFFE JWT-SVID token-exchange | `/token` (`subject_token_type=jwt`, `sub` a `spiffe://` URI) | `WithSPIFFEJWTSVID(trustDomain, audience, JWKSSource)` — validates the SVID against the operator-supplied SPIRE trust-bundle JWKS via the shared `security.VerifyCompactJWS` (asymmetric alg-allowlist, no alg=none); strict `aud` + trust-domain; maps `spiffe://` → Subject (AMR `["spiffe"]`, RFC 9068 ClientID set); tried ONLY as a fallback after the local-issuer path (local `:jwt` unchanged); all failures → `invalid_grant` (oracle-safe); nil = byte-identical off; JWT-SVID only (x509/Workload-API out) | `security/spiffe_svid.go` + `security/jwks_verify.go` + `handlers.go` |
| OpenID SSF v1 (CAEP+RISC) SET push | none (push transmitter; receiver in `Client.Attributes`) | `WithCAEPTransmitter`; SET via issuer `SignJWT` (`typ:secevent+jwt`); scoped to affected client/tenant; async best-effort | `caep/` |
| Envoy/Istio ext_authz (HTTP mode) | `/mesh/ext-authz` (GET+POST, default path) | `WithMeshExtAuthz(path)` — per-request mesh authz: validates the bearer EXACTLY like `/userinfo` (`validateAnyToken` + DPoP/mTLS sender-constraint enforced, so a stolen sender-constrained token can't replay as a plain bearer), 200 ALLOW with DERIVED `X-Auth-{Subject,Client-Id,Scopes,Expires}` (+ `X-Auth-Roles` when a permissions provider is wired) identity headers the sidecar injects upstream, else 401 DENY (`invalid_token`, oracle-safe; no body); `tokenNoStoreHeaders`; mesh-internal + mesh MUST strip client-supplied `X-Auth-*` (edge-strip, §2); nil = byte-identical off; read-side residency gate (§4); the dep-free decision is the `MeshAuthorize` core seam reused by the gRPC variant | `handler.go` + `mesh_authz.go` |
| Envoy/Istio ext_authz (gRPC mode) | `envoy.service.auth.v3.Authorization` | `extauthz` nested module (`NewAuthorizationServer(srv)`); maps `CheckRequest`↔`MeshAuthorize`↔`CheckResponse`: ALLOW injects derived `X-Auth-*` (`HeadersToRemove` + OVERWRITE edge-strip), DENY=`PERMISSION_DENIED` 401 (no fail-open, no body); surfaces the RFC 9449 §8 `DPoP-Nonce` on the gRPC DENY; go-control-plane stays OUT of core go.mod | `extauthz/authz.go` |
| SAML 2.0 (SP+IdP, SSO+SLO) | `/auth/saml/callback`+`/auth/saml/slo` (SP); `/saml/{metadata,sso,sso/finish,slo,slo/continue}` (IdP) | `saml` nested module (`saml.Build(deps,cfg)`→operator-fork mounts); SP consumes a pinned-cert IdP assertion (XSW-resistant: SignedInfo-ref'd, boot-pinned cert, ≠1-assertion reject), IdP mints enveloped-XML-DSig assertions per-tenant (`CryptoSigner()`; RSA/ECDSA-DER only, EdDSA→`saml_assertion_failed`); SLO back-channel fan-out + front-channel chain (detached §3.4.4.1 sigs, single-use rotating state); oracle-safe (`saml_assertion_invalid`/`saml_request_invalid`); ACS/SLO URL allowlist + https-only SSRF gate; sqlite replay/index peers | `saml/saml.go` |
| Kerberos/SPNEGO (Windows Integrated Auth) | `/auth/kerberos` (Negotiate, cmd-mounted) | `kerberos` nested module (`kerberosauth.Build(deps,cfg,validator)`); RFC 4559 401-Negotiate handshake; validates AP-REQ against the KEYTAB (fail-closed: sig+lifetime+per-process replay cache), maps `principal@REALM`→Subject (AMR `["krb5"]`, RFC 9068 ClientID), mints via per-tenant issuer/session seams; oracle-safe `invalid_token`+retry; NO refresh; gokrb5 replay cache is PER-PROCESS → multi-replica needs sticky affinity; optional `MaxClockSkew`; secret-free `login_failure` audit | `kerberos/handler.go` |
| WebAuthn attestation policy | `/webauthn/registration/finish` | `webauthn.Config.{AttestationConveyance,AttestationPolicy,MDS}`; AAGUID allowlist/denylist gated at `FinishRegistration` AFTER go-webauthn verifies attestation; active policy requires conveyance≥direct (boot guard) + rejects `none`-attestation; optional FIDO MDS (`BuildMDSProvider`, JWS-rooted at FIDO ProductionMDSRoot) makes the gate adversary-resistant; new code `attestation_denied` (403, oracle-safe) | `authenticators/webauthn/{attestation_policy,mds}.go` |
| Multi-region data residency | `/auth/login` + `/userinfo` + mesh + WebAuthn | `WithRegionMiddleware` + `WithTenantResidencyCheck(ttl)`; tenant `HomeRegion`/`AllowedRegions`/`EnforceWrites` gate the serving region: write-gate on every login mint (`residencyGateLogin`), read-gate on resource access (`residencyDeniedForAccess`); fail-OPEN on tenant-store outage (AP/governance); `region_not_allowed`/`residency_violation` are governance codes (reveal residency binding like `tenant_mismatch`, NOT credential oracles); `/token` grant-side + introspect deliberately uncovered | `region/region.go` + `server_extensions.go` |

**JWE decrypters/encrypters** (JAR-in, id_token-out, userinfo-out):
`RSA` (RSA-OAEP-256 + A256GCM, default), `ECDH` (ECDH-ES), or `Multi`
(composes both, selects by the RP's published key type).

**Token strategies** (per-client `token_strategy: jwt|session`): `jwt` —
stateless, signed + JWKS (pass one `Ed25519JWTIssuer` to both
`WithTokenIssuer` + `WithIDTokenIssuer`); `session` — opaque, backed by
`SessionManager`. Register via `sso.WithTokenIssuer(name, issuer)`.

**Signing-key lifecycle.** All three issuers (`Ed25519`/`ECDSA`/`RSA`)
route signing through a `{Algo}Signer` seam — default in-process, or
`With{Algo}ExternalSigner` for a KMS/HSM key that never enters the process
(`defaultimpl/cryptosigner` bridges any `crypto.Signer`; ECDSA DER→R‖S).
Concrete external-signer peers: **AWS KMS** (`kms/awskms/`), **GCP Cloud
KMS** (`kms/gcpkms/`, +Ed25519), **Azure Key Vault** (`kms/azurekeyvault/`),
**PKCS#11** HSM/smart-card (`kms/pkcs11/`, +EdDSA where the token has CKM_EDDSA),
each a SEPARATE nested module; plus IN-CORE dep-free **HashiCorp Vault transit**
(`defaultimpl/vaulttransit/`, +Ed25519, net/http only). ES256/384/512 + RS256/PS256
across all; AWS+Azure have **no Ed25519** → `ErrUnsupportedKey`. KMS/HSM/Vault
sign is a 5-50ms round-trip, so extend token TTL / cache — §4. The 3 issuers also
expose `CryptoSigner()` to hand the key out as a stdlib `crypto.Signer` (SAML
XML-DSig).
`RotateKey`/`RetireKey` do overlap-window rotation (demoted key stays
verify-only in JWKS through its TTL); `StartRotation` runs the scheduled
loop. cmd wires `keys.rotation.*` → `signing_key_rotated` audit +
`sso_signing_key_rotations_total` + busts the signed-discovery cache.
Single-issuer cluster: run on a leader, share a KMS signer, or opt into
leaderless aggregation (next). Alg via `keys.signing.alg`
(`eddsa|es256|rs256|ps256`); each issuer accepts ONLY its own alg, so
`validateAnyToken` is structurally alg-confusion-safe.

**Leaderless multi-replica aggregation** (opt-in, `signingkeys/`). When
replicas each hold their OWN per-process signing key (distinct kid, no
shared KMS), a token signed by A fails on B — B's verify-set lacks A's kid.
`WithSharedSigningKeyRegistry` + `StartSigningKeyAggregation` fix it: each
replica PUBLISHES its signing PUBLIC keys to a shared `signingkeys.Registry`
and ADOPTS peers' keys VERIFY-ONLY
(`{Ed25519,ECDSA,RSA}JWTIssuer.AdoptVerifyKey/DropVerifyKey`) into the
matching-alg issuer, so JWKS + Validate serve the union while each replica
still SIGNS only with its own key. Adoption is alg-matched BEFORE install
(RS256≠PS256, cross-alg keys skipped — alg-confusion-safe) and peer-key
decode fails OPEN (malformed key logged + skipped, never fatal); adopted
keys sit in a separate verify set untouched by local `RotateKey`/`RetireKey`.
**`WithSigningKeyReplicaID` is REQUIRED** once wired — empty id errors out
rather than adopt peers while its own announcement is rejected. Re-publish on
rotation. The adoption loop SELF-HEALS: a Subscribe-channel close while ctx is
live (watch death) no longer kills the consumer silently — it flips a degraded
flag (→ `signing-key-aggregation` /readyz check fails 503 +
`signing_key_aggregation_degraded` audit once-per-transition +
`sso_signing_key_aggregation_up`=0), backs off, and resubscribes (re-seeding
List); a clean ctx-cancel exits WITHOUT degrading. Peer decode/adopt failures
bump `sso_signing_key_adoption_errors_total{reason}`. Backends: `memory`
(single-process) + `etcd` (cross-process, KeepAlive'd lease; a crashed
replica's expiry drops its keys). Nil registry = zero regression vs a
non-aggregating build (no goroutine, metric, or readycheck).

---

## 4. Subsystems

Map only — locator + key trap + file pointer. Code is the source of truth.

**AWS KMS signer** (`kms/awskms/`, SEPARATE nested module). Concrete
`crypto.Signer` over a KMS asymmetric key — the private key never leaves
the HSM (FIPS/PCI/SOC2 gate). Wired via `cryptosigner.{ECDSA,RSA}` →
`With{ECDSA,RSA}ExternalSigner`. ECDSA returns ASN.1 DER (bridge converts
to JWS R‖S); RSA raw. ES256/384/512 + RS256/PS256; **no Ed25519** (KMS has
no EdDSA spec → `ErrUnsupportedKey`); KMS errors fail closed. The
`aws-sdk-go-v2` dep lives ONLY in this module's `go.mod` (core stays
dep-free) — **no `go.work`** (a workspace would surface aws in the root
`go list -m all`); `make ci` runs `ci-modules` which `cd`s in to
build+race-test it.

**Cloud-KMS + HSM + Vault signer peers** (the rest of the
`With{Algo}ExternalSigner` fleet — all bridge via `defaultimpl/cryptosigner`,
all fail closed, all amortized by token TTL/cache like AWS KMS). The ECDSA
hash↔curve pairing is enforced fail-closed in every peer (a caller can't sign
under a hash disagreeing with the curve's ES\* alg JWKS publishes).
- **`kms/gcpkms/`** (SEPARATE nested module, `cloud.google.com/go/kms`). Key =
  a fully-qualified `CryptoKeyVersion` (the version fixes the scheme). ECDSA DER,
  RSA raw. **Supports Ed25519** (`EC_SIGN_ED25519`, sent un-prehashed in the
  `Data` field) — the differentiator over AWS. ES256/384 end-to-end caps at
  P-256 through the issuer; ES384/521 reachable only as a bare `crypto.Signer`.
- **`kms/pkcs11/`** (SEPARATE nested module, `github.com/miekg/pkcs11`, **CGO** —
  needs `CGO_ENABLED=1` + a C toolchain even to build). `CKM_ECDSA` returns RAW
  R‖S → this Signer converts to DER for the stdlib ECDSA contract (the
  cryptosigner bridge converts back to R‖S — deliberate double-convert keeps it a
  faithful `crypto.Signer`). RS256 over DigestInfo, PSS salt=hashlen. **EdDSA via
  `CKM_EDDSA`** where the token implements it.
- **`kms/azurekeyvault/`** (SEPARATE nested module,
  `github.com/Azure/azure-sdk-for-go` `azkeys`). Vault returns ECDSA as RAW R‖S →
  converts to DER (inverse of the cryptosigner bridge). Parses the RP key from a
  raw JWK (N/E/X/Y, not x509 SPKI) with on-curve + small-exponent (`e<3`/even) +
  2048-bit-modulus rejection. **No Ed25519** (`ErrUnsupportedKey`, like AWS).
- **`defaultimpl/vaulttransit/`** (IN THE CORE — DEP-FREE: net/http + json +
  stdlib crypto only, NO nested module, NO dep; the HIBP precedent that a runtime
  HTTPS call ≠ a go.mod dep). HashiCorp Vault transit engine. ECDSA asks
  `marshaling_algorithm=asn1` → DER; RSA `pss`/`pkcs1v15`; **Ed25519** signs the
  RAW message un-prehashed. `TokenSource` is called PER request (operator owns
  renewal); `https`-only + verifying TLS default; the Vault token is never logged.

**SQLite substrate** (`defaultimpl/sqlite/`). Pure-Go
(`modernc.org/sqlite`). Race-free via `DELETE … RETURNING` (single-use
stores), `UPDATE … RETURNING WHERE expires_at>now AND revoked=0` (session
refresh), `INSERT … ON CONFLICT` (JTI/index upserts), `BEGIN IMMEDIATE`
(lockout RMW). Prod DSN `file:/var/lib/sso/sso.db?_journal=WAL`; tests
`file::memory:?cache=shared`. `sql.ErrNoRows` → typed `ErrNoSuchX`;
timestamps Unix-ns INTEGER.

**Redis hot-path peer** (`redis/`, SEPARATE nested module — go-redis stays
OUT of core go.mod, mirrors kms/awskms; `make ci` `ci-modules` builds +
race-tests it against miniredis, NO real Redis). The >1k-QPS multi-replica
scale layer; SQLite stays the embedded fallback. Redis peers for the full
hot-path set (`SessionManager`; `RefreshTokenStore` + Inspector/Subject
Index/Counter/ClientPurger/FamilyTracker; `AuthCodeStore`; `PARStore`;
`JTIReplayStore`; `ratelimit.Limiter`; `DeviceCodeStore`;
`MFAChallengeStore`; `CIBAStore`), each mirroring its SQLite atomic
EXACTLY: Consume = **GETDEL** (single-use, oracle-leak collapse, the
analogue of `DELETE … RETURNING` — auth-code/PAR/MFA-challenge/device
single-use); session Refresh = a **Lua script** (refuses expired/revoked
before extending); JTI MarkSeen = **SET NX EX** (atomic first-sighting);
rate-limit Allow = **Lua INCR + conditional EXPIRE** (fixed-window, the
genuinely-hot per-request store, fails OPEN per §2); CIBA SetStatus = a
**Lua read-check-rewrite KEEPTTL** (pending-only transition guard, the
analogue of `UPDATE … WHERE status='pending'`; Get/poll collapse
unknown/expired to one `ErrCIBARequestNotFound`); device user_code is a
pointer key dereferenced to the canonical device_code record (shared TTL);
refresh families ride a `consumed:<tok>` marker + family/subject/client SET
indexes so reuse → `ErrRefreshTokenReused` → `DeleteFamily`. Wire via the
same `WithSessionManager`/`WithRefreshTokenStore`/`WithAuthCodeStore`/
`WithPARStore`/`WithJTIReplayStore`/`WithDeviceCodeStore`/
`WithMFAChallengeStore`/`WithCIBA`/`WithRateLimit`. Fail-closed on `/token`
per §2 (rate-limit fails OPEN — defense layer, not correctness);
cross-region replication-lag caveat (run single-use traffic on the
primary).

**Migrations** (`migrate/`, pure-Go). Backends declare
`[]migrate.Migration` and route `New`/`NewWithDB` through `migrate.Run(ctx,
db, "<ns>", …)`; v1 = existing schema (populated DBs no-op + stamp).
Per-store namespace (`schema_migrations_<ns>`), forward-only, one `BEGIN
IMMEDIATE` txn (serialize via the runner's `PRAGMA busy_timeout`, NOT the
DSN param modernc ignores). New column/index → append v2+. Inspect offline:
`sso-migrate status --dsn`.

**Cluster-shared backends** — each has a memory + sqlite peer; memory
`Ping` is a no-op, cmd auto-registers `sqlite-<subsystem>` readychecks
only when the backend exposes `Ping`. YAML toggles:

| Subsystem | toggle |
|---|---|
| Identity (User/Client/Session) | `identity.backend` |
| OAuth (AuthCode/Refresh/Device/PAR) | `oauth.<store>.backend` |
| JTI replay / Account lockout | `security.{jti_replay,account_lockout}.backend` |
| Pairwise subjects | `server.pairwise_subjects.backend` |
| BCL subject-client index | `backchannel_logout.index.backend` |
| Rate limiter | `security.rate_limit.backend` |
| WebAuthn (users + sessions) | `webauthn.storage.{users,sessions}.backend` |
| MFA challenges / Push approvals | `mfa.{challenge,provider.push}.backend` |
| CIBA requests | `ciba.backend` |
| Audit sink / Permissions | `audit.backend` / `permissions.backend` |
| Tenants + Domains | `tenant.backend` |
| Recent logins / IP failure counter | `anomaly.{recent_login,ip_failure}.backend` |
| Signing-key registry (opt-in leaderless aggregation; memory+etcd) | `keys.signing_key_registry.backend` |
| Network policy / Service registry (memory+etcd) | `network.store.backend` / `registry.backend` |

**Authenticators** (`authenticators/`). 9 pluggable: `password`, `phone`,
`email`, `temp_token`, `keypair`, `apikey`, `certificate`, `totp`,
`oidc_federation` (Google/Microsoft/GitHub/Auth0/Keycloak via
`?provider=`). `allowed_authenticators` per client gates methods; unknown
password users hit a cost-matched dummy bcrypt hash. **WebAuthn**
(`authenticators/webauthn/`): the four-call ceremony doesn't fit the SPI,
so cmd mounts `/webauthn/{registration,login}/{begin,finish}`;
`login/finish?client_id=` mints tokens (AMR `["webauthn"]`). The `password`
authenticator optionally chains a `spi.PasswordHealthChecker`
(`WithPasswordHealthChecker`, reference `DictionaryPasswordHealthChecker`):
a fail-open, NON-blocking signal run AFTER bcrypt verify. A hit rides on
`AuthResult.CredentialHealth` (`json:"-"`, NEVER in tokens — keep it OFF
`Attributes`, which flows into id_token claims) and surfaces as a
`password_weak`/`password_compromised` audit event (Outcome=success); adds
no wire error.

**Risk scoring** (`spi/risk.go`). `RiskScorer` runs on `/auth/login` AFTER
creds, BEFORE issuance → `Allow`/`RequireMFA`/`Deny` (403). Fail-open,
zero overhead when unset. Reference `RuleBasedRiskScorer` (IP/country
deny-allow lists; `deny_on_geo_missing` hardens when geo absent). Richer
scorers own their store inside `Score` — don't pad `RiskRequest`.

**Anomaly detection** (`anomaly/` + `defaultimpl/detectors/`). Async, OFF
the request path, on every login event; surfaces via audit + webhook,
NEVER feeds back into the decision. `AsyncAnomalyRunner` worker pool (1024
queue / 4 workers / drop-newest); nil = zero overhead. Detectors:
`ImpossibleTravel` (haversine, 800km/h ceiling), `Velocity`, `NewDevice`,
`NewCountry`, `BruteForceShadow` (cross-account same-IP via
`IPFailureCounter`). State in `RecentLoginStore` (hashed/PII-light) +
`IPFailureCounter`.

**MFA orchestration** (`handler.go` + `handlers.go`; SPI `spi/mfa.go`).
Two-leg step-up gated by Risk `RequireMFA`; without both `WithMFAProvider`
+ `WithMFAChallengeStore` it decays to Allow. `/auth/login` returns
`{error: mfa_required, mfa_challenge_id, mfa_methods, iss}` (HTTP 200);
client POSTs `/auth/mfa` → server replays `finishLogin` on frozen state.
Single-use `Consume`. Providers: `TOTP` (1-call), `WebAuthn`/`Push`
(2-call), `Multi` (composes; name conflicts rejected at construction).
Audit: `mfa_required`/`mfa_success`/`mfa_failure`.

**Audit** (`audit/`). `Recorder` fans Events (each carries W3C
`TraceID`/`SpanID`) to `Sink`s. Compose **Async → Multi → Retry → leaf**
(e.g. `AsyncSink(MultiSink(SQLitePrimary, RetryingSink(WebhookSink)))`):
`WithHashChain` (`PrevHash`+`Hash`; `VerifyChain` oldest-first;
`sso-audit-verify` CLI), `WithRedactor` (runs BEFORE the chainer),
`NewRetryingSink`, `NewAsyncSink` (bounded, never blocks, drops on full).
Query has an OPTIONAL `FacetQuerier` (`Facets(ctx, Query) → *Facets`,
type-asserted like the cluster `Ping`/`Stats` seam) backing the
admin-gated `GET /api/v1/audit/facets` (filter-UI candidate values +
counts; mirrors `parseQuery`, 501 when the Sink lacks support). Bounded
dimensions only — outcome/type/client/provider, NEVER high-cardinality
actor/trace/request (§5 metric rule). Memory + sqlite reuse the same
`Query.Match`/WHERE builder so semantics match exactly
(`audit/sqlite/facets_conformance_test.go` locks memory==sqlite).

**Permissions** (`permissions/`). Per-app role registries, wildcard matcher
(`user:*` ⊇ `user:read`, `*` ⊇ all), menu filtering, login embedding via
`WithEmbedPermissionsInLogin()`. SQLite peer: 3 tables; `RemoveRole`
transactionally strips the code from every assignment.
`permissionstest.ConformanceSuite` locks memory/sqlite equivalence.
**Decentralized authz** (`policy_bundle.go`): read-only admin export `GET
/api/v1/admin/authz/policy-bundle?client_id=` (admin:read, gated by the
`/api/v1/admin/` prefix) serializes ONLY role DEFINITIONS (code →
permissions[] + static `WildcardSemantics`), NOT per-subject assignments —
a mesh sidecar (OPA/Cedar; ref Rego `docs/examples/opa-authz-policy.rego`)
already has the caller's roles from the token (pairs with
`WithEmbedPermissionsInLogin`), so it enforces locally with no per-request
Authorizer RPC. ETag-cached like the discovery doc (content-hash over
canonical roles EXCLUDING `generated_at` → stable across rebuilds; 304 on
`If-None-Match`; `WithAuthzPolicyBundleCacheTTL`, default 5m). Role/menu
mutations fire `InvalidateAuthzPolicyBundleCache` (local + bus
`KindAuthzPolicyChange`, fail-open on publish) via a nil-safe callback on
`grpcserver.PermissionAdminService` (the callback-field pattern, NOT a
`*sso.Server` injection).

**Compliance** (`compliance/`). GDPR Art. 17/15/20 (+ CCPA/PIPL) workflows
no single SPI owns. `Eraser`: revoke refresh tokens (per client) → destroy
sessions → delete user — credentials-first so a mid-way failure leaves the
subject locked-out not half-usable; idempotent; best-effort `Report`
(per-step errors never abort siblings); `DryRun` previews. `Exporter`: JSON
bundle from `UserProvider` + `SessionManager` + pluggable `SubjectExporter`s
(refresh tokens excluded — exporting opaque secrets leaks). Pure: composes
existing SPIs, adds no storage, emits no audit (the caller records). cmd
mounts `/api/v1/compliance/users/:id/{export,erase}` under `AdminMiddleware`
(read|write).

**Service registry** (`registry/`). `memory` (TTL+Watch) / `etcd`
(lease+KeepAlive) via `registry.backend`. cmd self-registers `Name:"sso"`,
`Service.ID = registry.service_id` (default `<issuer>-<short-hostname>`,
prevents replica clobber), TTL 30s under etcd.

**gRPC** (`proto/` + `grpcserver/`). Services **reuse the same**
`audit.Recorder` / `permissions.Provider` / `registry.Registry` as HTTP.
`sso.AdminMiddleware` validates Bearer, requires `admin:read`/`admin:write`
(`admin:*` ⊇ both), 401 carries `Bearer realm="admin"`, every mutation
emits `admin_*` audit. `isAdminProtectedPath` covers `/api/v1/audit/*` +
`/netpolicy/policies*` + `/classify` + `/api/v1/compliance/*`;
`/netpolicy/resolve-me` stays open.

| Phase | Services | REST |
|---|---|---|
| A core | `audit.v1.AuditWriter`, `authz.v1.Authorizer`, `discovery.v1.Discovery` | — |
| B netpolicy | `netpolicy.v1.PolicyService` | `/api/v1/netpolicy/` |
| C admin | `admin.v1.{Client,User,Token,Permission}AdminService` | `/api/v1/admin/` |
| D | `admin.v1.{Snapshot,Release}AdminService` | `/api/v1/admin/{snapshots,releases}` |
| E tenant | `admin.v1.TenantAdminService` | `/api/v1/admin/{tenants,domains}` |

**Network policy** (`netpolicy/`). Named classes (intranet/public/dmz/…)
of CIDRs + hostnames + URLs; hostname-beats-CIDR, priority breaks ties.
`Classifier` holds a hot snapshot subscribed to `Store.Watch` via `Start`
(subscribe before the seed `Reload` to avoid lost events). Backends
`memory`/`etcd`, seeded via `config.ApplyNetworkPolicySeeds`.

**Bootstrap** (`bootstrap/`). Versioned first-run init; Runner re-runs only
`Version > high-water`. Trackers `memory`/`file`; Lock SPI
`noop`/`file`/`etcd` (loss → `ErrLockLost` cancels in-flight Steps).
Built-in steps (namespace `"sso-server"`): v0 `restore_from_snapshot`, v1
`seed_admin_role`, v2 `seed_admin_user` (**prints the generated password
ONCE to stdout — capture it**), v3 `seed_default_netpolicy`, v4
`seed_admin_client`.

**Snapshot** (`snapshot/`). Export/restore operator state. `Restore` modes
`ModeMerge`/`ModeOverwrite`/`ModeReplace` (`Confirm==SnapshotID`); `DryRun`
counts only. Sealers (§6) + storage `file`/`inline`; `Pipeline`
sha256-verifies (`ErrChecksumMismatch`). First-boot auto-restore via
`snapshot.restore_from` (builtin v0, before seeds). Retention
`snapshot.PruneOldest` keeps last N. Offline CLI `sso-snapshotctl
list|inspect|verify`. **Opt-in `SnapshotRedactSecrets()`** (export-time
`ExportOptions.Redactor` / `Snapshotter.DefaultExportRedactor`,
`snapshot.redact_secrets`) zeros `Client.Secret` +
`RegistrationAccessToken` on export-local COPIES — defense-in-depth for
SAFE-SHARING/inspection, NOT restore (a redacted snapshot's clients
can't authenticate; encryption stays the restorable-backup path).
Default nil ⇒ byte-identical export; never mutates the live store.

**Releases** (`releases/`). Frontend+backend version pin/rollback;
`Validate` refuses one-sided. `Pinner` encodes asymmetric order
(backend-first forward, frontend-first rollback); backends
`noop`/`static`/`docker`. Forward `Pin` rejects schema regression
(`ErrSchemaRegress` → use `Rollback`); `HealthProbe` gates forward
(all-fail → auto-rollback). REST under `/api/v1/admin/releases`.

**Geo** (`geo/`). IP → enrichment as **UX hint, NOT security**. 200ms
timeout, `ErrNotFound` non-fatal, nil = no-op. Login response carries
`country_code` + `recommended_language`; every Event gets `geo.*`.

**Tenant** (`tenant/`). Multi-tenant + multi-domain; a Tenant is the
business boundary above `Client` (one tenant → many clients).
`Client.TenantID` set → login + token reject mismatch 403
`tenant_mismatch`; empty = any. **Active suspension**
(`WithTenantSuspensionCheck(ttl)`): tenant-bound tokens get a Status
lookup, Suspended → `ErrTenantSuspended` (cached, default 30s; admin
`SetStatus` MUST call `InvalidateTenantSuspensionCache`; outage
fail-open). Without it, existing tokens survive suspension.

**Multi-region / data residency** (`region/`, IN-CORE). Mirrors `geo/`'s
discipline: opt-in, nil-default byte-identical, non-fatal middleware
(`region.Middleware` after geo). SPI = `ID`/`Resolver`/`ResidencyPolicy`/
`PolicyStore` + `ConfigPinned`/`Header`/`Chain` resolvers (header path is
anti-injection allowlisted — the serving region is a `X-Forwarded-*`-class edge
header, §2) + a `memory` peer. The serving region (which DEPLOYMENT served the
request) is a DELIBERATELY DIFFERENT namespace from `geo.Region` (where the
CLIENT is). Tenant gains `HomeRegion`/`AllowedRegions`/`EnforceWrites` (sqlite
migration). `WithTenantResidencyCheck(ttl)` arms `s.checkTenantResidency` (cached,
default TTL; admin tenant-mutation MUST call `InvalidateTenantResidencyCache`):
WRITE-gate (`residencyGateLogin`) on every interactive-login mint (direct/code +
silent-renewal + `/auth/mfa` 2nd leg), READ-gate (`residencyDeniedForAccess`) on
`/userinfo` + mesh ext_authz; WebAuthn login closes the hole via the context-free
`ResidencyDecision` seam (cmd resolves the region off the raw request). FAIL-OPEN
on tenant-store outage (AP/governance, like suspension). `region_not_allowed`
(serving region ∉ AllowedRegions) + `residency_violation` (write leaves HomeRegion
under EnforceWrites) are governance codes, NOT credential oracles (§2). `/token`
grant-side + introspect deliberately uncovered (no `HandlerContext` in scope).

**CAEP / Shared Signals** (`caep/`). OpenID SSF v1 (CAEP + RISC) push
transmitter for real-time cross-RP revocation. Opt-in
`WithCAEPTransmitter` (nil ⇒ no-op, byte-identical); the `Transmitter` is
an `audit.Sink` tapped onto the recorder (`Recorder.AddSink`). On each
recorded event it maps the SMALL mapped subset (`event_mapper.go`:
`refresh_token_reuse_detected`→session-revoked+token-claims-change,
`tenant_tokens_revoked`→account-disabled+session-revoked, scoped
`admin_token_revoked`→token-revoked), mints a SIGNED SET (RFC 8417,
`typ:secevent+jwt`) via the issuer's generic `SignJWT` seam — the SAME key
in JWKS, so RPs validate with no new trust — and POSTs it. **Scoping is
the crux**: push ONLY to the AFFECTED client's receiver, never broadcast —
client-named events → that client; tenant events → `ListByTenant` of THAT
tenant only (no cross-tenant leak); multi-RP-per-subject fan-out is v2.
Receiver endpoint + auth come ONLY from registered
`Client.Attributes["caep_receiver_endpoint"|"caep_receiver_auth"]`
(validated https at create/update; never request input), resolved FRESH
from the ClientStore per send (no cache, no bus). Async + best-effort +
fail-open (a dead receiver drops the SET — metric + `caep_broadcast_failed`
audit; bounded per-receiver timeout + `recover()`, no hot-path retry —
the revocation already happened). jti unique per SET (RP replay defense).

**SAML 2.0** (`saml/`, SEPARATE nested module, `crewjam/saml` + goxmldsig +
etree). Full SP+IdP, SSO+SLO — the SAML mirror of `oidc_federation`. A nested
module CANNOT import cmd `package main`, so it exports its OWN importable
`Deps`/`Config`/`HandlerSpec`/`BuildResult` + `Build(deps,cfg)` (root-module +
stdlib + crewjam types only); the operator's fork adapts the result onto cmd's
`SAMLHandlerSet`. **SP**: consumes an upstream IdP's signed assertion —
XSW-resistant (crewjam resolves the signed element by DSig SignedInfo ref +
verifies against the IdP cert PINNED at boot from metadata, NEVER a
request-embedded cert; rejects >1 assertion), oracle-safe (every failure →
`saml_assertion_invalid`), bounded per-replica AssertionID replay store (NOT the
OAuth JTI store). **IdP** (`cfg.IdP.Enabled`): signs assertions per-tenant via
`deps.IssuerForClient` + `CryptoSigner()` (RSA RS256/PS256 or ECDSA ES256, DER
not R‖S; **EdDSA → `saml_assertion_failed`** — goxmldsig has no EdDSA method,
fail-closed, never cross-tenant fallback); SP registration is per-client
`Attributes` (`saml_sp_entity_id`/`_acs_urls`/`_slo_url`/`_signing_cert`/…, read
at request time, never request input); ACS + SLO URL allowlists are the
exfil/injection defense. **SLO**: SP-side + IdP-side, back-channel fan-out
(async/bounded/best-effort, gated by the opt-in `SAMLSessionIndex`) + front-channel
browser chain (single-use rotating 256-bit state, detached §3.4.4.1 sigs,
verify-before-advance); LogoutRequest signing is MANDATORY (a destructive action).
Multi-replica sqlite peers for the replay/index stores (FAIL-CLOSED — guards an
auth/destructive action; `saml/samltest` locks memory==sqlite); the two
sticky-session-covered browser-flow stores stay memory-only by design. https-only
SSRF gate throughout.

**LDAP / AD** (`ldap/`, SEPARATE nested module, `go-ldap/ldap/v3`). An
`sso.Authenticator` (search-then-bind over TLS), registered via the normal
`WithAuthenticator`/`allowed_authenticators` seam from the operator's fork.
Injection-safe (`ldap.EscapeFilter` on every user value — the raw value is NEVER
formatted into a filter); anti-enumeration (unknown user ≡ wrong password → one
`ErrAuthFailed`, both pay a dummy-bind timing cost like the password
authenticator's dummy bcrypt); TLS-required default (plaintext/InsecureSkipVerify
needs an explicit dev opt-out); bind creds + user password never logged;
DialTimeout/RequestTimeout bound a dead directory.

**Kerberos / SPNEGO** (`kerberos/`, SEPARATE nested module, `gokrb5/v8`). Windows
Integrated Auth / desktop SSO. SPNEGO is a Negotiate-HEADER handshake, not a
credential map, so it's a cmd-MOUNTED handler (like WebAuthn/SAML), exporting its
own `Deps`/`Config`/`SPNEGOValidator`/`HandlerSpec`/`Build`. RFC 4559: 401
`WWW-Authenticate: Negotiate` challenge (also returned on validation failure for
retry); validates the AP-REQ against the **KEYTAB** (the trust anchor + a
high-value secret loaded once, never logged) — fail-closed on bad
sig/expired/replayed/wrong-realm; maps `principal@REALM` → Subject (AMR `["krb5"]`,
RFC 9068 ClientID, ONLY the 2 derived realm+PAC-group attrs — a ticket can't
smuggle a claim), mints via the per-tenant issuer/session seams. Oracle-safe
(`invalid_token` + retry); no-store; NO refresh (desktop SSO re-runs the silent
handshake). **gokrb5's AP-REQ replay cache is PER-PROCESS** (in-memory, not
cross-replica) → multi-replica MUST pin Negotiate traffic to one replica
(sticky affinity), mirroring the redis "single-use on the primary" precedent;
window bounded by clock-skew (`MaxClockSkew`, default 5m). The minimal validator
seam keeps handler tests KDC-free.

**gRPC ext_authz** (`extauthz/`, SEPARATE nested module, `go-control-plane`).
The gRPC-mode companion to the in-core HTTP-mode mesh ext_authz; ALL auth logic
lives in the dep-free `MeshAuthorize` core seam (`mesh_authz.go`) — `*sso.Server`
satisfies the package's `MeshAuthorizer`, and `Check` does ONLY
`CheckRequest`↔seam↔`CheckResponse` wire-mapping (URL rebuilt for the DPoP htu
binding; Envoy peer cert → `*x509.Certificate` for mTLS). ALLOW → derived
`X-Auth-*` injected (`OVERWRITE_IF_EXISTS_OR_ADD` + listed in `HeadersToRemove`,
edge-strip §2); DENY → `PERMISSION_DENIED` 401 + Bearer challenge, NO body
(oracle-safe, no fail-open); the sole DENY detail is the RFC 9449 §8 `DPoP-Nonce`
handshake (protocol-required, not a leak). Single source of truth ⇒ a stolen
DPoP/mTLS-bound token presented as a plain bearer is DENIED over gRPC exactly as
over HTTP. Operator fork constructs `NewAuthorizationServer(srv)` + registers it
on its own grpc.Server (mesh-internal).

**WebAuthn attestation policy** (`authenticators/webauthn/`). Operator-configured
AAGUID `allowlist`/`denylist` + conveyance, gated at `FinishRegistration` AFTER
go-webauthn verifies the attestation (so the AAGUID is the attestation-verified
value). An active policy REQUIRES conveyance `direct|enterprise` (`NewHelper`
boot guard — under none/indirect most authenticators report the zero AAGUID an
allowlist rejects) and rejects `none`-attestation (go-webauthn accepts that format
with ZERO sig verification → its AAGUID is untrustworthy). New wire error
`attestation_denied` (403, oracle-safe; AAGUID + reason go to audit, never the
client). **Without MDS the gate is an OPERATIONAL control** (honest-client gating
+ audit visibility), NOT adversary-resistant — a hostile registrant can craft a
self-signed x5c asserting an allowlisted AAGUID. Wiring `Config.MDS`
(`BuildMDSProvider` → go-webauthn `metadata.Provider`, JWS-rooted at the built-in
FIDO `ProductionMDSRoot`, or a test `CustomRootPEM`; file or dep-free https fetch;
STARTUP SNAPSHOT, reload by restart) makes it adversary-resistant: the attestation
cert chain must root in the FIDO MDS. AAGUID canonicalization is in-tree (avoids
promoting `google/uuid` to a direct dep). Nil/off = byte-identical.

**ssoclient.** Per-capability `ssoclient/local` (in-process) or
`ssoclient/remote` (gRPC + JWKS); mix freely on one `appcore.Handler`.
`remote.JWKSCache` does background refresh + single-flight refetch on
unknown `kid`. `ssoclient/dev` bypass stubs emit a one-time stderr `AUTH
BYPASS ACTIVE` (suppress via `WithSilent*` in tests).

**Edge** (`deploy/`). OpenResty `lua-resty-jwt` = **fast-reject, not a
trust boundary** (Go re-validates). Kubernetes Kustomize + distroless pod
security. docker compose = onboarding/smoke only, NOT production. Grafana
`sso-overview.json` + `alerts.yaml`.

**Middleware order.** Probes registered OUTSIDE the stack so kubelet can't
be throttled:

```
/metrics, /livez, /readyz                          (outside)
tracing → ratelimit → bodyLimit → metrics → CORS → router
```

Wire via `sso.With{Tracing,RateLimit,BodyLimit,Metrics,CORS}`.
**Ratelimit** `KeyByClientIP` honors XFF (trust an edge — see §2
X-Forwarded-*); `KeyByClientIDOrIP` keys Basic-authed `/token` by
`client_id`, body creds fall back to IP. **ReadyCheck**: any fail → 503,
3s aggregate deadline; SQLite stores ship `Ping`, auto-registered.

---

## 5. Observability

**Metrics** — bounded cardinality by design (no per-path/per-user labels;
per-endpoint breakdowns come from traces). MFA labels restricted to the
provider's `SupportedMethods()` (user values dropped before the registry).
`/health` exposes build info via `runtime/debug.ReadBuildInfo`.

| Metric | Type | Labels |
|---|---|---|
| `sso_http_requests_total` | Counter | method, status_class |
| `sso_http_request_duration_seconds` | Histogram | method |
| `sso_login_attempts_total` / `_duration_seconds` | Counter/Histogram | provider, outcome |
| `sso_tokens_issued_total` | Counter | strategy |
| `sso_risk_decisions_total` | Counter | decision |
| `sso_mfa_challenges_total` | Counter | mfa_method |
| `sso_mfa_completions_total` / `_duration_seconds` | Counter/Histogram | mfa_method, outcome |
| `sso_webauthn_{registrations,assertions}_total` | Counter | outcome |
| `sso_credential_health_signals_total` | Counter | signal |
| `sso_retention_{pruned,prune_errors}_total` | Counter | subsystem |
| `sso_anomalies_detected_total` | Counter | anomaly_type, severity |
| `sso_anomaly_dispatch_drops_total` / `_inspect_errors_total` | Counter | reason / detector |
| `sso_signing_key_rotations_total` | Counter | — |
| `sso_signing_operations_total` / `_operation_duration_seconds` | Counter/Histogram | alg, outcome / alg |
| `sso_signing_backend_up` | Gauge | alg |
| `sso_signing_key_adoption_errors_total` | Counter | reason (decode\|adopt) |
| `sso_signing_key_aggregation_up` | Gauge | — |
| `sso_fapi_violations_total` | Counter | rule, mode |
| `sso_ciba_ping_total` | Counter | outcome (success\|error) |
| `sso_caep_sets_total` | Counter | outcome (success\|failed\|dropped) |

**Retention schedulers** — three cmd-side prune loops, uniformly wired
(cancel + bounded-wait on shutdown, emit `sso_retention_*{subsystem}`,
first prune AFTER the first interval). Each needs its SQLite backend
(memory peers self-prune):

| YAML knob | SDK function | label |
|---|---|---|
| `audit.retention.{enabled,max_age,interval}` | `audit/sqlite.Sink.Prune` | `audit` |
| `snapshot.retention.{enabled,keep,interval}` | `snapshot.PruneOldest` | `snapshot` |
| `mfa.provider.push.prune_interval` | `sqlite.PushApprovalStore.PruneExpired` | `push_approvals` |

---

## 6. Configuration

`cmd/sso-server/config.yaml` is canonical; top-level keys map 1:1 to the
SDK SPI. The §4 backend table enumerates every `backend (memory|sqlite)`
knob; below is only the non-obvious operator surface.

- **server.issuer** MUST differ from `sso.DefaultIssuer`; prod SHOULD set
  the canonical public URL (stamped into JWT `iss`, discovery `issuer`,
  every RFC 9207 `iss`).
- **clients[]** map 1:1 to `sso.Client`; `client_id: ""` is a valid bucket
  (demo); prod tokens should carry explicit audience.
- **bootstrap.lock.backend** (noop|file|etcd) — loss → `ErrLockLost`.
- **snapshot.restore_from** — first-boot auto-restore URI (CLI
  `--bootstrap-restore-from` wins).
- **snapshot.encryption.backend** (none|passphrase|aes-gcm) — passphrase →
  argon2id (human secrets); aes-gcm → direct 32-byte key (KMS DEKs).
- **snapshot.redact_secrets** (bool, default false) — opt-in: wires
  `SnapshotRedactSecrets()` so every export strips client credentials for
  SAFE-SHARING/inspection. NOT restorable (use encryption for that).
- **security.mtls.backend** (tls|header) — `header` for reverse-proxy edges
  (`X-SSL-Client-Cert` etc.); **edge MUST strip it from untrusted traffic**
  (same threat model as XFF, §2).
- **security.jti_replay.fail_closed** (default false) — `WithJTIReplayFailClosed`:
  on a replay-store transport error, reject (treat-as-replay, same wire code
  per site) instead of fail-open. For replay-sensitive multi-replica deploys
  (§2).
- **tenant.suspension_check.cache_ttl** — admin SetStatus invalidates via
  `InvalidateTenantSuspensionCache`.
- **keys.signing_key_registry.{backend,replica_id,lease_ttl,etcd_*}**
  (backend: ``|memory|etcd) — opt-in leaderless aggregation (§3). `etcd_*`
  (`endpoints,prefix,dial_timeout,username,password`) mirrors `cluster.bus`.
  `replica_id` defaults to the service-registry id and MUST be unique per
  replica; `lease_ttl` is the announcement lease.
- **spiffe.{enabled,trust_domain,audience,jwks_file,max_clock_skew}** — opt
  into SPIFFE JWT-SVID token-exchange acceptance (§3). Enabled requires ALL
  of `trust_domain` + `audience` + `jwks_file` (cmd fails loud; no safe
  default for any). `jwks_file` is the operator-supplied SPIRE trust-bundle
  JWKS (`StaticJWKS`); `audience` is THIS server's id the SVID `aud` MUST
  contain (lax aud = cross-service replay). Disabled = byte-identical off.
- **mesh.ext_authz.{enabled,path}** — opt into the Envoy/Istio ext_authz
  HTTP-mode authorization endpoint (§3). `path` empty = SDK default
  `/mesh/ext-authz`; must match the sidecar's filter path. Disabled = route
  NOT mounted (byte-identical off). MESH-INTERNAL (operator network policy)
  + the mesh MUST strip client-supplied `X-Auth-*` at ingress (edge-strip,
  §2). The gRPC ext_authz variant (needs go-control-plane) is out of scope.
- **oauth.jar** — RFC 9101 §5.2.2 request_uri fetcher (HTTPS, no-redirect).
- **dpop.{proof_max_age,max_clock_skew}** — RFC 9449 proof iat-window
  (past staleness / future skew). Both 0 = SDK default 60s (byte-identical
  to the old hardcoded bound); loosen for drifty DPoP-client fleets,
  tighten for strict deployments. Governs proof iat only — the nonce TTL
  is `security.dpop_nonce.ttl`.
- **mfa** — gated by Risk `RequireMFA`. `provider.kind`:
  `totp`/`webauthn`/`push`/`multi` (`provider.kinds: [...]`); cmd fails
  loud on missing leaf deps. `push.transport` `log`/`webhook` (custom
  FCM/APNs via cmd fork on `PushTransport`); callback via
  `POST /push/approval/:id/:decision` (empty auth = open, only safe behind
  an edge).
- **caep.{enabled,receiver_timeout,set_ttl}** — OpenID Shared Signals
  transmitter (reuses the signing issuer + ClientStore + audit pipeline;
  no extra signing config). Per-RP receiver lives in
  `clients[].attributes.caep_receiver_endpoint` (https, validated at boot)
  + `caep_receiver_auth`; NO documented HTTP endpoint in v1. Disabled =
  byte-identical.
- **External signers** (`RegisterExternalSigner` in the operator's fork, like
  SAML's `RegisterSAMLHandlers`) — `kms/{awskms,gcpkms,azurekeyvault,pkcs11}` +
  in-core `defaultimpl/vaulttransit` bridge a `crypto.Signer` into the issuers
  via `With{Algo}ExternalSigner`; the nested modules carry the vendor SDK, so
  the operator forks cmd to import them (`kms/pkcs11` additionally needs
  `CGO_ENABLED=1`). The signing alg still comes from `keys.signing.alg`; the
  key reference is the cloud/HSM/Vault resource id.
- **saml.{handler,sp_providers[]}** — `handler` is the registered
  `SAMLHandlerFactory` name (`""` mounts NOTHING, byte-identical); the operator
  FORKS cmd, imports their SAML module, calls
  `RegisterSAMLHandlers("<name>", factory)`, and the factory borrows the issuer
  key off `CryptoSigner()` (assertions signed with the JWKS-published key). The
  SAML/XML/DSig dep stays OUT of the core go.mod (§4). Per-SP/IdP details + the
  downstream-SP `saml_sp_*` client `Attributes` live in the module (§3/§4). LDAP
  + Kerberos are likewise operator-fork-wired (no top-level YAML block) — LDAP
  via `WithAuthenticator` + `allowed_authenticators`, Kerberos via a cmd-mounted
  Negotiate handler over the per-tenant seams (keytab path + optional
  `MaxClockSkew` in its own `Config`).
- **mesh.ext_authz.{enabled,path}** governs the HTTP-mode endpoint (above); the
  **gRPC**-mode variant is the `extauthz` nested module (`go-control-plane`),
  wired by the operator's fork as a standalone grpc.Server — same
  `MeshAuthorize` decision, no extra YAML (§3/§4).
- **region.{serving_region,header_name,allowed_regions,residency_check_cache_ttl}**
  — opt into the serving-region middleware + data-residency gate (§3/§4).
  Neither `serving_region` nor `header_name` set ⇒ middleware NOT installed +
  gate inert (byte-identical). `header_name` reads the serving region off a
  trusted edge header (allowlisted via `allowed_regions`, anti-injection — same
  edge-strip model as XFF, §2); `serving_region` is this deployment's pinned
  fallback. The per-tenant policy is `tenant.{home_region,allowed_regions,
  enforce_writes}`; `residency_check_cache_ttl` caches it (admin tenant-mutation
  MUST `InvalidateTenantResidencyCache`). Outage fail-open.
- **webauthn.attestation.{conveyance,policy_mode,aaguids,mds}** — AAGUID gate
  (§3/§4). `policy_mode` `""/off|allowlist|denylist`; an active mode REQUIRES
  `conveyance: direct|enterprise` (boot fails otherwise) + at least one AAGUID
  (canonical-UUID or bare-32-hex; include the all-zero AAGUID to admit
  self/no-attestation). `mds.{file|fetch_url,custom_root_pem,fetch_timeout}`
  (EXACTLY ONE of file/fetch_url; both empty ⇒ MDS off) turns the gate
  adversary-resistant via FIDO-root-validated metadata; `custom_root_pem` is
  ONLY for a non-prod/test MDS.

**Multi-source loader.** `config.Loader` composes prioritized `Source`s
(lowest first, last wins): `NewFileSource` (baseline) → `NewEnvSource`
(12-factor `SSO_<UPPER>__...`) → `etcd.New` (live) → `NewFlagSource` (CLI).
Maps deep-merge; scalars + slices overwrite; env/etcd leaf strings pass
through `yaml.Unmarshal` (`"true"`→bool). `config.Load(path)` is the legacy
single-source entry.

---

## 7. Operations

| CLI | Purpose |
|---|---|
| `cmd/sso-server` | Production binary |
| `cmd/sso-audit-verify` | Offline hash-chain check (`--from-url` paginates / `--from-file` JSON) |
| `cmd/sso-snapshotctl` | Offline snapshot `list|inspect|verify` (passphrase-capable) |
| `cmd/sso-migrate` | Offline schema-version inspection (`status --dsn`) |

Offline CLIs work directly against wire artifacts (no running server) —
backup-integrity + DR drills.

**Storage-health report** (`storage_health.go`, opt-in `WithStorageHealth`).
`GET /api/v1/admin/storage-health` (admin:read) — the detailed counterpart to
`/readyz`'s pass/fail aggregate: per wired store it reports reachability
(timed Ping → `reachable` + `ping_latency_ms`) + schema version (migrate
namespace → version, from each SQLite store's `DB()` via `migrate.Status`).
For DR drills + rolling-upgrade safety. One store down ⇒ `reachable:false` +
generic error (NO DSN/secret), report still 200 (survivors surface). cmd
collects sources at the `appendReadyCheck` points (`appendStorageHealthSource`);
no sources ⇒ route unmounted.

**Release pipeline**: `goreleaser` from `.github/workflows/release.yml` on
`vX.Y.Z` tags (linux+darwin × amd64+arm64 + windows/amd64; archives bundle
LICENSE + SECURITY.md + CHANGELOG.md; `checksums.txt` + syft SBOMs).
`release.disable: true` runs the full matrix without publishing; locally
`make release-snapshot → dist/`.

**API specs**: HTTP `docs/openapi.yaml` (update in the same commit as any
documented endpoint change — CI `make docs-validate`); gRPC `proto/*.proto`.
`docs/error-codes.md` is the stable catalog of every wire `error` value —
**adding any new `Err*` requires updating it in the same commit.** SPAs
branch on `error`, never `error_description`.

---

## 8. Working in this repo

### Conventions
- **No literal leaks** — paths/headers/error codes live in `consts.go`
  (root or per-package).
- **No mocks for storage** — use real `MemoryProvider`/`MemorySink`/
  `memory.Registry`.
- **No emojis** in code, comments, or commits.
- **Comments explain WHY**, not what — only for hidden constraints,
  invariants, or workarounds.
- **Interface guards in implementation packages**, e.g.
  `var _ ssoclient.AuthClient = (*remote.AuthClient)(nil)` in
  `ssoclient/remote/` — never in `ssoclient/` (cycle).
- **gRPC name renames**: protoc-gen-go does `ID→Id`, `URL→Url`.
- **Tests follow the behavior.** Subpackage unit tests beside the code;
  cross-server integration tests (full `*sso.Server` over HTTP) live in
  `test/` (`package ssotest`) on one shared harness. Race/ordering fixes
  prove with `-count=10+`.
- **Hexagonal handler extraction**: handler bodies move to oauth/ / oidc/
  as `HandleX(deps Deps, ctx)` free functions; `*sso.Server` satisfies
  `Deps` via `accessors.go`; root keeps a one-line delegator. oauth/ must
  NOT import oidc/ (oidc imports oauth — cycle).

### Don'ts
- No `git reset --hard`, `push --force`, `branch -D` without explicit
  authorization; no git-config changes; no hook bypass
  (`--no-verify`/`--no-gpg-sign`).
- No mocks where an in-memory impl exists.
- No "while I'm here" cleanup/refactors; no Markdown files unless asked.
- Don't violate oracle-leak / anti-enumeration (§2). Don't bypass
  `SetMeta` for audit metadata.

### Common tasks
- **New authenticator**: implement `sso.Authenticator` in
  `authenticators/<name>.go` → YAML knob in `config/config.go` → wire in
  cmd `buildAuthenticators` → whitelist under `allowed_authenticators:`.
- **New audit Sink**: implement `audit.Sink` (+ `audit.Closer` if
  lifecycle); wire via `audit.New(...)` / `MultiSink`.
- **New permissions backend**: implement `permissions.Provider` in
  `permissions/<name>/`, plumb `WithPermissionProvider`, keep wildcard
  semantics, run `permissionstest.ConformanceSuite`.
- **New netpolicy at runtime**: `POST /api/v1/netpolicy/policies` (or gRPC
  `PolicyService.Apply`); boot-time via `network.policies:`.
- **New gRPC service**: `proto/<name>/v1/<name>.proto` → regenerate →
  implement in `grpcserver/<name>.go` over an interface HTTP already uses →
  register in cmd `newGRPCServer` → `bufconn` test.
- **New OAuth/OIDC grant**: handler via `bindOAuthParams`; HTTP Basic >
  body creds; map errors `400 invalid_<...>` (oracle-leak pattern);
  single-use atomic `DELETE RETURNING`; wire in `sso.go`; advertise in
  discovery (`handlers.go`); add `WithXxxStore`; tests enumerate
  oracle-leak cases.
- **New credential / bearer endpoint**: `tokenNoStoreHeaders(ctx)` at
  entry; `setBearerChallenge(ctx, ...)` on 401.

### Commits
Conventional (`feat(area):`, `fix(area):`, `chore:`, `docs:`), imperative
subject, body explains why. Co-author trailer when AI-assisted. Don't
commit binaries (the four `cmd/` outputs are gitignored).
