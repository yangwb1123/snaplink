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
defaultimpl/   Default issuers (Ed25519/ECDSA/RSA) + Memory* stores + JWE
               (RSA/ECDH/Multi) + cryptosigner KMS bridge; /sqlite (pure-Go); /detectors
adapters/{echo,gin}/   Router adapters
audit/         Recorder + Sinks + hash chain
permissions/   Roles + menus + wildcard matcher
compliance/    GDPR/CCPA/PIPL data-subject erasure + export (composes existing SPIs; no new store)
netpolicy/{memory,etcd}/   Network classification
registry/{memory,etcd}/    Service discovery
bootstrap/{file,memory,builtin,lock}/   First-run init + dist lock
snapshot/{storage,encryption,loader}/   State export/restore
releases/{store,pinner,probe}/   Frontend+backend release pinning
signingkeys/{memory}/   Opt-in leaderless multi-replica JWKS public-key aggregation (publish own signing pubkeys + adopt peers' verify-only)
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
  `invalid_request_uri` (PAR). DPoP/mTLS failure → `invalid_token`;
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
  tenant-suspension lookup outage. **Fail-closed**: refresh rotation grant
  (500), signature/validation failure, scope expansion, family-reuse
  (kills family → 400 `invalid_grant`).
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
  a captured expired session id can't be resurrected.
- **Audit metadata via `SetMeta(e, k, v)`.** Geo + tenant middleware
  enrich `Event.Metadata`; **never** assign `e.Metadata = map{...}`
  (clobbers enrichment).
- **X-Forwarded-* trust.** `requestBaseURL` + `DefaultGeoIPExtractor` +
  `DefaultHostExtractor` honor first-hop `X-Forwarded-Proto/Host/For` —
  **only safe behind a trusted edge** that strips + re-sets them.
  Internet-facing without one MUST install `TrustedProxies(CIDR...)`. The
  same "edge must strip untrusted headers" model governs
  `security.mtls.backend: header` and ratelimit IP keying (§4, §6).
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
| RFC 9068 JWT Access Token | `{Ed25519,ECDSA,RSA}JWTIssuer` (EdDSA/ES256/RS256\|PS256) | always; alg gate `WithSupportedSigningAlgs`, strict per-issuer kid→alg; `Rotate`/`Retire`/`StartRotation` + KMS seam | `defaultimpl/{ed25519,ecdsa,rsa}_jwt_issuer.go` |
| RFC 8705 mTLS-bound + aliases | `/token` + `/userinfo` | `WithClientCertExtractor` | `server_extensions.go` |
| RFC 9470 Step-Up | resource-server helper | always | `security/step_up_auth.go` |
| RFC 9449 DPoP | `/token` + `/userinfo` | header-triggered; replay via `WithJTIReplayStore`; nonce via `WithDPoPNonceProvider` | `server_extensions.go` |
| RFC 8414 §2.1 signed_metadata | discovery | `WithMetadataSigner` | `handlers.go` |
| OAuth 2.1 strict | `/auth/login` | `WithOAuth21StrictMode` | `handler.go` |
| FAPI 2.0 profile | `/auth/login` + `/token` + discovery | `WithFAPIProfile(Inspection\|Enforce)`; rules: PAR-only, signed request, S256, code-only, sender-constrained, no shared secret | `fapi/` + `handler.go` |
| RFC 9396 RAR | `authorization_details` | per-client allowlist | `oauth/rar.go` |
| RFC 9101 JAR | `request`, `request_uri` | `Client.JWKS`; URL fetch `WithJARFetcher` + `AllowedRequestURIs`; required via `Client.RequireSignedRequestObject` | `server_extensions.go` + `security/jar_fetch.go` |
| RFC 9101 §6.4 JWE JAR | `request` (JWE) | `WithJARDecrypter`; enc key auto-published in JWKS `use:enc` | `security/jwe.go` |
| OIDC Core §10.2 id_token JWE | `id_token` (encrypted) | `WithJWEResponseEncrypter` + per-client `IDTokenEncryptedResponseAlg`/`_Enc`; RP key from `Client.JWKS` `use:enc` | `oidc/userinfo_signing.go` + `server_extensions.go` |
| OIDC Core §5.3.2 userinfo JWE | `/userinfo` (encrypted) | `WithJWEResponseEncrypter` + per-client `UserinfoEncryptedResponseAlg`/`_Enc` | `oidc/userinfo_signing.go` |
| OIDC CIBA Core 1.0 (poll + ping) | `/backchannel-authentication`, `/token` (`grant=…:ciba`) | `WithCIBA`; ping via `WithCIBAPingNotifier` + `ResolveBackchannelAuthRequest` | `oauth/ciba.go` + `oauth/handle_ciba.go` |
| MFA orchestration | `/auth/login` + `/auth/mfa` | `WithMFAProvider` + `WithMFAChallengeStore` (gated by Risk `RequireMFA`) | `handlers.go` + `spi/mfa.go` |
| Per-account lockout | `/auth/login` | `WithAccountLockout` | `security/account_lockout.go` |

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
(`defaultimpl/cryptosigner` bridges any `crypto.Signer`).
`RotateKey`/`RetireKey` do overlap-window rotation (demoted key stays
verify-only in JWKS through its TTL); `StartRotation` runs the scheduled
loop. cmd wires `keys.rotation.*` → `signing_key_rotated` audit +
`sso_signing_key_rotations_total` + busts the signed-discovery cache.
Single-issuer cluster: run on a leader or share a KMS signer — OR opt into
leaderless aggregation (below). Alg via `keys.signing.alg`
(`eddsa|es256|rs256|ps256`); each issuer accepts ONLY its own alg, so
`validateAnyToken` is structurally alg-confusion-safe.

**Leaderless multi-replica aggregation** (opt-in, `signingkeys/`). When
replicas each hold their OWN per-process signing key (distinct kid, no
shared KMS), a token signed by A fails on B because B's JWKS/verify-set
lacks A's kid. `WithSharedSigningKeyRegistry` + `StartSigningKeyAggregation`
fix it: each replica PUBLISHES its signing PUBLIC keys to a shared
`signingkeys.Registry` and ADOPTS peers' keys VERIFY-ONLY into the
matching-alg issuer (`Ed25519JWTIssuer.AdoptVerifyKey/DropVerifyKey`), so
JWKS() + Validate() serve the union while each replica still SIGNS only with
its own private key. Alg-match is enforced BEFORE adoption (preserves
per-issuer kid→alg + alg-confusion safety); adopted peer keys live in a
SEPARATE `peerVerifyKeys` map untouched by local `RotateKey`/`RetireKey`.
Nil registry = byte-identical to a non-aggregating build (zero regression).
Re-publish on rotation. Ed25519 only today (ECDSA/RSA + etcd backend
follow).

---

## 4. Subsystems

Map only — locator + key trap + file pointer. Code is the source of truth.

**SQLite substrate** (`defaultimpl/sqlite/`). Pure-Go
(`modernc.org/sqlite`). Race-free via `DELETE … RETURNING` (single-use
stores), `UPDATE … RETURNING WHERE expires_at>now AND revoked=0` (session
refresh), `INSERT … ON CONFLICT` (JTI/index upserts), `BEGIN IMMEDIATE`
(lockout RMW). Prod DSN `file:/var/lib/sso/sso.db?_journal=WAL`; tests
`file::memory:?cache=shared`. `sql.ErrNoRows` → typed `ErrNoSuchX`;
timestamps Unix-ns INTEGER.

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
| Signing-key registry (opt-in leaderless aggregation; memory today, etcd to follow) | `keys.signing_key_registry.backend` |
| Network policy / Service registry (memory+etcd) | `network.store.backend` / `registry.backend` |

**Authenticators** (`authenticators/`). 9 pluggable: `password`, `phone`,
`email`, `temp_token`, `keypair`, `apikey`, `certificate`, `totp`,
`oidc_federation` (Google/Microsoft/GitHub/Auth0/Keycloak via
`?provider=`). `allowed_authenticators` per client gates methods; unknown
password users hit a cost-matched dummy bcrypt hash. **WebAuthn**
(`authenticators/webauthn/`): the four-call ceremony doesn't fit the SPI,
so cmd mounts `/webauthn/{registration,login}/{begin,finish}`;
`login/finish?client_id=` mints tokens (AMR `["webauthn"]`). The `password`
authenticator takes an optional `spi.PasswordHealthChecker`
(`WithPasswordHealthChecker`, reference `DictionaryPasswordHealthChecker`):
a fail-open, NON-blocking login-time signal run AFTER bcrypt verify (the
only plaintext touchpoint — creds are pre-bcrypted/seeded). A hit rides on
`AuthResult.CredentialHealth` (typed, NEVER serialized into tokens — keep
it OFF `Attributes`, which flows into id_token claims) and surfaces as a
`password_weak`/`password_compromised` audit event (Outcome=success);
adds no wire error.

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

**Permissions** (`permissions/`). Per-app role registries, wildcard matcher
(`user:*` ⊇ `user:read`, `*` ⊇ all), menu filtering, login embedding via
`WithEmbedPermissionsInLogin()`. SQLite peer: 3 tables; `RemoveRole`
transactionally strips the code from every assignment.
`permissionstest.ConformanceSuite` locks memory/sqlite equivalence.

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
list|inspect|verify`.

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
| `sso_fapi_violations_total` | Counter | rule, mode |

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
- **security.mtls.backend** (tls|header) — `header` for reverse-proxy edges
  (`X-SSL-Client-Cert` etc.); **edge MUST strip it from untrusted traffic**
  (same threat model as XFF, §2).
- **tenant.suspension_check.cache_ttl** — admin SetStatus invalidates via
  `InvalidateTenantSuspensionCache`.
- **keys.signing_key_registry.{backend,replica_id,lease_ttl}**
  (backend: ``|memory|etcd) — opt-in leaderless multi-replica JWKS
  aggregation (§3). `memory` is functional today; `etcd` errors as
  not-yet-supported (follow-up commit). `replica_id` defaults to the
  service-registry id; MUST be unique per replica.
- **oauth.jar** — RFC 9101 §5.2.2 request_uri fetcher (HTTPS, no-redirect).
- **mfa** — gated by Risk `RequireMFA`. `provider.kind`:
  `totp`/`webauthn`/`push`/`multi` (`provider.kinds: [...]`); cmd fails
  loud on missing leaf deps. `push.transport` `log`/`webhook` (custom
  FCM/APNs via cmd fork on `PushTransport`); callback via
  `POST /push/approval/:id/:decision` (empty auth = open, only safe behind
  an edge).

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
