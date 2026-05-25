# AGENTS.md

Operational guide for AI agents. Follows [agents.md](https://agents.md).
User instructions override conflicts. The invariants in §2 are gates,
not style — violating one is a regression.

---

## 1. Orient

`github.com/snaplink/sso` — Go SSO server SDK + runnable binary. OAuth
2.0 + OIDC, swappable authenticators, audit, permissions, service
registry, admin gRPC/REST, snapshot + release lifecycle. Every concern
is an interface; defaults in `defaultimpl/` (memory) +
`defaultimpl/sqlite/` (pure-Go, no CGO). No external SaaS dep. Consumers
wire **embedded** (`ssoclient/local`) or **centralized**
(`ssoclient/remote`, gRPC + JWKS) per capability;
`examples/{embedded-app,remote-app}` share one `appcore.Handler`, only
wiring differs.

### Build, test

```bash
go build ./...
go test ./... -race
go test ./test/ -run TestE2E -v     # cross-wire HTTP + JWKS + bufconn
make ci                              # gofmt + vet + race + build + proto-lint
make docker | make release-snapshot
```

Run E2E whenever changing anything crossing the gRPC or JWKS wire.
Protobuf stubs are checked in; regen rarely needed (`protoc -I proto
--go_out=... --go-grpc_out=... proto/<svc>/v1/<svc>.proto`).

### Layout

Root `package sso` is **6 non-test files**. Tests: server-level
integration tests in `test/` (`package ssotest`, full `*sso.Server`
over HTTP via a shared fixture harness — add new ones there);
subpackage unit tests beside their code (e.g.
`security/step_up_auth_test.go`); only `example_test.go` (godoc) +
`header_client_cert_extractor_test.go` (white-box `package sso`) stay
at root.

```
sso.go                Server type + Options + route registration
handler.go            Login flow orchestrator (every endpoint paths through here)
handlers.go           Discovery + remaining handler bodies + one-line delegators
server_extensions.go  Server-coupled: DPoP/mTLS/JAR/JWE/BCL/FCL/pairwise/tenant-susp/buildinfo
accessors.go          Server field accessors backing subpackage Deps interfaces
aliases.go            core/ + subpackage re-exports (backward compat)

core/          Foundational types + SPIs (User/Client/Session/Token/Subject/AuthRequest/
               AuthResult/HandlerContext/Router/MiddlewareFunc + Authenticator/UserProvider/
               ClientStore/SessionManager/TokenIssuer/JWK/JWKSProvider + wire consts + sentinels)
oauth/         AuthCode/Device/Refresh/PAR stores, DCR+RAR+claims-param validators.
               Hexagonal handlers (Deps iface; *sso.Server impl): HandleIntrospect, HandleRevoke[All],
               HandlePAR, HandleRegister + HandleRegistration{Get,Put,Delete}
oidc/          ID Token SPIs (IDTokenIssuer/UserinfoSigner/MetadataSigner). Hexagonal handlers:
               HandleJWKS, HandleEndSession, HandleSilentRenewal, RenderFormPostResponse,
               MaybeSignUserInfo + discovery_options + DocEntry/WriteDoc body cache
security/      Lockout, JTI replay, JAR/JWE, step-up, mTLS header extractor,
               subject-client index, ConstantTimeStringEq
spi/           Standalone SPIs: Logger, CodeSender, RiskScorer, MFAProvider+Challenge
anomaly/       Async behavioral-detection SPIs
cluster/       Cross-replica coordination Bus (Publish/Subscribe) for cache
               invalidation; memory + etcd peers. Server.{InvalidateTenantSuspensionCache,
               InvalidateDiscoveryCache} publish; StartInvalidationBus subscribes
middleware/    Auth, CORS, Logger, Tracing, RequestID, no-store, base-URL helpers
admin/         Admin auth: HTTP middleware + gRPC interceptor + scope rules
tenant/        Tenant resolution middleware + Tenant/Domain types + Store
geo/           Geo enrichment middleware + GeoInfo + Provider
authenticators/  9 pluggable + webauthn/ helper
defaultimpl/   Default issuer + Memory* stores; /sqlite (pure-Go); /detectors (anomaly impls)
adapters/{echo,gin}/   Router adapters
audit/         Recorder + Sinks + hash chain
permissions/   Roles + menus + wildcard matcher
netpolicy/{memory,etcd}/   Network classification
registry/{memory,etcd}/    Service discovery
bootstrap/{file,memory,builtin,lock}/   First-run init + dist lock
snapshot/{storage,encryption,loader}/   State export/restore
releases/{store,pinner,probe}/   Frontend+backend release pinning
ratelimit/ cors/ metrics/ tracing/   Middleware + observability
config/{etcd}/   YAML + env + etcd + flag loader
proto/ gen/proto/ grpcserver/   Protobuf + generated Go + gRPC services + REST gateway
ssoclient/{local,remote,dev,bootstrap}/   Consumer-facing clients
migrate/       Pure-Go SQLite schema-migration runner (versioned, per-namespace,
               forward-only); every sqlite backend routes New through migrate.Run
cmd/{sso-server,sso-audit-verify,sso-snapshotctl,sso-migrate}/   Binary + offline CLIs
deploy/{openresty,k8s,compose,grafana}/   Operator artifacts
test/          Server-level integration suite (package ssotest)
```

---

## 2. Wire-contract invariants

- **Plugin SPI + storage.** Every concern is an interface in its parent
  package + a `memory` impl + optionally `sqlite`/`etcd`/`file`; new
  backends slot in via `WithXxx`. **No mocks** — use Memory* in tests.
  SQLite covers every OAuth/OIDC + WebAuthn + MFA flow (§4 table). Redis
  is the recommended next step for SaaS-scale auth-heavy loads.
- **Form + JSON via `bindOAuthParams`.** All OAuth/OIDC endpoints accept
  both form-urlencoded (RFC mandatory) and JSON via the `oauth_bind.go`
  dispatcher. JSON-only breaks off-the-shelf clients.
- **HTTP Basic > body credentials** (RFC 6749 §2.3.1) on `/token`,
  `/token/introspect`, `/token/revoke`, `/par`.
- **Oracle-leak hardening.** Single-use consumption (AuthCode / Refresh
  / Device / PAR / PKCE verifier) MUST collapse unknown/expired/
  consumed/client-mismatch into one response (`400 invalid_grant` for
  /token; `invalid_request_uri` for PAR). DPoP/mTLS failures →
  `invalid_token`; `private_key_jwt` → `invalid_client`. Tests enumerate
  failure cases to lock it.
- **Anti-enumeration.**
  - `/register/:client_id` (RFC 7592): missing/wrong/unknown bearer →
    identical 401 `invalid_token`; compare via `crypto/subtle`.
  - `/token/revoke` (RFC 7009 §2.2): 200 on valid client creds
    regardless of token existence.
  - `/token/introspect` inactive → `{"active":false}`.
  - Bcrypt verifier runs a cost-matched dummy hash for unknown users.
  - WebAuthn unknown user / unknown session → `404 session_invalid`.
  - MFA: unknown/expired/consumed challenge, unsupported method, wrong
    factor → `400 mfa_invalid` on `/auth/mfa`; detail only via
    `mfa_failure` audit event.
- **Fail-open** (log + continue): refresh issuance during login /
  auth_code exchange, ID Token issuance, geo, risk-scorer error, audit
  Sink error, tenant-suspension lookup outage.
  **Fail-closed**: refresh rotation grant (500), signature/validation
  failure, scope expansion, family-reuse (kills family, 400
  invalid_grant).
- **PKCE: first-exchange only.** `code_challenge` captured at
  `/auth/login`, verified at `/token grant=authorization_code`. Refresh
  rotations carry no verifier (bound via `client_id`).
- **Refresh-token family rotation** (BCP §4.13/§4.14). Every token
  carries `FamilyID` through every rotation. Opt into reuse detection
  via `RefreshTokenFamilyTracker`: replay → `ErrRefreshTokenReused` →
  `DeleteFamily(fid)` → audit `refresh_token_reuse_detected` →
  `invalid_grant`. Empty `FamilyID` opts out.
- **Session Refresh refuses expired/revoked.** Both Memory + SQLite
  `SessionManager.Refresh` filter expired/revoked rows BEFORE extending
  — a captured expired session id can't be resurrected.
- **Audit metadata via `setMeta(e, k, v)`.** Geo + tenant middleware
  enrich `Event.Metadata`; **never** assign `e.Metadata = map{...}`
  (clobbers enrichment).
- **X-Forwarded-* trust.** `requestBaseURL` + `DefaultGeoIPExtractor` +
  `DefaultHostExtractor` honor first-hop `X-Forwarded-Proto/Host/For` —
  **only safe behind a trusted edge** that strips + re-sets them.
  Internet-facing without one MUST install `TrustedProxies(CIDR...)`.
- **`aud` claim parsing** (RFC 7519 §4.1.3): `audClaim` unmarshals
  string or array, marshals single-aud as compact string per OIDC.
- **`alg` + `typ` allowlist on Validate** (RFC 9068 §4) checked BEFORE
  signature verify, so alg-confusion (`alg=none`, wrong-key-shape) fails
  early. New signer → extend `supportedJWTAlgs` explicitly.
- **RFC 9068 access-token claims.** Every Issue MUST set
  `Subject.ClientID` (REQUIRED §2.2). Login/auth_code/device set
  `AuthTime` + `AMR` from the live event; refresh propagates original
  `AMR` without resetting `AuthTime`; token-exchange propagates
  `AuthTime`+`ACR`+`AMR`+`SID` from the inbound subject_token (multi-hop
  `act` chain prepended, time-ordered); `client_credentials` sets
  `ClientID` only. `jti` always auto-generated.
- **Discovery is derived** from server state — endpoints from request
  base URL, scopes from `openid` ∪ every client's `AllowedScopes`,
  opt-in features (PAR/DCR/JARFetcher/mTLS/BCL/MFA/JWE-JAR) flip flags
  only when wired. New opt-in → branch the doc.
- **`iss` on authorization responses** (RFC 9207). Every `/auth/login`
  response (success/error/provider-list) carries `iss` via
  `s.resolveIssuer(ctx)` = discovery `issuer`. New authorization
  handlers MUST use `s.authzErrorBody(ctx, code)`, not `errorBody`.
- **JWKS + discovery caching.** JWKS: `Cache-Control: public,
  max-age=<ttl>` + `ETag=sha256(body)[:8]`, default 5min
  (`WithJWKSCacheTTL`); rotation serves outgoing + incoming keys.
  Discovery double-cached: `WithDiscoveryCacheTTL` (5s) caches the
  snapshot, `WithDiscoveryDocCacheTTL` (5s) caches body + `ETag` keyed
  by base URL (multi-host safe), honors `If-None-Match` → 304. Body TTL
  0 disables in-process cache AND headers.
- **Cache headers on credential endpoints** (RFC 6749 §5.1): `/token`,
  `/token/introspect`, `/token/revoke[-all]`, `/par`, `/auth/login`,
  `/userinfo`, `/register*` stamp `Cache-Control: no-store` +
  `Pragma: no-cache` via `tokenNoStoreHeaders(ctx)` — including error
  responses (a cached cross-user 401 from /userinfo is catastrophic).
- **WWW-Authenticate on 401** (RFC 6750 §3) via `setBearerChallenge`:
  missing-token omits `error=`; validation failure carries
  `error="invalid_token"`. Descriptions pass `quoteAuthParam` (anti
  auth-param injection).

---

## 3. OAuth 2.0 / OIDC surface

One row per spec; owner file (root delegators point into oauth/ + oidc/
where Hexagonal handlers moved). §2 gotchas apply across grants.

| Spec | Endpoint(s) | Opt-in | File |
|---|---|---|---|
| RFC 6749 §4.1 authorization_code | `/auth/login` + `/token` | `WithAuthCodeStore` | `auth_code.go` |
| RFC 6749 §4.4 client_credentials | `/token` | always | `handle_token_*.go` |
| RFC 6749 §6 refresh_token | `/token` | `WithRefreshTokenStore` | `refresh_token.go` |
| RFC 7636 PKCE | `/auth/login` + `/token` | per-request / `Client.RequirePKCE` | `auth_code.go` |
| RFC 7662 introspection | `/token/introspect` | always | `oauth/handle_introspect.go` |
| RFC 7009 revocation | `/token/revoke[-all]` | always; bulk via `RefreshTokenSubjectIndex` | `oauth/handle_revoke.go` |
| RFC 8628 device | `/device/{code,verify}`, `/token` | `WithDeviceCodeStore` | `handle_device.go` |
| RFC 8693 token-exchange | `/token` | always; refresh via `WithRefreshTokenStore`; actor replay via `WithJTIReplayStore` | `handle_token_exchange.go` |
| RFC 8707 resource indicators | every issuance | `Client.AllowedResources` | per-grant |
| RFC 9126 PAR | `/par` | `WithPARStore` | `oauth/handle_par.go` |
| RFC 7591/7592 DCR | `/register[/:id]` | `WithDynamicClientRegistration` | `oauth/handle_register.go` |
| OIDC Core ID Token | `id_token` w/ `openid` | `WithIDTokenIssuer` | `oidc.go` |
| OIDC Discovery 1.0 | `/.well-known/openid-configuration` | always | `oidc_discovery.go` |
| OIDC RP-Initiated Logout | `/end_session` | always | `oidc/handle_end_session.go` |
| OIDC BCL 1.0 | `/logout`, `/end_session` | `WithBackchannelLogout`; multi-RP via `WithSubjectClientIndex` | `backchannel_logout.go` |
| OIDC FCL 1.0 | `/end_session` | `Client.FrontchannelLogoutURI` | `frontchannel_logout.go` |
| OIDC `sid` claim | access + id + logout | `WithSessionManager` | `defaultimpl/ed25519_jwt_issuer.go` |
| OIDC `login_hint` | `/auth/login`, `/par`, JAR | always | `handler.go` + `par.go` + `jar.go` |
| OIDC Form Post Response Mode | `/auth/login`, `/par`, JAR | always | `oidc/form_post.go` |
| OIDC `prompt=none` | `/auth/login` | `WithSessionManager` + `WithIDTokenIssuer` | `oidc/handle_silent_renewal.go` |
| RFC 7521+7523 `private_key_jwt` | `/token`, `/par`, `/introspect`, `/revoke` | `Client.JWKS` | `security/jwt_client_assertion.go` |
| RFC 9207 AS Issuer Id | every `/auth/login` | always | `iss_response.go` |
| RFC 9068 JWT Access Token | `Ed25519JWTIssuer` | always | `defaultimpl/ed25519_jwt_issuer.go` |
| RFC 8705 mTLS-bound + aliases | `/token` + `/userinfo` | `WithClientCertExtractor` | `mtls_bound.go` |
| RFC 9470 Step-Up | resource-server helper | always | `security/step_up_auth.go` |
| RFC 9449 DPoP | `/token` + `/userinfo` | header-triggered; replay via `WithJTIReplayStore`; nonce via `WithDPoPNonceProvider` | `dpop.go` + `dpop_nonce.go` |
| RFC 8414 §2.1 signed_metadata | discovery | `WithMetadataSigner` (Ed25519JWTIssuer satisfies) | `oidc_discovery.go` |
| OAuth 2.1 strict | `/auth/login` | `WithOAuth21StrictMode` | `handler.go` |
| RFC 9396 RAR | `authorization_details` | per-client allowlist | `rar.go` |
| RFC 9101 JAR | `request`, `request_uri` | `Client.JWKS`; URL fetch via `WithJARFetcher` + `AllowedRequestURIs`; required via `Client.RequireSignedRequestObject` | `security/jar*.go` |
| RFC 9101 §6.4 JWE JAR | `request` (JWE) | `WithJARDecrypter`; default `RSAJWEDecrypter` (RSA-OAEP-256 + A256GCM); enc key auto-published in JWKS `use:enc` | `security/jwe.go` |
| MFA orchestration | `/auth/login` + `/auth/mfa` | `WithMFAProvider` + `WithMFAChallengeStore` (gated by Risk `RequireMFA`) | `mfa.go` + `handle_mfa.go` |
| Per-account lockout | `/auth/login` | `WithAccountLockout` | `security/account_lockout.go` |

**Token strategies** (per-client `token_strategy: jwt|session`):
`TokenStrategyJWT` — Ed25519 + JWKS, stateless (pass one
`Ed25519JWTIssuer` to both `WithTokenIssuer` + `WithIDTokenIssuer`);
`TokenStrategySession` — opaque, backed by `SessionManager`. Register
via `sso.WithTokenIssuer(name, issuer)`.

**Signing-key lifecycle** (`Ed25519JWTIssuer`): all sign sites route
through an `Ed25519Signer` seam — default in-process, or
`WithEd25519ExternalSigner` for a KMS/HSM-backed key that never enters
the process. `RotateKey`/`RetireKey` do runtime overlap-window rotation
(demoted key stays verify-only in JWKS through its TTL); `StartRotation`
runs the scheduled loop. cmd wires it via `keys.rotation.*` → emits
`signing_key_rotated` audit + `sso_signing_key_rotations_total` + busts
the signed discovery cache (JWKS is live). Single-issuer: run on a
leader or share a KMS signer across replicas.

---

## 4. Subsystems

### SQLite substrate (`defaultimpl/sqlite/`)
Pure-Go (`modernc.org/sqlite`). Race-free patterns: single-use stores
(AuthCode/Device/Refresh/PAR/MFAChallenge) `DELETE … RETURNING`;
Session refresh `UPDATE … RETURNING WHERE expires_at>now AND revoked=0`;
JTI replay `INSERT … ON CONFLICT DO NOTHING` + RowsAffected; index
upserts (SubjectClient, Pairwise) `INSERT … ON CONFLICT DO UPDATE`;
AccountLockout read-modify-write in `BEGIN IMMEDIATE`; PushApproval
SetStatus `UPDATE … WHERE status='pending'`.

Prod DSN `file:/var/lib/sso/sso.db?_journal=WAL&_busy_timeout=5000`;
shared-pool tests `file::memory:?cache=shared`. `New<Provider>(dsn)` /
`Close()` / `New<Provider>WithDB(db)`. `sql.ErrNoRows` → typed
`ErrNoSuchX`; timestamps Unix-ns INTEGER.

**Schema migrations via `migrate/`** (pure-Go, no external dep). Every
backend declares `var migrations = []migrate.Migration{{Version:1,
Name:"baseline", SQL:<schema>}}` and routes `New`/`NewWithDB` through
`migrate.Run(ctx, db, "<namespace>", migrations)` (defaultimpl/sqlite
stores share the `ensureSchema(db, ns, schema)` helper). v1 = the
existing schema, so a populated DB no-ops the baseline + is stamped v1;
fresh DBs are created. **Per-store namespace** (`schema_migrations_<ns>`)
— stores may share one DSN, so each tracks its own version. Forward-only;
applied in one `BEGIN IMMEDIATE` txn (replicas serialize via the
runner's `PRAGMA busy_timeout`, NOT the mattn-style `_busy_timeout` DSN
param which modernc ignores). New column/index → append v2+ (SQL, or a
`Func` step for conditional/data migrations, e.g. refresh_tokens'
add-column-if-missing). `migrate.Status` + `sso-migrate status --dsn`
report a DB's per-namespace versions offline.

**Cluster-shared coverage** (each has memory + sqlite peer; YAML toggle):

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
| Audit sink / Permissions | `audit.backend` / `permissions.backend` |
| Tenants + Domains | `tenant.backend` |
| Recent logins / IP failure counter | `anomaly.{recent_login,ip_failure}.backend` |
| Network policy / Service registry (memory+etcd) | `network.store.backend` / `registry.backend` |

Memory `Ping(ctx)` is a no-op; cmd's `appendReadyCheck` auto-registers
`sqlite-<subsystem>` / `etcd-<subsystem>` only when the backend exposes
it.

### Authenticators (`authenticators/`)
9 pluggable: `password`, `phone`, `email`, `temp_token`, `keypair`,
`apikey`, `certificate`, `totp` (RFC 6238), `oidc_federation` (Google /
Microsoft / GitHub / Auth0 / Keycloak via `?provider=<name>`).
`allowed_authenticators` per client gates methods. **password**: cmd
verifies bcrypt hashes from per-user files; unknown users hit a
cost-matched dummy hash.

**WebAuthn** (CTAP/FIDO2, `authenticators/webauthn/`): the four-call
ceremony (`Helper.{Begin,Finish}{Registration,Login}`) doesn't fit the
single-step SPI, so cmd mounts `/webauthn/{registration,login}/{begin,
finish}` via `Server.Handle` when `webauthn.enabled`.
`/webauthn/login/finish?client_id=...` mints tokens (AMR `["webauthn"]`;
`id_token`/`refresh_token` when wired); without `client_id`,
verification only. SQLite peers at `authenticators/webauthn/sqlite/`.

### Risk scoring (`risk.go`)
`RiskScorer` runs on `/auth/login` AFTER credential validation, BEFORE
issuance → `Allow` / `RequireMFA` (gates MFA) / `Deny` (403 + audit
`login_failure reason=risk_denied`). **Fail-open** on error, zero
overhead when unset. Reference: `NoopRiskScorer`; `RuleBasedRiskScorer`
(IP/country deny-allow lists, eval IP deny → IP allow default-deny →
country deny → country allow; `deny_on_geo_missing` hardens country
allow when geo absent). Richer scorers implement `sso.RiskScorer` and
own their store inside `Score` — don't pad `RiskRequest`.

### Anomaly detection (`anomaly/` + `defaultimpl/detectors/`)
Async path complementing the synchronous RiskScorer: detectors run OFF
the request path on every login event (success + failure), surface via
audit + webhook, NEVER feed back into the login decision.
`AsyncAnomalyRunner` worker pool (default 1024 queue, 4 workers,
drop-newest) consumes `LoginEvent`s stamped at
`recordLogin{Success,Failure}` → fans to each `AnomalyDetector`. Runner
nil = zero overhead. Per-detector 5s ctx; errors logged + metric'd,
never propagated.

Reference detectors: `ImpossibleTravelDetector` (haversine + speed
ceiling 800 km/h; 800–2000 warn, 2000+ critical; 10km metro floor, 24h
window; owns `RecentLoginStore` writes); `VelocityDetector` (sliding
window Hourly 25 warn / Daily 200 critical); `NewDeviceDetector` (UA
fingerprint vs 30-day baseline + 7-day grace); `NewCountryDetector`
(90-day baseline + 7-day grace, no lat/lon needed);
`BruteForceShadowDetector` (CROSS-account same-IP via `IPFailureCounter`
— catches credential spray under per-account lockout: Failure 50 warn /
DistinctSubject 10 critical).

State: `RecentLoginStore` (memory + sqlite; per-subject 256-entry ring,
SHA-256-salted IP + per-subject-salted UA + lat/lon + country, PII-light
by construction); `IPFailureCounter` (IP-keyed counter with
distinct-subject aggregation, kept separate from RecentLoginStore for
the IP- vs subject-keyed access pattern). `HashLoginEntry(event,
ipSalt)` is the canonical converter (UA salt derived from
subjectID+ipSalt).

### MFA orchestration (`mfa.go` + `handle_mfa.go`)
Two-leg step-up gated by Risk `DecisionRequireMFA`. Without both
`WithMFAProvider` + `WithMFAChallengeStore`, RequireMFA decays to Allow.
`/auth/login` returns `{error: mfa_required, mfa_challenge_id,
mfa_methods, iss}` (HTTP 200 — primary creds validated); two-call
providers add `mfa_method_data[<method>]` via `MFABeginner`. Client
POSTs `/auth/mfa` `{mfa_challenge_id, mfa_method,
code|assertion|params}`; server replays `finishLogin` on frozen state →
standard direct-mint / code / form_post response (caller can't
distinguish gated). Client/tenant deactivated mid-flow →
`inactive_client` (distinct from `mfa_invalid`). Single-use:
`MFAChallengeStore.Consume` atomically deletes. Wired → `mfa_endpoint` +
`mfa_methods_supported` in discovery.

Providers: `TOTPMFAProvider` (single-call); `WebAuthnMFAProvider`
(two-call, subject binding enforced); `PushMFAProvider` (two-call; Begin
issues via `PushTransport` [`log`/`webhook`], Verify polls
`PushApprovalStore` until device callback); `MultiMFAProvider` (composes
leaves, name conflicts rejected at construction, always a `MFABeginner`).
`MFABeginner.Begin(ctx, subjectID, method)` type-asserted at
`issueMFAChallenge` — one Begin per method, results under
`mfa_method_data`; per-method failure non-fatal. Audit: `mfa_required`,
`mfa_success`, `mfa_failure` (additive — `login_success` still fires on
resume).

### Audit (`audit/`)
`Recorder` fans Events to `Sink`s: `MemorySink`, `WriterSink`,
`WebhookSink`, `MultiSink`, SQLite peer (queryable + durable +
replica-shared). Every Event carries W3C `TraceID`/`SpanID`/
`ParentSpanID`. Wrappers compose **Async → Multi → Retry → leaf**:
`WithHashChain` (`PrevHash`+`Hash`; `VerifyChain` oldest-first;
`sso-audit-verify` CLI); `WithRedactor` (runs BEFORE chainer;
`RedactActorIDHash`/`RedactIPTruncate`/`RedactUserAgent`/
`RedactMetadataKeys`/`DefaultPIIRedactor`); `NewRetryingSink` (backoff +
jitter); `NewAsyncSink` (bounded buffer, never blocks; drops
`ErrAsyncQueueFull`/`ErrAsyncSinkClosed`; wire
`metrics.NewAsyncSinkCollector`). Recommended:
`AsyncSink(MultiSink(SQLitePrimary, RetryingSink(WebhookSink)))`.

### Permissions (`permissions/`)
Per-APP role registries, wildcard matcher (`user:*` ⊇ `user:read`, `*` ⊇
all), menu filtering (`FilterMenuTree` + `FilterButtons`), login
embedding via `WithEmbedPermissionsInLogin()`. `MenuLister` feeds
snapshots + admin RPCs. SQLite peer: three tables (roles/assignments/
menus); RemoveRole transactionally strips the code from every assignment
under the client. `permissionstest.ConformanceSuite` locks memory/sqlite
equivalence (both run it).

### Service registry (`registry/`)
`memory` (TTL + Watch) / `etcd` (lease + KeepAlive); cmd's
`buildRegistry` selects on `registry.backend` (etcd materialized in cmd
to keep the dep out of the SPI). cmd self-registers `Name:"sso"`,
`Service.ID = registry.service_id` (default `<issuer>-<short-hostname>`
to prevent replica clobber), `Service.TTL` 30s under etcd.

### gRPC (`proto/` + `grpcserver/`)

| Phase | Services | REST |
|---|---|---|
| A core | `audit.v1.AuditWriter`, `authz.v1.Authorizer`, `discovery.v1.Discovery` | — |
| B netpolicy | `netpolicy.v1.PolicyService` | `/api/v1/netpolicy/` |
| C admin | `admin.v1.{Client,User,Token,Permission}AdminService` | `/api/v1/admin/` |
| D | `admin.v1.{Snapshot,Release}AdminService` | `/api/v1/admin/{snapshots,releases}` |
| E tenant | `admin.v1.TenantAdminService` | `/api/v1/admin/{tenants,domains}` |

gRPC services **reuse the same** audit.Recorder / permissions.Provider /
registry.Registry instances HTTP uses. `sso.AdminMiddleware` validates
Bearer via `ValidateToken`, requires `admin:read` (read) / `admin:write`
(mutations; `admin:*` ⊇ both), stashes actor via
`AdminActorFromContext`, 401 carries `Bearer realm="admin"`, every
mutation emits `admin_*` audit. `isAdminProtectedPath` also covers
`/api/v1/audit/*` + `/netpolicy/policies*` + `/classify`;
`/netpolicy/resolve-me` stays open. Admin disabled → cmd leaves audit +
netpolicy open + logs a warning. `Discovery.Watch` flushes initial
headers via `SendHeader` so clients can block on `stream.Header()`.

### Network policy (`netpolicy/`)
Named classes (intranet/public/dmz/…) of CIDRs + hostnames + URLs;
hostname-beats-CIDR, priority breaks ties. `Classifier` holds a hot
snapshot subscribed to `Store.Watch` via `Start` — subscribe before seed
Reload to avoid lost events. HTTP `/api/v1/netpolicy/{policies,classify,
resolve-me}`; helper `(*Server).ClassifyRequest(r)`. Backends `memory` /
`etcd`, both seeded via `config.ApplyNetworkPolicySeeds`.

### Bootstrap (`bootstrap/`)
Versioned first-run init. `Step = Name()/Version()/Run(ctx)`; Runner
re-runs only `Version > high-water`. Trackers: `memory` / `file` (atomic
JSON, single-node default). Lock SPI: `noop` / `file` (flock) / `etcd`
(lease+Txn) via `WithLock`/`WithLockTTL`/`WithLockBlocking`; lock loss
cancels in-flight Steps → `ErrLockLost`. Built-in `bootstrap/builtin/`
Steps (namespace `"sso-server"`, reserved):

| v | Effect |
|---|---|
| 0 | `restore_from_snapshot` (when `snapshot.restore_from` set) |
| 1 | `seed_admin_role` (sso-admin, admin:*) |
| 2 | `seed_admin_user` — **prints generated password ONCE to stdout** |
| 3 | `seed_default_netpolicy` (intranet RFC1918 if none) |
| 4 | `seed_admin_client` |

**Capture the admin password from boot log.** `ssoclient/bootstrap`
wraps file tracker + namespaced runner.

### Snapshot (`snapshot/`)
Export/restore operator state (clients, users, roles, assignments,
menus, netpolicies, bootstrap high-water). `Snapshotter.Export` pulls
each backend's `List()`. `Restorer.Restore` modes: `ModeMerge`
(insert-only) / `ModeOverwrite` (upsert) / `ModeReplace` (wipe+seed,
`Confirm == SnapshotID`); `DryRun` counts only; `AdvanceBootstrap` bumps
Tracker. Codec JSON schema `"1"`; sealers `none` / `passphrase`
(argon2id + XChaCha20-Poly1305) / `aes-gcm` (direct 32-byte AES-256 key,
KMS DEKs); storage `file` (atomic 0o600) / `inline`; `Pipeline` composes
with sha256 verify (`ErrChecksumMismatch`). `loader.FromURI` parses
`file:///abs` + `inline:<base64>`. Admin RPC
`admin.v1.SnapshotAdminService`; offline CLI `sso-snapshotctl
list|inspect|verify` (`--passphrase[-file]`).

**First-boot auto-restore**: `snapshot.restore_from` (CLI
`--bootstrap-restore-from` wins) runs as builtin v0 BEFORE the seed
Runner so `AdvanceBootstrap` skips covered seeds; default Overwrite.
**Retention** (`snapshot.PruneOldest`): keep last N by lexical
`snap_<RFC3339>_<rand>` order; `snapshot.retention.{enabled,keep,
interval}`.

### Releases (`releases/`)
App version pin/rollback. `Release` pairs frontend+backend `Artifact`;
`Validate` refuses one-sided. `ReleaseStore`: `memory` / `file`.
`Pinner.PinForward`+`PinRollback` encode asymmetric order (backend-first
forward, frontend-first rollback); backends `noop` / `static` (symlink
swap) / `docker` (rewrite `.env` + compose pull/up). `Registry` =
Store + Pinner; forward Pin rejects schema regression
(`ErrSchemaRegress` → use Rollback). `HealthProbe` gates forward Pin
(all-fail → auto-rollback; none on Rollback). `SnapshotRestorer` on
Rollback restores admin state BEFORE the flip. REST
`POST/GET /api/v1/admin/releases`, `/releases:current`,
`/releases/{id}[:pin,:rollback]`.

### Geo (`geo/`)
IP → enrichment as **UX hint, NOT security**. 200ms timeout,
`ErrNotFound` non-fatal, nil Provider = no-op; `geo/static` is CIDR
longest-prefix. Login response carries `country_code` +
`recommended_language` when no stronger signal; every Event gets `geo.*`.

### Tenant (`tenant/`)
Multi-tenant + multi-domain. Tenant = business boundary; Domain =
hostname → Tenant (lowercased, trailing-dot-stripped per RFC 1035).
**Tenant sits above `Client`** (one tenant → many clients, shared
audit). SQLite peer: `tenants` + `tenant_domains` with `ON DELETE
CASCADE`. `Client.TenantID` set → login + token reject mismatches 403
`tenant_mismatch` (audited `login_failure`); empty = any tenant.
Suspended tenants resolve to "no tenant". Every Event gets `tenant.*`.
**Active suspension** (`WithTenantSuspensionCheck(ttl)`): tenant-bound
tokens get a Status lookup, Suspended → `ErrTenantSuspended`
(`invalid_token` at resource paths, `inactive` at introspect); without
it, existing tokens survive suspension (only issuance blocks). Cached
(default 30s); admin SetStatus MUST call
`InvalidateTenantSuspensionCache(id)`; store outage fail-open. RPC
`admin.v1.TenantAdminService` (UpdateTenant preserves Status; Delete
fires invalidation).

### ssoclient
Per-capability choice — `ssoclient/local` (in-process) or
`ssoclient/remote` (gRPC + JWKS):

```go
handler := &appcore.Handler{
    Auth:  local.NewAuthClient(issuer, local.WithSessionManager(sessions)),
    Authz: remote.NewAuthzClient(grpcConn),
    Audit: remote.NewAuditClient(grpcConn),
}
```

`remote.JWKSCache` does background refresh + single-flight refetch on
unknown `kid`. `ssoclient/dev` provides bypass stubs (`AllowAll`, no-op
audit); **every dev constructor emits a one-time stderr `AUTH BYPASS
ACTIVE`** (suppress via `WithSilent*` in tests).

### Edge (`deploy/`)
- **OpenResty** — `lua-resty-jwt` verifies via JWKS, sets
  `X-Auth-{Subject,Scopes}` / `X-Network`. **Fast-reject, not a trust
  boundary** — the Go server re-validates.
- **Kubernetes** — Kustomize base, distroless pod security (nonroot,
  RO-rootfs, drop ALL caps, `RuntimeDefault`); `configMapGenerator`
  hashes names for rolling restarts; Ingress/HPA/NetworkPolicy/PDB/
  ServiceMonitor in overlays.
- **docker compose** — sso-server + etcd + optional `--profile
  observability`; onboarding/smoke only, NOT production.
- **Grafana** — `sso-overview.json` + `alerts.yaml` (thresholds are
  starting points).

### Middleware order
Probes registered OUTSIDE the stack so kubelet can't be throttled:

```
/metrics, /livez, /readyz                          (outside)
tracing → ratelimit → bodyLimit → metrics → CORS → router
```

Wire via `sso.With{Tracing,RateLimit,BodyLimit,Metrics,CORS}`.
**Ratelimit**: `Default` + ordered `Prefixes`; `KeyByClientIP` honors
XFF/X-Real-IP/RemoteAddr (**trust an edge or wrap TrustedProxies**);
`KeyByClientIDOrIP` keys by `client_id` for Basic-authed /token,
body-supplied creds hit IP fallback (avoids consuming r.Body); composes
with RiskScorer. **Tracing**: `tracing.Init`; OTLP gRPC via
`OTEL_EXPORTER_OTLP_ENDPOINT`, no-op when unset. **ReadyCheck**:
pluggable SPI, any fail → 503; 3s aggregate deadline, per-check override
`WithReadyCheckTimeout(name, ttl)`; SQLite stores ship `Ping`,
auto-registered `sqlite-<subsystem>`; payload `{"status":"ready|
unready","checks":{name:"ok"|err}}`.

---

## 5. Observability

**Metrics** — bounded cardinality by design (no per-path/per-user
labels; per-endpoint breakdowns come from traces):

| Metric | Type | Labels |
|---|---|---|
| `sso_http_requests_total` | Counter | method, status_class |
| `sso_http_request_duration_seconds` | Histogram | method |
| `sso_login_attempts_total` / `_duration_seconds` | Counter/Histogram | provider, outcome |
| `sso_tokens_issued_total` | Counter | strategy |
| `sso_risk_decisions_total` | Counter | decision |
| `sso_mfa_challenges_total` | Counter | mfa_method |
| `sso_mfa_completions_total` / `_duration_seconds` | Counter/Histogram | mfa_method, outcome / outcome |
| `sso_webauthn_{registrations,assertions}_total` | Counter | outcome |
| `sso_retention_{pruned,prune_errors}_total` | Counter | subsystem |
| `sso_anomalies_detected_total` | Counter | anomaly_type, severity |
| `sso_anomaly_dispatch_drops_total` | Counter | reason |
| `sso_anomaly_inspect_errors_total` | Counter | detector |
| `sso_signing_key_rotations_total` | Counter | — |

MFA labels are restricted to the provider's `SupportedMethods()`
(`totp`/`webauthn`/`push`) — user-controlled values dropped before the
registry (anti cardinality-bloat). `/health` exposes build info
(version + VCS revision + commit time via `runtime/debug.ReadBuildInfo`).

### Retention schedulers
Three cmd-side prune loops, uniformly wired: cancel + bounded-wait on
shutdown, emit `sso_retention_{pruned,prune_errors}_total{subsystem}`,
transient errors don't tear down the loop, first prune fires AFTER the
first interval. Each requires its SQLite backend (memory peers self-prune).

| YAML knob | SDK function | label |
|---|---|---|
| `audit.retention.{enabled,max_age,interval}` | `audit/sqlite.Sink.Prune` | `audit` |
| `snapshot.retention.{enabled,keep,interval}` | `snapshot.PruneOldest` | `snapshot` |
| `mfa.provider.push.prune_interval` | `sqlite.PushApprovalStore.PruneExpired` | `push_approvals` |

---

## 6. Configuration

`cmd/sso-server/config.yaml` is canonical; top-level keys map 1:1 to
YAML, field coverage matches the SDK SPI. The §4 backend table
enumerates every `backend(memory|sqlite)` knob; below is only the
non-obvious operator surface.

- **server.issuer** MUST differ from `sso.DefaultIssuer` (cmd default
  `"sso-server"`; prod SHOULD set the canonical public URL — stamped
  into JWT `iss`, discovery `issuer`, every RFC 9207 `iss`).
- **clients[]** map 1:1 to `sso.Client`; `client_id: ""` is a valid
  bucket (demo uses it); prod tokens should carry explicit audience.
- **bootstrap.lock.backend** (noop|file|etcd) — loss → `ErrLockLost`.
- **snapshot.restore_from** — first-boot auto-restore URI (CLI
  `--bootstrap-restore-from` wins).
- **snapshot.encryption.backend** (none|passphrase|aes-gcm) — passphrase
  → argon2id key (human secrets); aes-gcm → direct 32-byte key (KMS DEKs;
  `key_file` raw/hex/base64).
- **security.mtls.backend** (tls|header) — tls for in-process; header
  for reverse-proxy edges (nginx `X-SSL-Client-Cert`, ALB
  `X-Amzn-Mtls-Clientcert`, Apache `Ssl-Client-Cert`) — **edge MUST
  strip the header from untrusted traffic** (same threat model as XFF).
- **tenant.suspension_check.cache_ttl** — Active-suspension cache; admin
  SetStatus invalidates via `InvalidateTenantSuspensionCache`.
- **oauth.jar** — RFC 9101 §5.2.2 request_uri fetcher (HTTPS, no-redirect).
- **mfa** — gated by Risk `DecisionRequireMFA`. `provider.kind`:
  `totp`/`webauthn`/`push` (each shares its authenticator/helper — one
  enrollment, two roles) / `multi` (`provider.kinds: [...]`); cmd fails
  loud on missing leaf deps. `push.transport`: `log` or `webhook`
  (`mfa.provider.push.webhook.*`); custom transports (FCM/APNs) via cmd
  fork on the `PushTransport` SPI. Push callback resolves via
  `PushApprovalStore.SetStatus` — operator handler OR cmd reference
  `POST /push/approval/:id/:decision`
  (`mfa.provider.push.callback.{enabled,bearer_token,allowed_cidrs}`;
  empty both = open, only safe behind an auth edge).

### Multi-source loader
`config.Loader` composes prioritized `Source`s (lowest first, last
wins): `NewFileSource(path)` (baseline) → `NewEnvSource()` (12-factor
`SSO_<UPPER>__...`) → `etcd.New(cfg)` (live) → `NewFlagSource(fs)` (CLI
`Bind()`). Maps deep-merge; scalars + slices overwrite; env/etcd leaf
strings pass through `yaml.Unmarshal` (`"true"`→bool). `config.Load(path)`
is the legacy single-source entry.

---

## 7. Operations

| CLI | Purpose |
|---|---|
| `cmd/sso-server` | Production binary |
| `cmd/sso-audit-verify` | Offline hash-chain check (`--from-url` paginates / `--from-file` JSON) |
| `cmd/sso-snapshotctl` | Offline snapshot `list|inspect|verify` (passphrase-capable) |
| `cmd/sso-migrate` | Offline schema-version inspection (`status --dsn` → per-namespace versions) |

Both offline CLIs work directly against wire artifacts (no running
server) — backup-integrity + DR drills.

**Release pipeline**: `goreleaser` from `.github/workflows/release.yml`
on `vX.Y.Z` tags (linux+darwin × amd64+arm64 + windows/amd64; archives
bundle LICENSE + SECURITY.md + CHANGELOG.md; `checksums.txt` + syft
SBOMs). `release.disable: true` runs the full build+SBOM matrix without
publishing — flip when a target lands; locally `make release-snapshot →
dist/`.

**API specs**: HTTP `docs/openapi.yaml` (OpenAPI 3.0; update in the same
commit as any documented endpoint change — CI `make docs-validate`);
gRPC `proto/*.proto`. `docs/error-codes.md` is the stable catalog of
every wire `error` value — **adding any new `Err*` (consts.go OR a
per-handler file) requires updating it in the same commit.** SPAs branch
on `error`, never `error_description`.

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
- **Tests follow the behavior.** Subpackage unit tests beside the code
  (`package <pkg>_test`); cross-server integration tests (anything
  building a full `*sso.Server` over HTTP) live in `test/` (`package
  ssotest`) on one shared harness — add server-level tests there, not at
  root. Race/ordering fixes prove with `-count=10+`.
- **Hexagonal handler extraction**: handler bodies move to oauth/ / oidc/
  as `HandleX(deps Deps, ctx)` free functions; `*sso.Server` satisfies
  `Deps` via `accessors.go`; root keeps a one-line delegator. oauth/
  must NOT import oidc/ (oidc imports oauth — cycle).

### Don'ts
- No `git reset --hard`, `push --force`, `branch -D` without explicit
  authorization; no git-config changes; no hook bypass
  (`--no-verify`/`--no-gpg-sign`).
- No mocks where an in-memory impl exists.
- No "while I'm here" cleanup/refactors; no Markdown files unless asked.
- Don't violate oracle-leak / anti-enumeration (§2) — stability
  contracts. Don't bypass `setMeta` for audit metadata.

### Common tasks
- **New authenticator**: implement `sso.Authenticator` in
  `authenticators/<name>.go` → YAML knob in `config/config.go` → wire in
  cmd `buildAuthenticators` → whitelist under a client's
  `allowed_authenticators:`.
- **New audit Sink**: implement `audit.Sink` (+ `audit.Closer` if
  lifecycle); wire via `audit.New(...)` / `MultiSink`.
- **New permissions backend**: implement `permissions.Provider` in
  `permissions/<name>/`, plumb `WithPermissionProvider`, keep wildcard
  semantics, run `permissionstest.ConformanceSuite`.
- **New netpolicy at runtime**: `POST /api/v1/netpolicy/policies` (or
  gRPC `PolicyService.Apply`); boot-time via `network.policies:`.
- **New gRPC service**: `proto/<name>/v1/<name>.proto` → regenerate →
  implement in `grpcserver/<name>.go` over an interface HTTP already
  uses → register in cmd `newGRPCServer` → `bufconn` test.
- **New OAuth/OIDC grant**: handler via `bindOAuthParams`; HTTP Basic >
  body creds; map errors `400 invalid_<...>` (oracle-leak pattern);
  single-use atomic delete-and-return (SQLite `DELETE RETURNING`); wire
  in `sso.go`; advertise in `oidc_discovery.go`; add `WithXxxStore`;
  tests enumerate oracle-leak cases.
- **New credential / bearer endpoint**: `tokenNoStoreHeaders(ctx)` at
  entry; `setBearerChallenge(ctx, ...)` on 401.

### Commits
Conventional (`feat(area):`, `fix(area):`, `chore:`, `docs:`),
imperative subject, blank line, body explains why. Co-author trailer
when AI-assisted. Don't commit binaries (`sso-server` /
`sso-audit-verify` / `sso-snapshotctl` / `sso-migrate` ignored).
