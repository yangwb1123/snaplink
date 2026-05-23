# AGENTS.md

Operational guide for AI agents in this repo. Follows
[agents.md](https://agents.md). User instructions override conflicts.

---

## 1. Orient

`github.com/snaplink/sso` — Go SSO server SDK + runnable binary. OAuth
2.0 + OIDC, swappable authenticators, audit, permissions, service
registry, admin gRPC/REST, snapshot + release lifecycle. Every concern
is an interface; defaults live in `defaultimpl/` (memory) and
`defaultimpl/sqlite/` (pure-Go, no CGO). No external SaaS dep.
Consumers wire **embedded** (`ssoclient/local`, in-process) or
**centralized** (`ssoclient/remote`, gRPC + JWKS) per capability.
`examples/{embedded-app,remote-app}` share the same
`appcore.Handler`; only wiring differs.

### Build, test

```bash
go build ./...
go test ./... -race
go test -run TestE2E -v .       # cross-wire HTTP + JWKS + bufconn
make ci                          # gofmt + vet + race + build + proto-lint
make docker
make release-snapshot
```

Run E2E whenever changing anything that crosses the gRPC or JWKS wire.

Protobuf regen (stubs checked in, rarely needed):

```bash
protoc -I proto \
  --go_out=gen/proto --go_opt=paths=source_relative \
  --go-grpc_out=gen/proto --go-grpc_opt=paths=source_relative \
  proto/<svc>/v1/<svc>.proto
```

### Layout

```
Root package (sso) — 6 files total:
sso.go                              Server type + Option functions + route registration
handler.go                          Login flow orchestrator (every endpoint paths through here)
aliases.go                          core/ re-exports for backward compatibility
handlers.go                         All endpoint HTTP handlers (token/auth/admin/oidc)
middlewares.go                      All HTTP middleware (admin/tenant/geo/auth/CORS/tracing)
server_extensions.go                Server-coupled features (DPoP/mTLS/JAR/JWE/BCL/FCL/pairwise/tenant-suspension/buildinfo)

core/                               Foundational types + SPIs (User/Client/Session/Token/
                                    Subject/AuthRequest/AuthResult/HandlerContext/Router/
                                    MiddlewareFunc + Authenticator/UserProvider/ClientStore/
                                    SessionManager/TokenIssuer/JWK/JWKSProvider + 176 wire
                                    constants + sentinel errors)
anomaly/                            Async behavioral detection SPIs
security/                           Per-account lockout, JTI replay,
                                    JAR/JWE, step-up, mTLS header
                                    extractor, subject-client index
oauth/                              AuthCode/DeviceCode/RefreshToken/PAR
                                    stores, DCR + RAR + claims-param
                                    validators
spi/                                Standalone SPIs: Logger, CodeSender,
                                    RiskScorer, MFAProvider+Challenge
oidc/                               OIDC ID Token SPIs: IDTokenIssuer,
                                    UserinfoSigner, MetadataSigner
authenticators/                     9 pluggable + webauthn/ helper
defaultimpl/                        Default issuer + Memory* stores
defaultimpl/sqlite/                 Pure-Go SQLite (no CGO)
defaultimpl/detectors/              Reference anomaly detector impls
adapters/{echo,gin}/                Router adapters
audit/                              Recorder + Sinks + hash chain
permissions/                        Roles + menus + wildcard matcher
netpolicy/{memory,etcd}/            Network classification
registry/{memory,etcd}/             Service discovery
bootstrap/{file,memory,builtin,lock}/  First-run init + dist lock
snapshot/{storage,encryption,loader}/  State export/restore
releases/{store,pinner,probe}/      Frontend+backend release pinning
geo/  tenant/  ratelimit/  cors/    Middleware + enrichment
metrics/  tracing/                  Observability
config/{etcd}/                      YAML + env + etcd + flag loader
proto/ + gen/proto/                 Protobuf + generated Go
grpcserver/                         gRPC services + REST gateway
ssoclient/{local,remote,dev,bootstrap}/  Consumer-facing clients
cmd/sso-server/                     Production binary
cmd/sso-audit-verify/               Offline audit-chain verifier CLI
cmd/sso-snapshotctl/                Offline snapshot inspect/verify CLI
deploy/{openresty,k8s,compose,grafana}/  Operator artifacts
```

---

## 2. Wire-contract invariants

Violating these is a regression — gates, not style.

### Plugin SPI + storage
Every concern is an interface in its parent package + a `memory` impl
+ optionally `sqlite` / `etcd` / `file`. New backends slot in via
`WithXxx`. **No mocks** — use Memory* in tests. SQLite covers every
OAuth/OIDC + WebAuthn + MFA flow on a shared file (see §4
backend-coverage table). Redis is the recommended next step for
SaaS-scale auth-heavy workloads.

### Form + JSON via `bindOAuthParams`
All OAuth/OIDC endpoints accept both `application/x-www-form-urlencoded`
(RFC mandatory) and JSON via the `oauth_bind.go` dispatcher. JSON-only
would break every off-the-shelf OAuth client.

### HTTP Basic > body credentials (RFC 6749 §2.3.1)
On `/token`, `/token/introspect`, `/token/revoke`, `/par`:
`Authorization: Basic` beats body `client_id`+`client_secret`.

### Oracle-leak hardening
Single-use code consumption (AuthCode / Refresh / Device / PAR / PKCE
verifier) MUST collapse unknown / expired / consumed / client-mismatch
into one wire response (`400 invalid_grant` for /token;
`invalid_request_uri` for PAR). DPoP/mTLS failures → `invalid_token`;
`private_key_jwt` failures → `invalid_client`. Tests enumerate the
failure cases to lock the behavior.

### Anti-enumeration
- `/register/:client_id` (RFC 7592): missing / wrong bearer / unknown
  id → identical 401 `invalid_token`. Bearer compare via
  `crypto/subtle.ConstantTimeCompare`.
- `/token/revoke` (RFC 7009 §2.2): 200 OK on valid client creds
  regardless of token existence.
- `/token/introspect` inactive: `{"active":false}`.
- Bcrypt password verifier runs against a cost-matched dummy hash for
  unknown users (timing parity).
- WebAuthn unknown user / unknown session both collapse to `404
  session_invalid`.
- MFA orchestration: unknown / expired / consumed challenge,
  unsupported method, wrong factor — all collapse to `400 mfa_invalid`
  on `/auth/mfa`. Detail surfaces via `mfa_failure` audit event only.

### Fail-open vs fail-closed
- **Fail-open** (log + continue): refresh issuance during `/auth/login`
  or auth_code exchange, ID Token issuance, geo, risk scorer error,
  audit Sink error, tenant suspension lookup outage.
- **Fail-closed**: refresh rotation grant (500), signature/validation
  failure, scope expansion, family-reuse detection (kills whole family,
  400 invalid_grant).

### PKCE: first-exchange only
`code_challenge` captured at `/auth/login`; verified against
`code_verifier` at `/token grant=authorization_code`. Refresh rotations
carry no verifier (bound via `client_id`).

### Refresh-token family rotation (BCP §4.13/§4.14)
Every refresh token carries `FamilyID` propagated through every
rotation. Stores opt into reuse detection via
`RefreshTokenFamilyTracker`. Replay → `ErrRefreshTokenReused` →
`DeleteFamily(fid)` → audit `refresh_token_reuse_detected` →
`invalid_grant`. Empty `FamilyID` opts out.

### Session Refresh refuses expired/revoked
Both Memory + SQLite peers of `SessionManager.Refresh` filter out
expired/revoked rows BEFORE extending expiry. A captured session id
past its expiry cannot be resurrected via Refresh.

### Audit metadata: `setMeta(e, k, v)`
Geo + tenant middleware enrich every event via `Event.Metadata`.
**Never** assign `e.Metadata = map{...}` — clobbers enrichment.

### X-Forwarded-* trust
`requestBaseURL` + `DefaultGeoIPExtractor` + `DefaultHostExtractor`
honor first-hop `X-Forwarded-Proto/Host/For`. **Only safe behind a
trusted edge** that strips and re-sets them. Internet-facing deploys
without one MUST install `TrustedProxies(CIDR...)`.

### `aud` claim parsing
RFC 7519 §4.1.3 — string or array. `audClaim` unmarshals either,
marshals single-aud as compact string per OIDC.

### `alg` + `typ` allowlist on Validate (RFC 9068 §4)
Checked BEFORE signature verify so alg-confusion attacks (`alg=none`,
wrong-key-shape spoof) fail early. New signer → extend
`supportedJWTAlgs` explicitly.

### RFC 9068 access-token claim population
Every Issue call site MUST set `Subject.ClientID` (REQUIRED §2.2).
Login / auth_code / device set `AuthTime` + `AMR` from the live auth
event. Refresh propagates original `AMR` without resetting `AuthTime`.
Token-exchange propagates `AuthTime` + `ACR` + `AMR` + `SID` from the
inbound subject_token (multi-hop `act` chain prepended, time-ordered).
`client_credentials` populates `ClientID` only. `jti` always
auto-generated.

### Discovery is derived
`/.well-known/openid-configuration` computed from server state:
endpoints from request base URL, scopes from union of `openid` + every
client's `AllowedScopes`, opt-in features (PAR, DCR, JARFetcher, mTLS,
BCL, MFA, JWE-JAR) flip flags only when wired. New opt-in → branch the
doc.

### `iss` on authorization responses (RFC 9207)
Every `/auth/login` response — success, error, provider-list — carries
`iss` via `s.resolveIssuer(ctx)`, MUST equal discovery `issuer`. New
authorization-flow handlers MUST use `s.authzErrorBody(ctx, code)`,
not plain `errorBody`.

### JWKS + discovery caching
- JWKS: `Cache-Control: public, max-age=<ttl>` + `ETag =
  sha256(body)[:8]`. Default TTL 5min via `WithJWKSCacheTTL`. Rotation
  serves both outgoing and incoming keys.
- Discovery double-cached: `WithDiscoveryCacheTTL` (default 5s) caches
  the snapshot; `WithDiscoveryDocCacheTTL` (default 5s) caches body +
  `ETag` keyed by request base URL (multi-host safe); honors
  `If-None-Match` → 304. Body TTL 0 disables both the in-process cache
  AND response headers.

### Cache headers on credential endpoints (RFC 6749 §5.1)
`/token`, `/token/introspect`, `/token/revoke[-all]`, `/par`,
`/auth/login`, `/userinfo`, `/register*` stamp `Cache-Control:
no-store` + `Pragma: no-cache` via `tokenNoStoreHeaders(ctx)` — same
rule applies to error responses (a 401 from /userinfo cached cross-user
would be catastrophic). New credential endpoint: one-line opt-in.

### WWW-Authenticate on 401 (RFC 6750 §3)
Resource endpoints stamp a Bearer challenge via `setBearerChallenge`.
Missing-token omits `error=`; validation failure carries
`error="invalid_token"`. Descriptions pass `quoteAuthParam` to prevent
auth-param injection.

---

## 3. OAuth 2.0 / OIDC surface

One row per spec; file is the owner. Gotchas above apply across grants.

| Spec | Endpoint(s) | Opt-in | File |
|---|---|---|---|
| RFC 6749 §4.1 authorization_code | `/auth/login` + `/token` | `WithAuthCodeStore` | `auth_code.go` |
| RFC 6749 §4.4 client_credentials | `/token` | always | `handle_token_*.go` |
| RFC 6749 §6 refresh_token | `/token` | `WithRefreshTokenStore` | `refresh_token.go` |
| RFC 7636 PKCE | `/auth/login` + `/token` | per-request / `Client.RequirePKCE` | `auth_code.go` |
| RFC 7662 introspection | `/token/introspect` | always | `handle_introspect.go` |
| RFC 7009 revocation | `/token/revoke[-all]` | always; bulk via `RefreshTokenSubjectIndex` | `handle_revoke.go` |
| RFC 8628 device | `/device/code`, `/device/verify`, `/token` | `WithDeviceCodeStore` | `handle_device.go` |
| RFC 8693 token-exchange | `/token` | always; refresh-output via `WithRefreshTokenStore`; actor replay via `WithJTIReplayStore` | `handle_token_exchange.go` |
| RFC 8707 resource indicators | every issuance | `Client.AllowedResources` | per-grant |
| RFC 9126 PAR | `/par` | `WithPARStore` | `handle_par.go` |
| RFC 7591/7592 DCR | `/register[/:id]` | `WithDynamicClientRegistration` | `handle_register.go` |
| OIDC Core ID Token | `id_token` w/ `openid` | `WithIDTokenIssuer` | `oidc.go` |
| OIDC Discovery 1.0 | `/.well-known/openid-configuration` | always | `oidc_discovery.go` |
| OIDC RP-Initiated Logout | `/end_session` | always | `handle_end_session.go` |
| OIDC BCL 1.0 | `/logout`, `/end_session` | `WithBackchannelLogout`; multi-RP via `WithSubjectClientIndex` | `backchannel_logout.go` |
| OIDC FCL 1.0 | `/end_session` | `Client.FrontchannelLogoutURI` | `frontchannel_logout.go` |
| OIDC `sid` claim | access + id + logout | `WithSessionManager` | `defaultimpl/ed25519_jwt_issuer.go` |
| OIDC `login_hint` | `/auth/login`, `/par`, JAR | always | `handler.go` + `par.go` + `jar.go` |
| OIDC Form Post Response Mode | `/auth/login`, `/par`, JAR | always | `form_post_response_mode.go` |
| OIDC `prompt=none` | `/auth/login` | `WithSessionManager` + `WithIDTokenIssuer` | `prompt.go` |
| RFC 7521 + 7523 `private_key_jwt` | `/token`, `/par`, `/introspect`, `/revoke` | `Client.JWKS` | `jwt_client_assertion.go` |
| RFC 9207 AS Issuer Id | every `/auth/login` | always | `iss_response.go` |
| RFC 9068 JWT Access Token | `Ed25519JWTIssuer` | always | `defaultimpl/ed25519_jwt_issuer.go` |
| RFC 8705 mTLS-bound + aliases | `/token` + `/userinfo` | `WithClientCertExtractor` | `mtls_bound.go` |
| RFC 9470 Step-Up | resource-server helper | always | `step_up_auth.go` |
| RFC 9449 DPoP | `/token` + `/userinfo` | header-triggered; replay via `WithJTIReplayStore`; nonce via `WithDPoPNonceProvider` | `dpop.go` + `dpop_nonce.go` |
| RFC 8414 §2.1 signed_metadata | discovery | `WithMetadataSigner` (Ed25519JWTIssuer satisfies) | `oidc_discovery.go` |
| OAuth 2.1 strict | `/auth/login` | `WithOAuth21StrictMode` | `handler.go` |
| RFC 9396 RAR | `authorization_details` | per-client allowlist | `rar.go` |
| RFC 9101 JAR | `request`, `request_uri` | `Client.JWKS`; URL fetch via `WithJARFetcher` + `AllowedRequestURIs`; required via `Client.RequireSignedRequestObject` | `jar.go` + `jar_fetch.go` |
| RFC 9101 §6.4 JWE JAR | `request` (JWE-wrapped) | `WithJARDecrypter`; default `defaultimpl.RSAJWEDecrypter` (RSA-OAEP-256 + A256GCM); enc public key auto-published in JWKS with `use:enc` | `jwe.go` + `defaultimpl/rsa_jwe_decrypter.go` |
| MFA orchestration | `/auth/login` + `/auth/mfa` | `WithMFAProvider` + `WithMFAChallengeStore` (gated by `RiskScorer.DecisionRequireMFA`) | `mfa.go` + `handle_mfa.go` |
| Per-account lockout | `/auth/login` | `WithAccountLockout` | `account_lockout.go` |

**Token strategies** are per-client (`token_strategy: jwt|session`):
- `TokenStrategyJWT` — Ed25519 + JWKS, stateless. Pass the same
  `Ed25519JWTIssuer` to `WithTokenIssuer` and `WithIDTokenIssuer`.
- `TokenStrategySession` — opaque, backed by `SessionManager`.

Register via `sso.WithTokenIssuer(name, issuer)`.

---

## 4. Subsystems

### SQLite substrate (`defaultimpl/sqlite/`)
Pure-Go via `modernc.org/sqlite`. Race-free patterns by store:
- single-use (AuthCode, DeviceCode, RefreshToken, PAR, MFAChallenge):
  `DELETE … RETURNING`
- Session refresh: `UPDATE … RETURNING WHERE expires_at > now AND
  revoked = 0`
- JTI replay: `INSERT … ON CONFLICT DO NOTHING` + RowsAffected
- index upserts (SubjectClientIndex, PairwiseSubject): `INSERT … ON
  CONFLICT DO UPDATE`
- AccountLockout: read-modify-write inside `BEGIN IMMEDIATE`
- PushApproval SetStatus: `UPDATE … WHERE status = 'pending'` (refuses
  re-resolution)

Production DSN: `file:/var/lib/sso/sso.db?_journal=WAL&_busy_timeout=5000`.
Shared-pool tests: `file::memory:?cache=shared`. Schema via `CREATE
TABLE IF NOT EXISTS` at construction. Constructor: `New<Provider>(dsn)`
/ `Close()` / `New<Provider>WithDB(db)` for shared pools.
`sql.ErrNoRows` → typed `ErrNoSuchX`. Timestamps as Unix-ns INTEGER.
**The next multi-table backend MUST bring goose/golang-migrate.**

**Cluster-shared coverage** (every entry has memory + sqlite peer):

| Subsystem | Memory | SQLite | YAML backend toggle |
|---|---|---|---|
| Identity (User/Client/Session) | ✓ | ✓ | `identity.backend` |
| OAuth (AuthCode/Refresh/Device/PAR) | ✓ | ✓ | `oauth.<store>.backend` |
| JTI replay | ✓ | ✓ | `security.jti_replay.backend` |
| Account lockout | ✓ | ✓ | `security.account_lockout.backend` |
| Pairwise subjects | ✓ | ✓ | `server.pairwise_subjects.backend` |
| BCL subject-client index | ✓ | ✓ | `backchannel_logout.index.backend` |
| Rate limiter | ✓ | ✓ | `security.rate_limit.backend` |
| WebAuthn (users + sessions) | ✓ | ✓ | `webauthn.storage.{users,sessions}.backend` |
| MFA challenges | ✓ | ✓ | `mfa.challenge.backend` |
| Push approvals | ✓ | ✓ | `mfa.provider.push.backend` |
| Audit sink | ✓ | ✓ | `audit.backend` |
| Permissions (Provider) | ✓ | ✓ | `permissions.backend` |
| Tenants + Domains | ✓ | ✓ | `tenant.backend` |
| Recent logins (anomaly state) | ✓ | ✓ | `anomaly.recent_login.backend` |
| IP failure counter (brute-force) | ✓ | ✓ | `anomaly.ip_failure.backend` |
| Network policy store | ✓ | etcd | `network.store.backend` |
| Service registry | ✓ | etcd | `registry.backend` |

Memory-backed `Ping(ctx)` is a no-op; cmd's `appendReadyCheck` auto-
registers under `sqlite-<subsystem>` / `etcd-<subsystem>` only when
the backend exposes it.

### Authenticators (`authenticators/`)
9 pluggable: `password`, `phone`, `email`, `temp_token`, `keypair`,
`apikey`, `certificate`, `totp` (RFC 6238), `oidc_federation` (Google
/ Microsoft / GitHub / Auth0 / Keycloak at
`/auth/login?provider=<name>`). `allowed_authenticators` per client
gates methods. **password**: cmd verifies bcrypt hashes loaded from
per-user files; unknown users hit a cost-matched dummy hash for
timing parity.

**WebAuthn** (CTAP/FIDO2) ships at `authenticators/webauthn/` — the
four-call ceremony (`Helper.{Begin,Finish}{Registration,Login}`)
doesn't fit the single-step Authenticator SPI, so cmd mounts
`/webauthn/{registration,login}/{begin,finish}` via `Server.Handle`
when `webauthn.enabled`. `/webauthn/login/finish?client_id=...` mints
tokens (AMR=`["webauthn"]`; `id_token` when client has `openid` +
`WithIDTokenIssuer`; `refresh_token` when `WithRefreshTokenStore`);
without `client_id`, credential-verification only. SQLite peers for
UserStore + SessionStore at `authenticators/webauthn/sqlite/`. Built
on `github.com/go-webauthn/webauthn`.

### Risk scoring (`risk.go`)
`RiskScorer` runs on `/auth/login` AFTER credential validation, BEFORE
token issuance. Returns `Allow` / `RequireMFA` (gates the MFA flow) /
`Deny` (403 + audit `login_failure reason=risk_denied`). **Fail-open**
on scorer error. **Zero overhead** when option unset.

Reference impls in `defaultimpl/`:
- `NoopRiskScorer` — typed Allow-always.
- `RuleBasedRiskScorer` — declarative IP / country deny-and-allow
  lists. Eval order: IP deny → IP allow default-deny → country deny →
  country allow; `deny_on_geo_missing` promotes country allow to
  hard-required when geo enrichment is absent.

Richer scorers (impossible-travel, device fingerprint, ML) implement
`sso.RiskScorer` directly and query their own store inside `Score` —
don't pad `RiskRequest`.

### Anomaly detection (`anomaly/` + `defaultimpl/detectors/`)
Async behavioral-anomaly path that complements the synchronous
[RiskScorer]. The synchronous scorer can only afford ms-level
decisions; anomaly detectors run OFF the request path on every
login event (success + failure), surface anomalies via audit +
webhook, NEVER back into the login decision. Operators want
"tell me what's unusual, let me decide policy" — not "block on
every guess."

Wire shape: `AsyncAnomalyRunner` worker pool (bounded queue,
default 1024 depth + 4 workers, drop-newest on overflow) consumes
`LoginEvent`s + fans to every registered `AnomalyDetector`. Events
are stamped at `recordLoginSuccess` / `recordLoginFailure`; runner
nil → zero overhead. Per-detector 5s ctx bound; one slow detector
can't pile up siblings. Per-detector errors logged + metric'd,
never propagated.

Reference detectors (`defaultimpl/detectors/`):
- `ImpossibleTravelDetector` — haversine distance + speed ceiling
  (default 800 km/h). 800-2000 = warn; 2000+ = critical. 10km
  same-metro floor; 24h history window. Owns the
  `RecentLoginStore` writes (other detectors are read-only).
- `VelocityDetector` — sliding window per-subject failure +
  success counts. HourlyLimit (default 25 → warn) +
  DailyLimit (default 200 → critical) fire independently.
- `NewDeviceDetector` — UA fingerprint comparison vs 30-day
  baseline + 7-day bootstrap grace period (cold-start
  suppression).
- `NewCountryDetector` — country comparison vs 90-day baseline +
  7-day grace. Works without lat/lon-capable geo provider.
- `BruteForceShadowDetector` — CROSS-account same-IP failure
  counter against `IPFailureCounter`. Catches the AccountLockout
  blind spot: attacker spraying credentials across N accounts
  staying below per-account threshold (5 fails × 100 accounts =
  500 IP failures invisible to per-subject lockout). FailureLimit
  (default 50 → warn) + DistinctSubjectLimit (default 10 →
  critical) fire independently.

State substrate:
- `RecentLoginStore` (memory + sqlite peer at
  `defaultimpl/sqlite/recent_login.go`): per-subject ring buffer,
  256 entries default, append + windowed read + prune-older.
  Stores SHA-256-salted IP + per-subject-salted UA hash + lat/lon
  + country. Cluster-shared via SQLite. PII-light by construction
  (never raw IP / UA).
- `IPFailureCounter` (memory + sqlite peer): IP-keyed counter
  with distinct-subject aggregation. Separate from
  `RecentLoginStore` to avoid double-index cost: subject-keyed
  access pattern vs IP-keyed access pattern.

`HashLoginEntry(event, ipSalt)` is the canonical event-to-entry
converter — detector implementations call this rather than
reaching for crypto/sha256 themselves. Per-subject UA salt
deterministically derived from subjectID + ipSalt so privacy
holds even on dump.

### MFA orchestration (`mfa.go` + `handle_mfa.go`)
Two-leg step-up flow gated by `RiskScorer` returning
`DecisionRequireMFA`. Without both `WithMFAProvider` +
`WithMFAChallengeStore`, RequireMFA decays to Allow (back-compat).

**Wire shape:** `/auth/login` returns `{error: mfa_required,
mfa_challenge_id, mfa_methods, iss}` (HTTP 200 — primary credential
validated, pending step-up). Two-call providers additionally populate
`mfa_method_data[<method>]` via `MFABeginner`. Client POSTs
`/auth/mfa` with `{mfa_challenge_id, mfa_method, code|assertion|params}`;
server replays `finishLogin` against the frozen state and returns the
standard direct-mint / code / form_post response — caller can't
distinguish MFA-gated from non-gated. Client / tenant deactivated
between login and /auth/mfa surfaces as `inactive_client` (distinct
from `mfa_invalid` so SIEM can tell it wasn't the factor that
failed). Single-use: `MFAChallengeStore.Consume` atomically deletes.

**Discovery:** when wired, `mfa_endpoint` + `mfa_methods_supported`
appear in `/.well-known/openid-configuration`.

**`MFAProvider` impls**:
- `authenticators.TOTPMFAProvider` — single-call; reuses
  `TOTPAuthenticator` store + skew.
- `authenticators/webauthn.WebAuthnMFAProvider` — two-call
  (`MFABeginner`); reuses Helper. Subject binding enforced.
- `defaultimpl.PushMFAProvider` — two-call (`MFABeginner`). Begin
  issues approval via `PushTransport` (cmd ships `log` + `webhook`;
  custom transports via SDK fork); Verify polls `PushApprovalStore`
  until the device-driven callback (operator-built OR cmd's
  reference `POST /push/approval/:id/:decision`) resolves it.
- `defaultimpl.MultiMFAProvider` — composes leaves; method-name
  conflicts rejected at construction. Always implements `MFABeginner`
  so single-call providers in the mix don't break Begin dispatch.

**`MFABeginner` optional interface**
(`Begin(ctx, subjectID, method) (map[string]string, error)`):
type-asserted at `issueMFAChallenge`; implementing providers get one
Begin call per supported method, results bucketed under
`mfa_method_data`. Per-method Begin failure non-fatal — method stays
in `mfa_methods` without an attached data entry.

**Audit events**: `mfa_required` (challenge issued), `mfa_success`
(factor verified), `mfa_failure` (factor rejected). Standard
`login_success` event still fires on resume — MFA gating is additive
observability.

### Audit (`audit/`)
`audit.Recorder` fans Events to `Sink`s. Built-in sinks: `MemorySink`,
`WriterSink`, `WebhookSink`, `MultiSink`; SQLite peer (`audit/sqlite`)
is queryable + restart-durable + replica-shared. Every Event carries
W3C `TraceID` / `SpanID` / `ParentSpanID`.

Optional wrappers (compose in order: Async → Multi → Retry → leaf):
- `WithHashChain` — `PrevHash` + `Hash` on every Event;
  `VerifyChain` validates oldest-first; `sso-audit-verify` CLI walks
  `/api/v1/audit/events` or a JSON file.
- `WithRedactor` (runs BEFORE chainer) — `RedactActorIDHash(salt)`,
  `RedactIPTruncate`, `RedactUserAgent`, `RedactMetadataKeys(...)`,
  `DefaultPIIRedactor(salt)`.
- `NewRetryingSink` — exponential backoff + jitter.
- `NewAsyncSink(...).Start()` — bounded buffer + worker pool; Record
  never blocks. Drops: `ErrAsyncQueueFull` / `ErrAsyncSinkClosed` /
  inner. Use for WebhookSink. Wire
  `metrics.NewAsyncSinkCollector(asyncSink)` for drop/queue series.

Recommended cluster composition:
`AsyncSink(MultiSink(SQLitePrimary, RetryingSink(WebhookSink)))`.

### Permissions (`permissions/`)
Per-APP role registries, wildcard matcher (`user:*` matches
`user:read`, `*` matches all), menu filtering (`FilterMenuTree` +
`FilterButtons`), login-response embedding via
`WithEmbedPermissionsInLogin()`. `MenuLister` is the extension
snapshots + admin RPCs use. SQLite peer
(`permissions/sqlite`) uses three tables (roles, assignments, menus);
RemoveRole transactionally strips the code from every assignment
under the client. Shared `permissions/permissionstest.ConformanceSuite`
locks memory/sqlite equivalence — both backends run it.

### Service registry (`registry/`)
`memory` (TTL + Watch) and `etcd` (lease + KeepAlive). cmd's
`buildRegistry` selects on `registry.backend`; etcd path materialized
in cmd to keep the transitive dep out of the SPI. cmd self-registers
as `Name: "sso"`, `Service.ID = registry.service_id` (defaults
`<issuer>-<short-hostname>` to prevent replica clobber). `Service.TTL`
defaults 30s under etcd.

### gRPC (`proto/` + `grpcserver/`)

| Phase | Services | REST |
|---|---|---|
| A core | `audit.v1.AuditWriter`, `authz.v1.Authorizer`, `discovery.v1.Discovery` | — |
| B netpolicy | `netpolicy.v1.PolicyService` | `/api/v1/netpolicy/` |
| C admin | `admin.v1.{Client,User,Token,Permission}AdminService` | `/api/v1/admin/` |
| D | `admin.v1.{Snapshot,Release}AdminService` | `/api/v1/admin/{snapshots,releases}` |
| E tenant | `admin.v1.TenantAdminService` | `/api/v1/admin/{tenants,domains}` |

gRPC services **reuse the same** audit.Recorder / permissions.Provider
/ registry.Registry instances HTTP uses.

`sso.AdminMiddleware` validates Bearer via `(*sso.Server).ValidateToken`,
requires `admin:read` for read / `admin:write` for mutations
(`admin:*` matches both), stashes actor via `AdminActorFromContext`.
401s carry `Bearer realm="admin"`. Every mutation emits `admin_*`
audit. `isAdminProtectedPath` also covers `/api/v1/audit/*` (PII-grade
event query) and `/api/v1/netpolicy/policies*` + `/classify`;
`/netpolicy/resolve-me` stays open as the client-facing lookup. When
admin is disabled, cmd leaves audit + netpolicy open and logs a
startup warning.

`Discovery.Watch` flushes initial headers via `SendHeader` so clients
can block on `stream.Header()` before mutations.

### Network policy (`netpolicy/`)
Named classes (intranet/public/dmz/…) of CIDRs + hostnames + URLs.
Hostname-beats-CIDR; priority breaks ties. `Classifier` holds a hot
snapshot subscribed to `Store.Watch` via `Start` — subscribe before
seed Reload to avoid lost events. HTTP at
`/api/v1/netpolicy/{policies,classify,resolve-me}`. Server helper:
`(*sso.Server).ClassifyRequest(r)`. Backends: `memory`, `etcd`
(cluster-shared); both funnel seeds through
`config.ApplyNetworkPolicySeeds`.

### Bootstrap (`bootstrap/`)
Versioned first-run init. `Step = Name()/Version()/Run(ctx)`; Runner
re-runs only `Version > high-water`. Trackers: `memory` (tests), `file`
(atomic JSON, single-node default). Lock SPI in `lock/`: `noop`, `file`
(flock), `etcd` (lease+Txn). Wired via
`WithLock`/`WithLockTTL`/`WithLockBlocking`. Lock loss cancels
in-flight Steps + surfaces `ErrLockLost`.

Built-in `bootstrap/builtin/` Steps under namespace `"sso-server"`:

| v | Effect |
|---|---|
| 0 | `restore_from_snapshot` (when `snapshot.restore_from` set) |
| 1 | `seed_admin_role` (sso-admin, admin:*) |
| 2 | `seed_admin_user` — prints generated password ONCE to stdout |
| 3 | `seed_default_netpolicy` (intranet RFC1918 if none) |
| 4 | `seed_admin_client` |

**Capture the admin password from boot log.** `ssoclient/bootstrap`
wraps file tracker + namespaced runner. `"sso-server"` namespace
reserved.

### Snapshot (`snapshot/`)
Export/restore operator state (clients, users, roles, role
assignments, menus, netpolicies, bootstrap high-water).

- `Snapshotter.Export` pulls every wired backend's `List()`.
- `Restorer.Restore` modes: `ModeMerge` (insert-only) / `ModeOverwrite`
  (upsert) / `ModeReplace` (wipe+seed, requires `Confirm ==
  SnapshotID`). `DryRun` returns counts only. `AdvanceBootstrap` bumps
  Tracker.
- Codec: JSON canonical, schema `"1"`. Sealers: `none` (typed no-op),
  `passphrase` (argon2id + XChaCha20-Poly1305 OWASP-2024), `aes-gcm`
  (direct 32-byte AES-256 key, for KMS-emitted DEKs). Storage: `file`
  (atomic 0o600), `inline` (memory). `Pipeline` composes with sha256
  verify (`ErrChecksumMismatch`).
- `snapshot/loader.FromURI` parses `file:///abs/path` + `inline:<base64>`.
- Admin RPC: `admin.v1.SnapshotAdminService` (admin:* gate).
- Offline CLI: `sso-snapshotctl list|inspect|verify` against a storage
  dir — bypasses the running server, useful for backup-pipeline
  integrity + DR drills. `verify` accepts `--passphrase` /
  `--passphrase-file`.

**First-boot auto-restore**: `snapshot.restore_from` YAML (or CLI
`--bootstrap-restore-from`, which wins) runs as `bootstrap/builtin`
v0 BEFORE the seed Runner so `AdvanceBootstrap` skips already-covered
seeds. Default mode: Overwrite.

**Retention** (`snapshot.PruneOldest`): keep last N by lexical order
of the `snap_<RFC3339>_<rand>` SnapshotID (chronological by
construction). Wired via `snapshot.retention.{enabled,keep,interval}`.

### Releases (`releases/`)
Admin app version pin / rollback. `Release` pairs frontend+backend
`Artifact` halves; `Validate` refuses one-sided releases.

- `ReleaseStore`: `memory`, `file` (atomic 0o600). Separates
  current-pointer from registration.
- `Pinner.PinForward` + `PinRollback` encode asymmetric ordering
  (backend-first forward, frontend-first rollback). Backends: `noop`,
  `static` (atomic symlink swap), `docker` (rewrite `.env` + `docker
  compose pull && up -d`).
- `Registry` composes Store + Pinner. Forward Pin rejects schema
  regression with `ErrSchemaRegress` — use Rollback.
- `HealthProbe` (e.g. `releases/probe/http`) gates forward Pin;
  all-fail → auto-rollback. No probe on Rollback.
- `SnapshotRestorer` hook on Rollback: non-empty `ConfigSnapshot`
  restores admin state BEFORE the Pinner flips.

Admin REST: `POST/GET /api/v1/admin/releases`, `/releases:current`,
`/releases/{id}[:pin,:rollback]`.

### Geo (`geo/`)
IP → enrichment as **UX hint, NOT security**. 200ms timeout;
`ErrNotFound` non-fatal; nil Provider = no-op. `geo/static` is CIDR
longest-prefix. Login response carries `country_code` +
`recommended_language` when stronger signal absent. Every Event gets
`geo.*` keys.

### Tenant (`tenant/`)
Multi-tenant + multi-domain routing. Tenant = business boundary;
Domain = hostname → Tenant (lowercase + trailing-dot-stripped per RFC
1035). **Tenant sits above `Client`** — one tenant typically owns many
clients sharing one audit. SQLite peer (`tenant/sqlite`) uses
`tenants` + `tenant_domains` with `FOREIGN KEY ... ON DELETE CASCADE`
so DeleteTenant doesn't leave orphan domain rows.

`Client.TenantID`: when set, login + token endpoints reject mismatches
with 403 `tenant_mismatch` audited as `login_failure`. Empty = served
from any tenant. `TenantScopedClientStore.ListByTenant` is the
optional admin-UI extension. Suspended tenants resolve to "no tenant"
by default. Every Event gets `tenant.*` keys.

**Active suspension** (`WithTenantSuspensionCheck(ttl)`): every token
whose `Client.TenantID` is set has its tenant Status looked up;
Suspended → `ErrTenantSuspended` (→ `invalid_token` at resource paths,
`inactive` at introspect). Without this option, existing tokens
continue post-suspension (only new issuance blocked). Cached `ttl`
(default 30s); admin SetStatus MUST call
`(*Server).InvalidateTenantSuspensionCache(id)`. Store outage is
fail-open by design.

**Admin RPCs**: `admin.v1.TenantAdminService` ships CRUD + surgical
`SetTenantStatus`. UpdateTenant preserves Status (no backdoor
suspension). DeleteTenant fires the invalidation callback.

### ssoclient
Per-capability client choice (Auth / Authz / Audit) — pick
`ssoclient/local` (in-process; pass the SDK provider directly) or
`ssoclient/remote` (gRPC + JWKS) per capability:

```go
handler := &appcore.Handler{
    Auth:  local.NewAuthClient(issuer, local.WithSessionManager(sessions)),
    Authz: remote.NewAuthzClient(grpcConn),
    Audit: remote.NewAuditClient(grpcConn),
}
```

`remote.JWKSCache` does background refresh + single-flight refetch on
unknown `kid`. `ssoclient/dev` provides bypass stubs for local UI
iteration (`AllowAll`, no-op audit). **Every dev constructor emits a
one-time stderr `AUTH BYPASS ACTIVE` warning;** suppress via
`WithSilent*` opts in tests.

### Edge (`deploy/`)
- **OpenResty** — `lua-resty-jwt` verifies via our JWKS; sets
  `X-Auth-Subject` / `X-Auth-Scopes` / `X-Network`. **Edge is
  fast-reject, not a trust boundary** — the Go server re-validates.
- **Kubernetes** — Kustomize base, distroless pod security
  (`runAsNonRoot`, `readOnlyRootFilesystem`, drop ALL caps,
  `seccompProfile: RuntimeDefault`). `configMapGenerator` hashes names
  for rolling restarts. Ingress / HPA / NetworkPolicy / PDB /
  ServiceMonitor in overlays.
- **docker compose** — sso-server + etcd + optional `--profile
  observability` (Prometheus + Grafana). Onboarding / smoke tests,
  NOT production-grade.
- **Grafana** — `sso-overview.json` + `alerts.yaml`. Thresholds are
  starting points.

### Middleware order
Probes registered OUTSIDE the stack so kubelet can't be throttled.

```
/metrics, /livez, /readyz                                (outside)
  ↓
tracing → ratelimit → bodyLimit → metrics → CORS → router
```

Wire each with `sso.With{Tracing, RateLimit, BodyLimit, Metrics, CORS}`.

**Ratelimit**: `Default` + ordered `Prefixes`. `KeyByClientIP` honors
XFF/X-Real-IP/RemoteAddr — **trust an edge or wrap in TrustedProxies
upstream**. `KeyByClientIDOrIP` keys by `client_id` for HTTP
Basic-authed /token-style requests, falling back to IP — body-supplied
credentials hit the IP fallback (avoids consuming r.Body). Composes
with `RiskScorer` (limiter rejects bots before scoring).

**Tracing**: `tracing.Init(ctx, ...)`; OTLP gRPC enabled by
`OTEL_EXPORTER_OTLP_ENDPOINT`. No-op when unset.

**ReadyCheck**: pluggable SPI; any failing check → 503. Aggregate 3s
deadline, with per-check override via `WithReadyCheckTimeout(name,
ttl)` (operator wires the timeout option before or after the check
option — they merge by name). Every SQLite store ships `Ping(ctx)`;
cmd auto-registers under `sqlite-<subsystem>` (memory backends silent
no-op). Payload: `{"status":"ready|unready","checks":{name:
"ok"|err}}`.

---

## 5. Observability

**Metrics** (bounded cardinality by design — no per-path / per-user
labels):

| Metric | Type | Labels |
|---|---|---|
| `sso_http_requests_total` | Counter | method, status_class |
| `sso_http_request_duration_seconds` | Histogram | method |
| `sso_login_attempts_total` | Counter | provider, outcome |
| `sso_login_duration_seconds` | Histogram | provider, outcome |
| `sso_tokens_issued_total` | Counter | strategy |
| `sso_risk_decisions_total` | Counter | decision |
| `sso_mfa_challenges_total` | Counter | mfa_method |
| `sso_mfa_completions_total` | Counter | mfa_method, outcome |
| `sso_mfa_completion_duration_seconds` | Histogram | outcome |
| `sso_webauthn_registrations_total` | Counter | outcome |
| `sso_webauthn_assertions_total` | Counter | outcome |
| `sso_retention_pruned_total` | Counter | subsystem |
| `sso_retention_prune_errors_total` | Counter | subsystem |
| `sso_anomalies_detected_total` | Counter | anomaly_type, severity |
| `sso_anomaly_dispatch_drops_total` | Counter | reason |
| `sso_anomaly_inspect_errors_total` | Counter | detector |

Per-endpoint breakdowns come from traces, not labels. MFA labels are
restricted to the wired provider's `SupportedMethods()` set
(`totp` / `webauthn` / `push`) — arbitrary user-controlled method
values are dropped before the label hits the registry, so an attacker
can't bloat metric cardinality.

`/health` exposes runtime build info (version + VCS revision + commit
time) via `runtime/debug.ReadBuildInfo` — operators can confirm which
commit a replica is running without shelling into the container.

### Retention schedulers
Three cmd-side background prune loops, all wired uniformly: cancel +
bounded-wait on Done during shutdown, log + emit
`sso_retention_pruned_total{subsystem}` /
`sso_retention_prune_errors_total{subsystem}`, transient errors don't
tear down the loop, first prune fires AFTER the first interval
(boot-safe). Each requires its SQLite backend (memory peers self-prune
by capacity or expiry).

| YAML knob | SDK function | Subsystem label |
|---|---|---|
| `audit.retention.{enabled,max_age,interval}` | `audit/sqlite.Sink.Prune` | `audit` |
| `snapshot.retention.{enabled,keep,interval}` | `snapshot.PruneOldest` | `snapshot` |
| `mfa.provider.push.prune_interval` | `defaultimpl/sqlite.PushApprovalStore.PruneExpired` | `push_approvals` |

---

## 6. Configuration

`cmd/sso-server/config.yaml` is the canonical reference. Top-level
keys map 1:1 to YAML; field coverage matches the SDK SPI. The
backend-coverage table in §4 enumerates every `backend(memory|sqlite)`
knob; this section only calls out the operator-surface items that
aren't obvious from the table.

- **server.issuer** MUST differ from `sso.DefaultIssuer` sentinel (cmd
  default `"sso-server"`; production SHOULD set the canonical public
  URL — same value stamped into JWT `iss`, discovery `issuer`, every
  RFC 9207 `iss` param).
- **clients[]** — every field maps 1:1 to `sso.Client` SPI.
  `client_id: ""` is a valid bucket (the demo uses it). Production
  tokens should carry an explicit audience.
- **bootstrap.lock.backend (noop|file|etcd)** — lock loss cancels
  in-flight Steps and surfaces `ErrLockLost`.
- **snapshot.restore_from** — URI for first-boot auto-restore (CLI
  `--bootstrap-restore-from` wins).
- **snapshot.encryption.backend (none|passphrase|aes-gcm)** —
  passphrase derives the AEAD key via argon2id (for human-typed
  secrets); aes-gcm takes a direct 32-byte key (for KMS-emitted
  DEKs; `key_file` accepts raw / hex / base64).
- **security.mtls.backend (tls|header)**: tls for in-process
  termination; header for reverse-proxy edges (nginx
  `X-SSL-Client-Cert`, AWS ALB `X-Amzn-Mtls-Clientcert`, Apache
  `Ssl-Client-Cert`) — **edge MUST strip the header from untrusted
  traffic**, same threat model as XFF.
- **tenant.suspension_check.cache_ttl** controls Active-suspension
  cache; admin SetStatus invalidates per-replica via
  `Server.InvalidateTenantSuspensionCache`.
- **oauth.jar** = RFC 9101 §5.2.2 request_uri fetcher (HTTPS,
  no-redirect).
- **mfa** — step-up orchestration gated by Risk's
  `DecisionRequireMFA`. `provider.kind`: `totp` / `webauthn` / `push`
  (each shares its underlying authenticator/helper — one enrollment,
  two roles) / `multi` with `provider.kinds: [...]` composing leaves.
  cmd fails loud on missing leaf deps. `push.transport`: `log`
  (structured-log stub) or `webhook` (POSTs to operator URL —
  `mfa.provider.push.webhook.*` for URL + auth + retry tuning).
  Custom transports (FCM/APNs) ship via cmd fork against the stable
  `PushTransport` SPI. Push-approval user-device callback resolves
  approvals via `PushApprovalStore.SetStatus` — operators either
  build their own handler OR opt into cmd's reference at
  `POST /push/approval/:id/:decision` toggled by
  `mfa.provider.push.callback.{enabled,bearer_token,allowed_cidrs}`
  (bearer + IP allowlist; empty both = open, only safe behind an
  auth-enforcing edge).

### Multi-source loader

`config.Loader` composes prioritized `Source`s (lowest first; last
wins):

| Source | When |
|---|---|
| `NewFileSource(path)` | Baseline YAML |
| `NewEnvSource()` | 12-factor (`SSO_<UPPER>__...`) |
| `etcd.New(cfg)` | Centralized live config |
| `NewFlagSource(fs)` | CLI overrides via `Bind()` |

Maps deep-merge; scalars + slices overwrite. Leaf strings from
env/etcd pass through `yaml.Unmarshal` so `"true"` → bool, `"42"` →
int. `config.Load(path)` is the legacy single-source entry point.

---

## 7. Operations

### CLIs

| Binary | Purpose |
|---|---|
| `cmd/sso-server` | Production binary |
| `cmd/sso-audit-verify` | Offline hash-chain integrity check (`--from-url` paginates, `--from-file` reads JSON) |
| `cmd/sso-snapshotctl` | Offline snapshot `list|inspect|verify` against a storage dir (passphrase-capable) |

Both offline CLIs operate directly against wire artifacts — no
running server required. Useful for backup-pipeline integrity + DR
drills.

### Release pipeline

`goreleaser` driven from `.github/workflows/release.yml` on `vX.Y.Z`
tags. Matrix: linux+darwin × amd64+arm64 + windows/amd64. Each archive
bundles LICENSE + SECURITY.md + CHANGELOG.md; `checksums.txt` +
per-archive syft SBOMs.

Today `release.disable: true` short-circuits publish — CI runs the
full build+SBOM matrix without uploading. Flip when a target lands.
Locally: `make release-snapshot` → `dist/`.

### API specs

| Surface | Source of truth | Consumers |
|---|---|---|
| HTTP | `docs/openapi.yaml` (OpenAPI 3.0) | swagger-ui, Postman, OpenAPI Generator |
| gRPC | `proto/*.proto` | `protoc` / `buf`, BSR, grpc-gateway |

Update `docs/openapi.yaml` in the same commit as any documented
endpoint change. CI runs `make docs-validate`.

`docs/error-codes.md` is the stable wire-contract catalog of every
`error` value. **Adding a new `Err*` anywhere (`consts.go` OR a
per-handler file like `jar.go` / `rar.go` / `step_up_auth.go`)
requires updating the catalog in the same commit.** SPAs branch on
`error`, never on `error_description`.

---

## 8. Working in this repo

### Conventions
- **No literal leaks** — paths, headers, error codes live in
  `consts.go` (root or per-package).
- **No mocks for storage** — use real `MemoryProvider` / `MemorySink` /
  `memory.Registry`.
- **No emojis** in code, comments, or commits.
- **Comments explain WHY**, not what. Reach for one only for hidden
  constraints, invariants, or workarounds.
- **Interface guards in implementation packages**, e.g. `var _
  ssoclient.AuthClient = (*remote.AuthClient)(nil)` in
  `ssoclient/remote/` — never in `ssoclient/` (cycle).
- **gRPC name renames**: protoc-gen-go does `ID→Id`, `URL→Url`.
- **Tests in same package** as behavior. Race / ordering fixes prove
  with `-count=10+`.

### Don'ts
- Don't run `git reset --hard`, `git push --force`, `branch -D`
  without explicit authorization.
- Don't init or modify git config.
- Don't bypass pre-commit hooks (`--no-verify`, `--no-gpg-sign`).
- Don't introduce mocks where a real in-memory impl exists.
- Don't add "while I'm here" cleanup or refactors.
- Don't write Markdown files unless asked.
- Don't violate oracle-leak / anti-enumeration patterns — stability
  contracts, not style.
- Don't bypass `setMeta` for audit metadata.

### Common tasks

**New authenticator**: implement `sso.Authenticator` in
`authenticators/<name>.go` → YAML knob under `authenticators:` in
`config/config.go` → wire in `cmd/sso-server/main.go`
`buildAuthenticators` → whitelist under a client's
`allowed_authenticators:` to test.

**New audit Sink**: implement `audit.Sink` (`Record(ctx, *Event)
error`); add `audit.Closer` if lifecycle. Wire via `audit.New(s1,
s2, ...)` or `audit.MultiSink`.

**New permissions backend**: implement `permissions.Provider` in
`permissions/<name>/`. Plumb via `sso.WithPermissionProvider(...)`.
Keep wildcard matcher semantics (`*`, `pkg:*`). Run
`permissionstest.ConformanceSuite` against the new peer.

**New netpolicy at runtime**: `POST /api/v1/netpolicy/policies` (or
gRPC `PolicyService.Apply`); watchers pick up via Watch. Boot-time
seed: add to `network.policies:`.

**New gRPC service**: write `proto/<name>/v1/<name>.proto` →
regenerate → implement server in `grpcserver/<name>.go` over an
interface the HTTP layer already uses → register in
`cmd/sso-server/main.go` `newGRPCServer` → add a `bufconn`-based
test in `grpcserver/`.

**New OAuth/OIDC grant**: handler in `handle_<grant>.go` using
`bindOAuthParams`; honor HTTP Basic > body credentials; map errors to
`400 invalid_<...>` following the oracle-leak pattern; single-use:
atomic delete-and-return (SQLite `DELETE RETURNING`; Redis `GETDEL`);
wire in `sso.go` (`s.router.POST(...)`); advertise in
`oidc_discovery.go`; add `WithXxxStore(store, ttl)`; tests in same
package enumerating oracle-leak failure cases.

**New credential / bearer-protected endpoint**: call
`tokenNoStoreHeaders(ctx)` at handler entry; for bearer-protected
endpoints use `setBearerChallenge(ctx, ...)` on 401.

### Commits

- Conventional: `feat(area): summary`, `fix(area): summary`, `chore:`,
  `docs:`. Imperative subject; blank line; body explains why.
- Co-author trailer when AI-assisted.
- Don't commit binaries — `sso-server` / `sso-audit-verify` /
  `sso-snapshotctl` are ignored.
