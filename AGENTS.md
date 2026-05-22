# AGENTS.md

Operational guide for AI agents in this repo. Follows
[agents.md](https://agents.md). User instructions override conflicts
below.

---

## What this is

`github.com/snaplink/sso` — Go SSO server SDK + runnable binary. OAuth
2.0 + OIDC, swappable authenticators, audit, permissions, service
registry, admin gRPC/REST, snapshot + release lifecycle. Every concern
is an interface; defaults live in `defaultimpl/` (memory) and
`defaultimpl/sqlite/` (pure-Go, no CGO). No external SaaS dep.
Consumers wire **embedded** (`ssoclient/local`, in-process) or
**centralized** (`ssoclient/remote`, gRPC + JWKS) per capability.

`examples/{embedded-app,remote-app}` share the same `appcore.Handler`;
only wiring differs.

---

## Build, test

```bash
go build ./...
go test ./... -race
go test -run TestE2E -v .       # cross-wire HTTP + JWKS + bufconn
make ci                          # gofmt + vet + race + build + proto-lint
make docker
make release-snapshot
```

Run E2E whenever you change anything crossing the gRPC or JWKS wire.

Protobuf regen (stubs checked in, rarely needed):

```bash
protoc -I proto \
  --go_out=gen/proto --go_opt=paths=source_relative \
  --go-grpc_out=gen/proto --go-grpc_opt=paths=source_relative \
  proto/<svc>/v1/<svc>.proto
```

---

## Layout

```
sso.go / handler.go / router.go     Server, HandlerContext, routing
consts.go                           Paths, headers, error codes
handle_*.go                         Per-endpoint HTTP handlers
oauth_bind.go                       form+JSON dispatcher
authenticators/                     9 pluggable + webauthn/ helper
defaultimpl/                        Default issuer + Memory* stores
defaultimpl/sqlite/                 Pure-Go SQLite (no CGO)
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

## Stability contracts (invariants)

Violating these is a regression — wire-contract gates, not style.

### Plugin SPI + storage
Every concern is an interface in its parent package + a `memory` impl
+ optionally `sqlite` / `etcd` / `file`. New backends slot in via
`WithXxx`. **No mocks** — use Memory* in tests. SQLite covers User,
Client, AuthCode, RefreshToken (+ Inspector + FamilyTracker),
DeviceCode, PAR, Session, JTIReplay, SubjectClientIndex,
AccountLockout, PairwiseSubject, RateLimiter, WebAuthn (User + Session),
MFAChallenge — every OAuth/OIDC + WebAuthn + MFA flow runs horizontally
on a shared SQLite file. Redis is the recommended next step for
SaaS-scale auth-heavy workloads.

### Form + JSON via `bindOAuthParams`
All OAuth/OIDC endpoints accept both `application/x-www-form-urlencoded`
(RFC mandatory) and JSON via the dispatcher in `oauth_bind.go`.
JSON-only would break every off-the-shelf OAuth client.

### HTTP Basic > body credentials (RFC 6749 §2.3.1)
On `/token`, `/token/introspect`, `/token/revoke`, `/par`:
`Authorization: Basic` beats body `client_id`+`client_secret`.

### Oracle-leak hardening
Single-use code consumption (AuthCode / Refresh / Device / PAR / PKCE
verifier) MUST collapse unknown / expired / consumed / client-mismatch
into one wire response (`400 invalid_grant` for /token;
`invalid_request_uri` for PAR; etc.). DPoP/mTLS failures →
`invalid_token`; `private_key_jwt` failures → `invalid_client`. Tests
enumerate the failure cases to lock the behavior.

### Anti-enumeration
- `/register/:client_id` (RFC 7592): missing / wrong bearer / unknown
  id all return identical 401 `invalid_token`. Bearer compare uses
  `crypto/subtle.ConstantTimeCompare`.
- `/token/revoke` (RFC 7009 §2.2): 200 OK on valid client creds
  regardless of token existence.
- `/token/introspect` inactive: `{"active":false}`.
- Bcrypt password verifier runs against a cost-matched dummy hash for
  unknown users (timing parity).
- WebAuthn unknown user / unknown session both collapse to `404
  session_invalid`.
- MFA orchestration: unknown / expired / already-consumed challenge,
  unsupported method, wrong factor — all collapse to `400 mfa_invalid`
  on `/auth/mfa`. Operator-visible detail surfaces via the
  `mfa_failure` audit event only.

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

### Audit metadata: `setMeta(e, k, v)`
Geo + tenant middleware enrich every event via `Event.Metadata`.
**Never** assign `e.Metadata = map{...}` — it clobbers enrichment.

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
inbound subject_token. `client_credentials` populates `ClientID` only.
`jti` always auto-generated.

### Discovery is derived
`/.well-known/openid-configuration` computed from server state:
endpoints from request base URL, scopes from union of `openid` + every
client's `AllowedScopes`, opt-in features (PAR, DCR, JARFetcher, mTLS,
BCL) flip flags only when wired. New opt-in → branch the doc.

### `iss` on authorization responses (RFC 9207)
Every `/auth/login` response — success, error, provider-list — carries
`iss` via `s.resolveIssuer(ctx)`, which MUST equal discovery `issuer`.
New authorization-flow handlers MUST use `s.authzErrorBody(ctx, code)`,
not plain `errorBody`.

### JWKS + discovery caching
- JWKS: `Cache-Control: public, max-age=<ttl>` + `ETag = sha256(body)[:8]`.
  Default TTL 5min via `WithJWKSCacheTTL`. Rotation serves both
  outgoing and incoming keys.
- Discovery double-cached: `WithDiscoveryCacheTTL` (default 5s) caches
  the snapshot; `WithDiscoveryDocCacheTTL` (default 5s) caches body +
  `ETag = sha256(body)[:8]` keyed by request base URL (multi-host
  safe), honors `If-None-Match` → 304. Body TTL 0 disables both the
  in-process cache AND response headers.

### Cache headers on credential endpoints (RFC 6749 §5.1)
`/token`, `/token/introspect`, `/token/revoke`, `/token/revoke-all`,
`/par`, `/auth/login`, `/userinfo`, `/register*` stamp `Cache-Control:
no-store` + `Pragma: no-cache` via `tokenNoStoreHeaders(ctx)` — same
rule applies to error responses (a 401 from /userinfo cached cross-user
would be catastrophic). New credential endpoint: one-line opt-in.

### WWW-Authenticate on 401 (RFC 6750 §3)
Resource endpoints stamp a Bearer challenge via `setBearerChallenge`.
Missing-token omits `error=`; validation failure carries
`error="invalid_token"`. Descriptions pass `quoteAuthParam` to prevent
auth-param injection.

---

## OAuth 2.0 / OIDC surface

One row per spec; file is the owner. Gotchas above apply across grants.

| Spec | Endpoint(s) | Opt-in | File |
|---|---|---|---|
| RFC 6749 §4.1 authorization_code | `/auth/login` + `/token` | `WithAuthCodeStore` | `auth_code.go` |
| RFC 6749 §4.4 client_credentials | `/token` | always | `handle_token_*.go` |
| RFC 6749 §6 refresh_token | `/token` | `WithRefreshTokenStore` | `refresh_token.go` |
| RFC 7636 PKCE | /auth/login + /token | per-request / `Client.RequirePKCE` | `auth_code.go` |
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
| RFC 7521 + 7523 `private_key_jwt` | `/token`, `/par`, `/introspect`, `/revoke` | `Client.JWKS` | `jwt_client_assertion.go` |
| OIDC `prompt=none` | `/auth/login` | `WithSessionManager` + `WithIDTokenIssuer` | `prompt.go` |
| RFC 9207 AS Issuer Id | every `/auth/login` | always | `iss_response.go` |
| RFC 9068 JWT Access Token | `Ed25519JWTIssuer` | always | `defaultimpl/ed25519_jwt_issuer.go` |
| RFC 8705 mTLS-bound + aliases | `/token` + `/userinfo` | `WithClientCertExtractor` | `mtls_bound.go` |
| RFC 9470 Step-Up | resource-server helper | always | `step_up_auth.go` |
| RFC 9449 DPoP | `/token` + `/userinfo` | header-triggered; replay via `WithJTIReplayStore`; nonce via `WithDPoPNonceProvider` | `dpop.go` + `dpop_nonce.go` |
| RFC 8414 §2.1 signed_metadata | discovery | `WithMetadataSigner` (Ed25519JWTIssuer satisfies) | `oidc_discovery.go` |
| OAuth 2.1 strict | `/auth/login` | `WithOAuth21StrictMode` | `handler.go` |
| RFC 9396 RAR | `authorization_details` | per-client allowlist | `rar.go` |
| RFC 9101 JAR | `request`, `request_uri` | `Client.JWKS`; URL via `WithJARFetcher` + `AllowedRequestURIs`; required via `Client.RequireSignedRequestObject` | `jar.go` + `jar_fetch.go` |
| RFC 9101 §6.4 JWE JAR | `request` (JWE-wrapped) | `WithJARDecrypter`; default `defaultimpl.RSAJWEDecrypter` (RSA-OAEP-256 + A256GCM); enc public key auto-published in JWKS with `use:enc` | `jwe.go` + `defaultimpl/rsa_jwe_decrypter.go` |
| Per-account lockout | `/auth/login` | `WithAccountLockout` | `account_lockout.go` |

**Token strategies** are per-client (`token_strategy: jwt|session`):
- `TokenStrategyJWT` — Ed25519 + JWKS, stateless. Pass the same
  `Ed25519JWTIssuer` to `WithTokenIssuer` and `WithIDTokenIssuer`.
- `TokenStrategySession` — opaque, backed by `SessionManager`.

Register via `sso.WithTokenIssuer(name, issuer)`.

---

## Subsystems

### Authenticators (`authenticators/`)
9 pluggable: `password`, `phone`, `email`, `temp_token`, `keypair`,
`apikey`, `certificate`, `totp` (RFC 6238), `oidc_federation` (Google /
Microsoft / GitHub / Auth0 / Keycloak at
`/auth/login?provider=<name>`). `allowed_authenticators` per client
gates methods. **password**: cmd verifies bcrypt hashes loaded from
per-user files; unknown users hit a cost-matched dummy hash for timing
parity.

**WebAuthn** (CTAP/FIDO2) ships at `authenticators/webauthn/`. The
four-call begin/finish ceremony doesn't fit the single-step
Authenticator interface, so the package exposes
`Helper.{BeginRegistration, FinishRegistration, BeginLogin,
FinishLogin}`. cmd mounts `/webauthn/{registration,login}/{begin,finish}`
on the SSO router via `Server.Handle(method, path, http.HandlerFunc)`
when `webauthn.enabled`, sharing the standard middleware stack.

`/webauthn/login/finish?client_id=...` mints tokens for the
authenticated subject (AMR=`["webauthn"]`, scopes default to client's
`AllowedScopes`). `id_token` rides along when client has `openid` +
`WithIDTokenIssuer` wired; `refresh_token` when `WithRefreshTokenStore`
wired; missing deps degrade silently. Without `client_id` the response
is the v1 credential-verification shape (embedders unaffected).

Pluggable `UserStore` + `SessionStore`; SQLite peers at
`authenticators/webauthn/sqlite/` for multi-replica deploys
(`UserStore` upserts inside `BEGIN IMMEDIATE`; `SessionStore` uses
`DELETE … RETURNING` for single-use ceremony state). Built on
`github.com/go-webauthn/webauthn`.

### SQLite (`defaultimpl/sqlite/`)
Pure-Go via `modernc.org/sqlite`. Race-free patterns by store:
- single-use (AuthCode, DeviceCode, RefreshToken, PAR, MFAChallenge): `DELETE … RETURNING`
- Session refresh: `UPDATE … RETURNING`
- JTI replay: `INSERT … ON CONFLICT DO NOTHING` + RowsAffected
- index upserts (SubjectClientIndex, PairwiseSubject): `INSERT … ON CONFLICT DO UPDATE`
- AccountLockout: read-modify-write inside `BEGIN IMMEDIATE`

Production DSN: `file:/var/lib/sso/sso.db?_journal=WAL&_busy_timeout=5000`.
Shared-pool tests: `file::memory:?cache=shared`. Schema via `CREATE
TABLE IF NOT EXISTS` at construction. Constructor: `New<Provider>(dsn)`
/ `Close()` / `New<Provider>WithDB(db)` for shared pools.
`sql.ErrNoRows` → typed `ErrNoSuchX`. Timestamps as Unix-ns INTEGER.
**The next multi-table backend MUST bring goose/golang-migrate.**

### Audit (`audit/`)
`audit.Recorder` fans Events to `Sink`s. Built-in: `MemorySink`,
`WriterSink`, `WebhookSink`, `MultiSink`, plus SQLite at `audit/sqlite`
(queryable, restart-durable, replica-shared via shared DSN). Every
Event carries W3C `TraceID` / `SpanID` / `ParentSpanID`.

Optional wrappers:
- **Hash chain** (`audit.WithHashChain`): stamps `PrevHash` + `Hash`;
  `audit.VerifyChain(events)` validates oldest-first. The
  `sso-audit-verify` CLI pages `/api/v1/audit/events` (or reads a JSON
  file), reverses, validates, exits non-zero on a break.
- **PII redaction** (`audit.WithRedactor`): runs BEFORE the chainer.
  Helpers: `RedactActorIDHash(salt)`, `RedactIPTruncate`,
  `RedactUserAgent`, `RedactMetadataKeys(...)`,
  `DefaultPIIRedactor(salt)`.
- **Retry** (`audit.NewRetryingSink`): exponential backoff + jitter.
  Options for max attempts, backoff bounds, error classifier.
- **Async** (`audit.NewAsyncSink(...).Start()`): bounded buffer +
  worker pool; Record never blocks the request path. Drop reasons:
  `ErrAsyncQueueFull` / `ErrAsyncSinkClosed` / inner errors. Caller
  ctx intentionally dropped (TraceID rides on Event). Use for
  WebhookSink; skip for Memory/Writer. Observability via
  `metrics.NewAsyncSinkCollector(asyncSink)` — exposes all 5 series
  (`sso_audit_async_drops_*`, `sso_audit_async_queue_*`) without a
  polling goroutine.

Recommended cluster composition:
`AsyncSink(MultiSink(SQLitePrimary, RetryingSink(WebhookSink)))`.

### Permissions (`permissions/`)
`MemoryProvider`: per-APP role registries, wildcard matcher (`user:*`
matches `user:read`, `*` matches all), menu filtering, login-response
embedding via `WithEmbedPermissionsInLogin()`. `MenuLister` is the
extension snapshots + admin RPCs use.

### Service registry (`registry/`)
`memory` (TTL + Watch) and `etcd` (lease + KeepAlive). cmd's
`buildRegistry` selects on `registry.backend`; etcd path materialized
in cmd to keep the transitive dep out of the registry SPI. cmd
self-registers as `Name: "sso"`, `Service.ID = registry.service_id`
(defaults `<issuer>-<short-hostname>` to prevent replica clobber).
`Service.TTL` defaults 30s under etcd. etcd `Ping(ctx)` →
`etcd-registry` on /readyz.

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
(cluster-shared, etcd path materialized in cmd); both funnel seeds
through `config.ApplyNetworkPolicySeeds`. etcd `Ping(ctx)` →
`etcd-netpolicy` on /readyz.

### Bootstrap (`bootstrap/`)
Versioned first-run init. `Step = Name()/Version()/Run(ctx)`; Runner
re-runs only `Version > high-water`. Trackers: `memory` (tests),
`file` (atomic JSON, single-node default). Lock SPI in `lock/`:
`noop`, `file` (flock), `etcd` (lease+Txn). Wired via
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
Export/restore operator state (clients, users, roles, role assignments,
menus, netpolicies, bootstrap high-water).

- `Snapshotter.Export` pulls every wired backend's `List()`.
- `Restorer.Restore` modes: `ModeMerge` (insert-only) / `ModeOverwrite`
  (upsert) / `ModeReplace` (wipe+seed, requires `Confirm == SnapshotID`).
  `DryRun` returns counts only. `AdvanceBootstrap` bumps Tracker.
- Codec: JSON canonical, schema `"1"`. Sealers: `none` (typed no-op),
  `passphrase` (argon2id + XChaCha20-Poly1305 OWASP-2024). Storage:
  `file` (atomic 0o600), `inline` (memory). `Pipeline` composes with
  sha256 verify (`ErrChecksumMismatch`).
- `snapshot/loader.FromURI` parses `file:///abs/path` + `inline:<base64>`.
- Admin RPC: `admin.v1.SnapshotAdminService` (admin:* gate).
- Offline CLI: `sso-snapshotctl list|inspect|verify` against a storage
  dir — bypasses the running server, useful for backup-pipeline
  integrity + DR drills. `verify` accepts `--passphrase` /
  `--passphrase-file` for the encrypted case.

**First-boot auto-restore**: `snapshot.restore_from` YAML (or CLI
`--bootstrap-restore-from`, which wins) runs as `bootstrap/builtin` v0
BEFORE the seed Runner so `AdvanceBootstrap` skips already-covered
seeds. Default mode: Overwrite.

### Releases (`releases/`)
Admin app version pin / rollback. `Release` pairs frontend+backend
`Artifact` halves; `Validate` refuses one-sided releases.

- `ReleaseStore` separates current-pointer from registration:
  `memory`, `file` (atomic 0o600).
- `Pinner.PinForward` + `PinRollback` encode asymmetric ordering
  (backend-first forward, frontend-first rollback). Backends: `noop`,
  `static` (atomic symlink swap), `docker` (rewrite `.env` +
  `docker compose pull && up -d`).
- `Registry` composes Store + Pinner. Forward Pin rejects schema
  regression with `ErrSchemaRegress` — use Rollback.
- `HealthProbe` (e.g. `releases/probe/http`) gates forward Pin; all-fail
  → auto-rollback. No probe on Rollback.
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
clients sharing one audit.

`Client.TenantID`: when set, login + token endpoints reject mismatches
with 403 `tenant_mismatch` audited as `login_failure`. Empty = served
from any tenant. `TenantScopedClientStore.ListByTenant` is the optional
admin-UI extension. Suspended tenants resolve to "no tenant" by
default. Every Event gets `tenant.*` keys.

**Active suspension** (`WithTenantSuspensionCheck(ttl)`): every token
whose `Client.TenantID` is set has its tenant Status looked up;
Suspended → `ErrTenantSuspended` (→ `invalid_token` at resource paths,
`inactive` at introspect). Without this option, existing tokens
continue post-suspension (only new issuance blocked). Cached `ttl`
(default 30s); admin SetStatus MUST call
`(*Server).InvalidateTenantSuspensionCache(id)`. Store outage is
fail-open by design.

**Admin RPCs**: `admin.v1.TenantAdminService` ships CRUD on Tenants +
Domains plus surgical `SetTenantStatus`. Update preserves current
Status (no backdoor suspension via UpdateTenant). DeleteTenant also
fires the invalidation callback.

### ssoclient
```go
// Embedded:
handler := &appcore.Handler{
    Auth:  local.NewAuthClient(issuer, local.WithSessionManager(sessions)),
    Authz: local.NewAuthzClient(prov),
    Audit: local.NewAuditClient(recorder),
}
// Centralized:
handler := &appcore.Handler{
    Auth:  remote.NewAuthClient(remote.NewJWKSCache(jwksURL)),
    Authz: remote.NewAuthzClient(grpcConn),
    Audit: remote.NewAuditClient(grpcConn),
}
```

Each capability chooses independently. `remote.JWKSCache` does
background refresh + single-flight refetch on unknown `kid`.

`ssoclient/dev` provides bypass stubs for local UI iteration:
`ValidateToken` → fake Subject, `Check` → AllowAll, `Record` → no-op.
**Every constructor emits a one-time stderr `AUTH BYPASS ACTIVE`
warning.** Suppress in tests via `WithSilent` / `WithSilentAuthz` /
`WithSilentAudit`.

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

**Metrics** bounded by design (no per-path / per-user labels):

| Metric | Type | Labels |
|---|---|---|
| `sso_http_requests_total` | Counter | method, status_class |
| `sso_http_request_duration_seconds` | Histogram | method |
| `sso_login_attempts_total` | Counter | provider, outcome |
| `sso_tokens_issued_total` | Counter | strategy |
| `sso_risk_decisions_total` | Counter | decision |
| `sso_mfa_challenges_total` | Counter | mfa_method |
| `sso_mfa_completions_total` | Counter | mfa_method, outcome |

Per-endpoint breakdowns come from traces, not labels. MFA labels
are restricted to the wired provider's `SupportedMethods()` set
(cmd-defined: `totp`, `webauthn`, `push`) — arbitrary user-controlled
method values are dropped before the label hits the registry, so an
attacker can't bloat metric cardinality.

**Tracing**: `tracing.Init(ctx, ...)`; OTLP gRPC enabled by
`OTEL_EXPORTER_OTLP_ENDPOINT`. No-op when unset.

**Ratelimit**: `Default` + ordered `Prefixes`. `KeyByClientIP` honors
XFF/X-Real-IP/RemoteAddr — **trust an edge or wrap in TrustedProxies
upstream**. `KeyByClientIDOrIP` keys by `client_id` for HTTP
Basic-authed /token-style requests, falling back to IP — body-supplied
credentials hit the IP fallback (avoids consuming r.Body). Composes
with `RiskScorer` (limiter rejects bots before scoring).

**ReadyCheck**: pluggable SPI; any failing check → 503. Bounded 3s
deadline. Every SQLite store ships a `Ping(ctx)`; cmd auto-registers
one per wired store via `appendReadyCheck`, naming each after the
subsystem (`sqlite-identity-clients`, `sqlite-oauth-refresh-tokens`,
`sqlite-jti-replay`, `sqlite-account-lockout`,
`sqlite-pairwise-subjects`, `sqlite-bcl-subject-client-index`,
`sqlite-webauthn-{users,sessions}`, `sqlite-mfa-challenges`, etc.).
SQLite rate limiter
participates too: `sqlite-ratelimit-default` + `sqlite-ratelimit-<prefix>`
per declared prefix (slashes collapse to hyphens). etcd backends
register as `etcd-netpolicy` / `etcd-registry`. Memory backends
silently no-op. Payload:
`{"status":"ready|unready","checks":{name: "ok"|err}}`.

### Risk scoring (`risk.go`)
`RiskScorer` runs on `/auth/login` AFTER credential validation, BEFORE
token issuance. Returns `Allow` / `RequireMFA` (gates the MFA flow
below) / `Deny` (403 + audit `login_failure reason=risk_denied`).
**Fail-open** on scorer error (alert on the log line). **Zero overhead**
when option unset.

Reference impls in `defaultimpl/`:
- `NoopRiskScorer` — typed Allow-always.
- `RuleBasedRiskScorer` — declarative IP / country deny-and-allow lists.
  cmd wires when `risk.enabled`. Eval order: IP deny → IP allow
  default-deny → country deny → country allow; `deny_on_geo_missing`
  promotes country allow to hard-required when geo enrichment is
  absent.

Richer scorers (impossible-travel, device fingerprint, ML) implement
[sso.RiskScorer] directly and query their own store inside `Score` —
don't pad `RiskRequest`.

### MFA orchestration (`mfa.go` + `handle_mfa.go`)
Two-leg step-up flow gated by `RiskScorer` returning `DecisionRequireMFA`.
Without `WithMFAProvider` + `WithMFAChallengeStore` wired, RequireMFA
decays to Allow (back-compat for callers shipping a forward-looking
scorer ahead of MFA orchestration).

Wire shape:
- `/auth/login` returns `{error: mfa_required, mfa_challenge_id,
  mfa_methods: ["totp"], iss}` instead of tokens (HTTP 200 — the
  primary credential validated, it's just pending step-up).
- Client POSTs `/auth/mfa` with `{mfa_challenge_id, mfa_method, code |
  assertion | params}`; on success the server replays `finishLogin`
  against the frozen state and returns the standard direct-mint /
  code / form_post response. The caller can't tell an MFA-gated login
  from a non-gated one.
- Oracle-leak hardening: missing / expired / consumed challenge,
  unsupported method, wrong factor — all collapse to `400 mfa_invalid`.
  Operator-visible reasons ride on `mfa_failure` audit events only.
- Single-use: `MFAChallengeStore.Consume` atomically deletes; replay
  → `mfa_invalid`.
- Client / tenant re-validated on resume (deactivated between login
  and /auth/mfa surfaces as `inactive_client`, distinct from `mfa_invalid`
  so SIEM can tell it wasn't the factor that failed).
- Discovery: when wired, `mfa_endpoint` + `mfa_methods_supported`
  appear in `/.well-known/openid-configuration`.

`MFAProvider` is pluggable; ship-included impls:
- `authenticators.TOTPMFAProvider` adapts an existing
  `TOTPAuthenticator` so the same TOTPStore + skew config serves
  primary auth (when wired) AND step-up. Single-call factor.
- `authenticators/webauthn.WebAuthnMFAProvider` adapts an existing
  WebAuthn `Helper` so the same UserStore + SessionStore + RP config
  serves primary `/webauthn/login/{begin,finish}` AND step-up.
  Two-call factor — implements `MFABeginner` so the server
  pre-issues the assertion challenge into
  `mfa_method_data["webauthn"]` on the `mfa_required` response;
  client signs and replays via /auth/mfa params. Subject binding
  (resolved user ≡ SubjectID) enforced on Verify.

Two-call factors implement the optional `MFABeginner` interface
(`Begin(ctx, subjectID, method) (map[string]string, error)`). The
SSO server type-asserts during `issueMFAChallenge`: providers
implementing the interface get one Begin call per supported method,
results bucketed under the response's `mfa_method_data` key.
Single-call factors (TOTP) don't implement the interface; the
response omits the key. Per-method Begin failure is non-fatal —
method stays in `mfa_methods`, just without an attached
`mfa_method_data` entry.

Custom factors (push notification, hardware FIDO2 outside WebAuthn,
upstream IdP step-up) implement `MFAProvider` directly + `MFABeginner`
when they need server-side challenge issuance. `SupportedMethods()`
populates the wire `mfa_methods` array; `Verify()` returns nil on
success, any error on failure (collapsed to `mfa_invalid`).

`MFAChallengeStore`: in-process `defaultimpl.MemoryMFAChallengeStore`
for single-replica deploys; `defaultimpl/sqlite.MFAChallengeStore`
for cluster-shared state (atomic `DELETE … RETURNING` Consume; row
deletion enforces single-use even on expired-entry consume). Default
TTL 5min (`DefaultMFAChallengeTTL`); tune via the ttl arg on
`WithMFAChallengeStore`.

Audit events: `mfa_required` (challenge issued), `mfa_success`
(factor verified), `mfa_failure` (factor rejected). The standard
`login_success` event still fires on the resume, so existing SIEM
queries continue to work — MFA gating is additive observability.

---

## Configuration

`cmd/sso-server/config.yaml` is the canonical reference. Top-level
keys map 1:1 to YAML; field coverage matches the SDK SPI. Areas where
the operator surface needs explanation:

- **server.issuer** MUST differ from `sso.DefaultIssuer` sentinel (cmd
  default `"sso-server"`; production SHOULD set the canonical public
  URL — same value stamped into JWT `iss`, discovery `issuer`, every
  RFC 9207 `iss` param).
- **server.pairwise_subjects.backend(memory|sqlite)** — sqlite shares
  reverse lookup so /userinfo resolves on any replica.
- **audit.backend(memory|sqlite)** — sqlite persists across restarts
  + shares state across replicas. `webhook` composes as
  `AsyncSink(MultiSink(Primary, RetryingSink(WebhookSink)))`.
  `audit.retention.{enabled,max_age,interval}` opts into a
  background prune loop against the SQLite primary (memory
  self-prunes by capacity); cmd cancels the loop during shutdown
  before draining the AsyncSink to avoid mid-prune contention.
- **network.store / registry.backend (memory|etcd)** — etcd path
  materialized in cmd to keep the transitive dep out of the SPI. etcd
  registry uses TTL lease; `service_id` defaults
  `<issuer>-<short-hostname>`.
- **clients[]** — every field maps 1:1 to `sso.Client` SPI (the cmd
  YAML surface used to drop ~15 of these silently; now full coverage).
- **bootstrap.lock.backend (noop|file|etcd)** — lock loss cancels
  in-flight Steps and surfaces `ErrLockLost`.
- **snapshot.restore_from** — URI for first-boot auto-restore (CLI
  `--bootstrap-restore-from` wins).
- **snapshot.retention.{enabled,keep,interval}** — background loop
  calling `snapshot.PruneOldest`; relies on the time-prefixed
  `SnapshotID` format for lexical ordering. Keep must be > 0 when
  enabled.
- **security** — every storage-backed defense (`rate_limit`,
  `jti_replay`, `account_lockout`) supports `backend(memory|sqlite)`
  for cluster-shared state. `mtls.backend(tls|header)`: tls for
  in-process termination; header for reverse-proxy edges (nginx
  `X-SSL-Client-Cert`, AWS ALB `X-Amzn-Mtls-Clientcert`, Apache
  `Ssl-Client-Cert`) — **edge MUST strip the header from untrusted
  traffic**, same threat model as XFF.
- **tenant.suspension_check.cache_ttl** controls Active-suspension
  cache; admin SetStatus invalidates.
- **oauth** — per-store `enabled` + `ttl`; `backend(memory|sqlite)`
  shared substrate. `oauth.jar` = RFC 9101 §5.2.2 request_uri fetcher
  (HTTPS, no-redirect).
- **identity.backend(memory|sqlite)** — User + Client + Session
  substrate.
- **backchannel_logout.index.backend(memory|sqlite)** — sqlite shares
  fan-out set across the cluster.
- **webauthn.storage.{users,sessions}.backend(memory|sqlite)**.
- **mfa** — opts into step-up orchestration gated by Risk's
  `DecisionRequireMFA`. Four `provider.kind` values: `totp` reuses
  the `authenticators.totp` secret store + skew (single enrollment,
  two consumer roles); `webauthn` reuses the `webauthn.enabled`
  Helper (UserStore + SessionStore + RP config — same enrollment
  as primary `/webauthn/login`); `push` wires the reference
  `defaultimpl.PushMFAProvider` with `push.backend(memory|sqlite)`
  and `push.transport=log` (operators fork cmd for FCM/APNs/webhook
  — the SDK's `PushTransport` interface is stable); `multi`
  composes several leaf kinds via `defaultimpl.MultiMFAProvider`,
  listed under `provider.kinds:` — operators offering concurrent
  TOTP fallback + WebAuthn primary use this.
  `challenge.backend(memory|sqlite)` shares in-flight MFA
  challenges across replicas. Disabled or unwired → RequireMFA
  decays to Allow (back-compat). cmd refuses `kind=totp` unless
  `authenticators.totp.enabled=true`, `kind=webauthn` unless
  `webauthn.enabled=true`, `kind=push` with unknown
  backend/transport or sqlite without DSN, and `kind=multi` with
  empty / single-entry / duplicate / nested-multi `kinds` lists.
  Two-call providers (WebAuthn, Push) implement [MFABeginner] so
  the `mfa_required` response surfaces
  `mfa_method_data["<method>"] = {...}` for the client; multi
  inherits this via the composite's MFABeginner. Push-approval
  user-device callbacks (PENDING → APPROVED/DENIED) are NOT
  shipped from cmd — operators build the handler against the
  SDK's `PushApprovalStore.SetStatus`.

`client_id: ""` is a valid bucket (the demo uses it). Production tokens
should carry an explicit audience.

### Multi-source loader

`config.Loader` composes prioritized `Source`s (lowest first; last wins):

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

## Operational tooling

| Binary | Purpose |
|---|---|
| `cmd/sso-server` | Production binary |
| `cmd/sso-audit-verify` | Offline hash-chain integrity check (`--from-url` paginates, `--from-file` reads JSON) |
| `cmd/sso-snapshotctl` | Offline snapshot `list|inspect|verify` against a storage dir (passphrase-capable) |

Both CLIs operate directly against wire artifacts — no running server
required. Backup-pipeline integrity + DR drills.

---

## Release pipeline

`goreleaser` driven from `.github/workflows/release.yml` on `vX.Y.Z`
tags. Matrix: linux+darwin × amd64+arm64 + windows/amd64. Each archive
bundles LICENSE + SECURITY.md + CHANGELOG.md; `checksums.txt` +
per-archive syft SBOMs.

Today `release.disable: true` short-circuits publish — CI runs the
full build+SBOM matrix without uploading. Flip when a target lands.
Locally: `make release-snapshot` → `dist/`.

---

## API specs

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

## Conventions

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

---

## Things not to do

- Don't run `git reset --hard`, `git push --force`, `branch -D` without
  explicit authorization.
- Don't init or modify git config.
- Don't bypass pre-commit hooks (`--no-verify`, `--no-gpg-sign`).
- Don't introduce mocks where a real in-memory impl exists.
- Don't add "while I'm here" cleanup or refactors.
- Don't write Markdown files unless asked.
- Don't violate oracle-leak / anti-enumeration patterns — stability
  contracts, not style.
- Don't bypass `setMeta` for audit metadata.

---

## Common tasks

### New authenticator
1. Implement `sso.Authenticator` in `authenticators/<name>.go`.
2. Add YAML knob under `authenticators:` in `config/config.go`.
3. Wire in `cmd/sso-server/main.go` `buildAuthenticators`.
4. Whitelist under a client's `allowed_authenticators:` to test.

### New audit Sink
1. Implement `audit.Sink` (`Record(ctx, *Event) error`).
2. If lifecycle, also implement `audit.Closer`.
3. Wire via `audit.New(s1, s2, ...)` or `audit.MultiSink`.

### New permissions backend
1. Implement `permissions.Provider` in `permissions/<name>/`.
2. Plumb via `sso.WithPermissionProvider(...)`.
3. Keep wildcard matcher semantics (`*`, `pkg:*`).

### New netpolicy at runtime
1. `POST /api/v1/netpolicy/policies` (or gRPC `PolicyService.Apply`).
2. Watchers pick up via Watch.
3. To seed at boot: add to `network.policies:`.

### New gRPC service
1. Write `proto/<name>/v1/<name>.proto`.
2. Regenerate.
3. Implement server in `grpcserver/<name>.go` over an interface the
   HTTP layer already uses.
4. Register in `cmd/sso-server/main.go` `newGRPCServer`.
5. Add a `bufconn`-based test in `grpcserver/`.

### New OAuth/OIDC grant
1. Handler in `handle_<grant>.go` using `bindOAuthParams` for body.
2. Honor HTTP Basic > body credentials.
3. Map errors to `400 invalid_<...>` — follow oracle-leak pattern.
4. Single-use: atomic delete-and-return (SQLite `DELETE RETURNING`;
   Redis `GETDEL`).
5. Wire in `sso.go` (`s.router.POST(...)`), advertise in
   `oidc_discovery.go`, add `WithXxxStore(store, ttl)`.
6. Tests in same package; enumerate oracle-leak failure cases.

### New credential / bearer-protected endpoint
1. Call `tokenNoStoreHeaders(ctx)` at handler entry.
2. Bearer-protected? Use `setBearerChallenge(ctx, ...)` on 401.

---

## Commits

- Conventional: `feat(area): summary`, `fix(area): summary`, `chore:`,
  `docs:`. Imperative subject; blank line; body explains why.
- Co-author trailer when AI-assisted.
- Don't commit binaries — `sso-server` is ignored.
