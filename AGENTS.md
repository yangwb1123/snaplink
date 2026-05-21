# AGENTS.md

Operational guide for AI agents working in this repo. Follows
[agents.md](https://agents.md). User instructions override any
conflict below.

---

## What this is

`github.com/snaplink/sso` — a Go SSO server SDK + runnable binary.
Implements OAuth 2.0 + OIDC, swappable authenticators, audit,
permissions, service registry, admin gRPC/REST, snapshot + release
lifecycle. Every concern is an interface; every default backend is
in `defaultimpl/` (memory) or `defaultimpl/sqlite/`. No external SaaS
dependency. Consumers pick **embedded** (`ssoclient/local`, in-process)
or **centralized** (`ssoclient/remote`, gRPC + JWKS) per capability.

---

## Layout

```
sso.go / handler.go / router.go     Server, HandlerContext, routing
consts.go                           Paths, headers, error codes (no literal leaks)
handle_*.go                         Per-endpoint HTTP handlers
oauth_bind.go                       form+JSON dispatcher
authenticators/                     8 pluggable AuthN impls
defaultimpl/                        Default issuer + Memory* stores
defaultimpl/sqlite/                 Pure-Go SQLite (no CGO)
adapters/{echo,gin}/                Router adapters
audit/                              Recorder + Sinks + hash chain
permissions/                        Roles + menus + wildcard matcher
netpolicy/{memory,etcd}/            Network classification
registry/{memory,etcd}/             Service discovery
bootstrap/{file,memory,builtin,lock}/  First-run init + dist lock
snapshot/{storage,encryption,loader}/  Admin-managed state export/restore
releases/{store,pinner,probe}/      Frontend+backend release pinning
geo/  tenant/  ratelimit/  cors/    Middleware + enrichment
metrics/  tracing/                  Observability
config/{etcd}/                      YAML + env + etcd + flag loader
proto/ + gen/proto/                 Protobuf + generated Go
grpcserver/                         gRPC services + REST gateway
ssoclient/{local,remote,dev,bootstrap}/  Consumer-facing clients
cmd/sso-server/                     Production binary
deploy/{openresty,k8s,compose,grafana}/  Operator artifacts
examples/                           Including embedded-app + remote-app
```

`examples/embedded-app` and `examples/remote-app` share the **same**
`appcore.Handler` — only the wiring differs. That's the local/remote
demo.

---

## Build, test

```bash
go build ./...
go run ./cmd/sso-server --config cmd/sso-server/config.yaml
go test ./... -race
go test -run TestE2E -v .              # cross-wire HTTP + JWKS + bufconn
make ci                                 # gofmt + vet + race + build + proto-lint
make docker
make release-snapshot                   # dist/ multi-arch (no publish)
```

Run the E2E suite (`e2e_test.go`) when changing anything that
crosses the gRPC or JWKS wire.

Protobuf regen (stubs are checked in; rarely needed):

```bash
protoc -I proto \
  --go_out=gen/proto --go_opt=paths=source_relative \
  --go-grpc_out=gen/proto --go-grpc_opt=paths=source_relative \
  proto/<svc>/v1/<svc>.proto
```

---

## Invariants

These apply across files. Violating them is a regression.

### Plugin SPI
Every concern is an interface in its parent package + a `memory`
impl + optionally `sqlite` / `etcd` / `file`. New backends slot in
via `WithXxx`. **Don't introduce mocks** — use Memory* in tests.

### Storage today
Memory (default) or SQLite (`defaultimpl/sqlite/`) for User /
AuthCode / RefreshToken / DeviceCode. PAR / Session / Client /
RateLimiter / RefreshTokenFamily are memory-only. **Multi-replica
deployments break OAuth flows** until those grow distributed
backends.

### Form + JSON via `bindOAuthParams`
All OAuth/OIDC endpoints (`/token`, `/par`, `/device/code` …)
accept both `application/x-www-form-urlencoded` (RFC mandatory)
and JSON via the dispatcher in `oauth_bind.go`. JSON-only would
break every off-the-shelf OAuth client.

### HTTP Basic > body credentials (RFC 6749 §2.3.1)
On `/token`, `/token/introspect`, `/token/revoke`, `/par`:
`Authorization: Basic` beats body `client_id`+`client_secret`.

### Oracle-leak hardening
Single-use code consumption (AuthCode / Refresh / Device / PAR /
PKCE verifier) MUST collapse unknown / expired / consumed /
client-mismatch failures into a single wire response (`400
invalid_grant` for /token; `invalid_request_uri` for PAR; etc.).
Same applies to DPoP/mTLS resource failures (→ `invalid_token`)
and `private_key_jwt` failures (→ `invalid_client`). Tests
enumerate failure cases to lock the behavior.

### Anti-enumeration
- `/register/:client_id` (RFC 7592): missing / wrong bearer / unknown
  client_id all return identical 401 `invalid_token`. Bearer compare
  uses `crypto/subtle.ConstantTimeCompare`.
- `/token/revoke` (RFC 7009 §2.2): 200 OK on valid client creds
  regardless of whether the token existed.
- `/token/introspect` inactive path returns `{"active":false}` only.

### Fail-open vs fail-closed
- **Fail-open** (log + continue): refresh-token issuance during
  `/auth/login` or auth_code exchange, ID Token issuance, geo,
  risk scorer error, audit Sink error.
- **Fail-closed**: refresh rotation grant itself (500),
  signature/validation failure, scope expansion, family-reuse
  detection (kills the whole family, 400 invalid_grant).

### PKCE: first-exchange only
`code_challenge` captured at `/auth/login`; verified against
`code_verifier` at `/token grant=authorization_code`. Subsequent
refresh rotations carry no verifier (bound via `client_id` instead).

### Refresh-token family rotation (OAuth Security BCP §4.13/§4.14)
Every refresh token carries a `FamilyID` propagated through every
rotation. Stores opt into reuse detection via
`RefreshTokenFamilyTracker`. Replay of a consumed token →
`ErrRefreshTokenReused` → `DeleteFamily(fid)` → audit
`refresh_token_reuse_detected` → `invalid_grant`. Empty `FamilyID`
opts out.

### Audit metadata: `setMeta(e, k, v)`
Geo + tenant middleware enrich every event via `Event.Metadata`.
**Never** assign `e.Metadata = map{...}` — it clobbers enrichment.

### X-Forwarded-* trust
`requestBaseURL` + `DefaultGeoIPExtractor` + `DefaultHostExtractor`
honor first-hop `X-Forwarded-Proto/Host/For`. **Only safe with a
trusted edge** that strips and re-sets them. Internet-facing deploys
without one MUST install a `TrustedProxies(CIDR...)` allowlist.

### `aud` claim parsing
RFC 7519 §4.1.3 — may be string or array. `audClaim` unmarshals
either, marshals single-aud as a compact string per OIDC.

### `alg` + `typ` allowlist on Validate (RFC 9068 §4)
Checked BEFORE signature verify so alg-confusion attacks
(`alg=none`, wrong-key-shape spoof) fail early. Adding a new signer
→ extend `supportedJWTAlgs` explicitly.

### RFC 9068 access-token claim population
Every Issue call site MUST set `Subject.ClientID` (REQUIRED §2.2).
Login / auth_code / device set `AuthTime` + `AMR` from the live
auth event. Refresh propagates the original `AMR` without resetting
`AuthTime`. Token-exchange propagates `AuthTime` + `ACR` + `AMR` +
`SID` from the inbound subject_token. `client_credentials`
populates `ClientID` only. `jti` always auto-generated.

### Discovery is derived
`/.well-known/openid-configuration` computed from server state:
endpoints from request base URL, scopes from union of `openid` +
every client's `AllowedScopes`, opt-in features (PAR, DCR,
JARFetcher, mTLS, BCL) flip flags only when wired. Adding a new
opt-in → branch the discovery doc.

### `iss` on authorization responses (RFC 9207)
Every `/auth/login` response — success, error, provider-list —
carries `iss` via `s.resolveIssuer(ctx)`, which MUST equal the
discovery doc's `issuer` field. New authorization-flow handlers
MUST use `s.authzErrorBody(ctx, code)` — not plain `errorBody`.

### JWKS caching
`/.well-known/jwks.json`: `Cache-Control: public, max-age=<ttl>` +
`ETag = sha256(body)[:8]`. Default TTL is 5 minutes; tune via
`WithJWKSCacheTTL(d)`. During rotation, both outgoing and incoming
keys are served so pre-rotation tokens still verify.

### Discovery doc caching
`/.well-known/openid-configuration` is double-cached:
`WithDiscoveryCacheTTL(d)` (default 5s) caches the
clientDiscoverySnapshot so projection fields don't re-iterate the
client store on every hit; `WithDiscoveryDocCacheTTL(d)` (default 5s)
caches the marshaled body + `ETag = sha256(body)[:8]` keyed by the
request base URL (multi-host SSO safe) and honors `If-None-Match`
→ 304. `Cache-Control: public, max-age=ttl` is stamped on every
200. Setting body TTL to 0 disables both the in-process cache AND
the response headers (every request renders fresh; CDNs / RP
libraries told not to cache).

### Cache headers on credential endpoints (RFC 6749 §5.1)
`/token`, `/token/introspect`, `/token/revoke`, `/token/revoke-all`,
`/par` all stamp `Cache-Control: no-store` + `Pragma: no-cache` at
handler entry via `tokenNoStoreHeaders(ctx)`. New credential
endpoints opt in with one line.

### WWW-Authenticate on 401 (RFC 6750 §3)
Resource endpoints (`/userinfo`, `/token/revoke-all`, admin REST,
`/register*`) stamp a Bearer challenge via `setBearerChallenge`.
Missing-token omits `error=`; validation failure carries
`error="invalid_token"`. Description values pass through
`quoteAuthParam` to prevent auth-param injection.

---

## OAuth 2.0 / OIDC

One row per spec; file is the owner. Gotchas above apply across
every grant.

| Spec | Endpoint(s) | Opt-in | File |
|---|---|---|---|
| RFC 6749 §4.1 authorization_code | `/auth/login` + `/token` | `WithAuthCodeStore` | `auth_code.go` |
| RFC 6749 §4.4 client_credentials | `/token` | always | `handle_token_*.go` |
| RFC 6749 §6 refresh_token | `/token` | `WithRefreshTokenStore` | `refresh_token.go` |
| RFC 7636 PKCE | param on /auth/login + /token | per-request / `Client.RequirePKCE` | `auth_code.go` |
| RFC 7662 introspection | `/token/introspect` | always | `handle_introspect.go` |
| RFC 7009 revocation | `/token/revoke[-all]` | always; bulk needs `RefreshTokenSubjectIndex` | `handle_revoke.go` |
| RFC 8628 device | `/device/code`, `/device/verify`, `/token` | `WithDeviceCodeStore` | `handle_device.go` |
| RFC 8693 token-exchange | `/token` (urn:...:token-exchange) | always; refresh-output needs `WithRefreshTokenStore`; actor_token JTI replay via `WithJTIReplayStore` | `handle_token_exchange.go` |
| RFC 8707 resource indicators | every issuance | `Client.AllowedResources` | per-grant |
| RFC 9126 PAR | `/par` | `WithPARStore` | `handle_par.go` |
| RFC 7591 DCR | `/register` | `WithDynamicClientRegistration` | `handle_register.go` |
| RFC 7592 DCR mgmt | `/register/:id` | same as 7591 | `handle_register.go` |
| OIDC Core ID Token | `id_token` w/ `openid` scope | `WithIDTokenIssuer` | `oidc.go` |
| OIDC Discovery 1.0 | `/.well-known/openid-configuration` | always | `oidc_discovery.go` |
| OIDC RP-Initiated Logout | `/end_session` | always | `handle_end_session.go` |
| OIDC BCL 1.0 | `/logout`, `/end_session` | `WithBackchannelLogout`; multi-RP via `WithSubjectClientIndex` | `backchannel_logout.go` |
| OIDC FCL 1.0 | `/end_session` | `Client.FrontchannelLogoutURI` | `frontchannel_logout.go` |
| OIDC `sid` claim | access + id + logout tokens | `WithSessionManager` | `defaultimpl/ed25519_jwt_issuer.go` |
| OIDC `login_hint` | `/auth/login`, `/par`, JAR | always accepted | `handler.go` + `par.go` + `jar.go` |
| OIDC Form Post Response Mode 1.0 | `/auth/login`, `/par`, JAR | always (`response_mode=form_post`) | `form_post_response_mode.go` |
| RFC 7521 + 7523 `private_key_jwt` | `/token`, `/par`, `/introspect`, `/revoke` | `Client.JWKS` | `jwt_client_assertion.go` |
| OIDC `prompt=none` | `/auth/login` | `WithSessionManager` + `WithIDTokenIssuer` | `prompt.go` |
| RFC 9207 AS Issuer Id | every `/auth/login` response | always | `iss_response.go` |
| RFC 9068 JWT Access Token | `Ed25519JWTIssuer` | always | `defaultimpl/ed25519_jwt_issuer.go` |
| RFC 8705 mTLS-bound tokens + endpoint aliases | `/token` + `/userinfo` | `WithClientCertExtractor` | `mtls_bound.go` |
| RFC 9470 Step-Up | resource-server helper | always | `step_up_auth.go` |
| RFC 9449 DPoP | `/token` + `/userinfo` | always when header present; replay via `WithJTIReplayStore`; §8 nonce via `WithDPoPNonceProvider` | `dpop.go` + `dpop_nonce.go` |
| RFC 8414 §2.1 signed_metadata | `/.well-known/openid-configuration` | `WithMetadataSigner` (Ed25519JWTIssuer satisfies the interface) | `oidc_discovery.go` |
| OAuth 2.1 strict | `/auth/login` | `WithOAuth21StrictMode` | `handler.go` |
| RFC 9396 RAR | `authorization_details` | per-client allowlist | `rar.go` |
| RFC 9101 JAR | `request`, `request_uri` | `Client.JWKS`; URL fetch via `WithJARFetcher` + `AllowedRequestURIs`; require via `Client.RequireSignedRequestObject` | `jar.go` + `jar_fetch.go` |
| Per-account lockout | `/auth/login` | `WithAccountLockout` | `account_lockout.go` |

**Token strategies** are per-client (`token_strategy: jwt|session`):
- `TokenStrategyJWT` — Ed25519 + JWKS, stateless. Pass the same
  `Ed25519JWTIssuer` to `WithTokenIssuer` and `WithIDTokenIssuer`.
- `TokenStrategySession` — opaque, backed by `SessionManager`.

Register via `sso.WithTokenIssuer(name, issuer)`.

---

## Subsystems

### Authenticators (`authenticators/`)
8 pluggable: `password`, `phone`, `email`, `temp_token`, `keypair`,
`apikey`, `certificate`, `totp` (RFC 6238). `allowed_authenticators:`
on a client gates which methods are permitted. WebAuthn + upstream
IdP federation remain on the roadmap.

### SQLite (`defaultimpl/sqlite/`)
Pure-Go via `modernc.org/sqlite` — no CGO. Backends: User, AuthCode,
RefreshToken (+ Inspector + FamilyTracker), DeviceCode. Single-use
stores use `DELETE … RETURNING` for race-free consumption.

DSN cookbook:
| DSN | Use |
|---|---|
| `file:/var/lib/sso/sso.db?_journal=WAL&_busy_timeout=5000` | Production |
| `:memory:` | Per-connection isolated DB |
| `file::memory:?cache=shared` | Shared pool (tests) |

Schema migration: `CREATE TABLE IF NOT EXISTS` at construction. The
next multi-table backend MUST bring goose/golang-migrate. Pattern:
`New<Provider>(dsn)`, `Close()`, `New<Provider>WithDB(db)` for shared
pool. `sql.ErrNoRows` → typed `ErrNoSuchX`. Timestamps as Unix-ns
INTEGER.

### Audit (`audit/`)
`audit.Recorder` fans Events to `Sink`s. Built-in: `MemorySink`,
`WriterSink`, `WebhookSink`, `MultiSink`. Every Event carries W3C
`TraceID` / `SpanID` / `ParentSpanID`.

- **Hash chain** (opt-in): `audit.WithHashChain()` stamps
  `PrevHash` + `Hash`; `audit.VerifyChain(events)` validates.
  In-process only, oldest-first required, last event not
  detectable without external attestation.
- **PII redaction** (opt-in): `audit.WithRedactor(r)` runs BEFORE
  the chainer. Helpers: `RedactActorIDHash(salt)`, `RedactIPTruncate`,
  `RedactUserAgent`, `RedactMetadataKeys(...)`,
  `DefaultPIIRedactor(salt)`.
- **Retry wrapper** (opt-in): `audit.NewRetryingSink(inner, ...)` retries
  Record on transient errors with exponential backoff + jitter.
  Options: `WithRetryMaxAttempts(n)` (default 3), `WithRetryInitialBackoff(d)`,
  `WithRetryMaxBackoff(d)`, `WithRetryClassifier(c)` to mark some
  errors permanent (default: every error is transient). Compose as
  `AsyncSink(RetryingSink(WebhookSink))` — retry runs inside the
  AsyncSink worker so total backoff time must stay under the queue
  capacity / arrival rate, or backpressure shows up as drops.
- **Async wrapper** (opt-in): `audit.NewAsyncSink(inner, ...).Start()`
  drains a bounded buffer on a worker pool — Record never blocks the
  request path. Options: `WithAsyncBuffer(n)` (default 1024),
  `WithAsyncWorkers(n)` (default 1), `WithAsyncDropHandler(fn)`,
  `WithAsyncRecordTimeout(d)`. Drop reasons: `ErrAsyncQueueFull`,
  `ErrAsyncSinkClosed`, plus surfaced inner errors. Caller-side
  context is intentionally dropped (TraceID rides on the Event, not
  ctx) so request-goroutine cancellation can't abort delivery. Use
  this for `WebhookSink`; skip for `MemorySink` / `WriterSink`.
  Observability: `Pending()` / `Capacity()` for queue depth gauge;
  `DropsQueueFull()` / `DropsClosed()` / `DropsInnerError()` for
  monotonic drop counters operators scrape into Prometheus.
  Ready-made collector: `metrics.NewAsyncSinkCollector(asyncSink)`
  → register on the Prometheus registry to expose all 5 series
  (`sso_audit_async_drops_*`, `sso_audit_async_queue_*`) without
  a polling goroutine.

### Permissions (`permissions/`)
`MemoryProvider` gives per-APP role registries, wildcard matcher
(`user:*` matches `user:read`, `*` matches all), menu filtering,
login response embedding via `WithEmbedPermissionsInLogin()`.
`MenuLister` is the extension snapshots/admin RPCs use.

### Service registry (`registry/`)
`memory` (TTL + Watch) and `etcd` (lease + KeepAlive).
`cmd/sso-server` self-registers under `Name: "sso"`.

### gRPC (`proto/` + `grpcserver/`)

| Phase | Services | REST |
|---|---|---|
| A core | `audit.v1.AuditWriter`, `authz.v1.Authorizer`, `discovery.v1.Discovery` | — |
| B netpolicy | `netpolicy.v1.PolicyService` | `/api/v1/netpolicy/` |
| C admin | `admin.v1.{Client,User,Token,Permission}AdminService` | `/api/v1/admin/` |
| D | `admin.v1.{Snapshot,Release}AdminService` | `/api/v1/admin/{snapshots,releases}` |

gRPC services **reuse the same** audit.Recorder / permissions.Provider
/ registry.Registry instances the HTTP layer uses.

Admin auth: `sso.AdminMiddleware` validates Bearer via
`(*sso.Server).ValidateToken`, requires `admin:read` for read /
`admin:write` for mutations (`admin:*` matches both), stashes actor
via `AdminActorFromContext`. 401s carry a `Bearer realm="admin"`
challenge. Every mutation emits `admin_*` audit.

`Discovery.Watch` flushes initial headers via `SendHeader` so clients
can block on `stream.Header()` before mutations.

### Network policy (`netpolicy/`)
Named classes (intranet/public/dmz/…) of CIDRs + hostnames + URLs.
Classifier: hostname-beats-CIDR, priority breaks ties. `Classifier`
holds a hot snapshot subscribed to `Store.Watch` via `Start`
(subscribe before seed Reload to avoid lost events). HTTP at
`/api/v1/netpolicy/{policies,classify,resolve-me}`. Server helper:
`(*sso.Server).ClassifyRequest(r)`.

### Bootstrap (`bootstrap/`)
Versioned first-run init. `Step = Name()/Version()/Run(ctx)`; Runner
re-runs only `Version > high-water`. Trackers: `memory` (tests),
`file` (atomic JSON, single-node default). Lock SPI in `lock/`:
`noop` / `file` (flock) / `etcd` (lease+Txn). Wired via `WithLock`+
`WithLockTTL`+`WithLockBlocking`. Lock loss cancels in-flight Steps
+ surfaces `ErrLockLost`.

Built-in `bootstrap/builtin/` Steps under namespace `"sso-server"`:

| v | Effect |
|---|---|
| 0 | `restore_from_snapshot` (when `snapshot.restore_from` set) |
| 1 | `seed_admin_role` (sso-admin role, admin:*) |
| 2 | `seed_admin_user` — prints generated password ONCE to stdout |
| 3 | `seed_default_netpolicy` (intranet RFC1918 if none exist) |
| 4 | `seed_admin_client` |

**Capture the admin password from boot log.** `ssoclient/bootstrap`
wraps file tracker + namespaced runner. `"sso-server"` namespace is
reserved.

### Snapshot (`snapshot/`)
Export/restore operator state (clients, users, roles, role
assignments, menus, netpolicies, bootstrap high-water).

- `Snapshotter.Export` pulls every wired backend's `List()`.
- `Restorer.Restore` applies in dependency order. Modes:
  `ModeMerge` (insert-only) / `ModeOverwrite` (upsert) / `ModeReplace`
  (wipe+seed, requires `Confirm == SnapshotID`). `DryRun` returns
  counts only. `AdvanceBootstrap` bumps Tracker to snapshot version.
- `Codec` (JSON canonical, schema `"1"`), `Sealer` (`none` typed
  no-op; `passphrase` argon2id + XChaCha20-Poly1305 OWASP-2024),
  `Storage` (`file` atomic 0o600; `inline` memory). `Pipeline`
  composes with sha256 verify (`ErrChecksumMismatch`).
- `snapshot/loader.FromURI` parses `file:///abs/path` +
  `inline:<base64>`.
- Admin RPCs at `admin.v1.SnapshotAdminService` (admin:* gate).

**First-boot auto-restore**: `snapshot.restore_from` YAML key +
`--bootstrap-restore-from` CLI (CLI wins). Runs in `bootstrap/builtin`
v0 step BEFORE the seed Runner so `AdvanceBootstrap` can skip
already-covered seeds. Default mode: Overwrite.

### Releases (`releases/`)
Admin app version pin / rollback. `Release` pairs frontend+backend
`Artifact` halves; `Validate` refuses one-sided releases.

- `ReleaseStore` separates current-pointer from registration.
  Backends: `memory`, `file` (atomic 0o600).
- `Pinner.PinForward` + `PinRollback` encode asymmetric ordering
  (backend-first forward, frontend-first rollback). Backends:
  `noop`, `static` (atomic symlink swap), `docker` (rewrite `.env`
  + `docker compose pull && up -d`).
- `Registry` composes Store + Pinner. Forward Pin rejects schema
  regression with `ErrSchemaRegress` — use Rollback.
- `HealthProbe` (e.g. `releases/probe/http`) gates forward Pin;
  all-fail → auto-rollback. No probe on Rollback.
- `SnapshotRestorer` hook on Rollback: when target's
  `ConfigSnapshot` is non-empty, restore admin state BEFORE the
  Pinner flips.

Admin REST: `POST/GET /api/v1/admin/releases`,
`/api/v1/admin/releases:current`,
`/api/v1/admin/releases/{id}[:pin,:rollback]`. `GetCurrent` returns
empty when nothing pinned.

### Geo (`geo/`)
IP → enrichment as **UX hint, NOT security**. 200ms timeout;
`ErrNotFound` non-fatal; nil Provider = no-op. `geo/static` is
CIDR longest-prefix. Login response carries `country_code` +
`recommended_language` when the authenticator didn't supply
stronger signal. Every Event gets `geo.*` keys (presence-check
friendly).

### Tenant (`tenant/`)
Multi-tenant + multi-domain routing. Tenant = business boundary;
Domain = hostname → Tenant (lowercase + trailing-dot-stripped per
RFC 1035). **Tenant sits above `Client`** — one tenant typically
owns many clients (admin / customer / mobile) sharing one audit.

`Client.TenantID` (YAML `tenant_id`): when set, login + token endpoints
reject mismatches with 403 `tenant_mismatch` audited as `login_failure`.
Empty = served from any tenant (single-tenant + platform-admin clients).
`TenantScopedClientStore.ListByTenant` is the optional extension for
admin UIs. Suspended tenants resolve to "no tenant" by default. Every
Event gets `tenant.*` keys.

**Active suspension** (opt-in): `WithTenantSuspensionCheck(ttl)`
installs a post-validation gate — every token whose
`Client.TenantID` is set has its tenant Status looked up; tokens whose
tenant is `Suspended` fail with `ErrTenantSuspended` (→ `invalid_token`
at resource paths, `inactive` at introspect). Without this option,
existing tokens continue to work after suspension (only new issuance
is blocked). Lookups cached for `ttl` (default 30s); admin SetStatus
handlers MUST call `(*Server).InvalidateTenantSuspensionCache(id)` so
the flip takes effect on the next validate. Tenant store outage is
fail-open by design — don't 401 the world during a partition.

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
`ValidateToken` returns a fake Subject, `Check` defaults to
AllowAll, `Record` no-ops. **Every constructor emits a one-time
stderr `AUTH BYPASS ACTIVE` warning** on first non-silent call.
Suppress in tests via `WithSilent` / `WithSilentAuthz` /
`WithSilentAudit`.

### Edge (`deploy/`)
- **OpenResty** — `lua-resty-jwt` verifies via our JWKS; sets
  `X-Auth-Subject` / `X-Auth-Scopes` / `X-Network`. **Edge is
  fast-reject, not a trust boundary** — the Go server re-validates.
- **Kubernetes** — Kustomize base, distroless pod security
  (`runAsNonRoot`, `readOnlyRootFilesystem`, drop ALL caps,
  `seccompProfile: RuntimeDefault`). `configMapGenerator` hashes
  names for rolling restarts. Ingress / HPA / NetworkPolicy / PDB
  / ServiceMonitor in overlays.
- **docker compose** — sso-server + etcd + optional
  `--profile observability` (Prometheus + Grafana). Onboarding /
  smoke tests, NOT production-grade.
- **Grafana** — `sso-overview.json` (12 panels, `$instance` template)
  + `alerts.yaml` (6 rules). Thresholds are starting points.

### Middleware order
Probes registered OUTSIDE the stack so kubelet can't be throttled.

```
/metrics, /livez, /readyz                                (outside)
  ↓
tracing → ratelimit → bodyLimit → metrics → CORS → router
```

Wire each with `sso.With{Tracing, RateLimit, BodyLimit, Metrics, CORS}`.

**Metrics** are bounded by design (no per-path / per-user labels):

| Metric | Type | Labels |
|---|---|---|
| `sso_http_requests_total` | Counter | method, status_class |
| `sso_http_request_duration_seconds` | Histogram | method |
| `sso_login_attempts_total` | Counter | provider, outcome |
| `sso_tokens_issued_total` | Counter | strategy |
| `sso_risk_decisions_total` | Counter | decision |

Per-endpoint breakdowns come from traces, not labels.

**Tracing**: `tracing.Init(ctx, ...)`; OTLP gRPC enabled by
`OTEL_EXPORTER_OTLP_ENDPOINT`. No-op when unset.

**Ratelimit**: `Default` + ordered `Prefixes`. `KeyByClientIP`
honors XFF/X-Real-IP/RemoteAddr — **trust an edge or wrap in
TrustedProxies upstream**. `KeyByClientIDOrIP` keys by `client_id`
when an HTTP Basic-authed /token-style request supplies one, falling
back to IP — sensible for /token, /par, /token/introspect, /token/revoke
where the natural noisy-neighbor is the client (not a NAT'd source IP).
Body-supplied credentials (client_secret_post) intentionally hit the
IP fallback to avoid consuming r.Body. Composes with `RiskScorer`
(limiter rejects bots before scoring).

**ReadyCheck**: pluggable SPI; any failing check → 503. Bounded by
3s context deadline.

### Risk scoring (`risk.go`)
`RiskScorer` runs on `/auth/login` AFTER credential validation,
BEFORE token issuance. Returns `Allow` / `RequireMFA` (reserved,
treated as Allow today) / `Deny` (403 + audit `login_failure
reason=risk_denied`).

- **Fail-open** on scorer error (alert on the log line).
- **Zero overhead** when option unset.

Scorers needing richer signals query their own store inside
`Score` — don't pad `RiskRequest`.

---

## Configuration

`cmd/sso-server/config.yaml` is the reference. Top-level keys:

```yaml
server:        # listen, issuer, TTLs, default_token_strategy,
               # discovery_doc_cache_ttl, signed_metadata
logging:       # level: debug|info|error
audit:         # enabled, api_enabled, memory_capacity
               # async: { enabled, buffer_size, workers, record_timeout_ms }
permissions:   # apps[] (roles + menus per client_id), user_roles[], embed_in_login
network:       # enabled, api_enabled, store, policies[]
clients:       # id, secret, allowed_authenticators, token_strategy,
               # redirect_uris, post_logout_redirect_uris, allowed_resources,
               # require_pkce, tenant_id, allowed_request_uris, jwks,
               # require_signed_request_object, ...
authenticators: # per-method enable + tuning
admin:         # enabled, api_rest_enabled
bootstrap:     # disabled, state_path, admin_user_id, admin_client_id, admin_role_code
               # lock: { backend, key, ttl, blocking, file.dir, etcd.endpoints }
snapshot:      # enabled, restore_from (URI; --bootstrap-restore-from overrides)
               # storage: { backend(file|inline), file.dir }
               # encryption: { backend(none|passphrase), passphrase, passphrase_file }
releases:      # enabled, store, pinner, probe, snapshot_integration
geo:           # enabled, backend(static), lookup_timeout, static.entries[]
security:      # body_limit, rate_limit, cors
               # dpop_nonce: { enabled, key_file, ttl }
tenant:        # enabled, backend, lookup_timeout, include_suspended,
               # tenants[], domains[],
               # suspension_check: { enabled, cache_ttl }
```

`client_id: ""` is a valid bucket (the demo uses it). Production tokens
should carry an explicit audience.

### Multi-source loader

`config.Loader` composes prioritized `Source`s (lowest first; last
wins per key):

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

## Release pipeline

`goreleaser` driven from `.github/workflows/release.yml` on `vX.Y.Z`
tags. Matrix: linux+darwin × amd64+arm64 + windows/amd64. Each
archive bundles LICENSE + SECURITY.md + CHANGELOG.md;
`checksums.txt` + per-archive syft SBOMs.

Today `release.disable: true` short-circuits publish — CI runs the
full build+SBOM matrix without uploading. Flip to `false` when a
target lands. Locally: `make release-snapshot` → `dist/`.

---

## API specs

| Surface | Source of truth | Consumers |
|---|---|---|
| HTTP | `docs/openapi.yaml` (OpenAPI 3.0) | swagger-ui, Postman, OpenAPI Generator |
| gRPC | `proto/*.proto` | `protoc` / `buf`, BSR, grpc-gateway |

OpenAPI covers core auth + self-service. Admin REST, audit query,
netpolicy CRUD are additive.

When you change a documented HTTP endpoint, update `docs/openapi.yaml`
in the same commit. CI runs `make docs-validate`.

`docs/error-codes.md` is the stable wire-contract catalog of every
`error` value. **Adding a new `Err*` in `consts.go` requires
updating the catalog in the same commit.** SPAs branch on `error`,
never on `error_description`.

---

## Conventions

- **No literal leaks** — paths, headers, error codes live in root
  `consts.go` or the package's own.
- **No mocks for storage** — use real `MemoryProvider` / `MemorySink`
  / `memory.Registry`.
- **No emojis** in code, comments, or commits.
- **Comments explain WHY**, not what. Reach for one only for hidden
  constraints, invariants, or workarounds.
- **Interface guards in implementation packages**, e.g.
  `var _ ssoclient.AuthClient = (*remote.AuthClient)(nil)` in
  `ssoclient/remote/` — never in `ssoclient/` (cycle).
- **gRPC name renames** — protoc-gen-go does `ID→Id`, `URL→Url`.
- **Tests in the same package** as behavior. Race / ordering fixes
  prove with `-count=10+`.

---

## Things not to do

- Don't run `git reset --hard`, `git push --force`, or `branch -D`
  without explicit authorization.
- Don't init or modify git config.
- Don't bypass pre-commit hooks (`--no-verify`, `--no-gpg-sign`).
- Don't introduce mocks where a real in-memory impl exists.
- Don't add "while I'm here" cleanup or refactors.
- Don't write Markdown files unless the user asked.
- Don't violate the oracle-leak / anti-enumeration patterns — they
  are stability contracts, not stylistic.
- Don't bypass `setMeta` for audit metadata.

---

## Common tasks

### New authenticator
1. Implement `sso.Authenticator` in `authenticators/<name>.go`.
2. Add YAML knob under `authenticators:` in `config/config.go`.
3. Wire in `cmd/sso-server/main.go` `buildAuthenticators`.
4. Whitelist under a client's `allowed_authenticators:` to test.

### New audit Sink
1. Implement `audit.Sink` (`Write(ctx, *Event) error`).
2. If lifecycle, also implement `audit.Closer`.
3. Wire via `audit.New(s1, s2, ...)` or `audit.MultiSink`.

### New permissions backend
1. Implement `permissions.Provider` in `permissions/<name>/`.
2. Plumb via `sso.WithPermissionProvider(...)`.
3. Keep wildcard matcher semantics (`*`, `pkg:*`).

### New netpolicy at runtime
1. `POST /api/v1/netpolicy/policies` (or gRPC `PolicyService.Apply`).
2. Watchers (OpenResty cache, in-process Classifier) pick up via Watch.
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

- Conventional: `feat(area): summary`, `fix(area): summary`,
  `chore:`, `docs:`. Imperative subject; blank line; body explains why.
- Co-author trailer when AI-assisted.
- Don't commit binaries — `sso-server` is ignored.
