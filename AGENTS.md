# AGENTS.md

Operational guide for AI agents working in this repository. Follows the
[agents.md](https://agents.md) convention. Claude Code, Codex, Cursor, Aider,
and Jules all read this file at the repo root.

If a section here conflicts with explicit user instructions, prefer the user
instructions for the current task.

---

## Project overview

`github.com/snaplink/sso` is a Go SSO server SDK plus a runnable server. It
ships seven authentication methods, two token strategies, per-APP dynamic
configuration, an independent audit module, an independent permissions module
with menu authorization, an optional OpenResty edge integration, a service
registry, gRPC services, and a client package (`ssoclient/`) that lets
consumer apps choose embedded vs centralized mode per capability — same
business code, two deployment shapes.

There is no external SaaS dependency. Every concern (token issuance, audit
sinks, permission storage, service discovery) goes through a Go interface so
production deployments can plug in their own backends.

---

## Repository layout

```
.
├── sso.go / handler.go / ...          Core Server, HandlerContext, routing
├── consts.go                          All literals (paths, headers, errors)
├── authenticators/                    7 pluggable AuthN implementations
├── defaultimpl/                       Default TokenIssuer + session/client stores
├── adapters/                          Echo + Gin shims for the Handler
├── audit/                             Independent audit module (Recorder + Sinks)
├── audit_handler.go                   GET /api/v1/audit/events HTTP API
├── permissions/                       Roles, menus, wildcard matcher
├── permission_handler.go              /me/permissions /me/menus /me/roles
├── netpolicy/                         Network-classification control plane
│   ├── memory/                        In-process Store
│   └── etcd/                          etcd-backed Store
├── netpolicy_handler.go               /api/v1/netpolicy/* HTTP API
├── config/                            YAML config loader
├── registry/                          Service discovery (memory + etcd)
├── proto/  +  gen/proto/              Protobuf sources + generated Go
├── grpcserver/                        gRPC adapters for Phase A + B services
├── ssoclient/                         Consumer-facing client interfaces
│   ├── local/                         In-process (embedded SDK) implementations
│   └── remote/                        gRPC + JWKS implementations
├── cmd/sso-server/                    Production binary (config.yaml lives here)
├── deploy/openresty/                  Edge JWT verify + request-id + audit
└── examples/
    ├── basic/                         Minimal SDK wiring
    ├── grpc-client/                   Dial the gRPC API
    ├── embedded-app/                  Uses ssoclient/local everywhere
    ├── remote-app/                    Uses ssoclient/remote everywhere
    └── appcore/                       Shared business handler used by both apps
```

`examples/embedded-app` and `examples/remote-app` share the exact same
`appcore.Handler` — the only difference is wiring. That is the demo of the
ssoclient local/remote split.

---

## Setup commands

```bash
# Build everything
go build ./...

# Run the production server (config at cmd/sso-server/config.yaml)
go run ./cmd/sso-server --config cmd/sso-server/config.yaml

# Override listen ports without touching config:
go run ./cmd/sso-server --config cmd/sso-server/config.yaml \
  --listen :18080 --grpc-listen :18081

# Disable gRPC (HTTP-only)
go run ./cmd/sso-server --config cmd/sso-server/config.yaml --grpc-listen ""

# Or via Makefile (mirrors what CI runs):
make build      # bin/sso-server
make ci         # gofmt + vet + race + build + proto-lint
make docker     # snaplink/sso-server:dev image (multi-stage distroless)

# In-cluster deploy:
kubectl apply -k deploy/k8s/   # see deploy/k8s/README.md for overlays

# API specs:
make docs-validate    # lint docs/openapi.yaml against OpenAPI 3.0 schema
make docs-serve       # serve swagger-ui locally on :8088 (needs Docker)

# Release dry-run:
make release-check       # static lint of .goreleaser.yaml
make release-snapshot    # full multi-OS / multi-arch build to dist/
                         # (no publish; tag-less; embeds short commit)
```

Re-generating protobuf code (rarely needed; checked-in stubs cover all imports):

```bash
protoc -I proto \
  --go_out=gen/proto --go_opt=paths=source_relative \
  --go-grpc_out=gen/proto --go-grpc_opt=paths=source_relative \
  proto/audit/v1/audit.proto proto/authz/v1/authz.proto proto/discovery/v1/discovery.proto
```

---

## Test instructions

```bash
go vet ./...
go test ./...

# With race detector (recommended before committing)
go test -race ./...

# Single package, verbose
go test -v ./ssoclient/remote/

# Single test, repeated (good for flake hunts)
go test -run TestDiscovery_Watch_StreamsAddedAndRemoved -count=10 ./grpcserver/

# Cross-wire E2E (login → JWKS-verified token → bufconn-gRPC authz/audit):
go test -run TestE2E -v .
```

The E2E suite (`e2e_test.go`, package `sso_test`) stands up a real
sso.Server on httptest + bufconn and drives `examples/appcore.Handler`
through it with the REMOTE ssoclient implementations. If you change
anything that crosses the gRPC or JWKS wire, run those tests.

Current coverage (informational, not a gate):

| Package | Coverage |
|---|---|
| audit | 95.5% |
| permissions | 100% |
| defaultimpl | 38.2% |
| registry/memory | 85.7% |
| registry/etcd | 16.7% |
| grpcserver | 68.7% |
| ssoclient/local | 69.6% |
| ssoclient/remote | 77.5% |
| netpolicy | 89%+ |
| netpolicy/memory | 90%+ |
| netpolicy/etcd | 70%+ (logic-only; no etcd server) |

When you add behavior, add tests in the same package. When you fix a race or
ordering bug, use `-count=10` (or higher) to prove the fix.

---

## Capabilities (what this project actually does)

### 1. Seven authenticators

All in `authenticators/`, all implement `sso.Authenticator`:

| Method | Use case | Wire it with |
|---|---|---|
| `password` | Classic web login | `NewPasswordAuthenticator(verifier)` |
| `phone` | SMS code | `NewPhoneAuthenticator(codeStore, smsSender)` |
| `email` | Email code | `NewEmailAuthenticator(codeStore, emailSender)` |
| `temp_token` | One-time link / magic token | `NewTempTokenAuthenticator(store, ttl)` |
| `keypair` | Ed25519 service-to-service | `NewKeyPairAuthenticator(pubKeyStore, skew)` |
| `apikey` | Long-lived service credential | `NewAPIKeyAuthenticator(store)` |
| `certificate` | mTLS / X.509 | `NewCertificateAuthenticator(rootPool)` |

To add a new one: implement `Authenticator` (returns `*AuthResult`), register
it with `sso.WithAuthenticator(...)`, then list its name under a client's
`allowed_authenticators:` in the YAML.

### 2. Two token strategies (per-APP)

- `sso.TokenStrategyJWT` — Ed25519, JWKS-publishable, stateless verify
- `sso.TokenStrategySession` — opaque token backed by `SessionManager`

Each registered client (APP) picks its own:

```yaml
clients:
  - id: web-app
    token_strategy: session
    allowed_authenticators: [password, phone, email]
  - id: mobile-app
    token_strategy: jwt
    allowed_authenticators: [password, phone]
```

The `Server` looks up `TokenIssuer` by the client's strategy name registered
via `sso.WithTokenIssuer(name, issuer)`. Custom strategies plug in the same
way as custom authenticators.

### 3. Audit (`audit/`)

`audit.Recorder` fans Events out to one or more Sinks. Built-in sinks:

- `MemorySink(capacity)` — ring buffer, queryable via `GET /api/v1/audit/events`
- `WriterSink(w)` — newline-delimited JSON to any `io.Writer`
- `WebhookSink(url)` — POST to an HTTP endpoint, context-cancelable
- `MultiSink(sinks...)` — fan-out with first-error semantics

Every event carries W3C `TraceID` / `SpanID` / `ParentSpanID` so audit records
correlate with the rest of your trace stack without OpenTelemetry as a
dependency.

To embed audit without the SSO server: import `audit` directly. To stream
audit from another service: dial the gRPC `AuditWriter` service.

### 4. Permissions (`permissions/`)

`permissions.Provider` is the storage interface. `MemoryProvider` implements
it with:

- Per-APP role registries (different clients can name different role codes)
- Wildcard permission matcher (`user:*` matches `user:read`, `*` matches all)
- Menu tree filtering — branches the user can't see are pruned
- Login response embedding (`WithEmbedPermissionsInLogin()`) so SPAs don't
  need a second roundtrip after sign-in

### 5. Service registry (`registry/`)

Pluggable `Registry` interface. Two implementations:

- `registry/memory` — in-process, TTL eviction, `Watch` fan-out
- `registry/etcd` — etcd v3 client with lease + automatic KeepAlive

The `cmd/sso-server` binary self-registers under `Name: "sso"` in whichever
registry is wired in.

### 6. gRPC Phase A (`proto/` + `grpcserver/`)

Three v1 services:

- `snaplink.audit.v1.AuditWriter` — `Record` + `StreamEvents`
- `snaplink.authz.v1.Authorizer` — `Check` + `ListPermissions` + `ListRoles` + `GetMenus`
- `snaplink.discovery.v1.Discovery` — `Register` + `Deregister` + `Discover` + `Watch`

These reuse the same audit Recorder / permissions Provider / registry Registry
instances the HTTP layer uses — no business-logic duplication.

`Discovery.Watch` flushes initial headers via `SendHeader` once the registry
subscription is live. Clients should block on `stream.Header()` before issuing
mutations whose events they expect to receive.

### 6b. gRPC Phase B — network policy (`netpolicy/` + `proto/netpolicy/v1/`)

One v1 service: `snaplink.netpolicy.v1.PolicyService` with
`Get` + `List` + `Apply` + `Delete` + `Watch` + `Classify`.

Use case: declare named classes of network (intranet, public, dmz, ...),
each with the CIDRs / hostnames that identify them and the URLs the SSO
server should advertise back to callers in that class. The classifier
applies hostname-beats-CIDR, priority-breaks-ties matching.

Storage backends mirror `registry/`:

- `netpolicy/memory` — in-process Watch fan-out (single-replica deployments).
- `netpolicy/etcd` — JSON-per-policy under `<prefix>/<name>`; Version is the
  etcd ModRevision so cache invalidation just compares integers.

Architecture: `Store` is persistence + Watch; `Classifier` is a hot
priority-sorted snapshot subscribed to Watch via `Classifier.Start`
(`Start` synchronously subscribes before returning, so the seed Reload
can't lose events). `Apply` and `Delete` are mirrored to `audit.Recorder`
as `EventNetPolicyApply` / `EventNetPolicyDelete` events on both the gRPC
and REST surfaces.

HTTP surface (mounted when `network.enabled` and `network.api_enabled`):

- `GET    /api/v1/netpolicy/policies` — list all
- `GET    /api/v1/netpolicy/policies/:name` — one
- `POST   /api/v1/netpolicy/policies` — upsert (Apply)
- `DELETE /api/v1/netpolicy/policies/:name` — idempotent delete
- `GET    /api/v1/netpolicy/classify?remote_addr=...&host=...` — explicit
- `GET    /api/v1/netpolicy/resolve-me` — classifies the current request

Server-side helper for embedders: `(*sso.Server).ClassifyRequest(r) *Policy`.

### 6c. gRPC Phase C — admin control plane (`proto/admin/v1/` + `grpcserver/admin_*.go`)

Four v1 services under `snaplink.admin.v1.`:

| Service                  | RPCs                                                                     |
| ------------------------ | ------------------------------------------------------------------------ |
| `ClientAdminService`     | List, Get, Create, Update, Delete, RotateSecret                          |
| `UserAdminService`       | List, Get, Create, Update, Delete, ListUserSessions                      |
| `TokenAdminService`      | ListSessions, Revoke, IssueTempToken                                     |
| `PermissionAdminService` | ListRoles, AddRole, UpdateRole, RemoveRole, ListAssignments, AssignRoles, UnassignRoles, SetMenus |

All services are defined once in `.proto` and served two ways:

- **gRPC** — registered in `cmd/sso-server/main.go::newGRPCServer` when
  `admin.enabled` is true.
- **REST** — auto-generated reverse proxy via `grpc-gateway` (the
  `pb.gw.go` files under `gen/proto/admin/v1/`) mounted under
  `/api/v1/admin/` when both `admin.enabled` and `admin.api_rest_enabled`
  are true. The REST URL conventions (`POST /api/v1/admin/clients`,
  `POST /api/v1/admin/clients/{id}:rotateSecret`, etc.) come straight from
  the `google.api.http` annotations in the protos.

**Auth + scope.** Both transports go through `sso.AdminMiddleware`
(`admin_middleware.go`), which:

1. Pulls a bearer token from `Authorization: Bearer ...` (HTTP) or the
   `authorization` metadata key (gRPC).
2. Validates it via `(*sso.Server).ValidateToken` — same JWT pipeline as
   /userinfo.
3. Looks up the subject's permissions on the token's `aud` (client ID).
4. Requires `admin:read` for List/Get/Search/Find methods and
   `admin:write` for everything else; the wildcard `admin:*` matches both.
5. Stashes the actor (userID + clientID) in the request context so
   admin handlers can attribute audit events. Read it from any handler
   with `sso.AdminActorFromContext(ctx)`.

The gRPC interceptor only fires on `/snaplink.admin.v1.*` methods; the
HTTP middleware only fires on `/api/v1/admin/*` paths. Non-admin
endpoints pass through unchanged.

Every mutation emits an `admin_*` audit event (see `audit/event.go`):
`admin_client_created`, `admin_user_deleted`, `admin_role_assigned`, etc.

### 6d. Bootstrap (`bootstrap/` + `bootstrap/builtin/` + `ssoclient/bootstrap/`)

First-run init for both the SDK itself AND consumer apps. Three pieces:

- **`bootstrap.Step`** — one init action: `Name() / Version() / Run(ctx)`.
  Versioned monotonically per namespace; the Runner only re-runs steps
  with `Version > tracker's recorded high-water mark`.
- **`bootstrap.Tracker`** — persists "highest applied version per
  namespace". Two backends: `bootstrap/memory` (tests) and
  `bootstrap/file` (JSON file with atomic-rename writes; default for
  single-node deployments).
- **`bootstrap/lock.Lock`** (Phase D-1) — distributed lock SPI for
  multi-replica coordination. Backends: `noop` (default), `file`
  (`flock(2)`), `etcd` (lease + Txn). Wired via
  `bootstrap.WithLock(lock, key)` + `WithLockTTL` + `WithLockBlocking`.
  The Runner takes the lock before iterating Steps, runs a heartbeat
  goroutine that cancels in-flight Steps on lease loss, and Releases
  on exit. Lock loss surfaces as `bootstrap.ErrLockLost`.
- **`bootstrap.Runner`** — sorts Steps by Version, skips already-applied
  ones, runs the rest, marks each applied. Emits
  `bootstrap_step_applied/skipped/failed` audit events when wired with
  `WithRecorder`.

The sso-server registers four built-in Steps under namespace
`"sso-server"` (`bootstrap/builtin/builtin.go`):

1. **`seed_admin_role`** (v1) — creates the `sso-admin` role with the
   `admin:*` permission so the admin user can hit every admin RPC.
2. **`seed_admin_user`** (v2) — generates a 24-byte random password,
   stores `admin` user with the password as a `seeded_password` attribute
   (so a custom verifier can read it), assigns the admin role, and
   prints the password ONCE to stdout. Capture it from the boot log;
   it's never re-emitted.
3. **`seed_default_netpolicy`** (v3) — registers an "intranet" RFC1918
   policy if no policies exist yet. Skipped silently when netpolicy is
   disabled or already populated.
4. **`seed_admin_client`** (v4) — creates the `sso-admin` client with a
   random 32-byte secret. Skipped if the operator already declared a
   client with that ID in YAML.

State file defaults to `bootstrap.json` next to the binary; override
with `bootstrap.state_path` in the YAML config. Set
`bootstrap.disabled: true` to skip the runner entirely (useful in tests
or when an external orchestrator owns init).

**Consumer-app helper.** `ssoclient/bootstrap` wraps the file tracker +
namespaced runner into a one-shot facade so embedding apps don't have to
repeat the glue:

```go
bs, _ := ssobootstrap.New("billing-app", "/var/lib/billing/init.json",
    ssobootstrap.WithRecorder(recorder),
    ssobootstrap.WithLogger(logger),
)
defer bs.Close()
bs.Register(
    ssobootstrap.StepFunc("create_schema", 1, createSchema),
    ssobootstrap.StepFunc("seed_admin", 2, seedAdminUser),
)
_ = bs.Run(ctx)
```

The reserved namespace `"sso-server"` is rejected — pick something else.
Multiple apps can share one state file as long as their namespaces differ.

### 6e. Snapshot (`snapshot/` — Phase D-2)

Export / restore for the operator-managed state: clients, users, role
definitions, role assignments, menus, network policies, plus the
bootstrap Tracker's per-namespace high-water mark. Use cases: stand up a
peer node from a known-good baseline, migrate config across air-gapped
networks, DR drills, time-travel debugging.

Layered SPI per the same plugin pattern as the rest of the repo:

- **`snapshot.Snapshotter`** — pulls every wired backend's `List()` into a
  versioned `Snapshot` envelope. Backends are independently optional —
  unconfigured categories are silently skipped. Provider needs the
  optional `permissions.MenuLister` extension to round-trip menus.
- **`snapshot.Restorer`** — applies a Snapshot in dependency order
  (clients → users → roles → menus → assignments → netpolicy → bootstrap
  state). Three modes:
  - `ModeMerge` — insert when missing, leave existing untouched.
  - `ModeOverwrite` — insert when missing, update when present. No deletes.
  - `ModeReplace` — wipe categories the snapshot covers, then re-seed.
    Requires `Confirm == snap.SnapshotID` to guard against accidents.
  `DryRun: true` returns a Report with the would-be counts but performs
  no mutations. `AdvanceBootstrap: true` bumps the destination Tracker
  to the snapshot's recorded version (only when newer).
- **`snapshot.Codec`** — `JSONCodec` is the canonical encoding (indented,
  HTML-escape off, `DisallowUnknownFields` on read). Schema version `"1"`;
  unknown versions are rejected with `ErrUnknownSchemaVersion`.
- **`snapshot.Sealer`** — encryption SPI with two backends:
  - `snapshot/encryption/none` — typed no-op (Pipeline also picks this
    up automatically when Sealer is nil).
  - `snapshot/encryption/passphrase` — argon2id KDF + XChaCha20-Poly1305
    AEAD; salt + nonce + KDF tunables travel inside `EncryptionParams`.
    Defaults: time=1, memory=64 MiB, threads=4 (OWASP 2024 baseline).
- **`snapshot.Storage`** — opaque-bytes persistence. Two backends:
  - `snapshot/storage/file` — directory-backed; atomic tempfile + rename
    writes; sanitised filenames; `0o600` files under a `0o700` dir.
  - `snapshot/storage/inline` — in-memory map for tests + same-process
    pipelines.
- **`snapshot.Pipeline`** — composes Codec + Sealer + Storage. `Save`
  marshals → seals → wraps in `SealedEnvelope` (header carries codec +
  algorithm + sha256 + opaque encryption params) → stores. `Load`
  reverses it and verifies the sha256 with `ErrChecksumMismatch` on drift.
- **`snapshot/loader.FromURI`** — turns `file:///abs/path/snap.snap` or
  `inline:<base64>` into a `(Storage, name)` pair. Shared by the admin
  Restore RPC and the bootstrap restore path so both speak the same URI
  grammar.

**Operator surface:**

- Admin RPCs at `snaplink.admin.v1.SnapshotAdminService` (gated by
  `admin:*` like the rest of the admin plane). REST gateway:

  | Method | Path |
  | --- | --- |
  | POST | `/api/v1/admin/snapshots`             |
  | GET  | `/api/v1/admin/snapshots`             |
  | GET  | `/api/v1/admin/snapshots/{id}`        |
  | POST | `/api/v1/admin/snapshots/{id}:restore` |
  | DELETE | `/api/v1/admin/snapshots/{id}`     |

  Sentinel mapping: `ErrSnapshotNotFound` → `NotFound`,
  `ErrConfirmation*` / `ErrUnknownSchemaVersion` → `FailedPrecondition`,
  `ErrChecksumMismatch` → `DataLoss`. Each mutation emits one audit
  event (`snapshot_exported|restored|deleted`) with the snapshot id +
  (for Restore) the mode and dry_run flag.
- List endpoint projects only the envelope wrapper (snapshot id, codec,
  algorithm, size_bytes); body-derived fields (taken_at_unix,
  source_namespace, bootstrap_applied_version) stay zero — call Get to
  populate them.

**First-boot auto-restore:**

- `snapshot.restore_from` YAML key + `--bootstrap-restore-from` CLI
  override. Accepts the same URI grammar as `loader.FromURI`. CLI wins
  when both are set; no env var fallback.
- Runs via `bootstrap/builtin.ApplyRestore` BEFORE the bootstrap Runner
  so `RestoreOptions.AdvanceBootstrap=true` can bump the Tracker — that
  causes seed steps already covered by the snapshot to skip themselves
  on the same boot. Mode defaults to `Overwrite`.
- This path is not a `bootstrap.Step` because the Runner skips any step
  whose `Version <= current` (a fresh tracker starts at 0, so a
  Version=0 step would never run). Wedging it in any other version
  would have meant renumbering the existing seeds and re-running
  `seed_admin_user` on existing deployments — overwriting the captured
  admin password. Re-importing onto an already-bootstrapped node is the
  admin Restore RPC's job, not this hook's.

### 6f. Releases (`releases/` — Phase D-3)

Admin app version pin / rollback. A `Release` is the paired
frontend+backend deployment artifact set CI/CD registers atomically;
operators Pin one as "current" and Rollback to a previous one. The
goal is to never end up with frontend v3 talking to backend v2.

Layered SPI per the same plugin pattern as snapshot:

- **`releases.Release`** — id + channel + Frontend/Backend
  `Artifact` pair + schema_version + optional `ConfigSnapshot` (the
  D-2 snapshot id this release was paired with). `Validate` refuses
  one-sided releases — both halves must carry at least one
  identifying field (GitRef or URI).
- **`releases.ReleaseStore`** — Register / Get / List / Delete +
  separate SetCurrent / Current / ClearCurrent. The "current"
  pointer is tracked separately so pinning is one mutation, not a
  re-register. Two backends:
  - `releases/store/memory` — in-process map; tests + ephemeral
    demos.
  - `releases/store/file` — directory-backed; one `<id>.json` per
    release + a `CURRENT` marker file. Both atomic via tempfile +
    rename; sanitised filenames; `0o600` / `0o700` perms.
- **`releases.Pinner`** — deploy SPI. Two methods (`PinForward` /
  `PinRollback`) so each implementation encodes the asymmetric
  ordering operators have to live with — backend-first on forward,
  frontend-first on rollback — without operators having to remember.
  Two backends:
  - `releases/pinner/noop` — records the call, returns nil. Useful
    for tests, dry-runs, and bootstrap setups that want the audit
    trail + current-pointer management before a real Pinner is wired.
  - `releases/pinner/static` — frontend-bundle-only Pinner. Expects
    bundles staged at `<BundleDir>/<release-id>/` by CI; atomically
    swaps a `<BundleDir>/current` symlink via `rename(2)`. Forward
    and Rollback are symmetric here — no backend ordering to worry
    about.
  - `releases/pinner/docker` — docker compose Pinner. Rewrites a
    managed `.env` (RELEASE_ID, BACKEND_IMAGE, FRONTEND_IMAGE) in
    BundleDir then runs `docker compose pull && up -d`. The compose
    file references `${BACKEND_IMAGE}` / `${FRONTEND_IMAGE}` so the
    up-d recreates services with the new tags. Cmd defaults to
    `docker`; swap to `podman` when needed. Forward + Rollback
    symmetric (compose treats the graph as a unit).
- **`releases.Registry`** — composes Store + Pinner. Pinner runs
  first; only on success does Store advance the current pointer (so
  a half-failed deploy doesn't leave the system reporting a release
  that didn't actually flip). Forward Pin rejects schema regression
  with `ErrSchemaRegress` — operators must use Rollback for that
  direction explicitly.
- **`releases.HealthProbe`** — optional post-Pin gate. When set on
  the Registry, forward Pin runs the probe on a polling cadence
  (`ProbePolls` × `ProbeBackoff`, defaults 6 × 5s). First nil result
  wins. After every attempt fails the Registry auto-rollbacks to the
  previous release (PinRollback + SetCurrent) and returns the
  wrapped probe error. No probe runs on Rollback — recovering
  shouldn't add risk. An http probe ships in `releases/probe/http`.
- **`releases.SnapshotRestorer`** — optional Rollback-time hook.
  Slim interface (`RestoreByID(ctx, id)`) so the releases package
  stays free of any snapshot import; the cmd binary owns the
  adapter that bridges releases → snapshot. When wired AND the
  rollback target's `ConfigSnapshot` field is non-empty, Rollback
  restores the paired admin-managed state (clients/users/roles)
  BEFORE flipping the Pinner. Restorer errors abort before the
  Pinner runs, so operators see a half-applied rollback as an
  error rather than as success.

**Operator surface:**

- Admin RPCs at `snaplink.admin.v1.ReleaseAdminService` (gated by
  `admin:*`). REST gateway:

  | Method | Path |
  | --- | --- |
  | POST | `/api/v1/admin/releases`              |
  | GET  | `/api/v1/admin/releases`              |
  | GET  | `/api/v1/admin/releases:current`      |
  | GET  | `/api/v1/admin/releases/{id}`         |
  | POST | `/api/v1/admin/releases/{id}:pin`     |
  | POST | `/api/v1/admin/releases/{id}:rollback` |
  | DELETE | `/api/v1/admin/releases/{id}`       |

  Sentinel mapping: `ErrReleaseNotFound` → `NotFound`,
  `ErrReleaseExists` → `AlreadyExists`, `ErrInvalidPair` →
  `InvalidArgument`, `ErrSchemaRegress` → `FailedPrecondition`.
  `GetCurrent` returns an empty release (not an error) when nothing
  is pinned, so fresh deployments can poll without erroring. Each
  mutation emits one audit event (`release_registered|pinned|rolled_back|deleted`)
  with the release id + (for pin/rollback) the previous current id.

### 6g. Geo (`geo/` + sso/geo_middleware.go)

IP → geo enrichment on the auth path. The middleware extracts the
client IP from the request (XFF first hop → X-Real-IP →
RemoteAddr by default), looks it up via a `geo.Provider`, and
stashes the resulting `*GeoInfo` on `HandlerContext`. The login
handler reads it back and fills `AuthResult.CountryCode` (ISO
3166-1 alpha-2) + `RecommendedLanguage` (BCP-47) when the
authenticator didn't supply a stronger signal — the response
carries `country_code` and `recommended_language` so the
post-login UI can render in the user's most-likely region +
language without an extra round trip.

Geo is deliberately a UX hint, not a security signal:
`ErrNotFound` is non-fatal, `Lookup` runs under a short timeout
(200ms default), and a nil Provider makes the whole path no-op.

- **`geo.Provider`** — single-method SPI (`Lookup(ctx, ip) →
  *GeoInfo`). `GeoInfo` carries `CountryCode` / `Region` / `City`
  / `TimeZone` / `RecommendedLanguage`; all optional.
- **`geo/static`** — CIDR → GeoInfo lookup table; longest-prefix
  match; thread-safe; for tests + small operator-curated
  overrides (private RFC1918 ranges, regional office blocks).
  No external deps. Future `geo/maxmind` backend stacks behind
  this for full coverage.
- **`geo.WithContext` / `FromContext`** — pure context.Context
  helpers for threading `*GeoInfo` through downstream gRPC calls
  or audit metadata enrichment.
- **`sso.GeoMiddleware`** — `MiddlewareFunc` factory; lives in
  the sso package because the natural import direction is
  sso → geo (geo stays free of any sso dep). `sso.WithGeoProvider`
  installs it on Mount; `sso.WithGeoMiddlewareOptions` tunes the
  IP extractor / timeout / error reporter.
- **`sso.GeoFromHandlerContext`** — typed read-back for handlers
  + custom downstream code.

**Authenticator priority**: `AuthResult.RecommendedLanguage` set by
the Authenticator wins (e.g. a hypothetical phone Authenticator
that knows the SIM's region); the geo fallback only fills when the
field is empty. The `recommended_language` response key is omitted
entirely when no source has a value, so clients can rely on its
absence to mean "no hint, use your own preference".

**Security note on `X-Forwarded-For`**: `DefaultGeoIPExtractor`
trusts `XFF` and `X-Real-IP`, which is correct ONLY when a known
edge proxy strips and re-sets them. Internet-facing deployments
without an edge proxy should write a custom `GeoIPExtractor` that
ignores forwarded headers and uses `RemoteAddr` only.

**Audit enrichment**: every `audit.Event` produced by the SSO
server (login, login_failure, code_sent, token_issued, logout,
permission_query, callback_failure) automatically carries
`geo.country_code` / `geo.region` / `geo.city` /
`geo.recommended_language` keys in `Event.Metadata` when the geo
middleware ran. Only non-empty fields are projected so SIEMs can
do a presence check rather than a value check. Use
`setMeta(e, key, val)` (not direct `e.Metadata = map{...}`) when
adding new event metadata to avoid clobbering the geo enrichment.

### 6h. Tenant (`tenant/` + sso/tenant_middleware.go)

Multi-tenant + multi-domain routing layer. A `Tenant` is a
business boundary (independent billing/audit/admin); a `Domain` is
a hostname mapped to one Tenant. Same SSO server can host
admin.acme.com + portal.acme.com (→ tenant `acme`) and
admin.beta.io (→ tenant `beta`) without operators running
separate binaries.

- **`tenant.Tenant`** — id + slug + name + status (active|suspended)
  + free-form Settings map. Slug is the URL-safe identifier
  operators use in admin tooling; ID is the immutable primary key.
- **`tenant.Domain`** — hostname (unique key) + tenant_id +
  optional default_client_id + optional Branding map for
  per-domain logo/theme/locale defaults. Hostname normalized to
  lowercase + trailing-dot-stripped per RFC 1035.
- **`tenant.Store`** — Tenant + Domain CRUD in one interface.
  `tenant/memory` is the in-process backend (fine for tests +
  small embedded deployments). Production SaaS will want a SQL
  backend.
- **`sso.TenantMiddleware`** — `MiddlewareFunc` factory; lives in
  the sso package because the natural import direction is
  sso → tenant. `sso.WithTenantStore` installs it on Mount;
  `sso.WithTenantMiddlewareOptions` tunes the host extractor /
  timeout / suspended-tenant visibility.
- **`sso.TenantFromHandlerContext`** — typed read-back returning
  `*ResolvedTenant{Tenant, Domain}`.
- **`sso.DefaultHostExtractor`** — XFH first-hop → r.Host with
  port stripped + IPv6 brackets handled.

**Tenant ownership intentionally sits one level above `sso.Client`** —
one tenant typically owns multiple clients (admin-portal,
customer-portal, mobile-API) sharing one audit trail.

**Client ↔ Tenant linkage**: `sso.Client` carries an optional
`TenantID` field (YAML key `tenant_id`). When set, login + token
endpoints reject requests whose resolved tenant doesn't match
(returns 403 with error code `tenant_mismatch`, recorded as a
`login_failure` audit event). When empty (the backward-compatible
default), the client is served from any tenant context — keeping
single-tenant deployments and the platform-admin client (which
belongs to no operator tenant) working unchanged. The check is
also skipped when no tenant resolved on the request, so enabling
the tenant store doesn't suddenly break every existing client.

The optional `sso.TenantScopedClientStore` extension interface
exposes efficient `ListByTenant(ctx, tenantID)` for backends with
an index — admin UIs that show "all clients owned by tenant X"
should type-assert before using.

**Audit enrichment**: every `audit.Event` now carries
`tenant.id` / `tenant.slug` / `tenant.domain` in `Metadata` when
the middleware ran. Combined with the `geo.*` enrichment, every
SIEM record carries (tenant, country) by default — filters like
"failed logins for tenant X from outside the US" are a single
two-key match.

**Suspended tenants** resolve to "no tenant" by default so
handlers naturally degrade. Set `IncludeSuspended=true` if you
want to surface a maintenance page from a handler.

**Security note on `X-Forwarded-Host`**: `DefaultHostExtractor`
trusts XFH first-hop, which is correct ONLY when a known edge
proxy strips and re-sets it. Internet-facing deployments without
one should write a custom HostExtractor that returns r.Host
unconditionally (and ignores XFH).

### 7. ssoclient (the local/remote split)

```go
// Embedded mode — everything in-process:
handler := &appcore.Handler{
    Auth:  local.NewAuthClient(issuer, local.WithSessionManager(sessions)),
    Authz: local.NewAuthzClient(prov),
    Audit: local.NewAuditClient(recorder),
}

// Centralized mode — gRPC + JWKS:
handler := &appcore.Handler{
    Auth:  remote.NewAuthClient(remote.NewJWKSCache(jwksURL)),
    Authz: remote.NewAuthzClient(grpcConn),
    Audit: remote.NewAuditClient(grpcConn),
}
```

Each capability is independently choosable. An APP can do local audit (cheap,
in-process) while delegating authz to a central server.

`remote.JWKSCache` does periodic background refresh + single-flight refetch on
unknown `kid`, so key rotation lands within one extra HTTP round trip rather
than a full refresh interval.

`ssoclient/dev` is the third option: drop-in `Auth`/`Authz`/`Audit` stubs
that bypass real verification for local UI iteration. `ValidateToken`
returns a configurable fake Subject, `Check` defaults to AllowAll,
`Record` is a no-op (or mirrors to a sink). Every constructor emits a
one-time stderr `AUTH BYPASS ACTIVE` warning on first non-silent call
so accidental production use is loud. Suppress in tests of the dev
package itself via `WithSilent` / `WithSilentAuthz` / `WithSilentAudit`.

### 8. OpenResty edge (`deploy/openresty/`)

Pushes cheap concerns to the gateway:

- `lua-resty-jwt` verifies signature + `exp`/`nbf` using the SDK's
  `/.well-known/jwks.json`
- Decoded subject and scopes forwarded as `X-Auth-Subject` / `X-Auth-Scopes`
- Request-ID generated at the edge if absent, propagated downstream
- `netpolicy_cache.lua` pulls policies from `/api/v1/netpolicy/policies`,
  refreshes them on a worker timer, classifies the inbound request, and
  stamps `X-Network: intranet|public|...` so every downstream backend can
  read the class without reimplementing CIDR matching.
- Audit mirror — nginx duplicates select request fields to a syslog channel
  the Go `audit/WriterSink` can ingest

The Go server still re-checks tokens; the edge is fast-reject, not a trust
boundary.

### 8a. Local-dev compose stack (`deploy/compose/`)

`docker compose up` for sso-server + etcd, or `docker compose
--profile observability up` adds a Prometheus + Grafana stack with
the snaplink dashboard auto-provisioned. Mirrors `deploy/k8s/` for
symmetry: same Dockerfile, same config shape, just wired for a
single host instead of a cluster.

Used for: new-contributor onboarding (clone → up → working SSO),
manual smoke tests of the etcd config source (the in-cluster path
leaves etcd as operator-add; compose wires it by default), and
end-to-end observability verification (real metrics flowing into
real Grafana panels).

NOT production-grade — single-node etcd, ephemeral volumes,
admin/admin Grafana, anonymous viewer access. See
`deploy/compose/README.md` for details on what's deliberately
weak vs the K8s manifests.

### 8b. Kubernetes (`deploy/k8s/`)

Kustomize-based base manifests for in-cluster deployment. Namespace +
Deployment (distroless-friendly pod security: `runAsNonRoot`,
`readOnlyRootFilesystem`, drop ALL caps, `seccompProfile: RuntimeDefault`)
+ Service (named `http`/8080 + `grpc`/8081 ports) + ConfigMap via
`configMapGenerator` so file edits hash the name and trigger rolling
restarts on the next apply.

```bash
kubectl apply -k deploy/k8s/
```

`deploy/k8s/README.md` covers the three-layer config story (file → env
→ etcd) and explicitly enumerates what's deferred to overlays (ingress,
HPA, NetworkPolicy, PDB, ServiceMonitor, ServiceAccount) — each is one
config decision that varies per environment.

### 8c0. Grafana / Prometheus operator pack (`deploy/grafana/`)

Companion to §8c — a Grafana dashboard + Prometheus alerts ready to
import without further authoring:

* `sso-overview.json` — 12-panel dashboard across 4 rows (overview,
  HTTP, auth flow, Go runtime). `$instance` template variable for
  per-replica drilldown.
* `alerts.yaml` — 6 alerting rules: 5xx rate, login failure rate
  (creds-stuffing signal), rate-limit saturation, p95 latency, risk
  scorer silent (fail-open safety net), instance down.
* `deploy/grafana/README.md` covers the kube-prometheus-stack
  `PrometheusRule` wrapper + plain-Prometheus `rule_files` paths.

All thresholds are starting points — operators tune for their
traffic baseline before promoting to paging severity. The dashboard
is vendor-neutral (Grafana 10+ schemaVersion 39).

### 8c. Metrics (`metrics/`)

Prometheus instrumentation. Wire `sso.WithMetrics(metrics.New())` and
the Server's `Handler()` additionally serves `/metrics` (outside the
router so scrapes don't self-inflate) and wraps every other request
in an HTTP middleware that records count + duration.

Five bounded-cardinality collectors:

| Metric                              | Type      | Labels                       |
|-------------------------------------|-----------|------------------------------|
| `sso_http_requests_total`           | Counter   | method, status_class         |
| `sso_http_request_duration_seconds` | Histogram | method                       |
| `sso_login_attempts_total`          | Counter   | provider, outcome            |
| `sso_tokens_issued_total`           | Counter   | strategy                     |
| `sso_risk_decisions_total`          | Counter   | decision                     |

Plus the standard Go runtime + process collectors (`go_*`, `process_*`).
All bounded by design: `status_class` (2xx / 4xx / 5xx) not raw code,
`method` not path, `provider` not user id. Per-endpoint breakdowns
should be derived from traces, not from labels.

Construct once at boot, reuse across the process. `metrics.New()`
returns a fresh isolated registry suitable for `cmd/sso-server`;
`metrics.NewWithRegistry(reg)` binds to an existing registerer when
embedding the SSO server in a larger app.

Zero overhead when [WithMetrics] is omitted — the Handler returns the
bare router and no instrumentation runs.

### 8e. Operational endpoints (`/livez`, `/readyz`)

Probe endpoints served OUTSIDE the entire middleware stack — never
rate-limited (kubelet probes can't be throttled), never counted in
HTTP metrics (probe traffic is noise), never body-capped. Both always
respond as long as the handler runs at all.

| Endpoint  | Status | Purpose                                                  |
|-----------|--------|----------------------------------------------------------|
| `/livez`  | 200    | Process is alive — the handler running IS the signal     |
| `/readyz` | 200/503 | Composite readiness — aggregates `sso.WithReadyCheck`   |

`ReadyCheck` is a pluggable SPI:

```go
sso.NewServer(
    sso.WithReadyCheck("db", pingDB),
    sso.WithReadyCheck("etcd", checkEtcdReachable),
    sso.WithReadyCheck("bootstrap", bootstrapComplete),
)
```

Any check returning an error marks the server unready (503). Bounded
by a 3s context deadline so a hung check can't wedge the probe.
Empty check list = always ready (default).

`/health` stays registered inside the router for backward compat —
operators with existing dashboards / monitors hitting it still work.
Cluster probes MUST migrate to `/livez` + `/readyz` (the
`deploy/k8s/` manifest is already pointed at the new endpoints).

### 8d. Rate limiting (`ratelimit/`)

Token-bucket rate limiter — the missing brute-force defense on
`/auth/login`. Wire `sso.WithRateLimit(policy)` and the middleware
slots into the Server's Handler() chain between `/metrics` (never
limited so Prometheus scrapers can't get throttled) and the metrics
recorder (so 429 responses still appear in `sso_http_requests_total`
with `status_class="4xx"`).

`ratelimit.Limiter` is a pluggable SPI; `ratelimit.MemoryLimiter` is
the in-process default (wraps `golang.org/x/time/rate`). Operators
running multiple replicas should swap for a Redis-backed Limiter when
cross-replica enforcement matters.

Policy shape: a `Default` limiter for all paths + ordered `Prefixes`
for path-specific overrides. Keying is pluggable (default
`KeyByClientIP`, respects XFF / X-Real-IP / RemoteAddr — operators
behind an untrusted edge should layer a TrustedProxies check
upstream).

```go
sso.WithRateLimit(ratelimit.Policy{
    Default: ratelimit.NewMemoryLimiter(1, 60),        // 1/s sustained, 60 burst
    Prefixes: []ratelimit.PrefixRule{
        {Prefix: "/auth/login",     Limiter: ratelimit.NewMemoryLimiter(10.0/60, 10)},
        {Prefix: "/auth/send-code", Limiter: ratelimit.NewMemoryLimiter(10.0/60, 10)},
    },
})
```

429 responses include the standard `Retry-After` header (seconds,
ceiling-rounded so clients never retry early) and a JSON body
`{"error":"rate_limited"}` so SPAs can branch on the code.

Composes with `RiskScorer` (§9): rate limiter rejects bot traffic
BEFORE risk scoring runs, so the scorer only sees attempts that
passed the volume gate. Two complementary defenses, no overlap.

### 8f. Body size limit (`sso.WithBodyLimit`)

`sso.WithBodyLimit(1 << 20)` caps request body size at 1 MiB (or
whatever value you pass). Defends against pathological JSON bombs
that swallow memory and slow-loris reads that dribble bytes forever.

Fast path: when `Content-Length` is set and exceeds the limit, reject
with 413 + `{"error":"payload_too_large"}` before reading any bytes.
Chunked uploads fall back to the streaming `http.MaxBytesReader`
guard.

Layer position: inside rate-limit + metrics so 413s show up in
`sso_http_requests_total{status_class="4xx"}` and so over-sized
requests still count against the rate-limit bucket (a malicious
client can't drain the bucket faster by spamming oversized payloads
than by spamming small ones).

### 9. Risk scoring (`risk.go`)

`sso.RiskScorer` is an optional SPI that runs on every `/auth/login`
attempt AFTER credential validation but BEFORE token issuance. The
scorer returns a `Decision` — `Allow`, `RequireMFA` (reserved; treated
as Allow today), or `Deny` (HTTP 403 + audit `login_failure` with
reason=`risk_denied`). This is the canonical hook for AI / ML risk
backends, IP-allowlist enforcers, geo gates, off-hours blocks, or any
"is this attempt legitimate" evaluator.

```go
sso.NewServer(
    /* ... usual options ... */
    sso.WithRiskScorer(myScorer),  // optional; omit for zero overhead
)
```

Two contract guarantees that matter:

- **Fail-open**: scorer errors are logged but do not block the login.
  Failing closed on a misbehaving scorer would lock every user out —
  worse than skipping one risk check. Alert on the `risk scorer failed`
  log line if silent-bypass concerns you.
- **Zero overhead when unset**: a nil-check in `handleLogin` skips
  the scorer entirely. No risk policy = no risk evaluation, no
  latency.

`defaultimpl.NoopRiskScorer` is provided as an explicit "no scoring"
stand-in for tests and downstream wiring that wants a typed value
rather than nil.

The input (`sso.RiskRequest`) is what the server can observe at the
login moment: subject id, client id, authenticator name, remote IP,
user agent, geo info (when geo middleware ran), timestamp. Scorers
that need richer signals (device fingerprint, recent failure history,
network reputation) should query their own data store from inside
`Score`, not pad the input struct.

---

## Configuration

`cmd/sso-server/config.yaml` is the reference. Key sections:

```yaml
server:        # listen, issuer, TTLs, default_token_strategy
logging:       # level: debug|info|error
audit:         # enabled, api_enabled, memory_capacity
permissions:   # apps[] (roles + menus per client_id), user_roles[], embed_in_login
network:       # enabled, api_enabled, store, policies[] (CIDR/hostname rules)
clients:       # per-APP id, secret, allowed_authenticators, token_strategy
authenticators: # per-method enable + tuning (code length, TTL, max_clock_skew, ...)
admin:         # enabled, api_rest_enabled — gates admin gRPC + REST gateway
bootstrap:     # disabled, state_path, admin_user_id, admin_client_id, admin_role_code
               # lock: { backend (noop|file|etcd), key, ttl, blocking, file.dir, etcd.endpoints }
snapshot:      # enabled, restore_from (URI; --bootstrap-restore-from overrides)
               # storage: { backend (file|inline), file.dir }
               # encryption: { backend (none|passphrase), passphrase, passphrase_file }
releases:      # enabled
               # store: { backend (file|memory), file.dir }
               # pinner: { backend (noop|static|docker),
               #          static.bundle_dir,
               #          docker.{bundle_dir, cmd} }
               # probe: { backend ("" | http), http.url, polls, backoff }
               # snapshot_integration: bool — when true + snapshot.enabled,
               #   Rollback restores target.ConfigSnapshot before Pinner
geo:           # enabled, backend (static), lookup_timeout
               # static.entries[]: { cidr, country_code, region, city,
               #                     time_zone, recommended_language }
tenant:        # enabled, backend (memory), lookup_timeout, include_suspended
               # tenants[]: { id, slug, name, status, settings }
               # domains[]: { hostname, tenant_id, default_client_id,
               #              is_apex, branding }
```

`client_id: ""` (empty string) is a valid bucket — used by the demo so tokens
without an `aud` claim still resolve to a role. Production code should issue
tokens with an explicit audience and key permissions under the real client_id.

### Multi-source loader

`config.Loader` composes a prioritized chain of `config.Source`
implementations (lowest priority first; last source wins per key):

| Source                       | Where it lives          | When to use                              |
|------------------------------|-------------------------|------------------------------------------|
| `config.NewFileSource(path)` | `config/source_file.go` | Baseline YAML at `--config`              |
| `config.NewEnvSource()`      | `config/source_env.go`  | 12-factor overrides (`SSO_<UPPER>__...`) |
| `etcd.New(cfg)`              | `config/etcd/`          | Centralized live config in K8s clusters  |
| `config.NewFlagSource(fs)`   | `config/source_flag.go` | Explicit CLI overrides via `Bind()`      |

Maps deep-merge, scalars + slices overwrite. Leaf string values from
env/etcd run through `yaml.Unmarshal` so `"true"`→bool, `"42"`→int, and
`"5s"` falls through as the string that downstream `time.Duration`
parsing expects. `cmd/sso-server` wires all four: file + env are
always on; etcd activates when `--etcd-endpoints` is non-empty (slots
between env and flag in the chain so cluster-wide values beat the
local file but a CLI override still wins); flag is always last.

```bash
# File + env + flag only (default):
go run ./cmd/sso-server --config cmd/sso-server/config.yaml

# Layer etcd over the file:
go run ./cmd/sso-server --config cmd/sso-server/config.yaml \
    --etcd-endpoints localhost:2379 \
    --etcd-prefix /snaplink/config
```

`config.Load(path)` is the legacy single-source entry point and remains
a thin wrapper over `LoadFromSources(NewFileSource(path))` so zero call
sites had to change when the Loader landed.

---

## Release pipeline

`goreleaser` drives binary distribution at release time. Configured in
`.goreleaser.yaml`; triggered from `.github/workflows/release.yml` on
`vX.Y.Z` tag push.

Build matrix: linux + darwin × amd64 + arm64, plus windows/amd64
(windows/arm64 skipped — no users on that combo yet). Each archive
bundles `LICENSE`, `SECURITY.md`, and the autogenerated `CHANGELOG.md`
alongside the binary. `checksums.txt` sits beside the archives;
syft-generated SPDX-JSON SBOMs ship per-archive so supply-chain
scanners (Trivy / Grype / Dependency-Track) can ingest them directly.

Today `release.disable: true` in `.goreleaser.yaml` short-circuits the
publish step — the CI workflow runs the full build + SBOM matrix
without uploading anywhere. Flip to `false` (or remove the key) once
a target is wired:

| Target | What to flip |
|---|---|
| GitHub Releases | `release.disable: false`; the workflow's `GITHUB_TOKEN` is the credential |
| Container registry | Uncomment the `dockers:` block (use the existing root Dockerfile as canonical, or let goreleaser drive a separate path) |
| cosign signing | Uncomment the `signs:` block; relies on the `id-token: write` permission already declared in `release.yml` |

Locally: `make release-snapshot` runs the full matrix into `dist/` so
you can poke at the produced artifacts (archives, checksums, SBOMs)
without pushing a tag.

---

## API specifications

Two schemas, two consumption surfaces:

| Surface | Source of truth          | Consumers                             |
|---------|--------------------------|---------------------------------------|
| HTTP    | `docs/openapi.yaml` (OpenAPI 3.0) | swagger-ui, Postman/Insomnia/Bruno, ReadMe.io, Mintlify, Stoplight, OpenAPI Generator (client SDKs in 20+ languages) |
| gRPC    | `proto/*.proto`          | `protoc` / `buf generate`, buf.build BSR, grpc-gateway, every grpc-* client lib |

`docs/openapi.yaml` covers the core auth flow + self-service endpoints
(login, send-code, logout, userinfo, /me/{permissions,roles,menus}, JWKS,
health). The admin REST surface (`/api/v1/admin/*`), audit query API, and
netpolicy CRUD are not in the spec yet — additive layering only when added,
no schema rewrites needed.

When you change a documented HTTP endpoint, update `docs/openapi.yaml` in
the same commit. CI runs `make docs-validate` so a mismatched schema fails
the PR.

`docs/error-codes.md` is the stable wire-contract catalog of every
`error` value the server can emit. SPAs / downstream services branch
on the `error` code, never on `error_description`. When you add a new
`Err*` constant in `consts.go`, update the catalog in the same commit.

---

## Conventions

- **No literals leak** — all paths, headers, error codes, claim names live in
  `consts.go` (root) or the package's `consts.go`. When you introduce a new
  string that another file refers to, add a constant.
- **No mocks for storage** — tests use the real `MemoryProvider` /
  `MemorySink` / `memory.Registry`. Mocks invite drift between test and prod.
- **No emojis in code, comments, or commits.** Prose is fine in chat
  responses if the user uses them first.
- **Comments explain why, not what.** Identifiers should be readable enough
  to convey what. Reach for a comment when there's a hidden constraint,
  invariant, or workaround a future reader would otherwise reverse-engineer.
- **Interface guards in implementation packages, not parent.** Use
  `var _ ssoclient.AuthClient = (*remote.AuthClient)(nil)` inside
  `ssoclient/remote/`, never in `ssoclient/` itself (would import-cycle).
- **gRPC field names** — protoc-gen-go renames `ID` → `Id`, `URL` → `Url`,
  etc. Refer to generated Go names, not the .proto names, in Go code.

---

## Common tasks

### Add a new authenticator
1. Implement `sso.Authenticator` in `authenticators/<name>.go`.
2. Add the YAML knob under `authenticators:` in `config/config.go`.
3. Wire it in `cmd/sso-server/main.go`'s `buildAuthenticators`.
4. Whitelist it under a client's `allowed_authenticators:` to test.

### Add a new audit Sink
1. Implement `audit.Sink` (one method: `Write(ctx, *Event) error`).
2. If it has lifecycle, also implement `audit.Closer`.
3. Wire it via `audit.New(sink1, sink2, ...)` or `audit.MultiSink`.

### Add a new permission storage backend
1. Implement `permissions.Provider` in `permissions/<name>/`.
2. Plumb it through `sso.WithPermissionProvider(...)` at server build time.
3. Keep the wildcard matcher behavior — `*` and `pkg:*` must match.

### Add a new network policy at runtime
1. `POST /api/v1/netpolicy/policies` with `{"name":..., "cidrs":[...], "hostnames":[...], "priority":...}`.
   Or gRPC `PolicyService.Apply`. Both mirror to audit automatically.
2. Watchers (OpenResty edge cache, classifier in-process) pick up the
   change via Watch — no restart.
3. To seed at boot, add an entry under `network.policies:` in
   `cmd/sso-server/config.yaml`.

### Add a new gRPC service (Phase C+)
1. Write `proto/<name>/v1/<name>.proto`.
2. Regenerate (see Setup commands).
3. Implement the server in `grpcserver/<name>.go` over an interface that the
   HTTP layer already uses — no duplication of business logic.
4. Register it in `cmd/sso-server/main.go`'s `newGRPCServer`.
5. Add a `bufconn`-based test in `grpcserver/grpcserver_test.go`.

---

## Commit conventions

- Conventional Commits style: `feat(area): summary`, `fix(area): summary`,
  `chore: summary`, `docs: summary`.
- Subject line short and imperative; one blank line; body explains the why.
- Co-author trailer when commits are AI-assisted.
- Don't commit binaries — `/sso-server` and `cmd/sso-server/sso-server` are
  ignored. If you see new top-level binaries, add them to `.gitignore`.

---

## Things not to do

- Don't run `git reset --hard`, `git push --force`, or delete branches
  without explicit user authorization.
- Don't init or modify git config.
- Don't bypass pre-commit hooks (`--no-verify`, `--no-gpg-sign`).
- Don't introduce mocks where a real in-memory implementation already exists.
- Don't add features, refactors, or "while I'm here" cleanup that the user
  didn't ask for.
- Don't write Markdown files unless the user asked for them. (This file
  itself was explicitly requested.)
