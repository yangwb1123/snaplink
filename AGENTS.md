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
```

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
```

`client_id: ""` (empty string) is a valid bucket — used by the demo so tokens
without an `aud` claim still resolve to a role. Production code should issue
tokens with an explicit audience and key permissions under the real client_id.

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
