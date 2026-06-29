# sso-mcp — MCP server fronting snaplink's read-only authz surface

- **Date:** 2026-06-29
- **Status:** Design approved (pending spec review) → next: writing-plans
- **Scope:** New binary `cmd/sso-mcp`. First, testable slice = read-only identity/authz tools.

## 1. Context & goal

snaplink is the OAuth 2.0 / OIDC authorization server. AI agents must not bypass
its permission system. We want a single shared service that exposes snaplink's
**read-only identity/authz surface** to many agents over the Model Context
Protocol (MCP), so agents can answer "who is this subject, and what may they do?"
through a standard tool interface.

This server contains **no MCP-into-snaplink coupling**: snaplink stays a pure
authorization server. `cmd/sso-mcp` is a *consumer* of snaplink (like
`cmd/sso-server` consumes the SDK), and the MCP SDK dependency is isolated in a
nested module so it never enters the core dependency graph.

### Goals
- Expose 5 read-only authz tools backed 1:1 by snaplink's gRPC `Authorizer`
  service + token validation.
- Serve many remote agents (Streamable HTTP) and local single-host agents (stdio).
- Be a spec-compliant OAuth 2.0 Resource Server (MCP 2025-06-18 / 2025-11-25
  authorization model) on the HTTP transport.

### Non-goals (this slice)
- No write/admin tools (create user, revoke token, etc.) — deferred to phase 2.
- No deployment artifacts beyond a note (k8s Deployment/Service is phase 2).
- snaplink itself is unchanged. (Optional, separate: the `/.well-known/oauth-authorization-server`
  RFC 8414 alias discussed earlier is NOT part of this work.)

## 2. Decisions

| # | Decision | Choice |
|---|---|---|
| 1 | Module placement | **Nested module** `cmd/sso-mcp/go.mod` — keeps the MCP Go SDK out of the core `go.mod`; wired into `make ci` via `ci-modules` (same pattern as `kms/`, `saml/`, `redis/`). |
| 2 | Transport | **Both.** Transport-agnostic MCP core. Streamable HTTP for many remote agents; stdio for local/dev. Selected by `--transport http\|stdio` (default http). |
| 3 | MCP Go SDK | Official `github.com/modelcontextprotocol/go-sdk`. Exact version pinned in the plan (SDK is pre-1.0; verify API in planning). |
| 4 | Tool set | The 5 read-only tools below, as a first testable slice. |

### Transport ⇒ two auth models (explicit, not a hole)
The OAuth Bearer gate is an HTTP-layer concept. Over **stdio** there is no
`Authorization` header, and per the MCP spec stdio servers use the
**trusted-subprocess** model (the host spawns the process; credentials come from
the environment).

- **HTTP transport:** full per-agent OAuth Resource Server gate (validate
  Bearer, check `aud`, check scope; 401 + `WWW-Authenticate` + PRM). This is the
  "many agents" path.
- **stdio transport:** local trusted mode — the caller (host) is the trust
  boundary; no per-call Bearer gate. sso-mcp still uses its own constrained
  service credential to reach snaplink.

In **both** cases, sso-mcp authenticates to snaplink with its own `admin:read`
service credential (client_credentials) and **never passes an agent's token
through** to snaplink (MCP spec forbids token passthrough / confused-deputy).

## 3. Architecture

```
                 ┌──────────── cmd/sso-mcp (standalone, nested module) ────────────┐
 agent ─Bearer──▶│  MCP transport (Streamable HTTP | stdio)                        │
 (aud=sso-mcp,   │      │                                                          │
  scope mcp:read)│      ▼                                                          │
                 │  OAuth RS gate (HTTP only): validate Bearer via JWKS,           │
                 │    aud==resource URI, scope ⊇ mcp:read   ──fail──▶ 401 + PRM    │
                 │      │ ok                                                        │
                 │      ▼                                                          │
                 │  tool dispatch ──▶ authz_client (ssoclient/remote)              │
                 └──────────────────────────┬──────────────────────────────────────┘
                                            │ gRPC, admin:read service credential
                                            ▼
                                snaplink: gRPC Authorizer + JWKS
```

**Components**
- *MCP core* — registers tools, transport-agnostic; the official SDK provides
  stdio and Streamable HTTP transports.
- *OAuth RS gate* (`auth.go`) — HTTP middleware: extract Bearer, validate via
  `ssoclient/remote` JWKS, enforce `aud` + `scope`; emit 401
  `WWW-Authenticate: Bearer ... resource_metadata="…"`; serve RFC 9728 PRM at
  `/.well-known/oauth-protected-resource` (`authorization_servers=[snaplink issuer]`).
- *authz_client* (`authz_client.go`) — thin wrapper over `ssoclient/remote`
  `AuthClient` + `AuthzClient`, holding the gRPC conn + the `admin:read` token
  source.
- *config* — listen addr, transport, snaplink gRPC addr, snaplink JWKS/issuer
  URL, resource URI (the `aud` this server requires), service client_id/secret.

## 4. Tool set (1:1 with real snaplink APIs)

All read-only. Permissions are resolved **per (subject, client)** — `client_id`
is the app context, required by the underlying `Authorizer` calls.

| MCP tool | Args | snaplink backend (verified) | Returns |
|---|---|---|---|
| `introspect_token` | `token` | `ssoclient/remote.AuthClient.ValidateToken` (JWKS, local JWT verify) | `{active, sub, client_id, scope, aud, tenant, exp}` |
| `check_permission` | `subject_id, client_id, permission` | `AuthzClient.Check(CheckRequest)` | `{allowed: bool}` |
| `list_permissions` | `subject_id, client_id` | `AuthzClient.ListPermissions(subjectID, clientID)` | `[permissions]` |
| `list_roles` | `subject_id, client_id` | `AuthzClient.ListRoles(subjectID, clientID)` | `[roles]` |
| `get_menus` | `subject_id, client_id` | `AuthzClient.GetMenus(subjectID, clientID)` | `menu tree` |

`resolve_tenant` is folded into `introspect_token`'s output rather than a
separate tool. Wildcard semantics (`user:*` ⊇ `user:read`) are snaplink's; we do
not re-implement matching.

## 5. Package & module layout

Respects code budgets: file ≤ 500 lines, function ≤ 50 lines, cyclo ≤ 15,
≤ 10 `.go` files/dir, directory depth ≤ 3.

```
cmd/sso-mcp/
  go.mod / go.sum   # nested module: github.com/snaplink/sso/cmd/sso-mcp (depends on parent + MCP SDK)
  main.go           # flags/env, wire, run selected transport, graceful shutdown on signal
  config.go         # config struct + load (YAML + env), validation
  server.go         # MCP server construction + tool registration entrypoint + /livez /readyz (HTTP) + PRM mount
  auth.go           # OAuth RS gate (HTTP): Bearer extract, validate, aud+scope, 401 + WWW-Authenticate + PRM doc
  authz_client.go   # ssoclient/remote wrapper (AuthClient + AuthzClient + admin:read token source)
  tools.go          # the 5 tool handlers (split into tool_*.go only if it approaches 500 lines)
  *_test.go         # bufconn integration tests against a real in-memory snaplink Authorizer
```

Nested-module wiring: add `cmd/sso-mcp` to the `ci-modules` list so
`make ci` builds/tests it; it is NOT part of the parent `go build ./...`.

## 6. Configuration (YAML + env, snaplink convention)

```
listen_addr:        ":8090"          # HTTP transport bind
transport:          "http"           # http | stdio
snaplink_grpc_addr: "sso:8081"       # Authorizer gRPC
snaplink_jwks_url:  "https://sso/.well-known/jwks.json"
snaplink_issuer:    "https://sso"
resource_uri:       "https://mcp/"   # required aud in agent tokens (RFC 8707)
required_scope:     "mcp:read"
service_client_id:  "sso-mcp"        # admin:read service credential (client_credentials)
service_client_secret_env: "SSO_MCP_CLIENT_SECRET"
```

## 7. Testing strategy (no mocks — AGENTS.md)

- **Tool tests:** wire a real in-memory snaplink `Authorizer` over **bufconn**
  (existing `grpcserver` pattern); assert each tool returns the backend's answer.
- **Auth gate tests (HTTP):** missing token, bad signature, wrong `aud`,
  insufficient scope → each yields 401 with the correct `WWW-Authenticate` +
  `resource_metadata`.
- **PRM test:** `/.well-known/oauth-protected-resource` lists snaplink as
  `authorization_servers`.
- **Transport smoke:** stdio init/list-tools/call round-trip; HTTP same.
- Race + the committed maintainability/import-boundary gates pass; nested module
  green under `ci-modules`.

## 8. Risks & open questions (resolve in planning)

1. **MCP Go SDK API/version** — pre-1.0; pin a version and confirm the
   stdio + Streamable HTTP transport APIs and tool-registration signatures.
2. **Multi-alg JWKS** — `ssoclient/remote.JWKSCache.Get` is Ed25519-centered
   (there is `auth_multialg_test.go`); confirm RS256/ES256 coverage if snaplink
   may sign mcp tokens with non-Ed25519 keys, else constrain the issuer alg.
3. **Service credential acquisition** — sso-mcp needs an `admin:read`
   client_credentials token to call gRPC; decide static secret vs. periodic
   refresh and how the gRPC call carries it (per-RPC metadata).
4. **`introspect_token` for opaque tokens** — `ValidateToken` covers JWTs; if
   opaque tokens must be introspected, add an HTTP call to `/token/introspect`
   (needs the service client creds). Default: JWT-only for the first slice.
5. **CheckRequest shape** — confirm exact fields of `ssoclient.CheckRequest`
   (subject/client/permission) when wiring `check_permission`.

## 9. Out of scope / future

- **Phase 2 (write tools):** `create_user`, `revoke_token`, `assign_role`, …
  mapped to `/api/v1/admin/*`, gated on `admin:write` / dedicated scopes.
- **Phase 2 (deploy):** `ops/deploy/k8s` Deployment + Service + HPA for sso-mcp.
- **Optional, separate:** snaplink RFC 8414 `oauth-authorization-server` alias.
