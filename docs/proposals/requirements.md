Evidence gathering is complete. I verified every claim in the analysis against the code: `ResolveResource` has zero consumers outside `domains/permissions/` (grep hits only `memory_resources.go`), the sqlite backend's own comment admits resources are "NOT covered", `Check` in authz.go does only flat `permissions.Matches`, the `Permission.Resource` wire field exists but is never populated, and the admin proto has no resource RPCs. Here is the specification.

---

# Requirements Specification: `domains/permissions` — Direction 1: wiring `ResourceProvider` into resource-level authorization enforcement points

Scope: the analysis document's Direction 1 only — turning the built-but-unwired resource catalog (`ResourceProvider`, `ResolveResource`, `RequireMode`, `RequiresAuth`) into a live authorization execution surface. Three improvements, each with name, problem, evidence, proposed behavior, acceptance check.

## ## 1. Resource-aware decision at the authorization `Check` point

**Name**: Make the authz `Check` path resolve catalog entries instead of flat permission codes only.

**Problem**: The runtime authorization decision ignores the resource catalog entirely. `Check` returns `permissions.Matches(perms, in.Permission)` — a flat code lookup — even though the wire protocol already anticipates resource-level authorization: `Permission` carries a `resource` field (`gen/proto/authz/v1/authz.pb.go:199`, `proto/authz/v1/authz.proto` `message Permission { string code = 1; string resource = 2; }`) that no backend ever populates (`domains/permissions/memory.go:283` emits only `Permission{Code: code}`). Meanwhile the complete matching engine — `ResolveResource` (`domains/permissions/memory_resources.go:100`), per-type attribute matching with `:param` path wildcards (`matchAttributes`/`matchPath`), `RequireMode` any/all projection (`ResourceDecision`, `EffectiveRequireMode` in `resources.go`) — has zero callers outside the package. Code runs; policy is not enforced.

**Proposed behavior**:
- Extend `CheckRequest` additively (authz/v1 is STABLE per ADR-0008: new fields only) with a resource lookup: `resource_type` + `attributes` map (and optionally `tenant_id`), matching `ResourceLookup` (`resources.go`).
- When the lookup is present and the provider satisfies `ResourceProvider` (type-assert, same pattern as `MenuLister`): call `ResolveResource`. If `Found=true`, decide by the projected policy — `RequiresAuth` gate plus `RequiredPermissions` combined per `RequireMode` (`RequireAll` = every listed code via `Matches`; `RequireAny` = at least one). If `Found=false`, fall back to the current flat `Matches` behavior so existing callers' semantics are byte-identical.
- Keep the decision in one exported helper in `domains/permissions` (e.g. `CheckResource(provider, lookup, subjectPerms)`), with `interfaces/grpcserver/authz.go` as a thin adapter, preserving the hexagonal boundary.

**Acceptance check**:
- New tests (grpcserver-level): register an `http_api` resource `{method: POST, path: /api/v1/users/:id, require_mode: all, required_permissions: [billing:write, audit:read]}`; `Check` with a matching lookup and a subject holding only one of the codes returns `allowed=false`; holding both returns `allowed=true`; a lookup with no catalog entry returns exactly the old flat-code result.
- `RequireMode` defaults to `any` when empty (matches `EffectiveRequireMode`).
- `go build ./... && go vet ./...` plus `go test -run 'TestMaintainability_|TestArchitecture_' .` pass; authz/v1 proto remains wire-compatible (no field renumbering/removal).

## ## 2. Durable resource catalog backend + conformance suite

**Name**: Persist the catalog in a durable backend and make backend conformance verifiable.

**Problem**: The catalog exists only in memory. `domains/permissions/sqlite/sqlite.go:18-21` states outright: "Resources … are **NOT covered** here — they live behind a separate Provider extension interface" — so in any multi-replica or restarting deployment the catalog silently vanishes or forks per replica. Redis/postgres peers have the same gap. There is also no `ResourceProvider` conformance suite: `permissionstest/` covers base `Provider`, SoD, and menus, but a backend claiming resource support cannot be verified (contrast `permissionstest/sod_conformance.go:144` which at least type-asserts and skips honestly). AGENTS.md §4 requires every storage concern to be "an interface plus a real `Memory*` implementation and optional durable backends" with conformance as the verification tool.

**Proposed behavior**:
- Add a `permissions_resources` table (tenant_id, client_id, type, name, requires_auth, attributes_json, required_permissions_json, require_mode, timestamps; unique on (tenant_id, client_id, type, name)) as migration v2 in `domains/permissions/sqlite/` (append to the existing `migrations` slice, keep v1 untouched). Implement `ResourceProvider` on the sqlite provider: `RegisterResource` returns `ErrResourceExists` on real tuple conflicts (idempotent re-register of the same ID updates), `DeleteResource` is idempotent, `ResolveResource` uses a per-type dispatch index (method+path key for `http_api`, service+method for `grpc_api`) rather than a scan.
- Add `ResourceConformanceSuite` to `permissionstest` covering: register/get/list/delete round-trip, `ErrResourceNotFound`, tuple-conflict → `ErrResourceExists`, tenant/client scoping (empty = no-tenant/no-client bucket), `RequireMode` projection, `:param` path matching, `Found=false` on no match. Run it against Memory and sqlite; list redis/postgres as known gaps in the suite's skip mechanism rather than silently passing.

**Acceptance check**:
- `go test ./domains/permissions/...` runs the new suite against both MemoryProvider and the sqlite provider with zero skips for those two.
- Restart-persistence test: write resources through sqlite, reopen the store, `GetResource`/`ResolveResource` return identical data.
- Migration path is backward compatible: a v1-stamped DB upgrades to v2 without data loss (`make ci` includes module validation; existing `permissions_roles`/`assignments`/`menus` tables untouched).

## ## 3. Management plane + RFC 9396 `authorization_details` enforcement coupling

**Name**: Admin CRUD for the catalog, and make RAR tokens the first enforced consumer.

**Problem**: Two half-built ends of the same wire. (a) There is no way to manage the catalog: `proto/admin/v1/permissions.proto` exposes exactly 8 RPCs (List/Add/Update/Remove roles, List/Assign/Unassign, SetMenus) — nothing registers a resource — so even the memory backend's catalog can only be populated by direct Go code. (b) RFC 9396 `authorization_details` already travels on the wire — `protocols/oauth/handle_par.go:222` calls `ValidateAuthorizationDetails` and the payload is stored into the token (`protocols/oauth/oauthvalidate/rar.go` `KeyAuthorizationDetails`) — but validation is shape-only (`checkRARShape` in `rar.go:80` caps size/depth/count and allowlists `type`); the payload is never interpreted against the resource catalog, so a client can request `http_api` scopes for methods/paths that do not exist or that demand more than the client should hold.

**Proposed behavior**:
- Add resource CRUD RPCs to `PermissionAdminService` (RegisterResource / GetResource / ListResources / DeleteResource; additive, regenerate `gen/`), mapping `ErrResourceNotFound` → `NotFound` and `ErrResourceExists` → `AlreadyExists` following the existing `admin_permissions.go` pattern, and route them through the `invalidateAuthzPolicy` callback (`interfaces/grpcserver/grpcadmin/admin_permissions.go:37`) so bundle caches invalidate on catalog changes.
- Add a config-gated catalog check in the PAR flow (after the existing shape validation at `handle_par.go:222`): for `type` values `http_api`/`grpc_api`/`graphql_api`, when a `ResourceProvider` is configured, resolve each element via `ResolveResource` using the element's `method`/`path` (or `service`/`method`) fields; unknown or attribute-mismatched elements fail with `invalid_authorization_details` (RFC 9396 §6) so tokens never carry unverifiable resource claims. When no provider is configured, behavior is unchanged (shape-only), preserving backward compatibility for existing clients.
- Update contracts in the same change per AGENTS.md §5: new `Err*` → `docs/error-codes.md`, new RPCs → `docs/openapi.yaml`/proto, config knob → `docs/config-reference.md`.

**Acceptance check**:
- Admin gRPC test (bufconn, per the gRPC pattern): register a resource via RPC, list it back, delete it, re-delete returns success (idempotent); unknown-ID get returns gRPC `NotFound`.
- PAR integration test: `authorization_details` with a registered `http_api` resource matching its attributes is accepted; the same payload with a method/path not in the catalog is rejected with `invalid_authorization_details`; with no provider configured, both pass (shape-only) — proving no regression for catalog-less deployments.
- `python cli.py` checks + `go test ./test/ -run TestE2E` green; error-code and config-reference docs updated in the same commit.

---

**Dependencies/notes**: improvement 1 and 3 both consume improvement 2's conformance-verified persistence; 1 is the runtime decision point, 3 is the management/validation surface. All three stay within existing budgets (`domains/permissions` and `interfaces/grpcserver` are not at file ceilings; `interfaces/sso` is untouched).
