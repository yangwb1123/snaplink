# Requirements Spec: interfaces/admin — 管理面双轨一致性 (HTTP 与 gRPC 单一事实源与能力对齐)

> Source: expansion direction 2 of `docs/auto/interfaces-admin-analysis.md`.
> Scope: `interfaces/admin` (gate), `interfaces/grpcserver/grpcadmin` (gRPC
> services), `proto/admin/v1` (contract), `cmd/sso-server` (wiring),
> `interfaces/sso/server_routes_admin.go` (HTTP mount).
> Module classification: Admin endpoint + Authorization/policy + Refactoring.
> Default: behavior-preserving on both tracks when unconfigured (byte-identical
> to today); all new gRPC services are opt-in like their HTTP siblings.

## Constraints (from AGENTS.md, checked against the tree)

- `interfaces/admin` has 10 non-test `.go` files and `interfaces/grpcserver/grpcadmin`
  has 10 — both at the fan-out ceiling. No new non-test files in either
  directory; extend existing files. `middleware.go` (492/500 lines) and
  `governance.go` (483/500) are near their per-file budgets; the decision-3
  refactor must keep them under budget (move logic out, never in).
- New RPCs require proto + `buf` regeneration (`gen/proto/admin/v1`), gRPC
  service registration in `registerAdminGRPCServices`
  (`cmd/sso-server/main_servers.go`), and gateway routing must stay derived,
  not hand-copied.
- Contracts updated in the same change: `docs/openapi.yaml` (only if HTTP
  routes change — none do here), `docs/error-codes.md` (new gRPC status
  mappings), `docs/config-reference.md` (only if config surface changes — none
  do here).
- OAuth/OIDC oracle-safety and audit invariants in AGENTS.md §3 are untouched;
  this spec adds no new `Err*` codes and no config knobs.

---

## 1. 能力对齐：补齐 HTTP-only 管理操作的 gRPC RPC（消除自动化断层）

**Name**: gRPC capability parity — every admin operation family reachable over gRPC.

**Problem**: The gRPC admin plane covers 9 services / 53 RPCs, while the HTTP
surface exposes 172 `/api/v1/admin` path occurrences in `docs/openapi.yaml`
(≥132 distinct paths per the analysis scan). Every helpdesk- and
security-critical workflow that lives only on HTTP — device revocation,
login-history lookup, break-glass approval, connection probe, tenant
export/invitation, audit query — is unreachable from gRPC consumers
(sso-operator, MCP, CI). The handlers themselves are already transport-agnostic
`Deps`-based free functions; only the RPC surface is missing.

**Evidence**:

- `proto/admin/v1/`: 9 services, 53 RPCs total (`clients.proto` 9, `keys.proto` 2,
  `operations.proto` 2, `permissions.proto` 8, `releases.proto` 7, `snapshots.proto` 5,
  `tenants.proto` 11, `tokens.proto` 3, `users.proto` 6).
- `cmd/sso-server/main_servers.go` `registerAdminGRPCServices` — the complete gRPC
  registration list; it is the authoritative inventory of what gRPC can do.
- `interfaces/admin/connections.go` `HandleAdminListConnections` /
  `HandleAdminUpsertConnection` / `HandleAdminProbeConnection` /
  `HandleAdminGetConnectionHealth` / `HandleAdminListProviders` /
  `HandleAdminCreateProvider` — 11 connection/provider handlers, no proto.
- `interfaces/admin/lifecycle.go` `HandleAdminListAllDevices` /
  `HandleAdminBulkRevokeDevices` / `HandleAdminDeleteUserDevice` /
  `HandleAdminDeviceStats` / `HandleAdminResetDeviceTrust` /
  `HandleAdminListUserLoginHistory` / `HandleAdminListSecurityActivity` — no proto.
- `interfaces/admin/break_glass.go` `HandleCreateBreakGlass` /
  `HandleListBreakGlass` / `HandleApproveBreakGlass` / `HandleRevokeBreakGlass`
  (plus impersonation, `break_glass_impersonate.go`) — no proto.
- `interfaces/admin/governance.go` `HandleAdminProposeChange` /
  `HandleAdminApproveChange` / `HandleAdminRejectChange` — no proto.
- `interfaces/admin/tenants.go` `HandleAdminExportTenant` /
  `HandleAdminSendInvitation` / `HandleAdminListTenantMembers` /
  `HandleAdminPutTenantMember` / `HandleAdminListConnectionDomains` — no proto
  (`tenants.proto` covers only tenant/domain CRUD + status).
- `interfaces/admin/token_portfolio.go` `HandleSubjectTokens` /
  `HandleTokenExpiring` / `HandleBulkRevoke` / `HandleLinkedSessions` — no proto
  (`tokens.proto` has only `ListSessions`/`Revoke`/`IssueTempToken`).
- `interfaces/admin/users.go` — 14 user-state handlers (consents, MFA, password
  reset, lockout, device secrets, refresh tokens, reset-token families) vs
  `users.proto`'s 6 RPCs (CRUD + sessions).
- `proto/audit/v1/audit.proto` — `AuditWriter` has only `StreamEvents`; audit
  query (`interfaces/sso/server_discovery.go` `handleAuditEvents` →
  `platform/audit/handlers.go` `HandleEvents`/`HandleFacets`/`HandleEventByID`)
  is HTTP-only.
- `interfaces/sso/server_routes_admin.go` `mountAdminSurface` — the HTTP mount
  blocks (`mountAdminB2B`, `mountAdminDeviceUserRoutes`, `mountAdminBreakGlass`,
  `mountAdminChangeApproval`, `mountAdminUserState`, `mountAdminTokenGovernance`,
  `mountConfigAuditAPI`) that have no gRPC counterpart.

**Proposed behavior**:

1. Extend `proto/admin/v1` with RPCs for each missing family, in this order
   (helpdesk/security critical first): `DeviceAdminService` (list user devices,
   list all devices, delete, bulk revoke, stats, trust reset, activity),
   `SessionHistoryService` (login history, security activity),
   `BreakGlassAdminService` (create/list/approve/revoke),
   `ChangeApprovalService` (propose/list/get/approve/reject),
   `ConnectionAdminService` + `ProviderAdminService` (CRUD, health, probe),
   `TenantAdminService` extension (members, invitations, export, connection
   domains), `TokenAdminService` extension (portfolio, subject, expiring,
   bulk-revoke), `UserAdminService` extension (password reset, MFA, consents,
   lockout, device secrets, refresh-token revocation), `AuditQueryService`
   (events, facets, event-by-id).
2. gRPC service implementations live in `interfaces/grpcserver/grpcadmin`
   (extend existing files — the directory is at its 10-file ceiling) and
   delegate to the existing `interfaces/admin` `Deps`-based free functions —
   the handlers are already transport-agnostic; the RPC layer is a thin adapter
   (matches the "domain free function + thin adapter" pattern in AGENTS.md §5).
   No logic duplication between `interfaces/admin` and `grpcadmin`.
3. Register all new services in `registerAdminGRPCServices`
   (`cmd/sso-server/main_servers.go`), gated on the same opt-in stores the HTTP
   mounts use (nil store ⇒ service not registered — byte-identical to a build
   without the feature, same as the HTTP side).
4. Add a parity gate test (Go test, part of `make ci`): enumerate the HTTP
   admin handler inventory (the `mountAdmin*` blocks in
   `server_routes_admin.go`) and the registered gRPC services, and fail when an
   operation family has no RPC counterpart. A short documented allowlist covers
   genuine non-goals (SSE event stream, docs UI, GatedRouter-runtime-only
   routes).

**Acceptance check**:

- Each listed family has at least one RPC; `buf`-generated code is committed and
  the new services are registered; `go build ./... && go vet ./...` and
  `go test ./interfaces/grpcserver/grpcadmin/` pass.
- New bufconn tests (following the existing `admin_*_test.go` pattern) drive
  e.g. `DeviceAdminService/ListAllDevices` and `BreakGlassAdminService/Approve`
  and assert both the family-specific audit event (e.g.
  `EventAdminBreakGlassApproved`) and the interceptor's
  `EventAdminGRPCCalled` — same event evidence as the HTTP path.
- The parity gate test passes with zero undocumented gaps; `make ci` green.

---

## 2. 单一事实源：一张声明式 operation→scope 表，两个传输共同消费

**Name**: Single source of truth for scope decisions (and gated-set mirroring).

**Problem**: Scope is derived three different ways and mirrored by comment
promise: HTTP decides by HTTP method (GET/HEAD/OPTIONS → read), gRPC by an
RPC-name prefix heuristic (`isReadMethod`), and one shared `methodScopes` map is
interpreted under two different lookup conventions (exact FQ gRPC method name
vs longest-prefix HTTP path). A third hand-maintained mirror exists for the
gateway (`adminGatewayExactPaths`), whose own comment admits it was forgotten
at least twice. A new endpoint can land with a wrong scope on one track
silently — a security event, not an experience issue.

**Evidence**:

- `interfaces/admin/middleware.go` `scopeForHTTP` (lines 160–175, HTTP-method
  rule) vs `scopeForGRPC` (lines 145–158, `isReadMethod` name heuristic,
  lines 177–190: `List`/`Get`/`Search`/`Find` prefixes) — two different rules
  for the same operation.
- `interfaces/admin/middleware.go` `methodScopes` (line 71) + `SetMethodScope`
  (line 116): one map keyed by FQ gRPC method (exact match in `scopeForGRPC`)
  or HTTP path prefix (longest-prefix, segment-bounded lookup in
  `interfaces/admin/governance.go` `methodScopeForPath`) — the same map, two
  semantics.
- `interfaces/admin/middleware.go` `isGatedGRPCMethod` (line 192) — comment
  "MIRRORS the HTTP IsProtectedPath set"; the two sets are maintained by hand.
- `cmd/sso-server/build_app.go` `wireAdminMW` — the only `SetMethodScope` calls
  in production (lines 301, 304) register HTTP paths only
  (`PathAdminWASMAuthzCheck`, `PathAdminConfigClusterDiff`); the gRPC side has
  no per-method override path in use.
- `cmd/sso-server/build_http.go` `adminGatewayExactPaths` — a third
  hand-maintained copy of the proto `google.api.http` annotations
  ("Reproduce with: `grep WithHTTPPathPattern(...)`"; its doc admits the
  previous whole-subtree scheme "was forgotten at least twice (bulk-revoke,
  commit fdebea60, and the local-user CRUD collision)").
- `interfaces/sso/server_routes_admin.go` `mountAdminSurface` — the HTTP route
  table is assembled by hand in a fourth place.

**Proposed behavior**:

1. Introduce one declarative table — one row per admin operation, keyed by a
   canonical operation id (the gRPC FQ method name for RPC-backed operations;
   the gateway path + HTTP method for the REST aliases) — declaring the
   required scope. Both `scopeForHTTP` and `scopeForGRPC` resolve through this
   table; the `isReadMethod` heuristic is deleted.
2. The table is the single source for all three mirrors: the gRPC gated set
   (`isGatedGRPCMethod`) and the HTTP gated set (`IsProtectedPath`) are both
   derived from it, replacing the "MIRRORS" comment with a checked invariant;
   the gateway exact-path list in `build_http.go` is regenerated from the
   proto annotations at build time (or verified by a test comparing it to
   `gen/proto/admin/v1/*.pb.gw.go` `WithHTTPPathPattern` extraction) instead
   of being hand-copied.
3. Fail-closed default: a new admin operation with no table row requires
   `admin:write` (write is the conservative default on both transports — no
   silent read-scope widening). `SetMethodScope` overrides become table rows
   with the same path-boundary semantics as today (`methodScopeForPath`
   behavior preserved byte-identically).
4. Consistency test: walk every registered gRPC admin method and every mounted
   HTTP admin route, and assert both transports resolve the same operation to
   the same scope, and that the gated sets (`IsProtectedPath` vs
   `isGatedGRPCMethod`) are identical for the admin surface.

**Acceptance check**:

- `grep -rn "isReadMethod" interfaces/` returns nothing; scope decisions come
  only from the table.
- New test `TestAdminScopeTableConsistency` passes: for every gRPC admin RPC
  and every HTTP admin path, `scopeForGRPC` == `scopeForHTTP` for the same
  operation, and the gated sets match; a deliberately added RPC without a
  table row fails the test (fail-closed).
- The gateway path list is verified against generated code (test, or
  generated at build): `TestAdminGatewayExactPaths_ValidServeMuxSyntax` and
  its siblings in `cmd/sso-server/admin_gateway_routing_test.go` still pass;
  existing `SetMethodScope`-override behavior (wasmauthz check, cluster diff)
  unchanged.

---

## 3. 治理对齐：传输无关的治理闸门，HTTP 与 gRPC 共用同一判定

**Name**: Governance parity — IP allowlist, rate limit, write quota,
destructive confirmation, and idle timeout enforced on both transports.

**Problem**: All five transport-level governance checks run only inside
`HTTPMiddleware`; the gRPC interceptor enforces only bearer + scope. A direct
gRPC consumer (native port, not the REST gateway — which sits inside
`HTTPMiddleware`) bypasses the IP allowlist, the admin-wide rate limit, the
per-tenant/admin write quota, the destructive-action `X-Confirm` guard, and the
admin-session idle timeout. The same operation (e.g. client delete) has
different governance strength depending on which port it arrives on, while
`config/config_admin.go` documents these sections as transport-level checks
with no transport caveat.

**Evidence**:

- `interfaces/admin/middleware.go` `HTTPMiddleware` (lines ~349–371): runs
  `checkIPPolicy` → `checkRateLimit` → `checkDestructiveConfirm` →
  `authenticateHTTP` → `enforceIdleTimeout` → `checkWriteQuota` — the only
  consumer of `a.rateLimitStore`, `a.quota`, `a.ipPolicy`, `a.destructive`,
  `a.adminTokenStore`, `a.sessionTTL`.
- `interfaces/admin/middleware.go` `UnaryServerInterceptor` and
  `StreamServerInterceptor`: call `authorizeGRPC` only; never read the six
  governance fields.
- `interfaces/admin/governance.go` — `checkIPPolicy` / `checkRateLimit` /
  `checkDestructiveConfirm` / `checkWriteQuota` all take
  `http.ResponseWriter` and write HTTP responses directly; the decisions are
  HTTP-coupled, so the interceptor cannot reuse them as-is.
- `cmd/sso-server/build_app.go` `wireAdminMW` + `wireAdminGovernanceMW`
  (lines 306–347): `SetRateLimit` / `SetWriteQuota` / `SetDestructiveActions` /
  `SetIPAllowlist` / `SetAdminTokenStore` / `SetAdminSessionTTL` wire the
  shared `Middleware` construction object, but only `HTTPMiddleware` consumes
  them.
- `cmd/sso-server/main_servers.go` `grpcInterceptorOptions` (lines 196–204):
  the gRPC chain contains only Recovery + the scope interceptor — no
  governance stage.
- `interfaces/admin/middleware.go` `SetAuditRecorder` doc ("logs every gRPC
  admin RPC") and the interceptor's denial recording (`EventAdminGRPCCalled` +
  `OutcomeFailure`) vs the HTTP side's silent denials — observability of the
  two tracks diverges exactly where governance does (denial paths; see also
  analysis direction 3).
- `platform/audit/auditspi/event_types_admin.go` — the denial event types
  `EventAdminIPDenied` / `EventAdminWriteQuotaExceeded` are already defined and
  classified in `platform/audit/auditreport/control_areas.go`, but `grep` shows
  no production code ever records them; the taxonomy is ready, the emitters do
  not exist.

**Proposed behavior**:

1. Refactor the five checks into one transport-neutral gate on the shared
   `Middleware`: a single evaluation order (IP policy → rate limit →
   destructive confirm → authenticate + idle timeout → write quota, preserving
   the documented no-oracle ordering: IP policy before auth machinery) that
   returns a decision value `{allow, code, retryAfter, challenge}` without
   touching `http.ResponseWriter`.
2. Two thin renderers: the HTTP middleware maps the decision to the existing
   byte-identical responses (403 `admin_ip_denied`, 429 `rate_limit_exceeded`
   / `admin_write_quota_exceeded` with `Retry-After`, 409
   `destructive_confirmation_required`, 401 `missing_token`/`invalid_token`/
   `session_expired` with `WWW-Authenticate: Bearer realm="admin"` — no change
   to any current response); the gRPC interceptor maps it to gRPC codes
   (`PermissionDenied`, `ResourceExhausted` with `retry-after`-style metadata,
   `FailedPrecondition`, `Unauthenticated`) plus the existing
   `EventAdminGRPCCalled` denial audit event with the denial reason. Denial
   events emitted by the shared gate use the already-classified
   `EventAdminIPDenied` / `EventAdminWriteQuotaExceeded` types (and rate-limit
   / destructive-confirm counterparts), which are defined in
   `auditspi/event_types_admin.go` but never recorded today.
3. Both transports consume the same `Middleware` fields; unconfigured gates
   remain byte-identical to today on both tracks (nil checks unchanged).
4. Keep the refactor inside existing files (`middleware.go` / `governance.go`)
   with logic moved out where needed to respect the 500-line budgets.

**Acceptance check**:

- New tests in `interfaces/admin` (`middleware_test.go` / `governance_test.go`):
   with `SetWriteQuota` / `SetDestructiveActions` / `SetIPAllowlist` /
   `SetRateLimit` configured, the same operation (e.g.
   `ClientAdminService/Delete` vs `DELETE /api/v1/admin/clients/{id}`) is
   refused on BOTH transports with equivalent outcomes (gRPC
   `PermissionDenied`/`ResourceExhausted`/`Unauthenticated` vs HTTP
   403/429/409/401), and allowed on both when the gate is unconfigured.
- A bufconn test drives a gRPC admin RPC with the destructive set matching it
  and `X-Confirm` absent: refused, and the denial is recorded
  (`EventAdminGRPCCalled` + `OutcomeFailure`) — the same evidence the
  interceptor already emits for scope denials.
- All existing `middleware_test.go` / `governance_test.go` HTTP expectations
  pass unchanged (responses byte-identical); `go test ./... -race` and
  `make ci` green.
