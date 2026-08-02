Spec written to `docs/auto/interfaces-admin-direction1-spec.md`. All evidence re-verified against code; one correction vs. the source analysis: `HandleAdminRotateSigningKey` does not exist — the real key-rotation symbol is `KeyAdminService.RotateSigningKey` (`interfaces/grpcserver/grpcadmin/admin_keys.go:74`), which the spec cites instead.

## The three improvements (each a `##` decision in the spec)

**1. Resource-qualified capability codes with handler-declared requirements**
- *Problem*: the whole authorization language is `admin:*`/`admin:read`/`admin:write` (`middleware.go:24-30`); `scopeForHTTP`/`scopeForGRPC` can only emit the two legacy values; 55 `HandleAdminX` handlers run with zero authz layering (per `deps.go:22-24`).
- *Key evidence found while digging*: `domains/permissions/matcher.go` `Matches` already expands `domain:*`, and the full resource catalog (`ResourceProvider.ResolveResource`, tenant-aware `Resource`) has **zero runtime callers** — `Permission.Resource` is round-tripped but never matched. The machinery exists; the gate just doesn't consume it.

**2. Tenant-scoped admin authorization**
- *Problem*: tenant is a quota-key hint (`tenantHintFromClaims`, sole caller `middleware.go:345`) and a fail-open host check (`tenantRequestMismatch`, `tenants.go:273-287`); `HasAdminScope` has no tenant parameter and the actor context carries only (userID, clientID).
- *Key evidence*: `Resource.TenantID` and tenant-aware `ResourceLookup` already exist in the data model; `core.TenantMembership`/`TenantRole` exist for the user surface but are never consulted by the admin gate.

**3. Role-aware delegation in governed flows**
- *Problem*: `TargetHoldsAdminScope` matches exactly `[admin:read, admin:write]` (`accessors_feature_gates.go:291-316`) — binary, and blind to resource-qualified grants; `ApproveAndApply`'s only constraint is `ErrChangeSelfApproval` ("approver must differ from proposer"), `ChangeRequest` has no role field.
- *Proposed fix*: subset-based impersonation floor (impersonator never gains capabilities they don't hold) + action_type → required-capability matrix for approvals, both reusing improvement 1's matcher.

Each decision carries concrete acceptance checks: oracle-safe denial matrices, gRPC/HTTP parity, `permissionstest.ConformanceSuite`, seeded-`sso-admin` compatibility regressions, and the mandatory gates. No code was modified.
