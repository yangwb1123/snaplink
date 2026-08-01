Spec written to `docs/auto/domains-permissions-spec.md`. All evidence claims were independently re-verified against the tree before writing:

**Verified evidence**
- `ResourceProvider`/`ResolveResource`/`RegisterResource` — grep across all `*.go` returns zero consumers outside `domains/permissions/`; `sqlite.go:18-21` doc admits resources "NOT covered"; `authz.go` `Check` does flat `permissions.Matches` only; `memory.go:283` emits `Permission{Code: code}` with `Resource` never populated while `authz.proto` already reserves the wire field; `rar.go` shape-checks RFC 9396 details but never validates them.
- `ActiveRoles`/`SessionRoleActivator` — zero consumers outside the package; `permissionstest/sod_conformance.go` self-admits gaps via `t.Skip` on type-asserts; admin proto has only 8 role/assignment/menu RPCs; `docs/feature-matrix.md` and `docs/error-codes.md` have no SoD entries.
- `authz.go` `Check` has no audit event and no `sso_authz_*` metrics anywhere; `RecordQuery`/`EventPermissionQuery` (`aliases_spi.go:162`) covers only `/me/*`; `PolicyBundle` carries only roles + wildcard semantics, and `server_health.go:40` calls it "the role-definition half"; `invalidateAuthzPolicy` plumbing already exists.

**The 3 improvements (each `##` section: problem → evidence → proposed behavior → acceptance check)**
1. **Wire the resource catalog into an enforcement point** — conformance suite + durable sqlite/redis/postgres backends, admin gRPC/REST management, resource-aware authz `Check`, RAR validation against the catalog.
2. **Make SoD operable end-to-end** — admin RPCs for conflict sets/session activation, durable SSoD/DSoD tables, `Check` consumption of `ActiveRoles` keyed by OIDC `sid`, error-code/feature-matrix sync.
3. **Decision-plane observability + complete policy export** — `EventPermissionCheck` audit + `sso_authz_checks_total` counters, `PolicyBundle` v2 with resources/SoD sets (ETag-preserving), OPA reference-policy conformance to prevent sidecar drift.

Docs-only change — no Go gates triggered.
