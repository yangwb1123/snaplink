The design doc is written to `docs/design/permissions-resource-catalog-wiring.md`. All claims were verified against the tree before writing. Summary of the design:

**## 1 — Resource-aware `Check`**
- Additive `CheckRequest` fields 4–6 (`resource_type`, `tenant_id`, `attributes` map) per ADR-0008; presence = non-empty `resource_type` (safe: `Resource.Validate()` rejects empty types).
- One exported `CheckResource(rp, lookup, perms, want)` in the domain, placed in the **existing** `resources.go` — the package root is exactly at its 10-file ceiling, contradicting the requirement's "not at ceilings" claim.
- Decision table: `Found=false` → flat `Matches` fallback (spec-mandated, byte-identical); `Found=true` → `RequiresAuth` gate, then per-`RequireMode` projection via `EffectiveRequireMode()`. Lookup against a non-`ResourceProvider` backend fails closed with `FailedPrecondition`.

**## 2 — Durable catalog + conformance**
- Migration v2 `permissions_resources` (unique tuple, JSON-as-TEXT columns, RFC3339 timestamps) with provider-maintained dispatch columns. `http_api` uses a `(method, segments)` narrowing index + Go `matchPath` — exact keys are unsound for `:param` wildcards; all other types get exact `dispatch_key` hits.
- Upsert semantics via tx + owner SELECT (avoids `RowsAffected` ambiguity), matching the memory peer's check-then-write under lock.
- `ResourceConformanceSuite` with an honest `SkipReason` mechanism; zero skips for memory + sqlite.

**## 3 — Admin CRUD + RAR enforcement**
- Four additive RPCs; implementations go into the **existing** `admin_permissions.go` (`grpcadmin/` is also exactly at its 10-file ceiling — second contradiction with the requirement). Error mapping, audit events (classified in `auditreport`), and `invalidateAuthzPolicy` on register/delete.
- PAR gate: `security.rar_catalog_check.enabled` knob → `PARDeps.ResourceCatalog()` accessor (only implementer is `*sso.Server` plus one test fake); enforcement via `ValidateAuthorizationDetailsCatalog` in `oauthvalidate` using `client.TenantID`/`client.ID` scoping, fail-closed on unknown elements, shape-only when unconfigured.

**Failure modes & breakage risks** include the `Found=false` allow-inversion window (spec-mandated, flagged for a follow-up knob), `RequiresAuth` being unverifiable at `Check` (no auth-state input), rolling-deploy skew, `gen/` drift, migration-version pins in `schema_guard_test.go` (must verify), PAR-only enforcement gap vs `/auth/login`, and the still-dead `Permission.Resource` wire field.
