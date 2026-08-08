Both deliverables are in place. Here is the completion summary.

## Done. The evidence-backed requirements specification is complete.

### Deliverables
- **Pipeline artifact**: `docs/architect-analysis/auto/runs/input-harden-entity-id-interpolation-and-add-the-077a1671/artifacts/requirements-10762e10/requirements.md` (+ `requirements.md.meta.json` with sha256 fingerprint)
- **Canonical spec**: `docs/architect-analysis/auto/cmd-sso-ctl-entitiescmd-requirements.md` (replaces the now-shipped direction-1 spec)

### Verification summary — all 15 citations checked against the working tree

| Citation | Verdict |
|---|---|
| `tenants.go:135/174/198/223`, `users.go:145` unvalidated id interpolation | Verified exact; superset: `runUserUpdate` (:181) / `runUserDelete` (:205) splice identically — REQ-1 hardens all seven sites |
| `attrFlag` :88-98, `validateTenantStatus` :248 fail-fast patterns | Verified, line drift (:40-49 / :243) |
| `build_http.go:191-193` "`{id}` also catches `{id}:set-status`" | Verified + routing test pin (admin_gateway_routing_test.go:141) |
| ZERO `admin/tenants`/`admin/users` probes in the sweep | Verified by grep |
| `token.go:211-233` verifyClaims, `error-codes.md:298`, `issue_payload.go:46,83-87`, `RejectUnregistered`, `config_load.go:220` | All verified (path drift: `infrastructure/defaultimpl/issue_payload.go`) |

### New evidence produced (server half of the acceptance is verified behavior, not prose)
- Unknown-id set-status → `codes.NotFound "tenant not found"` (admin_tenants.go:328-330) → gateway 404 `{"code":5,"message":"tenant not found",...}`; **no introspection-wire suspension test exists anywhere** (test/tenant_suspension_test.go asserts `ValidateToken` only) — REQ-3's A11 is genuinely new coverage.
- Suspension gate lives inside `validateAnyToken` (server_token_clientauth.go:400) → introspect returns `{"active":false}` (introspect_cache.go:130-131), wired via `tenant.suspension_check.enabled`.
- Threat model made concrete: `?` truncation silently deletes/fetches a *different* real tenant; `/` reaches SSO-router-owned sub-surfaces (`tenants/{id}/usage`); `:` collides with the gateway custom-verb route.

### Two design decisions forced by evidence (documented, scope kept)
1. **T-8f is opt-in** (`--admin-entities`, requires `SSO_ADMIN_TOKEN`): sweep tests clear the token env and golden runs assert `check OK` — a default-on group would break every token-less run and the existing suite.
2. **Suspension leg uses the operator's minted token** (admin API cannot tenant-bind clients — `tenant_id` read-only) and warns before the flip: real suspension irrevocably revokes the tenant's refresh tokens/sessions; probe always restores.

Acceptance preserved verbatim in §3, mapped to testable criteria A1–A13. Pre-existing failures (apiclient `TestIntrospect_Non401Fails` trace_id fixture issue; `check` dispatch gap in main.go) re-verified and reported separately, untouched.
