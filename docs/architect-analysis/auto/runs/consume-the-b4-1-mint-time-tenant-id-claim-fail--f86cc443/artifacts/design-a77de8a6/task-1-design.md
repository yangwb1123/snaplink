Design complete. Every evidence citation in the requirements spec was re-verified against HEAD — all confirmed, with three load-bearing nuances the spec glossed over — and the concrete design is at `docs/architect-analysis/cmd-snaplink-billing-tenant-claim-design.md`.

## Verification verdict

All cited symbols confirmed line-exact: `issue_payload.go:46,86-87` (mint stamping), `rs/claims.go` (no projection, `serving_region` precedent with the "Runs LAST" gate), `app.go:220-222`, `auth.go:159,180-193`, `quota_relay.go:434-453` (485/500 lines), `http_client.go:102,143`, `README.md:170-172`, `oauth_token_source.go:44-46`, `error-codes.md:137,1014`. One additional confirmation: `token_client_credentials.go` stamps `TenantID: client.TenantID` — the claim is the IdP-side client binding, which drives the biggest compatibility constraint below.

**Nuances the spec missed** (resolved in the design):
1. `Resolve` never returns `(nil, nil)` — unknown client is `ErrSourceBindingUnauthorized`, so the "no binding ⇒ no gate" carve-out is an error branch and applies **only to admin routes** (payment/metering already deny unbound clients).
2. Metering's existing binding denial is `metering_source_unauthorized` — a distinct class. The drift denial must use the **scope-denial shape** to satisfy byte-identical no-oracle.
3. A shared multi-tenant relay client **cannot survive** the T-8(e) cross-check: its token always carries one IdP-bound tenant (or no claim at all → everything pauses). Migration requires per-tenant relay clients; the README quota section must be updated alongside R5.1.

## Design highlights

- **R1**: `rs.Claims.TenantID/Roles` + `HasTenantID()` — additive projection via the existing `wireClaims`/embedded `wireIntrospection`, zero config, 8 rs test files untouched (A1).
- **R2**: one comparison per family where the binding is already held (payment `payment_ingest.go`, metering `authorize` after resolve); admin gate gains a `tenantResolver` interface threaded through `newAdminContractRouter` + an extracted `adminTenantBindingMatches` helper, with a new explicit **fail-open-on-store-outage** decision (A11) and the metering matrix (A12) as design additions.
- **R3**: `verifyBearerTenant`/`jwsPayload` in `http_client.go` (not `quota_relay.go` — 485/500), returning the existing `ErrAuthorizationRejected` → `reasonAuthorization` bounded retry, event retained; e2e drives the production `HTTPClient`.
- **API changes**: Go-internal only — two additive `Claims` fields + one method, one unexported relay check, two internal signature changes. No wire/config/OpenAPI/`Err*`/audit changes.
- **Failure modes F1–F8** incl. the pre-B4-1 fleet hazard (always-on gate, no kill switch — sequencing is the migration), stale-cache TTL window, and the no-oracle pins.
- **Migration**: R1 ships standalone → IdP mint live (G5 slot) → pre-flight per-tenant relay client registration → R2+R3+R4+R5 in one change → verification → revert-only rollback (outbox retained, zero data loss).
- **Acceptance mapping**: A1–A12 table tying every requirement acceptance to a concrete test file and seam.
