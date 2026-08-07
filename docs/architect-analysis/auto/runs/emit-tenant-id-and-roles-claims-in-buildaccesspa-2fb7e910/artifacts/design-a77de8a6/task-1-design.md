Design artifact complete and all evidence verified. Final summary:

## Verification results (evidence treated as untrusted)

All 7 citations confirmed against HEAD — 6 exact (including line numbers), 1 with the self-flagged drift (`KeyRoles` at `consts_wire.go:277`, not 267). All bonus findings confirmed, plus three new constraints found during verification:

1. **`server_finish_login.go`, `server_login_client.go` are at exactly 500 lines** and `server_helpers.go` at 498 — no additions may land in them. The mint wiring and new helper must go in `server_login.go` (469 → ~492) and the policy-seam refactor is net-zero.
2. **ID tokens can't leak the claims structurally** — `ed25519IDPayload`/`ed25519LogoutPayload` are separate structs.
3. **`TokenClaims`/`Validate()` would drop the new claims** — `claimsFromPayload` (validate_claims.go) maps enumerated fields only; extending it is an explicit non-goal since R5 excludes introspection/openapi changes.

## Design (written to `artifacts/design-a77de8a6/task-1-design.md`)

- **API changes**: `core.Subject.Roles []string` (alias-picked-up by `sso.Subject`); `ed25519Payload.TenantID`/`Roles` with `tenant_id`/`roles` omitempty tags matching `KeyTenantID`/`KeyRoles`; projection via the two existing house disciplines (ServingRegion unconditional-literal for `tenant_id`, AMR guard+copy for `roles`); shared fail-open `subjectRoles` helper extracted from the policy seam and wired into `mintAccessToken` (roles keyed on `result.UserID`, never the pairwise pseudonym); feature-matrix row per the `sid` precedent.
- **Compatibility**: byte-identical single-tenant output; token-endpoint grants deliberately leave `roles` empty (documented semantic asymmetry: code-flow tokens won't carry `roles`); policy-seam refactor behavior-preserving (same log string, same metric, same value).
- **Failure modes**: all fail-open with logging (store outage, no membership, no store, tenant-less client, JIT ordering preserved since `ensureJITMembership` runs at server_finish_login.go:47 before the mint).
- **Acceptance mapping**: T-2 decomposed into AC-1..AC-7 — per-issuer `tenant_id`/`roles` tests, `strings.Count(header, "kid") == 1`, golden claim-set byte-identity (modulo crypto/rand `jti`, fixed `With*Clock`), server-level login test with seeded `MemoryTenantUserStore`, and a tag-vs-const coupling guard.
- **Migration**: no data/config migration; single commit with per-step green builds; rollback is a revert with no state to unwind.

No code changes were made — this is a design-stage artifact only; the baseline `go build ./...` remains green.
