All verification complete. The resolution is written to `docs/architect-analysis/auto/runs/emit-tenant-id-and-roles-claims-in-buildaccesspa-2fb7e910/artifacts/design-a77de8a6/task-1-design-resolution.md` (216 lines). No Go code changed — this is a design-stage amendment; the pre-existing worktree modifications are the campaign's own and were left untouched.

## Resolution summary

**1. Collision ground truth (all re-verified at HEAD `718345d6`)**
- `tenantHintFromClaims` (governance.go:478-483) consumes `claims.Extra[KeyTenantID]` — the **`ext` map's** `tenant_id` — as an admin write-quota hint (`QuotaKey`: `"tenant:"+hint`, documented fallback `"admin:"+actorID`).
- `ext` = `subject.Claims` (issue_payload.go:34), the authenticator attribute bag at every grant. Core writes no `tenant_id`/`roles` attributes today, but the bag is open and extensible (Kerberos doc.go:75 documents mapping into a `"roles"` attribute), so the collision is reachable — **for both new claim names**, not just `tenant_id`.
- The new top-level claims are invisible to `tenantHintFromClaims` (`claimsFromPayload` enumerates fields; TokenClaims unchanged per the R5 non-goal), so "consumer prefers the literal" is unavailable — the collision must be prevented at emission.

**2. Precedence-or-strip rule (defined)**: the mint-time client binding wins; whenever a top-level claim is emitted (`TenantID != ""` → `tenant_id`; `len(Roles) > 0` → `roles`), the same-named `ext` key is stripped via a copying helper (`claimsWithoutEmittedKeys`, keyed on `core.KeyTenantID`/`KeyRoles`, never literals). Deterministic regardless of value equality; never mutates the caller-owned map (shared with `st.claims.Extra`, authenticator attribute maps). When no top-level claim is emitted, `ext` passes through untouched → single-tenant/global-admin output stays byte-identical and the quota hint survives. Documented consequence: tenant-bound admin tokens fall back to the admin-identity quota bucket (a budget dimension, not authz).

**3. Semantics (verified sound, no change)**: `tenant_mismatch` (`tenant.ClientOK` vs request-context tenant) and suspension (`WithTenantSuspensionCheck`, fail-open on outage) treat the claim as mint-time client-binding evidence like `serving_region` — no new oracle.

**4. Token-exchange (contract pin)**: `tokExSubject` (:399) stamps the **exchanging** client's binding (guest tenant on cross-tenant hops, which are fail-closed gated separately); contract wording pinned to "the OAuth client's tenant binding at mint time," matching `serving_region`'s mint-time discipline.

**5. Collision AC (AC-8a..f)**: per-issuer decode assertions for strip-on-conflict, strip-on-equality, single-tenant passthrough, no-side-effect guard, the roles variant, and a direct helper unit test (no-op returns original map identity — no allocation on the hot path).

**6. Code-comment drift (same-change pins)**: `types_token.go:226-231` doc rewritten (the "NOT a token claim" sentence is false after the change); `consts_wire.go:275-277` gets a **net-zero in-place** comment amendment noting `KeyRoles`' dual JWT-claim role (file is at exactly 500 lines — no additions, no move, since it is not an introspection key); `ed25519_types.go` field comments state the strip rule. Budget check: issue_payload.go 201→~216, types_token.go 284→~290, ed25519_types.go 162→~170, consts_wire.go stays 500.

Carried forward from the review pass (unchanged): per-issuer AC-4/AC-5, error-injecting store stub, pairwise-keying AC-6 variant, and the `s.metrics` nil-guard in the extracted `subjectRoles` helper.
