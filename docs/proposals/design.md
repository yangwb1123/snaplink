Design doc written to `docs/auto/domains-userlifecycle-direction2-design.md`, following the `direction1-design.md` convention (verification record, numbered decisions, failure-mode table, risk list, test plan). Every spec claim was re-verified against the tree before writing — with three corrections found:

**Corrections to the spec (documented in the verification record):**
- `memory_test.go:88-89` is not a PURGED persistence fixture — it's `TestGet_ReturnsCopy` (copy isolation). The "PURGED persists forever" claim is proven structurally (no `Store.Delete`, terminal table), so the behavior stands but the evidence citation was wrong.
- The admin handler 404 check is at lines 28-31, not 22-25 (minor drift).
- **Direction 1 has not landed** (`AllowsAuthentication`/`rejectLifecycleBlockedUser` absent), so the acceptance-trigger ordering contract must compose under both orderings.

**Key design decisions:**
1. **Erase on purge** — the admin handler owns the erasure (only it can refuse-before-`Append` in fail-closed mode and surface the report in the response); `EraseOnPurge` remains the reference reaction for SDK embedders. Documented deviation: `cmd` does *not* register `OnUserPurged` on the bus — doing so would erase every purge twice. Handler-owned erasure also keeps fail-closed enforcement working with `audit.enabled: false` (stronger than direction 1's bus dependency).
2. **INVITED provisioning** — domain `SeedInvited`/`AcceptInvitation`/`Seeder`, admin seed form (knob-gated, with the existing 409/400 mapping), SCIM create hook via a new option (no new file in `protocols/scim` — frozen fan-out ceiling), auto-accept on first login pinned to run *before* direction 1's gate.
3. **Tombstone** — idempotent `Store.Delete`, delete rule `rep.Err()==nil && rep.UserDeleted` (the record outlives nothing but never misrepresents a surviving account), crash-window repair inside `SeedInvited`.

**Biggest risk (verified with line counts):** `interfaces/admin` is at its 10-file ceiling with every file 460-492 lines, and `interfaces/sso` is at its 60-file ceiling with nearly every file 488-500. The design mandates a new `interfaces/admin/lifecycle` subpackage and a concrete `interfaces/sso` shuffle (userlifecycle option cluster → `server_routes_admin.go`, helper → `server_login_resolve.go`), with a fallback if direction 1 has already consumed the headroom.
