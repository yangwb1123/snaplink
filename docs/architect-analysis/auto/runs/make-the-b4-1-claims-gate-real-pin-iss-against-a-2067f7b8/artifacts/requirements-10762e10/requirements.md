Requirements spec complete: `docs/architect-analysis/cmd-sso-ctl-b4-1-claims-gate-requirements.md`.

## Verification verdicts (all direction citations re-checked against the repository)

**Confirmed (minor line drift):**
- `check.go:77-78` — opt-in `--expect-tenant-id`/`--expect-roles` flags, wired at 116-117
- `token.go:187-188, 215-228` — `iss == discovery issuer` is the only oracle; tenant_id/roles only when declared; the "cc-path mints never resolve Subject.Roles" diagnostic (line 228) is **structurally true** — `HandleClientCredentialsGrant` builds a Subject with no `Roles` and no `Claims`, so `--expect-roles` is a guaranteed-fail declaration (blind spot is stronger than stated)
- `server_discovery.go:251-256` — `resolveIssuer` falls back to `requestBaseURL`; discovery issuer is Host-derived in lockstep (`server_discovery_config.go:144, 264-265`); B4-1's "禁 Host 派生" clause (`docs/campaigns/implementation-gate.md` row 1) is unverifiable today
- `issue_payload.go:46` — `TenantID` stamped unconditionally; `claimsWithoutEmittedKeys` (116-131) dedup strip

**Corrected (material):**
1. **Cmd-default nuance**: `config/config_load.go:60,70-71` defaults `server.issuer` to `"sso-server"` (non-sentinel), so the *stock* deployment pins both discovery and minted iss to a literal; the Host-lockstep arises at the SDK level or under the regression. The probe's polarity holds either way (green on correct config, fails only under Host-derived mint) — captured in decision D1 with a regression-fixture test design.
2. **Device-leg premise refuted**: the device mint (`token_device.go:92-105`) never sets `Subject.Roles` — roles arrive via the approval-time attribute bag. The proposed leg's value is the *bag-carrying* path; the roles assertion must accept both claim shapes (D3, kept proposed).
3. **"Exactly once" restated**: the bag marshals under nested `ext`, so the assertion must be over the flattened view (top-level ∪ `ext`), not raw bytes (D2).
4. **`device_codes_test.go` citation weak** — it only tests the code generator; the grant is at `server_device.go`/`token_device.go`.

**Pre-existing failures reported separately (AGENTS.md §2.7):** the apiclient sweep is untracked WIP with 11 red tests; the dominant root cause is a harness defect (`newLiveServer` mints `iss="snaplink-sso"` ≠ discovery issuer) — repaired by the R5 fixture prerequisite; the trace_id/echo-drift rows are explicitly out of scope.

The three acceptance clauses are preserved as R1 (allowlist pin), R2 (Host-variance probe with verified pass/fail polarity), R3 (exactly-once), each with named, testable rows; R4 stays proposed; R5 is the harness prerequisite. No scope expansion: no server-side changes, no new endpoints, no device leg, exit-code contract unchanged.
