Verification complete — report written to `design_gate-6a76b0dd/task-1-design-gate.md`. **Verdict: PASS.** All five claims hold against the repository:

**1. No binding mutation path** — `protoToClient` and `applyProtoToExistingClient` (`admin_clients.go:417-460`) contain zero `TenantID`/`GrantTypes` consumption; the only occurrences in the file are comments. All write paths (Create/Update/Approve/RotateSecret) route through them or flip `Active` only. The overlay pin `TestClientAdminService_UpdatePreservesFieldsNotInAdminProto` seeds `TenantID: "tenant-acme"` and passes at HEAD. Binding is writable only via DCR (`handle_register*.go`), YAML, federation, store seed — never the admin wire.

**2. Claim path untouched** — `server_login.go:119` (Subject.TenantID), `issue_payload.go:46`, `ed25519_types.go:50` (`json:"tenant_id,omitempty"`), and all **8** grant stamps (authcode :136, cc :52, device :99, ciba :124, jwt_bearer :112, saml2_bearer :123, exchange :399, refresh :292 — in `internal/handler/tokengrant/`, not `server_login.go` as the spec implied) all read the stored core `client.TenantID`. `server_login_client.go:329` is confirmed as trust-signal input, not claim emission. Design's change set touches none of these.

**3. Oracle-safe responses unaffected** — `verifyTenantID` (token.go:227-235) three-way semantics (match / `tenant_id absent` / `"X" != "Y"`) intact; `rejectDisallowedGrantType` → `400 unauthorized_client` enforcement untouched; `tenant_mismatch` 403 sites read core state only. No new `Err*`, routes, or config keys — the AGENTS.md oracle table is structurally unreachable by this change.

**4. Admin-gated only** — all client RPCs ride `/api/v1/admin/clients*` gateway paths behind `AdminMiddleware` (GET `admin:read`, mutations `admin:write`, `Bearer realm="admin"`); List/Get emit no audit events (only the 6 mutations), so no new event type or exposure; secret stays write-only.

**5. E-2/E-6 consistent by construction** — both surfaces project the same stored field, so a mis-bound client shows identically on the admin wire and in the `--expect-tenant-id` sweep failure, with the named diagnostic leaking only the two tenant values.

**Two caveats flagged:** (a) a pre-existing, unrelated test failure at `check_test.go:1370` (introspect-probe formatting in untracked worktree content, no tenant involvement); (b) no direct unit test pins the `!=` mismatch diagnostic today — the design's E-6 real-deployment test is the right closure, keep it.
