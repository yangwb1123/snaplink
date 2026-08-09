Design document written to `docs/architect-analysis/cmd-sso-ctl-legacysync-tenant-binding-gate-design.md`. Summary of the verification and design:

## Evidence verification verdict

All 8 cited claims verified against HEAD — **2 minor drifts, no substance invalidated**:

| Claim | Verdict |
|---|---|
| `loadTargetClients` id-only select (`target.go:167`) | ✅ `SELECT id FROM clients WHERE active=1` |
| `buildReport` existence-only check (`target.go:185-189`) | ✅ "does not exist or is inactive" is the only gate |
| `syncReport` no tenant field | ✅ Self-corrected to `model.go:104-114`; confirmed |
| `clients.tenant_id NOT NULL DEFAULT ''` (`clients.go:46`), partial index 49-51, `clients_scan.go:190` | ✅ Exact |
| `issue_payload.go:46` unconditional stamp; dedup at `claimsWithoutEmittedKeys` (116-131) | ✅ Exact |
| `server_token_clientauth.go:193` binding resolution | ⚠️ **Drift**: line 193 is the function decl; the `clientTenantOK` gate is at 218-221. Grant stamps confirmed (`token_authcode.go:136` ✅, `token_refresh.go:292` vs cited 288, `token_client_credentials.go:52` ✅, plus device/ciba/jwt-bearer/saml2/exchange) |
| `testTargetSchema` lacks `tenant_id` (`target_test.go:145-155`) | ✅ Confirmed |
| "today exit 0" | ✅ `buildReport` at 52-54 precedes the write branch (56-59); `return 0` at 67 |

Also verified: `KeyTenantID` at `consts_wire.go:169`, no doc-contract updates needed (legacy-sync absent from all 4 contract docs), no MySQL seam in `openLegacyDB`, harness patterns exist, budgets hold (target.go 403→~416, buildReport 34→~44).

## Design essentials

- **API changes**: none exported. `targetSnapshot.Clients` → `map[string]string` (3 touch sites, all in target.go); `loadTargetClients` selects `id, COALESCE(tenant_id,'')` (NULL ≡ unbound); `buildReport` aggregates unbound **mapped** clients into a sorted `errors.Join` — one per-client line, both modes exit 1 before any write.
- **Compatibility**: real deployments always have the column (v1 migration); hand-made targets/fixtures must add it — missing column now fails loudly (documented, not papered over). Unmapped unbound clients pass; `' '` counts as bound (exact-match, server semantics).
- **Failure modes**: 9 enumerated (unbound, NULL, multi-client, missing column, inactive client, unmapped, empty app map, whitespace) — no new oracle surface.
- **Migration**: operational only — `UPDATE clients SET tenant_id=...` for mapped clients, dry-run loop until exit 0; rollback = revert two files.
- **Acceptance mapping**: 7 unit tests (U1-U7) + 2 integration tests (I1/I2 via real `sqlitestores` + `/auth/login` mint, `strings.Count(payload, "\"tenant_id\":") == 1` with `"tenant-acme"`), mapped to T-8a/T-9/REQ-1..5.

No `.go` files were touched, so no build gates were triggered — this deliverable is documentation-only.
