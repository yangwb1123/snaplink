Specification written to `docs/architect-analysis/cmd-sso-ctl-legacysync-tenant-binding-gate-requirements.md`. All cited evidence was verified against HEAD:

**Verification results**

| Cited | Status |
|---|---|
| `target.go:166-180` `loadTargetClients` id-only select (line 167) | Verified |
| `target.go:182-215` `buildReport` existence-only check (185-189) | Verified |
| `target.go:116-131` syncReport no tenant field | **Corrected**: struct is in `model.go:104-114`; substance holds |
| `sqlite/clients.go:37-48` `tenant_id TEXT NOT NULL DEFAULT ''` (line 46, partial index 49-51) | Verified; binding resolves via `clients_scan.go:190` |
| `issue_payload.go:46` unconditional `TenantID` stamp; `:108-131` dedup | Verified (exact lines) |
| `server_token_clientauth.go:193` binding resolution | Verified; grants stamp `TenantID: client.TenantID` (`token_authcode.go:136`, `token_refresh.go:288`, `token_client_credentials.go:52`, et al.) |
| `testTargetSchema` lacks `tenant_id` (target_test.go:145-155) | Verified |
| "today exit 0" | Verified (`main.go:52-54, 67`) |

**Key spec decisions**
- REQ-1/2: `loadTargetClients` reads `tenant_id`; `buildReport` fails unbound mapped clients with a per-client diagnostic; mode-independent since `buildReport` runs before the `--apply` write branch — exit 1 in both modes via the existing `reportError` path, with no writes.
- REQ-3 (T-9): no `syncReport` field, `printReport` golden byte-identical; the per-client coverage line exists only in the violation diagnostic.
- REQ-5 (T-8a): `test/` integration on real `sqlitestores` (pattern of `auth_password_expiry_test.go`) asserting `tenant_id == "tenant-acme"` exactly once via raw-payload key count — the dedup guarantee of `claimsWithoutEmittedKeys`.
- Exit-code testability is discharged at the `buildReport` boundary (both mode args) plus the documented `run()` control flow; a `run()`-level test would require a fake MySQL source (`openLegacyDB` TCP ping, no seam) — flagged as out of scope rather than silently assumed.
- Budgets checked: `target.go` 403→~418 lines, `buildReport` 35→~43 lines, no new package files, no layer changes, no doc-contract updates needed (no new `Err*`/endpoint/config knob; `legacy-sync` is absent from config/feature docs).
