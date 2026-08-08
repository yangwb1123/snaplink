Requirements specification delivered: `docs/architect-analysis/cmd-sso-ctl-clientscmd-tenant-binding-wire-requirements.md` (314 lines).

## Verification summary

**Every cited symbol verified against the repository** — all content claims hold; three line numbers are stale:

| Citation | Measured | Verdict |
|---|---|---|
| `clients.go:21-38` (clientListItem, gap comment) | comment :65-72, struct :73-81; gap comment verbatim at :70-72 | Confirmed, line drift ~44 |
| `clients.proto:41-89` (Client, no tenant field) | `message Client` :70-84, fields 1-10, no reserved ranges → 11/12 free | Confirmed, line drift |
| `server_login_client.go:329` (`TenantID: client.TenantID`) | exact at :329 — but it's the **trust-signal** projection; the token-claim chain is `server_login.go:119` + 4 tokengrant stamps → `Subject.TenantID` → `issue_payload.go:46` → tag at `ed25519_types.go:50` | Confirmed, attribution corrected |
| `issue_payload.go:46`, `ed25519_types.go:47-52` | exact | Confirmed |
| `clients_test.go:34-73` (shape pin) | test at :45-95, fixture camelCase | Confirmed, line drift |
| `token.go:215-225` (`check --expect-tenant-id`) | :215-216 call, `verifyTenantID` :222-234, flag at check.go:118 | Confirmed |

**Key findings that shaped the spec:**
- `clientToProto` (admin_clients.go:394-415) is the single read-path mapper; the write-side overlay already prevents Update from wiping the binding (pinned by `TestClientAdminService_UpdatePreservesFieldsNotInAdminProto`)
- Gateway default marshaler (grpc-gateway v2.28.0) emits camelCase **with EmitUnpopulated** → `"tenantId":""`/`"grantTypes":[]` for unbound clients; `omitempty` on the CLI struct keeps output clean
- ADR-0008 Rule 1 permits additive v1 fields; `make ci` gates proto-lint and docs-validate (openapi `AdminClient` schema must gain the fields)
- `test/` cannot import `cmd/` and has no binary-spawn precedent → the direction's "proposed new test in test/" is split: wire-level equality cross-check in `test/` + faithful CLI-driving e2e in `cmd/sso-ctl/clientscmd` (real `runGet` + real `apiclient.CheckRun` against a real assembled server+gateway)

**Scope discipline:** R1-R7 stay within the direction — additive read-only proto fields 11/12, single mapper change, clientscmd decode/render (JSON + table), T-8a pin-test extension, and the two acceptance e2e legs (equality + anti-drift). Mutations explicitly closed (read-only wire fields), no token-claim/config/flag changes, other direction entries excluded. Acceptance checks preserved and made testable as 8 Given/When/Then cases.
