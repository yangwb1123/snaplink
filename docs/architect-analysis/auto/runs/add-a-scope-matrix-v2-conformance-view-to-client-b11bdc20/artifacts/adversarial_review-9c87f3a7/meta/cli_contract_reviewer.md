Verification complete — no edits made. All evidence below measured against HEAD (`3223d12a`); `cmd/sso-ctl/clientscmd` and `configcmd` suites are green at HEAD.

## 1. Exit-code contract: verified, no drift

| Convention | Measured in `clientscmd` | Sibling corroboration |
|---|---|---|
| Usage errors → 2 | `Run` no-args/unknown-subcommand → 2 (`clients.go:32,45`); `runGet` missing client-id → 2 + usage (`clients.go:153-155`); `runList` flag-parse error → 2 (`clients.go:61`) | `configcmd`, `sessionscmd`, `tokenscmd`, `entitiescmd` all return 2 on misuse; `main.go` exits 2 for no-args/unknown; `apiclient/check.go:13` documents "2 CLI misuse" |
| Operational/HTTP errors → 1 with `progName:` prefix | `sso-ctl clients: get failed (HTTP %d): ...` (`clients.go:170`), `list failed:` (`clients.go:135,144`), `parse response:` (`clients.go:96,175`) | Identical shape in `sessionscmd` (`revoke failed (HTTP %d)`), `tokenscmd`, `entitiescmd` (`get failed (HTTP %d)`), `configcmd` (`invalid config:`) |
| Unknown client → HTTP 404 → exit 1 | `grpcadmin` GetClient returns `codes.NotFound` (`admin_clients.go:208`; pinned by `admin_clients_test.go` NotFound tests) → gateway 404 → `runGet` non-200 branch → exit 1 | n/a |

**Mapping check (explicit ask):** the deliverable maps unknown client → **1** (R1.3, FM-2, U6), not 2 — exactly the `get` family. No drift found anywhere in R1's contract: 0 = pass (stdout `validate: OK`), 1 = conformance/fetch/parse/construction failure, 2 = usage. This is byte-for-byte the `config validate` contract (`configcmd`: usage 2, `invalid config:` → 1, stdout `config OK:` on pass) and `check`'s documented 0/1/2.

## 2. stderr-only offender output: consistent

Every sibling routes diagnostics to `os.Stderr` and payload/pass signals to stdout (`config OK: <file>`, `check OK`, `check FAIL`). The proposed `validate: OK` on stdout + offenders on stderr matches. Pass-signal wording also matches the module's "OK" idiom.

## 3. Dispatch-arm + usage-line edit cannot perturb list/get byte-identity: confirmed

- The switch arm is additive; `runList`/`runGet`/`printClients`/`clientListItem`/`fetchList` are untouched per R5.
- **No test anywhere invokes `clientscmd.Run` with `list`/`get`** — the three list pins (`TestRunList_DecodesGatewayCamelCaseShape`, `TableFormat`, `UnboundClientOmitsReadOnlyKeys`) and E-4 call `runList`/`runGet` directly; `rg usage(` in clientscmd tests → 0 hits, so the usage-line addition is unpinned; `dispatch_test.go` pins only main's `subcommands` map, which the spec explicitly leaves unchanged.
- The only consumers of `clientscmd.Run` are `main.go:50` and the new `validate` tests.

## 4. `validate` verb/naming: consistent

- `validate` is an established toolbelt verb: `sso-ctl config validate` (offline conformance gate, same 0/1/2). Usage-line format `sso-ctl clients validate <client-id>` mirrors `sso-ctl clients get <client-id>`. No name collision in the `Run` switch (only list/get/help).
- `main.go`'s `clients` one-liner ("List OAuth clients or inspect a specific client.") won't mention validate — acceptable: `config`'s one-liner also omits its `schema`/`validate-schema` subcommands (summaries, not enumerations).

## Findings to flag

- **F1 — deliverable §7 env-var error (factual).** The Credentials row says `SSO_ADMIN_TOKEN` + `SSO_ADDR`; the actual env is `SSO_ADMIN_ADDR` (`apiclient.go:27`; no `SSO_ADDR` exists anywhere in the repo). R1.2's "same env credentials as list/get" is correct — fix the §7 table, since U-tests will set these vars.
- **F2 — offender-line shape (cosmetic, but pinned by U4/U5/E1a).** Proposed `sso-ctl clients: validate: scope "..."` nests the verb after the colon; the module idiom is `progName: <verb> failed: ...` (`get failed (HTTP 404)`, `revoke failed`, `invalid config:`). `progName:` prefix contract is preserved either way, but `validate failed: scope "..." is not in the built-in scope matrix` is the more idiomatic form — decide before the tests pin it.
- **F3 — pre-existing, unrelated failures at HEAD (report per AGENTS.md §2).** `sso-ctl check` is **not registered** in `main.go`'s `subcommands` map and absent from its usage — `TestSubcommands_CheckIsWired` fails at HEAD; `cmd/sso-ctl/apiclient` also fails at HEAD (`TestCheck_AddrValidation` usage-text drift, `TestSweep_GreenPath` issuer mismatch, `TestIntrospect_Non401Fails` message drift). Impact on the deliverable: FM-5/FM-7's operator guidance ("gate with `sso-ctl check`") names a CLI surface that is currently unreachable from the binary; E3 itself drives `apiclient.CheckRun` in-process (like E-5/E-6), so the test is unaffected — but the spec should note the dispatch gap rather than assume `sso-ctl check` exists.
- **F4 — evidence-table arithmetic nit.** "8 structural aliases (commerce ×5…)" mislabels the breakdown: the commerce const block has 5 consts, 2 of which are admin (`ScopeAdminRead/Write`); actual split is admin×2 + commerce×3 + metering×2 + wildcard×1 = 8, + audit literal. Cosmetic; the 9-row `Matrix()` claim itself is exact.
- **F5 — U7b parsing style note.** Unknown-flag → 2 via `FlagSet` mirrors `list`/`check`, not `get` (which has no FlagSet and would treat `--nope` as a client-id → 404 → 1). Deliberate and fine; worth one sentence in R1.1 naming which sibling it mirrors.

**Verdict:** the 0/1/2 contract, stderr-only output, unknown-client→1 mapping, dispatch-arm byte-identity, and `validate` naming all conform to established convention; F1 (env var name) is the only substantive error to fix in the deliverable before implementation.
