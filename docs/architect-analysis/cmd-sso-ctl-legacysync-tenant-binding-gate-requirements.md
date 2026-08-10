# Requirements: tenant-binding gate on mapped clients (cmd/sso-ctl/legacysync)

Source direction (B4-1 / T-8a `tenant_id` claim):

> Tenant-binding gate on mapped clients: read tenant_id from the target
> clients table and fail the plan when a mapped client has no tenant binding.

This document verifies every cited file/symbol, states the requirements in
testable form, and preserves the supplied acceptance checks unchanged.

## 1. Goal and user outcome

`legacy-sync` is the deployment path for offline SQLite targets. B4-1 (the
IdP half of the G1 trust-path gate; `docs/campaigns/implementation-gate.md`
row 1, `docs/campaigns/campaign-snaplink-b4.yaml` lines 4/59) requires every
minted token to carry the `tenant_id` claim stamped from the client binding.
The mint side is already implemented and unconditional
(`infrastructure/defaultimpl/issue_payload.go:46`); the sync tool, however,
never inspects the binding, so it can produce a deployment whose mapped
clients are tenant-less and whose tokens silently omit the mandatory
`tenant_id` claim.

Completion: `legacy-sync` dry-run and `--apply` refuse (exit 1, naming the
offending client id) a plan that maps a client with an empty tenant binding;
with all mapped clients bound, output is byte-identical to today; an
integration assertion proves a minted token for an imported user carries
`tenant_id` exactly once.

## 2. Evidence verification (every cited symbol checked against HEAD)

| Cited evidence | Verified status | Note |
|---|---|---|
| `cmd/sso-ctl/legacysync/target.go:166-180` — `loadTargetClients` selects only `id` | VERIFIED | `SELECT id FROM clients WHERE active=1` at line 167; `targetSnapshot.Clients` is `map[string]struct{}` (target.go:29), no binding carried |
| `cmd/sso-ctl/legacysync/target.go:182-215` — `buildReport` mapped-client check is existence-only | VERIFIED | Lines 185-189: fails only with `mapped target client %q does not exist or is inactive`; no tenant check |
| `cmd/sso-ctl/legacysync/target.go:116-131` — `syncReport` has no tenant field | CORRECTED LOCATION | `syncReport` is defined in `model.go:104-114`; substance verified — the struct (Source, Create/Update/DeactivateUsers, Credentials, Roles, Assignments, Mode) has no tenant-coverage signal. The cited target.go lines are inside `loadTargetAssignments` |
| `infrastructure/defaultimpl/sqlite/clients.go:37-48` — `clients.tenant_id TEXT NOT NULL DEFAULT ''` | VERIFIED | Column at line 46 inside the Version-1 migration block (lines 36-52); partial index `idx_clients_tenant ... WHERE tenant_id <> ''` at lines 49-51. Binding resolves into `sso.Client.TenantID` via `clients_scan.go:190`; `clientSelectAll()` includes `tenant_id` (clients.go:433-449) |
| `infrastructure/defaultimpl/issue_payload.go:46` — `TenantID: subject.TenantID` unconditional | VERIFIED | Exact line; comment confirms the mint-time binding is stamped unconditionally and `omitempty` handles the empty case |
| `infrastructure/defaultimpl/issue_payload.go:108-131` — `claimsWithoutEmittedKeys` dedup | VERIFIED | `stripTenant := subject.TenantID != ""` at line 117; `tenant_id` removed from the attribute-bag copy at lines 122-131, so the claim appears exactly once |
| `interfaces/sso/server_token_clientauth.go:193` — client binding resolution at `/token` | VERIFIED | `authenticateTokenClient` starts at line 193; the binding is resolved via `clientStore.Get` (lines 204-206) and tenant-gated by `clientTenantOK` (line 209). Grant handlers then stamp `TenantID: client.TenantID`: `internal/handler/tokengrant/token_authcode.go:136`, `token_refresh.go:288`, `token_client_credentials.go:52`, `token_device.go:99`, `token_ciba.go:124`, `token_jwt_bearer.go:108`, `token_saml2_bearer.go:119`; login mint at `interfaces/sso/server_login.go:114` |
| `target_test.go` `testTargetSchema` clients table lacks `tenant_id` | VERIFIED | `target_test.go:145-155`: `CREATE TABLE clients(id TEXT PRIMARY KEY,active INTEGER NOT NULL DEFAULT 1);`; seed inserts only `(id,active)` (target_test.go:67) |
| Exit-code claim "today exit 0" | VERIFIED | `main.go:52-54` (`buildReport` error → `reportError` → return 1) is the only failure path; with no tenant check the unbound-client plan reaches `printReport` and returns 0 (main.go:67) |
| Claim key | VERIFIED | `shared/core/consts_wire.go:169`: `KeyTenantID = "tenant_id"` |

Consequence chain (all links verified): the SQLite clients table stores the
binding (`clients.go:46`) → the store resolves it (`clients_scan.go:190`) →
`/token` resolves the client (`server_token_clientauth.go:204`) → grants stamp
`Subject.TenantID` (`token_authcode.go:136` et al.) → `buildAccessPayload`
emits it unconditionally (`issue_payload.go:46`) and dedups the attribute bag
(`issue_payload.go:108-131`). The single gap is the sync tool: it never reads
`tenant_id` (`target.go:167`), so an empty binding passes silently and the
offline deployment mints tokens without the mandatory claim.

## 3. Product boundary

- Surface: `sso-ctl legacy-sync` CLI (`cmd/sso-ctl/legacysync`); read-only gate
  over the target SQLite database. No server, SDK, or wire-surface change.
- Default: the gate is unconditional (matches the mandatory T-8a claim); no
  opt-in flag. An empty binding is always a plan failure.
- Explicit non-goals (do not expand scope):
  - No change to mint-side behavior: `issue_payload.go`,
    `claimsWithoutEmittedKeys`, grant handlers, `interfaces/sso` are
    do-not-modify.
  - No new `syncReport` field, no new `printReport` line in the success path
    (T-9 byte-identical report).
  - No storage migration: the real schema already has `tenant_id`; only the
    test fixture schema (`testTargetSchema`) changes.
  - No scope-registry gate, no audit/outbox rows, no source-TLS change (these
    are separate directions in the source analysis).
  - No run()-level MySQL harness: `run()` requires a live legacy MySQL source
    (`source.go:43-66` `openLegacyDB` TCP ping) with no injection seam;
    building a fake source would expand scope. The exit-code acceptance is
    discharged at the `buildReport` boundary plus the documented `run()`
    control flow (§6).

## 4. Requirements

### REQ-1 — snapshot carries the tenant binding

`loadTargetClients` selects `tenant_id` alongside `id`
(`SELECT id,tenant_id FROM clients WHERE active=1`) and
`targetSnapshot` retains, per active client, its binding. Representation is
the implementer's choice (e.g. `Clients` becomes `map[string]string` id →
tenant_id, or a parallel map); the empty-binding semantics in REQ-2 must
treat both SQL `NULL` and `''` as unbound (the real schema is
`NOT NULL DEFAULT ''`, so `''` is the operative case; `NULL` only occurs in
hand-made schemas).

### REQ-2 — mapped clients without a tenant binding fail the plan

In `buildReport`, after the existing existence/inactivity check
(target.go:185-189), every mapped client whose binding is empty fails the
plan with an error naming that client id, one per-client line per offending
client (the "per-client tenant coverage line" appears only when a violation
exists). The check is mode-independent: `buildReport` is invoked before the
`cfg.Apply` write branch (`main.go:52-56`), so dry-run and `--apply` behave
identically — both exit 1 via `reportError` (main.go:65-67) with no write
performed, and no report printed to stdout.

Proposed error shape (implementer may reword, must keep per-client naming):

```text
sso-ctl legacy-sync: mapped target client "web" has no tenant binding (tenant_id empty)
```

### REQ-3 — success path is byte-identical (T-9)

With every mapped client tenant-bound: exit 0, `syncReport` gains no field,
`printReport` output is byte-for-byte the current two-line format
(`main.go:70-78`). The inactive/missing mapped-client error text is unchanged.

### REQ-4 — unit tests (cmd/sso-ctl/legacysync)

- `testTargetSchema` (target_test.go:145-155): the `clients` table gains
  `tenant_id TEXT NOT NULL DEFAULT ''` mirroring the real schema; the seed
  (`seedTarget`, target_test.go:67) binds `sverp-web` to a non-empty tenant.
- The two existing tests (`TestApplyPlanPreservesNativeAuthorizationAndMenus`,
  `TestBuildReportRejectsNativeUserCollision`) keep their names and final
  assertions unchanged; only fixtures gain the column/value.
- New tests:
  - unbound mapped client (`tenant_id=''`) → `buildReport` error containing
    the client id, for both `"dry-run"` and `"applied"` mode arguments;
  - bound mapped client → `buildReport` succeeds;
  - multiple unbound mapped clients → every offending id is named;
  - `printReport` golden: for a passing plan the stdout bytes equal the
    current two-line format (byte-identical pin).

### REQ-5 — integration assertion in test/ (T-8a)

New `test/` (package `ssotest`) test, following the established sqlite-backed
deployment pattern (`test/auth_password_expiry_test.go`,
`test/client_tenant_binding_test.go`, `test/refresh_rotation_claims_test.go`):

- Precondition: a target SQLite deployment in exactly the shape
  `legacy-sync --apply` produces — `clients` row active with
  `tenant_id='tenant-acme'`, `users` row provider `sv_sso` (imported user),
  `password_credentials` row with a bcrypt hash — wired through the real
  `sqlitestores` (`NewClientStore`, `NewPasswordCredentialStore`) plus
  `MemoryUserProvider`, the password authenticator, and an Ed25519 JWT
  issuer.
- Mint: `POST /auth/login` with the imported user's credentials against the
  tenant-bound client (`mintAccessToken`, `server_login.go:114`, same
  unconditional stamp at `issue_payload.go:46` as `/token` grants).
- Assert: the access token payload (decode per `test/auth_code_test.go:253`
  `jwtAllClaims`) contains the `tenant_id` key exactly once —
  `strings.Count(payloadJSON, "\"tenant_id\":") == 1` — with value
  `"tenant-acme"` (exactly-once is the dedup guarantee of
  `claimsWithoutEmittedKeys`, issue_payload.go:108-131).

## 5. Acceptance criteria (preserved, with testable form)

1. **T-8a (positive):** given a target client with `tenant_id='tenant-acme'`,
   after legacy-sync apply a minted token for an imported user carries
   `tenant_id == 'tenant-acme'` exactly once.
   Testable form: REQ-5 integration test in `test/`; the exactly-once
   assertion is the raw-payload key count, the value assertion is the decoded
   claim.
2. **T-8a (negative):** given a mapped client whose `tenant_id` is `''` or
   absent, legacy-sync dry-run and `--apply` exit 1 naming the client id
   (today exit 0).
   Testable form: REQ-4 unit test calls `buildReport(plan, target, "dry-run")`
   and `buildReport(plan, target, "applied")` and asserts the error names the
   client id; the exit-1 path for both modes follows from the unchanged
   `run()` control flow (main.go:52-54, 56, 65-67: buildReport error →
   `reportError` → return 1, before the write branch). A gold-plated `run()`-level
   test is impossible without a legacy MySQL source and is out of scope.
3. **T-9:** with all mapped clients tenant-bound the report stays
   byte-identical; a new per-client tenant coverage line appears only when a
   violation exists; the existing plan/target unit tests (plan_test.go,
   target_test.go, whose `testTargetSchema` clients table gains the
   `tenant_id` column) pass unchanged.
   Testable form: REQ-3 golden output pin; REQ-2 per-client diagnostic; REQ-4
   fixture updates with unchanged test names/assertions.

## 6. Files

### Create

```text
cmd/sso-ctl/legacysync/tenant_gate_test.go — new unit tests (unbound/bound/
multi-client gate, printReport golden, mode coverage); _test.go does not count
against the package file ceiling
test/legacy_sync_tenant_claim_test.go — sqlite-backed mint integration
assertion (package ssotest)
docs/architect-analysis/cmd-sso-ctl-legacysync-tenant-binding-gate-requirements.md — this spec
```

### Modify

```text
cmd/sso-ctl/legacysync/target.go — loadTargetClients selects tenant_id and
snapshot carries bindings (REQ-1); buildReport fails unbound mapped clients,
naming each id (REQ-2). Budget check: target.go is 403 lines today; the
change adds ~10-15 lines (under the 500 ceiling); buildReport grows from 35
to ~43 lines (under 50); cyclomatic complexity stays well under 15
cmd/sso-ctl/legacysync/target_test.go — testTargetSchema clients table gains
tenant_id TEXT NOT NULL DEFAULT ''; seedTarget binds sverp-web (REQ-4)
```

### Do not modify

```text
infrastructure/defaultimpl/issue_payload.go — mint-side stamp + dedup already
correct (evidence lines 46, 108-131)
infrastructure/defaultimpl/sqlite/clients.go — real schema already has
tenant_id (line 46); no migration
interfaces/sso/*, internal/handler/tokengrant/* — /token binding resolution
and grant stamping already correct
cmd/sso-ctl/legacysync/plan.go, source.go, config.go, model.go, main.go —
plan shape, source load, flags, and run() control flow are unchanged
```

## 7. Dependencies and compatibility

- New SPI / option / YAML key / storage migration: none. The real `clients`
  schema already carries `tenant_id` (`NOT NULL DEFAULT ''`); the gate is a
  read-only validation.
- HTTP/proto compatibility: none — no endpoint, no wire error code, no
  discovery surface. The failure is a CLI stderr diagnostic plus exit 1;
  AGENTS.md §5.6 requires no doc-contract updates (no new `Err*`,
  endpoint, or config knob; verified `legacy-sync` is absent from
  docs/config-reference.md and docs/feature-matrix.md).
- Oracle/security posture: unchanged. The gate adds a failure mode for
  operator misconfiguration; it introduces no new response surface and no
  new distinguishing information across internal causes (there is only one
  cause: empty binding).
- Rollout/rollback: revert the two files; a deployment created after the
  gate is strictly safer than before (bound clients mint `tenant_id`; the
  claim emission itself predates this change at issue_payload.go:46).

## 8. Verification plan

Mandatory after every `.go` edit:

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
```

Targeted:

```bash
go test ./cmd/sso-ctl/legacysync/ -run 'TestApplyPlan|TestBuildReport|TestTenant' -v
go test ./test/ -run 'TestLegacySyncTenantClaim' -v
```

Handoff (proportional to a small, self-contained change):

```bash
go test ./... -race
make ci
```
