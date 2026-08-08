# Requirements: Replace guaranteed-fail `--expect-roles` with a conditional roles assertion

Requirements specification for the selected direction "Replace guaranteed-fail
`--expect-roles` with a conditional roles assertion" (direction 3 of the module
analysis). Doc-only artifact; no `.go` edits, so no build gates are triggered by
this file.

Module: `cmd/sso-ctl/apiclient` (composition layer; dispatch table
`cmd/sso-ctl/main.go`). Source analysis:
`docs/architect-analysis/auto/analyses/cmd-sso-ctl-apiclient-12aa9498.json`,
direction 3. Every citation below was re-checked against the working tree; the
supplied acceptance is preserved verbatim in section 3 and made testable.

## 1. Verification outcome — citations checked against the repository

| Citation | Verdict |
|---|---|
| `cmd/sso-ctl/apiclient/check.go` — `--expect-roles` flag + usage text | **Verified** — `fs.Bool("expect-roles", false, "declare the minted token MUST carry a non-empty roles claim")` at check.go:78, wired into the `checker` struct at 117 (`expectRoles` field, sweep.go:60); usage banner line at check.go:169. The flag is opt-in: absence of an undeclared claim is never asserted (token.go:174-178 comment). |
| `cmd/sso-ctl/apiclient/token.go:verifyClaims` roles branch — "flag is a declaration, not a guess" | **Verified** — roles branch at token.go:225-229: `if ck.expectRoles { roles, _ := p["roles"].([]any); if len(roles) == 0 { diags = append(diags, "claims: roles absent — cc-path mints never resolve Subject.Roles; flag is a declaration, not a guess") } }`. `verifyClaims` spans 175-229 (55 lines — already at the function budget ceiling, see §4). |
| `cmd/sso-ctl/apiclient/check_test.go:921` — `TestMint_RolesExpectationFailsOnCC` | **Verified** — func at exactly 921 (comment at 918-920: "cc-path mints never carry roles, so `--expect-roles` fails deterministically on the live server"). Subtest `live-cc-fails` (925-931) asserts exit 1 + `claims: roles absent` against `newLiveServer`; subtest `stub-with-roles-passes` (933-942) asserts exit 0 for a stub token carrying `roles: ["admin"]`. The acceptance inverts the `live-cc-fails` subtest — it is the landmine this direction removes (REQ-1/REQ-6). |
| `internal/handler/tokengrant/token_client_credentials.go:Issue` — Subject with no Roles | **Verified** — lines 50-58: `ti.Issue(ctx, &core.Subject{ID: client.ID, Resources: resources, ClientID: client.ID, TenantID: client.TenantID, TTL: ..., ConfirmationJKT: ..., ConfirmationX5TS256: ..., ServingRegion: ...})` — no `Roles`, no `Claims`. The cc path cannot resolve roles structurally; nothing in this direction changes that (invariant 2). |
| `infrastructure/defaultimpl/issue_payload.go:applyOptionalClaims` — roles emitted only when non-empty | **Verified** — lines 83-88: `// Roles: same guard+copy discipline as AMR — the claim is emitted only when non-empty ...` `if len(subject.Roles) > 0 { payload.Roles = append([]string(nil), subject.Roles...) }`. Wire shape `Roles []string \`json:"roles,omitempty"\`` (ed25519_types.go:57). `claimsWithoutEmittedKeys` (issue_payload.go:117-132) drops the `ext`/attribute-bag `roles` copy whenever `Subject.Roles` is non-empty, so the top-level claim is never duplicated. |
| `check_test.go` `goldenGreenStdout` | **Verified** — constant at check_test.go:32: `"discovery: OK\nmint: OK\ninvalid_scope: OK\nintrospect: OK\ncheck OK\n"`; asserted byte-exact by `TestSweep_GreenPath` (line 446+), `TestStdoutDeterministic` (475+), `TestCheck_EnvAddrValidation` (453+), `TestSweep_AdvertisedOnly` (534+). The acceptance requires this constant to stay byte-identical (REQ-3). |

Additional facts verified during this pass (load-bearing for the requirements):

1. **Roles sources are user-token paths only.** `Subject.Roles` is populated by
   `server_login.go:108,120` (`mintRoles` → authcode/direct-login mint),
   `server_oauth.go:90` (device flow via `authCtx.Roles`), and
   `token_refresh.go:279` — never by `token_client_credentials.go`. The CLI
   cannot drive any of those paths with client credentials alone, which is
   exactly why the assertion must be conditional (absence tolerated) and why
   `--expect-no-roles` is the attainable cc pin.
2. **`--expect-roles` today is bool-typed and guaranteed-fail.** Because the
   cc Subject never carries `Roles`, `p["roles"]` is absent on every live
   mint; the branch at token.go:226-229 therefore fails whenever the flag is
   used against a live server. check_test.go:921 codifies that exit 1 as
   *intended* behavior ("documented deterministic failure" per the module
   design doc, `docs/architect-analysis/auto/cmd-sso-ctl-apiclient-design.md`
   row 16 at line 365). This direction supersedes row 16's semantics: the
   flag becomes a conditional assertion, and the codified test is replaced
   (REQ-6). A roles-emission regression therefore no longer needs a
   guaranteed-fail flag to be detected — the conditional assertion still
   fails on mismatch, and the cc path gains a *passable* pin.
3. **The roles claim decodes as a JSON array.** The sweep decodes the JWT
   payload into `map[string]any` (token.go:155-164), so a `roles` array
   surfaces as `[]any` (the type the current branch already reads) and a
   malformed string value surfaces as `string`. The assertion must handle
   present-but-non-array as a malformed failure, not as absence.
4. **Diagnostic precedent for flag values.** `verifyClaims` already names the
   observed vs declared value in its diagnostics (`claims: tenant_id %q !=
   %q`, token.go:219; `claims: scope %q missing %q`, 213). The check.go
   header's "no diagnostic ever echoes a flag value" claim is narrower than
   the code (client secrets and minted tokens are never echoed; declared
   tenant/scope/role values are). The roles mismatch diagnostic follows the
   tenant_id/scope precedent (REQ-1) and never echoes credentials or tokens.
5. **Bare `--expect-roles` misuse already has a test row.**
   `TestExitCodes` row `expect-roles-without-creds` (check_test.go:335) runs
   `--expect-roles` with no credentials and expects exit 2. Under the
   bool→value transition the row stays green for a different reason: the flag
   package rejects a value-less `--expect-roles` ("flag needs an argument")
   during `fs.Parse` (check.go:83-96) — exit 2 with usage, same contract
   (REQ-6 criterion 6).
6. **`stringList` is the package's existing repeatable/space-separated flag
   value** (check.go:174-182), used by `--resource`. Reusing it for
   `--expect-roles` requires no new flag machinery and matches the
   `--resource` precedent byte-for-byte (`Set` splits on `strings.Fields`,
   so `--expect-roles admin ops` and repeated `--expect-roles admin
   --expect-roles ops` are equivalent).
7. **Cross-campaign interaction.** `docs/architect-analysis/
   cmd-sso-ctl-b4-1-claims-gate-requirements.md:41` recorded "no changes to
   `--expect-roles` semantics on the cc path" as *its* scope guard (a
   server-side claims direction). This direction deliberately changes the
   check CLI's semantics only — no server behavior, no claims emission, no
   config — so the two directions do not conflict; the divergence is
   documented here (section 7).
8. **Module test baseline is red today (pre-existing).** `go test
   ./cmd/sso-ctl/apiclient/` fails 11 tests (TestCheck_AddrValidation,
   TestSweep_GreenPath, TestStdoutDeterministic, TestSweep_TokenEndpointSuffix,
   TestSweep_AdvertisedURLRejection, TestMint_ClaimsMatrix,
   TestMint_ScopeContainsRequested, TestMint_AudContainsResource,
   TestMint_ResponseFail, TestRevoke_RoundTrip, TestIntrospect_Non401Fails).
   Root cause: the sweep files (check.go/check_test.go/sweep.go/token.go/
   apiclient_test.go) are untracked WIP and `apiclient.go` carries uncommitted
   edits, against an `interfaces/sso` tree with uncommitted drift — the same
   condition the sibling campaign (`form-urlencoded-probe-path...`) recorded.
   The verification plan (§6) reports this separately; this direction adds
   its tests on top of the existing file set and must not be blamed for the
   pre-existing failures. `go build ./cmd/sso-ctl/...` passes.

## 2. Core invariants

1. **Conditional roles assertion.** `roles` is a wiring-conditional claim
   (emitted only when `Subject.Roles` is non-empty — issue_payload.go:86).
   The check asserts it conditionally: with `--expect-roles <set>`, a minted
   non-empty roles claim must be set-equal to the declared set, and absence
   (missing or empty) is tolerated; with `--expect-no-roles`, absence is
   required. An undeclared roles claim is never asserted (unchanged from
   today, token.go:174-178).
2. **cc-path determinism is the design constraint, not a failure mode.**
   The cc mint cannot resolve `Subject.Roles` (token_client_credentials.go:
   50-58 — structural, unchanged). The attainable cc pin is therefore
   `--expect-no-roles` (always passes on a live server), and
   `--expect-roles <set>` is the assertion for deployments whose token paths
   can emit roles (authcode/device via authenticator attributes). No flag
   combination can fail on a healthy live cc deployment.
3. **Exit-code and stdout discipline unchanged.** 0 = all executed groups
   passed; 1 = any failure; 2 = CLI misuse (including the new
   `--expect-roles`+`--expect-no-roles` conflict and value-less
   `--expect-roles`). Roles flags affect only stderr diagnostics; stdout
   stays the byte-deterministic `goldenGreenStdout` on a green run.
4. **Server untouched.** No change to `interfaces/sso`,
   `internal/handler/tokengrant`, `infrastructure/defaultimpl`, the stores,
   discovery, OpenAPI, error codes, or config. Server-side roles emission
   stays pinned by the existing `defaultimpl` tests
   (`infrastructure/defaultimpl/tenant_roles_test.go`,
   `TestTenantRoles_ClaimsPerIssuer`) — verified present, one test per
   signer (Ed25519/ECDSA/RSA), asserting top-level `tenant_id` + `roles`
   claims for a Subject with `TenantID` + `Roles`.
5. **Never echo credentials or tokens.** The new diagnostics may name the
   observed/declared roles sets (tenant_id/scope precedent, §1.4) but never
   the client secret, the minted token, or the probe scope; sanitization
   rules are unchanged.

## 3. Requirements

Acceptance (supplied, preserved verbatim): **T-8(a): `--expect-roles` becomes
conditional — minted roles, when present, must equal the declared set
(failure), absence is tolerated (no failure); add `--expect-no-roles` pin for
the cc path; keep exit-0 green-path golden (check_test.go goldenGreenStdout)
unchanged; server-side roles emission stays pinned by
infrastructure/defaultimpl issue_payload tests, documented in the check usage
text**

| # | Acceptance sentence | Requirement(s) |
|---|---|---|
| A1 | `--expect-roles` becomes conditional — minted roles, when present, must equal the declared set (failure), absence is tolerated (no failure) | REQ-1 |
| A2 | add `--expect-no-roles` pin for the cc path | REQ-2 |
| A3 | keep exit-0 green-path golden (`goldenGreenStdout`) unchanged | REQ-3 |
| A4 | server-side roles emission stays pinned by `infrastructure/defaultimpl` issue_payload tests | REQ-4 |
| A5 | documented in the check usage text | REQ-5 |

### REQ-1 — `--expect-roles` becomes a declared-set assertion (A1)

- **Flag shape.** `--expect-roles` changes from `fs.Bool` (check.go:78) to a
  value flag reusing the package's existing `stringList` type
  (check.go:174-182; the `--resource` precedent): repeatable and
  space-separated, declaring the expected roles set. A value-less
  `--expect-roles` is flag-parse misuse → exit 2 (flag package "needs an
  argument" path, check.go:83-96). `checker.expectRoles bool`
  (sweep.go:60) becomes the declared set (`[]string` built from the
  `stringList`).
- **Assertion semantics** (replacing the roles branch at token.go:225-229,
  extracted into a focused helper — see §4):
  - roles claim **absent or empty** → no failure (absence tolerated).
  - roles claim **non-empty array** → set equality: the token's roles and
    the declared set must have exactly the same members (order-insensitive;
    roles are a set). Any declared role missing from the token, or any token
    role not declared, fails with a diagnostic naming the observed set vs
    the declared set (tenant_id/scope precedent, §1.4), e.g.
    `claims: roles [admin] != declared [ops]`.
  - roles claim **present but not a JSON array** (e.g. a string) → failure
    with a malformed diagnostic (`claims: roles claim is not an array`):
    the claim is present and cannot equal a declared set, and a
    misbehaving server must be surfaced, not tolerated.
- **Empty declared set.** `--expect-roles ""` declares the empty set:
  absence passes, any non-empty roles array fails (set equality is exact).
  No special case needed beyond the generic rule.

Testable criteria:

1. Given a live server (cc mint — no roles claim ever) and
   `--expect-roles admin`, then exit is 0 and stdout is `goldenGreenStdout`
   (absence tolerated; this is the inversion of the removed
   `live-cc-fails` subtest).
2. Given a stub minting `roles: ["admin"]` and `--expect-roles admin`, then
   exit is 0.
3. Given a stub minting `roles: ["admin"]` and `--expect-roles ops`, then
   exit is 1 and stderr names both the observed and the declared set.
4. Given a stub minting `roles: ["admin","ops"]` and
   `--expect-roles ops admin` (order-insensitive), then exit is 0; with
   `--expect-roles admin`, exit is 1 (undelcared token role is a mismatch).
5. Given a stub minting `roles: "admin"` (string, not array) and
   `--expect-roles admin`, then exit is 1 with the not-an-array diagnostic.
6. Given a value-less `--expect-roles`, then exit is 2 with usage on stderr
   (keeps the `expect-roles-without-creds` row of `TestExitCodes` green —
   §1.5).
7. Given `--expect-roles` and `--expect-no-roles` together, then exit is 2
   (contradictory declarations; misuse check added to `TestExitCodes`).

### REQ-2 — `--expect-no-roles` cc-path pin (A2)

- **Flag shape.** New `fs.Bool("expect-no-roles", ...)`: declares that the
  minted token MUST NOT carry a non-empty roles claim. `checker` gains a
  `expectNoRoles bool` field. Mutually exclusive with `--expect-roles`
  (both declared → misuse, exit 2, REQ-1 criterion 7).
- **Assertion semantics** (same helper as REQ-1):
  - roles claim **absent or empty** → pass. This is the attainable cc pin:
    on a live server the cc Subject never resolves roles, so
    `--expect-no-roles` always passes (invariant 2).
  - roles claim **non-empty array** → fail with a diagnostic naming the
    violation, e.g. `claims: roles present but --expect-no-roles declared`.
  - roles claim **present but not a JSON array** → fail (malformed claim is
    not "no roles").
- **Usage text.** The banner documents the pin as the cc-path roles
  assertion and states why: cc mints never resolve `Subject.Roles`, roles
  arrive only on authcode/device/refresh paths (server_login.go:120,
  server_oauth.go:90, token_refresh.go:279) that the CLI cannot drive with
  client credentials alone.

Testable criteria:

1. Given a live server (cc mint) and `--expect-no-roles`, then exit is 0
   and stdout is `goldenGreenStdout`.
2. Given a stub minting `roles: ["admin"]` and `--expect-no-roles`, then
   exit is 1 with the roles-present diagnostic.
3. Given a stub minting no roles claim and `--expect-no-roles`, then exit is 0.
4. Given a stub minting `roles: "admin"` (string) and `--expect-no-roles`,
   then exit is 1 with the not-an-array diagnostic.
5. Given no roles flag at all, then a roles-bearing or roles-less token
   both pass (undeclared claims are never asserted — unchanged invariant).

### REQ-3 — golden stdout unchanged (A3)

- `goldenGreenStdout` (check_test.go:32) and every green-path assertion
  (`TestSweep_GreenPath`, `TestStdoutDeterministic`,
  `TestCheck_EnvAddrValidation` valid-env subtest, `TestSweep_AdvertisedOnly`)
  stay byte-identical. The roles flags never add or remove stdout lines —
  they only add stderr diagnostics on mismatch; a run passing every group
  prints exactly the four group lines plus `check OK`.

Testable criterion:

1. Given a live server run with `--expect-roles admin --expect-no-roles`
   absent (i.e. the flag-default run) and with `--expect-no-roles`, then
   stdout equals `goldenGreenStdout` in both cases, byte-for-byte.

### REQ-4 — server-side roles emission stays pinned (A4)

- No server-side edit. The existing `infrastructure/defaultimpl/
  tenant_roles_test.go` (`TestTenantRoles_ClaimsPerIssuer`, one issuer per
  signer: Ed25519/ECDSA/RSA) keeps pinning that a Subject with `Roles`
  mints a payload with a top-level `roles` claim, and `applyOptionalClaims`
  keeps its non-empty guard (issue_payload.go:83-88). The check usage text
  (REQ-5) names this pin so the operator knows where the emission contract
  is attested.

Testable criterion:

1. Given `go test ./infrastructure/defaultimpl/ -run TestTenantRoles -v`,
   then all three per-signer subtests pass unchanged.

### REQ-5 — usage text documents the conditional contract (A5)

- `usage()` (check.go:163-171) replaces the current `--expect-roles` line
  ("declare the minted token MUST carry a non-empty roles claim") with:
  - `--expect-roles <role>...` — declare the roles set a minted token's
    `roles` claim MUST equal when present; absence is tolerated (conditional
    assertion; repeatable/space-separated).
  - `--expect-no-roles` — declare the minted token MUST NOT carry a
    non-empty `roles` claim (the attainable client-credentials pin: cc
    mints never resolve `Subject.Roles`; roles arrive only on
    authcode/device/refresh paths).
  - A line noting server-side roles emission is pinned by the
    `infrastructure/defaultimpl` issue_payload tests.
- The probe-group banner (check.go:9-16) T-8a line is updated to reflect the
  conditional roles assertion.

Testable criterion:

1. Given `sso-ctl check -h`, then the usage output contains
   `--expect-roles`, `--expect-no-roles`, the words "absence is tolerated",
   and the defaultimpl-pin sentence, and exits 0.

### REQ-6 — test updates (the landmine's codified exit 1 is removed)

- `TestMint_RolesExpectationFailsOnCC` (check_test.go:918-944) is replaced
  by the REQ-1/REQ-2 matrix:
  - `TestMint_RolesConditional`: live-cc + `--expect-roles admin` → 0;
    stub `roles:["admin"]` + declared `admin` → 0; stub `roles:["admin"]` +
    declared `ops` → 1 (observed-vs-declared diagnostic); stub
    `roles:["admin","ops"]` + declared `ops admin` → 0 (order-insensitive)
    and + declared `admin` → 1 (extra token role); stub string `roles` →
    1 (not-an-array).
  - `TestMint_ExpectNoRoles`: live-cc → 0; stub `roles:["admin"]` → 1;
    stub absent → 0; stub string `roles` → 1.
  - `TestExitCodes` (check_test.go:322-352) gains rows:
    `expect-roles-no-value` (`--expect-roles` alone → 2),
    `expect-no-roles-without-creds` (→ 2), `both-roles-flags`
    (`--expect-roles admin --expect-no-roles` → 2).
  - The stub-based green subtest of the removed test survives in spirit as
    criterion 2 of REQ-1 (`roles:["admin"]` + `--expect-roles admin` → 0).
- `TestClaimsMatrix_FailureDiagnostics` (check_test.go:1008-1049) needs no
  change: its rows cover kid/typ/iss/sub/client_id/scope/aud only; the
  roles assertion is a separate conditional path tested by the new matrix.
- `goldenGreenStdout` and all green-path tests are untouched (REQ-3).

Testable criterion:

1. Given `go test ./cmd/sso-ctl/apiclient/ -run 'TestMint_Roles|TestMint_ExpectNoRoles|TestExitCodes' -v`, then all matrix subtests pass on a
   baseline with the pre-existing failures of §1.8 excluded/reported.

## 4. Budgets and design constraints (checked before editing)

- `verifyClaims` (token.go:175-229) is already **55 lines** — over the
  50-line function budget and will grow with the conditional roles logic.
  The roles assertion MUST be extracted into a focused helper (e.g.
  `verifyRolesClaims(payload map[string]any, declared []string, noRoles bool)
  []string` in token.go), keeping `verifyClaims` at or under 50 lines and the
  helper under 50. If the helper exceeds 50 lines, split the set-equality
  normalizer into its own function (≤ 15 complexity, ≤ 3 if-nesting).
- `cmd/sso-ctl/apiclient` currently has 4 non-test files (apiclient.go 205,
  check.go 277, sweep.go 284, token.go 413 — all ≤ 500 lines); the change
  adds no file, only edits token.go (roles helper), check.go (flag decl,
  usage, misuse check), sweep.go (checker fields). File budgets hold.
- `cmd/sso-ctl/` stays at its 16-directory fan-out ceiling — no new
  subpackage (unchanged from the module's direction-1 spec).
- `interfaces/sso` is at its 60-file ceiling and is NOT touched (invariant 4).
- Import flow unchanged: `cmd/sso-ctl/apiclient` imports only stdlib
  (net/http, net/url, encoding/json, crypto/rand, flag, os, strings, time).
- No OpenAPI/error-code/config-reference changes: CLI-only surface, no new
  server endpoints, errors, or config keys.

## 5. Files

### Modify

```text
cmd/sso-ctl/apiclient/check.go    — REQ-1/REQ-2/REQ-5: --expect-roles bool → stringList value
                                   flag; new --expect-no-roles bool; mutual-exclusion misuse
                                   (exit 2); usage() text for both flags + the defaultimpl pin
cmd/sso-ctl/apiclient/sweep.go    — checker struct: expectRoles bool → declared roles []string;
                                   new expectNoRoles bool
cmd/sso-ctl/apiclient/token.go    — REQ-1/REQ-2: replace the roles branch at 225-229 with the
                                   extracted conditional assertion helper (absent/empty
                                   tolerated; set equality; not-an-array failure; no-roles pin);
                                   verifyClaims stays ≤ 50 lines
cmd/sso-ctl/apiclient/check_test.go — REQ-6: replace TestMint_RolesExpectationFailsOnCC with
                                   TestMint_RolesConditional + TestMint_ExpectNoRoles; extend
                                   TestExitCodes with the three new misuse rows
```

### Do not modify

```text
internal/handler/tokengrant/token_client_credentials.go — cc Subject stays Roles-less
                                                           (invariant 2; the pin, not the fix)
infrastructure/defaultimpl/issue_payload.go, ed25519_types.go — roles emission unchanged;
                                                               pinned by existing tests (REQ-4)
interfaces/sso/*, docs/openapi.yaml, docs/error-codes.md, docs/config-reference.md — untouched
cmd/sso-ctl/apiclient/apiclient.go, apiclient_test.go — client contract untouched (untracked WIP
                                                        drift is pre-existing, §1.8)
```

## 6. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/apiclient/ -run 'TestMint_RolesConditional|TestMint_ExpectNoRoles|TestExitCodes|TestSweep_GreenPath' -race
go test ./infrastructure/defaultimpl/ -run TestTenantRoles -v
go test ./test/ -run TestE2E -v
make ci
```

Targeted tests beside the code: REQ-1 criteria 1-7 (conditional assertion
matrix — live-cc tolerance, stub set equality, order-insensitivity, mismatch
and malformed diagnostics, misuse exits); REQ-2 criteria 1-5 (no-roles pin
matrix); REQ-3 criterion 1 (goldenGreenStdout byte-identity under the new
flags); REQ-5 criterion 1 (usage text); REQ-6 criterion 1 (replaced/codified
tests). All tests run without external services (httptest only).

Baseline note (AGENTS.md: report pre-existing failures separately): as of
this spec, `go test ./cmd/sso-ctl/apiclient/` has 11 pre-existing failures
from untracked WIP + `interfaces/sso` drift (§1.8), unrelated to this
direction. The implementer must re-run the suite after the change and
attribute any remaining failures to that baseline, not to the roles work.

## 7. Explicit non-goals (scope guard)

- **No server-side change.** cc mints keep resolving no roles; the roles
  claim emission, its non-empty guard, and the `claimsWithoutEmittedKeys`
  dedup all stay byte-identical. The server-side contract continues to be
  attested by `infrastructure/defaultimpl/tenant_roles_test.go` only.
- **No new assertion modes beyond the acceptance.** No `--expect-roles`
  containment semantics (subset), no per-claim ordering guarantee (roles are
  a set), no roles assertion on non-mint rows, no role resolution in the CLI.
- **No changes to the other expectation flags.** `--expect-tenant-id`
  semantics (present+equal, absence fails) are untouched; only the roles
  flag changes shape.
- **Deliberate divergence from the B4-1 claims-gate direction.** Its spec
  (`docs/architect-analysis/cmd-sso-ctl-b4-1-claims-gate-requirements.md:41`)
  recorded "no changes to `--expect-roles` semantics on the cc path" as its
  own scope guard. This direction changes the check CLI's flag semantics
  only — no server behavior, no claims emission, no config — and is the
  acceptance-mandated resolution of the guaranteed-fail landmine. The module
  design doc row 16 (`cmd-sso-ctl-apiclient-design.md:365`) is superseded.
- **No migration of deploy-tree callers.** No `ops/deploy/*` script or CI
  wiring changes; any deployment using bare `--expect-roles` must switch to
  `--expect-roles <set>` or `--expect-no-roles` (bare usage is now misuse,
  exit 2, with the flag package's diagnostic pointing at the flag).
- **No doc updates outside the check usage text** (REQ-5): the module's
  design/test-mapping docs are historical records of the superseded row 16
  and are not rewritten by this direction.
