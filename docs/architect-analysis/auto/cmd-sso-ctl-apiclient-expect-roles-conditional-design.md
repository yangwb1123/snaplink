# Design: conditional `--expect-roles` + `--expect-no-roles` for `sso-ctl check`

Design for direction 3 of `cmd/sso-ctl/apiclient` (composition layer; dispatch
table `cmd/sso-ctl/main.go`), per the requirements spec committed at `ad4f12f4`
(mirror: `docs/architect-analysis/auto/cmd-sso-ctl-apiclient-expect-roles-conditional-requirements.md`).
This document covers the API changes, compatibility constraints, failure
modes, migration steps, and the testable acceptance mapping.

## 0. Evidence verification verdict (claims re-checked against the repo)

| Claim | Verdict |
|---|---|
| Commit `ad4f12f4`, 2 files only, docs-only | **Verified** — `git show --stat` = 2 files, 808 insertions, 0 deletions; no `.go` files |
| `check.go:78` bool `--expect-roles`; usage at 169; wiring at 117 | **Verified** (exact lines) |
| `sweep.go:60` `expectRoles bool` | **Verified** |
| `token.go:225-229` roles branch; `verifyClaims` spans 175-229 (55 lines) | **Verified** |
| `check_test.go:921` `TestMint_RolesExpectationFailsOnCC`; subtests at 925-942 | **Verified** (func at exactly 921) |
| `goldenGreenStdout` at check_test.go:32; byte-asserted by 4 green-path tests | **Verified** (constant at 32; assertions at 433/453/475/534) |
| `token_client_credentials.go:50-58` Subject without Roles/Claims | **Verified** |
| `issue_payload.go:83-88` non-empty guard; `ed25519_types.go:57` wire shape | **Verified** (exact lines) |
| Roles sources: server_login.go:108/120, server_oauth.go:90, token_refresh.go:279 | **Verified** (`interfaces/sso/` paths) |
| `TestTenantRoles_ClaimsPerIssuer` in defaultimpl | **Verified** (tenant_roles_test.go:77) |
| B4-1 spec scope guard at line 41; design-doc row 16 at line 365 | **Verified** |
| 11 pre-existing module test failures, named in spec §1.8 | **Verified** — exactly 11 `--- FAIL` tests, names match |
| `go build ./cmd/sso-ctl/...` passes | **Verified** |
| Artifact/mirror byte-identical | **Verified at commit time** (`diff` of the two blobs at `ad4f12f4` = identical, both 404 lines); **NOT true in the current tree** — see discrepancy 1 |
| 980 pre-existing worktree changes untouched | **Consistent** — current `git status` = 982 entries (874 untracked, 108 modified); the campaign contributed 2 tracked + ~3 untracked files of that total |

Discrepancies found (none load-bearing for the design):

1. **Pipeline artifact overwritten at HEAD.** The file
   `runs/replace-guaranteed-fail-expect-roles-with-a-cond-cbe204e6/artifacts/requirements-10762e10/requirements.md`
   is now a 26-line stage summary; the stage commit `fdf2d9fd` replaced the
   404-line spec that `ad4f12f4` committed there. The repo-visible mirror
   `docs/architect-analysis/auto/cmd-sso-ctl-apiclient-expect-roles-conditional-requirements.md`
   is the canonical spec. Any later consumer must read the mirror.
2. **Minor citation drift:** spec §3 REQ-6 cites
   `TestClaimsMatrix_FailureDiagnostics` at check_test.go:1008-1049; the func
   starts at 993. Substantive claim (its rows cover kid/typ/iss/sub/
   client_id/scope/aud only, no roles row) verified true.
3. **Worktree arithmetic:** "980 pre-existing" is an approximation; 982
   entries today, of which this campaign accounts for ~5. Not load-bearing.

## 1. Direction summary

`--expect-roles` is today a bool whose only live-server outcome is exit 1:
the cc mint never resolves `Subject.Roles`
(`token_client_credentials.go:50-58`, structural), so the token.go:225-229
branch is a guaranteed-fail landmine codified as *intended* by
`TestMint_RolesExpectationFailsOnCC` (check_test.go:921) and design-doc row 16
(line 365). The acceptance T-8(a) supersedes row 16: the flag becomes a
**conditional** declared-set assertion (absence tolerated, set equality on
presence), plus a new **`--expect-no-roles`** pin that is the attainable cc
assertion (always passes on a healthy live cc deployment).

Server behavior is untouched in every respect; this is a CLI-only semantic
change in `cmd/sso-ctl/apiclient`.

## 2. API changes

### 2.1 CLI surface (`sso-ctl check`)

| Flag | Today | After |
|---|---|---|
| `--expect-roles` | bool; declare token MUST carry non-empty `roles`; guaranteed exit 1 on live cc | value flag reusing `stringList` (check.go:174-182): `--expect-roles <role>...`, repeatable and space-separated; declares the set the minted `roles` claim MUST equal **when present**; absence (missing or empty) tolerated; `--expect-roles ""` declares the empty set (any non-empty claim fails) |
| `--expect-no-roles` | absent | new bool; declare token MUST NOT carry a non-empty `roles` claim; the attainable cc pin |
| mutual exclusion | n/a | both flags declared → CLI misuse, exit 2 |
| bare `--expect-roles` | accepted | flag-parse error ("flag needs an argument") → exit 2 with usage; keeps the `expect-roles-without-creds` TestExitCodes row (check_test.go:335) green for a different reason |

Exit-code contract preserved: 0 = all executed groups passed; 1 = any
failure; 2 = CLI misuse. Roles flags affect **stderr only**; stdout stays the
byte-deterministic `goldenGreenStdout` on green runs.

### 2.2 Go-level changes (4 files, no new files)

- `sweep.go:60` — `expectRoles bool` → `expectRoles []string`; add
  `expectNoRoles bool`.
- `check.go:78` — `fs.Bool("expect-roles", ...)` → `var expectRoles stringList; fs.Var(&expectRoles, "expect-roles", ...)`; add `fs.Bool("expect-no-roles", false, ...)`; wire at :117 (`expectRoles: []string(expectRoles)`); add the mutual-exclusion check next to the credentials check at :85-91 (exit 2 path); replace the two usage-banner lines at :168-169 with the conditional semantics, the no-roles pin rationale, and the defaultimpl-pin sentence; update the T-8a line in the probe-group banner (check.go:9-16).
- `token.go` — replace the roles branch at 225-229 with a call to a new
  extracted helper (see §2.3). `verifyClaims` must end at ≤ 50 lines (it is
  at 55 today; extraction is mandatory, not optional).
- `check_test.go` — replace `TestMint_RolesExpectationFailsOnCC` (921-944)
  with the REQ-1/REQ-2 matrix (§5); extend `TestExitCodes` (325-352) with
  `expect-roles-no-value`, `expect-no-roles-without-creds`,
  `both-roles-flags`.

### 2.3 Assertion semantics — `verifyRolesClaims` helper

New function in token.go:

```go
// verifyRolesClaims runs the conditional roles assertion: absence/empty is
// tolerated under --expect-roles (wiring-conditional claim, issue_payload
// non-empty guard); presence requires set equality with the declared set,
// or absence under --expect-no-roles; a non-array claim is always a failure.
func (ck *checker) verifyRolesClaims(declared []string, noRoles bool) []string
```

Reads `ck.payload["roles"]`. Truth table:

| token `roles` | `--expect-roles <set>` | `--expect-no-roles` | result |
|---|---|---|---|
| absent | any | — | pass (tolerated) |
| empty array `[]` | any | — | pass (tolerated; server never emits this anyway — non-empty guard + omitempty) |
| non-empty array | set equal (order-insensitive) | — | pass |
| non-empty array | set mismatch (missing declared member **or** extra token member) | — | fail: `claims: roles [<observed>] != declared [<declared>]` |
| non-empty array | — | — | fail: `claims: roles present but --expect-no-roles declared` |
| non-array (string/number/bool) | any | any | fail: `claims: roles claim is not an array` |

Set equality is exact: subset semantics are an explicit non-goal. Diagnostics
follow the tenant_id/scope precedent (token.go:213,219) — they name observed
and declared role values but never credentials or tokens (sanitization rules
unchanged; `redactURL` applies where URLs appear, which roles never are).

### 2.4 No API changes outside the check CLI

No changes to: server (`interfaces/sso`, `internal/handler/tokengrant`,
`infrastructure/defaultimpl`), stores, discovery, OpenAPI, error codes,
config, other `--expect-*` flags, `--resource`/`stringList` machinery, or the
apiclient client contract. No new package; import graph unchanged (stdlib
only).

## 3. Compatibility constraints

1. **Wire and server contracts frozen.** cc mints keep resolving no roles;
   roles emission, the non-empty guard, and the `claimsWithoutEmittedKeys`
   dedup stay byte-identical. The server-side contract stays attested solely
   by `TestTenantRoles_ClaimsPerIssuer` (one subtest per signer: Ed25519/
   ECDSA/RSA).
2. **CLI exit-code and stdout discipline frozen.** 0/1/2 semantics unchanged;
   `goldenGreenStdout` and all four green-path byte assertions stay
   byte-identical; roles flags add stderr lines only.
3. **`--expect-roles` is a deliberate breaking change at the same flag
   name.** bool → value is an either/or at parse time; no deprecation window
   is possible. Bare `--expect-roles` users break loudly (exit 2 + flag-package
   diagnostic naming the flag). This is the intended migration forcing; usage
   text (REQ-5) documents the replacement.
4. **Undeclared claims are never asserted** (token.go:174-178 comment,
   unchanged): no roles flag → roles-bearing or roles-less tokens both pass.
5. **Flag-value equivalence**: `--expect-roles admin ops` ≡ repeated
   `--expect-roles admin --expect-roles ops` (stringList `Set` splits on
   `strings.Fields`); order-insensitive by set semantics.
6. **Budgets**: `verifyRolesClaims` ≤ 50 lines, complexity ≤ 15, nesting ≤ 3;
   if it exceeds 50, split the set-normalizer into its own function.
   File budgets hold (token.go ~413→~445, check.go 277→~300, sweep.go
   284→~290; all < 500). `interfaces/sso` 60-file ceiling untouched;
   `cmd/sso-ctl` 16-directory fan-out unchanged.
7. **Cross-campaign coordination.** The B4-1 claims-gate spec
   (`cmd-sso-ctl-b4-1-claims-gate-requirements.md:41`) recorded "no changes to
   `--expect-roles` semantics on the cc path" as its scope guard. This
   direction changes only the check CLI's flag semantics — no server behavior,
   claims emission, or config — so the two directions do not conflict; the
   divergence is deliberate and documented (spec §7). Design-doc row 16 is
   superseded by this direction.

## 4. Failure modes

| # | Mode | Expected behavior | Rationale / guard |
|---|---|---|---|
| F1 | Live cc mint + `--expect-roles admin` | exit 0, stdout = golden | Absence tolerated; the landmine inversion (REQ-1 c1) |
| F2 | Stub `roles:["admin"]` + declared `ops` | exit 1, `claims: roles [admin] != declared [ops]` | Declared role missing (REQ-1 c3) |
| F3 | Stub `roles:["admin","ops"]` + declared `admin` | exit 1 | Extra token role = set mismatch (REQ-1 c4) |
| F4 | Stub `roles:"admin"` (string) + any roles flag | exit 1, not-an-array | Malformed claim must surface, never be read as absence (REQ-1 c5, REQ-2 c4) |
| F5 | Value-less `--expect-roles` | exit 2 + usage | flag package; keeps TestExitCodes row green (REQ-1 c6) |
| F6 | `--expect-roles` + `--expect-no-roles` | exit 2 | Contradictory declarations (REQ-1 c7, REQ-2) |
| F7 | Live cc + `--expect-no-roles` | exit 0, stdout = golden | The attainable cc pin (REQ-2 c1) |
| F8 | Stub `roles:["admin"]` + `--expect-no-roles` | exit 1, roles-present diagnostic | Violation of the pin (REQ-2 c2) |
| F9 | Server regression: cc mint starts emitting roles | `--expect-no-roles` catches it (F8) | The pin's purpose |
| F10 | Server regression: user-path roles emission silently stops | **NOT caught by `--expect-roles`** (absence tolerated) | Documented residual gap — see below |
| F11 | Mint/discovery/revoke/introspect failures | unchanged exit 1 per group | No roles-specific change |

**Residual gap (F10) — must be documented in the design, not papered over.**
The conditional assertion cannot detect a complete loss of the `roles` claim
on a user path, because absence is tolerated by acceptance mandate (T-8(a)).
Mitigations: (a) the server-side emission contract remains pinned by
`TestTenantRoles_ClaimsPerIssuer` at the unit level (REQ-4) — this is the
actual regression guard; (b) spec §1.2's claim that "the conditional
assertion still fails on mismatch" is true only for value mismatches, not
absence — the usage text (REQ-5) should state that absence tolerance is why
the defaultimpl pin exists. No stricter semantics (subset/containment,
absence-fails) are added: they would recreate the guaranteed-fail landmine on
the cc path, which is the exact defect being removed.

**Pre-existing baseline (reported, not repaired):** the module has 11
pre-existing test failures (untracked WIP sweep files + `interfaces/sso`
drift; verified — exact names match spec §1.8). All targeted verification for
this work must use `-run` filters so baseline noise is excluded; the
implementer re-runs the full suite and attributes remaining failures to the
baseline.

## 5. Migration steps

1. **Fields first** — `sweep.go`: `expectRoles []string`, add
   `expectNoRoles bool`. Compile.
2. **Assertion helper** — `token.go`: extract `verifyRolesClaims`; replace
   the 225-229 branch with the call; re-measure `verifyClaims` ≤ 50 lines.
   (Budget gate: run `go test -run 'TestMaintainability_' .` here.)
3. **Flags + misuse + usage** — `check.go`: `fs.Var` + `--expect-no-roles`;
   mutual-exclusion check (exit 2) beside the credentials check; usage banner
   rewrites (REQ-5).
4. **Tests** — `check_test.go`: replace `TestMint_RolesExpectationFailsOnCC`
   with `TestMint_RolesConditional` + `TestMint_ExpectNoRoles`; extend
   `TestExitCodes` with the three misuse rows; leave all green-path tests and
   `TestClaimsMatrix_FailureDiagnostics` untouched.
5. **Deploy-tree callers** — no `ops/deploy/*` or CI changes in this
   direction. Any script using bare `--expect-roles` must switch to
   `--expect-roles <set>` or `--expect-no-roles`; breakage is loud (exit 2).
   The usage text is the migration notice; no other docs change.
6. **Gates** — after every `.go` edit: `go build ./... && go vet ./...` and
   `go test -run 'TestMaintainability_|TestArchitecture_' .`. Handoff:
   targeted `-race` matrix (§6), `go test ./infrastructure/defaultimpl/ -run
   TestTenantRoles -v`, `go test ./test/ -run TestE2E -v`, `make ci`.

## 6. Testable acceptance mapping

| Acceptance (verbatim) | REQ | Testable criteria | Verification |
|---|---|---|---|
| A1: `--expect-roles` conditional — minted roles, when present, must equal the declared set (failure); absence tolerated (no failure) | REQ-1 | c1 live-cc + `--expect-roles admin` → 0 + golden stdout; c2 stub `["admin"]` + `admin` → 0; c3 stub `["admin"]` + `ops` → 1 + both sets named; c4 `["admin","ops"]` + `ops admin` → 0, + `admin` → 1; c5 string roles → 1 not-an-array; c6 bare flag → 2; c7 both flags → 2 | `go test ./cmd/sso-ctl/apiclient/ -run 'TestMint_RolesConditional|TestExitCodes' -v` |
| A2: `--expect-no-roles` pin for the cc path | REQ-2 | c1 live-cc → 0 + golden; c2 stub `["admin"]` → 1; c3 stub absent → 0; c4 string roles → 1; c5 no flags → roles-bearing/roles-less both 0 | `go test ./cmd/sso-ctl/apiclient/ -run 'TestMint_ExpectNoRoles' -v` |
| A3: exit-0 green-path golden unchanged | REQ-3 | byte-compare stdout against `goldenGreenStdout` for flag-default run and `--expect-no-roles` run; all four existing green-path byte assertions unchanged | existing `TestSweep_GreenPath`, `TestStdoutDeterministic`, `TestCheck_EnvAddrValidation`, `TestSweep_AdvertisedOnly` |
| A4: server-side roles emission pinned by defaultimpl issue_payload tests | REQ-4 | all three per-signer subtests pass unchanged (no server edit) | `go test ./infrastructure/defaultimpl/ -run TestTenantRoles -v` |
| A5: documented in the check usage text | REQ-5 | `sso-ctl check -h` contains `--expect-roles`, `--expect-no-roles`, "absence is tolerated", the defaultimpl-pin sentence; exit 0 | manual/flag-test assertion on usage() output |
| A6 (implied): landmine codified exit 1 removed | REQ-6 | old test replaced by the A1/A2 matrix; no test asserts exit 1 for live-cc + `--expect-roles` | `grep -R 'RolesExpectationFailsOnCC' cmd/sso-ctl/apiclient/` empty |

Targeted verification commands:

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/apiclient/ -run 'TestMint_RolesConditional|TestMint_ExpectNoRoles|TestExitCodes|TestSweep_GreenPath' -race
go test ./infrastructure/defaultimpl/ -run TestTenantRoles -v
go test ./test/ -run TestE2E -v
make ci
```

All targeted tests are httptest-only; no external services. The 11 pre-existing
module failures are baseline (verified) and must be reported separately, never
attributed to this change.

## 7. Non-goals

- No server-side change, no claims-emission change, no config/OpenAPI/
  error-code change.
- No new assertion modes (no subset/containment, no absence-fails under
  `--expect-roles`, no ordering guarantee, no roles assertion on non-mint
  rows, no role resolution in the CLI).
- No changes to `--expect-tenant-id` or other expectation flags.
- No `ops/deploy/*` or CI migration in this direction (callers migrate via
  the loud exit-2 break).
- No rewrite of historical docs (design doc row 16, test-mapping docs) —
  superseded, not rewritten.
