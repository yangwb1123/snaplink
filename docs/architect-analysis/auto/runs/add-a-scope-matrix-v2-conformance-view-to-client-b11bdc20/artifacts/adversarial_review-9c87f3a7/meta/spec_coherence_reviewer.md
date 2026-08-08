# Re-verification report: post-edit deliverable state

**Headline finding: the six boundary edits were never applied.** The deliverable (`docs/architect-analysis/cmd-sso-ctl-clientscmd-scope-matrix-conformance-requirements.md`, untracked, 401 lines) is still the pre-review version. Every one of the six scope_security_reviewer edits is absent, as are the test_design_reviewer corrections (E3 client, FM-1/3/5/7 tests, stdout-empty assertions) and the cli_contract_reviewer F1 fix. The sections "agree with each other" only in the vacuous sense — they all consistently carry the same unqualified runtime-agreement framing the edits were meant to replace. All claims below were re-measured against the current tree (see provenance caveat at the end).

## 1. The six boundary edits — all absent

| # | Required edit | In doc? | Evidence |
|---|---|---|---|
| 1 | Static-conformance reframe (§2 marker + §10.3) | **No** | §2 still reads "a scope the CLI rejects is exactly a scope `/token` would 400 for, and a matrix member the CLI accepts is exactly a scope `/token` would mint" — unconditional. §10.3 still guarantees "cannot introduce a check that passes while runtime mints 400 (or fails while runtime mints 200) for built-in-matrix deployments" — no `registry-enabled` qualifier. Grep for "static conformance"/"target-state"/"pre-enablement": 0 hits |
| 2 | Registry-enabled axis (new FM row) | **No** | FM table still FM-1..FM-7; nothing for `enabled: false` (the default). `build_stores.go:295-314` wires the registry only inside the `Enabled` branch; `reject.go:31-42` is a nil-registry no-op — so on the default deployment `validate` exit 1 for `billing:typo` while `/token` mints it. The one "enabled" mention is §2's config-knob naming |
| 3 | False-pass quadrant (FM-5 both directions; §3 non-goal) | **No** | FM-5's Mode says "or drops built-ins" but Behavior/Rationale describe only false positives. Provisioned matrix is full replacement (`scope_registry_wiring_test.go:78-90`: `admin:read` NOT registered) — a provisioned matrix dropping `metering:*` yields CLI exit 0 while `/token` 400s: the tool masking exactly the drift it exists to catch, CI green. Unlabeled |
| 4 | Version-skew note (§8.5) | **No** | §8.5 covers wire shape only ("both directions safe — reads only the existing admin endpoint"). The matrix is compiled into both binaries and expected to grow (`config/scope_registry_test.go`: "after billing:checkout:create joins the built-in table") — a mixed-version fleet gets both false directions. No mention |
| 5 | Mitigation honesty (FM-5/FM-7) | **No** | Still "operators on provisioned deployments gate with `config validate` + `sso-ctl check` T-8d". Measured reality: `validateScopeRegistry`'s client-membership step runs **only when `enabled: true`** and only over config-declared clients (`config/config_oauth2.go:30-77`); T-8d's 400 is allowlist-or-registry ambiguous (`token.go:376`) and checks neither client scopes nor registry wiring for non-empty-allowlist clients. Admin-registry clients on provisioned deployments have **no correct offline gate**; the effective-registry admin surface is never named |
| 6 | FM-2 oracle sentence | **No** | FM-2 row is only "matches `get`; distinct from usage (2)". The reasoning is sound and verified (`grpcadmin/admin_clients.go`: Get 404s only on `ErrNoSuchClient`; inactive clients return 200; 401 precedes the handler; same `admin:read` class already holds `list`) — but the sentence is absent |

## 2. Coherence of the five named sections

They are internally consistent **with each other** — §2 marker ↔ §10.3 guarantee are the same claim in two voices; FM-5/FM-7 ↔ §3 non-goal share the identical "covered by `config validate` + `check`" mitigation; §8.5's "both directions safe" is the only version statement and doesn't contradict §2 (wire shape only). So the requested agreement check passes trivially — and fails against the required post-edit contract on every one of the five sections.

Two genuine internal tensions worth flagging:

- **§2 vs §3/FM-5 coverage claim.** §2 says `config validate` covers "config-declared clients only, never the admin-registry state the CLI surfaces"; §3/FM-5 then say provisioned deployments "are covered by `config validate`". Only §3's parenthetical "(config-declared clients)" reconciles them — for the CLI's actual target population (admin-registry clients), the claimed coverage does not exist, and on `enabled: false` `config validate` runs no client-membership check at all.
- **All mitigation instructions name an unreachable CLI surface.** §3, FM-5, FM-7, and the §9 posture paragraph say "gate with `sso-ctl check`" — but `"check"` is absent from `main.go`'s `subcommands` map and `TestSubcommands_CheckIsWired` **fails** (I ran it: `dispatch_test.go:21`). The doc never notes the dispatch gap (F3 unaddressed).

## 3. U1-U9 / E1-E3 mapping — corrections and additions absent

- **E3 client choice — still wrong (verified end-to-end).** E3 uses `client-v` with no `--scope`. Measured path: `CheckRun` → `mint()` omits `scope` when empty (`token.go:21-42`) → server `GrantedScopes` rule 4 defaults to client-v's allowlist minus openid = `[profile, billing:typo, admin:read]` → cc branch `RejectUnregistered` 400s `billing:typo` (`token_client_credentials.go:46`) → `mint: FAIL` → `check FAIL`, exit 1. The doc's Then ("`invalid_scope: OK` — keeps the live probe green") is **false as written; the sweep is red**. The corrected choice (client-m: rule-4 default = all 9 matrix rows → all registered → mint 200) is absent.
- **FM-1/FM-3/FM-5/FM-7 tests — absent.** U-table is U1-U9 only: no closed-port/timeout (FM-1), no garbage-response (FM-3), no provisioned-matrix fixture (FM-5), no `extra_scopes` fixture (FM-7). FM-4's unreachability is honestly labeled, so no claim there.
- **stdout-empty-on-failure assertions — absent.** U4/U5/U6/U7a/E1a assert stderr content only; §7's "stdout carries only `validate: OK` (script-safe)" half is unpinned. `captureStdoutAndStderr` already exists in the package (`e2e_test.go:150`), so the fix is trivial — but it isn't there.
- **R3 triple — still sound, but only for the exactness class.** E1a/E1b/E1c/E2a/E2b re-verified against code: the registry-wired fixture mirroring `newCLIDeployment` is implementable (`srv.Handler()` at `/`; `WithScopeRegistry` at `options_misc.go:494`); A-1b pin is trimmed byte-identical `{"error":"invalid_scope"}` with no-trace_id (`test/scope_registry_test.go:205`); `admin:read` passes via `admin:*`; all 9 rows mint. The triple proves agreement on the enabled+built-in+no-extras+same-version class — which is exactly what the reframe would claim — but §2/§10.3 generalize it beyond the class.
- **U7b tension (minor, unaddressed).** R1's preamble says "mirror `runGet`'s fetch path exactly"; `runGet` ignores trailing args, so `Run(["validate","c1","--nope"])` → exit 2 requires a `len(args)>1` guard R1 never specifies (F5's one-sentence fix absent).

## 4. Sections still implying runtime agreement on the default (registry-disabled) deployment

- **§2 completion marker** — unqualified; false on default-off deployments in both directions.
- **§10.3 adoption guarantee** — "built-in-matrix deployments" lacks the `registry-enabled` qualifier; on default-off, adopting `validate` *does* introduce a check that fails while runtime mints 200.
- **§3 non-goal** — "covered by ... the T-8d live probe (`sso-ctl check`) at runtime; operators must gate with `check` instead".
- **FM-5 / FM-7 rationales** — "gate with `config validate` + `sso-ctl check` T-8d" / "covered by the T-8d probe at runtime".
- **FM-6** — "T-8d probes it live" is only true for unrestricted probe clients; on a non-empty-allowlist client (client-v, E3) the allowlist rejects the probe first, so T-8d passes wired *or* unwired.
- **§9 posture paragraph** — "both of which are covered by `check` T-8d at deploy time".

## 5. Tests claimed to cover a quadrant they cannot reach

- **E3 is the one. Two failures:** (a) it cannot reach its own Then — the sweep is red on client-v, so it would fail, not assert "green"; (b) its T-8d half cannot detect registry wiring on client-v (allowlist rejects the random probe first — `token.go:376` ambiguity), so even a passing T-8d proves nothing about the registry. Everything else is reachable as written: U1-U9 and E1a-E2b verified against the seams; FM-4's unreachability is honestly labeled.

## 6. Also still open from the other reviewers

- **F1 (factual error in the spec):** §3 and §7 say credentials are `SSO_ADMIN_TOKEN` + `SSO_ADDR`; the env is `SSO_ADMIN_ADDR` (`apiclient.go:27`; zero `SSO_ADDR` hits in the repo). The U/E tests set `apiclient.EnvAddr`, so the table would mislead implementers.
- **F2:** offender-line shape still `sso-ctl clients: validate: scope ...` — cosmetic, unpinned, undecided.
- **F4:** §1's "8 structural aliases (commerce ×5...)" mislabels the split — the commerce const block has 5 consts, 2 of which are admin; actual: admin×2 + commerce×3 + metering×2 + wildcard×1 + audit literal. Cosmetic.
- **Provenance caveat:** the §1 "measured against HEAD" table cites files that are **untracked working-tree files** (`interfaces/scopecontract/consts.go`, `protocols/oauth/scoperegistry/*`, `apiclient/{check,token}.go`, `test/scope_registry_test.go`, `cmd/sso-server/scope_registry_wiring_test.go`, `config/scope_registry_test.go`, `clientscmd/e2e_test.go`); at HEAD (`3223d12a`), `build_stores.go` has **zero** `ScopeRegistry` references — the entire scope-matrix-v2 server feature is uncommitted. I ran the oracle suites in the tree (`./test/ -run TestScopeRegistry`, `TestBuildApp_ScopeRegistry*`, `TestValidateScopeRegistry`): all green, so "pre-existing, cited not re-created" holds for the tree but not for HEAD.

## Gates run (current tree)

`go build ./...` + `go vet ./cmd/sso-ctl/...` pass; `clientscmd` suite green (E-4/E-5/E-6 floor holds); `TestSubcommands_CheckIsWired` fails (pre-existing F3); scope-registry oracle suites green.

**Verdict:** the deliverable is not in the post-edit state the task premises — none of the six boundary edits (nor the E3 correction, FM-1/3/5/7 tests, stdout-empty assertions, or F1/F3 fixes) exist in the file, and the R3 triple/E3 mapping as written does not prove the revised claims because E3 is broken. The doc needs the six edits plus the E3 client-m fix applied before the coherence claims hold; say the word and I'll apply them.
