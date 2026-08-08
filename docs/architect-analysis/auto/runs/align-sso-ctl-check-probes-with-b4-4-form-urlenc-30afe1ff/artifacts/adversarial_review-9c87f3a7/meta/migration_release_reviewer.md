# Review: commit-by-commit gate compliance for align-sso-ctl-check-probes (M1/M2/M4)

## Verdict summary

| Question | Verdict |
|---|---|
| Q1 — `make ci` green at M1 / M2? | **No.** No M1/M2/M4 commits exist at all (HEAD `c970d3d7` is the design meta-commit; the entire sweep — `check.go`, `check_test.go`, `sweep.go`, `token.go`, `apiclient_test.go` — is **untracked working-tree content**, and `git log --all` has no implementation commits). The pre-M1 tree is **already red** (11 failing tests in this package). Simulating M1 faithfully makes it worse: 13 failures, including a regression the design never lists. M2's flip works mechanically but cannot turn the tree green. |
| Q2 — ordering safety of the strict-mode dependency | **Not safe as documented.** The flip is **unowned**: the strict-mode campaign's requirements/design/rollout-review never mention the sso-ctl pin test or the required `newLiveServer` opt-in, and the design's "M2 flips it with zero sweep-side edits" is false — the flip needs two edits inside `cmd/sso-ctl/apiclient/check_test.go`. Ordering is not gate-enforced (strict mode is default-off), so the dependency can silently never consummate. |
| Q3 — M4 rollback byte-identical? | **Binary behavior: yes.** Repo-green at M4: **no** — the enumerated set omits the new tests/harness that must be reverted too. |

---

## Q1 — `make ci` at each intermediate state

**There are no commits to check.** `git ls-tree HEAD cmd/sso-ctl/apiclient/` returns only `apiclient.go`; the sweep files are `??` untracked. The campaign is at design stage. I therefore simulated the planned states in an isolated copy of the working tree (real `sso.NewServer`, real sweep code, no working-tree mutation).

**Baseline (pre-M1) is already red.** `go test ./cmd/sso-ctl/apiclient/` fails 11 tests today, e.g. `TestSweep_GreenPath`: `claims: iss "snaplink-sso" != discovery issuer "http://127.0.0.1:..."` — an unrelated in-flight issuer campaign's change. So `make ci` (which includes `race`) is red on the tree M1 would build on, independent of this campaign.

**M1 simulation (PostForm + five form call sites + runT8b + golden + stub rework + red pin):**
1. The design's core claims hold: T-8b legs against the permissive live server get **200 with a real minted token** (both `text/plain` and absent CT — empirically confirmed), while form-wire mint/T-8d/T-9/post-revoke-introspect stay byte-exact green. So `content_type: FAIL` + exit 1 is real.
2. But the six live-server exit-0 tests **cannot pass at M1**: `TestSweep_GreenPath`, `TestStdoutDeterministic`, `TestMint_ClaimsMatrix`, `TestMint_ScopeContainsRequested`, `TestMint_AudContainsResource` (live subtest), `TestRevoke_RoundTrip` all run `newLiveServer` (permissive) and assert exit 0. The design's claim that they "follow" the golden update is wrong — the golden is the *expected* constant; the *actual* stdout is `content_type: FAIL` + `check FAIL`. The requirements doc even admits it ("TestSweep_GreenPath red at T-8b only", §8 item 6) while asserting these stay green — a direct internal contradiction.
3. **A regression the design never lists**: `TestSweep_3xxTruthinessPasses` breaks — it installs its own `/token` stub handler that mints on any non-empty body, so the new T-8b legs get 200 and fail the row. The design's harness rework (§2.5 `handleToken` T-8b branch) only covers the default handler, not tests that replace `/token` entirely; FM-9/FM-10 don't cover it.
4. The pin test itself (`exit 1, content_type: FAIL, every other row OK`) **cannot pass on the current tree**: mint is red from the pre-existing `iss` mismatch, so "every other row OK" is false.

**M2 simulation (strict credential-CT gate on the live server + pin flipped to green):** the flip mechanics work (`content_type: OK`, exit 0), but the tree remains red on the pre-existing `iss` issue and the 3xx stub collision. `make ci` at M2 is red too.

## Q2 — cross-campaign ordering safety

- **Strict mode is config-gated, default OFF** (`security.strict_credential_content_type`, R1; `WithStrictCredentialContentType()` opt-in, D1). Consequence: repo-level ordering M1→M2 is **not enforced by any gate** — the pin test asserts red against the in-process live server, which stays permissive by default in either order. The "permissive-server window" cannot close by commit order alone.
- **Ownership of the flip is undefined.** Flipping `TestSweep_ContentTypeRowFailsToday` green requires two edits *inside the sso-ctl package*: (a) `newLiveServer` must pass `sso.WithStrictCredentialContentType()`, (b) the pin's assertions flip from red to green. The strict-mode campaign's requirements, design, and rollout-review **never mention sso-ctl, the sweep, or this test** (grep: only unrelated `config validate-schema` mentions). The align design's "M2 flips it with zero sweep-side edits" is only defensible if "sweep-side" excludes test code — and no campaign's committed plan contains those two edits. If the strict-mode change lands without them, the pin stays red-asserting and **green**, `make ci` passes, and the campaign's acceptance ("flips green when the strict-mode server lands") silently never consummates. That is a coordination hazard, not a gate hazard — nothing fails to call it out.
- **Deployment window**: D1/FM-2 (stale toolbelt vs hardened server → loud `mint: FAIL`) is correctly documented as intended with the M3 ship-together constraint — but the strict-mode rollout-review documents the flip-window blast radius and never references the sweep as its verification instrument. The coupling is one-sided: only the align side records it.

## Q3 — M4 rollback revert set

- **Binary behavior: byte-identical — yes.** Reverting the five call sites restores the JSON `Post` wire; reverting the `CheckRun` wiring removes the `content_type` line and restores exit-code semantics; reverting `goldenGreenStdout` restores `"discovery: OK\nmint: OK\ninvalid_scope: OK\nintrospect: OK\ncheck OK\n"`. stdout/stderr/exit codes match pre-M1 byte-for-byte. `PostForm` is additive and behavior-neutral if left in place (dead code). "No persisted state, no config, no server dependency" is accurate.
- **Repo-green at M4: the set is incomplete.** The enumerated "five call sites + runT8b wiring + golden stdout" omits: (a) the pin test and all new `TestSweep_ContentTypeRow*`/`TestSweep_FormWire*` tests — they fail after rollback (they assert `content_type` lines and form-CT recorded requests that no longer exist); (b) `token_contenttype.go` (dead code); (c) `TestPostForm_*` if `PostForm` is removed; (d) the `usage()`/doc-comment text (part of the wiring). The design's M4 text covers the binary; the question's enumeration covers the binary plus golden — but not the tests, so `make ci` at M4 would still be red on the campaign's own new tests (and, on the current tree, on the pre-existing `iss` failure regardless).

## Required fixes before this design can claim gate compliance

1. M1 must move the six live exit-0 tests (`GreenPath`, `StdoutDeterministic`, `Mint_ClaimsMatrix`, `Mint_ScopeContainsRequested`, `Mint_AudContainsResource`-live, `Revoke_RoundTrip`) to the **stub** (which serves the T-8b 400s), keeping only the pin test on `newLiveServer` — or land the T-8b wiring at M2, not M1.
2. M1 must enumerate and fix the `/token`-handler-override collision (`TestSweep_3xxTruthinessPasses` and any stub test asserting exit 0 with a custom `/token` handler).
3. The flip ownership must be written into the strict-mode campaign's plan (opt-in on `newLiveServer` + pin assertion flip), or the align campaign must schedule its own post-M2 flip commit; "zero sweep-side edits" must be corrected.
4. M4's revert set must be documented as including the new tests and `token_contenttype.go`, not just the five call sites + wiring + golden.
5. The baseline red (`iss "snaplink-sso"` from the in-flight issuer campaign) must land before M1 for the pin's "every other row OK" clause and any green-path claim to hold.

Simulation artifacts were created in `/tmp` copies only and removed; the working tree is untouched.
