All checks complete. Here is the verification report.

# Verification: flip ownership and cross-campaign claims

## A. Strict-mode campaign owns the flip? — **NO**

I checked every strict-mode-campaign document (requirements, design, rollout-review) in both related runs, plus the delivered docs. The two `check_test.go` edits are filed **nowhere**, with **no named owner anywhere**:

**Run `enforce-application-x-www-form-urlencoded-on-cre-8a92c453` (billing, the campaign you named):**
- `requirements-10762e10/requirements.md` (04:55) — its caller sweep (R5.1/C5) covers `test/`, `interfaces/sso`, `protocols/oauth`, gensdk. **Zero mentions** of `cmd/sso-ctl`, `check_test.go`, `newLiveServer`, the pin, or any owner.
- `design-a77de8a6/task-1-design.md` / delivered `cmd-snaplink-billing-b4-4-credential-form-only-design.md` (05:07) — the only `sso-ctl` string is a pointer to an unrelated sibling (`cmd-sso-ctl-entitiescmd-b4-4-*`, :12). No flip, no owner.
- **No rollout-review artifact exists in this run** (pipeline: requirements → design → adversarial_review → design_gate). The `design_gate` verdict (05:23) is **FAIL** with blocking findings unresolved — the campaign is not even approved.
- The only related text lives in *meta reviewer artifacts* (`migration_revalidation.md:68-74`, `migration_plan_reviewer.md:13`): "the four legs … 400 against strict at runtime — disclosed as a shipped-consumer breakage **for the WIP owner to convert before landing**". That is (a) unnamed, (b) about the four *production* legs converting to form, **not** the two test edits, and (c) an internal review note, not the campaign's requirements/design/rollout-review.

**Run `enforce-form-urlencoded-credential-strict-mode-0a8df02f` (the default-off opt-in design the align side's M2 pins on):**
- requirements (R2/R3/AC-1..AC-6), design, and the rollout-review (`task-1-rollout-review.md`) mention sso-ctl **only** as `sso-ctl config validate-schema` pre-flight (D-3). The sweep, the pin test, `newLiveServer`, and both edits never appear. `verify-amendments` adds counters/boot-log/convergence — still no flip filing.

**Knob polarity divergence (compounding):** 8a92c453 proposes `sso.WithCredentialFormOnly(bool)` **default true** (breaking); 0a8df02f proposes no-arg `sso.WithStrictCredentialContentType()` **default off** — the polarity your premise assumes. The align design's M2 names 0a8df02f as the flip dependency while you name 8a92c453 as "the strict-mode campaign". Under either polarity "zero sweep-side edits" is false: default-off needs both edits (fixture opt-in + expectation flip); default-true needs at least the expectation flip (and an opt-out if the fixture must stay permissive). The hazard you cite stands either way: with default-off, no gate enforces M1→M2, so the pin test can sit green-asserting-red forever with `make ci` green.

## B. Align design's "zero sweep-side edits" / "stays green throughout" — **NOT corrected**

Verified against `cmd-sso-ctl-b4-4-check-probes-form-design.md` (05:53, unmodified since; untracked):
- §5 M2 still reads: "flips `TestSweep_ContentTypeRowFailsToday` to green **with zero sweep-side edits**" (line ~250) — unchanged.
- §5 M2 still reads: "`TestSweep_GreenPath` **stays green throughout**" (line 252) — unchanged, and contradicted by the requirements' own §8 item 6 parenthetical ("`TestSweep_GreenPath` red at T-8b only").
- §5 M1 still describes only the pin as red-today. No enumeration of the 7-test red set (6 live exit-0 tests: `GreenPath`, `StdoutDeterministic`, `Mint_ClaimsMatrix`, `Mint_ScopeContainsRequested`, `Mint_AudContainsResource`-live, `Revoke_RoundTrip`; plus `TestSweep_3xxTruthinessPasses`, whose custom `/token` stub mints for T-8b legs — `check_test.go:691-724`, a collision the §2.5 harness rework does not cover). `TestSweep_3xxTruthinessPasses` appears in **neither** align document.
- The M1 premise "every other row OK" is still stated without the fixture `iss` fix. I re-ran the baseline: `go test ./cmd/sso-ctl/apiclient/` fails **11 top-level tests today** (iss mismatch on all six live tests, plus `TestCheck_AddrValidation`, `TestSweep_TokenEndpointSuffix`, `TestSweep_AdvertisedURLRejection`, `TestMint_ResponseFail/status-400`, `TestIntrospect_Non401Fails/wrong-bytes`) — matching the reviewers' M0 count. So neither the pin's "all other rows OK" nor any "stay green" claim can hold without pre-landing the issuer fix.

## C. M4 revert set — **NOT corrected**

- Design §5 M4: "revert the five call sites and the `runT8b` wiring" — only.
- Requirements §9: "revert the five probe call sites + `runT8b` wiring" — only.
- Both still omit: the new tests (`TestSweep_ContentTypeRow*`, `TestSweep_FormWire*`, `TestPostForm_*`), `token_contenttype.go` (dead code post-rollback), and the `usage()`/doc-comment text. `make ci` at M4 would still be red on the campaign's own new tests.

## D. Ship-together constraint — **NOT consistent (one-sided)**

- Align side: documented (D1, §5 M3: "ship the updated `sso-ctl` binary and the hardened server together"; stale toolbelt → loud `mint: FAIL`).
- 0a8df02f rollout-review: documents the flip-window blast radius, drift convergence, rollback paths — **never references the sweep as its verification instrument or the binary ship-together**.
- 8a92c453: default-true breaking design; its own requirements/design state no ship-together constraint with the sso-ctl binary; only the meta migration reviewers disclose the WIP runtime breakage, and the design_gate is FAIL.

## Required corrections (still outstanding)

1. File into the strict-mode campaign's requirements/design (and its rollout-review, which does not exist in 8a92c453 and must be added, or the 0a8df02f rollout-review amended): edit (a) `newLiveServer` opt-in to `sso.WithStrictCredentialContentType()` (or the actual shipped knob, resolving the 8a92c453/0a8df02f polarity conflict first) and (b) the pin expectation flip to exit 0 / `content_type: OK`, **with a named owner** and a commit-ordering note.
2. Correct align design §5 M2: delete "zero sweep-side edits" and "`TestSweep_GreenPath` stays green throughout"; enumerate the M1 red set (7 tests + pin) and the M0 issuer prerequisite.
3. Correct align design §5 M4 + requirements §9: include the new tests and `token_contenttype.go` in the revert set.
4. Reconcile ship-together in the strict-mode rollout-review (reference the sweep as the flip/rollback verification instrument) and resolve which strict-mode knob polarity is authoritative before either campaign implements.

VERDICT: FAIL - The strict-mode campaign (both 8a92c453 and 0a8df02f runs) still files neither check_test.go edit with a named owner (8a92c453 has no rollout-review and a FAILed design gate; 0a8df02f's rollout-review mentions only config validate-schema), the align design's "zero sweep-side edits" and "TestSweep_GreenPath stays green throughout" claims are unchanged and contradicted by its own requirements (M1 red set is 7 tests + pin, baseline already red on 11), the M4 revert set still omits the new tests and token_contenttype.go, and the ship-together constraint is recorded only on the align side while the two strict-mode campaigns disagree on knob polarity (default-true vs default-off).
