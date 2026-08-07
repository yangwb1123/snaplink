Design-gate deliverable written to `docs/architect-analysis/auto/runs/b4-4-enforce-application-x-www-form-urlencoded-o-6bd46522/artifacts/design_gate-8351f253/task-1-design-gate.md`.

## Verification summary

The design was never amended: `design-6bd46522/task-1-design.md` (11:13:44) predates all three reviews (11:22–11:24); `design-a77de8a6` is a 17-line stage-pass summary. I re-verified every finding at HEAD `18c94576`:

1. **PAR json.RawMessage — UNRESOLVED.** `parRequestForm.AuthorizationDetails/Claims` are `json.RawMessage` (handle_par.go:100,105); `setFormField` silently skips them (bind.go:126–150); `ValidateAuthorizationDetails` treats empty as no-RAR (rar.go:154–156). Design has zero mentions; "assertions unchanged" is false for `test/handle_par_test.go:394–405` and the 6 JSON RAR posts in `protocols/oauth/handle_par_test.go`. Neither the fail-closed binder path nor a documented contract-loss exclusion exists.
2. **handleDeviceVerify no-store — UNRESOLVED.** Verified: only `handleDeviceCode` (:42) calls `tokenNoStoreHeaders`; the verify handler's 401/400 paths have none. Design §0/§1.4 claim "all 10" with 9 refs; the one-line fix is absent.
3. **Migration scope — UNRESOLVED.** Design step 5 covers `test/` only. Independent counts: `interfaces/sso/` 48 files / ~90+ seam-targeting `rcovPostJSON` calls; `protocols/oauth/` 27 `ContentTypeJSON` posts; plus the `test/` surface.
4. **Commit split — UNRESOLVED.** `make ci`'s `race` runs `go test -race ./...` including `ssotest`, so step 1 alone breaks `TestFormEncoded_JSONStillWorks` (test/oauth_bind_test.go:272). Steps remain 8-way split; the fuzz-same-commit note contradicts steps 1 vs 4 and omits compat inversion + AGENTS.md:113 + openapi.
5. **Fuzz claim — UNRESOLVED.** Design still asserts the old target "is expected to fail"; `bind_fuzz_test.go:81` calls the package-local `BindParams` alias, which the design itself keeps dual-mode — it cannot fail (coverage, not gate, is at stake).
6. **SDK MFA — UNRESOLVED.** `MFACompleteRequest.params` (client.py:826) / `mfaCompleteRequest.Params` map (server_mfa.go) has no form case; step 7 never specifies flat `code`/`assertion` encoding.

The no-store acceptance row (§5) is unsatisfiable for the device class, and the §1.3 behavior table omits the RawMessage/map field-level loss. Confirmed-correct items (variant architecture, openapi 10 ops, SDK 7 methods, exclusions, 400-over-415) don't cure the six.

VERDICT: FAIL - all six blocking findings (PAR json.RawMessage silent drop with no binder path or documented exclusion, missing tokenNoStoreHeaders in handleDeviceVerify, migration scope still covering only test/ while interfaces/sso and protocols/oauth hold ~90 and 27 seam JSON posts, no gate-clean A/B/C commit split with compat inversion + AGENTS.md + openapi in commit A, the uncorrected "fuzz expected to fail" claim, and unspecified SDK MFA flat-field encoding) are confirmed in code at HEAD, absent from the audited design, and neither resolved nor explicitly rejected, so the design is not ready for implementation and must be amended per the reviewers' required updates.
