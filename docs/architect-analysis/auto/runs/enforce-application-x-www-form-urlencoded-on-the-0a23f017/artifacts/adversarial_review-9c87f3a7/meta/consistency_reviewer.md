All checks are complete. Here is the cross-check report.

---

# Cross-check: Design Rev 3 vs. earlier reviews

**Baseline verified**: HEAD `3ef27fa5`; `go build ./...` clean (matches the Rev 3 header claim). Rev 2's full text is unrecoverable (the design file is untracked and was overwritten; memory index has no payload for the design session), so Rev 2's tables are reconstructed from the three reviewer artifacts + the task-1 deliverable summary — all present in the run's `artifacts/adversarial_review-9c87f3a7/meta/` — and checked against the tree.

## 1. D1-D6 pins + §3.7/§5/§8 amendments: 20-case mapping and four-site scope PRESERVED

Cross-checked case-by-case against requirements Rev 2 §5 (the canonical 20 cases):

| Cases | Rev 3 §3.7 home | Verdict |
|---|---|---|
| 1–4 (T-8(a)) | `TestStrictToken_JSONRejected/MissingCTRejected/BasicAuthStill415/CharsetParamBinds` + D1–D3 rows | intact |
| 5–6 (T-8(b)) | existing `TestFormEncoded_*`/`bind_extra`/`TestSdkForm_*` unmodified + `TestStrictToken_FormByteIdentical` (refresh-rotation arm) | intact |
| 7–13 (T-8(c)) | `TestStrictIntrospect/Revoke/PAR_*` (415, missing-CT, 12 CT combos = 3×4, form byte-identical incl. batch + idempotent revoke, T-9 existing introspect tests, no-store) + D1–D4 | intact |
| 14–15 (T-8(d)) | `JSONStillWorks`/`JSONDefault`/bench:89 unmodified + `TestServerOptions_AppendOnlyWhenSet` | intact |
| 16–17 (T-8(e)) | `TestDeployTreeRequireFormContentTypeSingleFlipPoint` (R6 a/b/c) + `TestAuditProvisionerPlatformTokenSourceStrictServer` (R7 identity/scopes, 200 + Bearer) | intact |
| 18–20 (unit) | `bind_strict_test.go` + `FuzzBindParamsFormOnly` + constant-time `-race -count=10` re-runs, +D5–D6 | intact |

Sum 4+2+7+2+2+3 = **20 — no case dropped, none replaced**: D1–D6 are additive rows appended to the existing cases, and every D-pin row stays on the four endpoints or the shared unit binder (§3.8 rows cite only `/token` + the three protocol sites; D2's `%ZZ`/`invalid_grant` rows are `/token` rows). §5's file list is the same four test files as Rev 2 plus `bind_strict.go`, with D-rows folded into the existing files (`oauthwire` 6→7 non-test, `interfaces/sso` stays at 60). §8's verification plan is consistent with §5 names (adds `TestStrict`, `TestAuditProvisionerPlatformTokenSource`, `TestDeployTreeRequireFormContentType` vs requirements §10). Four-site scope is intact everywhere: §3.1 table, §3.4, §3.7, §3.8, §5 Modify/Do-not-modify, §8. I re-verified the key line anchors: `IntrospectDeps` at :29, no-store stamps :22/:112/:68/:182/:55, bind sites :30/:120/:75/:66, fakes at `handle_{introspect,par,revoke}_test.go:78/:38/:58`, `WithMaxTokenBytes` :103, `ServerOptions()` :301/`anySet()` :345.

## 2. The four oauth-review caveats: three addressed, one carried forward unaddressed

1. **Status-code split (plain `core.ErrorBody` 415 vs trace-aware 400 on `/token`) — ADDRESSED.** Rev 3 §3.3 explicitly pins and justifies: "Deliberately not the trace-aware `errorBody`: per-request trace variance would break the byte-identical-across-sites pin," D1 test-pins the exact bytes, and the hardening artifact documents the asymmetry as observability, not oracle. Residual nicety only: the reviewer's "worth keeping in the openapi description note" client-mapping sentence ("map both 415 and 400 → `invalid_request`") is not spelled into §5's openapi entry — it stays generic ("description notes on the four credential paths").
2. **415-vs-401 on introspect/par — ADDRESSED (retained with justification).** §3.3 restates parse-before-auth explicitly ("unauthenticated JSON introspect 415s at the parse stage (T-8(a)); every bindable form request still reaches the `401 invalid_client` gate (T-9); client-auth-before-parse is rejected (C3)"), and §3.7's T-8(c) row preserves the T-9 pin via the unmodified `TestIntrospect_RejectsMissingCreds/_RejectsWrongSecret/_AcceptsBasicAuth`. This is retention-with-justification (media-type-deterministic, not a credential oracle) — the acceptable disposition.
3. **"44 dual-mode sites outside the four" — NOT ADDRESSED, no explicit rejection.** The phrase survives verbatim in §3.4. My tree count at HEAD: **40 direct `BindParams(` call sites** (42 grep hits − `bind.go` def − `server_jar.go` alias body) **+ 6 `bindOAuthParams(` call sites** (7 − def; device :53/:242, mfa :255, two admin sites, token :30) **= 46 total, 42 outside the four** — and the reviewer's own arithmetic (40+4=44) itself missed the two admin alias sites. Either way "44 … outside the four" is numerically loose. Substance correct, zero risk, but this is the one caveat with no trace in Rev 3 — a two-word fix ("42" or "all dual-mode sites except the four").
4. **Device-grant scoping misread — ADDRESSED.** §3.1's `/token` row explicitly enumerates "all grants: authcode, refresh, **device**, cc, exchange, delegation" (device/CIBA exchanges are inside the flip), and §3.4 now names the four dedicated endpoints (`/device/code`, `/device/verify`, `/auth/mfa`, `/backchannel-authentication`) as NOT flipped with the "(direction acceptance names four endpoints)" qualifier; T-8(a)'s issuer-spy "zero issuance" rows cover every grant including `device_code`. The reader-misread is resolved.

## 3. Failure-mode and test-file tables: internally consistent across Rev 2 → Rev 3

- **F-table**: F1–F9 numbering is stable. Rev 2's set (415 envelope oracle safety, malformed-`%ZZ`-not-`ErrFormOnly`, double-flip-point drift guard, RED `TestSdkForm_PARClaimsThreaded`) maps 1:1 onto Rev 3's F1/F5, F6, F3, F9 — confirmed by the oauth reviewer's own Rev-2-era reference to "F6" for the `%ZZ` boundary and the task-1 summary's F1–F9 list. Every F-row guard cross-references case numbers that exist in §3.7 and file names that exist in §5: F1→1–3,7–9; F2→3,8; F3→case 16/`TestDeployTreeRequireFormContentTypeSingleFlipPoint` (same name in §3.7 and §5); F5→unit 18 + 1–3,7–9; F6→unit 18; F7→case 15; F9→C8 + the comment-only `credential_sdk_form_test.go:8-9` change in §5. No dangling references.
- **Test-file table**: same four Create files as Rev 2, same Modify set (fakes update included, verified at the real assertion lines), D-rows additive only. The one Rev 3-internal nit: §3.8's intro says the D1–D6 "four-digit row labels are the new test functions in `test/credential_content_type_test.go`" — true for D1–D4; D5–D6 live in `oauthwire/bind_strict_test.go` and `bind_fuzz_test.go` (as §3.7 and the D5/D6 rows themselves correctly state).

## Non-blocking observations (unchanged from Rev 2, carried into Rev 3)

- §3.7 T-8(b) cites `TestFormEncoded_*` :146/:272/:288 "run against both modes" — :272 (`JSONStillWorks`) is a mode-off-only pin; inherited from requirements case-5 phrasing and resolved as success-rows-only by the test-adequacy review.
- The T-8(b) row's enumeration drops the requirements' case-5 mentions of `scope_registry_test.go`/`ciba_*` (neither §10 plan runs them either); form-wire substance is covered by the cited family. Documentation terseness, not a dropped case.
- Case 12's strict-mode Basic-over-body rows on the three protocol endpoints remain implicit in "form byte-identical rows" (test-adequacy reviewer's residual risk #2); Rev 3's D3 adds the explicit Basic-415-precedence row on `/token` but not the protocol-endpoint identity rows.

**Bottom line**: the hardening pass is faithful — 20/20 cases and the four-endpoint scope survive the D1–D6/§3.3/§3.7/§5/§8 amendments; caveats 1, 2, and 4 are addressed with justification; caveat 3 (the "44 sites" phrase in §3.4) is the single item neither corrected nor explicitly rejected — recommend a two-word fix at implementation time.
