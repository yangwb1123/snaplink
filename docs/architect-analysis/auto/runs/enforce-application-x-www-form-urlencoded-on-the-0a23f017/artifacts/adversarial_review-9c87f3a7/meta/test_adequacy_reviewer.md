All verification complete. Here is the audit report.

---

# Audit: acceptance mapping for B4-4 credential form-only design (Rev 2)

**Baseline verified**: HEAD `61455c06`; T-8(a-e) re-extracted verbatim from entry 3 of `docs/architect-analysis/auto/analyses/cmd-snaplink-audit-provisioner-7492095d.json` and compared against requirements Rev 2 (§5 cases 1–20) and design Rev 2 (§3.7).

## 1. T-8(a-e) → 20 Given/When/Then: full coverage, no gaps

Verbatim acceptance has five sub-clauses; the mapping is exact:

| Sub-clause (verbatim) | Cases | Verdict |
|---|---|---|
| (a) `/token` JSON CT **or** no CT → 415 + never mints | 1–4 | Covered: JSON incl. charset variant (1), missing CT with JSON body and with empty body (3), no-mint via issuer spy (1), rejection-precedes-auth with valid Basic (2). The "or the documented form-only error" parenthetical is resolved — design pins 415 as the single behavior, so no dangling alternative. |
| (b) form-urlencoded byte-identical | 5–6 | Covered: full family run against both servers (5), refresh rotation arm with single-use (6). |
| (c) `/introspect`, `/revoke`, `/par` behave identically | 7–13 | Covered: JSON 415 + no side effect (7), missing CT (8), 12 unexpected-CT combos (9: 3 CTs × 4 endpoints — arithmetic checks), form byte-identical incl. batch introspect + idempotent revoke (10), T-9 401 gate (11), Basic precedence (12), no-store on all 415/400/401 (13). |
| (d) mode off: JSON tests + bench + SDK compat unchanged | 14–15 | Covered: named pins (14), config append-only-when-set (15). |
| (e) deploy-tree single flip + sweep assertion | 16–17 | Covered: sweep asserts existence-once/absence-everywhere/docs (16), consumer pin (17). |

**Duplicate-assertion analysis** (only near-overlaps found, none true duplicates):
- **Case 10 vs case 5 family**: partial overlap — `TestFormEncoded_Introspect`/`_Revoke`/`TestSdkForm_PARRepeatedResourceKeys` already run on both servers under case 5. Case 10 still adds unique rows: batch introspection (needs `IntrospectionBatchMaxSize`; the harness family never enables it) and strict-vs-default twin comparisons for the three protocol endpoints. Justified, not redundant.
- **Case 6 vs case 5**: `TestFormEncoded_TokenRefreshGrant` (:123, verified) asserts rotation *presence* but not single-use of the old token — case 6's single-use assertion is genuinely new.
- **Case 4 vs case 18** (charset binds): same property at endpoint and unit level — intentional layering, not duplication.
- **Case 2 vs case 12** (Basic): distinct assertions (415-precedence vs Basic-over-body identity); **case 13 vs case 5's no-store check**: 415 rows exist only in case 13 (case 5 compares success rows only); **case 11 vs case 7**: T-9 vs T-8(a) precedence, complementary.

**Verdict: 20/20 cases map to concrete test homes** (verified each in §5 of requirements and §3.7/§5 of design); no acceptance sentence is left without a case, and no case is a strict duplicate.

## 2. Each proposed test file fails against pre-change code — verified

Strict-mode symbols are confirmed unlanded: `grep -r` for `BindParamsFormOnly|WithCredentialFormOnly|require_form_content_type|ErrFormOnly` over all `.go/.yaml/.yml` (excluding `docs/architect-analysis` artifacts) → **zero hits** (grep exit 1).

| File | Pre-change failure mode | Verified |
|---|---|---|
| `protocols/oauth/oauthwire/bind_strict_test.go` | **Compile failure**: `oauthwire.BindParamsFormOnly`/`ErrFormOnly` don't exist (only `BindParams` at bind.go:28). | grep exit 1; `oauthwire` has 6 non-test files |
| `test/credential_content_type_test.go` | **Compile failure** (`sso.WithCredentialFormOnly` absent) **plus runtime failure** if it compiled: JSON on `/token` today binds and mints 200 — proven by green `TestFormEncoded_JSONStillWorks` (:272); all four sites map bind errors to 400, never 415 (server_token.go:33, handle_introspect.go:121, handle_revoke.go:76, handle_par.go:67). | double RED |
| `test/audit_provisioner_form_e2e_test.go` | **Compile failure only** (`WithCredentialFormOnly` absent). Note: its runtime assertions (form mint → 200) would pass on pre-change code — the RED is the missing option symbol, which is correct for a consumer pin that ships with the feature. | documented nuance |
| `test/deploy_form_only_sweep_test.go` | **Runtime failure**: assertion (a) — key missing from `ops/deploy/compose/config.yaml` `server:` block (:9–16, verified); assertion (c) — `docs/config-reference.md` has zero hits for the key. Assertion (b) (absence elsewhere in `ops/deploy/`) trivially holds today. | triple RED |

## 3. Regression coverage: bound + Deps-fake updates are sufficient

**Existing-tests-pass-unmodified bound — all named pins exist at the cited lines and are green at HEAD**:
- `test/oauth_bind_test.go`: `newFormHarness` :28, `TestFormEncoded_BasicAuthOverridesBodyCreds` :146, `JSONStillWorks` :272, `ScopeSpaceSeparated` :288; `bind_extra_test.go` `JSONDefault` :148, `ContentTypeWithCharset` :162; `bind_bench_test.go` :74/:89; `credential_sdk_form_test.go` `TestSdkForm_*` :69/:111/:150; `handle_introspect_test.go` `RejectsMissingCreds` :175, `RejectsWrongSecret` :187, `AcceptsBasicAuth` :196.
- Ran: `./test/` (TestFormEncoded_|TestSdkForm_|TestIntrospect_|TestRevoke_|TestPAR|TestScopeRegistry|TestCIBA), `./protocols/oauth/` (bind pins), `./oauthwire/` full — **all pass**, except `TestSdkForm_PARClaimsThreaded`, which is **confirmed deliberately RED with an in-file "must never be skipped" declaration** (credential_sdk_form_test.go:8–13, :196–200) — sibling condition, correctly disclosed as not ours.
- The mode-off byte-identical baseline is structural, not asserted-only: seeded `false` in `NewServer` (sso.go:58–80 seeds pattern verified), nil config appends nothing (`anySet()` precedent at config_load.go:342–345 verified), `bindCredentialParams` falls through to `bindOAuthParams` (server_jar.go:304). `bindOAuthParams`'s other five callers (device :53/:242, mfa :255, admin :414/:293) stay untouched — verified.

**Deps-fake updates — complete, exactly three fakes**: `IntrospectDeps` (:29), `PARDeps` (:18), `RevokeDeps` (:16) have exactly four implementors repo-wide: `*sso.Server` (production, `handlers.go:35/99/104` pass `s`) and three compile-time-asserted fakes — `var _ IntrospectDeps = (*introspectDeps)(nil)` (handle_introspect_test.go:78), `PARDeps` (:38), `RevokeDeps` (:58). `RoutesDeps` (grant_handler.go:36) embeds the three but has no other implementor (grep-verified). So the new member breaks exactly the three fakes + `*sso.Server`; the design's list matches reality with no omissions. Fakes returning `false` keep every protocol-layer unit test on the dual-mode path — byte-identical.

**Residual risks (accepted, disclosed in design, confirmed consistent)**:
1. The strict branch of the three protocol handlers is exercised only by the new `test/` endpoint tests (fakes stay false) — the same code path via the real server, so coverage is real, not absent.
2. Case 12's strict-mode Basic-precedence rows on the three protocol endpoints are only *implicitly* in the design's §3.7 file description ("form byte-identical rows") — a documentation imprecision, not a coverage gap.
3. `oauthwire` budget: 6 → 7 non-test files (≤10 ✓); `interfaces/sso` at exactly 60 files (no new files ✓); `bind.go` 158 lines as disclosed.

**Overall verdict: the acceptance mapping is sound** — T-8(a-e) is fully covered by 20 non-duplicative cases, each with a concrete test home; all four proposed test files are RED against HEAD (three compile-level, one behavioral, one both); the unmodified-existing-tests bound is real and verified green at HEAD, and the Deps-fake update set is provably complete. The only caveats are the two minor documentation-level imprecisions noted above (case-12 file attribution, audit_provisioner e2e RED mechanism being compile-only) — neither affects implementation correctness.
