Review complete. All three review axes verified against HEAD with the mandatory gates run fresh. Verdict: the mapping and step ordering are **sound and mostly code-verified, with three concrete defects** (a nonexistent test name that silently no-ops the SDK gate, an unnamed CIBA negative, and an unreported pre-existing gate failure) and one boundary decision (revoke-all) that is correct but unpinned.

## Q1 — All 16 requirements cases map to named, typed tests: YES, with one wrong name

Verified the §3.6 table row-by-row against real code. Every UNCHANGED/SWEEP row names a test that exists at the cited location:

| Verified in code | Location |
|---|---|
| `TestFormEncoded_*` family (9 funcs, incl. `BasicAuthOverridesBodyCreds`:146, `BasicAuthAlsoAcceptedRaw`:163, `ScopeSpaceSeparated`:288) | test/oauth_bind_test.go |
| `TestIntrospect_RejectsMissingCreds`:175, `_RejectsWrongSecret`:187, `_AcceptsBasicAuth`:196 | test/handle_introspect_test.go |
| `TestFormEncoded_JSONStillWorks`:272 (inversion target; JSON post at :276) | test/oauth_bind_test.go |
| All 16 sweep files exist; every JSON post in `test/` targeting a credential path is inside the inventory (full-repo audit below) | test/ |

**Defect 1 — `TestEmit` does not exist.** The case-15 row, §4 verification plan, and the requirements' §10 plan all name `TestEmit` (cmd/gensdk/emit_test.go). The real tests are `TestTSClientAuthenticationOperations`:159 (which pins exactly the four client-auth ops the design must switch), `TestGenerateTS_BalancedBracesAndNoRawTemplateLeftovers`:121, `TestPyFieldName_...`:180. I ran the design's own gate: `go test -run TestEmit ./cmd/gensdk/` → `ok [no tests to run]`, **exit 0**. The step-4 gate as written proves nothing and would pass even if the form emission were never implemented. Fix: name the real tests and use `-run 'TestTSClientAuthentication|TestGenerateTS'`.

**Minor — mfa_test.go line-level omission.** Requirements' inventory cites only mfa_test.go:175, but :200 is a second `/auth/mfa` JSON post. The design's "credential rows only" phrasing and the F1 grep audit catch it, so this is precision drift, not a functional gap.

## Q2 — Endpoint coverage of the inverted test + negative suite: one real gap (CIBA), revoke-all exclusion verified correct

**Verified correct:**
- **Inverted test** → `TestFormEncoded_JSONRejected` (covers `/token`); the remaining 9 endpoints are covered by the new suite. ✓
- **`/token/revoke-all` exclusion is code-correct**: `HandleRevokeAll` at handle_revoke.go:181 does `authenticateRevokeAllBearer` with **no body binding** — there is no parse surface to harden; its tests (test/handle_revoke_all_test.go) post JSON only to `/auth/login`, so "no wire migration" holds. OpenAPI declares **no requestBody** for revoke-all (:1366 block — the form/JSON hits at :1347-1351 belong to `/token/revoke`). One recommendation: the §3.6 table has **no revoke-all row** — the exclusion lives only in §1/§2 prose. Since you asked for revoke-all to be accounted for, add an explicit `UNCHANGED`/`REGRESSION-PIN` row (e.g. `TestRevokeAll*` — bearer-only, body-agnostic) so the table is self-contained.
- **Form-wire 401 pin**: `TestIntrospect_UnauthenticatedForm_401` (NEW) is correctly specified — every *bindable* request reaches the auth gate; JSON 400s are the intended precedence change (T-8(b) vs T-9 resolution is internally consistent).

**Defect 2 — CIBA has no named negative test and is missing from the OpenAPI edit.** `/backchannel-authentication` is the 10th R1 endpoint (handle_ciba.go:87), and R1 mandates JSON → `400 invalid_request`. But: T-8(b) cases 1–4 never mention CIBA; the `JSONRejected` row lists only the 7 non-admin endpoints; `MissingCTRejected`'s description doesn't enumerate the ten; `UnexpectedCTRejected` is scoped to the four main endpoints (correct per T-8(e) case 7's own text). Only requirements case 5 ("any of the ten endpoints") nominally covers CIBA, and the named-test description drops it. **Worse**: openapi.yaml:1584-1607 declares `application/json` on `/backchannel-authentication`'s requestBody, and neither the requirements' nor the design's "seven paths" list includes it — the same-change contract update (step 5, F7) inherits the omission. The OpenAPI edit must be **eight** paths.

## Q3 — Incremental green per step: build/vet YES at all six; maintainability gates green on the change surface but RED at HEAD for an unreported pre-existing reason; "shippable incrementally" is only partially true

**`go build ./... && go vet ./...` — verified clean at HEAD and green at every step.** Step 2 introduces the alias + `server_jar.go` delegate + all ten call-site switches within the same step (no dangling symbols); step 4's regenerated artifacts aren't Go. ✓

**Maintainability gates — green on the B4-4 surface at every step** (verified budgets): oauthwire 6→7 non-test files (≤10), interfaces/sso stays at exactly 60 (no new files — delegate only), no new packages (architecture_layer_test.go untouched), no new subdirs, `bind.go` refactor only reduces complexity, `bind_strict.go`/`BindParamsFormOnly` trivially within 500-line/50-line/15/3 budgets, test-file additions exempt.

**Defect 3 — the gate command is currently RED at HEAD and the design doesn't report it.** I ran `go test -run 'TestMaintainability_|TestArchitecture_' .` fresh: 3 failures, all caused by the campaign's own tracked artifact tree — `TestArchitecture_DirectoryDepth` (227 dirs; `docs/architect-analysis/auto/runs` at depth 5–8, git-tracked, 337 files), `TestArchitecture_DirectorySubdirFanout` (docs 18>16, auto/runs 89>16, root 24>frozen 21). AGENTS.md §5.7 requires reporting pre-existing failures separately; the design's step-6 "none known in the cited surface" is technically true but the implementer following §4 will hit red output and may chase (or worse, "fix") the wrong gate. The design must name this drift explicitly — and the B4-4 change itself never touches it.

**The honest answer on "shippable incrementally":** the six steps are **not six shippable commits**. `go test ./...` (and make ci's `race` target, which runs the full suite) is red at step 2 by design — every JSON-posting test plus the not-yet-inverted `JSONStillWorks`; the suite only goes green at step 3. Between steps 3 and 4 the suite is green but the committed SDK artifacts emit JSON to a server that now 400s (no in-repo test exercises the generated clients — I verified — so nothing catches it). Steps 4–5 don't affect any `make ci` check I could find: `route-contract` only checks route *presence*, `sdk-surface check` only validates operationIds (I read ops/scripts/sdk_surface.py — media types are not part of the registry). So the earliest shippable unit is the full change-set — which is exactly what the design itself claims ("must land together; ordering is commit-internal"), so it is internally consistent, but the premise in your question holds only for build/vet + maintainability, not for the behavioral suite or `make ci`.

## Required fixes before implementation

1. **Name the real SDK tests** (`TestTSClientAuthenticationOperations` + `TestGenerateTS_BalancedBracesAndNoRawTemplateLeftovers`) in case 15 and both §4 verification plans — `-run TestEmit` silently validates nothing.
2. **Add CIBA to the negative suite** — a named JSON-rejection row for `/backchannel-authentication` in `TestCredentialEndpoints_JSONRejected`/`_MissingCTRejected`, and **add it as the eighth OpenAPI path** in step 5 (openapi.yaml:1607).
3. **Add a revoke-all row** to §3.6 (UNCHANGED/REGRESSION-PIN) so the bearer-only exclusion is part of the acceptance table, not just prose.
4. **Report the pre-existing gate failure** (docs/architect-analysis/auto/runs depth/fanout drift) in step 6 per AGENTS.md §5.7, so the implementer attributes it correctly.

No changes to the design's mechanism, ten-site list, sweep inventory (verified complete — my full-repo audit found zero credential-path JSON posts outside the 16 files), or the six-step ordering are needed; the defects are in the mapping's naming/coverage completeness, not in the architecture.
