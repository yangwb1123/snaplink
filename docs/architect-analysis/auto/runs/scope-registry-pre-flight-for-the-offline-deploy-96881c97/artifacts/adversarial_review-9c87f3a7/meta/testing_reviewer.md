# Review: acceptance-to-test mapping for the scope-registry pre-flight (REQ-5/REQ-6, T-2/T-8d/T-9, F1–F12)

I re-verified every mapping against HEAD, traced the `/token` flow line-by-line, and checked the existing registry integration suite for overlap. **Verdict: the mapping is structurally sound and the D2 repair is necessary — but D2's stated mechanism is wrong, one runtime predicate the acceptance depends on is pinned by no test anywhere, and four unit-test fixtures as specified would be masked or spuriously fail.**

---

## 1. The D2 mechanism is misstated — the repair is still required, for different reasons

The design (§1 D2, §7.3) claims the negative leg with a *clean* allowlist would 400 via the allowlist gate (`GrantedScopes` rule 1), masking the registry seam. **Tracing the code disproves this:**

- `dispatchTokenGrant` calls `s.rejectUnregisteredScopes(ctx, scopes)` on **request-borne** scopes at `server_token.go:132`, before `dispatchGrantBranch` (:152) — and `GrantedScopes`/allowlist rule 1 lives inside `HandleClientCredentialsGrant` (`token_client_credentials.go:38`), which only runs after the seam.
- With the registry wired (as REQ-6 specifies, `sso.WithScopeRegistry(reg)`), `scope=legacy:menu:1:view` is rejected at the seam **regardless of the allowlist contents**. The allowlist gate never executes. The 400 body is byte-identical either way.

The dirty allowlist is nonetheless **required**, but its real rationale is regression sensitivity:

1. **Extra-reconciliation leg cannot return 200 without it.** Clean allowlist + `legacy:*` registry: the seam passes (registered), then `GrantedScopes` rule 3 rejects (`token_client_credentials.go:38` → `scope.go:113-121`) — the 200 the leg asserts would never happen. The dirty allowlist is load-bearing for the positive leg.
2. **Negative leg's failure-detection property.** With a clean allowlist, deleting the registry wiring (or the seam) leaves the allowlist gate emitting the identical 400 → test stays green → the regression is masked. With the dirty allowlist, deleting the seam/wiring → allowlist admits → post-resolution check no-ops → 200 → test fails. The dirty shape is what makes the negative leg *fail when the gate regresses* — which is exactly the review criterion.

**Action:** keep the repair; correct the rationale in §1/§7.3 (the 400 comes from the seam in the wired case; the masking is the allowlist gate's *fallback equivalence*, not its precedence). Also add the empty-scope leg (finding 2), which needs the dirty allowlist for the same reason.

## 2. Material gap: the post-resolution effective-scope check is pinned by no test anywhere (REQ-6)

The requirements' own motivation scenario is: *"an unregistered entry is minted by default and then rejected by the registry seam"* — empty request → `GrantedScopes` rule 4 defaults to the dirty allowlist minus `openid` (`scope.go:90-101`) → post-resolution `RejectUnregistered` (`token_client_credentials.go:46`) rejects.

All three designed REQ-6 legs send an **explicit `scope`**, so every rejection/acceptance resolves at the *dispatch seam* (`server_token.go:132`). If `token_client_credentials.go:46` were deleted, all three legs stay green (negative: seam still 400s; positive/extra: 200s). I checked the existing suite: `test/scope_registry_test.go` has only a matrix-allowlist client (`srClientReg`) and a nil-allowlist client (`srClientAny`) — **no harness anywhere has a dirty non-empty allowlist**, so the rule-4-default → post-resolution path is unpinned by every existing test too.

**Action:** add a fourth REQ-6 leg — dirty allowlist (`["admin:read","legacy:menu:1:view"]`), **no `scope` param**, matrix-only registry → dispatch seam skips (empty set, `server_token.go:130`), rule 4 defaults, post-resolution rejects → 400 `invalid_scope`. Optionally its positive twin (clean allowlist, empty scope → 200 with `scope=admin:read`). This is the first test anywhere that would fail if the per-branch check regressed.

## 3. Material gap: REQ-5 fixtures omit the tenant map — the tenant gate masks (the unit-level D2)

`buildReport` runs `validateMappedClientBindings` **before** the scope gate (target.go:221), and it requires every `plan.MappedClients` entry to exist in `target.Clients` with a non-empty tenant. Every REQ-5 test shape as written — `plan.MappedClients{"web"}` + `target.ClientScopes{"web": ...}`, with no `target.Clients` — would fail against a *correct* implementation with `mapped target client "web" does not exist or is inactive`, and the asserted scope string never appears. The unwired no-op test has the same defect.

**Action:** state in REQ-5 that every S1/S2/S3 and unwired test seeds `target.Clients: map[string]string{"web": "tenant-acme"}` (the scope string in the assertion is then the discriminator that makes masking impossible — keep the "names both `web` AND the scope" assertion; it's the right shape once the fixture is complete).

## 4. Material gap: S2/S3 combined fixture masks per-check regressions

REQ-5's "a planned role whose `Code` or `Permissions` contains an unregistered string" is ambiguous; a single fixture with *both* a bad code and a bad permission would stay red... no — would stay **green in the wrong way**: if S3 (code check) regresses, S2 (permission) still errors → test passes → regression undetected. Same class as D2.

**Action:** two tests — (a) unregistered `Code` + registered `Permissions` → error names the **code**; (b) registered `Code` + unregistered `Permissions` member (e.g. `content:read`) → error names the **permission**. Each must assert the specific string, so neither can be satisfied by the other.

## 5. Material gap: F12 (error precedence) has no test — no test fails if the gate moves

The design documents "existence/tenant gate → scope gate → user-collision → role-assignment" (§2, F12) but lists no test constructing a plan that fails **two** gates. If the call site moves (e.g. after `validateMappedRoles`), every listed test still passes — S1-negative has no role violations, so the scope error is returned eventually regardless of position.

**Action:** two precedence tests: (a) unbound client **and** dirty scope → error is the tenant text, scope string absent; (b) dirty scope **and** an assignment referencing an undefined role → error names the scope, role text absent. These pin F12 exactly.

## 6. Moderate gap: F8 (SQL NULL fold) is untestable with the planned fixtures

F8 says `COALESCE(allowed_scopes,'[]')` folds SQL NULL, and it's a listed failure mode — but both `testTargetSchema` *and* `testTargetSchemaNullableClients` are planned to gain `allowed_scopes TEXT NOT NULL DEFAULT '[]'` (§7.2). With NOT NULL you cannot insert NULL, so the fold can never fire; F8 has **no test mapping**. (Note F8's premise is already weak: real rows are NOT NULL, clients.go:42 — the design itself says only hand-made schemas can hold NULL.)

**Action:** either give the *nullable* fixture `allowed_scopes TEXT` (no NOT NULL) and add a NULL-insert test asserting `ClientScopes[id] == "[]"`, or explicitly mark F8 as untested-by-construction in the F-table. As written, the fixture plan and the failure mode contradict each other.

## 7. Moderate gap: CLI happy-path wiring is untested end-to-end

REQ-5 covers only flag **error** paths (`"*"`, extra-without-registry). The unit tests build the registry via `wireRegistry`/`buildScopeRegistry` directly, and REQ-6 wires the *server* registry — the actual REQ-1 chain `--scope-registry` → `parseScopeRegistryFlags` → `cfg.ScopeRegistry` → `plan.ScopeRegistry` is exercised by **no test**. A regression where the helper builds but never assigns (or assigns nil) keeps every listed test green.

**Action:** add a `parseFlags` happy-path test: `--scope-registry` alone → `cfg.ScopeRegistry != nil`, `Registered("admin:read")` true, `Registered("legacy:menu:1:view")` false; with `--scope-registry-extra legacy:*` → true. Also pin the empty-segment semantics (`--scope-registry-extra ","` → matrix-only — **not** an error, contradicting F3's "empty → exit 2" row; §3.1 step 2 drops empties, so F3's "empty" case is wrong as stated and should be corrected, with the actual semantics pinned by the test).

## 8. Moderate gap: unmapped dirty client passes — unpinned

The gate checks only `plan.MappedClients` (mirroring M7's managed-scope semantics). No test pins that an **unmapped** client's dirty `allowed_scopes` passes. A regression to "check all active clients" would break real deployments (a pre-existing native client holding a `legacy:*` scope would block the sync) and no listed test would catch it — the unit fixtures contain only mapped clients.

**Action:** add `TestBuildReportUnmappedDirtyClientPasses` (the M7 mirror): `MappedClients{"web"}`, `ClientScopes` with `"web": clean, "other": dirty`, wired → pass.

## 9. Moderate: integration 400 should assert the raw body

The design says "→ 400 `{"error":"invalid_scope"}`", but `postToken` returns a decoded map; a map assertion won't catch a drifted body (e.g. a trace_id added by a future `errorBody` swap — precisely the byte-compat shape the seam exists to preserve). The sibling suite already pins the raw body (`test/scope_registry_test.go:205`, `registry_test.go:191-192`).

**Action:** in the new test, capture the raw body (as `srCC` does) and assert `strings.TrimSpace(raw) == `{"error":"invalid_scope"}`` plus no `trace_id`. Same for the positive leg: assert `out["scope"] == "admin:read"` (the minted scope, as `TestScopeRegistry_MatrixScopesMintable` does), not just the 200.

## 10. Minor gaps

- **Nil `ClientScopes` + wired registry** is unpinned. Specified semantics ("for each mapped client *present in* `target.ClientScopes`") mean a nil map must no-op; an implementer reading `ClientScopes[id]` on the zero value gets `""` → JSON parse error → spurious failure on every hand-built snapshot (U7-style tests construct `targetSnapshot{Clients: ...}` without the new map). One test with wired registry + nil `ClientScopes` → pass pins the present-check.
- **S1∩S2 dedup** is claimed but untested: a scope in both a client's allowlist and a role's permissions must yield **one** line. Fold into the determinism test.
- **Unwired + malformed JSON** (`"not-json"`, nil registry → pass) pins F1's "malformed JSON cannot regress unwired runs" sub-claim; the listed unwired test uses a *valid* dirty value.
- **`buildScopeRegistry(nil)` vs `([]string{})`** equivalence is untested (NewMemory handles both — `registry.go:68` — but the CLI's nil-extra path deserves the one-line assertion in the §7 happy-path test).

## 11. Boundaries verified sound (no action)

- **Empty registry**: unreachable by construction — the CLI always seeds `NewMemory(Matrix(), extras)`; matrix-only is the floor, covered by S1-negative + S1-positive-matrix. ✓
- **Nil extra**: covered by the same pair; see §7 for the missing parse-level pin. ✓
- **Concurrent sync**: no new surface. The gate reads one more column of the snapshot captured in `inspectTarget`; `applyPlan` never writes `clients`, so within a run the gate's input cannot disagree with the write; cross-process locking/TOCTOU (inspect → apply) is inherited from the tenant gate unchanged. One line in the design noting this would close the review question; no test is warranted.
- **Harness fidelity**: verified end-to-end — the real sqlite `ClientStore.Put` marshals `AllowedScopes` verbatim with no pattern validation (`clients_scan.go:41`), so the dirty allowlist is seedable through the real store; body-secret client auth works for client_credentials (`server_token_clientauth.go:193-247`); the tenant-claim client shape (Secret, Active, jwt strategy, no GrantTypes → unrestricted) passes `rejectDisallowedGrantType`, `denyPublicClientCredentials`, and the rate-limiter (unwired no-op); registry construction matches build_stores.go:306 exactly. T-2's no-modify set and the U7 column-order pin (`tenant_id` before `allowed_scopes`) are correct. F2/F4/F5/F6/F7/F9/F11 test mappings are each regression-sensitive as specified; the exit-1/exit-2 discharge via `run()` control flow follows the tenant-gate precedent.

## Summary table

| # | Finding | Severity | Fix |
|---|---|---|---|
| 1 | D2 mechanism misstated (seam precedes allowlist gate); repair still needed for regression sensitivity + extra leg | Material (accuracy) | Correct rationale in §1/§7.3; keep dirty seed |
| 2 | Post-resolution effective-scope path (rule-4 default) unpinned by REQ-6 and by all existing tests | **Material** | Add empty-`scope` negative leg (+ optional positive) |
| 3 | REQ-5 fixtures omit `target.Clients` tenant map → tenant gate masks/spurious failure | **Material** | Seed `Clients{"web":"tenant-acme"}` in every S1/S2/S3/unwired fixture |
| 4 | S2/S3 combined fixture masks per-check regression | **Material** | Split into code-only and permission-only tests, assert the specific string |
| 5 | F12 precedence has no test; call-site moves undetected | **Material** | Two dual-violation precedence tests |
| 6 | F8 SQL-NULL fold untestable with NOT NULL fixtures | Moderate | Nullable column on the nullable fixture + test, or declare F8 uncovered |
| 7 | CLI happy path (flag→registry→plan carrier) untested | Moderate | `parseFlags` positive test; fix F3's "empty" row vs §3.1 |
| 8 | Unmapped dirty client pass unpinned | Moderate | M7-mirror test |
| 9 | Integration 400 asserted on decoded map, not raw body | Moderate | Raw-body byte assertion + minted-scope assertion |
| 10 | Nil `ClientScopes` wired semantics, S1∩S2 dedup, unwired-malformed, nil-vs-empty extras | Minor | One test each, folded into existing cases |

The mapping is *directionally* correct — every listed test does fail if its own predicate regresses, and the F1/F2/F4/F5/F6/F7/F9/F11 entries are faithful — but findings 2–5 are the D2 class the review was asked to hunt: each is a leg whose green status survives the regression it claims to pin. Findings 2–5 should be incorporated into REQ-5/REQ-6 before implementation; the rest are cheap additions.
