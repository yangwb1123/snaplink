Audit complete. All claims verified empirically (predicate simulation against the real template text, mutation probes, budget-gate source). Findings:

## 1. Predicate-by-predicate soundness

**`issuer.Issue(` absence early-return — SOUND.** `t.Errorf` + `return`, matching `assertFormContentTypeGuard`'s `bindIdx < 0` pattern exactly (Errorf, not Fatal). Absence is always loud. Two minor notes: when the anchor is absent the missing-marker checks are skipped too (one error instead of five — less diagnostic, not unsound); and first-occurrence anchoring would silently weaken if a future comment above the call ever mentions `issuer.Issue(` — neither current nor proposed text does.

**grantedScopes) ordering-vs-presence — the design's defect-1 resolution is empirically necessary and correct.** Simulation of the proposed text: `grantedScopes)` at index 4244 vs `issuer.Issue(` at 4045 — an ordering assertion *fails the correct output*, proving the requirements' A1 wording was unsatisfiable. Presence-only is precise: `grantedScopes)` matches only the Issue tail (`GrantedScopes(` is case-different; `grantedScopes, err :=` has a comma). Presence+ban are jointly near-exhaustive — any tail deviation fails presence loudly; the exact regression fails the ban.

**`}, scopes)` ban vs current tail — exact match, fires red, no false positive.** The banned tail is at **`templates_handler.go:208`** (`//    }, scopes)`), not 204 as cited (204 is the `issuer.Issue(` line — cosmetic drift). The proposed tail `}, grantedScopes)` does not contain `}, scopes)`; simulation confirms zero occurrences in the proposed text, including the long step-2 comment.

**`Roles(` marker — TWO REAL HOLES, worse than the design's acknowledged trade-off.** Mutation probes against the proposed text:
- **Step-3 `h.Roles(` call deleted → all predicates still pass.** The marker is satisfied by the step-3 *citation* (`permissions.Provider.Roles(ctx, ...)`) — and would be satisfied by the 4.1(a) struct TODO alone ("a `Roles(`... accessor"), which sits ~30 lines above `Handle`. The "before issuance" leg for `Roles(` is structurally vacuous, not just rename-tolerant as §6 frames it.
- **Subject-literal `Roles: roles` dropped → all predicates still pass.** The helper asserts `Roles(` (paren) and `TenantID:...`; the `Roles:` claim projection is asserted by *nothing*.

**Fix (both fail red today — template has zero `Roles(`/`Roles:` occurrences — and pass green):** (i) tighten the ordering marker from `Roles(` to `h.Roles(` — first occurrence is only the step-3 example call; (ii) add a presence assertion `Roles:\s+roles` (regexp already imported). Plain `strings.Contains(text, "Roles: roles")` would **false-positive** — the literal is gofmt-aligned `Roles:    roles` (4 spaces).

## 2. Red-first proof — REAL, but the "six markers" premise is factually wrong

The current template **does** contain two of the six: `}, scopes)` (`:208`) and `TenantID: client.TenantID` (`:207`). The red run still fires **6 named failures** (4 missing gate markers + missing `grantedScopes)` + the ban); `TenantID` passes green — it is a green→green pin ("unchanged literal, now pinned"), correctly not part of the red proof. Corrected statement: *five of seven asserted markers absent, banned tail present → red; TenantID is a pin.* Baseline confirmed green today (`go test -run 'TestGeneratedScaffoldsCompile|TestRunExitCodes'` passes, helper not yet wired).

## 3. A1–A6 mapping

| ID | Assertion | Fails red | Passes green | Verdict |
|---|---|---|---|---|
| A1 | 4 ordering + `grantedScopes)` presence + ban | **Yes** (6 named failures, simulated) | Yes (simulated) | OK — except A1's `Roles(` leg (hole above) |
| A2 | `TenantID:` presence; `Roles: roles` in Subject | **No** — TenantID already present; `Roles: roles` unasserted | — | **GAP** — add `Roles:\s+roles` |
| A3 | per-marker named `t.Errorf` | mechanism itself | — | OK |
| A4 | isolated build+vet loop | Red on broken templates (historical — test doc cites prior fabricated-shape failures) | Yes today and after | Correctly **not** red for this change; comment-only edit must not flip it |
| A5 | `TestRunExitCodes` | Red on CLI-surface change | Yes | Same category as A4 |
| A6 | red-first precondition | **Yes** — 6 named failures (simulated) | after edit | REAL, with marker-count correction |

A4/A5 are stability gates whose red state exists but is correctly untriggered by a comment-only template change; A1/A3/A6 are true red-first assertions; A2 needs the added check to satisfy "fails red and passes green".

## 4. 4.1(c) dispatcher — sound, keep

`TestGeneratedScaffoldsCompile` is exactly lines 97–146 = **50 today** (verified by line count). The 3-line `if tc.kind == "handler"` block (131–133) → 1-line `assertKindInvariants(t, tc.kind, generated)` = **48 lines**. Coverage fully preserved: handler→`assertFormContentTypeGuard`, grant→`assertGrantScopeGateClaims`, authenticator/store→no kind-specific invariants (status-quo policy — the 4-kind table gains grant coverage). Both helpers share the exact signature `(t *testing.T, kind string, content []byte)` → clean switch, no shims; dispatcher needs `t.Helper()` and must land in `scaffold_contract_test.go` with the helper (same change — it references it). Minor wording caution: design §4.3's "alongside the handler-kind guard" is obsolete once the dispatcher replaces that guard.

## 5. Conventions + budget exemption — CONFIRMED

- `assertGrantScopeGateClaims` matches `assertFormContentTypeGuard`: identical signature, `t.Helper()` first, `"%s scaffold:"` error prefix, Errorf+early-return on missing anchor, doc comment citing the invariant and precedent. Consistent.
- Exemption verified in gate source: `maintainability_budget_test.go:71` and `maintainability_complexity_test.go:142` both skip `_test.go` — the 500-line file and 50-line function gates don't apply. Evidence defect-2 confirmed; the 51-line variant would be compliant and the dispatcher yields 48. File stays ~335 lines regardless.

**Verdict: adopt with two material corrections** — replace the `Roles(` ordering marker with `h.Roles(` and add a `Roles:\s+roles` presence check (closes the A2 gap and the vacuity); and correct the record that the red-first premise is "five of seven markers absent + banned tail present," not "none of the six."
