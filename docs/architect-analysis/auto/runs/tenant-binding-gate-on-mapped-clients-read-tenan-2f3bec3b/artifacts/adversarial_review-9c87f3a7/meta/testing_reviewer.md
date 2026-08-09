Audit complete. I verified every claim against the working tree. Findings per audit point, with evidence and required fixes.

## (1) U4/U6 NULL fixture — **confirmed blocker, needs a schema variant**

- Real schema: `tenant_id TEXT NOT NULL DEFAULT ''` (`infrastructure/defaultimpl/sqlite/clients.go:46`, v1 migration).
- Proposed fixture change mirrors it (`NOT NULL DEFAULT ''`), so `INSERT INTO clients(id,active,tenant_id) VALUES ('x',1,NULL)` fails with `NOT NULL constraint failed` — U4 ("fixture row with `tenant_id NULL` fails identically to `''`") and U6's "NULL yields `\"\"` (COALESCE)" branch are **unexecutable on the proposed fixture**.
- Fix (recommended): refactor `openTestTarget` (`target_test.go:49`) into `openTestTargetWithSchema(t, schema)` and add a `testTargetSchemaNullableClients` variant (`tenant_id TEXT`, no NOT NULL) used only by U4/U6. U7 already needs a second schema variant (missing column), so the pattern is established.
- Alternative (weaker): restate U4/U6 to drop the NULL branch, documenting NULL as unreachable in real deployments and COALESCE as defense-in-depth. Keep COALESCE either way — dropping it turns a hand-made nullable schema's NULL into a scan error (different failure mode) instead of unbound.

## (2) U5 golden — **design states the wrong line count (two vs three)**

- `printReport` (`main.go:71,72,75`) emits **three** lines, not the design's "two-line format":
  ```
  legacy-sync mode=%s
  source users=%d active=%d inactive=%d roles=%d grants=%d overrides=%d
  target create_users=%d update_users=%d deactivate_users=%d credentials=%d roles=%d assignments=%d
  ```
- Baseline is trivially capturable: `printReport`/`syncReport` are untouched by this design, so the golden can be authored in the same change and frozen. It is byte-deterministic — the output contains only counts, and although `legacyFixture` embeds a fresh bcrypt hash per run (random salt, `plan_test.go:102-108`), hashes never reach the report. Two goldens needed (mode `dry-run` vs `applied` differ in line 1), or parameterize the expected first line.
- Required correction: the design's acceptance-mapping row for U5 and §2 "byte-identical" claim must say three lines with the exact templates above.

## (3) `strings.Count(payload, "\"tenant_id\":") == 1` — **sound as written, but decoded-assertion alone is insufficient**

The escaping analysis: in decoded JSON text, the substring `"tenant_id":` (quote, name, quote, colon) can only occur as a genuine JSON **key** named `tenant_id`:
- `"x_tenant_id":` cannot match (leading char before `tenant_id` is `_`, not `"`);
- string **values** cannot match: embedded quotes are escaped (`\"tenant_id\":` has `\` between `"` and `:`, and a value starting `"tenant_id: x"` lacks the closing quote-colon adjacency).

So the count is a structural exactly-once assertion, not a naive substring pin. Residual collision vector: nested `tenant_id` keys inside the raw-JSON pass-through claims `_claims_` (RequestedClaims) and `authorization_details` — both `json.RawMessage`. Not present in the proposed password-login harness (no requested claims, no authz details), so I1/I2 is safe as specified.

**Decoded-assertion alone does NOT suffice**: `json.Unmarshal` into `map[string]any` silently last-wins on duplicate keys — if dedup (`claimsWithoutEmittedKeys`, `issue_payload.go:116-131`) regressed and both the top-level literal and an `ext.tenant_id` were emitted, `payload["tenant_id"] == "tenant-acme"` would still pass while the raw count catches it. Keep both assertions (count = exactly-once, decoded = value). One implementation note: `jwtAllClaims` (`test/auth_code_test.go:253`) returns only the decoded map — I1/I2 needs its own base64 decode of segment 1 or a sibling helper returning the raw payload string.

## (4) Failure-mode coverage — **4 of 9 modes lack tests, not 2**

Design table order (row → mode → coverage):

| Row | Mode | Test | Status |
|---|---|---|---|
| 1 | bound | U2 | ✓ |
| 2 | unbound `''` | U1 | ✓ |
| 3 | SQL NULL | U4 | ⚠ blocked by (1) |
| 4 | multiple unbound | U3 | ✓ |
| 5 | missing column | U7 | ✓ |
| 6 | missing/inactive | — | ✗ **no test** (zero coverage even today — pre-existing path this change preserves, text pinned nowhere) |
| 7 | unmapped unbound passes | — | ✗ **no test** (the design's own §4 compatibility constraint) |
| 8 | empty app map | — | ✗ **no test** |
| 9 | `' '` whitespace bound | — | ✗ **no test** |

The prompt's "M7 = empty app map, M9 = `' '`" numbering doesn't match the design table (empty map is row 8, whitespace row 9) — substance unchanged: rows 6–9 are all uncovered. All four are one-liners: e.g. M9 `buildReport(plan{MappedClients:{"web"}}, target{Clients:{"web":" "}}, "dry-run")` → nil; M8 `buildReport(syncPlan{}, targetSnapshot{Clients: map[string]string{}}, ...)` → nil; M7 mapped bound + unbound `"other":""` → nil; M6 mapped client absent → error containing `does not exist or is inactive`. Add them to `tenant_gate_test.go`.

## (5) U3 determinism + existing-test breakage

- **Deterministic**: the proposed gate sorts `unbound` before emitting, and `errors.Join` preserves slice order — U3's sorted-order assertion is stable. (Caveat: the existence-error early return inside the same map-iteration loop is nondeterministic for *multiple missing* clients — not part of U3, but don't write a multi-missing variant.)
- **`TestBuildReportRejectsNativeUserCollision` breaks at compile time**: `target_test.go:39` constructs `Clients: map[string]struct{}{}` — with the `map[string]string` change this is a compile error. The design's "existing test names and final assertions unchanged" (REQ-4 row) hides a **mandatory one-line source edit** (map-literal type). Behaviorally it still passes (nil `MappedClients` → gate loop no-ops → collision error returned).
- **`TestApplyPlanPreservesNativeAuthorizationAndMenus`** survives only because the design binds `sverp-web` in `seedTarget` (`target_test.go:64`); without that binding the new gate fails `buildReport` inside the test. The design accounts for it — correct. `plan_test.go` never touches the DB or snapshot; no other breakage.

## Verdict

The mapping is implementable with four required changes: (a) nullable schema variant for U4/U6, (b) U5 golden corrected to three lines, (c) four missing failure-mode tests (rows 6–9), (d) the `target_test.go:39` map-literal compile fix; plus two documentation corrections ("two-line" → three-line; REQ-4 row must disclose the type fix). I1/I2 is sound as specified, with the raw-payload helper addition noted. No file changes made — this is the audit deliverable.
