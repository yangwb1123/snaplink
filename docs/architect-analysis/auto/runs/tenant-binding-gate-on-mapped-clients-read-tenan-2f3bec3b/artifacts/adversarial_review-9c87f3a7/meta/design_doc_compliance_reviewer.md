All corrections verified and applied. Final report:

## Verification verdict: the doc is corrected (6/6 required items), with one reviewer line-number deviation corrected and two residual findings closed

### Required corrections (a)–(f)

| # | Required correction | Status |
|---|---|---|
| (a) | Nullable `tenant_id` schema variant for U4/U6 | ✅ **Incorporated.** §3 fixture row now specifies the `openTestTargetWithSchema(t, schema)` refactor with three schemas: parity (`NOT NULL DEFAULT ''`), `testTargetSchemaNullableClients` (`tenant_id TEXT`, no NOT NULL — only U4/U6), column-less (only U7). The old self-contradiction (NULL rows demanded in a NOT NULL fixture) is resolved in both §3 and the U4/U6 rows. |
| (b) | U5 golden = three-line `printReport` | ✅ **Incorporated.** U5 row now states the exact templates (`legacy-sync mode=%s` / `source users=%d active=%d inactive=%d roles=%d grants=%d overrides=%d` / `target create_users=%d ...`), the two-goldens-or-parameterized-first-line requirement, and the byte-determinism rationale (bcrypt salt never reaches the report). |
| (c) | Failure-mode tests rows 6–9 | ✅ **Incorporated.** Four new unit rows M6 (missing/inactive → `does not exist or is inactive`), M7 (unmapped unbound passes), M8 (empty app map → nil), M9 (`' '` → nil, no trimming). |
| (d) | `target_test.go` map-literal compile fix in REQ-4 row | ✅ **Incorporated** in the REQ-4 row (type change + behavioral no-op rationale). ⚠️ **Deviation:** reviewers cited `target_test.go:39`; I measured the literal (`Assignments: map[assignmentKey][]string{}, Clients: map[string]struct{}{}`) at **line 42** and cited the verified line. |
| (e) | Admin API/UI equivalence claim | ✅ **Replaced.** §6 step 3 now says the only write paths are config re-seed (`config_client.go:20-24` → `seedClients`), DCR `POST /register` (`handle_register.go:72,114`), or direct SQL — with the read-only admin-wire evidence (`grpcadmin/admin_clients.go:59`, `protoToClient`/`applyProtoToExistingClient` never set it). |
| (f) | Cosmetic drifts | ✅ All four fixed: M4 error text → `target clients query: SQL logic error: no such column: tenant_id (1)`; 4th touch site disclosed in E1 + §3 table; write branch 56-59 → **56-60** (E8 row, §4 bullet, REQ-2 row); gate at 218-221 was already correct in E6 and re-verified at `interfaces/sso/server_token_clientauth.go:218-221`. Bonus fix: E8's `return 0 at 67` was also wrong — actual is 62. |

### Assessment 1 — Operational UPDATE vs inactive mapped clients

**Partially covered by the original doc; now fully closed.** The SQL itself has no `active` filter, so it binds inactive rows if run for every mapped id — step 3 now says "including currently inactive ones." Two subtleties are now explicit: (1) binding alone does **not** unblock an inactive mapped client — `loadTargetClients` filters `WHERE active=1`, so the pre-existing "does not exist or is inactive" check fails the sync regardless; the operator must reactivate (tenant gate then applies, already satisfied) or remove it from the app map. (2) The reactivation-later scenario the prompt describes is real and is the intended safety property: an admin-API reactivation (only `TenantID` is read-only on the wire; `Active` is mutable) of a skipped client fails the next sync loudly with the new gate — now stated so operators don't file it as a regression.

### Assessment 2 — Dry-run-loop sequencing

**Was incomplete; now complete.** Step 4 documents the two convergence conditions beyond unbound rows: (i) missing/inactive mapped clients are named one-per-run by the existence check, **nondeterministically when several are missing** (map-iteration order) — the runbook now directs operators to cross-check the app map against the step-2 inventory instead of relying on the error to enumerate; (ii) reactivation re-introduces the gate. The `AND tenant_id = ''` guard limitation (wrong non-empty bindings pass the gate, surfaced later by the server's 403) is by-design M9 and remains documented.

### Residual findings

1. **Reviewers' own line citations drifted** (target_test.go:39 → actual 42; `return 0 at 67` → actual 62). Corrected to measured values in the doc; substance unaffected.
2. **I1/I2 raw-payload helper** (from the testing review) was still latent: the doc told implementers to decode per `jwtAllClaims` while asserting the raw count — a contradiction (that helper returns only a decoded map). Added the implementation note: sibling base64 decode of segment 1, keep both assertions (count = exactly-once pin; decoded map silently last-wins on duplicates).

No `.go` files touched — documentation-only, so no build gates were triggered.
