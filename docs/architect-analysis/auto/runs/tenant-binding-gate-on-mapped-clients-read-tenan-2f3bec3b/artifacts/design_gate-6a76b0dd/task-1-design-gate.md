All blocking findings are verified resolved against the actual working tree — no legacysync `.go` files modified (deliverable remains documentation-only), and I independently re-measured the load-bearing claims rather than trusting the reviewer chain.

**Findings verification (each checked against HEAD by me):**

| Blocking finding | Status | My evidence |
|---|---|---|
| (a) U4/U6 NULL fixture unexecutable on NOT NULL schema | **Resolved** | §3 + U4/U6 rows specify `openTestTargetWithSchema` + `testTargetSchemaNullableClients` (`tenant_id TEXT`, no NOT NULL), explicitly acknowledging the parity schema cannot hold NULL. Verified: real schema `NOT NULL DEFAULT ''` (sqlite/clients.go:46), `openTestTarget` at target_test.go:49, column-less `testTargetSchema` at 145-155. |
| (b) U5 golden = three lines, not two | **Resolved** | U5 row states the exact templates; I read `printReport` (main.go:71, 72-74, 75-77) — byte-identical to the three templates quoted, plus two-goldens and bcrypt-determinism rationale. |
| (c) Failure-mode rows 6–9 untested | **Resolved** | M6/M7/M8/M9 unit rows present with concrete one-liner assertions; the multi-missing nondeterminism caveat is documented in the failure table and step 4. |
| (d) `target_test.go` map-literal compile fix hidden | **Resolved** | REQ-4 row discloses it at the measured **line 42** (compliance reviewer's correction over the testing reviewer's 39 — my `sed` confirms 42), plus the 4th touch site in §3/E1. |
| (e) Admin API/UI equivalence claim false | **Resolved** | §6 step 3 replaced it: TenantID read-only on the admin wire, actual write paths = config re-seed (`config_client.go:20-24` → `seedClients` → `Put`), DCR `/register` (`handle_register.go:72,114`), direct SQL. |
| (f) Cosmetic drifts | **Resolved** | M4 error text matches the real wrapper (`target clients query: %w`, target.go:169); write branch 56-60, `return 0` at 62, `reportError` at 65-67 — all match my own readings of main.go. |
| I1/I2 raw-payload helper contradiction | **Resolved** | Implementation note added (sibling base64 decode of segment 1; keep both count+decoded assertions, last-wins rationale). |
| Inactive-client UPDATE + dry-run-loop sequencing | **Resolved** | §6 steps 3–4 cover "including currently inactive ones", reactivation-reintroduces-gate, and both convergence conditions. |

Security and CLI reviews raised no blockers; their drifts are correctly reflected. The only scoped-out item (run()-level exit-code test, no MySQL seam in `openLegacyDB`) is a documented, evidenced decision, not a rejected blocker.

VERDICT: PASS - every blocking finding from the testing and database reviews is incorporated into the design document with verified code evidence, the reviewer-line drift was corrected to measured values, and no legacysync source was modified; the design is ready for implementation.
