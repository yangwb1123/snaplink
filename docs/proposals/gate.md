All verification complete. I've cross-checked every reviewer finding against the design doc (994 lines), the requirements spec, and the working tree. Key code facts re-verified: `Threat.TenantID` has zero readers in `domains/threataction/` (only the field at line 51); `maxversions.go` hardcodes `1`; `recordLoginSuccess` has exactly 4 call sites; `RateLimitKey` has no tenant component; `build_trust.go:189,215` call the changing SPIs with bare request ctx; `sessions.ListByUser` and `refresh_tokens` have no tenant predicate/column; `registry.go:109-113` audits refusals (`OK:false, Detail:"rate-limited"`).

# Gatekeeper report

## Resolved or dismissed with reasons — verified ✓

The 21 findings in the final-gate disposition table (SEC-F1…F6, DB-H1/H2/M3/M4/M5, DS-F1…F10) are all resolved or explicitly accepted with reasons, and the design's factual corrections check out against code:

- **SEC-F1** (High): accepted residual (remediation c) with mitigation + defined follow-up; false premise corrected throughout the design; verified basis.
- **SEC-F2/F3/F4** — ctx-first resolution, guard truth table (`execute ⟺ event.TenantID != "" ∧ a.TenantID == event.TenantID`), NUL rejection — all encoded as decisions + tests T3/T2/T4.
- **DB-H1** (High): dedicated trust-scorer decision + T8; **DB-H2** (High): retention loop wired (decision + T13 + config-reference.md); **DB-M5**: additive `WithThreatSkippedCallback`; **DS-F1/F3**: max-version bump + T5, throttle key tenant-prefix + T12.
- DS-F4…F10 documented as accepted with reasons; DB-M4 cold-start release-noted.

## NOT resolved, NOT dismissed — blocking issues

**A. The compliance review's findings are absent from the design and the gate record.** The disposition table covers exactly 21 findings (6 SEC + 5 DB + 10 DS) — zero of the compliance officer's items are disposed of, and the compliance review explicitly marked several "required before implementation":

1. **D1 (Medium, required):** the guard's refusal produces **no audit event** (warn log + metric + callback only) — inconsistent with the package's own convention (`registry.go:109-113` audits refusals with `OK:false` + Detail). Nothing in the design addresses this.
2. **D2 (Medium, required):** executed-threat audit rows are not tenant-stamped — `recordAudit` is never mentioned; only `NewRecorderSink` gets stamping. The `tenant_id` audit filter cannot attribute the response half of the trail.
3. **D6/D7 (Low, required in same commit):** `observability.md` (new tripwire counter) and `feature-matrix.md` (threat-bridge behavior row) are missing from the contract-update list; no CHANGELOG break-set entry is specified.
4. **R5/R6:** no statement that the Eraser/DataMap omit the anomaly stores, and no documented follow-up hook (the new `tenant_id` column) for tenant/subject-scoped delete.

**B. Requirements spec drift — the spec contradicts the design (AGENTS.md §1).** The qa_lead's spec edit predates the SEC-F1 arbitration, and the spec was never reconciled:

5. Spec line 18 / 87 / 92 still assert the **false premise** SEC-F1 debunked ("already tenant-aware on the execution side", "act on that tenant's state", "making the cross-tenant case impossible") — the design corrected these; the spec did not.
6. **Acceptance-criteria conflict:** spec lines 100–107 require the t2 side-effect test (zero t2 sessions/refresh tokens) as **this change's** acceptance check, while the design (T1, lines 574–575, 590) explicitly excludes it from this change's green set (follow-up). As written, the design cannot pass the spec's acceptance check — one must be amended to the other.
7. Minor: spec line 115 still lists the retention loop as a non-goal while the design wires it — the design records the supersession with a reason (acceptable dismissal), but the spec should be amended to match.

## Non-blocking observations

- The max-version and `recordLoginSuccess` four-site corrections are accurate (verified in code).
- Pre-existing tree drift (`build_app_oidc.go:110`, `docs` fan-out) is unrelated and was correctly reported separately.

**Bottom line:** the security/database/distributed findings are genuinely closed, but the gate record ignores an entire review (compliance D1–D7, R5/R6), two of which are Medium and explicitly "required before implementation", and the requirements spec retains the debunked premise plus an acceptance check the design deliberately defers. That is not "every finding resolved or explicitly accepted."

VERDICT: FAIL - compliance findings D1 (refusal un-audited) and D2 (executed-threat audit not tenant-stamped) are required-before-implementation and unaddressed; D6/D7 (observability.md, feature-matrix.md, CHANGELOG) and the R5/R6 erasure/DataMap statement are missing from contract updates; the requirements spec still asserts the debunked "executors are tenant-aware" premise (SEC-F1) and requires the t2 side-effect test as this change's acceptance while the design excludes it from the green set — spec and design must be reconciled before implementation.
