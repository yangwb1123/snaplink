All verifications pass. The design document is now fully reconciled with the final audited template and helper.

## Summary of changes to `task-1-design.md`

**§1 defect list (was stale):**
- **Defect 1 (A1 predicate):** resolution now names the corrected marker set — ordering applies to `GrantedScopes(`/`SplitScope(`/`core.ErrInvalidScope`/`h.Roles(`; `grantedScopes)` is presence-only with the `}, scopes)` ban. Added the review-surfaced companion fixes: marker tightened `Roles(` → `h.Roles(` (bare form was vacuous — the step-3 citation and struct TODO satisfied it) and the A2 gap closed via a new `Roles:\s+roles` presence check (regexp, since gofmt aligns the literal to `Roles:    roles`).
- **Defect 2 (budget):** now states the **48-line outcome** (50 − 3-line guard at 131–133 + 1-line dispatch); the 51-line variant noted as gate-exempt, dispatcher adopted.
- **New defect 4:** the "none of the six markers" premise corrected — today's template already contains the banned tail (`}, scopes)`, `:208`) and the TenantID pin (`:207`); corrected premise is *six of eight absent + banned tail present → seven named failures, TenantID is a green→green pin*.

**§4.1(b):** final audited template text — internal-mint `RejectUnregistered` scoping sentence (security review hard gate), no literal backticks (raw-string hazard), line-free citations (dropped `:46`), "same guard discipline as the AMR claim" wording, mint-path-vs-accessor distinction with `role.Code` projection, fail-open divergence note (F3), and the restored post-issuance err-check/success-response tail the draft block had truncated. File estimate corrected to ~276 lines.

**§4.2:** consolidated helper — `h.Roles(` ordering marker + `Roles:\s+roles` presence check, updated doc comment.

**§4.3:** dispatcher **replaces, not accompanies** the handler-kind guard; 48-line outcome; −2 net line change.

**§7/§8/§6:** corrected red-first premise everywhere (consistent: 8 markers, 2 present, 7 named red failures); A1 uses `h.Roles(`, A2 asserts `Roles:\s+roles`, A6 states the corrected premise; §7 step 4 upgraded to the explicit two-commit sequence (verify-gate commit carries the untracked `scaffold_contract_test.go`; B-first forbidden).

**§5/§6/§10 confirmed:** no runtime change, no import-graph change (`regexp` already imported), CLI frozen, docs untouched, contract-helper compatibility — all hold for the final text; the single changed figure (~252 → ~276) is flagged. §10 verdict updated and the pre-existing stale SAML2 citation flagged as follow-up.

Verified by grep: zero stale phrases outside correction statements, correct marker ordering in the template block, zero backticks and zero line-numbered citations inside it. Docs-only change; no Go gates required.
