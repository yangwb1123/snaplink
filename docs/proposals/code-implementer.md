The implementation plan is complete and verified. **`docs/architect-analysis/auto/domains-tokenpolicy-direction3-implementation-plan.md`** (540 lines, auto-mirrored to `docs/auto/` via the symlink). Every number was derived by simulating the exact edits on file copies — no `.go` files touched, per design-stage convention.

## The four requested deliverables

**1. Scope-combo call-site edit (`server_token.go` — 500 → 500, +0).** One line, at :168:
```go
// before
	if s.denyTokenScopeCombo(ctx, client.ID, scopes) {
// after
	if s.denyTokenScopeCombo(ctx, client.ID, client.TenantID, scopes) {
```
The signature/literal edit lives in `server_helpers.go`, not this file. Verified: simulated replacement yields exactly 500 lines.

**2. Corrected arithmetic — both reviews were wrong in different directions:**
- **`server_helpers.go` 493 → 495** — SRE F7's 497 is a miscount: both signatures gain `tenantID` **on the existing line** (103 and 129 chars; gofmt doesn't wrap), so only the two `TenantID: tenantID,` literal lines are added. The design's original 493→495 was right.
- **`server_oauth.go` 481 → 495 (+14)** — security F5's "~491" identified the right error class but undercounted: the exact session-seam function (31→45 lines, reproduced in §6) needs the Evaluate hoist (+1), `TenantID:` (+1), the 9-line role block (incl. both `logger.Error` lines **and** the F3/F4 metric call), and the constraint comment (+3 net). Verified by applying the exact function: 495.

**3. `validate.go` placement + decodeStrictWithFallback ordering.** New `domains/tokenpolicy/validate.go` (6th non-test file, 6 ≤ 10 ceiling). The SRE F2 hazard is real — I probed goccy v1.19.2: the whole-config lenient re-decode **silently drops `tennat_id`** before `BuildTokenPolicyStore` runs, so semantic-only `Validate` can't catch it. The fix is a strict `Policy.UnmarshalYAML` (type-alias pattern, probed: errors under **both** outer decode modes, so the fallback can't rescue a policy-item typo while unrelated-key tolerance is preserved), plus `Validate` in `ParseYAML` (File) and `BuildTokenPolicyStore` (inline) + the SRE F1 `subject_roles` boot warning. `config/config_snapshot.go` needs **zero** edits.

**4. `TestParseYAML_Empty` fixture.** Exact new test text in §5: loop drops `other: 1`, which moves to `TestParseYAML_Malformed` alongside `tennat_id`; `""` and `[]` pinned clean (probed).

## Gate proof (full table in §10)

All 27 edited files with final counts — the tightest: `server_token.go` 500 (same-line), `server_login.go` **499→500** (gate edge; the stamp must be that file's last edit ever), `server_oauth.go`/`server_helpers.go` 495, `token_exchange_stages.go` 496. Also corrected the census both reviews missed: **13 mint sites + 1 template** (design's 10, plus silent-renewal, agent-delegation, break-glass — with a documented non-stamp for break-glass, which has no client) — per-site decisions and clamp tests included. §8 maps every security/SRE/QA finding (F1–F8, H1–H2, M1–M5, L1–L2) to a plan item, §9 is the seam×selector liveness matrix, §11 the gate sequence (`go build/vet` → maintainability/architecture → targeted `-race` → `./... -race` → route-contract → `make ci`, with the pre-existing red items called out and binary-first rollout for SRE F3).
