All verification complete. The kin-openapi validator passes (exit 0), and no Go was touched (no Go gates triggered).

## Verification report — docs vs design Rev 3

**Verdict: 3 of 5 items already held; 2 were missing and have been landed** (docs-only edits + report artifact):

| # | Checklist item | Result |
|---|---|---|
| 1 | Four flipped endpoints declare form-urlencoded | ✅ Already present — `requestBody.content` on `/token` (:1102), `/token/introspect` (:1280), `/token/revoke` (:1347), `/par` (:1477), verified via `yaml.safe_load` |
| 2 | 415 documented with `invalid_request` envelope (caveat 1) | ❌→✅ **Was zero "415" hits in the file.** Added a **Content-Type strictness (opt-in)** note on all four paths: `415 Unsupported Media Type` + plain `{"error":"invalid_request"}` envelope, byte-identical across the four endpoints, fires before body read and before client auth (media-type-deterministic, never a credential oracle), `%ZZ` still → `400 invalid_request` |
| 3 | JSON variants remain declared | ✅ Untouched — both requestBody variants on all four paths (design §3.4 pin) |
| 4 | no-store headers reflected | ⚠️→✅ Partially held (success rows); every new 415 note documents `Cache-Control: no-store` + `Pragma: no-cache` (D4) |
| 5 | Knob in config-reference `server:` block | ❌→✅ **Was zero hits.** Added `server.require_form_content_type` row to the `## Server` table (default off / byte-identical, `sso.WithCredentialFormOnly(true)` spelling, boot-time, rollback semantics) |

**Files changed** (per design Rev 3 §7 / AGENTS.md §5.6):
- `docs/openapi.yaml` (+60) — four opt-in notes; also corrected the stale `oauth_bind.go` → `oauthwire/bind.go` dispatcher pointer inside the rewritten paragraph. `/register`, admin, device/MFA/CIBA untouched. Passes `make docs-validate` (kin-openapi).
- `docs/config-reference.md` (+1 row) — satisfies sweep-test case 16 (key appears once; **zero** hits under `ops/deploy/`).
- `docs/error-codes.md` — 415 note on the credential `invalid_request` rows; no new code (design §7 pin).
- `CHANGELOG.md` — opt-in hardening bullet under `### Security`.

**Constraints honored:** pre-existing unrelated worktree changes (scope-registry row, sso-ctl sections) preserved untouched; no response-block `"415"` entries added (design §3.4 pins "only description notes"); report written to `docs/architect-analysis/auto/runs/enforce-application-x-www-form-urlencoded-on-the-0a23f017/artifacts/adversarial_review-9c87f3a7/docs_contracts_reviewer.md` beside the sibling reviewer reports.

**Deferred to the implementation stage** (noted in the report): the Go mechanism, the compose `config.yaml` flip, and the RED tests — the docs now declare the target contract those must match.
