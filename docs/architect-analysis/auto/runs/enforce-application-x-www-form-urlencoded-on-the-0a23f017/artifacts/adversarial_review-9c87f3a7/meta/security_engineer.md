Hardening complete. Both deliverables are in place; no Go code was touched (no gates needed), and unrelated worktree changes were preserved.

## Deliverables

**1. Hardening review (evidence chain):** `docs/architect-analysis/auto/runs/enforce-application-x-www-form-urlencoded-on-the-0a23f017/artifacts/adversarial_review-9c87f3a7/hardening-oracle-safety.md`

**2. Design updated to Revision 3:** `docs/architect-analysis/cmd-snaplink-audit-provisioner-b4-4-credential-form-only-design.md` — new §3.8 pins D1-D6, hardened §3.3 envelope snippet, amended §3.7 acceptance rows, §5 files, §8 verification plan.

## Verification results (all four claims re-derived from code, not the design's citations)

**1. 415 envelope cannot distinguish internal causes — VERIFIED.** The 415 is reachable *only* via the media-type class, returned before any body read; the three named causes map to disjoint, pre-existing classes: wrong CT → 415 (the only 415 producer), malformed `%ZZ` under form CT → 400 `invalid_request` (ParseForm error, never `ErrFormOnly`), unknown/consumed code → 400 `invalid_grant` (collapse at `token_authcode.go:182-215`). No client/code/store/DPoP/PKCE state is consulted before the 415 at any of the four sites. Envelope is constant: `415` + `application/json` + `{"error":"invalid_request"}\n` (encoder newline) + pre-stamped no-store.

**2. DPoP/mTLS/Basic/PKCE byte-identical under default-off — VERIFIED.** Mode-off dispatch is a transparent pass-through (`bindCredentialParams` → `bindOAuthParams` → `BindParams`; `errors.Is(err, ErrFormOnly)` structurally false); ordering untouched (bind → Basic override → client auth → `captureSenderConstraint` :250-295 → grants; PKCE constant-time compares `auth_code_handler.go:83/:85` unchanged). Bonus pinned: strict-on 415 fires before Basic parse, DPoP verify, mTLS extract, and PKCE compare — it cannot leak any credential state; idempotency capture/replay is unreachable for wrong-CT requests.

**3. No-store on all error paths — VERIFIED.** All four sites stamp before the bind (`server_token.go:22`, `handle_introspect.go:112`, `handle_revoke.go:68/:182`, `handle_par.go:55`), so every in-handler error branch carries both headers.

**4. No fail-open in `BindParamsFormOnly` dispatch — VERIFIED (5 structural guarantees).** Pure function of the normalized CT (fail-closed: JSON/multipart/missing/whitespace → `ErrFormOnly`); `decodeSingleJSON` unreachable (separate function); ParseForm error returns before `formIntoStruct` (no partial bind); sentinel never wrapped/co-produced; zero-struct bodies hit unchanged per-endpoint validation.

## Pre-existing drifts reported separately (not fixed)

- `bodyLimitMiddleware` 413 (`internal/handler/health.go:56-65`) lacks no-store — config-gated, mode-independent, outside this change.
- `TestSdkForm_PARClaimsThreaded` deliberately RED (already disclosed, C8/F9).
- PAR zero-struct issuance for empty-body form requests (pre-existing, mode-identical).
- Cosmetic line drifts on current HEAD (revoke no-store :68, par no-store :55, introspect no-store :112).
