Adversarial review complete — written to `docs/architect-analysis/auto/runs/enforce-form-urlencoded-credential-strict-mode-0a8df02f/artifacts/adversarial-review-3024b680/task-1-adversarial-review.md`. Every claim re-verified against the tree (bind.go:31-34, all four handler bind/error paths, `core.ErrorBody`, `maintainability_budget_test.go`, the Deps/test structs, `inspectTokenClientAuth`, `rar.go`).

**Core questions — design holds, no bypass found:**

1. **normalizeContentType edge matrix** — charset/params stripped at first `;` (accepted, RFC-correct); case handled by `ToLower` with Unicode case-folding collision **impossible** (canonical has no `k`/`s`/combining chars); whitespace trimmed both ends; quoted → fail closed (media types are never quoted per RFC 7231); comma lists → fail closed in both orders (not comma-separable per RFC 7231); trailing `;` → accepted; duplicate CT headers can't split the gate from `ParseForm` (both use `Header.Get`); multipart/BOM/CTLs → fail closed. The false-accept direction is empty: only strings normalizing *exactly* to the canonical pass, and the strict binder never calls `decodeSingleJSON`.

2. **Confusion attack closed** — exactly one bind site per endpoint (server_token.go:30, handle_introspect.go:120, handle_revoke.go:75, handle_par.go:66); no secondary raw-body readers on those routes (request_log restores the body; body-limit wraps only); form presence semantics preserved via `r.PostForm.Has(...)` (server_token_clientauth.go:99); 400-vs-401 boundary moves only for JSON bodies — intended.

3. **Oracle-safe byte-identity** — all four handlers map any bind error to today's exact 400 envelope (error value never inspected); no invented `WWW-Authenticate`; no-store pre-bind everywhere. Per-endpoint identity holds; `/token`'s trace_id is the only cross-endpoint difference and it's status quo.

**Findings:**
- **F1 (blocking)** — `sso_protocol.go` is *exactly* 500 lines, not "under budget": the +1 field fails `TestMaintainability_`. Fix: `oauth21Strict, strictCredentialContentType bool` on one line.
- **F2 (blocking)** — "next to WithJTIReplayFailClosed" points at `options_security.go`, also exactly 500 lines. Pin the option to `options.go` (490→498).
- **F3** — PAR `authorization_details`/`claims` (`json.RawMessage`) are silently dropped by form binding; `ValidateAuthorizationDetails(nil)` validates as empty, so the §6 JSON→form migration silently loses RAR details. Needs a documented caveat or a deliberate `setFormField` extension.
- **F4** — AC-6 pins none of the bypass-relevant edges (case/quoted/comma/trailing-`;`/multipart); extend the table to regression-lock the matrix.
- **F5/F6** — wording fixes (AC-2b trace_id parenthetical; absent-CT row overstates breakage — CT-less *form* callers already 400 today).

VERDICT: CONDITIONAL PASS — security design withstands review with no bypass, but F1/F2 are hard gate failures that must be corrected before implementation.
