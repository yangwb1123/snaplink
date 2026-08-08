All amendments are in place and verified. The artifact files are untracked run outputs (not committed to git), which is expected for this analysis pipeline; the requirements fix is confirmed at line 62.

## Consolidated adjudication — complete

**Verified every finding against the tree before disposition** (no finding accepted on faith): `wc -l` confirmed both 500-line ceilings, a live python parse of `openapi.yaml` confirmed `postRevoke` is the only credential op missing the 400, `router.go:141-146`/`handle_revoke.go:111` confirmed the `json.Encoder` trailing newline and `"{}\n"` body, `issue_payload.go` confirmed `nbf==iat==now`, `handle_par.go:100,105` + `bind.go:117-124` + `rar.go:154-156` confirmed the RAR drop.

**All 18 findings applied to `task-1-design.md` (251 lines, +§10):**

| Area | Amendments |
|---|---|
| Protocol (P-F1..F4 + extra) | RFC 9126 §2.1 in §2.1 doc comment **and** requirements artifact line 62; `postRevoke` 400 `invalid_request` added to the OpenAPI plan (§2.5/§8); config row moved to the **Security** table with `Maps to sso.WithStrictCredentialContentType` (D5/§2.5/§8); GoDoc-only note on accessors; §3.2 duplicate-parameter non-over-claim sentence (§3 + §9) |
| Test-design (T-A1..A4, B1-B2) | `nbf` added to exclusion set `{jti, iat, nbf, exp}` (§0 C1 + AC-2(b1)); revoke-200 golden `"{}\n"` (3 bytes, `handle_revoke.go:111`); trailing `\n` on both byte-exact goldens (28 bytes); JSON-shaped payload pins for AC-1 rejected-CT rows; permissive bind-failure pinned to `text/plain`+non-JSON (permissive+JSON succeeds — no 400 exists); header subset `{Cache-Control, Pragma, Content-Type}` + no-`WWW-Authenticate` + minus-`Date` pinned in AC-2(b4)/AC-4/§3; pre-built wrong-secret constants + round-robin batch interleaving in AC-5 |
| Security (S-F1..F6) | `oauth21Strict, strictCredentialContentType bool` combined on one line (`sso_protocol.go` 500→500, net +0); option pinned to `options.go` next to `WithOAuth21StrictMode` (:194), misleading "next to WithJTIReplayFailClosed" parenthetical deleted (D1/§2.4/§4.4); RAR `authorization_details`/`claims` drop documented in §2.5 row, §6 step 2 (fix option (a): document; separate `setFormField` change), and §9; AC-6 extended with the full bypass-relevant edge matrix (case/quoted/comma both orders/trailing `;`/space-`;`/multipart + permissive-side mirrors); AC-2(b2) trace_id wording; §5 CT-less row sharpened (CT-less **form** callers already 400 today) |

**Conflict resolutions (5):**
1. **Config-row placement** — adjudicated for the Security table: the "Maps to `sso.WithX`" convention is this row's exact shape; `security.jti_replay.fail_closed` (the OAuth-table precedent) has no option mapping. One row, one table.
2. **"No OpenAPI change"** (design + security review's verified-accurate list) **vs P-F2** — P-F2 wins, live-verified; the security item is superseded for OpenAPI, its "no new error codes" half stands.
3. **Option placement** — precedent citation to `options_security.go:39` kept (the function lives there), placement pinned to `options.go`.
4. **Revoke-200 body** — `"{}\n"` wins (encoder semantics).
5. **AC-2 byte-identity** — both reviews hold: assertable with tracing-off harnesses / identical trace context, caveat now explicit.

**Residual-contradiction check:** grep confirms the exclusion set, `"{}\n"`, `\n` goldens, Security-table citation, options.go pin, OpenAPI change, and line-budget claims are now uniform across §0/§2/§3/§4/§7/§8 — the only remaining hits for old phrasings ("§3.1", "empty", "under budget", "full header set", "OAuth table") are intentional meta-references inside §10's own adjudication record. No residual contradictions; documentation-only change, no Go gates triggered.
