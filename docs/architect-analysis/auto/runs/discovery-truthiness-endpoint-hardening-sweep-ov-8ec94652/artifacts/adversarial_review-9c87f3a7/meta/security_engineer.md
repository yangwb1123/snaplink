All three review areas are now fully verified against the working tree, including baselines (`go test ./interfaces/admin/` and the e2e 401 test pass on the current tree). Here is the adversarial review.

---

# Adversarial review: oracle-safety claims (REQ-2, REQ-4, no-store/D5)

## (1) REQ-2 — `authenticateHTTP` convergence: **holds, with full precision**

**Byte identity (headers, body, ordering).** The proposed missing-bearer branch is a verbatim copy of the existing wrong-bearer branch (middleware.go:369-371):

- Same single header set (`WWW-Authenticate: Bearer realm="admin", error="invalid_token"`) via `w.Header().Set` *before* `http.Error`;
- `http.Error` then contributes `Content-Type: text/plain; charset=utf-8` + `X-Content-Type-Options: nosniff` + `{"error":"invalid_token"}\n` + 401 in both branches — identical call, identical args, identical order; net/http writes headers in sorted-key order, so even wire order is deterministic and equal;
- Pre-auth chain (`checkRateLimit` :330, `checkDestructiveConfirm` :333) runs before `authenticateHTTP` identically for both branches — nothing interposes.

**Malformed-header convergence.** `bearerFromHTTP` (:409-418) returns `""` for absent header, non-`Bearer ` prefix (Basic/lowercase/no-space), and whitespace-only tokens — all land in the missing branch, so they inherit the *invalid_token* bytes too. No escape into a third branch. The four-case test table (no header / malformed / garbage / valid-shaped-unknown) is sound.

**Residual distinct 401s are not oracles.** `session_expired` (different challenge + `{"error":"session_expired"}` body) and 403 `forbidden` are reachable *only with a previously-valid token* — an attacker cannot use them to distinguish missing vs wrong credentials. 503 `admin_auth_not_configured` fires before both branches. Byte identity holds for the missing-vs-wrong pair, which is exactly the T-9 claim.

**Challenge conventions.** `Bearer realm="admin", error="invalid_token"` is byte-identical to `setBearerChallenge(ctx, "admin", "invalid_token", "")` output: `QuoteAuthParam("admin")` → `"admin"`, `QuoteAuthParam("invalid_token")` → `"invalid_token"`, joined with `", "` (server_extensions.go:111-119, step_up_auth.go:103-112). The admin package uses literals rather than the helper (pre-existing), but the new literal matches the helper's emission exactly.

**Two flagged observations (not failures):**
1. *RFC 6750 §3.1 nuance* — including `error="invalid_token"` for a credential-*less* request is permitted ("MAY be omitted") but some clients treat it as "refresh and retry", risking a refresh loop for unauthenticated callers. This is the deliberate price of convergence; it's documented in the same change (error-codes.md:957, openapi.yaml:13056-13057 — both verified to currently say `missing_token` / bare `Bearer realm="admin"` challenge). Fine as designed; just calling out the intentional deviation.
2. *Timing asymmetry* — missing-branch does zero crypto; wrong-branch runs `ValidateToken`. Not an oracle: the attacker's own request determines the branch, and it reveals no secret. No mitigation needed.

**Additive-test fact:** `interfaces/admin/middleware_test.go` currently contains **zero** 401/`WWW-Authenticate`/`missing_token` pins (grep-verified) — the design's four-case table is purely additive, no conflicting pin. The `missing_token` pins that must stay green (device/userinfo/revoke: `test/handle_revoke_all_test.go:159`, `userinfo_logout_test.go:156`, `me_sessions_test.go:239,466,528`) are on *different* middlewares — the admin middleware only gates `/api/v1/{admin,compliance,scim,audit,netpolicy}*`. The E2E path-list extension is valid too: `adminGatewayE2EConfig` derives from `fullFeatureConfig` (Audit.APIEnabled=true, build_app_coverage_test.go:133), so the audit route is mounted in `TestAdminGatewayE2E_UnauthenticatedRequestsStill401`'s config and `/api/v1/audit/events` is not yet in its path list (verified :333-338).

## (2) REQ-4 — `BindParamsFormOnly`/`normalizeContentType` bypass probes: **all blocked; no new oracle**

I probed each vector against the proposed gate (which is the verbatim extraction of BindParams :31-34: strip at first `;` → TrimSpace → ToLower → TrimSpace):

| Vector | Result |
|---|---|
| `; charset=UTF-8` / `;boundary=x` / `; charset = utf-8` (any param) | Stripped at first `;` → passes gate — correct per RFC 6749 §3.2, not a bypass |
| Leading/trailing spaces/tabs; `form ;charset` | TrimSpace → passes — correct normalization |
| Casing `Application/X-Www-Form-Urlencoded` | ToLower → passes |
| Internal whitespace `application / x-www-form-urlencoded` | No match → **rejected (fail-closed)** |
| `multipart/form-data; boundary=...` | No match → rejected |
| Missing header / whitespace-only header | `ct == ""` → rejected (explicit) |
| Duplicate Content-Type headers | Go's `Header.Get` returns the first value; first must be the form CT to pass; a JSON body behind a form CT goes through `ParseForm` → no `grant_type` binds → 400 — **no JSON decode ever in strict mode, no smuggling path** |
| Query-string credential injection | `formIntoStruct` reads `r.PostForm` (body only) — blocked in both modes |
| NUL/BOM prefix | TrimSpace doesn't strip → rejected (fail-closed) |

**No drift risk:** the extraction is mechanical from the exact lines verified in bind.go; permissive `BindParams` behavior is provably unchanged, and both dispatchers share one normalization so the gate can't disagree with the parser.

**Default-off leaks no oracle:** (a) zero value false; `WithStrictCredentialContentType()` no-arg — verified `oauth21Strict bool` sits at sso_protocol.go:184 and the combined-field trick keeps the 500-line budget; (b) the strict 400 is `{"error":"invalid_request"}\n` (28 bytes — `ctx.JSON` = `json.NewEncoder` + sorted single-key map, no trace middleware in the harness) — **byte-identical to the permissive mode's own bind-failure 400** (e.g. permissive + `text/plain` + non-JSON), same `Content-Type: application/json`, no `WWW-Authenticate` (bind-failure path uses `ctx.JSON` directly); (c) all credential-relevant outcomes (`invalid_client`, DPoP/mTLS, grant dispatch) are mode-independent and byte-identical across modes — strict mode only moves *which requests reach them*; (d) the observable strict-vs-permissive difference (JSON→400 vs JSON→200) reveals the config knob, never credential/store state — not a credential oracle. `TestToken_BadJSON_400`'s status-only assertion is indeed mode-proof (A4 verified: test/handle_token_test.go:85-96).

## (3) no-store/Pragma and the D5 `os.Exit` path: **preserved; no oracle**

- `tokenNoStoreHeaders` (interfaces/middleware/no_store.go:22-29: `Cache-Control: no-store` + `Pragma: no-cache`) is stamped at server_token.go:22 — **before** `requireDeps` and the bind — so both the permissive and strict branches, and every outcome (strict 400, bind 400, 500, 401 `invalid_client`, 200 success), carry both headers. The design's "strict 400 carries no-store + no-cache" claim is structurally guaranteed, not just tested.
- Admin-surface 401s do *not* carry no-store — pre-existing and unchanged; the admin surface isn't a credential endpoint and REQ-2 adds no endpoint, so AGENTS.md's `tokenNoStoreHeaders` rule for *new* bearer endpoints isn't triggered. Worth noting as inherited state, not a regression.
- **D5:** verified `Run`'s only load-error handling is `errorf("load events: %v", err)` → `os.Exit(1)` (main.go:496-499), so the wrong-bearer 401 leg (`page (offset=0) http 401: ...`) genuinely cannot be asserted in-process; the design's `readFromURL`-level leg (b) is the correct choice. Oracle analysis of that path: (a) the bearer travels only in the `Authorization` header (fetchEventPage :461), never in URL/query/error strings; (b) exit code 1 for *every* load error (401, network, parse, 5xx) — no distinguishability; (c) the stderr message mirrors the server body verbatim, which REQ-2 converges for missing/wrong; (d) missing `--bearer` exits 2 via `usageErr` before any I/O — deterministic local misuse, no server interaction. No credential material ever reaches stderr. **No new oracle.**
- One pre-existing, out-of-scope note: `fetchEventPage`'s error embeds the raw response body — a *malicious server* could inject terminal escapes into operator stderr (log injection, CLI-is-client side). Not a credential oracle; unchanged by this design.

## Verdict

**All three oracle-safety claims hold.** REQ-2's convergence is byte-exact (headers, body, ordering) and the challenge literal equals `setBearerChallenge`/`QuoteAuthParam` output; REQ-4's gate blocks every probed bypass vector (charset, whitespace, casing, multipart, absent header, duplicates) and the default-off strict 400 is byte-identical to the existing permissive bind-failure — no new oracle; no-store/Pragma survive on both branches by construction, and the D5 `os.Exit` load-error path carries no credential material and no distinguishing exit behavior. Two non-blocking observations to record in the design's failure-mode table: the deliberate RFC 6750 §3.1 "error on credential-less request" deviation (client refresh-loop consideration) and the pre-existing lack of no-store on admin 401s (unchanged, not a regression).
