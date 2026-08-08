# Credential-handling review: form-encoded probe path (b4-4 design)

Reviewed the design against the working tree (`apiclient.go`, `token.go`, `check.go`, `sweep.go`, `check_test.go`, `oauthwire/bind.go`, `server_token_clientauth.go`, `handle_introspect.go`). Tree builds clean. Verdict: **sound on all seven asked items, with one real design-internal defect (migration ordering) and three nits.**

## 1. `client_secret` in body vs Basic — correct, no Basic anywhere

All five flip sites verified: mint (:72), revoke (:244-246), post-revoke introspect (:259-261), T-8d (:297-303), T-9 (:353-357, explicit CT :357). Every site already used body credentials today; the flip is JSON-body → form-body, **never Basic**. This is the correct RFC 6749 §2.3.1 fallback posture, and the server round-trips it: `r.PostForm.Has("client_secret")` (server_token_clientauth.go:99) survives the form wire, `BindParams` form branch → `formIntoStruct(r.PostForm, v)` binds `TokenRequest.Resource []string` via multi-value (bind.go:149-157). Secrets never appear in URLs (body-only), and the no-redirect pin means a 307/308 `Location` is observed, never fetched (`rejectRedirect` → `ErrUseLastResponse`; `TestSweep_RedirectNotFollowed` pins zero requests to the target).

## 2. Bearer attachment in `PostForm` — inert for all call sites, correct

`PostForm` mirrors `Do`'s `if c.token != ""` guard. All five flips go through `probeClient` (sweep.go:269-277), which constructs `&Client{baseURL, http}` with **no token** — no bearer can attach. The only token-capable client (`ck.client`, inherits `SSO_ADMIN_TOKEN`) is used exclusively for discovery GET + T-2 rows, never PostForm. T-8e uses a bare client. So the documented posture ("mint/T-8d/T-9 probes never carry a bearer; a non-Basic Authorization header makes /token reject outright") holds; `PostForm`'s bearer branch is defensive API symmetry, not reachable from the sweep.

## 3. No-redirect pin through `c.http` — confirmed

`PostForm` dispatches via `c.http.Do(req)`; the pin lives on the `http.Client` (`CheckRedirect: rejectRedirect`), which travels with the client. `probeClient` and both bare clients (runT9, T-8e legs) set it explicitly. The uncommitted `WithNoRedirect` (confirmed: apiclient.go has a working-tree diff adding it; the entire `apiclient/` dir is uncommitted WIP) pins the sweep client additionally — but the five flips don't depend on it, so no latent dependency on committing WIP. 3xx on any flipped probe → observed, body read, FAIL — never forwarded. Also note: even if a redirect were followed, Go only re-sends bodies on 307/308 — but the pin makes it moot.

## 4. T-9 bearer-less bare-client probe — preserved exactly

The flip keeps the bare `&http.Client{Timeout: 30s, CheckRedirect: rejectRedirect}` (structurally immune to `SSO_ADMIN_TOKEN` — `apiclient.New`'s env fallback never runs), drops the explicit JSON CT for form, and the body stays credential-less (`token=sweep-probe-dummy`). Stub discrimination holds on the form wire: `handleIntrospect` keys on `"client_id"` presence, and the T-9 form body has none (the *post-revoke* introspect does — see finding F1). Live server: form branch binds `token` only → `401 invalid_client`. Byte pin `{"error":"invalid_client"}\n` is response-side, transport-independent.

## 5. Error-envelope parsing — no credential/token echo path found

- T-8e pass = 4xx + JSON object with non-empty string `error`; fail diagnostics name leg CT + status only.
- 200 (real token) → **body never decoded, never echoed** — consistent with the mint rule (mint's 200-without-access_token branch also never echoes).
- Non-2xx echoes go through `sanitizeBody` (redacts `access_token`/`refresh_token`/`id_token`/`client_secret` values, truncates at 200B) — and 4xx snaplink bodies are envelopes, not tokens.
- No code path prints a *request* body; credentials appear only in bodies and are never echoed. `TestDiagnostics_NeverEchoSecrets` pins the integration behavior.
- Pre-existing bounded gap (not widened here): `redactSensitiveFields` only redacts exact JSON keys; a server echoing the secret inside `error_description` would leak to stderr. Strict-mode envelopes are `{"error":"invalid_request"}` only, so out of scope — worth a note, not a change.

## 6. Residual (200-leg mints TTL-bounded unrevoked tokens) — acceptably bounded; revoke-on-200 decision is sound

Confirmed the exposure: on a permissive server each 200 leg mints a real token, and unlike T-8a's mint (revoked in the success path) these two are never revoked. Bounds: token lives in the 1MB in-memory read buffer and is dropped; never printed or persisted; scoped to the operator's own client; minted only by the exact permissiveness the row detects; and the T-8a crash window (mint→revoke gap) already leaves the same class of exposure. Revoke-on-200 would corrupt the verdict (a CT-enforcing server with a broken/absent revoke endpoint → false FAIL), require token extraction from the very body the row deliberately never decodes, and gain nothing against a server that already fails the row at 200. D3's trade-off is correct. **Nit (F3):** "TTL-bounded (1 min)" is the *fixture* TTL (`newLiveServer` → `WithEd25519TokenTTL(time.Minute)`); production bound is the server's configured token TTL. The design should say "bounded by the server's configured token TTL" to avoid overstating the bound.

## 7. Cache-Control on the client side — nothing needed; make it explicit

No client-side handling is required and none is warranted: Go's `http.Client` has no cache layer, the sweep reads each body once into memory (`ReadBody`, 1MB cap) and drops it — nothing is ever persisted or replayed. `no-store` is a *server* contract: `middleware.TokenNoStoreHeaders` already stamps introspect (confirmed), `server_token.go:20` documents token/revoke, and the separate `stamp-cache-control-no-store…` campaign owns enforcement. The scope guard's "no cache-header assertions on the new row" is correct — asserting them would conflate the CT-enforcement verdict with a header contract and false-fail an otherwise conforming server. Recommend one positive sentence in §2.3/§8 stating the client has no cache layer and no-store remains server-side; currently the design only states the negative.

## Findings

- **F1 (real, must fix): migration-step ordering contradicts its own gate.** Step 3 says "flip the five call sites … run the module suite (T-8e not yet wired; suite must stay green)" but the REQ-8 `handleIntrospect` wire-agnostic fix is scheduled in step 5. After the flips, the post-revoke introspect sends a form body containing `client_id=…` — the stub's JSON-only `"client_id"` substring check (check_test.go:249-258) misses it, misclassifies it as the T-9 probe, returns `401 invalid_client`, and breaks the revoke leg. I traced the impact: at least 10 stub-based tests fail — `TestIntrospect_NoCreds401`, `TestIntrospect_NoAuthHeaderLeak`, `TestInvalidScope_ByteExact`, `TestSweep_3xxTruthinessPasses`, `TestSweep_AdvertisedOnly`, `TestSweep_DecoyFieldNotFetched`, `TestSweep_EnvAddrValidation/valid-env-steers-sweep`, `TestRevoke_StillActiveFails`, `TestMint_TenantIDExpectation/present-matches`, `TestMint_RolesExpectationFailsOnCC/stub-with-roles-passes`. **Fix:** move the `handleIntrospect` discrimination change into step 3 (it is the *enabling* harness fix for the flips, not a follow-on), or reword step 3's gate.
- **F2 (nit):** design §2.2 misnames REQ-0.6's operand — the `%q` is on the *expected* body constant (`expected 401 %q` at token.go:368); the observed body is already `%s`. The requirements doc says "expected body unquoted" (correct). Substance (unquote at :368) is right; fix the phrasing.
- **F3 (nit):** D3 TTL bound — see §6.
- **F4 (note):** runT8e skips `validateAdvertisedURL`, unlike T-9. Not a new exposure: T-2's row-2 preflight validates `token_endpoint` before any credential-bearing probe (and mint/runT8d also skip it), so the asymmetry is only vs T-9 (whose field T-2 doesn't validate — introspection_endpoint is not a T-2 row). No action required; consistency with mint is the right call.

## Bottom line

Credential handling in the proposed form path is safe and bounded: secrets stay body-only, bearer stays off the credential probes, the redirect pin holds end-to-end, envelope parsing never echoes token material, the minted-but-unrevoked residual is TTL-bounded and no worse in kind than the existing T-8a window, and no client-side `Cache-Control` work is needed. The one must-fix is **F1** (harness discrimination must ship with the flips, not after); F2/F3 are one-line doc corrections.
