All three review targets have been checked against the working tree (HEAD `f9ceb251`, plus the sibling/requirements docs). Verdicts, then the findings.

## Review verdict

**A. Content-type ambiguity: sound.** **B. Oracle parity at the 8 sites: sound with one behavioral leak into legacy mode (F12).** **C. Admin dual-mode sites: not flipped (D-5 holds), but the shared-decoder F11 change has one unnamed collateral consumer, and the sweep checklist misses the `protocols/oauth` unit suites (guaranteed red at the step-3 checkpoint).** Four concrete fixable findings below, plus one internal contradiction the design inherits from requirements R5.2.

---

## A. Content-type ambiguity — verified sound

Confirmed against `protocols/oauth/oauthwire/bind.go:28-58` and the seam chain (`server_jar.go:304` → `aliases.go:97` → `bind.go:28`):

- **Missing-CT→JSON default** (:43-45, comment :24-25) is exactly as cited; the strict binder rejecting before body read is correct, and Go's `ParseForm` internal CT check is a *prefix* match while the strict binder's normalized check is an *exact* match — the binder can never pass a CT that `ParseForm` would refuse, so the shared `bindForm` (ParseForm + `formIntoStruct`) is consistent.
- **Charset/parameter variants**: `;`-strip + lowercase + trim (bind.go:31-35) handles `;charset=UTF-8`, quoted values, ` ; ` whitespace, and boundary-style params; a garbage suffix without `;` (`application/x-www-form-urlencodedX`) falls to reject — no divergence since the strict path never reaches `ParseForm`.
- **Multipart**: normalized to `multipart/form-data` → rejected before parse; note Go's own `ParseForm` would parse multipart, but the strict path never calls it — the acceptance case 7 (12 combinations) is consistent. No `ParseMultipartForm` exists anywhere in the server handlers (verified).
- **Empty CT header, double CT headers (first-wins via `Header.Get`)**: both behave as designed; no new oracle.

Two precision nits:

1. **`device/verify` credential-first ordering** — `authenticateDeviceVerifyBearer` runs at `server_device.go:233`, the bind at `:242` (9 lines earlier in the handler, *before* the parse). §3.1's "reject … before any body parse and before any credential logic" is false for this site, and acceptance cases T-8(b) 1-2 and T-8(c) 5-6 ("400 on **all eight** endpoints") only hold at `/device/verify` when the request carries a **valid bearer** — otherwise it 401s before the CT check. The test rows need the bearer; the claim should be scoped to the seven parse-first sites.
2. §3.2's "empty body WITH form CT → /token → 400 invalid_request for missing grant_type" only holds with *valid client credentials*; without Basic the empty form 401s at the auth gate (bind precedes auth at :30/:35, so the empty struct still reaches `authenticateTokenClient`). Cosmetic example imprecision, not a defect.

## B. Oracle parity across the 8 sites — verified, one finding

All eight sites collapse every bind error (including the new `errFormOnly`) to their canonical envelope, verified line-by-line:

| Site | Bind error → wire |
|---|---|
| token :30, introspect :120, revoke :75, par :66, device/code :53, device/verify :242 | `400 invalid_request` |
| ciba :87 | `400 invalid_request` |
| mfa :255 (`parseMFACompleteRequest`) | `400 mfa_invalid` via `authzErrorBody` (server_discovery.go:265: `iss` + trace + localization), no audit |

No text, code, or header distinguishes `errFormOnly` from a malformed form body at any site; strict-vs-legacy and JSON-vs-form collapse identically; the 400-vs-401 boundary exists only for *bindable* form bodies, unchanged from HEAD. `errFormOnly` unexported — no new `Err*`, consistent with AGENTS.md §3. (Pre-existing, unchanged: sso-side envelopes carry `trace_id` via `errorBody`→`ErrorBodyWithTrace`, protocol-side don't — a cross-family envelope asymmetry that predates this design; the MFA envelope already includes `iss`.)

**Finding B1 (MEDIUM) — the F12 `params` fail-loud is unconditional and breaks the legacy fallback's byte-identical claim.** `parseMFACompleteRequest` (server_mfa.go:253) is the one place the design puts a *behavioral* check (not the binder): `PostForm.Has("params")` → 400. Under `WithCredentialFormOnly(false)` the sites call `BindParams`, whose form path today silently drops `params` and continues; after F12 the same request 400s. §3.2's "byte-identical to HEAD" fallback promise and case 15 cover only JSON/missing-CT acceptance, so this legacy-mode delta is unnamed. Fix: gate the check on `s.credentialFormOnly` (strict-only), or explicitly carve `/auth/mfa` form+`params` out of the byte-identical claim and add a case-15 row for it. (The `PostForm` dependency itself is safe: `ParseForm` runs inside the shared `bindForm` in both modes, and the JSON path never populates `PostForm` — but note `server_token_clientauth.go:99` reads `r.PostForm.Has("client_secret")` directly, so the strict binder must keep calling `r.ParseForm()`; the shared-`bindForm` extraction preserves this — pin it with the existing form-harness auth tests.)

## C. Dual-mode admin sites — not flipped; one collateral consumer

D-5 verified: `server_admin_handlers.go:293` and `options_admin.go:414` stay on `bindOAuthParams` (dual-mode); both structs are single-string (`Reason`) so JSON/form divergence is nil there; the admin compromise tests (`interfaces/sso/rootcov_admin_credential_compromise_test.go:178` posts `application/json`) stay green. No accidental flip in the design; F14 covers the review gate.

**Finding C1 (MEDIUM) — F11's shared-decoder RawMessage branch has an unnamed non-credential consumer.** `interfaces/admin/governance.go:35` — `proposeChangeRequest.Payload json.RawMessage`, bound via `oauth.BindParams` at governance.go:61 (POST `/api/v1/admin/changes`). Today a form `payload` is silently dropped; after the F11 Uint8 branch it binds (json.Valid-gated). The design's "byte-identical for every existing supported field kind; the only behavior change is for form keys that today silently drop (PAR `authorization_details`/`claims`)" is factually incomplete — the design noticed the `map[string]string` silent-skip case but not this one. Low practical exposure (admin API is JSON-first), but the change is in the *shared* decoder so it cannot be scoped to PAR; either name governance.go in the change note with a pin test, or accept-and-document. The pre-existing []string/`map` JSON↔form divergence at other admin dual-mode sites (e.g. connections.go:23-25) is untouched — correct.

## Additional findings

**Finding D1 (HIGH) — the sweep inventory omits the `protocols/oauth` unit suites; step 3's "expected red" is bigger than the checklist covers.** The four Deps fakes — `introspectDeps` (handle_introspect_test.go:28), `revokeDeps` (:19), `parDeps` (:17), `cibaDeps` (:18) — must gain `RequireFormContentType()`. If they return `true` (matching the production default), **27 JSON-post call sites go red that are not in the §3.5 step-4 / F1 checklist** (which lists only `test/` files): handle_revoke_test.go (10), handle_introspect_test.go (7), handle_par_test.go (6), handle_ciba_test.go (3), introspect_cache_test.go (1). If they return `false`, the strict path is untested at protocol-unit level (e2e-only) and the fakes silently diverge from the production default — a future-contributor trap either way. The design must decide and enumerate: I recommend fakes return `true` + migrate the 27 posts (they are small, structured bodies), and the F1 checklist gains these five files.

**Finding D2 (MEDIUM) — step 4's "flip TestBindParamsJSONDefault" contradicts the design's own F9/§3.3.** The test calls the package-level `BindParams` (legacy), whose JSON-default branch is *kept* for the 44 non-credential consumers and the fallback mode (requirements appendix :376-377 "default branch kept"). Flipping it to assert strict rejection either fails against the kept code or (if rewritten to call `BindParamsFormOnly`) silently deletes the only regression pin for the preserved legacy default — the exact guard F9 requires. The requirements' R5.2 mandate is the root cause; this needs a requirements correction. Resolution: keep `TestBindParamsJSONDefault` green as the legacy pin (re-comment it as "non-credential/legacy contract"), and put strict rejection in the new `bind_strict_test.go` (case 16) where the design already has unit coverage. Same logic for the fuzz: re-seeding `FuzzBindParams` (actual line **:34**, not :28 as cited) to assert strict errors means the *legacy* binder — still live on 44 sites — loses its panic-safety fuzz; keep a legacy fuzz alongside the strict one. Also note `FuzzBindParams`' `fuzzBindTarget` already carries `Claims json.RawMessage`, so the F11 branch is fuzz-reachable on the form path only after the decoder change — add form-path `claims` seeds.

**Finding D3 (LOW) — MFA OpenAPI schema is shared between the form and JSON variants.** openapi.yaml:14462+ defines `MFACompleteRequest` (with `params`) referenced by *both* content types at :641/:644. Step 7 says "document the params-is-JSON-only rejection" — but with a shared `$ref`, the form variant must diverge (or carry an explicit note) or the contract still implies form `params` is accepted. Contract-drift risk; split the schema or annotate.

## Verification log (all confirmed against the tree)

- 8 sites + line numbers: exact (`token:30, introspect:120, revoke:75, par:66, device:53/242, mfa:255, ciba:87`); `bindOAuthParams` seam :304; alias :97; `BindParams` :28.
- `TestBindParamsJSONDefault` :148/:150; `TestFormEncoded_JSONStillWorks` test/oauth_bind_test.go:272; `BasicAuthOverridesBodyCreds` :146; C1 `ctx.Bind` router.go:137; payment_ingest.go:99 JSON-required; config_server.go:16; `ServerOptions()` :301 with `anySet` gate :336-339; `NewServer` seed-before-options pattern (sso.go:56-76, next to `clientRegistrationRateLimiter`); `interfaces/sso` = 60 non-test files (ceiling exact); oauthwire 6→7 files; gensdk sequencing gate verified (`cmd-gensdk-tokenfamily-form-emission-design.md:476`: "MUST land before the server form-only flip"); OpenAPI: 8 form CTs (641/1100/1278/1345/1475/1541/1602/1849), 8 JSON variants (644/1139/1281/1348/1478/1544/1605/1852), paragraph :1061-1066; **C9 confirmed** — requirements appendix says "seven paths" (:388), CIBA JSON variant exists at :1605.
- Minor citation drifts (report only): `FuzzBindParams` :34 vs :28; CIBA JSON variant 1605 vs "~1610"; `config_gates_test.go` reference :52 vs :41; no production-code drift found.

**Bottom line:** the binder semantics, the error collapse, and the D-5 exclusion are correct as designed. Before implementation: fold in D1 (sweep completeness), D2 (test-flip contradiction — needs the requirements correction), B1 (gate or document F12 in legacy), and C1 (name governance.go's RawMessage). Items A1/A2 and D3 are test-spec/contract precision fixes.
