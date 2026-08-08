Design written to `docs/architect-analysis/cmd-sso-ctl-apiclient-b4-4-form-probes-design.md`. Verification and design summary:

## Verification verdict

All four headline citations confirmed exactly; the red baseline reproduced (11 top-level failures + 9 subtests, all six root causes visible in output). **One claim refuted:**

| Claim | Verdict |
|---|---|
| `apiclient.go:Do` JSON-only (:103 marshal, :119 CT, :122 Accept, no `net/url`) | ✅ Confirmed |
| `token.go` five JSON sends (mint :72, revoke :244, post-revoke introspect :259, T-8d :297, T-9 :353-357) | ✅ Confirmed |
| `oauthwire/bind.go:28` — form branch :38-42, `default:` :43-46 → `decodeSingleJSON` | ✅ Confirmed |
| `goldenGreenStdout` :32, `TestSweep_GreenPath` :446 | ✅ Confirmed |
| Baseline red — 11 tests, six root causes (incl. `iss` fixture missing `WithEd25519Issuer`, prod wiring at build_signing_issuers.go:43) | ✅ Reproduced |
| Supporting facts: `PostForm.Has("client_secret")` (interfaces/sso/server_token_clientauth.go:99), `Resource []string` (token_request.go:25), introspect via `BindParams` (:120), `_test.go` exempt from 500-line gate (maintainability_budget_test.go:71), strict-mode R3/R5, sibling T-8b, deferred note :490 | ✅ Confirmed |
| **"Both files are in place and identical"** | ❌ **REFUTED** — direct diff: the pipeline artifact is a 26-line summary *asserting* identity; the mirror is the full 449-line spec. Downstream stages must read the mirror |

Minor line drift only (handle_introspect :74-78 vs :72-78; formStringSlice at bind.go:149-157 vs cited :119-157); substance intact.

## Concrete design

**API changes**
- `apiclient.Client.PostForm(path string, values url.Values) (*http.Response, error)` — sole addition; `values.Encode()` (deterministic, key-sorted), form CT, `Accept: application/json`, bearer when token set, `c.http` carries the no-redirect pin. `Do/Post/Get/Delete/Patch` byte-identical.
- Five call-site flips in token.go: mint, revoke, post-revoke introspect, T-8d, T-9 → form bodies; byte-identical `invalid_scope`/`invalid_client` pins, refresh_token rejection, and T-9's bearer-less bare client unchanged (REQ-0.6 unquotes its diagnostic).
- New `runT8e()` in `token_contenttype.go`: legs A/B = JSON credential body under `application/json`/`text/plain` CT (JSON body is load-bearing — a form body 400s today too, making the row vacuous). Pass = 4xx + JSON error envelope (class, not code → tolerates strict-mode `400 invalid_request` and `trace_id`); fail = 200 (body never echoed — real token), 3xx, 5xx, non-JSON, missing `error`. Group line `content_type: OK/FAIL`; golden extended; wired between runT8a and runT8d.
- REQ-0 baseline stabilization: six harness fixes + one sweep.go assertion (`checkTokenSuffix` aligns to the stricter contract the test already pins).

**Compatibility** — server untouched (`BindParams` accepts form today, so five probes stay green; only T-8e turns red = intended detection); response pins transport-independent; secret presence survives via `PostForm.Has`; sibling campaign's same-five-flips merge idempotently.

**Failure modes** — permissive server → FAIL/exit 1 (designed); partial enforcement, redirects (never followed), 5xx, non-JSON envelopes → FAIL; invalid creds → vacuous pass documented (sweep already red); 200 legs mint TTL-bounded unrevoked tokens → accepted residual (D3, mirrors T-8a's crash window; revoke-on-200 deliberately out of scope).

**Migration** — REQ-0 gate (suite green with current golden) → PostForm → five flips → runT8e+wiring → harness/tests → `build/vet`, maintainability/architecture, `-race`, `make ci`. Rollback = revert five sites + wiring; no persisted state.

**Acceptance mapping** — T-8(a)→ClaimsMatrix/Revoke_RoundTrip/StdoutDeterministic + form-shape assertions; T-8(d)→InvalidScope_ByteExact; T-9→NoCreds401/NoAuthHeaderLeak/Non401Fails; T-8(e)→8-case matrix + skip; green-under-enforcement→`TestSweep_FormOnlyGreen`; red-today→`TestSweep_ContentTypeRowFailsToday`. Budgets: all files ≤500, 5 non-test files, no new packages.
