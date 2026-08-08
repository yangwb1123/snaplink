Requirements specification complete. **`docs/architect-analysis/cmd-sso-ctl-b4-4-check-probes-form-requirements.md`** — doc-only artifact (no `.go` edits, so no build gates triggered).

## Evidence verification results

Every citation in the direction was re-checked against the working tree. All symbols and behaviors confirmed; the analysis's line numbers drifted (older revision):

| Citation | Verdict |
|---|---|
| `apiclient.go:74-90` Do JSON-encodes all bodies | Confirmed — actually :98-123 (`json.Marshal` :103, CT `application/json` :119) |
| `token.go:37-47` mint | Confirmed — mint :59-72 (body map :60-70, `Post` :72) |
| `token.go:224-244` T-8d | Confirmed — runT8d :286-336 (POST :297-303, `wantBody` :316-317) |
| `token.go:263-276` T-9 | Confirmed — runT9 :338-362 (JSON body :353, CT :357) |
| `oauthwire/bind.go:28-46` unexpected CT → JSON | Confirmed **exactly** (:28-46; `default:` :43-46 → `decodeSingleJSON`) |
| `check.go:34-41` body-credentials posture | Confirmed — comment block :25-32, `probeClient` :269-277 |
| T-8e `refresh_token` assertion | Confirmed — token.go:96-99 (test row at check_test.go:961) |

## Key load-bearing findings beyond the citations

1. **The T-8b probe body must be JSON** for the row to be meaningful: a form body under `text/plain` 400s *today* (JSON decode failure), making the row vacuous — only a JSON body is accepted today (`handleToken` bind-failure → `400 invalid_request`, server_token.go:31-34) and rejected after hardening.
2. **Byte-identical `{"error":"invalid_request"}\n` is achievable**: the default server emits no `trace_id` (Tracing is opt-in), and the server-side strict-mode contract pins exactly this body with a "modulo trace_id" caveat — T-8b inherits that caveat (the only probe whose path is trace-capable; T-8d/T-9 use trace-free `core.ErrorBody`).
3. **Form decoding of all probe fields is already supported** (`formIntoStruct`, `PostForm.Has("client_secret")`), so mint/T-8d/T-9 stay green today after the transport switch; only T-8b turns red — the intended detection behavior, pinned by a `TestSweep_ContentTypeRowFailsToday` live-server test that flips to green when the strict parser lands.
4. **Test-harness wire coupling**: the stub's `handleIntrospect` discriminates T-9 vs post-revoke via the JSON-only `"client_id"` substring and would misroute form bodies — REQ-7 makes it wire-agnostic.
5. **Scope inventory**: exactly five JSON credential sends switch to the form wire (mint :72, revoke :244, post-revoke introspect :259, T-8d :297, T-9 :353-357); T-2's body-less rows and the admin-API JSON contract are untouched.

The supplied acceptance checks are preserved verbatim (§4) and mapped to testable criteria (REQ-1–REQ-7, §8 verification plan). Scope is bounded: no server-side edits, no cache-header assertions, no typed helpers, no T-8c; the prior sweep spec's deferred "T-8b JSON Content-Type rejection" note is advanced.
