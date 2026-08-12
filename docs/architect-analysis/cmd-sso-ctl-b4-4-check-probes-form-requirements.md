# Requirements Spec: sso-ctl check probes aligned with B4-4 form-urlencoded hardening

- Direction: B4-4 / T-8 (source: `docs/architect-analysis/auto/analyses/cmd-sso-ctl-7e52c2bb.json`, entry 1)
- Module: `cmd/sso-ctl` (`apiclient` package — composition layer)
- Status: requirements (evidence-verified against HEAD)

## 1. Evidence verification

Every citation in the direction was re-checked against the working tree. All
symbols and behaviors are confirmed; several line numbers drifted (the analysis
was written against an earlier revision). Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `cmd/sso-ctl/apiclient/apiclient.go:74-90` — "Do JSON-encodes every body" | `Do` spans apiclient.go:98-123: `json.Marshal(body)` at :103, `Content-Type: application/json` set at :119 whenever `body != nil`, `Accept: application/json` at :122. Lines 74-94 are `WithAddr`/`WithNoRedirect`/`rejectRedirect` in the working tree | Confirmed (line drift ≈24; substance exact: every non-nil body is JSON-encoded and every body-bearing request carries `application/json`) |
| `cmd/sso-ctl/apiclient/token.go:37-47` (mint) | `mint` at token.go:59-72; body map (`grant_type`/`client_id`/`client_secret`, optional `scope`, `resource` as `[]string`) built at :60-70; `client.Post("", body)` at :72 | Confirmed (line drift ≈22) |
| `cmd/sso-ctl/apiclient/token.go:224-244` (T-8d) | `runT8d` at token.go:286-336; the credential POST (`grant_type`/`client_id`/`client_secret`/`scope` map) at :297-303; byte-identical `wantBody = {"error":"invalid_scope"}\n` at :316-317. Lines 224-266 are `revoke`'s two JSON POSTs (revoke at :244-246, post-revoke introspect at :259-261) — same defect class, in scope via T-8a's "revoke/introspect matrix" | Confirmed (line drift ≈60; substance exact) |
| `cmd/sso-ctl/apiclient/token.go:263-276` (T-9) | `runT9` at token.go:338-362; `http.NewRequest(POST, target, strings.NewReader(`{"token":"sweep-probe-dummy"}`))` at :353; `req.Header.Set("Content-Type", "application/json")` at :357; bare `http.Client` (structurally bearer-less) at :350-351 | Confirmed (line drift ≈75) |
| `protocols/oauth/oauthwire/bind.go:28-46` — Content-Type dispatch; unexpected CT defaults to JSON | `BindParams` at :28; `switch ct` at :37-42 (form branch :38-42); `default:` at :43-46 — "Default to JSON for application/json, missing CT, or anything unexpected" → `decodeSingleJSON(r.Body, v)` | Confirmed exactly (28-46 matches) |
| `cmd/sso-ctl/apiclient/check.go:34-41` — probe security posture "body credentials only" | The "Security posture" comment block sits at check.go:25-32 ("credential-bearing probes go through apiclient with body credentials, targeted at the *advertised* endpoints only" at :29-30); lines 34-41 are the import block. `probeClient` (:269-277) is token-less, no-redirect, env-fallback-free | Confirmed (line drift ≈9; substance exact) |
| Acceptance's "token.go:52-54 assertion" (T-8e, no refresh_token) | The cc-response refresh_token rejection is at token.go:96-99 (`if out.RefreshToken != "" { return ..., "mint: unexpected refresh_token in cc response" }`); test row exists at check_test.go:961 | Confirmed (line drift ≈44) |

Load-bearing facts verified during this pass (each pins a spec requirement):

1. **The "fails today" claim is executable and the probe body must be JSON.**
   `handleToken` maps every `bindOAuthParams` failure to `400 invalid_request`
   (interfaces/sso/server_token.go:31-34). Today, `text/plain` or absent
   Content-Type with a **JSON** body falls into `decodeSingleJSON` and mints
   (200) — the row fails. A *form* body under those Content-Types would
   JSON-decode-fail and 400 even today (vacuous pass), so both T-8b legs MUST
   carry the JSON credential body to detect the missing hardening.
2. **The default server's `400 invalid_request` body is byte-identical
   `{"error":"invalid_request"}\n`.** The body goes through
   `core.ErrorBodyWithTrace` (shared/core/error_body.go:31-37), which omits
   `trace_id` when no trace is in context; the Tracing middleware that stashes
   one is opt-in (`WithTracingMiddleware`, interfaces/sso/options_security.go:487-497;
   `requestIDMW` defaults false, sso_wiring.go:53; mounted at server_routes.go:112).
   The server-side B4-4 strict-mode contract pins the identical rejection:
   wrong/absent Content-Type → `400` + body exactly `{"error":"invalid_request"}`
   (docs/architect-analysis/auto/runs/enforce-form-urlencoded-credential-strict-mode-0a8df02f/artifacts/requirements-0a8df02f/requirements.md:88-89,108,149-150),
   with the byte-compare caveat "modulo the request's own `trace_id` if Tracing
   is wired" (AC-2 b2, same artifact). T-8b inherits exactly that caveat.
3. **T-8b is the only probe whose assertion path can see a `trace_id`.**
   T-8d's `invalid_scope` and T-9's `invalid_client` come from plain
   `core.ErrorBody` (scoperegistry/reject.go:37; handle_introspect.go:216,227,233),
   which never carries `trace_id` — the sweep's existing byte-identical checks
   (check_test.go:1100 row 19, :1193 row) are unconditionally strict. The
   `invalid_request` path is trace-capable by construction, hence T-8b's
   modulo-`trace_id` rule (REQ-6).
4. **Form decoding of every probe field is already supported server-side.**
   `formIntoStruct` binds `grant_type`/`client_id`/`client_secret`/`scope`
   (string) and `resource` (`[]string`, multi-value or space-split,
   oauthwire/bind.go:128-157, token_request.go:12-25); secret *presence*
   survives the form wire via `r.PostForm.Has("client_secret")`
   (server_token_clientauth.go:99) — `BindParams` calls `ParseForm` before
   decoding (bind.go:38-42); `introspectRequest.Token` binds on the form wire
   (handle_introspect.go:75-76). So mint/T-8d/T-9 remain green against the
   *current* server after switching transport; only T-8b turns red today.
5. **T-2 is unaffected.** Its endpoint rows POST with `nil` bodies
   (sweep.go:158-162: `client.Do(row.method, path, nil)`) — no body, no
   Content-Type; truthiness rows (want==0) pass on any non-404 under both the
   permissive and the strict parser.
6. **The prior sweep spec deferred exactly this work.**
   docs/architect-analysis/auto/cmd-sso-ctl-apiclient-requirements.md:490:
   "B4 items T-8b/T-8c/T-8e (JSON Content-Type rejection, ...) are other
   directions' acceptance, not this one." This direction is that deferred T-8b
   plus the form transport; T-8c (constant-time) stays out of scope.
7. **Test-harness wire coupling must be updated.** The stub's
   `handleIntrospect` discriminates T-9 vs post-revoke requests with
   `bytes.Contains(body, []byte(`"client_id"`))` (check_test.go:239-244) — a
   JSON-only shape; form bodies carry `client_id=` without quotes, so the
   discrimination must parse the body (form/JSON) instead. The stub's
   `handleToken` discriminates T-8d by the raw `sweep-probe-` substring
   (:229-231) and survives the form switch unchanged.
8. **Scope inventory of JSON credential sends in the sweep** (all five switch
   to the form wire; T-2's body-less rows stay): mint token.go:72; revoke
   :244; post-revoke introspect :259; T-8d :297; T-9 :353-357.
9. **Admin API callers must stay JSON.** `apiclient.Do` is also the admin API
   client (GKE-gateway JSON surface). The form transport is a NEW method used
   only by the credential probes; `Do`'s JSON behavior is untouched (REQ-1).

## 2. Goal and user outcome

B4-4 hardens the credential endpoints (`/token`, `/token/introspect`,
`/token/revoke`, `/par`) to enforce `application/x-www-form-urlencoded`.
`sso-ctl check` — the deploy-tree live sweep — must (a) keep exercising its
credential probes on the canonical form wire so they survive the hardening
instead of breaking or bypassing the hardened parser, and (b) gain a
wrong-Content-Type rejection row that turns red on today's permissive parser,
so a deployment that has not received the hardening fails the sweep.

Completion markers for the operator:

- `sso-ctl check` against a hardened server passes with a new
  `content_type: OK` line among the existing group lines (exit 0).
- The same command against today's permissive server fails exactly at that
  row (`content_type: FAIL`, exit 1) — the missing B4-4 hardening is
  detectable, which today it is not.
- Every mint/revoke/introspect/invalid_scope probe now speaks
  `application/x-www-form-urlencoded`; all existing byte-identical contracts
  are unchanged.

## 3. Product boundary

- Surface: `sso-ctl` operator toolbelt (`cmd/sso-ctl/apiclient`), `check`
  subcommand probe groups.
- Default: always-on probe rows (no flag gates the transport; T-8b follows the
  T-8d precedent of a documented validity precondition rather than a flag).
- Explicit non-goals:
  - No server-side changes: no `interfaces/sso`, `protocols/oauth` or
    `oauthwire` edits, no new endpoints, no OpenAPI/config/error-code changes.
    The strict parser itself is the separate
    `enforce-form-urlencoded-credential-strict-mode` direction; this spec
    pins the sweep against its published contract (evidence fact 2).
  - T-8c (constant-time comparisons) and T-8e-as-a-separate-row (cache-header
    assertion) stay other directions' acceptance; here T-8e is only the
    existing refresh_token rejection kept green on the form path.
  - No cache-header (no-store) assertions, no typed `TokenRequest`/
    `Introspect` helpers, no JWT signature verification.
  - No change to `apiclient.Do` or the admin-API JSON contract.

## 4. Acceptance criteria (supplied acceptance, preserved verbatim)

> T-8a: mint probe POSTs application/x-www-form-urlencoded to the advertised
> token_endpoint and the existing claims/revoke/introspect matrix still passes;
> T-8b (new row): POST with Content-Type text/plain and with no Content-Type
> to the advertised token_endpoint returns a byte-identical 400 invalid_request
> (fails today because bind.go defaults to JSON); T-8d: probe body switches to
> form-urlencoded while the byte-identical 400 {"error":"invalid_scope"}
> contract is unchanged; T-8e: cc response still must not carry refresh_token
> (token.go:52-54 assertion) on the form-encoded path; T-9: credential-less
> introspection probe posts form-urlencoded per RFC 7662 and still expects
> byte-identical 401 {"error":"invalid_client"}.

Testable form of each check (map to the verification plan in §8):

| Check | Testable criteria |
|---|---|
| T-8a form mint | REQ-2: the mint request recorded by the stub carries `Content-Type: application/x-www-form-urlencoded` and a form body (`grant_type=client_credentials&client_id=...&client_secret=...`, `scope`/`resource` only when declared, `resource` repeated per entry); live-server `TestMint_ClaimsMatrix` (check_test.go:849) and `TestRevoke_RoundTrip` (:1039) stay green; revoke + post-revoke introspect requests (REQ-3) also carry the form Content-Type. |
| T-8b wrong-CT row | REQ-6: against a stub returning `400 {"error":"invalid_request"}\n` for both legs → exit 0 and `content_type: OK` in stdout; against today's live server → exit 1 with `content_type: FAIL` and a diagnostic naming status 200 (the row "fails today" — pinned by `TestSweep_ContentTypeRowFailsToday`, flips to the golden green when the strict parser lands); wrong status (e.g. 401) or wrong body (`invalid_scope`) fails; a `trace_id`-enriched body passes (evidence fact 2's modulo rule); an `error_description`-bearing body fails; both legs are exercised (two requests, one with `Content-Type: text/plain`, one with no Content-Type header at all). |
| T-8d form + byte-identical | REQ-4: `TestInvalidScope_ByteExact` (:1083) and rows 19-21 (:1094-1146) stay green; the recorded T-8d request carries the form Content-Type; the body still contains the randomized `sweep-probe-` scope; `wantBody {"error":"invalid_scope"}\n` byte comparison unchanged. |
| T-8e refresh_token | REQ-2: the assertion at token.go:96-99 is unchanged and the existing row (check_test.go:961, `mint: unexpected refresh_token in cc response`) stays green on the form-encoded mint path. |
| T-9 form introspect | REQ-5: `TestIntrospect_NoCreds401` (:1148), `TestIntrospect_NoAuthHeaderLeak` (:1159) and `TestIntrospect_Non401Fails` (:1184) stay green; the recorded T-9 request carries `Content-Type: application/x-www-form-urlencoded` with body `token=sweep-probe-dummy`; bare client, no `Authorization` header even with `SSO_ADMIN_TOKEN` exported; byte-identical `401 {"error":"invalid_client"}\n`. |

## 5. Requirements

### REQ-1 — Form transport method on apiclient (additive, admin contract untouched)

`apiclient.Client` gains exactly one method:

```go
// PostForm sends a POST with an application/x-www-form-urlencoded body.
func (c *Client) PostForm(path string, values url.Values) (*http.Response, error)
```

- Body bytes = `values.Encode()`; header `Content-Type: application/x-www-form-urlencoded`.
- Keeps `Do`'s semantics: `Accept: application/json`, bearer header when
  `c.token != ""`, the caller's `http.Client` (so `probeClient`'s no-redirect
  pin applies), caller closes the body.
- `Do`/`Post`/`Get`/`Delete`/`Patch` are byte-for-byte unchanged — the admin
  API JSON surface never changes.
- New import: `net/url` in apiclient.go (apiclient.go stays ≈225 lines).

### REQ-2 — T-8a mint on the form wire

`mint` (token.go:59-72) builds `url.Values` instead of the JSON map and sends
via `probeClient(ck.doc.TokenEndpoint).PostForm("", values)`:

- Always: `grant_type=client_credentials`, `client_id`, `client_secret`.
- `scope` only when `ck.scope != ""`; `resource` as repeated keys, one per
  entry (server-side multi-value branch, evidence fact 4).
- Everything downstream is unchanged: JWT decode, claims matrix, revoke leg,
  and the T-8e refresh_token rejection at token.go:96-99.
- `resource` is dropped from the form body only when empty — never sent empty.

### REQ-3 — revoke + post-revoke introspection on the form wire

`revoke` (token.go:244-266): both POSTs (revoke at :244-246, post-revoke
introspect at :259-261) switch to `PostForm` with
`token`/`client_id`/`client_secret`. Status and `{"active":false}` assertions
unchanged.

### REQ-4 — T-8d on the form wire

`runT8d` (token.go:297-303) switches to `PostForm` with
`grant_type`/`client_id`/`client_secret`/`scope=probeScope`. The byte-identical
`wantBody {"error":"invalid_scope"}\n` comparison (:316-317), the 200 =
enforcement-absent branch, and the wrong-code diagnostic are unchanged.

### REQ-5 — T-9 on the form wire (RFC 7662 §2.1)

`runT9` (token.go:353-357): body becomes
`url.Values{"token": {"sweep-probe-dummy"}}.Encode()` with
`Content-Type: application/x-www-form-urlencoded`. Bare `http.Client` with
`rejectRedirect`, `validateAdvertisedURL` preflight, the
`{"error":"invalid_client"}\n` byte-identical assertion, and the
credential-less posture (no bearer, no env inheritance) are unchanged.

### REQ-6 — New T-8b row: wrong-Content-Type rejection

New probe group `runT8b()` (new file `token_contenttype.go`, same package):

- Precondition/skip: no advertised `token_endpoint` → stderr note,
  `check INCOMPLETE` semantics exactly like T-8d/T-9.
- Two legs against `ck.doc.TokenEndpoint` (after `validateAdvertisedURL`),
  both carrying the SAME JSON credential body as mint — `json.Marshal` of
  `{"grant_type":"client_credentials","client_id":...,"client_secret":...}`
  (no scope) — because only a JSON body is accepted by today's permissive
  parser (evidence fact 1; a form body under a wrong CT 400s today too and
  would make the row vacuous):
  - leg A: `Content-Type: text/plain`;
  - leg B: no Content-Type header at all.
- Expected response per leg: status 400 and the error envelope with
  `error == "invalid_request"`; raw body must be byte-identical to
  `{"error":"invalid_request"}\n`, with exactly one permitted deviation: a
  single additional top-level string field `trace_id` (the opt-in Tracing
  middleware's enrichment — evidence facts 2-3; this mirrors the strict-mode
  AC-2 b2 caveat). Any other extra field (`error_description`, …) fails.
- Failure diagnostics: one stderr line per failing leg naming the leg's
  Content-Type and the observed status; the observed body is echoed ONLY for
  non-2xx responses through `sanitizeBody` (a 200 body is a real minted token
  — the mint bodyEcho rule at token.go:81-84 applies). No credential, token,
  or probe material ever reaches a diagnostic; 2xx bodies are never echoed.
- Group line: `content_type: OK` / `content_type: FAIL`; participates in the
  exit-code contract (any failure → exit 1).
- Security posture: bare `http.Client` (`rejectRedirect`, 30s timeout) —
  structurally bearer-less like T-9; targeted at the advertised endpoint only.

### REQ-7 — Sweep wiring and docs

- `CheckRun` (check.go:120-122) executes `ck.runT8b()` between `runT8a` and
  `runT8d`; skip/failure participate in the INCOMPLETE/FAIL verdicts.
- `goldenGreenStdout` becomes
  `discovery: OK\nmint: OK\ncontent_type: OK\ninvalid_scope: OK\nintrospect: OK\ncheck OK\n`
  (check_test.go:32).
- Update the package doc comment (check.go:11-46, add T-8b to the group list
  and the security-posture bullets), `usage()` (check.go:137-191), and the
  T-8 group table comment in token.go's header.
- Stub harness: `handleIntrospect` discrimination switches from the JSON-only
  `"client_id"` substring (check_test.go:239-244) to body parsing that works
  for both wires (e.g. `url.ParseQuery` and check the `client_id` key, with a
  JSON fallback); `handleToken`'s `sweep-probe-` discrimination is unchanged.

## 6. Budgets and architecture

- No new packages, no import-direction changes: `apiclient` remains stdlib-only
  production code (evidence: apiclient.go imports); tests keep the existing
  downward `interfaces/sso` + `infrastructure/defaultimpl` imports.
- File budgets (ceiling 500): apiclient.go 205→~225; token.go 413→~420
  (form conversions only); new token_contenttype.go ~130 (runT8b + leg helper);
  check.go +~10 lines; check_test.go +~180.
- Directory fan-out: no new subdirectory (cmd/sso-ctl/ stays at its committed
  16-subdirectory ceiling, untouched); `cmd/sso-ctl/apiclient` grows from 4 to
  5 non-test files (token_contenttype.go) — well under the 10 non-test
  files/directory ceiling; the cmd/sso-ctl root's 2 non-test files unchanged.
- Function budget: `runT8b` ≤50 lines via a shared leg helper; complexity ≤15.
- `interfaces/sso` 60-file ceiling: untouched.

## 7. Files

### Create

```text
cmd/sso-ctl/apiclient/token_contenttype.go — runT8b + wrong-CT leg helper
  (keeps token.go under 500 lines); package doc line for the T-8b group
```

### Modify

```text
cmd/sso-ctl/apiclient/apiclient.go — PostForm method (REQ-1), net/url import
cmd/sso-ctl/apiclient/token.go — mint/revoke/T-8d/T-9 form transport (REQ-2-5)
cmd/sso-ctl/apiclient/check.go — runT8b wiring, doc comment, usage text
cmd/sso-ctl/apiclient/check_test.go — golden stdout, form-transport request
  assertions, T-8b rows, stub handleIntrospect wire-agnostic discrimination,
  live-server red-today pin
cmd/sso-ctl/apiclient/apiclient_test.go — PostForm contract tests
```

### Do not modify

```text
protocols/oauth/oauthwire/bind.go — the permissive parser is the B4-4
  server-side direction's surface; the sweep must detect it, not change it
interfaces/sso/server_token.go, protocols/oauth/handle_introspect.go —
  no server-side edits
cmd/sso-ctl/apiclient/sweep.go — T-2 body-less rows are already wire-neutral
docs/openapi.yaml, docs/error-codes.md, docs/config-reference.md — no
  public-contract change (no new endpoint, Err*, or config knob)
```

## 8. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/apiclient/ -run 'TestPostForm_|TestSweep_|TestMint_|TestRevoke_|TestInvalidScope_|TestIntrospect_|TestContentType' -v
go test ./cmd/sso-ctl/... -race
make ci
```

Targeted tests to add/update:

1. `TestPostForm_FormEncoding` (apiclient_test.go): body bytes equal
   `values.Encode()`, `Content-Type: application/x-www-form-urlencoded`,
   `Accept: application/json`, bearer preserved, no `application/json` CT.
2. Stub request-record assertions: mint, revoke, post-revoke introspect, T-8d
   requests carry the form Content-Type and form bodies; T-9 carries
   `token=sweep-probe-dummy`; T-8b legs carry `text/plain` and absent CT with
   JSON bodies.
3. T-8b green (stub 400 `{"error":"invalid_request"}\n` on both legs): exit 0,
   stdout contains `content_type: OK`; trace_id variant also exit 0;
   `error_description` variant exit 1; 401 status exit 1; 200-token response
   exit 1 with no token echo in stderr.
4. T-8b skip: stub without `token_endpoint` → `check INCOMPLETE`, exit 1.
5. `TestSweep_ContentTypeRowFailsToday` (live `newLiveServer`): exit 1,
   `content_type: FAIL` in stdout, all other group lines OK — the executable
   "fails today" pin; when the strict parser lands this test flips to exit 0
   with the new `goldenGreenStdout` (dependency: the
   `enforce-form-urlencoded-credential-strict-mode` server change).
6. Existing live tests (`TestSweep_GreenPath` red at T-8b only, claims/revoke/
   invalid_scope/introspect rows) stay green on the form wire against the
   current server — evidence fact 4.

## 9. Dependencies and compatibility

- Runtime dependency: none (probes degrade to `content_type: FAIL` + exit 1 on
  an unhardened server — the intended detection behavior).
- Land-order dependency: T-8b's live-server green test flips only when the
  server-side strict parser (separate B4-4 direction) lands; the sweep-side
  change is independently shippable and red-today by design.
- Wire compatibility: no server wire behavior changes; the sweep's own probes
  switch to the RFC-mandated form wire (RFC 6749 §3.2, RFC 7009 §2.1,
  RFC 7662 §2.1); `trace_id` tolerance mirrors the strict-mode contract.
- Rollout/rollback: revert the five probe call sites + `runT8b` wiring to
  restore the previous binary's exact behavior; no persisted state.

## 10. Documentation

- [x] `docs/openapi.yaml` — not applicable (no server endpoint).
- [x] `docs/error-codes.md` — not applicable (no new `Err*`; `invalid_request`
      is the existing credential-endpoint bind-failure code).
- [x] `docs/config-reference.md` — not applicable (no config knob; the new row
      is self-documenting in `sso-ctl check --help`).
- [ ] Backlog: advance the deferred "T-8b JSON Content-Type rejection" note in
      docs/architect-analysis/auto/cmd-sso-ctl-apiclient-requirements.md:490 —
      now covered by this direction (T-8c/T-8e-as-cache-row remain deferred).
