# Requirements Spec: form-urlencoded probe transport + Content-Type enforcement row (T-8e) for sso-ctl check

- Direction: "Form-urlencoded probe path + Content-Type enforcement probe for credential endpoints" (source: `docs/architect-analysis/auto/analyses/cmd-sso-ctl-apiclient-12aa9498.json`, entry 1)
- Module: `cmd/sso-ctl/apiclient` (composition layer)
- Status: requirements (evidence-verified against the working tree; baseline red state enumerated in §2)

## 1. Evidence verification

Every citation in the direction was re-checked against the working tree. All
symbols and behaviors are confirmed; line numbers were re-measured (the
analysis was written against an earlier revision, and the sweep files are
uncommitted worktree state — see §2). Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `apiclient.go:Do` — "always json.Marshal + Content-Type application/json, no form path" | `Do` spans apiclient.go:98-123: `json.Marshal(body)` at :103, `Content-Type: application/json` set at :119 whenever `body != nil`, `Accept: application/json` at :122. No `net/url`, no `url.Values` anywhere in the package's production files | Confirmed (substance exact: every non-nil body is JSON-encoded, every body-bearing request carries `application/json`) |
| `token.go:runT8a/mint/runT8d/revoke/runT9` — "all JSON bodies" | `runT8a` :21, `mint` :59-72 (JSON `map[string]any` body :60-70, `client.Post("", body)` :72), `revoke` :236-284 (revoke POST :244-246, post-revoke introspect :259-261 — both JSON maps), `runT8d` :286-336 (JSON credential POST :297-303, byte-identical `wantBody = {"error":"invalid_scope"}\n` :310/:316), `runT9` :338-362 (JSON body `{"token":"sweep-probe-dummy"}` :353, explicit `Content-Type: application/json` :357, byte-identical `wantBody = {"error":"invalid_client"}\n` :366-367) | Confirmed (all five credential sends are JSON) |
| `protocols/oauth/oauthwire/bind.go:28 BindParams` — "defaults ANY unknown/missing Content-Type to JSON parsing, so no 415/400 exists to probe today" | `BindParams` at :28; the `switch ct` at :37-42 has exactly two branches — form (`:38-42`) and `default:` (`:43-46`) which reads "Default to JSON for application/json, missing CT, or anything unexpected" and calls `decodeSingleJSON(r.Body, v)` | Confirmed exactly. `application/json`, `text/plain`, garbage, or an absent header all decode the body as JSON; `handleToken` maps only *decode failures* to `400 invalid_request` (interfaces/sso/server_token.go:31-34). A JSON credential body therefore mints (200) under every Content-Type today |
| `check_test.go TestSweep_GreenPath` golden output | `goldenGreenStdout = "discovery: OK\nmint: OK\ninvalid_scope: OK\nintrospect: OK\ncheck OK\n"` at check_test.go:32; `TestSweep_GreenPath` at :446-457 asserts exit 0 + the golden + silent stderr | Confirmed (the golden is the byte-deterministic stdout contract any new group line must extend) |

Load-bearing facts verified during this pass (each pins a requirement):

1. **The T-8(e) probe body must be JSON, not form-encoded.** Today's permissive
   parser accepts any Content-Type for a JSON body (200 mint), so a JSON body
   under `application/json` or `text/plain` Content-Type is the only shape that
   is green today (200 = enforcement absent → row FAILs = detection works) and
   red after form-only enforcement lands (rejected non-200 → row passes). A
   *form* body under a wrong Content-Type would JSON-decode-fail and 400 even
   today (bind.go:43-46 → `decodeSingleJSON` error → `400 invalid_request`),
   making the row vacuous — the same trap the sibling campaign documented for
   its T-8b (cmd-sso-ctl-b4-4-check-probes-form-requirements.md §1 finding 1).
2. **The server-side form-only contract this row pins.** The separate
   strict-mode campaign
   (`docs/architect-analysis/auto/runs/enforce-form-urlencoded-credential-strict-mode-0a8df02f/artifacts/requirements-0a8df02f/requirements.md`
   R3/R5) hardens `/token`, `/token/introspect`, `/token/revoke`, `/par` to
   reject any Content-Type other than `application/x-www-form-urlencoded` —
   including `application/json`, `text/plain`, and an absent header — with
   `400 {"error":"invalid_request"}` (byte-identical to today's bind-failure
   body, no-store headers already stamped). The direction's acceptance
   deliberately asserts the *class* ("rejected with a non-200 error body,
   never a 200 token response") rather than the exact code, so the row stays
   green under that contract without pinning its internals.
3. **Form decoding of every probe field is already supported server-side.**
   `formIntoStruct` binds `grant_type`/`client_id`/`client_secret`/`scope`
   (string) and `resource` (`[]string`, multi-value or space-split,
   oauthwire/bind.go:119-157; `TokenRequest` with `Resource []string` at
   oauthwire/token_request.go:11-29); secret *presence*
   survives the form wire via `r.PostForm.Has("client_secret")`
   (server_token_clientauth.go:99); `/token/introspect` binds the same
   request through `BindParams` (`introspectRequest` struct at
   handle_introspect.go:72-78, bind at :120). So mint/T-8d/T-9 remain green
   against the *current* server after the transport switch; only T-8(e)
   turns red today — the intended detection behavior.
4. **Exactly five JSON credential sends switch to the form wire.** mint
   token.go:72; revoke :244; post-revoke introspect :259; T-8d :297;
   T-9 :353-357. T-2's endpoint rows POST with `nil` bodies
   (sweep.go:158-162) — no body, no Content-Type — and are wire-neutral under
   both parsers. The admin-API JSON surface (`apiclient.Do` and its
   `Get`/`Post`/`Delete`/`Patch` wrappers) is untouched.
5. **The test harness is wire-coupled.** The stub's `handleIntrospect`
   (check_test.go:249-258) discriminates T-9 vs post-revoke requests with
   `bytes.Contains(body, []byte(`"client_id"`))` — a JSON-only shape; form
   bodies carry `client_id=` without quotes and would be misrouted. The
   stub's `handleToken` (check_test.go:229-248) discriminates T-8d by the raw
   `sweep-probe-` substring (alphanumeric, survives `url.Values.Encode`
   unencoded) and is unaffected. Recorded requests (`r.Clone` in
   `stubCheck.dispatch`) share the body reader, so body assertions must
   capture bytes inside handlers, not from the recorded clone.
6. **The prior sweep spec deferred exactly this work.**
   docs/architect-analysis/auto/cmd-sso-ctl-apiclient-requirements.md:490:
   "B4 items T-8b/T-8c/T-8e (JSON Content-Type rejection, ...) are other
   directions' acceptance, not this one." This direction is that deferred
   JSON-Content-Type-rejection row (here labeled T-8(e)) plus the form
   transport for every credential probe. T-8c (constant-time) stays out of
   scope.
7. **Sibling-campaign overlap.** The `cmd/sso-ctl`-module campaign
   (`docs/architect-analysis/cmd-sso-ctl-b4-4-check-probes-form-requirements.md`)
   specs the same five-call-site form transport but a *different* rejection
   row (T-8b: `text/plain` + absent header → byte-identical `400
   invalid_request`) and keeps T-8e as the refresh_token rejection. This
   direction's T-8(e) is the wrong-Content-Type row itself ("JSON or
   text/plain Content-Type POST ... rejected with a non-200 error body"),
   with no absent-header leg and no byte-identical requirement; the
   refresh_token rejection is already part of T-8a's mint matrix
   (token.go:96-99). Both campaigns flip the same five call sites; they land
   in the same shape whichever ships first.

## 2. Baseline state: the module's test suite is red today (pre-existing, must be stabilized first)

`go test ./cmd/sso-ctl/apiclient/` fails 11 tests on the working tree. This
is pre-existing worktree drift — the sweep files (`check.go`, `sweep.go`,
`token.go`, `check_test.go`, `apiclient_test.go`) are untracked WIP from the
earlier check-sweep campaign, `apiclient.go` carries an uncommitted
`WithNoRedirect` addition, and `interfaces/sso/` has uncommitted drift that
changed token issuance. The sibling campaign's adversarial review
(`align-sso-ctl-check-probes-with-b4-4-form-urlenc-30afe1ff`, baseline
stabilization review) enumerated six root causes; all six were independently
reproduced in this pass:

| # | Root cause | Working-tree evidence | Fix surface |
|---|---|---|---|
| 1 | Live fixture `iss` mismatch | `newLiveServer` (check_test.go:71-92) passes `sso.WithIssuer(addr)` but the token issuer is `defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))` with no `defaultimpl.WithEd25519Issuer(addr)` — the minted `iss` is `core.DefaultIssuer` ("snaplink-sso", interfaces/sso/aliases.go:179) ≠ discovery issuer. Production wiring does pass it (cmd/sso-server/serverbuildsign/build_signing_issuers.go:43) | 6 tests + 1 subtest red: `claims: iss "snaplink-sso" != discovery issuer "http://127.0.0.1:PORT"` | check_test.go fixture only |
| 2 | `TestCheck_AddrValidation` no-echo trip | Cases `"8443"` and `"http://"` are substrings of the usage banner's default `"http://127.0.0.1:8443"`; the test asserts the addr is never echoed | `TestCheck_AddrValidation` red | check_test.go only |
| 3 | `checkTokenSuffix` too loose | sweep.go:192 `strings.HasSuffix(u.Path, "/token")` accepts `/oauth2/token`, so `TestSweep_TokenEndpointSuffix`'s suffix diagnostic is unreachable (the 404 row fires first) | `TestSweep_TokenEndpointSuffix` red | sweep.go A4 assertion (the test already pins the contract) |
| 4 | `advertiseDoc` unconditional concatenation | check_test.go:176-188 does `s.srv.URL + suffix` for every field; `TestSweep_AdvertisedURLRejection` passes *absolute* URLs → `http://127.0.0.1:PORTfile:///x` garbage; the "relative" subtest exits 0 instead of 1 | 4 subtests red | check_test.go harness only |
| 5 | `TestMint_ResponseFail` never sends 400 | Only the `redirect-302` case sets a non-200 status; the `status-400` row writes its error body at 200 → `mint: response has no access_token` instead of `mint: status 400` | `TestMint_ResponseFail/status-400` red | check_test.go only |
| 6 | `runT9` diagnostic quoting | token.go:368 formats `expected 401 %q` (quoted); `TestIntrospect_Non401Fails/wrong-bytes` expects the unquoted body | 1 subtest red | token.go diagnostic only (no wire impact) |

REQ-0 stabilizes these six. Without it, the acceptance's "unit test ... a
server enforcing form-only still yields a green sweep" is unverifiable: the
live-server green path (`TestSweep_GreenPath`, `TestMint_*`,
`TestRevoke_RoundTrip`) is in the red cohort today, and no new-row test can
land on a red baseline. The fixes are bounded to this module's test harness
plus one A4 assertion in sweep.go — no server-side edits, no contract change.

## 3. Goal and user outcome

B4 item 4 ("Content-Type form-urlencoded enforced") is not implemented
server-side: `oauthwire.BindParams` defaults any unknown/missing Content-Type
to JSON parsing, so a deployment has no way to tell whether enforcement is
present. `sso-ctl check` is the only deploy-tree surface that can pin this
contract, but today every credential probe speaks JSON and the sweep cannot
even express the assertion. If enforcement lands, every probe group breaks; if
it never lands, item 4 has zero deploy-tree coverage.

Completion markers for the operator:

- Every credential probe (mint, revoke, post-revoke introspect, T-8d, T-9)
  now speaks `application/x-www-form-urlencoded` — the RFC-mandated wire
  (RFC 6749 §3.2, RFC 7009 §2.1, RFC 7662 §2.1) — with all existing
  byte-identical assertions unchanged.
- A new `content_type: OK` group line appears among the sweep lines, asserting
  that a JSON- or text/plain-Content-Type POST to the advertised
  token_endpoint is rejected with a non-200 error body (never a 200 token
  response).
- Against today's permissive server the new row fails (`content_type: FAIL`,
  exit 1) — the missing hardening becomes detectable. Against a form-only
  enforcing server the whole sweep is green (exit 0), pinned by a unit test.

## 4. Product boundary

- Surface: `sso-ctl check` probe groups (`cmd/sso-ctl/apiclient`), the
  deploy-tree live sweep.
- Default: always-on probe rows; no flag gates the transport. T-8(e) follows
  the T-8d precedent of a documented validity precondition rather than a flag.
- Explicit non-goals:
  - No server-side changes: no `interfaces/sso`, `protocols/oauth`, or
    `oauthwire` edits, no new endpoints, no OpenAPI/config/error-code changes.
    The strict parser itself is the separate
    `enforce-form-urlencoded-credential-strict-mode` direction; this spec
    pins the sweep against its published contract (§1 finding 2).
  - No absent-Content-Type leg, no byte-identical-`invalid_request`
    requirement for the new row (this direction's acceptance asserts the
    class, not the code — §5); the sibling campaign's T-8b remains its own
    direction's acceptance.
  - T-8c (constant-time comparisons) stays another direction's acceptance.
  - No cache-header (no-store) assertions on the new row.
  - No typed `TokenRequest`/`Introspect` helpers, no JWT signature
    verification, no change to `apiclient.Do`/`Post`/`Get`/`Delete`/`Patch`
    (the admin-API JSON contract) beyond the additive `PostForm` (REQ-1).
  - REQ-0's baseline stabilization is limited to the six enumerated causes;
    no unrelated cleanup of the untracked sweep files.

## 5. Acceptance criteria (supplied acceptance, preserved verbatim)

> T-8(a)/T-8(d)/T-9: probe mint/revoke/introspect with
> application/x-www-form-urlencoded bodies and keep the byte-identical 400
> invalid_scope / 401 invalid_client assertions; add a T-8(e) row asserting a
> JSON or text/plain Content-Type POST to the advertised token_endpoint is
> rejected with a non-200 error body (never a 200 token response); unit test
> in cmd/sso-ctl/apiclient that a server enforcing form-only still yields a
> green sweep

Testable form of each check (map to REQ-1..REQ-8, verification plan §9):

| Check | Testable criteria |
|---|---|
| T-8(a) form mint/revoke | REQ-2/REQ-3: the mint request carries `Content-Type: application/x-www-form-urlencoded` and the encoded body `grant_type=client_credentials&client_id=...&client_secret=...` (`scope`/`resource` only when declared; `resource` repeated per entry); revoke and post-revoke introspect requests carry `token`/`client_id`/`client_secret` as form fields; the refresh_token rejection (token.go:96-99) and the full claims/revoke/introspect matrix behave unchanged — `TestMint_ClaimsMatrix`, `TestRevoke_RoundTrip`, `TestStdoutDeterministic` green on the live server (after REQ-0.1). |
| T-8(d) form + byte-identical | REQ-4: the T-8d request carries the form Content-Type with `scope=<randomized probe scope>`; `wantBody {"error":"invalid_scope"}\n` comparison (token.go:310,316), the 200=enforcement-absent branch, and the wrong-code diagnostic are unchanged — `TestInvalidScope_ByteExact` and rows 19-21 stay green. |
| T-9 form + byte-identical | REQ-5: body `token=sweep-probe-dummy` with `Content-Type: application/x-www-form-urlencoded` (RFC 7662 §2.1); bare client, no `Authorization` header even with `SSO_ADMIN_TOKEN` exported; `wantBody {"error":"invalid_client"}\n` (token.go:366-367) unchanged — `TestIntrospect_NoCreds401`, `TestIntrospect_NoAuthHeaderLeak`, `TestIntrospect_Non401Fails` stay green (after REQ-0.6). |
| T-8(e) wrong-CT row | REQ-6: two legs against the advertised token_endpoint — leg A `Content-Type: application/json`, leg B `Content-Type: text/plain`, both with the JSON credential body. Each leg passes only on a 4xx response whose body is a JSON error envelope (non-empty `error` string); a 200 token response, any 3xx, 5xx, or a non-error body fails. Group line `content_type: OK`/`content_type: FAIL`; participates in the exit-code contract. |
| Green sweep under enforcement | REQ-8: a stub that accepts only form bodies at `/token` (rejects the JSON/text-plain legs with `400 {"error":"invalid_request"}\n`) yields exit 0 with the extended golden stdout; the live permissive server yields exit 1 with `content_type: FAIL` and every other group line OK (the red-today pin, `TestSweep_ContentTypeRowFailsToday`). |

## 6. Requirements

### REQ-0 — Baseline stabilization (precondition, bounded)

Fix the six root causes of §2 before the transport work lands:

- REQ-0.1 — `newLiveServer` (check_test.go:71-92) adds
  `defaultimpl.WithEd25519Issuer(addr)` to the token issuer so the minted
  `iss` equals the discovery issuer (mirrors production wiring,
  build_signing_issuers.go:43).
- REQ-0.2 — `TestCheck_AddrValidation` uses inputs that are not substrings of
  the usage banner and keeps the never-echo property for genuinely
  credential-bearing inputs (`user:pass@`).
- REQ-0.3 — sweep.go `checkTokenSuffix` (:184-199) accepts a path only when
  it is exactly `/token` or exactly `<sweep-base path>/token` (the A4
  base-path-prefix tolerance); `/oauth2/token` fails with the suffix
  diagnostic `TestSweep_TokenEndpointSuffix` already pins.
- REQ-0.4 — `advertiseDoc` (check_test.go:176-188) prefixes `s.srv.URL` only
  for relative values; absolute http(s) URLs are advertised as-is.
- REQ-0.5 — `TestMint_ResponseFail` gains a per-case status so the
  `status-400` row actually writes 400.
- REQ-0.6 — the `runT9` failure diagnostic (token.go:368) prints the expected
  body unquoted to match `TestIntrospect_Non401Fails`.

Exit criterion: `go test ./cmd/sso-ctl/apiclient/` green with the *current*
golden (`§1` citation 4) before any transport change.

### REQ-1 — Form transport method on apiclient (additive, admin contract untouched)

`apiclient.Client` gains exactly one method:

```go
// PostForm sends a POST with an application/x-www-form-urlencoded body.
func (c *Client) PostForm(path string, values url.Values) (*http.Response, error)
```

- Body bytes = `values.Encode()`; header `Content-Type:
  application/x-www-form-urlencoded`.
- Keeps `Do`'s semantics: `Accept: application/json`, bearer header when
  `c.token != ""`, the caller's `http.Client` (so `probeClient`'s no-redirect
  pin applies), caller closes the body.
- `Do`/`Post`/`Get`/`Delete`/`Patch` are byte-for-byte unchanged — the admin
  API JSON surface never changes.
- New import: `net/url` in apiclient.go (apiclient.go stays ≈225 lines).

### REQ-2 — T-8(a) mint on the form wire

`mint` (token.go:59-72) builds `url.Values` instead of the JSON map and sends
via `probeClient(ck.doc.TokenEndpoint).PostForm("", values)`:

- Always: `grant_type=client_credentials`, `client_id`, `client_secret`.
- `scope` only when `ck.scope != ""`; `resource` as repeated keys, one per
  entry (server-side multi-value branch, §1 finding 3).
- Everything downstream is unchanged: JWT decode, claims matrix, revoke leg,
  and the refresh_token rejection at token.go:96-99 (a form-encoded cc mint
  must still never return a refresh_token).

### REQ-3 — revoke + post-revoke introspection on the form wire

`revoke` (token.go:236-284): both POSTs (revoke :244-246, post-revoke
introspect :259-261) switch to `PostForm` with `token`/`client_id`/
`client_secret`. Status-200 and `{"active":false}` assertions unchanged.

### REQ-4 — T-8(d) on the form wire

`runT8d` (token.go:297-303) switches to `PostForm` with
`grant_type`/`client_id`/`client_secret`/`scope=probeScope`. The byte-identical
`wantBody {"error":"invalid_scope"}\n` comparison (:310,:316), the 200 =
enforcement-absent branch, and the wrong-code diagnostic are unchanged.

### REQ-5 — T-9 on the form wire (RFC 7662 §2.1)

`runT9` (token.go:353-357): body becomes
`url.Values{"token": {"sweep-probe-dummy"}}.Encode()` with
`Content-Type: application/x-www-form-urlencoded`. The bare `http.Client`
with `rejectRedirect` and the 30s timeout, the `validateAdvertisedURL`
preflight, the `{"error":"invalid_client"}\n` byte-identical assertion, and
the credential-less posture (no bearer, no env inheritance) are unchanged.
REQ-0.6's diagnostic fix applies on the way.

### REQ-6 — New T-8(e) row: JSON/text-plain Content-Type rejection

New probe group `runT8e()` (new file `token_contenttype.go`, same package):

- Precondition/skip: no advertised `token_endpoint` → stderr note
  `check: T-8e skipped: advertised token_endpoint absent`, no stdout line,
  `check INCOMPLETE` semantics exactly like T-8d/T-9 (defensive: `runT8a`
  already forces INCOMPLETE in that case).
- Two legs against `ck.doc.TokenEndpoint` (after `validateAdvertisedURL`),
  both carrying the SAME JSON credential body as mint —
  `json.Marshal({"grant_type":"client_credentials","client_id":...,
  "client_secret":...})` (no scope). The JSON body is load-bearing: only a
  JSON body is accepted by today's permissive parser (§1 finding 1); a form
  body under a wrong Content-Type would 400 today too and make the row
  vacuous.
  - leg A: `Content-Type: application/json`;
  - leg B: `Content-Type: text/plain`.
- Pass condition per leg: status in 400-499 AND the body decodes as a JSON
  object with a non-empty string `error` field. The exact code is NOT pinned
  (the acceptance asserts "non-200 error body"; the strict-mode contract
  pins `400 invalid_request` when it lands — §1 finding 2); a `trace_id`
  enrichment is tolerated by construction.
- Fail conditions: 200 (token response — enforcement absent; the body may be
  a real minted token and is NEVER echoed, mint bodyEcho rule at
  token.go:81-84 applies); any 3xx (content-row semantics — never followed);
  5xx; non-JSON body; empty or missing `error`.
- Failure diagnostics: one stderr line per failing leg naming the leg's
  Content-Type and the observed status; the observed body is echoed ONLY for
  non-2xx responses through `sanitizeBody`. No credential, token, or probe
  material ever reaches a diagnostic.
- Group line: `content_type: OK` / `content_type: FAIL`; participates in the
  exit-code contract (any failure → exit 1).
- Security posture: bare `http.Client` (`rejectRedirect`, 30s timeout),
  structurally bearer-less like T-9 — a non-Basic Authorization header makes
  `/token` reject the request outright and would corrupt the leg. The
  client_credentials body is the only credential carrier.
- Validity precondition (usage text, T-8d precedent): the row is meaningful
  only when the client's credentials are valid; with invalid credentials
  today's server rejects with `401 invalid_client` and the row passes
  without testing Content-Type enforcement (the sweep is already red via
  T-8a/T-8d in that case, so nothing is masked).

### REQ-7 — Sweep wiring, golden output, docs

- `CheckRun` (check.go:120-122) executes `ck.runT8e()` between `runT8a` and
  `runT8d`; skip/failure participate in the INCOMPLETE/FAIL verdicts.
- `goldenGreenStdout` becomes
  `discovery: OK\nmint: OK\ncontent_type: OK\ninvalid_scope: OK\nintrospect: OK\ncheck OK\n`
  (check_test.go:32).
- Update the package doc comment (check.go:11-46: add the T-8(e) group and a
  security-posture bullet), `usage()` (check.go:137-191: new group + validity
  precondition), and the group table comment in token.go's header.

### REQ-8 — Harness and tests

- `handleIntrospect` (check_test.go:249-258) discrimination switches from the
  JSON-only `"client_id"` substring to body parsing that works for both wires
  (e.g. `url.ParseQuery` and check the `client_id` key, JSON fallback);
  `handleToken`'s `sweep-probe-` discrimination is unchanged.
- Request-shape assertions capture body bytes inside handlers (recorded
  clones share the body reader — §1 finding 5) and assert the form
  Content-Type plus decoded form keys for mint/revoke/post-revoke/T-8d/T-9.
- New tests:
  1. `TestPostForm_FormEncoding` (apiclient_test.go): body bytes equal
     `values.Encode()`, form Content-Type, `Accept: application/json`,
     bearer preserved, no `application/json` Content-Type.
  2. `TestSweep_FormOnlyGreen` — the acceptance's "server enforcing form-only
     still yields a green sweep": a stub whose `/token`, `/token/revoke`, and
     `/token/introspect` handlers accept ONLY the form Content-Type (any
     other CT → `400 {"error":"invalid_request"}\n`) returns exit 0 with the
     extended golden stdout and silent stderr.
  3. `TestSweep_ContentTypeRowFailsToday` — live `newLiveServer` (after
     REQ-0.1): exit 1, `content_type: FAIL` in stdout, every other group line
     OK — the executable red-today pin; flips to green when the strict-mode
     server change lands (dependency, §10).
  4. T-8(e) row matrix: 400 `invalid_request` on both legs → pass;
     `trace_id`-enriched 400 → pass; 415 + JSON error envelope → pass;
     200 token response → fail with no token echoed; 302 → fail; 500 → fail;
     non-JSON body → fail; one leg green + one red → fail with both
     diagnostics.
  5. T-8(e) skip: stub without `token_endpoint` → `check INCOMPLETE`, exit 1.
  6. Byte-identical regression: `TestInvalidScope_ByteExact` /
     `TestIntrospect_NoCreds401` / rows 19-22 stay green on the form wire.

## 7. Budgets and architecture

- No new packages, no import-direction changes: `apiclient` remains
  stdlib-only production code; tests keep the existing downward
  `interfaces/sso` + `infrastructure/defaultimpl` imports.
- File budgets (ceiling 500): apiclient.go 205→~225; token.go 413→~445 (form
  conversions + REQ-0.6 diagnostic); new token_contenttype.go ~140 (runT8e +
  leg helper — function ≤50 lines via the helper, complexity ≤15, `if`
  nesting ≤3 via guards); check.go 277→~292; sweep.go 284→~286 (REQ-0.3);
  check_test.go 1345→~1560 (tests exempt from the file ceiling per the
  interfaces/sso precedent but stay proportionate).
- Directory fan-out: no new subdirectory; `cmd/sso-ctl/apiclient` grows from
  4 to 5 non-test files — under the 10 non-test files/directory ceiling;
  `cmd/sso-ctl` root fan-out (16) untouched.
- `interfaces/sso` 60-file ceiling: untouched.

## 8. Files

### Create

```text
cmd/sso-ctl/apiclient/token_contenttype.go — runT8e + wrong-CT leg helper
  (keeps token.go under 500 lines); package doc line for the T-8(e) group
docs/architect-analysis/cmd-sso-ctl-apiclient-b4-4-form-probes-requirements.md
  — this specification (mirror of this artifact)
```

### Modify

```text
cmd/sso-ctl/apiclient/apiclient.go — PostForm method (REQ-1), net/url import
cmd/sso-ctl/apiclient/token.go — mint/revoke/T-8d/T-9 form transport
  (REQ-2..REQ-5), runT9 diagnostic unquote (REQ-0.6)
cmd/sso-ctl/apiclient/check.go — runT8e wiring, doc comment, usage text
  (REQ-7)
cmd/sso-ctl/apiclient/sweep.go — checkTokenSuffix exact-suffix rule (REQ-0.3)
cmd/sso-ctl/apiclient/check_test.go — golden constant, REQ-0 fixture fixes
  (newLiveServer issuer, advertiseDoc, AddrValidation, Mint_ResponseFail),
  handleIntrospect wire-agnostic discrimination, form-transport request
  assertions, T-8(e) rows, TestSweep_FormOnlyGreen,
  TestSweep_ContentTypeRowFailsToday (REQ-0/REQ-8)
cmd/sso-ctl/apiclient/apiclient_test.go — PostForm contract tests (REQ-8.1)
```

### Do not modify

```text
protocols/oauth/oauthwire/bind.go — the permissive parser is the server-side
  strict-mode direction's surface; the sweep must detect it, not change it
interfaces/sso/*, protocols/oauth/handle_introspect.go — no server-side edits
cmd/sso-ctl/apiclient/apiclient.go Do/Post/Get/Delete/Patch semantics — the
  admin-API JSON contract
docs/openapi.yaml, docs/error-codes.md, docs/config-reference.md — no
  public-contract change (no new endpoint, Err*, or config knob)
```

## 9. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/apiclient/ -run 'TestPostForm_|TestSweep_|TestMint_|TestRevoke_|TestInvalidScope_|TestIntrospect_|TestContentType' -v
go test ./cmd/sso-ctl/... -race
make ci
```

Targeted tests to add/update (mapped in §5/REQ-8): `TestPostForm_FormEncoding`;
stub request-record assertions for all five form sends; T-8(e) row matrix
(REQ-8.4); `TestSweep_FormOnlyGreen` (REQ-8.2); `TestSweep_ContentTypeRowFailsToday`
(REQ-8.3); T-8(e) skip (REQ-8.5); byte-identical regressions (REQ-8.6). REQ-0
must be verified first: the full module suite green with the CURRENT golden
before the transport change (REQ-0 exit criterion).

## 10. Dependencies and compatibility

- Runtime dependency: none. Probes degrade to `content_type: FAIL` + exit 1
  on an unhardened server — the intended detection behavior.
- Land-order dependency: the sweep-side change is independently shippable and
  red-today by design; `TestSweep_ContentTypeRowFailsToday` flips to green
  only when the server-side strict-mode direction lands (separate campaign).
  The sibling `cmd/sso-ctl`-module campaign specs the same five call sites;
  whichever ships first, the second lands on the same single-point flips.
- Wire compatibility: no server wire behavior changes; the sweep's own probes
  switch to the RFC-mandated form wire (RFC 6749 §3.2, RFC 7009 §2.1,
  RFC 7662 §2.1); all byte-identical assertions are preserved. The new row
  asserts the class of the rejection, not a code, so it tolerates the
  strict-mode contract's `400 invalid_request` without pinning it.
- Rollout/rollback: revert the five probe call sites + `runT8e` wiring to
  restore the previous binary's exact behavior; no persisted state.

## 11. Documentation

- [x] `docs/openapi.yaml` — not applicable (no server endpoint).
- [x] `docs/error-codes.md` — not applicable (no new `Err*`; the row asserts a
      rejection class, and `invalid_request` is the existing bind-failure code).
- [x] `docs/config-reference.md` — not applicable (no config knob; the new row
      is self-documenting in `sso-ctl check --help`).
- [ ] Backlog: advance the deferred "T-8b/T-8c/T-8e JSON Content-Type
      rejection" note in
      docs/architect-analysis/auto/cmd-sso-ctl-apiclient-requirements.md:490 —
      the T-8(e) half is now covered by this direction (T-8c remains
      deferred).
