# Design: sso-ctl check probes aligned with B4-4 form-urlencoded hardening

Companion to `docs/architect-analysis/cmd-sso-ctl-b4-4-check-probes-form-requirements.md`.
This document treats that spec (and the direction it cites) as untrusted
evidence, records what was independently verified against HEAD, and turns the
requirements into a concrete, ordered design with API changes, compatibility
constraints, failure modes, migration steps, and testable acceptance mapping.

## 1. Evidence verification verdict

Every citation in the requirements spec was re-checked against the working
tree. The spec's factual citations are accurate; the line-number drifts it
discloses are confirmed and re-measured below. No material defects found in
the spec's semantics; one pre-existing coupling (D1) is load-bearing for the
migration and one naming nuance (D2) is corrected for the test plan.

| # | Claim | Verdict |
|---|---|---|
| E1 | `apiclient.go` `Do` JSON-encodes every non-nil body (`json.Marshal` :103, `Content-Type: application/json` :119, `Accept: application/json` :122); no form transport exists | Confirmed (apiclient.go:98-123; method set is exactly `Do`/`Get`/`Post`/`Delete`/`Patch`; apiclient.go is 205 lines, 4 non-test files in package) |
| E2 | `token.go` mint at :59-72 — JSON map (`grant_type`/`client_id`/`client_secret`, optional `scope`, `resource` as `[]string`) via `client.Post("", body)` | Confirmed exactly |
| E3 | `token.go` revoke at :244-246 + post-revoke introspect at :259-261 — two JSON POSTs; `{"active":false}` assertion | Confirmed (revoke :221-268) |
| E4 | `token.go` T-8d at :297-303 — JSON credential+scope POST; byte-identical `wantBody = {"error":"invalid_scope"}\n` at :316-317 | Confirmed (runT8d :286-336) |
| E5 | `token.go` T-9 at :353-357 — raw JSON body + `Content-Type: application/json` on a bare `http.Client` | Confirmed (runT9 :338-362; bare client :350-351) |
| E6 | T-8e refresh_token rejection at token.go:96-99; test row at check_test.go:961 | Confirmed (row: `{"refresh-token", ... "mint: unexpected refresh_token in cc response"}`) |
| E7 | `oauthwire/bind.go:28-46` — CT switch; only exact `application/x-www-form-urlencoded` takes the form branch; `default:` → `decodeSingleJSON` | Confirmed exactly (:37-42 form, :43-46 default) |
| E8 | `check.go:25-32` security-posture comment; `probeClient` :269-277 token-less, no-redirect, env-fallback-free | Confirmed (comment :25-32; probeClient builds a bare `Client` struct — `New`'s `SSO_ADMIN_TOKEN`/`SSO_ADMIN_ADDR` fallbacks cannot apply) |
| E9 | `handleToken` maps every `bindOAuthParams` failure to `400 invalid_request` | Confirmed (interfaces/sso/server_token.go:31-34) |
| E10 | `400 invalid_request` body is byte-identical `{"error":"invalid_request"}\n` absent tracing: `errorBody` → `core.ErrorBodyWithTrace` omits `trace_id` when the context has none (handlers.go:399-402; shared/core/error_body.go:31-37) | Confirmed |
| E11 | Tracing is opt-in: `WithTracingMiddleware` sets `requestIDMW` (options_security.go:487-497), field at sso_wiring.go:53, mounted at server_routes.go:112 | Confirmed |
| E12 | `invalid_scope`/`invalid_client` paths never carry `trace_id` (plain `core.ErrorBody`): scoperegistry/reject.go:37; handle_introspect.go:216,227,233 | Confirmed — T-8b is the only probe whose assertion path is trace-capable |
| E13 | Strict-mode server contract pins wrong/absent CT → `400 {"error":"invalid_request"}`, both variants, byte-identical to today's bind failure (run `enforce-form-urlencoded-credential-strict-mode-0a8df02f`, R3/R5/AC-1) | Confirmed (requirements-0a8df02f/requirements.md:85-89,108,149-150) |
| E14 | Stub `handleIntrospect` discriminates T-9 vs post-revoke by the JSON-only `"client_id"` substring (check_test.go:251); `handleToken` discriminates T-8d by raw `sweep-probe-` (:229-231) | Confirmed — the `"client_id"` check is wire-coupled and must be reworked |
| E15 | `goldenGreenStdout` at check_test.go:32; `TestSweep_GreenPath`/`TestStdoutDeterministic` compare stdout against it | Confirmed (:446-481) |
| E16 | `sweep.go` T-2 rows POST `nil` bodies (`client.Do(row.method, path, nil)`, :158-162) — wire-neutral | Confirmed |
| E17 | Deferred note at `auto/cmd-sso-ctl-apiclient-requirements.md:490`: "T-8b/T-8c/T-8e (JSON Content-Type rejection …) are other directions' acceptance" | Confirmed |
| E18 | Budgets: `cmd/sso-ctl/` at exactly 16 immediate subdirs (Go gate cap 16); apiclient has 4 non-test files; token.go 413 lines | Confirmed |
| E19 | `TestSweep_ContentTypeRowFailsToday` does not exist yet | Confirmed — it is a NEW test this design adds (the spec's finding-3 phrasing is forward-looking; §8 of the spec says the same) |

### D1 — Deployment coupling (pre-existing, load-bearing)

The five JSON credential sends are the *only* thing keeping the current sweep
green against today's permissive server; the sweep-side transport switch makes
the sweep correct on the form wire, and the new T-8b row makes an unhardened
server detectable. But the reverse direction is asymmetric: an **old** sso-ctl
binary (JSON bodies) against a **hardened** server fails loudly at `mint: FAIL`
(JSON under strict CT → `400 invalid_request`). That is acceptable for a
deploy-tree verification tool — a stale toolbelt failing against a hardened
server is the correct failure mode — but it must be an explicit rollout
constraint: ship the server hardening and the updated `sso-ctl` together
(§5, M3).

### D2 — Naming nuance in the test plan

The spec's verification-plan item 5 calls the live-server test
`TestSweep_ContentTypeRowFailsToday`; the suite convention is a `TestSweep_`
prefix for sweep rows and `TestContentType_` is unused. Keep the spec's name
verbatim so the flips-green contract is greppable, but note it is red-today
**by design**, not a failing gate: it must be committed while red, with a
`t.Skip`-free explicit assertion of the red state (exit 1 + `content_type: FAIL`
+ every other row OK), and it flips to green only when the strict-mode
server direction lands.

## 2. API changes

### 2.1 `apiclient.Client.PostForm` (additive, the only production API change)

New method on the existing `Client` (apiclient.go, +~20 lines, new import
`net/url`):

```go
// PostForm sends a POST with an application/x-www-form-urlencoded body.
// The caller must close resp.Body. Bearer/Accept semantics match Do.
func (c *Client) PostForm(path string, values url.Values) (*http.Response, error)
```

- Body bytes = `values.Encode()` (Go's sorted-key, URL-escaped form encoding).
- Headers: `Content-Type: application/x-www-form-urlencoded` (exact, no
  charset parameter — the server strips parameters anyway, bind.go:31-34, and
  the canonical header is what the strict parser compares), plus the existing
  `Accept: application/json` and `Authorization: Bearer <token>` when
  `c.token != ""` — mirroring `Do` (apiclient.go:114-122).
- Uses `c.http` unchanged, so `probeClient`'s `CheckRedirect: rejectRedirect`
  and 30s timeout apply to every credential probe that uses it.
- `Do`/`Post`/`Get`/`Delete`/`Patch` are byte-for-byte unchanged. The admin
  API JSON surface (GKE-gateway callers) never changes.

### 2.2 Five probe call sites switch to the form wire (token.go)

| Site | Today (JSON map via `Post`) | After (via `PostForm`) |
|---|---|---|
| `mint` :72 | `grant_type`/`client_id`/`client_secret`/`scope?`/`resource?` map | `url.Values`: always `grant_type`, `client_id`, `client_secret`; `scope` only when `ck.scope != ""`; `resource` as repeated keys, one per entry, omitted when empty (never sent empty). Caller: `probeClient(ck.doc.TokenEndpoint)` |
| `revoke` :244-246 | `token`/`client_id`/`client_secret` map | same three keys as `url.Values` |
| post-revoke introspect :259-261 | same map | same three keys as `url.Values` |
| `runT8d` :297-303 | map + `scope: probeScope` | `url.Values` + `scope`; `wantBody`/200-branch/wrong-code diagnostics unchanged |
| `runT9` :353-357 | raw `{"token":"sweep-probe-dummy"}` + `application/json` on bare client | body = `url.Values{"token": {"sweep-probe-dummy"}}.Encode()` with `Content-Type: application/x-www-form-urlencoded`; bare client, `validateAdvertisedURL` preflight, byte-identical `401 {"error":"invalid_client"}\n` unchanged |

Downstream of each call is untouched: JWT decode + claims matrix, the T-8e
refresh_token rejection (token.go:96-99), the `{"active":false}` assertion,
and all redaction helpers (`bodyEcho`/`sanitizeBody`/`redactURL`, sweep.go:
201-262) apply unchanged. Server-side form decoding of every field used is
confirmed present (`formIntoStruct` + `r.PostForm.Has("client_secret")`,
oauthwire/bind.go:128-157 and token_request.go:12-25; revoke/introspect bind
via `BindParams`, handle_revoke.go:75, handle_introspect.go:120).

### 2.3 New T-8b probe group (new file `cmd/sso-ctl/apiclient/token_contenttype.go`, ~130 lines)

`func (ck *checker) runT8b() (ok, skipped bool)` plus one shared leg helper
(`t8bLeg(client *http.Client, target, contentType string, body []byte) (diag string, ok bool)`).

- **Precondition/skip**: `ck.doc == nil || ck.doc.TokenEndpoint == ""` →
  stderr `check: T-8b skipped: advertised token_endpoint absent`, return
  `(false, true)` — same INCOMPLETE semantics as T-8d/T-9.
- **Preflight**: `validateAdvertisedURL(ck.doc.TokenEndpoint)` before any
  request; failure is a row FAIL, never a skip.
- **Client**: bare `&http.Client{Timeout: 30 * time.Second, CheckRedirect:
  rejectRedirect}` — structurally bearer-less like T-9 (`apiclient.New`'s
  env fallbacks cannot apply).
- **Body (both legs)**: `json.Marshal` of
  `{"grant_type":"client_credentials","client_id":ck.clientID,"client_secret":ck.clientSecret}`
  (no scope). Marshal of a map is key-sorted → deterministic
  `{"client_id":...,"client_secret":...,"grant_type":"client_credentials"}`.
  The body MUST be JSON, not form: only a JSON body is accepted by today's
  permissive parser (evidence fact 1 — a form body under a wrong CT 400s
  today too, which would make the row vacuous).
- **Legs** (both against the advertised token_endpoint):
  - leg A: `Content-Type: text/plain`;
  - leg B: no `Content-Type` header at all.
- **Expected per leg**: status 400 and raw body byte-identical to
  `{"error":"invalid_request"}\n`, with exactly one permitted deviation — a
  single additional top-level string field `trace_id` (the opt-in Tracing
  middleware's enrichment; T-8b is the only probe whose assertion path can
  see one, evidence E10-E12; mirrors the strict-mode AC-2 b2 caveat).

  The byte check is a **canonical re-encode comparison** (new helper
  `matchInvalidRequestBody(raw []byte) (diag string, ok bool)`):
  1. `json.Unmarshal` into `map[string]any` — must succeed;
  2. `env["error"]` must be the string `"invalid_request"`;
  3. every key must be `error` or `trace_id`, and `trace_id` (when present)
     must be a string;
  4. `json.Marshal(env)` + `"\n"` must equal `raw` byte-for-byte.

  This is stricter than a shape check and looser than a fixed constant in
  exactly the intended way: `{"error":"invalid_request"}\n` passes;
  `{"error":"invalid_request","trace_id":"x"}\n` passes (Marshal is
  key-sorted, matching the server's emission order); any
  `error_description`, wrong code, whitespace deviation, missing newline, or
  non-string `trace_id` fails. Complexity ≤ 15, fits the 50-line function
  budget with the helper split.
- **Diagnostics** (stderr, one line per failing leg, both legs always
  executed): `content_type probe (text/plain): status 401 body ...; expected 400 invalid_request` /
  `content_type probe (no Content-Type): ...`. The observed body is echoed
  ONLY for non-2xx responses, through `sanitizeBody` (redacts
  access_token/refresh_token/id_token/client_secret, truncates at 200 bytes);
  a 2xx body is a real minted token and is never echoed — the mint
  bodyEcho rule (token.go:81-84) applies. No credential, token, or probe
  material ever reaches a diagnostic.
- **Group line**: `content_type: OK` / `content_type: FAIL` on stdout;
  participates in the exit-code contract (any failure → `check FAIL`, exit 1).

### 2.4 Wiring and docs

- `CheckRun` (check.go:120-122): `contentTypeOK, contentTypeSkipped :=
  ck.runT8b()` executed between `runT8a` and `runT8d`; `contentTypeSkipped`
  joins the INCOMPLETE branch and `!contentTypeOK` the FAIL branch. Stdout
  order becomes `discovery, mint, content_type, invalid_scope, introspect,
  check OK`.
- `goldenGreenStdout` (check_test.go:32) becomes
  `"discovery: OK\nmint: OK\ncontent_type: OK\ninvalid_scope: OK\nintrospect: OK\ncheck OK\n"`;
  `TestSweep_GreenPath` and `TestStdoutDeterministic` follow automatically.
- Package doc comment (check.go:11-46): add T-8b to the group list and to the
  security-posture bullets (bare client, JSON credential body, two CT legs).
- `usage()` (check.go:137-191): add the T-8b group line.
- token.go header comment: extend the T-8 group table comment.

### 2.5 Test-harness changes (check_test.go)

- **`handleIntrospect`** (check_test.go:239-244): replace the JSON-only
  `bytes.Contains(body, []byte(`"client_id"`))` discrimination with a
  wire-agnostic parse: when `Content-Type` is
  `application/x-www-form-urlencoded`, `url.ParseQuery` the body and test
  `form.Has("client_id")`; otherwise keep the JSON substring test. (A raw
  JSON body under `url.ParseQuery` would become a single garbage key with an
  empty value — the CT dispatch is mandatory, not an optimization.)
- **`handleToken`**: add a T-8b branch. After the form switch, mint and T-8d
  are the only form-CT requests to `/token`, and T-8d is already
  discriminated by the raw `sweep-probe-` substring; every non-form-CT
  request (text/plain or absent CT) is a T-8b leg → serve
  `stub.t8bResp()` (new field, default `400 {"error":"invalid_request"}\n`,
  function-valued like `probeResp`/`t9Resp` so failure rows override it).
- **Request-record assertions**: mint/revoke/post-revoke introspect/T-8d
  records carry `Content-Type: application/x-www-form-urlencoded` and
  parseable form bodies (`url.ParseQuery` — never substring-match, Encode()
  sorts and escapes); T-9 carries `token=sweep-probe-dummy`; T-8b legs carry
  the JSON body with `text/plain` / absent CT.

## 3. Compatibility constraints

1. **Admin API JSON surface is frozen**: `Do` and its wrappers are untouched;
   `PostForm` is strictly additive. GKE-gateway and other JSON callers see no
   change.
2. **Wire contracts preserved**: all byte-identical assertions survive —
   `{"error":"invalid_scope"}\n` (T-8d), `{"error":"invalid_client"}\n`
   (T-9), `{"error":"invalid_request"}\n` modulo `trace_id` (T-8b), the
   refresh_token rejection (T-8e), and the `{"active":false}` post-revoke
   check. No server wire behavior changes; the probes move TO the
   RFC-mandated wire (RFC 6749 §3.2, RFC 7009 §2.1, RFC 7662 §2.1) that the
   B4-4 strict parser enforces.
3. **No public-contract surface changes**: no new endpoint, `Err*`, or config
   knob → `docs/openapi.yaml`, `docs/error-codes.md`,
   `docs/config-reference.md` are untouched.
4. **Architecture gates**: no new packages, no import-direction changes;
   `apiclient` remains stdlib-only production code; `interfaces/sso` 60-file
   ceiling untouched; `cmd/sso-ctl/` stays at its 16-subdir ceiling (new file
   lives in the existing `apiclient` package, growing it 4 → 5 non-test files,
   under the 10-file ceiling). Function budgets: `runT8b` ≤ 50 lines (leg
   helper split), complexity ≤ 15.
5. **Env inheritance**: `probeClient` and the bare clients are structurally
   env-fallback-free; `SSO_ADMIN_TOKEN`/`SSO_ADMIN_ADDR` can never steer or
   authenticate a credential probe.
6. **Forward/backward wire posture**: the new binary runs green against both
   permissive and hardened servers for mint/revoke/T-8d/T-9 (form decoding
   exists today, evidence E7/E13); only the T-8b row changes color — red on
   permissive (detection), green on hardened (compliance).

## 4. Failure modes

| # | Mode | Behavior | Design response |
|---|---|---|---|
| FM-1 | Unhardened server (JSON still accepted at /token) | T-8b legs get 200 (real token) | Row FAIL, exit 1 — the intended detection; 200 body never echoed (token-leak rule) |
| FM-2 | Hardened server + stale sso-ctl binary (JSON probes) | mint/revoke/T-8d 400 | Old binary fails loudly; deploy-time coupling, see D1/M3 |
| FM-3 | `trace_id`-enriched 400 (Tracing wired) | Body has extra top-level string field | PASSES — canonical re-encode check admits exactly `trace_id` |
| FM-4 | `error_description` / any other extra field | Body deviates | FAIL (key-allowlist check) |
| FM-5 | Wrong status (401/403/500) or wrong code (`invalid_scope`) | — | FAIL with per-leg stderr naming the leg's CT and observed status; body echoed via `sanitizeBody` (non-2xx only) |
| FM-6 | No advertised `token_endpoint` | — | Skip → stderr note + `check INCOMPLETE`, exit 1 (T-8d/T-9 precedent) |
| FM-7 | Redirect (3xx) on a leg | 307/308 would forward the JSON credential body; same-host Authorization | `rejectRedirect` on the bare client → observed 3xx fails the row; credentials never forwarded |
| FM-8 | Transport/network error on a leg | — | FAIL; `redactURL` on the error text (userinfo never echoed) |
| FM-9 | Mint body regressions (scope/resource encode) | `scope` dropped / `resource` sent empty / secret mangled by escaping | Form-wire recorded-request assertions in tests; `url.Values.Encode()` escapes and `ParseForm` decodes symmetrically |
| FM-10 | Stub misrouting after the form switch | `handleIntrospect`'s JSON-only discriminator misroutes form bodies | Wire-agnostic CT-dispatched parse (2.5) |
| FM-11 | Server emits non-sorted `trace_id` JSON or different whitespace | Byte deviation | FAIL — byte-identical is the contract; the snaplink server emits the canonical form (evidence E10-E13) |

## 5. Migration steps

1. **M1 — Land this sweep change alone** (independent, red-today by design):
   `PostForm` + five call-site switches + `runT8b` + harness rework + golden
   update + the new tests, including `TestSweep_ContentTypeRowFailsToday`
   which asserts the red state (exit 1, `content_type: FAIL`, all other rows
   OK) against `newLiveServer`.
2. **M2 — Land the server-side strict-mode direction separately**
   (`enforce-form-urlencoded-credential-strict-mode-0a8df02f`): flips
   `TestSweep_ContentTypeRowFailsToday` to green with zero sweep-side edits;
   both T-8b legs pass against the hardened server; `TestSweep_GreenPath`
   stays green throughout.
3. **M3 — Rollout order**: ship the updated `sso-ctl` binary and the hardened
   server together. The sweep is the rollout's verification instrument:
   green `content_type: OK` on a hardened deployment, `content_type: FAIL`
   (exit 1) on any canary that did not receive the hardening. A stale toolbelt
   against a hardened server fails loudly at `mint: FAIL` (D1) — document in
   the release notes, do not paper over.
4. **M4 — Rollback**: revert the five call sites and the `runT8b` wiring to
   restore the previous binary's exact behavior. No persisted state, no
   config, no server dependency.
5. **M5 — Doc bookkeeping**: advance the deferred note at
   `auto/cmd-sso-ctl-apiclient-requirements.md:490` (T-8b now covered;
   T-8c and T-8e-as-cache-row remain deferred).

## 6. Testable acceptance mapping

Supplied acceptance (requirements §4, preserved verbatim) → concrete tests.
Existing tests are listed by current line; new tests are named.

| Acceptance | Testable criteria | Test |
|---|---|---|
| T-8a form mint + matrix | mint request carries `Content-Type: application/x-www-form-urlencoded`, form body with the three required keys, `scope`/`resource` only when declared, `resource` repeated; claims matrix, revoke, post-revoke, T-8e stay green | New: `TestSweep_FormWireMint` (recorded-request assertions on the stub). Stay green: `TestMint_ClaimsMatrix` (:849), `TestMint_ScopeContainsRequested` (:859), `TestMint_AudContainsResource` (:870), `TestRevoke_RoundTrip` (:1039), `TestMint_ResponseFail` refresh_token row (:961), `TestMint_TenantIDExpectation`/`TestMint_RolesExpectationFailOnCC` |
| T-8a revoke + post-revoke introspect form | both recorded requests carry form CT + `token`/`client_id`/`client_secret`; `{"active":false}` assertion unchanged | New: `TestSweep_FormWireRevoke` (recorded-request assertions; post-revoke introspect discrimination via the reworked `handleIntrospect`). Stay green: `TestRevoke_*` (:1039-1083) |
| T-8b wrong-CT row | exit 0 + `content_type: OK` when both legs get `400 {"error":"invalid_request"}\n`; `trace_id` variant exit 0; `error_description`/extra-field variant exit 1; wrong status (401) exit 1; 200-token exit 1 with no token echo in stderr; both legs exercised (text/plain AND absent CT, JSON bodies); skip when token_endpoint absent → INCOMPLETE | New: `TestSweep_ContentTypeRow` (stub green), `TestSweep_ContentTypeRowTraceID` (modulo rule), `TestSweep_ContentTypeRowExtraFieldFails`, `TestSweep_ContentTypeRowWrongStatusFails`, `TestSweep_ContentTypeRow200NoEcho`, `TestSweep_ContentTypeRowSkip`; New: `TestSweep_ContentTypeRowFailsToday` (live `newLiveServer`: exit 1, `content_type: FAIL`, every other row OK — flips green when the strict-mode server lands, M2) |
| T-8d form + byte-identical | recorded T-8d request carries form CT; body still contains the randomized `sweep-probe-` scope; `wantBody` byte comparison unchanged | New: `TestSweep_FormWireT8d`. Stay green: `TestInvalidScope_ByteExact` (:1084), `TestInvalidScope_ExtraFieldFails` (:1096), `TestInvalidScope_EnforcementAbsent` (:1112), `TestInvalidScope_WrongCode` (:1132) |
| T-8e refresh_token | assertion at token.go:96-99 unchanged; row stays green on the form mint path | `TestMint_ResponseFail` (:948-961 row) — no edit |
| T-9 form introspect | recorded request carries form CT + `token=sweep-probe-dummy`; bare client; no Authorization even with `SSO_ADMIN_TOKEN` set; byte-identical `401 {"error":"invalid_client"}\n` | New: `TestSweep_FormWireT9` + recorded-request assertion. Stay green: `TestIntrospect_NoCreds401` (:1149), `TestIntrospect_NoAuthHeaderLeak` (:1162), `TestIntrospect_Non401Fails` (:1183), `TestIntrospect_SkipWhenNotAdvertised` (:1216) |
| Sweep contract | stdout byte-deterministic with the new `content_type` line; exit 0 on a green live run; red-today pin | `goldenGreenStdout` updated (:32) → `TestSweep_GreenPath` (:446), `TestStdoutDeterministic` (:463) follow; `TestSweep_ContentTypeRowFailsToday` as above |
| `PostForm` API contract | body bytes = `values.Encode()`; CT exactly `application/x-www-form-urlencoded`; `Accept: application/json`; bearer preserved when token set; caller's `http.Client` used; response body left open | New: `TestPostForm_FormEncoding`, `TestPostForm_BearerPreserved`, `TestPostForm_UsesClient` (apiclient_test.go) |
| Regression guards | redaction helpers, no-redirect pin, env inheritance | Stay green: `TestSweep_RedirectNotFollowed` (:793), `TestSweep_3xxContentRowFails` (:728), `TestRedactURL_RedactsUserinfo` (:1254), `TestSanitizeBody_RedactsSensitiveFields` (:1275), `TestDiagnostics_NeverEchoSecrets` (:1301) |

Verification commands (unchanged from the requirements spec §8):

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/apiclient/ -run 'TestPostForm_|TestSweep_|TestMint_|TestRevoke_|TestInvalidScope_|TestIntrospect_|TestContentType' -v
go test ./cmd/sso-ctl/... -race
make ci
```

## 7. Files

### Create

```text
cmd/sso-ctl/apiclient/token_contenttype.go — runT8b + t8bLeg + matchInvalidRequestBody
```

### Modify

```text
cmd/sso-ctl/apiclient/apiclient.go       — PostForm (REQ-1), net/url import (205 → ~225 lines)
cmd/sso-ctl/apiclient/token.go           — mint/revoke/T-8d/T-9 form transport (413 → ~420 lines)
cmd/sso-ctl/apiclient/check.go           — runT8b wiring, doc comment, usage (+~10 lines)
cmd/sso-ctl/apiclient/check_test.go      — golden stdout, form-wire assertions, T-8b rows,
                                           wire-agnostic handleIntrospect, handleToken T-8b branch,
                                           TestSweep_ContentTypeRowFailsToday (+~180 lines)
cmd/sso-ctl/apiclient/apiclient_test.go  — PostForm contract tests
docs/architect-analysis/auto/cmd-sso-ctl-apiclient-requirements.md — advance the deferred note (M5)
```

### Do not modify

```text
protocols/oauth/oauthwire/bind.go          — permissive parser is the server direction's surface
interfaces/sso/*, protocols/oauth/*        — no server-side edits
cmd/sso-ctl/apiclient/sweep.go             — T-2 rows are already wire-neutral
docs/openapi.yaml, docs/error-codes.md, docs/config-reference.md — no public-contract change
```

## 8. Scope guard (unchanged from requirements §3)

No server-side changes, no T-8c (constant-time), no T-8e-as-a-separate-row
(cache-header assertion), no cache-header assertions, no typed
`TokenRequest`/`Introspect` helpers, no JWT signature verification, no change
to `apiclient.Do` or the admin-API JSON contract. The deferred note in the
prior sweep spec covers exactly T-8b (this direction) and continues to defer
T-8c/T-8e-cache-row.
