# Design: form-urlencoded probe transport + Content-Type enforcement row (T-8e) for sso-ctl check

Companion to `docs/architect-analysis/cmd-sso-ctl-apiclient-b4-4-form-probes-requirements.md`.
This document treats that spec (and its summary artifact) as untrusted
evidence, records what was independently verified against the working tree,
and turns the requirements into a concrete, ordered design with API changes,
compatibility constraints, failure modes, migration steps, and testable
acceptance mapping.

## 1. Evidence verification verdict

Every citation in the requirements spec was re-checked against the working
tree. All four headline citations are confirmed exactly; the baseline-red
claim is reproduced (11 top-level failing tests + 9 failing subtests, all six
enumerated root causes visible in the failure output). One claim in the
pipeline summary artifact is REFUTED (V19): the two output files are not
identical — the pipeline artifact is a 26-line summary that asserts identity,
while the repo-visible mirror is the full 449-line spec. Downstream consumers
must read the mirror; the artifact alone does not contain the requirements.

| # | Claim | Verdict |
|---|---|---|
| V1 | `apiclient.go` `Do` JSON-only: `json.Marshal` :103, `Content-Type: application/json` :119, `Accept: application/json` :122; no form path, no `net/url` | Confirmed (Do :98-123; method set exactly `Do`/`Get`/`Post`/`Delete`/`Patch`; `WithNoRedirect` present as uncommitted WIP) |
| V2 | `token.go` all five credential sends are JSON: mint :72, revoke :244, post-revoke introspect :259, T-8d :297, T-9 :353-357 (explicit `Content-Type: application/json` at :357) | Confirmed exactly (grep-verified) |
| V3 | `oauthwire/bind.go:28` `BindParams`; form branch :38-42; `default:` :43-46 → `decodeSingleJSON` for any unknown/missing CT | Confirmed exactly |
| V4 | `check_test.go` `goldenGreenStdout` :32; `TestSweep_GreenPath` :446 | Confirmed (:446-457; `TestStdoutDeterministic` also compares the golden) |
| V5 | Baseline red: `go test ./cmd/sso-ctl/apiclient/` fails 11 tests | Confirmed — 11 top-level `--- FAIL` + 9 `--- FAIL` subtests; all six root causes reproduced with matching diagnostics |
| V6 | Root cause 1: `newLiveServer` (check_test.go:71-92) mints with `defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(...))` — no `WithEd25519Issuer(addr)` → `iss` = `core.DefaultIssuer` (`"snaplink-sso"`, interfaces/sso/aliases.go:179); production passes it at cmd/sso-server/serverbuildsign/build_signing_issuers.go:43 | Confirmed — red cohort: TestSweep_GreenPath, TestStdoutDeterministic, TestMint_ClaimsMatrix, TestMint_ScopeContainsRequested, TestMint_AudContainsResource/live-array-form, TestRevoke_RoundTrip (6 tests + 1 subtest) |
| V7 | Root causes 2-6: addr-validation substring trip; `checkTokenSuffix` loose `HasSuffix(u.Path, "/token")` (sweep.go:192); `advertiseDoc` unconditional URL concatenation; `TestMint_ResponseFail/status-400` writes 400 body at 200; `runT9` diagnostic `%q` quoting (token.go:368) | Confirmed — red cohort: TestCheck_AddrValidation (2 subtests), TestSweep_TokenEndpointSuffix, TestSweep_AdvertisedURLRejection (4 subtests), TestMint_ResponseFail/status-400, TestIntrospect_Non401Fails/wrong-bytes |
| V8 | Bind failure → `400 invalid_request` (interfaces/sso/server_token.go:31-34) | Confirmed |
| V9 | `formIntoStruct` binds string + `[]string` (multi-value or space-split) — oauthwire/bind.go:119-157; `TokenRequest.Resource []string` at oauthwire/token_request.go:11-29 | Confirmed (substance exact; `formStringSlice` multi-value/space-split lives at bind.go:149-157, `Resource` at token_request.go:25 — the spec's ranges are loose but harmless) |
| V10 | Secret presence survives the form wire via `r.PostForm.Has("client_secret")` | Confirmed (interfaces/sso/server_token_clientauth.go:99) |
| V11 | `/token/introspect` binds the same request through `BindParams` (`introspectRequest` :72-78, bind :120) | Confirmed (handle_introspect.go:74-78, :120 — off by 2 lines) |
| V12 | Stub harness is wire-coupled: `handleIntrospect` discriminates by JSON-only `"client_id"` substring (check_test.go:251); `handleToken` by raw `sweep-probe-` (:231); recorded clones share the body reader | Confirmed |
| V13 | T-2 endpoint rows POST `nil` bodies (sweep.go:158-162) — wire-neutral | Confirmed (`probeEndpoint` → `client.Do(row.method, path, nil)`) |
| V14 | Strict-mode campaign contract: wrong/absent CT on the four credential endpoints → byte-identical `400 {"error":"invalid_request"}` (run `enforce-form-urlencoded-credential-strict-mode-0a8df02f`, R3/R5) | Confirmed (requirements-0a8df02f:83-109) |
| V15 | Sibling campaign specs the same five call sites with a different row (T-8b: `text/plain` + absent CT → byte-identical `400 invalid_request`) | Confirmed (`cmd-sso-ctl-b4-4-check-probes-form-requirements.md`) |
| V16 | Deferred note at `auto/cmd-sso-ctl-apiclient-requirements.md:490` — T-8b/T-8c/T-8e are other directions' acceptance | Confirmed |
| V17 | `check.go` doc :11-46, `CheckRun` wiring :120-122, `usage()` :137-191; `probeClient` :269-277 bearer-less (no env fallbacks) | Confirmed |
| V18 | Budgets: apiclient.go 205, token.go 413, check.go 277, sweep.go 284, check_test.go 1345; 4 non-test files; `_test.go` exempt from the 500-line gate | Confirmed (maintainability_budget_test.go:71 skips `_test.go`) |
| V19 | **"Both files are in place and identical"** | **REFUTED** — direct diff: the pipeline artifact is a 26-line summary (containing the identity claim itself); the mirror is the full 449-line spec. Distinct content in every section. The design stage must read the mirror |

### D-carrying decisions (from verification, folded into the design)

- **D1 — T-8(e) body must be JSON.** Only a JSON body mints 200 under today's
  permissive parser (V3/V8); a form body under a wrong CT would bind-fail and
  400 even today, making the row vacuous. This is the load-bearing shape of
  the new row.
- **D2 — REQ-0.3 is the only production-code change in the baseline
  stabilization.** `checkTokenSuffix` (sweep.go:184-199) currently accepts
  `/oauth2/token`; `TestSweep_TokenEndpointSuffix` pins the stricter
  contract. Per AGENTS.md (satisfy the stricter contract), the sweep.go
  assertion aligns with the test, not the reverse.
- **D3 — T-8(e) 200 legs mint unrevoked tokens.** On a permissive server each
  leg returns a real token that is not revoked by this row. Accepted
  residual: TTL-bounded (1 min), permissive-server-only (an enforcing server
  never mints), and identical in kind to the T-8a mint's existing crash
  window between mint and revoke. Revoke-on-200 is deliberately out of scope:
  it would expand the row's failure surface (revoke failures would corrupt
  the content-type verdict) for negligible gain.

## 2. API changes

### 2.1 `apiclient.Client.PostForm` (REQ-1, additive)

Exactly one new method; `Do`/`Post`/`Get`/`Delete`/`Patch` stay
byte-for-byte unchanged (the admin-API JSON contract):

```go
// PostForm sends a POST with an application/x-www-form-urlencoded body
// (RFC 6749 §3.2, RFC 7009 §2.1, RFC 7662 §2.1). Same contract as Do:
// Accept: application/json, bearer header when c.token != "", caller
// closes resp.Body, c.http applies (the WithNoRedirect pin holds).
func (c *Client) PostForm(path string, values url.Values) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	return resp, nil
}
```

- `values.Encode()` never fails (no marshal-error path), sorts keys
  lexicographically (deterministic wire bytes), and percent-encodes
  values. `resource` is repeated per entry (`values.Add`).
- Standalone method, not a `Do` generalization: `Do`'s JSON marshal and the
  form wire share nothing but the header/Accept pattern. Smallest change.
- Imports: `net/url` added; `strings` already imported.

### 2.2 Five probe call-site flips (REQ-2..REQ-5, token.go)

| Site | Today (JSON) | After (form) |
|---|---|---|
| `mint` :72 | `client.Post("", map[string]any{...})` | `client.PostForm("", url.Values{"grant_type": {"client_credentials"}, "client_id": {ck.clientID}, "client_secret": {ck.clientSecret}})`; `scope` only when `ck.scope != ""`; `resource` via `values.Add` per entry |
| `revoke` :244 | JSON `token`/`client_id`/`client_secret` | same keys via `url.Values` |
| post-revoke introspect :259 | JSON same | same keys via `url.Values` |
| `runT8d` :297 | JSON + `scope` | form + `scope=probeScope` |
| `runT9` :353-357 | raw JSON `{"token":"sweep-probe-dummy"}` + CT json on a bare `http.Client` | `strings.NewReader(url.Values{"token": {"sweep-probe-dummy"}}.Encode())` + `Content-Type: application/x-www-form-urlencoded`; bare client, no bearer, 30s timeout, `rejectRedirect` unchanged |

Downstream behavior is untouched at every site: JWT decode, claims matrix,
the refresh_token rejection (token.go:96-99), the byte-identical pins
(`{"error":"invalid_scope"}\n` at :310/:326, `{"error":"invalid_client"}\n`
at :366-367), the 200 = enforcement-absent branch, and the credential-less
posture of T-9. REQ-0.6 changes the T-9 failure diagnostic from `%q` to `%s`
for the observed body (token.go:368).

### 2.3 New probe group T-8(e) (REQ-6, new file `token_contenttype.go`)

```go
// runT8e executes the T-8(e) Content-Type enforcement probe: POST the JSON
// credential body to the advertised token_endpoint under the
// application/json and text/plain Content-Types. Each leg passes only on a
// 4xx response whose body is a JSON error envelope; a 200 means the
// permissive JSON-default parser is still in place. The JSON body is
// load-bearing: a form body would 400 today too (bind failure), which
// would make the row vacuous.
func (ck *checker) runT8e() (ok, skipped bool)
```

- **Skip**: no advertised `token_endpoint` → stderr
  `check: T-8e skipped: advertised token_endpoint absent`, no stdout line,
  INCOMPLETE semantics (defensive — `runT8a` already forces INCOMPLETE).
- **Legs**: leg A `Content-Type: application/json`, leg B
  `Content-Type: text/plain`; identical JSON credential body as `mint`
  (no `scope`), sent through a bare `&http.Client{Timeout: 30 * time.Second,
  CheckRedirect: rejectRedirect}` — structurally bearer-less like T-9.
- **Pass per leg**: status 400-499 AND body decodes as a JSON object with a
  non-empty string `error`. Exact code not pinned (tolerates the strict-mode
  `400 invalid_request` and `trace_id` enrichment by construction).
- **Fail per leg**: 200 (token response — enforcement absent; body NEVER
  echoed: it can be a real minted token, `mint` bodyEcho rule applies);
  any 3xx (observed, never followed); 5xx (server broken, not enforcing);
  non-JSON body; empty/missing `error`.
- **Diagnostics**: one stderr line per failing leg naming the leg's
  Content-Type and observed status; body echoed only for non-2xx through
  `sanitizeBody`. Group line `content_type: OK` / `content_type: FAIL` from
  `CheckRun`'s group runner; any failure → exit 1.
- **Leg helper** (`t8eLeg`, same file, ≤50 lines) keeps `runT8e` under the
  function budget; complexity ≤15, `if` nesting ≤3 via guards.
- **Validity precondition** (usage text, T-8d precedent): the row is
  meaningful only with valid client credentials; with invalid credentials
  the server answers `401 invalid_client` (a valid envelope → leg passes)
  and the sweep is already red via T-8a/T-8d, so nothing is masked.

### 2.4 Wiring, golden, docs (REQ-7)

- `CheckRun` (check.go:120-122) gains `contentTypeOK, contentTypeSkipped :=
  ck.runT8e()` between `runT8a` and `runT8d`; both verdict aggregations
  (INCOMPLETE/FAIL) extend to the new group.
- `goldenGreenStdout` (check_test.go:32) becomes
  `"discovery: OK\nmint: OK\ncontent_type: OK\ninvalid_scope: OK\nintrospect: OK\ncheck OK\n"`.
- Package doc comment (check.go:11-46): add the T-8(e) group line and a
  security-posture bullet (bare client, no bearer, 200 bodies never echoed).
- `usage()` (check.go:137-191): new group line + validity precondition.

### 2.5 Baseline stabilization (REQ-0, precondition)

All six fixes from requirements §2, unchanged: REQ-0.1 `WithEd25519Issuer(addr)`
on `newLiveServer`; REQ-0.2 addr-validation inputs not substring of the
banner; REQ-0.3 exact `/token` or `<base-path>/token` suffix in sweep.go;
REQ-0.4 `advertiseDoc` prefixes only relative values; REQ-0.5 per-case status
in `TestMint_ResponseFail`; REQ-0.6 unquote the `runT9` diagnostic. Exit
criterion: full module suite green with the CURRENT golden before any
transport change.

## 3. Compatibility constraints

- **Server wire**: zero server-side changes. `BindParams` accepts form
  bodies today (V3), so all five probes stay green against the current
  server; only the T-8(e) row turns red today — the intended detection.
- **Response pins**: the byte-identical `invalid_scope`/`invalid_client`
  assertions are response-side and transport-independent; preserved.
- **Form encoding**: `url.Values.Encode()` sorts keys (deterministic wire:
  `client_id` < `client_secret` < `grant_type` < `scope`); `resource`
  repeated per entry (server multi-value branch, V9); `scope` single
  space-separated value (`%20` on the wire, server space-splits); the
  `sweep-probe-` substring (alphanumeric + hyphen) survives encoding
  unescaped, so the stub's T-8d discrimination keeps working.
- **Secret presence**: `client_secret=` with a present (even empty) value
  round-trips through `r.PostForm.Has("client_secret")` (V10). Probes always
  send the real secret.
- **Admin JSON surface**: `apiclient.Do`/`Post`/`Get`/`Delete`/`Patch`
  byte-for-byte unchanged; T-2's nil-body rows are wire-neutral (V13).
- **No flags**: the transport and the T-8(e) row are always-on; the row's
  validity precondition is documented, not gated.
- **Enforcement contract**: the row asserts the *class* (4xx + JSON error
  envelope), so it is green under the strict-mode contract's
  `400 {"error":"invalid_request"}` without pinning it (V14).
- **Sibling campaign overlap** (V15): both campaigns flip the same five call
  sites. Merging is idempotent per site; the stdout-line order of the two
  rows (`content_type` vs the sibling's row) is the merge decision. If the
  sibling lands first, this design rebases onto single-point flips.
- **No new packages/import directions**: `apiclient` stays stdlib-only.

## 4. Failure modes

| Mode | Behavior | Verdict |
|---|---|---|
| Permissive server (today) | Both legs 200 → `content_type: FAIL`, exit 1; token bodies never echoed | Intended red-today detection |
| One leg 200, one 4xx | FAIL with both per-leg diagnostics | Correct (enforcement is partial) |
| Redirect (3xx) | Observed, never followed (`rejectRedirect`); FAIL | No credential/token forwarding |
| 5xx / network error | FAIL with sanitized diagnostic | Correct (not enforcement) |
| Non-JSON error body (e.g. text/plain error page) | FAIL | Correct (row pins the JSON envelope) |
| `trace_id`-enriched 400 | PASS (envelope check ignores extras) | Compatible with strict-mode tracing |
| Invalid client credentials | Legs 401 `invalid_client` → PASS vacuously; sweep already red via T-8a/T-8d | Documented validity precondition; nothing masked |
| Missing `token_endpoint` | Skip, `check INCOMPLETE`, exit 1 | Defensive (runT8a already forces INCOMPLETE) |
| `SSO_ADMIN_TOKEN` exported | Bare client structurally bearer-less; no header leak | Same posture as T-9 |
| 200 legs mint unrevoked tokens | TTL-bounded (1 min), permissive-server-only; mirrors T-8a's existing mint/revoke crash window | Accepted residual (D3); revoke-on-200 out of scope |
| Sibling campaign merged | Same five flips; both rows coexist; line-order merge decision | No functional conflict |

## 5. Migration steps

1. **REQ-0 first** — stabilize the six root causes; gate: full module suite
   green with the CURRENT golden. No transport change lands on a red
   baseline.
2. **REQ-1** — `PostForm` + `TestPostForm_FormEncoding`
   (body bytes = `values.Encode()`, form CT, `Accept: application/json`,
   bearer preserved, no JSON CT).
3. **REQ-2..REQ-5 + F1** — flip the five call sites AND the
   `handleIntrospect` wire-agnostic discrimination change (the enabling
   harness fix; must ship in THIS step, not step 5 — §9.1). After the
   flips, the post-revoke introspect sends a form body (`client_id=…`,
   no quotes) that the stub's JSON-only `"client_id"` substring check
   (check_test.go:249-258) misroutes to the T-9 401 response, breaking 12
   stub tests (§9.2). Land the discriminator first (it is JSON-wire-neutral
   — checkpoint green), then the flips. Keep byte pins; T-8e not yet
   wired. Gate: full module suite green with the CURRENT golden.
4. **REQ-6/REQ-7 + fixture rework** — `token_contenttype.go`, `CheckRun`
   wiring, golden update, doc/usage updates — AND the fixture rework the
   wiring necessitates (§9.3): the row is red by design on any permissive
   fixture (both legs mint 200 today — verified), so the six live exit-0
   tests move to a form-only-enforcing wrapper around `newLiveServer` and
   the healthy stub's `/token` + `/token/introspect` + `/token/revoke`
   handlers reject non-form CT (empty bodies pass through, so the T-2
   nil-body rows survive). Safe sub-order: 4a fixtures (green, old
   golden) → 4b wiring + golden + `TestSweep_ContentTypeRowFailsToday`
   (green, extended golden). Gate: full module suite green with the
   EXTENDED golden.
5. **REQ-8 remainder** — request-shape assertions capture bytes inside
   handlers (recorded clones share the body reader — V12);
   `TestSweep_FormOnlyGreen` (if kept distinct from the enforcing healthy
   stub); the T-8(e) row matrix and skip tests (REQ-8.4/8.5); byte-identical
   regressions (REQ-8.6).
6. **Full gates** — `go build ./... && go vet ./...`; maintainability +
   architecture tests; module tests `-race`; `go test ./test/ -run TestE2E`;
   `make ci`.
7. **Rollback** — revert steps 3-5 wholesale: the five call sites, the
   `handleIntrospect` discrimination change, the `runT8e` wiring, the golden
   extension, the enforcing-fixture reworks, and the T-8(e)-specific tests
   (incl. `TestSweep_ContentTypeRowFailsToday`, which asserts
   `content_type: FAIL` and fails once the wiring is gone — §9.4). Keep
   steps 1-2 (REQ-0 is the stabilized baseline; `PostForm` is additive dead
   code that stays green). No persisted state, no server change to roll
   back. The intentionally red `TestSweep_ContentTypeRowFailsToday` flips
   green only when the strict-mode server campaign lands (separate
   campaign, V14).

## 6. Testable acceptance mapping

| Acceptance (verbatim §5) | REQ | Tests (existing / new) |
|---|---|---|
| T-8(a): form mint/revoke, byte-identical pins unchanged | REQ-2/REQ-3 | `TestMint_ClaimsMatrix`, `TestRevoke_RoundTrip`, `TestStdoutDeterministic`, `TestSweep_GreenPath` (green after REQ-0.1; after step 4 these live exit-0 tests run against the form-only-enforcing wrapper, §9.3); new request-record assertions: form CT + decoded form keys on mint/revoke/post-revoke sends |
| T-8(d): form + byte-identical `invalid_scope` | REQ-4 | `TestInvalidScope_ByteExact`, rows 19-21; new form-shape assertion on the T-8d send |
| T-9: form + byte-identical `invalid_client`, no bearer | REQ-5 | `TestIntrospect_NoCreds401`, `TestIntrospect_NoAuthHeaderLeak`, `TestIntrospect_Non401Fails` (after REQ-0.6) |
| T-8(e): JSON/text-plain CT POST rejected, non-200 error body, never a 200 token response | REQ-6 | New matrix: both legs 400 `invalid_request` → pass; `trace_id`-enriched 400 → pass; 415 + JSON envelope → pass; 200 token response → fail with no token echoed; 302 → fail; 500 → fail; non-JSON body → fail; one leg green + one red → fail with both diagnostics; skip (no `token_endpoint`) → INCOMPLETE, exit 1 |
| Green sweep under a form-only-enforcing server | REQ-8.2 | `TestSweep_FormOnlyGreen`: stub rejects non-form CT at `/token` (and form-only at revoke/introspect) → exit 0, extended golden stdout, silent stderr |
| Red-today detection | REQ-8.3 | `TestSweep_ContentTypeRowFailsToday`: live server → exit 1, `content_type: FAIL`, every other group line OK |
| PostForm contract | REQ-1 | `TestPostForm_FormEncoding` |
| Baseline precondition | REQ-0 | Full module suite green with the current golden (step 1 gate) |

## 7. Files

Create:

```text
cmd/sso-ctl/apiclient/token_contenttype.go — runT8e + t8eLeg (REQ-6)
docs/architect-analysis/cmd-sso-ctl-apiclient-b4-4-form-probes-design.md — this document
```

Modify:

```text
cmd/sso-ctl/apiclient/apiclient.go — PostForm + net/url import (REQ-1)
cmd/sso-ctl/apiclient/token.go — five form flips (REQ-2..5), runT9 diagnostic unquote (REQ-0.6)
cmd/sso-ctl/apiclient/check.go — runT8e wiring, doc comment, usage (REQ-7)
cmd/sso-ctl/apiclient/sweep.go — checkTokenSuffix exact-suffix rule (REQ-0.3)
cmd/sso-ctl/apiclient/check_test.go — golden, REQ-0 fixture fixes, wire-agnostic
  handleIntrospect, form request assertions, T-8(e) matrix, TestSweep_FormOnlyGreen,
  TestSweep_ContentTypeRowFailsToday (REQ-0/REQ-8)
cmd/sso-ctl/apiclient/apiclient_test.go — PostForm contract tests (REQ-8.1)
```

Do not modify:

```text
protocols/oauth/oauthwire/bind.go — the permissive parser is the strict-mode
  server direction's surface; the sweep detects it, does not change it
interfaces/sso/*, protocols/oauth/handle_introspect.go — no server-side edits
apiclient.go Do/Post/Get/Delete/Patch semantics — admin-API JSON contract
docs/openapi.yaml, docs/error-codes.md, docs/config-reference.md — no public-contract change
```

Budgets: apiclient.go 205→~223, token.go 413→~434, check.go 277→~292,
sweep.go 284→~286, token_contenttype.go ~100 (all ≤500, functions ≤50,
complexity ≤15, nesting ≤3); 5 non-test files/directory (≤10); no new
subdirectory; `cmd/sso-ctl` root fan-out and `interfaces/sso` 60-file ceiling
untouched. `_test.go` files are exempt from the 500-line gate
(maintainability_budget_test.go:71).

## 8. Scope guard (unchanged from requirements §4)

No server-side changes, no absent-CT leg, no byte-identical requirement for
the new row, no T-8c, no cache-header assertions on the new row, no typed
`TokenRequest`/`Introspect` helpers, no change to the admin JSON surface
beyond additive `PostForm`, REQ-0 bounded to the six enumerated causes. The
`enforce-form-urlencoded-credential-strict-mode` campaign owns the server
parser; this design pins the sweep against its published contract.

## 9. F1 fold-in: wire-agnostic discrimination + corrected migration gates

Re-validation of §5 with the security review's F1 correction folded in,
plus the hidden ordering dependency the fold-in exposed in step 4. Every
claim below was verified against the working tree (baseline reproduced: 11
top-level + 9 subtests red, six root causes) and empirically (wire
discrimination matrix, live-server leg behavior).

### 9.1 The precise `handleIntrospect` change (ships in step 3)

Replace the JSON-only substring check (check_test.go:249-258) with a
wire-agnostic discriminator. Exact shape:

```go
func (s *stubCheck) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if !introspectHasClientID(body) {
		status, respBody := s.t9Resp()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
		return
	}
	status, respBody := s.postRevoke()
	w.WriteHeader(status)
	_, _ = w.Write([]byte(respBody))
}

// introspectHasClientID reports whether the introspect body carries a
// client_id on either wire: form bodies (the flipped post-revoke probe)
// parse via url.ParseQuery and are keyed on the client_id entry; JSON
// bodies keep the keyed-substring check. The two probes never overlap:
// the T-9 credential-less body has no client_id in either encoding, and a
// JSON body can never yield a client_id key under ParseQuery (no '&' or
// '=' separators inside realistic payloads — the whole JSON collapses to
// one key), so the checks are disjoint and order-independent.
func introspectHasClientID(body []byte) bool {
	if vals, err := url.ParseQuery(string(body)); err == nil {
		if _, ok := vals["client_id"]; ok {
			return true
		}
	}
	return bytes.Contains(body, []byte(`"client_id"`))
}
```

Verified empirically over the seven real body shapes (T-9 form, post-revoke
form incl. a JWT token value, T-9 JSON, post-revoke JSON, mint form, T-8d
form, and a paranoid JSON value containing `=`): routing is identical to
today on every JSON wire and correct on the form wire. The change is a
strict superset of the old discriminator — it cannot flip any
currently-green JSON-wire test — which is what makes the in-step-3
checkpoint (discriminator first, suite green, then flips, suite green)
sound. `url.ParseQuery` error is tolerated: partial maps still key
correctly and the JSON fallback covers the rest. Needs `net/url` import in
check_test.go.

### 9.2 Complete stub-test enumeration for the change

**Verdict-flipping without the fix (12 tests/subtests)** — every one is a
full-sweep run whose post-revoke introspect must route to `postRevoke`:

1. `TestIntrospect_NoCreds401` (:1149) — exit 0, golden
2. `TestIntrospect_NoAuthHeaderLeak` (:1162) — exit 0 + auth-header pins
3. `TestInvalidScope_ByteExact` (:1084) — exit 0, golden
4. `TestSweep_3xxTruthinessPasses` (:678) — exit 0, golden
5. `TestSweep_AdvertisedOnly` (:519) — exit 0, golden
6. `TestSweep_DecoyFieldNotFetched` (:653) — exit 0
7. `TestCheck_EnvAddrValidation/valid-env-steers-sweep` (:400) — exit 0, golden
8. `TestRevoke_StillActiveFails` (:1067) — exit 1 but asserts the
   still-active diagnostic, which only appears when the post-revoke
   introspect reaches the `postRevoke` override
9. `TestMint_TenantIDExpectation/present-matches` (:893) — exit 0
10. `TestMint_RolesExpectationFailsOnCC/stub-with-roles-passes` (:921) — exit 0
11. `TestMint_AudContainsResource/stub-string-form` (:870) — exit 0
    (NOT in the security review's list — addition)
12. `TestSweep_RedirectNotFollowed/truthiness-302-not-followed` (:793) —
    exit 0 (NOT in the security review's list — addition)

The security review's ~10 is therefore 12: items 11-12 were missed. (Also
note: `TestMint_AudContainsResource/live-array-form` and
`TestRevoke_RoundTrip` are live-server runs — the real `handleIntrospect`
binds through `BindParams` and is wire-neutral; they are NOT in this class.)

**Tolerate-class (verdict unchanged; stderr gains one revoke-leg line if
the fix were absent)** — exit-1/substring assertions survive the misroute:
`TestClaimsMatrix_FailureDiagnostics` (8 subtests, :993),
`TestInvalidScope_ExtraFieldFails` (:1096), `TestInvalidScope_EnforcementAbsent`
(:1112), `TestInvalidScope_WrongCode` (:1132), `TestIntrospect_Non401Fails`
(3 subtests, :1183), `TestMint_TenantIDExpectation/absent-fails` (:893),
`TestSweep_3xxContentRowFails` (6 subtests, :728). No edit needed; their
stderr grows a `revoke: post-revoke introspect: status 401` line only.

**Untouched** — no introspect request or no revoke path reaches the stub:
CLI-misuse rows (`TestCheck_NoCredentialsMisuse`, `TestExitCodes`,
`TestCheck_AddrValidation`), discovery-fail rows
(`TestSweep_DiscoveryFetchFail`, `TestSweep_TransportErrorRow`,
`TestSweep_404RowFails`, `TestSweep_TokenEndpointSuffix`,
`TestSweep_AdvertisedURLRejection`), `TestIntrospect_SkipWhenNotAdvertised`
(zero introspect requests), `TestMint_ResponseFail` (mint fails before
revoke), `TestRevoke_Non200Fails` (revoke fails before introspect),
`TestDiagnostics_NeverEchoSecrets` (mint fails first),
`TestMint_RandReadFailure` (zero requests).

### 9.3 Step-4 hidden dependency: the wiring turns every permissive fixture red

Verified against the live server wiring: both T-8(e) legs
(JSON body + `application/json` / `text/plain` CT) mint **200** against the
current permissive `newLiveServer` (empirically reproduced with the exact
fixture construction). Therefore `CheckRun` wiring alone flips red — by
design — every exit-0 sweep test on a permissive fixture:

- **6 live tests**: `TestSweep_GreenPath`, `TestStdoutDeterministic`,
  `TestMint_ClaimsMatrix`, `TestMint_ScopeContainsRequested`,
  `TestMint_AudContainsResource/live-array-form`, `TestRevoke_RoundTrip`.
- **11 stub tests** (the §9.2 items 1-7, 9-12): the healthy stub's
  `handleToken` mints for the T-8(e) bodies (no `sweep-probe-`), so the
  legs get 200 → `content_type: FAIL` → exit 1.

Fix (must land in the same step as the wiring, so each checkpoint stays
green):

- `newLiveServer` stays permissive (it is `TestSweep_ContentTypeRowFailsToday`'s
  fixture); add a test-side form-only gate wrapping `srv.Handler()` for the
  six live exit-0 tests: paths `/token`, `/token/introspect`, `/token/revoke`
  with a non-form CT AND a non-empty body →
  `400 {"error":"invalid_request"}\n`; everything else (GETs, the T-2
  nil-body rows, form probes) passes through to the real server.
- The healthy stub's `handleToken`/`handleIntrospect`/`handleRevoke` gain
  the same gate before their existing discrimination (CT != form AND
  non-empty body → 400 envelope). This is exactly the
  `TestSweep_FormOnlyGreen` stub of REQ-8.2 — folding it into `healthy()`
  makes FormOnlyGreen near-redundant (keep it as the explicit acceptance
  pin or drop it; decision recorded here). `TestSweep_3xxTruthinessPasses`
  replaces `handleToken` with a custom handler that must gain the same CT
  check for its T-8(e) legs (its mint branch would otherwise 200 them).
- Golden update is atomic with the wiring: exactly five tests compare
  `goldenGreenStdout` (:433, :453, :475, :534, :721).

Safe sub-order: 4a fixtures alone (enforcement invisible while T-8e is
unwired — old golden, suite green) → 4b wiring + extended golden +
`TestSweep_ContentTypeRowFailsToday` (suite green). Exit-1 tests all
survive step 4 unedited (verified per test: `TestIntrospect_SkipWhenNotAdvertised`
keeps INCOMPLETE, `TestMint_ResponseFail`/`TestDiagnostics_NeverEchoSecrets`
keep their asserted diagnostics and never-echo pins; the T-8(e) 200-body
never-echo rule is what keeps `MINTED-BUT-NOT-ACCESS`/`MINTED` off stderr).

### 9.4 Rollback correction

The rollback unit is steps 3-5 wholesale, not "five sites + wiring + golden":
the discrimination change, the enforcing-fixture reworks, and the
T-8(e)-specific tests ride with the feature. In particular
`TestSweep_ContentTypeRowFailsToday` asserts `content_type: FAIL` and
FAILS once the wiring is reverted — it must be reverted too. Steps 1-2 stay
(REQ-0 is the stabilized baseline — reverting it re-breaks the 11-test red
cohort; `PostForm` is additive dead code that stays green). The
enforcing-fixture reworks are rollback-neutral on their own (enforcement is
invisible without the T-8(e) row), so they can be reverted or kept — the
clean boundary is steps 3-5. No persisted state, no server change.
