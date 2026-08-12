# Decisions: B4-4 form-only wire — PAR RawMessage encoding (F1) and MFA params map loss (F3)

- Direction: B4-4 (source: `docs/architect-analysis/auto/analyses/cmd-sso-ctl-entitiescmd-631f0c1d.json`, entry 3)
- Amends: `docs/architect-analysis/cmd-sso-ctl-entitiescmd-b4-4-credential-form-only-design.md` (the "design")
- Resolves: the two HIGH findings from the oauth-wire-security review — reviewer F1 (PAR `authorization_details`/`claims` `json.RawMessage` inexpressible on the form wire; silent drop today) and reviewer F3 (`mfaCompleteRequest.Params map[string]string` wire loss)
- Status: decided, validated against RFC 6749/7009/7662/8628/9126/9396 + OIDC Core §5.5 and the in-repo RAR/MFA tests; `go build ./... && go vet ./...` clean at decision time (HEAD 5c8bfcc2 + working tree)

## 1. Facts re-verified at decision time

| Fact | Location | Meaning |
|---|---|---|
| `setFormField` handles only string/bool/int/*int/[]string; `json.RawMessage` (`[]byte`, slice-of-Uint8) and `map[string]string` fall through silently | `protocols/oauth/oauthwire/bind.go:112-134` | Both are silently dropped on the form wire today; the request proceeds with the field zero-valued |
| `parRequestForm` carries `AuthorizationDetails json.RawMessage` and `Claims json.RawMessage` | `protocols/oauth/handle_par.go:89-107` | The only credential-site struct with RawMessage fields (verified: `TokenRequest`, `introspectRequest`, `revokeRequest`, both device structs, `cibaRequest`, `compromiseCredentialRequest`, `cryptoKeyCompromiseRequest` have none) |
| `ValidateAuthorizationDetails` on empty input returns `(nil, nil)` — no error | `protocols/oauth/oauthvalidate/rar.go:153-157` | Today a form PAR carrying `authorization_details` is accepted with the details silently discarded; the mandated RAR test is the proof (`test/handle_par_test.go:391`) |
| `/auth/mfa` bind errors collapse to `400 mfa_invalid`, no audit | `interfaces/sso/server_mfa.go:253-258` | The F3 fail-loud rejection inherits this envelope; no new `Err*` |
| Flat `Code`/`Assertion` fields exist explicitly for form callers | `interfaces/sso/server_mfa.go:224-241` | The form contract for MFA factor material is already defined |
| Non-credential `BindParams` consumers with RawMessage/map fields: `interfaces/admin/governance.go:35,61` (`Payload json.RawMessage`), `interfaces/admin/connections.go:25,134` + `internal/adminuser/service.go:52` + `protocols/selfservice/selfserviceaccount/profile.go:107,109` (`map[string]string`) | grep of all 36 non-credential bind sites | Scoping constraint: the shared decoder must not gain a map case (would 400 those form consumers and break the design's byte-identical boundary pin); the RawMessage case has exactly one non-credential collateral consumer (governance) |
| No in-repo test sends `params` to `/auth/mfa` (only `test/oidc-conformance/drive_test.py` uses the word as an unrelated WebSocket RPC keyword) | grep `test/` + `interfaces/sso/*_test.go` | F3 has no in-repo positive caller to preserve; fail-loud breaks nothing in-tree |
| RFC 9396 contains no §7.2; the normative form-encoding text is §3 ("encoded using the application/x-www-form-urlencoded format of the serialized JSON", Figure 8) | rfc-editor.org rfc9396.txt §3 | The reviewer's "§7.2" citation is a misnumbering; the concept (JSON-string form encoding) is real and normative |
| RFC 9126 §2.1: PAR body is `x-www-form-urlencoded`, UTF-8, composed of "any of the parameters applicable for use at the authorization endpoint... including all applicable extensions" | rfc-editor.org rfc9126.txt §2.1 | `authorization_details`/`claims` must be expressible on the PAR form wire; a form-only PAR that cannot carry them is a non-compliant RFC 9396 §3 implementation of the PAR surface |

## 2. Decision F1 — PAR RawMessage fields: RFC 9396 §3 JSON-string form encoding, with fail-loud on malformed values

**Chosen option:** extend the shared form decoder so a `json.RawMessage` (`[]byte`) field binds from a form key whose single value is the serialized JSON text — the JSON-string form encoding of RFC 9396 §3 (for `authorization_details`) and of OIDC Core §5.5's own authorization-request transmission (for `claims`, which is a URL-encoded JSON object). Malformed input (value that is not valid JSON, or a repeated key) fails loud at the bind with the site's existing canonical 400. The fail-loud-only alternative is rejected (below).

### 2.1 Why the encoding, not fail-loud-only

1. **RFC 9126 §2.1 + RFC 9396 §3 settle it.** PAR is a form-wire protocol that carries "any of the parameters applicable for use at the authorization endpoint... including all applicable extensions". RFC 9396 §3 defines exactly one form encoding for `authorization_details` — the serialized-JSON value. A server whose PAR surface rejects `authorization_details` on the form wire cannot serve a compliant RFC 9396 client that pushes RAR parameters. RAR-over-PAR support is a shipped, tested contract of this server (feature matrix, `test/handle_par_test.go`, `test/rar_test.go`), not roadmap prose.
2. **The mandated test must keep passing with a defined remediation, not become a permanent negative.** `TestPAR_AuthorizationDetailsSurvivesIntoAccessToken` pins shipped RAR-over-PAR capability end-to-end (PAR push → login → access-token claim). Its remediation is a wire migration of the `parThenLogin` helper to the form wire with the JSON-string value (the RFC's own encoding) — the test then passes unchanged in substance. Fail-loud-only would convert a capability test into a rejection test, deleting shipped behavior.
3. **Silent drop is not an option under either branch of the mandate.** The reviewer's finding stands: `ValidateAuthorizationDetails(nil)` returns `(nil, nil)`, so a form PAR carrying `authorization_details` today succeeds with the client's RAR intent vanished from the minted token. Both decided options (decode or reject) eliminate the drop; we take decode because the RFC defines it.

### 2.2 Decoder semantics (pinned)

In `oauthwire/bind.go`, extend the existing `case reflect.Slice` in `setFormField` (:128-134) with a `reflect.Uint8` sub-branch (covers `json.RawMessage` = `[]byte`; no other `[]byte` fields exist on bound structs):

| Input on the form wire | Behavior |
|---|---|
| Key absent | Unchanged — field stays zero, request proceeds (identical to today) |
| Key present, exactly one value, `json.Valid(value)` | Field set to the raw bytes verbatim (whitespace preserved, exactly as JSON-wire `RawMessage` capture preserves it); all downstream PAR logic (`validatePARRequestParams` → `ValidateAuthorizationDetails` + `RARLimits` + type allowlist → PAR store → login merge → token stamping) runs unchanged |
| Key present, value not valid JSON (incl. empty value) | Bind error → the site's existing canonical 400 (`invalid_request` on `/par`, `mfa_invalid` on `/auth/mfa` — no site distinguishes binder errors, oracle-safe) |
| Key repeated (`a=…&a=…`) | Bind error → same canonical 400. No RFC defines repeated-key semantics for a single JSON value; accepting only the first would let a smuggled second value ride along silently. Fail loud on ambiguity |

`claims` gets the same treatment (OIDC Core §5.5 JSON object, URL-encoded in authorization requests). Shape enforcement (object for `claims`, array of typed objects for `authorization_details`) stays exactly where it is today: `ValidateClaimsParameter` at the login gate (`interfaces/sso/server_login_gates.go:328`, `shared/core/claims_param.go:184`) and `ValidateAuthorizationDetails` at PAR (`handle_par.go:222`). The decoder validates only JSON-ness, mirroring how a malformed JSON body 400s at JSON decode today.

### 2.3 Remediation path for the mandated test and the RAR-over-PAR suite

`test/handle_par_test.go`:

| Change | Details |
|---|---|
| `parThenLogin` helper (:337) | The `/par` POST switches from `application/json` + `json.Marshal` to `url.Values` + `application/x-www-form-urlencoded`; `authorization_details` is carried as the plain JSON text string (the form encoder URL-encodes it — that IS the RFC 9396 §3 wire form). The `/auth/login` POST stays JSON (login is JSON-only, out of scope) |
| `TestPAR_AuthorizationDetailsSurvivesIntoAccessToken` (:391) | Remediated by the helper migration; assertions byte-identical — PAR 201, login 200, token JWT payload carries `authorization_details` with all four fields preserved |
| `TestPAR_RejectsDisallowedAuthorizationDetailsTypeAtPushTime` (:417), `TestPAR_RejectsMalformedAuthorizationDetailsAtPushTime` (:429), `TestPAR_AuthorizationDetailsOverridesLoginParam` (:444), and the code-flow/request_uri tests using the harness | Same helper migration; the malformed-details test keeps asserting `400 invalid_authorization_details` (shape errors still surface from `ValidateAuthorizationDetails`, not the binder — the JSON-string `{"type":"payment_initiation"}` is valid JSON, so it binds, then the RAR validator rejects the non-array shape; identical to the JSON wire today) |
| `TestPAR_HappyPath_JSON` (:102) | Migrates to a form body; renamed `TestPAR_HappyPath_Form` (the name documents the wire) |

New negatives (land in `test/credential_content_type_test.go` or `protocols/oauth/oauthwire/bind_strict_test.go`):

- Form PAR, `authorization_details` = `not-json` → 400 `invalid_request` (fail-loud on malformed JSON-string; the F1-mandated "fail loud" branch applies to malformed input).
- Form PAR, `authorization_details` repeated key → 400 `invalid_request`.
- Form PAR, `claims` = valid JSON object string → 201, and a follow-up login with the `request_uri` succeeds with the requested claims threaded (new positive coverage — PAR claims have no in-repo test today; mirrors `TestClaimsParam_AcceptedAndThreaded` across the PAR merge).
- Form PAR, `claims` = `[]` → 201 at PAR, 400 at login (`ValidateClaimsParameter` object gate) — same split as the JSON wire today.
- Unit (`bind_strict_test.go`): RawMessage happy path with verbatim byte preservation; invalid JSON error; repeated-key error; and a byte-identity pin — a form request carrying a `map[string]string`-typed key still binds without error at the decoder (see F3 for where the rejection lives).

### 2.4 Byte-identical confirmation for existing fields

The extension is a sub-branch inside the existing `case reflect.Slice` that today falls through for byte slices:

- Requests whose form keys map only to supported field types (string/bool/int/*int/[]string) take an **identical** control path: same `formIntoStruct` iteration order, same `formFieldKey`/`setFormInt`/`formStringSlice` behavior, same `ParseForm`/media-type handling, same errors. `decodeSingleJSON` and the `BindParams` default branch are untouched, so the 36 non-credential consumers' JSON and form semantics are byte-identical.
- The new branch is reachable only when a form key maps to a `[]byte` field — a request shape that today silently drops the value. "Existing fields" (the supported kinds) are byte-identical by construction; the RawMessage case is the F1 decision surface, not an existing field.
- **Disclosed collateral (additive, same defect class):** `interfaces/admin/governance.go:61` binds `Payload json.RawMessage` via the shared `BindParams`. Form-wire requests carrying `payload` change from silent drop to JSON-string decode (or 400 on malformed). No other non-credential consumer has a `[]byte` field. JSON wire and the `normalizedJSON`-gated commerce surface are unaffected.
- **Deliberately NOT extended:** `map[string]string`. A decoder-level map case would turn form requests carrying `config`/`attributes` keys at `interfaces/admin/connections.go:134`, `internal/adminuser/handlers.go:32/96`, and `protocols/selfservice/selfserviceaccount/profile.go:109` from silent-skip into 400s — breaking the design's non-credential byte-identical boundary. Maps stay silent-skip in the shared decoder; the credential MFA site enforces fail-loud explicitly (F3).

## 3. Decision F3 — MFA `params` map: fail loud at `/auth/mfa`, document the form contract

**Chosen option:** a form request to `/auth/mfa` that carries the `params` key is rejected with the existing `400 mfa_invalid` envelope at parse time; the flat `code`/`assertion` fields remain the documented form contract; the `params` map remains declared and JSON-only. This is the reviewer's "fail loud" branch, not "document only".

### 3.1 Why fail loud, and why at the handler

1. **No RFC defines a form encoding for maps.** RFC 6749 §2.3.1/§3.2 define simple parameters; nothing in 6749/7009/7662/8628/9126/9396 or OIDC provides `map[string]string` form semantics. Inventing one (`params[foo]=bar`, repeated-key flattening) would create a proprietary wire contract with no client ecosystem and no RFC anchor — worse than either decided branch.
2. **Silent drop is non-deterministic across providers.** A form client that ports a JSON payload and sends `params` would have its factor material discarded before `collectMFAParams` (`server_mfa.go:296`, `:440-447`). For totp/webauthn the provider then fails with empty params (a misleading `mfa_invalid`, no audit trail pointing at the wire); for a provider that verifies from challenge state alone, the request would succeed *without the caller's data*. Both outcomes are wrong in different directions; fail-loud makes the outcome one deterministic, documented 400.
3. **Oracle safety is free.** The rejection collapses to the same `mfa_invalid` envelope as every other `/auth/mfa` failure (AGENTS.md: "Any MFA failure → 400 mfa_invalid; details only in mfa_failure audit"), uses no new `Err*`, and is indistinguishable from a bad code on the wire. It is a wire-shape rejection, never state-derived — no new oracle.
4. **No in-repo caller is affected** (verified: zero tests send `params` to `/auth/mfa`), and the flat fields already exist for form clients (`server_mfa.go:231-234` "HTML forms, simple clients").
5. **Why the handler, not the decoder:** the shared decoder must keep maps as silent-skip to preserve the non-credential boundary (F3's decoder-level alternative would 400 admin/selfservice form consumers). The check belongs at the one credential site with a map field.

### 3.2 Semantics (pinned)

In `parseMFACompleteRequest` (`interfaces/sso/server_mfa.go:253`), after the strict bind succeeds:

```go
// A form wire has no RFC-defined encoding for map[string]string. A form
// request carrying `params` would silently drop the factor material
// (the shared decoder skips map fields to keep the non-credential
// boundary byte-identical) — reject instead of guessing, with the
// existing mfa_invalid envelope. Form callers use the flat
// code/assertion fields (server_mfa.go flat-field contract).
if r := ctx.Request(); r.PostForm != nil && r.PostForm.Has("params") {
    ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMFAInvalid))
    return req, false
}
```

- Reachability is exact: under the form-only binder, `r.PostForm` is populated only for form content types; JSON/missing-CT requests fail the bind before this check, so `PostForm.Has("params")` is precisely "a form request that carries `params`".
- No audit — consistent with the existing bind-error path comment (`server_mfa.go:250-252`); no new error code, no openapi error-code change beyond a note.
- Documentation lands in the same change: `server_mfa.go` field comment ("`params` is JSON-only; a form request carrying it is rejected with `mfa_invalid`; form callers use `code`/`assertion`"), `docs/error-codes.md` note, and the openapi `/auth/mfa` schema description.
- The `params` field stays declared: it remains the JSON contract for richer providers if JSON support is ever restored by a future config knob, and `collectMFAParams` keeps its structure. Under B4-4 its only wire expression is the rejection.

New tests: form `/auth/mfa` with a `params` key (any value) → 400 `mfa_invalid`, envelope byte-identical to a wrong-code response (table row in `test/credential_content_type_test.go`); form `/auth/mfa` with `code`/`assertion` binds and dispatches as today (existing `TestMFA_*` family, SWEEP-unchanged).

## 4. RFC validation

| RFC / spec | Position on the affected surface | Verdict for the decided options |
|---|---|---|
| RFC 6749 §3.2, §2.3.1 | Token endpoint and client-auth parameters are form-encoded; `invalid_request` 400 (§5.2) | Form-only enforcement is §3.2-conformant; F1/F3 introduce no token-endpoint surface (`TokenRequest` has no RawMessage/map); the JSON-string value is a normal form parameter per Appendix B |
| RFC 7009 §2.1 | Revocation request is form-encoded | Unaffected (`revokeRequest` has no RawMessage/map); form-only alignment unchanged |
| RFC 7662 §2.1 | Introspection request is form-encoded | Unaffected (`introspectRequest` has no RawMessage/map) |
| RFC 8628 §3.1-3.2 | Device authorization and verification are form-encoded | Unaffected (neither device struct has RawMessage/map); RFC 9396 §3's device-context `authorization_details` remains a documented non-goal (no field, no test — separate feature) |
| RFC 9126 §2.1 | PAR body is `x-www-form-urlencoded`, UTF-8, may carry any authorization-endpoint parameter incl. extensions | F1's JSON-string form is the only way a form-only PAR surface can carry `authorization_details`/`claims` at all — the decision is required by §2.1 |
| RFC 9396 §2, §3 | §2: parameter is an array of objects (shape enforced downstream); §3: form encoding is "the application/x-www-form-urlencoded format of the serialized JSON" (Figure 8) | F1 implements §3 verbatim (value = serialized JSON); §2 shape enforcement stays in `ValidateAuthorizationDetails` untouched; malformed JSON-string values are malformed requests → canonical 400 (no RFC conflict — the encoding is defined, garbage is not a value) |
| OIDC Core §5.5 | `claims` is a JSON object, transmitted URL-encoded in authorization requests | F1's claims handling is the same JSON-string form; object-shape enforcement stays at `ValidateClaimsParameter` (login gate), identical split to the JSON wire |
| CIBA (OID-CIBA) | Backchannel auth is a form POST | Unaffected (`cibaRequest` has no RawMessage/map); RFC 9396 §3 CIBA-context RAR remains a documented non-goal |
| AGENTS.md oracle table | `/auth/mfa` → `400 mfa_invalid`; bind errors indistinguishable per site | F3 rejection uses the existing envelope, no audit, no new `Err*`; F1 bind errors collapse per-site exactly as today |

## 5. Interaction with the design doc

The design's §3.4 F5 row ("MFA error-shape drift") and the §3.1 binder description are extended by these decisions; the design's existing F1-F10 rows are otherwise unchanged. Reconciliation note (`docs/architect-analysis/b4-4-credential-form-sdk-binder-reconciliation.md` D3): the strict surface is the eight RFC-mandated OAuth credential endpoints; the two admin compromise sites stay dual-mode, which does not affect F1/F3 — the shared decoder keeps maps as silent-skip and the RawMessage sub-branch's disclosed collateral (`interfaces/admin/governance.go:61`) is unchanged. Implementation impact:

- Step 1 (binder) additionally implements the RawMessage sub-branch and its unit tests (2.2, 2.4).
- Step 2 (eight-site switch per the reconciliation D3 — the two admin compromise sites stay dual-mode and keep `bindOAuthParams`) is otherwise unchanged; `server_mfa.go` additionally gains the `params`-rejection check (3.2).
- Step 3 (sweep) additionally migrates `parThenLogin` and `TestPAR_HappyPath_JSON`, adds the F1/F3 negative rows, and the PAR-claims positive (2.3).
- Step 5 (contracts) additionally documents: JSON-string form encoding for `authorization_details`/`claims` on `/par` (openapi schema description), `params` JSON-only + rejection on `/auth/mfa` (openapi + `docs/error-codes.md` note).
- §4 audit: the post-change grep gains `/par`-specific coverage — after the change, no `test/` file may POST JSON to `/par` (migrated inventory: `handle_par_test.go` only); `grep -rn '"application/json"' test/ | grep -E '/(token|introspect|revoke|par|device|auth/mfa|backchannel)'` must return only `/auth/login` posts.

## 6. Rejected alternatives

| Alternative | Rejected because |
|---|---|
| F1: fail-loud-only on form `authorization_details`/`claims` (400 `invalid_request`) | Makes RAR-over-PAR non-compliant with RFC 9396 §3 on the RFC 9126 §2.1 form surface; converts the mandated capability test into a permanent negative; deletes shipped, tested behavior |
| F1: silent drop preserved + document | The exact defect the reviewer flagged; the mandated test cannot pass and no remediation path exists; violates "no silent drop of client intent" |
| F1: proprietary map-style or bracket encoding (`details[0].type=…`) | No RFC anchor, no client ecosystem, unbounded shape grammar, reimplements JSON badly |
| F3: document-only (silent drop + note) | Non-deterministic per-provider outcome (empty-params success for challenge-state providers); a caller's factor material vanishes with no wire signal |
| F3: decoder-level map rejection | Breaks the non-credential byte-identical boundary: form requests carrying `config`/`attributes` at admin/selfservice/adminuser sites would start 400ing |
| F3: proprietary map form encoding (`params[foo]=bar`) | Same RFC-anchor objection as F1's bracket encoding |
