# Requirements Spec: B4-4 — Enforce Content-Type form-urlencoded on credential endpoints (billing-module run, Rev 2)

- Direction: "Enforce Content-Type form-urlencoded on credential endpoints (B4-4)",
  entry 2 of `docs/architect-analysis/auto/analyses/cmd-snaplink-billing-a1788a26.json`
- Direction scores: value 8 / risk_reduction 8 / effort 3 / confidence 10
- Module label: `cmd/snaplink-billing` (analysis-file label; the module is a
  **consumer** of the credential surface — its audit/quota/retention relays mint
  client-credentials tokens, `relay.go:28-74`, `quota_relay.go:347,427`, and
  contain no credential-server code). Owning layers: `protocols/oauth/oauthwire`
  (binder), `protocols/oauth` (handlers), `interfaces/sso` (server bind sites),
  `config` (switch), `test/` + `cmd/snaplink-billing/*_test.go` (pins).
- Status: requirements, re-verified against the working tree (HEAD `18530d0f`).
- Supersedes the pre-implementation spec
  `docs/architect-analysis/cmd-snaplink-billing-b4-4-credential-form-only-requirements.md`
  (Rev 1, written against a tree where the mechanism was unlanded). Prior art:
  the accepted sibling revisions
  `docs/architect-analysis/cmd-snaplink-audit-provisioner-b4-4-credential-form-only-requirements.md`
  (Rev 2/3, opt-in default-off, four-site scope) and the partial implementation
  left by the timed-out implement stage of run
  `enforce-application-x-www-form-urlencoded-on-the-0a23f017`.

## 0. Executive summary

The direction's core defect — `oauthwire.BindParams` defaulting missing/any
Content-Type to JSON on credential endpoints — is **already fixed in the tree**
by the partial implementation of the prior run: a strict binder
(`BindParamsFormOnly`), a config gate (`server.require_form_content_type` /
`sso.WithCredentialFormOnly`, opt-in), wiring at all four acceptance endpoints,
public-contract docs, and 27 passing tests. This spec's delta:

1. **One documented deviation to ratify**: the acceptance says "400
   `invalid_request`"; the landed contract answers **415** with the identical
   plain `{"error":"invalid_request"}` envelope (pinned in
   `docs/error-codes.md:332-338`, `docs/config-reference.md:42`, OpenAPI, and
   every strict-mode test). Oracle-safety properties are unaffected (§2.3).
2. **The billing-consumer pin (this module's distinctive deliverable) is the
   remaining gap**: `cmd/snaplink-billing/quota_relay_test.go` asserts the
   minted form **body** but never the `Content-Type` header, and no test drives
   the billing identities' real mints against a strict-mode server
   (§5 R7). Everything else in the acceptance is already implemented and
   tested (§4).

## 1. Evidence verification

Every citation in the direction was re-checked against the repository.
Verdicts:

| Direction citation | Measured reality | Verdict |
|---|---|---|
| `protocols/oauth/oauthwire/bind.go:28-49` — `BindParams` accepts form but defaults ANY other/missing Content-Type to JSON | `func BindParams` at :28; switch on `normalizedMediaType(r)` :37; `case "application/x-www-form-urlencoded"` :38 → `bindForm`; `default:` :41-47 → `decodeSingleJSON` for `application/json`, missing CT, and "anything unexpected" (:43-44 comment). Doc :26-27: "Empty body + no Content-Type is treated as JSON". The default branch is **preserved** for non-credential consumers; the strict sibling `BindParamsFormOnly` (`bind_strict.go`) is a separate function, never a flag inside `BindParams` | Confirmed exact — the seam the direction describes still exists in this exact shape; strict enforcement now lives beside it |
| `protocols/oauth/handle_introspect.go:120, handle_par.go:66, handle_ciba.go:87` — `BindParams` call sites | `handle_introspect.go` — the bind now goes through `bindCredentialRequest` (:90-106), invoked at **:154** (direction's :120 is now the `introspectRequest` struct boundary before the `HandleIntrospect` docstring; 34-line drift). `handle_par.go` — `bindCredentialRequest` at **:73** (:66 is now the PAR-not-configured 501 branch; `TokenNoStoreHeaders` sits at :55; 7-line drift). `handle_ciba.go:87` — `BindParams(ctx, &req)` at **:87 exact**, still dual-mode (CIBA is out of this direction's four-endpoint acceptance, §3). Both dispatchers: strict `BindParamsFormOnly` when `d.RequireFormContentType()`, else byte-identical `BindParams`; `errors.Is(err, ErrFormOnly)` → 415 plain `core.ErrorBody(core.ErrInvalidRequest)` **before the body is read** | Confirmed (two 7-34-line drifts; CIBA site exact) |
| `shared/security/client_secret.go:17-31` — constant-time compare already present | `CompareClientSecret` at `client_secret.go:19`: bcrypt via `bcrypt.CompareHashAndPassword` for `$2`-prefixed stores, else `ConstantTimeStringEq` (`constant_time.go:5`, crypto/subtle wrapper). Single compare seam used by `/token` client auth and the RFC 7592 registration-token gate; behavioral coverage `client_secret_test.go` is timing-independent | Confirmed exact — no work (the B4-4 "rest already exists" clause) |
| `interfaces/sso/server_token.go:199-204` — existing `invalid_scope`/oracle-safe body discipline | :199-204 now sits inside the `rejectUnregisteredScopes` seam comment block (the scope-registry dispatch): "plain `invalid_scope` body (core.ErrorBody — never errorBody, whose trace_id would drift the byte-compat baseline)... one deterministic shape, no registry-state oracle". The same plain-envelope discipline is what the strict-mode 415 reuses (`server_jar.go:307-333`) | Confirmed — pattern relocated; the discipline it cites is the one the 415 path implements |

Additional verified facts that shape the spec:

- **C1 — the strict mechanism is landed**: `protocols/oauth/oauthwire/bind_strict.go`
  defines `BindParamsFormOnly` + exported sentinel `ErrFormOnly` (contract
  points 1-5 in its doc: dispatch is a pure function of the normalized CT;
  `decodeSingleJSON` unreachable; `ParseForm` before `formIntoStruct`;
  `ErrFormOnly` only from the media-type branch, never the form path; empty
  form-CT body binds zero-struct → per-endpoint 400). Exported `oauthwire`
  aliases at `protocols/oauth/aliases.go:97-99`.
- **C2 — all four acceptance endpoints are wired**: `/token`
  `server_token.go:30` → `s.bindCredentialParams` (`server_jar.go:317-333`);
  `/token/introspect` `handle_introspect.go:154`; `/token/revoke`
  `handle_revoke.go:82`; `/par` `handle_par.go:73` — the latter three via
  `bindCredentialRequest`. `RequireFormContentType() bool` on
  `IntrospectDeps`/`PARDeps`/`RevokeDeps`; `*sso.Server` implements it
  (`accessors_handlers.go:407-410`).
- **C3 — config + docs landed**: `ServerConfig.RequireFormContentType *bool`
  (`yaml:"require_form_content_type"`, `config/config_server.go:61-72`),
  append-only-when-set (`credentialFormOnlyOptions`, `config/config_server.go:219-225`);
  `WithCredentialFormOnly` (`options.go:107-113`); seed `credentialFormOnly =
  false` at `sso.go:76` ("explicit seed guards a future default flip").
  Documented at `docs/error-codes.md:332-338` (415, four endpoints, fires
  before body read + client auth), `docs/config-reference.md:42`,
  `CHANGELOG.md:81`, and OpenAPI (all four paths carry "this endpoint accepts
  ONLY application/x-www-form-urlencoded" + the 415 note: `/token` ~:1064,
  `/token/introspect` ~:1275, `/token/revoke` ~:1376, `/par` ~:1520).
- **C4 — test suite landed and green** (verified by running them, §6):
  `protocols/oauth/oauthwire/bind_strict_test.go` (8 tests: CT matrix,
  charset-param binds, malformed `%ZZ` is ParseForm-not-ErrFormOnly, body not
  read on 415, bare-sentinel `errors.Is`); `test/credential_content_type_test.go`
  (19 tests: exact 415 bytes, no-store on both headers, body-independence,
  Basic/DPoP independence, no-mint assertions, missing-CT incl. **empty body**,
  text/plain + multipart rows on all four endpoints, form byte-identical happy
  paths, malformed percent-encoding → 400, unauthenticated form → 401
  `invalid_client`, Basic-over-body precedence, options append-only-when-set);
  `test/credential_sdk_form_test.go` + `test/audit_provisioner_form_e2e_test.go`
  + `test/deploy_form_only_sweep_test.go` (single flip point in the deploy
  tree). 20 of 21 `test/` B4-4 tests pass; the one red test,
  `TestSdkForm_PARClaimsThreaded`, is the **documented deliberate-red
  merge-interlock** for the sibling RFC 9396 §3 decoder (`credential_sdk_form_test.go:14-17`:
  "must never be skipped — CI cannot go green before the sibling change
  merges") — out of this direction's scope.
- **C5 — billing-consumer pin missing (the remaining gap)**: the billing
  mints all speak the mandated wire (`infrastructure/auditgovernance/oauth_token_source.go:200-210`
  form body + `Content-Type: application/x-www-form-urlencoded` :209;
  `platform_token.go:151-162` :162), and the provisioner sibling has an e2e pin
  (`test/audit_provisioner_form_e2e_test.go`), but: (a)
  `cmd/snaplink-billing/quota_relay_test.go` `assertQuotaTokenRequest` (:149)
  / `assertRetentionTokenRequest` (:94) assert `PostForm` only — the
  `Content-Type` header is never asserted; (b) no test drives the billing
  identities (`snaplink-relay` audit relay via `NewOAuthTokenSource`
  `relay.go:45-52`; quota relay `NewOAuthTokenSource` `quota_relay.go:427` +
  retention `NewPlatformTokenSource` `quota_relay.go:347`) against a
  strict-mode server. The billing `/readyz` depends on these mints
  (`app.go:100,103`), so a strict-mode break would surface as 503 — the pin
  is the module's contribution.
- **C6 — budgets**: `cmd/snaplink-billing` has exactly 10 non-test files
  (fan-out ceiling) — R7 is test-only. `quota_relay.go` is 485 lines; no
  production edits. `interfaces/sso` is at its 60-file ceiling — no new files.
  `test/` additions are unconstrained (test files do not count toward
  interface ceilings).

## 2. Drift reports (code/doc vs. direction acceptance)

### 2.1 Status code: 415 vs the acceptance's literal "400"

The acceptance says "requests with text/plain or an unknown media type return
400 invalid_request". The landed contract returns **415 Unsupported Media
Type** with the identical plain `{"error":"invalid_request"}` envelope —
deliberate (sibling design D-1 resolution, accepted through design_gate;
adversarial review "status-code split ... ADDRESSED") and now documented in
`docs/error-codes.md:332-338`, `docs/config-reference.md:42`, OpenAPI, and 27
tests. The acceptance's operative properties — identical envelope, no
parser-state oracle, byte-identical across endpoints and causes — hold
unchanged. **Pin: 415**; do not re-churn the landed contract to 400. The
spec's testable acceptance (§7) states the pinned status and notes the
deviation.

### 2.2 Missing Content-Type with an empty body

Acceptance: "missing Content-Type with an empty body keeps current
compatibility (or is explicitly rejected per contract)". Both branches are
now pinned:

- Strict mode ON: missing CT (any body, incl. empty) → 415 before the body is
  read — the "explicitly rejected per contract" branch
  (`TestStrictToken_MissingCTRejected` asserts both a JSON body and an **empty
  body** row, plus no-mint).
- Mode OFF (default): `BindParams` default branch → `decodeSingleJSON` on the
  empty body → `io.EOF` → 400 — byte-identical to pre-change behavior
  ("keeps current compatibility"; preserved by the REGRESSION BOUNDARY
  comment at `bind.go:44-47`).

### 2.3 Oracle-safety chain (unchanged by the landed contract)

415 is reachable only via the media-type class, before the body is read and
before client authentication (`server_jar.go:324-331`,
`handle_introspect.go:98-104`); the envelope is the plain `core.ErrorBody`
(no `trace_id`, unlike `errorBody`); malformed percent-encoding under a form
CT stays on the 400 bind path (never `ErrFormOnly`); no new `Err*` codes;
nothing is minted, revoked, introspected, or stored on the 415 rows
(mint-counting spy in `test/credential_content_type_test.go`). The
`WWW-Authenticate` bearer challenges (RFC 6750) on the **bearer** surface —
`/token/revoke-all` (`handle_revoke.go:257-269`), mesh/resource-server
(`mesh_authz.go`) — are untouched; the four credential endpoints' client-auth
failures remain plain `401 invalid_client` per RFC 6749 §5.2, and strict mode
never converts a bindable (form) request away from that 401
(`TestStrictIntrospect_UnauthenticatedFormStill401`).

## 3. Goal and user outcome

RFC 6749 §3.2 / RFC 7662 §2.1 / RFC 7009 §2.1 mandate
`application/x-www-form-urlencoded` on the token, introspection, revocation,
and PAR endpoints. The goal (unchanged from the direction): enforce that
mandate on `/token`, `/token/introspect`, `/token/revoke`, `/par` with a
deterministic, oracle-safe rejection of every other media type, while keeping
the byte-compat baseline for the default build and proving that Snaplink's
own machine consumers — in particular `cmd/snaplink-billing`'s three relay
mints — are unaffected. Completion marker for THIS run: the strict-mode
behavior and its 27 tests stay green, and the billing-consumer pin (R7) lands:
billing-identity mints return 200 against a strict server with zero billing
production-code changes, and the relay tests assert the exact `Content-Type`
header they emit.

## 4. Product boundary

- In scope (acceptance surface): the four credential endpoints `/token`,
  `/token/introspect`, `/token/revoke`, `/par`; the strict binder and its
  dispatch; the config switch; the billing-consumer regression pin.
- Explicit non-goals (do not implement):
  - No flip of `/backchannel-authentication` (CIBA, `handle_ciba.go:87`),
    `/device/code`, `/device/verify`, `/auth/mfa` — the direction's acceptance
    names four endpoints; the accepted sibling Rev-3 pinned the same four-site
    scope. The CIBA seam remains dual-mode by design; extend only via a
    follow-up direction that names it.
  - No change to non-credential `BindParams` consumers (commerce/admin/
    selfservice, incl. `payment_ingest.go:99` which REQUIRES JSON), `/auth/login`
    (JSON-only), `/register` (RFC 7591 §3.1 JSON), the two admin-API bind sites.
  - No default flip: `WithCredentialFormOnly` seeds `false`; unset config =
    byte-identical legacy build (accepted Rev-3 pin; the `sso.go:76` seed
    comment is the guard for any future flip, which is NOT this direction).
  - No new `Err*`, no new routes, no no-store/ordering changes, no
    production-code change in `cmd/snaplink-billing` (C5/C6).
  - Not in scope: sibling items B4-1 (issuer allowlist), B4-2 (scope
    registry), B4-5 (auditoutbox/usage-ledger feed) from the same analysis
    file; the sibling RFC 9396 §3 decoder interlock
    (`TestSdkForm_PARClaimsThreaded` stays red until that sibling lands).

## 5. Requirements

### R1 — Strict binder semantics (LANDED, pin as-is)

`BindParamsFormOnly` accepts only `application/x-www-form-urlencoded`
(parameter-stripped, lowercased, `; charset=UTF-8` tolerated), returns
`ErrFormOnly` for any other/missing CT before reading the body, and shares
`normalizedMediaType`/`bindForm` with `BindParams` (one definition of form
semantics). `ErrFormOnly` is never wrapped, never produced by the form path,
never written to the wire. `bind_strict_test.go` pins all five contract
points. No rework.

### R2 — Four-endpoint wiring (LANDED, pin as-is)

`/token`, `/token/introspect`, `/token/revoke`, `/par` dispatch through the
flag-aware binders (`server_jar.go:317-333`, `handle_introspect.go:90-106`)
keyed on `RequireFormContentType()`. Ordering unchanged: `TokenNoStoreHeaders`
before parse; parse before client auth (Basic-over-body precedence intact).
Mode OFF is byte-identical (`BindCredentialParams(ctx, v, false)` ≡
`BindParams`). No rework.

### R3 — 415 envelope, oracle-safe (LANDED, pin as-is; ratifies §2.1)

Any non-form CT on the four endpoints → `415` + plain
`{"error":"invalid_request"}` (core.ErrorBody, no trace_id), byte-identical
across the four endpoints and across causes, before body read and before
client auth; no mint/revoke/introspect/store side effects; no-store on every
response. Test pins: `TestStrictAllEndpoints_ContentTypeCombinations`
(12 rows), `TestStrictToken_JSONRejected`, `_MissingCTRejected`,
`_BasicAuthStill415`, `_DPoPProofStill415`, `_BodyIndependent415`.

### R4 — Missing Content-Type (LANDED, pin as-is; §2.2)

Strict: 415 for missing CT with JSON body and with empty body. Default:
legacy byte-identical behavior. Test pin: `TestStrictToken_MissingCTRejected`.

### R5 — no-store and auth-failure behavior retained (LANDED, pin as-is)

Every strict-mode response carries `Cache-Control: no-store` + `Pragma:
no-cache` (asserted in `assert415`, `test/credential_content_type_test.go:156-159`);
form-encoded requests still reach the `401 invalid_client` gate
(`TestStrictIntrospect_UnauthenticatedFormStill401`,
`TestStrictToken_BasicAuthPrecedenceForm`); bearer challenges on the bearer
surface untouched (§2.3).

### R6 — Config switch and contract docs (LANDED, pin as-is)

`server.require_form_content_type` (nil/false = legacy; true = strict),
`WithCredentialFormOnly`, boot-time only, rollback by key removal, single
flip point in `ops/deploy/compose/config.yaml` (pinned by
`test/deploy_form_only_sweep_test.go`). Docs already landed (§1 C3). No
further doc work except the R7 test deliverable's own comments.

### R7 — Billing-consumer pin (REMAINING WORK; this module's deliverable)

The acceptance's "form-urlencoded requests still succeed" clause must be
proven for the module's own mints, which today nothing does:

- R7.1 — `cmd/snaplink-billing/quota_relay_test.go`: extend
  `assertQuotaTokenRequest` (:149) and `assertRetentionTokenRequest` (:94) to
  also assert `request.Header.Get("Content-Type") ==
  "application/x-www-form-urlencoded"` (the minted body is already asserted).
  Test-only; the module's 10-file ceiling and `quota_relay.go` (485 lines)
  are untouched.
- R7.2 — new `test/billing_form_e2e_test.go` (package `ssotest`, mirroring
  `test/audit_provisioner_form_e2e_test.go`): against a strict-mode server
  (`sso.WithCredentialFormOnly(true)`), run the REAL
  `auditgovernance.NewOAuthTokenSource` and `NewPlatformTokenSource`
  configured exactly as `cmd/snaplink-billing` wires them (`relay.go:45-52`
  audit identity; `quota_relay.go:427` quota identity; `quota_relay.go:347`
  retention identity — client/scope/resource values taken from the billing
  module's own test fixtures, `quota_relay_test.go` `billing-quota-relay` /
  `billing-retention-relay` + `sso-quota-api`), and assert each mint returns
  200 with a non-empty Bearer `access_token` — proving the strict flip is a
  no-op for billing with **zero billing production-code changes**. Assert
  also that a deliberately JSON-shaped `/token` request against the same
  server 415s (control arm, so the test cannot pass vacuously against a
  dual-mode server).

### R8 — Regression bound (LANDED, pin as-is)

Existing tests run unmodified: `protocols/oauth/oauthwire` (8 strict tests +
legacy `TestBindParamsJSONDefault`/`FuzzBindParams` on the preserved dual-mode
binder), `cmd/snaplink-billing` (green), the `TestFormEncoded_*` families
(mode-off byte-compat), `TestStrict*` (19), SDK form tests, provisioner e2e,
deploy sweep. `TestSdkForm_PARClaimsThreaded` stays red (documented sibling
interlock, §4) and must never be skipped.

## 6. Engineering-gate constraints (verified by running the gates at HEAD `18530d0f`)

| Gate | Result | Note |
|---|---|---|
| `go build ./... && go vet ./...` | PASS | — |
| `go test -run 'TestMaintainability_|TestArchitecture_' .` | 3 pre-existing failures, unrelated to this direction | `TestArchitecture_DirectoryDepth` (1103 dirs > depth 3, all under `docs/architect-analysis/auto/...` — the pipeline's own run artifacts); `TestArchitecture_DirectorySubdirFanout` (`docs/architect-analysis/auto/runs` 601 subdirs; repo root 24 > frozen ceiling 21); `TestMaintainability_FileSizeBudget` (`infrastructure/defaultimpl/ed25519_jwt_issuer.go` 539 lines). None touch this direction's files |
| `go test ./protocols/oauth/oauthwire/ -run FormOnly` | PASS | 8 strict-binder tests |
| `go test ./cmd/snaplink-billing/` | PASS | R7.1 extends this package's tests only |
| `go test ./test/ -run 'TestStrict|TestAuditProvisioner|TestSdkForm|TestDeployFormOnly'` | 20/21 PASS; 1 documented-red | `TestSdkForm_PARClaimsThreaded` — sibling decoder interlock (out of scope) |

Budgets (no new non-test files anywhere): `cmd/snaplink-billing` 10-file
ceiling (test-only changes), `quota_relay.go` 485 lines (unmodified),
`interfaces/sso` 60-file ceiling (no changes needed), `oauthwire` under all
limits (no changes needed). New tests only: assertions in
`cmd/snaplink-billing/quota_relay_test.go` and one new file in `test/`.

## 7. Testable acceptance (Given/When/Then — preserves the supplied checks verbatim, pinned to the landed 415 contract)

T-8(c/d) — form-urlencoded-only enforcement on the four endpoints:

1. Given `application/x-www-form-urlencoded` bodies with valid credentials,
   when posted to `/token` (client_credentials + authcode/refresh),
   `/token/introspect`, `/token/revoke`, `/par`, then each succeeds exactly as
   in default mode (200 / `{"active":true}` / 200 / `urn:ietf:params:oauth:grant_type:par_1`)
   — pinned by `TestStrictToken_FormByteIdentical`,
   `TestStrictIntrospect_FormByteIdentical`, `TestStrictRevoke_FormByteIdentical`,
   `TestStrictPAR_FormByteIdentical`.
2. Given `text/plain` and an unknown media type (e.g. `multipart/form-data`,
   `application/octet-stream`) bodies, when posted to each of the four
   endpoints, then **415** (deviation from the literal "400" in the supplied
   check — §2.1) with the byte-identical plain `{"error":"invalid_request"}`
   envelope in every row, before the body is read — no token minted, no PAR
   stored, no revocation/introspection performed — and the envelope is
   independent of body content, Basic/DPoP credentials, and prior
   authentication state (no parser-state oracle) — pinned by
   `TestStrictAllEndpoints_ContentTypeCombinations`,
   `TestStrictToken_JSONRejected(_CharsetVariant)`, `_BasicAuthStill415`,
   `_DPoPProofStill415`, `_BodyIndependent415`, and the mint-counting spy.
3. Given a request with missing Content-Type, when posted to the four
   endpoints with a JSON body AND with an empty body, then under strict mode
   415 `invalid_request` (the "explicitly rejected per contract" branch) and
   under default mode byte-identical legacy behavior (the "keeps current
   compatibility" branch) — pinned by `TestStrictToken_MissingCTRejected` and
   the unchanged `TestFormEncoded_*` families.
4. Given any strict-mode response on the four endpoints (success AND error),
   then `Cache-Control: no-store` + `Pragma: no-cache` are present; given an
   unauthenticated form-encoded request, then the unchanged `401
   invalid_client` (RFC 6749 §5.2 plain envelope; bearer challenges on the
   bearer surface unchanged) — pinned by `assert415` and
   `TestStrictIntrospect_UnauthenticatedFormStill401`.
5. Given a strict-mode server and the real billing relay mints
   (`NewOAuthTokenSource` as wired at `relay.go:45-52` and `quota_relay.go:427`,
   `NewPlatformTokenSource` as wired at `quota_relay.go:347`), when the
   billing audit/quota/retention identities mint, then each returns 200 with a
   non-empty Bearer token and **zero billing code changes** (NEW — R7.2);
   given the same mints' HTTP requests, then the `Content-Type` header is
   exactly `application/x-www-form-urlencoded` (NEW — R7.1).
6. Given the full existing B4-4 suite (unit + server + SDK + provisioner +
   deploy sweep), then green; `TestSdkForm_PARClaimsThreaded` remains the
   single documented-red interlock for the sibling decoder and is never
   skipped.

## 8. Files

### Create
- `test/billing_form_e2e_test.go` (R7.2; package `ssotest`; mirrors
  `test/audit_provisioner_form_e2e_test.go`).

### Modify (test-only)
- `cmd/snaplink-billing/quota_relay_test.go` — add the `Content-Type` header
  assertions to `assertQuotaTokenRequest` / `assertRetentionTokenRequest`
  (R7.1). File stays under 500 lines.

### Do not modify
- `protocols/oauth/oauthwire/bind.go`, `bind_strict.go` — landed contract (§5
  R1); the REGRESSION BOUNDARY comment at `bind.go:44-47` is load-bearing.
- `interfaces/sso/server_token.go`, `server_jar.go`, `accessors_handlers.go`,
  `options.go`, `sso.go` — landed wiring (§5 R2/R3).
- `protocols/oauth/handle_introspect.go`, `handle_revoke.go`, `handle_par.go`,
  `handle_ciba.go` — CIBA stays dual-mode (§4).
- `config/config_server.go`, `docs/error-codes.md`, `docs/config-reference.md`,
  `docs/openapi.yaml`, `CHANGELOG.md`, `ops/deploy/**` — landed (§5 R6).
- `cmd/snaplink-billing/*.go` production files — none change.

## 9. Dependencies and compatibility

- No new dependencies; no wire-format change to the default build
  (byte-identical legacy mode); strict mode is opt-in per deployment.
- Compatibility: JSON/missing-CT callers on the four endpoints break ONLY
  under the explicit opt-in — the documented migration contract
  (`docs/error-codes.md:332-338`).
- Interlock: the sibling RFC 9396 §3 form-decoder change owns
  `TestSdkForm_PARClaimsThreaded`; this direction neither fixes nor skips it.

## 10. Verification plan

1. `go build ./... && go vet ./...` (green).
2. `go test ./protocols/oauth/oauthwire/ -run FormOnly -count=1` (green).
3. `go test ./cmd/snaplink-billing/ -count=1` (green, incl. new R7.1 asserts).
4. `go test ./test/ -run 'TestStrict|TestAuditProvisioner|TestSdkForm|TestDeployFormOnly|TestBillingFormE2E' -count=1`
   — 20 existing green + the new R7.2 test green;
   `TestSdkForm_PARClaimsThreaded` remains the sole documented-red interlock.
5. `go test -run 'TestMaintainability_|TestArchitecture_' .` — re-run and
   report the same three pre-existing failures separately (never "fixed"
   here).
6. `make ci` at handoff; report any pre-existing failure separately.
