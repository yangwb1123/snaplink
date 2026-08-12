# Requirements Spec: Form-urlencoded token-family emission in the generated TS/Python SDKs

Module: `cmd/gensdk` (SDK-side slice of B4-4)
Source direction: `docs/architect-analysis/auto/analyses/cmd-gensdk-4ffda121.json` (entry 1, "Form-urlencoded token-family emission in the generated TS/Python SDKs (B4-4)")
Approved upstream spec: `docs/architect-analysis/cmd-gensdk-tokenfamily-form-spec.md` REQ-2.1-2.6 (unimplemented)
Related module: `cmd-sso-ctl-entitiescmd-b4-4-credential-form-only-requirements.md` (server-side form-only binding; owns acceptance T-9(d)/(e) below)

## 1. Problem

The generator emits `Content-Type: application/json` with `JSON.stringify` /
`json.dumps` bodies for every body operation, including the four RFC-mandated
form-urlencoded OAuth credential endpoints. The committed SDKs therefore send
JSON to `/token`, `/token/introspect`, `/token/revoke`, and `/par` today, with
zero form-urlencoded bodies in either client. When B4-4 server-side
form-only enforcement ships, those committed clients break with
`400 invalid_request`. This module makes the generator and the committed
clients emit form-urlencoded bodies for exactly those four operations first.

## 2. Evidence verification

Every citation in the direction was checked against the tree. All verified;
two claims corrected (C1, C2).

| # | Cited evidence | Verification result |
|---|---|---|
| E1 | `cmd/gensdk/gen_ts_runtime.go:158` — `headers["Content-Type"] = "application/json"` for any body | Confirmed, exact. `request()`: `if (authenticatedBody !== undefined) { headers["Content-Type"] = "application/json"; init.body = JSON.stringify(authenticatedBody); }` (gen_ts_runtime.go:158-160). The `requestOptions` interface (:35-41) has `query/body/auth/clientAuth` only — no `form` flag. |
| E2 | `cmd/gensdk/gen_py.go:100-103` — `pyClientHeader` `_request` JSON-only body path | Confirmed (gen_py.go:102-104): `headers["Content-Type"] = "application/json"; data = json.dumps(body).encode("utf-8")` for any non-nil body. `_request` has `method/path/query/body/auth` only — no `form` param. |
| E3 | `cmd/gensdk/gen_ts.go:101` `tsUsesClientAuth` — four-op predicate precedent | Confirmed: func at gen_ts.go:99-109; the case list `"postToken", "postIntrospect", "postRevoke", "postPAR"` sits at :101. This is the precedent for a shared four-op predicate. |
| E4 | `cmd/gensdk/emit_test.go:159` `TestTSClientAuthenticationOperations` | Confirmed, exact. Table-driven over the same four ops (true) + `postLogin`/`postLogout` (false) — the natural extension point for a form-marker test. |
| E5 | `cmd/gensdk/emit_test.go:207` `TestGenerateTS_ConfidentialAuthAndStrictOptionalTransport` | Confirmed, exact. Asserts `{ body, clientAuth: true });` at :231 — must become `{ body, clientAuth: true, form: true }` for `postToken` in the fixture ops. |
| E6 | `protocols/oauth/oauthwire/bind.go:28` `BindParams` — JSON default; `BindFormParams` absent repo-wide | Confirmed. `BindParams` at bind.go:28 dispatches on Content-Type; only `application/x-www-form-urlencoded` takes the form path (:38-42, `r.ParseForm` + `formIntoStruct(r.PostForm, v)` — body-only, never query params); `default:` (:43-45) decodes single JSON for `application/json`, missing CT, and anything unexpected. `BindFormParams`: 0 matches repo-wide (verified). |
| E7 | `docs/openapi.yaml:1102/1280/1347/1473` — "form-urlencoded-only request bodies" | **C1 (correction).** Only `postToken` (openapi.yaml:1102) is form-only today. `postIntrospect` (:1280), `postRevoke` (:1347), `postPAR` (:1477) each declare BOTH `application/x-www-form-urlencoded` and `application/json`. The "form-only" framing holds for one of four; dropping the JSON variants is the B4-4 server module's R5.4, not this module's scope. This does not change the SDK work: the generator must emit form for all four regardless (the spec's `content` lists always include form, and `contentSchema` at cmd/gensdk/operations.go:192-201 prefers JSON first for schema resolution only — the generator has no content-type knowledge in its `Operation` model). |
| E8 | `docs/openapi.yaml:1063-1065` — stale "Form + JSON ... `oauth_bind.go`" text | Confirmed. The `/token` description says both content types "are accepted via the dispatcher in `oauth_bind.go`"; no `oauth_bind.go` file exists anywhere in the repo (find: 0 results). Text fix is REQ-6 below (carried from the approved spec REQ-2.6), valid only once server enforcement is live. |
| E9 | `docs/architect-analysis/cmd-gensdk-tokenfamily-form-spec.md` REQ-2.1-2.6 — approved, unimplemented | Confirmed. REQ-2.1 (`FormBody bool` on `Operation`, four-op predicate), REQ-2.2 (TS runtime `form` option), REQ-2.3 (Python runtime `form` param), REQ-2.4 (emit tests), REQ-2.5 (regeneration), REQ-2.6 (openapi.yaml text) all present. Implemented nowhere: `Operation` (cmd/gensdk/operations.go:58-70) has `HasBody` but no `FormBody`; neither runtime has a form path. |
| E10 | `docs/sdks/typescript/client.ts` + `docs/sdks/python/client.py` — 0 form-urlencoded bodies | Confirmed: 0 matches for `x-www-form-urlencoded` in both (client.ts is 3494 lines, client.py 2772). The four methods: client.ts:2903 `postToken` → `{ body, clientAuth: true }` (likewise postIntrospect :2908, postRevoke :2913, postPAR :2878); client.py:2280-2288 `post_token`/`post_introspect`/`post_revoke`/`post_par` → `body=body`, no form marker. |
| E11 | `ops/scripts/sdk_surface.py:146-151` — generate = `go run ./cmd/gensdk --lang=all` | Confirmed (sdk_surface.py:148). Subcommands: `check` (validate registry vs docs/openapi.yaml + capabilities, :114-125) and `generate` (:146-151). `cmd/gensdk/main.go` `--lang=ts|py|all` (:21-23, :86). |
| E12 | `test/oauth_bind_test.go:272` `TestFormEncoded_JSONStillWorks` | Confirmed, exact. Currently asserts `application/json` on `/token` → `200 OK` ("json fallback failed"). Inversion is acceptance T-9(d), owned by the B4-4 server module. |
| E13 | Basic-stripping mechanism for clientAuth+form (acceptance T-9(c)) | Confirmed: TS `withClientAuthentication` (gen_ts_runtime.go:183) strips `client_id`/`client_secret` into `Authorization: Basic` and returns the stripped body BEFORE the encoding branch — so form encoding of the stripped body is an ordering-preserving change. Python `_request` has no Basic/clientAuth support today (bearer only) — the Python side emits `form=True` with the body unchanged. |
| E14 | No-store headers set before binding (acceptance T-9(e)) | Confirmed at all four sites: `tokenNoStoreHeaders(ctx)` before `bindOAuthParams` (interfaces/sso/server_token.go:21-29); `middleware.TokenNoStoreHeaders` before binding at protocols/oauth/handle_introspect.go:112, handle_revoke.go:68, handle_par.go:55. The mechanism for T-9(e) already exists; the 400 rejection inherits it. |
| E15 | Surface membership | Confirmed: `postToken`, `postIntrospect`, `postRevoke`, `postPAR` all in `ops/build/sdk-surface.json` (316 operations total), so the generated clients carry all four. `postDeviceCode`, `postDeviceVerify`, `postMFAComplete` are also in the surface — out of scope (REQ-1 keeps them JSON). |

## 3. Requirements (module scope: `cmd/gensdk`)

### REQ-1 — `FormBody` flag on `Operation`, four-op predicate

- REQ-1.1 Add `FormBody bool` to `Operation` (`cmd/gensdk/operations.go:58`),
  populated by a predicate `usesFormBody(operationID string) bool` covering
  exactly `postToken`, `postIntrospect`, `postRevoke`, `postPAR` — mirroring
  the `tsUsesClientAuth` precedent (gen_ts.go:99-109) and shared by both
  emitters (single source of truth; no per-language duplication).
- REQ-1.2 Do NOT derive `FormBody` from the spec's content types: the
  generator's model ignores content types today (`contentSchema` is
  schema-only, operations.go:192-201), and spec-driven derivation would pull
  `postDeviceCode`/`postDeviceVerify`/`postMFAComplete` into scope (their
  handlers still accept JSON). Hardcode the four ops; extend deliberately
  later.
- REQ-1.3 Negative predicate guarantee: `postLogin`, `postLogout`,
  `postRevokeAll`, all admin/SCIM/SSF/federation ops return `FormBody=false`
  (JSON unchanged).

### REQ-2 — TS runtime form path (`cmd/gensdk/gen_ts_runtime.go`)

- REQ-2.1 `requestOptions` gains `form?: boolean` (next to `clientAuth`, :35-41).
- REQ-2.2 In `request()`, when `form` is set: `headers["Content-Type"] =
  "application/x-www-form-urlencoded"` and the body is built with the
  URLSearchParams repeated-key style already used for queries (:142-151) —
  arrays (`resource`, `audience`) become repeated keys, matching the server's
  multi-value form parsing (`formIntoStruct` on `r.PostForm`, bind.go:42).
- REQ-2.3 Ordering with clientAuth (acceptance T-9(c)): `withClientAuthentication`
  runs first (Basic header + `client_id`/`client_secret` stripping, :183),
  then the STRIPPED body is form-encoded. The current code already computes
  `authenticatedBody` at :154, before the encoding branch — the form branch
  encodes `authenticatedBody`, never `opts.body`.
- REQ-2.4 Non-form ops keep the JSON branch byte-for-byte.

### REQ-3 — Python runtime form path (`cmd/gensdk/gen_py.go`)

- REQ-3.1 `_request` gains `form: bool = False` (after `auth`, in
  `pyClientHeader`). When true: `Content-Type: application/x-www-form-urlencoded`
  and `data = urllib.parse.urlencode(body).encode("utf-8")` — a dict of
  lists yields repeated keys, matching the server's multi-value parsing.
- REQ-3.2 `pyEmitMethod` emits `, form=True` in the `_request(...)` call for
  the four `FormBody` ops; every other method's call is unchanged.

### REQ-4 — Emit tests (`cmd/gensdk/emit_test.go`)

- REQ-4.1 Extend `TestTSClientAuthenticationOperations` (:159) or add a
  sibling `TestTSFormBodyOperations`: table over `usesFormBody` with the four
  ops true and `postLogin`, `postLogout`, `postRevokeAll`, one admin op, one
  SCIM op false. Mirror for the Python emitter (assert `form=True` appears in
  the emitted `_request(...)` call for the four ops and is absent elsewhere).
- REQ-4.2 Update `TestGenerateTS_ConfidentialAuthAndStrictOptionalTransport`
  (:207): the `postToken` fixture op now yields `{ body, clientAuth: true,
  form: true }` (:231 currently `{ body, clientAuth: true }`); add a
  generated-output assertion that the form request body is
  `URLSearchParams`-encoded from the Basic-stripped body (no
  `client_id`/`client_secret` keys in the encoded output).

### REQ-5 — Regeneration and commit

- REQ-5.1 Run `python cli.py sdk-surface generate` (`go run ./cmd/gensdk
  --lang=all`); commit `docs/sdks/typescript/client.ts` and
  `docs/sdks/python/client.py` diffs showing the four methods sending
  `application/x-www-form-urlencoded` with urlencoded bodies and the JSON
  body path gone for them; every other method unchanged (0 unrelated diff
  hunks).
- REQ-5.2 `python cli.py sdk-surface check` stays green.

### REQ-6 — Spec text drift (carried from approved spec REQ-2.6)

- REQ-6.1 When server-side form-only enforcement is live (B4-4 module), rewrite
  `docs/openapi.yaml:1063-1065` in this same change: drop "Form + JSON — both
  ... accepted via the dispatcher in `oauth_bind.go`" (the file does not
  exist) and state form-urlencoded only. No schema changes: the four request
  bodies already declare form (E7).

## 4. Acceptance criteria (preserved from the direction, made testable)

**T-9(a)** — form markers in emit tests. `go test ./cmd/gensdk/ -run
'TestTSFormBodyOperations|TestTSClientAuthenticationOperations|TestGenerateTS_ConfidentialAuthAndStrictOptionalTransport' -v`
passes, and the committed emit tests assert: `postToken`/`postIntrospect`/
`postRevoke`/`postPAR` carry the form marker (TS emitted request options
contain `form: true`; Python emitted `_request(...)` calls contain
`form=True`), while `postLogin`/`postRevokeAll`/admin/SCIM ops keep JSON (no
form marker; `Content-Type: application/json` branch untouched).

**T-9(b)** — `python cli.py sdk-surface generate` then `python cli.py
sdk-surface check` both exit 0.

**T-9(c)** — committed diffs. `docs/sdks/typescript/client.ts` and
`docs/sdks/python/client.py` diffs show the four methods emitting
`application/x-www-form-urlencoded` with URLSearchParams-style (TS) /
`urlencode` (Python) repeated-key bodies. In the TS runtime, the emitted
`request()` encodes the `withClientAuthentication`-stripped body (Basic
header set before encoding; `client_id`/`client_secret` absent from the
encoded body). Testable via the REQ-4.2 generated-output assertions plus a
manual diff review of the two committed files (0 unrelated hunks).

**T-9(d)** — server inversion (owned by the B4-4 server module;
dependency-gated, see §6). `TestFormEncoded_JSONStillWorks`
(test/oauth_bind_test.go:272) inverted: `application/json` body and
missing-Content-Type body both return byte-identical `400 invalid_request`
(same status, same body bytes), form-urlencoded succeeds. Testable:
`go test ./test/ -run TestFormEncoded_ -v -count=1`.

**T-9(e)** — no-store on rejections (mechanism verified, E14; owned by the
B4-4 server module). The `400 invalid_request` rejection on all four
endpoints carries `Cache-Control: no-store` + `Pragma: no-cache` — asserted
in the rejection tests (headers are set before binding:
server_token.go:21-29, handle_introspect.go:112, handle_revoke.go:68,
handle_par.go:55). Testable: `go test ./test/ -run
'TestFormEncoded_|TestTokenNoStore' -v`.

## 5. Verification commands

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/gensdk/... -count=1
python cli.py sdk-surface generate && python cli.py sdk-surface check
go test ./... -race
go test ./test/ -run TestE2E -v
make ci
```

## 6. Dependencies and sequencing

- T-9(d)/(e) require the server-side form-only binding from
  `docs/architect-analysis/cmd-sso-ctl-entitiescmd-b4-4-credential-form-only-requirements.md`
  (R1, R5). This module is the prerequisite: committed clients must emit form
  BEFORE that enforcement ships. If the server module has not landed when
  this module is verified, (a)-(c) are complete and (d)/(e) fail-fast as
  expected; both must hold once the B4-4 change sequence is complete.
- REQ-6 (openapi.yaml text) is likewise sequenced after the server flip —
  claiming form-only in prose while the server still accepts JSON would be
  new drift.

## 7. Out of scope (explicit)

- Server-side binding changes (`BindFormParams`, handler bind-site switches,
  the 34 JSON call-site migrations in test/) — owned by the B4-4 server
  module; only the acceptance pins above are preserved here.
- `postDeviceCode`/`postDeviceVerify`/`postMFAComplete` emission and their
  JSON acceptance (same drift class; separate change).
- `postRevokeAll` (bearer JSON op) and all JSON-declared ops (`postLogin`,
  admin, SCIM, SSF, federation).
- Discovery truthiness sweep (B4-3) and any other direction from
  `cmd-gensdk-4ffda121.json`.

## 8. Risks and notes

- The TS `withClientAuthentication` ordering is the one behavioral subtlety:
  stripping must precede form encoding, or `client_id`/`client_secret` leak
  into the encoded body. REQ-4.2 pins it.
- Python has no confidential-client (Basic) path today; `form=True` ships
  with the body unchanged. Adding Python Basic auth is out of scope.
- The generator's spec input already declares form for all four ops (E7),
  so `sdk-surface check` cannot catch a missing form emission — the emit
  tests (REQ-4) are the gate, plus the committed-client diff review (T-9(c)).
