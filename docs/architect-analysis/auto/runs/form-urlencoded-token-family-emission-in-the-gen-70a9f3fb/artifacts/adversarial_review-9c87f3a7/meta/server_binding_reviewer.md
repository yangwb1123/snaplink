## Verification verdict: F-A confirmed real, proposed fix validated, all gates clear

Report written to `docs/architect-analysis/auto/runs/form-urlencoded-token-family-emission-in-the-gen-70a9f3fb/artifacts/server-side-fa-verification/server-side-fa-verification.md`.

### 1. Location + missing case — confirmed, **empirically reproduced**
- `formIntoStruct` at `protocols/oauth/oauthwire/bind.go:69-97`, `setFormField` at `:112-134`. The switch handles String/Bool/Int/Pointer-Int/`[]string` only; `json.RawMessage` (Slice of Uint8) falls through all cases.
- I reproduced through the **real path** (`BindParams → r.ParseForm → formIntoStruct → setFormField`): `authorization_details=%5B%7B...%7D%5D` and `claims={...}` bind **empty** while `resource` binds fine. Downstream, nil RAR = "absent" (`ValidateAuthorizationDetails` len-0 skip) and `mergeStoredPARRequest` (server_login_resolve.go:167/:182) skips empty fields — the drop is silent at **both** hops; PAR issues 201 with no RAR/claims.

### 2. Proposed addition — validated via scratch-implement + revert (tree restored)
- RawMessage case (`f.Type() == reflect.TypeOf(json.RawMessage(nil))`, `SetBytes(raw[0])`, error on `len(raw) != 1`): well-formed JSON strings bind **byte-verbatim** — repro flipped from FAIL to PASS.
- **Malformed RAR** → raw bytes preserved → `ValidateAuthorizationDetails` rejects → 400 `invalid_authorization_details` (RFC 9396 §6) — this is the *correct* code per the openapi contract; bind-time `json.Valid` would contradict it and diverge media types (rejected).
- **Malformed claims** → PAR carries raw payload (never stripped) → login `ValidateClaimsParameter` → 400 `invalid_request` — byte-parity with the JSON branch, which also defers claims validation to login.
- **Multi-value** → bind error → generic 400 `invalid_request` (handle_par.go:60-62), oracle-safe, no new `Err*`. The "400 invalid_request, oracle-safe" floor holds; the design's test must pin both codes.

### 3. Contract consistency
- openapi text verbatim at **:15045-15058** (the :15034-15037 citation is ~15 lines stale; file evolved). The fix closes documented-but-unimplemented drift.
- `BindParams`/JSON path untouched — pre-flip form fidelity becomes identical to the JSON branch; post-flip (B4-4 `BindFormParams`, four sites) works. Fix must land in the same dependency group, before the flip.

### 4. Full-bind-path test — feasible, harness exists
`postForm` (url.Values.Encode — Go-side analog of URLSearchParams/urlencode, wire-equivalence already established 3-way) → `ParseQuery` → `setFormField` → PARStore → login `consumePARRequest`/merge → token projection. `newPARHarnessWithAuthzDetailsAllowlist` returns the store — the test can assert byte-identical stored RAR/claims (direct no-silent-null proof) plus the access-token projection. Only new code: a small form-PAR variant of `parThenLogin`; unit subtests slot into `bindForm`/`bindTarget` (bind_extra_test.go).

### 5. Budgets/ceiling — all clear
`bind.go` 158→~184 (<500); `setFormField` cyclo 10→11 (measured, not exempt, no exemption added); `server_jar.go` ~430; `server_token.go` 495 (identifier swap only); test files exempt from filesize+complexity gates; `test/` has 0 non-test files (fan-out unaffected). **interfaces/sso: exactly 60 non-test files, untouched** — the fix lives in `protocols/oauth/oauthwire` + `test/`; B4-4 M1 edits existing files only. No new `Err*`, no exemption growth, no new imports.

Gates: `go build && go vet` green; binder/PAR/form tests green. Only the pre-existing failures remain (ed25519_jwt_issuer.go 539L, docs fanout, root subdirs, `decodeRefreshJSONCols` 16>15) — unchanged by this work. My scratch edits and repro test are fully reverted; the `auth_code_handler.go` dirt is a pre-existing unrelated change.
