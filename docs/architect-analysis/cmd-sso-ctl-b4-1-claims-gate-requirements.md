# Requirements Spec: make the B4-1 claims gate real — iss allowlist pin (Host-variance probe) and the tenant_id/roles blind spot in T-8a

- Direction: "Make the B4-1 claims gate real: pin iss against an operator allowlist (Host-variance probe) and close the tenant_id/roles blind spot in T-8a" (source: `docs/architect-analysis/auto/analyses/cmd-sso-ctl-7e52c2bb.json`, entry 2, the selected direction)
- Analysis module: `cmd/sso-ctl` (surface: `cmd/sso-ctl/apiclient/` — `check.go`, `token.go`, `sweep.go`, `check_test.go`). No other module, no root-module edits, no server-side edits.
- Status: requirements (evidence-verified against the worktree HEAD state `6cb50de3`)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `check.go:78-80` "opt-in expect flags" (`--expect-tenant-id`/`--expect-roles`) | Flags are at `check.go:77-78` (`expectTenantID := fs.String("expect-tenant-id", …)`, `expectRoles := fs.Bool("expect-roles", …)`), wired into the `checker` struct at 116-117, usage text at 168-169. Both opt-in; neither is asserted unless declared | Confirmed (line numbers shifted by 1-2, behavior exact) |
| `token.go:165-208` "iss==discovery; tenant_id/roles only when declared; 'cc-path mints never resolve Subject.Roles'" | `verifyClaims` is at `token.go:175-228`. The iss check is 187-188 (`iss != ck.doc.Issuer` — the discovery issuer is the ONLY oracle); the tenant_id block is 215-221 (`if ck.expectTenantID != ""`); the roles block is 225-228 with the exact diagnostic `"claims: roles absent — cc-path mints never resolve Subject.Roles; flag is a declaration, not a guess"` at 228. The unconditional/declared split is documented at 174-178 | Confirmed (cited range 165-208 covers the iss row; the declared-claims blocks end at 228). Strengthened: the cc-path roles impossibility is a *structural* guarantee — `HandleClientCredentialsGrant` (`internal/handler/tokengrant/token_client_credentials.go:63-71`) builds `&core.Subject{ID, Resources, ClientID, TenantID, TTL, ConfirmationJKT, ConfirmationX5TS256, ServingRegion}` with no `Roles` and no `Claims`. So `--expect-roles` on the cc path is a guaranteed-fail declaration: the flag is unusable, and a roles regression therefore passes the deploy-tree gate unless an operator declares the one flag that always fails |
| `server_discovery.go:251-258` "resolveIssuer falls back to the request base URL when unconfigured" | `resolveIssuer` is at `server_discovery.go:251-256`: `if s.issuer != "" && s.issuer != DefaultIssuer { return s.issuer }; return requestBaseURL(ctx.Request())`. `requestBaseURL` = `middleware.BaseURL` (`server_federation.go:40`; `interfaces/middleware/request_url.go`): `scheme://r.Host` with trusted-proxy X-Forwarded-* honoring | Confirmed (exact) |
| "discovery is derived from the same Host" (the lockstep blind spot) | `handleOIDCDiscovery` seeds `base := requestBaseURL(ctx.Request())` (`server_discovery_config.go:63-66`); `buildBaseMetadata` sets `Issuer: base` (line 144); the `WithIssuer` override applies only when `s.issuer` is set and non-sentinel (264-265). So when `s.issuer` is empty or the `DefaultIssuer` sentinel, the discovery issuer and `resolveIssuer` derive from the same request Host — a mint whose `iss` came from `resolveIssuer`/`requestBaseURL` would satisfy `iss == ck.doc.Issuer` | Confirmed, with a deployment nuance: `config/config_load.go:60,70-71` defaults the cmd `server.issuer` to `"sso-server"` (deliberately NOT the SDK sentinel, per the comment at 44-59), so a *stock* sso-server pins both discovery and minted iss to that literal. The Host-derived lockstep arises (a) at the SDK level (`WithIssuer` unset/sentinel — the `resolveIssuer` fallback is live), or (b) under the B4-1 regression where a mint sources its issuer from `resolveIssuer`/`requestBaseURL`. The current sweep cannot distinguish any of these states because its only oracle is the discovery issuer, which moves in lockstep. The direction's conclusion stands: the "never Host-derived" clause of B4-1 (`docs/campaigns/implementation-gate.md` row 1: "`iss` 配置化（allowlist，禁 Host 派生；resolveIssuer `server_discovery.go:251` + WithIssuer 覆盖）", acceptance T-8(a) claims `{iss/aud/scope/client_id/tenant_id/roles}`) is unverifiable today |
| Minted `iss` source (mechanism the probe must pin) | `buildAccessPayload(j.issuer, …)` (`ed25519_issue.go:43`); `j.issuer` is the issuer option value (`ed25519_jwt_issuer.go:178-180`), wired from `srv.Issuer` by `buildEd25519SigningIssuer` (`cmd/sso-server/serverbuildsign/build_signing_issuers.go:44-46`); `NewEd25519JWTIssuer` defaults to the SDK sentinel when the option is absent (322-326). The minted `iss` is therefore a fixed string today, never request-derived in the stock server — which is exactly why the Host-variance probe is green on a correct deployment and fails only under the regression | Confirmed (new evidence, anchors the probe's pass/fail polarity) |
| `issue_payload.go:26-47` "TenantID stamped unconditionally" | `buildAccessPayload` is at 27-50; `TenantID: subject.TenantID` at line 46 with the documented discipline "the client's mint-time tenant binding is stamped unconditionally and omitempty omits it when empty" (42-46). Struct field: `ed25519_types.go:41-47` (`json:"tenant_id,omitempty"`) | Confirmed (exact) |
| `issue_payload.go:108-131` "roles via Extra with claimsWithoutEmittedKeys dedup" | `claimsWithoutEmittedKeys` is at 116-131: strips `tenant_id` (when `subject.TenantID != ""`) and `roles` (when `len(subject.Roles) > 0`) from the attribute-bag copy; the "one claim name, one value per token" contract is documented at 106-114 and on `ed25519_types.go:45-47,53-56`. Precision note: the bag marshals under the nested `ext` key (`ed25519_types.go:26` `Extra map[string]string json:"ext,omitempty"`), so the exactly-once assertion must be defined over the flattened claim view (top-level claim ∪ `ext` bag), never a raw-payload byte count — a byte count would legitimately find `ext.tenant_id` too. On the cc path the bag is absent (`subject.Claims` is nil), so the dedup assertion is structurally satisfied there; its regression value accrues to a bag-carrying mint path | Confirmed (behavior exact; the "exactly once" acceptance must be restated precisely) |
| "protocols/oauth/device_codes_test.go shows the grant exists" | The cited test file only unit-tests the code generator (`GenerateDeviceCode`, 43-char code). The RFC 8628 grant lives at `interfaces/sso/server_device.go` (`handleDeviceCode:40`, `handleDeviceVerify:223`, `handleDeviceTokenGrant:320`) delegating to `internal/handler/tokengrant/token_device.go` (`HandleDeviceGrant:45`, `deviceMintAndRespond:85`) | Partially confirmed — better citations are `server_device.go` + `token_device.go`; the grant exists, the cited test file does not itself show it |
| "the sweep has no such leg today" | Probe groups in `check.go`: T-2 (`runT2`), T-8a (`runT8a`), T-8d (`runT8d`), T-9 (`runT9`). No device leg, no authorization leg | Confirmed (exact) |
| Proposed device leg "exercises the mandatory roles claim on a path that resolves Subject.Roles" | `deviceMintAndRespond` (`token_device.go:92-105`) builds `&core.Subject{ID: issuedSub, Provider: dc.Provider, Claims: dc.Attributes, Resources, ClientID, TenantID, AuthTime, AMR, ServingRegion, TTL, …}` — `Roles` is never set; `dc.Attributes` is the approving session's token `Extra` bag (`applyDeviceDecision` stores `claims.Extra`, `server_device.go:295-303`). `Subject.Roles` resolution exists only on the direct-mint/authcode path (`server_login.go:120` via `mintRoles` → `subjectRoles`, 148-157) | Refuted as stated — a headless device leg exercises the *attribute-bag* roles/tenant_id path (string form under `ext`) and the `claimsWithoutEmittedKeys` dedup strip on a bag-carrying mint; it does NOT resolve `Subject.Roles`. The proposed leg must be restated with this premise, or the sweep's roles assertion must accept both shapes (top-level array from a `Subject.Roles`-resolving mint; `ext` string from a bag-carrying mint) |
| B4-1 / T-8a mapping | `docs/campaigns/implementation-gate.md` row 1 (snaplink 部署仓): B4-1 requires `tenant_id` (client binding) + `roles` claims in `buildAccessPayload`, and "`iss` 配置化（allowlist，禁 Host 派生…）" with acceptance "T-8(a)：`POST /token` → 200 + header kid + claims {iss/aud/scope/client_id/tenant_id/roles}；T-1.2 联合" | Confirmed — this spec is the sweep-side oracle the row's T-8a acceptance needs |
| Pre-existing test state at spec time | `go test ./cmd/sso-ctl/apiclient/` at worktree HEAD fails 11 top-level tests, all in the untracked WIP sweep (`check.go`, `sweep.go`, `token.go`, `check_test.go`, `apiclient_test.go` are untracked; only `apiclient.go` is committed). Dominant root cause: the `newLiveServer` harness (`check_test.go:71-90`) wires `sso.WithIssuer(addr)` but its JWT issuer is built without `WithEd25519Issuer` → minted `iss` = SDK sentinel `"snaplink-sso"` ≠ discovery issuer `addr` → every live-server claims row fails (e.g. `TestSweep_GreenPath`: `claims: iss "snaplink-sso" != discovery issuer "http://127.0.0.1:39779"`). Unrelated WIP defects also present: `TestIntrospect_Non401Fails/wrong-bytes` (server error body carries `trace_id`, the fixture expects byte-identical body without it), `TestCheck_AddrValidation`, `TestMint_ResponseFail/status-400` | Pre-existing failures — reported separately in §9; only the issuer-misalignment root cause is repaired by this direction's fixture requirement (R5) |

## 2. Goal and user outcome

T-8a's claims matrix trusts two oracles, and both are blind to the B4-1 contract it exists to verify:

1. `iss` is compared only against the discovery issuer (`token.go:187-188`). Because the discovery issuer is itself request-base-derived whenever `s.issuer` is unset/sentinel (`server_discovery_config.go:144`, `server_discovery.go:251-256`), a mint whose `iss` is Host-derived satisfies the check — the exact "禁 Host 派生" (never Host-derived) clause of B4-1 is unverifiable. An operator cannot declare "this deployment's tokens MUST carry the issuer I configured" at all.
2. `tenant_id` and `roles` are asserted only when the operator remembers `--expect-tenant-id`/`--expect-roles`. `--expect-roles` is additionally a guaranteed failure on the client-credentials leg (the cc Subject never carries `Roles` or `Claims`, `token_client_credentials.go:63-71`), so the roles claim is effectively never asserted, and a regression that drops `TenantID` stamping (`issue_payload.go:46`) passes the gate whenever the flag is forgotten.

Completion marker: `sso-ctl check` accepts `--expect-issuer <value>`; with it declared, the sweep asserts minted `iss` equals the declared value AND the discovery issuer, and additionally mints a second token with an overridden Host header and asserts the two mints' `iss` claims are byte-identical (fails exactly when the mint derives `iss` from the request Host); with `--expect-tenant-id`, the sweep asserts the claim appears exactly once in the flattened claim view (top-level ∪ `ext`). All assertions route through the existing exit-code contract (failures print `claims: …` to stderr and force `mint: FAIL` / exit 1).

## 3. Product boundary

- Surface: `cmd/sso-ctl/apiclient/` only — `check.go` (flag + usage), `token.go` (verifyClaims extension + Host-variance mint), `check_test.go` (tests + harness alignment). No other module, no server-side edits, no root-module edits.
- The Host-variance probe is a second mint against the SAME advertised `token_endpoint` with the SAME body/credentials — it adds no new wire surface, no new endpoint probes, and preserves the no-redirect pin and the no-bearer posture (`check.go` security-posture comment).
- Explicit non-goals (do not implement):
  - No server-side issuer allowlist. B4-1's "allowlist" is satisfied sweep-side by the operator-declared `--expect-issuer` pin; nothing in `interfaces/sso/`, `cmd/sso-server/`, or `config/` changes. (The server's `resolveIssuer` fallback is deliberate SDK behavior; this direction only makes it observable.)
  - No changes to `--expect-roles` semantics on the cc path. The diagnostic at `token.go:228` stays; the direction does not make cc mints resolve roles.
  - No device-flow leg. The acceptance's device leg stays PROPOSED and unverified until a separate change lands it (see R4). This spec only fixes the premise wording and defines the claim-shape contract the leg must satisfy.
  - No changes to T-8d/T-9, the mint body, the discovery sweep, the revoke/introspect legs, exit-code semantics, or the `usage()` banner structure beyond the new flag line.
  - No fix for pre-existing WIP failures unrelated to the issuer misalignment (e.g. the `TestIntrospect_Non401Fails/wrong-bytes` trace_id drift, `TestCheck_AddrValidation` expectation drift) — reported, not repaired.

## 4. Module classification

- [x] Infrastructure/config/deployment (deploy-tree live-sweep oracle for the B4-1 claims contract)
- [ ] OAuth/OIDC protocol flow · [ ] Store · [ ] Admin endpoint · [ ] Authenticator · [ ] Audit · [ ] Authorization · [ ] Cold module · [ ] Refactoring only

Owning layer: `cmd/sso-ctl/apiclient` (root module; no new imports — stdlib `net/http`/`flag` plus the package's existing `probeClient`/`decodeJWT`/`redactURL` helpers only).

Budget check at spec time: `check.go` 277 lines, `token.go` 413 lines (both under the 500-line file budget; the R1-R3 additions stay within it — if `token.go` approaches the ceiling, the Host-variance probe helper moves to `sweep.go`, 284 lines). `check_test.go` is untracked WIP at 1345 lines; `_test.go` files do not count toward budgets.

## 5. Requirements

### R1 — `--expect-issuer` allowlist pin

`check.go`: new flag `--expect-issuer string` ("declare the minted token MUST carry exactly this iss; the sweep also requires iss == the discovery issuer"), wired into `checker` as `expectIssuer string`; documented in `usage()`. Env parity (`SSO_EXPECT_ISSUER`, env-wins per the `effectiveAddr` precedent) is permitted but not required.

`token.go` `verifyClaims`: when `ck.expectIssuer != ""`, assert `p["iss"] == ck.expectIssuer` (diagnostic `claims: iss %q != declared issuer %q`, both values through `redactURL` — a flag value is never echoed raw) in addition to the existing `iss == ck.doc.Issuer` row (187-188). When unset, behavior is byte-identical to today.

Testable acceptance:
1. Live-server green path: `newLiveServer` with an aligned issuer (R5) + `--expect-issuer <addr>` → exit 0, `mint: OK`, stdout unchanged from the golden.
2. Live-server with `--expect-issuer https://other.example` → exit 1, stderr `claims: iss … != declared issuer …`, `mint: FAIL`, no flag value echoed verbatim in any output.
3. Stub-server row: minted `iss` ≠ declared value → same failure shape.

### R2 — Host-variance probe (the "never Host-derived" oracle)

`token.go` (next to `mint`): a second mint leg that reuses the mint body/credentials but sends the request with an overridden Host header (`req.Host = <altered-host>`; connection/URL unchanged — the request still targets the advertised `token_endpoint`). The altered host is a fixed non-echoed constant (e.g. `"sweep-host-variance.invalid"`), never a flag value. Requires a small probe-client extension (e.g. `probeClientWithHost(target, host)` or a per-request Host setter) — `apiclient.Do` builds the request internally, so the override must thread through the probe, not the shared `Client`.

Assertions, in order:
1. The second mint succeeds: 200 + `access_token` (non-2xx → `claims: host-variance mint: status N` via the existing `bodyEcho` sanitizer).
2. `decodeJWT` of the second mint's payload yields `iss` byte-identical to the first mint's `iss` (diagnostic `claims: iss %q differs across Host variance` — values redacted).
3. The first mint's own `iss` rows (R1 and the existing discovery comparison) still apply to both mints.

Polarity (verified against the stock server): the minted `iss` is a fixed string (`ed25519_issue.go:43` ← issuer option ← `server.issuer`), so the probe is green on a correct deployment and fails exactly when a mint sources `iss` from `resolveIssuer`/`requestBaseURL` (the Host-derived regression) or from any other per-request value.

Testable acceptance:
1. Live server with aligned issuer: `--expect-issuer <addr>` → both mints carry `<addr>` → exit 0.
2. Regression fixture: a test server whose token issuer stamps `requestBaseURL`-derived `iss` (a small wrapper `TokenIssuer` in `check_test.go` that reads `ctx.Request().Host` — the SDK's `resolveIssuer` fallback at `server_discovery.go:251-256` is the production stand-in for this shape) → first mint `iss` = original host, second mint `iss` = altered host → exit 1 with the variance diagnostic. This is the acceptance's "fails when resolveIssuer's requestBaseURL fallback is in play".
3. The probe never forwards a bearer, never follows redirects, and never targets a non-advertised endpoint (unchanged posture).

### R3 — `tenant_id` exactly-once assertion (dedup contract)

`token.go` `verifyClaims`, inside the existing `ck.expectTenantID != ""` block: after the value match, assert exactly-once over the flattened claim view — top-level `p["tenant_id"]` present AND `p["ext"]["tenant_id"]` absent. (`p["ext"]` is the decoded `Extra` bag; `decodeJWT` yields `map[string]any`.) Absence of `ext` entirely satisfies the assertion. Diagnostic for the violation: `claims: tenant_id present in ext bag and as a top-level claim — claimsWithoutEmittedKeys strip missing` (no values echoed).

Precision notes, verified:
- The bag marshals under the nested `ext` key (`ed25519_types.go:26`), so "exactly once" is defined over top-level ∪ `ext`, not over raw payload bytes.
- On the cc leg the bag is structurally absent (`token_client_credentials.go` sets no `Claims`), so the assertion is trivially satisfied today — it is the regression tripwire for the `claimsWithoutEmittedKeys` strip (`issue_payload.go:116-131`) and accrues real detection value on the proposed bag-carrying device leg (R4).

Testable acceptance:
1. Live server, tenant-bound client, `--expect-tenant-id t1`: exit 0 (green) — including with the aligned-issuer fixture.
2. Stub-server row with `ext: {"tenant_id": "t1"}` in the minted payload: exit 1 with the dedup diagnostic (this row cannot be produced by the cc path — it pins the assertion's shape for bag-carrying mints).

### R4 — Proposed (unverified until the leg lands): headless device-flow mint leg

Not implemented by this direction. The premise is corrected against verified code: the device mint (`token_device.go:92-105`) resolves roles via the approval-time attribute bag (`dc.Attributes` = the approving session's token `Extra`, `server_device.go:295-303`), NOT via `Subject.Roles` — so a headless device leg exercises the bag-carrying roles/tenant_id path and the `claimsWithoutEmittedKeys` dedup strip in a user-authenticated flow, and the sweep's roles assertion for that leg must accept both shapes (top-level array from a `Subject.Roles`-resolving mint; `ext` string from the bag) with the same exactly-once rule as R3. The leg lands only with its own change (device-approval drive in `check_test.go`/sweep code), at which point this section is revisited and re-verified.

### R5 — Test-harness issuer alignment (fixture prerequisite)

`check_test.go` `newLiveServer`: wire the JWT issuer with `defaultimpl.WithEd25519Issuer(addr)` so minted `iss` == discovery issuer == `addr`. This is a hard prerequisite of R1/R2's green-path rows (the current harness mints the SDK sentinel `"snaplink-sso"` and every live claims row fails) and repairs the pre-existing green-path failures whose root cause is the misalignment (`TestSweep_GreenPath`, `TestStdoutDeterministic`, `TestSweep_TokenEndpointSuffix`, `TestMint_*` live rows, `TestRevoke_RoundTrip`).

Testable acceptance:
1. `TestSweep_GreenPath` passes with `--expect-issuer <addr>` added to the green-path arguments (exit 0, golden stdout unchanged).
2. Pre-existing failures NOT rooted in the issuer misalignment remain red and are tracked separately (§9) — this direction neither fixes nor masks them.

## 6. Files

### Create

```text
(none — all changes extend existing WIP files; no new production file is
needed. If token.go crosses ~470 lines during implementation, move the
Host-variance helper to sweep.go instead of creating a new file.)
```

### Modify

```text
cmd/sso-ctl/apiclient/check.go — R1: --expect-issuer flag + checker field + usage line
cmd/sso-ctl/apiclient/token.go — R1: verifyClaims iss pin; R2: Host-variance second mint + probe Host override; R3: tenant_id exactly-once assertion
cmd/sso-ctl/apiclient/check_test.go — R5: newLiveServer WithEd25519Issuer(addr); R1-R3 test rows; R2 regression fixture (Host-derived issuer wrapper)
```

### Do not modify

```text
interfaces/sso/server_discovery.go — resolveIssuer fallback is deliberate SDK behavior; the sweep-side pin makes it observable without touching it
infrastructure/defaultimpl/issue_payload.go — buildAccessPayload/claimsWithoutEmittedKeys are the contract under test, not the fix surface
cmd/sso-ctl/apiclient/apiclient.go — shared client transport; the Host override rides the probe client, never the shared Do path
internal/handler/tokengrant/token_client_credentials.go — cc Subject shape (no Roles/Claims) is the verified fact behind the diagnostic, not a defect
```

Confirm file/function/directory frozen ceilings before implementation: `check.go` 277/500 lines, `token.go` 413/500 lines, functions all under the 50-line budget after the additions (split the Host-variance leg into its own function if `verifyClaims` grows past 50).

## 7. Dependencies and compatibility

- New/changed SPI: none (apiclient-internal).
- New option/store wiring: none.
- New YAML/env keys: none required (env `SSO_EXPECT_ISSUER` is permitted as an alternative to the flag, mirroring `effectiveAddr`).
- Storage migration: none.
- HTTP/proto compatibility: the Host-variance probe is an HTTP request to the already-advertised `token_endpoint`; no new route, no new method, no new body shape. Wire-compat note: the sibling B4-4 form-urlencoded campaign (`docs/architect-analysis/cmd-sso-ctl-b4-4-check-probes-form-requirements.md`) converts the mint body to `application/x-www-form-urlencoded`; the Host-variance leg must reuse whatever body transport the mint leg uses at implementation time, so the two campaigns land in the same shape.
- Rollout/rollback: flag-only; omitting `--expect-issuer`/`--expect-tenant-id` reproduces today's behavior byte-for-byte.

## 8. Documentation

- [ ] `docs/config-reference.md` — not applicable (CLI flag, not config; `usage()` is canonical; sibling campaign docs list the check flags)
- [x] `docs/architect-analysis/cmd-sso-ctl-b4-1-claims-gate-requirements.md` (this spec)
- [ ] `docs/openapi.yaml`, `docs/error-codes.md` — not applicable (no endpoint, no `Err*`)
- The R4 device leg, when it lands, must update the T-8a group description in `check.go`'s header comment and the sibling campaign requirement docs.

## 9. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/apiclient/ -run 'TestSweep_|TestMint_|TestRevoke_|TestStdoutDeterministic' -v
make ci
```

Pre-existing failures at spec time (worktree HEAD `6cb50de3`, `go test ./cmd/sso-ctl/apiclient/` — 11 failing top-level tests, all in untracked WIP sweep files):

| Failure | Root cause (verified) | Relation to this direction |
|---|---|---|
| `TestSweep_GreenPath`, `TestStdoutDeterministic`, `TestSweep_TokenEndpointSuffix`, `TestMint_ClaimsMatrix`, `TestMint_AudContainsResource/live-array-form`, `TestMint_ScopeContainsRequested`, `TestRevoke_RoundTrip` | `newLiveServer` mints `iss` = SDK sentinel `"snaplink-sso"` ≠ discovery issuer `addr` | Repaired by R5 (fixture prerequisite) |
| `TestIntrospect_Non401Fails/wrong-bytes` | Fixture expects a byte-identical 401 body; the live server's error body carries `trace_id` | Out of scope — reported, not fixed |
| `TestCheck_AddrValidation/no-scheme,empty-host` | WIP mismatch between the `validateBaseURL` error-echo path and the test's no-raw-addr-echo expectation (`check_test.go:379`); unrelated to issuer | Out of scope — reported, not fixed |
| `TestSweep_AdvertisedURLRejection/*`, `TestMint_ResponseFail/status-400` | WIP expectation drift in the untracked tests (stub 400 body vs `mint: status N` echo, `check_test.go:982`); unrelated to issuer | Out of scope — reported, not fixed |

Post-implementation handoff gate: all apiclient tests green except the explicitly tracked out-of-scope rows above; `make ci` green; this spec's R1-R3 acceptance rows each map to a named test.

## 10. Decisions recorded during verification

- D1 (R2 polarity): the probe fails only under a Host-derived `iss` mint. A correctly configured deployment — including the cmd default `server.issuer = "sso-server"` — passes, because the minted `iss` is a fixed string. The acceptance's "fails when resolveIssuer's requestBaseURL fallback is in play" is realized by the regression fixture (a `requestBaseURL`-stamping test issuer), not by the stock server.
- D2 (R3 shape): "exactly once" is the flattened view (top-level claim ∪ `ext` bag), because the bag is nested under `ext`. A raw-payload `strings.Count("tenant_id")` would false-positive on `ext.tenant_id`.
- D3 (R4 premise): the direction's "device leg resolves Subject.Roles" is refuted by `token_device.go:92-105`; the leg's value is the bag-carrying path, and the roles assertion must accept both claim shapes. The leg stays proposed.
