All verification dimensions are now checked. Here is the report.

## Verification report: strict-mode 415 envelope on /token, /introspect, /revoke, /par

**Verdict: PASS — the landed strict-wire surface is oracle-safe, correctly cached, challenge-free, and doc-covered, with two minor non-blocking observations.**

### 1. Oracle-safety (rejection before any credential/token processing) — CONFIRMED

All four handlers bind **before** any client authentication, token verification, store access, or grant dispatch:

| Endpoint | Bind site | What the 415 bypasses |
|---|---|---|
| `/token` | `interfaces/sso/server_token.go:30` (`bindCredentialParams`) | `authenticateTokenClient`, DPoP/mTLS capture, residency gate, grant dispatch |
| `/token/introspect` | `handle_introspect.go:154` (`bindCredentialRequest`) | `BasicClientCreds`, `authenticateIntrospectClient`, token verification/cache |
| `/token/revoke` | `handle_revoke.go:82` | client auth, both revocation tiers |
| `/par` | `handle_par.go:73` | client auth, param validation, PAR storage |

- `BindParamsFormOnly` (`bind_strict.go`) is a pure function of `normalizedMediaType` (header-only: strip params, lowercase, compare); the body is never read. Proven by `TestBindParamsFormOnly_DoesNotReadBodyOn415` and `TestStrictToken_BodyIndependent415` (`%ZZ`, bindable forms, and `\x00\xff` under `text/plain` all produce byte-identical 415).
- **State-independence**: valid Basic creds (`TestStrictToken_BasicAuthStill415`), a valid DPoP proof (`TestStrictToken_DPoPProofStill415`), real minted access/refresh tokens (`TestStrictIntrospect/Revoke_JSONAndMissingCTRejected`), and missing creds all 415 identically; `mintCountingIssuer` asserts **zero mints** on three 415 rows. The only pre-bind checks are config-state (nil-store 500s), never input-state.
- **Byte-identical across endpoints**: both mapping sites emit the identical `ctx.JSON(415, core.ErrorBody(core.ErrInvalidRequest))` — plain `{"error":"invalid_request"}\n`, `Content-Type: application/json` (no charset), no `trace_id`, no `error_description`. `TestStrictAllEndpoints_ContentTypeCombinations` drives 12 rows (3 CTs × 4 endpoints) with exact-byte assertions.
- **No timing distinction**: the decision path is a header string op plus a JSON write — no body parse, no crypto, no store, no credential compare. Mode-off vs mode-on is a documented deployment-mode difference, not an input-state oracle.
- Malformed percent-encoding under a *form* CT stays on the existing `400 invalid_request` path (`TestStrictToken_FormMalformedPercentEncoding400`, binder F6 pin) — never 415, never `ErrFormOnly`.

### 2. Cache headers — CONFIRMED
`middleware.TokenNoStoreHeaders` (`no_store.go`) sets `Cache-Control: no-store` + `Pragma: no-cache` and runs before the bind in all four handlers; `ctx.JSON` never touches these. `assert415` checks **both** headers on every 415 row (D4), including the form-400 arm.

### 3. No WWW-Authenticate — CONFIRMED
The 415 write is a bare `ctx.JSON`. None of the four handlers call `setBearerChallenge` (it lives only in quota/mesh_authz/extauthz surfaces), no global middleware injects challenges on error statuses, and the 415 row additionally carries no `DPoP-Nonce` (explicitly asserted). The default middleware chain (tracing/tenant/geo/region) is header-only — the only body-reading middleware (`request_log.go`) is opt-in and replays the body unchanged.

### 4. Error-code/OpenAPI coverage — CONFIRMED, with one nit
- `docs/error-codes.md` (§Token endpoint): dedicated opt-in section naming all four endpoints, exact envelope, byte-identical claim, no-store headers, before-body/before-auth oracle statement, and "No new error code is introduced" — `ErrFormOnly` is an internal sentinel never on the wire (verified: only two mapping sites, both `errors.Is`).
- `docs/config-reference.md:42`: full `server.require_form_content_type` semantics; `config_server.go:72` (`*bool`, append-only-when-set) and `options.go:107-113` (`WithCredentialFormOnly`) match; `TestServerOptions_AppendOnlyWhenSet` PASS.
- `docs/openapi.yaml`: 415 documented in prose on all four paths (lines ~1072/1288/1378/1522). **Nit**: no formal `415:` entry in the four `responses` maps — consistent with the spec's existing style (`/token/revoke` also omits its `400`), so not a regression, but a formal entry would be more precise.
- Deploy tree: `ops/deploy/compose/config.yaml:21` already `true` (as the evidence stated — a shipped mode, not hypothetical), pinned by `TestDeployTreeRequireFormContentTypeSingleFlipPoint` PASS.

### Gates
- `go build ./... && go vet ./...`: clean.
- `oauthwire` strict binder: 8/8 PASS. Endpoint suite: 19/19 PASS, green under `-race`.
- Pre-existing failures only (matching the evidence): FileSizeBudget (`ed25519_jwt_issuer.go` 539 lines), DirectoryDepth/DirectorySubdirFanout (root 24 > frozen 21; `docs/architect-analysis/auto/runs` — the pipeline's own artifacts, depth 4–7). None touch the strict-wire code.

### Observations (non-blocking, matching the design evidence)
1. **R7 gap stands**: `assertQuotaTokenRequest` (`quota_relay_test.go:149`) and `assertRetentionTokenRequest` (`:94`) assert `PostForm` but never the CT header; `test/billing_form_e2e_test.go` does not exist (HEAD `880443ef` is the design stage). The audit-provisioner mint e2e (`TestAuditProvisionerPlatformTokenSourceStrictServer`) is landed, so only the two billing mints lack strict-mode e2e drive — the R7 delta remains to be implemented.
2. The OpenAPI `415` coverage is prose-only in the descriptions; no schema-level response entry (see nit above).
