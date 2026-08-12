Done. All 11 failing subtests are fixed and committed (`29ed9269`).

## What was wrong and what I changed

**Fixture/test alignment (tests now exercise the documented contract):**
- **`newLiveServer`** — the Ed25519 token issuer kept its default non-URL issuer (`snaplink-sso`), so every live-server mint failed `iss != discovery issuer`. Added `WithEd25519Issuer(addr)` (mirrors `cmd/sso-server` wiring). This alone unblocked `TestSweep_GreenPath`, `TestStdoutDeterministic`, `TestMint_*` (iss chain), and `TestRevoke_RoundTrip`.
- **`advertiseDoc`** prepended the base URL to every advertised value, so the row-2 rejection matrix advertised concatenations like `http://hostfile:///x`. Added `advertiseDocRaw` (verbatim advertisement) and drove `TestSweep_AdvertisedURLRejection` through it.
- **`TestMint_ResponseFail`** — the "status-400" case returned 200, so the tool reported "no access_token"; the case table now carries the explicit status.
- **`TestCheck_AddrValidation`** — the blanket stderr check collided with the usage banner's documented `DefaultAddr` (`8443`/`http://` are legitimately printed there); the assertion now targets the `invalid base URL:` rejection line only, which is the actual never-echo contract.

**Tool fixes (per the contract in check.go / design doc):**
- `checkTokenSuffix` used `strings.HasSuffix`, silently accepting `/oauth2/token`; it now requires the path (minus the issuer's path prefix) to be exactly `/token` — the A4 suffix diagnostic fires.
- `mint`/`runT8d`/`loadJWKS`/`revoke` probed advertised URLs without row-2 preflight, letting `url.Error` echo malformed URLs verbatim (leaking `u:p` userinfo). Every credential-bearing probe target now preflights with `validateAdvertisedURL`: redacted diagnostic, zero requests — oracle-safe.
- `runT9` rendered the expected 401 body with `%q`, injecting a quoted `\n`; it now prints the trimmed constant so the diagnostic reads `expected 401 {"error":"invalid_client"}`.

**Budget compliance:** claims-matrix code moved to a new `claims.go` (token.go hit the 500-line file budget); `postRevokeIntrospect` extracted to hold `revoke` under 50 lines.

**Verification:** `go build ./... && go vet ./...` clean; maintainability/architecture gates pass; `./cmd/sso-ctl/... -race -count=1` green (17 packages); the only full-tree red is the documented G5b expected-red `TestSdkForm_PARClaimsThreaded` (F1 decoder not landed — pre-existing by design, unrelated to this change).
