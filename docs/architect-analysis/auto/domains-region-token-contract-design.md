# Design: `domains/region` — serving-region token contract (expansion direction 2)

Design counterpart to `docs/auto/domains-region-token-contract-spec.md`. Covers
the API surface, storage model, failure modes, and breakage risks for the
three improvements. Every placement below was re-verified against current
source and the committed gates; the spec's proposed file placements were
checked line-by-line and **two of them collide with the 500-line budget and
are re-homed here**.

Layer map used throughout:

```text
composition (cmd/sso-server)                                   ← wires WithServingRegionAdvertisement (decision 2)
  → interfaces/sso (server_*; sso_wiring.go)                   ← mint stamping, discovery option, region helper
  → infrastructure/defaultimpl (issue_payload, ed25519_types,  ← shared claim projection (all 3 signers)
    validate_claims, ed25519/ecdsa/rsa_issue)
  → protocols (oidc metadata/types, oauth handle_introspect)   ← discovery field, RFC 7662 echo
  → internal/handler/tokengrant                                ← grant-path mint stamping
  → domains/region (UNCHANGED)                                 ← FromHandlerContext is the only source
  → shared/core (types_token, consts_wire)                     ← plain-string fields; no Snaplink imports
interfaces/ssoclient/rs                                        ← decision 3 (leaf SDK, own budget)
```

Non-negotiable constraints re-verified against source:

- `interfaces/sso` is at its frozen 60-non-test-file ceiling (`directory_fanout_test.go`).
  `protocols/oauth` is at its frozen 12-file ceiling — a new file there must be
  net-zero (merge + create).
- `interfaces/sso/server_discovery_config.go` is at **exactly 500 lines** and
  `protocols/oauth/handle_introspect.go` at **exactly 500 lines**
  (`maintainability_budget_test.go`: `n > 500` fails; 500 passes, 501 fails).
  The spec's plan to extend both is impossible — see decisions 1 and 2 for the
  re-homing.
- `interfaces/sso/options_misc.go` (496), `server_login.go` (498),
  `server_finish_login.go` (499), `accessors_feature_gates.go` (498),
  `sso.go` (490), `server_tenant_residency.go` (493), `token_exchange.go`
  (498), `token_exchange_stages.go` (491) have near-zero headroom. Each gets
  at most the one required line; nothing else in those files.
- `shared/core` imports no Snaplink package: all region fields are plain
  `string`, never `region.ID`. `region.FromHandlerContext` is the ONLY source;
  `domains/region` changes nothing.
- Oracle-safe semantics, the fail-open ladder, and the introspection
  non-gate in `server_tenant_residency.go` are NOT touched.

---

## 决策 1 — `serving_region` claim on access + ID tokens

Mint-region evidence becomes a first-class claim on RFC 9068 access tokens
and OIDC ID tokens, stamped from the same middleware stash the login gate and
audit already read. Empty ⇒ claim omitted ⇒ byte-identical.

### API surface

**1. `shared/core/types_token.go`** (+4 lines, file at 258):

- `Subject.ServingRegion string` — input to every `Issue` call; doc comment
  follows the `SID` precedent ("Empty = no region middleware wired / resolved
  none → the issuer omits the claim").
- `TokenClaims.ServingRegion string json:"serving_region,omitempty"` —
  validated view, same placement as `SID`.

**2. `infrastructure/defaultimpl` — one projection, three signers.** The
spec's key claim holds: `buildAccessPayload` + `claimsFromPayload` +
`ed25519Payload` are shared verbatim by Ed25519/ECDSA/RSA, so a single change
covers every issuer:

- `ed25519_types.go` (150): `ed25519Payload.ServingRegion string
  json:"serving_region,omitempty"` and `ed25519IDPayload.ServingRegion string
  json:"serving_region,omitempty"`.
- `issue_payload.go` (238): `ServingRegion: subject.ServingRegion` in the
  `buildAccessPayload` struct literal — NOT in `applyOptionalClaims`. The
  literal assignment is unconditional and `omitempty` performs the omission,
  which is exactly the SID discipline; no wire-visible guard needed.
- `validate_claims.go` (70): `ServingRegion: p.ServingRegion` in
  `claimsFromPayload`.
- The three `IssueIDToken` bodies (`ed25519_issue.go:91`, `ecdsa_issue.go:67`,
  `rsa_issue.go:58`) each add `ServingRegion: req.ServingRegion,` to their
  inline `ed25519IDPayload{...}` literal. There is NO shared ID-payload
  builder (verified), so this is three one-line edits — the only per-issuer
  drift point in the design.

**3. `protocols/oidc/types.go`** (109): `IDTokenRequest.ServingRegion string`
— first-class field, never a `Claims` map entry, so OIDC §5.5
`ProjectIDTokenClaims` (which filters only the `Extra` map) can never drop it.

**4. Mint-site stamping.** Every mint site reads the live stash once via a
tiny package-local helper and sets the field on the `Subject` /
`IDTokenRequest` literal:

```go
// servingRegionFrom returns the serving region the region middleware
// stashed on ctx, or "" when no middleware ran / it resolved none.
func servingRegionFrom(ctx HandlerContext) string {
    id, _ := region.FromHandlerContext(ctx)
    return string(id)
}
```

- `interfaces/sso/server_tenant_residency.go` (493): the helper lives here —
  the file already imports `domains/region` and has 7 lines of headroom
  (helper is 6). Used by the three sso-side sites.
- sso-side mint sites (one field line each): `server_login.go:112`
  `mintAccessToken` (498 → 499, fits), `server_finish_login.go:296`
  `emitLoginIDToken` (499 → 500 — **exactly at the limit; this file receives
  no other edit in this change**), `server_native_sso.go:227` (339).
- `internal/handler/tokengrant`: same helper shape in `token_authcode.go`
  (275 → ~283; the package already imports `domains/*` elsewhere —
  `token_exchange.go` imports `domains/tenant`, so the layer edge is legal).
  Field lines at the `Issue` literals: `token_authcode.go:107`,
  `token_client_credentials.go:40`, `token_device.go:82`, `token_ciba.go:99`,
  `token_jwt_bearer.go:95`, `token_saml2_bearer.go:103`; ID-token literals at
  `token_authcode.go:246`, `token_ciba.go:269`, `token_device.go:185`,
  `token_exchange.go:288` (498 → 499, fits).
- Pure subject builders without `ctx` — `refreshRotatedSubject`
  (`token_refresh.go:246`) and `tokExSubject` (`token_exchange_stages.go:386`)
  — gain a `servingRegion string` parameter, passed by their `ctx`-holding
  callers (`refreshIssueAndRotate`, `tokExResolveSubjectAndIssue`). This keeps
  the builders pure and unit-testable rather than reaching into a context
  they don't own. `token_exchange.go:288`'s IDTokenRequest is inside the
  exchange handler — ctx is in scope there.
- **Deliberately empty (documented "unconstrained")**: break-glass
  impersonation (`accessors_feature_gates.go:257`) and admin temp tokens
  (`interfaces/grpcserver/grpcadmin/admin_tokens.go:174`) run on bare
  contexts outside the region pipeline. Empty claim == no evidence, matching
  `region.ID("")` semantics — same as the login gate's "no region ⇒
  unconstrained" step.

**5. Introspection echo** — `protocols/oauth/handle_introspect.go` is at
exactly 500 lines, so this requires the split below. The echo itself is the
SID pattern verbatim:

```go
// populateIntrospectionServingRegion echoes the token's mint region (RFC
// 7662 extension, same discipline as client_id/jti/sid). Provenance of the
// token, NOT the calling RS's region — deliberately ungated, like the rest
// of introspection.
func populateIntrospectionServingRegion(body map[string]any, claims *core.TokenClaims) {
    if claims.ServingRegion != "" {
        body[core.KeyServingRegion] = claims.ServingRegion
    }
}
```

called from `populateAccessIntrospectionBody` using the existing
`core.KeyServingRegion` wire key (no new const).

**Required split (net-zero file count, protocols/oauth frozen at 12):**
move `recordIntrospectionUsage` + `populateIntrospectionSID` +
`populateIntrospectionConfirmation` + `populateAccessIntrospectionBody` +
the new `populateIntrospectionServingRegion` into a new
`protocols/oauth/introspect_body.go` (~115 lines with the new helper), and
merge `introspect_session.go` (30 lines, `introspectSessionActive` — same
introspection-support concern) into it. `handle_introspect.go` drops to
~415 lines; the directory stays at 12 non-test files. This is a pure move:
same package, same symbols, zero behavior change for the moved helpers.

### Storage model

**No persistent storage anywhere.** The claim is derived per mint from the
request-pipeline stash (`region.FromHandlerContext`); the token itself is the
only carrier. Specifically:

- AuthCode / refresh / device / CIBA / PAR stores change nothing. Region is
  mint-time semantics: an auth-code exchange stamps the region that SERVED
  the `/token` exchange, a refresh rotation stamps the region that SERVED the
  refresh — consistent with audit `region.serving` being per-event. The
  spec's "claim survives exchange" acceptance is satisfied because the
  exchange mints a fresh token with the current stash, not because anything
  is persisted at login.
- The introspection response is assembled per call from the validated token;
  the optional introspection cache (`IntrospectionCache`, keyed by token hash)
  stores opaque `CachedResult.Body` maps — an echoed `serving_region` rides
  through it unchanged because the body map is preserved verbatim.
- `TokenClaims.ServingRegion` is derived state, never stored.

### Failure modes

| Mode | Behavior |
|---|---|
| No region middleware wired (default) | `FromHandlerContext` → `("", false)` → empty field → `omitempty` drops the claim. Byte-identical. |
| Middleware ran, resolver failed / not allowed | Empty `ID` stashed → same omission. The middleware's non-fatal discipline is preserved; a failed resolver yields a token with NO evidence (fail-open, matching the login gate). |
| Break-glass / admin / raw-handler mints | Empty claim, documented "unconstrained" — an operator must know these tokens carry no mint provenance. |
| `claims` parameter (§5.5) | Immune by construction: first-class payload field, filtered map only affects `Extra`. |
| One issuer updated, others not | Impossible by structure: all three share the payload struct + builders; only the three ID literals are per-issuer (a test pins all three — below). |
| Region changes between login and exchange | Claim reflects the exchange's region. Intended; documented as mint-time semantics in the `Subject.ServingRegion` doc. |
| ID-token encryption (JWE) | Claim is inside the signed JWS before encryption; unaffected. |

### What could break the design

- **`server_finish_login.go` has one line of headroom.** The
  `emitLoginIDToken` edit must be exactly the `ServingRegion:` field line;
  any doc-comment or reflow edit in that file in the same change fails
  `TestMaintainability_FileSizeBudget`. Same caution for `server_login.go`
  (498) and `token_exchange.go` (498).
- **The introspection split is load-bearing.** Skipping it (adding the echo
  inline) is a guaranteed gate failure: 501 > 500. The move must be a pure
  relocation — the moved functions keep their names, signatures, and comment
  text; `handle_introspect.go`'s call sites are unchanged.
- **`applyOptionalClaims` must NOT gain the field.** That function's comment
  makes every `if` guard wire-visible; an unconditional struct-literal
  assignment in `buildAccessPayload` + `omitempty` is the exact `SID`/`ACR`
  pattern and keeps the three-issuer byte-identity invariant trivially
  checkable.
- **Claim-name collision**: `serving_region` is already the login-response
  key (`KeyServingRegion`) and an audit meta key. Reusing the const is
  intended; using a different spelling would silently fork the wire
  vocabulary.
- **Refresh rotation changes the claim across regions**: a token rotated in
  `us-east-1` from a `eu-west-1` login carries `us-east-1`. This is the
  designed mint-time semantic, but an RS gate (decision 3) configured for a
  single region will see the claim CHANGE on rotation — the doc comment and
  the E2E test must state this so operators don't file it as a bug.
- **`TokenClaims` json tag**: `json:"serving_region,omitempty"` mirrors
  `SID`; TokenClaims is not serialized on a hot path, but the tag keeps any
  future projection consistent with the payload tag.

---

## 决策 2 — OIDC discovery advertises the serving region

An opt-in SnapLink-extension field on `ProviderMetadata` plus
`claims_supported` membership, emitted only when the deployment's region is
statically pinned via a new server option.

### API surface

**1. `protocols/oidc/metadata.go`** (298 → ~308):
`ProviderMetadata.ServingRegion string json:"serving_region,omitempty"` with
the `MFAEndpoint` documentation style — "SnapLink extension; non-standard
OIDC discovery field". Sits next to the operator-metadata block.

**2. New option + apply helper — re-homed from the spec's proposal.**
The spec named `options_misc.go` (496, 4 lines headroom) and
`server_discovery_config.go` (500, zero headroom); neither can hold a
doc-commented option. Both go into `interfaces/sso/server_discovery_cache.go`
(295 → ~325), which already owns discovery-adjacent config
(`WithDiscoveryCacheTTL`, snapshot machinery):

```go
// WithServingRegionAdvertisement pins this deployment's serving region for
// DISCOVERY advertisement. The value MUST be deployment-static: the
// discovery document is cached per base URL, and every minted token in this
// process must carry the same serving_region. Wire it together with
// WithRegionMiddleware so advertised == minted. A header-resolver-only
// deployment (region varies per request) MUST NOT wire this. Empty (the
// default) omits the field and the claims_supported entry — byte-identical.
func WithServingRegionAdvertisement(id region.ID) Option {
    return func(s *Server) { s.servingRegionAdvertisement = id }
}
```

The `Server` field `servingRegionAdvertisement region.ID` goes in
`sso_wiring.go` (438 → ~442) next to `regionResolver`/`regionMiddlewareOpts`
(the file already imports `domains/region`).

```go
// applyServingRegionMetadata advertises the pinned serving region. Runs
// AFTER applyStaticClaimsAndSecurity because that helper ASSIGNS a fresh
// ClaimsSupported literal; appending here avoids the overwrite.
func (s *Server) applyServingRegionMetadata(cfg *oidc.ProviderMetadata) {
    if s.servingRegionAdvertisement == "" {
        return
    }
    cfg.ServingRegion = string(s.servingRegionAdvertisement)
    cfg.ClaimsSupported = append(cfg.ClaimsSupported, "serving_region")
}
```

**3. Call ordering in `buildOIDCConfiguration`** (`server_discovery_config.go`
— no new lines there: the call is added to the existing apply chain in
`buildOIDCConfiguration`, which is NOT the 500-line file... **verified
correction**: `buildOIDCConfiguration` lives in `server_discovery_config.go`
which is at 500/500. The one-line call must therefore replace an existing
line's position — impossible. **Re-home:** `applyServingRegionMetadata` is
called from `buildOIDCConfiguration` — the call line must go into that file.
**Resolution:** `server_discovery_config.go` must shed one line in the same
change (compress the `buildOIDCConfiguration` doc comment by one line, or
fold a two-line comment into one) so the net add is zero. This is the single
tightest edit in the design; flagged explicitly for review.

Ordering requirement: `applyStaticClaimsAndSecurity` ASSIGNS
`cfg.ClaimsSupported = []string{...}` (verified at
`server_discovery_config.go:381`); the append MUST come after it in the
apply chain, immediately before `applyEndpointAuthSigningAlgs` (or after —
any position after `applyStaticClaimsAndSecurity` and before
`signDiscoveryMetadata` works).

**4. `signed_metadata`**: `signDiscoveryMetadata` marshals the FINAL cfg —
the new field and the `claims_supported` entry are covered automatically; no
separate handling.

**5. Federation**: `BuildOPMetadata` derives from the same `cfg` — the
advertisement rides into the federation entity configuration automatically.
No change.

### Storage model

Process-static config only. The value lives on the `Server` struct, is set
once at construction, and flows into the per-base-URL discovery doc cache
(`discoveryDocEntry` → `oidc.WriteDoc`, TTL-bounded). Because the value is
constant per process, caching it per base URL is safe: every base URL
advertises the same region. No store, no per-request resolution.

### Failure modes

| Mode | Behavior |
|---|---|
| Option not wired (default) | Field omitted, `claims_supported` unchanged. Byte-identical; `rootcov2_discovery_test.go` passes untouched. |
| Option wired, middleware NOT wired | Discovery advertises a region the tokens don't carry — a lie that would make an RS gate (decision 3) fail closed on every token. Mitigation: a Mount-time `logger.Warn` when `servingRegionAdvertisement != "" && regionResolver == nil`. Fail-open (discovery still serves), loud in logs. |
| Header-resolver deployment wires it anyway | Same warning path; doc comment forbids it. The option is the operator's explicit pin — the design does not add a hard gate (matches the nil-discipline of every other With* option). |
| Discovery cache TTL | Advertised value is static, so a stale cached body is never stale w.r.t. the region. |
| Signed metadata | Auto-covered; the signature binds the advertised region to the doc — an RS can trust the field cryptographically. |

### What could break the design

- **`server_discovery_config.go` is at 500 lines.** The call-line insertion
  requires a compensating one-line reduction in the same file. If review
  rejects comment compression, the fallback is to move one existing small
  helper (e.g. `baseAdvertisedGrants`, 11 lines) into
  `server_discovery_cache.go` — still net-zero on file count, no ceiling
  issue (295 + 11 = 306).
- **`applyStaticClaimsAndSecurity` overwrite ordering** is the classic bug:
  wiring the append BEFORE that call silently no-ops (ClaimsSupported
  reassigned). The apply-chain position is pinned in the code, and the
  acceptance test asserts `claims_supported` contains `serving_region` when
  wired.
- **RP-requested claims (§5.5) interplay**: `claims_supported` advertising
  `serving_region` may invite RPs to REQUEST it via the `claims` parameter
  for userinfo. It is server-stamped on tokens only — it is NOT a userinfo
  attribute and will not appear in `/userinfo` responses. The openapi
  description must say "present on access + ID tokens; not available via
  userinfo" to avoid a support bug.
- **Discovery byte-identity**: the option's zero value must not touch the
  struct or the append; the existing discovery tests are the regression net.
- **`WithServingRegionAdvertisement` vs `WithRegionMiddleware` decoupling**:
  no compile-time coupling exists. The Mount-time warning is the only guard;
  an operator who ignores it gets fail-closed RS gates, which is the safe
  direction (deny, not leak).

---

## 决策 3 — RS SDK typed claim + opt-in region gate

`serving_region` becomes a typed field on `interfaces/ssoclient/rs` `Claims`,
with an opt-in `Config.AllowedServingRegions` gate applied in BOTH validation
modes (local JWT and introspection), mapped to HTTP 403 as a governance
denial.

### API surface

All in `interfaces/ssoclient/rs` (leaf SDK, ample headroom: `claims.go` 152,
`validate.go` 110, `introspect.go` 133, `rs.go` 170, `middleware.go` 155,
`errors.go` 73):

1. `claims.go`: `Claims.ServingRegion string`, `wireClaims.ServingRegion
   string json:"serving_region"`, `parseClaims` maps it, and
   `Claims.HasServingRegion() bool` mirroring `HasAudience` (reports
   non-empty).
2. `rs.go`: `Config.AllowedServingRegions []string` — opt-in; empty = gate
   skipped (byte-identical). Doc comment: "when non-empty, the token's
   `serving_region` MUST be present and in this set; a token without the
   claim is rejected (fail-closed) — this expresses 'this deployment only
   serves tokens minted by these regions'."
3. `errors.go`: `ErrServingRegionMismatch = errors.New("rs: serving region
   mismatch")` — governance sentinel, slotted beside `ErrAudienceMismatch`.
4. `validate.go` — local gate, at the END of `validateClaims` (after the
   identity/time gates, so a garbage/expired token still reports its
   higher-priority sentinel):

```go
if len(cfg.AllowedServingRegions) > 0 && !c.HasServingRegionIn(cfg.AllowedServingRegions) {
    return fmt.Errorf("%w: serving_region %q", ErrServingRegionMismatch, c.ServingRegion)
}
```

5. `introspect.go` — two edits:
   - The `Claims{...}` literal in `ValidateTokenWithIntrospect` gains
     `ServingRegion: w.ServingRegion`. **The `wireIntrospection` embed alone
     is NOT sufficient** — the projection literal is explicit field-by-field
     (verified); forgetting this line makes the remote gate a silent no-op
     while the local gate enforces. A test must pin both.
   - `validateIntrospectedClaims` gains the same gate. RFC 7662 makes
     optional claims optional: `iss`/`aud`/`exp` are enforced only when
     present — but `serving_region` FAILS CLOSED when configured: an AS that
     doesn't echo it (older AS, or an opaque issuer) must deny, because the
     operator declared a region-constrained deployment. This asymmetry is
     deliberate and documented.
6. `middleware.go` — `writeChallenge` branches BEFORE the 401:

```go
if errors.Is(err, ErrServingRegionMismatch) {
    // Governance denial, not a token-validity failure: 403, no bearer
    // challenge — mirrors the AS's region_not_allowed discipline
    // (server_tenant_residency.go). no-store headers stay set.
    w.Header().Set(headerContentType, contentTypeJSON)
    w.WriteHeader(http.StatusForbidden)
    _, _ = w.Write([]byte(`{"error":"region_not_allowed"}`))
    return
}
```

`challengeDescription` stays untouched (region mismatch never reaches it).
The DPoP path needs nothing: `ValidateTokenWithDPoP` wraps
`validateByMode`, and `errors.Is` carries the sentinel through the wrap.

### Storage model

Config-only, zero storage: `AllowedServingRegions` is a value on the RS's
`Config`, compared against the token's claim. Nothing cached, nothing
persisted.

### Failure modes

| Mode | Behavior |
|---|---|
| Config empty (default) | Gate skipped entirely; existing `validate_test.go` / `introspect_test.go` pass unchanged. |
| Token without the claim + configured gate | `ErrServingRegionMismatch` — fail-closed by design; an operator who pins regions cannot accept unverifiable provenance. |
| Mismatched region | Same sentinel; exact string match (region IDs are opaque, case-sensitive). |
| Old AS not echoing `serving_region` at introspection | Fail-closed when configured — the documented rollout-order hazard (below). |
| DPoP-bound token | Sentinels survive `ValidateTokenWithDPoP` wrapping; 403 mapping applies identically. |
| Oracle safety | The 403 fires only AFTER full validation (signature/typ/iss/aud/exp) — an attacker cannot probe the gate with a garbage token, mirroring the AS's "token is valid, so NOT a 401" rule. |

### What could break the design

- **The two-gate symmetry trap**: the local gate in `validateClaims` and the
  remote gate in `validateIntrospectedClaims` are separate code paths with
  separate tests. `validateIntrospectedClaims` currently checks `Issuer != ""
  && ...` — the region gate must be unconditional-on-presence (fail-closed),
  a different shape from its neighbors; a copy-paste of the `Issuer` pattern
  would silently fail OPEN. The acceptance tests (missing claim + configured
  gate ⇒ sentinel, in BOTH modes) are the net.
- **`wireIntrospection` embed ≠ populated `Claims`**: the field must be
  copied in the literal in `ValidateTokenWithIntrospect`. A test asserting
  `claims.ServingRegion == "eu-west-1"` from a parsed introspection body
  catches the omission.
- **403-vs-401 discipline**: `writeChallenge` is shared by the no-credentials
  path (`err == nil`) and the failure path. The region branch must sit after
  the no-store headers (kept for both) but before the `WWW-Authenticate`
  write, and must NOT emit a challenge — the AS's `region_not_allowed` 403 is
  challenge-less (`authzErrorBody`). Existing middleware tests asserting 401 +
  challenge for invalid tokens stay untouched.
- **Rollout order is load-bearing**: `AllowedServingRegions` must be enabled
  only after the AS fleet mints/echoes the claim (decision 1) — otherwise
  every token in a region-pinned deployment is rejected. The doc comment and
  error-codes row state this explicitly.
- **Semantic asymmetry with the AS read-gate**: the AS's
  `residencyDeniedForAccess` gates the CALLING region against the tenant's
  policy; the RS gate gates the MINT region against the deployment's
  allowlist. They are complementary, not redundant: the RS cannot observe the
  caller's region, only the token's provenance. The design doc for the SDK
  must say this, or operators will "fix" the RS gate by removing it after it
  correctly denies a cross-region-minted token.
- **Refresh rotation interaction**: a rotated token carries a NEW region
  (mint-time semantics, decision 1). An RS pinned to one region will deny a
  token whose rotation happened elsewhere — correct per the model, but the
  error-codes row should mention rotation as the common cause.

---

## Cross-cutting: contract docs, tests, rollout order

**Contract docs (same change, AGENTS.md §5.6):**

- `docs/openapi.yaml`: login-response `serving_region` description gains "also
  rides issued access + ID tokens"; `OpenIDConfiguration` schema gains the
  extension property ("present only when the server advertises a pinned
  serving region"; example `eu-west-1`); id_token / access-token claim
  schemas gain `serving_region`.
- `docs/error-codes.md`: `region_not_allowed` disposition gains "see the
  discovery `serving_region` field; enforce at the resource-server boundary
  with the rs SDK `AllowedServingRegions` gate".
- `docs/feature-matrix.md` row 150 (Multi-region data residency) extended
  with token-claim / discovery / RS-gate coverage.
- No metrics/audit changes (direction 1); `region.serving` audit key
  unchanged.

**Test plan** (beside the code, per spec acceptance checks):

- Issuer round-trip (Ed25519 + ECDSA + RSA): mint with
  `Subject.ServingRegion="eu-west-1"` ⇒ decoded payload has the claim; empty
  ⇒ absent. `claimsFromPayload` round-trip; introspection body echo.
- §5.5 immunity: login with `claims` parameter ⇒ both tokens still carry the
  field.
- Discovery: wired option ⇒ field + `claims_supported` entry + signed_metadata
  verifies; unwired ⇒ byte-identical (`rootcov2_discovery_test.go` unchanged).
- RS: four-way matrix (local/remote × in-set/out-of-set/missing-claim/empty
  config); middleware 403 without challenge vs 401 unchanged.
- E2E in `test/` (`package ssotest`, residency-fixture pattern): pinned
  `eu-west-1` login ⇒ decode both tokens; auth-code exchange survival; refresh
  rotation re-stamps; RS SDK accepts in-region, denies out-of-region.

**Rollout order:** decision 1 (claims) → decision 2 (discovery) → decision 3
(RS gate). Decision 3's config is safe only after the AS fleet carries
decision 1.

**Verification per AGENTS.md:** `go build ./... && go vet ./...` after every
edit; `go test -run 'TestMaintainability_|TestArchitecture_' .` (the budget
tests are the ones this design's placements are tuned to);
`go test ./... -race`; `go test ./test/ -run TestE2E -v`; `make ci` before
handoff.
