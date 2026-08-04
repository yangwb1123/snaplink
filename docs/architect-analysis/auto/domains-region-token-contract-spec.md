# domains/region — 扩展方向 2 需求规格：把 serving region 写进令牌与发现契约

Scope: expansion direction 2 from `docs/auto/domains-region-analysis.md` —
「把 serving region 写进令牌与发现契约：让驻留约束延伸到资源服务器边界」.
The serving region today is a login-response UX marker, an audit
`region.serving` metadata value, and an in-process enforcement input. It is
not in the ID token, not in the RFC 9068 access token, and not in OIDC
discovery — so the residency boundary ends at the SSO server itself.

This spec contains exactly three evidence-backed improvements:

1.  `serving_region` claim on access + ID tokens (mint-region evidence rides
    the token).
2.  OIDC discovery advertises the serving region (machine-readable routing
    contract).
3.  RS SDK typed claim + opt-in region gate (the constraint is enforceable at
    the resource-server boundary).

## Preserved invariants (non-negotiable)

- Oracle-safe semantics and the fail-open decision ladder in
  `interfaces/sso/server_tenant_residency.go` are NOT touched. The claim is
  evidence; server-side gates (`residencyGateLogin`,
  `residencyGateTokenGrant`, `residencyDeniedForAccess`) behave byte-identically.
- `/token/introspect` stays deliberately ungated by residency
  (`server_tenant_residency.go:156-159` documents why the CALLING RS's region
  is not the data-serving region). Echoing the token's MINT region is
  compatible: it is the token's own provenance, not the caller's region.
- Zero-value byte-identity: no region middleware wired ⇒ no claim, no
  discovery field, no RS gate. Every existing test stays green unchanged.
- `shared/core` imports no Snaplink package (AGENTS.md §4), so claim fields on
  `core.Subject` / `core.TokenClaims` are plain `string`, never `region.ID`.
- `interfaces/sso` is at its 60-file ceiling: all interface-layer changes
  extend existing files (`options_misc.go`, `server_discovery_config.go`), no
  new files.
- All three signers (Ed25519/ECDSA/RSA) share `buildAccessPayload`,
  `claimsFromPayload`, and `ed25519IDPayload` (`infrastructure/defaultimpl/`),
  so one projection change covers every issuer — no per-alg drift.

---

## 决策 1：access token / ID token 增加 `serving_region` claim

### Name

Mint-region evidence on the token: a first-class `serving_region` claim on
RFC 9068 access tokens and OIDC ID tokens, stamped by every token-minting
grant path.

### Problem

The serving region is the primary evidence of WHERE a token was minted, but
it exists only in (a) the login response map
(`server_finish_login.go` `applyLoginResponseExtras`, comment: "the
serving_region marker (UX, not a security signal)"), (b) audit metadata
(`platform/audit/handler_helpers.go` `metaKeyRegionServing`), and (c) the
per-request middleware stash (`domains/region/middleware.go`
`FromHandlerContext`). The tokens themselves carry nothing. Consequences:

- A token minted in `eu-west-1` is presented to a `us-east` resource server
  with zero verifiable mint-region evidence; the RS SDK's local-validation
  mode (`interfaces/ssoclient/rs`) validates signature/iss/aud/exp only.
- The server's own read gate (`residencyDeniedForAccess`,
  `server_tenant_residency.go:387-412`) must resolve the tenant via
  `claims.ClientID → clientStore.Get → Client.TenantID` — an extra store
  round-trip per read, and a binding that is absent for tokens without a
  `client_id`.
- Audit at the RS has no machine-readable provenance to correlate with
  `region.serving` server-side events.

### Evidence

- `interfaces/sso/server_finish_login.go:319-330` —
  `applyLoginResponseExtras`; `serving_region` written only into the response
  map; self-described "UX, not a security signal".
- `shared/core/consts_wire.go` `KeyServingRegion` — the only wire key;
  reused as the claim name (no new const needed).
- `shared/core/types_token.go:152` `type Subject struct` — carries
  `ClientID`/`AuthTime`/`AMR`/`ACR`/`SID` per RFC 9068 §2.2, no region.
- `infrastructure/defaultimpl/issue_payload.go:26-38` `buildAccessPayload` +
  `ed25519_types.go:15-50` `ed25519Payload` — the RFC 9068 claim projection
  (no region field).
- `infrastructure/defaultimpl/validate_claims.go:20` `claimsFromPayload` —
  payload → `sso.TokenClaims` mapping (no region field).
- `protocols/oidc/types.go:15` `IDTokenRequest` — `SID`/`AMR`/`ACR`/`AZP`
  precedent fields; no region.
- `protocols/oidc/oidcsupport/idtoken_claims.go:17` `ProjectIDTokenClaims` —
  OIDC §5.5 `claims` parameter FILTERS the extra-claims map; a server-stamped
  region must be a first-class payload field, never a `Claims`-map entry
  (AGENTS.md §2: "OIDC requested claims survive the AuthCode store and token
  projection" — the inverse: server claims must survive RP-requested
  projection).
- Mint sites that must stamp it (all run inside the HandlerContext pipeline;
  region middleware is mounted globally at `interfaces/sso/server_routes.go:132`):
  `interfaces/sso/server_login.go:112` (`mintAccessToken`),
  `interfaces/sso/server_finish_login.go` `emitLoginIDToken`,
  `interfaces/sso/server_native_sso.go:190`,
  `internal/handler/tokengrant/token_authcode.go:107`,
  `internal/handler/tokengrant/token_refresh.go:246`, plus CIBA / device /
  token-exchange / client_credentials / JWT+SAML bearer in the same package.
- Introspection echo point: `protocols/oauth/handle_introspect.go:366`
  `populateAccessIntrospectionBody` — mirrors how `client_id`/`jti`/`sid`
  are echoed into the RFC 7662 body.

### Proposed behavior

1. `core.Subject.ServingRegion string` (input) and
   `core.TokenClaims.ServingRegion string json:"serving_region,omitempty"`
   (validated view) in `shared/core/types_token.go`.
2. `ed25519Payload.ServingRegion string json:"serving_region,omitempty"` —
   set in `buildAccessPayload`, mapped in `claimsFromPayload`.
3. `populateAccessIntrospectionBody` echoes it (RFC 7662 extension echo,
   same discipline as `client_id`/`jti`).
4. `oidc.IDTokenRequest.ServingRegion string`; all three ID issuers
   (`ed25519_issue.go` / `ecdsa_issue.go` / `rsa_issue.go` `IssueIDToken`)
   stamp a first-class `serving_region` field on `ed25519IDPayload`
   (`ed25519_types.go:132-150`) — NOT via `Extra` (`json:"ext"`), so §5.5
   projection can never drop it.
5. Every mint site passes `region.FromHandlerContext(ctx)`; empty ⇒ claim
   omitted (byte-identical when no region middleware). Break-glass
   (`accessors_feature_gates.go:257`) and admin-minted tokens
   (`interfaces/grpcserver/grpcadmin/admin_tokens.go:174`) run outside the
   region pipeline and keep the claim empty — documented as "unconstrained",
   matching `region.ID("")` semantics.
6. Refresh rotation stamps the region that SERVED the refresh — mint-time
   semantics, consistent with audit `region.serving` being per-event.

### Acceptance check

- Issuer unit tests (each of Ed25519/ECDSA/RSA): token minted with
  `Subject.ServingRegion="eu-west-1"` decodes with `serving_region` present;
  empty input ⇒ claim absent; existing issuer tests unchanged.
- `claimsFromPayload` round-trip: `TokenClaims.ServingRegion` populated;
  introspection body from a minted token includes `serving_region`.
- §5.5 immunity test: login with a `claims` parameter (id_token + access
  token) still carries `serving_region` on both tokens.
- E2E (`test/region_residency_test.go` fixture pattern): pinned
  `eu-west-1` login ⇒ decode the response's access token + id_token and
  assert `serving_region="eu-west-1"`; auth-code exchange at `/token`
  ⇒ claim survives; refresh rotation ⇒ new mint carries the current region.

---

## 决策 2：OIDC discovery 广告 serving region

### Name

Discovery contract: an opt-in `serving_region` extension field on
`ProviderMetadata` plus `claims_supported` membership, emitted only when the
deployment's region is static (pinned).

### Problem

`docs/error-codes.md:88-89` tells a client hit with `region_not_allowed` to
"Route the request to an allowed region" — but there is no machine-readable
way to learn which region this deployment serves. Discovery carries no
region field, so an RP/RS cannot branch on region, cannot auto-select an
endpoint, and cannot pre-empt the 403. The `serving_region` response field
exists ONLY in the login-response schema (`docs/openapi.yaml:12156`) and is
documented there as "A UX/governance hint, not a security signal" — no
contract advertises it.

### Evidence

- `protocols/oidc/metadata.go:14` `type ProviderMetadata struct` — the full
  discovery surface; no region field anywhere (checked every field).
- `interfaces/sso/server_discovery_config.go:102` `buildOIDCConfiguration`
  and `:381` `applyStaticClaimsAndSecurity` — `cfg.ClaimsSupported` is a
  hardcoded literal list without `serving_region`.
- `docs/openapi.yaml:12156` — `serving_region` only in the login-response
  schema; `OpenIDConfiguration` schema (`docs/openapi.yaml:15243`) has no
  region property.
- `docs/error-codes.md:88-89` — `region_not_allowed` disposition assumes the
  client can find an allowed region.
- Cache constraint: the discovery doc is cached per request base URL
  (`interfaces/sso/server_discovery.go` `discoveryDocEntry`,
  `writeDiscoveryDoc`, `WithDiscoveryDocCacheTTL`) — an advertised region
  must be deployment-static, so only a PINNED region may be advertised;
  header-resolver-only deployments (region varies per request) must omit it.
- Precedent for opt-in metadata: `WithOperatorMetadata` →
  `OpPolicyURI`/`OpTosURI`/`ServiceDocumentation`, all `omitempty`
  (`protocols/oidc/metadata.go`), and `MFAEndpoint` which is documented as a
  "SnapLink extension; non-standard" field — the same documentation style
  applies here.

### Proposed behavior

1. `oidc.ProviderMetadata.ServingRegion string json:"serving_region,omitempty"`
   — a SnapLink extension field, documented as such (mirroring
   `MFAEndpoint`'s documentation block).
2. New opt-in option `WithServingRegionAdvertisement(id region.ID)` on
   `Server` (`interfaces/sso/options_misc.go`, alongside
   `WithRegionMiddleware`); nil-default ⇒ field absent, byte-identical.
3. `buildOIDCConfiguration` calls a new `applyServingRegionMetadata(&cfg)`
   which sets the field and appends `"serving_region"` to
   `ClaimsSupported` — only when the option is wired. Because the value is
   process-static, it is safe inside the per-base-URL discovery cache.
4. `signed_metadata` (`signDiscoveryMetadata`,
   `server_discovery_config.go:27`) covers the new field automatically since
   it signs the built `cfg`.
5. Contract docs in the same change: `OpenIDConfiguration` schema property
   (example `eu-west-1`; "present only when the server advertises a pinned
   serving region"), `region_not_allowed` row in `docs/error-codes.md`
   gains "see the discovery `serving_region` field", feature-matrix row
   `docs/feature-matrix.md:150`.

### Acceptance check

- Discovery JSON (`/.well-known/openid-configuration` + RFC 8414 alias)
  includes `serving_region` and lists it in `claims_supported` when the
  option is wired; byte-identical output without it (existing
  `rootcov2_discovery_test.go` passes unchanged).
- `signed_metadata` verifies against the same document including the field.
- E2E: the residency fixture (pinned `eu-west-1` resolver +
  `WithServingRegionAdvertisement("eu-west-1")`) asserts the field on the
  live discovery response.

---

## 决策 3：RS SDK 类型化 claim 与可选 region 门（驻留约束延伸到资源服务器边界）

### Name

Resource-server enforcement: `serving_region` becomes a typed field on
`interfaces/ssoclient/rs` `Claims`, with an opt-in
`Config.AllowedServingRegions` gate applied in BOTH validation modes
(local JWT and introspection).

### Problem

The mesh ext_authz read gate (`interfaces/sso/mesh_authz.go:197`) and the
`/userinfo` gate (`protocols/oidc/handle_userinfo.go:57`) enforce residency
only while the request is still inside the SSO server. A microservice using
the RS SDK's LOCAL validation mode (`ValidateToken`) has the AS off the
request path by design — and its `Claims` projection has no region field:
an unknown claim only lands in `Raw` (`interfaces/ssoclient/rs/claims.go`).
So even after Decision 1 puts `serving_region` on the token, the SDK cannot
act on it in typed form, and there is no way to express "this deployment
only serves eu-west-1-minted tokens" — the error-codes advice ("Route the
request to an allowed region") remains un-actionable at the boundary where
the tenant's data actually lives.

### Evidence

- `interfaces/ssoclient/rs/claims.go` — `Claims` struct + `wireClaims`
  (typed projection ends at `client_id`/`scope`/`cnf`; everything else is
  `Raw map[string]any`); `HasAudience` helper precedent.
- `interfaces/ssoclient/rs/rs.go` — `Config` (package doc: "Local
  (stateless) … the AS is NOT on the per-request path"; two validation
  modes).
- `interfaces/ssoclient/rs/validate.go` — `ValidateToken` local mode;
  `validateClaims(claims, cfg, time.Now())` is the claim-gate point (after
  typ/alg/signature gates).
- `interfaces/ssoclient/rs/introspect.go:33` `ValidateTokenWithIntrospect`,
  `:122` `validateIntrospectedClaims`, `:70` `wireIntrospection` (embeds
  `wireClaims`, so one field addition covers both modes).
- `interfaces/ssoclient/rs/errors.go` — sentinel taxonomy
  (`ErrIssuerMismatch`, `ErrAudienceMismatch`, `ErrTokenExpired` …); a new
  governance sentinel slots in here.
- AS-side 403-vs-401 precedent: `server_tenant_residency.go` `mapResidencyError`
  and the `residencyDeniedForAccess` comment "the token is valid, so NOT a
  401 invalid_token bearer challenge — a policy denial is a distinct
  condition". The RS must mirror this: region mismatch is a governance
  denial (403), not a token-validity failure (401).

### Proposed behavior

1. `rs.Claims.ServingRegion string` + `wireClaims.ServingRegion
   json:"serving_region"` + `Claims.HasServingRegion() bool` (mirrors
   `HasAudience`). Because `wireIntrospection` embeds `wireClaims`, local
   and remote modes both populate it.
2. `rs.Config.AllowedServingRegions []string` (opt-in). Gate in
   `validateClaims` (local) AND `validateIntrospectedClaims` (remote):
   when non-empty, the token's `serving_region` MUST be present and in the
   set, else the new sentinel `ErrServingRegionMismatch`
   (`interfaces/ssoclient/rs/errors.go`) is returned. Fail-closed when
   configured (an operator who declares a region-constrained deployment
   cannot accept a token with no verifiable mint region); zero-value config
   ⇒ no gate, byte-identical.
3. `interfaces/ssoclient/rs/middleware.go` error mapping maps
   `ErrServingRegionMismatch` to HTTP 403 (governance denial) with a
   `region_not_allowed`-style description, keeping 401 challenges for
   token-validity failures — mirroring the AS's two-code discipline.
4. Docs: package doc for `rs` gains the region-gate section; error-codes row
   updated to name the RS SDK gate as the enforcement point at the boundary.

### Acceptance check

- rs unit tests: token minted with `serving_region="eu-west-1"` +
  `Config.AllowedServingRegions=["eu-west-1"]` ⇒ `ValidateToken` OK; token
  with `"us-east-1"` ⇒ `ErrServingRegionMismatch`; token WITHOUT the claim +
  non-empty config ⇒ `ErrServingRegionMismatch` (fail-closed); empty config
  ⇒ all pass (existing `validate_test.go` / `introspect_test.go` unchanged).
- Remote mode: introspection response (echoed per Decision 1) parsed by
  `ValidateTokenWithIntrospect` hits the same gate.
- Middleware test: HTTP status 403 and no `WWW-Authenticate` challenge for
  `ErrServingRegionMismatch`; 401 unchanged for invalid-token errors.
- E2E: RS SDK validates a token minted by the pinned-region residency
  fixture against a matching `AllowedServingRegions`; a mismatched config
  denies.

---

## Cross-cutting contract updates (AGENTS.md §5.6)

- `docs/openapi.yaml`: access-token / id_token schemas gain the
  `serving_region` claim; `OpenIDConfiguration` gains the extension
  property; login-response `serving_region` description updated to note it
  also rides issued tokens.
- `docs/error-codes.md`: `region_not_allowed` disposition references the
  discovery field + RS gate.
- `docs/feature-matrix.md` row 150 (Multi-region data residency) extended
  with token-claim / discovery / RS-gate coverage.
- No metrics/audit changes in this direction (that is direction 1); the
  existing `region.serving` audit key is unchanged.
