# Token-policy tenant/subject selectors — identity-protocol review

Reviewer role: identity-protocol expert (`ai-dev/prompts/protocol_expert.md`).
Input: the direction-3 design in
`docs/auto/domains-tokenpolicy-direction3-design.md`, re-verified against
current handlers, discovery metadata, OpenAPI, config-reference, and tests at
HEAD `ff690260`. Scope is the standards the design actually touches (OAuth 2.0
token issuance/rotation, OIDC prompt=none + ID-token pair, RFC 9068 claim
surface, RFC 7662 introspection, RFC 8693 exchange, RFC 8628 device, admin
governance API). SAML, SCIM, CAEP/SSF, WebAuthn, DPoP/mTLS binding, PKCE, and
JARM are out of scope: the design changes none of them.

Checks that actually ran for this revision: **none** (design-stage, read-only —
no `.go` files changed, no gates run, per the direction-3 convention). Every
claim below is **Verified** by source inspection at `ff690260`; the QA review's
test inventory (`go build/vet`, maintainability+architecture, `-race` on the
owning packages, `make ci` with its pre-existing fmt failure) is adopted as
supplementary evidence at the same revision.

---

## 1. Protocol/profile scope and authoritative references

| Protocol | Surface the design touches | Authoritative reference |
|---|---|---|
| OAuth 2.0 | `/token` grant dispatch (scope-combo deny), refresh rotation (depth deny), `expires_in` in token responses | RFC 6749 §5.1 (response), §5.2 (errors), §6 (refresh); OAuth 2.1 refresh-token rotation (profile) |
| OIDC Core 1.0 | `prompt=none` silent renewal mint (authz endpoint), ID-token/access-token pair, `at_hash` | OIDC Core §3.1.2.1, §3.1.2.6, §3.1.3.6 |
| RFC 9068 | JWT access-token claim set: `exp`/`iat`/`sub`/`client_id`/`jti`/`act`; auth-context preservation | RFC 9068 §2.2 |
| RFC 7662 | Introspection `active` + custom `renew_after` member | RFC 7662 §2.2 |
| RFC 8693 | Token exchange + agent-delegation mint, `act` chain | RFC 8693 §4.1 |
| RFC 8628 | Device-authorization `expires_in` (device-code lifetime) | RFC 8628 §3.2 |
| RFC 8414 / OIDC Discovery | Discovery metadata (unchanged by design) | RFC 8414 §2; OIDC Discovery §3 |
| RFC 7523 / SAML2 bearer / CIBA | Mint sites funnelled through the clamp seam | RFC 7523 §3; SAML 2.0 Profile for OAuth 2.0; RFC 8628/CIBA grant |
| Admin governance API | `GET /api/v1/admin/token-policies` item schema | `docs/openapi.yaml` (admin section) |

Profile notes: token policies are an opt-in stock-binary capability
(`sso.WithTokenPolicy` / `token_policies.*` config), default-off and
byte-identical when unwired. The wire contract the design preserves: denies
collapse to generic `invalid_scope` / `invalid_grant`, no new `Err*`, no new
claims, no new endpoints. **No OIDF certification is claimed anywhere in the
tree** (`docs/sso/oidc-conformance.md` states "no recorded OpenID Foundation
certification listing"; feature-matrix.md:86 says "Implemented" does not mean
OpenID Certified) — this review likewise claims none.

---

## 2. Compliance matrix

Requirement levels: **MUST** / **SHOULD** / **MAY** from the cited sections;
"extension" = permitted non-standard member; "internal" = not on the wire.

| # | Section / requirement | Level | Implementation evidence (HEAD ff690260) | Status | Deviation | Test |
|---|---|---|---|---|---|---|
| 1 | RFC 6749 §5.1 — `expires_in` is the lifetime of the access token in the response | SHOULD (RECOMMENDED; must be truthful when present) | `ClampingIssuer.Issue` mutates `subject.TTL` before delegating (`domains/tokenpolicy/clamp_issuer.go:44-52`); issuers derive both `ExpiresIn` and JWT `exp` from `effectiveAccessTTL(subject.TTL, …)` (`infrastructure/defaultimpl/ed25519_issue.go`); every grant response emits `core.KeyExpiresIn: token.ExpiresIn` | **Compliant — preserved by the design** | None; tenant rules ride the same seam | `TestRcov_TokenPolicy_MaxTTLClampsIssuedToken` asserts `expires_in == 15` on the real `/token` path (`interfaces/sso/rootcov_token_policy_test.go:67`); design plan adds tenant-rule clamp tests per grant |
| 2 | RFC 9068 §2.2 / RFC 7519 §4.1.4 — `exp`, `iat`, `sub`, `aud`, `jti`, `client_id` claim set | MUST (per RFC 9068 §2.2) | `buildAccessPayload` assembles claims by explicit enumeration (`infrastructure/defaultimpl/issue_payload.go:26-41`); `ed25519Payload` has no tenant field; ID tokens are built from a separate `IDTokenRequest` struct | **Compliant — claim surface sealed** | None; `core.Subject.TenantID` is policy input only, never a claim | Design plan: claim-set pin (access token for a tenant-bound client carries no `tenant_id`) |
| 3 | RFC 6749 §5.2 — error responses; no oracle about which policy tripped | MUST (AGENTS.md §3) | Denies surface `wireCodeForPolicyDeny` output (`interfaces/sso/server_helpers.go:110-115`); `DenyReason` is metric/audit-only by package contract (`domains/tokenpolicy/tokenpolicy.go`) | **Compliant** | None | `TestRcov_TokenPolicy_ScopeComboDenied` (generic `invalid_scope`); `TestEvaluate_DenyReasonDeterministic` |
| 4 | RFC 6749 §6 / OAuth 2.1 rotation — refresh family depth deny | profile | `EnforceRefreshDepthPolicy(ctx, client.ID, info.UserID, grantScopes, info.Generation)` at `internal/handler/tokengrant/token_refresh.go:116`, collapse to `invalid_grant` | **Compliant** | Refresh-seam role selectors are a documented no-op (roles empty ⇒ no match); `subject`/`tenant_id` work | Design plan: refresh-depth tenant rule fires with `client.TenantID` threaded |
| 5 | OIDC Core §3.1.2.1 — `prompt=none` issues a bearer **without fresh end-user authentication** | MUST (flow semantics) | `HandleSilentRenewal` mints via `IssuerForClient` → `NewClampingIssuer` (`protocols/oidc/handle_silent_renewal.go:210`); stock-reachable via `interfaces/sso/server_login_resolve.go:169` | **Deviation (gap)** — tenant `max_ttl` rules silently never clamp this path: no `TenantID` stamp, no closure-captured tenant | Tenant-scoped TTL governance — the exact control that should bound a no-reauth issuance — is inert here | None today; design plan must add silent-renewal clamp tests (F1) |
| 6 | OIDC Core §3.1.3.6 — `at_hash` binds ID token to access token | MUST when both issued | `at_hash` computed at every ID-token mint (`infrastructure/defaultimpl/ed25519_issue.go` IssueIDToken) | **Compliant** | None | Existing ID-token tests |
| 7 | OIDC Core §3.1.3.6 pair semantics — ID-token lifetime vs clamped access token | no MUST (only `at_hash` binding) | Access token clamped to tenant `max_ttl`; ID-token TTL is the issuer default (`IDTokenRequest` at `token_authcode.go:258` sets no TTL) | **Partial** — pre-existing asymmetry (already true for global `max_ttl` rules), extended to tenant rules; not a spec violation | Should be stated in config-reference + pinned | Design plan: extend the claim-set pin with "ID-token TTL unchanged by tenant clamp" (F3) |
| 8 | RFC 7662 §2.2 — `active` + additional response members | MUST (`active`); MAY (extensions) | `IntrospectionRenewExceeded` (`interfaces/sso/sso_protocol.go:477`) flips a past-renew-threshold token to `active:false`; `renew_after` is a documented custom member (`shared/core/consts_wire.go:165-167`, openapi.yaml:12783) | **Compliant** (extension permitted) | Tenant-scoped `require_renew_after` can never fire here — the introspection request carries no tenant by Decision 5, and `PolicyInput` at this site has none | Document in the config-reference liveness matrix (F2) |
| 9 | RFC 8414 §2 / OIDC Discovery — metadata derived from server state | MUST (truthful metadata) | No token-lifetime member exists in either standard; discovery doc renders server state (`interfaces/sso/server_discovery.go`, `protocols/oidc/metadata.go`) | **Compliant — no discovery change needed or possible** | None | n/a |
| 10 | RFC 8693 §4.1 — `act` chain, per-hop TTL | MUST (chain semantics) | Token exchange + agent delegation mint through the clamp seam; clamp is downward-only (`clampTTL`), so a hop TTL can never exceed the chain ceiling (`internal/handler/tokengrant/token_exchange.go:132`) | **Compliant** | Agent-delegation mint has no `TenantID` stamp (SDK surface, not stock) | Design plan: agent-delegation clamp test (F1/F6) |
| 11 | RFC 8628 §3.2 — device-authorization `expires_in` is the **device-code** lifetime | MUST | `server_device.go:440-448` computes it from the stored code's `ExpiresAt`, independent of access-token policy | **Compliant** — policy clamp cannot leak onto the device-code response | None | Existing device tests |
| 12 | RFC 7523 §3 / SAML2 bearer / CIBA mints — uniform clamp coverage | MUST (uniformity is the feature's own contract) | All funnel through `issuerForClient` → `NewClampingIssuer` (`interfaces/sso/server_helpers.go:66-67`) | **Partial** — see F1: 3 of 13 reachable mint sites cannot carry the tenant stamp under the design as written | Tenant rules inert at silent renewal, break-glass, agent delegation | Design plan: per-site clamp tests for all 13 sites (F1) |
| 13 | Admin API — item schema carries the new selector fields | internal (OpenAPI contract) | `GET /api/v1/admin/token-policies` serializes `Policy` verbatim (`domains/tokenpolicy/admin.go`); schema at `docs/openapi.yaml:6866-6884` (the design cites `:6836`, which is the GET description — see F4) | **Compliant** (content); line cite drift | `subject` selector matches the **local** subject ID, which for pairwise clients differs from the token `sub` — the OpenAPI description should say so (design only promises config-reference does) | `make ci` OpenAPI check; design plan: admin round-trip test (QA M5) |
| 14 | Config surface — strict YAML + `Validate` | internal | Unknown fields/bare-`*`/invalid roles fail load (conditionalaccess precedent); deliberate behavior change: `other: 1` no longer parses as "no policies" (`TestParseYAML_Empty`, `domains/tokenpolicy/yaml_test.go:59-72`) | **Compliant** (internal) | Deploy discipline: old bundles with unknown keys fail boot; previously-inert `client_id: "prefix*"` rules silently activate on the new binary (SRE F3) | `validate_test.go` + updated `yaml_test.go` in the design plan |

---

## 3. Findings

### F1 — High — The mint-site census is wrong in the design **and in both prior reviews**: it is 13 reachable sites + 1 template, not 10 (design) or 12 (security/QA)

- **Requirement level**: feature-contract (RFC 6749 §5.1 truthfulness of the clamp; the design's own "uniform seam" claim in `clamp_issuer.go`).
- **Location**: the design's Decision 5 lists 10 sites. The security review adds `handle_silent_renewal.go:210` + `agentidentity/grant.go:185` (missing break-glass); the QA review adds `agentidentity/grant.go:185` + `accessors_feature_gates.go:257` (missing silent renewal). The full non-test census at `ff690260` is: `token_authcode.go:118`, `token_client_credentials.go:40`, `token_refresh.go:247`, `token_device.go:82`, `token_ciba.go:99`, `token_jwt_bearer.go:95`, `token_saml2_bearer.go:103`, `token_exchange_stages.go:390`, `server_login.go:112`, `server_native_sso.go:190`, `protocols/oidc/handle_silent_renewal.go:210`, `domains/tokenexchange/agentidentity/grant.go:185`, `interfaces/sso/accessors_feature_gates.go:257`, plus the codegen template `cmd/sso-ctl/generate/templates_handler.go:193`.
- **Interoperability/security impact**: silent renewal (OIDC Core §3.1.2.1) is the authorization-endpoint path that issues a bearer **without fresh authentication** — exactly where a tenant `max_ttl` ceiling is the control an operator would expect to bound the renewed token. Under the design as written, `subject.TenantID` stays `""` there, so the tenant rule silently never clamps (fail-open, but policy-silent). Break-glass is worse than a forgotten stamp: it is **structurally unstampable** — `MintImpersonationToken` calls `s.issuerForClient(nil)` with no client object (`accessors_feature_gates.go:248-257`), so `client.TenantID` does not exist at that site. It must be declared global-rules-only, not "one of the 10".
- **Corrective behavior**: prefer the structural fix the design already has an in-tree precedent for: capture the tenant in the clamp wrapper at resolution time — `pipelineTokenIssuer` already threads `tenantID` the same way (`interfaces/sso/accessors_threat.go:331-338`). A `NewClampingIssuer(ti, store, client.TenantID)` closure inside `issuerForClient` is one code site that makes a forgotten stamp impossible, removes `core.Subject.TenantID` entirely (Decision 5's claim-surface risk disappears with it), and handles break-glass by construction (`nil` client ⇒ `""` tenant ⇒ global rules only). If the stamp approach is kept, stamp all 13 sites + template and add per-site clamp tests, including silent-renewal, agent-delegation, and break-glass (asserting global `max_ttl` still clamps break-glass).
- **Validation step**: `go test ./interfaces/sso/ -run 'TestRcov_TokenPolicy_TenantMaxTTL_SilentRenewal|TestRcov_TokenPolicy_TenantMaxTTL_AgentDelegation|TestRcov_TokenPolicy_TenantMaxTTL_BreakGlass' -count=1` plus a grep census check (`grep -rn "\.Issue(ctx" —include="*.go"` excluding `_test.go`, `IssueIDToken`, and store `Issue` calls must equal the reviewed list).

### F2 — High — Inert selector×dimension combinations are accepted by `Validate` and load silently; one of the five `Evaluate` sites is unnamed in the design

- **Requirement level**: feature-contract (the design's own "no invisible no-op" standard, risk #7); RFC 7662 §2.2 surface.
- **Location**: (a) the clamp seam's `PolicyInput` has no `Subject` (`clamp_issuer.go:44-52`) ⇒ `subject`/`subject_roles` × `max_ttl` never match; (b) the scope-combo seam passes only `clientID`+`scopes` (`server_token.go:168`) ⇒ `subject` × `block_scope_combos` never matches; (c) the fifth site, `IntrospectionRenewExceeded` (`interfaces/sso/sso_protocol.go:477`, called from `protocols/oauth/handle_introspect.go:279`), builds `PolicyInput{ClientID, Scopes, Kind}` with no tenant — and cannot, because Decision 5 deliberately keeps tenant out of the claims. `tenant_id: A, require_renew_after: 0.5` loads, shows in the admin API, and never fires on the one surface that enforces `require_renew_after`.
- **Interoperability/security impact**: operators configure rules that look active and never enforce — the human-vs-machine TTL motivation in the spec is unimplementable as designed, and the introspection gap is on an enforcement surface (RFC 7662 `active:false`), not an advisory one.
- **Corrective behavior**: document every inert (seam × selector) pair in a liveness matrix in `docs/config-reference.md` (including the introspection seam by name), add no-op pin tests per inert pair, and keep `Validate` accepting the combinations only while the matrix exists (roles × `max_active_sessions` is genuinely live at the session seam, so blanket rejection is wrong).
- **Validation step**: table-driven test that for each (seam, selector) pair asserts the documented behavior, e.g. `TestRcov_TokenPolicy_SubjectMaxTTLInert` (rule loads; clamp does not fire; `expires_in` unclamped).

### F3 — Medium — Tenant `max_ttl` clamps the access token but not the paired ID token; pre-existing, extended by the new selector, needs documentation + a pin

- **Requirement level**: OIDC Core §3.1.3.6 (no lifetime-equality MUST — only `at_hash`); the issuer's own documented invariant ("matching access-token lifetime keeps expiration semantics consistent across the pair", `ed25519_issue.go` IssueIDToken comment) is already broken today for global `max_ttl` rules because ID-token mints set no `TTL` (`token_authcode.go:258`) and fall back to the issuer default.
- **Location**: `infrastructure/defaultimpl/ed25519_issue.go` (`effectiveAccessTTL` vs `IssueIDToken` TTL fallback).
- **Interoperability/security impact**: RPs anchoring session state to ID-token `exp` outlive a clamped access token; the asymmetry is not new, but the tenant selector widens its reach and the design's doc sync should state it rather than inherit it silently. Direction is safe (ID token outlives access token, not the reverse).
- **Corrective behavior**: one config-reference sentence in the selector section + extend the claim-set pin: "tenant clamp leaves ID-token TTL unchanged" (`exp` of the pair diverges by design).
- **Validation step**: assertion in the claim-set test that the paired `id_token`'s `exp - iat` equals the issuer default while `expires_in` equals the clamped value.

### F4 — Low — OpenAPI line cite drift in the design

- **Location**: the design says "`docs/openapi.yaml:6836`: the policies item schema"; 6836 is inside the GET operation description — the item schema is at `docs/openapi.yaml:6866-6884`. The sync content itself is correct.
- **Corrective**: fix the cite; also add to the OpenAPI item description that `subject` matches the local subject ID (not the pairwise-projected `sub`) and that a missing `tenant_id` is the global rule — the design only promises that text in config-reference, and the admin API is the other surface an operator reads.
- **Validation step**: `python cli.py openapi check`-equivalent (part of `make ci`).

### F5 — Info — Two mint surfaces sit outside the clamp seam and should be declared, not assumed

- Break-glass tokens *are* clamped by **global** `max_ttl` rules (they pass through `NewClampingIssuer` via `issuerForClient(nil)`); opaque temp tokens (`interfaces/grpcserver/grpcadmin/admin_tokens.go:175`, `domains/authenticators/temp_token.go:81`) never pass the ClampingIssuer and are governance-invisible. Both are pre-existing; the config-reference "uniform across every grant" wording should list them as declared exceptions.
- **Validation step**: a sentence in config-reference + a break-glass clamp assertion (global rule clamps, tenant rule does not) in the F1 test batch.

### F6 — Info — Stock vs SDK reachability must be distinguished in the census

- Silent renewal and break-glass are stock-reachable (`server_login_resolve.go:169`, `options_*`/accessors wired in the stock server). Agent delegation (`WithAgentDelegationGrant`, `interfaces/sso/options_grants.go:416`) is an embedding/SDK option — no reference exists in `cmd/` or `config/` at `ff690260`. The fix list should say so, or a reader will assume the stock binary exposes `delegation_token`.

### Positive controls verified (no change required)

1. **`expires_in` truthfulness (RFC 6749 §5.1)**: clamp mutates `subject.TTL` pre-issuance; `ExpiresIn` and JWT `exp` derive from the same `effectiveAccessTTL` — the response can never advertise a lifetime longer than the clamped token. Existing pin: `expires_in == 15` under a 15s `max_ttl`.
2. **Claim surface sealed (RFC 9068 §2.2)**: `buildAccessPayload` enumerates claims; `ed25519Payload` carries no tenant field; ID tokens are built from a structurally separate `IDTokenRequest` — `Subject.TenantID` cannot leak without an explicit new assignment. The planned claim-set pin locks this.
3. **Oracle safety (RFC 6749 §5.2)**: no new `Err*`, no reason on the wire, no new metrics labels; tenant/subject are evaluation inputs only.
4. **No downgrade at the governance layer**: strictest-wins union means a tenant rule can only tighten a global ceiling (`Evaluate` untouched); `clampTTL` is downward-only — the clamp can never raise a lifetime above a client-configured TTL, the chain ceiling (RFC 8693), or the issuer default.
5. **No cross-surface leak**: device-code `expires_in` (RFC 8628 §3.2) and refresh-token lifetimes are not policy-clamped; `renew_after` is a permitted RFC 7662 §2.2 extension, already documented in openapi.yaml:12783.
6. **Tenant input provenance**: every seam reads `client.TenantID` (record-derived, mismatch-gated at `interfaces/sso/handlers.go:51` before `/token` dispatch), never the header-derived tenant — no forgery surface for policy input.

---

## 4. Priority conformance tests, declared unsupported features, certification evidence

### Priority conformance tests (to land with the code)

1. Per-site tenant clamp matrix — all **13** mint sites + template; assert `expires_in` and JWT `exp` consistency per site; silent-renewal, agent-delegation, and break-glass get explicit global-vs-tenant assertions (F1).
2. Claim-surface pin: access token for a tenant-bound client carries no `tenant_id`; paired ID-token TTL unchanged (F3).
3. Inert-pair liveness pins: subject/roles × `max_ttl`, subject × `block_scope_combos`, tenant × `require_renew_after` at introspection — each asserts documented no-op behavior (F2).
4. Tenant-source pin: "tenant A denied / tenant B allowed" per seam, so a conflicting middleware stash cannot satisfy the test (QA M2).
5. Strictness: `TestParseYAML_*` updates (fixture change for `other: 1`), `Validate` bare-`*`/interior-`*`/role-set cases, inline-path boot-fail at `BuildTokenPolicyStore` (QA M4).
6. Admin round-trip of the three new fields via `GET /api/v1/admin/token-policies` (QA M5) against the OpenAPI schema at `docs/openapi.yaml:6866-6884`.

### Declared unsupported / documented-limitation surface (all fail-open, none wire-visible)

- Tenant `max_ttl` on silent renewal, agent delegation, and break-glass unless F1's structural fix lands (break-glass is global-rules-only by construction).
- `subject_roles` at the refresh seam and `require_renew_after` tenant-scoped at introspection (roles/tenant never reach those `PolicyInput`s).
- Bare-`*` `client_id`/`subject` selectors rejected by `Validate` while bare-`*` scope selectors keep their existing match-all semantics — intentional asymmetry, decoupled surfaces.
- Opaque temp tokens (gRPC `IssueTempToken`, authenticator temp tokens) are outside the policy engine entirely (pre-existing).

### Remaining certification evidence

- **No OIDF certification is claimed or evidenced** (`docs/sso/oidc-conformance.md`; feature-matrix.md:86). The headless OIDF harness (`test/oidc-conformance/run-headless.sh`, suite `release-v5.2.1`) is smoke evidence only — 59 SUCCESS steps on an HTTP-only local topology with one expected `VerifyClientManagementCredentials` failure — and is not in default CI. Nothing in this design changes that posture; `require_renew_after`, tenant selectors, and the clamp are non-standard governance extensions that OIDF conformance plans do not exercise.
- Remaining evidence gaps: no token-policy E2E in `test/`; the design's gate list omits `go test ./... -race` and E2E; `make ci` is red on a pre-existing fmt failure (untracked `test/region_token_contract_test.go` + `infrastructure/defaultimpl/sqlite/refresh_tokens_schema.go`) that must be cleared before the handoff gate can pass.

Advisory only — no files other than this review were changed.
