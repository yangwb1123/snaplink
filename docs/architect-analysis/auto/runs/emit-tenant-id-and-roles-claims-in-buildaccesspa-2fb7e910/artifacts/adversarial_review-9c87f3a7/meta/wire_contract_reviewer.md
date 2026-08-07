All claims verified against HEAD. Here is the independent wire-level verification report.

## Verdict: all four wire-level claims hold against HEAD

### 1. `tenant_id`/`roles` omitempty projections match the house disciplines — VERIFIED

- **ServingRegion-unconditional-literal**: `buildAccessPayload` assigns `ServingRegion: subject.ServingRegion` as a bare struct literal with no wire-visible guard — `issue_payload.go:39-43`, comment: *"Unconditional literal assignment (SID discipline): omitempty performs the omission"*. The proposed `TenantID: subject.TenantID` is the exact same pattern.
- **AMR guard+copy**: `if len(subject.AMR) > 0 { payload.AMR = append([]string(nil), subject.AMR...) }` — `issue_payload.go:83-86` (guard + defensive copy inside `applyOptionalClaims`). The proposed `roles` projection mirrors it structurally.
- **Tags vs consts**: `KeyTenantID = "tenant_id"` at `shared/core/consts_wire.go:169`; `KeyRoles = "roles"` at **277** — the design's self-flagged drift (not 267) is confirmed correct.
- `ed25519Payload` (`ed25519_types.go:15`) has neither field today; the change is purely additive. Minor nuance: the code comment names the unconditional discipline "SID discipline" (SID and ServingRegion are both unconditional literals); the design's label is substantively identical.

### 2. Byte-identical single-tenant output / golden claim-set — VERIFIED

- Single-tenant = empty `Client.TenantID` ("no tenant affinity", `shared/core/types.go:39-47`); empty roles. `omitempty` skips both fields, so payload bytes, header, and signing input are unchanged; Ed25519 signing is deterministic, and ECDSA/RSA signatures were already randomized pre-change (payload claim-set identity is unaffected).
- `Subject.Claims` map marshals deterministically (json.Marshal sorts map keys). The only nondeterminism in the claim set is `jti` via `generateJTI` (crypto/rand, 16 B) at `ed25519_issue.go:38`, `ecdsa_issue.go:29/110`, `rsa_issue.go:24/102`; `With*Clock` machinery exists (`issue_payload.go` `Clock`/`nowFrom`). `buildAccessPayload` is shared verbatim by all three issuers at the cited lines 43/37/29.

### 3. Emission asymmetry vs OIDC/discovery/feature-matrix/openapi — VERIFIED, no contradiction

- **Mechanics**: direct mint (`mintAccessToken`, `server_login.go:99-141`) has `result.UserID` + `client.TenantID`; all token-endpoint grants (`token_authcode.go:136`, `token_refresh.go:291`, `token_client_credentials.go:52`, `token_device.go:99`, `token_ciba.go:124`, `token_jwt_bearer.go:112`, `token_saml2_bearer.go:123`, `token_exchange_stages.go:399`) stamp `TenantID` but deliberately no roles (R4).
- **OIDC**: `roles` is not an OIDC Core §5.1 standard claim; `claims_supported` (§5.6.2) is optional/advisory. No cross-grant uniformity requirement exists. No contradiction.
- **Discovery**: the static `claims_supported` list (`server_discovery_config.go:368-372`) already omits `sid`, `jti`, `client_id`, `act`, `authorization_details` (and `serving_region` unless `WithServingRegionAdvertisement`, `server_discovery_cache.go:38`) — omitting the new claims matches the `sid` precedent exactly.
- **Feature-matrix/openapi**: `sid` row at `docs/feature-matrix.md:118` is the precedent; openapi documents `roles` only in the login-response embed (`openapi.yaml:4807-4809`, `WithEmbedPermissionsInLogin`) and `/roles/me` (3392), never in an access-token claim schema — so no openapi change is needed.
- **Reinforcing discipline**: roles keyed on the local subject (never the pairwise pseudonym) matches `mesh_authz.go:326-339` verbatim ("or a pairwise client gets EMPTY roles"). ID/logout tokens cannot leak the claims structurally (`ed25519IDPayload` in `ed25519_types.go`; `ed25519LogoutPayload` in `ed25519_issue.go:171`).

### 4. `TokenClaims`/`Validate()` drop cannot corrupt validation — VERIFIED

- Validate chain (`ed25519_validate.go`; shared by ECDSA/RSA): header alg/typ allowlist → signature over the **raw** segments → `decodeAndCheckClaims` (only exp/nbf vs `maxClockSkew`) → `claimsFromPayload` (`validate_claims.go:16`, enumerated mapping into a `TokenClaims` that has no Roles/TenantID fields). No check reads the new claims, and `json.Unmarshal` ignores unknown fields — validation outcomes are byte-identical whether or not tokens carry the claims. No silent corruption.
- Downstream: introspection echoes the `TokenClaims` projection (comment at `validate_claims.go:14-15`) → the claims are absent there (R5's explicit non-goal, consistent with unchanged openapi). All re-emission seams stamp `TenantID` from `client.TenantID` directly, never from `TokenClaims`, so the drop has no re-emission corruption path.

### Supporting constraints also confirmed

- Line counts: `server_finish_login.go` 500, `server_login_client.go` 500, `server_helpers.go` 498, `server_login.go` 469 — the design's 469→~492 plan fits the 500-line budget.
- `ensureJITMembership` at `server_finish_login.go:47`, before the mint — JIT role visible at mint time.
- Fail-open seam at `server_oauth.go:205-213` (requirements cited 202-213 — ~3-line drift, same block; log string + `ObserveTokenPolicyRoleResolutionError` metric confirmed).
- `sso.Subject = core.Subject` alias (`aliases.go:132`); `cloneHookSubject` shallow-copies (`accessors_threat.go:391`), so `Roles` survives the threat pipeline.
- `MemoryTenantUserStore` exists (`infrastructure/defaultimpl/memorystoreidentity/memory_tenant_user.go`) for the seeded acceptance test.
- `go build ./...` green at HEAD.

### Caveats to carry forward (no wire impact)

1. **`core.Subject.TenantID`'s doc comment** (`types_token.go`, "NOT a token claim — issuers emit only fields they enumerate in buildAccessPayload") becomes false once TenantID is emitted; it must be updated in the same change — the design doesn't list this code-comment update.
2. `KeyRoles` lives in the *Permission endpoint response keys* const block (`consts_wire.go:275-277`) — its value doubles as the JWT claim name; the tag-vs-const coupling guard keeps them coherent.
3. The asymmetry itself (roles on legacy direct-mint tokens only, absent on the primary code flow) is a deliberate product decision — the feature-matrix row should state the direct-mint-only scope so RPs don't assume cross-grant presence.

The design's wire-level contract claims are accurate against HEAD; no contradictions found.
