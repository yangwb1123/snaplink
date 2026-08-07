All verification targets are now covered with mechanism-level evidence. Here is the report.

---

# Verification report — additive claims / kid regression vs. token consumers, mirror drift, mode-off byte-identity, call-site enumeration

## 1. Consumer breakage: PASS — no mechanism exists in any named surface

**Introspection (RFC 7662) projection** — `introspectAccess` (`protocols/oauth/handle_introspect.go`) builds the body from `core.TokenClaims` via `populateAccessIntrospectionBody` (`introspect_body.go:65-106`): a fixed, explicit projection (exp/iat/nbf/aud/client_id/scope/jti/auth_time/acr/amr/sid/cnf/serving_region). There is no generic claim echo, so new `tenant_id`/`roles` wire claims cannot change the response. Feed path uses plain `json.Unmarshal` (`ed25519_validate.go:101-121`, `rsa_validate.go:95-113`) — unknown fields are ignored; the only `DisallowUnknownFields` sites in the repo (quotaprojection receipt, payment ingest, config APIs) are unrelated to tokens. RFC 9701 signed responses sign the same fixed body. Introspection cache keys on SHA-256(token), content-agnostic.

**RFC 9068 projections** — `claimsFromPayload` (`validate_claims.go:16-55`) copies only enumerated fields; new claims are dropped from the typed view with no error path. The typ/alg gates (`at+jwt`, allowlist) are payload-claim-independent.

**Resource-server middleware** (`interfaces/ssoclient/rs`) — `parseClaims` (`claims.go:113-136`) unmarshals into `wireClaims` (unknowns ignored) plus a `Raw map[string]any` documented as "the complete claim document… for claims this struct does not project". `validateClaims` gates only on iss/aud/exp/nbf/iat. The middleware routes on header `kid` (`validate.go:50-56`, `GetJWK(ctx, hdr.Kid)`) — which is exactly why R3's kid-regression-only discipline is load-bearing; kid is already set at Issue time in all three issuers (`ed25519_issue.go:33`, `ecdsa_issue.go:26`, `rsa_issue.go:23`; header structs at `ecdsa_jwt_issuer.go:439`/`rsa_jwt_issuer.go:436` as cited).

**cmd/gensdk clients** — generated TS interfaces are type-erased (`client.ts` `IntrospectResponse` is all-optional); the Python client's `_request` → `_parse_body` is a bare `json.loads` (`client.py:2759-2763`) — no schema validation, unknown keys unrepresentable as an error. Neither SDK decodes access-token JWTs; the introspection schema in openapi.yaml is untouched (design's "no introspection echo" boundary holds). Bonus: ID tokens use a separate `ed25519IDPayload` (`ed25519_issue.go:105`), so R1's payload-struct field cannot leak into ID tokens.

## 2. core.RoleClaim mirror: constraint real, drift-prevention NOT test-enforced

The boundary is real and enforced: `shared/core` is layer 0 (`architecture_layer_test.go` `layerName`), imports flow toward shared, so a shared→`domains/permissions` import is an upward edge the layer test rejects; AGENTS.md §4 forbids it. Since `sso.Subject = core.Subject` (`aliases.go:132`), `Subject.Roles` lands in shared/core and a dependency-free mirror of `permissions.Role` (`types.go:16-21`: `code`/`name`/`description`/`permissions`) is the only legal shape. **But "cannot drift" is not enforced anywhere today**: no `core.RoleClaim` exists, and the repo has no cross-boundary JSON-tag mirror pin (shared/core `wire_test.go` pins core's own types only; permissions tests never marshal against a mirror). The design's "wire-equality test pinning element-for-element identity" is a promise whose concrete home is the **A1–A9 acceptance mapping, which is not present in the artifact** (see §5).

## 3. Mode-off byte-identical: NOT test-enforced today; artifact does not demonstrate it

The current suite has zero golden byte tests — `ed25519_rfc9068_test.go` and the ECDSA/RSA issuer tests assert semantic claims (typ/alg values, presence of jti/exp/…), never exact token bytes. The design's R5 ("golden byte-identity tests across all three issuers") and the T-2/T-8(a)/fail-open mapping are references to absent content. Worse, the artifact never addresses the subtlety that R1/R2 change bytes **unconditionally** — a golden captured post-implementation would bake in the new bytes and prove nothing about mode-off; only a pre-change golden or a differential mode-on/off test could, and no such test is specified in the deliverable.

## 4. Call-site enumeration: INCOMPLETE — the central adversarial finding

Within its own frame the E6 discipline holds: **8** tokengrant files (not nine) with `Subject{` sites at `token_authcode.go:121`, `token_ciba.go:102`, `token_client_credentials.go:40`, `token_device.go:85`, `token_exchange_stages.go:369/390`, `token_jwt_bearer.go:98`, `token_refresh.go:217/274`, `token_saml2_bearer.go:106`; the line citations `server_login.go:118` / `server_native_sso.go:193` are exactly the `TenantID: client.TenantID` lines (Subject opens at 112/190 — the design cites the TenantID line, accurately); all 10 claimed sites populate `Subject.TenantID`.

But as an enumeration of **user-bound access-token issuance sites** it is not complete. Missing root-module production sites:

| Site | User-bound? | TenantID | In the 10? |
|---|---|---|---|
| `protocols/oidc/handle_silent_renewal.go:210` | yes (sub=user, AuthTime/AMR/SID carried) | set | **no** |
| `interfaces/sso/accessors_feature_gates.go:257` (break-glass impersonation) | yes (TargetUserID, AuthTime) | `""` deliberately | **no** |
| `cmd/sso-server/serverwebauthn/webauthn.go:217` | yes (userID, AuthTime) | not set | **no** |
| `domains/tokenexchange/agentidentity/grant.go:185` | agent (act=human), no AuthTime | set | **no** |
| `infrastructure/kerberos/handler.go:268` (nested module) | yes | not set | **no** |

That is 14 root-module production issuance sites (13 user-bound by the AuthTime criterion) plus kerberos — not 10, and not 9 user-bound. No exclusion rationale is given for silent renewal, break-glass, or webauthn. The sibling run `carry-tenant-binding-roles-into-the-webauthn-min-d60cae64` independently confirms the webauthn gap ("WebAuthn-minted access tokens silently diverge from every other grant surface on the exact claim the G1 gate asserts") — i.e., the enumeration is known-incomplete, and the design ships `roles`/`tenant_id` on some user-bound paths but not silent renewal / break-glass / webauthn. Not a consumer breakage, but the design's central quantitative claim fails adversarial completeness, and its own T-8(a)-style parity check would fail between webauthn and `/token` mints.

## 5. Artifact-completeness finding

The design artifact (16 lines, run stopped after design) references "acceptance mapping A1–A9" tying T-2's five checks, T-8(a), and the fail-open outage variant to concrete test homes — **no such mapping exists in the artifact set**. Both the drift-impossibility (§2) and mode-off byte-identity (§3) promises rest entirely on that absent content. This is a deliverable gap, not a code defect.

## Bottom line

- Additive claims + kid regression **cannot** break introspection, RFC 9068 projections, the RS middleware, or gensdk clients — verified at the mechanism level (fixed claim projections, plain unmarshal, `Raw` passthrough, type-erased/`json.loads` SDKs, kid already in every header).
- E10 refutation holds (`config_load.go:305` wires `WithIssuer`; `issuer_test.go` guards the `"sso-server"` non-sentinel); V1–V5 all confirmed; exactly 28 non-test `resolveIssuer` callers, as claimed.
- The **10-total/9-user-bound enumeration is incomplete** (≥13 user-bound root sites; silent renewal, break-glass, webauthn, agentidentity, kerberos omitted, with no documented exclusion).
- `core.RoleClaim` mirror necessity is real and enforced by the layer test, but "cannot drift" and "mode-off byte-identical" are **promised, not test-enforced** — no such tests exist in the repo, and the A1–A9 mapping that was supposed to home them is absent from the deliverable.
