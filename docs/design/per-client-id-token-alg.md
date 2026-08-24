# Design: per-client id_token signing algorithm (`id_token_signed_response_alg`)

Status: committed (implemented).

Scope: `shared/core` (Client field), `protocols/oauth` (+`oauthvalidate`, DCR
wire + validation), `protocols/oidc` (discovery advertisement source),
`interfaces/sso` (issuer selection + option + discovery), `config` + `cmd/sso-server`
(static config), `infrastructure/defaultimpl/{sqlite,postgres}` (persistence),
`docs/openapi.yaml` + `docs/config-reference.md` (contracts).

Driver: the FAPI 2.0 conformance blocker recorded in
`docs/campaigns/reports/b11-fapi-conformance.md` + the archived
`test/oidc-conformance/results/39ecdf7a-fapi/BLOCKER.md`. The OIDF suite's own
login uses Spring Security's `OidcIdTokenDecoderFactory`, whose
`jwsAlgorithmResolver` is hard-coded to RS256, while the FAPI 2.0 Security
Profile forbids RS256 for ID tokens (its own discovery check requires
PS256/ES256/EdDSA/Ed25519). The product-level unblock chosen here is per-client
`id_token_signed_response_alg` (RFC 7591 §2 / OIDC Core §3.1.3.1 client
metadata): the AS signs a given RP's ID tokens with the algorithm that RP
declared, so the suite's RS256-only login client coexists with ES256/PS256 FAPI
clients on one issuer.

The six design questions the task demands adjudicated:

## Decision 1 — Data model

`core.Client.IDTokenSignedResponseAlg string` (JSON/YAML
`id_token_signed_response_alg,omitempty`), placed beside the JWE response
metadata (`IDTokenEncryptedResponseAlg/_Enc`, `UserinfoEncryptedResponseAlg/
_Enc`) which are the closest sibling contract (OIDC Core §2/§3/§5.3.2 client
metadata). Empty = today's single-issuer behavior, byte-identical.

| Surface | Field/key |
|---|---|
| `core.Client` | `IDTokenSignedResponseAlg` |
| DCR request (`DCRRequest`) | `id_token_signed_response_alg` (RFC 7591 §2 naming) |
| DCR response / GET / PUT echo (`DCRResponse`) | `id_token_signed_response_alg` |
| DCR validation (`oauthvalidate.DCRMetadata`) | `IDTokenSignedResponseAlg` |
| Static config (`config.ClientConfig`) | `clients[].id_token_signed_response_alg` → seeded into `core.Client` |
| Persistence | sqlite `clients.id_token_signed_response_alg` (migration v7), postgres `clientSchemaV5` `ADD COLUMN IF NOT EXISTS`; redis/memory round-trip the whole `Client` JSON so no change |

Validation: an alg is accepted ONLY when it is in the server's wired id_token
signing set — the same set discovery advertises (`id_token_signing_alg_values_supported`).

- DCR (`POST /register`, `PUT /register/:id`): the live wired set is passed
  into `ValidateDCRMetadata` (5th parameter, same pattern as the existing
  `supportedGrants` parameter); an unknown alg → 400 `invalid_client_metadata`.
- Static config: `config` boot validation maps `keys.signing.alg` to its
  canonical JWS name (EdDSA/ES256/RS256/PS256) and rejects any
  `clients[].id_token_signed_response_alg` outside it → config validation
  failure, same loud pre-deploy gate `sso-ctl config validate` enforces for
  every other client field.

The whitelist is AGENTS.md §3's accepted JWS algorithm set
(`security.AsymmetricJWSAlgs()`: EdDSA, ES256/384/512, RS256, PS256). The
`WithIDTokenIssuerAlg` SDK option panics at construction on an alg outside it
(mirroring `WithRSAAlg`'s panic discipline). "none" is never whitelisted and
no issuer can be wired for it, so it is rejected on every path.

## Decision 2 — Issuance selection

New Server state: `idTokenIssuerAlgs map[string]oidc.IDTokenIssuer` (in
`wiringState`, beside the sibling routing maps `tokenIssuers` /
`tenantTokenStrategies`), populated by the new option
`WithIDTokenIssuerAlg(alg, issuer)`.

`idTokenIssuerForClient` resolves in this order:

1. `Client.IDTokenSignedResponseAlg` set → the issuer wired for that exact alg
   (map lookup). Missing → fail closed (error; the caller omits id_token).
2. Otherwise the existing resolution unchanged: tenant mapping
   (`WithTenantTokenIssuer`) → shared `s.idTokenIssuer` (including the
   emit=false omission rules for non-`oidc.IDTokenIssuer` strategies).

Rationale for a multi-issuer map over composing the single issuer: the map is
the same shape as every other issuer-routing structure in the server
(`tokenIssuers`, `tenantTokenStrategies`), the real Ed25519/ECDSA/RSA issuers
already satisfy `oidc.IDTokenIssuer` (so no adapter is needed), and the default
path is untouched by construction — with no per-alg map entries and no client
field set, resolution is byte-identical to today. Every id_token minting path
(auth-code exchange, login direct-mint, device, CIBA, token-exchange, native
SSO) funnels through `idTokenIssuerForClient` / `IDTokenIssuerForClient`, so
one change point covers all grants.

The per-alg issuer MUST also be registered via `WithTokenIssuer`: its public
key then lands in the aggregated `/.well-known/jwks.json` and
`validateAnyToken` (which iterates `tokenIssuers`) can validate the client's
id_token as an `id_token_hint` at silent renewal / end_session. Documented
requirement, enforced by tests.

## Decision 3 — Key/algorithm mismatch: fail closed

When a client's `IDTokenSignedResponseAlg` has no wired issuer:

- Registration/config time: rejected (Decision 1) — the state cannot arise via
  any supported provisioning path.
- Issuance time (defensive backstop — a store row written by an older replica,
  or a downstream fork with a different option set): `idTokenIssuerForClient`
  returns an error and every minting caller omits id_token (logs + fail-open
  posture of the surrounding auth flow preserved — the access token still
  issues; only id_token is withheld). No fallback to another key: signing with
  a different algorithm would violate the client's declared metadata (the RP's
  decoder would reject it anyway) and would silently defeat the per-client
  isolation the field exists to provide. This mirrors the existing
  tenant-issuer fail-closed discipline in `idTokenIssuerForClient` /
  `issuerForClient` exactly, so config validation and runtime agree.

## Decision 4 — Discovery advertisement

`id_token_signing_alg_values_supported` becomes the union of the default
issuer's live signing set (`SigningAlgValues`) and every alg key in the
per-alg map, deduped + sorted, via a new accessor `IDTokenSigningAlgValues`.
Byte-identical to `SigningAlgValues` when no per-alg issuers are wired (the
map is empty → early return). The `s.idTokenIssuer != nil` gate widens to
"default issuer OR per-alg issuers wired" so a per-alg-only deployment still
advertises. This is what FAPI clients need: the suite's discovery check
(`FAPI2CheckDiscEndpointIdTokenSigningAlgValuesSupported`) sees the
PS256/ES256/EdDSA entry while an RS256 login client is served its own alg. The
userinfo signing advertisement gate widens the same way (any wired id_token
issuer implementing `oidc.UserinfoSigner`), because the userinfo signer is
selected via `IDTokenIssuerForClient` too.

## Decision 5 — Security boundary

- `alg=none` rejected on every path: not in `security.AsymmetricJWSAlgs()`, so
  `WithIDTokenIssuerAlg` panics, DCR returns 400, static config fails boot.
- Accepted algs exactly AGENTS.md §3 (`AsymmetricJWSAlgs`: EdDSA, ES256-512,
  RS256, PS256). The repo's issuers implement EdDSA/ES256/RS256/PS256.
- `at_hash` unaffected: each issuer computes `at_hash` from its own alg's hash
  (`infrastructure/defaultimpl/at_hash.go` — SHA-256 for ES256/RS256/PS256,
  SHA-512 for EdDSA), and the per-alg path reuses the real issuers, so the
  RP's recomputation from the JOSE header keeps matching.
- Server-level alg-confusion gate (`WithSupportedSigningAlgs`) is unaffected:
  per-alg id_token issuance is a signing-side choice; validation-side gates
  stay as wired.
- JARM (`jarmSignerForClient`) is deliberately NOT routed through the per-alg
  map: JARM's own metadata is `authorization_signed_response_alg` (not in
  scope), and the authorization-response JWT is a different surface.

## Decision 6 — Acceptance assertions (all tested, none skipped)

1. Static config path: `clients[].id_token_signed_response_alg` seeds
   `core.Client.IDTokenSignedResponseAlg` (extended `client_config_test.go`);
   an alg ≠ `keys.signing.alg` fails config validation.
2. DCR path: `POST /register` with `id_token_signed_response_alg` persists +
   echoes the field; `PUT` updates it; `GET` returns it; unknown alg → 400
   `invalid_client_metadata`.
3. Per-alg issuance: two real issuers (EdDSA + RS256) wired via
   `WithIDTokenIssuerAlg`; a client with the field set gets an id_token whose
   JOSE header carries the requested alg; a client without the field keeps the
   default issuer (byte-identical path).
4. Fail-closed: client with an alg that has no wired issuer → id_token omitted
   (no crash, no wrong-key signing).
5. Default byte-identical: no client field, no map entries → discovery +
   issuance match the pre-feature behavior (existing discovery + multialg
   tests stay green).
6. Discovery: `id_token_signing_alg_values_supported` = union of the wired
   set, and `IDTokenSigningAlgValues` equals what DCR accepts.
7. FAPI-related suite: `test/multialg_*`, `test/oidc_*` tests green;
   `TestMaintainability_|TestArchitecture_|TestDirectory` green.

Persistence + contracts are updated in the same change: sqlite migration v7,
postgres `clientSchemaV5`, `docs/openapi.yaml` DCRRequest/DCRResponse schemas,
`docs/config-reference.md` `clients[]` row, CHANGELOG entry.
