All verification complete. Here is the step-6 contract-update verification report.

---

# Step-6 contract verification: flip + new surfaces

## 1. `docs/openapi.yaml` — **amendment required; the design's "no OpenAPI change" (§2.1.6) is wrong**

**Discovery `issuer` sentinel flip — the schema pins semantics that the flip changes:**

| Location | Current contract | Post-flip status |
|---|---|---|
| `OpenIDConfiguration.issuer` (`openapi.yaml:17628-17635`) | `type: string, format: uri` + "MUST equal the `iss` claim of every token issued AND the `iss` parameter on every authorization response (RFC 9207)" | The MUST-equal sentence is **false today** (discovery=base URL, minted=sentinel) and becomes **true** post-flip — but `format: uri` is violated by the non-URL `"snaplink-sso"` sentinel in SDK-default. Amendment: keep MUST-equal, drop/relax `format: uri`, note "non-URL logical sentinel when `WithIssuer`/`server.issuer` unset" |
| RFC 9207 `iss` — `LoginResponse` (`:14286`), code response (`:14385`) | `format: uri` | Same sentinel tension (both flip per design §3.2) |
| `/branding` `iss` (`:3167-3170`) | `iss: { type: string }`, **no derivation pinned** | **`server_me.go:90` stamps `KeyIss: s.resolveIssuer(ctx)` → flips, and this site is MISSING from the design's §3.2 inventory** (neither flips nor carve-out; the listed selfservice stamps are `profile.go:64,139` under `protocols/selfservice/selfserviceaccount/` — path drift — and `server_mfa.go:139`, but not `handleBranding`). Amendment: pin `iss` = logical issuer (sentinel when unconfigured) |

**PAR/introspect/userinfo response shapes — confirmed untouched, no amendment:**
- `PARResponse` (`:15082-15091`): `request_uri` + `expires_in` only — no `iss`, no claims. ✓
- `IntrospectResponse` (`:14935+`): hand-enumerated; **no `tenant_id`/`roles`**, no `additionalProperties: false`; RFC 9701 body documented as "wrapping the SAME shape" — accurate, no-echo preserved. ✓
- `UserInfo` (`:16454+`): no `tenant_id`/`roles`. ✓ Access-token body is an opaque string in the spec, so new claims need no enumeration.
- `/.well-known/oauth-protected-resource` (`:2898`): "authorization_servers to the server issuer" — stays accurate under the class-D legacy carve-out (`server_resource.go:182`). No contradiction.
- `/token` `client_assertion` text (`:14796-14798`, "aud MUST include this AS issuer **or the token endpoint URL**") — stays accurate: the legacy resolver = token endpoint URL branch. ✓

## 2. `docs/error-codes.md` — **two amendments required; "no error-codes change" is also wrong**

**Allowlist misconfig errors (mint-gate cause):** `no_token_strategy` (`error-codes.md:796`) — "Client's `token_strategy` doesn't match any registered issuer" gains a second cause. Amendment: OR clause — "or the signer name resolved for the client's token strategy is not in the configured issuer allowlist" — exactly the in-worktree `invalid_scope` OR-clause precedent (`:298`). **No new code row** (design correctly has no new `Err*`), so docscheck `TestErrorCodesDocumented`'s Go-const cross-reference stays green. Boot-time failures (panic / config load error) are not HTTP surfaces — correctly out of scope for this catalogue; they belong in `config-reference.md` (design covers the knob) and the option doc.

**Workload-identity carve-out at `server_token_clientauth.go:180` — CONFIRMED and MISSING from the design:**
- `server_token_clientauth.go:180`: `provider.Validate(ctx, req.ClientAssertion, s.resolveIssuer(ctx))` — the resolver output is the **expected audience**; `workload_identity.go:228,235`: "aud MUST contain expectedAudience — THE security crux".
- Flipping `resolveIssuer` → sentinel breaks every existing workload-identity client in SDK-default state. This is a **class-A-equivalent credential-surface aud validation** and is **absent from the design's §3.2 inventory** (which cites `:135` private_key_jwt but not `:180`). It must be added to the carve-out list (re-point to `ResolveIssuerLegacy`).
- `error-codes.md:316` documents the collapse ("issuer, audience and mapped-subject binding … collapses to `invalid_client`") but not the audience source — one sentence pins it: expected audience remains the reachable deployment URL (request base URL), unchanged by the flip.

## 3. `docs/feature-matrix.md` — **amendment required; design is silent**

- **New capability row** for the issuer allowlist (`WithIssuerAllowlist` SDK + `server.issuer_allowlist` config) in the spec table — precedent: the in-worktree "Global scope registry" row. (The generated registry table would need `ops/build/capabilities.json` + regenerate; the spec-table row is the lighter path.)
- **RFC 9207 row** ("always | `server_finish_login.go`"): note SDK-default `iss` = the `snaplink-sso` sentinel; `WithIssuer`/`server.issuer` for a URL issuer.
- **Workload-identity row**: same audience pin as error-codes.md:316.
- The `server.issuer` config row (`config-reference.md:48`, "stamped into JWT `iss`, discovery `issuer`, every RFC 9207 `iss`") remains accurate in cmd state — and the new `server.issuer_allowlist` row belongs next to it (design covers this).

## 4. 'Byte-identical' scope discipline

The design's §3.1 scopes byte-identity correctly; the claim docs must keep that scope explicit and not regress to blanket phrasing: byte-identity holds for **(a)** access-token bytes when `TenantID==""`/`Roles` empty (step-1 goldens), **(b)** ID-token payload shape, **(c)** introspection/revoke/PAR/userinfo/DCR responses, **(d)** every issuer surface in `WithIssuer`/configured states. It does **not** hold for discovery/RFC 9207/`/branding` `iss` values in SDK-default (they flip to the sentinel by design). The `handleBranding` flip is a new divergence the design's scoping statements never acknowledge.

## 5. Ceilings and budgets — **CONFIRMED surviving**

- `interfaces/sso`: exactly **60** non-test files (ceiling); design adds no files (§8). ✓
- Line counts match the design exactly (current worktree): sso.go 499, options.go 490, options_security.go 500, sso_wiring.go 456, accessors.go 494, accessors_handlers.go 477, server_discovery.go 483, server_discovery_config.go 487, server_helpers.go 498, `token_exchange_stages.go` 500, `token_exchange.go` 495, `consts_wire.go` 500, config_load.go 498, config.go 236. ✓
- The step-6 amendments above are `.md`/`.yaml`-only → zero `.go` line impact → budgets trivially survive. (The migration-gate reviewer's separate finding on the step-2 net-zero arithmetic is a design-doc issue, not a contract-doc one.)
- Gates: `TestErrorCodesDocumented` safe (no new code rows), `TestOpenAPIRoutesRegistered` safe (no path changes), kin-openapi validate passes (parsed OK; `format` removal is valid).

**Bottom line:** budgets/ceilings survive; PAR/introspect/userinfo shapes confirmed untouched. But the design's "no contract-doc change" conclusion fails on four counts: `OpenIDConfiguration.issuer` + RFC 9207 `format: uri`/MUST-equal contract, `/branding` `iss` (both an OpenAPI pin and a missing §3.2 flip), the `no_token_strategy` OR-clause, and the `server_token_clientauth.go:180` workload-identity carve-out (missing from the inventory + audience pin at error-codes.md:316). feature-matrix.md needs the allowlist capability row and the two derivation notes.
