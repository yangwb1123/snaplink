Audit complete. Report saved to `docs/architect-analysis/auto/runs/emit-tenant-id-roles-in-buildaccesspayload-and-r-bbad8fa5/artifacts/adversarial-review-wire-identity-3a1c9d4e/audit.md`. Every claim re-verified against the tree at HEAD.

## 1. Byte-identical wire when unbound — coverage is partial, and "byte-identical" is over-broad

**Mechanism is sound** (verified): struct-end append + `omitempty` adds zero bytes when empty; `buildAccessPayload` is the single shared projection for all 3 signers; `TokenClaims` is never marshaled wholesale anywhere in-tree. But coverage per endpoint:

- **/token**: strong but *planned* — no byte-goldens exist in-tree today (zero `*.golden` files); step-1 goldens are new tests built on the verified `fixedClock` pattern (`ed25519_jwt_issuer_test.go:171-176`).
- **/introspect**: functional no-echo assertion only (A4), not a byte-golden; adequate since the body is hand-enumerated (`introspect_body.go`) and the RFC 9701 JWT nests the same hand-built body.
- **/userinfo**: **no test pinned** (safe by construction — claims-projection, not `TokenClaims` marshaling).
- **discovery**: **not byte-identical when unbound — it flips to the sentinel by design**. The design discloses this honestly (§3.3); the evidence's blanket phrasing doesn't.
- **/par**: **no test pinned**; the A-class regression test covers the shared `validateAssertionClaims` via /token only, not the PAR call-site wiring (`handle_par.go:170`).

## 2. TokenClaims placement — cannot perturb, confirmed

- **Single-aud compacting**: `audClaim.MarshalJSON` untouched; new fields append *after the last field*, so not even marshal order interacts.
- **at_hash**: pure digest of the issued access token (`at_hash.go`) — unbound clients get identical bytes → identical at_hash; bound clients get a *correctly recomputed* one (a stable at_hash would be the bug).
- **Introspection no-echo**: body hand-enumerated; `serving_region` echoed (:51-57), `tenant_id`/`roles` not — asymmetry real and pinned.
- One residual: `TokenClaims` is exported with json tags — out-of-tree marshaling would newly emit the fields; recommend explicit `json:"-"`.

## 3. Legacy-resolver inventory — 3 real gaps (one breaking)

All 31 cited carve-out sites + 9 Deps lines (= 40 ✓) and all 22 flips verified at/near anchor with correct semantics. Contract docs consistent (error-codes `invalid_client`/`invalid_request_object`/`no_token_strategy` all exist; OpenAPI pins no issuer derivation; workload-identity collapse documented at error-codes.md:316). But:

1. **`server_token_clientauth.go:180` — breaking-change gap**: workload-identity `provider.Validate(..., s.resolveIssuer(ctx))` passes the issuer as the **expected audience** (`workload_identity.go:235`: "aud MUST contain expectedAudience"). Flipping to the sentinel breaks every existing workload-identity client with zero security gain — class-A equivalent, missing from the inventory.
2. **`mesh_authz.go:179`** — bare RFC 6750 challenge realm, same class-C surface as the cited `:217/:253`, omitted.
3. **`server_me.go:90`** — `handleBranding` stamps `KeyIss`, documented in OpenAPI (`/branding` schema, :3171); appears in *neither* the flips nor the carve-out, though it's the same class as the selfservice flips.

Cosmetic drift: 4 Deps anchors off by 1-2 lines (`handle_par.go:24`→:23, `handle_ciba.go:38`→:37, `handle_introspect.go:36`→:34, `caep/receiver.go:19`→:243); `token_authcode.go:28` → actual `ErrNoTokenStrategy` response at :122. All budgets verified (stages 500/500, config_load 498→500, interfaces/sso at 60-file ceiling).

Recommendations: scope the "byte-identical" claim to token bytes + untouched surfaces; add one response-shape assertion each for /userinfo and /par; include the ID token in step-1 goldens so unbound at_hash is pinned explicitly.
