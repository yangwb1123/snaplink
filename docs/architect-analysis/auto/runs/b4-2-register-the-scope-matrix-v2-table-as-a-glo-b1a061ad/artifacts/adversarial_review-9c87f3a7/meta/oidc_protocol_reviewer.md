Done. The blocking gap is closed with a code-verified mechanism specification.

## Deliverable

**`docs/architect-analysis/auto/runs/b4-2-register-the-scope-matrix-v2-table-as-a-glo-b1a061ad/artifacts/design-a77de8a6/task-2-oidc-standard-scopes.md`** (273 lines), plus a pointer section appended to `task-1-design.md`.

## Decision: **Memory pre-seeding** (Option A)

The five OIDC standard scopes become pre-seeded protocol scopes of the registry — new `shared/core` constants (`ScopeProfile/ScopeEmail/ScopeAddress/ScopePhone/ScopeOfflineAccess`) joining `ScopeOpenID`/`ScopeDeviceSSO` at `consts_wire.go:239-246`, imported by `scoperegistry.Memory` (7 protocol scopes ∪ 8-scope matrix ∪ `extra_scopes`). **The seam carries no hardcoded exemption list** — the "protocol-trigger bypass" is structural, killing the parallel-list drift surface. `extra_scopes` is downgraded to tenant resource scopes only; the five are never required there (fail-closed bare-`*` validation kept).

**B rejected** (openid-presence): breaks `offline_access`-without-`openid` clients, breaks rule-4 defaults (which exclude `openid`, scope.go:97-111), and store-bound flows (device/CIBA/refresh/webauthn) have no request to test presence against. **C rejected** (mandatory extra_scopes): operator omission/typo turns compliant RPs into 400 machines — the exact drift the registry exists to kill.

## Conformance verifications (code-checked)

- **Discovery** — corrected the design's "discovery untouched" claim: `scopes_supported` is the client-set union `sorted(openid ∪ ⋃ AllowedScopes)` (`computeDiscoverySnapshot`→`projectClientFields`, server_discovery_cache.go:135-201). Unfiltered, the `anything` fixture gets advertised but 400s at `/token` under an enabled registry. Fix: filter through `Registry.Registered` when wired; registry-off stays byte-identical. One filter covers OIDC discovery, RFC 8414 resource metadata, federation, and signed metadata (all share the snapshot); fingerprint/cache unaffected (registry is build-once).
- **Refresh chain** — `refreshResolveScopes` (token_refresh.go:359-369) defaults to family `info.Scopes`; one post-resolution check subsumes omitted and subset paths (subset property), rotation re-carries the checked set (induction), and pre-enablement families fail closed with the existing plain-`ErrorBody` 400 (byte-identical, no silent narrowing). The webauthn-minted `offline_access` family (webauthn.go:164,192,315-318) crosses into `/token` jurisdiction at refresh and passes only because of the pre-seed — named as the jurisdiction bridge.

## Pinned acceptance tests

**A-8a..A-8f**: mintability across grants (cc/jwt_bearer/exchange/authcode with all five scopes → 200), refresh-chain preservation + fail-closed negative, webauthn offline_access refresh flow, discovery filter conformance (`anything` filtered, `read`/`write` fixtures unaffected), protocol-set↔bypass-constant drift guard (compile-time), and byte-identical-body negative (`profile billing:typo` → `{"error":"invalid_scope"}`, no trace_id). Each row cross-references the design's existing pins (A-1b, FM-4, FM-6, Step 2/5/7).

No `.go` files touched — docs-only; all other worktree modifications are pre-existing harness changes, left untouched.
