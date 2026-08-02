All cross-checks complete. Here is the gatekeeper report.

# Gatekeeper cross-check: review findings vs. design/implementation

**State:** Reviews were filed against design commit `744580d8`. The design doc (`docs/auto/domains-region-token-contract-design.md`) is **unchanged** since then — no review finding was folded into it (no uncommitted doc edits; the `docs/` diffs present belong to other batches). The in-flight implementation resolves a subset in code. I re-verified every finding against the live tree; `go build` and `TestMaintainability_|TestArchitecture_` pass at write time.

## Resolved (in the in-flight code, not in the design doc)

| Finding | Status | Evidence |
|---|---|---|
| QA F1 — remote gate fail-closed, both modes, order pinning | **Resolved** | `introspect_test.go` in-set/out-of-set/no-echo cases; `TestValidateToken_ServingRegionGateRunsLast`; remote gate sits last in `validateIntrospectedClaims` with the fail-closed asymmetry documented inline |
| QA F2 — per-issuer ID-token stamps | **Resolved** | `TestServingRegion_IDTokenClaim` iterates all three signers, empty ⇒ absent |
| QA F3 — `baseAdvertisedGrants` move | **Resolved** | Deterministic move adopted: helper now in `server_discovery_cache.go:47`; `server_discovery_config.go` at 488, gates green |
| QA F5 — `refreshRotatedSubject` param | **Resolved** | Param added (`token_refresh.go:245`), unit pin in `refresh_grace_test.go:28`, E2E re-stamp test |
| QA F6 — full-payload decode helper | **Resolved** | `decodeJWTPayload` decodes both tokens in E2E |
| QA F7 — echo positive + negative | **Resolved** | `TestIntrospectionEmitsServingRegion` (present + absent) |
| Sec F2 — `[""]` fail-open edge | **Partially resolved** | `HasServingRegionIn` short-circuits on empty claim, so `[""]` cannot admit claim-less tokens — but the explicit `AllowedServingRegions: []string{""}` regression test requested by the reviewer does not exist |
| Sec F4(a) — `HasServingRegion` vs `HasServingRegionIn` | **Resolved** | Both defined; gate uses `HasServingRegionIn` |
| Proto H2 — placement/budget arithmetic | **Resolved** | 503→500, split `introspect_body.go`, `handle_introspect.go` 415; maintainability gates pass |
| Proto L2 / DPoP ordering | **Resolved** | Gate-last placement pinned by test + comment |

## Unresolved — no dismissal with reasons anywhere

1. **Sec F1 / Proto H1 / M1 / M2 (High/Medium) — six mint sites still unstamped and not allowlisted.** Verified in the live tree: `protocols/oidc/handle_silent_renewal.go:210` (access) and `:390` (ID); `cmd/sso-server/serverwebauthn/webauthn.go:217` (access) and `:291` (ID); `infrastructure/kerberos/handler.go:268` (access) and `:294` (ID). The design's "deliberately empty" list covers only break-glass and admin temp tokens; silent renewal runs inside the HandlerContext pipeline (region stashed, so stamping is trivial and its omission breaks decision 2's "advertised == minted" invariant), WebAuthn already resolves the region for its residency gate, and Kerberos needs the deps-threaded decision the reviewers demanded. The requested mint-site enumeration regression test does not exist. Decision 3's fail-closed gate will mass-deny all six flows in region-pinned deployments.
2. **Contract docs missing (AGENTS.md §5.6 — same change).** Verified absent: `docs/error-codes.md` row 88 (no RS-gate/`serving_region` disposition); `docs/openapi.yaml` (only the pre-existing login `serving_region` at :12156 — no `OpenIDConfiguration` extension property, no token-schema claims, no login-description update); `docs/feature-matrix.md` row 150 unextended; `docs/config-reference.md` has no `WithServingRegionAdvertisement`/`AllowedServingRegions` entries.
3. **Sec F3 (Medium) — trust-chain precondition unstated.** No `PeerTrust`/`Allowed` precondition on `AllowedServingRegions` anywhere; no header-resolver-without-`PeerTrust` warning; error-codes row (the remediation's carrier) is untouched.
4. **QA F4 (Medium) — Mount-time warn untested.** Warning exists at `server_routes.go:139-140` but no log-capture test asserts it fires at Mount.
5. **Proto L3 (Low) — adversarial inputs unpinned.** No non-string `serving_region` (`123`) → `ErrTokenMalformed`/parse-failure test in either mode.

## Verdict

The implementation is strong on the decision-3 gate matrix, per-issuer ID stamps, budget placement, and E2E — but the two highest-severity review findings (the incomplete mint-site inventory with six live unstamped paths, and the §5.6 contract-doc obligation) are neither resolved nor dismissed with reasons, and the design document itself was never revised to incorporate any review feedback. The silent-renewal/WebAuthn/Kerberos gap converts decision 3 from a governance gate into an availability break on real user paths, and no enumeration net exists to prevent regression. This blocks implementation-stage handoff as reviewed.

VERDICT: FAIL - six unstamped mint sites (silent renewal x2, WebAuthn x2, Kerberos x2) with no enumeration test or documented exclusion; contract docs (error-codes.md, openapi.yaml, feature-matrix.md, config-reference.md) unupdated per AGENTS.md 5.6; trust-chain precondition (Sec F3) unstated; Mount-warn untested (QA F4); explicit ["\"]-config and non-string-claim tests missing
