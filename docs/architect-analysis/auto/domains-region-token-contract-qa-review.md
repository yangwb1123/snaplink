# QA Review: `domains/region` serving-region token contract (design stage)

Review of `docs/auto/domains-region-token-contract-design.md` (revision
`744580d8` "Stage: design"; design and spec are committed, zero
implementation of the three decisions exists in the tree). Every planned
test below is therefore **Proposed**; every baseline claim was re-verified
against the current working tree and the committed gates.

Evidence labels: **Verified** = reproduced in this review; **Partial** =
design states it but evidence is indirect; **Proposed** = planned, not yet
implemented; **Missing** = gap found.

---

## 1. Test inventory and commands actually run for this revision

| Command | Result | What it establishes |
|---|---|---|
| `go build ./... && go vet ./...` | PASS | Whole-tree compile + vet for the reviewed revision |
| `go test -run 'TestMaintainability_|TestArchitecture_' .` | PASS | File-size budget (500-line cap), complexity, fan-out ceilings, maxdepth, layer map — the gates every placement in the design is tuned to |
| `go test ./interfaces/ssoclient/rs/` | PASS | 32 tests / 8 files — the decision-3 regression net (`validate_test.go`, `introspect_test.go`, `middleware_test.go`, dpop/authz/trusted_proxy) |
| `go test ./protocols/oauth/` | PASS | Introspection + cache tests (`handle_introspect_test.go`, `introspect_cache_test.go`) — the decision-1 echo regression net |
| `go test ./infrastructure/defaultimpl/...` | PASS | All issuers incl. `ed25519/ecdsa/rsa_jwt_issuer_test.go`, `at_hash_test.go`, `issuer_extras_test.go` — the decision-1 projection regression net |
| `go test ./interfaces/sso/ -run 'TestRcov2D_' -v` | PASS (4/4) | `rootcov2_discovery_test.go` — the decision-2 byte-identity net named by the design |
| `go test ./test/ -run 'TestResidency' -v` | PASS (19/19) | `region_residency{,_access,_grant,_mfa}_test.go` — the fixture pattern the E2E plan reuses |

NOT run (deliberately, design-stage): `make ci` (includes `race`, nested
modules, config validation, route-contract, capabilities), `go test ./... -race`,
`make chaos-test` (manual suite), `make bench-gate` (opt-in), `make load-test`
(manual k6). These are the implementation handoff gates; see §5.

## 2. Design claims re-verified against source

All load-bearing numbers and structural claims in the design were checked
and hold:

| Design claim | Evidence |
|---|---|
| `server_discovery_config.go` and `handle_introspect.go` both exactly 500 lines | Verified via `wc -l`; budget test fails at 501 |
| `server_finish_login.go` 499, `server_login.go` 498, `options_misc.go` 496, `server_tenant_residency.go` 493, `sso_wiring.go` 438, `server_discovery_cache.go` 295, `introspect_session.go` 30 | Verified via `wc -l` |
| `protocols/oauth` frozen at 12 non-test files, `interfaces/sso` at 60 | Verified: `directory_fanout_test.go:59-61` |
| `validateIntrospectedClaims` presence-conditional shape (`Issuer != ""`, `ExpiresAt != 0`) — the copy-paste trap | Verified: `interfaces/ssoclient/rs/introspect.go:122-135` |
| `wireIntrospection` embed alone is insufficient; `Claims` literal in `ValidateTokenWithIntrospect` is explicit field-by-field | Verified: `introspect.go:46-58` — every field is a separate `w.X` assignment |
| `applyStaticClaimsAndSecurity` ASSIGNS a fresh `ClaimsSupported` literal | Verified: `server_discovery_config.go:381-387` — overwrite ordering hazard is real |
| `applyServingRegionMetadata` must slot between `applyStaticClaimsAndSecurity` (`:115`) and `signDiscoveryMetadata` (`:125`) | Verified in the `buildOIDCConfiguration` apply chain |
| `KeyServingRegion = "serving_region"` exists, reused as claim name | Verified: `shared/core/consts_wire.go:145` |
| Introspection deliberately ungated, doc at `server_tenant_residency.go:156-159` | Verified |
| Three per-issuer `ed25519IDPayload` literals, no shared ID builder | Verified: `ed25519_issue.go:91`, `ecdsa_issue.go:67`, `rsa_issue.go:58` |
| Shared access-payload projection (`buildAccessPayload` / `claimsFromPayload`) | Verified: `issue_payload.go:26-38`, `validate_claims.go:20` |
| `refreshRotatedSubject` (`token_refresh.go:245`) and `tokExSubject` (`token_exchange_stages.go:389`) are pure builders without ctx | Verified |
| `residencyFixture` pinned-resolver pattern reusable for E2E | Verified: `test/region_residency_test.go:54`, `ConfigPinnedResolver` |
| Decode helpers exist for E2E | Partial: `decodeAccessTokenPayload` exists (`test/rar_test.go:107`); ID-token helper `decodeIDTokenSub` (`test/pairwise_test.go:252`) decodes sub only — a full id_token payload decode helper is needed (finding F6) |
| `writeChallenge` structure allows the 403 branch before the challenge write | Verified: `middleware.go:101-140` — no-store headers first, then `WWW-Authenticate`, then 401 |
| `WithLogger` exists for warn-capture tests | Verified: `interfaces/sso/options.go:343` |

## 3. Requirement-to-test matrix

Status: all rows for new behavior are **Proposed** (design-stage). Existing
regression nets: **Verified PASS** (ran in §1).

| Requirement (spec) | Planned test | Status / evidence |
|---|---|---|
| D1: access-token `serving_region` round-trip, all 3 issuers | Issuer unit tests via shared `buildAccessPayload` | Proposed — one shared-path test suffices (projection is shared, verified); precedent `at_hash_test.go` |
| D1: empty ⇒ claim absent, byte-identical | Same tests, empty input | Proposed — pinned; `TestResidency_NoRegionWired_LoginSucceeds` is the wire-level precedent (Verified PASS) |
| D1: `claimsFromPayload` round-trip | defaultimpl round-trip test | Proposed |
| D1: introspection echo | `populateAccessIntrospectionBody` test (precedent `handle_introspect_test.go:682-721`) + negative (no claim ⇒ no key) | Proposed — negative test NOT explicitly in the design's plan (finding F5) |
| D1: §5.5 immunity | E2E login with `claims` param; unit: `oidc.ProjectIDTokenClaims` projection | Proposed |
| D1: ID-token stamp on ALL THREE issuers | **Missing from the design's test plan** — only E2E (single fixture issuer) touches the ID path (finding F2) | Proposed |
| D1: refresh rotation re-stamps (mint-time semantics) | E2E only in the plan; unit test for `refreshRotatedSubject` param + cross-region grant test missing (finding F4) | Proposed |
| D2: discovery field + `claims_supported` when wired | New discovery test beside `rootcov2_discovery_test.go:40`; live-endpoint precedent `test/acr_values_supported_test.go:45` | Proposed |
| D2: byte-identical when unwired | `rootcov2_discovery_test.go` unchanged | Verified PASS (ran) |
| D2: signed_metadata covers the field | Extend discovery test to verify JWS | Proposed |
| D2: warn when advertisement wired without middleware | **Missing from the design's test plan** (finding F3) | Proposed |
| D3: local gate 4-way matrix | New `validate_test.go` cases (in-set / out-of-set / missing-claim / empty-config) | Proposed |
| D3: remote gate same matrix + fail-closed on missing claim | New `introspect_test.go` cases (httptest precedent `:40`) | Proposed — the #1 correctness risk (finding F1) |
| D3: middleware 403, no challenge; 401 unchanged | New `middleware_test.go` cases (precedent `:13`, `:37`) | Proposed |
| D3: DPoP path carries the sentinel | Extend dpop tests | Proposed (design states it; test not explicit) |
| D3: E2E accept/deny with fixture-minted token | New `test/` test using `residencyFixture` + rs SDK | Proposed |
| Cross-cutting: openapi / error-codes / feature-matrix | Doc review in same change | Proposed — `region_not_allowed` row verified at `docs/error-codes.md:88`; login `serving_region` verified at `docs/openapi.yaml:12156`; `OpenIDConfiguration` schema (`:15243`) description already says "field set is dynamic", so the optional property is consistent |

## 4. Findings

### F1 — High: remote-gate fail-closed trap: acceptance test must be written first and pin BOTH modes

**Evidence (Verified):** `validateIntrospectedClaims` (`interfaces/ssoclient/rs/introspect.go:122-135`) is presence-conditional for every neighbor check (`c.Issuer != "" && ...`, `c.ExpiresAt != 0`). A developer adding `if c.ServingRegion != "" && !c.HasServingRegionIn(...)` — the natural copy of the `Issuer` pattern — silently fails OPEN, and the local gate in `validateClaims` would still pass, so the package test suite alone would not catch the asymmetry until an introspection-mode test exists.

**Regression risk:** an RS in introspection mode accepts region-unpinned tokens in a pinned deployment. The failure is silent (no error, no log), and only manifests in remote-mode deployments.

**Exact tests to add (first, before the implementation):**
1. `TestValidateTokenWithIntrospect_ServingRegionMissingClaim_FailsClosed` — introspection body `{"active":true,"iss":"...","aud":"..."}` (no `serving_region`), `Config{AllowedServingRegions: ["eu-west-1"]}` ⇒ `errors.Is(err, ErrServingRegionMismatch)`.
2. `TestValidateTokenWithIntrospect_ServingRegionMismatch` — body with `serving_region:"us-east-1"` ⇒ same sentinel; body with `"eu-west-1"` ⇒ OK.
3. `TestValidateToken_ServingRegion_FourWay` (local): in-set OK; out-of-set sentinel; missing claim + non-empty config ⇒ sentinel; empty config ⇒ OK.

**Acceptance assertion:** the missing-claim case returns the sentinel in BOTH modes; `errors.Is` works through the DPoP wrap (`validateByMode`).

**Also unpinned:** the design says the local gate sits "at the END of `validateClaims`" but does not pin the position inside `validateIntrospectedClaims`. Pin it: region gate LAST in both functions so iss/aud/exp sentinels keep priority (matches the middleware's 401-vs-403 split — a mismatched-issuer token must surface `ErrIssuerMismatch`, not a 403).

### F2 — High: the three per-issuer ID-token literals are the design's own "only drift point" but the test plan never exercises them directly

**Evidence (Verified):** three separate `ed25519IDPayload{...}` literals at `ed25519_issue.go:91`, `ecdsa_issue.go:67`, `rsa_issue.go:58`; no shared ID builder. The design's test plan's "Issuer round-trip (Ed25519 + ECDSA + RSA)" targets `Subject.ServingRegion` — the shared ACCESS-token path where one test covers all three. The ID path (`IDTokenRequest.ServingRegion`) is per-issuer code and is only covered by E2E, which exercises exactly one issuer (whatever `emitLoginIDToken`'s `idIssuer` resolves to in the fixture).

**Regression risk:** if one of the three literals misses the stamp, unit tests stay green (shared-path tests pass), and the E2E may also stay green if the fixture login uses one of the other two issuers. The omission ships as a per-alg wire difference.

**Exact tests to add:**
- `TestIssueIDToken_ServingRegion` per issuer: `IDTokenRequest{ServingRegion: "eu-west-1"}` ⇒ decoded payload `serving_region == "eu-west-1"`; `""` ⇒ key absent. Precedent: `TestIssueIDToken_AtHash` (`at_hash_test.go:77`) or `TestECDSAJWT_IDTokenAndUserinfo` (`ecdsa_jwt_issuer_test.go:251`).
- Optionally a shared table test across the three issuers to make the byte-identity of the claim set checkable ("keeps the three-issuer byte-identity invariant trivially checkable" — the design's own goal).

**Acceptance assertion:** all three issuers decode the claim identically; empty ⇒ absent in all three.

### F3 — High: decision-2's only hard-budget edit is a 500-line cliff; make the `baseAdvertisedGrants` move the primary plan

**Evidence (Verified):** `server_discovery_config.go` is exactly 500 lines; the call must land in `buildOIDCConfiguration`'s apply chain (between `:115` and `:125`), i.e. +1 line in a 501-fails file. The design's primary resolution (compress the `buildOIDCConfiguration` doc comment by one line) works only if nothing else in that file changes and the compression itself is accepted; its own fallback (move `baseAdvertisedGrants`, 11 lines, to `server_discovery_cache.go`, 295→306) is deterministic, touches zero logic, and leaves headroom.

**Recommendation:** adopt the fallback as the primary plan; keep the comment compression as the fallback. The design's text is internally consistent but convoluted ("impossible" → "Resolution") and risks an implementer "fixing" the doc comment instead of doing the move.

**Acceptance assertion:** after the edit, `go test -run 'TestMaintainability_' .` passes and `git diff --stat -- interfaces/sso/server_discovery_config.go` shows a net-zero line delta.

### F4 — Medium: the Mount-time warn mitigation (decision 2) has no planned test, and the fail-open direction should be confirmed

**Evidence (Verified):** `WithLogger` exists (`options.go:343`), so a warn-capture test is cheap. The design's failure-mode table says a deployment that wires `WithServingRegionAdvertisement` without `WithRegionMiddleware` produces a discovery document that advertises a region the tokens don't carry — a "lie" that makes any decision-3 gate fail closed on every token. The design's mitigation is warn-only, fail-open.

**Exact test to add:** in `interfaces/sso`, construct a server with `WithServingRegionAdvertisement("eu-west-1")` and NO `WithRegionMiddleware`; capture logs via `WithLogger`; assert exactly one Warn mentioning the advertisement/middleware mismatch and that discovery still serves the field. If no log-capture sink exists in the sso test package, add a minimal `spi.Logger` stub (fixture need).

**Acceptance assertion:** the warning fires at Mount; discovery output unchanged (fail-open preserved).

### F5 — Medium: refresh-rotation re-stamp is pinned only at E2E level; the unit surface of the signature change is untested

**Evidence (Verified):** `refreshRotatedSubject` (`token_refresh.go:245`) gains a parameter — a signature change with no planned unit test. The design's "don't later fix this as a bug" pin (rotation re-stamps the serving region, so an RS pinned to one region sees the claim CHANGE on rotation) needs a test that makes the intended semantics executable, not just documented.

**Exact tests to add:**
1. Unit: `refreshRotatedSubject` with `servingRegion="eu-west-1"` ⇒ `Subject.ServingRegion` set; `""` ⇒ unset.
2. Grant-level: login in region A, refresh at `/token` in region B (two pinned resolvers / per-request header resolver) ⇒ rotated token decodes with B, not A. This is the case an operator will file as a bug.

**Acceptance assertion:** the rotated token's `serving_region` equals the region that served the refresh; the login region is NOT preserved.

### F6 — Medium: E2E fixture gap — full id_token payload decode helper

**Evidence (Verified):** `decodeAccessTokenPayload` exists (`test/rar_test.go:107`); the ID-token helper `decodeIDTokenSub` (`test/pairwise_test.go:252`) only returns `sub`. The E2E plan asserts `serving_region` on BOTH tokens, so a full-payload id_token decode helper (or a generalized `decodeTokenPayload`) is required.

**Acceptance assertion:** the new helper decodes the fixture's id_token and asserts `serving_region == "eu-west-1"` and `at_hash` presence (the at_hash invariant is adjacent and already covered at unit level).

### F7 — Low: introspection echo negative test missing from the plan

The plan covers "introspection body from a minted token includes `serving_region`" but not the byte-identity negative (token minted with no middleware ⇒ RFC 7662 body has no `serving_region` key at all). The design's zero-value claim ("Empty ⇒ claim omitted ⇒ byte-identical") deserves a body-level assertion, not just a payload-level one. Precedent: `handle_introspect_test.go:682-721` direct-call pattern. Also add one cache-path assertion: an `IntrospectionCache` hit with a body map containing `serving_region` returns it verbatim (`introspect_cache_test.go` precedent exists).

### F8 — Low: introspection split verification step

The "pure move" (new `introspect_body.go`, merge `introspect_session.go`) has no mechanical check beyond the 12-file ceiling and 500-line budget. Because the moved functions are referenced directly by tests in the same package (`handle_introspect_test.go:686-708`), the suite itself survives the move. Add a review checklist item: `git diff -M --find-renames` to confirm the moved functions are byte-identical (names, signatures, comments), and confirm `handle_introspect.go` stays ≥400 lines of headroom after the drop (~415).

### F9 — Info: E2E gate naming

AGENTS.md's documented E2E command is `go test ./test/ -run TestE2E -v`, but the residency suite is named `TestResidency*` and the design's new tests will follow that pattern. The effective gate is `make test-e2e` (`go test -race -count=1 ./test/...`). The handoff instructions for this change should reference `make test-e2e`, not `-run TestE2E`, or the new tests silently drop out of the documented gate.

### F10 — Info: chaos/load/bench suites correctly out of scope

`make chaos-test` is explicitly manual ("run on main/pre-release, not every PR"); `bench-gate` is opt-in and not part of `make ci`; `load-test` is manual k6. The change adds one ctx read + one string copy per mint and a static config read at discovery-build — no hot-path or concurrency-atomicity surface. The existing `refresh_rotation_chaos_test.go` covers rotation fail-closed and is unaffected by the region stamp. No new chaos/bench tests required; note this in the handoff so nobody adds them speculatively.

## 5. Prioritized scenario list

P0 (block the change if untested):
1. Local gate four-way: in-set pass / out-of-set sentinel / missing-claim+configured fail-closed / empty-config pass.
2. Remote gate same four-way + `active:false` precedence (inactive wins over region sentinel).
3. ID-token stamp on all three issuers + empty ⇒ absent (F2).
4. Discovery wired ⇒ field + `claims_supported` + signed_metadata verifies; unwired ⇒ byte-identical (existing `rootcov2_discovery_test.go` unchanged).

P1:
5. Middleware: `ErrServingRegionMismatch` ⇒ 403, `region_not_allowed`-style body, NO `WWW-Authenticate`; invalid-token 401 + challenge unchanged; DPoP path 403.
6. Introspection echo present/absent + cache-hit verbatim (F7).
7. E2E pinned `eu-west-1`: login ⇒ both tokens carry claim; auth-code exchange at `/token` re-stamps; refresh rotation re-stamps; cross-region rotation (F5); RS SDK accept in-region / deny out-of-region.
8. §5.5 `claims` parameter: both tokens still carry the field.

P2:
9. Mount warn when advertisement wired without middleware (F4).
10. Race: discovery build concurrent with option read (static after Mount — assert no data race under `-race`; nothing new shared).
11. Oracle-safety: garbage/expired token still reports its higher-priority sentinel before the region gate (local) — asserts the "at the END" placement.
12. Break-glass/admin mints carry no claim — assert empty in the E2E/unit where those paths are exercised (documented "unconstrained").

Recovery paths: introspection AS outage (`ErrIntrospection`) is unchanged by this design — no new recovery surface. Refresh rotation failure remains fail-closed (`refresh_rotation_chaos_test.go`) — the region stamp must not alter that path (verify with the existing chaos suite on main).

## 6. CI/manual-suite gaps, flake risks, fixtures, exit criteria

**CI gaps (all Proposed-resolution):**
- No test currently asserts the remote-mode fail-closed shape (F1) — the highest-severity gap.
- No per-issuer ID-token stamp test (F2).
- No warn-capture test for the decision-2 mitigation (F4).
- `go test ./test/ -run TestE2E -v` (AGENTS.md) does not run the residency-named tests — use `make test-e2e` (F9).

**Flake risks:** none observed in the runs (§1) — the residency suite is deterministic (httptest + memory stores, no sleeps). New E2E must follow the fixture pattern: no timing-based assertions; token-expiry tests must use the config skew rather than wall-clock sleeps.

**Fixtures needed:**
1. Full-payload id_token decode helper in `package ssotest` (F6).
2. `residencyFixture` variant (or option list) adding `WithServingRegionAdvertisement` for decisions 2/3 E2E.
3. Minimal `spi.Logger` capture sink for the warn test (F4), if none exists.

**Exit criteria (implementation handoff):**
1. `go build ./... && go vet ./...` after every edit; `go test -run 'TestMaintainability_|TestArchitecture_' .` (the budget tests the placements are tuned to — `server_discovery_config.go` net-zero delta, `server_finish_login.go` 499→500 exactly).
2. All P0/P1 tests above green; existing regression nets unchanged and green: `interfaces/ssoclient/rs`, `protocols/oauth`, `infrastructure/defaultimpl/...`, `interfaces/sso` (Rcov2D), `test/` residency suite.
3. `go test ./... -race`; `make test-e2e` (not `-run TestE2E`).
4. `make ci` full gate (includes modules, config, route-contract, capabilities, docs checks for the openapi/error-codes changes).
5. Manual (main/pre-release, not required for the PR): `make chaos-test` to confirm the refresh-rotation chaos suite still passes with the stamp; `make bench-gate` only if issuance benchmarks move (not expected).
6. Doc updates verified in the same change: `docs/openapi.yaml` (login schema description, `OpenIDConfiguration` property, token schemas), `docs/error-codes.md:88` row, `docs/feature-matrix.md` row 150.

**Explicit non-goals for this change (design-consistent):** no metrics/audit changes, no server-side gate changes (`residencyGateLogin`/`residencyGateTokenGrant`/`residencyDeniedForAccess` byte-identical), no new persistence, no chaos/bench additions.
