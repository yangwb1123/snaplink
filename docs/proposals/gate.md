All cross-checks complete. Here is the gatekeeper report.

---

# Gatekeeper Cross-Check — `domains/tokenanomaly` Direction 1 (design at `c8ab9768`)

I re-verified the contested evidence myself rather than trusting either side. Findings fall into three classes.

## A. Resolved in the design (dismissed with reasons — no action)

| Finding | Design disposition |
|---|---|
| Per-replica observation tables bound the flagship promise (DB F6, arch F5, dist scenario) | Design risk 9 documents it explicitly; spec E2E constrained to single-server. Accepted limitation |
| Subject-scoped (not family-scoped) revoke for geo findings (arch F8-adjacent, protocol table) | Decision 8 documents it and pins the fallback in a contract test |
| Zero-value byte-identity fail-open (all reviewers) | Decisions 1/2/9 + failure-mode table; verified `""` path |
| JTI stamp fail-loud asymmetry (DB F5, arch F11, QA F6) | Failure-mode table documents it; generator-level test exists; not failure-injectable |
| Redis JSON compat both directions (DB §4, protocol #8) | Decision 5; verified `omitempty` + unknown-key semantics |
| Oracle safety, no-store headers, wire bodies untouched (protocol #1–6, security §4) | Decisions 3/6; verified Offer-after-response |
| Audit evidence truncation (security F7) | **Refuted by arch F12 and my own math: 249×2+248 = 746 < 1024 cap. No issue** |
| `postgres` conformance peer wording (protocol F2, DB F2, QA F4) | Not design-blocking — but text is **wrong in spec acceptance AND design Verification**; must be fixed in the same change |

## B. Blocking — neither resolved nor dismissed with reasons

**B1 (High, consensus: security F1 / architect F1 / protocol F1) — Introspector-geography semantics is absent from the design.** I verified: the only production thumbprint-bearing Offers are the two introspection seams (`EndpointUserinfo` has no Offer site); `observation` has no `Kind` field, so the table cannot distinguish access-token (resource-server egress) from refresh-token (presenter) geo; and the design's Decision 8 test #2 actively teaches `velocity → ActionRevoke` → subject-scoped `DeleteAllForSubject`. Every access-token holder (RS, token-exchange recipient) becomes a revocation trigger; multi-region RS fleets produce systematic false lockouts. The design neither resolves this (no `token_kind` evidence, no exclusion) nor dismisses it (it never mentions it). Architect D2 decision required before implementation.

**B2 (Medium, consensus: security F2 / architect F2) — Decision 6's "this closes the hole" is refuted as written.** I verified the rotation Offer (`token_refresh.go`) carries no Thumbprint; only `/token/introspect` presentations are observed. The design's dismissal (zero hot-file changes) is a reason, but it does not narrow the overclaimed headline — the spec/design asserts coverage of rotation-path theft it does not deliver. Architect D1 decision required: extend the rotation seam (D1-b) or narrow the claim (D1-a); the current text is false assurance either way.

**B3 (Medium, distributed F2) — the design's clock-skew failure-mode row is refuted.** I verified `updateGeoLocked` takes `abs()` of the gap and `minSwitch` is monotonic-decreasing: an NTP step-back between two geo sightings shrinks the gap, flipping benign `multi_geo` into `critical velocity`, which re-dispatches every sweep under the design's own seeded revoke policy. The design claims "skew only delays/advances the finding" — demonstrably false. Needs the ingestion clamp (`ev.At` bounded to `[now-window, now]`) or an explicit NTP-discipline decision plus the unit test.

**B4 (Medium, QA F1 / DB F1 / architect F3) — change map omits both pinned test files; the design's "maxversions_test asserts only positivity" is refuted.** I verified HEAD: `maxversions_test.go:58` pins `RefreshTokensMaxVersion() != 7` (DB review right, QA's characterization wrong) and `migration_test.go:72` pins `want 7`. The v8 commit fails the sqlite package until both pins move; the change map must list both files with the bump + legacy `jti == ''` assertion.

**B5 (Medium, DB F3 / architect F4) — the one unindexed scan path is the exact path geo findings trigger.** `DeleteAllForSubject`/`CountForSubject` scan `refresh_tokens` by `user_id [AND client_id]` (indexes: client/expires_at/family only). The design activates this path via Decision 8 but its "no index needed" statement only covers JTI. Decide D3-ii (subject index in the same v8 migration) or defer with a measured threshold.

**B6 (Medium-High, distributed F1) — enforcement reach is per-replica in the stock memory backend.** Verified: `BuildRefreshTokenStore` defaults to memory; the executor's `KindTokenRevoked` broadcast carries no `MetaRevokedToken` and is an unactioned dead letter for refresh tokens. A finding on replica B cannot revoke a token held by replica A. Decision 9's docs plan must state the shared-store/single-replica topology requirement for `revoke_family` enforcement — currently absent.

## C. Non-blocking obligations that must land with the code (AGENTS.md §5)

Text fixes (B-cluster adjacent): risk 5's `count` footgun direction (protocol F3/arch F7 — fail-closed non-match, not "different meaning"); trusted_proxies/XFF precondition (security F3/arch F10); rate-limit + re-dispatch guidance (security F6/dist F3/arch F9); LWW clientID + empty-ClientID every-client collapse (security F5/arch F8); eviction-by-insertion suppression note (security F4/dist F4 — accepted hardening, should be stated). Test obligations: five full-Event-equality seam tests in Imp-1 (QA F3, P0 — I confirmed no Offer-content assertion exists in the repo today); recommended single-server E2E (QA F2). Worktree hygiene: pre-existing `make ci` fmt blocker on untracked `test/region_token_contract_test.go` (QA F5) must be resolved before handoff.

## D. Worktree observation

The worktree already carries an **uncommitted implementation of the design as-written** (extractor, five seams, `RefreshToken.JTI`, sqlite v8 with test pins bumped to 8, Evidence `geos`/`count`), and it reproduces the unresolved gaps verbatim: no `Kind` on `observation`, no rotation-seam Thumbprint, no `At` clamp. A design revision for B1–B3 must be folded into that in-progress implementation, not just the doc.

---

**Bottom line:** mechanics verified sound, but the gate test is "resolved or dismissed with reasons" — B1 (the consensus High) is absent from the design entirely, B2/B3 rest on claims I verified as false in source, and B4/B5/B6 are unresolved design decisions the change map and docs plan do not cover. The reviews' "no rework required" referred to the code mechanics, not the semantics decisions (architect's D1/D2) that the design stage must make. These block implementation of the design as written.

VERDICT: FAIL - B1 introspector-geography semantics unresolved (no token_kind/exclusion decision; Design 8 teaches velocity→revoke on RS-egress geo); B2 Decision 6 "closes the hole" claim refuted for rotation-path theft (D1 decision missing); B3 clock-rollback row refuted (abs() gap fabricates critical velocity; no At-clamp); B4 change map omits maxversions_test.go and migration_test.go v7 pins (design's "only positivity" claim false); B5 subject-revoke index decision missing; B6 per-replica revoke-reach/topology requirement absent from Decision 9 — plus mandatory same-change text fixes (postgres peers, count footgun direction, trusted_proxies precondition) and P0 seam tests; pre-existing make ci fmt blocker must be cleared before handoff.
