All anchors verified. I have the complete picture: the run's committed design artifact contains only the 17-line summary (the claimed 170-line design was never committed — verified via `git show d0a697bd`), so the A1–A3 mapping must be reconstructed from the summary plus sibling-run designs (`emit-tenant-id-roles-in-buildaccesspayload-and-r-bbad8fa5`, `b4-1-emit-...-7df5e5c3/task-1-named-test-plan.md`, the entitiescmd + configcmd specs) and checked against the tree. Here is the audit.

---

# Audit: A1–A3 acceptance mapping — falsifiability and completeness

## 0. Blocking deliverable-state finding

**S0 — The acceptance mapping itself is not on disk.** The run's design artifact (`artifacts/design-a77de8a6/task-1-design.md`) is a 17-line summary; the claimed "170 lines" with the file-by-file A1/A2/A3 table, 10 compatibility constraints, 10 failure modes, and 6 migration steps were never committed (git HEAD `d0a697bd` = same 17 lines). The summary even cites itself as the location of the full design. Consequences:

- The "six falsifiable allowlist tests" are **unenumerated** — no names, files, or assertion predicates exist anywhere in the committed deliverables (the term "six" appears only in the summary).
- The "B-series boot-validation tests" are **unenumerated** — "B-series" appears in exactly one file in the repo (the summary). No names, files, or assertions.
- The sibling full designs that *do* enumerate tests (`task-1-named-test-plan.md`, `emit-…/task-1-design.md`) **diverge from the summary on the core semantics** (sentinel-when-unset vs Host-fallback-retained; cc-roles-presence vs cc-emits-none; NewServer panic vs runtime fail-closed; mint-500 vs discovery-503). An implementer cannot tell which mapping is authoritative.

Everything below is audited against the summary's claims, using the tree as ground truth. Every anchor cited was re-verified at HEAD.

## 1. A1 — T-8(a) per-signer tests, byte-compat negative, wire round trip

**1.1 Per-signer tests: falsifiable ✓ (anchors verified).**
`TestRFC9068_PayloadCarriesRequiredClaims` (`infrastructure/defaultimpl/ed25519_rfc9068_test.go:69`), `TestECDSAJWT_RFC9068Claims` (`ecdsa_jwt_issuer_test.go:60`), `TestRSAJWT_RoundTrip_BothAlgs` (`rsa_jwt_issuer_test.go:20`) all exist. The extensions fail pre-change by compile gate (`Subject` has no `Roles`; `ed25519Payload` has neither field) and `TestRFC9068_ValidatePopulatesAccessTokenClaims` (:230) fails both by compile gate (`TokenClaims` lacks the fields) and at runtime (`claimsFromPayload`, `validate_claims.go:16`, projects neither). C6's precedence test would fail on HEAD (`tenantHintFromClaims`, `governance.go:477-483`, reads only `Extra[KeyTenantID]`).

**Gaps in A1:**
- **The reserved-key scrub (C4) is not pinned in the current deliverable.** The sibling plan's C4 is the *only* test that fails on HEAD's runtime behavior (`buildAccessPayload` copies `subject.Claims` into `ext` unscrubbed at `issue_payload.go:36`; a `Claims{"tenant_id":"evil"}` today reaches `ext`). The current summary pins "one unconditional literal" for tenant_id but says nothing about scrubbing — if the scrub was dropped, the "no `ext.tenant_id`/`ext.roles`" wire-hygiene acceptance has no test; if kept, it is unpinned.
- **The wire round trip's grant is unpinned — and the sibling's version contradicts the design.** The sibling plan's R1 asserts `roles == ["billing.admin"]` on a **client_credentials** token; the current summary pins "client_credentials emits none by design". A cc-leg asserting roles **fails by design**; the only compatible candidate (refresh wire test, `TestRcov_RefreshGrant` at `rootcov_flow_test.go:384` — exists) is not referenced by the current deliverable.
- **"client_credentials emits none by design" has no named falsifiable test.** The entitiescmd per-grant matrix (case 7) asserts `tenant_id` on all 7 grants but **never asserts roles-absence on cc**; case 9's grant is unpinned ("when `POST /token` runs") — if the implementer picks cc, case 9 *fails by design*; if a user grant, nothing pins which. The design pins a per-grant roles expectation table (cc: absent; user grants: present-when-wired) that exists nowhere.
- **"roles resolved fresh per mint"** — a pinned design behavior — has no freshness test (assign → mint → reassign → mint → assert delta) in any named mapping.

**1.2 Byte-compat negative: partially falsifiable, one vacuous leg.**
- The unbound-client case (entitiescmd case 5: `TenantID:""` → no `tenant_id` key) is a legitimate green-today regression pin. ✓
- **Golden capture order is unpinned in the committed artifact.** Byte-identity is falsifiable only against *pre-change* captures (the sibling design's migration step 1 with the existing `fixedClock` at `ed25519_jwt_issuer_test.go:171`). The summary lists "6 migration steps" but never states step 1 = pre-change capture; a post-change capture makes the "single-tenant byte-identical" acceptance vacuous.
- **The `Roles: []string{}` leg is vacuous for this codebase.** Payloads marshal with Go's `encoding/json` + `omitempty`, which omits *any* zero-length slice (the `ServingRegion` precedent at `ed25519_types.go` documents exactly this discipline). A `[]string{}` assignment produces zero wire bytes, so the design's "must assign nil, never `[]string{}`" requirement cannot be falsified by any wire test — the entitiescmd design's F3 claim ("omitempty does not drop empty slices") is factually wrong for the stdlib. The nil-discipline is enforceable only by review, and no test can detect it.

## 2. A2 — T-1.2 local round trip + cross-repo fixture contract

**2.1 Mint→validate round trip: falsifiable ✓** (C5/C6, see 1.1). **But the T-1.2 issuer-coherence legs (entitiescmd cases 3/11) are green on HEAD and falsify nothing:** with `WithIssuer("https://sso.test")` wired, `resolveIssuer` (`server_discovery.go:251-258`) already returns the configured value and the minted `iss` is the signer name — both already != the request Host. They are regression pins for the *configured* state; the direction's "never Host-derived" acceptance is untested (see 3.2).

**2.2 Introspection contract is unpinned, and one test asserts the opposite of the only pinned behavior.** The entitiescmd requirements case 8 asserts "the same `tenant_id` claim is **echoed**" — conditional on an unpinned R0 decision — while the sibling design explicitly pins **no-echo** (enumerated `populateAccessIntrospectionBody`, with a documented asymmetry vs `serving_region`). The current summary pins neither. Case 8 is simultaneously (a) not a criterion ("implement only if…"), and (b) if implemented per the sibling design, asserting the inverse of the pinned contract.

**2.3 Cross-repo fixture contract: unfalsifiable in-repo and contradictory as inherited.**
- Verified: `scripts/mint-token.sh`, `test/e2e/fullstack.sh`, `deploy/docker-compose.verify.yml` do not exist in this repo (sink-side, out-of-tree). No in-repo test can fail on X1–X3.
- **X1's `--assert-claims` (requires top-level `tenant_id` **and** `roles` on a client_credentials-minted token, per the sibling plan) is unsatisfiable under the current design's "cc emits none by design"** — the fixture contract as previously pinned can never pass. The current deliverable does not re-pin X1 (no mention of `mint-token.sh`, `AUDIT_ALLOW_DEV_AUTH`, or the 422 fixture).
- **K1 — the only in-repo falsifiable half — is absent from the current deliverable**, and as specified in the sibling plan (`seedClient` gains `Client.Roles`, `test/testkit/testkit.go:194`) it cannot compile under the current design (no `Client.Roles`; roles come from the permissions provider). The summary's refinement #3 explicitly rejected `Client.Roles`.
- The landing predicate (X1∧X2∧X3∧K1 as a gate condition, which the sibling plan demands) is not stated as a gate condition anywhere in the committed artifacts.

## 3. A3 — six allowlist tests, oidc_discovery:80 extension, trusted-proxy re-pointing, B-series

**3.1 (Headline) The direction's "never Host-derived" acceptance has no satisfiable, non-vacuous test under this design — and the design contradicts the direction.**
The direction mandates: *"with server.issuer unset, discovery issuer and JWT iss never derive from the request Host (extend `test/oidc_discovery_test.go:80` to assert the Host-derived fallback is gone…)"*. Under the summary's design every state is unsatisfiable or vacuous:
- allowlist non-empty + issuer unset → **boot error** (unreachable state);
- allowlist empty → **Host fallback retained by design** → discovery issuer *is* Host-derived (`buildBaseMetadata` seeds `Issuer: base`, `server_discovery_config.go:144`; `resolveIssuer` returns `requestBaseURL`) — the direction-mandated extension **fails by design** in the only reachable issuer-unset state;
- issuer set → the fallback was unreachable on HEAD too → "fallback is gone" is vacuous.

The sibling design satisfied the direction (sentinel-when-unset, `TestDiscovery_IssuerIsSentinelWhenUnset` failing on HEAD; trusted-proxy trio re-pointed to sentinel). The two designs pin **opposite assertions for the same tests** (sentinel vs Host-derived-legacy vs config-pinned-200), and the committed summary chose the one that breaks the direction's acceptance. Either the legacy carve-out must be removed or the acceptance amended — as committed, this is an acceptance criterion *without* a falsifiable test, in a design that violates its own mandate. Same verdict for the direction's "only allowlisted values are emitted": it reduces to the boot check + 503 gate, is violated in the legacy state, and has no independent test.

**3.2 The 200-with-pinned / 503-only tests: coherent, partially falsifiable, but under-specified.**
- The re-pointed untrusted-peer test (200 + config-pinned issuer) is compile-gated pre-change (no `WithIssuerAllowlist` exists anywhere — verified) and post-change-falsifiable for a real regression: if the allowlist gate ran *before* peer-trust filtering, the XFH-derived base (`evil.example`) would 503 and the test catches it. ✓ as a pin.
- The 503 leg **is genuinely falsifiable**: the discovery handler has no 503 path today (only 200/304 and a 500 marshal-error branch, `server_discovery_config.go:60-88`). A non-allowlisted base returns 200 on HEAD. ✓
- **But the summary is self-contradictory about what the re-pointed tests assert**: "empty allowlist = byte-identical legacy (Host fallback retained, **protected by re-pointed trusted-proxy tests**)" vs "the **re-pointed test asserts 200 with config-pinned issuer**". The three existing tests (`test/trusted_proxy_gate_test.go:267/283/299`) wire no `WithIssuer` and assert Host-derived values; both readings cannot hold for the same test set. The per-test harness state and assertions are not enumerated. The legacy-state protection (the "byte-identical legacy" pin) is consequently **unpinned**: if all three tests move to the allowlist state, the legacy untrusted/unset/trusted assertions (and the no-503-in-legacy property) lose their tests.
- Unpinned: the trusted-peer + allowlist interaction (XFH honored → base ∉ allowlist → 503?), and the 503 gate's comparison semantics (exact string? origin? trailing-slash normalization — the configcmd spec pins normalization for the CLI gate, but the discovery gate's semantics are unspecified), which determines whether the 200/503 assertions can pass at all.

**3.3 B-series boot-validation tests: combos are falsifiable in principle, unenumerated and contested in fact.**
- Pre-change, `server.issuer_allowlist` is an unknown key (`config/source.go` warns-and-ignores) and `config.validate()` rejects only the sentinel (`config_load.go:183-184`) — so B1 (issuer ∉ allowlist), B2 (non-URL entries), B3 (allowlist without explicit issuer) would each fail pre-change **if implemented in `config.validate()`**, and the natural home (`cmd/sso-server/issuer_test.go`, with `writeIssuerYAML`/`loadIssuerOnlyConfig` helpers, exists) is sound. ✓ in principle.
- **As committed they don't exist** — no names/files/assertions. The mapping's B-series is unfalsifiable-as-written (S0).
- **Placement conflict with the sibling configcmd spec**: that spec pins "No enforcement inside `config.Load`/`validate()`" and "the key is not read at boot", while the summary pins "true boot validation lives in `config.validate()`". The configcmd spec defers server-side enforcement to this server module, so it is a sequencing tension rather than a hard contradiction — but the B-series tests land on one side of it, and the committed mapping does not say which. (The CLI-layer equivalent — configcmd's 16 cases — *is* enumerated and falsifiable; it does not cover the server-boot layer.)
- **The SDK-side incoherent state has no test at all**: the summary's own refinement #2 (NewServer returns no error → runtime fail-closed + loud logging) leaves the non-empty-allowlist-without-issuer SDK state's runtime behavior (discovery 503? log-only?) unpinned and untested. The sibling's I1 (panic + `WithIssuerNamer`) is stale on both axes — no namer in the current design, and "fail-loud" is not a panic.

## 4. Consolidated verdict

| Acceptance / pinned behavior | Falsifiable test exists? | Verdict |
|---|---|---|
| Per-signer tenant_id/roles projection (C1–C3) | ✓ compile gates + C4/C5 fail on HEAD | PASS — but scrub (C4) unpinned in current deliverable |
| Mint→validate round trip (C5) + tenant-hint precedence (C6) | ✓ fail on HEAD | PASS |
| Byte-compat negative (unbound client) | ✓ green-today pin; **[]string{} leg vacuous** (stdlib omitempty) | PARTIAL |
| Byte-identity goldens | depends on **pre-change capture** — unpinned | GAP |
| Wire round trip (A1) | grant unpinned; sibling cc+roles leg **fails by design** | GAP |
| cc emits no roles / per-grant roles table | no named test asserts cc-absence; case 9 grant unpinned | GAP |
| Roles fresh per mint | no freshness test | GAP |
| T-1.2 issuer coherence (cases 3/11) | green on HEAD; pins configured state only | PIN, not acceptance |
| **"iss never Host-derived" (direction)** | **no satisfiable state under the design; extension fails by design** | **CRITICAL — design contradicts direction** |
| "Only allowlisted values emitted" (direction) | reduces to boot check + 503; violated in legacy state | CRITICAL |
| 200-with-config-pinned issuer (re-pointed untrusted-peer) | compile-gated; catches gate/trust ordering post-change | PASS as pin |
| 503 for non-allowlisted base | ✓ fails on HEAD (no 503 path in discovery today) | PASS — but "only" sweep + comparison semantics unpinned |
| Trusted-proxy re-pointing as a set | assertions self-contradictory in summary; legacy trio's fate unpinned | GAP |
| B-series boot validation (3 combos) | falsifiable in principle at `config.validate()`; **unenumerated**; placement contested | GAP |
| SDK-side fail-closed for incoherent options | no test | GAP |
| Cross-repo fixture contract (X1–X3) | out-of-tree; X1 roles-on-cc **unsatisfiable**; K1 absent + non-compiling as specified | CRITICAL |
| Introspection echo/no-echo | unpinned; case 8 asserts the opposite of the only pinned (sibling) behavior | GAP |

**Tests asserting behavior the design does not pin down (or pins the opposite of):** entitiescmd case 8 (introspection echo vs sibling no-echo pin); sibling R1's cc-wire roles presence (vs cc-emits-none); sibling I1 panic/namer (no namer, no error return); sibling M1 mint-500 (current design pins 503 only for non-allowlisted base); sibling I2/T1–T3 sentinel-when-unset (vs legacy-retained); sibling K1 `Client.Roles` (rejected by design); the per-signer ID-token-absence legs and the reserved-key scrub, if inherited without the current deliverable pinning them.

**Highest-priority fixes:** (1) commit the actual design document (S0) — the mapping is not auditable as shipped; (2) resolve the direction conflict: either drop the legacy Host fallback (sibling sentinel approach) or explicitly amend the "never Host-derived" acceptance — as committed the mandated `oidc_discovery_test.go:80` extension cannot pass; (3) re-pin X1/K1 to the current roles source (permissions provider, cc-emits-none) or remove the cross-repo contract from A2; (4) enumerate the six allowlist tests and the B1–B3 tests with files and assertion predicates, and state which of the three trusted-proxy tests keeps the legacy assertions.
