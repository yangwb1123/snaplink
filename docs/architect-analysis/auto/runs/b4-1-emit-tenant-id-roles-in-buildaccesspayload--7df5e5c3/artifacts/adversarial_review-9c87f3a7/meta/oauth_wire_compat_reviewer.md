# Wire-compatibility verification — B4-1 sentinel resolveIssuer / discovery truthing / claims workstream

All claims below were re-verified against the tree at `c676f974` (plus the run artifacts). Verdict per requested item, with evidence pins and gaps.

## 1. RFC 9068/9207 issuer semantics under sentinel resolveIssuer + discovery truthing

**Mechanics verified.** `resolveIssuer` (interfaces/sso/server_discovery.go:251-258) today returns `s.issuer` only when set-and-non-sentinel, else `requestBaseURL` (server_federation.go:40 → middleware.BaseURL). Discovery seeds `Issuer: base` in `buildBaseMetadata` (server_discovery_config.go:144) with the sole override in `applyMFAIssuerSigning` (:264-265, conditional `s.issuer != "" && != DefaultIssuer`). The sentinel is `sso.DefaultIssuer = "snaplink-sso"` (shared/core/consts_oauth.go:139, seeded at sso.go:67).

**Per-state wire delta table** (design change in **bold**):

| State | minted `iss` | discovery `issuer` | resolveIssuer (RFC 9207 stamps, etc.) |
|---|---|---|---|
| cmd production (WithIssuer="sso-server"/URL) | X | X | X — **zero delta** |
| SDK `WithIssuer` set | X | X | X — **zero delta** |
| SDK default (unset) | "snaplink-sso" (unchanged) | base URL → **"snaplink-sso"** | base URL → **"snaplink-sso"** |
| SDK allowlist-only, no WithIssuer | **unspecified** (see F-5) | **sentinel** | **sentinel** |

The summary's "minted == discovery == RFC 9207 iss already holds in production" is **confirmed** for cmd: `config_load.go:60` `DefaultServerIssuer="sso-server"`, `:71` default, `:184` rejects `server.issuer == sso.DefaultIssuer`; the JWT issuer is built with the same name (cmd/sso-server/serverbuildsign/build_signing_issuers.go:43), so all three surfaces agree today. The config loader's own comment (:175-190) documents the SDK-default divergence the design fixes. **Correct claim, but note the "already holds" is production-only** — SDK-default currently mints "snaplink-sso" while discovery advertises the base URL; the design closes exactly that.

## 2. Impact on existing token consumers

Minted-token `iss` itself is **unchanged in every state** (signer name == sentinel/configured in all in-tree wiring; verified: harness at trusted_proxy_gate_test.go:53 uses no `WithEd25519Issuer`, testkit wires both names at testkit.go:128/136, quickstart pins `sso.DefaultIssuer` at main.go:200). What changes in SDK-default state:

- **RFC 9207 stamping surface** (16 sites — authzErrorBody root at server_discovery.go:268, form_post :343, finish_login :191/456/461/469, login_gates :178, logout :259, mfa :139, native SSO, oauth :447/460, origin_validation :163/176, FCL :450, silent renewal via `d.ResolveIssuer`): base URL → sentinel. **Consumers performing mix-up checks against discovery** get a consistent value (improvement).
- **URL-concatenating consumers — the real hazard:** `server_resource.go:182` (RFC 8414 protected-resource metadata `authorization_servers`) and `protocols/caep/receiver.go:258-264` (SSF `iss`, `JWKSURI = iss + "/.well-known/jwks.json"`, `ConfigurationEndpoint`) build URLs from the resolved issuer. With the sentinel ("snaplink-sso", not a URL), authServers becomes a non-URL identifier and SSF JWKSURI a broken URL. The sibling run's R4 spec explicitly excluded these classes from strict resolution for exactly this reason; the target design's summary shows **no exclusion carve-out**.
- **`private_key_jwt` validation (class A):** handle_par.go:170, handle_ciba.go:195, handle_introspect.go:213, handle_revoke.go:132 validate RFC 7523 client assertions against `ResolveIssuer`. Under a blanket sentinel, existing SDK-default clients asserting `iss` = base URL get `401 invalid_client` — an oracle-safe but breaking migration. The sibling design kept this class legacy; the target summary is silent.
- **RFC 9701 introspection JWT `iss`** (handle_introspect.go:184) and **bearer-challenge realms** (mesh_authz.go:179/217/253, server_me.go:43/49, userinfo, DCR, revoke — ~12 sites) also flip. Challenges are cosmetic; the RFC 9701 `iss` is validated by RSs.
- **Discovery consumers:** sentinel truthing makes SDK-default discovery `issuer` a non-URL string. RP libraries enforcing OIDC Discovery §4.3 URL-ness (many do) will refuse the doc — cmd already ships this shape ("sso-server"), so it's not a new class, but it extends it to every SDK embedder. A URL-shaped sentinel (e.g., a fixed `https://…` sentinel) would satisfy T-2 ("never equal Host") without breaking standard consumers; the design should pin this explicitly.
- **Intra-repo consumers that benefit:** quickstart's remote pin (`remote.WithIssuer(sso.DefaultIssuer)`, main.go:196-200, which today must *not* match discovery) becomes discovery-consistent — but the comment there becomes stale and needs the design's doc sweep.

## 3. The three trusted_proxy_gate_test.go assertions

**Verified and correct as claimed:** the three tests sit at :267, :283, :299 (span 265-313), asserting `issuer == srv.URL` (untrusted peer ignores XFH), `issuer == "https://public.example.com"` (unset knob, legacy first-hop), `issuer == "https://public.example.com"` (trusted edge). All three become wrong under truthing (issuer is constant = sentinel in every trust state) and **must be re-pointed** to `sso.DefaultIssuer`. Re-pointing caveat: once `issuer` is constant, these tests lose their trusted-proxy coverage — the re-pointed versions should additionally assert the trust-gating on base-derived endpoint fields (`authorization_endpoint`, `token_endpoint`) so the gate keeps a discovery regression leg. `TestDiscovery_IssuerComesFromWithIssuer` (test/oidc_discovery_test.go:80, harness wires `WithIssuer(discoIssuer)`) is **unaffected** by truthing.

## 4. Per-signer ID-token absence pinning

**Structurally verifiable and feasible.** All three signers share `ed25519IDPayload` (ed25519_types.go:138) — no `tenant_id`/`roles` fields — and `IssueIDToken` (ed25519_issue.go:88, ecdsa_issue.go:60, rsa_issue.go:59) projects only `req.*` + `Extra: req.Claims`. A `buildAccessPayload` change cannot leak into ID tokens by construction; the 3 per-signer unit tests pin that. Test homes exist (ed25519_rfc9068_test.go:69, ecdsa_jwt_issuer_test.go:60, rsa_jwt_issuer_test.go:20). **Caveat:** ID tokens still pass `req.Claims` into `ext` — the pin covers the structured claims only; an embedder putting `tenant_id` in Claims still leaks it via `ext` (unchanged today, out of the pin's scope — should be stated).

## 5. Byte-identity-when-empty constraint

**Mechanism verified:** `ed25519Payload` marshals in struct-declaration order with `omitempty`; appending `TenantID string json:"tenant_id,omitempty"` + `Roles []string json:"roles,omitempty"` at the struct end leaves the empty case byte-identical (same argument the sibling's §5 pins). No in-tree mint path writes `KeyTenantID` into `Subject.Claims` (verified: zero writers), so the ext-scrub's interaction is wire-neutral in-tree. **Two carve-outs the constraint must state:** (a) out-of-tree embedders whose `Claims` contained reserved keys lose them from `ext` (deliberate dedupe, but a wire delta the "byte-identity" name doesn't cover); (b) introspection — verified no-echo boundary: RFC 7662 bodies are hand-enumerated in `populateAccessIntrospectionBody` (protocols/oauth/introspect_body.go, no `Extra` echo) and RFC 9701 signs that same map, so `tenant_id`/`roles` cannot auto-echo. Note the sibling design planned to *add* roles echoing (A-new-4); the target design's no-echo stance is self-consistent but opposite — pin it so implementers don't reconcile the two.

## 6. Ordering/rollback of the 6 migration steps — NOT verifiable

**The deliverable artifact (task-1-design.md, 15 lines) does not enumerate the 6 steps** — only the summary names them ("exact per-file line-budget checkpoint (sso.go lands at exactly 500)"). Ordering/rollback of unspecified steps cannot be verified. What the tree does verify about the checkpoint: sso.go is 499 lines today (500 limit, `maxFileLines` at maintainability_budget_test.go:34, `n > 500` fails) — "+1 line" is arithmetically consistent only if the post-options validation is a single call line with the helper elsewhere. **Budget reality check:** `options_security.go` is at exactly 500/500 (**zero headroom** — `WithIssuerAllowlist` cannot go there); `options.go` 490, `server_discovery.go` 483, `server_discovery_config.go` 487, `accessors.go` 494, `config_load.go` 495 (a `server.issuer_allowlist` key + load-time error needs ~5+ lines in an already-tight file — the existing sentinel-rejection block at :184 is the natural home, but headroom is minimal). Only sso.go's landing point is stated; the other five files' allocations are absent.

Required ordering properties the design must satisfy (from the tree): (1) capture pre-change byte-identity goldens **first** — no golden test exists in defaultimpl today, but `fixedClock` (ed25519_jwt_issuer_test.go:171-176) makes it deterministic; (2) claims workstream (additive, empty-case byte-identical) before issuer workstream (behavioral) so each stage's `make ci` is green independently; (3) rollback independence: the two workstreams touch disjoint surfaces (payload struct + mint sites vs resolveIssuer/discovery/config), so revert order is free — but each revert must restore golden bytes, which requires the goldens to predate both. Steps (4-6) are unverifiable by absence.

## Findings requiring resolution before implementation

- **F-1 (blocking):** allowlist enforcement point is underspecified. With "never Host", the allowlist has no Host to compare against. T-2's "only allowlisted iss accepted" forces the reading "allowlist gates the mint (IssuerNamer), empty allowlist = sentinel allowed", but then the mint-gate's wire surface when it trips is unpinned ("no new Err*" + fail-closed = which existing status/body?). Pin: what /token returns when the mint gate refuses.
- **F-2 (blocking):** no exclusion classes stated. The sibling design's four exclusions (private_key_jwt, JAR, bearer challenges, authServers/SSF) exist to avoid new oracles and broken bootstrap; the target design's sweeping sentinel hits all of them. Adopt the exclusions or justify each flip.
- **F-3:** sentinel non-URL-ness vs standard discovery consumers (see §2).
- **F-4:** re-pointed trusted-proxy tests must keep gate coverage via endpoint fields (§3).
- **F-5:** the 6 migration steps + per-file allocations must be enumerated (only sso.go's 500 checkpoint is given; options_security.go's zero headroom makes placement decisive).
- **F-6:** doc-sweep must include quickstart main.go:196-200 (its "mismatch" comment becomes false) alongside the already-listed oauth_token_source.go:43-46 / types_token.go comments.

**Net:** every factual claim in the deliverable that is checkable against the tree checks out (9/9 evidence items, the three test lines, budgets, mint/discovery/RFC 9207 congruence in production, ID-token structural absence, no-echo introspection). The issuer workstream's *semantics* are wire-compatible for cmd production and in-tree SDK wiring, but the deliverable as written (summary-only) leaves three load-bearing decisions unpinned — the allowlist/mint-gate interaction, the exclusion classes, and the migration-step enumeration — without which the sentinel's impact on RFC 8414 metadata, SSF configuration, and private_key_jwt consumers cannot be certified.
