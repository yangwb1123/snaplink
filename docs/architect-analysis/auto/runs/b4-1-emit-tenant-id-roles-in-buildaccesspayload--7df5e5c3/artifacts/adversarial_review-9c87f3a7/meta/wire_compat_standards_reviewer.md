The deliverable is complete and internally consistent. Here's a summary of the resolution:

## Deliverable

`docs/architect-analysis/auto/runs/b4-1-emit-tenant-id-roles-in-buildaccesspayload--7df5e5c3/artifacts/design-a77de8a6/task-1b-sentinel-semantics-resolution.md` — an amendment to `task-1-design.md` that resolves all eleven design-gate findings (F-1…F-6, S1…S5). Every anchor was re-verified against the tree at HEAD before pinning.

## Decisions

**D1 — Sentinel shape: URL-shaped.** `sso.DefaultIssuer` becomes `https://snaplink.invalid/sso` (RFC 2606 `.invalid` — guaranteed never to resolve, so no legitimate Host can equal it). This is the only shape that satisfies T-2 *and* "don't break standard discovery consumers" simultaneously: discovery truthing makes the SDK-default `issuer` a §4.3-valid https URL, and congruence forces minted iss == discovery == RFC 9207 == RFC 9701 to share the value. Verified zero delta for cmd production (signer wired with `server.issuer` at `serverbuildsign:43`) and SDK `WithIssuer`; the blast radius of the constant change is test fixtures and config comments only.

**D2 — Exclusion classes: all five excluded** via a new `resolveIssuerLegacy` (= today's resolver; configured issuer, else base URL) + `ResolveIssuerLegacy` accessor + 7 Deps interface lines, re-pointing 27 call sites (zero-line swaps). Justifications, per class: private_key_jwt and JAR `aud` are *target claims* (RFC 7523/9101), not stamped identities — flipping breaks every existing SDK-default client with `401 invalid_client`/`400 invalid_request_object`; bearer realms are presentation-only protection-space names; RFC 8414 `authorization_servers` and the whole SSF config document (iss + JWKSURI + ConfigurationEndpoint) are *locators* that receivers must fetch — the sentinel is unresolvable by construction, and splitting SSF issuer/JWKSURI would be internally inconsistent for strict receivers. **RFC 9701 introspection-JWT `iss` is NOT excluded** — it's an issuer-identity claim, so it flips with the sentinel (fixing today's SDK-default divergence). Exclusion set is closed at A–E.

**D3 — Allowlist/mint gate pinned:** empty = no gate, byte-identical; non-empty = name gate inside `issuerForClient` (verified single funnel — JWT/SAML2 bearer grants call the same accessor); refusal reuses the existing **500 `ErrNoTokenStrategy`** shape (no new Err\*); construction panic requires the effective issuer ∈ allowlist (making congruence enforceable); `IssuerNamer` is an optional resolution override, never a bypass; ID-token mint path out of scope.

**Congruence matrix (§4)** verifies minted == discovery == RFC 9207 in every state: cmd, WithIssuer, SDK default (the fix), allowlist-only `{sentinel}`, and unreachable `{X≠sentinel}`-without-WithIssuer.

**Carve-out pins (§5):** byte-identity-when-empty holds in-tree (struct-end `omitempty` fields, zero in-tree writers of reserved keys — verified); carve-out = out-of-tree `Claims`/`req.Claims` reserved-key dedupe, extended to **both** access and ID tokens via shared `scrubReservedExt` (closes security finding S2; per-signer tests assert absence inside `ext`). S1 (DCR `Roles` exclusion) and S5 (`serving_region` echo asymmetry) pinned with tests.

Plus: F-4 trusted-proxy re-pointing with endpoint-field legs, F-5 six migration steps with verified per-file line budgets (sso.go lands at exactly 500; `options.go`/`options_security.go` untouched at zero headroom), F-6 doc sweep, and a fully named test inventory (3 signer units + 2 rootcov wire tests + 4 construction/discovery/config tests + S1/S5/golden pins) with real file targets — resolving the falsifiability rejection. No `.go` files were touched, so the build gates are unaffected.
