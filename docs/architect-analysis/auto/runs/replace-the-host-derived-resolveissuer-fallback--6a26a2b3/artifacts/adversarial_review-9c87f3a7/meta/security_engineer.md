Audit complete. Full report at `docs/architect-analysis/auto/runs/replace-the-host-derived-resolveissuer-fallback--6a26a2b3/artifacts/adversarial_review-9c87f3a7/meta/security_reviewer.md`. Summary:

## Verdict: design's security core is sound; one blocking scope gap

**1. resolveIssuer pin coverage — CONFIRMED.** `resolveIssuer` (server_discovery.go:251-256) is a single choke point; all 20+ consumers route through it: RFC 9207 authz-error bodies, form-post, JARM success+error, JAR `aud` binding (server_jar.go:247), bearer challenges (mesh/me/userinfo/step-up), private_key_jwt + workload-identity `aud`, RFC 9701 introspection JWT, silent renewal, FCL iframes, RFC 9728 `authorization_servers`, federation `iss`/`sub`. One early return pins every row — no per-site miss possible.

**2. Discovery issuer AND endpoints — mechanism is right, but F1 (BLOCKING):** the pin must land in the shared `buildOIDCConfiguration` projection. The federation entity config consumes the *same* projection via `deps.RequestBaseURL` (domains/federation/handler.go:83 → BuildOPMetadata), is wired in the stock build, and its body cache is keyed by the **pinned** `iss` (handler.go:91-96) — so with allowlist on it serves a pinned `iss` with Host-derived `openid_provider` endpoints, and a spoofed-Host first render poisons the shared cached entity config for the TTL. The design summary never mentions this surface.

**3. Host/XFH unreachable — CONFIRMED** on every issuer surface; enumerated the 5 request-derived surfaces that must stay request-derived (DPoP `htu` per RFC 9449, device `verification_uri`, RFC 9728 resource/JWKSURI, resource_metadata advertisement, bundle-cache key) so the implementer doesn't over-pin.

**4. No downgrade path — CONFIRMED** with two spec requirements: nil vs empty-`[]` allowlist must be distinguished (empty ⇒ fail closed), and the NewServer gate must run after the options loop. Feature off is byte-identical legacy by construction; sentinel-rejection message is asserted verbatim by two tests and must survive the relocation.

**5. Bypass probes — all fail-closed.** Trailing-slash (one-slash trim) can't resurrect the fallback: the pin is an early return of the configured issuer; normalization only selects which operator string is pinned. Ports compare literally (`:443` ≠ none). Multi-host has no per-request selector by construction. Scheme/host case, userinfo, whitespace variants all fail exact match.

**6. FM-1..FM-11 — validated**, incl. FM-9 (core.TokenIssuer has no issuer accessor, spi.go:245-249 — the "no-SPI minting contract" limitation is accurate) and FM-10 (base_url is dead at boot; offline gate only).

**Non-blocking findings:** F2 — the placement rationale is factually wrong (`cacheState` is in sso_protocol.go:360 at 500/500, not server_discovery_cache.go; a new embedded struct is required or the line gate breaks); F3 — artifact says 21 GWT cases but buckets sum to 24; F4 — five spec details to pin (URL-shape validation for FM-2, nil/empty semantics, gate placement, residual list, message preservation); F5 — 5 deploy configs already carry coherent `issuer_allowlist` keys (worktree), 3 still on `issuer: sso-server` — no boot break either way, but kustomize base pins endpoints to the cluster-internal DNS URL.
