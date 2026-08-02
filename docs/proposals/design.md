Design doc written to `docs/auto/domains-tokenexchange-direction1-design.md`. All claims verified against source before inclusion (deny-set keyed by token string in all 3 issuers, zero `GetDescendants` production callers, zero `RevokeSession`/`RevokeAllForHuman` production callers, file-budget headroom measured with `wc -l`).

## Key decisions (each a `##` heading in the doc)

**Decision 1 — `ChainRevoker` extension interface.** Optional SPI (`RevokeDescendants` + `HopsBySession`) so the `ChainStore` read contract and every test fake stay untouched. Pinned two spec deviations: `expire` receives the whole `ChainHop` (the deny TTL must come from somewhere), and walk truncation at `maxChainWalk` becomes `ErrChainWalkTruncated` — `GetDescendants` today silently stops at 1000 visited nodes and returns success, which as a cascade would be silent partial revocation.

**Decision 2 — the keystone: a jti-keyed revocation deny set.** The existing RFC 9068 deny-set is keyed by full token string; `ChainHop` records only jti, and no jti→token index exists. So improvement 1 requires a *new* validation seam: per-issuer `jtiRevoked` maps consulted by `Validate`, a durable `JTIRevocationStore` sibling, and an `expire` closure built once at the `interfaces/sso` layer. Explicitly rejected `security.JTIReplayStore` as the deny primitive (fail-open error direction + semantic conflation).

**Decision 3 — storage model.** `ChainHop` gains `SessionID` + `ExpiresAt` (unix seconds), sqlite migration v2 with a session index; `ExpiresAt == 0` aborts the cascade (`ErrHopMissingExpiry`) — a hop with no TTL can never be silently denied-for-zero.

**Decision 4–5 — admin surface + `/token/revoke`.** Two new routes (descendants GET `admin:read`, revoke POST `admin:write`; handlers must live in `token_portfolio.go` — `interfaces/admin` is at its 10-file ceiling and `lifecycle.go` at 481/500). The admin revoke kills the root *via the jti deny set* — the admin holds only a jti, so the per-token path is unreachable from it (a gap the spec didn't address). `/token/revoke` uses the `RefreshTokenInspector`-style optional-capability type-assert; cascade runs only when the root was actually revoked, after the 200 is decided — oracle-safe by construction.

**Decision 6 — agent delegation.** Flagged the spec's "subject = human, actor = agent" as **backwards** relative to `ChainHop` semantics (minted token has `sub=agent`, `act=human`) — following the spec would mislabel every agent token in the admin UI. Session cascade kills each minted token *and* its whole derived subtree, fail-closed reporting, session revocation applies regardless.

**Decision 8 — cross-replica parity.** New `KindTokenRevokedJTI` bus event + `SeedJTIRevocations` re-seed; without it a jti denial dies on restart/late-join, weaker than the token deny-set it parallels.

**Decision 10 — breakage risks.** 12 ranked risks; top ones: incomplete validation seam (silent "revoked" lie), missing `ExpiresAt` (deny pruned immediately), spec's subject/actor inversion, `maxChainWalk` truncation, and the file-budget collisions (compile-enforced).
