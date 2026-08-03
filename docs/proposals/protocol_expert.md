Review complete. Deliverable: `docs/auto/infrastructure-redis-direction1-protocol-review.md` (doc-only change; no Go files touched, so the mandatory gates don't apply).

## What I did

Read `ai-dev/prompts/README.md`, the spec and design docs, then independently re-verified every protocol-relevant claim against source and the **pinned vendored dependencies** (go-redis v9.20.0, miniredis v2.38.0 in the module cache), not just the worktree.

## Standards actually in scope

The design touches zero HTTP surfaces, so I reviewed the protocol contracts whose semantics the bus carries: RFC 7009 §2.1/§2.2/§2.2.1 (revocation), RFC 9068 (access-token deny-set), RFC 7519 §4.1.4 (`exp`), RFC 7517/OIDC JWKS rotation, RFC 8414/OIDC Discovery freshness, and the CAEP/SSF boundary. Compliance matrix shows the design **preserves** every wire contract it touches (200-always revoke, oracle-safety, client auth, no-store headers, discovery derivation) — verified against `handle_revoke.go`, `cross_replica.go`, `revocation_set.go`, `server_discovery_cache.go`.

## Key findings (protocol side)

- **P-1 Critical** — G-2 ("loss = closed channel") is not delivered by `PubSub.Channel()` on go-redis v9.20.0: `initMsgChan` closes only on `pool.ErrClosed` and retries forever (`pubsub.go:731-737`); ping failure → `reconnect`, never closure (`pubsub.go:709-717`); no read deadline with timeout 0 (`internal/pool/conn.go` `noDeadline`). A blind replica would validate revoked RFC 9068 tokens until `exp` with `/readyz` green. Fix: bus-owned `ReceiveTimeout` loop + `ps.Close()` unblock + `defer ps.Close()`.
- **P-2 High** — the `KindTokenRevoked` re-seed source is sqlite/memory only (`build_signing.go:84-107`); the direction's "one Redis" story silently degrades to a no-op re-seed unless `keys.signing.revocation_backend: sqlite` is stated as a requirement.
- **P-3 High** — F-1's "TTL fallback" wording is wrong for `KindTokenRevoked` (deny-set is exp-bounded, no TTL); collision impact is the token's full remaining validity. Requires the build-layer ID-equality test.
- **P-4 Medium** — the channel now carries full bearer credentials; Redis ACL/network-isolation requirements must be documented as operational MUSTs.
- **P-6** — corrected a factual error in the design's loss taxonomy (go-redis heartbeat reconnects, never closes).

Corroborated the database review's Critical/High and the QA lead's H1/H2/M1/M4 with my own vendored-source line citations.
