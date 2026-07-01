Saved as `docs/expansion-directions-auth-plane-2026-07-01.md`. This document is distinct from the existing `analysis-expansion-directions.md` (Chinese, infrastructure-centric) — it targets the **auth-plane architecture** layer.

### Key Observations vs. Existing Analysis

| Dimension | Existing (Chinese) | Your New (English) |
|---|---|---|
| Focus | Infrastructure/enterprise integration | Auth-plane architecture & RS optimization |
| Primary audience | Ops / IT admins | Platform architects / security engineers |
| Foundational dependency | Job Queue needed before others | Token Exchange + Introspection are self-contained |
| Overlap on Adaptive Auth | Yes — but existing is a lighter sketch | Yours goes deeper on `DeviceFingerprint` SPI and policy engine specifics |
| Uniqueness | Webhooks + Notifications + ABAC | Token chain governance + Session hub + Introspection suite |

### Which to Pursue First?

Your recommendation to start with **Directions 2 & 5** is sound — they're contained, medium-effort, and hit production pain points directly. A few additional notes from my reading of the codebase:

**Direction 2 (Token Exchange Governance):** The `act` chain is currently in `protocols/oauth/token_exchange.go` as a linked list with `ActorClaim` recursion. The circulation detector can be implemented as a cheap hash-set walk (`O(depth)`) before the serialization step — the performance impact is negligible since `MaxActChainDepth=10`. The scope-minimization change is the riskiest part (semantic change to `scope` behavior) — I'd recommend a feature flag (`strict_token_exchange_scope: true`) for gradual rollout.

**Direction 5 (Introspection):** The batch endpoint needs careful RPS budgeting — even with oracle-safe responses, a `POST /token/introspect/batch` with 10K hashes is a memscan on the token store. A per-client rate-limit on batch size + a `max_batch_keys` config parameter would prevent abuse without hurting the caching use case.

Would you like me to dive into any specific direction with a more detailed implementation plan — SPI interfaces, package layout, integration points, and test strategy?
