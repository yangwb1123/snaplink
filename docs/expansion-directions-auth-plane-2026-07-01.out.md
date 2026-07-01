This is a thorough and well-structured analysis. The five directions are well-grounded in the existing architecture — each one identifies gaps in what's already built rather than suggesting something from scratch.

A few observations from reading this against the codebase:

**On Direction 1 (Adaptive Auth):** The key constraint is the 50ms synchronous evaluation window mentioned. The `anomaly.Detector` SPI already has the event structure (`LoginEvent` with geo, device, fingerprint fields), and `LoginContext` in `domains/anomaly/types.go` even has a `RiskPolicyDecision` field that's currently unused. The policy engine SPI would essentially bridge the gap between the existing parallel tracks — but the DSL for composing rules (weighted signals, thresholds, allowlists) would be the novel design challenge.

**On Direction 2 (Token Exchange):** I notice the `act` chain implementation uses recursive `*ActorClaim` pointers. A circulation detector is actually simpler than it sounds — a pointer-identity or `sub`+`client_id` cycle check during `prependAct` would catch self-loops immediately. The scope narrowing change is the more impactful one: currently `ExchangedTokenInfo` copies scopes verbatim from the subject token. Making `intersect(client_allowed_scopes, subject_scopes)` the default and requiring explicit opt-in for expansion would be a small code change with significant security impact.

**On Direction 5 (Introspection):** The `SignedIntrospectionResponse` idea is interesting — it decouples cache authority from the RS. Currently the `IntrospectionCache` SPI is best-effort and per-server. A signed response allows RS-side caching without trusting the RS's cache. The batch endpoint would also reduce connection overhead significantly for Envoy sidecar deployments.

What would you like to do with this? I can:
- **Dive deeper** into any direction with code-level analysis
- **Start implementing** one of the recommended starting points (2 or 5)
- **Run the maintainability gates** to identify which files are near budget before we touch them
- **Cross-reference** against existing SPIs to map the exact integration points
