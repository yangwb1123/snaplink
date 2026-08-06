Design complete. Summary of the work:

## Evidence verification (all claims checked against the tree)

**Confirmed (9/9 cited items):** `buildAccessPayload` emits no tenant_id/roles; `ed25519Payload` lacks both (kid at header :12); client_credentials mints `Subject.TenantID`; `Subject.TenantID` is self-documented "NOT a token claim"; `resolveIssuer` Host-falls back via `requestBaseURL`; `TestDiscovery_IssuerComesFromWithIssuer` at :80; billing README:170 documents the missing claim; `token_exchange.go:446` `guest.Roles` is entitlement narrowing only; no `Client.Roles`/`Subject.Roles` exist (roles owner is genuinely undecided in code).

**Two imprecisions (non-blocking):** "spi.go:171 alias" is `SessionMeta.TenantID`, not a Subject alias (the real alias is `aliases.go:132`); the discovery `Issuer: base` seed lives in `buildBaseMetadata` (server_discovery_config.go:144) with only `applyMFAIssuerSigning` overriding.

**Load-bearing facts the evidence omitted:** the committed file-size gate (`n > 500` fails, zero exemptions) leaves several target files at 490–500 lines — forcing placement decisions; `test/trusted_proxy_gate_test.go:265-311` asserts discovery issuer == base URL in 3 states (must be re-pointed); cmd always wires a non-sentinel issuer (`DefaultServerIssuer`, sentinel rejected at config load), so minted == discovery == RFC 9207 iss already holds in production.

## Design (delivered to `artifacts/design-a77de8a6/task-1-design.md`)

- **Claims workstream:** `Client.Roles` → `Subject.Roles` at the client_credentials + refresh mint sites (pinned owner), first-class `tenant_id`/`roles` in `ed25519Payload` via `buildAccessPayload` with reserved-key ext scrub, round-trip through `claimsFromPayload`, `tenantHintFromClaims` structured-claim precedence with pre-change ext fallback.
- **Issuer workstream:** `WithIssuerAllowlist` + post-options `NewServer` validation (remediation-naming panic, order-independent), `server.issuer_allowlist` config with load-time error, `resolveIssuer` sentinel (never Host), discovery `Issuer` truthing, fail-closed mint gate via a new optional `IssuerNamer` extension — no new Err\*, endpoints, or interfaces/sso files (60-file ceiling).
- **Compatibility, failure modes, migration, acceptance mapping:** 10 constraints (byte-identity when empty, ID-token absence pinned per signer, introspection no-echo boundary), 10 failure-mode rows, 6 migration steps with an exact per-file line-budget checkpoint (sso.go lands at exactly 500), and T-8(a)/T-2/T-1.2 mapped to concrete named tests — 3 signer unit tests + 2 rootcov wire tests, 4 falsifiable construction/discovery/config tests, and the testkit tenant-binding option with the 422 gate explicitly cross-repo.
