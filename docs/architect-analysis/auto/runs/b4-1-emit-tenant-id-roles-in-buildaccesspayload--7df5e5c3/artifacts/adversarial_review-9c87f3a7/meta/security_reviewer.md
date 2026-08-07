Audit complete. Report written to `docs/architect-analysis/auto/runs/b4-1-emit-tenant-id-roles-in-buildaccesspayload--7df5e5c3/artifacts/adversarial_review-9c87f3a7/meta/security_reviewer.md`. All five areas verified by reading the pre-change tree (HEAD `c676f974`); the design is the only delta.

## Findings

**1. Client.Roles → Subject.Roles (client_credentials/refresh) — no escalation *if* one pin holds**
- No `Roles` field exists on `core.Client`/`core.Subject` today (verified). The source is operator-registered `Client.Roles`; the mint sites (`token_client_credentials.go:40-53`, `token_refresh.go:273`) can't self-assign.
- **Blocking pin (S1):** DCR is the escalation surface. `buildRegisteredClient`/`buildUpdatedClient` (`handle_register_helpers.go:170,287`) enumerate fields and `updated := *client` copies — safe only if `Roles` is never added to `DCRRequest`. Adding it would make anonymous `/register` self-assign roles. Needs an explicit exclusion + wire test.
- Refresh mints client roles onto a **user** sub — conflation, not escalation (the client already owns those roles on its own token), but requires the documented "roles = acting-client roles, keyed by client_id" semantics. Roles appear *only* on cc+refresh tokens — silent renewal and exchange mints lack it; document to prevent a "widening fix."

**2. Reserved-key ext scrub — sound, one gap**
- Load-bearing against three real injection paths: auth-hook pre-mint merge (`accessors_threat.go:371`), exchange re-emission of subject-token ext (`token_exchange.go:294`, incl. SPIFFE SVID attributes at `token_exchange_stages.go:121`), and provider attributes.
- Wire-compatible: no mint site emits `ext.tenant_id`/`ext.roles` today (grep-verified).
- **Blocking gap (S2):** the ID-token path (`ed25519IDPayload.Extra = req.Claims`, `ed25519_issue.go:91`/`ecdsa_issue.go:67`/`rsa_issue.go:58`) is not covered by a `buildAccessPayload` scrub — a provider attribute named `roles` still leaks via ID-token `ext`. Pin a shared `scrubReservedExt` on both paths; per-signer tests must assert absence inside `ext`, not just top-level.

**3. tenantHintFromClaims precedence — correct, tightens trust**
- Today it trusts provider-asserted `Extra["tenant_id"]` for the admin write-quota bucket (`governance.go:478`, `middleware.go:345`). Structured-wins-over-ext is fail-safe (client binding over untrusted attributes), the fallback is genuinely needed for pre-change tokens, and the round-trip is single-point via `claimsFromPayload`. Advisory budget key only — no oracle.

**4. Introspection no-echo boundary — holds, needs the asymmetry doc pin (S5)**
- `populateAccessIntrospectionBody` is enumerated; `Extra` never echoed. Echoing `roles` would be a privilege oracle (RFC 7662 §2.1 lets any active client introspect); `tenant_id` echo would leak tenant affinity. Both JSON and RFC 9701 forms share the boundary. Must document that `serving_region` *is* echoed while these aren't, or a maintainer will "fix" it.

**5. Fail-closed mint — sound once the state matrix is explicit (S3/S4)**
- Verified: `s.issuer` seeds to the sentinel (`sso.go:67`), `resolveIssuer` Host-falls back (`server_discovery.go:251-258`, attacker-influenced under legacy first-hop trust), minted `iss` is the JWT issuer's *separate* internal string — so the IssuerNamer gate is genuinely needed. `issuerForClient` is the single funnel; every caller already maps failure to one `ErrNoTokenStrategy` 500 shape (oracle-safe, no new Err\*).
- Required matrix: **empty allowlist = no gate** (byte-identical legacy; fail-closed here would break every deployment); **non-empty + IssuerNamer absent = 500 at mint** (plus construction panic and config-load error so the state is unreachable); non-empty + namer = allowlist check at mint. ID-token mint path must be explicitly out of scope.
- **Ambiguity (S3):** "sentinel (never Host)" vs "empty mode byte-identical legacy" conflict; the re-pointed `trusted_proxy_gate_test.go:265-311` implies the sentinel-in-all-modes reading — the re-pointed tests must move their forwarded-host assertions onto endpoint fields (still base-derived) so trust-proxy coverage survives.

**Verdict:** no credential oracle in any area; escalation vectors are closed by design *provided* S1 (DCR exclusion) and S2 (ID-token ext scrub) are pinned with tests, and S3/S4 are stated explicitly. cmd's `DefaultServerIssuer` (non-sentinel, sentinel rejected at load) already yields minted == discovery == RFC 9207 in production, confirming the design's base-line claim.
