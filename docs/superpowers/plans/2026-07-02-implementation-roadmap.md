# Implementation Roadmap (2026-07-02)

Synthesized from all requirement-bearing markdown under `docs/` (~130 analysis/expansion/review documents, 330 distinct proposals mined) cross-checked against the 2026-07-02 code-verified gap backlog (42 confirmed gaps: 24 missing, 18 partial; every item verified against the code with file-level evidence, 0 candidates refuted).

How to read this document:

- **Wave 1** is fully planned in [2026-07-02-wave1-quick-wins.md](2026-07-02-wave1-quick-wins.md) — nine S-effort, code-verified, independently shippable tasks.
- **Wave 2** items are code-verified gaps at M effort. Each is one plan-sized unit; write its plan when scheduled (the verified evidence is recorded in project memory and the wave notes below).
- **Wave 3** items are L effort and each REQUIRES its own design spec (brainstorm + spec before any plan).
- **Verification queue** items came only from docs and were NOT code-verified this round. Confirm against the code before promoting into a wave — historical precedent: most doc-only gap claims turn out already shipped.
- **Wave 4 / Dropped** records what was deliberately deferred or refuted so future analysis rounds do not re-litigate them.

---

## Wave 1 — Quick wins (S effort, code-verified, plan ready)

| # | Task | Value |
|---|------|-------|
| 1 | RFC 8414 `/.well-known/oauth-authorization-server` alias | Pure-OAuth/MCP client discovery 404s today; metadata doc already complete |
| 2 | Invitation revocation | Mis-sent invite = live 7-day credential with no kill switch |
| 3 | Webhook HMAC payload signing | Origin/integrity/replay protection for audit + MFA push webhooks; prerequisite for Wave-2 subscriptions |
| 4 | CAEP SET delivery retry | Transmitter one-shot send silently drops revocation signals; own receiver 500s to demand retry |
| 5 | TopTenants admin endpoint | Metering backend already computes it; pure surface wiring |
| 6 | SQLite backup ops | `/tmp` hardcode → configurable dir + response metadata + retention |
| 7 | sso-ctl import: postgres target | Migration cutover onto the HA Postgres identity backend without SQLite hop |
| 8 | Alert rules: audit drops + signing health | Metrics exist, nothing consumes them; silent compliance loss |
| 9 | config-reference.md postgres matrix | Shipped Postgres backend is undiscoverable in the config reference |

All nine are independent; any order works. Detailed TDD plan: [2026-07-02-wave1-quick-wins.md](2026-07-02-wave1-quick-wins.md).

## Wave 2 — High-value M-effort (ordered by operator/customer value)

1. **Admin list API pagination/filter/sort** — proto defines `page_token`/`page_size`/`filter`, every impl discards them; >10K-record deployments OOM the console. Dependency: add pagination signatures to store interfaces first; reuse the SCIM filter parser. (sources: ops-api-productization-2026-07-01, analysis-round14)
2. **MFA recovery codes + admin MFA unlock** — `core.RecoveryCodeStore` SPI + memory impl fully written, zero references; needs durable stores + `/auth/mfa` recovery method + self-service generate/regenerate + AdminUnlockMFA. Keep the `mfa_invalid` anti-enumeration collapse. (analysis-round10-sqlite-connections-mfa-recovery)
3. **Built-in SMTP/SMS senders + templates** — all five sender SPIs are no-ops in the shipped binary (`build_app_selfservice.go:109`); blocks every email-dependent flow for binary operators. Unblocks the signup-verification finish (verification queue). (analysis-round3, analysis-expansion-directions)
4. **Tenant quota enforcement** — `checkQuotaBeforeCreate` is dead code; wire client-create, user-create, token-issuance guard points + admin quota API. (expansion-analysis-beyond-30)
5. **Webhook subscriptions + event filtering** — single global URL receives the full firehose today. Depends on Wave-1 HMAC signing. Design the subscription model once: SIEM/Kafka sinks and lifecycle events all become producers on it. (expansion-v2-2026-07-01)
6. **SIEM export formats (CEF/OCSF/syslog)** — implement as `audit.Sink` formatters (~150 lines each); pairs with Kafka/NATS below. (analysis-round3)
7. **Bulk audit export + hash re-chain** — compliance evidence extraction; must preserve tamper-evident chain semantics across the export boundary (`Prune` doc itself names the missing tool).
8. **GDPR Art. 15 export: wire SubjectExporter** — exporter seam exists with zero impls; Eraser deletes data the Exporter cannot export. Cheapest compliance win. (expansion-analysis-20260701)
9. **SOC2 evidence pack** — packaged reports over existing audit/chain/rotation primitives; do after bulk audit export to reuse its path. (analysis-final-project-expansion-directions)
10. **Runtime apikey/keypair rotation API** — extend the signing-key rotation machinery (overlap windows, bus broadcast) rather than building a parallel system. (expansion-novel-five, ops-api-productization)
11. **Delegated org admin** — `TenantRoleAdmin` is stored but never consulted; add org-scoped roster/invitation surface. Watch cross-tenant leak invariants. (analysis-round10)
12. **Email-domain ownership verification** — DNS TXT challenge + verified/pending state; today `Upsert` silently steals domains (last-write-wins). Security prerequisite for Wave-3 connection-driven login. (ROADMAP)
13. **Connection health telemetry** — per-connection status/last-success/last-error + test-connection probe; feeds Wave-1 alert-rule pattern. (expansion-directions-v3)
14. **Tenant-scoped export** — tenant offboarding/migration extraction; schedule after delegated-org-admin scoping decisions. (analysis-round10)
15. **Trusted devices skip-MFA** — hashed privacy-preserving fingerprint + trust decay + portal review/revoke; design the device record so a later adaptive-risk engine can consume it. (expansion-v2)
16. **dpop_jkt authorization-code binding (RFC 9449 §10)** — closes the stolen-code window for DPoP clients; failures collapse to `invalid_grant` per oracle rules. (completeness-audit techlead)
17. **RFC 9701 signed introspection responses** — dedicated `use: introspection` JWK with independent rotation; AsymmetricJWSAlgs only; default off. (expansion-directions-auth-plane)
18. **Async-path OTel spans** — audit sink, CAEP delivery, cluster, migrate; ctx already carries the parent span. Do before debugging any eventing work above. (senior-architect-expansion)
19. **Kafka/NATS audit sink module** — nested infrastructure module implementing `audit.Sink`; schedule after SIEM formats so the wire format settles once. (analysis-round3)

## Wave 3 — Strategic L-effort (design spec REQUIRED before planning)

- **B2B connection-driven upstream login** — the flagship gap: consume the dead `Connection.Config`, per-tenant SAML/OIDC upstream instantiation at runtime. Spec must cover connection model, HRD interaction, secrets handling. Do Wave-2 email-domain verification first.
- **SCIM outbound provisioning** — cross-review upgrades to XL: requires a durable outbox/retry/DLQ pipeline (`cluster.Bus` is contractually best-effort). Design the outbox as shared infrastructure first (see verification queue: durable outbox).
- **Config hot-reload** — classify safe-to-reload keys; etcd watcher → ConfigDelta → ApplyDelta. Draw the boundary against config versioning/drift (verification queue) in the spec.
- **UI i18n** — `ui_locales` is plumbed end-to-end but nothing renders it. Carve out the login-SPA-only slice first (cross-review: half-day, high procurement visibility).
- **SSF stream management/metadata/poll delivery** — completes the SSF story beyond push CAEP; receiver stays FAIL-CLOSED.
- **Field encryption for TOTP secrets / refresh tokens at rest** — envelope encryption via existing JWE/KMS bridge + migration path for existing rows; coordinate with the Wave-2 rotation API.
- **Non-Go SDKs (TypeScript/Python)** — generate from openapi.yaml; start with a generated-Go-client CI step to prove the spec (293KB drift risk flagged).
- **Access certification** — Phase 0 must add batch aggregation SPIs (e.g. `ListAllFactors`); FacetQuerier cannot serve governance queries.
- **Four-eyes approval** — implement as AdminMiddleware pre-check hook so break-glass and future ABAC stack on the same seam without touching `permissions.Provider`.

## Wave 4 — Deferred by decision

- **Attestation-based client auth** — draft-stage spec, negligible adoption; revisit on FAPI/mobile customer demand.
- **OAuth hot stores Postgres backend** — Redis covers the HA hot path; full task breakdown exists (~1 dev-week) if an all-Postgres customer appears.
- **ToS acceptance tracking** — no current driver; can reuse consent infra later at no added cost.
- **Legal hold** — customer-specific requirements unknowable in advance.
- **OpenID4VCI/VP + SD-JWT VC** — eIDAS driver real but unnamed customer; large moving-spec surface; re-evaluate in 2 quarters.

## Verification queue (doc-sourced, NOT code-verified — confirm before scheduling)

Security-critical (verify first; each is small if real):
- **TOCTOU re-validation across login→MFA→consent→token** — claimed 1-line `rejectDeactivatedUser` in `resumeLoginAfterMFA`; highest marginal security value if the resume path is still unguarded.
- **SAML Bearer grant XML signature verification** — claimed bare `xml.Unmarshal` with no `ds:Signature` check (forgeable assertions). P0 if true, ~50 lines.
- **Client credential at-rest hardening** — claimed plaintext `Client.Secret` + non-constant-time compare; sqlite ClientStore claimed to drop JWKS/RAT/JWE/federation fields.
- **Introspection DPoP `token_type` bug** — claimed to return `Bearer` for DPoP-bound tokens (misleads RSes). 2-hour fix if real.
- **Panic recovery middleware default-on** — claimed no `recover()` in the stack.
- **Built-in trusted-proxy support (CIDR allowlist)** — all XFF consumers trust the first hop unconditionally per ROADMAP; verify current middleware.
- **Upstream HTTP timeout/circuit-breaker + LDAP pool** — caep/extauthz claimed to use default `http.Client` (hung authorizer hangs `/token`).
- **Security header/timing batch** — send-code no-store, SecurityHeaders default-on, SPA CSP + form_post nonce, KDF dummy-cost matching, federation SSRF connect-time recheck.

Product completions (verify residuals, then small):
- **OIDC conformance batch** — wire claimed-dead `ProjectIDTokenClaims` (discovery advertises `claims_parameter_supported=true`), AMR propagation, acr_values/max_age enforcement; then run the OIDF suite.
- **Finish signup email verification** — claimed `email_change` never sets `email_verified=true` (real bug if unfixed; merge as own PR first).
- **Password policy completion** — MaxAgeDays silently ignored (no `password_changed_at`); PasswordHistoryStore never wired.
- **Refresh-token absolute max lifetime + revoke-by-user/client + purge** (REF-01..03).
- **Consent grant TTL/expiry**; **concurrent session limits per user**; **RBAC static separation-of-duty**; **admin write idempotency + trace_id in error bodies** (`ErrorBodyWithTrace` claimed zero callers).
- **Passkeys as primary authentication** — WebAuthn stack complete; ~600-line `provider=passkey` wrapper proposed twice, never implemented.
- **JWT Bearer grant (RFC 7523)** — SAML Bearer exists, JWT equivalent does not; prerequisite for cloud workload-identity connectors.
- **Token-exchange governance** — scope-intersect default, act-chain cycle detection, may_act enforcement. Hard prerequisite: split `token_exchange_stages.go` (~520 lines) below the 500-line budget first.

Platform/infra (verify, then decide):
- **Durable outbox / async job queue** — three docs converge on it (SCIM outbound, webhook retries, revoke-all); design once before Wave-3 SCIM outbound.
- **Backend conformance suites + fail-open/fail-closed contract tests** — named the highest-ROI architectural investment; extend the `permissionstest.ConformanceSuite` pattern to all core SPIs.
- **Config JSON Schema + `validateServer()` conflict detection**; **runtime config versioning/change audit**; **admin SSE event stream**; **DoS/robustness hardening batch**; **doc-drift CI checkers** (measured 22x config-key documentation gap); **license CI gate + NOTICE.txt + SBOM**; **bulk import + lazy hash migration**; **per-tenant feature flags**; **threat model + fuzz suite**; **break-glass admin sessions**; **cross-protocol identity linking** (needs design); **adaptive risk engine (shadow mode)**; **user lifecycle state machine**; **RS validation SDK (`ssoclient/rs`)**; **multi-dimensional rate limiting**; **admin console full CRUD UI + PKCE login**; **production polish batch** (8 small ops fixes).

## Cross-cutting sequencing rules (from the docs' own dependency analyses)

1. Webhook HMAC signing (Wave 1) before webhook subscriptions (Wave 2) before SIEM formats/Kafka sinks — design the signing header and subscription model exactly once.
2. Email-domain ownership verification (Wave 2) before connection-driven upstream login (Wave 3).
3. Durable outbox design before SCIM outbound (Wave 3) — otherwise two L-efforts become one XL twice.
4. Async OTel spans (Wave 2) before debugging any eventing work.
5. Token-exchange governance requires splitting `token_exchange_stages.go` first (500-line gate).
6. `cluster.Bus` upgrade (topic subscription, persistent replay) is shared infra for admin governance + RS intelligence + GitOps directions — do once if any two are scheduled.
7. Agent-identity ADR (RFC 8693 reuse vs new grant) before any AI-agent code (round-31 doc).

## Refuted / stale claims (do not re-litigate)

- `go build ./...` breakage (BLOCKER-0) — stale; build is green.
- Cross-replica atomic layer, revocation persistence, monotonic clock trio — refuted by their own verify docs / later HA campaigns.
- Consent store SPI, hosted login/portal SPA, home-realm discovery, per-tenant metering (except TopTenants exposure) — shipped; docs conflict resolved by code.
- Known out-of-scope set (project memory): mobile Native SSO infra, prompt=login/max_age rework, RFC 7592 RAT rotation, crypto/ecdh modernization.
- 11 of 12 `results/analysis-*.out.techlead.md` are failed pipeline runs (missing bedrock API key) with no content — pipeline concern, not repo work.
