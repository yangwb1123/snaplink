# Deferred Backlog

Consolidated, de-duplicated list of directions that the historical analysis
docs proposed but that are **not yet implemented** in the code (verified by
grep against the current tree, not by trusting the source docs' own stale
claims). The point-in-time analysis docs those items came from are preserved
in the project's git history (removed from the working tree during a docs
cleanup); this file is the single living index of what remains open.

Status legend for each theme: **none** (nothing built) / **partial** (a
related capability exists but the proposed feature does not).

---

## Eventing & integration

- **Generic event/webhook egress engine** — none. `EventSubscription` store +
  delivery engine + dead-letter queue + HMAC signing + retry/backoff for
  lifecycle events (`user.created`, `client.secret_rotated`, `credential.expiring`,
  …). Today only CAEP/SSF (to affected RPs) and the admin SSE stream exist; there
  is no operator-configurable outbound webhook system.
  _Sources: expansion-v2, expansion-analysis-20260701, expansion-directions,
  expansion-directions-auth-plane, analysis-novel-directions-passkey…,
  expansion-directions-2026-07-01-v3, analysis-expansion-directions._
- **SCIM push provisioning** — partial. SCIM is receiver-only; add an outbound
  `SCIMProvisioner` SPI that pushes to downstream apps. _Source:
  enterprise-expansion-directions-2026-07-01._
- **Event-driven identity lifecycle automation** — none. `LifecycleEventBus`,
  outbound `scimclient`, lifecycle webhooks. _Source: expansion-directions-2026-07-01-v3._

## Authorization model

- **ReBAC / relationship tuples** — none. Zanzibar-style `RelationTupleStore` +
  check engine; `conditionalaccess` covers attribute conditions only. _Sources:
  expansion-v2, analysis-expansion-directions._

## Sessions, identity & tokens

- **Cross-protocol Session Hub** — none. `global_sid` + unified logout across
  OIDC/SAML/Kerberos/WebAuthn. _Sources: expansion-directions,
  expansion-directions-auth-plane, expansion-identity-beyond-protocols._
- **Identity linking / account merging** — none. `IdentityLinkStore`,
  `/me/identities`, `MergePolicy`. _Sources: expansion-architecture-gaps-2026-07-01,
  analysis-five-directions-toctou…, expansion-identity-beyond-protocols._
- **Passwordless passkey as primary authenticator** — partial. WebAuthn is a
  second factor only; add `WebAuthnPrimaryAuthenticator`, `provider=webauthn` at
  `/auth/login`, `AllowPasswordlessOnly`. _Sources: expansion-v2,
  analysis-novel-directions-passkey…._
- **OIDC Session Management 1.0** — none. `check_session_iframe` /
  `end_session_iframe` / `session_state`. _Sources: completeness-audit (x2),
  analysis-round6._

## Novel / future protocols

- **RFC 9321 Transaction Tokens** — none. _Source: expansion-2026-07-01._
- **Cloud workload-identity connectors** — none. AWS/GCP/Azure IMDS /
  `AssumeRoleWithWebIdentity` / `WorkloadIdentityProvider`. _Source: expansion-2026-07-01._
- **AI-agent identity + delegation grant** — none. `AgentProvider` SPI,
  `AgentSession`, `delegation_token` grant. _Source: expansion-round31._
- **Edge MQTT + WASM** — none. MQTT `cluster.Bus` backend, WASM authz engine,
  WASM authenticator, MQTT CAEP channel. _Source: analysis-round11._

## Enterprise governance & compliance

- **Cross-tenant B2B collaboration** — none. `ExternalUserStore`/guest records,
  cross-tenant token-exchange grant, `TenantCollaboration` trust model,
  `original_subject`/`original_tenant` audit fields. _Sources:
  senior-architect-expansion-2026-07-02, expansion-novel-directions-2026-07-02._
- **Admin governance framework** — partial. Per-tenant/admin write quotas,
  change-approval workflow, `DestructiveActionGuard`, admin IP-allowlist/geo-lock,
  universal write-reason (rate-limit + break-glass approval exist). _Sources:
  senior-architect-expansion-2026-07-02, expansion-novel-directions-2026-07-02,
  analysis-final-project-expansion-directions._
- **Declarative multi-cluster config governance** — partial. K8s CRDs, config
  Operator/GitOps reconciler, canary rollout, cross-cluster diff (only
  intra-cluster drift detection exists). _Sources: senior-architect-expansion-2026-07-02,
  expansion-novel-directions-2026-07-02, enterprise-expansion-directions-2026-07-01._
- **Compliance reporting** — partial. SOC2 evidence pack, GDPR Art.30 data-map,
  active-consents report, automated data-retention-policy engine (erasure/export
  primitives exist). _Sources: analysis-final-project-expansion-directions,
  expansion-analysis-20260701._

## Productization & DX

- **Admin Console write-CRUD SPA** — partial. Productized UI for clients/users/
  tenants + dogfood OAuth/PKCE login (currently a stub console + raw bearer).
  _Sources: expansion-architecture-gaps-2026-07-01, analysis-five-directions-toctou…._
- **Multi-language SDK generation + developer portal** — none. `oapi-codegen`
  client generation, embedded Swagger/Redoc at `/api/v1/admin/docs`, TS/Python
  consumer SDKs, developer app portal + review workflow. _Sources: health-and-dx-2026-07-01,
  expansion-analysis-20260701, expansion-directions-2026-07-01-v3._
- **i18n / L10n infrastructure** — none. `shared/i18n` Localizer + translation
  bundles for SPA/error/audit surfaces. _Source: health-and-dx-2026-07-01._
- **Repo hygiene** — none. `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, devcontainer +
  hot-reload dev tooling, CI status/coverage badges, more godoc `Example*` funcs.
  _Sources: dx-and-build-infra-2026-07-01, analysis-round15-login…._

## Security headers, crypto & versioning

- **Security-headers framework** — none. CSP + Permissions-Policy +
  Clear-Site-Data + per-request nonce on SPA/form_post surfaces. _Sources:
  architecture-analysis, runtime-performance…, senior-architect-expansion-2026-07-01._
- **FIPS 140-3 build mode** — none. Build tags, `Dockerfile.fips`, GOEXPERIMENT,
  FIPS issuer, crypto-algorithm governance. _Sources: architecture-analysis,
  senior-architect-expansion-2026-07-01._
- **Config JSON-Schema + hot reload** — partial. Schema generation + validator
  chain + `SIGHUP`/`ReloadConfig` hot reload (`DisallowUnknownFields` is warn-only
  today). _Sources: architecture-analysis, ops-api-productization-2026-07-01,
  senior-architect-expansion-2026-07-01, architectural-debt-and-risks-2026-07-01._
- **API versioning / deprecation** — none. `Sunset`/`Deprecation` headers,
  `Accept-Version` negotiation, v2alpha path (ADR-0008 documents the strategy).
  _Source: expansion-novel-architectural-gaps._

## Observability, performance & tests

- **OTel spans across async paths** — partial. Span hierarchy bridge for the
  async audit sink / CAEP / cluster bus / migrate paths (`context.Background()`
  currently breaks the trace). _Sources: senior-architect-expansion-2026-07-01,
  architecture-analysis, runtime-performance…._
- **Benchmark budget CI gate** — none. `.benchmarks.yaml` + `benchstat`
  regression gate. _Sources: architecture-analysis, senior-architect-expansion-2026-07-01._
- **Hot-path performance** — none. `sync.Pool` buffer pooling for JWT issuance,
  sharded/keyed mutexes for memory OAuth stores, `TimeSource`/`Clock` injection,
  bounded memory stores (MaxEntries/reaper) for JTI/refresh/authcode/PAR.
  _Sources: runtime-performance…, edgecases-and-perf-2026-07-01._
- **Per-tenant rate-limit metric** — none. `sso_rate_limit_hits{tenant_id}`.
  _Source: ops-api-productization-2026-07-01._
- **Signing-key hygiene metrics** — none. `PruneVerifyKeys`, verify-set-size
  gauge, per-key/alg signing-usage counters. _Source: ops-api-productization-2026-07-01._
- **Doc/code drift CI checkers** — none. OpenAPI-operationId→route,
  error-code→consts, config-key→docs coverage checks. _Source:
  architectural-debt-and-risks-2026-07-01._
- **Unit-test coverage gaps** — none. `grpcadmin`, `protocols/selfservice`,
  `platform/audit` (auditspi/auditsink), `serverbuildstore`/`serverbuildauthn`
  still have zero unit tests. _Source: test-coverage-gaps-2026-07-01._
- **Input-limit hardening** — partial. `authorization_details` depth/size/count
  limits, scope-count cap, `MaxTokenBytes` gate, `aud` normalization to array.
  _Sources: edgecases-and-perf-2026-07-01, expansion-2026-07-01._

---

*Generated from a grep-verified audit of the historical analysis docs. For the
full rationale behind any item, retrieve the cited doc from git history
(e.g. `git log --all --diff-filter=D -- 'docs/<name>.md'` then `git show`).*
