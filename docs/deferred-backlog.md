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

## Authorization model

- **ReBAC / relationship tuples** — none. Zanzibar-style `RelationTupleStore` +
  check engine; `conditionalaccess` covers attribute conditions only. _Sources:
  expansion-v2, analysis-expansion-directions._

## Novel / future protocols

- **Cloud workload-identity connectors** — partial. GCP fully implemented
  (`security.NewGCPWorkloadIdentityValidator`, `/token` client authentication
  via `WithWorkloadIdentityProviders`); AWS (no single stable published JWKS —
  needs its own design pass) and Azure AD Workload Identity Federation (likely
  reuses the shared `securityverify` core via a tenant-scoped JWKS URL) remain.
  _Source: expansion-2026-07-01._
- **Edge MQTT + WASM** — none. MQTT `cluster.Bus` backend, WASM authz engine,
  WASM authenticator, MQTT CAEP channel. _Source: analysis-round11._

## Enterprise governance & compliance

- **Declarative multi-cluster config governance** — partial. K8s CRDs, config
  Operator/GitOps reconciler, canary rollout, cross-cluster diff (only
  intra-cluster drift detection exists). _Sources: senior-architect-expansion-2026-07-02,
  expansion-novel-directions-2026-07-02, enterprise-expansion-directions-2026-07-01._

## Productization & DX

- **Admin Console write-CRUD SPA** — partial. Productized UI for clients/users/
  tenants + dogfood OAuth/PKCE login (currently a stub console + raw bearer).
  _Sources: expansion-architecture-gaps-2026-07-01, analysis-five-directions-toctou…._
- **Multi-language SDK generation + developer portal** — none. `oapi-codegen`
  client generation, embedded Swagger/Redoc at `/api/v1/admin/docs`, TS/Python
  consumer SDKs, developer app portal + review workflow. _Sources: health-and-dx-2026-07-01,
  expansion-analysis-20260701, expansion-directions-2026-07-01-v3._
- **Repo hygiene** — none. `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, devcontainer +
  hot-reload dev tooling, CI status/coverage badges, more godoc `Example*` funcs.
  _Sources: dx-and-build-infra-2026-07-01, analysis-round15-login…._

## Security headers, crypto & versioning

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
- **Hot-path performance** — partial. `sync.Pool` buffer pooling for JWT
  issuance, sharded locks for the auth-code/PAR memory OAuth stores, and
  injectable `Clock` (Ed25519/ECDSA/RSA issuers) are done. Bounded memory
  stores (MaxEntries/reaper) for JTI/refresh/device-code/PAR remain — deferred
  because `infrastructure/defaultimpl`, `interfaces/sso`, `config/`, and
  `shared/security` are all already at their frozen file-count ceilings, so
  wiring a reaper lifecycle across 5 store types needs its own focused pass
  with file-count budget planned in. Sharding the refresh-token and
  device-code stores was deliberately NOT done — both have cross-key
  invariants (family-keyed `DeleteFamily`, dual device/user-code indices) that
  sharding would turn into real races, not just missed optimizations.
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
