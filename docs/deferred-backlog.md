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

## Novel / future protocols

- **Cloud workload-identity connectors** — done. GCP, AWS, and Azure all
  implemented (`security.NewGCPWorkloadIdentityValidator`, AWS preset, Azure
  preset via `security.NewAzureWorkloadIdentityValidator` — tenant-scoped
  issuer + JWKS URL derived from an operator-supplied tenant id, reusing the
  shared `securityverify` `WorkloadIdentityValidator` core); `/token` client
  authentication via `WithWorkloadIdentityProviders`. _Source:
  expansion-2026-07-01._
- **Edge MQTT + WASM** — done. WASM authz engine
  (`platform/lifecycle/wasmauthz`, opt-in `sso.WithWASMAuthzEngine`, one
  admin debug endpoint `POST /api/v1/admin/wasmauthz/check`), WASM
  authenticator (`domains/authenticators/wasmauth`, a `core.Authenticator`
  wired via the existing `sso.WithAuthenticator`), an MQTT `cluster.Bus`
  backend (`infrastructure/mqtt`, wired via the existing
  `sso.WithInvalidationBus`), and an MQTT CAEP/SSF delivery channel
  (`protocols/caep`'s `WithMQTTPublisher` + `AttrReceiverMQTTTopic`,
  satisfied by `infrastructure/mqtt`'s `TopicPublisher`) are all
  implemented; see `docs/wasmauthz.md`. _Source: analysis-round11._

## Enterprise governance & compliance

- **Declarative multi-cluster config governance** — partial. K8s CRDs, config
  Operator/GitOps reconciler, canary rollout, cross-cluster diff (only
  intra-cluster drift detection exists). _Sources: senior-architect-expansion-2026-07-02,
  expansion-novel-directions-2026-07-02, enterprise-expansion-directions-2026-07-01._

## Productization & DX

- **Admin Console write-CRUD SPA** — partial. Productized UI for clients/users/
  tenants + dogfood OAuth/PKCE login (currently a stub console + raw bearer).
  _Sources: expansion-architecture-gaps-2026-07-01, analysis-five-directions-toctou…._
- **Multi-language SDK generation + developer portal** — partial. Embedded
  read-only API-docs viewer at `/api/v1/admin/docs` (+ a `/openapi.json`
  companion), opt-in via `WithAPIDocsUI` (`interfaces/apidocs`; no CDN
  script, no vendored Swagger-UI/Redoc bundle — a small hand-rolled page in
  the same style as the admin/login/portal SPAs). A curated TS + Python
  consumer-SDK generator (`cmd/gensdk`, committed output at
  `docs/sdks/{typescript,python}`, same "generated but checked in" pattern
  as `gen/proto/*.pb.go`) covering core OAuth2/OIDC + token lifecycle +
  self-service + a small representative admin sample — NOT the full
  ~150-route grpc-gateway-generated admin CRUD surface, nor SCIM/CAEP/
  federation (see `docs/sdks/*/README.md` for the exact allowlist and
  simplifications). The developer app portal + review workflow remains
  undone — a separate, large feature (an application UI + backend
  approval/review workflow) deliberately out of scope for the pass that
  added the above. _Sources: health-and-dx-2026-07-01,
  expansion-analysis-20260701, expansion-directions-2026-07-01-v3._

## Security headers, crypto & versioning

- **Config JSON-Schema + hot reload** — partial. Schema generation
  (`config/schema`, `sso-ctl config validate-schema`) + validator chain +
  `SIGHUP` hot reload done for `logging.level` AND `security.rate_limit.*`
  (`ratelimit.DynamicMiddleware` + `ratelimit.PolicyStore` +
  `Server.SetRateLimitPolicy`, wired via `config/reload`'s
  `SetRateLimitHook` — the whole Policy rebuilds as one atomic unit per
  reload, in-memory bucket state resets); feature-gate hot-reload remains
  deferred — toggling a gate after boot cannot add/remove already-registered
  mux routes without a full re-Mount, which this SDK does not support at
  runtime (a fundamentally harder problem than rate-limit's numeric-knob
  swap). _Sources: architecture-analysis, ops-api-productization-2026-07-01,
  senior-architect-expansion-2026-07-01, architectural-debt-and-risks-2026-07-01._

## Observability, performance & tests

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

---

*Generated from a grep-verified audit of the historical analysis docs. For the
full rationale behind any item, retrieve the cited doc from git history
(e.g. `git log --all --diff-filter=D -- 'docs/<name>.md'` then `git show`).*
