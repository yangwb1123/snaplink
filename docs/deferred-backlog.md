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

- **Declarative multi-cluster config governance** — partial. Cross-cluster
  diff is now done as an HTTP primitive: `POST /api/v1/admin/config/cluster-diff`
  (`platform/configaudit.HandleClusterDiff`) accepts a peer cluster's config
  snapshot (typically fetched from that peer's own existing
  `GET .../config/running`) and returns the RFC 6902 patch against THIS
  cluster's running config, reusing the same `Diff`/`RedactOps` pipeline the
  existing intra-cluster applied-vs-running `GET .../config/diff` uses.
  Deliberately does NOT fetch the peer itself (no new outbound network
  capability or peer-discovery mechanism) — an operator or a small external
  reconciler script does the two-cluster fetch-then-post. K8s CRDs, a config
  Operator/GitOps reconciler, and canary rollout remain undone — those need
  a k8s client-go/controller-runtime dependency and a real reconciliation
  loop, a much larger and qualitatively different undertaking than this
  diff primitive; this HTTP endpoint is the natural building block a future
  operator/reconciler would call, not a placeholder for it.
  _Sources: senior-architect-expansion-2026-07-02,
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
  simplifications). The backend approval/review workflow half is now done:
  `client_registration.default_active: false` registers a new DCR client
  pending (`Active=false`); `ClientAdminService.Approve`/`Reject`
  (`POST /api/v1/admin/clients/{id}/{approve,reject}`) let an admin activate
  or delete it, each emitting a distinct `admin_client_approved`/
  `admin_client_rejected` audit event (not the generic `admin_client_updated`/
  `admin_client_deleted`). Closed a real gap found while wiring this: the
  `private_key_jwt` client-assertion path (`verifyJWTClientAssertion`) never
  checked `Client.Active` at all — unlike the `client_secret` path
  (`ClientStore.ValidateSecret`), so a pending/deactivated client could have
  authenticated via a signed JWT assertion regardless of its review status;
  fixed with the same collapsed `invalid_client` wire shape as every other
  rejection on that path. The developer-facing PORTAL UI (an application
  browsing/submission page) remains undone — a frontend project, not a
  bounded backend increment; an admin reviews pending registrations today
  via the existing `GET /api/v1/admin/clients?filter=active:false` list. _Sources:
  health-and-dx-2026-07-01, expansion-analysis-20260701,
  expansion-directions-2026-07-01-v3._

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

- **Hot-path performance** — done. `sync.Pool` buffer pooling for JWT
  issuance, sharded locks for the auth-code/PAR memory OAuth stores,
  injectable `Clock` (Ed25519/ECDSA/RSA issuers), and bounded memory
  stores (`MaxEntries` + an opt-in background reaper) for the JTI-replay,
  refresh-token, device-code, and PAR memory stores are all done. The
  reaper lifecycle avoided the file-count-ceiling problem that deferred
  it earlier: `infrastructure/defaultimpl/memreaper` is a small new
  subdirectory (a fresh, separately-budgeted package, mirroring the
  `webauthn`/`wasmauth` sibling-subdirectory pattern), and each store's
  `Close()` is reached at shutdown through the EXISTING
  `Server.RefreshTokenStore()`/`DeviceCodeStore()`/`PARStore()`/
  `JTIReplayStore()` accessors + an `io.Closer` type assertion — the same
  idiom `cmd/sso-server`'s shutdown path already used for the CAEP
  transmitter and the Kafka audit sink — so no new fields were needed on
  `interfaces/sso.Server` or `cmd/sso-server`'s `app` struct. All four
  knobs (`max_entries` / `reap_interval`) default to 0 (disabled/
  unbounded), byte-identical to pre-feature behavior, and only apply to
  the memory backend (sqlite/redis bound growth their own way). Sharding
  the refresh-token and device-code stores was deliberately NOT done —
  both have cross-key invariants (family-keyed `DeleteFamily`, dual
  device/user-code indices) that sharding would turn into real races, not
  just missed optimizations. _Sources: runtime-performance…,
  edgecases-and-perf-2026-07-01._

---

*Generated from a grep-verified audit of the historical analysis docs. For the
full rationale behind any item, retrieve the cited doc from git history
(e.g. `git log --all --diff-filter=D -- 'docs/<name>.md'` then `git show`).*
