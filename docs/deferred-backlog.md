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
  diff is done as an HTTP primitive: `POST /api/v1/admin/config/cluster-diff`
  (`platform/configaudit.HandleClusterDiff`) accepts a peer cluster's config
  snapshot (typically fetched from that peer's own existing
  `GET .../config/running`) and returns the RFC 6902 patch against THIS
  cluster's running config, reusing the same `Diff`/`RedactOps` pipeline the
  existing intra-cluster applied-vs-running `GET .../config/diff` uses.
  Deliberately does NOT fetch the peer itself (no new outbound network
  capability or peer-discovery mechanism) — the caller does the two-cluster
  fetch-then-post.

  The K8s-native half of this is now ALSO done: `cmd/sso-operator` (a
  separate nested Go module, `github.com/snaplink/operator`, depending on
  `sigs.k8s.io/controller-runtime` + `k8s.io/{api,apimachinery,client-go}`,
  with zero dependency on the `github.com/snaplink/sso` SDK itself) ships an
  `SSOConfigDrift` CRD (`sso.snaplink.io/v1alpha1`) + reconciler
  (`cmd/sso-operator/controller`). Reconciling one resolves both
  clusters' bearer tokens from referenced Secrets, does the
  fetch-`config/running`-then-POST-`config/cluster-diff` round trip itself
  on a `PollInterval` (default 5m), and reports `DriftDetected` /
  `PatchOpCount` / `Message` in `.status` — `kubectl get ssoconfigdrift <name>
  -o yaml` is now the declarative, K8s-native way to see two clusters'
  drift, instead of a hand-run script. Fail-open: an HTTP/secret-lookup
  error sets `.status.message` and requeues in 30s WITHOUT touching
  `DriftDetected`/`PatchOpCount` (a transient failure is not evidence of "no
  drift") and never fails the reconcile loop, mirroring
  `platform/configaudit/drift.go`'s own report-only doctrine. Bearer tokens
  are read from Secrets and used only in the outbound `Authorization`
  header — never logged or written to Status.

  An adversarial review pass on this operator (before it was considered
  done) found and fixed three real issues: (1) the reconciler's own
  `Status().Update()` re-triggered itself via controller-runtime's default
  Update handler, defeating `PollInterval` entirely — fixed with
  `builder.WithPredicates(predicate.GenerationChangedPredicate{})`, which a
  status-subresource-only write doesn't satisfy; (2) `http.DefaultClient`
  has no timeout, so an unreachable/slow-loris `BaseURL` could hang the
  single-worker reconcile loop indefinitely — fixed with an explicit
  `defaultHTTPClient{Timeout: 15s}`; (3) a confused-deputy/SSRF risk —
  `BaseURL`/`BearerSecretRef` are CR-author-controlled with no in-code
  relationship check, so whoever can write a `SSOConfigDrift` can make the
  controller's own ServiceAccount read ANY same-namespace Secret and POST
  it to an ATTACKER-CHOSEN host. Mitigated (not eliminated — this is an
  inherent property of any K8s resource referencing a same-namespace
  Secret by name, e.g. a Pod's `envFrom.secretKeyRef`) by requiring
  `https://` on `BaseURL` (enforced both by the CRD schema's `pattern` and
  by the reconciler itself, so a token is never placed on the wire in
  plaintext) and by documenting the RBAC precondition explicitly in
  `cmd/sso-operator/doc.go`'s "Trust model" section: write access to
  `SSOConfigDrift` MUST be scoped no more broadly than read access to
  Secrets in the same namespace.

  Explicitly still OUT OF SCOPE (unchanged from before): config APPLY (the
  operator never issues a write request against either cluster — the
  cluster-diff endpoint it calls is diff-only, not apply), canary rollout,
  auto-remediation ("reconcile B to match A" on any trigger), and a GitOps
  reconciler that writes desired state FROM a Git repo INTO a cluster (this
  operator only ever compares two already-running clusters against each
  other). Extending to an apply mode would need an explicit opt-in spec
  field (defaulting off), a new write-capable endpoint (cluster-diff stays
  read-only by design), a canary/rollout strategy, and an audit trail
  distinguishing "detected" from "applied" — a materially larger, separate
  undertaking; see `cmd/sso-operator/doc.go` for the detailed next-step
  sketch.
  _Sources: senior-architect-expansion-2026-07-02,
  expansion-novel-directions-2026-07-02, enterprise-expansion-directions-2026-07-01._

## Productization & DX

- **Admin Console write-CRUD SPA** — done. Clients CRUD is done in
  `interfaces/web/admin` (hand-rolled HTML/JS/CSS, no build step, no CDN —
  matches the login/portal SPAs' existing convention): create, edit, delete,
  rotate-secret, and approve/reject (wired to `ClientAdminService.Approve`/
  `Reject`) all reachable from the Clients page's detail panel. Fixed a
  real pre-existing bug found while wiring this: the console's Clients AND
  Users pages read `token_strategy`/`allowed_scopes`/`redirect_uris`/
  `allowed_authenticators`/`external_id` (snake_case) from the admin
  gRPC-gateway's JSON responses, but the gateway's default protojson
  marshaler emits lowerCamelCase (`tokenStrategy`, `allowedScopes`, ...) —
  confirmed empirically (a real `protojson.Marshal` call, not a doc
  assumption). Every one of those fields was silently reading `undefined`
  since the page shipped: the client list's Strategy column always showed
  the "jwt" fallback regardless of actual strategy, Scopes/Redirect URIs/
  Allowed Authenticators always rendered empty, and a "Require PKCE" row
  referenced a field that doesn't exist on the proto message at all
  (removed). Fixed by reading the correct camelCase names client-side
  (NOT by changing the wire format — that would be a breaking change for
  any other REST consumer of this already-shipped API). Users and Tenants
  CRUD are now done too, same page/panel pattern as Clients: Users gets
  create/edit/delete (attributes as a `key=value`-per-line textarea, same
  idiom as the Clients form's newline-separated redirect URIs); Tenants
  gets its own new nav page + create/edit/delete plus a dedicated
  Suspend/Activate action wired to `TenantAdminService.SetTenantStatus`
  (kept separate from the Edit form deliberately — the backend split
  status from Update specifically so a status flip stays a surgical,
  race-free RPC, and routing it through the generic Update would defeat
  that). Every new request/response shape (camelCase field names again —
  `externalId`, `homeRegion`, `allowedRegions`, `enforceWrites`, ...) was
  confirmed empirically the same way as the Clients fix, against the real
  `UserAdminService`/`TenantAdminService` behind a real grpc-gateway mux,
  not assumed from the .proto alone. The dogfood OAuth/PKCE login is also
  now done: the login screen offers "Sign in with SSO" (RFC 6749 §4.1 +
  RFC 7636 S256 PKCE, hand-rolled with `crypto.subtle` — no library),
  redirecting to the hosted login page (`/login/`, `WithHostedLoginFS`)
  as the already-seeded public client `sso-admin-console`
  (`platform/bootstrap/builtin`'s `stepSeedAdminConsoleClient`,
  `RequirePKCE: true`, no secret) and exchanging the returned code at
  `/token` with `code_verifier` alone. Falls back to (and keeps) the
  manual bearer-token field, and hides the SSO button entirely outside a
  secure context (`crypto.subtle` requires HTTPS or localhost) rather
  than offering a control that would always fail. Requires the operator
  to register this page's own URL as a `redirect_uri` on
  `sso-admin-console` and to wire `WithHostedLoginFS` — documented inline
  on the login screen. Domains (hostname→tenant mapping) CRUD is now done
  too — same page/panel pattern, a new nav page with create/edit/delete
  against `TenantAdminService`'s `*Domain` RPCs (`hostname` as the primary
  key instead of a separate `id`, branding as a `key=value`-per-line
  textarea like the other map fields). **Every functional item under this
  backlog entry is now done.**
  _Sources: expansion-architecture-gaps-2026-07-01, analysis-five-directions-toctou…._
- **Multi-language SDK generation + developer portal** — done. Embedded
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
  rejection on that path. The developer-facing portal UI is now done too:
  `interfaces/web/developer` (opt-in via `WithDeveloperPortalFS`, mounted
  at `/developer/` only when `client_registration.enabled` — no point
  offering self-registration when `/register` itself 501s) is a hand-rolled
  SPA, same no-CDN convention as the other embedded SPAs, for an
  ANONYMOUS third-party developer (not an admin, not a logged-in end
  user): a Register tab calls `POST /register` (RFC 7591 DCR) and displays
  the one-time `client_secret`/`registration_access_token`/
  `registration_client_uri`; a Manage tab calls `GET`/`PUT`/`DELETE
  /register/:client_id` (RFC 7592), authenticated by the
  registration_access_token alone. The PUT path round-trips every field
  the edit form doesn't expose (`grant_types`, `response_types`,
  `allowed_authenticators`, `allowed_resources`,
  `post_logout_redirect_uris`, ...) unchanged from the prior GET, since the
  server takes those fields verbatim with no stored-value fallback —
  confirmed by reading `buildUpdatedClient` (`protocols/oauth/
  handle_register_helpers.go`), not assumed. **Every functional item under
  this backlog entry is now done.** _Sources: health-and-dx-2026-07-01,
  expansion-analysis-20260701, expansion-directions-2026-07-01-v3._

## Security headers, crypto & versioning

- **Config JSON-Schema + hot reload** — done. Schema generation
  (`config/schema`, `sso-ctl config validate-schema`) + validator chain +
  `SIGHUP` hot reload done for `logging.level`, `security.rate_limit.*`
  (`ratelimit.DynamicMiddleware` + `ratelimit.PolicyStore` +
  `Server.SetRateLimitPolicy`, wired via `config/reload`'s
  `SetRateLimitHook` — the whole Policy rebuilds as one atomic unit per
  reload, in-memory bucket state resets), AND all seven
  `feature_gates.*` fields (`admin_api`, `web_spa`, `oidc`, `ciba`, `caep`,
  `federation`, `self_service`): `interfaces/sso` mounts every gated route
  group UNCONDITIONALLY at `Mount()` time and wraps every registered route
  in a request-time check (`shared/core.GatedRouter` for router-native
  groups, `shared/core.GateHTTPHandler` for the SPA static-asset mounts)
  instead of deciding "mount or don't" once, at boot — gate-off answers
  `http.NotFound` byte-identically to a path that was never registered at
  all. `config/reload`'s `Set*GateHook` (one per gate, wired to the
  matching `Server.Set*GateEnabled` in `cmd/sso-server`'s
  `wireFeatureGateReload`, alongside `wireRateLimitReload`) flips each
  live check on a SIGHUP reload with no restart and no re-Mount, in BOTH
  directions (on->off and off->on) — unlike rate-limit's hook, which can
  only ever retune an already-`WithRateLimit`-enabled policy's numbers.
  Three of the seven have an asymmetry surfaced as `Result.Ignored` rather
  than a false `Result.Applied`: `SetWebSPAGateEnabled` (no SPA filesystem
  ever wired via a `With*FS` option), `SetCAEPGateEnabled` (no
  `WithCAEPReceiver`), and `SetFederationGateEnabled` (none of
  protected-resource metadata / `WithFederationEntity` /
  `WithConnectionStore` wired) — a live gate can only suppress/reveal an
  ALREADY-mounted route, it can never conjure one that was never
  constructed. The other four (`admin_api`, `oidc`, `ciba`,
  `self_service`) have no such gap: each group always has at least one
  unconditionally-mounted route (the admin endpoint inventory,
  `/userinfo`+`/end_session`, `/backchannel-authentication`, and
  `/permissions,/menus,/roles/me` respectively), so their `Set*GateEnabled`
  is always effective.

  An adversarial review pass (before `admin_api`/`web_spa` were considered
  done) found and fixed a real oracle leak: `shared/core.GateHandler`'s
  original design only wrapped the HANDLER, so a global `Use()`-registered
  middleware (Tracing, added before `mountAdminSurface`/
  `mountBrandingEndpoint` ran) still executed and stamped
  `X-Request-Id`/`Traceparent`/`X-Trace-Id` on a gated-off response — a
  real, `httptest`-reproduced difference from a genuinely-never-mounted
  path's 404 (confirmed both for the `/api/v1/admin/*` group and,
  separately, for `mountBrandingEndpoint`, which used the same
  handler-only pattern). Fixed by moving the gate check into the ROUTER's
  own route-matching loop (`StdRoute.live`/`StdRouter.registerGated`,
  checked in `ServeHTTP` BEFORE a matched route's middlewares run — a
  gated-off route is now treated as NOT MATCHED at all, exactly like a
  route never registered, rather than matched-then-answered-404 by the
  handler): `GatedRouter` now prefers this route-matching-level gate when
  the underlying `Router` is (or derives via `Group` from) the default
  `*StdRouter`, falling back to the old handler-wrap for a custom `Router`
  (`WithRouter`, e.g. an echo/gin adapter), which is documented as
  strictly-no-worse-than-before rather than a silent claim of the same
  guarantee. The web_spa SPA filesystem mounts (`GateHTTPHandler` on a raw
  `http.ServeMux` entry, outside the router's middleware system entirely)
  were checked and confirmed NOT affected by this — they never carried
  Tracing to begin with. Also found and fixed: `SetWebSPAGateEnabled`'s
  "was anything wired" check omitted `tenantStore`
  (`mountBrandingEndpoint`'s own independent condition), so toggling the
  gate with ONLY a tenant store wired (no SPA filesystem) would misreport
  `Result.Ignored` for a toggle that did, in fact, change the branding
  endpoint's reachability. Because every one of the remaining five gates
  (`oidc`/`ciba`/`caep`/`federation`/`self_service`) reuses the SAME
  `core.GatedRouter` primitive at every call site (`mountOIDCUserEndpoints`,
  `mountCIBAEndpoint`, the CAEP receiver route in `mountClusterEndpoints`,
  `mountFederationEndpoints`, `mountUnauthenticatedSelfServiceRoutes`,
  `mountSelfServiceProfile`, `mountSelfServiceCredentials`), each inherits
  this route-matching-level fix automatically rather than needing it
  rediscovered per gate — confirmed by a dedicated
  `WithTracingMiddleware`-wired byte-identical-to-404 test per gate in
  `feature_gate_hotreload_test.go`.

  **Every functional item under this backlog entry is now done.**
  _Sources: architecture-analysis, ops-api-productization-2026-07-01,
  senior-architect-expansion-2026-07-01,
  architectural-debt-and-risks-2026-07-01._

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
