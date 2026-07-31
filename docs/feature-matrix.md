# Feature Matrix

OAuth 2.0 / OIDC / SSO capability matrix, verified against the current code on
2026-07-29.

This table records implemented code, not certification and not default
availability on every deployment:

- An `interfaces/sso` `With*` option is an **SDK** capability.
- A `config.yaml` key is a **stock `sso-server`** capability.
- A row naming a nested module (SAML, LDAP, Kerberos, RADIUS, ext-authz,
  Kafka, MQTT or selected KMS/HSM adapters) requires that module to be built or
  registered by the composition root. `full` and the historical
  `standard-kafka` compatibility profile carry Kafka; the others remain
  integration-required.
- Optional endpoints only exist when their required store/option is wired and
  their feature gate is on.
- The runtime is API-only. Frontend applications are external projects; the
  admin-gated API-doc viewer is the only self-contained HTML utility described
  here.

Availability has four independent dimensions:

| Dimension | Meaning |
|---|---|
| Compiled capability | A cold profile includes the code and dependency closure. |
| Runtime backend | Startup configuration selects one of the compiled implementations. |
| Feature gate | An already compiled and wired endpoint or behavior is exposed. |
| Hot lifecycle | A prepared generation can activate, become ready, drain, and stop without rebuilding/restarting. |

Do not infer one dimension from another. In particular, a disabled gate does
not remove linked code, and the current server has no general hot-plugin
lifecycle.

<!-- BEGIN GENERATED CAPABILITY AVAILABILITY -->
## Capability availability registry

Generated from [`ops/build/capabilities.json`](../ops/build/capabilities.json); edit the registry and run `python cli.py capabilities generate`.

| Capability | Availability | Default | Feature gate | Required store(s) | Surface(s) |
|---|---|---|---|---|---|
| Admin control plane (`admin.control-plane`) | `sdk`<br>`stock-binary` | `conditional` | `feature_gates.admin_api` | `AdminTokenStore` | `/api/v1/admin/*` |
| Embedded API docs viewer (`api.docs-viewer`) | `sdk` | `disabled` | `feature_gates.admin_api` | — | `/api/v1/admin/docs` |
| Kafka audit sink (`audit.kafka`) | `stock-binary`<br>`module-only` | `disabled` | — | — | `audit sink` |
| Fine-grained authorization (`authorization.fga`) | `sdk`<br>`stock-binary` | `disabled` | — | `RebacStore`<br>`RebacEngine` | `/authz/*` |
| Public tenant branding (`branding.public`) | `sdk`<br>`stock-binary` | `conditional` | `feature_gates.branding` | `TenantStore` | `/branding` |
| CAEP and Shared Signals (`caep.shared-signals`) | `sdk`<br>`stock-binary` | `disabled` | `feature_gates.caep` | `CAEPStreamStore`<br>`JTIReplayStore` | `/.well-known/ssf-configuration`<br>`/ssf/*` |
| OpenID Connect CIBA (`ciba.core`) | `sdk`<br>`stock-binary` | `disabled` | `feature_gates.ciba` | `CIBAStore` | `/backchannel-authentication`<br>`/token` |
| Cluster and HA coordination (`cluster.ha`) | `sdk`<br>`stock-binary` | `disabled` | — | `cluster.Bus`<br>`shared durable stores` | `/readyz`<br>`cross-replica bus` |
| OpenID Federation (`federation.openid`) | `sdk`<br>`stock-binary` | `disabled` | `feature_gates.federation` | `FederationEntity` | `/.well-known/openid-federation*`<br>`/auth/home-realm` |
| Admin console (`frontend.admin`) | `external-frontend` | `external` | — | — | `/admin/*` |
| Developer portal (`frontend.developer`) | `external-frontend` | `external` | — | — | `/developer/*` |
| Hosted login (`frontend.login`) | `external-frontend` | `external` | — | — | `/login/*` |
| Self-service portal (`frontend.self-service`) | `external-frontend` | `external` | — | — | `/portal/*` |
| Setup application (`frontend.setup`) | `external-frontend` | `external` | — | — | `/setup/*` |
| Enterprise authenticators (`identity.enterprise-auth`) | `module-only` | `disabled` | — | — | `/auth/saml/*`<br>`/auth/kerberos`<br>`Authenticator SPI` |
| MFA and passkeys (`identity.mfa`) | `sdk`<br>`stock-binary` | `conditional` | — | `MFAChallengeStore`<br>`MFAEnrollmentStore` | `/auth/mfa`<br>`/me/mfa/*`<br>`/webauthn/*` |
| Password authentication (`identity.password`) | `sdk`<br>`stock-binary` | `enabled` | — | `UserProvider`<br>`PasswordCredentialStore` | `/auth/login` |
| Identity self-service APIs (`identity.self-service`) | `sdk`<br>`stock-binary` | `conditional` | `feature_gates.self_service` | `UserProvider`<br>`feature-specific stores` | `/me/*`<br>`/sessions/me/*`<br>`/consents/me/*` |
| Signing-key lifecycle (`keys.lifecycle`) | `sdk`<br>`stock-binary` | `conditional` | — | `signing key Registry` | `/.well-known/jwks.json`<br>`/readyz` |
| Advanced OAuth security (`oauth.advanced`) | `sdk`<br>`stock-binary` | `conditional` | — | `feature-specific OAuth stores` | `/par`<br>`/token`<br>`/auth/login` |
| OAuth client credentials (`oauth.client-credentials`) | `sdk`<br>`stock-binary` | `enabled` | — | `ClientStore` | `/token` |
| OAuth SSO core (`oauth.sso`) | `sdk`<br>`stock-binary` | `enabled` | — | `AuthCodeStore`<br>`SessionManager` | `/auth/login`<br>`/token` |
| Observability (`observability.core`) | `sdk`<br>`stock-binary` | `enabled` | — | — | `/livez`<br>`/readyz`<br>`/metrics` |
| OpenID Connect core (`oidc.core`) | `sdk`<br>`stock-binary` | `enabled` | `feature_gates.oidc` | `IDTokenIssuer` | `/.well-known/openid-configuration`<br>`/userinfo`<br>`/end_session` |
| SCIM provisioning (`provisioning.scim`) | `sdk`<br>`stock-binary` | `disabled` | — | `UserProvider` | `/api/v1/scim/v2/*` |
| Production storage backends (`storage.production`) | `stock-binary` | `conditional` | — | — | `storage SPI` |
| Tenant platform (`tenant.platform`) | `sdk`<br>`stock-binary` | `conditional` | — | `TenantStore` | `/api/v1/admin/tenants/*`<br>`tenant middleware` |
| Threat detection and response (`threat.detection-response`) | `sdk`<br>`stock-binary` | `disabled` | — | `ThreatPolicyStore`<br>`anomaly stores` | `/api/v1/admin/threat-policies/*`<br>`/api/v1/admin/tokens/suspicious` |
<!-- END GENERATED CAPABILITY AVAILABILITY -->

| Profile | Maturity | Capability claim |
|---|---|---|
| `prototype` | Preview; buildable | SSO + OAuth Authorization Code/PKCE, password and reusable OP-session login, basic JSON logs, memory defaults, and a stable `default` tenant seam. OIDC surfaces are excluded. |
| `minimal` | Preview; buildable | Inherits `prototype`; adds OIDC discovery, ID Token, UserInfo and logout plus request tracing. |
| `full` | Supported; buildable | Inherits `minimal`; selects the complete current stock `sso-server` composition and registered Kafka audit cold module. Other independently packaged integrations remain registration-dependent. |
| `standard`, `standard-kafka` | Supported compatibility profiles | Historical stock composition only; not layers in the edition hierarchy. |

Build an edition with, for example,
`python cli.py configure --profile minimal --version v1.1.1 --build`.
`prototype` and `minimal` currently share the `cmd/sso-minimal` physical
dependency graph despite exposing different runtime surfaces. See
[plugin-system.md](plugin-system.md) for lifecycle boundaries.

“Implemented” does not mean OpenID Certified. Certification evidence is tracked
in [sso/oidc-conformance.md](sso/oidc-conformance.md), and intentional limits
are tracked in [deferred-backlog.md](deferred-backlog.md).

| Spec | Endpoint(s) | Opt-in | File |
|---|---|---|---|
| RFC 6749 §4.1 authorization_code | `/auth/login` + `/token` | `WithAuthCodeStore` | `protocols/oauth/oauthspi/auth_code.go` + `protocols/oauth/oauthwire/auth_code_handler.go` |
| RFC 6749 §4.4 client_credentials | `/token` | always | `protocols/oauth/oauthwire/client_creds.go` |
| RFC 6749 §6 refresh_token | `/token` | `WithRefreshTokenStore`; grace: `WithRefreshRotationGrace(window)`; family absolute-max-lifetime: `WithRefreshAbsoluteMaxLifetime(d)` | `protocols/oauth/oauthspi/refresh_token.go` + `interfaces/sso/server_token.go` |
| RFC 7636 PKCE | `/auth/login` + `/token` | per-request / `Client.RequirePKCE` | `protocols/oauth/oauthwire/auth_code_handler.go` |
| RFC 7662 introspection | `/token/introspect` | always; cache: `WithIntrospectionCache`; batch: `WithIntrospectionBatch(maxSize)` | `protocols/oauth/handle_introspect.go` + `protocols/oauth/introspect_cache.go` |
| RFC 9701 signed introspection | `/token/introspect` (`Accept: application/token-introspection+jwt`) | `WithIntrospectionSigner(signer)`; default OFF; reuses the existing signing issuer OR (`keys.introspection_signing.enabled`) a DEDICATED, independently-rotated key; JWKS `use:introspection` | `protocols/oauth/handle_introspect.go` |
| RFC 7009 revocation | `/token/revoke[-all]` | always; bulk: `RefreshTokenSubjectIndex`; cross-replica: `WithCrossReplicaRevocation`; durable: `With{Algo}RevocationStore` | `protocols/oauth/handle_revoke.go` |
| RFC 8628 device | `/device/{code,verify}`, `/token` | `WithDeviceCodeStore` | `protocols/oauth/oauthspi/device_code.go` + `interfaces/sso/server_token.go` |
| RFC 8693 token-exchange | `/token` | always; refresh: `WithRefreshTokenStore`; actor replay: `WithJTIReplayStore`; act-chain cycle detection: always-on; chain-lifetime cap: `WithMaxTokenExchangeChainLifetime(d)`; hop authorization: `WithTokenExchangePolicy(policy)` (`domains/tokenexchange` SPI + `memory.Store` reference impl); cross-tenant B2B collaboration: `WithExternalUserStore(store)` + `WithTenantCollaborationStore(store)` (`domains/tenant` SPI + `domains/tenant/memory` reference impl; BOTH required to activate, fail-closed default-deny) | `interfaces/sso/server_token.go` + `domains/tokenexchange/` + `domains/tenant/tenant_collab.go` |
| RFC 8707 resource indicators | every issuance | `Client.AllowedResources` | `shared/core/types.go` + issuance handlers under `interfaces/sso/` |
| RFC 9126 PAR | `/par` | `WithPARStore` | `protocols/oauth/handle_par.go` |
| RFC 7591/7592 DCR | `/register[/:id]` | `WithDynamicClientRegistration` | `protocols/oauth/handle_register.go` |
| OIDC Core ID Token | `id_token` w/ `openid` | `WithIDTokenIssuer`; `at_hash` when `access_token` in same response | `protocols/oidc/types.go` + `interfaces/sso/server_finish_login.go` + `infrastructure/defaultimpl/ed25519_issue.go` + `infrastructure/defaultimpl/ecdsa_issue.go` + `infrastructure/defaultimpl/rsa_issue.go` |
| OIDC Discovery 1.0 | `/.well-known/openid-configuration` | always | `interfaces/sso/server_discovery.go` + `interfaces/sso/server_discovery_config.go` + `protocols/oidc/oidcsupport/discovery_doc_cache.go` |
| RFC 8414 AS Metadata (alias, same handler/body as OIDC discovery) | `/.well-known/oauth-authorization-server` | always | `interfaces/sso/server_discovery.go` |
| OIDC RP-Initiated Logout | `/end_session` | always | `protocols/oidc/handle_end_session.go` |
| OIDC BCL 1.0 | `/logout`, `/end_session` | `WithBackchannelLogout`; multi-RP: `WithSubjectClientIndex` | `interfaces/sso/server_backchannel_logout.go` |
| OIDC FCL 1.0 | `/end_session` | `Client.FrontchannelLogoutURI` | `interfaces/sso/server_backchannel_logout.go` + `protocols/oidc/handle_end_session.go` |
| OIDC `sid` claim | access + id + logout | `WithSessionManager` | `infrastructure/defaultimpl/ed25519_issue.go` + `infrastructure/defaultimpl/ecdsa_issue.go` + `infrastructure/defaultimpl/rsa_issue.go` |
| OIDC `login_hint` | `/auth/login`, `/par`, JAR | always | `interfaces/sso/server_login.go` + `protocols/oauth/oauthspi/par.go` + `interfaces/sso/server_jar.go` |
| OIDC Form Post | `/auth/login`, `/par`, JAR | always | `protocols/oidc/oidcsupport/form_post.go` |
| JARM | `response_mode={jwt,query.jwt,fragment.jwt,form_post.jwt}` | `WithJARM(signer)` (fail-closed without) | `protocols/oidc/jarm.go` |
| OIDC `prompt=none` | `/auth/login` | `WithSessionManager` + `WithIDTokenIssuer` | `protocols/oidc/handle_silent_renewal.go` |
| RFC 7521+7523 `private_key_jwt` | `/token`, `/par`, `/introspect`, `/revoke` | `Client.JWKS`; sig via `AsymmetricJWSAlgs` | `interfaces/sso/server_token_clientauth.go` + `shared/security/securityverify/jwks_verify.go` |
| RFC 9207 AS Issuer Id | every `/auth/login` | always | `interfaces/sso/server_finish_login.go` |
| RFC 9068 JWT Access Token | JWT access tokens | always; alg gate `WithSupportedSigningAlgs` | `infrastructure/defaultimpl/ed25519_issue.go` + `infrastructure/defaultimpl/ecdsa_issue.go` + `infrastructure/defaultimpl/rsa_issue.go` + `infrastructure/defaultimpl/ed25519_validate.go` + `infrastructure/defaultimpl/ecdsa_validate.go` + `infrastructure/defaultimpl/rsa_validate.go` |
| RFC 8705 mTLS-bound + aliases | `/token` + `/userinfo` | `WithClientCertExtractor` | `interfaces/sso/server_token_clientauth.go` + `interfaces/sso/server_userinfo.go` |
| mTLS / X.509 certificate revocation check | `/token` (tls_client_auth, self_signed_tls) + `certificate` authenticator | `WithMTLSRevocationChecker` (client auth) / `authenticators.WithCertRevocationChecker` (end-user X.509 login); default OFF, fail-open on checker error | `interfaces/sso/server_token_clientauth.go` + `domains/authenticators/certificate.go` + `shared/spi/risk.go` |
| RFC 9470 Step-Up | resource-server helper | always | `shared/security/securityverify/step_up_auth.go` |
| RFC 9449 DPoP | `/token` + `/userinfo` | header-triggered; replay: `WithJTIReplayStore`; nonce: `WithDPoPNonceProvider` | `interfaces/sso/server_dpop.go` |
| RFC 8414 §2.1 signed_metadata | discovery | `WithMetadataSigner` | `interfaces/sso/server_discovery_config.go` + `protocols/oidc/metadata.go` |
| OAuth 2.1 strict | `/auth/login` | `WithOAuth21StrictMode` | `interfaces/sso/options.go` + `interfaces/sso/server_finish_login.go` |
| FAPI 2.0 profile | `/auth/login` + `/token` + discovery | `WithFAPIProfile(Inspection\|Enforce)` | `protocols/fapi/` + `interfaces/sso/server_discovery_config.go` |
| RFC 9396 RAR | `authorization_details` | per-client allowlist | `protocols/oauth/oauthvalidate/rar.go` + `interfaces/sso/server_login.go` |
| RFC 9101 JAR | `request`, `request_uri` | `Client.JWKS`; URL fetch: `WithJARFetcher`; required: `Client.RequireSignedRequestObject` | `interfaces/sso/server_jar.go` + `shared/security/securityverify/jar_fetch.go` |
| RFC 9101 §6.4 JWE JAR | `request` (JWE) | `WithJARDecrypter`; enc key in JWKS `use:enc` | `shared/security/jwe.go` |
| OIDC §10.2 id_token JWE | `id_token` (encrypted) | `WithJWEResponseEncrypter` + per-client `IDTokenEncryptedResponseAlg/_Enc` | `protocols/oidc/userinfo_signing.go` |
| OIDC §5.3.2 userinfo JWE | `/userinfo` (encrypted) | `WithJWEResponseEncrypter` + per-client `UserinfoEncryptedResponseAlg/_Enc` | `protocols/oidc/userinfo_signing.go` |
| OIDC CIBA (poll + ping + push; no `user_code` mode) | `/backchannel-authentication`, `/token` | `WithCIBA`; ping: `WithCIBAPingNotifier`; push: `WithCIBAPushNotifier` | `protocols/oauth/oauthspi/ciba.go` + `protocols/oauth/handle_ciba.go` |
| MFA orchestration | `/auth/login` + `/auth/mfa` | `WithMFAProvider` + `WithMFAChallengeStore` | `interfaces/sso/server_mfa.go` + `shared/spi/mfa.go` |
| Per-account lockout | `/auth/login` | `WithAccountLockout` | `shared/security/account_lockout.go` + `interfaces/sso/options.go` |
| Password history / reuse prevention | `POST /me/password`, `POST /auth/reset-password` | `WithPasswordHistoryStore` (+ `PasswordPolicyConfig.MaxHistory` for the record capacity) | `interfaces/sso/server_signup.go` + `infrastructure/defaultimpl/memorystorecredential/memory_password_credentials.go` |
| SPIFFE JWT-SVID token-exchange | `/token` | `WithSPIFFEJWTSVID(trustDomain, audience, JWKSSource)` | `shared/security/securityverify/spiffe_svid.go` |
| RFC 9321 Transaction Tokens | `/token` (grant=token-exchange, `requested_token_type=...:txn-token`) | `WithTransactionTokens(Issuer, Validator)` | `protocols/oauth/txntoken/` |
| Cloud workload-identity client auth (GCP, AWS, Azure) | `/token` client authentication | `WithWorkloadIdentityProviders(security.NewGCPWorkloadIdentityValidator(...), security.NewAWSWorkloadIdentityValidator(issuer, ...), security.NewAzureWorkloadIdentityValidator(tenantID, ...))` + `Client.TokenEndpointAuthMethod=workload_identity` | `shared/security/securityverify/workload_identity.go` + `shared/security/securityverify/workload_identity_presets.go` |
| OpenID SSF v1 configuration + Stream Management | `/.well-known/ssf-configuration`, `/ssf/streams[/:id]` | configuration is CAEP-gated; CRUD requires `WithCAEPStreamStore` | `protocols/caep/receiver.go` + `interfaces/sso/server_federation.go` + `infrastructure/defaultimpl/sqlite/authz_stores.go` |
| OpenID SSF v1 SET transmitter | push to the affected RP receiver | `WithCAEPTransmitter` | `protocols/caep/broadcaster.go` |
| OpenID SSF v1 SET receiver | `/ssf/receive` | `WithCAEPReceiver` | `protocols/caep/receiver_receive.go` |
| Envoy ext_authz HTTP | `/mesh/ext-authz` | `WithMeshExtAuthz(path)` | `interfaces/sso/mesh_authz.go` |
| Envoy ext_authz gRPC | `envoy.service.auth.v3.Authorization` | `extauthz` nested module | `infrastructure/extauthz/authz.go` |
| SAML 2.0 SP+IdP | `/auth/saml/*`, `/saml/*` | `saml` nested module | `infrastructure/saml/saml.go` |
| Cross-protocol coordinated logout (SAML SLO reached from OIDC/session logout) | `POST /logout`, `GET /end_session` | always (Session Hub is always-on bookkeeping); SAML leg fires only when `saml`'s `Deps.SessionHub` was wired | `platform/lifecycle/sessionhub/coordinator.go` + `interfaces/sso/server_backchannel_logout.go`'s `TriggerSessionHubLogout` |
| RFC 7662 introspection `renew_after` early warning | `/token/introspect` | automatic once `WithTokenPolicy`'s `RequireRenewAfter` is configured | `domains/tokenpolicy/evaluate.go`'s `RenewAt` + `protocols/oauth/handle_introspect.go` |
| Kerberos/SPNEGO | `/auth/kerberos` | `kerberos` nested module | `infrastructure/kerberos/handler.go` |
| RADIUS authenticator | via `WithAuthenticator` | `radius` nested module | `infrastructure/radius/authenticator.go` |
| WebAuthn attestation policy | `/webauthn/registration/finish` | `webauthn.Config.{AttestationConveyance,AttestationPolicy,MDS}` | `domains/authenticators/webauthn/` |
| WebAuthn passwordless PRIMARY login | `/auth/login` `provider=webauthn` | `webauthn.primary_auth_enabled`; per-client `Client.AllowPasswordlessOnly` | `domains/authenticators/webauthn/conditional_login.go` |
| Multi-region data residency | `/auth/login` + `/userinfo` + mesh + WebAuthn | `WithRegionMiddleware` + `WithTenantResidencyCheck` | `domains/region/region.go` + `interfaces/sso/server_extensions.go` |
| SCIM 2.0 | `/api/v1/scim/v2/` | `scim.NewHandler(users, basePath, ...)` | `protocols/scim/handler.go` |
| SCIM 2.0 push provisioning (outbound) | pushes to a downstream SCIM app's `/Users` + `/Groups` | `scim.push.enabled` / `sso.WithSCIMProvisioner` | `protocols/scimprovision/http_provisioner.go` + `protocols/scimprovision/sink.go` |
| FGA / ReBAC product API | `/authz/tuples`, `/authz/tuples/batch`, `/authz/graph`, `/authz/check` | tuple routes: `WithRebacStore`; check: `WithRebacEngine`; client-credentials gated; memory + SQLite stores | `platform/lifecycle/rebac/` + `infrastructure/defaultimpl/sqlite/authz_stores.go` + `interfaces/sso/server_routes.go` |
| API-docs viewer (self-contained utility, admin-gated; not a product frontend) | `/api/v1/admin/docs` + `/api/v1/admin/docs/openapi.json` | SDK-only `sso.WithAPIDocsUI` | `interfaces/apidocs/` |
| CSP Level 3 + Permissions-Policy + Clear-Site-Data | API responses + `/logout`, `/me/account/erase` | `WithSecurityHeaders` / `WithSecurityHeadersPolicy`; separately deployed frontends configure their own static-asset CSP | `internal/handler/security_headers.go` |
| OpenID Federation 1.0 entity + operational endpoints | `/.well-known/openid-federation`, `/fetch`, `/.well-known/openid-federation-{list,resolve,trust-mark-status,historical-keys}` | `WithFederationEntity(cfg, signer)`; individual routes also depend on subordinates/resolver/historical-key store | `domains/federation/` + `interfaces/sso/server_federation.go` |
| User-lifecycle admin state machine (INVITED→ACTIVE→{SUSPENDED,INACTIVE}→ARCHIVED→PURGED) + optional auto-deprovision sweep | `GET`/`POST /api/v1/admin/users/:id/lifecycle` | `WithUserLifecycle(store)` (+ `WithUserAutoDeprovision(cfg, activity)`); cmd: `user_lifecycle.enabled` (+ `.auto_deprovision.enabled`) | `domains/userlifecycle/` + `interfaces/sso/options_admin.go` + `cmd/sso-server/build_stores.go` |
| Durable identity linking / account-merge conflict resolution | `GET`/`DELETE /me/identities` + built-in OIDC federation subject mapping | `WithIdentityLinkStore(store)` (+ `WithIdentityMergePolicy(policy)`); cmd: `self_service.identity_link.{enabled,backend,merge_policy}`; memory + SQLite + Postgres | `domains/identitylink/` + `infrastructure/identitylinkpostgres/` + `cmd/sso-server/build_stores.go` |
