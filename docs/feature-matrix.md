# Feature Matrix

OAuth 2.0 / OIDC / SSO feature compliance matrix. Extracted from AGENTS.md.

| Spec | Endpoint(s) | Opt-in | File |
|---|---|---|---|
| RFC 6749 §4.1 authorization_code | `/auth/login` + `/token` | `WithAuthCodeStore` | `oauth/auth_code.go` |
| RFC 6749 §4.4 client_credentials | `/token` | always | `oauth/client_creds.go` |
| RFC 6749 §6 refresh_token | `/token` | `WithRefreshTokenStore`; grace: `WithRefreshRotationGrace(window)` | `oauth/refresh_token.go` |
| RFC 7636 PKCE | `/auth/login` + `/token` | per-request / `Client.RequirePKCE` | `oauth/auth_code.go` |
| RFC 7662 introspection | `/token/introspect` | always | `oauth/handle_introspect.go` |
| RFC 7009 revocation | `/token/revoke[-all]` | always; bulk: `RefreshTokenSubjectIndex`; cross-replica: `WithCrossReplicaRevocation`; durable: `With{Algo}RevocationStore` | `oauth/handle_revoke.go` |
| RFC 8628 device | `/device/{code,verify}`, `/token` | `WithDeviceCodeStore` | `oauth/device_code.go` |
| RFC 8693 token-exchange | `/token` | always; refresh: `WithRefreshTokenStore`; actor replay: `WithJTIReplayStore` | `handlers.go` + `oauth/token_exchange_helpers.go` |
| RFC 8707 resource indicators | every issuance | `Client.AllowedResources` | per-grant |
| RFC 9126 PAR | `/par` | `WithPARStore` | `oauth/handle_par.go` |
| RFC 7591/7592 DCR | `/register[/:id]` | `WithDynamicClientRegistration` | `oauth/handle_register.go` |
| OIDC Core ID Token | `id_token` w/ `openid` | `WithIDTokenIssuer`; `at_hash` when `access_token` in same response | `handler.go` + `oidc/userinfo_signing.go` |
| OIDC Discovery 1.0 | `/.well-known/openid-configuration` | always | `handlers.go` + `oidc/discovery_doc_cache.go` |
| RFC 8414 AS Metadata (alias) | `/.well-known/oauth-authorization-server` | always | Same handler/body as OIDC discovery |
| OIDC RP-Initiated Logout | `/end_session` | always | `oidc/handle_end_session.go` |
| OIDC BCL 1.0 | `/logout`, `/end_session` | `WithBackchannelLogout`; multi-RP: `WithSubjectClientIndex` | `server_extensions.go` |
| OIDC FCL 1.0 | `/end_session` | `Client.FrontchannelLogoutURI` | `server_extensions.go` |
| OIDC `sid` claim | access + id + logout | `WithSessionManager` | `defaultimpl/ed25519_jwt_issuer.go` |
| OIDC `login_hint` | `/auth/login`, `/par`, JAR | always | `handler.go` + `oauth/par.go` + `server_extensions.go` |
| OIDC Form Post | `/auth/login`, `/par`, JAR | always | `oidc/form_post.go` |
| JARM | `response_mode={jwt,query.jwt,fragment.jwt,form_post.jwt}` | `WithJARM(signer)` (fail-closed without) | `oidc/jarm.go` |
| OIDC `prompt=none` | `/auth/login` | `WithSessionManager` + `WithIDTokenIssuer` | `oidc/handle_silent_renewal.go` |
| RFC 7521+7523 `private_key_jwt` | `/token`, `/par`, `/introspect`, `/revoke` | `Client.JWKS`; sig via `AsymmetricJWSAlgs` | `server_extensions.go` |
| RFC 9207 AS Issuer Id | every `/auth/login` | always | `handlers.go` |
| RFC 9068 JWT Access Token | JWT access tokens | always; alg gate `WithSupportedSigningAlgs` | `defaultimpl/{ed25519,ecdsa,rsa}_jwt_issuer.go` |
| RFC 8705 mTLS-bound + aliases | `/token` + `/userinfo` | `WithClientCertExtractor` | `server_extensions.go` |
| RFC 9470 Step-Up | resource-server helper | always | `security/step_up_auth.go` |
| RFC 9449 DPoP | `/token` + `/userinfo` | header-triggered; replay: `WithJTIReplayStore`; nonce: `WithDPoPNonceProvider` | `server_extensions.go` |
| RFC 8414 §2.1 signed_metadata | discovery | `WithMetadataSigner` | `handlers.go` |
| OAuth 2.1 strict | `/auth/login` | `WithOAuth21StrictMode` | `handler.go` |
| FAPI 2.0 profile | `/auth/login` + `/token` + discovery | `WithFAPIProfile(Inspection\|Enforce)` | `fapi/` + `handler.go` |
| RFC 9396 RAR | `authorization_details` | per-client allowlist | `oauth/rar.go` |
| RFC 9101 JAR | `request`, `request_uri` | `Client.JWKS`; URL fetch: `WithJARFetcher`; required: `Client.RequireSignedRequestObject` | `server_extensions.go` + `security/jar_fetch.go` |
| RFC 9101 §6.4 JWE JAR | `request` (JWE) | `WithJARDecrypter`; enc key in JWKS `use:enc` | `security/jwe.go` |
| OIDC §10.2 id_token JWE | `id_token` (encrypted) | `WithJWEResponseEncrypter` + per-client `IDTokenEncryptedResponseAlg/_Enc` | `oidc/userinfo_signing.go` |
| OIDC §5.3.2 userinfo JWE | `/userinfo` (encrypted) | `WithJWEResponseEncrypter` + per-client `UserinfoEncryptedResponseAlg/_Enc` | `oidc/userinfo_signing.go` |
| OIDC CIBA (poll+ping) | `/backchannel-authentication`, `/token` | `WithCIBA`; ping: `WithCIBAPingNotifier` | `oauth/ciba.go` + `oauth/handle_ciba.go` |
| MFA orchestration | `/auth/login` + `/auth/mfa` | `WithMFAProvider` + `WithMFAChallengeStore` | `handlers.go` + `spi/mfa.go` |
| Per-account lockout | `/auth/login` | `WithAccountLockout` | `security/account_lockout.go` |
| SPIFFE JWT-SVID token-exchange | `/token` | `WithSPIFFEJWTSVID(trustDomain, audience, JWKSSource)` | `security/spiffe_svid.go` |
| OpenID SSF v1 SET transmitter | push to RP receiver | `WithCAEPTransmitter` | `caep/` |
| OpenID SSF v1 SET receiver | `/ssf/receive` | `WithCAEPReceiver` | `caep/receiver.go` |
| Envoy ext_authz HTTP | `/mesh/ext-authz` | `WithMeshExtAuthz(path)` | `handler.go` + `mesh_authz.go` |
| Envoy ext_authz gRPC | `envoy.service.auth.v3.Authorization` | `extauthz` nested module | `extauthz/authz.go` |
| SAML 2.0 SP+IdP | `/auth/saml/*`, `/saml/*` | `saml` nested module | `saml/saml.go` |
| Kerberos/SPNEGO | `/auth/kerberos` | `kerberos` nested module | `kerberos/handler.go` |
| RADIUS authenticator | via `WithAuthenticator` | `radius` nested module | `radius/authenticator.go` |
| WebAuthn attestation policy | `/webauthn/registration/finish` | `webauthn.Config.{AttestationConveyance,AttestationPolicy,MDS}` | `authenticators/webauthn/` |
| Multi-region data residency | `/auth/login` + `/userinfo` + mesh + WebAuthn | `WithRegionMiddleware` + `WithTenantResidencyCheck` | `region/region.go` + `server_extensions.go` |
| SCIM 2.0 | `/api/v1/scim/v2/` | `scim.NewHandler(users, basePath, ...)` | `scim/handler.go` |
| OpenID Federation 1.0 (5 slices) | `/.well-known/openid-federation`, `/fetch` | `WithFederationEntity(cfg, signer)` | `federation/` + `handlers.go` + `sso.go` |
