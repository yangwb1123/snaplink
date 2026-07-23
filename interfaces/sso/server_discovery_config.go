package sso

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/security"
)

func codeChallengeMethodsFor(s *Server) []string {
	return oidc.CodeChallengeMethodsFor(s.oauth21Strict)
}

func responseTypesFor(s *Server) []string {
	return oidc.ResponseTypesFor(s.oauth21Strict)
}

func subjectTypesFor(s *Server) []string {
	return oidc.SubjectTypesFor(s.pairwiseStore != nil)
}

// signDiscoveryMetadata marshals cfg, clears SignedMetadata, re-parses as a
// claim map, and asks the oidc.MetadataSigner to JWS it (RFC 8414 §2.1).
func (s *Server) signDiscoveryMetadata(ctx context.Context, cfg *oidc.ProviderMetadata) (string, error) {
	if s.metadataSigner == nil {
		return "", nil
	}
	saved := cfg.SignedMetadata
	cfg.SignedMetadata = ""
	defer func() { cfg.SignedMetadata = saved }()
	raw, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return "", err
	}
	return s.metadataSigner.SignMetadata(ctx, claims)
}

// Both `require_signed_request_object` (RFC 9101 §10.5) and
// `require_pushed_authorization_requests` (RFC 9126 §5) derive from
// scanning the client store. They share a cached clientDiscoverySnapshot
// so a single iteration powers every derivation across one request.

// handleOIDCDiscovery serves the OpenID Connect Discovery 1.0 +
// RFC 8414 metadata document. Always wired by Mount (no opt-in
// option) — relying parties expect this endpoint at a fixed URL
// per the spec.
//
// Absolute URLs are derived from the incoming request (scheme +
// host) so the same SSO server can be advertised under multiple
// hostnames without a per-deployment base-URL configuration knob.
// Operators behind a TLS-terminating proxy MUST forward
// X-Forwarded-Proto so the discovery endpoint advertises https,
// not http — otherwise OIDC RPs refuse the issuer per §4.3.
func (s *Server) handleOIDCDiscovery(ctx HandlerContext) {
	base := requestBaseURL(ctx.Request())
	// Body cache: skip the marshal + struct assembly when a recent
	// rendering for this base URL is still fresh. Keyed by base URL
	// so multi-host SSO doesn't conflate. Honors If-None-Match so
	// well-behaved RP libraries can short-circuit to 304.
	if s.discoveryDocCacheTTL > 0 {
		if entry := s.lookupDiscoveryDocCache(base); entry != nil {
			s.writeDiscoveryDoc(ctx, entry)
			return
		}
	}
	cfg := s.buildOIDCConfiguration(ctx, base)

	// ttl <= 0 disables both in-process caching AND the response-side
	// ETag / Cache-Control headers — every request renders fresh and
	// downstream caches (CDN, RP libraries) are told not to cache.
	if s.discoveryDocCacheTTL <= 0 {
		ctx.JSON(http.StatusOK, cfg)
		return
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		s.logger.Error("discovery marshal failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrInternal))
		return
	}
	entry := buildDiscoveryDocEntry(body, s.discoveryDocCacheTTL)
	s.storeDiscoveryDocCache(base, entry)
	s.writeDiscoveryDoc(ctx, entry)
}

// buildOIDCConfiguration assembles the fully-finalized OpenID Connect
// Discovery 1.0 + RFC 8414 metadata struct for the given request base URL
// — every derived field plus the RFC 8414 §2.1 signed_metadata. Extracted
// from handleOIDCDiscovery (behavior-preserving) so the federation entity
// configuration can DERIVE its openid_provider metadata from the SAME
// projection (see BuildOPMetadata) instead of hand-duplicating the
// derivation, which would risk the two metadata views drifting apart. The
// output is byte-identical to the previous inline assembly — the existing
// discovery + signed_metadata tests are the proof.
func (s *Server) buildOIDCConfiguration(ctx HandlerContext, base string) oidc.ProviderMetadata {
	// Single client-store iteration powers every derived field below
	// (scopes union, RequirePAR-any, RequireSignedRequestObject-all,
	// frontchannel_logout_supported, authorization_details types
	// union). TTL-cached across requests so a hot RP polling the
	// discovery doc doesn't pay 5× ClientStore.List per call.
	clientSnap := s.discoverySnapshot(ctx.Request().Context())
	cfg := buildBaseMetadata(s, base)
	s.applyClientAuthAndRequestParams(&cfg)
	s.applyEncryptionMetadata(&cfg)
	s.applyMFAIssuerSigning(&cfg, ctx, base)
	s.applyGrantEndpoints(&cfg, base, clientSnap)
	s.applyLogoutMetadata(&cfg, clientSnap)
	s.applyStaticClaimsAndSecurity(&cfg, clientSnap)
	s.applyEndpointAuthSigningAlgs(&cfg)
	s.applyResponseModesAndProfiles(&cfg, ctx)
	s.applyIntrospectionSigningMetadata(&cfg, ctx.Request().Context())
	// RFC 8414 §2.1 signed_metadata MUST be produced AFTER every
	// other field is finalized so the signed claims match what RPs
	// see in the plaintext fields. The signing itself excludes the
	// signed_metadata field (chicken-and-egg) — claims are sourced
	// from the cfg struct via json round-trip.
	if s.metadataSigner != nil {
		if jws, err := s.signDiscoveryMetadata(ctx.Request().Context(), &cfg); err != nil {
			s.logger.Error("signed_metadata generation failed", "error", err)
		} else {
			cfg.SignedMetadata = jws
		}
	}
	return cfg
}

// buildBaseMetadata seeds the always-present identity, endpoint, and core
// capability fields. The conditional + derived fields are layered on by the
// apply* helpers in buildOIDCConfiguration, in the same order as the original
// inline assembly so the output stays byte-identical.
// baseAdvertisedGrants is the set of grant types ALWAYS advertised in
// discovery, independent of optional store wiring. device_code and CIBA are
// conditionally appended in applyGrantEndpoints only when their store is wired
// (RFC 8414 §2: advertise only what is actually supported — /device/* and the
// device token grant return 501 when WithDeviceCodeStore is omitted). This is
// deliberately NARROWER than core.SupportedGrants, which stays the full
// recognized set for unsupported_grant_type errors.
func baseAdvertisedGrants() []string {
	return []string{
		GrantAuthorizationCode,
		GrantRefreshToken,
		GrantClientCredentials,
		GrantTokenExchange,
	}
}

func buildBaseMetadata(s *Server, base string) oidc.ProviderMetadata {
	cfg := oidc.ProviderMetadata{
		Issuer:                        base,
		AuthorizationEndpoint:         base + PathLogin,
		TokenEndpoint:                 base + PathToken,
		JWKSURI:                       base + PathJWKS,
		RevocationEndpoint:            base + PathRevoke,
		IntrospectionEndpoint:         base + PathIntrospect,
		ResponseTypesSupported:        responseTypesFor(s),
		GrantTypesSupported:           baseAdvertisedGrants(),
		SubjectTypesSupported:         subjectTypesFor(s),
		CodeChallengeMethodsSupported: codeChallengeMethodsFor(s),
	}
	// userinfo_endpoint / end_session_endpoint are both omitempty — branch
	// the doc (rather than always setting them) so an OIDC-gated-off
	// deployment's discovery document matches its actually-mounted routes
	// (mountOIDCUserEndpoints skips both when the gate is off).
	if s.oidcGateOn() {
		cfg.UserInfoEndpoint = base + PathUserInfo
		cfg.EndSessionEndpoint = base + PathEndSession
		if s.sessionManagementEnabled {
			cfg.CheckSessionIframe = base + PathCheckSessionIframe
		}
	}
	return cfg
}

// applyClientAuthAndRequestParams advertises the client-authentication methods
// accepted on /token, /introspect, /revoke plus the JAR request-parameter
// capabilities. These values are constant for a given build.
func (s *Server) applyClientAuthAndRequestParams(cfg *oidc.ProviderMetadata) {
	cfg.TokenEndpointAuthMethodsSupported = []string{
		"client_secret_basic",
		"client_secret_post",
		"private_key_jwt", // RFC 7521 + 7523
		// RFC 8705 §2 — mTLS client certificate authentication.
		// tls_client_auth = server verifies the client cert's subject
		// DN or SAN against the registered TLSClientAuth* fields;
		// self_signed_tls = the client presents a self-signed cert
		// whose public key matches a registered JWK. Both are
		// accepted by DCR (dcr_validate.go) and verified in the token
		// handler's authenticateTokenClient path.
		"tls_client_auth",
		"self_signed_tls",
		// RFC 6749 §2.1 / OIDC Core §9 — public clients (SPAs,
		// native apps) authenticate only by client_id + PKCE,
		// so `none` is the spec-defined method for them. DCR
		// already accepts it (handle_register.go), so advertise
		// it here so RP libraries don't reject the AS during
		// metadata validation.
		"none",
	}
	// Introspection + revocation share the same client-auth
	// pipeline as /token, so advertise the same list.
	cfg.IntrospectionEndpointAuthMethodsSupported = []string{
		"client_secret_basic", "client_secret_post", "private_key_jwt",
		"tls_client_auth", "self_signed_tls",
	}
	cfg.RevocationEndpointAuthMethodsSupported = []string{
		"client_secret_basic", "client_secret_post", "private_key_jwt",
		"tls_client_auth", "self_signed_tls",
	}
	// RFC 9207 §3: this server always includes `iss` in
	// authorization responses (see handleLogin + resolveIssuer).
	cfg.AuthorizationResponseIssParameterSupported = true
	// RFC 9101 §10.5: JAR `request` parameter accepted; URL
	// fetched `request_uri` flips true when WithJARFetcher is
	// wired (applyEncryptionMetadata).
	cfg.RequestParameterSupported = true
	cfg.RequestURIParameterSupported = false
	// JAR request objects (RFC 9101) verify through
	// security.VerifyCompactJWS, which accepts the full asymmetric
	// allowlist — advertise exactly what is accepted on the wire so
	// RP metadata validation reflects reality.
	cfg.RequestObjectSigningAlgValuesSupported = security.AsymmetricJWSAlgValues()
	cfg.ClaimsParameterSupported = true
}

// applyEncryptionMetadata advertises JAR request-object encryption (when a
// decrypter is wired), response-direction JWE for id_token/userinfo (when an
// encrypter is wired), and flips request_uri support when a JAR fetcher is set.
func (s *Server) applyEncryptionMetadata(cfg *oidc.ProviderMetadata) {
	if s.jarFetcher != nil {
		cfg.RequestURIParameterSupported = true
	}
	if s.jarDecrypter != nil {
		// Advertising the alg + enc lists tells RPs which JWE shapes
		// the AS will accept on the `request` parameter. RPs that don't
		// see these fields know to fall back to plain JWS JAR (which
		// is always accepted).
		cfg.RequestObjectEncryptionAlgValuesSupported = s.jarDecrypter.SupportedAlgs()
		cfg.RequestObjectEncryptionEncValuesSupported = s.jarDecrypter.SupportedEncs()
	}
	if s.jweResponseEncrypter != nil {
		// Response-direction JWE: advertise the alg + enc the AS can
		// produce so RPs register a matching id_token / userinfo
		// encrypted_response_alg + _enc (and publish a use:enc JWKS key).
		algs := s.jweResponseEncrypter.SupportedAlgs()
		encs := s.jweResponseEncrypter.SupportedEncs()
		cfg.IDTokenEncryptionAlgValuesSupported = algs
		cfg.IDTokenEncryptionEncValuesSupported = encs
		cfg.UserinfoEncryptionAlgValuesSupported = algs
		cfg.UserinfoEncryptionEncValuesSupported = encs
	}
}

// applyMFAIssuerSigning advertises MFA orchestration (Provider+Store both
// wired), honors a WithIssuer override, and derives the id_token/userinfo
// signing algs from the wired signers.
func (s *Server) applyMFAIssuerSigning(cfg *oidc.ProviderMetadata, ctx HandlerContext, base string) {
	// MFA orchestration is advertised only when both Provider + Store
	// are wired — having Provider without Store would be a misconfig
	// (handleMFAComplete returns 404 in that state) so we don't leak
	// the endpoint into discovery either.
	if s.mfaProvider != nil && s.mfaChallengeStore != nil {
		cfg.MFAEndpoint = base + PathMFAComplete
		cfg.MFAMethodsSupported = s.mfaProvider.SupportedMethods()
	}
	// When the operator overrode the issuer name with WithIssuer, prefer
	// that — many production deployments set issuer to the canonical
	// public URL even when the SSO server is internally reachable at a
	// different host.
	if s.issuer != "" && s.issuer != DefaultIssuer {
		cfg.Issuer = s.issuer
	}
	// Signing algs are derived from the wired signers (EdDSA for an
	// Ed25519JWTIssuer, ES256 for an ECDSAJWTIssuer, both in a mixed
	// deployment) or pinned by WithSupportedSigningAlgs. See
	// (*Server).SigningAlgValues.
	signingAlgs := s.SigningAlgValues(ctx.Request().Context())
	if s.idTokenIssuer != nil {
		cfg.IDTokenSigningAlgValuesSupported = signingAlgs
		// Userinfo signing capability is gated on the issuer
		// implementing the oidc.UserinfoSigner extension. The default
		// Ed25519JWTIssuer does — third-party implementations may
		// not, and the omitempty serialization correctly hides the
		// claim in that case.
		if _, ok := s.idTokenIssuer.(oidc.UserinfoSigner); ok {
			cfg.UserinfoSigningAlgValuesSupported = signingAlgs
		}
	}
}

// applyCIBABackchannel advertises the OIDC CIBA Core 1.0 §4 backchannel
// endpoint + delivery modes only when CIBA is wired (opt-in). Poll is always
// available; ping/push are added when their respective notifier is wired
// (WithCIBAPingNotifier / WithCIBAPushNotifier — modes built by
// cibaDeliveryModes, accessors_feature_gates.go, to stay under this file's
// maintainability line budget). Poll mode resolves the user from
// login_hint/id_token_hint rather than a user_code, so the user_code
// parameter is unsupported.
func (s *Server) applyCIBABackchannel(cfg *oidc.ProviderMetadata, base string) {
	if s.cibaStore == nil || !s.cibaGateOn() {
		return
	}
	cfg.BackchannelAuthenticationEndpoint = base + PathBackchannelAuth
	cfg.BackchannelTokenDeliveryModesSupported = s.cibaDeliveryModes()
	cfg.BackchannelUserCodeParameterSupported = false
	cfg.GrantTypesSupported = append(cfg.GrantTypesSupported, GrantCIBA)
}

// applyGrantEndpoints advertises the CIBA (see applyCIBABackchannel), PAR,
// and dynamic-registration endpoints (each opt-in) plus the client-derived
// scopes_supported and authorization_details_types_supported unions.
func (s *Server) applyGrantEndpoints(cfg *oidc.ProviderMetadata, base string, clientSnap *clientDiscoverySnapshot) {
	if s.deviceCodeStore != nil {
		// RFC 8414 §2 + RFC 8628: advertise the device grant only when a
		// device code store is wired. Without WithDeviceCodeStore the
		// device token grant returns 501, so advertising it unconditionally
		// would mislead a discovery client into attempting an unsupported
		// flow. SupportedGrants still lists it for unsupported_grant_type.
		cfg.GrantTypesSupported = append(cfg.GrantTypesSupported, GrantDeviceCode)
	}
	s.applyCIBABackchannel(cfg, base)
	if s.parStore != nil {
		// RFC 9126 §5: advertise the PAR endpoint so RPs that prefer
		// the pushed-request flow can discover it. The server-wide
		// `require_pushed_authorization_requests` discovery flag is
		// flipped when ANY registered client has RequirePAR=true —
		// matches the OIDC convention where a discovery boolean
		// reflects "is this supported anywhere".
		cfg.PushedAuthReqEndpoint = base + PathPAR
		cfg.PushedAuthorizationRequestEndpointAuthMethodsSupported = []string{
			"client_secret_basic", "client_secret_post", "private_key_jwt",
			"tls_client_auth", "self_signed_tls",
		}
		if clientSnap.requirePAR {
			cfg.RequirePushedAuthReq = true
		}
	}
	if s.dcrPolicy != nil {
		// RFC 7591 §3: advertise the registration endpoint so
		// dynamic clients can discover it. The initial access
		// token (when required) is distributed out-of-band, not
		// via discovery.
		cfg.RegistrationEndpoint = base + oauth.PathRegister
	}
	if len(clientSnap.scopes) > 0 {
		cfg.ScopesSupported = clientSnap.scopes
	}
	if len(clientSnap.authorizationDetailTypes) > 0 {
		cfg.AuthorizationDetailsTypesSupported = clientSnap.authorizationDetailTypes
	}
}

// applyLogoutMetadata advertises back/front-channel logout, each gated on its
// wiring (and the per-client frontchannel snapshot flag).
func (s *Server) applyLogoutMetadata(cfg *oidc.ProviderMetadata, clientSnap *clientDiscoverySnapshot) {
	if s.logoutTokenIssuer != nil && s.logoutNotifier != nil {
		cfg.BackchannelLogoutSupported = true
		if s.sessionMgr != nil {
			cfg.BackchannelLogoutSessionSupported = true
		}
	}
	if clientSnap.frontchannelLogout {
		cfg.FrontchannelLogoutSupported = true
		if s.sessionMgr != nil {
			cfg.FrontchannelLogoutSessionSupported = true
		}
	}
}

// applyStaticClaimsAndSecurity sets the static claim list, the unconditional
// DPoP advertisement, the mTLS-bound-token aliases (when a cert extractor is
// wired), ACR values, policy/ToS URIs, and the client-derived
// require_signed_request_object_global flag.
func (s *Server) applyStaticClaimsAndSecurity(cfg *oidc.ProviderMetadata, clientSnap *clientDiscoverySnapshot) {
	cfg.ClaimsSupported = []string{
		"sub", "iss", "aud", "exp", "iat", "nbf", "scope",
		"nonce", "auth_time", "amr", "acr", "azp",
	}
	// DPoP advertisement is unconditional — the handler accepts
	// the `DPoP` header on /token whenever it's present; there's
	// no opt-in store to wire. DPoP proofs verify through
	// security.VerifyCompactJWS, so advertise the full asymmetric
	// allowlist (DPoP clients are almost always ES256).
	cfg.DPoPSigningAlgValuesSupported = security.AsymmetricJWSAlgValues()
	if s.clientCertExtractor != nil {
		cfg.TLSClientCertificateBoundAccessTokens = true
		cfg.MTLSEndpointAliases = &oidc.MTLSEndpointAliases{
			TokenEndpoint:         cfg.TokenEndpoint,
			RevocationEndpoint:    cfg.RevocationEndpoint,
			IntrospectionEndpoint: cfg.IntrospectionEndpoint,
			UserInfoEndpoint:      cfg.UserInfoEndpoint,
			RegistrationEndpoint:  cfg.RegistrationEndpoint,
			PushedAuthReqEndpoint: cfg.PushedAuthReqEndpoint,
		}
	}
	if len(s.supportedACRValues) > 0 {
		cfg.ACRValuesSupported = append([]string(nil), s.supportedACRValues...)
	}
	cfg.OpPolicyURI = s.opPolicyURI
	cfg.OpTosURI = s.opTosURI
	cfg.ServiceDocumentation = s.serviceDocumentation
	cfg.ClaimTypesSupported = []string{"normal"}
	cfg.DisplayValuesSupported = []string{"page"}
	if clientSnap.requireSignedRequestObject {
		cfg.RequireSignedRequestObjectGlobal = true
	}
}

// applyEndpointAuthSigningAlgs advertises the private_key_jwt (RFC 7523)
// client-assertion signing algs accepted on each client-auth endpoint — the
// full asymmetric allowlist, since they all verify through VerifyCompactJWS.
func (s *Server) applyEndpointAuthSigningAlgs(cfg *oidc.ProviderMetadata) {
	authAlgs := security.AsymmetricJWSAlgValues()
	cfg.TokenEndpointAuthSigningAlgValuesSupported = authAlgs
	cfg.IntrospectionEndpointAuthSigningAlgValuesSupported = authAlgs
	cfg.RevocationEndpointAuthSigningAlgValuesSupported = authAlgs
	if s.parStore != nil {
		cfg.PushedAuthorizationRequestEndpointAuthSigningAlgValuesSupported = authAlgs
	}
}

// applyResponseModesAndProfiles advertises the supported prompt + response
// modes (adding the JARM jwt modes when a JARM signer is wired) and applies the
// FAPI 2.0 enforce-mode hard requirements LAST so they override any earlier
// advertisement.
func (s *Server) applyResponseModesAndProfiles(cfg *oidc.ProviderMetadata, ctx HandlerContext) {
	// OIDC Core §3.1.2.1 — advertise "none" so SPAs know they can
	// run silent renewal via id_token_hint. Also advertise consent
	// when a ConsentStore is wired (server-side consent gates exist).
	// The login and select_account prompts aren't surfaced because
	// the RP drives the interactive flow; the server authenticates
	// on demand.
	prompts := []string{PromptNone}
	if s.consentStore != nil {
		prompts = append(prompts, PromptConsent)
	}
	cfg.PromptValuesSupported = prompts

	// Form Post Response Mode 1.0: every shape this server can
	// emit. `form_post` is the value-add (auto-POST HTML page);
	// query + fragment are advertised for spec completeness so
	// RPs that introspect discovery know they're accepted on
	// the wire.
	cfg.ResponseModesSupported = []string{
		ResponseModeQuery, ResponseModeFragment, ResponseModeFormPost,
	}

	// JARM — advertise the jwt response modes + the signing alg when wired.
	if s.jarmSigner != nil {
		cfg.ResponseModesSupported = append(cfg.ResponseModesSupported,
			oidc.ResponseModeJWT, oidc.ResponseModeQueryJWT,
			oidc.ResponseModeFragmentJWT, oidc.ResponseModeFormPostJWT,
		)
		cfg.AuthorizationSigningAlgValuesSupported = s.SigningAlgValues(ctx.Request().Context())
	}

	// FAPI 2.0 enforce mode narrows discovery constraints server-wide.
	s.applyFAPIEnforceDiscovery(cfg)
}

// applyFAPIEnforceDiscovery narrows the discovery doc when FAPI enforce mode
// is active: only ECDSA/EdDSA signing algs, only private_key_jwt/tls_client_auth.
func (s *Server) applyFAPIEnforceDiscovery(cfg *oidc.ProviderMetadata) {
	if !s.fapiValidator.Enforcing() {
		return
	}
	cfg.RequirePushedAuthReq = true
	cfg.RequireSignedRequestObjectGlobal = true
	cfg.ResponseTypesSupported = []string{"code"}
	cfg.CodeChallengeMethodsSupported = []string{PKCEMethodS256}
	cfg.IDTokenSigningAlgValuesSupported = s.fapiValidator.AllowedAlgValues(cfg.IDTokenSigningAlgValuesSupported)
	cfg.UserinfoSigningAlgValuesSupported = s.fapiValidator.AllowedAlgValues(cfg.UserinfoSigningAlgValuesSupported)
	cfg.RequestObjectSigningAlgValuesSupported = s.fapiValidator.AllowedAlgValues(cfg.RequestObjectSigningAlgValuesSupported)
	cfg.AuthorizationSigningAlgValuesSupported = s.fapiValidator.AllowedAlgValues(cfg.AuthorizationSigningAlgValuesSupported)
	cfg.TokenEndpointAuthSigningAlgValuesSupported = s.fapiValidator.AllowedAlgValues(cfg.TokenEndpointAuthSigningAlgValuesSupported)
	cfg.IntrospectionEndpointAuthSigningAlgValuesSupported = s.fapiValidator.AllowedAlgValues(cfg.IntrospectionEndpointAuthSigningAlgValuesSupported)
	cfg.RevocationEndpointAuthSigningAlgValuesSupported = s.fapiValidator.AllowedAlgValues(cfg.RevocationEndpointAuthSigningAlgValuesSupported)
	if len(cfg.PushedAuthorizationRequestEndpointAuthSigningAlgValuesSupported) > 0 {
		cfg.PushedAuthorizationRequestEndpointAuthSigningAlgValuesSupported = s.fapiValidator.AllowedAlgValues(cfg.PushedAuthorizationRequestEndpointAuthSigningAlgValuesSupported)
	}
	cfg.TokenEndpointAuthMethodsSupported = s.fapiValidator.AllowedClientAuthMethods(cfg.TokenEndpointAuthMethodsSupported)
}

// BuildOPMetadata projects the openid_provider metadata for the OpenID
// Federation 1.0 entity configuration (federation.Deps). It DERIVES from the
// same buildOIDCConfiguration projection the /.well-known/openid-configuration
// discovery doc uses — taking only the federation-relevant subset (OpenID
// Federation 1.0 §4.5: federation OP metadata is OIDC OP metadata) — so the
// federation view can never drift from the discovery view. signed_metadata
// (an RFC 8414 field of the discovery doc) is deliberately NOT carried: the
// Entity Statement is itself a signed JWS, so the discovery-doc signature is
// redundant inside it.
// BuildOPMetadata, handleFederationEntityConfig, handleFederationFetch,
// and requestBaseURL were extracted to federation_handler.go.
