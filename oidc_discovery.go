package sso

import "github.com/snaplink/sso/oauth"

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// PathOIDCDiscovery is the OpenID Connect Discovery 1.0 metadata
// endpoint (also the de-facto location for RFC 8414 OAuth 2.0
// Authorization Server Metadata since most ecosystems collapsed them).
const PathOIDCDiscovery = "/.well-known/openid-configuration"

// oidcConfiguration mirrors OpenID Connect Discovery 1.0 §3 +
// RFC 8414 §2 fields. Optional fields are omitempty so the wire stays
// minimal — relying parties branch on presence per the spec.
type oidcConfiguration struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint,omitempty"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint,omitempty"`
	RevocationEndpoint    string `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
	RegistrationEndpoint  string `json:"registration_endpoint,omitempty"`
	PushedAuthReqEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
	RequirePushedAuthReq  bool   `json:"require_pushed_authorization_requests,omitempty"`
	// RFC 9101 §10.5 — true when every registered client enforces
	// signed request objects (RequireSignedRequestObject=true on
	// the Client). Advertised AS-wide because the spec field is
	// boolean (no per-client surface in discovery). Stays false
	// when any client still accepts unsigned authorization
	// requests — matching the strictest-possible-promise semantics
	// the field implies.
	RequireSignedRequestObjectGlobal  bool     `json:"require_signed_request_object,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`

	// RFC 8414 §2 + RFC 7662 §6: same set of client auth methods
	// the introspection endpoint accepts. The /token + /par +
	// /introspect + /revoke endpoints all share the same auth
	// pipeline in this server, so we advertise the same list on
	// each.
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	// RFC 8414 §2 + RFC 7009 §4.1.2: same set for the revocation
	// endpoint.
	RevocationEndpointAuthMethodsSupported []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	// RFC 9126 §5: client auth methods accepted on /par. Mirrors
	// the /token list since /par shares the same auth pipeline.
	PushedAuthorizationRequestEndpointAuthMethodsSupported []string `json:"pushed_authorization_request_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported                          []string `json:"code_challenge_methods_supported,omitempty"`
	ClaimsSupported                                        []string `json:"claims_supported,omitempty"`

	// RFC 9207 §3 — when true, this AS includes `iss` on every
	// authorization response (success + error). Constant true here
	// because handleLogin unconditionally stamps it via
	// authzErrorBody / resolveIssuer.
	AuthorizationResponseIssParameterSupported bool `json:"authorization_response_iss_parameter_supported"`

	// RFC 9396 §13 — the union of every registered client's
	// AllowedAuthorizationDetailsTypes. Empty / omitted when no
	// client has declared a type allowlist (the parameter is
	// still accepted but unconstrained).
	AuthorizationDetailsTypesSupported []string `json:"authorization_details_types_supported,omitempty"`

	// OIDC Back-Channel Logout 1.0 §2.1 — true when this server
	// will POST logout tokens to RPs' backchannel_logout_uri
	// endpoints. Set when both LogoutTokenIssuer + LogoutNotifier
	// are wired via WithBackchannelLogout.
	BackchannelLogoutSupported bool `json:"backchannel_logout_supported,omitempty"`
	// BackchannelLogoutSessionSupported flips true when the AS
	// stamps `sid` in access + ID tokens — that is, when a
	// SessionManager is wired. Without a session manager every
	// token has empty sid, so advertising session support would
	// be a lie. With one wired, /end_session reads the sid from
	// the id_token_hint and forwards it on logout_tokens, letting
	// RPs invalidate the specific session rather than every
	// session for the subject.
	BackchannelLogoutSessionSupported bool `json:"backchannel_logout_session_supported,omitempty"`

	// OIDC Front-Channel Logout 1.0 §2.1 — true when at least one
	// registered client opts in via FrontchannelLogoutURI. The
	// server's /end_session handler then renders an HTML iframe
	// page instead of the bare 302/204 response. Per-client
	// metadata (the URI itself) is not advertised in discovery;
	// it's pre-registered out-of-band like every other client
	// secret.
	FrontchannelLogoutSupported bool `json:"frontchannel_logout_supported,omitempty"`
	// FrontchannelLogoutSessionSupported mirrors the back-channel
	// flag — true when SessionManager is wired so id_tokens
	// carry a sid claim the RP can correlate to its local
	// session at logout time.
	FrontchannelLogoutSessionSupported bool `json:"frontchannel_logout_session_supported,omitempty"`

	// OIDC Core §3.1.2.1 — the prompt values this AS understands.
	// "none" enables silent renewal via id_token_hint; the others
	// are accepted but currently lower the request to its default
	// interactive path (login/consent/select_account UIs aren't
	// rendered by this server, only their downstream signaling).
	PromptValuesSupported []string `json:"prompt_values_supported,omitempty"`

	// OIDC Core §3.1.2.1 + Form Post Response Mode 1.0 — the
	// response delivery modes this AS supports for authorization
	// responses. `form_post` triggers the HTML auto-POST page;
	// `query` / `fragment` are accepted but currently just
	// influence the response shape the RP's own JS handles
	// (this server is JSON-bodied for /auth/login by default).
	ResponseModesSupported []string `json:"response_modes_supported,omitempty"`

	// OIDC Core §5.5 — true when the AS accepts the `claims`
	// request parameter. Always true here (the parameter is
	// validated for JSON-object shape and threaded into
	// AuthRequest.RequestedClaims; authenticators / issuers that
	// honor it project the requested claims into output).
	ClaimsParameterSupported bool `json:"claims_parameter_supported"`

	// OIDC Core §5.3.2 — JWS algs supported for signing /userinfo
	// responses when the client's `userinfo_signed_response_alg`
	// metadata is set. Empty / omitted = signed userinfo not
	// available (the IDTokenIssuer doesn't implement UserinfoSigner).
	UserinfoSigningAlgValuesSupported []string `json:"userinfo_signing_alg_values_supported,omitempty"`

	// RFC 9449 §5.1 — JWS algs accepted on the DPoP proof
	// header. Always EdDSA today (matches every other JWT path
	// on this server). Presence of the field signals the AS
	// supports DPoP at all.
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`

	// RFC 8705 §3.3 — true when the AS supports issuing tokens
	// bound to mTLS client certificates. Flipped when
	// WithClientCertExtractor is wired.
	TLSClientCertificateBoundAccessTokens bool `json:"tls_client_certificate_bound_access_tokens,omitempty"`

	// RFC 8705 §5 — when the AS terminates mTLS on a different
	// hostname / port than the standard endpoints (typical edge:
	// `auth.example.com` for bearer flows, `mtls.example.com` for
	// cert-authenticated flows), publish the alternates here.
	// RPs that need cert-bound issuance route to the alias; plain
	// bearer continues hitting the regular endpoints. This server
	// publishes the same endpoint URLs on both sides today (the
	// HTTPS server accepts certs on every endpoint), so RPs see
	// identical hostnames but the field's presence signals "mTLS
	// is operationally available." Operators with split-hostname
	// terminations override via deploy-side proxy rewriting.
	MTLSEndpointAliases *MTLSEndpointAliases `json:"mtls_endpoint_aliases,omitempty"`

	// OIDC Discovery §3 `acr_values_supported`. Populated from
	// the operator-declared `WithSupportedACRValues` — empty /
	// omitted when no list is configured. RPs branching on ACR
	// (step-up auth, FAPI 2.0) use this to validate what they
	// can request from the AS.
	ACRValuesSupported []string `json:"acr_values_supported,omitempty"`

	// OIDC Discovery §3 operator metadata. Pointed at by RPs
	// during consent ("by signing in you accept ..." linking to
	// op_policy_uri / op_tos_uri) and used by integrators looking
	// up the AS's own SDK reference (service_documentation).
	// Populated via `WithOperatorMetadata`; omitted when unset.
	OpPolicyURI          string `json:"op_policy_uri,omitempty"`
	OpTosURI             string `json:"op_tos_uri,omitempty"`
	ServiceDocumentation string `json:"service_documentation,omitempty"`

	// OIDC Discovery §3 `claim_types_supported`. RPs introspect
	// what claim shapes the AS emits — "normal" (claims are
	// inline in the id_token / userinfo response), "aggregated"
	// (claims arrive as a JWT inside the response), "distributed"
	// (claims at a fetchable URL). This server only emits the
	// inline normal form; advertised as ["normal"] for spec
	// completeness so OIDC conformance suites pass without
	// inferring the default.
	ClaimTypesSupported []string `json:"claim_types_supported,omitempty"`

	// OIDC Core §3.1.2.1 `display` parameter — values RPs may pass
	// to hint the auth UI form factor (page / popup / touch / wap).
	// This server renders no chrome itself (authenticators own the
	// UI), but advertises "page" — the spec default — so OIDC
	// conformance suites don't have to infer it. RPs requesting
	// other values get the same default path; the parameter is
	// accepted on the wire without being acted on.
	DisplayValuesSupported []string `json:"display_values_supported,omitempty"`

	// OIDC Core §9 — JWS algorithms the AS accepts on the
	// `client_assertion` JWT for `private_key_jwt` client
	// authentication. RPs introspect this to know which alg to
	// sign their assertion with. Matches the same EdDSA-only
	// surface JAR + DPoP advertise.
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`

	// Same JWS algorithm advertisement for the introspect /
	// revoke / PAR endpoints — all share the JWT-assertion path
	// so they accept the same alg set.
	IntrospectionEndpointAuthSigningAlgValuesSupported              []string `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	RevocationEndpointAuthSigningAlgValuesSupported                 []string `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	PushedAuthorizationRequestEndpointAuthSigningAlgValuesSupported []string `json:"pushed_authorization_request_endpoint_auth_signing_alg_values_supported,omitempty"`

	// RFC 9101 §10.5 — true when the `request` parameter is
	// accepted on /auth/login. Always true here.
	RequestParameterSupported bool `json:"request_parameter_supported"`
	// RequestURIParameterSupported reflects whether the AS accepts
	// `request_uri` as an HTTPS URL it will fetch (RFC 9101 §5.2.2)
	// — flipped true when `WithJARFetcher` is wired. The PAR
	// `urn:ietf:params:oauth:request_uri:` prefix is ALWAYS accepted
	// when a oauth.PARStore is wired (advertised separately via
	// pushed_authorization_request_endpoint).
	RequestURIParameterSupported bool `json:"request_uri_parameter_supported"`
	// RequestObjectSigningAlgValuesSupported lists the alg values
	// the JAR verifier accepts on the request JWT. EdDSA today.
	RequestObjectSigningAlgValuesSupported []string `json:"request_object_signing_alg_values_supported,omitempty"`

	// RFC 9101 §6.4 encrypted JAR. Populated when WithJARDecrypter
	// is wired — the SupportedAlgs() / SupportedEncs() the decrypter
	// reports surface here so RPs know which alg + enc to use when
	// constructing the JWE. Omitted (the fields disappear from the
	// JSON) when no decrypter is wired; encrypted requests are
	// rejected with invalid_request_object in that case.
	RequestObjectEncryptionAlgValuesSupported []string `json:"request_object_encryption_alg_values_supported,omitempty"`
	RequestObjectEncryptionEncValuesSupported []string `json:"request_object_encryption_enc_values_supported,omitempty"`

	// RFC 8414 §2.1 — when set, contains a JWS over the same
	// metadata claims as the surrounding document. RPs MUST verify
	// the signature with JWKS before trusting any endpoint; if the
	// signed_metadata fields disagree with the plaintext, the
	// signed payload wins. Wired via `WithMetadataSigner` — left
	// empty (and field omitted) when no signer is plugged in.
	SignedMetadata string `json:"signed_metadata,omitempty"`

	// MFA orchestration (SnapLink extension; non-standard). When
	// [WithMFAProvider] + [WithMFAChallengeStore] are wired, MFAEndpoint
	// points at /auth/mfa and MFAMethodsSupported lists the factor
	// names the provider can verify. Discovery clients branch on the
	// presence of MFAEndpoint to know whether to handle the
	// mfa_required response shape. Fields omitted from the JSON when
	// MFA is not wired (preserves wire-shape parity with vanilla OIDC
	// discovery for callers that don't speak the extension).
	MFAEndpoint         string   `json:"mfa_endpoint,omitempty"`
	MFAMethodsSupported []string `json:"mfa_methods_supported,omitempty"`
}

// MTLSEndpointAliases is the RFC 8705 §5 alias map. Only endpoints
// that participate in client authentication / token issuance need
// alternates; discovery, JWKS, and end_session aren't gated on mTLS.
// Empty fields are omitted from the JSON output so the structure
// stays compact for deployments that publish a subset of endpoints.
type MTLSEndpointAliases struct {
	TokenEndpoint         string `json:"token_endpoint,omitempty"`
	RevocationEndpoint    string `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
	UserInfoEndpoint      string `json:"userinfo_endpoint,omitempty"`
	RegistrationEndpoint  string `json:"registration_endpoint,omitempty"`
	PushedAuthReqEndpoint string `json:"pushed_authorization_request_endpoint,omitempty"`
}

// codeChallengeMethodsFor advertises the PKCE methods this AS will
// actually accept. OAuth 2.1 strict mode forbids `plain` server-wide
// (RFC 7636 §4.2 marks it weaker; 2.1 §7.5.2 mandates S256), so the
// discovery list MUST shrink to ["S256"] when the operator enabled
// the strict flag. Otherwise both are accepted on the wire and both
// are advertised. Per-client AllowedPKCEMethods narrows further at
// the request path; the discovery list reflects the AS-wide ceiling.
func codeChallengeMethodsFor(s *Server) []string {
	if s.oauth21Strict {
		return []string{PKCEMethodS256}
	}
	return []string{PKCEMethodS256, PKCEMethodPlain}
}

// responseTypesFor mirrors codeChallengeMethodsFor. OAuth 2.1 §1.1
// retires the implicit grant (response_type=token), so strict mode
// MUST omit it from the discovery advertisement — otherwise an RP
// scanning discovery sees "token" supported, sends the request, and
// gets unsupported_response_type at runtime. The mismatch is a real
// integration footgun: lock the wire down to what we actually accept.
func responseTypesFor(s *Server) []string {
	if s.oauth21Strict {
		return []string{"code"}
	}
	return []string{"code", "token"}
}

// subjectTypesFor reflects WithPairwiseSubjectStore — every server
// advertises "public" (the default), and "pairwise" only when an
// operator wired the store so the AS can actually resolve pairwise
// subs at resource time. Advertising pairwise without the store
// would be a footgun: RPs registering with subject_type=pairwise
// would silently get public subs.
func subjectTypesFor(s *Server) []string {
	if s.pairwiseStore != nil {
		return []string{"public", "pairwise"}
	}
	return []string{"public"}
}

// signDiscoveryMetadata marshals cfg to JSON with SignedMetadata
// cleared, re-parses as a claim map, and asks the wired
// MetadataSigner to JWS it. The signed payload must equal the
// plaintext fields per RFC 8414 §2.1; we enforce that by sourcing
// the claims from the same struct, with one round-trip through
// json (Marshal + Unmarshal) to get the map shape the signer
// expects.
func (s *Server) signDiscoveryMetadata(ctx context.Context, cfg *oidcConfiguration) (string, error) {
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
// scanning the client store. They share the cached
// clientDiscoverySnapshot so a single iteration powers every
// derivation across one discovery doc request.

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
	// Single client-store iteration powers every derived field below
	// (scopes union, RequirePAR-any, RequireSignedRequestObject-all,
	// frontchannel_logout_supported, authorization_details types
	// union). TTL-cached across requests so a hot RP polling the
	// discovery doc doesn't pay 5× ClientStore.List per call.
	clientSnap := s.discoverySnapshot(ctx.Request().Context())
	cfg := oidcConfiguration{
		Issuer:                 base,
		AuthorizationEndpoint:  base + PathLogin,
		TokenEndpoint:          base + PathToken,
		UserInfoEndpoint:       base + PathUserInfo,
		JWKSURI:                base + PathJWKS,
		EndSessionEndpoint:     base + PathEndSession,
		RevocationEndpoint:     base + PathRevoke,
		IntrospectionEndpoint:  base + PathIntrospect,
		ResponseTypesSupported: responseTypesFor(s),
		GrantTypesSupported:    append([]string(nil), SupportedGrants...),
		SubjectTypesSupported:  subjectTypesFor(s),
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
			"private_key_jwt", // RFC 7521 + 7523
			// RFC 6749 §2.1 / OIDC Core §9 — public clients (SPAs,
			// native apps) authenticate only by client_id + PKCE,
			// so `none` is the spec-defined method for them. DCR
			// already accepts it (handle_register.go), so advertise
			// it here so RP libraries don't reject the AS during
			// metadata validation.
			"none",
		},
		// Introspection + revocation share the same client-auth
		// pipeline as /token, so advertise the same list.
		IntrospectionEndpointAuthMethodsSupported: []string{
			"client_secret_basic", "client_secret_post", "private_key_jwt",
		},
		RevocationEndpointAuthMethodsSupported: []string{
			"client_secret_basic", "client_secret_post", "private_key_jwt",
		},
		CodeChallengeMethodsSupported: codeChallengeMethodsFor(s),
		// RFC 9207 §3: this server always includes `iss` in
		// authorization responses (see handleLogin + resolveIssuer).
		AuthorizationResponseIssParameterSupported: true,
		// RFC 9101 §10.5: JAR `request` parameter accepted; URL
		// fetched `request_uri` flips true when WithJARFetcher is
		// wired (set below).
		RequestParameterSupported:              true,
		RequestURIParameterSupported:           false,
		RequestObjectSigningAlgValuesSupported: []string{"EdDSA"},
		ClaimsParameterSupported:               true,
	}
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
	if s.idTokenIssuer != nil {
		// We always sign with EdDSA today; when more signers land this
		// list should reflect every registered signature algorithm.
		cfg.IDTokenSigningAlgValuesSupported = []string{"EdDSA"}
		// Userinfo signing capability is gated on the issuer
		// implementing the UserinfoSigner extension. The default
		// Ed25519JWTIssuer does — third-party implementations may
		// not, and the omitempty serialization correctly hides the
		// claim in that case.
		if _, ok := s.idTokenIssuer.(UserinfoSigner); ok {
			cfg.UserinfoSigningAlgValuesSupported = []string{"EdDSA"}
		}
	}
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
	cfg.ClaimsSupported = []string{
		"sub", "iss", "aud", "exp", "iat", "nbf", "scope",
		"nonce", "auth_time", "amr", "acr", "azp",
	}
	// DPoP advertisement is unconditional — the handler accepts
	// the `DPoP` header on /token whenever it's present; there's
	// no opt-in store to wire.
	cfg.DPoPSigningAlgValuesSupported = []string{"EdDSA"}
	if s.clientCertExtractor != nil {
		cfg.TLSClientCertificateBoundAccessTokens = true
		cfg.MTLSEndpointAliases = &MTLSEndpointAliases{
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
	cfg.TokenEndpointAuthSigningAlgValuesSupported = []string{"EdDSA"}
	cfg.IntrospectionEndpointAuthSigningAlgValuesSupported = []string{"EdDSA"}
	cfg.RevocationEndpointAuthSigningAlgValuesSupported = []string{"EdDSA"}
	if s.parStore != nil {
		cfg.PushedAuthorizationRequestEndpointAuthSigningAlgValuesSupported = []string{"EdDSA"}
	}
	// OIDC Core §3.1.2.1 — advertise "none" so SPAs know they can
	// run silent renewal via id_token_hint. The other prompt
	// values (login / consent / select_account) aren't surfaced
	// today because this server doesn't render those UIs itself;
	// the RP is responsible for the interactive flow.
	cfg.PromptValuesSupported = []string{PromptNone}

	// Form Post Response Mode 1.0: every shape this server can
	// emit. `form_post` is the value-add (auto-POST HTML page);
	// query + fragment are advertised for spec completeness so
	// RPs that introspect discovery know they're accepted on
	// the wire.
	cfg.ResponseModesSupported = []string{
		ResponseModeQuery, ResponseModeFragment, ResponseModeFormPost,
	}

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
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	entry := buildDiscoveryDocEntry(body, s.discoveryDocCacheTTL)
	s.storeDiscoveryDocCache(base, entry)
	s.writeDiscoveryDoc(ctx, entry)
}

// requestBaseURL derives an absolute scheme://host base from the
// request. Honors X-Forwarded-Proto / X-Forwarded-Host from a known
// edge proxy; falls back to req.TLS for scheme and req.Host
// otherwise. Internet-facing deployments without an edge proxy that
// strips and re-sets those headers MUST install a stricter base
// extractor — XFF spoofing on a public endpoint can serve the wrong
// scheme to OIDC RPs.
func requestBaseURL(r *http.Request) string {
	if r == nil {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if v := r.Header.Get("X-Forwarded-Proto"); v != "" {
		// First hop only — some chains comma-separate.
		if i := strings.IndexByte(v, ','); i >= 0 {
			v = v[:i]
		}
		scheme = strings.TrimSpace(v)
	}
	host := r.Host
	if v := r.Header.Get("X-Forwarded-Host"); v != "" {
		if i := strings.IndexByte(v, ','); i >= 0 {
			v = v[:i]
		}
		host = strings.TrimSpace(v)
	}
	return scheme + "://" + host
}
