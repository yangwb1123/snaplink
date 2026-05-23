package sso

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/oidc"
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
	// available (the oidc.IDTokenIssuer doesn't implement oidc.UserinfoSigner).
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
// oidc.MetadataSigner to JWS it. The signed payload must equal the
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
		// implementing the oidc.UserinfoSigner extension. The default
		// Ed25519JWTIssuer does — third-party implementations may
		// not, and the omitempty serialization correctly hides the
		// claim in that case.
		if _, ok := s.idTokenIssuer.(oidc.UserinfoSigner); ok {
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

// PathJWKS is the standard discovery endpoint for the issuer's signing keys.
const PathJWKS = "/.well-known/jwks.json"

// JWK is a single JSON Web Key entry. Fields follow RFC 7517; only the
// subset relevant to the issuers shipped in this SDK is exposed. Issuers can
// emit additional fields by embedding extra json tags in their own structs.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`

	// OKP (Ed25519): Crv + X
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`

	// RSA: N + E
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
}

// JWKSProvider is implemented by TokenIssuer types whose tokens are publicly
// verifiable. The Server's JWKS endpoint aggregates JWKs from every
// registered issuer that satisfies this interface; symmetric issuers (HMAC,
// opaque session) simply skip the assertion and are excluded.
type JWKSProvider interface {
	JWKS(ctx context.Context) ([]JWK, error)
}

// DefaultJWKSCacheMaxAge is the freshness window advertised in
// Cache-Control for the JWKS response. 5 minutes balances key-
// rotation responsiveness against avoiding per-request hits from
// heavily-deployed RPs.
//
// Operators who rotate keys faster MUST lower this AND set
// `kid` rotation expectations on RPs — JWKS caches stick around in
// libraries past this timeout in some cases.
const DefaultJWKSCacheMaxAge = 5 * time.Minute

func (s *Server) handleJWKS(ctx HandlerContext) {
	keys := make([]JWK, 0)
	for _, ti := range s.tokenIssuers {
		jp, ok := ti.(JWKSProvider)
		if !ok {
			continue
		}
		ks, err := jp.JWKS(ctx.Request().Context())
		if err != nil {
			s.logger.Error("jwks provider failed", "error", err)
			continue
		}
		keys = append(keys, ks...)
	}
	// JAR JWE decrypter typically also implements JWKSProvider so its
	// public encryption key (use: "enc") publishes alongside the
	// issuer signing keys (use: "sig"). A single JWKS doc covers both
	// roles; RPs branch on `use` to know which key to encrypt to vs
	// verify with.
	if jp, ok := s.jarDecrypter.(JWKSProvider); ok {
		ks, err := jp.JWKS(ctx.Request().Context())
		if err != nil {
			s.logger.Error("jwks decrypter failed", "error", err)
		} else {
			keys = append(keys, ks...)
		}
	}

	body, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		s.logger.Error("jwks marshal failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	// ETag = strong validator. RP libraries can send If-None-Match on
	// poll-style fetches to short-circuit when keys haven't rotated.
	// Weak validator semantics ("W/") would be wrong here — the JSON
	// is byte-exact (json.Marshal is deterministic for the same input
	// modulo map iteration; the keys slice ordering is stable across
	// one process lifetime, so any change means real key rotation).
	sum := sha256.Sum256(body)
	etag := `"` + base64.RawURLEncoding.EncodeToString(sum[:8]) + `"`

	w := ctx.ResponseWriter()
	r := ctx.Request()
	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(int(s.jwksCacheMaxAge().Seconds())))
	w.Header().Set("ETag", etag)

	if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) jwksCacheMaxAge() time.Duration {
	if s.jwksCacheTTL > 0 {
		return s.jwksCacheTTL
	}
	return DefaultJWKSCacheMaxAge
}

// silentRenewalRequest captures the subset of /auth/login parameters
// the OIDC prompt=none silent flow needs. Bound from the inline req
// struct in handleLogin so the silent-renewal path can be tested and
// reasoned about in isolation.
type silentRenewalRequest struct {
	ClientID             string
	Scope                []string
	State                string
	Nonce                string
	Resource             []string
	AuthorizationDetails json.RawMessage
	IDTokenHint          string
	// MaxAge is the OIDC Core §3.1.2.1 max_age parameter — when
	// non-nil, the silent renewal is rejected with login_required
	// if the hint's auth_time is older than this many seconds.
	// nil = no max_age constraint (RP didn't pass one).
	MaxAge *int64
}

// parsePromptValues splits the OIDC prompt parameter and returns the
// unique non-empty values. Empty input returns nil so the caller can
// short-circuit with a `len() == 0` check.
func parsePromptValues(raw string) []string {
	if raw == "" {
		return nil
	}
	seen := make(map[string]struct{}, 4)
	out := make([]string, 0, 4)
	for _, v := range strings.Fields(raw) {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// promptHasNone reports whether the prompt parameter requests silent
// authentication. Convenience over scanning the slice at each site.
func promptHasNone(values []string) bool {
	for _, v := range values {
		if v == PromptNone {
			return true
		}
	}
	return false
}

// handleSilentRenewal implements OIDC Core §3.1.2.1's prompt=none flow.
// The RP loads /auth/login in a hidden iframe with prompt=none +
// id_token_hint to probe whether the End-User still has an active
// session — when yes, a freshly minted access (and id) token returns
// without any UI; when no, error login_required tells the iframe to
// fall back to the visible login flow.
//
// Spec checkpoints satisfied here:
//
//   - §3.1.2.1: prompt=none MUST NOT be combined with other prompt
//     values (caller validated this).
//   - §3.1.2.6: missing or unverifiable id_token_hint → login_required.
//   - §3.1.2.6: no active End-User session → login_required.
//   - §3.1.2.6: hint subject doesn't match the live session → login_required.
//   - The new ID token's `auth_time` MUST equal the original — no fresh
//     authentication event happened, so the factor freshness signal
//     downstream services see is preserved (RFC 9068 §2.2).
//
// Returns true when the silent flow handled the response (caller MUST
// bail). False on a non-prompt-none request (caller continues).
func (s *Server) handleSilentRenewal(ctx HandlerContext, prompts []string, req silentRenewalRequest, client *Client) bool {
	if !promptHasNone(prompts) {
		return false
	}
	// §3.1.2.1: "none" cannot be combined with any other prompt
	// value; mixing them is meaningless ("don't show UI AND show
	// login UI") and the spec mandates invalid_request.
	if len(prompts) > 1 {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyDesc(ctx, ErrInvalidRequest, "prompt=none must not be combined with other prompt values"))
		return true
	}
	if req.IDTokenHint == "" {
		// Without a hint we have no way to identify which user
		// the silent renewal targets; the only spec-correct
		// answer is login_required (§3.1.2.6).
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrLoginRequired))
		return true
	}
	claims, _, err := s.validateAnyToken(ctx.Request().Context(), req.IDTokenHint)
	if err != nil || claims == nil {
		// A bad-signature hint is indistinguishable from "no
		// session" on the wire (§3.1.2.6's login_required is
		// the catch-all for "AS needs user reauth"). Don't leak
		// which failure mode triggered it.
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrLoginRequired))
		return true
	}
	// The hint's client_id binding MUST match the requesting client
	// — a hint minted for client A can't be redeemed by client B
	// for a silent renewal (cross-RP confused deputy defense).
	hintedClientID := claims.ClientID
	if hintedClientID == "" && len(claims.Audience) > 0 {
		hintedClientID = claims.Audience[0]
	}
	if hintedClientID != "" && hintedClientID != client.ID {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrLoginRequired))
		return true
	}
	// OIDC Core §3.1.2.1 max_age: when the RP sets it, the AS MUST
	// reauthenticate if the elapsed time since auth_time exceeds
	// the value. prompt=none can't reauthenticate (no UI allowed),
	// so the only spec-correct response is login_required —
	// telling the iframe to fall back to the visible login flow.
	// max_age=0 collapses to "always reauthenticate"; nil = no
	// constraint. A zero auth_time means the original token was
	// minted without RFC 9068 claim population — treat as
	// unverifiable freshness and reject the silent renewal.
	if req.MaxAge != nil {
		if claims.AuthTime.IsZero() {
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrLoginRequired))
			return true
		}
		if time.Since(claims.AuthTime) > time.Duration(*req.MaxAge)*time.Second {
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrLoginRequired))
			return true
		}
	}

	if s.sessionMgr == nil {
		// No session manager wired = no notion of "active session";
		// safest default is login_required so a misconfigured
		// silent flow falls back cleanly.
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrLoginRequired))
		return true
	}
	sessions, err := s.sessionMgr.ListByUser(ctx.Request().Context(), claims.Subject)
	if err != nil || len(sessions) == 0 {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrLoginRequired))
		return true
	}
	hasLive := false
	for _, sess := range sessions {
		if sess == nil || sess.Revoked || sess.IsExpired() {
			continue
		}
		hasLive = true
		break
	}
	if !hasLive {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrLoginRequired))
		return true
	}

	// Issue the renewed access token. Note the explicit reuse of
	// AuthTime/AMR/ACR from the original ID token — silent renewal
	// does NOT represent a fresh end-user auth event, so downstream
	// services consuming RFC 9068 claims see the original factor
	// strength rather than a misleading "just-authenticated" timestamp.
	strategy, ti, err := s.issuerForClient(client)
	if err != nil {
		s.logger.Error("no token strategy for client during silent renewal", "client", client.ID, "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrNoTokenStrategy))
		return true
	}
	scopes := req.Scope
	if len(scopes) == 0 {
		// Caller didn't repeat the original scopes — preserve
		// what the hint token carried so the renewed token has
		// the same authority. (If the RP wants to downscope it
		// supplies a subset in the request.)
		scopes = claims.Scopes
	}
	token, err := ti.Issue(ctx.Request().Context(), &Subject{
		ID:                   claims.Subject,
		Resources:            req.Resource,
		ClientID:             client.ID,
		AuthTime:             claims.AuthTime,
		ACR:                  claims.ACR,
		AMR:                  append([]string(nil), claims.AMR...),
		AuthorizationDetails: oauth.CloneRawJSON(req.AuthorizationDetails),
		Actor:                claims.Actor,
		// SID stays locked to the hint's session — silent renewal
		// targets the same session the original id_token was minted
		// for, so RPs that bound their local state to the sid see
		// continuity across renewals.
		SID: claims.SID,
		TTL: client.AccessTokenTTL,
	}, scopes)
	if err != nil {
		s.logger.Error("silent renewal token issuance failed", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return true
	}

	resp := map[string]any{
		KeyAccessToken:   token.AccessToken,
		KeyTokenType:     token.TokenType,
		KeyExpiresIn:     token.ExpiresIn,
		KeyScope:         token.Scope,
		KeyTokenStrategy: strategy,
		KeyIss:           s.resolveIssuer(ctx),
	}
	if req.State != "" {
		resp[KeyState] = req.State
	}

	// OIDC id_token: when openid scope present + ID token issuer
	// is wired, mint a fresh id_token alongside. The nonce echoes
	// the request nonce per §3.1.3.7 (the RP correlates this
	// renewed token with its current auth round trip).
	if s.idTokenIssuer != nil && scopeContainsOpenID(scopes) {
		idTok, idErr := s.idTokenIssuer.IssueIDToken(ctx.Request().Context(), &oidc.IDTokenRequest{
			Subject:  claims.Subject,
			Audience: client.ID,
			Nonce:    req.Nonce,
			AuthTime: claims.AuthTime,
			ACR:      claims.ACR,
			AMR:      append([]string(nil), claims.AMR...),
			SID:      claims.SID,
		})
		if idErr != nil {
			s.logger.Error("silent renewal id_token issuance failed", "error", idErr)
		} else {
			resp[KeyIDToken] = idTok
		}
	}

	// Silent renewal reuses the original session; emit a token-
	// issued event at the same shape as a fresh login success so
	// auditors see continuous activity per (client, subject).
	s.recordLoginSuccess(ctx, client.ID, "silent_renewal", strategy, claims.Subject, "")
	ctx.JSON(http.StatusOK, resp)
	return true
}

// scopeContainsOpenID is a small helper used by the silent flow + ID
// token plumbing to gate openid-only behaviors. Independent of
// strings.Contains-on-joined to avoid the "openid_extra" false match.
func scopeContainsOpenID(scopes []string) bool {
	for _, s := range scopes {
		if s == ScopeOpenID {
			return true
		}
	}
	return false
}

// defaultDiscoveryCacheTTL is the freshness window for client-store-
// derived discovery fields. 5 seconds is short enough that DCR /
// admin client edits visibly propagate (humans typically wait > 5s
// before refreshing the discovery doc) and long enough that a busy
// RP polling /.well-known/openid-configuration N times per second
// doesn't pay 5× ClientStore.List per request. When 0, the cache is
// disabled entirely (legacy behavior).
const defaultDiscoveryCacheTTL = 5 * time.Second

// clientDiscoverySnapshot memoizes the discovery-doc fields that
// derive from iterating the entire client store. Computing them
// requires one ClientStore.List + a pass per derivation; without
// caching, every /.well-known/openid-configuration hit pays 5×
// List + 5× iteration. With caching, the cost amortizes across the
// TTL window.
//
// IMPORTANT: every field here MUST be safe to read concurrently
// after the snapshot is published via atomic.Pointer. We copy slices
// at compute-time so downstream readers can't mutate the snapshot
// in place.
type clientDiscoverySnapshot struct {
	requirePAR                 bool
	requireSignedRequestObject bool
	frontchannelLogout         bool
	scopes                     []string
	authorizationDetailTypes   []string
	expiresAt                  time.Time
}

// WithDiscoveryCacheTTL overrides the freshness window for the
// client-store-derived discovery fields. Pass 0 to disable the
// cache (every request re-iterates the client store — useful when
// running in a hot-reload dev loop where DCR edits must reflect
// instantly). Defaults to defaultDiscoveryCacheTTL.
func WithDiscoveryCacheTTL(d time.Duration) Option {
	return func(s *Server) { s.discoveryCacheTTL = d }
}

// discoverySnapshot returns the current client-store-derived snapshot,
// refreshing it via single-flight when stale or absent. Safe for
// concurrent use. When the client store is unavailable or returns
// an error, the snapshot has empty/false fields (the legacy
// "degraded discovery" behavior) — discovery MUST keep serving even
// when the store is sick.
func (s *Server) discoverySnapshot(ctx context.Context) *clientDiscoverySnapshot {
	ttl := s.discoveryCacheTTL
	if ttl == 0 {
		// Caching disabled — compute every time. The single-flight
		// path is bypassed so dev-loop hot-reload sees DCR edits
		// instantly.
		return s.computeDiscoverySnapshot(ctx)
	}
	if snap := s.discoveryCache.Load(); snap != nil && time.Now().Before(snap.expiresAt) {
		return snap
	}
	s.discoveryCacheMu.Lock()
	defer s.discoveryCacheMu.Unlock()
	// Re-check after acquiring the lock — a peer may have refreshed
	// while we waited. Standard double-checked-locking pattern.
	if snap := s.discoveryCache.Load(); snap != nil && time.Now().Before(snap.expiresAt) {
		return snap
	}
	snap := s.computeDiscoverySnapshot(ctx)
	s.discoveryCache.Store(snap)
	return snap
}

// computeDiscoverySnapshot does the expensive client-store iteration
// once and projects all four derived fields. Splitting compute from
// the cache wrapper lets tests assert the projection directly
// without poking the cache.
func (s *Server) computeDiscoverySnapshot(ctx context.Context) *clientDiscoverySnapshot {
	snap := &clientDiscoverySnapshot{expiresAt: time.Now().Add(s.discoveryCacheTTL)}
	if s.idTokenIssuer != nil {
		snap.scopes = []string{ScopeOpenID}
	}
	if s.clientStore == nil {
		return snap
	}
	clients, err := s.clientStore.List(ctx)
	if err != nil {
		return snap
	}
	scopesSeen := map[string]struct{}{}
	if s.idTokenIssuer != nil {
		scopesSeen[ScopeOpenID] = struct{}{}
	}
	adTypesSeen := map[string]struct{}{}
	allRequireSignedRequestObject := len(clients) > 0
	for _, c := range clients {
		if c == nil {
			allRequireSignedRequestObject = false
			continue
		}
		if c.RequirePAR {
			snap.requirePAR = true
		}
		if !c.RequireSignedRequestObject {
			allRequireSignedRequestObject = false
		}
		if c.FrontchannelLogoutURI != "" {
			snap.frontchannelLogout = true
		}
		for _, sc := range c.AllowedScopes {
			if sc != "" {
				scopesSeen[sc] = struct{}{}
			}
		}
		for _, t := range c.AllowedAuthorizationDetailsTypes {
			if t != "" {
				adTypesSeen[t] = struct{}{}
			}
		}
	}
	snap.requireSignedRequestObject = allRequireSignedRequestObject
	snap.scopes = sortedKeys(scopesSeen)
	if len(adTypesSeen) > 0 {
		snap.authorizationDetailTypes = sortedKeys(adTypesSeen)
	}
	return snap
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// DefaultDiscoveryDocCacheTTL bounds how long a rendered discovery
// document may serve from cache. Same scale as the snapshot cache
// (which feeds the dynamic fields below). Set <= 0 via
// [WithDiscoveryDocCacheTTL] to disable body caching while keeping
// snapshot caching in place — useful when an upstream CDN already
// caches and operators want every origin hit to be fresh.
const DefaultDiscoveryDocCacheTTL = 5 * time.Second

// discoveryDocEntry is the cached, pre-marshaled discovery document
// for a given base URL. body + etag are computed together so the
// HTTP layer just writes both.
type discoveryDocEntry struct {
	body      []byte
	etag      string
	expiresAt time.Time
}

func (e *discoveryDocEntry) fresh() bool {
	return e != nil && time.Now().Before(e.expiresAt)
}

// buildDiscoveryDocEntry computes the strong ETag (sha256 prefix) and
// the expiry. Pure function so it's safe to call without the cache
// lock held.
func buildDiscoveryDocEntry(body []byte, ttl time.Duration) *discoveryDocEntry {
	sum := sha256.Sum256(body)
	return &discoveryDocEntry{
		body:      body,
		etag:      `"` + base64.RawURLEncoding.EncodeToString(sum[:8]) + `"`,
		expiresAt: time.Now().Add(ttl),
	}
}

// lookupDiscoveryDocCache returns a fresh cached entry for base, or
// nil to signal "render fresh". The sync.Map keeps reads lock-free
// in the hot path.
func (s *Server) lookupDiscoveryDocCache(base string) *discoveryDocEntry {
	v, ok := s.discoveryDocCache.Load(base)
	if !ok {
		return nil
	}
	entry, _ := v.(*discoveryDocEntry)
	if entry.fresh() {
		return entry
	}
	// Stale — drop so the next caller re-renders.
	s.discoveryDocCache.Delete(base)
	return nil
}

func (s *Server) storeDiscoveryDocCache(base string, entry *discoveryDocEntry) {
	s.discoveryDocCache.Store(base, entry)
}

// writeDiscoveryDoc emits the cached document with Cache-Control +
// ETag headers and honors If-None-Match → 304.
func (s *Server) writeDiscoveryDoc(ctx HandlerContext, entry *discoveryDocEntry) {
	w := ctx.ResponseWriter()
	r := ctx.Request()
	w.Header().Set(HeaderContentType, ContentTypeJSON)
	maxAge := int(s.discoveryDocCacheTTL.Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(maxAge))
	w.Header().Set("ETag", entry.etag)
	if match := r.Header.Get("If-None-Match"); match != "" && match == entry.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(entry.body)
}

// WithDiscoveryDocCacheTTL configures how long a rendered discovery
// document body may serve from cache. ttl <= 0 disables body caching
// (snapshot caching via [WithDiscoveryCacheTTL] continues independently).
// Default is [DefaultDiscoveryDocCacheTTL].
func WithDiscoveryDocCacheTTL(ttl time.Duration) Option {
	return func(s *Server) { s.discoveryDocCacheTTL = ttl }
}

// OIDC + RFC 9207 response-shaping helpers. Three concerns clustered
// here for navigability:
//
//   1. resolveIssuer + authzErrorBody* — RFC 9207 issuer-identification
//      stamping on every authorization-endpoint response.
//   2. renderFormPostResponse + helpers — OIDC Form Post Response Mode 1.0
//      auto-submit HTML for response_mode=form_post.
//   3. maybeSignUserInfo — OIDC userinfo signed-response (JWT) path.
//
// All three live on *Server because they reach into Server fields
// (issuer, idTokenIssuer, clientStore, logger).

// -----------------------------------------------------------------------------
// RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification.
//
// Defense against mix-up attacks: when a client is configured with
// multiple authorization servers, an attacker can attempt to trick the
// client into accepting an authorization response from one AS as if it
// came from another. Including the AS issuer identifier in every
// authorization response lets the client verify "this code/token came
// from the AS I expected" before redeeming the code at the token
// endpoint.
//
// RFC 9207 §2 is written for redirect-based responses (`?iss=...`
// query param on the redirect to the RP). This server's /auth/login is
// a BFF-shaped JSON endpoint rather than a 302-redirect endpoint; the
// adaptation is to include `iss` in the JSON response body alongside
// `code` / `state` / `error`. A client that builds the redirect URI
// on the SPA side can propagate the value into `iss=...` as the spec
// intends.

// resolveIssuer returns the issuer identifier this server stamps in
// authorization responses. Matches the value advertised in the OIDC
// discovery document: operator-configured `WithIssuer` value when set
// and not the default sentinel; otherwise the request's base URL.
//
// Critical invariant: the value returned here MUST equal
// `oidcConfiguration.Issuer` for the same request — RFC 9207 §2
// requires the `iss` parameter to be the same identifier the AS
// publishes via discovery, so a client comparing them detects mix-up.
func (s *Server) resolveIssuer(ctx HandlerContext) string {
	if s.issuer != "" && s.issuer != DefaultIssuer {
		return s.issuer
	}
	return requestBaseURL(ctx.Request())
}

// authzErrorBody returns the standard error envelope for an
// authorization endpoint response with `iss` stamped per RFC 9207 §2.
// Use this in handleLogin (and any future authorization endpoint) —
// NOT in token / userinfo / callback handlers, which are not
// authorization responses.
func (s *Server) authzErrorBody(ctx HandlerContext, code string) map[string]string {
	return map[string]string{
		KeyError: code,
		KeyIss:   s.resolveIssuer(ctx),
	}
}

// authzErrorBodyDesc is authzErrorBody plus an error_description.
func (s *Server) authzErrorBodyDesc(ctx HandlerContext, code, desc string) map[string]string {
	return map[string]string{
		KeyError:            code,
		KeyErrorDescription: desc,
		KeyIss:              s.resolveIssuer(ctx),
	}
}

// -----------------------------------------------------------------------------
// OpenID Connect Form Post Response Mode 1.0.
//
// The RP requests `response_mode=form_post` when it wants the
// authorization response delivered as an HTML auto-submitted POST
// to its redirect_uri, rather than the default query-string redirect.
// Useful for RPs that handle POST bodies more naturally than parsing
// fragment / query parameters, and for delivering longer responses
// (id_token, etc.) without URL-length limits.
//
// Spec: https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
//
// This implementation:
//   - Renders a minimal HTML document with a hidden form whose body
//     POSTs {code, state, iss} to redirect_uri.
//   - Auto-submits via a body onload handler — operators using strict
//     CSP that blocks inline event handlers should serve this
//     endpoint outside their CSP middleware OR allowlist a 'self'
//     script-src for /auth/login.
//   - Provides a manual submit button inside <noscript> so RPs that
//     disable JS still see a fallback (the user clicks once).
//   - All response values pass through html/template's
//     auto-escaping (URL context for action=, attribute context for
//     value=), so an attacker can't break out of the form fields.
//   - Hardens response headers: X-Frame-Options: DENY (clickjacking)
//     + Cache-Control: no-store + Referrer-Policy: no-referrer
//     (don't leak the AS's URL to the RP via Referer; the auth
//     response itself is what the RP needs).

// ResponseModeFormPost is the OIDC Form Post Response Mode 1.0
// magic string for the `response_mode` parameter.
const ResponseModeFormPost = "form_post"

// ResponseModeQuery is the default response_mode for response_type=code
// per OIDC Core §3.1.2.5: parameters appended to the redirect_uri's
// query string.
const ResponseModeQuery = "query"

// ResponseModeFragment is the default response_mode for token-bearing
// response types (implicit flow). Parameters delivered after `#`.
const ResponseModeFragment = "fragment"

// formPostTemplate renders the auto-POST HTML page. The form
// elements are scoped via id="f" so the noscript fallback button's
// `form="f"` association keeps working even though the button
// itself lives outside the form (HTML5 spec).
var formPostTemplate = template.Must(template.New("formPost").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Submitting…</title>
</head>
<body onload="document.forms[0].submit()">
<noscript>
<p>JavaScript is required to complete sign-in. Please click the button below to continue.</p>
</noscript>
<form id="f" method="POST" action="{{.RedirectURI}}">
<input type="hidden" name="code" value="{{.Code}}">
{{if .State}}<input type="hidden" name="state" value="{{.State}}">{{end}}
<input type="hidden" name="iss" value="{{.Iss}}">
<noscript><button type="submit">Continue</button></noscript>
</form>
</body>
</html>
`))

// formPostData carries the values rendered into the response HTML.
// One struct (rather than a map) so html/template can pick the
// correct escaping context per field at parse time.
type formPostData struct {
	RedirectURI string
	Code        string
	State       string
	Iss         string
}

// renderFormPostResponse delivers the OIDC Form Post Response Mode
// 1.0 HTML for a successful authorization_code response. Called
// instead of ctx.JSON when response_mode=form_post.
func (s *Server) renderFormPostResponse(ctx HandlerContext, redirectURI, code, state string) {
	w := ctx.ResponseWriter()
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_ = formPostTemplate.Execute(w, formPostData{
		RedirectURI: redirectURI,
		Code:        code,
		State:       state,
		Iss:         s.resolveIssuer(ctx),
	})
}

// isValidResponseMode reports whether the supplied `response_mode`
// value is one this server understands. Empty is always valid (it
// means "use the response_type-defined default") so callers MUST
// short-circuit on empty before this check.
func isValidResponseMode(mode string) bool {
	switch mode {
	case ResponseModeQuery, ResponseModeFragment, ResponseModeFormPost:
		return true
	}
	return false
}

// -----------------------------------------------------------------------------
// OIDC userinfo signed-response (JWT) path.

// userinfoSignedAlgEdDSA is the only `userinfo_signed_response_alg`
// value this server can satisfy today — matches the access-token /
// id-token signing algorithm.
const userinfoSignedAlgEdDSA = "EdDSA"

// maybeSignUserInfo returns true when it has handled the response
// (signed JWT delivered to ctx) — callers MUST bail. False means
// the caller should fall through to the JSON response path.
//
// The signed-JWT path fires only when:
//   - clientID resolves to a registered client AND
//   - that client's UserinfoSignedResponseAlg is set AND
//   - the wired oidc.IDTokenIssuer implements oidc.UserinfoSigner
//
// Unsupported alg values (anything besides EdDSA) fall through to
// JSON — the spec says the AS MUST honor the request OR return JSON
// when it can't; we choose the latter to keep RPs working.
func (s *Server) maybeSignUserInfo(ctx HandlerContext, clientID string, body map[string]any) bool {
	if s.idTokenIssuer == nil || s.clientStore == nil || clientID == "" {
		return false
	}
	signer, ok := s.idTokenIssuer.(oidc.UserinfoSigner)
	if !ok {
		return false
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), clientID)
	if err != nil || client == nil || client.UserinfoSignedResponseAlg == "" {
		return false
	}
	if client.UserinfoSignedResponseAlg != userinfoSignedAlgEdDSA {
		// Unsupported alg — fall through to JSON. The RP picks
		// up the misconfiguration from a discovery comparison.
		return false
	}
	jwt, err := signer.SignUserInfo(ctx.Request().Context(), client.ID, body)
	if err != nil {
		s.logger.Error("userinfo sign failed", "error", err, "client", client.ID)
		return false
	}
	w := ctx.ResponseWriter()
	w.Header().Set("Content-Type", "application/jwt")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(jwt))
	return true
}
