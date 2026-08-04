package oidc

// ProviderMetadata (formerly the root-package oidcConfiguration) is the
// OpenID Provider Metadata wire type — OIDC Discovery 1.0 §4 + RFC 8414.
// It is assembled per request by the server's discovery builder and cached.
// oidcConfiguration is the OIDC Discovery 1.0 §4 response shape.
//
// The struct is built once per /auth/login and cached; the
// Server.buildOIDCConfiguration method populates it from live server
// state. Every opt-in feature branches the output here.
//
// Fields with omitempty stay hidden when the feature is off.
type ProviderMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint,omitempty"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint,omitempty"`
	// CheckSessionIframe is the OpenID Connect Session Management 1.0 §3
	// `check_session_iframe` URL — an RP-embeddable, OP-hosted static page
	// (see oidcsupport.RenderCheckSessionIframe) that lets an RP detect
	// End-User login-state changes via postMessage. Present only when
	// WithOIDCSessionManagement is wired (default off) AND the OIDC gate is
	// on — omitted (field vanishes from the JSON) otherwise, so discovery
	// stays byte-identical for deployments that never opt in.
	CheckSessionIframe    string `json:"check_session_iframe,omitempty"`
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

	// JARM (JWT Secured Authorization Response Mode) — JWS algs the AS
	// uses to sign the authorization response JWT. Omitted unless a
	// JARM signer is wired (WithJARM); its presence signals JARM
	// support alongside the jwt response_modes.
	AuthorizationSigningAlgValuesSupported []string `json:"authorization_signing_alg_values_supported,omitempty"`

	// RFC 9701 §7 — JWS algs the AS uses to sign a JWT-formatted
	// /token/introspect response. Omitted unless a DEDICATED
	// introspection signer is wired (WithIntrospectionSigning); its
	// presence is how a resource server discovers the feature is
	// available at all before ever sending the opt-in Accept header.
	IntrospectionSigningAlgValuesSupported []string `json:"introspection_signing_alg_values_supported,omitempty"`

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

	// ServingRegion (SnapLink extension; non-standard OIDC discovery
	// field) advertises the deployment's PINNED serving region — the
	// machine-readable routing contract for clients hit with
	// region_not_allowed. Present ONLY when
	// [sso.WithServingRegionAdvertisement] is wired; the value MUST be
	// deployment-static because the discovery document is cached per
	// base URL and every token minted in this process carries the same
	// serving_region. Omitted otherwise (byte-identical discovery for
	// deployments that never opt in).
	ServingRegion string `json:"serving_region,omitempty"`

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

	// OIDC Core §3 response-encryption metadata. Populated only when
	// WithJWEResponseEncrypter is wired (the response-direction mirror
	// of the request_object_encryption_* fields above) — the encrypter's
	// SupportedAlgs() / SupportedEncs() surface here so RPs know which
	// alg + enc to register for id_token / userinfo encryption. Omitted
	// (fields disappear from the JSON) when no encrypter is wired;
	// clients that nonetheless register an encrypted_response_alg get a
	// fail-closed response.
	IDTokenEncryptionAlgValuesSupported  []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	IDTokenEncryptionEncValuesSupported  []string `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserinfoEncryptionAlgValuesSupported []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserinfoEncryptionEncValuesSupported []string `json:"userinfo_encryption_enc_values_supported,omitempty"`

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

	// OIDC CIBA Core 1.0 discovery metadata. Advertised only when
	// WithCIBA is wired (opt-in). BackchannelAuthenticationEndpoint
	// points at /backchannel-authentication;
	// BackchannelTokenDeliveryModesSupported is ["poll"], plus "ping"
	// when a CIBAPingNotifier is wired (WithCIBAPingNotifier); push
	// delivery is not implemented.
	// BackchannelUserCodeParameterSupported is false (the user is
	// resolved via login_hint/id_token_hint, not a user_code).
	BackchannelAuthenticationEndpoint      string   `json:"backchannel_authentication_endpoint,omitempty"`
	BackchannelTokenDeliveryModesSupported []string `json:"backchannel_token_delivery_modes_supported,omitempty"`
	BackchannelUserCodeParameterSupported  bool     `json:"backchannel_user_code_parameter_supported,omitempty"`
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
