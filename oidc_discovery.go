package sso

import (
	"context"
	"net/http"
	"sort"
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
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
	JWKSURI                           string   `json:"jwks_uri"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	PushedAuthReqEndpoint             string   `json:"pushed_authorization_request_endpoint,omitempty"`
	RequirePushedAuthReq              bool     `json:"require_pushed_authorization_requests,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
	ClaimsSupported                   []string `json:"claims_supported,omitempty"`

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
	// BackchannelLogoutSessionSupported stays false today — this
	// server doesn't stamp `sid` in access tokens yet, so it
	// can't emit `sid` in logout tokens either. Will flip when
	// session-id support lands across the token issuers.
	BackchannelLogoutSessionSupported bool `json:"backchannel_logout_session_supported,omitempty"`
}

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
	cfg := oidcConfiguration{
		Issuer:                base,
		AuthorizationEndpoint: base + PathLogin,
		TokenEndpoint:         base + PathToken,
		UserInfoEndpoint:      base + PathUserInfo,
		JWKSURI:               base + PathJWKS,
		EndSessionEndpoint:    base + PathEndSession,
		RevocationEndpoint:    base + PathRevoke,
		IntrospectionEndpoint: base + PathIntrospect,
		ResponseTypesSupported: []string{
			"code",
			"token",
		},
		GrantTypesSupported:               append([]string(nil), SupportedGrants...),
		SubjectTypesSupported:             []string{"public"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		CodeChallengeMethodsSupported:     []string{PKCEMethodS256, PKCEMethodPlain},
		// RFC 9207 §3: this server always includes `iss` in
		// authorization responses (see handleLogin + resolveIssuer).
		AuthorizationResponseIssParameterSupported: true,
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
	}
	if s.parStore != nil {
		// RFC 9126 §5: advertise the PAR endpoint so RPs that prefer
		// the pushed-request flow can discover it. require_pushed_*
		// stays false here — we accept both shapes; a future
		// per-server policy knob can flip it.
		cfg.PushedAuthReqEndpoint = base + PathPAR
	}
	if s.dcrPolicy != nil {
		// RFC 7591 §3: advertise the registration endpoint so
		// dynamic clients can discover it. The initial access
		// token (when required) is distributed out-of-band, not
		// via discovery.
		cfg.RegistrationEndpoint = base + PathRegister
	}
	scopes := scopeAdvertisement(ctx.Request().Context(), s)
	if len(scopes) > 0 {
		cfg.ScopesSupported = scopes
	}
	if rar := authorizationDetailsTypeAdvertisement(ctx.Request().Context(), s); len(rar) > 0 {
		cfg.AuthorizationDetailsTypesSupported = rar
	}
	if s.logoutTokenIssuer != nil && s.logoutNotifier != nil {
		cfg.BackchannelLogoutSupported = true
	}
	cfg.ClaimsSupported = []string{
		"sub", "iss", "aud", "exp", "iat", "nbf", "scope",
		"nonce", "auth_time", "amr", "acr", "azp",
	}

	ctx.JSON(http.StatusOK, cfg)
}

// authorizationDetailsTypeAdvertisement collects the union of
// every client's AllowedAuthorizationDetailsTypes. Empty result
// = omit the discovery field (no client has declared a type
// allowlist; the parameter remains accepted but unconstrained).
// ClientStore.List errors are non-fatal — discovery MUST keep
// responding even when the store is degraded.
func authorizationDetailsTypeAdvertisement(ctx context.Context, s *Server) []string {
	if s.clientStore == nil {
		return nil
	}
	clients, err := s.clientStore.List(ctx)
	if err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	for _, c := range clients {
		for _, t := range c.AllowedAuthorizationDetailsTypes {
			if t != "" {
				seen[t] = struct{}{}
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// scopeAdvertisement collects scopes the server can grant. Always
// includes "openid" when an ID token issuer is wired, plus the union
// of every client's AllowedScopes — so RPs see what they can ask for
// without poking each client manually. A ClientStore.List error is
// non-fatal (the OIDC discovery endpoint MUST keep responding even
// when the store is degraded); the openid scope still gets
// advertised on its own.
func scopeAdvertisement(ctx context.Context, s *Server) []string {
	seen := map[string]struct{}{}
	if s.idTokenIssuer != nil {
		seen[ScopeOpenID] = struct{}{}
	}
	if s.clientStore != nil {
		if clients, err := s.clientStore.List(ctx); err == nil {
			for _, c := range clients {
				for _, sc := range c.AllowedScopes {
					if sc != "" {
						seen[sc] = struct{}{}
					}
				}
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for sc := range seen {
		out = append(out, sc)
	}
	sort.Strings(out)
	return out
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
