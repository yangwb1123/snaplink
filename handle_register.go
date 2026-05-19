package sso

import (
	"net/http"
	"slices"
	"time"
)

// dcrRequest mirrors the RFC 7591 §2 client metadata subset this
// server understands. Unknown fields are ignored per §3.1 ("the
// authorization server MUST ignore values it does not understand").
type dcrRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ClientName              string   `json:"client_name"`
	Scope                   string   `json:"scope"`
	Contacts                []string `json:"contacts"`
	TokenStrategy           string   `json:"token_strategy"`
	AllowedAuthenticators   []string `json:"allowed_authenticators"`
	AllowedResources        []string `json:"allowed_resources"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris"`
	TenantID                string   `json:"tenant_id"`
	RequirePKCE             bool     `json:"require_pkce"`
}

// dcrResponse is the RFC 7591 §3.2.1 successful-registration body.
// Echoes every accepted metadata field plus the issued credentials
// and timestamps.
type dcrResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	TokenStrategy           string   `json:"token_strategy,omitempty"`
	AllowedAuthenticators   []string `json:"allowed_authenticators,omitempty"`
	AllowedResources        []string `json:"allowed_resources,omitempty"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris,omitempty"`
	RequirePKCE             bool     `json:"require_pkce,omitempty"`
}

// handleRegister implements RFC 7591 Dynamic Client Registration.
// Opt-in via WithDynamicClientRegistration; without it /register
// returns 501.
//
// Auth gate: requires the configured initial access token (a
// pre-shared bearer the operator distributes) unless the policy's
// AllowOpenRegistration=true is set. Open registration is
// supported but discouraged — every public registration endpoint
// in the wild eventually gets used for resource exhaustion.
//
// Response per §3.2.1: 201 Created + the issued credentials +
// the echoed metadata. Public clients (token_endpoint_auth_method
// = "none") skip secret generation per §2.
func (s *Server) handleRegister(ctx HandlerContext) {
	if s.dcrPolicy == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrRegistrationDisabled))
		return
	}
	if err := s.requireDeps(depClientStore); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	// Authentication gate. Initial-access-token takes precedence
	// when configured; AllowOpenRegistration is the explicit
	// escape hatch.
	if !s.dcrPolicy.AllowOpenRegistration {
		if s.dcrPolicy.InitialAccessToken == "" {
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
			return
		}
		if bearer := bearerToken(ctx.Request()); bearer != s.dcrPolicy.InitialAccessToken {
			ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
			return
		}
	}

	var req dcrRequest
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBodyWithDescription(ErrInvalidClientMetadata, err.Error()))
		return
	}

	if err := validateDCRMetadata(&req, s.dcrPolicy); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBodyWithDescription(ErrInvalidClientMetadata, err.Error()))
		return
	}

	id, err := generateClientID()
	if err != nil {
		s.logger.Error("dcr id gen failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	// Public clients (no secret) per RFC 7591 §2 +
	// RFC 6749 §2.3 — the "none" auth method opts out of secret
	// issuance entirely. SPAs and mobile apps that hold no
	// confidential secret should request this.
	public := req.TokenEndpointAuthMethod == "none"
	secret := ""
	if !public {
		secret, err = generateClientSecret()
		if err != nil {
			s.logger.Error("dcr secret gen failed", "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
			return
		}
	}

	tokenStrategy := req.TokenStrategy
	if tokenStrategy == "" {
		tokenStrategy = s.dcrPolicy.DefaultTokenStrategy
	}

	client := &Client{
		ID:                     id,
		Secret:                 secret,
		Name:                   req.ClientName,
		RedirectURIs:           append([]string(nil), req.RedirectURIs...),
		AllowedScopes:          splitScope(req.Scope),
		AllowedAuthenticators:  append([]string(nil), req.AllowedAuthenticators...),
		TokenStrategy:          tokenStrategy,
		Active:                 s.dcrPolicy.DefaultActive,
		TenantID:               req.TenantID,
		RequirePKCE:            req.RequirePKCE || public, // public clients always PKCE
		AllowedResources:       append([]string(nil), req.AllowedResources...),
		PostLogoutRedirectURIs: append([]string(nil), req.PostLogoutRedirectURIs...),
	}

	if err := s.clientStore.Add(ctx.Request().Context(), client); err != nil {
		s.logger.Error("dcr persist failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	now := time.Now().Unix()
	resp := dcrResponse{
		ClientID:                id,
		ClientSecret:            secret,
		ClientIDIssuedAt:        now,
		ClientSecretExpiresAt:   0, // 0 = never expires per RFC 7591 §3.2.1
		RedirectURIs:            client.RedirectURIs,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		ClientName:              client.Name,
		Scope:                   req.Scope,
		Contacts:                req.Contacts,
		TokenStrategy:           client.TokenStrategy,
		AllowedAuthenticators:   client.AllowedAuthenticators,
		AllowedResources:        client.AllowedResources,
		PostLogoutRedirectURIs:  client.PostLogoutRedirectURIs,
		RequirePKCE:             client.RequirePKCE,
	}

	ctx.JSON(http.StatusCreated, resp)
}

// validateDCRMetadata enforces the subset of RFC 7591 §2 / §5
// rules this server understands plus the policy's whitelist
// constraints.
func validateDCRMetadata(req *dcrRequest, policy *DCRPolicy) error {
	// redirect_uris is REQUIRED for grant_type=authorization_code
	// (the default), OPTIONAL for client_credentials-only clients
	// (per §2 — "redirect_uris is OPTIONAL ... If the grant types
	// supported include authorization_code or implicit, then this
	// metadata REQUIRED").
	wantsCodeFlow := len(req.GrantTypes) == 0 ||
		slices.Contains(req.GrantTypes, GrantAuthorizationCode)
	if wantsCodeFlow && len(req.RedirectURIs) == 0 {
		return errDCR("redirect_uris required for authorization_code flow")
	}

	if slices.Contains(req.RedirectURIs, "") {
		return errDCR("empty redirect_uri")
	}

	switch req.TokenEndpointAuthMethod {
	case "", "client_secret_basic", "client_secret_post", "none":
		// supported
	default:
		return errDCR("unsupported token_endpoint_auth_method: " + req.TokenEndpointAuthMethod)
	}

	for _, g := range req.GrantTypes {
		if !slices.Contains(SupportedGrants, g) {
			return errDCR("unsupported grant_type: " + g)
		}
	}

	for _, rt := range req.ResponseTypes {
		switch rt {
		case "code", "token", "":
			// supported
		default:
			return errDCR("unsupported response_type: " + rt)
		}
	}

	if len(policy.AllowedAuthenticators) > 0 {
		for _, a := range req.AllowedAuthenticators {
			if !slices.Contains(policy.AllowedAuthenticators, a) {
				return errDCR("authenticator not permitted by registration policy: " + a)
			}
		}
	}

	return nil
}

func errDCR(msg string) error {
	return &dcrError{msg: msg}
}

type dcrError struct{ msg string }

func (e *dcrError) Error() string { return e.msg }
